package assistant

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/pirpc"
	"github.com/open-card/open-card/internal/piworker"
)

// PiGrantFactory binds a server-owned actor/scope/run to a short-lived tool
// capability. The raw bearer is sent only through the protected worker socket.
// It is never part of a model prompt, browser event, or error message.
type PiGrantFactory func(RunnerRun, time.Time) (token string, revoke func(), err error)

type PiRunnerConfig struct {
	SocketPath string
	Grant      PiGrantFactory
	RunTimeout time.Duration
}

type PiRunner struct {
	config PiRunnerConfig
	mu     sync.Mutex
	active map[domain.ID]*piRunHandle
}

type piRunHandle struct {
	owner        *PiRunner
	sessionID    domain.ID
	client       *pirpc.Client
	transport    *pirpc.Transport
	subscription *pirpc.Subscription
	cancel       context.CancelFunc
	revoke       func()
	done         chan struct{}
	err          error
}

func NewPiRunner(config PiRunnerConfig) (*PiRunner, error) {
	if config.SocketPath == "" || config.Grant == nil {
		return nil, ErrUnavailable
	}
	if config.RunTimeout <= 0 || config.RunTimeout > 5*time.Minute {
		config.RunTimeout = 5 * time.Minute
	}
	return &PiRunner{config: config, active: make(map[domain.ID]*piRunHandle)}, nil
}

func (p *PiRunner) Start(startCtx, runCtx context.Context, run RunnerRun, emit func(RunnerEvent) error) (RunnerHandle, error) {
	if p == nil || emit == nil || run.Scope.Validate() != nil || !validActor(run.Actor) {
		return nil, ErrInvalidInput
	}
	p.mu.Lock()
	if _, exists := p.active[run.SessionID]; exists {
		p.mu.Unlock()
		return nil, ErrUnavailable
	}
	// A reservation prevents concurrent Start calls for one session before the
	// worker handshake has completed. The service serializes its Abort gate.
	p.active[run.SessionID] = nil
	p.mu.Unlock()
	owned := false
	defer func() {
		if !owned {
			p.mu.Lock()
			delete(p.active, run.SessionID)
			p.mu.Unlock()
		}
	}()
	token, revoke, err := p.config.Grant(run, time.Now().Add(p.config.RunTimeout))
	if err != nil || revoke == nil {
		return nil, ErrUnavailable
	}
	cleanupGrant := true
	defer func() {
		if cleanupGrant {
			revoke()
		}
	}()
	var connection net.Conn
	for {
		connection, _, err = piworker.Dial(startCtx, p.config.SocketPath, piworker.OpenRequest{
			Protocol: piworker.ProtocolVersion, Type: "open", RunToken: token, RunID: run.RunID.String(), SessionID: run.SessionID.String(),
			Scope: piworker.Scope{Kind: string(run.Scope.Kind), ApplicationID: run.Scope.AppID.String()},
		}, 5*time.Second)
		if err == nil {
			break
		}
		var refused *piworker.OpenError
		if !errors.As(err, &refused) || refused.Code != "busy" {
			return nil, ErrUnavailable
		}
		// A preceding connection may be draining its owned process. No prompt
		// was sent on a busy handshake, so admission can be retried safely.
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-startCtx.Done():
			timer.Stop()
			return nil, ErrUnavailable
		case <-runCtx.Done():
			timer.Stop()
			return nil, ErrUnavailable
		case <-timer.C:
		}
	}
	ctx, cancel := context.WithTimeout(runCtx, p.config.RunTimeout)
	transport := pirpc.NewTransport(connection, pirpc.Options{})
	client := pirpc.NewClient(transport)
	subscription := client.Subscribe()
	handle := &piRunHandle{owner: p, sessionID: run.SessionID, client: client, transport: transport, subscription: subscription, cancel: cancel, revoke: revoke, done: make(chan struct{})}
	p.mu.Lock()
	p.active[run.SessionID] = handle
	p.mu.Unlock()
	owned, cleanupGrant = true, false
	// A missing acknowledgement after sending a prompt is an unknown outcome,
	// never proof that the model or a tool did not start.
	_, err = client.Prompt(startCtx, run.Message)
	if err != nil {
		go handle.finish(ErrRunnerOutcomeUnknown)
		return handle, nil
	}
	go handle.consume(ctx, emit)
	return handle, nil
}

func (h *piRunHandle) consume(ctx context.Context, emit func(RunnerEvent) error) {
	var outcome error
	defer func() { h.finish(outcome) }()
	// Coalesce token-sized deltas into small UI frames. This keeps local
	// PostgreSQL fsync work bounded while preserving a responsive stream.
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var pending strings.Builder
	totalBytes := 0
	flush := func() error {
		if pending.Len() == 0 {
			return nil
		}
		text := pending.String()
		pending.Reset()
		return emit(RunnerEvent{Kind: RunnerDelta, Text: text})
	}
	for {
		select {
		case <-ticker.C:
			if flush() != nil {
				outcome = ErrRunnerOutcomeUnknown
				return
			}
		case <-ctx.Done():
			outcome = ErrRunnerOutcomeUnknown
			return
		case <-h.transport.Done():
			outcome = ErrRunnerOutcomeUnknown
			return
		case <-h.subscription.Done:
			outcome = ErrRunnerOutcomeUnknown
			return
		case event, ok := <-h.subscription.Events:
			if !ok {
				outcome = ErrRunnerOutcomeUnknown
				return
			}
			if event.Type == pirpc.EventMessageUpdate && event.DeltaType == pirpc.DeltaText {
				totalBytes += len(event.Text)
				if event.Truncated || totalBytes > 4*MaxEventTextBytes {
					outcome = ErrRunnerOutcomeUnknown
					return
				}
				if pending.Len()+len(event.Text) > MaxEventTextBytes && flush() != nil {
					outcome = ErrRunnerOutcomeUnknown
					return
				}
				pending.WriteString(event.Text)
				if pending.Len() >= 512 && flush() != nil {
					outcome = ErrRunnerOutcomeUnknown
					return
				}
			}
			if event.Type == pirpc.EventExtensionUIRequest && event.UI != nil {
				// This first diagnostic runner grants no approval authority to extension
				// dialogs. Future mutations need a separate server-owned approval record.
				if event.UI.ID != "" {
					_ = h.client.CancelUI(ctx, event.UI.ID)
				}
			}
			if event.Type == pirpc.EventAgentEnd && !event.WillRetry {
				if flush() != nil {
					outcome = ErrRunnerOutcomeUnknown
					return
				}
				messages, err := h.client.GetMessages(ctx)
				if err != nil {
					outcome = ErrRunnerOutcomeUnknown
					return
				}
				for index := len(messages) - 1; index >= 0; index-- {
					message := messages[index]
					if message.Role != "assistant" {
						continue
					}
					if message.StopReason == "error" || message.StopReason == "aborted" || message.IsError {
						outcome = ErrUnavailable
						return
					}
					if message.Truncated {
						outcome = ErrRunnerOutcomeUnknown
						return
					}
					if message.Text != "" {
						outcome = emit(RunnerEvent{Kind: RunnerMessage, Text: message.Text})
					}
					return
				}
				outcome = ErrUnavailable
				return
			}
		}
	}
}

func (h *piRunHandle) finish(err error) {
	h.cancel()
	_ = h.transport.Close()
	h.subscription.Close()
	h.revoke()
	h.owner.mu.Lock()
	if h.owner.active[h.sessionID] == h {
		delete(h.owner.active, h.sessionID)
	}
	h.owner.mu.Unlock()
	h.err = err
	close(h.done)
}
func (h *piRunHandle) Wait() error { <-h.done; return h.err }

func (p *PiRunner) Abort(ctx context.Context, request RunnerAbort) error {
	p.mu.Lock()
	handle := p.active[request.SessionID]
	p.mu.Unlock()
	if handle == nil {
		return nil
	}
	_, _, err := handle.client.Abort(ctx)
	handle.cancel()
	// The service may already have cancelled the run context. A closed
	// transport means this worker connection cannot start queued work again.
	if err != nil && !errors.Is(err, pirpc.ErrClosed) {
		return ErrUnavailable
	}
	return nil
}

var _ Runner = (*PiRunner)(nil)
