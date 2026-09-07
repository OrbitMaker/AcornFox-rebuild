package assistant

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/open-card/open-card/internal/domain"
)

type Config struct {
	Store             Store
	Runner            Runner
	Clock             func() time.Time
	StartTimeout      time.Duration
	GlobalConcurrency int
}

type sessionLane struct {
	wake         chan struct{}
	updates      chan struct{}
	control      sync.Mutex
	activeRun    domain.ID
	activeCancel context.CancelFunc
	halted       bool
}

type Service struct {
	store        Store
	runner       Runner
	clock        func() time.Time
	startTimeout time.Duration
	globalSlots  chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	lanes        map[domain.ID]*sessionLane
	wg           sync.WaitGroup
}

func NewService(config Config) (*Service, error) {
	if config.Store == nil || config.Runner == nil {
		return nil, ErrUnavailable
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	startTimeout := config.StartTimeout
	if startTimeout == 0 {
		startTimeout = MaxRunnerStartTimeout
	}
	if startTimeout < 0 || startTimeout > MaxRunnerStartTimeout {
		return nil, ErrInvalidInput
	}
	globalConcurrency := config.GlobalConcurrency
	if globalConcurrency == 0 {
		globalConcurrency = 1
	}
	if globalConcurrency < 1 || globalConcurrency > MaxGlobalConcurrency {
		return nil, ErrInvalidInput
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{store: config.Store, runner: config.Runner, clock: clock, startTimeout: startTimeout, globalSlots: make(chan struct{}, globalConcurrency), ctx: ctx, cancel: cancel, lanes: make(map[domain.ID]*sessionLane)}, nil
}

// Recover marks pre-restart accepted/running work unknown. It intentionally
// does not wake a lane or resubmit a prompt.
func (s *Service) Recover(ctx context.Context) (int, error) {
	if s == nil || s.store == nil {
		return 0, ErrUnavailable
	}
	count, err := s.store.RecoverInterrupted(ctx, s.now())
	if err != nil {
		return 0, ErrUnavailable
	}
	return count, nil
}

func (s *Service) CreateSession(ctx context.Context, actor Actor, scope Scope) (Session, error) {
	if !validActor(actor) {
		return Session{}, ErrUnauthorized
	}
	if scope.Validate() != nil {
		return Session{}, ErrInvalidInput
	}
	id, err := domain.NewID("asst_session")
	if err != nil {
		return Session{}, ErrUnavailable
	}
	now := s.now()
	session := Session{ID: id, Scope: scope, CreatedAt: now, UpdatedAt: now, ownerID: actor.AdminID}
	if err := s.store.CreateSession(ctx, actor, session); err != nil {
		return Session{}, serviceStoreError(err)
	}
	return session, nil
}

func (s *Service) ListSessions(ctx context.Context, actor Actor) ([]Session, error) {
	if !validActor(actor) {
		return nil, ErrUnauthorized
	}
	sessions, err := s.store.ListSessions(ctx, actor)
	if err != nil {
		return nil, serviceStoreError(err)
	}
	return sessions, nil
}

func (s *Service) SubmitRun(ctx context.Context, actor Actor, sessionID domain.ID, idempotencyKey, message string) (SubmitRunResult, error) {
	if !validActor(actor) {
		return SubmitRunResult{}, ErrUnauthorized
	}
	if sessionID.Empty() || !validIdempotencyKey(idempotencyKey) || !validMessage(message) {
		return SubmitRunResult{}, ErrInvalidInput
	}
	if _, err := s.store.GetSession(ctx, actor, sessionID); err != nil {
		return SubmitRunResult{}, serviceStoreError(err)
	}
	id, err := domain.NewID("asst_run")
	if err != nil {
		return SubmitRunResult{}, ErrUnavailable
	}
	now := s.now()
	run := Run{ID: id, SessionID: sessionID, Status: RunAccepted, CreatedAt: now, UpdatedAt: now, message: message}
	lane := s.laneFor(sessionID)
	lane.control.Lock()
	if lane.halted {
		lane.control.Unlock()
		return SubmitRunResult{}, ErrUnavailable
	}
	stored, replay, err := s.store.CreateOrReplayRun(ctx, actor, sessionID, idempotencyKey, messageDigest(message), run, now)
	lane.control.Unlock()
	if err != nil {
		return SubmitRunResult{}, serviceStoreError(err)
	}
	if !replay {
		s.notify(lane)
		s.signal(lane)
	}
	return SubmitRunResult{Run: stored, Replay: replay}, nil
}

func (s *Service) Events(ctx context.Context, actor Actor, sessionID domain.ID, after uint64) (EventSnapshot, error) {
	if !validActor(actor) {
		return EventSnapshot{}, ErrUnauthorized
	}
	if sessionID.Empty() {
		return EventSnapshot{}, ErrInvalidInput
	}
	snapshot, err := s.store.EventsAfter(ctx, actor, sessionID, after, DefaultEventPageSize)
	if err != nil {
		if errors.Is(err, ErrCursorExpired) {
			return snapshot, ErrCursorExpired
		}
		return EventSnapshot{}, serviceStoreError(err)
	}
	return snapshot, nil
}

func (s *Service) Abort(ctx context.Context, actor Actor, sessionID domain.ID) (AbortResult, error) {
	if !validActor(actor) {
		return AbortResult{}, ErrUnauthorized
	}
	if sessionID.Empty() {
		return AbortResult{}, ErrInvalidInput
	}
	if _, err := s.store.GetSession(ctx, actor, sessionID); err != nil {
		return AbortResult{}, serviceStoreError(err)
	}
	lane := s.laneFor(sessionID)
	lane.control.Lock()
	count, err := s.store.AbortSessionRuns(ctx, actor, sessionID, s.now())
	s.notify(lane)
	if err != nil {
		lane.halted = true
		if lane.activeCancel != nil {
			abortCtx, cancelAbort := context.WithTimeout(context.Background(), MaxRunnerAbortTimeout)
			_ = s.runner.Abort(abortCtx, RunnerAbort{SessionID: sessionID, ClearQueue: true})
			cancelAbort()
			lane.activeCancel()
		}
		lane.control.Unlock()
		return AbortResult{}, serviceStoreError(err)
	}
	if lane.activeCancel != nil {
		abortCtx, cancelAbort := context.WithTimeout(context.Background(), MaxRunnerAbortTimeout)
		_ = s.runner.Abort(abortCtx, RunnerAbort{SessionID: sessionID, ClearQueue: true})
		cancelAbort()
		lane.activeCancel()
	}
	lane.control.Unlock()
	return AbortResult{Aborted: count}, nil
}

// Close is a process lifecycle operation. Browser disconnect, tab close, and
// minimize never call it and therefore never cancel a run.
func (s *Service) Close() {
	if s == nil {
		return
	}
	s.cancel()
	s.wg.Wait()
}

func (s *Service) laneFor(sessionID domain.ID) *sessionLane {
	s.mu.Lock()
	lane := s.lanes[sessionID]
	if lane == nil {
		lane = &sessionLane{wake: make(chan struct{}, 1), updates: make(chan struct{}, 1)}
		s.lanes[sessionID] = lane
		s.wg.Add(1)
		go s.runLane(sessionID, lane)
	}
	s.mu.Unlock()
	return lane
}

func (s *Service) signal(lane *sessionLane) {
	select {
	case lane.wake <- struct{}{}:
	default:
	}
}

func (s *Service) notify(lane *sessionLane) {
	select {
	case lane.updates <- struct{}{}:
	default:
	}
}

// WaitForEvents waits only for a local projection change. Canceling this wait
// on browser disconnect has no effect on the runner lifecycle.
func (s *Service) WaitForEvents(ctx context.Context, actor Actor, sessionID domain.ID) error {
	if !validActor(actor) {
		return ErrUnauthorized
	}
	if _, err := s.store.GetSession(ctx, actor, sessionID); err != nil {
		return serviceStoreError(err)
	}
	lane := s.laneFor(sessionID)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return ErrUnavailable
	case <-lane.updates:
		return nil
	}
}

func (s *Service) runLane(sessionID domain.ID, lane *sessionLane) {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-lane.wake:
			for {
				if !s.acquireGlobalSlot() {
					return
				}
				lane.control.Lock()
				if lane.halted {
					lane.control.Unlock()
					s.releaseGlobalSlot()
					break
				}
				run, found, err := s.store.ClaimNextRun(s.ctx, sessionID, s.now())
				if err != nil || !found {
					lane.control.Unlock()
					s.releaseGlobalSlot()
					break
				}
				s.notify(lane)
				handle, startErr := s.start(run, lane)
				lane.control.Unlock()
				if startErr != nil {
					status := RunFailed
					if errors.Is(startErr, ErrRunnerOutcomeUnknown) {
						status = RunUnknown
					}
					if !s.finishRun(run, status) {
						lane.control.Lock()
						lane.halted = true
						lane.control.Unlock()
						s.releaseGlobalSlot()
						break
					}
					s.releaseGlobalSlot()
					continue
				}
				waited := s.wait(run, lane, handle)
				s.releaseGlobalSlot()
				if !waited {
					lane.control.Lock()
					lane.halted = true
					lane.control.Unlock()
					break
				}
			}
		}
	}
}

func (s *Service) acquireGlobalSlot() bool {
	select {
	case s.globalSlots <- struct{}{}:
		return true
	case <-s.ctx.Done():
		return false
	}
}
func (s *Service) releaseGlobalSlot() { <-s.globalSlots }

func (s *Service) start(run Run, lane *sessionLane) (RunnerHandle, error) {
	session, err := s.store.GetSession(s.ctx, Actor{AdminID: run.ownerID}, run.SessionID)
	if err != nil {
		return nil, ErrUnavailable
	}
	runCtx, cancel := context.WithCancel(s.ctx)
	lane.activeRun, lane.activeCancel = run.ID, cancel
	var projectionOnce sync.Once
	var projectionErr error
	emit := func(input RunnerEvent) error {
		kind, ok := projectedRunnerEvent(input.Kind)
		if !ok {
			return nil
		}
		if !validEventText(input.Text) {
			projectionOnce.Do(func() { projectionErr = ErrEventLimit })
			return ErrEventLimit
		}
		_, appendErr := s.store.AppendEvent(s.ctx, run.SessionID, run.ID, kind, input.Text, s.now())
		if appendErr != nil {
			projectionOnce.Do(func() { projectionErr = appendErr })
			return ErrEventLimit
		}
		s.notify(lane)
		return nil
	}
	startCtx, stopStart := context.WithTimeout(s.ctx, s.startTimeout)
	handle, startErr := s.runner.Start(startCtx, runCtx, RunnerRun{RunID: run.ID, SessionID: run.SessionID, Actor: Actor{AdminID: run.ownerID}, Scope: session.Scope, Message: run.message}, emit)
	startContextErr := startCtx.Err()
	stopStart()
	if startErr != nil || handle == nil || startContextErr != nil {
		cancel()
		if handle != nil {
			_ = s.runner.Abort(context.Background(), RunnerAbort{SessionID: run.SessionID, ClearQueue: true})
		}
		lane.activeRun, lane.activeCancel = "", nil
		if handle != nil || startContextErr != nil || errors.Is(startErr, ErrRunnerOutcomeUnknown) {
			return nil, ErrRunnerOutcomeUnknown
		}
		return nil, ErrUnavailable
	}
	return &projectionHandle{inner: handle, projectionErr: func() error { return projectionErr }}, nil
}

type projectionHandle struct {
	inner         RunnerHandle
	projectionErr func() error
}

func (h *projectionHandle) Wait() error {
	err := h.inner.Wait()
	if projectionErr := h.projectionErr(); projectionErr != nil {
		return projectionErr
	}
	return err
}

func (s *Service) wait(run Run, lane *sessionLane, handle RunnerHandle) bool {
	runErr := handle.Wait()
	lane.control.Lock()
	if lane.activeRun == run.ID {
		if lane.activeCancel != nil {
			lane.activeCancel()
		}
		lane.activeRun, lane.activeCancel = "", nil
	}
	lane.control.Unlock()
	status := RunCompleted
	if runErr != nil && !errors.Is(runErr, ErrRunnerOutcomeUnknown) && !errors.Is(runErr, context.Canceled) {
		status = RunFailed
	}
	if errors.Is(runErr, ErrRunnerOutcomeUnknown) || errors.Is(runErr, context.Canceled) {
		status = RunUnknown
	}
	finished := s.finishRun(run, status)
	if finished {
		s.notify(lane)
	}
	return finished
}

func (s *Service) finishRun(run Run, status RunStatus) bool {
	for attempt := 0; attempt < 3; attempt++ {
		if _, err := s.store.FinishRun(context.Background(), run.SessionID, run.ID, status, s.now()); err == nil {
			return true
		}
	}
	// Stop this session lane with the durable row still running. A restart calls
	// RecoverInterrupted and marks it unknown without resubmitting.
	return false
}

func projectedRunnerEvent(kind RunnerEventKind) (EventType, bool) {
	switch kind {
	case RunnerDelta:
		return EventAssistantDelta, true
	case RunnerMessage:
		return EventAssistantMessage, true
	default:
		return "", false
	}
}

func validActor(actor Actor) bool { return !actor.AdminID.Empty() }
func validMessage(message string) bool {
	return message != "" && len(message) <= MaxMessageBytes && utf8.ValidString(message) && !strings.ContainsRune(message, 0)
}
func validEventText(text string) bool {
	return len(text) <= MaxEventTextBytes && utf8.ValidString(text) && !strings.ContainsRune(text, 0)
}
func validIdempotencyKey(key string) bool {
	if key == "" || len(key) > MaxIdempotencyKeyBytes {
		return false
	}
	for _, r := range key {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && !strings.ContainsRune("._:-", r) {
			return false
		}
	}
	return true
}
func messageDigest(message string) string {
	sum := sha256.Sum256([]byte("acornfox-assistant-message-v1\x00" + message))
	return hex.EncodeToString(sum[:])
}
func (s *Service) now() time.Time { return s.clock().UTC() }

func serviceStoreError(err error) error {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return ErrUnauthorized
	case errors.Is(err, ErrNotFound):
		return ErrNotFound
	case errors.Is(err, ErrInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, ErrIdempotencyConflict):
		return ErrIdempotencyConflict
	case errors.Is(err, ErrSessionLimit):
		return ErrSessionLimit
	case errors.Is(err, ErrRunLimit):
		return ErrRunLimit
	case errors.Is(err, ErrCursorExpired):
		return ErrCursorExpired
	default:
		return ErrUnavailable
	}
}
