package agenttransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/domain"
)

type EnvelopeHandler interface {
	HandleControlEnvelope(context.Context, v1.Envelope) ([]v1.Envelope, error)
}

type Client struct {
	BaseURL            string
	HTTPClient         *http.Client
	Hello              v1.Hello
	Handler            EnvelopeHandler
	PollWait           time.Duration
	MinBackoff         time.Duration
	MaxBackoff         time.Duration
	MinProtocolVersion string
	MaxProtocolVersion string
	clock              func() time.Time

	mu                   sync.Mutex
	sessionID            string
	cursor               uint64
	heartbeat            uint64
	heartbeatInterval    time.Duration
	lastHeartbeat        time.Time
	negotiatedVersion    string
	disabledCapabilities []string
	enabledCapabilities  []string
}

func (c *Client) normalize() error {
	if strings.TrimSpace(c.BaseURL) == "" || c.HTTPClient == nil || c.Handler == nil {
		return errors.New("agent client requires base URL, mTLS HTTP client and handler")
	}
	parsedURL, err := url.Parse(c.BaseURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" {
		return errors.New("agent control-plane URL must be absolute HTTPS")
	}
	if strings.TrimSpace(c.Hello.InstanceID) == "" || strings.TrimSpace(c.Hello.NodeID) == "" || strings.TrimSpace(c.Hello.AgentVersion) == "" {
		return errors.New("agent client hello identity and version are required")
	}
	if c.PollWait <= 0 || c.PollWait > maxPollWait {
		c.PollWait = 500 * time.Millisecond
	}
	if c.MinBackoff <= 0 {
		c.MinBackoff = time.Second
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = 30 * time.Second
	}
	if c.MaxBackoff < c.MinBackoff {
		return errors.New("agent reconnect max backoff is smaller than min backoff")
	}
	if c.clock == nil {
		c.clock = time.Now
	}
	if c.MinProtocolVersion == "" {
		c.MinProtocolVersion = v1.PreviousProtocolVersion
	}
	if c.MaxProtocolVersion == "" {
		c.MaxProtocolVersion = v1.ProtocolVersion
	}
	if _, err := v1.NegotiateProtocol(c.MinProtocolVersion, c.MaxProtocolVersion, v1.SupportedAgentVersions); err != nil {
		return err
	}
	return nil
}

func (c *Client) Run(ctx context.Context) error {
	if err := c.normalize(); err != nil {
		return err
	}
	backoff := c.MinBackoff
	connected := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !connected {
			if err := c.connect(ctx); err != nil {
				if err := waitBackoff(ctx, backoff); err != nil {
					return err
				}
				backoff = nextBackoff(backoff, c.MaxBackoff)
				continue
			}
			connected = true
			backoff = c.MinBackoff
		}
		if err := c.pollOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err := waitBackoff(ctx, backoff); err != nil {
				return err
			}
			connected = false
			backoff = nextBackoff(backoff, c.MaxBackoff)
			continue
		}
		if !c.heartbeatDue() {
			continue
		}
		if err := c.sendHeartbeat(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err := waitBackoff(ctx, backoff); err != nil {
				return err
			}
			connected = false
			backoff = nextBackoff(backoff, c.MaxBackoff)
		}
	}
}

func (c *Client) connect(ctx context.Context) error {
	c.mu.Lock()
	previousSessionID := c.sessionID
	c.mu.Unlock()
	var response ConnectResponse
	if err := c.postJSON(ctx, "/v1/agent/connect", ConnectRequest{Hello: c.Hello, MinVersion: c.MinProtocolVersion, MaxVersion: c.MaxProtocolVersion}, &response); err != nil {
		return err
	}
	if response.SessionID == "" {
		return errors.New("control plane returned an empty agent session")
	}
	if response.NegotiatedVersion == "" {
		response.NegotiatedVersion = v1.PreviousProtocolVersion
		response.DisabledCapabilities = append(response.DisabledCapabilities, "agent_sequence", "observation_details", v1.AgentCapabilityRuntimeDeployGroup, v1.AgentCapabilityRuntimeObserveGroup, v1.AgentCapabilityRuntimeRollbackGroup, v1.AgentCapabilityRuntimeDestroyGroup)
	}
	negotiatedVersion, err := v1.NormalizeProtocolVersion(response.NegotiatedVersion)
	if err != nil {
		return errors.New("control plane returned an invalid negotiated Agent version")
	}
	advertised := make(map[string]struct{}, len(c.Hello.Capabilities))
	for _, capability := range c.Hello.Capabilities {
		advertised[strings.TrimSpace(capability)] = struct{}{}
	}
	for _, capability := range response.EnabledCapabilities {
		if _, ok := advertised[capability]; !ok {
			return errors.New("control plane enabled an Agent capability that was not advertised")
		}
		if v1.IsAggregateRuntimeCapability(capability) && negotiatedVersion != v1.ProtocolVersion {
			return errors.New("control plane enabled aggregate runtime on an incompatible Agent protocol")
		}
	}
	c.mu.Lock()
	if previousSessionID != "" && response.SessionID != previousSessionID {
		// The control plane restarted and its in-memory queue generation reset.
		// Durable database leases will re-enqueue unacknowledged work, so the
		// Agent must reset its transport cursor rather than polling past it.
		c.cursor = 0
	}
	c.sessionID = response.SessionID
	c.heartbeatInterval = time.Duration(response.HeartbeatSeconds) * time.Second
	c.negotiatedVersion = negotiatedVersion
	c.disabledCapabilities = append([]string(nil), response.DisabledCapabilities...)
	c.enabledCapabilities = append([]string(nil), response.EnabledCapabilities...)
	if c.heartbeatInterval <= 0 {
		c.heartbeatInterval = time.Second
	}
	c.mu.Unlock()
	return nil
}

func (c *Client) pollOnce(ctx context.Context) error {
	c.mu.Lock()
	request := PollRequest{SessionID: c.sessionID, After: c.cursor, WaitMS: int(c.PollWait / time.Millisecond)}
	c.mu.Unlock()
	var response PollResponse
	if err := c.postJSON(ctx, "/v1/agent/poll", request, &response); err != nil {
		return err
	}
	for _, item := range response.Items {
		c.mu.Lock()
		current := c.cursor
		c.mu.Unlock()
		if item.Cursor <= current {
			continue
		}
		if item.Cursor != current+1 {
			return errors.New("control-plane task cursor is not contiguous")
		}
		if expiredTaskEnvelope(item.Envelope, c.clock().UTC()) {
			c.mu.Lock()
			c.cursor = item.Cursor
			c.mu.Unlock()
			continue
		}
		outgoing, err := c.handleControlEnvelope(ctx, item.Envelope)
		if err != nil {
			return err
		}
		if len(outgoing) > 0 {
			if err := c.sendEvents(ctx, outgoing); err != nil {
				return err
			}
		}
		c.mu.Lock()
		c.cursor = item.Cursor
		c.mu.Unlock()
	}
	return nil
}

func (c *Client) handleControlEnvelope(ctx context.Context, envelope v1.Envelope) ([]v1.Envelope, error) {
	if envelope.Kind != v1.KindTaskRequest {
		return c.Handler.HandleControlEnvelope(ctx, envelope)
	}
	c.mu.Lock()
	interval := c.heartbeatInterval / 2
	c.mu.Unlock()
	if interval <= 0 || interval > time.Second {
		interval = time.Second
	}
	heartbeatCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				// Task results remain authoritative. A transient heartbeat error is
				// retried by the normal reconnect loop after the handler returns.
				_ = c.sendHeartbeat(heartbeatCtx)
			}
		}
	}()
	outgoing, err := c.Handler.HandleControlEnvelope(ctx, envelope)
	cancel()
	<-done
	return outgoing, err
}

func expiredTaskEnvelope(envelope v1.Envelope, now time.Time) bool {
	if envelope.Kind != v1.KindTaskRequest {
		return false
	}
	var task v1.TaskRequest
	if json.Unmarshal(envelope.Payload, &task) != nil || task.Deadline.IsZero() {
		return false
	}
	return !now.Before(task.Deadline)
}

func (c *Client) sendHeartbeat(ctx context.Context) error {
	c.mu.Lock()
	c.heartbeat++
	sequence := c.heartbeat
	sessionID := c.sessionID
	c.mu.Unlock()
	payload, err := json.Marshal(v1.Heartbeat{InstanceID: c.Hello.InstanceID, NodeID: c.Hello.NodeID, Sequence: sequence, At: c.clock().UTC()})
	if err != nil {
		return err
	}
	messageID, err := domain.NewID("agent_message")
	if err != nil {
		return err
	}
	c.mu.Lock()
	negotiatedVersion := c.negotiatedVersion
	c.mu.Unlock()
	envelope := v1.Envelope{Protocol: v1.ProtocolName, Version: negotiatedVersion, MessageID: messageID.String(), InstanceID: c.Hello.InstanceID, NodeID: c.Hello.NodeID, Kind: v1.KindHeartbeat, SentAt: c.clock().UTC(), Payload: payload}
	if err := c.postJSON(ctx, "/v1/agent/events", EventBatch{SessionID: sessionID, Events: []v1.Envelope{envelope}}, nil); err != nil {
		return err
	}
	c.mu.Lock()
	c.lastHeartbeat = c.clock().UTC()
	c.mu.Unlock()
	return nil
}

func (c *Client) heartbeatDue() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastHeartbeat.IsZero() || c.clock().UTC().Sub(c.lastHeartbeat) >= c.heartbeatInterval
}

func (c *Client) sendEvents(ctx context.Context, events []v1.Envelope) error {
	c.mu.Lock()
	sessionID := c.sessionID
	negotiatedVersion := c.negotiatedVersion
	c.mu.Unlock()
	compatible := make([]v1.Envelope, len(events))
	for index, event := range events {
		downgraded, _, err := v1.DowngradeEnvelope(event, negotiatedVersion)
		if err != nil {
			return err
		}
		compatible[index] = downgraded
	}
	return c.postJSON(ctx, "/v1/agent/events", EventBatch{SessionID: sessionID, Events: compatible}, nil)
}

func (c *Client) postJSON(ctx context.Context, path string, input, output any) error {
	encoded, err := json.Marshal(input)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.HTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("agent gateway %s returned %s", path, response.Status)
	}
	if output != nil {
		if err := json.NewDecoder(response.Body).Decode(output); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) Cursor() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cursor
}

func (c *Client) NegotiatedVersion() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.negotiatedVersion
}

func (c *Client) DisabledCapabilities() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.disabledCapabilities...)
}

func (c *Client) EnabledCapabilities() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.enabledCapabilities...)
}

func nextBackoff(current, maximum time.Duration) time.Duration {
	next := current * 2
	if next > maximum {
		return maximum
	}
	return next
}

func waitBackoff(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
