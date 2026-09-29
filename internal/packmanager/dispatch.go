package packmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	contracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/packprotocol"
)

type ProtocolDispatcher struct {
	timeout time.Duration
}

func NewProtocolDispatcher(timeout time.Duration) *ProtocolDispatcher {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &ProtocolDispatcher{
		timeout: timeout,
	}
}

func (d *ProtocolDispatcher) getClient(inst contracts.PackProtocolInstance) *UnixHTTPClient {
	validator := func(pid int32, uid uint32) error {
		return VerifyProcessIdentity(pid, uid, inst.ExecutableSHA256, inst.ProcessStartTime)
	}
	return NewUnixHTTPClient(inst.SocketPath, inst.ExpectedPID, inst.ExpectedUID, validator, d.timeout)
}

func (d *ProtocolDispatcher) getClientFromAuth(auth contracts.PackProtocolDispatchAuthorization) *UnixHTTPClient {
	validator := func(pid int32, uid uint32) error {
		return VerifyProcessIdentity(pid, uid, auth.ExecutableSHA256, auth.ProcessStartTime)
	}
	return NewUnixHTTPClient(auth.SocketPath, auth.ExpectedPID, auth.ExpectedUID, validator, d.timeout)
}

func (d *ProtocolDispatcher) CheckHealth(ctx context.Context, inst contracts.PackProtocolInstance) (packprotocol.HealthResponse, error) {
	return d.CheckReadiness(ctx, inst, []string{packprotocol.CapabilityDiagnosticObserve})
}

func (d *ProtocolDispatcher) CheckReadiness(ctx context.Context, inst contracts.PackProtocolInstance, expectedCapabilities []string) (packprotocol.HealthResponse, error) {
	return d.CheckReadinessWithValidator(ctx, inst, expectedCapabilities, nil)
}

func (d *ProtocolDispatcher) CheckReadinessWithValidator(ctx context.Context, inst contracts.PackProtocolInstance, expectedCapabilities []string, customValidator func(pid int32, uid uint32) error) (packprotocol.HealthResponse, error) {
	validator := func(pid int32, uid uint32) error {
		if customValidator != nil {
			return customValidator(pid, uid)
		}
		return VerifyProcessIdentity(pid, uid, inst.ExecutableSHA256, inst.ProcessStartTime)
	}
	client := NewUnixHTTPClient(inst.SocketPath, inst.ExpectedPID, inst.ExpectedUID, validator, d.timeout)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v1/health", nil)
	if err != nil {
		return packprotocol.HealthResponse{}, err
	}
	resp, body, err := client.Do(httpReq)
	if err != nil {
		return packprotocol.HealthResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return packprotocol.HealthResponse{}, fmt.Errorf("health check returned status %d", resp.StatusCode)
	}
	health, err := packprotocol.ParseHealthResponse(body)
	if err != nil {
		return health, err
	}

	// Strictly verify health identity and capabilities against expected instance
	if health.PackID != inst.PackID || health.Version != inst.Version || health.InstanceID != inst.InstanceID {
		return health, errors.New("health response identity mismatch with registered instance")
	}

	for _, reqCap := range expectedCapabilities {
		capFound := false
		for _, c := range health.Capabilities {
			if c == reqCap {
				capFound = true
				break
			}
		}
		if !capFound {
			return health, fmt.Errorf("health response missing required capability: %s", reqCap)
		}
	}

	return health, nil
}

func (d *ProtocolDispatcher) DispatchTask(ctx context.Context, inst contracts.PackProtocolInstance, req packprotocol.ObserveTaskRequest) error {
	raw, err := json.Marshal(req)
	if err != nil {
		return err
	}
	client := d.getClient(inst)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/tasks/observe", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, _, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("task dispatch returned status %d", resp.StatusCode)
	}
	return nil
}

func (d *ProtocolDispatcher) dispatchTaskWithClient(ctx context.Context, client *UnixHTTPClient, req packprotocol.ObserveTaskRequest) error {
	raw, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/tasks/observe", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, _, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("task dispatch returned status %d", resp.StatusCode)
	}
	return nil
}

func (d *ProtocolDispatcher) PollEvent(ctx context.Context, inst contracts.PackProtocolInstance, taskID string) (packprotocol.ObserveTaskEvent, error) {
	client := d.getClient(inst)
	u := fmt.Sprintf("http://unix/v1/tasks/events?task_id=%s", url.QueryEscape(taskID))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return packprotocol.ObserveTaskEvent{}, err
	}
	resp, body, err := client.Do(httpReq)
	if err != nil {
		return packprotocol.ObserveTaskEvent{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return packprotocol.ObserveTaskEvent{}, fmt.Errorf("poll event returned status %d", resp.StatusCode)
	}
	return packprotocol.ParseObserveTaskEvent(body)
}

func (d *ProtocolDispatcher) pollEventWithClient(ctx context.Context, client *UnixHTTPClient, taskID string) (packprotocol.ObserveTaskEvent, error) {
	u := fmt.Sprintf("http://unix/v1/tasks/events?task_id=%s", url.QueryEscape(taskID))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return packprotocol.ObserveTaskEvent{}, err
	}
	resp, body, err := client.Do(httpReq)
	if err != nil {
		return packprotocol.ObserveTaskEvent{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return packprotocol.ObserveTaskEvent{}, fmt.Errorf("poll event returned status %d", resp.StatusCode)
	}
	return packprotocol.ParseObserveTaskEvent(body)
}

func (d *ProtocolDispatcher) AcknowledgeReceipt(ctx context.Context, inst contracts.PackProtocolInstance, ack packprotocol.ObserveTaskAck) error {
	raw, err := json.Marshal(ack)
	if err != nil {
		return err
	}
	client := d.getClient(inst)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/tasks/ack", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, _, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ack returned status %d", resp.StatusCode)
	}
	return nil
}

func (d *ProtocolDispatcher) acknowledgeReceiptWithClient(ctx context.Context, client *UnixHTTPClient, ack packprotocol.ObserveTaskAck) error {
	raw, err := json.Marshal(ack)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/tasks/ack", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, _, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ack returned status %d", resp.StatusCode)
	}
	return nil
}

func (d *ProtocolDispatcher) RequestCancel(ctx context.Context, inst contracts.PackProtocolInstance, req packprotocol.CancelTaskRequest) (packprotocol.CancelTaskResponse, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return packprotocol.CancelTaskResponse{}, err
	}
	client := d.getClient(inst)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/tasks/cancel", bytes.NewReader(raw))
	if err != nil {
		return packprotocol.CancelTaskResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, body, err := client.Do(httpReq)
	if err != nil {
		return packprotocol.CancelTaskResponse{}, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return packprotocol.CancelTaskResponse{}, fmt.Errorf("cancel request returned status %d", resp.StatusCode)
	}
	return packprotocol.ParseCancelTaskResponse(body)
}

func (d *ProtocolDispatcher) ExecuteDiagnosticRoundtrip(
	ctx context.Context,
	repo contracts.PackExecutionRepository,
	inst contracts.PackProtocolInstance,
	task contracts.Task,
	input contracts.DiagnosticInputContext,
	audit contracts.AuditContext,
) (contracts.PackProtocolReceipt, error) {
	now := time.Now().UTC()

	// 1. Authoritative preflight query directly from store immediately before any send
	auth, err := repo.AuthorizePackProtocolDispatch(ctx, contracts.AuthorizePackProtocolDispatchRequest{
		TaskID:          task.ID,
		InstanceID:      inst.InstanceID,
		Owner:           task.LeaseOwner,
		CoreGeneration:  task.CoreGeneration,
		LeaseGeneration: task.LeaseGeneration,
		Now:             now,
	})
	if err != nil {
		return contracts.PackProtocolReceipt{}, fmt.Errorf("authoritative dispatch authorization failed: %w", err)
	}

	inputDigest, _, err := packprotocol.DigestDiagnosticInput(input)
	if err != nil {
		return contracts.PackProtocolReceipt{}, err
	}
	if auth.InputDigest != inputDigest {
		return contracts.PackProtocolReceipt{}, errors.New("dispatch input digest mismatch with check authorization")
	}

	// Single client instance bound to authoritative connection with in-dial verification
	client := d.getClientFromAuth(auth)

	deadlineTime := now.Add(d.timeout)
	if auth.LeaseUntil.Before(deadlineTime) {
		deadlineTime = auth.LeaseUntil
	}
	deadline := packprotocol.FormatCanonicalTime(deadlineTime)

	req := packprotocol.ObserveTaskRequest{
		Schema:             packprotocol.ProtocolSchemaV1,
		ProtocolVersion:    packprotocol.ProtocolVersion1,
		TaskID:             auth.TaskID.String(),
		OperationID:        auth.OperationID.String(),
		PackID:             auth.PackID,
		InstanceID:         auth.InstanceID,
		InstanceGeneration: auth.InstanceGeneration,
		CoreGeneration:     auth.CoreGeneration,
		LeaseGeneration:    auth.LeaseGeneration,
		Kind:               auth.Kind,
		Capability:         auth.Capability,
		InputDigest:        inputDigest,
		InputContext:       input,
		Deadline:           deadline,
	}

	// 2. Dispatch task to adapter
	if err := d.dispatchTaskWithClient(ctx, client, req); err != nil {
		return contracts.PackProtocolReceipt{}, fmt.Errorf("dispatch task: %w", err)
	}

	// 3. Poll for event with context deadline
	var event packprotocol.ObserveTaskEvent
	pollStart := time.Now()
	for {
		event, err = d.pollEventWithClient(ctx, client, auth.TaskID.String())
		if err == nil {
			break
		}
		if time.Since(pollStart) > d.timeout {
			return contracts.PackProtocolReceipt{}, errors.New("timeout polling for diagnostic observation event")
		}
		select {
		case <-ctx.Done():
			return contracts.PackProtocolReceipt{}, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}

	occurredAt, err := packprotocol.ParseCanonicalTime(event.OccurredAt)
	if err != nil {
		return contracts.PackProtocolReceipt{}, fmt.Errorf("invalid event occurred_at: %w", err)
	}

	var termState contracts.TaskState
	if event.Terminal {
		if event.TerminalStatus == "succeeded" {
			termState = contracts.TaskCompleted
		} else if event.TerminalStatus == "failed" {
			if event.Observation.Status == "cancelled" {
				termState = contracts.TaskCancelled
			} else {
				termState = contracts.TaskFailed
			}
		}
	}

	// 4. Atomic Commit to Core SQLite
	commitReq := contracts.CommitPackProtocolEventRequest{
		TaskID:             auth.TaskID,
		InstanceID:         auth.InstanceID,
		CoreGeneration:     auth.CoreGeneration,
		LeaseGeneration:    auth.LeaseGeneration,
		InstanceGeneration: auth.InstanceGeneration,
		Owner:              auth.LeaseOwner,
		Sequence:           event.Sequence,
		InputDigest:        inputDigest,
		EventDigest:        event.EventDigest,
		Kind:               event.Kind,
		Observation:        event.Observation,
		Terminal:           event.Terminal,
		TerminalStatus:     event.TerminalStatus,
		TerminalState:      termState,
		OccurredAt:         occurredAt,
		Audit:              audit,
		Now:                time.Now().UTC(),
	}

	receipt, err := repo.CommitPackProtocolEvent(ctx, commitReq)
	if err != nil {
		return contracts.PackProtocolReceipt{}, fmt.Errorf("commit pack protocol event: %w", err)
	}

	// 5. Acknowledge Receipt to Adapter
	ack := packprotocol.ObserveTaskAck{
		Schema:      packprotocol.ProtocolSchemaV1,
		ReceiptID:   receipt.ReceiptID,
		TaskID:      auth.TaskID.String(),
		InstanceID:  auth.InstanceID,
		Sequence:    event.Sequence,
		EventDigest: receipt.EventDigest,
		Status:      "persisted",
		CommittedAt: packprotocol.FormatCanonicalTime(receipt.CommittedAt),
	}
	if err := d.acknowledgeReceiptWithClient(ctx, client, ack); err != nil {
		// Receipt committed durable; transport ack warning returned
		return receipt, fmt.Errorf("acknowledge receipt warning: %w", err)
	}

	return receipt, nil
}
