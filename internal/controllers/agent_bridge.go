package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type AgentTaskQueue interface {
	Enqueue(instanceID, nodeID string, envelope v1.Envelope) (uint64, error)
}

type AgentDispatchStore interface {
	ExpireExhaustedControllerTask(context.Context, time.Time, int) (bool, error)
	ClaimControllerTask(context.Context, postgres.ClaimTaskRequest) (postgres.ControllerTask, bool, error)
	FailControllerTask(context.Context, postgres.FailControllerTaskRequest) (postgres.FinishControllerTaskResult, error)
}

type AgentTaskSpec struct {
	Kind       v1.TaskKind     `json:"kind"`
	Parameters json.RawMessage `json:"parameters"`
}

type AgentDispatcher struct {
	Store         AgentDispatchStore
	Queue         AgentTaskQueue
	InstanceID    string
	NodeID        string
	LeaseDuration time.Duration
	TaskTimeout   time.Duration
	MaxAttempts   int
	Clock         func() time.Time
}

func (d *AgentDispatcher) DispatchOne(ctx context.Context) (bool, error) {
	if d.Store == nil || d.Queue == nil || strings.TrimSpace(d.InstanceID) == "" || strings.TrimSpace(d.NodeID) == "" {
		return false, errors.New("Agent dispatcher requires store, queue, instance and node")
	}
	if d.LeaseDuration <= 0 {
		d.LeaseDuration = 30 * time.Second
	}
	if d.MaxAttempts <= 0 {
		d.MaxAttempts = 3
	}
	if d.TaskTimeout <= d.LeaseDuration {
		d.TaskTimeout = 5 * time.Minute
	}
	if d.Clock == nil {
		d.Clock = time.Now
	}
	now := d.Clock().UTC()
	if expired, err := d.Store.ExpireExhaustedControllerTask(ctx, now, d.MaxAttempts); err != nil {
		return false, err
	} else if expired {
		return true, nil
	}
	claimed, ok, err := d.Store.ClaimControllerTask(ctx, postgres.ClaimTaskRequest{Owner: d.NodeID, Now: now, Kinds: dispatchableAgentTaskKinds(), LeasePolicy: postgres.LeasePolicy{Duration: d.LeaseDuration, MaxAttempts: d.MaxAttempts}})
	if err != nil || !ok {
		return ok, err
	}
	var spec AgentTaskSpec
	if err := json.Unmarshal(claimed.Task.Payload, &spec); err != nil {
		_, failErr := d.Store.FailControllerTask(ctx, postgres.FailControllerTaskRequest{TaskID: claimed.Task.ID, Owner: d.NodeID, Now: now, Retryable: false, FailureReason: "durable Agent task payload is not valid JSON"})
		if failErr != nil {
			return true, failErr
		}
		return true, errors.New("durable task payload JSON is not dispatchable")
	}
	if !dispatchableAgentTaskKind(spec.Kind) {
		_, failErr := d.Store.FailControllerTask(ctx, postgres.FailControllerTaskRequest{TaskID: claimed.Task.ID, Owner: d.NodeID, Now: now, Retryable: false, FailureReason: "durable Agent task kind is not allowlisted"})
		if failErr != nil {
			return true, failErr
		}
		return true, errors.New("durable task kind is not dispatchable")
	}
	if len(spec.Parameters) == 0 {
		_, failErr := d.Store.FailControllerTask(ctx, postgres.FailControllerTaskRequest{TaskID: claimed.Task.ID, Owner: d.NodeID, Now: now, Retryable: false, FailureReason: "durable task payload is not a valid allowlisted Agent task"})
		if failErr != nil {
			return true, failErr
		}
		return true, errors.New("durable task payload is not dispatchable")
	}
	wireIdempotencyKey := agentTaskWireIdempotency(claimed.Task.Payload, claimed.Operation.IdempotencyKey)
	if strings.TrimSpace(wireIdempotencyKey) == "" {
		_, failErr := d.Store.FailControllerTask(ctx, postgres.FailControllerTaskRequest{TaskID: claimed.Task.ID, Owner: d.NodeID, Now: now, Retryable: false, FailureReason: "durable task idempotency identity is missing"})
		if failErr != nil {
			return true, failErr
		}
		return true, errors.New("durable task idempotency identity is not dispatchable")
	}
	task := v1.TaskRequest{TaskID: claimed.Task.ID.String(), InstanceID: d.InstanceID, NodeID: d.NodeID, Kind: spec.Kind, IdempotencyKey: wireIdempotencyKey, LeaseID: fmt.Sprintf("%s:%d", claimed.Task.ID, claimed.Task.Attempt), Parameters: append(json.RawMessage(nil), spec.Parameters...), Deadline: now.Add(d.TaskTimeout)}
	payload, err := json.Marshal(task)
	if err != nil {
		return true, err
	}
	messageID, err := domain.NewID("control_message")
	if err != nil {
		return true, err
	}
	envelope := v1.Envelope{Protocol: v1.ProtocolName, Version: v1.ProtocolVersion, MessageID: messageID.String(), InstanceID: d.InstanceID, NodeID: d.NodeID, Kind: v1.KindTaskRequest, SentAt: now, IdempotencyKey: task.IdempotencyKey, Payload: payload}
	if _, err := d.Queue.Enqueue(d.InstanceID, d.NodeID, envelope); err != nil {
		retryable := !errors.Is(err, v1.ErrCapabilityUnavailable)
		failureReason := "Agent task delivery failed"
		if !retryable {
			failureReason = "Agent lacks the required task capability"
		}
		_, failErr := d.Store.FailControllerTask(ctx, postgres.FailControllerTaskRequest{TaskID: claimed.Task.ID, Owner: d.NodeID, Now: now, Retryable: retryable, FailureReason: failureReason})
		if failErr != nil {
			return true, fmt.Errorf("enqueue Agent task: %v; persist retry: %w", err, failErr)
		}
		return true, err
	}
	return true, nil
}

func dispatchableAgentTaskKind(kind v1.TaskKind) bool {
	switch kind {
	case v1.TaskObserve, v1.TaskDeploy, v1.TaskDeployGroup, v1.TaskDestroyGroup, v1.TaskDestroyVolume, v1.TaskLogs, v1.TaskRestart, v1.TaskScale, v1.TaskRollback, v1.TaskDestroy:
		return true
	default:
		return false
	}
}

func dispatchableAgentTaskKinds() []string {
	return []string{
		string(v1.TaskObserve), string(v1.TaskDeploy), string(v1.TaskDeployGroup),
		string(v1.TaskDestroyGroup), string(v1.TaskDestroyVolume), string(v1.TaskLogs),
		string(v1.TaskRestart), string(v1.TaskScale), string(v1.TaskRollback), string(v1.TaskDestroy),
	}
}

func agentTaskWireIdempotency(payload json.RawMessage, fallback string) string {
	var task AgentTaskSpec
	if json.Unmarshal(payload, &task) != nil {
		return strings.TrimSpace(fallback)
	}
	var direct struct {
		Operation contracts.OperationContext `json:"operation"`
		Request   json.RawMessage            `json:"request"`
	}
	if json.Unmarshal(task.Parameters, &direct) != nil {
		return strings.TrimSpace(fallback)
	}
	if key := strings.TrimSpace(direct.Operation.IdempotencyKey); key != "" {
		return key
	}
	if len(direct.Request) > 0 {
		var wrapped struct {
			Operation contracts.OperationContext `json:"operation"`
		}
		if json.Unmarshal(direct.Request, &wrapped) == nil {
			if key := strings.TrimSpace(wrapped.Operation.IdempotencyKey); key != "" {
				return key
			}
		}
	}
	return strings.TrimSpace(fallback)
}

type AgentResultStore interface {
	GetControllerTask(context.Context, domain.ID) (postgres.ControllerTask, error)
	StartControllerTask(context.Context, domain.ID, string, time.Time) (application.Event, error)
	RecordAgentEvent(context.Context, postgres.AgentEventRequest) (postgres.AgentEventResult, error)
	FinishControllerTask(context.Context, postgres.FinishControllerTaskRequest) (postgres.FinishControllerTaskResult, error)
	FailControllerTask(context.Context, postgres.FailControllerTaskRequest) (postgres.FinishControllerTaskResult, error)
}

type DurableAgentSink struct {
	Store     AgentResultStore
	Projector AgentEvidenceProjector
	Clock     func() time.Time
}

// AgentEvidenceProjector is invoked after the immutable Agent event has been
// persisted. Implementations must be idempotent by task/event sequence so a
// gateway retry after a control-plane restart cannot duplicate logs or metric
// samples.
type AgentEvidenceProjector interface {
	ProjectAgentEvidence(context.Context, postgres.ControllerTask, v1.Envelope) error
}

func (s *DurableAgentSink) RecordAgentEnvelope(ctx context.Context, envelope v1.Envelope) error {
	if s.Store == nil {
		return errors.New("durable Agent sink store is required")
	}
	if err := v1.ValidateEnvelopePayload(envelope); err != nil {
		return err
	}
	if envelope.Kind == v1.KindHeartbeat {
		return nil
	}
	wireVersion, err := v1.NormalizeProtocolVersion(envelope.Version)
	if err != nil {
		return err
	}
	if envelope.AgentSequence == 0 {
		if wireVersion == v1.PreviousProtocolVersion {
			return errors.New("Agent 1.0 connection is compatible for heartbeat/readiness but durable task events require agent_sequence capability")
		}
		return errors.New("durable Agent task event sequence is required")
	}
	if s.Clock == nil {
		s.Clock = time.Now
	}
	now := s.Clock().UTC()
	taskID, idempotencyKey, evidence, result, err := decodeAgentTaskEnvelope(envelope)
	if err != nil {
		return err
	}
	task, err := s.Store.GetControllerTask(ctx, taskID)
	if err != nil {
		return err
	}
	// A process-restarted Agent may replay an envelope that was queued before
	// the durable lease reached a terminal state. The envelope has already
	// passed wire validation and identity decoding; acknowledge it without
	// mutating terminal state so one stale cursor cannot poison reconnection.
	if task.Operation.Status.IsTerminal() {
		return nil
	}
	expectedIdempotencyKey := agentTaskWireIdempotency(task.Task.Payload, task.Operation.IdempotencyKey)
	if expectedIdempotencyKey != idempotencyKey || envelope.NodeID != task.Task.LeaseOwner && !task.Operation.Status.IsTerminal() {
		return errors.New("Agent event does not match durable task identity or lease owner")
	}
	if envelope.Kind == v1.KindTaskAck {
		var ack v1.TaskAck
		if err := json.Unmarshal(envelope.Payload, &ack); err != nil {
			return err
		}
		if ack.Status == v1.AckAccepted || ack.Status == v1.AckDuplicate {
			if _, err := s.Store.StartControllerTask(ctx, taskID, envelope.NodeID, now); err != nil {
				return err
			}
		}
	}
	disabled := []string{}
	if wireVersion == v1.PreviousProtocolVersion {
		disabled = []string{"agent_sequence", "observation_details"}
	}
	compatibilityReport, _ := json.Marshal(map[string]any{"negotiated_version": wireVersion, "disabled_capabilities": disabled})
	if _, err := s.Store.RecordAgentEvent(ctx, postgres.AgentEventRequest{TaskID: taskID, Owner: envelope.NodeID, Now: now, Sequence: envelope.AgentSequence, Kind: string(envelope.Kind), Payload: envelope.Payload, WireVersion: wireVersion, CompatibilityReport: compatibilityReport, DisabledCapabilities: disabled}); err != nil {
		return err
	}
	if s.Projector != nil {
		if err := s.Projector.ProjectAgentEvidence(ctx, task, envelope); err != nil {
			return err
		}
	}
	if envelope.Kind == v1.KindTaskAck {
		var ack v1.TaskAck
		_ = json.Unmarshal(envelope.Payload, &ack)
		if ack.Status == v1.AckRejected {
			_, err := s.Store.FailControllerTask(ctx, postgres.FailControllerTaskRequest{TaskID: taskID, Owner: envelope.NodeID, Now: now, Retryable: false, FailureReason: ack.Reason})
			return err
		}
	}
	if result != nil {
		_, err := s.Store.FinishControllerTask(ctx, finishRequestForAgentResult(task, envelope.NodeID, now, *result, evidence))
		return err
	}
	return nil
}

func decodeAgentTaskEnvelope(envelope v1.Envelope) (domain.ID, string, []string, *v1.TaskResult, error) {
	switch envelope.Kind {
	case v1.KindTaskAck:
		var value v1.TaskAck
		if err := json.Unmarshal(envelope.Payload, &value); err != nil {
			return "", "", nil, nil, err
		}
		return domain.ID(value.TaskID), envelope.IdempotencyKey, nil, nil, nil
	case v1.KindLogChunk:
		var value v1.LogChunk
		if err := json.Unmarshal(envelope.Payload, &value); err != nil {
			return "", "", nil, nil, err
		}
		return domain.ID(value.TaskID), envelope.IdempotencyKey, nil, nil, nil
	case v1.KindObservation:
		var value v1.Observation
		if err := json.Unmarshal(envelope.Payload, &value); err != nil {
			return "", "", nil, nil, err
		}
		return domain.ID(value.TaskID), envelope.IdempotencyKey, append([]string(nil), value.EvidenceRefs...), nil, nil
	case v1.KindTaskResult:
		var value v1.TaskResult
		if err := json.Unmarshal(envelope.Payload, &value); err != nil {
			return "", "", nil, nil, err
		}
		return domain.ID(value.TaskID), value.IdempotencyKey, append([]string(nil), value.EvidenceRefs...), &value, nil
	default:
		return "", "", nil, nil, fmt.Errorf("Agent envelope kind %s is not a durable task event", envelope.Kind)
	}
}

func finishRequestForAgentResult(task postgres.ControllerTask, owner string, now time.Time, result v1.TaskResult, evidence []string) postgres.FinishControllerTaskRequest {
	outcome := postgres.ControllerTaskFailed
	if result.Status == v1.TaskResultCancelled {
		outcome = postgres.ControllerTaskCancelled
	} else if result.Succeeded {
		outcome = postgres.ControllerTaskSucceeded
		if task.Operation.Type == domain.OperationRollback {
			outcome = postgres.ControllerTaskRolledBack
		}
	}
	return postgres.FinishControllerTaskRequest{TaskID: task.Task.ID, Owner: owner, Now: now, Outcome: outcome, DeferOperationTerminal: result.Succeeded && m4DeferredTask(task.Task.Payload), FailureReason: result.ErrorMessage, EvidenceIDs: evidence, EffectUnknown: result.ErrorCode == "runtime_effect_unknown"}
}

func m4DeferredTask(payload json.RawMessage) bool {
	if m4ReplacementTask(payload) {
		return true
	}
	var task AgentTaskSpec
	if json.Unmarshal(payload, &task) != nil || task.Kind != v1.TaskDestroyGroup {
		return false
	}
	var request contracts.DestroyRequest
	return json.Unmarshal(task.Parameters, &request) == nil && request.PreserveVolumes && request.ConfirmationToken == "" && strings.HasPrefix(request.Operation.IdempotencyKey, "m4-cleanup:") && request.DeploymentID.String() != ""
}

// m4ReplacementTask detects only the typed aggregate replacement payloads.
// It intentionally defaults to false: unknown or legacy task forms retain the
// established terminal semantics rather than silently gaining a new privilege.
func m4ReplacementTask(payload json.RawMessage) bool {
	var task AgentTaskSpec
	if json.Unmarshal(payload, &task) != nil || (task.Kind != v1.TaskDeploy && task.Kind != v1.TaskRollback) {
		return false
	}
	var marker struct {
		PayloadType string `json:"m4_payload_type"`
	}
	if json.Unmarshal(task.Parameters, &marker) != nil {
		return false
	}
	return marker.PayloadType == "service_group.redeploy" || marker.PayloadType == "service_group.rollback"
}
