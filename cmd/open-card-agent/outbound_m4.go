package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

const (
	m4MaxLogChunks = 64
	m4MaxLogBytes  = 64 << 10
)

// M4OutboundExecutor is an unattached, typed execution seam for the M4
// operations controller. A composition root may call Execute after its normal
// mTLS task validation; this type deliberately does not broaden outbound.go's
// existing task dispatcher by itself.
type M4OutboundExecutor struct {
	instanceID   string
	nodeID       string
	runtime      contracts.RuntimeDriver
	groupRuntime contracts.ServiceGroupRuntimeDriver
	clock        func() time.Time

	mu      sync.Mutex
	running map[string]*m4OutboundRun
}

type m4OutboundRun struct {
	fingerprint [32]byte
	done        chan struct{}
	result      M4OutboundResult
}

// M4OutboundResult is transport-neutral so callers can wrap its static log,
// observations, and result in their own envelopes without exposing runtime
// implementation output or arbitrary command execution.
type M4OutboundResult struct {
	Logs         []v1.LogChunk
	Observations []v1.Observation
	Result       v1.TaskResult
}

func NewM4OutboundExecutor(instanceID, nodeID string, runtime contracts.RuntimeDriver) *M4OutboundExecutor {
	return &M4OutboundExecutor{instanceID: strings.TrimSpace(instanceID), nodeID: strings.TrimSpace(nodeID), runtime: runtime, clock: time.Now, running: make(map[string]*m4OutboundRun)}
}

// NewM4OutboundExecutorWithGroupRuntime is the composition API for M2
// ServiceGroup operations. The group driver remains distinct from the
// single-service RuntimeDriver, so a group payload cannot silently fall back
// to an arbitrary Docker or shell operation.
func NewM4OutboundExecutorWithGroupRuntime(instanceID, nodeID string, runtime contracts.RuntimeDriver, groupRuntime contracts.ServiceGroupRuntimeDriver) *M4OutboundExecutor {
	executor := NewM4OutboundExecutor(instanceID, nodeID, runtime)
	executor.groupRuntime = groupRuntime
	return executor
}

// M4GroupTaskPayload is a mandatory wrapper for aggregate-runtime actions.
// Marker and Kind must agree; Request is decoded again with unknown fields
// rejected before any provider call.
type M4GroupTaskPayload struct {
	M4PayloadType string          `json:"m4_payload_type"`
	Request       json.RawMessage `json:"request"`
}

type M4GroupServiceRestartRequest = contracts.RestartGroupServiceRequest

// M4GroupServiceRestarter is deliberately optional because the standard M2
// group Driver has no restart method. Implementations may expose this narrow,
// typed effect; no fallback to a command runner is allowed.
type M4GroupServiceRestarter = contracts.ServiceGroupServiceRestarter
type M4GroupRestarter = contracts.ServiceGroupRestarter

// Execute accepts exactly the typed M4 task surface: restart, deploy (the
// controller's redeploy command), rollback, logs, and deployment observation.
// It never accepts a command, shell, path, environment value, or secret.
func (e *M4OutboundExecutor) Execute(ctx context.Context, task v1.TaskRequest) (M4OutboundResult, error) {
	if e == nil {
		return M4OutboundResult{}, errors.New("M4 runtime executor is unavailable")
	}
	if err := task.Validate(); err != nil {
		return M4OutboundResult{}, err
	}
	if task.InstanceID != e.instanceID || task.NodeID != e.nodeID {
		return M4OutboundResult{}, errors.New("M4 task identity mismatch")
	}
	if !task.Deadline.After(e.now()) {
		return M4OutboundResult{}, errors.New("M4 task deadline has elapsed")
	}
	if !m4AllowedTaskKind(task.Kind) {
		return rejectedM4(task, "unsupported_capability", "M4 task kind is not allowlisted"), nil
	}
	encoded, err := json.Marshal(task)
	if err != nil {
		return M4OutboundResult{}, err
	}
	fingerprint := sha256.Sum256(encoded)
	e.mu.Lock()
	if previous := e.running[task.IdempotencyKey]; previous != nil {
		if previous.fingerprint != fingerprint {
			e.mu.Unlock()
			return M4OutboundResult{}, errors.New("M4 task idempotency key conflicts with prior input")
		}
		e.mu.Unlock()
		select {
		case <-previous.done:
			return cloneM4OutboundResult(previous.result), nil
		case <-ctx.Done():
			return M4OutboundResult{}, ctx.Err()
		}
	}
	run := &m4OutboundRun{fingerprint: fingerprint, done: make(chan struct{})}
	e.running[task.IdempotencyKey] = run
	e.mu.Unlock()

	run.result = e.execute(ctx, task)
	close(run.done)
	return cloneM4OutboundResult(run.result), nil
}

func (e *M4OutboundExecutor) execute(ctx context.Context, task v1.TaskRequest) M4OutboundResult {
	taskContext, cancel := context.WithDeadline(ctx, task.Deadline)
	defer cancel()
	if m4GroupMarked(task.Parameters) {
		return e.executeGroup(taskContext, task)
	}
	switch task.Kind {
	case v1.TaskRestart:
		var request contracts.RestartRequest
		if err := m4DecodeTask(task, &request); err != nil || request.DeploymentID.Empty() || strings.TrimSpace(request.ServiceName) == "" {
			return rejectedM4(task, "invalid_argument", "restart parameters are invalid")
		}
		if err := e.require(taskContext, contracts.CapabilityRuntimeRestart); err != nil {
			return failedM4(task, "unsupported_capability", err)
		}
		if err := e.runtime.Restart(taskContext, request); err != nil {
			return failedM4(task, "runtime_restart_failed", err)
		}
		return e.observeAfter(taskContext, task, request.DeploymentID, request.Operation, "service restart completed")
	case v1.TaskDeploy: // M4 redeploy is an immutable, controller-selected DeployRequest.
		var request contracts.DeployRequest
		if err := m4DecodeTask(task, &request); err != nil || !m4ValidDeploy(request) {
			return rejectedM4(task, "invalid_argument", "redeploy parameters are invalid")
		}
		if err := e.require(taskContext, contracts.CapabilityRuntimeDeploy); err != nil {
			return failedM4(task, "unsupported_capability", err)
		}
		deployed, err := e.runtime.Deploy(taskContext, request)
		if err != nil {
			return failedM4(task, "runtime_redeploy_failed", err)
		}
		if deployed.ID != request.DeploymentID || deployed.ReleaseID != request.Spec.ReleaseID || deployed.ApplicationID != request.Spec.ApplicationID || deployed.EnvironmentID != request.Spec.EnvironmentID {
			return failedM4(task, "runtime_identity_mismatch", errors.New("runtime returned deployment outside requested immutable redeploy identity"))
		}
		return e.observeAfter(taskContext, task, request.DeploymentID, request.Operation, "current immutable release redeployed")
	case v1.TaskRollback:
		var request contracts.RollbackRequest
		if err := m4DecodeTask(task, &request); err != nil || request.DeploymentID.Empty() || request.ReleaseID.Empty() {
			return rejectedM4(task, "invalid_argument", "rollback parameters are invalid")
		}
		if err := e.require(taskContext, contracts.CapabilityRuntimeRollback); err != nil {
			return failedM4(task, "unsupported_capability", err)
		}
		deployed, err := e.runtime.Rollback(taskContext, request)
		if err != nil {
			return failedM4(task, "runtime_rollback_failed", err)
		}
		if deployed.ID != request.DeploymentID || deployed.ReleaseID != request.ReleaseID {
			return failedM4(task, "runtime_identity_mismatch", errors.New("runtime returned deployment outside requested rollback identity"))
		}
		return e.observeAfter(taskContext, task, request.DeploymentID, request.Operation, "previous successful release rolled back; persistent data unchanged")
	case v1.TaskObserve:
		var request contracts.ObserveRequest
		if err := m4DecodeTask(task, &request); err != nil || request.DeploymentID.Empty() {
			return rejectedM4(task, "invalid_argument", "runtime observe parameters are invalid")
		}
		return e.observe(taskContext, task, request)
	case v1.TaskLogs:
		var request contracts.LogsRequest
		if err := m4DecodeTask(task, &request); err != nil || request.DeploymentID.Empty() || strings.TrimSpace(request.ServiceName) == "" || request.Tail < 1 || request.Tail > m4MaxLogChunks {
			return rejectedM4(task, "invalid_argument", "runtime logs parameters are invalid")
		}
		return e.logs(taskContext, task, request)
	default:
		return rejectedM4(task, "unsupported_capability", "M4 task kind is not allowlisted")
	}
}

func (e *M4OutboundExecutor) observeAfter(ctx context.Context, task v1.TaskRequest, deploymentID domain.ID, operation contracts.OperationContext, log string) M4OutboundResult {
	operation.IdempotencyKey += ":observe"
	result := e.observe(ctx, task, contracts.ObserveRequest{DeploymentID: deploymentID, Operation: operation})
	if result.Result.Succeeded {
		result.Logs = []v1.LogChunk{{TaskID: task.TaskID, Sequence: 1, Stream: v1.LogStreamStdout, Data: log, Final: true}}
	}
	return result
}

func (e *M4OutboundExecutor) observe(ctx context.Context, task v1.TaskRequest, request contracts.ObserveRequest) M4OutboundResult {
	if err := e.require(ctx, contracts.CapabilityRuntimeObserve); err != nil {
		return failedM4(task, "unsupported_capability", err)
	}
	observation, err := e.runtime.Observe(ctx, request)
	if err != nil {
		return failedM4(task, "runtime_observe_failed", err)
	}
	if observation.DeploymentID != request.DeploymentID {
		return failedM4(task, "runtime_identity_mismatch", errors.New("runtime observation does not match requested deployment"))
	}
	details, err := json.Marshal(observation)
	if err != nil {
		return failedM4(task, "observation_encode_failed", err)
	}
	refs := m4EvidenceRefs(observation.Evidence)
	wire := v1.Observation{TaskID: task.TaskID, Sequence: 1, TargetRef: "deployment/" + request.DeploymentID.String(), Status: observation.Status, Healthy: observation.Healthy, At: observation.ObservedAt.UTC(), EvidenceRefs: refs, Details: json.RawMessage(foundation.RedactText(string(details)))}
	if err := wire.Validate(); err != nil {
		return failedM4(task, "invalid_runtime_observation", err)
	}
	return M4OutboundResult{Observations: []v1.Observation{wire}, Result: successM4(task, refs)}
}

func (e *M4OutboundExecutor) logs(ctx context.Context, task v1.TaskRequest, request contracts.LogsRequest) M4OutboundResult {
	if err := e.require(ctx, contracts.CapabilityRuntimeLogs); err != nil {
		return failedM4(task, "unsupported_capability", err)
	}
	lines, err := e.runtime.Logs(ctx, request)
	if err != nil {
		return failedM4(task, "runtime_logs_failed", err)
	}
	return m4LogLines(ctx, task, lines)
}

func m4LogLines(ctx context.Context, task v1.TaskRequest, lines <-chan string) M4OutboundResult {
	result := M4OutboundResult{Result: successM4(task, nil)}
	remaining := m4MaxLogBytes
	var content strings.Builder
	lineCount := 0
	for lineCount < m4MaxLogChunks && remaining > 0 {
		select {
		case <-ctx.Done():
			return failedM4(task, "runtime_logs_cancelled", ctx.Err())
		case line, ok := <-lines:
			if !ok {
				if content.Len() > 0 {
					result.Logs = []v1.LogChunk{{TaskID: task.TaskID, Sequence: 1, Stream: v1.LogStreamStdout, Data: content.String(), Final: true}}
				}
				return result
			}
			line = foundation.RedactText(line)
			if content.Len() > 0 && remaining > 0 {
				content.WriteByte('\n')
				remaining--
			}
			if len(line) > remaining {
				line = line[:remaining]
			}
			remaining -= len(line)
			content.WriteString(line)
			lineCount++
		}
	}
	if content.Len() > 0 {
		result.Logs = []v1.LogChunk{{TaskID: task.TaskID, Sequence: 1, Stream: v1.LogStreamStdout, Data: content.String(), Final: true}}
	}
	return result
}

func (e *M4OutboundExecutor) require(ctx context.Context, capability contracts.Capability) error {
	if e.runtime == nil {
		return errors.New("single-service runtime capability is unavailable")
	}
	if err := e.runtime.Metadata(ctx).Supports(capability); err != nil {
		return errors.New("runtime capability is unavailable")
	}
	return nil
}

func (e *M4OutboundExecutor) executeGroup(ctx context.Context, task v1.TaskRequest) M4OutboundResult {
	payload, err := m4DecodeGroupPayload(task.Parameters)
	if err != nil {
		return rejectedM4(task, "invalid_argument", "service-group M4 payload is invalid")
	}
	switch payload.M4PayloadType {
	case "service_group.observe":
		if task.Kind != v1.TaskObserve {
			return rejectedM4(task, "invalid_argument", "service-group observe payload requires observe task kind")
		}
		var request contracts.ObserveGroupRequest
		if err := m4DecodeGroupRequest(task, payload.Request, &request); err != nil || request.DeploymentID.Empty() {
			return rejectedM4(task, "invalid_argument", "service-group observe parameters are invalid")
		}
		return e.observeGroup(ctx, task, request)
	case "service_group.logs":
		if task.Kind != v1.TaskLogs {
			return rejectedM4(task, "invalid_argument", "service-group logs payload requires logs task kind")
		}
		var request contracts.LogsRequest
		if err := m4DecodeGroupRequest(task, payload.Request, &request); err != nil || request.DeploymentID.Empty() || strings.TrimSpace(request.ServiceName) == "" || request.Tail < 1 || request.Tail > m4MaxLogChunks {
			return rejectedM4(task, "invalid_argument", "service-group logs parameters are invalid")
		}
		return e.groupLogs(ctx, task, request)
	case "service_group.redeploy":
		if task.Kind != v1.TaskDeploy {
			return rejectedM4(task, "invalid_argument", "service-group redeploy payload requires deploy task kind")
		}
		var request contracts.DeployGroupRequest
		if err := m4DecodeGroupRequest(task, payload.Request, &request); err != nil || request.DeploymentID.Empty() || request.Spec.Validate() != nil || !request.ForceRecreate {
			return rejectedM4(task, "invalid_argument", "service-group redeploy parameters are invalid")
		}
		if err := e.requireGroup(ctx, contracts.CapabilityRuntimeDeployGroup); err != nil {
			return failedM4(task, "unsupported_capability", err)
		}
		deployed, err := e.groupRuntime.DeployGroup(ctx, request)
		if err != nil {
			return failedM4(task, "runtime_group_redeploy_failed", err)
		}
		if deployed.ID != request.DeploymentID || deployed.ReleaseID != request.Spec.ReleaseID || deployed.ApplicationID != request.Spec.ApplicationID || deployed.EnvironmentID != request.Spec.EnvironmentID {
			return failedM4(task, "runtime_identity_mismatch", errors.New("aggregate runtime returned deployment outside requested immutable redeploy identity"))
		}
		return e.observeGroupAfter(ctx, task, request.DeploymentID, request.Operation, "current immutable service-group release redeployed")
	case "service_group.rollback":
		if task.Kind != v1.TaskRollback {
			return rejectedM4(task, "invalid_argument", "service-group rollback payload requires rollback task kind")
		}
		var request contracts.RollbackGroupRequest
		if err := m4DecodeGroupRequest(task, payload.Request, &request); err != nil || request.DeploymentID.Empty() || request.TargetDeploymentID.Empty() || request.DeploymentID == request.TargetDeploymentID || request.Target.Validate() != nil {
			return rejectedM4(task, "invalid_argument", "service-group rollback parameters are invalid")
		}
		if err := e.requireGroup(ctx, contracts.CapabilityRuntimeRollbackGroup); err != nil {
			return failedM4(task, "unsupported_capability", err)
		}
		deployed, err := e.groupRuntime.RollbackGroup(ctx, request)
		if err != nil {
			return failedM4(task, "runtime_group_rollback_failed", err)
		}
		if deployed.ID != request.TargetDeploymentID || deployed.ReleaseID != request.Target.ReleaseID {
			return failedM4(task, "runtime_identity_mismatch", errors.New("aggregate runtime returned deployment outside requested rollback identity"))
		}
		return e.observeGroupAfter(ctx, task, request.TargetDeploymentID, request.Operation, "previous successful service-group release rolled back; persistent data unchanged")
	case "service_group.restart_service":
		if task.Kind != v1.TaskRestart {
			return rejectedM4(task, "invalid_argument", "service-group restart payload requires restart task kind")
		}
		var request M4GroupServiceRestartRequest
		if err := m4DecodeGroupRequest(task, payload.Request, &request); err != nil || request.Validate() != nil {
			return rejectedM4(task, "invalid_argument", "service-group restart parameters are invalid")
		}
		restarter, ok := e.groupRuntime.(M4GroupServiceRestarter)
		if !ok {
			return rejectedM4(task, "unsupported_capability", "service-group runtime does not expose typed service restart")
		}
		if err := restarter.RestartGroupService(ctx, request); err != nil {
			return failedM4(task, "runtime_group_restart_failed", err)
		}
		return e.observeGroupAfter(ctx, task, request.DeploymentID, request.Operation, "service-group service restart completed")
	case "service_group.restart":
		if task.Kind != v1.TaskRestart {
			return rejectedM4(task, "invalid_argument", "service-group restart payload requires restart task kind")
		}
		var request contracts.RestartGroupRequest
		if err := m4DecodeGroupRequest(task, payload.Request, &request); err != nil || request.Validate() != nil {
			return rejectedM4(task, "invalid_argument", "service-group restart parameters are invalid")
		}
		restarter, ok := e.groupRuntime.(M4GroupRestarter)
		if !ok {
			return rejectedM4(task, "unsupported_capability", "service-group runtime does not expose typed group restart")
		}
		if err := restarter.RestartGroup(ctx, request); err != nil {
			return failedM4(task, "runtime_group_restart_failed", err)
		}
		return e.observeGroupAfter(ctx, task, request.DeploymentID, request.Operation, "service-group application restart completed")
	default:
		return rejectedM4(task, "invalid_argument", "service-group M4 payload type is not allowlisted")
	}
}

func (e *M4OutboundExecutor) observeGroupAfter(ctx context.Context, task v1.TaskRequest, deploymentID domain.ID, operation contracts.OperationContext, log string) M4OutboundResult {
	operation.IdempotencyKey += ":observe-group"
	result := e.observeGroup(ctx, task, contracts.ObserveGroupRequest{DeploymentID: deploymentID, Operation: operation})
	if result.Result.Succeeded {
		result.Logs = []v1.LogChunk{{TaskID: task.TaskID, Sequence: 1, Stream: v1.LogStreamStdout, Data: log, Final: true}}
	}
	return result
}

func (e *M4OutboundExecutor) observeGroup(ctx context.Context, task v1.TaskRequest, request contracts.ObserveGroupRequest) M4OutboundResult {
	if err := e.requireGroup(ctx, contracts.CapabilityRuntimeObserveGroup); err != nil {
		return failedM4(task, "unsupported_capability", err)
	}
	observation, err := e.groupRuntime.ObserveGroup(ctx, request)
	if err != nil {
		return failedM4(task, "runtime_group_observe_failed", err)
	}
	if observation.DeploymentID != request.DeploymentID || observation.ReleaseID.Empty() || (observation.Effect != contracts.RuntimeEffectKnown && observation.Effect != contracts.RuntimeEffectUnknown) {
		return failedM4(task, "runtime_identity_mismatch", errors.New("aggregate runtime observation does not match requested deployment"))
	}
	if err := m4RequireIndependentGroupMetrics(observation); err != nil {
		return failedM4(task, "runtime_metrics_unavailable", err)
	}
	details, err := json.Marshal(observation)
	if err != nil {
		return failedM4(task, "observation_encode_failed", err)
	}
	status := observation.Status
	if status == "" {
		status = "unknown"
	}
	healthy := observation.Effect == contracts.RuntimeEffectKnown && (observation.Status == "runtime_ready" || observation.Status == "degraded")
	wire := v1.Observation{TaskID: task.TaskID, Sequence: 1, TargetRef: "deployment/" + request.DeploymentID.String(), Status: status, Healthy: healthy, At: e.now().UTC(), EvidenceRefs: m4EvidenceRefs(observation.Evidence), Details: json.RawMessage(foundation.RedactText(string(details)))}
	if err := wire.Validate(); err != nil {
		return failedM4(task, "invalid_runtime_observation", err)
	}
	return M4OutboundResult{Observations: []v1.Observation{wire}, Result: successM4(task, wire.EvidenceRefs)}
}

func (e *M4OutboundExecutor) groupLogs(ctx context.Context, task v1.TaskRequest, request contracts.LogsRequest) M4OutboundResult {
	if err := e.requireGroup(ctx, contracts.CapabilityRuntimeLogsGroup); err != nil {
		return failedM4(task, "unsupported_capability", err)
	}
	reader, ok := e.groupRuntime.(contracts.ServiceGroupLogReader)
	if !ok {
		return rejectedM4(task, "unsupported_capability", "service-group runtime does not expose typed service logs")
	}
	lines, err := reader.Logs(ctx, request)
	if err != nil {
		return failedM4(task, "runtime_group_logs_failed", err)
	}
	return m4LogLines(ctx, task, lines)
}

func m4RequireIndependentGroupMetrics(observation contracts.ServiceGroupRuntimeObservation) error {
	if observation.Effect != contracts.RuntimeEffectKnown || len(observation.Services) == 0 {
		return errors.New("independent Docker runtime observation is incomplete")
	}
	for _, service := range observation.Services {
		if !service.MetricsKnown || strings.TrimSpace(service.ContainerID) == "" || service.MemoryBytes < 0 || service.DiskBytes < 0 || service.NetworkRxBytes < 0 || service.NetworkTxBytes < 0 || service.CPUUsageMillis < 0 || service.PIDsCurrent < 0 || service.ChangedPaths < 0 {
			return errors.New("independent Docker runtime metrics are unavailable")
		}
		if service.Status == "running" && !service.CgroupVerified {
			return errors.New("running Docker runtime cgroup limits are unverified")
		}
	}
	return nil
}

func (e *M4OutboundExecutor) requireGroup(ctx context.Context, capability contracts.Capability) error {
	if e.groupRuntime == nil {
		return errors.New("service-group runtime capability is unavailable")
	}
	if err := e.groupRuntime.Metadata(ctx).Supports(capability); err != nil {
		return errors.New("service-group runtime capability is unavailable")
	}
	return nil
}

func m4GroupMarked(data json.RawMessage) bool {
	var marker struct {
		M4PayloadType string `json:"m4_payload_type"`
	}
	return json.Unmarshal(data, &marker) == nil && strings.TrimSpace(marker.M4PayloadType) != ""
}

func m4DecodeGroupPayload(data json.RawMessage) (M4GroupTaskPayload, error) {
	var payload M4GroupTaskPayload
	if err := m4DecodeStrict(data, &payload); err != nil || strings.TrimSpace(payload.M4PayloadType) == "" || len(payload.Request) == 0 {
		return M4GroupTaskPayload{}, errors.New("service-group M4 payload marker and request are required")
	}
	return payload, nil
}

func m4DecodeGroupRequest(task v1.TaskRequest, data json.RawMessage, target any) error {
	if err := m4DecodeStrict(data, target); err != nil {
		return err
	}
	operation, err := m4GroupTaskOperation(target)
	if err != nil {
		return err
	}
	if err := operation.Validate(); err != nil {
		return err
	}
	if operation.IdempotencyKey != task.IdempotencyKey {
		return errors.New("service-group M4 task operation idempotency identity mismatch")
	}
	if operation.Deadline.IsZero() || operation.Deadline.After(task.Deadline) {
		operation.Deadline = task.Deadline
		m4SetGroupTaskOperation(target, operation)
	}
	return nil
}

func m4GroupTaskOperation(target any) (contracts.OperationContext, error) {
	switch request := target.(type) {
	case *contracts.DeployGroupRequest:
		return request.Operation, nil
	case *contracts.ObserveGroupRequest:
		return request.Operation, nil
	case *contracts.LogsRequest:
		return request.Operation, nil
	case *contracts.RollbackGroupRequest:
		return request.Operation, nil
	case *M4GroupServiceRestartRequest:
		return request.Operation, nil
	default:
		return contracts.OperationContext{}, errors.New("service-group M4 task parameter type is unsupported")
	}
}

func m4SetGroupTaskOperation(target any, operation contracts.OperationContext) {
	switch request := target.(type) {
	case *contracts.DeployGroupRequest:
		request.Operation = operation
	case *contracts.ObserveGroupRequest:
		request.Operation = operation
	case *contracts.LogsRequest:
		request.Operation = operation
	case *contracts.RollbackGroupRequest:
		request.Operation = operation
	case *M4GroupServiceRestartRequest:
		request.Operation = operation
	}
}

func (e *M4OutboundExecutor) now() time.Time {
	if e.clock == nil {
		return time.Now()
	}
	return e.clock()
}

func m4DecodeTask(task v1.TaskRequest, target any) error {
	if err := m4DecodeStrict(task.Parameters, target); err != nil {
		return err
	}
	operation, err := m4TaskOperation(target)
	if err != nil {
		return err
	}
	if err := operation.Validate(); err != nil {
		return err
	}
	if operation.IdempotencyKey != task.IdempotencyKey {
		return errors.New("M4 task operation idempotency identity mismatch")
	}
	if operation.Deadline.IsZero() || operation.Deadline.After(task.Deadline) {
		operation.Deadline = task.Deadline
		m4SetTaskOperation(target, operation)
	}
	return nil
}

func m4ValidDeploy(request contracts.DeployRequest) bool {
	if request.DeploymentID.Empty() || request.Spec.ReleaseID.Empty() || request.Spec.ApplicationID.Empty() || request.Spec.EnvironmentID.Empty() || strings.TrimSpace(request.Spec.ServiceName) == "" || (request.Spec.Port != 0 && (request.Spec.Port < 1 || request.Spec.Port > 65535)) {
		return false
	}
	return request.Spec.Image.Validate() == nil
}

func m4TaskOperation(target any) (contracts.OperationContext, error) {
	switch request := target.(type) {
	case *contracts.RestartRequest:
		return request.Operation, nil
	case *contracts.DeployRequest:
		return request.Operation, nil
	case *contracts.RollbackRequest:
		return request.Operation, nil
	case *contracts.ObserveRequest:
		return request.Operation, nil
	case *contracts.LogsRequest:
		return request.Operation, nil
	default:
		return contracts.OperationContext{}, errors.New("M4 task parameter type is unsupported")
	}
}

func m4SetTaskOperation(target any, operation contracts.OperationContext) {
	switch request := target.(type) {
	case *contracts.RestartRequest:
		request.Operation = operation
	case *contracts.DeployRequest:
		request.Operation = operation
	case *contracts.RollbackRequest:
		request.Operation = operation
	case *contracts.ObserveRequest:
		request.Operation = operation
	case *contracts.LogsRequest:
		request.Operation = operation
	}
}

func m4DecodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("multiple JSON values are not allowed")
	}
	return nil
}

func m4AllowedTaskKind(kind v1.TaskKind) bool {
	switch kind {
	case v1.TaskRestart, v1.TaskDeploy, v1.TaskRollback, v1.TaskLogs, v1.TaskObserve:
		return true
	default:
		return false
	}
}

func successM4(task v1.TaskRequest, refs []string) v1.TaskResult {
	return v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Succeeded: true, Status: v1.TaskResultSucceeded, EvidenceRefs: append([]string(nil), refs...)}
}

func rejectedM4(task v1.TaskRequest, code, message string) M4OutboundResult {
	return M4OutboundResult{Result: v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: code, ErrorMessage: message}}
}

func failedM4(task v1.TaskRequest, code string, err error) M4OutboundResult {
	return rejectedM4(task, code, foundation.RedactText(err.Error()))
}

func m4EvidenceRefs(evidence contracts.Evidence) []string {
	refs := make([]string, 0, len(evidence.Refs))
	for _, ref := range evidence.Refs {
		refs = append(refs, ref.ID.String())
	}
	return refs
}

func cloneM4OutboundResult(result M4OutboundResult) M4OutboundResult {
	result.Logs = append([]v1.LogChunk(nil), result.Logs...)
	result.Observations = append([]v1.Observation(nil), result.Observations...)
	for index := range result.Observations {
		result.Observations[index].EvidenceRefs = append([]string(nil), result.Observations[index].EvidenceRefs...)
		result.Observations[index].Details = append(json.RawMessage(nil), result.Observations[index].Details...)
	}
	result.Result.EvidenceRefs = append([]string(nil), result.Result.EvidenceRefs...)
	return result
}
