package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/foundation"
)

// AcornFoxOutboundExecutor accepts the intentionally narrow single-service
// task surface. It does not run a probe, shell command, or general runtime
// request: all lifecycle effects remain behind AcornFoxRuntimeDriver.
type AcornFoxOutboundExecutor struct {
	instanceID string
	nodeID     string
	driver     contracts.AcornFoxRuntimeDriver
	clock      func() time.Time
}

type acornFoxTaskPayload struct {
	PayloadType string          `json:"acornfox_payload_type"`
	Request     json.RawMessage `json:"request"`
}

type acornFoxOutboundResult struct {
	Logs         []v1.LogChunk
	Observations []v1.Observation
	Result       v1.TaskResult
}

func NewAcornFoxOutboundExecutor(instanceID, nodeID string, driver contracts.AcornFoxRuntimeDriver) *AcornFoxOutboundExecutor {
	return &AcornFoxOutboundExecutor{instanceID: strings.TrimSpace(instanceID), nodeID: strings.TrimSpace(nodeID), driver: driver, clock: time.Now}
}

func acornFoxPayloadMarked(data json.RawMessage) bool {
	var object map[string]json.RawMessage
	if json.NewDecoder(bytes.NewReader(data)).Decode(&object) != nil {
		return false
	}
	_, present := object["acornfox_payload_type"]
	return present
}

// Execute decodes a marker before any legacy route is considered. A malformed
// or mismatched marker returns typed rejected task events and never falls
// through to M4, grouped, recovery, scale, logs, or Docker facts handling.
func (e *AcornFoxOutboundExecutor) Execute(ctx context.Context, task v1.TaskRequest) acornFoxOutboundResult {
	if e == nil || e.driver == nil {
		return rejectedAcornFox(task, "unsupported_capability", "AcornFox runtime capability is unavailable")
	}
	if err := task.Validate(); err != nil || task.InstanceID != e.instanceID || task.NodeID != e.nodeID || !task.Deadline.After(e.now()) {
		return rejectedAcornFox(task, "invalid_argument", "AcornFox task is invalid")
	}
	payload, err := decodeAcornFoxPayload(task.Parameters)
	if err != nil {
		return rejectedAcornFox(task, "invalid_argument", "AcornFox task wrapper is invalid")
	}
	taskContext, cancel := context.WithDeadline(ctx, task.Deadline)
	defer cancel()

	switch payload.PayloadType {
	case "deploy", "redeploy":
		if task.Kind != v1.TaskDeploy {
			return rejectedAcornFox(task, "invalid_argument", "AcornFox payload type does not match task kind")
		}
		var request contracts.AcornFoxRuntimeDeployRequest
		if err := decodeStrictJSON(payload.Request, &request); err != nil || request.IdempotencyKey != task.IdempotencyKey || request.Recreate != (payload.PayloadType == "redeploy") {
			return rejectedAcornFox(task, "invalid_argument", "AcornFox deploy request is invalid")
		}
		deployment, err := e.driver.Deploy(taskContext, request)
		if err != nil {
			return failedAcornFox(task, "runtime_deploy_failed", err)
		}
		if !acornFoxDeploymentMatches(request.Fact, deployment) {
			return failedAcornFox(task, "runtime_identity_mismatch", errors.New("runtime returned an unexpected deployment"))
		}
		observation, err := e.driver.Observe(taskContext, contracts.AcornFoxRuntimeReference{Fact: request.Fact})
		if err != nil {
			return failedAcornFox(task, "runtime_observe_failed", err)
		}
		return completedAcornFox(task, "immutable runtime deployment completed", observation)
	case "observe":
		if task.Kind != v1.TaskObserve {
			return rejectedAcornFox(task, "invalid_argument", "AcornFox payload type does not match task kind")
		}
		var reference contracts.AcornFoxRuntimeReference
		if err := decodeStrictJSON(payload.Request, &reference); err != nil {
			return rejectedAcornFox(task, "invalid_argument", "AcornFox observe request is invalid")
		}
		observation, err := e.driver.Observe(taskContext, reference)
		if err != nil {
			return failedAcornFox(task, "runtime_observe_failed", err)
		}
		return completedAcornFox(task, "runtime state observed", observation)
	case "restart":
		if task.Kind != v1.TaskRestart {
			return rejectedAcornFox(task, "invalid_argument", "AcornFox payload type does not match task kind")
		}
		var request contracts.AcornFoxRuntimeActionRequest
		if err := decodeStrictJSON(payload.Request, &request); err != nil || request.IdempotencyKey != task.IdempotencyKey {
			return rejectedAcornFox(task, "invalid_argument", "AcornFox restart request is invalid")
		}
		if err := e.driver.Restart(taskContext, request); err != nil {
			return failedAcornFox(task, "runtime_restart_failed", err)
		}
		observation, err := e.driver.Observe(taskContext, contracts.AcornFoxRuntimeReference{Fact: request.Fact})
		if err != nil {
			return failedAcornFox(task, "runtime_observe_failed", err)
		}
		return completedAcornFox(task, "runtime restart completed", observation)
	case "destroy":
		if task.Kind != v1.TaskDestroy {
			return rejectedAcornFox(task, "invalid_argument", "AcornFox payload type does not match task kind")
		}
		var request contracts.AcornFoxRuntimeActionRequest
		if err := decodeStrictJSON(payload.Request, &request); err != nil || request.IdempotencyKey != task.IdempotencyKey {
			return rejectedAcornFox(task, "invalid_argument", "AcornFox destroy request is invalid")
		}
		if err := e.driver.Destroy(taskContext, request); err != nil {
			return failedAcornFox(task, "runtime_destroy_failed", err)
		}
		return stoppedAcornFox(task, request.Fact, e.now())
	default:
		return rejectedAcornFox(task, "unsupported_capability", "AcornFox payload type is not allowlisted")
	}
}

func (e *AcornFoxOutboundExecutor) now() time.Time {
	if e.clock == nil {
		return time.Now()
	}
	return e.clock()
}

func decodeAcornFoxPayload(data json.RawMessage) (acornFoxTaskPayload, error) {
	var payload acornFoxTaskPayload
	if err := decodeStrictJSON(data, &payload); err != nil || strings.TrimSpace(payload.PayloadType) == "" || len(payload.Request) == 0 {
		return acornFoxTaskPayload{}, errors.New("AcornFox task wrapper is invalid")
	}
	return payload, nil
}

func acornFoxDeploymentMatches(fact contracts.AcornFoxRuntimeReleaseFact, deployment contracts.AcornFoxRuntimeDeployment) bool {
	expectedID, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	return err == nil && deployment.DeploymentID == expectedID && deployment.ApplicationID == fact.ApplicationID && deployment.EnvironmentID == fact.EnvironmentID && deployment.ReleaseID == fact.ReleaseID && deployment.ServiceName == fact.ServiceName && deployment.Image == fact.Image
}

func completedAcornFox(task v1.TaskRequest, logMessage string, observation contracts.AcornFoxRuntimeObservation) acornFoxOutboundResult {
	wireObservation, err := acornFoxWireObservation(task, observation)
	if err != nil {
		return failedAcornFox(task, "runtime_observation_invalid", err)
	}
	return acornFoxOutboundResult{
		Logs:         []v1.LogChunk{{TaskID: task.TaskID, Sequence: 1, Stream: v1.LogStreamStdout, Data: logMessage, Final: true}},
		Observations: []v1.Observation{wireObservation},
		Result:       v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Succeeded: true, Status: v1.TaskResultSucceeded, EvidenceRefs: []string{"acornfox-runtime:" + observation.DeploymentID.String()}},
	}
}

func stoppedAcornFox(task v1.TaskRequest, fact contracts.AcornFoxRuntimeReleaseFact, now time.Time) acornFoxOutboundResult {
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	if err != nil {
		return failedAcornFox(task, "runtime_identity_mismatch", err)
	}
	details, err := json.Marshal(map[string]string{"deployment_id": deploymentID.String(), "runtime_state": "stopped"})
	if err != nil {
		return failedAcornFox(task, "internal_error", err)
	}
	return acornFoxOutboundResult{
		Logs:         []v1.LogChunk{{TaskID: task.TaskID, Sequence: 1, Stream: v1.LogStreamStdout, Data: "runtime destroy completed", Final: true}},
		Observations: []v1.Observation{{TaskID: task.TaskID, Sequence: 1, TargetRef: "deployment/" + deploymentID.String(), Status: "stopped", Healthy: false, At: now.UTC(), Details: details}},
		Result:       v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Succeeded: true, Status: v1.TaskResultSucceeded, EvidenceRefs: []string{"acornfox-runtime:" + deploymentID.String()}},
	}
}

func acornFoxWireObservation(task v1.TaskRequest, observation contracts.AcornFoxRuntimeObservation) (v1.Observation, error) {
	if observation.DeploymentID.Empty() || strings.TrimSpace(observation.ServiceName) == "" || observation.ObservedAt.IsZero() {
		return v1.Observation{}, errors.New("runtime observation is incomplete")
	}
	// Runtime providers can carry older product lifecycle labels internally.
	// The AcornFox wire surface reports only objective Docker container states,
	// so normalize a copy before either details or top-level status is emitted.
	normalized := observation
	normalized.RuntimeState = acornFoxObjectiveRuntimeState(observation.RuntimeState)
	details, err := json.Marshal(normalized)
	if err != nil {
		return v1.Observation{}, err
	}
	// Healthy is deliberately false: this objective runtime readback does not
	// claim an HTTP response or invoke the legacy loopback health probe.
	return v1.Observation{TaskID: task.TaskID, Sequence: 1, TargetRef: "deployment/" + observation.DeploymentID.String(), Status: normalized.RuntimeState, Healthy: false, At: observation.ObservedAt.UTC(), Details: details}, nil
}

func acornFoxObjectiveRuntimeState(value string) string {
	value = strings.TrimSpace(value)
	switch value {
	case "created", "running", "restarting", "paused", "exited", "dead", "removing", "stopped", "unknown":
		return value
	default:
		return "unknown"
	}
}

func rejectedAcornFox(task v1.TaskRequest, code, message string) acornFoxOutboundResult {
	return acornFoxOutboundResult{Result: v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: code, ErrorMessage: foundation.RedactText(message)}}
}

func failedAcornFox(task v1.TaskRequest, code string, err error) acornFoxOutboundResult {
	message := "AcornFox runtime operation failed"
	if err != nil {
		message = foundation.RedactText(err.Error())
	}
	return acornFoxOutboundResult{Logs: []v1.LogChunk{{TaskID: task.TaskID, Sequence: 1, Stream: v1.LogStreamStderr, Data: "AcornFox runtime operation failed", Final: true}}, Result: v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: code, ErrorMessage: message}}
}
