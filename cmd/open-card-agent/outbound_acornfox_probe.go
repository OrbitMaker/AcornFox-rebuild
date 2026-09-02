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
)

// acornFoxRuntimeProber is deliberately narrower than a general network
// client. The executor gives it only a validated request and a current runtime
// observation; no caller-selected address can cross this boundary.
type acornFoxRuntimeProber interface {
	Probe(context.Context, contracts.AcornFoxProbeRequest, contracts.AcornFoxRuntimeObservation) (contracts.AcornFoxProbeResult, error)
}

type AcornFoxProbeOutboundExecutor struct {
	instanceID string
	nodeID     string
	runtime    contracts.AcornFoxRuntimeDriver
	prober     acornFoxRuntimeProber
	clock      func() time.Time
}

type acornFoxProbeTaskPayload struct {
	PayloadType string          `json:"acornfox_probe_payload_type"`
	Request     json.RawMessage `json:"request"`
}

type acornFoxProbeOutboundResult struct {
	Logs         []v1.LogChunk
	Observations []v1.Observation
	Result       v1.TaskResult
}

func NewAcornFoxProbeOutboundExecutor(instanceID, nodeID string, runtime contracts.AcornFoxRuntimeDriver, prober acornFoxRuntimeProber) *AcornFoxProbeOutboundExecutor {
	return &AcornFoxProbeOutboundExecutor{instanceID: strings.TrimSpace(instanceID), nodeID: strings.TrimSpace(nodeID), runtime: runtime, prober: prober, clock: time.Now}
}

func acornFoxProbePayloadMarked(data json.RawMessage) bool {
	var object map[string]json.RawMessage
	if json.NewDecoder(bytes.NewReader(data)).Decode(&object) != nil {
		return false
	}
	_, present := object["acornfox_probe_payload_type"]
	return present
}

func (e *AcornFoxProbeOutboundExecutor) Execute(ctx context.Context, task v1.TaskRequest) acornFoxProbeOutboundResult {
	if e == nil || e.runtime == nil || e.prober == nil {
		return rejectedAcornFoxProbe(task, "unsupported_capability", "AcornFox probe capability is unavailable")
	}
	if err := task.Validate(); err != nil || task.InstanceID != e.instanceID || task.NodeID != e.nodeID || !task.Deadline.After(e.now()) {
		return rejectedAcornFoxProbe(task, "invalid_argument", "AcornFox probe task is invalid")
	}
	if task.Kind != v1.TaskObserve {
		return rejectedAcornFoxProbe(task, "invalid_argument", "AcornFox probe payload type does not match task kind")
	}
	payload, err := decodeAcornFoxProbePayload(task.Parameters)
	if err != nil || payload.PayloadType != "probe" {
		return rejectedAcornFoxProbe(task, "invalid_argument", "AcornFox probe task wrapper is invalid")
	}
	var request contracts.AcornFoxProbeRequest
	if err := decodeStrictJSON(payload.Request, &request); err != nil || request.IdempotencyKey != task.IdempotencyKey {
		return rejectedAcornFoxProbe(task, "invalid_argument", "AcornFox probe request is invalid")
	}
	taskContext, cancel := context.WithDeadline(ctx, task.Deadline)
	defer cancel()
	// The runtime is the sole address authority. Never accept an observation or
	// target supplied by the control plane, even if it resembles loopback.
	observation, err := e.runtime.Observe(taskContext, request.Reference)
	if err != nil {
		return failedAcornFoxProbe(task, "runtime_observe_failed")
	}
	result, err := e.prober.Probe(taskContext, request, observation)
	if err != nil {
		return failedAcornFoxProbe(task, "probe_failed")
	}
	if err := validateAcornFoxProbeResult(request, observation, result); err != nil {
		return failedAcornFoxProbe(task, "probe_result_invalid")
	}
	details, err := json.Marshal(result)
	if err != nil {
		return failedAcornFoxProbe(task, "internal_error")
	}
	wireObservation := v1.Observation{
		TaskID: task.TaskID, Sequence: 1,
		TargetRef:    "deployment/" + result.DeploymentID.String() + "/probe/" + result.ServiceName,
		Status:       "unknown",
		Healthy:      false,
		At:           result.ObservedAt.UTC(),
		EvidenceRefs: []string{"acornfox-probe:" + result.FactDigest},
		Details:      details,
	}
	return acornFoxProbeOutboundResult{
		Logs:         []v1.LogChunk{{TaskID: task.TaskID, Sequence: 1, Stream: v1.LogStreamStdout, Data: "loopback probe completed", Final: true}},
		Observations: []v1.Observation{wireObservation},
		Result:       v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Succeeded: true, Status: v1.TaskResultSucceeded, EvidenceRefs: wireObservation.EvidenceRefs},
	}
}

func (e *AcornFoxProbeOutboundExecutor) now() time.Time {
	if e.clock == nil {
		return time.Now()
	}
	return e.clock()
}

func decodeAcornFoxProbePayload(data json.RawMessage) (acornFoxProbeTaskPayload, error) {
	var payload acornFoxProbeTaskPayload
	if err := decodeStrictJSON(data, &payload); err != nil || strings.TrimSpace(payload.PayloadType) == "" || len(payload.Request) == 0 {
		return acornFoxProbeTaskPayload{}, errors.New("AcornFox probe task wrapper is invalid")
	}
	return payload, nil
}

func validateAcornFoxProbeResult(request contracts.AcornFoxProbeRequest, observation contracts.AcornFoxRuntimeObservation, result contracts.AcornFoxProbeResult) error {
	if err := result.Validate(); err != nil {
		return err
	}
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(request.Reference.Fact)
	if err != nil || result.ApplicationID != request.Reference.Fact.ApplicationID || result.EnvironmentID != request.Reference.Fact.EnvironmentID || result.ReleaseID != request.Reference.Fact.ReleaseID || result.DeploymentID != deploymentID || result.ServiceName != request.Reference.Fact.ServiceName || result.Protocol != request.Protocol {
		return errors.New("AcornFox probe result identity is invalid")
	}
	expectedDigest, err := contracts.AcornFoxProbeFactDigest(request, observation, result.Outcome, result.HTTPStatus)
	if err != nil || result.FactDigest != expectedDigest {
		return errors.New("AcornFox probe result is not bound to the live runtime observation")
	}
	return nil
}

func rejectedAcornFoxProbe(task v1.TaskRequest, code, message string) acornFoxProbeOutboundResult {
	return acornFoxProbeOutboundResult{Result: v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: code, ErrorMessage: message}}
}

// Probe and runtime failures are intentionally not serialized. Their raw
// network/daemon details are not a user-facing wire fact.
func failedAcornFoxProbe(task v1.TaskRequest, code string) acornFoxProbeOutboundResult {
	return acornFoxProbeOutboundResult{Logs: []v1.LogChunk{{TaskID: task.TaskID, Sequence: 1, Stream: v1.LogStreamStderr, Data: "AcornFox probe operation failed", Final: true}}, Result: v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: code, ErrorMessage: "AcornFox probe operation failed"}}
}
