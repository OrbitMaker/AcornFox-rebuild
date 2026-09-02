package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/agenttransport"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

type OutboundHandler struct {
	instanceID      string
	nodeID          string
	facts           DockerFactsReader
	runtime         contracts.RuntimeDriver
	groupRuntime    contracts.ServiceGroupRuntimeDriver
	volumeRuntime   contracts.VolumeProvider
	m4Runtime       *M4OutboundExecutor
	acornFoxRuntime *AcornFoxOutboundExecutor
	acornFoxProbe   *AcornFoxProbeOutboundExecutor
	acornFoxLogs    *AcornFoxLogsOutboundExecutor
	clock           func() time.Time
	healthProbe     func(context.Context, int, time.Time) error
	mu              sync.Mutex
	results         map[string]outboundTaskResult
}

type outboundTaskResult struct {
	fingerprint [32]byte
	events      []v1.Envelope
}

func NewOutboundHandler(instanceID, nodeID string, facts DockerFactsReader) *OutboundHandler {
	return &OutboundHandler{instanceID: instanceID, nodeID: nodeID, facts: facts, clock: time.Now, healthProbe: probeLoopbackHealth, results: make(map[string]outboundTaskResult)}
}

func NewOutboundHandlerWithRuntime(instanceID, nodeID string, facts DockerFactsReader, runtime contracts.RuntimeDriver) *OutboundHandler {
	handler := NewOutboundHandler(instanceID, nodeID, facts)
	handler.runtime = runtime
	if runtime != nil {
		handler.m4Runtime = NewM4OutboundExecutor(instanceID, nodeID, runtime)
	}
	return handler
}

func NewOutboundHandlerWithRuntimes(instanceID, nodeID string, facts DockerFactsReader, runtime contracts.RuntimeDriver, groupRuntime contracts.ServiceGroupRuntimeDriver) *OutboundHandler {
	handler := NewOutboundHandlerWithRuntime(instanceID, nodeID, facts, runtime)
	handler.groupRuntime = groupRuntime
	if runtime != nil || groupRuntime != nil {
		handler.m4Runtime = NewM4OutboundExecutorWithGroupRuntime(instanceID, nodeID, runtime, groupRuntime)
	}
	return handler
}

func NewOutboundHandlerWithProviders(instanceID, nodeID string, facts DockerFactsReader, runtime contracts.RuntimeDriver, groupRuntime contracts.ServiceGroupRuntimeDriver, volumeRuntime contracts.VolumeProvider) *OutboundHandler {
	handler := NewOutboundHandlerWithRuntimes(instanceID, nodeID, facts, runtime, groupRuntime)
	handler.volumeRuntime = volumeRuntime
	return handler
}

// NewOutboundHandlerWithProvidersAndAcornFoxRuntime adds the single-service
// AcornFox task surface without changing legacy runtime composition. Marker
// routing remains opt-in and occurs before every existing dispatcher branch.
func NewOutboundHandlerWithProvidersAndAcornFoxRuntime(instanceID, nodeID string, facts DockerFactsReader, runtime contracts.RuntimeDriver, groupRuntime contracts.ServiceGroupRuntimeDriver, volumeRuntime contracts.VolumeProvider, acornFoxRuntime contracts.AcornFoxRuntimeDriver) *OutboundHandler {
	handler := NewOutboundHandlerWithProviders(instanceID, nodeID, facts, runtime, groupRuntime, volumeRuntime)
	if acornFoxRuntime != nil {
		handler.acornFoxRuntime = NewAcornFoxOutboundExecutor(instanceID, nodeID, acornFoxRuntime)
	}
	return handler
}

// NewOutboundHandlerWithAcornFoxProbe adds the separate loopback-probe
// authority without widening lifecycle or legacy task handling.
func NewOutboundHandlerWithAcornFoxProbe(instanceID, nodeID string, facts DockerFactsReader, runtime contracts.RuntimeDriver, groupRuntime contracts.ServiceGroupRuntimeDriver, volumeRuntime contracts.VolumeProvider, acornFoxRuntime contracts.AcornFoxRuntimeDriver, prober acornFoxRuntimeProber) *OutboundHandler {
	handler := NewOutboundHandlerWithProvidersAndAcornFoxRuntime(instanceID, nodeID, facts, runtime, groupRuntime, volumeRuntime, acornFoxRuntime)
	if boundedLogs, ok := runtime.(contracts.AcornFoxBoundedLogReader); ok {
		handler.acornFoxLogs = NewAcornFoxLogsOutboundExecutor(instanceID, nodeID, boundedLogs)
	}
	if acornFoxRuntime != nil && prober != nil {
		handler.acornFoxProbe = NewAcornFoxProbeOutboundExecutor(instanceID, nodeID, acornFoxRuntime, prober)
	}
	return handler
}

func (h *OutboundHandler) HandleControlEnvelope(ctx context.Context, envelope v1.Envelope) ([]v1.Envelope, error) {
	if err := v1.ValidateEnvelopePayload(envelope); err != nil {
		return nil, err
	}
	if envelope.InstanceID != h.instanceID || envelope.NodeID != h.nodeID {
		return nil, errors.New("control envelope identity mismatch")
	}
	switch envelope.Kind {
	case v1.KindTaskRequest:
		var task v1.TaskRequest
		if err := json.Unmarshal(envelope.Payload, &task); err != nil {
			return nil, err
		}
		if err := task.Validate(); err != nil {
			return nil, err
		}
		if task.InstanceID != h.instanceID || task.NodeID != h.nodeID {
			return nil, errors.New("task identity mismatch")
		}
		fingerprint, err := semanticTaskFingerprint(task)
		if err != nil {
			return nil, err
		}
		h.mu.Lock()
		if cached, ok := h.results[task.IdempotencyKey]; ok {
			if cached.fingerprint != fingerprint {
				h.mu.Unlock()
				return nil, errors.New("task idempotency key conflicts with prior task input")
			}
			result := cloneEnvelopes(cached.events)
			h.mu.Unlock()
			return result, nil
		}
		h.mu.Unlock()
		result, err := h.executeTask(ctx, task)
		if err != nil {
			return nil, err
		}
		h.mu.Lock()
		h.results[task.IdempotencyKey] = outboundTaskResult{fingerprint: fingerprint, events: cloneEnvelopes(result)}
		h.mu.Unlock()
		return result, nil
	case v1.KindCancelTask:
		var cancel v1.CancelTask
		if err := json.Unmarshal(envelope.Payload, &cancel); err != nil {
			return nil, err
		}
		if err := cancel.Validate(); err != nil {
			return nil, err
		}
		return h.cancelResult(cancel)
	default:
		return nil, fmt.Errorf("control envelope kind %s is not accepted by the Agent", envelope.Kind)
	}
}

// semanticTaskFingerprint excludes lease transport fields that necessarily
// change when the control plane takes over an expired durable task. The task
// identity, kind, target and typed parameters remain protected: changing any
// of those still conflicts instead of repeating a side effect.
func semanticTaskFingerprint(task v1.TaskRequest) ([32]byte, error) {
	task.LeaseID = ""
	task.Deadline = time.Time{}
	encoded, err := json.Marshal(task)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func (h *OutboundHandler) executeTask(ctx context.Context, task v1.TaskRequest) ([]v1.Envelope, error) {
	ack := v1.TaskAck{TaskID: task.TaskID, Status: v1.AckAccepted}
	if acornFoxLogsPayloadMarked(task.Parameters) {
		var result acornFoxLogsOutboundResult
		if h.acornFoxLogs == nil {
			result = rejectedAcornFoxLogs(task, "unsupported_capability", "AcornFox logs capability is unavailable")
		} else {
			result = h.acornFoxLogs.Execute(ctx, task)
		}
		return h.wrapAcornFoxLogsTaskEvents(task, ack, result)
	}
	if acornFoxProbePayloadMarked(task.Parameters) {
		var result acornFoxProbeOutboundResult
		if h.acornFoxProbe == nil {
			result = rejectedAcornFoxProbe(task, "unsupported_capability", "AcornFox probe capability is unavailable")
		} else {
			result = h.acornFoxProbe.Execute(ctx, task)
		}
		return h.wrapAcornFoxProbeTaskEvents(task, ack, result)
	}
	if acornFoxPayloadMarked(task.Parameters) {
		var result acornFoxOutboundResult
		if h.acornFoxRuntime == nil {
			result = rejectedAcornFox(task, "unsupported_capability", "AcornFox runtime capability is unavailable")
		} else {
			result = h.acornFoxRuntime.Execute(ctx, task)
		}
		return h.wrapAcornFoxTaskEvents(task, ack, result)
	}
	if h.m4Runtime != nil && (task.Kind == v1.TaskRestart || task.Kind == v1.TaskRollback || task.Kind == v1.TaskLogs || m4GroupMarked(task.Parameters)) {
		result, err := h.m4Runtime.Execute(ctx, task)
		if err != nil {
			return nil, err
		}
		return h.wrapM4TaskEvents(task, ack, result)
	}
	if task.Kind == v1.TaskDeploy {
		return h.executeDeploy(ctx, task, ack)
	}
	if task.Kind == v1.TaskDeployGroup {
		return h.executeDeployGroup(ctx, task, ack)
	}
	if task.Kind == v1.TaskDestroyGroup {
		return h.executeDestroyGroup(ctx, task, ack)
	}
	if task.Kind == v1.TaskDestroyVolume {
		return h.executeDestroyVolume(ctx, task, ack)
	}
	if task.Kind != v1.TaskObserve {
		ack.Status = v1.AckRejected
		ack.Reason = "outbound M0 executor only supports read-only observe"
		result := v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: "unsupported_capability", ErrorMessage: ack.Reason}
		return h.wrapTaskEvents(task, ack, nil, nil, result)
	}
	var parameters struct {
		Scope string `json:"scope"`
	}
	decoder := json.NewDecoder(bytes.NewReader(task.Parameters))
	decoder.DisallowUnknownFields()
	decoderErr := decoder.Decode(&parameters)
	var extra any
	if decoderErr != nil || decoder.Decode(&extra) != io.EOF || parameters.Scope != "node_docker_facts" {
		return nil, errors.New("observe task scope is not allowlisted")
	}
	if h.facts == nil {
		return nil, errors.New("docker facts reader is unavailable")
	}
	facts, err := h.facts.ReadFacts(ctx)
	if err != nil {
		result := v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: "docker_facts_unavailable", ErrorMessage: err.Error()}
		return h.wrapTaskEvents(task, ack, nil, nil, result)
	}
	factsJSON, err := json.Marshal(facts)
	if err != nil {
		return nil, err
	}
	observation := &v1.Observation{TaskID: task.TaskID, Sequence: 1, TargetRef: "node/" + h.nodeID + "/docker", Status: "healthy", Healthy: true, At: h.clock().UTC(), EvidenceRefs: []string{"docker-api:/version", "docker-api:/info"}, Details: factsJSON}
	log := &v1.LogChunk{TaskID: task.TaskID, Sequence: 1, Stream: v1.LogStreamStdout, Data: "read-only Docker node facts collected", Final: true}
	result := v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Succeeded: true, Status: v1.TaskResultSucceeded, EvidenceRefs: observation.EvidenceRefs}
	return h.wrapTaskEvents(task, ack, log, *observation, result)
}

func (h *OutboundHandler) wrapAcornFoxLogsTaskEvents(task v1.TaskRequest, ack v1.TaskAck, result acornFoxLogsOutboundResult) ([]v1.Envelope, error) {
	if !result.Result.Succeeded && (result.Result.ErrorCode == "invalid_argument" || result.Result.ErrorCode == "unsupported_capability") {
		ack.Status = v1.AckRejected
		ack.Reason = "AcornFox logs task was rejected"
	}
	events := []v1.Envelope{h.envelope(v1.KindTaskAck, task.IdempotencyKey, ack)}
	for _, log := range result.Logs {
		events = append(events, h.envelope(v1.KindLogChunk, task.IdempotencyKey, log))
	}
	events = append(events, h.envelope(v1.KindTaskResult, task.IdempotencyKey, result.Result))
	for index := range events {
		events[index].AgentSequence = uint64(index + 1)
		if err := v1.ValidateEnvelopePayload(events[index]); err != nil {
			return nil, err
		}
	}
	return events, nil
}

func (h *OutboundHandler) wrapAcornFoxProbeTaskEvents(task v1.TaskRequest, ack v1.TaskAck, result acornFoxProbeOutboundResult) ([]v1.Envelope, error) {
	if !result.Result.Succeeded && (result.Result.ErrorCode == "invalid_argument" || result.Result.ErrorCode == "unsupported_capability") {
		ack.Status = v1.AckRejected
		ack.Reason = "AcornFox probe task was rejected"
	}
	events := []v1.Envelope{h.envelope(v1.KindTaskAck, task.IdempotencyKey, ack)}
	for _, log := range result.Logs {
		events = append(events, h.envelope(v1.KindLogChunk, task.IdempotencyKey, log))
	}
	for _, observation := range result.Observations {
		events = append(events, h.envelope(v1.KindObservation, task.IdempotencyKey, observation))
	}
	events = append(events, h.envelope(v1.KindTaskResult, task.IdempotencyKey, result.Result))
	for index := range events {
		events[index].AgentSequence = uint64(index + 1)
		if err := v1.ValidateEnvelopePayload(events[index]); err != nil {
			return nil, err
		}
	}
	return events, nil
}

func (h *OutboundHandler) wrapAcornFoxTaskEvents(task v1.TaskRequest, ack v1.TaskAck, result acornFoxOutboundResult) ([]v1.Envelope, error) {
	if !result.Result.Succeeded && (result.Result.ErrorCode == "invalid_argument" || result.Result.ErrorCode == "unsupported_capability") {
		ack.Status = v1.AckRejected
		ack.Reason = "AcornFox task was rejected"
	}
	events := []v1.Envelope{h.envelope(v1.KindTaskAck, task.IdempotencyKey, ack)}
	for _, log := range result.Logs {
		events = append(events, h.envelope(v1.KindLogChunk, task.IdempotencyKey, log))
	}
	for _, observation := range result.Observations {
		events = append(events, h.envelope(v1.KindObservation, task.IdempotencyKey, observation))
	}
	events = append(events, h.envelope(v1.KindTaskResult, task.IdempotencyKey, result.Result))
	for index := range events {
		events[index].AgentSequence = uint64(index + 1)
		if err := v1.ValidateEnvelopePayload(events[index]); err != nil {
			return nil, err
		}
	}
	return events, nil
}

func (h *OutboundHandler) wrapM4TaskEvents(task v1.TaskRequest, ack v1.TaskAck, result M4OutboundResult) ([]v1.Envelope, error) {
	events := []v1.Envelope{h.envelope(v1.KindTaskAck, task.IdempotencyKey, ack)}
	for _, log := range result.Logs {
		events = append(events, h.envelope(v1.KindLogChunk, task.IdempotencyKey, log))
	}
	for _, observation := range result.Observations {
		events = append(events, h.envelope(v1.KindObservation, task.IdempotencyKey, observation))
	}
	events = append(events, h.envelope(v1.KindTaskResult, task.IdempotencyKey, result.Result))
	for index := range events {
		events[index].AgentSequence = uint64(index + 1)
		if err := v1.ValidateEnvelopePayload(events[index]); err != nil {
			return nil, err
		}
	}
	return events, nil
}

func (h *OutboundHandler) executeDestroyVolume(ctx context.Context, task v1.TaskRequest, ack v1.TaskAck) ([]v1.Envelope, error) {
	if h.volumeRuntime == nil {
		ack.Status = v1.AckRejected
		ack.Reason = "exact volume destroy capability is not configured"
		result := v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: "unsupported_capability", ErrorMessage: ack.Reason}
		return h.wrapTaskEvents(task, ack, nil, nil, result)
	}
	var parameters struct {
		Volume             contracts.VolumeSpec       `json:"volume"`
		ConfirmationPhrase string                     `json:"confirmation_phrase"`
		Operation          contracts.OperationContext `json:"operation"`
	}
	if err := decodeStrictJSON(task.Parameters, &parameters); err != nil || parameters.Operation.IdempotencyKey != task.IdempotencyKey || parameters.Volume.Name == "" || parameters.ConfirmationPhrase == "" {
		return nil, errors.New("destroy_volume task parameters are invalid")
	}
	if parameters.Operation.Deadline.IsZero() || parameters.Operation.Deadline.After(task.Deadline) {
		parameters.Operation.Deadline = task.Deadline
	}
	request := contracts.VolumeRequest{Volume: parameters.Volume, ConfirmationToken: parameters.ConfirmationPhrase, Operation: parameters.Operation}
	if err := h.volumeRuntime.Destroy(ctx, request); err != nil {
		result := v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: "volume_destroy_failed", ErrorMessage: foundation.RedactText(err.Error())}
		return h.wrapTaskEvents(task, ack, nil, nil, result)
	}
	log := v1.LogChunk{TaskID: task.TaskID, Sequence: 1, Stream: v1.LogStreamStdout, Data: "exact confirmed task volume destroyed", Final: true}
	result := v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Succeeded: true, Status: v1.TaskResultSucceeded}
	return h.wrapTaskEvents(task, ack, &log, nil, result)
}

func (h *OutboundHandler) executeDestroyGroup(ctx context.Context, task v1.TaskRequest, ack v1.TaskAck) ([]v1.Envelope, error) {
	if h.groupRuntime == nil {
		ack.Status = v1.AckRejected
		ack.Reason = "aggregate runtime destroy capability is not configured"
		result := v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: "unsupported_capability", ErrorMessage: ack.Reason}
		return h.wrapTaskEvents(task, ack, nil, nil, result)
	}
	var request contracts.DestroyRequest
	if err := decodeStrictJSON(task.Parameters, &request); err != nil || request.DeploymentID.Empty() || request.Operation.IdempotencyKey != task.IdempotencyKey {
		return nil, errors.New("destroy_group task parameters are invalid")
	}
	if !request.PreserveVolumes {
		ack.Status = v1.AckRejected
		ack.Reason = "aggregate destroy preserves volumes; exact claim deletion is a separate confirmed operation"
		result := v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: "volume_confirmation_required", ErrorMessage: ack.Reason}
		return h.wrapTaskEvents(task, ack, nil, nil, result)
	}
	if request.Operation.Deadline.IsZero() || request.Operation.Deadline.After(task.Deadline) {
		request.Operation.Deadline = task.Deadline
	}
	if err := h.groupRuntime.DestroyGroup(ctx, request); err != nil {
		result := v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: "runtime_group_destroy_failed", ErrorMessage: foundation.RedactText(err.Error())}
		return h.wrapTaskEvents(task, ack, nil, nil, result)
	}
	log := v1.LogChunk{TaskID: task.TaskID, Sequence: 1, Stream: v1.LogStreamStdout, Data: "aggregate runtime destroyed with volumes retained", Final: true}
	result := v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Succeeded: true, Status: v1.TaskResultSucceeded}
	return h.wrapTaskEvents(task, ack, &log, nil, result)
}

func (h *OutboundHandler) executeDeployGroup(ctx context.Context, task v1.TaskRequest, ack v1.TaskAck) ([]v1.Envelope, error) {
	if h.groupRuntime == nil {
		ack.Status = v1.AckRejected
		ack.Reason = "aggregate runtime deployment capability is not configured"
		result := v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: "unsupported_capability", ErrorMessage: ack.Reason}
		return h.wrapTaskEvents(task, ack, nil, nil, result)
	}
	var request contracts.DeployGroupRequest
	if err := decodeStrictJSON(task.Parameters, &request); err != nil {
		return nil, errors.New("deploy_group task parameters are invalid")
	}
	if request.DeploymentID.Empty() || request.Operation.IdempotencyKey != task.IdempotencyKey {
		return nil, errors.New("deploy_group task operation identity mismatch")
	}
	if err := request.Spec.Validate(); err != nil {
		return nil, errors.New("deploy_group runtime specification is invalid")
	}
	if request.Operation.Deadline.IsZero() || request.Operation.Deadline.After(task.Deadline) {
		request.Operation.Deadline = task.Deadline
	}
	deployed, err := h.groupRuntime.DeployGroup(ctx, request)
	if err != nil {
		message := foundation.RedactText(err.Error())
		result := v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: "runtime_group_deploy_failed", ErrorMessage: message}
		return h.wrapTaskEvents(task, ack, nil, nil, result)
	}
	if deployed.ID != request.DeploymentID || deployed.ReleaseID != request.Spec.ReleaseID {
		return nil, errors.New("aggregate runtime returned a deployment outside the requested identity")
	}
	observeOperation := request.Operation
	observeOperation.IdempotencyKey += ":observe-group"
	observation, observeErr := h.groupRuntime.ObserveGroup(ctx, contracts.ObserveGroupRequest{DeploymentID: request.DeploymentID, Operation: observeOperation})
	if observeErr == nil {
		observeErr = observation.ValidateFor(request.Spec)
	}
	if observeErr == nil && observation.DeploymentID != request.DeploymentID {
		return nil, errors.New("aggregate runtime observation identity mismatch")
	}
	entryHealthy := false
	entryPort := 0
	for _, service := range observation.Services {
		if service.ServiceName == request.Spec.EntryService {
			entryHealthy = service.Healthy
			entryPort = service.HostPort
			break
		}
	}
	healthyStatus := observation.Status == "runtime_ready" || observation.Status == "degraded"
	if observeErr == nil && observation.Effect == contracts.RuntimeEffectKnown && healthyStatus && entryHealthy {
		observeErr = h.healthProbe(ctx, entryPort, task.Deadline)
	}
	if observeErr != nil || observation.Effect != contracts.RuntimeEffectKnown || !healthyStatus || !entryHealthy {
		failure := "aggregate runtime health observation failed"
		code := "runtime_group_unhealthy"
		if observeErr != nil {
			failure = foundation.RedactText(observeErr.Error())
		}
		if observation.Effect == contracts.RuntimeEffectUnknown {
			code = "runtime_effect_unknown"
			failure = "aggregate runtime effect is unknown; destructive retry suppressed"
		} else {
			cleanupOperation := request.Operation
			cleanupOperation.IdempotencyKey += ":cleanup-group"
			_ = h.groupRuntime.DestroyGroup(ctx, contracts.DestroyRequest{DeploymentID: request.DeploymentID, PreserveVolumes: true, Operation: cleanupOperation})
		}
		result := v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: code, ErrorMessage: failure}
		return h.wrapTaskEvents(task, ack, nil, nil, result)
	}
	details, err := json.Marshal(observation)
	if err != nil {
		return nil, err
	}
	evidence := evidenceStrings(observation.Evidence)
	evidence = append(evidence, fmt.Sprintf("loopback-health:%d", entryPort))
	wireObservation := v1.Observation{TaskID: task.TaskID, Sequence: 1, TargetRef: "deployment/" + request.DeploymentID.String(), Status: observation.Status, Healthy: true, At: h.clock().UTC(), EvidenceRefs: evidence, Details: details}
	log := v1.LogChunk{TaskID: task.TaskID, Sequence: 1, Stream: v1.LogStreamStdout, Data: "complete immutable ServiceGroup deployed and observed", Final: true}
	result := v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Succeeded: true, Status: v1.TaskResultSucceeded, EvidenceRefs: evidence}
	return h.wrapTaskEvents(task, ack, &log, wireObservation, result)
}

func (h *OutboundHandler) executeDeploy(ctx context.Context, task v1.TaskRequest, ack v1.TaskAck) ([]v1.Envelope, error) {
	if h.runtime == nil {
		ack.Status = v1.AckRejected
		ack.Reason = "runtime deployment capability is not configured"
		result := v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: "unsupported_capability", ErrorMessage: ack.Reason}
		return h.wrapTaskEvents(task, ack, nil, nil, result)
	}
	var request contracts.DeployRequest
	if err := decodeStrictJSON(task.Parameters, &request); err != nil {
		return nil, errors.New("deploy task parameters are invalid")
	}
	if request.Operation.IdempotencyKey != task.IdempotencyKey {
		return nil, errors.New("deploy task operation identity mismatch")
	}
	if request.Operation.Deadline.IsZero() || request.Operation.Deadline.After(task.Deadline) {
		request.Operation.Deadline = task.Deadline
	}
	deployed, err := h.runtime.Deploy(ctx, request)
	if err != nil {
		message := foundation.RedactText(err.Error())
		result := v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: "runtime_deploy_failed", ErrorMessage: message}
		return h.wrapTaskEvents(task, ack, nil, nil, result)
	}
	if deployed.ID != request.DeploymentID || deployed.ReleaseID != request.Spec.ReleaseID {
		return nil, errors.New("runtime returned a deployment outside the requested identity")
	}
	observeOperation := request.Operation
	observeOperation.IdempotencyKey += ":observe"
	observation, err := h.runtime.Observe(ctx, contracts.ObserveRequest{DeploymentID: request.DeploymentID, Operation: observeOperation})
	if err == nil && observation.Healthy {
		err = h.healthProbe(ctx, observation.HostPort, task.Deadline)
	}
	if err != nil || !observation.Healthy {
		failure := "runtime health observation failed"
		if err != nil {
			failure = foundation.RedactText(err.Error())
		}
		cleanupOperation := request.Operation
		cleanupOperation.IdempotencyKey += ":cleanup"
		_ = h.runtime.Destroy(ctx, contracts.DestroyRequest{DeploymentID: request.DeploymentID, Operation: cleanupOperation})
		result := v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: "runtime_unhealthy", ErrorMessage: failure}
		return h.wrapTaskEvents(task, ack, nil, nil, result)
	}
	details, err := json.Marshal(observation)
	if err != nil {
		return nil, err
	}
	evidence := evidenceStrings(observation.Evidence)
	evidence = append(evidence, fmt.Sprintf("loopback-health:%d", observation.HostPort))
	wireObservation := v1.Observation{TaskID: task.TaskID, Sequence: 1, TargetRef: "deployment/" + request.DeploymentID.String(), Status: "runtime_ready", Healthy: true, At: observation.ObservedAt.UTC(), EvidenceRefs: evidence, Details: details}
	log := v1.LogChunk{TaskID: task.TaskID, Sequence: 1, Stream: v1.LogStreamStdout, Data: "immutable OCI digest deployed and health observed", Final: true}
	result := v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Succeeded: true, Status: v1.TaskResultSucceeded, EvidenceRefs: evidence}
	return h.wrapTaskEvents(task, ack, &log, wireObservation, result)
}

func probeLoopbackHealth(ctx context.Context, port int, deadline time.Time) error {
	if port < 1 || port > 65535 {
		return errors.New("runtime did not report a system-assigned host port")
	}
	client := &http.Client{Timeout: 500 * time.Millisecond}
	url := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	probeDeadline := time.Now().Add(10 * time.Second)
	if !deadline.IsZero() && deadline.Before(probeDeadline) {
		probeDeadline = deadline
	}
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Until(probeDeadline) <= 100*time.Millisecond {
			return errors.New("runtime loopback health probe timed out")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func decodeStrictJSON(data []byte, target any) error {
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

func evidenceStrings(evidence contracts.Evidence) []string {
	refs := make([]string, 0, len(evidence.Refs))
	for _, ref := range evidence.Refs {
		refs = append(refs, ref.ID.String())
	}
	return refs
}

func (h *OutboundHandler) cancelResult(cancel v1.CancelTask) ([]v1.Envelope, error) {
	result := v1.TaskResult{TaskID: cancel.TaskID, IdempotencyKey: cancel.IdempotencyKey, Status: v1.TaskResultCancelled, ErrorCode: "cancelled", ErrorMessage: "task cancellation acknowledged"}
	envelope := h.envelope(v1.KindTaskResult, cancel.IdempotencyKey, result)
	envelope.AgentSequence = 1
	return []v1.Envelope{envelope}, nil
}

func (h *OutboundHandler) wrapTaskEvents(task v1.TaskRequest, ack v1.TaskAck, log *v1.LogChunk, observation any, result v1.TaskResult) ([]v1.Envelope, error) {
	events := []v1.Envelope{h.envelope(v1.KindTaskAck, task.IdempotencyKey, ack)}
	if log != nil {
		events = append(events, h.envelope(v1.KindLogChunk, task.IdempotencyKey, *log))
	}
	if observation != nil {
		events = append(events, h.envelope(v1.KindObservation, task.IdempotencyKey, observation))
	}
	events = append(events, h.envelope(v1.KindTaskResult, task.IdempotencyKey, result))
	for index := range events {
		events[index].AgentSequence = uint64(index + 1)
		if err := v1.ValidateEnvelopePayload(events[index]); err != nil {
			return nil, err
		}
	}
	return events, nil
}

func (h *OutboundHandler) envelope(kind v1.MessageKind, idempotencyKey string, payload any) v1.Envelope {
	encoded, _ := json.Marshal(payload)
	messageID, _ := domain.NewID("agent_message")
	return v1.Envelope{Protocol: v1.ProtocolName, Version: v1.ProtocolVersion, MessageID: messageID.String(), InstanceID: h.instanceID, NodeID: h.nodeID, Kind: kind, SentAt: h.clock().UTC(), IdempotencyKey: idempotencyKey, Payload: encoded}
}

func cloneEnvelopes(values []v1.Envelope) []v1.Envelope {
	result := make([]v1.Envelope, len(values))
	copy(result, values)
	for index := range result {
		result[index].Payload = append(json.RawMessage(nil), values[index].Payload...)
	}
	return result
}

func loadOutboundMTLSConfig(caPath, certificatePath, keyPath, serverName string) (*tls.Config, error) {
	if caPath == "" || certificatePath == "" || keyPath == "" || serverName == "" {
		return nil, errors.New("outbound Agent mTLS requires CA, certificate, key and server name")
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("outbound Agent CA contains no valid certificate")
	}
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{certificate}, ServerName: strings.TrimSpace(serverName)}, nil
}

var _ agenttransport.EnvelopeHandler = (*OutboundHandler)(nil)
