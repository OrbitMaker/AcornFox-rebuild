package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/domain"
)

const (
	acornFoxCandidatePayloadType = "acornfox_candidate_validation_v1"
	acornFoxCandidateCleanupTTL  = 10 * time.Second
)

var acornFoxCandidateIDPattern = regexp.MustCompile(`^candidate_[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// AcornFoxCandidateRuntime is the complete authority granted to candidate
// validation. Its input has no release, environment, host path, volume,
// secret, route, command or shell field. Implementations must use a dedicated
// runtime namespace and derive their container identity from
// AcornFoxCandidateRuntimeID.
type AcornFoxCandidateRuntime interface {
	Deploy(context.Context, AcornFoxCandidateRuntimeSpec) error
	Observe(context.Context, AcornFoxCandidateRuntimeSpec) (AcornFoxCandidateRuntimeObservation, error)
	Probe(context.Context, AcornFoxCandidateRuntimeSpec, AcornFoxCandidateRuntimeObservation) (AcornFoxCandidateRuntimeProbe, error)
	Destroy(context.Context, AcornFoxCandidateRuntimeSpec) error
	ConfirmAbsent(context.Context, AcornFoxCandidateRuntimeSpec) (AcornFoxCandidateRuntimeAbsence, error)
}

type AcornFoxCandidateRuntimeSpec struct {
	CandidateID   domain.ID                         `json:"candidate_id"`
	ApplicationID domain.ID                         `json:"application_id"`
	Image         AcornFoxCandidateImage            `json:"image"`
	ContainerPort int                               `json:"container_port"`
	Resources     AcornFoxCandidateRuntimeResources `json:"resources"`
}

type AcornFoxCandidateImage struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
}

type AcornFoxCandidateRuntimeResources struct {
	CPUMillis            int64 `json:"cpu_millis"`
	MemoryBytes          int64 `json:"memory_bytes"`
	PIDs                 int64 `json:"pids"`
	DiskReservationBytes int64 `json:"disk_reservation_bytes"`
}

type AcornFoxCandidateRuntimeObservation struct {
	RuntimeID        string                            `json:"runtime_id"`
	ContainerID      string                            `json:"container_id"`
	RuntimeState     string                            `json:"runtime_state"`
	Image            AcornFoxCandidateImage            `json:"image"`
	HostPort         int                               `json:"host_port"`
	AppliedResources AcornFoxCandidateRuntimeResources `json:"applied_resources"`
	ObservedAt       time.Time                         `json:"observed_at"`
}

type AcornFoxCandidateRuntimeProbe struct {
	RuntimeID   string    `json:"runtime_id"`
	ContainerID string    `json:"container_id"`
	TargetClass string    `json:"target_class"`
	Outcome     string    `json:"outcome"`
	EvidenceRef string    `json:"evidence_ref"`
	ObservedAt  time.Time `json:"observed_at"`
}

type AcornFoxCandidateRuntimeAbsence struct {
	RuntimeID   string    `json:"runtime_id"`
	Absent      bool      `json:"absent"`
	EvidenceRef string    `json:"evidence_ref"`
	ObservedAt  time.Time `json:"observed_at"`
}

type AcornFoxCandidateOutboundExecutor struct {
	instanceID string
	nodeID     string
	runtime    AcornFoxCandidateRuntime
	clock      func() time.Time
}

type acornFoxCandidateTaskPayload struct {
	PayloadType string          `json:"acornfox_candidate_payload_type"`
	Request     json.RawMessage `json:"request"`
}

type acornFoxCandidateOutboundResult struct {
	Logs         []v1.LogChunk
	Observations []v1.Observation
	Result       v1.TaskResult
}

func NewAcornFoxCandidateOutboundExecutor(instanceID, nodeID string, runtime AcornFoxCandidateRuntime) *AcornFoxCandidateOutboundExecutor {
	return &AcornFoxCandidateOutboundExecutor{instanceID: strings.TrimSpace(instanceID), nodeID: strings.TrimSpace(nodeID), runtime: runtime, clock: time.Now}
}

func acornFoxCandidatePayloadMarked(data json.RawMessage) bool {
	var object map[string]json.RawMessage
	if json.NewDecoder(bytes.NewReader(data)).Decode(&object) != nil {
		return false
	}
	_, present := object["acornfox_candidate_payload_type"]
	return present
}

func (e *AcornFoxCandidateOutboundExecutor) Execute(ctx context.Context, task v1.TaskRequest) acornFoxCandidateOutboundResult {
	if e == nil || e.runtime == nil {
		return rejectedAcornFoxCandidate(task, "unsupported_capability", "AcornFox candidate validation capability is unavailable")
	}
	if err := task.Validate(); err != nil || task.InstanceID != e.instanceID || task.NodeID != e.nodeID || !task.Deadline.After(e.now()) || task.Kind != v1.TaskDeploy {
		return rejectedAcornFoxCandidate(task, "invalid_argument", "AcornFox candidate validation task is invalid")
	}
	payload, err := decodeAcornFoxCandidatePayload(task.Parameters)
	if err != nil || payload.PayloadType != acornFoxCandidatePayloadType {
		return rejectedAcornFoxCandidate(task, "invalid_argument", "AcornFox candidate validation wrapper is invalid")
	}
	var spec AcornFoxCandidateRuntimeSpec
	if err := decodeStrictJSON(payload.Request, &spec); err != nil || spec.Validate() != nil {
		return rejectedAcornFoxCandidate(task, "invalid_argument", "AcornFox candidate runtime request is invalid")
	}

	taskContext, cancel := context.WithDeadline(ctx, task.Deadline)
	defer cancel()
	primaryCode := ""
	var observation AcornFoxCandidateRuntimeObservation
	var probe AcornFoxCandidateRuntimeProbe
	if err := e.runtime.Deploy(taskContext, spec); err != nil {
		primaryCode = candidateRuntimeFailureCode(taskContext, "candidate_runtime_deploy_failed")
	} else if observation, err = e.runtime.Observe(taskContext, spec); err != nil {
		primaryCode = candidateRuntimeFailureCode(taskContext, "candidate_runtime_observe_failed")
	} else if err = validateAcornFoxCandidateObservation(spec, observation); err != nil {
		primaryCode = "candidate_runtime_identity_mismatch"
	} else if probe, err = e.runtime.Probe(taskContext, spec, observation); err != nil {
		primaryCode = candidateRuntimeFailureCode(taskContext, "candidate_runtime_probe_failed")
	} else if err = validateAcornFoxCandidateProbe(spec, observation, probe); err != nil {
		primaryCode = "candidate_runtime_probe_invalid"
	}

	cleanupContext, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), acornFoxCandidateCleanupTTL)
	defer cleanupCancel()
	destroyErr := e.runtime.Destroy(cleanupContext, spec)
	absence, absenceErr := e.runtime.ConfirmAbsent(cleanupContext, spec)
	if destroyErr != nil {
		return failedAcornFoxCandidate(task, "candidate_runtime_cleanup_failed")
	}
	if absenceErr != nil || validateAcornFoxCandidateAbsence(spec, absence) != nil {
		return failedAcornFoxCandidate(task, "candidate_runtime_absence_unconfirmed")
	}
	if primaryCode != "" {
		return failedAcornFoxCandidate(task, primaryCode)
	}
	return completedAcornFoxCandidate(task, spec, probe, absence)
}

func (e *AcornFoxCandidateOutboundExecutor) now() time.Time {
	if e.clock == nil {
		return time.Now()
	}
	return e.clock()
}

func (spec AcornFoxCandidateRuntimeSpec) Validate() error {
	if !acornFoxCandidateIDPattern.MatchString(spec.CandidateID.String()) || spec.ApplicationID.Empty() {
		return errors.New("candidate runtime identity is invalid")
	}
	if _, err := domain.ParseImageDigest(spec.Image.Repository, spec.Image.Digest); err != nil {
		return errors.New("candidate runtime image is invalid")
	}
	if spec.ContainerPort < 1 || spec.ContainerPort > 65535 {
		return errors.New("candidate runtime container port is invalid")
	}
	if spec.Resources.CPUMillis <= 0 || spec.Resources.MemoryBytes <= 0 || spec.Resources.PIDs <= 0 || spec.Resources.DiskReservationBytes <= 0 {
		return errors.New("candidate runtime resources are invalid")
	}
	return nil
}

// AcornFoxCandidateRuntimeID deterministically binds all accepted fields. It has a
// candidate-only prefix and cannot be mistaken for a normal deployment ID.
func AcornFoxCandidateRuntimeID(spec AcornFoxCandidateRuntimeSpec) (string, error) {
	if err := spec.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "candidate_runtime_" + hex.EncodeToString(digest[:16]), nil
}

func decodeAcornFoxCandidatePayload(data json.RawMessage) (acornFoxCandidateTaskPayload, error) {
	var payload acornFoxCandidateTaskPayload
	if err := decodeStrictJSON(data, &payload); err != nil || strings.TrimSpace(payload.PayloadType) == "" || len(payload.Request) == 0 {
		return acornFoxCandidateTaskPayload{}, errors.New("AcornFox candidate task wrapper is invalid")
	}
	return payload, nil
}

func validateAcornFoxCandidateObservation(spec AcornFoxCandidateRuntimeSpec, observation AcornFoxCandidateRuntimeObservation) error {
	runtimeID, err := AcornFoxCandidateRuntimeID(spec)
	if err != nil || observation.RuntimeID != runtimeID || strings.TrimSpace(observation.ContainerID) == "" || observation.RuntimeState != "running" || observation.Image != spec.Image || observation.HostPort < 1 || observation.HostPort > 65535 || observation.AppliedResources != spec.Resources || observation.ObservedAt.IsZero() {
		return errors.New("candidate runtime observation is invalid")
	}
	return nil
}

func validateAcornFoxCandidateProbe(spec AcornFoxCandidateRuntimeSpec, observation AcornFoxCandidateRuntimeObservation, probe AcornFoxCandidateRuntimeProbe) error {
	runtimeID, err := AcornFoxCandidateRuntimeID(spec)
	if err != nil || probe.RuntimeID != runtimeID || probe.ContainerID != observation.ContainerID || probe.TargetClass != "loopback" || probe.Outcome != "responded" || strings.TrimSpace(probe.EvidenceRef) == "" || probe.ObservedAt.IsZero() {
		return errors.New("candidate runtime probe result is invalid")
	}
	return nil
}

func validateAcornFoxCandidateAbsence(spec AcornFoxCandidateRuntimeSpec, absence AcornFoxCandidateRuntimeAbsence) error {
	runtimeID, err := AcornFoxCandidateRuntimeID(spec)
	if err != nil || absence.RuntimeID != runtimeID || !absence.Absent || strings.TrimSpace(absence.EvidenceRef) == "" || absence.ObservedAt.IsZero() {
		return errors.New("candidate runtime absence is invalid")
	}
	return nil
}

func candidateRuntimeFailureCode(ctx context.Context, fallback string) string {
	if ctx.Err() != nil {
		return "candidate_runtime_cancelled"
	}
	return fallback
}

func completedAcornFoxCandidate(task v1.TaskRequest, spec AcornFoxCandidateRuntimeSpec, probe AcornFoxCandidateRuntimeProbe, absence AcornFoxCandidateRuntimeAbsence) acornFoxCandidateOutboundResult {
	details, err := json.Marshal(struct {
		CandidateID domain.ID                         `json:"candidate_id"`
		RuntimeID   string                            `json:"runtime_id"`
		Image       AcornFoxCandidateImage            `json:"image"`
		Resources   AcornFoxCandidateRuntimeResources `json:"resources"`
		Probe       AcornFoxCandidateRuntimeProbe     `json:"probe"`
		Absence     AcornFoxCandidateRuntimeAbsence   `json:"absence"`
	}{CandidateID: spec.CandidateID, RuntimeID: absence.RuntimeID, Image: spec.Image, Resources: spec.Resources, Probe: probe, Absence: absence})
	if err != nil {
		return failedAcornFoxCandidate(task, "internal_error")
	}
	refs := []string{probe.EvidenceRef, absence.EvidenceRef}
	return acornFoxCandidateOutboundResult{
		Logs:         []v1.LogChunk{{TaskID: task.TaskID, Sequence: 1, Stream: v1.LogStreamStdout, Data: "candidate runtime validation and cleanup completed", Final: true}},
		Observations: []v1.Observation{{TaskID: task.TaskID, Sequence: 1, TargetRef: "candidate/" + spec.CandidateID.String() + "/runtime", Status: "stopped", Healthy: false, At: absence.ObservedAt.UTC(), EvidenceRefs: refs, Details: details}},
		Result:       v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Succeeded: true, Status: v1.TaskResultSucceeded, EvidenceRefs: refs},
	}
}

func rejectedAcornFoxCandidate(task v1.TaskRequest, code, message string) acornFoxCandidateOutboundResult {
	return acornFoxCandidateOutboundResult{Result: v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: code, ErrorMessage: message}}
}

func failedAcornFoxCandidate(task v1.TaskRequest, code string) acornFoxCandidateOutboundResult {
	return acornFoxCandidateOutboundResult{
		Logs:   []v1.LogChunk{{TaskID: task.TaskID, Sequence: 1, Stream: v1.LogStreamStderr, Data: "candidate runtime validation failed", Final: true}},
		Result: v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: code, ErrorMessage: "candidate runtime validation failed"},
	}
}
