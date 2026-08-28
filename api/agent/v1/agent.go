// Package v1 defines the versioned Node Agent wire model. Transport security
// is intentionally outside this package: production deployments use
// agent-initiated mutual TLS, while tests can validate the same messages over
// an in-memory codec.
package v1

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var ErrCapabilityUnavailable = errors.New("agent capability unavailable")

const (
	ProtocolName            = "open-card-agent"
	ProtocolVersion         = "1.1"
	PreviousProtocolVersion = "1.0"
	LegacyProtocolVersion   = "v1"
)

type MessageKind string

const (
	KindHello       MessageKind = "hello"
	KindHeartbeat   MessageKind = "heartbeat"
	KindTaskRequest MessageKind = "task_request"
	KindTaskAck     MessageKind = "task_ack"
	KindTaskResult  MessageKind = "task_result"
	KindCancelTask  MessageKind = "cancel_task"
	KindLogChunk    MessageKind = "log_chunk"
	KindObservation MessageKind = "observation"
)

type TaskKind string

const (
	TaskObserve       TaskKind = "observe"
	TaskDeploy        TaskKind = "deploy"
	TaskDeployGroup   TaskKind = "deploy_group"
	TaskDestroyGroup  TaskKind = "destroy_group"
	TaskDestroyVolume TaskKind = "destroy_volume"
	TaskLogs          TaskKind = "logs"
	TaskRestart       TaskKind = "restart"
	TaskScale         TaskKind = "scale"
	TaskRollback      TaskKind = "rollback"
	TaskDestroy       TaskKind = "destroy"
)

func (t TaskKind) Allowed() bool {
	switch t {
	case TaskObserve, TaskDeploy, TaskDeployGroup, TaskDestroyGroup, TaskDestroyVolume, TaskLogs, TaskRestart, TaskScale, TaskRollback, TaskDestroy:
		return true
	default:
		return false
	}
}

const (
	AgentCapabilityRuntimeDeployGroup         = "runtime.deploy_group"
	AgentCapabilityRuntimeObserveGroup        = "runtime.observe_group"
	AgentCapabilityRuntimeLogsGroup           = "runtime.logs_group"
	AgentCapabilityRuntimeRollbackGroup       = "runtime.rollback_group"
	AgentCapabilityRuntimeDestroyGroup        = "runtime.destroy_group"
	AgentCapabilityRuntimeRestartGroupService = "runtime.restart_group_service"
	AgentCapabilityRuntimeRestartGroup        = "runtime.restart_group"
	AgentCapabilityRuntimeRestart             = "runtime.restart"
	AgentCapabilityRuntimeRollback            = "runtime.rollback"
)

func (t TaskKind) RequiredCapability() string {
	if t == TaskDeployGroup {
		return AgentCapabilityRuntimeDeployGroup
	}
	if t == TaskDestroyGroup || t == TaskDestroyVolume {
		return AgentCapabilityRuntimeDestroyGroup
	}
	return ""
}

// RequiredCapabilityForTaskRequest refines the broad TaskKind gate for M4's
// strict ServiceGroup recovery wrapper. An old Agent must not receive a group
// restart/rollback/redeploy merely because it supports a single-container
// task with the same wire kind.
func RequiredCapabilityForTaskRequest(task TaskRequest) string {
	var marker struct {
		PayloadType string `json:"m4_payload_type"`
	}
	if json.Unmarshal(task.Parameters, &marker) == nil && marker.PayloadType != "" {
		switch marker.PayloadType {
		case "service_group.observe":
			return AgentCapabilityRuntimeObserveGroup
		case "service_group.logs":
			return AgentCapabilityRuntimeLogsGroup
		case "service_group.redeploy":
			return AgentCapabilityRuntimeDeployGroup
		case "service_group.rollback":
			return AgentCapabilityRuntimeRollbackGroup
		case "service_group.restart_service":
			return AgentCapabilityRuntimeRestartGroupService
		case "service_group.restart":
			return AgentCapabilityRuntimeRestartGroup
		default:
			return "m4.unknown_payload"
		}
	}
	switch task.Kind {
	case TaskRestart:
		return AgentCapabilityRuntimeRestart
	case TaskRollback:
		return AgentCapabilityRuntimeRollback
	default:
		return task.Kind.RequiredCapability()
	}
}

func IsAggregateRuntimeCapability(capability string) bool {
	switch capability {
	case AgentCapabilityRuntimeDeployGroup, AgentCapabilityRuntimeObserveGroup, AgentCapabilityRuntimeLogsGroup, AgentCapabilityRuntimeRollbackGroup, AgentCapabilityRuntimeDestroyGroup, AgentCapabilityRuntimeRestartGroupService, AgentCapabilityRuntimeRestartGroup:
		return true
	default:
		return false
	}
}

type Envelope struct {
	Protocol       string          `json:"protocol"`
	Version        string          `json:"version"`
	MessageID      string          `json:"message_id"`
	InstanceID     string          `json:"instance_id"`
	NodeID         string          `json:"node_id"`
	Kind           MessageKind     `json:"kind"`
	SentAt         time.Time       `json:"sent_at"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	AgentSequence  uint64          `json:"agent_sequence,omitempty"`
	Payload        json.RawMessage `json:"payload,omitempty"`
}

func (e Envelope) Validate() error {
	if e.Protocol != ProtocolName {
		return ValidationError("unsupported agent protocol")
	}
	normalizedVersion, err := NormalizeProtocolVersion(e.Version)
	if err != nil {
		return ValidationError("unsupported agent protocol version")
	}
	if strings.TrimSpace(e.MessageID) == "" || strings.TrimSpace(e.InstanceID) == "" || strings.TrimSpace(e.NodeID) == "" {
		return ValidationError("agent envelope identity is required")
	}
	if !validMessageKind(e.Kind) {
		return ValidationError("agent message kind is unsupported")
	}
	if e.SentAt.IsZero() {
		return ValidationError("agent envelope timestamp is required")
	}
	if normalizedVersion == ProtocolVersion && isAgentTaskEvent(e.Kind) && e.AgentSequence == 0 {
		return ValidationError("agent task event sequence is required")
	}
	if len(e.Payload) == 0 {
		return ValidationError("agent message payload is required")
	}
	return nil
}

type Hello struct {
	InstanceID    string   `json:"instance_id"`
	NodeID        string   `json:"node_id"`
	AgentVersion  string   `json:"agent_version"`
	Capabilities  []string `json:"capabilities"`
	CertificateID string   `json:"certificate_id"`
}

func (h Hello) Validate() error {
	if err := requireAgentIdentity(h.InstanceID, h.NodeID); err != nil {
		return err
	}
	if strings.TrimSpace(h.AgentVersion) == "" {
		return ValidationError("agent version is required")
	}
	for _, capability := range h.Capabilities {
		if strings.TrimSpace(capability) == "" {
			return ValidationError("agent capability must not be blank")
		}
	}
	return nil
}

type Heartbeat struct {
	InstanceID string    `json:"instance_id"`
	NodeID     string    `json:"node_id"`
	Sequence   uint64    `json:"sequence"`
	At         time.Time `json:"at"`
	Load       Load      `json:"load"`
}

func (h Heartbeat) Validate() error {
	if err := requireAgentIdentity(h.InstanceID, h.NodeID); err != nil {
		return err
	}
	if h.Sequence == 0 {
		return ValidationError("agent heartbeat sequence must be positive")
	}
	if h.At.IsZero() {
		return ValidationError("agent heartbeat timestamp is required")
	}
	if h.Load.CPUMillis < 0 || h.Load.MemoryBytes < 0 || h.Load.MemoryAvailable < 0 || h.Load.DiskBytes < 0 || h.Load.DiskAvailable < 0 {
		return ValidationError("agent heartbeat load values must not be negative")
	}
	return nil
}

type Load struct {
	CPUMillis       int64 `json:"cpu_millis"`
	MemoryBytes     int64 `json:"memory_bytes"`
	MemoryAvailable int64 `json:"memory_available"`
	DiskBytes       int64 `json:"disk_bytes"`
	DiskAvailable   int64 `json:"disk_available"`
}

type TaskRequest struct {
	TaskID         string          `json:"task_id"`
	InstanceID     string          `json:"instance_id"`
	NodeID         string          `json:"node_id"`
	Kind           TaskKind        `json:"kind"`
	IdempotencyKey string          `json:"idempotency_key"`
	LeaseID        string          `json:"lease_id"`
	Parameters     json.RawMessage `json:"parameters"`
	Deadline       time.Time       `json:"deadline"`
}

func (r TaskRequest) Validate() error {
	if err := requireAgentIdentity(r.InstanceID, r.NodeID); err != nil {
		return err
	}
	if strings.TrimSpace(r.TaskID) == "" {
		return ValidationError("agent task id is required")
	}
	if !r.Kind.Allowed() {
		return ValidationError("agent task kind is not allowlisted")
	}
	if strings.TrimSpace(r.IdempotencyKey) == "" || strings.TrimSpace(r.LeaseID) == "" {
		return ValidationError("agent task idempotency key and lease are required")
	}
	if len(r.Parameters) == 0 {
		return ValidationError("agent task parameters are required")
	}
	if err := validateJSONObject(r.Parameters, "agent task parameters"); err != nil {
		return err
	}
	if r.Deadline.IsZero() {
		return ValidationError("agent task deadline is required")
	}
	return nil
}

type TaskAckStatus string

const (
	AckAccepted  TaskAckStatus = "accepted"
	AckDuplicate TaskAckStatus = "duplicate"
	AckRejected  TaskAckStatus = "rejected"
)

type TaskAck struct {
	TaskID string        `json:"task_id"`
	Status TaskAckStatus `json:"status"`
	Reason string        `json:"reason,omitempty"`
}

func (a TaskAck) Validate() error {
	if strings.TrimSpace(a.TaskID) == "" {
		return ValidationError("agent task ack task id is required")
	}
	switch a.Status {
	case AckAccepted, AckDuplicate:
	case AckRejected:
		if strings.TrimSpace(a.Reason) == "" {
			return ValidationError("rejected task ack reason is required")
		}
	default:
		return ValidationError("agent task ack status is unsupported")
	}
	return nil
}

type TaskResult struct {
	TaskID         string   `json:"task_id"`
	IdempotencyKey string   `json:"idempotency_key"`
	Succeeded      bool     `json:"succeeded"`
	Status         string   `json:"status"`
	ErrorCode      string   `json:"error_code,omitempty"`
	ErrorMessage   string   `json:"error_message,omitempty"`
	EvidenceRefs   []string `json:"evidence_refs,omitempty"`
}

func (r TaskResult) Validate() error {
	if strings.TrimSpace(r.TaskID) == "" || strings.TrimSpace(r.IdempotencyKey) == "" {
		return ValidationError("agent task result identity is required")
	}
	if !validTaskResultStatus(r.Status) {
		return ValidationError("agent task result status is unsupported")
	}
	if r.Succeeded && r.Status != TaskResultSucceeded {
		return ValidationError("successful task result must have succeeded status")
	}
	if !r.Succeeded && r.Status == TaskResultSucceeded {
		return ValidationError("unsuccessful task result cannot have succeeded status")
	}
	return validateEvidenceRefs(r.EvidenceRefs, "agent task result evidence refs")
}

type CancelTask struct {
	TaskID         string `json:"task_id"`
	IdempotencyKey string `json:"idempotency_key"`
	Reason         string `json:"reason"`
}

func (c CancelTask) Validate() error {
	if strings.TrimSpace(c.TaskID) == "" || strings.TrimSpace(c.IdempotencyKey) == "" {
		return ValidationError("agent cancel task identity is required")
	}
	if strings.TrimSpace(c.Reason) == "" {
		return ValidationError("agent cancel task reason is required")
	}
	return nil
}

type LogChunk struct {
	TaskID   string `json:"task_id"`
	Sequence uint64 `json:"sequence"`
	Stream   string `json:"stream"`
	Data     string `json:"data"`
	Final    bool   `json:"final"`
}

func (l LogChunk) Validate() error {
	if strings.TrimSpace(l.TaskID) == "" {
		return ValidationError("agent log chunk task id is required")
	}
	if l.Sequence == 0 {
		return ValidationError("agent log chunk sequence must be positive")
	}
	switch l.Stream {
	case LogStreamStdout, LogStreamStderr:
	default:
		return ValidationError("agent log chunk stream is unsupported")
	}
	return nil
}

type Observation struct {
	TaskID       string          `json:"task_id"`
	Sequence     uint64          `json:"sequence"`
	TargetRef    string          `json:"target_ref"`
	Status       string          `json:"status"`
	Healthy      bool            `json:"healthy"`
	At           time.Time       `json:"at"`
	EvidenceRefs []string        `json:"evidence_refs,omitempty"`
	Details      json.RawMessage `json:"details,omitempty"`
}

func (o Observation) Validate() error {
	if strings.TrimSpace(o.TaskID) == "" || strings.TrimSpace(o.TargetRef) == "" {
		return ValidationError("agent observation identity is required")
	}
	if o.Sequence == 0 {
		return ValidationError("agent observation sequence must be positive")
	}
	if !validObservationStatus(o.Status) {
		return ValidationError("agent observation status is unsupported")
	}
	if o.At.IsZero() {
		return ValidationError("agent observation timestamp is required")
	}
	if len(o.Details) > 0 {
		if err := validateJSONObject(o.Details, "agent observation details"); err != nil {
			return err
		}
	}
	return validateEvidenceRefs(o.EvidenceRefs, "agent observation evidence refs")
}

const (
	LogStreamStdout = "stdout"
	LogStreamStderr = "stderr"

	TaskStatePending     = "pending"
	TaskStateAccepted    = "accepted"
	TaskStateCancelling  = "cancelling"
	TaskStateRunning     = "running"
	TaskStateWaiting     = "waiting"
	TaskStateSucceeded   = "succeeded"
	TaskStateFailed      = "failed"
	TaskStateCancelled   = "cancelled"
	TaskStateRollingBack = "rolling_back"
	TaskStateRolledBack  = "rolled_back"

	TaskResultSucceeded = "succeeded"
	TaskResultFailed    = "failed"
	TaskResultCancelled = "cancelled"
)

// TaskSnapshot is the control-plane projection returned by a task status
// query. StartedAt and FinishedAt remain zero until those lifecycle points
// have been observed; Result is present only when a result was recorded.
type TaskSnapshot struct {
	TaskID         string      `json:"task_id"`
	IdempotencyKey string      `json:"idempotency_key"`
	Kind           TaskKind    `json:"kind"`
	State          string      `json:"state"`
	AcceptedAt     time.Time   `json:"accepted_at"`
	StartedAt      time.Time   `json:"started_at,omitempty"`
	FinishedAt     time.Time   `json:"finished_at,omitempty"`
	Result         *TaskResult `json:"result,omitempty"`
}

func (s TaskSnapshot) Validate() error {
	if strings.TrimSpace(s.TaskID) == "" || strings.TrimSpace(s.IdempotencyKey) == "" {
		return ValidationError("agent task snapshot identity is required")
	}
	if !s.Kind.Allowed() {
		return ValidationError("agent task snapshot kind is not allowlisted")
	}
	if !validTaskState(s.State) {
		return ValidationError("agent task snapshot state is unsupported")
	}
	if s.AcceptedAt.IsZero() {
		return ValidationError("agent task snapshot accepted timestamp is required")
	}
	if !s.StartedAt.IsZero() && s.StartedAt.Before(s.AcceptedAt) {
		return ValidationError("agent task snapshot started timestamp precedes acceptance")
	}
	if !s.FinishedAt.IsZero() {
		if s.FinishedAt.Before(s.AcceptedAt) {
			return ValidationError("agent task snapshot finished timestamp precedes acceptance")
		}
		if !s.StartedAt.IsZero() && s.FinishedAt.Before(s.StartedAt) {
			return ValidationError("agent task snapshot finished timestamp precedes start")
		}
	}
	if s.Result != nil {
		if err := s.Result.Validate(); err != nil {
			return err
		}
		if s.Result.TaskID != s.TaskID || s.Result.IdempotencyKey != s.IdempotencyKey {
			return ValidationError("agent task snapshot result identity does not match task")
		}
	}
	return nil
}

type ErrorResponse struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

func EncodeEnvelope(e Envelope) ([]byte, error) {
	if err := ValidateEnvelopePayload(e); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

func DecodeEnvelope(data []byte) (Envelope, error) {
	var envelope Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return Envelope{}, err
	}
	if err := ValidateEnvelopePayload(envelope); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

func ValidateEnvelopePayload(envelope Envelope) error {
	if err := envelope.Validate(); err != nil {
		return err
	}
	validate := func(target any, check func() error) error {
		if err := json.Unmarshal(envelope.Payload, target); err != nil {
			return err
		}
		return check()
	}
	switch envelope.Kind {
	case KindHello:
		var value Hello
		return validate(&value, func() error { return value.Validate() })
	case KindHeartbeat:
		var value Heartbeat
		return validate(&value, func() error { return value.Validate() })
	case KindTaskRequest:
		var value TaskRequest
		return validate(&value, func() error { return value.Validate() })
	case KindTaskAck:
		var value TaskAck
		return validate(&value, func() error { return value.Validate() })
	case KindTaskResult:
		var value TaskResult
		return validate(&value, func() error { return value.Validate() })
	case KindCancelTask:
		var value CancelTask
		return validate(&value, func() error { return value.Validate() })
	case KindLogChunk:
		var value LogChunk
		return validate(&value, func() error { return value.Validate() })
	case KindObservation:
		var value Observation
		return validate(&value, func() error { return value.Validate() })
	default:
		return ValidationError("agent message kind is unsupported")
	}
}

func validMessageKind(kind MessageKind) bool {
	switch kind {
	case KindHello, KindHeartbeat, KindTaskRequest, KindTaskAck, KindTaskResult, KindCancelTask, KindLogChunk, KindObservation:
		return true
	default:
		return false
	}
}

func requireAgentIdentity(instanceID, nodeID string) error {
	if strings.TrimSpace(instanceID) == "" || strings.TrimSpace(nodeID) == "" {
		return ValidationError("agent instance and node identity are required")
	}
	return nil
}

func validateJSONObject(raw json.RawMessage, field string) error {
	if strings.TrimSpace(string(raw)) == "" {
		return ValidationError(field + " are required")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return ValidationError(field + " must be a valid JSON object")
	}
	return nil
}

func validateEvidenceRefs(refs []string, field string) error {
	for _, ref := range refs {
		if strings.TrimSpace(ref) == "" {
			return ValidationError(field + " must not contain empty references")
		}
	}
	return nil
}

func validTaskResultStatus(status string) bool {
	switch status {
	case TaskResultSucceeded, TaskResultFailed, TaskResultCancelled:
		return true
	default:
		return false
	}
}

func validObservationStatus(status string) bool {
	switch status {
	case "healthy", "unhealthy", "unknown", "pending", "preparing", "deploying", "runtime_ready", "degraded", "serving", "failed", "rolling_back", "rolled_back", "stopped":
		return true
	default:
		return false
	}
}

func validTaskState(state string) bool {
	switch state {
	case TaskStatePending, TaskStateAccepted, TaskStateCancelling, TaskStateRunning, TaskStateWaiting, TaskStateSucceeded, TaskStateFailed, TaskStateCancelled, TaskStateRollingBack, TaskStateRolledBack:
		return true
	default:
		return false
	}
}

// ValidationError is local to the wire package so it can be used by generated
// protocol adapters without importing the domain package.
type ValidationError string

func (e ValidationError) Error() string { return string(e) }
