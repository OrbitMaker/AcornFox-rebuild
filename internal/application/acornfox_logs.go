package application

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const (
	AcornFoxLogsTaskDeadline       = 90 * time.Second
	AcornFoxLogsTaskAttempts       = 3
	AcornFoxLogsCollectionInterval = 30 * time.Second
	acornFoxLogsBucketWidth        = AcornFoxLogsCollectionInterval
)

// AcornFoxLogsCollectionSince is the default lower bound selected by the
// internal scheduler. Keeping it beside the bucket interval prevents the
// scheduler, candidate-freshness policy, and collection request from drifting.
func AcornFoxLogsCollectionSince(now time.Time) time.Time {
	if now.IsZero() {
		return time.Time{}
	}
	return now.UTC().Add(-AcornFoxLogsCollectionInterval)
}

// AcornFoxLogsTaskPlan is a read-only collection intent. Building it has no
// runtime or persistence side effect; only an internal scheduler may decide
// when to durably enqueue it, never a public GET path.
type AcornFoxLogsTaskPlan struct {
	Operation   domain.Operation
	TaskID      domain.ID
	Payload     json.RawMessage
	Deadline    time.Time
	MaxAttempts int
}

// BuildAcornFoxLogsTaskPlan turns one immutable, bounded request into a
// deterministic Agent task. A 30-second bucket matches the default internal
// collection cadence while stable replay inside that window returns the same
// operation and task identities.
func BuildAcornFoxLogsTaskPlan(request contracts.AcornFoxLogsRequest, now time.Time) (AcornFoxLogsTaskPlan, error) {
	if err := request.Validate(); err != nil {
		return AcornFoxLogsTaskPlan{}, fmt.Errorf("logs request is invalid: %w", err)
	}
	if now.IsZero() {
		return AcornFoxLogsTaskPlan{}, fmt.Errorf("logs task time is required")
	}
	now = now.UTC()
	bucket := now.Truncate(acornFoxLogsBucketWidth)
	operationID, err := contracts.AcornFoxRuntimeOperationID(request.Reference.Fact, "logs", request.IdempotencyKey+"\x00"+bucket.Format(time.RFC3339))
	if err != nil {
		return AcornFoxLogsTaskPlan{}, fmt.Errorf("logs operation identity is invalid: %w", err)
	}
	operation := domain.Operation{
		ID:             domain.ID(operationID),
		ApplicationID:  request.Reference.Fact.ApplicationID,
		EnvironmentID:  request.Reference.Fact.EnvironmentID,
		TargetRef:      "deployment/" + request.DeploymentID.String() + "/logs/" + request.ServiceName,
		Type:           domain.OperationObserve,
		IdempotencyKey: request.IdempotencyKey,
		Status:         domain.OperationPending,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := operation.Validate(); err != nil {
		return AcornFoxLogsTaskPlan{}, err
	}
	parameters, err := json.Marshal(struct {
		PayloadType string                        `json:"acornfox_log_payload_type"`
		Request     contracts.AcornFoxLogsRequest `json:"request"`
	}{PayloadType: "logs", Request: request})
	if err != nil {
		return AcornFoxLogsTaskPlan{}, err
	}
	payload, err := json.Marshal(struct {
		Kind       v1.TaskKind     `json:"kind"`
		Parameters json.RawMessage `json:"parameters"`
	}{Kind: v1.TaskLogs, Parameters: parameters})
	if err != nil {
		return AcornFoxLogsTaskPlan{}, err
	}
	taskID := domain.ID("task_" + strings.TrimPrefix(operationID, "acornfox-runtime-logs-"))
	return AcornFoxLogsTaskPlan{Operation: operation, TaskID: taskID, Payload: payload, Deadline: now.Add(AcornFoxLogsTaskDeadline), MaxAttempts: AcornFoxLogsTaskAttempts}, nil
}
