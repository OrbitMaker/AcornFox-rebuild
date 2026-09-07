package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

type acornFoxOperationTask struct {
	ID        domain.ID
	State     TaskState
	Payload   json.RawMessage
	CreatedAt time.Time
	UpdatedAt time.Time
}

// GetAcornFoxOperationResult returns a bounded, app-scoped read model. It
// treats malformed, missing, ambiguous, or historical evidence as unknown,
// never as execution success.
func (s *Store) GetAcornFoxOperationResult(ctx context.Context, applicationID, operationID domain.ID) (contracts.AcornFoxOperationResult, error) {
	if err := s.requireDB(); err != nil {
		return contracts.AcornFoxOperationResult{}, err
	}
	if err := domain.RequireID(applicationID, "application id"); err != nil {
		return contracts.AcornFoxOperationResult{}, err
	}
	if err := domain.RequireID(operationID, "operation id"); err != nil {
		return contracts.AcornFoxOperationResult{}, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT operation.id,operation.application_id,operation.environment_id,operation.deployment_id,
		       operation.operation_type,operation.state,operation.created_at,operation.updated_at,
		       task.task_id,task.state,task.payload,task.created_at,task.updated_at
		  FROM operations operation
		  LEFT JOIN task_leases task ON task.operation_id=operation.id
		 WHERE operation.id=$1 AND operation.application_id=$2
		 ORDER BY task.created_at,task.task_id
	`, operationID.String(), applicationID.String())
	if err != nil {
		return contracts.AcornFoxOperationResult{}, fmt.Errorf("query AcornFox operation result: %w", err)
	}
	defer rows.Close()
	var result contracts.AcornFoxOperationResult
	var environmentID domain.ID
	var operationState string
	tasks := make([]acornFoxOperationTask, 0, 1)
	for rows.Next() {
		var rowID, rowApplicationID, rowEnvironmentID, operationType, rowOperationState string
		var deployment sql.NullString
		var taskID, taskState sql.NullString
		var taskPayload []byte
		var taskCreatedAt, taskUpdatedAt sql.NullTime
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&rowID, &rowApplicationID, &rowEnvironmentID, &deployment, &operationType, &rowOperationState, &createdAt, &updatedAt, &taskID, &taskState, &taskPayload, &taskCreatedAt, &taskUpdatedAt); err != nil {
			return contracts.AcornFoxOperationResult{}, fmt.Errorf("scan AcornFox operation result: %w", err)
		}
		if result.OperationID.Empty() {
			result = contracts.AcornFoxOperationResult{OperationID: domain.ID(rowID), OperationType: operationType, Status: contracts.AcornFoxOperationUnknown, AcceptedAt: createdAt.UTC(), UpdatedAt: updatedAt.UTC()}
			environmentID = domain.ID(rowEnvironmentID)
			operationState = rowOperationState
			if rowApplicationID != applicationID.String() || rowID != operationID.String() || deployment.Valid && domain.ID(deployment.String).Empty() {
				return contracts.AcornFoxOperationResult{}, domain.ValidationError("persisted AcornFox operation scope is invalid")
			}
			if deployment.Valid {
				result.DeploymentID = domain.ID(deployment.String)
			}
		} else if result.OperationType != operationType || operationState != rowOperationState || result.AcceptedAt != createdAt.UTC() || result.UpdatedAt != updatedAt.UTC() {
			return contracts.AcornFoxOperationResult{}, domain.ValidationError("persisted AcornFox operation rows disagree")
		}
		if taskID.Valid {
			if !taskState.Valid || !taskCreatedAt.Valid || !taskUpdatedAt.Valid || !json.Valid(taskPayload) {
				return result, nil
			}
			tasks = append(tasks, acornFoxOperationTask{ID: domain.ID(taskID.String), State: TaskState(taskState.String), Payload: append(json.RawMessage(nil), taskPayload...), CreatedAt: taskCreatedAt.Time.UTC(), UpdatedAt: taskUpdatedAt.Time.UTC()})
		}
		result.Status = projectAcornFoxOperationFailure(operationState, result.Status, tasks)
	}
	if err := rows.Err(); err != nil {
		return contracts.AcornFoxOperationResult{}, fmt.Errorf("iterate AcornFox operation result: %w", err)
	}
	if result.OperationID.Empty() {
		return contracts.AcornFoxOperationResult{}, ErrNotFound
	}
	if result.Status == contracts.AcornFoxOperationFailed {
		return result, nil
	}
	if len(tasks) != 1 {
		return result, nil
	}
	task := tasks[0]
	result.TaskID = task.ID
	if evidence, found, err := s.acornFoxOperationEvidence(ctx, applicationID, environmentID, result, task); err != nil {
		return contracts.AcornFoxOperationResult{}, err
	} else if found {
		result.Status, result.Evidence = contracts.AcornFoxOperationVerified, evidence
		return result, nil
	}
	if task.State == TaskCompleted {
		return result, nil
	}
	if task.State == TaskReady && operationState == string(domain.OperationPending) {
		result.Status = contracts.AcornFoxOperationAccepted
		return result, nil
	}
	if task.State == TaskLeased || operationState == string(domain.OperationLeased) || operationState == string(domain.OperationRunning) || operationState == string(domain.OperationWaiting) || operationState == string(domain.OperationCancelling) {
		result.Status = contracts.AcornFoxOperationRunning
	}
	return result, nil
}

func projectAcornFoxOperationFailure(operationState string, current contracts.AcornFoxOperationStatus, tasks []acornFoxOperationTask) contracts.AcornFoxOperationStatus {
	switch domain.OperationStatus(operationState) {
	case domain.OperationFailed, domain.OperationCancelled, domain.OperationRolledBack:
		return contracts.AcornFoxOperationFailed
	}
	for _, task := range tasks {
		if task.State == TaskFailed || task.State == TaskCancelled {
			return contracts.AcornFoxOperationFailed
		}
	}
	return current
}

func (s *Store) acornFoxOperationEvidence(ctx context.Context, applicationID, environmentID domain.ID, result contracts.AcornFoxOperationResult, task acornFoxOperationTask) (*contracts.AcornFoxOperationEvidence, bool, error) {
	probe, marked, err := decodeAcornFoxProbeTaskPayload(task.Payload)
	if err != nil || marked {
		if err != nil || result.OperationType != string(domain.OperationObserve) || result.DeploymentID.Empty() {
			return nil, false, nil
		}
		expected, identityErr := contracts.AcornFoxRuntimeDeploymentID(probe.Reference.Fact)
		if identityErr != nil || expected != result.DeploymentID || probe.Reference.Fact.ApplicationID != applicationID || probe.Reference.Fact.EnvironmentID != environmentID {
			return nil, false, nil
		}
		facts, queryErr := s.ListAcornFoxProbeObservations(ctx, task.ID.String(), 2)
		if queryErr != nil {
			return nil, false, fmt.Errorf("read AcornFox operation probe evidence: %w", queryErr)
		}
		if len(facts) != 1 || facts[0].ApplicationID != applicationID.String() || facts[0].EnvironmentID != environmentID.String() || facts[0].DeploymentID != result.DeploymentID.String() || facts[0].ReleaseID != probe.Reference.Fact.ReleaseID.String() || facts[0].ServiceName != probe.Reference.Fact.ServiceName || facts[0].Protocol != probe.Protocol {
			return nil, false, nil
		}
		evidence := &contracts.AcornFoxOperationEvidence{Kind: contracts.AcornFoxOperationResponseObservation, Verdict: acornFoxProbeVerdict(facts[0]), ObservedAt: facts[0].ObservedAt.UTC(), HTTPStatus: facts[0].HTTPStatus}
		if evidence.Verdict == contracts.AcornFoxOperationEvidenceUnknown || evidence.Validate() != nil {
			return nil, false, nil
		}
		return evidence, true, nil
	}

	fact, action, runtimeMarked, runtimeErr := decodeAcornFoxOperationRuntimeTask(task.Payload)
	if runtimeErr != nil || !runtimeMarked || result.DeploymentID.Empty() || !matchesAcornFoxOperationType(result.OperationType, action) {
		return nil, false, nil
	}
	expected, identityErr := contracts.AcornFoxRuntimeDeploymentID(fact)
	if identityErr != nil || expected != result.DeploymentID || fact.ApplicationID != applicationID || fact.EnvironmentID != environmentID {
		return nil, false, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM task_agent_events WHERE task_id=$1 AND event_type='observation' ORDER BY sequence DESC`, task.ID.String())
	if err != nil {
		return nil, false, fmt.Errorf("read AcornFox operation runtime evidence: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var payload json.RawMessage
		if err := rows.Scan(&payload); err != nil {
			return nil, false, err
		}
		var event v1.Observation
		var observed contracts.AcornFoxRuntimeObservation
		if decodeControllerTaskJSON(payload, &event) != nil || len(event.Details) == 0 || decodeControllerTaskJSON(event.Details, &observed) != nil || !acornFoxOperationRuntimeObservationMatches(fact, result.DeploymentID, observed) {
			continue
		}
		evidence := &contracts.AcornFoxOperationEvidence{Kind: contracts.AcornFoxOperationRuntimeObservation, Verdict: contracts.AcornFoxOperationEvidenceObserved, ObservedAt: observed.ObservedAt.UTC()}
		return evidence, true, nil
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return nil, false, nil
}

func decodeAcornFoxOperationRuntimeTask(payload json.RawMessage) (contracts.AcornFoxRuntimeReleaseFact, string, bool, error) {
	request, marked, err := decodeAcornFoxRuntimeTask(payload)
	if marked {
		if err != nil {
			return contracts.AcornFoxRuntimeReleaseFact{}, "", true, err
		}
		if request.Recreate {
			return request.Fact, "redeploy", true, nil
		}
		return request.Fact, "deploy", true, nil
	}
	var task struct {
		Kind       v1.TaskKind     `json:"kind"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if decodeControllerTaskJSON(payload, &task) != nil || task.Kind != v1.TaskRestart {
		return contracts.AcornFoxRuntimeReleaseFact{}, "", false, nil
	}
	var wrapped struct {
		PayloadType string                                 `json:"acornfox_payload_type"`
		Request     contracts.AcornFoxRuntimeActionRequest `json:"request"`
	}
	if decodeControllerTaskJSON(task.Parameters, &wrapped) != nil || wrapped.PayloadType != "restart" || wrapped.Request.Validate() != nil {
		return contracts.AcornFoxRuntimeReleaseFact{}, "", true, domain.ValidationError("AcornFox restart task is invalid")
	}
	return wrapped.Request.Fact, "restart", true, nil
}

func matchesAcornFoxOperationType(operationType, action string) bool {
	return (operationType == string(domain.OperationDeploy) && action == "deploy") || (operationType == string(domain.OperationRedeploy) && action == "redeploy") || (operationType == string(domain.OperationRestart) && action == "restart")
}

func acornFoxOperationRuntimeObservationMatches(fact contracts.AcornFoxRuntimeReleaseFact, deploymentID domain.ID, observed contracts.AcornFoxRuntimeObservation) bool {
	if observed.DeploymentID != deploymentID || observed.ServiceName != fact.ServiceName || observed.ObservedAt.IsZero() || observed.RequestedResources != fact.Resources || observed.AppliedLimits.CPUMillis != fact.Resources.CPUMillis || observed.AppliedLimits.MemoryBytes != fact.Resources.MemoryBytes || observed.AppliedLimits.PIDs != fact.Resources.PIDs {
		return false
	}
	return (fact.ContainerPort == 0 && observed.InternalAddress == "") || (fact.ContainerPort > 0 && observed.InternalAddress != "")
}

func acornFoxProbeVerdict(observation AcornFoxProbeObservation) contracts.AcornFoxOperationEvidenceVerdict {
	if observation.Outcome == contracts.AcornFoxProbeOutcomeNotApplicable {
		return contracts.AcornFoxOperationEvidenceUnknown
	}
	if observation.Outcome != contracts.AcornFoxProbeOutcomeResponded {
		return contracts.AcornFoxOperationEvidenceUnhealthy
	}
	if observation.HTTPStatus != nil && *observation.HTTPStatus >= 500 {
		return contracts.AcornFoxOperationEvidenceUnhealthy
	}
	return contracts.AcornFoxOperationEvidenceObserved
}
