package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

var (
	ErrOutOfOrderAgentEvent       = errors.New("agent event sequence is out of order")
	ErrTaskResultConflict         = errors.New("task result conflicts with the recorded result")
	ErrEnvironmentOperationActive = errors.New("environment already has an active operation")
)

type ControllerTask struct {
	Task         Task
	Operation    domain.Operation
	DeploymentID domain.ID
}

type EnqueueControllerTaskRequest struct {
	Operation            domain.Operation
	Deployment           *domain.Deployment
	ExistingDeploymentID domain.ID
	TaskID               domain.ID
	Payload              json.RawMessage
	MaxAttempts          int
	InitialPublishStatus domain.PublishStatus
}

type AgentEventRequest struct {
	TaskID               domain.ID
	Owner                string
	Now                  time.Time
	Sequence             uint64
	Kind                 string
	Payload              json.RawMessage
	WireVersion          string
	CompatibilityReport  json.RawMessage
	DisabledCapabilities []string
}

type AgentEventResult struct {
	Replayed bool
	Event    application.Event
}

type ControllerTaskOutcome string

const (
	ControllerTaskSucceeded  ControllerTaskOutcome = "succeeded"
	ControllerTaskFailed     ControllerTaskOutcome = "failed"
	ControllerTaskCancelled  ControllerTaskOutcome = "cancelled"
	ControllerTaskRolledBack ControllerTaskOutcome = "rolled_back"
)

type FinishControllerTaskRequest struct {
	TaskID  domain.ID
	Owner   string
	Now     time.Time
	Outcome ControllerTaskOutcome
	// DeferOperationTerminal is reserved for a control-plane owned
	// replacement handoff. A successful Agent task proves only that its
	// candidate is runtime-ready; RouteController must later decide serving
	// and atomically finish the parent operation with the route-set facts.
	DeferOperationTerminal bool
	FailureReason          string
	EvidenceIDs            []string
	EffectUnknown          bool
}

type FinishControllerTaskResult struct {
	Replayed   bool
	Operation  domain.Operation
	Deployment *domain.Deployment
	Event      application.Event
}

type FailControllerTaskRequest struct {
	TaskID        domain.ID
	Owner         string
	Now           time.Time
	Retryable     bool
	FailureReason string
	EvidenceIDs   []string
}

func (s *Store) GetControllerTask(ctx context.Context, taskID domain.ID) (ControllerTask, error) {
	if err := s.requireDB(); err != nil {
		return ControllerTask{}, err
	}
	if err := domain.RequireID(taskID, "task id"); err != nil {
		return ControllerTask{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return ControllerTask{}, err
	}
	row := tx.QueryRowContext(ctx, `SELECT task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at,last_agent_sequence FROM task_leases WHERE task_id=$1`, taskID.String())
	task, err := scanTask(row)
	if err != nil {
		_ = tx.Rollback()
		if errors.Is(err, sql.ErrNoRows) {
			return ControllerTask{}, ErrNotFound
		}
		return ControllerTask{}, err
	}
	operation, deploymentID, _, err := loadOperationTx(ctx, tx, task.OperationID, false)
	if err != nil {
		_ = tx.Rollback()
		return ControllerTask{}, err
	}
	if err := tx.Commit(); err != nil {
		return ControllerTask{}, err
	}
	return ControllerTask{Task: task, Operation: operation, DeploymentID: deploymentID}, nil
}

// ExpireExhaustedControllerTask closes one lease that has both expired and
// consumed its attempt budget. Without this sweep such a row is no longer
// claimable but remains leased forever, leaving its deployment non-terminal.
func (s *Store) ExpireExhaustedControllerTask(ctx context.Context, now time.Time, maxAttempts int) (bool, error) {
	if err := s.requireDB(); err != nil {
		return false, err
	}
	if now.IsZero() {
		now = s.now()
	}
	if maxAttempts <= 0 {
		maxAttempts = defaultTaskMaxAttempts
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	rollback := func(cause error) (bool, error) { return false, rollbackTx(tx, cause) }
	var taskID string
	err = tx.QueryRowContext(ctx, `SELECT task_id FROM task_leases WHERE state='leased' AND lease_until<=$1 AND attempt>=LEAST(max_attempts,$2) ORDER BY lease_until,task_id LIMIT 1 FOR UPDATE SKIP LOCKED`, now, maxAttempts).Scan(&taskID)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return false, nil
	}
	if err != nil {
		return rollback(err)
	}
	task, _, _, err := loadTaskForFinishTx(ctx, tx, domain.ID(taskID))
	if err != nil {
		return rollback(err)
	}
	operation, deploymentID, operationVersion, err := loadOperationTx(ctx, tx, task.OperationID, true)
	if err != nil {
		return rollback(err)
	}
	if err := operation.Transition(domain.OperationFailed, now); err != nil {
		return rollback(err)
	}
	reason := "Agent task lease expired after exhausting its retry budget"
	operation.FailureReason = reason
	if err := execExactlyOneTx(ctx, tx, `UPDATE operations SET state='failed',failure_reason=$1,version=version+1,updated_at=$2 WHERE id=$3 AND version=$4`, reason, now, operation.ID.String(), operationVersion); err != nil {
		return rollback(err)
	}
	resultPayload, _ := json.Marshal(map[string]any{"outcome": ControllerTaskFailed, "failure_reason": reason})
	if err := execExactlyOneTx(ctx, tx, `UPDATE task_leases SET state='failed',lease_owner=NULL,lease_until=NULL,last_error=$1,result_digest=$2,result=$3::jsonb,completed_at=$4,updated_at=$4 WHERE task_id=$5`, reason, digestBytes(resultPayload), resultPayload, now, task.ID.String()); err != nil {
		return rollback(err)
	}
	if !deploymentID.Empty() && operation.Type != domain.OperationObserve {
		deployment, version, err := loadDeploymentTx(ctx, tx, deploymentID, true)
		if err != nil {
			return rollback(err)
		}
		if err := transitionDeploymentForTaskOutcome(&deployment, domain.DeploymentFailed, now); err != nil {
			return rollback(err)
		}
		deployment.FailureReason = reason
		if err := execExactlyOneTx(ctx, tx, `UPDATE deployments SET state=$1,failure_reason=$2,version=version+1,updated_at=$3 WHERE id=$4 AND version=$5`, string(deployment.Status), reason, now, deployment.ID.String(), version); err != nil {
			return rollback(err)
		}
	}
	if _, err := s.appendControllerEventTx(ctx, tx, operation, "operation.retry_exhausted", string(domain.PublishFailed), "Agent retry budget exhausted", nil, now); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("%w: commit exhausted Agent task: %v", ErrOutcomeUnknown, err)
	}
	return true, nil
}

// MarkNodeDeploymentsUnknown projects missed Agent heartbeats into every
// non-terminal deployment whose active durable lease is owned by that node.
// Product success is never retained while the only executor is unreachable.
func (s *Store) MarkNodeDeploymentsUnknown(ctx context.Context, nodeID string, now time.Time) (int, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return 0, domain.ValidationError("node id is required")
	}
	if now.IsZero() {
		now = s.now()
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	rollback := func(cause error) (int, error) { return 0, rollbackTx(tx, cause) }
	rows, err := tx.QueryContext(ctx, `SELECT o.id,d.id FROM task_leases t JOIN operations o ON o.id=t.operation_id JOIN deployments d ON d.id=o.deployment_id WHERE t.lease_owner=$1 AND t.state='leased' AND o.state IN ('leased','running','waiting') AND d.state IN ('pending','preparing','deploying','runtime_ready','serving') FOR UPDATE OF o,d`, nodeID)
	if err != nil {
		return rollback(err)
	}
	type pair struct{ operationID, deploymentID domain.ID }
	var pairs []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.operationID, &p.deploymentID); err != nil {
			rows.Close()
			return rollback(err)
		}
		pairs = append(pairs, p)
	}
	if err := rows.Close(); err != nil {
		return rollback(err)
	}
	for _, p := range pairs {
		deployment, version, err := loadDeploymentTx(ctx, tx, p.deploymentID, true)
		if err != nil {
			return rollback(err)
		}
		if err := deployment.Transition(domain.DeploymentUnknown, now); err != nil {
			return rollback(err)
		}
		if err := execExactlyOneTx(ctx, tx, `UPDATE deployments SET state='unknown',runtime_healthy=false,version=version+1,updated_at=$1 WHERE id=$2 AND version=$3`, now, deployment.ID.String(), version); err != nil {
			return rollback(err)
		}
		operation, _, _, err := loadOperationTx(ctx, tx, p.operationID, false)
		if err != nil {
			return rollback(err)
		}
		if _, err := s.appendControllerEventTx(ctx, tx, operation, "deployment.unknown", string(domain.PublishDeploying), "Agent heartbeat expired; deployment health is unknown", []string{"node:" + nodeID}, now); err != nil {
			return rollback(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("%w: commit node unknown projection: %v", ErrOutcomeUnknown, err)
	}
	return len(pairs), nil
}

// EnqueueControllerTask persists the desired operation, optional deployment,
// durable task and first outbox event atomically. A Release is still created
// separately and remains immutable; this method only establishes execution
// state around it.
func (s *Store) EnqueueControllerTask(ctx context.Context, request EnqueueControllerTaskRequest) (application.Event, error) {
	if err := s.requireDB(); err != nil {
		return application.Event{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return application.Event{}, fmt.Errorf("begin enqueue controller task: %w", err)
	}
	event, err := s.enqueueControllerTaskTx(ctx, tx, request)
	if err != nil {
		return application.Event{}, rollbackTx(tx, err)
	}
	if err := tx.Commit(); err != nil {
		return application.Event{}, fmt.Errorf("%w: commit controller task enqueue: %v", ErrOutcomeUnknown, err)
	}
	return event, nil
}

// EnqueueControllerTaskAndCompletePublish commits the durable Agent task and
// its command response together. It closes the historical crash window where
// a task was already visible but its idempotency row remained in_progress.
func (s *Store) EnqueueControllerTaskAndCompletePublish(ctx context.Context, request EnqueueControllerTaskRequest, key, requestDigest string, response json.RawMessage, now time.Time) (application.Event, error) {
	if err := s.requireDB(); err != nil {
		return application.Event{}, err
	}
	key, requestDigest = strings.TrimSpace(key), strings.TrimSpace(requestDigest)
	if key == "" || !strings.HasPrefix(requestDigest, "sha256:") || len(response) == 0 || !json.Valid(response) {
		return application.Event{}, domain.ValidationError("publish completion is invalid")
	}
	if now.IsZero() {
		now = s.now()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return application.Event{}, fmt.Errorf("begin AcornFox delivery commit: %w", err)
	}
	event, err := s.enqueueControllerTaskTx(ctx, tx, request)
	if err != nil {
		return application.Event{}, rollbackTx(tx, err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE m1_publish_requests SET status='completed',response=$1::jsonb,failure_reason=NULL,updated_at=$2 WHERE idempotency_key=$3 AND request_digest=$4 AND status='in_progress'`, response, now.UTC(), key, requestDigest)
	if err != nil {
		return application.Event{}, rollbackTx(tx, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return application.Event{}, rollbackTx(tx, err)
	}
	if rows != 1 {
		return application.Event{}, rollbackTx(tx, ErrOutcomeUnknown)
	}
	if err := tx.Commit(); err != nil {
		return application.Event{}, fmt.Errorf("%w: commit AcornFox delivery task: %v", ErrOutcomeUnknown, err)
	}
	return event, nil
}

// enqueueControllerTaskTx is the common mutation used by ordinary controller
// queueing and AcornFox's accepted-command commit. Callers own the transaction
// so a task can never become visible without its idempotent command result.
func (s *Store) enqueueControllerTaskTx(ctx context.Context, tx *sql.Tx, request EnqueueControllerTaskRequest) (application.Event, error) {
	if err := request.Operation.Validate(); err != nil {
		return application.Event{}, err
	}
	if request.Operation.Status != domain.OperationPending {
		return application.Event{}, domain.ValidationError("new controller operation must be pending")
	}
	if err := domain.RequireID(request.TaskID, "task id"); err != nil {
		return application.Event{}, err
	}
	if len(request.Payload) == 0 || !json.Valid(request.Payload) {
		return application.Event{}, domain.ValidationError("task payload must be valid JSON")
	}
	redactedPayload, err := foundation.RedactJSON(request.Payload, nil)
	if err != nil {
		return application.Event{}, fmt.Errorf("redact task payload: %w", err)
	}
	maxAttempts := request.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = defaultTaskMaxAttempts
	}
	now := request.Operation.CreatedAt.UTC()
	if now.IsZero() {
		now = s.now().UTC()
	}

	if request.Operation.Type != domain.OperationObserve {
		if err := s.preemptReadOnlyControllerOperationTx(ctx, tx, request.Operation.EnvironmentID, now); err != nil {
			return application.Event{}, err
		}
	}
	var deploymentID any
	if request.Deployment != nil && !request.ExistingDeploymentID.Empty() {
		return application.Event{}, domain.ValidationError("new and existing deployment are mutually exclusive")
	}
	if request.Deployment != nil {
		if err := request.Deployment.Validate(); err != nil {
			return application.Event{}, err
		}
		if request.Deployment.Status != domain.DeploymentPending {
			return application.Event{}, domain.ValidationError("new deployment must be pending")
		}
		if request.Deployment.ApplicationID != request.Operation.ApplicationID || request.Deployment.EnvironmentID != request.Operation.EnvironmentID {
			return application.Event{}, domain.ValidationError("deployment and operation scope do not match")
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO deployments
				(id, environment_id, release_id, state, version, created_at, updated_at)
			VALUES ($1, $2, $3, $4, 1, $5, $5)
		`, request.Deployment.ID.String(), request.Deployment.EnvironmentID.String(), request.Deployment.ReleaseID.String(), string(request.Deployment.Status), now); err != nil {
			return application.Event{}, fmt.Errorf("insert controller deployment: %w", err)
		}
		deploymentID = request.Deployment.ID.String()
	} else if !request.ExistingDeploymentID.Empty() {
		var applicationID, environmentID string
		if err := tx.QueryRowContext(ctx, `SELECT e.application_id,d.environment_id FROM deployments d JOIN environments e ON e.id=d.environment_id WHERE d.id=$1`, request.ExistingDeploymentID.String()).Scan(&applicationID, &environmentID); err != nil {
			return application.Event{}, fmt.Errorf("load existing deployment: %w", err)
		}
		if applicationID != request.Operation.ApplicationID.String() || environmentID != request.Operation.EnvironmentID.String() {
			return application.Event{}, domain.ValidationError("existing deployment and operation scope do not match")
		}
		deploymentID = request.ExistingDeploymentID.String()
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO operations
			(id, application_id, environment_id, deployment_id, operation_type,
			 idempotency_key, state, version, target_ref, failure_reason,
			 created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8, NULL, $9, $9)
	`, request.Operation.ID.String(), request.Operation.ApplicationID.String(), request.Operation.EnvironmentID.String(), deploymentID,
		string(request.Operation.Type), request.Operation.IdempotencyKey, string(request.Operation.Status), request.Operation.TargetRef, now); err != nil {
		return application.Event{}, mapControllerOperationInsertError(err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO task_leases
			(task_id, operation_id, attempt, max_attempts, state, payload,
			 created_at, updated_at)
		VALUES ($1, $2, 0, $3, 'ready', $4::jsonb, $5, $5)
	`, request.TaskID.String(), request.Operation.ID.String(), maxAttempts, redactedPayload, now); err != nil {
		return application.Event{}, fmt.Errorf("insert controller task: %w", err)
	}
	initialStatus := request.InitialPublishStatus
	if initialStatus == "" {
		initialStatus = domain.PublishPreparing
	}
	event, err := s.appendControllerEventTx(ctx, tx, request.Operation, "operation.queued", string(initialStatus), "operation queued", nil, now)
	if err != nil {
		return application.Event{}, err
	}
	return event, nil
}

// preemptReadOnlyControllerOperationTx gives a foreground mutation priority
// over the M4 observation/log collectors. Both collectors use OperationObserve
// and have no runtime side effect, so cancelling their task and operation in
// the same transaction is safe. Any other active operation remains a strict
// serialization conflict.
func (s *Store) preemptReadOnlyControllerOperationTx(ctx context.Context, tx *sql.Tx, environmentID domain.ID, now time.Time) error {
	var activeID domain.ID
	err := tx.QueryRowContext(ctx, `SELECT id FROM operations WHERE environment_id=$1 AND state IN ('pending','leased','running','waiting','cancelling') ORDER BY created_at,id LIMIT 1 FOR UPDATE`, environmentID.String()).Scan(&activeID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	operation, _, version, err := loadOperationTx(ctx, tx, activeID, false)
	if err != nil {
		return err
	}
	if operation.Type != domain.OperationObserve {
		return domain.WrapError(domain.ErrConflict, "environment already has an active operation", ErrEnvironmentOperationActive)
	}
	reason := "background observation superseded by foreground operation"
	result, err := tx.ExecContext(ctx, `UPDATE task_leases SET state='cancelled',lease_owner=NULL,lease_until=NULL,last_error=$1,completed_at=$2,updated_at=$2 WHERE operation_id=$3 AND state IN ('ready','leased')`, reason, now, activeID.String())
	if err != nil {
		return err
	}
	if err := requireOneTaskMutation(result); err != nil {
		return domain.NewError(domain.ErrConflict, "background observation task is no longer preemptible")
	}
	if err := operation.Transition(domain.OperationCancelled, now); err != nil {
		return err
	}
	operation.FailureReason = reason
	if err := execExactlyOneTx(ctx, tx, `UPDATE operations SET state='cancelled',failure_reason=$1,version=version+1,updated_at=$2 WHERE id=$3 AND version=$4`, reason, now, activeID.String(), version); err != nil {
		return err
	}
	_, err = s.appendControllerEventTx(ctx, tx, operation, "operation.cancelled", string(domain.PublishPreparing), reason, nil, now)
	return err
}

func mapControllerOperationInsertError(err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.ConstraintName {
		case "operations_one_active_per_environment":
			return domain.WrapError(domain.ErrConflict, "environment already has an active operation", errors.Join(ErrEnvironmentOperationActive, err))
		case "operations_environment_id_idempotency_key_key", "operations_pkey":
			return domain.WrapError(domain.ErrConflict, "controller operation identity already exists", err)
		}
	}
	return fmt.Errorf("insert controller operation: %w", err)
}

// ClaimControllerTask is the high-level lease boundary used by controller
// workers. It advances Operation and appends an event in the same transaction
// as the lease acquisition. An expired lease may be taken over without moving
// an already-running Operation backwards.
func (s *Store) ClaimControllerTask(ctx context.Context, request ClaimTaskRequest) (ControllerTask, bool, error) {
	if err := s.requireDB(); err != nil {
		return ControllerTask{}, false, err
	}
	request.Owner = strings.TrimSpace(request.Owner)
	if request.Owner == "" || request.Duration <= 0 || request.MaxAttempts <= 0 {
		return ControllerTask{}, false, errors.New("controller claim requires owner, duration and max attempts")
	}
	if request.Now.IsZero() {
		request.Now = s.now()
	}
	request.Now = request.Now.UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ControllerTask{}, false, fmt.Errorf("begin controller claim: %w", err)
	}
	rollback := func(cause error) (ControllerTask, bool, error) {
		return ControllerTask{}, false, rollbackTx(tx, cause)
	}
	task, previousOwner, previousState, found, err := selectClaimableTaskTx(ctx, tx, request)
	if err != nil {
		return rollback(err)
	}
	if !found {
		if err := tx.Commit(); err != nil {
			return ControllerTask{}, false, fmt.Errorf("%w: commit empty controller claim: %v", ErrOutcomeUnknown, err)
		}
		return ControllerTask{}, false, nil
	}
	operation, deploymentID, operationVersion, err := loadOperationTx(ctx, tx, task.OperationID, true)
	if err != nil {
		return rollback(err)
	}
	newStatus := operation.Status
	if operation.Status == domain.OperationPending || operation.Status == domain.OperationWaiting {
		if err := operation.Transition(domain.OperationLeased, request.Now); err != nil {
			return rollback(err)
		}
		newStatus = operation.Status
	} else if operation.Status != domain.OperationLeased && operation.Status != domain.OperationRunning {
		return rollback(fmt.Errorf("operation %s is not claimable from %s", operation.ID, operation.Status))
	}
	leaseUntil := request.Now.Add(request.Duration)
	if err := execExactlyOneTx(ctx, tx, `
		UPDATE task_leases
		   SET lease_owner=$1, lease_until=$2, attempt=attempt+1,
		       max_attempts=LEAST(max_attempts,$3), state='leased', updated_at=$4
		 WHERE task_id=$5
	`, request.Owner, leaseUntil, request.MaxAttempts, request.Now, task.ID.String()); err != nil {
		return rollback(fmt.Errorf("claim controller task %s: %w", task.ID, err))
	}
	if err := execExactlyOneTx(ctx, tx, `
		UPDATE operations SET state=$1, version=version+1, updated_at=$2 WHERE id=$3 AND version=$4
	`, string(newStatus), request.Now, operation.ID.String(), operationVersion); err != nil {
		return rollback(fmt.Errorf("advance claimed operation %s: %w", operation.ID, err))
	}
	operation.Status = newStatus
	operation.UpdatedAt = request.Now
	message := "operation leased"
	eventType := "operation.leased"
	if previousState == TaskLeased {
		message = "expired task lease taken over"
		eventType = "operation.lease_taken_over"
	}
	evidence := []string{}
	if previousOwner != "" {
		evidence = append(evidence, "previous-owner:"+previousOwner)
	}
	publishStatus := domain.PublishPreparing
	if operation.Type == domain.OperationDeploy || operation.Type == domain.OperationRedeploy || operation.Type == domain.OperationRollback || operation.Type == domain.OperationRestart {
		publishStatus = domain.PublishDeploying
	}
	event, err := s.appendControllerEventTx(ctx, tx, operation, eventType, string(publishStatus), message, evidence, request.Now)
	if err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return ControllerTask{}, false, fmt.Errorf("%w: commit controller claim: %v", ErrOutcomeUnknown, err)
	}
	task.LeaseOwner = request.Owner
	task.LeaseUntil = &leaseUntil
	task.Attempt++
	task.State = TaskLeased
	task.UpdatedAt = request.Now
	_ = event
	return ControllerTask{Task: task, Operation: operation, DeploymentID: deploymentID}, true, nil
}

// RenewOwnedControllerTaskLeases keeps acknowledged long-running Agent effects
// claimable by the same connected node. A node heartbeat alone must not renew
// a task that has never produced an Agent event: the in-memory gateway message
// may have been lost during a reconnect, and that lease must expire so the
// durable dispatcher can re-enqueue it.
func (s *Store) RenewOwnedControllerTaskLeases(ctx context.Context, owner string, now time.Time, duration time.Duration) (int64, error) {
	owner = strings.TrimSpace(owner)
	if owner == "" || duration <= 0 {
		return 0, domain.ValidationError("controller lease renewal requires owner and duration")
	}
	if now.IsZero() {
		now = s.now()
	}
	now = now.UTC()
	result, err := s.db.ExecContext(ctx, `
		UPDATE task_leases
		   SET lease_until=$1,updated_at=$2
		 WHERE state='leased' AND lease_owner=$3 AND lease_until>$2
		   AND last_agent_sequence>0
	`, now.Add(duration), now, owner)
	if err != nil {
		return 0, fmt.Errorf("renew connected Agent task leases: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read connected Agent lease renewal count: %w", err)
	}
	return count, nil
}

// StartControllerTask records the transition from an accepted lease to active
// execution. It is idempotent for the same current owner.
func (s *Store) StartControllerTask(ctx context.Context, taskID domain.ID, owner string, now time.Time) (application.Event, error) {
	if now.IsZero() {
		now = s.now()
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return application.Event{}, err
	}
	rollback := func(cause error) (application.Event, error) { return application.Event{}, rollbackTx(tx, cause) }
	task, err := loadOwnedTaskTx(ctx, tx, taskID, owner, now)
	if err != nil {
		return rollback(err)
	}
	_, probeTask, err := decodeAcornFoxProbeTaskPayload(task.Payload)
	if err != nil {
		return rollback(err)
	}
	operation, deploymentID, version, err := loadOperationTx(ctx, tx, task.OperationID, true)
	if err != nil {
		return rollback(err)
	}
	alreadyRunning := operation.Status == domain.OperationRunning
	if !alreadyRunning {
		if err := operation.Transition(domain.OperationRunning, now); err != nil {
			return rollback(err)
		}
		if err := execExactlyOneTx(ctx, tx, `UPDATE operations SET state='running', version=version+1, updated_at=$1 WHERE id=$2 AND version=$3`, now, operation.ID.String(), version); err != nil {
			return rollback(err)
		}
	}
	if !probeTask && !deploymentID.Empty() {
		deployment, deploymentVersion, err := loadDeploymentTx(ctx, tx, deploymentID, true)
		if err != nil {
			return rollback(err)
		}
		if operation.Type == domain.OperationRollback && deployment.Status == domain.DeploymentFailed {
			if err := deployment.Transition(domain.DeploymentRollingBack, now); err != nil {
				return rollback(err)
			}
		} else if deployment.Status == domain.DeploymentPending {
			if err := deployment.Transition(domain.DeploymentPreparing, now); err != nil {
				return rollback(err)
			}
			if err := deployment.Transition(domain.DeploymentDeploying, now); err != nil {
				return rollback(err)
			}
		} else if deployment.Status == domain.DeploymentUnknown && operation.Type == domain.OperationDeploy {
			if err := deployment.Transition(domain.DeploymentDeploying, now); err != nil {
				return rollback(err)
			}
		}
		if err := execExactlyOneTx(ctx, tx, `UPDATE deployments SET state=$1, version=version+1, updated_at=$2 WHERE id=$3 AND version=$4`, string(deployment.Status), now, deployment.ID.String(), deploymentVersion); err != nil {
			return rollback(err)
		}
	}
	event := application.Event{}
	if !alreadyRunning {
		event, err = s.appendControllerEventTx(ctx, tx, operation, "operation.started", string(domain.PublishDeploying), "operation started", nil, now)
		if err != nil {
			return rollback(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return application.Event{}, fmt.Errorf("%w: commit controller start: %v", ErrOutcomeUnknown, err)
	}
	return event, nil
}

// RecordAgentEvent enforces a gap-free per-task sequence. Replaying the exact
// same sequence and digest is harmless; a different or skipped event fails
// closed and cannot move product state backwards.
func (s *Store) RecordAgentEvent(ctx context.Context, request AgentEventRequest) (AgentEventResult, error) {
	if request.Sequence == 0 || strings.TrimSpace(request.Kind) == "" {
		return AgentEventResult{}, domain.ValidationError("agent event sequence and kind are required")
	}
	if request.Now.IsZero() {
		request.Now = s.now()
	}
	request.Now = request.Now.UTC()
	if len(request.Payload) == 0 || !json.Valid(request.Payload) {
		return AgentEventResult{}, domain.ValidationError("agent event payload must be valid JSON")
	}
	payload, err := foundation.RedactJSON(request.Payload, nil)
	if err != nil {
		return AgentEventResult{}, err
	}
	digest := digestAgentEvent(request.Kind, payload)
	if request.WireVersion == "" {
		request.WireVersion = "1.0"
	}
	if len(request.CompatibilityReport) == 0 {
		request.CompatibilityReport = json.RawMessage(`{}`)
	}
	if !json.Valid(request.CompatibilityReport) {
		return AgentEventResult{}, domain.ValidationError("compatibility report must be valid JSON")
	}
	disabledCapabilities, err := json.Marshal(request.DisabledCapabilities)
	if err != nil {
		return AgentEventResult{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AgentEventResult{}, err
	}
	rollback := func(cause error) (AgentEventResult, error) { return AgentEventResult{}, rollbackTx(tx, cause) }
	task, err := loadOwnedTaskTx(ctx, tx, request.TaskID, request.Owner, request.Now)
	if err != nil {
		return rollback(err)
	}
	probeRequest, probeTask, err := decodeAcornFoxProbeTaskPayload(task.Payload)
	if err != nil {
		return rollback(err)
	}
	var operation domain.Operation
	var deploymentID domain.ID
	operationLoaded := false
	var probeObservation *AcornFoxProbeObservation
	if probeTask && request.Kind == string(v1.KindObservation) {
		operation, deploymentID, _, err = loadOperationTx(ctx, tx, task.OperationID, false)
		if err != nil {
			return rollback(err)
		}
		operationLoaded = true
		result, err := validateAcornFoxProbeAgentObservation(payload, request.TaskID, request.Sequence, deploymentID, probeRequest)
		if err != nil {
			return rollback(err)
		}
		fact := acornFoxProbeObservationForAgentEvent(request.TaskID, request.Sequence, result, request.Now)
		probeObservation = &fact
	}
	var lastSequence uint64
	if err := tx.QueryRowContext(ctx, `SELECT last_agent_sequence FROM task_leases WHERE task_id=$1 FOR UPDATE`, request.TaskID.String()).Scan(&lastSequence); err != nil {
		return rollback(err)
	}
	if request.Sequence <= lastSequence {
		var storedDigest string
		err := tx.QueryRowContext(ctx, `SELECT event_digest FROM task_agent_events WHERE task_id=$1 AND sequence=$2`, request.TaskID.String(), request.Sequence).Scan(&storedDigest)
		if err == nil && storedDigest == digest {
			if probeObservation != nil {
				if err := verifyAcornFoxProbeObservationReplayTx(ctx, tx, *probeObservation); err != nil {
					return rollback(err)
				}
			}
			if err := tx.Commit(); err != nil {
				return AgentEventResult{}, fmt.Errorf("%w: commit agent replay: %v", ErrOutcomeUnknown, err)
			}
			return AgentEventResult{Replayed: true}, nil
		}
		return rollback(ErrOutOfOrderAgentEvent)
	}
	if request.Sequence != lastSequence+1 {
		return rollback(ErrOutOfOrderAgentEvent)
	}
	if !operationLoaded {
		operation, deploymentID, _, err = loadOperationTx(ctx, tx, task.OperationID, false)
		if err != nil {
			return rollback(err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO task_agent_events(task_id,sequence,event_type,payload,event_digest,created_at,wire_version,compatibility_report)
		VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8::jsonb)
	`, request.TaskID.String(), request.Sequence, request.Kind, payload, digest, request.Now, request.WireVersion, request.CompatibilityReport); err != nil {
		return rollback(fmt.Errorf("append agent event: %w", err))
	}
	if err := execExactlyOneTx(ctx, tx, `UPDATE task_leases SET last_agent_sequence=$1, wire_version=$2, negotiated_capabilities=$3::jsonb, updated_at=$4 WHERE task_id=$5`, request.Sequence, request.WireVersion, disabledCapabilities, request.Now, request.TaskID.String()); err != nil {
		return rollback(err)
	}
	if probeObservation != nil {
		if _, _, err := appendAcornFoxProbeObservationTx(ctx, tx, *probeObservation); err != nil {
			return rollback(err)
		}
	}
	if request.Kind == "observation" && !probeTask && !deploymentID.Empty() {
		var wire struct {
			Healthy bool            `json:"healthy"`
			At      time.Time       `json:"at"`
			Details json.RawMessage `json:"details"`
		}
		groupSpec, groupTask, err := loadM2GroupTaskSpecForAgentEventTx(ctx, tx, task.Payload, deploymentID)
		if err != nil {
			return rollback(err)
		}
		var runtime struct {
			DeploymentID domain.ID `json:"deployment_id"`
			HostPort     int       `json:"host_port"`
		}
		validRuntime := false
		groupProjection := ""
		if json.Unmarshal(payload, &wire) == nil && wire.Healthy {
			if groupTask {
				var group contracts.ServiceGroupRuntimeObservation
				if json.Unmarshal(wire.Details, &group) == nil && group.DeploymentID == deploymentID && group.ValidateFor(groupSpec) == nil && group.Effect == contracts.RuntimeEffectKnown && (group.Status == "runtime_ready" || group.Status == "degraded") {
					for _, service := range group.Services {
						if service.ServiceName == groupSpec.EntryService && service.Healthy && service.HostPort > 0 && service.HostPort <= 65535 {
							runtime.DeploymentID, runtime.HostPort, validRuntime = group.DeploymentID, service.HostPort, true
							groupProjection = group.Status
							break
						}
					}
				}
			} else if json.Unmarshal(wire.Details, &runtime) == nil && runtime.DeploymentID == deploymentID && runtime.HostPort > 0 && runtime.HostPort <= 65535 {
				validRuntime = true
			}
		}
		if validRuntime {
			observedAt := wire.At.UTC()
			if observedAt.IsZero() {
				observedAt = request.Now
			}
			if groupProjection != "" {
				if err := execExactlyOneTx(ctx, tx, `UPDATE deployments SET state=CASE WHEN EXISTS(SELECT 1 FROM m3_route_pointers pointer WHERE pointer.deployment_id=$4) THEN 'serving' WHEN state IN ('deploying','unknown') THEN $1 WHEN state='runtime_ready' AND $1='degraded' THEN 'degraded' WHEN state='degraded' AND $1='runtime_ready' THEN 'runtime_ready' ELSE state END,host_ip='127.0.0.1',host_port=$2,last_observed_at=$3,runtime_healthy=true,version=version+1,updated_at=$3 WHERE id=$4 AND state IN ('deploying','unknown','runtime_ready','degraded','serving')`, groupProjection, runtime.HostPort, observedAt, deploymentID.String()); err != nil {
					return rollback(fmt.Errorf("persist aggregate runtime summary: %w", err))
				}
			} else if err := execExactlyOneTx(ctx, tx, `UPDATE deployments SET host_ip='127.0.0.1',host_port=$1,last_observed_at=$2,runtime_healthy=true,updated_at=$2 WHERE id=$3`, runtime.HostPort, observedAt, deploymentID.String()); err != nil {
				return rollback(fmt.Errorf("persist runtime endpoint observation: %w", err))
			}
		}
	}
	event, err := s.appendControllerEventTx(ctx, tx, operation, "agent."+request.Kind, string(domain.PublishDeploying), "agent event accepted", []string{fmt.Sprintf("agent-sequence:%d", request.Sequence)}, request.Now)
	if err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return AgentEventResult{}, fmt.Errorf("%w: commit agent event: %v", ErrOutcomeUnknown, err)
	}
	return AgentEventResult{Event: event}, nil
}

// decodeAcornFoxProbeTaskPayload recognizes only the complete marker shape.
// A top-level probe marker is a security boundary: malformed typed payloads
// must not fall through to historical runtime-health projection.
func decodeAcornFoxProbeTaskPayload(payload json.RawMessage) (contracts.AcornFoxProbeRequest, bool, error) {
	var task struct {
		Kind       v1.TaskKind     `json:"kind"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if err := decodeControllerTaskJSON(payload, &task); err != nil {
		return contracts.AcornFoxProbeRequest{}, false, nil
	}
	var marker map[string]json.RawMessage
	if json.Unmarshal(task.Parameters, &marker) != nil {
		return contracts.AcornFoxProbeRequest{}, false, nil
	}
	if _, present := marker["acornfox_probe_payload_type"]; !present {
		return contracts.AcornFoxProbeRequest{}, false, nil
	}
	if task.Kind != v1.TaskObserve {
		return contracts.AcornFoxProbeRequest{}, true, domain.ValidationError("AcornFox probe task kind is invalid")
	}
	var wrapped struct {
		PayloadType string                         `json:"acornfox_probe_payload_type"`
		Request     contracts.AcornFoxProbeRequest `json:"request"`
	}
	if err := decodeControllerTaskJSON(task.Parameters, &wrapped); err != nil || wrapped.PayloadType != "probe" || wrapped.Request.Validate() != nil {
		return contracts.AcornFoxProbeRequest{}, true, domain.ValidationError("AcornFox probe task payload is invalid")
	}
	return wrapped.Request, true, nil
}

func validateAcornFoxProbeAgentObservation(payload json.RawMessage, taskID domain.ID, agentSequence uint64, deploymentID domain.ID, request contracts.AcornFoxProbeRequest) (contracts.AcornFoxProbeResult, error) {
	if deploymentID.Empty() {
		return contracts.AcornFoxProbeResult{}, domain.ValidationError("AcornFox probe task has no deployment")
	}
	expectedDeployment, err := contracts.AcornFoxRuntimeDeploymentID(request.Reference.Fact)
	if err != nil || expectedDeployment != deploymentID {
		return contracts.AcornFoxProbeResult{}, domain.ValidationError("AcornFox probe task deployment does not match immutable reference")
	}
	var wire v1.Observation
	if err := decodeControllerTaskJSON(payload, &wire); err != nil || wire.Validate() != nil {
		return contracts.AcornFoxProbeResult{}, domain.ValidationError("AcornFox probe observation is invalid")
	}
	if wire.TaskID != taskID.String() || wire.Sequence != 1 || agentSequence == 0 || wire.Healthy || wire.Status != "unknown" || wire.TargetRef != "deployment/"+deploymentID.String()+"/probe/"+request.Reference.Fact.ServiceName {
		return contracts.AcornFoxProbeResult{}, domain.ValidationError("AcornFox probe observation identity is invalid")
	}
	var result contracts.AcornFoxProbeResult
	if err := decodeControllerTaskJSON(wire.Details, &result); err != nil || result.Validate() != nil {
		return contracts.AcornFoxProbeResult{}, domain.ValidationError("AcornFox probe observation details are invalid")
	}
	if result.ApplicationID != request.Reference.Fact.ApplicationID || result.EnvironmentID != request.Reference.Fact.EnvironmentID || result.ReleaseID != request.Reference.Fact.ReleaseID || result.DeploymentID != deploymentID || result.ServiceName != request.Reference.Fact.ServiceName || result.Protocol != request.Protocol || result.TargetClass != contracts.AcornFoxProbeTargetClassLoopback {
		return contracts.AcornFoxProbeResult{}, domain.ValidationError("AcornFox probe observation details do not match durable task")
	}
	if wire.At.UTC() != result.ObservedAt.UTC() || len(wire.EvidenceRefs) != 1 || wire.EvidenceRefs[0] != "acornfox-probe:"+result.FactDigest {
		return contracts.AcornFoxProbeResult{}, domain.ValidationError("AcornFox probe observation evidence does not match durable result")
	}
	return result, nil
}

func acornFoxProbeObservationForAgentEvent(taskID domain.ID, sequence uint64, result contracts.AcornFoxProbeResult, createdAt time.Time) AcornFoxProbeObservation {
	sampleID := "acornfox-probe:" + taskID.String() + ":" + fmt.Sprint(sequence)
	return AcornFoxProbeObservation{
		ID:            "probe_" + strings.TrimPrefix(digestBytes([]byte(sampleID)), "sha256:")[:32],
		SampleID:      sampleID,
		TaskID:        taskID.String(),
		AgentSequence: sequence,
		ApplicationID: result.ApplicationID.String(),
		EnvironmentID: result.EnvironmentID.String(),
		ReleaseID:     result.ReleaseID.String(),
		DeploymentID:  result.DeploymentID.String(),
		ServiceName:   result.ServiceName,
		Protocol:      result.Protocol,
		TargetClass:   contracts.AcornFoxProbeTargetClassLoopback,
		Outcome:       result.Outcome,
		HTTPStatus:    result.HTTPStatus,
		LatencyMS:     result.LatencyMS,
		ErrorCode:     result.ErrorCode,
		ObservedAt:    result.ObservedAt.UTC(),
		CreatedAt:     createdAt.UTC(),
		FactDigest:    result.FactDigest,
	}
}

func decodeControllerTaskJSON(data []byte, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("multiple JSON values")
	}
	return nil
}

func decodeM2GroupTaskSpec(payload json.RawMessage) (contracts.ServiceGroupRuntimeSpec, bool) {
	var taskSpec struct {
		Kind       string          `json:"kind"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if json.Unmarshal(payload, &taskSpec) != nil {
		return contracts.ServiceGroupRuntimeSpec{}, false
	}
	if taskSpec.Kind == "deploy" || taskSpec.Kind == "rollback" {
		// M4 recovery reuses the durable Agent task table, but its aggregate
		// payload is wrapped so an old Agent cannot confuse it with a
		// single-container effect.  Extract only the immutable runtime spec
		// needed to validate the ensuing Agent observation; execution still
		// requires the M4 marker/capability at the gateway and Agent boundary.
		var wrapper struct {
			PayloadType string          `json:"m4_payload_type"`
			Request     json.RawMessage `json:"request"`
		}
		if json.Unmarshal(taskSpec.Parameters, &wrapper) != nil {
			return contracts.ServiceGroupRuntimeSpec{}, false
		}
		switch wrapper.PayloadType {
		case "service_group.redeploy":
			var request contracts.DeployGroupRequest
			if json.Unmarshal(wrapper.Request, &request) != nil || !request.ForceRecreate || request.DeploymentID.Empty() || request.Spec.Validate() != nil {
				return contracts.ServiceGroupRuntimeSpec{}, true
			}
			return request.Spec, true
		case "service_group.rollback":
			var request contracts.RollbackGroupRequest
			if json.Unmarshal(wrapper.Request, &request) != nil || request.DeploymentID.Empty() || request.TargetDeploymentID.Empty() || request.TargetDeploymentID == request.DeploymentID || request.Target.Validate() != nil {
				return contracts.ServiceGroupRuntimeSpec{}, true
			}
			return request.Target, true
		default:
			return contracts.ServiceGroupRuntimeSpec{}, false
		}
	}
	if taskSpec.Kind != "deploy_group" {
		return contracts.ServiceGroupRuntimeSpec{}, false
	}
	var request contracts.DeployGroupRequest
	if json.Unmarshal(taskSpec.Parameters, &request) != nil || request.Spec.Validate() != nil {
		return contracts.ServiceGroupRuntimeSpec{}, true
	}
	return request.Spec, true
}

func loadM2GroupTaskSpecForAgentEventTx(ctx context.Context, tx *sql.Tx, payload json.RawMessage, deploymentID domain.ID) (contracts.ServiceGroupRuntimeSpec, bool, error) {
	if spec, groupTask := decodeM2GroupTaskSpec(payload); groupTask {
		return spec, true, nil
	}
	var taskSpec struct {
		Kind       string          `json:"kind"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if json.Unmarshal(payload, &taskSpec) != nil || taskSpec.Kind != string(v1.TaskObserve) {
		return contracts.ServiceGroupRuntimeSpec{}, false, nil
	}
	var wrapper struct {
		PayloadType string          `json:"m4_payload_type"`
		Request     json.RawMessage `json:"request"`
	}
	if json.Unmarshal(taskSpec.Parameters, &wrapper) != nil || wrapper.PayloadType != "service_group.observe" {
		return contracts.ServiceGroupRuntimeSpec{}, false, nil
	}
	var request contracts.ObserveGroupRequest
	if json.Unmarshal(wrapper.Request, &request) != nil || request.DeploymentID.Empty() || request.Operation.Validate() != nil {
		return contracts.ServiceGroupRuntimeSpec{}, true, domain.ValidationError("service-group observation task is invalid")
	}
	if request.DeploymentID != deploymentID {
		return contracts.ServiceGroupRuntimeSpec{}, true, domain.ValidationError("service-group observation deployment does not match durable task")
	}
	var encoded []byte
	if err := tx.QueryRowContext(ctx, `SELECT runtime.spec FROM deployments deployment JOIN m2_release_runtime_specs runtime ON runtime.release_id=deployment.release_id WHERE deployment.id=$1`, deploymentID.String()).Scan(&encoded); err != nil {
		return contracts.ServiceGroupRuntimeSpec{}, true, err
	}
	var spec contracts.ServiceGroupRuntimeSpec
	if json.Unmarshal(encoded, &spec) != nil || spec.Validate() != nil || spec.ReleaseID.Empty() {
		return contracts.ServiceGroupRuntimeSpec{}, true, domain.ValidationError("persisted service-group runtime specification is invalid")
	}
	return spec, true, nil
}

func (s *Store) FinishControllerTask(ctx context.Context, request FinishControllerTaskRequest) (FinishControllerTaskResult, error) {
	if request.Now.IsZero() {
		request.Now = s.now()
	}
	request.Now = request.Now.UTC()
	request.FailureReason = foundation.RedactText(strings.TrimSpace(request.FailureReason))
	resultPayload, err := json.Marshal(map[string]any{"outcome": request.Outcome, "failure_reason": request.FailureReason, "evidence_ids": request.EvidenceIDs, "effect_unknown": request.EffectUnknown})
	if err != nil {
		return FinishControllerTaskResult{}, err
	}
	resultDigest := digestBytes(resultPayload)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return FinishControllerTaskResult{}, err
	}
	rollback := func(cause error) (FinishControllerTaskResult, error) {
		return FinishControllerTaskResult{}, rollbackTx(tx, cause)
	}
	task, storedDigest, storedResult, err := loadTaskForFinishTx(ctx, tx, request.TaskID)
	if err != nil {
		return rollback(err)
	}
	if task.State == TaskCompleted || task.State == TaskFailed || task.State == TaskCancelled {
		if storedDigest == resultDigest && len(storedResult) > 0 {
			if err := tx.Commit(); err != nil {
				return FinishControllerTaskResult{}, err
			}
			return FinishControllerTaskResult{Replayed: true}, nil
		}
		return rollback(ErrTaskResultConflict)
	}
	if task.State != TaskLeased || task.LeaseOwner != strings.TrimSpace(request.Owner) || task.LeaseUntil == nil || !task.LeaseUntil.After(request.Now) {
		return rollback(ErrLeaseLost)
	}
	_, probeTask, err := decodeAcornFoxProbeTaskPayload(task.Payload)
	if err != nil {
		return rollback(err)
	}
	operation, deploymentID, operationVersion, err := loadOperationTx(ctx, tx, task.OperationID, true)
	if err != nil {
		return rollback(err)
	}
	var taskState TaskState
	var eventType, message string
	operationTerminal := true
	candidateCleanup := m4CandidateCleanupTaskPayload(task.Payload, deploymentID)
	switch request.Outcome {
	case ControllerTaskSucceeded:
		if request.DeferOperationTerminal {
			operationTerminal = false
			if candidateCleanup {
				taskState, eventType, message = TaskCompleted, "operation.candidate_cleaned", "failed rollout candidate removed; volumes retained"
			} else {
				taskState, eventType, message = TaskCompleted, "operation.candidate_ready", "replacement candidate is runtime-ready; route handoff remains pending"
			}
		} else {
			if err := operation.Transition(domain.OperationSucceeded, request.Now); err != nil {
				return rollback(err)
			}
			taskState, eventType, message = TaskCompleted, "operation.succeeded", "operation succeeded"
		}
	case ControllerTaskFailed:
		if err := operation.Transition(domain.OperationFailed, request.Now); err != nil {
			return rollback(err)
		}
		operation.FailureReason = request.FailureReason
		taskState, eventType, message = TaskFailed, "operation.failed", "operation failed"
	case ControllerTaskCancelled:
		if operation.Status == domain.OperationRunning {
			if err := operation.Transition(domain.OperationCancelling, request.Now); err != nil {
				return rollback(err)
			}
		}
		if err := operation.Transition(domain.OperationCancelled, request.Now); err != nil {
			return rollback(err)
		}
		taskState, eventType, message = TaskCancelled, "operation.cancelled", "operation cancelled"
	case ControllerTaskRolledBack:
		if operation.Type != domain.OperationRollback {
			return rollback(domain.ValidationError("rolled_back outcome requires rollback operation"))
		}
		if request.DeferOperationTerminal {
			operationTerminal = false
			taskState, eventType, message = TaskCompleted, "operation.candidate_ready", "rollback candidate is runtime-ready; route handoff remains pending"
		} else {
			if operation.Status != domain.OperationRollingBack {
				if err := operation.Transition(domain.OperationRollingBack, request.Now); err != nil {
					return rollback(err)
				}
			}
			if err := operation.Transition(domain.OperationRolledBack, request.Now); err != nil {
				return rollback(err)
			}
			taskState, eventType, message = TaskCompleted, "operation.rolled_back", "operation rolled back"
		}
	default:
		return rollback(domain.ValidationError("controller task outcome is unsupported"))
	}
	if operationTerminal {
		if err := execExactlyOneTx(ctx, tx, `
			UPDATE operations SET state=$1, failure_reason=$2, version=version+1, updated_at=$3
			 WHERE id=$4 AND version=$5
		`, string(operation.Status), nullableString(operation.FailureReason), request.Now, operation.ID.String(), operationVersion); err != nil {
			return rollback(err)
		}
	}
	var deployment *domain.Deployment
	if !probeTask && !deploymentID.Empty() {
		value, version, err := loadDeploymentTx(ctx, tx, deploymentID, true)
		if err != nil {
			return rollback(err)
		}
		switch request.Outcome {
		case ControllerTaskSucceeded:
			if operation.Type == domain.OperationDestroy || candidateCleanup {
				if err := value.Transition(domain.DeploymentStopped, request.Now); err != nil {
					return rollback(err)
				}
			} else if value.Status == domain.DeploymentDeploying {
				if err := value.Transition(domain.DeploymentRuntimeReady, request.Now); err != nil {
					return rollback(err)
				}
				var healthy bool
				var port sql.NullInt64
				if err := tx.QueryRowContext(ctx, `SELECT runtime_healthy,host_port FROM deployments WHERE id=$1`, value.ID.String()).Scan(&healthy, &port); err != nil {
					return rollback(err)
				}
				if !request.DeferOperationTerminal && healthy && port.Valid && port.Int64 > 0 {
					if err := value.Transition(domain.DeploymentServing, request.Now); err != nil {
						return rollback(err)
					}
				}
			}
		case ControllerTaskFailed:
			// Observation and log-collection tasks are read-only. Their retry
			// exhaustion is evidence that the sample is unavailable, not proof
			// that the independently serving deployment failed. Heartbeat loss
			// is projected separately by MarkNodeDeploymentsUnknown.
			if operation.Type != domain.OperationObserve {
				target := domain.DeploymentFailed
				if request.EffectUnknown {
					target = domain.DeploymentUnknown
				}
				if err := transitionDeploymentForTaskOutcome(&value, target, request.Now); err != nil {
					return rollback(err)
				}
				value.FailureReason = request.FailureReason
			}
		case ControllerTaskRolledBack:
			if value.Status == domain.DeploymentRollingBack {
				if err := value.Transition(domain.DeploymentRolledBack, request.Now); err != nil {
					return rollback(err)
				}
			} else if !value.RuntimeReady() {
				// M4 rollback creates a distinct candidate deployment for the
				// previous immutable release. Its Operation is rolled_back, but
				// the replacement deployment must stay runtime-ready/serving;
				// marking that new object rolled_back would erase the actual
				// current recovery target from the fact model.
				return rollback(domain.ValidationError("rollback candidate deployment is not runtime-ready"))
			}
		}
		if err := execExactlyOneTx(ctx, tx, `UPDATE deployments SET state=$1, version=version+1, updated_at=$2 WHERE id=$3 AND version=$4`, string(value.Status), request.Now, value.ID.String(), version); err != nil {
			return rollback(err)
		}
		deployment = &value
	}
	if err := execExactlyOneTx(ctx, tx, `
		UPDATE task_leases SET state=$1, lease_owner=NULL, lease_until=NULL,
		       result_digest=$2, result=$3::jsonb, completed_at=$4, updated_at=$4
		 WHERE task_id=$5
	`, string(taskState), resultDigest, resultPayload, request.Now, task.ID.String()); err != nil {
		return rollback(err)
	}
	if !probeTask && request.Outcome == ControllerTaskSucceeded && request.DeferOperationTerminal && !candidateCleanup {
		updated, err := tx.ExecContext(ctx, `UPDATE m4_rollout_coordinations SET phase='candidate_ready',lease_owner=NULL,lease_until=NULL,updated_at=$1 WHERE replacement_task_id=$2 AND operation_id=$3 AND candidate_deployment_id=$4 AND phase='candidate_requested'`, request.Now, task.ID.String(), operation.ID.String(), deploymentID.String())
		if err != nil {
			return rollback(err)
		}
		count, err := updated.RowsAffected()
		if err != nil {
			return rollback(err)
		}
		if count == 1 {
			evidence := make([]domain.EvidenceRef, 0, len(request.EvidenceIDs))
			for _, id := range request.EvidenceIDs {
				evidence = append(evidence, domain.EvidenceRef{ID: domain.ID(id), Kind: "agent.task"})
			}
			if err := appendM4RolloutEventTx(ctx, tx, operation.ID, 0, M4RolloutCandidateReady, request.Owner, evidence, "replacement Agent task is runtime-ready; serving remains unchanged", request.Now); err != nil {
				return rollback(err)
			}
		} else {
			var phase string
			if err := tx.QueryRowContext(ctx, `SELECT phase FROM m4_rollout_coordinations WHERE replacement_task_id=$1 AND operation_id=$2`, task.ID.String(), operation.ID.String()).Scan(&phase); err != nil {
				return rollback(err)
			}
			if phase != string(M4RolloutCandidateReady) && phase != string(M4RolloutRouteStaged) && phase != string(M4RolloutRouteCommitted) && phase != string(M4RolloutOldRetiring) && phase != string(M4RolloutCompleted) {
				return rollback(domain.NewError(domain.ErrConflict, "replacement task does not match a recoverable rollout"))
			}
		}
	}
	event, err := s.appendControllerEventTx(ctx, tx, operation, eventType, publishStatusForOperation(operation.Status), message, request.EvidenceIDs, request.Now)
	if err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return FinishControllerTaskResult{}, fmt.Errorf("%w: commit task result: %v", ErrOutcomeUnknown, err)
	}
	return FinishControllerTaskResult{Operation: operation, Deployment: deployment, Event: event}, nil
}

func m4CandidateCleanupTaskPayload(payload json.RawMessage, deploymentID domain.ID) bool {
	var envelope struct {
		Kind       string          `json:"kind"`
		Parameters json.RawMessage `json:"parameters"`
	}
	var request contracts.DestroyRequest
	return json.Unmarshal(payload, &envelope) == nil && envelope.Kind == "destroy_group" && json.Unmarshal(envelope.Parameters, &request) == nil && request.DeploymentID == deploymentID && request.PreserveVolumes && request.ConfirmationToken == "" && strings.HasPrefix(request.Operation.IdempotencyKey, "m4-cleanup:")
}

func (s *Store) FailControllerTask(ctx context.Context, request FailControllerTaskRequest) (FinishControllerTaskResult, error) {
	if request.Now.IsZero() {
		request.Now = s.now()
	}
	request.Now = request.Now.UTC()
	request.FailureReason = foundation.RedactText(strings.TrimSpace(request.FailureReason))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return FinishControllerTaskResult{}, err
	}
	rollback := func(cause error) (FinishControllerTaskResult, error) {
		return FinishControllerTaskResult{}, rollbackTx(tx, cause)
	}
	task, err := loadOwnedTaskTx(ctx, tx, request.TaskID, request.Owner, request.Now)
	if err != nil {
		return rollback(err)
	}
	_, probeTask, err := decodeAcornFoxProbeTaskPayload(task.Payload)
	if err != nil {
		return rollback(err)
	}
	operation, deploymentID, version, err := loadOperationTx(ctx, tx, task.OperationID, true)
	if err != nil {
		return rollback(err)
	}
	if request.Retryable && task.Attempt < task.MaxAttempts {
		if err := operation.Transition(domain.OperationWaiting, request.Now); err != nil {
			return rollback(err)
		}
		if err := execExactlyOneTx(ctx, tx, `UPDATE operations SET state='waiting', failure_reason=$1, version=version+1, updated_at=$2 WHERE id=$3 AND version=$4`, nullableString(request.FailureReason), request.Now, operation.ID.String(), version); err != nil {
			return rollback(err)
		}
		if err := execExactlyOneTx(ctx, tx, `UPDATE task_leases SET state='ready', lease_owner=NULL, lease_until=NULL, last_error=$1, updated_at=$2 WHERE task_id=$3`, request.FailureReason, request.Now, task.ID.String()); err != nil {
			return rollback(err)
		}
		event, err := s.appendControllerEventTx(ctx, tx, operation, "operation.retry_scheduled", string(domain.PublishPreparing), "retry scheduled", request.EvidenceIDs, request.Now)
		if err != nil {
			return rollback(err)
		}
		if err := tx.Commit(); err != nil {
			return FinishControllerTaskResult{}, err
		}
		return FinishControllerTaskResult{Operation: operation, Event: event}, nil
	}
	if err := operation.Transition(domain.OperationFailed, request.Now); err != nil {
		return rollback(err)
	}
	operation.FailureReason = request.FailureReason
	if err := execExactlyOneTx(ctx, tx, `UPDATE operations SET state='failed', failure_reason=$1, version=version+1, updated_at=$2 WHERE id=$3 AND version=$4`, nullableString(request.FailureReason), request.Now, operation.ID.String(), version); err != nil {
		return rollback(err)
	}
	resultPayload, _ := json.Marshal(map[string]any{"outcome": ControllerTaskFailed, "failure_reason": request.FailureReason, "evidence_ids": request.EvidenceIDs})
	if err := execExactlyOneTx(ctx, tx, `UPDATE task_leases SET state='failed', lease_owner=NULL, lease_until=NULL, last_error=$1, result_digest=$2, result=$3::jsonb, completed_at=$4, updated_at=$4 WHERE task_id=$5`, request.FailureReason, digestBytes(resultPayload), resultPayload, request.Now, task.ID.String()); err != nil {
		return rollback(err)
	}
	var deployment *domain.Deployment
	if !probeTask && !deploymentID.Empty() && operation.Type != domain.OperationObserve {
		value, deploymentVersion, err := loadDeploymentTx(ctx, tx, deploymentID, true)
		if err != nil {
			return rollback(err)
		}
		if err := transitionDeploymentForTaskOutcome(&value, domain.DeploymentFailed, request.Now); err != nil {
			return rollback(err)
		}
		value.FailureReason = request.FailureReason
		if err := execExactlyOneTx(ctx, tx, `UPDATE deployments SET state=$1, version=version+1, updated_at=$2 WHERE id=$3 AND version=$4`, string(value.Status), request.Now, value.ID.String(), deploymentVersion); err != nil {
			return rollback(err)
		}
		deployment = &value
	}
	event, err := s.appendControllerEventTx(ctx, tx, operation, "operation.failed", string(domain.PublishFailed), "operation failed", request.EvidenceIDs, request.Now)
	if err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return FinishControllerTaskResult{}, err
	}
	return FinishControllerTaskResult{Operation: operation, Deployment: deployment, Event: event}, nil
}

func transitionDeploymentForTaskOutcome(value *domain.Deployment, target domain.DeploymentStatus, at time.Time) error {
	if value.Status == target {
		return nil
	}
	// A cleanup/recovery task may finish after the primary deployment has
	// already reached a terminal state. Its own Operation/Task must still close
	// without trying to move the deployment from failed to failed (or to a less
	// authoritative unknown state).
	switch value.Status {
	case domain.DeploymentFailed, domain.DeploymentRolledBack, domain.DeploymentStopped:
		return nil
	default:
		return value.Transition(target, at)
	}
}

func selectClaimableTaskTx(ctx context.Context, tx *sql.Tx, request ClaimTaskRequest) (Task, string, TaskState, bool, error) {
	var task Task
	var owner sql.NullString
	var leaseUntil sql.NullTime
	var state string
	var payload []byte
	kinds, err := normalizedClaimKinds(request.Kinds)
	if err != nil {
		return Task{}, "", "", false, err
	}
	kindsJSON, err := json.Marshal(kinds)
	if err != nil {
		return Task{}, "", "", false, fmt.Errorf("encode claim task kinds: %w", err)
	}
	err = tx.QueryRowContext(ctx, `
		SELECT task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at,last_agent_sequence
		  FROM task_leases
		 WHERE ((state='ready' AND attempt < LEAST(max_attempts,$2))
		    OR (state='leased' AND lease_until <= $1 AND attempt < LEAST(max_attempts,$2)))
		   AND (jsonb_array_length($3::jsonb)=0 OR payload->>'kind' IN (SELECT jsonb_array_elements_text($3::jsonb)))
		 ORDER BY created_at,task_id LIMIT 1 FOR UPDATE SKIP LOCKED
	`, request.Now, request.MaxAttempts, string(kindsJSON)).Scan(&task.ID, &task.OperationID, &owner, &leaseUntil, &task.Attempt, &task.MaxAttempts, &state, &payload, &task.CreatedAt, &task.UpdatedAt, &task.LastAgentSequence)
	if errors.Is(err, sql.ErrNoRows) {
		return Task{}, "", "", false, nil
	}
	if err != nil {
		return Task{}, "", "", false, err
	}
	if !json.Valid(payload) {
		return Task{}, "", "", false, errors.New("claimable task payload is invalid JSON")
	}
	task.Payload = append(json.RawMessage(nil), payload...)
	task.LeaseOwner = owner.String
	if leaseUntil.Valid {
		value := leaseUntil.Time.UTC()
		task.LeaseUntil = &value
	}
	task.State = TaskState(state)
	return task, owner.String, TaskState(state), true, nil
}

func normalizedClaimKinds(input []string) ([]string, error) {
	if len(input) == 0 {
		return []string{}, nil
	}
	seen := make(map[string]struct{}, len(input))
	result := make([]string, 0, len(input))
	for _, raw := range input {
		kind := strings.TrimSpace(raw)
		if kind == "" {
			return nil, errors.New("claim task kind must not be empty")
		}
		if _, exists := seen[kind]; exists {
			continue
		}
		seen[kind] = struct{}{}
		result = append(result, kind)
	}
	return result, nil
}

func loadOwnedTaskTx(ctx context.Context, tx *sql.Tx, taskID domain.ID, owner string, now time.Time) (Task, error) {
	row := tx.QueryRowContext(ctx, `SELECT task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at,last_agent_sequence FROM task_leases WHERE task_id=$1 FOR UPDATE`, taskID.String())
	task, err := scanTask(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Task{}, ErrNotFound
	}
	if err != nil {
		return Task{}, err
	}
	if task.State != TaskLeased || task.LeaseOwner != strings.TrimSpace(owner) || task.LeaseUntil == nil || !task.LeaseUntil.After(now) {
		return Task{}, ErrLeaseLost
	}
	return task, nil
}

func loadTaskForFinishTx(ctx context.Context, tx *sql.Tx, taskID domain.ID) (Task, string, json.RawMessage, error) {
	var task Task
	var owner sql.NullString
	var leaseUntil sql.NullTime
	var state string
	var payload []byte
	var resultDigest sql.NullString
	var result []byte
	err := tx.QueryRowContext(ctx, `
		SELECT task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at,last_agent_sequence,result_digest,result
		  FROM task_leases WHERE task_id=$1 FOR UPDATE
	`, taskID.String()).Scan(&task.ID, &task.OperationID, &owner, &leaseUntil, &task.Attempt, &task.MaxAttempts, &state, &payload, &task.CreatedAt, &task.UpdatedAt, &task.LastAgentSequence, &resultDigest, &result)
	if errors.Is(err, sql.ErrNoRows) {
		return Task{}, "", nil, ErrNotFound
	}
	if err != nil {
		return Task{}, "", nil, err
	}
	task.LeaseOwner = owner.String
	if leaseUntil.Valid {
		value := leaseUntil.Time.UTC()
		task.LeaseUntil = &value
	}
	task.State = TaskState(state)
	task.Payload = append(json.RawMessage(nil), payload...)
	return task, resultDigest.String, append(json.RawMessage(nil), result...), nil
}

func loadOperationTx(ctx context.Context, tx *sql.Tx, operationID domain.ID, lock bool) (domain.Operation, domain.ID, int, error) {
	query := `SELECT id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,version,target_ref,failure_reason,created_at,updated_at FROM operations WHERE id=$1`
	if lock {
		query += ` FOR UPDATE`
	}
	var operation domain.Operation
	var deploymentID sql.NullString
	var operationType, status string
	var failureReason sql.NullString
	var version int
	err := tx.QueryRowContext(ctx, query, operationID.String()).Scan(&operation.ID, &operation.ApplicationID, &operation.EnvironmentID, &deploymentID, &operationType, &operation.IdempotencyKey, &status, &version, &operation.TargetRef, &failureReason, &operation.CreatedAt, &operation.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Operation{}, "", 0, ErrNotFound
	}
	if err != nil {
		return domain.Operation{}, "", 0, err
	}
	operation.Type = domain.OperationType(operationType)
	operation.Status = domain.OperationStatus(status)
	operation.FailureReason = failureReason.String
	if err := operation.Validate(); err != nil {
		return domain.Operation{}, "", 0, err
	}
	return operation, domain.ID(deploymentID.String), version, nil
}

func loadDeploymentTx(ctx context.Context, tx *sql.Tx, deploymentID domain.ID, lock bool) (domain.Deployment, int, error) {
	query := `SELECT d.id,e.application_id,d.environment_id,d.release_id,d.state,d.version,d.created_at,d.updated_at FROM deployments d JOIN environments e ON e.id=d.environment_id WHERE d.id=$1`
	if lock {
		query += ` FOR UPDATE OF d`
	}
	var deployment domain.Deployment
	var status string
	var version int
	err := tx.QueryRowContext(ctx, query, deploymentID.String()).Scan(&deployment.ID, &deployment.ApplicationID, &deployment.EnvironmentID, &deployment.ReleaseID, &status, &version, &deployment.CreatedAt, &deployment.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Deployment{}, 0, ErrNotFound
	}
	if err != nil {
		return domain.Deployment{}, 0, err
	}
	deployment.Status = domain.DeploymentStatus(status)
	if err := deployment.Validate(); err != nil {
		return domain.Deployment{}, 0, err
	}
	return deployment, version, nil
}

func (s *Store) appendControllerEventTx(ctx context.Context, tx *sql.Tx, operation domain.Operation, eventType, status, message string, evidence []string, now time.Time) (application.Event, error) {
	lockKey := "open-card-operation:" + operation.ID.String()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockKey); err != nil {
		return application.Event{}, err
	}
	var aggregateSequence int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM outbox_events WHERE aggregate_type='operation' AND aggregate_id=$1`, operation.ID.String()).Scan(&aggregateSequence); err != nil {
		return application.Event{}, err
	}
	streamSequence, err := s.nextStreamSequence(ctx, tx)
	if err != nil {
		return application.Event{}, err
	}
	event := application.Event{SchemaVersion: "1.1", ID: "evt-" + formatSequence(uint64(streamSequence)), OperationID: operation.ID.String(), ApplicationID: operation.ApplicationID.String(), Sequence: uint64(streamSequence), OccurredAt: now.UTC(), Kind: eventType, Status: status, Message: foundation.RedactText(message), EvidenceIDs: append([]string(nil), evidence...)}
	payload, err := json.Marshal(event)
	if err != nil {
		return application.Event{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO outbox_events(id,aggregate_type,aggregate_id,aggregate_version,sequence,stream_sequence,event_type,payload,created_at,payload_version)
		VALUES($1,'operation',$2,$3,$4,$5,$6,$7::jsonb,$8,$9)
	`, event.ID, operation.ID.String(), aggregateSequence, aggregateSequence, streamSequence, eventType, payload, now.UTC(), event.SchemaVersion); err != nil {
		return application.Event{}, err
	}
	return event, nil
}

func rollbackTx(tx *sql.Tx, cause error) error {
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		return fmt.Errorf("%w (rollback: %v)", cause, err)
	}
	return cause
}

func execExactlyOneTx(ctx context.Context, tx *sql.Tx, statement string, args ...any) error {
	result, err := tx.ExecContext(ctx, statement, args...)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("expected one transactional row mutation, got %d", rows)
	}
	return nil
}

func digestAgentEvent(kind string, payload []byte) string {
	return digestBytes(append(append([]byte(kind), 0), payload...))
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func nullableString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func publishStatusForOperation(status domain.OperationStatus) string {
	if status == domain.OperationSucceeded || status == domain.OperationRolledBack {
		return string(domain.PublishSucceeded)
	}
	if status == domain.OperationFailed || status == domain.OperationCancelled {
		return string(domain.PublishFailed)
	}
	return string(domain.PublishDeploying)
}
