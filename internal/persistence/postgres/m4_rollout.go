package postgres

// Durable M4 rollout coordination deliberately lives beside PostgreSQL rather
// than an in-process controller map. A replacement may survive a control-plane
// restart only when its candidate, route-set snapshot and retirement intent
// are all explicit facts.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

type M4RolloutPhase string

const (
	M4RolloutCandidateRequested M4RolloutPhase = "candidate_requested"
	M4RolloutCandidateReady     M4RolloutPhase = "candidate_ready"
	M4RolloutRouteStaged        M4RolloutPhase = "route_staged"
	M4RolloutCandidateCleanup   M4RolloutPhase = "candidate_cleanup"
	M4RolloutRouteCommitted     M4RolloutPhase = "route_committed"
	M4RolloutOldRetiring        M4RolloutPhase = "old_retiring"
	M4RolloutCompleted          M4RolloutPhase = "completed"
	M4RolloutFailed             M4RolloutPhase = "failed"
	M4RolloutRolledBack         M4RolloutPhase = "rolled_back"
)

func (p M4RolloutPhase) terminal() bool {
	return p == M4RolloutCompleted || p == M4RolloutFailed || p == M4RolloutRolledBack
}

func validM4RolloutTransition(from, to M4RolloutPhase) bool {
	if from == to {
		return true
	}
	switch from {
	case M4RolloutCandidateRequested:
		return to == M4RolloutCandidateReady || to == M4RolloutFailed || to == M4RolloutRolledBack
	case M4RolloutCandidateReady:
		return to == M4RolloutRouteStaged || to == M4RolloutCandidateCleanup || to == M4RolloutFailed || to == M4RolloutRolledBack
	case M4RolloutRouteStaged:
		return to == M4RolloutRouteCommitted || to == M4RolloutCandidateCleanup || to == M4RolloutFailed || to == M4RolloutRolledBack
	case M4RolloutCandidateCleanup:
		return to == M4RolloutFailed || to == M4RolloutRolledBack
	case M4RolloutRouteCommitted:
		return to == M4RolloutOldRetiring || to == M4RolloutCompleted
	case M4RolloutOldRetiring:
		return to == M4RolloutCompleted
	default:
		return false
	}
}

type M4RolloutCoordinator struct {
	OperationID             domain.ID            `json:"operation_id"`
	ApplicationID           domain.ID            `json:"application_id"`
	EnvironmentID           domain.ID            `json:"environment_id"`
	SourceDeploymentID      domain.ID            `json:"source_deployment_id"`
	CandidateDeploymentID   domain.ID            `json:"candidate_deployment_id"`
	ReplacementTaskID       domain.ID            `json:"replacement_task_id,omitempty"`
	CandidateCleanupTaskID  domain.ID            `json:"candidate_cleanup_task_id,omitempty"`
	OldRetirementTaskID     domain.ID            `json:"old_retirement_task_id,omitempty"`
	Phase                   M4RolloutPhase       `json:"phase"`
	RouteSetDigest          string               `json:"route_set_digest"`
	ExpectedRouteSetVersion int64                `json:"expected_route_set_version"`
	Attempt                 int                  `json:"attempt"`
	LeaseOwner              string               `json:"lease_owner,omitempty"`
	LeaseUntil              *time.Time           `json:"lease_until,omitempty"`
	ObservationDeadline     *time.Time           `json:"observation_deadline,omitempty"`
	FailureReason           string               `json:"failure_reason,omitempty"`
	CandidateCleanupReason  string               `json:"candidate_cleanup_reason,omitempty"`
	Evidence                []domain.EvidenceRef `json:"evidence,omitempty"`
	CreatedAt               time.Time            `json:"created_at"`
	UpdatedAt               time.Time            `json:"updated_at"`
	CompletedAt             *time.Time           `json:"completed_at,omitempty"`
}

func (r M4RolloutCoordinator) Validate() error {
	for name, id := range map[string]domain.ID{"operation": r.OperationID, "application": r.ApplicationID, "environment": r.EnvironmentID, "source deployment": r.SourceDeploymentID, "candidate deployment": r.CandidateDeploymentID} {
		if err := domain.RequireID(id, name+" id"); err != nil {
			return err
		}
	}
	if r.SourceDeploymentID == r.CandidateDeploymentID || !m4SHA256(r.RouteSetDigest) || r.ExpectedRouteSetVersion < 0 || r.Attempt < 0 {
		return domain.ValidationError("M4 rollout identity or route-set version is invalid")
	}
	if !validM4RolloutPhase(r.Phase) || (r.Phase.terminal() != (r.CompletedAt != nil)) {
		return domain.ValidationError("M4 rollout phase terminal shape is invalid")
	}
	if (r.LeaseOwner == "") != (r.LeaseUntil == nil) {
		return domain.ValidationError("M4 rollout lease is invalid")
	}
	if r.Phase == M4RolloutFailed && strings.TrimSpace(r.FailureReason) == "" {
		return domain.ValidationError("failed M4 rollout requires a reason")
	}
	if r.Phase == M4RolloutCandidateCleanup && (r.CandidateCleanupTaskID.Empty() || strings.TrimSpace(r.CandidateCleanupReason) == "") {
		return domain.ValidationError("candidate cleanup phase requires task and reason")
	}
	for _, evidence := range r.Evidence {
		if err := evidence.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func validM4RolloutPhase(p M4RolloutPhase) bool {
	switch p {
	case M4RolloutCandidateRequested, M4RolloutCandidateReady, M4RolloutRouteStaged, M4RolloutCandidateCleanup, M4RolloutRouteCommitted, M4RolloutOldRetiring, M4RolloutCompleted, M4RolloutFailed, M4RolloutRolledBack:
		return true
	}
	return false
}

type CreateM4RolloutRequest struct {
	Coordinator M4RolloutCoordinator
	Actor       string
	Reason      string
}
type ClaimM4RolloutRequest struct {
	Owner    string
	Now      time.Time
	Duration time.Duration
	Limit    int
}
type AdvanceM4RolloutRequest struct {
	OperationID domain.ID
	Owner       string
	From, To    M4RolloutPhase
	Evidence    []domain.EvidenceRef
	Reason      string
	Now         time.Time
}

type M4StagedRouteEntry struct {
	RouteID             domain.ID `json:"route_id"`
	ServiceName         string    `json:"service_name"`
	Host                string    `json:"host"`
	Path                string    `json:"path"`
	CertificateID       domain.ID `json:"certificate_id,omitempty"`
	OldDeploymentID     domain.ID `json:"old_deployment_id"`
	OldPortLeaseID      domain.ID `json:"old_port_lease_id"`
	OldPointerRevision  int64     `json:"old_pointer_revision"`
	CandidateDeployment domain.ID `json:"candidate_deployment_id"`
	CandidatePort       int       `json:"candidate_port"`
}
type M4StagedRouteSet struct {
	OperationID           domain.ID            `json:"operation_id"`
	ApplicationID         domain.ID            `json:"application_id"`
	SourceDeploymentID    domain.ID            `json:"source_deployment_id"`
	CandidateDeploymentID domain.ID            `json:"candidate_deployment_id"`
	OldDigest             string               `json:"old_digest"`
	CandidateDigest       string               `json:"candidate_digest"`
	ExpectedVersion       int64                `json:"expected_version"`
	State                 string               `json:"state"`
	Entries               []M4StagedRouteEntry `json:"entries"`
}

type FinalizeM4ServingRequest struct {
	OperationID     domain.ID
	Owner           string
	RouteSetDigest  string
	ExpectedVersion int64
	Actor           string
	Reason          string
	Evidence        []domain.EvidenceRef
	Now             time.Time
}
type FinalizeM4ServingResult struct {
	Coordinator M4RolloutCoordinator
	RouteSet    M4StagedRouteSet
	Replayed    bool
}

type CreateM4RetirementTaskRequest struct {
	RolloutOperationID domain.ID
	OldDeploymentID    domain.ID
	Operation          domain.Operation
	TaskID             domain.ID
	Payload            json.RawMessage
	MaxAttempts        int
	Now                time.Time
}

type CreateM4CandidateCleanupTaskRequest struct {
	RolloutOperationID  domain.ID
	CandidateDeployment domain.ID
	TaskID              domain.ID
	Payload             json.RawMessage
	Owner               string
	Reason              string
	MaxAttempts         int
	Now                 time.Time
}

func (s *Store) CreateM4CandidateCleanupTask(ctx context.Context, request CreateM4CandidateCleanupTaskRequest) (ControllerTask, bool, error) {
	if err := s.requireDB(); err != nil {
		return ControllerTask{}, false, err
	}
	request.Owner, request.Reason = strings.TrimSpace(request.Owner), foundation.RedactText(strings.TrimSpace(request.Reason))
	if request.RolloutOperationID.Empty() || request.CandidateDeployment.Empty() || request.TaskID.Empty() || request.Owner == "" || request.Reason == "" || len(request.Payload) == 0 || !json.Valid(request.Payload) {
		return ControllerTask{}, false, domain.ValidationError("M4 candidate cleanup task identity is invalid")
	}
	var envelope struct {
		Kind       string          `json:"kind"`
		Parameters json.RawMessage `json:"parameters"`
	}
	var destroy contracts.DestroyRequest
	if json.Unmarshal(request.Payload, &envelope) != nil || envelope.Kind != "destroy_group" || json.Unmarshal(envelope.Parameters, &destroy) != nil || destroy.DeploymentID != request.CandidateDeployment || !destroy.PreserveVolumes || destroy.ConfirmationToken != "" || !strings.HasPrefix(destroy.Operation.IdempotencyKey, "m4-cleanup:") {
		return ControllerTask{}, false, domain.ValidationError("M4 candidate cleanup payload is not an exact volume-preserving destroy")
	}
	redacted, err := foundation.RedactJSON(request.Payload, nil)
	if err != nil {
		return ControllerTask{}, false, err
	}
	now := m4Now(s, request.Now)
	maxAttempts := request.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ControllerTask{}, false, err
	}
	rollback := func(e error) (ControllerTask, bool, error) { return ControllerTask{}, false, rollbackTx(tx, e) }
	rollout, found, err := loadM4RolloutTx(ctx, tx, request.RolloutOperationID, true)
	if err != nil {
		return rollback(err)
	}
	if !found {
		return rollback(ErrNotFound)
	}
	if rollout.CandidateDeploymentID != request.CandidateDeployment || rollout.SourceDeploymentID == request.CandidateDeployment {
		return rollback(domain.NewError(domain.ErrConflict, "candidate cleanup target differs from rollout"))
	}
	if !rollout.CandidateCleanupTaskID.Empty() {
		if rollout.CandidateCleanupTaskID != request.TaskID {
			return rollback(domain.NewError(domain.ErrConflict, "candidate cleanup task identity conflicts"))
		}
		task, _, _, err := loadTaskForFinishTx(ctx, tx, request.TaskID)
		if err != nil {
			return rollback(err)
		}
		if !m4JSONEquivalent(task.Payload, redacted) {
			return rollback(domain.NewError(domain.ErrConflict, "candidate cleanup task replay differs"))
		}
		operation, deploymentID, _, err := loadOperationTx(ctx, tx, task.OperationID, false)
		if err != nil {
			return rollback(err)
		}
		if operation.ID != rollout.OperationID || deploymentID != request.CandidateDeployment {
			return rollback(domain.NewError(domain.ErrConflict, "candidate cleanup task scope differs"))
		}
		if err := tx.Commit(); err != nil {
			return ControllerTask{}, false, err
		}
		return ControllerTask{Task: task, Operation: operation, DeploymentID: deploymentID}, true, nil
	}
	if rollout.Phase != M4RolloutCandidateReady && rollout.Phase != M4RolloutRouteStaged {
		return rollback(domain.NewError(domain.ErrConflict, "candidate cleanup can start only before route commit"))
	}
	if rollout.LeaseOwner != request.Owner || rollout.LeaseUntil == nil || !rollout.LeaseUntil.After(now) {
		return rollback(ErrLeaseLost)
	}
	var candidateState string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM deployments WHERE id=$1 FOR UPDATE`, request.CandidateDeployment.String()).Scan(&candidateState); err != nil {
		return rollback(err)
	}
	if candidateState == "serving" || candidateState == "stopped" {
		return rollback(domain.NewError(domain.ErrConflict, "candidate cleanup cannot target serving or already stopped deployment"))
	}
	operation, deploymentID, _, err := loadOperationTx(ctx, tx, rollout.OperationID, true)
	if err != nil {
		return rollback(err)
	}
	if operation.Status != domain.OperationRunning || deploymentID != request.CandidateDeployment {
		return rollback(domain.NewError(domain.ErrConflict, "candidate cleanup parent operation scope changed"))
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO task_leases(task_id,operation_id,attempt,max_attempts,state,payload,created_at,updated_at) VALUES($1,$2,0,$3,'ready',$4::jsonb,$5,$5)`, request.TaskID.String(), rollout.OperationID.String(), maxAttempts, redacted, now); err != nil {
		return rollback(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE m4_rollout_coordinations SET candidate_cleanup_task_id=$1,candidate_cleanup_reason=$2,phase='candidate_cleanup',lease_owner=NULL,lease_until=NULL,updated_at=$3 WHERE operation_id=$4`, request.TaskID.String(), request.Reason, now, rollout.OperationID.String()); err != nil {
		return rollback(err)
	}
	if err := appendM4RolloutEventTx(ctx, tx, rollout.OperationID, 0, M4RolloutCandidateCleanup, request.Owner, nil, "old route restored; candidate cleanup queued", now); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return ControllerTask{}, false, fmt.Errorf("%w: create M4 candidate cleanup task: %v", ErrOutcomeUnknown, err)
	}
	task := Task{ID: request.TaskID, OperationID: rollout.OperationID, MaxAttempts: maxAttempts, State: TaskReady, Payload: redacted, CreatedAt: now, UpdatedAt: now}
	return ControllerTask{Task: task, Operation: operation, DeploymentID: request.CandidateDeployment}, false, nil
}

func (s *Store) CreateM4RetirementTask(ctx context.Context, request CreateM4RetirementTaskRequest) (ControllerTask, bool, error) {
	if err := s.requireDB(); err != nil {
		return ControllerTask{}, false, err
	}
	if request.RolloutOperationID.Empty() || request.OldDeploymentID.Empty() || request.TaskID.Empty() || request.Operation.Type != domain.OperationDestroy || request.Operation.Status != domain.OperationPending || request.Operation.TargetRef != "destroy/"+request.OldDeploymentID.String() || len(request.Payload) == 0 || !json.Valid(request.Payload) {
		return ControllerTask{}, false, domain.ValidationError("M4 retirement task identity is invalid")
	}
	if err := request.Operation.Validate(); err != nil {
		return ControllerTask{}, false, err
	}
	redacted, err := foundation.RedactJSON(request.Payload, nil)
	if err != nil {
		return ControllerTask{}, false, err
	}
	now := m4Now(s, request.Now)
	max := request.MaxAttempts
	if max <= 0 {
		max = 3
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ControllerTask{}, false, err
	}
	rollback := func(e error) (ControllerTask, bool, error) { return ControllerTask{}, false, rollbackTx(tx, e) }
	rollout, found, err := loadM4RolloutTx(ctx, tx, request.RolloutOperationID, true)
	if err != nil {
		return rollback(err)
	}
	if !found {
		return rollback(ErrNotFound)
	}
	if rollout.SourceDeploymentID != request.OldDeploymentID || rollout.Phase != M4RolloutOldRetiring {
		return rollback(domain.NewError(domain.ErrConflict, "M4 retirement target does not match rollout"))
	}
	if !rollout.OldRetirementTaskID.Empty() {
		if rollout.OldRetirementTaskID != request.TaskID {
			return rollback(domain.NewError(domain.ErrConflict, "M4 retirement task identity conflicts"))
		}
		task, _, _, err := loadTaskForFinishTx(ctx, tx, request.TaskID)
		if err != nil {
			return rollback(err)
		}
		if task.OperationID != request.Operation.ID || !m4JSONEquivalent(task.Payload, redacted) {
			return rollback(domain.NewError(domain.ErrConflict, "M4 retirement task replay differs"))
		}
		operation, deploymentID, _, err := loadOperationTx(ctx, tx, task.OperationID, false)
		if err != nil {
			return rollback(err)
		}
		if deploymentID != request.OldDeploymentID {
			return rollback(domain.NewError(domain.ErrConflict, "M4 retirement task deployment differs"))
		}
		if err := tx.Commit(); err != nil {
			return ControllerTask{}, false, err
		}
		return ControllerTask{Task: task, Operation: operation, DeploymentID: deploymentID}, true, nil
	}
	var app, environment string
	if err := tx.QueryRowContext(ctx, `SELECT e.application_id,d.environment_id FROM deployments d JOIN environments e ON e.id=d.environment_id WHERE d.id=$1`, request.OldDeploymentID.String()).Scan(&app, &environment); err != nil {
		return rollback(err)
	}
	if app != rollout.ApplicationID.String() || environment != rollout.EnvironmentID.String() || request.Operation.ApplicationID != rollout.ApplicationID || request.Operation.EnvironmentID != rollout.EnvironmentID {
		return rollback(domain.ValidationError("M4 retirement scope differs from rollout"))
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,version,target_ref,created_at,updated_at) VALUES($1,$2,$3,$4,'destroy',$5,'pending',1,$6,$7,$7)`, request.Operation.ID.String(), rollout.ApplicationID.String(), rollout.EnvironmentID.String(), request.OldDeploymentID.String(), request.Operation.IdempotencyKey, request.Operation.TargetRef, now); err != nil {
		return rollback(mapControllerOperationInsertError(err))
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO task_leases(task_id,operation_id,attempt,max_attempts,state,payload,created_at,updated_at) VALUES($1,$2,0,$3,'ready',$4::jsonb,$5,$5)`, request.TaskID.String(), request.Operation.ID.String(), max, redacted, now); err != nil {
		return rollback(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE m4_rollout_coordinations SET old_retirement_task_id=$1,updated_at=$2 WHERE operation_id=$3 AND old_retirement_task_id IS NULL`, request.TaskID.String(), now, request.RolloutOperationID.String()); err != nil {
		return rollback(err)
	}
	if err := execExactlyOneTx(ctx, tx, `UPDATE m4_rollout_coordinations SET updated_at=$1 WHERE operation_id=$2 AND old_retirement_task_id=$3`, now, request.RolloutOperationID.String(), request.TaskID.String()); err != nil {
		return rollback(err)
	}
	event, err := s.appendControllerEventTx(ctx, tx, request.Operation, "operation.queued", string(domain.PublishDeploying), "old service group retirement queued", nil, now)
	if err != nil {
		return rollback(err)
	}
	_ = event
	if err := tx.Commit(); err != nil {
		return ControllerTask{}, false, fmt.Errorf("%w: create M4 retirement task: %v", ErrOutcomeUnknown, err)
	}
	task := Task{ID: request.TaskID, OperationID: request.Operation.ID, MaxAttempts: max, State: TaskReady, Payload: redacted, CreatedAt: now, UpdatedAt: now}
	return ControllerTask{Task: task, Operation: request.Operation, DeploymentID: request.OldDeploymentID}, false, nil
}

func (s *Store) FinalizeM4Serving(ctx context.Context, request FinalizeM4ServingRequest) (FinalizeM4ServingResult, error) {
	if err := s.requireDB(); err != nil {
		return FinalizeM4ServingResult{}, err
	}
	if request.OperationID.Empty() || strings.TrimSpace(request.Owner) == "" || !m4SHA256(request.RouteSetDigest) || request.ExpectedVersion < 0 || strings.TrimSpace(request.Actor) == "" {
		return FinalizeM4ServingResult{}, domain.ValidationError("FinalizeM4Serving identity is invalid")
	}
	now := m4Now(s, request.Now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return FinalizeM4ServingResult{}, err
	}
	rollback := func(e error) (FinalizeM4ServingResult, error) { return FinalizeM4ServingResult{}, rollbackTx(tx, e) }
	rollout, found, err := loadM4RolloutTx(ctx, tx, request.OperationID, true)
	if err != nil {
		return rollback(err)
	}
	if !found {
		return rollback(ErrNotFound)
	}
	var routeSet M4StagedRouteSet
	var state string
	var leaseOwner sql.NullString
	var leaseUntil sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT rollout_operation_id,application_id,source_deployment_id,candidate_deployment_id,old_digest,candidate_digest,expected_version,state,lease_owner,lease_until FROM m4_rollout_route_sets WHERE rollout_operation_id=$1 FOR UPDATE`, request.OperationID.String()).Scan(&routeSet.OperationID, &routeSet.ApplicationID, &routeSet.SourceDeploymentID, &routeSet.CandidateDeploymentID, &routeSet.OldDigest, &routeSet.CandidateDigest, &routeSet.ExpectedVersion, &state, &leaseOwner, &leaseUntil)
	if errors.Is(err, sql.ErrNoRows) {
		return rollback(ErrNotFound)
	}
	if err != nil {
		return rollback(err)
	}
	routeSet.State = state
	if routeSet.CandidateDigest != request.RouteSetDigest || routeSet.ExpectedVersion != request.ExpectedVersion || rollout.RouteSetDigest != request.RouteSetDigest || rollout.ExpectedRouteSetVersion != request.ExpectedVersion {
		return rollback(domain.NewError(domain.ErrConflict, "FinalizeM4Serving route-set identity conflicts"))
	}
	if state == "current" && (rollout.Phase == M4RolloutRouteCommitted || rollout.Phase == M4RolloutOldRetiring || rollout.Phase == M4RolloutCompleted) {
		var deploymentState string
		if err := tx.QueryRowContext(ctx, `SELECT state FROM deployments WHERE id=$1`, routeSet.CandidateDeploymentID.String()).Scan(&deploymentState); err != nil {
			return rollback(err)
		}
		if deploymentState != "serving" {
			return rollback(domain.NewError(domain.ErrConflict, "committed route-set candidate is not serving"))
		}
		if err := tx.Commit(); err != nil {
			return FinalizeM4ServingResult{}, err
		}
		return FinalizeM4ServingResult{Coordinator: rollout, RouteSet: routeSet, Replayed: true}, nil
	}
	if rollout.Phase != M4RolloutRouteStaged || state != "observed" || rollout.LeaseOwner != request.Owner || rollout.LeaseUntil == nil || !rollout.LeaseUntil.After(now) || !leaseOwner.Valid || leaseOwner.String != request.Owner || !leaseUntil.Valid || !leaseUntil.Time.After(now) {
		return rollback(ErrLeaseLost)
	}
	rows, err := tx.QueryContext(ctx, `SELECT route_id,service_name,host,path_prefix,COALESCE(certificate_reference_id,''),old_deployment_id,old_port_lease_id,old_pointer_revision,candidate_deployment_id,candidate_port FROM m4_rollout_route_set_entries WHERE rollout_operation_id=$1 ORDER BY route_id FOR SHARE`, request.OperationID.String())
	if err != nil {
		return rollback(err)
	}
	entries := make([]M4StagedRouteEntry, 0)
	for rows.Next() {
		var entry M4StagedRouteEntry
		var candidatePort sql.NullInt64
		if err := rows.Scan(&entry.RouteID, &entry.ServiceName, &entry.Host, &entry.Path, &entry.CertificateID, &entry.OldDeploymentID, &entry.OldPortLeaseID, &entry.OldPointerRevision, &entry.CandidateDeployment, &candidatePort); err != nil {
			rows.Close()
			return rollback(err)
		}
		if candidatePort.Valid {
			entry.CandidatePort = int(candidatePort.Int64)
		}
		entries = append(entries, entry)
	}
	if err := rows.Close(); err != nil {
		return rollback(err)
	}
	for _, entry := range entries {
		if entry.CandidatePort == 0 {
			if err := tx.QueryRowContext(ctx, `SELECT host_port FROM m4_service_observations WHERE deployment_id=$1 AND service_name=$2 AND healthy=true AND host_port BETWEEN 1 AND 65535 ORDER BY observed_at DESC,id DESC LIMIT 1`, entry.CandidateDeployment.String(), entry.ServiceName).Scan(&entry.CandidatePort); err != nil {
				return rollback(domain.NewError(domain.ErrConflict, "candidate route endpoint is not observed"))
			}
		}
		var currentDeployment, currentLease string
		var revision int64
		if err := tx.QueryRowContext(ctx, `SELECT deployment_id,port_lease_id,revision FROM m3_route_pointers WHERE route_id=$1 FOR UPDATE`, entry.RouteID.String()).Scan(&currentDeployment, &currentLease, &revision); err != nil {
			rows.Close()
			return rollback(err)
		}
		if currentDeployment != entry.OldDeploymentID.String() || currentLease != entry.OldPortLeaseID.String() || revision != entry.OldPointerRevision {
			rows.Close()
			return rollback(ErrRoutePointerConflict)
		}
		candidateLeaseID := tlsAllowLeaseID(routeSet.ApplicationID, entry.CandidateDeployment, entry.ServiceName, entry.CandidatePort)
		leaseID, err := ensureTLSAllowLeaseTx(ctx, tx, candidateLeaseID, routeSet.ApplicationID, entry.CandidateDeployment, entry.ServiceName, entry.CandidatePort, now)
		if err != nil {
			rows.Close()
			return rollback(err)
		}
		if currentLease != leaseID.String() || currentDeployment != entry.CandidateDeployment.String() {
			var oldPort int
			if err := tx.QueryRowContext(ctx, `SELECT port FROM m3_port_leases WHERE id=$1 AND application_id=$2 AND deployment_id=$3 AND service_name=$4 AND bind_host='127.0.0.1' AND released_at IS NULL FOR UPDATE`, entry.OldPortLeaseID.String(), routeSet.ApplicationID.String(), entry.OldDeploymentID.String(), entry.ServiceName).Scan(&oldPort); err != nil {
				rows.Close()
				return rollback(ErrRoutePointerConflict)
			}
			result, err := tx.ExecContext(ctx, `UPDATE m3_route_pointers SET deployment_id=$1,port_lease_id=$2,revision=revision+1,updated_at=$3 WHERE route_id=$4 AND deployment_id=$5 AND port_lease_id=$6 AND revision=$7`, entry.CandidateDeployment.String(), leaseID.String(), now, entry.RouteID.String(), entry.OldDeploymentID.String(), entry.OldPortLeaseID.String(), entry.OldPointerRevision)
			if err != nil {
				rows.Close()
				return rollback(err)
			}
			if err := requireOneTaskMutation(result); err != nil {
				rows.Close()
				return rollback(ErrRoutePointerConflict)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE m3_desired_routes SET deployment_id=$1,updated_at=$2 WHERE id=$3`, entry.CandidateDeployment.String(), now, entry.RouteID.String()); err != nil {
				rows.Close()
				return rollback(err)
			}
			if _, err := releaseTLSAllowLeaseIfUnreferencedTx(ctx, tx, entry.OldPortLeaseID, routeSet.ApplicationID, entry.OldDeploymentID, entry.ServiceName, oldPort, now); err != nil {
				rows.Close()
				return rollback(err)
			}
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE deployments SET state='serving',version=version+1,updated_at=$1 WHERE id=$2 AND state IN ('runtime_ready','degraded')`, now, routeSet.CandidateDeploymentID.String())
	if err != nil {
		return rollback(err)
	}
	if err := requireOneTaskMutation(result); err != nil {
		return rollback(domain.NewError(domain.ErrConflict, "candidate deployment is not runtime-ready"))
	}
	var operation domain.Operation
	var operationType, operationState string
	if err := tx.QueryRowContext(ctx, `SELECT id,application_id,environment_id,target_ref,operation_type,idempotency_key,state,created_at,updated_at FROM operations WHERE id=$1 FOR UPDATE`, request.OperationID.String()).Scan(&operation.ID, &operation.ApplicationID, &operation.EnvironmentID, &operation.TargetRef, &operationType, &operation.IdempotencyKey, &operationState, &operation.CreatedAt, &operation.UpdatedAt); err != nil {
		return rollback(err)
	}
	operation.Type = domain.OperationType(operationType)
	terminalState := domain.OperationSucceeded
	action := "redeploy"
	if operation.Type == domain.OperationRollback {
		terminalState = domain.OperationRolledBack
		action = "rollback"
	}
	result, err = tx.ExecContext(ctx, `UPDATE operations SET state=$1,version=version+1,updated_at=$2 WHERE id=$3 AND state='running'`, string(terminalState), now, request.OperationID.String())
	if err != nil {
		return rollback(err)
	}
	if err := requireOneTaskMutation(result); err != nil {
		return rollback(domain.NewError(domain.ErrConflict, "parent operation is not running"))
	}
	operation.Status = terminalState
	operation.UpdatedAt = now
	candidateDeployment := domain.Deployment{ID: routeSet.CandidateDeploymentID, ApplicationID: rollout.ApplicationID, EnvironmentID: rollout.EnvironmentID, ReleaseID: domain.ID(""), Status: domain.DeploymentServing}
	if err := tx.QueryRowContext(ctx, `SELECT release_id,created_at,updated_at FROM deployments WHERE id=$1`, routeSet.CandidateDeploymentID.String()).Scan(&candidateDeployment.ReleaseID, &candidateDeployment.CreatedAt, &candidateDeployment.UpdatedAt); err != nil {
		return rollback(err)
	}
	resultPayload, _ := json.Marshal(map[string]any{"operation": operation, "action": action, "scope": "application", "release_id": candidateDeployment.ReleaseID, "deployment": candidateDeployment, "rollback_data": false, "data_notice": "Application code/configuration only; persistent data is not rolled back.", "kept_last_usable": false, "evidence": request.Evidence})
	result, err = tx.ExecContext(ctx, `UPDATE m4_operation_requests SET result=$1::jsonb,completed_at=$2 WHERE operation_id=$3 AND result IS NULL`, resultPayload, now, request.OperationID.String())
	if err != nil {
		return rollback(err)
	}
	if err := requireOneTaskMutation(result); err != nil {
		return rollback(domain.NewError(domain.ErrConflict, "parent operation request result is already terminal"))
	}
	if request.Evidence == nil {
		request.Evidence = []domain.EvidenceRef{}
	}
	evidenceJSON, _ := json.Marshal(request.Evidence)
	inputDigest := digestBytes([]byte(request.OperationID.String() + "\x00" + request.RouteSetDigest + "\x00" + fmt.Sprint(request.ExpectedVersion)))
	var previous sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT record_hash FROM audit_evidence ORDER BY sequence DESC LIMIT 1`).Scan(&previous); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return rollback(err)
	}
	recordHash := digestBytes([]byte(previous.String + "\x00" + inputDigest + "\x00" + now.Format(time.RFC3339Nano)))
	auditID := m4ServingID("audit", request.OperationID.String(), request.RouteSetDigest)
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_evidence(id,actor_type,actor_id,action,reason,input_digest,result,evidence_refs,previous_hash,record_hash,created_at) VALUES($1,'system',$2,'operations.route_set_serving',$3,$4,'succeeded',$5::jsonb,$6,$7,$8)`, auditID.String(), request.Actor, foundation.RedactText(request.Reason), inputDigest, evidenceJSON, nullableString(previous.String), recordHash, now); err != nil {
		return rollback(err)
	}
	var aggregateSequence, streamSequence int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM outbox_events WHERE aggregate_type='operation' AND aggregate_id=$1`, request.OperationID.String()).Scan(&aggregateSequence); err != nil {
		return rollback(err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT nextval('outbox_events_stream_sequence'::regclass)`).Scan(&streamSequence); err != nil {
		return rollback(err)
	}
	var previousLifecycle string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT lower(events.event_type) FROM outbox_events events JOIN operations prior ON prior.id=events.aggregate_id WHERE events.aggregate_type='operation' AND prior.environment_id=$1 AND (lower(events.event_type) ~ '(failure|failed|escalat|recover|recovered)$' OR lower(COALESCE(events.payload->>'status','')) IN ('failure','failed','escalation','escalated','recovery','recovered')) ORDER BY events.stream_sequence DESC LIMIT 1),'')`, rollout.EnvironmentID.String()).Scan(&previousLifecycle); err != nil {
		return rollback(err)
	}
	eventType, eventStatus, eventMessage := "operations.route_set_serving.succeeded", "succeeded", "candidate route-set is serving"
	if strings.Contains(previousLifecycle, "fail") || strings.Contains(previousLifecycle, "escalat") {
		eventType, eventStatus, eventMessage = "operations.route_set_serving.recovered", "recovered", "serving restored after failed rollout; previous deployment remained available"
	}
	eventID := m4ServingID("evt", request.OperationID.String(), fmt.Sprint(streamSequence))
	payload, _ := json.Marshal(application.Event{SchemaVersion: "1.1", ID: eventID.String(), OperationID: request.OperationID.String(), ApplicationID: rollout.ApplicationID.String(), Sequence: uint64(streamSequence), Kind: eventType, Status: eventStatus, Message: eventMessage, OccurredAt: now, EvidenceIDs: evidenceRefIDs(request.Evidence)})
	if _, err := tx.ExecContext(ctx, `INSERT INTO outbox_events(id,aggregate_type,aggregate_id,aggregate_version,sequence,stream_sequence,event_type,payload,created_at,payload_version) VALUES($1,'operation',$2,$3,$3,$4,$5,$6::jsonb,$7,'1.1')`, eventID.String(), request.OperationID.String(), aggregateSequence, streamSequence, eventType, payload, now); err != nil {
		return rollback(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE m4_rollout_route_sets SET state='current',lease_owner=NULL,lease_until=NULL,updated_at=$1 WHERE rollout_operation_id=$2 AND state='observed'`, now, request.OperationID.String()); err != nil {
		return rollback(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE m4_rollout_coordinations SET phase='route_committed',evidence=evidence||$1::jsonb,updated_at=$2 WHERE operation_id=$3 AND phase='route_staged'`, evidenceJSON, now, request.OperationID.String()); err != nil {
		return rollback(err)
	}
	if err := appendM4RolloutEventTx(ctx, tx, request.OperationID, 0, M4RolloutRouteCommitted, request.Owner, request.Evidence, "route-set atomically committed and candidate serving", now); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return FinalizeM4ServingResult{}, fmt.Errorf("%w: FinalizeM4Serving: %v", ErrOutcomeUnknown, err)
	}
	rollout.Phase = M4RolloutRouteCommitted
	rollout.Evidence = append(rollout.Evidence, request.Evidence...)
	routeSet.State = "current"
	return FinalizeM4ServingResult{Coordinator: rollout, RouteSet: routeSet}, nil
}

func m4ServingID(prefix string, parts ...string) domain.ID {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(part))
	}
	return domain.ID(prefix + "_" + hex.EncodeToString(h.Sum(nil))[:32])
}

func nullableM4PositiveInt(value int) any {
	if value <= 0 {
		return nil
	}
	return value
}

func m4JSONEquivalent(left, right []byte) bool {
	var l, r any
	if json.Unmarshal(left, &l) != nil || json.Unmarshal(right, &r) != nil {
		return false
	}
	lb, _ := json.Marshal(l)
	rb, _ := json.Marshal(r)
	return string(lb) == string(rb)
}

func (s *Store) StageM4RouteSet(ctx context.Context, value M4StagedRouteSet, owner string, now time.Time) (M4StagedRouteSet, bool, error) {
	if err := s.requireDB(); err != nil {
		return M4StagedRouteSet{}, false, err
	}
	if value.OperationID.Empty() || value.ApplicationID.Empty() || value.SourceDeploymentID.Empty() || value.CandidateDeploymentID.Empty() || value.SourceDeploymentID == value.CandidateDeploymentID || !m4SHA256(value.OldDigest) || !m4SHA256(value.CandidateDigest) || value.ExpectedVersion < 0 || strings.TrimSpace(owner) == "" {
		return M4StagedRouteSet{}, false, domain.ValidationError("M4 staged route-set identity is invalid")
	}
	now = m4Now(s, now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return M4StagedRouteSet{}, false, err
	}
	rollback := func(e error) (M4StagedRouteSet, bool, error) { return M4StagedRouteSet{}, false, rollbackTx(tx, e) }
	var digest string
	err = tx.QueryRowContext(ctx, `SELECT candidate_digest FROM m4_rollout_route_sets WHERE rollout_operation_id=$1 FOR UPDATE`, value.OperationID.String()).Scan(&digest)
	if err == nil {
		if digest != value.CandidateDigest {
			return rollback(domain.NewError(domain.ErrConflict, "staged route-set identity conflicts"))
		}
		if err := tx.Commit(); err != nil {
			return M4StagedRouteSet{}, false, err
		}
		return value, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return rollback(err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO m4_rollout_route_sets(rollout_operation_id,application_id,source_deployment_id,candidate_deployment_id,old_digest,candidate_digest,expected_version,state,lease_owner,lease_until,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,'staged',$8,$9,$10,$10)`, value.OperationID.String(), value.ApplicationID.String(), value.SourceDeploymentID.String(), value.CandidateDeploymentID.String(), value.OldDigest, value.CandidateDigest, value.ExpectedVersion, owner, now.Add(30*time.Second), now); err != nil {
		return rollback(err)
	}
	for _, e := range value.Entries {
		if e.RouteID.Empty() || e.OldDeploymentID != value.SourceDeploymentID || e.CandidateDeployment != value.CandidateDeploymentID || e.OldPortLeaseID.Empty() || e.OldPointerRevision < 1 || e.CandidatePort < 0 || e.CandidatePort > 65535 || strings.TrimSpace(e.ServiceName) == "" {
			return rollback(domain.ValidationError("M4 staged route-set entry is invalid"))
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO m4_rollout_route_set_entries(rollout_operation_id,route_id,service_name,host,path_prefix,certificate_reference_id,old_deployment_id,old_port_lease_id,old_pointer_revision,candidate_deployment_id,candidate_port) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, value.OperationID.String(), e.RouteID.String(), e.ServiceName, e.Host, e.Path, nullableM4ID(e.CertificateID), e.OldDeploymentID.String(), e.OldPortLeaseID.String(), e.OldPointerRevision, e.CandidateDeployment.String(), nullableM4PositiveInt(e.CandidatePort)); err != nil {
			return rollback(err)
		}
	}
	if err = tx.Commit(); err != nil {
		return M4StagedRouteSet{}, false, err
	}
	value.State = "staged"
	return value, false, nil
}

func (s *Store) MarkM4RouteSetObserved(ctx context.Context, operationID domain.ID, owner string, evidence []domain.EvidenceRef, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	if operationID.Empty() || strings.TrimSpace(owner) == "" {
		return domain.ValidationError("M4 staged route-set observation is invalid")
	}
	if evidence == nil {
		evidence = []domain.EvidenceRef{}
	}
	encoded, _ := json.Marshal(evidence)
	now = m4Now(s, now)
	result, err := s.db.ExecContext(ctx, `UPDATE m4_rollout_route_sets SET state='observed',observe_evidence=$1::jsonb,updated_at=$2 WHERE rollout_operation_id=$3 AND state IN ('staged','loaded') AND lease_owner=$4 AND lease_until>$2`, encoded, now, operationID.String(), owner)
	if err != nil {
		return err
	}
	return requireOneTaskMutation(result)
}
func (s *Store) DiscardM4RouteSet(ctx context.Context, operationID domain.ID, owner, reason string, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	now = m4Now(s, now)
	result, err := s.db.ExecContext(ctx, `UPDATE m4_rollout_route_sets SET state='discarded',failure_reason=$1,lease_owner=NULL,lease_until=NULL,updated_at=$2 WHERE rollout_operation_id=$3 AND state NOT IN ('current','discarded') AND lease_owner=$4`, foundation.RedactText(reason), now, operationID.String(), owner)
	if err != nil {
		return err
	}
	return requireOneTaskMutation(result)
}

func (s *Store) GetM4StagedRouteSet(ctx context.Context, operationID domain.ID) (M4StagedRouteSet, error) {
	if err := s.requireDB(); err != nil {
		return M4StagedRouteSet{}, err
	}
	var value M4StagedRouteSet
	err := s.db.QueryRowContext(ctx, `SELECT rollout_operation_id,application_id,source_deployment_id,candidate_deployment_id,old_digest,candidate_digest,expected_version,state FROM m4_rollout_route_sets WHERE rollout_operation_id=$1`, operationID.String()).Scan(&value.OperationID, &value.ApplicationID, &value.SourceDeploymentID, &value.CandidateDeploymentID, &value.OldDigest, &value.CandidateDigest, &value.ExpectedVersion, &value.State)
	if errors.Is(err, sql.ErrNoRows) {
		return M4StagedRouteSet{}, ErrNotFound
	}
	if err != nil {
		return M4StagedRouteSet{}, err
	}
	entries, err := s.ReadM4StagedRouteEntries(ctx, operationID)
	if err != nil {
		return M4StagedRouteSet{}, err
	}
	value.Entries = entries
	return value, nil
}

func (s *Store) ReadM4StagedRouteEntries(ctx context.Context, operationID domain.ID) ([]M4StagedRouteEntry, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT route_id,service_name,host,path_prefix,COALESCE(certificate_reference_id,''),old_deployment_id,old_port_lease_id,old_pointer_revision,candidate_deployment_id,candidate_port FROM m4_rollout_route_set_entries WHERE rollout_operation_id=$1 ORDER BY host,path_prefix,route_id`, operationID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []M4StagedRouteEntry{}
	for rows.Next() {
		var item M4StagedRouteEntry
		var candidatePort sql.NullInt64
		if err := rows.Scan(&item.RouteID, &item.ServiceName, &item.Host, &item.Path, &item.CertificateID, &item.OldDeploymentID, &item.OldPortLeaseID, &item.OldPointerRevision, &item.CandidateDeployment, &candidatePort); err != nil {
			return nil, err
		}
		if candidatePort.Valid {
			item.CandidatePort = int(candidatePort.Int64)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) ClaimM4StagedRouteSet(ctx context.Context, operationID domain.ID, owner string, now time.Time, duration time.Duration) (M4StagedRouteSet, error) {
	if err := s.requireDB(); err != nil {
		return M4StagedRouteSet{}, err
	}
	if operationID.Empty() || strings.TrimSpace(owner) == "" || duration <= 0 {
		return M4StagedRouteSet{}, domain.ValidationError("M4 staged route-set lease is invalid")
	}
	now = m4Now(s, now)
	until := now.Add(duration)
	result, err := s.db.ExecContext(ctx, `UPDATE m4_rollout_route_sets SET lease_owner=$1,lease_until=$2,updated_at=$3 WHERE rollout_operation_id=$4 AND state NOT IN ('current','discarded') AND (lease_until IS NULL OR lease_until <= $3 OR lease_owner=$1)`, owner, until, now, operationID.String())
	if err != nil {
		return M4StagedRouteSet{}, err
	}
	if err := requireOneTaskMutation(result); err != nil {
		return M4StagedRouteSet{}, ErrLeaseLost
	}
	return s.GetM4StagedRouteSet(ctx, operationID)
}

// RenewM4Rollout extends only the active owner's lease. A stale reconciler
// cannot keep a coordinator alive after another worker has taken it over.
func (s *Store) RenewM4Rollout(ctx context.Context, operationID domain.ID, owner string, now time.Time, duration time.Duration) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	if operationID.Empty() || strings.TrimSpace(owner) == "" || duration <= 0 {
		return domain.ValidationError("M4 rollout renewal is invalid")
	}
	now = m4Now(s, now)
	until := now.Add(duration)
	result, err := s.db.ExecContext(ctx, `UPDATE m4_rollout_coordinations SET lease_until=$1,updated_at=$2 WHERE operation_id=$3 AND lease_owner=$4 AND lease_until>$2 AND phase NOT IN ('completed','failed','rolled_back')`, until, now, operationID.String(), owner)
	if err != nil {
		return err
	}
	return requireOneTaskMutation(result)
}

func (s *Store) ListRecoverableM4Rollouts(ctx context.Context, limit int) ([]M4RolloutCoordinator, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 100 {
		return nil, domain.ValidationError("M4 rollout recovery limit is invalid")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT operation_id FROM m4_rollout_coordinations WHERE phase NOT IN ('completed','failed','rolled_back') ORDER BY updated_at,operation_id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]M4RolloutCoordinator, 0, limit)
	for rows.Next() {
		var id domain.ID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		item, found, err := loadM4Rollout(ctx, s.db, id)
		if err != nil {
			return nil, err
		}
		if found {
			result = append(result, item)
		}
	}
	return result, rows.Err()
}

func (s *Store) FailM4Rollout(ctx context.Context, operationID domain.ID, owner string, from M4RolloutPhase, evidence []domain.EvidenceRef, reason string, now time.Time) (M4RolloutCoordinator, error) {
	return s.AdvanceM4Rollout(ctx, AdvanceM4RolloutRequest{OperationID: operationID, Owner: owner, From: from, To: M4RolloutFailed, Evidence: evidence, Reason: reason, Now: now})
}

func evidenceRefIDs(refs []domain.EvidenceRef) []string {
	result := make([]string, 0, len(refs))
	for _, ref := range refs {
		if !ref.ID.Empty() {
			result = append(result, ref.ID.String())
		}
	}
	return result
}

func (s *Store) CompleteM4Rollout(ctx context.Context, operationID domain.ID, owner string, from M4RolloutPhase, evidence []domain.EvidenceRef, now time.Time) (M4RolloutCoordinator, error) {
	return s.AdvanceM4Rollout(ctx, AdvanceM4RolloutRequest{OperationID: operationID, Owner: owner, From: from, To: M4RolloutCompleted, Evidence: evidence, Reason: "old deployment retirement completed", Now: now})
}

func (s *Store) CreateM4Rollout(ctx context.Context, request CreateM4RolloutRequest) (M4RolloutCoordinator, bool, error) {
	if err := s.requireDB(); err != nil {
		return M4RolloutCoordinator{}, false, err
	}
	r := request.Coordinator
	r.Phase = M4RolloutCandidateRequested
	r.CreatedAt = m4Now(s, r.CreatedAt)
	r.UpdatedAt = r.CreatedAt
	if err := r.Validate(); err != nil {
		return M4RolloutCoordinator{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return M4RolloutCoordinator{}, false, err
	}
	rollback := func(e error) (M4RolloutCoordinator, bool, error) {
		return M4RolloutCoordinator{}, false, rollbackTx(tx, e)
	}
	existing, found, err := loadM4RolloutTx(ctx, tx, r.OperationID, true)
	if err != nil {
		return rollback(err)
	}
	if found {
		if existing.ApplicationID != r.ApplicationID || existing.EnvironmentID != r.EnvironmentID || existing.SourceDeploymentID != r.SourceDeploymentID || existing.CandidateDeploymentID != r.CandidateDeploymentID || existing.RouteSetDigest != r.RouteSetDigest || existing.ExpectedRouteSetVersion != r.ExpectedRouteSetVersion {
			return rollback(domain.NewError(domain.ErrConflict, "M4 rollout operation identity conflicts"))
		}
		if err := tx.Commit(); err != nil {
			return M4RolloutCoordinator{}, false, fmt.Errorf("%w: replay M4 rollout: %v", ErrOutcomeUnknown, err)
		}
		return existing, true, nil
	}
	evidence, _ := json.Marshal(r.Evidence)
	if _, err := tx.ExecContext(ctx, `INSERT INTO m4_rollout_coordinations(operation_id,application_id,environment_id,source_deployment_id,candidate_deployment_id,replacement_task_id,phase,route_set_digest,expected_route_set_version,evidence,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$11)`, r.OperationID.String(), r.ApplicationID.String(), r.EnvironmentID.String(), r.SourceDeploymentID.String(), r.CandidateDeploymentID.String(), nullableM4ID(r.ReplacementTaskID), string(r.Phase), r.RouteSetDigest, r.ExpectedRouteSetVersion, evidence, r.CreatedAt); err != nil {
		return rollback(mapM4RolloutInsertError(err))
	}
	if err := appendM4RolloutEventTx(ctx, tx, r.OperationID, 1, r.Phase, request.Actor, nil, request.Reason, r.CreatedAt); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return M4RolloutCoordinator{}, false, fmt.Errorf("%w: create M4 rollout: %v", ErrOutcomeUnknown, err)
	}
	return r, false, nil
}

func (s *Store) GetM4Rollout(ctx context.Context, operationID domain.ID) (M4RolloutCoordinator, error) {
	if err := s.requireDB(); err != nil {
		return M4RolloutCoordinator{}, err
	}
	r, found, err := loadM4Rollout(ctx, s.db, operationID)
	if err != nil {
		return M4RolloutCoordinator{}, err
	}
	if !found {
		return M4RolloutCoordinator{}, ErrNotFound
	}
	return r, nil
}

func (s *Store) ClaimM4Rollouts(ctx context.Context, request ClaimM4RolloutRequest) ([]M4RolloutCoordinator, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(request.Owner) == "" || request.Duration <= 0 || request.Limit < 1 || request.Limit > 100 {
		return nil, domain.ValidationError("M4 rollout claim is invalid")
	}
	now := m4Now(s, request.Now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	rollback := func(e error) ([]M4RolloutCoordinator, error) { return nil, rollbackTx(tx, e) }
	rows, err := tx.QueryContext(ctx, `SELECT operation_id FROM m4_rollout_coordinations WHERE phase NOT IN ('completed','failed','rolled_back') AND (lease_until IS NULL OR lease_until <= $1) ORDER BY updated_at,operation_id LIMIT $2 FOR UPDATE SKIP LOCKED`, now, request.Limit)
	if err != nil {
		return rollback(err)
	}
	ids := make([]domain.ID, 0, request.Limit)
	for rows.Next() {
		var id domain.ID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return rollback(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return rollback(err)
	}
	if err := rows.Close(); err != nil {
		return rollback(err)
	}
	var result []M4RolloutCoordinator
	for _, id := range ids {
		r, found, err := loadM4RolloutTx(ctx, tx, id, true)
		if err != nil || !found {
			return rollback(err)
		}
		until := now.Add(request.Duration)
		if _, err := tx.ExecContext(ctx, `UPDATE m4_rollout_coordinations SET lease_owner=$1,lease_until=$2,attempt=attempt+1,updated_at=$3 WHERE operation_id=$4`, request.Owner, until, now, id.String()); err != nil {
			return rollback(err)
		}
		r.LeaseOwner = request.Owner
		r.LeaseUntil = &until
		r.Attempt++
		r.UpdatedAt = now
		result = append(result, r)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("%w: claim M4 rollouts: %v", ErrOutcomeUnknown, err)
	}
	return result, nil
}

func (s *Store) AdvanceM4Rollout(ctx context.Context, request AdvanceM4RolloutRequest) (M4RolloutCoordinator, error) {
	if err := s.requireDB(); err != nil {
		return M4RolloutCoordinator{}, err
	}
	now := m4Now(s, request.Now)
	if strings.TrimSpace(request.Owner) == "" || !validM4RolloutTransition(request.From, request.To) {
		return M4RolloutCoordinator{}, domain.ValidationError("M4 rollout transition is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return M4RolloutCoordinator{}, err
	}
	rollback := func(e error) (M4RolloutCoordinator, error) { return M4RolloutCoordinator{}, rollbackTx(tx, e) }
	r, found, err := loadM4RolloutTx(ctx, tx, request.OperationID, true)
	if err != nil {
		return rollback(err)
	}
	if !found {
		return rollback(ErrNotFound)
	}
	if r.LeaseOwner != request.Owner || r.LeaseUntil == nil || !r.LeaseUntil.After(now) {
		return rollback(ErrLeaseLost)
	}
	if r.Phase == request.To {
		if err := tx.Commit(); err != nil {
			return M4RolloutCoordinator{}, err
		}
		return r, nil
	}
	if r.Phase != request.From {
		return rollback(domain.NewError(domain.ErrConflict, "M4 rollout phase is out of order"))
	}
	if request.To.terminal() {
		r.CompletedAt = &now
		r.LeaseOwner = ""
		r.LeaseUntil = nil
	}
	r.Phase = request.To
	r.UpdatedAt = now
	r.Evidence = append(r.Evidence, request.Evidence...)
	if request.To == M4RolloutFailed {
		r.FailureReason = foundation.RedactText(request.Reason)
	}
	if err := r.Validate(); err != nil {
		return rollback(err)
	}
	evidence, _ := json.Marshal(r.Evidence)
	if _, err := tx.ExecContext(ctx, `UPDATE m4_rollout_coordinations SET phase=$1,evidence=$2::jsonb,failure_reason=$3,lease_owner=$4,lease_until=$5,completed_at=$6,updated_at=$7 WHERE operation_id=$8`, string(r.Phase), evidence, nullableString(r.FailureReason), nullableString(r.LeaseOwner), r.LeaseUntil, r.CompletedAt, now, r.OperationID.String()); err != nil {
		return rollback(err)
	}
	if request.To == M4RolloutFailed {
		operation, deploymentID, version, err := loadOperationTx(ctx, tx, r.OperationID, true)
		if err != nil {
			return rollback(err)
		}
		if operation.Status != domain.OperationFailed {
			if err := operation.Transition(domain.OperationFailed, now); err != nil {
				return rollback(err)
			}
			operation.FailureReason = r.FailureReason
			if err := execExactlyOneTx(ctx, tx, `UPDATE operations SET state='failed',failure_reason=$1,version=version+1,updated_at=$2 WHERE id=$3 AND version=$4`, nullableString(operation.FailureReason), now, operation.ID.String(), version); err != nil {
				return rollback(err)
			}
		}
		var candidate domain.Deployment
		var candidateState string
		if err := tx.QueryRowContext(ctx, `SELECT d.id,e.application_id,d.environment_id,d.release_id,d.state,d.created_at,d.updated_at FROM deployments d JOIN environments e ON e.id=d.environment_id WHERE d.id=$1`, deploymentID.String()).Scan(&candidate.ID, &candidate.ApplicationID, &candidate.EnvironmentID, &candidate.ReleaseID, &candidateState, &candidate.CreatedAt, &candidate.UpdatedAt); err != nil {
			return rollback(err)
		}
		candidate.Status = domain.DeploymentStatus(candidateState)
		resultPayload, _ := json.Marshal(map[string]any{"operation": operation, "action": string(operation.Type), "scope": "application", "release_id": candidate.ReleaseID, "deployment": candidate, "rollback_data": false, "data_notice": "Application code/configuration only; persistent data is not rolled back.", "kept_last_usable": true, "evidence": request.Evidence})
		if _, err := tx.ExecContext(ctx, `UPDATE m4_operation_requests SET result=$1::jsonb,completed_at=$2 WHERE operation_id=$3 AND result IS NULL`, resultPayload, now, operation.ID.String()); err != nil {
			return rollback(err)
		}
		if _, err := s.appendControllerEventTx(ctx, tx, operation, "operation.failed", string(domain.PublishFailed), "rollout failed; previous deployment remains serving", evidenceRefIDs(request.Evidence), now); err != nil {
			return rollback(err)
		}
		// A rollout that exhausted its automated pre-commit recovery is now an
		// operator-visible escalation. Persist it after the occurrence in the
		// same transaction so Webhook consumers observe a stable
		// failure->escalation order and never see escalation without the
		// authoritative failed operation fact.
		if _, err := s.appendControllerEventTx(ctx, tx, operation, "operation.escalated", string(domain.PublishFailed), "automated rollout recovery exhausted; previous deployment remains serving", evidenceRefIDs(request.Evidence), now); err != nil {
			return rollback(err)
		}
	}
	if err := appendM4RolloutEventTx(ctx, tx, r.OperationID, 0, r.Phase, request.Owner, request.Evidence, request.Reason, now); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return M4RolloutCoordinator{}, fmt.Errorf("%w: advance M4 rollout: %v", ErrOutcomeUnknown, err)
	}
	return r, nil
}

func loadM4Rollout(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, id domain.ID) (M4RolloutCoordinator, bool, error) {
	return loadM4RolloutRow(q.QueryRowContext(ctx, `SELECT operation_id,application_id,environment_id,source_deployment_id,candidate_deployment_id,COALESCE(replacement_task_id,''),COALESCE(candidate_cleanup_task_id,''),COALESCE(old_retirement_task_id,''),phase,route_set_digest,expected_route_set_version,attempt,COALESCE(lease_owner,''),lease_until,observation_deadline,COALESCE(failure_reason,''),COALESCE(candidate_cleanup_reason,''),evidence,created_at,updated_at,completed_at FROM m4_rollout_coordinations WHERE operation_id=$1`, id.String()))
}
func loadM4RolloutTx(ctx context.Context, tx *sql.Tx, id domain.ID, lock bool) (M4RolloutCoordinator, bool, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	return loadM4RolloutRow(tx.QueryRowContext(ctx, `SELECT operation_id,application_id,environment_id,source_deployment_id,candidate_deployment_id,COALESCE(replacement_task_id,''),COALESCE(candidate_cleanup_task_id,''),COALESCE(old_retirement_task_id,''),phase,route_set_digest,expected_route_set_version,attempt,COALESCE(lease_owner,''),lease_until,observation_deadline,COALESCE(failure_reason,''),COALESCE(candidate_cleanup_reason,''),evidence,created_at,updated_at,completed_at FROM m4_rollout_coordinations WHERE operation_id=$1`+suffix, id.String()))
}
func loadM4RolloutRow(row *sql.Row) (M4RolloutCoordinator, bool, error) {
	var r M4RolloutCoordinator
	var lease, deadline, completed sql.NullTime
	var raw []byte
	err := row.Scan(&r.OperationID, &r.ApplicationID, &r.EnvironmentID, &r.SourceDeploymentID, &r.CandidateDeploymentID, &r.ReplacementTaskID, &r.CandidateCleanupTaskID, &r.OldRetirementTaskID, &r.Phase, &r.RouteSetDigest, &r.ExpectedRouteSetVersion, &r.Attempt, &r.LeaseOwner, &lease, &deadline, &r.FailureReason, &r.CandidateCleanupReason, &raw, &r.CreatedAt, &r.UpdatedAt, &completed)
	if errors.Is(err, sql.ErrNoRows) {
		return M4RolloutCoordinator{}, false, nil
	}
	if err != nil {
		return M4RolloutCoordinator{}, false, err
	}
	if lease.Valid {
		v := lease.Time.UTC()
		r.LeaseUntil = &v
	}
	if deadline.Valid {
		v := deadline.Time.UTC()
		r.ObservationDeadline = &v
	}
	if completed.Valid {
		v := completed.Time.UTC()
		r.CompletedAt = &v
	}
	if json.Unmarshal(raw, &r.Evidence) != nil {
		return M4RolloutCoordinator{}, false, ErrOutcomeUnknown
	}
	r.CreatedAt = r.CreatedAt.UTC()
	r.UpdatedAt = r.UpdatedAt.UTC()
	if err := r.Validate(); err != nil {
		return M4RolloutCoordinator{}, false, err
	}
	return r, true, nil
}
func appendM4RolloutEventTx(ctx context.Context, tx *sql.Tx, operationID domain.ID, sequence int64, phase M4RolloutPhase, actor string, evidence []domain.EvidenceRef, reason string, now time.Time) error {
	if sequence == 0 {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "m4-rollout-events:"+operationID.String()); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM m4_rollout_phase_events WHERE operation_id=$1`, operationID.String()).Scan(&sequence); err != nil {
			return err
		}
	}
	if evidence == nil {
		evidence = []domain.EvidenceRef{}
	}
	encoded, _ := json.Marshal(evidence)
	_, err := tx.ExecContext(ctx, `INSERT INTO m4_rollout_phase_events(operation_id,sequence,phase,actor,evidence,reason,created_at) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7)`, operationID.String(), sequence, string(phase), actor, encoded, foundation.RedactText(reason), now)
	return err
}
func mapM4RolloutInsertError(err error) error {
	if strings.Contains(err.Error(), "m4_rollout_coordinations_active_environment_uidx") {
		return domain.NewError(domain.ErrConflict, "an M4 rollout is already active for this environment")
	}
	return err
}
