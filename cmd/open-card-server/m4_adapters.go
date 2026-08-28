package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
	"github.com/open-card/open-card/internal/observability"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// m4PostgresAdapter is the M4 boundary between the pure operations controller
// and PostgreSQL. Its two controller methods are transactionally responsible
// for operation state, audit-chain evidence, and outbox events; providers and
// browser input never become facts directly.
type m4PostgresAdapter struct {
	store   *postgres.Store
	logs    *observability.LogStore
	metrics *observability.SQLMetricStore
	clock   func() time.Time
}

var _ controllers.M4OperationStore = (*m4PostgresAdapter)(nil)
var _ m4OperationsViewReader = (*m4PostgresAdapter)(nil)
var _ m4DefaultEnvironmentReader = (*m4PostgresAdapter)(nil)
var _ controllers.AgentEvidenceProjector = (*m4PostgresAdapter)(nil)
var _ m4WebhookConfigurationStore = (*m4PostgresAdapter)(nil)

type m4AtomicRolloutPlan struct {
	Candidate   domain.Deployment
	TaskID      domain.ID
	TaskPayload json.RawMessage
	Coordinator postgres.M4RolloutCoordinator
	RouteSet    postgres.M4StagedRouteSet
}

func (a *m4PostgresAdapter) buildM4AtomicRolloutPlan(ctx context.Context, request controllers.M4OperationAcquire, operation domain.Operation, environment controllers.M4Environment, now time.Time) (m4AtomicRolloutPlan, error) {
	targetRelease := environment.CurrentRelease
	action := "redeploy"
	if request.Type == domain.OperationRollback {
		if environment.PreviousSuccessful == nil {
			return m4AtomicRolloutPlan{}, controllers.ErrM4NoRollbackTarget
		}
		targetRelease = environment.PreviousSuccessful.Release
		action = "rollback"
	}
	candidate := domain.Deployment{ID: m4AdapterID("deployment", operation.ID.String()+":"+action+":"+targetRelease.ID.String()), ApplicationID: request.ApplicationID, EnvironmentID: request.EnvironmentID, ReleaseID: targetRelease.ID, Status: domain.DeploymentPending, CreatedAt: now, UpdatedAt: now}
	if err := candidate.Validate(); err != nil {
		return m4AtomicRolloutPlan{}, err
	}
	spec, _, err := a.store.GetM2ReleaseRuntimeSpec(ctx, targetRelease.ID)
	if err != nil {
		return m4AtomicRolloutPlan{}, err
	}
	spec.EnvironmentID = request.EnvironmentID
	spec.Rollout = contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutRolling, PreviousDeploymentID: environment.CurrentDeployment.ID, PreserveOldUntilHealthy: true, DeferOldTeardown: true}
	op := contracts.OperationContext{IdempotencyKey: operation.IdempotencyKey, Deadline: now.Add(2 * time.Minute), Actor: "m4-operations-controller"}
	var kind v1.TaskKind
	var parameters []byte
	if request.Type == domain.OperationRollback {
		kind = v1.TaskRollback
		parameters, err = m4GroupParameters("service_group.rollback", contracts.RollbackGroupRequest{DeploymentID: environment.CurrentDeployment.ID, TargetDeploymentID: candidate.ID, Target: spec, Operation: op})
	} else {
		kind = v1.TaskDeploy
		parameters, err = m4GroupParameters("service_group.redeploy", contracts.DeployGroupRequest{DeploymentID: candidate.ID, Spec: spec, Operation: op, ForceRecreate: true})
	}
	if err != nil {
		return m4AtomicRolloutPlan{}, err
	}
	taskID := m4AdapterID("task", operation.ID.String()+":"+action)
	taskPayload, err := json.Marshal(controllers.AgentTaskSpec{Kind: kind, Parameters: parameters})
	if err != nil {
		return m4AtomicRolloutPlan{}, err
	}
	desired, err := a.store.ListDesiredRoutes(ctx)
	if err != nil {
		return m4AtomicRolloutPlan{}, err
	}
	entries := make([]postgres.M4StagedRouteEntry, 0)
	oldIdentity, candidateIdentity := make([]string, 0), make([]string, 0)
	var expectedVersion int64
	for _, item := range desired {
		if item.Route.ApplicationID != request.ApplicationID || item.Pointer == nil || item.Lease == nil || item.Lease.ReleasedAt != nil || item.Pointer.DeploymentID != environment.CurrentDeployment.ID {
			continue
		}
		entry := postgres.M4StagedRouteEntry{RouteID: item.Route.ID, ServiceName: item.Route.ServiceName, Host: item.Route.Host, Path: item.Route.Path, CertificateID: item.CertificateID, OldDeploymentID: environment.CurrentDeployment.ID, OldPortLeaseID: item.Pointer.PortLeaseID, OldPointerRevision: item.Pointer.Revision, CandidateDeployment: candidate.ID}
		entries = append(entries, entry)
		if item.Pointer.Revision > expectedVersion {
			expectedVersion = item.Pointer.Revision
		}
		oldIdentity = append(oldIdentity, item.Route.ID.String(), environment.CurrentDeployment.ID.String(), item.Pointer.PortLeaseID.String(), fmt.Sprint(item.Pointer.Revision), item.Route.ServiceName)
		candidateIdentity = append(candidateIdentity, item.Route.ID.String(), candidate.ID.String(), item.Route.ServiceName)
	}
	oldDigest := m4AdapterDigest(strings.Join(oldIdentity, "\x00"))
	candidateDigest := m4AdapterDigest(strings.Join(candidateIdentity, "\x00"))
	coordinator := postgres.M4RolloutCoordinator{OperationID: operation.ID, ApplicationID: request.ApplicationID, EnvironmentID: request.EnvironmentID, SourceDeploymentID: environment.CurrentDeployment.ID, CandidateDeploymentID: candidate.ID, ReplacementTaskID: taskID, Phase: postgres.M4RolloutCandidateRequested, RouteSetDigest: candidateDigest, ExpectedRouteSetVersion: expectedVersion, CreatedAt: now, UpdatedAt: now}
	routeSet := postgres.M4StagedRouteSet{OperationID: operation.ID, ApplicationID: request.ApplicationID, SourceDeploymentID: environment.CurrentDeployment.ID, CandidateDeploymentID: candidate.ID, OldDigest: oldDigest, CandidateDigest: candidateDigest, ExpectedVersion: expectedVersion, State: "staged", Entries: entries}
	return m4AtomicRolloutPlan{Candidate: candidate, TaskID: taskID, TaskPayload: taskPayload, Coordinator: coordinator, RouteSet: routeSet}, nil
}

func (a *m4PostgresAdapter) insertM4AtomicRolloutPlanTx(ctx context.Context, tx *sql.Tx, request controllers.M4OperationAcquire, operation domain.Operation, plan m4AtomicRolloutPlan, now time.Time) error {
	var oldRelease, oldState string
	if err := tx.QueryRowContext(ctx, `SELECT release_id,state FROM deployments WHERE id=$1 FOR SHARE`, plan.Coordinator.SourceDeploymentID.String()).Scan(&oldRelease, &oldState); err != nil {
		return err
	}
	if oldState != "serving" && oldState != "runtime_ready" && oldState != "degraded" {
		return domain.NewError(domain.ErrConflict, "current deployment is no longer usable")
	}
	if request.Type == domain.OperationRedeploy && oldRelease != plan.Candidate.ReleaseID.String() {
		return domain.NewError(domain.ErrConflict, "redeploy target is not the current release")
	}
	if request.Type == domain.OperationRollback {
		var previous string
		err := tx.QueryRowContext(ctx, `SELECT r.id FROM releases r WHERE r.application_id=$1 AND r.id<>$2 AND r.release_status='ready' AND EXISTS (SELECT 1 FROM deployments d JOIN environments e ON e.id=d.environment_id JOIN operations succeeded ON succeeded.deployment_id=d.id WHERE d.release_id=r.id AND e.application_id=$1 AND succeeded.operation_type IN ('deploy','redeploy','rollback') AND succeeded.state IN ('succeeded','rolled_back')) ORDER BY r.created_at DESC,r.id DESC LIMIT 1`, request.ApplicationID.String(), oldRelease).Scan(&previous)
		if errors.Is(err, sql.ErrNoRows) {
			return controllers.ErrM4NoRollbackTarget
		}
		if err != nil {
			return err
		}
		if previous != plan.Candidate.ReleaseID.String() {
			return domain.NewError(domain.ErrConflict, "rollback target is no longer the previous successful release")
		}
	}
	for _, entry := range plan.RouteSet.Entries {
		var deployment, lease string
		var revision int64
		if err := tx.QueryRowContext(ctx, `SELECT deployment_id,port_lease_id,revision FROM m3_route_pointers WHERE route_id=$1 FOR SHARE`, entry.RouteID.String()).Scan(&deployment, &lease, &revision); err != nil {
			return err
		}
		if deployment != entry.OldDeploymentID.String() || lease != entry.OldPortLeaseID.String() || revision != entry.OldPointerRevision {
			return postgres.ErrRoutePointerConflict
		}
	}
	redactedTask, err := foundation.RedactJSON(plan.TaskPayload, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO task_leases(task_id,operation_id,attempt,max_attempts,state,payload,created_at,updated_at) VALUES($1,$2,0,3,'ready',$3::jsonb,$4,$4)`, plan.TaskID.String(), operation.ID.String(), redactedTask, now); err != nil {
		return err
	}
	evidenceJSON := `[]`
	if _, err := tx.ExecContext(ctx, `INSERT INTO m4_rollout_coordinations(operation_id,application_id,environment_id,source_deployment_id,candidate_deployment_id,replacement_task_id,phase,route_set_digest,expected_route_set_version,evidence,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'candidate_requested',$7,$8,$9::jsonb,$10,$10)`, operation.ID.String(), request.ApplicationID.String(), request.EnvironmentID.String(), plan.Coordinator.SourceDeploymentID.String(), plan.Candidate.ID.String(), plan.TaskID.String(), plan.Coordinator.RouteSetDigest, plan.Coordinator.ExpectedRouteSetVersion, evidenceJSON, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO m4_rollout_phase_events(operation_id,sequence,phase,actor,evidence,reason,created_at) VALUES($1,1,'candidate_requested',$2,'[]'::jsonb,$3,$4)`, operation.ID.String(), request.Actor, foundation.RedactText(request.Reason), now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO m4_rollout_route_sets(rollout_operation_id,application_id,source_deployment_id,candidate_deployment_id,old_digest,candidate_digest,expected_version,state,target_release_id,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,'staged',$8,$9,$9)`, operation.ID.String(), request.ApplicationID.String(), plan.Coordinator.SourceDeploymentID.String(), plan.Candidate.ID.String(), plan.RouteSet.OldDigest, plan.RouteSet.CandidateDigest, plan.RouteSet.ExpectedVersion, plan.Candidate.ReleaseID.String(), now); err != nil {
		return err
	}
	for _, entry := range plan.RouteSet.Entries {
		if _, err := tx.ExecContext(ctx, `INSERT INTO m4_rollout_route_set_entries(rollout_operation_id,route_id,service_name,host,path_prefix,certificate_reference_id,old_deployment_id,old_port_lease_id,old_pointer_revision,candidate_deployment_id,candidate_port) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL)`, operation.ID.String(), entry.RouteID.String(), entry.ServiceName, entry.Host, entry.Path, nullableM4Failure(entry.CertificateID.String()), entry.OldDeploymentID.String(), entry.OldPortLeaseID.String(), entry.OldPointerRevision, entry.CandidateDeployment.String()); err != nil {
			return err
		}
	}
	var previous sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT record_hash FROM audit_evidence ORDER BY sequence DESC LIMIT 1`).Scan(&previous); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	recordHash := m4AdapterDigest(previous.String + "\x00" + request.RequestDigest + "\x00" + now.Format(time.RFC3339Nano))
	auditID := m4AdapterID("audit", operation.ID.String()+":requested")
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_evidence(id,actor_type,actor_id,action,reason,input_digest,result,evidence_refs,previous_hash,record_hash,created_at) VALUES($1,'user',$2,$3,$4,$5,'pending','[]'::jsonb,$6,$7,$8)`, auditID.String(), request.Actor, "operations."+string(request.Type)+".requested", foundation.RedactText(request.Reason), request.RequestDigest, nullableM4Failure(previous.String), recordHash, now); err != nil {
		return err
	}
	event := application.Event{SchemaVersion: "1.1", OperationID: operation.ID.String(), ApplicationID: request.ApplicationID.String(), Kind: "operations." + string(request.Type) + ".requested", Status: "running", Message: string(request.Type) + " rollout plan requested", OccurredAt: now}
	return appendM4OutboxTx(ctx, tx, event, now)
}

func (a *m4PostgresAdapter) now() time.Time {
	if a.clock == nil {
		return time.Now().UTC()
	}
	return a.clock().UTC()
}

func (a *m4PostgresAdapter) GetDefaultEnvironmentID(ctx context.Context, applicationID domain.ID) (domain.ID, error) {
	return a.store.GetDefaultEnvironmentID(ctx, applicationID)
}

func (a *m4PostgresAdapter) ConfigureM4Webhook(ctx context.Context, applicationID domain.ID, endpointURL string, reference domain.SecretReference, eventTypes []string, _ string) (controllers.M4WebhookEndpoint, error) {
	if a == nil || a.store == nil || applicationID.Empty() {
		return controllers.M4WebhookEndpoint{}, domain.ValidationError("M4 webhook configuration store is unavailable")
	}
	if err := reference.Validate(); err != nil || !m4WebhookEventTypesAllowed(eventTypes) {
		return controllers.M4WebhookEndpoint{}, domain.ValidationError("M4 webhook configuration is invalid")
	}
	now := a.now()
	endpointID := m4AdapterID("webhook", applicationID.String()+"\x00"+strings.TrimSpace(endpointURL))
	endpoint := postgres.WebhookEndpoint{ID: endpointID, ApplicationID: applicationID, URL: strings.TrimSpace(endpointURL), SecretReferenceID: reference.ID, SecretName: reference.Name, SecretProvider: reference.Provider, SecretVersion: reference.Version, EventTypes: append([]string(nil), eventTypes...), Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := a.store.UpsertWebhookEndpoint(ctx, endpoint, now); err != nil {
		return controllers.M4WebhookEndpoint{}, err
	}
	return controllers.M4WebhookEndpoint{ID: endpoint.ID.String(), URL: endpoint.URL, Enabled: endpoint.Enabled, SecretRef: reference}, nil
}

func (a *m4PostgresAdapter) GetM4Webhook(ctx context.Context, applicationID, endpointID domain.ID) (controllers.M4WebhookEndpoint, error) {
	if a == nil || a.store == nil || applicationID.Empty() || endpointID.Empty() {
		return controllers.M4WebhookEndpoint{}, domain.ValidationError("M4 webhook identity is required")
	}
	endpoint, err := a.store.GetWebhookEndpoint(ctx, endpointID)
	if err != nil {
		return controllers.M4WebhookEndpoint{}, err
	}
	if endpoint.ApplicationID != applicationID || !endpoint.Enabled {
		return controllers.M4WebhookEndpoint{}, domain.NewError(domain.ErrForbidden, "webhook endpoint does not belong to this application")
	}
	reference := domain.SecretReference{ID: endpoint.SecretReferenceID, Name: endpoint.SecretName, Provider: endpoint.SecretProvider, Version: endpoint.SecretVersion}
	if err := reference.Validate(); err != nil {
		return controllers.M4WebhookEndpoint{}, err
	}
	return controllers.M4WebhookEndpoint{ID: endpoint.ID.String(), URL: endpoint.URL, Enabled: endpoint.Enabled, SecretRef: reference}, nil
}

func (a *m4PostgresAdapter) GetApplicationOperationsView(ctx context.Context, applicationID, environmentID domain.ID) (domain.ApplicationOperationsView, error) {
	environment, err := a.environment(ctx, applicationID, environmentID)
	if err != nil {
		return domain.ApplicationOperationsView{}, err
	}
	return a.viewFromEnvironment(ctx, environment)
}

func (a *m4PostgresAdapter) AcquireM4Operation(ctx context.Context, request controllers.M4OperationAcquire) (controllers.M4OperationReservation, error) {
	if a == nil || a.store == nil || a.store.DB() == nil {
		return controllers.M4OperationReservation{}, errors.New("M4 PostgreSQL store is unavailable")
	}
	if request.ApplicationID.Empty() || request.EnvironmentID.Empty() || strings.TrimSpace(request.IdempotencyKey) == "" || strings.TrimSpace(request.RequestDigest) == "" || strings.TrimSpace(request.ExpectedVersion) == "" {
		return controllers.M4OperationReservation{}, domain.ValidationError("M4 operation acquire identity is incomplete")
	}
	environment, err := a.environment(ctx, request.ApplicationID, request.EnvironmentID)
	if err != nil {
		return controllers.M4OperationReservation{}, err
	}
	now := request.Now
	if now.IsZero() {
		now = a.now()
	}
	operationID := m4AdapterID("op", request.ApplicationID.String()+"\x00"+request.EnvironmentID.String()+"\x00"+request.IdempotencyKey)
	operation := domain.Operation{ID: operationID, ApplicationID: request.ApplicationID, EnvironmentID: request.EnvironmentID, TargetRef: request.TargetRef, Type: request.Type, IdempotencyKey: request.IdempotencyKey, Status: domain.OperationRunning, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	if err := operation.Validate(); err != nil {
		return controllers.M4OperationReservation{}, err
	}
	var rolloutPlan *m4AtomicRolloutPlan
	if request.Type == domain.OperationRedeploy || request.Type == domain.OperationRollback {
		plan, err := a.buildM4AtomicRolloutPlan(ctx, request, operation, environment, now.UTC())
		if err != nil {
			return controllers.M4OperationReservation{}, err
		}
		rolloutPlan = &plan
	}
	tx, err := a.store.DB().BeginTx(ctx, nil)
	if err != nil {
		return controllers.M4OperationReservation{}, err
	}
	rollback := func(cause error) (controllers.M4OperationReservation, error) {
		_ = tx.Rollback()
		return controllers.M4OperationReservation{}, cause
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "open-card-m4-environment:"+request.EnvironmentID.String()); err != nil {
		return rollback(err)
	}
	storedOperation, storedDigest, storedResult, found, err := loadM4OperationTx(ctx, tx, request.EnvironmentID, request.IdempotencyKey)
	if err != nil {
		return rollback(err)
	}
	if found {
		if storedDigest != request.RequestDigest {
			return rollback(application.ErrIdempotencyConflict)
		}
		if storedResult != nil {
			if err := tx.Commit(); err != nil {
				return controllers.M4OperationReservation{}, err
			}
			return controllers.M4OperationReservation{Replay: storedResult}, nil
		}
		if storedOperation.Type == domain.OperationRedeploy || storedOperation.Type == domain.OperationRollback {
			var candidate domain.Deployment
			var state string
			if err := tx.QueryRowContext(ctx, `SELECT d.id,e.application_id,d.environment_id,d.release_id,d.state,d.created_at,d.updated_at FROM m4_rollout_coordinations rollout JOIN deployments d ON d.id=rollout.candidate_deployment_id JOIN environments e ON e.id=d.environment_id WHERE rollout.operation_id=$1`, storedOperation.ID.String()).Scan(&candidate.ID, &candidate.ApplicationID, &candidate.EnvironmentID, &candidate.ReleaseID, &state, &candidate.CreatedAt, &candidate.UpdatedAt); err != nil {
				return rollback(err)
			}
			candidate.Status = domain.DeploymentStatus(state)
			action := "redeploy"
			if storedOperation.Type == domain.OperationRollback {
				action = "rollback"
			}
			replay := controllers.M4OperationResult{Operation: storedOperation, Action: action, Scope: "application", ReleaseID: candidate.ReleaseID, Deployment: candidate, RollbackData: false, DataNotice: "Application code/configuration only; persistent data is not rolled back."}
			if err := tx.Commit(); err != nil {
				return controllers.M4OperationReservation{}, err
			}
			return controllers.M4OperationReservation{Replay: &replay}, nil
		}
		return rollback(controllers.ErrM4ActiveOperation)
	}
	if environment.FactVersion != request.ExpectedVersion {
		return rollback(domain.NewError(domain.ErrConflict, "operations facts changed; refresh before retrying"))
	}
	if err := preemptM4ObservationTx(ctx, tx, request.EnvironmentID, now.UTC()); err != nil {
		return rollback(err)
	}
	targetDeploymentID := environment.CurrentDeployment.ID
	if rolloutPlan != nil {
		targetDeploymentID = rolloutPlan.Candidate.ID
		if _, err := tx.ExecContext(ctx, `INSERT INTO deployments(id,environment_id,release_id,state,version,created_at,updated_at) VALUES($1,$2,$3,'pending',1,$4,$4)`, rolloutPlan.Candidate.ID.String(), rolloutPlan.Candidate.EnvironmentID.String(), rolloutPlan.Candidate.ReleaseID.String(), now.UTC()); err != nil {
			return rollback(err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'running',$7,$8,$8)`, operation.ID.String(), operation.ApplicationID.String(), operation.EnvironmentID.String(), targetDeploymentID.String(), string(operation.Type), operation.IdempotencyKey, operation.TargetRef, operation.CreatedAt); err != nil {
		var databaseError *pgconn.PgError
		if errors.As(err, &databaseError) && databaseError.Code == "23505" {
			return rollback(controllers.ErrM4ActiveOperation)
		}
		return rollback(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO m4_operation_requests(operation_id,request_digest,expected_fact_version,actor_id,reason,created_at) VALUES($1,$2,$3,$4,$5,$6)`, operation.ID.String(), request.RequestDigest, request.ExpectedVersion, request.Actor, request.Reason, operation.CreatedAt); err != nil {
		return rollback(err)
	}
	if rolloutPlan != nil {
		if err := a.insertM4AtomicRolloutPlanTx(ctx, tx, request, operation, *rolloutPlan, now.UTC()); err != nil {
			return rollback(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return controllers.M4OperationReservation{}, err
	}
	return controllers.M4OperationReservation{Operation: operation, Environment: environment}, nil
}

// preemptM4ObservationTx gives an explicit operator mutation priority over a
// background read-only observation that happens to hold the environment's
// single active-operation slot. The task and operation are cancelled in the
// same transaction that creates the user operation; late Agent events see a
// terminal operation and are acknowledged without changing facts. No runtime
// effect is cancelled because observe tasks are strictly read-only.
func preemptM4ObservationTx(ctx context.Context, tx *sql.Tx, environmentID domain.ID, now time.Time) error {
	var operationID, operationType string
	err := tx.QueryRowContext(ctx, `SELECT id,operation_type FROM operations WHERE environment_id=$1 AND state IN ('pending','leased','running','waiting','cancelling') ORDER BY created_at,id LIMIT 1 FOR UPDATE`, environmentID.String()).Scan(&operationID, &operationType)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if operationType != string(domain.OperationObserve) {
		return controllers.ErrM4ActiveOperation
	}
	reason := "background observation superseded by operator operation"
	if _, err := tx.ExecContext(ctx, `UPDATE task_leases SET state='cancelled',lease_owner=NULL,lease_until=NULL,last_error=$1,completed_at=$2,updated_at=$2 WHERE operation_id=$3 AND state IN ('ready','leased')`, reason, now, operationID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE operations SET state='cancelled',failure_reason=$1,version=version+1,updated_at=$2 WHERE id=$3 AND state IN ('pending','leased','running','waiting','cancelling')`, reason, now, operationID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return controllers.ErrM4ActiveOperation
	}
	return nil
}

func (a *m4PostgresAdapter) CommitM4Operation(ctx context.Context, commit controllers.M4OperationCommit) error {
	if a == nil || a.store == nil || a.store.DB() == nil {
		return errors.New("M4 PostgreSQL store is unavailable")
	}
	if err := commit.Operation.Validate(); err != nil {
		return err
	}
	if commit.Result.Operation.ID != commit.Operation.ID || commit.Result.Operation.Status != commit.Operation.Status {
		return domain.ValidationError("M4 commit result does not match operation")
	}
	resultJSON, err := json.Marshal(commit.Result)
	if err != nil {
		return err
	}
	now := a.now()
	tx, err := a.store.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	rollback := func(cause error) error { _ = tx.Rollback(); return cause }
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "open-card-m4-environment:"+commit.Operation.EnvironmentID.String()); err != nil {
		return rollback(err)
	}
	var currentState string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM operations WHERE id=$1 FOR UPDATE`, commit.Operation.ID.String()).Scan(&currentState); err != nil {
		return rollback(err)
	}
	state := string(domain.OperationFailed)
	if commit.Succeeded {
		if commit.Operation.Status != domain.OperationSucceeded && commit.Operation.Status != domain.OperationRolledBack {
			return rollback(controllers.ErrM4StoreProtocol)
		}
		state = string(commit.Operation.Status)
	}
	if currentState == "running" {
		if _, err := tx.ExecContext(ctx, `UPDATE operations SET state=$1,failure_reason=$2,version=version+1,updated_at=$3 WHERE id=$4`, state, nullableM4Failure(commit.Failure), now, commit.Operation.ID.String()); err != nil {
			return rollback(err)
		}
	} else if currentState != state {
		// Agent task completion may have transitioned the operation first. It
		// is safe to append the M4 audit/result exactly once only when it
		// reached the same terminal outcome.
		return rollback(controllers.ErrM4StoreProtocol)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE m4_operation_requests SET result=$1::jsonb,completed_at=$2 WHERE operation_id=$3 AND result IS NULL`, resultJSON, now, commit.Operation.ID.String()); err != nil {
		return rollback(err)
	}
	if err := appendM4AuditTx(ctx, tx, commit, now); err != nil {
		return rollback(err)
	}
	if err := appendM4OutboxTx(ctx, tx, commit.Outbox, now); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (a *m4PostgresAdapter) environment(ctx context.Context, applicationID, environmentID domain.ID) (controllers.M4Environment, error) {
	if a == nil || a.store == nil || a.store.DB() == nil {
		return controllers.M4Environment{}, errors.New("M4 PostgreSQL store is unavailable")
	}
	var applicationName string
	if err := a.store.DB().QueryRowContext(ctx, `SELECT name FROM applications WHERE id=$1`, applicationID.String()).Scan(&applicationName); err != nil {
		return controllers.M4Environment{}, err
	}
	var deployment domain.Deployment
	var state string
	err := a.store.DB().QueryRowContext(ctx, `SELECT d.id,e.application_id,d.environment_id,d.release_id,d.state,d.created_at,d.updated_at FROM deployments d JOIN environments e ON e.id=d.environment_id WHERE d.environment_id=$1 AND e.application_id=$2 AND d.state IN ('runtime_ready','degraded','serving','unknown') ORDER BY d.updated_at DESC,d.id DESC LIMIT 1`, environmentID.String(), applicationID.String()).Scan(&deployment.ID, &deployment.ApplicationID, &deployment.EnvironmentID, &deployment.ReleaseID, &state, &deployment.CreatedAt, &deployment.UpdatedAt)
	if err != nil {
		return controllers.M4Environment{}, err
	}
	deployment.Status = domain.DeploymentStatus(state)
	if err := deployment.Validate(); err != nil {
		return controllers.M4Environment{}, err
	}
	release, err := a.store.GetCompleteRelease(ctx, deployment.ReleaseID)
	if err != nil {
		return controllers.M4Environment{}, err
	}
	services, _, err := a.serviceFacts(ctx, applicationID, environmentID, deployment, release)
	if err != nil {
		return controllers.M4Environment{}, err
	}
	environment := controllers.M4Environment{ApplicationID: applicationID, EnvironmentID: environmentID, CurrentRelease: release, CurrentDeployment: deployment, Services: make([]controllers.M4ServiceState, 0, len(services))}
	for _, service := range services {
		environment.Services = append(environment.Services, controllers.M4ServiceState{Name: service.Name, Healthy: service.Healthy})
	}
	previousID, previousErr := a.store.PreviousSuccessfulReleaseID(ctx, applicationID, release.ID)
	if previousErr == nil {
		previousRelease, err := a.store.GetCompleteRelease(ctx, previousID)
		if err != nil {
			return controllers.M4Environment{}, err
		}
		previousDeployment, err := a.deploymentForRelease(ctx, applicationID, environmentID, previousID)
		if err != nil {
			return controllers.M4Environment{}, err
		}
		environment.PreviousSuccessful = &controllers.M4ReleaseDeployment{Release: previousRelease, Deployment: previousDeployment}
	} else if !errors.Is(previousErr, postgres.ErrNotFound) {
		return controllers.M4Environment{}, previousErr
	}
	view := a.buildView(applicationName, environment, services)
	environment.FactVersion = view.Version
	return environment, nil
}

func (a *m4PostgresAdapter) deploymentForRelease(ctx context.Context, applicationID, environmentID, releaseID domain.ID) (domain.Deployment, error) {
	var deployment domain.Deployment
	var state string
	err := a.store.DB().QueryRowContext(ctx, `SELECT d.id,e.application_id,d.environment_id,d.release_id,d.state,d.created_at,d.updated_at FROM deployments d JOIN environments e ON e.id=d.environment_id JOIN operations succeeded ON succeeded.deployment_id=d.id WHERE d.environment_id=$1 AND e.application_id=$2 AND d.release_id=$3 AND succeeded.operation_type IN ('deploy','redeploy','rollback') AND succeeded.state IN ('succeeded','rolled_back') ORDER BY succeeded.updated_at DESC,d.updated_at DESC,d.id DESC LIMIT 1`, environmentID.String(), applicationID.String(), releaseID.String()).Scan(&deployment.ID, &deployment.ApplicationID, &deployment.EnvironmentID, &deployment.ReleaseID, &state, &deployment.CreatedAt, &deployment.UpdatedAt)
	if err != nil {
		return domain.Deployment{}, err
	}
	deployment.Status = domain.DeploymentStatus(state)
	return deployment, deployment.Validate()
}

func (a *m4PostgresAdapter) viewFromEnvironment(ctx context.Context, environment controllers.M4Environment) (domain.ApplicationOperationsView, error) {
	var applicationName string
	if err := a.store.DB().QueryRowContext(ctx, `SELECT name FROM applications WHERE id=$1`, environment.ApplicationID.String()).Scan(&applicationName); err != nil {
		return domain.ApplicationOperationsView{}, err
	}
	services, _, err := a.serviceFacts(ctx, environment.ApplicationID, environment.EnvironmentID, environment.CurrentDeployment, environment.CurrentRelease)
	if err != nil {
		return domain.ApplicationOperationsView{}, err
	}
	return a.buildView(applicationName, environment, services), nil
}

func (a *m4PostgresAdapter) serviceFacts(ctx context.Context, applicationID, environmentID domain.ID, deployment domain.Deployment, release domain.Release) ([]domain.ServiceOperationsFact, time.Time, error) {
	spec, _, err := a.store.GetM2ReleaseRuntimeSpec(ctx, release.ID)
	if err != nil {
		return nil, time.Time{}, err
	}
	type storedObservation struct {
		name, role, status, containerID                       string
		healthy, required, cgroupVerified, metricsKnown       bool
		exitReason                                            sql.NullString
		cpu, memory, disk, rx, tx, restarts, pids, appliedCPU int64
		appliedMemory, appliedPIDs, changedPaths, hostPort    int64
		observedAt                                            time.Time
	}
	rows, err := a.store.DB().QueryContext(ctx, `SELECT DISTINCT ON (service_name) service_name,service_role,runtime_status,container_id,healthy,required,cgroup_verified,metrics_known,exit_reason,cpu_millicores,memory_bytes,disk_bytes,network_rx_bytes,network_tx_bytes,restart_count,pids_current,applied_cpu_millicores,applied_memory_bytes,applied_pids,changed_path_count,host_port,observed_at FROM m4_service_observations WHERE application_id=$1 AND environment_id=$2 AND deployment_id=$3 ORDER BY service_name,observed_at DESC,id DESC`, applicationID.String(), environmentID.String(), deployment.ID.String())
	if err != nil {
		return nil, time.Time{}, err
	}
	defer rows.Close()
	observed := map[string]storedObservation{}
	latest := deployment.UpdatedAt.UTC()
	for rows.Next() {
		var item storedObservation
		if err := rows.Scan(&item.name, &item.role, &item.status, &item.containerID, &item.healthy, &item.required, &item.cgroupVerified, &item.metricsKnown, &item.exitReason, &item.cpu, &item.memory, &item.disk, &item.rx, &item.tx, &item.restarts, &item.pids, &item.appliedCPU, &item.appliedMemory, &item.appliedPIDs, &item.changedPaths, &item.hostPort, &item.observedAt); err != nil {
			return nil, time.Time{}, err
		}
		observed[item.name] = item
		if item.observedAt.After(latest) {
			latest = item.observedAt.UTC()
		}
	}
	if err := rows.Err(); err != nil {
		return nil, time.Time{}, err
	}
	services := make([]domain.ServiceOperationsFact, 0, len(spec.Services))
	for _, service := range spec.Services {
		item, ok := observed[service.Name]
		fact := domain.ServiceOperationsFact{Name: service.Name, Role: service.Role, DeploymentID: deployment.ID, ReleaseID: release.ID, Required: service.Required, ObservedAt: latest}
		if !ok {
			fact.Status, fact.Healthy, fact.Impact, fact.NextAction = "unknown", false, "Runtime observation is pending", "wait for Agent observation before operation"
		} else {
			fact.Status, fact.Healthy = item.status, item.healthy
			fact.Actual = domain.ResourceObservation{ContainerID: item.containerID, CPUCores: float64(item.cpu) / 1000, MemoryBytes: uint64(item.memory), DiskBytes: uint64(item.disk), NetworkRxBytes: uint64(item.rx), NetworkTxBytes: uint64(item.tx), RestartCount: uint64(item.restarts), PIDsCurrent: uint64(item.pids), AppliedCPUMillicores: uint64(item.appliedCPU), AppliedMemoryBytes: uint64(item.appliedMemory), AppliedPIDs: uint64(item.appliedPIDs), ChangedPathCount: uint64(item.changedPaths), CgroupVerified: item.cgroupVerified, MetricsKnown: item.metricsKnown, HostPort: int(item.hostPort)}
			if item.exitReason.Valid {
				fact.NextAction = item.exitReason.String
			}
			if fact.Healthy {
				fact.Impact = "Service is healthy"
			} else {
				fact.Impact = "Service requires operator attention"
				if fact.NextAction == "" {
					fact.NextAction = "restart the affected service"
				}
			}
		}
		services = append(services, fact)
	}
	return services, latest, nil
}

func (a *m4PostgresAdapter) buildView(applicationName string, environment controllers.M4Environment, services []domain.ServiceOperationsFact) domain.ApplicationOperationsView {
	observedAt := environment.CurrentDeployment.UpdatedAt.UTC()
	if len(services) > 0 && services[0].ObservedAt.After(observedAt) {
		observedAt = services[0].ObservedAt
	}
	state, impact, next := domain.ApplicationHealthy, "All required services are healthy", "No operation is required"
	restarts := make([]string, 0)
	for _, service := range services {
		if !service.Healthy {
			state, impact, next = domain.ApplicationAttention, service.Impact, service.NextAction
			restarts = append(restarts, service.Name)
		}
	}
	if len(restarts) > 1 {
		state, impact, next = domain.ApplicationPartial, "Multiple services need attention", "restart the application after reviewing service facts"
	}
	version := m4FactVersion(environment.CurrentDeployment, services)
	allowed := domain.OperationsAllowedActions{RestartServices: restarts, Redeploy: true, Rollback: environment.PreviousSuccessful != nil, RollbackData: false}
	if environment.CurrentDeployment.Status == domain.DeploymentUnknown {
		state = domain.ApplicationAttention
		impact = "Runtime reachability is unknown"
		next = "wait for Agent heartbeat and observation recovery"
		allowed = domain.OperationsAllowedActions{RollbackData: false}
	}
	return domain.ApplicationOperationsView{Version: version, ApplicationID: environment.ApplicationID, ApplicationName: applicationName, EnvironmentID: environment.EnvironmentID, ReleaseID: environment.CurrentRelease.ID, State: state, Serving: environment.CurrentDeployment.Serving(), Summary: impact, Impact: impact, NextStep: next, Services: services, AllowedActions: allowed, DataNotice: "Rollback changes code and configuration only; persistent data is not rolled back.", AIStatus: "disabled", ObservedAt: observedAt}
}

func loadM4OperationTx(ctx context.Context, tx *sql.Tx, environmentID domain.ID, key string) (domain.Operation, string, *controllers.M4OperationResult, bool, error) {
	var operation domain.Operation
	var kind, state, requestDigest string
	var result []byte
	err := tx.QueryRowContext(ctx, `SELECT o.id,o.application_id,o.environment_id,o.target_ref,o.operation_type,o.idempotency_key,o.state,COALESCE(o.failure_reason,''),o.created_at,o.updated_at,r.request_digest,r.result FROM operations o JOIN m4_operation_requests r ON r.operation_id=o.id WHERE o.environment_id=$1 AND o.idempotency_key=$2 FOR UPDATE`, environmentID.String(), key).Scan(&operation.ID, &operation.ApplicationID, &operation.EnvironmentID, &operation.TargetRef, &kind, &operation.IdempotencyKey, &state, &operation.FailureReason, &operation.CreatedAt, &operation.UpdatedAt, &requestDigest, &result)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Operation{}, "", nil, false, nil
	}
	if err != nil {
		return domain.Operation{}, "", nil, false, err
	}
	operation.Type, operation.Status = domain.OperationType(kind), domain.OperationStatus(state)
	if err := operation.Validate(); err != nil {
		return domain.Operation{}, "", nil, false, err
	}
	if len(result) == 0 {
		return operation, requestDigest, nil, true, nil
	}
	var replay controllers.M4OperationResult
	if err := json.Unmarshal(result, &replay); err != nil {
		return domain.Operation{}, "", nil, false, err
	}
	return operation, requestDigest, &replay, true, nil
}

func appendM4AuditTx(ctx context.Context, tx *sql.Tx, commit controllers.M4OperationCommit, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('open-card-audit-evidence-chain',0))`); err != nil {
		return err
	}
	var previous sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT record_hash FROM audit_evidence ORDER BY sequence DESC LIMIT 1`).Scan(&previous); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	refs, err := json.Marshal(commit.Audit.Evidence)
	if err != nil {
		return err
	}
	recordHash := m4AdapterDigest(previous.String + "\x00" + commit.Audit.Action + "\x00" + commit.Audit.InputDigest + "\x00" + now.UTC().Format(time.RFC3339Nano))
	id := m4AdapterID("audit", recordHash)
	result := "failed"
	if commit.Succeeded {
		result = "succeeded"
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_evidence(id,actor_type,actor_id,action,reason,input_digest,result,evidence_refs,previous_hash,record_hash,created_at) VALUES($1,'user',$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10)`, id.String(), commit.Audit.Actor, commit.Audit.Action, commit.Audit.Reason, commit.Audit.InputDigest, result, refs, nullableM4Failure(previous.String), recordHash, now.UTC())
	return err
}

func appendM4OutboxTx(ctx context.Context, tx *sql.Tx, event application.Event, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "open-card-outbox:operation:"+event.OperationID); err != nil {
		return err
	}
	var aggregateSequence, streamSequence int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM outbox_events WHERE aggregate_type='operation' AND aggregate_id=$1`, event.OperationID).Scan(&aggregateSequence); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT nextval('outbox_events_stream_sequence'::regclass)`).Scan(&streamSequence); err != nil {
		return err
	}
	event.ID, event.Sequence, event.OccurredAt = "evt-m4-"+strings.TrimPrefix(m4AdapterDigest(event.OperationID+"\x00"+fmt.Sprint(streamSequence)), "sha256:")[:24], uint64(streamSequence), now.UTC()
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO outbox_events(id,aggregate_type,aggregate_id,aggregate_version,sequence,stream_sequence,event_type,payload,created_at,payload_version) VALUES($1,'operation',$2,$3,$3,$4,$5,$6::jsonb,$7,'1.1')`, event.ID, event.OperationID, aggregateSequence, streamSequence, event.Kind, payload, now.UTC())
	return err
}

// ProjectAgentEvidence is intentionally replay-safe: agent_events is the
// durable cursor authority, while every derived file/index/sample uses a
// deterministic task+sequence identity. A failed projector can therefore be
// retried by the Agent without duplicating operational facts.
func (a *m4PostgresAdapter) ProjectAgentEvidence(ctx context.Context, task postgres.ControllerTask, envelope v1.Envelope) error {
	if a == nil || a.store == nil || task.DeploymentID.Empty() {
		return nil
	}
	switch envelope.Kind {
	case v1.KindLogChunk:
		if a.logs == nil {
			return nil
		}
		var chunk v1.LogChunk
		if err := json.Unmarshal(envelope.Payload, &chunk); err != nil {
			return err
		}
		if err := chunk.Validate(); err != nil {
			return err
		}
		return a.projectLogChunk(ctx, task, envelope.AgentSequence, chunk)
	case v1.KindObservation:
		if a.metrics == nil {
			return nil
		}
		var observation v1.Observation
		if err := json.Unmarshal(envelope.Payload, &observation); err != nil {
			return err
		}
		if err := observation.Validate(); err != nil {
			return err
		}
		return a.projectRuntimeObservation(ctx, task, envelope.AgentSequence, observation)
	default:
		return nil
	}
}

func (a *m4PostgresAdapter) projectLogChunk(ctx context.Context, task postgres.ControllerTask, sequence uint64, chunk v1.LogChunk) error {
	stream := "task-" + task.Task.ID.String() + "-" + fmt.Sprint(sequence)
	if prior, err := a.logs.Read(observability.LogCategoryRuntime, stream); err != nil {
		return err
	} else if len(prior) == 0 {
		if err := a.logs.Append(observability.LogCategoryRuntime, stream, []byte(chunk.Data)); err != nil {
			return err
		}
	}
	files, err := a.logs.List(observability.LogCategoryRuntime, stream)
	if err != nil || len(files) == 0 {
		return err
	}
	var releaseID string
	if err := a.store.DB().QueryRowContext(ctx, `SELECT release_id FROM deployments WHERE id=$1`, task.DeploymentID.String()).Scan(&releaseID); err != nil {
		return err
	}
	serviceName := m4LogTaskServiceName(task.Task.Payload)
	for _, file := range files {
		indexID := m4AdapterID("log", task.Task.ID.String()+":"+fmt.Sprint(sequence)+":"+fmt.Sprint(file.Sequence))
		var exists bool
		if err := a.store.DB().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM m4_log_indexes WHERE id=$1)`, indexID.String()).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		if err := a.store.AppendLogIndex(ctx, postgres.LogIndex{ID: indexID, ApplicationID: task.Operation.ApplicationID, ServiceName: serviceName, ReleaseID: domain.ID(releaseID), DeploymentID: task.DeploymentID, OperationID: task.Operation.ID, Category: postgres.LogIndexRuntime, Path: file.Path, Segment: file.Sequence, ByteSize: file.Bytes, CreatedAt: a.now()}, a.now()); err != nil {
			return err
		}
	}
	return m4ReconcileOrdinaryLogIndexes(ctx, a.store, a.logs, a.now())
}

func m4LogTaskServiceName(payload json.RawMessage) string {
	var task controllers.AgentTaskSpec
	if json.Unmarshal(payload, &task) != nil || task.Kind != v1.TaskLogs {
		return "runtime"
	}
	var direct contracts.LogsRequest
	if json.Unmarshal(task.Parameters, &direct) == nil && strings.TrimSpace(direct.ServiceName) != "" {
		return strings.TrimSpace(direct.ServiceName)
	}
	var wrapped struct {
		M4PayloadType string          `json:"m4_payload_type"`
		Request       json.RawMessage `json:"request"`
	}
	if json.Unmarshal(task.Parameters, &wrapped) != nil || wrapped.M4PayloadType != "service_group.logs" {
		return "runtime"
	}
	if json.Unmarshal(wrapped.Request, &direct) != nil || strings.TrimSpace(direct.ServiceName) == "" {
		return "runtime"
	}
	return strings.TrimSpace(direct.ServiceName)
}

func (a *m4PostgresAdapter) projectRuntimeObservation(ctx context.Context, task postgres.ControllerTask, sequence uint64, wire v1.Observation) error {
	var group contracts.ServiceGroupRuntimeObservation
	if err := json.Unmarshal(wire.Details, &group); err == nil && group.DeploymentID == task.DeploymentID && len(group.Services) > 0 {
		for _, service := range group.Services {
			if err := a.projectOneRuntimeObservation(ctx, task, sequence, wire, service); err != nil {
				return err
			}
		}
		return nil
	}
	var runtime contracts.RuntimeObservation
	if err := json.Unmarshal(wire.Details, &runtime); err != nil {
		// Node Docker facts and forward-compatible observation envelopes are
		// still durable Agent events, but not service-level M4 measurements.
		return nil
	}
	return a.projectOneRuntimeObservation(ctx, task, sequence, wire, runtime)
}

func (a *m4PostgresAdapter) projectOneRuntimeObservation(ctx context.Context, task postgres.ControllerTask, sequence uint64, wire v1.Observation, runtime contracts.RuntimeObservation) error {
	if runtime.DeploymentID != task.DeploymentID || strings.TrimSpace(runtime.ServiceName) == "" {
		return nil
	}
	environmentID := task.Operation.EnvironmentID
	releaseID := runtime.DeploymentID
	var deploymentRelease string
	if err := a.store.DB().QueryRowContext(ctx, `SELECT release_id FROM deployments WHERE id=$1`, task.DeploymentID.String()).Scan(&deploymentRelease); err != nil {
		return err
	}
	releaseID = domain.ID(deploymentRelease)
	role, required := domain.RoleWorker, true
	if spec, _, err := a.store.GetM2ReleaseRuntimeSpec(ctx, releaseID); err == nil {
		for _, service := range spec.Services {
			if service.Name == runtime.ServiceName {
				role, required = service.Role, service.Required
				break
			}
		}
	}
	sampleID := "agent:" + task.Task.ID.String() + ":" + fmt.Sprint(sequence) + ":" + runtime.ServiceName
	now := wire.At.UTC()
	if now.IsZero() {
		now = a.now()
	}
	metric := observability.Sample{ID: sampleID, ApplicationID: task.Operation.ApplicationID.String(), ServiceName: runtime.ServiceName, ReleaseID: releaseID.String(), At: now, CPU: float64(maxM4Int(runtime.CPUUsageMillis)) / 1000, MemoryBytes: float64(maxM4Int(runtime.MemoryBytes)), DiskBytes: float64(maxM4Int(runtime.DiskBytes)), NetworkRxBytes: uint64(maxM4Int(runtime.NetworkRxBytes)), NetworkTxBytes: uint64(maxM4Int(runtime.NetworkTxBytes)), RestartCount: runtime.RestartCount}
	if err := a.metrics.InsertSamples(ctx, []observability.Sample{metric}); err != nil {
		return err
	}
	id := m4AdapterID("observation", sampleID)
	_, err := a.store.DB().ExecContext(ctx, `INSERT INTO m4_service_observations(id,sample_id,application_id,environment_id,deployment_id,release_id,service_name,service_role,runtime_status,healthy,required,exit_reason,cpu_millicores,memory_bytes,disk_bytes,network_rx_bytes,network_tx_bytes,restart_count,observed_at,created_at,container_id,host_port,pids_current,applied_cpu_millicores,applied_memory_bytes,applied_pids,changed_path_count,cgroup_verified,metrics_known) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28) ON CONFLICT(sample_id) DO NOTHING`, id.String(), sampleID, task.Operation.ApplicationID.String(), environmentID.String(), task.DeploymentID.String(), releaseID.String(), runtime.ServiceName, string(role), runtime.Status, runtime.Healthy, required, nullableM4Failure(runtime.ExitReason), maxM4Int(runtime.CPUUsageMillis), maxM4Int(runtime.MemoryBytes), maxM4Int(runtime.DiskBytes), maxM4Int(runtime.NetworkRxBytes), maxM4Int(runtime.NetworkTxBytes), runtime.RestartCount, now, runtime.ContainerID, runtime.HostPort, maxM4Int(runtime.PIDsCurrent), maxM4Int(runtime.Limits.CPUMillis), maxM4Int(runtime.Limits.MemoryBytes), maxM4Int(runtime.Limits.PIDs), maxM4Int(runtime.ChangedPaths), runtime.CgroupVerified, runtime.MetricsKnown)
	return err
}

func maxM4Int(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}

func m4FactVersion(deployment domain.Deployment, services []domain.ServiceOperationsFact) string {
	parts := []string{deployment.ID.String(), deployment.ReleaseID.String(), string(deployment.Status), deployment.UpdatedAt.UTC().Format(time.RFC3339Nano)}
	for _, service := range services {
		parts = append(parts, service.Name, service.Status, fmt.Sprint(service.Healthy), service.ObservedAt.UTC().Format(time.RFC3339Nano), service.Actual.ContainerID, fmt.Sprint(service.Actual.RestartCount), fmt.Sprint(service.Actual.AppliedCPUMillicores), fmt.Sprint(service.Actual.AppliedMemoryBytes), fmt.Sprint(service.Actual.AppliedPIDs), fmt.Sprint(service.Actual.CgroupVerified))
	}
	sort.Strings(parts[4:])
	return "m4-" + strings.TrimPrefix(m4AdapterDigest(strings.Join(parts, "\x00")), "sha256:")[:24]
}

func m4AdapterID(prefix, value string) domain.ID {
	return domain.ID(prefix + "_" + strings.TrimPrefix(m4AdapterDigest(value), "sha256:")[:32])
}
func m4AdapterDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func nullableM4Failure(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
