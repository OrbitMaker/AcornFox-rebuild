package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"strings"
	"time"
)

var _ appcontracts.ImageLifecycleStore = (*Store)(nil)

const imageLifecycleScope = "image.lifecycle.v1"

func validLifecycleAction(a appcontracts.ImageLifecycleAction) bool {
	return a == appcontracts.ImageLifecycleStop || a == appcontracts.ImageLifecycleStart || a == appcontracts.ImageLifecycleRestart
}

func (s *Store) CreateImageLifecycle(ctx context.Context, adminID domain.ID, in appcontracts.CreateImageLifecycleInput) (appcontracts.ImageLifecycleBinding, error) {
	var b appcontracts.ImageLifecycleBinding
	if err := s.checkOpen(); err != nil {
		return b, err
	}
	if adminID.Empty() {
		return b, domain.NewError(domain.ErrUnauthorized, "administrator required")
	}
	key := strings.TrimSpace(in.IdempotencyKey)
	if in.DeploymentID.Empty() || !validLifecycleAction(in.Action) || key == "" || len(key) > 256 {
		return b, domain.ValidationError("invalid lifecycle command")
	}
	digest := sha256Hex(fmt.Sprintf("%s:%s:%s", adminID, in.DeploymentID, in.Action))
	now := time.Now().UTC()
	stamp := FormatTime(now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return b, err
	}
	defer tx.Rollback()
	// This first write acquires SQLite's serialized writer before ownership/active checks.
	res, err := tx.ExecContext(ctx, `INSERT INTO idempotency_records(scope,idempotency_key,request_digest,status,created_at,updated_at) VALUES(?,?,?,'in_progress',?,?) ON CONFLICT(scope,idempotency_key) DO NOTHING`, imageLifecycleScope, key, digest, stamp, stamp)
	if err != nil {
		return b, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return b, err
	}
	var savedDigest, state string
	var response sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT request_digest,status,response FROM idempotency_records WHERE scope=? AND idempotency_key=?`, imageLifecycleScope, key).Scan(&savedDigest, &state, &response); err != nil {
		return b, err
	}
	if savedDigest != digest {
		return b, ErrIdempotencyConflict
	}
	// Current administrator must still be enabled even for a replay.
	var enabled int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM admin_credentials WHERE id=? AND disabled_at IS NULL`, adminID.String()).Scan(&enabled); err != nil {
		return b, err
	}
	if enabled != 1 {
		return b, domain.NewError(domain.ErrUnauthorized, "administrator unavailable")
	}
	if n == 0 {
		if state != "completed" {
			return b, ErrIdempotencyInProgress
		}
		if !response.Valid || json.Unmarshal([]byte(response.String), &b) != nil || b.OperationID.Empty() || b.TaskID.Empty() || b.DeploymentID != in.DeploymentID || b.Action != in.Action || b.State != "pending" || b.CreatedAt.IsZero() {
			return b, ErrIdempotencyCorrupt
		}
		if appcontracts.ValidatePlanConsistency(b.Plan) != nil || b.Plan.ID != b.PlanID || b.Plan.PlanDigest != b.PlanDigest || b.Plan.AdminID != adminID || b.Plan.ResolvedImage.Digest != b.ManifestDigest {
			return b, ErrIdempotencyCorrupt
		}
		var owner string
		if err := tx.QueryRowContext(ctx, `SELECT admin_id FROM image_lifecycle_commands WHERE operation_id=? AND deployment_id=? AND task_id=?`, b.OperationID.String(), b.DeploymentID.String(), b.TaskID.String()).Scan(&owner); err != nil {
			return b, ErrIdempotencyCorrupt
		}
		if owner != adminID.String() {
			return b, domain.NewError(domain.ErrForbidden, "command owner mismatch")
		}
		return b, lifecycleCommit(tx)
	}
	var depState, owner string
	err = tx.QueryRowContext(ctx, `SELECT d.id,d.release_id,d.application_id,d.environment_id,d.operation_id,r.plan_id,r.plan_digest,r.digest,d.container_id,d.image_id,e.host_port,e.container_port,d.status,p.admin_id
 FROM image_deployments d JOIN image_releases r ON r.id=d.release_id AND r.application_id=d.application_id
 JOIN image_deploy_intents i ON i.operation_id=d.operation_id AND i.application_id=d.application_id AND i.environment_id=d.environment_id AND i.plan_id=r.plan_id AND i.plan_digest=r.plan_digest
 JOIN image_plans p ON p.id=r.plan_id AND p.plan_digest=r.plan_digest
 JOIN operations o ON o.id=d.operation_id AND o.state='succeeded'
 JOIN image_endpoints e ON e.deployment_id=d.id AND e.application_id=d.application_id AND e.environment_id=d.environment_id
 WHERE d.id=? AND EXISTS(SELECT 1 FROM image_artifacts a WHERE a.release_id=r.id AND a.digest=r.digest AND a.image_id=d.image_id)`, in.DeploymentID.String()).Scan(&b.DeploymentID, &b.ReleaseID, &b.ApplicationID, &b.EnvironmentID, &b.DeployOperationID, &b.PlanID, &b.PlanDigest, &b.ManifestDigest, &b.ContainerID, &b.ImageID, &b.HostPort, &b.ContainerPort, &depState, &owner)
	if errors.Is(err, sql.ErrNoRows) {
		return b, ErrNotFound
	}
	if err != nil {
		return b, err
	}
	if owner != adminID.String() {
		return b, domain.NewError(domain.ErrForbidden, "deployment owner mismatch")
	}
	b.Plan, err = readLifecyclePlanTx(ctx, tx, b, adminID)
	if err != nil {
		return b, err
	}
	if b.ContainerID == "" || !validSha256Digest(b.ImageID) || !validSha256Digest(b.ManifestDigest) || !validSha256Digest(b.PlanDigest) || b.HostPort <= 0 || b.ContainerPort <= 0 {
		return b, ErrCorruptData
	}
	if (in.Action == appcontracts.ImageLifecycleStart && depState != "stopped") || (in.Action != appcontracts.ImageLifecycleStart && depState != "running") {
		return b, domain.NewError(domain.ErrConflict, "action incompatible with deployment state")
	}
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM image_lifecycle_commands c JOIN operations o ON o.id=c.operation_id WHERE c.deployment_id=? AND o.state IN ('pending','leased','running','waiting','cancelling')`, in.DeploymentID.String()).Scan(&active); err != nil {
		return b, err
	}
	if active != 0 {
		return b, domain.NewError(domain.ErrConflict, "deployment command active")
	}
	b.OperationID, err = domain.NewID("op")
	if err != nil {
		return b, err
	}
	b.TaskID, err = domain.NewID("task")
	if err != nil {
		return b, err
	}
	b.Action = in.Action
	b.State = "pending"
	b.CreatedAt = now
	binding, err := json.Marshal(b)
	if err != nil {
		return b, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations(id,application_id,environment_id,operation_type,idempotency_key,state,version,target_ref,target_kind,created_at,updated_at) VALUES(?,?,?,?,?,'pending',1,?,'application',?,?)`, b.OperationID.String(), b.ApplicationID.String(), b.EnvironmentID.String(), "image."+string(b.Action), key, b.ApplicationID.String(), stamp, stamp); err != nil {
		return b, err
	}
	payload, err := json.Marshal(map[string]any{"kind": appcontracts.ImageLifecycleTaskKind, "binding": b})
	if err != nil {
		return b, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO task_leases(task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at) VALUES(?,?,NULL,NULL,0,?,'ready',?,?,?)`, b.TaskID.String(), b.OperationID.String(), defaultTaskMaxAttempts, string(payload), stamp, stamp); err != nil {
		return b, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO image_lifecycle_commands(operation_id,task_id,deployment_id,admin_id,action,binding,created_at) VALUES(?,?,?,?,?,?,?)`, b.OperationID.String(), b.TaskID.String(), b.DeploymentID.String(), adminID.String(), string(b.Action), string(binding), stamp); err != nil {
		return b, err
	}
	if err := lifecycleEvidenceTx(ctx, tx, b, "accepted", auditContextFromAdmin(adminID), now, 1); err != nil {
		return b, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE idempotency_records SET status='completed',response=?,updated_at=? WHERE scope=? AND idempotency_key=?`, string(binding), stamp, imageLifecycleScope, key); err != nil {
		return b, err
	}
	return b, lifecycleCommit(tx)
}

func lifecycleCommit(tx *sql.Tx) error {
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: lifecycle transaction: %v", ErrOutcomeUnknown, err)
	}
	return nil
}

func readLifecycleTx(ctx context.Context, tx *sql.Tx, opID domain.ID) (appcontracts.ImageLifecycleBinding, int64, error) {
	var b appcontracts.ImageLifecycleBinding
	var raw, state string
	var version int64
	var taskID, depID, action string
	var result sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT c.binding,c.task_id,c.deployment_id,c.action,o.state,o.version,r.result FROM image_lifecycle_commands c JOIN operations o ON o.id=c.operation_id LEFT JOIN image_lifecycle_results r ON r.operation_id=c.operation_id WHERE c.operation_id=?`, opID.String()).Scan(&raw, &taskID, &depID, &action, &state, &version, &result)
	if errors.Is(err, sql.ErrNoRows) {
		return b, 0, ErrNotFound
	}
	if err != nil {
		return b, 0, err
	}
	if json.Unmarshal([]byte(raw), &b) != nil || b.OperationID != opID || b.TaskID.String() != taskID || b.DeploymentID.String() != depID || string(b.Action) != action || !validLifecycleAction(b.Action) {
		return b, 0, ErrCorruptData
	}
	if appcontracts.ValidatePlanConsistency(b.Plan) != nil || b.Plan.ID != b.PlanID || b.Plan.PlanDigest != b.PlanDigest || b.Plan.ResolvedImage.Digest != b.ManifestDigest {
		return b, 0, ErrCorruptData
	}
	b.State = state
	b.RecoveryRequired = state == "waiting"
	if result.Valid {
		b.Result = &appcontracts.ImageLifecycleResult{}
		if json.Unmarshal([]byte(result.String), b.Result) != nil {
			return b, 0, ErrCorruptData
		}
	}
	return b, version, nil
}

func (s *Store) lifecycleAuthorityTx(ctx context.Context, tx *sql.Tx, in appcontracts.BeginImageExecutionInput) (appcontracts.ImageLifecycleBinding, int64, error) {
	var b appcontracts.ImageLifecycleBinding
	if in.TaskID.Empty() || in.OperationID.Empty() || in.Owner == "" || in.CoreGeneration <= 0 || in.LeaseGeneration <= 0 {
		return b, 0, domain.ValidationError("incomplete lifecycle authority")
	}
	task, err := s.verifyTaskLeaseTx(ctx, tx, appcontracts.TaskMutationRequest{TaskID: in.TaskID, Owner: in.Owner, CoreGeneration: in.CoreGeneration, LeaseGeneration: in.LeaseGeneration, Now: time.Now().UTC()})
	if err != nil {
		return b, 0, err
	}
	if task.OperationID != in.OperationID {
		return b, 0, appcontracts.ErrLeaseLost
	}
	b, v, err := readLifecycleTx(ctx, tx, in.OperationID)
	if err != nil {
		return b, 0, err
	}
	if b.TaskID != in.TaskID || (b.State != "pending" && b.State != "running" && b.State != "waiting") {
		return b, 0, appcontracts.ErrLeaseLost
	}
	// Verify fresh command tuple, immutable source provenance and current runtime identity.
	var matched int
	err = tx.QueryRowContext(ctx, `SELECT count(*) FROM image_lifecycle_commands c
 JOIN image_deployments d ON d.id=c.deployment_id
 JOIN image_releases r ON r.id=d.release_id
 JOIN operations o ON o.id=c.operation_id AND o.application_id=d.application_id AND o.environment_id=d.environment_id AND o.target_kind='application' AND o.target_ref=d.application_id AND o.operation_type='image.'||c.action
 JOIN task_leases t ON t.task_id=c.task_id AND t.operation_id=c.operation_id
 WHERE c.operation_id=? AND d.release_id=? AND d.application_id=? AND d.environment_id=? AND d.operation_id=? AND d.container_id=? AND d.image_id=? AND r.plan_id=? AND r.plan_digest=? AND r.digest=? AND d.status IN ('running','stopped')
 AND json_extract(t.payload,'$.binding')=json(c.binding) AND json_extract(t.payload,'$.kind')=? AND json_extract(t.payload,'$.binding.operation_id')=c.operation_id AND json_extract(t.payload,'$.binding.deployment_id')=d.id AND json_extract(t.payload,'$.binding.action')=c.action
 AND EXISTS(SELECT 1 FROM image_endpoints e WHERE e.deployment_id=d.id AND e.host_port=? AND e.container_port=?)`, b.OperationID.String(), b.ReleaseID.String(), b.ApplicationID.String(), b.EnvironmentID.String(), b.DeployOperationID.String(), b.ContainerID, b.ImageID, b.PlanID.String(), b.PlanDigest, b.ManifestDigest, appcontracts.ImageLifecycleTaskKind, b.HostPort, b.ContainerPort).Scan(&matched)
	if err != nil {
		return b, 0, err
	}
	if matched != 1 {
		return b, 0, domain.NewError(domain.ErrForbidden, "lifecycle binding drift")
	}
	var commandAdmin domain.ID
	if err := tx.QueryRowContext(ctx, `SELECT admin_id FROM image_lifecycle_commands WHERE operation_id=?`, b.OperationID.String()).Scan(&commandAdmin); err != nil {
		return b, 0, err
	}
	plan, err := readLifecyclePlanTx(ctx, tx, b, commandAdmin)
	if err != nil {
		return b, 0, err
	}
	storedPlan, err := json.Marshal(b.Plan)
	if err != nil {
		return b, 0, err
	}
	currentPlan, err := json.Marshal(plan)
	if err != nil {
		return b, 0, err
	}
	if string(storedPlan) != string(currentPlan) {
		return b, 0, domain.NewError(domain.ErrForbidden, "original lifecycle plan drift")
	}
	b.Plan = plan
	return b, v, nil
}
func exactLifecycleInput(b appcontracts.ImageLifecycleBinding, in appcontracts.ImageLifecycleAuthorityInput) error {
	if b.DeploymentID != in.DeploymentID || b.ReleaseID != in.ReleaseID || b.PlanDigest != in.PlanDigest || b.ContainerID != in.ContainerID || b.Action != in.Action {
		return domain.NewError(domain.ErrForbidden, "lifecycle authority target mismatch")
	}
	return nil
}
func (s *Store) BeginImageLifecycle(ctx context.Context, in appcontracts.BeginImageExecutionInput) (appcontracts.ImageLifecycleBinding, error) {
	var b appcontracts.ImageLifecycleBinding
	if err := s.checkOpen(); err != nil {
		return b, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return b, err
	}
	defer tx.Rollback()
	b, _, err = s.lifecycleAuthorityTx(ctx, tx, in)
	if err != nil {
		return b, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE operations SET state='running',version=version+1,updated_at=max(updated_at,?) WHERE id=? AND state='pending'`, FormatTime(time.Now().UTC()), in.OperationID.String()); err != nil {
		return b, err
	}
	if !b.RecoveryRequired {
		b.State = "running"
	}
	return b, lifecycleCommit(tx)
}
func (s *Store) AuthorizeImageLifecycle(ctx context.Context, in appcontracts.ImageLifecycleAuthorityInput) (appcontracts.ImageLifecycleBinding, error) {
	var b appcontracts.ImageLifecycleBinding
	if err := s.checkOpen(); err != nil {
		return b, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return b, err
	}
	defer tx.Rollback()
	b, _, err = s.lifecycleAuthorityTx(ctx, tx, in.BeginImageExecutionInput)
	if err != nil {
		return b, err
	}
	return b, exactLifecycleInput(b, in)
}
func (s *Store) CommitImageLifecycleResult(ctx context.Context, in appcontracts.CommitImageLifecycleInput) error {
	return s.finishImageLifecycle(ctx, in.ImageLifecycleAuthorityInput, &in.Result, "succeeded", "")
}
func (s *Store) RecordImageLifecycleUnknown(ctx context.Context, in appcontracts.ImageLifecycleOutcomeInput) error {
	return s.finishImageLifecycle(ctx, in.ImageLifecycleAuthorityInput, nil, "waiting", in.Reason)
}
func (s *Store) FailImageLifecycle(ctx context.Context, in appcontracts.ImageLifecycleOutcomeInput) error {
	return s.finishImageLifecycle(ctx, in.ImageLifecycleAuthorityInput, nil, "failed", in.Reason)
}
func (s *Store) finishImageLifecycle(ctx context.Context, in appcontracts.ImageLifecycleAuthorityInput, result *appcontracts.ImageLifecycleResult, state, reason string) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	b, version, err := s.lifecycleAuthorityTx(ctx, tx, in.BeginImageExecutionInput)
	if err != nil {
		return err
	}
	if err := exactLifecycleInput(b, in); err != nil {
		return err
	}
	now := time.Now().UTC()
	stamp := FormatTime(now)
	if result != nil {
		r := *result
		if !r.VerifiedIdentity || r.ContainerID != b.ContainerID || r.ImageID != b.ImageID || r.ManifestDigest != b.ManifestDigest || r.ObservedAt.IsZero() || r.ObservedAt.Before(b.CreatedAt) || r.ObservedAt.After(now.Add(time.Minute)) || r.ObservedAt.Before(now.Add(-2*time.Minute)) {
			return domain.ValidationError("fresh same-container runtime observation required")
		}
		depState := "running"
		if b.Action == appcontracts.ImageLifecycleStop {
			if r.Running || r.EndpointReady {
				return domain.ValidationError("stop observation must be stopped without ready endpoint")
			}
			depState = "stopped"
		} else if !r.Running || !r.EndpointReady || r.HostPort != b.HostPort || r.ContainerPort != b.ContainerPort {
			return domain.ValidationError("running same-port observation and actual endpoint probe required")
		}
		raw, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO image_lifecycle_results(operation_id,result,created_at) VALUES(?,?,?)`, b.OperationID.String(), string(raw), stamp); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE image_deployments SET status=?,updated_at=max(updated_at,?) WHERE id=? AND container_id=?`, depState, stamp, b.DeploymentID.String(), b.ContainerID); err != nil {
			return err
		}
		// Retain endpoint allocation for start; readers must gate readiness on current state.
		if r.Running {
			if _, err := tx.ExecContext(ctx, `UPDATE image_endpoints SET observed_at=?,updated_at=max(updated_at,?) WHERE deployment_id=?`, FormatTime(r.ObservedAt), stamp, b.DeploymentID.String()); err != nil {
				return err
			}
		}
	}
	reason = cleanLastErrorReason(reason)
	request := appcontracts.TaskMutationRequest{TaskID: in.TaskID, Owner: in.Owner, CoreGeneration: in.CoreGeneration, LeaseGeneration: in.LeaseGeneration, Now: now}
	taskState := "completed"
	if state == "failed" {
		taskState = "failed"
	}
	if state == "waiting" {
		taskState = "ready"
	}
	if _, err := s.mutateTaskTx(ctx, tx, request, taskState, reason); err != nil {
		return err
	}
	if state == "waiting" {
		// Keep unknown marker durable; reclaim must inspect before attempting a write.
		if _, err := tx.ExecContext(ctx, `UPDATE task_leases SET last_error=? WHERE task_id=?`, cleanLastErrorReason("unknown: "+reason), in.TaskID.String()); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE operations SET state=?,version=version+1,failure_reason=?,updated_at=max(updated_at,?) WHERE id=?`, state, reason, stamp, b.OperationID.String()); err != nil {
		return err
	}
	eventState := state
	if state == "waiting" {
		eventState = "unknown"
	}
	if err := lifecycleEvidenceTx(ctx, tx, b, eventState, appcontracts.AuditContext{ActorType: "system", ActorID: "core-system", Reason: "image.lifecycle"}, now, version+1); err != nil {
		return err
	}
	return lifecycleCommit(tx)
}
func lifecycleEvidenceTx(ctx context.Context, tx *sql.Tx, b appcontracts.ImageLifecycleBinding, outcome string, actor appcontracts.AuditContext, now time.Time, version int64) error {
	evt, err := appendOutboxTx(ctx, tx, appcontracts.OutboxEvent{AggregateType: "operation", AggregateID: b.OperationID.String(), AggregateVersion: version, EventType: "image.lifecycle." + outcome, CreatedAt: now, PayloadVersion: "1.0"}, func(id string, cursor int64) ([]byte, error) {
		return json.Marshal(map[string]any{"event_id": id, "sequence": cursor, "operation_id": b.OperationID, "deployment_id": b.DeploymentID, "action": b.Action, "outcome": outcome})
	})
	if err != nil {
		return err
	}
	id, err := domain.NewID("audit")
	if err != nil {
		return err
	}
	_, err = appendAuditTx(ctx, tx, auditInput{ID: id.String(), Actor: actor, Action: "image.lifecycle." + outcome, InputDigest: "sha256:" + sha256Hex(fmt.Sprintf("%s:%s:%s", b.OperationID, b.DeploymentID, b.Action)), Result: outcome, EvidenceRefs: []string{b.ApplicationID.String(), b.OperationID.String(), b.TaskID.String(), evt.ID}, CreatedAt: now})
	return err
}
func (s *Store) ReadImageLifecycle(ctx context.Context, adminID, opID domain.ID) (appcontracts.ImageLifecycleBinding, error) {
	var b appcontracts.ImageLifecycleBinding
	if err := s.checkOpen(); err != nil {
		return b, err
	}
	if adminID.Empty() || opID.Empty() {
		return b, domain.ValidationError("administrator and command required")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return b, err
	}
	defer tx.Rollback()
	var authorized int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM image_lifecycle_commands c JOIN admin_credentials a ON a.id=c.admin_id AND a.disabled_at IS NULL WHERE c.operation_id=? AND c.admin_id=?`, opID.String(), adminID.String()).Scan(&authorized); err != nil {
		return b, err
	}
	if authorized != 1 {
		return b, ErrNotFound
	}
	b, _, err = readLifecycleTx(ctx, tx, opID)
	if err != nil {
		return b, err
	}
	// Diagnostics are populated only on this administrator read path, never on
	// the immutable command binding used by Begin/Authorize or task matching.
	if b.State == "failed" || b.State == "waiting" {
		var operationReason, taskReason string
		err = tx.QueryRowContext(ctx, `SELECT COALESCE(o.failure_reason,''),COALESCE(t.last_error,'')
 FROM image_lifecycle_commands c JOIN operations o ON o.id=c.operation_id
 LEFT JOIN task_leases t ON t.task_id=c.task_id AND t.operation_id=c.operation_id
 WHERE c.operation_id=?`, opID.String()).Scan(&operationReason, &taskReason)
		if err != nil {
			return b, err
		}
		reason := operationReason
		if strings.TrimSpace(reason) == "" {
			reason = taskReason
		}
		if strings.TrimSpace(reason) != "" {
			b.Reason = cleanLastErrorReason(reason)
		}
	}
	return b, nil
}

// Use SQLite's JSON projection to decode the existing ImagePlan DTO once, then
// reuse the same content/digest validator as the original deployment path.
// The supplied administrator is persisted command ownership, never worker context.
func readLifecyclePlanTx(ctx context.Context, tx *sql.Tx, b appcontracts.ImageLifecycleBinding, adminID domain.ID) (appcontracts.ImagePlan, error) {
	var plan appcontracts.ImagePlan
	var raw, created, updated string
	err := tx.QueryRowContext(ctx, `SELECT json_object(
 'id',p.id,'admin_id',p.admin_id,'app_name',p.app_name,'status',p.status,'plan_digest',p.plan_digest,
 'canonical_input',json(p.canonical_input),'resolved_image',json(p.resolved_image),
 'resolver_provenance',json(p.resolver_provenance),'missing_inputs',json(p.missing_inputs),
 'created_at',p.created_at,'updated_at',p.updated_at),p.created_at,p.updated_at
 FROM image_plans p
 JOIN image_deploy_intents i ON i.plan_id=p.id AND i.plan_digest=p.plan_digest
 JOIN image_releases r ON r.plan_id=p.id AND r.plan_digest=p.plan_digest AND r.application_id=i.application_id
 JOIN image_deployments d ON d.operation_id=i.operation_id AND d.release_id=r.id AND d.application_id=i.application_id AND d.environment_id=i.environment_id
 WHERE p.id=? AND p.plan_digest=? AND p.admin_id=? AND i.operation_id=? AND r.id=? AND r.digest=? AND d.id=? AND d.application_id=? AND d.environment_id=?`, b.PlanID.String(), b.PlanDigest, adminID.String(), b.DeployOperationID.String(), b.ReleaseID.String(), b.ManifestDigest, b.DeploymentID.String(), b.ApplicationID.String(), b.EnvironmentID.String()).Scan(&raw, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return plan, domain.NewError(domain.ErrForbidden, "original lifecycle plan provenance mismatch")
	}
	if err != nil {
		return plan, err
	}
	if err := json.Unmarshal([]byte(raw), &plan); err != nil {
		return plan, fmt.Errorf("%w: decode lifecycle original plan: %v", ErrCorruptData, err)
	}
	plan.CreatedAt, err = ParseTime(created)
	if err != nil {
		return plan, fmt.Errorf("%w: lifecycle plan created_at: %v", ErrCorruptData, err)
	}
	plan.UpdatedAt, err = ParseTime(updated)
	if err != nil {
		return plan, fmt.Errorf("%w: lifecycle plan updated_at: %v", ErrCorruptData, err)
	}
	if err := appcontracts.ValidatePlanConsistency(plan); err != nil {
		return plan, fmt.Errorf("%w: lifecycle plan consistency: %v", ErrCorruptData, err)
	}
	if plan.Status != appcontracts.ImagePlanStatusPlanned || plan.CanonicalInput.Port != b.ContainerPort || plan.ResolvedImage.Digest != b.ManifestDigest {
		return plan, domain.NewError(domain.ErrForbidden, "lifecycle plan target mismatch")
	}
	return plan, nil
}
