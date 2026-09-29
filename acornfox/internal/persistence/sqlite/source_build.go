package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

var sourceBuildCommitPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
var _ appcontracts.SourceBuildFactsStore = (*Store)(nil)

func validSourceBuildDefinition(f appcontracts.SourceBuildDefinitionFact, r domain.SourceRevision) bool {
	if f.SourceRevisionID != r.ID || f.SourceDigest != r.ContentDigest || !validSha256Digest(f.DefinitionDigest) {
		return false
	}
	switch f.Status {
	case string(contracts.AcornFoxDockerfileReady):
		return validSha256Digest(f.DockerfileDigest)
	case string(contracts.AcornFoxDockerfileWaitingLater):
		return f.DockerfileDigest == ""
	case string(contracts.AcornFoxDockerfileUnsupported):
		return f.DockerfileDigest == "" || validSha256Digest(f.DockerfileDigest)
	default:
		return false
	}
}
func sourceBuildNow(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now().UTC()
	}
	return now.UTC()
}
func sourceBuildFence(b appcontracts.SourceBuildBinding, now time.Time) (appcontracts.TaskMutationRequest, error) {
	if b.TaskID.Empty() || b.OperationID.Empty() || b.ApplicationID.Empty() || strings.TrimSpace(b.Owner) == "" || b.CoreGeneration == 0 || b.LeaseGeneration == 0 || b.CoreGeneration > math.MaxInt64 || b.LeaseGeneration > math.MaxInt64 {
		return appcontracts.TaskMutationRequest{}, domain.ValidationError("valid source-build fence required")
	}
	return appcontracts.TaskMutationRequest{TaskID: b.TaskID, Owner: b.Owner, CoreGeneration: int64(b.CoreGeneration), LeaseGeneration: int64(b.LeaseGeneration), Now: sourceBuildNow(now)}, nil
}
func requireSourceBuildAdmin(ctx context.Context, tx *sql.Tx, admin domain.ID) error {
	var enabled int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM admin_credentials WHERE id=? AND disabled_at IS NULL`, admin.String()).Scan(&enabled); err != nil {
		return err
	}
	if enabled != 1 {
		return domain.NewError(domain.ErrUnauthorized, "administrator unavailable")
	}
	return nil
}
func sourceBuildJSON(value any) (string, error) {
	raw, err := json.Marshal(value)
	return string(raw), err
}
func sourceBuildID(prefix string) (domain.ID, error) { return domain.NewID(prefix) }
func commitSourceBuildFacts(tx *sql.Tx) error {
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: source-build transaction commit: %w", ErrOutcomeUnknown, err)
	}
	return nil
}
func validSourceEvidence(e appcontracts.SourceBuildEvidenceFact) bool {
	if len(e.Summary) > 4096 || !validSha256Digest(e.Digest) || !e.Redacted || len(e.Refs) == 0 || len(e.Refs) > 16 {
		return false
	}
	for _, ref := range e.Refs {
		if ref.Validate() != nil {
			return false
		}
	}
	return true
}
func validSourceResources(r appcontracts.SourceBuildResourcesFact) bool {
	return r.CPUMillis > 0 && r.MemoryBytes > 0 && r.DiskBytes > 0 && r.PIDs >= 0 && r.TimeoutSeconds > 0 && r.TimeoutSeconds <= 3600 && r.ConcurrencySlot == 1
}

// Reservation and original response reuse share the existing serialized
// idempotency transaction. Only the owning administrator's request hashes match.
func reserveSourceBuildKey(ctx context.Context, tx *sql.Tx, scope, key string, request any, now time.Time) (*appcontracts.SourceBuildIntentFact, error) {
	raw, err := sourceBuildJSON(request)
	if err != nil {
		return nil, err
	}
	digest := sha256Hex(raw)
	result, err := tx.ExecContext(ctx, `INSERT INTO idempotency_records(scope,idempotency_key,request_digest,status,created_at,updated_at) VALUES(?,?,?,'in_progress',?,?) ON CONFLICT(scope,idempotency_key) DO NOTHING`, scope, key, digest, FormatTime(now), FormatTime(now))
	if err != nil {
		return nil, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	var saved, status string
	var response sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT request_digest,status,response FROM idempotency_records WHERE scope=? AND idempotency_key=?`, scope, key).Scan(&saved, &status, &response); err != nil {
		return nil, err
	}
	if saved != digest {
		return nil, ErrIdempotencyConflict
	}
	if n == 0 {
		if status != "completed" || !response.Valid {
			return nil, ErrIdempotencyCorrupt
		}
		var fact appcontracts.SourceBuildIntentFact
		if err := json.Unmarshal([]byte(response.String), &fact); err != nil {
			return nil, ErrIdempotencyCorrupt
		}
		return &fact, nil
	}
	return nil, nil
}
func finishSourceBuildKey(ctx context.Context, tx *sql.Tx, scope, key string, f appcontracts.SourceBuildIntentFact, now time.Time) error {
	raw, err := sourceBuildJSON(f)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE idempotency_records SET status='completed',response=?,updated_at=? WHERE scope=? AND idempotency_key=? AND status='in_progress'`, raw, FormatTime(now), scope, key)
	return err
}
func appendSourceBuildEvidence(ctx context.Context, tx *sql.Tx, f appcontracts.SourceBuildIntentFact, action, result string, now time.Time) error {
	raw, err := sourceBuildJSON(map[string]any{"operation_id": f.OperationID, "application_id": f.ApplicationID, "intent_id": f.ID, "stage": f.Stage})
	if err != nil {
		return err
	}
	event, err := appendOutboxTx(ctx, tx, appcontracts.OutboxEvent{AggregateType: "operation", AggregateID: f.OperationID.String(), AggregateVersion: 1, EventType: action, CreatedAt: now, PayloadVersion: "1.0"}, func(string, int64) ([]byte, error) { return []byte(raw), nil })
	if err != nil {
		return err
	}
	id, err := sourceBuildID("audit")
	if err != nil {
		return err
	}
	actor := appcontracts.AuditContext{ActorType: "system", ActorID: "core-source-build", Reason: "fenced source-build fact"}
	if result == "accepted" {
		actor = auditContextFromAdmin(f.AdminID)
		actor.Reason = "source-build approved intent"
	}
	_, err = appendAuditTx(ctx, tx, auditInput{ID: id.String(), Actor: actor, Action: action, InputDigest: "sha256:" + sha256Hex(raw), Result: result, EvidenceRefs: []string{f.ApplicationID.String(), f.OperationID.String(), f.TaskID.String(), event.ID}, CreatedAt: now})
	return err
}
func insertSourceBuildOperation(ctx context.Context, tx *sql.Tx, f appcontracts.SourceBuildIntentFact, key string, now time.Time) error {
	stamp := FormatTime(now)
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations(id,application_id,environment_id,operation_type,idempotency_key,state,created_at,updated_at) VALUES(?,?,?,?,?,'pending',?,?)`, f.OperationID.String(), f.ApplicationID.String(), f.EnvironmentID.String(), "source_"+string(f.Stage), "source."+string(f.Stage)+":"+key, stamp, stamp); err != nil {
		return err
	}
	payload, err := sourceBuildJSON(map[string]any{"kind": "source." + string(f.Stage), "intent_id": f.ID, "application_id": f.ApplicationID})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO task_leases(task_id,operation_id,attempt,max_attempts,state,payload,created_at,updated_at) VALUES(?,?,0,?,'ready',?,?,?)`, f.TaskID.String(), f.OperationID.String(), defaultTaskMaxAttempts, payload, stamp, stamp)
	return err
}

// Creating this narrow source intent creates real app/environment rows itself;
// generic applications do not carry a per-admin ownership fact to borrow.
func (s *Store) CreateSourcePrepareIntent(ctx context.Context, admin domain.ID, in appcontracts.CreateSourcePrepareIntentInput) (appcontracts.SourceBuildIntentFact, error) {
	var zero appcontracts.SourceBuildIntentFact
	if err := s.checkOpen(); err != nil {
		return zero, err
	}
	if admin.Empty() {
		return zero, domain.NewError(domain.ErrUnauthorized, "administrator required")
	}
	in.AppName = strings.TrimSpace(in.AppName)
	in.Repository = strings.TrimSpace(in.Repository)
	in.IdempotencyKey = strings.TrimSpace(in.IdempotencyKey)
	u, err := url.Parse(in.Repository)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !sourceBuildCommitPattern.MatchString(in.Commit) || in.IdempotencyKey == "" || len(in.IdempotencyKey) > 256 || in.TimeoutSeconds <= 0 || in.TimeoutSeconds > 3600 || (in.ExpectedContentDigest != "" && !validSha256Digest(in.ExpectedContentDigest)) {
		return zero, domain.ValidationError("invalid pinned public source intent")
	}
	now := time.Now().UTC()
	app, err := domain.NewApplication(in.AppName, now)
	if err != nil {
		return zero, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	if err := requireSourceBuildAdmin(ctx, tx, admin); err != nil {
		return zero, err
	}
	replay, err := reserveSourceBuildKey(ctx, tx, "source.prepare", in.IdempotencyKey, struct {
		Admin domain.ID
		Input appcontracts.CreateSourcePrepareIntentInput
	}{admin, in}, now)
	if err != nil {
		return zero, err
	}
	if replay != nil {
		return *replay, nil
	}
	f := appcontracts.SourceBuildIntentFact{AdminID: admin, ApplicationID: app.ID, Stage: appcontracts.SourceBuildPrepare, State: "pending", Prepare: in, ProviderActor: "core-source-build"}
	for _, slot := range []struct {
		prefix string
		target *domain.ID
	}{{"spi", &f.ID}, {"env", &f.EnvironmentID}, {"op", &f.OperationID}, {"task", &f.TaskID}} {
		*slot.target, err = sourceBuildID(slot.prefix)
		if err != nil {
			return zero, err
		}
	}
	f.ProviderOperationKey = "source-prepare:" + f.ID.String()
	stamp := FormatTime(now)
	if _, err := tx.ExecContext(ctx, `INSERT INTO applications(id,name,version,created_at,updated_at) VALUES(?,?,1,?,?)`, app.ID.String(), app.Name, stamp, stamp); err != nil {
		return zero, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO environments(id,application_id,name,created_at) VALUES(?,?,?,?)`, f.EnvironmentID.String(), app.ID.String(), defaultEnvironmentName, stamp); err != nil {
		return zero, err
	}
	if err := insertSourceBuildOperation(ctx, tx, f, in.IdempotencyKey, now); err != nil {
		return zero, err
	}
	request, err := sourceBuildJSON(in)
	if err != nil {
		return zero, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO source_prepare_intents(id,admin_id,application_id,environment_id,operation_id,task_id,request,state,created_at) VALUES(?,?,?,?,?,?,?,'pending',?)`, f.ID.String(), admin.String(), f.ApplicationID.String(), f.EnvironmentID.String(), f.OperationID.String(), f.TaskID.String(), request, stamp); err != nil {
		return zero, err
	}
	if err := appendSourceBuildEvidence(ctx, tx, f, "source.prepare.accepted", "accepted", now); err != nil {
		return zero, err
	}
	if err := finishSourceBuildKey(ctx, tx, "source.prepare", in.IdempotencyKey, f, now); err != nil {
		return zero, err
	}
	if err := commitSourceBuildFacts(tx); err != nil {
		return zero, err
	}
	return f, nil
}

func (s *Store) ApproveSourceBuildPlan(ctx context.Context, admin domain.ID, in appcontracts.ApproveSourceBuildPlanInput) (appcontracts.SourceBuildIntentFact, error) {
	var zero appcontracts.SourceBuildIntentFact
	if err := s.checkOpen(); err != nil {
		return zero, err
	}
	if admin.Empty() {
		return zero, domain.NewError(domain.ErrUnauthorized, "administrator required")
	}
	in.IdempotencyKey = strings.TrimSpace(in.IdempotencyKey)
	if in.PrepareIntentID.Empty() || in.IdempotencyKey == "" || len(in.IdempotencyKey) > 256 || in.Plan.Validate() != nil || !validSourceResources(in.Policy.Resources) {
		return zero, domain.ValidationError("invalid approved build plan")
	}
	if in.Policy.NetworkMode != "none" && in.Policy.NetworkMode != "controlled_egress_v1" {
		return zero, domain.ValidationError("unsupported build network policy")
	}
	if (in.Policy.NetworkMode == "none" && in.Policy.WorkerPolicyDigest != "") || (in.Policy.NetworkMode == "controlled_egress_v1" && !validSha256Digest(in.Policy.WorkerPolicyDigest)) || in.Plan.AcornFoxNetworkMode != in.Policy.NetworkMode || in.Plan.AcornFoxWorkerPolicyDigest != in.Policy.WorkerPolicyDigest {
		return zero, domain.ValidationError("plan and worker network policy differ")
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	if err := requireSourceBuildAdmin(ctx, tx, admin); err != nil {
		return zero, err
	}
	replay, err := reserveSourceBuildKey(ctx, tx, "source.build", in.IdempotencyKey, struct {
		Admin domain.ID
		Input appcontracts.ApproveSourceBuildPlanInput
	}{admin, in}, now)
	if err != nil {
		return zero, err
	}
	if replay != nil {
		return *replay, nil
	}
	f, err := s.approveSourceBuildPlanTx(ctx, tx, admin, in, now)
	if err != nil {
		return zero, err
	}
	if err := commitSourceBuildFacts(tx); err != nil {
		return zero, err
	}
	return f, nil
}
func (s *Store) approveSourceBuildPlanTx(ctx context.Context, tx *sql.Tx, admin domain.ID, in appcontracts.ApproveSourceBuildPlanInput, now time.Time) (appcontracts.SourceBuildIntentFact, error) {
	var zero appcontracts.SourceBuildIntentFact
	var err error
	var f appcontracts.SourceBuildIntentFact
	var owner, state, revision, request string
	err = tx.QueryRowContext(ctx, `SELECT p.admin_id,p.application_id,p.environment_id,p.state,r.revision,p.request FROM source_prepare_intents p JOIN native_source_revisions r ON r.intent_id=p.id WHERE p.id=?`, in.PrepareIntentID.String()).Scan(&owner, &f.ApplicationID, &f.EnvironmentID, &state, &revision, &request)
	if errors.Is(err, sql.ErrNoRows) {
		return zero, domain.NewError(domain.ErrConflict, "actual prepared source fact is required")
	}
	if err != nil {
		return zero, err
	}
	if owner != admin.String() {
		return zero, domain.NewError(domain.ErrForbidden, "source intent belongs to another administrator")
	}
	if state != "prepared" {
		return zero, domain.NewError(domain.ErrConflict, "source is not prepared")
	}
	var source domain.SourceRevision
	if err := json.Unmarshal([]byte(revision), &source); err != nil || source.Validate() != nil || source.ApplicationID != f.ApplicationID {
		return zero, ErrCorruptData
	}
	if in.Plan.SourceRevisionID != source.ID || in.Plan.SourceDigest != source.ContentDigest {
		return zero, domain.NewError(domain.ErrConflict, "build plan does not bind actual prepared source")
	}
	if err := json.Unmarshal([]byte(request), &f.Prepare); err != nil {
		return zero, ErrCorruptData
	}
	f.AdminID = admin
	f.PrepareIntentID = in.PrepareIntentID
	f.Source = &source
	f.Plan = &in.Plan
	f.Policy = in.Policy
	f.Stage = appcontracts.SourceBuildBuild
	f.State = "pending"
	f.ProviderActor = "core-source-build"
	for _, slot := range []struct {
		prefix string
		target *domain.ID
	}{{"sbi", &f.ID}, {"build", &f.BuildID}, {"op", &f.OperationID}, {"task", &f.TaskID}} {
		*slot.target, err = sourceBuildID(slot.prefix)
		if err != nil {
			return zero, err
		}
	}
	f.ProviderOperationKey = "source-build:" + f.BuildID.String()
	if err := insertSourceBuildOperation(ctx, tx, f, in.IdempotencyKey, now); err != nil {
		return zero, err
	}
	plan, err := sourceBuildJSON(in.Plan)
	if err != nil {
		return zero, err
	}
	policy, err := sourceBuildJSON(in.Policy)
	if err != nil {
		return zero, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO source_build_intents(id,prepare_intent_id,source_revision_id,admin_id,application_id,environment_id,operation_id,task_id,build_id,plan_id,plan,policy,state,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'pending',?)`, f.ID.String(), in.PrepareIntentID.String(), source.ID.String(), admin.String(), f.ApplicationID.String(), f.EnvironmentID.String(), f.OperationID.String(), f.TaskID.String(), f.BuildID.String(), in.Plan.ID.String(), plan, policy, FormatTime(now)); err != nil {
		return zero, err
	}
	if err := appendSourceBuildEvidence(ctx, tx, f, "source.build.accepted", "accepted", now); err != nil {
		return zero, err
	}
	if err := finishSourceBuildKey(ctx, tx, "source.build", in.IdempotencyKey, f, now); err != nil {
		return zero, err
	}
	return f, nil
}

func (s *Store) readSourceBuildTx(ctx context.Context, tx *sql.Tx, b appcontracts.SourceBuildBinding, stage appcontracts.SourceBuildStage, now time.Time, bound bool) (appcontracts.SourceBuildIntentFact, error) {
	var f appcontracts.SourceBuildIntentFact
	fence, err := sourceBuildFence(b, now)
	if err != nil {
		return f, err
	}
	task, err := s.verifyTaskLeaseTx(ctx, tx, fence)
	if err != nil {
		return f, err
	}
	if task.OperationID != b.OperationID {
		return f, appcontracts.ErrLeaseLost
	}
	var deadline, sha sql.NullString
	var cg, lg sql.NullInt64
	var opState, kind, envApp string
	var request, revision, plan, policy string
	switch stage {
	case appcontracts.SourceBuildPrepare:
		err = tx.QueryRowContext(ctx, `SELECT p.id,p.admin_id,p.application_id,p.environment_id,p.operation_id,p.task_id,p.request,p.state,p.deadline,p.command_sha,p.bound_core_generation,p.bound_lease_generation,o.state,o.operation_type,e.application_id FROM source_prepare_intents p JOIN operations o ON o.id=p.operation_id JOIN environments e ON e.id=p.environment_id WHERE p.task_id=? AND p.operation_id=?`, b.TaskID.String(), b.OperationID.String()).Scan(&f.ID, &f.AdminID, &f.ApplicationID, &f.EnvironmentID, &f.OperationID, &f.TaskID, &request, &f.State, &deadline, &sha, &cg, &lg, &opState, &kind, &envApp)
		f.ProviderOperationKey = "source-prepare:" + f.ID.String()
	case appcontracts.SourceBuildBuild:
		err = tx.QueryRowContext(ctx, `SELECT b.id,b.admin_id,b.application_id,b.environment_id,b.operation_id,b.task_id,b.prepare_intent_id,b.build_id,b.plan,b.policy,b.state,b.deadline,b.command_sha,b.bound_core_generation,b.bound_lease_generation,p.request,r.revision,o.state,o.operation_type,e.application_id FROM source_build_intents b JOIN source_prepare_intents p ON p.id=b.prepare_intent_id AND p.admin_id=b.admin_id AND p.application_id=b.application_id AND p.environment_id=b.environment_id AND p.state='prepared' JOIN native_source_revisions r ON r.id=b.source_revision_id AND r.intent_id=p.id AND r.application_id=b.application_id JOIN operations o ON o.id=b.operation_id JOIN environments e ON e.id=b.environment_id WHERE b.task_id=? AND b.operation_id=?`, b.TaskID.String(), b.OperationID.String()).Scan(&f.ID, &f.AdminID, &f.ApplicationID, &f.EnvironmentID, &f.OperationID, &f.TaskID, &f.PrepareIntentID, &f.BuildID, &plan, &policy, &f.State, &deadline, &sha, &cg, &lg, &request, &revision, &opState, &kind, &envApp)
		f.ProviderOperationKey = "source-build:" + f.BuildID.String()
	default:
		return f, domain.NewError(domain.ErrConflict, "no persisted source-build control approval")
	}
	if errors.Is(err, sql.ErrNoRows) {
		return f, domain.NewError(domain.ErrForbidden, "source-build task is not bound to this stage")
	}
	if err != nil {
		return f, err
	}
	if err := requireSourceBuildAdmin(ctx, tx, f.AdminID); err != nil {
		return f, err
	}
	if f.ApplicationID != b.ApplicationID || envApp != f.ApplicationID.String() || kind != "source_"+string(stage) || (opState != "pending" && opState != "running" && opState != "waiting") || (f.State != "pending" && f.State != "running" && f.State != "waiting") {
		return f, appcontracts.ErrLeaseLost
	}
	if err := json.Unmarshal([]byte(request), &f.Prepare); err != nil {
		return f, ErrCorruptData
	}
	if stage == appcontracts.SourceBuildBuild {
		var src domain.SourceRevision
		var p domain.BuildPlan
		if json.Unmarshal([]byte(revision), &src) != nil || json.Unmarshal([]byte(plan), &p) != nil || json.Unmarshal([]byte(policy), &f.Policy) != nil || src.Validate() != nil || p.Validate() != nil || src.ApplicationID != f.ApplicationID || p.SourceRevisionID != src.ID || p.SourceDigest != src.ContentDigest {
			return f, ErrCorruptData
		}
		f.Source = &src
		f.Plan = &p

	}
	f.Stage = stage
	f.ProviderActor = "core-source-build"
	f.RecoveryRequired = f.State == "waiting" || (f.State == "running" && sha.Valid && (cg.Int64 != fence.CoreGeneration || lg.Int64 != fence.LeaseGeneration))
	f.CommandSHA256 = sha.String
	if deadline.Valid {
		f.Deadline, err = ParseTime(deadline.String)
		if err != nil {
			return f, ErrCorruptData
		}
	}
	if bound && (!cg.Valid || !lg.Valid || cg.Int64 != fence.CoreGeneration || lg.Int64 != fence.LeaseGeneration || !f.Deadline.After(fence.Now)) {
		return f, appcontracts.ErrLeaseLost
	}
	return f, nil
}

// Trusted Core-only composition entry. Never register this as a role RPC.
// Unknown outcomes retain their recovery flag; this does not approve a retry.
func (s *Store) BeginSourceBuildStage(ctx context.Context, in appcontracts.BeginSourceBuildStageInput) (appcontracts.SourceBuildIntentFact, error) {
	var zero appcontracts.SourceBuildIntentFact
	if err := s.checkOpen(); err != nil {
		return zero, err
	}
	now := sourceBuildNow(in.Now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	f, err := s.readSourceBuildTx(ctx, tx, in.Binding, in.Stage, now, false)
	if err != nil {
		return zero, err
	}
	// A live, renewed task lease cannot reopen an expired sealed operation.
	// Preserve the original input digest/deadline as recovery evidence.
	if f.CommandSHA256 != "" && !f.Deadline.After(now) {
		table := "source_prepare_intents"
		if in.Stage == appcontracts.SourceBuildBuild {
			table = "source_build_intents"
		}
		if _, err := tx.ExecContext(ctx, `UPDATE `+table+` SET state='waiting' WHERE id=?`, f.ID.String()); err != nil {
			return zero, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE operations SET state='waiting',updated_at=max(updated_at,?) WHERE id=?`, FormatTime(now), f.OperationID.String()); err != nil {
			return zero, err
		}
		if err := commitSourceBuildFacts(tx); err != nil {
			return zero, err
		}
		f.State = "waiting"
		f.RecoveryRequired = true
		return f, nil
	}
	// A composition repeated in one claim must not revoke its own active permit.
	if current, err := s.readSourceBuildTx(ctx, tx, in.Binding, in.Stage, now, true); err == nil && current.CommandSHA256 != "" {
		if err := commitSourceBuildFacts(tx); err != nil {
			return zero, err
		}
		return current, nil
	}
	fence, _ := sourceBuildFence(in.Binding, now)
	task, err := s.verifyTaskLeaseTx(ctx, tx, fence)
	if err != nil {
		return zero, err
	}
	timeout := f.Prepare.TimeoutSeconds
	table := "source_prepare_intents"
	if in.Stage == appcontracts.SourceBuildBuild {
		table = "source_build_intents"
		timeout = f.Policy.Resources.TimeoutSeconds
	}
	if timeout <= 0 || timeout > 3600 {
		return zero, ErrCorruptData
	}
	// Execution budget belongs to the approved operation, independently from
	// the short renewable task lease checked for every authority/commit action.
	deadline := now.Add(time.Duration(timeout) * time.Second)
	if task.LeaseUntil == nil {
		return zero, appcontracts.ErrLeaseLost
	}

	if !deadline.After(now) {
		return zero, appcontracts.ErrLeaseLost
	}
	f.Deadline = deadline
	f.CommandSHA256 = ""
	if _, err := tx.ExecContext(ctx, `UPDATE `+table+` SET deadline=?,command_sha=NULL,bound_core_generation=?,bound_lease_generation=? WHERE id=?`, FormatTime(deadline), fence.CoreGeneration, fence.LeaseGeneration, f.ID.String()); err != nil {
		return zero, err
	}

	if f.RecoveryRequired {
		if _, err := tx.ExecContext(ctx, `UPDATE `+table+` SET state='waiting' WHERE id=?`, f.ID.String()); err != nil {
			return zero, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE operations SET state='waiting',updated_at=max(updated_at,?) WHERE id=?`, FormatTime(now), f.OperationID.String()); err != nil {
			return zero, err
		}
		f.State = "waiting"
	}
	if !f.RecoveryRequired {
		if _, err := tx.ExecContext(ctx, `UPDATE `+table+` SET state='running' WHERE id=?`, f.ID.String()); err != nil {
			return zero, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE operations SET state='running',updated_at=max(updated_at,?) WHERE id=?`, FormatTime(now), f.OperationID.String()); err != nil {
			return zero, err
		}
		f.State = "running"
	}
	if err := commitSourceBuildFacts(tx); err != nil {
		return zero, err
	}
	return f, nil
}
func (s *Store) ReadSourceBuildAuthority(ctx context.Context, b appcontracts.SourceBuildBinding, stage appcontracts.SourceBuildStage, now time.Time) (appcontracts.SourceBuildIntentFact, error) {
	var zero appcontracts.SourceBuildIntentFact
	if err := s.checkOpen(); err != nil {
		return zero, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	return s.readSourceBuildTx(ctx, tx, b, stage, sourceBuildNow(now), true)
}

// Only the trusted Core composer may seal a command reconstructed from facts.
// The authorizer given to the role exposes ONLY AuthorizeSourceBuild, not this.
func (s *Store) BindSourceBuildCommand(ctx context.Context, b appcontracts.SourceBuildBinding, stage appcontracts.SourceBuildStage, sha string, now time.Time) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if !validSha256Digest(sha) {
		return domain.ValidationError("valid command digest required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	f, err := s.readSourceBuildTx(ctx, tx, b, stage, sourceBuildNow(now), true)
	if err != nil {
		return err
	}
	if f.RecoveryRequired {
		return domain.NewError(domain.ErrConflict, "unknown outcome requires reconciliation")
	}
	if f.CommandSHA256 != "" && f.CommandSHA256 != sha {
		return domain.NewError(domain.ErrConflict, "active command cannot be replaced")
	}
	table := "source_prepare_intents"
	if stage == appcontracts.SourceBuildBuild {
		table = "source_build_intents"
	}
	if _, err := tx.ExecContext(ctx, `UPDATE `+table+` SET command_sha=? WHERE id=?`, sha, f.ID.String()); err != nil {
		return err
	}
	return commitSourceBuildFacts(tx)
}
func (s *Store) CommitPreparedSource(ctx context.Context, in appcontracts.CommitPreparedSourceInput) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	now := sourceBuildNow(in.Now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	f, err := s.readSourceBuildTx(ctx, tx, in.Binding, appcontracts.SourceBuildPrepare, now, true)
	if err != nil {
		return err
	}
	r := in.Revision
	if f.RecoveryRequired || f.CommandSHA256 == "" || in.CommandSHA256 != f.CommandSHA256 || r.Validate() != nil || r.Kind != domain.SourceGitHTTPS || r.ApplicationID != f.ApplicationID || r.Locator != f.Prepare.Repository || r.Ref != f.Prepare.Commit || r.Commit != f.Prepare.Commit || !validSha256Digest(r.ContentDigest) || (f.Prepare.ExpectedContentDigest != "" && r.ContentDigest != f.Prepare.ExpectedContentDigest) || r.CreatedAt.IsZero() || r.CreatedAt.After(now.Add(time.Minute)) || !validSourceEvidence(in.Evidence) || in.Evidence.Digest != r.ContentDigest || !validSourceBuildDefinition(in.Definition, r) {
		return domain.ValidationError("actual approved immutable source receipt required")
	}
	revision, err := sourceBuildJSON(r)
	if err != nil {
		return err
	}
	evidence, err := sourceBuildJSON(in.Evidence)
	if err != nil {
		return err
	}
	definition, err := sourceBuildJSON(in.Definition)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO native_source_revisions(id,intent_id,application_id,revision,evidence,definition,created_at) VALUES(?,?,?,?,?,?,?)`, r.ID.String(), f.ID.String(), f.ApplicationID.String(), revision, evidence, definition, FormatTime(now)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE source_prepare_intents SET state='prepared' WHERE id=?`, f.ID.String()); err != nil {
		return err
	}
	return s.completeSourceBuildTx(ctx, tx, f, in.Binding, now, "source.prepare.completed")
}
func (s *Store) CommitSourceBuildOutput(ctx context.Context, in appcontracts.CommitSourceBuildOutputInput) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	now := sourceBuildNow(in.Now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	f, err := s.readSourceBuildTx(ctx, tx, in.Binding, appcontracts.SourceBuildBuild, now, true)
	if err != nil {
		return err
	}
	if f.RecoveryRequired || f.CommandSHA256 == "" || in.CommandSHA256 != f.CommandSHA256 || f.Plan == nil || in.Build.ID != f.BuildID || in.Build.PlanID != f.Plan.ID || in.Build.Status != domain.BuildSucceeded || in.Artifact.Validate() != nil || in.Artifact.BuildID != f.BuildID || in.Build.ArtifactID != in.Artifact.ID || in.Artifact.Image.Repository != f.Plan.TargetRepository || strings.TrimSpace(in.LogRef) == "" || !validSourceEvidence(in.Evidence) {
		return domain.ValidationError("actual approved build/artifact receipt required")
	}
	build, err := sourceBuildJSON(in.Build)
	if err != nil {
		return err
	}
	artifact, err := sourceBuildJSON(in.Artifact)
	if err != nil {
		return err
	}
	evidence, err := sourceBuildJSON(in.Evidence)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO source_build_results(intent_id,build_id,artifact_id,build,artifact,log_ref,evidence,created_at) VALUES(?,?,?,?,?,?,?,?)`, f.ID.String(), f.BuildID.String(), in.Artifact.ID.String(), build, artifact, in.LogRef, evidence, FormatTime(now)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE source_build_intents SET state='succeeded' WHERE id=?`, f.ID.String()); err != nil {
		return err
	}
	return s.completeSourceBuildTx(ctx, tx, f, in.Binding, now, "source.build.completed")
}
func (s *Store) completeSourceBuildTx(ctx context.Context, tx *sql.Tx, f appcontracts.SourceBuildIntentFact, b appcontracts.SourceBuildBinding, now time.Time, event string) error {
	fence, err := sourceBuildFence(b, now)
	if err != nil {
		return err
	}
	if _, err := s.mutateTaskTx(ctx, tx, fence, "completed", ""); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE operations SET state='succeeded',updated_at=max(updated_at,?) WHERE id=?`, FormatTime(now), f.OperationID.String()); err != nil {
		return err
	}
	if err := appendSourceBuildEvidence(ctx, tx, f, event, "succeeded", now); err != nil {
		return err
	}
	return commitSourceBuildFacts(tx)
}
func (s *Store) RecordSourceBuildUnknown(ctx context.Context, b appcontracts.SourceBuildBinding, stage appcontracts.SourceBuildStage, reason string, now time.Time) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	now = sourceBuildNow(now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	f, err := s.readSourceBuildTx(ctx, tx, b, stage, now, true)
	if err != nil {
		return err
	}
	table := "source_prepare_intents"
	if stage == appcontracts.SourceBuildBuild {
		table = "source_build_intents"
	}
	fence, _ := sourceBuildFence(b, now)
	task, err := s.verifyTaskLeaseTx(ctx, tx, fence)
	if err != nil {
		return err
	}
	if task.Attempt >= task.MaxAttempts {
		reason = "needs_action: source-build attempt budget exhausted; " + reason
	}
	reason = cleanLastErrorReason(reason)
	if _, err := s.mutateTaskTx(ctx, tx, fence, "ready", reason); err != nil {
		return err
	}
	diagnostic, err := tx.ExecContext(ctx, `UPDATE task_leases SET last_error=? WHERE task_id=? AND operation_id=? AND state='ready' AND core_generation=? AND lease_generation=?`, reason, b.TaskID.String(), b.OperationID.String(), fence.CoreGeneration, fence.LeaseGeneration)
	if err != nil {
		return err
	}
	changed, err := diagnostic.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return appcontracts.ErrLeaseLost
	}
	if _, err := tx.ExecContext(ctx, `UPDATE `+table+` SET state='waiting' WHERE id=?`, f.ID.String()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE operations SET state='waiting',failure_reason=?,updated_at=max(updated_at,?) WHERE id=?`, reason, FormatTime(now), f.OperationID.String()); err != nil {
		return err
	}
	if err := appendSourceBuildEvidence(ctx, tx, f, "source."+string(stage)+".unknown", "unknown", now); err != nil {
		return err
	}
	return commitSourceBuildFacts(tx)
}

// Core may reconstruct a build plan from the persisted random source identity
// after a restart, rather than borrowing the role's process-local result cache.
func (s *Store) ReadPreparedSource(ctx context.Context, admin, intent domain.ID) (domain.SourceRevision, error) {
	var revision domain.SourceRevision
	if err := s.checkOpen(); err != nil {
		return revision, err
	}
	if admin.Empty() {
		return revision, domain.NewError(domain.ErrUnauthorized, "administrator required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return revision, err
	}
	defer tx.Rollback()
	if err := requireSourceBuildAdmin(ctx, tx, admin); err != nil {
		return revision, err
	}
	var owner, app, id, raw, state string
	err = tx.QueryRowContext(ctx, `SELECT p.admin_id,p.application_id,r.id,r.revision,p.state FROM source_prepare_intents p JOIN native_source_revisions r ON r.intent_id=p.id AND r.application_id=p.application_id WHERE p.id=?`, intent.String()).Scan(&owner, &app, &id, &raw, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return revision, ErrNotFound
	}
	if err != nil {
		return revision, err
	}
	if owner != admin.String() {
		return revision, domain.NewError(domain.ErrForbidden, "prepared source belongs to another administrator")
	}
	if state != "prepared" || json.Unmarshal([]byte(raw), &revision) != nil || revision.Validate() != nil || revision.ID.String() != id || revision.ApplicationID.String() != app || !validSha256Digest(revision.ContentDigest) {
		return domain.SourceRevision{}, ErrCorruptData
	}
	return revision, nil
}
