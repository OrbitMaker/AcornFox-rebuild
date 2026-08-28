package ledger

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// PostgresStore persists each evidence phase as an immutable row.  It accepts
// a caller-owned *sql.DB so the existing control-plane Store can expose DB()
// without creating a second connection pool.
type PostgresStore struct{ db *sql.DB }

func NewPostgres(db *sql.DB) *PostgresStore       { return &PostgresStore{db: db} }
func NewPostgresLedger(db *sql.DB) *PostgresStore { return NewPostgres(db) }

func (s *PostgresStore) requireDB() error {
	if s == nil || s.db == nil {
		return ErrInvalid
	}
	return nil
}
func (s *PostgresStore) DB() *sql.DB {
	if s == nil {
		return nil
	}
	return s.db
}

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func appendPayload(exec sqlExecutor, ctx context.Context, table, id, key, digest string, payload any, columns string, values ...any) (bool, []byte, error) {
	// Older call sites kept an explicit placeholder string next to the column
	// list while this helper now derives placeholders from values.  Accept that
	// harmless spelling so the persistence boundary remains easy to review.
	if len(values) > 0 {
		if placeholder, ok := values[0].(string); ok && strings.HasPrefix(placeholder, "$4") {
			values = values[1:]
		}
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return false, nil, fmt.Errorf("%w: marshal %s payload: %v", ErrInvalid, table, err)
	}
	if err := ValidateNoPlaintext(payload); err != nil {
		return false, nil, err
	}
	query := fmt.Sprintf("INSERT INTO %s (id,idempotency_key,request_digest,%s,payload) VALUES ($1,$2,$3,%s,$%d::jsonb) ON CONFLICT (idempotency_key) DO NOTHING", table, columns, placeholders(4, len(values)), len(values)+4)
	args := make([]any, 0, len(values)+4)
	args = append(args, id, key, digest)
	args = append(args, values...)
	args = append(args, data)
	result, err := exec.ExecContext(ctx, query, args...)
	if err != nil {
		return false, nil, fmt.Errorf("append %s: %w", table, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, nil, err
	}
	if rows == 1 {
		return false, data, nil
	}
	var storedDigest string
	var stored []byte
	if err := exec.QueryRowContext(ctx, fmt.Sprintf("SELECT request_digest,payload FROM %s WHERE idempotency_key=$1", table), key).Scan(&storedDigest, &stored); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil, ErrCorrupt
		}
		return false, nil, err
	}
	if storedDigest != digest {
		return false, nil, ErrConflict
	}
	if len(stored) == 0 || !json.Valid(stored) {
		return false, nil, ErrCorrupt
	}
	return true, stored, nil
}

func placeholders(start, count int) string {
	values := make([]string, count)
	for i := range values {
		values[i] = fmt.Sprintf("$%d", start+i)
	}
	return strings.Join(values, ",")
}

func (s *PostgresStore) AppendInvocation(ctx context.Context, request AppendInvocationRequest) (Invocation, bool, error) {
	if err := checkContext(ctx); err != nil {
		return Invocation{}, false, err
	}
	if err := s.requireDB(); err != nil {
		return Invocation{}, false, err
	}
	record := cloneInvocation(request.Record)
	key, digest, err := normalizeRequest(firstNonEmpty(request.IdempotencyKey, record.IdempotencyKey), firstNonEmpty(request.RequestDigest, record.RequestDigest), record, record.ID)
	if err != nil {
		return Invocation{}, false, err
	}
	record.ID = ensureID("aiinv", record.ID, key, digest)
	record.IdempotencyKey, record.RequestDigest = key, digest
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if err := validateInvocation(record); err != nil {
		return Invocation{}, false, err
	}
	replayed, payload, err := appendPayload(s.db, ctx, "m6_ai_invocations", record.ID, key, digest, record, "task_type,application_id,problem_fingerprint,version_key,cache_key,provider,model,policy_version,profile,context_id,status,outcome,tokens,duration_ms,cpu_seconds,memory_bytes,disk_bytes,network_rx_bytes,network_tx_bytes,peak_memory_bytes,candidate_id,created_at", "$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25", record.TaskType, record.ApplicationID, record.ProblemFingerprint, record.VersionKey, record.CacheKey, record.Provider, record.Model, record.PolicyVersion, record.Profile, record.ContextID, record.Status, record.Outcome, record.Tokens, record.DurationMS, record.Resource.CPUSeconds, record.Resource.MemoryBytes, record.Resource.DiskBytes, record.Resource.NetworkRxBytes, record.Resource.NetworkTxBytes, record.Resource.PeakMemoryBytes, record.CandidateID, record.CreatedAt.UTC())
	if err != nil {
		return Invocation{}, false, err
	}
	if replayed {
		var existing Invocation
		if json.Unmarshal(payload, &existing) != nil {
			return Invocation{}, false, ErrCorrupt
		}
		return existing, true, nil
	}
	return record, false, nil
}

func (s *PostgresStore) AppendContext(ctx context.Context, request AppendContextRequest) (ContextPackage, bool, error) {
	if err := checkContext(ctx); err != nil {
		return ContextPackage{}, false, err
	}
	if err := s.requireDB(); err != nil {
		return ContextPackage{}, false, err
	}
	record := cloneContext(request.Record)
	key, digest, err := normalizeRequest(firstNonEmpty(request.IdempotencyKey, record.IdempotencyKey), firstNonEmpty(request.RequestDigest, record.RequestDigest), record, record.ID)
	if err != nil {
		return ContextPackage{}, false, err
	}
	record.ID = ensureID("aictx", record.ID, key, digest)
	record.IdempotencyKey, record.RequestDigest = key, digest
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if err := validateContext(record); err != nil {
		return ContextPackage{}, false, err
	}
	scope, _ := json.Marshal(record.Scope)
	refs, _ := json.Marshal(record.SourceRefs)
	replayed, payload, err := appendPayload(s.db, ctx, "m6_ai_context_packages", record.ID, key, digest, record, "invocation_id,scope,source_refs,authorized,redacted,template_version,profile,retention,created_at", "$4,$5::jsonb,$6::jsonb,$7,$8,$9,$10,$11,$12", record.InvocationID, scope, refs, record.Authorized, record.Redacted, record.TemplateVersion, record.Profile, record.Retention, record.CreatedAt.UTC())
	if err != nil {
		return ContextPackage{}, false, err
	}
	if replayed {
		var existing ContextPackage
		if json.Unmarshal(payload, &existing) != nil {
			return ContextPackage{}, false, ErrCorrupt
		}
		return existing, true, nil
	}
	return record, false, nil
}

func (s *PostgresStore) AppendPlan(ctx context.Context, request AppendPlanRequest) (ActionPlan, bool, error) {
	if err := checkContext(ctx); err != nil {
		return ActionPlan{}, false, err
	}
	if err := s.requireDB(); err != nil {
		return ActionPlan{}, false, err
	}
	record := clonePlan(request.Record)
	key, digest, err := normalizeRequest(firstNonEmpty(request.IdempotencyKey, record.IdempotencyKey), firstNonEmpty(request.RequestDigest, record.RequestDigest), record, record.ID)
	if err != nil {
		return ActionPlan{}, false, err
	}
	record.ID = ensureID("aiplan", record.ID, key, digest)
	record.IdempotencyKey, record.RequestDigest = key, digest
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if err := validatePlan(record); err != nil {
		return ActionPlan{}, false, err
	}
	targets, _ := json.Marshal(record.TargetRefs)
	assumptions, _ := json.Marshal(record.Assumptions)
	refs, _ := json.Marshal(record.EvidenceRefs)
	actions, _ := json.Marshal(record.Actions)
	replayed, payload, err := appendPayload(s.db, ctx, "m6_ai_action_plans", record.ID, key, digest, record, "invocation_id,task_type,target_refs,assumptions,evidence_refs,actions,rollback_id,confidence,requires_user_confirmation,schema_version,created_at", "$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9::jsonb,$10,$11,$12,$13,$14", record.InvocationID, record.TaskType, targets, assumptions, refs, actions, record.RollbackID, record.Confidence, record.RequiresUserConfirmation, record.SchemaVersion, record.CreatedAt.UTC())
	if err != nil {
		return ActionPlan{}, false, err
	}
	if replayed {
		var existing ActionPlan
		if json.Unmarshal(payload, &existing) != nil {
			return ActionPlan{}, false, ErrCorrupt
		}
		return existing, true, nil
	}
	return record, false, nil
}

func (s *PostgresStore) AppendToolAction(ctx context.Context, request AppendToolActionRequest) (ToolAction, bool, error) {
	if err := checkContext(ctx); err != nil {
		return ToolAction{}, false, err
	}
	if err := s.requireDB(); err != nil {
		return ToolAction{}, false, err
	}
	record := cloneAction(request.Record)
	key, digest, err := normalizeRequest(firstNonEmpty(request.IdempotencyKey, record.IdempotencyKey), firstNonEmpty(request.RequestDigest, record.RequestDigest), record, record.ID)
	if err != nil {
		return ToolAction{}, false, err
	}
	record.ID = ensureID("aiaction", record.ID, key, digest)
	record.IdempotencyKey, record.RequestDigest = key, digest
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if err := validateAction(record); err != nil {
		return ToolAction{}, false, err
	}
	params, _ := json.Marshal(record.Parameters)
	bounds, _ := json.Marshal(record.Bounds)
	replayed, payload, err := appendPayload(s.db, ctx, "m6_ai_tool_actions", record.ID, key, digest, record, "invocation_id,plan_id,sequence,tool_id,tool_version,parameters,workspace_ref,risk_class,validation_id,bounds,network,timeout_ms,status,output_digest,diff_digest,created_at", "$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13::jsonb,$14,$15,$16,$17,$18,$19", record.InvocationID, record.PlanID, record.Sequence, record.ToolID, record.ToolVersion, params, record.WorkspaceRef, record.RiskClass, record.ValidationID, bounds, record.Network, record.TimeoutMS, record.Status, record.OutputDigest, record.DiffDigest, record.CreatedAt.UTC())
	if err != nil {
		return ToolAction{}, false, err
	}
	if replayed {
		var existing ToolAction
		if json.Unmarshal(payload, &existing) != nil {
			return ToolAction{}, false, ErrCorrupt
		}
		return existing, true, nil
	}
	return record, false, nil
}

func (s *PostgresStore) AppendVerification(ctx context.Context, request AppendVerificationRequest) (Verification, bool, error) {
	if err := checkContext(ctx); err != nil {
		return Verification{}, false, err
	}
	if err := s.requireDB(); err != nil {
		return Verification{}, false, err
	}
	record := cloneVerification(request.Record)
	key, digest, err := normalizeRequest(firstNonEmpty(request.IdempotencyKey, record.IdempotencyKey), firstNonEmpty(request.RequestDigest, record.RequestDigest), record, record.ID)
	if err != nil {
		return Verification{}, false, err
	}
	record.ID = ensureID("aiver", record.ID, key, digest)
	record.IdempotencyKey, record.RequestDigest = key, digest
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if err := validateVerification(record); err != nil {
		return Verification{}, false, err
	}
	refs, _ := json.Marshal(record.EvidenceRefs)
	replayed, payload, err := appendPayload(s.db, ctx, "m6_ai_verifications", record.ID, key, digest, record, "invocation_id,plan_id,action_id,validator_id,passed,evidence_refs,summary,created_at", "$4,$5,$6,$7,$8,$9::jsonb,$10,$11", record.InvocationID, record.PlanID, record.ActionID, record.ValidatorID, record.Passed, refs, record.Summary, record.CreatedAt.UTC())
	if err != nil {
		return Verification{}, false, err
	}
	if replayed {
		var existing Verification
		if json.Unmarshal(payload, &existing) != nil {
			return Verification{}, false, ErrCorrupt
		}
		return existing, true, nil
	}
	return record, false, nil
}

func (s *PostgresStore) AppendRollback(ctx context.Context, request AppendRollbackRequest) (Rollback, bool, error) {
	if err := checkContext(ctx); err != nil {
		return Rollback{}, false, err
	}
	if err := s.requireDB(); err != nil {
		return Rollback{}, false, err
	}
	record := cloneRollback(request.Record)
	key, digest, err := normalizeRequest(firstNonEmpty(request.IdempotencyKey, record.IdempotencyKey), firstNonEmpty(request.RequestDigest, record.RequestDigest), record, record.ID)
	if err != nil {
		return Rollback{}, false, err
	}
	record.ID = ensureID("airollback", record.ID, key, digest)
	record.IdempotencyKey, record.RequestDigest = key, digest
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if err := validateRollback(record); err != nil {
		return Rollback{}, false, err
	}
	refs, _ := json.Marshal(record.EvidenceRefs)
	replayed, payload, err := appendPayload(s.db, ctx, "m6_ai_rollbacks", record.ID, key, digest, record, "invocation_id,plan_id,rollback_id,status,reason,evidence_refs,created_at", "$4,$5,$6,$7,$8,$9::jsonb,$10", record.InvocationID, record.PlanID, record.RollbackID, record.Status, record.Reason, refs, record.CreatedAt.UTC())
	if err != nil {
		return Rollback{}, false, err
	}
	if replayed {
		var existing Rollback
		if json.Unmarshal(payload, &existing) != nil {
			return Rollback{}, false, ErrCorrupt
		}
		return existing, true, nil
	}
	return record, false, nil
}

func (s *PostgresStore) AppendOutcome(ctx context.Context, request AppendOutcomeRequest) (Outcome, bool, error) {
	if err := checkContext(ctx); err != nil {
		return Outcome{}, false, err
	}
	if err := s.requireDB(); err != nil {
		return Outcome{}, false, err
	}
	record := request.Record
	key, digest, err := normalizeRequest(firstNonEmpty(request.IdempotencyKey, record.IdempotencyKey), firstNonEmpty(request.RequestDigest, record.RequestDigest), record, record.ID)
	if err != nil {
		return Outcome{}, false, err
	}
	record.ID = ensureID("aioutcome", record.ID, key, digest)
	record.IdempotencyKey, record.RequestDigest = key, digest
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if err := validateOutcome(record); err != nil {
		return Outcome{}, false, err
	}
	resource, _ := json.Marshal(record.Resource)
	replayed, payload, err := appendPayload(s.db, ctx, "m6_ai_outcomes", record.ID, key, digest, record, "invocation_id,status,exit_code,summary,user_confirmed,rolled_back,failure_code,resource,tokens,duration_ms,candidate_id,created_at", "$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$14,$15", record.InvocationID, record.Status, record.ExitCode, record.Summary, record.UserConfirmed, record.RolledBack, record.FailureCode, resource, record.Tokens, record.DurationMS, record.CandidateID, record.CreatedAt.UTC())
	if err != nil {
		return Outcome{}, false, err
	}
	if replayed {
		var existing Outcome
		if json.Unmarshal(payload, &existing) != nil {
			return Outcome{}, false, ErrCorrupt
		}
		return existing, true, nil
	}
	return record, false, nil
}

func (s *PostgresStore) AppendCandidateRef(ctx context.Context, request AppendCandidateRefRequest) (CandidateRef, bool, error) {
	if err := checkContext(ctx); err != nil {
		return CandidateRef{}, false, err
	}
	if err := s.requireDB(); err != nil {
		return CandidateRef{}, false, err
	}
	record := request.Record
	key, digest, err := normalizeRequest(firstNonEmpty(request.IdempotencyKey, record.IdempotencyKey), firstNonEmpty(request.RequestDigest, record.RequestDigest), record, record.ID)
	if err != nil {
		return CandidateRef{}, false, err
	}
	record.ID = ensureID("aicandidate", record.ID, key, digest)
	record.IdempotencyKey, record.RequestDigest = key, digest
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if err := validateCandidateRef(record); err != nil {
		return CandidateRef{}, false, err
	}
	var resolvedInvocationID string
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM m6_ai_invocations WHERE id=$1 OR id LIKE '%_' || $1 ORDER BY CASE WHEN id=$1 THEN 0 ELSE 1 END, created_at DESC, id DESC LIMIT 1`, record.InvocationID).Scan(&resolvedInvocationID); err == nil {
		record.InvocationID = resolvedInvocationID
	}
	replayed, payload, err := appendPayload(s.db, ctx, "m6_ai_candidate_refs", record.ID, key, digest, record, "invocation_id,candidate_id,fingerprint,aggregation,status,created_at", "$4,$5,$6,$7,$8,$9", record.InvocationID, record.CandidateID, record.Fingerprint, record.Aggregation, record.Status, record.CreatedAt.UTC())
	if err != nil {
		return CandidateRef{}, false, err
	}
	if replayed {
		var existing CandidateRef
		if json.Unmarshal(payload, &existing) != nil {
			return CandidateRef{}, false, ErrCorrupt
		}
		return existing, true, nil
	}
	return record, false, nil
}

func (s *PostgresStore) AppendIntervention(ctx context.Context, request AppendInterventionRequest) (Intervention, bool, error) {
	if err := checkContext(ctx); err != nil {
		return Intervention{}, false, err
	}
	if err := s.requireDB(); err != nil {
		return Intervention{}, false, err
	}
	record := cloneIntervention(request.Record)
	key, digest, err := normalizeRequest(firstNonEmpty(request.IdempotencyKey, record.Invocation.IdempotencyKey), firstNonEmpty(request.RequestDigest, record.Invocation.RequestDigest), record, record.ID)
	if err != nil {
		return Intervention{}, false, err
	}
	record.ID = ensureID("aiint", record.ID, key, digest)
	record.Invocation.ID = ensureID("aiinv", record.Invocation.ID, key, digest)
	record.Invocation.IdempotencyKey, record.Invocation.RequestDigest = key, digest
	if record.Invocation.CreatedAt.IsZero() {
		record.Invocation.CreatedAt = time.Now().UTC()
	}
	if record.Context != nil {
		record.Context.InvocationID = firstNonEmpty(record.Context.InvocationID, record.Invocation.ID)
		record.Context.IdempotencyKey = firstNonEmpty(record.Context.IdempotencyKey, key+":context")
		record.Context.RequestDigest = firstNonEmpty(record.Context.RequestDigest, Digest(*record.Context))
		record.Context.ID = ensureID("aictx", record.Context.ID, record.Context.IdempotencyKey, record.Context.RequestDigest)
		if record.Context.CreatedAt.IsZero() {
			record.Context.CreatedAt = record.Invocation.CreatedAt
		}
	}
	if record.Plan != nil {
		record.Plan.InvocationID = firstNonEmpty(record.Plan.InvocationID, record.Invocation.ID)
		record.Plan.IdempotencyKey = firstNonEmpty(record.Plan.IdempotencyKey, key+":plan")
		record.Plan.RequestDigest = firstNonEmpty(record.Plan.RequestDigest, Digest(*record.Plan))
		record.Plan.ID = ensureID("aiplan", record.Plan.ID, record.Plan.IdempotencyKey, record.Plan.RequestDigest)
		if record.Plan.CreatedAt.IsZero() {
			record.Plan.CreatedAt = record.Invocation.CreatedAt
		}
	}
	for i := range record.Actions {
		record.Actions[i].InvocationID = firstNonEmpty(record.Actions[i].InvocationID, record.Invocation.ID)
		record.Actions[i].IdempotencyKey = firstNonEmpty(record.Actions[i].IdempotencyKey, fmt.Sprintf("%s:action:%d", key, i))
		record.Actions[i].RequestDigest = firstNonEmpty(record.Actions[i].RequestDigest, Digest(record.Actions[i]))
		record.Actions[i].ID = ensureID("aiaction", record.Actions[i].ID, record.Actions[i].IdempotencyKey, record.Actions[i].RequestDigest)
		if record.Actions[i].CreatedAt.IsZero() {
			record.Actions[i].CreatedAt = record.Invocation.CreatedAt
		}
	}
	for i := range record.Verifications {
		record.Verifications[i].InvocationID = firstNonEmpty(record.Verifications[i].InvocationID, record.Invocation.ID)
		record.Verifications[i].IdempotencyKey = firstNonEmpty(record.Verifications[i].IdempotencyKey, fmt.Sprintf("%s:verification:%d", key, i))
		record.Verifications[i].RequestDigest = firstNonEmpty(record.Verifications[i].RequestDigest, Digest(record.Verifications[i]))
		record.Verifications[i].ID = ensureID("aiver", record.Verifications[i].ID, record.Verifications[i].IdempotencyKey, record.Verifications[i].RequestDigest)
		if record.Verifications[i].CreatedAt.IsZero() {
			record.Verifications[i].CreatedAt = record.Invocation.CreatedAt
		}
	}
	if record.Rollback != nil {
		record.Rollback.InvocationID = firstNonEmpty(record.Rollback.InvocationID, record.Invocation.ID)
		record.Rollback.IdempotencyKey = firstNonEmpty(record.Rollback.IdempotencyKey, key+":rollback")
		record.Rollback.RequestDigest = firstNonEmpty(record.Rollback.RequestDigest, Digest(*record.Rollback))
		record.Rollback.ID = ensureID("airollback", record.Rollback.ID, record.Rollback.IdempotencyKey, record.Rollback.RequestDigest)
		if record.Rollback.CreatedAt.IsZero() {
			record.Rollback.CreatedAt = record.Invocation.CreatedAt
		}
	}
	if record.Outcome != nil {
		record.Outcome.InvocationID = firstNonEmpty(record.Outcome.InvocationID, record.Invocation.ID)
		record.Outcome.IdempotencyKey = firstNonEmpty(record.Outcome.IdempotencyKey, key+":outcome")
		record.Outcome.RequestDigest = firstNonEmpty(record.Outcome.RequestDigest, Digest(*record.Outcome))
		record.Outcome.ID = ensureID("aioutcome", record.Outcome.ID, record.Outcome.IdempotencyKey, record.Outcome.RequestDigest)
		if record.Outcome.CreatedAt.IsZero() {
			record.Outcome.CreatedAt = record.Invocation.CreatedAt
		}
	}
	if record.CandidateRef != nil {
		record.CandidateRef.InvocationID = firstNonEmpty(record.CandidateRef.InvocationID, record.Invocation.ID)
		record.CandidateRef.IdempotencyKey = firstNonEmpty(record.CandidateRef.IdempotencyKey, key+":candidate")
		record.CandidateRef.RequestDigest = firstNonEmpty(record.CandidateRef.RequestDigest, Digest(*record.CandidateRef))
		record.CandidateRef.ID = ensureID("aicandidate", record.CandidateRef.ID, record.CandidateRef.IdempotencyKey, record.CandidateRef.RequestDigest)
		if record.CandidateRef.CreatedAt.IsZero() {
			record.CandidateRef.CreatedAt = record.Invocation.CreatedAt
		}
	}
	if err := validateIntervention(record); err != nil {
		return Intervention{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Intervention{}, false, err
	}
	rollback := func(cause error) (Intervention, bool, error) { _ = tx.Rollback(); return Intervention{}, false, cause }
	// A complete intervention is committed as one transaction.  If the root
	// invocation was already committed, read the immutable top-level payload
	// after the transaction and return it as a replay.
	invReplay, _, err := s.appendInvocationTx(ctx, tx, record.Invocation, key, digest)
	if err != nil {
		return rollback(err)
	}
	if invReplay {
		_ = tx.Commit()
		existing, readErr := s.GetIntervention(ctx, record.ID)
		if readErr != nil {
			return Intervention{}, false, readErr
		}
		return existing, true, nil
	}
	if record.Context != nil {
		if _, _, err = s.appendContextTx(ctx, tx, *record.Context, record.Context.IdempotencyKey, record.Context.RequestDigest); err != nil {
			return rollback(err)
		}
	}
	if record.Plan != nil {
		if _, _, err = s.appendPlanTx(ctx, tx, *record.Plan, record.Plan.IdempotencyKey, record.Plan.RequestDigest); err != nil {
			return rollback(err)
		}
	}
	for _, item := range record.Actions {
		if _, _, err = s.appendActionTx(ctx, tx, item, item.IdempotencyKey, item.RequestDigest); err != nil {
			return rollback(err)
		}
	}
	for _, item := range record.Verifications {
		if _, _, err = s.appendVerificationTx(ctx, tx, item, item.IdempotencyKey, item.RequestDigest); err != nil {
			return rollback(err)
		}
	}
	if record.Rollback != nil {
		if _, _, err = s.appendRollbackTx(ctx, tx, *record.Rollback, record.Rollback.IdempotencyKey, record.Rollback.RequestDigest); err != nil {
			return rollback(err)
		}
	}
	if record.Outcome != nil {
		if _, _, err = s.appendOutcomeTx(ctx, tx, *record.Outcome, record.Outcome.IdempotencyKey, record.Outcome.RequestDigest); err != nil {
			return rollback(err)
		}
	}
	if record.CandidateRef != nil {
		if _, _, err = s.appendCandidateTx(ctx, tx, *record.CandidateRef, record.CandidateRef.IdempotencyKey, record.CandidateRef.RequestDigest); err != nil {
			return rollback(err)
		}
	}
	data, _ := json.Marshal(record)
	result, err := tx.ExecContext(ctx, `INSERT INTO m6_ai_interventions(id,idempotency_key,request_digest,invocation_id,payload,created_at) VALUES($1,$2,$3,$4,$5::jsonb,$6) ON CONFLICT(idempotency_key) DO NOTHING`, record.ID, key, digest, record.Invocation.ID, data, record.Invocation.CreatedAt.UTC())
	if err != nil {
		return rollback(err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		var storedDigest string
		if err := tx.QueryRowContext(ctx, `SELECT request_digest FROM m6_ai_interventions WHERE idempotency_key=$1`, key).Scan(&storedDigest); err != nil {
			return rollback(err)
		}
		if storedDigest != digest {
			return rollback(ErrConflict)
		}
	}
	if err = tx.Commit(); err != nil {
		return Intervention{}, false, err
	}
	return record, false, nil
}

func (s *PostgresStore) appendInvocationTx(ctx context.Context, tx *sql.Tx, record Invocation, key, digest string) (bool, Invocation, error) {
	data, _ := json.Marshal(record)
	result, err := tx.ExecContext(ctx, `INSERT INTO m6_ai_invocations(id,idempotency_key,request_digest,task_type,application_id,problem_fingerprint,version_key,cache_key,provider,model,policy_version,profile,context_id,status,outcome,tokens,duration_ms,cpu_seconds,memory_bytes,disk_bytes,network_rx_bytes,network_tx_bytes,peak_memory_bytes,candidate_id,payload,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25::jsonb,$26) ON CONFLICT(idempotency_key) DO NOTHING`, record.ID, key, digest, record.TaskType, record.ApplicationID, record.ProblemFingerprint, record.VersionKey, record.CacheKey, record.Provider, record.Model, record.PolicyVersion, record.Profile, record.ContextID, record.Status, record.Outcome, record.Tokens, record.DurationMS, record.Resource.CPUSeconds, record.Resource.MemoryBytes, record.Resource.DiskBytes, record.Resource.NetworkRxBytes, record.Resource.NetworkTxBytes, record.Resource.PeakMemoryBytes, record.CandidateID, data, record.CreatedAt.UTC())
	if err != nil {
		return false, Invocation{}, err
	}
	n, _ := result.RowsAffected()
	if n == 1 {
		return false, record, nil
	}
	var storedDigest string
	var stored []byte
	if err := tx.QueryRowContext(ctx, `SELECT request_digest,payload FROM m6_ai_invocations WHERE idempotency_key=$1`, key).Scan(&storedDigest, &stored); err != nil {
		return false, Invocation{}, err
	}
	if storedDigest != digest {
		return false, Invocation{}, ErrConflict
	}
	var existing Invocation
	if json.Unmarshal(stored, &existing) != nil {
		return false, Invocation{}, ErrCorrupt
	}
	return true, existing, nil
}

func (s *PostgresStore) appendContextTx(ctx context.Context, tx *sql.Tx, record ContextPackage, key, digest string) (bool, ContextPackage, error) {
	scope, _ := json.Marshal(record.Scope)
	refs, _ := json.Marshal(record.SourceRefs)
	data, _ := json.Marshal(record)
	result, err := tx.ExecContext(ctx, `INSERT INTO m6_ai_context_packages(id,idempotency_key,request_digest,invocation_id,scope,source_refs,authorized,redacted,template_version,profile,retention,payload,created_at) VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8,$9,$10,$11,$12::jsonb,$13) ON CONFLICT(idempotency_key) DO NOTHING`, record.ID, key, digest, record.InvocationID, scope, refs, record.Authorized, record.Redacted, record.TemplateVersion, record.Profile, record.Retention, data, record.CreatedAt.UTC())
	if err != nil {
		return false, ContextPackage{}, err
	}
	n, _ := result.RowsAffected()
	if n == 1 {
		return false, record, nil
	}
	var d string
	var stored []byte
	if err := tx.QueryRowContext(ctx, `SELECT request_digest,payload FROM m6_ai_context_packages WHERE idempotency_key=$1`, key).Scan(&d, &stored); err != nil {
		return false, ContextPackage{}, err
	}
	if d != digest {
		return false, ContextPackage{}, ErrConflict
	}
	var existing ContextPackage
	if json.Unmarshal(stored, &existing) != nil {
		return false, ContextPackage{}, ErrCorrupt
	}
	return true, existing, nil
}
func (s *PostgresStore) appendPlanTx(ctx context.Context, tx *sql.Tx, record ActionPlan, key, digest string) (bool, ActionPlan, error) {
	targets, _ := json.Marshal(record.TargetRefs)
	assumptions, _ := json.Marshal(record.Assumptions)
	refs, _ := json.Marshal(record.EvidenceRefs)
	actions, _ := json.Marshal(record.Actions)
	data, _ := json.Marshal(record)
	result, err := tx.ExecContext(ctx, `INSERT INTO m6_ai_action_plans(id,idempotency_key,request_digest,invocation_id,task_type,target_refs,assumptions,evidence_refs,actions,rollback_id,confidence,requires_user_confirmation,schema_version,payload,created_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9::jsonb,$10,$11,$12,$13,$14::jsonb,$15) ON CONFLICT(idempotency_key) DO NOTHING`, record.ID, key, digest, record.InvocationID, record.TaskType, targets, assumptions, refs, actions, record.RollbackID, record.Confidence, record.RequiresUserConfirmation, record.SchemaVersion, data, record.CreatedAt.UTC())
	if err != nil {
		return false, ActionPlan{}, err
	}
	n, _ := result.RowsAffected()
	if n == 1 {
		return false, record, nil
	}
	var d string
	var stored []byte
	if err := tx.QueryRowContext(ctx, `SELECT request_digest,payload FROM m6_ai_action_plans WHERE idempotency_key=$1`, key).Scan(&d, &stored); err != nil {
		return false, ActionPlan{}, err
	}
	if d != digest {
		return false, ActionPlan{}, ErrConflict
	}
	var existing ActionPlan
	if json.Unmarshal(stored, &existing) != nil {
		return false, ActionPlan{}, ErrCorrupt
	}
	return true, existing, nil
}
func (s *PostgresStore) appendActionTx(ctx context.Context, tx *sql.Tx, record ToolAction, key, digest string) (bool, ToolAction, error) {
	params, _ := json.Marshal(record.Parameters)
	bounds, _ := json.Marshal(record.Bounds)
	data, _ := json.Marshal(record)
	result, err := tx.ExecContext(ctx, `INSERT INTO m6_ai_tool_actions(id,idempotency_key,request_digest,invocation_id,plan_id,sequence,tool_id,tool_version,parameters,workspace_ref,risk_class,validation_id,bounds,network,timeout_ms,status,output_digest,diff_digest,payload,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13::jsonb,$14,$15,$16,$17,$18,$19::jsonb,$20) ON CONFLICT(idempotency_key) DO NOTHING`, record.ID, key, digest, record.InvocationID, record.PlanID, record.Sequence, record.ToolID, record.ToolVersion, params, record.WorkspaceRef, record.RiskClass, record.ValidationID, bounds, record.Network, record.TimeoutMS, record.Status, record.OutputDigest, record.DiffDigest, data, record.CreatedAt.UTC())
	if err != nil {
		return false, ToolAction{}, err
	}
	n, _ := result.RowsAffected()
	if n == 1 {
		return false, record, nil
	}
	var d string
	var stored []byte
	if err := tx.QueryRowContext(ctx, `SELECT request_digest,payload FROM m6_ai_tool_actions WHERE idempotency_key=$1`, key).Scan(&d, &stored); err != nil {
		return false, ToolAction{}, err
	}
	if d != digest {
		return false, ToolAction{}, ErrConflict
	}
	var existing ToolAction
	if json.Unmarshal(stored, &existing) != nil {
		return false, ToolAction{}, ErrCorrupt
	}
	return true, existing, nil
}
func (s *PostgresStore) appendVerificationTx(ctx context.Context, tx *sql.Tx, record Verification, key, digest string) (bool, Verification, error) {
	refs, _ := json.Marshal(record.EvidenceRefs)
	data, _ := json.Marshal(record)
	result, err := tx.ExecContext(ctx, `INSERT INTO m6_ai_verifications(id,idempotency_key,request_digest,invocation_id,plan_id,action_id,validator_id,passed,evidence_refs,summary,payload,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11::jsonb,$12) ON CONFLICT(idempotency_key) DO NOTHING`, record.ID, key, digest, record.InvocationID, record.PlanID, record.ActionID, record.ValidatorID, record.Passed, refs, record.Summary, data, record.CreatedAt.UTC())
	if err != nil {
		return false, Verification{}, err
	}
	n, _ := result.RowsAffected()
	if n == 1 {
		return false, record, nil
	}
	var d string
	var stored []byte
	if err := tx.QueryRowContext(ctx, `SELECT request_digest,payload FROM m6_ai_verifications WHERE idempotency_key=$1`, key).Scan(&d, &stored); err != nil {
		return false, Verification{}, err
	}
	if d != digest {
		return false, Verification{}, ErrConflict
	}
	var existing Verification
	if json.Unmarshal(stored, &existing) != nil {
		return false, Verification{}, ErrCorrupt
	}
	return true, existing, nil
}
func (s *PostgresStore) appendRollbackTx(ctx context.Context, tx *sql.Tx, record Rollback, key, digest string) (bool, Rollback, error) {
	refs, _ := json.Marshal(record.EvidenceRefs)
	data, _ := json.Marshal(record)
	result, err := tx.ExecContext(ctx, `INSERT INTO m6_ai_rollbacks(id,idempotency_key,request_digest,invocation_id,plan_id,rollback_id,status,reason,evidence_refs,payload,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11) ON CONFLICT(idempotency_key) DO NOTHING`, record.ID, key, digest, record.InvocationID, record.PlanID, record.RollbackID, record.Status, record.Reason, refs, data, record.CreatedAt.UTC())
	if err != nil {
		return false, Rollback{}, err
	}
	n, _ := result.RowsAffected()
	if n == 1 {
		return false, record, nil
	}
	var d string
	var stored []byte
	if err := tx.QueryRowContext(ctx, `SELECT request_digest,payload FROM m6_ai_rollbacks WHERE idempotency_key=$1`, key).Scan(&d, &stored); err != nil {
		return false, Rollback{}, err
	}
	if d != digest {
		return false, Rollback{}, ErrConflict
	}
	var existing Rollback
	if json.Unmarshal(stored, &existing) != nil {
		return false, Rollback{}, ErrCorrupt
	}
	return true, existing, nil
}
func (s *PostgresStore) appendOutcomeTx(ctx context.Context, tx *sql.Tx, record Outcome, key, digest string) (bool, Outcome, error) {
	resource, _ := json.Marshal(record.Resource)
	data, _ := json.Marshal(record)
	result, err := tx.ExecContext(ctx, `INSERT INTO m6_ai_outcomes(id,idempotency_key,request_digest,invocation_id,status,exit_code,summary,user_confirmed,rolled_back,failure_code,resource,tokens,duration_ms,candidate_id,payload,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$14,$15::jsonb,$16) ON CONFLICT(idempotency_key) DO NOTHING`, record.ID, key, digest, record.InvocationID, record.Status, record.ExitCode, record.Summary, record.UserConfirmed, record.RolledBack, record.FailureCode, resource, record.Tokens, record.DurationMS, record.CandidateID, data, record.CreatedAt.UTC())
	if err != nil {
		return false, Outcome{}, err
	}
	n, _ := result.RowsAffected()
	if n == 1 {
		return false, record, nil
	}
	var d string
	var stored []byte
	if err := tx.QueryRowContext(ctx, `SELECT request_digest,payload FROM m6_ai_outcomes WHERE idempotency_key=$1`, key).Scan(&d, &stored); err != nil {
		return false, Outcome{}, err
	}
	if d != digest {
		return false, Outcome{}, ErrConflict
	}
	var existing Outcome
	if json.Unmarshal(stored, &existing) != nil {
		return false, Outcome{}, ErrCorrupt
	}
	return true, existing, nil
}
func (s *PostgresStore) appendCandidateTx(ctx context.Context, tx *sql.Tx, record CandidateRef, key, digest string) (bool, CandidateRef, error) {
	data, _ := json.Marshal(record)
	result, err := tx.ExecContext(ctx, `INSERT INTO m6_ai_candidate_refs(id,idempotency_key,request_digest,invocation_id,candidate_id,fingerprint,aggregation,status,payload,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10) ON CONFLICT(idempotency_key) DO NOTHING`, record.ID, key, digest, record.InvocationID, record.CandidateID, record.Fingerprint, record.Aggregation, record.Status, data, record.CreatedAt.UTC())
	if err != nil {
		return false, CandidateRef{}, err
	}
	n, _ := result.RowsAffected()
	if n == 1 {
		return false, record, nil
	}
	var d string
	var stored []byte
	if err := tx.QueryRowContext(ctx, `SELECT request_digest,payload FROM m6_ai_candidate_refs WHERE idempotency_key=$1`, key).Scan(&d, &stored); err != nil {
		return false, CandidateRef{}, err
	}
	if d != digest {
		return false, CandidateRef{}, ErrConflict
	}
	var existing CandidateRef
	if json.Unmarshal(stored, &existing) != nil {
		return false, CandidateRef{}, ErrCorrupt
	}
	return true, existing, nil
}

func (s *PostgresStore) GetIntervention(ctx context.Context, id string) (Intervention, error) {
	if err := checkContext(ctx); err != nil {
		return Intervention{}, err
	}
	if err := s.requireDB(); err != nil {
		return Intervention{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return Intervention{}, ErrInvalid
	}
	var payload []byte
	err := s.db.QueryRowContext(ctx, `SELECT payload FROM m6_ai_interventions WHERE id=$1`, id).Scan(&payload)
	if err == nil {
		var result Intervention
		if json.Unmarshal(payload, &result) != nil {
			return Intervention{}, ErrCorrupt
		}
		return result, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Intervention{}, err
	}
	var invocation Invocation
	if err = s.db.QueryRowContext(ctx, `SELECT payload FROM m6_ai_invocations WHERE id=$1`, id).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Intervention{}, ErrNotFound
		}
		return Intervention{}, err
	}
	if json.Unmarshal(payload, &invocation) != nil {
		return Intervention{}, ErrCorrupt
	}
	return s.getByInvocation(ctx, invocation)
}

func (s *PostgresStore) getByInvocation(ctx context.Context, invocation Invocation) (Intervention, error) {
	result := Intervention{ID: invocation.ID, Invocation: invocation}
	var payload []byte
	err := s.db.QueryRowContext(ctx, `SELECT payload FROM m6_ai_context_packages WHERE invocation_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1`, invocation.ID).Scan(&payload)
	if err == nil {
		var item ContextPackage
		if json.Unmarshal(payload, &item) != nil {
			return Intervention{}, ErrCorrupt
		}
		result.Context = &item
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Intervention{}, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT payload FROM m6_ai_action_plans WHERE invocation_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1`, invocation.ID).Scan(&payload)
	if err == nil {
		var item ActionPlan
		if json.Unmarshal(payload, &item) != nil {
			return Intervention{}, ErrCorrupt
		}
		result.Plan = &item
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Intervention{}, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM m6_ai_tool_actions WHERE invocation_id=$1 ORDER BY sequence,id`, invocation.ID)
	if err != nil {
		return Intervention{}, err
	}
	for rows.Next() {
		if err := rows.Scan(&payload); err != nil {
			rows.Close()
			return Intervention{}, err
		}
		var item ToolAction
		if json.Unmarshal(payload, &item) != nil {
			rows.Close()
			return Intervention{}, ErrCorrupt
		}
		result.Actions = append(result.Actions, item)
	}
	if err := rows.Close(); err != nil {
		return Intervention{}, err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT payload FROM m6_ai_verifications WHERE invocation_id=$1 ORDER BY created_at,id`, invocation.ID)
	if err != nil {
		return Intervention{}, err
	}
	for rows.Next() {
		if err := rows.Scan(&payload); err != nil {
			rows.Close()
			return Intervention{}, err
		}
		var item Verification
		if json.Unmarshal(payload, &item) != nil {
			rows.Close()
			return Intervention{}, ErrCorrupt
		}
		result.Verifications = append(result.Verifications, item)
	}
	if err := rows.Close(); err != nil {
		return Intervention{}, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT payload FROM m6_ai_rollbacks WHERE invocation_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1`, invocation.ID).Scan(&payload)
	if err == nil {
		var item Rollback
		if json.Unmarshal(payload, &item) != nil {
			return Intervention{}, ErrCorrupt
		}
		result.Rollback = &item
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Intervention{}, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT payload FROM m6_ai_outcomes WHERE invocation_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1`, invocation.ID).Scan(&payload)
	if err == nil {
		var item Outcome
		if json.Unmarshal(payload, &item) != nil {
			return Intervention{}, ErrCorrupt
		}
		result.Outcome = &item
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Intervention{}, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT payload FROM m6_ai_candidate_refs WHERE invocation_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1`, invocation.ID).Scan(&payload)
	if err == nil {
		var item CandidateRef
		if json.Unmarshal(payload, &item) != nil {
			return Intervention{}, ErrCorrupt
		}
		result.CandidateRef = &item
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Intervention{}, err
	}
	return result, nil
}

func (s *PostgresStore) Query(ctx context.Context, filter QueryFilter) ([]Intervention, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	where := []string{"1=1"}
	args := []any{}
	if filter.ApplicationID != "" {
		args = append(args, filter.ApplicationID)
		where = append(where, fmt.Sprintf("application_id=$%d", len(args)))
	}
	if filter.TaskType != "" {
		args = append(args, filter.TaskType)
		where = append(where, fmt.Sprintf("task_type=$%d", len(args)))
	}
	if !filter.From.IsZero() {
		args = append(args, filter.From.UTC())
		where = append(where, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if !filter.To.IsZero() {
		args = append(args, filter.To.UTC())
		where = append(where, fmt.Sprintf("created_at <= $%d", len(args)))
	}
	if filter.CandidateID != "" {
		args = append(args, filter.CandidateID)
		where = append(where, fmt.Sprintf("(candidate_id=$%d OR EXISTS (SELECT 1 FROM m6_ai_candidate_refs cr WHERE cr.invocation_id=m6_ai_invocations.id AND cr.candidate_id=$%d))", len(args), len(args)))
	}
	if filter.Outcome != "" {
		args = append(args, filter.Outcome)
		where = append(where, fmt.Sprintf("COALESCE((SELECT status FROM m6_ai_outcomes o WHERE o.invocation_id=m6_ai_invocations.id ORDER BY o.created_at DESC,o.id DESC LIMIT 1),NULLIF(outcome,''),status)=$%d", len(args)))
	}
	query := fmt.Sprintf("SELECT payload FROM m6_ai_invocations WHERE %s ORDER BY created_at,id LIMIT %d", strings.Join(where, " AND "), normalizeLimit(filter.Limit))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Intervention
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var invocation Invocation
		if json.Unmarshal(payload, &invocation) != nil {
			return nil, ErrCorrupt
		}
		item, err := s.getByInvocation(ctx, invocation)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *PostgresStore) Metrics(ctx context.Context, filter QueryFilter) (Metrics, error) {
	if err := checkContext(ctx); err != nil {
		return Metrics{}, err
	}
	if err := s.requireDB(); err != nil {
		return Metrics{}, err
	}
	where := []string{"1=1"}
	args := []any{}
	if filter.ApplicationID != "" {
		args = append(args, filter.ApplicationID)
		where = append(where, fmt.Sprintf("i.application_id=$%d", len(args)))
	}
	if filter.TaskType != "" {
		args = append(args, filter.TaskType)
		where = append(where, fmt.Sprintf("i.task_type=$%d", len(args)))
	}
	if !filter.From.IsZero() {
		args = append(args, filter.From.UTC())
		where = append(where, fmt.Sprintf("i.created_at >= $%d", len(args)))
	}
	if !filter.To.IsZero() {
		args = append(args, filter.To.UTC())
		where = append(where, fmt.Sprintf("i.created_at <= $%d", len(args)))
	}
	if filter.Outcome != "" {
		args = append(args, filter.Outcome)
		where = append(where, fmt.Sprintf("COALESCE(NULLIF(o.status,''),NULLIF(i.outcome,''),i.status)=$%d", len(args)))
	}
	var m Metrics
	var candidateCount int64
	err := s.db.QueryRowContext(ctx, fmt.Sprintf(`SELECT COUNT(*),COUNT(*) FILTER(WHERE COALESCE(NULLIF(o.status,''),NULLIF(i.outcome,''),i.status)='succeeded'),COUNT(*) FILTER(WHERE COALESCE(NULLIF(o.status,''),NULLIF(i.outcome,''),i.status)='failed'),COUNT(*) FILTER(WHERE COALESCE(NULLIF(o.status,''),NULLIF(i.outcome,''),i.status)='rolled_back'),COALESCE(SUM(COALESCE(o.tokens,i.tokens)),0),COALESCE(SUM(COALESCE(o.duration_ms,i.duration_ms)),0),COUNT(cr.id),COUNT(DISTINCT cr.candidate_id) FROM m6_ai_invocations i LEFT JOIN LATERAL (SELECT status,tokens,duration_ms FROM m6_ai_outcomes WHERE invocation_id=i.id ORDER BY created_at DESC,id DESC LIMIT 1) o ON TRUE LEFT JOIN m6_ai_candidate_refs cr ON cr.invocation_id=i.id WHERE %s`, strings.Join(where, " AND ")), args...).Scan(&m.Interventions, &m.Succeeded, &m.Failed, &m.RolledBack, &m.Tokens, &m.DurationMS, &m.CandidateRefs, &candidateCount)
	if err != nil {
		return Metrics{}, err
	}
	m.DistinctCandidates = candidateCount
	var failed int64
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM m6_ai_verifications v JOIN m6_ai_invocations i ON i.id=v.invocation_id WHERE v.passed=false`).Scan(&failed)
	if err != nil {
		return Metrics{}, err
	}
	m.VerificationFailed = failed
	return m, nil
}

var _ Repository = (*PostgresStore)(nil)

// Keep compile-time visibility of the database driver contract to callers
// that use sql.ErrNoRows when translating ErrNotFound.
var _ = sql.ErrNoRows
