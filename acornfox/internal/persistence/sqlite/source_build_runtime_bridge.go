package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

// ReadSourceBuiltArtifact returns private handoff authority only from the same
// owner's successful, original Source/Build/App/Environment fact chain. It is
// read-only; an arbitrary OCI storage ref or caller-supplied digest is never a
// substitute for the persisted Build result and actual store evidence.
func (s *Store) ReadSourceBuiltArtifact(ctx context.Context, admin, buildIntent, artifactID domain.ID) (appcontracts.SourceBuiltArtifactFact, error) {
	var zero appcontracts.SourceBuiltArtifactFact
	if err := s.checkOpen(); err != nil {
		return zero, err
	}
	if admin.Empty() || buildIntent.Empty() || artifactID.Empty() {
		return zero, domain.ValidationError("original administrator, build intent and artifact required")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	return s.readSourceBuiltArtifactTx(ctx, tx, admin, buildIntent, artifactID)
}
func (s *Store) readSourceBuiltArtifactTx(ctx context.Context, tx *sql.Tx, admin, buildIntent, artifactID domain.ID) (appcontracts.SourceBuiltArtifactFact, error) {
	var zero appcontracts.SourceBuiltArtifactFact
	if err := requireSourceBuildAdmin(ctx, tx, admin); err != nil {
		return zero, err
	}
	if err := sourceBuildSchemaReadyTx(ctx, tx); err != nil {
		return zero, err
	}
	var appName, owner, app, env, bid, buildID, planID, sourceID, state, opState, prepareOwner, prepareApp, prepareEnv, prepareState, sourceRaw, buildRaw, artifactRaw, planRaw string
	err := tx.QueryRowContext(ctx, `SELECT a.name,b.admin_id,b.application_id,b.environment_id,b.id,b.build_id,b.plan_id,b.source_revision_id,b.state,o.state,p.admin_id,p.application_id,p.environment_id,p.state,r.revision,br.build,br.artifact,b.plan FROM source_build_intents b JOIN applications a ON a.id=b.application_id JOIN source_prepare_intents p ON p.id=b.prepare_intent_id AND p.application_id=b.application_id AND p.environment_id=b.environment_id JOIN native_source_revisions r ON r.id=b.source_revision_id AND r.intent_id=p.id AND r.application_id=b.application_id JOIN operations o ON o.id=b.operation_id AND o.application_id=b.application_id AND o.environment_id=b.environment_id JOIN source_build_results br ON br.intent_id=b.id AND br.build_id=b.build_id WHERE b.id=? AND br.artifact_id=?`, buildIntent.String(), artifactID.String()).Scan(&appName, &owner, &app, &env, &bid, &buildID, &planID, &sourceID, &state, &opState, &prepareOwner, &prepareApp, &prepareEnv, &prepareState, &sourceRaw, &buildRaw, &artifactRaw, &planRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return zero, ErrNotFound
	}
	if err != nil {
		return zero, err
	}
	if owner != admin.String() {
		return zero, domain.NewError(domain.ErrForbidden, "source-built artifact belongs to another administrator")
	}
	if appName == "" || prepareOwner != owner || prepareApp != app || prepareEnv != env || prepareState != "prepared" || state != "succeeded" || opState != "succeeded" {
		return zero, ErrCorruptData
	}
	var source domain.SourceRevision
	var build domain.Build
	var artifact domain.Artifact
	var plan domain.BuildPlan
	if json.Unmarshal([]byte(sourceRaw), &source) != nil || json.Unmarshal([]byte(buildRaw), &build) != nil || json.Unmarshal([]byte(artifactRaw), &artifact) != nil || json.Unmarshal([]byte(planRaw), &plan) != nil || source.Validate() != nil || artifact.Validate() != nil || plan.Validate() != nil {
		return zero, ErrCorruptData
	}
	if source.ID.String() != sourceID || source.ApplicationID.String() != app || plan.ID.String() != planID || plan.SourceRevisionID != source.ID || plan.SourceDigest != source.ContentDigest || build.ID.String() != buildID || build.PlanID != plan.ID || build.Status != domain.BuildSucceeded || build.ArtifactID != artifact.ID || artifact.ID != artifactID || artifact.BuildID != build.ID || artifact.Image.Repository != plan.TargetRepository || artifact.OCIStorageRef == "" || artifact.SizeBytes <= 0 {
		return zero, ErrCorruptData
	}
	archiveSHA := ""
	for _, ref := range artifact.Evidence {
		if ref.Kind == "image.oci_store" {
			if archiveSHA != "" || !validSha256Digest(ref.Digest) {
				return zero, ErrCorruptData
			}
			archiveSHA = ref.Digest
		}
	}
	if archiveSHA == "" {
		return zero, ErrCorruptData
	}
	fact := appcontracts.SourceBuiltArtifactFact{AppName: appName, AdminID: admin, ApplicationID: domain.ID(app), EnvironmentID: domain.ID(env), BuildIntentID: domain.ID(bid), BuildID: build.ID, SourceRevisionID: source.ID, BuildPlanID: plan.ID, ArtifactID: artifact.ID, Image: artifact.Image, StorageRef: artifact.OCIStorageRef, ArchiveSHA256: archiveSHA, SizeBytes: artifact.SizeBytes}
	return fact, nil
}

const (
	sourceRunPlanScope    = "source.run.plan"
	sourceRunConfirmScope = "source.run.confirm"
)

func sourceRunRequestDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return sha256Hex(string(raw)), nil
}
func (s *Store) ReadSourceRunPlan(ctx context.Context, admin, planID domain.ID) (appcontracts.ImagePlan, error) {
	var zero appcontracts.ImagePlan
	plan, err := s.GetImagePlan(ctx, planID, admin)
	if err != nil {
		return zero, err
	}
	if plan.ResolverProvenance.Provider != "source-build" || plan.ResolverProvenance.EvidenceRef == "" {
		return zero, domain.NewError(domain.ErrForbidden, "plan is not an original source-built preview")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	var buildIntent string
	if err := tx.QueryRowContext(ctx, `SELECT intent_id FROM source_build_results WHERE artifact_id=?`, plan.ResolverProvenance.EvidenceRef).Scan(&buildIntent); err != nil {
		return zero, ErrCorruptData
	}
	fact, err := s.readSourceBuiltArtifactTx(ctx, tx, admin, domain.ID(buildIntent), domain.ID(plan.ResolverProvenance.EvidenceRef))
	if err != nil {
		return zero, err
	}
	if fact.Image.Repository != plan.ResolvedImage.Repository || fact.Image.Digest != plan.ResolvedImage.Digest {
		return zero, ErrCorruptData
	}
	return plan, nil
}

// ReadSourceRunPlanReplay answers only an already committed exact semantic
// request. It never creates a plan or treats a missing Source peer as proof.
func (s *Store) ReadSourceRunPlanReplay(ctx context.Context, admin domain.ID, in appcontracts.SourceRunPlanInput, canonical appcontracts.CanonicalExecutionInput) (appcontracts.ImagePlan, bool, error) {
	var zero appcontracts.ImagePlan
	if err := s.checkOpen(); err != nil {
		return zero, false, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return zero, false, err
	}
	defer tx.Rollback()
	fact, err := s.readSourceBuiltArtifactTx(ctx, tx, admin, in.BuildIntentID, in.ArtifactID)
	if err != nil {
		return zero, false, err
	}
	if canonical.AppName != fact.AppName || canonical.Repository != fact.Image.Repository || canonical.ResolvedRef != fact.Image.Digest {
		return zero, false, ErrCorruptData
	}
	semantic := canonical
	semantic.AppName = ""
	digest, err := sourceRunRequestDigest(struct {
		Admin     domain.ID
		Request   appcontracts.SourceRunPlanInput
		Canonical appcontracts.CanonicalExecutionInput
	}{admin, in, semantic})
	if err != nil {
		return zero, false, err
	}
	var saved, status string
	var cached sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT request_digest,status,response FROM idempotency_records WHERE scope=? AND idempotency_key=?`, sourceRunPlanScope, strings.TrimSpace(in.IdempotencyKey)).Scan(&saved, &status, &cached)
	if errors.Is(err, sql.ErrNoRows) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, err
	}
	if saved != digest {
		return zero, false, ErrIdempotencyConflict
	}
	if status != "completed" || !cached.Valid {
		return zero, false, ErrIdempotencyInProgress
	}
	var plan appcontracts.ImagePlan
	if json.Unmarshal([]byte(cached.String), &plan) != nil || appcontracts.ValidatePlanConsistency(plan) != nil || plan.AdminID != admin || plan.ResolverProvenance.Provider != "source-build" || plan.ResolverProvenance.EvidenceRef != fact.ArtifactID.String() {
		return zero, false, ErrIdempotencyCorrupt
	}
	return plan, true, nil
}

// CreateSourceRunPlan persists only an immutable preview from the original
// application. The caller's observed OCI identity came from a fully read and
// closed, authenticated SourceRole archive; Store rechecks all durable facts.
func (s *Store) CreateSourceRunPlan(ctx context.Context, admin domain.ID, in appcontracts.SourceRunPlanInput, canonical appcontracts.CanonicalExecutionInput, observed appcontracts.SourceRunOCIIdentity) (appcontracts.ImagePlan, error) {
	var zero appcontracts.ImagePlan
	if err := s.checkOpen(); err != nil {
		return zero, err
	}
	key := strings.TrimSpace(in.IdempotencyKey)
	if admin.Empty() || in.BuildIntentID.Empty() || in.ArtifactID.Empty() || key == "" || len(key) > 256 {
		return zero, domain.ValidationError("original source run plan and key required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	fact, err := s.readSourceBuiltArtifactTx(ctx, tx, admin, in.BuildIntentID, in.ArtifactID)
	if err != nil {
		return zero, err
	}
	if canonical.AppName != fact.AppName || canonical.Repository != fact.Image.Repository || canonical.ResolvedRef != fact.Image.Digest || canonical.Port != in.Port || observed.ArchiveSize != fact.SizeBytes || observed.ManifestDigest != fact.Image.Digest || !validSha256Digest(observed.ConfigDigest) || observed.OS != "linux" || observed.Architecture != "amd64" {
		return zero, domain.NewError(domain.ErrConflict, "source-built OCI/plan differs from original artifact")
	}
	semantic := canonical
	semantic.AppName = "" // app name is a derived, possibly renamed display fact; original key still replays.
	digest, err := sourceRunRequestDigest(struct {
		Admin     domain.ID
		Request   appcontracts.SourceRunPlanInput
		Canonical appcontracts.CanonicalExecutionInput
	}{admin, in, semantic})
	if err != nil {
		return zero, err
	}
	now := time.Now().UTC()
	nowStr := FormatTime(now)
	result, err := tx.ExecContext(ctx, `INSERT INTO idempotency_records(scope,idempotency_key,request_digest,status,created_at,updated_at) VALUES(?,?,?,'in_progress',?,?) ON CONFLICT(scope,idempotency_key) DO NOTHING`, sourceRunPlanScope, key, digest, nowStr, nowStr)
	if err != nil {
		return zero, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return zero, err
	}
	var saved, status string
	var cached sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT request_digest,status,response FROM idempotency_records WHERE scope=? AND idempotency_key=?`, sourceRunPlanScope, key).Scan(&saved, &status, &cached); err != nil {
		return zero, err
	}
	if saved != digest {
		return zero, ErrIdempotencyConflict
	}
	if inserted == 0 {
		if status != "completed" || !cached.Valid {
			return zero, ErrIdempotencyInProgress
		}
		var plan appcontracts.ImagePlan
		if json.Unmarshal([]byte(cached.String), &plan) != nil || appcontracts.ValidatePlanConsistency(plan) != nil || plan.ResolverProvenance.Provider != "source-build" || plan.ResolverProvenance.EvidenceRef != fact.ArtifactID.String() {
			return zero, ErrIdempotencyCorrupt
		}
		return plan, nil
	}
	var existing int
	if err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM image_deploy_intents WHERE application_id=? AND environment_id=?) + (SELECT count(*) FROM image_deployments WHERE application_id=? AND environment_id=?)`, fact.ApplicationID.String(), fact.EnvironmentID.String(), fact.ApplicationID.String(), fact.EnvironmentID.String()).Scan(&existing); err != nil {
		return zero, err
	}
	if existing != 0 {
		return zero, domain.NewError(domain.ErrConflict, "existing deployment intent requires a separate update operation")
	}
	planID, err := domain.NewID("ipl")
	if err != nil {
		return zero, err
	}
	statusPlan := appcontracts.ImagePlanStatusPlanned
	var missing []string
	if canonical.Port == 0 {
		statusPlan = appcontracts.ImagePlanStatusNeedsInput
		missing = []string{"container_port"}
	}
	resolved := appcontracts.ResolvedImage{Repository: fact.Image.Repository, Digest: fact.Image.Digest, OS: "linux", Architecture: "amd64"}
	provenance := appcontracts.ResolverProvenance{Provider: "source-build", EvidenceRef: fact.ArtifactID.String(), Digest: fact.Image.Digest, ResolvedAt: now}
	planDigest, err := appcontracts.ComputePlanDigest(canonical, resolved.Digest)
	if err != nil {
		return zero, err
	}
	plan := appcontracts.ImagePlan{ID: planID, AdminID: admin, AppName: fact.AppName, Status: statusPlan, PlanDigest: planDigest, CanonicalInput: canonical, ResolvedImage: resolved, ResolverProvenance: provenance, MissingInputs: missing, CreatedAt: now, UpdatedAt: now}
	if err := appcontracts.ValidatePlanConsistency(plan); err != nil {
		return zero, err
	}
	canonicalJSON, _ := json.Marshal(canonical)
	resolvedJSON, _ := json.Marshal(resolved)
	provenanceJSON, _ := json.Marshal(provenance)
	missingJSON, _ := json.Marshal(missing)
	if _, err := tx.ExecContext(ctx, `INSERT INTO image_plans(id,admin_id,app_name,status,plan_digest,canonical_input,resolved_image,resolver_provenance,missing_inputs,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, plan.ID.String(), admin.String(), plan.AppName, string(plan.Status), plan.PlanDigest, string(canonicalJSON), string(resolvedJSON), string(provenanceJSON), string(missingJSON), nowStr, nowStr); err != nil {
		return zero, err
	}
	response, _ := json.Marshal(plan)
	if _, err := tx.ExecContext(ctx, `UPDATE idempotency_records SET status='completed',response=?,updated_at=? WHERE scope=? AND idempotency_key=? AND status='in_progress'`, string(response), nowStr, sourceRunPlanScope, key); err != nil {
		return zero, err
	}
	if err := tx.Commit(); err != nil {
		return zero, fmt.Errorf("%w: publish source-run plan: %v", ErrOutcomeUnknown, err)
	}
	return plan, nil
}

// ConfirmSourceRunPlan creates the existing image.deploy task for the SAME
// original app/env. It never calls ConfirmImagePlan's new-application branch.
func (s *Store) ConfirmSourceRunPlan(ctx context.Context, admin domain.ID, in appcontracts.ConfirmImagePlanInput) (appcontracts.ConfirmImagePlanResult, error) {
	var zero appcontracts.ConfirmImagePlanResult
	if err := s.checkOpen(); err != nil {
		return zero, err
	}
	key := strings.TrimSpace(in.IdempotencyKey)
	if admin.Empty() || in.PlanID.Empty() || in.PlanDigest == "" || key == "" || len(key) > 256 {
		return zero, domain.ValidationError("source-run plan/digest/key required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	if err := requireSourceBuildAdmin(ctx, tx, admin); err != nil {
		return zero, err
	}
	if err := sourceBuildSchemaReadyTx(ctx, tx); err != nil {
		return zero, err
	}
	requestDigest, err := sourceRunRequestDigest(struct {
		Admin domain.ID
		Input appcontracts.ConfirmImagePlanInput
	}{admin, in})
	if err != nil {
		return zero, err
	}
	now := time.Now().UTC()
	nowStr := FormatTime(now)
	row, err := tx.ExecContext(ctx, `INSERT INTO idempotency_records(scope,idempotency_key,request_digest,status,created_at,updated_at) VALUES(?,?,?,'in_progress',?,?) ON CONFLICT(scope,idempotency_key) DO NOTHING`, sourceRunConfirmScope, key, requestDigest, nowStr, nowStr)
	if err != nil {
		return zero, err
	}
	inserted, err := row.RowsAffected()
	if err != nil {
		return zero, err
	}
	var saved, status string
	var cached sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT request_digest,status,response FROM idempotency_records WHERE scope=? AND idempotency_key=?`, sourceRunConfirmScope, key).Scan(&saved, &status, &cached); err != nil {
		return zero, err
	}
	if saved != requestDigest {
		return zero, ErrIdempotencyConflict
	}
	if inserted == 0 {
		if status != "completed" || !cached.Valid {
			return zero, ErrIdempotencyInProgress
		}
		var original appcontracts.ConfirmImagePlanResult
		if json.Unmarshal([]byte(cached.String), &original) != nil || original.PlanID != in.PlanID || original.PlanDigest != in.PlanDigest || original.OperationID.Empty() || original.TaskID.Empty() {
			return zero, ErrIdempotencyCorrupt
		}
		return original, nil
	}
	var planOwner, appName, planStatus, storedDigest, canonicalJSON, resolvedJSON, provenanceJSON, missingJSON, createdAt, updatedAt string
	err = tx.QueryRowContext(ctx, `SELECT admin_id,app_name,status,plan_digest,canonical_input,resolved_image,resolver_provenance,missing_inputs,created_at,updated_at FROM image_plans WHERE id=?`, in.PlanID.String()).Scan(&planOwner, &appName, &planStatus, &storedDigest, &canonicalJSON, &resolvedJSON, &provenanceJSON, &missingJSON, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return zero, ErrNotFound
	}
	if err != nil {
		return zero, err
	}
	if planOwner != admin.String() {
		return zero, domain.NewError(domain.ErrForbidden, "source-run plan belongs to another administrator")
	}
	var canonical appcontracts.CanonicalExecutionInput
	var resolved appcontracts.ResolvedImage
	var provenance appcontracts.ResolverProvenance
	var missing []string
	if json.Unmarshal([]byte(canonicalJSON), &canonical) != nil || json.Unmarshal([]byte(resolvedJSON), &resolved) != nil || json.Unmarshal([]byte(provenanceJSON), &provenance) != nil || json.Unmarshal([]byte(missingJSON), &missing) != nil {
		return zero, ErrCorruptData
	}
	stamp, err := ParseTime(createdAt)
	if err != nil {
		return zero, ErrCorruptData
	}
	update, err := ParseTime(updatedAt)
	if err != nil {
		return zero, ErrCorruptData
	}
	plan := appcontracts.ImagePlan{ID: in.PlanID, AdminID: admin, AppName: appName, Status: appcontracts.ImagePlanStatus(planStatus), PlanDigest: storedDigest, CanonicalInput: canonical, ResolvedImage: resolved, ResolverProvenance: provenance, MissingInputs: missing, CreatedAt: stamp, UpdatedAt: update}
	if appcontracts.ValidatePlanConsistency(plan) != nil || plan.ResolverProvenance.Provider != "source-build" || plan.PlanDigest != in.PlanDigest || plan.Status != appcontracts.ImagePlanStatusPlanned {
		return zero, domain.NewError(domain.ErrConflict, "source-run plan is not the original approved ready plan")
	}
	var buildIntentID string
	err = tx.QueryRowContext(ctx, `SELECT intent_id FROM source_build_results WHERE artifact_id=?`, plan.ResolverProvenance.EvidenceRef).Scan(&buildIntentID)
	if err != nil {
		return zero, ErrCorruptData
	}
	fact, err := s.readSourceBuiltArtifactTx(ctx, tx, admin, domain.ID(buildIntentID), domain.ID(plan.ResolverProvenance.EvidenceRef))
	if err != nil {
		return zero, err
	}
	if fact.Image.Repository != resolved.Repository || fact.Image.Digest != resolved.Digest || fact.Image.Digest != plan.ResolverProvenance.Digest || canonical.Repository != fact.Image.Repository || canonical.ResolvedRef != fact.Image.Digest {
		return zero, ErrCorruptData
	}
	var prior int
	if err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM image_deploy_intents WHERE application_id=? AND environment_id=?) + (SELECT count(*) FROM image_deployments WHERE application_id=? AND environment_id=?)`, fact.ApplicationID.String(), fact.EnvironmentID.String(), fact.ApplicationID.String(), fact.EnvironmentID.String()).Scan(&prior); err != nil {
		return zero, err
	}
	if prior != 0 {
		return zero, domain.NewError(domain.ErrConflict, "existing deployment intent requires separate update")
	}
	opID, err := domain.NewID("op")
	if err != nil {
		return zero, err
	}
	taskID, err := domain.NewID("task")
	if err != nil {
		return zero, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations(id,application_id,environment_id,operation_type,idempotency_key,state,version,target_ref,target_kind,created_at,updated_at) VALUES(?,?,?,?,?,'pending',1,?,'application',?,?)`, opID.String(), fact.ApplicationID.String(), fact.EnvironmentID.String(), imageDeployOpType, key, fact.ApplicationID.String(), nowStr, nowStr); err != nil {
		return zero, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO image_deploy_intents(operation_id,plan_id,application_id,environment_id,plan_digest,created_at) VALUES(?,?,?,?,?,?)`, opID.String(), plan.ID.String(), fact.ApplicationID.String(), fact.EnvironmentID.String(), plan.PlanDigest, nowStr); err != nil {
		return zero, err
	}
	payload, _ := json.Marshal(map[string]any{"kind": imageDeployTaskKind, "application_id": fact.ApplicationID, "environment_id": fact.EnvironmentID, "operation_id": opID, "plan_id": plan.ID, "plan_digest": plan.PlanDigest, "canonical_input": canonical, "resolved_image": resolved})
	if _, err := tx.ExecContext(ctx, `INSERT INTO task_leases(task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at) VALUES(?,?,NULL,NULL,0,?,'ready',?,?,?)`, taskID.String(), opID.String(), defaultTaskMaxAttempts, string(payload), nowStr, nowStr); err != nil {
		return zero, err
	}
	evt, err := appendOutboxTx(ctx, tx, appcontracts.OutboxEvent{AggregateType: "operation", AggregateID: opID.String(), AggregateVersion: 1, EventType: imageDeployEventType, CreatedAt: now, PayloadVersion: "1.0"}, func(id string, cursor int64) ([]byte, error) {
		return json.Marshal(map[string]any{"event_id": id, "sequence": cursor, "operation_id": opID, "application_id": fact.ApplicationID, "kind": imageDeployEventType, "plan_id": plan.ID, "plan_digest": plan.PlanDigest, "occurred_at": nowStr})
	})
	if err != nil {
		return zero, err
	}
	auditID, err := domain.NewID("audit")
	if err != nil {
		return zero, err
	}
	if _, err := appendAuditTx(ctx, tx, auditInput{ID: auditID.String(), Actor: auditContextFromAdmin(admin), Action: "source.run.accepted", InputDigest: "sha256:" + requestDigest, Result: "accepted", EvidenceRefs: []string{fact.ApplicationID.String(), opID.String(), taskID.String(), evt.ID}, CreatedAt: now}); err != nil {
		return zero, err
	}
	accepted := appcontracts.ConfirmImagePlanResult{ApplicationID: fact.ApplicationID, EnvironmentID: fact.EnvironmentID, OperationID: opID, TaskID: taskID, PlanID: plan.ID, PlanDigest: plan.PlanDigest, Status: "pending", CreatedAt: now}
	response, _ := json.Marshal(accepted)
	if _, err := tx.ExecContext(ctx, `UPDATE idempotency_records SET status='completed',response=?,updated_at=? WHERE scope=? AND idempotency_key=? AND status='in_progress'`, string(response), nowStr, sourceRunConfirmScope, key); err != nil {
		return zero, err
	}
	if err := tx.Commit(); err != nil {
		return zero, fmt.Errorf("%w: confirm source-run plan: %v", ErrOutcomeUnknown, err)
	}
	return accepted, nil
}

// sourceArtifactForImagePlanTx is the extra same-app/owner/fact proof required
// on every source-origin Begin and Core authority check. Legacy registry plans
// keep their existing verified resolver path and never enter this branch.
func (s *Store) sourceArtifactForImagePlanTx(ctx context.Context, tx *sql.Tx, plan appcontracts.ImagePlan, appID, envID domain.ID) (*appcontracts.SourceBuiltArtifactFact, error) {
	if plan.ResolverProvenance.Provider == "registryhttp" {
		return nil, nil
	}
	if plan.ResolverProvenance.Provider != "source-build" || plan.ResolverProvenance.EvidenceRef == "" {
		return nil, ErrCorruptData
	}
	var buildIntentID string
	if err := tx.QueryRowContext(ctx, `SELECT intent_id FROM source_build_results WHERE artifact_id=?`, plan.ResolverProvenance.EvidenceRef).Scan(&buildIntentID); err != nil {
		return nil, ErrCorruptData
	}
	fact, err := s.readSourceBuiltArtifactTx(ctx, tx, plan.AdminID, domain.ID(buildIntentID), domain.ID(plan.ResolverProvenance.EvidenceRef))
	if err != nil {
		return nil, err
	}
	if fact.ApplicationID != appID || fact.EnvironmentID != envID || fact.Image.Repository != plan.ResolvedImage.Repository || fact.Image.Digest != plan.ResolvedImage.Digest || fact.Image.Digest != plan.ResolverProvenance.Digest || fact.AppName == "" || plan.CanonicalInput.Repository != fact.Image.Repository || plan.CanonicalInput.ResolvedRef != fact.Image.Digest {
		return nil, ErrCorruptData
	}
	return &fact, nil
}
