package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func sourceBuildSchemaReadyTx(ctx context.Context, tx *sql.Tx) error {
	var checksum string
	if err := tx.QueryRowContext(ctx, `SELECT checksum FROM _schema_migrations WHERE version=?`, version0012_source_build).Scan(&checksum); err != nil || checksum != sha256Hex(sourceBuildSchemaSQL) {
		return domain.NewError(domain.ErrUnavailable, "source-build migration unavailable")
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('source_prepare_intents','native_source_revisions','source_build_intents','source_build_results')`).Scan(&count); err != nil || count != 4 {
		return domain.NewError(domain.ErrUnavailable, "source-build schema unavailable")
	}
	return nil
}
func (s *Store) SourceBuildSchemaReady(ctx context.Context) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return sourceBuildSchemaReadyTx(ctx, tx)
}

// ErrSourceDefinitionNeedsInput is a fixed public-safe category; the private
// persisted definition remains authoritative for the specific missing state.
var ErrSourceDefinitionNeedsInput = errors.New("root Dockerfile is missing or unsupported")

// Public idempotency fingerprints contain semantic input and trusted policy,
// before assigning real Core plan identity/time inside the same transaction.
func (s *Store) ApprovePublicSourceBuildPlan(ctx context.Context, admin domain.ID, in appcontracts.SourceBuildPublicApprovalInput, policy appcontracts.SourceBuildPolicyFact) (appcontracts.SourceBuildIntentFact, error) {
	var zero appcontracts.SourceBuildIntentFact
	if err := s.checkOpen(); err != nil {
		return zero, err
	}
	if admin.Empty() || in.PrepareIntentID.Empty() || in.SourceRevisionID.Empty() || !validSha256Digest(in.SourceDigest) || strings.TrimSpace(in.IdempotencyKey) == "" || len(in.IdempotencyKey) > 256 || !appcontracts.ValidPublicSourceBuildServiceName(in.ServiceName) || !appcontracts.ValidPublicSourceBuildResources(in.Resources) || policy.Resources != in.Resources || policy.NetworkMode != "controlled_egress_v1" || !validSha256Digest(policy.WorkerPolicyDigest) {
		return zero, domain.ValidationError("invalid public source-build approval")
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
	if err := sourceBuildSchemaReadyTx(ctx, tx); err != nil {
		return zero, err
	}
	replay, err := reserveSourceBuildKey(ctx, tx, "source.build", in.IdempotencyKey, struct {
		Admin  domain.ID
		Public appcontracts.SourceBuildPublicApprovalInput
		Policy appcontracts.SourceBuildPolicyFact
	}{admin, in, policy}, now)
	if err != nil {
		return zero, err
	}
	if replay != nil {
		return *replay, nil
	}
	var owner, state, raw, definitionRaw string
	if err := tx.QueryRowContext(ctx, `SELECT p.admin_id,p.state,r.revision,r.definition FROM source_prepare_intents p JOIN native_source_revisions r ON r.intent_id=p.id AND r.application_id=p.application_id WHERE p.id=?`, in.PrepareIntentID.String()).Scan(&owner, &state, &raw, &definitionRaw); errors.Is(err, sql.ErrNoRows) {
		return zero, domain.NewError(domain.ErrConflict, "actual prepared source required")
	} else if err != nil {
		return zero, err
	}
	if owner != admin.String() {
		return zero, domain.NewError(domain.ErrForbidden, "prepared source belongs to another administrator")
	}
	if state != "prepared" {
		return zero, domain.NewError(domain.ErrConflict, "source is not prepared")
	}
	var source domain.SourceRevision
	if json.Unmarshal([]byte(raw), &source) != nil || source.Validate() != nil {
		return zero, ErrCorruptData
	}
	if source.ID != in.SourceRevisionID || source.ContentDigest != in.SourceDigest {
		return zero, domain.NewError(domain.ErrConflict, "approval does not match original prepared source")
	}
	var definition appcontracts.SourceBuildDefinitionFact
	if json.Unmarshal([]byte(definitionRaw), &definition) != nil || !validSourceBuildDefinition(definition, source) {
		return zero, ErrCorruptData
	}
	if definition.Status != "ready" {
		return zero, ErrSourceDefinitionNeedsInput
	}
	planID, err := sourceBuildID("plan")
	if err != nil {
		return zero, err
	}
	plan := domain.BuildPlan{ID: planID, SourceRevisionID: source.ID, SourceDigest: source.ContentDigest, ServiceName: in.ServiceName, Kind: domain.BuildDockerfile, ContextPath: in.ContextPath, DockerfilePath: in.DockerfilePath, TargetRepository: in.TargetRepository, Output: domain.BuildOutputContract{Format: domain.BuildOutputOCI, Retention: domain.BuildRetentionPersist, StorageKey: "source-build-" + planID.String()}, IdempotencyKey: in.IdempotencyKey, CreatedAt: now, AcornFoxDefinitionDigest: definition.DefinitionDigest, AcornFoxDockerfileDigest: definition.DockerfileDigest, AcornFoxNetworkMode: policy.NetworkMode, AcornFoxWorkerPolicyDigest: policy.WorkerPolicyDigest}
	if err := plan.Validate(); err != nil {
		return zero, err
	}
	f, err := s.approveSourceBuildPlanTx(ctx, tx, admin, appcontracts.ApproveSourceBuildPlanInput{PrepareIntentID: in.PrepareIntentID, Plan: plan, Policy: policy, IdempotencyKey: in.IdempotencyKey}, now)
	if err != nil {
		return zero, err
	}
	if err := commitSourceBuildFacts(tx); err != nil {
		return zero, err
	}
	return f, nil
}

func (s *Store) ReadPublicSourceBuildIntent(ctx context.Context, admin, id domain.ID) (appcontracts.SourceBuildPublicIntent, error) {
	var out appcontracts.SourceBuildPublicIntent
	if err := s.checkOpen(); err != nil {
		return out, err
	}
	if admin.Empty() || id.Empty() {
		return out, domain.ValidationError("administrator and source-build intent required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if err := requireSourceBuildAdmin(ctx, tx, admin); err != nil {
		return out, err
	}
	if err := sourceBuildSchemaReadyTx(ctx, tx); err != nil {
		return out, err
	}
	var owner, opState string
	err = tx.QueryRowContext(ctx, `SELECT p.admin_id,p.application_id,p.operation_id,p.state,o.state FROM source_prepare_intents p JOIN operations o ON o.id=p.operation_id AND o.application_id=p.application_id JOIN task_leases t ON t.task_id=p.task_id AND t.operation_id=p.operation_id WHERE p.id=?`, id.String()).Scan(&owner, &out.ApplicationID, &out.OperationID, &out.State, &opState)
	out.IntentID = id
	out.Stage = appcontracts.SourceBuildPrepare
	if errors.Is(err, sql.ErrNoRows) {
		out.Stage = appcontracts.SourceBuildBuild
		err = tx.QueryRowContext(ctx, `SELECT b.admin_id,b.application_id,b.operation_id,b.state,o.state,b.prepare_intent_id,b.source_revision_id,b.plan_id,b.build_id FROM source_build_intents b JOIN operations o ON o.id=b.operation_id AND o.application_id=b.application_id JOIN task_leases t ON t.task_id=b.task_id AND t.operation_id=b.operation_id WHERE b.id=?`, id.String()).Scan(&owner, &out.ApplicationID, &out.OperationID, &out.State, &opState, &out.PrepareIntentID, &out.SourceRevisionID, &out.PlanID, &out.BuildID)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return appcontracts.SourceBuildPublicIntent{}, ErrNotFound
	}
	if err != nil {
		return appcontracts.SourceBuildPublicIntent{}, err
	}
	if owner != admin.String() {
		return appcontracts.SourceBuildPublicIntent{}, domain.NewError(domain.ErrForbidden, "source-build intent belongs to another administrator")
	}
	sourceIntent := out.PrepareIntentID
	if out.Stage == appcontracts.SourceBuildPrepare {
		sourceIntent = id
	}
	var sourceJSON, definitionRaw string
	err = tx.QueryRowContext(ctx, `SELECT revision,definition FROM native_source_revisions WHERE intent_id=? AND application_id=?`, sourceIntent.String(), out.ApplicationID.String()).Scan(&sourceJSON, &definitionRaw)
	if err == nil {
		var source domain.SourceRevision
		if json.Unmarshal([]byte(sourceJSON), &source) != nil || source.Validate() != nil || source.ApplicationID != out.ApplicationID || (out.Stage == appcontracts.SourceBuildBuild && source.ID != out.SourceRevisionID) {
			return appcontracts.SourceBuildPublicIntent{}, ErrCorruptData
		}
		out.SourceRevisionID = source.ID
		out.SourceDigest = source.ContentDigest
		var definition appcontracts.SourceBuildDefinitionFact
		if json.Unmarshal([]byte(definitionRaw), &definition) != nil || !validSourceBuildDefinition(definition, source) {
			return appcontracts.SourceBuildPublicIntent{}, ErrCorruptData
		}
		out.DefinitionStatus = definition.Status
		if out.Stage == appcontracts.SourceBuildPrepare && out.State == "prepared" && definition.Status != "ready" {
			out.ActionRequired = true
			if definition.Status == "waiting_later" {
				out.Reason = "root Dockerfile is missing"
			} else {
				out.Reason = "root Dockerfile is unsupported"
			}
		}

	} else if !errors.Is(err, sql.ErrNoRows) {
		return appcontracts.SourceBuildPublicIntent{}, err
	} else if out.State == "prepared" || out.Stage == appcontracts.SourceBuildBuild {
		return appcontracts.SourceBuildPublicIntent{}, ErrCorruptData
	}
	if out.Stage == appcontracts.SourceBuildBuild && out.State == "succeeded" {
		var buildJSON, artifactJSON string
		if err := tx.QueryRowContext(ctx, `SELECT build,artifact FROM source_build_results WHERE intent_id=? AND build_id=?`, id.String(), out.BuildID.String()).Scan(&buildJSON, &artifactJSON); err != nil {
			return appcontracts.SourceBuildPublicIntent{}, ErrCorruptData
		}
		var build domain.Build
		var artifact domain.Artifact
		if json.Unmarshal([]byte(buildJSON), &build) != nil || json.Unmarshal([]byte(artifactJSON), &artifact) != nil || artifact.Validate() != nil || build.ID != out.BuildID || build.PlanID != out.PlanID || build.Status != domain.BuildSucceeded || build.ArtifactID != artifact.ID || artifact.BuildID != out.BuildID {
			return appcontracts.SourceBuildPublicIntent{}, ErrCorruptData
		}
		out.ArtifactID = artifact.ID
		image := artifact.Image
		out.Image = &image
	}
	if out.State == "waiting" || opState == "waiting" {
		out.Reason = "source-build outcome requires review"
		out.ActionRequired = true
	} else if out.State == "failed" {
		out.Reason = "source-build task failed; review required"
		out.ActionRequired = true
	}
	return out, nil
}

var _ appcontracts.SourceBuildPublicStore = (*Store)(nil)
