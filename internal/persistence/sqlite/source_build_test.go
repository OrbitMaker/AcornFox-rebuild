package sqlite

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/application"
	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
	"github.com/open-card/open-card/internal/importers/dockerfile"
	"github.com/open-card/open-card/internal/localpeer"
	capacityprovider "github.com/open-card/open-card/internal/providers/capacity"
	imageprovider "github.com/open-card/open-card/internal/providers/image"
	"github.com/open-card/open-card/internal/sourcebuildexecution"
)

// This disposable Store uses the registered 0012 migration. It is not
// provider/network execution or an installed Native worker proof.
func TestSourceBuildFactsRequirePreparedSourceAndFencedAuthority(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(Config{DataDirectory: directory})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	authority, err := application.NewCoreSourceBuildAuthority(store)
	if err != nil {
		t.Fatal(err)
	}
	admin := domain.ID("admin_source_fixture")
	insertTestAdmin(t, store, admin)
	commit := strings.Repeat("a", 40)
	sourceRoot := filepath.Join(directory, "source-workspace")
	if err := os.Mkdir(sourceRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "Dockerfile"), []byte("FROM scratch\nCMD [\"/app\"]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	digestHex, err := foundation.HashDirectory(sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + digestHex
	input := appcontracts.CreateSourcePrepareIntentInput{AppName: "native-source", Repository: "https://github.com/acme/app", Commit: commit, ExpectedContentDigest: digest, TimeoutSeconds: 120, IdempotencyKey: "source-prepare-unique"}
	if _, err := store.CreateSourcePrepareIntent(ctx, "missing_admin", input); err == nil {
		t.Fatal("nonexistent administrator created facts")
	}
	intent, err := store.CreateSourcePrepareIntent(ctx, admin, input)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := store.CreateSourcePrepareIntent(ctx, admin, input)
	if err != nil || replay.ID != intent.ID || replay.ApplicationID != intent.ApplicationID {
		t.Fatal("prepare intent replay changed real app/intent")
	}
	changed := input
	changed.Commit = strings.Repeat("c", 40)
	if _, err := store.CreateSourcePrepareIntent(ctx, admin, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed intent replay: %v", err)
	}
	claim := func(stage appcontracts.SourceBuildStage) appcontracts.SourceBuildBinding {
		t.Helper()
		task, ok, err := store.ClaimTask(ctx, appcontracts.ClaimTaskRequest{Kinds: []string{"source." + string(stage)}, Owner: "source-core-fixture", Now: time.Now().UTC(), LeasePolicy: appcontracts.LeasePolicy{Duration: 2 * time.Minute, MaxAttempts: 3}})
		if err != nil || !ok {
			t.Fatalf("claim: %v %v", ok, err)
		}
		return appcontracts.SourceBuildBinding{TaskID: task.ID, OperationID: task.OperationID, ApplicationID: intent.ApplicationID, Owner: task.LeaseOwner, CoreGeneration: uint64(task.CoreGeneration), LeaseGeneration: uint64(task.LeaseGeneration)}
	}
	prepareBinding := claim(appcontracts.SourceBuildPrepare)
	command, err := authority.ComposeSourceBuildStage(ctx, appcontracts.BeginSourceBuildStageInput{Binding: prepareBinding, Stage: appcontracts.SourceBuildPrepare})
	if err != nil {
		t.Fatal(err)
	}
	permit, err := authority.AuthorizeSourceBuild(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE admin_credentials SET disabled_at=? WHERE id=?`, FormatTime(time.Now().UTC()), admin.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.AuthorizeSourceBuild(ctx, command); err == nil {
		t.Fatal("disabled administrator retained active task authority")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE admin_credentials SET disabled_at=NULL WHERE id=?`, admin.String()); err != nil {
		t.Fatal(err)
	}

	wrong := command
	copyInput := *command.Prepare
	copyInput.WorkspaceRef = "/caller-chosen"
	wrong.Prepare = &copyInput
	if _, err := authority.AuthorizeSourceBuild(ctx, wrong); !errors.Is(err, sourcebuildexecution.ErrBinding) {
		t.Fatal("role self-authorized changed full input")
	}
	overflow := prepareBinding
	overflow.CoreGeneration = math.MaxUint64
	if _, err := store.ReadSourceBuildAuthority(ctx, overflow, appcontracts.SourceBuildPrepare, time.Now()); err == nil {
		t.Fatal("unsigned generation overflow accepted")
	}
	sourceID, err := domain.NewID("src")
	if err != nil {
		t.Fatal(err)
	}
	source := domain.SourceRevision{ID: sourceID, ApplicationID: intent.ApplicationID, Kind: domain.SourceGitHTTPS, Locator: input.Repository, Ref: commit, Commit: commit, ContentDigest: digest, WorkspaceRef: sourceRoot, CreatedAt: time.Now().UTC(), Immutable: true}
	evidence := func(kind string) appcontracts.SourceBuildEvidenceFact {
		return appcontracts.SourceBuildEvidenceFact{Digest: digest, Redacted: true, Refs: []domain.EvidenceRef{{ID: domain.ID("ev_" + kind), Kind: kind, Digest: digest, Locator: "source://evidence/" + kind}}}
	}
	resources := appcontracts.SourceBuildResourcesFact{CPUMillis: 500, MemoryBytes: 128 << 20, DiskBytes: 1 << 30, TimeoutSeconds: 120, ConcurrencySlot: 1, PIDs: 64}
	plan := domain.BuildPlan{ID: "plan_actual_source", SourceRevisionID: source.ID, SourceDigest: digest, ServiceName: "web", Kind: domain.BuildDockerfile, ContextPath: ".", DockerfilePath: "Dockerfile", TargetRepository: "ghcr.io/acme/native", Output: domain.BuildOutputContract{Format: domain.BuildOutputOCI, Retention: domain.BuildRetentionPersist, StorageKey: "native-artifact"}, IdempotencyKey: "build-plan-original", CreatedAt: time.Now().UTC(), AcornFoxNetworkMode: "none"}
	approve := appcontracts.ApproveSourceBuildPlanInput{PrepareIntentID: intent.ID, Plan: plan, Policy: appcontracts.SourceBuildPolicyFact{Resources: resources, NetworkMode: "none"}, IdempotencyKey: "source-build-unique"}
	if _, err := store.ApproveSourceBuildPlan(ctx, admin, approve); err == nil {
		t.Fatal("build approved before actual source was committed")
	}
	definition, err := dockerfile.Import(source)
	if err != nil || definition.Status != contracts.AcornFoxDockerfileReady {
		t.Fatal("actual fixture root Dockerfile is not ready")
	}
	receipt := appcontracts.CommitPreparedSourceInput{Binding: prepareBinding, CommandSHA256: permit.CommandSHA256, Revision: source, Evidence: evidence("source.prepare"), Definition: appcontracts.SourceBuildDefinitionFact{Status: string(definition.Status), SourceRevisionID: source.ID, SourceDigest: source.ContentDigest, DefinitionDigest: definition.DefinitionDigest, DockerfileDigest: definition.DockerfileDigest}}
	if err := store.CommitPreparedSource(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitPreparedSource(ctx, receipt); !errors.Is(err, appcontracts.ErrLeaseLost) {
		t.Fatal("old prepared receipt committed twice")
	}
	storedSource, err := store.ReadPreparedSource(ctx, admin, intent.ID)
	if err != nil || storedSource.ID != source.ID || storedSource.WorkspaceRef != source.WorkspaceRef {
		t.Fatal("Core could not recover actual persisted random source")
	}
	if _, err := store.ReadPreparedSource(ctx, "other_admin", intent.ID); err == nil {
		t.Fatal("foreign administrator read private workspace")
	}

	if _, err := store.db.ExecContext(ctx, `UPDATE admin_credentials SET disabled_at=? WHERE id=?`, FormatTime(time.Now().UTC()), admin.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSourcePrepareIntent(ctx, admin, input); err == nil {
		t.Fatal("disabled administrator replayed prepare")
	}
	if _, err := store.ReadPreparedSource(ctx, admin, intent.ID); err == nil {
		t.Fatal("disabled administrator read workspace")
	}
	if _, err := store.ApproveSourceBuildPlan(ctx, admin, approve); err == nil {
		t.Fatal("disabled administrator approved build")
	}
	insertTestAdmin(t, store, "other_admin")
	if _, err := store.ReadPreparedSource(ctx, "other_admin", intent.ID); err == nil {
		t.Fatal("enabled nonowner read private workspace")
	}
	if _, err := store.ApproveSourceBuildPlan(ctx, "other_admin", approve); err == nil {
		t.Fatal("enabled nonowner approved source build")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE admin_credentials SET disabled_at=? WHERE id=?`, FormatTime(time.Now().UTC()), "other_admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE admin_credentials SET disabled_at=NULL WHERE id=?`, admin.String()); err != nil {
		t.Fatal(err)
	}
	drift := approve
	drift.Plan.SourceRevisionID = "src_invented"
	if _, err := store.ApproveSourceBuildPlan(ctx, admin, drift); err == nil {
		t.Fatal("invented source revision approved")
	}
	buildIntent, err := store.ApproveSourceBuildPlan(ctx, admin, approve)
	if err != nil {
		t.Fatal(err)
	}
	replayBuild, err := store.ApproveSourceBuildPlan(ctx, admin, approve)
	if err != nil || replayBuild.BuildID != buildIntent.BuildID || replayBuild.OperationID != buildIntent.OperationID {
		t.Fatal("build approval did not replay original identity")
	}
	binding := claim(appcontracts.SourceBuildBuild)
	buildCommand, err := authority.ComposeSourceBuildStage(ctx, appcontracts.BeginSourceBuildStageInput{Binding: binding, Stage: appcontracts.SourceBuildBuild})
	if err != nil {
		t.Fatal(err)
	}
	buildPermit, err := authority.AuthorizeSourceBuild(ctx, buildCommand)
	if err != nil {
		t.Fatal(err)
	}
	bad := buildCommand
	body := *buildCommand.Build
	body.Resources.PIDs++
	bad.Build = &body
	if _, err := authority.AuthorizeSourceBuild(ctx, bad); !errors.Is(err, sourcebuildexecution.ErrBinding) {
		t.Fatal("modified resource budget authorized")
	}
	archive, manifestDigest, configDigest := sourceRunArchiveFixture(t)
	imageRoot := filepath.Join(directory, "source-oci")
	if err := os.Mkdir(imageRoot, 0700); err != nil {
		t.Fatal(err)
	}
	images, err := imageprovider.New(imageprovider.Config{Root: imageRoot})
	if err != nil {
		t.Fatal(err)
	}
	image := domain.ImageDigest{Repository: plan.TargetRepository, Digest: manifestDigest}
	storedArchive, err := images.StoreOCI(ctx, contracts.StoreOCIRequest{Image: image, StorageKey: "actual-byte-transaction-fixture", Archive: bytes.NewReader(archive), Operation: contracts.OperationContext{IdempotencyKey: "source-run-fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	artifact := domain.Artifact{ID: "artifact_actual", BuildID: buildIntent.BuildID, Image: image, OCIStorageRef: storedArchive.StorageRef, SizeBytes: storedArchive.SizeBytes, Evidence: []domain.EvidenceRef{{ID: "ev_actual_oci", Kind: "image.oci_store", Digest: storedArchive.Evidence.Digest, Locator: "image-store://source-fixture"}}, CreatedAt: time.Now().UTC()}
	build := domain.Build{ID: buildIntent.BuildID, PlanID: plan.ID, Status: domain.BuildSucceeded, ArtifactID: artifact.ID, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	output := appcontracts.CommitSourceBuildOutputInput{Binding: binding, CommandSHA256: buildPermit.CommandSHA256, Build: build, Artifact: artifact, LogRef: "durable-log-ref", Evidence: evidence("build.output")}
	if err := store.CommitSourceBuildOutput(ctx, output); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitSourceBuildOutput(ctx, output); !errors.Is(err, appcontracts.ErrLeaseLost) {
		t.Fatal("late build result accepted")
	}
	var resultCount, sourceCount int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM source_build_results`).Scan(&resultCount); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM native_source_revisions`).Scan(&sourceCount); err != nil {
		t.Fatal(err)
	}
	if resultCount != 1 || sourceCount != 1 {
		t.Fatal("two-stage facts were duplicated")
	}
	var events, audits int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM outbox_events WHERE aggregate_id IN (?,?)`, intent.OperationID.String(), buildIntent.OperationID.String()).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_evidence WHERE action IN ('source.prepare.accepted','source.prepare.completed','source.build.accepted','source.build.completed')`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if events != 4 || audits != 4 {
		t.Fatal("source/build facts did not include atomic audit/outbox")
	}
	// This asserts the same-owner/same-app Source result feeds an immutable
	// reviewable plan and distinct deployment confirm. The OCI bytes above are
	// structural test evidence, not a BuildKit success claim.
	original, err := store.ReadSourceBuiltArtifact(ctx, admin, buildIntent.ID, artifact.ID)
	if err != nil || original.ApplicationID != intent.ApplicationID || original.EnvironmentID != intent.EnvironmentID || original.ArchiveSHA256 != storedArchive.Evidence.Digest || original.Image.Digest != manifestDigest {
		t.Fatalf("original source artifact relation: %#v %v", original, err)
	}
	request := appcontracts.SourceRunPlanInput{BuildIntentID: buildIntent.ID, ArtifactID: artifact.ID, Port: 8080, IdempotencyKey: "original-source-run-plan"}
	canonical := appcontracts.CanonicalExecutionInput{AppName: input.AppName, Repository: image.Repository, ResolvedRef: image.Digest, Port: 8080, Resources: appcontracts.RuntimeRequestedResources{CPUMillis: 500, MemoryBytes: 128 << 20, DiskReservationBytes: 1 << 30, PIDs: 64}}
	observed := appcontracts.SourceRunOCIIdentity{ArchiveSize: storedArchive.SizeBytes, ManifestDigest: manifestDigest, ConfigDigest: configDigest, OS: "linux", Architecture: "amd64"}
	if _, found, err := store.ReadSourceRunPlanReplay(ctx, admin, request, canonical); err != nil || found {
		t.Fatalf("new plan falsely replayed: %v %v", found, err)
	}
	runPlan, err := store.CreateSourceRunPlan(ctx, admin, request, canonical, observed)
	if err != nil || runPlan.ResolverProvenance.Provider != "source-build" || runPlan.ResolverProvenance.EvidenceRef != artifact.ID.String() {
		t.Fatalf("original source-run plan: %#v %v", runPlan, err)
	}
	if read, err := store.ReadSourceRunPlan(ctx, admin, runPlan.ID); err != nil || read.ID != runPlan.ID {
		t.Fatalf("owner could not read original plan: %#v %v", read, err)
	}
	if _, err := store.ReadSourceRunPlan(ctx, "other_admin", runPlan.ID); err == nil {
		t.Fatal("foreign administrator read source-run plan")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE admin_credentials SET disabled_at=? WHERE id=?`, FormatTime(time.Now().UTC()), admin.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadSourceRunPlan(ctx, admin, runPlan.ID); err == nil {
		t.Fatal("disabled administrator read source-run plan")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE admin_credentials SET disabled_at=NULL WHERE id=?`, admin.String()); err != nil {
		t.Fatal(err)
	}
	if replay, found, err := store.ReadSourceRunPlanReplay(ctx, admin, request, canonical); err != nil || !found || replay.ID != runPlan.ID {
		t.Fatalf("completed plan did not replay from Core: %#v %v %v", replay, found, err)
	}
	badOCI := observed
	badOCI.ManifestDigest = source.ContentDigest
	changedRun := request
	changedRun.IdempotencyKey = "unverified-source-run"
	if _, err := store.CreateSourceRunPlan(ctx, admin, changedRun, canonical, badOCI); err == nil {
		t.Fatal("unverified manifest became a source-run plan")
	}
	confirmation := appcontracts.ConfirmImagePlanInput{PlanID: runPlan.ID, PlanDigest: runPlan.PlanDigest, IdempotencyKey: "original-source-run-confirm"}
	accepted, err := store.ConfirmSourceRunPlan(ctx, admin, confirmation)
	if err != nil || accepted.ApplicationID != intent.ApplicationID || accepted.EnvironmentID != intent.EnvironmentID {
		t.Fatalf("source-run created a different application: %#v %v", accepted, err)
	}
	if replay, err := store.ConfirmSourceRunPlan(ctx, admin, confirmation); err != nil || replay.OperationID != accepted.OperationID {
		t.Fatalf("confirm replay changed operation: %#v %v", replay, err)
	}
	secondConfirm := confirmation
	secondConfirm.IdempotencyKey = "different-source-run-confirm"
	if _, err := store.ConfirmSourceRunPlan(ctx, admin, secondConfirm); err == nil {
		t.Fatal("second key created competing deployment intent for original app")
	}
	claimed, ok, err := store.ClaimTask(ctx, appcontracts.ClaimTaskRequest{Kinds: []string{"image.deploy"}, Owner: "source-image-worker", Now: time.Now().UTC(), LeasePolicy: appcontracts.LeasePolicy{Duration: time.Minute, MaxAttempts: 3}})
	if err != nil || !ok || claimed.ID != accepted.TaskID {
		t.Fatalf("source-run image task not claimed: %#v %v %v", claimed, ok, err)
	}
	imageBinding, err := store.BeginImageExecution(ctx, appcontracts.BeginImageExecutionInput{TaskID: claimed.ID, OperationID: claimed.OperationID, Owner: claimed.LeaseOwner, CoreGeneration: claimed.CoreGeneration, LeaseGeneration: claimed.LeaseGeneration, Now: time.Now().UTC()})
	if err != nil || imageBinding.SourceArtifact == nil || imageBinding.SourceArtifact.ArtifactID != artifact.ID {
		t.Fatalf("image worker lost source provenance: %#v %v", imageBinding.SourceArtifact, err)
	}
	authorized, err := store.AuthorizeImageExecution(ctx, appcontracts.AuthorizeImageExecutionInput{TaskID: claimed.ID, OperationID: claimed.OperationID, DeploymentID: imageBinding.DeploymentID, PlanDigest: runPlan.PlanDigest, Owner: claimed.LeaseOwner, CoreGeneration: claimed.CoreGeneration, LeaseGeneration: claimed.LeaseGeneration, Now: time.Now().UTC()})
	if err != nil || authorized.ImageOrigin != "source-build" || authorized.SourceArtifact == nil || authorized.SourceArtifact.ArchiveSHA256 != storedArchive.Evidence.Digest {
		t.Fatalf("Core authority lost original archive: %#v %v", authorized, err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE task_leases SET max_attempts=1 WHERE task_id=?`, claimed.ID.String()); err != nil {
		t.Fatal(err)
	}
	if err := store.FailImageExecution(ctx, appcontracts.FailImageExecutionInput{TaskID: claimed.ID, OperationID: claimed.OperationID, DeploymentID: imageBinding.DeploymentID, Owner: claimed.LeaseOwner, CoreGeneration: claimed.CoreGeneration, LeaseGeneration: claimed.LeaseGeneration, Reason: "transaction fixture ends before Docker", Now: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	// The next real task retains unknown state and budget. Reclaim does not
	// blindly authorize another build or release the prepared workspace.
	unknownPlan := approve
	unknownPlan.Plan.ID = "plan_unknown_source"
	unknownPlan.Plan.IdempotencyKey = "plan-unknown-key"
	unknownPlan.IdempotencyKey = "build-unknown-key"
	unknownIntent, err := store.ApproveSourceBuildPlan(ctx, admin, unknownPlan)
	if err != nil {
		t.Fatal(err)
	}
	unknownBinding := claim(appcontracts.SourceBuildBuild)
	if _, err := authority.ComposeSourceBuildStage(ctx, appcontracts.BeginSourceBuildStageInput{Binding: unknownBinding, Stage: appcontracts.SourceBuildBuild}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordSourceBuildUnknown(ctx, unknownBinding, appcontracts.SourceBuildBuild, "transport token=private-token /owned/private-workspace /logs/private-build", time.Now()); err != nil {
		t.Fatal(err)
	}
	reclaimed := claim(appcontracts.SourceBuildBuild)
	task, err := store.GetTask(ctx, reclaimed.TaskID)
	if err != nil || task.Attempt != 2 || task.MaxAttempts != 3 || task.LastError == "" || !strings.Contains(task.LastError, "transport") || strings.Contains(task.LastError, "private-token") {
		t.Fatal("unknown reset budget or leaked diagnostic")
	}
	if _, err := authority.ComposeSourceBuildStage(ctx, appcontracts.BeginSourceBuildStageInput{Binding: reclaimed, Stage: appcontracts.SourceBuildBuild}); err == nil {
		t.Fatal("unknown outcome blindly reauthorized effects")
	}
	if _, err := authority.AuthorizeSourceBuild(ctx, buildCommand); !errors.Is(err, appcontracts.ErrLeaseLost) {
		t.Fatal("completed generation retained authority")
	}
	unknownPublic, err := store.ReadPublicSourceBuildIntent(ctx, admin, unknownIntent.ID)
	if err != nil || !unknownPublic.ActionRequired || unknownPublic.Reason != "source-build outcome requires review" {
		t.Fatal("public unknown did not use fixed status reason")
	}
	rawPublic, _ := json.Marshal(unknownPublic)
	for _, private := range []string{"private-token", "/owned/private-workspace", "/logs/private-build"} {
		if strings.Contains(string(rawPublic), private) {
			t.Fatal("private task diagnostic leaked to public source response")
		}
	}
	emptyWorkspace := filepath.Join(directory, "missing-root-Dockerfile")
	if err := os.Mkdir(emptyWorkspace, 0700); err != nil {
		t.Fatal(err)
	}
	emptyHash, err := foundation.HashDirectory(emptyWorkspace)
	if err != nil {
		t.Fatal(err)
	}
	missingInput := appcontracts.CreateSourcePrepareIntentInput{AppName: "missing-root", Repository: "https://github.com/acme/missing", Commit: commit, TimeoutSeconds: 120, IdempotencyKey: "missing-root-prepare"}
	missingIntent, err := store.CreateSourcePrepareIntent(ctx, admin, missingInput)
	if err != nil {
		t.Fatal(err)
	}
	missingTask, ok, err := store.ClaimTask(ctx, appcontracts.ClaimTaskRequest{Kinds: []string{"source.prepare"}, Owner: "source-core-fixture", Now: time.Now().UTC(), LeasePolicy: appcontracts.LeasePolicy{Duration: 2 * time.Minute, MaxAttempts: 3}})
	if err != nil || !ok {
		t.Fatal("missing Dockerfile source claim unavailable")
	}
	missingBinding := appcontracts.SourceBuildBinding{TaskID: missingTask.ID, OperationID: missingTask.OperationID, ApplicationID: missingIntent.ApplicationID, Owner: missingTask.LeaseOwner, CoreGeneration: uint64(missingTask.CoreGeneration), LeaseGeneration: uint64(missingTask.LeaseGeneration)}
	missingCommand, err := authority.ComposeSourceBuildStage(ctx, appcontracts.BeginSourceBuildStageInput{Binding: missingBinding, Stage: appcontracts.SourceBuildPrepare})
	if err != nil {
		t.Fatal(err)
	}
	missingSHA, _ := sourcebuildexecution.SourceBuildCommandDigest(missingCommand)
	missingID, err := domain.NewID("src")
	if err != nil {
		t.Fatal(err)
	}
	missingSource := domain.SourceRevision{ID: missingID, ApplicationID: missingIntent.ApplicationID, Kind: domain.SourceGitHTTPS, Locator: missingInput.Repository, Ref: commit, Commit: commit, ContentDigest: "sha256:" + emptyHash, WorkspaceRef: emptyWorkspace, CreatedAt: time.Now().UTC(), Immutable: true}
	missingDefinition, err := dockerfile.Import(missingSource)
	if err != nil || missingDefinition.Status != contracts.AcornFoxDockerfileWaitingLater {
		t.Fatal("missing root Dockerfile was not actually observed")
	}
	missingFact := appcontracts.SourceBuildDefinitionFact{Status: string(missingDefinition.Status), SourceRevisionID: missingSource.ID, SourceDigest: missingSource.ContentDigest, DefinitionDigest: missingDefinition.DefinitionDigest, DockerfileDigest: missingDefinition.DockerfileDigest}
	missingEvidence := appcontracts.SourceBuildEvidenceFact{Digest: missingSource.ContentDigest, Redacted: true, Refs: []domain.EvidenceRef{{ID: "ev_missing_source", Kind: "source.prepare", Digest: missingSource.ContentDigest, Locator: "source://evidence/missing"}}}
	if err := store.CommitPreparedSource(ctx, appcontracts.CommitPreparedSourceInput{Binding: missingBinding, Revision: missingSource, CommandSHA256: missingSHA, Definition: missingFact, Evidence: missingEvidence}); err != nil {
		t.Fatal(err)
	}
	missingPublic, err := store.ReadPublicSourceBuildIntent(ctx, admin, missingIntent.ID)
	if err != nil || missingPublic.State != "prepared" || missingPublic.DefinitionStatus != "waiting_later" || !missingPublic.ActionRequired || missingPublic.Reason != "root Dockerfile is missing" {
		t.Fatal("missing root Dockerfile did not remain prepared needs-input")
	}
	missingResources := resources
	missingResources.MemoryBytes = appcontracts.SourceBuildPublicMemoryBytes
	missingResources.PIDs = 0
	missingApproval := appcontracts.SourceBuildPublicApprovalInput{PrepareIntentID: missingIntent.ID, SourceRevisionID: missingSource.ID, SourceDigest: missingSource.ContentDigest, ServiceName: "web", ContextPath: ".", DockerfilePath: "Dockerfile", TargetRepository: "ghcr.io/acme/missing", Resources: missingResources, IdempotencyKey: "missing-root-approval"}
	if _, err := store.ApprovePublicSourceBuildPlan(ctx, admin, missingApproval, appcontracts.SourceBuildPolicyFact{Resources: missingResources, NetworkMode: "controlled_egress_v1", WorkerPolicyDigest: "sha256:" + strings.Repeat("e", 64)}); !errors.Is(err, ErrSourceDefinitionNeedsInput) {
		t.Fatalf("missing Dockerfile approval returned wrong category: %v", err)
	}

}

// The consumer fixture uses the real Store, worker, Core authority, role adapter
// and capacity provider. Source/build external effects are controlled providers;
// this is not Native IPC or a physical BuildKit acceptance test.
func TestSourceBuildWorkerConsumesDurableFacts(t *testing.T) { runSourceBuildWorkerFixture(t, false) }
func TestSourceBuildWorkerDeadlineSurvivesRenewAndCancelsOnLeaseLoss(t *testing.T) {
	runSourceBuildWorkerFixture(t, true)
}
func runSourceBuildWorkerFixture(t *testing.T, leaseProbe bool) {
	if runtime.GOOS != "linux" {
		t.Skip("real kernel Unix peer fixture requires Linux")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(Config{DataDirectory: root})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	admin := domain.ID("admin_worker_fixture")
	insertTestAdmin(t, store, admin)
	sourceRoot := filepath.Join(root, "worker-workspace")
	if err := os.Mkdir(sourceRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "Dockerfile"), []byte("FROM scratch\nCMD [\"/app\"]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	digestHex, err := foundation.HashDirectory(sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + digestHex
	authority, err := application.NewCoreSourceBuildAuthority(store)
	if err != nil {
		t.Fatal(err)
	}
	cap, err := capacityprovider.New(capacityprovider.Config{Reader: capacityprovider.ReaderFunc(func(context.Context, string) (capacityprovider.HostCapacity, error) {
		return capacityprovider.HostCapacity{TotalCPUMillis: 10000, AvailableCPUMillis: 10000, TotalMemoryBytes: 4 << 30, AvailableMemoryBytes: 4 << 30, TotalDiskBytes: 4 << 30, AvailableDiskBytes: 4 << 30}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	provider := &workerStageProvider{digest: digest, capacity: cap, workspaceRef: sourceRoot}
	// Same-process kernel credentials keep this a transport fixture, not
	// isolated role deployment. Production still requires distinct sealed tuples.
	att, err := localpeer.AttestLinuxProcess(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	peerValidator := func(pid int32, uid uint32) error {
		return localpeer.VerifyProcessIdentity(pid, uid, att.ExecutableSHA256, att.StartTime)
	}
	authorityPath := filepath.Join(root, "source-authority.sock")
	authorityServer, err := sourcebuildexecution.NewAuthorityServer(sourcebuildexecution.ServerConfig{SocketPath: authorityPath, ExpectedPID: att.PID, ExpectedUID: att.UID, PeerValidator: peerValidator}, authority)
	if err != nil {
		t.Fatal(err)
	}
	defer authorityServer.Close()
	authorityClient, err := sourcebuildexecution.NewAuthorityClient(sourcebuildexecution.ClientConfig{SocketPath: authorityPath, ExpectedPID: att.PID, ExpectedUID: att.UID, PeerValidator: peerValidator})
	if err != nil {
		t.Fatal(err)
	}
	role, err := sourcebuildexecution.NewRuntime(sourcebuildexecution.Config{Source: provider, Authority: authorityClient, Capacity: cap, BuilderFactory: func(c contracts.CapacityProvider) (contracts.BuildProvider, error) {
		if c != cap {
			t.Fatal("capacity owner substituted")
		}
		return provider, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	executePath := filepath.Join(root, "source-execute.sock")
	executionServer, err := sourcebuildexecution.NewExecutionServer(sourcebuildexecution.ServerConfig{SocketPath: executePath, ExpectedPID: att.PID, ExpectedUID: att.UID, PeerValidator: peerValidator}, role)
	if err != nil {
		t.Fatal(err)
	}
	defer executionServer.Close()
	executionClient, err := sourcebuildexecution.NewClient(sourcebuildexecution.ClientConfig{SocketPath: executePath, ExpectedPID: att.PID, ExpectedUID: att.UID, PeerValidator: peerValidator})
	if err != nil {
		t.Fatal(err)
	}
	var publicService *application.SourceBuildService
	var intent appcontracts.SourceBuildIntentFact
	prepareInput := appcontracts.CreateSourcePrepareIntentInput{AppName: "worker-source", Repository: "https://github.com/acme/app", Commit: strings.Repeat("a", 40), ExpectedContentDigest: digest, TimeoutSeconds: 120, IdempotencyKey: "worker-prepare"}
	if leaseProbe {
		intent, err = store.CreateSourcePrepareIntent(ctx, admin, prepareInput)
	} else {
		if err := store.SourceBuildSchemaReady(ctx); err != nil {
			t.Fatal("registered source schema unavailable", err)
		}
		publicService = &application.SourceBuildService{Store: store, Policy: appcontracts.SourceBuildPolicyFact{NetworkMode: "controlled_egress_v1", WorkerPolicyDigest: "sha256:" + strings.Repeat("e", 64)}, Available: executionClient.CheckReady}
		accepted, prepareErr := publicService.Prepare(ctx, admin, prepareInput)
		err = prepareErr
		intent = appcontracts.SourceBuildIntentFact{ID: accepted.IntentID, ApplicationID: accepted.ApplicationID, OperationID: accepted.OperationID}
		replay, err := publicService.Prepare(ctx, admin, prepareInput)
		if err != nil || replay.IntentID != accepted.IntentID {
			t.Fatal("public prepare replay changed actual identity")
		}
		tooLong := prepareInput
		tooLong.TimeoutSeconds = 121
		if _, err := publicService.Prepare(ctx, admin, tooLong); err == nil {
			t.Fatal("public Prepare advertised beyond actual120s capability")
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	leaseDuration := 2 * time.Minute
	if leaseProbe {
		leaseDuration = 3 * time.Second
	}
	worker, err := application.NewSourceBuildExecutionWorker(application.SourceBuildExecutionWorkerConfig{WorkerID: "core-worker-fixture", LeaseDuration: leaseDuration, Store: store, TaskRepo: store, Client: executionClient})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := worker.PollOnce(ctx); !ok || err != nil {
		t.Fatalf("prepare consumer: %v %v", ok, err)
	}
	source, err := store.ReadPreparedSource(ctx, admin, intent.ID)
	if err != nil || source.ID != "src_actual_worker" {
		t.Fatalf("persist actual random revision: %v", err)
	}
	plan := domain.BuildPlan{ID: "plan_worker", SourceRevisionID: source.ID, SourceDigest: digest, ServiceName: "web", Kind: domain.BuildDockerfile, ContextPath: ".", DockerfilePath: "Dockerfile", TargetRepository: "ghcr.io/acme/worker", Output: domain.BuildOutputContract{Format: domain.BuildOutputOCI, Retention: domain.BuildRetentionPersist, StorageKey: "worker-output"}, IdempotencyKey: "worker-plan", CreatedAt: time.Now().UTC(), AcornFoxNetworkMode: "none"}
	buildTimeout := int64(120)
	if leaseProbe {
		buildTimeout = 1200
		provider.entered = make(chan contracts.BuildRequest, 1)
		provider.cancelled = make(chan struct{})
	}
	var built appcontracts.SourceBuildIntentFact
	if leaseProbe {
		built, err = store.ApproveSourceBuildPlan(ctx, admin, appcontracts.ApproveSourceBuildPlanInput{PrepareIntentID: intent.ID, Plan: plan, Policy: appcontracts.SourceBuildPolicyFact{Resources: appcontracts.SourceBuildResourcesFact{CPUMillis: 500, MemoryBytes: 128 << 20, DiskBytes: 1 << 30, TimeoutSeconds: buildTimeout, ConcurrencySlot: 1, PIDs: 64}, NetworkMode: "none"}, IdempotencyKey: "worker-build"})
		if err != nil {
			t.Fatal(err)
		}
	} else {
		prepared, err := publicService.Read(ctx, admin, intent.ID)
		if err != nil || prepared.SourceRevisionID != source.ID || prepared.SourceDigest != digest || prepared.State != "prepared" {
			t.Fatal("public reader did not expose actual persisted revision")
		}
		activateAdmin := func(id domain.ID) {
			t.Helper()
			tx, err := store.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err := tx.ExecContext(ctx, `UPDATE admin_credentials SET disabled_at=? WHERE disabled_at IS NULL`, FormatTime(time.Now().UTC())); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE admin_credentials SET disabled_at=NULL WHERE id=?`, id.String()); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		secondAdmin := domain.ID("admin_public_other")
		if _, err := store.db.ExecContext(ctx, `UPDATE admin_credentials SET disabled_at=? WHERE id=?`, FormatTime(time.Now().UTC()), admin.String()); err != nil {
			t.Fatal(err)
		}
		insertTestAdmin(t, store, secondAdmin)
		if _, err := publicService.Read(ctx, secondAdmin, intent.ID); err == nil {
			t.Fatal("public source facts crossed ownership")
		} else {
			var domainErr *domain.DomainError
			if !errors.As(err, &domainErr) || domainErr.Code != domain.ErrForbidden {
				t.Fatalf("foreign active administrator did not reach ownership fence: %v", err)
			}
		}
		activateAdmin(admin)
		approval := appcontracts.SourceBuildPublicApprovalInput{PrepareIntentID: intent.ID, SourceRevisionID: source.ID, SourceDigest: digest, ServiceName: "web", ContextPath: ".", DockerfilePath: "Dockerfile", TargetRepository: "ghcr.io/acme/worker", Resources: appcontracts.SourceBuildResourcesFact{CPUMillis: appcontracts.SourceBuildPublicCPUMillis, MemoryBytes: appcontracts.SourceBuildPublicMemoryBytes, DiskBytes: 1 << 30, TimeoutSeconds: 120, ConcurrencySlot: 1, PIDs: 0}, IdempotencyKey: "worker-public-build"}
		invalidResource := approval
		invalidResource.Resources.PIDs = 64
		invalidResource.IdempotencyKey = "invalid-pids-approval"
		var beforeIntents int
		if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM source_build_intents`).Scan(&beforeIntents); err != nil {
			t.Fatal(err)
		}
		if _, err := publicService.ApproveBuild(ctx, admin, invalidResource); err == nil {
			t.Fatal("public PIDs64 was admitted before real BuildKit")
		}
		invalidName := approval
		invalidName.ServiceName = "bad/name"
		invalidName.IdempotencyKey = "invalid-service-name"
		if _, err := publicService.ApproveBuild(ctx, admin, invalidName); err == nil {
			t.Fatal("unsafe BuildKit service name was admitted")
		}
		var afterIntents int
		if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM source_build_intents`).Scan(&afterIntents); err != nil || afterIntents != beforeIntents || provider.built != 0 {
			t.Fatal("invalid public BuildKit inputs caused task/provider effects")
		}
		snapshot, _, err := cap.Preflight(ctx, contracts.CapacityRequest{Scope: contracts.CapacityBuild, Operation: contracts.OperationContext{IdempotencyKey: "public-invalid-no-reserve"}})
		if err != nil || snapshot.ReservedCPUMillis != 0 {
			t.Fatal("invalid public approval reserved real role capacity")
		}
		accepted, err := publicService.ApproveBuild(ctx, admin, approval)
		if err != nil {
			t.Fatal(err)
		}
		replay, err := publicService.ApproveBuild(ctx, admin, approval)
		if err != nil || replay.IntentID != accepted.IntentID || replay.PlanID != accepted.PlanID || replay.OperationID != accepted.OperationID {
			t.Fatal("generated public plan metadata broke same-key replay")
		}
		changed := approval
		changed.TargetRepository = "ghcr.io/acme/other"
		if _, err := publicService.ApproveBuild(ctx, admin, changed); !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatal("changed public semantic approval did not conflict")
		}
		wrongOwner := approval
		wrongOwner.IdempotencyKey = "foreign-public-build"
		activateAdmin(secondAdmin)
		if _, err := publicService.ApproveBuild(ctx, secondAdmin, wrongOwner); err == nil {
			t.Fatal("foreign administrator approved source")
		} else {
			var domainErr *domain.DomainError
			if !errors.As(err, &domainErr) || domainErr.Code != domain.ErrForbidden {
				t.Fatalf("foreign active administrator did not reach approval ownership fence: %v", err)
			}
		}
		activateAdmin(admin)
		built = appcontracts.SourceBuildIntentFact{ID: accepted.IntentID, ApplicationID: accepted.ApplicationID, OperationID: accepted.OperationID, BuildID: accepted.BuildID}
		if err := store.db.QueryRowContext(ctx, `SELECT task_id FROM source_build_intents WHERE id=?`, built.ID.String()).Scan(&built.TaskID); err != nil {
			t.Fatal(err)
		}
	}
	if leaseProbe {
		done := make(chan error, 1)
		joined := false
		defer func() {
			cancel()
			if !joined {
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Error("worker cleanup did not join")
				}
			}
		}()
		go func() { _, err := worker.PollOnce(ctx); done <- err }()
		var request contracts.BuildRequest
		select {
		case request = <-provider.entered:
		case <-time.After(time.Second):
			t.Fatal("build never reached actual Unix role")
		}
		task, err := store.GetTask(ctx, built.TaskID)
		if err != nil || task.LeaseUntil == nil {
			t.Fatal("initial build lease unavailable")
		}
		initialUntil := *task.LeaseUntil
		if !request.Operation.Deadline.After(initialUntil.Add(10 * time.Minute)) {
			t.Fatal("approved20min execution deadline was truncated to initial task lease")
		}
		var sealedSHA, sealedDeadline string
		if err := store.db.QueryRowContext(ctx, `SELECT command_sha,deadline FROM source_build_intents WHERE id=?`, built.ID.String()).Scan(&sealedSHA, &sealedDeadline); err != nil {
			t.Fatal(err)
		}
		wait := time.Until(initialUntil.Add(100 * time.Millisecond))
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case err := <-done:
				joined = true
				timer.Stop()
				t.Fatalf("build stopped at initial lease: %v", err)
			}
		}
		renewed, err := store.GetTask(ctx, built.TaskID)
		if err != nil || renewed.LeaseUntil == nil || !renewed.LeaseUntil.After(initialUntil) {
			t.Fatal("real lease was not renewed past initial deadline")
		}
		binding := appcontracts.SourceBuildBinding{TaskID: renewed.ID, OperationID: renewed.OperationID, ApplicationID: built.ApplicationID, Owner: renewed.LeaseOwner, CoreGeneration: uint64(renewed.CoreGeneration), LeaseGeneration: uint64(renewed.LeaseGeneration)}
		unchanged, err := authority.ComposeSourceBuildStage(ctx, appcontracts.BeginSourceBuildStageInput{Binding: binding, Stage: appcontracts.SourceBuildBuild})
		if err != nil {
			t.Fatal("renewed actual claim lost authority")
		}
		actualSHA, _ := sourcebuildexecution.SourceBuildCommandDigest(unchanged)
		if actualSHA != sealedSHA || FormatTime(unchanged.Build.Operation.Deadline) != sealedDeadline {
			t.Fatal("renew rolled or resealed original operation deadline")
		}
		if _, err := authority.AuthorizeSourceBuild(ctx, unchanged); err != nil {
			t.Fatal("actual authority did not survive original lease boundary")
		}
		// Check expired operation authority independently from a live task lease:
		// fixture clock advances only the Begin check, after an actual longer renew.
		if err := store.RenewTask(ctx, appcontracts.TaskMutationRequest{TaskID: renewed.ID, Owner: renewed.LeaseOwner, CoreGeneration: renewed.CoreGeneration, LeaseGeneration: renewed.LeaseGeneration, Now: time.Now().UTC(), LeasePolicy: appcontracts.LeasePolicy{Duration: 21 * time.Minute}}); err != nil {
			t.Fatal(err)
		}
		if _, err := authority.ComposeSourceBuildStage(ctx, appcontracts.BeginSourceBuildStageInput{Binding: binding, Stage: appcontracts.SourceBuildBuild, Now: unchanged.Build.Operation.Deadline.Add(time.Second)}); err == nil {
			t.Fatal("expired sealed deadline was renewed into a new execution window")
		}
		var expiredSHA, expiredDeadline, expiredState string
		if err := store.db.QueryRowContext(ctx, `SELECT command_sha,deadline,state FROM source_build_intents WHERE id=?`, built.ID.String()).Scan(&expiredSHA, &expiredDeadline, &expiredState); err != nil || expiredSHA != sealedSHA || expiredDeadline != sealedDeadline || expiredState != "waiting" {
			t.Fatal("expired operation did not preserve sealed evidence/recovery barrier")
		}
		// Renew is monotonic, so a shorter duration cannot expire a lease.
		// The replacement worker uses the ordinary queue clock seam just past
		// the actual current lease, claiming the same task with a new tuple.
		latest, err := store.GetTask(ctx, built.TaskID)
		if err != nil || latest.LeaseUntil == nil {
			t.Fatal("current lease unavailable")
		}
		reclaimAt := latest.LeaseUntil.Add(time.Second)
		replacement, err := application.NewSourceBuildExecutionWorker(application.SourceBuildExecutionWorkerConfig{WorkerID: "replacement-worker", LeaseDuration: 3 * time.Second, Store: store, TaskRepo: store, Client: executionClient, Clock: func() time.Time { return reclaimAt }})
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := replacement.PollOnce(ctx); !ok || err == nil {
			t.Fatal("ordinary reclaim did not retain original unknown outcome")
		}
		select {
		case err := <-done:
			joined = true
			if !errors.Is(err, appcontracts.ErrLeaseLost) {
				t.Fatalf("lost lease did not stop RPC: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("lost lease worker did not cancel bounded RPC")
		}
		select {
		case <-provider.cancelled:
		case <-time.After(time.Second):
			t.Fatal("actual Unix role provider context was not cancelled")
		}
		if provider.built != 1 {
			t.Fatal("lost lease blindly redispatched provider build")
		}
		var state string
		var results int
		if err := store.db.QueryRowContext(ctx, `SELECT state FROM source_build_intents WHERE id=?`, built.ID.String()).Scan(&state); err != nil || state != "waiting" {
			t.Fatal("lost sealed claim did not persist recovery barrier")
		}
		if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM source_build_results WHERE intent_id=?`, built.ID.String()).Scan(&results); err != nil || results != 0 {
			t.Fatal("cancelled original claim committed stale output")
		}
		snapshot, _, err := cap.Preflight(ctx, contracts.CapacityRequest{Scope: contracts.CapacityBuild, Operation: contracts.OperationContext{IdempotencyKey: "verify-lost-capacity-retained"}})
		if err != nil || snapshot.ReservedCPUMillis != request.Resources.CPUMillis {
			t.Fatal("unknown BuildKit outcome blindly released real reservation")
		}
		return
	}
	if ok, err := worker.PollOnce(ctx); !ok || err != nil {
		t.Fatalf("build consumer: %v %v", ok, err)
	}
	task, err := store.GetTask(ctx, built.TaskID)
	if err != nil || task.State != appcontracts.TaskCompleted || provider.prepared != 1 || provider.built != 1 {
		t.Fatalf("consumer did not commit original task: %v %#v", err, task)
	}
	var artifactID string
	if err := store.db.QueryRowContext(ctx, `SELECT artifact_id FROM source_build_results WHERE intent_id=?`, built.ID.String()).Scan(&artifactID); err != nil || artifactID != "artifact_actual_worker" {
		t.Fatalf("actual artifact not persisted: %v", err)
	}
	if ok, err := worker.PollOnce(ctx); ok || err != nil {
		t.Fatal("completed task redispatched")
	}
	if publicService != nil {
		output, err := publicService.Read(ctx, admin, built.ID)
		if err != nil || output.State != "succeeded" || output.ArtifactID != "artifact_actual_worker" || output.Image == nil || output.BuildID != built.BuildID {
			t.Fatal("public result did not use actual committed build/artifact")
		}
		raw, _ := json.Marshal(output)
		for _, private := range []string{"workspace", "lease", "command_sha", "OCIStorage", "owned-provider-archive", "owned-log", "environment"} {
			if strings.Contains(string(raw), private) {
				t.Fatal("private source/build fact leaked in public result")
			}
		}
	}
	// A sealed running task whose worker vanished cannot authorize a second
	// provider call merely because the ordinary queue reclaimed its lease.
	lost, err := store.CreateSourcePrepareIntent(ctx, admin, appcontracts.CreateSourcePrepareIntentInput{AppName: "lost-worker-source", Repository: "https://github.com/acme/app", Commit: strings.Repeat("a", 40), TimeoutSeconds: 120, IdempotencyKey: "lost-worker-prepare"})
	if err != nil {
		t.Fatal(err)
	}
	task, ok, err := store.ClaimTask(ctx, appcontracts.ClaimTaskRequest{Kinds: []string{"source.prepare"}, Owner: "lost-worker", Now: time.Now().UTC(), LeasePolicy: appcontracts.LeasePolicy{Duration: time.Minute, MaxAttempts: 3}})
	if err != nil || !ok {
		t.Fatal("claim lost worker")
	}
	fence := appcontracts.SourceBuildBinding{TaskID: task.ID, OperationID: task.OperationID, ApplicationID: lost.ApplicationID, Owner: "lost-worker", CoreGeneration: uint64(task.CoreGeneration), LeaseGeneration: uint64(task.LeaseGeneration)}
	if _, err := authority.ComposeSourceBuildStage(ctx, appcontracts.BeginSourceBuildStageInput{Binding: fence, Stage: appcontracts.SourceBuildPrepare}); err != nil {
		t.Fatal(err)
	}
	reclaimAt := task.LeaseUntil.Add(time.Second)
	reclaimed, ok, err := store.ClaimTask(ctx, appcontracts.ClaimTaskRequest{Kinds: []string{"source.prepare"}, Owner: "replacement-worker", Now: reclaimAt, LeasePolicy: appcontracts.LeasePolicy{Duration: time.Minute, MaxAttempts: 3}})
	if err != nil || !ok || reclaimed.ID != task.ID {
		t.Fatal("reclaim original source task")
	}
	fence.Owner = "replacement-worker"
	fence.CoreGeneration = uint64(reclaimed.CoreGeneration)
	fence.LeaseGeneration = uint64(reclaimed.LeaseGeneration)
	if _, err := authority.ComposeSourceBuildStage(ctx, appcontracts.BeginSourceBuildStageInput{Binding: fence, Stage: appcontracts.SourceBuildPrepare, Now: reclaimAt}); err == nil {
		t.Fatal("lost worker reauthorized blind provider effects")
	}
	var state string
	if err := store.db.QueryRowContext(ctx, `SELECT state FROM source_prepare_intents WHERE id=?`, lost.ID.String()).Scan(&state); err != nil || state != "waiting" {
		t.Fatal("lost claim recovery barrier not durable")
	}
}

type workerStageProvider struct {
	digest          string
	workspaceRef    string
	capacity        contracts.CapacityProvider
	prepared, built int
	entered         chan contracts.BuildRequest
	cancelled       chan struct{}
}

func (p *workerStageProvider) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{}
}
func (p *workerStageProvider) Prepare(_ context.Context, r contracts.PrepareSourceRequest) (contracts.PrepareSourceResult, error) {
	p.prepared++
	return contracts.PrepareSourceResult{Revision: domain.SourceRevision{ID: "src_actual_worker", ApplicationID: r.ApplicationID, Kind: r.Kind, Locator: r.Locator, Ref: r.Ref, Commit: r.Ref, ContentDigest: p.digest, WorkspaceRef: p.workspaceRef, CreatedAt: time.Now().UTC(), Immutable: true}, Evidence: p.evidence()}, nil
}
func (p *workerStageProvider) Release(context.Context, contracts.ReleaseSourceRequest) error {
	return errors.New("release control unavailable")
}
func (p *workerStageProvider) Cancel(context.Context, contracts.OperationContext) error {
	return errors.New("cancel control unavailable")
}
func (p *workerStageProvider) Build(ctx context.Context, r contracts.BuildRequest) (contracts.BuildResult, error) {
	if r.Capacity == nil {
		return contracts.BuildResult{}, errors.New("missing real role lease")
	}
	if err := p.capacity.Activate(ctx, *r.Capacity, contracts.OperationContext{IdempotencyKey: r.Operation.IdempotencyKey + ":capacity-activate", Deadline: r.Operation.Deadline, Actor: r.Operation.Actor}); err != nil {
		return contracts.BuildResult{}, err
	}
	p.built++
	if p.entered != nil {
		p.entered <- r
		<-ctx.Done()
		close(p.cancelled)
		return contracts.BuildResult{}, ctx.Err()
	}
	artifact := domain.Artifact{ID: "artifact_actual_worker", BuildID: r.BuildID, Image: domain.ImageDigest{Repository: r.Plan.TargetRepository, Digest: p.digest}, OCIStorageRef: "owned-provider-archive", SizeBytes: 123, CreatedAt: time.Now().UTC()}
	return contracts.BuildResult{Build: domain.Build{ID: r.BuildID, PlanID: r.Plan.ID, Status: domain.BuildSucceeded, ArtifactID: artifact.ID}, Artifact: &artifact, LogRef: "owned-log", Evidence: p.evidence()}, nil
}
func (p *workerStageProvider) evidence() contracts.Evidence {
	return contracts.Evidence{Digest: p.digest, Redacted: true, Refs: []domain.EvidenceRef{{ID: "ev_worker", Kind: "source-build", Digest: p.digest, Locator: "source://owned-evidence"}}}
}
