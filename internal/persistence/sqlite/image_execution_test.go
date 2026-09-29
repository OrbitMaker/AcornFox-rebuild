package sqlite

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func sampleExecutionPlan(adminID domain.ID) appcontracts.ImagePlan {
	canonical := appcontracts.CanonicalExecutionInput{
		AppName:     "test-exec-app",
		Repository:  "ghcr.io/stefanprodan/podinfo",
		ResolvedRef: "latest",
		Port:        9898,
		Resources: appcontracts.RuntimeRequestedResources{
			CPUMillis:            500,
			MemoryBytes:          256 << 20,
			DiskReservationBytes: 512 << 20,
			PIDs:                 64,
		},
	}
	digest := "sha256:72611294759dc6b304d1f3efa2d4b1de212ce422866244f31bc29f731e3b2079"
	planDigest, _ := appcontracts.ComputePlanDigest(canonical, digest)

	now := time.Now().UTC()
	return appcontracts.ImagePlan{
		ID:             domain.ID("ipl_testexec001"),
		AdminID:        adminID,
		AppName:        canonical.AppName,
		Status:         appcontracts.ImagePlanStatusPlanned,
		PlanDigest:     planDigest,
		CanonicalInput: canonical,
		ResolvedImage: appcontracts.ResolvedImage{
			Repository:   canonical.Repository,
			Digest:       digest,
			ResolvedTag:  "latest",
			Architecture: "amd64",
			OS:           "linux",
		},
		ResolverProvenance: appcontracts.ResolverProvenance{
			Provider:   "registryhttp",
			Digest:     digest,
			ResolvedAt: now,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func setupExecutionStore(t *testing.T) (*Store, domain.ID, appcontracts.ConfirmImagePlanResult) {
	t.Helper()
	dir := secureTestDir(t, "image_exec_data")
	store, err := Open(Config{
		DataDirectory: dir,
		DBName:        "image-exec-test.db",
	})
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	adminID := domain.ID("adm_exec_test01")
	insertTestAdmin(t, store, adminID)

	plan := sampleExecutionPlan(adminID)
	if err := store.CreateImagePlan(ctx, plan); err != nil {
		t.Fatalf("CreateImagePlan: %v", err)
	}

	res, err := store.ConfirmImagePlan(ctx, adminID, appcontracts.ConfirmImagePlanInput{
		PlanID:         plan.ID,
		PlanDigest:     plan.PlanDigest,
		IdempotencyKey: "test-confirm-exec-key",
	})
	if err != nil {
		t.Fatalf("ConfirmImagePlan: %v", err)
	}

	return store, adminID, res
}

func TestImageExecution_BeginAuthorizeCommit(t *testing.T) {
	store, adminID, confirmRes := setupExecutionStore(t)
	ctx := context.Background()

	// 1. Claim task using existing TaskRepository
	owner := "worker-test-1"
	claimReq := appcontracts.ClaimTaskRequest{
		Kinds: []string{"image.deploy"},
		Owner: owner,
		Now:   time.Now().UTC(),
		LeasePolicy: appcontracts.LeasePolicy{
			Duration:    2 * time.Minute,
			MaxAttempts: 3,
		},
	}
	claimedTask, ok, err := store.ClaimTask(ctx, claimReq)
	if err != nil {
		t.Fatalf("ClaimTask failed: %v", err)
	}
	if !ok || claimedTask.ID != confirmRes.TaskID {
		t.Fatalf("expected claimed task %s, got ok=%v id=%s", confirmRes.TaskID, ok, claimedTask.ID)
	}

	// 2. BeginImageExecution binds release and deployment
	beginInput := appcontracts.BeginImageExecutionInput{
		TaskID:          claimedTask.ID,
		OperationID:     confirmRes.OperationID,
		Owner:           owner,
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		Now:             time.Now().UTC(),
	}
	binding, err := store.BeginImageExecution(ctx, beginInput)
	if err != nil {
		t.Fatalf("BeginImageExecution failed: %v", err)
	}
	if binding.ReleaseID.Empty() || binding.DeploymentID.Empty() {
		t.Fatalf("expected non-empty release and deployment IDs: %+v", binding)
	}
	if binding.Plan.PlanDigest != confirmRes.PlanDigest {
		t.Fatalf("expected plan digest %s, got %s", confirmRes.PlanDigest, binding.Plan.PlanDigest)
	}

	// 3. Repeat BeginImageExecution returns the exact same stable IDs (idempotency)
	binding2, err := store.BeginImageExecution(ctx, beginInput)
	if err != nil {
		t.Fatalf("BeginImageExecution repeat failed: %v", err)
	}
	if binding2.ReleaseID != binding.ReleaseID || binding2.DeploymentID != binding.DeploymentID {
		t.Fatalf("stable identities drifted: first=%+v second=%+v", binding, binding2)
	}

	// 4. AuthorizeImageExecution checks live fencing
	authInput := appcontracts.AuthorizeImageExecutionInput{
		TaskID:          claimedTask.ID,
		OperationID:     confirmRes.OperationID,
		DeploymentID:    binding.DeploymentID,
		PlanDigest:      confirmRes.PlanDigest,
		Owner:           owner,
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		Now:             time.Now().UTC(),
	}
	facts, err := store.AuthorizeImageExecution(ctx, authInput)
	if err != nil {
		t.Fatalf("AuthorizeImageExecution failed: %v", err)
	}
	if facts.PlanDigest != confirmRes.PlanDigest || facts.ApprovedPort != 9898 {
		t.Fatalf("unexpected authority facts: %+v", facts)
	}

	// Reject wrong owner
	wrongOwnerInput := authInput
	wrongOwnerInput.Owner = "intruder"
	if _, err := store.AuthorizeImageExecution(ctx, wrongOwnerInput); !errors.Is(err, appcontracts.ErrLeaseLost) {
		t.Fatalf("expected ErrLeaseLost for wrong owner, got %v", err)
	}

	// Reject wrong plan digest
	wrongPlanInput := authInput
	wrongPlanInput.PlanDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := store.AuthorizeImageExecution(ctx, wrongPlanInput); err == nil {
		t.Fatal("expected error for wrong plan digest, got nil")
	}

	// 5. CommitImageExecutionResult records observed facts and completes task atomically
	now := time.Now().UTC()
	commitInput := appcontracts.CommitImageExecutionResultInput{
		TaskID:          claimedTask.ID,
		OperationID:     confirmRes.OperationID,
		DeploymentID:    binding.DeploymentID,
		ReleaseID:       binding.ReleaseID,
		Owner:           owner,
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		Now:             now,
		ContainerID:     "c-podinfo-00123456",
		ContainerName:   "acornfox-podinfo-c1",
		ImageID:         "sha256:72611294759dc6b304d1f3efa2d4b1de212ce422866244f31bc29f731e3b2079",
		ManifestDigest:  "sha256:72611294759dc6b304d1f3efa2d4b1de212ce422866244f31bc29f731e3b2079",
		Artifact: appcontracts.StorageArtifactReceipt{
			StorageRef:    "image/ghcr.io/stefanprodan/podinfo/sha256_72611294",
			ContentDigest: "sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
			SizeBytes:     16777216,
		},
		HostPort:      39898,
		ContainerPort: 9898,
		ObservedAt:    now,
	}
	if err := store.CommitImageExecutionResult(ctx, commitInput); err != nil {
		t.Fatalf("CommitImageExecutionResult failed: %v", err)
	}

	// 6. Query operation detail through same Store: returns succeeded with durable results
	opDetail, err := store.GetImageOperation(ctx, adminID, confirmRes.OperationID)
	if err != nil {
		t.Fatalf("GetImageOperation failed: %v", err)
	}
	if opDetail.State != "succeeded" {
		t.Fatalf("expected state 'succeeded', got %s", opDetail.State)
	}
	if opDetail.Result == nil {
		t.Fatal("expected non-nil Result in operation detail")
	}
	if opDetail.Result.DeploymentID != binding.DeploymentID {
		t.Fatalf("expected deployment ID %s, got %s", binding.DeploymentID, opDetail.Result.DeploymentID)
	}
	if opDetail.Result.ContainerID != commitInput.ContainerID {
		t.Fatalf("expected container ID %s, got %s", commitInput.ContainerID, opDetail.Result.ContainerID)
	}
	if opDetail.Result.HostPort != 39898 || opDetail.Result.Endpoint != "http://127.0.0.1:39898" {
		t.Fatalf("expected loopback endpoint http://127.0.0.1:39898, got port=%d endpoint=%s", opDetail.Result.HostPort, opDetail.Result.Endpoint)
	}

	// 7. Late/stale commit attempt is rejected (task already completed)
	if err := store.CommitImageExecutionResult(ctx, commitInput); !errors.Is(err, appcontracts.ErrLeaseLost) {
		t.Fatalf("expected ErrLeaseLost for repeated commit on completed task, got %v", err)
	}

	// Observation can read terminal facts without a lease, but cannot mix plans.
	observed, err := store.ReadImageObservationBinding(ctx, confirmRes.OperationID, binding.DeploymentID)
	if err != nil || observed.ApplicationID != binding.ApplicationID || observed.ApprovedPort != 9898 || observed.Digest != commitInput.ManifestDigest {
		t.Fatalf("terminal observation binding: %+v, %v", observed, err)
	}
	if _, err := store.ReadImageObservationBinding(ctx, "op-unrelated", binding.DeploymentID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong operation accepted: %v", err)
	}
	// Deliberately corrupt only this disposable fixture to exercise the read guard.
	if _, err := store.db.ExecContext(ctx, "DROP TRIGGER image_releases_frozen"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "UPDATE image_releases SET plan_digest = ? WHERE id = ?", "sha256:"+strings.Repeat("f", 64), binding.ReleaseID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadImageObservationBinding(ctx, confirmRes.OperationID, binding.DeploymentID); !errors.Is(err, ErrCorruptData) {
		t.Fatalf("mixed release/plan binding accepted: %v", err)
	}
}

func TestImageExecution_FailTask(t *testing.T) {
	store, adminID, confirmRes := setupExecutionStore(t)
	ctx := context.Background()

	owner := "worker-test-fail"
	claimedTask, ok, err := store.ClaimTask(ctx, appcontracts.ClaimTaskRequest{
		Kinds: []string{"image.deploy"},
		Owner: owner,
		Now:   time.Now().UTC(),
		LeasePolicy: appcontracts.LeasePolicy{
			Duration:    time.Minute,
			MaxAttempts: 1, // Will exhaust on first fail
		},
	})
	if err != nil || !ok {
		t.Fatalf("ClaimTask: ok=%v err=%v", ok, err)
	}

	binding, err := store.BeginImageExecution(ctx, appcontracts.BeginImageExecutionInput{
		TaskID:          claimedTask.ID,
		OperationID:     confirmRes.OperationID,
		Owner:           owner,
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		Now:             time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("BeginImageExecution: %v", err)
	}

	// Terminal failure
	failInput := appcontracts.FailImageExecutionInput{
		TaskID:          claimedTask.ID,
		OperationID:     confirmRes.OperationID,
		DeploymentID:    binding.DeploymentID,
		Owner:           owner,
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		Reason:          "container execution failed explicitly",
		Now:             time.Now().UTC(),
	}
	if err := store.FailImageExecution(ctx, failInput); err != nil {
		t.Fatalf("FailImageExecution: %v", err)
	}

	opDetail, err := store.GetImageOperation(ctx, adminID, confirmRes.OperationID)
	if err != nil {
		t.Fatalf("GetImageOperation: %v", err)
	}
	if opDetail.State != "failed" {
		t.Fatalf("expected failed state, got %s", opDetail.State)
	}
}

func TestImageExecution_GuardValidation(t *testing.T) {
	store, _, confirmRes := setupExecutionStore(t)
	ctx := context.Background()

	owner := "worker-test-guards"
	claimedTask, ok, err := store.ClaimTask(ctx, appcontracts.ClaimTaskRequest{
		Kinds: []string{"image.deploy"},
		Owner: owner,
		Now:   time.Now().UTC(),
		LeasePolicy: appcontracts.LeasePolicy{
			Duration:    time.Minute,
			MaxAttempts: 3,
		},
	})
	if err != nil || !ok {
		t.Fatalf("ClaimTask: ok=%v err=%v", ok, err)
	}

	// 1. Cross-task rejection: provide a mismatched operation ID to Begin
	_, err = store.BeginImageExecution(ctx, appcontracts.BeginImageExecutionInput{
		TaskID:          claimedTask.ID,
		OperationID:     domain.ID("op_foreign_001"),
		Owner:           owner,
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		Now:             time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("expected error when TaskID does not match OperationID in Begin, got nil")
	}

	// Begin correctly
	binding, err := store.BeginImageExecution(ctx, appcontracts.BeginImageExecutionInput{
		TaskID:          claimedTask.ID,
		OperationID:     confirmRes.OperationID,
		Owner:           owner,
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		Now:             time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("BeginImageExecution: %v", err)
	}

	// 2. Port mismatch rejection in Commit
	now := time.Now().UTC()
	err = store.CommitImageExecutionResult(ctx, appcontracts.CommitImageExecutionResultInput{
		TaskID:          claimedTask.ID,
		OperationID:     confirmRes.OperationID,
		DeploymentID:    binding.DeploymentID,
		ReleaseID:       binding.ReleaseID,
		Owner:           owner,
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		Now:             now,
		ContainerID:     "cid-port-mismatch",
		ImageID:         "sha256:5b85a3c2678f134440c9502b406b7d6fb8fa83842f1f513f5fb4ebcbe5e638b9",
		ManifestDigest:  "sha256:72611294759dc6b304d1f3efa2d4b1de212ce422866244f31bc29f731e3b2079",
		Artifact: appcontracts.StorageArtifactReceipt{
			StorageRef:    "image/test",
			ContentDigest: "sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
			SizeBytes:     1024,
		},
		HostPort:      39898,
		ContainerPort: 80, // Plan requires 9898!
		ObservedAt:    now,
	})
	if err == nil {
		t.Fatal("expected conflict error on ContainerPort mismatch, got nil")
	}

	// 3. Zero or future ObservedAt rejection
	err = store.CommitImageExecutionResult(ctx, appcontracts.CommitImageExecutionResultInput{
		TaskID:          claimedTask.ID,
		OperationID:     confirmRes.OperationID,
		DeploymentID:    binding.DeploymentID,
		ReleaseID:       binding.ReleaseID,
		Owner:           owner,
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		Now:             now,
		ContainerID:     "cid-zero-obs",
		ImageID:         "sha256:5b85a3c2678f134440c9502b406b7d6fb8fa83842f1f513f5fb4ebcbe5e638b9",
		ManifestDigest:  "sha256:72611294759dc6b304d1f3efa2d4b1de212ce422866244f31bc29f731e3b2079",
		Artifact: appcontracts.StorageArtifactReceipt{
			StorageRef:    "image/test",
			ContentDigest: "sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
			SizeBytes:     1024,
		},
		HostPort:      39898,
		ContainerPort: 9898,
		ObservedAt:    time.Time{}, // Zero!
	})
	if err == nil {
		t.Fatal("expected validation error on zero ObservedAt, got nil")
	}

	// 4. Advanced DB core generation rejection
	if _, err := store.db.Exec(`UPDATE core_generation SET generation = generation + 1 WHERE singleton = 1`); err != nil {
		t.Fatalf("advance core generation in DB: %v", err)
	}

	// Authorize must fail now
	_, err = store.AuthorizeImageExecution(ctx, appcontracts.AuthorizeImageExecutionInput{
		TaskID:          claimedTask.ID,
		OperationID:     confirmRes.OperationID,
		DeploymentID:    binding.DeploymentID,
		PlanDigest:      confirmRes.PlanDigest,
		Owner:           owner,
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
	})
	if !errors.Is(err, appcontracts.ErrLeaseLost) {
		t.Fatalf("expected ErrLeaseLost after DB core generation advance, got %v", err)
	}

	// Commit must fail now
	err = store.CommitImageExecutionResult(ctx, appcontracts.CommitImageExecutionResultInput{
		TaskID:          claimedTask.ID,
		OperationID:     confirmRes.OperationID,
		DeploymentID:    binding.DeploymentID,
		ReleaseID:       binding.ReleaseID,
		Owner:           owner,
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		Now:             now,
		ContainerID:     "cid-advanced-core",
		ImageID:         "sha256:5b85a3c2678f134440c9502b406b7d6fb8fa83842f1f513f5fb4ebcbe5e638b9",
		ManifestDigest:  "sha256:72611294759dc6b304d1f3efa2d4b1de212ce422866244f31bc29f731e3b2079",
		Artifact: appcontracts.StorageArtifactReceipt{
			StorageRef:    "image/test",
			ContentDigest: "sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
			SizeBytes:     1024,
		},
		HostPort:      39898,
		ContainerPort: 9898,
		ObservedAt:    now,
	})
	if !errors.Is(err, appcontracts.ErrLeaseLost) {
		t.Fatalf("expected ErrLeaseLost in commit after DB core generation advance, got %v", err)
	}
}

func TestImageExecution_RecordUnknownAndReclaim(t *testing.T) {
	store, adminID, confirmRes := setupExecutionStore(t)
	ctx := context.Background()

	owner := "worker-test-unknown"
	claimedTask, ok, err := store.ClaimTask(ctx, appcontracts.ClaimTaskRequest{
		Kinds: []string{"image.deploy"},
		Owner: owner,
		Now:   time.Now().UTC(),
		LeasePolicy: appcontracts.LeasePolicy{
			Duration:    time.Minute,
			MaxAttempts: 3,
		},
	})
	if err != nil || !ok {
		t.Fatalf("ClaimTask: ok=%v err=%v", ok, err)
	}

	binding, err := store.BeginImageExecution(ctx, appcontracts.BeginImageExecutionInput{
		TaskID:          claimedTask.ID,
		OperationID:     confirmRes.OperationID,
		Owner:           owner,
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		Now:             time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("BeginImageExecution: %v", err)
	}

	// Record unknown outcome
	now := time.Now().UTC()
	err = store.RecordImageExecutionUnknown(ctx, appcontracts.RecordImageExecutionUnknownInput{
		TaskID:          claimedTask.ID,
		OperationID:     confirmRes.OperationID,
		DeploymentID:    binding.DeploymentID,
		Owner:           owner,
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		Reason:          "network timeout after dispatch",
		Now:             now,
	})
	if err != nil {
		t.Fatalf("RecordImageExecutionUnknown failed: %v", err)
	}

	// Operation detail should show state unknown
	detail, err := store.GetImageOperation(ctx, adminID, confirmRes.OperationID)
	if err != nil {
		t.Fatalf("GetImageOperation: %v", err)
	}
	if detail.State != "unknown" {
		t.Fatalf("expected state 'unknown', got %s", detail.State)
	}

	// Task should be ready for reclaim
	reclaimedTask, ok, err := store.ClaimTask(ctx, appcontracts.ClaimTaskRequest{
		Kinds: []string{"image.deploy"},
		Owner: "worker-reclaim",
		Now:   time.Now().UTC(),
		LeasePolicy: appcontracts.LeasePolicy{
			Duration:    time.Minute,
			MaxAttempts: 3,
		},
	})
	if err != nil || !ok {
		t.Fatalf("ClaimTask after unknown: ok=%v err=%v", ok, err)
	}
	if reclaimedTask.ID != claimedTask.ID {
		t.Fatalf("expected same task %s reclaimed, got %s", claimedTask.ID, reclaimedTask.ID)
	}

	// Begin on reclaimed task should succeed and reuse same deployment
	bindingReclaim, err := store.BeginImageExecution(ctx, appcontracts.BeginImageExecutionInput{
		TaskID:          reclaimedTask.ID,
		OperationID:     confirmRes.OperationID,
		Owner:           "worker-reclaim",
		CoreGeneration:  reclaimedTask.CoreGeneration,
		LeaseGeneration: reclaimedTask.LeaseGeneration,
		Now:             time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("BeginImageExecution on reclaim: %v", err)
	}
	if bindingReclaim.DeploymentID != binding.DeploymentID {
		t.Fatalf("expected same deployment %s on reclaim, got %s", binding.DeploymentID, bindingReclaim.DeploymentID)
	}

	// 2. Test unknown on exhausted attempt budget (MaxAttempts=1)
	storeExhaust, adminExhaust, confirmExhaust := setupExecutionStore(t)
	claimedExhaust, ok, err := storeExhaust.ClaimTask(ctx, appcontracts.ClaimTaskRequest{
		Kinds: []string{"image.deploy"},
		Owner: "worker-exhaust",
		Now:   time.Now().UTC(),
		LeasePolicy: appcontracts.LeasePolicy{
			Duration:    time.Minute,
			MaxAttempts: 1, // Will exhaust on first attempt!
		},
	})
	if err != nil || !ok {
		t.Fatalf("ClaimTask exhaust: ok=%v err=%v", ok, err)
	}

	bindingExhaust, err := storeExhaust.BeginImageExecution(ctx, appcontracts.BeginImageExecutionInput{
		TaskID:          claimedExhaust.ID,
		OperationID:     confirmExhaust.OperationID,
		Owner:           "worker-exhaust",
		CoreGeneration:  claimedExhaust.CoreGeneration,
		LeaseGeneration: claimedExhaust.LeaseGeneration,
		Now:             time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("BeginImageExecution exhaust: %v", err)
	}

	err = storeExhaust.RecordImageExecutionUnknown(ctx, appcontracts.RecordImageExecutionUnknownInput{
		TaskID:          claimedExhaust.ID,
		OperationID:     confirmExhaust.OperationID,
		DeploymentID:    bindingExhaust.DeploymentID,
		Owner:           "worker-exhaust",
		CoreGeneration:  claimedExhaust.CoreGeneration,
		LeaseGeneration: claimedExhaust.LeaseGeneration,
		Reason:          strings.Repeat("x", 1024),
		Now:             time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("RecordImageExecutionUnknown exhaust failed: %v", err)
	}

	// Task must remain ready with attempt==1 and cannot be auto-claimed
	_, ok, err = storeExhaust.ClaimTask(ctx, appcontracts.ClaimTaskRequest{
		Kinds: []string{"image.deploy"},
		Owner: "worker-cant-claim",
		Now:   time.Now().UTC(),
		LeasePolicy: appcontracts.LeasePolicy{
			Duration:    time.Minute,
			MaxAttempts: 1,
		},
	})
	if err != nil {
		t.Fatalf("ClaimTask check: %v", err)
	}
	if ok {
		t.Fatal("expected exhausted task NOT to be claimable, but was claimed")
	}

	// Operation detail should show state unknown
	detailExhaust, err := storeExhaust.GetImageOperation(ctx, adminExhaust, confirmExhaust.OperationID)
	if err != nil {
		t.Fatalf("GetImageOperation exhaust: %v", err)
	}
	if detailExhaust.State != "unknown" {
		t.Fatalf("expected state 'unknown', got %s", detailExhaust.State)
	}

	taskExhaust, err := storeExhaust.GetTask(ctx, claimedExhaust.ID)
	if err != nil || len(taskExhaust.LastError) > 1024 || !strings.Contains(taskExhaust.LastError, "needs_action") {
		t.Fatalf("exhaustion marker lost from bounded diagnostic: length=%d, err=%v", len(taskExhaust.LastError), err)
	}
}
