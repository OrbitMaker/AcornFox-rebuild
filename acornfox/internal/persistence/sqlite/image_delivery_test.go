package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/auth"
	"github.com/acornfox/acornfox/internal/domain"
)

func insertTestAdmin(t *testing.T, store *Store, adminID domain.ID) {
	t.Helper()
	nowStr := FormatTime(time.Now().UTC())
	_, err := store.db.Exec(`
		INSERT INTO admin_credentials
			(id, password_hash_scheme, password_hash, credential_version, disabled_at, created_at, updated_at)
		VALUES (?, ?, '$pbkdf2-sha256$i=600000,l=32$c2FsdHNhbHQ$a2V5', 1, NULL, ?, ?);
	`, adminID.String(), auth.PasswordHashScheme, nowStr, nowStr)
	if err != nil {
		t.Fatalf("insert test admin credential: %v", err)
	}
}

func insertDisabledAdmin(t *testing.T, store *Store, adminID domain.ID) {
	t.Helper()
	nowStr := FormatTime(time.Now().UTC())
	_, err := store.db.Exec(`
		INSERT INTO admin_credentials
			(id, password_hash_scheme, password_hash, credential_version, disabled_at, created_at, updated_at)
		VALUES (?, ?, '$pbkdf2-sha256$i=600000,l=32$c2FsdHNhbHQ$a2V5', 1, ?, ?, ?);
	`, adminID.String(), auth.PasswordHashScheme, nowStr, nowStr, nowStr)
	if err != nil {
		t.Fatalf("insert disabled test admin credential: %v", err)
	}
}

func sampleImagePlan(adminID domain.ID, status appcontracts.ImagePlanStatus) appcontracts.ImagePlan {
	now := time.Now().UTC()
	port := 8080
	var missing []string
	if status == appcontracts.ImagePlanStatusNeedsInput {
		port = 0
		missing = []string{"container_port"}
	}
	canonical := appcontracts.CanonicalExecutionInput{
		AppName:     "sample-app",
		Repository:  "registry-1.docker.io/library/nginx",
		ResolvedRef: "1.27.0",
		Port:        port,
		Environment: []appcontracts.RuntimeEnvironmentVariable{
			{Name: "ENV", Value: "prod", Kind: "literal"},
		},
		Resources: appcontracts.RuntimeRequestedResources{
			CPUMillis:   500,
			MemoryBytes: 512 << 20,
		},
	}
	digest := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	planDigest, _ := appcontracts.ComputePlanDigest(canonical, digest)
	return appcontracts.ImagePlan{
		ID:             domain.ID("ipl_0123456789abcdef"),
		AdminID:        adminID,
		AppName:        "sample-app",
		Status:         status,
		PlanDigest:     planDigest,
		CanonicalInput: canonical,
		ResolvedImage: appcontracts.ResolvedImage{
			Repository:   "registry-1.docker.io/library/nginx",
			Digest:       digest,
			ResolvedTag:  "1.27.0",
			Architecture: "amd64",
			OS:           "linux",
		},
		ResolverProvenance: appcontracts.ResolverProvenance{
			Provider:    "registryhttp",
			EvidenceRef: "ev_test_1",
			Digest:      digest,
			ResolvedAt:  now,
		},
		MissingInputs: missing,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func TestImagePlan_CreateAndGet_WithOwnership(t *testing.T) {
	ctx := context.Background()
	dir := secureTestDir(t, "image_plan_create_get")
	store, err := Open(Config{DataDirectory: dir})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	admin1 := domain.ID("adm_owner_1")
	admin2 := domain.ID("adm_other_2")
	insertTestAdmin(t, store, admin1)
	insertDisabledAdmin(t, store, admin2)

	plan := sampleImagePlan(admin1, appcontracts.ImagePlanStatusPlanned)

	// 1. Create plan
	if err := store.CreateImagePlan(ctx, plan); err != nil {
		t.Fatalf("CreateImagePlan failed: %v", err)
	}

	// 2. Read back as owner: must succeed
	got, err := store.GetImagePlan(ctx, plan.ID, admin1)
	if err != nil {
		t.Fatalf("GetImagePlan failed: %v", err)
	}
	if got.ID != plan.ID || got.AppName != plan.AppName || got.PlanDigest != plan.PlanDigest {
		t.Fatalf("mismatched plan fields: %+v", got)
	}

	// 3. Read back as another admin: must be forbidden
	_, err = store.GetImagePlan(ctx, plan.ID, admin2)
	if err == nil {
		t.Fatalf("expected forbidden error for non-owner, got nil")
	}
	var domErr *domain.DomainError
	if !errors.As(err, &domErr) || domErr.Code != domain.ErrForbidden {
		t.Fatalf("expected ErrForbidden, got: %v", err)
	}

	// 4. Non-existent plan ID: must be not found
	_, err = store.GetImagePlan(ctx, domain.ID("ipl_nonexistent"), admin1)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}

	// 5. Verify status trigger immutability: UPDATE status must abort
	_, err = store.db.Exec(`UPDATE image_plans SET status = 'needs_input' WHERE id = ?;`, plan.ID.String())
	if err == nil {
		t.Fatalf("expected trigger to abort update on image_plans status, but got nil")
	}
}

func TestImagePlan_Confirm_Atomic_ReplayAndReopen(t *testing.T) {
	ctx := context.Background()
	dir := secureTestDir(t, "image_plan_confirm_replay")
	store, err := Open(Config{DataDirectory: dir})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	adminID := domain.ID("adm_confirm_owner")
	insertTestAdmin(t, store, adminID)

	plan := sampleImagePlan(adminID, appcontracts.ImagePlanStatusPlanned)
	if err := store.CreateImagePlan(ctx, plan); err != nil {
		t.Fatalf("CreateImagePlan: %v", err)
	}

	confirmInput := appcontracts.ConfirmImagePlanInput{
		PlanID:         plan.ID,
		PlanDigest:     plan.PlanDigest,
		IdempotencyKey: "confirm-key-1",
	}

	// 1. Confirm plan: creates app, env, operation, task, plan binding, outbox event, audit
	result1, err := store.ConfirmImagePlan(ctx, adminID, confirmInput)
	if err != nil {
		t.Fatalf("ConfirmImagePlan failed: %v", err)
	}
	if result1.ApplicationID.Empty() || result1.EnvironmentID.Empty() || result1.OperationID.Empty() || result1.TaskID.Empty() {
		t.Fatalf("confirm result missing durable IDs: %+v", result1)
	}
	if result1.Status != "pending" {
		t.Fatalf("expected status pending, got %s", result1.Status)
	}

	// Verify database rows
	var appCount, envCount, opCount, taskCount, intentCount, outboxCount, auditCount int
	_ = store.db.QueryRow("SELECT count(*) FROM applications;").Scan(&appCount)
	_ = store.db.QueryRow("SELECT count(*) FROM environments;").Scan(&envCount)
	_ = store.db.QueryRow("SELECT count(*) FROM operations WHERE operation_type = 'deploy_image';").Scan(&opCount)
	_ = store.db.QueryRow("SELECT count(*) FROM task_leases;").Scan(&taskCount)
	_ = store.db.QueryRow("SELECT count(*) FROM image_deploy_intents;").Scan(&intentCount)
	_ = store.db.QueryRow("SELECT count(*) FROM outbox_events;").Scan(&outboxCount)
	_ = store.db.QueryRow("SELECT count(*) FROM audit_evidence;").Scan(&auditCount)

	if appCount != 1 || envCount != 1 || opCount != 1 || taskCount != 1 || intentCount != 1 || outboxCount != 1 || auditCount != 1 {
		t.Fatalf("expected 1 row in all tables, got apps=%d envs=%d ops=%d tasks=%d intents=%d outbox=%d audit=%d",
			appCount, envCount, opCount, taskCount, intentCount, outboxCount, auditCount)
	}

	// 2. Same key replay before reopen: must return exact original response
	result2, err := store.ConfirmImagePlan(ctx, adminID, confirmInput)
	if err != nil {
		t.Fatalf("replay ConfirmImagePlan failed: %v", err)
	}
	if result1.OperationID != result2.OperationID || result1.ApplicationID != result2.ApplicationID || result1.TaskID != result2.TaskID {
		t.Fatalf("replay returned different IDs: %+v vs %+v", result1, result2)
	}

	// 3. Reopen store and verify idempotent replay survives store restart
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	store2, err := Open(Config{DataDirectory: dir})
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer store2.Close()

	result3, err := store2.ConfirmImagePlan(ctx, adminID, confirmInput)
	if err != nil {
		t.Fatalf("reopen replay failed: %v", err)
	}
	if result1.OperationID != result3.OperationID || result1.ApplicationID != result3.ApplicationID || result1.TaskID != result3.TaskID {
		t.Fatalf("reopened replay returned different IDs: %+v vs %+v", result1, result3)
	}

	// 4. Same key with different plan: must conflict
	conflictInput := appcontracts.ConfirmImagePlanInput{
		PlanID:         domain.ID("ipl_different_plan"),
		PlanDigest:     plan.PlanDigest,
		IdempotencyKey: "confirm-key-1",
	}
	_, err = store2.ConfirmImagePlan(ctx, adminID, conflictInput)
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected ErrIdempotencyConflict, got: %v", err)
	}
}

func TestImagePlan_Confirm_NeedsInputRefused(t *testing.T) {
	ctx := context.Background()
	dir := secureTestDir(t, "image_plan_needs_input_refused")
	store, err := Open(Config{DataDirectory: dir})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	adminID := domain.ID("adm_needs_input")
	insertTestAdmin(t, store, adminID)

	plan := sampleImagePlan(adminID, appcontracts.ImagePlanStatusNeedsInput)
	if err := store.CreateImagePlan(ctx, plan); err != nil {
		t.Fatalf("CreateImagePlan: %v", err)
	}

	confirmInput := appcontracts.ConfirmImagePlanInput{
		PlanID:         plan.ID,
		PlanDigest:     plan.PlanDigest,
		IdempotencyKey: "confirm-needs-input-key",
	}

	_, err = store.ConfirmImagePlan(ctx, adminID, confirmInput)
	if err == nil {
		t.Fatalf("expected error confirming needs_input plan, got nil")
	}
	var domErr *domain.DomainError
	if !errors.As(err, &domErr) || domErr.Code != domain.ErrConflict {
		t.Fatalf("expected ErrConflict, got: %v", err)
	}

	// Ensure no rows were created in applications, operations, or task_leases
	var appCount, opCount int
	_ = store.db.QueryRow("SELECT count(*) FROM applications;").Scan(&appCount)
	_ = store.db.QueryRow("SELECT count(*) FROM operations WHERE operation_type = 'deploy_image';").Scan(&opCount)
	if appCount != 0 || opCount != 0 {
		t.Fatalf("expected 0 application/operation rows, got app=%d op=%d", appCount, opCount)
	}
}

func TestImagePlan_Confirm_RollbackOnMismatchedDigest(t *testing.T) {
	ctx := context.Background()
	dir := secureTestDir(t, "image_plan_rollback_mismatched")
	store, err := Open(Config{DataDirectory: dir})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	adminID := domain.ID("adm_rollback")
	insertTestAdmin(t, store, adminID)

	plan := sampleImagePlan(adminID, appcontracts.ImagePlanStatusPlanned)
	if err := store.CreateImagePlan(ctx, plan); err != nil {
		t.Fatalf("CreateImagePlan: %v", err)
	}

	// Submit with tampered plan digest
	confirmInput := appcontracts.ConfirmImagePlanInput{
		PlanID:         plan.ID,
		PlanDigest:     "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		IdempotencyKey: "tampered-digest-key",
	}

	_, err = store.ConfirmImagePlan(ctx, adminID, confirmInput)
	if err == nil {
		t.Fatalf("expected error confirming plan with tampered digest, got nil")
	}

	// Verify rollback: no application or operation created
	var appCount, opCount, taskCount int
	_ = store.db.QueryRow("SELECT count(*) FROM applications;").Scan(&appCount)
	_ = store.db.QueryRow("SELECT count(*) FROM operations WHERE operation_type = 'deploy_image';").Scan(&opCount)
	_ = store.db.QueryRow("SELECT count(*) FROM task_leases;").Scan(&taskCount)
	if appCount != 0 || opCount != 0 || taskCount != 0 {
		t.Fatalf("expected 0 partial rows after rollback, got apps=%d ops=%d tasks=%d", appCount, opCount, taskCount)
	}
}

func TestImagePlan_GetImageOperation(t *testing.T) {
	ctx := context.Background()
	dir := secureTestDir(t, "image_operation_detail")
	store, err := Open(Config{DataDirectory: dir})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	adminID := domain.ID("adm_op_reader")
	otherAdminID := domain.ID("adm_op_other")
	insertTestAdmin(t, store, adminID)
	insertDisabledAdmin(t, store, otherAdminID)

	plan := sampleImagePlan(adminID, appcontracts.ImagePlanStatusPlanned)
	if err := store.CreateImagePlan(ctx, plan); err != nil {
		t.Fatalf("CreateImagePlan: %v", err)
	}

	result, err := store.ConfirmImagePlan(ctx, adminID, appcontracts.ConfirmImagePlanInput{
		PlanID:         plan.ID,
		PlanDigest:     plan.PlanDigest,
		IdempotencyKey: "op-detail-key",
	})
	if err != nil {
		t.Fatalf("ConfirmImagePlan: %v", err)
	}

	// 1. Owner can read operation detail
	detail, err := store.GetImageOperation(ctx, adminID, result.OperationID)
	if err != nil {
		t.Fatalf("GetImageOperation failed: %v", err)
	}
	if detail.OperationID != result.OperationID {
		t.Fatalf("expected opID %s, got %s", result.OperationID, detail.OperationID)
	}
	if detail.ApplicationID != result.ApplicationID {
		t.Fatalf("expected appID %s, got %s", result.ApplicationID, detail.ApplicationID)
	}
	if detail.PlanID != plan.ID {
		t.Fatalf("expected planID %s, got %s", plan.ID, detail.PlanID)
	}
	if detail.PlanDigest != plan.PlanDigest {
		t.Fatalf("expected planDigest %s, got %s", plan.PlanDigest, detail.PlanDigest)
	}
	if detail.State != "pending" {
		t.Fatalf("expected pending state, got %s", detail.State)
	}
	if detail.TaskID.Empty() {
		t.Fatalf("expected non-empty task ID")
	}

	// Persisted unknown/failure diagnostics are bounded and redacted again on read.
	for _, tc := range []struct {
		state, taskState, reason string
		attempt, maxAttempts     int
		wantReason, wantAction   bool
	}{
		{"waiting", "ready", "registry token=private-secret\nretry", 1, 3, true, false},
		{"waiting", "ready", "needs_action: budget exhausted", 3, 3, true, true},
		{"failed", "failed", "registry token=private-secret", 3, 3, true, true},
		{"succeeded", "completed", "old retry error", 3, 3, false, false},
		{"failed", "failed", "", 3, 3, false, true},
	} {
		if _, err := store.db.ExecContext(ctx, `UPDATE operations SET state = ? WHERE id = ?`, tc.state, result.OperationID.String()); err != nil {
			t.Fatalf("set operation state: %v", err)
		}
		if _, err := store.db.ExecContext(ctx, `UPDATE task_leases SET state = ?, last_error = ?, attempt = ?, max_attempts = ? WHERE task_id = ?`, tc.taskState, tc.reason, tc.attempt, tc.maxAttempts, detail.TaskID.String()); err != nil {
			t.Fatalf("set persisted task diagnostic: %v", err)
		}
		got, err := store.GetImageOperation(ctx, adminID, result.OperationID)
		if err != nil {
			t.Fatalf("read %s diagnostic: %v", tc.state, err)
		}
		if (got.Reason != "") != tc.wantReason || got.ActionRequired != tc.wantAction {
			t.Fatalf("%s diagnostic: reason=%q action_required=%v", tc.state, got.Reason, got.ActionRequired)
		}
		if strings.Contains(got.Reason, "private-secret") || strings.ContainsAny(got.Reason, "\n\r") || len(got.Reason) > 1024 {
			t.Fatalf("unsafe diagnostic returned: %q", got.Reason)
		}
	}

	// 2. Other admin reading operation is forbidden
	_, err = store.GetImageOperation(ctx, otherAdminID, result.OperationID)
	if err == nil {
		t.Fatalf("expected forbidden error for other admin, got nil")
	}
	var domErr *domain.DomainError
	if !errors.As(err, &domErr) || domErr.Code != domain.ErrForbidden {
		t.Fatalf("expected ErrForbidden, got: %v", err)
	}

	// 3. Non-existent operation returns ErrNotFound
	_, err = store.GetImageOperation(ctx, adminID, domain.ID("op_nonexistent"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing operation, got: %v", err)
	}
}

func TestManagedImageApplicationsOwnedBoundedAndRecoverable(t *testing.T) {
	ctx := context.Background()
	store, err := Open(Config{DataDirectory: secureTestDir(t, "saved-images")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	admin := domain.ID("adm_saved_images")
	insertTestAdmin(t, store, admin)
	other := domain.ID("adm_saved_other")
	insertDisabledAdmin(t, store, other)
	create := func(owner domain.ID, key string) appcontracts.ConfirmImagePlanResult {
		t.Helper()
		plan := sampleImagePlan(owner, appcontracts.ImagePlanStatusPlanned)
		plan.ID = domain.MustNewID("ipl")
		plan.AppName = key
		plan.CanonicalInput.AppName = key
		var err error
		plan.PlanDigest, err = appcontracts.ComputePlanDigest(plan.CanonicalInput, plan.ResolvedImage.Digest)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.CreateImagePlan(ctx, plan); err != nil {
			t.Fatal(err)
		}
		result, err := store.ConfirmImagePlan(ctx, owner, appcontracts.ConfirmImagePlanInput{PlanID: plan.ID, PlanDigest: plan.PlanDigest, IdempotencyKey: key})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	first := create(admin, "saved-one")
	second := create(admin, "saved-two")
	_ = create(other, "foreign-image")
	if _, err := store.db.ExecContext(ctx, `UPDATE operations SET state='failed' WHERE id=?`, first.OperationID.String()); err != nil {
		t.Fatal(err)
	}

	task, ok, err := store.ClaimTask(ctx, appcontracts.ClaimTaskRequest{Kinds: []string{"image.deploy"}, AllowedOperationStates: []string{"pending"}, Owner: "saved-list-fixture", Now: time.Now().UTC(), LeasePolicy: appcontracts.LeasePolicy{Duration: time.Minute, MaxAttempts: 3}})
	if err != nil || !ok || task.OperationID != second.OperationID {
		t.Fatal("expected owned pending deployment task")
	}
	deploy, err := store.BeginImageExecution(ctx, appcontracts.BeginImageExecutionInput{TaskID: task.ID, OperationID: task.OperationID, Owner: task.LeaseOwner, CoreGeneration: task.CoreGeneration, LeaseGeneration: task.LeaseGeneration})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitImageExecutionResult(ctx, appcontracts.CommitImageExecutionResultInput{TaskID: task.ID, OperationID: task.OperationID, DeploymentID: deploy.DeploymentID, ReleaseID: deploy.ReleaseID, Owner: task.LeaseOwner, CoreGeneration: task.CoreGeneration, LeaseGeneration: task.LeaseGeneration, ContainerID: "saved-owned-container", ImageID: deploy.Plan.ResolvedImage.Digest, ManifestDigest: deploy.Plan.ResolvedImage.Digest, Artifact: appcontracts.StorageArtifactReceipt{StorageRef: "fixture/oci", ContentDigest: deploy.Plan.ResolvedImage.Digest, SizeBytes: 123}, HostPort: 39081, ContainerPort: deploy.Plan.CanonicalInput.Port, ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	command, err := store.CreateImageLifecycle(ctx, admin, appcontracts.CreateImageLifecycleInput{DeploymentID: deploy.DeploymentID, Action: appcontracts.ImageLifecycleStop, IdempotencyKey: "saved-command"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE operations SET state='waiting' WHERE id=?`, command.OperationID.String()); err != nil {
		t.Fatal(err)
	}
	list, err := store.ListManagedImageApplications(ctx, admin, 1)
	if err != nil || len(list.Items) != 1 || !list.Truncated {
		t.Fatalf("bounded list: %+v %v", list, err)
	}
	list, err = store.ListManagedImageApplications(ctx, admin, 50)
	if err != nil || len(list.Items) != 2 || list.Truncated {
		t.Fatalf("owned list: %+v %v", list, err)
	}
	seen := map[domain.ID]bool{}
	for _, item := range list.Items {
		seen[item.DeployOperationID] = true
		if item.PlanDigest == "" || item.PlanID.Empty() {
			t.Fatal("missing durable resume identity")
		}
	}
	if !seen[first.OperationID] || !seen[second.OperationID] {
		t.Fatal("saved failed or pending application lost")
	}
	for _, item := range list.Items {
		if item.DeployOperationID == second.OperationID && (item.ActiveCommand == nil || item.LastCommand == nil || item.ActiveCommand.OperationID != command.OperationID || item.ActiveCommand.State != "unknown" || item.LastCommand.OperationID != command.OperationID) {
			t.Fatal("durable unknown command was not discoverable")
		}
	}

	raw, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"canonical_input", "environment", "lease_owner", "storage_ref", "admin_id"} {
		if strings.Contains(string(raw), `"`+field+`"`) {
			t.Fatal("private plan/authority leaked in summary")
		}
	}
	if _, err := store.ListManagedImageApplications(ctx, admin, 101); err == nil {
		t.Fatal("unbounded limit accepted")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE admin_credentials SET disabled_at=? WHERE id=?`, FormatTime(time.Now().UTC()), admin.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListManagedImageApplications(ctx, admin, 50); err == nil {
		t.Fatal("disabled administrator listed applications")
	}
}
