package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/domain"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This fixture records a synthetic observed deploy through the production store;
// it is neither a live Docker observation nor product acceptance.
func TestImageLifecycleCommandIdentityAndRecovery(t *testing.T) {
	s, admin, confirm := setupExecutionStore(t)
	ctx := context.Background()
	claim := func(kind string) appcontracts.Task {
		t.Helper()
		task, ok, err := s.ClaimTask(ctx, appcontracts.ClaimTaskRequest{Kinds: []string{kind}, Owner: "lifecycle-test", Now: time.Now().UTC(), LeasePolicy: appcontracts.LeasePolicy{Duration: time.Minute, MaxAttempts: 3}})
		if err != nil || !ok {
			t.Fatalf("claim %s: %v %v", kind, ok, err)
		}
		return task
	}
	deployTask := claim("image.deploy")
	begin := appcontracts.BeginImageExecutionInput{TaskID: deployTask.ID, OperationID: confirm.OperationID, Owner: "lifecycle-test", CoreGeneration: deployTask.CoreGeneration, LeaseGeneration: deployTask.LeaseGeneration}
	deploy, err := s.BeginImageExecution(ctx, begin)
	if err != nil {
		t.Fatal(err)
	}
	image := "sha256:72611294759dc6b304d1f3efa2d4b1de212ce422866244f31bc29f731e3b2079"
	if err := s.CommitImageExecutionResult(ctx, appcontracts.CommitImageExecutionResultInput{TaskID: deployTask.ID, OperationID: confirm.OperationID, DeploymentID: deploy.DeploymentID, ReleaseID: deploy.ReleaseID, Owner: begin.Owner, CoreGeneration: begin.CoreGeneration, LeaseGeneration: begin.LeaseGeneration, ContainerID: "fixture-container", ImageID: image, ManifestDigest: image, Artifact: appcontracts.StorageArtifactReceipt{StorageRef: "fixture/image", ContentDigest: image, SizeBytes: 123}, HostPort: 39898, ContainerPort: 9898, ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	in := appcontracts.CreateImageLifecycleInput{DeploymentID: deploy.DeploymentID, Action: appcontracts.ImageLifecycleStop, IdempotencyKey: "stop-fixture"}
	cmd, err := s.CreateImageLifecycle(ctx, admin, in)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.OperationID == confirm.OperationID || cmd.TaskID == deployTask.ID || cmd.DeployOperationID != confirm.OperationID || cmd.Result != nil {
		t.Fatalf("command borrowed deploy identity/result: %+v", cmd)
	}
	if cmd.Plan.ID != deploy.Plan.ID || cmd.Plan.PlanDigest != deploy.Plan.PlanDigest || cmd.Plan.AdminID != admin || cmd.Plan.CanonicalInput.Resources != deploy.Plan.CanonicalInput.Resources || cmd.Plan.ResolvedImage.Digest != deploy.Plan.ResolvedImage.Digest {
		t.Fatal("command did not preserve original verified plan")
	}
	replay, err := s.CreateImageLifecycle(ctx, admin, in)
	if err != nil || replay.OperationID != cmd.OperationID {
		t.Fatalf("replay %v %+v", err, replay)
	}
	stamp := FormatTime(time.Now().UTC())
	if _, err := s.db.ExecContext(ctx, `UPDATE admin_credentials SET disabled_at=? WHERE id=?`, stamp, admin.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateImageLifecycle(ctx, admin, in); err == nil {
		t.Fatal("disabled owner replayed command")
	}
	if _, err := s.ReadImageLifecycle(ctx, admin, cmd.OperationID); err == nil {
		t.Fatal("disabled owner read command")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE admin_credentials SET disabled_at=NULL WHERE id=?`, admin.String()); err != nil {
		t.Fatal(err)
	}
	changed := in
	changed.Action = appcontracts.ImageLifecycleRestart
	if _, err := s.CreateImageLifecycle(ctx, admin, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different command same key: %v", err)
	}
	other := domain.ID("adm_other_lifecycle")
	insertDisabledAdmin(t, s, other)
	if _, err := s.CreateImageLifecycle(ctx, other, in); err == nil {
		t.Fatal("another administrator replayed command")
	}
	if _, err := s.ReadImageLifecycle(ctx, other, cmd.OperationID); err == nil {
		t.Fatal("read disclosed command to another owner")
	}
	changed.IdempotencyKey = "overlap"
	if _, err := s.CreateImageLifecycle(ctx, admin, changed); err == nil {
		t.Fatal("allowed overlapping deployment command")
	}
	task := claim(appcontracts.ImageLifecycleTaskKind)
	authority := appcontracts.ImageLifecycleAuthorityInput{BeginImageExecutionInput: appcontracts.BeginImageExecutionInput{TaskID: task.ID, OperationID: cmd.OperationID, Owner: begin.Owner, CoreGeneration: task.CoreGeneration, LeaseGeneration: task.LeaseGeneration}, DeploymentID: cmd.DeploymentID, ReleaseID: cmd.ReleaseID, PlanDigest: cmd.PlanDigest, ContainerID: cmd.ContainerID, Action: cmd.Action}
	begun, err := s.BeginImageLifecycle(ctx, authority.BeginImageExecutionInput)
	if err != nil {
		t.Fatal(err)
	}
	if begun.Plan.ID != cmd.Plan.ID || begun.Plan.PlanDigest != cmd.PlanDigest || begun.Plan.CanonicalInput.Port != 9898 {
		t.Fatal("begin lost original verified plan")
	}
	authorized, err := s.AuthorizeImageLifecycle(ctx, authority)
	if err != nil {
		t.Fatal(err)
	}
	if authorized.Plan.ID != cmd.Plan.ID || authorized.Plan.PlanDigest != cmd.PlanDigest || authorized.Plan.AdminID != admin {
		t.Fatal("authorization lost original verified plan")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE operations SET operation_type='image.start' WHERE id=?`, cmd.OperationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthorizeImageLifecycle(ctx, authority); err == nil {
		t.Fatal("authorized operation/action drift")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE operations SET operation_type='image.stop' WHERE id=?`, cmd.OperationID.String()); err != nil {
		t.Fatal(err)
	}
	wrong := authority
	wrong.OperationID = confirm.OperationID
	if _, err := s.AuthorizeImageLifecycle(ctx, wrong); err == nil {
		t.Fatal("authorized lifecycle task against deploy operation")
	}
	wrong = authority
	wrong.DeploymentID = domain.ID("dep_other")
	if _, err := s.AuthorizeImageLifecycle(ctx, wrong); err == nil {
		t.Fatal("authorized wrong deployment")
	}
	if err := s.RecordImageLifecycleUnknown(ctx, appcontracts.ImageLifecycleOutcomeInput{ImageLifecycleAuthorityInput: authority, Reason: "fixture token=private-secret\n disconnected"}); err != nil {
		t.Fatal(err)
	}
	stored, err := s.ReadImageLifecycle(ctx, admin, cmd.OperationID)
	if err != nil || stored.State != "waiting" || stored.Result != nil {
		t.Fatalf("unknown result %v %+v", err, stored)
	}
	if stored.Reason == "" || strings.Contains(stored.Reason, "private-secret") || strings.ContainsAny(stored.Reason, "\n\r") || len(stored.Reason) > 1024 {
		t.Fatalf("unsafe or absent unknown reason: %q", stored.Reason)
	}
	privateBindingJSON, err := json.Marshal(stored)
	if err != nil || strings.Contains(string(privateBindingJSON), `"reason"`) {
		t.Fatal("read-only reason entered immutable authority JSON")
	}
	dir, dbName := s.dir, filepath.Base(s.dbPath)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(Config{DataDirectory: dir, DBName: dbName})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.AuthorizeImageLifecycle(ctx, authority); !errors.Is(err, appcontracts.ErrLeaseLost) {
		t.Fatalf("old core generation authorized: %v", err)
	}
	reclaimed := claim(appcontracts.ImageLifecycleTaskKind)
	if reclaimed.LeaseGeneration <= task.LeaseGeneration {
		t.Fatal("reclaim did not fence old generation")
	}
	if _, err := s.AuthorizeImageLifecycle(ctx, authority); !errors.Is(err, appcontracts.ErrLeaseLost) {
		t.Fatalf("old lease authorized: %v", err)
	}
	authority.CoreGeneration = reclaimed.CoreGeneration
	authority.LeaseGeneration = reclaimed.LeaseGeneration
	recovering, err := s.BeginImageLifecycle(ctx, authority.BeginImageExecutionInput)
	if err != nil || !recovering.RecoveryRequired {
		t.Fatalf("unknown recovery flag: %v %+v", err, recovering)
	}
	again, err := s.BeginImageLifecycle(ctx, authority.BeginImageExecutionInput)
	if err != nil || !again.RecoveryRequired {
		t.Fatalf("repeat begin erased recovery: %v %+v", err, again)
	}
	result := appcontracts.ImageLifecycleResult{VerifiedIdentity: true, ContainerID: cmd.ContainerID, ImageID: cmd.ImageID, ManifestDigest: cmd.ManifestDigest, ObservedAt: time.Now().UTC()}
	if err := s.CommitImageLifecycleResult(ctx, appcontracts.CommitImageLifecycleInput{ImageLifecycleAuthorityInput: authority, Result: result}); err != nil {
		t.Fatal(err)
	}
	stored, err = s.ReadImageLifecycle(ctx, admin, cmd.OperationID)
	if err != nil || stored.State != "succeeded" || stored.Result == nil || stored.Result.Running || stored.Result.EndpointReady {
		t.Fatalf("stop result: %v %+v", err, stored)
	}
	if stored.Reason != "" {
		t.Fatalf("successful lifecycle leaked stale error: %q", stored.Reason)
	}
	terminalReplay, err := s.CreateImageLifecycle(ctx, admin, in)
	if err != nil || terminalReplay.OperationID != cmd.OperationID || terminalReplay.State != "pending" || terminalReplay.Result != nil {
		t.Fatalf("terminal replay did not preserve original response: %v %+v", err, terminalReplay)
	}
	var originOp, originTask, status string
	if err := s.db.QueryRowContext(ctx, `SELECT operation_id,task_id,status FROM image_deployments WHERE id=?`, cmd.DeploymentID.String()).Scan(&originOp, &originTask, &status); err != nil {
		t.Fatal(err)
	}
	if originOp != confirm.OperationID.String() || originTask != deployTask.ID.String() || status != "stopped" {
		t.Fatal("lifecycle rewrote original deployment provenance")
	}
	for _, state := range []string{"failed", "waiting", "pending", "running", "succeeded"} {
		if _, err := s.db.ExecContext(ctx, `UPDATE operations SET state=?,failure_reason=? WHERE id=?`, state, "old token=private-secret\n"+strings.Repeat("x", 1100), cmd.OperationID.String()); err != nil {
			t.Fatal(err)
		}
		read, err := s.ReadImageLifecycle(ctx, admin, cmd.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		wantReason := state == "failed" || state == "waiting"
		if (read.Reason != "") != wantReason || strings.Contains(read.Reason, "private-secret") || strings.ContainsAny(read.Reason, "\n\r") || len(read.Reason) > 1024 {
			t.Fatalf("%s read diagnostic invalid: %q", state, read.Reason)
		}
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE operations SET state='failed',failure_reason='' WHERE id=?`, cmd.OperationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE task_leases SET last_error='persisted task fallback' WHERE task_id=?`, cmd.TaskID.String()); err != nil {
		t.Fatal(err)
	}
	read, err := s.ReadImageLifecycle(ctx, admin, cmd.OperationID)
	if err != nil || read.Reason != "persisted task fallback" {
		t.Fatalf("task reason fallback lost: %q %v", read.Reason, err)
	}
}
