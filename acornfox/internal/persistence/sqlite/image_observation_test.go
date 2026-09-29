package sqlite

import (
	"context"
	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"testing"
	"time"
)

func TestManagedImageObservationOwnershipReadOnly(t *testing.T) {
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

	before, err := s.ListManagedImageApplications(ctx, admin, 100)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.ReadManagedImageObservationBinding(ctx, admin, deploy.DeploymentID)
	if err != nil || b.AdminID != admin || b.Runtime.ContainerID != "fixture-container" || b.Runtime.DeployOperationID != confirm.OperationID {
		t.Fatalf("owned observation: %v", err)
	}
	foreign := domain.ID("foreign-admin")
	if _, err = s.db.ExecContext(ctx, "UPDATE admin_credentials SET disabled_at=? WHERE id=?", FormatTime(time.Now().UTC()), admin.String()); err != nil {
		t.Fatal(err)
	}
	insertTestAdmin(t, s, foreign)
	if _, err = s.ReadManagedImageObservationBinding(ctx, foreign, deploy.DeploymentID); err == nil {
		t.Fatal("foreign administrator accepted")
	}
	if _, err = s.db.ExecContext(ctx, "UPDATE admin_credentials SET disabled_at=? WHERE id=?", FormatTime(time.Now().UTC()), foreign.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, "UPDATE admin_credentials SET disabled_at=NULL WHERE id=?", admin.String()); err != nil {
		t.Fatal(err)
	}
	after, err := s.ListManagedImageApplications(ctx, admin, 100)
	if err != nil || len(before.Items) != len(after.Items) {
		t.Fatal("observation changed applications")
	}
	var count int
	if err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM image_lifecycle_commands").Scan(&count); err != nil || count != 0 {
		t.Fatal("read created lifecycle command")
	}
}
