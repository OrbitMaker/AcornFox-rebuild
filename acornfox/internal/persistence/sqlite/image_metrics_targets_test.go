package sqlite

import (
	"context"
	"testing"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
)

func TestManagedImageMetricTargetsEnabledOwnerAndRealDeployment(t *testing.T) {
	s, admin, confirm := setupExecutionStore(t)
	ctx := context.Background()
	if got, err := s.ListActiveManagedImageMetricTargets(ctx, 32); err != nil || len(got.Targets) != 0 {
		t.Fatalf("pending deploy was sampled: %+v %v", got, err)
	}
	task, ok, err := s.ClaimTask(ctx, appcontracts.ClaimTaskRequest{Kinds: []string{"image.deploy"}, Owner: "metrics-fixture", Now: time.Now().UTC(), LeasePolicy: appcontracts.LeasePolicy{Duration: time.Minute, MaxAttempts: 3}})
	if err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	begin := appcontracts.BeginImageExecutionInput{TaskID: task.ID, OperationID: confirm.OperationID, Owner: "metrics-fixture", CoreGeneration: task.CoreGeneration, LeaseGeneration: task.LeaseGeneration}
	deploy, err := s.BeginImageExecution(ctx, begin)
	if err != nil {
		t.Fatal(err)
	}
	image := "sha256:72611294759dc6b304d1f3efa2d4b1de212ce422866244f31bc29f731e3b2079"
	if err := s.CommitImageExecutionResult(ctx, appcontracts.CommitImageExecutionResultInput{TaskID: task.ID, OperationID: confirm.OperationID, DeploymentID: deploy.DeploymentID, ReleaseID: deploy.ReleaseID, Owner: begin.Owner, CoreGeneration: begin.CoreGeneration, LeaseGeneration: begin.LeaseGeneration, ContainerID: "fixture-container", ImageID: image, ManifestDigest: image, Artifact: appcontracts.StorageArtifactReceipt{StorageRef: "fixture/image", ContentDigest: image, SizeBytes: 123}, HostPort: 39898, ContainerPort: 9898, ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListActiveManagedImageMetricTargets(ctx, 32)
	if err != nil || got.Limited || len(got.Targets) != 1 || got.Targets[0].AdminID != admin || got.Targets[0].DeploymentID != deploy.DeploymentID {
		t.Fatalf("verified deployment selection: %+v %v", got, err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE image_deployments SET status='stopped' WHERE id=?`, deploy.DeploymentID.String()); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ListActiveManagedImageMetricTargets(ctx, 32); err != nil || len(got.Targets) != 1 {
		t.Fatalf("stopped retained allocation was dropped: %+v %v", got, err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE admin_credentials SET disabled_at=? WHERE id=?`, FormatTime(time.Now().UTC()), admin.String()); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ListActiveManagedImageMetricTargets(ctx, 32); err != nil || len(got.Targets) != 0 {
		t.Fatalf("disabled owner was sampled: %+v %v", got, err)
	}
}
