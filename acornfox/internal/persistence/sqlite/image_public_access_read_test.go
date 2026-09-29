package sqlite

import (
	"context"
	"strings"
	"testing"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

func TestImagePublicAccessHistoricalOwnerReadAndStoppedCurrent(t *testing.T) {
	s, admin, confirm := setupExecutionStore(t)
	ctx := context.Background()
	if err := s.checkImagePublicAccess(ctx); err != nil {
		t.Fatalf("registered 0013 required for current/public operation read: %v", err)
	}
	claim := func(kind string) appcontracts.Task {
		t.Helper()
		task, ok, err := s.ClaimTask(ctx, appcontracts.ClaimTaskRequest{Kinds: []string{kind}, Owner: "domain-read-fixture", Now: time.Now().UTC(), LeasePolicy: appcontracts.LeasePolicy{Duration: time.Minute, MaxAttempts: 3}})
		if err != nil || !ok {
			t.Fatalf("claim %s: %v", kind, err)
		}
		return task
	}
	deployTask := claim("image.deploy")
	deploy, err := s.BeginImageExecution(ctx, appcontracts.BeginImageExecutionInput{TaskID: deployTask.ID, OperationID: confirm.OperationID, Owner: "domain-read-fixture", CoreGeneration: deployTask.CoreGeneration, LeaseGeneration: deployTask.LeaseGeneration})
	if err != nil {
		t.Fatal(err)
	}
	image := "sha256:72611294759dc6b304d1f3efa2d4b1de212ce422866244f31bc29f731e3b2079"
	if err := s.CommitImageExecutionResult(ctx, appcontracts.CommitImageExecutionResultInput{TaskID: deployTask.ID, OperationID: confirm.OperationID, DeploymentID: deploy.DeploymentID, ReleaseID: deploy.ReleaseID, Owner: "domain-read-fixture", CoreGeneration: deployTask.CoreGeneration, LeaseGeneration: deployTask.LeaseGeneration, ContainerID: "domain-read-container", ImageID: image, ManifestDigest: image, Artifact: appcontracts.StorageArtifactReceipt{StorageRef: "fixture/image", ContentDigest: image, SizeBytes: 123}, HostPort: 39898, ContainerPort: 9898, ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	bind, err := s.BeginImagePublicAccess(ctx, admin, appcontracts.ImagePublicAccessRequest{DeploymentID: deploy.DeploymentID, Hostname: "app.customer.example", Action: appcontracts.ImagePublicAccessEnsure, IdempotencyKey: "read-bind"})
	if err != nil {
		t.Fatal(err)
	}
	bindTask := claim(appcontracts.ImagePublicAccessTaskKind)
	authority := func(command appcontracts.ImagePublicAccessCommand, task appcontracts.Task) appcontracts.ImagePublicAccessAuthority {
		return appcontracts.ImagePublicAccessAuthority{BeginImageExecutionInput: appcontracts.BeginImageExecutionInput{TaskID: task.ID, OperationID: command.OperationID, Owner: "domain-read-fixture", CoreGeneration: task.CoreGeneration, LeaseGeneration: task.LeaseGeneration}, ApprovalID: command.ApprovalID, DeploymentID: command.DeploymentID, EndpointVersion: command.EndpointVersion, ContainerID: command.ContainerID, Action: command.Action}
	}
	bindAuthority := authority(bind, bindTask)
	if _, err := s.AuthorizeImagePublicAccess(ctx, bindAuthority); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitImagePublicAccess(ctx, bindAuthority, appcontracts.ImagePublicAccessObservation{RouteApplied: true, ObservedAt: time.Now().UTC(), CertificateFingerprint: image, CertificateExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	old, err := s.ReadImagePublicAccessOperation(ctx, admin, bind.OperationID)
	if err != nil || old.State != "succeeded" || old.Result == nil || old.Result.CertificateFingerprint != image || old.DeploymentID != deploy.DeploymentID {
		t.Fatalf("historical approved result: %v %+v", err, old)
	}
	foreign := domain.ID("adm_other_domain_read")
	insertDisabledAdmin(t, s, foreign)
	if _, err := s.ReadImagePublicAccessOperation(ctx, foreign, bind.OperationID); err == nil {
		t.Fatal("foreign administrator read historical domain operation")
	}
	remove, err := s.BeginImagePublicAccess(ctx, admin, appcontracts.ImagePublicAccessRequest{DeploymentID: deploy.DeploymentID, Hostname: bind.Hostname, Action: appcontracts.ImagePublicAccessRemove, IdempotencyKey: "read-remove"})
	if err != nil {
		t.Fatal(err)
	}
	removeTask := claim(appcontracts.ImagePublicAccessTaskKind)
	removeAuthority := authority(remove, removeTask)
	if _, err := s.AuthorizeImagePublicAccess(ctx, removeAuthority); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordImagePublicAccessUnknown(ctx, removeAuthority, "token=private-secret disconnected"); err != nil {
		t.Fatal(err)
	}
	unknown, err := s.ReadImagePublicAccessOperation(ctx, admin, remove.OperationID)
	if err != nil || unknown.State != "unknown" || unknown.Result != nil || unknown.Reason == "" || strings.Contains(unknown.Reason, "private-secret") {
		t.Fatalf("unsafe unknown operation: %v %+v", err, unknown)
	}
	stillOld, err := s.ReadImagePublicAccessOperation(ctx, admin, bind.OperationID)
	if err != nil || stillOld.Result == nil || stillOld.Result.CertificateFingerprint != image {
		t.Fatalf("later command rewrote historical result: %v %+v", err, stillOld)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE image_deployments SET status='stopped' WHERE id=?`, deploy.DeploymentID.String()); err != nil {
		t.Fatal(err)
	}
	current, err := s.GetImagePublicAccess(ctx, admin, deploy.DeploymentID)
	if err != nil || current.DeploymentStatus != "stopped" || current.Command.OperationID != remove.OperationID || current.LocalRouteState != "reconcile_required" {
		t.Fatalf("retained hostname stopped/current projection: %v %+v", err, current)
	}
}
