package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

// Synthetic SQLite facts exercise the transaction boundary only. They do not
// claim a Caddy, DNS, TLS or Docker observation.
func TestImagePublicAccessApprovalAndEndpointFence(t *testing.T) {
	s, admin, confirm := setupExecutionStore(t)
	ctx := context.Background()
	request := appcontracts.ImagePublicAccessRequest{DeploymentID: domain.ID("dep_missing"), Hostname: "app.example.test", Action: appcontracts.ImagePublicAccessEnsure, IdempotencyKey: "domain-one"}
	if _, err := s.BeginImagePublicAccess(ctx, admin, request); !errors.Is(err, ErrNotFound) {
		t.Fatalf("registered schema admitted a nonexistent deployment: %v", err)
	}
	claim := func(kind string) appcontracts.Task {
		t.Helper()
		task, ok, err := s.ClaimTask(ctx, appcontracts.ClaimTaskRequest{Kinds: []string{kind}, Owner: "domain-fixture", Now: time.Now().UTC(), LeasePolicy: appcontracts.LeasePolicy{Duration: time.Minute, MaxAttempts: 3}})
		if err != nil || !ok {
			t.Fatalf("claim %s: %v %v", kind, ok, err)
		}
		return task
	}
	deployTask := claim("image.deploy")
	deploy, err := s.BeginImageExecution(ctx, appcontracts.BeginImageExecutionInput{TaskID: deployTask.ID, OperationID: confirm.OperationID, Owner: "domain-fixture", CoreGeneration: deployTask.CoreGeneration, LeaseGeneration: deployTask.LeaseGeneration})
	if err != nil {
		t.Fatal(err)
	}
	image := "sha256:72611294759dc6b304d1f3efa2d4b1de212ce422866244f31bc29f731e3b2079"
	if err := s.CommitImageExecutionResult(ctx, appcontracts.CommitImageExecutionResultInput{TaskID: deployTask.ID, OperationID: confirm.OperationID, DeploymentID: deploy.DeploymentID, ReleaseID: deploy.ReleaseID, Owner: "domain-fixture", CoreGeneration: deployTask.CoreGeneration, LeaseGeneration: deployTask.LeaseGeneration, ContainerID: "domain-fixture-container", ImageID: image, ManifestDigest: image, Artifact: appcontracts.StorageArtifactReceipt{StorageRef: "fixture/image", ContentDigest: image, SizeBytes: 123}, HostPort: 39898, ContainerPort: 9898, ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	request.DeploymentID = deploy.DeploymentID
	other := domain.ID("adm_other_domain")
	insertDisabledAdmin(t, s, other)
	if _, err := s.BeginImagePublicAccess(ctx, other, request); err == nil {
		t.Fatal("foreign/disabled administrator wrote domain")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE image_deployments SET status='stopped' WHERE id=?`, deploy.DeploymentID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginImagePublicAccess(ctx, admin, request); err == nil {
		t.Fatal("stopped deployment received new public approval")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE image_deployments SET status='running' WHERE id=?`, deploy.DeploymentID.String()); err != nil {
		t.Fatal(err)
	}
	inflight, err := s.CreateImageLifecycle(ctx, admin, appcontracts.CreateImageLifecycleInput{DeploymentID: deploy.DeploymentID, Action: appcontracts.ImageLifecycleStop, IdempotencyKey: "before-domain"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginImagePublicAccess(ctx, admin, request); err == nil {
		t.Fatal("inflight lifecycle admitted domain write")
	}
	var domainRows int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM image_public_access`).Scan(&domainRows); err != nil || domainRows != 0 {
		t.Fatalf("rejected owner/state/inflight attempt wrote domain: rows=%d err=%v", domainRows, err)
	}
	inflightTask := claim(appcontracts.ImageLifecycleTaskKind)
	inflightAuth := appcontracts.ImageLifecycleAuthorityInput{BeginImageExecutionInput: appcontracts.BeginImageExecutionInput{TaskID: inflightTask.ID, OperationID: inflight.OperationID, Owner: "domain-fixture", CoreGeneration: inflightTask.CoreGeneration, LeaseGeneration: inflightTask.LeaseGeneration}, DeploymentID: inflight.DeploymentID, ReleaseID: inflight.ReleaseID, PlanDigest: inflight.PlanDigest, ContainerID: inflight.ContainerID, Action: inflight.Action}
	if err := s.FailImageLifecycle(ctx, appcontracts.ImageLifecycleOutcomeInput{ImageLifecycleAuthorityInput: inflightAuth, Reason: "fixture pre-effect failure"}); err != nil {
		t.Fatal(err)
	}
	b, err := s.BeginImagePublicAccess(ctx, admin, request)
	if err != nil {
		t.Fatal(err)
	}
	if b.OperationID == confirm.OperationID || b.TaskID == deployTask.ID || b.EndpointVersion == "" || b.ContainerID != "domain-fixture-container" {
		t.Fatalf("domain command lost distinct approved identity: %+v", b)
	}
	replayed, err := s.BeginImagePublicAccess(ctx, admin, request)
	if err != nil || replayed.OperationID != b.OperationID || replayed.TaskID != b.TaskID {
		t.Fatalf("same-key original response: %v %+v", err, replayed)
	}
	changed := request
	changed.Hostname = "other.example.test"
	if _, err := s.BeginImagePublicAccess(ctx, admin, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same key changed hostname: %v", err)
	}
	if _, err := s.CreateImageLifecycle(ctx, admin, appcontracts.CreateImageLifecycleInput{DeploymentID: deploy.DeploymentID, Action: appcontracts.ImageLifecycleStop, IdempotencyKey: "overlap-stop"}); err == nil {
		t.Fatal("domain operation did not exclude concurrent lifecycle command")
	}
	task := claim(appcontracts.ImagePublicAccessTaskKind)
	auth := appcontracts.ImagePublicAccessAuthority{BeginImageExecutionInput: appcontracts.BeginImageExecutionInput{TaskID: task.ID, OperationID: b.OperationID, Owner: "domain-fixture", CoreGeneration: task.CoreGeneration, LeaseGeneration: task.LeaseGeneration}, ApprovalID: b.ApprovalID, DeploymentID: b.DeploymentID, EndpointVersion: b.EndpointVersion, ContainerID: b.ContainerID, Action: b.Action}
	wrong := auth
	wrong.LeaseGeneration--
	if _, err := s.AuthorizeImagePublicAccess(ctx, wrong); err == nil {
		t.Fatal("old lease authorized route")
	}
	if _, err := s.AuthorizeImagePublicAccess(ctx, auth); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitImagePublicAccess(ctx, auth, appcontracts.ImagePublicAccessObservation{ObservedAt: time.Now().UTC()}); err == nil {
		t.Fatal("committed route without projector success")
	}
	if err := s.CommitImagePublicAccess(ctx, auth, appcontracts.ImagePublicAccessObservation{RouteApplied: true, ObservedAt: time.Now().UTC(), CertificateFingerprint: image, CertificateExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	approved, err := s.GetImagePublicAccess(ctx, admin, b.DeploymentID)
	if err != nil || !approved.DesiredPublic || approved.LocalRouteState != "configured" || approved.CertificateFingerprint != image {
		t.Fatalf("durable approved route: %v %+v", err, approved)
	}
	var resultRows int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM image_public_access_results WHERE operation_id=?`, b.OperationID.String()).Scan(&resultRows); err != nil || resultRows != 1 {
		t.Fatalf("command result was not persisted separately: rows=%d err=%v", resultRows, err)
	}
	routes, err := s.ListImagePublicAccessRoutes(ctx)
	if err != nil || len(routes) != 1 || !routes[0].Enabled || routes[0].Hostname != request.Hostname || routes[0].HostPort != 39898 {
		t.Fatalf("bad route inventory: %v %+v", err, routes)
	}
	if err := s.CheckImagePublicAccessRoute(ctx, routes[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE image_endpoints SET host_port=39899 WHERE deployment_id=?`, b.DeploymentID.String()); err == nil {
		t.Fatal("active route allowed endpoint reuse")
	}
	// Stop preserves the allocation and custom hostname; it is not an unbind.
	stop, err := s.CreateImageLifecycle(ctx, admin, appcontracts.CreateImageLifecycleInput{DeploymentID: b.DeploymentID, Action: appcontracts.ImageLifecycleStop, IdempotencyKey: "domain-stop"})
	if err != nil {
		t.Fatal(err)
	}
	stopTask := claim(appcontracts.ImageLifecycleTaskKind)
	stopAuth := appcontracts.ImageLifecycleAuthorityInput{BeginImageExecutionInput: appcontracts.BeginImageExecutionInput{TaskID: stopTask.ID, OperationID: stop.OperationID, Owner: "domain-fixture", CoreGeneration: stopTask.CoreGeneration, LeaseGeneration: stopTask.LeaseGeneration}, DeploymentID: stop.DeploymentID, ReleaseID: stop.ReleaseID, PlanDigest: stop.PlanDigest, ContainerID: stop.ContainerID, Action: stop.Action}
	if _, err := s.BeginImageLifecycle(ctx, stopAuth.BeginImageExecutionInput); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitImageLifecycleResult(ctx, appcontracts.CommitImageLifecycleInput{ImageLifecycleAuthorityInput: stopAuth, Result: appcontracts.ImageLifecycleResult{VerifiedIdentity: true, ContainerID: stop.ContainerID, ImageID: stop.ImageID, ManifestDigest: stop.ManifestDigest, ObservedAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	approved, err = s.GetImagePublicAccess(ctx, admin, b.DeploymentID)
	if err != nil || approved.LocalRouteState != "configured" || !approved.DesiredPublic {
		t.Fatalf("Stop erased domain config: %v %+v", err, approved)
	}
	remove := appcontracts.ImagePublicAccessRequest{DeploymentID: b.DeploymentID, Hostname: b.Hostname, Action: appcontracts.ImagePublicAccessRemove, IdempotencyKey: "domain-remove"}
	removed, err := s.BeginImagePublicAccess(ctx, admin, remove)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckImagePublicAccessRoute(ctx, routes[0]); err == nil {
		t.Fatal("stale route snapshot passed exact pre-write fence")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE image_endpoints SET host_port=39899 WHERE deployment_id=?`, b.DeploymentID.String()); err == nil {
		t.Fatal("pending removal released endpoint before route withdrawal")
	}
	removeTask := claim(appcontracts.ImagePublicAccessTaskKind)
	removeAuth := appcontracts.ImagePublicAccessAuthority{BeginImageExecutionInput: appcontracts.BeginImageExecutionInput{TaskID: removeTask.ID, OperationID: removed.OperationID, Owner: "domain-fixture", CoreGeneration: removeTask.CoreGeneration, LeaseGeneration: removeTask.LeaseGeneration}, ApprovalID: removed.ApprovalID, DeploymentID: removed.DeploymentID, EndpointVersion: removed.EndpointVersion, ContainerID: removed.ContainerID, Action: removed.Action}
	if _, err := s.AuthorizeImagePublicAccess(ctx, removeAuth); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitImagePublicAccess(ctx, removeAuth, appcontracts.ImagePublicAccessObservation{RouteApplied: true, ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE image_endpoints SET host_port=39899 WHERE deployment_id=?`, b.DeploymentID.String()); err != nil {
		t.Fatalf("withdrawn route retained endpoint fence: %v", err)
	}
}
