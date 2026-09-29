package corehttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/application"
	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

// The observed result here is a synthetic Store fact; this HTTP fixture proves
// auth/idempotency/public projection, not a real Caddy or public certificate.
func TestImageDomainHTTPAuthReplayAndStoppedAvailability(t *testing.T) {
	h, store, authService, session, csrf := setupTestDeliveryHTTP(t)
	defer store.Close()
	ctx := context.Background()
	admin := domain.ID("adm_test_admin")
	plan, err := h.Service.CreatePlan(ctx, admin, appcontracts.ImagePlanInput{AppName: "http-domain", Image: "nginx:latest", Port: 80, Environment: map[string]string{"MODE": "private-domain-marker"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateImagePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	confirmed, err := store.ConfirmImagePlan(ctx, admin, appcontracts.ConfirmImagePlanInput{PlanID: plan.ID, PlanDigest: plan.PlanDigest, IdempotencyKey: "http-domain-deploy"})
	if err != nil {
		t.Fatal(err)
	}
	claim := func(kind string) appcontracts.Task {
		t.Helper()
		task, ok, err := store.ClaimTask(ctx, appcontracts.ClaimTaskRequest{Kinds: []string{kind}, Owner: "http-domain-fixture", Now: time.Now().UTC(), LeasePolicy: appcontracts.LeasePolicy{Duration: time.Minute, MaxAttempts: 3}})
		if err != nil || !ok {
			t.Fatalf("claim %s: %v", kind, err)
		}
		return task
	}
	deployTask := claim("image.deploy")
	deploy, err := store.BeginImageExecution(ctx, appcontracts.BeginImageExecutionInput{TaskID: deployTask.ID, OperationID: confirmed.OperationID, Owner: "http-domain-fixture", CoreGeneration: deployTask.CoreGeneration, LeaseGeneration: deployTask.LeaseGeneration})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitImageExecutionResult(ctx, appcontracts.CommitImageExecutionResultInput{TaskID: deployTask.ID, OperationID: confirmed.OperationID, DeploymentID: deploy.DeploymentID, ReleaseID: deploy.ReleaseID, Owner: "http-domain-fixture", CoreGeneration: deployTask.CoreGeneration, LeaseGeneration: deployTask.LeaseGeneration, ContainerID: "http-domain-container", ImageID: plan.ResolvedImage.Digest, ManifestDigest: plan.ResolvedImage.Digest, Artifact: appcontracts.StorageArtifactReceipt{StorageRef: "fixture/image", ContentDigest: plan.ResolvedImage.Digest, SizeBytes: 123}, HostPort: 39081, ContainerPort: 80, ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	private := t.TempDir()
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	trust := filepath.Join(private, "trust")
	if err := os.Mkdir(trust, 0o750); err != nil {
		t.Fatal(err)
	}
	lockFile := filepath.Join(trust, "gateway-projection.lock")
	if err := os.WriteFile(lockFile, nil, 0o660); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lockFile, 0o660); err != nil {
		t.Fatal(err)
	}
	commands := &application.ImagePublicAccessCommands{Store: store, Lock: application.GatewayProjectionLock{Path: lockFile, ExpectedOwnerUID: uint32(os.Getuid()), IPCGID: uint32(os.Getgid())}}
	h.Domain = &ImagePublicAccessHandler{Commands: commands, Store: store, Auth: authService, Config: LocalAuthRouteConfig, Available: func(context.Context) error { return nil }}
	request := func(method, path, body, key string, proof bool) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:12345"
		req.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.SessionCookie, Value: session})
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		if proof {
			req.Header.Set("Origin", "http://127.0.0.1:8080")
			req.Header.Set(LocalAuthRouteConfig.CSRFHeader, csrf)
			req.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.CSRFCookie, Value: csrf})
		}
		rec := httptest.NewRecorder()
		if !h.Handle(rec, req) {
			t.Fatal("domain route not dispatched")
		}
		return rec
	}
	path := ImageDeploymentsAPIBase + deploy.DeploymentID.String() + "/domain-commands"
	body := `{"hostname":"app.customer.example","action":"ensure","idempotency_key":"domain-key"}`
	if got := request(http.MethodPost, path, body, "domain-key", false).Code; got != http.StatusUnauthorized {
		t.Fatalf("missing CSRF accepted: %d", got)
	}
	if got := request(http.MethodPost, path, body, "other-key", true).Code; got != http.StatusBadRequest {
		t.Fatalf("header/body key mismatch accepted: %d", got)
	}
	h.Domain.Available = nil
	if got := request(http.MethodPost, path, body, "domain-key", true).Code; got != http.StatusServiceUnavailable {
		t.Fatalf("missing Gateway accepted a new command: %d", got)
	}
	h.Domain.Available = func(context.Context) error { return nil }
	accepted := request(http.MethodPost, path, body, "domain-key", true)
	if accepted.Code != http.StatusAccepted || strings.Contains(accepted.Body.String(), "private-domain-marker") || strings.Contains(accepted.Body.String(), "container_id") || strings.Contains(accepted.Body.String(), "host_port") {
		t.Fatalf("unsafe accepted domain response: code=%d body=%s", accepted.Code, accepted.Body.String())
	}
	var operation appcontracts.ImagePublicAccessOperation
	if err := json.Unmarshal(accepted.Body.Bytes(), &operation); err != nil || operation.State != "pending" || operation.Result != nil || operation.OperationID == confirmed.OperationID || operation.DeploymentID != deploy.DeploymentID {
		t.Fatalf("POST did not return independent original pending operation: %v %+v", err, operation)
	}
	replay := request(http.MethodPost, path, body, "domain-key", true)
	if replay.Code != http.StatusAccepted || replay.Body.String() != accepted.Body.String() {
		t.Fatal("same-key POST did not replay original response")
	}
	h.Domain.Available = nil
	offlineReplay := request(http.MethodPost, path, body, "domain-key", true)
	if offlineReplay.Code != http.StatusAccepted || offlineReplay.Body.String() != accepted.Body.String() {
		t.Fatal("Gateway outage hid the original accepted command")
	}
	if got := request(http.MethodPost, path, `{"hostname":"app.customer.example","action":"remove","idempotency_key":"domain-key"}`, "domain-key", true).Code; got != http.StatusConflict {
		t.Fatalf("offline same-key changed body did not conflict: %d", got)
	}
	if got := request(http.MethodPost, path, `{"hostname":"app.customer.example","action":"ensure","idempotency_key":"new-key"}`, "new-key", true).Code; got != http.StatusServiceUnavailable {
		t.Fatalf("Gateway outage created a new command: %d", got)
	}
	h.Domain.Available = func(context.Context) error { return nil }
	if got := request(http.MethodPost, path, `{"hostname":"app.customer.example","action":"remove","idempotency_key":"domain-key"}`, "domain-key", true).Code; got != http.StatusConflict {
		t.Fatalf("changed same-key body accepted: %d", got)
	}
	task := claim(appcontracts.ImagePublicAccessTaskKind)
	authority := appcontracts.ImagePublicAccessAuthority{BeginImageExecutionInput: appcontracts.BeginImageExecutionInput{TaskID: task.ID, OperationID: operation.OperationID, Owner: "http-domain-fixture", CoreGeneration: task.CoreGeneration, LeaseGeneration: task.LeaseGeneration}, ApprovalID: operation.ApprovalID, DeploymentID: operation.DeploymentID, EndpointVersion: "", ContainerID: "", Action: operation.Action}
	// Private target fields come only from the claimed task's persisted binding;
	// the public POST never exposes them.
	var payload struct {
		Binding appcontracts.ImagePublicAccessCommand `json:"binding"`
	}
	if err := json.Unmarshal(task.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	authority.EndpointVersion, authority.ContainerID = payload.Binding.EndpointVersion, payload.Binding.ContainerID
	if _, err := store.AuthorizeImagePublicAccess(ctx, authority); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitImagePublicAccess(ctx, authority, appcontracts.ImagePublicAccessObservation{RouteApplied: true, ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	read := request(http.MethodGet, ImageDomainOperationsAPIBase+operation.OperationID.String(), "", "", false)
	if read.Code != http.StatusOK || strings.Contains(read.Body.String(), "container_id") || strings.Contains(read.Body.String(), "private-domain-marker") {
		t.Fatalf("unsafe historical domain read: %d %s", read.Code, read.Body.String())
	}
	stop, err := store.CreateImageLifecycle(ctx, admin, appcontracts.CreateImageLifecycleInput{DeploymentID: deploy.DeploymentID, Action: appcontracts.ImageLifecycleStop, IdempotencyKey: "http-domain-stop"})
	if err != nil {
		t.Fatal(err)
	}
	stopTask := claim(appcontracts.ImageLifecycleTaskKind)
	stopAuthority := appcontracts.ImageLifecycleAuthorityInput{BeginImageExecutionInput: appcontracts.BeginImageExecutionInput{TaskID: stopTask.ID, OperationID: stop.OperationID, Owner: "http-domain-fixture", CoreGeneration: stopTask.CoreGeneration, LeaseGeneration: stopTask.LeaseGeneration}, DeploymentID: stop.DeploymentID, ReleaseID: stop.ReleaseID, PlanDigest: stop.PlanDigest, ContainerID: stop.ContainerID, Action: stop.Action}
	if err := store.CommitImageLifecycleResult(ctx, appcontracts.CommitImageLifecycleInput{ImageLifecycleAuthorityInput: stopAuthority, Result: appcontracts.ImageLifecycleResult{VerifiedIdentity: true, ContainerID: stop.ContainerID, ImageID: stop.ImageID, ManifestDigest: stop.ManifestDigest, ObservedAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	current := request(http.MethodGet, ImageDeploymentsAPIBase+deploy.DeploymentID.String()+"/domain", "", "", false)
	var status appcontracts.ImagePublicAccessCurrent
	if current.Code != http.StatusOK || json.Unmarshal(current.Body.Bytes(), &status) != nil || status.DeploymentStatus != "stopped" || status.LocalRouteState != "configured" || status.Availability != "degraded" || !status.DesiredPublic {
		t.Fatalf("Stop did not retain degraded domain fact: %d %+v", current.Code, status)
	}
}
