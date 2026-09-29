package corehttp

import (
	"context"
	"encoding/json"
	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestImageLifecycleHTTPCommandIdentityAuthAndStoppedEndpoint(t *testing.T) {
	h, store, _, session, csrf := setupTestDeliveryHTTP(t)
	defer store.Close()
	ctx := context.Background()
	admin := domain.ID("adm_test_admin")
	plan, err := h.Service.CreatePlan(ctx, admin, appcontracts.ImagePlanInput{AppName: "http-lifecycle", Image: "nginx:latest", Port: 80, Environment: map[string]string{"MODE": "private_plan_marker"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateImagePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	confirmed, err := store.ConfirmImagePlan(ctx, admin, appcontracts.ConfirmImagePlanInput{PlanID: plan.ID, PlanDigest: plan.PlanDigest, IdempotencyKey: "http-lifecycle-deploy"})
	if err != nil {
		t.Fatal(err)
	}
	claim := func(kind string) appcontracts.Task {
		t.Helper()
		task, ok, err := store.ClaimTask(ctx, appcontracts.ClaimTaskRequest{Kinds: []string{kind}, Owner: "http-fixture", Now: time.Now().UTC(), LeasePolicy: appcontracts.LeasePolicy{Duration: time.Minute, MaxAttempts: 3}})
		if err != nil || !ok {
			t.Fatalf("claim: %v %v", ok, err)
		}
		return task
	}
	task := claim("image.deploy")
	original, err := store.BeginImageExecution(ctx, appcontracts.BeginImageExecutionInput{TaskID: task.ID, OperationID: confirmed.OperationID, Owner: task.LeaseOwner, CoreGeneration: task.CoreGeneration, LeaseGeneration: task.LeaseGeneration})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitImageExecutionResult(ctx, appcontracts.CommitImageExecutionResultInput{TaskID: task.ID, OperationID: confirmed.OperationID, DeploymentID: original.DeploymentID, ReleaseID: original.ReleaseID, Owner: task.LeaseOwner, CoreGeneration: task.CoreGeneration, LeaseGeneration: task.LeaseGeneration, ContainerID: "http-fixture-container", ImageID: plan.ResolvedImage.Digest, ManifestDigest: plan.ResolvedImage.Digest, Artifact: appcontracts.StorageArtifactReceipt{StorageRef: "http-fixture/archive", ContentDigest: plan.ResolvedImage.Digest, SizeBytes: 123}, HostPort: 39081, ContainerPort: 80, ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string, proof bool) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:12345"
		req.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.SessionCookie, Value: session})
		if proof {
			req.Header.Set("Origin", "http://127.0.0.1:8080")
			req.Header.Set(LocalAuthRouteConfig.CSRFHeader, csrf)
			req.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.CSRFCookie, Value: csrf})
		}
		rec := httptest.NewRecorder()
		if !h.Handle(rec, req) {
			t.Fatal("lifecycle route not dispatched")
		}
		return rec
	}
	path := ImageDeploymentsAPIBase + original.DeploymentID.String() + "/lifecycle"
	body := `{"action":"stop","idempotency_key":"http-stop"}`
	if rec := request(http.MethodPost, path, body, false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing CSRF accepted %d", rec.Code)
	}
	if rec := request(http.MethodPost, path, `{"action":"stop","idempotency_key":"http-stop","deployment_id":"different"}`, true); rec.Code != http.StatusBadRequest {
		t.Fatal("alternate body target accepted")
	}
	rec := request(http.MethodPost, path, body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	var command appcontracts.ImageLifecycleOperation
	if err := json.Unmarshal(rec.Body.Bytes(), &command); err != nil {
		t.Fatal(err)
	}
	if command.OperationID == confirmed.OperationID || command.DeploymentID != original.DeploymentID || command.Action != appcontracts.ImageLifecycleStop || command.Result != nil || strings.Contains(rec.Body.String(), "private_plan_marker") || strings.Contains(rec.Body.String(), `"plan":`) {
		t.Fatal("command identity/plan projection failed")
	}
	replay := request(http.MethodPost, path, body, true)
	if replay.Body.String() != rec.Body.String() {
		t.Fatal("HTTP replay changed original command response")
	}
	conflict := request(http.MethodPost, path, `{"action":"restart","idempotency_key":"http-stop"}`, true)
	if conflict.Code != http.StatusConflict {
		t.Fatal("changed same-key action accepted")
	}
	task = claim(appcontracts.ImageLifecycleTaskKind)
	binding, err := store.BeginImageLifecycle(ctx, appcontracts.BeginImageExecutionInput{TaskID: task.ID, OperationID: command.OperationID, Owner: task.LeaseOwner, CoreGeneration: task.CoreGeneration, LeaseGeneration: task.LeaseGeneration})
	if err != nil {
		t.Fatal(err)
	}
	authority := appcontracts.ImageLifecycleAuthorityInput{BeginImageExecutionInput: appcontracts.BeginImageExecutionInput{TaskID: task.ID, OperationID: command.OperationID, Owner: task.LeaseOwner, CoreGeneration: task.CoreGeneration, LeaseGeneration: task.LeaseGeneration}, DeploymentID: binding.DeploymentID, ReleaseID: binding.ReleaseID, PlanDigest: binding.PlanDigest, ContainerID: binding.ContainerID, Action: binding.Action}
	if err := store.CommitImageLifecycleResult(ctx, appcontracts.CommitImageLifecycleInput{ImageLifecycleAuthorityInput: authority, Result: appcontracts.ImageLifecycleResult{VerifiedIdentity: true, ContainerID: binding.ContainerID, ImageID: binding.ImageID, ManifestDigest: binding.ManifestDigest, HostPort: binding.HostPort, ContainerPort: binding.ContainerPort, ObservedAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	read := request(http.MethodGet, ImageLifecycleOperationsAPIBase+command.OperationID.String(), "", false)
	if read.Code != http.StatusOK {
		t.Fatal("command read failed")
	}
	if err := json.Unmarshal(read.Body.Bytes(), &command); err != nil {
		t.Fatal(err)
	}
	if command.State != "succeeded" || command.Result == nil || command.Result.Running || command.Result.EndpointReady {
		t.Fatal("stop borrowed ready endpoint")
	}
	old := request(http.MethodGet, OperationsAPIBase+confirmed.OperationID.String(), "", false)
	var detail appcontracts.ImageOperationDetailWithResult
	if err := json.Unmarshal(old.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if old.Code != http.StatusOK || detail.State != "succeeded" || detail.Result == nil || detail.Result.Status != "stopped" || detail.Result.Endpoint != "" || detail.Result.HostPort != 39081 {
		t.Fatalf("old deploy historical success/current stopped projection: %+v", detail)
	}
}

func TestPublicImageLifecycleReasonIsOptionalAndOutcomeScoped(t *testing.T) {
	binding := appcontracts.ImageLifecycleBinding{State: "waiting", Reason: "persisted safe diagnostic"}
	public := publicImageLifecycle(binding)
	if public.State != "unknown" || public.Reason != binding.Reason {
		t.Fatal("unknown command omitted actual read diagnostic")
	}
	binding.State = "succeeded"
	public = publicImageLifecycle(binding)
	encoded, err := json.Marshal(public)
	if err != nil || public.Reason != "" || strings.Contains(string(encoded), `"reason"`) {
		t.Fatal("successful command exposed stale diagnostic")
	}
}
