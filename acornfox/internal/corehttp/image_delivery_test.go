package corehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/application"
	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/auth"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/persistence/sqlite"
)

type fakeHTTPResolver struct{}

func (f *fakeHTTPResolver) ResolveMetadata(ctx context.Context, repository, reference string) (appcontracts.ResolvedMetadataResult, error) {
	return appcontracts.ResolvedMetadataResult{
		Repository:  repository,
		Digest:      "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ResolvedTag: reference,
		EvidenceRef: "ev_http_test_1",
	}, nil
}

func setupTestDeliveryHTTP(t *testing.T) (*ImageDeliveryHandler, *sqlite.Store, *auth.Service, string, string) {
	t.Helper()
	temp := t.TempDir()
	if err := os.Chmod(temp, 0700); err != nil {
		t.Fatal(err)
	}

	store, err := sqlite.Open(sqlite.Config{DataDirectory: temp})
	if err != nil {
		t.Fatalf("open sqlite store: %v", err)
	}

	origin := "http://127.0.0.1:8080"
	authService, err := auth.NewLocalService(auth.Config{
		Store:  store,
		Origin: origin,
	})
	if err != nil {
		t.Fatalf("init auth service: %v", err)
	}

	// Bootstrap admin password
	ctx := context.Background()
	adminID := domain.ID("adm_test_admin")
	hash, err := authService.HashPassword("SuperSecretPassword123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	now := time.Now().UTC()
	err = store.CreateAdminCredential(ctx, domain.AdminCredential{
		ID:                 adminID,
		PasswordHashScheme: auth.PasswordHashScheme,
		PasswordHash:       hash,
		CredentialVersion:  1,
		CreatedAt:          now,
		UpdatedAt:          now,
	})
	if err != nil {
		t.Fatalf("create admin credential: %v", err)
	}

	// Login to get session and csrf token
	loginRes, err := authService.Login(ctx, origin, "SuperSecretPassword123!", "127.0.0.1")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	deliveryService := application.NewImageDeliveryService(&fakeHTTPResolver{})
	handler := &ImageDeliveryHandler{
		Service: deliveryService,
		Store:   store,
		Auth:    authService,
		Config:  LocalAuthRouteConfig,
	}

	return handler, store, authService, loginRes.SessionToken, loginRes.CSRFTok
}

func TestImageDeliveryHTTP_AuthAndCSRFEnforcement(t *testing.T) {
	handler, store, _, sessionToken, csrfToken := setupTestDeliveryHTTP(t)
	defer store.Close()

	bodyJSON := `{"app_name":"web-app","image":"nginx:latest","port":80}`

	// 1. POST without session cookie: 401 Unauthorized
	req := httptest.NewRequest(http.MethodPost, ImagePlansAPIBase, strings.NewReader(bodyJSON))
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	handled := handler.Handle(rec, req)
	if !handled || rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected handled 401 without cookie, got handled=%v code=%d", handled, rec.Code)
	}

	// 2. POST with session cookie but missing CSRF token: 401 Unauthorized
	req = httptest.NewRequest(http.MethodPost, ImagePlansAPIBase, strings.NewReader(bodyJSON))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.SessionCookie, Value: sessionToken})
	rec = httptest.NewRecorder()
	handled = handler.Handle(rec, req)
	if !handled || rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected handled 401 without CSRF header, got handled=%v code=%d", handled, rec.Code)
	}

	// 3. POST with session cookie + valid CSRF + Origin: 201 Created
	req = httptest.NewRequest(http.MethodPost, ImagePlansAPIBase, strings.NewReader(bodyJSON))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Header.Set(LocalAuthRouteConfig.CSRFHeader, csrfToken)
	req.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.SessionCookie, Value: sessionToken})
	req.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.CSRFCookie, Value: csrfToken})
	rec = httptest.NewRecorder()
	handled = handler.Handle(rec, req)
	if !handled || rec.Code != http.StatusCreated {
		t.Fatalf("expected handled 201 with valid auth, got handled=%v code=%d body=%s", handled, rec.Code, rec.Body.String())
	}

	var plan appcontracts.ImagePlan
	if err := json.Unmarshal(rec.Body.Bytes(), &plan); err != nil {
		t.Fatalf("decode created plan response: %v", err)
	}
	if plan.AppName != "web-app" || plan.Status != appcontracts.ImagePlanStatusPlanned {
		t.Fatalf("unexpected plan response: %+v", plan)
	}

	// 4. GET /api/v1/acornfox/image-plans/{id} with session cookie: 200 OK
	getReq := httptest.NewRequest(http.MethodGet, ImagePlansAPIBase+"/"+plan.ID.String(), nil)
	getReq.RemoteAddr = "127.0.0.1:12345"
	getReq.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.SessionCookie, Value: sessionToken})
	getRec := httptest.NewRecorder()
	handled = handler.Handle(getRec, getReq)
	if !handled || getRec.Code != http.StatusOK {
		t.Fatalf("expected handled 200 on plan GET, got handled=%v code=%d body=%s", handled, getRec.Code, getRec.Body.String())
	}
}

func TestImageDeliveryHTTP_StrictBody(t *testing.T) {
	handler, store, _, sessionToken, csrfToken := setupTestDeliveryHTTP(t)
	defer store.Close()

	// 1. Unknown fields rejected
	unknownFieldJSON := `{"app_name":"web-app","image":"nginx:latest","port":80,"unknown_field":"value"}`
	req := httptest.NewRequest(http.MethodPost, ImagePlansAPIBase, strings.NewReader(unknownFieldJSON))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Header.Set(LocalAuthRouteConfig.CSRFHeader, csrfToken)
	req.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.SessionCookie, Value: sessionToken})
	req.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.CSRFCookie, Value: csrfToken})
	rec := httptest.NewRecorder()
	handler.Handle(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on unknown fields, got %d", rec.Code)
	}

	// 2. Trailing closing brace rejected
	trailingBraceJSON := `{"app_name":"web-app","image":"nginx:latest","port":80}}`
	req = httptest.NewRequest(http.MethodPost, ImagePlansAPIBase, strings.NewReader(trailingBraceJSON))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Header.Set(LocalAuthRouteConfig.CSRFHeader, csrfToken)
	req.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.SessionCookie, Value: sessionToken})
	req.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.CSRFCookie, Value: csrfToken})
	rec = httptest.NewRecorder()
	handler.Handle(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on trailing closing brace, got %d", rec.Code)
	}

	// 3. Valid JSON with over-limit trailing whitespace (>64KB total) rejected
	validWithOverLimitWhitespace := append([]byte(`{"app_name":"web-app","image":"nginx:latest","port":80}`), bytes.Repeat([]byte(" "), 70<<10)...)
	req = httptest.NewRequest(http.MethodPost, ImagePlansAPIBase, bytes.NewReader(validWithOverLimitWhitespace))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Header.Set(LocalAuthRouteConfig.CSRFHeader, csrfToken)
	req.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.SessionCookie, Value: sessionToken})
	req.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.CSRFCookie, Value: csrfToken})
	rec = httptest.NewRecorder()
	handler.Handle(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on oversized payload with trailing whitespace, got %d", rec.Code)
	}
}

func TestImageDeliveryHTTP_ConfirmAndOperationDetail(t *testing.T) {
	handler, store, _, sessionToken, csrfToken := setupTestDeliveryHTTP(t)
	defer store.Close()

	// 1. Create a planned image plan
	bodyJSON := `{"app_name":"my-service","image":"nginx:1.27.0","port":8080}`
	req := httptest.NewRequest(http.MethodPost, ImagePlansAPIBase, strings.NewReader(bodyJSON))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Header.Set(LocalAuthRouteConfig.CSRFHeader, csrfToken)
	req.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.SessionCookie, Value: sessionToken})
	req.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.CSRFCookie, Value: csrfToken})
	rec := httptest.NewRecorder()
	handler.Handle(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create plan failed: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var plan appcontracts.ImagePlan
	_ = json.Unmarshal(rec.Body.Bytes(), &plan)

	// 2. Confirm the plan via POST /api/v1/acornfox/image-plans/{id}/confirm
	confirmBody := map[string]string{
		"plan_id":         plan.ID.String(),
		"plan_digest":     plan.PlanDigest,
		"idempotency_key": "http-confirm-key-1",
	}
	confirmJSON, _ := json.Marshal(confirmBody)
	confirmReq := httptest.NewRequest(http.MethodPost, ImagePlansAPIBase+"/"+plan.ID.String()+"/confirm", bytes.NewReader(confirmJSON))
	confirmReq.RemoteAddr = "127.0.0.1:12345"
	confirmReq.Header.Set("Origin", "http://127.0.0.1:8080")
	confirmReq.Header.Set(LocalAuthRouteConfig.CSRFHeader, csrfToken)
	confirmReq.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.SessionCookie, Value: sessionToken})
	confirmReq.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.CSRFCookie, Value: csrfToken})
	confirmRec := httptest.NewRecorder()
	handler.Handle(confirmRec, confirmReq)
	if confirmRec.Code != http.StatusOK {
		t.Fatalf("confirm plan failed: code=%d body=%s", confirmRec.Code, confirmRec.Body.String())
	}

	var confirmResult appcontracts.ConfirmImagePlanResult
	if err := json.Unmarshal(confirmRec.Body.Bytes(), &confirmResult); err != nil {
		t.Fatalf("decode confirm response: %v", err)
	}
	if confirmResult.OperationID.Empty() || confirmResult.Status != "pending" {
		t.Fatalf("unexpected confirm result: %+v", confirmResult)
	}

	// 3. Read operation detail via GET /api/v1/acornfox/operations/{id}
	opReq := httptest.NewRequest(http.MethodGet, OperationsAPIBase+confirmResult.OperationID.String(), nil)
	opReq.RemoteAddr = "127.0.0.1:12345"
	opReq.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.SessionCookie, Value: sessionToken})
	opRec := httptest.NewRecorder()
	handler.Handle(opRec, opReq)
	if opRec.Code != http.StatusOK {
		t.Fatalf("get operation detail failed: code=%d body=%s", opRec.Code, opRec.Body.String())
	}

	var opDetail appcontracts.ImageOperationDetail
	if err := json.Unmarshal(opRec.Body.Bytes(), &opDetail); err != nil {
		t.Fatalf("decode operation detail: %v", err)
	}
	if opDetail.OperationID != confirmResult.OperationID || opDetail.PlanID != plan.ID || opDetail.State != "pending" {
		t.Fatalf("unexpected operation detail: %+v", opDetail)
	}

	// 4. Exercise real result query after execution commit
	ctx := context.Background()
	owner := "core-worker-test"
	claimedTask, ok, err := store.ClaimTask(ctx, appcontracts.ClaimTaskRequest{
		Kinds: []string{"image.deploy"},
		Owner: owner,
		Now:   time.Now().UTC(),
		LeasePolicy: appcontracts.LeasePolicy{
			Duration:    2 * time.Minute,
			MaxAttempts: 3,
		},
	})
	if err != nil || !ok {
		t.Fatalf("ClaimTask: ok=%v err=%v", ok, err)
	}

	binding, err := store.BeginImageExecution(ctx, appcontracts.BeginImageExecutionInput{
		TaskID:          claimedTask.ID,
		OperationID:     confirmResult.OperationID,
		Owner:           owner,
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		Now:             time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("BeginImageExecution: %v", err)
	}

	execNow := time.Now().UTC()
	if err := store.CommitImageExecutionResult(ctx, appcontracts.CommitImageExecutionResultInput{
		TaskID:          claimedTask.ID,
		OperationID:     confirmResult.OperationID,
		DeploymentID:    binding.DeploymentID,
		ReleaseID:       binding.ReleaseID,
		Owner:           owner,
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		Now:             execNow,
		ContainerID:     "c-podinfo-corehttp-01",
		ContainerName:   "acornfox-podinfo-ch",
		ImageID:         "sha256:5b85a3c2678f134440c9502b406b7d6fb8fa83842f1f513f5fb4ebcbe5e638b9",
		ManifestDigest:  plan.ResolvedImage.Digest,
		Artifact: appcontracts.StorageArtifactReceipt{
			StorageRef:    "image/ghcr.io/stefanprodan/podinfo/test",
			ContentDigest: "sha256:2222333344445555666677778888999900001111222233334444555566667777",
			SizeBytes:     1234567,
		},
		HostPort:      45678,
		ContainerPort: plan.CanonicalInput.Port,
		ObservedAt:    execNow,
	}); err != nil {
		t.Fatalf("CommitImageExecutionResult: %v", err)
	}

	// Query operation detail via API again after completion
	opReq2 := httptest.NewRequest(http.MethodGet, OperationsAPIBase+confirmResult.OperationID.String(), nil)
	opReq2.RemoteAddr = "127.0.0.1:12345"
	opReq2.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.SessionCookie, Value: sessionToken})
	opRec2 := httptest.NewRecorder()
	handler.Handle(opRec2, opReq2)
	if opRec2.Code != http.StatusOK {
		t.Fatalf("get completed operation failed: code=%d body=%s", opRec2.Code, opRec2.Body.String())
	}

	var opDetailWithResult appcontracts.ImageOperationDetailWithResult
	if err := json.Unmarshal(opRec2.Body.Bytes(), &opDetailWithResult); err != nil {
		t.Fatalf("decode completed operation detail: %v", err)
	}
	if opDetailWithResult.State != "succeeded" {
		t.Fatalf("expected state 'succeeded', got %s", opDetailWithResult.State)
	}
	if opDetailWithResult.Result == nil {
		t.Fatal("expected non-nil result in operation response")
	}
	if opDetailWithResult.Result.DeploymentID != binding.DeploymentID {
		t.Fatalf("expected deployment ID %s, got %s", binding.DeploymentID, opDetailWithResult.Result.DeploymentID)
	}
	if opDetailWithResult.Result.Endpoint != "http://127.0.0.1:45678" {
		t.Fatalf("expected endpoint http://127.0.0.1:45678, got %s", opDetailWithResult.Result.Endpoint)
	}
}

func TestManagedImageApplicationsHTTPUsesSessionAndStrictLimit(t *testing.T) {
	h, store, _, session, _ := setupTestDeliveryHTTP(t)
	defer store.Close()
	request := func(path string, authenticated bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if authenticated {
			r.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.SessionCookie, Value: session})
		}
		w := httptest.NewRecorder()
		if !h.Handle(w, r) {
			t.Fatal("saved image route not handled")
		}
		return w
	}
	if w := request("/api/v1/acornfox/image-apps", false); w.Code != http.StatusUnauthorized {
		t.Fatal("unauthenticated image listing allowed")
	}
	if w := request("/api/v1/acornfox/image-apps?limit=50", true); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatalf("list response %d %s", w.Code, w.Body.String())
	}
	if w := request("/api/v1/acornfox/image-apps?limit=101", true); w.Code != http.StatusBadRequest {
		t.Fatal("invalid list limit allowed")
	}
	if w := request("/api/v1/acornfox/image-apps?admin_id=other", true); w.Code != http.StatusBadRequest {
		t.Fatal("caller selected list owner")
	}
}
