package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/auth"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

func attachTestAcornFoxAdministratorTokens(t *testing.T, server *Server, now *time.Time) (*authHTTPStore, *http.Cookie, *http.Cookie) {
	t.Helper()
	store, session, csrf := attachTestAdministratorTokens(t, server, now)
	session.Name, csrf.Name = acornFoxAuthSessionCookie, acornFoxAuthCSRFCookie
	return store, session, csrf
}

func addAcornFoxWriteProof(request *http.Request, csrf *http.Cookie) {
	request.Header.Set("Origin", "https://console.example.test")
	request.AddCookie(csrf)
	request.Header.Set(acornFoxAuthCSRFHeader, csrf.Value)
}

type acornFoxCommandFixture struct {
	calls []string
	err   error
}

func TestAcornFoxAuthLoginAuthenticatesCleanAPIOnly(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	store := &authHTTPStore{}
	service, err := auth.NewService(auth.Config{Store: store, Origin: "https://console.example.test", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	password := "acornfox correct horse battery staple 123"
	hash, err := service.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	store.credential = domain.AdminCredential{ID: "admin_1", PasswordHashScheme: auth.PasswordHashScheme, PasswordHash: hash, CredentialVersion: 1, CreatedAt: now, UpdatedAt: now}
	server := NewAcornFoxServer()
	server.SetAuth(&AuthHTTPHandler{Service: service})

	login := httptest.NewRecorder()
	server.Handler().ServeHTTP(login, authRequest(http.MethodPost, acornFoxAuthAPIBase+"login", `{"password":"`+password+`"}`))
	if login.Code != http.StatusOK {
		t.Fatalf("clean login status=%d body=%s", login.Code, login.Body.String())
	}
	session, csrf := cookieValue(login.Result().Cookies(), acornFoxAuthSessionCookie), cookieValue(login.Result().Cookies(), acornFoxAuthCSRFCookie)
	if session == nil || csrf == nil || cookieValue(login.Result().Cookies(), authSessionCookie) != nil || cookieValue(login.Result().Cookies(), authCSRFCookie) != nil {
		t.Fatalf("clean login cookies=%#v", login.Result().Cookies())
	}
	apps := httptest.NewRequest(http.MethodGet, acornFoxAPIBase, nil)
	apps.AddCookie(session)
	appsRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(appsRecorder, apps)
	if appsRecorder.Code != http.StatusOK {
		t.Fatalf("clean authenticated API status=%d body=%s", appsRecorder.Code, appsRecorder.Body.String())
	}
	current := authRequest(http.MethodGet, acornFoxAuthAPIBase+"session", "")
	current.Header.Del("Content-Type")
	current.AddCookie(session)
	currentRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(currentRecorder, current)
	if currentRecorder.Code != http.StatusOK {
		t.Fatalf("clean session status=%d body=%s", currentRecorder.Code, currentRecorder.Body.String())
	}
	logout := authRequest(http.MethodPost, acornFoxAuthAPIBase+"logout", "")
	logout.Header.Del("Content-Type")
	logout.AddCookie(session)
	addAcornFoxWriteProof(logout, csrf)
	logoutRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(logoutRecorder, logout)
	if logoutRecorder.Code != http.StatusNoContent {
		t.Fatalf("clean logout status=%d body=%s", logoutRecorder.Code, logoutRecorder.Body.String())
	}
	legacy := httptest.NewRecorder()
	server.Handler().ServeHTTP(legacy, authRequest(http.MethodPost, authAPIBase+"login", `{"password":"`+password+`"}`))
	if legacy.Code != http.StatusNotFound {
		t.Fatalf("legacy auth unexpectedly exposed status=%d body=%s", legacy.Code, legacy.Body.String())
	}
}

func (f *acornFoxCommandFixture) Create(_ context.Context, app domain.ID, input acornFoxDeliveryInput, key, actor string) (acornFoxDeliveryResult, error) {
	if f.err != nil {
		return acornFoxDeliveryResult{}, f.err
	}
	f.calls = append(f.calls, "create:"+input.SourceRevisionID.String()+":"+key+":"+actor)
	return acornFoxDeliveryResult{DeploymentID: "dep_fixture", OperationID: "op_fixture", TaskID: "task_fixture", Status: "deploying"}, nil
}

func TestAcornFoxRouterRejectsPrefixConfusionUnknownPathsAndLegacyVariants(t *testing.T) {
	server := NewAcornFoxServer()
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session, csrf := attachTestAcornFoxAdministratorTokens(t, server, &now)
	paths := []string{
		"/api/v1/acornfox/auth/login/",
		"/api/v1/acornfox/auth//login",
		"/api/v1/acornfox/auth/unknown",
		"/api/v1/acornfox/appsfoo",
		"/api/v1/acornfox/apps/",
		"/api/v1/acornfox/apps//app_1",
		"/api/v1/acornfox/apps/app_1/deliveries/dep_1/restart/extra",
		"/api/v1/acornfox/apps/app_1/unknown",
		"/api/v1/acornfox/apps/app_1/deliveries/dep_1/rollback",
	}
	for _, legacy := range contracts.AcornFoxMigrationOnlyRouteInventory() {
		path := strings.NewReplacer("{applicationId}", "app_1", "{serviceGroupId}", "group_1", "{deploymentId}", "dep_1", "{releaseId}", "rel_1", "{claimId}", "claim_1", "{action}", "restart").Replace(legacy.Path)
		paths = append(paths, path, path+"/")
	}
	for _, path := range paths {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
			request := httptest.NewRequest(method, path, nil)
			request.AddCookie(session)
			if controlPlaneUnsafeMethod(method) {
				addAcornFoxWriteProof(request, csrf)
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusNotFound {
				t.Fatalf("%s %s status=%d body=%s", method, path, response.Code, response.Body.String())
			}
		}
	}
}

func TestAcornFoxOptionsUsesExactRouteMethodParity(t *testing.T) {
	server := NewAcornFoxServer()
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session, _ := attachTestAcornFoxAdministratorTokens(t, server, &now)
	for path, want := range map[string]string{
		"/api/v1/acornfox/apps":                                 "GET, POST, OPTIONS",
		"/api/v1/acornfox/apps/app_1":                           "GET, OPTIONS",
		"/api/v1/acornfox/apps/app_1/sources/src_1":             "GET, OPTIONS",
		"/api/v1/acornfox/apps/app_1/deliveries":                "POST, OPTIONS",
		"/api/v1/acornfox/apps/app_1/deliveries/dep_1":          "GET, OPTIONS",
		"/api/v1/acornfox/apps/app_1/deliveries/dep_1/restart":  "POST, OPTIONS",
		"/api/v1/acornfox/apps/app_1/deliveries/dep_1/redeploy": "POST, OPTIONS",
		"/api/v1/acornfox/apps/app_1/deliveries/dep_1/probes":   "POST, OPTIONS",
		"/api/v1/acornfox/apps/app_1/deliveries/dep_1/logs":     "GET, OPTIONS",
	} {
		request := httptest.NewRequest(http.MethodOptions, path, nil)
		request.AddCookie(session)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNoContent || response.Header().Get("Allow") != want {
			t.Fatalf("%s status=%d allow=%q want=%q", path, response.Code, response.Header().Get("Allow"), want)
		}
	}
}

func TestAcornFoxTaskAdapterRejectsMalformedAndLegacyTasks(t *testing.T) {
	runtime := mustAcornFoxAdapterTask(t, v1.TaskDeploy, map[string]any{"acornfox_payload_type": "deploy", "request": map[string]any{}})
	restart := mustAcornFoxAdapterTask(t, v1.TaskRestart, map[string]any{"acornfox_payload_type": "restart", "request": map[string]any{}})
	probe := mustAcornFoxAdapterTask(t, v1.TaskObserve, map[string]any{"acornfox_probe_payload_type": "probe", "request": map[string]any{}})
	for name, value := range map[string]json.RawMessage{"deploy": runtime, "restart": restart, "probe": probe, "legacy": mustAcornFoxAdapterTask(t, v1.TaskScale, map[string]any{"operation": map[string]any{}}), "wrong_kind": mustAcornFoxAdapterTask(t, v1.TaskObserve, map[string]any{"acornfox_payload_type": "deploy", "request": map[string]any{}})} {
		if validAcornFoxTaskPayload(value) {
			t.Fatalf("%s malformed task was accepted", name)
		}
	}
}

func mustAcornFoxAdapterTask(t *testing.T, kind v1.TaskKind, parameters map[string]any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{"kind": kind, "parameters": parameters})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
func (f *acornFoxCommandFixture) Restart(_ context.Context, _, _ domain.ID, key, _ string) (acornFoxDeliveryResult, error) {
	if f.err != nil {
		return acornFoxDeliveryResult{}, f.err
	}
	f.calls = append(f.calls, "restart:"+key)
	return acornFoxDeliveryResult{DeploymentID: "dep_fixture", OperationID: "op_restart", TaskID: "task_restart", Status: "restarting"}, nil
}
func (f *acornFoxCommandFixture) Redeploy(_ context.Context, _, _ domain.ID, key, _ string) (acornFoxDeliveryResult, error) {
	if f.err != nil {
		return acornFoxDeliveryResult{}, f.err
	}
	f.calls = append(f.calls, "redeploy:"+key)
	return acornFoxDeliveryResult{DeploymentID: "dep_fixture", OperationID: "op_redeploy", TaskID: "task_redeploy", Status: "redeploying"}, nil
}
func (f *acornFoxCommandFixture) Probe(_ context.Context, _, _ domain.ID, input acornFoxProbeInput, key, _ string) (acornFoxDeliveryResult, error) {
	if f.err != nil {
		return acornFoxDeliveryResult{}, f.err
	}
	f.calls = append(f.calls, "probe:"+string(input.Protocol)+":"+input.Path+":"+key)
	return acornFoxDeliveryResult{DeploymentID: "dep_fixture", OperationID: "op_probe", TaskID: "task_probe", Status: "probing"}, nil
}

func TestAcornFoxCleanRouteModeHidesLegacyRoutesAndCompatibilityHeaders(t *testing.T) {
	server := NewAcornFoxServer()
	configureTestSourcePreparer(server)
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session, csrf := attachTestAcornFoxAdministratorTokens(t, server, &now)

	legacy := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	request.AddCookie(session)
	server.Handler().ServeHTTP(legacy, request)
	if legacy.Code != http.StatusNotFound || legacy.Header().Get(apiVersionHeader) != "" {
		t.Fatalf("clean legacy response status=%d headers=%#v", legacy.Code, legacy.Header())
	}

	create := httptest.NewRequest(http.MethodPost, "/api/v1/acornfox/apps", strings.NewReader(`{"name":"acornfox-demo","source":{"type":"public_git","repository_url":"https://github.com/acornfox/example.git","ref":"main"}}`))
	create.Header.Set("Content-Type", "application/json")
	create.Header.Set("Idempotency-Key", "acornfox-create")
	create.AddCookie(session)
	addAcornFoxWriteProof(create, csrf)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, create)
	if response.Code != http.StatusCreated || response.Header().Get(apiVersionHeader) != "" || strings.Contains(response.Body.String(), "repository_url") {
		t.Fatalf("clean create status=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	missingRef := httptest.NewRequest(http.MethodPost, "/api/v1/acornfox/apps", strings.NewReader(`{"name":"missing-ref","source":{"type":"public_git","repository_url":"https://github.com/acornfox/example.git"}}`))
	missingRef.Header.Set("Content-Type", "application/json")
	missingRef.Header.Set("Idempotency-Key", "missing-ref")
	missingRef.AddCookie(session)
	addAcornFoxWriteProof(missingRef, csrf)
	missingRefResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(missingRefResponse, missingRef)
	if missingRefResponse.Code != http.StatusUnprocessableEntity || !strings.Contains(missingRefResponse.Body.String(), `"code":"validation_failed"`) {
		t.Fatalf("missing ref status=%d body=%s", missingRefResponse.Code, missingRefResponse.Body.String())
	}
}

func TestAcornFoxMutationsHaveNarrowInputsAndNoLegacyHeader(t *testing.T) {
	server := NewAcornFoxServer()
	fixture := &acornFoxCommandFixture{}
	server.SetAcornFoxDeliveryCommand(fixture)
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session, csrf := attachTestAcornFoxAdministratorTokens(t, server, &now)
	for _, test := range []struct{ path, body, want string }{
		{"/api/v1/acornfox/apps/app_1/deliveries", `{"source_revision_id":"src_1"}`, "create:src_1:mutation-key:admin_1"},
		{"/api/v1/acornfox/apps/app_1/deliveries/dep_1/restart", ``, "restart:mutation-key"},
		{"/api/v1/acornfox/apps/app_1/deliveries/dep_1/redeploy", `{}`, "redeploy:mutation-key"},
		{"/api/v1/acornfox/apps/app_1/deliveries/dep_1/probes", `{"protocol":"http","path":"/ready"}`, "probe:http:/ready:mutation-key"},
	} {
		request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "mutation-key")
		request.AddCookie(session)
		addAcornFoxWriteProof(request, csrf)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusAccepted || response.Header().Get(apiVersionHeader) != "" {
			t.Fatalf("%s status=%d headers=%#v body=%s", test.path, response.Code, response.Header(), response.Body.String())
		}
	}
	if strings.Join(fixture.calls, ",") != "create:src_1:mutation-key:admin_1,restart:mutation-key,redeploy:mutation-key,probe:http:/ready:mutation-key" {
		t.Fatalf("calls=%v", fixture.calls)
	}
	for _, body := range []string{`{"source_revision_id":"src_1","runtime":{}}`, `{"protocol":"http","host":"127.0.0.1"}`} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/acornfox/apps/app_1/deliveries", strings.NewReader(body))
		request.Header.Set("Idempotency-Key", "bad")
		request.AddCookie(session)
		addAcornFoxWriteProof(request, csrf)
		if strings.Contains(body, "protocol") {
			request.URL.Path = "/api/v1/acornfox/apps/app_1/deliveries/dep_1/probes"
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d", body, response.Code)
		}
	}
}

func TestAcornFoxPublicErrorsUseStableStatusAndEnvelope(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	for name, test := range map[string]struct {
		err  error
		want int
		code string
	}{
		"ownership":  {err: domain.NewError(domain.ErrNotFound, "other application"), want: http.StatusNotFound, code: "not_found"},
		"validation": {err: domain.ValidationError("invalid request"), want: http.StatusUnprocessableEntity, code: "validation_failed"},
		"active":     {err: postgres.ErrIdempotencyInProgress, want: http.StatusConflict, code: "operation_conflict"},
		"dependency": {err: errors.New("dependency unavailable"), want: http.StatusServiceUnavailable, code: "temporarily_unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			server := NewAcornFoxServer()
			server.SetAcornFoxDeliveryCommand(&acornFoxCommandFixture{err: test.err})
			_, session, csrf := attachTestAcornFoxAdministratorTokens(t, server, &now)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/acornfox/apps/app_1/deliveries", strings.NewReader(`{"source_revision_id":"src_1"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "error-"+name)
			request.AddCookie(session)
			addAcornFoxWriteProof(request, csrf)
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != test.want || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) || !strings.Contains(response.Body.String(), `"message":"`) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestAcornFoxMigrationModePreservesHistoricalRoutesOnlyWhenExplicit(t *testing.T) {
	server := NewServer()
	server.SetLegacyRoutesEnabled(true)
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session, _ := attachTestAdministratorTokens(t, server, &now)
	legacy := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	request.AddCookie(session)
	server.Handler().ServeHTTP(legacy, request)
	if legacy.Code != http.StatusOK {
		t.Fatalf("migration route status=%d body=%s", legacy.Code, legacy.Body.String())
	}
	for raw, want := range map[string]bool{"": false, "enabled": true, "true": false, "disabled": false} {
		got, err := acornFoxMigrationCompatibilityMode(raw)
		if want {
			if err != nil || !got {
				t.Fatalf("%q got=%v err=%v", raw, got, err)
			}
		} else if raw == "" {
			if err != nil || got {
				t.Fatalf("empty got=%v err=%v", got, err)
			}
		} else if err == nil {
			t.Fatalf("%q was accepted", raw)
		}
	}
}
