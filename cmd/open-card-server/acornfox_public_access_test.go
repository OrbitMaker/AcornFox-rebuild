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

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

type acornFoxPublicAccessHTTPFixture struct {
	get      contracts.AcornFoxPublicAccessFact
	set      contracts.AcornFoxPublicAccessFact
	err      error
	gets     int
	requests []application.AcornFoxPublicAccessRequest
}

func (fixture *acornFoxPublicAccessHTTPFixture) Get(_ context.Context, _, _ domain.ID) (contracts.AcornFoxPublicAccessFact, error) {
	fixture.gets++
	return fixture.get, fixture.err
}

func (fixture *acornFoxPublicAccessHTTPFixture) Set(_ context.Context, request application.AcornFoxPublicAccessRequest) (contracts.AcornFoxPublicAccessFact, error) {
	fixture.requests = append(fixture.requests, request)
	return fixture.set, fixture.err
}

func TestAcornFoxPublicAccessHTTPHasExactShapeAndAuthBoundary(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	server := NewAcornFoxServer()
	_, session, csrf := attachTestAcornFoxAdministratorTokens(t, server, &now)
	host, err := contracts.AcornFoxPublicHostname("example.test", "app_1", "dep_1")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &acornFoxPublicAccessHTTPFixture{
		get: contracts.AcornFoxPublicAccessFact{ApplicationID: "app_1", DeploymentID: "dep_1", Hostname: host, Status: contracts.AcornFoxPublicDisabled, InternalEndpoint: contracts.AcornFoxInternalEndpointNotObserved, LocalRoute: contracts.AcornFoxLocalRouteDisabled},
		set: contracts.AcornFoxPublicAccessFact{ApplicationID: "app_1", DeploymentID: "dep_1", Hostname: host, Status: contracts.AcornFoxPublicPendingExternalValidation, DesiredPublic: true, InternalEndpoint: contracts.AcornFoxInternalEndpointAccepted, LocalRoute: contracts.AcornFoxLocalRouteConfigured},
	}
	server.SetAcornFoxPublicAccess(&AcornFoxPublicAccessHTTPHandler{Service: fixture})
	path := acornFoxAPIBase + "/app_1/deliveries/dep_1/public-access"

	get := httptest.NewRequest(http.MethodGet, path, nil)
	get.AddCookie(session)
	getRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(getRecorder, get)
	if getRecorder.Code != http.StatusOK || fixture.gets != 1 || strings.Contains(getRecorder.Body.String(), "port") || strings.Contains(getRecorder.Body.String(), "service") || !strings.Contains(getRecorder.Body.String(), `"internal_endpoint":"not_observed"`) || !strings.Contains(getRecorder.Body.String(), `"local_route":"disabled"`) {
		t.Fatalf("GET did not expose only local public facts: status=%d body=%s calls=%d", getRecorder.Code, getRecorder.Body.String(), fixture.gets)
	}

	put := httptest.NewRequest(http.MethodPut, path, strings.NewReader(`{"enabled":true}`))
	put.Header.Set("Content-Type", "application/json")
	put.Header.Set("Idempotency-Key", "toggle-1")
	put.AddCookie(session)
	addAcornFoxWriteProof(put, csrf)
	putRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(putRecorder, put)
	if putRecorder.Code != http.StatusOK || len(fixture.requests) != 1 || !fixture.requests[0].Enabled || fixture.requests[0].IdempotencyKey != "toggle-1" || !strings.Contains(putRecorder.Body.String(), "PENDING_EXTERNAL_VALIDATION") || !strings.Contains(putRecorder.Body.String(), `"local_route":"configured"`) {
		t.Fatalf("PUT did not pass exact public-access request: status=%d body=%s requests=%#v", putRecorder.Code, putRecorder.Body.String(), fixture.requests)
	}
	for _, body := range []string{"{}", `{"enabled":true,"hostname":"attacker.example"}`, `{"enabled":"true"}`} {
		req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "invalid-"+body[:2])
		req.AddCookie(session)
		addAcornFoxWriteProof(req, csrf)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusBadRequest || len(fixture.requests) != 1 {
			t.Fatalf("unsafe body=%s status=%d requests=%#v", body, recorder.Code, fixture.requests)
		}
	}
	missingProof := httptest.NewRequest(http.MethodPut, path, strings.NewReader(`{"enabled":false}`))
	missingProof.Header.Set("Content-Type", "application/json")
	missingProof.Header.Set("Idempotency-Key", "toggle-2")
	missingProof.AddCookie(session)
	missingProofRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(missingProofRecorder, missingProof)
	if missingProofRecorder.Code != http.StatusUnauthorized || len(fixture.requests) != 1 {
		t.Fatalf("missing CSRF was not denied: status=%d requests=%#v", missingProofRecorder.Code, fixture.requests)
	}
}

func TestAcornFoxPublicAccessHTTPMapsOnlyStableErrors(t *testing.T) {
	for errorValue, wantStatus := range map[error]int{
		application.ErrAcornFoxPublicAccessIdempotencyConflict: http.StatusConflict,
		application.ErrAcornFoxInternalEndpointNotReady:        http.StatusConflict,
		application.ErrAcornFoxPublicAccessConflict:            http.StatusConflict,
		application.ErrAcornFoxPublicAccessOwnershipConflict:   http.StatusConflict,
		application.ErrAcornFoxPublicAccessUnavailable:         http.StatusServiceUnavailable,
	} {
		recorder := httptest.NewRecorder()
		writeAcornFoxPublicAccessError(recorder, errorValue)
		var response map[string]string
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if recorder.Code != wantStatus || response["code"] == "" {
			t.Fatalf("error=%v status=%d response=%v", errorValue, recorder.Code, response)
		}
	}
}

func TestAcornFoxPublicAccessRouteAdapterUsesOnlyDerivedRoute(t *testing.T) {
	provider := contracts.NewFakeRouteProvider(true)
	adapter := acornFoxPublicAccessRouteAdapter{Routes: provider}
	endpoint := contracts.AcornFoxRoutableEndpoint{ApplicationID: "app_1", DeploymentID: "dep_1", ServiceName: "web", Port: 18080, Accepted: true}
	intent, err := contracts.NewAcornFoxPublicRouteIntent("example.test", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.EnsureAcornFoxPublicRoute(context.Background(), intent, "key-1"); err != nil {
		t.Fatal(err)
	}
	spec, err := intent.RouteSpec()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Observe(context.Background(), contracts.RouteRequest{Route: spec, Operation: contracts.OperationContext{IdempotencyKey: "observe"}}); err != nil {
		t.Fatalf("derived route was not applied: %v", err)
	}
	if err := adapter.RemoveAcornFoxPublicRoute(context.Background(), intent, "key-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Observe(context.Background(), contracts.RouteRequest{Route: spec, Operation: contracts.OperationContext{IdempotencyKey: "observe-after-remove"}}); err == nil {
		t.Fatal("derived route was not removed")
	}
	if !errors.Is(acornFoxPublicAccessRouteError(errors.New("provider unavailable")), application.ErrAcornFoxPublicAccessUnavailable) {
		t.Fatal("unknown provider error was not fail-closed")
	}
}
