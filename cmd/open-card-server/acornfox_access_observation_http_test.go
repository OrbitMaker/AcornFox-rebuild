package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type accessObservationFixture struct {
	value       contracts.AcornFoxAccessObservation
	createError error
	replayed    bool
	owner       domain.ID
	found       bool
}

func (f *accessObservationFixture) CreateAcornFoxAccessObservation(_ context.Context, applicationID, deploymentID, owner domain.ID, report contracts.AcornFoxAccessObservationReport, now time.Time) (contracts.AcornFoxAccessObservation, bool, error) {
	f.owner = owner
	if f.createError != nil {
		return contracts.AcornFoxAccessObservation{}, false, f.createError
	}
	if applicationID != "app_1" || deploymentID != "dep_1" {
		return contracts.AcornFoxAccessObservation{}, false, postgres.ErrNotFound
	}
	value := f.value
	value.AcornFoxAccessObservationReport = report
	if !f.replayed {
		value.ReceivedAt = now
		value.ExpiresAt = now.Add(contracts.AcornFoxAccessObservationLifetime)
	}
	return value, f.replayed, nil
}

func (f *accessObservationFixture) GetCurrentAcornFoxAccessObservation(_ context.Context, applicationID, deploymentID domain.ID, _ time.Time) (contracts.AcornFoxAccessObservation, bool, error) {
	if applicationID != "app_1" || deploymentID != "dep_1" {
		return contracts.AcornFoxAccessObservation{}, false, postgres.ErrNotFound
	}
	return f.value, f.found, nil
}

func TestAcornFoxAccessObservationHTTPRequiresAdministratorAndEnforcesMethodAndJSON(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	fixture := &accessObservationFixture{value: accessObservationHTTPValue(now), found: true}
	handler := &AcornFoxAccessObservationHTTPHandler{Store: fixture, Clock: func() time.Time { return now }}

	unauthenticated := httptest.NewRecorder()
	handler.Handle(unauthenticated, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(validAccessObservationBody(now))), "app_1", "dep_1")
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d body=%s", unauthenticated.Code, unauthenticated.Body.String())
	}

	wrongMethod := httptest.NewRecorder()
	handler.Handle(wrongMethod, accessObservationAdminRequest(http.MethodPut, nil), "app_1", "dep_1")
	if wrongMethod.Code != http.StatusMethodNotAllowed || wrongMethod.Header().Get("Allow") != "GET, POST" {
		t.Fatalf("method status=%d allow=%q", wrongMethod.Code, wrongMethod.Header().Get("Allow"))
	}

	unknown := httptest.NewRecorder()
	body := strings.TrimSuffix(validAccessObservationBody(now), "}") + `,"extra":1}`
	handler.Handle(unknown, accessObservationAdminRequest(http.MethodPost, strings.NewReader(body)), "app_1", "dep_1")
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d body=%s", unknown.Code, unknown.Body.String())
	}

	oversized := httptest.NewRecorder()
	handler.Handle(oversized, accessObservationAdminRequest(http.MethodPost, strings.NewReader(validAccessObservationBody(now)+strings.Repeat(" ", acornFoxAccessObservationMaxBody))), "app_1", "dep_1")
	if oversized.Code != http.StatusBadRequest {
		t.Fatalf("oversized status=%d body=%s", oversized.Code, oversized.Body.String())
	}
}

func TestAcornFoxAccessObservationHTTPBindsOwnerAndDistinguishesReplay(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	fixture := &accessObservationFixture{value: accessObservationHTTPValue(now), found: true}
	handler := &AcornFoxAccessObservationHTTPHandler{Store: fixture, Clock: func() time.Time { return now }}

	created := httptest.NewRecorder()
	handler.Handle(created, accessObservationAdminRequest(http.MethodPost, strings.NewReader(validAccessObservationBody(now))), "app_1", "dep_1")
	if created.Code != http.StatusCreated || fixture.owner != "admin_1" {
		t.Fatalf("create status=%d owner=%q body=%s", created.Code, fixture.owner, created.Body.String())
	}

	fixture.replayed = true
	fixture.value.ReceivedAt = now.Add(-time.Minute)
	fixture.value.ExpiresAt = fixture.value.ReceivedAt.Add(contracts.AcornFoxAccessObservationLifetime)
	replay := httptest.NewRecorder()
	handler.Handle(replay, accessObservationAdminRequest(http.MethodPost, strings.NewReader(validAccessObservationBody(now))), "app_1", "dep_1")
	if replay.Code != http.StatusOK || !strings.Contains(replay.Body.String(), `"received_at":"2023-11-14T22:12:20Z"`) {
		t.Fatalf("replay status=%d body=%s", replay.Code, replay.Body.String())
	}
}

func TestAcornFoxAccessObservationHTTPReturnsExpiredFactAndMapsConflicts(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	value := accessObservationHTTPValue(now.Add(-10 * time.Minute))
	fixture := &accessObservationFixture{value: value, found: true}
	handler := &AcornFoxAccessObservationHTTPHandler{Store: fixture, Clock: func() time.Time { return now }}

	expired := httptest.NewRecorder()
	handler.Handle(expired, accessObservationAdminRequest(http.MethodGet, nil), "app_1", "dep_1")
	if expired.Code != http.StatusOK || !strings.Contains(expired.Body.String(), `"availability":"expired"`) || !strings.Contains(expired.Body.String(), `"report_id":"r1"`) {
		t.Fatalf("expired status=%d body=%s", expired.Code, expired.Body.String())
	}

	fixture.createError = postgres.ErrIdempotencyConflict
	conflict := httptest.NewRecorder()
	handler.Handle(conflict, accessObservationAdminRequest(http.MethodPost, strings.NewReader(validAccessObservationBody(now))), "app_1", "dep_1")
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), "idempotency_conflict") {
		t.Fatalf("conflict status=%d body=%s", conflict.Code, conflict.Body.String())
	}
}

func TestAcornFoxAccessObservationHTTPReturnsNotObservedForValidUnopenedTarget(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	fixture := &accessObservationFixture{}
	handler := &AcornFoxAccessObservationHTTPHandler{Store: fixture, Clock: func() time.Time { return now }}
	response := httptest.NewRecorder()
	handler.Handle(response, accessObservationAdminRequest(http.MethodGet, nil), "app_1", "dep_1")
	if response.Code != http.StatusOK || response.Body.String() != "{\"availability\":\"not_observed\"}\n" {
		t.Fatalf("not observed status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAcornFoxAccessObservationHTTPDistinguishesMissingAndDisabledTargets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	fixture := &accessObservationFixture{value: accessObservationHTTPValue(now)}
	handler := &AcornFoxAccessObservationHTTPHandler{Store: fixture, Clock: func() time.Time { return now }}

	missing := httptest.NewRecorder()
	handler.Handle(missing, accessObservationAdminRequest(http.MethodGet, nil), "app_other", "dep_1")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing target status=%d body=%s", missing.Code, missing.Body.String())
	}

	fixture.createError = domain.NewError(domain.ErrConflict, "public access is not enabled")
	disabled := httptest.NewRecorder()
	handler.Handle(disabled, accessObservationAdminRequest(http.MethodPost, strings.NewReader(validAccessObservationBody(now))), "app_1", "dep_1")
	if disabled.Code != http.StatusConflict || !strings.Contains(disabled.Body.String(), "target_conflict") {
		t.Fatalf("disabled target status=%d body=%s", disabled.Code, disabled.Body.String())
	}
}

func accessObservationHTTPValue(now time.Time) contracts.AcornFoxAccessObservation {
	return contracts.AcornFoxAccessObservation{
		Observer: "administrator_client", ApplicationID: "app_1", DeploymentID: "dep_1", Hostname: "delivery-aaaaaaaaaaaaaaaaaaaa.apps.example.test",
		AcornFoxAccessObservationReport: contracts.AcornFoxAccessObservationReport{
			ReportID: "r1", ObservedAt: now,
			DNS: contracts.AcornFoxAccessDNSReport{State: contracts.AcornFoxAccessFailed, FailureCode: "dns_timeout"},
			TLS: contracts.AcornFoxAccessTLSReport{State: contracts.AcornFoxAccessNotAttempted}, HTTPS: contracts.AcornFoxAccessHTTPSReport{State: contracts.AcornFoxAccessNotAttempted},
		},
		ReceivedAt: now, ExpiresAt: now.Add(contracts.AcornFoxAccessObservationLifetime),
	}
}

func validAccessObservationBody(now time.Time) string {
	return `{"report_id":"r1","observed_at":"` + now.Format(time.RFC3339Nano) + `","dns":{"state":"failed","failure_code":"dns_timeout"},"tls":{"state":"not_attempted"},"https":{"state":"not_attempted"}}`
}

func accessObservationAdminRequest(method string, body *strings.Reader) *http.Request {
	var request *http.Request
	if body == nil {
		request = httptest.NewRequest(method, "/", nil)
	} else {
		request = httptest.NewRequest(method, "/", body)
	}
	return withControlPlaneIdentity(request, "admin_1")
}
