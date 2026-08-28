package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/persistence/postgres"
)

type systemStatusFixtureStore struct {
	fact  postgres.G3PlatformDomainFact
	found bool
	count int
	err   error
}

func (s systemStatusFixtureStore) PlatformDomain(context.Context) (postgres.G3PlatformDomainFact, bool, error) {
	return s.fact, s.found, s.err
}
func (s systemStatusFixtureStore) CountEnabledWebhookEndpoints(context.Context) (int, error) {
	return s.count, s.err
}

func TestSystemStatusRequiresSessionAndReturnsOnlyAggregateFacts(t *testing.T) {
	server := NewServer()
	server.SetSystemStatusNode("instance_fixture", "node_fixture")
	server.SetSystemStatusStore(systemStatusFixtureStore{fact: postgres.G3PlatformDomainFact{BaseDomain: "apps.example.test", VerificationStatus: postgres.G3VerificationVerified, Certificate: &postgres.G3CertificateFact{Status: "ready"}}, found: true, count: 1})
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session, csrf := attachTestAdministratorTokens(t, server, &now)
	anonymous := httptest.NewRecorder()
	server.Handler().ServeHTTP(anonymous, httptest.NewRequest(http.MethodGet, "/api/v1/settings/system-status", nil))
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous=%d", anonymous.Code)
	}
	allowed := httptest.NewRecorder()
	server.Handler().ServeHTTP(allowed, controlPlaneRequest(http.MethodGet, "/api/v1/settings/system-status", nil, session))
	if allowed.Code != http.StatusOK || strings.Contains(strings.ToLower(allowed.Body.String()), "secret") || strings.Contains(strings.ToLower(allowed.Body.String()), "url") || !strings.Contains(allowed.Body.String(), `"enabled_count":1`) || !strings.Contains(allowed.Body.String(), `"status":"ready"`) || !strings.Contains(allowed.Body.String(), `"webhooks":{"enabled_count":1,"status":"configured"}`) {
		t.Fatalf("status=%d body=%s", allowed.Code, allowed.Body.String())
	}
	missingCSRF := httptest.NewRecorder()
	post := controlPlaneRequest(http.MethodPost, "/api/v1/settings/system-status", nil, session)
	server.Handler().ServeHTTP(missingCSRF, post)
	if missingCSRF.Code != http.StatusUnauthorized {
		t.Fatalf("missing csrf=%d", missingCSRF.Code)
	}
	method := httptest.NewRecorder()
	post = controlPlaneRequest(http.MethodPost, "/api/v1/settings/system-status", nil, session)
	addControlPlaneWriteProof(post, csrf)
	server.Handler().ServeHTTP(method, post)
	if method.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method=%d", method.Code)
	}
}

func TestSystemStatusMarksZeroEnabledWebhooksUnconfigured(t *testing.T) {
	server := NewServer()
	server.SetSystemStatusStore(systemStatusFixtureStore{})
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session := attachTestAdministrator(t, server, &now)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, controlPlaneRequest(http.MethodGet, "/api/v1/settings/system-status", nil, session))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"webhooks":{"enabled_count":0,"status":"unconfigured"}`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestSystemStatusMarksUnconfiguredProvidersExplicitly(t *testing.T) {
	server := NewServer()
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session := attachTestAdministrator(t, server, &now)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, controlPlaneRequest(http.MethodGet, "/api/v1/settings/system-status", nil, session))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"readiness":"unconfigured"`) || !strings.Contains(recorder.Body.String(), `"status":"not_installed"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
