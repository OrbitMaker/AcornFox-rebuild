package corehttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/application"
	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/sqlite"
)

type countingSourcePrepareStore struct{ creates int }

func (*countingSourcePrepareStore) SourceBuildSchemaReady(context.Context) error { return nil }
func (s *countingSourcePrepareStore) CreateSourcePrepareIntent(context.Context, domain.ID, appcontracts.CreateSourcePrepareIntentInput) (appcontracts.SourceBuildIntentFact, error) {
	s.creates++
	return appcontracts.SourceBuildIntentFact{}, nil
}
func (*countingSourcePrepareStore) ApprovePublicSourceBuildPlan(context.Context, domain.ID, appcontracts.SourceBuildPublicApprovalInput, appcontracts.SourceBuildPolicyFact) (appcontracts.SourceBuildIntentFact, error) {
	return appcontracts.SourceBuildIntentFact{}, nil
}
func (*countingSourcePrepareStore) ReadPublicSourceBuildIntent(context.Context, domain.ID, domain.ID) (appcontracts.SourceBuildPublicIntent, error) {
	return appcontracts.SourceBuildPublicIntent{}, nil
}

// Existing real auth/SQLite fixture proves this new route preserves auth/CSRF
// and refuses business admission while actual0012 is not registered. The
// existing SQLite source fixture covers its real service/worker/Unix facts chain.
func TestSourceBuildHTTPPreservesAuthAndFailsClosedBeforeIntegration(t *testing.T) {
	_, store, authService, session, csrf := setupTestDeliveryHTTP(t)
	defer store.Close()
	handler := &SourceBuildHandler{Service: &application.SourceBuildService{Store: store, Available: func(context.Context) error { return nil }}, Auth: authService, Config: LocalAuthRouteConfig}
	body := `{"app_name":"source-http","repository":"https://github.com/acme/app","commit":"` + strings.Repeat("a", 40) + `","timeout_seconds":120,"idempotency_key":"source-http-key"}`
	call := func(cookie, csrfHeader, key, payload string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, SourceBuildAPIBase+"/prepare", strings.NewReader(payload))
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set("Origin", "http://127.0.0.1:8080")
		r.Header.Set("Idempotency-Key", key)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.SessionCookie, Value: cookie})
		}
		if csrfHeader != "" {
			r.Header.Set(LocalAuthRouteConfig.CSRFHeader, csrfHeader)
			r.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.CSRFCookie, Value: csrfHeader})
		}
		w := httptest.NewRecorder()
		if !handler.Handle(w, r) {
			t.Fatal("source route not handled")
		}
		return w
	}
	if w := call("", "", "source-http-key", body); w.Code != http.StatusUnauthorized {
		t.Fatal("source POST bypassed authentication")
	}
	if w := call(session, "", "source-http-key", body); w.Code != http.StatusUnauthorized {
		t.Fatal("source POST bypassed CSRF")
	}
	if w := call(session, csrf, "other-key", body); w.Code != http.StatusBadRequest {
		t.Fatal("request body/header key mismatch accepted")
	}
	if w := call(session, csrf, "source-http-key", body); w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "workspace") || strings.Contains(w.Body.String(), "sqlite") {
		t.Fatalf("missing actual migration was advertised ready: %d %s", w.Code, w.Body.String())
	}
	if w := call(session, csrf, "source-http-key", strings.TrimSuffix(body, "}")+`,"network":"caller-policy"}`); w.Code != http.StatusBadRequest {
		t.Fatal("caller network authority was accepted")
	}
	rec := httptest.NewRecorder()
	sourceBuildHTTPError(rec, sqlite.ErrSourceDefinitionNeedsInput)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "needs_input") {
		t.Fatal("missing root Dockerfile did not map to safe needs_input")
	}
	r := httptest.NewRequest(http.MethodGet, SourceBuildAPIBase+"/intents/spi_original", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.AddCookie(&http.Cookie{Name: LocalAuthRouteConfig.SessionCookie, Value: session})
	w := httptest.NewRecorder()
	handler.Handle(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal("missing source fact schema read did not fail closed")
	}
	// Once schema and peer admission are available, the actual service must
	// reject canonical private-host aliases before calling the Store writer.
	counting := &countingSourcePrepareStore{}
	handler.Service.Store = counting
	alias := strings.Replace(body, "https://github.com/acme/app", "https://LOCALHOST.../acme/app", 1)
	if w := call(session, csrf, "source-http-key", alias); w.Code != http.StatusBadRequest || counting.creates != 0 {
		t.Fatalf("canonical private-host alias reached Store: status=%d calls=%d", w.Code, counting.creates)
	}
}
