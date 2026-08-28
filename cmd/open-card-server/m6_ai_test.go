package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ailedger "github.com/open-card/open-card/internal/ai/ledger"
	aiprovider "github.com/open-card/open-card/internal/ai/provider"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

type m6BackendFixture struct {
	settings M6AISettings
	request  M6AIRequest
}

func (f *m6BackendFixture) ListInterventions(context.Context, domain.ID, bool) (M6AIInterventionView, error) {
	return M6AIInterventionView{Version: "ai-v1", Mode: "ordinary", AIStatus: "disabled", Items: []M6AIInterventionFact{}}, nil
}
func (f *m6BackendFixture) RequestIntervention(_ context.Context, _ domain.ID, r M6AIRequest) (M6AIInterventionFact, error) {
	f.request = r
	return M6AIInterventionFact{ID: "airec_1", ApplicationID: "app_1", TaskType: r.TaskType, Status: "manual_fallback", Reason: r.Reason, Summary: "AI disabled", Suggestion: "manual review"}, nil
}
func (f *m6BackendFixture) GetSettings(context.Context) (M6AISettings, error) { return f.settings, nil }
func (f *m6BackendFixture) UpdateSettings(_ context.Context, u M6AISettingsUpdate) (M6AISettings, error) {
	f.settings = M6AISettings{Version: "ai-v2", Enabled: u.Enabled, Profile: u.Profile, Provider: u.Provider, Model: u.Model, DataScopes: u.DataScopes, MaxTokens: u.MaxTokens, MaxDurationMS: u.MaxDurationMS, CooldownSeconds: u.CooldownSeconds, CacheEnabled: u.CacheEnabled, ExternalCalls: false}
	return f.settings, nil
}

func TestM6AIHandlerKeepsOrdinaryViewSimpleAndOperatorFactsPrivate(t *testing.T) {
	h := &M6AIHTTPHandler{Backend: &m6BackendFixture{}}
	ordinary := httptest.NewRecorder()
	h.Handle(ordinary, httptest.NewRequest(http.MethodGet, "/api/v1/applications/app_1/ai/interventions", nil))
	if ordinary.Code != http.StatusOK || strings.Contains(ordinary.Body.String(), "plan") {
		t.Fatalf("ordinary=%d %s", ordinary.Code, ordinary.Body.String())
	}
	denied := httptest.NewRecorder()
	h.Handle(denied, httptest.NewRequest(http.MethodGet, "/api/v1/applications/app_1/ai/interventions?mode=operator", nil))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("operator leaked=%d %s", denied.Code, denied.Body.String())
	}
}

func TestM6AIHandlerDoesNotOptimisticallyClaimDisabledFallback(t *testing.T) {
	backend := &m6BackendFixture{}
	h := &M6AIHTTPHandler{Backend: backend}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/applications/app_1/ai/interventions", strings.NewReader(`{"task_type":"build_failure_diagnosis","reason":"rule miss","expected_version":"ops-v1","confirmed":false}`))
	request = withControlPlaneIdentity(request, "admin_test")
	request.Header.Set("Idempotency-Key", "ai-request-1")
	response := httptest.NewRecorder()
	h.Handle(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"manual_fallback"`) {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
}

func TestM6AISettingsFailClosedAndNeverClaimExternalCalls(t *testing.T) {
	backend := &m6BackendFixture{settings: M6AISettings{Version: "ai-v1", Enabled: false, Status: "disabled", Profile: "disabled", ExternalCalls: false}}
	h := &M6AIHTTPHandler{Backend: backend}
	denied := httptest.NewRecorder()
	h.Handle(denied, httptest.NewRequest(http.MethodGet, "/api/v1/settings/ai", nil))
	if denied.Code != http.StatusForbidden {
		t.Fatal(denied.Code)
	}
	request := httptest.NewRequest(http.MethodPut, "/api/v1/settings/ai", strings.NewReader(`{"expected_version":"ai-v1","enabled":true,"profile":"local","provider":"fixture","model":"deterministic","data_scopes":["summary"],"max_tokens":128,"max_duration_ms":1000,"cooldown_seconds":60,"cache_enabled":true}`))
	request = withControlPlaneIdentity(request, "admin_test")
	request.Header.Set("Idempotency-Key", "ai-settings-1")
	response := httptest.NewRecorder()
	h.Handle(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), `"external_calls":true`) {
		t.Fatalf("settings=%d %s", response.Code, response.Body.String())
	}
}

func TestM6BackendSettingsVersioningAndDisabledFallbackLeaveLedgerEmpty(t *testing.T) {
	store := ailedger.NewLocal()
	provider := aiprovider.NewFake(aiprovider.ProfileLocal)
	backend := &m6AIBackend{ledger: store, providers: map[ailedger.Profile]contracts.AIProvider{ailedger.ProfileLocal: provider}, now: func() time.Time { return time.Unix(100, 0).UTC() }}
	settings, err := backend.GetSettings(context.Background())
	if err != nil || settings.Version != "ai-v0" || settings.Status != "disabled" {
		t.Fatalf("default=%+v err=%v", settings, err)
	}
	view, err := backend.ListInterventions(context.Background(), "app_1", true)
	if err != nil || view.Version != "ai-v1:empty" {
		t.Fatalf("view=%+v err=%v", view, err)
	}
	fallback, err := backend.RequestIntervention(context.Background(), "app_1", M6AIRequest{TaskType: "build_failure_diagnosis", Reason: "rule miss", ExpectedVersion: view.Version, Actor: "operator", IdempotencyKey: "ai-disabled-1"})
	if err != nil || fallback.Status != "manual_fallback" {
		t.Fatalf("fallback=%+v err=%v", fallback, err)
	}
	metrics, _ := store.Metrics(context.Background(), ailedger.QueryFilter{})
	if metrics.Interventions != 0 {
		t.Fatalf("disabled fallback wrote AI ledger: %+v", metrics)
	}
	updated, err := backend.UpdateSettings(context.Background(), M6AISettingsUpdate{ExpectedVersion: "ai-v0", Enabled: true, Profile: "local", Provider: "deterministic-fixture", Model: "fixture-v1", DataScopes: []string{"operations_summary"}, MaxTokens: 128, MaxDurationMS: 1000, CooldownSeconds: 60, CacheEnabled: true, Actor: "operator", IdempotencyKey: "settings-1"})
	if err != nil || updated.Version != "ai-v1" || updated.Status != "available" || updated.ExternalCalls {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
}
