package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
)

type m4HTTPFixture struct {
	view     domain.ApplicationOperationsView
	requests []controllers.M4OperationRequest
	webhooks []controllers.M4WebhookEndpoint
	notifies []controllers.M4NotificationRequest
}

func (f *m4HTTPFixture) GetApplicationOperationsView(context.Context, domain.ID, domain.ID) (domain.ApplicationOperationsView, error) {
	return f.view, nil
}
func (f *m4HTTPFixture) GetDefaultEnvironmentID(context.Context, domain.ID) (domain.ID, error) {
	return "env_test", nil
}
func (f *m4HTTPFixture) Restart(_ context.Context, request controllers.M4OperationRequest) (controllers.M4OperationResult, error) {
	f.requests = append(f.requests, request)
	return controllers.M4OperationResult{Operation: domain.Operation{ID: "op_restart", ApplicationID: request.ApplicationID, EnvironmentID: request.EnvironmentID, TargetRef: "environment/" + request.EnvironmentID.String(), Type: domain.OperationRestart, IdempotencyKey: request.IdempotencyKey, Status: domain.OperationSucceeded, CreatedAt: time.Unix(2, 0), UpdatedAt: time.Unix(2, 0)}, Action: "service_restart", Scope: "service", ServiceName: "api", RollbackData: false, DataNotice: "Persistent data is not rolled back."}, nil
}
func (f *m4HTTPFixture) Redeploy(ctx context.Context, request controllers.M4OperationRequest) (controllers.M4OperationResult, error) {
	return f.Restart(ctx, request)
}
func (f *m4HTTPFixture) Rollback(ctx context.Context, request controllers.M4OperationRequest) (controllers.M4OperationResult, error) {
	return f.Restart(ctx, request)
}
func (f *m4HTTPFixture) ConfigureM4Webhook(_ context.Context, _ domain.ID, url string, reference domain.SecretReference, _ []string, _ string) (controllers.M4WebhookEndpoint, error) {
	endpoint := controllers.M4WebhookEndpoint{ID: "webhook_test", URL: url, Enabled: true, SecretRef: reference}
	f.webhooks = append(f.webhooks, endpoint)
	return endpoint, nil
}
func (f *m4HTTPFixture) GetM4Webhook(_ context.Context, _ domain.ID, id domain.ID) (controllers.M4WebhookEndpoint, error) {
	if id != "webhook_test" || len(f.webhooks) == 0 {
		return controllers.M4WebhookEndpoint{}, domain.NewError(domain.ErrNotFound, "webhook endpoint was not found")
	}
	return f.webhooks[0], nil
}
func (f *m4HTTPFixture) Publish(_ context.Context, request controllers.M4NotificationRequest) (controllers.M4NotificationResult, error) {
	f.notifies = append(f.notifies, request)
	return controllers.M4NotificationResult{DeliveryID: "delivery_test", EventID: "notify_test", Status: controllers.M4NotificationPending}, nil
}

func m4HTTPView() domain.ApplicationOperationsView {
	now := time.Unix(1, 0).UTC()
	return domain.ApplicationOperationsView{Version: "facts-v1", ApplicationID: "app_test", ApplicationName: "operations test", EnvironmentID: "env_test", ReleaseID: "release_test", State: domain.ApplicationPartial, Serving: true, Summary: "API unhealthy", Impact: "API unavailable", NextStep: "restart api", Services: []domain.ServiceOperationsFact{{Name: "api", Role: domain.RoleWorker, DeploymentID: "dep_test", ReleaseID: "release_test", Status: "unhealthy", Healthy: false, Required: true, Impact: "API unavailable", NextAction: "restart api", ObservedAt: now}}, AllowedActions: domain.OperationsAllowedActions{RestartServices: []string{"api"}, Redeploy: true, Rollback: true}, DataNotice: "Persistent data is not rolled back.", AIStatus: "disabled", ObservedAt: now}
}

func TestM4ViewsShareFactVersionAndProtectOperatorDetail(t *testing.T) {
	fixture := &m4HTTPFixture{view: m4HTTPView()}
	handler := &M4OperationsHTTPHandler{Operations: fixture, Views: fixture}
	ordinary := httptest.NewRecorder()
	handler.Handle(ordinary, httptest.NewRequest(http.MethodGet, "/api/v1/operations/views/app_test?environment_id=env_test&mode=ordinary", nil))
	operatorRequest := httptest.NewRequest(http.MethodGet, "/api/v1/operations/views/app_test?environment_id=env_test&mode=operator", nil)
	operatorRequest.Header.Set("X-Open-Card-Role", "operator")
	operator := httptest.NewRecorder()
	handler.Handle(operator, operatorRequest)
	if ordinary.Code != http.StatusOK || operator.Code != http.StatusOK || !strings.Contains(ordinary.Body.String(), `"version":"facts-v1"`) || !strings.Contains(operator.Body.String(), `"version":"facts-v1"`) {
		t.Fatalf("views diverged ordinary=%d %s operator=%d %s", ordinary.Code, ordinary.Body.String(), operator.Code, operator.Body.String())
	}
	forbidden := httptest.NewRecorder()
	handler.Handle(forbidden, httptest.NewRequest(http.MethodGet, "/api/v1/operations/views/app_test?environment_id=env_test&mode=operator", nil))
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("operator facts were public: %d %s", forbidden.Code, forbidden.Body.String())
	}
}

func TestM4UnknownDeploymentRemainsVisibleButActionsFailClosed(t *testing.T) {
	now := time.Now().UTC()
	adapter := &m4PostgresAdapter{}
	environment := controllers.M4Environment{
		ApplicationID:     "app_unknown",
		EnvironmentID:     "env_unknown",
		CurrentRelease:    domain.Release{ID: "release_unknown", ApplicationID: "app_unknown"},
		CurrentDeployment: domain.Deployment{ID: "dep_unknown", ApplicationID: "app_unknown", EnvironmentID: "env_unknown", ReleaseID: "release_unknown", Status: domain.DeploymentUnknown, CreatedAt: now, UpdatedAt: now},
	}
	view := adapter.buildView("unknown runtime", environment, []domain.ServiceOperationsFact{{Name: "api", Healthy: true, ObservedAt: now}})
	if view.Serving || view.State != domain.ApplicationAttention || view.AllowedActions.Redeploy || view.AllowedActions.Rollback || len(view.AllowedActions.RestartServices) != 0 {
		t.Fatalf("unknown deployment view is not fail-closed: %+v", view)
	}
	if view.Impact != "Runtime reachability is unknown" || view.NextStep == "" {
		t.Fatalf("unknown deployment guidance is inaccurate: %+v", view)
	}
}

func TestM4MutationRequiresOperatorActorIdempotencyAndExpectedVersion(t *testing.T) {
	fixture := &m4HTTPFixture{view: m4HTTPView()}
	handler := &M4OperationsHTTPHandler{Operations: fixture, Views: fixture}
	body := `{"application_id":"app_test","environment_id":"env_test","expected_version":"facts-v1","reason":"restart unhealthy api"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/operations/restart", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "restart-api")
	request.Header.Set("X-Open-Card-Actor", "user_test")
	request.Header.Set("X-Open-Card-Role", "operator")
	recorder := httptest.NewRecorder()
	handler.Handle(recorder, request)
	if recorder.Code != http.StatusAccepted || len(fixture.requests) != 1 || fixture.requests[0].ExpectedVersion != "facts-v1" || !strings.Contains(recorder.Body.String(), `"rollback_data":false`) {
		t.Fatalf("mutation response=%d %s requests=%#v", recorder.Code, recorder.Body.String(), fixture.requests)
	}
	unauthorized := httptest.NewRecorder()
	handler.Handle(unauthorized, httptest.NewRequest(http.MethodPost, "/api/v1/operations/restart", strings.NewReader(body)))
	if unauthorized.Code != http.StatusForbidden {
		t.Fatalf("unauthorized operation accepted: %d %s", unauthorized.Code, unauthorized.Body.String())
	}
}

func TestM4BrowserApplicationOperationsContractUsesServerEnvironment(t *testing.T) {
	fixture := &m4HTTPFixture{view: m4HTTPView()}
	handler := &M4OperationsHTTPHandler{Operations: fixture, Views: fixture}
	get := httptest.NewRecorder()
	if !handler.HandleApplication(get, httptest.NewRequest(http.MethodGet, "/api/v1/applications/app_test/operations", nil)) || get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"application_name":"operations test"`) || !strings.Contains(get.Body.String(), `"cpu_millicores":0`) {
		t.Fatalf("browser facts response=%d %s", get.Code, get.Body.String())
	}
	body := `{"action":"restart","target_service_id":"api","expected_version":"facts-v1","reason":"operator reviewed unhealthy api"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/applications/app_test/operations", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "browser-restart")
	request.Header.Set("Open-Card-Actor", "web-console")
	request.Header.Set("Open-Card-Role", "operator")
	post := httptest.NewRecorder()
	handler.HandleApplication(post, request)
	if post.Code != http.StatusAccepted || len(fixture.requests) != 1 || fixture.requests[0].EnvironmentID != "env_test" || !strings.Contains(post.Body.String(), `"operation_id":"op_restart"`) {
		t.Fatalf("browser action response=%d %s requests=%#v", post.Code, post.Body.String(), fixture.requests)
	}
}

func TestM4WebhookConfigurationUsesOpaqueReferenceAndQueuesTest(t *testing.T) {
	fixture := &m4HTTPFixture{view: m4HTTPView()}
	handler := &M4WebhookHTTPHandler{Store: fixture, Notifications: fixture, Environments: fixture, Clock: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }}
	body := `{"url":"https://receiver.fixture.test/events","secret_ref":{"id":"secret_webhook","name":"webhook","provider":"filesystem-secret","version":"v1"},"event_types":["notification.occurrence","notification.recovery"]}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/applications/app_test/webhooks", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Open-Card-Role", "operator")
	request.Header.Set("Open-Card-Actor", "operator_test")
	request.Header.Set("Idempotency-Key", "webhook-config")
	configured := httptest.NewRecorder()
	if !handler.HandleApplication(configured, request) || configured.Code != http.StatusCreated || len(fixture.webhooks) != 1 || strings.Contains(configured.Body.String(), "ciphertext") {
		t.Fatalf("webhook configuration response=%d %s endpoint=%#v", configured.Code, configured.Body.String(), fixture.webhooks)
	}
	testRequest := httptest.NewRequest(http.MethodPost, "/api/v1/applications/app_test/webhooks/webhook_test/test", nil)
	testRequest.Header.Set("Open-Card-Role", "operator")
	testRequest.Header.Set("Open-Card-Actor", "operator_test")
	testRequest.Header.Set("Idempotency-Key", "webhook-test")
	tested := httptest.NewRecorder()
	if !handler.HandleApplication(tested, testRequest) || tested.Code != http.StatusAccepted || len(fixture.notifies) != 1 || fixture.notifies[0].Event.Kind != controllers.M4NotificationOccurrence || fixture.notifies[0].Endpoint.SecretRef.ID != "secret_webhook" {
		t.Fatalf("webhook test response=%d %s notifications=%#v", tested.Code, tested.Body.String(), fixture.notifies)
	}
	bad := httptest.NewRequest(http.MethodPost, "/api/v1/applications/app_test/webhooks", strings.NewReader(strings.Replace(body, "notification.recovery", "deployment.failed", 1)))
	bad.Header.Set("Content-Type", "application/json")
	bad.Header.Set("Open-Card-Role", "operator")
	bad.Header.Set("Open-Card-Actor", "operator_test")
	bad.Header.Set("Idempotency-Key", "webhook-invalid")
	invalid := httptest.NewRecorder()
	if !handler.HandleApplication(invalid, bad) || invalid.Code != http.StatusBadRequest || len(fixture.webhooks) != 1 {
		t.Fatalf("unsupported webhook event type was accepted: code=%d endpoint=%#v", invalid.Code, fixture.webhooks)
	}
}

func TestM4WebhookTestUsesOpaquePerKeyIncidentIdentity(t *testing.T) {
	fixture := &m4HTTPFixture{view: m4HTTPView(), webhooks: []controllers.M4WebhookEndpoint{{ID: "webhook_test", URL: "https://receiver.fixture.test/events", Enabled: true, SecretRef: domain.SecretReference{ID: "secret_webhook", Name: "webhook", Provider: "filesystem-secret", Version: "v1"}}}}
	handler := &M4WebhookHTTPHandler{Store: fixture, Notifications: fixture, Environments: fixture, Clock: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }}
	post := func(key string) int {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/applications/app_test/webhooks/webhook_test/test", nil)
		request.Header.Set("Open-Card-Role", "operator")
		request.Header.Set("Open-Card-Actor", "operator_test")
		request.Header.Set("Idempotency-Key", key)
		recorder := httptest.NewRecorder()
		handler.HandleApplication(recorder, request)
		return recorder.Code
	}
	if post("test-key-one") != http.StatusAccepted || post("test-key-two") != http.StatusAccepted || post("test-key-one") != http.StatusAccepted || len(fixture.notifies) != 3 {
		t.Fatalf("test requests were not queued: %#v", fixture.notifies)
	}
	first, second, replay := fixture.notifies[0].Event.IncidentID, fixture.notifies[1].Event.IncidentID, fixture.notifies[2].Event.IncidentID
	if first == second || first != replay || strings.Contains(first, "test-key") || strings.Contains(second, "test-key") {
		t.Fatalf("operator test identities are not stable and opaque: first=%q second=%q replay=%q", first, second, replay)
	}
}
