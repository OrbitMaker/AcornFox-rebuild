package main

import (
	"context"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type publishStoreFixture struct {
	input postgres.ApplicationPublishInput
	calls int
}

func (s *publishStoreFixture) LatestApplicationPublishInput(context.Context, domain.ID) (postgres.ApplicationPublishInput, error) {
	s.calls++
	return s.input, nil
}

type publisherFixture struct {
	request controllers.PublishRequest
	empty   bool
}

func (p *publisherFixture) Publish(_ context.Context, r controllers.PublishRequest) (controllers.PublishResult, error) {
	p.request = r
	if p.empty {
		return controllers.PublishResult{}, nil
	}
	return controllers.PublishResult{Operation: domain.Operation{ID: "op_publish"}, Release: domain.Release{ID: "rel_publish"}, Deployment: domain.Deployment{ID: "dep_publish"}, TaskID: "task_publish", SourceRevision: domain.SourceRevision{ID: "src_publish"}}, nil
}
func TestApplicationPublishRejectsIncompleteResult(t *testing.T) {
	store := &publishStoreFixture{input: postgres.ApplicationPublishInput{SourceRevisionID: "src_1", SourceKind: "upload", Locator: "upload://upload_1", ContentDigest: "sha256:" + strings.Repeat("a", 64), EnvironmentID: "env_1", NextVersion: 2}}
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"build_kind":"static","context_path":".","service_name":"web","container_port":8080}`))
	request.Header.Set("Idempotency-Key", "key")
	recorder := httptest.NewRecorder()
	handleApplicationPublish(recorder, request, "app_1", store, &publisherFixture{empty: true}, "admin", time.Now)
	if recorder.Code != http.StatusInternalServerError || strings.Contains(recorder.Body.String(), "workspace") || strings.Contains(recorder.Body.String(), "locator") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
func TestApplicationPublishSuccessUsesDerivedSafeRequest(t *testing.T) {
	store := &publishStoreFixture{input: postgres.ApplicationPublishInput{SourceRevisionID: "src_1", SourceKind: "upload", Locator: "upload://upload_1", ContentDigest: "sha256:" + strings.Repeat("a", 64), EnvironmentID: "env_1", NextVersion: 2}}
	publisher := &publisherFixture{}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/applications/app_1/publishes", strings.NewReader(`{"build_kind":"static","context_path":".","service_name":"web","container_port":8080}`))
	request.Header.Set("Idempotency-Key", "publish-key")
	recorder := httptest.NewRecorder()
	handleApplicationPublish(recorder, request, "app_1", store, publisher, "admin_1", func() time.Time { return time.Unix(1, 0) })
	body := recorder.Body.String()
	if recorder.Code != http.StatusAccepted || strings.Contains(body, "workspace") || strings.Contains(body, "locator") || !strings.Contains(body, "op_publish") {
		t.Fatalf("status=%d body=%s", recorder.Code, body)
	}
	if publisher.request.Actor != "admin_1" || publisher.request.IdempotencyKey != "publish-key" || publisher.request.ServiceGroupID != "legacy" || publisher.request.BuildNetwork.Mode != "none" || publisher.request.ContextPath != "." || publisher.request.BuildResources.CPUMillis != 500 || publisher.request.BuildResources.PIDs != 0 || publisher.request.RuntimeResources.PIDs != 64 {
		t.Fatalf("request=%+v", publisher.request)
	}
}
func TestApplicationPublishRejectsBeforeSideEffects(t *testing.T) {
	for _, tc := range []struct {
		name, key, actor string
		store            publishInputStore
		publisher        applicationPublisher
		want             int
	}{{"missing_key", "", "admin", &publishStoreFixture{}, &publisherFixture{}, http.StatusUnprocessableEntity}, {"missing_actor", "key", "", &publishStoreFixture{}, &publisherFixture{}, http.StatusUnprocessableEntity}, {"nil_dependencies", "key", "admin", nil, nil, http.StatusServiceUnavailable}} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/v1/applications/app_1/publishes", strings.NewReader(`{"build_kind":"static","context_path":".","service_name":"web","container_port":8080}`))
			request.Header.Set("Idempotency-Key", tc.key)
			recorder := httptest.NewRecorder()
			handleApplicationPublish(recorder, request, "app_1", tc.store, tc.publisher, tc.actor, time.Now)
			if recorder.Code != tc.want {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if store, ok := tc.store.(*publishStoreFixture); ok && store.calls != 0 {
				t.Fatalf("store calls=%d", store.calls)
			}
		})
	}
}
func TestApplicationPublishRejectsUnknownJSONField(t *testing.T) {
	store := &publishStoreFixture{input: postgres.ApplicationPublishInput{SourceRevisionID: "src_1", SourceKind: "upload", Locator: "upload://upload_1", ContentDigest: "sha256:" + strings.Repeat("a", 64), EnvironmentID: "env_1", NextVersion: 2}}
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"build_kind":"static","context_path":".","service_name":"web","container_port":8080,"unknown":true}`))
	r.Header.Set("Idempotency-Key", "key")
	w := httptest.NewRecorder()
	handleApplicationPublish(w, r, "app_1", store, &publisherFixture{}, "admin", time.Now)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}
