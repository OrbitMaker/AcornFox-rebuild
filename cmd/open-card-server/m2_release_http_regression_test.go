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
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// m2ReleaseHTTPRegressionStore is deliberately shared by the HTTP adapter and
// the controller. It models the facts that the adapter reads from PostgreSQL
// and counts only the durable release write as a side effect.
type m2ReleaseHTTPRegressionStore struct {
	record       postgres.ServiceGroupRecord
	identity     postgres.M2ServiceGroupIdentity
	source       domain.SourceRevision
	environment  domain.ID
	workspace    postgres.WorkspaceLifecycle
	releaseCalls int
	buildCalls   int
}

type m2ReleaseHTTPRegistryFake struct {
	allowedPrefix  string
	calls          int
	lastRepository string
}

func (f *m2ReleaseHTTPRegistryFake) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{
		Name:            "m2-http-regression-registry",
		Version:         "test",
		ContractVersion: contracts.ContractAPIVersion,
		Capabilities:    contracts.NewCapabilitySet(contracts.CapabilityImageResolve, contracts.CapabilityImagePull),
	}
}

func (f *m2ReleaseHTTPRegistryFake) Resolve(ctx context.Context, request contracts.ImageResolveRequest) (contracts.ImageResolveResult, error) {
	return f.ResolveAndPull(ctx, request)
}

func (f *m2ReleaseHTTPRegistryFake) ResolveAndPull(_ context.Context, request contracts.ImageResolveRequest) (contracts.ImageResolveResult, error) {
	f.calls++
	f.lastRepository = request.Repository
	if !strings.HasPrefix(request.Repository, f.allowedPrefix) {
		return contracts.ImageResolveResult{}, &contracts.ProviderError{Code: contracts.ErrValidation, Message: "registry repository host does not match endpoint", Retry: contracts.RetryNever}
	}
	image, err := domain.ParseImageDigest(request.Repository, "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd")
	if err != nil {
		return contracts.ImageResolveResult{}, err
	}
	image.ResolvedTag = request.Tag
	return contracts.ImageResolveResult{Image: image}, nil
}

func (s *m2ReleaseHTTPRegressionStore) CreateSourceRevision(_ context.Context, revision domain.SourceRevision) (domain.SourceRevision, error) {
	return revision, nil
}
func (s *m2ReleaseHTTPRegressionStore) CreateServiceGroupRevision(_ context.Context, request postgres.ServiceGroupCreateRequest) (domain.ServiceGroup, error) {
	s.record.Group = request.Group
	s.identity = request.Identity
	return request.Group, nil
}
func (s *m2ReleaseHTTPRegressionStore) CreateBuildPlan(_ context.Context, plan domain.BuildPlan) (domain.BuildPlan, error) {
	return plan, nil
}
func (s *m2ReleaseHTTPRegressionStore) CreateBuild(_ context.Context, build domain.Build) (domain.Build, error) {
	s.buildCalls++
	return build, nil
}
func (s *m2ReleaseHTTPRegressionStore) StartBuild(_ context.Context, id domain.ID, now time.Time) (domain.Build, error) {
	return domain.Build{ID: id, Status: domain.BuildRunning, CreatedAt: now, UpdatedAt: now}, nil
}
func (s *m2ReleaseHTTPRegressionStore) CompleteBuild(_ context.Context, artifact domain.Artifact, _ *postgres.ReleaseCreation, now time.Time) (domain.Build, error) {
	return domain.Build{ID: artifact.BuildID, Status: domain.BuildSucceeded, ArtifactID: artifact.ID, CreatedAt: now, UpdatedAt: now}, nil
}
func (s *m2ReleaseHTTPRegressionStore) FailBuild(_ context.Context, id domain.ID, _ string, now time.Time) (domain.Build, error) {
	return domain.Build{ID: id, Status: domain.BuildFailed, CreatedAt: now, UpdatedAt: now}, nil
}
func (s *m2ReleaseHTTPRegressionStore) CreateM2Release(_ context.Context, creation postgres.M2ReleaseCreation, _ time.Time) (domain.Release, error) {
	s.releaseCalls++
	return creation.Release, nil
}
func (s *m2ReleaseHTTPRegressionStore) EnqueueControllerTask(_ context.Context, _ postgres.EnqueueControllerTaskRequest) (application.Event, error) {
	return application.Event{}, nil
}

func (s *m2ReleaseHTTPRegressionStore) GetSourceRevision(_ context.Context, id domain.ID) (domain.SourceRevision, error) {
	if id != s.source.ID {
		return domain.SourceRevision{}, errors.New("source revision not found")
	}
	return s.source, nil
}
func (s *m2ReleaseHTTPRegressionStore) GetSourceWorkspaceLifecycle(_ context.Context, id domain.ID) (postgres.WorkspaceLifecycle, error) {
	if id != s.source.ID {
		return "", errors.New("source workspace not found")
	}
	return s.workspace, nil
}
func (s *m2ReleaseHTTPRegressionStore) CreateDeliveryDefinition(_ context.Context, definition domain.ApplicationDeliveryDefinition) (domain.ApplicationDeliveryDefinition, error) {
	return definition, nil
}
func (s *m2ReleaseHTTPRegressionStore) GetDeliveryDefinition(_ context.Context, id domain.ID) (domain.ApplicationDeliveryDefinition, error) {
	return domain.ApplicationDeliveryDefinition{ID: id}, nil
}
func (s *m2ReleaseHTTPRegressionStore) GetServiceGroupRecord(_ context.Context, id domain.ID) (postgres.ServiceGroupRecord, error) {
	if id != s.record.Group.ID {
		return postgres.ServiceGroupRecord{}, errors.New("service group not found")
	}
	return s.record, nil
}
func (s *m2ReleaseHTTPRegressionStore) GetServiceGroupIdentity(_ context.Context, id domain.ID) (postgres.M2ServiceGroupIdentity, error) {
	if id != s.record.Group.ID {
		return postgres.M2ServiceGroupIdentity{}, errors.New("service group identity not found")
	}
	return s.identity, nil
}
func (s *m2ReleaseHTTPRegressionStore) GetCompleteRelease(context.Context, domain.ID) (domain.Release, error) {
	return domain.Release{}, errors.New("complete release lookup is not part of this fixture")
}
func (s *m2ReleaseHTTPRegressionStore) GetM2ReleaseRuntimeSpec(context.Context, domain.ID) (contracts.ServiceGroupRuntimeSpec, string, error) {
	return contracts.ServiceGroupRuntimeSpec{}, "", errors.New("runtime spec lookup is not part of this fixture")
}
func (s *m2ReleaseHTTPRegressionStore) GetDeployment(context.Context, domain.ID) (domain.Deployment, error) {
	return domain.Deployment{}, errors.New("deployment lookup is not part of this fixture")
}
func (s *m2ReleaseHTTPRegressionStore) GetDeploymentEndpoint(context.Context, domain.ID) (postgres.DeploymentEndpoint, error) {
	return postgres.DeploymentEndpoint{}, errors.New("endpoint lookup is not part of this fixture")
}
func (s *m2ReleaseHTTPRegressionStore) GetDefaultEnvironmentID(context.Context, domain.ID) (domain.ID, error) {
	return s.environment, nil
}
func (s *m2ReleaseHTTPRegressionStore) GetDeploymentOperationID(context.Context, domain.ID) (domain.ID, error) {
	return "", errors.New("operation lookup is not part of this fixture")
}
func (s *m2ReleaseHTTPRegressionStore) ListM2ReleaseVolumeClaims(context.Context, domain.ID) ([]postgres.M2ServiceGroupVolumeClaim, error) {
	return nil, nil
}

func m2ReleaseHTTPRegressionFixture() (*m2ReleaseHTTPRegressionStore, *controllers.M2ReleaseController) {
	const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	now := time.Unix(1_700_000_000, 0).UTC()
	group := domain.ServiceGroup{
		ID:            "group_m4_http_regression",
		ApplicationID: "app_m4_http_regression",
		Name:          "canonical-m4",
		CreatedAt:     now,
		Services: []domain.ServiceSpec{{
			Name:     "web",
			Role:     domain.RoleIngress,
			Required: true,
			Port:     8080,
			Source:   domain.ServiceSource{Kind: domain.ServiceStatic, Static: &domain.StaticSource{Directory: "."}},
		}},
	}
	store := &m2ReleaseHTTPRegressionStore{
		record: postgres.ServiceGroupRecord{Group: group},
		identity: postgres.M2ServiceGroupIdentity{
			DefinitionID:    "def_m4_http_regression",
			Version:         1,
			ConfigDigest:    digest,
			CanonicalDigest: digest,
		},
		source: domain.SourceRevision{
			ID:            "src_m4_http_regression",
			ApplicationID: group.ApplicationID,
			Kind:          domain.SourceUpload,
			Locator:       "upload://m4-http-regression",
			ContentDigest: digest,
			WorkspaceRef:  "workspace://m4-http-regression",
			CreatedAt:     now,
			Immutable:     true,
		},
		environment: "env_m4_http_regression",
		workspace:   postgres.WorkspacePrepared,
	}
	controller := &controllers.M2ReleaseController{
		Store:               store,
		Source:              contracts.NewFakeSourceProvider(),
		Build:               contracts.NewFakeBuildProvider(true),
		Registry:            &m2ReleaseHTTPRegistryFake{allowedPrefix: "127.0.0.1:45542/"},
		Capacity:            contracts.NewFakeCapacityProvider(true),
		StaticRuntimeDigest: digest,
		Clock:               func() time.Time { return now },
	}
	return store, controller
}

func m2ReleaseHTTPRegressionServer(store *m2ReleaseHTTPRegressionStore, controller *controllers.M2ReleaseController) *Server {
	server := NewServer()
	server.m2Store = store
	server.m2Controller = controller
	return server
}

func TestM2ReleaseRejectsNonPreparedUploadBeforeBuildProvider(t *testing.T) {
	store, controller := m2ReleaseHTTPRegressionFixture()
	store.workspace = postgres.WorkspaceReleased
	server := m2ReleaseHTTPRegressionServer(store, controller)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/service-groups/"+store.record.Group.ID.String()+"/releases", strings.NewReader(`{"source_revision_id":"src_m4_http_regression","version":1}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "m2-pending-source")
	recorder := httptest.NewRecorder()
	if !server.handleM2(recorder, request) {
		t.Fatal("M2 release route was not handled")
	}
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "source_preparation_pending") || store.buildCalls != 0 || store.releaseCalls != 0 {
		t.Fatalf("non-prepared source status=%d body=%s builds=%d releases=%d", recorder.Code, recorder.Body.String(), store.buildCalls, store.releaseCalls)
	}
}

func decodeM2ReleaseHTTPBody(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: status=%d body=%q err=%v", recorder.Code, recorder.Body.String(), err)
	}
	return body
}

func TestM2ReleaseCanonicalHTTPRequestCreatesOneImmutableRelease(t *testing.T) {
	store, controller := m2ReleaseHTTPRegressionFixture()
	server := m2ReleaseHTTPRegressionServer(store, controller)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/service-groups/"+store.record.Group.ID.String()+"/releases", strings.NewReader(`{"source_revision_id":"src_m4_http_regression","version":1}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "m4-canonical-release-1")
	recorder := httptest.NewRecorder()

	if !server.handleM2(recorder, request) {
		t.Fatal("M2 release route was not handled")
	}
	if recorder.Code != http.StatusCreated {
		t.Fatalf("canonical release request status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := decodeM2ReleaseHTTPBody(t, recorder)
	if body["release"] == nil || body["canonical_digest"] == nil {
		t.Fatalf("canonical release response omitted immutable release facts: %s", recorder.Body.String())
	}
	if store.buildCalls != 1 || store.releaseCalls != 1 {
		t.Fatalf("canonical request produced unexpected side effects: builds=%d releases=%d", store.buildCalls, store.releaseCalls)
	}
}

func TestM2ReleaseInvalidRegistryIsStructuredAndHasNoReleaseSideEffect(t *testing.T) {
	store, controller := m2ReleaseHTTPRegressionFixture()
	store.record.Group.Services[0].Source = domain.ServiceSource{Kind: domain.ServicePrebuilt, Prebuilt: &domain.PrebuiltSource{Reference: "example/web:stable"}}
	server := m2ReleaseHTTPRegressionServer(store, controller)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/service-groups/"+store.record.Group.ID.String()+"/releases", strings.NewReader(`{"source_revision_id":"src_m4_http_regression","version":1,"registries":[{"endpoint":"http://example.invalid:45542"}]}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "m4-invalid-registry-1")
	recorder := httptest.NewRecorder()
	if !server.handleM2(recorder, request) {
		t.Fatal("M2 release route was not handled")
	}
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid registry status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := decodeM2ReleaseHTTPBody(t, recorder)
	if body["code"] != "invalid_registry" || strings.TrimSpace(body["message"].(string)) == "" {
		t.Fatalf("invalid registry response is not structured: %#v", body)
	}
	if store.buildCalls != 0 || store.releaseCalls != 0 {
		t.Fatalf("invalid registry created release side effects: builds=%d releases=%d", store.buildCalls, store.releaseCalls)
	}
}

func TestM2ReleaseCanonicalRegistryHostMatchCreatesOneImmutableRelease(t *testing.T) {
	store, controller := m2ReleaseHTTPRegressionFixture()
	store.record.Group.Services[0].Source = domain.ServiceSource{Kind: domain.ServicePrebuilt, Prebuilt: &domain.PrebuiltSource{Reference: "127.0.0.1:45542/open-card/web:stable"}}
	server := m2ReleaseHTTPRegressionServer(store, controller)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/service-groups/"+store.record.Group.ID.String()+"/releases", strings.NewReader(`{"source_revision_id":"src_m4_http_regression","version":1,"registries":[{"endpoint":"http://127.0.0.1:45542","secret_ref":{"id":"secret_m4_registry","name":"registry","provider":"fixture","version":"v1"}}]}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "m4-canonical-registry-match-1")
	recorder := httptest.NewRecorder()
	if !server.handleM2(recorder, request) {
		t.Fatal("M2 release route was not handled")
	}
	if recorder.Code != http.StatusCreated {
		t.Fatalf("matching registry host status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := decodeM2ReleaseHTTPBody(t, recorder)
	if body["release"] == nil || body["canonical_digest"] == nil {
		t.Fatalf("matching registry host omitted immutable release facts: %s", recorder.Body.String())
	}
	registry := controller.Registry.(*m2ReleaseHTTPRegistryFake)
	if registry.calls != 1 || registry.lastRepository != "127.0.0.1:45542/open-card/web" || store.releaseCalls != 1 || store.buildCalls != 0 {
		t.Fatalf("matching registry host produced unexpected facts: repository=%q registry=%d builds=%d releases=%d", registry.lastRepository, registry.calls, store.buildCalls, store.releaseCalls)
	}
}

func TestM2ReleaseRegistryHostMismatchIsStructuredAndSideEffectFree(t *testing.T) {
	store, controller := m2ReleaseHTTPRegressionFixture()
	store.record.Group.Services[0].Source = domain.ServiceSource{Kind: domain.ServicePrebuilt, Prebuilt: &domain.PrebuiltSource{Reference: "127.0.0.1:45532/open-card/web:stable"}}
	server := m2ReleaseHTTPRegressionServer(store, controller)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/service-groups/"+store.record.Group.ID.String()+"/releases", strings.NewReader(`{"source_revision_id":"src_m4_http_regression","version":1,"registries":[{"endpoint":"http://127.0.0.1:45542","secret_ref":{"id":"secret_m4_registry","name":"registry","provider":"fixture","version":"v1"}}]}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "m4-canonical-registry-mismatch-1")
	recorder := httptest.NewRecorder()
	if !server.handleM2(recorder, request) {
		t.Fatal("M2 release route was not handled")
	}
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("mismatched registry host status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := decodeM2ReleaseHTTPBody(t, recorder)
	registry := controller.Registry.(*m2ReleaseHTTPRegistryFake)
	// Before the handler-side authority gate, this input was rewritten to
	// 127.0.0.1:45542/127.0.0.1:45532/open-card/web and failed later in the
	// provider. The contract now rejects the mismatch before provider use.
	if registry.calls != 0 || registry.lastRepository != "" {
		t.Fatalf("mismatched registry host reached the provider: calls=%d repository=%q", registry.calls, registry.lastRepository)
	}
	code, codeOK := body["code"].(string)
	message, messageOK := body["message"].(string)
	if !codeOK || code == "" || !messageOK || strings.TrimSpace(message) == "" {
		t.Fatalf("mismatched registry host response is not structured: %#v", body)
	}
	if code != "invalid_registry" && code != string(contracts.ErrValidation) {
		t.Fatalf("mismatched registry host returned unexpected code %q: %#v", code, body)
	}
	if store.buildCalls != 0 || store.releaseCalls != 0 {
		t.Fatalf("mismatched registry host created release side effects: builds=%d releases=%d", store.buildCalls, store.releaseCalls)
	}
}

func TestM2ReleaseIncompletePersistedIdentityIsStructuredAndSideEffectFree(t *testing.T) {
	store, controller := m2ReleaseHTTPRegressionFixture()
	store.identity.ConfigDigest = ""
	server := m2ReleaseHTTPRegressionServer(store, controller)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/service-groups/"+store.record.Group.ID.String()+"/releases", strings.NewReader(`{"source_revision_id":"src_m4_http_regression","version":1}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "m4-incomplete-identity-1")
	recorder := httptest.NewRecorder()
	if !server.handleM2(recorder, request) {
		t.Fatal("M2 release route was not handled")
	}
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("incomplete identity status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := decodeM2ReleaseHTTPBody(t, recorder)
	if body["code"] != string(domain.ErrValidation) || strings.TrimSpace(body["message"].(string)) == "" {
		t.Fatalf("incomplete identity response is not structured: %#v", body)
	}
	if store.buildCalls != 0 || store.releaseCalls != 0 {
		t.Fatalf("incomplete identity created release side effects: builds=%d releases=%d", store.buildCalls, store.releaseCalls)
	}
}
