package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/acornfoxcandidate"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/domain"
)

type fixCandidateHTTPFixture struct {
	value   application.AcornFoxFixCandidate
	request application.AcornFoxFixCandidateCreateRequest
	read    acornfoxcandidate.ReadResult
}

func (f *fixCandidateHTTPFixture) ReadSource(context.Context, domain.ID, domain.ID, []string) (acornfoxcandidate.ReadResult, error) {
	return f.read, nil
}
func (f *fixCandidateHTTPFixture) ReadSourceForAI(context.Context, domain.ID, domain.ID, []string) (acornfoxcandidate.ReadResult, error) {
	return f.read, nil
}

func (f *fixCandidateHTTPFixture) Create(_ context.Context, request application.AcornFoxFixCandidateCreateRequest) (application.AcornFoxFixCandidate, error) {
	f.request = request
	value := f.value
	if !request.OwnerAdminID.Empty() {
		value.OwnerAdminID = request.OwnerAdminID
	}
	if !request.ApplicationID.Empty() {
		value.ApplicationID = request.ApplicationID
	}
	return value, nil
}

func (f *fixCandidateHTTPFixture) MatchSource(_ context.Context, _, _, source, _ domain.ID) (application.AcornFoxFixCandidate, error) {
	value := f.value
	value.Status, value.MatchedSourceRevisionID, value.MatchedCommit = application.AcornFoxFixCandidateSourceMatched, source, strings.Repeat("d", 40)
	return value, nil
}

func (f *fixCandidateHTTPFixture) Publish(context.Context, domain.ID, domain.ID, domain.ID, string) (application.AcornFoxDeliveryResult, error) {
	return application.AcornFoxDeliveryResult{DeploymentID: "dep_candidate", OperationID: "op_candidate", TaskID: "task_candidate", Status: "accepted"}, nil
}

func (f *fixCandidateHTTPFixture) GetAcornFoxFixCandidate(context.Context, domain.ID, domain.ID) (application.AcornFoxFixCandidate, error) {
	return f.value, nil
}
func (f *fixCandidateHTTPFixture) ListAcornFoxFixCandidates(context.Context, domain.ID, domain.ID) ([]application.AcornFoxFixCandidate, error) {
	return []application.AcornFoxFixCandidate{f.value}, nil
}

func TestAcornFoxFixCandidateHTTPBindsAdministratorAndStrictJSON(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	fixture := &fixCandidateHTTPFixture{value: fixCandidateHTTPValue(now)}
	handler := &AcornFoxFixCandidateHTTPHandler{Service: fixture, Store: fixture}
	body := `{"base_source_revision_id":"src_base","paths":["Dockerfile"],"unified_diff":"diff\\n","container_port":8080}`
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "candidate-key")
	request = withControlPlaneIdentity(request, "admin_candidate")
	response := httptest.NewRecorder()
	handler.HandleCollection(response, request, "app_candidate")
	if response.Code != http.StatusAccepted || fixture.request.OwnerAdminID != "admin_candidate" || fixture.request.ApplicationID != "app_candidate" || fixture.request.IdempotencyKey != "candidate-key" || !strings.Contains(response.Body.String(), `"canonical_diff":"diff\n"`) {
		t.Fatalf("status=%d request=%+v body=%s", response.Code, fixture.request, response.Body.String())
	}

	unknown := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.TrimSuffix(body, "}")+`,"shell":"no"}`))
	unknown.Header.Set("Content-Type", "application/json")
	unknown = withControlPlaneIdentity(unknown, "admin_candidate")
	rejected := httptest.NewRecorder()
	handler.HandleCollection(rejected, unknown, "app_candidate")
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("unknown status=%d body=%s", rejected.Code, rejected.Body.String())
	}
}

func TestAcornFoxFixCandidateHTTPReadAndSourceMatchStayOwnerScoped(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	fixture := &fixCandidateHTTPFixture{value: fixCandidateHTTPValue(now)}
	handler := &AcornFoxFixCandidateHTTPHandler{Service: fixture, Store: fixture}

	foreign := httptest.NewRequest(http.MethodGet, "/", nil)
	foreign = withControlPlaneIdentity(foreign, "admin_other")
	denied := httptest.NewRecorder()
	handler.HandleItem(denied, foreign, "app_candidate", fixture.value.ID, "")
	if denied.Code != http.StatusNotFound {
		t.Fatalf("foreign read=%d %s", denied.Code, denied.Body.String())
	}

	match := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"source_revision_id":"src_imported"}`))
	match.Header.Set("Content-Type", "application/json")
	match = withControlPlaneIdentity(match, "admin_candidate")
	matched := httptest.NewRecorder()
	handler.HandleItem(matched, match, "app_candidate", fixture.value.ID, "source-match")
	if matched.Code != http.StatusOK || !strings.Contains(matched.Body.String(), `"status":"source_matched"`) {
		t.Fatalf("match=%d %s", matched.Code, matched.Body.String())
	}
}

func TestAcornFoxFixCandidateHTTPReturnsAcceptedLifecycleAndBoundedOwnerList(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	accepted := application.AcornFoxFixCandidate{ID: "candidate_0123456789abcdef0123456789abcdef", ApplicationID: "app_candidate", BaseSourceRevisionID: "src_base", OwnerAdminID: "admin_candidate", RequestKey: "candidate-key", Status: application.AcornFoxFixCandidatePreparing, CreatedAt: now}
	fixture := &fixCandidateHTTPFixture{value: accepted}
	handler := &AcornFoxFixCandidateHTTPHandler{Service: fixture, Store: fixture}

	create := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"base_source_revision_id":"src_base","paths":["Dockerfile"],"unified_diff":"diff\n","container_port":8080}`))
	create.Header.Set("Content-Type", "application/json")
	create.Header.Set("Idempotency-Key", "candidate-key")
	create = withControlPlaneIdentity(create, "admin_candidate")
	created := httptest.NewRecorder()
	handler.HandleCollection(created, create, accepted.ApplicationID)
	if created.Code != http.StatusAccepted || strings.Contains(created.Body.String(), "validated_image") || !strings.Contains(created.Body.String(), `"status":"preparing"`) {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}

	list := withControlPlaneIdentity(httptest.NewRequest(http.MethodGet, "/", nil), "admin_candidate")
	listed := httptest.NewRecorder()
	handler.HandleCollection(listed, list, accepted.ApplicationID)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"items":[{"candidate_id":"`+accepted.ID.String()) || strings.Contains(listed.Body.String(), "validated_image") {
		t.Fatalf("list=%d %s", listed.Code, listed.Body.String())
	}
	query := withControlPlaneIdentity(httptest.NewRequest(http.MethodGet, "/?limit=1", nil), "admin_candidate")
	rejected := httptest.NewRecorder()
	handler.HandleCollection(rejected, query, accepted.ApplicationID)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("query=%d %s", rejected.Code, rejected.Body.String())
	}
}

func TestAcornFoxFixCandidateStandbyServesReadsAndRejectsExecution(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	accepted := application.AcornFoxFixCandidate{ID: "candidate_0123456789abcdef0123456789abcdef", ApplicationID: "app_candidate", BaseSourceRevisionID: "src_base", OwnerAdminID: "admin_candidate", RequestKey: "candidate-key", Status: application.AcornFoxFixCandidatePreparing, CreatedAt: now}
	fixture := &fixCandidateHTTPFixture{value: accepted}
	handler := &AcornFoxFixCandidateHTTPHandler{Store: fixture}

	list := withControlPlaneIdentity(httptest.NewRequest(http.MethodGet, "/", nil), accepted.OwnerAdminID)
	listed := httptest.NewRecorder()
	handler.HandleCollection(listed, list, accepted.ApplicationID)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), accepted.ID.String()) {
		t.Fatalf("standby list=%d %s", listed.Code, listed.Body.String())
	}
	item := withControlPlaneIdentity(httptest.NewRequest(http.MethodGet, "/", nil), accepted.OwnerAdminID)
	got := httptest.NewRecorder()
	handler.HandleItem(got, item, accepted.ApplicationID, accepted.ID, "")
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"status":"preparing"`) {
		t.Fatalf("standby item=%d %s", got.Code, got.Body.String())
	}
	post := withControlPlaneIdentity(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), accepted.OwnerAdminID)
	rejected := httptest.NewRecorder()
	handler.HandleCollection(rejected, post, accepted.ApplicationID)
	if rejected.Code != http.StatusServiceUnavailable {
		t.Fatalf("standby post=%d %s", rejected.Code, rejected.Body.String())
	}
}

func fixCandidateHTTPValue(now time.Time) application.AcornFoxFixCandidate {
	image, _ := domain.ParseImageDigest("local/candidate", "sha256:"+strings.Repeat("a", 64))
	return application.AcornFoxFixCandidate{ID: "candidate_0123456789abcdef0123456789abcdef", ApplicationID: "app_candidate", BaseSourceRevisionID: "src_base", BaseRepositoryURL: "https://github.com/OrbitMaker/acornfox.git", BaseCommit: strings.Repeat("b", 40), BaseTreeDigest: "sha256:" + strings.Repeat("1", 64), PatchDigest: "sha256:" + strings.Repeat("2", 64), ResultTreeDigest: "sha256:" + strings.Repeat("3", 64), ContainerPort: 8080, ChangedPaths: []string{"Dockerfile"}, CanonicalDiff: "diff\n", ValidatedImage: image, BuildLogRef: "log", BuildEvidenceDigest: "sha256:" + strings.Repeat("4", 64), Runtime: application.AcornFoxFixCandidateRuntimeEvidence{TaskID: "task_candidate", Image: image, RuntimeState: "stopped", ProbeOutcome: "responded", CleanupConfirmed: true, EvidenceDigest: "sha256:" + strings.Repeat("5", 64)}, OwnerAdminID: "admin_candidate", RequestKey: "candidate-key", Status: application.AcornFoxFixCandidateValidated, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
}
