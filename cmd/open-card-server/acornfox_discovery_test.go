package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type acornFoxDiscoveryFixture struct {
	sources      postgres.AcornFoxSourceRevisionPage
	deliveries   postgres.AcornFoxDeploymentPage
	lastSource   *postgres.AcornFoxDiscoveryCursor
	lastDelivery *postgres.AcornFoxDiscoveryCursor
}

func (f *acornFoxDiscoveryFixture) ListAcornFoxSourceRevisions(_ context.Context, _ domain.ID, cursor *postgres.AcornFoxDiscoveryCursor, _ int) (postgres.AcornFoxSourceRevisionPage, error) {
	f.lastSource = cursor
	return f.sources, nil
}
func (f *acornFoxDiscoveryFixture) ListAcornFoxDeployments(_ context.Context, _ domain.ID, cursor *postgres.AcornFoxDiscoveryCursor, _ int) (postgres.AcornFoxDeploymentPage, error) {
	f.lastDelivery = cursor
	return f.deliveries, nil
}

func TestAcornFoxDiscoveryListsUseScopedRestartStableCursorsAndNeverLeakSourceTopology(t *testing.T) {
	now := time.Unix(1_700_000_000, 123).UTC()
	source := domain.SourceRevision{ID: "src_1", ApplicationID: "app_1", Kind: domain.SourceGitHTTPS, Locator: "https://github.com/acme/example.git", Ref: "main", Commit: strings.Repeat("a", 40), ContentDigest: "sha256:" + strings.Repeat("b", 64), WorkspaceRef: "/private/workspace/src_1", CreatedAt: now, Immutable: true}
	deployment := domain.Deployment{ID: "dep_1", ApplicationID: "app_1", EnvironmentID: "env_1", ReleaseID: "rel_1", Status: domain.DeploymentDeploying, CreatedAt: now, UpdatedAt: now}
	fixture := &acornFoxDiscoveryFixture{sources: postgres.AcornFoxSourceRevisionPage{Items: []domain.SourceRevision{source}, NextCursor: &postgres.AcornFoxDiscoveryCursor{CreatedAt: now, ID: source.ID}}, deliveries: postgres.AcornFoxDeploymentPage{Items: []domain.Deployment{deployment}, NextCursor: &postgres.AcornFoxDiscoveryCursor{CreatedAt: now, ID: deployment.ID}}}
	var key [32]byte
	copy(key[:], "a stable derived discovery key")
	server := NewAcornFoxServer()
	server.SetAcornFoxDiscovery(newAcornFoxDiscoveryHTTPHandler(fixture, key))
	_, session, _ := attachTestAcornFoxAdministratorTokens(t, server, &now)

	sources := acornFoxDiscoveryRequest(t, server, session, http.MethodGet, "/api/v1/acornfox/apps/app_1/sources?limit=1")
	if sources.Code != http.StatusOK || strings.Contains(sources.Body.String(), source.Locator) || strings.Contains(sources.Body.String(), source.WorkspaceRef) {
		t.Fatalf("source list status/body=%d/%s", sources.Code, sources.Body.String())
	}
	var sourceBody struct {
		Items      []map[string]any `json:"items"`
		NextCursor string           `json:"next_cursor"`
	}
	if err := json.Unmarshal(sources.Body.Bytes(), &sourceBody); err != nil || len(sourceBody.Items) != 1 || sourceBody.NextCursor == "" || sourceBody.Items[0]["locator_sha256"] == source.Locator {
		t.Fatalf("source body=%s err=%v", sources.Body.String(), err)
	}

	// A reconstructed handler using the same derived key accepts the prior
	// cursor; no process-memory pagination state participates in validation.
	restarted := NewAcornFoxServer()
	restarted.SetAcornFoxDiscovery(newAcornFoxDiscoveryHTTPHandler(fixture, key))
	_, restartedSession, _ := attachTestAcornFoxAdministratorTokens(t, restarted, &now)
	accepted := acornFoxDiscoveryRequest(t, restarted, restartedSession, http.MethodGet, "/api/v1/acornfox/apps/app_1/sources?cursor="+sourceBody.NextCursor)
	if accepted.Code != http.StatusOK || fixture.lastSource == nil || fixture.lastSource.ID != source.ID {
		t.Fatalf("restart cursor status/cursor=%d/%#v", accepted.Code, fixture.lastSource)
	}
	for _, path := range []string{
		"/api/v1/acornfox/apps/app_other/sources?cursor=" + sourceBody.NextCursor,
		"/api/v1/acornfox/apps/app_1/deliveries?cursor=" + sourceBody.NextCursor,
		"/api/v1/acornfox/apps/app_1/sources?cursor=" + sourceBody.NextCursor[:len(sourceBody.NextCursor)-1] + "x",
	} {
		response := acornFoxDiscoveryRequest(t, restarted, restartedSession, http.MethodGet, path)
		if response.Code != http.StatusUnprocessableEntity {
			t.Fatalf("scoped cursor %q status=%d body=%s", path, response.Code, response.Body.String())
		}
	}

	deliveries := acornFoxDiscoveryRequest(t, restarted, restartedSession, http.MethodGet, "/api/v1/acornfox/apps/app_1/deliveries?limit=1")
	if deliveries.Code != http.StatusOK || strings.Contains(deliveries.Body.String(), "rolling") || strings.Contains(deliveries.Body.String(), "service_group") {
		t.Fatalf("delivery list status/body=%d/%s", deliveries.Code, deliveries.Body.String())
	}
}

func TestAcornFoxDiscoveryRejectsInvalidQueriesAndIsReadOnly(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	server := NewAcornFoxServer()
	server.SetAcornFoxDiscovery(newAcornFoxDiscoveryHTTPHandler(&acornFoxDiscoveryFixture{}, [32]byte{1}))
	_, session, csrf := attachTestAcornFoxAdministratorTokens(t, server, &now)
	for _, path := range []string{
		"/api/v1/acornfox/apps/app_1/sources?limit=0",
		"/api/v1/acornfox/apps/app_1/sources?limit=101",
		"/api/v1/acornfox/apps/app_1/sources?unknown=1",
		"/api/v1/acornfox/apps/app_1/deliveries?cursor=not-a-cursor",
	} {
		response := acornFoxDiscoveryRequest(t, server, session, http.MethodGet, path)
		if response.Code != http.StatusUnprocessableEntity {
			t.Fatalf("%s status=%d", path, response.Code)
		}
	}
	request := httptest.NewRequest(http.MethodPut, "/api/v1/acornfox/apps/app_1/sources", nil)
	request.AddCookie(session)
	addAcornFoxWriteProof(request, csrf)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, POST, OPTIONS" {
		t.Fatalf("method status/allow=%d/%q", response.Code, response.Header().Get("Allow"))
	}
}

func acornFoxDiscoveryRequest(t *testing.T, server *Server, session *http.Cookie, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, nil)
	request.AddCookie(session)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

var _ acornFoxDiscoveryReader = (*acornFoxDiscoveryFixture)(nil)

func TestAcornFoxUploadSourceDiscovery(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	base := domain.SourceRevision{ID: "src_upload", ApplicationID: "app_1", Kind: domain.SourceUpload, Locator: "upload://upload_1", Ref: "upload_1", ContentDigest: "sha256:" + strings.Repeat("b", 64), WorkspaceRef: "/private/workspace/src_upload", CreatedAt: now, Immutable: true}
	cases := []struct {
		name   string
		change func(*domain.SourceRevision)
		want   int
	}{
		{"claimed upload", func(*domain.SourceRevision) {}, http.StatusOK},
		{"locator mismatch", func(s *domain.SourceRevision) { s.Locator = "upload://other" }, http.StatusServiceUnavailable},
		{"empty reference", func(s *domain.SourceRevision) { s.Ref = ""; s.Locator = "upload://" }, http.StatusServiceUnavailable},
		{"commit forbidden", func(s *domain.SourceRevision) { s.Commit = strings.Repeat("a", 40) }, http.StatusServiceUnavailable},
		{"mutable forbidden", func(s *domain.SourceRevision) { s.Immutable = false }, http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := base
			tc.change(&source)
			fixture := &acornFoxDiscoveryFixture{sources: postgres.AcornFoxSourceRevisionPage{Items: []domain.SourceRevision{source}}}
			server := NewAcornFoxServer()
			server.SetAcornFoxDiscovery(newAcornFoxDiscoveryHTTPHandler(fixture, [32]byte{1}))
			_, session, _ := attachTestAcornFoxAdministratorTokens(t, server, &now)
			response := acornFoxDiscoveryRequest(t, server, session, http.MethodGet, "/api/v1/acornfox/apps/app_1/sources")
			if response.Code != tc.want {
				t.Fatalf("status=%d expected=%d body=%s", response.Code, tc.want, response.Body.String())
			}
			if strings.Contains(response.Body.String(), source.Locator) || strings.Contains(response.Body.String(), source.WorkspaceRef) {
				t.Fatal("source topology leaked")
			}
			if tc.want == http.StatusOK {
				var body struct {
					Items []struct {
						Kind        string `json:"kind"`
						LocatorHash string `json:"locator_sha256"`
					} `json:"items"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || len(body.Items) != 1 || body.Items[0].Kind != "upload" || body.Items[0].LocatorHash == "" {
					t.Fatalf("invalid redacted source response: %s", response.Body.String())
				}
			}
		})
	}
}
