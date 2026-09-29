package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/acornfoxcandidate"
	"github.com/open-card/open-card/internal/hostmetrics"
)

func TestRetiredAssistantRoutesRejectExplicitly(t *testing.T) {
	server := NewAcornFoxServer()
	now := time.Now()
	_, session, csrf := attachTestAcornFoxAdministratorTokens(t, server, &now)

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/acornfox/assistant"},
		{http.MethodGet, "/api/v1/acornfox/assistant/sessions"},
		{http.MethodPost, "/api/v1/acornfox/assistant/sessions"},
		{http.MethodPost, "/api/v1/acornfox/assistant/sessions/session-1/runs"},
		{http.MethodGet, "/api/v1/acornfox/assistant/sessions/session-1/events"},
		{http.MethodPost, "/api/v1/acornfox/assistant/sessions/session-1/abort"},
		{http.MethodGet, "/api/v1/acornfox/assistant/sessions/session-1/actions"},
		{http.MethodPost, "/api/v1/acornfox/assistant/sessions/session-1/actions/prop-1/decision"},
	}

	for _, route := range routes {
		t.Run("unauthenticated_"+route.method+"_"+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, req)
			if recorder.Code != http.StatusNotFound && recorder.Code != http.StatusGone {
				t.Fatalf("expected retired route %s %s to return 404 or 410, got %d", route.method, route.path, recorder.Code)
			}
		})

		t.Run("authenticated_"+route.method+"_"+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(session)
			addAcornFoxWriteProof(req, csrf)
			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, req)
			if recorder.Code != http.StatusNotFound && recorder.Code != http.StatusGone {
				t.Fatalf("expected retired route %s %s to return 404 or 410, got %d", route.method, route.path, recorder.Code)
			}
		})
	}
}

func TestRetiredM6AIRoutesReject(t *testing.T) {
	for _, legacyEnabled := range []bool{false, true} {
		server := NewServer()
		server.SetLegacyRoutesEnabled(legacyEnabled)
		now := time.Now()
		_, session, csrf := attachTestAdministratorTokens(t, server, &now)

		routes := []struct {
			method string
			path   string
		}{
			{http.MethodGet, "/api/v1/settings/ai"},
			{http.MethodPost, "/api/v1/settings/ai"},
			{http.MethodGet, "/api/v1/applications/app-1/ai/interventions"},
			{http.MethodPost, "/api/v1/applications/app-1/ai/interventions"},
		}

		for _, route := range routes {
			t.Run(route.method+"_"+route.path, func(t *testing.T) {
				req := httptest.NewRequest(route.method, route.path, strings.NewReader("{}"))
				req.Header.Set("Content-Type", "application/json")
				req.AddCookie(session)
				addControlPlaneWriteProof(req, csrf)
				recorder := httptest.NewRecorder()
				server.Handler().ServeHTTP(recorder, req)
				if recorder.Code != http.StatusNotFound && recorder.Code != http.StatusGone {
					t.Fatalf("expected retired M6 route %s %s (legacy=%v) to return 404 or 410, got %d", route.method, route.path, legacyEnabled, recorder.Code)
				}
			})
		}
	}
}

func TestCandidateAndPublicRoutesRemainAvailable(t *testing.T) {
	server := NewAcornFoxServer()
	now := time.Now().UTC()
	authStore, session, csrf := attachTestAcornFoxAdministratorTokens(t, server, &now)

	candValue := fixCandidateHTTPValue(now)
	candValue.OwnerAdminID = authStore.credential.ID
	candFixture := &fixCandidateHTTPFixture{
		value: candValue,
		read: acornfoxcandidate.ReadResult{
			BaseSourceRevisionID: "src_base",
			BaseCommit:           strings.Repeat("a", 40),
			BaseTreeDigest:       "sha256:" + strings.Repeat("b", 64),
			Files:                []acornfoxcandidate.SourceFile{{Path: "Dockerfile", Content: "FROM scratch\n", Digest: "sha256:" + strings.Repeat("c", 64), Bytes: 13}},
			TotalBytes:           13,
		},
	}
	server.SetAcornFoxFixCandidate(&AcornFoxFixCandidateHTTPHandler{
		Service: candFixture,
		Store:   candFixture,
	})
	server.SetAcornFoxHostMetrics(hostmetrics.NewHTTPHandler(hostmetrics.NewSampler(hostmetrics.Config{OS: "unsupported-test"})))

	// 1. Verify fix-candidate collection GET
	t.Run("fix_candidates_list", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/apps/app_candidate/fix-candidates", nil)
		req.AddCookie(session)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("fix candidate list failed: %d, body: %s", recorder.Code, recorder.Body.String())
		}
		if !strings.Contains(recorder.Body.String(), candValue.ID.String()) {
			t.Fatalf("fix candidate list does not contain candidate ID: %s", recorder.Body.String())
		}
	})

	// 2. Verify fix-candidate collection POST (create)
	t.Run("fix_candidates_create", func(t *testing.T) {
		body := `{"base_source_revision_id":"src_base","paths":["Dockerfile"],"unified_diff":"diff\n","container_port":8080}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/acornfox/apps/app_candidate/fix-candidates", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "idemp-key-1")
		req.AddCookie(session)
		addAcornFoxWriteProof(req, csrf)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusAccepted {
			t.Fatalf("fix candidate create failed: %d, body: %s", recorder.Code, recorder.Body.String())
		}
		if !strings.Contains(recorder.Body.String(), candValue.ID.String()) {
			t.Fatalf("fix candidate create response missing candidate ID: %s", recorder.Body.String())
		}
	})

	// 3. Verify fix-candidate item GET
	t.Run("fix_candidate_get", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/apps/app_candidate/fix-candidates/"+candValue.ID.String(), nil)
		req.AddCookie(session)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("fix candidate get failed: %d, body: %s", recorder.Code, recorder.Body.String())
		}
		if !strings.Contains(recorder.Body.String(), candValue.ID.String()) {
			t.Fatalf("fix candidate get response missing candidate ID: %s", recorder.Body.String())
		}
	})

	// 4. Verify fix-candidate source-match POST
	t.Run("fix_candidate_match", func(t *testing.T) {
		body := `{"source_revision_id":"src_imported"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/acornfox/apps/app_candidate/fix-candidates/"+candValue.ID.String()+"/source-match", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(session)
		addAcornFoxWriteProof(req, csrf)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("fix candidate match failed: %d, body: %s", recorder.Code, recorder.Body.String())
		}
		if !strings.Contains(recorder.Body.String(), "source_matched") {
			t.Fatalf("fix candidate match response missing source_matched status: %s", recorder.Body.String())
		}
	})

	// 5. Verify host metrics route
	t.Run("host_metrics", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/host/metrics", nil)
		req.AddCookie(session)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("host metrics failed: %d", recorder.Code)
		}
	})

	// 6. Verify auth session check
	t.Run("auth_session", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/auth/session", nil)
		req.AddCookie(session)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("auth session failed: %d", recorder.Code)
		}
	})
}
