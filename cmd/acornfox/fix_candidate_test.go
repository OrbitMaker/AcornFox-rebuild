package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFixCandidateCreateReadsBoundedDiffAndUsesAuthenticatedAPI(t *testing.T) {
	var received map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != apiBase+"/apps/app_1/fix-candidates" || r.Header.Get("Idempotency-Key") != "candidate-key" || r.Header.Get("X-AcornFox-CSRF") != "csrf" {
			t.Errorf("request method=%s path=%s headers=%v", r.Method, r.URL.Path, r.Header)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, validFixCandidateResponse())
	}))
	defer server.Close()
	stateRoot := t.TempDir()
	env := func(key string) string {
		if key == "XDG_STATE_HOME" {
			return stateRoot
		}
		return ""
	}
	if err := saveState(env, sessionState{Origin: server.URL, Session: "session", CSRF: "csrf", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	diff := "diff --git a/Dockerfile b/Dockerfile\n--- a/Dockerfile\n+++ b/Dockerfile\n@@ -1 +1 @@\n-a\n+b\n"
	diffPath := filepath.Join(t.TempDir(), "candidate.diff")
	if err := os.WriteFile(diffPath, []byte(diff), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	c := &cli{in: strings.NewReader(""), out: &output, err: io.Discard, env: env, client: server.Client(), json: true}
	if err := c.fixCandidate([]string{"create", "app_1", "src_1", "--paths", "Dockerfile", "--diff", diffPath, "--port", "8080", "--idempotency-key", "candidate-key"}); err != nil {
		t.Fatal(err)
	}
	if received["base_source_revision_id"] != "src_1" || received["unified_diff"] != diff || received["container_port"] != float64(8080) || !strings.Contains(output.String(), `"candidate_id":"candidate_0123456789abcdef0123456789abcdef"`) {
		t.Fatalf("received=%v output=%s", received, output.String())
	}
}

func TestFixCandidateDecoderAcceptsLifecycleAndBoundedList(t *testing.T) {
	pending := `{"candidate_id":"candidate_0123456789abcdef0123456789abcdef","application_id":"app_1","base_source_revision_id":"src_1","status":"preparing","created_at":"2026-09-08T00:00:00Z"}`
	if _, err := decodeResponse(strings.NewReader(pending), shapeFixCandidate); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeResponse(strings.NewReader(`{"items":[`+pending+`]}`), shapeFixCandidateList); err != nil {
		t.Fatal(err)
	}
	withEvidence := strings.TrimSuffix(pending, "}") + `,"validated_image":{"repository":"x","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`
	if _, err := decodeResponse(strings.NewReader(withEvidence), shapeFixCandidate); err == nil {
		t.Fatal("preparing candidate with validation evidence was accepted")
	}
}

func TestFixCandidateListUsesOwnerScopedCollection(t *testing.T) {
	pending := `{"candidate_id":"candidate_0123456789abcdef0123456789abcdef","application_id":"app_1","base_source_revision_id":"src_1","status":"preparing","created_at":"2026-09-08T00:00:00Z"}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != apiBase+"/apps/app_1/fix-candidates" || r.URL.RawQuery != "" {
			t.Errorf("request method=%s path=%s query=%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		_, _ = io.WriteString(w, `{"items":[`+pending+`]}`)
	}))
	defer server.Close()
	stateRoot := t.TempDir()
	env := func(key string) string {
		if key == "XDG_STATE_HOME" {
			return stateRoot
		}
		return ""
	}
	if err := saveState(env, sessionState{Origin: server.URL, Session: "session", CSRF: "csrf", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	c := &cli{in: strings.NewReader(""), out: &output, err: io.Discard, env: env, client: server.Client(), json: true}
	if err := c.fixCandidate([]string{"list", "app_1"}); err != nil || !strings.Contains(output.String(), `"status":"preparing"`) {
		t.Fatalf("output=%s err=%v", output.String(), err)
	}
}

func TestFixCandidateDecoderRejectsMissingCleanupEvidence(t *testing.T) {
	bad := strings.Replace(validFixCandidateResponse(), `"cleanup_confirmed":true`, `"cleanup_confirmed":false`, 1)
	if _, err := decodeResponse(strings.NewReader(bad), shapeFixCandidate); err == nil {
		t.Fatal("candidate without confirmed cleanup was accepted")
	}
}

func validFixCandidateResponse() string {
	return `{"candidate_id":"candidate_0123456789abcdef0123456789abcdef","application_id":"app_1","base_source_revision_id":"src_1","base_repository_url":"https://github.com/OrbitMaker/acornfox.git","base_commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","base_tree_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","patch_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","result_tree_digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","container_port":8080,"changed_paths":["Dockerfile"],"canonical_diff":"diff\n","validated_image":{"repository":"local/candidate","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"build_log_ref":"log","build_evidence_digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444","runtime":{"task_id":"task_candidate","image":{"repository":"local/candidate","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"runtime_state":"stopped","probe_outcome":"responded","cleanup_confirmed":true,"evidence_digest":"sha256:5555555555555555555555555555555555555555555555555555555555555555"},"status":"validated","created_at":"2026-09-08T00:00:00Z","expires_at":"2026-09-08T01:00:00Z"}`
}
