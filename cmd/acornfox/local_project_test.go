package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func localProjectFixture(t *testing.T, withDockerfile bool) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("PASSWORD=SHOULD_NOT_UPLOAD"), 0600); err != nil {
		t.Fatal(err)
	}
	if withDockerfile {
		if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM scratch\nEXPOSE 8080\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
func localPlanFixture(source string) map[string]any {
	return map[string]any{"application_id": "app", "source_revision_id": source, "source_type": "upload", "repository_url": "", "ref": "upload_1", "commit": "", "dockerfile": map[string]any{"status": "ready", "path": "Dockerfile", "stage_count": 1, "digest": "sha256:" + strings.Repeat("d", 64)}, "ports": []any{map[string]any{"port": 8080, "protocol": "tcp", "source": "dockerfile_expose"}}, "port_selection": map[string]any{"status": "selected", "reason": "single", "selected_port": 8080, "candidates": []int{8080}}, "healthcheck": map[string]bool{"present": false}, "environment": []any{}, "gaps": []string{}, "warnings": []string{}, "required_actions": []string{}, "ready_to_deploy": true}
}
func localUploadFixture() map[string]any {
	return map[string]any{"id": "upload_1", "kind": "archive", "status": "ready", "digest": "sha256:" + strings.Repeat("a", 64), "bytes": 32, "file_count": 2, "expires_at": "2030-01-01T00:00:00Z"}
}
func TestLocalProjectCheckReportsMissingConfigurationAndExcludesCredentials(t *testing.T) {
	project := localProjectFixture(t, false)
	var out bytes.Buffer
	code := run([]string{"check", project, "--json"}, strings.NewReader(""), &out, io.Discard, func(string) string { return "" })
	if code != 2 || strings.Contains(out.String(), "SHOULD_NOT_UPLOAD") {
		t.Fatalf("unsafe or misleading check: %d %s", code, out.String())
	}
	var result struct {
		Status   string   `json:"status"`
		Files    int      `json:"files"`
		Excluded []string `json:"excluded_paths"`
	}
	if json.Unmarshal(out.Bytes(), &result) != nil || result.Status != "configuration_required" || result.Files != 1 || len(result.Excluded) != 1 || result.Excluded[0] != ".env" {
		t.Fatal(out.String())
	}
	outside := filepath.Join(t.TempDir(), "outside")
	_ = os.WriteFile(outside, []byte("private"), 0600)
	if err := os.Symlink(outside, filepath.Join(project, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectLocalProject(project); err == nil {
		t.Fatal("nested symlink accepted")
	}
}
func TestLocalUpUploadsSelectedFilesAndPreservesApplicationIdentity(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "existing"}[existing], func(t *testing.T) {
			project := localProjectFixture(t, true)
			runtimeFile := filepath.Join(t.TempDir(), "runtime.json")
			if err := os.WriteFile(runtimeFile, []byte(`{"command":["serve"],"environment":[{"name":"MODE","value":"development"}]}`), 0600); err != nil {
				t.Fatal(err)
			}
			created, updated, delivered := 0, 0, 0
			sourceID := "src"
			if existing {
				sourceID = "src_next"
			}
			app := map[string]any{"id": "app", "name": "local", "created_at": "2030-01-01T00:00:00Z", "updated_at": "2030-01-01T00:00:00Z"}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if cookieRequest(r, "__Host-acornfox_session") != "session" {
					t.Error("session absent")
				}
				respond := func(status int, value any) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(status)
					_ = json.NewEncoder(w).Encode(value)
				}
				switch {
				case r.URL.Path == apiBase+"/source-uploads":
					if r.Header.Get("X-AcornFox-CSRF") != "csrf" || r.Header.Get("Idempotency-Key") != "local-flow:upload" {
						t.Error("upload write proof missing")
					}
					if err := r.ParseMultipartForm(2 << 20); err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					defer r.MultipartForm.RemoveAll()
					file, _, err := r.FormFile("archive")
					if err != nil {
						t.Error(err)
						return
					}
					defer file.Close()
					z, err := gzip.NewReader(file)
					if err != nil {
						t.Error(err)
						return
					}
					defer z.Close()
					archive := tar.NewReader(z)
					names := []string{}
					for {
						header, err := archive.Next()
						if err == io.EOF {
							break
						}
						if err != nil {
							t.Error(err)
							break
						}
						names = append(names, header.Name)
						payload, _ := io.ReadAll(archive)
						if strings.Contains(string(payload), "SHOULD_NOT_UPLOAD") {
							t.Error("credential file uploaded")
						}
					}
					if strings.Join(names, ",") != "Dockerfile,index.html" || r.FormValue("mode") != "archive" {
						t.Errorf("archive files=%v", names)
					}
					respond(201, localUploadFixture())
				case r.URL.Path == apiBase+"/apps" && r.Method == http.MethodPost:
					created++
					var input map[string]any
					_ = json.NewDecoder(r.Body).Decode(&input)
					src, _ := input["source"].(map[string]any)
					if src["type"] != "upload" || src["upload_id"] != "upload_1" {
						t.Error("wrong upload source")
					}
					respond(201, map[string]any{"application": app, "source_revision_id": sourceID, "operation_id": "op_create"})
				case r.URL.Path == apiBase+"/apps/app" && r.Method == http.MethodGet:
					respond(200, app)
				case r.URL.Path == apiBase+"/apps/app/sources" && r.Method == http.MethodPost:
					updated++
					var body map[string]string
					_ = json.NewDecoder(r.Body).Decode(&body)
					if body["base_source_revision_id"] != "base" || body["upload_id"] != "upload_1" || len(body) != 2 {
						t.Error("wrong local update source")
					}
					respond(201, map[string]string{"source_revision_id": sourceID, "status": "imported"})
				case strings.HasSuffix(r.URL.Path, "/deployment-plan"):
					respond(200, localPlanFixture(sourceID))
				case r.URL.Path == apiBase+"/apps/app/deliveries":
					delivered++
					var body map[string]any
					_ = json.NewDecoder(r.Body).Decode(&body)
					runtime, _ := body["runtime"].(map[string]any)
					if body["source_revision_id"] != sourceID || body["container_port"] != float64(8080) || runtime == nil {
						t.Error("runtime input lost")
					}
					respond(202, map[string]string{"deployment_id": "dep", "operation_id": "op", "task_id": "task", "status": "accepted"})
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					w.WriteHeader(404)
				}
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
			var out bytes.Buffer
			c := &cli{in: strings.NewReader(""), out: &out, err: io.Discard, env: env, client: server.Client(), json: true}
			args := []string{"up", project, "--name", "local", "--runtime-file", runtimeFile, "--idempotency-key", "local-flow"}
			if existing {
				args = append(args, "--app", "app", "--base-source", "base")
			}
			if err := c.command(args); err != nil {
				t.Fatal(err)
			}
			if delivered != 1 || existing && (created != 0 || updated != 1) || !existing && (created != 1 || updated != 0) {
				t.Fatalf("created=%d updated=%d delivered=%d", created, updated, delivered)
			}
			var result map[string]any
			if json.Unmarshal(out.Bytes(), &result) != nil || result["accepted"] != true || result["deployed"] != false || result["source_revision_id"] != sourceID {
				t.Fatal("acceptance confused with runtime success", out.String())
			}
		})
	}
}
func TestLocalLoginIsExplicitAndLoopbackOnly(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.SetCookie(w, &http.Cookie{Name: "acornfox_local_session", Value: "local-session", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "acornfox_local_csrf", Value: "local-csrf", Path: "/"})
		_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": true, "idle_expires_at": "2030-01-01T00:00:00Z", "absolute_expires_at": "2030-01-02T00:00:00Z"})
	}))
	defer server.Close()
	stateRoot := t.TempDir()
	env := func(key string) string {
		if key == "XDG_STATE_HOME" {
			return stateRoot
		}
		return ""
	}
	c := &cli{in: strings.NewReader("test-password\n"), out: io.Discard, err: io.Discard, env: env, client: server.Client()}
	if err := c.command([]string{"login", "--server", server.URL, "--password-stdin"}); err == nil || calls != 0 {
		t.Fatal("HTTP implicitly accepted")
	}
	c.in = strings.NewReader("test-password\n")
	if err := c.command([]string{"login", "--local", "--server", server.URL, "--password-stdin"}); err != nil {
		t.Fatal(err)
	}
	state, err := loadState(env)
	if err != nil || !state.Local || state.Session != "local-session" || state.CSRF != "local-csrf" {
		t.Fatal("local session not saved", err)
	}
	if _, err := normalizeOrigin("http://192.0.2.1:8080", true); err == nil {
		t.Fatal("remote HTTP accepted")
	}
}
func TestLocalPlanDoesNotLeakUploadLocatorAndRejectsGitCommit(t *testing.T) {
	fixture := localPlanFixture("src")
	raw, _ := json.Marshal(fixture)
	if _, err := decodeResponse(bytes.NewReader(raw), shapeDeploymentPlan); err != nil {
		t.Fatal(err)
	}
	fixture["repository_url"] = "upload://private"
	raw, _ = json.Marshal(fixture)
	if _, err := decodeResponse(bytes.NewReader(raw), shapeDeploymentPlan); err == nil {
		t.Fatal("upload storage locator accepted as URL")
	}
	source := `{"id":"s","application_id":"a","kind":"upload","locator_sha256":"sha256:x","content_digest":"sha256:y","created_at":"2030-01-01T00:00:00Z","immutable":true}`
	if _, err := decodeResponse(strings.NewReader(source), shapeSource); err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(source, `"immutable":true`, `"immutable":true,"commit":"fake-git-commit"`, 1)
	if _, err := decodeResponse(strings.NewReader(bad), shapeSource); err == nil {
		t.Fatal("upload with Git commit accepted")
	}
	var reported reportedCLIResult
	if !errors.As(reportedCLIResult{2, "configuration missing"}, &reported) {
		t.Fatal("reported result did not retain exit code")
	}
}
