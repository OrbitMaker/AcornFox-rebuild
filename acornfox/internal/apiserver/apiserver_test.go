package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/acornfox/acornfox/internal/state"
)

func newTestServer(t *testing.T) (http.Handler, *fakeStore, *fakeKicker, *fakeRunner, string) {
	t.Helper()
	dir := t.TempDir()
	st := newFakeStore()
	k := &fakeKicker{}
	rn := newFakeRunner()
	h := New(Config{
		Store:      st,
		Kicker:     k,
		Runner:     rn,
		UploadDir:  dir,
		PublicHost: "192.168.1.10",
	})
	return h, st, k, rn, dir
}

func do(t *testing.T, h http.Handler, method, target string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, target, r)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestUploadHappyPath(t *testing.T) {
	h, st, k, _, dir := newTestServer(t)
	w := do(t, h, "POST", "/v1/apps/myapp/deployments", []byte("tarball-bytes"), nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", w.Code, w.Body.String())
	}
	var dep state.Deployment
	if err := json.Unmarshal(w.Body.Bytes(), &dep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dep.Status != state.StatusQueued {
		t.Fatalf("status = %q, want queued", dep.Status)
	}
	// File renamed to <id>.tar.gz.
	final := filepath.Join(dir, dep.ID+".tar.gz")
	if _, err := os.Stat(final); err != nil {
		t.Fatalf("final upload not found: %v", err)
	}
	// Mode 0640.
	info, _ := os.Stat(final)
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, want 0640", info.Mode().Perm())
	}
	// SourceRef points to the final file.
	got, _ := st.GetDeployment(context.Background(), dep.ID)
	if got.SourceRef != final {
		t.Fatalf("SourceRef = %q, want %q", got.SourceRef, final)
	}
	if len(k.kicks) != 1 || k.kicks[0] != "myapp" {
		t.Fatalf("kicks = %v, want [myapp]", k.kicks)
	}
	// No leftover *.part temp files.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".part") {
			t.Fatalf("leftover temp file %s", e.Name())
		}
	}
}

func TestUploadDuplicateByKey(t *testing.T) {
	h, _, _, _, _ := newTestServer(t)
	hdr := map[string]string{"Idempotency-Key": "abc123"}
	w1 := do(t, h, "POST", "/v1/apps/myapp/deployments", []byte("v1"), hdr)
	if w1.Code != http.StatusAccepted {
		t.Fatalf("first status = %d, want 202", w1.Code)
	}
	var d1 state.Deployment
	_ = json.Unmarshal(w1.Body.Bytes(), &d1)

	w2 := do(t, h, "POST", "/v1/apps/myapp/deployments", []byte("v2-different"), hdr)
	if w2.Code != http.StatusOK {
		t.Fatalf("dup status = %d, want 200; body=%s", w2.Code, w2.Body.String())
	}
	var d2 state.Deployment
	_ = json.Unmarshal(w2.Body.Bytes(), &d2)
	if d1.ID != d2.ID {
		t.Fatalf("dup returned new id %s (orig %s)", d2.ID, d1.ID)
	}
}

func TestUploadDuplicateByDigest(t *testing.T) {
	h, _, _, _, _ := newTestServer(t)
	same := []byte("identical-content")
	w1 := do(t, h, "POST", "/v1/apps/myapp/deployments", same, nil)
	var d1 state.Deployment
	_ = json.Unmarshal(w1.Body.Bytes(), &d1)

	w2 := do(t, h, "POST", "/v1/apps/myapp/deployments", same, nil)
	if w2.Code != http.StatusOK {
		t.Fatalf("dup-by-digest status = %d, want 200; body=%s", w2.Code, w2.Body.String())
	}
	var d2 state.Deployment
	_ = json.Unmarshal(w2.Body.Bytes(), &d2)
	if d1.ID != d2.ID {
		t.Fatalf("dup returned new id %s (orig %s)", d2.ID, d1.ID)
	}
}

func TestUploadSizeLimit(t *testing.T) {
	dir := t.TempDir()
	st := newFakeStore()
	h := New(Config{
		Store: st, Kicker: &fakeKicker{}, Runner: newFakeRunner(),
		UploadDir: dir, PublicHost: "h", MaxUploadBytes: 16,
	})
	w := do(t, h, "POST", "/v1/apps/myapp/deployments", bytes.Repeat([]byte("x"), 100), nil)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", w.Code, w.Body.String())
	}
	// No temp file left behind.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("temp files left after 413: %v", entries)
	}
}

func TestUploadBadAppName(t *testing.T) {
	h, _, _, _, _ := newTestServer(t)
	w := do(t, h, "POST", "/v1/apps/Bad_Name/deployments", []byte("x"), nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	var eb errorBody
	_ = json.Unmarshal(w.Body.Bytes(), &eb)
	if eb.Error.Code != "invalid_app" {
		t.Fatalf("code = %q, want invalid_app", eb.Error.Code)
	}
}

func TestSecretNeverInResponse(t *testing.T) {
	h, _, _, _, _ := newTestServer(t)
	// Create app.
	do(t, h, "POST", "/v1/apps/myapp/deployments", []byte("x"), nil)

	// Set a secret env var.
	secretVal := "S3CR3T-TOPSECRET-VALUE"
	body, _ := json.Marshal(envRequest{Value: secretVal, Secret: true})
	wPut := do(t, h, "PUT", "/v1/apps/myapp/env/API_KEY", body, nil)
	if wPut.Code != http.StatusOK {
		t.Fatalf("put env status = %d; body=%s", wPut.Code, wPut.Body.String())
	}
	if strings.Contains(wPut.Body.String(), secretVal) {
		t.Fatalf("secret leaked in PUT response: %s", wPut.Body.String())
	}

	// Set a non-secret env var.
	body2, _ := json.Marshal(envRequest{Value: "public-value", Secret: false})
	do(t, h, "PUT", "/v1/apps/myapp/env/PUBLIC", body2, nil)

	// Get app detail.
	wGet := do(t, h, "GET", "/v1/apps/myapp", nil, nil)
	if strings.Contains(wGet.Body.String(), secretVal) {
		t.Fatalf("secret leaked in app detail: %s", wGet.Body.String())
	}
	if !strings.Contains(wGet.Body.String(), "public-value") {
		t.Fatalf("non-secret value missing from detail: %s", wGet.Body.String())
	}
	// List apps must also not leak.
	wList := do(t, h, "GET", "/v1/apps", nil, nil)
	if strings.Contains(wList.Body.String(), secretVal) {
		t.Fatalf("secret leaked in app list: %s", wList.Body.String())
	}
	// URL present.
	if !strings.Contains(wGet.Body.String(), "http://192.168.1.10:") {
		t.Fatalf("URL missing from detail: %s", wGet.Body.String())
	}
}

func TestRollbackNoTarget(t *testing.T) {
	h, _, _, _, _ := newTestServer(t)
	do(t, h, "POST", "/v1/apps/myapp/deployments", []byte("x"), nil)
	w := do(t, h, "POST", "/v1/apps/myapp/rollback", nil, nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	var eb errorBody
	_ = json.Unmarshal(w.Body.Bytes(), &eb)
	if eb.Error.Code != "no_rollback_target" {
		t.Fatalf("code = %q, want no_rollback_target", eb.Error.Code)
	}
}

func TestRollbackSuccess(t *testing.T) {
	h, st, k, _, _ := newTestServer(t)
	ctx := context.Background()
	st.EnsureApp(ctx, "myapp")
	// Seed a retired deployment with an image.
	d, _, _ := st.CreateDeployment(ctx, state.NewDeployment{App: "myapp", SourceKind: state.SourceUpload, SourceRef: "/x", SourceDigest: "deadbeef"})
	st.UpdateDeployment(ctx, d.ID, func(dep *state.Deployment) error {
		dep.Status = state.StatusRetired
		dep.ImageID = "sha256:image123"
		return nil
	})

	before := len(k.kicks)
	w := do(t, h, "POST", "/v1/apps/myapp/rollback", nil, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", w.Code, w.Body.String())
	}
	var newDep state.Deployment
	_ = json.Unmarshal(w.Body.Bytes(), &newDep)
	if newDep.SourceKind != state.SourceImage {
		t.Fatalf("source_kind = %q, want image", newDep.SourceKind)
	}
	if newDep.SourceRef != "sha256:image123" {
		t.Fatalf("source_ref = %q, want image id", newDep.SourceRef)
	}
	if len(k.kicks) != before+1 {
		t.Fatalf("rollback did not kick")
	}
}

func TestValidateListen(t *testing.T) {
	good := []string{
		"127.0.0.1:18800",
		"localhost:18800",
		"[::1]:18800",
		"unix:/run/acornfox/api.sock",
		"/run/acornfox/api.sock",
	}
	for _, addr := range good {
		if err := ValidateListen(addr); err != nil {
			t.Errorf("ValidateListen(%q) = %v, want nil", addr, err)
		}
	}
	bad := []string{
		"",
		"0.0.0.0:18800",
		"192.168.1.10:18800",
		":18800",
		"unix:relative.sock",
		"host-without-port",
		"example.com:80",
	}
	for _, addr := range bad {
		if err := ValidateListen(addr); err == nil {
			t.Errorf("ValidateListen(%q) = nil, want error", addr)
		}
	}
}

func TestStatusHasAPIVersion(t *testing.T) {
	h, _, _, _, _ := newTestServer(t)
	w := do(t, h, "GET", "/v1/status", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var body struct {
		APIVersion int `json:"api_version"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.APIVersion != 1 {
		t.Fatalf("api_version = %d, want 1", body.APIVersion)
	}
}

func TestDeployImageJSON(t *testing.T) {
	h, st, k, _, _ := newTestServer(t)
	body := []byte(`{"image":"nginx:1.27-alpine"}`)
	w := do(t, h, "POST", "/v1/apps/web/deployments", body, map[string]string{"Content-Type": "application/json"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", w.Code, w.Body.String())
	}
	var dep state.Deployment
	_ = json.Unmarshal(w.Body.Bytes(), &dep)
	if dep.SourceKind != state.SourceImage || dep.SourceRef != "nginx:1.27-alpine" {
		t.Fatalf("unexpected deployment: %+v", dep)
	}
	got, _ := st.GetDeployment(context.Background(), dep.ID)
	if got.SourceKind != state.SourceImage {
		t.Fatalf("stored source kind = %q", got.SourceKind)
	}
	if len(k.kicks) != 1 {
		t.Fatalf("expected a kick")
	}
}

func TestDeployImageJSONIdempotencyKey(t *testing.T) {
	h, _, _, _, _ := newTestServer(t)
	hdr := map[string]string{"Content-Type": "application/json", "Idempotency-Key": "k1"}
	w1 := do(t, h, "POST", "/v1/apps/web/deployments", []byte(`{"image":"nginx:1.27-alpine"}`), hdr)
	var d1 state.Deployment
	_ = json.Unmarshal(w1.Body.Bytes(), &d1)
	w2 := do(t, h, "POST", "/v1/apps/web/deployments", []byte(`{"image":"other:latest"}`), hdr)
	if w2.Code != http.StatusOK {
		t.Fatalf("dup status = %d, want 200", w2.Code)
	}
	var d2 state.Deployment
	_ = json.Unmarshal(w2.Body.Bytes(), &d2)
	if d1.ID != d2.ID {
		t.Fatalf("idempotency key did not dedupe: %s vs %s", d1.ID, d2.ID)
	}
}

func TestDeployGitJSON(t *testing.T) {
	h, _, _, _, _ := newTestServer(t)
	body := []byte(`{"git":"https://github.com/acme/app.git","ref":"main"}`)
	w := do(t, h, "POST", "/v1/apps/web/deployments", body, map[string]string{"Content-Type": "application/json"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", w.Code, w.Body.String())
	}
	var dep state.Deployment
	_ = json.Unmarshal(w.Body.Bytes(), &dep)
	if dep.SourceKind != state.SourceGit {
		t.Fatalf("source_kind = %q, want git", dep.SourceKind)
	}
	if dep.SourceRef != "https://github.com/acme/app.git#main" {
		t.Fatalf("source_ref = %q", dep.SourceRef)
	}
}

func TestDeployGitRejectsNonHTTPS(t *testing.T) {
	h, _, _, _, _ := newTestServer(t)
	cases := []string{
		`{"git":"http://github.com/acme/app.git"}`,
		`{"git":"git@github.com:acme/app.git"}`,
		`{"git":"https://user:pass@github.com/acme/app.git"}`,
	}
	for _, c := range cases {
		w := do(t, h, "POST", "/v1/apps/web/deployments", []byte(c), map[string]string{"Content-Type": "application/json"})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("git %s: status = %d, want 400", c, w.Code)
		}
	}
}

func TestDeployJSONRejectsBothOrNeither(t *testing.T) {
	h, _, _, _, _ := newTestServer(t)
	for _, c := range []string{`{}`, `{"image":"a","git":"https://x/y.git"}`} {
		w := do(t, h, "POST", "/v1/apps/web/deployments", []byte(c), map[string]string{"Content-Type": "application/json"})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400", c, w.Code)
		}
	}
}

func TestDeployImageRejectsBadDigest(t *testing.T) {
	h, _, _, _, _ := newTestServer(t)
	w := do(t, h, "POST", "/v1/apps/web/deployments", []byte(`{"image":"nginx@sha256:short"}`), map[string]string{"Content-Type": "application/json"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestPatchAppBounds(t *testing.T) {
	h, st, _, _, _ := newTestServer(t)
	ctx := context.Background()
	st.EnsureApp(ctx, "web")

	// Valid update.
	body := []byte(`{"memory_mb":1024,"cpu_milli":2000,"port":3000,"health_path":"/healthz"}`)
	w := do(t, h, "PATCH", "/v1/apps/web", body, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	a, _ := st.GetApp(ctx, "web")
	if a.MemoryMB != 1024 || a.CPUMilli != 2000 || a.Port != 3000 || a.HealthPath != "/healthz" {
		t.Fatalf("patch not applied: %+v", a)
	}

	// Out-of-bounds memory rejected and unchanged.
	w = do(t, h, "PATCH", "/v1/apps/web", []byte(`{"memory_mb":32}`), nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("low memory status = %d, want 400", w.Code)
	}
	w = do(t, h, "PATCH", "/v1/apps/web", []byte(`{"memory_mb":99999}`), nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("high memory status = %d, want 400", w.Code)
	}
	w = do(t, h, "PATCH", "/v1/apps/web", []byte(`{"cpu_milli":50}`), nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("low cpu status = %d, want 400", w.Code)
	}
	a2, _ := st.GetApp(ctx, "web")
	if a2.MemoryMB != 1024 || a2.CPUMilli != 2000 {
		t.Fatalf("rejected patch changed state: %+v", a2)
	}
}

func TestAppLogsNoLiveDeployment(t *testing.T) {
	h, st, _, _, _ := newTestServer(t)
	st.EnsureApp(context.Background(), "web")
	w := do(t, h, "GET", "/v1/apps/web/logs", nil, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	var eb errorBody
	_ = json.Unmarshal(w.Body.Bytes(), &eb)
	if eb.Error.Code != "no_live_deployment" {
		t.Fatalf("code = %q, want no_live_deployment", eb.Error.Code)
	}
}

func TestAppLogsRedactsSecrets(t *testing.T) {
	h, st, _, rn, _ := newTestServer(t)
	ctx := context.Background()
	st.EnsureApp(ctx, "web")
	// Mark a live deployment.
	d, _, _ := st.CreateDeployment(ctx, state.NewDeployment{App: "web", SourceKind: state.SourceUpload, SourceRef: "/x", SourceDigest: "dd"})
	st.UpdateApp(ctx, "web", func(a *state.App) error { a.CurrentDeployment = d.ID; return nil })
	// A secret env var whose value appears in the logs.
	secret := "TOPSECRETVALUE123"
	st.SetEnv(ctx, state.EnvVar{App: "web", Key: "API_KEY", Value: secret, Secret: true})

	name := "af-web-" + d.ID
	rn.logLines[name] = []string{"starting with key " + secret, "public line ok"}

	w := do(t, h, "GET", "/v1/apps/web/logs?tail=50", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), secret) {
		t.Fatalf("secret leaked in logs: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "******") {
		t.Fatalf("expected redaction mask: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "public line ok") {
		t.Fatalf("non-secret line missing: %s", w.Body.String())
	}
}

func TestAppLogsTailBounds(t *testing.T) {
	h, st, _, rn, _ := newTestServer(t)
	ctx := context.Background()
	st.EnsureApp(ctx, "web")
	d, _, _ := st.CreateDeployment(ctx, state.NewDeployment{App: "web", SourceKind: state.SourceUpload, SourceRef: "/x", SourceDigest: "dd"})
	st.UpdateApp(ctx, "web", func(a *state.App) error { a.CurrentDeployment = d.ID; return nil })
	rn.logLines["af-web-"+d.ID] = []string{"a", "b"}

	// Invalid tail rejected.
	w := do(t, h, "GET", "/v1/apps/web/logs?tail=0", nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("tail=0 status = %d, want 400", w.Code)
	}
	// Large tail clamped, still 200.
	w = do(t, h, "GET", "/v1/apps/web/logs?tail=99999", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("tail=99999 status = %d, want 200", w.Code)
	}
}
