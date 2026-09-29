package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---- fake ssh via test-binary re-exec ----
//
// The test binary re-execs itself as the "ssh" program. TestMain inspects the
// FAKE_SSH_MODE env var and, when set, behaves as a fake ssh instead of running
// tests:
//   - FAKE_SSH_MODE=proxy: dial the TCP address in FAKE_SSH_ADDR and splice
//     stdin<->conn, so real HTTP flows over the fake pipe (keep-alive works).
//   - FAKE_SSH_MODE=stderr: print FAKE_SSH_STDERR to stderr and exit with
//     FAKE_SSH_EXIT.
// A counter file at FAKE_SSH_COUNT is incremented once per launch so tests can
// assert that keep-alive reuses a single process.

func TestMain(m *testing.M) {
	switch os.Getenv("FAKE_SSH_MODE") {
	case "proxy":
		fakeSSHProxy()
		return
	case "stderr":
		fakeSSHStderr()
		return
	case "listen":
		fakeSSHListen()
		return
	}
	os.Exit(m.Run())
}

func bumpCounter() {
	if path := os.Getenv("FAKE_SSH_COUNT"); path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err == nil {
			_, _ = f.WriteString("x")
			_ = f.Close()
		}
	}
}

func fakeSSHProxy() {
	bumpCounter()
	addr := os.Getenv("FAKE_SSH_ADDR")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake ssh: dial failed:", err)
		os.Exit(1)
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(conn, os.Stdin); done <- struct{}{} }()
	go func() { _, _ = io.Copy(os.Stdout, conn); done <- struct{}{} }()
	<-done
	_ = conn.Close()
	os.Exit(0)
}

func fakeSSHStderr() {
	bumpCounter()
	fmt.Fprint(os.Stderr, os.Getenv("FAKE_SSH_STDERR"))
	code := 255
	if v := os.Getenv("FAKE_SSH_EXIT"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &code)
	}
	os.Exit(code)
}

// selfExe returns the path of the running test binary, used as the fake ssh.
func selfExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// withFakeSSH points sshPath at the test binary for the duration of the test.
func withFakeSSH(t *testing.T) {
	t.Helper()
	old := sshPath
	sshPath = selfExe(t)
	t.Cleanup(func() { sshPath = old })
}

// ---- direct mode tests ----

// newDirectClient wires a Client at ts.URL.
func newDirectClient(t *testing.T, ts *httptest.Server) *Client {
	t.Helper()
	c, err := Connect(context.Background(), Target{URL: ts.URL})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestStatusVersionOK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/status" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"api_version": APIVersion, "runner": "ok", "apps": 2})
	}))
	defer ts.Close()
	c := newDirectClient(t, ts)
	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.APIVersion != APIVersion || st.Apps != 2 {
		t.Errorf("unexpected status: %+v", st)
	}
}

func TestStatusVersionMismatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"api_version": 999})
	}))
	defer ts.Close()
	c := newDirectClient(t, ts)
	_, err := c.Status(context.Background())
	var e *Error
	if !asError(err, &e) {
		t.Fatalf("want *Error, got %v", err)
	}
	if e.Diag.Stage != stageConnect || e.Diag.Code != codeVersionMismatch {
		t.Errorf("want connect/version_mismatch, got %s/%s", e.Diag.Stage, e.Diag.Code)
	}
}

func TestDeployUploadNewAndDuplicate(t *testing.T) {
	var gotCT, gotKey string
	var gotLen int64
	status := http.StatusAccepted
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		gotKey = r.Header.Get("Idempotency-Key")
		gotLen = r.ContentLength
		body, _ := io.ReadAll(r.Body)
		_ = body
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "abc123", "app": "notes", "status": "queued"})
	}))
	defer ts.Close()
	c := newDirectClient(t, ts)

	payload := "tar.gz bytes"
	dep, created, err := c.Deploy(context.Background(), "notes", DeployOptions{
		Upload:         strings.NewReader(payload),
		UploadSize:     int64(len(payload)),
		IdempotencyKey: "key-1",
		Port:           8080,
		HealthPath:     "/healthz",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Error("202 should be created=true")
	}
	if dep.ID != "abc123" {
		t.Errorf("dep.ID = %q", dep.ID)
	}
	if gotCT != "application/gzip" {
		t.Errorf("content-type = %q", gotCT)
	}
	if gotKey != "key-1" {
		t.Errorf("idempotency key = %q", gotKey)
	}
	if gotLen != int64(len(payload)) {
		t.Errorf("content-length = %d, want %d", gotLen, len(payload))
	}

	status = http.StatusOK
	_, created, err = c.Deploy(context.Background(), "notes", DeployOptions{
		Upload:     strings.NewReader(payload),
		UploadSize: int64(len(payload)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Error("200 should be created=false (duplicate)")
	}
}

func TestDeployImageAndGitJSON(t *testing.T) {
	var body map[string]string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "d1", "app": "x"})
	}))
	defer ts.Close()
	c := newDirectClient(t, ts)

	_, _, err := c.Deploy(context.Background(), "x", DeployOptions{Image: "nginx:1.27-alpine"})
	if err != nil {
		t.Fatal(err)
	}
	if body["image"] != "nginx:1.27-alpine" {
		t.Errorf("image body = %+v", body)
	}

	body = nil
	_, _, err = c.Deploy(context.Background(), "x", DeployOptions{Git: "https://example.com/r.git", Ref: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if body["git"] != "https://example.com/r.git" || body["ref"] != "main" {
		t.Errorf("git body = %+v", body)
	}
}

func TestServerErrorMapping(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"invalid_app","message":"应用名不合法"}}`))
	}))
	defer ts.Close()
	c := newDirectClient(t, ts)
	_, err := c.App(context.Background(), "bad")
	var e *Error
	if !asError(err, &e) {
		t.Fatalf("want *Error, got %v", err)
	}
	if e.Status != 400 || e.Diag.Stage != "server" || e.Diag.Code != "invalid_app" {
		t.Errorf("unexpected: %+v", e)
	}
	if e.Diag.Message != "应用名不合法" {
		t.Errorf("message = %q", e.Diag.Message)
	}
}

func TestDeploymentAndEvents(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") != "5" {
			t.Errorf("after = %q", r.URL.Query().Get("after"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"deployment": map[string]any{"id": "d9", "app": "notes", "status": "live"},
			"events":     []map[string]any{{"id": 6, "stage": "route", "message": "已上线"}},
		})
	}))
	defer ts.Close()
	c := newDirectClient(t, ts)
	dep, events, err := c.Deployment(context.Background(), "d9", 5)
	if err != nil {
		t.Fatal(err)
	}
	if dep.Status != "live" || len(events) != 1 || events[0].ID != 6 {
		t.Errorf("dep=%+v events=%+v", dep, events)
	}
}

func TestAppsListAndLogsAndEnvVolumes(t *testing.T) {
	var calls []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.URL.Path == "/v1/apps":
			_ = json.NewEncoder(w).Encode(map[string]any{"apps": []map[string]any{{"name": "notes"}}})
		case r.URL.Path == "/v1/apps/notes/logs":
			if r.URL.Query().Get("tail") != "50" {
				t.Errorf("tail = %q", r.URL.Query().Get("tail"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"lines": []string{"a", "b"}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	defer ts.Close()
	c := newDirectClient(t, ts)
	ctx := context.Background()

	apps, err := c.Apps(ctx)
	if err != nil || len(apps) != 1 || apps[0].Name != "notes" {
		t.Fatalf("apps=%+v err=%v", apps, err)
	}
	lines, err := c.Logs(ctx, "notes", 50)
	if err != nil || len(lines) != 2 {
		t.Fatalf("logs=%+v err=%v", lines, err)
	}
	if err := c.SetEnv(ctx, "notes", "KEY", "val", true); err != nil {
		t.Fatal(err)
	}
	if err := c.UnsetEnv(ctx, "notes", "KEY"); err != nil {
		t.Fatal(err)
	}
	if err := c.AddVolume(ctx, "notes", "/data"); err != nil {
		t.Fatal(err)
	}
	if err := c.Stop(ctx, "notes"); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx, "notes"); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"GET /v1/apps",
		"GET /v1/apps/notes/logs",
		"PUT /v1/apps/notes/env/KEY",
		"DELETE /v1/apps/notes/env/KEY",
		"POST /v1/apps/notes/volumes",
		"POST /v1/apps/notes/stop",
		"POST /v1/apps/notes/start",
	}
	for i, w := range want {
		if i >= len(calls) || calls[i] != w {
			t.Errorf("call[%d] = %q, want %q (all=%v)", i, safeIdx(calls, i), w, calls)
		}
	}
}

func TestUpdateAppPATCH(t *testing.T) {
	var body AppSettings
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "notes", "memory_mb": 1024})
	}))
	defer ts.Close()
	c := newDirectClient(t, ts)
	mem := 1024
	a, err := c.UpdateApp(context.Background(), "notes", AppSettings{MemoryMB: &mem})
	if err != nil {
		t.Fatal(err)
	}
	if a.MemoryMB != 1024 {
		t.Errorf("memory = %d", a.MemoryMB)
	}
	if body.MemoryMB == nil || *body.MemoryMB != 1024 {
		t.Errorf("patched body memory = %+v", body.MemoryMB)
	}
}

// ---- ssh mode tests ----

func TestSSHArgvConstruction(t *testing.T) {
	got := sshArgs(Target{SSH: "ubuntu@1.2.3.4", Port: 2222, Identity: "/k/id"})
	want := []string{"-T", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=15",
		"-p", "2222", "-i", "/k/id", "ubuntu@1.2.3.4", "acornfox proxy"}
	if !equalStrings(got, want) {
		t.Errorf("argv = %v\nwant %v", got, want)
	}

	// Defaults: no port/identity, default remote command.
	got = sshArgs(Target{SSH: "alias"})
	want = []string{"-T", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=15", "alias", "acornfox proxy"}
	if !equalStrings(got, want) {
		t.Errorf("argv defaults = %v\nwant %v", got, want)
	}

	// Custom remote command is preserved.
	got = sshArgs(Target{SSH: "h", RemoteCommand: "custom cmd"})
	if got[len(got)-1] != "custom cmd" {
		t.Errorf("remote command = %q", got[len(got)-1])
	}
}

func TestSSHKeepAliveSingleProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-ssh via re-exec assumes unix-style process pipes for this test")
	}
	withFakeSSH(t)

	var reqCount int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{"api_version": APIVersion, "runner": "ok"})
	}))
	defer backend.Close()

	countFile := filepath.Join(t.TempDir(), "count")
	t.Setenv("FAKE_SSH_MODE", "proxy")
	t.Setenv("FAKE_SSH_ADDR", strings.TrimPrefix(backend.URL, "http://"))
	t.Setenv("FAKE_SSH_COUNT", countFile)

	c, err := Connect(context.Background(), Target{SSH: "devbox"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for i := 0; i < 3; i++ {
		if _, err := c.Status(context.Background()); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&reqCount); got != 3 {
		t.Errorf("backend saw %d requests, want 3", got)
	}
	launches := processLaunches(t, countFile)
	if launches != 1 {
		t.Errorf("ssh launched %d times, want 1 (keep-alive)", launches)
	}
}

func TestSSHConnectDiagnoses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-ssh via re-exec assumes unix-style process pipes for this test")
	}
	withFakeSSH(t)

	cases := []struct {
		name   string
		stderr string
		exit   string
		code   string
	}{
		{"resolve", "ssh: Could not resolve hostname foo: Name or service not known", "255", codeHostUnreachable},
		{"refused", "ssh: connect to host x port 22: Connection refused", "255", codeHostUnreachable},
		{"timeout", "ssh: connect to host x port 22: Connection timed out", "255", codeHostUnreachable},
		{"noroute", "ssh: connect to host x port 22: No route to host", "255", codeHostUnreachable},
		{"auth", "user@host: Permission denied (publickey).", "255", codeAuthFailed},
		{"hostkey", "Host key verification failed.", "255", codeHostKeyUnknown},
		{"notfound", "bash: acornfox: command not found", "127", codeAcornfoxMissing},
		{"notfound-zh", "bash: 行 1: acornfox: 未找到命令", "1", codeAcornfoxMissing},
		{"notfound-dash", "sh: 1: acornfox: not found", "1", codeAcornfoxMissing},
		{"proxy_perm", "acornfox proxy: permission denied", "13", codePermissionDenied},
		{"proxy_down", "acornfox proxy: server not running", "14", codeServerDown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("FAKE_SSH_MODE", "stderr")
			t.Setenv("FAKE_SSH_STDERR", tc.stderr)
			t.Setenv("FAKE_SSH_EXIT", tc.exit)

			c, err := Connect(context.Background(), Target{SSH: "devbox"})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err = c.Status(ctx)
			var e *Error
			if !asError(err, &e) {
				t.Fatalf("want *Error, got %v", err)
			}
			if e.Diag.Stage != stageConnect {
				t.Errorf("stage = %q, want connect", e.Diag.Stage)
			}
			if e.Diag.Code != tc.code {
				t.Errorf("code = %q, want %q (stderr=%q)", e.Diag.Code, tc.code, e.Diag.LogExcerpt)
			}
		})
	}
}

func TestSSHMissing(t *testing.T) {
	old := sshPath
	sshPath = "ssh" // force PATH lookup
	t.Cleanup(func() { sshPath = old })
	t.Setenv("PATH", t.TempDir()) // empty dir: no ssh

	c, err := Connect(context.Background(), Target{SSH: "devbox"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Status(context.Background())
	var e *Error
	if !asError(err, &e) {
		t.Fatalf("want *Error, got %v", err)
	}
	if e.Diag.Code != codeSSHMissing {
		t.Errorf("code = %q, want ssh_missing", e.Diag.Code)
	}
}

// ---- helpers ----

func asError(err error, target **Error) bool {
	if err == nil {
		return false
	}
	e, ok := err.(*Error)
	if ok {
		*target = e
	}
	return ok
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func safeIdx(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return "<none>"
}

func processLaunches(t *testing.T, countFile string) int {
	t.Helper()
	data, err := os.ReadFile(countFile)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatal(err)
	}
	return len(data)
}

// ensure exec is referenced even if all ssh tests are skipped on some platform.
var _ = exec.Command
