package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/client"
)

// runOpen invokes `open` with injected tunnel/opener/port hooks. It returns the
// exit code, stdout and stderr. ctx controls Ctrl+C simulation.
func (h *harness) runOpen(ctx context.Context, cfg func(a *app), args ...string) (int, string, string) {
	h.t.Helper()
	var out, errBuf bytes.Buffer
	a := &app{
		out:       &outputWriter{stdout: &out, stderr: &errBuf},
		stdin:     io.NopCloser(bytes.NewReader(nil)),
		connect:   h.connect,
		getenv:    func(string) string { return "" },
		configDir: h.configDir,
		workDir:   h.workDir,
	}
	if cfg != nil {
		cfg(a)
	}
	rest, err := a.parseGlobal(args)
	if err != nil {
		return exitUsage, out.String(), errBuf.String()
	}
	// rest[0] == "open"
	code := a.cmdOpen(ctx, rest[1:])
	return code, out.String(), errBuf.String()
}

// TestOpenURLModeNoTunnel: a target with URL uses its host:port directly, opens
// the browser and blocks until ctx is cancelled (Ctrl+C) → exit 0.
func TestOpenURLModeNoTunnel(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://127.0.0.1:18800")

	var openedURL string
	h.api.consoleTokenFn = func(ctx context.Context) (string, error) { return "tok-secret-123", nil }

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()

	code, out, _ := h.runOpen(ctx, func(a *app) {
		a.openURL = func(u string) error { openedURL = u; return nil }
		// A tunnel function that must NOT be called in url mode.
		a.openTunnel = func(ctx context.Context, tg client.Target, p int) (*client.Tunnel, error) {
			t.Fatal("tunnel should not be used in url mode")
			return nil, nil
		}
	}, "open")

	if code != exitOK {
		t.Fatalf("exit = %d want 0", code)
	}
	if !strings.Contains(openedURL, "/console/login?t=tok-secret-123") {
		t.Fatalf("login URL = %q", openedURL)
	}
	// Token must not leak into human output when the browser opened.
	if strings.Contains(out, "tok-secret-123") {
		t.Fatalf("token leaked in output: %s", out)
	}
	if !strings.Contains(out, "http://127.0.0.1:18800") {
		t.Fatalf("base URL missing from output: %s", out)
	}
}

// TestOpenJSONShape: --json prints {"ok":true,"url":...} without the token.
func TestOpenJSONShape(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://127.0.0.1:18800")
	h.api.consoleTokenFn = func(ctx context.Context) (string, error) { return "json-token-xyz", nil }

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()

	code, out, _ := h.runOpen(ctx, func(a *app) {
		a.openURL = func(u string) error { return nil }
	}, "--json", "open")

	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	m := decodeJSON(t, out)
	if m["ok"] != true {
		t.Fatalf("ok != true: %v", m)
	}
	if m["url"] != "http://127.0.0.1:18800" {
		t.Fatalf("url = %v", m["url"])
	}
	if strings.Contains(out, "json-token-xyz") {
		t.Fatalf("token leaked in json: %s", out)
	}
}

// TestOpenNoBrowserPrintsLink: --no-browser prints the login URL (with token)
// and a note.
func TestOpenNoBrowserPrintsLink(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://127.0.0.1:18800")
	h.api.consoleTokenFn = func(ctx context.Context) (string, error) { return "nb-token-999", nil }

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()

	opened := false
	code, out, _ := h.runOpen(ctx, func(a *app) {
		a.openURL = func(u string) error { opened = true; return nil }
	}, "open", "--no-browser")

	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if opened {
		t.Fatalf("browser should not open with --no-browser")
	}
	if !strings.Contains(out, "nb-token-999") {
		t.Fatalf("login link with token should be printed: %s", out)
	}
	if !strings.Contains(out, "一次性") {
		t.Fatalf("single-use note missing: %s", out)
	}
}

// TestOpenBrowserFailurePrintsLink: when the opener fails, the login link is
// printed instead.
func TestOpenBrowserFailurePrintsLink(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://127.0.0.1:18800")
	h.api.consoleTokenFn = func(ctx context.Context) (string, error) { return "fail-token-777", nil }

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()

	code, out, _ := h.runOpen(ctx, func(a *app) {
		a.openURL = func(u string) error { return io.ErrUnexpectedEOF }
	}, "open")

	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "fail-token-777") {
		t.Fatalf("fallback link missing: %s", out)
	}
}

// TestOpenTunnelModeSuccess: ssh-mode target uses the injected tunnel; ctx
// cancel ends with exit 0.
func TestOpenTunnelModeSuccess(t *testing.T) {
	h := newHarness(t)
	// SSH-mode target (no URL).
	tf, _ := loadTargets(h.configDir)
	tf.Targets["dev"] = &client.Target{Name: "dev", SSH: "u@h"}
	tf.Default = "dev"
	if err := saveTargets(h.configDir, tf); err != nil {
		t.Fatal(err)
	}

	h.api.consoleTokenFn = func(ctx context.Context) (string, error) { return "ssh-token-abc", nil }

	var openedURL string
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()

	var gotPort int
	code, out, _ := h.runOpen(ctx, func(a *app) {
		a.freePort = func() (int, error) { return 45678, nil }
		a.openURL = func(u string) error { openedURL = u; return nil }
		a.openTunnel = func(ctx context.Context, tg client.Target, p int) (*client.Tunnel, error) {
			gotPort = p
			return client.NewLiveTunnelForTest("http://127.0.0.1:45678"), nil
		}
	}, "open")

	if code != exitOK {
		t.Fatalf("exit = %d want 0 out=%s", code, out)
	}
	if gotPort != 45678 {
		t.Fatalf("tunnel port = %d want 45678", gotPort)
	}
	if !strings.Contains(openedURL, "http://127.0.0.1:45678/console/login?t=ssh-token-abc") {
		t.Fatalf("login URL = %q", openedURL)
	}
	if strings.Contains(out, "ssh-token-abc") {
		t.Fatalf("token leaked in human output: %s", out)
	}
}

// TestOpenTunnelDiesConnectExit3: when the tunnel dies with a connect error,
// exit code is 3.
func TestOpenTunnelDiesConnectExit3(t *testing.T) {
	h := newHarness(t)
	tf, _ := loadTargets(h.configDir)
	tf.Targets["dev"] = &client.Target{Name: "dev", SSH: "u@h"}
	tf.Default = "dev"
	if err := saveTargets(h.configDir, tf); err != nil {
		t.Fatal(err)
	}
	h.api.consoleTokenFn = func(ctx context.Context) (string, error) { return "t", nil }

	// A tunnel whose Done is already closed with a connect error.
	tun := client.NewClosedTunnel("http://127.0.0.1:45999", &client.Error{
		Diag: client.Diagnosis{Stage: "connect", Code: "forwarding_disabled", Message: "转发被禁止"},
	})

	code, _, errOut := h.runOpen(context.Background(), func(a *app) {
		a.freePort = func() (int, error) { return 45999, nil }
		a.openURL = func(u string) error { return nil }
		a.openTunnel = func(ctx context.Context, tg client.Target, p int) (*client.Tunnel, error) {
			return tun, nil
		}
	}, "open")

	if code != exitConnect {
		t.Fatalf("exit = %d want %d (stderr=%s)", code, exitConnect, errOut)
	}
	if !strings.Contains(errOut, "转发被禁止") {
		t.Fatalf("diagnosis missing: %s", errOut)
	}
}

// TestOpenTokenErrorPropagates: a failure fetching the token surfaces as the
// client error's exit code.
func TestOpenTokenErrorExit3(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://127.0.0.1:18800")
	h.api.consoleTokenFn = func(ctx context.Context) (string, error) {
		return "", &client.Error{Diag: client.Diagnosis{Stage: "connect", Code: "server_down", Message: "未运行"}}
	}
	code, _, errOut := h.runOpen(context.Background(), func(a *app) {
		a.openURL = func(u string) error { return nil }
	}, "open")
	if code != exitConnect {
		t.Fatalf("exit = %d want %d", code, exitConnect)
	}
	if !strings.Contains(errOut, "未运行") {
		t.Fatalf("error not surfaced: %s", errOut)
	}
}
