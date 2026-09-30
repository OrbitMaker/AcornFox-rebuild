package caddyroute

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// TestCaddyIntegration drives a real Caddy admin API. It is skipped unless
// ACORNFOX_CADDY_IT=1 and ACORNFOX_CADDY_ADMIN (a unix socket path) are set, and
// ACORNFOX_CADDY_ROOT_CA points at Caddy's local CA root.crt. The devbox
// harness (a shell script) extracts Caddy from its image, starts it on a temp
// socket with a temp XDG_DATA_HOME, and sets those env vars.
//
// The test:
//  1. Starts a local httptest upstream serving a known body.
//  2. Syncs one route with a domain, internal issuer and isolated free ports.
//  3. Checks HTTPS content and the HTTP redirect using the Caddy local root CA.
//  4. Repeats the sync, then removes routes and checks policy cleanup.
func TestCaddyIntegration(t *testing.T) {
	if os.Getenv("ACORNFOX_CADDY_IT") != "1" {
		t.Skip("set ACORNFOX_CADDY_IT=1 to run the real Caddy integration test")
	}
	adminSock := os.Getenv("ACORNFOX_CADDY_ADMIN")
	if adminSock == "" {
		t.Fatal("ACORNFOX_CADDY_ADMIN not set")
	}
	rootCAPath := os.Getenv("ACORNFOX_CADDY_ROOT_CA")
	if rootCAPath == "" {
		t.Fatal("ACORNFOX_CADDY_ROOT_CA not set")
	}

	const domain = "notes.acornfox.test"
	const body = "hello from acornfox upstream"

	// 1. local upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, body)
	}))
	defer upstream.Close()
	upHost := upstream.Listener.Addr().String() // 127.0.0.1:<port>

	ctx := context.Background()

	// Isolate this check from the running development console and app routes.
	httpPort, httpsPort, publicPort := freePorts(t)
	r := New(adminSock, HTTPSConfig{HTTPPort: httpPort, HTTPSPort: httpsPort, Issuer: "internal"})
	// 2. sync a route with the domain
	route := Route{App: "notes", PublicPort: publicPort, Upstream: upHost, Domains: []string{domain}}
	if err := r.Sync(ctx, []Route{route}); err != nil {
		t.Fatalf("Sync with domain: %v", err)
	}

	// Wait for the internal CA to issue the certificate (Caddy issues on demand
	// / at load; poll the HTTPS endpoint until it presents a valid cert).
	pool := loadRootCA(t, rootCAPath)
	client := httpsClient(pool, domain, fmt.Sprintf("127.0.0.1:%d", httpsPort))

	deadline := time.Now().Add(30 * time.Second)
	var got string
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(fmt.Sprintf("https://%s:%d/", domain, httpsPort))
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		got = string(b)
		lastErr = nil
		break
	}
	if lastErr != nil {
		t.Fatalf("https GET never succeeded: %v", lastErr)
	}
	if got != body {
		t.Fatalf("body = %q, want %q", got, body)
	}

	// HTTP must redirect before any application content is served, retaining
	// the path and query. Caddy treats HTTPSPort as the internal listener port;
	// its public redirect uses the canonical HTTPS URL.
	redirectClient := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", httpPort))
		}},
	}
	resp, err := redirectClient.Get(fmt.Sprintf("http://%s:%d/redirect-check?from=http", domain, httpPort))
	if err != nil {
		t.Fatalf("HTTP redirect: %v", err)
	}
	resp.Body.Close()
	wantLocation := "https://" + domain + "/redirect-check?from=http"
	if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != wantLocation {
		t.Fatalf("HTTP redirect = %d %q, want 308 %q", resp.StatusCode, resp.Header.Get("Location"), wantLocation)
	}

	// Confirm the af-domains server and our TLS policy exist.
	cur, err := r.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if d := cur["notes"].Domains; len(d) != 1 || d[0] != domain {
		t.Fatalf("Current domains = %v", d)
	}
	if err := r.Sync(ctx, []Route{route}); err != nil {
		t.Fatalf("repeat Sync with existing TLS policy: %v", err)
	}

	// 4. sync with no routes: af-domains and the policy must be gone.
	if err := r.Sync(ctx, nil); err != nil {
		t.Fatalf("Sync empty: %v", err)
	}
	assertGone(t, adminSock, "/config/apps/http/servers/af-domains")
	assertGone(t, adminSock, "/id/"+tlsPolicyID)
}

func freePorts(t *testing.T) (int, int, int) {
	t.Helper()
	var listeners []net.Listener
	defer func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}()
	for range 3 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, ln)
	}
	return listeners[0].Addr().(*net.TCPAddr).Port, listeners[1].Addr().(*net.TCPAddr).Port, listeners[2].Addr().(*net.TCPAddr).Port
}

func loadRootCA(t *testing.T, path string) *x509.CertPool {
	t.Helper()
	// Caddy writes the local CA root lazily once a config referencing the
	// internal issuer is loaded; wait for it to appear.
	deadline := time.Now().Add(20 * time.Second)
	var pem []byte
	var err error
	for time.Now().Before(deadline) {
		pem, err = os.ReadFile(path)
		if err == nil && len(pem) > 0 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil || len(pem) == 0 {
		t.Fatalf("read root ca %s: %v", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatalf("no certs parsed from %s", path)
	}
	return pool
}

// httpsClient builds a client that resolves any dial to fixedAddr (like curl
// --resolve) and verifies against pool with SNI/hostname = serverName.
func httpsClient(pool *x509.CertPool, serverName, fixedAddr string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, fixedAddr)
			},
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				ServerName: serverName,
			},
		},
	}
}

func assertGone(t *testing.T, sock, path string) {
	t.Helper()
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
	resp, err := client.Get("http://caddy" + path)
	if err != nil {
		t.Fatalf("admin GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return
	}
	// A present-but-null body also counts as gone.
	trimmed := string(b)
	if trimmed == "" || trimmed == "null\n" || trimmed == "null" {
		return
	}
	t.Fatalf("expected %s to be gone, got status %d body %q", path, resp.StatusCode, trimmed)
}
