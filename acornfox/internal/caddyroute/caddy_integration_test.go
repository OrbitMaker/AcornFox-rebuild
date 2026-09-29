package caddyroute

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
//  2. Syncs one route with a domain, Issuer internal, ports 18080/18443.
//  3. Fetches https://<domain>:18443/ (resolving the name to 127.0.0.1) using
//     the Caddy local root CA and asserts the body.
//  4. Syncs with no routes and asserts af-domains and the policy are gone.
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

	r := New(adminSock, HTTPSConfig{HTTPPort: 18080, HTTPSPort: 18443, Issuer: "internal"})
	ctx := context.Background()

	// 2. sync a route with the domain
	route := Route{App: "notes", PublicPort: 18810, Upstream: upHost, Domains: []string{domain}}
	if err := r.Sync(ctx, []Route{route}); err != nil {
		t.Fatalf("Sync with domain: %v", err)
	}

	// Wait for the internal CA to issue the certificate (Caddy issues on demand
	// / at load; poll the HTTPS endpoint until it presents a valid cert).
	pool := loadRootCA(t, rootCAPath)
	client := httpsClient(pool, domain, "127.0.0.1:18443")

	deadline := time.Now().Add(30 * time.Second)
	var got string
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get("https://" + domain + ":18443/")
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

	// Confirm the af-domains server and our TLS policy exist.
	cur, err := r.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if d := cur["notes"].Domains; len(d) != 1 || d[0] != domain {
		t.Fatalf("Current domains = %v", d)
	}

	// 4. sync with no routes: af-domains and the policy must be gone.
	if err := r.Sync(ctx, nil); err != nil {
		t.Fatalf("Sync empty: %v", err)
	}
	assertGone(t, adminSock, "/config/apps/http/servers/af-domains")
	assertGone(t, adminSock, "/id/"+tlsPolicyID)
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
