package apiserver

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/state"
)

// newTestConfig builds a Config wired to fakes for N3 tests.
func newTestConfig(t *testing.T) (Config, *fakeStore, *fakeKicker) {
	t.Helper()
	store := newFakeStore()
	kicker := &fakeKicker{}
	cfg := Config{
		Store:      store,
		Kicker:     kicker,
		Runner:     newFakeRunner(),
		UploadDir:  t.TempDir(),
		PublicHost: "192.168.1.10",
		Resolver:   fakeResolver{addrs: map[string][]net.IPAddr{}},
	}
	return cfg, store, kicker
}

// login mints a token on the trusted handler, redeems it on the console
// handler, and returns the session cookie and CSRF token.
func login(t *testing.T, trusted, console http.Handler) (*http.Cookie, string) {
	t.Helper()
	// Mint token via trusted handler.
	req := httptest.NewRequest(http.MethodPost, "/v1/console/tokens", nil)
	rec := httptest.NewRecorder()
	trusted.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("mint token: status %d", rec.Code)
	}
	var tok struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if tok.Token == "" || tok.ExpiresIn <= 0 {
		t.Fatalf("bad token response: %+v", tok)
	}

	// Redeem on console handler.
	lreq := httptest.NewRequest(http.MethodGet, "/console/login?t="+tok.Token, nil)
	lreq.Host = "127.0.0.1:12345"
	lrec := httptest.NewRecorder()
	console.ServeHTTP(lrec, lreq)
	if lrec.Code != http.StatusFound {
		t.Fatalf("login: status %d, want 302", lrec.Code)
	}
	if loc := lrec.Header().Get("Location"); loc != "/" {
		t.Fatalf("login redirect Location = %q, want /", loc)
	}
	if strings.Contains(lrec.Header().Get("Location"), tok.Token) {
		t.Fatalf("token leaked into redirect Location")
	}
	var cookie *http.Cookie
	for _, c := range lrec.Result().Cookies() {
		if c.Name == sessionCookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatalf("no session cookie set")
	}
	// Cookie flags.
	if !cookie.HttpOnly {
		t.Errorf("cookie not HttpOnly")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie SameSite = %v, want Strict", cookie.SameSite)
	}
	if cookie.Secure {
		t.Errorf("cookie must not be Secure (http loopback)")
	}
	if cookie.Path != "/" {
		t.Errorf("cookie Path = %q, want /", cookie.Path)
	}

	// Fetch CSRF via session endpoint.
	sreq := httptest.NewRequest(http.MethodGet, "/v1/console/session", nil)
	sreq.Host = "127.0.0.1:12345"
	sreq.AddCookie(cookie)
	srec := httptest.NewRecorder()
	console.ServeHTTP(srec, sreq)
	if srec.Code != http.StatusOK {
		t.Fatalf("session: status %d", srec.Code)
	}
	var sess struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(srec.Body.Bytes(), &sess); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if sess.CSRF == "" {
		t.Fatalf("empty csrf")
	}
	return cookie, sess.CSRF
}

func TestConsoleTokenSingleUseOverHTTP(t *testing.T) {
	cfg, _, _ := newTestConfig(t)
	trusted := New(cfg)
	console := NewConsole(cfg)

	// Mint a token.
	req := httptest.NewRequest(http.MethodPost, "/v1/console/tokens", nil)
	rec := httptest.NewRecorder()
	trusted.ServeHTTP(rec, req)
	var tok struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)

	// First redemption succeeds.
	first := doLogin(console, tok.Token)
	if first.Code != http.StatusFound {
		t.Fatalf("first login status %d", first.Code)
	}
	// Second redemption of same token fails (Chinese failure page, 401).
	second := doLogin(console, tok.Token)
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("second login status %d, want 401", second.Code)
	}
	if !strings.Contains(second.Body.String(), "acornfox open") {
		t.Errorf("failure page missing guidance: %s", second.Body.String())
	}
}

func doLogin(console http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/console/login?t="+token, nil)
	req.Host = "127.0.0.1:9999"
	rec := httptest.NewRecorder()
	console.ServeHTTP(rec, req)
	return rec
}

func TestConsoleTokensNotOnConsoleEntry(t *testing.T) {
	cfg, _, _ := newTestConfig(t)
	console := NewConsole(cfg)
	req := httptest.NewRequest(http.MethodPost, "/v1/console/tokens", nil)
	req.Host = "127.0.0.1:9999"
	rec := httptest.NewRecorder()
	console.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST /v1/console/tokens on console = %d, want 404", rec.Code)
	}
}

func TestConsoleHostCheck(t *testing.T) {
	cfg, _, _ := newTestConfig(t)
	console := NewConsole(cfg)
	for _, host := range []string{"evil.example.com", "192.168.1.10:18800", "attacker.local:80"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		console.ServeHTTP(rec, req)
		if rec.Code != http.StatusMisdirectedRequest {
			t.Errorf("Host %q = %d, want 421", host, rec.Code)
		}
	}
	for _, host := range []string{"127.0.0.1:18800", "localhost:5000", "[::1]:9000"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		console.ServeHTTP(rec, req)
		if rec.Code == http.StatusMisdirectedRequest {
			t.Errorf("loopback Host %q rejected", host)
		}
	}
}

func TestConsoleSecurityHeaders(t *testing.T) {
	cfg, _, _ := newTestConfig(t)
	console := NewConsole(cfg)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:18800"
	rec := httptest.NewRecorder()
	console.ServeHTTP(rec, req)
	h := rec.Header()
	if !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Errorf("missing CSP: %q", h.Get("Content-Security-Policy"))
	}
	if h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("missing nosniff")
	}
	if h.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("missing referrer policy")
	}
	if h.Get("Cache-Control") != "no-store" {
		t.Errorf("missing cache-control no-store")
	}
}

func TestConsoleRequiresCookieForEveryV1Route(t *testing.T) {
	cfg, store, _ := newTestConfig(t)
	if _, _, err := store.EnsureApp(context.Background(), "web"); err != nil {
		t.Fatal(err)
	}
	console := NewConsole(cfg)

	routes := []struct {
		method, path string
	}{
		{http.MethodGet, "/v1/apps"},
		{http.MethodGet, "/v1/apps/web"},
		{http.MethodPatch, "/v1/apps/web"},
		{http.MethodGet, "/v1/apps/web/logs"},
		{http.MethodGet, "/v1/apps/web/deployments"},
		{http.MethodPost, "/v1/apps/web/deployments"},
		{http.MethodPost, "/v1/apps/web/rollback"},
		{http.MethodPut, "/v1/apps/web/env/FOO"},
		{http.MethodDelete, "/v1/apps/web/env/FOO"},
		{http.MethodPost, "/v1/apps/web/volumes"},
		{http.MethodGet, "/v1/apps/web/domains"},
		{http.MethodPost, "/v1/apps/web/domains"},
		{http.MethodDelete, "/v1/apps/web/domains/x.example.com"},
		{http.MethodPost, "/v1/apps/web/stop"},
		{http.MethodPost, "/v1/apps/web/start"},
		{http.MethodGet, "/v1/host"},
		{http.MethodGet, "/v1/status"},
		{http.MethodGet, "/v1/console/session"},
		{http.MethodPost, "/v1/console/logout"},
	}
	for _, rt := range routes {
		req := httptest.NewRequest(rt.method, rt.path, nil)
		req.Host = "127.0.0.1:18800"
		rec := httptest.NewRecorder()
		console.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without cookie = %d, want 401", rt.method, rt.path, rec.Code)
		}
	}
}

func TestConsoleCSRFRequired(t *testing.T) {
	cfg, store, _ := newTestConfig(t)
	if _, _, err := store.EnsureApp(context.Background(), "web"); err != nil {
		t.Fatal(err)
	}
	trusted := New(cfg)
	console := NewConsole(cfg)
	cookie, csrf := login(t, trusted, console)

	// Non-GET without CSRF -> 403.
	req := httptest.NewRequest(http.MethodPost, "/v1/apps/web/stop", nil)
	req.Host = "127.0.0.1:18800"
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	console.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without CSRF = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "csrf_required") {
		t.Errorf("body missing csrf_required: %s", rec.Body.String())
	}

	// Non-GET with CSRF -> allowed (200).
	req2 := httptest.NewRequest(http.MethodPost, "/v1/apps/web/stop", nil)
	req2.Host = "127.0.0.1:18800"
	req2.AddCookie(cookie)
	req2.Header.Set(csrfHeader, csrf)
	rec2 := httptest.NewRecorder()
	console.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("POST with CSRF = %d, want 200", rec2.Code)
	}
}

func TestConsoleLogout(t *testing.T) {
	cfg, _, _ := newTestConfig(t)
	trusted := New(cfg)
	console := NewConsole(cfg)
	cookie, csrf := login(t, trusted, console)

	req := httptest.NewRequest(http.MethodPost, "/v1/console/logout", nil)
	req.Host = "127.0.0.1:18800"
	req.AddCookie(cookie)
	req.Header.Set(csrfHeader, csrf)
	rec := httptest.NewRecorder()
	console.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout = %d", rec.Code)
	}
	// After logout the session is revoked -> 401.
	req2 := httptest.NewRequest(http.MethodGet, "/v1/apps", nil)
	req2.Host = "127.0.0.1:18800"
	req2.AddCookie(cookie)
	rec2 := httptest.NewRecorder()
	console.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("after logout = %d, want 401", rec2.Code)
	}
}

func TestConsoleServesV1WithCookie(t *testing.T) {
	cfg, store, _ := newTestConfig(t)
	if _, _, err := store.EnsureApp(context.Background(), "web"); err != nil {
		t.Fatal(err)
	}
	trusted := New(cfg)
	console := NewConsole(cfg)
	cookie, _ := login(t, trusted, console)

	req := httptest.NewRequest(http.MethodGet, "/v1/apps", nil)
	req.Host = "127.0.0.1:18800"
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	console.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/apps with cookie = %d", rec.Code)
	}
}

func TestConsoleStaticPlaceholder(t *testing.T) {
	cfg, _, _ := newTestConfig(t) // ConsoleFS nil
	console := NewConsole(cfg)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:18800"
	rec := httptest.NewRecorder()
	console.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("placeholder = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "控制台") {
		t.Errorf("placeholder page unexpected: %s", rec.Body.String())
	}
}

func TestDeploymentsLimitValidation(t *testing.T) {
	cfg, store, _ := newTestConfig(t)
	if _, _, err := store.EnsureApp(context.Background(), "web"); err != nil {
		t.Fatal(err)
	}
	h := New(cfg)

	for _, raw := range []string{"0", "101", "-1", "abc"} {
		req := httptest.NewRequest(http.MethodGet, "/v1/apps/web/deployments?limit="+raw, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("limit=%q = %d, want 400", raw, rec.Code)
		}
	}
	// Valid.
	req := httptest.NewRequest(http.MethodGet, "/v1/apps/web/deployments?limit=20", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid limit = %d", rec.Code)
	}
}

func TestHostEndpoint(t *testing.T) {
	cfg, _, _ := newTestConfig(t)
	cpu := 42.5
	total := uint64(1000)
	used := uint64(400)
	cfg.HostMetrics = fakeHostProvider{view: HostView{
		Available: true, CPUPercent: &cpu, MemoryTotal: &total, MemoryUsed: &used,
	}}
	h := New(cfg)
	req := httptest.NewRequest(http.MethodGet, "/v1/host", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("host = %d", rec.Code)
	}
	var v HostView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode host: %v", err)
	}
	if !v.Available || v.CPUPercent == nil || *v.CPUPercent != 42.5 {
		t.Fatalf("unexpected host view: %+v", v)
	}
}

func TestHostEndpointUnavailable(t *testing.T) {
	cfg, _, _ := newTestConfig(t)
	cfg.HostMetrics = fakeHostProvider{view: HostView{Available: false}}
	h := New(cfg)
	req := httptest.NewRequest(http.MethodGet, "/v1/host", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("host = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"available":false`) {
		t.Errorf("expected available:false, got %s", rec.Body.String())
	}
}

func TestDomainAddConflict(t *testing.T) {
	cfg, store, _ := newTestConfig(t)
	ctx := context.Background()
	if _, _, err := store.EnsureApp(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.EnsureApp(ctx, "api"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AddDomain(ctx, "api", "shared.example.com"); err != nil {
		t.Fatal(err)
	}
	h := New(cfg)
	body := strings.NewReader(`{"name":"shared.example.com"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/apps/web/domains", body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("conflict = %d, want 409", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "domain_taken") {
		t.Errorf("missing domain_taken: %s", rec.Body.String())
	}
}

func TestDomainAddInvalid(t *testing.T) {
	cfg, store, _ := newTestConfig(t)
	if _, _, err := store.EnsureApp(context.Background(), "web"); err != nil {
		t.Fatal(err)
	}
	h := New(cfg)
	for _, name := range []string{"nodot", "UPPER.example.com", "1.2.3.4", ""} {
		body := strings.NewReader(`{"name":"` + name + `"}`)
		req := httptest.NewRequest(http.MethodPost, "/v1/apps/web/domains", body)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("name=%q = %d, want 400", name, rec.Code)
		}
	}
}

func TestDomainAddDNSMismatchWarning(t *testing.T) {
	cfg, store, kicker := newTestConfig(t)
	if _, _, err := store.EnsureApp(context.Background(), "web"); err != nil {
		t.Fatal(err)
	}
	// PublicHost is 192.168.1.10; resolver returns a different IP -> mismatch.
	cfg.Resolver = fakeResolver{addrs: map[string][]net.IPAddr{
		"notes.example.com": {{IP: net.ParseIP("203.0.113.7")}},
	}}
	h := New(cfg)
	body := strings.NewReader(`{"name":"notes.example.com"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/apps/web/domains", body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("add domain = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "dns_mismatch") {
		t.Errorf("expected dns_mismatch warning: %s", rec.Body.String())
	}
	// Kicker fired after the domain change.
	kicker.mu.Lock()
	defer kicker.mu.Unlock()
	if len(kicker.kicks) == 0 || kicker.kicks[len(kicker.kicks)-1] != "web" {
		t.Errorf("kicker not fired for web: %v", kicker.kicks)
	}
}

func TestDomainAddNoWarningWhenMatch(t *testing.T) {
	cfg, store, _ := newTestConfig(t)
	if _, _, err := store.EnsureApp(context.Background(), "web"); err != nil {
		t.Fatal(err)
	}
	cfg.Resolver = fakeResolver{addrs: map[string][]net.IPAddr{
		"notes.example.com": {{IP: net.ParseIP("192.168.1.10")}},
	}}
	h := New(cfg)
	body := strings.NewReader(`{"name":"notes.example.com"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/apps/web/domains", body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("add domain = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "dns_mismatch") {
		t.Errorf("unexpected dns_mismatch: %s", rec.Body.String())
	}
}

func TestSecretsNeverInResponses(t *testing.T) {
	cfg, store, _ := newTestConfig(t)
	ctx := context.Background()
	if _, _, err := store.EnsureApp(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	const secretValue = "super-secret-token-value"
	if err := store.SetEnv(ctx, state.EnvVar{App: "web", Key: "API_KEY", Value: secretValue, Secret: true}); err != nil {
		t.Fatal(err)
	}
	h := New(cfg)
	req := httptest.NewRequest(http.MethodGet, "/v1/apps/web", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get app = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), secretValue) {
		t.Fatalf("secret value leaked in app view: %s", rec.Body.String())
	}
}

func TestConsoleSessionExpiredWhenSessionRevoked(t *testing.T) {
	cfg, store, _ := newTestConfig(t)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	store.clock = func() time.Time { return now }
	trusted := New(cfg)
	console := NewConsole(cfg)
	cookie, _ := login(t, trusted, console)

	// Jump past absolute expiry.
	now = now.Add(state.ConsoleSessionAbsolute + time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/v1/apps", nil)
	req.Host = "127.0.0.1:18800"
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	console.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired session = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "session_expired") {
		t.Errorf("missing session_expired: %s", rec.Body.String())
	}
}
