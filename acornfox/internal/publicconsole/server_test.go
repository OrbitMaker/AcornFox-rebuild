package publicconsole

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/caddyroute"
	"github.com/acornfox/acornfox/internal/state"
)

type fakeVerifier struct {
	mu                sync.Mutex
	host, path, body  string
	set, cleared, err int
}

func (f *fakeVerifier) SetChallenge(_ context.Context, host, path, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err > 0 {
		return errors.New("caddy down")
	}
	f.host, f.path, f.body = host, path, body
	f.set++
	return nil
}

func (f *fakeVerifier) ClearChallenge(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.host, f.path, f.body = "", "", ""
	f.cleared++
	return nil
}

type fakeSessions struct {
	mu      sync.Mutex
	n       int
	live    map[string]bool // secret -> valid
	revoked []string        // digests
}

func (f *fakeSessions) CreateConsoleToken(context.Context) (string, error) { return "tok", nil }
func (f *fakeSessions) RedeemConsoleToken(context.Context, string) (state.ConsoleSession, string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	secret := "secret-" + string(rune('a'+f.n))
	if f.live == nil {
		f.live = map[string]bool{}
	}
	f.live[secret] = true
	return state.ConsoleSession{}, secret, "csrf", nil
}
func (f *fakeSessions) TouchConsoleSession(_ context.Context, s string) (state.ConsoleSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.live[s] {
		return state.ConsoleSession{}, state.ErrNotFound
	}
	return state.ConsoleSession{}, nil
}
func (f *fakeSessions) RevokeConsoleSessionDigest(_ context.Context, d string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, d)
	for s := range f.live {
		if Digest(s) == d {
			delete(f.live, s)
		}
	}
	return nil
}

type fakeRefresher struct{ n int }

func (f *fakeRefresher) RefreshRoutes(context.Context) { f.n++ }

func newManager(t *testing.T) (*Manager, *FileStore, *fakeVerifier, *fakeSessions, *fakeRefresher) {
	t.Helper()
	store := NewFileStore(filepath.Join(t.TempDir(), "public-console.json"))
	v, s, r := &fakeVerifier{}, &fakeSessions{}, &fakeRefresher{}
	m := NewManager(ManagerConfig{
		Store: store, Verifier: v, Sessions: s, Routes: r,
		Fetch: func(_ context.Context, u string) (string, error) {
			if u == MetadataIPv4URLs[0] {
				return "203.0.113.10", nil
			}
			return "", errors.New("no")
		},
		Domains: func(context.Context) ([]string, error) { return []string{"shop.example.com"}, nil },
	})
	return m, store, v, s, r
}

func errCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestManagerVerifyEnableDisable(t *testing.T) {
	ctx := context.Background()
	m, store, v, sess, routes := newManager(t)

	if _, err := m.StartVerify(ctx, "https://x"); errCode(err) != "invalid_domain" {
		t.Fatalf("invalid domain err = %v", err)
	}
	if _, err := m.StartVerify(ctx, "shop.example.com"); errCode(err) != "domain_in_use" {
		t.Fatalf("app domain err = %v", err)
	}
	if _, err := m.Enable(ctx, "panel.example.com", "nope", false); errCode(err) != "verify_required" {
		t.Fatalf("enable without verify = %v", err)
	}

	info, err := m.StartVerify(ctx, "Panel.Example.com")
	if err != nil {
		t.Fatalf("StartVerify: %v", err)
	}
	if info.Domain != "panel.example.com" || info.IPs.V4[0] != "203.0.113.10" || !strings.HasPrefix(info.Path, VerifyPathPrefix) {
		t.Fatalf("info = %+v", info)
	}
	if v.host != "panel.example.com" || v.path != info.Path || v.body != info.Token {
		t.Fatalf("challenge = %+v", v)
	}
	if st, _ := m.Status(ctx); st.Enabled || st.Verifying != "panel.example.com" {
		t.Fatalf("status during verify = %+v", st)
	}
	if _, err := m.Enable(ctx, "panel.example.com", "wrong-id", false); errCode(err) != "verify_required" {
		t.Fatalf("wrong verify id = %v", err)
	}

	res, err := m.Enable(ctx, "panel.example.com", info.VerifyID, false)
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if res.Password == "" || res.URL != "https://panel.example.com" {
		t.Fatalf("enable result = %+v", res)
	}
	if v.body != "" || routes.n != 1 {
		t.Fatalf("challenge not cleared or routes not refreshed: %+v %d", v, routes.n)
	}
	cfg, _ := store.Load()
	if cfg == nil || !cfg.CheckPassword(res.Password) || strings.Contains(cfg.PasswordSHA256, res.Password) {
		t.Fatalf("stored config = %+v", cfg)
	}

	// Enabling again without reset keeps the password and shows none.
	again, err := m.Enable(ctx, "panel.example.com", "", false)
	if err != nil || !again.AlreadyEnabled || again.Password != "" {
		t.Fatalf("re-enable = %+v %v", again, err)
	}

	// Sessions issued by the gateway are revoked on disable.
	_ = store.Update(func(c *Config) { c.Sessions = append(c.Sessions, IssuedSession{Digest: "d1"}) })
	was, err := m.Disable(ctx)
	if err != nil || !was {
		t.Fatalf("Disable = %v %v", was, err)
	}
	if len(sess.revoked) != 1 || sess.revoked[0] != "d1" {
		t.Fatalf("revoked = %v", sess.revoked)
	}
	if cfg, _ := store.Load(); cfg != nil {
		t.Fatal("config not deleted")
	}
	if was, _ := m.Disable(ctx); was {
		t.Fatal("second disable reported enabled")
	}
}

func TestManagerVerifyExpires(t *testing.T) {
	ctx := context.Background()
	m, _, _, _, _ := newManager(t)
	now := time.Now()
	m.cfg.Now = func() time.Time { return now }
	info, err := m.StartVerify(ctx, "panel.example.com")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(VerifyTTL + time.Second)
	if _, err := m.Enable(ctx, "panel.example.com", info.VerifyID, false); errCode(err) != "verify_required" {
		t.Fatalf("expired verify = %v", err)
	}
}

func TestManagerNoPublicIP(t *testing.T) {
	m, _, _, _, _ := newManager(t)
	m.cfg.Fetch = func(context.Context, string) (string, error) { return "", errors.New("offline") }
	if _, err := m.StartVerify(context.Background(), "panel.example.com"); errCode(err) != "public_ip_unknown" {
		t.Fatalf("err = %v", err)
	}
}

// --- gateway ---

type gatewayFixture struct {
	h       http.Handler
	store   *FileStore
	sess    *fakeSessions
	console *http.Request // last request seen by the native console
	limiter *Limiter
	now     *time.Time
}

func newGateway(t *testing.T) (*gatewayFixture, string) {
	t.Helper()
	store := NewFileStore(filepath.Join(t.TempDir(), "pc.json"))
	if err := store.Save(&Config{Domain: "panel.example.com", PasswordSHA256: Digest("right-password")}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	f := &gatewayFixture{store: store, sess: &fakeSessions{}, now: &now}
	f.limiter = NewLimiter(func() time.Time { return *f.now })
	console := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.console = r
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
		_, _ = w.Write([]byte("console"))
	})
	f.h = NewGateway(GatewayConfig{Store: store, Sessions: f.sess, Console: console, Limiter: f.limiter})
	return f, "right-password"
}

func (f *gatewayFixture) do(method, path string, form url.Values, cookie, origin string, remote string) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, "https://panel.example.com"+path, body)
	r.Host = "panel.example.com"
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	r.RemoteAddr = "127.0.0.1:40000"
	if remote != "" {
		r.Header.Set("X-Forwarded-For", remote)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}

const origin = "https://panel.example.com"

func TestGatewayLoginFlow(t *testing.T) {
	f, pw := newGateway(t)

	// Anonymous page and API requests are turned away.
	if w := f.do("GET", "/", nil, "", "", ""); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("anonymous / = %d %v", w.Code, w.Header())
	}
	if w := f.do("GET", "/v1/apps", nil, "", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous api = %d", w.Code)
	}
	if w := f.do("GET", "/login", nil, "", "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `name="password"`) {
		t.Fatalf("login page = %d", w.Code)
	} else if rp := w.Header().Get("Referrer-Policy"); rp == "no-referrer" {
		// Browsers send "Origin: null" for form posts under no-referrer, which
		// the Origin check would reject: the login form could never succeed.
		t.Fatalf("login page Referrer-Policy = %q", rp)
	}
	// Token login of `acornfox open` is not reachable publicly.
	if w := f.do("GET", "/console/login?t=x", nil, "", "", ""); w.Code != http.StatusNotFound {
		t.Fatalf("/console/login = %d", w.Code)
	}

	// Cross-site login attempt is refused before the password is checked.
	if w := f.do("POST", "/login", url.Values{"password": {pw}}, "", "https://evil.example", ""); w.Code != http.StatusForbidden {
		t.Fatalf("cross origin login = %d", w.Code)
	}

	w := f.do("POST", "/login", url.Values{"password": {pw}}, "", origin, "198.51.100.1")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login = %d %s", w.Code, w.Body.String())
	}
	var secret string
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			secret = c.Value
			if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
				t.Fatalf("cookie flags = %+v", c)
			}
		}
	}
	if secret == "" {
		t.Fatal("no session cookie")
	}
	if w.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("no HSTS")
	}

	// Logged in: requests reach the native console with a loopback Host and
	// the console's cookies come back Secure.
	w = f.do("GET", "/v1/apps", nil, secret, "", "")
	if w.Code != 200 || f.console == nil || f.console.Host != "127.0.0.1" || f.console.Header.Get("X-Forwarded-For") != "" {
		t.Fatalf("proxied = %d host=%v", w.Code, f.console)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && !c.Secure {
			t.Fatal("console cookie not Secure")
		}
	}
	// Writes need the exact origin.
	if w := f.do("POST", "/v1/apps/x/stop", nil, secret, "", ""); w.Code != http.StatusForbidden {
		t.Fatalf("write without origin = %d", w.Code)
	}
	if w := f.do("POST", "/v1/apps/x/stop", nil, secret, origin, ""); w.Code != 200 {
		t.Fatalf("write with origin = %d", w.Code)
	}

	// A session not issued by the gateway (e.g. from `acornfox open`) is refused.
	if w := f.do("GET", "/v1/apps", nil, "loopback-session", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("foreign session = %d", w.Code)
	}

	// Logout forgets the session at the gateway.
	f.do("POST", "/v1/console/logout", nil, secret, origin, "")
	if w := f.do("GET", "/v1/apps", nil, secret, "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("after logout = %d", w.Code)
	}
}

func TestGatewayWrongHostAndDisabled(t *testing.T) {
	f, _ := newGateway(t)
	r := httptest.NewRequest("GET", "https://other.example.com/", nil)
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	if w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("other host = %d", w.Code)
	}
	_ = f.store.Delete()
	if w := f.do("GET", "/login", nil, "", "", ""); w.Code != http.StatusNotFound {
		t.Fatalf("disabled = %d", w.Code)
	}
}

func TestGatewayRateLimit(t *testing.T) {
	f, pw := newGateway(t)
	for i := 0; i < freeFailures; i++ {
		if w := f.do("POST", "/login", url.Values{"password": {"wrong"}}, "", origin, "198.51.100.9"); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d", i, w.Code)
		}
	}
	// Locked: even the right password is refused for now.
	if w := f.do("POST", "/login", url.Values{"password": {pw}}, "", origin, "198.51.100.9"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("locked = %d", w.Code)
	}
	// Another client is not affected.
	if w := f.do("POST", "/login", url.Values{"password": {pw}}, "", origin, "198.51.100.10"); w.Code != http.StatusSeeOther {
		t.Fatalf("other client = %d", w.Code)
	}
	*f.now = f.now.Add(firstLockout + time.Second)
	if w := f.do("POST", "/login", url.Values{"password": {pw}}, "", origin, "198.51.100.9"); w.Code != http.StatusSeeOther {
		t.Fatalf("after lockout = %d", w.Code)
	}
}

func TestLimiterBackoffAndGlobal(t *testing.T) {
	now := time.Now()
	l := NewLimiter(func() time.Time { return now })
	for i := 0; i < freeFailures+2; i++ {
		l.Fail("a")
	}
	if ok, wait := l.Allow("a"); ok || wait != 4*time.Minute {
		t.Fatalf("backoff = %v %v", ok, wait)
	}
	for i := 0; i < 40; i++ {
		l.Fail("a")
	}
	if _, wait := l.Allow("a"); wait > maxLockout {
		t.Fatalf("lockout above cap: %v", wait)
	}
	// Distributed failures trip the global pause.
	l2 := NewLimiter(func() time.Time { return now })
	for i := 0; i <= globalMax; i++ {
		l2.Fail(string(rune('A' + i%26)) + string(rune('a'+i/26)))
	}
	if ok, _ := l2.Allow("fresh-client"); ok {
		t.Fatal("global pause not applied")
	}
	now = now.Add(globalLockout + time.Second)
	if ok, _ := l2.Allow("fresh-client"); !ok {
		t.Fatal("global pause did not end")
	}
}

// --- router wrapper ---

type fakeInner struct {
	synced  []caddyroute.Route
	current map[string]caddyroute.Route
}

func (f *fakeInner) Sync(_ context.Context, r []caddyroute.Route) error { f.synced = r; return nil }
func (f *fakeInner) Current(context.Context) (map[string]caddyroute.Route, error) {
	out := map[string]caddyroute.Route{}
	for k, v := range f.current {
		out[k] = v
	}
	return out, nil
}

func TestWrapRouter(t *testing.T) {
	ctx := context.Background()
	store := NewFileStore(filepath.Join(t.TempDir(), "pc.json"))
	inner := &fakeInner{current: map[string]caddyroute.Route{"web": {App: "web", PublicPort: 18810}}}
	r := WrapRouter(inner, store, "127.0.0.1:18801")

	// Off: no extra route, Current unchanged.
	_ = r.Sync(ctx, []caddyroute.Route{{App: "web"}})
	if len(inner.synced) != 1 {
		t.Fatalf("synced = %v", inner.synced)
	}
	if m, _ := r.Current(ctx); len(m) != 1 {
		t.Fatalf("current off = %v", m)
	}

	// On but missing in Caddy: Current reports a difference.
	_ = store.Save(&Config{Domain: "panel.example.com"})
	if m, _ := r.Current(ctx); len(m) != 2 {
		t.Fatalf("missing console route not flagged: %v", m)
	}
	_ = r.Sync(ctx, []caddyroute.Route{{App: "web"}})
	if len(inner.synced) != 2 || inner.synced[1].App != RouteApp || inner.synced[1].Domains[0] != "panel.example.com" || inner.synced[1].PublicPort != 0 {
		t.Fatalf("synced = %+v", inner.synced)
	}
	// Present and correct: hidden from the reconciler.
	inner.current[RouteApp] = caddyroute.Route{App: RouteApp, Upstream: "127.0.0.1:18801", Domains: []string{"panel.example.com"}}
	if m, _ := r.Current(ctx); len(m) != 1 || m["web"].App != "web" {
		t.Fatalf("current on = %v", m)
	}
	// Disabled but still in Caddy: flagged so it gets removed.
	_ = store.Delete()
	if m, _ := r.Current(ctx); len(m) != 2 {
		t.Fatalf("stale console route not flagged: %v", m)
	}
}

func TestGeneratePassword(t *testing.T) {
	a, _ := GeneratePassword()
	b, _ := GeneratePassword()
	if a == b || len(a) != 27 || strings.Count(a, "-") != 3 {
		t.Fatalf("passwords %q %q", a, b)
	}
	if strings.ContainsAny(a, "0O1lI") {
		t.Fatalf("ambiguous characters in %q", a)
	}
}
