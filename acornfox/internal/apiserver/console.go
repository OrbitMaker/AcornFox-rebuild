package apiserver

import (
	"context"
	"crypto/subtle"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"strings"

	"github.com/acornfox/acornfox/internal/state"
)

// sessionCookieName is the console session cookie. It is not marked Secure
// because the console is only ever reached over http://127.0.0.1 through the
// SSH tunnel; Secure would break that plain-HTTP loopback connection.
const sessionCookieName = "af_session"

// csrfHeader is required on every non-GET console request.
const csrfHeader = "X-AcornFox-CSRF"

// contentSecurityPolicy locks the console to same-origin assets only.
const contentSecurityPolicy = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// createConsoleToken implements POST /v1/console/tokens (trusted entry only).
// It returns a one-time token the browser trades for a session cookie.
func (s *server) createConsoleToken(w http.ResponseWriter, r *http.Request) {
	token, err := s.store.CreateConsoleToken(r.Context())
	if err != nil {
		s.mapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_in": int(state.ConsoleTokenTTL.Seconds()),
	})
}

// NewConsole builds the console HTTP handler served on the loopback console
// listener. It enforces a Host check (anti DNS-rebinding), security headers,
// cookie-based sessions with CSRF, and serves static assets plus the shared
// /v1 API (minus POST /v1/console/tokens, which 404s here).
func NewConsole(cfg Config) http.Handler {
	s := newServer(cfg)

	api := http.NewServeMux()
	s.registerV1(api)
	// Session lifecycle endpoints live only on the console entry.
	api.HandleFunc("GET /v1/console/session", s.consoleSession)
	api.HandleFunc("POST /v1/console/logout", s.consoleLogout)

	// Wrap the /v1 API with the session + CSRF middleware.
	guardedAPI := s.sessionMiddleware(api)

	root := http.NewServeMux()
	// Login redeems a token and is reachable without a session.
	root.HandleFunc("GET /console/login", s.consoleLogin)
	// The console entry must never mint tokens: 404 here, ahead of the session
	// guard so it does not turn into a 401.
	root.HandleFunc("POST /v1/console/tokens", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "对象不存在")
	})
	// All other /v1 traffic goes through the guarded API mux.
	root.Handle("/v1/", guardedAPI)
	// Everything else is static console assets.
	root.HandleFunc("/", s.serveStatic)

	// Outermost: Host check + security headers on every response.
	return s.hostGuard(s.securityHeaders(root))
}

// hostGuard rejects requests whose Host is not a loopback name, defeating DNS
// rebinding attacks against the console listener.
func (s *server) hostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackConsoleHost(r.Host) {
			writeError(w, http.StatusMisdirectedRequest, "bad_host", "无效的 Host 头")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isLoopbackConsoleHost reports whether host is 127.0.0.1[:port],
// localhost[:port] or [::1][:port].
func isLoopbackConsoleHost(host string) bool {
	if host == "" {
		return false
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host // no port
	}
	switch h {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// securityHeaders sets the console response headers on every request.
func (s *server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		// API responses must not be cached; static assets are also fine no-store.
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// consoleLogin implements GET /console/login?t=<token>. On success it sets the
// session cookie and 302s to "/" (dropping the token from the URL). On failure
// it renders a Chinese failure page.
func (s *server) consoleLogin(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("t")
	if token == "" {
		s.loginFailure(w)
		return
	}
	_, sessionSecret, _, err := s.store.RedeemConsoleToken(r.Context(), token)
	if err != nil {
		s.loginFailure(w)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionSecret,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	// 302 to "/" so the token never lingers in the address bar or history.
	http.Redirect(w, r, "/", http.StatusFound)
}

// loginFailure renders the Chinese login-failure page.
func (s *server) loginFailure(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">` +
		`<title>登录失败</title></head><body>` +
		`<p>登录链接已失效，请重新执行 <code>acornfox open</code>。</p>` +
		`</body></html>`))
}

// consoleSession implements GET /v1/console/session: returns the CSRF token and
// the session's absolute expiry. It runs after the session middleware, which
// has already validated the cookie and stashed the session in the context.
func (s *server) consoleSession(w http.ResponseWriter, r *http.Request) {
	sess, ok := sessionFromContext(r.Context())
	if !ok {
		s.sessionExpired(w)
		return
	}
	csrf, ok := csrfFromContext(r.Context())
	if !ok {
		s.sessionExpired(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"csrf":       csrf,
		"expires_at": sess.AbsoluteExpires,
	})
}

// consoleLogout implements POST /v1/console/logout: revokes the session.
func (s *server) consoleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		_ = s.store.RevokeConsoleSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// context keys for the validated session and its CSRF token.
type ctxKey int

const (
	ctxKeySession ctxKey = iota
	ctxKeyCSRF
)

func sessionFromContext(ctx context.Context) (state.ConsoleSession, bool) {
	v, ok := ctx.Value(ctxKeySession).(state.ConsoleSession)
	return v, ok
}

func csrfFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxKeyCSRF).(string)
	return v, ok
}

// sessionMiddleware validates the session cookie for every /v1 request, slides
// the idle expiry, and enforces the CSRF header on non-GET requests. On an
// invalid or expired session it returns 401 session_expired. The CSRF token is
// derived from the session secret (the cookie), so it is recoverable here for
// GET /v1/console/session and comparable on state-changing requests.
func (s *server) sessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookieName)
		if err != nil || c.Value == "" {
			s.sessionExpired(w)
			return
		}
		sess, err := s.store.TouchConsoleSession(r.Context(), c.Value)
		if err != nil {
			if errors.Is(err, state.ErrNotFound) {
				s.sessionExpired(w)
				return
			}
			s.mapStoreError(w, err)
			return
		}
		expectedCSRF := state.ConsoleCSRFToken(c.Value)
		// CSRF check for state-changing methods.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			presented := r.Header.Get(csrfHeader)
			if presented == "" || subtle.ConstantTimeCompare([]byte(presented), []byte(expectedCSRF)) != 1 {
				writeError(w, http.StatusForbidden, "csrf_required", "缺少或无效的 CSRF 令牌")
				return
			}
		}
		ctx := context.WithValue(r.Context(), ctxKeySession, sess)
		ctx = context.WithValue(ctx, ctxKeyCSRF, expectedCSRF)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// sessionExpired writes the 401 session_expired JSON error.
func (s *server) sessionExpired(w http.ResponseWriter) {
	writeError(w, http.StatusUnauthorized, "session_expired", "会话已过期，请重新执行 acornfox open")
}

// serveStatic serves the console assets from Config.ConsoleFS. "/" serves
// index.html. When ConsoleFS is nil a tiny placeholder page is served so the
// console listener is still useful before the assets package is wired in.
func (s *server) serveStatic(w http.ResponseWriter, r *http.Request) {
	if s.consoleFS == nil {
		s.placeholder(w)
		return
	}
	upath := strings.TrimPrefix(r.URL.Path, "/")
	if upath == "" {
		upath = "index.html"
	}
	f, err := s.consoleFS.Open(upath)
	if err != nil {
		// Fall back to index.html so a client-side router works, else placeholder.
		if idx, ierr := s.consoleFS.Open("index.html"); ierr == nil {
			_ = idx.Close()
			serveFSFile(w, r, s.consoleFS, "index.html")
			return
		}
		s.placeholder(w)
		return
	}
	_ = f.Close()
	serveFSFile(w, r, s.consoleFS, upath)
}

// serveFSFile serves a single file from an fs.FS using http.FileServer's
// content-type and range handling.
func serveFSFile(w http.ResponseWriter, r *http.Request, fsys fs.FS, name string) {
	http.StripPrefix("/", http.FileServer(http.FS(fsys))).ServeHTTP(w, requestForName(r, name))
}

// requestForName clones r with its path set to "/"+name so http.FileServer
// serves that exact file.
func requestForName(r *http.Request, name string) *http.Request {
	clone := r.Clone(r.Context())
	clone.URL.Path = "/" + name
	return clone
}

// placeholder renders a minimal Chinese page used when no console assets are
// embedded yet.
func (s *server) placeholder(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">` +
		`<title>AcornFox 控制台</title></head><body>` +
		`<p>控制台界面尚未安装。请稍后重试或更新到包含控制台资源的版本。</p>` +
		`</body></html>`))
}
