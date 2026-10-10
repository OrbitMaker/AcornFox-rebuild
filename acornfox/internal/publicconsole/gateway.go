package publicconsole

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/acornfox/acornfox/internal/state"
)

const sessionCookie = "af_session" // shared with the native console

// GatewayConfig wires the public console gateway.
type GatewayConfig struct {
	Store    *FileStore
	Sessions Sessions
	Console  http.Handler     // the native console handler (apiserver.NewConsole)
	Limiter  *Limiter         // nil => NewLimiter(nil)
	Now      func() time.Time // nil => time.Now
	Logger   *slog.Logger     // nil => slog.Default()
}

// NewGateway returns the handler Caddy reverse-proxies the public domain to.
// It answers only for the configured domain, logs users in with the generated
// password (rate limited), accepts only sessions it issued itself, requires an
// exact HTTPS Origin on state-changing requests, and hands everything else to
// the native console with a loopback Host and Secure cookies.
func NewGateway(cfg GatewayConfig) http.Handler {
	if cfg.Limiter == nil {
		cfg.Limiter = NewLimiter(nil)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &gateway{cfg: cfg}
}

type gateway struct{ cfg GatewayConfig }

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")

	cfg, err := g.cfg.Store.Load()
	if err != nil {
		g.cfg.Logger.Error("public console: load config", "err", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	if cfg == nil {
		http.Error(w, "公网访问未开启", http.StatusNotFound)
		return
	}
	if !strings.EqualFold(hostOnly(r.Host), cfg.Domain) {
		http.Error(w, "域名不匹配", http.StatusMisdirectedRequest)
		return
	}
	h.Set("Strict-Transport-Security", "max-age=31536000")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if origins := r.Header.Values("Origin"); len(origins) != 1 || origins[0] != "https://"+cfg.Domain {
			http.Error(w, "来源不被允许", http.StatusForbidden)
			return
		}
	}

	switch r.URL.Path {
	case "/login":
		if r.Method == http.MethodPost {
			g.login(w, r, cfg)
			return
		}
		g.loginPage(w, http.StatusOK, "")
		return
	case "/login.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write([]byte(loginCSS))
		return
	case "/console/login", "/v1/console/tokens":
		// Token login belongs to `acornfox open` over SSH only.
		http.NotFound(w, r)
		return
	}

	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" || !cfg.HasSession(Digest(c.Value)) {
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			writeJSONError(w, http.StatusUnauthorized, "session_expired", "登录已过期，请刷新页面重新登录")
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	out := r.Clone(r.Context())
	out.Host = "127.0.0.1"
	for _, k := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"} {
		out.Header.Del(k)
	}
	g.cfg.Console.ServeHTTP(&secureCookieWriter{ResponseWriter: w}, out)

	if r.Method == http.MethodPost && r.URL.Path == "/v1/console/logout" {
		g.forget(Digest(c.Value))
	}
}

func (g *gateway) login(w http.ResponseWriter, r *http.Request, cfg *Config) {
	ip := clientIP(r)
	if ok, wait := g.cfg.Limiter.Allow(ip); !ok {
		mins := int(wait.Minutes() + 0.999)
		g.loginPage(w, http.StatusTooManyRequests, fmt.Sprintf("尝试次数过多，请 %d 分钟后再试。", mins))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		g.loginPage(w, http.StatusBadRequest, "请求无效，请重试。")
		return
	}
	if !cfg.CheckPassword(r.PostFormValue("password")) {
		g.cfg.Limiter.Fail(ip)
		g.cfg.Logger.Warn("public console: login failed", "client", ip)
		g.loginPage(w, http.StatusUnauthorized, "密码不对。")
		return
	}
	g.cfg.Limiter.Success(ip)

	ctx := r.Context()
	token, err := g.cfg.Sessions.CreateConsoleToken(ctx)
	if err != nil {
		g.loginPage(w, http.StatusInternalServerError, "登录失败，请重试。")
		return
	}
	_, secret, _, err := g.cfg.Sessions.RedeemConsoleToken(ctx, token)
	if err != nil {
		g.loginPage(w, http.StatusInternalServerError, "登录失败，请重试。")
		return
	}
	if err := g.remember(Digest(secret)); err != nil {
		g.cfg.Logger.Error("public console: record session", "err", err)
		g.loginPage(w, http.StatusInternalServerError, "登录失败，请重试。")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: secret, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// remember records an issued session and drops ones past their lifetime.
func (g *gateway) remember(digest string) error {
	now := g.cfg.Now().UTC()
	return g.cfg.Store.Update(func(c *Config) {
		kept := c.Sessions[:0]
		for _, s := range c.Sessions {
			if now.Sub(s.IssuedAt) < state.ConsoleSessionAbsolute {
				kept = append(kept, s)
			}
		}
		c.Sessions = append(kept, IssuedSession{Digest: digest, IssuedAt: now})
	})
}

func (g *gateway) forget(digest string) {
	_ = g.cfg.Store.Update(func(c *Config) {
		kept := c.Sessions[:0]
		for _, s := range c.Sessions {
			if s.Digest != digest {
				kept = append(kept, s)
			}
		}
		c.Sessions = kept
	})
}

// clientIP is the visitor's address: Caddy, connecting over loopback, sets
// X-Forwarded-For to the real client and drops what clients sent themselves.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	return host
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// secureCookieWriter marks the console session cookie Secure on the way out.
type secureCookieWriter struct {
	http.ResponseWriter
	done bool
}

func (s *secureCookieWriter) fix() {
	if s.done {
		return
	}
	s.done = true
	h := s.Header()
	values := h.Values("Set-Cookie")
	for i, raw := range values {
		if c, err := http.ParseSetCookie(raw); err == nil && c.Name == sessionCookie {
			c.Secure = true
			values[i] = c.String()
		}
	}
	if len(values) > 0 {
		h["Set-Cookie"] = values
	}
}

func (s *secureCookieWriter) WriteHeader(code int) { s.fix(); s.ResponseWriter.WriteHeader(code) }
func (s *secureCookieWriter) Write(b []byte) (int, error) {
	s.fix()
	return s.ResponseWriter.Write(b)
}
func (s *secureCookieWriter) Flush() {
	s.fix()
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func writeJSONError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	body.Error.Code, body.Error.Message = code, msg
	_ = json.NewEncoder(w).Encode(body)
}

var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>登录 · AcornFox 控制台</title>
<link rel="stylesheet" href="/login.css"></head>
<body><main>
<h1>AcornFox 控制台</h1>
<p class="sub">输入开通公网访问时生成的密码。</p>
{{if .}}<p class="err" role="alert">{{.}}</p>{{end}}
<form method="post" action="/login">
<label for="password">密码</label>
<input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
<button type="submit">登录</button>
</form>
<p class="note">忘记密码：在电脑上运行 <code>acornfox public-console enable 域名 --reset-password</code> 重新生成。</p>
</main></body></html>`))

func (g *gateway) loginPage(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	_ = loginTmpl.Execute(w, msg)
}

// loginCSS follows docs/brand.md (ink, paper, line, pill buttons).
const loginCSS = `:root{--paper:#f4f6f7;--surface:#fff;--line:#dde3e6;--ink:#13161c;--muted:#5a6470;--danger:#b42d20}
@media (prefers-color-scheme:dark){:root{--paper:#13161c;--surface:#1c2028;--line:#2e343d;--ink:#f4f6f7;--muted:#a9b3bc;--danger:#f06a5c}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--paper);color:var(--ink);font:16px/1.6 "IBM Plex Sans","PingFang SC","Noto Sans SC","Microsoft YaHei",system-ui,sans-serif}
main{width:min(400px,100% - 32px);padding:32px;border-radius:16px;background:var(--surface);border:1px solid var(--line)}
h1{margin:0;font-size:22px}.sub,.note{color:var(--muted);font-size:14px}.err{color:var(--danger);font-weight:500}
form{display:flex;flex-direction:column;gap:10px;margin:16px 0}label{font-weight:500;font-size:14px}
input{height:44px;padding:0 16px;border-radius:999px;border:1px solid var(--line);background:var(--paper);color:var(--ink);font:inherit}
button{height:44px;border:0;border-radius:999px;background:var(--ink);color:var(--paper);font:inherit;font-weight:700;cursor:pointer}
:focus-visible{outline:2px solid #0c7565;outline-offset:3px}code{font-size:13px}`
