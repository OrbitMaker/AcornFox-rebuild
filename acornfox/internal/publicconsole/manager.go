package publicconsole

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/acornfox/acornfox/internal/caddyroute"
	"github.com/acornfox/acornfox/internal/state"
)

// VerifyTTL is how long a started verification (and its HTTP challenge) lasts.
const VerifyTTL = 30 * time.Minute

// ipCacheTTL bounds how long detected public addresses are reused.
const ipCacheTTL = 10 * time.Minute

// Sessions is the subset of the state store the public console needs.
type Sessions interface {
	CreateConsoleToken(ctx context.Context) (string, error)
	RedeemConsoleToken(ctx context.Context, token string) (state.ConsoleSession, string, string, error)
	TouchConsoleSession(ctx context.Context, sessionSecret string) (state.ConsoleSession, error)
	RevokeConsoleSessionDigest(ctx context.Context, digest string) error
}

// Refresher re-syncs Caddy routes (the reconciler's RefreshRoutes).
type Refresher interface{ RefreshRoutes(ctx context.Context) }

// Error is a classified failure returned to the API layer.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

// Status is the public console state reported to clients.
type Status struct {
	Enabled   bool       `json:"enabled"`
	Domain    string     `json:"domain,omitempty"`
	URL       string     `json:"url,omitempty"`
	EnabledAt *time.Time `json:"enabled_at,omitempty"`
	Verifying string     `json:"verifying,omitempty"` // domain of a verification in progress
}

// VerifyInfo is what a client needs to verify a domain from outside.
type VerifyInfo struct {
	Domain    string    `json:"domain"`
	VerifyID  string    `json:"verify_id"`
	Path      string    `json:"path"`
	Token     string    `json:"token"`
	IPs       PublicIPs `json:"ips"`
	ExpiresIn int       `json:"expires_in"`
}

// EnableResult is returned once by Enable. Password is set only when a new
// password was generated; it is never stored or shown again.
type EnableResult struct {
	Domain         string `json:"domain"`
	URL            string `json:"url"`
	Password       string `json:"password,omitempty"`
	AlreadyEnabled bool   `json:"already_enabled,omitempty"`
}

// ManagerConfig wires a Manager.
type ManagerConfig struct {
	Store    *FileStore
	Verifier caddyroute.Verifier
	Sessions Sessions
	Routes   Refresher
	Fetch    Fetcher                                     // nil => HTTPFetcher(3s)
	Domains  func(ctx context.Context) ([]string, error) // app domains; nil => none
	Now      func() time.Time                            // nil => time.Now
	Logger   *slog.Logger                                // nil => slog.Default()
}

// Manager implements verify / enable / disable / status on the server.
type Manager struct {
	cfg     ManagerConfig
	mu      sync.Mutex
	pending *pendingVerify
	ips     PublicIPs
	ipsAt   time.Time
	timer   *time.Timer
}

type pendingVerify struct {
	domain, id, token string
	expires           time.Time
}

// NewManager returns a Manager.
func NewManager(cfg ManagerConfig) *Manager {
	if cfg.Fetch == nil {
		cfg.Fetch = HTTPFetcher(3 * time.Second)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Manager{cfg: cfg}
}

// Cleanup removes a challenge left over from a previous server process.
func (m *Manager) Cleanup(ctx context.Context) {
	if err := m.cfg.Verifier.ClearChallenge(ctx); err != nil {
		m.cfg.Logger.Warn("public console: clear stale challenge", "err", err)
	}
}

// Status reports the current state.
func (m *Manager) Status(ctx context.Context) (Status, error) {
	cfg, err := m.cfg.Store.Load()
	if err != nil {
		return Status{}, &Error{Status: http.StatusInternalServerError, Code: "internal", Message: err.Error()}
	}
	var st Status
	if cfg != nil {
		at := cfg.EnabledAt
		st = Status{Enabled: true, Domain: cfg.Domain, URL: "https://" + cfg.Domain, EnabledAt: &at}
	}
	m.mu.Lock()
	if m.pending != nil && m.cfg.Now().Before(m.pending.expires) {
		st.Verifying = m.pending.domain
	}
	m.mu.Unlock()
	return st, nil
}

func (m *Manager) publicIPs(ctx context.Context) PublicIPs {
	m.mu.Lock()
	if len(m.ips.All()) > 0 && m.cfg.Now().Sub(m.ipsAt) < ipCacheTTL {
		ips := m.ips
		m.mu.Unlock()
		return ips
	}
	m.mu.Unlock()
	ips := DetectPublicIPs(ctx, m.cfg.Fetch)
	if len(ips.All()) > 0 {
		m.mu.Lock()
		m.ips, m.ipsAt = ips, m.cfg.Now()
		m.mu.Unlock()
	}
	return ips
}

func invalidDomain(domain string) error {
	return &Error{Status: http.StatusBadRequest, Code: "invalid_domain",
		Message: fmt.Sprintf("域名 %q 不合法：请填写完整的域名，例如 panel.example.com（不要带 http:// 或端口）", domain)}
}

// StartVerify detects this server's public addresses and starts serving an
// HTTP challenge for domain on port 80.
func (m *Manager) StartVerify(ctx context.Context, domain string) (VerifyInfo, error) {
	d, ok := NormalizeDomain(domain)
	if !ok {
		return VerifyInfo{}, invalidDomain(domain)
	}
	if m.cfg.Domains != nil {
		names, err := m.cfg.Domains(ctx)
		if err != nil {
			return VerifyInfo{}, &Error{Status: http.StatusInternalServerError, Code: "internal", Message: err.Error()}
		}
		for _, n := range names {
			if n == d {
				return VerifyInfo{}, &Error{Status: http.StatusConflict, Code: "domain_in_use",
					Message: fmt.Sprintf("域名 %s 已绑定到一个应用；公网控制台请用另一个域名（例如 panel.%s）", d, d)}
			}
		}
	}
	ips := m.publicIPs(ctx)
	if len(ips.All()) == 0 {
		return VerifyInfo{}, &Error{Status: http.StatusBadGateway, Code: "public_ip_unknown",
			Message: "无法获取本服务器的公网 IP：云厂商元数据和公共查询接口都没有响应。请确认服务器有公网 IP 并能访问外网。"}
	}
	id, err := randomHex(8)
	if err != nil {
		return VerifyInfo{}, err
	}
	token, err := randomHex(16)
	if err != nil {
		return VerifyInfo{}, err
	}
	path := VerifyPathPrefix + id
	if err := m.cfg.Verifier.SetChallenge(ctx, d, path, token); err != nil {
		return VerifyInfo{}, &Error{Status: http.StatusBadGateway, Code: "caddy_unavailable",
			Message: "无法在 Caddy 上设置域名验证：" + err.Error()}
	}
	m.mu.Lock()
	m.pending = &pendingVerify{domain: d, id: id, token: token, expires: m.cfg.Now().Add(VerifyTTL)}
	if m.timer != nil {
		m.timer.Stop()
	}
	m.timer = time.AfterFunc(VerifyTTL, func() { m.expire(id) })
	m.mu.Unlock()
	return VerifyInfo{Domain: d, VerifyID: id, Path: path, Token: token, IPs: ips, ExpiresIn: int(VerifyTTL.Seconds())}, nil
}

// expire clears the challenge of verification id if it is still pending.
func (m *Manager) expire(id string) {
	m.mu.Lock()
	if m.pending == nil || m.pending.id != id {
		m.mu.Unlock()
		return
	}
	m.pending = nil
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m.Cleanup(ctx)
}

// Enable turns the public console on for domain. verifyID must come from a
// StartVerify of the same domain that has not expired. When the console is
// already on for domain and resetPassword is false, nothing changes.
func (m *Manager) Enable(ctx context.Context, domain, verifyID string, resetPassword bool) (EnableResult, error) {
	d, ok := NormalizeDomain(domain)
	if !ok {
		return EnableResult{}, invalidDomain(domain)
	}
	cur, err := m.cfg.Store.Load()
	if err != nil {
		return EnableResult{}, &Error{Status: http.StatusInternalServerError, Code: "internal", Message: err.Error()}
	}
	if cur != nil && cur.Domain == d && !resetPassword {
		m.clearPending(ctx)
		m.cfg.Routes.RefreshRoutes(ctx)
		return EnableResult{Domain: d, URL: "https://" + d, AlreadyEnabled: true}, nil
	}

	m.mu.Lock()
	p := m.pending
	valid := p != nil && p.domain == d && p.id == verifyID && m.cfg.Now().Before(p.expires)
	m.mu.Unlock()
	if !valid {
		return EnableResult{}, &Error{Status: http.StatusConflict, Code: "verify_required",
			Message: "请先完成域名验证：运行 acornfox public-console enable " + d}
	}

	password, err := GeneratePassword()
	if err != nil {
		return EnableResult{}, err
	}
	if cur != nil {
		m.revoke(ctx, cur)
	}
	if err := m.cfg.Store.Save(&Config{Domain: d, PasswordSHA256: Digest(password), EnabledAt: m.cfg.Now().UTC()}); err != nil {
		return EnableResult{}, &Error{Status: http.StatusInternalServerError, Code: "internal", Message: err.Error()}
	}
	m.clearPending(ctx)
	m.cfg.Routes.RefreshRoutes(ctx)
	return EnableResult{Domain: d, URL: "https://" + d, Password: password}, nil
}

// Disable turns the public console off: the route goes away, the
// configuration is deleted and every session issued by the gateway is
// revoked. It reports whether the console was on.
func (m *Manager) Disable(ctx context.Context) (bool, error) {
	cur, err := m.cfg.Store.Load()
	if err != nil {
		return false, &Error{Status: http.StatusInternalServerError, Code: "internal", Message: err.Error()}
	}
	if cur != nil {
		m.revoke(ctx, cur)
	}
	if err := m.cfg.Store.Delete(); err != nil {
		return false, &Error{Status: http.StatusInternalServerError, Code: "internal", Message: err.Error()}
	}
	m.clearPending(ctx)
	m.cfg.Routes.RefreshRoutes(ctx)
	return cur != nil, nil
}

func (m *Manager) revoke(ctx context.Context, cfg *Config) {
	for _, s := range cfg.Sessions {
		if err := m.cfg.Sessions.RevokeConsoleSessionDigest(ctx, s.Digest); err != nil {
			m.cfg.Logger.Warn("public console: revoke session", "err", err)
		}
	}
}

func (m *Manager) clearPending(ctx context.Context) {
	m.mu.Lock()
	m.pending = nil
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
	m.mu.Unlock()
	m.Cleanup(ctx)
}
