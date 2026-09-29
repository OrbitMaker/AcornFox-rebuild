package state

import "time"

// N3: console login without passwords. `acornfox open` asks the trusted API
// (unix socket, reached over SSH) for a one-time token; the browser trades it
// for a session cookie on the console listener. Only SHA-256 digests of the
// token, session and CSRF secrets are stored.
const (
	ConsoleTokenTTL        = 60 * time.Second
	ConsoleSessionIdle     = 8 * time.Hour
	ConsoleSessionAbsolute = 24 * time.Hour
)

// ConsoleSession is an authenticated browser session.
type ConsoleSession struct {
	ID              string // random 16 hex, not secret
	CSRFDigest      string // sha256 hex of the CSRF token
	CreatedAt       time.Time
	LastSeenAt      time.Time
	IdleExpiresAt   time.Time
	AbsoluteExpires time.Time
	RevokedAt       *time.Time
}

// Domain statuses.
const (
	DomainPending = "pending" // added; certificate not yet confirmed
	DomainReady   = "ready"   // HTTPS handshake presents a valid certificate for the name
	DomainFailed  = "failed"  // pending for longer than DomainPendingBudget; Diagnosis explains
)

// DomainPendingBudget is how long a domain may stay pending before it is
// reported as failed (it keeps being retried).
const DomainPendingBudget = 10 * time.Minute

// Domain is a custom hostname routed to one app over HTTPS.
type Domain struct {
	App       string     `json:"app"`
	Name      string     `json:"name"` // lowercase, IDNA ASCII, no trailing dot, unique across apps
	Status    string     `json:"status"`
	Diagnosis *Diagnosis `json:"diagnosis,omitempty"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

/*
Store additions (migration 0004: console_tokens, console_sessions, app_domains):

	CreateConsoleToken(ctx) (token string, err error)            // 32 random bytes hex; stores digest + expiry (ConsoleTokenTTL)
	RedeemConsoleToken(ctx, token string) (s ConsoleSession, sessionSecret, csrfToken string, err error)
	    // single use: deletes the token; ErrNotFound when unknown/expired/used; creates a session
	TouchConsoleSession(ctx, sessionSecret string) (ConsoleSession, error) // ErrNotFound when unknown/expired/revoked; slides idle expiry
	RevokeConsoleSession(ctx, sessionSecret string) error
	PruneConsole(ctx) error                                       // deletes expired tokens and sessions

	AddDomain(ctx, app, name string) (Domain, bool, error)         // idempotent for same app; ErrConflict if another app has it
	RemoveDomain(ctx, app, name string) error
	ListDomains(ctx, app string) ([]Domain, error)                  // app "" = all apps
	SetDomainStatus(ctx, app, name, status string, diag *Diagnosis) error // sets CheckedAt=now
*/
