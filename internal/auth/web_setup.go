package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

const (
	WebSetupStateInitialized   WebSetupState = "initialized"
	WebSetupStateUninitialized WebSetupState = "uninitialized"
	WebSetupStateUnavailable   WebSetupState = "unavailable"
)

var (
	ErrWebSetupInitialized = errors.New("administrator setup is already complete")
	ErrWebSetupToken       = errors.New("administrator setup authentication failed")
	ErrWebSetupUnavailable = errors.New("administrator setup is unavailable")
)

// WebSetupState is the complete unauthenticated state vocabulary. It contains
// no database, credential-file, or operator-secret detail.
type WebSetupState string

// WebSetupStore keeps the HTTP bootstrap path behind the same durable
// administrator singleton as the root-only CLI. AdministratorExists must
// count historical disabled rows too: once any administrator has existed,
// web setup stays closed permanently.
type WebSetupStore interface {
	AdministratorExists(context.Context) (bool, error)
	CreateAdminCredential(context.Context, domain.AdminCredential) error
}

type WebSetupConfig struct {
	Store                WebSetupStore
	Auth                 *Service
	SetupTokenCredential []byte
	Clock                func() time.Time
}

type webSetupAttempt struct {
	windowExpires time.Time
	attempts      int
}

// WebSetupService owns the one-time unauthenticated bootstrap decision. It
// retains only a SHA-256 digest of the operator credential, never its raw
// bytes. Database state, rather than credential-file cleanup, is the durable
// single-use authority.
type WebSetupService struct {
	store       WebSetupStore
	auth        *Service
	tokenDigest domain.AuthDigest
	clock       func() time.Time

	attemptMu sync.Mutex
	attempt   webSetupAttempt
}

func NewWebSetupService(config WebSetupConfig) (*WebSetupService, error) {
	if config.Store == nil || config.Auth == nil {
		return nil, errors.New("web setup store and authentication service are required")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	service := &WebSetupService{store: config.Store, auth: config.Auth, clock: clock}
	if token := parseWebSetupCredential(config.SetupTokenCredential); token != "" {
		service.tokenDigest = digestToken(token)
	}
	return service, nil
}

func (s *WebSetupService) State(ctx context.Context) WebSetupState {
	if s == nil || s.store == nil {
		return WebSetupStateUnavailable
	}
	exists, err := s.store.AdministratorExists(ctx)
	if err != nil {
		return WebSetupStateUnavailable
	}
	if exists {
		return WebSetupStateInitialized
	}
	if s.tokenDigest == "" || s.auth == nil {
		return WebSetupStateUnavailable
	}
	return WebSetupStateUninitialized
}

// Setup creates exactly one administrator after validating the operator token
// and the configured HTTPS origin. A concurrent winner is reported as already
// initialized only after AdministratorExists observes its committed row.
func (s *WebSetupService) Setup(ctx context.Context, origin, setupToken, password string) error {
	if s == nil || s.store == nil || s.auth == nil {
		return ErrWebSetupUnavailable
	}
	exists, err := s.store.AdministratorExists(ctx)
	if err != nil {
		return ErrWebSetupUnavailable
	}
	if exists {
		return ErrWebSetupInitialized
	}
	if s.tokenDigest == "" {
		return ErrWebSetupUnavailable
	}
	if err := s.auth.RequireOrigin(origin); err != nil {
		return err
	}
	if !s.takeAttempt() {
		return ErrRateLimited
	}
	presented := digestToken(setupToken)
	if presented == "" || subtle.ConstantTimeCompare([]byte(presented), []byte(s.tokenDigest)) != 1 {
		return ErrWebSetupToken
	}
	hash, err := s.auth.HashPassword(password)
	if err != nil {
		return err
	}
	// Hashing is deliberately outside the database write. Re-check after that
	// expensive operation to avoid attempting a known-losing concurrent insert.
	exists, err = s.store.AdministratorExists(ctx)
	if err != nil {
		return ErrWebSetupUnavailable
	}
	if exists {
		return ErrWebSetupInitialized
	}
	now := s.now()
	id, err := domain.NewID("admin")
	if err != nil {
		return ErrWebSetupUnavailable
	}
	credential := domain.AdminCredential{ID: id, PasswordHashScheme: PasswordHashScheme, PasswordHash: hash, CredentialVersion: 1, CreatedAt: now, UpdatedAt: now}
	if err = s.store.CreateAdminCredential(ctx, credential); err == nil {
		return nil
	}
	// An insert can lose the database singleton race. Never infer that result
	// from an error string: only a fresh committed-row observation closes setup.
	exists, inspectErr := s.store.AdministratorExists(ctx)
	if inspectErr == nil && exists {
		return ErrWebSetupInitialized
	}
	return ErrWebSetupUnavailable
}

func (s *WebSetupService) takeAttempt() bool {
	// One global bucket keeps attacker-controlled forwarding headers from
	// allocating memory or multiplying the unauthenticated hashing budget.
	now := s.now()
	s.attemptMu.Lock()
	defer s.attemptMu.Unlock()
	attempt := s.attempt
	if attempt.windowExpires.IsZero() || !now.Before(attempt.windowExpires) {
		attempt = webSetupAttempt{windowExpires: now.Add(domain.AdminLoginFailureWindow)}
	}
	if attempt.attempts >= domain.AdminLoginMaxFailureAttempts {
		s.attempt = attempt
		return false
	}
	attempt.attempts++
	s.attempt = attempt
	return true
}

func (s *WebSetupService) now() time.Time { return s.clock().UTC() }

func parseWebSetupCredential(raw []byte) string {
	encodedLength := base64.RawURLEncoding.EncodedLen(tokenBytes)
	if len(raw) == encodedLength+1 && raw[len(raw)-1] == '\n' {
		raw = raw[:len(raw)-1]
	}
	if len(raw) != encodedLength {
		return ""
	}
	token := string(raw)
	if digestToken(token) == "" {
		return ""
	}
	return token
}
