// Package auth implements the single-administrator credential and session
// boundary. It owns raw password/token handling only for one request; storage
// receives encoded password hashes and SHA-256 digests exclusively.
package auth

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/acornfox/acornfox/internal/domain"
)

const (
	PasswordHashScheme      = "pbkdf2-sha256-v1"
	PasswordHashPrefix      = "pbkdf2-sha256"
	MinimumPBKDF2Iterations = 600_000
	maximumPBKDF2Iterations = 5_000_000
	pbkdf2SaltBytes         = 16
	pbkdf2KeyBytes          = 32
	tokenBytes              = 32
	minimumPasswordRunes    = 15
	maximumPasswordBytes    = 1024
)

var (
	ErrAuthenticationFailed = errors.New("authentication failed")
	// ErrAuthenticationUnavailable is deliberately separate from an invalid
	// credential or session. HTTP callers use it to return a retryable 503
	// without clearing a browser's potentially still-valid cookies.
	ErrAuthenticationUnavailable = errors.New("authentication persistence unavailable")
	ErrRateLimited               = domain.ErrRateLimited
	ErrOriginDenied              = errors.New("request origin denied")
	ErrCSRFInvalid               = errors.New("csrf validation failed")
	ErrPasswordPolicy            = errors.New("password does not meet the required policy")

	// Neutral shared sentinels aliased from domain.
	ErrNotFound                  = domain.ErrObjectNotFound
	ErrCredentialVersionConflict = domain.ErrCredentialVersionConflict
)

type Store interface {
	ActiveAdminCredential(context.Context) (domain.AdminCredential, error)
	RotateAdminCredential(context.Context, domain.ID, int64, string, string, time.Time) (domain.AdminCredential, error)
	CreateAdminSession(context.Context, domain.AdminSession) error
	ActiveAdminSessionByDigest(context.Context, domain.AuthDigest, time.Time) (domain.AdminSession, error)
	TouchAdminSession(context.Context, domain.ID, int64, time.Time) (domain.AdminSession, error)
	RevokeAdminSession(context.Context, domain.ID, time.Time) error
	UpsertAdminLoginRateLimit(context.Context, domain.AdminLoginRateLimit) error
	AdminLoginRateLimit(context.Context, domain.ID, domain.AuthDigest) (domain.AdminLoginRateLimit, error)
	RecordAdminLoginFailure(ctx context.Context, adminID domain.ID, sourceDigest domain.AuthDigest, now time.Time) (domain.AdminLoginRateLimit, error)
	CreateAdminSessionIfLoginAllowed(ctx context.Context, session domain.AdminSession, sourceDigest domain.AuthDigest, now time.Time) error
}

type Config struct {
	Store      Store
	Origin     string
	Iterations int
	Random     io.Reader
	Clock      func() time.Time
}

type Service struct {
	store         Store
	origin        string
	iterations    int
	minIterations int
	random        io.Reader
	clock         func() time.Time
}

type LoginResult struct {
	SessionToken string
	CSRFTok      string
	Session      domain.AdminSession
}

type SessionInfo struct {
	Authenticated bool
	IdleExpiresAt time.Time
	AbsoluteAt    time.Time
}

const ExactLocalLoopbackOrigin = "http://127.0.0.1:8080"

func NewService(config Config) (*Service, error) { return newService(config, false) }

func NewLocalService(config Config) (*Service, error) { return newLocalService(config, false) }

// newService permits lower PBKDF2 iterations only for package-local unit tests.
// Production callers must use NewService, which enforces the fixed minimum.
func newService(config Config, allowTestParameters bool) (*Service, error) {
	return newServiceInternal(config, allowTestParameters, false)
}

func newLocalService(config Config, allowTestParameters bool) (*Service, error) {
	return newServiceInternal(config, allowTestParameters, true)
}

func newServiceInternal(config Config, allowTestParameters bool, allowLocalLoopback bool) (*Service, error) {
	if config.Store == nil {
		return nil, errors.New("auth store is required")
	}
	var origin string
	if allowLocalLoopback {
		trimmed := strings.TrimSpace(config.Origin)
		if trimmed == "" || trimmed != config.Origin {
			return nil, errors.New("local auth origin must not contain leading or trailing whitespace")
		}
		parsed, err := url.Parse(trimmed)
		if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, errors.New("local auth origin must be an exact loopback HTTP origin")
		}
		host, portStr, err := net.SplitHostPort(parsed.Host)
		if err != nil {
			return nil, errors.New("local auth origin must include explicit host and port")
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, errors.New("local auth origin must use a loopback IP address")
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("local auth origin port is invalid")
		}
		origin = parsed.String()
	} else {
		trimmed := strings.TrimSpace(config.Origin)
		if trimmed != "" {
			parsed, err := url.Parse(trimmed)
			if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
				return nil, errors.New("auth origin must be an exact HTTPS origin")
			}
			origin = parsed.String()
		}
	}
	iterations := config.Iterations
	if iterations == 0 {
		iterations = MinimumPBKDF2Iterations
	}
	if iterations > maximumPBKDF2Iterations || (!allowTestParameters && iterations < MinimumPBKDF2Iterations) || (allowTestParameters && iterations < 1) {
		return nil, errors.New("PBKDF2 iterations are outside the allowed range")
	}
	random := config.Random
	if random == nil {
		random = rand.Reader
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	minimum := MinimumPBKDF2Iterations
	if allowTestParameters {
		minimum = iterations
	}
	return &Service{store: config.Store, origin: origin, iterations: iterations, minIterations: minimum, random: random, clock: clock}, nil
}

func (s *Service) RequireOrigin(origin string) error {
	if s == nil || s.origin == "" || subtle.ConstantTimeCompare([]byte(origin), []byte(s.origin)) != 1 {
		return ErrOriginDenied
	}
	return nil
}

func (s *Service) Login(ctx context.Context, origin, password, source string) (LoginResult, error) {
	if err := s.RequireOrigin(origin); err != nil {
		return LoginResult{}, err
	}
	credential, err := s.store.ActiveAdminCredential(ctx)
	if err != nil {
		return LoginResult{}, authenticationStoreError(err)
	}
	now := s.now()
	sourceDigest := digestSource(source)
	if limit, limitErr := s.store.AdminLoginRateLimit(ctx, credential.ID, sourceDigest); limitErr == nil && limit.LockedUntil != nil && now.Before(*limit.LockedUntil) {
		return LoginResult{}, ErrRateLimited
	} else if limitErr != nil && !errors.Is(limitErr, ErrNotFound) {
		return LoginResult{}, ErrAuthenticationUnavailable
	}
	valid, verifyErr := verifyPassword(password, credential.PasswordHash, s.minIterations)
	if verifyErr != nil || !valid {
		if err := s.recordLoginFailure(ctx, credential.ID, sourceDigest, s.now()); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{}, ErrAuthenticationFailed
	}
	sessionToken, sessionDigest, err := s.newToken()
	if err != nil {
		return LoginResult{}, err
	}
	csrfToken, csrfDigest, err := s.newToken()
	if err != nil {
		return LoginResult{}, err
	}
	id, err := domain.NewID("session")
	if err != nil {
		return LoginResult{}, err
	}
	postVerifyNow := s.now()
	session := domain.AdminSession{
		ID:                id,
		AdminID:           credential.ID,
		SessionDigest:     sessionDigest,
		CSRFDigest:        csrfDigest,
		CredentialVersion: credential.CredentialVersion,
		CreatedAt:         postVerifyNow,
		LastSeenAt:        postVerifyNow,
		IdleExpiresAt:     postVerifyNow.Add(domain.AdminSessionIdleTimeout),
		AbsoluteExpiresAt: postVerifyNow.Add(domain.AdminSessionAbsoluteTimeout),
	}
	if err := s.store.CreateAdminSessionIfLoginAllowed(ctx, session, sourceDigest, postVerifyNow); err != nil {
		if errors.Is(err, ErrRateLimited) {
			return LoginResult{}, ErrRateLimited
		}
		if errors.Is(err, ErrCredentialVersionConflict) || errors.Is(err, ErrNotFound) {
			return LoginResult{}, ErrAuthenticationFailed
		}
		return LoginResult{}, ErrAuthenticationUnavailable
	}
	return LoginResult{SessionToken: sessionToken, CSRFTok: csrfToken, Session: session}, nil
}

func (s *Service) Session(ctx context.Context, sessionToken string) (SessionInfo, domain.AdminSession, error) {
	session, err := s.session(ctx, sessionToken)
	if err != nil {
		return SessionInfo{}, domain.AdminSession{}, err
	}
	return SessionInfo{Authenticated: true, IdleExpiresAt: session.IdleExpiresAt, AbsoluteAt: session.AbsoluteExpiresAt}, session, nil
}

// AuthorizeControlPlaneWrite validates the session before origin and CSRF so
// callers never reveal whether a rejected Origin or CSRF token belongs to a
// valid session. The session-bound CSRF digest is compared in constant time.
func (s *Service) AuthorizeControlPlaneWrite(ctx context.Context, origin, sessionToken, csrfToken string) (domain.AdminSession, error) {
	session, err := s.session(ctx, sessionToken)
	if err != nil {
		return domain.AdminSession{}, err
	}
	if err := s.RequireOrigin(origin); err != nil {
		return domain.AdminSession{}, err
	}
	if !validCSRF(session, csrfToken) {
		return domain.AdminSession{}, ErrCSRFInvalid
	}
	return session, nil
}

func (s *Service) Logout(ctx context.Context, origin, sessionToken, csrfToken string) error {
	if err := s.RequireOrigin(origin); err != nil {
		return err
	}
	session, err := s.session(ctx, sessionToken)
	if err != nil {
		return err
	}
	if !validCSRF(session, csrfToken) {
		return ErrCSRFInvalid
	}
	if err := s.store.RevokeAdminSession(ctx, session.ID, s.now()); err != nil {
		return ErrAuthenticationUnavailable
	}
	return nil
}

func (s *Service) ChangePassword(ctx context.Context, origin, sessionToken, csrfToken, currentPassword, nextPassword string) error {
	if err := s.RequireOrigin(origin); err != nil {
		return err
	}
	session, err := s.session(ctx, sessionToken)
	if err != nil {
		return err
	}
	if !validCSRF(session, csrfToken) {
		return ErrCSRFInvalid
	}
	credential, err := s.store.ActiveAdminCredential(ctx)
	if err != nil {
		return authenticationStoreError(err)
	}
	if credential.ID != session.AdminID {
		return ErrAuthenticationFailed
	}
	valid, verifyErr := verifyPassword(currentPassword, credential.PasswordHash, s.minIterations)
	if verifyErr != nil || !valid {
		return ErrAuthenticationFailed
	}
	encoded, err := s.HashPassword(nextPassword)
	if err != nil {
		return err
	}
	if _, err = s.store.RotateAdminCredential(ctx, credential.ID, credential.CredentialVersion, PasswordHashScheme, encoded, s.now()); err != nil {
		return ErrAuthenticationUnavailable
	}
	return nil
}

func (s *Service) HashPassword(password string) (string, error) {
	if err := validatePassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, pbkdf2SaltBytes)
	if _, err := io.ReadFull(s.random, salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, s.iterations, pbkdf2KeyBytes)
	if err != nil {
		return "", fmt.Errorf("derive password hash: %w", err)
	}
	return fmt.Sprintf("$%s$i=%d,l=%d$%s$%s", PasswordHashPrefix, s.iterations, pbkdf2KeyBytes, base64.RawURLEncoding.EncodeToString(salt), base64.RawURLEncoding.EncodeToString(key)), nil
}

// VerifyPasswordHash is a pure credential-replay check used by the root-only
// bootstrap command. It neither creates a session nor touches rate limits.
func (s *Service) VerifyPasswordHash(password, encoded string) (bool, error) {
	if s == nil {
		return false, ErrAuthenticationUnavailable
	}
	if err := validatePassword(password); err != nil {
		return false, err
	}
	return verifyPassword(password, encoded, s.minIterations)
}

func (s *Service) recordLoginFailure(ctx context.Context, adminID domain.ID, source domain.AuthDigest, now time.Time) error {
	record, err := s.store.RecordAdminLoginFailure(ctx, adminID, source, now)
	if err != nil {
		if errors.Is(err, ErrRateLimited) {
			return ErrRateLimited
		}
		return ErrAuthenticationUnavailable
	}
	if record.LockedUntil != nil && now.Before(*record.LockedUntil) {
		return ErrRateLimited
	}
	return nil
}

func (s *Service) session(ctx context.Context, token string) (domain.AdminSession, error) {
	digest := digestToken(token)
	if digest == "" {
		return domain.AdminSession{}, ErrAuthenticationFailed
	}
	session, err := s.store.ActiveAdminSessionByDigest(ctx, digest, s.now())
	if err != nil {
		return domain.AdminSession{}, authenticationStoreError(err)
	}
	touched, err := s.store.TouchAdminSession(ctx, session.ID, session.CredentialVersion, s.now())
	if err != nil {
		return domain.AdminSession{}, authenticationStoreError(err)
	}
	return touched, nil
}

func authenticationStoreError(err error) error {
	if errors.Is(err, ErrNotFound) {
		return ErrAuthenticationFailed
	}
	return ErrAuthenticationUnavailable
}

func (s *Service) newToken() (string, domain.AuthDigest, error) {
	raw := make([]byte, tokenBytes)
	if _, err := io.ReadFull(s.random, raw); err != nil {
		return "", "", fmt.Errorf("generate session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	return token, digestBytes(raw), nil
}

func (s *Service) now() time.Time { return s.clock().UTC() }

func validatePassword(password string) error {
	if !utf8.ValidString(password) || strings.IndexByte(password, 0) >= 0 || len(password) > maximumPasswordBytes || utf8.RuneCountInString(password) < minimumPasswordRunes {
		return ErrPasswordPolicy
	}
	return nil
}

func verifyPassword(password, encoded string, minimumIterations int) (bool, error) {
	if !utf8.ValidString(password) || strings.IndexByte(password, 0) >= 0 || len(password) > maximumPasswordBytes {
		return false, errors.New("invalid password encoding")
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != PasswordHashPrefix {
		return false, errors.New("password hash encoding is invalid")
	}
	parameters := strings.Split(parts[2], ",")
	if len(parameters) != 2 || !strings.HasPrefix(parameters[0], "i=") || !strings.HasPrefix(parameters[1], "l=") {
		return false, errors.New("password hash parameters are invalid")
	}
	iterationText := strings.TrimPrefix(parameters[0], "i=")
	iterations, err := strconv.Atoi(iterationText)
	if err != nil || strconv.Itoa(iterations) != iterationText || iterations < minimumIterations || iterations > maximumPBKDF2Iterations {
		return false, errors.New("password hash iterations are invalid")
	}
	lengthText := strings.TrimPrefix(parameters[1], "l=")
	length, err := strconv.Atoi(lengthText)
	if err != nil || strconv.Itoa(length) != lengthText || length != pbkdf2KeyBytes {
		return false, errors.New("password hash length is invalid")
	}
	salt, err := base64.RawURLEncoding.Strict().DecodeString(parts[3])
	if err != nil || len(salt) != pbkdf2SaltBytes {
		return false, errors.New("password hash salt is invalid")
	}
	expected, err := base64.RawURLEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(expected) != pbkdf2KeyBytes {
		return false, errors.New("password hash key is invalid")
	}
	derived, err := pbkdf2.Key(sha256.New, password, salt, iterations, length)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(derived, expected) == 1, nil
}

func digestToken(token string) domain.AuthDigest {
	if token == "" || len(token) > 256 {
		return ""
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != tokenBytes {
		return ""
	}
	return digestBytes(decoded)
}

func digestSource(source string) domain.AuthDigest {
	return digestBytes([]byte("open-card-source-v1\x00" + source))
}

func digestBytes(value []byte) domain.AuthDigest {
	sum := sha256.Sum256(value)
	return domain.AuthDigest(hex.EncodeToString(sum[:]))
}

func validCSRF(session domain.AdminSession, token string) bool {
	return subtle.ConstantTimeCompare([]byte(digestToken(token)), []byte(session.CSRFDigest)) == 1
}
