package corehttp

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/auth"
	"github.com/open-card/open-card/internal/domain"
)

type authHTTPStore struct {
	credential domain.AdminCredential
	sessions   map[domain.AuthDigest]domain.AdminSession
	rates      map[domain.AuthDigest]domain.AdminLoginRateLimit
	sessionErr error
}

func (s *authHTTPStore) ActiveAdminCredential(context.Context) (domain.AdminCredential, error) {
	if s.credential.ID.Empty() {
		return domain.AdminCredential{}, auth.ErrNotFound
	}
	return s.credential, nil
}

func (s *authHTTPStore) RotateAdminCredential(_ context.Context, id domain.ID, expected int64, scheme, hash string, now time.Time) (domain.AdminCredential, error) {
	if s.credential.ID != id || s.credential.CredentialVersion != expected {
		return domain.AdminCredential{}, auth.ErrCredentialVersionConflict
	}
	s.credential.PasswordHashScheme, s.credential.PasswordHash = scheme, hash
	s.credential.CredentialVersion++
	s.credential.UpdatedAt = now
	return s.credential, nil
}

func (s *authHTTPStore) CreateAdminSession(_ context.Context, session domain.AdminSession) error {
	if s.sessions == nil {
		s.sessions = map[domain.AuthDigest]domain.AdminSession{}
	}
	s.sessions[session.SessionDigest] = session
	return nil
}

func (s *authHTTPStore) ActiveAdminSessionByDigest(_ context.Context, digest domain.AuthDigest, now time.Time) (domain.AdminSession, error) {
	if s.sessionErr != nil {
		return domain.AdminSession{}, s.sessionErr
	}
	session, ok := s.sessions[digest]
	if !ok || session.RevokedAt != nil || !now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) || session.CredentialVersion != s.credential.CredentialVersion {
		return domain.AdminSession{}, auth.ErrNotFound
	}
	return session, nil
}

func (s *authHTTPStore) TouchAdminSession(_ context.Context, id domain.ID, credentialVersion int64, now time.Time) (domain.AdminSession, error) {
	for digest, session := range s.sessions {
		if session.ID == id && session.CredentialVersion == credentialVersion && now.Before(session.IdleExpiresAt) && now.Before(session.AbsoluteExpiresAt) {
			session.LastSeenAt = now
			session.IdleExpiresAt = now.Add(domain.AdminSessionIdleTimeout)
			if session.IdleExpiresAt.After(session.AbsoluteExpiresAt) {
				session.IdleExpiresAt = session.AbsoluteExpiresAt
			}
			s.sessions[digest] = session
			return session, nil
		}
	}
	return domain.AdminSession{}, auth.ErrNotFound
}

func (s *authHTTPStore) RevokeAdminSession(_ context.Context, id domain.ID, now time.Time) error {
	for digest, session := range s.sessions {
		if session.ID == id {
			session.RevokedAt = &now
			s.sessions[digest] = session
			return nil
		}
	}
	return auth.ErrNotFound
}

func (s *authHTTPStore) UpsertAdminLoginRateLimit(_ context.Context, record domain.AdminLoginRateLimit) error {
	if s.rates == nil {
		s.rates = map[domain.AuthDigest]domain.AdminLoginRateLimit{}
	}
	s.rates[record.SourceDigest] = record
	return nil
}

func (s *authHTTPStore) AdminLoginRateLimit(_ context.Context, _ domain.ID, digest domain.AuthDigest) (domain.AdminLoginRateLimit, error) {
	record, ok := s.rates[digest]
	if !ok {
		return domain.AdminLoginRateLimit{}, auth.ErrNotFound
	}
	return record, nil
}

func (s *authHTTPStore) RecordAdminLoginFailure(_ context.Context, adminID domain.ID, source domain.AuthDigest, now time.Time) (domain.AdminLoginRateLimit, error) {
	if s.rates == nil {
		s.rates = map[domain.AuthDigest]domain.AdminLoginRateLimit{}
	}
	var existing *domain.AdminLoginRateLimit
	if rec, ok := s.rates[source]; ok {
		existing = &rec
	}
	next := domain.TransitionAdminLoginRateLimit(existing, adminID, source, now)
	s.rates[source] = next
	return next, nil
}

func (s *authHTTPStore) CreateAdminSessionIfLoginAllowed(ctx context.Context, session domain.AdminSession, source domain.AuthDigest, now time.Time) error {
	if s.credential.ID != session.AdminID || s.credential.DisabledAt != nil {
		return auth.ErrNotFound
	}
	if s.credential.CredentialVersion != session.CredentialVersion {
		return auth.ErrCredentialVersionConflict
	}
	if rec, ok := s.rates[source]; ok && rec.IsLocked(now) {
		return auth.ErrRateLimited
	}
	return s.CreateAdminSession(ctx, session)
}

func newAuthHTTPTestHandler(t *testing.T, now *time.Time) (http.Handler, *authHTTPStore, string) {
	t.Helper()
	store := &authHTTPStore{}
	service, err := auth.NewService(auth.Config{Store: store, Origin: "https://console.example.test", Clock: func() time.Time { return *now }})
	if err != nil {
		t.Fatal(err)
	}
	password := "http correct horse battery staple 123"
	hash, err := service.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	store.credential = domain.AdminCredential{ID: "admin_1", PasswordHashScheme: auth.PasswordHashScheme, PasswordHash: hash, CredentialVersion: 1, CreatedAt: *now, UpdatedAt: *now}
	authHandler := &AuthHTTPHandler{Service: service}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authHandler.Handle(w, r) {
			return
		}
		http.NotFound(w, r)
	})
	return handler, store, password
}

func authRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:49152"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://console.example.test")
	return request
}

func cookieValue(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func TestAuthHTTPLoginSessionCSRFLogoutAndRotation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	handler, _, password := newAuthHTTPTestHandler(t, &now)
	login := httptest.NewRecorder()
	handler.ServeHTTP(login, authRequest(http.MethodPost, "/api/v1/auth/login", `{"password":"`+password+`"}`))
	if login.Code != http.StatusOK || login.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("login status=%d headers=%v body=%s", login.Code, login.Header(), login.Body.String())
	}
	cookies := login.Result().Cookies()
	sessionCookie, csrfCookie := cookieValue(cookies, AuthSessionCookie), cookieValue(cookies, AuthCSRFCookie)
	if sessionCookie == nil || csrfCookie == nil || !sessionCookie.Secure || !sessionCookie.HttpOnly || csrfCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteStrictMode || csrfCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("invalid auth cookies: %#v %#v", sessionCookie, csrfCookie)
	}
	session := authRequest(http.MethodGet, "/api/v1/auth/session", "")
	session.Header.Del("Content-Type")
	session.AddCookie(sessionCookie)
	sessionRecorder := httptest.NewRecorder()
	handler.ServeHTTP(sessionRecorder, session)
	if sessionRecorder.Code != http.StatusOK {
		t.Fatalf("session status=%d body=%s", sessionRecorder.Code, sessionRecorder.Body.String())
	}
	wrongOrigin := authRequest(http.MethodPost, "/api/v1/auth/password", `{"current_password":"`+password+`","new_password":"rotated correct horse battery staple 456"}`)
	wrongOrigin.Header.Set("Origin", "https://other.example.test")
	wrongOrigin.AddCookie(sessionCookie)
	wrongOrigin.AddCookie(csrfCookie)
	wrongOrigin.Header.Set(AuthCSRFHeader, csrfCookie.Value)
	wrongRecorder := httptest.NewRecorder()
	handler.ServeHTTP(wrongRecorder, wrongOrigin)
	if wrongRecorder.Code != http.StatusUnauthorized || strings.Contains(wrongRecorder.Body.String(), "origin") {
		t.Fatalf("origin denial leaked detail: %d %s", wrongRecorder.Code, wrongRecorder.Body.String())
	}
	wrongCSRF := authRequest(http.MethodPost, "/api/v1/auth/password", `{"current_password":"`+password+`","new_password":"rotated correct horse battery staple 456"}`)
	wrongCSRF.AddCookie(sessionCookie)
	wrongCSRF.AddCookie(csrfCookie)
	wrongCSRF.Header.Set(AuthCSRFHeader, "not-the-cookie")
	wrongCSRFRecorder := httptest.NewRecorder()
	handler.ServeHTTP(wrongCSRFRecorder, wrongCSRF)
	if wrongCSRFRecorder.Code != http.StatusUnauthorized || strings.Contains(wrongCSRFRecorder.Body.String(), "csrf") {
		t.Fatalf("CSRF denial leaked detail: %d %s", wrongCSRFRecorder.Code, wrongCSRFRecorder.Body.String())
	}
	rotate := authRequest(http.MethodPost, "/api/v1/auth/password", `{"current_password":"`+password+`","new_password":"rotated correct horse battery staple 456"}`)
	rotate.AddCookie(sessionCookie)
	rotate.AddCookie(csrfCookie)
	rotate.Header.Set(AuthCSRFHeader, csrfCookie.Value)
	rotateRecorder := httptest.NewRecorder()
	handler.ServeHTTP(rotateRecorder, rotate)
	if rotateRecorder.Code != http.StatusNoContent {
		t.Fatalf("rotate status=%d body=%s", rotateRecorder.Code, rotateRecorder.Body.String())
	}
	oldSession := authRequest(http.MethodGet, "/api/v1/auth/session", "")
	oldSession.Header.Del("Content-Type")
	oldSession.AddCookie(sessionCookie)
	oldRecorder := httptest.NewRecorder()
	handler.ServeHTTP(oldRecorder, oldSession)
	if oldRecorder.Code != http.StatusUnauthorized || len(oldRecorder.Result().Cookies()) != 2 {
		t.Fatalf("old session status=%d cookies=%#v", oldRecorder.Code, oldRecorder.Result().Cookies())
	}
}

func TestAuthHTTPRejectsInvalidJSONExpiryAndRateLimitWithoutDetail(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	handler, store, password := newAuthHTTPTestHandler(t, &now)
	invalid := httptest.NewRecorder()
	handler.ServeHTTP(invalid, authRequest(http.MethodPost, "/api/v1/auth/login", `{"password":"`+password+`","extra":true}`))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("unknown JSON status=%d", invalid.Code)
	}
	lockedAt := now
	store.rates = map[domain.AuthDigest]domain.AdminLoginRateLimit{}
	source := AuthSource(authRequest(http.MethodPost, "/api/v1/auth/login", ""))
	digest := authDigestForHTTPSource(source)
	store.rates[digest] = domain.AdminLoginRateLimit{AdminID: store.credential.ID, SourceDigest: digest, WindowStartedAt: now, WindowExpiresAt: now.Add(domain.AdminLoginFailureWindow), FailureCount: domain.AdminLoginMaxFailureAttempts, LastFailureAt: lockedAt, LockedAt: &lockedAt, LockedUntil: pointerHTTPTime(now.Add(domain.AdminLoginLockoutDuration)), UpdatedAt: now}
	limited := httptest.NewRecorder()
	handler.ServeHTTP(limited, authRequest(http.MethodPost, "/api/v1/auth/login", `{"password":"`+password+`"}`))
	if limited.Code != http.StatusTooManyRequests || strings.Contains(limited.Body.String(), "locked") || !strings.Contains(limited.Body.String(), "authentication failed") {
		t.Fatalf("rate limit response=%d %s", limited.Code, limited.Body.String())
	}
	now = now.Add(9 * time.Hour)
	expired := authRequest(http.MethodGet, "/api/v1/auth/session", "")
	expired.Header.Del("Content-Type")
	expiredRecorder := httptest.NewRecorder()
	handler.ServeHTTP(expiredRecorder, expired)
	if expiredRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("missing/expired session status=%d", expiredRecorder.Code)
	}
}

func TestAuthHTTPLogoutClearsBothCookiesAndExpiredSessionFails(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	handler, _, password := newAuthHTTPTestHandler(t, &now)
	login := httptest.NewRecorder()
	handler.ServeHTTP(login, authRequest(http.MethodPost, "/api/v1/auth/login", `{"password":"`+password+`"}`))
	sessionCookie, csrfCookie := cookieValue(login.Result().Cookies(), AuthSessionCookie), cookieValue(login.Result().Cookies(), AuthCSRFCookie)
	if sessionCookie == nil || csrfCookie == nil {
		t.Fatal("login did not issue both cookies")
	}
	now = now.Add(9 * time.Hour)
	expired := authRequest(http.MethodGet, "/api/v1/auth/session", "")
	expired.Header.Del("Content-Type")
	expired.AddCookie(sessionCookie)
	expiredRecorder := httptest.NewRecorder()
	handler.ServeHTTP(expiredRecorder, expired)
	if expiredRecorder.Code != http.StatusUnauthorized || len(expiredRecorder.Result().Cookies()) != 2 {
		t.Fatalf("expired session status=%d cookies=%#v", expiredRecorder.Code, expiredRecorder.Result().Cookies())
	}
	now = now.Add(-9 * time.Hour)
	logout := authRequest(http.MethodPost, "/api/v1/auth/logout", "")
	logout.Header.Del("Content-Type")
	logout.AddCookie(sessionCookie)
	logout.AddCookie(csrfCookie)
	logout.Header.Set(AuthCSRFHeader, csrfCookie.Value)
	logoutRecorder := httptest.NewRecorder()
	handler.ServeHTTP(logoutRecorder, logout)
	if logoutRecorder.Code != http.StatusNoContent {
		t.Fatalf("logout status=%d body=%s", logoutRecorder.Code, logoutRecorder.Body.String())
	}
	clearedSession, clearedCSRF := cookieValue(logoutRecorder.Result().Cookies(), AuthSessionCookie), cookieValue(logoutRecorder.Result().Cookies(), AuthCSRFCookie)
	if clearedSession == nil || clearedCSRF == nil || clearedSession.MaxAge >= 0 || clearedCSRF.MaxAge >= 0 {
		t.Fatalf("logout did not clear both cookies: %#v %#v", clearedSession, clearedCSRF)
	}
}

func TestAuthOpenAPIStructureIsDeclared(t *testing.T) {
	payload, err := os.ReadFile("../../api/openapi/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, path := range []string{"/api/v1/auth/login:", "/api/v1/auth/logout:", "/api/v1/auth/session:", "/api/v1/auth/password:", "AuthLoginRequest:", "AuthSessionResponse:"} {
		if !strings.Contains(text, path) {
			t.Fatalf("OpenAPI is missing %s", path)
		}
	}
	if !strings.Contains(text, "AdministratorSession:\n      type: apiKey\n      in: cookie\n      name: __Host-open_card_session") {
		t.Fatal("OpenAPI does not declare the administrator session cookie scheme")
	}
	for _, protected := range []string{"/api/v1/auth/logout:\n    post:\n      operationId: logoutAdministrator\n      security: []", "/api/v1/auth/session:\n    get:\n      operationId: getAdministratorSession\n      security: []", "/api/v1/auth/password:\n    post:\n      operationId: rotateAdministratorPassword\n      security: []"} {
		if strings.Contains(text, protected) {
			t.Fatalf("OpenAPI incorrectly marks a session-bound auth endpoint public: %q", protected)
		}
	}
}

func authDigestForHTTPSource(source string) domain.AuthDigest {
	return domain.AuthDigest(sha256Hex("open-card-source-v1\x00" + source))
}

func sha256Hex(value string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
}

func pointerHTTPTime(value time.Time) *time.Time { return &value }
