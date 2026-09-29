package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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

func attachTestAdministrator(t *testing.T, server *Server, now *time.Time) (*authHTTPStore, *http.Cookie) {
	store, session, _ := attachTestAdministratorTokens(t, server, now)
	return store, session
}

func attachTestAdministratorTokens(t *testing.T, server *Server, now *time.Time) (*authHTTPStore, *http.Cookie, *http.Cookie) {
	t.Helper()
	store := &authHTTPStore{}
	service, err := auth.NewService(auth.Config{Store: store, Origin: "https://console.example.test", Clock: func() time.Time { return *now }})
	if err != nil {
		t.Fatal(err)
	}
	password := "control plane correct horse battery staple 123"
	hash, err := service.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	store.credential = domain.AdminCredential{ID: "admin_1", PasswordHashScheme: auth.PasswordHashScheme, PasswordHash: hash, CredentialVersion: 1, CreatedAt: *now, UpdatedAt: *now}
	login, err := service.Login(context.Background(), "https://console.example.test", password, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	server.SetAuth(&AuthHTTPHandler{Service: service})
	return store, &http.Cookie{Name: authSessionCookie, Value: login.SessionToken, Path: "/"}, &http.Cookie{Name: authCSRFCookie, Value: login.CSRFTok, Path: "/"}
}

func controlPlaneRequest(method, target string, body io.Reader, session *http.Cookie) *http.Request {
	request := httptest.NewRequest(method, target, body)
	if session != nil {
		request.AddCookie(session)
	}
	return request
}

func addControlPlaneWriteProof(request *http.Request, csrf *http.Cookie) {
	request.Header.Set("Origin", "https://console.example.test")
	request.AddCookie(csrf)
	request.Header.Set(authCSRFHeader, csrf.Value)
}

func TestControlPlaneAuthRejectsAnonymousAndForgedIdentityHeaders(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	server := newServerWithReadySourceUpload(t)
	_, session, _ := attachTestAdministratorTokens(t, server, &now)

	forged := controlPlaneRequest(http.MethodGet, "/api/v1/applications", nil, nil)
	forged.Header.Set("Open-Card-Role", "operator")
	forged.Header.Set("Open-Card-Actor", "forged-admin")
	forged.Header.Set("X-Open-Card-Role", "operator")
	forged.Header.Set("X-Open-Card-Actor", "forged-admin")
	forged.AddCookie(&http.Cookie{Name: authSessionCookie, Value: "invalid"})
	denied := httptest.NewRecorder()
	server.Handler().ServeHTTP(denied, forged)
	if denied.Code != http.StatusUnauthorized || strings.Contains(denied.Body.String(), "forged-admin") || len(denied.Result().Cookies()) != 2 {
		t.Fatalf("forged request status=%d cookies=%#v body=%s", denied.Code, denied.Result().Cookies(), denied.Body.String())
	}

	health := httptest.NewRecorder()
	server.Handler().ServeHTTP(health, controlPlaneRequest(http.MethodGet, "/healthz", nil, nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health must remain public: %d %s", health.Code, health.Body.String())
	}
	readiness := httptest.NewRecorder()
	server.Handler().ServeHTTP(readiness, controlPlaneRequest(http.MethodGet, "/readyz", nil, nil))
	if readiness.Code != http.StatusOK {
		t.Fatalf("readiness must remain public: %d %s", readiness.Code, readiness.Body.String())
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		for _, method := range []string{http.MethodPost, http.MethodOptions, http.MethodDelete} {
			denied := httptest.NewRecorder()
			server.Handler().ServeHTTP(denied, controlPlaneRequest(method, path, nil, nil))
			if denied.Code != http.StatusMethodNotAllowed || denied.Header().Get("Allow") != http.MethodGet {
				t.Fatalf("anonymous health path %s method %s status=%d allow=%q", path, method, denied.Code, denied.Header().Get("Allow"))
			}
		}
	}

	allowed := httptest.NewRecorder()
	server.Handler().ServeHTTP(allowed, controlPlaneRequest(http.MethodGet, "/api/v1/applications", nil, session))
	if allowed.Code != http.StatusOK {
		t.Fatalf("authenticated list=%d %s", allowed.Code, allowed.Body.String())
	}
}

func TestControlPlaneAuthProtectsReadinessWritesAndSSE(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	server := newServerWithReadySourceUpload(t)
	_, session, csrf := attachTestAdministratorTokens(t, server, &now)

	protected := []string{
		"/api/v1/applications",
		"/api/v1/events",
		"/api/v1/access/platform-domains",
		"/api/v1/operations/views/app_test?environment_id=env_test",
		"/api/v1/applications/app_test/usage",
		"/api/v1/applications/app_test/ai/interventions",
		"/api/v1/applications/app_test/webhooks",
		"/api/v1/settings/ai",
	}
	for _, target := range protected {
		denied := httptest.NewRecorder()
		server.Handler().ServeHTTP(denied, controlPlaneRequest(http.MethodGet, target, nil, nil))
		if denied.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous %s status=%d body=%s", target, denied.Code, denied.Body.String())
		}
	}
	for _, target := range protected {
		if target == "/api/v1/events" {
			continue // SSE is exercised below with a cancelled request context.
		}
		allowed := httptest.NewRecorder()
		server.Handler().ServeHTTP(allowed, controlPlaneRequest(http.MethodGet, target, nil, session))
		if allowed.Code == http.StatusUnauthorized {
			t.Fatalf("authenticated request did not reach %s: %d %s", target, allowed.Code, allowed.Body.String())
		}
	}

	created := httptest.NewRecorder()
	create := controlPlaneRequest(http.MethodPost, "/api/v1/applications", strings.NewReader(`{"name":"authenticated","source":`+readySourceUploadJSON+`}`), session)
	create.Header.Set("Content-Type", "application/json")
	create.Header.Set("Idempotency-Key", "authenticated-create")
	addControlPlaneWriteProof(create, csrf)
	server.Handler().ServeHTTP(created, create)
	if created.Code != http.StatusCreated {
		t.Fatalf("authenticated create=%d %s", created.Code, created.Body.String())
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sseRequest := controlPlaneRequest(http.MethodGet, "/api/v1/events", nil, session).WithContext(ctx)
	sse := httptest.NewRecorder()
	server.Handler().ServeHTTP(sse, sseRequest)
	if sse.Code != http.StatusOK || !strings.Contains(sse.Body.String(), ": connected") {
		t.Fatalf("authenticated SSE=%d %s", sse.Code, sse.Body.String())
	}
}

func TestControlPlaneAuthExpiresSessionsAndReportsStoreFailure(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	server := newServerWithReadySourceUpload(t)
	store, session := attachTestAdministrator(t, server, &now)

	now = now.Add(domain.AdminSessionAbsoluteTimeout + time.Second)
	expired := httptest.NewRecorder()
	server.Handler().ServeHTTP(expired, controlPlaneRequest(http.MethodGet, "/api/v1/applications", nil, session))
	if expired.Code != http.StatusUnauthorized || len(expired.Result().Cookies()) != 2 {
		t.Fatalf("expired session status=%d cookies=%#v", expired.Code, expired.Result().Cookies())
	}

	now = time.Unix(1_700_000_000, 0).UTC()
	store.sessionErr = errors.New("temporary postgres outage")
	unavailable := httptest.NewRecorder()
	server.Handler().ServeHTTP(unavailable, controlPlaneRequest(http.MethodGet, "/api/v1/applications", nil, session))
	if unavailable.Code != http.StatusServiceUnavailable || len(unavailable.Result().Cookies()) != 0 || strings.Contains(unavailable.Body.String(), "postgres") {
		t.Fatalf("store failure status=%d cookies=%#v body=%s", unavailable.Code, unavailable.Result().Cookies(), unavailable.Body.String())
	}
}

func TestControlPlaneUnsafeRequestsRequireExactOriginAndSessionBoundCSRF(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	server := newServerWithReadySourceUpload(t)
	_, session, csrf := attachTestAdministratorTokens(t, server, &now)
	other, err := server.auth.Service.Login(context.Background(), "https://console.example.test", "control plane correct horse battery staple 123", "127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	otherSession := &http.Cookie{Name: authSessionCookie, Value: other.SessionToken, Path: "/"}
	otherCSRF := &http.Cookie{Name: authCSRFCookie, Value: other.CSRFTok, Path: "/"}

	request := func(session, csrf *http.Cookie, origin, csrfHeader string) *http.Request {
		value := controlPlaneRequest(http.MethodPost, "/api/v1/applications", strings.NewReader(`{"name":"csrf","source":`+readySourceUploadJSON+`}`), session)
		value.Header.Set("Content-Type", "application/json")
		value.Header.Set("Idempotency-Key", "csrf-contract")
		if csrf != nil {
			value.AddCookie(csrf)
			value.Header.Set(authCSRFHeader, csrf.Value)
		}
		if csrfHeader != "" {
			value.Header.Set(authCSRFHeader, csrfHeader)
		}
		if origin != "" {
			value.Header.Set("Origin", origin)
		}
		return value
	}
	for _, test := range []struct {
		name    string
		session *http.Cookie
		csrf    *http.Cookie
		origin  string
		header  string
		want    int
	}{
		{name: "missing session", origin: "https://other.example.test", want: http.StatusUnauthorized},
		{name: "missing origin", session: session, csrf: csrf, want: http.StatusUnauthorized},
		{name: "wrong origin", session: session, csrf: csrf, origin: "https://other.example.test", want: http.StatusUnauthorized},
		{name: "missing csrf", session: session, origin: "https://console.example.test", want: http.StatusUnauthorized},
		{name: "cross session csrf", session: session, csrf: otherCSRF, origin: "https://console.example.test", want: http.StatusUnauthorized},
		{name: "wrong csrf cookie header pair", session: otherSession, csrf: csrf, origin: "https://console.example.test", header: "wrong-csrf", want: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, request(test.session, test.csrf, test.origin, test.header))
			if recorder.Code != test.want || strings.Contains(recorder.Body.String(), "origin") || strings.Contains(recorder.Body.String(), "csrf") {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
	accepted := httptest.NewRecorder()
	server.Handler().ServeHTTP(accepted, request(session, csrf, "https://console.example.test", ""))
	if accepted.Code != http.StatusCreated {
		t.Fatalf("valid unsafe request=%d body=%s", accepted.Code, accepted.Body.String())
	}
	get := httptest.NewRecorder()
	server.Handler().ServeHTTP(get, controlPlaneRequest(http.MethodGet, "/api/v1/applications", nil, session))
	if get.Code != http.StatusOK {
		t.Fatalf("GET unexpectedly requires origin or CSRF: %d %s", get.Code, get.Body.String())
	}
	options := httptest.NewRecorder()
	server.Handler().ServeHTTP(options, controlPlaneRequest(http.MethodOptions, "/api/v1/applications", nil, session))
	if options.Code != http.StatusNoContent {
		t.Fatalf("authenticated OPTIONS status=%d body=%s", options.Code, options.Body.String())
	}
	anonymousOptions := httptest.NewRecorder()
	server.Handler().ServeHTTP(anonymousOptions, controlPlaneRequest(http.MethodOptions, "/api/v1/applications", nil, nil))
	if anonymousOptions.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous OPTIONS bypassed session: %d %s", anonymousOptions.Code, anonymousOptions.Body.String())
	}
}

func TestAuthSourceUsesEdgeClientHeaderOnlyFromLoopback(t *testing.T) {
	loopback := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	loopback.RemoteAddr = "127.0.0.1:18481"
	loopback.Header.Set("X-Open-Card-Client-IP", "198.51.100.10")
	loopback.Header.Set("X-Forwarded-For", "203.0.113.10")
	if got := authSource(loopback); got != "198.51.100.10" {
		t.Fatalf("loopback edge source=%q", got)
	}
	direct := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	direct.RemoteAddr = "198.51.100.20:443"
	direct.Header.Set("X-Open-Card-Client-IP", "203.0.113.20")
	if got := authSource(direct); got != "198.51.100.20" {
		t.Fatalf("direct source accepted a forged header: %q", got)
	}
}
