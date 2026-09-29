package corehttp

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/auth"
	"github.com/acornfox/acornfox/internal/domain"
)

type localAccessMemoryStore struct {
	credential domain.AdminCredential
	sessions   map[domain.AuthDigest]domain.AdminSession
	rates      map[domain.AuthDigest]domain.AdminLoginRateLimit
}

func (s *localAccessMemoryStore) ActiveAdminCredential(context.Context) (domain.AdminCredential, error) {
	if s.credential.ID.Empty() {
		return domain.AdminCredential{}, auth.ErrNotFound
	}
	return s.credential, nil
}

func (s *localAccessMemoryStore) RotateAdminCredential(_ context.Context, id domain.ID, expected int64, scheme, hash string, now time.Time) (domain.AdminCredential, error) {
	s.credential.PasswordHashScheme, s.credential.PasswordHash = scheme, hash
	s.credential.CredentialVersion++
	s.credential.UpdatedAt = now
	return s.credential, nil
}

func (s *localAccessMemoryStore) CreateAdminSession(_ context.Context, session domain.AdminSession) error {
	if s.sessions == nil {
		s.sessions = map[domain.AuthDigest]domain.AdminSession{}
	}
	s.sessions[session.SessionDigest] = session
	return nil
}

func (s *localAccessMemoryStore) ActiveAdminSessionByDigest(_ context.Context, digest domain.AuthDigest, now time.Time) (domain.AdminSession, error) {
	session, ok := s.sessions[digest]
	if !ok || session.RevokedAt != nil || !now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) || session.CredentialVersion != s.credential.CredentialVersion {
		return domain.AdminSession{}, auth.ErrNotFound
	}
	return session, nil
}

func (s *localAccessMemoryStore) TouchAdminSession(_ context.Context, id domain.ID, credentialVersion int64, now time.Time) (domain.AdminSession, error) {
	for digest, session := range s.sessions {
		if session.ID == id {
			session.IdleExpiresAt = now.Add(30 * time.Minute)
			s.sessions[digest] = session
			return session, nil
		}
	}
	return domain.AdminSession{}, auth.ErrNotFound
}

func (s *localAccessMemoryStore) RevokeAdminSession(_ context.Context, id domain.ID, now time.Time) error {
	for digest, session := range s.sessions {
		if session.ID == id {
			session.RevokedAt = &now
			s.sessions[digest] = session
			return nil
		}
	}
	return nil
}

func (s *localAccessMemoryStore) UpsertAdminLoginRateLimit(_ context.Context, record domain.AdminLoginRateLimit) error {
	if s.rates == nil {
		s.rates = map[domain.AuthDigest]domain.AdminLoginRateLimit{}
	}
	s.rates[record.SourceDigest] = record
	return nil
}

func (s *localAccessMemoryStore) AdminLoginRateLimit(_ context.Context, _ domain.ID, source domain.AuthDigest) (domain.AdminLoginRateLimit, error) {
	record, ok := s.rates[source]
	if !ok {
		return domain.AdminLoginRateLimit{}, auth.ErrNotFound
	}
	return record, nil
}

func (s *localAccessMemoryStore) RecordAdminLoginFailure(_ context.Context, adminID domain.ID, source domain.AuthDigest, now time.Time) (domain.AdminLoginRateLimit, error) {
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

func (s *localAccessMemoryStore) CreateAdminSessionIfLoginAllowed(ctx context.Context, session domain.AdminSession, source domain.AuthDigest, now time.Time) error {
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

func newLocalLoopbackTestServer(authHandler *AuthHTTPHandler, setupHandler *AcornFoxWebSetupHTTPHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ValidateLocalLoopbackRequest(r) {
			WriteJSONError(w, http.StatusForbidden, "access_denied", "local loopback access denied")
			return
		}
		if r.URL.Path == AcornFoxSetupPath {
			if setupHandler != nil {
				setupHandler.HandleWithPolicy(w, r, ConsoleAccessLocalLoopback)
			} else {
				WriteJSONError(w, http.StatusServiceUnavailable, "setup_unavailable", "setup unavailable")
			}
			return
		}
		if strings.HasPrefix(r.URL.Path, AcornFoxAuthAPIBase) {
			if authHandler != nil && authHandler.HandleAcornFoxWithConfig(w, r, LocalAuthRouteConfig) {
				return
			}
			AuthNoStore(w)
			AuthHTTPError(w, http.StatusServiceUnavailable, "authentication unavailable")
			return
		}
		WriteJSONError(w, http.StatusNotFound, "not_found", "route not found")
	})
}

func TestLocalLoopbackGateValidation(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		host       string
		uri        string
		path       string
		headers    map[string]string
		wantOk     bool
	}{
		{
			name:       "valid standard local console request",
			remoteAddr: "127.0.0.1:54321",
			host:       "127.0.0.1:8080",
			path:       "/api/v1/acornfox/auth/session",
			wantOk:     true,
		},
		{
			name:       "valid direct internal healthcheck",
			remoteAddr: "127.0.0.1:54321",
			host:       "127.0.0.1:18481",
			path:       "/healthz",
			wantOk:     true,
		},
		{
			name:       "valid console healthcheck",
			remoteAddr: "127.0.0.1:54321",
			host:       "127.0.0.1:8080",
			path:       "/readyz",
			wantOk:     true,
		},
		{
			name:       "valid caddy x-forwarded-proto http",
			remoteAddr: "127.0.0.1:54321",
			host:       "127.0.0.1:8080",
			path:       "/api/v1/acornfox/auth/session",
			headers:    map[string]string{"X-Forwarded-Proto": "http"},
			wantOk:     true,
		},
		{
			name:       "valid standard caddy proxy with both xfh and xfp",
			remoteAddr: "127.0.0.1:54321",
			host:       "127.0.0.1:8080",
			path:       "/api/v1/acornfox/auth/session",
			headers: map[string]string{
				"X-Forwarded-Host":  "127.0.0.1:8080",
				"X-Forwarded-Proto": "http",
			},
			wantOk: true,
		},
		{
			name:       "reject untrusted x-forwarded-host value",
			remoteAddr: "127.0.0.1:54321",
			host:       "127.0.0.1:8080",
			path:       "/api/v1/acornfox/auth/session",
			headers:    map[string]string{"X-Forwarded-Host": "evil.example.com"},
			wantOk:     false,
		},
		{
			name:       "reject multiple x-forwarded-host values",
			remoteAddr: "127.0.0.1:54321",
			host:       "127.0.0.1:8080",
			path:       "/api/v1/acornfox/auth/session",
			headers:    map[string]string{"X-Forwarded-Host": "127.0.0.1:8080, other.host"},
			wantOk:     false,
		},
		{
			name:       "reject multiple x-forwarded-proto values",
			remoteAddr: "127.0.0.1:54321",
			host:       "127.0.0.1:8080",
			path:       "/api/v1/acornfox/auth/session",
			headers:    map[string]string{"X-Forwarded-Proto": "http, https"},
			wantOk:     false,
		},
		{
			name:       "reject host with trailing whitespace",
			remoteAddr: "127.0.0.1:54321",
			host:       "127.0.0.1:8080 ",
			path:       "/api/v1/acornfox/auth/session",
			wantOk:     false,
		},
		{
			name:       "reject host with leading whitespace",
			remoteAddr: "127.0.0.1:54321",
			host:       " 127.0.0.1:8080",
			path:       "/api/v1/acornfox/auth/session",
			wantOk:     false,
		},
		{
			name:       "reject empty host",
			remoteAddr: "127.0.0.1:54321",
			host:       "",
			path:       "/api/v1/acornfox/auth/session",
			wantOk:     false,
		},
		{
			name:       "reject non-loopback remote addr",
			remoteAddr: "192.168.1.100:54321",
			host:       "127.0.0.1:8080",
			path:       "/api/v1/acornfox/auth/session",
			wantOk:     false,
		},
		{
			name:       "reject localhost hostname",
			remoteAddr: "127.0.0.1:54321",
			host:       "localhost:8080",
			path:       "/api/v1/acornfox/auth/session",
			wantOk:     false,
		},
		{
			name:       "reject wrong port",
			remoteAddr: "127.0.0.1:54321",
			host:       "127.0.0.1:9090",
			path:       "/api/v1/acornfox/auth/session",
			wantOk:     false,
		},
		{
			name:       "reject absolute uri http prefix",
			remoteAddr: "127.0.0.1:54321",
			host:       "127.0.0.1:8080",
			uri:        "http://127.0.0.1:8080/api/v1/acornfox/auth/session",
			path:       "/api/v1/acornfox/auth/session",
			wantOk:     false,
		},
		{
			name:       "reject forwarded header",
			remoteAddr: "127.0.0.1:54321",
			host:       "127.0.0.1:8080",
			path:       "/api/v1/acornfox/auth/session",
			headers:    map[string]string{"Forwarded": "for=1.2.3.4"},
			wantOk:     false,
		},
		{
			name:       "reject x-forwarded-host header",
			remoteAddr: "127.0.0.1:54321",
			host:       "127.0.0.1:8080",
			path:       "/api/v1/acornfox/auth/session",
			headers:    map[string]string{"X-Forwarded-Host": "evil.com"},
			wantOk:     false,
		},
		{
			name:       "reject x-forwarded-proto expanding to https",
			remoteAddr: "127.0.0.1:54321",
			host:       "127.0.0.1:8080",
			path:       "/api/v1/acornfox/auth/session",
			headers:    map[string]string{"X-Forwarded-Proto": "https"},
			wantOk:     false,
		},
		{
			name:       "reject direct internal listener host on non-health path",
			remoteAddr: "127.0.0.1:54321",
			host:       "127.0.0.1:18481",
			path:       "/api/v1/acornfox/auth/session",
			wantOk:     false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.path, nil)
			req.RemoteAddr = tc.remoteAddr
			req.Host = tc.host
			if tc.uri != "" {
				req.RequestURI = tc.uri
			}
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			ok := ValidateLocalLoopbackRequest(req)
			if ok != tc.wantOk {
				t.Fatalf("got ok=%v, want ok=%v", ok, tc.wantOk)
			}
		})
	}
}

func TestLocalLoopbackAuthAndCookieIsolation(t *testing.T) {
	store := &localAccessMemoryStore{}
	now := time.Now().UTC()
	authService, err := auth.NewLocalService(auth.Config{
		Store:  store,
		Origin: "http://127.0.0.1:8080",
		Clock:  func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("failed to create local auth service: %v", err)
	}

	authHandler := &AuthHTTPHandler{Service: authService}
	server := newLocalLoopbackTestServer(authHandler, nil)

	hash, err := authService.HashPassword("TestPassword123456789")
	if err != nil {
		t.Fatal(err)
	}
	store.credential = domain.AdminCredential{
		ID:                 "admin-1",
		PasswordHashScheme: auth.PasswordHashScheme,
		PasswordHash:       hash,
		CredentialVersion:  1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	// 1. Post Login via Local HTTP
	loginBody := `{"password":"TestPassword123456789"}`
	loginReq := httptest.NewRequest("POST", "/api/v1/acornfox/auth/login", strings.NewReader(loginBody))
	loginReq.RemoteAddr = "127.0.0.1:40001"
	loginReq.Host = "127.0.0.1:8080"
	loginReq.Header.Set("Origin", "http://127.0.0.1:8080")
	loginReq.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, loginReq)

	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: code=%d body=%s", rec.Code, rec.Body.String())
	}

	cookies := rec.Result().Cookies()
	var sessionCookie, csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == AcornFoxLocalSessionCookie {
			sessionCookie = c
		} else if c.Name == AcornFoxLocalCSRFCookie {
			csrfCookie = c
		}
	}

	if sessionCookie == nil || csrfCookie == nil {
		t.Fatalf("expected local cookies %q and %q, got: %+v", AcornFoxLocalSessionCookie, AcornFoxLocalCSRFCookie, cookies)
	}

	// Check local cookie properties: Secure MUST be false, Path=/
	if sessionCookie.Secure || csrfCookie.Secure {
		t.Fatalf("local loopback cookies must not be Secure: session=%v csrf=%v", sessionCookie.Secure, csrfCookie.Secure)
	}
	if !sessionCookie.HttpOnly || csrfCookie.HttpOnly {
		t.Fatalf("cookie HttpOnly mismatch: session=%v csrf=%v", sessionCookie.HttpOnly, csrfCookie.HttpOnly)
	}
	if sessionCookie.SameSite != http.SameSiteStrictMode || csrfCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("SameSite must be Strict: session=%v csrf=%v", sessionCookie.SameSite, csrfCookie.SameSite)
	}

	// 2. Query session with local session cookie
	sessionReq := httptest.NewRequest("GET", "/api/v1/acornfox/auth/session", nil)
	sessionReq.RemoteAddr = "127.0.0.1:40001"
	sessionReq.Host = "127.0.0.1:8080"
	sessionReq.AddCookie(sessionCookie)

	sessionRec := httptest.NewRecorder()
	server.ServeHTTP(sessionRec, sessionReq)

	if sessionRec.Code != http.StatusOK {
		t.Fatalf("session query failed: code=%d body=%s", sessionRec.Code, sessionRec.Body.String())
	}

	// 3. Attempting to use public HTTPS cookie in local mode must be ignored
	publicSessionCookie := &http.Cookie{Name: "__Host-acornfox_session", Value: sessionCookie.Value}
	crossReq := httptest.NewRequest("GET", "/api/v1/acornfox/auth/session", nil)
	crossReq.RemoteAddr = "127.0.0.1:40001"
	crossReq.Host = "127.0.0.1:8080"
	crossReq.AddCookie(publicSessionCookie)

	crossRec := httptest.NewRecorder()
	server.ServeHTTP(crossRec, crossReq)

	if crossRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when public cookie is supplied to local mode, got %d", crossRec.Code)
	}

	// 4. Test change password using local session and local CSRF
	newPass := "NewPassword987654321"
	changePassBody := `{"current_password":"TestPassword123456789","new_password":"` + newPass + `"}`
	changeReq := httptest.NewRequest("POST", "/api/v1/acornfox/auth/password", strings.NewReader(changePassBody))
	changeReq.RemoteAddr = "127.0.0.1:40001"
	changeReq.Host = "127.0.0.1:8080"
	changeReq.Header.Set("Origin", "http://127.0.0.1:8080")
	changeReq.Header.Set("Content-Type", "application/json")
	changeReq.Header.Set(AcornFoxLocalCSRFHeader, csrfCookie.Value)
	changeReq.AddCookie(sessionCookie)
	changeReq.AddCookie(csrfCookie)

	changeRec := httptest.NewRecorder()
	server.ServeHTTP(changeRec, changeReq)
	if changeRec.Code != http.StatusNoContent {
		t.Fatalf("change password failed: code=%d body=%s", changeRec.Code, changeRec.Body.String())
	}

	// 5. Old session must now be revoked/invalidated
	oldSessionReq := httptest.NewRequest("GET", "/api/v1/acornfox/auth/session", nil)
	oldSessionReq.RemoteAddr = "127.0.0.1:40001"
	oldSessionReq.Host = "127.0.0.1:8080"
	oldSessionReq.AddCookie(sessionCookie)
	oldSessionRec := httptest.NewRecorder()
	server.ServeHTTP(oldSessionRec, oldSessionReq)
	if oldSessionRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected old session to be unauthorized after password change, got %d", oldSessionRec.Code)
	}
}

type testWebSetupStore struct {
	adminExists bool
	credential  domain.AdminCredential
}

func (s *testWebSetupStore) AdministratorExists(context.Context) (bool, error) {
	return s.adminExists, nil
}

func (s *testWebSetupStore) CreateAdminCredential(_ context.Context, credential domain.AdminCredential) error {
	s.adminExists = true
	s.credential = credential
	return nil
}

func TestLocalLoopbackFullLifecycleSetupToAuth(t *testing.T) {
	now := time.Now().UTC()
	store := &localAccessMemoryStore{}
	setupStore := &testWebSetupStore{adminExists: false}

	authService, err := auth.NewLocalService(auth.Config{
		Store:  store,
		Origin: "http://127.0.0.1:8080",
		Clock:  func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte(i + 1)
	}
	validTokenStr := base64.RawURLEncoding.EncodeToString(rawBytes)
	tokenCredential := []byte(validTokenStr + "\n")
	webSetupService, err := auth.NewWebSetupService(auth.WebSetupConfig{
		Store:                setupStore,
		Auth:                 authService,
		SetupTokenCredential: tokenCredential,
		Clock:                func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	authHandler := &AuthHTTPHandler{Service: authService}
	setupHandler := &AcornFoxWebSetupHTTPHandler{Service: webSetupService}
	server := newLocalLoopbackTestServer(authHandler, setupHandler)

	// 1. Initial State should be uninitialized
	stateReq := httptest.NewRequest("GET", "/api/v1/acornfox/setup", nil)
	stateReq.RemoteAddr = "127.0.0.1:30001"
	stateReq.Host = "127.0.0.1:8080"
	stateRec := httptest.NewRecorder()
	server.ServeHTTP(stateRec, stateReq)
	if stateRec.Code != http.StatusOK || !strings.Contains(stateRec.Body.String(), `"uninitialized"`) {
		t.Fatalf("expected uninitialized setup state, got code=%d body=%s", stateRec.Code, stateRec.Body.String())
	}

	// 2. Reject setup post with wrong Origin
	badOriginReq := httptest.NewRequest("POST", "/api/v1/acornfox/setup", strings.NewReader(`{"setup_token":"`+validTokenStr+`","password":"InitialAdminPassword123"}`))
	badOriginReq.RemoteAddr = "127.0.0.1:30001"
	badOriginReq.Host = "127.0.0.1:8080"
	badOriginReq.Header.Set("Origin", "http://localhost:8080")
	badOriginReq.Header.Set("Content-Type", "application/json")
	badOriginRec := httptest.NewRecorder()
	server.ServeHTTP(badOriginRec, badOriginReq)
	if badOriginRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad origin, got %d", badOriginRec.Code)
	}

	// 3. Successful Setup Post
	setupReq := httptest.NewRequest("POST", "/api/v1/acornfox/setup", strings.NewReader(`{"setup_token":"`+validTokenStr+`","password":"InitialAdminPassword123"}`))
	setupReq.RemoteAddr = "127.0.0.1:30001"
	setupReq.Host = "127.0.0.1:8080"
	setupReq.Header.Set("Origin", "http://127.0.0.1:8080")
	setupReq.Header.Set("Content-Type", "application/json")
	setupRec := httptest.NewRecorder()
	server.ServeHTTP(setupRec, setupReq)
	if setupRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 created for setup, got code=%d body=%s", setupRec.Code, setupRec.Body.String())
	}

	// Sync created credential to local auth store
	store.credential = setupStore.credential

	// 4. Setup already initialized error on second post
	secondSetupReq := httptest.NewRequest("POST", "/api/v1/acornfox/setup", strings.NewReader(`{"setup_token":"`+validTokenStr+`","password":"InitialAdminPassword123"}`))
	secondSetupReq.RemoteAddr = "127.0.0.1:30001"
	secondSetupReq.Host = "127.0.0.1:8080"
	secondSetupReq.Header.Set("Origin", "http://127.0.0.1:8080")
	secondSetupReq.Header.Set("Content-Type", "application/json")
	secondSetupRec := httptest.NewRecorder()
	server.ServeHTTP(secondSetupRec, secondSetupReq)
	if secondSetupRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 conflict on second setup, got %d", secondSetupRec.Code)
	}

	// 5. Login with newly setup administrator password
	loginReq := httptest.NewRequest("POST", "/api/v1/acornfox/auth/login", strings.NewReader(`{"password":"InitialAdminPassword123"}`))
	loginReq.RemoteAddr = "127.0.0.1:30001"
	loginReq.Host = "127.0.0.1:8080"
	loginReq.Header.Set("Origin", "http://127.0.0.1:8080")
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	server.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("expected 200 ok for login, got code=%d body=%s", loginRec.Code, loginRec.Body.String())
	}

	// 6. Verify write operation with invalid CSRF rejected
	var sessCookie, csrfCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == AcornFoxLocalSessionCookie {
			sessCookie = c
		} else if c.Name == AcornFoxLocalCSRFCookie {
			csrfCookie = c
		}
	}
	if sessCookie == nil || csrfCookie == nil {
		t.Fatal("local session or csrf cookie missing")
	}

	badCsrfReq := httptest.NewRequest("POST", "/api/v1/acornfox/auth/password", strings.NewReader(`{"current_password":"InitialAdminPassword123","new_password":"RotatedPassword123"}`))
	badCsrfReq.RemoteAddr = "127.0.0.1:30001"
	badCsrfReq.Host = "127.0.0.1:8080"
	badCsrfReq.Header.Set("Origin", "http://127.0.0.1:8080")
	badCsrfReq.Header.Set("Content-Type", "application/json")
	badCsrfReq.Header.Set(AcornFoxLocalCSRFHeader, "wrong-csrf-token")
	badCsrfReq.AddCookie(sessCookie)
	badCsrfReq.AddCookie(csrfCookie)
	badCsrfRec := httptest.NewRecorder()
	server.ServeHTTP(badCsrfRec, badCsrfReq)
	if badCsrfRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid CSRF, got %d", badCsrfRec.Code)
	}

	// 7. Successful password change using real login local session and local CSRF
	newPass := "RotatedPassword123"
	changePassBody := `{"current_password":"InitialAdminPassword123","new_password":"` + newPass + `"}`
	goodChangeReq := httptest.NewRequest("POST", "/api/v1/acornfox/auth/password", strings.NewReader(changePassBody))
	goodChangeReq.RemoteAddr = "127.0.0.1:30001"
	goodChangeReq.Host = "127.0.0.1:8080"
	goodChangeReq.Header.Set("Origin", "http://127.0.0.1:8080")
	goodChangeReq.Header.Set("Content-Type", "application/json")
	goodChangeReq.Header.Set(AcornFoxLocalCSRFHeader, csrfCookie.Value)
	goodChangeReq.AddCookie(sessCookie)
	goodChangeReq.AddCookie(csrfCookie)
	goodChangeRec := httptest.NewRecorder()
	server.ServeHTTP(goodChangeRec, goodChangeReq)
	if goodChangeRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for password change, got code=%d body=%s", goodChangeRec.Code, goodChangeRec.Body.String())
	}

	// 8. Verify old session is revoked/invalidated
	revokedSessReq := httptest.NewRequest("GET", "/api/v1/acornfox/auth/session", nil)
	revokedSessReq.RemoteAddr = "127.0.0.1:30001"
	revokedSessReq.Host = "127.0.0.1:8080"
	revokedSessReq.AddCookie(sessCookie)
	revokedSessRec := httptest.NewRecorder()
	server.ServeHTTP(revokedSessRec, revokedSessReq)
	if revokedSessRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 unauthorized for old session after password change, got %d", revokedSessRec.Code)
	}

	// 9. Verify new password can log in successfully
	newLoginReq := httptest.NewRequest("POST", "/api/v1/acornfox/auth/login", strings.NewReader(`{"password":"RotatedPassword123"}`))
	newLoginReq.RemoteAddr = "127.0.0.1:30001"
	newLoginReq.Host = "127.0.0.1:8080"
	newLoginReq.Header.Set("Origin", "http://127.0.0.1:8080")
	newLoginReq.Header.Set("Content-Type", "application/json")
	newLoginRec := httptest.NewRecorder()
	server.ServeHTTP(newLoginRec, newLoginReq)
	if newLoginRec.Code != http.StatusOK {
		t.Fatalf("expected 200 ok for login with rotated password, got code=%d body=%s", newLoginRec.Code, newLoginRec.Body.String())
	}
}
