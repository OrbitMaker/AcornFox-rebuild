package corehttp

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/auth"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
	"github.com/open-card/open-card/internal/persistence/sqlite"
)

type setupHTTPStore struct {
	mu         sync.Mutex
	exists     bool
	credential domain.AdminCredential
	err        error
}

func (s *setupHTTPStore) AdministratorExists(context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exists, s.err
}

func (s *setupHTTPStore) CreateAdminCredential(_ context.Context, credential domain.AdminCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if s.exists {
		return errors.New("singleton conflict")
	}
	s.exists = true
	s.credential = credential
	return nil
}

func setupHTTPFixture(t *testing.T) (*AcornFoxWebSetupHTTPHandler, *setupHTTPStore, string) {
	t.Helper()
	now := time.Date(2026, 9, 7, 8, 0, 0, 0, time.UTC)
	authService, err := auth.NewService(auth.Config{Store: &authHTTPStore{}, Origin: "https://console.example.test", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	store := &setupHTTPStore{}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32))
	service, err := auth.NewWebSetupService(auth.WebSetupConfig{Store: store, Auth: authService, SetupTokenCredential: []byte(token + "\n"), Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return &AcornFoxWebSetupHTTPHandler{Service: service}, store, token
}

func secureSetupRequest(method, body string) *http.Request {
	request := httptest.NewRequest(method, AcornFoxSetupPath, strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:49152"
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("Origin", "https://console.example.test")
	request.Header.Set("Content-Type", "application/json")
	return request
}

func TestAcornFoxWebSetupHTTPStateSuccessAndReplay(t *testing.T) {
	handler, store, token := setupHTTPFixture(t)
	getRecorder := httptest.NewRecorder()
	if !handler.Handle(getRecorder, httptest.NewRequest(http.MethodGet, AcornFoxSetupPath, nil)) || getRecorder.Code != http.StatusOK || getRecorder.Body.String() != "{\"state\":\"uninitialized\"}\n" {
		t.Fatalf("GET=%d %s", getRecorder.Code, getRecorder.Body.String())
	}
	body := `{"setup_token":"` + token + `","password":"correct horse battery staple"}`
	postRecorder := httptest.NewRecorder()
	handler.Handle(postRecorder, secureSetupRequest(http.MethodPost, body))
	if postRecorder.Code != http.StatusCreated || postRecorder.Body.String() != "{\"initialized\":true}\n" || store.credential.ID.Empty() {
		t.Fatalf("POST=%d %s credential=%+v", postRecorder.Code, postRecorder.Body.String(), store.credential)
	}
	replayRecorder := httptest.NewRecorder()
	handler.Handle(replayRecorder, secureSetupRequest(http.MethodPost, body))
	if replayRecorder.Code != http.StatusConflict || strings.Contains(replayRecorder.Body.String(), token) {
		t.Fatalf("replay=%d %s", replayRecorder.Code, replayRecorder.Body.String())
	}
	initializedRecorder := httptest.NewRecorder()
	handler.Handle(initializedRecorder, httptest.NewRequest(http.MethodGet, AcornFoxSetupPath, nil))
	if initializedRecorder.Body.String() != "{\"state\":\"initialized\"}\n" {
		t.Fatalf("initialized GET=%s", initializedRecorder.Body.String())
	}
}

func TestAcornFoxWebSetupHTTPRequiresExactHTTPSOriginAndStrictBoundedJSON(t *testing.T) {
	handler, _, token := setupHTTPFixture(t)
	body := `{"setup_token":"` + token + `","password":"correct horse battery staple"}`
	tests := []struct {
		name   string
		mutate func(*http.Request)
		body   string
		status int
	}{
		{name: "wrong origin", mutate: func(r *http.Request) { r.Header.Set("Origin", "https://console.example.test/") }, body: body, status: http.StatusUnauthorized},
		{name: "untrusted plaintext", mutate: func(r *http.Request) { r.RemoteAddr = "198.51.100.3:443" }, body: body, status: http.StatusUnauthorized},
		{name: "loopback without edge TLS", mutate: func(r *http.Request) { r.Header.Del("X-Forwarded-Proto") }, body: body, status: http.StatusUnauthorized},
		{name: "unknown field", body: `{"setup_token":"` + token + `","password":"correct horse battery staple","email":"nobody@example.test"}`, status: http.StatusBadRequest},
		{name: "second object", body: body + `{}`, status: http.StatusBadRequest},
		{name: "oversized", body: `{"setup_token":"` + token + `","password":"` + strings.Repeat("x", AcornFoxSetupMaxJSONBody) + `"}`, status: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := secureSetupRequest(http.MethodPost, test.body)
			if test.mutate != nil {
				test.mutate(request)
			}
			recorder := httptest.NewRecorder()
			handler.Handle(recorder, request)
			if recorder.Code != test.status || strings.Contains(recorder.Body.String(), token) || recorder.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("response=%d %s headers=%v", recorder.Code, recorder.Body.String(), recorder.Header())
			}
		})
	}
}

func TestAcornFoxWebSetupHTTPUnavailableAndExactRoute(t *testing.T) {
	nilHandler := &AcornFoxWebSetupHTTPHandler{}
	recorder := httptest.NewRecorder()
	if !nilHandler.Handle(recorder, httptest.NewRequest(http.MethodGet, AcornFoxSetupPath, nil)) || recorder.Body.String() != "{\"state\":\"unavailable\"}\n" {
		t.Fatalf("unavailable=%d %s", recorder.Code, recorder.Body.String())
	}
	if nilHandler.Handle(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, AcornFoxSetupPath+"/", nil)) {
		t.Fatal("non-canonical route was handled")
	}
	methodRecorder := httptest.NewRecorder()
	handler, _, _ := setupHTTPFixture(t)
	handler.Handle(methodRecorder, httptest.NewRequest(http.MethodDelete, AcornFoxSetupPath, nil))
	if methodRecorder.Code != http.StatusMethodNotAllowed || methodRecorder.Header().Get("Allow") != "GET, POST" {
		t.Fatalf("method=%d allow=%q", methodRecorder.Code, methodRecorder.Header().Get("Allow"))
	}
}

func TestAcornFoxWebSetupConcurrentBootstrapOnTaskScopedPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_WEB_SETUP_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_WEB_SETUP_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || (parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "localhost" && parsed.Hostname() != "::1") || !strings.HasPrefix(strings.TrimPrefix(parsed.EscapedPath(), "/"), "open_card_websetup_") {
		t.Fatal("task-scoped web setup database URL is invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", "control-plane", "0022_admin_auth.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	store := postgres.NewStore(db)
	now := time.Date(2026, 9, 7, 8, 0, 0, 0, time.UTC)
	authService, err := auth.NewService(auth.Config{Store: store, Origin: "https://console.example.test", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{19}, 32))
	service, err := auth.NewWebSetupService(auth.WebSetupConfig{Store: store, Auth: authService, SetupTokenCredential: []byte(token + "\n"), Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	start := make(chan struct{})
	for index := 0; index < 2; index++ {
		go func() {
			<-start
			results <- service.Setup(ctx, "https://console.example.test", token, "postgres concurrent setup password")
		}()
	}
	close(start)
	success, initialized := 0, 0
	for index := 0; index < 2; index++ {
		switch err := <-results; {
		case err == nil:
			success++
		case errors.Is(err, auth.ErrWebSetupInitialized):
			initialized++
		default:
			t.Fatalf("concurrent setup error=%v", err)
		}
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM admin_credentials`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if success != 1 || initialized != 1 || count != 1 || service.State(ctx) != auth.WebSetupStateInitialized {
		t.Fatalf("success=%d initialized=%d count=%d state=%q", success, initialized, count, service.State(ctx))
	}
	if _, err := db.ExecContext(ctx, `UPDATE admin_credentials SET disabled_at = created_at`); err != nil {
		t.Fatal(err)
	}
	if state := service.State(ctx); state != auth.WebSetupStateInitialized {
		t.Fatalf("disabled historical administrator reopened setup: %q", state)
	}
}

func secureTestDir(t *testing.T, sub ...string) string {
	t.Helper()
	temp := t.TempDir()
	if err := os.Chmod(temp, 0o700); err != nil {
		t.Fatal(err)
	}
	if len(sub) > 0 {
		full := filepath.Join(append([]string{temp}, sub...)...)
		if err := os.MkdirAll(full, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, 0o700); err != nil {
			t.Fatal(err)
		}
		return full
	}
	return temp
}

func newSetupAuthTestHandler(setup *AcornFoxWebSetupHTTPHandler, authHandler *AuthHTTPHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == AcornFoxSetupPath {
			if setup != nil && setup.Handle(w, r) {
				return
			}
			AuthNoStore(w)
			WriteJSONError(w, http.StatusServiceUnavailable, "setup_unavailable", "setup unavailable")
			return
		}
		if strings.HasPrefix(r.URL.Path, AcornFoxAuthAPIBase) {
			if authHandler != nil && authHandler.HandleAcornFox(w, r) {
				return
			}
			AuthNoStore(w)
			AuthHTTPError(w, http.StatusServiceUnavailable, "authentication unavailable")
			return
		}
		http.NotFound(w, r)
	})
}

func TestAcornFoxWebSetupAndAuthHTTPIntegrationWithSQLite(t *testing.T) {
	dataDir := secureTestDir(t, "sqlite_http_integration")
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	clockNow := now

	store, err := sqlite.Open(sqlite.Config{
		DataDirectory: dataDir,
		DBName:        "acornfox.db",
	})
	if err != nil {
		t.Fatalf("Open sqlite store: %v", err)
	}

	authService, err := auth.NewService(auth.Config{
		Store:  store,
		Origin: "https://console.example.test",
		Clock:  func() time.Time { return clockNow },
	})
	if err != nil {
		t.Fatal(err)
	}

	rawToken := bytes.Repeat([]byte{42}, 32)
	setupToken := base64.RawURLEncoding.EncodeToString(rawToken)

	setupCredential := []byte(setupToken + "\n")
	setupService, err := auth.NewWebSetupService(auth.WebSetupConfig{
		Store:                store,
		Auth:                 authService,
		SetupTokenCredential: setupCredential,
		Clock:                func() time.Time { return clockNow },
	})
	clear(setupCredential)
	if err != nil {
		t.Fatal(err)
	}
	setupHandler := &AcornFoxWebSetupHTTPHandler{Service: setupService}

	authHandler := &AuthHTTPHandler{Service: authService}
	serverHandler := newSetupAuthTestHandler(setupHandler, authHandler)

	// 1. HTTP GET /api/v1/acornfox/setup -> uninitialized
	getRec := httptest.NewRecorder()
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/setup", nil)
	getReq.Header.Set("Origin", "https://console.example.test")
	serverHandler.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK || !strings.Contains(getRec.Body.String(), `"uninitialized"`) {
		t.Fatalf("GET /setup: code=%d body=%s", getRec.Code, getRec.Body.String())
	}

	// 2. HTTP POST /api/v1/acornfox/setup -> initialized
	initialPassword := "initial-secure-password-12345"
	setupReq := secureSetupRequest(http.MethodPost, `{"setup_token":"`+setupToken+`","password":"`+initialPassword+`"}`)
	setupRec := httptest.NewRecorder()
	serverHandler.ServeHTTP(setupRec, setupReq)
	if setupRec.Code != http.StatusCreated || !strings.Contains(setupRec.Body.String(), `"initialized":true`) {
		t.Fatalf("POST /setup: code=%d body=%s", setupRec.Code, setupRec.Body.String())
	}

	// 3. HTTP POST /api/v1/acornfox/auth/login -> 200 with cookies
	loginReq := authRequest(http.MethodPost, "/api/v1/acornfox/auth/login", `{"password":"`+initialPassword+`"}`)
	loginRec := httptest.NewRecorder()
	serverHandler.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("POST /login: code=%d body=%s", loginRec.Code, loginRec.Body.String())
	}
	cookies := loginRec.Result().Cookies()
	sessionCookie := cookieValue(cookies, AcornFoxAuthSessionCookie)
	csrfCookie := cookieValue(cookies, AcornFoxAuthCSRFCookie)
	if sessionCookie == nil || csrfCookie == nil {
		t.Fatalf("missing auth cookies after login: cookies=%+v", cookies)
	}

	// 4. HTTP POST /api/v1/acornfox/auth/password (rotate) -> 200
	newPassword := "rotated-secure-password-67890"
	passReq := authRequest(http.MethodPost, "/api/v1/acornfox/auth/password", `{"current_password":"`+initialPassword+`","new_password":"`+newPassword+`"}`)
	passReq.AddCookie(sessionCookie)
	passReq.AddCookie(csrfCookie)
	passReq.Header.Set(AcornFoxAuthCSRFHeader, csrfCookie.Value)
	passRec := httptest.NewRecorder()
	serverHandler.ServeHTTP(passRec, passReq)
	if passRec.Code != http.StatusNoContent {
		t.Fatalf("POST /password: code=%d body=%s", passRec.Code, passRec.Body.String())
	}

	// Old session is now invalidated
	sessReq := authRequest(http.MethodGet, "/api/v1/acornfox/auth/session", "")
	sessReq.Header.Del("Content-Type")
	sessReq.AddCookie(sessionCookie)
	sessRec := httptest.NewRecorder()
	serverHandler.ServeHTTP(sessRec, sessReq)
	if sessRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after password rotation, got %d", sessRec.Code)
	}

	// 5. Close and reopen SQLite store from disk
	_ = store.Close()

	reopenedStore, err := sqlite.Open(sqlite.Config{
		DataDirectory: dataDir,
		DBName:        "acornfox.db",
	})
	if err != nil {
		t.Fatalf("reopen sqlite store: %v", err)
	}
	defer reopenedStore.Close()

	clockNow = clockNow.Add(time.Hour)
	reopenedAuthService, err := auth.NewService(auth.Config{
		Store:  reopenedStore,
		Origin: "https://console.example.test",
		Clock:  func() time.Time { return clockNow },
	})
	if err != nil {
		t.Fatal(err)
	}

	reopenedAuthHandler := &AuthHTTPHandler{Service: reopenedAuthService}
	reopenedServerHandler := newSetupAuthTestHandler(nil, reopenedAuthHandler)

	// Login with old password fails (401)
	oldLoginReq := authRequest(http.MethodPost, "/api/v1/acornfox/auth/login", `{"password":"`+initialPassword+`"}`)
	oldLoginRec := httptest.NewRecorder()
	reopenedServerHandler.ServeHTTP(oldLoginRec, oldLoginReq)
	if oldLoginRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for old password, got %d", oldLoginRec.Code)
	}

	// Login with new password succeeds (200)
	newLoginReq := authRequest(http.MethodPost, "/api/v1/acornfox/auth/login", `{"password":"`+newPassword+`"}`)
	newLoginRec := httptest.NewRecorder()
	reopenedServerHandler.ServeHTTP(newLoginRec, newLoginReq)
	if newLoginRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for new password, got %d", newLoginRec.Code)
	}

	// Logout
	newCookies := newLoginRec.Result().Cookies()
	newSessCookie := cookieValue(newCookies, AcornFoxAuthSessionCookie)
	newCsrfCookie := cookieValue(newCookies, AcornFoxAuthCSRFCookie)

	logoutReq := authRequest(http.MethodPost, "/api/v1/acornfox/auth/logout", "")
	logoutReq.AddCookie(newSessCookie)
	logoutReq.AddCookie(newCsrfCookie)
	logoutReq.Header.Set(AcornFoxAuthCSRFHeader, newCsrfCookie.Value)
	logoutRec := httptest.NewRecorder()
	reopenedServerHandler.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusNoContent {
		t.Fatalf("logout code=%d body=%s", logoutRec.Code, logoutRec.Body.String())
	}
}
