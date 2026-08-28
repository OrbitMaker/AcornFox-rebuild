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

func attachTestAdministrator(t *testing.T, server *Server, now *time.Time) (*authHTTPStore, *http.Cookie) {
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
	return store, &http.Cookie{Name: authSessionCookie, Value: login.SessionToken, Path: "/"}
}

func controlPlaneRequest(method, target string, body io.Reader, session *http.Cookie) *http.Request {
	request := httptest.NewRequest(method, target, body)
	if session != nil {
		request.AddCookie(session)
	}
	return request
}

func TestControlPlaneAuthRejectsAnonymousAndForgedIdentityHeaders(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	server := NewServer()
	_, session := attachTestAdministrator(t, server, &now)

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

	allowed := httptest.NewRecorder()
	server.Handler().ServeHTTP(allowed, controlPlaneRequest(http.MethodGet, "/api/v1/applications", nil, session))
	if allowed.Code != http.StatusOK {
		t.Fatalf("authenticated list=%d %s", allowed.Code, allowed.Body.String())
	}
}

func TestControlPlaneAuthProtectsReadinessWritesAndSSE(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	server := NewServer()
	_, session := attachTestAdministrator(t, server, &now)

	protected := []string{
		"/readyz",
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
	create := controlPlaneRequest(http.MethodPost, "/api/v1/applications", strings.NewReader(`{"name":"authenticated"}`), session)
	create.Header.Set("Content-Type", "application/json")
	create.Header.Set("Idempotency-Key", "authenticated-create")
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
	server := NewServer()
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
