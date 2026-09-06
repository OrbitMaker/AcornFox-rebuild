package main

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/providers/acornfoxroute"
)

func TestCleanM1PublicCompositionIsIndependentAndRejectsOtherWriters(t *testing.T) {
	for _, tc := range []struct {
		name          string
		clean, m1, m3 bool
		root          string
		want          bool
		failure       bool
	}{
		{"clean M1", true, true, false, "console.example.com", true, false},
		{"no root", true, true, false, "", false, false},
		{"M1 required", true, false, false, "console.example.com", false, true},
		{"M3 second writer", true, true, true, "console.example.com", false, true},
		{"foreign root", true, true, false, "example.com", false, true},
		{"double apps root", true, true, false, "apps.console.example.com", false, true},
		{"legacy untouched", false, true, true, "example.com", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cleanPublicAccessEnabled(tc.clean, tc.m1, tc.m3, "https://console.example.com", tc.root)
			if got != tc.want || (err != nil) != tc.failure {
				t.Fatalf("enabled=%v err=%v", got, err)
			}
		})
	}
}

func TestCleanTLSAllowRequiresLoopbackOwnedPersistedEnabledHost(t *testing.T) {
	host, _ := contracts.AcornFoxPublicHostname("console.example.com", "app_one", "dep_one")
	for _, tc := range []struct {
		name, remote, method, query string
		enabled                     bool
		dbError                     bool
		want                        int
		calls                       int
	}{
		{"enabled", "127.0.0.1:12345", "GET", "domain=" + host, true, false, 200, 1},
		{"IPv6 loopback", "[::1]:12345", "GET", "domain=" + host, true, false, 200, 1},
		{"disabled", "127.0.0.1:12345", "GET", "domain=" + host, false, false, 403, 1},
		{"database unavailable", "127.0.0.1:12345", "GET", "domain=" + host, true, true, 403, 1},
		{"remote caller", "203.0.113.1:12345", "GET", "domain=" + host, true, false, 403, 0},
		{"spoofed proxy", "10.0.0.1:12345", "GET", "domain=" + host, true, false, 403, 0},
		{"wrong method", "127.0.0.1:12345", "POST", "domain=" + host, true, false, 403, 0},
		{"foreign root", "127.0.0.1:12345", "GET", "domain=delivery-01234567890123456789.apps.example.com", true, false, 403, 0},
		{"console is static only", "127.0.0.1:12345", "GET", "domain=console.example.com", true, false, 403, 0},
		{"wildcard", "127.0.0.1:12345", "GET", "domain=*.apps.console.example.com", true, false, 403, 0},
		{"malformed label", "127.0.0.1:12345", "GET", "domain=delivery-xxxx.apps.console.example.com", true, false, 403, 0},
		{"multiple names", "127.0.0.1:12345", "GET", "domain=" + host + "&domain=" + host, true, false, 403, 0},
		{"extra query", "127.0.0.1:12345", "GET", "domain=" + host + "&credential=canary", true, false, 403, 0},
		{"malformed query", "127.0.0.1:12345", "GET", "domain=%zz", true, false, 403, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s := NewAcornFoxServer()
			s.acornFoxTLSAllow = &acornFoxTLSAllowHandler{root: "console.example.com", allow: func(ctx context.Context, name string) (bool, error) {
				calls++
				if name != host {
					t.Fatal("unexpected hostname")
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("unbounded permission lookup")
				}
				if tc.dbError {
					return false, errors.New("secret-canary")
				}
				return tc.enabled, nil
			}}
			request := httptest.NewRequest(tc.method, acornfoxroute.PermissionPath+"?"+tc.query, nil)
			request.RemoteAddr = tc.remote
			request.Header.Set("X-Forwarded-For", "127.0.0.1")
			request.Header.Set("X-Open-Card-Client-IP", "127.0.0.1")
			response := httptest.NewRecorder()
			s.Handler().ServeHTTP(response, request)
			if response.Code != tc.want || calls != tc.calls || response.Body.Len() != 0 {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, calls, response.Body.String())
			}
		})
	}
}
func TestCleanPublicBoundaryDropsAuthorityButKeepsCSRF(t *testing.T) {
	s := NewAcornFoxServer()
	r := httptest.NewRequest("GET", "/anything", nil)
	for _, name := range []string{"X-Open-Card-Actor", "X-Open-Card-Role", "X-Open-Card-Task-Scope", "X-Open-Card-Client-IP", "x-open-card-future-authority"} {
		r.Header[name] = []string{"forged"}
	}
	r.Header.Set(acornFoxAuthCSRFHeader, "csrf-canary")
	if s.handleAcornFoxHTTPSBoundary(httptest.NewRecorder(), r) {
		t.Fatal("unrelated path consumed")
	}
	for name := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-open-card-") {
			t.Fatal("authority survived", name)
		}
	}
	if r.Header.Get(acornFoxAuthCSRFHeader) != "csrf-canary" {
		t.Fatal("CSRF removed")
	}
	legacy := NewServer()
	r.Header.Set("X-Open-Card-Role", "legacy")
	legacy.handleAcornFoxHTTPSBoundary(httptest.NewRecorder(), r)
	if r.Header.Get("X-Open-Card-Role") != "legacy" {
		t.Fatal("legacy behavior changed")
	}
}
func TestCleanPublicAPIKeepsPendingExternalValidationAndLegacyIsolation(t *testing.T) {
	s := NewAcornFoxServer()
	now := time.Now()
	_, cookie, csrf := attachTestAcornFoxAdministratorTokens(t, s, &now)
	host, _ := contracts.AcornFoxPublicHostname("console.example.com", "app_one", "dep_one")
	fixture := &acornFoxPublicAccessHTTPFixture{set: contracts.AcornFoxPublicAccessFact{ApplicationID: "app_one", DeploymentID: "dep_one", Hostname: host, Status: contracts.AcornFoxPublicPendingExternalValidation, DesiredPublic: true, InternalEndpoint: contracts.AcornFoxInternalEndpointAccepted, LocalRoute: contracts.AcornFoxLocalRouteConfigured}}
	s.SetAcornFoxPublicAccess(&AcornFoxPublicAccessHTTPHandler{Service: fixture})
	r := httptest.NewRequest("PUT", acornFoxAPIBase+"/app_one/deliveries/dep_one/public-access", strings.NewReader(`{"enabled":true}`))
	r.AddCookie(cookie)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", "https-enable")
	addAcornFoxWriteProof(r, csrf)
	r.Header.Set("X-Open-Card-Actor", "forged")
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, r)
	if response.Code != 200 || !strings.Contains(response.Body.String(), "https://"+host) || !strings.Contains(response.Body.String(), "PENDING_EXTERNAL_VALIDATION") || !strings.Contains(response.Body.String(), `"tls":"not_validated"`) {
		t.Fatal(response.Code, response.Body.String())
	}
	old := httptest.NewRecorder()
	s.Handler().ServeHTTP(old, httptest.NewRequest("GET", "/api/v1/applications", nil))
	if old.Code != 404 {
		t.Fatal("legacy API exposed")
	}
}
func TestPublicEdgeUnitUsesOnlyNativeBoundConfigAndBindCapability(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/systemd/acornfox-edge.service")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{"User=acornfox-edge\n", "ExecStartPre=/opt/acornfox/current/bin/caddy validate --config /etc/acornfox/runtime/edge.json\n", "ExecStart=/opt/acornfox/current/bin/caddy run --config /etc/acornfox/runtime/edge.json\n", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n", "AmbientCapabilities=CAP_NET_BIND_SERVICE\n", "ProtectSystem=strict\n", "ReadWritePaths=/var/lib/acornfox/edge /var/log/acornfox/edge\n"} {
		if !strings.Contains(text, want) {
			t.Fatal("missing Edge contract", want)
		}
	}
	for _, forbidden := range []string{"IPAddressDeny=any", "--adapter", "--environ", "--resume", "CAP_SYS_ADMIN"} {
		if strings.Contains(text, forbidden) {
			t.Fatal("unsafe/stale Edge setting", forbidden)
		}
	}
}
