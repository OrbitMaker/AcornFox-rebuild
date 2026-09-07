package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/hostmetrics"
)

func TestHostMetricsRouteRequiresAdministratorAndExactPath(t *testing.T) {
	server := NewAcornFoxServer()
	server.SetAcornFoxHostMetrics(hostmetrics.NewHTTPHandler(hostmetrics.NewSampler(hostmetrics.Config{OS: "unsupported-test"})))
	now := time.Now()
	_, session, _ := attachTestAcornFoxAdministratorTokens(t, server, &now)
	unauthorized := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/host/metrics", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthed status=%d", unauthorized.Code)
	}
	result := acornFoxDiscoveryRequest(t, server, session, http.MethodGet, "/api/v1/acornfox/host/metrics")
	if result.Code != http.StatusOK {
		t.Fatalf("authed status=%d", result.Code)
	}
	for _, path := range []string{"/api/v1/acornfox/host/metrics/", "/api/v1/acornfox/host/metrics/extra"} {
		result := acornFoxDiscoveryRequest(t, server, session, http.MethodGet, path)
		if result.Code != http.StatusNotFound {
			t.Fatalf("noncanonical status=%d", result.Code)
		}
	}
}
