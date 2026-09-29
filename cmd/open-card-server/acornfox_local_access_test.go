package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServerUnknownConsoleAccessMode(t *testing.T) {
	server := NewAcornFoxServer()

	// 1. SetConsoleAccessMode rejects unknown mode
	err := server.SetConsoleAccessMode("invalid_random_mode")
	if err == nil {
		t.Fatal("expected SetConsoleAccessMode to reject unknown mode")
	}

	// 2. Handler rejects request with 500 when mode is corrupt/unknown
	server.consoleAccessMode = "corrupted_mode"
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 internal server error for corrupted mode, got %d", rec.Code)
	}

	// 3. Setup boundaryAllowed rejects unknown policy
	setupHandler := &AcornFoxWebSetupHTTPHandler{}
	boundaryReq := httptest.NewRequest("POST", "/api/v1/acornfox/setup", nil)
	boundaryReq.RemoteAddr = "127.0.0.1:12345"
	boundaryReq.Header.Set("X-Forwarded-Proto", "https")
	if setupHandler.BoundaryAllowed(boundaryReq, "unknown_policy") {
		t.Fatal("expected BoundaryAllowed to reject unknown policy")
	}
}
