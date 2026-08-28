package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestM2LegacyAgentProbeFailsClosed(t *testing.T) {
	server := NewServer()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agents/capabilities/legacy-negative", strings.NewReader(`{
		"service_group_id":"group_legacy",
		"required_capabilities":["runtime.deploy"],
		"operation":{"idempotency_key":"legacy-negative"}
	}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	server.handleM2LegacyAgentNegative(recorder, request)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "runtime.deploy_group") || !strings.Contains(recorder.Body.String(), "without downgrade") {
		t.Fatalf("response did not explain fail-closed aggregate capability boundary: %s", recorder.Body.String())
	}
}

func TestM2CapabilityProjectionStartsEmpty(t *testing.T) {
	server := NewServer()
	server.m2AgentInstance = "instance-m2"
	server.m2AgentNode = "node-m2"
	recorder := httptest.NewRecorder()

	server.handleM2AgentCapabilities(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/agents/capabilities", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"capabilities":[]`) {
		t.Fatalf("an unconnected Agent must not be assigned capabilities: %s", recorder.Body.String())
	}
}
