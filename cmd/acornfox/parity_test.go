package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type openAPIParityMatrix struct {
	SourceRequestType  string                   `json:"sourceRequestType"`
	SourceRevisionKind string                   `json:"sourceRevisionKind"`
	Operations         []openAPIParityOperation `json:"operations"`
}

type openAPIParityOperation struct {
	OperationID   string `json:"operationId"`
	Method        string `json:"method"`
	PathTemplate  string `json:"pathTemplate"`
	SuccessStatus int    `json:"successStatus"`
	Proof         string `json:"proof"`
	Visible       bool   `json:"visible"`
}

type cliParityOperation struct {
	operationID string
	method      string
	path        string
	shape       responseShape
	body        any
}

func TestAcornFoxOpenAPIParity(t *testing.T) {
	matrixPath := os.Getenv("ACORNFOX_PARITY_MATRIX")
	if matrixPath == "" {
		t.Skip("run through npm --prefix web run test:acornfox-parity")
	}
	data, err := os.ReadFile(matrixPath)
	if err != nil {
		t.Fatal(err)
	}
	var matrix openAPIParityMatrix
	if err := json.Unmarshal(data, &matrix); err != nil {
		t.Fatal(err)
	}
	if matrix.SourceRequestType != "public_git" || matrix.SourceRevisionKind != "git_https" {
		t.Fatalf("source vocabulary=%q/%q", matrix.SourceRequestType, matrix.SourceRevisionKind)
	}
	validSource := `{"id":"source","application_id":"app","kind":"git_https","locator_sha256":"sha256:locator","content_digest":"sha256:content","created_at":"2030-01-01T00:00:00Z","immutable":true}`
	if _, err := decodeResponse(strings.NewReader(validSource), shapeSource); err != nil {
		t.Fatalf("git_https source rejected: %v", err)
	}
	if _, err := decodeResponse(strings.NewReader(strings.Replace(validSource, "git_https", "public_git", 1)), shapeSource); err == nil {
		t.Fatal("public_git response source was accepted")
	}

	operations := []cliParityOperation{
		{"loginAcornFoxAdministrator", http.MethodPost, "/auth/login", shapeSession, map[string]string{"password": "secret"}},
		{"logoutAcornFoxAdministrator", http.MethodPost, "/auth/logout", shapeSession, nil},
		{"getAcornFoxAdministratorSession", http.MethodGet, "/auth/session", shapeSession, nil},
		{"rotateAcornFoxAdministratorPassword", http.MethodPost, "/auth/password", shapeSession, map[string]string{"current_password": "old", "new_password": "new"}},
		{"listAcornFoxApps", http.MethodGet, "/apps", shapeApps, nil},
		{"createAcornFoxApp", http.MethodPost, "/apps", shapeCreateApp, map[string]any{"name": "app", "source": map[string]string{"type": "public_git", "repository_url": "https://github.com/acme/app.git", "ref": "main"}}},
		{"getAcornFoxApp", http.MethodGet, "/apps/app", shapeApplication, nil},
		{"listAcornFoxSourceRevisions", http.MethodGet, "/apps/app/sources", shapeSourceList, nil},
		{"getAcornFoxSourceRevision", http.MethodGet, "/apps/app/sources/source", shapeSource, nil},
		{"listAcornFoxDeliveries", http.MethodGet, "/apps/app/deliveries", shapeDeploymentList, nil},
		{"createAcornFoxDelivery", http.MethodPost, "/apps/app/deliveries", shapeCommand, map[string]string{"source_revision_id": "source"}},
		{"getAcornFoxDeliveryStatus", http.MethodGet, "/apps/app/deliveries/deployment", shapeStatus, nil},
		{"listAcornFoxDeliveryLogs", http.MethodGet, "/apps/app/deliveries/deployment/logs?source=runtime", shapeLogs, nil},
		{"restartAcornFoxDelivery", http.MethodPost, "/apps/app/deliveries/deployment/restart", shapeCommand, map[string]any{}},
		{"redeployAcornFoxDelivery", http.MethodPost, "/apps/app/deliveries/deployment/redeploy", shapeCommand, map[string]any{}},
		{"getAcornFoxDeliveryPublicAccess", http.MethodGet, "/apps/app/deliveries/deployment/public-access", shapePublicAccess, nil},
		{"setAcornFoxDeliveryPublicAccess", http.MethodPut, "/apps/app/deliveries/deployment/public-access", shapePublicAccess, map[string]bool{"enabled": true}},
	}
	byID := make(map[string]openAPIParityOperation, len(matrix.Operations))
	for _, operation := range matrix.Operations {
		byID[operation.OperationID] = operation
	}
	if len(byID) != len(matrix.Operations) {
		t.Fatal("OpenAPI matrix contains duplicate operation IDs")
	}
	if excluded, ok := byID["probeAcornFoxDeliveryOnce"]; !ok || excluded.Visible {
		t.Fatalf("probe exclusion=%+v found=%t", excluded, ok)
	}
	if len(operations) != len(matrix.Operations)-1 {
		t.Fatalf("CLI visible routes=%d OpenAPI operations=%d", len(operations), len(matrix.Operations))
	}

	state := sessionState{Origin: "https://console.example.test", Session: "session", CSRF: "csrf", ExpiresAt: time.Now().Add(time.Hour)}
	for _, declared := range operations {
		t.Run(declared.operationID, func(t *testing.T) {
			operation, ok := byID[declared.operationID]
			if !ok || !operation.Visible {
				t.Fatalf("not a visible OpenAPI operation: %+v", operation)
			}
			if operation.Method != declared.method || !sameAcornFoxRoute(operation.PathTemplate, apiBase+declared.path) {
				t.Fatalf("CLI route=%s %s OpenAPI=%s %s", declared.method, declared.path, operation.Method, operation.PathTemplate)
			}
			got, known := expectedSuccessStatus(declared.method, declared.path, declared.shape)
			if !known || got != operation.SuccessStatus {
				t.Fatalf("CLI success status=%d known=%t OpenAPI=%d", got, known, operation.SuccessStatus)
			}
			var captured *http.Request
			client := &cli{client: &http.Client{Transport: roundTripper(func(request *http.Request) (*http.Response, error) {
				captured = request.Clone(request.Context())
				captured.Body = request.Body
				return &http.Response{StatusCode: operation.SuccessStatus, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
			})}}
			csrf, key := cliProof(operation.Proof)
			requestState := state
			if operation.Proof == "anonymous-login" {
				requestState.Session, requestState.CSRF = "", ""
			}
			response, err := client.request(context.Background(), requestState, declared.method, declared.path, declared.body, csrf, key, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if captured == nil {
				t.Fatal("request was not captured")
			}
			assertCLIProof(t, captured, requestState, operation.Proof)
			if declared.operationID == "createAcornFoxApp" {
				var body map[string]any
				if err := json.NewDecoder(captured.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				source, ok := body["source"].(map[string]any)
				if !ok || source["type"] != matrix.SourceRequestType {
					t.Fatalf("create source=%v", body["source"])
				}
			}
		})
	}
}

func cliProof(proof string) (bool, string) {
	switch proof {
	case "anonymous-login", "session-read":
		return false, ""
	case "csrf-session-mutation":
		return true, ""
	case "csrf-idempotency-mutation":
		return true, "parity-key"
	default:
		return false, "unexpected-proof"
	}
}

func assertCLIProof(t *testing.T, request *http.Request, state sessionState, proof string) {
	t.Helper()
	hasSession := state.Session != "" && cookieRequest(request, "__Host-acornfox_session") == state.Session
	hasCSRF := state.CSRF != "" && cookieRequest(request, "__Host-acornfox_csrf") == state.CSRF && request.Header.Get("X-AcornFox-CSRF") == state.CSRF
	hasOrigin := request.Header.Get("Origin") == state.Origin
	hasKey := request.Header.Get("Idempotency-Key") != ""
	switch proof {
	case "anonymous-login":
		if hasSession || hasCSRF || !hasOrigin || hasKey {
			t.Fatalf("anonymous login proof headers=%v cookies=%v", request.Header, request.Cookies())
		}
	case "session-read":
		if !hasSession || hasCSRF || hasOrigin || hasKey {
			t.Fatalf("session read proof headers=%v cookies=%v", request.Header, request.Cookies())
		}
	case "csrf-session-mutation":
		if !hasSession || !hasCSRF || !hasOrigin || hasKey {
			t.Fatalf("CSRF mutation proof headers=%v cookies=%v", request.Header, request.Cookies())
		}
	case "csrf-idempotency-mutation":
		if !hasSession || !hasCSRF || !hasOrigin || !hasKey {
			t.Fatalf("idempotent mutation proof headers=%v cookies=%v", request.Header, request.Cookies())
		}
	default:
		t.Fatalf("unknown proof class %q", proof)
	}
}

func sameAcornFoxRoute(template, path string) bool {
	templateParts := strings.Split(strings.Trim(template, "/"), "/")
	pathParts := strings.Split(strings.Trim(strings.SplitN(path, "?", 2)[0], "/"), "/")
	if len(templateParts) != len(pathParts) {
		return false
	}
	for i := range templateParts {
		if strings.HasPrefix(templateParts[i], "{") && strings.HasSuffix(templateParts[i], "}") {
			if pathParts[i] == "" {
				return false
			}
			continue
		}
		if templateParts[i] != pathParts[i] {
			return false
		}
	}
	return true
}
