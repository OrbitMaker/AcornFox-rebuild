package main

import (
	"net/http"
	"strings"
	"testing"
)

type openAPIParityMatrix struct {
	SourceRequestTypes  []string                 `json:"sourceRequestTypes"`
	SourceRevisionKinds []string                 `json:"sourceRevisionKinds"`
	SourceRequestType   string                   `json:"sourceRequestType"`
	SourceRevisionKind  string                   `json:"sourceRevisionKind"`
	Operations          []openAPIParityOperation `json:"operations"`
}

type openAPIParityOperation struct {
	OperationID     string `json:"operationId"`
	Method          string `json:"method"`
	PathTemplate    string `json:"pathTemplate"`
	SuccessStatuses []int  `json:"successStatuses"`
	Proof           string `json:"proof"`
	Parity          string `json:"parity"`
	CLI             bool   `json:"cli"`
	WebClient       string `json:"webClient"`
}

type cliParityOperation struct {
	operationID string
	method      string
	path        string
	shape       responseShape
	body        any
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
