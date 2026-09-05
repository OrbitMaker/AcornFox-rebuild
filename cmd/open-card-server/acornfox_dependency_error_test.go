package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

func TestAcornFoxDependencyFailureKeepsSafeReasonOnly(t *testing.T) {
	for _, provider := range []string{"bounded-source", "rootless-buildkit-buildctl"} {
		t.Run(provider, func(t *testing.T) {
			err := &contracts.ProviderError{Provider: provider, Code: contracts.ErrUnavailable, Message: "dependency is unavailable", Cause: errors.New("credential-canary"), Details: map[string]string{"private": "private-path-canary"}}
			response := httptest.NewRecorder()
			writeAcornFoxError(response, err)
			body := response.Body.String()
			if response.Code != http.StatusServiceUnavailable || !strings.Contains(body, `"message":"dependency is unavailable"`) || strings.Contains(body, "canary") || strings.Contains(body, provider) {
				t.Fatalf("unsafe or unactionable response: %s", body)
			}
		})
	}
}

func TestAcornFoxActiveOperationHasAnActionableConflict(t *testing.T) {
	response := httptest.NewRecorder()
	writeAcornFoxError(response, errors.Join(postgres.ErrEnvironmentOperationActive, errors.New("private-cause-canary")))
	body := response.Body.String()
	if response.Code != http.StatusConflict || !strings.Contains(body, `"code":"operation_conflict"`) || strings.Contains(body, "canary") {
		t.Fatalf("unexpected conflict response: %s", body)
	}
}
