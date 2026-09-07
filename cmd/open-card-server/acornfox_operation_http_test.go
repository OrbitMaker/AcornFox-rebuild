package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type acornFoxOperationFixture struct {
	result contracts.AcornFoxOperationResult
}

func (f acornFoxOperationFixture) GetAcornFoxOperationResult(_ context.Context, applicationID, operationID domain.ID) (contracts.AcornFoxOperationResult, error) {
	if applicationID != "app_1" || operationID != f.result.OperationID {
		return contracts.AcornFoxOperationResult{}, postgres.ErrNotFound
	}
	return f.result, nil
}

func TestAcornFoxOperationHTTPUsesScopedSafeProjection(t *testing.T) {
	now := time.Unix(1_700_400_000, 0).UTC()
	status := 500
	handler := newAcornFoxOperationHTTPHandler(acornFoxOperationFixture{result: contracts.AcornFoxOperationResult{OperationID: "op_1", OperationType: "observe", Status: contracts.AcornFoxOperationVerified, TaskID: "task_1", DeploymentID: "dep_1", AcceptedAt: now, UpdatedAt: now, Evidence: &contracts.AcornFoxOperationEvidence{Kind: contracts.AcornFoxOperationResponseObservation, Verdict: contracts.AcornFoxOperationEvidenceUnhealthy, ObservedAt: now, HTTPStatus: &status}}})
	response := httptest.NewRecorder()
	handler.Handle(response, httptest.NewRequest(http.MethodGet, "/", nil), "app_1", "op_1")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"verified"`) || !strings.Contains(response.Body.String(), `"verdict":"unhealthy"`) || !strings.Contains(response.Body.String(), `"http_status":500`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	for _, forbidden := range []string{"payload", "failure_reason", "container", "endpoint", "secret"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("operation response leaked %q: %s", forbidden, response.Body.String())
		}
	}
	foreign := httptest.NewRecorder()
	handler.Handle(foreign, httptest.NewRequest(http.MethodGet, "/", nil), "app_other", "op_1")
	if foreign.Code != http.StatusNotFound {
		t.Fatalf("foreign status=%d body=%s", foreign.Code, foreign.Body.String())
	}
}
