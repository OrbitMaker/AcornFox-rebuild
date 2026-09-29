package contracts

import (
	"strings"
	"testing"
	"time"
)

func TestAcornFoxOperationResultSeparatesVerifiedExecutionFromHealth(t *testing.T) {
	now := time.Unix(1_700_400_000, 0).UTC()
	status := 500
	result := AcornFoxOperationResult{OperationID: "op_1", OperationType: "observe", Status: AcornFoxOperationVerified, TaskID: "task_1", DeploymentID: "dep_1", AcceptedAt: now, UpdatedAt: now, Evidence: &AcornFoxOperationEvidence{Kind: AcornFoxOperationResponseObservation, Verdict: AcornFoxOperationEvidenceUnhealthy, ObservedAt: now, HTTPStatus: &status}}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(AcornFoxOperationEvidenceObserved), "healthy") {
		t.Fatal("ordinary evidence must not imply health")
	}
	result.Status = AcornFoxOperationUnknown
	if err := result.Validate(); err == nil {
		t.Fatal("unknown result accepted task evidence")
	}
}
