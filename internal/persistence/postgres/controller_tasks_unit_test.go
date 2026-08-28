package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/open-card/open-card/internal/domain"
)

func TestMapControllerOperationInsertError(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		constraint string
		wantCode   domain.ErrorCode
	}{
		{name: "one active operation", constraint: "operations_one_active_per_environment", wantCode: domain.ErrConflict},
		{name: "idempotency identity", constraint: "operations_environment_id_idempotency_key_key", wantCode: domain.ErrConflict},
		{name: "operation identity", constraint: "operations_pkey", wantCode: domain.ErrConflict},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			err := mapControllerOperationInsertError(&pgconn.PgError{ConstraintName: test.constraint})
			if !domain.IsCode(err, test.wantCode) {
				t.Fatalf("expected %s, got %v", test.wantCode, err)
			}
		})
	}

	backend := errors.New("backend unavailable")
	if got := mapControllerOperationInsertError(backend); !errors.Is(got, backend) {
		t.Fatalf("unclassified backend error lost its cause: %v", got)
	}
}

func TestTaskOutcomeDoesNotReTransitionTerminalDeployment(t *testing.T) {
	for _, status := range []domain.DeploymentStatus{domain.DeploymentFailed, domain.DeploymentRolledBack, domain.DeploymentStopped} {
		deployment := domain.Deployment{Status: status}
		if err := transitionDeploymentForTaskOutcome(&deployment, domain.DeploymentFailed, time.Now()); err != nil {
			t.Fatalf("terminal %s rejected cleanup outcome: %v", status, err)
		}
		if deployment.Status != status {
			t.Fatalf("terminal %s was rewritten to %s", status, deployment.Status)
		}
	}
}

func TestTaskOutcomeStillEnforcesNonTerminalStateMachine(t *testing.T) {
	deployment := domain.Deployment{Status: domain.DeploymentDeploying}
	if err := transitionDeploymentForTaskOutcome(&deployment, domain.DeploymentFailed, time.Now()); err != nil {
		t.Fatal(err)
	}
	if deployment.Status != domain.DeploymentFailed {
		t.Fatalf("deployment status=%s", deployment.Status)
	}
}
