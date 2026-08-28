package contracts

import (
	"testing"

	"github.com/open-card/open-card/internal/domain"
)

func TestRuntimeRolloutPolicyDefersOldTeardownOnlyForSafeRollingRouteHandoff(t *testing.T) {
	valid := RuntimeRolloutPolicy{
		Mode:                    RuntimeRolloutRolling,
		PreviousDeploymentID:    domain.ID("dep_previous"),
		PreserveOldUntilHealthy: true,
		DeferOldTeardown:        true,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("two-phase rolling policy was rejected: %v", err)
	}

	for name, policy := range map[string]RuntimeRolloutPolicy{
		"initial":  {Mode: RuntimeRolloutInitial, DeferOldTeardown: true},
		"recreate": {Mode: RuntimeRolloutRecreate, PreviousDeploymentID: domain.ID("dep_previous"), DeferOldTeardown: true, DowntimeApproved: true},
	} {
		t.Run(name, func(t *testing.T) {
			if err := policy.Validate(); err == nil {
				t.Fatal("unsafe deferred teardown policy was accepted")
			}
		})
	}
}
