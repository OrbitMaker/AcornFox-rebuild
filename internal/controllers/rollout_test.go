package controllers

import (
	"errors"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func rolloutSpec(release, imageByte string, policy contracts.RuntimeRolloutPolicy) contracts.ServiceGroupRuntimeSpec {
	image := domain.ImageDigest{Repository: "registry.example.test/app/web", Digest: "sha256:" + strings.Repeat(imageByte, 64)}
	return contracts.ServiceGroupRuntimeSpec{
		SchemaVersion: contracts.ServiceGroupRuntimeSchema, ApplicationID: "app_rollout", EnvironmentID: "env_rollout", ReleaseID: domain.ID(release), ServiceGroupID: "group_rollout", ConfigDigest: "sha256:" + strings.Repeat(imageByte, 64), EntryService: "web", Rollout: policy,
		Services: []contracts.ServiceRuntimeSpec{{Name: "web", Role: domain.RoleIngress, Required: true, Image: image, Resources: contracts.ResourceLimits{CPUMillis: 250, MemoryBytes: 64 << 20, DiskBytes: 128 << 20, PIDs: 64}, ContainerPorts: []int{8080}}},
	}
}

func TestRolloutKeepsOldStatelessReleaseUntilHealthyAndGatesCapacity(t *testing.T) {
	current := rolloutSpec("rel_old", "a", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial})
	target := rolloutSpec("rel_new", "b", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutRolling, PreviousDeploymentID: "dep_old", PreserveOldUntilHealthy: true})
	plan, err := PlanServiceGroupRollout(&current, target, true)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Mode != contracts.RuntimeRolloutRolling || !plan.PreserveOldUntilHealthy || len(plan.ChangedServices) != 1 || plan.ChangedServices[0] != "web" || !plan.RollbackWholeRelease || plan.RollbackData {
		t.Fatalf("unexpected rolling plan: %#v", plan)
	}
	if _, err := PlanServiceGroupRollout(&current, target, false); !errors.Is(err, ErrRolloutCapacity) {
		t.Fatalf("parallel capacity shortage was not gated: %v", err)
	}
}

func TestRolloutStatefulWriterRequiresExplicitRecreateAndNeverPromisesDataRollback(t *testing.T) {
	current := rolloutSpec("rel_old", "a", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial})
	target := rolloutSpec("rel_new", "b", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutRolling, PreviousDeploymentID: "dep_old", PreserveOldUntilHealthy: true})
	target.Services = append(target.Services, contracts.ServiceRuntimeSpec{Name: "db", Role: domain.RoleStateful, Required: true, Image: domain.ImageDigest{Repository: "registry.example.test/app/db", Digest: "sha256:" + strings.Repeat("c", 64)}, Resources: contracts.ResourceLimits{CPUMillis: 250, MemoryBytes: 64 << 20, DiskBytes: 128 << 20, PIDs: 64}, Volumes: []domain.VolumeMount{{Name: "data", MountPath: "/data"}}})
	target.VolumeClaims = []contracts.RuntimeVolumeClaim{{ID: "volume_data", Name: "data", SizeBytes: 1 << 30, Retain: true}}
	if _, err := PlanServiceGroupRollout(&current, target, true); err == nil {
		t.Fatal("stateful writer update was accepted without downtime approval")
	}
	target.Rollout = contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutRecreate, PreviousDeploymentID: "dep_old", DowntimeApproved: true}
	plan, err := PlanServiceGroupRollout(&current, target, false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Mode != contracts.RuntimeRolloutRecreate || !plan.RequiresDowntimeApproval || plan.RollbackData {
		t.Fatalf("unexpected stateful plan: %#v", plan)
	}
}
