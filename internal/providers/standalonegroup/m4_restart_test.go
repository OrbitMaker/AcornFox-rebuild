package standalonegroup

import (
	"context"
	"testing"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func TestM4RestartGroupUsesOnlyOwnedContainersAndReplaysIdempotently(t *testing.T) {
	docker := &fakeDocker{containers: map[string]fakeContainer{}, failRun: map[string]error{}, logs: map[string]string{}}
	provider := newGroupProvider(t, docker, &fakeVolumes{})
	spec := groupSpec("rel_m4_restart_group", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial})
	deployment, err := provider.DeployGroup(context.Background(), deployRequest("m4-restart-group-deploy", "dep_m4_restart_group", spec))
	if err != nil {
		t.Fatal(err)
	}
	baseline := len(docker.callsSnapshot())
	request := contracts.RestartGroupRequest{
		DeploymentID:   deployment.ID,
		ServiceGroupID: spec.ServiceGroupID,
		ReleaseID:      spec.ReleaseID,
		Operation:      contracts.OperationContext{IdempotencyKey: "m4-restart-group"},
	}
	if err := provider.RestartGroup(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := provider.RestartGroup(context.Background(), request); err != nil {
		t.Fatal(err)
	}

	owned := map[string]bool{
		provider.containerName(deployment.ID, "db"):  true,
		provider.containerName(deployment.ID, "web"): true,
	}
	var restarts []string
	for _, call := range docker.callsSnapshot()[baseline:] {
		if len(call) == 0 || call[0] != "restart" {
			continue
		}
		if len(call) != 4 || call[1] != "--time" || call[2] != "10" {
			t.Fatalf("restart did not use the fixed timeout: %#v", call)
		}
		container := call[3]
		if !owned[container] {
			t.Fatalf("group restart escaped persisted ownership: %#v", call)
		}
		restarts = append(restarts, container)
	}
	if len(restarts) != 2 {
		t.Fatalf("idempotency replay repeated or omitted group side effects: %#v", docker.callsSnapshot()[baseline:])
	}
	// db is the dependency of web, so group recovery restarts the dependent
	// first and the dependency second, using the persisted deterministic order.
	if want := provider.containerName(deployment.ID, "web"); restarts[0] != want {
		t.Fatalf("group restart order did not use reverse dependency order: %#v", restarts)
	}
	if want := provider.containerName(deployment.ID, "db"); restarts[1] != want {
		t.Fatalf("group restart order did not finish with dependency: %#v", restarts)
	}
}

func TestM4RestartGroupRejectsMismatchedOwnershipWithoutDockerEffects(t *testing.T) {
	docker := &fakeDocker{containers: map[string]fakeContainer{}, failRun: map[string]error{}, logs: map[string]string{}}
	provider := newGroupProvider(t, docker, &fakeVolumes{})
	spec := groupSpec("rel_m4_restart_ownership", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial})
	deployment, err := provider.DeployGroup(context.Background(), deployRequest("m4-restart-ownership-deploy", "dep_m4_restart_ownership", spec))
	if err != nil {
		t.Fatal(err)
	}
	baseline := len(docker.callsSnapshot())

	wrongGroup := contracts.RestartGroupRequest{
		DeploymentID:   deployment.ID,
		ServiceGroupID: domain.ID("group_external"),
		ReleaseID:      spec.ReleaseID,
		Operation:      contracts.OperationContext{IdempotencyKey: "m4-restart-wrong-group"},
	}
	if err := provider.RestartGroup(context.Background(), wrongGroup); err == nil {
		t.Fatal("group restart accepted an external service-group identity")
	}
	wrongRelease := wrongGroup
	wrongRelease.ServiceGroupID = spec.ServiceGroupID
	wrongRelease.ReleaseID = domain.ID("rel_external")
	wrongRelease.Operation.IdempotencyKey = "m4-restart-wrong-release"
	if err := provider.RestartGroup(context.Background(), wrongRelease); err == nil {
		t.Fatal("group restart accepted an external release identity")
	}
	if got := countCalls(docker.callsSnapshot()[baseline:], "restart"); got != 0 {
		t.Fatalf("ownership rejection caused Docker restart side effects: %#v", docker.callsSnapshot()[baseline:])
	}
}
