package standalonegroup

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

// m4VolumeTracker keeps the existing fake volume behavior while recording the
// explicit retention effect used by the old-group retirement assertion.
type m4VolumeTracker struct {
	*fakeVolumes
	mu       sync.Mutex
	retained []string
}

func (v *m4VolumeTracker) Retain(_ context.Context, request contracts.VolumeRequest) error {
	v.mu.Lock()
	v.retained = append(v.retained, request.Volume.Name)
	v.mu.Unlock()
	return nil
}

func newM4TwoPhaseProvider(t *testing.T, docker *fakeDocker, volumes *m4VolumeTracker) *Provider {
	t.Helper()
	provider, err := New(Config{
		TaskPrefix: "opencard-m2-test",
		WorkRoot:   t.TempDir(),
		ImageStore: fakeLoader{},
		Capacity:   contracts.NewFakeCapacityProvider(true),
		Volumes:    volumes,
		Runner:     docker,
		Timeout:    time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func m4ContainerRunning(docker *fakeDocker, name string) bool {
	docker.mu.Lock()
	defer docker.mu.Unlock()
	container, ok := docker.containers[name]
	return ok && container.running
}

func m4HasCallFor(calls [][]string, command, container string) bool {
	for _, call := range calls {
		if len(call) > 0 && call[0] == command && call[len(call)-1] == container {
			return true
		}
	}
	return false
}

func TestM4DeferredRollingKeepsOldUntilExplicitDestroyAfterRestart(t *testing.T) {
	docker := &fakeDocker{containers: map[string]fakeContainer{}, failRun: map[string]error{}, logs: map[string]string{}}
	volumes := &m4VolumeTracker{fakeVolumes: &fakeVolumes{}}
	provider := newM4TwoPhaseProvider(t, docker, volumes)

	oldSpec := groupSpec("rel_m4_two_phase_old", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial})
	old, err := provider.DeployGroup(context.Background(), deployRequest("m4-two-phase-old", "dep_m4_two_phase_old", oldSpec))
	if err != nil {
		t.Fatal(err)
	}
	oldDB := provider.containerName(old.ID, "db")
	oldWeb := provider.containerName(old.ID, "web")

	candidateSpec := groupSpec("rel_m4_two_phase_new", contracts.RuntimeRolloutPolicy{
		Mode:                    contracts.RuntimeRolloutRolling,
		PreviousDeploymentID:    old.ID,
		PreserveOldUntilHealthy: true,
		DeferOldTeardown:        true,
	})
	candidateSpec.Services[0].Resources.CPUMillis = 300
	baseline := len(docker.callsSnapshot())
	candidate, err := provider.DeployGroup(context.Background(), contracts.DeployGroupRequest{
		DeploymentID:  "dep_m4_two_phase_new",
		Spec:          candidateSpec,
		Operation:     contracts.OperationContext{IdempotencyKey: "m4-two-phase-new"},
		ForceRecreate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Status != domain.DeploymentRuntimeReady {
		t.Fatalf("deferred rolling candidate was not runtime-ready: %#v", candidate)
	}

	candidateDB := provider.containerName(candidate.ID, "db")
	candidateWeb := provider.containerName(candidate.ID, "web")
	for _, name := range []string{oldDB, oldWeb, candidateDB, candidateWeb} {
		if !m4ContainerRunning(docker, name) {
			t.Fatalf("expected serving container %q to remain running", name)
		}
	}
	for _, call := range docker.callsSnapshot()[baseline:] {
		if len(call) == 0 {
			continue
		}
		if (call[0] == "stop" || call[0] == "rm") && (call[len(call)-1] == oldDB || call[len(call)-1] == oldWeb) {
			t.Fatalf("deferred rollout retired the old group before route handoff: %#v", call)
		}
	}
	if _, err := os.Stat(provider.durableStatePath(old.ID)); err != nil {
		t.Fatalf("old durable state was removed before explicit retirement: %v", err)
	}
	if _, err := os.Stat(provider.durableStatePath(candidate.ID)); err != nil {
		t.Fatalf("runtime-ready candidate was not persisted: %v", err)
	}

	// A fresh provider must be able to recover both durable groups. This keeps
	// the controller-owned route handoff safe across an Agent restart.
	restarted, err := New(provider.config)
	if err != nil {
		t.Fatal(err)
	}
	for name, deploymentID := range map[string]domain.ID{"old": old.ID, "candidate": candidate.ID} {
		observation, observeErr := restarted.ObserveGroup(context.Background(), contracts.ObserveGroupRequest{
			DeploymentID: deploymentID,
			Operation:    contracts.OperationContext{IdempotencyKey: "m4-two-phase-observe-" + name},
		})
		if observeErr != nil || observation.Status != "runtime_ready" {
			t.Fatalf("restart could not recover %s group: %#v %v", name, observation, observeErr)
		}
	}

	if err := restarted.DestroyGroup(context.Background(), contracts.DestroyRequest{
		DeploymentID:    old.ID,
		PreserveVolumes: true,
		Operation:       contracts.OperationContext{IdempotencyKey: "m4-two-phase-destroy-old"},
	}); err != nil {
		t.Fatal(err)
	}
	if m4ContainerRunning(docker, oldDB) || m4ContainerRunning(docker, oldWeb) {
		t.Fatal("explicit old-group destroy did not retire the exact old containers")
	}
	for _, name := range []string{candidateDB, candidateWeb} {
		if !m4ContainerRunning(docker, name) {
			t.Fatalf("destroying old deployment affected candidate container %q", name)
		}
	}
	if _, err := os.Stat(restarted.durableStatePath(old.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old durable state remained after explicit destroy: %v", err)
	}
	if _, err := os.Stat(restarted.durableStatePath(candidate.ID)); err != nil {
		t.Fatalf("candidate durable state was removed with old deployment: %v", err)
	}
	if m4HasCallFor(docker.callsSnapshot(), "stop", candidateDB) || m4HasCallFor(docker.callsSnapshot(), "stop", candidateWeb) || m4HasCallFor(docker.callsSnapshot(), "rm", candidateDB) || m4HasCallFor(docker.callsSnapshot(), "rm", candidateWeb) {
		t.Fatal("explicit old-group destroy issued a Docker retirement command for the candidate")
	}
	volumes.mu.Lock()
	retained := append([]string(nil), volumes.retained...)
	volumes.mu.Unlock()
	if len(retained) != 1 || volumes.destroyed != 0 {
		t.Fatalf("old-group destroy did not retain, rather than delete, its data volume: retained=%v destroyed=%d", retained, volumes.destroyed)
	}
}

func TestM4DeferredRollingCandidateFailurePreservesOldAndCleansCandidate(t *testing.T) {
	docker := &fakeDocker{containers: map[string]fakeContainer{}, failRun: map[string]error{}, logs: map[string]string{}}
	provider := newM4TwoPhaseProvider(t, docker, &m4VolumeTracker{fakeVolumes: &fakeVolumes{}})

	oldSpec := groupSpec("rel_m4_two_phase_failure_old", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial})
	old, err := provider.DeployGroup(context.Background(), deployRequest("m4-two-phase-failure-old", "dep_m4_two_phase_failure_old", oldSpec))
	if err != nil {
		t.Fatal(err)
	}
	oldDB := provider.containerName(old.ID, "db")
	oldWeb := provider.containerName(old.ID, "web")
	candidateID := domain.ID("dep_m4_two_phase_failure_new")
	candidateSpec := groupSpec("rel_m4_two_phase_failure_new", contracts.RuntimeRolloutPolicy{
		Mode:                    contracts.RuntimeRolloutRolling,
		PreviousDeploymentID:    old.ID,
		PreserveOldUntilHealthy: true,
		DeferOldTeardown:        true,
	})
	candidateSpec.Services[0].Resources.CPUMillis = 300
	candidateDB := provider.containerName(candidateID, "db")
	candidateWeb := provider.containerName(candidateID, "web")
	docker.failRun[candidateWeb] = errors.New("candidate failed before readiness")
	baseline := len(docker.callsSnapshot())
	if _, err := provider.DeployGroup(context.Background(), deployRequest("m4-two-phase-failure-new", candidateID, candidateSpec)); err == nil {
		t.Fatal("failed deferred rolling candidate was accepted")
	}
	if !m4ContainerRunning(docker, oldDB) || !m4ContainerRunning(docker, oldWeb) {
		t.Fatal("candidate failure interrupted the old serving group")
	}
	if m4ContainerRunning(docker, candidateDB) || m4ContainerRunning(docker, candidateWeb) || docker.hasContainer(candidateDB) || docker.hasContainer(candidateWeb) {
		t.Fatal("failed deferred rolling candidate left a container behind")
	}
	for _, call := range docker.callsSnapshot()[baseline:] {
		if len(call) > 0 && (call[0] == "stop" || call[0] == "rm") && (call[len(call)-1] == oldDB || call[len(call)-1] == oldWeb) {
			t.Fatalf("candidate failure retired an old container: %#v", call)
		}
	}
	if _, err := os.Stat(provider.durableStatePath(old.ID)); err != nil {
		t.Fatalf("old durable state was lost after candidate failure: %v", err)
	}
	if _, err := os.Stat(provider.durableStatePath(candidateID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed candidate durable state unexpectedly remained: %v", err)
	}
}
