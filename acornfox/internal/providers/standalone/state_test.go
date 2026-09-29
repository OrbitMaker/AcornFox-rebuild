package standalone

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	capacityprovider "github.com/acornfox/acornfox/internal/providers/capacity"
)

func TestFailedDockerRunRemovesNeverStartedContainerBeforeReleasingCapacity(t *testing.T) {
	root := t.TempDir()
	runner := dockerHappyRunner(t)
	happy := runner.run
	failedRun := false
	orphan := false
	runner.run = func(args []string, stdout io.Writer) error {
		if len(args) > 0 && args[0] == "run" && !failedRun {
			failedRun = true
			orphan = true
			if err := happy(args, stdout); err != nil {
				return err
			}
			return errors.New("runtime entrypoint permission denied")
		}
		if len(args) > 1 && args[0] == "container" && args[1] == "inspect" && orphan {
			var captured bytes.Buffer
			if err := happy(args, &captured); err != nil {
				return err
			}
			payload := strings.Replace(captured.String(), `"RestartCount":3`, `"RestartCount":0`, 1)
			payload = strings.Replace(payload, `"State":{"Running":true}`, `"State":{"Running":false,"Status":"created","Pid":0,"StartedAt":"0001-01-01T00:00:00Z"}`, 1)
			_, err := io.WriteString(stdout, payload)
			return err
		}
		if len(args) > 0 && args[0] == "rm" {
			orphan = false
		}
		return happy(args, stdout)
	}
	ports := &fixedPorts{port: 39124}
	provider := testProviderAt(t, root, runner, ports)
	request := testRequest("never-started-cleanup")
	if _, err := provider.Deploy(context.Background(), request); err == nil {
		t.Fatal("failed Docker start became deployment success")
	}
	if got := len(runner.callsFor("rm")); got != 1 || len(runner.callsFor("rm")[0]) != 2 || runner.callsFor("rm")[0][1] != testContainerID {
		t.Fatalf("never-started cleanup did not address exact container ID: %#v", runner.callsFor("rm"))
	}
	snapshot := mustDurableSnapshot(t, provider, request.DeploymentID)
	if snapshot.Phase != "pending" || snapshot.Capacity != nil || snapshot.LeaseGeneration != 1 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	fresh := testProviderAt(t, root, runner, ports)
	if err := fresh.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if deployment, err := fresh.Deploy(context.Background(), request); err != nil || deployment.ID != request.DeploymentID {
		t.Fatalf("retry deployment=%+v err=%v", deployment, err)
	}
	if got := len(runner.callsFor("run")); got != 2 {
		t.Fatalf("run count=%d", got)
	}
}

func TestFailedDockerRunDoesNotForceContainerThatStartsAcrossCleanupBoundary(t *testing.T) {
	runner := dockerHappyRunner(t)
	happy := runner.run
	failedRun := false
	runner.run = func(args []string, stdout io.Writer) error {
		if len(args) > 0 && args[0] == "run" && !failedRun {
			failedRun = true
			if err := happy(args, stdout); err != nil {
				return err
			}
			return errors.New("runtime start acknowledgement failed")
		}
		if len(args) > 1 && args[0] == "container" && args[1] == "inspect" {
			var captured bytes.Buffer
			if err := happy(args, &captured); err != nil {
				return err
			}
			payload := strings.Replace(captured.String(), `"RestartCount":3`, `"RestartCount":0`, 1)
			payload = strings.Replace(payload, `"State":{"Running":true}`, `"State":{"Running":false,"Status":"created","Pid":0,"StartedAt":"0001-01-01T00:00:00Z"}`, 1)
			_, err := io.WriteString(stdout, payload)
			return err
		}
		if len(args) > 0 && args[0] == "rm" {
			return errors.New("container became running")
		}
		return happy(args, stdout)
	}
	ports := &fixedPorts{port: 39124}
	provider := testProvider(t, runner, ports)
	request := testRequest("cleanup-start-race")
	if _, err := provider.Deploy(context.Background(), request); err == nil {
		t.Fatal("cleanup race became deployment success")
	}
	if calls := runner.callsFor("rm"); len(calls) != 1 || len(calls[0]) != 2 || calls[0][1] != testContainerID {
		t.Fatalf("cleanup used a force or non-exact removal: %#v", calls)
	}
	snapshot := mustDurableSnapshot(t, provider, request.DeploymentID)
	ports.mu.Lock()
	released := ports.released
	ports.mu.Unlock()
	if snapshot.Capacity == nil || released != 0 {
		t.Fatalf("uncertain container released capacity: snapshot=%+v released=%d", snapshot, released)
	}
}

func TestPostRunConfigurationDriftDoesNotRemoveContainerOrReleaseCapacity(t *testing.T) {
	runner := dockerHappyRunner(t)
	happy := runner.run
	runner.run = func(args []string, stdout io.Writer) error {
		if len(args) > 1 && args[0] == "container" && args[1] == "inspect" {
			var captured bytes.Buffer
			if err := happy(args, &captured); err != nil {
				return err
			}
			_, err := io.WriteString(stdout, strings.Replace(captured.String(), `"open-card.release-id":"rel_1"`, `"open-card.release-id":"rel_changed"`, 1))
			return err
		}
		return happy(args, stdout)
	}
	ports := &fixedPorts{port: 39124}
	provider := testProvider(t, runner, ports)
	request := testRequest("post-run-drift")
	if _, err := provider.Deploy(context.Background(), request); err == nil {
		t.Fatal("post-run configuration drift became success")
	}
	if calls := runner.callsFor("rm"); len(calls) != 0 {
		t.Fatalf("configuration-drifted container was removed: %#v", calls)
	}
	snapshot := mustDurableSnapshot(t, provider, request.DeploymentID)
	ports.mu.Lock()
	released := ports.released
	ports.mu.Unlock()
	if snapshot.Capacity == nil || released != 0 {
		t.Fatalf("configuration drift released capacity: snapshot=%+v released=%d", snapshot, released)
	}
}

func TestActiveStatePersistenceFailureDoesNotRemoveRunningContainerOrReleaseCapacity(t *testing.T) {
	root := t.TempDir()
	runner := dockerHappyRunner(t)
	happy := runner.run
	request := testRequest("active-persist-failure")
	statePath := filepath.Join(root, ".standalone-state-"+hash(request.DeploymentID.String())[:32]+".json")
	sabotaged := false
	runner.run = func(args []string, stdout io.Writer) error {
		if len(args) > 1 && args[0] == "container" && args[1] == "inspect" {
			if err := happy(args, stdout); err != nil {
				return err
			}
			if !sabotaged {
				sabotaged = true
				if err := os.Remove(statePath); err != nil {
					return err
				}
				if err := os.Mkdir(statePath, 0o700); err != nil {
					return err
				}
			}
			return nil
		}
		return happy(args, stdout)
	}
	ports := &fixedPorts{port: 39124}
	provider := testProviderAt(t, root, runner, ports)
	if _, err := provider.Deploy(context.Background(), request); err == nil {
		t.Fatal("active state persistence failure became deployment success")
	}
	if calls := runner.callsFor("rm"); len(calls) != 0 {
		t.Fatalf("running container was removed after persistence failure: %#v", calls)
	}
	ports.mu.Lock()
	released := ports.released
	ports.mu.Unlock()
	if released != 0 {
		t.Fatalf("running container capacity was released: %d", released)
	}
}

func TestReconcileRemovesHistoricalNeverStartedContainerWithoutCapacity(t *testing.T) {
	root := t.TempDir()
	runner := dockerHappyRunner(t)
	ports := &fixedPorts{port: 39124}
	first := testProviderAt(t, root, runner, ports)
	request := testRequest("historical-never-started")
	deployment, err := first.Deploy(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := mustDurableSnapshot(t, first, deployment.ID)
	snapshot.Phase, snapshot.Capacity, snapshot.LeaseGeneration = "pending", nil, 1
	writeDurableSnapshot(t, first, snapshot)
	ports.Release(39124)
	happy := runner.run
	runner.run = func(args []string, stdout io.Writer) error {
		if len(args) > 1 && args[0] == "container" && args[1] == "inspect" {
			payload := strings.Replace(ownedContainerInspect(request, testDigest), `"RestartCount":3`, `"RestartCount":0`, 1)
			payload = strings.Replace(payload, `"State":{"Running":true}`, `"State":{"Running":false,"Status":"created","Pid":0,"StartedAt":"0001-01-01T00:00:00Z"}`, 1)
			payload = strings.Replace(payload, `"HostPort":"39130"`, `"HostPort":"39124"`, 1)
			_, err := io.WriteString(stdout, payload)
			return err
		}
		return happy(args, stdout)
	}
	fresh := testProviderAt(t, root, runner, ports)
	if err := fresh.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(runner.callsFor("rm")); got != 1 || runner.callsFor("rm")[0][1] != testContainerID {
		t.Fatalf("historical cleanup=%#v", runner.callsFor("rm"))
	}
	recovered := mustDurableSnapshot(t, fresh, deployment.ID)
	if recovered.Phase != "pending" || recovered.Capacity != nil {
		t.Fatalf("recovered=%+v", recovered)
	}
}

func TestReconcileDoesNotRemoveHistoricalContainerThatPreviouslyStarted(t *testing.T) {
	root := t.TempDir()
	runner := dockerHappyRunner(t)
	ports := &fixedPorts{port: 39124}
	first := testProviderAt(t, root, runner, ports)
	request := testRequest("historical-started")
	deployment, err := first.Deploy(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := mustDurableSnapshot(t, first, deployment.ID)
	snapshot.Phase, snapshot.Capacity, snapshot.LeaseGeneration = "pending", nil, 1
	writeDurableSnapshot(t, first, snapshot)
	ports.Release(39124)
	happy := runner.run
	runner.run = func(args []string, stdout io.Writer) error {
		if len(args) > 1 && args[0] == "container" && args[1] == "inspect" {
			payload := strings.Replace(ownedContainerInspect(request, testDigest), `"RestartCount":3`, `"RestartCount":0`, 1)
			payload = strings.Replace(payload, `"State":{"Running":true}`, `"State":{"Running":false,"Status":"exited","Pid":0,"StartedAt":"2026-09-08T00:00:00Z"}`, 1)
			payload = strings.Replace(payload, `"HostPort":"39130"`, `"HostPort":"39124"`, 1)
			_, err := io.WriteString(stdout, payload)
			return err
		}
		return happy(args, stdout)
	}
	fresh := testProviderAt(t, root, runner, ports)
	if err := fresh.Reconcile(context.Background()); err == nil {
		t.Fatal("previously started container was reconciled as never-started")
	}
	if calls := runner.callsFor("rm"); len(calls) != 0 {
		t.Fatalf("previously started container was removed: %#v", calls)
	}
}

func TestNeverStartedPredicateRejectsAnyExecutionOrUncertainState(t *testing.T) {
	base := inspectFacts{RestartCount: 0}
	base.State.Status, base.State.Pid, base.State.StartedAt = "created", 0, "0001-01-01T00:00:00Z"
	if !base.neverStarted() {
		t.Fatal("exact never-started state was rejected")
	}
	for name, mutate := range map[string]func(*inspectFacts){
		"running":       func(f *inspectFacts) { f.State.Running = true },
		"exited":        func(f *inspectFacts) { f.State.Status = "exited" },
		"pid":           func(f *inspectFacts) { f.State.Pid = 1 },
		"restart":       func(f *inspectFacts) { f.RestartCount = 1 },
		"started":       func(f *inspectFacts) { f.State.StartedAt = "2026-09-08T00:00:00Z" },
		"missing start": func(f *inspectFacts) { f.State.StartedAt = "" },
	} {
		t.Run(name, func(t *testing.T) {
			facts := base
			mutate(&facts)
			if facts.neverStarted() {
				t.Fatal("uncertain or executed state was accepted")
			}
		})
	}
}

func TestDurableStateRestoresLifecycleWithoutNewPortLease(t *testing.T) {
	root := t.TempDir()
	runner := dockerHappyRunner(t)
	ports := &fixedPorts{port: 39124}
	first := testProviderAt(t, root, runner, ports)
	request := testRequest("durable-start")
	deployment, err := first.Deploy(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	path := first.durableStatePath(deployment.ID)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("durable state permissions are not strict: info=%v err=%v", info, err)
	}
	allocated := ports.allocated
	fresh := testProviderAt(t, root, runner, ports)
	if err := fresh.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	ports.mu.Lock()
	reconciled, afterAllocation := ports.reconciled, ports.allocated
	ports.mu.Unlock()
	if reconciled != 1 || afterAllocation != allocated {
		t.Fatalf("reconcile changed port allocation: reconciled=%d before=%d after=%d", reconciled, allocated, afterAllocation)
	}
	if observation, err := fresh.Observe(context.Background(), contracts.ObserveRequest{DeploymentID: deployment.ID, Operation: contracts.OperationContext{IdempotencyKey: "durable-observe"}}); err != nil || !observation.CgroupVerified || observation.HostPort != 39124 {
		t.Fatalf("fresh provider did not observe restored state: observation=%#v err=%v", observation, err)
	}
	if err := fresh.Restart(context.Background(), contracts.RestartRequest{DeploymentID: deployment.ID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "durable-restart"}}); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Destroy(context.Background(), contracts.DestroyRequest{DeploymentID: deployment.ID, Operation: contracts.OperationContext{IdempotencyKey: "durable-destroy"}}); err != nil {
		t.Fatal(err)
	}
}

func TestDurableStateRejectsUnsafeFileForms(t *testing.T) {
	root := t.TempDir()
	runner := dockerHappyRunner(t)
	provider := testProviderAt(t, root, runner, &fixedPorts{port: 39124})
	deployment, err := provider.Deploy(context.Background(), testRequest("durable-unsafe"))
	if err != nil {
		t.Fatal(err)
	}
	path := provider.durableStatePath(deployment.ID)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := provider.readDurableState(deployment.ID); err == nil {
		t.Fatal("permissive durable state was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(original, []byte(` {}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := provider.readDurableState(deployment.ID); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing durable state was accepted: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := provider.readDurableState(deployment.ID); err == nil {
		t.Fatal("unknown durable state field was accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := provider.readDurableState(deployment.ID); err == nil {
		t.Fatal("symlink durable state was accepted")
	}
}

func TestDestroyTombstoneRejectsOldDeployAndAllowsNewOperation(t *testing.T) {
	provider := testProvider(t, dockerHappyRunner(t), &fixedPorts{port: 39124})
	request := testRequest("old-deploy")
	deployment, err := provider.Deploy(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Destroy(context.Background(), contracts.DestroyRequest{DeploymentID: deployment.ID, Operation: contracts.OperationContext{IdempotencyKey: "destroy"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Deploy(context.Background(), request); err == nil {
		t.Fatal("destroyed deployment accepted its old deploy operation")
	}
	fresh := request
	fresh.Operation.IdempotencyKey = "new-deploy"
	if replacement, err := provider.Deploy(context.Background(), fresh); err != nil || replacement.ID != deployment.ID {
		t.Fatalf("new deploy operation did not explicitly start the immutable spec: deployment=%#v err=%v", replacement, err)
	}
}

func TestRecreateFailureRetriesSameOperationWithoutOldContainer(t *testing.T) {
	runner := dockerHappyRunner(t)
	happy := runner.run
	runs := 0
	runner.run = func(args []string, stdout io.Writer) error {
		if len(args) > 0 && args[0] == "run" {
			runs++
			if runs == 2 {
				return errors.New("temporary runtime start failure")
			}
		}
		return happy(args, stdout)
	}
	provider := testProvider(t, runner, &fixedPorts{port: 39124})
	request := testRequest("recreate-failure")
	if _, err := provider.Deploy(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	recreate := request
	recreate.Operation.IdempotencyKey = "recreate-same"
	if deployment, err := provider.Recreate(context.Background(), recreate); err == nil || !deployment.ID.Empty() {
		t.Fatalf("failed recreate returned success: deployment=%#v err=%v", deployment, err)
	}
	if deployment, err := provider.Recreate(context.Background(), recreate); err != nil || deployment.ID != request.DeploymentID {
		t.Fatalf("same recreate operation did not retry from durable state: deployment=%#v err=%v", deployment, err)
	}
	if runs != 3 {
		t.Fatalf("recreate retry did not perform exactly one replacement retry: runs=%d", runs)
	}
}

func TestDestroyRetriesCapacityReleaseAfterFreshProviderRecovery(t *testing.T) {
	root := t.TempDir()
	runner := dockerHappyRunner(t)
	ports := &fixedPorts{port: 39124}
	first := testProviderAt(t, root, runner, ports)
	request := testRequest("destroy-release-retry")
	deployment, err := first.Deploy(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	ports.mu.Lock()
	ports.releaseFailures = 1
	ports.mu.Unlock()
	destroy := contracts.DestroyRequest{DeploymentID: deployment.ID, Operation: contracts.OperationContext{IdempotencyKey: "destroy-release-retry"}}
	if err := first.Destroy(context.Background(), destroy); err == nil {
		t.Fatal("capacity release failure became destroy success")
	}
	if got := len(runner.callsFor("rm")); got != 1 {
		t.Fatalf("first destroy did not remove exactly once: %d", got)
	}
	fresh := testProviderAt(t, root, runner, ports)
	if err := fresh.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Destroy(context.Background(), destroy); err != nil {
		t.Fatalf("same destroy key did not retry release after recovery: %v", err)
	}
	if got := len(runner.callsFor("rm")); got != 1 {
		t.Fatalf("destroy retry repeated Docker removal: %d", got)
	}
	if err := fresh.Destroy(context.Background(), destroy); err != nil {
		t.Fatalf("completed destroy replay failed: %v", err)
	}
}

func TestRestartStartedActionFinalizesAfterFreshProviderWithoutRepeat(t *testing.T) {
	root := t.TempDir()
	runner := dockerHappyRunner(t)
	happy := runner.run
	containerInspects := 0
	startedAt := "before"
	runner.run = func(args []string, stdout io.Writer) error {
		if len(args) > 1 && args[0] == "container" && args[1] == "inspect" {
			containerInspects++
			if containerInspects == 1 {
				return happy(args, stdout)
			}
			payload := strings.Replace(ownedContainerInspect(testRequest("restart-fresh"), testDigest), `"HostPort":"39130"`, `"HostPort":"39124"`, 1)
			_, _ = io.WriteString(stdout, strings.Replace(payload, `"State":{"Running":true}`, `"State":{"Running":true,"StartedAt":"`+startedAt+`"}`, 1))
			return nil
		}
		return happy(args, stdout)
	}
	ports := &fixedPorts{port: 39124}
	first := testProviderAt(t, root, runner, ports)
	request := testRequest("restart-fresh")
	deployment, err := first.Deploy(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	actionKey := "restart-fresh-key"
	first.mu.Lock()
	state := first.states[deployment.ID]
	state.actions[actionIdentity("restart", actionKey)] = runtimeAction{identityHash: actionIdentity("restart", actionKey), action: "restart", fingerprint: state.fingerprint, status: "started", previousContainerID: state.containerID, previousStartedAt: "before", at: state.updatedAt}
	if err := first.persistState(state); err != nil {
		first.mu.Unlock()
		t.Fatal(err)
	}
	first.mu.Unlock()
	startedAt = "after"
	fresh := testProviderAt(t, root, runner, ports)
	if err := fresh.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Restart(context.Background(), contracts.RestartRequest{DeploymentID: deployment.ID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: actionKey}}); err != nil {
		t.Fatal(err)
	}
	if got := len(runner.callsFor("restart")); got != 0 {
		t.Fatalf("fresh same restart key repeated a completed Docker restart: %d", got)
	}
}

func TestDurableStateRejectsFingerprintAndIdentityMismatch(t *testing.T) {
	provider := testProvider(t, dockerHappyRunner(t), &fixedPorts{port: 39124})
	deployment, err := provider.Deploy(context.Background(), testRequest("state-identity"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, found, err := provider.readDurableState(deployment.ID)
	if err != nil || !found {
		t.Fatalf("read durable state: found=%v err=%v", found, err)
	}
	snapshot.Fingerprint = "sha256:wrong"
	if err := validateDurableRuntimeState(snapshot, provider.config); err == nil {
		t.Fatal("durable fingerprint mismatch was accepted")
	}
	snapshot, _, _ = provider.readDurableState(deployment.ID)
	snapshot.Spec.ServiceName = "other"
	if err := validateDurableRuntimeState(snapshot, provider.config); err == nil {
		t.Fatal("durable spec identity mismatch was accepted")
	}
	snapshot, _, _ = provider.readDurableState(deployment.ID)
	snapshot.Actions[0].Action = "scale"
	if err := validateDurableRuntimeState(snapshot, provider.config); err == nil {
		t.Fatal("unknown durable action was accepted")
	}
	snapshot, _, _ = provider.readDurableState(deployment.ID)
	snapshot.Actions[0].Fingerprint = "wrong"
	if err := validateDurableRuntimeState(snapshot, provider.config); err == nil {
		t.Fatal("action fingerprint mismatch was accepted")
	}
}

func TestRecreateSameKeyAfterFreshProviderDoesNotRepeatReplacement(t *testing.T) {
	root := t.TempDir()
	runner := dockerHappyRunner(t)
	ports := &fixedPorts{port: 39124}
	first := testProviderAt(t, root, runner, ports)
	request := testRequest("recreate-fresh")
	if _, err := first.Deploy(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	recreate := request
	recreate.Operation.IdempotencyKey = "recreate-fresh-key"
	if _, err := first.Recreate(context.Background(), recreate); err != nil {
		t.Fatal(err)
	}
	if got := len(runner.callsFor("run")); got != 2 {
		t.Fatalf("initial replacement did not create exactly one new container: %d", got)
	}
	fresh := testProviderAt(t, root, runner, ports)
	if err := fresh.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Recreate(context.Background(), recreate); err != nil {
		t.Fatal(err)
	}
	if got := len(runner.callsFor("run")); got != 2 {
		t.Fatalf("fresh same recreate key repeated Docker replacement: %d", got)
	}
}

func TestRecreateStartedCrashFixtures(t *testing.T) {
	tests := []struct {
		name         string
		prepare      func(*Provider, *fakeRunner, contracts.DeployRequest, domain.ID)
		wantRuns     int
		wantRemovals int
	}{
		{
			name: "old-container-present",
			prepare: func(provider *Provider, _ *fakeRunner, request contracts.DeployRequest, deploymentID domain.ID) {
				snapshot := mustDurableSnapshot(t, provider, deploymentID)
				snapshot.Actions = append(snapshot.Actions, durableRuntimeAction{IdentityHash: actionIdentity("recreate", "recreate-crash"), Action: "recreate", Fingerprint: snapshot.Fingerprint, Status: "started", PreviousContainerID: testContainerID, At: snapshot.UpdatedAt})
				writeDurableSnapshot(t, provider, snapshot)
			},
			wantRuns: 2, wantRemovals: 1,
		},
		{
			name: "container-absent-after-removal",
			prepare: func(provider *Provider, runner *fakeRunner, request contracts.DeployRequest, deploymentID domain.ID) {
				if err := provider.Destroy(context.Background(), contracts.DestroyRequest{DeploymentID: deploymentID, Operation: contracts.OperationContext{IdempotencyKey: "fixture-remove"}}); err != nil {
					t.Fatal(err)
				}
				snapshot := mustDurableSnapshot(t, provider, deploymentID)
				snapshot.Actions = append(snapshot.Actions, durableRuntimeAction{IdentityHash: actionIdentity("recreate", "recreate-crash"), Action: "recreate", Fingerprint: snapshot.Fingerprint, Status: "started", PreviousContainerID: testContainerID, At: snapshot.UpdatedAt})
				writeDurableSnapshot(t, provider, snapshot)
				_ = runner
			},
			wantRuns: 2, wantRemovals: 1,
		},
		{
			name: "new-container-present",
			prepare: func(provider *Provider, _ *fakeRunner, request contracts.DeployRequest, deploymentID domain.ID) {
				snapshot := mustDurableSnapshot(t, provider, deploymentID)
				snapshot.Actions = append(snapshot.Actions, durableRuntimeAction{IdentityHash: actionIdentity("recreate", "recreate-crash"), Action: "recreate", Fingerprint: snapshot.Fingerprint, Status: "started", PreviousContainerID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", At: snapshot.UpdatedAt})
				writeDurableSnapshot(t, provider, snapshot)
			},
			wantRuns: 1, wantRemovals: 0,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			runner := dockerHappyRunner(t)
			ports := &fixedPorts{port: 39124}
			first := testProviderAt(t, root, runner, ports)
			request := testRequest("initial-recreate-crash")
			deployment, err := first.Deploy(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			test.prepare(first, runner, request, deployment.ID)
			fresh := testProviderAt(t, root, runner, ports)
			if err := fresh.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			recreate := request
			recreate.Operation.IdempotencyKey = "recreate-crash"
			if _, err := fresh.Recreate(context.Background(), recreate); err != nil {
				t.Fatal(err)
			}
			if got := len(runner.callsFor("run")); got != test.wantRuns {
				t.Fatalf("run count=%d want=%d", got, test.wantRuns)
			}
			if got := len(runner.callsFor("rm")); got != test.wantRemovals {
				t.Fatalf("rm count=%d want=%d", got, test.wantRemovals)
			}
		})
	}
}

func TestPendingInitialDeployFixtures(t *testing.T) {
	t.Run("container-present-reconciles", func(t *testing.T) {
		root := t.TempDir()
		runner := dockerHappyRunner(t)
		ports := &fixedPorts{port: 39124}
		first := testProviderAt(t, root, runner, ports)
		request := testRequest("pending-present")
		deployment, err := first.Deploy(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := mustDurableSnapshot(t, first, deployment.ID)
		snapshot.Phase = "pending"
		writeDurableSnapshot(t, first, snapshot)
		fresh := testProviderAt(t, root, runner, ports)
		if err := fresh.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("container-absent-is-explicit-non-success", func(t *testing.T) {
		root := t.TempDir()
		runner := dockerHappyRunner(t)
		ports := &fixedPorts{port: 39124}
		first := testProviderAt(t, root, runner, ports)
		request := testRequest("pending-absent")
		deployment, err := first.Deploy(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if err := first.Destroy(context.Background(), contracts.DestroyRequest{DeploymentID: deployment.ID, Operation: contracts.OperationContext{IdempotencyKey: "pending-fixture-remove"}}); err != nil {
			t.Fatal(err)
		}
		snapshot := mustDurableSnapshot(t, first, deployment.ID)
		snapshot.Phase = "pending"
		writeDurableSnapshot(t, first, snapshot)
		fresh := testProviderAt(t, root, runner, ports)
		if err := fresh.Reconcile(context.Background()); err != nil {
			t.Fatalf("confirmed absent pending runtime did not reconcile safely: %v", err)
		}
		retry := request
		retry.Operation.IdempotencyKey = "pending-absent-retry"
		if _, err := fresh.Deploy(context.Background(), retry); err != nil {
			t.Fatalf("confirmed absent pending runtime did not allow one safe retry: %v", err)
		}
	})
}

func TestExitedContainerRemainsObservableAndRestartableAfterFreshReconcile(t *testing.T) {
	root := t.TempDir()
	runner := dockerHappyRunner(t)
	ports := &fixedPorts{port: 39124}
	first := testProviderAt(t, root, runner, ports)
	request := testRequest("exited-runtime")
	deployment, err := first.Deploy(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	happy := runner.run
	runner.run = func(args []string, stdout io.Writer) error {
		if len(args) > 1 && args[0] == "container" && args[1] == "inspect" {
			payload := strings.Replace(ownedContainerInspect(request, testDigest), `"HostPort":"39130"`, `"HostPort":"39124"`, 1)
			_, _ = io.WriteString(stdout, strings.Replace(payload, `"State":{"Running":true}`, `"State":{"Running":false,"Status":"exited"}`, 1))
			return nil
		}
		return happy(args, stdout)
	}
	fresh := testProviderAt(t, root, runner, ports)
	if err := fresh.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	observation, err := fresh.Observe(context.Background(), contracts.ObserveRequest{DeploymentID: deployment.ID, Operation: contracts.OperationContext{IdempotencyKey: "observe-exited"}})
	if err != nil || observation.Status != "exited" || observation.Healthy {
		t.Fatalf("exited runtime observation=%#v err=%v", observation, err)
	}
	if err := fresh.Restart(context.Background(), contracts.RestartRequest{DeploymentID: deployment.ID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "restart-exited"}}); err != nil {
		t.Fatal(err)
	}
}

func TestPendingExitedAndDaemonUnavailableStayNonSuccess(t *testing.T) {
	t.Run("exited", func(t *testing.T) {
		root := t.TempDir()
		runner := dockerHappyRunner(t)
		ports := &fixedPorts{port: 39124}
		first := testProviderAt(t, root, runner, ports)
		request := testRequest("pending-exited")
		deployment, err := first.Deploy(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := mustDurableSnapshot(t, first, deployment.ID)
		snapshot.Phase = "pending"
		writeDurableSnapshot(t, first, snapshot)
		happy := runner.run
		runner.run = func(args []string, stdout io.Writer) error {
			if len(args) > 1 && args[0] == "container" && args[1] == "inspect" {
				payload := strings.Replace(ownedContainerInspect(request, testDigest), `"HostPort":"39130"`, `"HostPort":"39124"`, 1)
				_, _ = io.WriteString(stdout, strings.Replace(payload, `"State":{"Running":true}`, `"State":{"Running":false,"Status":"exited"}`, 1))
				return nil
			}
			return happy(args, stdout)
		}
		fresh := testProviderAt(t, root, runner, ports)
		if err := fresh.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
		observation, err := fresh.Observe(context.Background(), contracts.ObserveRequest{DeploymentID: deployment.ID, Operation: contracts.OperationContext{IdempotencyKey: "pending-exited-observe"}})
		if err != nil || observation.Status != "exited" {
			t.Fatalf("pending exited observation=%#v err=%v", observation, err)
		}
		if _, err := fresh.Deploy(context.Background(), request); err == nil {
			t.Fatal("pending exited deploy replay became success")
		}
		if got := len(runner.callsFor("run")); got != 1 {
			t.Fatalf("pending exited replay created another container: %d", got)
		}
	})
	t.Run("daemon-unavailable", func(t *testing.T) {
		root := t.TempDir()
		runner := dockerHappyRunner(t)
		ports := &fixedPorts{port: 39124}
		first := testProviderAt(t, root, runner, ports)
		request := testRequest("pending-daemon")
		deployment, err := first.Deploy(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := mustDurableSnapshot(t, first, deployment.ID)
		snapshot.Phase = "pending"
		writeDurableSnapshot(t, first, snapshot)
		runsBeforeRecovery := len(runner.callsFor("run"))
		happy := runner.run
		runner.run = func(args []string, stdout io.Writer) error {
			if len(args) > 1 && args[0] == "container" && (args[1] == "inspect" || args[1] == "ls") {
				return errors.New("daemon unavailable")
			}
			return happy(args, stdout)
		}
		fresh := testProviderAt(t, root, runner, ports)
		if err := fresh.Reconcile(context.Background()); err == nil {
			t.Fatal("daemon unavailable reconciled pending state")
		}
		if delta := len(runner.callsFor("run")) - runsBeforeRecovery; delta != 0 {
			t.Fatalf("daemon unavailable reconcile started %d containers", delta)
		}
	})
}

func TestConcurrentDifferentRecreateKeysSerializeOneDeployment(t *testing.T) {
	runner := dockerHappyRunner(t)
	provider := testProvider(t, runner, &fixedPorts{port: 39124})
	request := testRequest("recreate-concurrent")
	if _, err := provider.Deploy(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	errorsByKey := make(chan error, 2)
	for _, key := range []string{"recreate-a", "recreate-b"} {
		wait.Add(1)
		go func(key string) {
			defer wait.Done()
			item := request
			item.Operation.IdempotencyKey = key
			_, err := provider.Recreate(context.Background(), item)
			errorsByKey <- err
		}(key)
	}
	wait.Wait()
	close(errorsByKey)
	for err := range errorsByKey {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := len(runner.callsFor("rm")); got != 2 {
		t.Fatalf("different recreate keys overlapped or skipped removal: %d", got)
	}
	if got := len(runner.callsFor("run")); got != 3 {
		t.Fatalf("different recreate keys corrupted replacement count: %d", got)
	}
	if _, found, err := provider.readDurableState(request.DeploymentID); err != nil || !found {
		t.Fatalf("concurrent recreate left invalid durable state: found=%v err=%v", found, err)
	}
}

func TestSameKeyRetryUsesFreshGenerationWithRealCapacityProvider(t *testing.T) {
	capacity, err := capacityprovider.New(capacityprovider.Config{
		Reader: capacityprovider.ReaderFunc(func(context.Context, string) (capacityprovider.HostCapacity, error) {
			return capacityprovider.HostCapacity{TotalCPUMillis: 8_000, AvailableCPUMillis: 8_000, TotalMemoryBytes: 8 << 30, AvailableMemoryBytes: 8 << 30, TotalDiskBytes: 40 << 30, AvailableDiskBytes: 40 << 30}, nil
		}),
		PortAllocator: capacityprovider.PortAllocatorFunc(func(context.Context) (net.Listener, error) { return net.Listen("tcp4", "127.0.0.1:0") }),
	})
	if err != nil {
		t.Fatal(err)
	}
	runner := dockerHappyRunner(t)
	happy := runner.run
	runs := 0
	runner.run = func(args []string, stdout io.Writer) error {
		if len(args) > 0 && args[0] == "run" {
			runs++
			if runs == 1 {
				return errors.New("controlled run failure")
			}
		}
		return happy(args, stdout)
	}
	provider, err := New(Config{TaskPrefix: "opencard-m1", WorkRoot: t.TempDir(), Runner: runner, Capacity: capacity, ImageStore: fakeImageStore{archive: []byte("persistent OCI archive"), result: contracts.StoreOCIResult{Image: testImage(), StorageRef: "oci://artifact/immutable", SizeBytes: 22}}, Clock: func() time.Time { return time.Unix(100, 0).UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest("real-capacity-generation")
	if _, err := provider.Deploy(context.Background(), request); err == nil {
		t.Fatal("controlled gen0 failure became success")
	}
	if capacity.ActiveLeaseCount() != 0 {
		t.Fatalf("gen0 cleanup leaked capacity: %d", capacity.ActiveLeaseCount())
	}
	if deployment, err := provider.Deploy(context.Background(), request); err != nil || deployment.ID != request.DeploymentID {
		t.Fatalf("same key did not create gen1: deployment=%#v err=%v", deployment, err)
	}
	if runs != 2 || capacity.ActiveLeaseCount() != 1 {
		t.Fatalf("gen1 did not reserve/activate exactly one lease: runs=%d active=%d", runs, capacity.ActiveLeaseCount())
	}
	if err := provider.Destroy(context.Background(), contracts.DestroyRequest{DeploymentID: request.DeploymentID, Operation: contracts.OperationContext{IdempotencyKey: "real-capacity-destroy"}}); err != nil {
		t.Fatal(err)
	}
	if capacity.ActiveLeaseCount() != 0 {
		t.Fatalf("gen1 destroy did not release capacity: %d", capacity.ActiveLeaseCount())
	}
}

func TestPersistAfterReserveFailureDurablyAdvancesGeneration(t *testing.T) {
	capacity := realCapacityProvider(t)
	root := t.TempDir()
	statePath := ""
	armed := true
	wrapped := reserveHookCapacity{CapacityProvider: capacity, afterReserve: func() {
		if !armed {
			return
		}
		armed = false
		if err := os.Remove(statePath); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(statePath, 0o700); err != nil {
			t.Fatal(err)
		}
	}, beforeRelease: func() {
		if info, err := os.Stat(statePath); err == nil && info.IsDir() {
			if err := os.Remove(statePath); err != nil {
				t.Fatal(err)
			}
		}
	}}
	runner := dockerHappyRunner(t)
	provider, err := New(Config{TaskPrefix: "opencard-m1", WorkRoot: root, Runner: runner, Capacity: wrapped, ImageStore: fakeImageStore{archive: []byte("persistent OCI archive"), result: contracts.StoreOCIResult{Image: testImage(), StorageRef: "oci://artifact/immutable", SizeBytes: 22}}, Clock: func() time.Time { return time.Unix(100, 0).UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest("persist-after-reserve")
	statePath = provider.durableStatePath(request.DeploymentID)
	if _, err := provider.Deploy(context.Background(), request); err == nil {
		t.Fatal("post-reserve durable write failure became success")
	}
	if capacity.ActiveLeaseCount() != 0 {
		t.Fatalf("post-reserve failure leaked capacity: %d", capacity.ActiveLeaseCount())
	}
	if deployment, err := provider.Deploy(context.Background(), request); err != nil || deployment.ID != request.DeploymentID {
		t.Fatalf("same key did not retry gen1 after durable cleanup: deployment=%#v err=%v", deployment, err)
	}
	if len(runner.callsFor("run")) != 1 || capacity.ActiveLeaseCount() != 1 {
		t.Fatalf("gen1 retry did not create one active workload: runs=%d active=%d", len(runner.callsFor("run")), capacity.ActiveLeaseCount())
	}
	if err := provider.Destroy(context.Background(), contracts.DestroyRequest{DeploymentID: request.DeploymentID, Operation: contracts.OperationContext{IdempotencyKey: "persist-after-reserve-destroy"}}); err != nil {
		t.Fatal(err)
	}
	if capacity.ActiveLeaseCount() != 0 {
		t.Fatalf("gen1 destroy leaked capacity: %d", capacity.ActiveLeaseCount())
	}
}

func realCapacityProvider(t *testing.T) *capacityprovider.Provider {
	t.Helper()
	provider, err := capacityprovider.New(capacityprovider.Config{Reader: capacityprovider.ReaderFunc(func(context.Context, string) (capacityprovider.HostCapacity, error) {
		return capacityprovider.HostCapacity{TotalCPUMillis: 8_000, AvailableCPUMillis: 8_000, TotalMemoryBytes: 8 << 30, AvailableMemoryBytes: 8 << 30, TotalDiskBytes: 40 << 30, AvailableDiskBytes: 40 << 30}, nil
	}), PortAllocator: capacityprovider.PortAllocatorFunc(func(context.Context) (net.Listener, error) { return net.Listen("tcp4", "127.0.0.1:0") })})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

type reserveHookCapacity struct {
	contracts.CapacityProvider
	afterReserve  func()
	beforeRelease func()
}

func (provider reserveHookCapacity) Reserve(ctx context.Context, request contracts.CapacityRequest) (contracts.CapacityLease, error) {
	lease, err := provider.CapacityProvider.Reserve(ctx, request)
	if err == nil && provider.afterReserve != nil {
		provider.afterReserve()
	}
	return lease, err
}
func (provider reserveHookCapacity) Release(ctx context.Context, lease contracts.CapacityLease, operation contracts.OperationContext) error {
	if provider.beforeRelease != nil {
		provider.beforeRelease()
	}
	return provider.CapacityProvider.Release(ctx, lease, operation)
}

func mustDurableSnapshot(t *testing.T, provider *Provider, deploymentID domain.ID) durableRuntimeState {
	t.Helper()
	snapshot, found, err := provider.readDurableState(deploymentID)
	if err != nil || !found {
		t.Fatalf("read durable snapshot: found=%v err=%v", found, err)
	}
	return snapshot
}

func writeDurableSnapshot(t *testing.T, provider *Provider, snapshot durableRuntimeState) {
	t.Helper()
	if err := validateDurableRuntimeState(snapshot, provider.config); err != nil {
		t.Fatalf("fixture durable state invalid: %v", err)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(provider.durableStatePath(snapshot.Deployment.ID), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}
