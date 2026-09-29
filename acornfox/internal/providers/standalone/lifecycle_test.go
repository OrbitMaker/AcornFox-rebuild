package standalone

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

func init() {
	if os.Getenv("ACORNFOX_LIFECYCLE_TEST_SUBPROCESS") == "1" {
		runLifecycleCrashRecoverySubprocess()
		os.Exit(0)
	}
}

func runLifecycleCrashRecoverySubprocess() {
	workRoot := os.Getenv("SUBPROCESS_WORK_ROOT")
	depID := domain.ID(os.Getenv("SUBPROCESS_DEPLOYMENT_ID"))
	opKey := os.Getenv("SUBPROCESS_OPERATION_KEY")
	action := os.Getenv("SUBPROCESS_ACTION")
	running := os.Getenv("SUBPROCESS_CONTAINER_RUNNING") == "true"

	runner := newLifecycleDockerRunner(testContainerID)
	runner.created = true
	runner.networkCreated = true
	runner.running = running
	ports := &fixedPorts{port: 39130}

	p, err := New(Config{
		TaskPrefix: "opencard-m1", WorkRoot: workRoot, Runner: runner, Capacity: capacityAdapter{ports},
		ImageStore:               fakeImageStore{archive: []byte("persistent OCI archive"), result: contracts.StoreOCIResult{Image: testImage(), StorageRef: "oci://artifact/immutable", SizeBytes: 22}},
		ExistingNetworkValidator: func(raw []byte) error { return nil },
		RestoreActiveGuard:       func(ctx context.Context) error { return nil },
		Clock:                    func() time.Time { return time.Unix(100, 0).UTC() },
	})
	if err != nil {
		os.Exit(98)
	}

	if action == "stop" {
		err = p.Stop(context.Background(), contracts.StopRequest{
			DeploymentID: depID,
			ServiceName:  "web",
			Operation:    contracts.OperationContext{IdempotencyKey: opKey},
		})
	} else if action == "start" {
		err = p.Start(context.Background(), contracts.StartRequest{
			DeploymentID: depID,
			ServiceName:  "web",
			Operation:    contracts.OperationContext{IdempotencyKey: opKey},
		})
	} else {
		os.Exit(99)
	}

	if err != nil {
		var pErr *contracts.ProviderError
		if errors.As(err, &pErr) && pErr.Code == contracts.ErrConflict {
			os.Exit(42) // Distinct exit code for ErrConflict
		}
		os.Exit(43) // Other error
	}
	os.Exit(0)
}

type lifecycleDockerRunner struct {
	mu                  sync.Mutex
	created             bool
	running             bool
	networkCreated      bool
	containerID         string
	networkID           string
	containerStartedAt  string
	runArgs             []string
	calls               [][]string
	driftConfig         bool
	driftID             bool
	missingID           bool
	daemonDown          bool
	networkExtra        bool
	networkMissing      bool
	networkWrongID      bool
	networkInspectError bool
}

func newLifecycleDockerRunner(containerID string) *lifecycleDockerRunner {
	return &lifecycleDockerRunner{
		containerID:    containerID,
		networkID:      strings.Repeat("1", 64),
		running:        false,
		created:        false,
		networkCreated: true,
	}
}

func (r *lifecycleDockerRunner) callsFor(prefix ...string) [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var calls [][]string
	for _, call := range r.calls {
		if len(call) < len(prefix) {
			continue
		}
		match := true
		for i := range prefix {
			if call[i] != prefix[i] {
				match = false
			}
		}
		if match {
			calls = append(calls, append([]string(nil), call...))
		}
	}
	return calls
}

func (r *lifecycleDockerRunner) Run(_ context.Context, command string, args []string, stdout, stderr io.Writer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, append([]string(nil), args...))

	if r.daemonDown {
		return errors.New("daemon connection failed")
	}

	if len(args) > 0 {
		switch args[0] {
		case "stop":
			r.running = false
			return nil
		case "start":
			r.running = true
			return nil
		case "restart":
			r.running = true
			return nil
		case "rm":
			r.created = false
			r.running = false
			return nil
		}
	}

	if len(args) > 1 && args[0] == "network" && args[1] == "create" {
		r.networkCreated = true
		return nil
	}

	cmdPrefix := strings.Join(args[:min(2, len(args))], " ")
	switch cmdPrefix {
	case "container inspect":
		if !r.created || r.missingID {
			return errors.New("no such container")
		}
		payload := ownedContainerInspect(testRequest("runtime-inspect"), testDigest)
		published := ""
		for index := 0; index+1 < len(r.runArgs); index++ {
			if r.runArgs[index] == "--publish" {
				published = r.runArgs[index+1]
			}
		}
		if published != "" {
			parts := strings.Split(published, ":")
			payload = strings.Replace(payload, `"HostPort":"39130"`, `"HostPort":"`+parts[1]+`"`, 1)
		}
		if !r.running {
			payload = strings.Replace(payload, `"Running":true`, `"Running":false,"Status":"exited"`, 1)
		} else {
			payload = strings.Replace(payload, `"Running":true`, `"Running":true,"Status":"running"`, 1)
			if r.containerStartedAt != "" {
				payload = strings.Replace(payload, `"Status":"running"`, `"Status":"running","StartedAt":"`+r.containerStartedAt+`"`, 1)
			}
		}
		if r.driftID {
			payload = strings.Replace(payload, `"Id":"`+testContainerID+`"`, `"Id":"badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad1"`, 1)
		}
		if r.driftConfig {
			payload = strings.Replace(payload, testDigest, "sha256:drifted00000000000000000000000000000000000000000000000000000000", -1)
		}
		if r.networkMissing {
			payload = strings.Replace(payload, `"HostConfig":{`, `"NetworkSettings":{"Networks":null},"HostConfig":{`, 1)
		} else if r.networkExtra {
			payload = strings.Replace(payload, `"HostConfig":{`, `"NetworkSettings":{"Networks":{"opencard-m1-network":{"NetworkID":`+fmt.Sprintf("%q", r.networkID)+`},"rogue":{"NetworkID":"`+strings.Repeat("9", 64)+`"}}},"HostConfig":{`, 1)
		} else if r.networkWrongID {
			payload = strings.Replace(payload, `"HostConfig":{`, `"NetworkSettings":{"Networks":{"opencard-m1-network":{"NetworkID":"`+strings.Repeat("3", 64)+`"}}},"HostConfig":{`, 1)
		} else {
			payload = strings.Replace(payload, `"HostConfig":{`, `"NetworkSettings":{"Networks":{"opencard-m1-network":{"NetworkID":`+fmt.Sprintf("%q", r.networkID)+`}}},"HostConfig":{`, 1)
		}
		_, _ = io.WriteString(stdout, payload)
		return nil

	case "container ls":
		if r.missingID {
			_, _ = io.WriteString(stdout, "")
			return nil
		}
		_, _ = io.WriteString(stdout, r.containerID+"\n")
		return nil

	case "load --input":
		return nil

	case "image inspect":
		_, _ = io.WriteString(stdout, testDigest+`|{"Volumes":null}`)
		return nil

	case "network inspect":
		if r.networkInspectError {
			return errors.New("network inspect failed")
		}
		if !r.networkCreated {
			return errors.New("network does not exist")
		}
		_, _ = io.WriteString(stdout, fmt.Sprintf(`[{"Id":%q}]`, r.networkID))
		return nil

	case "inspect --format":
		_, _ = io.WriteString(stdout, `{"Status":"running","Running":true}|0|134217728|134217728|100000|50000|64|`+r.containerID+`|{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"39130"}]}`)
		return nil

	default:
		// fallthrough
	}

	if len(args) > 0 && args[0] == "run" {
		r.runArgs = append([]string(nil), args...)
		r.created = true
		r.running = true
	}
	if len(args) > 0 && args[0] == "rm" {
		r.created = false
		r.running = false
	}
	return nil
}

func testLifecycleProviderAt(t *testing.T, workRoot string, runner *lifecycleDockerRunner, ports *fixedPorts) *Provider {
	if t != nil {
		t.Helper()
	}
	provider, err := New(Config{
		TaskPrefix: "opencard-m1", WorkRoot: workRoot, Runner: runner, Capacity: capacityAdapter{ports},
		ImageStore:               fakeImageStore{archive: []byte("persistent OCI archive"), result: contracts.StoreOCIResult{Image: testImage(), StorageRef: "oci://artifact/immutable", SizeBytes: 22}},
		ExistingNetworkValidator: func(raw []byte) error { return nil },
		RestoreActiveGuard:       func(ctx context.Context) error { return nil },
		Clock:                    func() time.Time { return time.Unix(100, 0).UTC() },
	})
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		return nil
	}
	return provider
}

func setupLifecycleTestDeployment(t *testing.T, runner *lifecycleDockerRunner, ports *fixedPorts) (*Provider, string) {
	t.Helper()
	workRoot := t.TempDir()
	provider := testLifecycleProviderAt(t, workRoot, runner, ports)

	// Deploy initial active container
	req := testRequest("deploy-init")
	dep, err := provider.Deploy(context.Background(), req)
	if err != nil {
		t.Fatalf("setup deploy: %v", err)
	}
	if dep.Status != domain.DeploymentRuntimeReady {
		t.Fatalf("expected runtime_ready, got %s", dep.Status)
	}
	return provider, workRoot
}

func TestLifecycleStopAndStartSuccessWithSchema3AndRetainedCapacity(t *testing.T) {
	runner := newLifecycleDockerRunner(testContainerID)
	ports := &fixedPorts{port: 39130}
	provider, workRoot := setupLifecycleTestDeployment(t, runner, ports)

	depID := domain.ID("dep_1234567890abcdef")
	stopOp := contracts.OperationContext{IdempotencyKey: "stop-key-1"}

	// 1. Stop active workload
	err := provider.Stop(context.Background(), contracts.StopRequest{DeploymentID: depID, ServiceName: "web", Operation: stopOp})
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// Verify state is paused and schema is 3
	state, found, err := provider.readDurableState(depID)
	if err != nil || !found {
		t.Fatalf("read durable state: found=%t err=%v", found, err)
	}
	if state.Phase != "paused" || state.Deployment.Status != domain.DeploymentPaused {
		t.Fatalf("expected phase paused, got phase=%s status=%s", state.Phase, state.Deployment.Status)
	}
	if state.SchemaVersion != "3" {
		t.Fatalf("expected schema version 3, got %s", state.SchemaVersion)
	}
	// Verify capacity was NOT released
	if ports.released != 0 {
		t.Fatalf("capacity lease was incorrectly released on stop: released=%d", ports.released)
	}

	// 2. Start workload back to active
	startOp := contracts.OperationContext{IdempotencyKey: "start-key-1"}
	err = provider.Start(context.Background(), contracts.StartRequest{DeploymentID: depID, ServiceName: "web", Operation: startOp})
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Verify state is active and schema remains 3 (never downgraded)
	stateAfter, found, err := provider.readDurableState(depID)
	if err != nil || !found {
		t.Fatalf("read durable state after start: found=%t err=%v", found, err)
	}
	if stateAfter.Phase != "active" || stateAfter.Deployment.Status != domain.DeploymentRuntimeReady {
		t.Fatalf("expected phase active, got phase=%s status=%s", stateAfter.Phase, stateAfter.Deployment.Status)
	}
	if stateAfter.SchemaVersion != "3" {
		t.Fatalf("schema version downgraded from 3: %s", stateAfter.SchemaVersion)
	}

	// 3. Fresh Provider Reconcile after restart
	freshProvider := testLifecycleProviderAt(t, workRoot, runner, ports)
	if err := freshProvider.Reconcile(context.Background()); err != nil {
		t.Fatalf("fresh provider reconcile: %v", err)
	}
	// Verify fresh provider loaded state as schema 3
	freshState, found, err := freshProvider.readDurableState(depID)
	if err != nil || !found || freshState.SchemaVersion != "3" {
		t.Fatalf("fresh state schema is not 3: %#v err=%v", freshState, err)
	}
}

func TestLifecycleBidirectionalAntiUndoAndReplaySafety(t *testing.T) {
	runner := newLifecycleDockerRunner(testContainerID)
	ports := &fixedPorts{port: 39130}
	provider, workRoot := setupLifecycleTestDeployment(t, runner, ports)
	depID := domain.ID("dep_1234567890abcdef")

	stopKeyA := contracts.OperationContext{IdempotencyKey: "stop-key-A"}
	startKeyB := contracts.OperationContext{IdempotencyKey: "start-key-B"}
	stopKeyC := contracts.OperationContext{IdempotencyKey: "stop-key-C"}

	// Step 1: Stop(key A) -> paused
	if err := provider.Stop(context.Background(), contracts.StopRequest{DeploymentID: depID, ServiceName: "web", Operation: stopKeyA}); err != nil {
		t.Fatalf("Stop A: %v", err)
	}
	if runner.running {
		t.Fatal("expected container stopped after Stop A")
	}

	// Step 2: Start(key B) -> active
	if err := provider.Start(context.Background(), contracts.StartRequest{DeploymentID: depID, ServiceName: "web", Operation: startKeyB}); err != nil {
		t.Fatalf("Start B: %v", err)
	}
	if !runner.running {
		t.Fatal("expected container running after Start B")
	}

	// Step 3 (P1-1): Replay Stop(key A) while active -> must not stop running container
	if err := provider.Stop(context.Background(), contracts.StopRequest{DeploymentID: depID, ServiceName: "web", Operation: stopKeyA}); err != nil {
		t.Fatalf("replay Stop A should succeed idempotently: %v", err)
	}
	if !runner.running {
		t.Fatal("P1-1 VIOLATION: replaying old Stop A stopped the active container!")
	}
	state, _, _ := provider.readDurableState(depID)
	if state.Phase != "active" {
		t.Fatalf("P1-1 VIOLATION: replaying old Stop A changed phase to %s", state.Phase)
	}

	// Step 4: Stop(key C) -> paused
	if err := provider.Stop(context.Background(), contracts.StopRequest{DeploymentID: depID, ServiceName: "web", Operation: stopKeyC}); err != nil {
		t.Fatalf("Stop C: %v", err)
	}
	if runner.running {
		t.Fatal("expected container stopped after Stop C")
	}

	// Step 5 (P1-1): Replay Start(key B) while paused -> must not start paused container
	if err := provider.Start(context.Background(), contracts.StartRequest{DeploymentID: depID, ServiceName: "web", Operation: startKeyB}); err != nil {
		t.Fatalf("replay Start B should succeed idempotently: %v", err)
	}
	if runner.running {
		t.Fatal("P1-1 VIOLATION: replaying old Start B started the paused container!")
	}
	state, _, _ = provider.readDurableState(depID)
	if state.Phase != "paused" {
		t.Fatalf("P1-1 VIOLATION: replaying old Start B changed phase to %s", state.Phase)
	}

	// Step 6: Test fresh Provider reboot preserves anti-undo
	freshProvider := testLifecycleProviderAt(t, workRoot, runner, ports)
	if err := freshProvider.Reconcile(context.Background()); err != nil {
		t.Fatalf("fresh provider reconcile: %v", err)
	}
	if err := freshProvider.Start(context.Background(), contracts.StartRequest{DeploymentID: depID, ServiceName: "web", Operation: startKeyB}); err != nil {
		t.Fatalf("fresh provider replay Start B: %v", err)
	}
	if runner.running {
		t.Fatal("P1-1 VIOLATION: fresh provider replay Start B started the paused container!")
	}
}

func TestLifecycleNoopRecordsKeyAsSucceeded(t *testing.T) {
	runner := newLifecycleDockerRunner(testContainerID)
	ports := &fixedPorts{port: 39130}
	provider, _ := setupLifecycleTestDeployment(t, runner, ports)
	depID := domain.ID("dep_1234567890abcdef")

	// 1. Initial stop to paused
	stopOp1 := contracts.OperationContext{IdempotencyKey: "stop-op-1"}
	if err := provider.Stop(context.Background(), contracts.StopRequest{DeploymentID: depID, ServiceName: "web", Operation: stopOp1}); err != nil {
		t.Fatal(err)
	}

	// 2. New Stop key X while already paused -> must succeed and record key X
	stopOpX := contracts.OperationContext{IdempotencyKey: "stop-op-X"}
	if err := provider.Stop(context.Background(), contracts.StopRequest{DeploymentID: depID, ServiceName: "web", Operation: stopOpX}); err != nil {
		t.Fatalf("noop stop should succeed: %v", err)
	}

	// 3. Start back to active
	startOp := contracts.OperationContext{IdempotencyKey: "start-op-1"}
	if err := provider.Start(context.Background(), contracts.StartRequest{DeploymentID: depID, ServiceName: "web", Operation: startOp}); err != nil {
		t.Fatal(err)
	}
	if !runner.running {
		t.Fatal("expected running after start")
	}

	// 4. Replay Stop key X -> must NOT stop active container
	if err := provider.Stop(context.Background(), contracts.StopRequest{DeploymentID: depID, ServiceName: "web", Operation: stopOpX}); err != nil {
		t.Fatalf("replay stop key X should succeed idempotently: %v", err)
	}
	if !runner.running {
		t.Fatal("P1-1 VIOLATION: replaying noop-recorded Stop key X stopped the active container!")
	}
}

func TestLifecycleRejectsNameSubstitutionAndContainerDrift(t *testing.T) {
	runner := newLifecycleDockerRunner(testContainerID)
	ports := &fixedPorts{port: 39130}
	provider, workRoot := setupLifecycleTestDeployment(t, runner, ports)
	depID := domain.ID("dep_1234567890abcdef")

	// 1. Simulate name substitution: inspect reports different container ID
	runner.driftID = true
	err := provider.Stop(context.Background(), contracts.StopRequest{DeploymentID: depID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "stop-drift"}})
	if err == nil {
		t.Fatal("P1-2 VIOLATION: Stop must reject substituted container ID")
	}

	// 2. Simulate configuration drift on Start
	runner.driftID = false
	if err := provider.Stop(context.Background(), contracts.StopRequest{DeploymentID: depID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "stop-valid"}}); err != nil {
		t.Fatal(err)
	}
	runner.driftConfig = true
	err = provider.Start(context.Background(), contracts.StartRequest{DeploymentID: depID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "start-drift"}})
	if err == nil {
		t.Fatal("P1-2 VIOLATION: Start must reject drifted container configuration")
	}

	// 3. Simulate missing container on Start -> must NOT recreate
	runner.driftConfig = false
	runner.missingID = true
	err = provider.Start(context.Background(), contracts.StartRequest{DeploymentID: depID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "start-missing"}})
	if err == nil {
		t.Fatal("P1-2 VIOLATION: Start must reject missing container and must not recreate")
	}

	// 4. Test stateFromDurable rejects name substitution on reboot
	runner.missingID = false
	runner.driftID = true
	freshProvider := testLifecycleProviderAt(t, workRoot, runner, ports)
	err = freshProvider.Reconcile(context.Background())
	if err == nil {
		t.Fatal("P1-2 VIOLATION: Reconcile must reject substituted container ID")
	}
}

func TestDestroyPreventsNameSubstitutionAndStrictIDVerification(t *testing.T) {
	runner := newLifecycleDockerRunner(testContainerID)
	ports := &fixedPorts{port: 39130}
	provider, _ := setupLifecycleTestDeployment(t, runner, ports)
	depID := domain.ID("dep_1234567890abcdef")

	// 1. If container is missing but daemon fails -> must NOT treat as absent
	runner.missingID = true
	runner.daemonDown = true
	err := provider.Destroy(context.Background(), contracts.DestroyRequest{DeploymentID: depID, Operation: contracts.OperationContext{IdempotencyKey: "destroy-daemon-down"}})
	if err == nil {
		t.Fatal("P1-2 VIOLATION: Destroy must fail when daemon is down, cannot assume absence")
	}

	// 2. If daemon confirms exact ID is absent -> idempotent convergence to destroyed
	runner.daemonDown = false
	err = provider.Destroy(context.Background(), contracts.DestroyRequest{DeploymentID: depID, Operation: contracts.OperationContext{IdempotencyKey: "destroy-absent-converge"}})
	if err != nil {
		t.Fatalf("Destroy should converge when exact ID is confirmed absent: %v", err)
	}
	if ports.released != 1 {
		t.Fatalf("expected capacity released after idempotent destroy: %d", ports.released)
	}

	// 3. If ID exists but drifted -> reject destroy
	runner2 := newLifecycleDockerRunner(testContainerID)
	ports2 := &fixedPorts{port: 39130}
	provider2, _ := setupLifecycleTestDeployment(t, runner2, ports2)
	runner2.driftConfig = true
	err = provider2.Destroy(context.Background(), contracts.DestroyRequest{DeploymentID: depID, Operation: contracts.OperationContext{IdempotencyKey: "destroy-drifted"}})
	if err == nil {
		t.Fatal("P1-2 VIOLATION: Destroy must reject container when configuration drifted")
	}
}

func TestLifecycleRejectsUnfinishedActionBypass(t *testing.T) {
	runner := newLifecycleDockerRunner(testContainerID)
	ports := &fixedPorts{port: 39130}
	provider, _ := setupLifecycleTestDeployment(t, runner, ports)
	depID := domain.ID("dep_1234567890abcdef")

	// Inject a started unfinished action
	provider.mu.Lock()
	state := provider.states[depID]
	state.actions["action-pending"] = runtimeAction{
		identityHash: "action-pending",
		action:       "restart",
		fingerprint:  state.fingerprint,
		status:       "started",
		at:           time.Now(),
	}
	provider.mu.Unlock()

	// New Stop request must be rejected with conflict
	err := provider.Stop(context.Background(), contracts.StopRequest{DeploymentID: depID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "stop-bypass"}})
	if err == nil {
		t.Fatal("P1-4 VIOLATION: Stop must reject when another action is started/unfinished")
	}
}

func TestReconcileOldDestroyedAndNewActiveWithSamePortDoesNotConflict(t *testing.T) {
	runner := newLifecycleDockerRunner(testContainerID)
	runner.created = true
	runner.running = true
	runner.networkCreated = true
	ports := &fixedPorts{port: 39130}
	workRoot := t.TempDir()
	provider := testLifecycleProviderAt(t, workRoot, runner, ports)

	// 1. Create durable state for new active deployment (port 39130)
	reqNew := testRequest("active-new")
	newLease := contracts.CapacityLease{
		ID:        "cap_new_active",
		Scope:     contracts.CapacityRuntime,
		Resources: reqNew.Spec.Resources,
		HostPort:  39130,
	}
	newState := &runtimeState{
		deployment:    domain.Deployment{ID: reqNew.DeploymentID, ApplicationID: reqNew.Spec.ApplicationID, EnvironmentID: reqNew.Spec.EnvironmentID, ReleaseID: reqNew.Spec.ReleaseID, Status: domain.DeploymentRuntimeReady},
		service:       reqNew.Spec.ServiceName,
		image:         reqNew.Spec.Image,
		container:     "opencard-m1-runtime-" + hash(reqNew.DeploymentID.String())[:20],
		containerID:   testContainerID,
		port:          39130,
		containerPort: 8080,
		resources:     reqNew.Spec.Resources,
		phase:         "active",
		networkID:     runner.networkID,
		fingerprint:   provider.fingerprint(reqNew.DeploymentID, reqNew.Spec),
		capacity:      &newLease,
		createdAt:     time.Now().UTC(),
		updatedAt:     time.Now().UTC(),
		actions:       map[string]runtimeAction{},
	}
	if err := provider.persistState(newState); err != nil {
		t.Fatalf("persist new state: %v", err)
	}

	// 2. Create durable state for old destroyed deployment that crashed before clearing capacity
	oldDepID := domain.ID("dep_9999999999oldold")
	oldSpec := reqNew.Spec
	oldSpec.ReleaseID = "rel_old"
	oldLease := contracts.CapacityLease{
		ID:        "cap_old_destroyed",
		Scope:     contracts.CapacityRuntime,
		Resources: oldSpec.Resources,
		HostPort:  39130, // Reused port!
	}
	oldState := &runtimeState{
		deployment:    domain.Deployment{ID: oldDepID, ApplicationID: oldSpec.ApplicationID, EnvironmentID: oldSpec.EnvironmentID, ReleaseID: oldSpec.ReleaseID, Status: domain.DeploymentStopped},
		service:       oldSpec.ServiceName,
		image:         oldSpec.Image,
		container:     "opencard-m1-runtime-" + hash(oldDepID.String())[:20],
		containerID:   "oldoldoldoldoldoldoldoldoldoldoldoldoldoldoldoldoldoldoldoldold1",
		port:          0,
		containerPort: 8080,
		resources:     oldSpec.Resources,
		phase:         "destroyed",
		destroyed:     true,
		fingerprint:   provider.fingerprint(oldDepID, oldSpec),
		capacity:      &oldLease, // Non-nil leftover capacity!
		createdAt:     time.Now().UTC(),
		updatedAt:     time.Now().UTC(),
		actions:       map[string]runtimeAction{},
	}
	if err := provider.persistState(oldState); err != nil {
		t.Fatalf("persist old state: %v", err)
	}

	// Order A: Reconcile old destroyed first, then new active
	freshA := testLifecycleProviderAt(t, workRoot, runner, ports)
	oldSnapshot, _, _ := freshA.readDurableState(oldDepID)
	newSnapshot, _, _ := freshA.readDurableState(reqNew.DeploymentID)

	// Finalize old destroyed first
	recoveredOld, err := freshA.stateFromDurable(context.Background(), oldSnapshot, contracts.OperationContext{IdempotencyKey: "rec-old"}, contracts.CapabilityRuntimeObserve, "reconcile")
	if err != nil {
		t.Fatalf("reconcile old destroyed failed: %v", err)
	}
	if recoveredOld.capacity != nil {
		t.Fatal("expected old destroyed capacity to be cleared to nil")
	}
	// Reconcile new active second -> must NOT report port conflict
	recoveredNew, err := freshA.stateFromDurable(context.Background(), newSnapshot, contracts.OperationContext{IdempotencyKey: "rec-new"}, contracts.CapabilityRuntimeObserve, "reconcile")
	if err != nil {
		t.Fatalf("P1-B VIOLATION: new active conflicted with finalized old lease: %v", err)
	}
	if recoveredNew.capacity == nil || recoveredNew.port != 39130 {
		t.Fatalf("expected new active lease to remain healthy: port=%d", recoveredNew.port)
	}

	// Order B: Reconcile new active first, then old destroyed
	freshB := testLifecycleProviderAt(t, workRoot, runner, ports)
	// New active first binds port 39130
	_, err = freshB.stateFromDurable(context.Background(), newSnapshot, contracts.OperationContext{IdempotencyKey: "rec-new-b"}, contracts.CapabilityRuntimeObserve, "reconcile")
	if err != nil {
		t.Fatalf("reconcile new active first: %v", err)
	}
	// Old destroyed second must NOT claim port or conflict with new active!
	recoveredOldB, err := freshB.stateFromDurable(context.Background(), oldSnapshot, contracts.OperationContext{IdempotencyKey: "rec-old-b"}, contracts.CapabilityRuntimeObserve, "reconcile")
	if err != nil {
		t.Fatalf("P1-B VIOLATION: old destroyed conflicted with already-active new lease: %v", err)
	}
	if recoveredOldB.capacity != nil {
		t.Fatal("expected old capacity cleared in order B")
	}
}

func TestLifecycleStartNetworkIdentityAndGuardEnforcement(t *testing.T) {
	runner := newLifecycleDockerRunner(testContainerID)
	ports := &fixedPorts{port: 39130}
	provider, workRoot := setupLifecycleTestDeployment(t, runner, ports)
	depID := domain.ID("dep_1234567890abcdef")

	// 1. Normal Stop: records network ID (64-char hex)
	stopOp := contracts.OperationContext{IdempotencyKey: "stop-net-valid"}
	if err := provider.Stop(context.Background(), contracts.StopRequest{DeploymentID: depID, ServiceName: "web", Operation: stopOp}); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	state, _, err := provider.readDurableState(depID)
	if err != nil || state.NetworkID != strings.Repeat("1", 64) {
		t.Fatalf("Stop did not record valid network ID: got=%q err=%v", state.NetworkID, err)
	}

	// 2. Missing attachment (zero attachments) -> Start must conflict before effect
	runner.networkMissing = true
	callsBefore := len(runner.callsFor("start"))
	err = provider.Start(context.Background(), contracts.StartRequest{DeploymentID: depID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "start-missing-net"}})
	if err == nil {
		t.Fatal("Start must reject container with missing network attachments")
	}
	if len(runner.callsFor("start")) != callsBefore {
		t.Fatal("Start executed docker start command despite network attachment failure!")
	}
	runner.networkMissing = false

	// 3. Extra attachment (rogue multi-network) -> Start must conflict before effect
	runner.networkExtra = true
	callsBefore = len(runner.callsFor("start"))
	err = provider.Start(context.Background(), contracts.StartRequest{DeploymentID: depID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "start-extra-net"}})
	if err == nil {
		t.Fatal("Start must reject container with extra network attachments")
	}
	if len(runner.callsFor("start")) != callsBefore {
		t.Fatal("Start executed docker start command despite extra network attachment!")
	}
	runner.networkExtra = false

	// 4. Wrong network ID -> Start must conflict before effect
	runner.networkWrongID = true
	callsBefore = len(runner.callsFor("start"))
	err = provider.Start(context.Background(), contracts.StartRequest{DeploymentID: depID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "start-wrong-net"}})
	if err == nil {
		t.Fatal("Start must reject container with wrong network ID")
	}
	if len(runner.callsFor("start")) != callsBefore {
		t.Fatal("Start executed docker start command despite wrong network ID!")
	}
	runner.networkWrongID = false

	// 5. Network guard failure (RestoreActiveGuard returns error) -> Start must conflict before effect
	providerWithGuard := testLifecycleProviderAt(t, workRoot, runner, ports)
	providerWithGuard.config.RestoreActiveGuard = func(ctx context.Context) error {
		return errors.New("firewall guard failed")
	}
	callsBefore = len(runner.callsFor("start"))
	err = providerWithGuard.Start(context.Background(), contracts.StartRequest{DeploymentID: depID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "start-guard-fail"}})
	if err == nil {
		t.Fatal("Start must reject when network guard is not ready")
	}
	if len(runner.callsFor("start")) != callsBefore {
		t.Fatal("Start executed docker start command despite guard failure!")
	}

	// 6. Network validator failure -> Start must conflict before effect
	providerWithValidator := testLifecycleProviderAt(t, workRoot, runner, ports)
	providerWithValidator.config.ExistingNetworkValidator = func(raw []byte) error {
		return errors.New("network validator rejected")
	}
	callsBefore = len(runner.callsFor("start"))
	err = providerWithValidator.Start(context.Background(), contracts.StartRequest{DeploymentID: depID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "start-validator-fail"}})
	if err == nil {
		t.Fatal("Start must reject when network validator fails")
	}
	if len(runner.callsFor("start")) != callsBefore {
		t.Fatal("Start executed docker start command despite validator failure!")
	}

	// 7. Same-named network recreation (Network ID changed from strings.Repeat("1", 64) to strings.Repeat("2", 64))
	runner.networkID = strings.Repeat("2", 64)
	callsBefore = len(runner.callsFor("start"))
	err = provider.Start(context.Background(), contracts.StartRequest{DeploymentID: depID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "start-recreated-net"}})
	if err == nil {
		t.Fatal("Start must reject when network was recreated with a different ID")
	}
	if len(runner.callsFor("start")) != callsBefore {
		t.Fatal("Start executed docker start command despite network recreation drift!")
	}
	runner.networkID = strings.Repeat("1", 64)

	// 8. Missing networkID in schema 3 state -> Start must reject without guessing
	stateNoNet := state
	stateNoNet.NetworkID = ""
	providerNoNet := testLifecycleProviderAt(t, t.TempDir(), runner, ports)
	_ = providerNoNet.persistState(&runtimeState{
		deployment:    stateNoNet.Deployment,
		service:       stateNoNet.Spec.ServiceName,
		image:         stateNoNet.Spec.Image,
		container:     stateNoNet.Container,
		containerID:   stateNoNet.ContainerID,
		port:          39130,
		containerPort: 8080,
		phase:         "paused",
		schemaVersion: "3",
		networkID:     "", // missing network identity
		fingerprint:   stateNoNet.Fingerprint,
		capacity:      stateNoNet.Capacity,
		createdAt:     time.Now().UTC(),
		updatedAt:     time.Now().UTC(),
		actions:       map[string]runtimeAction{},
	})
	callsBefore = len(runner.callsFor("start"))
	err = providerNoNet.Start(context.Background(), contracts.StartRequest{DeploymentID: depID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "start-nonet"}})
	if err == nil {
		t.Fatal("Start must reject schema 3 state lacking persisted network identity")
	}
	if len(runner.callsFor("start")) != callsBefore {
		t.Fatal("Start executed docker start command despite missing network ID in state!")
	}
}

func TestSchema3DurableValidatorConsistency(t *testing.T) {
	runner := newLifecycleDockerRunner(testContainerID)
	ports := &fixedPorts{port: 39130}
	provider, _ := setupLifecycleTestDeployment(t, runner, ports)
	depID := domain.ID("dep_1234567890abcdef")

	// Create a 100% valid schema 3 paused baseline through actual Stop
	stopOp := contracts.OperationContext{IdempotencyKey: "stop-baseline"}
	if err := provider.Stop(context.Background(), contracts.StopRequest{DeploymentID: depID, ServiceName: "web", Operation: stopOp}); err != nil {
		t.Fatalf("setup stop baseline: %v", err)
	}

	base, found, err := provider.readDurableState(depID)
	if err != nil || !found {
		t.Fatal(err)
	}
	// Verify base snapshot itself is 100% valid first!
	if err := validateDurableRuntimeState(base, provider.config); err != nil {
		t.Fatalf("base schema 3 snapshot must be valid: %v", err)
	}

	// 1. paused + RuntimeReady -> must reject
	s1 := base
	s1.Deployment.Status = domain.DeploymentRuntimeReady
	if err := validateDurableRuntimeState(s1, provider.config); err == nil {
		t.Fatal("validator must reject paused phase with deployment status runtime_ready")
	}

	// 2. active + DeploymentPaused -> must reject
	s2 := base
	s2.Phase = "active"
	s2.Deployment.Status = domain.DeploymentPaused
	if err := validateDurableRuntimeState(s2, provider.config); err == nil {
		t.Fatal("validator must reject active phase with deployment status paused")
	}

	// 3. pausing tests: construct valid pausing state first
	validPausing := base
	validPausing.Phase = "pausing"
	validPausing.Deployment.Status = domain.DeploymentRuntimeReady
	validPausing.Actions = []durableRuntimeAction{{
		IdentityHash:        "stop-hash-1",
		Action:              "stop",
		Fingerprint:         validPausing.Fingerprint,
		Status:              "started",
		PreviousContainerID: validPausing.ContainerID,
		At:                  time.Now().UTC(),
	}}
	if err := validateDurableRuntimeState(validPausing, provider.config); err != nil {
		t.Fatalf("valid pausing baseline must pass validation: %v", err)
	}

	// 3a: pausing + DeploymentPaused -> must reject
	s3a := validPausing
	s3a.Deployment.Status = domain.DeploymentPaused
	if err := validateDurableRuntimeState(s3a, provider.config); err == nil {
		t.Fatal("validator must reject pausing phase with deployment status paused")
	}

	// 3b: pausing lacking started stop action -> must reject
	s3b := validPausing
	s3b.Actions = nil
	if err := validateDurableRuntimeState(s3b, provider.config); err == nil {
		t.Fatal("validator must reject pausing phase lacking started stop action")
	}

	// 3c: pausing started stop action with wrong ContainerID -> must reject
	s3c := validPausing
	s3c.Actions = []durableRuntimeAction{{
		IdentityHash:        "stop-hash-1",
		Action:              "stop",
		Fingerprint:         validPausing.Fingerprint,
		Status:              "started",
		PreviousContainerID: "wrong-container-id-0000000000000000000000000000000000000000000000000",
		At:                  time.Now().UTC(),
	}}
	if err := validateDurableRuntimeState(s3c, provider.config); err == nil {
		t.Fatal("validator must reject pausing action with mismatched container ID")
	}

	// 4. resuming tests: construct valid resuming state first
	validResuming := base
	validResuming.Phase = "resuming"
	validResuming.Deployment.Status = domain.DeploymentPaused
	validResuming.Actions = []durableRuntimeAction{{
		IdentityHash:        "start-hash-1",
		Action:              "start",
		Fingerprint:         validResuming.Fingerprint,
		Status:              "started",
		PreviousContainerID: validResuming.ContainerID,
		At:                  time.Now().UTC(),
	}}
	if err := validateDurableRuntimeState(validResuming, provider.config); err != nil {
		t.Fatalf("valid resuming baseline must pass validation: %v", err)
	}

	// 4a: resuming lacking started start action -> must reject
	s4a := validResuming
	s4a.Actions = nil
	if err := validateDurableRuntimeState(s4a, provider.config); err == nil {
		t.Fatal("validator must reject resuming phase lacking started start action")
	}

	// 4b: resuming started start action with wrong ContainerID -> must reject
	s4b := validResuming
	s4b.Actions = []durableRuntimeAction{{
		IdentityHash:        "start-hash-1",
		Action:              "start",
		Fingerprint:         validResuming.Fingerprint,
		Status:              "started",
		PreviousContainerID: "wrong-container-id-0000000000000000000000000000000000000000000000000",
		At:                  time.Now().UTC(),
	}}
	if err := validateDurableRuntimeState(s4b, provider.config); err == nil {
		t.Fatal("validator must reject resuming action with mismatched container ID")
	}

	// 5. Schema 1 or 2 carrying lifecycle actions -> must reject
	s5 := base
	s5.SchemaVersion = "1"
	s5.Phase = "active"
	s5.Deployment.Status = domain.DeploymentRuntimeReady
	s5.Actions = []durableRuntimeAction{{
		IdentityHash:        "stop-legacy",
		Action:              "stop",
		Fingerprint:         s5.Fingerprint,
		Status:              "succeeded",
		PreviousContainerID: s5.ContainerID,
		At:                  time.Now().UTC(),
	}}
	if err := validateDurableRuntimeState(s5, provider.config); err == nil {
		t.Fatal("validator must reject lifecycle action in schema 1 state")
	}
}

func executeSubprocessHelper(t *testing.T, workRoot, depID, opKey, action string, running bool) int {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable failed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, exe, "-test.run=^$")
	cmd.Env = append(os.Environ(),
		"ACORNFOX_LIFECYCLE_TEST_SUBPROCESS=1",
		"SUBPROCESS_WORK_ROOT="+workRoot,
		"SUBPROCESS_DEPLOYMENT_ID="+depID,
		"SUBPROCESS_OPERATION_KEY="+opKey,
		"SUBPROCESS_ACTION="+action,
		"SUBPROCESS_CONTAINER_RUNNING="+strconv.FormatBool(running),
	)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	t.Fatalf("failed to run helper subprocess: %v output=%s", err, out.String())
	return -1
}

func TestCrashRecoverySubprocessFourQuadrants(t *testing.T) {
	// Quadrant 1: pausing + running (stop in-flight crashed before container exit)
	t.Run("Quadrant1_pausing_running", func(t *testing.T) {
		runner := newLifecycleDockerRunner(testContainerID)
		ports := &fixedPorts{port: 39130}
		provider, workRoot := setupLifecycleTestDeployment(t, runner, ports)
		depID := domain.ID("dep_1234567890abcdef")

		baseState, found, err := provider.readDurableState(depID)
		if err != nil || !found {
			t.Fatal(err)
		}

		actionHash := actionIdentity("stop", "stop-key-crash1")
		now := time.Now().UTC()
		crashState := &runtimeState{
			deployment:    domain.Deployment{ID: depID, ApplicationID: baseState.Deployment.ApplicationID, EnvironmentID: baseState.Deployment.EnvironmentID, ReleaseID: baseState.Deployment.ReleaseID, Status: domain.DeploymentRuntimeReady},
			service:       baseState.Spec.ServiceName,
			image:         baseState.Spec.Image,
			container:     baseState.Container,
			containerID:   baseState.ContainerID,
			port:          39130,
			containerPort: 8080,
			resources:     baseState.Spec.Resources,
			phase:         "pausing",
			schemaVersion: "3",
			networkID:     runner.networkID,
			fingerprint:   baseState.Fingerprint,
			capacity:      baseState.Capacity,
			createdAt:     now,
			updatedAt:     now,
			actions: map[string]runtimeAction{
				actionHash: {identityHash: actionHash, action: "stop", fingerprint: baseState.Fingerprint, status: "started", previousContainerID: baseState.ContainerID, at: now},
			},
		}
		if err := provider.persistState(crashState); err != nil {
			t.Fatalf("persist crash state Q1: %v", err)
		}

		// 1a: Different key -> must conflict (exit 42)
		codeDiff := executeSubprocessHelper(t, workRoot, depID.String(), "stop-key-different", "stop", true)
		if codeDiff != 42 {
			t.Fatalf("expected different key in pausing state to exit 42, got %d", codeDiff)
		}

		// 1b: Same key -> recovers, runs stop, exits 0, final state becomes paused
		codeSame := executeSubprocessHelper(t, workRoot, depID.String(), "stop-key-crash1", "stop", true)
		if codeSame != 0 {
			t.Fatalf("expected same key in pausing state to recover and exit 0, got %d", codeSame)
		}

		// Verify final durable state on disk (reading file, not in-memory)
		finalSnapshot, found, err := provider.readDurableState(depID)
		if err != nil || !found || finalSnapshot.Phase != "paused" || finalSnapshot.Deployment.Status != domain.DeploymentPaused {
			t.Fatalf("final state on disk was not converged to paused: phase=%s status=%s err=%v", finalSnapshot.Phase, finalSnapshot.Deployment.Status, err)
		}
	})

	// Quadrant 2: pausing + exited (docker stop succeeded, crashed before writing paused state)
	t.Run("Quadrant2_pausing_exited", func(t *testing.T) {
		runner := newLifecycleDockerRunner(testContainerID)
		ports := &fixedPorts{port: 39130}
		provider, workRoot := setupLifecycleTestDeployment(t, runner, ports)
		depID := domain.ID("dep_1234567890abcdef")

		baseState, found, err := provider.readDurableState(depID)
		if err != nil || !found {
			t.Fatal(err)
		}

		actionHash := actionIdentity("stop", "stop-key-crash2")
		now := time.Now().UTC()
		crashState := &runtimeState{
			deployment:    domain.Deployment{ID: depID, ApplicationID: baseState.Deployment.ApplicationID, EnvironmentID: baseState.Deployment.EnvironmentID, ReleaseID: baseState.Deployment.ReleaseID, Status: domain.DeploymentRuntimeReady},
			service:       baseState.Spec.ServiceName,
			image:         baseState.Spec.Image,
			container:     baseState.Container,
			containerID:   baseState.ContainerID,
			port:          39130,
			containerPort: 8080,
			resources:     baseState.Spec.Resources,
			phase:         "pausing",
			schemaVersion: "3",
			networkID:     runner.networkID,
			fingerprint:   baseState.Fingerprint,
			capacity:      baseState.Capacity,
			createdAt:     now,
			updatedAt:     now,
			actions: map[string]runtimeAction{
				actionHash: {identityHash: actionHash, action: "stop", fingerprint: baseState.Fingerprint, status: "started", previousContainerID: baseState.ContainerID, at: now},
			},
		}
		if err := provider.persistState(crashState); err != nil {
			t.Fatalf("persist crash state Q2: %v", err)
		}

		// 2a: Different key -> must conflict
		codeDiff := executeSubprocessHelper(t, workRoot, depID.String(), "stop-key-different", "stop", false)
		if codeDiff != 42 {
			t.Fatalf("expected different key in pausing state to exit 42, got %d", codeDiff)
		}

		// 2b: Same key with container already exited -> settles idempotently without repeat effect
		codeSame := executeSubprocessHelper(t, workRoot, depID.String(), "stop-key-crash2", "stop", false)
		if codeSame != 0 {
			t.Fatalf("expected same key to settle exited facts and exit 0, got %d", codeSame)
		}

		finalSnapshot, found, err := provider.readDurableState(depID)
		if err != nil || !found || finalSnapshot.Phase != "paused" || finalSnapshot.Deployment.Status != domain.DeploymentPaused {
			t.Fatalf("final state on disk was not converged to paused: phase=%s status=%s err=%v", finalSnapshot.Phase, finalSnapshot.Deployment.Status, err)
		}
	})

	// Quadrant 3: resuming + exited (start in-flight crashed before container started)
	t.Run("Quadrant3_resuming_exited", func(t *testing.T) {
		runner := newLifecycleDockerRunner(testContainerID)
		ports := &fixedPorts{port: 39130}
		provider, workRoot := setupLifecycleTestDeployment(t, runner, ports)
		depID := domain.ID("dep_1234567890abcdef")

		// First Stop normally to get paused state
		if err := provider.Stop(context.Background(), contracts.StopRequest{DeploymentID: depID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "stop-for-q3"}}); err != nil {
			t.Fatalf("stop for q3: %v", err)
		}
		pausedState, found, err := provider.readDurableState(depID)
		if err != nil || !found {
			t.Fatal(err)
		}

		actionHash := actionIdentity("start", "start-key-crash3")
		now := time.Now().UTC()
		crashState := &runtimeState{
			deployment:    domain.Deployment{ID: depID, ApplicationID: pausedState.Deployment.ApplicationID, EnvironmentID: pausedState.Deployment.EnvironmentID, ReleaseID: pausedState.Deployment.ReleaseID, Status: domain.DeploymentPaused},
			service:       pausedState.Spec.ServiceName,
			image:         pausedState.Spec.Image,
			container:     pausedState.Container,
			containerID:   pausedState.ContainerID,
			port:          39130,
			containerPort: 8080,
			resources:     pausedState.Spec.Resources,
			phase:         "resuming",
			schemaVersion: "3",
			networkID:     runner.networkID,
			fingerprint:   pausedState.Fingerprint,
			capacity:      pausedState.Capacity,
			createdAt:     now,
			updatedAt:     now,
			actions: map[string]runtimeAction{
				actionHash: {identityHash: actionHash, action: "start", fingerprint: pausedState.Fingerprint, status: "started", previousContainerID: pausedState.ContainerID, at: now},
			},
		}
		if err := provider.persistState(crashState); err != nil {
			t.Fatalf("persist crash state Q3: %v", err)
		}

		// 3a: Different key -> must conflict
		codeDiff := executeSubprocessHelper(t, workRoot, depID.String(), "start-key-different", "start", false)
		if codeDiff != 42 {
			t.Fatalf("expected different key in resuming state to exit 42, got %d", codeDiff)
		}

		// 3b: Same key -> executes start, succeeds with exit 0, final state becomes active
		codeSame := executeSubprocessHelper(t, workRoot, depID.String(), "start-key-crash3", "start", false)
		if codeSame != 0 {
			t.Fatalf("expected same key to recover start and exit 0, got %d", codeSame)
		}

		finalSnapshot, found, err := provider.readDurableState(depID)
		if err != nil || !found || finalSnapshot.Phase != "active" || finalSnapshot.Deployment.Status != domain.DeploymentRuntimeReady {
			t.Fatalf("final state on disk was not converged to active: phase=%s status=%s err=%v", finalSnapshot.Phase, finalSnapshot.Deployment.Status, err)
		}
	})

	// Quadrant 4: resuming + running (docker start succeeded, crashed before writing active state)
	t.Run("Quadrant4_resuming_running", func(t *testing.T) {
		runner := newLifecycleDockerRunner(testContainerID)
		ports := &fixedPorts{port: 39130}
		provider, workRoot := setupLifecycleTestDeployment(t, runner, ports)
		depID := domain.ID("dep_1234567890abcdef")

		if err := provider.Stop(context.Background(), contracts.StopRequest{DeploymentID: depID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "stop-for-q4"}}); err != nil {
			t.Fatalf("stop for q4: %v", err)
		}
		pausedState, found, err := provider.readDurableState(depID)
		if err != nil || !found {
			t.Fatal(err)
		}

		actionHash := actionIdentity("start", "start-key-crash4")
		now := time.Now().UTC()
		crashState := &runtimeState{
			deployment:    domain.Deployment{ID: depID, ApplicationID: pausedState.Deployment.ApplicationID, EnvironmentID: pausedState.Deployment.EnvironmentID, ReleaseID: pausedState.Deployment.ReleaseID, Status: domain.DeploymentPaused},
			service:       pausedState.Spec.ServiceName,
			image:         pausedState.Spec.Image,
			container:     pausedState.Container,
			containerID:   pausedState.ContainerID,
			port:          39130,
			containerPort: 8080,
			resources:     pausedState.Spec.Resources,
			phase:         "resuming",
			schemaVersion: "3",
			networkID:     runner.networkID,
			fingerprint:   pausedState.Fingerprint,
			capacity:      pausedState.Capacity,
			createdAt:     now,
			updatedAt:     now,
			actions: map[string]runtimeAction{
				actionHash: {identityHash: actionHash, action: "start", fingerprint: pausedState.Fingerprint, status: "started", previousContainerID: pausedState.ContainerID, at: now},
			},
		}
		if err := provider.persistState(crashState); err != nil {
			t.Fatalf("persist crash state Q4: %v", err)
		}

		// 4a: Different key -> must conflict
		codeDiff := executeSubprocessHelper(t, workRoot, depID.String(), "start-key-different", "start", true)
		if codeDiff != 42 {
			t.Fatalf("expected different key in resuming state to exit 42, got %d", codeDiff)
		}

		// 4b: Same key with container already running -> settles running facts and exits 0
		codeSame := executeSubprocessHelper(t, workRoot, depID.String(), "start-key-crash4", "start", true)
		if codeSame != 0 {
			t.Fatalf("expected same key to settle running facts and exit 0, got %d", codeSame)
		}

		finalSnapshot, found, err := provider.readDurableState(depID)
		if err != nil || !found || finalSnapshot.Phase != "active" || finalSnapshot.Deployment.Status != domain.DeploymentRuntimeReady {
			t.Fatalf("final state on disk was not converged to active: phase=%s status=%s err=%v", finalSnapshot.Phase, finalSnapshot.Deployment.Status, err)
		}
	})
}
