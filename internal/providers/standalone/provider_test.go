package standalone

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const testContainerID = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"

type fakeRunner struct {
	mu    sync.Mutex
	calls [][]string
	run   func([]string, io.Writer) error
}

func (r *fakeRunner) Run(_ context.Context, command string, args []string, stdout, _ io.Writer) error {
	if command != "docker" {
		return fmt.Errorf("unexpected command %q", command)
	}
	r.mu.Lock()
	r.calls = append(r.calls, append([]string(nil), args...))
	r.mu.Unlock()
	return r.run(args, stdout)
}

func (r *fakeRunner) callsFor(prefix ...string) [][]string {
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

type fakeImageStore struct {
	archive []byte
	result  contracts.StoreOCIResult
}

func (s fakeImageStore) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "fake-image-store", Version: "test", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilityImageResolve)}
}
func (s fakeImageStore) Resolve(context.Context, contracts.ImageResolveRequest) (contracts.ImageResolveResult, error) {
	return contracts.ImageResolveResult{}, errors.New("not implemented")
}
func (s fakeImageStore) Pull(context.Context, domain.ImageDigest, contracts.OperationContext) (contracts.Evidence, error) {
	return contracts.Evidence{}, errors.New("not implemented")
}
func (s fakeImageStore) Retain(context.Context, domain.ImageDigest, contracts.OperationContext) error {
	return errors.New("not implemented")
}
func (s fakeImageStore) Delete(context.Context, domain.ImageDigest, contracts.OperationContext) error {
	return errors.New("not implemented")
}
func (s fakeImageStore) StoreOCI(context.Context, contracts.StoreOCIRequest) (contracts.StoreOCIResult, error) {
	return contracts.StoreOCIResult{}, errors.New("not implemented")
}
func (s fakeImageStore) OpenOCI(_ context.Context, _ domain.ImageDigest, _ contracts.OperationContext) (io.ReadCloser, contracts.StoreOCIResult, error) {
	return io.NopCloser(strings.NewReader(string(s.archive))), s.result, nil
}

type fixedPorts struct {
	mu               sync.Mutex
	port             int
	allocated        int
	released         int
	reconciled       int
	releaseFailures  int
	fail             bool
	hostPortRequests []int
}

func (p *fixedPorts) Allocate(context.Context) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allocated++
	return p.port, nil
}
func (p *fixedPorts) Release(port int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if port == p.port {
		p.released++
	}
}
func (p *fixedPorts) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "fake-runtime-capacity", Version: "1", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilityCapacityCheck, contracts.CapabilityCapacityReserve)}
}
func (p *fixedPorts) Preflight(_ context.Context, request contracts.CapacityRequest) (contracts.CapacitySnapshot, contracts.Evidence, error) {
	return contracts.CapacitySnapshot{Scope: request.Scope, AvailableCPUMillis: 8000, AvailableMemoryBytes: 8 << 30, AvailableDiskBytes: 40 << 30}, contracts.Evidence{Redacted: true}, nil
}
func (p *fixedPorts) Reserve(ctx context.Context, request contracts.CapacityRequest) (contracts.CapacityLease, error) {
	p.mu.Lock()
	p.hostPortRequests = append(p.hostPortRequests, request.HostPorts)
	p.mu.Unlock()
	if p.fail {
		return contracts.CapacityLease{}, &contracts.ProviderError{Provider: "fake-runtime-capacity", Code: contracts.ErrCapacity, Message: "capacity unavailable", Retry: contracts.RetryBackoff, Retryable: true}
	}
	port := 0
	var err error
	if request.HostPorts > 0 {
		port, err = p.Allocate(ctx)
	}
	return contracts.CapacityLease{ID: "runtime-lease", Scope: request.Scope, Resources: request.Resources, HostPort: port, ExpiresAt: time.Now().Add(time.Minute)}, err
}
func (p *fixedPorts) Activate(context.Context, contracts.CapacityLease, contracts.OperationContext) error {
	return nil
}
func (p *fixedPorts) ReleaseCapacity(_ context.Context, lease contracts.CapacityLease, _ contracts.OperationContext) error {
	p.Release(lease.HostPort)
	return nil
}

func testImage() domain.ImageDigest {
	return domain.ImageDigest{Repository: "registry.open-card.test/apps/web", Digest: testDigest}
}

func testRequest(key string) contracts.DeployRequest {
	return contracts.DeployRequest{DeploymentID: domain.ID("dep_1234567890abcdef"), Spec: contracts.RuntimeSpec{
		ApplicationID: "app_1", EnvironmentID: "env_1", ReleaseID: "rel_1", ServiceName: "web", Image: testImage(), Port: 8080,
		Resources: contracts.ResourceLimits{CPUMillis: 500, MemoryBytes: 128 * 1024 * 1024, DiskBytes: 256 * 1024 * 1024, PIDs: 64},
	}, Operation: contracts.OperationContext{IdempotencyKey: key}}
}

func testProvider(t *testing.T, runner *fakeRunner, ports *fixedPorts) *Provider {
	return testProviderAt(t, t.TempDir(), runner, ports)
}

func testProviderAt(t *testing.T, workRoot string, runner *fakeRunner, ports *fixedPorts) *Provider {
	t.Helper()
	provider, err := New(Config{
		TaskPrefix: "opencard-m1", WorkRoot: workRoot, Runner: runner, Capacity: capacityAdapter{ports},
		ImageStore: fakeImageStore{archive: []byte("persistent OCI archive"), result: contracts.StoreOCIResult{Image: testImage(), StorageRef: "oci://artifact/immutable", SizeBytes: 22}},
		Clock:      func() time.Time { return time.Unix(100, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

type capacityAdapter struct{ ports *fixedPorts }

func (a capacityAdapter) Metadata(ctx context.Context) contracts.ProviderMetadata {
	return a.ports.Metadata(ctx)
}
func (a capacityAdapter) Preflight(ctx context.Context, r contracts.CapacityRequest) (contracts.CapacitySnapshot, contracts.Evidence, error) {
	return a.ports.Preflight(ctx, r)
}
func (a capacityAdapter) Reserve(ctx context.Context, r contracts.CapacityRequest) (contracts.CapacityLease, error) {
	return a.ports.Reserve(ctx, r)
}
func (a capacityAdapter) Activate(context.Context, contracts.CapacityLease, contracts.OperationContext) error {
	return nil
}
func (a capacityAdapter) Release(_ context.Context, l contracts.CapacityLease, _ contracts.OperationContext) error {
	a.ports.mu.Lock()
	if a.ports.releaseFailures > 0 {
		a.ports.releaseFailures--
		a.ports.mu.Unlock()
		return errors.New("temporary capacity release failure")
	}
	a.ports.mu.Unlock()
	a.ports.Release(l.HostPort)
	return nil
}
func (a capacityAdapter) ReconcileActive(context.Context, contracts.CapacityLease, contracts.OperationContext) error {
	a.ports.mu.Lock()
	a.ports.reconciled++
	a.ports.mu.Unlock()
	return nil
}

func dockerHappyRunner(t *testing.T) *fakeRunner {
	t.Helper()
	created := false
	var runArgs []string
	return &fakeRunner{run: func(args []string, stdout io.Writer) error {
		switch strings.Join(args[:min(2, len(args))], " ") {
		case "container inspect":
			if !created {
				return errors.New("container does not exist")
			}
			payload := ownedContainerInspect(testRequest("runtime-inspect"), testDigest)
			published := ""
			for index := 0; index+1 < len(runArgs); index++ {
				if runArgs[index] == "--publish" {
					published = runArgs[index+1]
				}
			}
			if published == "" {
				payload = strings.Replace(payload, `"PortBindings":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"39130"}]}`, `"PortBindings":{}`, 1)
			} else {
				parts := strings.Split(published, ":")
				payload = strings.Replace(payload, `"HostPort":"39130"`, `"HostPort":"`+parts[1]+`"`, 1)
			}
			_, _ = io.WriteString(stdout, payload)
		case "load --input":
			contents, err := os.ReadFile(args[2])
			if err != nil || string(contents) != "persistent OCI archive" {
				return fmt.Errorf("OCI archive was not safely staged: %v", err)
			}
		case "image inspect":
			_, _ = io.WriteString(stdout, testDigest+`|{"Volumes":null}`)
		case "network inspect":
			return errors.New("network does not exist")
		case "inspect --format":
			_, _ = io.WriteString(stdout, `{"Status":"running","Running":true,"Health":{"Status":"healthy"}}|3|134217728|134217728|100000|50000|64|`+testContainerID+`|{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"39124"}]}`)
		case "logs --timestamps":
			_, _ = io.WriteString(stdout, "2026-08-24T00:00:00Z hello\n2026-08-24T00:00:01Z ready\n")
		}
		if len(args) > 0 && args[0] == "run" {
			runArgs = append([]string(nil), args...)
			created = true
		}
		if len(args) > 0 && args[0] == "rm" {
			created = false
		}
		return nil
	}}
}

func TestDeployUsesImmutableArchiveAndConstrainedDockerArguments(t *testing.T) {
	runner := dockerHappyRunner(t)
	ports := &fixedPorts{port: 39123}
	provider := testProvider(t, runner, ports)
	request := testRequest("deploy-1")
	deployment, err := provider.Deploy(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if deployment.Status != domain.DeploymentRuntimeReady || deployment.ID.Empty() {
		t.Fatalf("unexpected deployment: %#v", deployment)
	}
	runs := runner.callsFor("run")
	if len(runs) != 1 {
		t.Fatalf("want one docker run, got %#v", runner.callsFor())
	}
	args := runs[0]
	assertContainsPairs(t, args,
		"--pull", "never", "--restart", "no", "--network", "opencard-m1-network",
		"--security-opt", "no-new-privileges=true", "--cap-drop", "ALL",
		"--cpu-period", "100000", "--cpu-quota", "50000",
		"--memory", "134217728", "--memory-swap", "134217728",
		"--pids-limit", "64",
		"--publish", "127.0.0.1:39123:8080/tcp",
	)
	if got := args[len(args)-1]; got != testDigest {
		t.Fatalf("runtime did not use immutable image reference: %q", got)
	}
	for _, forbidden := range []string{"--volume", "-v", "--mount", "--privileged", "--network=host", "--pid=host", "sh", "bash"} {
		for _, got := range args {
			if got == forbidden {
				t.Fatalf("unsafe Docker argument %q in %#v", forbidden, args)
			}
		}
	}
	if len(runner.callsFor("load")) != 1 || len(runner.callsFor("image", "inspect")) != 1 || len(runner.callsFor("network", "create")) != 1 {
		t.Fatalf("archive/image/network lifecycle is incomplete: %#v", runner.callsFor())
	}
	again, err := provider.Deploy(context.Background(), request)
	if err != nil || again.ID != deployment.ID || len(runner.callsFor("run")) != 1 {
		t.Fatalf("deploy was not idempotent: %#v %v %#v", again, err, runner.callsFor("run"))
	}
	conflict := testRequest("deploy-1")
	conflict.Spec.Port = 9090
	assertCode(t, deployError(provider, conflict), contracts.ErrConflict)
}

func TestLifecycleObservesLogsRestartsAndDestroysWithoutDocker(t *testing.T) {
	runner := dockerHappyRunner(t)
	ports := &fixedPorts{port: 39124}
	provider := testProvider(t, runner, ports)
	deployment, err := provider.Deploy(context.Background(), testRequest("lifecycle-deploy"))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := provider.Observe(context.Background(), contracts.ObserveRequest{DeploymentID: deployment.ID, Operation: contracts.OperationContext{IdempotencyKey: "observe"}})
	if err != nil || !observation.Healthy || observation.Status != "running" || observation.RestartCount != 3 || !observation.Evidence.Redacted {
		t.Fatalf("unexpected observation: %#v %v", observation, err)
	}
	logs, err := provider.Logs(context.Background(), contracts.LogsRequest{DeploymentID: deployment.ID, ServiceName: "web", Tail: 2, Operation: contracts.OperationContext{IdempotencyKey: "logs"}})
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for line := range logs {
		lines = append(lines, line)
	}
	if len(lines) != 2 || !strings.Contains(lines[1], "ready") {
		t.Fatalf("unexpected logs: %#v", lines)
	}
	restart := contracts.RestartRequest{DeploymentID: deployment.ID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "restart"}}
	if err := provider.Restart(context.Background(), restart); err != nil {
		t.Fatal(err)
	}
	if err := provider.Restart(context.Background(), restart); err != nil {
		t.Fatal(err)
	}
	if len(runner.callsFor("restart")) != 1 {
		t.Fatalf("restart was not idempotent")
	}
	destroy := contracts.DestroyRequest{DeploymentID: deployment.ID, Operation: contracts.OperationContext{IdempotencyKey: "destroy"}}
	if err := provider.Destroy(context.Background(), destroy); err != nil {
		t.Fatal(err)
	}
	if err := provider.Destroy(context.Background(), destroy); err != nil {
		t.Fatal(err)
	}
	if len(runner.callsFor("rm")) != 1 || ports.released != 1 {
		t.Fatalf("destroy did not clean up managed container/port")
	}
	stopped, err := provider.Observe(context.Background(), contracts.ObserveRequest{DeploymentID: deployment.ID, Operation: contracts.OperationContext{IdempotencyKey: "observe-stopped"}})
	if err != nil || stopped.Healthy || stopped.Status != "stopped" {
		t.Fatalf("destroy observation: %#v %v", stopped, err)
	}
	assertCode(t, provider.Scale(context.Background(), contracts.ScaleRequest{DeploymentID: deployment.ID, Replicas: 2, Operation: contracts.OperationContext{IdempotencyKey: "scale"}}), contracts.ErrUnsupportedCapability)
	_, err = provider.Rollback(context.Background(), contracts.RollbackRequest{DeploymentID: deployment.ID, ReleaseID: "rel_other", Operation: contracts.OperationContext{IdempotencyKey: "rollback"}})
	assertCode(t, err, contracts.ErrUnsupportedCapability)
}

func TestDeployRejectsEscapesAndDigestVerificationFailuresBeforeRun(t *testing.T) {
	runner := dockerHappyRunner(t)
	provider := testProvider(t, runner, &fixedPorts{port: 39125})
	bad := testRequest("secrets")
	bad.Spec.Secrets = []domain.SecretReference{{ID: "secret_1"}}
	assertCode(t, deployError(provider, bad), contracts.ErrForbidden)
	bad = testRequest("resources")
	bad.Spec.Resources.MemoryBytes = 0
	assertCode(t, deployError(provider, bad), contracts.ErrValidation)
	bad = testRequest("port")
	bad.Spec.Port = 70000
	assertCode(t, deployError(provider, bad), contracts.ErrValidation)
	if len(runner.callsFor()) != 0 {
		t.Fatalf("invalid request reached Docker: %#v", runner.callsFor())
	}

	wrongDigestRunner := dockerHappyRunner(t)
	wrongDigestRunner.run = func(args []string, stdout io.Writer) error {
		if len(args) > 1 && args[0] == "container" && args[1] == "inspect" {
			return errors.New("container does not exist")
		}
		if len(args) > 1 && args[0] == "image" && args[1] == "inspect" {
			_, _ = io.WriteString(stdout, `sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|{"Volumes":null}`)
		}
		return nil
	}
	provider = testProvider(t, wrongDigestRunner, &fixedPorts{port: 39126})
	assertCode(t, deployError(provider, testRequest("wrong-digest")), contracts.ErrConflict)
	if len(wrongDigestRunner.callsFor("run")) != 0 {
		t.Fatalf("unverified image reached docker run")
	}

	volumeRunner := dockerHappyRunner(t)
	volumeRunner.run = func(args []string, stdout io.Writer) error {
		if len(args) > 1 && args[0] == "container" && args[1] == "inspect" {
			return errors.New("container does not exist")
		}
		if len(args) > 1 && args[0] == "image" && args[1] == "inspect" {
			_, _ = io.WriteString(stdout, testDigest+`|{"Volumes":{"/data":{}}}`)
		}
		return nil
	}
	provider = testProvider(t, volumeRunner, &fixedPorts{port: 39127})
	assertCode(t, deployError(provider, testRequest("image-volume")), contracts.ErrForbidden)
	if len(volumeRunner.callsFor("run")) != 0 {
		t.Fatalf("image-declared volume reached docker run")
	}

	unownedNetworkRunner := dockerHappyRunner(t)
	unownedNetworkRunner.run = func(args []string, stdout io.Writer) error {
		switch strings.Join(args[:min(2, len(args))], " ") {
		case "container inspect":
			return errors.New("container does not exist")
		case "image inspect":
			_, _ = io.WriteString(stdout, testDigest+`|{"Volumes":null}`)
		case "network inspect":
			_, _ = io.WriteString(stdout, "false|someone-else")
		}
		return nil
	}
	provider = testProvider(t, unownedNetworkRunner, &fixedPorts{port: 39128})
	assertCode(t, deployError(provider, testRequest("unowned-network")), contracts.ErrConflict)
	if len(unownedNetworkRunner.callsFor("run")) != 0 {
		t.Fatalf("unmanaged network reached docker run")
	}
}

func TestRuntimeCapacityFailureHasNoMutatingDockerSideEffects(t *testing.T) {
	runner := dockerHappyRunner(t)
	ports := &fixedPorts{port: 39129, fail: true}
	provider := testProvider(t, runner, ports)
	assertCode(t, deployError(provider, testRequest("capacity-fail")), contracts.ErrCapacity)
	for _, mutation := range [][]string{{"load"}, {"network", "create"}, {"run"}} {
		if calls := runner.callsFor(mutation...); len(calls) != 0 {
			t.Fatalf("capacity rejection executed Docker mutation %v: %#v", mutation, calls)
		}
	}
	if ports.allocated != 0 {
		t.Fatalf("failed capacity preflight allocated port: %d", ports.allocated)
	}
}

func TestDeployWithoutContainerPortDoesNotReserveHostPort(t *testing.T) {
	runner := dockerHappyRunner(t)
	ports := &fixedPorts{port: 39131}
	provider := testProvider(t, runner, ports)
	request := testRequest("no-container-port")
	request.Spec.Port = 0
	if _, err := provider.Deploy(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	ports.mu.Lock()
	defer ports.mu.Unlock()
	if len(ports.hostPortRequests) != 1 || ports.hostPortRequests[0] != 0 || ports.allocated != 0 {
		t.Fatalf("portless deployment reserved a host port: requests=%v allocated=%d", ports.hostPortRequests, ports.allocated)
	}
	for _, arg := range runner.callsFor("run")[0] {
		if arg == "--publish" {
			t.Fatalf("portless deployment exposed a Docker port: %#v", runner.callsFor("run")[0])
		}
	}
}

func TestFailedDeployCanRetryWithSameDeterministicOperation(t *testing.T) {
	runner := dockerHappyRunner(t)
	happy := runner.run
	runAttempts := 0
	runner.run = func(args []string, stdout io.Writer) error {
		if len(args) > 0 && args[0] == "run" {
			runAttempts++
			if runAttempts == 1 {
				return errors.New("temporary Docker failure")
			}
		}
		return happy(args, stdout)
	}
	ports := &fixedPorts{port: 39132}
	provider := testProvider(t, runner, ports)
	request := testRequest("retry-after-failure")
	if _, err := provider.Deploy(context.Background(), request); err == nil {
		t.Fatal("first Docker failure became a deployment success")
	}
	if _, err := provider.Deploy(context.Background(), request); err != nil {
		t.Fatalf("same deterministic deploy did not retry honestly: %v", err)
	}
	if runAttempts != 2 {
		t.Fatalf("retry did not issue a fresh Docker run: attempts=%d", runAttempts)
	}
	ports.mu.Lock()
	reservations := len(ports.hostPortRequests)
	ports.mu.Unlock()
	if reservations != 2 {
		t.Fatalf("same-key retry reused a released capacity attempt: reservations=%d", reservations)
	}
}

func TestConcurrentSameDeployUsesOneDockerRun(t *testing.T) {
	runner := dockerHappyRunner(t)
	provider := testProvider(t, runner, &fixedPorts{port: 39127})
	request := testRequest("concurrent")
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	ids := make(chan domain.ID, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			deployed, err := provider.Deploy(context.Background(), request)
			if err == nil {
				ids <- deployed.ID
			}
			errs <- err
			wg.Done()
		}()
	}
	wg.Wait()
	close(errs)
	close(ids)
	var id domain.ID
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for got := range ids {
		if id != "" && got != id {
			t.Fatalf("idempotent deployment mismatch: %q %q", id, got)
		}
		id = got
	}
	if len(runner.callsFor("run")) != 1 {
		t.Fatalf("concurrent deploy created multiple containers: %#v", runner.callsFor("run"))
	}
}

func TestProviderRestartRejectsPreLedgerContainerAndExactDrift(t *testing.T) {
	request := testRequest("recover-deploy")
	runner := &fakeRunner{run: func(args []string, stdout io.Writer) error {
		switch strings.Join(args[:min(2, len(args))], " ") {
		case "container inspect":
			_, _ = io.WriteString(stdout, ownedContainerInspect(request, testDigest))
		}
		return nil
	}}
	provider := testProvider(t, runner, &fixedPorts{port: 39130})
	assertCode(t, deployError(provider, request), contracts.ErrConflict)
	if len(runner.callsFor("run")) != 0 || len(runner.callsFor("load")) != 0 {
		t.Fatalf("pre-ledger container reached Docker mutation: calls=%#v", runner.callsFor())
	}

	for _, testCase := range []struct {
		name   string
		mutate func(string) string
	}{
		{"digest", func(value string) string {
			return strings.Replace(value, testDigest, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1)
		}},
		{"label", func(value string) string {
			return strings.Replace(value, `"open-card.service":"web"`, `"open-card.service":"other"`, 1)
		}},
		{"cpu", func(value string) string { return strings.Replace(value, `"CpuQuota":50000`, `"CpuQuota":60000`, 1) }},
		{"memory", func(value string) string {
			return strings.Replace(value, `"Memory":134217728`, `"Memory":134217729`, 1)
		}},
		{"pid", func(value string) string { return strings.Replace(value, `"PidsLimit":64`, `"PidsLimit":65`, 1) }},
		{"cap-drop", func(value string) string {
			return strings.Replace(value, `"CapDrop":["ALL"]`, `"CapDrop":["ALL","NET_RAW"]`, 1)
		}},
		{"restart-policy", func(value string) string {
			return strings.Replace(value, `"RestartPolicy":{"Name":"no"}`, `"RestartPolicy":{"Name":"always"}`, 1)
		}},
		{"loopback-port", func(value string) string {
			return strings.Replace(value, `"HostIp":"127.0.0.1"`, `"HostIp":"0.0.0.0"`, 1)
		}},
		{"extra-port", func(value string) string {
			return strings.Replace(value, `"PortBindings":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"39130"}]}`, `"PortBindings":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"39130"}],"9090/tcp":[{"HostIp":"127.0.0.1","HostPort":"39131"}]}`, 1)
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			mismatch := &fakeRunner{run: func(args []string, stdout io.Writer) error {
				if len(args) > 1 && args[0] == "container" && args[1] == "inspect" {
					_, _ = io.WriteString(stdout, testCase.mutate(ownedContainerInspect(request, testDigest)))
				}
				return nil
			}}
			provider := testProvider(t, mismatch, &fixedPorts{port: 39130})
			assertCode(t, deployError(provider, request), contracts.ErrConflict)
			for _, mutation := range [][]string{{"load"}, {"network", "create"}, {"run"}} {
				if calls := mismatch.callsFor(mutation...); len(calls) != 0 {
					t.Fatalf("mismatched owned container reached Docker mutation %v: %#v", mutation, calls)
				}
			}
		})
	}
	portless := testRequest("recover-portless")
	portless.Spec.Port = 0
	extraBinding := &fakeRunner{run: func(args []string, stdout io.Writer) error {
		if len(args) > 1 && args[0] == "container" && args[1] == "inspect" {
			_, _ = io.WriteString(stdout, ownedContainerInspect(portless, testDigest))
		}
		return nil
	}}
	provider = testProvider(t, extraBinding, &fixedPorts{port: 39130})
	assertCode(t, deployError(provider, portless), contracts.ErrConflict)
	for _, mutation := range [][]string{{"load"}, {"network", "create"}, {"run"}} {
		if calls := extraBinding.callsFor(mutation...); len(calls) != 0 {
			t.Fatalf("portless durable state reached Docker mutation %v: %#v", mutation, calls)
		}
	}
}

func TestObserveRejectsIndependentLimitReadbackMismatch(t *testing.T) {
	runner := dockerHappyRunner(t)
	happy := runner.run
	containerInspects := 0
	runner.run = func(args []string, stdout io.Writer) error {
		if len(args) > 1 && args[0] == "container" && args[1] == "inspect" {
			containerInspects++
			if containerInspects <= 2 {
				return happy(args, stdout)
			}
			_, _ = io.WriteString(stdout, strings.Replace(strings.Replace(ownedContainerInspect(testRequest("readback-mismatch"), testDigest), `"HostPort":"39130"`, `"HostPort":"39124"`, 1), `"Memory":134217728`, `"Memory":1`, 1))
			return nil
		}
		return happy(args, stdout)
	}
	provider := testProvider(t, runner, &fixedPorts{port: 39124})
	deployment, err := provider.Deploy(context.Background(), testRequest("readback-mismatch"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.Observe(context.Background(), contracts.ObserveRequest{DeploymentID: deployment.ID, Operation: contracts.OperationContext{IdempotencyKey: "readback-mismatch-observe"}})
	assertCode(t, err, contracts.ErrConflict)
}

func ownedContainerInspect(request contracts.DeployRequest, image string) string {
	return `{"Id":"` + testContainerID + `","RestartCount":3,"Image":"` + image + `","Config":{"Labels":{"open-card.managed":"true","open-card.task-prefix":"opencard-m1","open-card.deployment-id":"` + request.DeploymentID.String() + `","open-card.application-id":"` + request.Spec.ApplicationID.String() + `","open-card.environment-id":"` + request.Spec.EnvironmentID.String() + `","open-card.release-id":"` + request.Spec.ReleaseID.String() + `","open-card.service":"` + request.Spec.ServiceName + `","open-card.image-repository":"` + request.Spec.Image.Repository + `","open-card.image-digest":"` + request.Spec.Image.Digest + `"},"Volumes":null},"State":{"Running":true},"HostConfig":{"NetworkMode":"opencard-m1-network","Privileged":false,"Binds":null,"CapAdd":null,"CapDrop":["ALL"],"Memory":134217728,"MemorySwap":134217728,"CpuPeriod":100000,"CpuQuota":50000,"PidsLimit":64,"SecurityOpt":["no-new-privileges=true"],"RestartPolicy":{"Name":"no"},"PortBindings":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"39130"}]}}}`
}

func assertContainsPairs(t *testing.T, args []string, pairs ...string) {
	t.Helper()
	for i := 0; i < len(pairs); i += 2 {
		found := false
		for j := 0; j+1 < len(args); j++ {
			if args[j] == pairs[i] && args[j+1] == pairs[i+1] {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing %q %q in %#v", pairs[i], pairs[i+1], args)
		}
	}
}

func deployError(provider *Provider, request contracts.DeployRequest) error {
	_, err := provider.Deploy(context.Background(), request)
	return err
}
func assertCode(t *testing.T, err error, code contracts.ErrorCode) {
	t.Helper()
	var providerErr *contracts.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Code != code {
		t.Fatalf("want %s, got %#v", code, err)
	}
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
