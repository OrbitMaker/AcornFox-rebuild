package standalonegroup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const groupDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type fakeDocker struct {
	mu         sync.Mutex
	calls      [][]string
	networks   map[string]bool
	images     map[string]bool
	containers map[string]fakeContainer
	failRun    map[string]error
	logs       map[string]string
	stderrLogs map[string]string
}

type fakeContainer struct {
	image         string
	labels        map[string]string
	network       string
	networks      map[string]bool
	memory        int64
	memorySwap    int64
	cpuPeriod     int64
	cpuQuota      int64
	pids          int64
	running       bool
	exitCode      int
	health        string
	hostPort      int
	containerPort int
}

func (r *fakeDocker) Run(_ context.Context, command string, args []string, stdout, stderr io.Writer) error {
	if command != "docker" {
		return fmt.Errorf("unexpected command %q", command)
	}
	r.mu.Lock()
	r.calls = append(r.calls, append([]string(nil), args...))
	r.mu.Unlock()
	if len(args) >= 2 && args[0] == "network" && args[1] == "inspect" {
		name := args[len(args)-1]
		r.mu.Lock()
		present := r.networks[name]
		r.mu.Unlock()
		if !present {
			return errors.New("network not found")
		}
		_, _ = io.WriteString(stdout, "true|opencard-m2-test")
		return nil
	}
	if len(args) >= 2 && args[0] == "network" && args[1] == "create" {
		name := args[len(args)-1]
		r.mu.Lock()
		if r.networks == nil {
			r.networks = map[string]bool{}
		}
		r.networks[name] = true
		r.mu.Unlock()
		_, _ = io.WriteString(stdout, "opencard-m2-test-group-network")
		return nil
	}
	if len(args) >= 2 && args[0] == "network" && args[1] == "rm" {
		name := args[len(args)-1]
		r.mu.Lock()
		delete(r.networks, name)
		r.mu.Unlock()
		return nil
	}
	if len(args) >= 2 && args[0] == "network" && args[1] == "connect" {
		network := args[len(args)-2]
		containerName := args[len(args)-1]
		r.mu.Lock()
		if container, ok := r.containers[containerName]; ok {
			if container.networks == nil {
				container.networks = map[string]bool{}
			}
			container.networks[network] = true
			r.containers[containerName] = container
		}
		r.mu.Unlock()
		return nil
	}
	if len(args) >= 3 && args[0] == "network" && args[1] == "disconnect" {
		network := args[len(args)-2]
		containerName := args[len(args)-1]
		r.mu.Lock()
		if container, ok := r.containers[containerName]; ok {
			delete(container.networks, network)
			r.containers[containerName] = container
		}
		r.mu.Unlock()
		return nil
	}
	if len(args) >= 2 && args[0] == "image" && args[1] == "inspect" {
		image := args[len(args)-1]
		digest := image
		if at := strings.LastIndex(image, "@"); at >= 0 {
			digest = image[at+1:]
		}
		r.mu.Lock()
		present := r.images[digest]
		r.mu.Unlock()
		if !present {
			return errors.New("image not found")
		}
		_, _ = io.WriteString(stdout, digest+`|{"Volumes":null}|["`+image+`"]`)
		return nil
	}
	if len(args) >= 2 && args[0] == "load" && args[1] == "--input" {
		r.mu.Lock()
		if r.images == nil {
			r.images = map[string]bool{}
		}
		r.images[groupDigest] = true
		r.mu.Unlock()
		return nil
	}
	if len(args) >= 2 && args[0] == "container" && args[1] == "inspect" {
		name := args[len(args)-1]
		r.mu.Lock()
		container, ok := r.containers[name]
		r.mu.Unlock()
		if !ok {
			return errors.New("container not found")
		}
		networks := map[string]any{}
		for network := range container.networks {
			networks[network] = map[string]any{}
		}
		value := map[string]any{
			"Image":           container.image,
			"Config":          map[string]any{"Image": container.image, "Labels": container.labels},
			"State":           map[string]any{"Status": statusFor(container.running), "Running": container.running, "ExitCode": container.exitCode, "Health": map[string]any{"Status": container.health}},
			"HostConfig":      map[string]any{"NetworkMode": container.network, "Memory": container.memory, "MemorySwap": container.memorySwap, "CpuPeriod": container.cpuPeriod, "CpuQuota": container.cpuQuota, "PidsLimit": container.pids},
			"NetworkSettings": map[string]any{"Ports": map[string]any{fmt.Sprintf("%d/tcp", container.containerPort): []map[string]string{{"HostIp": "127.0.0.1", "HostPort": fmt.Sprint(container.hostPort)}}}, "Networks": networks},
		}
		encoded, _ := json.Marshal(value)
		_, _ = stdout.Write(encoded)
		return nil
	}
	if len(args) >= 1 && args[0] == "run" {
		name := valueAfter(args, "--name")
		if failure := r.failFor(name); failure != nil {
			return failure
		}
		labels := map[string]string{}
		for i := 0; i+1 < len(args); i++ {
			if args[i] != "--label" {
				continue
			}
			parts := strings.SplitN(args[i+1], "=", 2)
			if len(parts) == 2 {
				labels[parts[0]] = parts[1]
			}
		}
		network := valueAfter(args, "--network")
		container := fakeContainer{image: lastImage(args), labels: labels, network: network, networks: map[string]bool{network: true}, memory: parseInt(valueAfter(args, "--memory")), memorySwap: parseInt(valueAfter(args, "--memory-swap")), cpuPeriod: parseInt(valueAfter(args, "--cpu-period")), cpuQuota: parseInt(valueAfter(args, "--cpu-quota")), pids: parseInt(valueAfter(args, "--pids-limit")), running: true, health: "healthy"}
		if publish := valueAfter(args, "--publish"); publish != "" {
			parts := strings.Split(publish, ":")
			if len(parts) == 3 {
				container.hostPort = int(parseInt(parts[1]))
				portProtocol := strings.Split(parts[2], "/")
				container.containerPort = int(parseInt(portProtocol[0]))
			}
		}
		r.mu.Lock()
		r.containers[name] = container
		r.mu.Unlock()
		_, _ = io.WriteString(stdout, name+"\n")
		return nil
	}
	if len(args) >= 1 && args[0] == "stop" {
		name := args[len(args)-1]
		r.mu.Lock()
		if container, ok := r.containers[name]; ok {
			container.running = false
			container.health = "none"
			r.containers[name] = container
		}
		r.mu.Unlock()
		return nil
	}
	if len(args) >= 1 && args[0] == "restart" {
		name := args[len(args)-1]
		r.mu.Lock()
		container, ok := r.containers[name]
		if ok {
			container.running = true
			container.health = "healthy"
			r.containers[name] = container
		}
		r.mu.Unlock()
		if !ok {
			return errors.New("container not found")
		}
		return nil
	}
	if len(args) >= 1 && args[0] == "rm" {
		name := args[len(args)-1]
		r.mu.Lock()
		delete(r.containers, name)
		r.mu.Unlock()
		return nil
	}
	if len(args) >= 1 && args[0] == "logs" {
		name := args[len(args)-1]
		r.mu.Lock()
		value := r.logs[name]
		stderrValue := r.stderrLogs[name]
		r.mu.Unlock()
		_, _ = io.WriteString(stdout, value)
		_, _ = io.WriteString(stderr, stderrValue)
		return nil
	}
	if len(args) >= 3 && args[0] == "exec" {
		if strings.Contains(strings.Join(args[2:], " "), "definitely-missing") {
			return errors.New("exec health command not found")
		}
		return nil
	}
	return fmt.Errorf("unexpected docker args %#v", args)
}

func (r *fakeDocker) failFor(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if failure := r.failRun[name]; failure != nil {
		return failure
	}
	return nil
}

func (r *fakeDocker) callsSnapshot() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([][]string, len(r.calls))
	for i := range r.calls {
		result[i] = append([]string(nil), r.calls[i]...)
	}
	return result
}

func (r *fakeDocker) hasContainer(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.containers[name]
	return ok
}

func statusFor(running bool) string {
	if running {
		return "running"
	}
	return "exited"
}

func valueAfter(args []string, key string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key {
			return args[i+1]
		}
	}
	return ""
}

func parseInt(value string) int64 {
	result, _ := strconv.ParseInt(value, 10, 64)
	return result
}

func lastImage(args []string) string {
	for i := len(args) - 1; i >= 0; i-- {
		if strings.HasPrefix(args[i], "sha256:") || strings.Contains(args[i], "@sha256:") {
			return args[i]
		}
	}
	return ""
}

type fakeLoader struct{}

func (fakeLoader) OpenOCI(_ context.Context, image domain.ImageDigest, _ contracts.OperationContext) (io.ReadCloser, contracts.StoreOCIResult, error) {
	stored := image
	stored.ResolvedTag = ""
	return io.NopCloser(bytes.NewReader([]byte("OCI-" + image.Digest))), contracts.StoreOCIResult{Image: stored, StorageRef: "oci://fake/" + image.Digest, SizeBytes: 1}, nil
}

type fakeVolumes struct {
	mu        sync.Mutex
	created   map[string]contracts.VolumeSpec
	destroyed int
}

func (v *fakeVolumes) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "fake-volumes", Version: "1", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilityVolumeManage)}
}
func (v *fakeVolumes) Create(_ context.Context, request contracts.VolumeRequest) (contracts.VolumeSpec, contracts.Evidence, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	created := request.Volume
	created.Name = "opencard-m2-test-volume-" + request.Volume.Name
	if v.created == nil {
		v.created = map[string]contracts.VolumeSpec{}
	}
	v.created[request.Volume.Name] = created
	return created, contracts.Evidence{Redacted: true}, nil
}
func (v *fakeVolumes) Attach(context.Context, contracts.VolumeRequest) error { return nil }
func (v *fakeVolumes) Detach(context.Context, contracts.VolumeRequest) error { return nil }
func (v *fakeVolumes) Retain(context.Context, contracts.VolumeRequest) error { return nil }
func (v *fakeVolumes) Destroy(_ context.Context, request contracts.VolumeRequest) error {
	if request.ConfirmationToken != "confirm" {
		return errors.New("wrong confirmation")
	}
	v.mu.Lock()
	v.destroyed++
	v.mu.Unlock()
	return nil
}

func groupCapacity() *contracts.FakeCapacityProvider {
	return contracts.NewFakeCapacityProvider(true)
}

func groupConfig(t *testing.T, docker *fakeDocker, volumes *fakeVolumes) Config {
	t.Helper()
	capacity := groupCapacity()
	provider, err := New(Config{TaskPrefix: "opencard-m2-test", WorkRoot: t.TempDir(), ImageStore: fakeLoader{}, Capacity: capacity, Volumes: volumes, Runner: docker, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return provider.config
}

func newGroupProvider(t *testing.T, docker *fakeDocker, volumes *fakeVolumes) *Provider {
	t.Helper()
	provider, err := New(groupConfig(t, docker, volumes))
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func groupSpec(release domain.ID, rollout contracts.RuntimeRolloutPolicy) contracts.ServiceGroupRuntimeSpec {
	db := contracts.ServiceRuntimeSpec{Name: "db", Role: domain.RoleStateful, Required: true, Image: domain.ImageDigest{Repository: "registry.example.test/db", Digest: groupDigest}, Resources: contracts.ResourceLimits{CPUMillis: 250, MemoryBytes: 64 << 20, DiskBytes: 128 << 20, PIDs: 64}, Healthcheck: &domain.HealthcheckSpec{Test: []string{"CMD", "true"}}}
	web := contracts.ServiceRuntimeSpec{Name: "web", Role: domain.RoleIngress, Required: true, Image: domain.ImageDigest{Repository: "registry.example.test/web", Digest: groupDigest}, Resources: contracts.ResourceLimits{CPUMillis: 250, MemoryBytes: 64 << 20, DiskBytes: 128 << 20, PIDs: 64}, ContainerPorts: []int{8080}, Dependencies: []domain.ServiceDependency{{Service: "db", Condition: domain.DependsHealthy}}, Volumes: []domain.VolumeMount{{Name: "data", MountPath: "/data"}}, Environment: []contracts.RuntimeEnvironmentVariable{{Name: "APP_MODE", Kind: contracts.RuntimeEnvironmentLiteral, Value: "test"}}}
	return contracts.ServiceGroupRuntimeSpec{SchemaVersion: contracts.ServiceGroupRuntimeSchema, ApplicationID: "app_group", EnvironmentID: "env_group", ReleaseID: release, ServiceGroupID: "group_group", ConfigDigest: "sha256:" + strings.Repeat("c", 64), EntryService: "web", Services: []contracts.ServiceRuntimeSpec{web, db}, VolumeClaims: []contracts.RuntimeVolumeClaim{{ID: "volume_data", Name: "data", SizeBytes: 1 << 20, Retain: true}}, Rollout: rollout}
}

func deployRequest(key string, id domain.ID, spec contracts.ServiceGroupRuntimeSpec) contracts.DeployGroupRequest {
	return contracts.DeployGroupRequest{DeploymentID: id, Spec: spec, Operation: contracts.OperationContext{IdempotencyKey: key}}
}

func TestDeployGroupStartsDAGWithPrivateNetworkAndOnlyEntryPort(t *testing.T) {
	docker := &fakeDocker{containers: map[string]fakeContainer{}, failRun: map[string]error{}, logs: map[string]string{}}
	provider := newGroupProvider(t, docker, &fakeVolumes{})
	spec := groupSpec("rel_group_1", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial})
	deployment, err := provider.DeployGroup(context.Background(), deployRequest("deploy-1", "dep_group_1", spec))
	if err != nil {
		t.Fatal(err)
	}
	if deployment.Status != domain.DeploymentRuntimeReady {
		t.Fatalf("unexpected deployment status: %s", deployment.Status)
	}
	observation, err := provider.ObserveGroup(context.Background(), contracts.ObserveGroupRequest{DeploymentID: deployment.ID, Operation: contracts.OperationContext{IdempotencyKey: "observe-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if observation.Status != domain.DeploymentRuntimeReady.String() || len(observation.Services) != 2 {
		t.Fatalf("unexpected group observation: %#v", observation)
	}
	webContainer := provider.containerName(deployment.ID, "web")
	docker.mu.Lock()
	if docker.stderrLogs == nil {
		docker.stderrLogs = map[string]string{}
	}
	docker.stderrLogs[webContainer] = "level=info event=http_request status=200\n"
	docker.mu.Unlock()
	logs, err := provider.Logs(context.Background(), contracts.LogsRequest{DeploymentID: deployment.ID, ServiceName: "web", Tail: 64, Operation: contracts.OperationContext{IdempotencyKey: "logs-stderr"}})
	if err != nil {
		t.Fatal(err)
	}
	if line, ok := <-logs; !ok || !strings.Contains(line, "event=http_request") {
		t.Fatalf("Docker stderr runtime log was lost: %q ok=%v", line, ok)
	}
	var runs [][]string
	for _, call := range docker.callsSnapshot() {
		if len(call) > 0 && call[0] == "run" {
			runs = append(runs, call)
		}
	}
	if len(runs) != 2 || !strings.Contains(runs[0][len(runs[0])-1], groupDigest) || !strings.Contains(runs[1][len(runs[1])-1], groupDigest) {
		t.Fatalf("expected two digest-only runs: %#v", runs)
	}
	if !strings.Contains(strings.Join(runs[0], " "), "db") || !strings.Contains(strings.Join(runs[1], " "), "web") {
		t.Fatalf("dependency order was not db then web: %#v", runs)
	}
	if containsFlag(runs[0], "--health-cmd") || countCalls(docker.callsSnapshot(), "exec") == 0 {
		t.Fatalf("exec-form healthcheck was not executed directly without a container shell: %#v", docker.callsSnapshot())
	}
	webRun := runs[1]
	if !containsPair(webRun, "--publish", "127.0.0.1:39001:8080/tcp") || containsFlag(runs[0], "--publish") || !strings.HasPrefix(valueAfter(webRun, "--network"), "opencard-m2-test-network-") || !containsPair(webRun, "--pids-limit", "64") {
		t.Fatalf("network/port/resource constraints were not exact: %#v", webRun)
	}
	forbidden := []string{"--privileged", "--device", "/var/run/docker.sock", "--pid", "--ipc", "--uts", "--network host"}
	for _, call := range runs {
		for _, value := range forbidden {
			if value == "--network host" {
				if strings.Contains(strings.Join(call, " "), value) {
					t.Fatalf("forbidden runtime argument %q in %#v", value, call)
				}
				continue
			}
			if containsFlag(call, value) || containsPair(call, "--mount", "source=/var/run/docker.sock,target=/var/run/docker.sock,type=volume") {
				t.Fatalf("forbidden runtime argument %q in %#v", value, call)
			}
		}
	}
	if _, err := provider.DeployGroup(context.Background(), deployRequest("deploy-1-replay", deployment.ID, spec)); err != nil {
		t.Fatal(err)
	}
	if countCalls(docker.callsSnapshot(), "run") != 2 {
		t.Fatalf("replaying an immutable deployment created a new container: %#v", docker.callsSnapshot())
	}
}

func TestExitedLongRunningServiceIsNotCompleted(t *testing.T) {
	facts := inspectFacts{State: struct {
		Status   string `json:"Status"`
		Running  bool   `json:"Running"`
		ExitCode int    `json:"ExitCode"`
		Health   *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	}{Status: "exited", ExitCode: 0}}
	if facts.completed(contracts.ServiceRuntimeSpec{Name: "worker", Role: domain.RoleWorker}) {
		t.Fatal("stopped long-running worker was treated as a completed one-shot service")
	}
	if !facts.completed(contracts.ServiceRuntimeSpec{Name: "migration", Role: domain.RoleOneShot}) {
		t.Fatal("successful exited one-shot service was not treated as completed")
	}
}

func TestRestartGroupServiceRestartsOnlyOwnedServiceAndReplaysIdempotently(t *testing.T) {
	docker := &fakeDocker{containers: map[string]fakeContainer{}, failRun: map[string]error{}, logs: map[string]string{}}
	provider := newGroupProvider(t, docker, &fakeVolumes{})
	spec := groupSpec("rel_group_restart", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial})
	deployment, err := provider.DeployGroup(context.Background(), deployRequest("restart-group-deploy", "dep_group_restart", spec))
	if err != nil {
		t.Fatal(err)
	}
	request := contracts.RestartGroupServiceRequest{DeploymentID: deployment.ID, ServiceGroupID: spec.ServiceGroupID, ReleaseID: spec.ReleaseID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "restart-group-web"}}
	if err := provider.RestartGroupService(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := provider.RestartGroupService(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	restarts := 0
	for _, call := range docker.callsSnapshot() {
		if len(call) > 0 && call[0] == "restart" {
			restarts++
			if call[len(call)-1] != provider.containerName(deployment.ID, "web") {
				t.Fatalf("restart escaped requested service: %#v", call)
			}
		}
	}
	if restarts != 1 {
		t.Fatalf("restart replay repeated or omitted side effect: %#v", docker.callsSnapshot())
	}
	bad := request
	bad.ServiceName = "missing"
	bad.Operation.IdempotencyKey = "restart-group-missing"
	if err := provider.RestartGroupService(context.Background(), bad); err == nil {
		t.Fatal("unknown service restart was accepted")
	}
}

func TestDeployGroupRequiredFailureCleansContainersAndOptionalFailureDoesNotBlock(t *testing.T) {
	docker := &fakeDocker{containers: map[string]fakeContainer{}, failRun: map[string]error{}, logs: map[string]string{}}
	provider := newGroupProvider(t, docker, &fakeVolumes{})
	spec := groupSpec("rel_group_fail", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial})
	docker.failRun[provider.containerName("dep_required_fail", "web")] = errors.New("run failed")
	if _, err := provider.DeployGroup(context.Background(), deployRequest("required-fail", "dep_required_fail", spec)); err == nil {
		t.Fatal("required service failure was accepted")
	}
	runsAfterFailure := countCalls(docker.callsSnapshot(), "run")
	if _, err := provider.DeployGroup(context.Background(), deployRequest("required-fail", "dep_required_fail", spec)); err == nil {
		t.Fatal("failed idempotent deployment replay was accepted")
	}
	if countCalls(docker.callsSnapshot(), "run") != runsAfterFailure {
		t.Fatal("failed idempotent deployment replay repeated Docker effects")
	}
	if docker.hasContainer(provider.containerName("dep_required_fail", "db")) || docker.hasContainer(provider.containerName("dep_required_fail", "web")) {
		t.Fatal("required failure left a task container behind")
	}

	docker.failRun = map[string]error{}
	optional := groupSpec("rel_optional", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial})
	optional.Services = append(optional.Services, contracts.ServiceRuntimeSpec{Name: "metrics", Role: domain.RoleWorker, Required: false, Image: domain.ImageDigest{Repository: "registry.example.test/metrics", Digest: groupDigest}, Resources: contracts.ResourceLimits{CPUMillis: 100, MemoryBytes: 32 << 20, DiskBytes: 1, PIDs: 16}})
	docker.failRun[provider.containerName("dep_optional", "metrics")] = errors.New("optional run failed")
	deployment, err := provider.DeployGroup(context.Background(), deployRequest("optional-fail", "dep_optional", optional))
	if err != nil {
		t.Fatal(err)
	}
	if deployment.Status != domain.DeploymentRuntimeReady || !docker.hasContainer(provider.containerName("dep_optional", "web")) {
		t.Fatalf("optional service failure blocked required group: %#v", deployment)
	}
	obs, err := provider.ObserveGroup(context.Background(), contracts.ObserveGroupRequest{DeploymentID: deployment.ID, Operation: contracts.OperationContext{IdempotencyKey: "optional-observe"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Services) != 3 {
		t.Fatalf("optional service fact was lost: %#v", obs.Services)
	}
}

func TestRollingCandidateFailureLeavesPreviousGroupServing(t *testing.T) {
	docker := &fakeDocker{containers: map[string]fakeContainer{}, failRun: map[string]error{}, logs: map[string]string{}}
	provider := newGroupProvider(t, docker, &fakeVolumes{})
	oldSpec := groupSpec("rel_old", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial})
	old, err := provider.DeployGroup(context.Background(), deployRequest("old", "dep_old", oldSpec))
	if err != nil {
		t.Fatal(err)
	}
	candidate := groupSpec("rel_new", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutRolling, PreviousDeploymentID: old.ID, PreserveOldUntilHealthy: true})
	candidate.Services[0].Resources.CPUMillis = 300 // force a changed web service; db remains reusable
	docker.failRun[provider.containerName("dep_new", "web")] = errors.New("candidate failed")
	if _, err := provider.DeployGroup(context.Background(), deployRequest("new", "dep_new", candidate)); err == nil {
		t.Fatal("failed rolling candidate was accepted")
	}
	if !docker.hasContainer(provider.containerName("dep_old", "db")) || !docker.hasContainer(provider.containerName("dep_old", "web")) {
		t.Fatal("old group was not preserved after candidate failure")
	}
	if docker.hasContainer(provider.containerName("dep_new", "db")) || docker.hasContainer(provider.containerName("dep_new", "web")) {
		t.Fatal("failed candidate left a container behind")
	}
}

func TestRollingCandidateReusesUnchangedServiceContainer(t *testing.T) {
	docker := &fakeDocker{containers: map[string]fakeContainer{}, failRun: map[string]error{}, logs: map[string]string{}}
	provider := newGroupProvider(t, docker, &fakeVolumes{})
	oldSpec := groupSpec("rel_reuse_old", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial})
	old, err := provider.DeployGroup(context.Background(), deployRequest("reuse-old", "dep_reuse_old", oldSpec))
	if err != nil {
		t.Fatal(err)
	}
	candidate := groupSpec("rel_reuse_new", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutRolling, PreviousDeploymentID: old.ID, PreserveOldUntilHealthy: true})
	candidate.Services[0].Resources.CPUMillis = 300 // web changes; db must be reused
	newDeployment, err := provider.DeployGroup(context.Background(), deployRequest("reuse-new", "dep_reuse_new", candidate))
	if err != nil {
		t.Fatal(err)
	}
	if got := countCalls(docker.callsSnapshot(), "run"); got != 3 {
		t.Fatalf("rolling update recreated unchanged db service: run count=%d calls=%#v", got, docker.callsSnapshot())
	}
	if !docker.hasContainer(provider.containerName(old.ID, "db")) || docker.hasContainer(provider.containerName(old.ID, "web")) || !docker.hasContainer(provider.containerName(newDeployment.ID, "web")) {
		t.Fatal("rolling update did not preserve unchanged db and replace changed web")
	}
	observation, err := provider.ObserveGroup(context.Background(), contracts.ObserveGroupRequest{DeploymentID: newDeployment.ID, Operation: contracts.OperationContext{IdempotencyKey: "reuse-observe"}})
	if err != nil || observation.Status != domain.DeploymentRuntimeReady.String() {
		t.Fatalf("reused candidate observation was invalid: %#v %v", observation, err)
	}
}

func TestProviderRestartRollingLoadsPreviousDurableGroup(t *testing.T) {
	docker := &fakeDocker{containers: map[string]fakeContainer{}, failRun: map[string]error{}, logs: map[string]string{}}
	volumes := &fakeVolumes{}
	root := t.TempDir()
	oldProvider, err := New(Config{TaskPrefix: "opencard-m2-test", WorkRoot: root, ImageStore: fakeLoader{}, Capacity: contracts.NewFakeCapacityProvider(true), Volumes: volumes, Runner: docker})
	if err != nil {
		t.Fatal(err)
	}
	oldSpec := groupSpec("rel_restart_roll_old", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial})
	old, err := oldProvider.DeployGroup(context.Background(), deployRequest("restart-roll-old", "dep_restart_roll_old", oldSpec))
	if err != nil {
		t.Fatal(err)
	}
	newProvider, err := New(Config{TaskPrefix: "opencard-m2-test", WorkRoot: root, ImageStore: fakeLoader{}, Capacity: contracts.NewFakeCapacityProvider(true), Volumes: volumes, Runner: docker})
	if err != nil {
		t.Fatal(err)
	}
	candidate := groupSpec("rel_restart_roll_new", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutRolling, PreviousDeploymentID: old.ID, PreserveOldUntilHealthy: true})
	candidate.ServiceGroupID = "group_restart_roll_new"
	candidate.Services[0].Resources.CPUMillis = 300
	deployed, err := newProvider.DeployGroup(context.Background(), deployRequest("restart-roll-new", "dep_restart_roll_new", candidate))
	if err != nil {
		t.Fatal(err)
	}
	if got := countCalls(docker.callsSnapshot(), "run"); got != 3 {
		t.Fatalf("restart rolling recreated unchanged service or failed to load old durable state: %d calls", got)
	}
	restarted, err := New(Config{TaskPrefix: "opencard-m2-test", WorkRoot: root, ImageStore: fakeLoader{}, Capacity: contracts.NewFakeCapacityProvider(true), Volumes: volumes, Runner: docker})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.DestroyGroup(context.Background(), contracts.DestroyRequest{DeploymentID: deployed.ID, PreserveVolumes: true, Operation: contracts.OperationContext{IdempotencyKey: "restart-roll-destroy"}}); err != nil {
		t.Fatal(err)
	}
	if docker.hasContainer(restarted.containerName(old.ID, "db")) || docker.hasContainer(restarted.containerName(deployed.ID, "web")) {
		t.Fatal("destroy after rolling restart left a reused or changed container behind")
	}
}

func TestProviderRestartAdoptsCompleteDigestGroupWithoutDuplicateRuns(t *testing.T) {
	docker := &fakeDocker{containers: map[string]fakeContainer{}, failRun: map[string]error{}, logs: map[string]string{}}
	volumes := &fakeVolumes{}
	first := newGroupProvider(t, docker, volumes)
	spec := groupSpec("rel_recover", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial})
	deployment, err := first.DeployGroup(context.Background(), deployRequest("recover-1", "dep_recover", spec))
	if err != nil {
		t.Fatal(err)
	}
	runsBefore := countCalls(docker.callsSnapshot(), "run")
	second := newGroupProvider(t, docker, volumes)
	if _, err := second.DeployGroup(context.Background(), deployRequest("recover-2", deployment.ID, spec)); err != nil {
		t.Fatal(err)
	}
	if countCalls(docker.callsSnapshot(), "run") != runsBefore {
		t.Fatalf("provider restart duplicated container effects: %#v", docker.callsSnapshot())
	}
}

func TestProviderRestartObserveAndDestroyUsesDurableState(t *testing.T) {
	docker := &fakeDocker{containers: map[string]fakeContainer{}, failRun: map[string]error{}, logs: map[string]string{}}
	volumes := &fakeVolumes{}
	root := t.TempDir()
	capacity := contracts.NewFakeCapacityProvider(true)
	first, err := New(Config{TaskPrefix: "opencard-m2-test", WorkRoot: root, ImageStore: fakeLoader{}, Capacity: capacity, Volumes: volumes, Runner: docker})
	if err != nil {
		t.Fatal(err)
	}
	spec := groupSpec("rel_durable", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial})
	deployment, err := first.DeployGroup(context.Background(), deployRequest("durable-deploy", "dep_durable", spec))
	if err != nil {
		t.Fatal(err)
	}
	statePath := first.durableStatePath(deployment.ID)
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("durable state permissions were not 0600: %o", info.Mode().Perm())
	}
	encodedState, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encodedState, []byte(`"value":"test"`)) || bytes.Contains(encodedState, []byte(`"command":[`)) || bytes.Contains(encodedState, []byte(`"entrypoint":[`)) {
		t.Fatalf("durable state retained plaintext runtime command/environment data: %s", encodedState)
	}
	second, err := New(Config{TaskPrefix: "opencard-m2-test", WorkRoot: root, ImageStore: fakeLoader{}, Capacity: contracts.NewFakeCapacityProvider(true), Volumes: volumes, Runner: docker})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := second.ObserveGroup(context.Background(), contracts.ObserveGroupRequest{DeploymentID: deployment.ID, Operation: contracts.OperationContext{IdempotencyKey: "durable-observe"}})
	if err != nil || observation.Status != domain.DeploymentRuntimeReady.String() {
		t.Fatalf("durable observe did not recover the group: %#v %v", observation, err)
	}
	if err := second.DestroyGroup(context.Background(), contracts.DestroyRequest{DeploymentID: deployment.ID, PreserveVolumes: true, Operation: contracts.OperationContext{IdempotencyKey: "durable-destroy"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("durable state remained after known destroy: %v", err)
	}
	if docker.hasContainer(second.containerName(deployment.ID, "db")) || docker.hasContainer(second.containerName(deployment.ID, "web")) {
		t.Fatal("destroy after provider restart left a container behind")
	}
}

func TestDestroyGroupStopsInReverseDAGOrderAndRequiresVolumeConfirmation(t *testing.T) {
	docker := &fakeDocker{containers: map[string]fakeContainer{}, failRun: map[string]error{}, logs: map[string]string{}}
	volumes := &fakeVolumes{}
	provider := newGroupProvider(t, docker, volumes)
	spec := groupSpec("rel_destroy", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial})
	deployment, err := provider.DeployGroup(context.Background(), deployRequest("destroy-deploy", "dep_destroy", spec))
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.DestroyGroup(context.Background(), contracts.DestroyRequest{DeploymentID: deployment.ID, PreserveVolumes: false, Operation: contracts.OperationContext{IdempotencyKey: "destroy-no-confirm"}}); err == nil {
		t.Fatal("volume deletion without confirmation was accepted")
	}
	if err := provider.DestroyGroup(context.Background(), contracts.DestroyRequest{DeploymentID: deployment.ID, PreserveVolumes: true, Operation: contracts.OperationContext{IdempotencyKey: "destroy-preserve"}}); err != nil {
		t.Fatal(err)
	}
	if err := provider.DestroyVolume(context.Background(), deployment.ID, "data", "confirm", contracts.OperationContext{IdempotencyKey: "destroy-volume"}); err != nil {
		t.Fatal(err)
	}
	if volumes.destroyed != 1 {
		t.Fatalf("volume destroy was not issued exactly once: %d", volumes.destroyed)
	}
	calls := docker.callsSnapshot()
	var stops []string
	for _, call := range calls {
		if len(call) > 0 && call[0] == "stop" {
			stops = append(stops, call[len(call)-1])
		}
	}
	if len(stops) < 2 || !strings.Contains(stops[0], "-web") || !strings.Contains(stops[1], "-db") {
		t.Fatalf("group stop order was not reverse dependency order: %#v", stops)
	}
}

func TestDeployGroupRejectsCyclesBeforeCapacityOrDockerMutation(t *testing.T) {
	docker := &fakeDocker{containers: map[string]fakeContainer{}, failRun: map[string]error{}, logs: map[string]string{}}
	provider := newGroupProvider(t, docker, &fakeVolumes{})
	spec := groupSpec("rel_cycle", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial})
	spec.Services[0].Dependencies = []domain.ServiceDependency{{Service: "web", Condition: domain.DependsStarted}}
	if _, err := provider.DeployGroup(context.Background(), deployRequest("cycle", "dep_cycle", spec)); err == nil {
		t.Fatal("dependency cycle was accepted")
	}
	if len(docker.callsSnapshot()) != 0 {
		t.Fatalf("cycle reached Docker: %#v", docker.callsSnapshot())
	}
}

func TestDeployGroupCapacityRejectionHasNoDockerOrVolumeSideEffects(t *testing.T) {
	docker := &fakeDocker{containers: map[string]fakeContainer{}, failRun: map[string]error{}, logs: map[string]string{}}
	volumes := &fakeVolumes{}
	capacity := contracts.NewFakeCapacityProvider(true)
	capacity.Snapshot.AvailableCPUMillis = 1
	provider, err := New(Config{TaskPrefix: "opencard-m2-test", WorkRoot: t.TempDir(), ImageStore: fakeLoader{}, Capacity: capacity, Volumes: volumes, Runner: docker})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DeployGroup(context.Background(), deployRequest("capacity-fail", "dep_capacity_fail", groupSpec("rel_capacity_fail", contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial}))); err == nil {
		t.Fatal("capacity failure was accepted")
	}
	for _, call := range docker.callsSnapshot() {
		if len(call) > 0 && (call[0] == "run" || call[0] == "load" || call[0] == "network") {
			t.Fatalf("capacity rejection reached Docker mutation: %#v", docker.callsSnapshot())
		}
	}
	volumes.mu.Lock()
	created := len(volumes.created)
	volumes.mu.Unlock()
	if created != 0 {
		t.Fatalf("capacity rejection created volumes: %#v", volumes.created)
	}
}

func containsPair(args []string, key, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key && args[i+1] == value {
			return true
		}
	}
	return false
}

func containsFlag(args []string, value string) bool {
	for _, arg := range args {
		if arg == value {
			return true
		}
	}
	return false
}

func countCalls(calls [][]string, command string) int {
	count := 0
	for _, call := range calls {
		if len(call) > 0 && call[0] == command {
			count++
		}
	}
	return count
}
