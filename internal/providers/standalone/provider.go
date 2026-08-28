// Package standalone implements the deliberately small M1 Docker runtime.
// It runs exactly one managed container per deployment from an immutable OCI
// archive supplied by contracts.ImageStore. It never accepts shell fragments,
// bind mounts, volumes, privileges, or host networking.
package standalone

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const (
	providerName    = "standalone-docker"
	providerVersion = "m1"
	defaultTimeout  = 2 * time.Minute
	defaultMaxOCI   = int64(4 << 30)
)

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
var safeRepository = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)

// CommandRunner is the only Docker execution boundary. Tests use an injected
// runner, so provider tests do not require a Docker daemon.
type CommandRunner interface {
	Run(ctx context.Context, command string, args []string, stdout, stderr io.Writer) error
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, command string, args []string, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return cmd.Run()
}

// PortAllocator chooses a loopback host port. The default asks the OS for an
// ephemeral port; an agent integration can provide a reservation-aware
// allocator when Docker and the agent share a stronger port-lease mechanism.
type PortAllocator interface {
	Allocate(context.Context) (int, error)
	Release(int)
}

type systemPortAllocator struct{}

func (systemPortAllocator) Allocate(ctx context.Context) (int, error) {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	if port < 1 || port > 65535 {
		return 0, errors.New("system port allocation returned an invalid port")
	}
	return port, nil
}

func (systemPortAllocator) Release(int) {}

// Config contains provider-owned boundaries. TaskPrefix namespaces every
// Docker object this provider can create; it must not overlap arbitrary host
// containers or networks.
type Config struct {
	Command               string
	TaskPrefix            string
	Network               string
	WorkRoot              string
	ImageStore            contracts.ImageStore
	Capacity              contracts.CapacityProvider
	Runner                CommandRunner
	Ports                 PortAllocator
	Timeout               time.Duration
	MaxOCIBytes           int64
	Clock                 func() time.Time
	WorkerNetworkIsolated bool
}

func (c Config) normalized() (Config, error) {
	if c.Command == "" {
		c.Command = "docker"
	}
	if !safeName.MatchString(c.TaskPrefix) {
		return Config{}, errors.New("standalone task prefix must be a safe non-empty name")
	}
	if c.Network == "" {
		c.Network = c.TaskPrefix + "-network"
	}
	if !safeName.MatchString(c.Network) || !strings.HasPrefix(c.Network, c.TaskPrefix+"-") {
		return Config{}, errors.New("standalone network must be a task-prefixed safe name")
	}
	if c.ImageStore == nil {
		return Config{}, errors.New("standalone image store is required")
	}
	if c.Capacity == nil {
		return Config{}, errors.New("standalone capacity provider is required")
	}
	if strings.TrimSpace(c.WorkRoot) == "" {
		return Config{}, errors.New("standalone work root is required")
	}
	workRoot, err := filepath.Abs(c.WorkRoot)
	if err != nil {
		return Config{}, fmt.Errorf("standalone work root: %w", err)
	}
	info, err := os.Stat(workRoot)
	if err != nil {
		return Config{}, fmt.Errorf("standalone work root: %w", err)
	}
	if !info.IsDir() {
		return Config{}, errors.New("standalone work root is not a directory")
	}
	c.WorkRoot = filepath.Clean(workRoot)
	if c.Runner == nil {
		c.Runner = execRunner{}
	}
	if c.Ports == nil {
		c.Ports = systemPortAllocator{}
	}
	if c.Timeout == 0 {
		c.Timeout = defaultTimeout
	}
	if c.Timeout <= 0 {
		return Config{}, errors.New("standalone timeout must be positive")
	}
	if c.MaxOCIBytes == 0 {
		c.MaxOCIBytes = defaultMaxOCI
	}
	if c.MaxOCIBytes <= 0 {
		return Config{}, errors.New("standalone OCI archive limit must be positive")
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	return c, nil
}

// Provider owns only containers and one bridge network whose names begin with
// Config.TaskPrefix. It intentionally does not expose scale or rollback: M1
// is one immutable image in one container.
type Provider struct {
	config   Config
	metadata contracts.ProviderMetadata

	mu        sync.Mutex
	networkMu sync.Mutex
	deploys   map[string]*deployRecord
	states    map[domain.ID]*runtimeState
}

type deployRecord struct {
	fingerprint string
	done        chan struct{}
	deployment  domain.Deployment
	err         error
}

type runtimeState struct {
	deployment domain.Deployment
	service    string
	container  string
	port       int
	destroyed  bool
	actions    map[string]struct{}
	capacity   *contracts.CapacityLease
	resources  contracts.ResourceLimits
}

var _ contracts.RuntimeDriver = (*Provider)(nil)

func New(config Config) (*Provider, error) {
	config, err := config.normalized()
	if err != nil {
		return nil, err
	}
	return &Provider{
		config: config,
		metadata: contracts.ProviderMetadata{
			Name:            providerName,
			Version:         providerVersion,
			ContractVersion: contracts.ContractAPIVersion,
			Capabilities: contracts.NewCapabilitySet(
				contracts.CapabilityRuntimeDeploy, contracts.CapabilityRuntimeObserve,
				contracts.CapabilityRuntimeLogs, contracts.CapabilityRuntimeRestart,
				contracts.CapabilityRuntimeDestroy,
			),
			SensitiveInputs: []string{"oci archive", "runtime logs"},
		},
		deploys: make(map[string]*deployRecord),
		states:  make(map[domain.ID]*runtimeState),
	}, nil
}

func NewProvider(config Config) (*Provider, error) { return New(config) }

func (p *Provider) Metadata(context.Context) contracts.ProviderMetadata { return p.metadata }

func (p *Provider) Deploy(ctx context.Context, request contracts.DeployRequest) (domain.Deployment, error) {
	if err := p.check(ctx, request.Operation, contracts.CapabilityRuntimeDeploy, "deploy"); err != nil {
		return domain.Deployment{}, err
	}
	if request.DeploymentID.Empty() {
		return domain.Deployment{}, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrInvalidArgument, "deployment id is required", contracts.RetryNever, false, nil)
	}
	if err := p.validateSpec(request.Spec, request.Operation); err != nil {
		return domain.Deployment{}, err
	}
	fingerprint := p.fingerprint(request.DeploymentID, request.Spec)
	key := request.Operation.IdempotencyKey
	p.mu.Lock()
	if previous := p.deploys[key]; previous != nil {
		if previous.fingerprint != fingerprint {
			p.mu.Unlock()
			return domain.Deployment{}, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrConflict, "idempotency key was reused for a different runtime specification", contracts.RetryNever, false, nil)
		}
		p.mu.Unlock()
		select {
		case <-previous.done:
			return previous.deployment, previous.err
		case <-ctx.Done():
			return domain.Deployment{}, p.contextError(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", ctx.Err())
		}
	}
	record := &deployRecord{fingerprint: fingerprint, done: make(chan struct{})}
	p.deploys[key] = record
	p.mu.Unlock()

	deployment, state, err := p.deploy(ctx, request, fingerprint)
	p.mu.Lock()
	record.deployment, record.err = deployment, err
	if err == nil {
		p.states[deployment.ID] = state
	}
	close(record.done)
	p.mu.Unlock()
	return deployment, err
}

func (p *Provider) deploy(ctx context.Context, request contracts.DeployRequest, fingerprint string) (deployment domain.Deployment, state *runtimeState, err error) {
	ctx, cancel := p.operationContext(ctx, request.Operation)
	defer cancel()
	deployment = domain.Deployment{ID: request.DeploymentID, ApplicationID: request.Spec.ApplicationID, EnvironmentID: request.Spec.EnvironmentID, ReleaseID: request.Spec.ReleaseID, Status: domain.DeploymentPending, CreatedAt: p.config.Clock().UTC(), UpdatedAt: p.config.Clock().UTC()}
	if err := deployment.Validate(); err != nil {
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrValidation, "deployment record is invalid", contracts.RetryNever, false, err)
	}
	if err := deployment.Transition(domain.DeploymentPreparing, p.config.Clock()); err != nil {
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrValidation, "deployment transition is invalid", contracts.RetryNever, false, err)
	}
	container := p.config.TaskPrefix + "-runtime-" + hash(string(deployment.ID))[:20]
	if recovered, ok, recoverErr := p.recover(ctx, container, deployment, request); recoverErr != nil {
		return domain.Deployment{}, nil, recoverErr
	} else if ok {
		return recovered.deployment, recovered, nil
	}
	capacityOperation := request.Operation
	capacityOperation.IdempotencyKey += ":runtime-capacity"
	capacity, err := p.config.Capacity.Reserve(ctx, contracts.CapacityRequest{Scope: contracts.CapacityRuntime, Resources: request.Spec.Resources, HostPorts: 1, Operation: capacityOperation})
	if err != nil {
		return domain.Deployment{}, nil, err
	}
	defer func() {
		if err != nil {
			releaseOperation := request.Operation
			releaseOperation.IdempotencyKey += ":runtime-capacity-release"
			_ = p.config.Capacity.Release(context.Background(), capacity, releaseOperation)
		}
	}()
	archive, stored, err := p.config.ImageStore.OpenOCI(ctx, request.Spec.Image, request.Operation)
	if err != nil {
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrUnavailable, "persistent OCI archive is unavailable", contracts.RetryBackoff, true, nil)
	}
	defer archive.Close()
	if !sameImage(stored.Image, request.Spec.Image) || strings.TrimSpace(stored.StorageRef) == "" {
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrValidation, "persistent OCI archive does not attest the requested digest", contracts.RetryNever, false, nil)
	}
	path, err := p.copyArchive(archive)
	if err != nil {
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrUnavailable, "persistent OCI archive could not be staged", contracts.RetryBackoff, true, nil)
	}
	defer os.Remove(path)
	if err := p.run(ctx, []string{"load", "--input", path}); err != nil {
		return domain.Deployment{}, nil, p.commandError(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", err)
	}
	if err := p.verifyImage(ctx, request.Spec.Image, request.Operation); err != nil {
		return domain.Deployment{}, nil, err
	}
	if err := p.ensureNetwork(ctx, request.Operation); err != nil {
		return domain.Deployment{}, nil, err
	}

	port := capacity.HostPort
	if request.Spec.Port != 0 && port == 0 {
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrCapacity, "capacity lease did not reserve a loopback host port", contracts.RetryBackoff, true, nil)
	}
	if err := deployment.Transition(domain.DeploymentDeploying, p.config.Clock()); err != nil {
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrValidation, "deployment transition is invalid", contracts.RetryNever, false, err)
	}
	args := p.runArgs(container, deployment, request.Spec, port)
	activateOperation := request.Operation
	activateOperation.IdempotencyKey += ":runtime-capacity-activate"
	if err = p.config.Capacity.Activate(ctx, capacity, activateOperation); err != nil {
		return domain.Deployment{}, nil, err
	}
	if err := p.run(ctx, args); err != nil {
		return domain.Deployment{}, nil, p.commandError(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", err)
	}
	if err := deployment.Transition(domain.DeploymentRuntimeReady, p.config.Clock()); err != nil {
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrValidation, "deployment transition is invalid", contracts.RetryNever, false, err)
	}
	return deployment, &runtimeState{deployment: deployment, service: request.Spec.ServiceName, container: container, port: port, actions: make(map[string]struct{}), capacity: &capacity, resources: request.Spec.Resources}, nil
}

func (p *Provider) recover(ctx context.Context, container string, deployment domain.Deployment, request contracts.DeployRequest) (*runtimeState, bool, error) {
	output, err := p.output(ctx, []string{"container", "inspect", "--format", "{{json .}}", container})
	if err != nil {
		return nil, false, nil
	}
	var value struct {
		Image  string `json:"Image"`
		Config struct {
			Labels  map[string]string `json:"Labels"`
			Volumes map[string]any    `json:"Volumes"`
		} `json:"Config"`
		State struct {
			Running bool `json:"Running"`
		} `json:"State"`
		HostConfig struct {
			NetworkMode  string   `json:"NetworkMode"`
			Privileged   bool     `json:"Privileged"`
			Binds        []string `json:"Binds"`
			CapAdd       []string `json:"CapAdd"`
			Memory       int64    `json:"Memory"`
			MemorySwap   int64    `json:"MemorySwap"`
			CpuPeriod    int64    `json:"CpuPeriod"`
			CpuQuota     int64    `json:"CpuQuota"`
			PidsLimit    *int64   `json:"PidsLimit"`
			SecurityOpt  []string `json:"SecurityOpt"`
			PortBindings map[string][]struct {
				HostIP   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			} `json:"PortBindings"`
		} `json:"HostConfig"`
	}
	if err := json.Unmarshal([]byte(output), &value); err != nil {
		return nil, true, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrConflict, "existing task container has invalid inspection data", contracts.RetryNever, false, nil)
	}
	labels := value.Config.Labels
	valid := labels["open-card.managed"] == "true" && labels["open-card.task-prefix"] == p.config.TaskPrefix && labels["open-card.deployment-id"] == deployment.ID.String() && labels["open-card.service"] == request.Spec.ServiceName
	valid = valid && value.Image == request.Spec.Image.Digest && value.State.Running && value.HostConfig.NetworkMode == p.config.Network && !value.HostConfig.Privileged && len(value.HostConfig.Binds) == 0 && len(value.HostConfig.CapAdd) == 0 && len(value.Config.Volumes) == 0
	valid = valid && value.HostConfig.Memory == request.Spec.Resources.MemoryBytes && value.HostConfig.MemorySwap == request.Spec.Resources.MemoryBytes && value.HostConfig.CpuPeriod == 100000 && value.HostConfig.CpuQuota == request.Spec.Resources.CPUMillis*100 && contains(value.HostConfig.SecurityOpt, "no-new-privileges=true")
	valid = valid && value.HostConfig.PidsLimit != nil && *value.HostConfig.PidsLimit == request.Spec.Resources.PIDs
	port := 0
	if request.Spec.Port != 0 {
		bindings := value.HostConfig.PortBindings[fmt.Sprintf("%d/tcp", request.Spec.Port)]
		if len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" {
			valid = false
		} else if _, err := fmt.Sscan(bindings[0].HostPort, &port); err != nil || port < 1 || port > 65535 {
			valid = false
		}
	}
	if !valid {
		return nil, true, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrConflict, "existing task container does not match the immutable constrained deployment", contracts.RetryNever, false, nil)
	}
	if err := deployment.Transition(domain.DeploymentDeploying, p.config.Clock()); err != nil {
		return nil, true, err
	}
	if err := deployment.Transition(domain.DeploymentRuntimeReady, p.config.Clock()); err != nil {
		return nil, true, err
	}
	return &runtimeState{deployment: deployment, service: request.Spec.ServiceName, container: container, port: port, actions: make(map[string]struct{}), resources: request.Spec.Resources}, true, nil
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func (p *Provider) Observe(ctx context.Context, request contracts.ObserveRequest) (contracts.RuntimeObservation, error) {
	if err := p.check(ctx, request.Operation, contracts.CapabilityRuntimeObserve, "observe"); err != nil {
		return contracts.RuntimeObservation{}, err
	}
	state, err := p.state(request.DeploymentID, request.Operation, contracts.CapabilityRuntimeObserve, "observe")
	if err != nil {
		return contracts.RuntimeObservation{}, err
	}
	if state.destroyed {
		return p.observation(state, "stopped", false, 0, 0, 0, request.Operation), nil
	}
	output, err := p.output(ctx, []string{"inspect", "--format", "{{json .State}}|{{.RestartCount}}", state.container})
	if err != nil {
		return contracts.RuntimeObservation{}, p.commandError(request.Operation, contracts.CapabilityRuntimeObserve, "observe", err)
	}
	status, healthy, restarts, err := parseState(output)
	if err != nil {
		return contracts.RuntimeObservation{}, p.failure(request.Operation, contracts.CapabilityRuntimeObserve, "observe", contracts.ErrValidation, "Docker returned an invalid runtime observation", contracts.RetryNever, false, nil)
	}
	return p.observation(state, status, healthy, restarts, 0, 0, request.Operation), nil
}

func (p *Provider) Logs(ctx context.Context, request contracts.LogsRequest) (<-chan string, error) {
	if err := p.check(ctx, request.Operation, contracts.CapabilityRuntimeLogs, "logs"); err != nil {
		return nil, err
	}
	state, err := p.state(request.DeploymentID, request.Operation, contracts.CapabilityRuntimeLogs, "logs")
	if err != nil {
		return nil, err
	}
	if request.ServiceName != "" && request.ServiceName != state.service {
		return nil, p.failure(request.Operation, contracts.CapabilityRuntimeLogs, "logs", contracts.ErrValidation, "runtime service does not match deployment", contracts.RetryNever, false, nil)
	}
	args := []string{"logs", "--timestamps"}
	if request.Tail > 0 {
		args = append(args, "--tail", fmt.Sprint(request.Tail))
	}
	if !request.Since.IsZero() {
		args = append(args, "--since", request.Since.UTC().Format(time.RFC3339))
	}
	args = append(args, state.container)
	output, err := p.output(ctx, args)
	if err != nil {
		return nil, p.commandError(request.Operation, contracts.CapabilityRuntimeLogs, "logs", err)
	}
	lines := make(chan string, strings.Count(output, "\n")+1)
	for _, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
		if line != "" {
			lines <- line
		}
	}
	close(lines)
	return lines, nil
}

func (p *Provider) Restart(ctx context.Context, request contracts.RestartRequest) error {
	if err := p.check(ctx, request.Operation, contracts.CapabilityRuntimeRestart, "restart"); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	state, err := p.stateLocked(request.DeploymentID, request.Operation, contracts.CapabilityRuntimeRestart, "restart")
	if err != nil {
		return err
	}
	if request.ServiceName != "" && request.ServiceName != state.service {
		return p.failure(request.Operation, contracts.CapabilityRuntimeRestart, "restart", contracts.ErrValidation, "runtime service does not match deployment", contracts.RetryNever, false, nil)
	}
	if _, done := state.actions[request.Operation.IdempotencyKey]; done {
		return nil
	}
	if err := p.run(ctx, []string{"restart", state.container}); err != nil {
		return p.commandError(request.Operation, contracts.CapabilityRuntimeRestart, "restart", err)
	}
	state.actions[request.Operation.IdempotencyKey] = struct{}{}
	return nil
}

func (p *Provider) Scale(ctx context.Context, request contracts.ScaleRequest) error {
	return p.unsupported(ctx, request.Operation, contracts.CapabilityRuntimeScale, "scale")
}

func (p *Provider) Rollback(ctx context.Context, request contracts.RollbackRequest) (domain.Deployment, error) {
	return domain.Deployment{}, p.unsupported(ctx, request.Operation, contracts.CapabilityRuntimeRollback, "rollback")
}

func (p *Provider) Destroy(ctx context.Context, request contracts.DestroyRequest) error {
	if err := p.check(ctx, request.Operation, contracts.CapabilityRuntimeDestroy, "destroy"); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	state, err := p.stateLocked(request.DeploymentID, request.Operation, contracts.CapabilityRuntimeDestroy, "destroy")
	if err != nil {
		return err
	}
	if state.destroyed || hasAction(state, request.Operation.IdempotencyKey) {
		return nil
	}
	if err := p.run(ctx, []string{"rm", "--force", state.container}); err != nil {
		return p.commandError(request.Operation, contracts.CapabilityRuntimeDestroy, "destroy", err)
	}
	state.destroyed = true
	state.actions[request.Operation.IdempotencyKey] = struct{}{}
	if state.port != 0 {
		state.port = 0
	}
	if state.capacity != nil {
		if err := p.config.Capacity.Release(ctx, *state.capacity, request.Operation); err != nil {
			return err
		}
		state.capacity = nil
	}
	return nil
}

func (p *Provider) validateSpec(spec contracts.RuntimeSpec, operation contracts.OperationContext) error {
	if spec.ApplicationID.Empty() || spec.EnvironmentID.Empty() || spec.ReleaseID.Empty() || !safeName.MatchString(spec.ServiceName) {
		return p.failure(operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrInvalidArgument, "runtime application, environment, release, and safe service name are required", contracts.RetryNever, false, nil)
	}
	if err := spec.Image.Validate(); err != nil || !safeRepository.MatchString(spec.Image.Repository) || strings.Contains(spec.Image.Repository, "..") {
		return p.failure(operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrValidation, "runtime image must be a safe immutable repository digest", contracts.RetryNever, false, nil)
	}
	if spec.Resources.CPUMillis <= 0 || spec.Resources.CPUMillis > int64(^uint64(0)>>1)/100 || spec.Resources.MemoryBytes <= 0 || spec.Resources.DiskBytes <= 0 || spec.Resources.PIDs <= 0 || spec.Resources.ConcurrencySlot != 0 || spec.Resources.TimeoutSeconds < 0 {
		return p.failure(operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrValidation, "runtime requires exact positive CPU, memory, disk-capacity and PID limits with no concurrency override", contracts.RetryNever, false, nil)
	}
	if spec.Port < 0 || spec.Port > 65535 {
		return p.failure(operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrValidation, "runtime container port is invalid", contracts.RetryNever, false, nil)
	}
	if len(spec.Secrets) != 0 {
		return p.failure(operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrForbidden, "standalone M1 does not materialize runtime secrets", contracts.RetryUserAction, false, nil)
	}
	return nil
}

func (p *Provider) ensureNetwork(ctx context.Context, operation contracts.OperationContext) error {
	p.networkMu.Lock()
	defer p.networkMu.Unlock()
	if output, err := p.output(ctx, []string{"network", "inspect", "--format", "{{index .Labels \"open-card.managed\"}}|{{index .Labels \"open-card.task-prefix\"}}", p.config.Network}); err == nil {
		if strings.TrimSpace(output) == "true|"+p.config.TaskPrefix {
			return nil
		}
		return p.failure(operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrConflict, "task-prefixed network is not managed by this provider", contracts.RetryNever, false, nil)
	}
	args := []string{"network", "create", "--driver", "bridge"}
	if !p.config.WorkerNetworkIsolated {
		args = append(args, "--internal")
	}
	args = append(args, "--label", "open-card.managed=true", "--label", "open-card.task-prefix="+p.config.TaskPrefix, p.config.Network)
	if err := p.run(ctx, args); err != nil {
		return p.commandError(operation, contracts.CapabilityRuntimeDeploy, "deploy", err)
	}
	return nil
}

func (p *Provider) verifyImage(ctx context.Context, image domain.ImageDigest, operation contracts.OperationContext) error {
	output, err := p.output(ctx, []string{"image", "inspect", "--format", "{{.Id}}|{{json .Config}}", image.Digest})
	if err != nil {
		return p.commandError(operation, contracts.CapabilityRuntimeDeploy, "deploy", err)
	}
	parts := strings.SplitN(strings.TrimSpace(output), "|", 2)
	if len(parts) != 2 || !validImageID(strings.TrimSpace(parts[0])) {
		return p.failure(operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrValidation, "loaded image did not report a valid image ID", contracts.RetryNever, false, nil)
	}
	if strings.TrimSpace(parts[0]) != image.Digest {
		return p.failure(operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrConflict, "loaded OCI image identity did not match the requested immutable digest", contracts.RetryNever, false, nil)
	}
	var config struct {
		Volumes map[string]any `json:"Volumes"`
	}
	if err := json.Unmarshal([]byte(parts[1]), &config); err != nil || len(config.Volumes) != 0 {
		return p.failure(operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrForbidden, "images declaring volumes are not supported by standalone M1", contracts.RetryUserAction, false, nil)
	}
	return nil
}

func (p *Provider) runArgs(container string, deployment domain.Deployment, spec contracts.RuntimeSpec, port int) []string {
	args := []string{
		"run", "--detach", "--name", container,
		"--pull", "never", "--restart", "no",
		"--network", p.config.Network,
		"--security-opt", "no-new-privileges=true", "--cap-drop", "ALL",
		"--cpu-period", "100000", "--cpu-quota", fmt.Sprint(spec.Resources.CPUMillis * 100),
		"--memory", fmt.Sprint(spec.Resources.MemoryBytes), "--memory-swap", fmt.Sprint(spec.Resources.MemoryBytes),
		"--pids-limit", fmt.Sprint(spec.Resources.PIDs),
		"--label", "open-card.managed=true",
		"--label", "open-card.task-prefix=" + p.config.TaskPrefix,
		"--label", "open-card.deployment-id=" + string(deployment.ID),
		"--label", "open-card.service=" + spec.ServiceName,
	}
	if port != 0 {
		args = append(args, "--publish", fmt.Sprintf("127.0.0.1:%d:%d/tcp", port, spec.Port))
	}
	return append(args, imageRef(spec.Image))
}

func (p *Provider) copyArchive(source io.Reader) (string, error) {
	file, err := os.CreateTemp(p.config.WorkRoot, ".standalone-oci-*.tar")
	if err != nil {
		return "", err
	}
	path := file.Name()
	success := false
	defer func() {
		if !success {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return "", err
	}
	n, copyErr := io.Copy(file, io.LimitReader(source, p.config.MaxOCIBytes+1))
	closeErr := file.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if n == 0 || n > p.config.MaxOCIBytes {
		return "", errors.New("OCI archive exceeds configured limit or is empty")
	}
	success = true
	return path, nil
}

func (p *Provider) state(id domain.ID, operation contracts.OperationContext, capability contracts.Capability, action string) (runtimeState, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	state, err := p.stateLocked(id, operation, capability, action)
	if err != nil {
		return runtimeState{}, err
	}
	return *state, nil
}

func (p *Provider) stateLocked(id domain.ID, operation contracts.OperationContext, capability contracts.Capability, action string) (*runtimeState, error) {
	if id.Empty() {
		return nil, p.failure(operation, capability, action, contracts.ErrInvalidArgument, "deployment id is required", contracts.RetryNever, false, nil)
	}
	state := p.states[id]
	if state == nil {
		return nil, p.failure(operation, capability, action, contracts.ErrNotFound, "managed deployment was not found", contracts.RetryUserAction, false, nil)
	}
	return state, nil
}

func (p *Provider) observation(state runtimeState, status string, healthy bool, restarts uint64, cpu, memory int64, operation contracts.OperationContext) contracts.RuntimeObservation {
	return contracts.RuntimeObservation{DeploymentID: state.deployment.ID, ServiceName: state.service, Status: status, Healthy: healthy, RestartCount: restarts, CPUUsageMillis: cpu, MemoryBytes: memory, HostPort: state.port, Limits: state.resources, ObservedAt: p.config.Clock().UTC(), Evidence: p.evidence(operation, "runtime.observe")}
}

func (p *Provider) output(ctx context.Context, args []string) (string, error) {
	var stdout, stderr bytes.Buffer
	if err := p.config.Runner.Run(ctx, p.config.Command, args, &stdout, &stderr); err != nil {
		return "", err
	}
	return stdout.String(), nil
}

func (p *Provider) run(ctx context.Context, args []string) error {
	_, err := p.output(ctx, args)
	return err
}

func (p *Provider) check(ctx context.Context, operation contracts.OperationContext, capability contracts.Capability, action string) error {
	if err := p.metadata.Supports(capability); err != nil {
		return err
	}
	if err := operation.Validate(); err != nil {
		return p.failure(operation, capability, action, contracts.ErrInvalidArgument, "provider idempotency key is required", contracts.RetryNever, false, err)
	}
	if err := ctx.Err(); err != nil {
		return p.contextError(operation, capability, action, err)
	}
	if !operation.Deadline.IsZero() && !time.Now().Before(operation.Deadline) {
		return p.contextError(operation, capability, action, context.DeadlineExceeded)
	}
	return nil
}

func (p *Provider) unsupported(ctx context.Context, operation contracts.OperationContext, capability contracts.Capability, action string) error {
	if err := operation.Validate(); err != nil {
		return p.failure(operation, capability, action, contracts.ErrInvalidArgument, "provider idempotency key is required", contracts.RetryNever, false, err)
	}
	if err := ctx.Err(); err != nil {
		return p.contextError(operation, capability, action, err)
	}
	return p.failure(operation, capability, action, contracts.ErrUnsupportedCapability, "standalone M1 supports one container only", contracts.RetryUserAction, false, nil)
}

func (p *Provider) operationContext(ctx context.Context, operation contracts.OperationContext) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(p.config.Timeout)
	if !operation.Deadline.IsZero() && operation.Deadline.Before(deadline) {
		deadline = operation.Deadline
	}
	return context.WithDeadline(ctx, deadline)
}

func (p *Provider) contextError(operation contracts.OperationContext, capability contracts.Capability, action string, cause error) error {
	if errors.Is(cause, context.DeadlineExceeded) {
		return p.failure(operation, capability, action, contracts.ErrTimeout, "provider operation timed out", contracts.RetryBackoff, true, cause)
	}
	return p.failure(operation, capability, action, contracts.ErrCancelled, "provider operation was cancelled", contracts.RetryAfterReconnect, true, cause)
}

func (p *Provider) commandError(operation contracts.OperationContext, capability contracts.Capability, action string, cause error) error {
	if errors.Is(cause, context.DeadlineExceeded) || errors.Is(cause, context.Canceled) {
		return p.contextError(operation, capability, action, cause)
	}
	return p.failure(operation, capability, action, contracts.ErrUnavailable, "Docker command failed", contracts.RetryBackoff, true, nil)
}

func (p *Provider) failure(operation contracts.OperationContext, capability contracts.Capability, action string, code contracts.ErrorCode, message string, retry contracts.RetryClass, retryable bool, cause error) error {
	return &contracts.ProviderError{Provider: p.metadata.Name, Code: code, Message: message, Retry: retry, Retryable: retryable, Capability: capability, Operation: action, Cause: cause, Details: map[string]string{"evidence_ref": string(evidenceID(p.metadata.Name, action, operation.IdempotencyKey)), "log_ref": "runtime://" + p.metadata.Name + "/" + action + "/" + hash(operation.IdempotencyKey)[:16]}}
}

func (p *Provider) evidence(operation contracts.OperationContext, kind string) contracts.Evidence {
	digest := "sha256:" + hash(p.metadata.Name, kind, operation.IdempotencyKey)
	return contracts.Evidence{Refs: []domain.EvidenceRef{{ID: evidenceID(p.metadata.Name, kind, operation.IdempotencyKey), Kind: kind, Digest: digest, Locator: "runtime://" + p.metadata.Name + "/" + kind + "/" + hash(operation.IdempotencyKey)[:16]}}, Summary: "redacted standalone runtime observation", Digest: digest, Redacted: true}
}

func (p *Provider) fingerprint(deploymentID domain.ID, spec contracts.RuntimeSpec) string {
	return hash(string(deploymentID), string(spec.ApplicationID), string(spec.EnvironmentID), string(spec.ReleaseID), spec.ServiceName, spec.Image.Repository, spec.Image.Digest, fmt.Sprint(spec.Resources), fmt.Sprint(spec.Port))
}

func imageRef(image domain.ImageDigest) string { return image.Digest }
func sameImage(left, right domain.ImageDigest) bool {
	return left.Repository == right.Repository && left.Digest == right.Digest
}
func hasAction(state *runtimeState, key string) bool { _, ok := state.actions[key]; return ok }
func validImageID(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(strings.TrimPrefix(value, "sha256:")) != 64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func parseState(output string) (string, bool, uint64, error) {
	parts := strings.SplitN(strings.TrimSpace(output), "|", 2)
	if len(parts) != 2 {
		return "", false, 0, errors.New("invalid inspect result")
	}
	var state struct {
		Status  string `json:"Status"`
		Running bool   `json:"Running"`
		Health  *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	}
	if err := json.Unmarshal([]byte(parts[0]), &state); err != nil || strings.TrimSpace(state.Status) == "" {
		return "", false, 0, errors.New("invalid Docker state")
	}
	var restarts uint64
	if _, err := fmt.Sscan(strings.TrimSpace(parts[1]), &restarts); err != nil {
		return "", false, 0, errors.New("invalid Docker restart count")
	}
	healthy := state.Running && (state.Health == nil || state.Health.Status == "healthy")
	return state.Status, healthy, restarts, nil
}

func hash(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func evidenceID(parts ...string) domain.ID { return domain.ID("ev_" + hash(parts...)[:32]) }
