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
	"strconv"
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
	// When supplied, the caller owns network preparation. Missing or altered
	// networks fail closed; this provider must never recreate an unguarded bridge.
	ExistingNetworkValidator func([]byte) error
	DNS                      []string
	// RestoreActiveGuard opts the installed host into startup recovery. The
	// caller must verify that the root-owned network guard started successfully.
	// Nil preserves observation-only reconciliation for other integrations.
	RestoreActiveGuard func(context.Context) error
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
	if len(c.DNS) > 8 {
		return Config{}, errors.New("standalone DNS configuration is invalid")
	}
	seenDNS := map[string]bool{}
	for _, address := range c.DNS {
		ip := net.ParseIP(address)
		if ip == nil || ip.To4() == nil || ip.String() != address || seenDNS[address] {
			return Config{}, errors.New("standalone DNS configuration is invalid")
		}
		seenDNS[address] = true
	}
	c.DNS = append([]string(nil), c.DNS...)
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

	mu             sync.Mutex
	networkMu      sync.Mutex
	guardMu        sync.Mutex
	lifecycleLocks map[domain.ID]*sync.Mutex
	deploys        map[string]*deployRecord
	states         map[domain.ID]*runtimeState
}

type deployRecord struct {
	fingerprint string
	done        chan struct{}
	deployment  domain.Deployment
	err         error
}

type runtimeState struct {
	deployment      domain.Deployment
	service         string
	image           domain.ImageDigest
	container       string
	containerID     string
	port            int
	containerPort   int
	destroyed       bool
	phase           string
	fingerprint     string
	createdAt       time.Time
	updatedAt       time.Time
	leaseGeneration int
	recovery        runtimeRecovery
	actions         map[string]runtimeAction
	capacity        *contracts.CapacityLease
	resources       contracts.ResourceLimits
}

type runtimeRecovery string

const (
	runtimeRecoveryActive            runtimeRecovery = "active"
	runtimeRecoveryPendingAbsent     runtimeRecovery = "pending_confirmed_absent"
	runtimeRecoveryPendingRunning    runtimeRecovery = "pending_present_running"
	runtimeRecoveryPendingNotRunning runtimeRecovery = "pending_present_not_running"
	runtimeRecoveryDestroyingAbsent  runtimeRecovery = "destroying_absent"
)

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
		deploys:        make(map[string]*deployRecord),
		states:         make(map[domain.ID]*runtimeState),
		lifecycleLocks: make(map[domain.ID]*sync.Mutex),
	}, nil
}

func NewProvider(config Config) (*Provider, error) { return New(config) }

func (p *Provider) Metadata(context.Context) contracts.ProviderMetadata { return p.metadata }

func (p *Provider) lockDeployment(id domain.ID) func() {
	p.guardMu.Lock()
	lock := p.lifecycleLocks[id]
	if lock == nil {
		lock = &sync.Mutex{}
		p.lifecycleLocks[id] = lock
	}
	p.guardMu.Unlock()
	lock.Lock()
	return lock.Unlock
}

func (p *Provider) Deploy(ctx context.Context, request contracts.DeployRequest) (domain.Deployment, error) {
	unlock := p.lockDeployment(request.DeploymentID)
	defer unlock()
	return p.deployOperation(ctx, request)
}

func (p *Provider) deployOperation(ctx context.Context, request contracts.DeployRequest) (domain.Deployment, error) {
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
			if previous.err == nil {
				p.mu.Lock()
				state := p.states[previous.deployment.ID]
				destroyed := state != nil && state.destroyed
				replacing := state != nil && state.phase == "replacing"
				p.mu.Unlock()
				if replacing {
					return domain.Deployment{}, p.replacementFailure(request.Operation, "deployment has an unfinished replacement task")
				}
				if destroyed {
					return domain.Deployment{}, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrConflict, "destroyed runtime rejects replay of its prior deploy operation", contracts.RetryNever, false, nil)
				}
			}
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
	if err != nil {
		delete(p.deploys, key)
	}
	p.mu.Unlock()
	return deployment, err
}

// Recreate replaces one immutable deployment. Installed AcornFox retains its
// capacity and published port through a durable replacing phase. Legacy callers
// preserve their existing destroyed-then-deploy replacement behavior.
func (p *Provider) Recreate(ctx context.Context, request contracts.DeployRequest) (domain.Deployment, error) {
	unlock := p.lockDeployment(request.DeploymentID)
	defer unlock()
	if err := p.check(ctx, request.Operation, contracts.CapabilityRuntimeDeploy, "recreate"); err != nil {
		return domain.Deployment{}, err
	}
	if request.DeploymentID.Empty() || p.validateSpec(request.Spec, request.Operation) != nil {
		return domain.Deployment{}, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "recreate", contracts.ErrInvalidArgument, "runtime deployment and immutable spec are invalid", contracts.RetryNever, false, nil)
	}
	if p.config.RestoreActiveGuard != nil {
		return p.recreateRetainingCapacity(ctx, request)
	}
	return p.recreateLegacy(ctx, request)
}

func (p *Provider) recreateLegacy(ctx context.Context, request contracts.DeployRequest) (domain.Deployment, error) {
	actionHash := actionIdentity("recreate", request.Operation.IdempotencyKey)
	if state, err := p.ensureState(ctx, request.DeploymentID, request.Operation, contracts.CapabilityRuntimeDeploy, "recreate"); err == nil {
		p.mu.Lock()
		if action, ok := state.actions[actionHash]; ok && action.action == "recreate" && action.fingerprint == state.fingerprint {
			if action.status == "succeeded" {
				deployment := state.deployment
				p.mu.Unlock()
				return deployment, nil
			}
			if state.phase == "active" && state.containerID != "" && state.containerID != action.previousContainerID {
				action.status, action.at = "succeeded", p.config.Clock().UTC()
				state.actions[actionHash], state.updatedAt = action, action.at
				persistErr := p.persistState(state)
				deployment := state.deployment
				p.mu.Unlock()
				if persistErr != nil {
					return domain.Deployment{}, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "persist_state", contracts.ErrUnavailable, "recreated runtime state could not be persisted", contracts.RetryBackoff, true, persistErr)
				}
				return deployment, nil
			}
		} else {
			now := p.config.Clock().UTC()
			state.actions[actionHash] = runtimeAction{identityHash: actionHash, action: "recreate", fingerprint: state.fingerprint, status: "started", previousContainerID: state.containerID, at: now}
			state.updatedAt = now
			if persistErr := p.persistState(state); persistErr != nil {
				p.mu.Unlock()
				return domain.Deployment{}, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "persist_state", contracts.ErrUnavailable, "pending recreate state could not be persisted", contracts.RetryBackoff, true, persistErr)
			}
		}
		destroyed := state.destroyed
		p.mu.Unlock()
		if !destroyed {
			destroy := contracts.DestroyRequest{DeploymentID: request.DeploymentID, Operation: request.Operation}
			destroy.Operation.IdempotencyKey += ":recreate-destroy"
			if err := p.destroyOperation(ctx, destroy); err != nil {
				return domain.Deployment{}, err
			}
		}
	} else if !isProviderCode(err, contracts.ErrNotFound) {
		return domain.Deployment{}, err
	}
	deploy := request
	deploy.Operation.IdempotencyKey += ":recreate-deploy"
	deployment, err := p.deployOperation(ctx, deploy)
	if err != nil {
		return domain.Deployment{}, err
	}
	p.mu.Lock()
	state := p.states[deployment.ID]
	if state == nil {
		p.mu.Unlock()
		return domain.Deployment{}, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "recreate", contracts.ErrUnavailable, "recreated runtime state is unavailable", contracts.RetryAfterReconnect, true, nil)
	}
	now := p.config.Clock().UTC()
	state.actions[actionHash] = runtimeAction{identityHash: actionHash, action: "recreate", fingerprint: state.fingerprint, status: "succeeded", at: now}
	state.updatedAt = now
	persistErr := p.persistState(state)
	p.mu.Unlock()
	if persistErr != nil {
		return domain.Deployment{}, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "persist_state", contracts.ErrUnavailable, "recreated runtime state could not be persisted", contracts.RetryBackoff, true, persistErr)
	}
	return deployment, nil
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
	var priorActions []durableRuntimeAction
	leaseGeneration := 0
	if snapshot, found, readErr := p.readDurableState(request.DeploymentID); readErr != nil {
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrUnavailable, "durable runtime state could not be read", contracts.RetryAfterReconnect, true, readErr)
	} else if found {
		if snapshot.Fingerprint != fingerprint {
			return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrConflict, "durable runtime state does not match the immutable deployment", contracts.RetryNever, false, nil)
		}
		if snapshot.Phase == "replacing" {
			return domain.Deployment{}, nil, p.replacementFailure(request.Operation, "deployment has an unfinished replacement task")
		}
		if snapshot.Phase == "active" {
			state, stateErr := p.stateFromDurable(ctx, snapshot, request.Operation, contracts.CapabilityRuntimeDeploy, "deploy")
			if stateErr != nil {
				return domain.Deployment{}, nil, stateErr
			}
			return state.deployment, state, nil
		}
		if snapshot.Phase == "pending" {
			state, stateErr := p.stateFromDurable(ctx, snapshot, request.Operation, contracts.CapabilityRuntimeDeploy, "deploy")
			if stateErr != nil {
				return domain.Deployment{}, nil, stateErr
			}
			if state.recovery == runtimeRecoveryPendingAbsent {
				leaseGeneration = state.leaseGeneration
			} else if state.recovery == runtimeRecoveryPendingNotRunning {
				return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrConflict, "pending runtime is present but not running", contracts.RetryNever, false, nil)
			} else {
				return state.deployment, state, nil
			}
			// A pending ledger with no provable live container is not adopted. The
			// new attempt overwrites it only after it obtains a fresh lease.
		}
		if snapshot.Phase == "destroyed" {
			priorActions = append(priorActions, snapshot.Actions...)
			for _, action := range snapshot.Actions {
				if action.IdentityHash == actionIdentity("deploy", request.Operation.IdempotencyKey) && action.Action == "deploy" {
					return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrConflict, "destroyed runtime rejects replay of its prior deploy operation", contracts.RetryNever, false, nil)
				}
			}
		}
	}
	container := p.config.TaskPrefix + "-runtime-" + hash(string(deployment.ID))[:20]
	if _, ok, recoverErr := p.recover(ctx, container, deployment, request); recoverErr != nil {
		return domain.Deployment{}, nil, recoverErr
	} else if ok {
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrConflict, "active runtime without a durable ledger cannot be adopted", contracts.RetryNever, false, nil)
	}
	now := p.config.Clock().UTC()
	pending := &runtimeState{deployment: deployment, service: request.Spec.ServiceName, image: request.Spec.Image, container: container, containerPort: request.Spec.Port, phase: "pending", fingerprint: fingerprint, createdAt: now, updatedAt: now, leaseGeneration: leaseGeneration, actions: make(map[string]runtimeAction), resources: request.Spec.Resources}
	if err := p.persistState(pending); err != nil {
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "persist_state", contracts.ErrUnavailable, "pending runtime generation could not be persisted", contracts.RetryBackoff, true, err)
	}
	capacityOperation := request.Operation
	capacityOperation.IdempotencyKey += ":runtime-capacity-reserve:" + strconv.Itoa(leaseGeneration)
	hostPorts := 0
	if request.Spec.Port != 0 {
		hostPorts = 1
	}
	capacity, err := p.config.Capacity.Reserve(ctx, contracts.CapacityRequest{Scope: contracts.CapacityRuntime, Resources: request.Spec.Resources, HostPorts: hostPorts, Operation: capacityOperation})
	if err != nil {
		return domain.Deployment{}, nil, err
	}
	pending.capacity = &capacity
	pending.port = capacity.HostPort
	pending.updatedAt = p.config.Clock().UTC()
	if err := p.persistState(pending); err != nil {
		persistErr := err
		releaseOperation := request.Operation
		releaseOperation.IdempotencyKey += ":runtime-capacity-release:" + strconv.Itoa(leaseGeneration)
		if releaseErr := p.config.Capacity.Release(context.Background(), capacity, releaseOperation); releaseErr != nil {
			return domain.Deployment{}, nil, fmt.Errorf("persist pending lease: %w; release lease: %v", persistErr, releaseErr)
		}
		pending.capacity = nil
		pending.leaseGeneration++
		pending.updatedAt = p.config.Clock().UTC()
		if cleanupErr := p.persistState(pending); cleanupErr != nil {
			return domain.Deployment{}, nil, fmt.Errorf("persist pending lease: %w; persist released lease cleanup: %v", persistErr, cleanupErr)
		}
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "persist_state", contracts.ErrUnavailable, "pending runtime lease could not be persisted", contracts.RetryBackoff, true, persistErr)
	}
	defer func() {
		if err != nil {
			cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
			cleanupErr := p.cleanupFailedDeployContainer(cleanupContext, pending, request.Spec, request.Operation)
			cleanupCancel()
			if cleanupErr != nil {
				err = fmt.Errorf("%w; failed runtime cleanup was not confirmed", err)
				return
			}
			releaseOperation := request.Operation
			releaseOperation.IdempotencyKey += ":runtime-capacity-release:" + strconv.Itoa(leaseGeneration)
			releaseErr := p.config.Capacity.Release(context.Background(), capacity, releaseOperation)
			if releaseErr == nil {
				pending.capacity = nil
				pending.leaseGeneration++
				pending.updatedAt = p.config.Clock().UTC()
				if persistErr := p.persistState(pending); persistErr != nil {
					err = fmt.Errorf("%w; persist cleanup: %v", err, persistErr)
				}
			} else {
				err = fmt.Errorf("%w; release cleanup: %v", err, releaseErr)
			}
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
	activateOperation.IdempotencyKey += ":runtime-capacity-activate:" + strconv.Itoa(leaseGeneration)
	if err = p.config.Capacity.Activate(ctx, capacity, activateOperation); err != nil {
		return domain.Deployment{}, nil, err
	}
	pending.port = port
	pending.capacity = &capacity
	pending.updatedAt = p.config.Clock().UTC()
	if err := p.persistState(pending); err != nil {
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "persist_state", contracts.ErrUnavailable, "pending runtime state could not be persisted", contracts.RetryBackoff, true, err)
	}
	if err := p.run(ctx, args); err != nil {
		return domain.Deployment{}, nil, p.commandError(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", err)
	}
	facts, inspectErr := p.inspectFacts(ctx, container)
	observedPort, matches := facts.matchesRunning(p.config, deployment, request.Spec)
	if inspectErr != nil || !matches || observedPort != port {
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "inspect", contracts.ErrConflict, "Docker runtime facts do not match the constrained deployment", contracts.RetryNever, false, inspectErr)
	}
	if err := deployment.Transition(domain.DeploymentRuntimeReady, p.config.Clock()); err != nil {
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrValidation, "deployment transition is invalid", contracts.RetryNever, false, err)
	}
	state = &runtimeState{deployment: deployment, service: request.Spec.ServiceName, image: request.Spec.Image, container: container, containerID: facts.ID, port: port, containerPort: request.Spec.Port, phase: "active", fingerprint: fingerprint, createdAt: now, updatedAt: p.config.Clock().UTC(), leaseGeneration: leaseGeneration, actions: make(map[string]runtimeAction), capacity: &capacity, resources: request.Spec.Resources}
	for _, action := range priorActions {
		state.actions[action.IdentityHash] = runtimeAction{identityHash: action.IdentityHash, action: action.Action, fingerprint: action.Fingerprint, status: action.Status, previousContainerID: action.PreviousContainerID, previousStartedAt: action.PreviousStartedAt, releaseAttempt: action.ReleaseAttempt, at: action.At}
	}
	deployAction := actionIdentity("deploy", request.Operation.IdempotencyKey)
	state.actions[deployAction] = runtimeAction{identityHash: deployAction, action: "deploy", fingerprint: fingerprint, status: "succeeded", at: now}
	if err := p.persistState(state); err != nil {
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "persist_state", contracts.ErrUnavailable, "durable runtime state could not be persisted", contracts.RetryBackoff, true, err)
	}
	return deployment, state, nil
}

func (p *Provider) recover(ctx context.Context, container string, deployment domain.Deployment, request contracts.DeployRequest) (*runtimeState, bool, error) {
	facts, err := p.inspectFacts(ctx, container)
	if err != nil {
		return nil, false, nil
	}
	port, valid := facts.matchesRunning(p.config, deployment, request.Spec)
	if !valid {
		return nil, true, p.failure(request.Operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrConflict, "existing task container does not match the immutable constrained deployment", contracts.RetryNever, false, nil)
	}
	if err := deployment.Transition(domain.DeploymentDeploying, p.config.Clock()); err != nil {
		return nil, true, err
	}
	if err := deployment.Transition(domain.DeploymentRuntimeReady, p.config.Clock()); err != nil {
		return nil, true, err
	}
	now := p.config.Clock().UTC()
	return &runtimeState{deployment: deployment, service: request.Spec.ServiceName, image: request.Spec.Image, container: container, containerID: facts.ID, port: port, containerPort: request.Spec.Port, phase: "active", fingerprint: p.fingerprint(deployment.ID, request.Spec), createdAt: now, updatedAt: now, actions: make(map[string]runtimeAction), resources: request.Spec.Resources}, true, nil
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
		return p.observation(state, "stopped", false, 0, 0, 0, contracts.ResourceLimits{}, false, "", request.Operation), nil
	}
	facts, err := p.inspectFacts(ctx, state.container)
	if err != nil {
		return contracts.RuntimeObservation{}, p.commandError(request.Operation, contracts.CapabilityRuntimeObserve, "observe", err)
	}
	port, valid := facts.matchesConfiguration(p.config, state.deployment, contracts.RuntimeSpec{ApplicationID: state.deployment.ApplicationID, EnvironmentID: state.deployment.EnvironmentID, ReleaseID: state.deployment.ReleaseID, ServiceName: state.service, Image: state.image, Resources: state.resources, Port: state.containerPort})
	if !valid || port != state.port {
		return contracts.RuntimeObservation{}, p.failure(request.Operation, contracts.CapabilityRuntimeObserve, "observe", contracts.ErrConflict, "Docker runtime readback does not match the constrained deployment", contracts.RetryNever, false, nil)
	}
	status := facts.State.Status
	if status == "" && facts.State.Running {
		status = "running"
	}
	return p.observation(state, status, facts.State.Running, facts.RestartCount, 0, 0, state.resources, true, facts.ID, request.Operation), nil
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
	args := dockerLogsArgs(request, state.container)
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

// ReadAcornFoxLogs is the bounded AcornFox-only log reader. Unlike the legacy
// RuntimeDriver.Logs method, it keeps stdout and stderr provenance and bounds
// all Docker process output before a buffer can grow beyond the public limit.
func (p *Provider) ReadAcornFoxLogs(ctx context.Context, request contracts.LogsRequest) (contracts.AcornFoxBoundedLogs, error) {
	if err := p.check(ctx, request.Operation, contracts.CapabilityRuntimeLogs, "logs"); err != nil {
		return contracts.AcornFoxBoundedLogs{}, err
	}
	state, err := p.state(request.DeploymentID, request.Operation, contracts.CapabilityRuntimeLogs, "logs")
	if err != nil {
		return contracts.AcornFoxBoundedLogs{}, err
	}
	if request.ServiceName != "" && request.ServiceName != state.service {
		return contracts.AcornFoxBoundedLogs{}, p.failure(request.Operation, contracts.CapabilityRuntimeLogs, "logs", contracts.ErrValidation, "runtime service does not match deployment", contracts.RetryNever, false, nil)
	}
	capture := newBoundedAcornFoxLogCapture(contracts.AcornFoxLogsMaxBytes)
	if err := p.config.Runner.Run(ctx, p.config.Command, dockerLogsArgs(request, state.container), capture.stdoutWriter(), capture.stderrWriter()); err != nil {
		return contracts.AcornFoxBoundedLogs{}, p.commandError(request.Operation, contracts.CapabilityRuntimeLogs, "logs", err)
	}
	return capture.result(), nil
}

func dockerLogsArgs(request contracts.LogsRequest, container string) []string {
	args := []string{"logs", "--timestamps"}
	if request.Tail > 0 {
		args = append(args, "--tail", fmt.Sprint(request.Tail))
	}
	if !request.Since.IsZero() {
		args = append(args, "--since", request.Since.UTC().Format(time.RFC3339))
	}
	return append(args, container)
}

// boundedAcornFoxLogCapture shares one byte allowance between Docker's stdout
// and stderr. Write intentionally reports success for discarded overflow: the
// command must never block or observe a short write merely because collection
// reached its public boundary.
type boundedAcornFoxLogCapture struct {
	mu            sync.Mutex
	remaining     int
	stdout        bytes.Buffer
	stderr        bytes.Buffer
	sourceLimited bool
}

type boundedAcornFoxLogWriter struct {
	capture *boundedAcornFoxLogCapture
	stream  string
}

func newBoundedAcornFoxLogCapture(limit int) *boundedAcornFoxLogCapture {
	return &boundedAcornFoxLogCapture{remaining: limit}
}

func (capture *boundedAcornFoxLogCapture) stdoutWriter() io.Writer {
	return boundedAcornFoxLogWriter{capture: capture, stream: contracts.AcornFoxLogStreamStdout}
}

func (capture *boundedAcornFoxLogCapture) stderrWriter() io.Writer {
	return boundedAcornFoxLogWriter{capture: capture, stream: contracts.AcornFoxLogStreamStderr}
}

func (writer boundedAcornFoxLogWriter) Write(data []byte) (int, error) {
	if writer.capture == nil || len(data) == 0 {
		return len(data), nil
	}
	writer.capture.mu.Lock()
	defer writer.capture.mu.Unlock()
	allowed := len(data)
	if allowed > writer.capture.remaining {
		allowed = writer.capture.remaining
		writer.capture.sourceLimited = true
	}
	if allowed > 0 {
		if writer.stream == contracts.AcornFoxLogStreamStderr {
			_, _ = writer.capture.stderr.Write(data[:allowed])
		} else {
			_, _ = writer.capture.stdout.Write(data[:allowed])
		}
		writer.capture.remaining -= allowed
	}
	if allowed < len(data) {
		writer.capture.sourceLimited = true
	}
	return len(data), nil
}

func (capture *boundedAcornFoxLogCapture) result() contracts.AcornFoxBoundedLogs {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	result := contracts.AcornFoxBoundedLogs{Records: make([]contracts.AcornFoxLogRecord, 0), SourceLimited: capture.sourceLimited}
	for _, stream := range []struct {
		name string
		data string
	}{
		{name: contracts.AcornFoxLogStreamStdout, data: capture.stdout.String()},
		{name: contracts.AcornFoxLogStreamStderr, data: capture.stderr.String()},
	} {
		if stream.data == "" {
			continue
		}
		for len(stream.data) > 0 {
			if len(result.Records) == contracts.AcornFoxLogsMaxRecords {
				result.SourceLimited = true
				return result
			}
			end := strings.IndexByte(stream.data, '\n')
			if end < 0 {
				result.Records = append(result.Records, contracts.AcornFoxLogRecord{Stream: stream.name, Data: stream.data})
				break
			}
			end++
			result.Records = append(result.Records, contracts.AcornFoxLogRecord{Stream: stream.name, Data: stream.data[:end]})
			stream.data = stream.data[end:]
		}
	}
	return result
}

func (p *Provider) Restart(ctx context.Context, request contracts.RestartRequest) error {
	unlock := p.lockDeployment(request.DeploymentID)
	defer unlock()
	if err := p.check(ctx, request.Operation, contracts.CapabilityRuntimeRestart, "restart"); err != nil {
		return err
	}
	if _, err := p.ensureState(ctx, request.DeploymentID, request.Operation, contracts.CapabilityRuntimeRestart, "restart"); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	state, err := p.stateLocked(request.DeploymentID, request.Operation, contracts.CapabilityRuntimeRestart, "restart")
	if err != nil {
		return err
	}
	if state.phase == "replacing" {
		return p.replacementFailure(request.Operation, "replacement must finish or be cancelled before restart")
	}
	if request.ServiceName != "" && request.ServiceName != state.service {
		return p.failure(request.Operation, contracts.CapabilityRuntimeRestart, "restart", contracts.ErrValidation, "runtime service does not match deployment", contracts.RetryNever, false, nil)
	}
	actionHash := actionIdentity("restart", request.Operation.IdempotencyKey)
	if action, done := state.actions[actionHash]; done && action.status == "succeeded" && action.action == "restart" && action.fingerprint == state.fingerprint {
		return nil
	}
	facts, inspectErr := p.inspectFacts(ctx, state.container)
	_, matches := facts.matchesConfiguration(p.config, state.deployment, contracts.RuntimeSpec{ApplicationID: state.deployment.ApplicationID, EnvironmentID: state.deployment.EnvironmentID, ReleaseID: state.deployment.ReleaseID, ServiceName: state.service, Image: state.image, Resources: state.resources, Port: state.containerPort})
	if inspectErr != nil || !matches {
		return p.failure(request.Operation, contracts.CapabilityRuntimeRestart, "restart", contracts.ErrConflict, "runtime facts do not match before restart", contracts.RetryNever, false, inspectErr)
	}
	if action, started := state.actions[actionHash]; started && action.action == "restart" && action.fingerprint == state.fingerprint && action.status == "started" && action.previousStartedAt != "" && facts.State.StartedAt != "" && facts.State.StartedAt != action.previousStartedAt {
		action.status, action.at = "succeeded", p.config.Clock().UTC()
		state.actions[actionHash], state.updatedAt = action, action.at
		if err := p.persistState(state); err != nil {
			return p.failure(request.Operation, contracts.CapabilityRuntimeRestart, "persist_state", contracts.ErrUnavailable, "recovered restart state could not be persisted", contracts.RetryBackoff, true, err)
		}
		return nil
	}
	if _, started := state.actions[actionHash]; !started {
		now := p.config.Clock().UTC()
		state.actions[actionHash] = runtimeAction{identityHash: actionHash, action: "restart", fingerprint: state.fingerprint, status: "started", previousContainerID: facts.ID, previousStartedAt: facts.State.StartedAt, at: now}
		state.updatedAt = now
		if err := p.persistState(state); err != nil {
			return p.failure(request.Operation, contracts.CapabilityRuntimeRestart, "persist_state", contracts.ErrUnavailable, "pending restart state could not be persisted", contracts.RetryBackoff, true, err)
		}
	}
	if err := p.run(ctx, []string{"restart", state.container}); err != nil {
		return p.commandError(request.Operation, contracts.CapabilityRuntimeRestart, "restart", err)
	}
	now := p.config.Clock().UTC()
	state.actions[actionHash] = runtimeAction{identityHash: actionHash, action: "restart", fingerprint: state.fingerprint, status: "succeeded", at: now}
	state.updatedAt = now
	if err := p.persistState(state); err != nil {
		return p.failure(request.Operation, contracts.CapabilityRuntimeRestart, "persist_state", contracts.ErrUnavailable, "restarted runtime state could not be persisted", contracts.RetryBackoff, true, err)
	}
	return nil
}

func (p *Provider) Scale(ctx context.Context, request contracts.ScaleRequest) error {
	return p.unsupported(ctx, request.Operation, contracts.CapabilityRuntimeScale, "scale")
}

func (p *Provider) Rollback(ctx context.Context, request contracts.RollbackRequest) (domain.Deployment, error) {
	return domain.Deployment{}, p.unsupported(ctx, request.Operation, contracts.CapabilityRuntimeRollback, "rollback")
}

func (p *Provider) Destroy(ctx context.Context, request contracts.DestroyRequest) error {
	unlock := p.lockDeployment(request.DeploymentID)
	defer unlock()
	return p.destroyOperation(ctx, request)
}

func (p *Provider) destroyOperation(ctx context.Context, request contracts.DestroyRequest) error {
	if err := p.check(ctx, request.Operation, contracts.CapabilityRuntimeDestroy, "destroy"); err != nil {
		return err
	}
	if _, err := p.ensureState(ctx, request.DeploymentID, request.Operation, contracts.CapabilityRuntimeDestroy, "destroy"); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	state, err := p.stateLocked(request.DeploymentID, request.Operation, contracts.CapabilityRuntimeDestroy, "destroy")
	if err != nil {
		return err
	}
	if state.phase == "replacing" {
		if err := p.cancelReplacement(ctx, state, request); err != nil {
			return err
		}
	}
	actionHash := actionIdentity("destroy", request.Operation.IdempotencyKey)
	if action, ok := state.actions[actionHash]; ok && action.action == "destroy" && action.fingerprint == state.fingerprint && action.status == "succeeded" && state.destroyed && state.capacity == nil {
		return nil
	}
	if !state.destroyed {
		now := p.config.Clock().UTC()
		state.actions[actionHash] = runtimeAction{identityHash: actionHash, action: "destroy", fingerprint: state.fingerprint, status: "started", previousContainerID: state.containerID, at: now}
		state.phase, state.updatedAt = "destroying", now
		if err := p.persistState(state); err != nil {
			return p.failure(request.Operation, contracts.CapabilityRuntimeDestroy, "persist_state", contracts.ErrUnavailable, "pending destroy state could not be persisted", contracts.RetryBackoff, true, err)
		}
		if err := p.run(ctx, []string{"rm", "--force", state.container}); err != nil {
			return p.commandError(request.Operation, contracts.CapabilityRuntimeDestroy, "destroy", err)
		}
		state.destroyed = true
		state.phase, state.updatedAt = "destroyed", p.config.Clock().UTC()
		state.port = 0
		if err := p.persistState(state); err != nil {
			return p.failure(request.Operation, contracts.CapabilityRuntimeDestroy, "persist_state", contracts.ErrUnavailable, "removed runtime state could not be persisted", contracts.RetryBackoff, true, err)
		}
	}
	if state.capacity != nil {
		action := state.actions[actionHash]
		action.releaseAttempt++
		state.actions[actionHash] = action
		state.updatedAt = p.config.Clock().UTC()
		if err := p.persistState(state); err != nil {
			return p.failure(request.Operation, contracts.CapabilityRuntimeDestroy, "persist_state", contracts.ErrUnavailable, "pending capacity release state could not be persisted", contracts.RetryBackoff, true, err)
		}
		releaseOperation := request.Operation
		releaseOperation.IdempotencyKey += ":destroy-release:" + strconv.Itoa(action.releaseAttempt)
		if err := p.config.Capacity.Release(ctx, *state.capacity, releaseOperation); err != nil {
			return err
		}
		state.capacity = nil
	}
	action := state.actions[actionHash]
	action.status, action.at = "succeeded", p.config.Clock().UTC()
	state.actions[actionHash] = action
	state.updatedAt = action.at
	if err := p.persistState(state); err != nil {
		return p.failure(request.Operation, contracts.CapabilityRuntimeDestroy, "persist_state", contracts.ErrUnavailable, "destroyed runtime state could not be persisted", contracts.RetryBackoff, true, err)
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
	if p.config.ExistingNetworkValidator != nil {
		raw, err := p.output(ctx, []string{"network", "inspect", p.config.Network})
		if err != nil || p.config.ExistingNetworkValidator([]byte(raw)) != nil {
			return p.failure(operation, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrConflict, "required runtime network is unavailable or changed", contracts.RetryUserAction, false, nil)
		}
		return nil
	}
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
		"--label", "open-card.application-id=" + string(deployment.ApplicationID),
		"--label", "open-card.environment-id=" + string(deployment.EnvironmentID),
		"--label", "open-card.release-id=" + string(deployment.ReleaseID),
		"--label", "open-card.service=" + spec.ServiceName,
		"--label", "open-card.image-repository=" + spec.Image.Repository,
		"--label", "open-card.image-digest=" + spec.Image.Digest,
	}
	if port != 0 {
		args = append(args, "--publish", fmt.Sprintf("127.0.0.1:%d:%d/tcp", port, spec.Port))
	}
	for _, resolver := range p.config.DNS {
		args = append(args, "--dns", resolver)
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
	state, err := p.ensureState(context.Background(), id, operation, capability, action)
	if err != nil {
		return runtimeState{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return *state, nil
}

func (p *Provider) ensureState(ctx context.Context, id domain.ID, operation contracts.OperationContext, capability contracts.Capability, action string) (*runtimeState, error) {
	if id.Empty() {
		return nil, p.failure(operation, capability, action, contracts.ErrInvalidArgument, "deployment id is required", contracts.RetryNever, false, nil)
	}
	p.mu.Lock()
	if state := p.states[id]; state != nil {
		p.mu.Unlock()
		return state, nil
	}
	p.mu.Unlock()
	snapshot, found, err := p.readDurableState(id)
	if err != nil {
		return nil, p.failure(operation, capability, action, contracts.ErrUnavailable, "durable runtime state could not be read", contracts.RetryAfterReconnect, true, err)
	}
	if !found {
		return nil, p.failure(operation, capability, action, contracts.ErrNotFound, "managed deployment was not found", contracts.RetryUserAction, false, nil)
	}
	loaded, err := p.stateFromDurable(ctx, snapshot, operation, capability, action)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	if existing := p.states[id]; existing != nil {
		p.mu.Unlock()
		return existing, nil
	}
	p.states[id] = loaded
	p.mu.Unlock()
	return loaded, nil
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

func (p *Provider) observation(state runtimeState, status string, healthy bool, restarts uint64, cpu, memory int64, observed contracts.ResourceLimits, cgroupVerified bool, containerID string, operation contracts.OperationContext) contracts.RuntimeObservation {
	return contracts.RuntimeObservation{DeploymentID: state.deployment.ID, ServiceName: state.service, ContainerID: containerID, Status: status, Healthy: healthy, RestartCount: restarts, CPUUsageMillis: cpu, MemoryBytes: memory, HostPort: state.port, Limits: observed, CgroupVerified: cgroupVerified, ObservedAt: p.config.Clock().UTC(), Evidence: p.evidence(operation, "runtime.observe")}
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

func isProviderCode(err error, code contracts.ErrorCode) bool {
	var providerErr *contracts.ProviderError
	return errors.As(err, &providerErr) && providerErr.Code == code
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
func hasAction(state *runtimeState, key string) bool {
	action, ok := state.actions[key]
	return ok && action.status == "succeeded"
}

func actionIdentity(action, providerOperationKey string) string {
	return hash(action + "\x00" + providerOperationKey)
}
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

func parseRuntimeReadback(output string, state runtimeState) (string, bool, uint64, contracts.ResourceLimits, string, error) {
	parts := strings.SplitN(strings.TrimSpace(output), "|", 9)
	if len(parts) != 9 {
		return "", false, 0, contracts.ResourceLimits{}, "", errors.New("invalid runtime inspect result")
	}
	status, healthy, restarts, err := parseState(parts[0] + "|" + parts[1])
	if err != nil {
		return "", false, 0, contracts.ResourceLimits{}, "", err
	}
	memory, memoryErr := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	memorySwap, memorySwapErr := strconv.ParseInt(strings.TrimSpace(parts[3]), 10, 64)
	cpuPeriod, cpuPeriodErr := strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64)
	cpuQuota, cpuQuotaErr := strconv.ParseInt(strings.TrimSpace(parts[5]), 10, 64)
	pids, pidsErr := strconv.ParseInt(strings.TrimSpace(parts[6]), 10, 64)
	containerID := strings.TrimSpace(parts[7])
	if memoryErr != nil || memorySwapErr != nil || cpuPeriodErr != nil || cpuQuotaErr != nil || pidsErr != nil || !validContainerID(containerID) || memory != state.resources.MemoryBytes || memorySwap != state.resources.MemoryBytes || cpuPeriod != 100000 || cpuQuota != state.resources.CPUMillis*100 || pids != state.resources.PIDs {
		return "", false, 0, contracts.ResourceLimits{}, "", errors.New("runtime limits do not match")
	}
	var bindings map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}
	if err := json.Unmarshal([]byte(parts[8]), &bindings); err != nil {
		return "", false, 0, contracts.ResourceLimits{}, "", err
	}
	if state.port == 0 {
		if len(bindings) != 0 {
			return "", false, 0, contracts.ResourceLimits{}, "", errors.New("unexpected host port")
		}
	} else {
		binding := bindings[fmt.Sprintf("%d/tcp", state.containerPort)]
		if len(bindings) != 1 || len(binding) != 1 || binding[0].HostIP != "127.0.0.1" || binding[0].HostPort != strconv.Itoa(state.port) {
			return "", false, 0, contracts.ResourceLimits{}, "", errors.New("loopback host port is absent")
		}
	}
	return status, healthy, restarts, state.resources, containerID, nil
}

func validContainerID(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
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
