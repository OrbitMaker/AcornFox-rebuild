// Package standalonegroup implements the task-scoped multi-service Docker
// runtime used by M2.  It is intentionally a small, fail-closed driver:
// images are loaded by digest, containers are created only on one private
// network, and the only Docker execution boundary is the injected Runner.
//
// The package does not accept shell fragments, host paths, devices, Docker
// sockets, privileged containers, or mutable image tags.  Controllers still
// own the durable Release/Deployment state; this package reports runtime
// facts and performs idempotent effects for one complete group Release.
package standalonegroup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const (
	providerName    = "standalone-group-docker"
	providerVersion = "m2"
	defaultTimeout  = 2 * time.Minute
	defaultMaxOCI   = int64(4 << 30)
)

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// Runner is the only Docker execution boundary.  The production Agent can
// supply a constrained command proxy; tests use a recorder/fake and therefore
// never need a Docker daemon.
type Runner interface {
	Run(context.Context, string, []string, io.Writer, io.Writer) error
}

// CommandRunner is a descriptive compatibility alias used by composition
// roots that already call their Docker dependency a command runner.
type CommandRunner = Runner

type execRunner struct{}

func (execRunner) Run(ctx context.Context, command string, args []string, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return cmd.Run()
}

// ImageLoader is deliberately the narrow immutable-image part of ImageStore.
// The concrete image.Provider and contracts.ImageStore both satisfy it.  The
// driver never resolves tags and never passes a tag to Docker.
type ImageLoader interface {
	OpenOCI(context.Context, domain.ImageDigest, contracts.OperationContext) (io.ReadCloser, contracts.StoreOCIResult, error)
}

// RuntimeMetrics is the independent, read-only Docker facts accepted by the
// ServiceGroup driver after it has already derived and validated a task-owned
// container name. The interface deliberately omits socket paths, raw inspect
// JSON, commands, mounts, environment values, and changed paths.
type RuntimeMetrics struct {
	ContainerID    string
	Status         string
	Healthy        bool
	RestartCount   uint64
	CPUMillicores  int64
	MemoryBytes    int64
	DiskBytes      int64
	NetworkRxBytes int64
	NetworkTxBytes int64
	PIDsCurrent    int64
	ChangedPaths   int64
	CgroupVerified bool
	Limits         contracts.ResourceLimits
	ExitReason     string
	ObservedAt     time.Time
}

type RuntimeMetricsReader interface {
	ReadGroupRuntimeMetrics(context.Context, string) (RuntimeMetrics, error)
}

// Config contains provider-owned boundaries.  Every Docker object created by
// the provider is derived from TaskPrefix.  WorkRoot is only used for a
// short-lived OCI staging file and is never exposed to a container.
type Config struct {
	Command    string
	TaskPrefix string
	Network    string
	WorkRoot   string
	ImageStore ImageLoader
	// ImageLoader is a readable alias for composition roots that name the
	// dependency by its narrower runtime role.
	ImageLoader ImageLoader
	Capacity    contracts.CapacityProvider
	Volumes     contracts.VolumeProvider
	// VolumeProvider is an explicit alias for Volumes.
	VolumeProvider contracts.VolumeProvider
	MetricsReader  RuntimeMetricsReader
	Runner         Runner
	// Docker is an explicit alias for Runner.
	Docker                Runner
	Timeout               time.Duration
	MaxOCIBytes           int64
	Clock                 func() time.Time
	WorkerNetworkIsolated bool
}

func (c Config) normalized() (Config, error) {
	if strings.TrimSpace(c.Command) == "" {
		c.Command = "docker"
	}
	c.TaskPrefix = strings.TrimSpace(c.TaskPrefix)
	if !safeName.MatchString(c.TaskPrefix) {
		return Config{}, errors.New("standalone group task prefix must be a safe non-empty name")
	}
	if strings.TrimSpace(c.Network) == "" {
		c.Network = c.TaskPrefix + "-network"
	}
	c.Network = strings.TrimSpace(c.Network)
	if !safeName.MatchString(c.Network) || !strings.HasPrefix(c.Network, c.TaskPrefix+"-") {
		return Config{}, errors.New("standalone group network must be task-prefixed")
	}
	if c.ImageStore == nil {
		c.ImageStore = c.ImageLoader
	}
	if c.Capacity == nil {
		return Config{}, errors.New("standalone group capacity provider is required")
	}
	if c.Volumes == nil {
		c.Volumes = c.VolumeProvider
	}
	if c.Volumes == nil {
		return Config{}, errors.New("standalone group volume provider is required")
	}
	if strings.TrimSpace(c.WorkRoot) != "" {
		root, err := filepath.Abs(c.WorkRoot)
		if err != nil {
			return Config{}, fmt.Errorf("standalone group work root: %w", err)
		}
		info, err := os.Stat(root)
		if err != nil {
			return Config{}, fmt.Errorf("standalone group work root: %w", err)
		}
		if !info.IsDir() {
			return Config{}, errors.New("standalone group work root is not a directory")
		}
		c.WorkRoot = filepath.Clean(root)
	}
	if c.ImageStore != nil && c.WorkRoot == "" {
		return Config{}, errors.New("standalone group work root is required when OCI loading is enabled")
	}
	if c.Runner == nil {
		c.Runner = c.Docker
	}
	if c.Runner == nil {
		c.Runner = execRunner{}
	}
	if c.Timeout == 0 {
		c.Timeout = defaultTimeout
	}
	if c.Timeout <= 0 {
		return Config{}, errors.New("standalone group timeout must be positive")
	}
	if c.MaxOCIBytes == 0 {
		c.MaxOCIBytes = defaultMaxOCI
	}
	if c.MaxOCIBytes <= 0 {
		return Config{}, errors.New("standalone group OCI archive limit must be positive")
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	return c, nil
}

type operationRecord struct {
	fingerprint string
	done        chan struct{}
	deployment  domain.Deployment
	err         error
}

type serviceState struct {
	spec                contracts.ServiceRuntimeSpec
	container           string
	port                int
	status              string
	healthy             bool
	completed           bool
	failed              error
	ownerDeploymentID   domain.ID
	ownerServiceGroupID domain.ID
	specDigest          string
	reused              bool
	networkAttached     bool
}

type groupState struct {
	mu             sync.Mutex
	deployment     domain.Deployment
	spec           contracts.ServiceGroupRuntimeSpec
	fingerprint    string
	network        string
	ingressNetwork string
	createdIngress bool
	order          []string
	services       map[string]*serviceState
	imageRefs      map[string]string
	volumes        map[string]contracts.VolumeSpec
	capacity       *contracts.CapacityLease
	destroyed      bool
	rolledBack     bool
}

const durableGroupStateSchema = "2"

// durableServiceState contains only the data needed to re-adopt a Docker
// object.  Failure values and runtime logs are deliberately excluded.  The
// persisted spec redacts literal environment values before encoding.
type durableServiceState struct {
	Name                string                   `json:"name"`
	Container           string                   `json:"container"`
	Port                int                      `json:"port,omitempty"`
	Status              string                   `json:"status,omitempty"`
	Healthy             bool                     `json:"healthy"`
	Completed           bool                     `json:"completed"`
	OwnerDeploymentID   domain.ID                `json:"owner_deployment_id"`
	OwnerServiceGroupID domain.ID                `json:"owner_service_group_id"`
	Reused              bool                     `json:"reused,omitempty"`
	NetworkAttached     bool                     `json:"network_attached"`
	Limits              contracts.ResourceLimits `json:"limits"`
	SpecDigest          string                   `json:"spec_digest"`
}

type durableGroupState struct {
	SchemaVersion  string                            `json:"schema_version"`
	Deployment     domain.Deployment                 `json:"deployment"`
	Spec           contracts.ServiceGroupRuntimeSpec `json:"spec"`
	Fingerprint    string                            `json:"fingerprint"`
	Network        string                            `json:"network"`
	IngressNetwork string                            `json:"ingress_network,omitempty"`
	Order          []string                          `json:"order"`
	Services       []durableServiceState             `json:"services"`
	ImageRefs      map[string]string                 `json:"image_refs,omitempty"`
	Volumes        map[string]contracts.VolumeSpec   `json:"volumes,omitempty"`
	RolledBack     bool                              `json:"rolled_back,omitempty"`
}

// ServiceFacts is the redacted runtime fact for one service.  It is useful to
// integrations that need the complete group snapshot without exposing raw
// Docker inspect JSON or logs in the control plane.
type ServiceFacts struct {
	Name      string                   `json:"name"`
	Container string                   `json:"container"`
	Status    string                   `json:"status"`
	Healthy   bool                     `json:"healthy"`
	Completed bool                     `json:"completed"`
	Required  bool                     `json:"required"`
	HostPort  int                      `json:"host_port,omitempty"`
	Limits    contracts.ResourceLimits `json:"limits"`
	Image     domain.ImageDigest       `json:"image"`
	Failure   string                   `json:"failure,omitempty"`
}

// GroupFacts is a redacted, complete read-back of the task-scoped objects
// owned by this provider.
type GroupFacts struct {
	Deployment domain.Deployment        `json:"deployment"`
	Network    string                   `json:"network"`
	Services   []ServiceFacts           `json:"services"`
	Volumes    []contracts.VolumeSpec   `json:"volumes,omitempty"`
	Capacity   contracts.ResourceLimits `json:"capacity"`
	Evidence   contracts.Evidence       `json:"evidence"`
}

// Provider is an idempotent multi-container runtime driver.  The state map is
// only a process cache; DeployGroup also adopts a complete, matching Docker
// group after a process restart by inspecting deterministic container names.
type Provider struct {
	config   Config
	metadata contracts.ProviderMetadata

	mu     sync.Mutex
	groups map[domain.ID]*groupState
	ops    map[string]*operationRecord
	// deploying serializes different idempotency keys targeting the same
	// immutable Deployment identity.  Without this guard two callers could
	// both miss the in-memory state and race into the same deterministic Docker
	// container names.
	deploying map[domain.ID]*operationRecord
	netsMu    sync.Mutex
}

// StandaloneDriver is the product-facing name for the M2 implementation.
// Keep Provider as the concrete constructor return type for consistency with
// the other local providers.
type StandaloneDriver = Provider

var _ contracts.ServiceGroupRuntimeDriver = (*Provider)(nil)
var _ contracts.ServiceGroupServiceRestarter = (*Provider)(nil)
var _ contracts.ServiceGroupLogReader = (*Provider)(nil)

// New constructs a fail-closed provider without contacting Docker.
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
				contracts.CapabilityRuntimeDeployGroup,
				contracts.CapabilityRuntimeObserveGroup,
				contracts.CapabilityRuntimeLogsGroup,
				contracts.CapabilityRuntimeRollbackGroup,
				contracts.CapabilityRuntimeDestroyGroup,
				contracts.CapabilityRuntimeRestartGroupService,
				contracts.CapabilityRuntimeRestartGroup,
			),
			SensitiveInputs: []string{"OCI archive", "runtime logs", "runtime environment"},
		},
		groups: make(map[domain.ID]*groupState),
		ops:    make(map[string]*operationRecord), deploying: make(map[domain.ID]*operationRecord),
	}, nil
}

// NewProvider is an explicit composition-root alias.
func NewProvider(config Config) (*Provider, error) { return New(config) }

func (p *Provider) Metadata(context.Context) contracts.ProviderMetadata { return p.metadata }

// RequiredCapabilities exposes the capability-gated Agent contract.  A
// caller must negotiate all returned capabilities before dispatching a group;
// there is intentionally no single-container fallback.
func (p *Provider) RequiredCapabilities() contracts.CapabilitySet {
	return contracts.NewCapabilitySet(contracts.CapabilityRuntimeDeployGroup, contracts.CapabilityRuntimeObserveGroup, contracts.CapabilityRuntimeLogsGroup, contracts.CapabilityRuntimeRollbackGroup, contracts.CapabilityRuntimeDestroyGroup, contracts.CapabilityRuntimeRestartGroupService, contracts.CapabilityRuntimeRestartGroup)
}

func (p *Provider) durableStatePath(deploymentID domain.ID) string {
	if strings.TrimSpace(p.config.WorkRoot) == "" || deploymentID.Empty() {
		return ""
	}
	return filepath.Join(p.config.WorkRoot, ".standalone-group-state-"+shortHash(string(deploymentID))+".json")
}

func redactRuntimeSpec(spec contracts.ServiceGroupRuntimeSpec) contracts.ServiceGroupRuntimeSpec {
	copySpec := canonicalSpec(spec)
	for serviceIndex := range copySpec.Services {
		// Commands and entrypoints are immutable execution inputs but are not
		// needed for Observe/Destroy recovery.  Omitting them prevents a command
		// line canary from becoming a plaintext durable secret.
		copySpec.Services[serviceIndex].Command = nil
		copySpec.Services[serviceIndex].Entrypoint = nil
		for envIndex := range copySpec.Services[serviceIndex].Environment {
			env := &copySpec.Services[serviceIndex].Environment[envIndex]
			if env.Kind == contracts.RuntimeEnvironmentLiteral {
				env.Value = ""
			}
		}
	}
	return copySpec
}

func (p *Provider) durableSnapshot(state *groupState) durableGroupState {
	state.mu.Lock()
	defer state.mu.Unlock()
	snapshot := durableGroupState{
		SchemaVersion:  durableGroupStateSchema,
		Deployment:     state.deployment,
		Spec:           redactRuntimeSpec(state.spec),
		Fingerprint:    state.fingerprint,
		Network:        state.network,
		IngressNetwork: state.ingressNetwork,
		Order:          append([]string(nil), state.order...),
		ImageRefs:      cloneStringMap(state.imageRefs),
		Volumes:        cloneVolumeMap(state.volumes),
		RolledBack:     state.rolledBack,
	}
	for name, service := range state.services {
		snapshot.Services = append(snapshot.Services, durableServiceState{
			Name:                name,
			Container:           service.container,
			Port:                service.port,
			Status:              service.status,
			Healthy:             service.healthy,
			Completed:           service.completed,
			OwnerDeploymentID:   service.ownerDeploymentID,
			OwnerServiceGroupID: service.ownerServiceGroupID,
			Reused:              service.reused,
			NetworkAttached:     service.networkAttached,
			Limits:              service.spec.Resources,
			SpecDigest:          serviceSpecDigest(service.spec),
		})
	}
	sort.Slice(snapshot.Services, func(i, j int) bool { return snapshot.Services[i].Name < snapshot.Services[j].Name })
	return snapshot
}

func (p *Provider) persistState(state *groupState) error {
	path := p.durableStatePath(state.deployment.ID)
	if path == "" {
		return nil
	}
	snapshot := p.durableSnapshot(state)
	if err := validateDurableState(snapshot, p.config.TaskPrefix); err != nil {
		return err
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode standalone group state: %w", err)
	}
	temporary, err := os.CreateTemp(p.config.WorkRoot, ".standalone-group-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create standalone group state temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure standalone group state temporary file: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write standalone group state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync standalone group state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close standalone group state: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish standalone group state: %w", err)
	}
	keep = true
	if directory, err := os.Open(p.config.WorkRoot); err == nil {
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil {
			return fmt.Errorf("sync standalone group state directory: %w", syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close standalone group state directory: %w", closeErr)
		}
	} else {
		return fmt.Errorf("open standalone group state directory: %w", err)
	}
	return nil
}

func (p *Provider) removeDurableState(deploymentID domain.ID) error {
	path := p.durableStatePath(deploymentID)
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove standalone group state: %w", err)
	}
	if directory, err := os.Open(p.config.WorkRoot); err == nil {
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil {
			return fmt.Errorf("sync standalone group state directory after removal: %w", syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close standalone group state directory after removal: %w", closeErr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("open standalone group state directory after removal: %w", err)
	}
	return nil
}

func (p *Provider) readDurableState(deploymentID domain.ID) (durableGroupState, bool, error) {
	path := p.durableStatePath(deploymentID)
	if path == "" {
		return durableGroupState{}, false, nil
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return durableGroupState{}, false, nil
	}
	if err != nil {
		return durableGroupState{}, false, fmt.Errorf("stat standalone group state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return durableGroupState{}, false, errors.New("standalone group state permissions or file type are unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return durableGroupState{}, false, fmt.Errorf("open standalone group state: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var snapshot durableGroupState
	if err := decoder.Decode(&snapshot); err != nil {
		return durableGroupState{}, false, fmt.Errorf("decode standalone group state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return durableGroupState{}, false, errors.New("standalone group state contains trailing data")
	}
	if err := validateDurableState(snapshot, p.config.TaskPrefix); err != nil {
		return durableGroupState{}, false, err
	}
	if snapshot.Deployment.ID != deploymentID {
		return durableGroupState{}, false, errors.New("standalone group state deployment identity does not match filename")
	}
	return snapshot, true, nil
}

func validateDurableState(snapshot durableGroupState, taskPrefix string) error {
	if snapshot.SchemaVersion != durableGroupStateSchema {
		return errors.New("standalone group state schema is unsupported")
	}
	if err := snapshot.Deployment.Validate(); err != nil {
		return fmt.Errorf("standalone group state deployment: %w", err)
	}
	if err := snapshot.Spec.Validate(); err != nil {
		return fmt.Errorf("standalone group state spec: %w", err)
	}
	if err := validateRuntimeNames(snapshot.Spec); err != nil {
		return err
	}
	if strings.TrimSpace(snapshot.Fingerprint) == "" || !safeName.MatchString(taskPrefix) || !strings.HasPrefix(snapshot.Network, taskPrefix+"-") || !safeName.MatchString(snapshot.Network) {
		return errors.New("standalone group state ownership is invalid")
	}
	if snapshot.IngressNetwork != "" && (!strings.HasPrefix(snapshot.IngressNetwork, taskPrefix+"-") || !safeName.MatchString(snapshot.IngressNetwork)) {
		return errors.New("standalone group ingress network ownership is invalid")
	}
	order, err := snapshot.Spec.DependencyOrder()
	if err != nil || !equalStrings(order, snapshot.Order) {
		return errors.New("standalone group state dependency order is invalid")
	}
	services := make(map[string]contracts.ServiceRuntimeSpec, len(snapshot.Spec.Services))
	for _, service := range snapshot.Spec.Services {
		services[service.Name] = service
	}
	seen := make(map[string]struct{}, len(snapshot.Services))
	for _, service := range snapshot.Services {
		if _, exists := services[service.Name]; !exists {
			return errors.New("standalone group state contains an unknown service")
		}
		if _, duplicate := seen[service.Name]; duplicate || service.OwnerDeploymentID.Empty() || service.OwnerServiceGroupID.Empty() || !safeName.MatchString(service.Container) {
			return errors.New("standalone group state service mapping is invalid")
		}
		if strings.TrimSpace(service.SpecDigest) == "" {
			return errors.New("standalone group state service spec digest is missing")
		}
		seen[service.Name] = struct{}{}
		if service.Limits != services[service.Name].Resources {
			return errors.New("standalone group state service limits do not match spec")
		}
	}
	if len(seen) != len(services) {
		return errors.New("standalone group state service mapping is incomplete")
	}
	for name, ref := range snapshot.ImageRefs {
		service, exists := services[name]
		if !exists || (ref != imageReference(service.Image) && ref != service.Image.Digest) {
			return errors.New("standalone group state image reference is not digest-bound")
		}
	}
	for name, volume := range snapshot.Volumes {
		if strings.TrimSpace(name) == "" || !safeName.MatchString(volume.Name) || strings.Contains(volume.Name, "..") || volume.SizeBytes <= 0 {
			return errors.New("standalone group state volume reference is invalid")
		}
	}
	return nil
}

func (p *Provider) stateFromDurable(ctx context.Context, snapshot durableGroupState, operation contracts.OperationContext, capability contracts.Capability, action string) (*groupState, error) {
	if err := p.verifyNetwork(ctx, snapshot.Network, operation, capability, action); err != nil {
		return nil, err
	}
	if snapshot.IngressNetwork != "" {
		if err := p.verifyNetwork(ctx, snapshot.IngressNetwork, operation, capability, action); err != nil {
			return nil, err
		}
	}
	serviceSpecs := make(map[string]contracts.ServiceRuntimeSpec, len(snapshot.Spec.Services))
	for _, service := range snapshot.Spec.Services {
		serviceSpecs[service.Name] = service
	}
	state := &groupState{deployment: snapshot.Deployment, spec: snapshot.Spec, fingerprint: snapshot.Fingerprint, network: snapshot.Network, ingressNetwork: snapshot.IngressNetwork, order: append([]string(nil), snapshot.Order...), services: make(map[string]*serviceState), imageRefs: cloneStringMap(snapshot.ImageRefs), volumes: cloneVolumeMap(snapshot.Volumes), rolledBack: snapshot.RolledBack}
	for _, persisted := range snapshot.Services {
		service := serviceSpecs[persisted.Name]
		if (persisted.Status == "failed" || persisted.Status == "skipped") && !service.Required {
			state.services[persisted.Name] = &serviceState{spec: service, container: persisted.Container, status: persisted.Status, healthy: false, completed: false, ownerDeploymentID: persisted.OwnerDeploymentID, ownerServiceGroupID: persisted.OwnerServiceGroupID, specDigest: persisted.SpecDigest, reused: persisted.Reused, networkAttached: persisted.NetworkAttached, failed: errors.New("optional service previously failed")}
			continue
		}
		facts, err := p.inspectContainer(ctx, persisted.Container)
		if err != nil {
			return nil, p.failure(operation, capability, action, contracts.ErrUnavailable, "durable group container could not be inspected", contracts.RetryAfterReconnect, true, nil)
		}
		if !facts.matchesOwner(p.config.TaskPrefix, snapshot.Deployment.ID, persisted.OwnerDeploymentID, persisted.OwnerServiceGroupID, service, snapshot.Network) {
			return nil, p.failure(operation, capability, action, contracts.ErrConflict, "durable group container facts do not match the persisted immutable mapping", contracts.RetryNever, false, nil)
		}
		healthy := facts.healthy(service)
		if isExecHealthcheck(service) && facts.State.Running {
			healthy = p.run(ctx, append([]string{"exec", persisted.Container}, service.Healthcheck.Test[1:]...)) == nil
		}
		state.services[persisted.Name] = &serviceState{spec: service, container: persisted.Container, port: facts.hostPort(service), status: facts.status(), healthy: healthy, completed: facts.completed(service), ownerDeploymentID: persisted.OwnerDeploymentID, ownerServiceGroupID: persisted.OwnerServiceGroupID, specDigest: persisted.SpecDigest, reused: persisted.Reused, networkAttached: persisted.NetworkAttached}
	}
	return state, nil
}

func (p *Provider) verifyNetwork(ctx context.Context, network string, operation contracts.OperationContext, capability contracts.Capability, action string) error {
	out, err := p.output(ctx, []string{"network", "inspect", "--format", "{{index .Labels \"open-card.managed\"}}|{{index .Labels \"open-card.task-prefix\"}}", network})
	if err != nil {
		return p.failure(operation, capability, action, contracts.ErrUnavailable, "durable group network could not be inspected", contracts.RetryAfterReconnect, true, nil)
	}
	if strings.TrimSpace(out) != "true|"+p.config.TaskPrefix {
		return p.failure(operation, capability, action, contracts.ErrConflict, "durable group network is not owned by this provider", contracts.RetryNever, false, nil)
	}
	return nil
}

func cloneStringMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func cloneVolumeMap(input map[string]contracts.VolumeSpec) map[string]contracts.VolumeSpec {
	if input == nil {
		return nil
	}
	output := make(map[string]contracts.VolumeSpec, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (p *Provider) DeployGroup(ctx context.Context, request contracts.DeployGroupRequest) (domain.Deployment, error) {
	if err := p.check(ctx, request.Operation, contracts.CapabilityRuntimeDeployGroup, "deploy_group"); err != nil {
		return domain.Deployment{}, err
	}
	if err := request.Spec.Validate(); err != nil {
		return domain.Deployment{}, p.failure(request.Operation, contracts.CapabilityRuntimeDeployGroup, "deploy_group", contracts.ErrValidation, "runtime service group is invalid", contracts.RetryNever, false, err)
	}
	if err := validateRuntimeNames(request.Spec); err != nil {
		return domain.Deployment{}, p.failure(request.Operation, contracts.CapabilityRuntimeDeployGroup, "deploy_group", contracts.ErrValidation, "runtime service group contains an unsafe Docker name", contracts.RetryNever, false, err)
	}
	if request.DeploymentID.Empty() {
		return domain.Deployment{}, p.failure(request.Operation, contracts.CapabilityRuntimeDeployGroup, "deploy_group", contracts.ErrInvalidArgument, "deployment id is required", contracts.RetryNever, false, nil)
	}
	fingerprint := p.fingerprint(request.DeploymentID, request.Spec)
	if deployment, ok, err := p.lookupDeployment(request.DeploymentID, fingerprint); err != nil {
		return domain.Deployment{}, err
	} else if ok {
		return deployment, nil
	}
	previous, wait, err := p.beginOperation(request.Operation.IdempotencyKey, fingerprint)
	if err != nil {
		return domain.Deployment{}, p.failure(request.Operation, contracts.CapabilityRuntimeDeployGroup, "deploy_group", contracts.ErrConflict, err.Error(), contracts.RetryNever, false, nil)
	}
	if wait {
		select {
		case <-previous.done:
			return previous.deployment, previous.err
		case <-ctx.Done():
			err := p.contextError(request.Operation, contracts.CapabilityRuntimeDeployGroup, "deploy_group", ctx.Err())
			p.finishOperation(request.Operation.IdempotencyKey, previous, domain.Deployment{}, nil, err)
			return domain.Deployment{}, err
		}
	}
	p.mu.Lock()
	active := p.deploying[request.DeploymentID]
	if active != nil {
		if active.fingerprint != fingerprint {
			p.mu.Unlock()
			err := p.failure(request.Operation, contracts.CapabilityRuntimeDeployGroup, "deploy_group", contracts.ErrConflict, "deployment id is already being deployed from a different immutable group release", contracts.RetryNever, false, nil)
			p.finishOperation(request.Operation.IdempotencyKey, previous, domain.Deployment{}, nil, err)
			return domain.Deployment{}, err
		}
		p.mu.Unlock()
		select {
		case <-active.done:
			p.finishOperation(request.Operation.IdempotencyKey, previous, active.deployment, nil, active.err)
			return active.deployment, active.err
		case <-ctx.Done():
			err := p.contextError(request.Operation, contracts.CapabilityRuntimeDeployGroup, "deploy_group", ctx.Err())
			p.finishOperation(request.Operation.IdempotencyKey, previous, domain.Deployment{}, nil, err)
			return domain.Deployment{}, err
		}
	}
	p.deploying[request.DeploymentID] = previous
	p.mu.Unlock()
	deployment, state, deployErr := p.deployGroup(ctx, request, fingerprint)
	p.finishOperation(request.Operation.IdempotencyKey, previous, deployment, state, deployErr)
	return deployment, deployErr
}

func (p *Provider) deployGroup(ctx context.Context, request contracts.DeployGroupRequest, fingerprint string) (domain.Deployment, *groupState, error) {
	ctx, cancel := p.operationContext(ctx, request.Operation)
	defer cancel()
	now := p.config.Clock().UTC()
	deployment := domain.Deployment{ID: request.DeploymentID, ApplicationID: request.Spec.ApplicationID, EnvironmentID: request.Spec.EnvironmentID, ReleaseID: request.Spec.ReleaseID, Status: domain.DeploymentPending, CreatedAt: now, UpdatedAt: now}
	if err := deployment.Validate(); err != nil {
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeployGroup, "deploy_group", contracts.ErrValidation, "deployment is invalid", contracts.RetryNever, false, err)
	}
	if err := deployment.Transition(domain.DeploymentPreparing, p.config.Clock()); err != nil {
		return domain.Deployment{}, nil, err
	}

	previous, err := p.previousGroup(ctx, request.Spec.Rollout, request.Operation)
	if err != nil {
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeployGroup, "deploy_group", contracts.ErrConflict, err.Error(), contracts.RetryNever, false, nil)
	}
	// A complete task-owned group is adopted before capacity or Docker mutation.
	if recovered, ok, recoverErr := p.recoverGroup(ctx, deployment, request.Spec, fingerprint, request.Operation); recoverErr != nil {
		return domain.Deployment{}, nil, recoverErr
	} else if ok {
		return recovered.deployment, recovered, nil
	}
	reused := p.reusableServices(previous, request.Spec)
	if request.ForceRecreate {
		// An M4 recovery redeploy must prove that a replacement set actually
		// starts.  Do not let an unchanged immutable spec turn that operation
		// into a no-op container adoption.
		reused = make(map[string]*serviceState)
	}

	aggregate, err := request.Spec.AggregateResources()
	if err != nil {
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeployGroup, "deploy_group", contracts.ErrValidation, "runtime group resources are invalid", contracts.RetryNever, false, err)
	}
	capacityResources := aggregate
	// CapacityProvider snapshots include active leases.  For a rolling update
	// the previous deployment's lease therefore remains accounted while this
	// candidate reserves only its own aggregate; the resulting preflight is the
	// single-replica double-capacity gate without double-counting the old lease.
	hostPorts := 0
	entry := entryService(request.Spec)
	if entry != nil && len(entry.ContainerPorts) > 0 {
		if _, reusedEntry := reused[entry.Name]; reusedEntry {
			hostPorts = 0
		} else {
			hostPorts = 1
		}
	}
	capacityOp := request.Operation
	capacityOp.IdempotencyKey += ":group-capacity"
	capacityRequest := contracts.CapacityRequest{Scope: contracts.CapacityRuntime, Resources: capacityResources, HostPorts: hostPorts, Operation: capacityOp}
	if _, _, err := p.config.Capacity.Preflight(ctx, capacityRequest); err != nil {
		return domain.Deployment{}, nil, err
	}
	capacity, err := p.config.Capacity.Reserve(ctx, capacityRequest)
	if err != nil {
		return domain.Deployment{}, nil, err
	}
	capacityHeld := true
	defer func() {
		if capacityHeld {
			releaseOp := request.Operation
			releaseOp.IdempotencyKey += ":group-capacity-release"
			_ = p.config.Capacity.Release(context.Background(), capacity, releaseOp)
		}
	}()
	if hostPorts == 1 && (capacity.HostPort < 1 || capacity.HostPort > 65535) {
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeployGroup, "deploy_group", contracts.ErrCapacity, "capacity lease did not reserve a host port", contracts.RetryBackoff, true, nil)
	}

	if request.Spec.Rollout.Mode == contracts.RuntimeRolloutRecreate && previous != nil {
		if err := p.stopGroup(ctx, previous, request.Operation); err != nil {
			return domain.Deployment{}, nil, err
		}
		p.markDestroyed(previous)
	}
	volumes, err := p.prepareVolumes(ctx, request.Spec, request.Operation)
	if err != nil {
		return domain.Deployment{}, nil, err
	}
	imageRefs, err := p.loadImages(ctx, request.Spec, request.Operation)
	if err != nil {
		return domain.Deployment{}, nil, err
	}
	network := p.networkFor(request.Spec.ServiceGroupID, deployment.ID)
	if err := p.ensureNetwork(ctx, network, request.Operation); err != nil {
		return domain.Deployment{}, nil, err
	}
	ingressNetwork := ""
	createdIngressNetwork := false
	if entry != nil && len(entry.ContainerPorts) > 0 {
		if _, reusedEntry := reused[entry.Name]; reusedEntry && previous != nil {
			previous.mu.Lock()
			ingressNetwork = previous.ingressNetwork
			previous.mu.Unlock()
		} else {
			ingressNetwork = p.ingressNetworkFor(request.Spec.ServiceGroupID, deployment.ID)
			if err := p.ensureIngressNetwork(ctx, ingressNetwork, request.Operation); err != nil {
				_ = p.removeNetwork(ctx, network, request.Operation)
				return domain.Deployment{}, nil, err
			}
			createdIngressNetwork = true
		}
	}
	if err := deployment.Transition(domain.DeploymentDeploying, p.config.Clock()); err != nil {
		_ = p.removeNetwork(ctx, network, request.Operation)
		if createdIngressNetwork {
			_ = p.removeNetwork(ctx, ingressNetwork, request.Operation)
		}
		return domain.Deployment{}, nil, err
	}
	activateOp := request.Operation
	activateOp.IdempotencyKey += ":group-capacity-activate"
	if err := p.config.Capacity.Activate(ctx, capacity, activateOp); err != nil {
		_ = p.removeNetwork(ctx, network, request.Operation)
		if createdIngressNetwork {
			_ = p.removeNetwork(ctx, ingressNetwork, request.Operation)
		}
		return domain.Deployment{}, nil, err
	}

	state := &groupState{deployment: deployment, spec: request.Spec, fingerprint: fingerprint, network: network, ingressNetwork: ingressNetwork, createdIngress: createdIngressNetwork, services: make(map[string]*serviceState), imageRefs: imageRefs, volumes: volumes, capacity: &capacity}
	order, err := request.Spec.DependencyOrder()
	if err != nil {
		cleanupErr := p.cleanupCandidateGroup(ctx, state, request.Operation)
		capacityHeld = false
		if cleanupErr != nil {
			return domain.Deployment{}, nil, cleanupErr
		}
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeployGroup, "deploy_group", contracts.ErrValidation, "runtime dependency graph is invalid", contracts.RetryNever, false, err)
	}
	state.order = order
	for name, service := range reused {
		state.services[name] = service
	}
	if err := p.attachReusedServices(ctx, state, reused, request.Operation); err != nil {
		cleanupErr := p.cleanupCandidateGroup(ctx, state, request.Operation)
		capacityHeld = false
		if cleanupErr != nil {
			return domain.Deployment{}, nil, cleanupErr
		}
		return domain.Deployment{}, nil, err
	}
	started := make([]string, 0, len(order))
	for _, name := range order {
		service := serviceByName(request.Spec.Services, name)
		if service == nil {
			return domain.Deployment{}, nil, errors.New("runtime dependency order named an unknown service")
		}
		if !dependenciesSatisfied(state, *service) {
			err := p.failure(request.Operation, contracts.CapabilityRuntimeDeployGroup, "deploy_group", contracts.ErrInvalidTransition, "runtime service dependency condition was not satisfied", contracts.RetryNever, false, nil)
			if service.Required {
				cleanupErr := p.cleanupFailedGroup(ctx, state, started, request.Operation)
				capacityHeld = false
				if cleanupErr != nil {
					return domain.Deployment{}, nil, cleanupErr
				}
				return domain.Deployment{}, nil, err
			}
			state.services[name] = &serviceState{spec: *service, container: p.containerName(deployment.ID, name), status: "skipped", failed: err, ownerDeploymentID: deployment.ID, ownerServiceGroupID: request.Spec.ServiceGroupID, specDigest: serviceSpecDigest(*service)}
			continue
		}
		if _, reusedService := reused[name]; reusedService {
			started = append(started, name)
			continue
		}
		ss, startErr := p.startService(ctx, deployment, *service, state, capacity.HostPort, request.Operation)
		if startErr != nil {
			// startService may have created the container before a health or
			// completion check failed.  Remove that exact deterministic name
			// before deciding whether the failure is required or optional.
			_ = p.stopContainer(ctx, p.containerName(deployment.ID, service.Name))
			if service.Required {
				cleanupErr := p.cleanupFailedGroup(ctx, state, started, request.Operation)
				capacityHeld = false
				if cleanupErr != nil {
					return domain.Deployment{}, nil, cleanupErr
				}
				return domain.Deployment{}, nil, startErr
			}
			state.services[name] = &serviceState{spec: *service, container: p.containerName(deployment.ID, name), status: "failed", failed: startErr, ownerDeploymentID: deployment.ID, ownerServiceGroupID: request.Spec.ServiceGroupID, specDigest: serviceSpecDigest(*service)}
			continue
		}
		state.services[name] = ss
		started = append(started, name)
	}
	if err := deployment.Transition(domain.DeploymentRuntimeReady, p.config.Clock()); err != nil {
		cleanupErr := p.cleanupFailedGroup(ctx, state, started, request.Operation)
		capacityHeld = false
		if cleanupErr != nil {
			return domain.Deployment{}, nil, cleanupErr
		}
		return domain.Deployment{}, nil, err
	}
	state.deployment = deployment
	if err := p.persistState(state); err != nil {
		cleanupErr := p.cleanupFailedGroup(ctx, state, started, request.Operation)
		capacityHeld = false
		if cleanupErr != nil {
			return domain.Deployment{}, nil, cleanupErr
		}
		_ = p.removeDurableState(deployment.ID)
		return domain.Deployment{}, nil, p.failure(request.Operation, contracts.CapabilityRuntimeDeployGroup, "persist_state", contracts.ErrUnavailable, "durable service group state could not be persisted: "+err.Error(), contracts.RetryBackoff, true, err)
	}
	capacityHeld = false
	if request.Spec.Rollout.Mode == contracts.RuntimeRolloutRolling && previous != nil {
		if request.Spec.Rollout.DeferOldTeardown {
			// The controller owns the route handoff and its observation window.
			// A runtime driver may only attest that this candidate is ready; it
			// must leave the previous group, its durable state, and its serving
			// containers untouched until an explicit DestroyGroup retires it.
			return deployment, state, nil
		}
		preserve := reusableServiceNames(state)
		if err := p.stopGroupExcept(ctx, previous, preserve, request.Operation); err != nil {
			// Preserve the old group when its stop is not proven.  The candidate
			// is removed so the caller can safely retry the same immutable
			// Release without leaving a second live group behind.
			_ = p.cleanupCandidateGroup(ctx, state, request.Operation)
			_ = p.removeDurableState(state.deployment.ID)
			return domain.Deployment{}, nil, err
		}
		_ = p.removeDurableState(previous.deployment.ID)
		p.markDestroyed(previous)
	}
	return deployment, state, nil
}

func (p *Provider) lookupDeployment(id domain.ID, fingerprint string) (domain.Deployment, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	state := p.groups[id]
	if state == nil {
		return domain.Deployment{}, false, nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.fingerprint != fingerprint {
		return domain.Deployment{}, false, p.failure(contracts.OperationContext{IdempotencyKey: "lookup"}, contracts.CapabilityRuntimeDeployGroup, "deploy_group", contracts.ErrConflict, "deployment id is already bound to a different immutable group release", contracts.RetryNever, false, nil)
	}
	return state.deployment, true, nil
}

func (p *Provider) beginOperation(key, fingerprint string) (*operationRecord, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if previous := p.ops[key]; previous != nil {
		if previous.fingerprint != fingerprint {
			return nil, false, errors.New("idempotency key was reused for a different service group")
		}
		return previous, true, nil
	}
	record := &operationRecord{fingerprint: fingerprint, done: make(chan struct{})}
	p.ops[key] = record
	return record, false, nil
}

func (p *Provider) finishOperation(key string, record *operationRecord, deployment domain.Deployment, state *groupState, err error) {
	p.mu.Lock()
	if err == nil && state != nil {
		p.groups[deployment.ID] = state
	}
	if active := p.deploying[deployment.ID]; active == record {
		delete(p.deploying, deployment.ID)
	}
	record.deployment, record.err = deployment, err
	close(record.done)
	p.mu.Unlock()
}

func (p *Provider) previousGroup(ctx context.Context, policy contracts.RuntimeRolloutPolicy, operation contracts.OperationContext) (*groupState, error) {
	if policy.Mode == contracts.RuntimeRolloutInitial || policy.PreviousDeploymentID.Empty() {
		return nil, nil
	}
	p.mu.Lock()
	state := p.groups[policy.PreviousDeploymentID]
	p.mu.Unlock()
	if state == nil {
		snapshot, found, readErr := p.readDurableState(policy.PreviousDeploymentID)
		if readErr != nil {
			return nil, readErr
		}
		if !found || snapshot.Deployment.Status == domain.DeploymentStopped {
			return nil, fmt.Errorf("previous rollout deployment %q was not found", policy.PreviousDeploymentID)
		}
		loaded, loadErr := p.stateFromDurable(ctx, snapshot, operation, contracts.CapabilityRuntimeDeployGroup, "previous_rollout")
		if loadErr != nil {
			return nil, loadErr
		}
		state = loaded
		p.mu.Lock()
		if existing := p.groups[policy.PreviousDeploymentID]; existing != nil {
			state = existing
		} else {
			p.groups[policy.PreviousDeploymentID] = state
		}
		p.mu.Unlock()
	}
	state.mu.Lock()
	destroyed := state.destroyed
	state.mu.Unlock()
	if destroyed {
		return nil, fmt.Errorf("previous rollout deployment %q is already stopped", policy.PreviousDeploymentID)
	}
	return state, nil
}

func (p *Provider) reusableServices(previous *groupState, spec contracts.ServiceGroupRuntimeSpec) map[string]*serviceState {
	result := make(map[string]*serviceState)
	if previous == nil {
		return result
	}
	previous.mu.Lock()
	previousID := previous.deployment.ID
	previousGroupID := previous.spec.ServiceGroupID
	previousServices := make(map[string]*serviceState, len(previous.services))
	for name, service := range previous.services {
		copyValue := *service
		previousServices[name] = &copyValue
	}
	previous.mu.Unlock()
	for _, service := range spec.Services {
		old := previousServices[service.Name]
		if old == nil || old.failed != nil || old.destroyed() || !serviceSpecMatches(old, service) {
			continue
		}
		old.ownerDeploymentID = previousID
		if old.ownerServiceGroupID.Empty() {
			old.ownerServiceGroupID = previousGroupID
		}
		old.reused = true
		old.networkAttached = false
		result[service.Name] = old
	}
	return result
}

func sameServiceSpec(left, right contracts.ServiceRuntimeSpec) bool {
	leftJSON, leftErr := json.Marshal(canonicalRuntimeService(left))
	rightJSON, rightErr := json.Marshal(canonicalRuntimeService(right))
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func serviceSpecDigest(service contracts.ServiceRuntimeSpec) string {
	encoded, err := json.Marshal(canonicalRuntimeService(service))
	if err != nil {
		return ""
	}
	return "sha256:" + hash(string(encoded))
}

func canonicalRuntimeService(service contracts.ServiceRuntimeSpec) contracts.ServiceRuntimeSpec {
	group := canonicalSpec(contracts.ServiceGroupRuntimeSpec{SchemaVersion: contracts.ServiceGroupRuntimeSchema, ApplicationID: "a", EnvironmentID: "e", ReleaseID: "r", ServiceGroupID: "g", ConfigDigest: "sha256:" + strings.Repeat("0", 64), EntryService: service.Name, Services: []contracts.ServiceRuntimeSpec{service}, Rollout: contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial}})
	return group.Services[0]
}

func (s *serviceState) destroyed() bool { return s.status == "stopped" }

func serviceSpecMatches(old *serviceState, current contracts.ServiceRuntimeSpec) bool {
	if old.specDigest != "" {
		return old.specDigest == serviceSpecDigest(current)
	}
	return sameServiceSpec(old.spec, current)
}

func (p *Provider) attachReusedServices(ctx context.Context, state *groupState, reused map[string]*serviceState, operation contracts.OperationContext) error {
	for name, service := range reused {
		if service.ownerDeploymentID.Empty() || service.container == "" {
			return p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "reuse_service", contracts.ErrValidation, "reused service mapping is incomplete", contracts.RetryNever, false, nil)
		}
		if err := p.run(ctx, []string{"network", "connect", "--alias", name, state.network, service.container}); err != nil {
			for attachedName, attached := range reused {
				if attachedName == name || !attached.networkAttached {
					continue
				}
				_ = p.run(ctx, []string{"network", "disconnect", "-f", state.network, attached.container})
			}
			return p.commandError(operation, contracts.CapabilityRuntimeDeployGroup, "reuse_service", err)
		}
		service.networkAttached = true
		state.services[name] = service
	}
	return nil
}

func reusableServiceNames(state *groupState) map[string]bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	result := make(map[string]bool)
	for name, service := range state.services {
		if service.reused {
			result[name] = true
		}
	}
	return result
}

func (p *Provider) recoverGroup(ctx context.Context, deployment domain.Deployment, spec contracts.ServiceGroupRuntimeSpec, fingerprint string, operation contracts.OperationContext) (*groupState, bool, error) {
	if snapshot, found, readErr := p.readDurableState(deployment.ID); readErr != nil {
		return nil, false, p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "deploy_group", contracts.ErrUnavailable, "durable service group state could not be read", contracts.RetryAfterReconnect, true, readErr)
	} else if found {
		if snapshot.Fingerprint != fingerprint || snapshot.Spec.ReleaseID != spec.ReleaseID {
			return nil, false, p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "deploy_group", contracts.ErrConflict, "durable service group state does not match the immutable release", contracts.RetryNever, false, nil)
		}
		state, err := p.stateFromDurable(ctx, snapshot, operation, contracts.CapabilityRuntimeDeployGroup, "deploy_group")
		if err != nil {
			return nil, false, err
		}
		return state, true, nil
	}
	names := make([]string, 0, len(spec.Services))
	for _, service := range spec.Services {
		names = append(names, p.containerName(deployment.ID, service.Name))
	}
	sort.Strings(names)
	found := 0
	network := p.networkFor(spec.ServiceGroupID, deployment.ID)
	ingressNetwork := p.ingressNetworkFor(spec.ServiceGroupID, deployment.ID)
	state := &groupState{deployment: deployment, spec: spec, fingerprint: fingerprint, network: network, ingressNetwork: ingressNetwork, services: make(map[string]*serviceState), imageRefs: make(map[string]string), volumes: make(map[string]contracts.VolumeSpec)}
	for _, service := range spec.Services {
		container := p.containerName(deployment.ID, service.Name)
		facts, err := p.inspectContainer(ctx, container)
		if err != nil {
			continue
		}
		found++
		if !facts.matches(p.config.TaskPrefix, deployment.ID, spec.ServiceGroupID, service, network) {
			return nil, false, p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "deploy_group", contracts.ErrConflict, "existing task container does not match the immutable constrained group", contracts.RetryNever, false, nil)
		}
		healthy := facts.healthy(service)
		if isExecHealthcheck(service) && facts.State.Running {
			healthy = p.run(ctx, append([]string{"exec", container}, service.Healthcheck.Test[1:]...)) == nil
		}
		state.services[service.Name] = &serviceState{spec: service, container: container, port: facts.hostPort(service), status: facts.status(), healthy: healthy, completed: facts.completed(service), ownerDeploymentID: deployment.ID, ownerServiceGroupID: spec.ServiceGroupID, specDigest: serviceSpecDigest(service), networkAttached: true}
		state.imageRefs[service.Name] = facts.Config.Image
	}
	if found != len(spec.Services) {
		return nil, false, nil
	}
	if err := p.verifyNetwork(ctx, ingressNetwork, operation, contracts.CapabilityRuntimeDeployGroup, "deploy_group"); err != nil {
		return nil, false, err
	}
	order, err := spec.DependencyOrder()
	if err != nil {
		return nil, false, err
	}
	state.order = order
	if err := deployment.Transition(domain.DeploymentDeploying, p.config.Clock()); err != nil {
		return nil, false, err
	}
	if err := deployment.Transition(domain.DeploymentRuntimeReady, p.config.Clock()); err != nil {
		return nil, false, err
	}
	state.deployment = deployment
	return state, true, nil
}

func (p *Provider) prepareVolumes(ctx context.Context, spec contracts.ServiceGroupRuntimeSpec, operation contracts.OperationContext) (map[string]contracts.VolumeSpec, error) {
	claims := append([]contracts.RuntimeVolumeClaim(nil), spec.VolumeClaims...)
	sort.Slice(claims, func(i, j int) bool { return claims[i].Name < claims[j].Name })
	result := make(map[string]contracts.VolumeSpec, len(claims))
	for _, claim := range claims {
		op := operation
		op.IdempotencyKey += ":volume-create:" + claim.Name
		created, _, err := p.config.Volumes.Create(ctx, contracts.VolumeRequest{Volume: contracts.VolumeSpec{Name: claim.Name, MountPath: "/", SizeBytes: claim.SizeBytes}, Operation: op})
		if err != nil {
			return nil, err
		}
		if !safeName.MatchString(created.Name) || strings.Contains(created.Name, "..") || strings.ContainsAny(created.Name, ",=") {
			return nil, p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "volume", contracts.ErrValidation, "volume provider returned an unsafe physical name", contracts.RetryNever, false, nil)
		}
		attachOp := operation
		attachOp.IdempotencyKey += ":volume-attach:" + claim.Name
		if err := p.config.Volumes.Attach(ctx, contracts.VolumeRequest{Volume: created, Operation: attachOp}); err != nil {
			return nil, err
		}
		result[claim.Name] = created
	}
	return result, nil
}

func (p *Provider) loadImages(ctx context.Context, spec contracts.ServiceGroupRuntimeSpec, operation contracts.OperationContext) (map[string]string, error) {
	services := append([]contracts.ServiceRuntimeSpec(nil), spec.Services...)
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	seen := make(map[string]struct{}, len(services))
	refs := make(map[string]string, len(services))
	for _, service := range services {
		key := service.Image.Repository + "@" + service.Image.Digest
		if _, exists := seen[key]; exists {
			for _, previous := range services {
				if previous.Name != service.Name && previous.Image == service.Image && refs[previous.Name] != "" {
					refs[service.Name] = refs[previous.Name]
					break
				}
			}
			continue
		}
		seen[key] = struct{}{}
		if err := service.Image.Validate(); err != nil {
			return nil, p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "image", contracts.ErrValidation, "runtime group image is not an immutable digest", contracts.RetryNever, false, err)
		}
		imageOp := operation
		imageOp.IdempotencyKey += ":image:" + digestKey(service.Image)
		if ref, presentErr := p.loadedImageReference(ctx, service.Image, operation); presentErr != nil {
			return nil, presentErr
		} else if ref != "" {
			refs[service.Name] = ref
			continue
		}
		if p.config.ImageStore == nil {
			return nil, p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "image", contracts.ErrUnavailable, "requested digest is not present and no persistent OCI image loader is configured", contracts.RetryUserAction, false, nil)
		}
		archive, stored, err := p.config.ImageStore.OpenOCI(ctx, service.Image, imageOp)
		if err != nil {
			return nil, p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "image", contracts.ErrUnavailable, "persistent OCI image is unavailable", contracts.RetryBackoff, true, nil)
		}
		if archive == nil {
			return nil, p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "image", contracts.ErrValidation, "image store returned no OCI archive", contracts.RetryNever, false, nil)
		}
		if stored.Image.Repository != service.Image.Repository || stored.Image.Digest != service.Image.Digest || strings.TrimSpace(stored.StorageRef) == "" {
			_ = archive.Close()
			return nil, p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "image", contracts.ErrConflict, "image store did not attest the requested digest", contracts.RetryNever, false, nil)
		}
		path, copyErr := p.copyArchive(archive)
		closeErr := archive.Close()
		if copyErr != nil || closeErr != nil {
			return nil, p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "image", contracts.ErrUnavailable, "persistent OCI image could not be staged", contracts.RetryBackoff, true, errors.Join(copyErr, closeErr))
		}
		loadErr := p.run(ctx, []string{"load", "--input", path})
		removeErr := os.Remove(path)
		if loadErr != nil {
			if removeErr != nil {
				return nil, p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "image", contracts.ErrUnavailable, "failed image build left an OCI staging file", contracts.RetryBackoff, true, removeErr)
			}
			return nil, p.commandError(operation, contracts.CapabilityRuntimeDeployGroup, "image", loadErr)
		}
		if removeErr != nil {
			return nil, p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "image", contracts.ErrUnavailable, "OCI staging file could not be removed", contracts.RetryBackoff, true, removeErr)
		}
		ref, err := p.loadedImageReference(ctx, service.Image, operation)
		if err != nil {
			return nil, err
		}
		if ref == "" {
			return nil, p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "image", contracts.ErrConflict, "loaded OCI image identity did not match the requested digest", contracts.RetryNever, false, nil)
		}
		refs[service.Name] = ref
	}
	return refs, nil
}

func (p *Provider) startService(ctx context.Context, deployment domain.Deployment, service contracts.ServiceRuntimeSpec, state *groupState, entryPort int, operation contracts.OperationContext) (*serviceState, error) {
	if err := validateRestart(service.Restart); err != nil {
		return nil, p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "service", contracts.ErrValidation, "runtime service restart policy is unsupported", contracts.RetryNever, false, err)
	}
	for _, env := range service.Environment {
		if env.Kind == contracts.RuntimeEnvironmentSecret {
			return nil, p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "service", contracts.ErrForbidden, "runtime secret environment materialization is not enabled by this driver", contracts.RetryUserAction, false, nil)
		}
	}
	container := p.containerName(deployment.ID, service.Name)
	args := p.runArgs(container, deployment, service, state, entryPort)
	if err := p.run(ctx, args); err != nil {
		return nil, p.commandError(operation, contracts.CapabilityRuntimeDeployGroup, "service", err)
	}
	if service.Name == state.spec.EntryService && state.ingressNetwork != "" {
		if err := p.run(ctx, []string{"network", "connect", state.ingressNetwork, container}); err != nil {
			_ = p.stopContainer(ctx, container)
			return nil, p.commandError(operation, contracts.CapabilityRuntimeDeployGroup, "connect_ingress", err)
		}
	}
	ss := &serviceState{spec: service, container: container, status: "running", healthy: service.Healthcheck == nil || service.Healthcheck.Disabled, ownerDeploymentID: deployment.ID, ownerServiceGroupID: state.spec.ServiceGroupID, specDigest: serviceSpecDigest(service), networkAttached: true}
	if len(service.ContainerPorts) > 0 && service.Name == state.spec.EntryService {
		ss.port = entryPort
	}
	if service.Role == domain.RoleOneShot || service.Healthcheck != nil && !service.Healthcheck.Disabled {
		if err := p.waitService(ctx, ss, operation); err != nil {
			return nil, err
		}
	}
	return ss, nil
}

func (p *Provider) runArgs(container string, deployment domain.Deployment, service contracts.ServiceRuntimeSpec, state *groupState, entryPort int) []string {
	args := []string{"run", "--detach", "--name", container, "--pull", "never", "--network", state.network, "--network-alias", service.Name, "--security-opt", "no-new-privileges=true", "--cap-drop", "ALL", "--cpu-period", "100000", "--cpu-quota", strconv.FormatInt(service.Resources.CPUMillis*100, 10), "--memory", strconv.FormatInt(service.Resources.MemoryBytes, 10), "--memory-swap", strconv.FormatInt(service.Resources.MemoryBytes, 10), "--pids-limit", strconv.FormatInt(service.Resources.PIDs, 10), "--label", "open-card.managed=true", "--label", "open-card.task-prefix=" + p.config.TaskPrefix, "--label", "open-card.deployment-id=" + string(deployment.ID), "--label", "open-card.service-group-id=" + string(state.spec.ServiceGroupID), "--label", "open-card.service=" + service.Name, "--label", "open-card.service-name=" + service.Name, "--label", "open-card.service-role=" + string(service.Role), "--label", "open-card.service-group-release=" + string(deployment.ReleaseID)}
	if service.Restart != "" {
		args = append(args, "--restart", service.Restart)
	} else {
		args = append(args, "--restart", "no")
	}
	for _, env := range service.Environment {
		args = append(args, "--env", env.Name+"="+env.Value)
	}
	for _, volume := range service.Volumes {
		physical := state.volumes[volume.Name].Name
		mount := "source=" + physical + ",target=" + volume.MountPath + ",type=volume"
		if volume.ReadOnly {
			mount += ",readonly"
		}
		args = append(args, "--mount", mount)
	}
	if service.Healthcheck != nil && !service.Healthcheck.Disabled && !isExecHealthcheck(service) {
		args = append(args, "--health-cmd", healthCommand(service.Healthcheck.Test))
		if service.Healthcheck.IntervalSeconds > 0 {
			args = append(args, "--health-interval", strconv.FormatInt(int64(service.Healthcheck.IntervalSeconds), 10)+"s")
		}
		if service.Healthcheck.TimeoutSeconds > 0 {
			args = append(args, "--health-timeout", strconv.FormatInt(int64(service.Healthcheck.TimeoutSeconds), 10)+"s")
		}
		if service.Healthcheck.StartPeriodSeconds > 0 {
			args = append(args, "--health-start-period", strconv.FormatInt(int64(service.Healthcheck.StartPeriodSeconds), 10)+"s")
		}
		if service.Healthcheck.Retries > 0 {
			args = append(args, "--health-retries", strconv.Itoa(service.Healthcheck.Retries))
		}
	}
	if service.Name == state.spec.EntryService && len(service.ContainerPorts) > 0 {
		args = append(args, "--publish", fmt.Sprintf("127.0.0.1:%d:%d/tcp", entryPort, service.ContainerPorts[0]))
	}
	if len(service.Entrypoint) > 0 {
		args = append(args, "--entrypoint", service.Entrypoint[0])
	}
	imageRef := state.imageRefs[service.Name]
	if imageRef == "" {
		imageRef = service.Image.Digest
	}
	args = append(args, imageRef)
	if len(service.Entrypoint) > 1 {
		args = append(args, service.Entrypoint[1:]...)
	}
	args = append(args, service.Command...)
	return args
}

func healthCommand(test []string) string {
	if len(test) == 0 {
		return ""
	}
	if strings.EqualFold(test[0], "CMD") || strings.EqualFold(test[0], "CMD-SHELL") {
		return strings.Join(test[1:], " ")
	}
	return strings.Join(test, " ")
}

func (p *Provider) waitService(ctx context.Context, state *serviceState, operation contracts.OperationContext) error {
	deadline := time.NewTimer(p.config.Timeout)
	defer deadline.Stop()
	execFailures := 0
	for {
		facts, err := p.inspectContainer(ctx, state.container)
		if err == nil {
			state.status, state.healthy, state.completed = facts.status(), facts.healthy(state.spec), facts.completed(state.spec)
			if isExecHealthcheck(state.spec) && facts.State.Running {
				if p.run(ctx, append([]string{"exec", state.container}, state.spec.Healthcheck.Test[1:]...)) == nil {
					state.healthy = true
					return nil
				}
				execFailures++
				if retries := state.spec.Healthcheck.Retries; retries > 0 && execFailures >= retries {
					return p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "service", contracts.ErrUnavailable, "runtime service exec healthcheck failed", contracts.RetryUserAction, false, nil)
				}
			} else if facts.State.Health != nil && facts.State.Health.Status == "unhealthy" {
				return p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "service", contracts.ErrUnavailable, "runtime service healthcheck reported unhealthy", contracts.RetryUserAction, false, nil)
			}
			if state.spec.Role == domain.RoleOneShot {
				if state.completed {
					if facts.State.ExitCode != 0 {
						return p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "service", contracts.ErrUnavailable, "one-shot service exited unsuccessfully", contracts.RetryUserAction, false, nil)
					}
					return nil
				}
			} else if state.healthy {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return p.contextError(operation, contracts.CapabilityRuntimeDeployGroup, "service", ctx.Err())
		case <-deadline.C:
			return p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "service", contracts.ErrTimeout, "runtime service did not reach its dependency readiness state", contracts.RetryBackoff, true, context.DeadlineExceeded)
		case <-time.After(healthRetryDelay(state.spec)):
		}
	}
}

func isExecHealthcheck(service contracts.ServiceRuntimeSpec) bool {
	return service.Healthcheck != nil && !service.Healthcheck.Disabled && len(service.Healthcheck.Test) > 1 && strings.EqualFold(service.Healthcheck.Test[0], "CMD")
}

func healthRetryDelay(service contracts.ServiceRuntimeSpec) time.Duration {
	if service.Healthcheck != nil && service.Healthcheck.IntervalSeconds > 0 {
		return time.Duration(service.Healthcheck.IntervalSeconds) * time.Second
	}
	return 100 * time.Millisecond
}

func (p *Provider) ensureNetwork(ctx context.Context, network string, operation contracts.OperationContext) error {
	p.netsMu.Lock()
	defer p.netsMu.Unlock()
	out, err := p.output(ctx, []string{"network", "inspect", "--format", "{{index .Labels \"open-card.managed\"}}|{{index .Labels \"open-card.task-prefix\"}}", network})
	if err == nil {
		if strings.TrimSpace(out) == "true|"+p.config.TaskPrefix {
			return nil
		}
		return p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "network", contracts.ErrConflict, "task-prefixed network is not owned by this provider", contracts.RetryNever, false, nil)
	}
	args := []string{"network", "create", "--driver", "bridge", "--internal", "--label", "open-card.managed=true", "--label", "open-card.task-prefix=" + p.config.TaskPrefix, "--label", "open-card.task=group", network}
	if err := p.run(ctx, args); err != nil {
		return p.commandError(operation, contracts.CapabilityRuntimeDeployGroup, "network", err)
	}
	return nil
}

func (p *Provider) ensureIngressNetwork(ctx context.Context, network string, operation contracts.OperationContext) error {
	p.netsMu.Lock()
	defer p.netsMu.Unlock()
	out, err := p.output(ctx, []string{"network", "inspect", "--format", "{{index .Labels \"open-card.managed\"}}|{{index .Labels \"open-card.task-prefix\"}}", network})
	if err == nil {
		if strings.TrimSpace(out) == "true|"+p.config.TaskPrefix {
			return nil
		}
		return p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "ingress_network", contracts.ErrConflict, "task-prefixed ingress network is not owned by this provider", contracts.RetryNever, false, nil)
	}
	args := []string{"network", "create", "--driver", "bridge", "--label", "open-card.managed=true", "--label", "open-card.task-prefix=" + p.config.TaskPrefix, "--label", "open-card.task=group-ingress", network}
	if err := p.run(ctx, args); err != nil {
		return p.commandError(operation, contracts.CapabilityRuntimeDeployGroup, "ingress_network", err)
	}
	return nil
}

func (p *Provider) loadedImageReference(ctx context.Context, image domain.ImageDigest, operation contracts.OperationContext) (string, error) {
	for _, reference := range []string{imageReference(image), image.Digest} {
		out, err := p.output(ctx, []string{"image", "inspect", "--format", imageInspectFormat, reference})
		if err != nil {
			continue
		}
		matched, inspectErr := validateImageInspection(out, image)
		if inspectErr != nil {
			return "", p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "image", contracts.ErrValidation, inspectErr.Error(), contracts.RetryNever, false, nil)
		}
		if !matched {
			return "", p.failure(operation, contracts.CapabilityRuntimeDeployGroup, "image", contracts.ErrConflict, "local image reference does not match the requested immutable digest", contracts.RetryNever, false, nil)
		}
		return reference, nil
	}
	return "", nil
}

const imageInspectFormat = "{{.Id}}|{{json .Config}}|{{json .RepoDigests}}"

func validateImageInspection(output string, image domain.ImageDigest) (bool, error) {
	parts := strings.SplitN(strings.TrimSpace(output), "|", 3)
	if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" {
		return false, errors.New("Docker returned an invalid image inspection")
	}
	matched := strings.TrimSpace(parts[0]) == image.Digest
	if len(parts) == 3 {
		var repoDigests []string
		if err := json.Unmarshal([]byte(parts[2]), &repoDigests); err != nil {
			return false, errors.New("Docker returned invalid image repository digests")
		}
		for _, reference := range repoDigests {
			if reference == imageReference(image) {
				matched = true
				break
			}
		}
	}
	var config struct {
		Volumes map[string]any `json:"Volumes"`
	}
	if err := json.Unmarshal([]byte(parts[1]), &config); err != nil {
		return false, errors.New("Docker returned invalid image configuration")
	}
	if len(config.Volumes) != 0 {
		return false, errors.New("images declaring unmanaged volumes are not supported")
	}
	return matched, nil
}

func (p *Provider) prepareContext(ctx context.Context, operation contracts.OperationContext) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(p.config.Timeout)
	if !operation.Deadline.IsZero() && operation.Deadline.Before(deadline) {
		deadline = operation.Deadline
	}
	return context.WithDeadline(ctx, deadline)
}

func (p *Provider) operationContext(ctx context.Context, operation contracts.OperationContext) (context.Context, context.CancelFunc) {
	return p.prepareContext(ctx, operation)
}

func (p *Provider) stopStarted(ctx context.Context, state *groupState, started []string, operation contracts.OperationContext) error {
	for i := len(started) - 1; i >= 0; i-- {
		name := started[i]
		service := state.services[name]
		if service == nil {
			continue
		}
		_ = p.stopContainer(ctx, service.container)
	}
	return nil
}

func (p *Provider) cleanupFailedGroup(ctx context.Context, state *groupState, _ []string, operation contracts.OperationContext) error {
	return p.cleanupCandidateGroup(ctx, state, operation)
}

func (p *Provider) stopGroup(ctx context.Context, state *groupState, operation contracts.OperationContext) error {
	return p.stopGroupExcept(ctx, state, nil, operation)
}

func (p *Provider) stopGroupExcept(ctx context.Context, state *groupState, preserve map[string]bool, operation contracts.OperationContext) error {
	state.mu.Lock()
	order := append([]string(nil), state.order...)
	services := make(map[string]*serviceState, len(state.services))
	for name, service := range state.services {
		copyValue := *service
		services[name] = &copyValue
	}
	state.mu.Unlock()
	var first error
	for i := len(order) - 1; i >= 0; i-- {
		service := services[order[i]]
		if service == nil {
			continue
		}
		if preserve[order[i]] {
			if service.networkAttached {
				if err := p.run(ctx, []string{"network", "disconnect", "-f", state.network, service.container}); err != nil && first == nil {
					first = p.commandError(operation, contracts.CapabilityRuntimeDestroyGroup, "disconnect_reused_service", err)
				}
			}
			continue
		}
		if err := p.stopContainer(ctx, service.container); err != nil && first == nil {
			first = p.commandError(operation, contracts.CapabilityRuntimeDestroyGroup, "stop_group", err)
		}
	}
	if first != nil {
		return first
	}
	if err := p.removeNetwork(ctx, state.network, operation); err != nil {
		return err
	}
	if !preserve[state.spec.EntryService] && state.ingressNetwork != "" {
		if err := p.removeNetwork(ctx, state.ingressNetwork, operation); err != nil {
			return err
		}
	}
	state.mu.Lock()
	capacity := state.capacity
	state.mu.Unlock()
	if capacity != nil {
		release := operation
		release.IdempotencyKey += ":group-capacity-release:" + string(state.deployment.ID)
		if err := p.config.Capacity.Release(ctx, *capacity, release); err != nil {
			return err
		}
		state.mu.Lock()
		state.capacity = nil
		state.mu.Unlock()
	}
	return nil
}

func (p *Provider) cleanupCandidateGroup(ctx context.Context, state *groupState, operation contracts.OperationContext) error {
	state.mu.Lock()
	order := append([]string(nil), state.order...)
	services := make(map[string]*serviceState, len(state.services))
	for name, service := range state.services {
		copyValue := *service
		services[name] = &copyValue
	}
	state.mu.Unlock()
	var first error
	for index := len(order) - 1; index >= 0; index-- {
		service := services[order[index]]
		if service == nil {
			continue
		}
		if service.reused {
			if service.networkAttached {
				if err := p.run(ctx, []string{"network", "disconnect", "-f", state.network, service.container}); err != nil && first == nil {
					first = p.commandError(operation, contracts.CapabilityRuntimeDestroyGroup, "cleanup_disconnect_reused_service", err)
				}
			}
			continue
		}
		if err := p.stopContainer(ctx, service.container); err != nil && first == nil {
			first = p.commandError(operation, contracts.CapabilityRuntimeDestroyGroup, "cleanup_stop_candidate", err)
		}
	}
	if err := p.removeNetworkWithRetry(ctx, state.network, operation); err != nil && first == nil {
		first = err
	}
	if state.createdIngress {
		if err := p.removeNetworkWithRetry(ctx, state.ingressNetwork, operation); err != nil && first == nil {
			first = err
		}
	}
	state.mu.Lock()
	capacity := state.capacity
	state.capacity = nil
	state.mu.Unlock()
	if capacity != nil {
		release := operation
		release.IdempotencyKey += ":group-capacity-release:" + string(state.deployment.ID)
		if err := p.config.Capacity.Release(ctx, *capacity, release); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (p *Provider) removeNetworkWithRetry(ctx context.Context, network string, operation contracts.OperationContext) error {
	if strings.TrimSpace(network) == "" {
		return nil
	}
	var last error
	for attempt := 0; attempt < 20; attempt++ {
		if err := p.removeNetwork(ctx, network, operation); err == nil {
			return nil
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return p.contextError(operation, contracts.CapabilityRuntimeDestroyGroup, "cleanup_network", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	return last
}

func (p *Provider) removeNetwork(ctx context.Context, network string, operation contracts.OperationContext) error {
	if strings.TrimSpace(network) == "" {
		return nil
	}
	if err := p.run(ctx, []string{"network", "rm", network}); err != nil {
		return p.commandError(operation, contracts.CapabilityRuntimeDestroyGroup, "network", err)
	}
	return nil
}

func (p *Provider) stopContainer(ctx context.Context, container string) error {
	if strings.TrimSpace(container) == "" {
		return nil
	}
	if err := p.run(ctx, []string{"stop", "--time", "10", container}); err != nil {
		// A stopped/exited container is still safe to remove.  Do not hide
		// unknown Docker errors, because they can indicate an ownership issue.
		if rmErr := p.run(ctx, []string{"rm", "--force", container}); rmErr != nil {
			return err
		}
		return nil
	}
	return p.run(ctx, []string{"rm", "--force", container})
}

func (p *Provider) markDestroyed(state *groupState) {
	state.mu.Lock()
	state.destroyed = true
	state.deployment.Status = domain.DeploymentStopped
	state.mu.Unlock()
}

func (p *Provider) ObserveGroup(ctx context.Context, request contracts.ObserveGroupRequest) (contracts.ServiceGroupRuntimeObservation, error) {
	if err := p.check(ctx, request.Operation, contracts.CapabilityRuntimeObserveGroup, "observe_group"); err != nil {
		return contracts.ServiceGroupRuntimeObservation{}, err
	}
	state, err := p.getGroup(ctx, request.DeploymentID, request.Operation, contracts.CapabilityRuntimeObserveGroup, "observe_group")
	if err != nil {
		return contracts.ServiceGroupRuntimeObservation{}, err
	}
	state.mu.Lock()
	deployment := state.deployment
	rolledBack := state.rolledBack
	services := append([]string(nil), state.order...)
	serviceStates := make(map[string]*serviceState, len(state.services))
	for name, value := range state.services {
		copyValue := *value
		serviceStates[name] = &copyValue
	}
	destroyed := state.destroyed
	state.mu.Unlock()
	observations := make([]contracts.RuntimeObservation, 0, len(services))
	effect := contracts.RuntimeEffectKnown
	requiredFailure := false
	optionalFailure := false
	for _, name := range services {
		ss := serviceStates[name]
		if ss == nil {
			continue
		}
		if !destroyed && ss.failed == nil {
			if facts, inspectErr := p.inspectContainer(ctx, ss.container); inspectErr == nil {
				ss.status, ss.healthy, ss.completed = facts.status(), facts.healthy(ss.spec), facts.completed(ss.spec)
				if isExecHealthcheck(ss.spec) && facts.State.Running {
					ss.healthy = p.run(ctx, append([]string{"exec", ss.container}, ss.spec.Healthcheck.Test[1:]...)) == nil
				}
				ss.port = facts.hostPort(ss.spec)
			} else {
				effect = contracts.RuntimeEffectUnknown
			}
		}
		metrics := RuntimeMetrics{}
		metricsKnown := false
		if !destroyed && ss.failed == nil && p.config.MetricsReader != nil {
			var metricsErr error
			metrics, metricsErr = p.config.MetricsReader.ReadGroupRuntimeMetrics(ctx, ss.container)
			if metricsErr != nil {
				effect = contracts.RuntimeEffectUnknown
			} else {
				metricsKnown = true
				if metrics.Status != "" && metrics.Status != ss.status {
					effect = contracts.RuntimeEffectUnknown
				}
			}
		}
		ready := ss.healthy || ss.completed
		if !ready {
			if ss.spec.Required {
				requiredFailure = true
			} else {
				optionalFailure = true
			}
		}
		status := ss.status
		if destroyed {
			status = "stopped"
			ready = false
		}
		observedAt := p.config.Clock().UTC()
		if metricsKnown && !metrics.ObservedAt.IsZero() {
			observedAt = metrics.ObservedAt.UTC()
		}
		limits := ss.spec.Resources
		if metricsKnown {
			limits = metrics.Limits
			// Docker cgroups enforce CPU/memory/PIDs. The task-scoped disk
			// reservation belongs to the provider capacity contract rather than
			// the per-container cgroup, so retain that immutable requested fact.
			limits.DiskBytes = ss.spec.Resources.DiskBytes
		}
		observations = append(observations, contracts.RuntimeObservation{DeploymentID: deployment.ID, ServiceName: ss.spec.Name, ContainerID: metrics.ContainerID, Status: status, Healthy: ready, RestartCount: metrics.RestartCount, CPUUsageMillis: metrics.CPUMillicores, MemoryBytes: metrics.MemoryBytes, DiskBytes: metrics.DiskBytes, NetworkRxBytes: metrics.NetworkRxBytes, NetworkTxBytes: metrics.NetworkTxBytes, PIDsCurrent: metrics.PIDsCurrent, ChangedPaths: metrics.ChangedPaths, CgroupVerified: metrics.CgroupVerified, ExitReason: metrics.ExitReason, MetricsKnown: metricsKnown, HostPort: ss.port, Limits: limits, ObservedAt: observedAt, Evidence: p.evidence(request.Operation, "runtime.group.observe."+ss.spec.Name)})
	}
	status := deployment.Status.String()
	if destroyed || effect == contracts.RuntimeEffectUnknown {
		effect = contracts.RuntimeEffectUnknown
		status = "unknown"
	} else if requiredFailure {
		status = "failed"
	} else if optionalFailure {
		status = "degraded"
	} else {
		status = "runtime_ready"
	}
	observation := contracts.ServiceGroupRuntimeObservation{DeploymentID: deployment.ID, ReleaseID: deployment.ReleaseID, Status: status, Effect: effect, RolledBack: rolledBack, Services: observations, Evidence: p.evidence(request.Operation, "runtime.group.observe")}
	if err := observation.ValidateFor(state.spec); err != nil {
		return contracts.ServiceGroupRuntimeObservation{}, p.failure(request.Operation, contracts.CapabilityRuntimeObserveGroup, "observe_group", contracts.ErrValidation, "runtime group observation failed its aggregate contract: "+err.Error(), contracts.RetryAfterReconnect, true, err)
	}
	return observation, nil
}

// Facts returns a complete, redacted snapshot for integration evidence.  It
// intentionally contains no raw Docker inspect payload or environment value.
func (p *Provider) Facts(ctx context.Context, request contracts.ObserveGroupRequest) (GroupFacts, error) {
	observation, err := p.ObserveGroup(ctx, request)
	if err != nil {
		return GroupFacts{}, err
	}
	state, err := p.getGroup(ctx, request.DeploymentID, request.Operation, contracts.CapabilityRuntimeObserveGroup, "facts")
	if err != nil {
		return GroupFacts{}, err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	facts := GroupFacts{Deployment: state.deployment, Network: state.network, Capacity: mustAggregate(state.spec), Evidence: observation.Evidence}
	for _, service := range observation.Services {
		ss := state.services[service.ServiceName]
		if ss == nil {
			continue
		}
		fact := ServiceFacts{Name: ss.spec.Name, Container: ss.container, Status: service.Status, Healthy: service.Healthy, Completed: ss.completed, Required: ss.spec.Required, HostPort: service.HostPort, Limits: ss.spec.Resources, Image: ss.spec.Image}
		if ss.failed != nil {
			fact.Failure = ss.failed.Error()
		}
		facts.Services = append(facts.Services, fact)
	}
	for _, volume := range state.volumes {
		facts.Volumes = append(facts.Volumes, volume)
	}
	sort.Slice(facts.Services, func(i, j int) bool { return facts.Services[i].Name < facts.Services[j].Name })
	sort.Slice(facts.Volumes, func(i, j int) bool { return facts.Volumes[i].Name < facts.Volumes[j].Name })
	return facts, nil
}

// RestartGroupService performs the smallest M4 recovery effect: one named,
// owned container in one immutable ServiceGroup deployment. The request never
// carries a Docker name or command, and an idempotency replay cannot restart
// the service a second time.
func (p *Provider) RestartGroupService(ctx context.Context, request contracts.RestartGroupServiceRequest) (err error) {
	if err := request.Validate(); err != nil {
		return err
	}
	if err := p.check(ctx, request.Operation, contracts.CapabilityRuntimeRestartGroupService, "restart_group_service"); err != nil {
		return err
	}
	fingerprint := "restart-service:" + string(request.DeploymentID) + ":" + string(request.ServiceGroupID) + ":" + string(request.ReleaseID) + ":" + request.ServiceName
	record, replay, err := p.beginOperation(request.Operation.IdempotencyKey, fingerprint)
	if err != nil {
		return p.failure(request.Operation, contracts.CapabilityRuntimeRestartGroupService, "restart_group_service", contracts.ErrConflict, "restart idempotency key conflicts with another group service", contracts.RetryNever, false, err)
	}
	if replay {
		select {
		case <-record.done:
			return record.err
		case <-ctx.Done():
			return p.contextError(request.Operation, contracts.CapabilityRuntimeRestartGroupService, "restart_group_service", ctx.Err())
		}
	}
	var deployment domain.Deployment
	var state *groupState
	defer func() { p.finishOperation(request.Operation.IdempotencyKey, record, deployment, state, err) }()
	state, err = p.getGroup(ctx, request.DeploymentID, request.Operation, contracts.CapabilityRuntimeRestartGroupService, "restart_group_service")
	if err != nil {
		return err
	}
	state.mu.Lock()
	if state.deployment.ReleaseID != request.ReleaseID || state.spec.ServiceGroupID != request.ServiceGroupID || state.destroyed {
		state.mu.Unlock()
		return p.failure(request.Operation, contracts.CapabilityRuntimeRestartGroupService, "restart_group_service", contracts.ErrValidation, "restart target is outside the active immutable service group", contracts.RetryNever, false, nil)
	}
	service := state.services[request.ServiceName]
	if service == nil || strings.TrimSpace(service.container) == "" {
		state.mu.Unlock()
		return p.failure(request.Operation, contracts.CapabilityRuntimeRestartGroupService, "restart_group_service", contracts.ErrNotFound, "service is not owned by the active service group", contracts.RetryUserAction, false, nil)
	}
	container := service.container
	deployment = state.deployment
	state.mu.Unlock()
	if err = p.run(ctx, []string{"restart", "--time", "10", container}); err != nil {
		return p.commandError(request.Operation, contracts.CapabilityRuntimeRestartGroupService, "restart_group_service", err)
	}
	observationOperation := request.Operation
	observationOperation.IdempotencyKey += ":observe"
	observation, observeErr := p.ObserveGroup(ctx, contracts.ObserveGroupRequest{DeploymentID: request.DeploymentID, Operation: observationOperation})
	if observeErr != nil {
		err = observeErr
		return err
	}
	for _, observed := range observation.Services {
		if observed.ServiceName == request.ServiceName && observed.Healthy {
			if err = p.persistState(state); err != nil {
				return p.failure(request.Operation, contracts.CapabilityRuntimeRestartGroupService, "restart_group_service", contracts.ErrUnavailable, "restarted group state could not be persisted", contracts.RetryBackoff, true, err)
			}
			return nil
		}
	}
	err = p.failure(request.Operation, contracts.CapabilityRuntimeRestartGroupService, "restart_group_service", contracts.ErrUnavailable, "restarted service did not become healthy", contracts.RetryBackoff, true, nil)
	return err
}

// RestartGroup is the deliberately broad M4 fallback after more than one
// service is unhealthy.  It reuses the same ownership and idempotency gates as
// an exact service restart, but the set of containers comes solely from the
// persisted ServiceGroup state rather than from an Agent payload.
func (p *Provider) RestartGroup(ctx context.Context, request contracts.RestartGroupRequest) (err error) {
	if err := request.Validate(); err != nil {
		return err
	}
	if err := p.check(ctx, request.Operation, contracts.CapabilityRuntimeRestartGroup, "restart_group"); err != nil {
		return err
	}
	fingerprint := "restart-group:" + string(request.DeploymentID) + ":" + string(request.ServiceGroupID) + ":" + string(request.ReleaseID)
	record, replay, err := p.beginOperation(request.Operation.IdempotencyKey, fingerprint)
	if err != nil {
		return p.failure(request.Operation, contracts.CapabilityRuntimeRestartGroup, "restart_group", contracts.ErrConflict, "restart idempotency key conflicts with another group recovery", contracts.RetryNever, false, err)
	}
	if replay {
		select {
		case <-record.done:
			return record.err
		case <-ctx.Done():
			return p.contextError(request.Operation, contracts.CapabilityRuntimeRestartGroup, "restart_group", ctx.Err())
		}
	}
	var deployment domain.Deployment
	var state *groupState
	defer func() { p.finishOperation(request.Operation.IdempotencyKey, record, deployment, state, err) }()
	state, err = p.getGroup(ctx, request.DeploymentID, request.Operation, contracts.CapabilityRuntimeRestartGroup, "restart_group")
	if err != nil {
		return err
	}
	state.mu.Lock()
	if state.deployment.ReleaseID != request.ReleaseID || state.spec.ServiceGroupID != request.ServiceGroupID || state.destroyed {
		state.mu.Unlock()
		return p.failure(request.Operation, contracts.CapabilityRuntimeRestartGroup, "restart_group", contracts.ErrValidation, "restart target is outside the active immutable service group", contracts.RetryNever, false, nil)
	}
	// Dependency order is stable and comes from the immutable spec.  Restart
	// each currently owned, non-completed service in reverse order so a
	// dependent does not race ahead of a service it relies on.
	containers := make([]string, 0, len(state.order))
	for index := len(state.order) - 1; index >= 0; index-- {
		service := state.services[state.order[index]]
		if service != nil && !service.completed && strings.TrimSpace(service.container) != "" {
			containers = append(containers, service.container)
		}
	}
	deployment = state.deployment
	state.mu.Unlock()
	if len(containers) == 0 {
		return p.failure(request.Operation, contracts.CapabilityRuntimeRestartGroup, "restart_group", contracts.ErrInvalidTransition, "active service group has no restartable services", contracts.RetryNever, false, nil)
	}
	for _, container := range containers {
		if err = p.run(ctx, []string{"restart", "--time", "10", container}); err != nil {
			return p.commandError(request.Operation, contracts.CapabilityRuntimeRestartGroup, "restart_group", err)
		}
	}
	observationOperation := request.Operation
	observationOperation.IdempotencyKey += ":observe"
	observation, observeErr := p.ObserveGroup(ctx, contracts.ObserveGroupRequest{DeploymentID: request.DeploymentID, Operation: observationOperation})
	if observeErr != nil {
		err = observeErr
		return err
	}
	if observation.Status != "runtime_ready" || !allGroupServicesHealthy(observation.Services) {
		err = p.failure(request.Operation, contracts.CapabilityRuntimeRestartGroup, "restart_group", contracts.ErrUnavailable, "restarted service group did not become healthy", contracts.RetryBackoff, true, nil)
		return err
	}
	if err = p.persistState(state); err != nil {
		return p.failure(request.Operation, contracts.CapabilityRuntimeRestartGroup, "restart_group", contracts.ErrUnavailable, "restarted group state could not be persisted", contracts.RetryBackoff, true, err)
	}
	return nil
}

func allGroupServicesHealthy(services []contracts.RuntimeObservation) bool {
	for _, service := range services {
		if !service.Healthy {
			return false
		}
	}
	return true
}

func (p *Provider) RollbackGroup(ctx context.Context, request contracts.RollbackGroupRequest) (domain.Deployment, error) {
	if err := p.check(ctx, request.Operation, contracts.CapabilityRuntimeRollbackGroup, "rollback_group"); err != nil {
		return domain.Deployment{}, err
	}
	if err := request.Target.Validate(); err != nil {
		return domain.Deployment{}, p.failure(request.Operation, contracts.CapabilityRuntimeRollbackGroup, "rollback_group", contracts.ErrValidation, "rollback target is invalid", contracts.RetryNever, false, err)
	}
	if request.DeploymentID.Empty() || request.TargetDeploymentID.Empty() || request.DeploymentID == request.TargetDeploymentID {
		return domain.Deployment{}, p.failure(request.Operation, contracts.CapabilityRuntimeRollbackGroup, "rollback_group", contracts.ErrValidation, "rollback source and target deployment identities must be distinct", contracts.RetryNever, false, nil)
	}
	// Keep the current deployment available until the rollback candidate has
	// passed health checks.  A failed rollback therefore leaves the known-good
	// version serving rather than turning a recovery action into an outage.
	request.Target.Rollout = contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutRolling, PreviousDeploymentID: request.DeploymentID, PreserveOldUntilHealthy: true, DeferOldTeardown: true}
	return p.DeployGroup(ctx, contracts.DeployGroupRequest{DeploymentID: request.TargetDeploymentID, Spec: request.Target, Operation: request.Operation, ForceRecreate: true})
}

func (p *Provider) DestroyGroup(ctx context.Context, request contracts.DestroyRequest) error {
	if err := p.check(ctx, request.Operation, contracts.CapabilityRuntimeDestroyGroup, "destroy_group"); err != nil {
		return err
	}
	state, err := p.getGroup(ctx, request.DeploymentID, request.Operation, contracts.CapabilityRuntimeDestroyGroup, "destroy_group")
	if err != nil {
		return err
	}
	state.mu.Lock()
	if state.destroyed {
		state.mu.Unlock()
		return nil
	}
	state.mu.Unlock()
	if !request.PreserveVolumes {
		return p.failure(request.Operation, contracts.CapabilityRuntimeDestroyGroup, "destroy_group", contracts.ErrForbidden, "group destroy cannot bulk-delete volumes; destroy each exact volume separately", contracts.RetryUserAction, false, nil)
	}
	if err := p.stopGroup(ctx, state, request.Operation); err != nil {
		return err
	}
	for name, volume := range state.volumes {
		detachOp := request.Operation
		detachOp.IdempotencyKey += ":volume-detach:" + name
		_ = p.config.Volumes.Detach(ctx, contracts.VolumeRequest{Volume: volume, Operation: detachOp})
		retainOp := request.Operation
		retainOp.IdempotencyKey += ":volume-retain:" + name
		if err := p.config.Volumes.Retain(ctx, contracts.VolumeRequest{Volume: volume, Operation: retainOp}); err != nil {
			return err
		}
	}
	if err := p.removeDurableState(request.DeploymentID); err != nil {
		return p.failure(request.Operation, contracts.CapabilityRuntimeDestroyGroup, "destroy_group", contracts.ErrUnavailable, "durable service group state could not be removed after known destroy", contracts.RetryBackoff, true, err)
	}
	p.markDestroyed(state)
	return nil
}

// DestroyVolume is the narrow destructive escape hatch for one exact
// physical claim.  DestroyGroup intentionally refuses PreserveVolumes=false
// so a generic group confirmation can never be replayed against multiple
// data volumes.  Callers must first stop the group, then provide the exact
// provider-scoped token for this one logical claim.
func (p *Provider) DestroyVolume(ctx context.Context, deploymentID domain.ID, volumeName, confirmationToken string, operation contracts.OperationContext) error {
	if err := p.check(ctx, operation, contracts.CapabilityRuntimeDestroyGroup, "destroy_volume"); err != nil {
		return err
	}
	if strings.TrimSpace(volumeName) == "" || strings.TrimSpace(confirmationToken) == "" {
		return p.failure(operation, contracts.CapabilityRuntimeDestroyGroup, "destroy_volume", contracts.ErrForbidden, "exact volume name and confirmation token are required", contracts.RetryUserAction, false, nil)
	}
	state, err := p.getGroup(ctx, deploymentID, operation, contracts.CapabilityRuntimeDestroyGroup, "destroy_volume")
	if err != nil {
		return err
	}
	state.mu.Lock()
	if !state.destroyed {
		state.mu.Unlock()
		return p.failure(operation, contracts.CapabilityRuntimeDestroyGroup, "destroy_volume", contracts.ErrConflict, "service group must be stopped before deleting a volume", contracts.RetryUserAction, false, nil)
	}
	volume, ok := state.volumes[volumeName]
	state.mu.Unlock()
	if !ok {
		return p.failure(operation, contracts.CapabilityRuntimeDestroyGroup, "destroy_volume", contracts.ErrNotFound, "runtime volume claim was not found", contracts.RetryUserAction, false, nil)
	}
	detachOp := operation
	detachOp.IdempotencyKey += ":volume-detach:" + volumeName
	_ = p.config.Volumes.Detach(ctx, contracts.VolumeRequest{Volume: volume, Operation: detachOp})
	destroyOp := operation
	destroyOp.IdempotencyKey += ":volume-destroy:" + volumeName
	if err := p.config.Volumes.Destroy(ctx, contracts.VolumeRequest{Volume: volume, ConfirmationToken: confirmationToken, Operation: destroyOp}); err != nil {
		return err
	}
	state.mu.Lock()
	delete(state.volumes, volumeName)
	state.mu.Unlock()
	return nil
}

// Logs exposes one service at a time.  Group observation remains redacted;
// callers must use the existing operation/audit boundary when consuming this
// intentionally sensitive stream.
func (p *Provider) Logs(ctx context.Context, request contracts.LogsRequest) (<-chan string, error) {
	if err := p.check(ctx, request.Operation, contracts.CapabilityRuntimeLogsGroup, "logs_group"); err != nil {
		return nil, err
	}
	state, err := p.getGroup(ctx, request.DeploymentID, request.Operation, contracts.CapabilityRuntimeLogsGroup, "logs_group")
	if err != nil {
		return nil, err
	}
	serviceName := strings.TrimSpace(request.ServiceName)
	state.mu.Lock()
	service := state.services[serviceName]
	state.mu.Unlock()
	if service == nil {
		return nil, p.failure(request.Operation, contracts.CapabilityRuntimeLogsGroup, "logs_group", contracts.ErrNotFound, "runtime service was not found", contracts.RetryUserAction, false, nil)
	}
	args := []string{"logs", "--timestamps"}
	if request.Tail > 0 {
		args = append(args, "--tail", strconv.Itoa(request.Tail))
	}
	if !request.Since.IsZero() {
		args = append(args, "--since", request.Since.UTC().Format(time.RFC3339))
	}
	args = append(args, service.container)
	out, err := p.outputLogs(ctx, args)
	if err != nil {
		return nil, p.commandError(request.Operation, contracts.CapabilityRuntimeLogsGroup, "logs_group", err)
	}
	lines := make(chan string, strings.Count(out, "\n")+1)
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if line != "" {
			lines <- line
		}
	}
	close(lines)
	return lines, nil
}

func (p *Provider) outputLogs(ctx context.Context, args []string) (string, error) {
	var stdout, stderr bytes.Buffer
	if err := p.config.Runner.Run(ctx, p.config.Command, args, &stdout, &stderr); err != nil {
		return "", err
	}
	// Docker preserves application stdout/stderr as distinct command streams.
	// Runtime logging is the one typed read path that must retain both; all
	// bytes cross the Agent redaction boundary before persistence.
	return stdout.String() + stderr.String(), nil
}

func (p *Provider) getGroup(ctx context.Context, id domain.ID, operation contracts.OperationContext, capability contracts.Capability, action string) (*groupState, error) {
	if id.Empty() {
		return nil, p.failure(operation, capability, action, contracts.ErrInvalidArgument, "deployment id is required", contracts.RetryNever, false, nil)
	}
	p.mu.Lock()
	state := p.groups[id]
	p.mu.Unlock()
	if state == nil {
		snapshot, found, readErr := p.readDurableState(id)
		if readErr != nil {
			return nil, p.failure(operation, capability, action, contracts.ErrUnavailable, "durable service group state could not be read", contracts.RetryAfterReconnect, true, readErr)
		}
		if !found || snapshot.Deployment.Status == domain.DeploymentStopped {
			return nil, p.failure(operation, capability, action, contracts.ErrNotFound, "managed service group was not found", contracts.RetryUserAction, false, nil)
		}
		loadedState, loadErr := p.stateFromDurable(ctx, snapshot, operation, capability, action)
		if loadErr != nil {
			return nil, loadErr
		}
		p.mu.Lock()
		if existing := p.groups[id]; existing != nil {
			state = existing
		} else {
			state = loadedState
			p.groups[id] = loadedState
		}
		p.mu.Unlock()
	}
	return state, nil
}

func (p *Provider) inspectContainer(ctx context.Context, container string) (inspectFacts, error) {
	out, err := p.output(ctx, []string{"container", "inspect", "--format", "{{json .}}", container})
	if err != nil {
		return inspectFacts{}, err
	}
	var facts inspectFacts
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &facts); err != nil {
		return inspectFacts{}, err
	}
	return facts, nil
}

type inspectFacts struct {
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	Image string `json:"Image"`
	State struct {
		Status   string `json:"Status"`
		Running  bool   `json:"Running"`
		ExitCode int    `json:"ExitCode"`
		Health   *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
		Memory      int64  `json:"Memory"`
		MemorySwap  int64  `json:"MemorySwap"`
		CPUQuota    int64  `json:"CpuQuota"`
		CPUPeriod   int64  `json:"CpuPeriod"`
		PidsLimit   int64  `json:"PidsLimit"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
		Networks map[string]struct{} `json:"Networks"`
	} `json:"NetworkSettings"`
}

func (f inspectFacts) matches(prefix string, deployment, groupID domain.ID, service contracts.ServiceRuntimeSpec, network string) bool {
	return f.matchesOwner(prefix, deployment, deployment, groupID, service, network)
}

func (f inspectFacts) matchesOwner(prefix string, deployment, ownerDeployment, ownerGroupID domain.ID, service contracts.ServiceRuntimeSpec, network string) bool {
	labels := f.Config.Labels
	image := f.Image
	if image == "" {
		image = f.Config.Image
	}
	imageMatches := image == service.Image.Digest || f.Config.Image == imageReference(service.Image)
	return labels["open-card.managed"] == "true" && labels["open-card.task-prefix"] == prefix && labels["open-card.deployment-id"] == string(ownerDeployment) && labels["open-card.service-group-id"] == string(ownerGroupID) && labels["open-card.service"] == service.Name && labels["open-card.service-name"] == service.Name && labels["open-card.service-role"] == string(service.Role) && imageMatches && (f.HostConfig.NetworkMode == network || f.hasNetwork(network)) && f.HostConfig.Memory == service.Resources.MemoryBytes && f.HostConfig.MemorySwap == service.Resources.MemoryBytes && f.HostConfig.CPUPeriod == 100000 && f.HostConfig.CPUQuota == service.Resources.CPUMillis*100 && f.HostConfig.PidsLimit == service.Resources.PIDs && strings.TrimSpace(string(deployment)) != ""
}

func (f inspectFacts) hasNetwork(network string) bool {
	_, ok := f.NetworkSettings.Networks[network]
	return ok
}

func (f inspectFacts) status() string {
	if strings.TrimSpace(f.State.Status) == "" {
		return "unknown"
	}
	return f.State.Status
}

func (f inspectFacts) healthy(service contracts.ServiceRuntimeSpec) bool {
	if service.Healthcheck == nil || service.Healthcheck.Disabled {
		return f.State.Running
	}
	return f.State.Running && f.State.Health != nil && f.State.Health.Status == "healthy"
}

func (f inspectFacts) completed(service contracts.ServiceRuntimeSpec) bool {
	return service.Role == domain.RoleOneShot && !f.State.Running && f.State.Status == "exited" && f.State.ExitCode == 0
}

func (f inspectFacts) hostPort(service contracts.ServiceRuntimeSpec) int {
	if len(service.ContainerPorts) == 0 {
		return 0
	}
	bindings := f.NetworkSettings.Ports[strconv.Itoa(service.ContainerPorts[0])+"/tcp"]
	if len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" {
		return 0
	}
	port, err := strconv.Atoi(bindings[0].HostPort)
	if err != nil || port < 1 || port > 65535 {
		return 0
	}
	return port
}

func dependenciesSatisfied(state *groupState, service contracts.ServiceRuntimeSpec) bool {
	for _, dependency := range service.Dependencies {
		dep := state.services[dependency.Service]
		if dep == nil || dep.failed != nil {
			return false
		}
		switch dependency.Condition {
		case domain.DependsStarted:
			if dep.status == "" || dep.status == "created" || dep.status == "failed" || dep.status == "skipped" {
				return false
			}
		case domain.DependsHealthy:
			if !dep.healthy {
				return false
			}
		case domain.DependsCompleted:
			if !dep.completed {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func serviceByName(services []contracts.ServiceRuntimeSpec, name string) *contracts.ServiceRuntimeSpec {
	for index := range services {
		if services[index].Name == name {
			return &services[index]
		}
	}
	return nil
}

func entryService(spec contracts.ServiceGroupRuntimeSpec) *contracts.ServiceRuntimeSpec {
	return serviceByName(spec.Services, spec.EntryService)
}

func (p *Provider) containerName(deploymentID domain.ID, service string) string {
	return p.config.TaskPrefix + "-group-" + shortHash(string(deploymentID)) + "-" + service
}

func (p *Provider) networkFor(groupID, deploymentID domain.ID) string {
	group := strings.TrimPrefix(string(groupID), "group_")
	name := p.config.Network + "-" + group + "-" + shortHash(string(deploymentID))
	if len(name) > 240 {
		name = name[:200] + "-" + shortHash(name)
	}
	return name
}

func (p *Provider) ingressNetworkFor(groupID, deploymentID domain.ID) string {
	name := p.networkFor(groupID, deploymentID) + "-ingress"
	if len(name) > 240 {
		name = name[:200] + "-ingress-" + shortHash(name)
	}
	return name
}

func (p *Provider) copyArchive(source io.Reader) (string, error) {
	file, err := os.CreateTemp(p.config.WorkRoot, ".standalone-group-oci-*.tar")
	if err != nil {
		return "", err
	}
	path := file.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return "", err
	}
	n, copyErr := io.Copy(file, io.LimitReader(source, p.config.MaxOCIBytes+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return "", errors.Join(copyErr, closeErr)
	}
	if n <= 0 || n > p.config.MaxOCIBytes {
		return "", errors.New("OCI archive exceeds configured limit or is empty")
	}
	ok = true
	return path, nil
}

func (p *Provider) run(ctx context.Context, args []string) error {
	_, err := p.output(ctx, args)
	return err
}

func (p *Provider) output(ctx context.Context, args []string) (string, error) {
	var stdout, stderr bytes.Buffer
	if err := p.config.Runner.Run(ctx, p.config.Command, args, &stdout, &stderr); err != nil {
		return "", err
	}
	return stdout.String(), nil
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
	return &contracts.ProviderError{Provider: p.metadata.Name, Code: code, Message: message, Retry: retry, Retryable: retryable, Capability: capability, Operation: action, Cause: cause, Details: map[string]string{"evidence_ref": string(evidenceID(p.metadata.Name, action, operation.IdempotencyKey)), "log_ref": "runtime://" + p.metadata.Name + "/" + action + "/" + shortHash(operation.IdempotencyKey)}}
}

func (p *Provider) evidence(operation contracts.OperationContext, kind string) contracts.Evidence {
	digest := "sha256:" + hash(p.metadata.Name, kind, operation.IdempotencyKey)
	return contracts.Evidence{Refs: []domain.EvidenceRef{{ID: evidenceID(p.metadata.Name, kind, operation.IdempotencyKey), Kind: kind, Digest: digest, Locator: "runtime://" + p.metadata.Name + "/" + kind + "/" + shortHash(operation.IdempotencyKey)}}, Summary: "redacted standalone group runtime fact", Digest: digest, Redacted: true}
}

func (p *Provider) fingerprint(id domain.ID, spec contracts.ServiceGroupRuntimeSpec) string {
	canonical := canonicalSpec(spec)
	data, _ := json.Marshal(struct {
		ID   domain.ID                         `json:"id"`
		Spec contracts.ServiceGroupRuntimeSpec `json:"spec"`
	}{id, canonical})
	return "sha256:" + hash(string(data))
}

func canonicalSpec(spec contracts.ServiceGroupRuntimeSpec) contracts.ServiceGroupRuntimeSpec {
	spec.Services = append([]contracts.ServiceRuntimeSpec(nil), spec.Services...)
	spec.VolumeClaims = append([]contracts.RuntimeVolumeClaim(nil), spec.VolumeClaims...)
	sort.Slice(spec.Services, func(i, j int) bool { return spec.Services[i].Name < spec.Services[j].Name })
	sort.Slice(spec.VolumeClaims, func(i, j int) bool { return spec.VolumeClaims[i].Name < spec.VolumeClaims[j].Name })
	for i := range spec.Services {
		s := &spec.Services[i]
		s.Dependencies = append([]domain.ServiceDependency(nil), s.Dependencies...)
		s.Volumes = append([]domain.VolumeMount(nil), s.Volumes...)
		s.Environment = append([]contracts.RuntimeEnvironmentVariable(nil), s.Environment...)
		s.ContainerPorts = append([]int(nil), s.ContainerPorts...)
		sort.Slice(s.Dependencies, func(a, b int) bool { return s.Dependencies[a].Service < s.Dependencies[b].Service })
		sort.Slice(s.Volumes, func(a, b int) bool { return s.Volumes[a].Name < s.Volumes[b].Name })
		sort.Slice(s.Environment, func(a, b int) bool { return s.Environment[a].Name < s.Environment[b].Name })
		sort.Ints(s.ContainerPorts)
	}
	return spec
}

func mustAggregate(spec contracts.ServiceGroupRuntimeSpec) contracts.ResourceLimits {
	value, _ := spec.AggregateResources()
	return value
}

func validateRestart(policy string) error {
	switch strings.TrimSpace(policy) {
	case "", "no", "always", "on-failure", "unless-stopped":
		return nil
	default:
		return fmt.Errorf("unsupported restart policy %q", policy)
	}
}

func validateRuntimeNames(spec contracts.ServiceGroupRuntimeSpec) error {
	if !safeName.MatchString(spec.EntryService) {
		return errors.New("entry service name is not safe")
	}
	for _, service := range spec.Services {
		if !safeName.MatchString(service.Name) {
			return fmt.Errorf("service %q has an unsafe name", service.Name)
		}
		for _, env := range service.Environment {
			if !safeName.MatchString(env.Name) || strings.ContainsAny(env.Name, "=,\r\n\x00") {
				return fmt.Errorf("service %q has an unsafe environment name", service.Name)
			}
		}
	}
	for _, claim := range spec.VolumeClaims {
		if !safeName.MatchString(claim.Name) || strings.Contains(claim.Name, "..") {
			return fmt.Errorf("volume claim %q has an unsafe name", claim.Name)
		}
	}
	return nil
}

func digestKey(image domain.ImageDigest) string {
	return shortHash(image.Repository + "@" + image.Digest)
}
func imageReference(image domain.ImageDigest) string { return image.Repository + "@" + image.Digest }
func shortHash(value string) string                  { return hash(value)[:20] }

func hash(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func evidenceID(parts ...string) domain.ID {
	return domain.ID("ev_" + shortHash(strings.Join(parts, "\x00")))
}
