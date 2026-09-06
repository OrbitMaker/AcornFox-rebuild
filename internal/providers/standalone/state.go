package standalone

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const durableRuntimeStateSchema = "1"

type durableRuntimeAction struct {
	IdentityHash        string    `json:"identity_hash"`
	Action              string    `json:"action"`
	Fingerprint         string    `json:"fingerprint"`
	Status              string    `json:"status"`
	PreviousContainerID string    `json:"previous_container_id,omitempty"`
	PreviousStartedAt   string    `json:"previous_started_at,omitempty"`
	ReleaseAttempt      int       `json:"release_attempt,omitempty"`
	At                  time.Time `json:"at"`
}

// durableRuntimeState contains only recovery facts. RuntimeSpec secrets are
// forbidden by this provider and are cleared defensively before encoding.
type durableRuntimeState struct {
	SchemaVersion   string                   `json:"schema_version"`
	Deployment      domain.Deployment        `json:"deployment"`
	Spec            contracts.RuntimeSpec    `json:"spec"`
	Fingerprint     string                   `json:"fingerprint"`
	Container       string                   `json:"container"`
	ContainerID     string                   `json:"container_id,omitempty"`
	Phase           string                   `json:"phase"`
	Capacity        *contracts.CapacityLease `json:"capacity,omitempty"`
	LeaseGeneration int                      `json:"lease_generation,omitempty"`
	Actions         []durableRuntimeAction   `json:"actions,omitempty"`
	CreatedAt       time.Time                `json:"created_at"`
	UpdatedAt       time.Time                `json:"updated_at"`
}

type runtimeAction struct {
	identityHash        string
	action              string
	fingerprint         string
	status              string
	previousContainerID string
	previousStartedAt   string
	releaseAttempt      int
	at                  time.Time
}

type capacityActiveReconciler interface {
	ReconcileActive(context.Context, contracts.CapacityLease, contracts.OperationContext) error
}

func (p *Provider) durableStatePath(id domain.ID) string {
	if id.Empty() {
		return ""
	}
	return filepath.Join(p.config.WorkRoot, ".standalone-state-"+hash(id.String())[:32]+".json")
}

func (p *Provider) durableSnapshot(state *runtimeState) durableRuntimeState {
	actions := make([]durableRuntimeAction, 0, len(state.actions))
	for _, action := range state.actions {
		actions = append(actions, durableRuntimeAction{IdentityHash: action.identityHash, Action: action.action, Fingerprint: action.fingerprint, Status: action.status, PreviousContainerID: action.previousContainerID, PreviousStartedAt: action.previousStartedAt, ReleaseAttempt: action.releaseAttempt, At: action.at.UTC()})
	}
	sort.Slice(actions, func(i, j int) bool { return actions[i].IdentityHash < actions[j].IdentityHash })
	spec := contracts.RuntimeSpec{ApplicationID: state.deployment.ApplicationID, EnvironmentID: state.deployment.EnvironmentID, ReleaseID: state.deployment.ReleaseID, ServiceName: state.service, Image: state.image, Resources: state.resources, Port: state.containerPort}
	return durableRuntimeState{SchemaVersion: durableRuntimeStateSchema, Deployment: state.deployment, Spec: spec, Fingerprint: state.fingerprint, Container: state.container, ContainerID: state.containerID, Phase: state.phase, Capacity: state.capacity, LeaseGeneration: state.leaseGeneration, Actions: actions, CreatedAt: state.createdAt.UTC(), UpdatedAt: state.updatedAt.UTC()}
}

func (p *Provider) persistState(state *runtimeState) error {
	path := p.durableStatePath(state.deployment.ID)
	snapshot := p.durableSnapshot(state)
	if err := validateDurableRuntimeState(snapshot, p.config); err != nil {
		return err
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode standalone state: %w", err)
	}
	temporary, err := os.CreateTemp(p.config.WorkRoot, ".standalone-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create standalone state temporary: %w", err)
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
		return fmt.Errorf("secure standalone state temporary: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write standalone state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync standalone state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close standalone state: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish standalone state: %w", err)
	}
	keep = true
	return syncRuntimeStateDirectory(p.config.WorkRoot)
}

func syncRuntimeStateDirectory(root string) error {
	directory, err := os.Open(root)
	if err != nil {
		return fmt.Errorf("open standalone state directory: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return fmt.Errorf("sync standalone state directory: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close standalone state directory: %w", closeErr)
	}
	return nil
}

func (p *Provider) readDurableState(id domain.ID) (durableRuntimeState, bool, error) {
	path := p.durableStatePath(id)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return durableRuntimeState{}, false, nil
	}
	if err != nil {
		return durableRuntimeState{}, false, fmt.Errorf("stat standalone state: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return durableRuntimeState{}, false, errors.New("standalone state permissions or file type are unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return durableRuntimeState{}, false, fmt.Errorf("open standalone state: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var snapshot durableRuntimeState
	if err := decoder.Decode(&snapshot); err != nil {
		return durableRuntimeState{}, false, fmt.Errorf("decode standalone state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return durableRuntimeState{}, false, errors.New("standalone state contains trailing data")
	}
	if err := validateDurableRuntimeState(snapshot, p.config); err != nil {
		return durableRuntimeState{}, false, err
	}
	if snapshot.Deployment.ID != id {
		return durableRuntimeState{}, false, errors.New("standalone state deployment identity does not match filename")
	}
	return snapshot, true, nil
}

func validateDurableRuntimeState(snapshot durableRuntimeState, config Config) error {
	if snapshot.SchemaVersion != durableRuntimeStateSchema || snapshot.Phase != "pending" && snapshot.Phase != "active" && snapshot.Phase != "destroying" && snapshot.Phase != "destroyed" {
		return errors.New("standalone state schema or phase is unsupported")
	}
	if err := snapshot.Deployment.Validate(); err != nil {
		return fmt.Errorf("standalone state deployment: %w", err)
	}
	if err := (&Provider{config: config, metadata: contracts.ProviderMetadata{Name: providerName}}).validateSpec(snapshot.Spec, contracts.OperationContext{IdempotencyKey: "state"}); err != nil {
		return errors.New("standalone state spec is invalid")
	}
	if snapshot.Deployment.ApplicationID != snapshot.Spec.ApplicationID || snapshot.Deployment.EnvironmentID != snapshot.Spec.EnvironmentID || snapshot.Deployment.ReleaseID != snapshot.Spec.ReleaseID || snapshot.Fingerprint == "" || snapshot.Fingerprint != (&Provider{}).fingerprint(snapshot.Deployment.ID, snapshot.Spec) || snapshot.Container != config.TaskPrefix+"-runtime-"+hash(snapshot.Deployment.ID.String())[:20] || snapshot.CreatedAt.IsZero() || snapshot.UpdatedAt.IsZero() {
		return errors.New("standalone state identity is invalid")
	}
	if snapshot.LeaseGeneration < 0 || snapshot.Capacity != nil && (snapshot.Capacity.ID == "" || snapshot.Capacity.Scope != contracts.CapacityRuntime || snapshot.Capacity.Resources != snapshot.Spec.Resources || (snapshot.Spec.Port == 0 && snapshot.Capacity.HostPort != 0) || (snapshot.Spec.Port != 0 && (snapshot.Capacity.HostPort < 1 || snapshot.Capacity.HostPort > 65535))) {
		return errors.New("standalone state capacity is invalid")
	}
	seen := map[string]struct{}{}
	for _, action := range snapshot.Actions {
		if action.IdentityHash == "" || !validRuntimeActionName(action.Action) || action.Fingerprint != snapshot.Fingerprint || (action.Status != "started" && action.Status != "succeeded") || action.At.IsZero() {
			return errors.New("standalone state action is invalid")
		}
		if _, ok := seen[action.IdentityHash]; ok {
			return errors.New("standalone state action is duplicated")
		}
		seen[action.IdentityHash] = struct{}{}
	}
	return nil
}

func (p *Provider) stateFromDurable(ctx context.Context, snapshot durableRuntimeState, operation contracts.OperationContext, capability contracts.Capability, action string) (*runtimeState, error) {
	state := &runtimeState{deployment: snapshot.Deployment, service: snapshot.Spec.ServiceName, image: snapshot.Spec.Image, container: snapshot.Container, containerID: snapshot.ContainerID, containerPort: snapshot.Spec.Port, fingerprint: snapshot.Fingerprint, phase: snapshot.Phase, capacity: snapshot.Capacity, leaseGeneration: snapshot.LeaseGeneration, resources: snapshot.Spec.Resources, createdAt: snapshot.CreatedAt, updatedAt: snapshot.UpdatedAt, actions: map[string]runtimeAction{}}
	for _, persisted := range snapshot.Actions {
		state.actions[persisted.IdentityHash] = runtimeAction{identityHash: persisted.IdentityHash, action: persisted.Action, fingerprint: persisted.Fingerprint, status: persisted.Status, previousContainerID: persisted.PreviousContainerID, previousStartedAt: persisted.PreviousStartedAt, releaseAttempt: persisted.ReleaseAttempt, at: persisted.At}
	}
	if state.phase == "destroyed" {
		state.destroyed = true
		if state.capacity != nil {
			reconciler, ok := p.config.Capacity.(capacityActiveReconciler)
			if !ok {
				return nil, p.failure(operation, capability, action, contracts.ErrUnavailable, "capacity provider cannot reconcile pending runtime release", contracts.RetryAfterReconnect, true, nil)
			}
			reconcileOp := operation
			reconcileOp.IdempotencyKey = "runtime-reconcile-" + hash(state.deployment.ID.String())[:24]
			if err := reconciler.ReconcileActive(ctx, *state.capacity, reconcileOp); err != nil {
				return nil, err
			}
		}
		return state, nil
	}
	facts, err := p.inspectFacts(ctx, state.container)
	if err != nil {
		if state.phase == "pending" || state.phase == "destroying" {
			absent, absenceErr := p.confirmContainerAbsent(ctx, state.container)
			if absenceErr != nil {
				return nil, p.failure(operation, capability, action, contracts.ErrUnavailable, "durable runtime absence could not be confirmed", contracts.RetryAfterReconnect, true, absenceErr)
			}
			if absent && state.phase == "destroying" {
				state.destroyed, state.phase, state.port = true, "destroyed", 0
				if state.capacity != nil {
					reconciler, ok := p.config.Capacity.(capacityActiveReconciler)
					if !ok {
						return nil, p.failure(operation, capability, action, contracts.ErrUnavailable, "capacity provider cannot reconcile pending runtime release", contracts.RetryAfterReconnect, true, nil)
					}
					reconcileOp := operation
					reconcileOp.IdempotencyKey = "runtime-reconcile-" + hash(state.deployment.ID.String())[:24]
					if reconcileErr := reconciler.ReconcileActive(ctx, *state.capacity, reconcileOp); reconcileErr != nil {
						return nil, reconcileErr
					}
				}
				return state, nil
			}
			if absent && state.phase == "pending" {
				if state.capacity != nil {
					reconciler, ok := p.config.Capacity.(capacityActiveReconciler)
					if !ok {
						return nil, p.failure(operation, capability, action, contracts.ErrUnavailable, "capacity provider cannot reconcile pending runtime lease", contracts.RetryAfterReconnect, true, nil)
					}
					reconcileOp := operation
					reconcileOp.IdempotencyKey = "runtime-reconcile-" + hash(state.deployment.ID.String())[:24]
					if reconcileErr := reconciler.ReconcileActive(ctx, *state.capacity, reconcileOp); reconcileErr != nil {
						return nil, reconcileErr
					}
					releaseOp := operation
					releaseOp.IdempotencyKey = "runtime-pending-release-" + hash(state.deployment.ID.String(), fmt.Sprint(state.leaseGeneration))[:24]
					if releaseErr := p.config.Capacity.Release(ctx, *state.capacity, releaseOp); releaseErr != nil {
						return nil, releaseErr
					}
					state.capacity = nil
					state.leaseGeneration++
				}
				state.recovery, state.updatedAt = runtimeRecoveryPendingAbsent, p.config.Clock().UTC()
				if persistErr := p.persistState(state); persistErr != nil {
					return nil, p.failure(operation, capability, action, contracts.ErrUnavailable, "pending absent runtime state could not be persisted", contracts.RetryBackoff, true, persistErr)
				}
				return state, nil
			}
		}
		return nil, p.failure(operation, capability, action, contracts.ErrUnavailable, "durable runtime container could not be inspected", contracts.RetryAfterReconnect, true, nil)
	}
	port, ok := facts.matchesConfiguration(p.config, state.deployment, snapshot.Spec)
	if !ok {
		return nil, p.failure(operation, capability, action, contracts.ErrConflict, "durable runtime facts do not match the immutable deployment", contracts.RetryNever, false, nil)
	}
	state.port, state.containerID = port, facts.ID
	if snapshot.Phase == "pending" {
		if facts.State.Running {
			state.phase, state.recovery = "active", runtimeRecoveryPendingRunning
		} else {
			state.phase, state.recovery = "pending", runtimeRecoveryPendingNotRunning
		}
	} else {
		state.phase, state.recovery = "active", runtimeRecoveryActive
	}
	if state.capacity == nil {
		return nil, p.failure(operation, capability, action, contracts.ErrConflict, "durable runtime state has no active capacity lease", contracts.RetryNever, false, nil)
	}
	reconciler, ok := p.config.Capacity.(capacityActiveReconciler)
	if !ok {
		return nil, p.failure(operation, capability, action, contracts.ErrUnavailable, "capacity provider cannot reconcile active runtime lease", contracts.RetryAfterReconnect, true, nil)
	}
	reconcileOp := operation
	reconcileOp.IdempotencyKey = "runtime-reconcile-" + hash(state.deployment.ID.String())[:24]
	if err := reconciler.ReconcileActive(ctx, *state.capacity, reconcileOp); err != nil {
		return nil, err
	}
	return state, nil
}

// confirmContainerAbsent uses a successful, bounded daemon list query rather
// than treating an inspect error as absence. It intentionally returns an
// error when the daemon cannot answer the query.
func (p *Provider) confirmContainerAbsent(ctx context.Context, container string) (bool, error) {
	output, err := p.output(ctx, []string{"container", "ls", "--all", "--filter", "name=^/" + container + "$", "--format", "{{.Names}}"})
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(output) == "", nil
}

// Reconcile restores every owned durable runtime state without allocating a
// port or creating a container. Installed hosts may resume stopped active
// containers only through RestoreActiveGuard. Any unsafe state stops reconciliation.
func (p *Provider) Reconcile(ctx context.Context) error {
	entries, err := filepath.Glob(filepath.Join(p.config.WorkRoot, ".standalone-state-*.json"))
	if err != nil {
		return err
	}
	for _, path := range entries {
		base := filepath.Base(path)
		if !strings.HasPrefix(base, ".standalone-state-") || !strings.HasSuffix(base, ".json") {
			return errors.New("standalone state filename is unsafe")
		}
		// The filename is only an opaque hash; decode first, then bind it to its
		// own deterministic state path before accepting it.
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
			return errors.New("standalone state file is unsafe")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		decoder := json.NewDecoder(file)
		decoder.DisallowUnknownFields()
		var snapshot durableRuntimeState
		decodeErr := decoder.Decode(&snapshot)
		var trailing any
		trailingErr := decoder.Decode(&trailing)
		_ = file.Close()
		if decodeErr != nil || trailingErr != io.EOF || validateDurableRuntimeState(snapshot, p.config) != nil || p.durableStatePath(snapshot.Deployment.ID) != path {
			return errors.New("standalone state file is invalid")
		}
		state, err := p.stateFromDurable(ctx, snapshot, contracts.OperationContext{IdempotencyKey: "runtime-reconcile-" + hash(snapshot.Deployment.ID.String())[:24]}, contracts.CapabilityRuntimeObserve, "reconcile")
		if err != nil {
			return err
		}
		if err := p.restoreActive(ctx, snapshot, state); err != nil {
			return err
		}
		p.mu.Lock()
		if existing := p.states[state.deployment.ID]; existing == nil {
			p.states[state.deployment.ID] = state
		}
		p.mu.Unlock()
	}
	return nil
}

type inspectFacts struct {
	ID           string `json:"Id"`
	Image        string `json:"Image"`
	RestartCount uint64 `json:"RestartCount"`
	Config       struct {
		Labels  map[string]string `json:"Labels"`
		Volumes map[string]any    `json:"Volumes"`
	} `json:"Config"`
	State struct {
		Running   bool   `json:"Running"`
		Status    string `json:"Status"`
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
	NetworkSettings struct {
		Networks map[string]struct {
			NetworkID string `json:"NetworkID"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
	HostConfig struct {
		NetworkMode   string   `json:"NetworkMode"`
		Privileged    bool     `json:"Privileged"`
		Binds         []string `json:"Binds"`
		CapAdd        []string `json:"CapAdd"`
		CapDrop       []string `json:"CapDrop"`
		Memory        int64    `json:"Memory"`
		MemorySwap    int64    `json:"MemorySwap"`
		CpuPeriod     int64    `json:"CpuPeriod"`
		CpuQuota      int64    `json:"CpuQuota"`
		PidsLimit     *int64   `json:"PidsLimit"`
		SecurityOpt   []string `json:"SecurityOpt"`
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
		PortBindings map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"PortBindings"`
	} `json:"HostConfig"`
}

func (p *Provider) inspectFacts(ctx context.Context, container string) (inspectFacts, error) {
	output, err := p.output(ctx, []string{"container", "inspect", "--format", "{{json .}}", container})
	if err != nil {
		return inspectFacts{}, err
	}
	var facts inspectFacts
	if err := json.Unmarshal([]byte(output), &facts); err != nil {
		return inspectFacts{}, err
	}
	return facts, nil
}

func (facts inspectFacts) matchesConfiguration(config Config, deployment domain.Deployment, spec contracts.RuntimeSpec) (int, bool) {
	labels := facts.Config.Labels
	valid := validContainerID(facts.ID) && facts.Image == spec.Image.Digest && labels["open-card.managed"] == "true" && labels["open-card.task-prefix"] == config.TaskPrefix && labels["open-card.deployment-id"] == deployment.ID.String() && labels["open-card.application-id"] == spec.ApplicationID.String() && labels["open-card.environment-id"] == spec.EnvironmentID.String() && labels["open-card.release-id"] == spec.ReleaseID.String() && labels["open-card.service"] == spec.ServiceName && labels["open-card.image-repository"] == spec.Image.Repository && labels["open-card.image-digest"] == spec.Image.Digest
	valid = valid && facts.HostConfig.NetworkMode == config.Network && !facts.HostConfig.Privileged && len(facts.HostConfig.Binds) == 0 && len(facts.Config.Volumes) == 0 && len(facts.HostConfig.CapAdd) == 0 && len(facts.HostConfig.CapDrop) == 1 && facts.HostConfig.CapDrop[0] == "ALL" && len(facts.HostConfig.SecurityOpt) == 1 && facts.HostConfig.SecurityOpt[0] == "no-new-privileges=true" && facts.HostConfig.RestartPolicy.Name == "no" && facts.HostConfig.Memory == spec.Resources.MemoryBytes && facts.HostConfig.MemorySwap == spec.Resources.MemoryBytes && facts.HostConfig.CpuPeriod == 100000 && facts.HostConfig.CpuQuota == spec.Resources.CPUMillis*100 && facts.HostConfig.PidsLimit != nil && *facts.HostConfig.PidsLimit == spec.Resources.PIDs
	if !valid {
		return 0, false
	}
	if spec.Port == 0 {
		return 0, len(facts.HostConfig.PortBindings) == 0
	}
	binding := facts.HostConfig.PortBindings[fmt.Sprintf("%d/tcp", spec.Port)]
	if len(facts.HostConfig.PortBindings) != 1 || len(binding) != 1 || binding[0].HostIP != "127.0.0.1" {
		return 0, false
	}
	var port int
	if _, err := fmt.Sscan(binding[0].HostPort, &port); err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}

func (facts inspectFacts) matchesRunning(config Config, deployment domain.Deployment, spec contracts.RuntimeSpec) (int, bool) {
	port, ok := facts.matchesConfiguration(config, deployment, spec)
	return port, ok && facts.State.Running
}

func validRuntimeActionName(value string) bool {
	switch value {
	case "deploy", "restart", "destroy", "recreate":
		return true
	default:
		return false
	}
}
