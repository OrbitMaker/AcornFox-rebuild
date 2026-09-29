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
	"strconv"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const (
	durableRuntimeStateSchema   = "1"
	durableRuntimeStateSchemaV1 = "1"
	durableRuntimeStateSchemaV2 = "2"
	durableRuntimeStateSchemaV3 = "3"
)

func isLifecyclePhase(phase string) bool {
	return phase == "pausing" || phase == "paused" || phase == "resuming"
}

func validPhase(phase string) bool {
	switch phase {
	case "pending", "active", "destroying", "destroyed", "replacing", "pausing", "paused", "resuming":
		return true
	default:
		return false
	}
}

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
	NetworkID       string                   `json:"network_id,omitempty"`
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
	spec := state.runtimeSpec()
	schema := state.schemaVersion
	if schema == "" {
		schema = runtimeStateSchema(spec)
	}
	if isLifecyclePhase(state.phase) || schema == durableRuntimeStateSchemaV3 {
		schema = durableRuntimeStateSchemaV3
		state.schemaVersion = durableRuntimeStateSchemaV3
	}
	return durableRuntimeState{SchemaVersion: schema, Deployment: state.deployment, Spec: spec, Fingerprint: state.fingerprint, Container: state.container, ContainerID: state.containerID, Phase: state.phase, Capacity: state.capacity, LeaseGeneration: state.leaseGeneration, NetworkID: state.networkID, Actions: actions, CreatedAt: state.createdAt.UTC(), UpdatedAt: state.updatedAt.UTC()}
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
	if !validPhase(snapshot.Phase) {
		return errors.New("standalone state schema or phase is unsupported")
	}
	switch snapshot.SchemaVersion {
	case durableRuntimeStateSchemaV1, durableRuntimeStateSchemaV2:
		if snapshot.SchemaVersion != runtimeStateSchema(snapshot.Spec) || isLifecyclePhase(snapshot.Phase) {
			return errors.New("standalone state schema or phase is unsupported")
		}
	case durableRuntimeStateSchemaV3:
		if snapshot.Phase == "active" || snapshot.Phase == "paused" || snapshot.Phase == "pausing" || snapshot.Phase == "resuming" || snapshot.Phase == "destroying" {
			if !validContainerID(snapshot.ContainerID) {
				return errors.New("schema 3 state requires valid full container ID")
			}
		}
		if snapshot.Phase == "active" || snapshot.Phase == "paused" || snapshot.Phase == "pausing" || snapshot.Phase == "resuming" {
			if !validContainerID(snapshot.NetworkID) {
				return errors.New("schema 3 state requires valid full network ID")
			}
		}
	default:
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
		if action.IdentityHash == "" || !validRuntimeActionName(action.Action) || action.Fingerprint != snapshot.Fingerprint || (action.Status != "started" && action.Status != "succeeded" && action.Status != "cancelled") || action.At.IsZero() {
			return errors.New("standalone state action is invalid")
		}
		if (action.Action == "stop" || action.Action == "start") && snapshot.SchemaVersion != durableRuntimeStateSchemaV3 {
			return errors.New("lifecycle actions require schema version 3")
		}
		if action.Status == "cancelled" && action.Action != "recreate" {
			return errors.New("standalone cancelled action is invalid")
		}
		if _, ok := seen[action.IdentityHash]; ok {
			return errors.New("standalone state action is duplicated")
		}
		seen[action.IdentityHash] = struct{}{}
	}
	if (snapshot.Phase == "active" || snapshot.Phase == "pausing") && snapshot.Deployment.Status != domain.DeploymentRuntimeReady {
		return errors.New("active and pausing phases require deployment status runtime_ready")
	}
	if (snapshot.Phase == "paused" || snapshot.Phase == "resuming") && snapshot.Deployment.Status != domain.DeploymentPaused {
		return errors.New("paused and resuming phases require deployment status paused")
	}
	if snapshot.Phase == "pausing" {
		if snapshot.Deployment.Status == domain.DeploymentPaused {
			return errors.New("pausing phase cannot have deployment status paused")
		}
		startedStopCount := 0
		for _, action := range snapshot.Actions {
			if action.Action == "stop" && action.Status == "started" {
				startedStopCount++
				if action.PreviousContainerID == "" || action.PreviousContainerID != snapshot.ContainerID {
					return errors.New("pausing started action must bind exact snapshot container ID")
				}
			}
		}
		if startedStopCount != 1 {
			return errors.New("pausing phase requires exactly one started stop action")
		}
	}
	if snapshot.Phase == "resuming" {
		if snapshot.Deployment.Status != domain.DeploymentPaused {
			return errors.New("resuming phase requires prior deployment status paused")
		}
		startedStartCount := 0
		for _, action := range snapshot.Actions {
			if action.Action == "start" && action.Status == "started" {
				startedStartCount++
				if action.PreviousContainerID == "" || action.PreviousContainerID != snapshot.ContainerID {
					return errors.New("resuming started action must bind exact snapshot container ID")
				}
			}
		}
		if startedStartCount != 1 {
			return errors.New("resuming phase requires exactly one started start action")
		}
	}
	if snapshot.Phase == "replacing" {
		if snapshot.Capacity == nil || !validContainerID(snapshot.ContainerID) {
			return errors.New("replacement lease or original identity is missing")
		}
		if action, ok := replacementAction(snapshot.Actions, snapshot.ContainerID); !ok || action.PreviousContainerID != snapshot.ContainerID {
			return errors.New("replacement action is missing, ambiguous or unbound")
		}
	}
	return nil
}

func (p *Provider) stateFromDurable(ctx context.Context, snapshot durableRuntimeState, operation contracts.OperationContext, capability contracts.Capability, action string) (*runtimeState, error) {
	state := &runtimeState{
		configuration:   copyRuntimeConfiguration(snapshot.Spec.Configuration),
		configDigest:    snapshot.Spec.ConfigDigest,
		deployment:      snapshot.Deployment,
		service:         snapshot.Spec.ServiceName,
		image:           snapshot.Spec.Image,
		container:       snapshot.Container,
		containerID:     snapshot.ContainerID,
		containerPort:   snapshot.Spec.Port,
		fingerprint:     snapshot.Fingerprint,
		phase:           snapshot.Phase,
		schemaVersion:   snapshot.SchemaVersion,
		capacity:        snapshot.Capacity,
		leaseGeneration: snapshot.LeaseGeneration,
		networkID:       snapshot.NetworkID,
		resources:       snapshot.Spec.Resources,
		createdAt:       snapshot.CreatedAt,
		updatedAt:       snapshot.UpdatedAt,
		actions:         map[string]runtimeAction{},
	}
	for _, persisted := range snapshot.Actions {
		state.actions[persisted.IdentityHash] = runtimeAction{identityHash: persisted.IdentityHash, action: persisted.Action, fingerprint: persisted.Fingerprint, status: persisted.Status, previousContainerID: persisted.PreviousContainerID, previousStartedAt: persisted.PreviousStartedAt, releaseAttempt: persisted.ReleaseAttempt, at: persisted.At}
	}
	if state.phase == "active" || state.phase == "replacing" {
		if err := p.verifyRuntimeVolumes(ctx, snapshot.Spec, operation); err != nil {
			return nil, err
		}
	}
	if state.phase == "replacing" {
		return p.reconcileReplacement(ctx, snapshot, state, operation)
	}
	if state.phase == "destroyed" {
		state.destroyed = true
		if state.capacity != nil {
			finalizer, ok := p.config.Capacity.(contracts.CapacityReleasedFinalizer)
			if !ok {
				return nil, p.failure(operation, capability, action, contracts.ErrUnavailable, "capacity provider cannot finalize released runtime lease", contracts.RetryAfterReconnect, true, nil)
			}
			finalizeOp := operation
			finalizeOp.IdempotencyKey = "runtime-finalize-" + hash(state.deployment.ID.String())[:24]
			if err := finalizer.FinalizeReleased(ctx, *state.capacity, finalizeOp); err != nil {
				return nil, err
			}
			state.capacity = nil
			state.updatedAt = p.config.Clock().UTC()
			if persistErr := p.persistState(state); persistErr != nil {
				return nil, p.failure(operation, capability, action, contracts.ErrUnavailable, "finalized destroyed runtime state could not be persisted", contracts.RetryBackoff, true, persistErr)
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
					finalizer, ok := p.config.Capacity.(contracts.CapacityReleasedFinalizer)
					if !ok {
						return nil, p.failure(operation, capability, action, contracts.ErrUnavailable, "capacity provider cannot finalize released runtime lease", contracts.RetryAfterReconnect, true, nil)
					}
					finalizeOp := operation
					finalizeOp.IdempotencyKey = "runtime-finalize-" + hash(state.deployment.ID.String())[:24]
					if finalizeErr := finalizer.FinalizeReleased(ctx, *state.capacity, finalizeOp); finalizeErr != nil {
						return nil, finalizeErr
					}
					state.capacity = nil
				}
				state.updatedAt = p.config.Clock().UTC()
				if persistErr := p.persistState(state); persistErr != nil {
					return nil, p.failure(operation, capability, action, contracts.ErrUnavailable, "finalized destroying runtime state could not be persisted", contracts.RetryBackoff, true, persistErr)
				}
				return state, nil
			}
			if absent && state.phase == "pending" {
				if state.capacity != nil {
					finalizer, ok := p.config.Capacity.(contracts.CapacityReleasedFinalizer)
					if !ok {
						return nil, p.failure(operation, capability, action, contracts.ErrUnavailable, "capacity provider cannot finalize released pending lease", contracts.RetryAfterReconnect, true, nil)
					}
					finalizeOp := operation
					finalizeOp.IdempotencyKey = "runtime-pending-finalize-" + hash(state.deployment.ID.String(), fmt.Sprint(state.leaseGeneration))[:24]
					if finalizeErr := finalizer.FinalizeReleased(ctx, *state.capacity, finalizeOp); finalizeErr != nil {
						return nil, finalizeErr
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
	if err := p.verifyRuntimeVolumes(ctx, snapshot.Spec, operation); err != nil {
		return nil, err
	}
	port, ok := facts.matchesConfiguration(p.config, state.deployment, snapshot.Spec)
	if !ok {
		return nil, p.failure(operation, capability, action, contracts.ErrConflict, "durable runtime facts do not match the immutable deployment", contracts.RetryNever, false, nil)
	}
	if snapshot.ContainerID != "" && facts.ID != snapshot.ContainerID {
		return nil, p.failure(operation, capability, action, contracts.ErrConflict, "container identity changed from persisted state; name substitution is forbidden", contracts.RetryNever, false, nil)
	}
	state.port, state.containerID = port, facts.ID
	if snapshot.SchemaVersion == durableRuntimeStateSchemaV3 && (snapshot.Phase == "active" || snapshot.Phase == "paused" || snapshot.Phase == "pausing" || snapshot.Phase == "resuming") {
		currentNetID, netErr := p.verifyRuntimeNetworkTopology(ctx, facts, operation, capability, action)
		if netErr != nil {
			return nil, netErr
		}
		if currentNetID != snapshot.NetworkID {
			return nil, p.failure(operation, capability, action, contracts.ErrConflict, "persisted network ID does not match current network", contracts.RetryNever, false, nil)
		}
		if facts.State.Running {
			if guardErr := p.requireRuntimeNetworkGuard(ctx, operation, capability, action); guardErr != nil {
				return nil, guardErr
			}
		}
	}
	if snapshot.Phase == "pending" {
		if facts.State.Running {
			state.phase, state.recovery = "active", runtimeRecoveryPendingRunning
		} else {
			state.phase, state.recovery = "pending", runtimeRecoveryPendingNotRunning
		}
	} else if snapshot.Phase == "paused" {
		if facts.State.Running || facts.State.Status != "exited" {
			return nil, p.failure(operation, capability, action, contracts.ErrConflict, "paused runtime container is not in exited status", contracts.RetryNever, false, nil)
		}
		state.phase, state.recovery = "paused", runtimeRecoveryPaused
		state.deployment.Status = domain.DeploymentPaused
		if state.capacity == nil {
			return nil, p.failure(operation, capability, action, contracts.ErrConflict, "durable paused runtime state has no capacity lease", contracts.RetryNever, false, nil)
		}
		reconciler, ok := p.config.Capacity.(contracts.CapacityRetainedReconciler)
		if !ok {
			return nil, p.failure(operation, capability, action, contracts.ErrUnavailable, "capacity provider cannot reconcile retained runtime lease", contracts.RetryAfterReconnect, true, nil)
		}
		reconcileOp := operation
		reconcileOp.IdempotencyKey = "runtime-reconcile-" + hash(state.deployment.ID.String())[:24]
		if err := reconciler.ReconcileRetained(ctx, *state.capacity, reconcileOp); err != nil {
			return nil, err
		}
		return state, nil
	} else if snapshot.Phase == "pausing" {
		state.phase, state.recovery = "pausing", runtimeRecoveryPausing
		if state.capacity != nil {
			reconciler, ok := p.config.Capacity.(contracts.CapacityRetainedReconciler)
			if !ok {
				return nil, p.failure(operation, capability, action, contracts.ErrUnavailable, "capacity provider cannot reconcile retained runtime lease", contracts.RetryAfterReconnect, true, nil)
			}
			reconcileOp := operation
			reconcileOp.IdempotencyKey = "runtime-reconcile-" + hash(state.deployment.ID.String())[:24]
			if err := reconciler.ReconcileRetained(ctx, *state.capacity, reconcileOp); err != nil {
				return nil, err
			}
		}
		return state, nil
	} else if snapshot.Phase == "resuming" {
		state.phase, state.recovery = "resuming", runtimeRecoveryResuming
		if facts.State.Running {
			if state.capacity != nil {
				reconciler, ok := p.config.Capacity.(capacityActiveReconciler)
				if !ok {
					return nil, p.failure(operation, capability, action, contracts.ErrUnavailable, "capacity provider cannot reconcile active runtime lease", contracts.RetryAfterReconnect, true, nil)
				}
				reconcileOp := operation
				reconcileOp.IdempotencyKey = "runtime-reconcile-" + hash(state.deployment.ID.String())[:24]
				if err := reconciler.ReconcileActive(ctx, *state.capacity, reconcileOp); err != nil {
					return nil, err
				}
			}
		} else {
			if state.capacity != nil {
				reconciler, ok := p.config.Capacity.(contracts.CapacityRetainedReconciler)
				if !ok {
					return nil, p.failure(operation, capability, action, contracts.ErrUnavailable, "capacity provider cannot reconcile retained runtime lease", contracts.RetryAfterReconnect, true, nil)
				}
				reconcileOp := operation
				reconcileOp.IdempotencyKey = "runtime-reconcile-" + hash(state.deployment.ID.String())[:24]
				if err := reconciler.ReconcileRetained(ctx, *state.capacity, reconcileOp); err != nil {
					return nil, err
				}
			}
		}
		return state, nil
	} else {
		state.phase, state.recovery = "active", runtimeRecoveryActive
	}
	if state.capacity == nil {
		if snapshot.Phase == "pending" && facts.neverStarted() {
			if err := p.removeNeverStartedPendingContainer(ctx, state, facts, operation, capability, action); err != nil {
				return nil, err
			}
			return state, nil
		}
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

func (p *Provider) confirmContainerAbsentByID(ctx context.Context, containerID string) (bool, error) {
	if !validContainerID(containerID) {
		return false, errors.New("container id is invalid")
	}
	output, err := p.output(ctx, []string{"container", "ls", "--all", "--filter", "id=^" + containerID + "$", "--format", "{{.ID}}"})
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
		if snapshot.Phase == "active" {
			if err := p.restoreActive(ctx, snapshot, state); err != nil {
				return err
			}
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
	imageConfiguration         runtimeImageConfiguration
	imageConfigurationVerified bool
	Mounts                     []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	ID           string `json:"Id"`
	Name         string `json:"Name"`
	Image        string `json:"Image"`
	RestartCount uint64 `json:"RestartCount"`
	Config       struct {
		Entrypoint []string          `json:"Entrypoint"`
		Cmd        []string          `json:"Cmd"`
		Env        []string          `json:"Env"`
		Labels     map[string]string `json:"Labels"`
		Volumes    map[string]any    `json:"Volumes"`
	} `json:"Config"`
	State struct {
		Running   bool   `json:"Running"`
		Status    string `json:"Status"`
		Pid       int    `json:"Pid"`
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
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
	if facts.Config.Labels["open-card.config-digest"] != "" {
		imageConfig, err := p.loadRuntimeImageConfiguration(ctx, facts.Image)
		if err != nil {
			return inspectFacts{}, err
		}
		facts.imageConfiguration = imageConfig
		facts.imageConfigurationVerified = true
	}
	if p.config.NetworkProfile == ApplicationLoopbackNetworkProfile && facts.State.Running && facts.State.Status != "paused" {
		raw, err := p.output(ctx, []string{"network", "inspect", p.config.Network})
		if err != nil {
			return inspectFacts{}, err
		}
		network, err := p.validateApplicationNetwork([]byte(raw))
		if err != nil {
			return inspectFacts{}, err
		}
		attachment, ok := facts.NetworkSettings.Networks[p.config.Network]
		if len(facts.NetworkSettings.Networks) != 1 || !ok || attachment.NetworkID != network.ID {
			return inspectFacts{}, errors.New("application container network attachment is not the verified network")
		}
	}
	return facts, nil
}

func (facts inspectFacts) neverStarted() bool {
	if facts.State.Running || facts.State.Status != "created" || facts.State.Pid != 0 || facts.RestartCount != 0 || facts.State.StartedAt == "" {
		return false
	}
	started, err := time.Parse(time.RFC3339Nano, facts.State.StartedAt)
	return err == nil && started.IsZero()
}

func (p *Provider) removeNeverStartedPendingContainer(ctx context.Context, state *runtimeState, facts inspectFacts, operation contracts.OperationContext, capability contracts.Capability, action string) error {
	if state == nil || state.phase != "pending" || state.capacity != nil || !facts.neverStarted() || !validContainerID(facts.ID) {
		return p.failure(operation, capability, action, contracts.ErrConflict, "pending runtime is not eligible for never-started cleanup", contracts.RetryNever, false, nil)
	}
	if err := p.run(ctx, []string{"rm", facts.ID}); err != nil {
		return p.commandError(operation, capability, action, err)
	}
	absent, err := p.confirmContainerAbsent(ctx, state.container)
	if err != nil || !absent {
		return p.failure(operation, capability, action, contracts.ErrUnavailable, "never-started runtime absence was not confirmed", contracts.RetryAfterReconnect, true, err)
	}
	state.containerID, state.port = "", 0
	state.recovery, state.updatedAt = runtimeRecoveryPendingAbsent, p.config.Clock().UTC()
	if err := p.persistState(state); err != nil {
		return p.failure(operation, capability, action, contracts.ErrUnavailable, "never-started runtime cleanup could not be persisted", contracts.RetryAfterReconnect, true, err)
	}
	return nil
}

func (p *Provider) cleanupFailedDeployContainer(ctx context.Context, state *runtimeState, spec contracts.RuntimeSpec, operation contracts.OperationContext) error {
	if state == nil || state.phase != "pending" || state.capacity == nil {
		return p.failure(operation, contracts.CapabilityRuntimeDeploy, "cleanup", contracts.ErrConflict, "failed runtime cleanup state is invalid", contracts.RetryNever, false, nil)
	}
	facts, err := p.inspectFacts(ctx, state.container)
	if err != nil {
		absent, absenceErr := p.confirmContainerAbsent(ctx, state.container)
		if absenceErr != nil || !absent {
			return p.failure(operation, contracts.CapabilityRuntimeDeploy, "cleanup", contracts.ErrUnavailable, "failed runtime absence could not be confirmed", contracts.RetryAfterReconnect, true, absenceErr)
		}
		return nil
	}
	port, matches := facts.matchesConfiguration(p.config, state.deployment, spec)
	if !matches || port != state.capacity.HostPort || !facts.neverStarted() {
		return p.failure(operation, contracts.CapabilityRuntimeDeploy, "cleanup", contracts.ErrConflict, "failed runtime container is not eligible for never-started cleanup", contracts.RetryNever, false, nil)
	}
	if err := p.run(ctx, []string{"rm", facts.ID}); err != nil {
		return p.commandError(operation, contracts.CapabilityRuntimeDeploy, "cleanup", err)
	}
	absent, err := p.confirmContainerAbsent(ctx, state.container)
	if err != nil || !absent {
		return p.failure(operation, contracts.CapabilityRuntimeDeploy, "cleanup", contracts.ErrUnavailable, "failed runtime absence was not confirmed", contracts.RetryAfterReconnect, true, err)
	}
	return nil
}

func (facts inspectFacts) matchesConfiguration(config Config, deployment domain.Deployment, spec contracts.RuntimeSpec) (int, bool) {
	labels := facts.Config.Labels
	valid := validContainerID(facts.ID) && facts.Image == spec.Image.Digest && labels["open-card.managed"] == "true" && labels["open-card.task-prefix"] == config.TaskPrefix && labels["open-card.deployment-id"] == deployment.ID.String() && labels["open-card.application-id"] == spec.ApplicationID.String() && labels["open-card.environment-id"] == spec.EnvironmentID.String() && labels["open-card.release-id"] == spec.ReleaseID.String() && labels["open-card.service"] == spec.ServiceName && labels["open-card.image-repository"] == spec.Image.Repository && labels["open-card.image-digest"] == spec.Image.Digest
	valid = valid && facts.HostConfig.NetworkMode == config.Network && !facts.HostConfig.Privileged && len(facts.HostConfig.Binds) == 0 && facts.matchesConfiguredRuntime(config, spec) && len(facts.HostConfig.CapAdd) == 0 && len(facts.HostConfig.CapDrop) == 1 && facts.HostConfig.CapDrop[0] == "ALL" && len(facts.HostConfig.SecurityOpt) == 1 && facts.HostConfig.SecurityOpt[0] == "no-new-privileges=true" && facts.HostConfig.RestartPolicy.Name == "no" && facts.HostConfig.Memory == spec.Resources.MemoryBytes && facts.HostConfig.MemorySwap == spec.Resources.MemoryBytes && facts.HostConfig.CpuPeriod == 100000 && facts.HostConfig.CpuQuota == spec.Resources.CPUMillis*100 && facts.HostConfig.PidsLimit != nil && *facts.HostConfig.PidsLimit == spec.Resources.PIDs
	if len(facts.NetworkSettings.Networks) > 1 {
		return 0, false
	}
	if len(facts.NetworkSettings.Networks) == 1 {
		if _, hasNet := facts.NetworkSettings.Networks[config.Network]; !hasNet {
			return 0, false
		}
	}
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
	if config.NetworkProfile == ApplicationLoopbackNetworkProfile && facts.State.Running && facts.State.Status != "paused" {
		key := fmt.Sprintf("%d/tcp", spec.Port)
		actual := facts.NetworkSettings.Ports[key]
		if len(actual) != 1 || actual[0].HostIP != "127.0.0.1" {
			return 0, false
		}
		actualPort, err := strconv.Atoi(actual[0].HostPort)
		if err != nil || actualPort != port {
			return 0, false
		}
		for other, bindings := range facts.NetworkSettings.Ports {
			if other != key && len(bindings) != 0 {
				return 0, false
			}
		}
		attachment, ok := facts.NetworkSettings.Networks[config.Network]
		if len(facts.NetworkSettings.Networks) != 1 || !ok || !validContainerID(attachment.NetworkID) {
			return 0, false
		}
	}
	return port, true
}

func (facts inspectFacts) matchesRunning(config Config, deployment domain.Deployment, spec contracts.RuntimeSpec) (int, bool) {
	port, ok := facts.matchesConfiguration(config, deployment, spec)
	return port, ok && facts.State.Running
}

func validRuntimeActionName(value string) bool {
	switch value {
	case "deploy", "restart", "destroy", "recreate", "stop", "start":
		return true
	default:
		return false
	}
}
