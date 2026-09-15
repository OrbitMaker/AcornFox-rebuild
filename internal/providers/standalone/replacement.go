package standalone

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const replacementLabel = "open-card.recreate-action"

func replacementAction(actions []durableRuntimeAction, originalID string) (durableRuntimeAction, bool) {
	var result durableRuntimeAction
	for _, action := range actions {
		if action.Action == "recreate" && action.PreviousContainerID == originalID && (action.Status == "started" || action.Status == "cancelled") {
			if result.IdentityHash != "" {
				return durableRuntimeAction{}, false
			}
			result = action
		}
	}
	return result, result.IdentityHash != "" && validContainerID(result.PreviousContainerID)
}

func (p *Provider) replacementFailure(op contracts.OperationContext, message string) error {
	return p.failure(op, contracts.CapabilityRuntimeDeploy, "recreate", contracts.ErrConflict, message, contracts.RetryAfterReconnect, true, nil)
}

// replacementFacts proves either absence or a container belonging to this
// exact immutable replacement. Names alone never authorize removal/adoption.
func (p *Provider) replacementFacts(ctx context.Context, snapshot durableRuntimeState, op contracts.OperationContext) (inspectFacts, bool, error) {
	facts, err := p.inspectFacts(ctx, snapshot.Container)
	if err != nil {
		absent, absenceErr := p.confirmContainerAbsent(ctx, snapshot.Container)
		if absenceErr != nil || !absent {
			return inspectFacts{}, false, p.replacementFailure(op, "replacement container absence is not confirmed")
		}
		return inspectFacts{}, false, nil
	}
	action, ok := replacementAction(snapshot.Actions, snapshot.ContainerID)
	port, matches := facts.matchesConfiguration(p.config, snapshot.Deployment, snapshot.Spec)
	if !ok || !matches || snapshot.Capacity == nil || port != snapshot.Capacity.HostPort || (facts.ID != action.PreviousContainerID && facts.Config.Labels[replacementLabel] != action.IdentityHash) {
		return inspectFacts{}, false, p.replacementFailure(op, "replacement container identity or configuration changed")
	}
	if err := p.validateReplacementNetwork(ctx, facts, op, facts.ID != action.PreviousContainerID && facts.Config.Labels[replacementLabel] == action.IdentityHash && !facts.State.Running && facts.State.Status == "created"); err != nil {
		return inspectFacts{}, false, err
	}
	return facts, true, nil
}

func (p *Provider) validateReplacementNetwork(ctx context.Context, facts inspectFacts, op contracts.OperationContext, allowUnstarted bool) error {
	if p.config.ExistingNetworkValidator == nil {
		return p.replacementFailure(op, "replacement network validator is unavailable")
	}
	raw, err := p.output(ctx, []string{"network", "inspect", p.config.Network})
	var networks []struct {
		ID string `json:"Id"`
	}
	if err != nil || p.config.ExistingNetworkValidator([]byte(raw)) != nil || json.Unmarshal([]byte(raw), &networks) != nil || len(networks) != 1 || !validContainerID(networks[0].ID) {
		return p.replacementFailure(op, "replacement network topology changed")
	}
	if facts.matchesRestoreNetwork(p.config.Network, networks[0].ID) {
		return nil
	}
	// Docker create can precede a failed start/bind. The current operation's
	// unstarted container may have no allocated endpoint yet. This permits
	// observation and exact-ID cleanup only; it is never a running success.
	attachment, present := facts.NetworkSettings.Networks[p.config.Network]
	if allowUnstarted && present && len(facts.NetworkSettings.Networks) == 1 && attachment.NetworkID == "" {
		return nil
	}
	return p.replacementFailure(op, "replacement network attachments changed")
}

func (p *Provider) reconcileReplacement(ctx context.Context, snapshot durableRuntimeState, state *runtimeState, op contracts.OperationContext) (*runtimeState, error) {
	if _, _, err := p.replacementFacts(ctx, snapshot, op); err != nil {
		return nil, err
	}
	reconciler, ok := p.config.Capacity.(capacityActiveReconciler)
	if !ok {
		return nil, p.replacementFailure(op, "replacement capacity cannot be reconciled")
	}
	reconcileOp := op
	reconcileOp.IdempotencyKey = "runtime-reconcile-" + hash(snapshot.Deployment.ID.String())[:24]
	if err := reconciler.ReconcileActive(ctx, *snapshot.Capacity, reconcileOp); err != nil {
		return nil, err
	}
	state.port = snapshot.Capacity.HostPort
	// The original task must resume removal/build/run. Reconciliation does not
	// release the retained lease, start a container or settle that task.
	return state, nil
}

func (p *Provider) recreateRetainingCapacity(ctx context.Context, request contracts.DeployRequest) (domain.Deployment, error) {
	if err := p.verifyRuntimeVolumes(ctx, request.Spec, request.Operation); err != nil {
		return domain.Deployment{}, err
	}

	ctx, cancel := p.operationContext(ctx, request.Operation)
	defer cancel()
	state, err := p.ensureState(ctx, request.DeploymentID, request.Operation, contracts.CapabilityRuntimeDeploy, "recreate")
	if err != nil {
		if isProviderCode(err, contracts.ErrNotFound) {
			return p.recreateLegacy(ctx, request)
		}
		return domain.Deployment{}, err
	}
	if state.fingerprint != p.fingerprint(request.DeploymentID, request.Spec) {
		return domain.Deployment{}, p.replacementFailure(request.Operation, "replacement does not match the immutable deployment")
	}
	if state.destroyed && state.capacity == nil {
		if previous, ok := state.actions[actionIdentity("recreate", request.Operation.IdempotencyKey)]; ok && previous.status == "cancelled" {
			return domain.Deployment{}, p.replacementFailure(request.Operation, "replacement was explicitly cancelled")
		}
		return p.recreateLegacy(ctx, request)
	}
	key := actionIdentity("recreate", request.Operation.IdempotencyKey)
	p.mu.Lock()
	defer p.mu.Unlock()
	if action, exists := state.actions[key]; exists {
		if action.status == "succeeded" {
			if state.destroyed {
				return domain.Deployment{}, p.replacementFailure(request.Operation, "destroyed runtime rejects replacement replay")
			}
			return state.deployment, nil
		}
		if action.status == "cancelled" {
			return domain.Deployment{}, p.replacementFailure(request.Operation, "replacement was explicitly cancelled")
		}
	}
	if state.phase != "active" && state.phase != "replacing" {
		return domain.Deployment{}, p.replacementFailure(request.Operation, "runtime is not eligible for fixed-port replacement")
	}
	for _, action := range state.actions {
		if action.status == "started" && action.identityHash != key {
			return domain.Deployment{}, p.replacementFailure(request.Operation, "another runtime mutation is unfinished")
		}
	}
	if state.capacity == nil || state.port != state.capacity.HostPort || !validContainerID(state.containerID) {
		return domain.Deployment{}, p.replacementFailure(request.Operation, "original replacement lease or identity is missing")
	}
	if state.phase == "active" {
		facts, err := p.inspectFacts(ctx, state.container)
		port, matches := facts.matchesConfiguration(p.config, state.deployment, request.Spec)
		if err != nil || !matches || facts.ID != state.containerID || port != state.capacity.HostPort {
			return domain.Deployment{}, p.replacementFailure(request.Operation, "original container changed before replacement")
		}
		if err := p.validateReplacementNetwork(ctx, facts, request.Operation, false); err != nil {
			return domain.Deployment{}, err
		}
		next := cloneReplacementState(state)
		now := p.config.Clock().UTC()
		next.actions[key] = runtimeAction{identityHash: key, action: "recreate", fingerprint: state.fingerprint, status: "started", previousContainerID: state.containerID, at: now}
		next.phase, next.updatedAt = "replacing", now
		if err := p.persistState(&next); err != nil {
			delete(p.states, state.deployment.ID)
			return domain.Deployment{}, err
		}
		*state = next
	}
	snapshot := p.durableSnapshot(state)
	pending, ok := replacementAction(snapshot.Actions, snapshot.ContainerID)
	if !ok || pending.IdentityHash != key || pending.Status != "started" {
		return domain.Deployment{}, p.replacementFailure(request.Operation, "replacement belongs to another task")
	}
	if p.config.RestoreActiveGuard(ctx) != nil {
		return domain.Deployment{}, p.replacementFailure(request.Operation, "replacement runtime guard is not ready")
	}
	facts, present, err := p.replacementFacts(ctx, snapshot, request.Operation)
	if err != nil {
		return domain.Deployment{}, err
	}
	if present && facts.ID != pending.PreviousContainerID && facts.State.Running {
		return p.completeReplacement(state, key, facts.ID)
	}
	// Load and validate the immutable input before removing the old container.
	if err := p.loadReplacementImage(ctx, request); err != nil {
		return domain.Deployment{}, err
	}
	if err := p.ensureNetwork(ctx, request.Operation); err != nil {
		return domain.Deployment{}, err
	}
	// Re-read after input preparation. A changed/foreign container is untouched.
	facts, present, err = p.replacementFacts(ctx, snapshot, request.Operation)
	if err != nil {
		return domain.Deployment{}, err
	}
	if present {
		if facts.ID != pending.PreviousContainerID && facts.State.Running {
			return p.completeReplacement(state, key, facts.ID)
		}
		if err := p.run(ctx, []string{"rm", "--force", facts.ID}); err != nil {
			return domain.Deployment{}, p.commandError(request.Operation, contracts.CapabilityRuntimeDeploy, "recreate", err)
		}
	}
	absent, err := p.confirmContainerAbsent(ctx, state.container)
	if err != nil || !absent {
		return domain.Deployment{}, p.replacementFailure(request.Operation, "removed replacement container is not confirmed absent")
	}
	if err := p.verifyRuntimeVolumes(ctx, request.Spec, request.Operation); err != nil {
		return domain.Deployment{}, err
	}
	args := p.runArgs(state.container, state.deployment, request.Spec, state.capacity.HostPort, replacementLabel+"="+key)
	if err := p.run(ctx, args); err != nil {
		return domain.Deployment{}, p.commandError(request.Operation, contracts.CapabilityRuntimeDeploy, "recreate", err)
	}
	if err := p.verifyRuntimeVolumes(ctx, request.Spec, request.Operation); err != nil {
		return domain.Deployment{}, err
	}
	facts, present, err = p.replacementFacts(ctx, snapshot, request.Operation)
	if err != nil {
		return domain.Deployment{}, err
	}
	if !present || !facts.State.Running || facts.ID == pending.PreviousContainerID || facts.Config.Labels[replacementLabel] != key {
		return domain.Deployment{}, p.replacementFailure(request.Operation, "replacement is not verified running")
	}
	return p.completeReplacement(state, key, facts.ID)
}

func cloneReplacementState(state *runtimeState) runtimeState {
	next := *state
	next.configuration = copyRuntimeConfiguration(state.configuration)
	next.actions = make(map[string]runtimeAction, len(state.actions))
	for k, v := range state.actions {
		next.actions[k] = v
	}
	return next
}

func (p *Provider) completeReplacement(state *runtimeState, key, id string) (domain.Deployment, error) {
	next := cloneReplacementState(state)
	action := next.actions[key]
	action.status, action.at = "succeeded", p.config.Clock().UTC()
	next.actions[key] = action
	next.containerID = id
	next.phase = "active"
	next.updatedAt = action.at
	if err := p.persistState(&next); err != nil {
		delete(p.states, state.deployment.ID)
		return domain.Deployment{}, err
	}
	*state = next
	return state.deployment, nil
}

func (p *Provider) loadReplacementImage(ctx context.Context, request contracts.DeployRequest) error {
	archive, stored, err := p.config.ImageStore.OpenOCI(ctx, request.Spec.Image, request.Operation)
	if err != nil {
		return p.replacementFailure(request.Operation, "persistent replacement image is unavailable")
	}
	defer archive.Close()
	if !sameImage(stored.Image, request.Spec.Image) || strings.TrimSpace(stored.StorageRef) == "" {
		return p.replacementFailure(request.Operation, "replacement image digest is not attested")
	}
	path, err := p.copyArchive(archive)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	if err := p.run(ctx, []string{"load", "--input", path}); err != nil {
		return p.commandError(request.Operation, contracts.CapabilityRuntimeDeploy, "recreate", err)
	}
	return p.verifyImage(ctx, request.Spec.Image, request.Operation, request.Spec)
}

// cancelReplacement records cancellation before removal so a crash cannot
// revive the original recreate task. The normal Destroy release path follows.
func (p *Provider) cancelReplacement(ctx context.Context, state *runtimeState, request contracts.DestroyRequest) error {
	snapshot := p.durableSnapshot(state)
	pending, ok := replacementAction(snapshot.Actions, snapshot.ContainerID)
	if !ok {
		return errors.New("replacement cancellation identity is unavailable")
	}
	facts, present, err := p.replacementFacts(ctx, snapshot, request.Operation)
	if err != nil {
		return err
	}
	next := cloneReplacementState(state)
	action := next.actions[pending.IdentityHash]
	action.status = "cancelled"
	action.at = p.config.Clock().UTC()
	next.actions[pending.IdentityHash] = action
	destroyKey := actionIdentity("destroy", request.Operation.IdempotencyKey)
	if _, exists := next.actions[destroyKey]; !exists {
		next.actions[destroyKey] = runtimeAction{identityHash: destroyKey, action: "destroy", fingerprint: state.fingerprint, status: "started", previousContainerID: state.containerID, at: action.at}
	}
	next.updatedAt = action.at
	if err := p.persistState(&next); err != nil {
		delete(p.states, state.deployment.ID)
		return err
	}
	*state = next
	if present {
		if err := p.run(ctx, []string{"rm", "--force", facts.ID}); err != nil {
			return p.commandError(request.Operation, contracts.CapabilityRuntimeDestroy, "destroy", err)
		}
	}
	absent, err := p.confirmContainerAbsent(ctx, state.container)
	if err != nil || !absent {
		return p.replacementFailure(request.Operation, "cancelled replacement removal is not confirmed")
	}
	state.destroyed = true
	state.phase = "destroyed"
	state.port = 0
	state.updatedAt = p.config.Clock().UTC()
	if err := p.persistState(state); err != nil {
		delete(p.states, state.deployment.ID)
		return err
	}
	return nil
}
