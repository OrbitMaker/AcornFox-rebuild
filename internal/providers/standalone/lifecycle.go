package standalone

import (
	"context"
	"fmt"
	"net"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

// Stop suspends an active container workload by running docker stop against its
// immutable container identity. Capacity leases, assigned host ports, lease
// generations, and volume receipts remain durably retained.
func (p *Provider) Stop(ctx context.Context, request contracts.StopRequest) error {
	unlock := p.lockDeployment(request.DeploymentID)
	defer unlock()

	if err := p.check(ctx, request.Operation, contracts.CapabilityRuntimeStop, "stop"); err != nil {
		return err
	}
	if _, err := p.ensureState(ctx, request.DeploymentID, request.Operation, contracts.CapabilityRuntimeStop, "stop"); err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	state, err := p.stateLocked(request.DeploymentID, request.Operation, contracts.CapabilityRuntimeStop, "stop")
	if err != nil {
		return err
	}
	if state.destroyed || state.phase == "destroyed" || state.phase == "destroying" {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStop, "stop", contracts.ErrConflict, "destroyed runtime cannot be stopped", contracts.RetryNever, false, nil)
	}
	if state.phase == "replacing" {
		return p.replacementFailure(request.Operation, "replacement must finish or be cancelled before stop")
	}
	if request.ServiceName != "" && request.ServiceName != state.service {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStop, "stop", contracts.ErrValidation, "runtime service does not match deployment", contracts.RetryNever, false, nil)
	}

	actionHash := actionIdentity("stop", request.Operation.IdempotencyKey)

	// P1-1: Completed keys must never re-trigger side effects or undo newer states (e.g. Stop key A -> Start key B -> replay Stop A).
	if action, done := state.actions[actionHash]; done && action.status == "succeeded" && action.action == "stop" && action.fingerprint == state.fingerprint {
		return nil
	}

	// P1-4: Unfinished older actions cannot be bypassed.
	for hashKey, existingAction := range state.actions {
		if hashKey != actionHash && existingAction.status == "started" {
			return p.failure(request.Operation, contracts.CapabilityRuntimeStop, "stop", contracts.ErrConflict, "concurrent or unfinished runtime action is pending", contracts.RetryBackoff, true, nil)
		}
	}

	// P1-4: In pending phases, new idempotency keys cannot take over the pending action.
	if state.phase == "pausing" || state.phase == "resuming" {
		action, started := state.actions[actionHash]
		if !started || action.status != "started" {
			return p.failure(request.Operation, contracts.CapabilityRuntimeStop, "stop", contracts.ErrConflict, "cannot take over pending lifecycle phase with a different operation key", contracts.RetryNever, false, nil)
		}
	}

	// P1-1: If state is already paused and a new key requests Stop, verify full identity facts and record key as succeeded (noop).
	if state.phase == "paused" {
		facts, inspectErr := p.inspectFacts(ctx, state.containerID)
		if inspectErr != nil || facts.ID != state.containerID || facts.State.Running || facts.State.Status != "exited" {
			return p.failure(request.Operation, contracts.CapabilityRuntimeStop, "stop", contracts.ErrConflict, "paused runtime facts do not match", contracts.RetryNever, false, inspectErr)
		}
		_, matches := facts.matchesConfiguration(p.config, state.deployment, state.runtimeSpec())
		if !matches {
			return p.failure(request.Operation, contracts.CapabilityRuntimeStop, "stop", contracts.ErrConflict, "paused runtime configuration drifted", contracts.RetryNever, false, nil)
		}
		if err := p.verifyRuntimeVolumes(ctx, state.runtimeSpec(), request.Operation); err != nil {
			return err
		}
		now := p.config.Clock().UTC()
		state.actions[actionHash] = runtimeAction{
			identityHash: actionHash,
			action:       "stop",
			fingerprint:  state.fingerprint,
			status:       "succeeded",
			at:           now,
		}
		state.updatedAt = now
		if err := p.persistState(state); err != nil {
			return p.failure(request.Operation, contracts.CapabilityRuntimeStop, "persist_state", contracts.ErrUnavailable, "noop stop state could not be persisted", contracts.RetryBackoff, true, err)
		}
		return nil
	}

	if state.phase != "active" && state.phase != "pausing" {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStop, "stop", contracts.ErrConflict, "runtime is not in an active or pausing state", contracts.RetryNever, false, nil)
	}

	if err := p.verifyRuntimeVolumes(ctx, state.runtimeSpec(), request.Operation); err != nil {
		return err
	}

	facts, inspectErr := p.inspectFacts(ctx, state.containerID)
	if inspectErr != nil {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStop, "stop", contracts.ErrConflict, "runtime container could not be inspected before stop", contracts.RetryNever, false, inspectErr)
	}
	if facts.ID != state.containerID {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStop, "stop", contracts.ErrConflict, "container identity changed before stop", contracts.RetryNever, false, nil)
	}
	_, matches := facts.matchesConfiguration(p.config, state.deployment, state.runtimeSpec())
	if !matches {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStop, "stop", contracts.ErrConflict, "runtime configuration drifted before stop", contracts.RetryNever, false, nil)
	}

	netID, netErr := p.verifyRuntimeNetworkTopology(ctx, facts, request.Operation, contracts.CapabilityRuntimeStop, "stop")
	if netErr != nil {
		return netErr
	}
	state.networkID = netID

	// Crash/timeout convergence: if action was already started and container is already exited, settle idempotently.
	if action, started := state.actions[actionHash]; started && action.action == "stop" && action.fingerprint == state.fingerprint && action.status == "started" && !facts.State.Running && facts.State.Status == "exited" {
		now := p.config.Clock().UTC()
		action.status = "succeeded"
		action.at = now
		state.actions[actionHash] = action
		state.phase = "paused"
		state.deployment.Status = domain.DeploymentPaused
		state.updatedAt = now
		if err := p.persistState(state); err != nil {
			return p.failure(request.Operation, contracts.CapabilityRuntimeStop, "persist_state", contracts.ErrUnavailable, "recovered stop state could not be persisted", contracts.RetryBackoff, true, err)
		}
		return nil
	}

	// Record pausing phase and started action with schema 3 promotion.
	if action, started := state.actions[actionHash]; !started || action.status != "started" {
		now := p.config.Clock().UTC()
		state.schemaVersion = durableRuntimeStateSchemaV3
		state.phase = "pausing"
		state.actions[actionHash] = runtimeAction{
			identityHash:        actionHash,
			action:              "stop",
			fingerprint:         state.fingerprint,
			status:              "started",
			previousContainerID: state.containerID,
			at:                  now,
		}
		state.updatedAt = now
		if err := p.persistState(state); err != nil {
			return p.failure(request.Operation, contracts.CapabilityRuntimeStop, "persist_state", contracts.ErrUnavailable, "pending stop state could not be persisted", contracts.RetryBackoff, true, err)
		}
	}

	// Execute docker stop against immutable container ID (not name).
	if err := p.run(ctx, []string{"stop", state.containerID}); err != nil {
		return p.commandError(request.Operation, contracts.CapabilityRuntimeStop, "stop", err)
	}

	// Verify stop facts: exited, same ID, same configuration.
	after, err := p.inspectFacts(ctx, state.containerID)
	if err != nil {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStop, "stop", contracts.ErrUnavailable, "stopped runtime container could not be inspected", contracts.RetryAfterReconnect, true, err)
	}
	if after.ID != state.containerID || after.State.Running || after.State.Status != "exited" {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStop, "stop", contracts.ErrConflict, "runtime container is not stopped in exited status", contracts.RetryNever, false, nil)
	}
	_, afterMatches := after.matchesConfiguration(p.config, state.deployment, state.runtimeSpec())
	if !afterMatches {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStop, "stop", contracts.ErrConflict, "runtime configuration changed after stop", contracts.RetryNever, false, nil)
	}

	now := p.config.Clock().UTC()
	state.schemaVersion = durableRuntimeStateSchemaV3
	state.phase = "paused"
	state.deployment.Status = domain.DeploymentPaused
	state.actions[actionHash] = runtimeAction{
		identityHash: actionHash,
		action:       "stop",
		fingerprint:  state.fingerprint,
		status:       "succeeded",
		at:           now,
	}
	state.updatedAt = now

	if err := p.persistState(state); err != nil {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStop, "persist_state", contracts.ErrUnavailable, "paused runtime state could not be persisted", contracts.RetryBackoff, true, err)
	}
	return nil
}

// Start resumes a paused container workload by running docker start against its
// immutable container identity. Configuration drift, missing containers, image,
// network, volume, or port identity drifts explicitly fail with conflict (409)
// and are never silently recreated.
func (p *Provider) Start(ctx context.Context, request contracts.StartRequest) error {
	unlock := p.lockDeployment(request.DeploymentID)
	defer unlock()

	if err := p.check(ctx, request.Operation, contracts.CapabilityRuntimeStart, "start"); err != nil {
		return err
	}
	if _, err := p.ensureState(ctx, request.DeploymentID, request.Operation, contracts.CapabilityRuntimeStart, "start"); err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	state, err := p.stateLocked(request.DeploymentID, request.Operation, contracts.CapabilityRuntimeStart, "start")
	if err != nil {
		return err
	}
	if state.destroyed || state.phase == "destroyed" || state.phase == "destroying" {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "start", contracts.ErrConflict, "destroyed runtime cannot be started", contracts.RetryNever, false, nil)
	}
	if state.phase == "replacing" {
		return p.replacementFailure(request.Operation, "replacement must finish or be cancelled before start")
	}
	if request.ServiceName != "" && request.ServiceName != state.service {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "start", contracts.ErrValidation, "runtime service does not match deployment", contracts.RetryNever, false, nil)
	}

	actionHash := actionIdentity("start", request.Operation.IdempotencyKey)

	// P1-1: Completed keys must never re-trigger side effects or undo newer states (e.g. Start key A -> Stop key B -> replay Start A).
	if action, done := state.actions[actionHash]; done && action.status == "succeeded" && action.action == "start" && action.fingerprint == state.fingerprint {
		return nil
	}

	// P1-4: Unfinished older actions cannot be bypassed.
	for hashKey, existingAction := range state.actions {
		if hashKey != actionHash && existingAction.status == "started" {
			return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "start", contracts.ErrConflict, "concurrent or unfinished runtime action is pending", contracts.RetryBackoff, true, nil)
		}
	}

	// P1-4: In pending phases, new idempotency keys cannot take over the pending action.
	if state.phase == "pausing" || state.phase == "resuming" {
		action, started := state.actions[actionHash]
		if !started || action.status != "started" {
			return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "start", contracts.ErrConflict, "cannot take over pending lifecycle phase with a different operation key", contracts.RetryNever, false, nil)
		}
	}

	// P1-1: If state is already active and a new key requests Start, verify full identity facts and record key as succeeded (noop).
	if state.phase == "active" {
		facts, inspectErr := p.inspectFacts(ctx, state.containerID)
		if inspectErr != nil || facts.ID != state.containerID || !facts.State.Running {
			return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "start", contracts.ErrConflict, "active runtime facts do not match", contracts.RetryNever, false, inspectErr)
		}
		port, matches := facts.matchesRunning(p.config, state.deployment, state.runtimeSpec())
		if !matches || (state.port > 0 && port != state.port) {
			return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "start", contracts.ErrConflict, "active runtime configuration drifted", contracts.RetryNever, false, nil)
		}
		if err := p.verifyRuntimeVolumes(ctx, state.runtimeSpec(), request.Operation); err != nil {
			return err
		}
		now := p.config.Clock().UTC()
		state.actions[actionHash] = runtimeAction{
			identityHash: actionHash,
			action:       "start",
			fingerprint:  state.fingerprint,
			status:       "succeeded",
			at:           now,
		}
		state.updatedAt = now
		if err := p.persistState(state); err != nil {
			return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "persist_state", contracts.ErrUnavailable, "noop start state could not be persisted", contracts.RetryBackoff, true, err)
		}
		return nil
	}

	if state.phase != "paused" && state.phase != "resuming" {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "start", contracts.ErrConflict, "runtime is not in a paused or resuming state", contracts.RetryNever, false, nil)
	}

	if err := p.verifyRuntimeVolumes(ctx, state.runtimeSpec(), request.Operation); err != nil {
		return err
	}

	// Verify existing container fact: missing container must fail with conflict (do not recreate).
	facts, inspectErr := p.inspectFacts(ctx, state.containerID)
	if inspectErr != nil {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "start", contracts.ErrConflict, "paused runtime container is missing; recreate is forbidden", contracts.RetryNever, false, inspectErr)
	}
	if facts.ID != state.containerID {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "start", contracts.ErrConflict, "container identity does not match paused deployment", contracts.RetryNever, false, nil)
	}

	port, matches := facts.matchesConfiguration(p.config, state.deployment, state.runtimeSpec())
	if !matches || (state.port > 0 && port != state.port) {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "start", contracts.ErrConflict, "runtime configuration or identity drifted before start; recreate is forbidden", contracts.RetryNever, false, nil)
	}

	// Host port external occupation check: if host port is occupied by external process while container is stopped, fail cleanly.
	if state.port > 0 && !facts.State.Running {
		listener, listenErr := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", state.port))
		if listenErr != nil {
			return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "start", contracts.ErrConflict, "host port is occupied by external process", contracts.RetryBackoff, true, listenErr)
		}
		_ = listener.Close()
	}

	// Verify network identity before effect: missing, extra, wrong ID, validator/guard failures all conflict before start
	if state.schemaVersion == durableRuntimeStateSchemaV3 && state.networkID == "" {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "start", contracts.ErrConflict, "persisted network identity is missing for schema 3 start", contracts.RetryNever, false, nil)
	}
	currentNetID, netErr := p.verifyRuntimeNetwork(ctx, facts, request.Operation, contracts.CapabilityRuntimeStart, "start")
	if netErr != nil {
		return netErr
	}
	if state.networkID != "" && currentNetID != state.networkID {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "start", contracts.ErrConflict, "runtime network identity changed before start; recreation of network is forbidden", contracts.RetryNever, false, nil)
	}
	if state.networkID == "" {
		state.networkID = currentNetID
	}

	// Crash/timeout convergence: if start was already started and container is now running, settle idempotently.
	if action, started := state.actions[actionHash]; started && action.action == "start" && action.fingerprint == state.fingerprint && action.status == "started" && facts.State.Running {
		runningPort, runningMatches := facts.matchesRunning(p.config, state.deployment, state.runtimeSpec())
		if runningMatches && runningPort == state.port {
			now := p.config.Clock().UTC()
			action.status = "succeeded"
			action.at = now
			state.actions[actionHash] = action
			state.phase = "active"
			state.deployment.Status = domain.DeploymentRuntimeReady
			state.schemaVersion = durableRuntimeStateSchemaV3
			state.updatedAt = now
			if err := p.persistState(state); err != nil {
				return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "persist_state", contracts.ErrUnavailable, "recovered start state could not be persisted", contracts.RetryBackoff, true, err)
			}
			return nil
		}
	}

	// Record resuming phase and started action with schema 3 retained.
	if action, started := state.actions[actionHash]; !started || action.status != "started" {
		now := p.config.Clock().UTC()
		state.schemaVersion = durableRuntimeStateSchemaV3
		state.phase = "resuming"
		state.actions[actionHash] = runtimeAction{
			identityHash:        actionHash,
			action:              "start",
			fingerprint:         state.fingerprint,
			status:              "started",
			previousContainerID: state.containerID,
			at:                  now,
		}
		state.updatedAt = now
		if err := p.persistState(state); err != nil {
			return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "persist_state", contracts.ErrUnavailable, "pending start state could not be persisted", contracts.RetryBackoff, true, err)
		}
	}

	// Execute docker start against immutable container ID.
	if err := p.run(ctx, []string{"start", state.containerID}); err != nil {
		return p.commandError(request.Operation, contracts.CapabilityRuntimeStart, "start", err)
	}

	// Inspect facts post-start: running, same ID, same configuration, same port, same volume.
	after, err := p.inspectFacts(ctx, state.containerID)
	if err != nil {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "start", contracts.ErrUnavailable, "started runtime container could not be inspected", contracts.RetryAfterReconnect, true, err)
	}
	if after.ID != state.containerID || !after.State.Running {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "start", contracts.ErrConflict, "runtime container failed to start into running status", contracts.RetryNever, false, nil)
	}
	afterPort, afterMatches := after.matchesRunning(p.config, state.deployment, state.runtimeSpec())
	if !afterMatches || afterPort != state.port {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "start", contracts.ErrConflict, "runtime facts or host port mismatch after start", contracts.RetryNever, false, nil)
	}

	afterNetID, afterNetErr := p.verifyRuntimeNetwork(ctx, after, request.Operation, contracts.CapabilityRuntimeStart, "start")
	if afterNetErr != nil {
		return afterNetErr
	}
	if state.networkID != "" && afterNetID != state.networkID {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "start", contracts.ErrConflict, "runtime network identity changed after start", contracts.RetryNever, false, nil)
	}

	now := p.config.Clock().UTC()
	state.schemaVersion = durableRuntimeStateSchemaV3
	state.phase = "active"
	state.deployment.Status = domain.DeploymentRuntimeReady
	state.actions[actionHash] = runtimeAction{
		identityHash: actionHash,
		action:       "start",
		fingerprint:  state.fingerprint,
		status:       "succeeded",
		at:           now,
	}
	state.updatedAt = now

	if err := p.persistState(state); err != nil {
		return p.failure(request.Operation, contracts.CapabilityRuntimeStart, "persist_state", contracts.ErrUnavailable, "active runtime state could not be persisted", contracts.RetryBackoff, true, err)
	}
	return nil
}
