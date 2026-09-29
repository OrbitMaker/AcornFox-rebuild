package standalone

import (
	"context"
	"encoding/json"

	"github.com/open-card/open-card/internal/contracts"
)

// Only a committed active deployment expresses the platform's intent to run.
// Destroy is the platform's explicit stop. A direct administrator docker stop
// has no platform intent record and is therefore treated like a host shutdown.
// Recovery is per deployment, not an all-or-nothing transaction across apps.
func (p *Provider) restoreActive(ctx context.Context, snapshot durableRuntimeState, state *runtimeState) error {
	if p.config.RestoreActiveGuard == nil || snapshot.Phase != "active" {
		return nil
	}
	operation := contracts.OperationContext{IdempotencyKey: "runtime-reconcile-" + hash(snapshot.Deployment.ID.String())[:24]}
	fail := func(message string) error {
		return p.failure(operation, contracts.CapabilityRuntimeRestart, "restore", contracts.ErrConflict, message, contracts.RetryAfterReconnect, true, nil)
	}
	ctx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()
	facts, err := p.inspectFacts(ctx, state.container)
	port, matches := facts.matchesConfiguration(p.config, snapshot.Deployment, snapshot.Spec)
	if err != nil || !matches || !validContainerID(snapshot.ContainerID) || facts.ID != snapshot.ContainerID || snapshot.Capacity == nil || port != snapshot.Capacity.HostPort {
		return fail("runtime identity or configuration changed before restoration")
	}
	// Leave interrupted explicit mutations to their original idempotent task.
	// Observation must remain available so that task can reconnect and settle;
	// startup recovery neither takes it over nor claims it succeeded.
	for _, action := range snapshot.Actions {
		if action.Status == "started" {
			return nil
		}
	}
	if !facts.State.Running && facts.State.Status != "exited" {
		return fail("runtime state is not eligible for restoration")
	}
	networkID, netErr := p.verifyRuntimeNetwork(ctx, facts, operation, contracts.CapabilityRuntimeRestart, "restore")
	if netErr != nil {
		return netErr
	}
	if snapshot.SchemaVersion == durableRuntimeStateSchemaV3 && snapshot.NetworkID != "" && networkID != snapshot.NetworkID {
		return fail("runtime network identity changed before restoration")
	}
	if facts.State.Running {
		return nil
	}
	// Address the immutable ID, never an adoptable name, across the start boundary.
	if err := p.run(ctx, []string{"start", snapshot.ContainerID}); err != nil {
		return p.commandError(operation, contracts.CapabilityRuntimeRestart, "restore", err)
	}
	facts, err = p.inspectFacts(ctx, snapshot.ContainerID)
	port, matches = facts.matchesRunning(p.config, snapshot.Deployment, snapshot.Spec)
	if err != nil || !matches || facts.ID != snapshot.ContainerID || port != snapshot.Capacity.HostPort || !facts.matchesRestoreNetwork(p.config.Network, networkID) {
		return fail("restored runtime is not verified running")
	}
	// No lifecycle or health success is fabricated in the durable record. Normal
	// observation/probing must still read Docker and the application afterward.
	return nil
}

// Application tasks require a real owned NAT network readback. Legacy worker
// and external networks retain their mandatory live RestoreActiveGuard.
func (p *Provider) requireRuntimeNetworkGuard(ctx context.Context, operation contracts.OperationContext, capability contracts.Capability, action string) error {
	if p.config.NetworkProfile == ApplicationLoopbackNetworkProfile {
		if _, err := p.inspectApplicationRuntimeNetwork(ctx, operation, capability, action); err != nil {
			return err
		}
		// No isolated-worker firewall guard is required by this ordinary NAT profile.
		// An explicitly configured extra guard is still honored below.
		if p.config.RestoreActiveGuard == nil {
			return nil
		}
	}
	if p.config.RestoreActiveGuard == nil {
		return p.failure(operation, capability, action, contracts.ErrConflict, "runtime network guard is required", contracts.RetryNever, false, nil)
	}
	if err := p.config.RestoreActiveGuard(ctx); err != nil {
		return p.failure(operation, capability, action, contracts.ErrConflict, "runtime network guard is not ready", contracts.RetryBackoff, true, err)
	}
	return nil
}

// verifyRuntimeNetworkTopology validates the configured profile and exact single
// attachment identity. It never creates or replaces a missing network.
func (p *Provider) verifyRuntimeNetworkTopology(ctx context.Context, facts inspectFacts, operation contracts.OperationContext, capability contracts.Capability, action string) (string, error) {
	if p.config.NetworkProfile == ApplicationLoopbackNetworkProfile {
		netID, err := p.inspectApplicationRuntimeNetwork(ctx, operation, capability, action)
		if err != nil {
			return "", err
		}
		if !facts.matchesRestoreNetwork(p.config.Network, netID) {
			return "", p.failure(operation, capability, action, contracts.ErrConflict, "application network attachments are missing, extra or mismatched", contracts.RetryNever, false, nil)
		}
		return netID, nil
	}
	if p.config.ExistingNetworkValidator == nil {
		return "", p.failure(operation, capability, action, contracts.ErrConflict, "runtime network validator is missing", contracts.RetryNever, false, nil)
	}
	if facts.NetworkSettings.Networks == nil || len(facts.NetworkSettings.Networks) == 0 {
		return "", p.failure(operation, capability, action, contracts.ErrConflict, "runtime network attachments are missing or empty", contracts.RetryNever, false, nil)
	}
	rawNetwork, err := p.output(ctx, []string{"network", "inspect", p.config.Network})
	if err != nil {
		return "", p.failure(operation, capability, action, contracts.ErrConflict, "runtime network inspect failed", contracts.RetryAfterReconnect, true, err)
	}
	if err := p.config.ExistingNetworkValidator([]byte(rawNetwork)); err != nil {
		return "", p.failure(operation, capability, action, contracts.ErrConflict, "runtime network validator rejected network", contracts.RetryNever, false, err)
	}
	var networks []struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal([]byte(rawNetwork), &networks); err != nil || len(networks) != 1 || !validContainerID(networks[0].ID) {
		return "", p.failure(operation, capability, action, contracts.ErrConflict, "runtime network topology is invalid", contracts.RetryNever, false, err)
	}
	netID := networks[0].ID
	if !facts.matchesRestoreNetwork(p.config.Network, netID) {
		return "", p.failure(operation, capability, action, contracts.ErrConflict, "runtime network attachments are missing, extra or mismatched", contracts.RetryNever, false, nil)
	}
	return netID, nil
}

// verifyRuntimeNetwork performs both network topology verification and live guard verification.
func (p *Provider) verifyRuntimeNetwork(ctx context.Context, facts inspectFacts, operation contracts.OperationContext, capability contracts.Capability, action string) (string, error) {
	if err := p.requireRuntimeNetworkGuard(ctx, operation, capability, action); err != nil {
		return "", err
	}
	return p.verifyRuntimeNetworkTopology(ctx, facts, operation, capability, action)
}

func (facts inspectFacts) matchesRestoreNetwork(name, id string) bool {
	attachment, exists := facts.NetworkSettings.Networks[name]
	return exists && len(facts.NetworkSettings.Networks) == 1 && attachment.NetworkID == id
}

// Reuse the same managed bridge/NAT validator used by deploy and operative
// running-container inspection. Network mutations and permissive callbacks are
// deliberately absent from lifecycle/recovery verification.
func (p *Provider) inspectApplicationRuntimeNetwork(ctx context.Context, operation contracts.OperationContext, capability contracts.Capability, action string) (string, error) {
	raw, err := p.output(ctx, []string{"network", "inspect", p.config.Network})
	if err != nil {
		return "", p.failure(operation, capability, action, contracts.ErrConflict, "application runtime network inspect failed", contracts.RetryAfterReconnect, true, err)
	}
	network, err := p.validateApplicationNetwork([]byte(raw))
	if err != nil {
		return "", p.failure(operation, capability, action, contracts.ErrConflict, "application runtime network differs from the owned NAT profile", contracts.RetryNever, false, err)
	}
	return network.ID, nil
}
