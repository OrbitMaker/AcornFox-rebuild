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
	if facts.State.Running {
		return nil
	}
	if facts.State.Status != "exited" {
		return fail("runtime state is not eligible for restoration")
	}
	if p.config.ExistingNetworkValidator == nil || p.config.RestoreActiveGuard(ctx) != nil {
		return fail("runtime network guard is not ready for restoration")
	}
	// Read the validated network identity, not only the container's original
	// NetworkMode: Docker can attach a second unguarded network afterward.
	// This path cannot create a missing network.
	rawNetwork, err := p.output(ctx, []string{"network", "inspect", p.config.Network})
	var networks []struct {
		ID string `json:"Id"`
	}
	if err != nil || p.config.ExistingNetworkValidator([]byte(rawNetwork)) != nil || json.Unmarshal([]byte(rawNetwork), &networks) != nil || len(networks) != 1 || !validContainerID(networks[0].ID) || !facts.matchesRestoreNetwork(p.config.Network, networks[0].ID) {
		return fail("runtime network attachments are missing or changed")
	}
	// Address the immutable ID, never an adoptable name, across the start boundary.
	if err := p.run(ctx, []string{"start", snapshot.ContainerID}); err != nil {
		return p.commandError(operation, contracts.CapabilityRuntimeRestart, "restore", err)
	}
	facts, err = p.inspectFacts(ctx, snapshot.ContainerID)
	port, matches = facts.matchesRunning(p.config, snapshot.Deployment, snapshot.Spec)
	if err != nil || !matches || facts.ID != snapshot.ContainerID || port != snapshot.Capacity.HostPort || !facts.matchesRestoreNetwork(p.config.Network, networks[0].ID) {
		return fail("restored runtime is not verified running")
	}
	// No lifecycle or health success is fabricated in the durable record. Normal
	// observation/probing must still read Docker and the application afterward.
	return nil
}

func (facts inspectFacts) matchesRestoreNetwork(name, id string) bool {
	attachment, exists := facts.NetworkSettings.Networks[name]
	return exists && len(facts.NetworkSettings.Networks) == 1 && attachment.NetworkID == id
}
