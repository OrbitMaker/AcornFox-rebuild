package standalone

import (
	"context"

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
	// Never take over an interrupted explicit lifecycle mutation.
	for _, action := range snapshot.Actions {
		if action.Status == "started" {
			return fail("active runtime has an unfinished lifecycle action")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()
	facts, err := p.inspectFacts(ctx, state.container)
	port, matches := facts.matchesConfiguration(p.config, snapshot.Deployment, snapshot.Spec)
	if err != nil || !matches || !validContainerID(snapshot.ContainerID) || facts.ID != snapshot.ContainerID || snapshot.Capacity == nil || port != snapshot.Capacity.HostPort {
		return fail("runtime identity or configuration changed before restoration")
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
	// This validation path cannot create a missing network.
	if err := p.ensureNetwork(ctx, operation); err != nil {
		return err
	}
	// Address the immutable ID, never an adoptable name, across the start boundary.
	if err := p.run(ctx, []string{"start", snapshot.ContainerID}); err != nil {
		return p.commandError(operation, contracts.CapabilityRuntimeRestart, "restore", err)
	}
	facts, err = p.inspectFacts(ctx, snapshot.ContainerID)
	port, matches = facts.matchesRunning(p.config, snapshot.Deployment, snapshot.Spec)
	if err != nil || !matches || facts.ID != snapshot.ContainerID || port != snapshot.Capacity.HostPort {
		return fail("restored runtime is not verified running")
	}
	// No lifecycle or health success is fabricated in the durable record. Normal
	// observation/probing must still read Docker and the application afterward.
	return nil
}
