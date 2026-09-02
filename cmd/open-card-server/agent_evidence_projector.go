package main

import (
	"context"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// agentEvidenceProjectorChain keeps independent evidence projections explicit
// at composition time. Each projector must be replay-safe on its own; the
// chain only preserves their deterministic ordering.
type agentEvidenceProjectorChain []controllers.AgentEvidenceProjector

func (chain agentEvidenceProjectorChain) ProjectAgentEvidence(ctx context.Context, task postgres.ControllerTask, envelope v1.Envelope) error {
	for _, projector := range chain {
		if projector == nil {
			continue
		}
		if err := projector.ProjectAgentEvidence(ctx, task, envelope); err != nil {
			return err
		}
	}
	return nil
}

var _ controllers.AgentEvidenceProjector = agentEvidenceProjectorChain{}
