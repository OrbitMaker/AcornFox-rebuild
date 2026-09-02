package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

func TestProjectAgentEvidenceTreatsMarkedProbeAsAlreadyDurable(t *testing.T) {
	plan := probeProjectorTaskPlan(t)
	task := postgres.ControllerTask{Task: postgres.Task{ID: plan.TaskID, OperationID: plan.Operation.ID, Payload: plan.Payload}, Operation: plan.Operation, DeploymentID: probeProjectorDeploymentID(t)}
	// No Store, metrics, or logs are configured. The marked task is an
	// intentional no-op because RecordAgentEvent committed its raw event and
	// immutable probe fact in the same database transaction.
	if err := (&m4PostgresAdapter{}).ProjectAgentEvidence(context.Background(), task, v1.Envelope{Kind: v1.KindObservation, AgentSequence: 3}); err != nil {
		t.Fatalf("marked probe projection was not a no-op: %v", err)
	}
}

func TestProjectAgentEvidenceKeepsNonProbeNilMetricNoop(t *testing.T) {
	task := postgres.ControllerTask{Task: postgres.Task{ID: "task_non_probe", Payload: []byte(`{"kind":"observe","parameters":{"scope":"node_docker_facts"}}`)}, DeploymentID: "dep_non_probe"}
	if err := (&m4PostgresAdapter{}).ProjectAgentEvidence(context.Background(), task, v1.Envelope{Kind: v1.KindObservation, AgentSequence: 1}); err != nil {
		t.Fatalf("legacy nil-metric no-op changed: %v", err)
	}
}

func probeProjectorTaskPlan(t *testing.T) application.AcornFoxProbeTaskPlan {
	t.Helper()
	now := time.Unix(1700000000, 0).UTC()
	fact := contracts.AcornFoxRuntimeReleaseFact{ApplicationID: "app_probe", EnvironmentID: "env_probe", ReleaseID: "release_probe", ServiceName: "web", Image: domain.ImageDigest{Repository: "registry.open-card.test/apps/web", Digest: "sha256:" + strings.Repeat("a", 64)}, Resources: contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 100, MemoryBytes: 1024, PIDs: 10, DiskReservationBytes: 2048}, ContainerPort: 8080, AcceptedAt: now, Immutable: true}
	request, err := contracts.NewAcornFoxProbeRequest(contracts.AcornFoxRuntimeReference{Fact: fact}, contracts.AcornFoxProbeProtocolHTTP, "/ready", "probe-projector")
	if err != nil {
		t.Fatal(err)
	}
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := application.BuildAcornFoxProbeTaskPlan(request, contracts.AcornFoxRuntimeObservation{DeploymentID: deploymentID, ServiceName: fact.ServiceName, InternalAddress: "127.0.0.1:39124", ObservedAt: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func probeProjectorDeploymentID(t *testing.T) domain.ID {
	t.Helper()
	plan := probeProjectorTaskPlan(t)
	var request struct {
		Parameters struct {
			Request contracts.AcornFoxProbeRequest `json:"request"`
		} `json:"parameters"`
	}
	if err := json.Unmarshal(plan.Payload, &request); err != nil {
		t.Fatal(err)
	}
	id, err := contracts.AcornFoxRuntimeDeploymentID(request.Parameters.Request.Reference.Fact)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
