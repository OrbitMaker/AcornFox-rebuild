//go:build integration

package persistence_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

func TestM1DeliveryPersistsDigestTaskObservationAndServing(t *testing.T) {
	databaseURL := os.Getenv("OPEN_CARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("OPEN_CARD_TEST_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	suffix := strings.ToLower(domain.MustNewID("m1").String())
	applicationID := domain.ID("app_" + suffix)
	environmentID := domain.ID("env_" + suffix)
	if _, err := db.ExecContext(ctx, `INSERT INTO applications(id,name) VALUES($1,$2)`, applicationID.String(), "m1-delivery-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO environments(id,application_id,name) VALUES($1,$2,'default')`, environmentID.String(), applicationID.String()); err != nil {
		t.Fatal(err)
	}
	store, err := postgres.OpenStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	controller := &controllers.ReleaseController{Store: store, Source: contracts.NewFakeSourceProvider(), Build: contracts.NewFakeBuildProvider(true), Capacity: contracts.NewFakeCapacityProvider(true), Clock: func() time.Time { return time.Now().UTC() }}
	publish := controllers.PublishRequest{
		ApplicationID: applicationID, EnvironmentID: environmentID, ServiceGroupID: domain.ID("legacy"), ServiceName: "web",
		Source:    contracts.PrepareSourceRequest{Kind: domain.SourceGitHTTPS, Locator: "https://example.com/open-card.git", Ref: "main", ContentDigest: "sha256:" + strings.Repeat("a", 64), WorkspaceRef: "/immutable/" + suffix},
		BuildKind: domain.BuildDockerfile, ContextPath: ".", DockerfilePath: "Dockerfile", TargetRepository: "open-card.local/apps/" + suffix,
		OutputStorageKey: applicationID.String() + "/web", BuildResources: contracts.ResourceLimits{CPUMillis: 500, MemoryBytes: 512 << 20, DiskBytes: 256 << 20}, BuildNetwork: contracts.NetworkPolicy{Mode: "none"},
		RuntimeResources: contracts.ResourceLimits{CPUMillis: 250, MemoryBytes: 64 << 20, DiskBytes: 128 << 20, PIDs: 64}, ContainerPort: 18080, Version: 1, IdempotencyKey: "m1-publish-" + suffix, Actor: "integration-test",
	}
	result, err := controller.Publish(ctx, publish)
	if err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := store.ClaimControllerTask(ctx, postgres.ClaimTaskRequest{Owner: "clean-worker-01", Now: time.Now().UTC(), LeasePolicy: postgres.LeasePolicy{Duration: time.Minute, MaxAttempts: 3}})
	if err != nil || !ok || claimed.Task.ID != result.TaskID {
		t.Fatalf("claim task: ok=%v task=%s err=%v", ok, claimed.Task.ID, err)
	}
	marked, err := store.MarkNodeDeploymentsUnknown(ctx, "clean-worker-01", time.Now().UTC())
	if err != nil || marked != 1 {
		t.Fatalf("mark node unknown: marked=%d err=%v", marked, err)
	}
	unknown, err := store.GetDeployment(ctx, result.Deployment.ID)
	if err != nil || unknown.Status != domain.DeploymentUnknown {
		t.Fatalf("deployment did not become unknown on heartbeat loss: %#v err=%v", unknown, err)
	}
	sink := &controllers.DurableAgentSink{Store: store, Clock: func() time.Time { return time.Now().UTC() }}
	send := func(sequence uint64, kind v1.MessageKind, payload any) {
		t.Helper()
		encoded, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		envelope := v1.Envelope{Protocol: v1.ProtocolName, Version: v1.ProtocolVersion, MessageID: domain.MustNewID("msg").String(), InstanceID: "clean-worker", NodeID: "clean-worker-01", Kind: kind, SentAt: time.Now().UTC(), IdempotencyKey: result.Operation.IdempotencyKey, AgentSequence: sequence, Payload: encoded}
		if err := sink.RecordAgentEnvelope(ctx, envelope); err != nil {
			t.Fatalf("record %s: %v", kind, err)
		}
	}
	send(1, v1.KindTaskAck, v1.TaskAck{TaskID: result.TaskID.String(), Status: v1.AckAccepted})
	runtimeObservation := contracts.RuntimeObservation{DeploymentID: result.Deployment.ID, ServiceName: "web", Status: "running", Healthy: true, HostPort: 18080, ObservedAt: time.Now().UTC(), Evidence: contracts.Evidence{Refs: []domain.EvidenceRef{{ID: "ev_runtime", Kind: "runtime.health"}}, Redacted: true}}
	details, _ := json.Marshal(runtimeObservation)
	send(2, v1.KindObservation, v1.Observation{TaskID: result.TaskID.String(), Sequence: 1, TargetRef: "deployment/" + result.Deployment.ID.String(), Status: "runtime_ready", Healthy: true, At: time.Now().UTC(), EvidenceRefs: []string{"ev_runtime", "loopback-health:18080"}, Details: details})
	send(3, v1.KindTaskResult, v1.TaskResult{TaskID: result.TaskID.String(), IdempotencyKey: result.Operation.IdempotencyKey, Succeeded: true, Status: v1.TaskResultSucceeded, EvidenceRefs: []string{"ev_runtime", "loopback-health:18080"}})

	deployment, err := store.GetDeployment(ctx, result.Deployment.ID)
	if err != nil || deployment.Status != domain.DeploymentServing {
		t.Fatalf("deployment did not reach serving: %#v err=%v", deployment, err)
	}
	endpoint, err := store.GetDeploymentEndpoint(ctx, result.Deployment.ID)
	if err != nil || !endpoint.Healthy || endpoint.HostIP != "127.0.0.1" || endpoint.HostPort != 18080 {
		t.Fatalf("endpoint was not persisted: %#v err=%v", endpoint, err)
	}
	if result.Artifact.Image.Digest == "" || result.Artifact.OCIStorageRef == "" || result.Artifact.BuildID != result.Build.ID {
		t.Fatalf("persistent artifact binding is incomplete: %#v", result.Artifact)
	}
}
