package main

import (
	"context"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type acornFoxProbeTaskStoreFixture struct {
	request postgres.EnqueueControllerTaskRequest
}

func (s *acornFoxProbeTaskStoreFixture) EnqueueControllerTask(_ context.Context, request postgres.EnqueueControllerTaskRequest) (application.Event, error) {
	s.request = request
	return application.Event{}, nil
}

func TestAcornFoxProbeTaskCreatorRecordsOneDurableObserveIntent(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	fact := contracts.AcornFoxRuntimeReleaseFact{ApplicationID: "app_probe", EnvironmentID: "env_probe", ReleaseID: "release_probe", ServiceName: "web", Image: domain.ImageDigest{Repository: "registry.open-card.test/apps/web", Digest: acornFoxProbeDigest}, Resources: contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 100, MemoryBytes: 1024, PIDs: 10, DiskReservationBytes: 2048}, ContainerPort: 8080, AcceptedAt: now, Immutable: true}
	request, err := contracts.NewAcornFoxProbeRequest(contracts.AcornFoxRuntimeReference{Fact: fact}, contracts.AcornFoxProbeProtocolTCP, "", "probe-once")
	if err != nil {
		t.Fatal(err)
	}
	deploymentID, _ := contracts.AcornFoxRuntimeDeploymentID(fact)
	store := &acornFoxProbeTaskStoreFixture{}
	creator := &AcornFoxProbeTaskCreator{Store: store, Clock: func() time.Time { return now }}
	if _, err := creator.CreateOnce(context.Background(), request, contracts.AcornFoxRuntimeObservation{DeploymentID: deploymentID, ServiceName: fact.ServiceName, InternalAddress: "127.0.0.1:39124", ObservedAt: now}); err != nil {
		t.Fatal(err)
	}
	if store.request.ExistingDeploymentID != deploymentID || store.request.Operation.Type != domain.OperationObserve || store.request.Operation.IdempotencyKey != request.IdempotencyKey || store.request.MaxAttempts != 3 {
		t.Fatalf("unexpected durable probe request: %#v", store.request)
	}
}

const acornFoxProbeDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
