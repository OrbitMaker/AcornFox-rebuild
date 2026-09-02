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

type acornFoxLogCollectionStoreFixture struct {
	candidates []postgres.AcornFoxLogCollectionCandidate
	runtime    contracts.AcornFoxRuntimeDeployRequest
	queued     []postgres.EnqueueControllerTaskRequest
}

func (f *acornFoxLogCollectionStoreFixture) ListAcornFoxLogCollectionCandidates(_ context.Context, _ time.Time, _ int) ([]postgres.AcornFoxLogCollectionCandidate, error) {
	return f.candidates, nil
}
func (f *acornFoxLogCollectionStoreFixture) GetAcornFoxRuntimeRequest(_ context.Context, _, _ domain.ID) (contracts.AcornFoxRuntimeDeployRequest, error) {
	return f.runtime, nil
}
func (f *acornFoxLogCollectionStoreFixture) EnqueueControllerTask(_ context.Context, request postgres.EnqueueControllerTaskRequest) (application.Event, error) {
	f.queued = append(f.queued, request)
	return application.Event{}, nil
}

func TestAcornFoxLogCollectionSchedulerUsesTrustedRuntimeFactAndCapsTick(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	fact := contracts.AcornFoxRuntimeReleaseFact{ApplicationID: "app_logs", EnvironmentID: "env_logs", ReleaseID: "release_logs", ServiceName: "web", Image: domain.ImageDigest{Repository: "registry.open-card.test/apps/web", Digest: acornFoxProbeDigest}, Resources: contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 100, MemoryBytes: 1024, PIDs: 10, DiskReservationBytes: 2048}, AcceptedAt: now, Immutable: true}
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	if err != nil {
		t.Fatal(err)
	}
	store := &acornFoxLogCollectionStoreFixture{candidates: []postgres.AcornFoxLogCollectionCandidate{{ApplicationID: fact.ApplicationID, EnvironmentID: fact.EnvironmentID, DeploymentID: deploymentID}, {ApplicationID: fact.ApplicationID, EnvironmentID: fact.EnvironmentID, DeploymentID: "deployment_older"}}, runtime: contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "deploy-logs"}}
	clock := now
	scheduler := &AcornFoxLogCollectionScheduler{Store: store, Clock: func() time.Time { return clock }}
	queued, err := scheduler.ScheduleOnce(context.Background(), acornFoxLogCollectorMaximumPerTick)
	if err != nil || queued != 1 || len(store.queued) != 1 {
		t.Fatalf("queued=%d err=%v requests=%#v", queued, err, store.queued)
	}
	request := store.queued[0]
	if request.ExistingDeploymentID != deploymentID || request.MaxAttempts != application.AcornFoxLogsTaskAttempts || request.Operation.Type != domain.OperationObserve || request.Operation.ApplicationID != fact.ApplicationID || request.Operation.EnvironmentID != fact.EnvironmentID {
		t.Fatalf("unexpected logs task: %#v", request)
	}
	firstKey := request.Operation.IdempotencyKey
	clock = now.Add(application.AcornFoxLogsCollectionInterval)
	if queued, err := scheduler.ScheduleOnce(context.Background(), acornFoxLogCollectorMaximumPerTick); err != nil || queued != 1 || len(store.queued) != 2 || store.queued[1].Operation.IdempotencyKey == firstKey {
		t.Fatalf("next bucket did not create a new durable identity: queued=%d err=%v requests=%#v", queued, err, store.queued)
	}
	if _, err := scheduler.ScheduleOnce(context.Background(), acornFoxLogCollectorMaximumPerTick+1); err == nil {
		t.Fatal("expected maximum tick bound")
	}
}
