package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type m4ObservationStoreFixture struct {
	candidates []postgres.M4ObservationCandidate
	queued     []postgres.EnqueueControllerTaskRequest
}

func (s *m4ObservationStoreFixture) ListM4ObservationCandidates(_ context.Context, _ time.Time, _ int) ([]postgres.M4ObservationCandidate, error) {
	return append([]postgres.M4ObservationCandidate(nil), s.candidates...), nil
}
func (s *m4ObservationStoreFixture) GetM2ReleaseRuntimeSpec(_ context.Context, releaseID domain.ID) (contracts.ServiceGroupRuntimeSpec, string, error) {
	return contracts.ServiceGroupRuntimeSpec{ReleaseID: releaseID}, "sha256:fixture", nil
}
func (s *m4ObservationStoreFixture) EnqueueControllerTask(_ context.Context, request postgres.EnqueueControllerTaskRequest) (application.Event, error) {
	s.queued = append(s.queued, request)
	s.candidates = nil
	return application.Event{}, nil
}

func TestM4ObservationSchedulerQueuesTypedAgentFactRefresh(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	store := &m4ObservationStoreFixture{candidates: []postgres.M4ObservationCandidate{{Deployment: domain.Deployment{ID: "dep_m4", ApplicationID: "app_m4", EnvironmentID: "env_m4", ReleaseID: "release_m4", Status: domain.DeploymentServing, CreatedAt: now, UpdatedAt: now}}}}
	scheduler := &M4ObservationScheduler{Store: store, Interval: 5 * time.Second, Clock: func() time.Time { return now }}
	queued, err := scheduler.ScheduleOnce(context.Background(), 10)
	if err != nil || queued != 1 || len(store.queued) != 1 {
		t.Fatalf("scheduler result queued=%d err=%v tasks=%#v", queued, err, store.queued)
	}
	task := store.queued[0]
	if task.Operation.Type != domain.OperationObserve || task.ExistingDeploymentID != "dep_m4" || task.Operation.Status != domain.OperationPending {
		t.Fatalf("scheduler did not create an observation-only operation: %#v", task)
	}
	var spec controllers.AgentTaskSpec
	if err := json.Unmarshal(task.Payload, &spec); err != nil || spec.Kind != v1.TaskObserve {
		t.Fatalf("scheduler task payload=%s err=%v", task.Payload, err)
	}
	var wrapper struct {
		M4PayloadType string          `json:"m4_payload_type"`
		Request       json.RawMessage `json:"request"`
	}
	if err := json.Unmarshal(spec.Parameters, &wrapper); err != nil || wrapper.M4PayloadType != "service_group.observe" {
		t.Fatalf("scheduler did not use strict M4 group observation marker: %s err=%v", spec.Parameters, err)
	}
	if queued, err := scheduler.ScheduleOnce(context.Background(), 10); err != nil || queued != 0 {
		t.Fatalf("scheduler repeated a candidate before store reported it due: queued=%d err=%v", queued, err)
	}
}
