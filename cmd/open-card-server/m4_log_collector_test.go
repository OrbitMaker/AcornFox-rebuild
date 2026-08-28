package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type m4LogCollectionStoreFixture struct {
	candidates []postgres.M4LogCollectionCandidate
	queued     []postgres.EnqueueControllerTaskRequest
}

func (s *m4LogCollectionStoreFixture) ListM4LogCollectionCandidates(context.Context, time.Time, int) ([]postgres.M4LogCollectionCandidate, error) {
	return append([]postgres.M4LogCollectionCandidate(nil), s.candidates...), nil
}

func (s *m4LogCollectionStoreFixture) EnqueueControllerTask(_ context.Context, request postgres.EnqueueControllerTaskRequest) (application.Event, error) {
	s.queued = append(s.queued, request)
	return application.Event{}, nil
}

func TestM4LogCollectionSchedulerQueuesTypedGroupLogsAndSerializesEnvironment(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	deployment := domain.Deployment{ID: "dep_logs", ApplicationID: "app_logs", EnvironmentID: "env_logs", ReleaseID: "release_logs", Status: domain.DeploymentServing, CreatedAt: now, UpdatedAt: now}
	store := &m4LogCollectionStoreFixture{candidates: []postgres.M4LogCollectionCandidate{
		{Deployment: deployment, ServiceName: "frontend"},
		{Deployment: deployment, ServiceName: "worker"},
	}}
	scheduler := &M4LogCollectionScheduler{Store: store, Interval: time.Minute, Clock: func() time.Time { return now }}
	queued, err := scheduler.ScheduleOnce(context.Background(), 10)
	if err != nil || queued != 1 || len(store.queued) != 1 {
		t.Fatalf("log collection queued=%d err=%v tasks=%#v", queued, err, store.queued)
	}
	task := store.queued[0]
	if task.Operation.Type != domain.OperationObserve || task.ExistingDeploymentID != deployment.ID || task.Operation.Status != domain.OperationPending {
		t.Fatalf("log collection operation is not read-only and deployment-bound: %#v", task)
	}
	var spec controllers.AgentTaskSpec
	if err := json.Unmarshal(task.Payload, &spec); err != nil || spec.Kind != v1.TaskLogs {
		t.Fatalf("log collection payload=%s err=%v", task.Payload, err)
	}
	var wrapper struct {
		M4PayloadType string          `json:"m4_payload_type"`
		Request       json.RawMessage `json:"request"`
	}
	if err := json.Unmarshal(spec.Parameters, &wrapper); err != nil || wrapper.M4PayloadType != "service_group.logs" {
		t.Fatalf("log collection did not use strict group marker: %s err=%v", spec.Parameters, err)
	}
	if service := m4LogTaskServiceName(task.Payload); service != "frontend" {
		t.Fatalf("persisted group log task lost service identity: %q", service)
	}
}
