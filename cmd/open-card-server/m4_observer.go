package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type m4ObservationStore interface {
	ListM4ObservationCandidates(context.Context, time.Time, int) ([]postgres.M4ObservationCandidate, error)
	GetM2ReleaseRuntimeSpec(context.Context, domain.ID) (contracts.ServiceGroupRuntimeSpec, string, error)
	EnqueueControllerTask(context.Context, postgres.EnqueueControllerTaskRequest) (application.Event, error)
}

// M4ObservationScheduler creates typed, durable Agent observe tasks. It never
// reads Docker, fabricates health, or mutates a deployment state itself.
type M4ObservationScheduler struct {
	Store    m4ObservationStore
	Interval time.Duration
	Clock    func() time.Time
}

func (s *M4ObservationScheduler) ScheduleOnce(ctx context.Context, limit int) (int, error) {
	if s == nil || s.Store == nil {
		return 0, errors.New("M4 observation scheduler requires a store")
	}
	if limit <= 0 || limit > 100 {
		return 0, domain.ValidationError("M4 observation scheduler limit must be between 1 and 100")
	}
	now := s.now()
	candidates, err := s.Store.ListM4ObservationCandidates(ctx, now.Add(-s.interval()), limit)
	if err != nil {
		return 0, err
	}
	queued := 0
	for _, candidate := range candidates {
		spec, _, err := s.Store.GetM2ReleaseRuntimeSpec(ctx, candidate.Deployment.ReleaseID)
		if err != nil {
			return queued, err
		}
		operation := domain.Operation{ID: m4AdapterID("observe", candidate.Deployment.ID.String()+":"+now.Truncate(s.interval()).Format(time.RFC3339Nano)), ApplicationID: candidate.Deployment.ApplicationID, EnvironmentID: candidate.Deployment.EnvironmentID, TargetRef: "deployment/" + candidate.Deployment.ID.String(), Type: domain.OperationObserve, IdempotencyKey: "m4-observe:" + candidate.Deployment.ID.String() + ":" + now.Truncate(s.interval()).Format(time.RFC3339Nano), Status: domain.OperationPending, CreatedAt: now, UpdatedAt: now}
		if err := operation.Validate(); err != nil {
			return queued, err
		}
		request := contracts.ObserveGroupRequest{DeploymentID: candidate.Deployment.ID, Operation: contracts.OperationContext{IdempotencyKey: operation.IdempotencyKey, Deadline: now.Add(90 * time.Second), Actor: "m4-observation-scheduler"}}
		if err := request.Operation.Validate(); err != nil {
			return queued, err
		}
		parameters, err := m4GroupParameters("service_group.observe", request)
		if err != nil {
			return queued, err
		}
		payload, err := json.Marshal(controllers.AgentTaskSpec{Kind: v1.TaskObserve, Parameters: parameters})
		if err != nil {
			return queued, err
		}
		_ = spec // GetM2ReleaseRuntimeSpec establishes that this is a complete M2 group release before queueing.
		_, err = s.Store.EnqueueControllerTask(ctx, postgres.EnqueueControllerTaskRequest{Operation: operation, ExistingDeploymentID: candidate.Deployment.ID, TaskID: m4AdapterID("task", operation.ID.String()), Payload: payload, MaxAttempts: 3, InitialPublishStatus: domain.PublishPreparing})
		if err != nil {
			return queued, err
		}
		queued++
	}
	return queued, nil
}

func (s *M4ObservationScheduler) interval() time.Duration {
	if s.Interval <= 0 {
		return 5 * time.Second
	}
	return s.Interval
}
func (s *M4ObservationScheduler) now() time.Time {
	if s.Clock == nil {
		return time.Now().UTC()
	}
	return s.Clock().UTC()
}
