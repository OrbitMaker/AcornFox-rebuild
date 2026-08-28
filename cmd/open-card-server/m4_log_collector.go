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

type m4LogCollectionStore interface {
	ListM4LogCollectionCandidates(context.Context, time.Time, int) ([]postgres.M4LogCollectionCandidate, error)
	EnqueueControllerTask(context.Context, postgres.EnqueueControllerTaskRequest) (application.Event, error)
}

// M4LogCollectionScheduler periodically creates typed, read-only Agent log
// tasks for immutable M2 service identities. It never accepts a container
// name, host path, command, or secret, and it skips duplicate environments in
// one pass so the Store's one-active-operation invariant remains authoritative.
type M4LogCollectionScheduler struct {
	Store    m4LogCollectionStore
	Interval time.Duration
	Clock    func() time.Time
}

func (s *M4LogCollectionScheduler) ScheduleOnce(ctx context.Context, limit int) (int, error) {
	if s == nil || s.Store == nil {
		return 0, errors.New("M4 log collection scheduler requires a store")
	}
	if limit <= 0 || limit > 100 {
		return 0, domain.ValidationError("M4 log collection scheduler limit must be between 1 and 100")
	}
	now := s.now()
	candidates, err := s.Store.ListM4LogCollectionCandidates(ctx, now.Add(-s.interval()), limit)
	if err != nil {
		return 0, err
	}
	queued := 0
	seenEnvironments := make(map[domain.ID]struct{}, len(candidates))
	for _, candidate := range candidates {
		if _, duplicate := seenEnvironments[candidate.Deployment.EnvironmentID]; duplicate {
			continue
		}
		seenEnvironments[candidate.Deployment.EnvironmentID] = struct{}{}
		bucket := now.Truncate(s.interval()).Format(time.RFC3339Nano)
		identity := candidate.Deployment.ID.String() + ":" + candidate.ServiceName + ":" + bucket
		operation := domain.Operation{
			ID:             m4AdapterID("logs", identity),
			ApplicationID:  candidate.Deployment.ApplicationID,
			EnvironmentID:  candidate.Deployment.EnvironmentID,
			TargetRef:      "deployment/" + candidate.Deployment.ID.String() + "/service/" + candidate.ServiceName + "/logs",
			Type:           domain.OperationObserve,
			IdempotencyKey: "m4-logs:" + identity,
			Status:         domain.OperationPending,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		if err := operation.Validate(); err != nil {
			return queued, err
		}
		request := contracts.LogsRequest{
			DeploymentID: candidate.Deployment.ID,
			ServiceName:  candidate.ServiceName,
			Since:        now.Add(-s.interval()),
			Tail:         64,
			Operation: contracts.OperationContext{
				IdempotencyKey: operation.IdempotencyKey,
				Deadline:       now.Add(90 * time.Second),
				Actor:          "m4-log-collector",
			},
		}
		parameters, err := m4GroupParameters("service_group.logs", request)
		if err != nil {
			return queued, err
		}
		payload, err := json.Marshal(controllers.AgentTaskSpec{Kind: v1.TaskLogs, Parameters: parameters})
		if err != nil {
			return queued, err
		}
		if _, err := s.Store.EnqueueControllerTask(ctx, postgres.EnqueueControllerTaskRequest{
			Operation:            operation,
			ExistingDeploymentID: candidate.Deployment.ID,
			TaskID:               m4AdapterID("task", operation.ID.String()),
			Payload:              payload,
			MaxAttempts:          3,
			InitialPublishStatus: domain.PublishPreparing,
		}); err != nil {
			return queued, err
		}
		queued++
	}
	return queued, nil
}

func (s *M4LogCollectionScheduler) interval() time.Duration {
	if s.Interval <= 0 {
		return 30 * time.Second
	}
	return s.Interval
}

func (s *M4LogCollectionScheduler) now() time.Time {
	if s.Clock == nil {
		return time.Now().UTC()
	}
	return s.Clock().UTC()
}
