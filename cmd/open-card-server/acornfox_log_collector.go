package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

const acornFoxLogCollectorMaximumPerTick = 10

type acornFoxLogCollectionStore interface {
	ListAcornFoxLogCollectionCandidates(context.Context, time.Time, int) ([]postgres.AcornFoxLogCollectionCandidate, error)
	GetAcornFoxRuntimeRequest(context.Context, domain.ID, domain.ID) (contracts.AcornFoxRuntimeDeployRequest, error)
	EnqueueControllerTask(context.Context, postgres.EnqueueControllerTaskRequest) (application.Event, error)
}

// AcornFoxLogCollectionScheduler is an internal, bounded read-only collector.
// It never shares the M2 group scheduler, and it reloads the trusted runtime
// fact for every candidate instead of accepting a service address or target.
type AcornFoxLogCollectionScheduler struct {
	Store    acornFoxLogCollectionStore
	Interval time.Duration
	Clock    func() time.Time
}

func (s *AcornFoxLogCollectionScheduler) ScheduleOnce(ctx context.Context, limit int) (int, error) {
	if s == nil || s.Store == nil {
		return 0, errors.New("AcornFox log collection scheduler requires a store")
	}
	if limit < 1 || limit > acornFoxLogCollectorMaximumPerTick {
		return 0, domain.ValidationError("AcornFox log collection scheduler limit must be between 1 and 10")
	}
	now := s.now()
	candidates, err := s.Store.ListAcornFoxLogCollectionCandidates(ctx, application.AcornFoxLogsCollectionSince(now), limit)
	if err != nil {
		return 0, err
	}
	queued := 0
	bucket := now.Truncate(application.AcornFoxLogsCollectionInterval).Format(time.RFC3339)
	seenEnvironments := make(map[domain.ID]struct{}, len(candidates))
	for _, candidate := range candidates {
		if _, duplicate := seenEnvironments[candidate.EnvironmentID]; duplicate {
			continue
		}
		seenEnvironments[candidate.EnvironmentID] = struct{}{}
		runtime, err := s.Store.GetAcornFoxRuntimeRequest(ctx, candidate.ApplicationID, candidate.DeploymentID)
		if err != nil {
			return queued, err
		}
		key := fmt.Sprintf("acornfox:logs:%s:%s:%s", candidate.DeploymentID, runtime.Fact.ServiceName, bucket)
		request, err := contracts.NewAcornFoxLogsRequest(contracts.AcornFoxRuntimeReference{Fact: runtime.Fact}, application.AcornFoxLogsCollectionSince(now), contracts.AcornFoxLogsMaxTail, key)
		if err != nil {
			return queued, err
		}
		plan, err := application.BuildAcornFoxLogsTaskPlan(request, now)
		if err != nil {
			return queued, err
		}
		if plan.Operation.ApplicationID != candidate.ApplicationID || plan.Operation.EnvironmentID != candidate.EnvironmentID || request.DeploymentID != candidate.DeploymentID {
			return queued, errors.New("AcornFox log task plan identity is invalid")
		}
		if _, err := s.Store.EnqueueControllerTask(ctx, postgres.EnqueueControllerTaskRequest{Operation: plan.Operation, ExistingDeploymentID: candidate.DeploymentID, TaskID: plan.TaskID, Payload: plan.Payload, MaxAttempts: application.AcornFoxLogsTaskAttempts}); err != nil {
			return queued, err
		}
		queued++
	}
	return queued, nil
}

func (s *AcornFoxLogCollectionScheduler) now() time.Time {
	if s != nil && s.Clock != nil {
		return s.Clock().UTC()
	}
	return time.Now().UTC()
}
