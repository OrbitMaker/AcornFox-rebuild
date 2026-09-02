package main

import (
	"context"
	"errors"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type acornFoxProbeTaskStore interface {
	EnqueueControllerTask(context.Context, postgres.EnqueueControllerTaskRequest) (application.Event, error)
}

// AcornFoxProbeTaskCreator records one caller-requested probe. It owns no
// polling loop and does not infer a request from deployment state, so a probe
// can never become an automatic health scheduler by accident.
type AcornFoxProbeTaskCreator struct {
	Store acornFoxProbeTaskStore
	Clock func() time.Time
}

func (c *AcornFoxProbeTaskCreator) CreateOnce(ctx context.Context, request contracts.AcornFoxProbeRequest, current contracts.AcornFoxRuntimeObservation) (application.Event, error) {
	if c == nil || c.Store == nil {
		return application.Event{}, errors.New("AcornFox probe task store is required")
	}
	now := time.Now().UTC()
	if c.Clock != nil {
		now = c.Clock().UTC()
	}
	plan, err := application.BuildAcornFoxProbeTaskPlan(request, current, now)
	if err != nil {
		return application.Event{}, err
	}
	return c.Store.EnqueueControllerTask(ctx, postgres.EnqueueControllerTaskRequest{
		Operation:            plan.Operation,
		ExistingDeploymentID: current.DeploymentID,
		TaskID:               plan.TaskID,
		Payload:              plan.Payload,
		MaxAttempts:          3,
	})
}
