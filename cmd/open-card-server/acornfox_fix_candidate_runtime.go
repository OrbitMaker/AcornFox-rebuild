package main

import (
	"context"
	"errors"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type acornFoxFixCandidateRuntimeStore interface {
	EnqueueAcornFoxFixCandidateRuntimeTask(context.Context, postgres.AcornFoxFixCandidateRuntimeTaskRequest) (domain.ID, error)
	GetAcornFoxFixCandidateRuntimeEvidence(context.Context, domain.ID, domain.ImageDigest) (application.AcornFoxFixCandidateRuntimeEvidence, bool, error)
}

type acornFoxFixCandidateRuntimeDispatcher struct {
	store acornFoxFixCandidateRuntimeStore
	clock func() time.Time
	poll  time.Duration
}

func (d *acornFoxFixCandidateRuntimeDispatcher) ValidateCandidateRuntime(ctx context.Context, request application.AcornFoxFixCandidateRuntimeRequest) (application.AcornFoxFixCandidateRuntimeEvidence, error) {
	if d == nil || d.store == nil {
		return application.AcornFoxFixCandidateRuntimeEvidence{}, errors.New("candidate runtime dispatcher is unavailable")
	}
	now := time.Now().UTC()
	if d.clock != nil {
		now = d.clock().UTC()
	}
	taskID, err := d.store.EnqueueAcornFoxFixCandidateRuntimeTask(ctx, postgres.AcornFoxFixCandidateRuntimeTaskRequest{CandidateID: request.CandidateID, ApplicationID: request.ApplicationID, Image: request.Image, ContainerPort: request.ContainerPort, IdempotencyKey: request.IdempotencyKey, Actor: request.Actor, Now: now})
	if err != nil {
		return application.AcornFoxFixCandidateRuntimeEvidence{}, err
	}
	poll := d.poll
	if poll <= 0 {
		poll = 100 * time.Millisecond
	}
	for {
		evidence, complete, err := d.store.GetAcornFoxFixCandidateRuntimeEvidence(ctx, taskID, request.Image)
		if err != nil {
			return application.AcornFoxFixCandidateRuntimeEvidence{}, err
		}
		if complete {
			return evidence, nil
		}
		select {
		case <-ctx.Done():
			return application.AcornFoxFixCandidateRuntimeEvidence{}, ctx.Err()
		case <-time.After(poll):
		}
	}
}
