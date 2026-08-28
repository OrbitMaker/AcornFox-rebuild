package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type m4OldRetirer struct {
	store *postgres.Store
	clock func() time.Time
}

func (r *m4OldRetirer) RetireOld(ctx context.Context, rollout postgres.M4RolloutCoordinator) (bool, []domain.EvidenceRef, error) {
	if r == nil || r.store == nil {
		return false, nil, errors.New("M4 old retirer is unavailable")
	}
	if rollout.SourceDeploymentID.Empty() {
		return true, nil, nil
	}
	old, err := r.store.GetDeployment(ctx, rollout.SourceDeploymentID)
	if errors.Is(err, postgres.ErrNotFound) {
		return true, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	if old.Status == domain.DeploymentStopped {
		return true, []domain.EvidenceRef{{ID: m4AdapterID("evidence", rollout.OperationID.String()+":old-absent"), Kind: "runtime.group.absent", Digest: rollout.RouteSetDigest, Locator: "deployment://" + old.ID.String()}}, nil
	}
	key := "m4-retire:" + rollout.OperationID.String() + ":" + old.ID.String()
	operation, err := domain.NewOperation(rollout.ApplicationID, rollout.EnvironmentID, domain.OperationDestroy, "destroy/"+old.ID.String(), key, r.now())
	if err != nil {
		return false, nil, err
	}
	operation.ID = m4AdapterID("operation", key)
	taskID := m4AdapterID("task", key)
	destroy := contracts.DestroyRequest{DeploymentID: old.ID, PreserveVolumes: true, Operation: contracts.OperationContext{IdempotencyKey: key, Deadline: r.now().Add(2 * time.Minute), Actor: "m4-rollout-retirer"}}
	parameters, err := json.Marshal(destroy)
	if err != nil {
		return false, nil, err
	}
	payload, err := json.Marshal(controllers.AgentTaskSpec{Kind: v1.TaskDestroyGroup, Parameters: parameters})
	if err != nil {
		return false, nil, err
	}
	task, _, err := r.store.CreateM4RetirementTask(ctx, postgres.CreateM4RetirementTaskRequest{RolloutOperationID: rollout.OperationID, OldDeploymentID: old.ID, Operation: operation, TaskID: taskID, Payload: payload, MaxAttempts: 3, Now: r.now()})
	if err != nil {
		return false, nil, err
	}
	switch task.Task.State {
	case postgres.TaskCompleted:
		return true, []domain.EvidenceRef{{ID: m4AdapterID("evidence", taskID.String()), Kind: "agent.destroy_group", Digest: rollout.RouteSetDigest, Locator: "task://" + taskID.String()}}, nil
	case postgres.TaskFailed, postgres.TaskCancelled:
		return false, nil, errors.New("old deployment retirement task is terminal without success")
	default:
		return false, nil, nil
	}
}
func (r *m4OldRetirer) now() time.Time {
	if r.clock == nil {
		return time.Now().UTC()
	}
	return r.clock().UTC()
}
