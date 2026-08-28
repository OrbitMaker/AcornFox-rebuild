package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// m4RolloutRuntime reads durable deployment facts; it never fabricates
// readiness from a controller projection.
type m4RolloutRuntime struct {
	store *postgres.Store
	owner string
	clock func() time.Time
}

func (r *m4RolloutRuntime) CandidateReady(ctx context.Context, rollout postgres.M4RolloutCoordinator) (bool, []domain.EvidenceRef, error) {
	if r == nil || r.store == nil {
		return false, nil, errors.New("M4 rollout runtime is unavailable")
	}
	deployment, err := r.store.GetDeployment(ctx, rollout.CandidateDeploymentID)
	if err != nil {
		return false, nil, err
	}
	if !deployment.RuntimeReady() {
		return false, nil, nil
	}
	return true, []domain.EvidenceRef{{ID: m4AdapterID("evidence", rollout.OperationID.String()+":candidate-ready"), Kind: "deployment.runtime_ready", Digest: rollout.RouteSetDigest, Locator: "deployment://" + deployment.ID.String()}}, nil
}
func (r *m4RolloutRuntime) CleanupCandidate(ctx context.Context, rollout postgres.M4RolloutCoordinator, reason string) (bool, []domain.EvidenceRef, error) {
	if r == nil || r.store == nil {
		return false, nil, errors.New("M4 rollout runtime is unavailable")
	}
	if rollout.CandidateDeploymentID.Empty() || rollout.CandidateDeploymentID == rollout.SourceDeploymentID {
		return false, nil, domain.NewError(domain.ErrConflict, "candidate cleanup identity is invalid")
	}
	candidate, err := r.store.GetDeployment(ctx, rollout.CandidateDeploymentID)
	if errors.Is(err, postgres.ErrNotFound) {
		return true, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	if candidate.Status == domain.DeploymentServing {
		return false, nil, domain.NewError(domain.ErrConflict, "candidate cleanup refused serving deployment")
	}
	if candidate.Status == domain.DeploymentStopped {
		return true, []domain.EvidenceRef{{ID: m4AdapterID("evidence", rollout.OperationID.String()+":candidate-clean"), Kind: "runtime.group.absent", Digest: rollout.RouteSetDigest, Locator: "deployment://" + candidate.ID.String()}}, nil
	}
	owner := strings.TrimSpace(r.owner)
	if owner == "" {
		owner = "m4-rollout-worker"
	}
	key := "m4-cleanup:" + rollout.OperationID.String() + ":" + candidate.ID.String()
	taskID := m4AdapterID("task", key)
	destroy := contracts.DestroyRequest{DeploymentID: candidate.ID, PreserveVolumes: true, Operation: contracts.OperationContext{IdempotencyKey: key, Deadline: r.now().Add(2 * time.Minute), Actor: "m4-rollout-cleanup"}}
	parameters, err := json.Marshal(destroy)
	if err != nil {
		return false, nil, err
	}
	payload, err := json.Marshal(controllers.AgentTaskSpec{Kind: v1.TaskDestroyGroup, Parameters: parameters})
	if err != nil {
		return false, nil, err
	}
	task, _, err := r.store.CreateM4CandidateCleanupTask(ctx, postgres.CreateM4CandidateCleanupTaskRequest{RolloutOperationID: rollout.OperationID, CandidateDeployment: candidate.ID, TaskID: taskID, Payload: payload, Owner: owner, Reason: reason, MaxAttempts: 5, Now: r.now()})
	if err != nil {
		return false, nil, err
	}
	switch task.Task.State {
	case postgres.TaskCompleted:
		return true, []domain.EvidenceRef{{ID: m4AdapterID("evidence", taskID.String()), Kind: "agent.destroy_group", Digest: rollout.RouteSetDigest, Locator: "task://" + taskID.String()}}, nil
	case postgres.TaskFailed, postgres.TaskCancelled:
		return false, nil, errors.New("candidate cleanup task exhausted retries without success")
	default:
		return false, nil, nil
	}
}

func (r *m4RolloutRuntime) now() time.Time {
	if r.clock == nil {
		return time.Now().UTC()
	}
	return r.clock().UTC()
}
