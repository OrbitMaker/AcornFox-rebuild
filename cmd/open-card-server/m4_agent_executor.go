package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// m4AgentRuntimeExecutor creates durable task_leases owned by the existing
// dispatcher. It never calls Docker from the control plane: a lost Agent
// connection leaves a claimable task whose result/replay remains the source of
// truth. This first executor supports the typed single-runtime restart path;
// group redeploy/rollback are wired only once their aggregate Agent contract is
// available.
type m4AgentRuntimeExecutor struct {
	store   *postgres.Store
	clock   func() time.Time
	poll    time.Duration
	timeout time.Duration
}

var _ controllers.M4RuntimeExecutor = (*m4AgentRuntimeExecutor)(nil)

func (e *m4AgentRuntimeExecutor) RestartService(ctx context.Context, action controllers.M4RuntimeAction) (controllers.M4RuntimeResult, error) {
	if strings.TrimSpace(action.ServiceName) == "" {
		return controllers.M4RuntimeResult{}, domain.ValidationError("service restart requires a service name")
	}
	return e.runRestart(ctx, action, action.ServiceName)
}

func (e *m4AgentRuntimeExecutor) RestartApplication(ctx context.Context, action controllers.M4RuntimeAction) (controllers.M4RuntimeResult, error) {
	if e == nil || e.store == nil {
		return controllers.M4RuntimeResult{}, errors.New("M4 Agent runtime store is unavailable")
	}
	spec, _, err := e.store.GetM2ReleaseRuntimeSpec(ctx, action.Current.Release.ID)
	if err != nil {
		return controllers.M4RuntimeResult{}, err
	}
	if len(spec.Services) == 0 {
		return controllers.M4RuntimeResult{}, domain.ValidationError("application restart has no persisted services")
	}
	operation := e.operation(action)
	request := contracts.RestartGroupRequest{DeploymentID: action.Current.Deployment.ID, ServiceGroupID: spec.ServiceGroupID, ReleaseID: spec.ReleaseID, Operation: operation}
	if err := request.Validate(); err != nil {
		return controllers.M4RuntimeResult{}, err
	}
	parameters, err := m4GroupParameters("service_group.restart", request)
	if err != nil {
		return controllers.M4RuntimeResult{}, err
	}
	return e.enqueueAndWait(ctx, action, "restart-group", v1.TaskRestart, parameters, action.Current.Deployment.ID)
}

func (e *m4AgentRuntimeExecutor) Redeploy(ctx context.Context, action controllers.M4RuntimeAction) (controllers.M4RuntimeResult, error) {
	if e == nil || e.store == nil {
		return controllers.M4RuntimeResult{}, errors.New("M4 Agent runtime store is unavailable")
	}
	target, err := e.prepareTargetDeployment(ctx, action, action.Current.Release.ID, "redeploy")
	if err != nil {
		return controllers.M4RuntimeResult{}, err
	}
	spec, _, err := e.store.GetM2ReleaseRuntimeSpec(ctx, action.Current.Release.ID)
	if err != nil {
		return controllers.M4RuntimeResult{}, err
	}
	spec.EnvironmentID = action.Current.Deployment.EnvironmentID
	// A replacement being runtime-ready is not an external serving decision.
	// Retain the current group until the control-plane RouteProvider confirms
	// the complete route set is serving and its observation window passes.
	spec.Rollout = contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutRolling, PreviousDeploymentID: action.Current.Deployment.ID, PreserveOldUntilHealthy: true, DeferOldTeardown: true}
	request := contracts.DeployGroupRequest{DeploymentID: target.ID, Spec: spec, Operation: e.operation(action), ForceRecreate: true}
	if err := request.Spec.Validate(); err != nil {
		return controllers.M4RuntimeResult{}, err
	}
	parameters, err := m4GroupParameters("service_group.redeploy", request)
	if err != nil {
		return controllers.M4RuntimeResult{}, err
	}
	result, err := e.enqueueAndWait(ctx, action, "redeploy", v1.TaskDeploy, parameters, target.ID)
	result.Deferred = err == nil
	return result, err
}

func (e *m4AgentRuntimeExecutor) Rollback(ctx context.Context, action controllers.M4RuntimeAction) (controllers.M4RuntimeResult, error) {
	if e == nil || e.store == nil || action.PreviousSuccessful == nil {
		return controllers.M4RuntimeResult{}, domain.NewError(domain.ErrUnsupportedCapability, "M4 rollback requires a previous immutable release")
	}
	target, err := e.prepareTargetDeployment(ctx, action, action.PreviousSuccessful.Release.ID, "rollback")
	if err != nil {
		return controllers.M4RuntimeResult{}, err
	}
	spec, _, err := e.store.GetM2ReleaseRuntimeSpec(ctx, action.PreviousSuccessful.Release.ID)
	if err != nil {
		return controllers.M4RuntimeResult{}, err
	}
	spec.EnvironmentID = action.Current.Deployment.EnvironmentID
	// Rollback follows the same two-phase route handoff. The previous release
	// is a candidate until the control plane, rather than the runtime driver,
	// confirms it is the serving route target.
	spec.Rollout = contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutRolling, PreviousDeploymentID: action.Current.Deployment.ID, PreserveOldUntilHealthy: true, DeferOldTeardown: true}
	request := contracts.RollbackGroupRequest{DeploymentID: action.Current.Deployment.ID, TargetDeploymentID: target.ID, Target: spec, Operation: e.operation(action)}
	parameters, err := m4GroupParameters("service_group.rollback", request)
	if err != nil {
		return controllers.M4RuntimeResult{}, err
	}
	result, err := e.enqueueAndWait(ctx, action, "rollback", v1.TaskRollback, parameters, target.ID)
	result.Deferred = err == nil
	return result, err
}

func (e *m4AgentRuntimeExecutor) runRestart(ctx context.Context, action controllers.M4RuntimeAction, service string) (controllers.M4RuntimeResult, error) {
	if e == nil || e.store == nil {
		return controllers.M4RuntimeResult{}, errors.New("M4 Agent runtime store is unavailable")
	}
	operation := e.operation(action)
	parameters, err := e.restartParameters(ctx, action, service, operation)
	if err != nil {
		return controllers.M4RuntimeResult{}, err
	}
	return e.enqueueAndWait(ctx, action, "restart:"+service, v1.TaskRestart, parameters, action.Current.Deployment.ID)
}

func (e *m4AgentRuntimeExecutor) restartParameters(ctx context.Context, action controllers.M4RuntimeAction, service string, operation contracts.OperationContext) ([]byte, error) {
	if spec, _, err := e.store.GetM2ReleaseRuntimeSpec(ctx, action.Current.Release.ID); err == nil {
		request := contracts.RestartGroupServiceRequest{DeploymentID: action.Current.Deployment.ID, ServiceGroupID: spec.ServiceGroupID, ReleaseID: spec.ReleaseID, ServiceName: service, Operation: operation}
		if err := request.Validate(); err != nil {
			return nil, err
		}
		return m4GroupParameters("service_group.restart_service", request)
	}
	return json.Marshal(contracts.RestartRequest{DeploymentID: action.Current.Deployment.ID, ServiceName: service, Operation: operation})
}

func (e *m4AgentRuntimeExecutor) operation(action controllers.M4RuntimeAction) contracts.OperationContext {
	return contracts.OperationContext{IdempotencyKey: action.Operation.IdempotencyKey, Deadline: e.now().Add(e.duration()), Actor: "m4-operations-controller"}
}

func m4GroupParameters(kind string, request any) ([]byte, error) {
	inner, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		PayloadType string          `json:"m4_payload_type"`
		Request     json.RawMessage `json:"request"`
	}{PayloadType: kind, Request: inner})
}

// prepareTargetDeployment allocates a deterministic candidate deployment and
// moves the already-acquired M4 Operation's task association to it atomically.
// The previous serving deployment remains a separate fact until the Agent has
// independently reported a healthy replacement.
func (e *m4AgentRuntimeExecutor) prepareTargetDeployment(ctx context.Context, action controllers.M4RuntimeAction, releaseID domain.ID, actionName string) (domain.Deployment, error) {
	if releaseID.Empty() {
		return domain.Deployment{}, domain.ValidationError("M4 target release is required")
	}
	now := e.now()
	target := domain.Deployment{ID: m4AdapterID("deployment", action.Operation.ID.String()+":"+actionName+":"+releaseID.String()), ApplicationID: action.Current.Deployment.ApplicationID, EnvironmentID: action.Current.Deployment.EnvironmentID, ReleaseID: releaseID, Status: domain.DeploymentPending, CreatedAt: now, UpdatedAt: now}
	if err := target.Validate(); err != nil {
		return domain.Deployment{}, err
	}
	tx, err := e.store.DB().BeginTx(ctx, nil)
	if err != nil {
		return domain.Deployment{}, err
	}
	rollback := func(cause error) (domain.Deployment, error) { _ = tx.Rollback(); return domain.Deployment{}, cause }
	var operationState, operationDeployment string
	if err := tx.QueryRowContext(ctx, `SELECT state,COALESCE(deployment_id,'') FROM operations WHERE id=$1 FOR UPDATE`, action.Operation.ID.String()).Scan(&operationState, &operationDeployment); err != nil {
		return rollback(err)
	}
	if operationState != string(domain.OperationRunning) || (operationDeployment != action.Current.Deployment.ID.String() && operationDeployment != target.ID.String()) {
		return rollback(domain.NewError(domain.ErrConflict, "M4 operation is no longer bound to its current deployment"))
	}
	var existingRelease, existingEnvironment, existingState string
	err = tx.QueryRowContext(ctx, `SELECT release_id,environment_id,state FROM deployments WHERE id=$1 FOR UPDATE`, target.ID.String()).Scan(&existingRelease, &existingEnvironment, &existingState)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO deployments(id,environment_id,release_id,state,version,created_at,updated_at) VALUES($1,$2,$3,'pending',1,$4,$4)`, target.ID.String(), target.EnvironmentID.String(), target.ReleaseID.String(), now); err != nil {
			return rollback(err)
		}
	} else if err != nil {
		return rollback(err)
	} else if existingRelease != target.ReleaseID.String() || existingEnvironment != target.EnvironmentID.String() || existingState != string(domain.DeploymentPending) {
		return rollback(domain.NewError(domain.ErrConflict, "M4 target deployment identity is already bound to another runtime state"))
	}
	if operationDeployment != target.ID.String() {
		if _, err := tx.ExecContext(ctx, `UPDATE operations SET deployment_id=$1,version=version+1,updated_at=$2 WHERE id=$3 AND state='running'`, target.ID.String(), now, action.Operation.ID.String()); err != nil {
			return rollback(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return domain.Deployment{}, err
	}
	return target, nil
}

func (e *m4AgentRuntimeExecutor) enqueueAndWait(ctx context.Context, action controllers.M4RuntimeAction, actionName string, kind v1.TaskKind, parameters []byte, deploymentID domain.ID) (controllers.M4RuntimeResult, error) {
	if len(parameters) == 0 || deploymentID.Empty() {
		return controllers.M4RuntimeResult{}, domain.ValidationError("M4 Agent task payload and deployment are required")
	}
	taskID := m4AdapterID("task", action.Operation.ID.String()+":"+actionName)
	payload, err := json.Marshal(controllers.AgentTaskSpec{Kind: kind, Parameters: parameters})
	if err != nil {
		return controllers.M4RuntimeResult{}, err
	}
	now := e.now()
	_, err = e.store.DB().ExecContext(ctx, `INSERT INTO task_leases(task_id,operation_id,max_attempts,state,payload,created_at,updated_at) VALUES($1,$2,3,'ready',$3::jsonb,$4,$4) ON CONFLICT(task_id) DO NOTHING`, taskID.String(), action.Operation.ID.String(), payload, now)
	if err != nil {
		return controllers.M4RuntimeResult{}, err
	}
	return e.wait(ctx, taskID, deploymentID)
}

func (e *m4AgentRuntimeExecutor) wait(ctx context.Context, taskID, deploymentID domain.ID) (controllers.M4RuntimeResult, error) {
	deadline := e.now().Add(e.duration())
	for {
		task, err := e.store.GetControllerTask(ctx, taskID)
		if err != nil {
			return controllers.M4RuntimeResult{}, err
		}
		if task.Task.State == postgres.TaskCompleted {
			deployment, deploymentErr := e.store.GetDeployment(ctx, deploymentID)
			result := controllers.M4RuntimeResult{Deployment: deployment, Evidence: []domain.EvidenceRef{{ID: domain.ID("evidence_" + taskID.String()), Kind: "agent.task"}}}
			if deploymentErr != nil {
				return result, deploymentErr
			}
			return result, nil
		}
		if task.Task.State == postgres.TaskFailed || task.Task.State == postgres.TaskCancelled || task.Operation.Status.IsTerminal() {
			return controllers.M4RuntimeResult{}, errors.New(strings.TrimSpace(task.Operation.FailureReason))
		}
		if e.now().After(deadline) {
			return controllers.M4RuntimeResult{}, domain.NewError(domain.ErrTimeout, "M4 Agent operation did not reach a terminal result before timeout")
		}
		select {
		case <-ctx.Done():
			return controllers.M4RuntimeResult{}, ctx.Err()
		case <-time.After(e.pollInterval()):
		}
	}
}

func (e *m4AgentRuntimeExecutor) now() time.Time {
	if e.clock == nil {
		return time.Now().UTC()
	}
	return e.clock().UTC()
}
func (e *m4AgentRuntimeExecutor) duration() time.Duration {
	if e.timeout <= 0 {
		return 2 * time.Minute
	}
	return e.timeout
}
func (e *m4AgentRuntimeExecutor) pollInterval() time.Duration {
	if e.poll <= 0 {
		return 100 * time.Millisecond
	}
	return e.poll
}

func (e *m4AgentRuntimeExecutor) String() string {
	return fmt.Sprintf("m4-agent-runtime:%t", e != nil && e.store != nil)
}
