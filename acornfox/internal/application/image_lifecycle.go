package application

import (
	"context"
	"errors"
	"fmt"
	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/contracts"
)

func (w *ImageExecutionWorker) executeLifecycleTask(ctx context.Context, task appcontracts.Task) error {
	begin := appcontracts.BeginImageExecutionInput{TaskID: task.ID, OperationID: task.OperationID, Owner: w.cfg.WorkerID, CoreGeneration: task.CoreGeneration, LeaseGeneration: task.LeaseGeneration, Now: w.cfg.Clock().UTC()}
	binding, err := w.cfg.LifecycleStore.BeginImageLifecycle(ctx, begin)
	if err != nil {
		return err
	} // No effect began; never substitute the old deploy lease.
	authority := appcontracts.ImageLifecycleAuthorityInput{BeginImageExecutionInput: begin, DeploymentID: binding.DeploymentID, ReleaseID: binding.ReleaseID, PlanDigest: binding.PlanDigest, ContainerID: binding.ContainerID, Action: binding.Action}
	execCtx, finish := w.startTaskLease(ctx, task)
	result, executeErr := w.cfg.LifecycleClient.ExecuteLifecycle(execCtx, binding, authority)
	if err := finish(); err != nil {
		return err
	}
	if executeErr != nil {
		if errors.Is(executeErr, appcontracts.ErrLeaseLost) {
			return executeErr
		}
		outcome := appcontracts.ImageLifecycleOutcomeInput{ImageLifecycleAuthorityInput: authority, Reason: executeErr.Error()}
		// A running observation cannot prove restart. Only the provider's same-key
		// durable action recovery may return success on a later claimed task.
		if errors.Is(executeErr, appcontracts.ErrOutcomeUnknown) || contracts.IsProviderOutcomeUnknown(executeErr) || errors.Is(executeErr, context.DeadlineExceeded) || errors.Is(executeErr, context.Canceled) {
			return w.cfg.LifecycleStore.RecordImageLifecycleUnknown(ctx, outcome)
		}
		return w.cfg.LifecycleStore.FailImageLifecycle(ctx, outcome)
	}
	if err := w.cfg.LifecycleStore.CommitImageLifecycleResult(ctx, appcontracts.CommitImageLifecycleInput{ImageLifecycleAuthorityInput: authority, Result: result}); err != nil {
		return fmt.Errorf("commit lifecycle result: %w", err)
	}
	return nil
}
