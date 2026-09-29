package application

import (
	"context"
	"fmt"
	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"sync"
	"time"
)

func startTaskExecutionLease(ctx context.Context, task appcontracts.Task, repo appcontracts.TaskRepository, owner string, duration time.Duration, clock func() time.Time) (context.Context, func() error) {
	// 2. Create child context for this task execution
	execCtx, cancelExec := context.WithCancel(ctx)

	// Renew lease periodically in background
	renewInterval := duration / 3
	if renewInterval < time.Second {
		renewInterval = time.Second
	}
	stopRenew := make(chan struct{})
	renewerDone := make(chan struct{})
	var renewErrMu sync.Mutex
	var renewErr error

	go func() {
		defer close(renewerDone)
		renewTicker := time.NewTicker(renewInterval)
		defer renewTicker.Stop()
		for {
			select {
			case <-stopRenew:
				return
			case <-execCtx.Done():
				return
			case <-renewTicker.C:
				renewNow := clock().UTC()
				err := repo.RenewTask(execCtx, appcontracts.TaskMutationRequest{
					TaskID:          task.ID,
					Owner:           owner,
					CoreGeneration:  task.CoreGeneration,
					LeaseGeneration: task.LeaseGeneration,
					Now:             renewNow,
					LeasePolicy: appcontracts.LeasePolicy{
						Duration: duration,
					},
				})
				if err != nil {
					renewErrMu.Lock()
					renewErr = fmt.Errorf("lease renewal failed: %w", err)
					renewErrMu.Unlock()
					cancelExec() // cancel child context immediately on lease failure
					return
				}
			}
		}
	}()

	return execCtx, func() error {
		close(stopRenew)
		<-renewerDone
		renewErrMu.Lock()
		lostErr := renewErr
		renewErrMu.Unlock()
		interrupted := execCtx.Err() != nil && ctx.Err() != nil
		cancelExec()
		if lostErr != nil {
			return lostErr
		}
		if interrupted {
			return ctx.Err()
		}
		return nil
	}
}
