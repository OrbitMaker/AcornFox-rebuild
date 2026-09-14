package install

import (
	"context"
	"errors"
	"time"
)

// Wait only before the upgrade obtains its repository lock and can mutate state.
// Observers keep their nonblocking behavior; no transaction is retried here.
func acquireAcornFoxUpgradeLock(ctx context.Context, store *TaskAcornFoxRepoStore) (AcornFoxRepoStoreLock, error) {
	wait, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if wait.Err() != nil {
			return nil, ErrAcornFoxRepoLocked
		}
		lock, err := store.Acquire(wait)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, ErrAcornFoxRepoLocked) {
			return nil, err
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-wait.Done():
			timer.Stop()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, ErrAcornFoxRepoLocked
		case <-timer.C:
		}
	}
}
