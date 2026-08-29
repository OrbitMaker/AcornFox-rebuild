package main

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// m4RolloutWorker is intentionally a wakeable poller: outbox/Agent events
// reduce latency, while periodic claims remain the recovery source after a
// missed wakeup or process restart.
type m4RolloutRunner interface {
	ReconcileOnce(context.Context, int) (int, error)
}
type m4RolloutWorker struct {
	reconciler m4RolloutRunner
	interval   time.Duration
	wake       chan struct{}
	once       sync.Once
}

type m4RolloutLifecycleWorker interface {
	Run(context.Context)
}

// startM4RolloutWorker retains route-set mutation authority until the worker
// has observed lifecycle cancellation and returned from its reconcile loop.
func startM4RolloutWorker(ctx context.Context, workers *routeMutationWorkerGroup, worker m4RolloutLifecycleWorker, afterRun func()) bool {
	if workers == nil || worker == nil {
		return false
	}
	return workers.Go(ctx, func() {
		worker.Run(ctx)
		if afterRun != nil {
			afterRun()
		}
	})
}

func newM4RolloutWorker(reconciler m4RolloutRunner, interval time.Duration) *m4RolloutWorker {
	if interval <= 0 {
		interval = time.Second
	}
	return &m4RolloutWorker{reconciler: reconciler, interval: interval, wake: make(chan struct{}, 1)}
}

func m4RolloutInterval(raw string) (time.Duration, error) {
	if raw == "" {
		return time.Second, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value < time.Second || value > 30*time.Second {
		return 0, fmt.Errorf("M4 rollout interval must be between 1s and 30s")
	}
	return value, nil
}

func validateM4RolloutComposition(enabled bool, routeProviderConfigured bool, databaseConfigured bool) error {
	if !enabled {
		return nil
	}
	if !databaseConfigured {
		return fmt.Errorf("M4 rollout requires PostgreSQL composition")
	}
	if !routeProviderConfigured {
		return fmt.Errorf("M4 rollout requires the M3 RouteProvider composition")
	}
	return nil
}
func (w *m4RolloutWorker) Wake() {
	if w == nil {
		return
	}
	select {
	case w.wake <- struct{}{}:
	default:
	}
}
func (w *m4RolloutWorker) Run(ctx context.Context) {
	if w == nil || w.reconciler == nil {
		return
	}
	run := func() {
		taskCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_, _ = w.reconciler.ReconcileOnce(taskCtx, 10)
	}
	run()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		case <-w.wake:
			run()
		}
	}
}
