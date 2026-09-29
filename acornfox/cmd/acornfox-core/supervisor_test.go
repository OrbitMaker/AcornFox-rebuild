package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(4 * superviseInterval)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSupervisorFollowsExecutorHealth(t *testing.T) {
	var healthy, ready atomic.Bool
	var starts, stops atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	s := supervise(ctx, "test", &ready,
		func(context.Context) error {
			if healthy.Load() {
				return nil
			}
			return errors.New("down")
		},
		func(context.Context) (*session, error) {
			starts.Add(1)
			return &session{stop: func() bool { stops.Add(1); return true }}, nil
		})

	time.Sleep(50 * time.Millisecond)
	if ready.Load() || starts.Load() != 0 {
		t.Fatal("worker started while the executor was unhealthy")
	}
	healthy.Store(true)
	waitFor(t, "start", func() bool { return ready.Load() && starts.Load() == 1 })
	healthy.Store(false)
	waitFor(t, "stop", func() bool { return !ready.Load() && stops.Load() == 1 })
	healthy.Store(true)
	waitFor(t, "restart", func() bool { return ready.Load() && starts.Load() == 2 })

	cancel()
	if !s.join(time.Second) {
		t.Fatal("supervisor did not join after cancel")
	}
	if stops.Load() != 2 || ready.Load() {
		t.Fatalf("shutdown did not stop the active worker: stops=%d ready=%v", stops.Load(), ready.Load())
	}
}

func TestSupervisorReportsWorkerThatCannotJoin(t *testing.T) {
	var ready atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	s := supervise(ctx, "stuck", &ready,
		func(context.Context) error { return nil },
		func(context.Context) (*session, error) { return &session{stop: func() bool { return false }}, nil })
	waitFor(t, "start", ready.Load)
	cancel()
	if s.join(time.Second) {
		t.Fatal("a worker that failed to join was reported as joined")
	}
}

func TestSupervisorRetriesFailedStart(t *testing.T) {
	var ready atomic.Bool
	var attempts atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	supervise(ctx, "flaky", &ready,
		func(context.Context) error { return nil },
		func(context.Context) (*session, error) {
			if attempts.Add(1) == 1 {
				return nil, errors.New("socket not ready")
			}
			return &session{stop: func() bool { return true }}, nil
		})
	waitFor(t, "second attempt", func() bool { return ready.Load() && attempts.Load() == 2 })
}
