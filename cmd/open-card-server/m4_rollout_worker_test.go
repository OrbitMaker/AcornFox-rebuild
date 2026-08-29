package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type m4RolloutRunnerFake struct {
	mu       sync.Mutex
	calls    int
	fail     int
	notified chan struct{}
}

type blockingM4LifecycleWorker struct {
	entered, cancelled, allowReturn, returned chan struct{}
}

func (w *blockingM4LifecycleWorker) Run(ctx context.Context) {
	close(w.entered)
	<-ctx.Done()
	close(w.cancelled)
	<-w.allowReturn
	close(w.returned)
}

func (f *m4RolloutRunnerFake) ReconcileOnce(context.Context, int) (int, error) {
	f.mu.Lock()
	f.calls++
	call := f.calls
	err := error(nil)
	if call <= f.fail {
		err = errors.New("transient")
	}
	f.mu.Unlock()
	select {
	case f.notified <- struct{}{}:
	default:
	}
	return 0, err
}
func (f *m4RolloutRunnerFake) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

func TestM4RolloutWorkerWakeCoalescesAndSurvivesTransientErrors(t *testing.T) {
	fake := &m4RolloutRunnerFake{fail: 1, notified: make(chan struct{}, 20)}
	worker := newM4RolloutWorker(fake, 200*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { worker.Run(ctx); close(done) }()
	select {
	case <-fake.notified:
	case <-time.After(time.Second):
		t.Fatal("initial recovery did not run")
	}
	for i := 0; i < 10; i++ {
		worker.Wake()
	}
	select {
	case <-fake.notified:
	case <-time.After(time.Second):
		t.Fatal("wake did not run")
	}
	if got := fake.count(); got > 3 {
		t.Fatalf("wakeups were not coalesced: %d", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop on context cancellation")
	}
}

func TestValidateM4RolloutCompositionFailsClosedOnlyWhenEnabled(t *testing.T) {
	if err := validateM4RolloutComposition(false, false, false); err != nil {
		t.Fatal(err)
	}
	if err := validateM4RolloutComposition(true, false, true); err == nil {
		t.Fatal("missing route provider accepted")
	}
	if err := validateM4RolloutComposition(true, true, false); err == nil {
		t.Fatal("missing database accepted")
	}
	if err := validateM4RolloutComposition(true, true, true); err != nil {
		t.Fatal(err)
	}
}

func TestM4RolloutIntervalIsBoundedAndExplicit(t *testing.T) {
	if value, err := m4RolloutInterval(""); err != nil || value != time.Second {
		t.Fatalf("default interval=%s err=%v", value, err)
	}
	if value, err := m4RolloutInterval("3s"); err != nil || value != 3*time.Second {
		t.Fatalf("configured interval=%s err=%v", value, err)
	}
	for _, value := range []string{"bad", "999ms", "31s"} {
		if _, err := m4RolloutInterval(value); err == nil {
			t.Fatalf("unsafe rollout interval %q accepted", value)
		}
	}
}

func TestM4RolloutShutdownRetainsRouteFenceUntilWorkerReturns(t *testing.T) {
	fence := newRouteSetMutationFence()
	adapter := &m4StagedRouteAdapter{fence: fence}
	if err := adapter.acquireRouteSet(context.Background(), "m4_shutdown"); err != nil {
		t.Fatal(err)
	}
	worker := &blockingM4LifecycleWorker{entered: make(chan struct{}), cancelled: make(chan struct{}), allowReturn: make(chan struct{}), returned: make(chan struct{})}
	lifecycleContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	released := make(chan struct{})
	if !startM4RolloutWorker(lifecycleContext, newRouteMutationWorkerGroup(), worker, func() {
		adapter.releaseAllRouteSets()
		close(released)
	}) {
		t.Fatal("M4 worker was not registered")
	}
	select {
	case <-worker.entered:
	case <-time.After(time.Second):
		t.Fatal("M4 worker did not start")
	}
	cancel()
	select {
	case <-worker.cancelled:
	case <-time.After(time.Second):
		t.Fatal("M4 worker did not observe lifecycle cancellation")
	}
	blocked, blockedCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer blockedCancel()
	if _, err := fence.Acquire(blocked); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("route fence was released before worker return: %v", err)
	}
	select {
	case <-released:
		t.Fatal("route fence release ran before worker return")
	default:
	}
	close(worker.allowReturn)
	select {
	case <-worker.returned:
	case <-time.After(time.Second):
		t.Fatal("M4 worker did not return")
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("route fence was not released after worker return")
	}
	release, err := fence.Acquire(context.Background())
	if err != nil {
		t.Fatalf("route fence did not become available after worker return: %v", err)
	}
	release()
}
