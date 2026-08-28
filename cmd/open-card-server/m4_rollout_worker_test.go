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
