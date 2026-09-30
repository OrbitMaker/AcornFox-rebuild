package reconcile

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func awaitAppLockSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for per-app lock signal")
	}
}

func TestWithAppWaitIsCancellable(t *testing.T) {
	h := newHarness(t)
	defer h.rec.shutdown()
	entered := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- h.rec.WithApp(context.Background(), "shop", func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	awaitAppLockSignal(t, entered)
	ctx, cancel := context.WithCancel(context.Background())
	waiterDone := make(chan error, 1)
	called := make(chan struct{}, 1)
	go func() {
		waiterDone <- h.rec.WithApp(ctx, "shop", func() error {
			called <- struct{}{}
			return nil
		})
	}()
	cancel()
	select {
	case err := <-waiterDone:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("want canceled, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("canceled waiter did not return")
	}
	select {
	case <-called:
		t.Error("canceled operation was executed")
	default:
	}
	close(release)
	if err := <-holderDone; err != nil {
		t.Fatal(err)
	}
	if err := h.rec.WithApp(context.Background(), "shop", func() error { return nil }); err != nil {
		t.Fatalf("cancellation leaked the token: %v", err)
	}
}

func TestWithAppDifferentAppsAreIndependent(t *testing.T) {
	h := newHarness(t)
	defer h.rec.shutdown()
	err := h.rec.WithApp(context.Background(), "shop", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return h.rec.WithApp(ctx, "other", func() error { return nil })
	})
	if err != nil {
		t.Fatalf("a different app was blocked: %v", err)
	}
}

func TestWithAppReleasesTokenOnError(t *testing.T) {
	h := newHarness(t)
	defer h.rec.shutdown()
	failure := errors.New("operation failed")
	if err := h.rec.WithApp(context.Background(), "shop", func() error { return failure }); !errors.Is(err, failure) {
		t.Fatalf("callback error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.rec.WithApp(ctx, "shop", func() error { return nil }); err != nil {
		t.Fatalf("callback error leaked the token: %v", err)
	}
}

func TestWithAppAlreadyCancelledDoesNotCreateWorker(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := h.rec.WithApp(ctx, "shop", func() error {
		t.Error("callback ran with a canceled context")
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("already cancelled: %v", err)
	}
	h.rec.mu.Lock()
	defer h.rec.mu.Unlock()
	if len(h.rec.workers) != 0 {
		t.Fatal("canceled request created a worker")
	}
}

func TestWithAppBlocksWorkerRoundAndAllowsKick(t *testing.T) {
	h := newHarness(t)
	defer h.rec.shutdown()
	h.store.putApp(baseApp("shop"))
	roundStarted := make(chan struct{})
	var once sync.Once
	h.runner.onList = func() { once.Do(func() { close(roundStarted) }) }
	err := h.rec.WithApp(context.Background(), "shop", func() error {
		h.rec.Kick("shop")
		select {
		case <-roundStarted:
			t.Error("round entered while the explicit operation held the token")
		case <-time.After(25 * time.Millisecond):
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	awaitAppLockSignal(t, roundStarted)
	// Wait for the round to finish before the harness's temporary files go away.
	if err := h.rec.WithApp(context.Background(), "shop", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerRoundBlocksWithApp(t *testing.T) {
	h := newHarness(t)
	defer h.rec.shutdown()
	h.store.putApp(baseApp("shop"))
	roundStarted := make(chan struct{})
	releaseRound := make(chan struct{})
	var once sync.Once
	h.runner.onList = func() {
		once.Do(func() {
			close(roundStarted)
			<-releaseRound
		})
	}
	h.rec.Kick("shop")
	awaitAppLockSignal(t, roundStarted)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	err := h.rec.WithApp(ctx, "shop", func() error {
		t.Error("operation ran while the round held the token")
		return nil
	})
	close(releaseRound)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting for round: %v", err)
	}
	if err := h.rec.WithApp(context.Background(), "shop", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}
