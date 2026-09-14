package install

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestAcornFoxUpgradeWaitsForExistingReaderLock(t *testing.T) {
	root := newAcornFoxRepoTaskRoot(t)
	first, held := acquireAcornFoxRepoStore(t, root)
	defer first.Close()
	defer held.Release()
	second, e := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	type result struct {
		lock AcornFoxRepoStoreLock
		err  error
	}
	done := make(chan result, 1)
	go func() { lock, err := acquireAcornFoxUpgradeLock(ctx, second); done <- result{lock, err} }()
	select {
	case r := <-done:
		t.Fatalf("did not wait for reader: %v", r.err)
	case <-time.After(80 * time.Millisecond):
	}
	if e := held.Release(); e != nil {
		t.Fatal(e)
	}
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		r.lock.Release()
	case <-ctx.Done():
		t.Fatal("lock handoff timed out")
	}
}
func TestAcornFoxUpgradeLockWaitCancels(t *testing.T) {
	root := newAcornFoxRepoTaskRoot(t)
	first, held := acquireAcornFoxRepoStore(t, root)
	defer first.Close()
	defer held.Release()
	second, e := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := acquireAcornFoxUpgradeLock(ctx, second); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation ignored")
	}
}
