package desktopupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func snapshotDirectory(t *testing.T, dir string) map[string]string {
	t.Helper()
	m := make(map[string]string)
	e := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if info.IsDir() {
			m[rel] = "dir"
		} else {
			content, _ := os.ReadFile(p)
			m[rel] = hostSHA(content)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return m
}

func compareSnapshots(t *testing.T, before, after map[string]string) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("directory modified: had %d entries, now %d entries", len(before), len(after))
	}
	for k, v := range before {
		if after[k] != v {
			t.Fatalf("entry %q changed: before %s, after %s", k, v, after[k])
		}
	}
}

func TestHostBootstrapReadOnlyCompleteState(t *testing.T) {
	f := newSlotFixture(t)
	m, a := f.open(t)
	ctx := context.Background()

	// 1. Initial complete canonical state: active is external bootstrap
	bootID, err := m.CurrentSlot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bootID != m.options.Bootstrap.ID() {
		t.Fatalf("expected active bootstrap ID, got %s", bootID)
	}

	before := snapshotDirectory(t, f.Root)

	called := false
	var savedFD *os.File
	err = OpenActiveControllerReadOnly(ctx, HostBootstrapReadOnlyOptions{
		Root:       f.Root,
		InstanceID: f.ID,
		Bootstrap:  m.options.Bootstrap,
	}, func(ctx context.Context, target HostActiveControllerTarget, controllerFD *os.File) error {
		called = true
		if target.Role != HostBootstrapRoleNormal {
			t.Fatalf("expected role normal, got %s", target.Role)
		}
		if target.IsRecovery() {
			t.Fatal("expected not recovery")
		}
		if target.SlotID != bootID {
			t.Fatalf("expected slot %s, got %s", bootID, target.SlotID)
		}
		if !target.ExternalBootstrap {
			t.Fatal("expected external bootstrap true")
		}
		// Controller FD should be readable
		buf := make([]byte, 16)
		n, rerr := controllerFD.Read(buf)
		if rerr != nil || n == 0 {
			t.Fatalf("read controllerFD failed: %v", rerr)
		}
		savedFD = controllerFD
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("callback was not called")
	}

	// Verify FD closed after callback
	buf := make([]byte, 16)
	if _, rerr := savedFD.Read(buf); rerr == nil {
		t.Fatal("expected controllerFD to be closed after callback")
	}

	// Verify tree was completely unchanged
	after := snapshotDirectory(t, f.Root)
	compareSnapshots(t, before, after)

	// 2. Complete canonical state after bundle prepare and activate: active is managed slot
	if err = m.Prepare(ctx, a, bootID); err != nil {
		t.Fatal(err)
	}
	attemptID := strings.Repeat("7", 64)
	if err = m.Activate(ctx, attemptID, bootID, a.SHA256()); err != nil {
		t.Fatal(err)
	}

	beforeManaged := snapshotDirectory(t, f.Root)
	calledManaged := false
	err = OpenActiveControllerReadOnly(ctx, HostBootstrapReadOnlyOptions{
		Root:       f.Root,
		InstanceID: f.ID,
		Bootstrap:  m.options.Bootstrap,
	}, func(ctx context.Context, target HostActiveControllerTarget, controllerFD *os.File) error {
		calledManaged = true
		if target.Role != HostBootstrapRoleNormal {
			t.Fatalf("expected role normal, got %s", target.Role)
		}
		if target.SlotID != a.SHA256() {
			t.Fatalf("expected slot %s, got %s", a.SHA256(), target.SlotID)
		}
		if target.ExternalBootstrap {
			t.Fatal("expected external bootstrap false")
		}
		savedFD = controllerFD
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !calledManaged {
		t.Fatal("callback was not called")
	}
	if _, rerr := savedFD.Read(buf); rerr == nil {
		t.Fatal("expected controllerFD to be closed after callback")
	}
	afterManaged := snapshotDirectory(t, f.Root)
	compareSnapshots(t, beforeManaged, afterManaged)
}

func TestHostBootstrapReadOnlyAbsentState(t *testing.T) {
	f := newSlotFixture(t)
	b, err := PinHostBootstrap(context.Background(), f.Spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })

	ctx := context.Background()

	// 1. Truly empty root without pre-created lock is rejected as incomplete installation
	err = OpenActiveControllerReadOnly(ctx, HostBootstrapReadOnlyOptions{
		Root:       f.Root,
		InstanceID: f.ID,
		Bootstrap:  b,
	}, func(ctx context.Context, target HostActiveControllerTarget, controllerFD *os.File) error {
		t.Fatal("should not callback when lock is missing")
		return nil
	})
	if !errors.Is(err, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict when lock is missing in empty root, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.Root, "lock")); !os.IsNotExist(err) {
		t.Fatal("lock was unexpectedly created")
	}

	// 2. Pre-create installer lock in root
	lockPath := filepath.Join(f.Root, "lock")
	if err := os.WriteFile(lockPath, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}

	before := snapshotDirectory(t, f.Root)

	called := false
	var savedFD *os.File
	err = OpenActiveControllerReadOnly(ctx, HostBootstrapReadOnlyOptions{
		Root:       f.Root,
		InstanceID: f.ID,
		Bootstrap:  b,
	}, func(ctx context.Context, target HostActiveControllerTarget, controllerFD *os.File) error {
		called = true
		if target.Role != HostBootstrapRoleNormal {
			t.Fatalf("expected role normal, got %s", target.Role)
		}
		if target.SlotID != b.ID() {
			t.Fatalf("expected slot %s, got %s", b.ID(), target.SlotID)
		}
		if !target.ExternalBootstrap {
			t.Fatal("expected external bootstrap true")
		}
		savedFD = controllerFD
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("callback was not called")
	}

	// Verify tree was completely unchanged (no state.json created!)
	after := snapshotDirectory(t, f.Root)
	compareSnapshots(t, before, after)
	if _, err := os.Stat(filepath.Join(f.Root, "state.json")); !os.IsNotExist(err) {
		t.Fatal("state.json was unexpectedly created")
	}

	// Verify descriptor closed
	buf := make([]byte, 16)
	if _, rerr := savedFD.Read(buf); rerr == nil {
		t.Fatal("expected controllerFD to be closed after callback")
	}
}

func TestHostBootstrapReadOnlyTornState(t *testing.T) {
	f := newSlotFixture(t)
	b, err := PinHostBootstrap(context.Background(), f.Spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })

	ctx := context.Background()

	// Write pre-created lock file (required for lock acquisition)
	lockPath := filepath.Join(f.Root, "lock")
	if err := os.WriteFile(lockPath, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}

	// Write a torn state.new in the root (0600 mode)
	tornPath := filepath.Join(f.Root, "state.new")
	tornContent := []byte("ACORNFOX-HOST-SLOTS-1\nincomplete torn state staged file\n")
	if err := os.WriteFile(tornPath, tornContent, 0600); err != nil {
		t.Fatal(err)
	}

	before := snapshotDirectory(t, f.Root)

	called := false
	var savedFD *os.File
	err = OpenActiveControllerReadOnly(ctx, HostBootstrapReadOnlyOptions{
		Root:       f.Root,
		InstanceID: f.ID,
		Bootstrap:  b,
	}, func(ctx context.Context, target HostActiveControllerTarget, controllerFD *os.File) error {
		called = true
		if target.Role != HostBootstrapRoleRecovery {
			t.Fatalf("expected role recovery, got %s", target.Role)
		}
		if !target.IsRecovery() {
			t.Fatal("expected IsRecovery true")
		}
		if target.SlotID != b.ID() {
			t.Fatalf("expected slot %s, got %s", b.ID(), target.SlotID)
		}
		if !target.ExternalBootstrap {
			t.Fatal("expected external bootstrap true")
		}
		savedFD = controllerFD
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("callback was not called")
	}

	// Verify state.new was NOT repaired, published, or deleted
	after := snapshotDirectory(t, f.Root)
	compareSnapshots(t, before, after)
	readContent, err := os.ReadFile(tornPath)
	if err != nil || string(readContent) != string(tornContent) {
		t.Fatal("state.new was unexpectedly altered")
	}

	// Verify descriptor closed
	buf := make([]byte, 16)
	if _, rerr := savedFD.Read(buf); rerr == nil {
		t.Fatal("expected controllerFD to be closed after callback")
	}
}

func TestHostBootstrapReadOnlySelectorLockConcurrency(t *testing.T) {
	f := newSlotFixture(t)
	m, a := f.open(t)
	ctx := context.Background()

	// Initialize slots ledger
	bootID, err := m.CurrentSlot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	lockPath := filepath.Join(f.Root, "lock")

	// 1. Test when active writer holds EX lock on lockfile:
	// OpenActiveControllerReadOnly must return ErrHostBusy and NOT invoke callback
	lockFile, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}

	opts := HostBootstrapReadOnlyOptions{
		Root:       f.Root,
		InstanceID: f.ID,
		Bootstrap:  m.options.Bootstrap,
	}

	err = OpenActiveControllerReadOnly(ctx, opts, func(ctx context.Context, target HostActiveControllerTarget, fd *os.File) error {
		t.Fatal("callback invoked while writer holds lock")
		return nil
	})
	if !errors.Is(err, ErrHostBusy) {
		t.Fatalf("expected ErrHostBusy while locked, got %v", err)
	}

	// Release lock
	syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	lockFile.Close()

	// 2. Active switch test: Active changes from bootID to a.SHA256() under writer lock
	// After writer commits and releases lock, selector must select the NEW active slot
	if err = m.Prepare(ctx, a, bootID); err != nil {
		t.Fatal(err)
	}
	attemptID := strings.Repeat("8", 64)
	if err = m.Activate(ctx, attemptID, bootID, a.SHA256()); err != nil {
		t.Fatal(err)
	}

	var selectedSlot string
	err = OpenActiveControllerReadOnly(ctx, opts, func(ctx context.Context, target HostActiveControllerTarget, fd *os.File) error {
		selectedSlot = target.SlotID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if selectedSlot != a.SHA256() {
		t.Fatalf("expected new active slot %s, got %s", a.SHA256(), selectedSlot)
	}
}

func TestHostBootstrapReadOnlyTornSecurityChecks(t *testing.T) {
	f := newSlotFixture(t)
	b, err := PinHostBootstrap(context.Background(), f.Spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })

	ctx := context.Background()
	lockPath := filepath.Join(f.Root, "lock")
	if err := os.WriteFile(lockPath, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}

	opts := HostBootstrapReadOnlyOptions{
		Root:       f.Root,
		InstanceID: f.ID,
		Bootstrap:  b,
	}

	// 1. state.new as directory must fail closed
	tornDir := filepath.Join(f.Root, "state.new")
	if err := os.Mkdir(tornDir, 0700); err != nil {
		t.Fatal(err)
	}
	err = OpenActiveControllerReadOnly(ctx, opts, func(ctx context.Context, target HostActiveControllerTarget, fd *os.File) error {
		return nil
	})
	os.Remove(tornDir)
	if !errors.Is(err, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict for directory state.new, got %v", err)
	}

	// 2. state.payload as directory must fail closed
	payloadDir := filepath.Join(f.Root, "state.payload")
	if err := os.Mkdir(payloadDir, 0700); err != nil {
		t.Fatal(err)
	}
	err = OpenActiveControllerReadOnly(ctx, opts, func(ctx context.Context, target HostActiveControllerTarget, fd *os.File) error {
		return nil
	})
	os.Remove(payloadDir)
	if !errors.Is(err, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict for directory state.payload, got %v", err)
	}

	// 3. state.new with insecure permissions (0644) must fail closed
	tornFile := filepath.Join(f.Root, "state.new")
	if err := os.WriteFile(tornFile, []byte("torn"), 0644); err != nil {
		t.Fatal(err)
	}
	err = OpenActiveControllerReadOnly(ctx, opts, func(ctx context.Context, target HostActiveControllerTarget, fd *os.File) error {
		return nil
	})
	os.Remove(tornFile)
	if !errors.Is(err, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict for insecure mode state.new, got %v", err)
	}

	// 4. slot directory with insecure permissions (0755) must fail closed
	slotDir := filepath.Join(f.Root, "slot-"+strings.Repeat("1", 64))
	if err := os.Mkdir(slotDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Add state.new so it's in torn branch
	os.WriteFile(tornFile, []byte("torn"), 0600)
	err = OpenActiveControllerReadOnly(ctx, opts, func(ctx context.Context, target HostActiveControllerTarget, fd *os.File) error {
		return nil
	})
	os.Remove(tornFile)
	os.Remove(slotDir)
	if !errors.Is(err, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict for insecure slot directory, got %v", err)
	}
}

func TestHostBootstrapReadOnlyUnsafeInventoryAndRejection(t *testing.T) {
	f := newSlotFixture(t)
	m, _ := f.open(t)
	ctx := context.Background()

	// Initialize state
	if _, err := m.CurrentSlot(ctx); err != nil {
		t.Fatal(err)
	}

	opts := HostBootstrapReadOnlyOptions{
		Root:       f.Root,
		InstanceID: f.ID,
		Bootstrap:  m.options.Bootstrap,
	}

	// 1. Foreign instance ID reject
	badInstanceOpts := opts
	badInstanceOpts.InstanceID = strings.Repeat("f", 64)
	err := OpenActiveControllerReadOnly(ctx, badInstanceOpts, func(ctx context.Context, target HostActiveControllerTarget, fd *os.File) error {
		return nil
	})
	if !errors.Is(err, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict for foreign instance, got %v", err)
	}

	// 2. Unsafe/foreign file in root reject
	unauthorizedFile := filepath.Join(f.Root, "unauthorized.txt")
	if err := os.WriteFile(unauthorizedFile, []byte("evil"), 0644); err != nil {
		t.Fatal(err)
	}
	err = OpenActiveControllerReadOnly(ctx, opts, func(ctx context.Context, target HostActiveControllerTarget, fd *os.File) error {
		return nil
	})
	if !errors.Is(err, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict for unknown file, got %v", err)
	}
	os.Remove(unauthorizedFile)

	// 3. Symlink reject
	symlinkPath := filepath.Join(f.Root, "symlink-entry")
	if err := os.Symlink(f.Root, symlinkPath); err == nil {
		err = OpenActiveControllerReadOnly(ctx, opts, func(ctx context.Context, target HostActiveControllerTarget, fd *os.File) error {
			return nil
		})
		os.Remove(symlinkPath)
		if !errors.Is(err, ErrHostConflict) {
			t.Fatalf("expected ErrHostConflict for symlink, got %v", err)
		}
	}

	// 4. Missing root directory reject without creating it
	nonExistentOpts := opts
	nonExistentOpts.Root = filepath.Join(filepath.Dir(f.Root), "nonexistent-root")
	err = OpenActiveControllerReadOnly(ctx, nonExistentOpts, func(ctx context.Context, target HostActiveControllerTarget, fd *os.File) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error for nonexistent root")
	}
	if _, err := os.Stat(nonExistentOpts.Root); !os.IsNotExist(err) {
		t.Fatal("nonexistent root was created")
	}

	// 5. Cancelled context reject
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	err = OpenActiveControllerReadOnly(cancelCtx, opts, func(ctx context.Context, target HostActiveControllerTarget, fd *os.File) error {
		t.Fatal("callback called with cancelled context")
		return nil
	})
	if err == nil {
		t.Fatal("expected error with cancelled context")
	}

	// 6. Nil callback reject
	err = OpenActiveControllerReadOnly(ctx, opts, nil)
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("expected ErrInvalidOptions for nil callback, got %v", err)
	}

	// 7. Nil bootstrap reject
	nilBootOpts := opts
	nilBootOpts.Bootstrap = nil
	err = OpenActiveControllerReadOnly(ctx, nilBootOpts, func(ctx context.Context, target HostActiveControllerTarget, fd *os.File) error {
		return nil
	})
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("expected ErrInvalidOptions for nil bootstrap, got %v", err)
	}
}
