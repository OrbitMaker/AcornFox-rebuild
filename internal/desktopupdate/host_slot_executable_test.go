package desktopupdate

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestHostSlotExecutableWithLauncherFD_ContinuityAndIdentity(t *testing.T) {
	fixture := newSlotFixture(t)
	slots, bundle := fixture.open(t)

	if err := slots.Prepare(context.Background(), bundle, fixture.Spec.Root); err != nil {
		// slot root id
		bID := slots.options.Bootstrap.ID()
		if err := slots.Prepare(context.Background(), bundle, bID); err != nil {
			t.Fatalf("Prepare failed: %v", err)
		}
	}

	viewsTested := 0
	slots.options.Hooks.Start = func(ctx context.Context, instance string, view HostSlotView) error {
		viewsTested++
		var capturedFD *os.File

		err := view.WithLauncherFD(ctx, func(f *os.File, id HostSlotExecutableIdentity) error {
			capturedFD = f

			if id.SHA256 == "" || id.Size <= 0 {
				t.Fatalf("unexpected empty identity: %+v", id)
			}
			// Verify file content matches identity
			h := hostSHA256Bytes(t, f, id.Size)
			if h != id.SHA256 {
				t.Fatalf("computed hash %s != expected %s", h, id.SHA256)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("WithLauncherFD failed: %v", err)
		}

		// Verify that FD is closed after callback returns
		var buf [1]byte
		if _, err := capturedFD.Read(buf[:]); err == nil {
			t.Fatalf("expected read on callback FD after return to fail, but it succeeded")
		}
		return nil
	}

	// Probe on bootstrap
	backend := strings.Repeat("a", 64)
	if err := slots.Probe(context.Background(), slots.options.Bootstrap.ID(), backend); err != nil {
		t.Fatalf("Probe bootstrap failed: %v", err)
	}

	// Activate next slot
	if err := slots.Activate(context.Background(), strings.Repeat("1", 64), slots.options.Bootstrap.ID(), bundle.SHA256()); err != nil {
		t.Fatalf("Activate failed: %v", err)
	}

	// Probe on managed slot
	if err := slots.Probe(context.Background(), bundle.SHA256(), backend); err != nil {
		t.Fatalf("Probe managed failed: %v", err)
	}

	if viewsTested != 2 {
		t.Fatalf("expected 2 views tested, got %d", viewsTested)
	}
}

func TestHostSlotExecutableWithLauncherFD_FailClosedOnDrift(t *testing.T) {
	fixture := newSlotFixture(t)
	bootstrap, err := PinHostBootstrap(context.Background(), fixture.Spec)
	if err != nil {
		t.Fatalf("PinHostBootstrap failed: %v", err)
	}
	defer bootstrap.Close()

	slots, err := NewHostSlots(HostSlotOptions{
		Root:       fixture.Root,
		InstanceID: fixture.ID,
		Bootstrap:  bootstrap,
		Hooks: HostSlotHooks{
			Stop: func(ctx context.Context, instance, attempt string, view HostSlotView) error {
				return nil
			},
			Start: func(ctx context.Context, instance string, view HostSlotView) error {
				return nil
			},
			Probe: func(ctx context.Context, instance string, view HostSlotView, backend string) error {
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("NewHostSlots failed: %v", err)
	}

	// 1. Nil callback returns ErrInvalidOptions
	slots.options.Hooks.Start = func(ctx context.Context, instance string, view HostSlotView) error {
		if err := view.WithLauncherFD(ctx, nil); !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("expected ErrInvalidOptions for nil callback, got: %v", err)
		}
		return nil
	}
	backend := strings.Repeat("a", 64)
	if err := slots.Probe(context.Background(), bootstrap.ID(), backend); err != nil {
		t.Fatalf("Probe failed: %v", err)
	}

	// 2. Cancelled context fails closed
	slots.options.Hooks.Start = func(ctx context.Context, instance string, view HostSlotView) error {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if err := view.WithLauncherFD(cctx, func(f *os.File, id HostSlotExecutableIdentity) error {
			return nil
		}); !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got: %v", err)
		}
		return nil
	}
	if err := slots.Probe(context.Background(), bootstrap.ID(), backend); err != nil {
		t.Fatalf("Probe failed: %v", err)
	}

	// 3. Uninitialized or closed view fails closed
	var emptyView HostSlotView
	if err := emptyView.WithLauncherFD(context.Background(), func(f *os.File, id HostSlotExecutableIdentity) error {
		return nil
	}); !errors.Is(err, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict on empty view, got: %v", err)
	}

	// 4. Content drift: modify file on disk before WithLauncherFD
	slots.options.Hooks.Start = func(ctx context.Context, instance string, view HostSlotView) error {
		// Tamper launcher file directly
		origBytes, err := os.ReadFile(view.LauncherPath())
		if err != nil {
			t.Fatal(err)
		}
		tampered := make([]byte, len(origBytes))
		copy(tampered, origBytes)
		tampered[len(tampered)-1] ^= 0xff
		if err := os.WriteFile(view.LauncherPath(), tampered, 0755); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = os.WriteFile(view.LauncherPath(), origBytes, 0755)
		}()

		called := false
		err = view.WithLauncherFD(ctx, func(f *os.File, id HostSlotExecutableIdentity) error {
			called = true
			return nil
		})
		if !errors.Is(err, ErrHostConflict) {
			t.Fatalf("expected ErrHostConflict on content drift, got: %v", err)
		}
		if called {
			t.Fatalf("callback must not be invoked on content drift")
		}
		return nil
	}
	if err := slots.Probe(context.Background(), bootstrap.ID(), backend); err != nil {
		t.Fatalf("Probe failed: %v", err)
	}

	// 5. Path swap: replace launcher path with a different file
	slots.options.Hooks.Start = func(ctx context.Context, instance string, view HostSlotView) error {
		origPath := view.LauncherPath()
		backupPath := origPath + ".bak"
		if err := os.Rename(origPath, backupPath); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = os.Rename(backupPath, origPath)
		}()

		// Write a dummy file with same name
		if err := os.WriteFile(origPath, []byte("tampered-content"), 0755); err != nil {
			t.Fatal(err)
		}

		called := false
		err = view.WithLauncherFD(ctx, func(f *os.File, id HostSlotExecutableIdentity) error {
			called = true
			return nil
		})
		if !errors.Is(err, ErrHostConflict) {
			t.Fatalf("expected ErrHostConflict on path swap, got: %v", err)
		}
		if called {
			t.Fatalf("callback must not be invoked on path swap")
		}
		return nil
	}
	if err := slots.Probe(context.Background(), bootstrap.ID(), backend); err != nil {
		t.Fatalf("Probe failed: %v", err)
	}

	// 6. Symlink replacement fails closed
	if runtime.GOOS != "windows" {
		slots.options.Hooks.Start = func(ctx context.Context, instance string, view HostSlotView) error {
			origPath := view.LauncherPath()
			backupPath := origPath + ".symbak"
			if err := os.Rename(origPath, backupPath); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = os.Remove(origPath)
				_ = os.Rename(backupPath, origPath)
			}()

			if err := os.Symlink(backupPath, origPath); err != nil {
				t.Fatal(err)
			}

			called := false
			err = view.WithLauncherFD(ctx, func(f *os.File, id HostSlotExecutableIdentity) error {
				called = true
				return nil
			})
			if !errors.Is(err, ErrHostConflict) {
				t.Fatalf("expected ErrHostConflict on symlink replacement, got: %v", err)
			}
			if called {
				t.Fatalf("callback must not be invoked on symlink replacement")
			}
			return nil
		}
		if err := slots.Probe(context.Background(), bootstrap.ID(), backend); err != nil {
			t.Fatalf("Probe failed: %v", err)
		}
	}

	// 7. Mode drift: fchmod to 0644 (not 0755) fails closed
	if runtime.GOOS != "windows" {
		slots.options.Hooks.Start = func(ctx context.Context, instance string, view HostSlotView) error {
			origPath := view.LauncherPath()
			if err := os.Chmod(origPath, 0644); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = os.Chmod(origPath, 0755)
			}()

			called := false
			err = view.WithLauncherFD(ctx, func(f *os.File, id HostSlotExecutableIdentity) error {
				called = true
				return nil
			})
			if !errors.Is(err, ErrHostConflict) {
				t.Fatalf("expected ErrHostConflict on mode drift, got: %v", err)
			}
			if called {
				t.Fatalf("callback must not be invoked on mode drift")
			}
			return nil
		}
		if err := slots.Probe(context.Background(), bootstrap.ID(), backend); err != nil {
			t.Fatalf("Probe failed: %v", err)
		}
	}

	// 8. Hard link drift: nlink > 1 fails closed
	if runtime.GOOS != "windows" {
		slots.options.Hooks.Start = func(ctx context.Context, instance string, view HostSlotView) error {
			origPath := view.LauncherPath()
			linkPath := origPath + ".hardlink"
			if err := os.Link(origPath, linkPath); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = os.Remove(linkPath)
			}()

			called := false
			err = view.WithLauncherFD(ctx, func(f *os.File, id HostSlotExecutableIdentity) error {
				called = true
				return nil
			})
			if !errors.Is(err, ErrHostConflict) {
				t.Fatalf("expected ErrHostConflict on hardlink drift, got: %v", err)
			}
			if called {
				t.Fatalf("callback must not be invoked on hardlink drift")
			}
			return nil
		}
		if err := slots.Probe(context.Background(), bootstrap.ID(), backend); err != nil {
			t.Fatalf("Probe failed: %v", err)
		}
	}
}

func hostSHA256Bytes(t *testing.T, r io.ReaderAt, size int64) string {
	t.Helper()
	buf := make([]byte, size)
	n, err := r.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if int64(n) != size {
		t.Fatalf("short read %d != %d", n, size)
	}
	return hostSHA(buf)
}

func TestOpenActiveControllerReadOnly_FDContinuity(t *testing.T) {
	fixture := newSlotFixture(t)
	slots, _ := fixture.open(t)
	ctx := context.Background()

	bootID, err := slots.CurrentSlot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	controllerPath := filepath.Join(fixture.Spec.Root, filepath.FromSlash(fixture.Spec.Controller))
	origBytes, err := os.ReadFile(controllerPath)
	if err != nil {
		t.Fatal(err)
	}
	origHash := hostSHA(origBytes)

	var callbackRan bool
	opts := HostBootstrapReadOnlyOptions{
		Root:       fixture.Root,
		InstanceID: fixture.ID,
		Bootstrap:  slots.options.Bootstrap,
	}

	err = OpenActiveControllerReadOnly(ctx, opts, func(cbCtx context.Context, target HostActiveControllerTarget, fd *os.File) error {
		callbackRan = true
		if target.SlotID != bootID {
			t.Fatalf("expected slot %s, got %s", bootID, target.SlotID)
		}

		// Replace controller file on disk during callback via path replacement
		tampered := append([]byte("replaced-controller-bytes"), origBytes...)
		tamperedPath := controllerPath + ".tampered"
		if err := os.WriteFile(tamperedPath, tampered, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tamperedPath, controllerPath); err != nil {
			t.Fatal(err)
		}

		// Read from the verified FD using pread from offset 0
		readBuf := make([]byte, len(origBytes))
		n, err := fd.ReadAt(readBuf, 0)
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("ReadAt failed: %v", err)
		}
		if n != len(origBytes) {
			t.Fatalf("read size mismatch: %d != %d", n, len(origBytes))
		}
		if hostSHA(readBuf) != origHash {
			t.Fatalf("FD content changed after disk replacement!")
		}

		// Also check more bytes beyond original size cannot be read
		extraBuf := make([]byte, 100)
		nExtra, _ := fd.ReadAt(extraBuf, int64(len(origBytes)))
		if nExtra != 0 {
			t.Fatalf("expected 0 extra bytes from original FD, got %d", nExtra)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("OpenActiveControllerReadOnly failed: %v", err)
	}
	if !callbackRan {
		t.Fatalf("callback did not run")
	}
}
