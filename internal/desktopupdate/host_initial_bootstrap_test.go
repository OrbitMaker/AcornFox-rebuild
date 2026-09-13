package desktopupdate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type initialBootstrapFixture struct {
	base           string
	controllerDir  string
	slotsDir       string
	controllerLock string
	slotsLock      string
	fixture        slotFixture
	bootstrap      *PinnedHostBootstrap
}

func newInitialBootstrapFixture(t *testing.T) *initialBootstrapFixture {
	t.Helper()
	f := newSlotFixture(t)
	ctx := context.Background()

	b, err := PinHostBootstrap(ctx, f.Spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })

	base, err := filepath.EvalSymlinks(createTestParentDir(t))
	if err != nil {
		t.Fatal(err)
	}

	controllerDir := filepath.Join(base, "controller")
	if err := os.Mkdir(controllerDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := secureNewStageDirectory(ctx, controllerDir); err != nil {
		t.Fatal(err)
	}

	slotsDir := filepath.Join(base, "slots")
	if err := os.Mkdir(slotsDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := secureNewStageDirectory(ctx, slotsDir); err != nil {
		t.Fatal(err)
	}

	controllerLock := filepath.Join(controllerDir, "lock")
	if err := os.WriteFile(controllerLock, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}

	slotsLock := filepath.Join(slotsDir, "lock")
	if err := os.WriteFile(slotsLock, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}

	return &initialBootstrapFixture{
		base:           base,
		controllerDir:  controllerDir,
		slotsDir:       slotsDir,
		controllerLock: controllerLock,
		slotsLock:      slotsLock,
		fixture:        f,
		bootstrap:      b,
	}
}

func (bf *initialBootstrapFixture) options() HostInitialBootstrapOptions {
	return HostInitialBootstrapOptions{
		ControllerRoot: bf.controllerDir,
		SlotsRoot:      bf.slotsDir,
		InstanceID:     bf.fixture.ID,
		Bootstrap:      bf.bootstrap,
	}
}

func TestHostInitialBootstrap_EmptyAndCanonicalC0Success(t *testing.T) {
	bf := newInitialBootstrapFixture(t)
	ctx := context.Background()
	opts := bf.options()

	// 1. Initial empty root success (controller has lock only, slots has lock only)
	beforeController := snapshotDirectory(t, bf.controllerDir)
	beforeSlots := snapshotDirectory(t, bf.slotsDir)

	var savedFD *os.File
	called := false
	err := OpenInitialBootstrapLauncherReadOnly(ctx, opts, func(cbCtx context.Context, target HostInitialBootstrapTarget, launcherFD *os.File) error {
		called = true
		if target.InstanceID != bf.fixture.ID {
			t.Fatalf("expected InstanceID %s, got %s", bf.fixture.ID, target.InstanceID)
		}
		if target.SlotSHA256 != bf.bootstrap.ID() {
			t.Fatalf("expected SlotSHA256 %s, got %s", bf.bootstrap.ID(), target.SlotSHA256)
		}
		if target.ControllerProtocol != 1 {
			t.Fatalf("expected ControllerProtocol 1, got %d", target.ControllerProtocol)
		}
		if target.InstanceProtocol != 1 {
			t.Fatalf("expected InstanceProtocol 1, got %d", target.InstanceProtocol)
		}
		if target.BackendAPIProtocol != 1 {
			t.Fatalf("expected BackendAPIProtocol 1, got %d", target.BackendAPIProtocol)
		}
		if launcherFD == nil {
			t.Fatal("launcherFD is nil")
		}

		// Read bytes from launcherFD to verify it is readable and backed by the verified binary
		buf := make([]byte, 16)
		n, rerr := launcherFD.Read(buf)
		if rerr != nil || n == 0 {
			t.Fatalf("reading launcherFD failed: %v", rerr)
		}
		savedFD = launcherFD
		return nil
	})
	if err != nil {
		t.Fatalf("OpenInitialBootstrapLauncherReadOnly failed: %v", err)
	}
	if !called {
		t.Fatal("callback was not called")
	}

	// Verify launcher descriptor is closed after callback returns
	buf := make([]byte, 16)
	if _, rerr := savedFD.Read(buf); rerr == nil {
		t.Fatal("expected launcherFD to be closed after callback")
	}

	// Verify directory snapshots are 100% unchanged (no creation, repair, delete, fsync, ledger)
	afterController := snapshotDirectory(t, bf.controllerDir)
	afterSlots := snapshotDirectory(t, bf.slotsDir)
	compareSnapshots(t, beforeController, afterController)
	compareSnapshots(t, beforeSlots, afterSlots)

	// 2. Canonical external-C0 state in slots (state.json with active == Bootstrap.ID(), records empty)
	canonicalLedger := slotLedger{
		Schema:      1,
		Revision:    1,
		InstanceID:  bf.fixture.ID,
		BootstrapID: bf.bootstrap.ID(),
		Active:      bf.bootstrap.ID(),
	}
	rawLedger := hostBytes(canonicalLedger)
	if err := os.WriteFile(filepath.Join(bf.slotsDir, "state.json"), rawLedger, 0600); err != nil {
		t.Fatal(err)
	}

	beforeControllerC0 := snapshotDirectory(t, bf.controllerDir)
	beforeSlotsC0 := snapshotDirectory(t, bf.slotsDir)

	calledC0 := false
	var savedFDC0 *os.File
	err = OpenInitialBootstrapLauncherReadOnly(ctx, opts, func(cbCtx context.Context, target HostInitialBootstrapTarget, launcherFD *os.File) error {
		calledC0 = true
		if target.InstanceID != bf.fixture.ID || target.SlotSHA256 != bf.bootstrap.ID() {
			t.Fatalf("unexpected target: %+v", target)
		}
		savedFDC0 = launcherFD
		return nil
	})
	if err != nil {
		t.Fatalf("canonical C0 OpenInitialBootstrapLauncherReadOnly failed: %v", err)
	}
	if !calledC0 {
		t.Fatal("callback was not called for canonical C0")
	}

	// Verify FD closed and directories unchanged
	if _, rerr := savedFDC0.Read(buf); rerr == nil {
		t.Fatal("expected launcherFD to be closed after canonical C0 callback")
	}
	afterControllerC0 := snapshotDirectory(t, bf.controllerDir)
	afterSlotsC0 := snapshotDirectory(t, bf.slotsDir)
	compareSnapshots(t, beforeControllerC0, afterControllerC0)
	compareSnapshots(t, beforeSlotsC0, afterSlotsC0)
}

func TestHostInitialBootstrap_ControllerStateRejection(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name  string
		setup func(t *testing.T, bf *initialBootstrapFixture)
	}{
		{
			name: "state.json present in controller root",
			setup: func(t *testing.T, bf *initialBootstrapFixture) {
				st := HostSnapshot{
					SchemaVersion: 1,
					Revision:      1,
					InstanceID:    bf.fixture.ID,
					PolicySHA256:  strings.Repeat("1", 64),
					Outcome:       "idle",
					Installed: HostInstallation{
						Version:         "1.0.0",
						SlotSHA256:      bf.bootstrap.ID(),
						BackendBinding:  strings.Repeat("a", 64),
						AppliedSequence: 0,
					},
				}
				if err := os.WriteFile(filepath.Join(bf.controllerDir, "state.json"), hostBytes(st), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "torn state.new present in controller root",
			setup: func(t *testing.T, bf *initialBootstrapFixture) {
				if err := os.WriteFile(filepath.Join(bf.controllerDir, "state.new"), []byte("ACORNFOX-HOST-CONTROLLER-1\ntorn"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "torn state.payload present in controller root",
			setup: func(t *testing.T, bf *initialBootstrapFixture) {
				if err := os.WriteFile(filepath.Join(bf.controllerDir, "state.payload"), []byte("torn"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "stage directory present in controller root",
			setup: func(t *testing.T, bf *initialBootstrapFixture) {
				stageDir := filepath.Join(bf.controllerDir, "stage-1234567890abcdef")
				if err := os.Mkdir(stageDir, 0700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unknown file present in controller root",
			setup: func(t *testing.T, bf *initialBootstrapFixture) {
				if err := os.WriteFile(filepath.Join(bf.controllerDir, "sentinel.txt"), []byte("unknown"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing lock file in controller root",
			setup: func(t *testing.T, bf *initialBootstrapFixture) {
				if err := os.Remove(bf.controllerLock); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bf := newInitialBootstrapFixture(t)
			tc.setup(t, bf)

			beforeController := snapshotDirectory(t, bf.controllerDir)
			beforeSlots := snapshotDirectory(t, bf.slotsDir)

			called := false
			err := OpenInitialBootstrapLauncherReadOnly(ctx, bf.options(), func(context.Context, HostInitialBootstrapTarget, *os.File) error {
				called = true
				return nil
			})
			if !errors.Is(err, ErrHostConflict) {
				t.Fatalf("expected ErrHostConflict, got %v", err)
			}
			if called {
				t.Fatal("callback was unexpectedly called")
			}

			// Verify snapshots completely unchanged
			afterController := snapshotDirectory(t, bf.controllerDir)
			afterSlots := snapshotDirectory(t, bf.slotsDir)
			compareSnapshots(t, beforeController, afterController)
			compareSnapshots(t, beforeSlots, afterSlots)
		})
	}
}

func TestHostInitialBootstrap_SlotsStateRejection(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name  string
		setup func(t *testing.T, bf *initialBootstrapFixture)
	}{
		{
			name: "torn state.new present in slots root",
			setup: func(t *testing.T, bf *initialBootstrapFixture) {
				tornContent := []byte("ACORNFOX-HOST-SLOTS-1\ntorn")
				if err := os.WriteFile(filepath.Join(bf.slotsDir, "state.new"), tornContent, 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "torn state.payload present in slots root",
			setup: func(t *testing.T, bf *initialBootstrapFixture) {
				if err := os.WriteFile(filepath.Join(bf.slotsDir, "state.payload"), []byte("torn"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "managed slot record present in slots state.json",
			setup: func(t *testing.T, bf *initialBootstrapFixture) {
				managedID := strings.Repeat("b", 64)
				l := slotLedger{
					Schema:      1,
					Revision:    1,
					InstanceID:  bf.fixture.ID,
					BootstrapID: bf.bootstrap.ID(),
					Active:      bf.bootstrap.ID(),
					Records: []slotRecord{
						{
							ID:        managedID,
							Directory: "slot-" + strings.Repeat("c", 64),
							Identity:  "dev-ino",
							Manifest: HostBootstrapSpec{
								OS:                 bf.bootstrap.spec.OS,
								Architecture:       bf.bootstrap.spec.Architecture,
								Version:            "1.1.0",
								Launcher:           "launcher/acornfox",
								Controller:         "controller/acornfox-host-update",
								ControllerProtocol: 1,
								InstanceProtocol:   1,
								BackendAPIProtocol: 1,
								Files: []HostBundleFile{
									{Path: "launcher/acornfox", SHA256: strings.Repeat("d", 64), Size: 100, Mode: 0755},
									{Path: "controller/acornfox-host-update", SHA256: strings.Repeat("e", 64), Size: 100, Mode: 0755},
								},
							},
						},
					},
				}
				if err := os.WriteFile(filepath.Join(bf.slotsDir, "state.json"), hostBytes(l), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "preparing slot present in slots state.json",
			setup: func(t *testing.T, bf *initialBootstrapFixture) {
				l := slotLedger{
					Schema:      1,
					Revision:    1,
					InstanceID:  bf.fixture.ID,
					BootstrapID: bf.bootstrap.ID(),
					Active:      bf.bootstrap.ID(),
					Preparing: &slotPreparation{
						Record: slotRecord{
							ID:        strings.Repeat("f", 64),
							Directory: "slot-" + strings.Repeat("1", 64),
							Manifest: HostBootstrapSpec{
								OS:                 bf.bootstrap.spec.OS,
								Architecture:       bf.bootstrap.spec.Architecture,
								Version:            "1.1.0",
								Launcher:           "launcher/acornfox",
								Controller:         "controller/acornfox-host-update",
								ControllerProtocol: 1,
								InstanceProtocol:   1,
								BackendAPIProtocol: 1,
								Files: []HostBundleFile{
									{Path: "launcher/acornfox", SHA256: strings.Repeat("2", 64), Size: 100, Mode: 0755},
									{Path: "controller/acornfox-host-update", SHA256: strings.Repeat("3", 64), Size: 100, Mode: 0755},
								},
							},
						},
					},
				}
				if err := os.WriteFile(filepath.Join(bf.slotsDir, "state.json"), hostBytes(l), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "deleting record present in slots state.json",
			setup: func(t *testing.T, bf *initialBootstrapFixture) {
				l := slotLedger{
					Schema:      1,
					Revision:    1,
					InstanceID:  bf.fixture.ID,
					BootstrapID: bf.bootstrap.ID(),
					Active:      bf.bootstrap.ID(),
					Deleting:    []string{strings.Repeat("9", 64)},
				}
				// Note: write raw bytes directly
				raw, _ := json.Marshal(l)
				if err := os.WriteFile(filepath.Join(bf.slotsDir, "state.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unknown directory present in slots root",
			setup: func(t *testing.T, bf *initialBootstrapFixture) {
				if err := os.Mkdir(filepath.Join(bf.slotsDir, "unknown-dir"), 0700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unknown file present in slots root",
			setup: func(t *testing.T, bf *initialBootstrapFixture) {
				if err := os.WriteFile(filepath.Join(bf.slotsDir, "sentinel.txt"), []byte("unknown"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing lock file in slots root",
			setup: func(t *testing.T, bf *initialBootstrapFixture) {
				if err := os.Remove(bf.slotsLock); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "canonical external-C0 state with revision 2 is rejected as historical evidence",
			setup: func(t *testing.T, bf *initialBootstrapFixture) {
				l := slotLedger{
					Schema:      1,
					Revision:    2,
					InstanceID:  bf.fixture.ID,
					BootstrapID: bf.bootstrap.ID(),
					Active:      bf.bootstrap.ID(),
				}
				if err := os.WriteFile(filepath.Join(bf.slotsDir, "state.json"), hostBytes(l), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bf := newInitialBootstrapFixture(t)
			tc.setup(t, bf)

			beforeController := snapshotDirectory(t, bf.controllerDir)
			beforeSlots := snapshotDirectory(t, bf.slotsDir)

			called := false
			err := OpenInitialBootstrapLauncherReadOnly(ctx, bf.options(), func(context.Context, HostInitialBootstrapTarget, *os.File) error {
				called = true
				return nil
			})
			if !errors.Is(err, ErrHostConflict) {
				t.Fatalf("expected ErrHostConflict, got %v", err)
			}
			if called {
				t.Fatal("callback was unexpectedly called")
			}

			// Verify snapshots completely unchanged
			afterController := snapshotDirectory(t, bf.controllerDir)
			afterSlots := snapshotDirectory(t, bf.slotsDir)
			compareSnapshots(t, beforeController, afterController)
			compareSnapshots(t, beforeSlots, afterSlots)
		})
	}
}

func TestHostInitialBootstrap_MismatchRejection(t *testing.T) {
	ctx := context.Background()

	// 1. InstanceID mismatch in state.json vs opts
	t.Run("instance ID mismatch in slots state", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		l := slotLedger{
			Schema:      1,
			Revision:    1,
			InstanceID:  strings.Repeat("9", 64),
			BootstrapID: bf.bootstrap.ID(),
			Active:      bf.bootstrap.ID(),
		}
		if err := os.WriteFile(filepath.Join(bf.slotsDir, "state.json"), hostBytes(l), 0600); err != nil {
			t.Fatal(err)
		}
		err := OpenInitialBootstrapLauncherReadOnly(ctx, bf.options(), func(context.Context, HostInitialBootstrapTarget, *os.File) error {
			t.Fatal("callback should not be called")
			return nil
		})
		if !errors.Is(err, ErrHostConflict) {
			t.Fatalf("expected ErrHostConflict, got %v", err)
		}
	})

	// 2. BootstrapID mismatch in state.json vs opts
	t.Run("bootstrap ID mismatch in slots state", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		l := slotLedger{
			Schema:      1,
			Revision:    1,
			InstanceID:  bf.fixture.ID,
			BootstrapID: strings.Repeat("8", 64),
			Active:      strings.Repeat("8", 64),
		}
		if err := os.WriteFile(filepath.Join(bf.slotsDir, "state.json"), hostBytes(l), 0600); err != nil {
			t.Fatal(err)
		}
		err := OpenInitialBootstrapLauncherReadOnly(ctx, bf.options(), func(context.Context, HostInitialBootstrapTarget, *os.File) error {
			t.Fatal("callback should not be called")
			return nil
		})
		if !errors.Is(err, ErrHostConflict) {
			t.Fatalf("expected ErrHostConflict, got %v", err)
		}
	})

	// 3. Active not bootstrap ID (e.g. points to managed slot)
	t.Run("active mismatch in slots state", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		l := slotLedger{
			Schema:      1,
			Revision:    1,
			InstanceID:  bf.fixture.ID,
			BootstrapID: bf.bootstrap.ID(),
			Active:      strings.Repeat("7", 64),
		}
		raw, _ := json.Marshal(l)
		if err := os.WriteFile(filepath.Join(bf.slotsDir, "state.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		err := OpenInitialBootstrapLauncherReadOnly(ctx, bf.options(), func(context.Context, HostInitialBootstrapTarget, *os.File) error {
			t.Fatal("callback should not be called")
			return nil
		})
		if !errors.Is(err, ErrHostConflict) {
			t.Fatalf("expected ErrHostConflict, got %v", err)
		}
	})

	// 4. Invalid instance ID in opts
	t.Run("invalid instance ID in opts", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		opts := bf.options()
		opts.InstanceID = "not-a-sha256"
		err := OpenInitialBootstrapLauncherReadOnly(ctx, opts, func(context.Context, HostInitialBootstrapTarget, *os.File) error {
			return nil
		})
		if !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("expected ErrInvalidOptions, got %v", err)
		}
	})

	// 5. Nil bootstrap
	t.Run("nil bootstrap in opts", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		opts := bf.options()
		opts.Bootstrap = nil
		err := OpenInitialBootstrapLauncherReadOnly(ctx, opts, func(context.Context, HostInitialBootstrapTarget, *os.File) error {
			return nil
		})
		if !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("expected ErrInvalidOptions, got %v", err)
		}
	})

	// 6. Nil callback
	t.Run("nil callback", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		err := OpenInitialBootstrapLauncherReadOnly(ctx, bf.options(), nil)
		if !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("expected ErrInvalidOptions, got %v", err)
		}
	})

	// 7. Nil context
	t.Run("nil context", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		err := OpenInitialBootstrapLauncherReadOnly(nil, bf.options(), func(context.Context, HostInitialBootstrapTarget, *os.File) error {
			return nil
		})
		if !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("expected ErrInvalidOptions, got %v", err)
		}
	})
}

func TestHostInitialBootstrap_PathAndOwnershipSecurityFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("relative ControllerRoot", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		opts := bf.options()
		opts.ControllerRoot = "relative/path"
		err := OpenInitialBootstrapLauncherReadOnly(ctx, opts, func(context.Context, HostInitialBootstrapTarget, *os.File) error { return nil })
		if !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("expected ErrInvalidOptions, got %v", err)
		}
	})

	t.Run("relative SlotsRoot", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		opts := bf.options()
		opts.SlotsRoot = "relative/path"
		err := OpenInitialBootstrapLauncherReadOnly(ctx, opts, func(context.Context, HostInitialBootstrapTarget, *os.File) error { return nil })
		if !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("expected ErrInvalidOptions, got %v", err)
		}
	})

	t.Run("non-clean ControllerRoot path", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		opts := bf.options()
		opts.ControllerRoot = bf.controllerDir + "/."
		err := OpenInitialBootstrapLauncherReadOnly(ctx, opts, func(context.Context, HostInitialBootstrapTarget, *os.File) error { return nil })
		if !errors.Is(err, ErrHostConflict) {
			t.Fatalf("expected ErrHostConflict, got %v", err)
		}
	})

	t.Run("identical roots", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		opts := bf.options()
		opts.ControllerRoot = bf.slotsDir
		err := OpenInitialBootstrapLauncherReadOnly(ctx, opts, func(context.Context, HostInitialBootstrapTarget, *os.File) error { return nil })
		if !errors.Is(err, ErrHostConflict) {
			t.Fatalf("expected ErrHostConflict, got %v", err)
		}
	})

	t.Run("nested roots: controller inside slots", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		opts := bf.options()
		opts.ControllerRoot = filepath.Join(bf.slotsDir, "sub-controller")
		err := OpenInitialBootstrapLauncherReadOnly(ctx, opts, func(context.Context, HostInitialBootstrapTarget, *os.File) error { return nil })
		if !errors.Is(err, ErrHostConflict) {
			t.Fatalf("expected ErrHostConflict, got %v", err)
		}
	})

	t.Run("nested roots: slots inside controller", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		opts := bf.options()
		opts.SlotsRoot = filepath.Join(bf.controllerDir, "sub-slots")
		err := OpenInitialBootstrapLauncherReadOnly(ctx, opts, func(context.Context, HostInitialBootstrapTarget, *os.File) error { return nil })
		if !errors.Is(err, ErrHostConflict) {
			t.Fatalf("expected ErrHostConflict, got %v", err)
		}
	})

	t.Run("root nested inside bootstrap root", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		opts := bf.options()
		opts.ControllerRoot = filepath.Join(bf.bootstrap.spec.Root, "nested-controller")
		err := OpenInitialBootstrapLauncherReadOnly(ctx, opts, func(context.Context, HostInitialBootstrapTarget, *os.File) error { return nil })
		if !errors.Is(err, ErrHostConflict) {
			t.Fatalf("expected ErrHostConflict, got %v", err)
		}
	})

	t.Run("root is a symlink", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		symlinkRoot := filepath.Join(bf.base, "symlink-controller")
		if err := os.Symlink(bf.controllerDir, symlinkRoot); err != nil {
			t.Fatal(err)
		}
		opts := bf.options()
		opts.ControllerRoot = symlinkRoot
		err := OpenInitialBootstrapLauncherReadOnly(ctx, opts, func(context.Context, HostInitialBootstrapTarget, *os.File) error { return nil })
		if !errors.Is(err, ErrHostConflict) {
			t.Fatalf("expected ErrHostConflict, got %v", err)
		}
	})

	t.Run("lock file is a symlink", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		realLock := filepath.Join(bf.base, "external-lock")
		if err := os.WriteFile(realLock, []byte{}, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(bf.controllerLock); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realLock, bf.controllerLock); err != nil {
			t.Fatal(err)
		}
		err := OpenInitialBootstrapLauncherReadOnly(ctx, bf.options(), func(context.Context, HostInitialBootstrapTarget, *os.File) error { return nil })
		if !errors.Is(err, ErrHostConflict) {
			t.Fatalf("expected ErrHostConflict, got %v", err)
		}
	})

	t.Run("insecure controller root permissions 0755", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		if err := os.Chmod(bf.controllerDir, 0755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(bf.controllerDir, 0700) })
		err := OpenInitialBootstrapLauncherReadOnly(ctx, bf.options(), func(context.Context, HostInitialBootstrapTarget, *os.File) error { return nil })
		if !errors.Is(err, ErrHostConflict) {
			t.Fatalf("expected ErrHostConflict, got %v", err)
		}
	})

	t.Run("insecure slots root permissions 0755", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		if err := os.Chmod(bf.slotsDir, 0755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(bf.slotsDir, 0700) })
		err := OpenInitialBootstrapLauncherReadOnly(ctx, bf.options(), func(context.Context, HostInitialBootstrapTarget, *os.File) error { return nil })
		if !errors.Is(err, ErrHostConflict) {
			t.Fatalf("expected ErrHostConflict, got %v", err)
		}
	})

	t.Run("insecure lock file permissions 0644", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		if err := os.Chmod(bf.controllerLock, 0644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(bf.controllerLock, 0600) })
		err := OpenInitialBootstrapLauncherReadOnly(ctx, bf.options(), func(context.Context, HostInitialBootstrapTarget, *os.File) error { return nil })
		if !errors.Is(err, ErrHostConflict) {
			t.Fatalf("expected ErrHostConflict, got %v", err)
		}
	})
}

func TestHostInitialBootstrap_BusyLocks(t *testing.T) {
	ctx := context.Background()

	// 1. Controller lock busy
	t.Run("controller lock held by another process", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		f, err := os.OpenFile(bf.controllerLock, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

		called := false
		err = OpenInitialBootstrapLauncherReadOnly(ctx, bf.options(), func(context.Context, HostInitialBootstrapTarget, *os.File) error {
			called = true
			return nil
		})
		if !errors.Is(err, ErrHostBusy) {
			t.Fatalf("expected ErrHostBusy, got %v", err)
		}
		if called {
			t.Fatal("callback called while controller lock busy")
		}
	})

	// 2. Slots lock busy (verifies Controller was locked then Slots, and Controller lock is released on error)
	t.Run("slots lock held by another process", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		f, err := os.OpenFile(bf.slotsLock, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

		called := false
		err = OpenInitialBootstrapLauncherReadOnly(ctx, bf.options(), func(context.Context, HostInitialBootstrapTarget, *os.File) error {
			called = true
			return nil
		})
		if !errors.Is(err, ErrHostBusy) {
			t.Fatalf("expected ErrHostBusy, got %v", err)
		}
		if called {
			t.Fatal("callback called while slots lock busy")
		}

		// Verify Controller lock was released: we should be able to acquire flock on controller lock now
		cf, err := os.OpenFile(bf.controllerLock, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer cf.Close()
		if err := syscall.Flock(int(cf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatalf("expected controller lock to be free after return, but lock failed: %v", err)
		}
		syscall.Flock(int(cf.Fd()), syscall.LOCK_UN)
	})
}

func TestHostInitialBootstrap_ContextCancellation(t *testing.T) {
	// 1. Context already canceled before call
	t.Run("canceled context before call", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		called := false
		err := OpenInitialBootstrapLauncherReadOnly(ctx, bf.options(), func(context.Context, HostInitialBootstrapTarget, *os.File) error {
			called = true
			return nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
		if called {
			t.Fatal("callback called with pre-canceled context")
		}
	})

	// 2. Context canceled inside callback
	t.Run("context canceled inside callback", func(t *testing.T) {
		bf := newInitialBootstrapFixture(t)
		ctx, cancel := context.WithCancel(context.Background())

		var savedFD *os.File
		called := false
		err := OpenInitialBootstrapLauncherReadOnly(ctx, bf.options(), func(cbCtx context.Context, target HostInitialBootstrapTarget, launcherFD *os.File) error {
			called = true
			savedFD = launcherFD
			cancel()
			return cbCtx.Err()
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
		if !called {
			t.Fatal("callback was not called")
		}

		// Verify launcher descriptor is closed
		buf := make([]byte, 16)
		if _, rerr := savedFD.Read(buf); rerr == nil {
			t.Fatal("expected launcherFD to be closed after canceled callback")
		}

		// Verify locks released
		cf, err := os.OpenFile(bf.controllerLock, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer cf.Close()
		if err := syscall.Flock(int(cf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatalf("controller lock not released after cancellation: %v", err)
		}
		syscall.Flock(int(cf.Fd()), syscall.LOCK_UN)
	})
}

func TestHostInitialBootstrap_CallbackFailure(t *testing.T) {
	bf := newInitialBootstrapFixture(t)
	ctx := context.Background()

	beforeController := snapshotDirectory(t, bf.controllerDir)
	beforeSlots := snapshotDirectory(t, bf.slotsDir)

	callbackErr := errors.New("sentinel-callback-failure")
	var savedFD *os.File
	called := false
	err := OpenInitialBootstrapLauncherReadOnly(ctx, bf.options(), func(cbCtx context.Context, target HostInitialBootstrapTarget, launcherFD *os.File) error {
		called = true
		savedFD = launcherFD
		return callbackErr
	})
	if !errors.Is(err, callbackErr) {
		t.Fatalf("expected callbackErr, got %v", err)
	}
	if !called {
		t.Fatal("callback was not called")
	}

	// Verify launcher descriptor closed
	buf := make([]byte, 16)
	if _, rerr := savedFD.Read(buf); rerr == nil {
		t.Fatal("expected launcherFD to be closed after callback error")
	}

	// Verify snapshots unchanged
	afterController := snapshotDirectory(t, bf.controllerDir)
	afterSlots := snapshotDirectory(t, bf.slotsDir)
	compareSnapshots(t, beforeController, afterController)
	compareSnapshots(t, beforeSlots, afterSlots)

	// Verify locks released
	cf, err := os.OpenFile(bf.controllerLock, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cf.Close()
	if err := syscall.Flock(int(cf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("controller lock not released: %v", err)
	}
	syscall.Flock(int(cf.Fd()), syscall.LOCK_UN)
}

func TestHostInitialBootstrap_TargetAuthorityBoundaries(t *testing.T) {
	bf := newInitialBootstrapFixture(t)
	ctx := context.Background()

	var capturedTarget HostInitialBootstrapTarget
	err := OpenInitialBootstrapLauncherReadOnly(ctx, bf.options(), func(cbCtx context.Context, target HostInitialBootstrapTarget, launcherFD *os.File) error {
		capturedTarget = target
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Target must have exact instance and slot SHA256 and protocol 1
	if capturedTarget.InstanceID != bf.fixture.ID {
		t.Fatalf("unexpected instance: %s", capturedTarget.InstanceID)
	}
	if capturedTarget.SlotSHA256 != bf.bootstrap.ID() {
		t.Fatalf("unexpected slot: %s", capturedTarget.SlotSHA256)
	}
	if capturedTarget.ControllerProtocol != 1 || capturedTarget.InstanceProtocol != 1 || capturedTarget.BackendAPIProtocol != 1 {
		t.Fatalf("protocols not 1: %+v", capturedTarget)
	}

	// Marshal/Unmarshal must be prohibited
	if _, err := json.Marshal(capturedTarget); !errors.Is(err, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict from json.Marshal, got %v", err)
	}
	var unmarshaled HostInitialBootstrapTarget
	if err := json.Unmarshal([]byte(`{}`), &unmarshaled); !errors.Is(err, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict from json.Unmarshal, got %v", err)
	}
}

func TestHostInitialBootstrap_WithInitialBootstrapLauncherReadOnlyAlias(t *testing.T) {
	bf := newInitialBootstrapFixture(t)
	ctx := context.Background()

	called := false
	err := WithInitialBootstrapLauncherReadOnly(ctx, bf.options(), func(cbCtx context.Context, target HostInitialBootstrapTarget, launcherFD *os.File) error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("alias callback was not called")
	}
}

func TestHostInitialBootstrap_CanonicalRevision2Rejection(t *testing.T) {
	bf := newInitialBootstrapFixture(t)
	ctx := context.Background()

	// Canonical schema-1 external-C0 bytes with revision 2, empty records, nil preparing/deleting,
	// and a lock-only controller root.
	l := slotLedger{
		Schema:      1,
		Revision:    2,
		InstanceID:  bf.fixture.ID,
		BootstrapID: bf.bootstrap.ID(),
		Active:      bf.bootstrap.ID(),
	}
	rawLedger := hostBytes(l)
	if err := os.WriteFile(filepath.Join(bf.slotsDir, "state.json"), rawLedger, 0600); err != nil {
		t.Fatal(err)
	}

	beforeController := snapshotDirectory(t, bf.controllerDir)
	beforeSlots := snapshotDirectory(t, bf.slotsDir)

	called := false
	err := OpenInitialBootstrapLauncherReadOnly(ctx, bf.options(), func(context.Context, HostInitialBootstrapTarget, *os.File) error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict for canonical external-C0 state with revision 2, got %v", err)
	}
	if called {
		t.Fatal("callback unexpectedly called for revision 2")
	}

	// Verify snapshots remain completely unchanged
	afterController := snapshotDirectory(t, bf.controllerDir)
	afterSlots := snapshotDirectory(t, bf.slotsDir)
	compareSnapshots(t, beforeController, afterController)
	compareSnapshots(t, beforeSlots, afterSlots)
}
