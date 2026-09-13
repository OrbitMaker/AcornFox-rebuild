package desktopupdate

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// HostBootstrapRole distinguishes normal active controller execution from
// fallback recovery controller execution.
type HostBootstrapRole string

const (
	HostBootstrapRoleNormal   HostBootstrapRole = "normal"
	HostBootstrapRoleRecovery HostBootstrapRole = "recovery"
)

// HostActiveControllerTarget carries immutable descriptor metadata passed into
// the read-only controller execution callback. No filesystem paths or durable
// records are returned for later execution.
type HostActiveControllerTarget struct {
	Role              HostBootstrapRole
	SlotID            string
	ExternalBootstrap bool
}

// IsRecovery reports whether the controller was selected under the fallback
// recovery role to reconcile interrupted or torn state.
func (t HostActiveControllerTarget) IsRecovery() bool {
	return t.Role == HostBootstrapRoleRecovery
}

// HostBootstrapReadOnlyOptions configures the read-only active controller
// selection and verification.
type HostBootstrapReadOnlyOptions struct {
	Root       string
	InstanceID string
	Bootstrap  *PinnedHostBootstrap
}

// OpenActiveControllerReadOnly inspects the installation slot root without
// creating directories or files, repairing torn state, or executing garbage collection.
//
// It opens the existing slot lockfile (which must already be provisioned by the installer
// or outer initialization) and acquires a non-blocking lock to guarantee that active
// controller selection and inventory verification are atomic with respect to any active
// writers. If an update writer currently holds the slot lock, it immediately returns
// ErrHostBusy.
//
// The slot lock is held across the invocation of callback and released upon return.
// The callback must only launch or pass the opened descriptor and perform pre-core
// handshakes; it MUST NOT block waiting for child processes to acquire the slot lock
// or signal VM/application readiness, as doing so would deadlock.
//
// State handling:
//   - Canonical committed state: selects verified active controller (managed or external).
//   - Absent state.json in valid empty root with existing lock: selects external bootstrap in normal role.
//   - Torn state (state.new or state.payload): selects ONLY external bootstrap in recovery role;
//     never repairs, publishes, or deletes torn files, and never selects torn candidates.
//   - Missing lock, unknown objects, or insecure file/directory permissions fail closed immediately.
func OpenActiveControllerReadOnly(
	ctx context.Context,
	opts HostBootstrapReadOnlyOptions,
	callback func(ctx context.Context, target HostActiveControllerTarget, controllerFD *os.File) error,
) error {
	if callback == nil || ctx == nil {
		return ErrInvalidOptions
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if opts.Bootstrap == nil || validateSHA256(opts.InstanceID) != nil || !filepath.IsAbs(opts.Root) {
		return ErrInvalidOptions
	}
	if filepath.Clean(opts.Root) != opts.Root {
		return ErrHostConflict
	}
	if opts.Root == opts.Bootstrap.spec.Root ||
		strings.HasPrefix(opts.Bootstrap.spec.Root, opts.Root+string(os.PathSeparator)) ||
		strings.HasPrefix(opts.Root, opts.Bootstrap.spec.Root+string(os.PathSeparator)) {
		return ErrHostConflict
	}
	real, e := filepath.EvalSymlinks(opts.Root)
	if e != nil || real != opts.Root {
		return ErrHostConflict
	}
	if e = opts.Bootstrap.verify(); e != nil {
		return e
	}

	pins, e := hostPinRoot(ctx, opts.Root)
	if e != nil {
		return e
	}
	defer func() {
		for _, f := range pins {
			f.Close()
		}
	}()

	if e = slotCheckPins(pins); e != nil {
		return e
	}

	root, e := os.OpenRoot(opts.Root)
	if e != nil {
		return e
	}
	defer root.Close()

	opened, e := root.Stat(".")
	at, ae := os.Lstat(opts.Root)
	if e != nil || ae != nil || !os.SameFile(opened, at) || at.Mode()&os.ModeSymlink != 0 {
		return ErrHostConflict
	}

	if e = slotCheckDirectory(opts.Root, true); e != nil {
		return e
	}

	// The slot lockfile MUST pre-exist (created by installer or previous initialization).
	// We open existing lock and acquire a non-blocking lock to synchronize with active writers.
	lockPath := filepath.Join(opts.Root, "lock")
	lockFile, e := driverOpenExistingLock(root, lockPath)
	if e != nil {
		// Missing lockfile means incomplete installation/state; fail closed.
		return ErrHostConflict
	}
	defer lockFile.Close()

	if e = hostCheckFile(lockFile, lockPath); e != nil {
		return e
	}

	if e = hostLockFile(lockFile); e != nil {
		// If held by active writer, returns ErrHostBusy immediately.
		return e
	}

	// Under held lock, read directory inventory.
	d, e := root.Open(".")
	if e != nil {
		return e
	}
	entries, e := d.ReadDir(-1)
	d.Close()
	if e != nil {
		return e
	}

	hasState := false
	hasNew := false
	hasPayload := false

	// Validate all inventory entries:
	// - Reject symlinks
	// - State/lock files must be regular 0600 files owned by current user
	// - Slot directories must satisfy slotCheckDirectory (0700, owned by current user)
	for _, ent := range entries {
		n := ent.Name()
		info, e := root.Lstat(n)
		if e != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrHostConflict
		}
		switch n {
		case "lock":
			// Lock file already verified above
		case "state.json":
			hasState = true
			sf, se := root.Open("state.json")
			if se != nil {
				return se
			}
			se = hostCheckFile(sf, filepath.Join(opts.Root, "state.json"))
			sf.Close()
			if se != nil {
				return se
			}
		case "state.new":
			hasNew = true
			nf, ne := root.Open("state.new")
			if ne != nil {
				return ne
			}
			ne = hostCheckFile(nf, filepath.Join(opts.Root, "state.new"))
			nf.Close()
			if ne != nil {
				return ne
			}
		case "state.payload":
			hasPayload = true
			pf, pe := root.Open("state.payload")
			if pe != nil {
				return pe
			}
			pe = hostCheckFile(pf, filepath.Join(opts.Root, "state.payload"))
			pf.Close()
			if pe != nil {
				return pe
			}
		default:
			if strings.HasPrefix(n, "slot-") && len(n) == 69 && validateSHA256(n[5:]) == nil {
				if !info.IsDir() {
					return ErrHostConflict
				}
				if e = slotCheckDirectory(filepath.Join(opts.Root, n), true); e != nil {
					return e
				}
			} else {
				// Unknown or unexpected object in slots root
				return ErrHostConflict
			}
		}
	}

	// 1. Torn state: state.new or state.payload present
	// ONLY select pinned external bootstrap C0 recovery; never select torn candidate or repair.
	if hasNew || hasPayload {
		target := HostActiveControllerTarget{
			Role:              HostBootstrapRoleRecovery,
			SlotID:            opts.Bootstrap.ID(),
			ExternalBootstrap: true,
		}
		return openExternalBootstrapControllerFD(ctx, opts.Bootstrap, target, callback)
	}

	// 2. Absent state.json: valid empty installed root with pre-created lock.
	if !hasState {
		// Only lock is allowed in empty root
		if len(entries) != 1 || entries[0].Name() != "lock" {
			return ErrHostConflict
		}
		target := HostActiveControllerTarget{
			Role:              HostBootstrapRoleNormal,
			SlotID:            opts.Bootstrap.ID(),
			ExternalBootstrap: true,
		}
		return openExternalBootstrapControllerFD(ctx, opts.Bootstrap, target, callback)
	}

	// 3. Complete canonical state.json
	info, e := root.Lstat("state.json")
	if e != nil || !info.Mode().IsRegular() || info.Size() > int64(hostStateMax) {
		return ErrHostConflict
	}
	stateFile, e := root.Open("state.json")
	if e != nil {
		return e
	}
	raw, e := io.ReadAll(io.LimitReader(stateFile, int64(hostStateMax+1)))
	stateFile.Close()
	if e != nil || len(raw) > hostStateMax {
		return ErrHostConflict
	}
	l, e := decodeSlotState(raw)
	if e != nil {
		return e
	}
	if l.InstanceID != opts.InstanceID || l.BootstrapID != opts.Bootstrap.ID() {
		return ErrHostConflict
	}

	known := map[string]bool{"lock": true, "state.json": true}
	for _, r := range l.Records {
		known[r.Directory] = true
	}
	if l.Preparing != nil {
		known[l.Preparing.Record.Directory] = true
	}
	for _, ent := range entries {
		if !known[ent.Name()] {
			return ErrHostConflict
		}
	}

	if l.Active == opts.Bootstrap.ID() {
		target := HostActiveControllerTarget{
			Role:              HostBootstrapRoleNormal,
			SlotID:            opts.Bootstrap.ID(),
			ExternalBootstrap: true,
		}
		return openExternalBootstrapControllerFD(ctx, opts.Bootstrap, target, callback)
	}

	// Managed active controller
	var activeRecord *slotRecord
	for i := range l.Records {
		if l.Records[i].ID == l.Active {
			activeRecord = &l.Records[i]
			break
		}
	}
	if activeRecord == nil || slotContains(l.Deleting, l.Active) {
		return ErrHostConflict
	}

	recDir := filepath.Join(opts.Root, activeRecord.Directory)
	key, e := hostDirectoryKey(recDir)
	if e != nil || key != activeRecord.Identity {
		return ErrHostConflict
	}
	recRoot, e := root.OpenRoot(activeRecord.Directory)
	if e != nil {
		return e
	}
	defer recRoot.Close()

	if e = slotVerifyTree(recRoot, recDir, activeRecord.Files, activeRecord.Launcher, activeRecord.Controller, activeRecord.OS, activeRecord.Architecture, true, false, nil); e != nil {
		return e
	}
	f, e := recRoot.Open(activeRecord.Controller)
	if e != nil {
		return e
	}
	defer f.Close()

	fullPath := filepath.Join(recDir, filepath.FromSlash(activeRecord.Controller))
	if e = slotCheckAsset(f, fullPath, 0755, true); e != nil {
		return e
	}
	if e = slotCPU(f, activeRecord.OS, activeRecord.Architecture); e != nil {
		return e
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}

	target := HostActiveControllerTarget{
		Role:              HostBootstrapRoleNormal,
		SlotID:            activeRecord.ID,
		ExternalBootstrap: false,
	}
	return callback(ctx, target, f)
}

// WithActiveControllerReadOnly is an alias for OpenActiveControllerReadOnly.
func WithActiveControllerReadOnly(
	ctx context.Context,
	opts HostBootstrapReadOnlyOptions,
	callback func(ctx context.Context, target HostActiveControllerTarget, controllerFD *os.File) error,
) error {
	return OpenActiveControllerReadOnly(ctx, opts, callback)
}

func openExternalBootstrapControllerFD(
	ctx context.Context,
	b *PinnedHostBootstrap,
	target HostActiveControllerTarget,
	callback func(context.Context, HostActiveControllerTarget, *os.File) error,
) error {
	if e := b.verify(); e != nil {
		return e
	}
	f, e := b.root.Open(b.spec.Controller)
	if e != nil {
		return e
	}
	defer f.Close()

	fullPath := filepath.Join(b.spec.Root, filepath.FromSlash(b.spec.Controller))
	if e = slotCheckAsset(f, fullPath, 0755, false); e != nil {
		return e
	}
	if e = slotCPU(f, b.spec.OS, b.spec.Architecture); e != nil {
		return e
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	return callback(ctx, target, f)
}
