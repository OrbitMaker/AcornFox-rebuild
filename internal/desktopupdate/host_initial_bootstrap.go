package desktopupdate

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// HostInitialBootstrapOptions configures the narrow read-only initial bootstrap
// launcher selection and verification.
//
// Root paths must be pre-provisioned secure directories containing their respective
// lockfiles (mode 0600).
type HostInitialBootstrapOptions struct {
	ControllerRoot string
	SlotsRoot      string
	InstanceID     string
	Bootstrap      *PinnedHostBootstrap
}

// HostInitialBootstrapTarget carries immutable identity and protocol authority
// into the initial bootstrap launcher execution callback.
//
// It deliberately exposes no backend binding, ready state, root path, or version
// override. It cannot be serialized or deserialized into an opaque intermediate basis.
type HostInitialBootstrapTarget struct {
	InstanceID         string
	SlotSHA256         string
	ControllerProtocol int
	InstanceProtocol   int
	BackendAPIProtocol int
}

// MarshalJSON prohibits serializing the target as an opaque basis token.
func (HostInitialBootstrapTarget) MarshalJSON() ([]byte, error) {
	return nil, ErrHostConflict
}

// UnmarshalJSON prohibits deserializing into an initial bootstrap target.
func (*HostInitialBootstrapTarget) UnmarshalJSON([]byte) error {
	return ErrHostConflict
}

// OpenInitialBootstrapLauncherReadOnly provides a narrow, read-only initial launcher callback
// that is valid ONLY while the secure controller root contains only its existing lock
// and the secure slots root is lock-only or in canonical external-C0 state with no
// managed, preparing, or deleting records.
//
// Locking and verification semantics:
//   - Root directories and lockfiles must already exist (pre-provisioned by installer).
//     This function opens existing objects only; it never creates, repairs, deletes, fsyncs,
//     or writes a ledger.
//   - Locks are acquired strictly in Controller -> Slots order and held across the callback.
//     If either lock is held by another process/writer, it fails immediately with ErrHostBusy.
//   - Controller root inventory must contain only "lock". The presence of state.json,
//     torn state.new / state.payload, stages, or any unknown objects causes immediate rejection.
//   - Slots root inventory must be lock-only or canonical external-C0 state (state.json with
//     revision == 1, active == Bootstrap.ID(), matching instance ID, and empty records/preparing/deleting).
//     Any torn candidate, managed slot/record, or unknown entry causes immediate rejection.
//   - The external bootstrap launcher executable is opened through the pinned bootstrap root
//     via WithLauncherFD, holding the verified descriptor across the callback and closing it
//     immediately upon callback return.
//   - The target exposes no backend binding, ready state, root paths, or version overrides.
//
// Guarantees and boundaries:
//   - The core verifies signed-manifest hash/size and executable format; Apple code-signing
//     verification remains in the native launch layer, not this platform-neutral API.
//   - The guarantee refuses whenever controller state or evidence exists (committed state,
//     torn files, stages, or unknown objects). It does not claim to detect arbitrary manual
//     deletion of all historical files without a ledger.
//   - It does not introduce a tombstone or a second state machine; it is purely a transient
//     authority valid while controller state is absent and active is C0.
func OpenInitialBootstrapLauncherReadOnly(
	ctx context.Context,
	opts HostInitialBootstrapOptions,
	callback func(context.Context, HostInitialBootstrapTarget, *os.File) error,
) error {
	if callback == nil || ctx == nil {
		return ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts.Bootstrap == nil || validateSHA256(opts.InstanceID) != nil ||
		!filepath.IsAbs(opts.ControllerRoot) || !filepath.IsAbs(opts.SlotsRoot) {
		return ErrInvalidOptions
	}
	if filepath.Clean(opts.ControllerRoot) != opts.ControllerRoot ||
		filepath.Clean(opts.SlotsRoot) != opts.SlotsRoot {
		return ErrHostConflict
	}
	if opts.ControllerRoot == opts.SlotsRoot ||
		strings.HasPrefix(opts.ControllerRoot, opts.SlotsRoot+string(os.PathSeparator)) ||
		strings.HasPrefix(opts.SlotsRoot, opts.ControllerRoot+string(os.PathSeparator)) {
		return ErrHostConflict
	}
	if opts.ControllerRoot == opts.Bootstrap.spec.Root ||
		strings.HasPrefix(opts.Bootstrap.spec.Root, opts.ControllerRoot+string(os.PathSeparator)) ||
		strings.HasPrefix(opts.ControllerRoot, opts.Bootstrap.spec.Root+string(os.PathSeparator)) {
		return ErrHostConflict
	}
	if opts.SlotsRoot == opts.Bootstrap.spec.Root ||
		strings.HasPrefix(opts.Bootstrap.spec.Root, opts.SlotsRoot+string(os.PathSeparator)) ||
		strings.HasPrefix(opts.SlotsRoot, opts.Bootstrap.spec.Root+string(os.PathSeparator)) {
		return ErrHostConflict
	}

	realController, err := filepath.EvalSymlinks(opts.ControllerRoot)
	if err != nil || realController != opts.ControllerRoot {
		return ErrHostConflict
	}
	realSlots, err := filepath.EvalSymlinks(opts.SlotsRoot)
	if err != nil || realSlots != opts.SlotsRoot {
		return ErrHostConflict
	}

	spec := opts.Bootstrap.spec
	if spec.OS != runtime.GOOS ||
		spec.Architecture != runtime.GOARCH ||
		spec.ControllerProtocol != 1 ||
		spec.InstanceProtocol != 1 ||
		spec.BackendAPIProtocol != 1 {
		return ErrHostConflict
	}
	if err := opts.Bootstrap.verify(); err != nil {
		return err
	}

	// 1. Lock Controller root
	controllerPins, err := hostPinRoot(ctx, opts.ControllerRoot)
	if err != nil {
		return err
	}
	defer func() {
		for _, f := range controllerPins {
			f.Close()
		}
	}()

	if err := slotCheckPins(controllerPins); err != nil {
		return err
	}

	controllerRoot, err := os.OpenRoot(opts.ControllerRoot)
	if err != nil {
		return err
	}
	defer controllerRoot.Close()

	openedController, err := controllerRoot.Stat(".")
	atController, ae := os.Lstat(opts.ControllerRoot)
	if err != nil || ae != nil || !os.SameFile(openedController, atController) || atController.Mode()&os.ModeSymlink != 0 {
		return ErrHostConflict
	}

	if err := slotCheckDirectory(opts.ControllerRoot, true); err != nil {
		return err
	}

	controllerLockPath := filepath.Join(opts.ControllerRoot, "lock")
	controllerLock, err := driverOpenExistingLock(controllerRoot, controllerLockPath)
	if err != nil {
		return ErrHostConflict
	}
	defer controllerLock.Close()

	if err := hostCheckFile(controllerLock, controllerLockPath); err != nil {
		return err
	}

	if err := hostLockFile(controllerLock); err != nil {
		return err
	}

	// Under held controller lock, inspect directory inventory: must contain ONLY "lock"
	cd, err := controllerRoot.Open(".")
	if err != nil {
		return err
	}
	controllerEntries, err := cd.ReadDir(-1)
	cd.Close()
	if err != nil {
		return err
	}

	if len(controllerEntries) != 1 || controllerEntries[0].Name() != "lock" {
		return ErrHostConflict
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	if err := slotCheckPins(controllerPins); err != nil {
		return err
	}

	// 2. Lock Slots root
	slotsPins, err := hostPinRoot(ctx, opts.SlotsRoot)
	if err != nil {
		return err
	}
	defer func() {
		for _, f := range slotsPins {
			f.Close()
		}
	}()

	if err := slotCheckPins(slotsPins); err != nil {
		return err
	}

	slotsRoot, err := os.OpenRoot(opts.SlotsRoot)
	if err != nil {
		return err
	}
	defer slotsRoot.Close()

	openedSlots, err := slotsRoot.Stat(".")
	atSlots, ae := os.Lstat(opts.SlotsRoot)
	if err != nil || ae != nil || !os.SameFile(openedSlots, atSlots) || atSlots.Mode()&os.ModeSymlink != 0 {
		return ErrHostConflict
	}

	if err := slotCheckDirectory(opts.SlotsRoot, true); err != nil {
		return err
	}

	slotsLockPath := filepath.Join(opts.SlotsRoot, "lock")
	slotsLock, err := driverOpenExistingLock(slotsRoot, slotsLockPath)
	if err != nil {
		return ErrHostConflict
	}
	defer slotsLock.Close()

	if err := hostCheckFile(slotsLock, slotsLockPath); err != nil {
		return err
	}

	if err := hostLockFile(slotsLock); err != nil {
		return err
	}

	// Under held slots lock, inspect directory inventory:
	// Allowed:
	//   - "lock" only; OR
	//   - "lock" and "state.json" (canonical schema1 state, active==Bootstrap.ID(), records/preparing/deleting empty)
	sd, err := slotsRoot.Open(".")
	if err != nil {
		return err
	}
	slotsEntries, err := sd.ReadDir(-1)
	sd.Close()
	if err != nil {
		return err
	}

	hasLock := false
	hasState := false
	for _, ent := range slotsEntries {
		n := ent.Name()
		info, err := slotsRoot.Lstat(n)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrHostConflict
		}
		switch n {
		case "lock":
			hasLock = true
		case "state.json":
			hasState = true
		default:
			// Any torn candidate (state.new, state.payload), managed slots, preparing dirs, unknown files are rejected
			return ErrHostConflict
		}
	}

	if !hasLock {
		return ErrHostConflict
	}

	if hasState {
		if len(slotsEntries) != 2 {
			return ErrHostConflict
		}
		info, err := slotsRoot.Lstat("state.json")
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > int64(hostStateMax) {
			return ErrHostConflict
		}
		sf, err := slotsRoot.Open("state.json")
		if err != nil {
			return err
		}
		if err := hostCheckFile(sf, filepath.Join(opts.SlotsRoot, "state.json")); err != nil {
			sf.Close()
			return err
		}
		raw, err := io.ReadAll(io.LimitReader(sf, int64(hostStateMax+1)))
		sf.Close()
		if err != nil || len(raw) > hostStateMax {
			return ErrHostConflict
		}
		l, err := decodeSlotState(raw)
		if err != nil {
			return err
		}
		if l.Schema != 1 || l.Revision != 1 || l.InstanceID != opts.InstanceID || l.BootstrapID != opts.Bootstrap.ID() ||
			l.Active != opts.Bootstrap.ID() || len(l.Records) != 0 || l.Preparing != nil || len(l.Deleting) != 0 {
			return ErrHostConflict
		}
	} else {
		if len(slotsEntries) != 1 {
			return ErrHostConflict
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	if err := slotCheckPins(controllerPins); err != nil {
		return err
	}
	if err := slotCheckPins(slotsPins); err != nil {
		return err
	}

	// 3. Find launcher file in Bootstrap spec
	var launcherFile HostBundleFile
	for _, f := range opts.Bootstrap.spec.Files {
		if f.Path == opts.Bootstrap.spec.Launcher {
			launcherFile = f
			break
		}
	}
	if launcherFile.Path == "" {
		return ErrHostConflict
	}

	view := HostSlotView{
		id:           opts.Bootstrap.id,
		version:      opts.Bootstrap.spec.Version,
		launcher:     filepath.Join(opts.Bootstrap.spec.Root, filepath.FromSlash(opts.Bootstrap.spec.Launcher)),
		controller:   filepath.Join(opts.Bootstrap.spec.Root, filepath.FromSlash(opts.Bootstrap.spec.Controller)),
		external:     true,
		root:         opts.Bootstrap.root,
		launcherRel:  filepath.FromSlash(opts.Bootstrap.spec.Launcher),
		launcherFile: launcherFile,
		osName:       opts.Bootstrap.spec.OS,
		arch:         opts.Bootstrap.spec.Architecture,
	}

	target := HostInitialBootstrapTarget{
		InstanceID:         opts.InstanceID,
		SlotSHA256:         opts.Bootstrap.ID(),
		ControllerProtocol: 1,
		InstanceProtocol:   1,
		BackendAPIProtocol: 1,
	}

	return view.WithLauncherFD(ctx, func(launcherFD *os.File, _ HostSlotExecutableIdentity) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return callback(ctx, target, launcherFD)
	})
}

// WithInitialBootstrapLauncherReadOnly is an alias for OpenInitialBootstrapLauncherReadOnly.
func WithInitialBootstrapLauncherReadOnly(
	ctx context.Context,
	opts HostInitialBootstrapOptions,
	callback func(context.Context, HostInitialBootstrapTarget, *os.File) error,
) error {
	return OpenInitialBootstrapLauncherReadOnly(ctx, opts, callback)
}
