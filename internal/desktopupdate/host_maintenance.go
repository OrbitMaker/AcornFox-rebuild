package desktopupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// ErrHostMaintenanceUnsupported is returned when StartMaintenance is invoked
// but no StartMaintenance hook was configured on HostSlots.
var ErrHostMaintenanceUnsupported = errors.New("desktopupdate: maintenance start hook is not configured")

// OpaqueMaintenanceSession wraps an underlying HostMaintenanceSession to prevent
// serialization and ensure safe, idempotent termination.
type OpaqueMaintenanceSession struct {
	mu      sync.Mutex
	inner   HostMaintenanceSession
	stopped bool
	closed  bool
}

func (s *OpaqueMaintenanceSession) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.stopped || s.inner == nil {
		return nil
	}
	if err := s.inner.Stop(ctx); err != nil {
		return err
	}
	s.stopped = true
	return nil
}

func (s *OpaqueMaintenanceSession) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.inner == nil {
		return nil
	}
	if err := s.inner.Close(); err != nil {
		return err
	}
	s.closed = true
	s.inner = nil
	return nil
}

func (*OpaqueMaintenanceSession) MarshalJSON() ([]byte, error) { return nil, ErrHostConflict }
func (*OpaqueMaintenanceSession) UnmarshalJSON([]byte) error   { return ErrHostConflict }
func (*OpaqueMaintenanceSession) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "host maintenance session [opaque handle]")
}

// HostMaintenanceBasis is an opaque, short-lived lease over a committed pending
// update state. It permits starting the verified active slot in a maintenance-only
// VM/SSH mode to observe or reconcile pending operations before normal startup.
//
// It exposes only instance, active slot, and protocol identities. It never exposes
// candidate paths, envelopes, or binding overrides, and cannot be serialized.
// The lease is invalidated immediately upon Close, context cancellation, or underlying
// state drift. Lock order is always Controller -> Slots.
type HostMaintenanceBasis struct {
	mu               sync.Mutex
	store            *hostStore
	ctx              context.Context
	stopCancel       func() bool
	stateSHA         string
	instance         string
	slot             string
	initialInventory map[string]string
	closed           bool
}

// Close invalidates the maintenance lease and releases the controller store lock.
func (b *HostMaintenanceBasis) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	if b.stopCancel != nil {
		b.stopCancel()
		b.stopCancel = nil
	}
	if b.store != nil {
		b.store.close()
		b.store = nil
	}
	return nil
}

func entryKey(info os.FileInfo) string {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%x-%x", st.Dev, st.Ino)
	}
	return fmt.Sprintf("%d-%d", info.Size(), info.ModTime().UnixNano())
}

func (b *HostMaintenanceBasis) validLocked() bool {
	if b.closed || b.store == nil || b.ctx.Err() != nil {
		return false
	}
	if driverCheckPins(b.store.pins) != nil || hostCheckFile(b.store.lock, filepath.Join(b.store.path, "lock")) != nil {
		return false
	}

	// Exact root inventory check: inventory must be 100% identical to initial snapshot.
	// Any newly added directory (including stage-*), deleted file, or replaced inode invalidates lease.
	d, e := b.store.root.Open(".")
	if e != nil {
		return false
	}
	entries, e := d.ReadDir(-1)
	d.Close()
	if e != nil || len(entries) != len(b.initialInventory) {
		return false
	}
	for _, ent := range entries {
		expectedKey, ok := b.initialInventory[ent.Name()]
		if !ok {
			return false
		}
		info, e := b.store.root.Lstat(ent.Name())
		if e != nil || info.Mode()&os.ModeSymlink != 0 || entryKey(info) != expectedKey {
			return false
		}
	}

	raw, e := b.store.read("state.json", hostStateMax)
	if e != nil || hostSHA(raw) != b.stateSHA {
		return false
	}
	for _, name := range []string{"state.new", "state.payload"} {
		if _, e = b.store.root.Lstat(name); !errors.Is(e, os.ErrNotExist) {
			return false
		}
	}
	return true
}

// Valid reports whether the maintenance lease remains live and uncorrupted.
// It never acquires a slot lock, preventing deadlocks when called while a slot
// lock is held.
func (b *HostMaintenanceBasis) Valid() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.validLocked()
}

func (b *HostMaintenanceBasis) field(selectField func(*HostMaintenanceBasis) string) string {
	if b == nil {
		return ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.validLocked() {
		return ""
	}
	return selectField(b)
}

// InstanceID returns the verified installation instance ID if the lease is valid.
func (b *HostMaintenanceBasis) InstanceID() string {
	return b.field(func(b *HostMaintenanceBasis) string { return b.instance })
}

// SlotSHA256 returns the verified active slot SHA256 if the lease is valid.
func (b *HostMaintenanceBasis) SlotSHA256() string {
	return b.field(func(b *HostMaintenanceBasis) string { return b.slot })
}

// ActiveSlotSHA256 is an alias for SlotSHA256.
func (b *HostMaintenanceBasis) ActiveSlotSHA256() string {
	return b.SlotSHA256()
}

// ControllerProtocol returns 1 if valid, 0 otherwise.
func (b *HostMaintenanceBasis) ControllerProtocol() int {
	if b.Valid() {
		return 1
	}
	return 0
}

// InstanceProtocol returns 1 if valid, 0 otherwise.
func (b *HostMaintenanceBasis) InstanceProtocol() int {
	if b.Valid() {
		return 1
	}
	return 0
}

// BackendAPIProtocol returns 1 if valid, 0 otherwise.
func (b *HostMaintenanceBasis) BackendAPIProtocol() int {
	if b.Valid() {
		return 1
	}
	return 0
}

func (*HostMaintenanceBasis) MarshalJSON() ([]byte, error) { return nil, ErrHostConflict }
func (*HostMaintenanceBasis) UnmarshalJSON([]byte) error   { return ErrHostConflict }
func (*HostMaintenanceBasis) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "host maintenance basis [opaque lease]")
}

// ReadMaintenanceBasis acquires an opaque, short-lived maintenance lease over a
// committed pending update state. It never initializes or repairs state, creates
// directories, or invokes mutation hooks.
//
// While holding the controller store lock, it queries the live Runtime.CurrentSlot
// and verifies that the actual active slot is consistent with the legal pendingFrom/To
// phase. Cleanup-only states and uncommitted states are rejected.
func (c *HostController) ReadMaintenanceBasis(ctx context.Context) (*HostMaintenanceBasis, error) {
	s, state, e := c.openExistingDriver(ctx)
	if e != nil {
		return nil, e
	}
	fail := func(err error) (*HostMaintenanceBasis, error) {
		s.close()
		return nil, err
	}
	if state.Pending == nil {
		return fail(ErrHostConflict)
	}
	p := state.Pending
	if c.options.Runtime == nil {
		return fail(ErrHostConflict)
	}
	if p.Candidate.Artifact == nil || validateSHA256(p.Candidate.Artifact.SHA256) != nil || validateSHA256(p.Previous.SlotSHA256) != nil {
		return fail(ErrHostConflict)
	}
	oldSlot := p.Previous.SlotSHA256
	nextSlot := p.Candidate.Artifact.SHA256

	// Lock order: Controller lock held -> call Runtime.CurrentSlot (Slots lock).
	actualSlot, e := c.options.Runtime.CurrentSlot(ctx)
	if e != nil {
		return fail(e)
	}

	// Verify actualSlot is consistent with legal pendingFrom/To phase.
	switch p.Phase {
	case "selected", "staged", "host_prepared", "backend_applying", "backend_confirmed", "discarding":
		if actualSlot != oldSlot {
			return fail(ErrHostConflict)
		}
	case "host_switch":
		if actualSlot != oldSlot && actualSlot != nextSlot {
			return fail(ErrHostConflict)
		}
	case "host_trial":
		if actualSlot != nextSlot {
			return fail(ErrHostConflict)
		}
	case "host_rollback":
		if actualSlot != oldSlot && actualSlot != nextSlot {
			return fail(ErrHostConflict)
		}
	default:
		return fail(ErrHostConflict)
	}

	// Capture exact inventory at basis construction time
	d, e := s.root.Open(".")
	if e != nil {
		return fail(e)
	}
	entries, e := d.ReadDir(-1)
	d.Close()
	if e != nil {
		return fail(e)
	}
	inventory := make(map[string]string, len(entries))
	for _, ent := range entries {
		info, e := s.root.Lstat(ent.Name())
		if e != nil || info.Mode()&os.ModeSymlink != 0 {
			return fail(ErrHostConflict)
		}
		inventory[ent.Name()] = entryKey(info)
	}

	b := &HostMaintenanceBasis{
		store:            s,
		ctx:              ctx,
		stateSHA:         hostSHA(hostBytes(state)),
		instance:         state.InstanceID,
		slot:             actualSlot,
		initialInventory: inventory,
	}
	b.mu.Lock()
	b.stopCancel = context.AfterFunc(ctx, func() { b.Close() })
	b.mu.Unlock()
	if !b.Valid() {
		b.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrHostConflict
	}
	return b, nil
}

func cleanupMaintenanceSession(session HostMaintenanceSession, cause error) (HostMaintenanceSession, error) {
	if session == nil {
		return nil, cause
	}
	wrapper, ok := session.(*OpaqueMaintenanceSession)
	if !ok {
		wrapper = &OpaqueMaintenanceSession{inner: session}
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	stopErr := wrapper.Stop(cleanupCtx)
	cancel()
	if stopErr != nil {
		// Stop failed: return opaque wrapper and joined error so caller retains ownership
		return wrapper, errors.Join(cause, stopErr)
	}
	// Stop succeeded: must call Close to release owned handle
	closeErr := wrapper.Close()
	if closeErr != nil {
		// Close failed: return opaque wrapper and joined error so caller retains ownership
		return wrapper, errors.Join(cause, closeErr)
	}
	// Full cleanup succeeded
	return nil, cause
}

// StartMaintenance starts the verified active slot using an opaque live maintenance
// basis. It verifies the view, invokes the distinct StartMaintenance hook while
// the view is pinned, reverifies the basis and view after the hook returns, and returns
// an owned maintenance session.
//
// It does not Probe the instance, claim backend readiness, or guess a backend binding.
func (m *HostSlots) StartMaintenance(ctx context.Context, basis *HostMaintenanceBasis) (HostMaintenanceSession, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrHostConflict
	}
	// Validate basis before taking Slot lock
	if basis == nil || !basis.Valid() {
		return nil, ErrHostConflict
	}
	if basis.InstanceID() != m.options.InstanceID {
		return nil, ErrHostConflict
	}
	if basis.ControllerProtocol() != 1 || basis.InstanceProtocol() != 1 || basis.BackendAPIProtocol() != 1 {
		return nil, ErrHostConflict
	}
	// Nil hook fails explicitly; don't fallback normal Start/Probe or guess backend binding
	if m.options.Hooks.StartMaintenance == nil {
		return nil, ErrHostMaintenanceUnsupported
	}

	// Take Slot lock
	s, l, e := m.open(ctx)
	if e != nil {
		return nil, e
	}
	defer s.close()

	// Recheck needed active/instance/protocol values under lock without recursive CurrentSlot call
	if !basis.Valid() || basis.InstanceID() != m.options.InstanceID || basis.SlotSHA256() != l.Active || basis.ControllerProtocol() != 1 || basis.InstanceProtocol() != 1 || basis.BackendAPIProtocol() != 1 {
		return nil, ErrHostConflict
	}

	// Existing view verification
	v, closeView, e := m.view(s, l, l.Active)
	if e != nil {
		return nil, e
	}
	defer closeView()

	// Call distinct StartMaintenance hook
	rawSession, hookErr := m.options.Hooks.StartMaintenance(ctx, m.options.InstanceID, v)
	if hookErr != nil {
		return cleanupMaintenanceSession(rawSession, hookErr)
	}
	if rawSession == nil {
		return nil, ErrHostConflict // Nil session cannot be treated as success
	}

	wrapper := &OpaqueMaintenanceSession{inner: rawSession}

	// Reverify context, basis, tuple, and view after hook returns
	var failErr error
	if ctx.Err() != nil {
		failErr = ctx.Err()
	} else if !basis.Valid() || basis.InstanceID() != m.options.InstanceID || basis.SlotSHA256() != l.Active || basis.ControllerProtocol() != 1 || basis.InstanceProtocol() != 1 || basis.BackendAPIProtocol() != 1 {
		failErr = ErrHostConflict
	} else {
		check, closeCheck, viewErr := m.view(s, l, l.Active)
		if closeCheck != nil {
			closeCheck()
		}
		if viewErr != nil || check.id != l.Active {
			failErr = ErrHostConflict
			if viewErr != nil {
				failErr = viewErr
			}
		}
	}

	if failErr != nil {
		return cleanupMaintenanceSession(wrapper, failErr)
	}

	return wrapper, nil
}

// WithMaintenanceStart is an alias for StartMaintenance.
func (m *HostSlots) WithMaintenanceStart(ctx context.Context, basis *HostMaintenanceBasis) (HostMaintenanceSession, error) {
	return m.StartMaintenance(ctx, basis)
}
