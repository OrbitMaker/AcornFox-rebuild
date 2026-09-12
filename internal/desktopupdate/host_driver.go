package desktopupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var ErrHostNotConfigured = errors.New("desktopupdate: host update policy is not configured")
var ErrHostPolicyMissing = errors.New("desktopupdate: policy missing for existing host update state")
var ErrHostUninitialized = errors.New("desktopupdate: no committed host update snapshot")
var ErrHostResumeUnsupported = errors.New("desktopupdate: backend does not support explicit resume")

// BackendResumer is optional. Resume wakes only the same durable backend attempt;
// it does not select a candidate, resubmit an upgrade, or prove backend success.
type BackendResumer interface {
	Resume(context.Context, HostUpgradeIntent, *VerifiedHostBundle) error
}

var _ BackendResumer = (*GuestBackend)(nil)

// ResumeBackend resolves its authority solely from the existing locked snapshot.
// Local temporary writes remain pending for explicit Advance reconciliation.
// Successful wakeup still returns ErrHostPending: only Advance's fresh backend
// observation may authorize host handoff. There are no caller-supplied IDs/paths.
func (c *HostController) ResumeBackend(ctx context.Context) (HostUpdateStatus, error) {
	s, state, e := c.openExistingDriver(ctx)
	if e != nil {
		return HostUpdateStatus{}, e
	}
	defer s.close()
	p := state.Pending
	if p == nil {
		return hostStatus(state), ErrHostConflict
	}
	if p.Phase != "backend_applying" {
		return hostStatus(state), ErrHostPending
	}
	resumer, ok := c.options.Backend.(BackendResumer)
	if !ok {
		return hostStatus(state), ErrHostResumeUnsupported
	}
	candidate, e := c.verifyPending(state, false)
	if e != nil {
		return hostStatus(state), e
	}
	if p.StageIdentity == "" {
		return hostStatus(state), ErrHostConflict
	}
	stage := s.stagePath(p.ID)
	key, e := hostDirectoryKey(stage)
	if e != nil || key != p.StageIdentity {
		return hostStatus(state), ErrHostConflict
	}
	pins, e := hostPinRoot(ctx, stage)
	if e != nil {
		return hostStatus(state), e
	}
	defer func() {
		for _, f := range pins {
			f.Close()
		}
	}()
	key, e = hostDirectoryKey(stage)
	if e != nil || key != p.StageIdentity {
		return hostStatus(state), ErrHostConflict
	}
	bundle, e := verifyHostBundle(ctx, filepath.Join(stage, StagePayloadFileName), candidate)
	if e != nil {
		return hostStatus(state), e
	}
	defer bundle.Close()
	bundle.envelope = append([]byte(nil), p.Envelope...)
	m := bundle.Manifest()
	if m.Backend.Mode != "candidate" || m.Backend.FromBinding != p.Previous.BackendBinding || m.Backend.FromBinding == m.Backend.ToBinding || m.Backend.Architecture != c.options.Policy.Arch || m.Backend.APIProtocol != 1 {
		return hostStatus(state), ErrHostConflict
	}
	if e = driverCheckPins(pins); e != nil {
		return hostStatus(state), e
	}
	intent := HostUpgradeIntent{InstanceID: state.InstanceID, AttemptID: p.ID, FromBinding: p.Previous.BackendBinding, ToBinding: m.Backend.ToBinding, ArtifactSHA256: bundle.SHA256()}
	if e = resumer.Resume(ctx, intent, bundle); e != nil {
		return hostStatus(state), e
	}
	return hostStatus(state), ErrHostPending
}

// HostStartupBasis is an opaque, short-lived lease over a committed snapshot.
// Keep it only across trusted normal startup and a fresh probe, then Close it.
// Close is idempotent; it releases pins/lock and makes all getters empty/zero.
// Context cancellation also closes the lease; Valid reports false immediately.
// The lock order is controller -> slot. Never obtain this lease inside an
// Advance/handoff hook (which already holds the controller lock), or invoke a
// controller mutation while holding it. Handoff uses its existing verified view.
//
// This is identity/protocol authority, not readiness or executable verification.
// The trusted native adapter must still verify the sealed slot before starting
// it, and must not retain getter values for execution after Close/cancellation.
// Schema-v1 committed host state uses controller/instance/backend protocol 1.
// No raw Pending, envelope, path, or user-provided binding can create this type.
type HostStartupBasis struct {
	mu                               sync.Mutex
	store                            *hostStore
	ctx                              context.Context
	stopCancel                       func() bool
	stateSHA                         string
	instance, slot, binding, version string
}

func (b *HostStartupBasis) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
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
func (b *HostStartupBasis) validLocked() bool {
	if b.store == nil || b.ctx.Err() != nil || driverCheckPins(b.store.pins) != nil || hostCheckFile(b.store.lock, filepath.Join(b.store.path, "lock")) != nil {
		return false
	}
	names, e := driverEntries(b.store)
	if e != nil || len(names) != 2 || !names["state.json"] || !names["lock"] {
		return false
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
func (b *HostStartupBasis) Valid() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.validLocked()
}
func (b *HostStartupBasis) field(selectField func(*HostStartupBasis) string) string {
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
func (b *HostStartupBasis) InstanceID() string {
	return b.field(func(b *HostStartupBasis) string { return b.instance })
}
func (b *HostStartupBasis) SlotSHA256() string {
	return b.field(func(b *HostStartupBasis) string { return b.slot })
}
func (b *HostStartupBasis) BackendBinding() string {
	return b.field(func(b *HostStartupBasis) string { return b.binding })
}
func (b *HostStartupBasis) Version() string {
	return b.field(func(b *HostStartupBasis) string { return b.version })
}
func (b *HostStartupBasis) ControllerProtocol() int {
	if b.Valid() {
		return 1
	}
	return 0
}
func (b *HostStartupBasis) InstanceProtocol() int {
	if b.Valid() {
		return 1
	}
	return 0
}
func (b *HostStartupBasis) BackendAPIProtocol() int {
	if b.Valid() {
		return 1
	}
	return 0
}
func (*HostStartupBasis) MarshalJSON() ([]byte, error) { return nil, ErrHostConflict }
func (*HostStartupBasis) UnmarshalJSON([]byte) error   { return ErrHostConflict }
func (*HostStartupBasis) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "host startup basis [opaque lease]")
}

// ReadStartupBasis never initializes or repairs state, creates a lock/directory,
// invokes backend/runtime hooks, chooses a pending slot, or probes durability.
// Missing policy is distinct from policy loss with pre-existing local evidence.
func (c *HostController) ReadStartupBasis(ctx context.Context) (*HostStartupBasis, error) {
	s, state, e := c.openExistingDriver(ctx)
	if e != nil {
		return nil, e
	}
	if state.Pending != nil || len(state.Cleanup) > 0 || state.CollectSlots {
		s.close()
		return nil, ErrHostPending
	}
	b := &HostStartupBasis{store: s, ctx: ctx, stateSHA: hostSHA(hostBytes(state)), instance: state.InstanceID, slot: state.Installed.SlotSHA256, binding: state.Installed.BackendBinding, version: state.Installed.Version}
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

// Unlike openHostStore/c.open, this opener has no creation, recovery, fsync or
// initialization path. It re-reads under an existing nonblocking lock, so a
// pre-lock snapshot disappearing can never trigger bootstrap initialization.
func (c *HostController) openExistingDriver(ctx context.Context) (*hostStore, HostSnapshot, error) {
	var state HostSnapshot
	if ctx == nil {
		return nil, state, ErrInvalidOptions
	}
	if e := ctx.Err(); e != nil {
		return nil, state, e
	}
	p := c.options.Root
	if p == "" && c.options.Policy == nil {
		return nil, state, ErrHostNotConfigured
	}
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return nil, state, ErrHostConflict
	}
	if _, e := os.Lstat(p); errors.Is(e, os.ErrNotExist) {
		if c.options.Policy == nil {
			return nil, state, ErrHostNotConfigured
		}
		return nil, state, ErrHostUninitialized
	} else if e != nil {
		return nil, state, e
	}
	real, e := filepath.EvalSymlinks(p)
	if e != nil || real != p {
		return nil, state, ErrHostConflict
	}
	pins, e := hostPinRoot(ctx, p)
	if e != nil {
		return nil, state, e
	}
	s := &hostStore{path: p, pins: pins}
	fail := func(e error) (*hostStore, HostSnapshot, error) { s.close(); return nil, state, e }
	s.root, e = os.OpenRoot(p)
	if e != nil {
		return fail(e)
	}
	if e = driverCheckPins(pins); e != nil {
		return fail(e)
	}
	info, e := s.root.Stat(".")
	at, ae := os.Lstat(p)
	if e != nil || ae != nil || !os.SameFile(info, at) {
		return fail(ErrHostConflict)
	}
	names, e := driverEntries(s)
	if e != nil {
		return fail(e)
	}
	if c.options.Policy == nil {
		if len(names) == 0 {
			return fail(ErrHostNotConfigured)
		}
		return fail(ErrHostPolicyMissing)
	}
	if !names["state.json"] {
		if names["state.new"] || names["state.payload"] {
			return fail(ErrHostPending)
		}
		for n := range names {
			if n != "lock" {
				return fail(ErrHostConflict)
			}
		}
		return fail(ErrHostUninitialized)
	}
	s.lock, e = driverOpenExistingLock(s.root, filepath.Join(p, "lock"))
	if e != nil {
		return fail(ErrHostConflict)
	}
	if e = hostCheckFile(s.lock, filepath.Join(p, "lock")); e != nil {
		return fail(e)
	}
	if e = hostLockFile(s.lock); e != nil {
		return fail(e)
	}
	names, e = driverEntries(s)
	if e != nil {
		return fail(e)
	}
	if names["state.new"] || names["state.payload"] {
		return fail(ErrHostPending)
	}
	state, e = s.load()
	if errors.Is(e, os.ErrNotExist) {
		return fail(ErrHostUninitialized)
	}
	if e != nil {
		return fail(e)
	}
	if state.InstanceID != c.options.InstanceID || state.PolicySHA256 != c.policySHA() {
		return fail(ErrHostConflict)
	}
	allowed := map[string]bool{"state.json": true, "lock": true}
	if state.Pending != nil {
		allowed[s.stageName(state.Pending.ID)] = true
	}
	for _, entry := range state.Cleanup {
		allowed[s.stageName(entry.ID)] = true
	}
	for n := range names {
		if !allowed[n] {
			return fail(ErrHostConflict)
		}
	}
	if e = driverCheckPins(pins); e != nil {
		return fail(e)
	}
	if e = ctx.Err(); e != nil {
		return fail(e)
	}
	return s, state, nil
}
func driverEntries(s *hostStore) (map[string]bool, error) {
	d, e := s.root.Open(".")
	if e != nil {
		return nil, e
	}
	entries, e := d.ReadDir(-1)
	d.Close()
	if e != nil {
		return nil, e
	}
	names := map[string]bool{}
	for _, v := range entries {
		n := v.Name()
		if n != "state.json" && n != "state.new" && n != "state.payload" && n != "lock" && !hostValidStageName(n) {
			return nil, ErrHostConflict
		}
		info, e := s.root.Lstat(n)
		if e != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrHostConflict
		}
		if hostValidStageName(n) {
			if !info.IsDir() {
				return nil, ErrHostConflict
			}
		} else if !info.Mode().IsRegular() {
			return nil, ErrHostConflict
		}
		names[n] = true
	}
	return names, nil
}
func driverCheckPins(pins []*os.File) error {
	if len(pins) == 0 {
		return ErrHostConflict
	}
	fresh, e := hostPinRoot(context.Background(), pins[len(pins)-1].Name())
	if e != nil {
		return e
	}
	defer func() {
		for _, f := range fresh {
			f.Close()
		}
	}()
	if len(fresh) != len(pins) {
		return ErrHostConflict
	}
	for i, f := range pins {
		a, e := f.Stat()
		b, be := fresh[i].Stat()
		if e != nil || be != nil || !os.SameFile(a, b) {
			return ErrHostConflict
		}
	}
	return nil
}
