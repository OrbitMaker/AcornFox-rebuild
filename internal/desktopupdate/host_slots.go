package desktopupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// BootstrapSpec is an installer-provided, independently trusted receipt. Pin
// verifies the explicitly named program/resources; it never discovers an old
// installation, modifies it, or includes it in managed collection.
type HostBootstrapSpec struct {
	Root               string           `json:"root"`
	OS                 string           `json:"os"`
	Architecture       string           `json:"arch"`
	Version            string           `json:"version"`
	Launcher           string           `json:"launcher"`
	Controller         string           `json:"controller"`
	ControllerProtocol int              `json:"controller_protocol"`
	InstanceProtocol   int              `json:"instance_protocol"`
	BackendAPIProtocol int              `json:"backend_api_protocol"`
	Files              []HostBundleFile `json:"files"`
}
type PinnedHostBootstrap struct {
	spec HostBootstrapSpec
	id   string
	root *os.Root
	pins []*os.File
}

func PinHostBootstrap(ctx context.Context, spec HostBootstrapSpec) (*PinnedHostBootstrap, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(spec.Root) || filepath.Clean(spec.Root) != spec.Root || spec.OS != runtime.GOOS || spec.Architecture != runtime.GOARCH || spec.ControllerProtocol != 1 || spec.InstanceProtocol != 1 || spec.BackendAPIProtocol != 1 {
		return nil, ErrHostConflict
	}
	if _, e := ParseSemver(spec.Version); e != nil {
		return nil, e
	}
	if e := slotValidateFiles(spec.Files, spec.Launcher, spec.Controller); e != nil {
		return nil, e
	}
	real, e := filepath.EvalSymlinks(spec.Root)
	if e != nil || real != spec.Root {
		return nil, ErrHostConflict
	}
	pins, e := slotPinExternal(ctx, spec.Root)
	if e != nil {
		return nil, e
	}
	root, e := os.OpenRoot(spec.Root)
	if e != nil {
		for _, f := range pins {
			f.Close()
		}
		return nil, e
	}
	spec.Files = append([]HostBundleFile(nil), spec.Files...)
	b := &PinnedHostBootstrap{spec: spec, id: hostSHA(append([]byte("acornfox-external-bootstrap-v1\x00"), hostBytes(spec)...)), root: root, pins: pins}
	if e := b.verify(); e != nil {
		b.Close()
		return nil, e
	}
	return b, nil
}
func (b *PinnedHostBootstrap) ID() string {
	if b == nil {
		return ""
	}
	return b.id
}
func (b *PinnedHostBootstrap) Close() error {
	if b == nil {
		return nil
	}
	for _, f := range b.pins {
		f.Close()
	}
	b.pins = nil
	if b.root != nil {
		e := b.root.Close()
		b.root = nil
		return e
	}
	return nil
}
func (b *PinnedHostBootstrap) verify() error {
	if b == nil || b.root == nil {
		return ErrHostConflict
	}
	if e := slotCheckPins(b.pins); e != nil {
		return e
	}
	return slotVerifyTree(b.root, b.spec.Root, b.spec.Files, b.spec.Launcher, b.spec.Controller, b.spec.OS, b.spec.Architecture, false, false, nil)
}

// Hooks are trusted native adapters, not an execution API. Prepare never calls
// them. No command or argv can be supplied by a bundle/JSON request.
// Stop MUST be idempotent for (instance ID, attempt ID, old slot ID): recovery
// can call it again after the old instance stopped but before the active pointer
// committed. An adapter must treat that exact old instance already being stopped
// as success, without stopping another instance or releasing unrelated resources.
// Start must be idempotent for the verified slot and this fixed installation.
type HostSlotHooks struct {
	Stop  func(context.Context, string, string, HostSlotView) error
	Start func(context.Context, string, HostSlotView) error
	Probe func(context.Context, string, HostSlotView, string) error
}

// HostSlotView is valid only during its trusted hook callback. Adapters must
// not retain paths for later execution; every start goes through Probe again.
type HostSlotView struct {
	id, version, launcher, controller string
	external                          bool
	root                              *os.Root
}

func (v HostSlotView) ID() string              { return v.id }
func (v HostSlotView) Version() string         { return v.version }
func (v HostSlotView) LauncherPath() string    { return v.launcher }
func (v HostSlotView) ControllerPath() string  { return v.controller }
func (v HostSlotView) ExternalBootstrap() bool { return v.external }

type HostSlotOptions struct {
	Root, InstanceID string
	Bootstrap        *PinnedHostBootstrap
	Hooks            HostSlotHooks
}
type HostSlots struct {
	options HostSlotOptions
	fault   func(string) error
}

var _ HostRuntime = (*HostSlots)(nil)

func NewHostSlots(o HostSlotOptions) (*HostSlots, error) {
	if validateSHA256(o.InstanceID) != nil || !filepath.IsAbs(o.Root) || o.Bootstrap == nil || o.Hooks.Stop == nil || o.Hooks.Start == nil || o.Hooks.Probe == nil {
		return nil, ErrInvalidOptions
	}
	if o.Root == o.Bootstrap.spec.Root || strings.HasPrefix(o.Bootstrap.spec.Root, o.Root+string(os.PathSeparator)) || strings.HasPrefix(o.Root, o.Bootstrap.spec.Root+string(os.PathSeparator)) {
		return nil, ErrHostConflict
	}
	if e := o.Bootstrap.verify(); e != nil {
		return nil, e
	}
	return &HostSlots{options: o}, nil
}
func (m *HostSlots) CurrentSlot(ctx context.Context) (string, error) {
	s, l, e := m.open(ctx)
	if e != nil {
		return "", e
	}
	defer s.close()
	v, close, e := m.view(s, l, l.Active)
	if e != nil {
		return "", e
	}
	defer close()
	return v.id, nil
}
func (m *HostSlots) view(s *slotStore, l slotLedger, id string) (HostSlotView, func(), error) {
	noop := func() {}
	if e := slotCheckPins(s.pins); e != nil {
		return HostSlotView{}, noop, e
	}
	if id == m.options.Bootstrap.ID() {
		b := m.options.Bootstrap
		if e := b.verify(); e != nil {
			return HostSlotView{}, noop, e
		}
		return HostSlotView{b.id, b.spec.Version, filepath.Join(b.spec.Root, filepath.FromSlash(b.spec.Launcher)), filepath.Join(b.spec.Root, filepath.FromSlash(b.spec.Controller)), true, b.root}, noop, nil
	}
	for _, r := range l.Records {
		if r.ID != id {
			continue
		}
		if slotContains(l.Deleting, id) {
			return HostSlotView{}, noop, ErrHostConflict
		}
		root, e := s.openRecord(r)
		if e != nil {
			return HostSlotView{}, noop, e
		}
		if e := slotVerifyTree(root, filepath.Join(s.path, r.Directory), r.Files, r.Launcher, r.Controller, r.OS, r.Architecture, true, false, nil); e != nil {
			root.Close()
			return HostSlotView{}, noop, e
		}
		base := filepath.Join(s.path, r.Directory)
		return HostSlotView{r.ID, r.Version, filepath.Join(base, filepath.FromSlash(r.Launcher)), filepath.Join(base, filepath.FromSlash(r.Controller)), false, root}, func() { root.Close() }, nil
	}
	return HostSlotView{}, noop, ErrHostConflict
}
func (m *HostSlots) Prepare(ctx context.Context, b *VerifiedHostBundle, old string) error {
	if b == nil || b.payload == nil || validateSHA256(b.SHA256()) != nil || verifyHostPayload(b.payload, b.payloadPath, b.artifact) != nil {
		return ErrHostConflict
	}
	manifest := b.Manifest()
	if manifest.OS != runtime.GOOS || manifest.Architecture != runtime.GOARCH || manifest.ControllerProtocol != 1 || manifest.InstanceProtocol != 1 || manifest.Backend.APIProtocol != 1 {
		return ErrHostConflict
	}
	s, l, e := m.open(ctx)
	if e != nil {
		return e
	}
	defer s.close()
	if l.Active != old || len(l.Deleting) > 0 {
		return ErrHostConflict
	}
	_, close, e := m.view(s, l, old)
	if e != nil {
		return e
	}
	close()
	for _, r := range l.Records {
		if r.ID == b.SHA256() {
			_, close, e := m.view(s, l, r.ID)
			defer close()
			return e
		}
	}
	if l.Preparing == nil {
		if len(l.Records) >= 3 {
			return ErrHostConflict
		}
		r, e := slotRecordFromBundle(b)
		if e != nil {
			return e
		}
		l.Preparing = &slotPreparation{Record: r}
		if e = s.save(&l); e != nil {
			return e
		}
	} else if l.Preparing.Record.ID != b.SHA256() || !slotSameBundle(l.Preparing.Record, b) {
		return ErrHostConflict
	}
	if e = s.prepareDirectory(&l); e != nil {
		return e
	}
	if e = s.copyBundle(ctx, &l, b); e != nil {
		return e
	}
	r := l.Preparing.Record
	root, e := s.openRecord(r)
	if e != nil {
		return e
	}
	e = slotVerifyTree(root, filepath.Join(s.path, r.Directory), r.Files, r.Launcher, r.Controller, r.OS, r.Architecture, true, false, nil)
	root.Close()
	if e != nil {
		return e
	}
	if e = s.step("slot-before-publish"); e != nil {
		return e
	}
	l.Records = append(l.Records, r)
	l.Preparing = nil
	if e = s.save(&l); e != nil {
		return e
	}
	return s.step("slot-published")
}
func (m *HostSlots) Activate(ctx context.Context, attempt, old, next string) error {
	if validateSHA256(attempt) != nil || validateSHA256(old) != nil || validateSHA256(next) != nil || old == next {
		return ErrHostConflict
	}
	s, l, e := m.open(ctx)
	if e != nil {
		return e
	}
	defer s.close()
	if l.Preparing != nil || len(l.Deleting) > 0 {
		return ErrHostConflict
	}
	if l.Active != old && l.Active != next {
		return ErrHostConflict
	}
	_, closeNext, e := m.view(s, l, next)
	if e != nil {
		return e
	}
	defer closeNext()
	if l.Active == next {
		return nil
	}
	before, closeOld, e := m.view(s, l, old)
	if e != nil {
		return e
	}
	defer closeOld()
	if e = s.step("slot-before-stop"); e != nil {
		return e
	}
	if e = m.options.Hooks.Stop(ctx, m.options.InstanceID, attempt, before); e != nil {
		return e
	}
	if e = s.step("slot-stopped"); e != nil {
		return e
	}
	// Only Stop returning successfully can authorize this pointer write. An
	// incomplete control write leaves old active; a complete write resumes next.
	l.Active = next
	if e = s.save(&l); e != nil {
		return e
	}
	return s.step("slot-activated")
}
func (m *HostSlots) Probe(ctx context.Context, id, backend string) error {
	if validateSHA256(backend) != nil {
		return ErrHostConflict
	}
	s, l, e := m.open(ctx)
	if e != nil {
		return e
	}
	defer s.close()
	if l.Active != id {
		return ErrHostConflict
	}
	v, close, e := m.view(s, l, id)
	if e != nil {
		return e
	}
	defer close()
	if e = m.options.Hooks.Start(ctx, m.options.InstanceID, v); e != nil {
		return e
	}
	// The descriptor remains pinned across both native calls. Revalidate every
	// managed byte once more before accepting the adapter's fresh readiness proof.
	check, closeCheck, e := m.view(s, l, id)
	if e != nil {
		return e
	}
	defer closeCheck()
	return m.options.Hooks.Probe(ctx, m.options.InstanceID, check, backend)
}
func (m *HostSlots) DiscardPrepared(ctx context.Context, id string) error {
	if validateSHA256(id) != nil || id == m.options.Bootstrap.ID() {
		return ErrHostConflict
	}
	s, l, e := m.open(ctx)
	if e != nil {
		return e
	}
	defer s.close()
	if l.Active == id {
		return ErrHostConflict
	}
	if len(l.Deleting) > 0 && !slotContains(l.Deleting, id) {
		return ErrHostConflict
	}
	found := false
	for _, r := range l.Records {
		if r.ID == id {
			found = true
		}
	}
	if l.Preparing != nil {
		if l.Preparing.Record.ID != id {
			return ErrHostConflict
		}
		found = true
	}
	if !found {
		return nil
	}
	if l.Preparing != nil && l.Preparing.Record.Identity == "" {
		if e = s.prepareDirectory(&l); e != nil {
			return e
		}
	}
	if len(l.Deleting) == 0 {
		if e = s.validateDeletion(l, []string{id}, false); e != nil {
			return e
		}
		l.Deleting = []string{id}
		if e = s.save(&l); e != nil {
			return e
		}
	}
	return s.deleteSlots(ctx, &l)
}
func (m *HostSlots) CollectInactive(ctx context.Context, keep []string) error {
	if len(keep) < 1 || len(keep) > 2 || keep[0] == "" {
		return ErrHostConflict
	}
	seen := map[string]bool{}
	for _, id := range keep {
		if validateSHA256(id) != nil || seen[id] {
			return ErrHostConflict
		}
		seen[id] = true
	}
	s, l, e := m.open(ctx)
	if e != nil {
		return e
	}
	defer s.close()
	if !seen[l.Active] || l.Preparing != nil {
		return ErrHostConflict
	}
	for _, id := range keep {
		_, close, e := m.view(s, l, id)
		if e != nil {
			return e
		}
		close()
	}
	if len(l.Deleting) > 0 {
		for _, id := range l.Deleting {
			if seen[id] {
				return ErrHostConflict
			}
		}
		return s.deleteSlots(ctx, &l)
	}
	for _, r := range l.Records {
		if !seen[r.ID] {
			l.Deleting = append(l.Deleting, r.ID)
		}
	}
	sort.Strings(l.Deleting)
	if len(l.Deleting) == 0 {
		return nil
	}
	if e = s.validateDeletion(l, l.Deleting, false); e != nil {
		return e
	}
	if e = s.save(&l); e != nil {
		return e
	}
	return s.deleteSlots(ctx, &l)
}
func slotContains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

var errSlotInjected = errors.New("host slot test interruption")
