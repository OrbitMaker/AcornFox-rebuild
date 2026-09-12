package desktopupdate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type slotRecord struct {
	ID        string            `json:"id"`
	Directory string            `json:"directory"`
	Identity  string            `json:"identity"`
	Manifest  HostBootstrapSpec `json:"manifest"`
	// Duplicated fields are deliberately avoided on disk.
	Files                                           []HostBundleFile `json:"-"`
	Launcher, Controller, OS, Architecture, Version string           `json:"-"`
}

func (r *slotRecord) expand() {
	r.Files = r.Manifest.Files
	r.Launcher = r.Manifest.Launcher
	r.Controller = r.Manifest.Controller
	r.OS = r.Manifest.OS
	r.Architecture = r.Manifest.Architecture
	r.Version = r.Manifest.Version
}

type slotPreparation struct {
	Record       slotRecord `json:"record"`
	Writing      string     `json:"writing,omitempty"`
	FileIdentity string     `json:"file_identity,omitempty"`
}
type slotLedger struct {
	Schema      int              `json:"schema"`
	Revision    uint64           `json:"revision"`
	InstanceID  string           `json:"instance_id"`
	BootstrapID string           `json:"bootstrap_id"`
	Active      string           `json:"active"`
	Records     []slotRecord     `json:"records"`
	Preparing   *slotPreparation `json:"preparing,omitempty"`
	Deleting    []string         `json:"deleting,omitempty"`
}

func (l *slotLedger) validate() error {
	if l.Schema != 1 || l.Revision == 0 || validateSHA256(l.InstanceID) != nil || validateSHA256(l.BootstrapID) != nil || validateSHA256(l.Active) != nil || len(l.Records) > 3 || len(l.Deleting) > 3 {
		return ErrHostConflict
	}
	seen := map[string]bool{l.BootstrapID: true}
	dirs := map[string]bool{}
	check := func(r *slotRecord, preparing bool) error {
		r.expand()
		if validateSHA256(r.ID) != nil || seen[r.ID] || !strings.HasPrefix(r.Directory, "slot-") || validateSHA256(strings.TrimPrefix(r.Directory, "slot-")) != nil || dirs[r.Directory] || (!preparing && r.Identity == "") || r.Manifest.Root != "" || r.OS != runtime.GOOS || r.Architecture != runtime.GOARCH || r.Manifest.ControllerProtocol != 1 || r.Manifest.InstanceProtocol != 1 || r.Manifest.BackendAPIProtocol != 1 {
			return ErrHostConflict
		}
		for _, f := range r.Files {
			if !validHostMember(f.Path) || (!strings.HasPrefix(f.Path, "launcher/") && !strings.HasPrefix(f.Path, "controller/")) {
				return ErrHostConflict
			}
		}
		if _, e := ParseSemver(r.Version); e != nil {
			return e
		}
		if slotValidateFiles(r.Files, r.Launcher, r.Controller) != nil {
			return ErrHostConflict
		}
		seen[r.ID] = true
		dirs[r.Directory] = true
		return nil
	}
	for i := range l.Records {
		if e := check(&l.Records[i], false); e != nil {
			return e
		}
	}
	if !seen[l.Active] {
		return ErrHostConflict
	}
	if p := l.Preparing; p != nil {
		if e := check(&p.Record, true); e != nil {
			return e
		}
		if (p.Writing == "") != (p.FileIdentity == "") {
			return ErrHostConflict
		}
		if p.Writing != "" {
			found := false
			for _, f := range p.Record.Files {
				if f.Path == p.Writing {
					found = true
				}
			}
			if !found || p.Record.Identity == "" {
				return ErrHostConflict
			}
		}
	}
	d := map[string]bool{}
	for _, id := range l.Deleting {
		if !seen[id] || id == l.Active || id == l.BootstrapID || d[id] {
			return ErrHostConflict
		}
		d[id] = true
	}
	return nil
}
func slotRecordFromBundle(b *VerifiedHostBundle) (slotRecord, error) {
	m := b.Manifest()
	var nonce [32]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return slotRecord{}, e
	}
	spec := HostBootstrapSpec{OS: m.OS, Architecture: m.Architecture, Version: m.Version, Launcher: m.Launcher, Controller: m.Controller, ControllerProtocol: m.ControllerProtocol, InstanceProtocol: m.InstanceProtocol, BackendAPIProtocol: m.Backend.APIProtocol}
	for _, f := range m.Files {
		if strings.HasPrefix(f.Path, "launcher/") || strings.HasPrefix(f.Path, "controller/") {
			spec.Files = append(spec.Files, f)
		}
	}
	r := slotRecord{ID: b.SHA256(), Directory: "slot-" + hex.EncodeToString(nonce[:]), Manifest: spec}
	r.expand()
	return r, slotValidateFiles(r.Files, r.Launcher, r.Controller)
}
func slotSameBundle(r slotRecord, b *VerifiedHostBundle) bool {
	n, e := slotRecordFromBundle(b)
	return e == nil && r.ID == n.ID && bytes.Equal(hostBytes(r.Manifest), hostBytes(n.Manifest))
}

type slotStore struct {
	*hostStore
	bootstrap, instance string
}

func (m *HostSlots) open(ctx context.Context) (*slotStore, slotLedger, error) {
	var l slotLedger
	p := m.options.Root
	if ctx == nil || ctx.Err() != nil || filepath.Clean(p) != p {
		return nil, l, ErrHostConflict
	}
	real, e := filepath.EvalSymlinks(p)
	if e != nil || real != p {
		return nil, l, ErrHostConflict
	}
	pins, e := hostPinRoot(ctx, p)
	if e != nil {
		return nil, l, e
	}
	s := &slotStore{hostStore: &hostStore{path: p, pins: pins, fault: m.fault}, bootstrap: m.options.Bootstrap.ID(), instance: m.options.InstanceID}
	fail := func(e error) (*slotStore, slotLedger, error) { s.close(); return nil, l, e }
	s.root, e = os.OpenRoot(p)
	if e != nil {
		return fail(e)
	}
	opened, e := s.root.Stat(".")
	at, ae := os.Lstat(p)
	if e != nil || ae != nil || !os.SameFile(opened, at) {
		return fail(ErrHostConflict)
	}
	s.lock, e = hostOpenLock(s.root, filepath.Join(p, "lock"))
	if e != nil {
		return fail(e)
	}
	if e = hostCheckFile(s.lock, filepath.Join(p, "lock")); e != nil {
		return fail(e)
	}
	if e = hostLockFile(s.lock); e != nil {
		return fail(e)
	}
	if e = hostProbeDurability(p); e != nil {
		return fail(e)
	}
	if e = s.recoverWrite(); e != nil {
		return fail(e)
	}
	raw, e := s.read("state.json", hostStateMax)
	if errors.Is(e, os.ErrNotExist) {
		l = slotLedger{Schema: 1, InstanceID: s.instance, BootstrapID: s.bootstrap, Active: s.bootstrap}
		if e = s.checkEntries(l); e != nil {
			return fail(e)
		}
		if e = s.save(&l); e != nil {
			return fail(e)
		}
	} else if e != nil {
		return fail(e)
	} else {
		l, e = decodeSlotState(raw)
		if e != nil {
			return fail(e)
		}
	}
	if l.InstanceID != s.instance || l.BootstrapID != s.bootstrap {
		return fail(ErrHostConflict)
	}
	if e = s.checkEntries(l); e != nil {
		return fail(e)
	}
	return s, l, nil
}
func (s *slotStore) checkEntries(l slotLedger) error {
	known := map[string]bool{"lock": true, "state.json": true}
	for _, r := range l.Records {
		known[r.Directory] = true
	}
	if l.Preparing != nil {
		known[l.Preparing.Record.Directory] = true
	}
	d, e := s.root.Open(".")
	if e != nil {
		return e
	}
	entries, e := d.ReadDir(-1)
	d.Close()
	if e != nil {
		return e
	}
	for _, v := range entries {
		if !known[v.Name()] {
			return ErrHostConflict
		}
	}
	return nil
}
func decodeSlotState(raw []byte) (slotLedger, error) {
	var l slotLedger
	if hostJSON(raw, &l) != nil || !bytes.Equal(raw, hostBytes(l)) || l.validate() != nil {
		return l, ErrHostConflict
	}
	return l, nil
}
func (s *slotStore) save(next *slotLedger) error {
	if slotCheckPins(s.pins) != nil || slotCheckDirectory(s.path, true) != nil {
		return ErrHostConflict
	}
	if hostCheckFile(s.lock, filepath.Join(s.path, "lock")) != nil {
		return ErrHostConflict
	}
	oldRaw, e := s.read("state.json", hostStateMax)
	oldSHA := hostStateZero
	if e == nil {
		old, e := decodeSlotState(oldRaw)
		if e != nil || old.BootstrapID != next.BootstrapID || old.InstanceID != next.InstanceID || old.Revision != next.Revision {
			return ErrHostConflict
		}
		oldSHA = hostSHA(oldRaw)
	} else if !errors.Is(e, os.ErrNotExist) || next.Revision != 0 {
		return ErrHostConflict
	}
	copy := *next
	copy.Revision++
	if copy.validate() != nil {
		return ErrHostConflict
	}
	raw := hostBytes(copy)
	if len(raw) > hostStateMax {
		return ErrHostConflict
	}
	if _, e = s.root.Lstat("state.new"); !errors.Is(e, os.ErrNotExist) {
		return ErrHostConflict
	}
	f, e := s.root.OpenFile("state.new", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	header := []byte(fmt.Sprintf("ACORNFOX-HOST-SLOTS-1\n%s\n%s\n%d\n", oldSHA, hostSHA(raw), len(raw)))
	if _, e = f.Write(header); e == nil {
		e = f.Sync()
	}
	if e == nil {
		_, e = f.Write(raw[:len(raw)/2])
	}
	if e == nil {
		e = f.Sync()
	}
	if e == nil {
		e = s.step("state-prefix")
	}
	if e == nil {
		_, e = f.Write(raw[len(raw)/2:])
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = s.step("state-staged"); e != nil {
		return e
	}
	if e = s.publishRecovered(raw); e != nil {
		return e
	}
	*next = copy
	return s.step("state-committed")
}
func (s *slotStore) recoverWrite() error {
	raw, e := s.read("state.new", hostStateMax+256)
	if errors.Is(e, os.ErrNotExist) {
		if _, err := s.root.Lstat("state.payload"); !errors.Is(err, os.ErrNotExist) {
			return ErrHostConflict
		}
		return nil
	}
	if e != nil {
		return e
	}
	parts := bytes.SplitN(raw, []byte{'\n'}, 5)
	if len(parts) != 5 || string(parts[0]) != "ACORNFOX-HOST-SLOTS-1" || validateSHA256(string(parts[1])) != nil || validateSHA256(string(parts[2])) != nil {
		return ErrHostConflict
	}
	n, e := strconv.Atoi(string(parts[3]))
	if e != nil || n < 1 || n > hostStateMax || len(parts[4]) > n {
		return ErrHostConflict
	}
	old, e := s.read("state.json", hostStateMax)
	oldSHA := hostStateZero
	if e == nil {
		if _, e := decodeSlotState(old); e != nil {
			return e
		}
		oldSHA = hostSHA(old)
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if string(parts[1]) != oldSHA {
		if oldSHA == string(parts[2]) && len(parts[4]) == n && bytes.Equal(parts[4], old) {
			if e := s.root.Remove("state.new"); e != nil {
				return e
			}
			return hostSyncDirectory(s.path)
		}
		return ErrHostConflict
	}
	if len(parts[4]) < n { // Explicit durable header authorizes discarding only this interrupted work buffer.
		if e := s.root.Remove("state.new"); e != nil {
			return e
		}
		return hostSyncDirectory(s.path)
	}
	if hostSHA(parts[4]) != string(parts[2]) {
		return ErrHostConflict
	}
	next, e := decodeSlotState(parts[4])
	if e != nil {
		return e
	}
	if oldSHA != hostStateZero {
		previous, _ := decodeSlotState(old)
		if next.Revision != previous.Revision+1 || next.InstanceID != previous.InstanceID || next.BootstrapID != previous.BootstrapID {
			return ErrHostConflict
		}
	} else if next.Revision != 1 {
		return ErrHostConflict
	}
	// The envelope header is removed before state publication; retain state.new
	// as the fixed recovery intent while writing the exact canonical payload.
	return s.publishRecovered(parts[4])
}
func (s *slotStore) publishRecovered(raw []byte) error {
	if old, e := s.read("state.payload", hostStateMax); e == nil {
		if !bytes.HasPrefix(raw, old) {
			return ErrHostConflict
		}
		if e := s.root.Remove("state.payload"); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	f, e := s.root.OpenFile("state.payload", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e := s.step("state-payload"); e != nil {
		return e
	}
	if e := slotReplacePayload(s.root, s.path); e != nil {
		return e
	}
	if e := s.step("state-published"); e != nil {
		return e
	}
	if e := s.root.Remove("state.new"); e != nil {
		return e
	}
	return hostSyncDirectory(s.path)
}

func slotCheckPins(pins []*os.File) error {
	if len(pins) == 0 {
		return ErrHostConflict
	}
	for _, f := range pins {
		info, e := f.Stat()
		actual, ae := os.Lstat(f.Name())
		if e != nil || ae != nil || !os.SameFile(info, actual) || actual.Mode()&os.ModeSymlink != 0 || slotValidatePin(f) != nil {
			return ErrHostConflict
		}
	}
	return nil
}
