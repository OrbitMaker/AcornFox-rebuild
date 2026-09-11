package desktopupdate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var ErrHostDurabilityUnavailable = errors.New("desktopupdate: host durability primitive unavailable")
var ErrHostBusy = errors.New("desktopupdate: another host update is active")

const hostStateMax = 8 << 20
const hostStateZero = "0000000000000000000000000000000000000000000000000000000000000000"

type HostInstallation struct {
	Version         string `json:"version"`
	SlotSHA256      string `json:"slot_sha256"`
	BackendBinding  string `json:"backend_binding"`
	AppliedSequence uint64 `json:"applied_sequence"`
}
type HostCatalogFloor struct {
	Sequence      uint64 `json:"sequence"`
	PayloadSHA256 string `json:"payload_sha256,omitempty"`
}
type HostFailure struct {
	Kind            string `json:"kind"`
	CandidateSHA256 string `json:"candidate_sha256"`
	FromBinding     string `json:"from_binding"`
	Reason          string `json:"reason"`
}
type HostPending struct {
	DiscardPrepared bool             `json:"discard_prepared,omitempty"`
	ID              string           `json:"id"`
	Phase           string           `json:"phase"`
	Envelope        []byte           `json:"envelope"`
	AcceptedAt      time.Time        `json:"accepted_at"`
	Candidate       CandidateResult  `json:"candidate"`
	Previous        HostInstallation `json:"previous"`
	StageIdentity   string           `json:"stage_identity,omitempty"`
}
type HostStageCleanup struct {
	ID       string `json:"id"`
	Identity string `json:"identity"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}
type HostSnapshot struct {
	PreviousSlot  string             `json:"previous_slot,omitempty"`
	CollectSlots  bool               `json:"collect_slots,omitempty"`
	Cleanup       []HostStageCleanup `json:"cleanup,omitempty"`
	SchemaVersion int                `json:"schema_version"`
	Revision      uint64             `json:"revision"`
	PolicySHA256  string             `json:"policy_sha256"`
	InstanceID    string             `json:"instance_id"`
	Catalog       HostCatalogFloor   `json:"catalog"`
	Installed     HostInstallation   `json:"installed"`
	Pending       *HostPending       `json:"pending,omitempty"`
	Failures      []HostFailure      `json:"failures,omitempty"`
	Outcome       string             `json:"outcome"`
}

func (i HostInstallation) valid() bool {
	_, e := ParseSemver(i.Version)
	return e == nil && validateSHA256(i.SlotSHA256) == nil && validateSHA256(i.BackendBinding) == nil
}
func (s HostSnapshot) validate() error {
	if s.PreviousSlot != "" && validateSHA256(s.PreviousSlot) != nil {
		return ErrHostConflict
	}
	if len(s.Cleanup) > 1 {
		return ErrHostConflict
	}
	for _, g := range s.Cleanup {
		if validateSHA256(g.ID) != nil || g.Identity == "" || validateSHA256(g.SHA256) != nil || g.Size < 1 {
			return ErrHostConflict
		}
	}
	if s.SchemaVersion != 1 || s.Revision == 0 || validateSHA256(s.PolicySHA256) != nil || validateSHA256(s.InstanceID) != nil || !s.Installed.valid() || s.Catalog.Sequence < s.Installed.AppliedSequence || len(s.Failures) > 64 {
		return ErrHostConflict
	}
	if s.Catalog.Sequence > 0 && validateSHA256(s.Catalog.PayloadSHA256) != nil {
		return ErrHostConflict
	}
	switch s.Outcome {
	case "idle", "updated", "backend-rolled-back", "host-rolled-back", "backend-rejected":
	default:
		return ErrHostConflict
	}
	for _, f := range s.Failures {
		if (f.Kind != "backend" && f.Kind != "host") || validateSHA256(f.CandidateSHA256) != nil || validateSHA256(f.FromBinding) != nil || (f.Reason != "rolled-back" && f.Reason != "rejected") {
			return ErrHostConflict
		}
	}
	if p := s.Pending; p != nil {
		if validateSHA256(p.ID) != nil || len(p.Envelope) == 0 || len(p.Envelope) > MaxIndexEnvelopeBytes || p.AcceptedAt.IsZero() || p.Candidate.Artifact == nil || validateSHA256(p.Candidate.Artifact.SHA256) != nil || validateSHA256(p.Candidate.Artifact.BackendBinding) != nil || !p.Previous.valid() || p.Candidate.Sequence != s.Catalog.Sequence {
			return ErrHostConflict
		}
		switch p.Phase {
		case "selected", "staged", "host_prepared", "backend_applying", "backend_confirmed", "host_switch", "host_trial", "host_rollback", "discarding":
		default:
			return ErrHostConflict
		}
	}
	return nil
}

type hostStore struct {
	path  string
	root  *os.Root
	lock  *os.File
	pins  []*os.File
	fault func(string) error
}

func openHostStore(ctx context.Context, p string, fault func(string) error) (*hostStore, error) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return nil, ErrHostConflict
	}
	canonical, e := filepath.EvalSymlinks(p)
	if e != nil || canonical != p {
		return nil, ErrHostConflict
	}
	pins, e := hostPinRoot(ctx, p)
	if e != nil {
		return nil, e
	}
	s := &hostStore{path: p, pins: pins, fault: fault}
	fail := func(e error) (*hostStore, error) { s.close(); return nil, e }
	s.root, e = os.OpenRoot(p)
	if e != nil {
		return fail(e)
	}
	before, e := os.Lstat(p)
	if e != nil {
		return fail(e)
	}
	opened, e := s.root.Stat(".")
	if e != nil || !os.SameFile(before, opened) {
		return fail(ErrHostConflict)
	}
	entries, e := s.root.Open(".")
	if e != nil {
		return fail(e)
	}
	names, readErr := entries.ReadDir(-1)
	entries.Close()
	if readErr != nil {
		return fail(readErr)
	}
	for _, name := range names {
		n := name.Name()
		if n != "state.json" && n != "state.new" && n != "state.payload" && n != "lock" && !hostValidStageName(n) {
			return fail(ErrHostConflict)
		}
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
	return s, nil
}
func (s *hostStore) close() {
	if s.lock != nil {
		s.lock.Close()
	}
	if s.root != nil {
		s.root.Close()
	}
	for _, f := range s.pins {
		f.Close()
	}
}
func (s *hostStore) step(name string) error {
	if s.fault != nil {
		return s.fault(name)
	}
	return nil
}
func (s *hostStore) read(name string, max int) ([]byte, error) {
	info, e := s.root.Lstat(name)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > int64(max) {
		return nil, ErrHostConflict
	}
	f, e := s.root.Open(name)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	got, e := f.Stat()
	if e != nil || !os.SameFile(info, got) || hostCheckFile(f, filepath.Join(s.path, name)) != nil {
		return nil, ErrHostConflict
	}
	raw, e := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if e != nil || len(raw) > max {
		return nil, ErrHostConflict
	}
	return raw, nil
}
func decodeHostState(raw []byte) (HostSnapshot, error) {
	var s HostSnapshot
	if hostJSON(raw, &s) != nil || !bytes.Equal(raw, hostBytes(s)) || s.validate() != nil {
		return s, ErrHostConflict
	}
	return s, nil
}
func (s *hostStore) load() (HostSnapshot, error) {
	raw, e := s.read("state.json", hostStateMax)
	if e != nil {
		return HostSnapshot{}, e
	}
	return decodeHostState(raw)
}
func (s *hostStore) save(next *HostSnapshot) error {
	if hostCheckFile(s.lock, filepath.Join(s.path, "lock")) != nil {
		return ErrHostConflict
	}
	oldRaw, e := s.read("state.json", hostStateMax)
	oldSHA := hostStateZero
	if e == nil {
		old, e := decodeHostState(oldRaw)
		if e != nil || old.PolicySHA256 != next.PolicySHA256 || old.InstanceID != next.InstanceID || old.Revision != next.Revision {
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
	header := []byte(fmt.Sprintf("ACORNFOX-HOST-STATE-1\n%s\n%s\n%d\n", oldSHA, hostSHA(raw), len(raw)))
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
func (s *hostStore) recoverWrite() error {
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
	if len(parts) != 5 || string(parts[0]) != "ACORNFOX-HOST-STATE-1" || validateSHA256(string(parts[1])) != nil || validateSHA256(string(parts[2])) != nil {
		return ErrHostConflict
	}
	n, e := strconv.Atoi(string(parts[3]))
	if e != nil || n < 1 || n > hostStateMax || len(parts[4]) > n {
		return ErrHostConflict
	}
	old, e := s.read("state.json", hostStateMax)
	oldSHA := hostStateZero
	if e == nil {
		if _, e := decodeHostState(old); e != nil {
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
	next, e := decodeHostState(parts[4])
	if e != nil {
		return e
	}
	if oldSHA != hostStateZero {
		previous, _ := decodeHostState(old)
		if next.Revision != previous.Revision+1 || next.InstanceID != previous.InstanceID || next.PolicySHA256 != previous.PolicySHA256 {
			return ErrHostConflict
		}
	} else if next.Revision != 1 {
		return ErrHostConflict
	}
	// The envelope header is removed before state publication; retain state.new
	// as the fixed recovery intent while writing the exact canonical payload.
	return s.publishRecovered(parts[4])
}
func (s *hostStore) publishRecovered(raw []byte) error {
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
	if e := hostReplacePayload(s.root, s.path); e != nil {
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
func (s *hostStore) stageName(id string) string { return "download-" + id }
func (s *hostStore) stagePath(id string) string { return filepath.Join(s.path, s.stageName(id)) }
func (s *hostStore) stageDirectory(id string) (string, error) {
	name := s.stageName(id)
	if validateSHA256(id) != nil {
		return "", ErrHostConflict
	}
	info, e := s.root.Lstat(name)
	if errors.Is(e, os.ErrNotExist) {
		if e = s.root.Mkdir(name, 0700); e != nil {
			return "", e
		}
		if e = secureNewStageDirectory(context.Background(), s.stagePath(id)); e != nil {
			return "", e
		}
		if e = hostSyncDirectory(s.path); e != nil {
			return "", e
		}
	} else if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrHostConflict
	}
	return hostDirectoryKey(s.stagePath(id))
}
func hostValidStageName(s string) bool {
	return strings.HasPrefix(s, "download-") && validateSHA256(strings.TrimPrefix(s, "download-")) == nil
}

func (HostSnapshot) Format(f fmt.State, _ rune) { fmt.Fprint(f, "host update snapshot [redacted]") }
func (HostPending) Format(f fmt.State, _ rune)  { fmt.Fprint(f, "host update pending [redacted]") }
