//go:build linux

// Package desktopupdateguest is the fixed-policy privileged transport for the
// existing backend upgrade transaction. It never implements that transaction.
package desktopupdateguest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

var ErrConflict = errors.New("guest update: state or policy conflict")
var ErrBusy = errors.New("guest update: job requires reconciliation")
var ErrNotConfigured = errors.New("guest update: not-configured")
var ErrCapacity = errors.New("guest update: receipt retention full")
var hexID = regexp.MustCompile(`^[a-f0-9]{64}$`)

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func encoded(v any) []byte     { raw, _ := json.Marshal(v); return raw }
func decode(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || !bytes.Equal(bytes.TrimSpace(raw), encoded(v)) {
		return ErrConflict
	}
	return nil
}

// Every traversed directory must be root-owned and not writable by other users.
// Tests use a private root-owned anchor instead of the production filesystem root.
func checkParents(anchor, path string) error {
	rel, e := filepath.Rel(anchor, path)
	if e != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return ErrConflict
	}
	current := anchor
	for _, part := range append([]string{""}, strings.Split(rel, string(filepath.Separator))...) {
		if part != "" && part != "." {
			current = filepath.Join(current, part)
		}
		info, e := os.Lstat(current)
		if e != nil {
			return e
		}
		s, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || s.Uid != 0 || s.Gid != 0 {
			return ErrConflict
		}
	}
	return nil
}
func openSafe(anchor, path string, mode os.FileMode) (*os.File, error) {
	if e := checkParents(anchor, filepath.Dir(path)); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	info, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != mode || s.Uid != 0 || s.Gid != 0 || s.Nlink != 1 {
		f.Close()
		return nil, ErrConflict
	}
	return f, nil
}
func readSafe(anchor, path string, mode os.FileMode, limit int64) ([]byte, error) {
	f, e := openSafe(anchor, path, mode)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, ErrConflict
	}
	return b, nil
}
func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func writeNew(path string, raw []byte, mode os.FileMode) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if e != nil {
		return e
	}
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	return e
}
func (x *Executor) lock() (*os.File, error) {
	if e := checkParents(x.paths.anchor, x.paths.state); e != nil {
		return nil, e
	}
	p := filepath.Join(x.paths.state, "lock")
	f, e := os.OpenFile(p, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return nil, e
	}
	info, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || s.Uid != 0 || s.Gid != 0 || s.Nlink != 1 {
		f.Close()
		return nil, ErrConflict
	}
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		return nil, ErrBusy
	}
	return f, nil
}
func (x *Executor) load() (snapshot, error) {
	if e := x.verifyInstance(); e != nil {
		return snapshot{}, e
	}
	if e := x.recoverSnapshot(); e != nil {
		return snapshot{}, e
	}
	raw, e := readSafe(x.paths.anchor, filepath.Join(x.paths.state, "state.json"), 0600, 256<<10)
	if errors.Is(e, os.ErrNotExist) {
		entries, readErr := os.ReadDir(x.paths.state)
		if readErr != nil {
			return snapshot{}, readErr
		}
		for _, f := range entries {
			if f.Name() != "lock" && f.Name() != "state-quarantine" && f.Name() != "quarantine-owner.json" {
				return snapshot{}, ErrConflict
			}
		}
		s := snapshot{Schema: 1, PolicySHA: digest(encoded(x.policy)), InstanceSHA: digest(encoded(x.instance))}
		if e := x.save(s); e != nil {
			return s, e
		}
		raw, e = readSafe(x.paths.anchor, filepath.Join(x.paths.state, "state.json"), 0600, 256<<10)
	}
	if e != nil {
		return snapshot{}, e
	}
	var s snapshot
	if decode(raw, &s) != nil || x.validateSnapshot(s) != nil {
		return s, ErrConflict
	}
	return x.resumeGC(s)
}
func (x *Executor) readSnapshot() (snapshot, error) {
	raw, e := readSafe(x.paths.anchor, filepath.Join(x.paths.state, "state.json"), 0600, 256<<10)
	if e != nil {
		return snapshot{}, e
	}
	var s snapshot
	if decode(raw, &s) != nil || x.validateSnapshot(s) != nil {
		return s, ErrConflict
	}
	return s, nil
}
func (x *Executor) validateSnapshot(s snapshot) error {
	if s.Schema != 1 || s.Revision == 0 || s.PolicySHA != digest(encoded(x.policy)) || s.InstanceSHA != digest(encoded(x.instance)) || len(s.Jobs) > 32 {
		return ErrConflict
	}
	if s.Revision == 1 && s.PreviousSHA != "" || s.Revision > 1 && !hexID.MatchString(s.PreviousSHA) || s.Floor > 0 && !hexID.MatchString(s.FloorSHA) {
		return ErrConflict
	}
	seen := map[string]bool{}
	for _, j := range s.Jobs {
		if !hexID.MatchString(j.Intent.AttemptID) || seen[j.Intent.AttemptID] || j.Intent.InstanceID != x.instance.InstanceID || !hexID.MatchString(j.Intent.FromBinding) || !hexID.MatchString(j.Intent.ToBinding) || !hexID.MatchString(j.Intent.ArtifactSHA256) || !hexID.MatchString(j.EnvelopeSHA) || j.AcceptedAt.IsZero() || j.Sequence == 0 || j.Sequence > s.Floor || len(j.Reason) > 64 {
			return ErrConflict
		}
		switch j.State {
		case "queued", "running", "recovering", "upgraded", "rolled-back", "rejected", "unknown":
		default:
			return ErrConflict
		}
		seen[j.Intent.AttemptID] = true
	}
	return x.validateGC(s)
}
func snapshotTransition(old, next snapshot) bool {
	if old.GC != nil || next.GC != nil {
		if old.Revision == 0 || old.Floor != next.Floor || old.FloorSHA != next.FloorSHA {
			return false
		}
		if old.GC == nil && next.GC != nil {
			return noActive(old) && bytes.Equal(encoded(old.Jobs), encoded(next.Jobs))
		}
		if old.GC != nil && next.GC == nil {
			expected := old.Jobs
			if old.GC.Kind == "job" {
				if len(expected) == 0 {
					return false
				}
				expected = expected[1:]
			}
			if len(expected) != len(next.Jobs) {
				return false
			}
			for i := range expected {
				if !bytes.Equal(encoded(expected[i]), encoded(next.Jobs[i])) {
					return false
				}
			}
			return true
		}
		return false
	}

	if old.Revision == 0 {
		return next.Revision == 1 && next.Floor == 0 && len(next.Jobs) == 0
	}
	if len(next.Jobs) == len(old.Jobs)+1 {
		for _, j := range old.Jobs {
			if j.State == "queued" || j.State == "running" || j.State == "recovering" || j.State == "unknown" {
				return false
			}
		}
		for i := range old.Jobs {
			if !bytes.Equal(encoded(next.Jobs[i]), encoded(old.Jobs[i])) {
				return false
			}
		}
		return next.Jobs[len(old.Jobs)].Sequence == next.Floor && next.Jobs[len(old.Jobs)].State == "queued" && next.Jobs[len(old.Jobs)].Process == (processIdentity{}) && next.Floor >= old.Floor && (next.Floor != old.Floor || next.FloorSHA == old.FloorSHA)
	}
	if len(next.Jobs) != len(old.Jobs) || next.Floor != old.Floor || next.FloorSHA != old.FloorSHA {
		return false
	}
	changed := 0
	for i, a := range old.Jobs {
		b := next.Jobs[i]
		if bytes.Equal(encoded(a), encoded(b)) {
			continue
		}
		changed++
		if a.Intent != b.Intent || a.EnvelopeSHA != b.EnvelopeSHA || !a.AcceptedAt.Equal(b.AcceptedAt) || a.Sequence != b.Sequence {
			return false
		}
		switch a.State {
		case "queued":
			if b.State != "running" && b.State != "rejected" {
				return false
			}
		case "running", "recovering", "unknown":
			if b.State != "recovering" && b.State != "upgraded" && b.State != "rolled-back" && b.State != "unknown" {
				return false
			}
		default:
			return false
		}
		if b.State == "running" || b.State == "recovering" {
			if b.Process.PID < 1 || b.Process.Start == "" || b.Process.Boot == "" {
				return false
			}
		} else if b.Process != a.Process {
			return false
		}
	}
	return changed == 1
}
func (x *Executor) recoverSnapshot() error {
	if _, e := readSafe(x.paths.anchor, filepath.Join(x.paths.state, "state-quarantine"), 0600, 256<<10); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	temp := filepath.Join(x.paths.state, "state-next.json")
	raw, e := readSafe(x.paths.anchor, temp, 0600, 256<<10)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	current, e := readSafe(x.paths.anchor, filepath.Join(x.paths.state, "state.json"), 0600, 256<<10)
	var old snapshot
	if e == nil {
		if decode(current, &old) != nil || x.validateSnapshot(old) != nil {
			return ErrConflict
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	var next snapshot
	if decode(raw, &next) == nil {
		previous := ""
		if len(current) > 0 {
			previous = digest(current)
		}
		if x.validateSnapshot(next) != nil || next.Revision != old.Revision+1 || next.PreviousSHA != previous || !x.authorizedTransition(old, next) {
			return ErrConflict
		}
		if e := x.syncSafeFile(temp); e != nil {
			return e
		}
		if e := os.Rename(temp, filepath.Join(x.paths.state, "state.json")); e != nil {
			return e
		}
		return syncDir(x.paths.state)
	}
	// GC completion and owned-quarantine cleanup have an exact deterministic
	// next snapshot. Repair only a matching byte prefix, avoiding recursion in
	// the quarantine slot when its own cleanup snapshot is interrupted.
	if old.GC != nil && x.gcCompleted(old.GC) == nil {
		next := old
		if old.GC.Kind == "job" {
			next.Jobs = append([]JobReceipt(nil), old.Jobs[1:]...)
		}
		next.GC = nil
		if ok, e := x.repairKnownSnapshot(raw, current, old, next); ok || e != nil {
			return e
		}
	} else if old.GC == nil && noActive(old) {
		if g, e := x.prepareQuarantineGC(old); e == nil && g != nil {
			next := old
			next.GC = g
			if ok, e := x.repairKnownSnapshot(raw, current, old, next); ok || e != nil {
				return e
			}
		}
	}
	return x.quarantineTorn(raw, current, old)
}
func (x *Executor) save(s snapshot) error {
	p := filepath.Join(x.paths.state, "state.json")
	temp := filepath.Join(x.paths.state, "state-next.json")
	raw, e := readSafe(x.paths.anchor, p, 0600, 256<<10)
	var old snapshot
	if e == nil {
		if decode(raw, &old) != nil || x.validateSnapshot(old) != nil {
			return ErrConflict
		}
		s.Revision = old.Revision + 1
		s.PreviousSHA = digest(raw)
	} else if errors.Is(e, os.ErrNotExist) {
		s.Revision = 1
		s.PreviousSHA = ""
	} else {
		return e
	}
	if x.validateSnapshot(s) != nil || !x.authorizedTransition(old, s) {
		return ErrConflict
	}
	next := encoded(s)
	f, e := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(next[:len(next)/2])
	if e == nil && x.fault != nil {
		x.fault("snapshot-partial")
	}
	if e == nil {
		_, e = f.Write(next[len(next)/2:])
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
	if x.fault != nil {
		x.fault("snapshot-before-rename")
	}
	if e := os.Rename(temp, p); e != nil {
		return e
	}
	if x.fault != nil {
		x.fault("snapshot-after-rename")
	}
	return syncDir(x.paths.state)
}
func jobIndex(s snapshot, id string) int {
	for i := range s.Jobs {
		if s.Jobs[i].Intent.AttemptID == id {
			return i
		}
	}
	return -1
}

func (x *Executor) authorizedTransition(old, next snapshot) bool {
	if !snapshotTransition(old, next) {
		return false
	}
	if old.GC != nil && next.GC == nil {
		return x.gcCompleted(old.GC) == nil
	}
	return true
}

func (x *Executor) repairKnownSnapshot(partial, current []byte, old, next snapshot) (bool, error) {
	next.Revision = old.Revision + 1
	next.PreviousSHA = digest(current)
	if x.validateSnapshot(next) != nil || !x.authorizedTransition(old, next) {
		return false, ErrConflict
	}
	want := encoded(next)
	if len(partial) > len(want) || !bytes.Equal(partial, want[:len(partial)]) {
		return false, nil
	}
	temp := filepath.Join(x.paths.state, "state-next.json")
	if e := x.ensureExactFile(temp, want, "snapshot-repair"); e != nil {
		return true, e
	}
	if e := os.Rename(temp, filepath.Join(x.paths.state, "state.json")); e != nil {
		return true, e
	}
	return true, syncDir(x.paths.state)
}
