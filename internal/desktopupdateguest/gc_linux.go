//go:build linux

package desktopupdateguest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/open-card/open-card/internal/desktopupdate"
)

// Only full verified terminal payloads are collected. Tiny deduplication
// tombstones intentionally grow with history and are read by exact sharded ID.
type retiredJob struct {
	Schema      int    `json:"schema_version"`
	PolicySHA   string `json:"policy_sha256"`
	InstanceSHA string `json:"instance_sha256"`
	ID          string `json:"id"`
	IntentSHA   string `json:"intent_sha256"`
	EnvelopeSHA string `json:"envelope_sha256"`
	State       string `json:"state"`
	Sequence    uint64 `json:"sequence"`
}
type gcFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}
type gcDirectory struct {
	Path   string `json:"path"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}
type gcIntent struct {
	Kind        string        `json:"kind"`
	JobID       string        `json:"job_id,omitempty"`
	ReceiptSHA  string        `json:"receipt_sha256,omitempty"`
	Tombstone   *retiredJob   `json:"tombstone,omitempty"`
	Files       []gcFile      `json:"files"`
	Directories []gcDirectory `json:"directories,omitempty"`
}
type quarantineOwner struct {
	Schema      int      `json:"schema_version"`
	PolicySHA   string   `json:"policy_sha256"`
	InstanceSHA string   `json:"instance_sha256"`
	Baseline    snapshot `json:"baseline"`
	BaselineSHA string   `json:"baseline_sha256"`
	Source      gcFile   `json:"source"`
}

func terminal(state string) bool {
	return state == "upgraded" || state == "rolled-back" || state == "rejected"
}
func noActive(s snapshot) bool {
	for _, j := range s.Jobs {
		if !terminal(j.State) {
			return false
		}
	}
	return true
}
func (x *Executor) retiredPath(id string) string {
	return filepath.Join(x.paths.state, "retired", id[:2], id[2:4], id+".json")
}
func (x *Executor) readRetired(id string) (retiredJob, error) {
	var t retiredJob
	if !hexID.MatchString(id) {
		return t, ErrConflict
	}
	raw, e := readSafe(x.paths.anchor, x.retiredPath(id), 0600, 2048)
	if e != nil {
		return t, e
	}
	if decode(raw, &t) != nil || t.Schema != 1 || t.ID != id || t.PolicySHA != digest(encoded(x.policy)) || t.InstanceSHA != digest(encoded(x.instance)) || !hexID.MatchString(t.IntentSHA) || !hexID.MatchString(t.EnvelopeSHA) || !terminal(t.State) || t.Sequence == 0 {
		return t, ErrConflict
	}
	return t, nil
}
func (x *Executor) ensureRetired(t retiredJob) error {
	for _, p := range []string{filepath.Join(x.paths.state, "retired"), filepath.Dir(filepath.Dir(x.retiredPath(t.ID))), filepath.Dir(x.retiredPath(t.ID))} {
		if e := os.Mkdir(p, 0700); e != nil && !errors.Is(e, os.ErrExist) {
			return e
		}
		if e := checkParents(x.paths.anchor, p); e != nil {
			return e
		}
		if e := syncDir(filepath.Dir(p)); e != nil {
			return e
		}
	}
	return x.ensureExactFile(x.retiredPath(t.ID), encoded(t), "gc-tombstone")
}

// A partially written metadata file can only be completed from a durable
// intent's exact expected bytes; foreign bytes are never overwritten.
func (x *Executor) ensureExactFile(p string, want []byte, label string) error {
	raw, e := readSafe(x.paths.anchor, p, 0600, 512<<10)
	if e == nil {
		if len(raw) > len(want) || !bytes.Equal(raw, want[:len(raw)]) {
			return ErrConflict
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e == nil && len(raw) == len(want) {
		if e := x.syncSafeFile(p); e != nil {
			return e
		}
		return syncDir(filepath.Dir(p))
	}
	flags := os.O_WRONLY | syscall.O_NOFOLLOW
	if errors.Is(e, os.ErrNotExist) {
		flags |= os.O_CREATE | os.O_EXCL
	}
	f, e := os.OpenFile(p, flags, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e := f.Seek(int64(len(raw)), io.SeekStart); e != nil {
		return e
	}
	remaining := want[len(raw):]
	half := len(remaining) / 2
	if _, e := f.Write(remaining[:half]); e != nil {
		return e
	}
	if x.fault != nil {
		x.fault(label + "-partial")
	}
	if _, e := f.Write(remaining[half:]); e != nil {
		return e
	}
	if e := f.Sync(); e != nil {
		return e
	}
	if x.fault != nil {
		x.fault(label + "-written")
	}
	return syncDir(filepath.Dir(p))
}
func (x *Executor) fileIdentity(rel string, mode os.FileMode) (gcFile, error) {
	p := filepath.Join(x.paths.state, rel)
	f, e := openSafe(x.paths.anchor, p, mode)
	if e != nil {
		return gcFile{}, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return gcFile{}, e
	}
	s := info.Sys().(*syscall.Stat_t)
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, desktopupdate.MaxArtifactSizeBytes+1))
	if e != nil || n > desktopupdate.MaxArtifactSizeBytes {
		return gcFile{}, ErrConflict
	}
	after, e := os.Lstat(p)
	if e != nil || !os.SameFile(info, after) || after.Size() != n {
		return gcFile{}, ErrConflict
	}
	return gcFile{rel, hex.EncodeToString(h.Sum(nil)), n, uint32(mode), uint64(s.Dev), s.Ino}, nil
}
func (x *Executor) directoryIdentity(rel string) (gcDirectory, error) {
	p := filepath.Join(x.paths.state, rel)
	if e := checkParents(x.paths.anchor, p); e != nil {
		return gcDirectory{}, e
	}
	info, e := os.Lstat(p)
	if e != nil {
		return gcDirectory{}, e
	}
	if info.Mode().Perm() != 0700 {
		return gcDirectory{}, ErrConflict
	}
	s := info.Sys().(*syscall.Stat_t)
	return gcDirectory{rel, uint64(s.Dev), s.Ino}, nil
}
func (x *Executor) sameDirectory(d gcDirectory, allowMissing bool) error {
	got, e := x.directoryIdentity(d.Path)
	if allowMissing && errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if got != d {
		return ErrConflict
	}
	return nil
}
func (x *Executor) sameGCFile(f gcFile, allowMissing bool) error {
	got, e := x.fileIdentity(f.Path, os.FileMode(f.Mode))
	if allowMissing && errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if got != f {
		return ErrConflict
	}
	return nil
}
func validGCPath(p string) bool {
	return filepath.Clean(p) == p && !filepath.IsAbs(p) && !strings.HasPrefix(p, "../") && p != "." && p != ".."
}
func (x *Executor) validateGC(s snapshot) error {
	g := s.GC
	if g == nil {
		return nil
	}
	if !noActive(s) || len(g.Files) > 10 {
		return ErrConflict
	}
	seen := map[string]bool{}
	for _, f := range g.Files {
		if !validGCPath(f.Path) || !hexID.MatchString(f.SHA256) || f.Size < 0 || f.Size > desktopupdate.MaxArtifactSizeBytes || f.Device == 0 || f.Inode == 0 || (f.Mode != 0600 && f.Mode != 0644 && f.Mode != 0755) || seen[f.Path] {
			return ErrConflict
		}
		seen[f.Path] = true
	}
	switch g.Kind {
	case "job":
		if len(s.Jobs) <= 2 || len(g.Files) != 9 || len(g.Directories) != 2 || g.Tombstone == nil || g.JobID != s.Jobs[0].Intent.AttemptID || g.ReceiptSHA != digest(encoded(s.Jobs[0])) {
			return ErrConflict
		}
		j := s.Jobs[0]
		want := retiredJob{1, s.PolicySHA, s.InstanceSHA, g.JobID, digest(encoded(j.Intent)), j.EnvelopeSHA, j.State, j.Sequence}
		if *g.Tombstone != want {
			return ErrConflict
		}
		prefix := "job-" + g.JobID
		expected := map[string]bool{prefix + "/payload": true, prefix + "/envelope.json": true, prefix + "/successor": true}
		candidate := 0
		for _, f := range g.Files {
			if strings.HasPrefix(f.Path, prefix+"/candidate/") && filepath.Base(f.Path) == strings.TrimPrefix(f.Path, prefix+"/candidate/") {
				candidate++
				continue
			}
			if !expected[f.Path] {
				return ErrConflict
			}
		}
		for _, f := range g.Files {
			switch f.Path {
			case prefix + "/payload":
				if f.Mode != 0600 || f.SHA256 != j.Intent.ArtifactSHA256 {
					return ErrConflict
				}
			case prefix + "/envelope.json":
				if f.Mode != 0600 || f.SHA256 != j.EnvelopeSHA || f.Size > desktopupdate.MaxIndexEnvelopeBytes {
					return ErrConflict
				}
			case prefix + "/successor":
				if f.Mode != 0755 {
					return ErrConflict
				}
			default:
				if f.Mode != 0644 {
					return ErrConflict
				}
			}
		}
		if candidate != 6 || g.Directories[0].Path != prefix+"/candidate" || g.Directories[1].Path != prefix {
			return ErrConflict
		}
	case "quarantine":
		if g.JobID != "" || g.Tombstone != nil || g.ReceiptSHA != "" || len(g.Directories) != 0 || len(g.Files) != 2 || g.Files[0].Path != "state-quarantine" || g.Files[1].Path != "quarantine-owner.json" {
			return ErrConflict
		}
		if g.Files[0].Mode != 0600 || g.Files[1].Mode != 0600 || g.Files[0].Size > 256<<10 || g.Files[1].Size > 512<<10 {
			return ErrConflict
		}
	default:
		return ErrConflict
	}
	for _, d := range g.Directories {
		if !validGCPath(d.Path) || d.Device == 0 || d.Inode == 0 {
			return ErrConflict
		}
	}
	return nil
}
func (x *Executor) verifyGCLayout(g *gcIntent) error {
	if g.Kind == "quarantine" {
		return nil
	}
	allowed := map[string]bool{}
	for _, f := range g.Files {
		allowed[f.Path] = true
	}
	for _, d := range g.Directories {
		allowed[d.Path] = true
	}
	for _, d := range g.Directories {
		if e := x.sameDirectory(d, true); e != nil {
			return e
		}
		entries, e := os.ReadDir(filepath.Join(x.paths.state, d.Path))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		for _, entry := range entries {
			if !allowed[filepath.Join(d.Path, entry.Name())] {
				return ErrConflict
			}
		}
	}
	return nil
}
func (x *Executor) prepareJobGC(ctx context.Context, s snapshot) (*gcIntent, error) {
	if len(s.Jobs) <= 2 || !noActive(s) {
		return nil, ErrBusy
	}
	obs, e := x.backend.Observe(ctx)
	if e != nil || !eligible(obs, x.policy.HostArch) {
		return nil, ErrBusy
	}
	last := s.Jobs[len(s.Jobs)-1]
	binding := last.Intent.FromBinding
	if last.State == "upgraded" {
		binding = last.Intent.ToBinding
	}
	if obs.Binding != binding {
		return nil, ErrConflict
	}
	j := s.Jobs[0]
	dir := x.jobDir(j.Intent.AttemptID)
	envelope, e := readSafe(x.paths.anchor, filepath.Join(dir, "envelope.json"), 0600, desktopupdate.MaxIndexEnvelopeBytes)
	if e != nil || digest(envelope) != j.EnvelopeSHA {
		return nil, ErrConflict
	}
	b, e := desktopupdate.VerifyHostBundle(ctx, filepath.Join(dir, "payload"), envelope, x.options(j.AcceptedAt))
	if e != nil {
		return nil, e
	}
	defer b.Close()
	m := b.Manifest()
	if b.SHA256() != j.Intent.ArtifactSHA256 || m.Backend.FromBinding != j.Intent.FromBinding || m.Backend.ToBinding != j.Intent.ToBinding {
		return nil, ErrConflict
	}
	if e := verifyExtracted(x, b, dir); e != nil {
		return nil, e
	}
	g := &gcIntent{Kind: "job", JobID: j.Intent.AttemptID, ReceiptSHA: digest(encoded(j)), Tombstone: &retiredJob{1, s.PolicySHA, s.InstanceSHA, j.Intent.AttemptID, digest(encoded(j.Intent)), j.EnvelopeSHA, j.State, j.Sequence}}
	prefix := "job-" + j.Intent.AttemptID
	for _, entry := range m.Files {
		if strings.HasPrefix(entry.Path, "backend/candidate/") {
			f, e := x.fileIdentity(prefix+"/candidate/"+filepath.Base(entry.Path), 0644)
			if e != nil {
				return nil, e
			}
			if f.SHA256 != entry.SHA256 || f.Size != entry.Size {
				return nil, ErrConflict
			}
			g.Files = append(g.Files, f)
		}
	}
	sort.Slice(g.Files, func(i, j int) bool { return g.Files[i].Path < g.Files[j].Path })
	for _, spec := range []struct {
		name string
		mode os.FileMode
	}{{"successor", 0755}, {"envelope.json", 0600}, {"payload", 0600}} {
		f, e := x.fileIdentity(prefix+"/"+spec.name, spec.mode)
		if e != nil {
			return nil, e
		}
		if spec.name == "successor" && f.SHA256 != m.Backend.HelperSHA256 {
			return nil, ErrConflict
		}
		g.Files = append(g.Files, f)
	}
	for _, p := range []string{prefix + "/candidate", prefix} {
		d, e := x.directoryIdentity(p)
		if e != nil {
			return nil, e
		}
		g.Directories = append(g.Directories, d)
	}
	candidate := s
	candidate.GC = g
	if x.validateGC(candidate) != nil || x.verifyGCLayout(g) != nil {
		return nil, ErrConflict
	}
	return g, nil
}

// resumeGC uses only the exact durable intent. Missing entries are completed
// steps; substituted files, new children, hardlinks and symlinks stop cleanup.
func (x *Executor) resumeGC(s snapshot) (snapshot, error) {
	if s.GC == nil {
		return s, nil
	}
	g := s.GC
	if x.validateGC(s) != nil {
		return s, ErrConflict
	}
	if g.Tombstone != nil {
		if e := x.ensureRetired(*g.Tombstone); e != nil {
			return s, e
		}
	}
	if e := x.verifyGCLayout(g); e != nil {
		return s, e
	}
	for _, f := range g.Files {
		if e := x.verifyGCLayout(g); e != nil {
			return s, e
		}
		if e := x.sameGCFile(f, true); e != nil {
			return s, e
		}
		p := filepath.Join(x.paths.state, f.Path)
		if e := os.Remove(p); e != nil && !errors.Is(e, os.ErrNotExist) {
			return s, e
		}
		if x.fault != nil {
			x.fault("gc-file-removed:" + filepath.Base(f.Path))
		}
		if e := syncExistingDirectory(filepath.Dir(p)); e != nil {
			return s, e
		}
	}
	for _, d := range g.Directories {
		if e := x.sameDirectory(d, true); e != nil {
			return s, e
		}
		if e := os.Remove(filepath.Join(x.paths.state, d.Path)); e != nil && !errors.Is(e, os.ErrNotExist) {
			return s, e
		}
		if x.fault != nil {
			x.fault("gc-directory-removed:" + filepath.Base(d.Path))
		}
		if e := syncExistingDirectory(filepath.Dir(filepath.Join(x.paths.state, d.Path))); e != nil {
			return s, e
		}
	}
	if g.Kind == "job" {
		s.Jobs = append([]JobReceipt(nil), s.Jobs[1:]...)
	}
	s.GC = nil
	if e := x.save(s); e != nil {
		return s, e
	}
	if x.fault != nil {
		x.fault("gc-state-committed")
	}
	return x.readSnapshot()
}
func syncExistingDirectory(p string) error {
	e := syncDir(p)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	return e
}
func (x *Executor) gcCompleted(g *gcIntent) error {
	if g.Tombstone != nil {
		t, e := x.readRetired(g.JobID)
		if e != nil || t != *g.Tombstone {
			return ErrConflict
		}
	}
	for _, f := range g.Files {
		if _, e := os.Lstat(filepath.Join(x.paths.state, f.Path)); !errors.Is(e, os.ErrNotExist) {
			return ErrConflict
		}
	}
	for _, d := range g.Directories {
		if _, e := os.Lstat(filepath.Join(x.paths.state, d.Path)); !errors.Is(e, os.ErrNotExist) {
			return ErrConflict
		}
	}
	return nil
}
func (x *Executor) collect(ctx context.Context, s snapshot) (snapshot, error) {
	if !noActive(s) {
		return s, nil
	}
	if owner, e := x.prepareQuarantineGC(s); e != nil {
		return s, e
	} else if owner != nil {
		s.GC = owner
		if e := x.save(s); e != nil {
			return s, e
		}
		s, e = x.resumeGC(s)
		if e != nil {
			return s, e
		}
	}
	for len(s.Jobs) > 2 {
		g, e := x.prepareJobGC(ctx, s)
		if e != nil {
			return s, e
		}
		s.GC = g
		if e := x.save(s); e != nil {
			return s, e
		}
		s, e = x.resumeGC(s)
		if e != nil {
			return s, e
		}
	}
	return s, nil
}

// Collect is a fixed-scope maintenance operation; callers cannot name paths.
func (x *Executor) Collect(ctx context.Context) error {
	if e := x.verifyInstance(); e != nil {
		return e
	}
	lock, e := x.lock()
	if e != nil {
		return e
	}
	defer lock.Close()
	s, e := x.load()
	if e != nil {
		return e
	}
	_, e = x.collect(ctx, s)
	return e
}

func (x *Executor) syncSafeFile(p string) error {
	f, e := openSafe(x.paths.anchor, p, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
