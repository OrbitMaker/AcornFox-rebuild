package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

var ErrUpgradeJournalConflict = errors.New("upgrade journal conflict")

const storeUpgradeInProgressPath = "upgrade-in-progress"

// pendingBootLockIdentity reserves the global upgrade flock while the boot
// barrier decides whether a marker exists. It is never persisted and is
// replaced with the marker transaction before any journal operation.
const pendingBootLockIdentity = "boot-pending-barrier"

type UpgradeStore struct {
	root             string
	lockPath         string
	production       bool
	dataWriter       *DurableWriter
	activationWriter *DurableWriter
	configDurable    *DurableWriter
	unitDurable      *DurableWriter
	edgeGID          int
	legacyVerifier   LegacyReleaseVerifier
	lock             *upgradeStoreLock
	// statusReadHook is a task-only test seam used to prove that the
	// read-only status snapshot rejects a concurrent change. Production leaves
	// it nil.
	statusReadHook func()
}

// LegacyReleaseVerifier is intentionally narrow: task tests may replace only
// immutable release evidence, never config, pointers, activation metadata, or
// systemd persistence.
type LegacyReleaseVerifier interface {
	VerifyRC0(releaseID string) (ReleaseV1, []MigrationRow, error)
	CandidateServerUnit(candidate ReleaseV1) ([]byte, error)
}

// legacyEdgeConfigVerifier binds both release templates and the candidate
// Caddy binary to their manifests. It is intentionally optional only for old
// test fakes; production always uses the fixed implementation below.
type legacyEdgeConfigVerifier interface {
	RC0EdgeTemplate(release ReleaseV1) ([]byte, error)
	CandidateEdgeConfig(candidate ReleaseV1) ([]byte, []byte, error)
}

type fixedLegacyReleaseVerifier struct {
	writer *DurableWriter
}

// secureReleaseFile opens a declared release file through a pinned root and
// validates every path component and the opened descriptor. Release evidence
// is only trusted when it is root-contained, non-writable by other users, and
// owned by the same principal that owns the upgrade store.
func secureReleaseFile(writer *DurableWriter, releaseID, name string, mode os.FileMode) ([]byte, error) {
	return secureReleaseFileWithOwnerCheck(writer, releaseID, name, mode, verifyOwner)
}

func secureReleaseFileWithOwnerCheck(writer *DurableWriter, releaseID, name string, mode os.FileMode, ownerCheck func(os.FileInfo, int, int) error) ([]byte, error) {
	if writer == nil || writer.ops == nil || !validID(releaseID) || name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name || strings.ContainsAny(name, "\\\\\x00") || ownerCheck == nil {
		return nil, ErrUpgradeJournalConflict
	}
	if err := secureReleaseParents(writer.ops, releaseID, name, writer.uid, writer.gid, ownerCheck); err != nil {
		return nil, err
	}
	leaf := filepath.ToSlash(filepath.Join("releases", releaseID, name))
	file, err := writer.ops.OpenFile(leaf, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUpgradeJournalConflict
	}
	defer writer.ops.CloseFile(file)
	if err := verifySecureReleaseLeaf(file, mode, writer.uid, writer.gid, ownerCheck); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, ErrUpgradeJournalConflict
	}
	if err := verifySecureReleaseLeaf(file, mode, writer.uid, writer.gid, ownerCheck); err != nil {
		return nil, err
	}
	return raw, nil
}

func secureReleaseParents(root durableRoot, releaseID, name string, uid, gid int, ownerCheck func(os.FileInfo, int, int) error) error {
	parents := []string{"releases", filepath.ToSlash(filepath.Join("releases", releaseID))}
	parent := filepath.Dir(filepath.FromSlash(name))
	if parent != "." {
		current := filepath.ToSlash(filepath.Join("releases", releaseID))
		for _, part := range strings.Split(filepath.ToSlash(parent), "/") {
			if part == "" || part == "." || part == ".." {
				return ErrUpgradeJournalConflict
			}
			current = filepath.ToSlash(filepath.Join(current, part))
			parents = append(parents, current)
		}
	}
	for _, parent := range parents {
		info, err := root.Lstat(parent)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || ownerCheck(info, uid, gid) != nil {
			return ErrUpgradeJournalConflict
		}
	}
	return nil
}

func verifySecureReleaseLeaf(file *os.File, mode os.FileMode, uid, gid int, ownerCheck func(os.FileInfo, int, int) error) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || ownerCheck(info, uid, gid) != nil {
		return ErrUpgradeJournalConflict
	}
	return nil
}

// verifySecureRelease replaces the legacy path-based verifier. It verifies the
// exact release tree through the same descriptor-rooted file reader used for
// manifests and service units; no path-based release helper is trusted here.
func verifySecureRelease(writer *DurableWriter, releaseID string, manifest Manifest) error {
	if writer == nil || writer.ops == nil || manifest.Validate() != nil || manifest.ReleaseID != releaseID || !validID(releaseID) {
		return ErrUpgradeJournalConflict
	}
	if err := secureReleaseParents(writer.ops, releaseID, "manifest.json", writer.uid, writer.gid, verifyOwner); err != nil {
		return err
	}
	expectedFiles := make(map[string]FileDigest, len(manifest.Files))
	expectedDirs := map[string]struct{}{"": {}}
	for _, declared := range manifest.Files {
		if _, exists := expectedFiles[declared.Path]; exists {
			return ErrUpgradeJournalConflict
		}
		expectedFiles[declared.Path] = declared
		for dir := filepath.Dir(filepath.FromSlash(declared.Path)); dir != "."; dir = filepath.Dir(dir) {
			expectedDirs[filepath.ToSlash(dir)] = struct{}{}
		}
	}
	seen := make(map[string]struct{}, len(expectedFiles))
	if err := scanSecureRelease(writer.ops, releaseID, "", expectedFiles, expectedDirs, seen, writer.uid, writer.gid); err != nil {
		return err
	}
	if len(seen) != len(expectedFiles) {
		return ErrUpgradeJournalConflict
	}
	for path, declared := range expectedFiles {
		raw, err := secureReleaseFile(writer, releaseID, path, os.FileMode(declared.Mode))
		if err != nil || sha256Bytes(raw) != declared.SHA256 {
			return ErrUpgradeJournalConflict
		}
	}
	return nil
}

func scanSecureRelease(root durableRoot, releaseID, relative string, expectedFiles map[string]FileDigest, expectedDirs map[string]struct{}, seen map[string]struct{}, uid, gid int) error {
	dir := filepath.ToSlash(filepath.Join("releases", releaseID, relative))
	if err := secureReleaseParents(root, releaseID, filepath.ToSlash(filepath.Join(relative, "probe")), uid, gid, verifyOwner); err != nil {
		return err
	}
	folder, err := root.OpenFile(dir, os.O_RDONLY, 0)
	if err != nil {
		return ErrUpgradeJournalConflict
	}
	entries, err := folder.ReadDir(-1)
	closeErr := folder.Close()
	if err != nil || closeErr != nil {
		return ErrUpgradeJournalConflict
	}
	for _, entry := range entries {
		name := entry.Name()
		child := filepath.ToSlash(filepath.Join(relative, name))
		full := filepath.ToSlash(filepath.Join("releases", releaseID, child))
		info, err := root.Lstat(full)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrUpgradeJournalConflict
		}
		if info.IsDir() {
			if _, ok := expectedDirs[child]; !ok || info.Mode().Perm()&0o022 != 0 || verifyOwner(info, uid, gid) != nil {
				return ErrUpgradeJournalConflict
			}
			if err := scanSecureRelease(root, releaseID, child, expectedFiles, expectedDirs, seen, uid, gid); err != nil {
				return err
			}
			continue
		}
		if child == "manifest.json" && relative == "" {
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 || verifyOwner(info, uid, gid) != nil {
				return ErrUpgradeJournalConflict
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return ErrUpgradeJournalConflict
		}
		if _, ok := expectedFiles[child]; !ok {
			return ErrUpgradeJournalConflict
		}
		seen[child] = struct{}{}
	}
	return nil
}

func parseReleaseManifest(raw []byte) (Manifest, error) {
	var m Manifest
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return Manifest{}, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return Manifest{}, ErrUpgradeJournalConflict
	}
	m, err := NormalizeManifest(m)
	if err != nil || m.Validate() != nil {
		return Manifest{}, ErrUpgradeJournalConflict
	}
	return m, nil
}

func (v fixedLegacyReleaseVerifier) VerifyRC0(releaseID string) (ReleaseV1, []MigrationRow, error) {
	manifestRaw, err := secureReleaseFile(v.writer, releaseID, "manifest.json", 0o644)
	manifest, err := parseReleaseManifest(manifestRaw)
	if err != nil {
		return ReleaseV1{}, nil, err
	}
	digest := sha256Bytes(manifestRaw)
	if err != nil || manifest.ReleaseID != releaseID || digest != RC0ReleaseManifestSHA256 || manifest.Version != ProductionNMinusOneVersion || manifest.SourceCommit != RC0SourceCommit || manifest.Architecture != "amd64" || manifest.MigrationVersion != "0023" || verifySecureRelease(v.writer, releaseID, manifest) != nil {
		return ReleaseV1{}, nil, ErrUpgradeJournalConflict
	}
	release := ReleaseV1{ID: manifest.ReleaseID, Version: manifest.Version, SourceCommit: manifest.SourceCommit, Architecture: manifest.Architecture, ManifestSHA256: digest}
	if !validRC0Release(release) {
		return ReleaseV1{}, nil, ErrUpgradeJournalConflict
	}
	rows, err := legacyMigrationRows(manifest)
	return release, rows, err
}
func (v fixedLegacyReleaseVerifier) CandidateServerUnit(candidate ReleaseV1) ([]byte, error) {
	manifestRaw, err := secureReleaseFile(v.writer, candidate.ID, "manifest.json", 0o644)
	manifest, err := parseReleaseManifest(manifestRaw)
	if err != nil || ValidateProductionCandidate(manifest) != nil || manifest.ReleaseID != candidate.ID || manifest.Version != candidate.Version || manifest.SourceCommit != candidate.SourceCommit || manifest.Architecture != candidate.Architecture {
		return nil, ErrUpgradeJournalConflict
	}
	d := sha256Bytes(manifestRaw)
	if d != candidate.ManifestSHA256 || verifySecureRelease(v.writer, candidate.ID, manifest) != nil {
		return nil, ErrUpgradeJournalConflict
	}
	raw, err := secureReleaseFile(v.writer, candidate.ID, "systemd/open-card-server.service", 0o644)
	if err != nil {
		return nil, err
	}
	for _, f := range manifest.Files {
		if f.Path == "systemd/open-card-server.service" && f.Mode == 0o644 && sha256Bytes(raw) == f.SHA256 {
			if validateLegacyCandidateUnit(raw) != nil {
				return nil, ErrUpgradeJournalConflict
			}
			return raw, nil
		}
	}
	return nil, ErrUpgradeJournalConflict
}

func edgeManifestFile(manifest Manifest, path string, mode uint32, raw []byte) error {
	for _, file := range manifest.Files {
		if file.Path == path && file.Mode == mode && file.SHA256 == sha256Bytes(raw) {
			return nil
		}
	}
	return ErrUpgradeJournalConflict
}

func (v fixedLegacyReleaseVerifier) RC0EdgeTemplate(release ReleaseV1) ([]byte, error) {
	if !validRC0Release(release) {
		return nil, ErrUpgradeJournalConflict
	}
	manifestRaw, err := secureReleaseFile(v.writer, release.ID, "manifest.json", 0o644)
	if err != nil {
		return nil, ErrUpgradeJournalConflict
	}
	manifest, err := parseReleaseManifest(manifestRaw)
	if err != nil || sha256Bytes(manifestRaw) != release.ManifestSHA256 || manifest.ReleaseID != release.ID || verifySecureRelease(v.writer, release.ID, manifest) != nil {
		return nil, ErrUpgradeJournalConflict
	}
	raw, err := secureReleaseFile(v.writer, release.ID, edgeTemplateRelativePath, 0o644)
	if err != nil || edgeManifestFile(manifest, edgeTemplateRelativePath, 0o644, raw) != nil {
		return nil, ErrUpgradeJournalConflict
	}
	return raw, nil
}

func (v fixedLegacyReleaseVerifier) CandidateEdgeConfig(candidate ReleaseV1) ([]byte, []byte, error) {
	manifestRaw, err := secureReleaseFile(v.writer, candidate.ID, "manifest.json", 0o644)
	if err != nil {
		return nil, nil, ErrUpgradeJournalConflict
	}
	manifest, err := parseReleaseManifest(manifestRaw)
	if err != nil || ValidateProductionCandidate(manifest) != nil || manifest.ReleaseID != candidate.ID || manifest.Version != candidate.Version || manifest.SourceCommit != candidate.SourceCommit || manifest.Architecture != candidate.Architecture || sha256Bytes(manifestRaw) != candidate.ManifestSHA256 || verifySecureRelease(v.writer, candidate.ID, manifest) != nil {
		return nil, nil, ErrUpgradeJournalConflict
	}
	template, err := secureReleaseFile(v.writer, candidate.ID, edgeTemplateRelativePath, 0o644)
	if err != nil || edgeManifestFile(manifest, edgeTemplateRelativePath, 0o644, template) != nil {
		return nil, nil, ErrUpgradeJournalConflict
	}
	caddy, err := secureReleaseFile(v.writer, candidate.ID, edgeCaddyRelativePath, 0o755)
	if err != nil || edgeManifestFile(manifest, edgeCaddyRelativePath, 0o755, caddy) != nil {
		return nil, nil, ErrUpgradeJournalConflict
	}
	return template, caddy, nil
}

type upgradeStoreLock struct {
	file  *os.File
	tx    string
	owner *UpgradeStore
}

func (l *upgradeStoreLock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	err := l.file.Close()
	if l.owner != nil && l.owner.lock == l {
		l.owner.lock = nil
	}
	return err
}

func ProductionUpgradeStore() (*UpgradeStore, error) {
	edge, err := user.LookupGroup(productionCaddyUser)
	if err != nil {
		return nil, ErrUpgradeJournalConflict
	}
	edgeGID, err := strconv.Atoi(edge.Gid)
	if err != nil || edgeGID < 0 {
		return nil, ErrUpgradeJournalConflict
	}
	d, e := ProductionDurableWriter("/var/lib/open-card")
	if e != nil {
		return nil, e
	}
	a, e := ProductionDurableWriter("/opt/open-card")
	if e != nil {
		_ = d.Close()
		return nil, e
	}
	c, e := ProductionDurableWriter("/etc/open-card")
	if e != nil {
		_ = d.Close()
		_ = a.Close()
		return nil, e
	}
	u, e := ProductionDurableWriter("/etc/systemd/system")
	if e != nil {
		_ = d.Close()
		_ = a.Close()
		_ = c.Close()
		return nil, e
	}
	return &UpgradeStore{root: "/", lockPath: "/run/lock/open-card-upgrade.lock", production: true, dataWriter: d, activationWriter: a, configDurable: c, unitDurable: u, edgeGID: edgeGID, legacyVerifier: fixedLegacyReleaseVerifier{writer: a}}, nil
}
func TaskUpgradeStore(root string, uid, gid int) (*UpgradeStore, error) {
	return TaskUpgradeStoreWithEdgeOwner(root, uid, gid, gid)
}

// TaskUpgradeStoreWithEdgeOwner is a task-only owner seam. Production never
// accepts a caller-selected Edge principal.
func TaskUpgradeStoreWithEdgeOwner(root string, uid, gid, edgeGID int) (*UpgradeStore, error) {
	if edgeGID < 0 {
		return nil, ErrUpgradeJournalConflict
	}
	if err := verifyPreparedTaskUpgradeLock(root, uid, gid); err != nil {
		return nil, err
	}
	d, e := TaskDurableWriter(filepath.Join(root, "var/lib/open-card"), uid, gid)
	if e != nil {
		return nil, e
	}
	a, e := TaskDurableWriter(filepath.Join(root, "opt/open-card"), uid, gid)
	if e != nil {
		_ = d.Close()
		return nil, e
	}
	c, e := TaskDurableWriter(filepath.Join(root, "etc/open-card"), uid, gid)
	if e != nil {
		_ = d.Close()
		_ = a.Close()
		return nil, e
	}
	u, e := TaskDurableWriter(filepath.Join(root, "etc/systemd/system"), uid, gid)
	if e != nil {
		_ = d.Close()
		_ = a.Close()
		_ = c.Close()
		return nil, e
	}
	return &UpgradeStore{root: root, lockPath: filepath.Join(root, "run/lock/open-card-upgrade.lock"), dataWriter: d, activationWriter: a, configDurable: c, unitDurable: u, edgeGID: edgeGID, legacyVerifier: fixedLegacyReleaseVerifier{writer: a}}, nil
}

// PrepareTaskUpgradeLock is the explicit task-root setup surface for tests.
// Production never calls it: a production lock must be provisioned by the
// host before any upgrade or read-only preflight is attempted.
func PrepareTaskUpgradeLock(root string, uid, gid int) error {
	if !safeAbsoluteDurableRoot(root) || uid < 0 || gid < 0 {
		return ErrUpgradeJournalConflict
	}
	if err := verifyTaskLockDirectory(root, uid, gid); err != nil {
		return err
	}
	runDir := filepath.Join(root, "run")
	if err := makeTaskLockDirectory(runDir, uid, gid); err != nil {
		return err
	}
	lockDir := filepath.Join(runDir, "lock")
	if err := makeTaskLockDirectory(lockDir, uid, gid); err != nil {
		return err
	}
	path := filepath.Join(lockDir, "open-card-upgrade.lock")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		fd, createErr := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, durableFileMode)
		if createErr != nil {
			return ErrUpgradeJournalConflict
		}
		if closeErr := syscall.Close(fd); closeErr != nil {
			return ErrUpgradeJournalConflict
		}
	} else if err != nil {
		return ErrUpgradeJournalConflict
	}
	if err := verifyLockFile(path, uid, gid); err != nil {
		return err
	}
	return nil
}

func verifyPreparedTaskUpgradeLock(root string, uid, gid int) error {
	if !safeAbsoluteDurableRoot(root) || uid < 0 || gid < 0 {
		return ErrUpgradeJournalConflict
	}
	for _, parent := range []string{root, filepath.Join(root, "run"), filepath.Join(root, "run/lock")} {
		if err := verifyTaskLockDirectory(parent, uid, gid); err != nil {
			return err
		}
	}
	return verifyLockFile(filepath.Join(root, "run/lock/open-card-upgrade.lock"), uid, gid)
}

func verifyTaskLockDirectory(path string, uid, gid int) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || verifyOwner(info, uid, gid) != nil {
		return ErrUpgradeJournalConflict
	}
	return nil
}

// /run/lock is commonly a root-owned sticky directory on Linux. The sticky
// bit prevents another principal from replacing this root-owned 0600 lock;
// rejecting that standard host layout would make the production constructor
// unusable without improving the lock-file invariant.
func verifyProductionLockDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || verifyOwner(info, 0, 0) != nil {
		return ErrUpgradeJournalConflict
	}
	if info.Mode().Perm()&0o022 != 0 && !(info.Mode()&os.ModeSticky != 0 && info.Mode().Perm() == 0o777) {
		return ErrUpgradeJournalConflict
	}
	return nil
}

func makeTaskLockDirectory(path string, uid, gid int) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, durableDirMode); err != nil {
			return ErrUpgradeJournalConflict
		}
	} else if err != nil {
		return ErrUpgradeJournalConflict
	}
	return verifyTaskLockDirectory(path, uid, gid)
}

func verifyLockFile(path string, uid, gid int) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != durableFileMode || verifyOwner(info, uid, gid) != nil {
		return ErrUpgradeJournalConflict
	}
	return nil
}

func (s *UpgradeStore) verifyLockPath() error {
	if s == nil || s.dataWriter == nil || s.lockPath == "" {
		return ErrUpgradeJournalConflict
	}
	uid, gid := s.dataWriter.uid, s.dataWriter.gid
	if s.production {
		if s.lockPath != "/run/lock/open-card-upgrade.lock" || uid != 0 || gid != 0 {
			return ErrUpgradeJournalConflict
		}
		for _, parent := range []string{"/run", "/run/lock"} {
			if err := verifyProductionLockDirectory(parent); err != nil {
				return err
			}
		}
	} else {
		if !safeAbsoluteDurableRoot(s.root) || s.lockPath != filepath.Join(s.root, "run/lock/open-card-upgrade.lock") {
			return ErrUpgradeJournalConflict
		}
		for _, parent := range []string{s.root, filepath.Join(s.root, "run"), filepath.Join(s.root, "run/lock")} {
			if err := verifyTaskLockDirectory(parent, uid, gid); err != nil {
				return err
			}
		}
	}
	return verifyLockFile(s.lockPath, uid, gid)
}

func TaskUpgradeStoreWithLegacyVerifier(root string, uid, gid int, verifier LegacyReleaseVerifier) (*UpgradeStore, error) {
	if verifier == nil {
		return nil, ErrUpgradeJournalConflict
	}
	s, err := TaskUpgradeStore(root, uid, gid)
	if err != nil {
		return nil, err
	}
	s.legacyVerifier = verifier
	return s, nil
}
func (s *UpgradeStore) journal(tx string) string {
	return filepath.ToSlash(filepath.Join("upgrade-transactions", tx+".json"))
}

func (s *UpgradeStore) Acquire(_ context.Context, tx string) (UpgradeLock, error) {
	if s == nil || !validID(tx) || s.lock != nil || s.verifyLiveRoots() != nil || s.lockPath == "" {
		return nil, ErrUpgradeJournalConflict
	}
	if err := s.verifyLockPath(); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(s.lockPath, syscall.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUpgradeJournalConflict
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil || stat.Uid != uint32(s.dataWriter.uid) || stat.Gid != uint32(s.dataWriter.gid) || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Mode&0o777 != durableFileMode {
		_ = syscall.Close(fd)
		return nil, ErrUpgradeJournalConflict
	}
	f := os.NewFile(uintptr(fd), s.lockPath)
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, ErrUpgradeLocked
	}
	lock := &upgradeStoreLock{file: f, tx: tx, owner: s}
	s.lock = lock
	return lock, nil
}

// AcquirePendingBoot makes the marker decision while owning the global
// upgrade flock.  In particular, callers must not call PendingTransaction
// and then acquire a transaction lock: an upgrade could publish its marker in
// that interval and escape the boot barrier.
func (s *UpgradeStore) AcquirePendingBoot(ctx context.Context) (UpgradeLock, PendingTransaction, error) {
	lock, err := s.Acquire(ctx, pendingBootLockIdentity)
	if err != nil {
		return nil, PendingTransaction{}, err
	}
	pending, pendingErr := s.PendingTransaction(ctx)
	if pendingErr != nil || pending.Marker != UpgradeMarkerAbsent && pending.Marker != UpgradeMarkerSame {
		if releaseErr := lock.Release(); releaseErr != nil {
			return nil, PendingTransaction{}, ErrUpgradeJournalConflict
		}
		return nil, PendingTransaction{}, ErrUpgradeJournalConflict
	}
	if pending.Marker == UpgradeMarkerSame {
		if pending.TransactionID == "" || s.lock == nil {
			if releaseErr := lock.Release(); releaseErr != nil {
				return nil, PendingTransaction{}, ErrUpgradeJournalConflict
			}
			return nil, PendingTransaction{}, ErrUpgradeJournalConflict
		}
		// Bind all following journal writes to the only transaction whose marker
		// was observed while this flock was held.
		s.lock.tx = pending.TransactionID
	}
	return lock, pending, nil
}
func (s *UpgradeStore) LoadJournal(_ context.Context, tx string) (UpgradeJournalV1, error) {
	if s == nil || !validID(tx) {
		return UpgradeJournalV1{}, ErrUpgradeJournalConflict
	}
	raw, e := s.dataWriter.ReadMetadata(s.journal(tx))
	if e != nil {
		return UpgradeJournalV1{}, e
	}
	return ParseUpgradeJournalV1(raw)
}
func (s *UpgradeStore) CreateJournal(_ context.Context, j UpgradeJournalV1) error {
	if !s.ownsLock() || s.lock.tx != j.TransactionID {
		return ErrUpgradeJournalConflict
	}
	if e := j.Validate(); e != nil {
		return e
	}
	raw, e := MarshalUpgradeJournalV1(j)
	if e != nil {
		return e
	}
	if err := s.dataWriter.CreateMetadata(s.journal(j.TransactionID), raw); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrUpgradeJournalConflict
		}
		return err
	}
	return nil
}
func (s *UpgradeStore) SaveJournal(ctx context.Context, j UpgradeJournalV1) error {
	if !s.ownsLock() || s.lock.tx != j.TransactionID {
		return ErrUpgradeJournalConflict
	}
	old, e := s.LoadJournal(ctx, j.TransactionID)
	if e != nil {
		return e
	}
	if j.Revision != old.Revision+1 || len(j.History) != len(old.History)+1 || j.History[len(old.History)].Revision != j.Revision || j.History[len(old.History)].From != old.State {
		return ErrUpgradeJournalConflict
	}
	for i := range old.History {
		if old.History[i] != j.History[i] {
			return ErrUpgradeJournalConflict
		}
	}
	raw, e := MarshalUpgradeJournalV1(j)
	if e != nil {
		return e
	}
	return s.dataWriter.WriteMetadata(s.journal(j.TransactionID), raw)
}
func (s *UpgradeStore) EnsureMarker(_ context.Context, tx string) error {
	if !validID(tx) {
		return ErrUpgradeJournalConflict
	}
	v, e := s.dataWriter.ReadMetadata(storeUpgradeInProgressPath)
	if e == nil {
		if string(v) == tx+"\n" {
			return nil
		}
		return ErrUpgradeJournalConflict
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return s.dataWriter.CreateMetadata(storeUpgradeInProgressPath, []byte(tx+"\n"))
}
func (s *UpgradeStore) Marker(ctx context.Context, set bool) error {
	if s == nil || s.lock == nil || s.lock.file == nil || s.lock.tx == "" {
		return ErrUpgradeJournalConflict
	}
	if set {
		return s.EnsureMarker(ctx, s.lock.tx)
	}
	v, e := s.dataWriter.ReadMetadata(storeUpgradeInProgressPath)
	if e != nil {
		return e
	}
	if len(v) == 0 {
		return ErrUpgradeJournalConflict
	}
	if string(v) != s.lock.tx+"\n" {
		return ErrUpgradeJournalConflict
	}
	return s.dataWriter.RemoveMetadata(storeUpgradeInProgressPath)
}
func (s *UpgradeStore) Close() error {
	if s == nil {
		return nil
	}
	lock := s.lock
	unit, config, activation, data := s.unitDurable, s.configDurable, s.activationWriter, s.dataWriter
	s.lock = nil
	s.unitDurable = nil
	s.configDurable = nil
	s.activationWriter = nil
	s.dataWriter = nil
	var first error
	if lock != nil {
		if err := lock.Release(); err != nil {
			first = err
		}
	}
	for _, writer := range []*DurableWriter{unit, config, activation, data} {
		if writer != nil {
			if err := writer.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

func (s *UpgradeStore) ReadActualState(_ context.Context, oldID, candidateID string) (UpgradeActualState, error) {
	if !s.ownsLock() || !validID(oldID) || !validID(candidateID) {
		return UpgradeActualState{}, ErrUpgradeJournalConflict
	}
	state, err := s.ReadActivationState(context.Background())
	if err != nil {
		return UpgradeActualState{}, err
	}
	marker, err := s.markerTransaction()
	if err != nil {
		return UpgradeActualState{}, err
	}
	actual := UpgradeActualState{
		ActiveID:                     state.ActiveID,
		PreviousID:                   state.PreviousID,
		MarkerTransactionID:          marker,
		PreviousActivationJSONSHA256: state.PreviousJSONSHA256,
	}
	oldDigest, oldExists, err := s.activationDigestIfPresent(oldID)
	if err != nil {
		return UpgradeActualState{}, err
	}
	candidateDigest, candidateExists, err := s.activationDigestIfPresent(candidateID)
	if err != nil {
		return UpgradeActualState{}, err
	}
	actual.OldActivationExists, actual.CandidateActivationExists = oldExists, candidateExists
	actual.OldActivationJSONSHA256, actual.CandidateActivationJSONSHA256 = oldDigest, candidateDigest
	return actual, nil
}
func (s *UpgradeStore) ReadActivationState(context.Context) (UpgradeActivationState, error) {
	if !s.ownsLock() {
		return UpgradeActivationState{}, ErrUpgradeJournalConflict
	}
	activeTarget, err := s.activationWriter.ReadActivationLink(ActivationLinkActive)
	if err != nil {
		return UpgradeActivationState{}, ErrUpgradeJournalConflict
	}
	activeID, ok := activationIDFromTarget(activeTarget)
	if !ok {
		return UpgradeActivationState{}, ErrUpgradeJournalConflict
	}
	_, activeDigest, err := s.readActivation(activeID)
	if err != nil {
		return UpgradeActivationState{}, ErrUpgradeJournalConflict
	}
	current, err := s.activationWriter.ReadActivationLink(ActivationLinkCurrent)
	if err != nil || current != "active/release" {
		return UpgradeActivationState{}, ErrUpgradeJournalConflict
	}
	state := UpgradeActivationState{ActiveID: activeID, ActiveActivationJSONSHA256: activeDigest}
	previousTarget, err := s.activationWriter.ReadActivationLink(ActivationLinkPreviousActive)
	if err == nil {
		previousID, ok := activationIDFromTarget(previousTarget)
		if !ok {
			return UpgradeActivationState{}, ErrUpgradeJournalConflict
		}
		_, previousDigest, err := s.readActivation(previousID)
		if err != nil {
			return UpgradeActivationState{}, ErrUpgradeJournalConflict
		}
		state.PreviousID, state.PreviousJSONSHA256 = previousID, previousDigest
	} else if !errors.Is(err, os.ErrNotExist) {
		return UpgradeActivationState{}, ErrUpgradeJournalConflict
	}
	marker, err := s.markerTransaction()
	if err != nil || marker != "" && marker != s.lock.tx {
		return UpgradeActivationState{}, ErrUpgradeJournalConflict
	}
	state.Marker = marker != ""
	return state, nil
}

// ReadActiveForRestore is the restore-only active slot reader. It permits no
// legacy current/server.env fallback: a restore must begin from a fully
// projected, strict activation slot whose opaque database.env is authenticated
// against activation metadata.
func (s *UpgradeStore) ReadActiveForRestore(ctx context.Context) (ExistingActivationPreflight, error) {
	if s == nil || !s.ownsLock() {
		return ExistingActivationPreflight{}, ErrUpgradeJournalConflict
	}
	state, err := s.ReadActivationState(ctx)
	if err != nil || state.Marker || !validID(state.ActiveID) || !validSHA(state.ActiveActivationJSONSHA256) {
		return ExistingActivationPreflight{}, ErrUpgradeJournalConflict
	}
	activation, digest, err := s.readActivation(state.ActiveID)
	if err != nil || digest != state.ActiveActivationJSONSHA256 || activation.LegacyProjection != nil {
		return ExistingActivationPreflight{}, ErrUpgradeJournalConflict
	}
	slot, err := s.activationSlotWriter(state.ActiveID)
	if err != nil {
		return ExistingActivationPreflight{}, ErrUpgradeJournalConflict
	}
	defer slot.Close()
	env, err := slot.ReadMetadata("database.env")
	if err != nil || sha256Bytes(env) != activation.DatabaseEnvSHA256 {
		return ExistingActivationPreflight{}, ErrUpgradeJournalConflict
	}
	if _, err := ParseDatabaseEnv(env); err != nil {
		return ExistingActivationPreflight{}, ErrUpgradeJournalConflict
	}
	return ExistingActivationPreflight{Activation: activation, JSONSHA256: digest, DatabaseEnv: append([]byte(nil), env...)}, nil
}

func (s *UpgradeStore) ownsLock() bool {
	return s != nil && s.activationWriter != nil && s.dataWriter != nil && s.lock != nil && s.lock.owner == s && s.lock.file != nil && s.lock.tx != "" && s.verifyLiveRoots() == nil
}

// verifyLiveRoots binds every privileged store action to the exact directory
// descriptors captured by the constructor. A renamed/replaced live root is a
// fail-closed conflict even though its old os.Root descriptor remains usable.
func (s *UpgradeStore) verifyLiveRoots() error {
	if s == nil || s.dataWriter == nil || s.activationWriter == nil || s.configDurable == nil || s.unitDurable == nil {
		return ErrUpgradeJournalConflict
	}
	for _, writer := range []*DurableWriter{s.dataWriter, s.activationWriter, s.configDurable, s.unitDurable} {
		if writer.VerifyLiveRoot() != nil {
			return ErrUpgradeJournalConflict
		}
	}
	return nil
}

func activationIDFromTarget(target string) (string, bool) {
	parts := strings.Split(filepath.ToSlash(target), "/")
	if len(parts) != 2 || parts[0] != "activations" || !validID(parts[1]) || target != filepath.ToSlash(filepath.Join("activations", parts[1])) {
		return "", false
	}
	return parts[1], true
}

// readActivation validates one fixed activation slot, including its secure
// metadata, database binding, typed release link, and release manifest.
func (s *UpgradeStore) readActivation(id string) (ActivationV1, string, error) {
	if s == nil || s.activationWriter == nil || !validID(id) {
		return ActivationV1{}, "", ErrUpgradeJournalConflict
	}
	slot, err := s.activationSlotWriter(id)
	if err != nil {
		return ActivationV1{}, "", err
	}
	defer slot.Close()
	raw, err := slot.ReadMetadata("activation.json")
	if err != nil {
		return ActivationV1{}, "", err
	}
	activation, err := ParseActivationV1(raw)
	if err != nil || activation.ActivationID != id {
		return ActivationV1{}, "", ErrUpgradeJournalConflict
	}
	env, err := slot.ReadMetadata("database.env")
	if err != nil {
		return ActivationV1{}, "", err
	}
	if _, err := ParseDatabaseEnv(env); err != nil || sha256Bytes(env) != activation.DatabaseEnvSHA256 {
		return ActivationV1{}, "", ErrUpgradeJournalConflict
	}
	info, err := slot.ops.Lstat("release")
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return ActivationV1{}, "", ErrUpgradeJournalConflict
	}
	target, err := slot.ops.Readlink("release")
	if err != nil || target != filepath.ToSlash(filepath.Join("..", "..", "releases", activation.Release.ID)) {
		return ActivationV1{}, "", ErrUpgradeJournalConflict
	}
	if activation.LegacyProjection == nil {
		if err := s.verifyCandidateRelease(activation); err != nil {
			return ActivationV1{}, "", err
		}
	}
	return activation, sha256Bytes(raw), nil
}

func (s *UpgradeStore) activationDigestIfPresent(id string) (string, bool, error) {
	_, digest, err := s.readActivation(id)
	if err == nil {
		return digest, true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	return "", false, err
}

func (s *UpgradeStore) markerTransaction() (string, error) {
	if s == nil || s.dataWriter == nil {
		return "", ErrUpgradeJournalConflict
	}
	raw, err := s.dataWriter.ReadMetadata(storeUpgradeInProgressPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || len(raw) == 0 || !strings.HasSuffix(string(raw), "\n") || strings.Count(string(raw), "\n") != 1 {
		return "", ErrUpgradeJournalConflict
	}
	tx := strings.TrimSuffix(string(raw), "\n")
	if !validID(tx) {
		return "", ErrUpgradeJournalConflict
	}
	return tx, nil
}

func (s *UpgradeStore) legacyCurrentPresent() bool {
	if s == nil || s.activationWriter == nil || s.activationWriter.ops == nil {
		return false
	}
	root := s.activationWriter.ops
	info, err := root.Lstat("current")
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return false
	}
	target, err := root.Readlink("current")
	if err != nil || filepath.IsAbs(target) || strings.ContainsAny(target, "\x00\\") {
		return false
	}
	parts := strings.Split(filepath.ToSlash(target), "/")
	if len(parts) != 2 || parts[0] != "releases" || !validID(parts[1]) || target != filepath.ToSlash(filepath.Join("releases", parts[1])) {
		return false
	}
	_, err = s.readLegacyServerEnv()
	return err == nil
}

// WriteCandidateActivation publishes a candidate activation only after its
// release and database identity have been bound to the durable activation
// metadata. Publication is deliberately append-only: an existing activation
// is accepted only when every persisted object is byte-for-byte equivalent.
func (s *UpgradeStore) WriteCandidateActivation(ctx context.Context, activation ActivationV1, databaseEnv []byte) (string, error) {
	if activation.Origin != "native" {
		return "", ErrUpgradeJournalConflict
	}
	return s.writeActivation(ctx, activation, databaseEnv, false)
}

// WriteRestoreActivation is the sole publication path for a restore origin.
// It shares append-only, root-contained activation publication with upgrades
// while refusing native or compatibility projection metadata.
func (s *UpgradeStore) WriteRestoreActivation(ctx context.Context, activation ActivationV1, databaseEnv []byte) (string, error) {
	if activation.Origin != "restore" || activation.RestoreSource == nil {
		return "", ErrUpgradeJournalConflict
	}
	return s.writeActivation(ctx, activation, databaseEnv, false)
}

func (s *UpgradeStore) writeActivation(_ context.Context, activation ActivationV1, databaseEnv []byte, legacy bool) (string, error) {
	if s == nil || s.activationWriter == nil || s.lock == nil || s.lock.owner != s || s.lock.file == nil || s.lock.tx != activation.CreatedByTransactionID {
		return "", ErrUpgradeJournalConflict
	}
	if legacy != (activation.Origin == "rc0_compat_projection") {
		return "", ErrUpgradeJournalConflict
	}
	if err := activation.Validate(); err != nil {
		return "", err
	}
	if _, err := ParseDatabaseEnv(databaseEnv); err != nil {
		return "", err
	}
	databaseSum := sha256.Sum256(databaseEnv)
	if hex.EncodeToString(databaseSum[:]) != activation.DatabaseEnvSHA256 {
		return "", ErrUpgradeJournalConflict
	}
	activationRaw, err := MarshalActivationV1(activation)
	if err != nil {
		return "", err
	}
	activationSum := sha256.Sum256(activationRaw)
	digest := hex.EncodeToString(activationSum[:])

	// A legacy projection records the already-verified RC0 release identity;
	// its fixed compatibility manifest digest is not the candidate's on-disk
	// manifest digest, so candidate-release verification is inapplicable.
	if !legacy {
		if err := s.verifyCandidateRelease(activation); err != nil {
			return "", err
		}
	} else {
		return s.writeLegacyActivation(activation, databaseEnv, activationRaw, digest)
	}

	created, err := s.createActivationDirectory(activation.ActivationID)
	if err != nil {
		return "", err
	}
	if !created {
		if err := s.matchExistingCandidateActivation(activation, databaseEnv, activationRaw); err != nil {
			return "", ErrUpgradeJournalConflict
		}
		return digest, nil
	}

	slot, err := s.activationSlotWriter(activation.ActivationID)
	if err != nil {
		return "", err
	}
	defer slot.Close()
	if err := slot.SwapActivationReleaseLink(activation.Release.ID); err != nil {
		if outcome := s.candidateWriteOutcome(activation, databaseEnv, activationRaw, err); outcome == nil {
			return digest, nil
		} else {
			return "", outcome
		}
	}
	if err := slot.CreateMetadata("database.env", databaseEnv); err != nil {
		if outcome := s.candidateWriteOutcome(activation, databaseEnv, activationRaw, err); outcome == nil {
			return digest, nil
		} else {
			return "", outcome
		}
	}
	if err := slot.CreateMetadata("activation.json", activationRaw); err != nil {
		if outcome := s.candidateWriteOutcome(activation, databaseEnv, activationRaw, err); outcome == nil {
			return digest, nil
		} else {
			return "", outcome
		}
	}
	// Each slot operation synchronizes its 0711 root. Also synchronize the
	// activation collection that records the newly-created directory.
	if err := s.syncActivationCollection(); err != nil {
		if outcome := s.candidateWriteOutcome(activation, databaseEnv, activationRaw, fmt.Errorf("%w: %v", ErrDurableCommitUnknown, err)); outcome == nil {
			return digest, nil
		} else {
			return "", outcome
		}
	}
	return digest, nil
}

// writeLegacyActivation is intentionally more permissive than the native
// candidate publisher only at a crash-recovery boundary. A legacy slot may
// already contain an exact prefix of the projection after a process crash;
// it is completed object-by-object and every existing object must be the
// exact immutable value. Native candidate slots remain append-only.
func (s *UpgradeStore) writeLegacyActivation(activation ActivationV1, databaseEnv, activationRaw []byte, digest string) (string, error) {
	if _, err := s.createActivationDirectory(activation.ActivationID); err != nil {
		return "", err
	}
	slot, err := s.activationSlotWriter(activation.ActivationID)
	if err != nil {
		return "", err
	}
	defer slot.Close()
	if err := ensureLegacyReleaseLink(slot, activation.Release.ID); err != nil {
		return "", err
	}
	if err := ensureLegacyMetadata(slot, "database.env", databaseEnv); err != nil {
		return "", err
	}
	if err := ensureLegacyMetadata(slot, "activation.json", activationRaw); err != nil {
		return "", err
	}
	if err := s.syncActivationCollection(); err != nil {
		return "", fmt.Errorf("%w: %v", ErrDurableCommitUnknown, err)
	}
	return digest, nil
}

func ensureLegacyReleaseLink(slot *DurableWriter, releaseID string) error {
	if slot == nil || slot.ops == nil {
		return ErrUpgradeJournalConflict
	}
	want := filepath.ToSlash(filepath.Join("..", "..", "releases", releaseID))
	info, err := slot.ops.Lstat("release")
	if errors.Is(err, os.ErrNotExist) {
		if err := slot.SwapActivationReleaseLink(releaseID); err != nil {
			return err
		}
		info, err = slot.ops.Lstat("release")
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return ErrUpgradeJournalConflict
	}
	target, err := slot.ops.Readlink("release")
	if err != nil || target != want {
		return ErrUpgradeJournalConflict
	}
	return nil
}

func ensureLegacyMetadata(slot *DurableWriter, name string, value []byte) error {
	if slot == nil {
		return ErrUpgradeJournalConflict
	}
	existing, err := slot.ReadMetadata(name)
	if err == nil {
		if !bytes.Equal(existing, value) {
			return ErrUpgradeJournalConflict
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ErrUpgradeJournalConflict
	}
	if err := slot.CreateMetadata(name, value); err == nil {
		return nil
	}
	// A rename/link plus parent-fsync ambiguity may have published the exact
	// object. Re-read only through the same pinned slot root before deciding.
	existing, err = slot.ReadMetadata(name)
	if err != nil || !bytes.Equal(existing, value) {
		return ErrUpgradeJournalConflict
	}
	return nil
}

// candidateWriteOutcome reconciles only a potentially durable outcome. A
// normal write error remains an error even if a concurrent actor happened to
// construct an equivalent activation afterwards.
func (s *UpgradeStore) candidateWriteOutcome(activation ActivationV1, databaseEnv, activationRaw []byte, cause error) error {
	if !errors.Is(cause, ErrDurableCommitUnknown) {
		return cause
	}
	if err := s.matchExistingCandidateActivation(activation, databaseEnv, activationRaw); err == nil {
		return nil
	}
	return cause
}

// matchExistingCandidateActivation reads all three candidate objects through
// their fixed paths and verifies the exact activation JSON, database.env, and
// typed release link. It is intentionally private so no caller can select an
// arbitrary activation path.
func (s *UpgradeStore) matchExistingCandidateActivation(activation ActivationV1, databaseEnv, activationRaw []byte) error {
	slot, err := s.activationSlotWriter(activation.ActivationID)
	if err != nil {
		return err
	}
	defer slot.Close()
	env, err := slot.ReadMetadata("database.env")
	if err != nil || !bytes.Equal(env, databaseEnv) {
		return ErrUpgradeJournalConflict
	}
	raw, err := slot.ReadMetadata("activation.json")
	if err != nil || !bytes.Equal(raw, activationRaw) {
		return ErrUpgradeJournalConflict
	}
	if _, err := ParseActivationV1(raw); err != nil {
		return ErrUpgradeJournalConflict
	}
	info, err := slot.ops.Lstat("release")
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return ErrUpgradeJournalConflict
	}
	target, err := slot.ops.Readlink("release")
	if err != nil || target != filepath.ToSlash(filepath.Join("..", "..", "releases", activation.Release.ID)) {
		return ErrUpgradeJournalConflict
	}
	return nil
}

func (s *UpgradeStore) validateActivationRoot() error {
	if s == nil || s.activationWriter == nil || s.activationWriter.VerifyLiveRoot() != nil {
		return ErrUpgradeJournalConflict
	}
	return nil
}

func (s *UpgradeStore) validateActivationLayout() error {
	if err := s.validateActivationRoot(); err != nil {
		return err
	}
	info, err := s.activationWriter.ops.Lstat("activations")
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != activationSlotDirMode || verifyOwner(info, s.activationWriter.uid, s.activationWriter.gid) != nil {
		return ErrUpgradeJournalConflict
	}
	return nil
}

// ensureActivationLayout creates the activation collection at the first
// journaled projection boundary.  A valid RC0 split layout has no collection
// yet, while native installs and recovery retries may already have the exact
// root-owned 0711 directory.
func (s *UpgradeStore) ensureActivationLayout() error {
	if err := s.validateActivationRoot(); err != nil {
		return err
	}
	_, err := s.activationWriter.CreateChildDirectory("activations", activationSlotDirMode)
	if err != nil {
		if !errors.Is(err, ErrDurableCommitUnknown) {
			if s.validateActivationLayout() != nil {
				return ErrUpgradeJournalConflict
			}
			return err
		}
		if s.validateActivationLayout() != nil {
			return err
		}
		// Visibility proves only that mkdir reached the live namespace; it
		// does not prove the parent directory entry survived the failed fsync.
		// Retry that durability boundary before native, restore, or legacy
		// publication can journal the collection as established.
		if _, retryErr := s.activationWriter.CreateChildDirectory("activations", activationSlotDirMode); retryErr != nil {
			return fmt.Errorf("%w: activation collection fsync retry: %v", ErrDurableCommitUnknown, retryErr)
		}
	}
	return s.validateActivationLayout()
}

func (s *UpgradeStore) validateActivationDirectory(path string) error {
	if s == nil || s.activationWriter == nil || cleanRelative(path) != nil {
		return ErrUpgradeJournalConflict
	}
	info, err := s.activationWriter.ops.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || verifyOwner(info, s.activationWriter.uid, s.activationWriter.gid) != nil {
		return ErrUpgradeJournalConflict
	}
	return nil
}

func (s *UpgradeStore) activationSlotWriter(id string) (*DurableWriter, error) {
	if !validID(id) || s.validateActivationLayout() != nil {
		return nil, ErrUpgradeJournalConflict
	}
	collection, err := s.activationWriter.OpenChildWriter("activations", activationSlotDirMode)
	if err != nil {
		return nil, ErrUpgradeJournalConflict
	}
	defer collection.Close()
	slot, err := collection.OpenChildWriter(id, activationSlotDirMode)
	if err != nil {
		return nil, ErrUpgradeJournalConflict
	}
	return slot, nil
}

func (s *UpgradeStore) syncActivationCollection() error {
	if err := s.validateActivationLayout(); err != nil {
		return err
	}
	writer, err := s.activationWriter.OpenChildWriter("activations", activationSlotDirMode)
	if err != nil {
		return err
	}
	defer writer.Close()
	return writer.SyncRoot()
}

func (s *UpgradeStore) createActivationDirectory(id string) (bool, error) {
	if !validID(id) {
		return false, ErrUpgradeJournalConflict
	}
	if err := s.ensureActivationLayout(); err != nil {
		return false, err
	}
	collection, err := s.activationWriter.OpenChildWriter("activations", activationSlotDirMode)
	if err != nil {
		return false, ErrUpgradeJournalConflict
	}
	defer collection.Close()
	created, err := collection.CreateChildDirectory(id, activationSlotDirMode)
	if err != nil {
		return false, err
	}
	return created, nil
}

func (s *UpgradeStore) verifyCandidateRelease(activation ActivationV1) error {
	release := activation.Release
	if !release.valid() {
		return ErrUpgradeJournalConflict
	}
	if err := s.validateActivationRoot(); err != nil {
		return err
	}
	manifestRaw, err := secureReleaseFile(s.activationWriter, release.ID, "manifest.json", 0o644)
	if err != nil || sha256Bytes(manifestRaw) != release.ManifestSHA256 {
		return ErrUpgradeJournalConflict
	}
	manifest, err := parseReleaseManifest(manifestRaw)
	if err != nil {
		return err
	}
	// The activation store remains reusable for historical/fixture releases,
	// while every real RC1 publication is pinned to the production candidate
	// payload contract before slot creation.
	if (release.Version == ProductionCandidateVersion && ValidateProductionCandidate(manifest) != nil) || manifest.ReleaseID != release.ID || manifest.Version != release.Version || manifest.SourceCommit != release.SourceCommit || manifest.Architecture != release.Architecture || manifest.MigrationVersion != activation.Database.Migration {
		return ErrUpgradeJournalConflict
	}
	return verifySecureRelease(s.activationWriter, release.ID, manifest)
}
func (s *UpgradeStore) SetPrevious(_ context.Context, oldID string) error {
	if !s.ownsLock() || !validID(oldID) {
		return ErrUpgradeJournalConflict
	}
	state, err := s.ReadActivationState(context.Background())
	if err != nil || state.ActiveID != oldID {
		return ErrUpgradeJournalConflict
	}
	if err := s.activationWriter.SwapActivationLink(ActivationLinkPreviousActive, oldID, ""); err != nil {
		return err
	}
	after, err := s.ReadActivationState(context.Background())
	if err != nil || after.PreviousID != oldID || after.PreviousJSONSHA256 != state.ActiveActivationJSONSHA256 {
		return ErrUpgradeJournalConflict
	}
	return nil
}
func (s *UpgradeStore) RestorePrevious(_ context.Context, expectedCurrent, baselineID, baselineDigest string) error {
	if !s.ownsLock() || !validID(expectedCurrent) || (baselineID == "") != (baselineDigest == "") || baselineID != "" && (!validID(baselineID) || !validSHA(baselineDigest)) {
		return ErrUpgradeJournalConflict
	}
	state, err := s.ReadActivationState(context.Background())
	if err != nil || state.ActiveID != expectedCurrent || state.PreviousID != expectedCurrent {
		return ErrUpgradeJournalConflict
	}
	if baselineID == "" {
		if err := s.activationWriter.RemoveActivationLink(ActivationLinkPreviousActive); err != nil {
			return err
		}
		after, err := s.ReadActivationState(context.Background())
		if err != nil || after.PreviousID != "" || after.PreviousJSONSHA256 != "" {
			return ErrUpgradeJournalConflict
		}
		return nil
	}
	_, digest, err := s.readActivation(baselineID)
	if err != nil || digest != baselineDigest {
		return ErrUpgradeJournalConflict
	}
	if state.PreviousID == baselineID && state.PreviousJSONSHA256 == baselineDigest {
		return nil
	}
	if err := s.activationWriter.SwapActivationLink(ActivationLinkPreviousActive, baselineID, ""); err != nil {
		return err
	}
	after, err := s.ReadActivationState(context.Background())
	if err != nil || after.ActiveID != expectedCurrent || after.PreviousID != baselineID || after.PreviousJSONSHA256 != baselineDigest {
		return ErrUpgradeJournalConflict
	}
	return nil
}
func (s *UpgradeStore) SwapActive(_ context.Context, candidateID string) error {
	if !s.ownsLock() || !validID(candidateID) {
		return ErrUpgradeJournalConflict
	}
	state, err := s.ReadActivationState(context.Background())
	if err != nil || state.PreviousID == "" {
		return ErrUpgradeJournalConflict
	}
	_, candidateDigest, err := s.readActivation(candidateID)
	if err != nil {
		return ErrUpgradeJournalConflict
	}
	if err := s.activationWriter.SwapActivationLink(ActivationLinkActive, candidateID, ""); err != nil {
		return err
	}
	after, err := s.ReadActivationState(context.Background())
	if err != nil || after.ActiveID != candidateID || after.ActiveActivationJSONSHA256 != candidateDigest || after.PreviousID != state.PreviousID || after.PreviousJSONSHA256 != state.PreviousJSONSHA256 {
		return ErrUpgradeJournalConflict
	}
	return nil
}
func (s *UpgradeStore) RestoreActive(_ context.Context, oldID, expectedCandidateID string) error {
	if !s.ownsLock() || !validID(oldID) || !validID(expectedCandidateID) {
		return ErrUpgradeJournalConflict
	}
	state, err := s.ReadActivationState(context.Background())
	if err != nil || state.ActiveID != expectedCandidateID || state.PreviousID != oldID {
		return ErrUpgradeJournalConflict
	}
	_, oldDigest, err := s.readActivation(oldID)
	if err != nil {
		return ErrUpgradeJournalConflict
	}
	if err := s.activationWriter.SwapActivationLink(ActivationLinkActive, oldID, ""); err != nil {
		return err
	}
	if err := s.activationWriter.SwapActivationLink(ActivationLinkPreviousActive, expectedCandidateID, ""); err != nil {
		return err
	}
	after, err := s.ReadActivationState(context.Background())
	if err != nil || after.ActiveID != oldID || after.ActiveActivationJSONSHA256 != oldDigest || after.PreviousID != expectedCandidateID || after.PreviousJSONSHA256 != state.ActiveActivationJSONSHA256 {
		return ErrUpgradeJournalConflict
	}
	return nil
}

var _ UpgradeJournalStore = (*UpgradeStore)(nil)

// PreflightPlan is the concrete, read-only preflight surface for native and
// RC0 installations. It intentionally does not alter pointers, configuration,
// units, or activation slots.
func (s *UpgradeStore) PreflightPlan(_ context.Context, request UpgradePreflightRequest) (UpgradePreflight, error) {
	if !s.ownsLock() || s.lock.tx != request.TransactionID || request.Validate() != nil {
		return UpgradePreflight{}, ErrUpgradeJournalConflict
	}
	if marker, err := s.markerTransaction(); err != nil || marker != "" {
		return UpgradePreflight{}, ErrUpgradeJournalConflict
	}
	if target, err := s.activationWriter.ReadActivationLink(ActivationLinkActive); err == nil {
		id, ok := activationIDFromTarget(target)
		if !ok {
			return UpgradePreflight{}, ErrUpgradeJournalConflict
		}
		a, digest, err := s.readActivation(id)
		if err != nil {
			return UpgradePreflight{}, ErrUpgradeJournalConflict
		}
		slot, err := s.activationSlotWriter(id)
		if err != nil {
			return UpgradePreflight{}, ErrUpgradeJournalConflict
		}
		defer slot.Close()
		databaseEnv, err := slot.ReadMetadata("database.env")
		if err != nil || databaseEnvSHA256(databaseEnv) != a.DatabaseEnvSHA256 {
			return UpgradePreflight{}, ErrUpgradeJournalConflict
		}
		previous, err := s.legacyPrevious()
		if err != nil {
			return UpgradePreflight{}, ErrUpgradeJournalConflict
		}
		return UpgradePreflight{Existing: &ExistingActivationPreflight{Activation: a, JSONSHA256: digest, DatabaseEnv: append([]byte(nil), databaseEnv...)}, Previous: previous}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return UpgradePreflight{}, ErrUpgradeJournalConflict
	}

	plan, err := s.readLegacyPlan(request)
	if err != nil {
		return UpgradePreflight{}, ErrUpgradeJournalConflict
	}
	return UpgradePreflight{Legacy: &plan, Previous: plan.Previous}, nil
}

func (s *UpgradeStore) readLegacyPlan(request UpgradePreflightRequest) (LegacyProjectionPlan, error) {
	if s == nil || s.activationWriter == nil || s.activationWriter.ops == nil {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	root := s.activationWriter.ops
	info, err := root.Lstat("current")
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	target, err := root.Readlink("current")
	if err != nil {
		return LegacyProjectionPlan{}, err
	}
	parts := strings.Split(filepath.ToSlash(target), "/")
	if len(parts) != 2 || parts[0] != "releases" || !validID(parts[1]) || target != filepath.ToSlash(filepath.Join("releases", parts[1])) {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	if s.legacyVerifier == nil {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	release, rows, err := s.legacyVerifier.VerifyRC0(parts[1])
	if err != nil || release.ID != parts[1] || !validRC0Release(release) {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	evidence, err := migrationEvidence(rows)
	if err != nil || evidence.RowsSHA256 == "" {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	envRaw, err := s.readLegacyServerEnv()
	if err != nil {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	databaseEnv, afterRaw, err := splitLegacyServerEnv(envRaw)
	if err != nil {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	unitBefore, err := s.readSystemdUnit()
	if err != nil {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	candidateUnit, err := s.legacyVerifier.CandidateServerUnit(request.CandidateRelease)
	if err != nil {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	if validateLegacyCandidateUnit(candidateUnit) != nil {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	edge, err := s.readLegacyEdgePlan(request.TransactionID, release, request.CandidateRelease)
	if err != nil {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	previous, err := s.legacyPrevious()
	if err != nil {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	activationID := "legacy-" + sha256Bytes([]byte(request.TransactionID))[:24]
	return LegacyProjectionPlan{TransactionID: request.TransactionID, ActivationID: activationID, Release: release, CurrentTarget: legacyReleaseTarget(release), ExpectedMigration: "0023", ExpectedRowsSHA256: evidence.RowsSHA256, DatabaseEnv: databaseEnv, DatabaseEnvSHA256: sha256Bytes(databaseEnv), ServerEnvBeforeSHA256: sha256Bytes(envRaw), ServerEnvAfterSHA256: sha256Bytes(afterRaw), ServerUnitBeforeSHA256: sha256Bytes(unitBefore), ServerUnitAfterSHA256: sha256Bytes(candidateUnit), ServerUnitReleaseID: request.CandidateRelease.ID, EdgeConfigTransition: edge, Previous: previous}, nil
}

func (s *UpgradeStore) readLegacyEdgePlan(tx string, source, candidate ReleaseV1) (*EdgeConfigTransitionPlan, error) {
	if s == nil || !validID(tx) {
		return nil, ErrUpgradeJournalConflict
	}
	verifier, ok := s.legacyVerifier.(legacyEdgeConfigVerifier)
	if !ok {
		return nil, ErrUpgradeJournalConflict
	}
	sourceTemplate, err := verifier.RC0EdgeTemplate(source)
	if err != nil {
		return nil, ErrUpgradeJournalConflict
	}
	candidateTemplate, caddy, err := verifier.CandidateEdgeConfig(candidate)
	if err != nil {
		return nil, ErrUpgradeJournalConflict
	}
	installed, err := s.readInstalledEdgeConfig()
	if err != nil {
		return nil, ErrUpgradeJournalConflict
	}
	return edgeConfigTransitionPlan(tx, source, candidate, sourceTemplate, installed, candidateTemplate, caddy)
}

func legacyMigrationRows(manifest Manifest) ([]MigrationRow, error) {
	byPath := map[string]FileDigest{}
	for _, f := range manifest.Files {
		byPath[f.Path] = f
	}
	rows := make([]MigrationRow, 0, 23)
	for i := 1; i <= 23; i++ {
		prefix := "migrations/control-plane/" + formatMigrationVersion(i) + "_"
		var found FileDigest
		n := 0
		for path, f := range byPath {
			if strings.HasPrefix(path, prefix) && strings.HasSuffix(path, ".sql") {
				found, n = f, n+1
			}
		}
		// The frozen RC0 production bundle declares migration payloads as
		// root-readable 0640 files.  Requiring the source-tree 0644 mode here
		// makes the verified N-1 artifact impossible to project.
		if n != 1 || found.Mode != 0o640 {
			return nil, ErrUpgradeJournalConflict
		}
		// control-plane-migrate.sh persists the canonical filename stem, not
		// only the numeric prefix.  Legacy inspection must hash the same rows
		// or an intact RC0 database can never match its release manifest.
		rows = append(rows, MigrationRow{Version: strings.TrimSuffix(filepath.Base(found.Path), ".sql"), Checksum: found.SHA256})
	}
	if !validMigrationRows(rows, 23) {
		return nil, ErrUpgradeJournalConflict
	}
	return rows, nil
}

func splitLegacyServerEnv(raw []byte) ([]byte, []byte, error) {
	if bytes.ContainsAny(raw, "\x00\r") {
		return nil, nil, ErrUpgradeJournalConflict
	}
	var value string
	n := 0
	lines := strings.SplitAfter(string(raw), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	after := make([]string, 0, len(lines))
	for _, full := range lines {
		line := strings.TrimSuffix(full, "\n")
		if strings.HasPrefix(line, "OPEN_CARD_DATABASE_URL=") {
			n++
			value = strings.TrimPrefix(line, "OPEN_CARD_DATABASE_URL=")
			continue
		}
		if strings.HasPrefix(line, "export ") || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			return nil, nil, ErrUpgradeJournalConflict
		}
		after = append(after, full)
	}
	if n != 1 {
		return nil, nil, ErrUpgradeJournalConflict
	}
	database, err := FormatDatabaseEnv(value)
	if err != nil {
		return nil, nil, ErrUpgradeJournalConflict
	}
	return database, []byte(strings.Join(after, "")), nil
}

func (s *UpgradeStore) configRoot() string {
	if s.root == "/" {
		return "/etc/open-card"
	}
	return filepath.Join(s.root, "etc/open-card")
}
func (s *UpgradeStore) unitRoot() string {
	if s.root == "/" {
		return "/etc/systemd/system"
	}
	return filepath.Join(s.root, "etc/systemd/system")
}
func (s *UpgradeStore) configWriter() (*DurableWriter, error) {
	if s == nil || s.configDurable == nil {
		return nil, ErrUpgradeJournalConflict
	}
	return s.configDurable, nil
}
func (s *UpgradeStore) unitWriter() (*DurableWriter, error) {
	if s == nil || s.unitDurable == nil {
		return nil, ErrUpgradeJournalConflict
	}
	return s.unitDurable, nil
}
func (s *UpgradeStore) readLegacyServerEnv() ([]byte, error) {
	w, err := s.configWriter()
	if err != nil {
		return nil, err
	}
	return w.ReadMetadata("server.env")
}

const installedEdgeConfigName = "open-card-edge.Caddyfile"

// readFixedOwnedFile deliberately does not expose a generic public file API.
// Edge configuration is the sole non-root-readable deployment file in the
// upgrade store, so its fixed name/mode/owner remain local to this package.
func readFixedOwnedFile(w *DurableWriter, name string, mode os.FileMode, uid, gid int) ([]byte, error) {
	if w == nil || w.ops == nil || w.VerifyLiveRoot() != nil || cleanRelative(name) != nil || w.requireSecureParents(filepath.Dir(name)) != nil {
		return nil, ErrUpgradeJournalConflict
	}
	file, err := w.ops.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUpgradeJournalConflict
	}
	defer w.ops.CloseFile(file)
	info, err := w.ops.Stat(file)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || verifyOwner(info, uid, gid) != nil {
		return nil, ErrUpgradeJournalConflict
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, ErrUpgradeJournalConflict
	}
	info, err = w.ops.Stat(file)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || verifyOwner(info, uid, gid) != nil || w.VerifyLiveRoot() != nil {
		return nil, ErrUpgradeJournalConflict
	}
	return raw, nil
}

func writeFixedOwnedFile(w *DurableWriter, name string, value []byte, mode os.FileMode, uid, gid int) error {
	if w == nil || w.ops == nil || w.VerifyLiveRoot() != nil || cleanRelative(name) != nil || w.requireSecureParents(filepath.Dir(name)) != nil || uid < 0 || gid < 0 {
		return ErrUpgradeJournalConflict
	}
	temporary, err := durableTempName(filepath.Dir(name), ".open-card-edge-")
	if err != nil {
		return ErrUpgradeJournalConflict
	}
	file, err := w.ops.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return ErrUpgradeJournalConflict
	}
	closed := false
	defer func() {
		if !closed {
			_ = w.ops.CloseFile(file)
		}
		_ = w.ops.Remove(temporary)
	}()
	if _, err = w.ops.Write(file, value); err != nil || w.ops.Sync(file) != nil || w.ops.Chmod(file, mode) != nil || w.ops.Chown(file, uid, gid) != nil {
		return ErrUpgradeJournalConflict
	}
	info, err := w.ops.Stat(file)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || verifyOwner(info, uid, gid) != nil || w.ops.Sync(file) != nil || w.ops.CloseFile(file) != nil {
		return ErrUpgradeJournalConflict
	}
	closed = true
	if err := w.ops.Rename(temporary, name); err != nil {
		return ErrUpgradeJournalConflict
	}
	if err := w.syncParent(filepath.Dir(name)); err != nil {
		return fmt.Errorf("%w: %v", ErrDurableCommitUnknown, err)
	}
	if err := w.VerifyLiveRoot(); err != nil {
		return fmt.Errorf("%w: %v", ErrDurableCommitUnknown, err)
	}
	return nil
}

func (s *UpgradeStore) readInstalledEdgeConfig() ([]byte, error) {
	w, err := s.configWriter()
	if err != nil || s.edgeGID < 0 {
		return nil, ErrUpgradeJournalConflict
	}
	return readFixedOwnedFile(w, installedEdgeConfigName, 0o640, w.uid, s.edgeGID)
}

func (s *UpgradeStore) edgeArtifactWriter(tx string, create bool) (*DurableWriter, error) {
	if s == nil || s.dataWriter == nil || !validID(tx) {
		return nil, ErrUpgradeJournalConflict
	}
	if create {
		if _, err := s.dataWriter.CreateChildDirectory("upgrade-artifacts", activationSlotDirMode); err != nil && !errors.Is(err, ErrDurableCommitUnknown) {
			return nil, ErrUpgradeJournalConflict
		}
	}
	artifacts, err := s.dataWriter.OpenChildWriter("upgrade-artifacts", activationSlotDirMode)
	if err != nil {
		return nil, ErrUpgradeJournalConflict
	}
	if create {
		if _, err := artifacts.CreateChildDirectory(tx, activationSlotDirMode); err != nil && !errors.Is(err, ErrDurableCommitUnknown) {
			_ = artifacts.Close()
			return nil, ErrUpgradeJournalConflict
		}
	}
	child, openErr := artifacts.OpenChildWriter(tx, activationSlotDirMode)
	closeErr := artifacts.Close()
	if openErr != nil || closeErr != nil {
		if child != nil {
			_ = child.Close()
		}
		return nil, ErrUpgradeJournalConflict
	}
	return child, nil
}
func (s *UpgradeStore) readSystemdUnit() ([]byte, error) {
	w, err := s.unitWriter()
	if err != nil {
		return nil, err
	}
	return w.ReadSystemdServerUnit()
}

// PrepareEdgeConfig publishes only the transaction-owned candidate artifact.
// The installed Caddyfile is deliberately read but never changed here.
func (s *UpgradeStore) PrepareEdgeConfig(_ context.Context, plan EdgeConfigTransitionPlan) (EdgeConfigObservationV1, error) {
	if !s.ownsLock() || s.lock.tx != plan.Evidence.TransactionID || plan.Validate() != nil || s.edgeGID < 0 {
		return EdgeConfigObservationV1{}, ErrUpgradeJournalConflict
	}
	installed, err := s.readInstalledEdgeConfig()
	if err != nil || bytesSHA256(installed) != plan.Evidence.InstalledBeforeSHA256 {
		return EdgeConfigObservationV1{}, ErrUpgradeJournalConflict
	}
	artifact, err := s.edgeArtifactWriter(plan.Evidence.TransactionID, true)
	if err != nil {
		return EdgeConfigObservationV1{}, err
	}
	defer artifact.Close()
	if raw, readErr := readFixedOwnedFile(artifact, edgeConfigArtifactName, 0o640, artifact.uid, s.edgeGID); readErr == nil {
		if !bytes.Equal(raw, plan.Target) {
			return EdgeConfigObservationV1{}, ErrUpgradeJournalConflict
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		// readFixedOwnedFile deliberately sanitizes failures; an absent artifact
		// is the only condition that permits the no-replace write.
		info, lstatErr := artifact.ops.Lstat(edgeConfigArtifactName)
		if !errors.Is(lstatErr, os.ErrNotExist) || info != nil {
			return EdgeConfigObservationV1{}, ErrUpgradeJournalConflict
		}
		if writeErr := writeFixedOwnedFile(artifact, edgeConfigArtifactName, plan.Target, 0o640, artifact.uid, s.edgeGID); writeErr != nil {
			if !errors.Is(writeErr, ErrDurableCommitUnknown) {
				return EdgeConfigObservationV1{}, writeErr
			}
			// A post-rename uncertainty is reconciled by the exact reread below.
		}
	}
	prepared, err := readFixedOwnedFile(artifact, edgeConfigArtifactName, 0o640, artifact.uid, s.edgeGID)
	if err != nil || !bytes.Equal(prepared, plan.Target) {
		return EdgeConfigObservationV1{}, ErrUpgradeJournalConflict
	}
	if after, err := s.readInstalledEdgeConfig(); err != nil || !bytes.Equal(after, installed) {
		return EdgeConfigObservationV1{}, ErrUpgradeJournalConflict
	}
	observation := EdgeConfigObservationV1{PreparedConfigSHA256: bytesSHA256(prepared), InstalledConfigSHA256: bytesSHA256(installed), CaddySHA256: plan.Evidence.CandidateCaddySHA256}
	if observation.Validate() != nil || observation.PreparedConfigSHA256 != plan.Evidence.InstalledAfterSHA256 || observation.InstalledConfigSHA256 != plan.Evidence.InstalledBeforeSHA256 {
		return EdgeConfigObservationV1{}, ErrUpgradeJournalConflict
	}
	return observation, nil
}

// FinalizeEdgeConfig performs the fixed installed-file before/after CAS after
// Caddy has validated the prepared artifact. Exact replay is a no-op; every
// other installed value is a conflict.
func (s *UpgradeStore) FinalizeEdgeConfig(_ context.Context, plan EdgeConfigTransitionPlan) (EdgeConfigObservationV1, error) {
	if !s.ownsLock() || s.lock.tx != plan.Evidence.TransactionID || plan.Validate() != nil || s.edgeGID < 0 {
		return EdgeConfigObservationV1{}, ErrUpgradeJournalConflict
	}
	artifact, err := s.edgeArtifactWriter(plan.Evidence.TransactionID, false)
	if err != nil {
		return EdgeConfigObservationV1{}, err
	}
	prepared, readErr := readFixedOwnedFile(artifact, edgeConfigArtifactName, 0o640, artifact.uid, s.edgeGID)
	closeErr := artifact.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(prepared, plan.Target) {
		return EdgeConfigObservationV1{}, ErrUpgradeJournalConflict
	}
	installed, err := s.readInstalledEdgeConfig()
	if err != nil {
		return EdgeConfigObservationV1{}, ErrUpgradeJournalConflict
	}
	if bytesSHA256(installed) == plan.Evidence.InstalledBeforeSHA256 {
		w, err := s.configWriter()
		if err != nil {
			return EdgeConfigObservationV1{}, ErrUpgradeJournalConflict
		}
		if writeErr := writeFixedOwnedFile(w, installedEdgeConfigName, plan.Target, 0o640, w.uid, s.edgeGID); writeErr != nil && !errors.Is(writeErr, ErrDurableCommitUnknown) {
			return EdgeConfigObservationV1{}, writeErr
		}
	} else if bytesSHA256(installed) != plan.Evidence.InstalledAfterSHA256 {
		return EdgeConfigObservationV1{}, ErrUpgradeJournalConflict
	}
	return s.ReadEdgeConfig(context.Background(), plan)
}

func (s *UpgradeStore) ReadEdgeConfig(_ context.Context, plan EdgeConfigTransitionPlan) (EdgeConfigObservationV1, error) {
	if s == nil || plan.Validate() != nil || s.edgeGID < 0 {
		return EdgeConfigObservationV1{}, ErrUpgradeJournalConflict
	}
	artifact, err := s.edgeArtifactWriter(plan.Evidence.TransactionID, false)
	if err != nil {
		return EdgeConfigObservationV1{}, err
	}
	prepared, readErr := readFixedOwnedFile(artifact, edgeConfigArtifactName, 0o640, artifact.uid, s.edgeGID)
	closeErr := artifact.Close()
	installed, installedErr := s.readInstalledEdgeConfig()
	if readErr != nil || closeErr != nil || installedErr != nil || !bytes.Equal(prepared, plan.Target) || bytesSHA256(installed) != plan.Evidence.InstalledAfterSHA256 {
		return EdgeConfigObservationV1{}, ErrUpgradeJournalConflict
	}
	observation := EdgeConfigObservationV1{PreparedConfigSHA256: bytesSHA256(prepared), InstalledConfigSHA256: bytesSHA256(installed), CaddySHA256: plan.Evidence.CandidateCaddySHA256}
	if observation.Validate() != nil {
		return EdgeConfigObservationV1{}, ErrUpgradeJournalConflict
	}
	return observation, nil
}

func (s *UpgradeStore) candidateServerUnit(release ReleaseV1) ([]byte, error) {
	if s != nil && s.legacyVerifier != nil {
		raw, err := s.legacyVerifier.CandidateServerUnit(release)
		if err != nil || validateLegacyCandidateUnit(raw) != nil {
			return nil, ErrUpgradeJournalConflict
		}
		return raw, nil
	}
	manifestRaw, err := secureReleaseFile(s.activationWriter, release.ID, "manifest.json", 0o644)
	manifest, err := parseReleaseManifest(manifestRaw)
	if err != nil || ValidateProductionCandidate(manifest) != nil || manifest.ReleaseID != release.ID || manifest.Version != release.Version || manifest.SourceCommit != release.SourceCommit || manifest.Architecture != release.Architecture || sha256Bytes(manifestRaw) != release.ManifestSHA256 {
		return nil, ErrUpgradeJournalConflict
	}
	if err := verifySecureRelease(s.activationWriter, release.ID, manifest); err != nil {
		return nil, ErrUpgradeJournalConflict
	}
	raw, err := secureReleaseFile(s.activationWriter, release.ID, "systemd/open-card-server.service", 0o644)
	if err != nil {
		return nil, err
	}
	for _, f := range manifest.Files {
		if f.Path == "systemd/open-card-server.service" && f.Mode == 0o644 && sha256Bytes(raw) == f.SHA256 {
			if validateLegacyCandidateUnit(raw) != nil {
				return nil, ErrUpgradeJournalConflict
			}
			return raw, nil
		}
	}
	return nil, ErrUpgradeJournalConflict
}

func validateLegacyCandidateUnit(raw []byte) error {
	section := ""
	environmentFiles := 0
	for _, rawLine := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			if name == "" || strings.TrimSpace(name) != name {
				return ErrUpgradeJournalConflict
			}
			section = name
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return ErrUpgradeJournalConflict
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if (key == "Environment" || key == "UnsetEnvironment" || key == "PassEnvironment") && strings.Contains(value, "OPEN_CARD_DATABASE_URL") {
			return ErrUpgradeJournalConflict
		}
		if key != "EnvironmentFile" {
			continue
		}
		if section != "Service" || environmentFiles >= 2 {
			return ErrUpgradeJournalConflict
		}
		want := "-/etc/open-card/server.env"
		if environmentFiles == 1 {
			want = "/opt/open-card/active/database.env"
		}
		if value != want {
			return ErrUpgradeJournalConflict
		}
		environmentFiles++
	}
	if environmentFiles != 2 {
		return ErrUpgradeJournalConflict
	}
	return nil
}

func (s *UpgradeStore) candidateServerUnitByID(id string) ([]byte, error) {
	if !validID(id) {
		return nil, ErrUpgradeJournalConflict
	}
	manifestRaw, err := secureReleaseFile(s.activationWriter, id, "manifest.json", 0o644)
	manifest, err := parseReleaseManifest(manifestRaw)
	if err != nil {
		return nil, ErrUpgradeJournalConflict
	}
	release := ReleaseV1{ID: manifest.ReleaseID, Version: manifest.Version, SourceCommit: manifest.SourceCommit, Architecture: manifest.Architecture}
	if release.ID != id {
		return nil, ErrUpgradeJournalConflict
	}
	release.ManifestSHA256 = sha256Bytes(manifestRaw)
	// Task fixtures may inject immutable release evidence, but production uses
	// fixedLegacyReleaseVerifier, which performs the exact production-candidate
	// manifest validation below through candidateServerUnit.
	return s.candidateServerUnit(release)
}

func (s *UpgradeStore) legacyPrevious() (ActivationPointerIdentity, error) {
	target, err := s.activationWriter.ReadActivationLink(ActivationLinkPreviousActive)
	if errors.Is(err, os.ErrNotExist) {
		return ActivationPointerIdentity{}, nil
	}
	if err != nil {
		return ActivationPointerIdentity{}, err
	}
	id, ok := activationIDFromTarget(target)
	if !ok {
		return ActivationPointerIdentity{}, ErrUpgradeJournalConflict
	}
	_, digest, err := s.readActivation(id)
	if err != nil {
		return ActivationPointerIdentity{}, err
	}
	return ActivationPointerIdentity{ID: id, JSONSHA256: digest}, nil
}

// PrepareLegacyProjection converges the non-secret activation projection and
// candidate unit while preserving the global database line for rollback.
func (s *UpgradeStore) PrepareLegacyProjection(_ context.Context, plan LegacyProjectionPlan, activation ActivationV1) (LegacyProjectionObservation, error) {
	if !s.ownsLock() || s.lock.tx != plan.TransactionID || plan.Validate() != nil || activation.Validate() != nil || activation.ActivationID != plan.ActivationID || activation.CreatedByTransactionID != plan.TransactionID || activation.LegacyProjection == nil {
		return LegacyProjectionObservation{}, ErrUpgradeJournalConflict
	}
	if err := s.validateLegacyMutationState(plan, activation, true); err != nil {
		return LegacyProjectionObservation{}, err
	}
	envRaw, err := s.readLegacyServerEnv()
	if err != nil || (sha256Bytes(envRaw) != plan.ServerEnvBeforeSHA256 && sha256Bytes(envRaw) != plan.ServerEnvAfterSHA256) {
		return LegacyProjectionObservation{}, ErrUpgradeJournalConflict
	}
	if _, err := s.writeActivation(context.Background(), activation, plan.DatabaseEnv, true); err != nil {
		return LegacyProjectionObservation{}, err
	}
	if previous, err := s.legacyPrevious(); err != nil || !previous.equal(plan.Previous) {
		return LegacyProjectionObservation{}, ErrUpgradeJournalConflict
	}
	if err := s.activationWriter.SwapActivationLink(ActivationLinkActive, activation.ActivationID, ""); err != nil {
		return LegacyProjectionObservation{}, err
	}
	if err := s.activationWriter.SwapActivationLink(ActivationLinkCurrent, "", ""); err != nil {
		return LegacyProjectionObservation{}, err
	}
	unit, err := s.candidateServerUnitByID(plan.ServerUnitReleaseID)
	if err != nil {
		return LegacyProjectionObservation{}, ErrUpgradeJournalConflict
	}
	w, err := s.unitWriter()
	if err != nil {
		return LegacyProjectionObservation{}, err
	}
	if err := w.WriteSystemdServerUnit(unit); err != nil {
		return LegacyProjectionObservation{}, err
	}
	if err := s.verifyLiveRoots(); err != nil {
		return LegacyProjectionObservation{}, ErrUpgradeJournalConflict
	}
	return s.readLegacyProjectionPhase(context.Background(), plan, activation, true)
}

func (s *UpgradeStore) FinalizeLegacyProjection(_ context.Context, plan LegacyProjectionPlan, activation ActivationV1) (LegacyProjectionObservation, error) {
	if !s.ownsLock() || s.lock.tx != plan.TransactionID || plan.Validate() != nil || activation.Validate() != nil || activation.ActivationID != plan.ActivationID || activation.CreatedByTransactionID != plan.TransactionID || activation.LegacyProjection == nil || activation.Release != plan.Release || activation.Database.Migration != plan.ExpectedMigration || activation.Database.SchemaMigrationsSHA256 != plan.ExpectedRowsSHA256 || activation.DatabaseEnvSHA256 != plan.DatabaseEnvSHA256 {
		return LegacyProjectionObservation{}, ErrUpgradeJournalConflict
	}
	if err := s.validateLegacyMutationState(plan, activation, false); err != nil {
		return LegacyProjectionObservation{}, err
	}
	if _, err := s.readLegacyProjectionPhase(context.Background(), plan, activation, true); err != nil {
		return LegacyProjectionObservation{}, err
	}
	raw, err := s.readLegacyServerEnv()
	if err != nil {
		return LegacyProjectionObservation{}, err
	}
	if sha256Bytes(raw) == plan.ServerEnvBeforeSHA256 {
		_, afterRaw, err := splitLegacyServerEnv(raw)
		if err != nil || sha256Bytes(afterRaw) != plan.ServerEnvAfterSHA256 {
			return LegacyProjectionObservation{}, ErrUpgradeJournalConflict
		}
		w, err := s.configWriter()
		if err != nil {
			return LegacyProjectionObservation{}, err
		}
		if err := s.verifyLiveRoots(); err != nil {
			return LegacyProjectionObservation{}, ErrUpgradeJournalConflict
		}
		if err := w.WriteMetadata("server.env", afterRaw); err != nil {
			return LegacyProjectionObservation{}, err
		}
	} else if sha256Bytes(raw) != plan.ServerEnvAfterSHA256 {
		return LegacyProjectionObservation{}, ErrUpgradeJournalConflict
	}
	if err := s.verifyLiveRoots(); err != nil {
		return LegacyProjectionObservation{}, ErrUpgradeJournalConflict
	}
	return s.ReadLegacyProjection(context.Background(), plan, activation)
}

// validateLegacyMutationState performs the compare-before-write portion of
// the legacy CAS. It accepts only the untouched legacy shape or the exact
// already-projected shape for idempotent retries.
func (s *UpgradeStore) validateLegacyMutationState(plan LegacyProjectionPlan, activation ActivationV1, preparing bool) error {
	if s.verifyLiveRoots() != nil {
		return ErrUpgradeJournalConflict
	}
	currentInfo, err := s.activationWriter.ops.Lstat("current")
	if err != nil || currentInfo.Mode()&os.ModeSymlink == 0 {
		return ErrUpgradeJournalConflict
	}
	current, err := s.activationWriter.ops.Readlink("current")
	if err != nil || (current != filepath.ToSlash(filepath.Join("releases", plan.Release.ID)) && current != legacyCurrentTarget) {
		return ErrUpgradeJournalConflict
	}
	active, err := s.activationWriter.ReadActivationLink(ActivationLinkActive)
	if err == nil {
		id, ok := activationIDFromTarget(active)
		if !ok || id != activation.ActivationID {
			return ErrUpgradeJournalConflict
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrUpgradeJournalConflict
	}
	previous, err := s.legacyPrevious()
	if err != nil || !previous.equal(plan.Previous) {
		return ErrUpgradeJournalConflict
	}
	env, err := s.readLegacyServerEnv()
	if err != nil || (sha256Bytes(env) != plan.ServerEnvBeforeSHA256 && sha256Bytes(env) != plan.ServerEnvAfterSHA256) {
		return ErrUpgradeJournalConflict
	}
	unit, err := s.readSystemdUnit()
	if err != nil {
		return ErrUpgradeJournalConflict
	}
	if preparing && sha256Bytes(unit) != plan.ServerUnitBeforeSHA256 && sha256Bytes(unit) != plan.ServerUnitAfterSHA256 {
		return ErrUpgradeJournalConflict
	}
	if !preparing && sha256Bytes(unit) != plan.ServerUnitAfterSHA256 {
		return ErrUpgradeJournalConflict
	}
	return nil
}

func (s *UpgradeStore) ReadLegacyProjection(_ context.Context, plan LegacyProjectionPlan, activation ActivationV1) (LegacyProjectionObservation, error) {
	return s.readLegacyProjectionPhase(context.Background(), plan, activation, false)
}

func (s *UpgradeStore) readLegacyProjectionPhase(_ context.Context, plan LegacyProjectionPlan, activation ActivationV1, allowBefore bool) (LegacyProjectionObservation, error) {
	if s.verifyLiveRoots() != nil || plan.Validate() != nil || activation.Validate() != nil {
		return LegacyProjectionObservation{}, ErrUpgradeJournalConflict
	}
	_, digest, err := s.readActivation(activation.ActivationID)
	if err != nil || digest != sha256BytesMust(activation) {
		return LegacyProjectionObservation{}, ErrUpgradeJournalConflict
	}
	state, err := s.ReadActivationState(context.Background())
	if err != nil || state.ActiveID != activation.ActivationID {
		return LegacyProjectionObservation{}, ErrUpgradeJournalConflict
	}
	env, err := s.readLegacyServerEnv()
	if err != nil || (sha256Bytes(env) != plan.ServerEnvAfterSHA256 && (!allowBefore || sha256Bytes(env) != plan.ServerEnvBeforeSHA256)) {
		return LegacyProjectionObservation{}, ErrUpgradeJournalConflict
	}
	unit, err := s.readSystemdUnit()
	if err != nil || sha256Bytes(unit) != plan.ServerUnitAfterSHA256 {
		return LegacyProjectionObservation{}, ErrUpgradeJournalConflict
	}
	o := LegacyProjectionObservation{ActivationID: activation.ActivationID, ActivationJSONSHA256: digest, DatabaseEnvSHA256: activation.DatabaseEnvSHA256, Active: ActivationPointerIdentity{ID: state.ActiveID, JSONSHA256: state.ActiveActivationJSONSHA256}, Previous: ActivationPointerIdentity{ID: state.PreviousID, JSONSHA256: state.PreviousJSONSHA256}, CurrentTarget: legacyCurrentTarget, ServerEnvSHA256: sha256Bytes(env), ServerUnitSHA256: sha256Bytes(unit)}
	if o.Validate() != nil {
		return LegacyProjectionObservation{}, ErrUpgradeJournalConflict
	}
	return o, nil
}

// RecoverLegacyPlan reconstructs the non-secret compatibility plan from the
// projected activation and fixed roots. Database credentials remain in memory.
func (s *UpgradeStore) RecoverLegacyPlan(_ context.Context, plannedOld ActivationV1, requestedManifestSHA string) (LegacyProjectionPlan, error) {
	if !s.ownsLock() || plannedOld.Validate() != nil || plannedOld.LegacyProjection == nil || !validSHA(requestedManifestSHA) {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	lp := plannedOld.LegacyProjection
	if s.verifyLiveRoots() != nil {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	currentInfo, err := s.activationWriter.ops.Lstat("current")
	if err != nil || currentInfo.Mode()&os.ModeSymlink == 0 {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	currentTarget, err := s.activationWriter.ops.Readlink("current")
	if err != nil || (currentTarget != filepath.ToSlash(filepath.Join("releases", plannedOld.Release.ID)) && currentTarget != legacyCurrentTarget) {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	manifestRaw, err := secureReleaseFile(s.activationWriter, lp.ServerUnitReleaseID, "manifest.json", 0o644)
	manifest, err := parseReleaseManifest(manifestRaw)
	if err != nil {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	if sha256Bytes(manifestRaw) != requestedManifestSHA || manifest.ReleaseID != lp.ServerUnitReleaseID {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	candidate := ReleaseV1{ID: manifest.ReleaseID, Version: manifest.Version, SourceCommit: manifest.SourceCommit, Architecture: manifest.Architecture, ManifestSHA256: sha256Bytes(manifestRaw)}
	if !candidate.valid() {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	edge, err := s.readLegacyEdgePlan(plannedOld.CreatedByTransactionID, plannedOld.Release, candidate)
	if err != nil {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	previous, err := s.legacyPrevious()
	if err != nil {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	envRaw, err := s.readLegacyServerEnv()
	if err != nil {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	databaseEnv, afterRaw, splitErr := splitLegacyServerEnv(envRaw)
	if splitErr != nil {
		_, _, readErr := s.readActivation(plannedOld.ActivationID)
		if readErr != nil {
			return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
		}
		slot, err := s.activationSlotWriter(plannedOld.ActivationID)
		if err != nil {
			return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
		}
		defer slot.Close()
		databaseEnv, err = slot.ReadMetadata("database.env")
		if err != nil {
			return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
		}
		if _, err := ParseDatabaseEnv(databaseEnv); err != nil {
			return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
		}
		afterRaw = envRaw
	}
	unit, err := s.readSystemdUnit()
	if err != nil {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	plan := LegacyProjectionPlan{TransactionID: plannedOld.CreatedByTransactionID, ActivationID: plannedOld.ActivationID, Release: plannedOld.Release, CurrentTarget: lp.Target, ExpectedMigration: plannedOld.Database.Migration, ExpectedRowsSHA256: plannedOld.Database.SchemaMigrationsSHA256, DatabaseEnv: databaseEnv, DatabaseEnvSHA256: plannedOld.DatabaseEnvSHA256, ServerEnvBeforeSHA256: lp.ServerEnvBeforeSHA256, ServerEnvAfterSHA256: lp.ServerEnvAfterSHA256, ServerUnitBeforeSHA256: lp.ServerUnitBeforeSHA256, ServerUnitAfterSHA256: lp.ServerUnitAfterSHA256, ServerUnitReleaseID: lp.ServerUnitReleaseID, EdgeConfigTransition: edge, Previous: previous}
	if plan.Validate() != nil || sha256Bytes(databaseEnv) != plan.DatabaseEnvSHA256 || (sha256Bytes(envRaw) != plan.ServerEnvBeforeSHA256 && sha256Bytes(envRaw) != plan.ServerEnvAfterSHA256) || (sha256Bytes(afterRaw) != plan.ServerEnvAfterSHA256 && sha256Bytes(envRaw) != plan.ServerEnvAfterSHA256) || (sha256Bytes(unit) != plan.ServerUnitBeforeSHA256 && sha256Bytes(unit) != plan.ServerUnitAfterSHA256) {
		return LegacyProjectionPlan{}, ErrUpgradeJournalConflict
	}
	return plan, nil
}

func sha256BytesMust(a ActivationV1) string {
	raw, err := MarshalActivationV1(a)
	if err != nil {
		return ""
	}
	return sha256Bytes(raw)
}
