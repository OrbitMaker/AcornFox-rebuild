package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

func (u *acornFoxUpgrade) ensureDirectory(s *TaskAcornFoxRepoStore, root *os.Root, path string, mode os.FileMode, owner acornFoxInstallPrincipal) error {
	return u.ensureDirectoryPrefix(s, root, path, mode, owner, false)
}
func (u *acornFoxUpgrade) ensureDirectoryPrefix(s *TaskAcornFoxRepoStore, root *os.Root, path string, mode os.FileMode, owner acornFoxInstallPrincipal, allowEmptyPrefix bool) error {
	if path == "." {
		return nil
	}
	if validateRelativePath(path) != nil {
		return ErrAcornFoxUpgradeConflict
	}
	info, e := root.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		if e = root.Mkdir(path, 0700); e != nil {
			return ErrAcornFoxUpgradeUnknown
		}
		if allowEmptyPrefix && root == s.hostRoot {
			if e = u.fault("directory-created"); e != nil {
				return e
			}
		}
		if allowEmptyPrefix && root != s.hostRoot && mode != 0700 {
			if e = u.fault("private-substrate-directory-created"); e != nil {
				return e
			}
		}
		f, e := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if e != nil {
			return ErrAcornFoxUpgradeUnknown
		}
		e = acornFoxLiveApplyOwner(s, f, owner)
		if e == nil {
			e = f.Chmod(mode)
		}
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e != nil || ce != nil || acornFoxLiveSyncDir(root, acornFoxUpgradeParent(path)) != nil {
			return ErrAcornFoxUpgradeUnknown
		}
		info, e = root.Lstat(path)
	}
	if e == nil && allowEmptyPrefix && info.IsDir() && info.Mode() == (os.ModeDir|0700) && mode != 0700 && verifyOwner(info, s.uid, s.gid) == nil {
		f, oe := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if oe != nil {
			return ErrAcornFoxUpgradeConflict
		}
		opened, se := f.Stat()
		children, re := f.ReadDir(1)
		if se != nil || !os.SameFile(info, opened) || len(children) != 0 || !errors.Is(re, io.EOF) {
			f.Close()
			return ErrAcornFoxUpgradeConflict
		}
		oe = acornFoxLiveApplyOwner(s, f, owner)
		if oe == nil {
			oe = f.Chmod(mode)
		}
		if oe == nil {
			oe = f.Sync()
		}
		ce := f.Close()
		if oe != nil || ce != nil || acornFoxLiveSyncDir(root, acornFoxUpgradeParent(path)) != nil {
			return ErrAcornFoxUpgradeUnknown
		}
		info, e = root.Lstat(path)
	}
	if e != nil || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm() != mode || !acornFoxLiveObservedOwner(s, info, owner) {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}
func acornFoxUpgradeParent(path string) string {
	parent := parentDirectory(path)
	if parent == "" {
		return "."
	}
	return parent
}
func acornFoxUpgradeTemp(path string) string {
	return acornFoxUpgradeParent(path) + "/.acornfox-upgrade-" + sha256Hex([]byte(path))[:32]
}
func (u *acornFoxUpgrade) atomicFile(s *TaskAcornFoxRepoStore, root *os.Root, path string, old, next []byte, mode os.FileMode) error {
	return u.atomicFileOwned(s, root, path, old, next, mode, acornFoxInstallPrincipal{})
}
func (u *acornFoxUpgrade) atomicFileOwned(s *TaskAcornFoxRepoStore, root *os.Root, path string, old, next []byte, mode os.FileMode, principal acornFoxInstallPrincipal) error {
	if !s.ownsLock() || validateRelativePath(path) != nil || next == nil {
		return ErrAcornFoxUpgradeConflict
	}
	current, e := u.readPrincipal(root, path, mode, acornFoxArchiveMaxBytes, principal)
	currentExists := e == nil
	if errors.Is(e, os.ErrNotExist) {
		if old != nil {
			return ErrAcornFoxUpgradeConflict
		}
	} else if e != nil || !bytes.Equal(current, old) && !bytes.Equal(current, next) {
		return ErrAcornFoxUpgradeConflict
	}
	temp := acornFoxUpgradeTemp(path)
	if partial, pe := u.read(root, temp, 0600, acornFoxArchiveMaxBytes); pe == nil {
		safe := bytes.HasPrefix(next, partial) || old != nil && bytes.HasPrefix(old, partial)
		if !safe && path == acornFoxUpgradeJournalPath {
			var j acornFoxUpgradeJournal
			if json.Unmarshal(next, &j) == nil {
				for _, phase := range []string{"PREPARED", "BLOCKED", "QUIESCED", "SNAPSHOT_CREATED", "MIGRATED", "VALIDATED", "PUBLISHED", "SWITCHED", "UPGRADED", "ROLLING_BACK", "RECOVERY_PREPARED", "ROLLED_BACK"} {
					j.Phase = phase
					if bytes.HasPrefix(acornFoxUpgradeJSON(j), partial) {
						safe = true
						break
					}
				}
			}
		}
		if !safe {
			return ErrAcornFoxUpgradeConflict
		}
		if root.Remove(temp) != nil || acornFoxLiveSyncDir(root, acornFoxUpgradeParent(path)) != nil {
			return ErrAcornFoxUpgradeUnknown
		}
	} else if !errors.Is(pe, os.ErrNotExist) {
		// A crash after chmod but before rename leaves a complete final-mode temp.
		full, fe := u.readPrincipal(root, temp, mode, acornFoxArchiveMaxBytes, principal)
		if fe != nil {
			full, fe = u.readPrincipal(root, temp, 0600, acornFoxArchiveMaxBytes, principal)
		}
		if fe != nil || !bytes.Equal(full, next) && !bytes.Equal(full, old) {
			return ErrAcornFoxUpgradeConflict
		}
		if root.Remove(temp) != nil || acornFoxLiveSyncDir(root, acornFoxUpgradeParent(path)) != nil {
			return ErrAcornFoxUpgradeUnknown
		}
	}
	if currentExists && bytes.Equal(current, next) {
		return nil
	}
	f, e := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	if e = acornFoxLiveApplyOwner(s, f, acornFoxInstallPrincipal{s.uid, s.gid}); e == nil {
		midpoint := len(next) / 2
		n, we := f.Write(next[:midpoint])
		e = we
		if e == nil && n != midpoint {
			e = io.ErrShortWrite
		}
		if e == nil {
			e = f.Sync()
		}
		if e == nil && root == s.hostRoot && path != acornFoxUpgradeMarkerPath {
			e = u.fault("host-file-prefix")
		}
		if e == nil {
			n, we = f.Write(next[midpoint:])
			e = we
			if e == nil && n != len(next)-midpoint {
				e = io.ErrShortWrite
			}
		}
	}
	if e == nil {
		e = f.Sync()
	}
	if e == nil && root == s.hostRoot && path != acornFoxUpgradeMarkerPath {
		e = u.fault("host-file-synced")
	}
	if e == nil {
		e = acornFoxLiveApplyOwner(s, f, principal)
	}
	if e == nil {
		e = f.Chmod(mode)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if errors.Is(e, errAcornFoxUpgradeInjectedCrash) {
		return e
	}
	if e != nil || ce != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	// Re-read before replacement. Foreign bytes or inode metadata cannot become
	// overwrite authority just because the transaction holds its own flock.
	again, ae := u.readPrincipal(root, path, mode, acornFoxArchiveMaxBytes, principal)
	if errors.Is(ae, os.ErrNotExist) {
		if current != nil {
			return ErrAcornFoxUpgradeConflict
		}
	} else if ae != nil || !bytes.Equal(again, current) {
		return ErrAcornFoxUpgradeConflict
	}
	if e = root.Rename(temp, path); e != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	if e := acornFoxLiveSyncDir(root, acornFoxUpgradeParent(path)); e != nil {
		return e
	}
	if root == s.hostRoot && path != acornFoxUpgradeMarkerPath {
		return u.fault("host-file-renamed")
	}
	return nil
}
func (u *acornFoxUpgrade) pointer(s *TaskAcornFoxRepoStore, path, old, next string) error {
	root := s.hostRoot
	info, e := root.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		if old != "" {
			return ErrAcornFoxUpgradeConflict
		}
	} else if e != nil || !acornFoxRepoPointerForLayout(root, s, u.layout, path, old, false) && !acornFoxRepoPointerForLayout(root, s, u.layout, path, next, false) {
		return ErrAcornFoxUpgradeConflict
	}
	temp := acornFoxUpgradeTemp(path)
	if ti, te := root.Lstat(temp); te == nil {
		if !acornFoxRepoPointerForLayout(root, s, u.layout, temp, old, false) && !acornFoxRepoPointerForLayout(root, s, u.layout, temp, next, false) {
			return ErrAcornFoxUpgradeConflict
		}
		if acornFoxRepoNlink(ti) != 1 || root.Remove(temp) != nil || acornFoxLiveSyncDir(root, acornFoxUpgradeParent(path)) != nil {
			return ErrAcornFoxUpgradeUnknown
		}
	} else if !errors.Is(te, os.ErrNotExist) {
		return ErrAcornFoxUpgradeConflict
	}
	if e == nil {
		target, te := root.Readlink(path)
		if te == nil && target == next {
			return nil
		}
	}
	if root.Symlink(next, temp) != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	if u.ownership.lchown(root, temp, 0, 0) != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	if info != nil {
		after, ae := root.Lstat(path)
		if ae != nil || !os.SameFile(info, after) {
			return ErrAcornFoxUpgradeConflict
		}
	}
	if root.Rename(temp, path) != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	return acornFoxLiveSyncDir(root, acornFoxUpgradeParent(path))
}
func (u *acornFoxUpgrade) marker(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal, present bool) error {
	raw := []byte(j.Old.Repo.BindingSHA256 + "\n" + j.Next.Repo.BindingSHA256 + "\n")
	got, e := u.read(s.hostRoot, acornFoxUpgradeMarkerPath, 0600, 256)
	if errors.Is(e, os.ErrNotExist) {
		if !present {
			return nil
		}
		return u.atomicFile(s, s.hostRoot, acornFoxUpgradeMarkerPath, nil, raw, 0600)
	}
	if e != nil || !bytes.Equal(got, raw) {
		return ErrAcornFoxUpgradeConflict
	}
	if present {
		return nil
	}
	if s.hostRoot.Remove(acornFoxUpgradeMarkerPath) != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	return acornFoxLiveSyncDir(s.hostRoot, parentDirectory(acornFoxUpgradeMarkerPath))
}
func (u *acornFoxUpgrade) stagePath(binding string) string {
	return filepath.Join(u.layout.hostRootPath, "var/tmp/acornfox-upgrade", binding)
}
func (u *acornFoxUpgrade) stage(ctx context.Context, s *TaskAcornFoxRepoStore, set *acornFoxCandidateSet) (*PublishedAcornFoxSubstrateV1, error) {
	// /var/tmp is a shared OS parent. Only the root-owned 0700 product child and
	// exact SHA directory are writable; neither is accepted as host evidence.
	root := s.hostRoot
	parent := "var/tmp"
	info, e := root.Lstat(parent)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || verifyOwner(info, u.layout.stateOwner.uid, u.layout.stateOwner.gid) != nil {
		return nil, ErrAcornFoxUpgradeConflict
	}
	for _, p := range []string{"var/tmp/acornfox-upgrade", "var/tmp/acornfox-upgrade/" + set.bindingSHA256} {
		if e = u.ensureDirectory(s, root, p, 0700, acornFoxInstallPrincipal{}); e != nil {
			return nil, e
		}
	}
	path := u.stagePath(set.bindingSHA256)
	stager, e := NewTaskAcornFoxStager(path, u.layout.stateOwner.uid, u.layout.stateOwner.gid)
	if e != nil {
		return nil, e
	}
	defer stager.Close()
	pub, e := NewTaskAcornFoxSubstratePublisher(path, u.layout.stateOwner.uid, u.layout.stateOwner.gid)
	if e != nil {
		return nil, e
	}
	defer pub.Close()
	inspect, e := pub.Inspect(set.bindingSHA256)
	if e != nil {
		return nil, e
	}
	switch inspect.Outcome {
	case AcornFoxReconcileAbsent:
		input, e := set.stageInput()
		if e != nil {
			return nil, e
		}
		stage, _, e := stager.Stage(input)
		if e != nil {
			return nil, e
		}
		defer stage.Close()
		if _, e = pub.Publish(ctx, &stage, set.bindingSHA256); e != nil {
			return nil, e
		}
	case AcornFoxReconcileResume:
		if _, e = pub.Resume(ctx, set.bindingSHA256); e != nil {
			return nil, e
		}
	case AcornFoxReconcileCompleted:
	default:
		return nil, ErrAcornFoxUpgradeConflict
	}
	return pub.Reopen(set.bindingSHA256)
}
func (u *acornFoxUpgrade) openSubstrate(root *os.Root, image acornFoxUpgradeImage) (*PublishedAcornFoxSubstrateV1, error) {
	h := &PublishedAcornFoxSubstrateV1{root: root, receipt: image.Substrate, uid: u.layout.stateOwner.uid, gid: u.layout.stateOwner.gid, layout: u.layout, fs: newAcornFoxSubstrateFS()}
	if image.Substrate.CandidateReceipt.MigrationVersion == AcornFoxLegacyPredecessorMigration {
		binding, err := verifiedAcornFoxUpgradePredecessor(image.Binding, image.Repo.BindingSHA256)
		if err != nil || validateAcornFoxLegacy0034SubstrateReceipt(image.Substrate, binding.binding, binding.digest) != nil {
			root.Close()
			return nil, ErrAcornFoxUpgradeConflict
		}
		for _, entry := range image.Substrate.Entries {
			if entry.Kind == SubstrateEntryFile {
				if _, err := acornFoxLiveReadSource(root, h, entry); err != nil {
					root.Close()
					return nil, ErrAcornFoxUpgradeConflict
				}
			}
		}
		return h, nil
	}
	if image.Substrate.CandidateReceipt.MigrationVersion == acornFoxRecentPredecessorMigration && AcornFoxV1MigrationVersion != acornFoxRecentPredecessorMigration {
		binding, err := verifiedAcornFoxUpgradePredecessor(image.Binding, image.Repo.BindingSHA256)
		if err != nil || validateAcornFoxRecent0039SubstrateReceipt(image.Substrate, binding.binding, binding.digest) != nil {
			root.Close()
			return nil, ErrAcornFoxUpgradeConflict
		}
		for _, entry := range image.Substrate.Entries {
			if entry.Kind == SubstrateEntryFile {
				if _, err := acornFoxLiveReadSource(root, h, entry); err != nil {
					root.Close()
					return nil, ErrAcornFoxUpgradeConflict
				}
			}
		}
		return h, nil
	}
	if e := h.Verify(); e != nil {
		root.Close()
		return nil, ErrAcornFoxUpgradeConflict
	}
	return h, nil
}
func (u *acornFoxUpgrade) locateSubstrate(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal, image acornFoxUpgradeImage) (*PublishedAcornFoxSubstrateV1, error) {
	stash := "upgrade/new-state"
	if image.Repo.BindingSHA256 == j.Old.Repo.BindingSHA256 {
		stash = "upgrade/old-state"
	}
	for _, path := range []string{".", stash} {
		info, e := s.root.Lstat(path)
		if e != nil {
			continue
		}
		if !safeAcornFoxRepoDir(info, s.uid, s.gid) {
			return nil, ErrAcornFoxUpgradeConflict
		}
		root, e := s.root.OpenRoot(path)
		if e != nil {
			continue
		}
		h, e := u.openSubstrate(root, image)
		if e == nil {
			return h, nil
		}
	}
	// Next construction source is a fixed SHA-derived private task artifact. It
	// may be read for recovery, but its layout is never accepted as host evidence.
	if image.Repo.BindingSHA256 == j.Next.Repo.BindingSHA256 {
		root, e := u.openStageRoot(s, image.Repo.BindingSHA256)
		if e == nil {
			return u.openSubstrate(root, image)
		}
	}
	return nil, ErrAcornFoxUpgradeConflict
}
func (u *acornFoxUpgrade) imageManifest(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal, image acornFoxUpgradeImage) ([]byte, error) {
	h, e := u.locateSubstrate(s, j, image)
	if e != nil {
		return nil, e
	}
	defer h.Close()
	raw, e := u.read(h.root, acornFoxSubstrateRootfs+"/opt/acornfox/releases/"+image.Activation.ReleaseID+"/manifest.json", 0644, acornFoxManifestMaxBytes)
	if e != nil || sha256Hex(raw) != image.Substrate.CandidateReceipt.ManifestSHA256 {
		return nil, ErrAcornFoxUpgradeConflict
	}
	return raw, nil
}

func (u *acornFoxUpgrade) copyNextSubstrate(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal) error {
	if root, e := s.root.OpenRoot("."); e == nil {
		if h, e := u.openSubstrate(root, j.Next); e == nil {
			h.Close()
			return nil
		}
	}
	source, e := u.locateSubstrate(s, j, j.Next)
	if e != nil {
		return e
	}
	defer source.Close()
	for _, p := range []string{"upgrade/new-state", "upgrade/old-state"} {
		if e = u.ensureDirectory(s, s.root, p, 0700, acornFoxInstallPrincipal{}); e != nil {
			return e
		}
	}
	target, e := s.root.OpenRoot("upgrade/new-state")
	if e != nil {
		return e
	}
	defer target.Close()
	entries := []SubstrateEntry{{Path: "substrate", Kind: SubstrateEntryDirectory, Mode: 0700}, {Path: "substrate/rootfs", Kind: SubstrateEntryDirectory, Mode: 0700}}
	rawReceipt := acornFoxUpgradeJSON(j.Next.Substrate)
	for _, p := range []string{acornFoxSubstrateIntent, acornFoxSubstrateReceipt} {
		raw, e := u.read(source.root, p, 0600, acornFoxUpgradeMaxJournal)
		if e != nil {
			return e
		}
		entries = append(entries, SubstrateEntry{Path: p, Kind: SubstrateEntryFile, Mode: 0600, Size: int64(len(raw)), SHA256: sha256Hex(raw)})
	}
	for _, entry := range j.Next.Substrate.Entries {
		entry.Path = acornFoxSubstrateRootfs + "/" + entry.Path
		entries = append(entries, entry)
	}
	entries = append(entries, SubstrateEntry{Path: acornFoxSubstrateRootfs + "/var/lib/acornfox/install/releases/" + j.Next.Activation.ReleaseID + ".json", Kind: SubstrateEntryFile, Mode: 0600, Size: int64(len(rawReceipt)), SHA256: sha256Hex(rawReceipt)})
	sort.Slice(entries, func(a, b int) bool { return entries[a].Path < entries[b].Path })
	for _, entry := range entries {
		if entry.Kind == SubstrateEntryDirectory {
			if e = u.ensureDirectoryPrefix(s, target, entry.Path, os.FileMode(entry.Mode), acornFoxInstallPrincipal{}, true); e != nil {
				return e
			}
			continue
		}
		raw, e := u.read(source.root, entry.Path, os.FileMode(entry.Mode), acornFoxArchiveMaxBytes)
		if e != nil || sha256Hex(raw) != entry.SHA256 {
			return ErrAcornFoxUpgradeConflict
		}
		if e = u.atomicFile(s, target, entry.Path, nil, raw, os.FileMode(entry.Mode)); e != nil {
			return e
		}
	}
	verify, e := s.root.OpenRoot("upgrade/new-state")
	if e != nil {
		return e
	}
	h, e := u.openSubstrate(verify, j.Next)
	if e == nil {
		h.Close()
	}
	return e
}
func (u *acornFoxUpgrade) switchSubstrate(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal, next bool) error {
	desired, other := j.Next, j.Old
	stash, retired := "upgrade/new-state/substrate", "upgrade/old-state/substrate"
	if !next {
		desired, other = j.Old, j.Next
		stash, retired = retired, stash
	}
	if root, e := s.root.OpenRoot("."); e == nil {
		if h, e := u.openSubstrate(root, desired); e == nil {
			h.Close()
			return nil
		}
	}
	if _, e := s.root.Lstat("substrate"); e == nil {
		root, e := s.root.OpenRoot(".")
		if e != nil {
			return e
		}
		h, e := u.openSubstrate(root, other)
		if e != nil {
			return e
		}
		h.Close()
		if _, e = s.root.Lstat(retired); !errors.Is(e, os.ErrNotExist) {
			return ErrAcornFoxUpgradeConflict
		}
		if s.root.Rename("substrate", retired) != nil || acornFoxLiveSyncDir(s.root, ".") != nil || acornFoxLiveSyncDir(s.root, parentDirectory(retired)) != nil {
			return ErrAcornFoxUpgradeUnknown
		}
		if e = u.fault("substrate-retired"); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return ErrAcornFoxUpgradeConflict
	}
	root, e := s.root.OpenRoot(parentDirectory(stash))
	if e != nil {
		return e
	}
	h, e := u.openSubstrate(root, desired)
	if e != nil {
		return e
	}
	h.Close()
	if s.root.Rename(stash, "substrate") != nil || acornFoxLiveSyncDir(s.root, parentDirectory(stash)) != nil || acornFoxLiveSyncDir(s.root, ".") != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	return nil
}

// Closed snapshots authorize only two possible values for each fixed file.
// Files that exist solely in a versioned release/activation are retained even
// after rollback; unrelated service-owned data directories are never walked.
func (u *acornFoxUpgrade) imageFiles(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal, image acornFoxUpgradeImage) (map[string][]byte, map[string]os.FileMode, error) {
	h, e := u.locateSubstrate(s, j, image)
	if e != nil {
		return nil, nil, e
	}
	defer h.Close()
	files := map[string][]byte{}
	modes := map[string]os.FileMode{}
	entries, e := acornFoxLiveExpectedEntriesForLayout(u.layout, h)
	if image.Substrate.CandidateReceipt.MigrationVersion == AcornFoxLegacyPredecessorMigration {
		entries, e = acornFoxLegacy0034ExpectedEntries(u.layout, image.Substrate)
	} else if image.Substrate.CandidateReceipt.MigrationVersion == acornFoxRecentPredecessorMigration && AcornFoxV1MigrationVersion != acornFoxRecentPredecessorMigration {
		entries, e = acornFoxRecent0039ExpectedEntries(u.layout, image.Substrate)
	}
	if e != nil {
		return nil, nil, e
	}
	for _, entry := range entries {
		if entry.Kind != SubstrateEntryFile {
			continue
		}
		raw, e := acornFoxLiveReadSource(h.root, h, entry)
		if e != nil {
			return nil, nil, e
		}
		files[entry.Path] = raw
		modes[entry.Path] = os.FileMode(entry.Mode)
	}
	state := "var/lib/acornfox/install/"
	for p, v := range map[string]any{state + acornFoxRepoInstallJournal: image.Repo, state + "live-receipt.json": image.Live, state + acornFoxControlPlaneReceipt: image.ControlPlane, state + acornFoxRuntimeIntentName: image.Runtime, state + acornFoxRuntimeReceiptName: image.Runtime.receipt(acornFoxUpgradeJSON(image.Runtime)), u.layout.activationReceiptPath(image.Activation.ActivationID): image.Activation} {
		files[p] = acornFoxUpgradeJSON(v)
		modes[p] = 0600
	}
	files[state+"bindings/"+image.Repo.BindingSHA256+".json"] = image.Binding
	modes[state+"bindings/"+image.Repo.BindingSHA256+".json"] = 0600
	env := bytes.Clone(image.DatabaseEnv)
	if len(env) == 0 {
		env, e = u.read(s.root, acornFoxControlPlaneStateEnv, 0600, 16384)
		if e != nil {
			return nil, nil, ErrAcornFoxUpgradeConflict
		}
	}
	database, databaseErr := acornFoxControlPlaneDatabaseName(env)
	if databaseErr != nil || !validAcornFoxBoundControlPlaneEnvironment(env, image.ControlPlane, database) {
		return nil, nil, ErrAcornFoxUpgradeConflict
	}
	files[u.layout.activationDir(image.Activation.ActivationID)+"/database.env"] = env
	modes[u.layout.activationDir(image.Activation.ActivationID)+"/database.env"] = 0600
	if len(image.DatabaseEnv) != 0 {
		files[state+acornFoxControlPlaneStateEnv] = env
		modes[state+acornFoxControlPlaneStateEnv] = 0600
	}
	for _, f := range image.Runtime.Files {
		p := strings.TrimPrefix(f.Path, "/")
		files[p] = f.Data
		modes[p] = os.FileMode(f.Mode)
	}
	return files, modes, nil
}
func (u *acornFoxUpgrade) applyImage(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal, next bool) error {
	old, om, e := u.imageFiles(s, j, j.Old)
	if e != nil {
		return e
	}
	new, nm, e := u.imageFiles(s, j, j.Next)
	if e != nil {
		return e
	}
	h, e := u.locateSubstrate(s, j, j.Next)
	if e != nil {
		return e
	}
	defer h.Close()
	entries, e := acornFoxLiveExpectedEntriesForLayout(u.layout, h)
	if e != nil {
		return e
	}
	// Only new immutable release directories may be created. Every shared or
	// service data directory must already have the recorded role and mode.
	for _, entry := range entries {
		if entry.Kind != SubstrateEntryDirectory || acornFoxProductionSharedParent(entry.Path) {
			continue
		}
		prefix := "opt/acornfox/releases/" + j.Next.Activation.ReleaseID
		if entry.Path == prefix || strings.HasPrefix(entry.Path, prefix+"/") {
			if e = u.ensureDirectoryPrefix(s, s.hostRoot, entry.Path, os.FileMode(entry.Mode), acornFoxLivePrincipalForEntry(u.layout, entry), true); e != nil {
				return e
			}
		} else if !acornFoxProductionEntryMatches(s.hostRoot, s, entry.Path, entry) {
			return ErrAcornFoxUpgradeConflict
		}
	}
	if e = u.ensureDirectoryPrefix(s, s.hostRoot, u.layout.activationDir(j.Next.Activation.ActivationID), u.layout.activationDirectoryMode(), acornFoxInstallPrincipal{}, true); e != nil {
		return e
	}

	principals := map[string]acornFoxInstallPrincipal{}
	for _, entry := range entries {
		if entry.Kind == SubstrateEntryFile {
			principals[entry.Path] = acornFoxLivePrincipalForEntry(u.layout, entry)
		}
	}
	keys := make([]string, 0, len(new))
	for p := range new {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	for _, p := range keys {
		wanted := new[p]
		mode := nm[p]
		if !next && old[p] != nil {
			wanted = old[p]
			mode = om[p]
		}
		if e = u.atomicFileOwned(s, s.hostRoot, p, old[p], wanted, mode, principals[p]); e != nil {
			// During rollback current may already be the new exact bytes.
			if next || old[p] == nil || u.atomicFileOwned(s, s.hostRoot, p, new[p], wanted, mode, principals[p]) != nil {
				return e
			}
		}
		if e = u.fault("file-published"); e != nil {
			return e
		}
	}
	return u.pointer(s, u.layout.activationReleasePath(j.Next.Activation.ActivationID), "", "../../releases/"+j.Next.Activation.ReleaseID)
}

func (u *acornFoxUpgrade) openStageRoot(s *TaskAcornFoxRepoStore, binding string) (*os.Root, error) {
	if !validSHA(binding) {
		return nil, ErrAcornFoxUpgradeConflict
	}
	for _, path := range []string{"var/tmp/acornfox-upgrade", "var/tmp/acornfox-upgrade/" + binding} {
		info, e := s.hostRoot.Lstat(path)
		if e != nil || !safeAcornFoxRepoDir(info, s.uid, s.gid) {
			return nil, ErrAcornFoxUpgradeConflict
		}
	}
	before, e := s.hostRoot.Lstat("var/tmp/acornfox-upgrade/" + binding)
	if e != nil {
		return nil, e
	}
	root, e := os.OpenRoot(u.stagePath(binding))
	if e != nil {
		return nil, e
	}
	opened, e := root.Stat(".")
	if e != nil || !os.SameFile(before, opened) {
		root.Close()
		return nil, ErrAcornFoxUpgradeConflict
	}
	return root, nil
}
