package install

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

var (
	ErrAcornFoxRepoConflict = errors.New("AcornFox repository install conflicts with task state")
	ErrAcornFoxRepoLocked   = errors.New("AcornFox repository install is locked")
)

const (
	acornFoxRepoInstallLock     = ".acornfox-repo-install.lock"
	acornFoxRepoInstallDir      = "repo-install"
	acornFoxRepoInstallJournal  = "repo-install/journal.json"
	acornFoxRepoCreateTemporary = "repo-install/.journal.create.tmp"
	acornFoxRepoSaveTemporary   = "repo-install/.journal.save.tmp"
	acornFoxRepoMaxJournalSize  = 1 << 20
)

// TaskAcornFoxRepoStore is a pinned task-root journal store. Its only mutable
// data entries are the fixed lock and the repository journal surface.
type TaskAcornFoxRepoStore struct {
	rootPath           string
	rootInfo           os.FileInfo
	root               *os.Root
	uid, gid           int
	fs                 acornFoxRepoFS
	lock               *acornFoxRepoStoreLock
	afterRootPathCheck func()
}

type acornFoxRepoFile interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Stat() (os.FileInfo, error)
	Sync() error
	Close() error
	Chmod(os.FileMode) error
	Chown(int, int) error
	Fd() uintptr
}

// acornFoxRepoFS is a narrow private fault seam for exact persistence-boundary
// tests. It does not expose a reusable installer abstraction.
type acornFoxRepoFS struct {
	lstatPath func(string) (os.FileInfo, error)
	openRoot  func(string) (*os.Root, error)
	openChild func(*os.Root, string) (*os.Root, error)
	lstat     func(*os.Root, string) (os.FileInfo, error)
	openFile  func(*os.Root, string, int, os.FileMode) (acornFoxRepoFile, error)
	mkdir     func(*os.Root, string, os.FileMode) error
	link      func(*os.Root, string, string) error
	rename    func(*os.Root, string, string) error
	remove    func(*os.Root, string) error
	flock     func(acornFoxRepoFile, int) error
}

func newAcornFoxRepoFS() acornFoxRepoFS {
	return acornFoxRepoFS{
		lstatPath: os.Lstat, openRoot: os.OpenRoot,
		openChild: func(root *os.Root, name string) (*os.Root, error) { return root.OpenRoot(name) },
		lstat:     func(root *os.Root, name string) (os.FileInfo, error) { return root.Lstat(name) },
		openFile: func(root *os.Root, name string, flags int, mode os.FileMode) (acornFoxRepoFile, error) {
			return root.OpenFile(name, flags, mode)
		},
		mkdir:  func(root *os.Root, name string, mode os.FileMode) error { return root.Mkdir(name, mode) },
		link:   func(root *os.Root, oldName, newName string) error { return root.Link(oldName, newName) },
		rename: func(root *os.Root, oldName, newName string) error { return root.Rename(oldName, newName) },
		remove: func(root *os.Root, name string) error { return root.Remove(name) },
		flock:  func(file acornFoxRepoFile, operation int) error { return syscall.Flock(int(file.Fd()), operation) },
	}
}

func NewTaskAcornFoxRepoStore(taskRoot string, uid, gid int) (*TaskAcornFoxRepoStore, error) {
	fs := newAcornFoxRepoFS()
	if uid < 0 || gid < 0 || !safeAbsoluteDurableRoot(taskRoot) || filepath.Clean(taskRoot) == string(filepath.Separator) {
		return nil, ErrAcornFoxRepoConflict
	}
	info, err := fs.lstatPath(taskRoot)
	if err != nil || !safeAcornFoxRepoRoot(info, uid, gid) {
		return nil, ErrAcornFoxRepoConflict
	}
	root, err := fs.openRoot(taskRoot)
	if err != nil {
		return nil, ErrAcornFoxRepoConflict
	}
	return &TaskAcornFoxRepoStore{rootPath: taskRoot, rootInfo: info, root: root, uid: uid, gid: gid, fs: fs}, nil
}

func safeAcornFoxRepoRoot(info os.FileInfo, uid, gid int) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 == 0 && verifyOwner(info, uid, gid) == nil
}
func safeAcornFoxRepoDir(info os.FileInfo, uid, gid int) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == durableDirMode && verifyOwner(info, uid, gid) == nil
}
func acornFoxRepoNlink(info os.FileInfo) uint64 {
	stat, ok := func() (*syscall.Stat_t, bool) {
		if info == nil {
			return nil, false
		}
		value, ok := info.Sys().(*syscall.Stat_t)
		return value, ok
	}()
	if !ok {
		return 0
	}
	return uint64(stat.Nlink)
}
func safeAcornFoxRepoFile(info os.FileInfo, uid, gid int) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == durableFileMode && acornFoxRepoNlink(info) == 1 && verifyOwner(info, uid, gid) == nil
}
func safeAcornFoxRepoTemporary(info os.FileInfo, uid, gid int) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == durableFileMode && (acornFoxRepoNlink(info) == 1 || acornFoxRepoNlink(info) == 2) && verifyOwner(info, uid, gid) == nil
}

func (s *TaskAcornFoxRepoStore) openRoot() (*os.Root, error) {
	if s == nil || s.root == nil || s.rootInfo == nil {
		return nil, ErrAcornFoxRepoConflict
	}
	info, err := s.fs.lstatPath(s.rootPath)
	if err != nil || !safeAcornFoxRepoRoot(info, s.uid, s.gid) || !os.SameFile(info, s.rootInfo) {
		return nil, ErrAcornFoxRepoConflict
	}
	if s.afterRootPathCheck != nil {
		s.afterRootPathCheck()
	}
	root, err := s.fs.openChild(s.root, ".")
	if err != nil {
		return nil, ErrAcornFoxRepoConflict
	}
	return root, nil
}
func (s *TaskAcornFoxRepoStore) Close() error {
	if s == nil {
		return nil
	}
	if s.lock != nil && s.lock.Release() != nil {
		return ErrAcornFoxRepoConflict
	}
	root := s.root
	s.root, s.rootInfo = nil, nil
	if root != nil && root.Close() != nil {
		return ErrAcornFoxRepoConflict
	}
	return nil
}

type AcornFoxRepoStoreLock interface{ Release() error }
type acornFoxRepoStoreLock struct {
	store *TaskAcornFoxRepoStore
	file  acornFoxRepoFile
}

func (s *TaskAcornFoxRepoStore) Acquire(ctx context.Context) (AcornFoxRepoStoreLock, error) {
	if ctx == nil || ctx.Err() != nil || s == nil || s.lock != nil {
		return nil, ErrAcornFoxRepoConflict
	}
	root, err := s.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	before, statErr := s.fs.lstat(root, acornFoxRepoInstallLock)
	created := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !created {
		return nil, ErrAcornFoxRepoConflict
	}
	flags := os.O_RDWR | syscall.O_NOFOLLOW
	if created {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := s.fs.openFile(root, acornFoxRepoInstallLock, flags, durableFileMode)
	if created && errors.Is(err, os.ErrExist) {
		created = false
		before, statErr = s.fs.lstat(root, acornFoxRepoInstallLock)
		if statErr == nil {
			file, err = s.fs.openFile(root, acornFoxRepoInstallLock, os.O_RDWR|syscall.O_NOFOLLOW, durableFileMode)
		}
	}
	if err != nil {
		return nil, ErrAcornFoxRepoConflict
	}
	if created {
		if err = file.Chmod(durableFileMode); err == nil {
			err = file.Chown(s.uid, s.gid)
		}
		if err == nil {
			err = file.Sync()
		}
		if err == nil {
			err = s.syncDirectory(root, ".")
		}
	}
	opened, openedErr := file.Stat()
	if err != nil || openedErr != nil || !safeAcornFoxRepoFile(opened, s.uid, s.gid) || (!created && (statErr != nil || !safeAcornFoxRepoFile(before, s.uid, s.gid) || !os.SameFile(before, opened))) {
		_ = file.Close()
		return nil, ErrAcornFoxRepoConflict
	}
	if err = s.fs.flock(file, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrAcornFoxRepoLocked
		}
		return nil, ErrAcornFoxRepoConflict
	}
	lock := &acornFoxRepoStoreLock{store: s, file: file}
	s.lock = lock
	return lock, nil
}
func (l *acornFoxRepoStoreLock) Release() error {
	if l == nil || l.file == nil || l.store == nil || l.store.lock != l {
		return ErrAcornFoxRepoConflict
	}
	file, store := l.file, l.store
	l.file, l.store, store.lock = nil, nil, nil
	if store.fs.flock(file, syscall.LOCK_UN) != nil || file.Close() != nil {
		return ErrAcornFoxRepoConflict
	}
	return nil
}
func (s *TaskAcornFoxRepoStore) ownsLock() bool {
	return s != nil && s.lock != nil && s.lock.file != nil
}

// acornFoxPreparedRepoLease is intentionally package-private authority.  A
// caller cannot supply a root, version, account, unit, or path: the lease pins
// the store descriptor, an exact PREPARED journal, and the verified substrate
// while retaining the store lock until the materializer is finished.
type acornFoxPreparedRepoLease struct {
	store     *TaskAcornFoxRepoStore
	lock      AcornFoxRepoStoreLock
	journal   AcornFoxRepoJournalV1
	substrate *PublishedAcornFoxSubstrateV1
}

// acornFoxLiveVerifiedLease is the only 04C handoff authority. It couples the
// current locked journal, same-root sealed substrate, and fixed live receipt;
// a parsed receipt DTO alone is never authority to continue installation.
type acornFoxLiveVerifiedLease struct {
	prepared *acornFoxPreparedRepoLease
	receipt  AcornFoxLiveReceiptV1
}

func (s *TaskAcornFoxRepoStore) mintLiveVerifiedLease(ctx context.Context, substrate *PublishedAcornFoxSubstrateV1, bindingSHA256 string) (*acornFoxLiveVerifiedLease, error) {
	prepared, err := s.mintPreparedLease(ctx, substrate, bindingSHA256)
	if err != nil {
		return nil, err
	}
	fail := func() (*acornFoxLiveVerifiedLease, error) {
		_ = prepared.Release()
		return nil, ErrAcornFoxRepoConflict
	}
	if prepared.journal.Phase != AcornFoxRepoStaticVerified && prepared.journal.Phase != AcornFoxRepoActivationWritten && prepared.journal.Phase != AcornFoxRepoActivePublished && prepared.journal.Phase != AcornFoxRepoCurrentPublished && prepared.journal.Phase != AcornFoxRepoPreparedFinal {
		return fail()
	}
	root, err := s.openRoot()
	if err != nil {
		return fail()
	}
	defer root.Close()
	raw, err := s.readExactLiveReceipt(root)
	if err != nil {
		return fail()
	}
	receipt, err := ParseAcornFoxLiveReceiptV1(raw)
	if err != nil || receipt.BindingSHA256 != bindingSHA256 || receipt.SubstrateReceiptSHA256 != prepared.journal.SubstrateReceiptSHA256 || receipt.ReleaseID != substrate.receipt.CandidateReceipt.ReleaseID || receipt.LiveTreeSHA256 != prepared.journal.LiveTreeSHA256 || receipt.OwnershipPlanSHA256 != prepared.journal.OwnershipPlanSHA256 || receipt.StaticSetSHA256 != prepared.journal.StaticSetSHA256 {
		return fail()
	}
	entries, err := acornFoxLiveExpectedEntries(substrate)
	// Keep the original sealed full-tree verifier at the 04B handoff. Later
	// phases retain the same entry set but also contain the closed 04C pointer
	// suffix, which is checked by the repository verifier below.
	if err != nil || (prepared.journal.Phase == AcornFoxRepoStaticVerified && !prepared.journal.NeedsRecovery && acornFoxLiveVerifyTarget(root, s, entries, receipt) != nil) || ((prepared.journal.Phase != AcornFoxRepoStaticVerified || prepared.journal.NeedsRecovery) && !acornFoxRepoVerifyPinnedLive(root, s, entries, receipt)) {
		return fail()
	}
	return &acornFoxLiveVerifiedLease{prepared: prepared, receipt: receipt}, nil
}

func (s *TaskAcornFoxRepoStore) readExactLiveReceipt(root *os.Root) ([]byte, error) {
	before, err := s.fs.lstat(root, acornFoxLiveReceipt)
	if err != nil || !safeAcornFoxRepoFile(before, s.uid, s.gid) || before.Size() < 1 || before.Size() > acornFoxRepoMaxJournalSize {
		return nil, ErrAcornFoxRepoConflict
	}
	file, err := s.fs.openFile(root, acornFoxLiveReceipt, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrAcornFoxRepoConflict
	}
	opened, statErr := file.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(file, acornFoxRepoMaxJournalSize+1))
	closeErr := file.Close()
	after, afterErr := s.fs.lstat(root, acornFoxLiveReceipt)
	if statErr != nil || readErr != nil || closeErr != nil || afterErr != nil || !safeAcornFoxRepoFile(opened, s.uid, s.gid) || !safeAcornFoxRepoFile(after, s.uid, s.gid) || !os.SameFile(before, opened) || !os.SameFile(before, after) || len(raw) < 1 || len(raw) > acornFoxRepoMaxJournalSize {
		return nil, ErrAcornFoxRepoConflict
	}
	return raw, nil
}
func (l *acornFoxLiveVerifiedLease) Release() error {
	if l == nil || l.prepared == nil {
		return ErrAcornFoxRepoConflict
	}
	prepared := l.prepared
	l.prepared = nil
	return prepared.Release()
}

func (s *TaskAcornFoxRepoStore) mintPreparedLease(ctx context.Context, substrate *PublishedAcornFoxSubstrateV1, bindingSHA256 string) (*acornFoxPreparedRepoLease, error) {
	if ctx == nil || ctx.Err() != nil || s == nil || substrate == nil || !validSHA(bindingSHA256) || s.ownsLock() {
		return nil, ErrAcornFoxRepoConflict
	}
	lock, err := s.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	fail := func() (*acornFoxPreparedRepoLease, error) { _ = lock.Release(); return nil, ErrAcornFoxRepoConflict }
	journal, err := s.Load(ctx)
	if err != nil || (journal.Phase != AcornFoxRepoPrepared && journal.Phase != AcornFoxRepoLiveMaterialized && journal.Phase != AcornFoxRepoStaticVerified && journal.Phase != AcornFoxRepoActivationWritten && journal.Phase != AcornFoxRepoActivePublished && journal.Phase != AcornFoxRepoCurrentPublished && journal.Phase != AcornFoxRepoPreparedFinal) || journal.BindingSHA256 != bindingSHA256 || substrate.Verify() != nil || !sameAcornFoxLiveTaskRoot(s, substrate) {
		return fail()
	}
	raw, err := MarshalInactiveSubstrateReceiptV1(substrate.receipt)
	if err != nil || sha256Hex(raw) != journal.SubstrateReceiptSHA256 || substrate.receipt.CandidateReceipt.BindingSHA256 != bindingSHA256 {
		return fail()
	}
	return &acornFoxPreparedRepoLease{store: s, lock: lock, journal: journal, substrate: substrate}, nil
}

func (l *acornFoxPreparedRepoLease) Release() error {
	if l == nil || l.lock == nil || l.store == nil || !l.store.ownsLock() {
		return ErrAcornFoxRepoConflict
	}
	lock := l.lock
	l.lock, l.store, l.substrate = nil, nil, nil
	return lock.Release()
}

func (s *TaskAcornFoxRepoStore) syncDirectory(root *os.Root, name string) error {
	file, err := s.fs.openFile(root, name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
func (s *TaskAcornFoxRepoStore) ensureJournalDirectory(root *os.Root) error {
	info, err := s.fs.lstat(root, acornFoxRepoInstallDir)
	created := errors.Is(err, os.ErrNotExist)
	if err != nil && !created {
		return ErrAcornFoxRepoConflict
	}
	if created {
		if err = s.fs.mkdir(root, acornFoxRepoInstallDir, durableDirMode); err != nil && !errors.Is(err, os.ErrExist) {
			return ErrAcornFoxRepoConflict
		}
		info, err = s.fs.lstat(root, acornFoxRepoInstallDir)
	}
	if err != nil || !safeAcornFoxRepoDir(info, s.uid, s.gid) {
		return ErrAcornFoxRepoConflict
	}
	if created && s.syncDirectory(root, ".") != nil {
		return ErrAcornFoxRepoConflict
	}
	return nil
}

// cleanCreateTemporary handles the only legitimate two-link topology: a
// completed no-replace Link whose temporary name has not yet been removed.
// A foreign hard link is never an owned temporary merely because it has the
// same mode and owner.
func (s *TaskAcornFoxRepoStore) cleanCreateTemporary(root *os.Root, want []byte) error {
	info, err := s.fs.lstat(root, acornFoxRepoCreateTemporary)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !safeAcornFoxRepoTemporary(info, s.uid, s.gid) {
		return ErrAcornFoxRepoConflict
	}
	final, finalErr := s.fs.lstat(root, acornFoxRepoInstallJournal)
	if errors.Is(finalErr, os.ErrNotExist) {
		if acornFoxRepoNlink(info) != 1 {
			return ErrAcornFoxRepoConflict
		}
	} else {
		if finalErr != nil || acornFoxRepoNlink(info) != 2 || !safeAcornFoxRepoTemporary(final, s.uid, s.gid) || acornFoxRepoNlink(final) != 2 || !os.SameFile(info, final) || !s.readExactOwnedBytes(root, acornFoxRepoCreateTemporary, want, true) || !s.readExactOwnedBytes(root, acornFoxRepoInstallJournal, want, true) {
			return ErrAcornFoxRepoConflict
		}
	}
	if s.fs.remove(root, acornFoxRepoCreateTemporary) != nil || s.syncDirectory(root, acornFoxRepoInstallDir) != nil {
		return ErrAcornFoxRepoConflict
	}
	if finalErr == nil && !s.readExactOwnedBytes(root, acornFoxRepoInstallJournal, want, false) {
		return ErrAcornFoxRepoConflict
	}
	return nil
}

// Save temporary entries must never have been linked. Any hard-link topology
// before Rename is ambiguous and is deliberately preserved for diagnosis.
func (s *TaskAcornFoxRepoStore) cleanSaveTemporary(root *os.Root) error {
	info, err := s.fs.lstat(root, acornFoxRepoSaveTemporary)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !safeAcornFoxRepoTemporary(info, s.uid, s.gid) || acornFoxRepoNlink(info) != 1 {
		return ErrAcornFoxRepoConflict
	}
	if s.fs.remove(root, acornFoxRepoSaveTemporary) != nil || s.syncDirectory(root, acornFoxRepoInstallDir) != nil {
		return ErrAcornFoxRepoConflict
	}
	return nil
}

func (s *TaskAcornFoxRepoStore) removeKnownSingleTemporary(root *os.Root, name string) error {
	info, err := s.fs.lstat(root, name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !safeAcornFoxRepoTemporary(info, s.uid, s.gid) || acornFoxRepoNlink(info) != 1 {
		return ErrAcornFoxRepoConflict
	}
	if s.fs.remove(root, name) != nil || s.syncDirectory(root, acornFoxRepoInstallDir) != nil {
		return ErrAcornFoxRepoConflict
	}
	return nil
}

func (s *TaskAcornFoxRepoStore) Load(ctx context.Context) (AcornFoxRepoJournalV1, error) {
	if ctx == nil || ctx.Err() != nil {
		return AcornFoxRepoJournalV1{}, ErrAcornFoxRepoConflict
	}
	root, err := s.openRoot()
	if err != nil {
		return AcornFoxRepoJournalV1{}, err
	}
	defer root.Close()
	journal, _, _, err := s.readJournal(root)
	return journal, err
}
func (s *TaskAcornFoxRepoStore) Resume(ctx context.Context) (AcornFoxRepoJournalV1, error) {
	return s.Load(ctx)
}
func (s *TaskAcornFoxRepoStore) readJournal(root *os.Root) (AcornFoxRepoJournalV1, []byte, os.FileInfo, error) {
	info, err := s.fs.lstat(root, acornFoxRepoInstallJournal)
	if err != nil || !safeAcornFoxRepoFile(info, s.uid, s.gid) || info.Size() < 1 || info.Size() > acornFoxRepoMaxJournalSize {
		return AcornFoxRepoJournalV1{}, nil, nil, ErrAcornFoxRepoConflict
	}
	file, err := s.fs.openFile(root, acornFoxRepoInstallJournal, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return AcornFoxRepoJournalV1{}, nil, nil, ErrAcornFoxRepoConflict
	}
	opened, statErr := file.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(file, acornFoxRepoMaxJournalSize+1))
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !safeAcornFoxRepoFile(opened, s.uid, s.gid) || !os.SameFile(info, opened) || len(raw) < 1 || len(raw) > acornFoxRepoMaxJournalSize {
		return AcornFoxRepoJournalV1{}, nil, nil, ErrAcornFoxRepoConflict
	}
	journal, err := ParseAcornFoxRepoJournalV1(raw)
	if err != nil {
		return AcornFoxRepoJournalV1{}, nil, nil, ErrAcornFoxRepoConflict
	}
	return journal, raw, info, nil
}
func (s *TaskAcornFoxRepoStore) readExact(root *os.Root, want AcornFoxRepoJournalV1) bool {
	got, _, _, err := s.readJournal(root)
	return err == nil && sameAcornFoxRepoJournal(got, want)
}
func (s *TaskAcornFoxRepoStore) readExactOwnedBytes(root *os.Root, name string, want []byte, allowDoubleLink bool) bool {
	info, err := s.fs.lstat(root, name)
	if err != nil || (allowDoubleLink && !safeAcornFoxRepoTemporary(info, s.uid, s.gid)) || (!allowDoubleLink && !safeAcornFoxRepoFile(info, s.uid, s.gid)) || info.Size() != int64(len(want)) {
		return false
	}
	file, err := s.fs.openFile(root, name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	opened, statErr := file.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(file, acornFoxRepoMaxJournalSize+1))
	closeErr := file.Close()
	return statErr == nil && readErr == nil && closeErr == nil && os.SameFile(info, opened) && bytes.Equal(raw, want)
}
func writeAcornFoxRepoAll(file acornFoxRepoFile, raw []byte) error {
	for len(raw) > 0 {
		n, err := file.Write(raw)
		if n < 0 || n > len(raw) {
			return ErrAcornFoxRepoConflict
		}
		raw = raw[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func (s *TaskAcornFoxRepoStore) writeTemporary(root *os.Root, name string, raw []byte) error {
	file, err := s.fs.openFile(root, name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, durableFileMode)
	if err != nil {
		return err
	}
	if err = file.Chmod(durableFileMode); err == nil {
		err = file.Chown(s.uid, s.gid)
	}
	if err == nil {
		err = writeAcornFoxRepoAll(file, raw)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	info, err := s.fs.lstat(root, name)
	if err != nil || !safeAcornFoxRepoTemporary(info, s.uid, s.gid) || info.Size() != int64(len(raw)) {
		return ErrAcornFoxRepoConflict
	}
	file, err = s.fs.openFile(root, name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrAcornFoxRepoConflict
	}
	got, readErr := io.ReadAll(io.LimitReader(file, acornFoxRepoMaxJournalSize+1))
	closeErr = file.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, raw) {
		return ErrAcornFoxRepoConflict
	}
	return nil
}

func (s *TaskAcornFoxRepoStore) Create(ctx context.Context, journal AcornFoxRepoJournalV1) error {
	if ctx == nil || ctx.Err() != nil || !s.ownsLock() || !acornFoxRepoInitialJournal(journal) {
		return ErrAcornFoxRepoConflict
	}
	raw, err := MarshalAcornFoxRepoJournalV1(journal)
	if err != nil {
		return ErrAcornFoxRepoConflict
	}
	root, err := s.openRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	if err = s.ensureJournalDirectory(root); err != nil {
		return err
	}
	if err = s.cleanCreateTemporary(root, raw); err != nil {
		return err
	}
	if _, finalErr := s.fs.lstat(root, acornFoxRepoInstallJournal); finalErr == nil {
		if s.readExact(root, journal) {
			return nil
		}
		return ErrAcornFoxRepoConflict
	} else if !errors.Is(finalErr, os.ErrNotExist) {
		return ErrAcornFoxRepoConflict
	}
	if err = s.writeTemporary(root, acornFoxRepoCreateTemporary, raw); err != nil {
		return ErrAcornFoxRepoConflict
	}
	if err = s.fs.link(root, acornFoxRepoCreateTemporary, acornFoxRepoInstallJournal); err != nil {
		if s.readExact(root, journal) && s.removeKnownSingleTemporary(root, acornFoxRepoCreateTemporary) == nil {
			return nil
		}
		return ErrAcornFoxRepoConflict
	}
	if err = s.syncDirectory(root, acornFoxRepoInstallDir); err != nil {
		if s.readExact(root, journal) {
			return nil
		}
		return ErrAcornFoxRepoConflict
	}
	if err = s.cleanCreateTemporary(root, raw); err != nil {
		return ErrAcornFoxRepoConflict
	}
	if !s.readExact(root, journal) {
		return ErrAcornFoxRepoConflict
	}
	return nil
}
func acornFoxRepoInitialJournal(j AcornFoxRepoJournalV1) bool {
	return j.Validate() == nil && j.Revision == 1 && j.Phase == AcornFoxRepoPrepared && !j.NeedsRecovery && j.Failure == nil && len(j.History) == 1 && j.LiveTreeSHA256 == "" && j.OwnershipPlanSHA256 == "" && j.StaticSetSHA256 == "" && j.ActivationSHA256 == "" && j.ActivePointerSHA256 == "" && j.CurrentPointerSHA256 == ""
}

func (s *TaskAcornFoxRepoStore) Save(ctx context.Context, next AcornFoxRepoJournalV1) error {
	if ctx == nil || ctx.Err() != nil || !s.ownsLock() || next.Validate() != nil {
		return ErrAcornFoxRepoConflict
	}
	root, err := s.openRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	if err = s.cleanSaveTemporary(root); err != nil {
		return err
	}
	old, oldRaw, oldInfo, err := s.readJournal(root)
	if err != nil || !validAcornFoxRepoSave(old, next) {
		return ErrAcornFoxRepoConflict
	}
	raw, err := MarshalAcornFoxRepoJournalV1(next)
	if err != nil {
		return ErrAcornFoxRepoConflict
	}
	if err = s.writeTemporary(root, acornFoxRepoSaveTemporary, raw); err != nil {
		return ErrAcornFoxRepoConflict
	}
	confirmed, confirmedRaw, confirmedInfo, confirmErr := s.readJournal(root)
	if confirmErr != nil || !sameAcornFoxRepoJournal(confirmed, old) || !bytes.Equal(confirmedRaw, oldRaw) || !os.SameFile(confirmedInfo, oldInfo) {
		return ErrAcornFoxRepoConflict
	}
	if err = s.fs.rename(root, acornFoxRepoSaveTemporary, acornFoxRepoInstallJournal); err != nil {
		if s.readExact(root, next) {
			return nil
		}
		return ErrAcornFoxRepoConflict
	}
	if err = s.syncDirectory(root, acornFoxRepoInstallDir); err != nil {
		if s.readExact(root, next) {
			return nil
		}
		return ErrAcornFoxRepoConflict
	}
	if !s.readExact(root, next) {
		return ErrAcornFoxRepoConflict
	}
	return nil
}
func validAcornFoxRepoSave(old, next AcornFoxRepoJournalV1) bool {
	if next.Revision != old.Revision+1 || next.SchemaVersion != old.SchemaVersion || next.TransactionID != old.TransactionID || next.BindingSHA256 != old.BindingSHA256 || next.SubstrateReceiptSHA256 != old.SubstrateReceiptSHA256 || len(next.History) != len(old.History)+1 {
		return false
	}
	for i := range old.History {
		if old.History[i] != next.History[i] {
			return false
		}
	}
	entry := next.History[len(old.History)]
	if entry.Revision != next.Revision || entry.From != old.Phase || entry.To != next.Phase || !preservesAcornFoxRepoEvidence(old, next) {
		return false
	}
	switch entry.Kind {
	case AcornFoxRepoHistoryAdvance:
		return !old.NeedsRecovery && !next.NeedsRecovery && old.Failure == nil && next.Failure == nil && ValidateAcornFoxRepoTransition(old.Phase, next.Phase) == nil && entry.EvidenceSHA256 == acornFoxRepoPhaseEvidence(next, next.Phase)
	case AcornFoxRepoHistoryFailure:
		return !old.NeedsRecovery && next.NeedsRecovery && old.Failure == nil && next.Failure != nil && next.Phase == old.Phase && entry.EvidenceSHA256 == next.Failure.Digest
	case AcornFoxRepoHistoryRecovered:
		return old.NeedsRecovery && !next.NeedsRecovery && old.Failure != nil && next.Failure == nil && next.Phase == old.Phase
	default:
		return false
	}
}
func preservesAcornFoxRepoEvidence(old, next AcornFoxRepoJournalV1) bool {
	for _, pair := range [][2]string{{old.LiveTreeSHA256, next.LiveTreeSHA256}, {old.OwnershipPlanSHA256, next.OwnershipPlanSHA256}, {old.StaticSetSHA256, next.StaticSetSHA256}, {old.ActivationSHA256, next.ActivationSHA256}, {old.ActivePointerSHA256, next.ActivePointerSHA256}, {old.CurrentPointerSHA256, next.CurrentPointerSHA256}} {
		if pair[0] != "" && pair[0] != pair[1] {
			return false
		}
	}
	return true
}
