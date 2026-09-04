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
	acornFoxRepoInstallLock    = ".acornfox-repo-install.lock"
	acornFoxRepoInstallDir     = "repo-install"
	acornFoxRepoInstallJournal = "repo-install/journal.json"
	acornFoxRepoMaxJournalSize = 1 << 20
)

// TaskAcornFoxRepoStore is task-root-only.  It persists the closed 04A
// repository journal and has no host, service, container, database, network,
// current, active, account, unit, or version input.
type TaskAcornFoxRepoStore struct {
	rootPath string
	rootInfo os.FileInfo
	root     *os.Root
	uid, gid int
	fs       acornFoxRepoFS
	lock     *acornFoxRepoStoreLock

	// afterRootPathCheck is a package-private race seam. The descriptor held by
	// root remains the authority after this hook runs.
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

type acornFoxRepoFS struct {
	lstatPath func(string) (os.FileInfo, error)
	openRoot  func(string) (*os.Root, error)
	openChild func(*os.Root, string) (*os.Root, error)
	lstat     func(*os.Root, string) (os.FileInfo, error)
	openFile  func(*os.Root, string, int, os.FileMode) (acornFoxRepoFile, error)
	mkdir     func(*os.Root, string, os.FileMode) error
	flock     func(acornFoxRepoFile, int) error
}

func newAcornFoxRepoFS() acornFoxRepoFS {
	return acornFoxRepoFS{
		lstatPath: os.Lstat,
		openRoot:  os.OpenRoot,
		openChild: func(root *os.Root, name string) (*os.Root, error) { return root.OpenRoot(name) },
		lstat:     func(root *os.Root, name string) (os.FileInfo, error) { return root.Lstat(name) },
		openFile: func(root *os.Root, name string, flags int, mode os.FileMode) (acornFoxRepoFile, error) {
			return root.OpenFile(name, flags, mode)
		},
		mkdir: func(root *os.Root, name string, mode os.FileMode) error { return root.Mkdir(name, mode) },
		flock: func(file acornFoxRepoFile, operation int) error { return syscall.Flock(int(file.Fd()), operation) },
	}
}

// NewTaskAcornFoxRepoStore accepts only an already-existing safe task root.
// It pins that root by inode; later path replacement is a conflict, never a
// reason to reopen the replacement by pathname.
func NewTaskAcornFoxRepoStore(taskRoot string, uid, gid int) (*TaskAcornFoxRepoStore, error) {
	fs := newAcornFoxRepoFS()
	if uid < 0 || gid < 0 || !safeAcornFoxRepoTaskRootPath(taskRoot) {
		return nil, ErrAcornFoxRepoConflict
	}
	info, err := fs.lstatPath(taskRoot)
	if err != nil || !safeAcornFoxRepoRootInfo(info, uid, gid) {
		return nil, ErrAcornFoxRepoConflict
	}
	root, err := fs.openRoot(taskRoot)
	if err != nil {
		return nil, ErrAcornFoxRepoConflict
	}
	return &TaskAcornFoxRepoStore{rootPath: taskRoot, rootInfo: info, root: root, uid: uid, gid: gid, fs: fs}, nil
}

func safeAcornFoxRepoTaskRootPath(path string) bool {
	return safeAbsoluteDurableRoot(path) && filepath.Clean(path) != string(filepath.Separator)
}

func safeAcornFoxRepoRootInfo(info os.FileInfo, uid, gid int) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 == 0 && verifyOwner(info, uid, gid) == nil
}

func safeAcornFoxRepoDirectoryInfo(info os.FileInfo, uid, gid int) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == durableDirMode && verifyOwner(info, uid, gid) == nil
}

func safeAcornFoxRepoFileInfo(info os.FileInfo, uid, gid int) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == durableFileMode && acornFoxRepoNlink(info) == 1 && verifyOwner(info, uid, gid) == nil
}

func acornFoxRepoNlink(info os.FileInfo) uint64 {
	if info == nil {
		return 0
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink < 0 {
		return 0
	}
	return uint64(stat.Nlink)
}

func (s *TaskAcornFoxRepoStore) openRoot() (*os.Root, error) {
	if s == nil || s.root == nil || s.rootInfo == nil {
		return nil, ErrAcornFoxRepoConflict
	}
	info, err := s.fs.lstatPath(s.rootPath)
	if err != nil || !safeAcornFoxRepoRootInfo(info, s.uid, s.gid) || !os.SameFile(info, s.rootInfo) {
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
	if s.lock != nil {
		if err := s.lock.Release(); err != nil {
			return ErrAcornFoxRepoConflict
		}
	}
	root := s.root
	s.root, s.rootInfo = nil, nil
	if root == nil {
		return nil
	}
	if err := root.Close(); err != nil {
		return ErrAcornFoxRepoConflict
	}
	return nil
}

type AcornFoxRepoStoreLock interface{ Release() error }

type acornFoxRepoStoreLock struct {
	store *TaskAcornFoxRepoStore
	file  acornFoxRepoFile
}

// Acquire holds the fixed task-local lock.  There is no caller-selected lock
// name and no production constructor.
func (s *TaskAcornFoxRepoStore) Acquire(ctx context.Context) (AcornFoxRepoStoreLock, error) {
	if ctx == nil || ctx.Err() != nil || s == nil || s.lock != nil {
		return nil, ErrAcornFoxRepoConflict
	}
	root, err := s.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, statErr := s.fs.lstat(root, acornFoxRepoInstallLock)
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
		info, statErr = s.fs.lstat(root, acornFoxRepoInstallLock)
		if statErr == nil {
			file, err = s.fs.openFile(root, acornFoxRepoInstallLock, os.O_RDWR|syscall.O_NOFOLLOW, durableFileMode)
		}
	}
	if err != nil {
		return nil, ErrAcornFoxRepoConflict
	}
	if created {
		err = file.Chmod(durableFileMode)
		if err == nil {
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
	if err != nil || statErr != nil && !created || openedErr != nil || !safeAcornFoxRepoFileInfo(opened, s.uid, s.gid) || (!created && (!safeAcornFoxRepoFileInfo(info, s.uid, s.gid) || !os.SameFile(info, opened))) {
		_ = file.Close()
		return nil, ErrAcornFoxRepoConflict
	}
	if err := s.fs.flock(file, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
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
	unlockErr := store.fs.flock(file, syscall.LOCK_UN)
	closeErr := file.Close()
	if unlockErr != nil || closeErr != nil {
		return ErrAcornFoxRepoConflict
	}
	return nil
}

func (s *TaskAcornFoxRepoStore) ownsLock() bool {
	return s != nil && s.lock != nil && s.lock.file != nil
}

func (s *TaskAcornFoxRepoStore) ensureJournalDirectory(root *os.Root) error {
	info, err := s.fs.lstat(root, acornFoxRepoInstallDir)
	created := errors.Is(err, os.ErrNotExist)
	if err != nil && !created {
		return ErrAcornFoxRepoConflict
	}
	if created {
		if err := s.fs.mkdir(root, acornFoxRepoInstallDir, durableDirMode); err != nil && !errors.Is(err, os.ErrExist) {
			return ErrAcornFoxRepoConflict
		}
		info, err = s.fs.lstat(root, acornFoxRepoInstallDir)
	}
	if err != nil || !safeAcornFoxRepoDirectoryInfo(info, s.uid, s.gid) {
		return ErrAcornFoxRepoConflict
	}
	if created && s.syncDirectory(root, ".") != nil {
		return ErrAcornFoxRepoConflict
	}
	return nil
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

// Load is read-only and validates the fixed journal path through the pinned
// root. It never creates a directory, a lock, or any host-facing state.
func (s *TaskAcornFoxRepoStore) Load(ctx context.Context) (AcornFoxRepoJournalV1, error) {
	if ctx == nil || ctx.Err() != nil {
		return AcornFoxRepoJournalV1{}, ErrAcornFoxRepoConflict
	}
	root, err := s.openRoot()
	if err != nil {
		return AcornFoxRepoJournalV1{}, err
	}
	defer root.Close()
	return s.loadLocked(root)
}

// Resume is deliberately only a fresh disk observation.  Recovery remains
// represented by NeedsRecovery at the last confirmed phase; this store does
// not infer or perform any host-side action.
func (s *TaskAcornFoxRepoStore) Resume(ctx context.Context) (AcornFoxRepoJournalV1, error) {
	return s.Load(ctx)
}

func (s *TaskAcornFoxRepoStore) loadLocked(root *os.Root) (AcornFoxRepoJournalV1, error) {
	if s == nil || root == nil {
		return AcornFoxRepoJournalV1{}, ErrAcornFoxRepoConflict
	}
	info, err := s.fs.lstat(root, acornFoxRepoInstallJournal)
	if err != nil || !safeAcornFoxRepoFileInfo(info, s.uid, s.gid) || info.Size() < 1 || info.Size() > acornFoxRepoMaxJournalSize {
		return AcornFoxRepoJournalV1{}, ErrAcornFoxRepoConflict
	}
	file, err := s.fs.openFile(root, acornFoxRepoInstallJournal, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return AcornFoxRepoJournalV1{}, ErrAcornFoxRepoConflict
	}
	opened, statErr := file.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(file, acornFoxRepoMaxJournalSize+1))
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !safeAcornFoxRepoFileInfo(opened, s.uid, s.gid) || !os.SameFile(info, opened) || len(raw) < 1 || len(raw) > acornFoxRepoMaxJournalSize {
		return AcornFoxRepoJournalV1{}, ErrAcornFoxRepoConflict
	}
	journal, err := ParseAcornFoxRepoJournalV1(raw)
	if err != nil {
		return AcornFoxRepoJournalV1{}, ErrAcornFoxRepoConflict
	}
	return journal, nil
}

// Create makes the fixed journal once. A concurrent or retried first create
// is accepted only when the durable object is byte-for-byte the same valid
// initial journal; all other existing objects are conflicts.
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
	if err := s.ensureJournalDirectory(root); err != nil {
		return err
	}
	file, err := s.fs.openFile(root, acornFoxRepoInstallJournal, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, durableFileMode)
	if errors.Is(err, os.ErrExist) {
		observed, loadErr := s.loadLocked(root)
		if loadErr == nil && sameAcornFoxRepoJournal(observed, journal) {
			return nil
		}
		return ErrAcornFoxRepoConflict
	}
	if err != nil {
		return ErrAcornFoxRepoConflict
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
	if err == nil {
		err = s.syncDirectory(root, acornFoxRepoInstallDir)
	}
	if err != nil {
		return s.reconcileExactJournal(root, journal)
	}
	return s.reconcileExactJournal(root, journal)
}

func acornFoxRepoInitialJournal(journal AcornFoxRepoJournalV1) bool {
	return journal.Validate() == nil && journal.Revision == 1 && journal.Phase == AcornFoxRepoPrepared && !journal.NeedsRecovery && journal.Failure == nil && len(journal.History) == 1 && journal.SubstrateReceiptSHA256 == "" && journal.LiveTreeSHA256 == "" && journal.OwnershipPlanSHA256 == "" && journal.StaticSetSHA256 == "" && journal.ActivationSHA256 == "" && journal.ActivePointerSHA256 == "" && journal.CurrentPointerSHA256 == ""
}

// Save implements revision CAS while the fixed flock is held. It does not
// replace the journal path or accept a caller-selected path. Any uncertain
// write is resolved only by a fresh exact readback of the fixed inode.
func (s *TaskAcornFoxRepoStore) Save(ctx context.Context, next AcornFoxRepoJournalV1) error {
	if ctx == nil || ctx.Err() != nil || !s.ownsLock() || next.Validate() != nil {
		return ErrAcornFoxRepoConflict
	}
	root, err := s.openRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	old, err := s.loadLocked(root)
	if err != nil || !validAcornFoxRepoSave(old, next) {
		return ErrAcornFoxRepoConflict
	}
	raw, err := MarshalAcornFoxRepoJournalV1(next)
	if err != nil {
		return ErrAcornFoxRepoConflict
	}
	info, err := s.fs.lstat(root, acornFoxRepoInstallJournal)
	if err != nil || !safeAcornFoxRepoFileInfo(info, s.uid, s.gid) {
		return ErrAcornFoxRepoConflict
	}
	file, err := s.fs.openFile(root, acornFoxRepoInstallJournal, os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, durableFileMode)
	if err != nil {
		return ErrAcornFoxRepoConflict
	}
	opened, statErr := file.Stat()
	if statErr != nil || !safeAcornFoxRepoFileInfo(opened, s.uid, s.gid) || !os.SameFile(info, opened) {
		_ = file.Close()
		return ErrAcornFoxRepoConflict
	}
	err = writeAcornFoxRepoAll(file, raw)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = s.syncDirectory(root, acornFoxRepoInstallDir)
	}
	if err != nil {
		return s.reconcileExactJournal(root, next)
	}
	return s.reconcileExactJournal(root, next)
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

func (s *TaskAcornFoxRepoStore) reconcileExactJournal(root *os.Root, want AcornFoxRepoJournalV1) error {
	observed, err := s.loadLocked(root)
	if err == nil && sameAcornFoxRepoJournal(observed, want) {
		return nil
	}
	return ErrAcornFoxRepoConflict
}

func validAcornFoxRepoSave(old, next AcornFoxRepoJournalV1) bool {
	if next.Revision != old.Revision+1 || next.SchemaVersion != old.SchemaVersion || next.TransactionID != old.TransactionID || next.BindingSHA256 != old.BindingSHA256 || len(next.History) != len(old.History)+1 {
		return false
	}
	for index := range old.History {
		if old.History[index] != next.History[index] {
			return false
		}
	}
	entry := next.History[len(old.History)]
	if entry.Revision != next.Revision || entry.From != old.Phase || entry.To != next.Phase || ValidateAcornFoxRepoTransition(old.Phase, next.Phase) != nil || !preservesAcornFoxRepoEvidence(old, next) {
		return false
	}
	if next.Phase == old.Phase {
		if next.NeedsRecovery && next.Failure != nil {
			return entry.EvidenceSHA256 == next.Failure.Digest
		}
		return entry.EvidenceSHA256 == old.History[len(old.History)-1].EvidenceSHA256
	}
	return entry.EvidenceSHA256 == acornFoxRepoPhaseEvidence(next, next.Phase)
}

func preservesAcornFoxRepoEvidence(old, next AcornFoxRepoJournalV1) bool {
	for _, pair := range [][2]string{
		{old.SubstrateReceiptSHA256, next.SubstrateReceiptSHA256}, {old.LiveTreeSHA256, next.LiveTreeSHA256}, {old.OwnershipPlanSHA256, next.OwnershipPlanSHA256}, {old.StaticSetSHA256, next.StaticSetSHA256}, {old.ActivationSHA256, next.ActivationSHA256}, {old.ActivePointerSHA256, next.ActivePointerSHA256}, {old.CurrentPointerSHA256, next.CurrentPointerSHA256},
	} {
		if pair[0] != "" && pair[0] != pair[1] {
			return false
		}
	}
	return true
}

func acornFoxRepoPhaseEvidence(journal AcornFoxRepoJournalV1, phase AcornFoxRepoPhase) string {
	switch phase {
	case AcornFoxRepoPrepared:
		return journal.BindingSHA256
	case AcornFoxRepoLiveMaterialized:
		return journal.LiveTreeSHA256
	case AcornFoxRepoStaticVerified:
		// The static set is the final static verifier output and therefore binds
		// the ownership plan and static verification result at this phase.
		return journal.StaticSetSHA256
	case AcornFoxRepoActivationWritten:
		return journal.ActivationSHA256
	case AcornFoxRepoActivePublished:
		return journal.ActivePointerSHA256
	case AcornFoxRepoCurrentPublished:
		return journal.CurrentPointerSHA256
	case AcornFoxRepoPreparedFinal:
		return journal.SubstrateReceiptSHA256
	default:
		return ""
	}
}

// acornFoxRepoBytesEqual is retained as a narrow package seam for fault tests
// that need to distinguish canonical byte identity from decoded equality.
func acornFoxRepoBytesEqual(left, right []byte) bool { return bytes.Equal(left, right) }
