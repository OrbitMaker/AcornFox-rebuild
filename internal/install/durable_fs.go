package install

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
)

const (
	durableFileMode       = 0o600
	systemdUnitMode       = 0o644
	durableDirMode        = 0o700
	activationSlotDirMode = 0o711

	upgradeInProgressPath = "var/lib/open-card/upgrade-in-progress"
)

const systemdServerUnitName = "open-card-server.service"

// ErrDurableCommitUnknown means Rename succeeded but fsyncing its parent did
// not. Callers must reread the named object from the same DurableWriter and
// reconcile against their journal; they must not assume the old name survived.
var ErrDurableCommitUnknown = errors.New("durable commit outcome is unknown")

// durableRoot is deliberately narrow so tests can inject every persistence
// boundary without allowing production callers to opt out of root containment.
type durableRoot interface {
	OpenFile(string, int, os.FileMode) (*os.File, error)
	OpenRoot(string) (durableRoot, error)
	Mkdir(string, os.FileMode) error
	Readlink(string) (string, error)
	Rename(string, string) error
	Link(string, string) error
	Remove(string) error
	Symlink(string, string) error
	Lstat(string) (os.FileInfo, error)
	Close() error
}

type osDurableRoot struct{ root *os.Root }

func (r osDurableRoot) OpenFile(name string, flag int, mode os.FileMode) (*os.File, error) {
	return r.root.OpenFile(name, flag, mode)
}
func (r osDurableRoot) OpenRoot(name string) (durableRoot, error) {
	child, err := r.root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return osDurableRoot{root: child}, nil
}
func (r osDurableRoot) Mkdir(name string, mode os.FileMode) error { return r.root.Mkdir(name, mode) }
func (r osDurableRoot) Readlink(name string) (string, error)      { return r.root.Readlink(name) }
func (r osDurableRoot) Rename(oldName, newName string) error      { return r.root.Rename(oldName, newName) }
func (r osDurableRoot) Link(oldName, newName string) error        { return r.root.Link(oldName, newName) }
func (r osDurableRoot) Remove(name string) error                  { return r.root.Remove(name) }
func (r osDurableRoot) Symlink(target, name string) error         { return r.root.Symlink(target, name) }
func (r osDurableRoot) Lstat(name string) (os.FileInfo, error)    { return r.root.Lstat(name) }
func (r osDurableRoot) Close() error                              { return r.root.Close() }

type durableOps interface {
	durableRoot
	Write(*os.File, []byte) (int, error)
	Sync(*os.File) error
	Chmod(*os.File, os.FileMode) error
	Chown(*os.File, int, int) error
	Stat(*os.File) (os.FileInfo, error)
	CloseFile(*os.File) error
	ReadDir(*os.File, int) ([]os.DirEntry, error)
}

type realDurableOps struct{ durableRoot }

func (realDurableOps) Write(file *os.File, value []byte) (int, error) { return file.Write(value) }
func (realDurableOps) Sync(file *os.File) error                       { return file.Sync() }
func (realDurableOps) Chmod(file *os.File, mode os.FileMode) error    { return file.Chmod(mode) }
func (realDurableOps) Chown(file *os.File, uid, gid int) error        { return file.Chown(uid, gid) }
func (realDurableOps) Stat(file *os.File) (os.FileInfo, error)        { return file.Stat() }
func (realDurableOps) CloseFile(file *os.File) error                  { return file.Close() }
func (realDurableOps) ReadDir(file *os.File, count int) ([]os.DirEntry, error) {
	return file.ReadDir(count)
}

// DurableWriter is a fixed-root, ownership-enforcing writer for activation,
// journal and marker metadata. It deliberately has no zero-value constructor.
// Use ProductionDurableWriter for root-owned production metadata or
// TaskDurableWriter only from task-scoped test roots.
type DurableWriter struct {
	ops      durableOps
	uid      int
	gid      int
	rootPath string
	rootInfo os.FileInfo
}

// DurableDirectChild is one direct entry observed below a pinned durable
// root. Mode is descriptive only; callers must reopen a managed entry through
// a typed DurableWriter API before trusting its contents.
type DurableDirectChild struct {
	Name string
	Mode os.FileMode
}

// DurableLock is an advisory process lock opened below a DurableWriter's
// pinned root descriptor. It owns no path and can only be released.
type DurableLock struct {
	mu   sync.Mutex
	file *os.File
}

func (l *DurableLock) Release() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	first := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	if err := file.Close(); err != nil && first == nil {
		first = err
	}
	return first
}

func ProductionDurableWriter(root string) (*DurableWriter, error) {
	return newDurableWriter(root, 0, 0, nil)
}

func TaskDurableWriter(root string, uid, gid int) (*DurableWriter, error) {
	if uid < 0 || gid < 0 {
		return nil, fmt.Errorf("task durable writer owner is invalid")
	}
	return newDurableWriter(root, uid, gid, nil)
}

func newDurableWriter(root string, uid, gid int, injected durableOps) (*DurableWriter, error) {
	if !safeAbsoluteDurableRoot(root) {
		return nil, fmt.Errorf("durable root is unsafe")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("durable root must be a non-symlink non-writable-by-others directory")
	}
	if err := verifyOwner(info, uid, gid); err != nil {
		return nil, err
	}
	if injected != nil {
		return &DurableWriter{ops: injected, uid: uid, gid: gid, rootPath: root, rootInfo: info}, nil
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	rootOps := osDurableRoot{root: opened}
	return &DurableWriter{ops: realDurableOps{durableRoot: rootOps}, uid: uid, gid: gid, rootPath: root, rootInfo: info}, nil
}

// VerifyLiveRoot rejects a pathname replacement after the writer was opened.
// os.Root keeps the old descriptor usable across a rename; accepting it after
// the named root changed would split durable writes from the live deployment.
func (w *DurableWriter) VerifyLiveRoot() error {
	if w == nil || w.ops == nil || w.rootPath == "" || w.rootInfo == nil {
		return fmt.Errorf("durable writer is not initialized")
	}
	info, err := os.Lstat(w.rootPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || !os.SameFile(info, w.rootInfo) {
		return fmt.Errorf("durable root identity changed")
	}
	return verifyOwner(info, w.uid, w.gid)
}

// OpenChildWriter opens one already-existing child directory through this
// writer's pinned descriptor. It deliberately does not reopen an absolute
// path, so a renamed parent cannot redirect slot writes.
func (w *DurableWriter) OpenChildWriter(name string, mode os.FileMode) (*DurableWriter, error) {
	if err := w.VerifyLiveRoot(); err != nil || cleanRelative(name) != nil || strings.Contains(filepath.ToSlash(name), "/") {
		return nil, fmt.Errorf("durable child path is unsafe")
	}
	info, err := w.ops.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != mode || verifyOwner(info, w.uid, w.gid) != nil {
		return nil, fmt.Errorf("durable child directory is unsafe")
	}
	child, err := w.ops.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &DurableWriter{ops: realDurableOps{durableRoot: child}, uid: w.uid, gid: w.gid, rootPath: filepath.Join(w.rootPath, name), rootInfo: info}, nil
}

// ReadDirectChildren enumerates only the pinned root's immediate entries. It
// never reopens rootPath and rechecks the live pathname after enumeration, so
// a rename/replacement cannot redirect reads to another directory.
func (w *DurableWriter) ReadDirectChildren() ([]DurableDirectChild, error) {
	if w == nil || w.ops == nil || w.VerifyLiveRoot() != nil {
		return nil, fmt.Errorf("durable writer is not initialized")
	}
	directory, err := w.ops.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = w.ops.CloseFile(directory)
		}
	}()
	info, err := w.ops.Stat(directory)
	if err != nil || !info.IsDir() || !os.SameFile(info, w.rootInfo) || verifyOwner(info, w.uid, w.gid) != nil {
		return nil, fmt.Errorf("durable root descriptor is unsafe")
	}
	entries, err := w.ops.ReadDir(directory, -1)
	if err != nil {
		return nil, err
	}
	children := make([]DurableDirectChild, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if cleanRelative(name) != nil || strings.Contains(filepath.ToSlash(name), "/") {
			return nil, fmt.Errorf("durable child name is unsafe")
		}
		child, err := w.ops.Lstat(name)
		if err != nil {
			return nil, err
		}
		children = append(children, DurableDirectChild{Name: name, Mode: child.Mode()})
	}
	if err := w.ops.CloseFile(directory); err != nil {
		return nil, err
	}
	closed = true
	if err := w.VerifyLiveRoot(); err != nil {
		return nil, err
	}
	sort.Slice(children, func(i, j int) bool { return children[i].Name < children[j].Name })
	return children, nil
}

// CreateChildDirectory creates one root-relative directory and synchronizes
// the pinned parent before returning. Existing directories are reported, not
// silently reused, so callers must read and reconcile them explicitly.
func (w *DurableWriter) CreateChildDirectory(name string, mode os.FileMode) (bool, error) {
	if err := w.VerifyLiveRoot(); err != nil || cleanRelative(name) != nil || strings.Contains(filepath.ToSlash(name), "/") {
		return false, fmt.Errorf("durable child path is unsafe")
	}
	if err := w.ops.Mkdir(name, mode); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return false, err
		}
		info, statErr := w.ops.Lstat(name)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != mode || verifyOwner(info, w.uid, w.gid) != nil {
			return false, fmt.Errorf("durable child directory is unsafe")
		}
		directory, openErr := w.ops.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			return false, fmt.Errorf("%w: %v", ErrDurableCommitUnknown, openErr)
		}
		directoryInfo, statErr := w.ops.Stat(directory)
		if statErr != nil || directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() || directoryInfo.Mode().Perm() != mode || verifyOwner(directoryInfo, w.uid, w.gid) != nil {
			_ = w.ops.CloseFile(directory)
			return false, fmt.Errorf("%w: durable child directory is unsafe", ErrDurableCommitUnknown)
		}
		if syncErr := w.ops.Sync(directory); syncErr != nil {
			_ = w.ops.CloseFile(directory)
			return false, fmt.Errorf("%w: %v", ErrDurableCommitUnknown, syncErr)
		}
		if closeErr := w.ops.CloseFile(directory); closeErr != nil {
			return false, fmt.Errorf("%w: %v", ErrDurableCommitUnknown, closeErr)
		}
		// A previous call may have published the entry but lost the outcome of
		// its directory or parent fsync. Re-sync both boundaries for an exact
		// existing directory before reporting convergence.
		if syncErr := w.SyncRoot(); syncErr != nil {
			return false, fmt.Errorf("%w: %v", ErrDurableCommitUnknown, syncErr)
		}
		return false, nil
	}
	unknown := func(err error) (bool, error) {
		return false, fmt.Errorf("%w: %v", ErrDurableCommitUnknown, err)
	}
	directory, err := w.ops.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return unknown(err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = w.ops.CloseFile(directory)
		}
	}()
	// Mkdir is subject to the process umask. Apply and verify the exact
	// deployment mode and owner through the no-follow directory descriptor.
	if err := w.ops.Chmod(directory, mode); err != nil {
		return unknown(err)
	}
	if err := w.ops.Chown(directory, w.uid, w.gid); err != nil {
		return unknown(err)
	}
	info, err := w.ops.Stat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != mode || verifyOwner(info, w.uid, w.gid) != nil {
		return unknown(fmt.Errorf("durable child directory is unsafe"))
	}
	if err := w.ops.Sync(directory); err != nil {
		return unknown(err)
	}
	if err := w.ops.CloseFile(directory); err != nil {
		return unknown(err)
	}
	closed = true
	if err := w.SyncRoot(); err != nil {
		return false, fmt.Errorf("%w: %v", ErrDurableCommitUnknown, err)
	}
	if err := w.verifyPublishedRoot(); err != nil {
		return false, err
	}
	return true, nil
}

// verifyPublishedRoot distinguishes an operation that failed before publish
// from one whose descriptor-root mutation may have committed but whose live
// pathname identity changed before the caller can safely proceed.
func (w *DurableWriter) verifyPublishedRoot() error {
	if err := w.VerifyLiveRoot(); err != nil {
		return fmt.Errorf("%w: durable root identity changed", ErrDurableCommitUnknown)
	}
	return nil
}

func safeAbsoluteDurableRoot(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.Contains(path, "\x00")
}

func cleanRelative(name string) error {
	if name == "" || filepath.IsAbs(name) || strings.ContainsAny(name, "\x00\\") || filepath.Clean(name) != name || name == "." || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
		return fmt.Errorf("durable path must be clean and relative")
	}
	return nil
}

func (w *DurableWriter) Close() error {
	if w == nil || w.ops == nil {
		return nil
	}
	ops := w.ops
	w.ops = nil
	w.rootInfo = nil
	return ops.Close()
}

// AcquireMetadataLock opens one single-component lock file through the pinned
// root descriptor, verifies its exact inode/mode/owner, synchronizes a newly
// created entry, and holds a nonblocking exclusive flock until Release.
// Callers cannot supply a nested path or recover the underlying descriptor.
func (w *DurableWriter) AcquireMetadataLock(name string) (*DurableLock, error) {
	if w == nil || w.ops == nil || w.VerifyLiveRoot() != nil || cleanRelative(name) != nil || strings.Contains(filepath.ToSlash(name), "/") {
		return nil, fmt.Errorf("durable lock path is unsafe")
	}
	if existing, err := w.ops.Lstat(name); err == nil {
		if existing.Mode()&os.ModeSymlink != 0 || verifyDurableFile(existing, w.uid, w.gid) != nil {
			return nil, fmt.Errorf("durable lock file is unsafe")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := w.ops.OpenFile(name, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, durableFileMode)
	if err != nil {
		return nil, err
	}
	locked := false
	defer func() {
		if !locked {
			_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
			_ = w.ops.CloseFile(file)
		}
	}()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, err
	}
	if err := w.ops.Chmod(file, durableFileMode); err != nil {
		return nil, err
	}
	if err := w.ops.Chown(file, w.uid, w.gid); err != nil {
		return nil, err
	}
	info, err := w.ops.Stat(file)
	if err != nil || verifyDurableFile(info, w.uid, w.gid) != nil {
		return nil, fmt.Errorf("durable lock file is unsafe")
	}
	leaf, err := w.ops.Lstat(name)
	if err != nil || leaf.Mode()&os.ModeSymlink != 0 || verifyDurableFile(leaf, w.uid, w.gid) != nil || !os.SameFile(info, leaf) {
		return nil, fmt.Errorf("durable lock file identity changed")
	}
	if err := w.ops.Sync(file); err != nil {
		return nil, err
	}
	if err := w.SyncRoot(); err != nil {
		return nil, err
	}
	if err := w.VerifyLiveRoot(); err != nil {
		return nil, err
	}
	locked = true
	return &DurableLock{file: file}, nil
}

func (w *DurableWriter) WriteMetadata(name string, value []byte) error {
	if w == nil || w.ops == nil || w.VerifyLiveRoot() != nil {
		return fmt.Errorf("durable writer is not initialized")
	}
	if err := cleanRelative(name); err != nil {
		return err
	}
	if err := w.requireSecureParents(filepath.Dir(name)); err != nil {
		return err
	}
	temporary, err := durableTempName(filepath.Dir(name), ".open-card-file-")
	if err != nil {
		return err
	}
	file, err := w.ops.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, durableFileMode)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = w.ops.CloseFile(file)
		}
		_ = w.ops.Remove(temporary)
	}()
	if written, writeErr := w.ops.Write(file, value); writeErr != nil {
		return writeErr
	} else if written != len(value) {
		return io.ErrShortWrite
	}
	if err = w.ops.Sync(file); err != nil {
		return err
	}
	if err = w.ops.Chmod(file, durableFileMode); err != nil {
		return err
	}
	if err = w.ops.Chown(file, w.uid, w.gid); err != nil {
		return err
	}
	info, err := w.ops.Stat(file)
	if err != nil {
		return err
	}
	if err = verifyDurableFile(info, w.uid, w.gid); err != nil {
		return err
	}
	if err = w.ops.Sync(file); err != nil {
		return err
	}
	if err = w.ops.CloseFile(file); err != nil {
		return err
	}
	closed = true
	if err = w.ops.Rename(temporary, name); err != nil {
		return err
	}
	if err = w.syncParent(filepath.Dir(name)); err != nil {
		return fmt.Errorf("%w: %v", ErrDurableCommitUnknown, err)
	}
	return w.verifyPublishedRoot()
}

// WriteSystemdServerUnit replaces only the fixed server unit with durable
// root-owned 0644 content. The writer root is /etc/systemd/system (or a task
// equivalent), so callers cannot select another unit name.
func (w *DurableWriter) WriteSystemdServerUnit(value []byte) error {
	return w.writeMetadataMode(systemdServerUnitName, value, systemdUnitMode)
}

func (w *DurableWriter) ReadSystemdServerUnit() ([]byte, error) {
	if w == nil || w.ops == nil || w.VerifyLiveRoot() != nil {
		return nil, fmt.Errorf("durable writer is not initialized")
	}
	file, err := w.ops.OpenFile(systemdServerUnitName, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer w.ops.CloseFile(file)
	info, err := w.ops.Stat(file)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != systemdUnitMode || verifyOwner(info, w.uid, w.gid) != nil {
		return nil, fmt.Errorf("systemd server unit is unsafe")
	}
	return io.ReadAll(file)
}

func (w *DurableWriter) writeMetadataMode(name string, value []byte, mode os.FileMode) error {
	if w == nil || w.ops == nil || mode != systemdUnitMode || w.VerifyLiveRoot() != nil {
		return fmt.Errorf("durable unit writer is not initialized")
	}
	if err := cleanRelative(name); err != nil {
		return err
	}
	if err := w.requireSecureParents(filepath.Dir(name)); err != nil {
		return err
	}
	temporary, err := durableTempName(filepath.Dir(name), ".open-card-unit-")
	if err != nil {
		return err
	}
	file, err := w.ops.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = w.ops.CloseFile(file)
		}
		_ = w.ops.Remove(temporary)
	}()
	if written, writeErr := w.ops.Write(file, value); writeErr != nil {
		return writeErr
	} else if written != len(value) {
		return io.ErrShortWrite
	}
	if err = w.ops.Sync(file); err != nil {
		return err
	}
	if err = w.ops.Chmod(file, mode); err != nil {
		return err
	}
	if err = w.ops.Chown(file, w.uid, w.gid); err != nil {
		return err
	}
	info, err := w.ops.Stat(file)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || verifyOwner(info, w.uid, w.gid) != nil {
		return fmt.Errorf("systemd server unit is unsafe")
	}
	if err = w.ops.Sync(file); err != nil {
		return err
	}
	if err = w.ops.CloseFile(file); err != nil {
		return err
	}
	closed = true
	if err = w.ops.Rename(temporary, name); err != nil {
		return err
	}
	if err = w.syncParent(filepath.Dir(name)); err != nil {
		return fmt.Errorf("%w: %v", ErrDurableCommitUnknown, err)
	}
	return w.verifyPublishedRoot()
}

// CreateMetadata publishes metadata with no-replace semantics. Hard-linking
// the fully fsynced temporary file makes destination creation atomic and
// rejects an existing destination without a check-then-replace race.
func (w *DurableWriter) CreateMetadata(name string, value []byte) error {
	if w == nil || w.ops == nil || w.VerifyLiveRoot() != nil {
		return fmt.Errorf("durable writer is not initialized")
	}
	if err := cleanRelative(name); err != nil {
		return err
	}
	if err := w.requireSecureParents(filepath.Dir(name)); err != nil {
		return err
	}
	temporary, err := durableTempName(filepath.Dir(name), ".open-card-file-")
	if err != nil {
		return err
	}
	file, err := w.ops.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, durableFileMode)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = w.ops.CloseFile(file)
		}
		_ = w.ops.Remove(temporary)
	}()
	if written, writeErr := w.ops.Write(file, value); writeErr != nil {
		return writeErr
	} else if written != len(value) {
		return io.ErrShortWrite
	}
	if err = w.ops.Sync(file); err != nil {
		return err
	}
	if err = w.ops.Chmod(file, durableFileMode); err != nil {
		return err
	}
	if err = w.ops.Chown(file, w.uid, w.gid); err != nil {
		return err
	}
	info, err := w.ops.Stat(file)
	if err != nil {
		return err
	}
	if err = verifyDurableFile(info, w.uid, w.gid); err != nil {
		return err
	}
	if err = w.ops.Sync(file); err != nil {
		return err
	}
	if err = w.ops.CloseFile(file); err != nil {
		return err
	}
	closed = true
	if err = w.ops.Link(temporary, name); err != nil {
		return err
	}
	if err = w.syncParent(filepath.Dir(name)); err != nil {
		return fmt.Errorf("%w: %v", ErrDurableCommitUnknown, err)
	}
	return w.verifyPublishedRoot()
}

func (w *DurableWriter) ReadMetadata(name string) ([]byte, error) {
	if w == nil || w.ops == nil || w.VerifyLiveRoot() != nil {
		return nil, fmt.Errorf("durable writer is not initialized")
	}
	if err := cleanRelative(name); err != nil {
		return nil, err
	}
	if err := w.requireSecureParents(filepath.Dir(name)); err != nil {
		return nil, err
	}
	file, err := w.ops.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer w.ops.CloseFile(file)
	info, err := w.ops.Stat(file)
	if err != nil {
		return nil, err
	}
	if err := verifyDurableFile(info, w.uid, w.gid); err != nil {
		return nil, err
	}
	return io.ReadAll(file)
}

// RemoveMetadata removes one writer-root-relative regular metadata file after
// validating its descriptor and synchronizing the containing directory.
func (w *DurableWriter) RemoveMetadata(name string) error {
	if w == nil || w.ops == nil || w.VerifyLiveRoot() != nil {
		return fmt.Errorf("durable writer is not initialized")
	}
	if err := cleanRelative(name); err != nil {
		return err
	}
	if err := w.requireSecureParents(filepath.Dir(name)); err != nil {
		return err
	}
	file, err := w.ops.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	info, statErr := w.ops.Stat(file)
	closeErr := w.ops.CloseFile(file)
	if statErr != nil {
		return statErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := verifyDurableFile(info, w.uid, w.gid); err != nil {
		return err
	}
	if err := w.ops.Remove(name); err != nil {
		return err
	}
	if err := w.syncParent(filepath.Dir(name)); err != nil {
		return fmt.Errorf("%w: %v", ErrDurableCommitUnknown, err)
	}
	return w.verifyPublishedRoot()
}

func (w *DurableWriter) WriteUpgradeInProgress(transactionID string) error {
	if !validID(transactionID) {
		return fmt.Errorf("upgrade transaction id is invalid")
	}
	return w.WriteMetadata(upgradeInProgressPath, []byte(transactionID+"\n"))
}

// ReadUpgradeInProgress reads only the fixed filesystem-root-relative marker;
// callers cannot substitute a different marker path.
func (w *DurableWriter) ReadUpgradeInProgress() ([]byte, error) {
	return w.ReadMetadata(upgradeInProgressPath)
}

// ClearUpgradeInProgress removes only the fixed upgrade marker after a
// committed upgrade. It verifies the marker through its no-follow descriptor
// before unlinking and makes the directory-sync outcome explicit.
func (w *DurableWriter) ClearUpgradeInProgress() error {
	if _, err := w.ReadUpgradeInProgress(); err != nil {
		return err
	}
	if err := w.ops.Remove(upgradeInProgressPath); err != nil {
		return err
	}
	if err := w.syncParent(filepath.Dir(upgradeInProgressPath)); err != nil {
		return fmt.Errorf("%w: %v", ErrDurableCommitUnknown, err)
	}
	return w.verifyPublishedRoot()
}

type ActivationLinkKind string

const (
	ActivationLinkActive         ActivationLinkKind = "active"
	ActivationLinkPreviousActive ActivationLinkKind = "previous-active"
	ActivationLinkCurrent        ActivationLinkKind = "current"
	ActivationLinkRelease        ActivationLinkKind = "release"
)

func (w *DurableWriter) SwapActivationLink(kind ActivationLinkKind, activationID, releaseID string) error {
	name, target, err := activationLink(kind, activationID, releaseID)
	if err != nil {
		return err
	}
	return w.swapRelativeSymlink(name, target)
}

// SwapActivationReleaseLink writes the only allowed link shape inside an
// activation slot writer rooted at activations/<id>.
func (w *DurableWriter) SwapActivationReleaseLink(releaseID string) error {
	if !validID(releaseID) {
		return fmt.Errorf("release link identity is invalid")
	}
	return w.swapRelativeSymlink("release", filepath.ToSlash(filepath.Join("..", "..", "releases", releaseID)))
}

// SyncRoot durably records changes made directly beneath a writer root. It is
// used by activation-slot writers whose 0711 roots deliberately differ from
// the stricter 0700 journal/data subdirectories.
func (w *DurableWriter) SyncRoot() error {
	if err := w.VerifyLiveRoot(); err != nil {
		return err
	}
	if err := w.syncParent("."); err != nil {
		return err
	}
	return w.verifyPublishedRoot()
}

// ReadActivationLink returns only a recognized typed activation pointer. The
// release link has an activation-specific path and therefore cannot be read
// from this fixed-name API.
func (w *DurableWriter) ReadActivationLink(kind ActivationLinkKind) (string, error) {
	if err := w.VerifyLiveRoot(); err != nil {
		return "", err
	}
	name, err := fixedActivationLinkName(kind)
	if err != nil {
		return "", err
	}
	if err := w.requireSecureParents(filepath.Dir(name)); err != nil {
		return "", err
	}
	info, err := w.ops.Lstat(name)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", fmt.Errorf("activation pointer is not a symlink")
	}
	target, err := w.ops.Readlink(name)
	if err != nil {
		return "", err
	}
	if !recognizedActivationLinkTarget(kind, target) {
		return "", fmt.Errorf("activation pointer target is invalid")
	}
	return target, nil
}

// RemoveActivationLink may remove only the fixed previous-active pointer.
// It verifies both the link type and its recognized target before unlinking.
func (w *DurableWriter) RemoveActivationLink(kind ActivationLinkKind) error {
	if err := w.VerifyLiveRoot(); err != nil {
		return err
	}
	if kind != ActivationLinkPreviousActive {
		return fmt.Errorf("activation pointer removal is not allowed")
	}
	name, err := fixedActivationLinkName(kind)
	if err != nil {
		return err
	}
	if err := w.requireSecureParents(filepath.Dir(name)); err != nil {
		return err
	}
	info, err := w.ops.Lstat(name)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("activation pointer is not a symlink")
	}
	target, err := w.ops.Readlink(name)
	if err != nil || !recognizedActivationLinkTarget(kind, target) {
		return fmt.Errorf("activation pointer target is invalid")
	}
	if err := w.ops.Remove(name); err != nil {
		return err
	}
	if err := w.syncParent(filepath.Dir(name)); err != nil {
		return fmt.Errorf("%w: %v", ErrDurableCommitUnknown, err)
	}
	return w.verifyPublishedRoot()
}

func fixedActivationLinkName(kind ActivationLinkKind) (string, error) {
	switch kind {
	case ActivationLinkActive, ActivationLinkPreviousActive, ActivationLinkCurrent:
		return string(kind), nil
	default:
		return "", fmt.Errorf("activation link kind has no fixed name")
	}
}

func recognizedActivationLinkTarget(kind ActivationLinkKind, target string) bool {
	switch kind {
	case ActivationLinkActive, ActivationLinkPreviousActive:
		parts := strings.Split(filepath.ToSlash(target), "/")
		return len(parts) == 2 && parts[0] == "activations" && validID(parts[1]) && target == filepath.ToSlash(filepath.Join("activations", parts[1]))
	case ActivationLinkCurrent:
		return target == "active/release"
	}
	return false
}

func activationLink(kind ActivationLinkKind, activationID, releaseID string) (string, string, error) {
	switch kind {
	case ActivationLinkActive, ActivationLinkPreviousActive:
		if !validID(activationID) || releaseID != "" {
			return "", "", fmt.Errorf("activation link identity is invalid")
		}
		return string(kind), filepath.ToSlash(filepath.Join("activations", activationID)), nil
	case ActivationLinkCurrent:
		if activationID != "" || releaseID != "" {
			return "", "", fmt.Errorf("current link identity is invalid")
		}
		return "current", filepath.ToSlash(filepath.Join("active", "release")), nil
	case ActivationLinkRelease:
		if !validID(activationID) || !validID(releaseID) {
			return "", "", fmt.Errorf("release link identity is invalid")
		}
		return filepath.ToSlash(filepath.Join("activations", activationID, "release")), filepath.ToSlash(filepath.Join("..", "..", "releases", releaseID)), nil
	default:
		return "", "", fmt.Errorf("activation link kind is invalid")
	}
}

func (w *DurableWriter) swapRelativeSymlink(name, target string) error {
	if err := w.VerifyLiveRoot(); err != nil {
		return err
	}
	if err := cleanRelative(name); err != nil {
		return err
	}
	if err := cleanLinkTarget(target); err != nil {
		return err
	}
	if err := w.requireSecureParents(filepath.Dir(name)); err != nil {
		return err
	}
	temporary, err := durableTempName(filepath.Dir(name), ".open-card-link-")
	if err != nil {
		return err
	}
	defer w.ops.Remove(temporary)
	if err := w.ops.Symlink(target, temporary); err != nil {
		return err
	}
	info, err := w.ops.Lstat(temporary)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("durable temporary link is not a symlink")
	}
	if err := w.ops.Rename(temporary, name); err != nil {
		return err
	}
	if err := w.syncParent(filepath.Dir(name)); err != nil {
		return fmt.Errorf("%w: %v", ErrDurableCommitUnknown, err)
	}
	return w.verifyPublishedRoot()
}

func (w *DurableWriter) requireSecureParents(dir string) error {
	if dir == "." {
		return nil
	}
	if err := cleanRelative(dir); err != nil {
		return err
	}
	current := ""
	for _, part := range strings.Split(filepath.ToSlash(dir), "/") {
		if current == "" {
			current = part
		} else {
			current = filepath.ToSlash(filepath.Join(current, part))
		}
		info, err := w.ops.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != durableDirMode {
			return fmt.Errorf("durable parent is unsafe")
		}
		if err := verifyOwner(info, w.uid, w.gid); err != nil {
			return err
		}
	}
	return nil
}

func (w *DurableWriter) syncParent(dir string) error {
	file, err := w.ops.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer w.ops.CloseFile(file)
	info, err := w.ops.Stat(file)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || (dir != "." && info.Mode().Perm() != durableDirMode) || (dir == "." && info.Mode().Perm()&0o022 != 0) {
		return fmt.Errorf("durable parent is unsafe")
	}
	if err := verifyOwner(info, w.uid, w.gid); err != nil {
		return err
	}
	return w.ops.Sync(file)
}

func verifyDurableFile(info os.FileInfo, uid, gid int) error {
	if !info.Mode().IsRegular() || info.Mode().Perm() != durableFileMode {
		return fmt.Errorf("durable file mode or type is unsafe")
	}
	return verifyOwner(info, uid, gid)
}

func verifyOwner(info os.FileInfo, uid, gid int) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid || int(stat.Gid) != gid {
		return fmt.Errorf("durable owner mismatch")
	}
	return nil
}

func durableTempName(dir, prefix string) (string, error) {
	if dir == "." {
		dir = ""
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return filepath.ToSlash(filepath.Join(dir, fmt.Sprintf("%s%x", prefix, random[:]))), nil
}

// cleanLinkTarget permits only the two link target shapes produced by
// activationLink. The release link intentionally climbs two directories, but
// only to the sibling releases directory inside the durable root.
func cleanLinkTarget(target string) error {
	if cleanRelative(target) == nil {
		return nil
	}
	const releasePrefix = "../../releases/"
	if strings.HasPrefix(target, releasePrefix) && validID(strings.TrimPrefix(target, releasePrefix)) {
		return nil
	}
	return fmt.Errorf("durable link target must be a recognized relative target")
}
