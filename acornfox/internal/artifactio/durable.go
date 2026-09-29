package artifactio

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
	DurableFileMode = 0o600
	DurableDirMode  = 0o700
)

var ErrDurableCommitUnknown = errors.New("durable commit outcome is unknown")

type DurableRoot interface {
	OpenFile(string, int, os.FileMode) (*os.File, error)
	OpenRoot(string) (DurableRoot, error)
	Mkdir(string, os.FileMode) error
	Readlink(string) (string, error)
	Rename(string, string) error
	Link(string, string) error
	Remove(string) error
	Symlink(string, string) error
	Lstat(string) (os.FileInfo, error)
	Close() error
}

type OSDurableRoot struct {
	root *os.Root
}

func (r OSDurableRoot) OpenFile(name string, flag int, mode os.FileMode) (*os.File, error) {
	return r.root.OpenFile(name, flag, mode)
}
func (r OSDurableRoot) OpenRoot(name string) (DurableRoot, error) {
	child, err := r.root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return OSDurableRoot{root: child}, nil
}
func (r OSDurableRoot) Mkdir(name string, mode os.FileMode) error { return r.root.Mkdir(name, mode) }
func (r OSDurableRoot) Readlink(name string) (string, error)      { return r.root.Readlink(name) }
func (r OSDurableRoot) Rename(oldName, newName string) error      { return r.root.Rename(oldName, newName) }
func (r OSDurableRoot) Link(oldName, newName string) error        { return r.root.Link(oldName, newName) }
func (r OSDurableRoot) Remove(name string) error                  { return r.root.Remove(name) }
func (r OSDurableRoot) Symlink(target, name string) error         { return r.root.Symlink(target, name) }
func (r OSDurableRoot) Lstat(name string) (os.FileInfo, error)    { return r.root.Lstat(name) }
func (r OSDurableRoot) Close() error                              { return r.root.Close() }

type DurableOps interface {
	DurableRoot
	Write(*os.File, []byte) (int, error)
	Sync(*os.File) error
	Chmod(*os.File, os.FileMode) error
	Chown(*os.File, int, int) error
	Stat(*os.File) (os.FileInfo, error)
	CloseFile(*os.File) error
	ReadDir(*os.File, int) ([]os.DirEntry, error)
}

type RealDurableOps struct {
	DurableRoot
}

func (RealDurableOps) Write(file *os.File, value []byte) (int, error) { return file.Write(value) }
func (RealDurableOps) Sync(file *os.File) error                       { return file.Sync() }
func (RealDurableOps) Chmod(file *os.File, mode os.FileMode) error    { return file.Chmod(mode) }
func (RealDurableOps) Chown(file *os.File, uid, gid int) error        { return file.Chown(uid, gid) }
func (RealDurableOps) Stat(file *os.File) (os.FileInfo, error)        { return file.Stat() }
func (RealDurableOps) CloseFile(file *os.File) error                  { return file.Close() }
func (RealDurableOps) ReadDir(file *os.File, count int) ([]os.DirEntry, error) {
	return file.ReadDir(count)
}

func VerifyDurableFile(info os.FileInfo, uid, gid int) error {
	if !info.Mode().IsRegular() || info.Mode().Perm() != DurableFileMode {
		return fmt.Errorf("durable file mode or type is unsafe")
	}
	return CheckFileOwner(info, uid, gid)
}

func SafeDurableRoot(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.Contains(path, "\x00") && path != "/" && path != "."
}

func CleanRelative(name string) error {
	if name == "" || filepath.IsAbs(name) || strings.ContainsAny(name, "\x00\\") || filepath.Clean(name) != name || name == "." || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
		return fmt.Errorf("durable path must be clean and relative")
	}
	return nil
}

func SyncDirectory(path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func DurableTempName(dir, prefix string) (string, error) {
	if dir == "." {
		dir = ""
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return filepath.ToSlash(filepath.Join(dir, fmt.Sprintf("%s%x", prefix, random[:]))), nil
}

type DurableDirectChild struct {
	Name string
	Mode os.FileMode
}

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

type DurableWriter struct {
	ops      DurableOps
	uid      int
	gid      int
	rootPath string
	rootInfo os.FileInfo
}

func ProductionDurableWriter(root string) (*DurableWriter, error) {
	return NewDurableWriter(root, 0, 0)
}

func TaskDurableWriter(root string, uid, gid int) (*DurableWriter, error) {
	if uid < 0 || gid < 0 {
		return nil, fmt.Errorf("task durable writer owner is invalid")
	}
	return NewDurableWriter(root, uid, gid)
}

func NewDurableWriter(root string, uid, gid int) (*DurableWriter, error) {
	return NewDurableWriterWithOps(root, uid, gid, nil)
}

func NewDurableWriterWithOps(root string, uid, gid int, injected DurableOps) (*DurableWriter, error) {
	if !SafeDurableRoot(root) {
		return nil, fmt.Errorf("durable root is unsafe: %q", root)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("durable root must be a non-symlink non-writable-by-others directory")
	}
	if err := CheckFileOwner(info, uid, gid); err != nil {
		return nil, err
	}
	if injected != nil {
		return &DurableWriter{ops: injected, uid: uid, gid: gid, rootPath: root, rootInfo: info}, nil
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	rootOps := OSDurableRoot{root: opened}
	return &DurableWriter{ops: RealDurableOps{DurableRoot: rootOps}, uid: uid, gid: gid, rootPath: root, rootInfo: info}, nil
}

func (w *DurableWriter) RootPath() string {
	return w.rootPath
}

func (w *DurableWriter) RootInfo() os.FileInfo {
	return w.rootInfo
}

func (w *DurableWriter) Ops() DurableOps {
	return w.ops
}

func (w *DurableWriter) UID() int {
	return w.uid
}

func (w *DurableWriter) GID() int {
	return w.gid
}

func NewDurableWriterWithState(ops DurableOps, uid, gid int, rootPath string, rootInfo os.FileInfo) *DurableWriter {
	return &DurableWriter{
		ops:      ops,
		uid:      uid,
		gid:      gid,
		rootPath: rootPath,
		rootInfo: rootInfo,
	}
}

func (w *DurableWriter) RequireSecureParents(dir string) error {
	return w.requireSecureParents(dir)
}

func (w *DurableWriter) SyncParent(dir string) error {
	return w.syncParent(dir)
}

func (w *DurableWriter) VerifyPublishedRoot() error {
	return w.verifyPublishedRoot()
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

func (w *DurableWriter) VerifyLiveRoot() error {
	if w == nil || w.ops == nil || w.rootPath == "" || w.rootInfo == nil {
		return fmt.Errorf("durable writer is not initialized")
	}
	info, err := os.Lstat(w.rootPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || !os.SameFile(info, w.rootInfo) {
		return fmt.Errorf("durable root identity changed")
	}
	return CheckFileOwner(info, w.uid, w.gid)
}

func (w *DurableWriter) verifyPublishedRoot() error {
	if err := w.VerifyLiveRoot(); err != nil {
		return fmt.Errorf("%w: durable root identity changed", ErrDurableCommitUnknown)
	}
	return nil
}

func (w *DurableWriter) requireSecureParents(dir string) error {
	if dir == "." {
		return nil
	}
	if err := CleanRelative(dir); err != nil {
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
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != DurableDirMode {
			return fmt.Errorf("durable parent is unsafe")
		}
		if err := CheckFileOwner(info, w.uid, w.gid); err != nil {
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
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || (dir != "." && info.Mode().Perm() != DurableDirMode) || (dir == "." && info.Mode().Perm()&0o022 != 0) {
		return fmt.Errorf("durable parent is unsafe")
	}
	if err := CheckFileOwner(info, w.uid, w.gid); err != nil {
		return err
	}
	return w.ops.Sync(file)
}

func (w *DurableWriter) SyncRoot() error {
	if w == nil || w.ops == nil || w.VerifyLiveRoot() != nil {
		return fmt.Errorf("durable writer is not initialized")
	}
	if err := w.syncParent("."); err != nil {
		return err
	}
	return w.verifyPublishedRoot()
}

func (w *DurableWriter) OpenChildWriter(name string, mode os.FileMode) (*DurableWriter, error) {
	if err := w.VerifyLiveRoot(); err != nil || CleanRelative(name) != nil || strings.Contains(filepath.ToSlash(name), "/") {
		return nil, fmt.Errorf("durable child path is unsafe")
	}
	info, err := w.ops.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != mode || CheckFileOwner(info, w.uid, w.gid) != nil {
		return nil, fmt.Errorf("durable child directory is unsafe")
	}
	child, err := w.ops.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	childOps := RealDurableOps{DurableRoot: child}
	return &DurableWriter{ops: childOps, uid: w.uid, gid: w.gid, rootPath: filepath.Join(w.rootPath, name), rootInfo: info}, nil
}

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
	if err != nil || !info.IsDir() || !os.SameFile(info, w.rootInfo) || CheckFileOwner(info, w.uid, w.gid) != nil {
		return nil, fmt.Errorf("durable root descriptor is unsafe")
	}
	entries, err := w.ops.ReadDir(directory, -1)
	if err != nil {
		return nil, err
	}
	children := make([]DurableDirectChild, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if CleanRelative(name) != nil || strings.Contains(filepath.ToSlash(name), "/") {
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

func (w *DurableWriter) CreateChildDirectory(name string, mode os.FileMode) (bool, error) {
	if err := w.VerifyLiveRoot(); err != nil || CleanRelative(name) != nil || strings.Contains(filepath.ToSlash(name), "/") {
		return false, fmt.Errorf("durable child path is unsafe")
	}
	if err := w.ops.Mkdir(name, mode); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return false, err
		}
		info, statErr := w.ops.Lstat(name)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != mode || CheckFileOwner(info, w.uid, w.gid) != nil {
			return false, fmt.Errorf("durable child directory is unsafe")
		}
		directory, openErr := w.ops.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			return false, fmt.Errorf("%w: %v", ErrDurableCommitUnknown, openErr)
		}
		directoryInfo, statErr := w.ops.Stat(directory)
		if statErr != nil || directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() || directoryInfo.Mode().Perm() != mode || CheckFileOwner(directoryInfo, w.uid, w.gid) != nil {
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
	if err := w.ops.Chmod(directory, mode); err != nil {
		return unknown(err)
	}
	if err := w.ops.Chown(directory, w.uid, w.gid); err != nil {
		return unknown(err)
	}
	info, err := w.ops.Stat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != mode || CheckFileOwner(info, w.uid, w.gid) != nil {
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

func (w *DurableWriter) CreateMetadata(name string, value []byte) error {
	if w == nil || w.ops == nil || w.VerifyLiveRoot() != nil {
		return fmt.Errorf("durable writer is not initialized")
	}
	if err := CleanRelative(name); err != nil {
		return err
	}
	if err := w.requireSecureParents(filepath.Dir(name)); err != nil {
		return err
	}
	temporary, err := DurableTempName(filepath.Dir(name), ".open-card-file-")
	if err != nil {
		return err
	}
	file, err := w.ops.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, DurableFileMode)
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
	if err = w.ops.Chmod(file, DurableFileMode); err != nil {
		return err
	}
	if err = w.ops.Chown(file, w.uid, w.gid); err != nil {
		return err
	}
	info, err := w.ops.Stat(file)
	if err != nil {
		return err
	}
	if err = VerifyDurableFile(info, w.uid, w.gid); err != nil {
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

func (w *DurableWriter) WriteMetadata(name string, value []byte) error {
	if w == nil || w.ops == nil || w.VerifyLiveRoot() != nil {
		return fmt.Errorf("durable writer is not initialized")
	}
	if err := CleanRelative(name); err != nil {
		return err
	}
	if err := w.requireSecureParents(filepath.Dir(name)); err != nil {
		return err
	}
	temporary, err := DurableTempName(filepath.Dir(name), ".open-card-file-")
	if err != nil {
		return err
	}
	file, err := w.ops.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, DurableFileMode)
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
	if err = w.ops.Chmod(file, DurableFileMode); err != nil {
		return err
	}
	if err = w.ops.Chown(file, w.uid, w.gid); err != nil {
		return err
	}
	info, err := w.ops.Stat(file)
	if err != nil {
		return err
	}
	if err = VerifyDurableFile(info, w.uid, w.gid); err != nil {
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

func (w *DurableWriter) ReadMetadata(name string) ([]byte, error) {
	if w == nil || w.ops == nil || w.VerifyLiveRoot() != nil {
		return nil, fmt.Errorf("durable writer is not initialized")
	}
	if err := CleanRelative(name); err != nil {
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
	if err := VerifyDurableFile(info, w.uid, w.gid); err != nil {
		return nil, err
	}
	return io.ReadAll(file)
}

func (w *DurableWriter) RemoveMetadata(name string) error {
	if w == nil || w.ops == nil || w.VerifyLiveRoot() != nil {
		return fmt.Errorf("durable writer is not initialized")
	}
	if err := CleanRelative(name); err != nil {
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
	if err := VerifyDurableFile(info, w.uid, w.gid); err != nil {
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

func (w *DurableWriter) AcquireMetadataLock(name string) (*DurableLock, error) {
	if w == nil || w.ops == nil || w.VerifyLiveRoot() != nil || CleanRelative(name) != nil || strings.Contains(filepath.ToSlash(name), "/") {
		return nil, fmt.Errorf("durable lock path is unsafe")
	}
	if existing, err := w.ops.Lstat(name); err == nil {
		if existing.Mode()&os.ModeSymlink != 0 || VerifyDurableFile(existing, w.uid, w.gid) != nil {
			return nil, fmt.Errorf("durable lock file is unsafe")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := w.ops.OpenFile(name, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, DurableFileMode)
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
	if err := w.ops.Chmod(file, DurableFileMode); err != nil {
		return nil, err
	}
	if err := w.ops.Chown(file, w.uid, w.gid); err != nil {
		return nil, err
	}
	info, err := w.ops.Stat(file)
	if err != nil || VerifyDurableFile(info, w.uid, w.gid) != nil {
		return nil, fmt.Errorf("durable lock file is unsafe")
	}
	leaf, err := w.ops.Lstat(name)
	if err != nil || leaf.Mode()&os.ModeSymlink != 0 || VerifyDurableFile(leaf, w.uid, w.gid) != nil || !os.SameFile(info, leaf) {
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
