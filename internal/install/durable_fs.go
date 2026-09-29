package install

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/open-card/open-card/internal/artifactio"
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
var ErrDurableCommitUnknown = artifactio.ErrDurableCommitUnknown

// durableRoot is deliberately narrow so tests can inject every persistence
// boundary without allowing production callers to opt out of root containment.
type durableRoot = artifactio.DurableRoot
type durableOps = artifactio.DurableOps

type osDurableRoot struct{ root *os.Root }

func (r osDurableRoot) OpenFile(name string, flag int, mode os.FileMode) (*os.File, error) {
	return r.root.OpenFile(name, flag, mode)
}
func (r osDurableRoot) OpenRoot(name string) (artifactio.DurableRoot, error) {
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

type DurableDirectChild = artifactio.DurableDirectChild
type DurableLock = artifactio.DurableLock

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

func (w *DurableWriter) toArtifactio() *artifactio.DurableWriter {
	if w == nil {
		return nil
	}
	return artifactio.NewDurableWriterWithState(w.ops, w.uid, w.gid, w.rootPath, w.rootInfo)
}

func (w *DurableWriter) VerifyLiveRoot() error {
	if w == nil || w.ops == nil {
		return fmt.Errorf("durable writer is not initialized")
	}
	return w.toArtifactio().VerifyLiveRoot()
}

func (w *DurableWriter) verifyPublishedRoot() error {
	if w == nil || w.ops == nil {
		return fmt.Errorf("durable writer is not initialized")
	}
	return w.toArtifactio().VerifyPublishedRoot()
}

func (w *DurableWriter) requireSecureParents(dir string) error {
	if w == nil || w.ops == nil {
		return fmt.Errorf("durable writer is not initialized")
	}
	return w.toArtifactio().RequireSecureParents(dir)
}

func (w *DurableWriter) syncParent(dir string) error {
	if w == nil || w.ops == nil {
		return fmt.Errorf("durable writer is not initialized")
	}
	return w.toArtifactio().SyncParent(dir)
}

func (w *DurableWriter) SyncRoot() error {
	if w == nil || w.ops == nil {
		return fmt.Errorf("durable writer is not initialized")
	}
	return w.toArtifactio().SyncRoot()
}

func (w *DurableWriter) OpenChildWriter(name string, mode os.FileMode) (*DurableWriter, error) {
	if w == nil || w.ops == nil {
		return nil, fmt.Errorf("durable writer is not initialized")
	}
	child, err := w.toArtifactio().OpenChildWriter(name, mode)
	if err != nil {
		return nil, err
	}
	return &DurableWriter{
		ops:      child.Ops(),
		uid:      child.UID(),
		gid:      child.GID(),
		rootPath: child.RootPath(),
		rootInfo: child.RootInfo(),
	}, nil
}

func (w *DurableWriter) ReadDirectChildren() ([]DurableDirectChild, error) {
	if w == nil || w.ops == nil {
		return nil, fmt.Errorf("durable writer is not initialized")
	}
	return w.toArtifactio().ReadDirectChildren()
}

func (w *DurableWriter) CreateChildDirectory(name string, mode os.FileMode) (bool, error) {
	if w == nil || w.ops == nil {
		return false, fmt.Errorf("durable writer is not initialized")
	}
	return w.toArtifactio().CreateChildDirectory(name, mode)
}

func (w *DurableWriter) CreateMetadata(name string, value []byte) error {
	if w == nil || w.ops == nil {
		return fmt.Errorf("durable writer is not initialized")
	}
	return w.toArtifactio().CreateMetadata(name, value)
}

func (w *DurableWriter) WriteMetadata(name string, value []byte) error {
	if w == nil || w.ops == nil {
		return fmt.Errorf("durable writer is not initialized")
	}
	return w.toArtifactio().WriteMetadata(name, value)
}

func (w *DurableWriter) ReadMetadata(name string) ([]byte, error) {
	if w == nil || w.ops == nil {
		return nil, fmt.Errorf("durable writer is not initialized")
	}
	return w.toArtifactio().ReadMetadata(name)
}

func (w *DurableWriter) RemoveMetadata(name string) error {
	if w == nil || w.ops == nil {
		return fmt.Errorf("durable writer is not initialized")
	}
	return w.toArtifactio().RemoveMetadata(name)
}

func (w *DurableWriter) AcquireMetadataLock(name string) (*DurableLock, error) {
	if w == nil || w.ops == nil {
		return nil, fmt.Errorf("durable writer is not initialized")
	}
	return w.toArtifactio().AcquireMetadataLock(name)
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

func (w *DurableWriter) WriteUpgradeInProgress(transactionID string) error {
	if !validID(transactionID) {
		return fmt.Errorf("upgrade transaction id is invalid")
	}
	return w.WriteMetadata(upgradeInProgressPath, []byte(transactionID+"\n"))
}

func (w *DurableWriter) ReadUpgradeInProgress() ([]byte, error) {
	return w.ReadMetadata(upgradeInProgressPath)
}

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

func (w *DurableWriter) SwapActivationReleaseLink(releaseID string) error {
	if !validID(releaseID) {
		return fmt.Errorf("release link identity is invalid")
	}
	return w.swapRelativeSymlink("release", filepath.ToSlash(filepath.Join("..", "..", "releases", releaseID)))
}

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

func verifyDurableFile(info os.FileInfo, uid, gid int) error {
	return artifactio.VerifyDurableFile(info, uid, gid)
}

func verifyOwner(info os.FileInfo, uid, gid int) error {
	return artifactio.CheckFileOwner(info, uid, gid)
}

func durableTempName(dir, prefix string) (string, error) {
	return artifactio.DurableTempName(dir, prefix)
}

func safeAbsoluteDurableRoot(path string) bool {
	return artifactio.SafeDurableRoot(path)
}

func cleanRelative(name string) error {
	return artifactio.CleanRelative(name)
}

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
