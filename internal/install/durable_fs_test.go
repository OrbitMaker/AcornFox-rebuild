package install

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func taskWriter(t *testing.T) (*DurableWriter, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"activations", "releases", "journal", "var", "var/lib", "var/lib/open-card"} {
		if err := os.Mkdir(filepath.Join(root, dir), durableDirMode); err != nil {
			t.Fatal(err)
		}
	}
	w, err := TaskDurableWriter(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w, root
}

func TestTaskDurableWriterRejectsRootOwnerMismatch(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if _, err := TaskDurableWriter(root, os.Getuid()+1, os.Getgid()); err == nil {
		t.Fatal("writer accepted a root with a mismatched expected owner")
	}
}

func TestDurableWriterRejectsLiveRootReplacement(t *testing.T) {
	w, root := taskWriter(t)
	moved := root + "-moved"
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := w.VerifyLiveRoot(); err == nil {
		t.Fatal("writer accepted a replacement root")
	}
	if err := w.WriteMetadata("journal/replaced.json", []byte("x")); err == nil {
		t.Fatal("writer wrote through a replaced root")
	}
	if _, err := os.Lstat(filepath.Join(root, "journal", "replaced.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement root received a write: %v", err)
	}
}

func TestDurableMetadataLockIsPinnedExclusiveAndRejectsReplacement(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	firstWriter, err := TaskDurableWriter(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer firstWriter.Close()
	secondWriter, err := TaskDurableWriter(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer secondWriter.Close()
	lock, err := firstWriter.AcquireMetadataLock("health.lock")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secondWriter.AcquireMetadataLock("health.lock"); err == nil {
		t.Fatal("concurrent durable lock acquired")
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	reopened, err := secondWriter.AcquireMetadataLock("health.lock")
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Release(); err != nil {
		t.Fatal(err)
	}

	moved := root + "-moved"
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	replacement := t.TempDir()
	if err := os.Symlink(replacement, root); err != nil {
		t.Fatal(err)
	}
	if _, err := firstWriter.AcquireMetadataLock("replacement.lock"); err == nil {
		t.Fatal("lock acquired after live root replacement")
	}
	if _, err := os.Lstat(filepath.Join(replacement, "replacement.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement root received lock side effect: %v", err)
	}
}

func TestDurableMetadataLockRejectsUnsafeLeaf(t *testing.T) {
	for name, prepare := range map[string]func(*testing.T, string){
		"symlink": func(t *testing.T, root string) {
			if err := os.Symlink("target", filepath.Join(root, "health.lock")); err != nil {
				t.Fatal(err)
			}
		},
		"wrong-mode": func(t *testing.T, root string) {
			path := filepath.Join(root, "health.lock")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, durableDirMode); err != nil {
				t.Fatal(err)
			}
			prepare(t, root)
			writer, err := TaskDurableWriter(root, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			if _, err := writer.AcquireMetadataLock("health.lock"); err == nil {
				t.Fatal("unsafe durable lock leaf accepted")
			}
		})
	}
	w, _ := faultWriter(t, "owner-mismatch", true)
	if _, err := w.AcquireMetadataLock("owner.lock"); err == nil {
		t.Fatal("durable lock accepted injected owner mismatch")
	}
}

func TestChildWriterKeepsPinnedParentIdentity(t *testing.T) {
	w, root := taskWriter(t)
	if err := os.Chmod(filepath.Join(root, "activations"), activationSlotDirMode); err != nil {
		t.Fatal(err)
	}
	if _, err := w.CreateChildDirectory("slot", activationSlotDirMode); err != nil {
		t.Fatal(err)
	}
	child, err := w.OpenChildWriter("slot", activationSlotDirMode)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	moved := root + "-moved"
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := child.WriteMetadata("activation.json", []byte("x")); err == nil {
		t.Fatal("child writer wrote after its parent root was replaced")
	}
}

func TestDurableWriterEnumeratesOnlyPinnedDirectChildren(t *testing.T) {
	w, root := taskWriter(t)
	if err := os.Mkdir(filepath.Join(root, "backup-b"), durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "unmanaged"), []byte("x"), durableFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("backup-b", filepath.Join(root, "backup-a")); err != nil {
		t.Fatal(err)
	}
	children, err := w.ReadDirectChildren()
	byName := make(map[string]DurableDirectChild, len(children))
	for _, child := range children {
		byName[child.Name] = child
	}
	if err != nil || byName["backup-a"].Mode&os.ModeSymlink == 0 || !byName["backup-b"].Mode.IsDir() || !byName["unmanaged"].Mode.IsRegular() {
		t.Fatalf("children=%#v err=%v", children, err)
	}
}

func TestDurableWriterEnumerationRejectsFaultAndRootReplacement(t *testing.T) {
	for _, failure := range []string{"readdir", "close"} {
		t.Run(failure, func(t *testing.T) {
			w, _ := faultWriter(t, failure, true)
			if _, err := w.ReadDirectChildren(); err == nil {
				t.Fatalf("%s failure was hidden", failure)
			}
		})
	}

	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	writer, fault := renameHookWriter(t, root)
	defer writer.Close()
	replacement := t.TempDir()
	fault.afterReadDir = func() error {
		moved := root + "-moved"
		if err := os.Rename(root, moved); err != nil {
			return err
		}
		return os.Symlink(replacement, root)
	}
	if _, err := writer.ReadDirectChildren(); err == nil {
		t.Fatal("enumeration accepted a replaced live root")
	}
}

func TestTaskDurableWriterWritesAndRereadsMetadata(t *testing.T) {
	w, root := taskWriter(t)
	if err := w.WriteMetadata("journal/transaction.json", []byte(`{"state":"PREFLIGHTED"}`)); err != nil {
		t.Fatal(err)
	}
	value, err := w.ReadMetadata("journal/transaction.json")
	if err != nil || string(value) != `{"state":"PREFLIGHTED"}` {
		t.Fatalf("read=%q err=%v", value, err)
	}
	info, err := os.Lstat(filepath.Join(root, "journal", "transaction.json"))
	if err != nil || info.Mode().Perm() != durableFileMode {
		t.Fatalf("mode=%v err=%v", info.Mode(), err)
	}
	if err := os.Chmod(filepath.Join(root, "journal", "transaction.json"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ReadMetadata("journal/transaction.json"); err == nil {
		t.Fatal("read accepted a non-0600 metadata file")
	}
}

func TestDurableWriterRejectsRootEscapeAndSymlinks(t *testing.T) {
	w, root := taskWriter(t)
	if err := os.Symlink(root, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../escape", "/absolute", "link/escape", "journal/../escape"} {
		if err := w.WriteMetadata(name, []byte("x")); err == nil {
			t.Fatalf("accepted unsafe path %q", name)
		}
	}
	if err := os.Symlink("transaction.json", filepath.Join(root, "journal", "leaf")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ReadMetadata("journal/leaf"); err == nil {
		t.Fatal("accepted symlink leaf")
	}
}

func TestActivationLinksAreTypedAndRelative(t *testing.T) {
	w, root := taskWriter(t)
	if err := os.Mkdir(filepath.Join(root, "activations", "act-1"), durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := w.SwapActivationLink(ActivationLinkActive, "act-1", ""); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(filepath.Join(root, "active")); err != nil || target != "activations/act-1" {
		t.Fatalf("active target=%q err=%v", target, err)
	}
	if err := w.SwapActivationLink(ActivationLinkPreviousActive, "act-1", ""); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(filepath.Join(root, "previous-active")); err != nil || target != "activations/act-1" {
		t.Fatalf("previous-active target=%q err=%v", target, err)
	}
	if err := w.SwapActivationLink(ActivationLinkCurrent, "", ""); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(filepath.Join(root, "current")); err != nil || target != "active/release" {
		t.Fatalf("current target=%q err=%v", target, err)
	}
	if err := w.SwapActivationLink(ActivationLinkRelease, "act-1", "release-1"); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(filepath.Join(root, "activations", "act-1", "release")); err != nil || target != "../../releases/release-1" {
		t.Fatalf("release target=%q err=%v", target, err)
	}
	if err := w.SwapActivationLink(ActivationLinkActive, "../../escape", ""); err == nil {
		t.Fatal("accepted activation escape")
	}
}

func TestReadAndRemoveActivationLinkAreTyped(t *testing.T) {
	w, root := taskWriter(t)
	if err := os.Mkdir(filepath.Join(root, "activations", "act-1"), durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := w.SwapActivationLink(ActivationLinkPreviousActive, "act-1", ""); err != nil {
		t.Fatal(err)
	}
	if target, err := w.ReadActivationLink(ActivationLinkPreviousActive); err != nil || target != "activations/act-1" {
		t.Fatalf("target=%q err=%v", target, err)
	}
	if err := w.RemoveActivationLink(ActivationLinkPreviousActive); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ReadActivationLink(ActivationLinkPreviousActive); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed link readable: %v", err)
	}
	if err := w.RemoveActivationLink(ActivationLinkActive); err == nil {
		t.Fatal("active pointer removal accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "previous-active"), []byte("not a link"), durableFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ReadActivationLink(ActivationLinkPreviousActive); err == nil {
		t.Fatal("regular pointer accepted")
	}
	if err := os.Remove(filepath.Join(root, "previous-active")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../outside", filepath.Join(root, "previous-active")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ReadActivationLink(ActivationLinkPreviousActive); err == nil {
		t.Fatal("unsafe pointer target accepted")
	}
}

func TestReadAndRemoveActivationLinkPropagateFaults(t *testing.T) {
	for _, failure := range []string{"readlink", "remove"} {
		t.Run(failure, func(t *testing.T) {
			w, _ := faultWriter(t, failure, true)
			if err := w.SwapActivationLink(ActivationLinkPreviousActive, "act-1", ""); err != nil {
				t.Fatal(err)
			}
			if failure == "readlink" {
				if _, err := w.ReadActivationLink(ActivationLinkPreviousActive); err == nil {
					t.Fatal("readlink failure was hidden")
				}
				return
			}
			if err := w.RemoveActivationLink(ActivationLinkPreviousActive); err == nil {
				t.Fatal("remove failure was hidden")
			}
		})
	}
}

type phaseFaultOps struct {
	durableOps
	fail         string
	syncCalls    int
	closeCalls   int
	afterRename  func() error
	afterReadDir func() error
}

func (f *phaseFaultOps) ReadDir(file *os.File, count int) ([]os.DirEntry, error) {
	if f.fail == "readdir" {
		return nil, errors.New("injected readdir failure")
	}
	entries, err := f.durableOps.ReadDir(file, count)
	if err != nil {
		return nil, err
	}
	if f.afterReadDir != nil {
		if err := f.afterReadDir(); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

type restrictiveMkdirOps struct{ durableOps }

func (o *restrictiveMkdirOps) Mkdir(name string, _ os.FileMode) error {
	return o.durableOps.Mkdir(name, 0o700)
}

func TestCreateChildDirectoryOverridesRestrictiveUmaskMode(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	base := realDurableOps{durableRoot: osDurableRoot{root: opened}}
	writer, err := newDurableWriter(root, os.Getuid(), os.Getgid(), &restrictiveMkdirOps{durableOps: base})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if created, err := writer.CreateChildDirectory("activation", activationSlotDirMode); err != nil || !created {
		t.Fatalf("created=%t err=%v", created, err)
	}
	info, err := os.Lstat(filepath.Join(root, "activation"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != activationSlotDirMode {
		t.Fatalf("mode=%v", info.Mode())
	}
}

func TestCreateChildDirectoryResyncsExactExistingDirectory(t *testing.T) {
	for _, failure := range []bool{false, true} {
		name := "success"
		if failure {
			name = "parent-sync-failure"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, durableDirMode); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(root, "activation"), activationSlotDirMode); err != nil {
				t.Fatal(err)
			}
			writer, fault := renameHookWriter(t, root)
			defer writer.Close()
			if failure {
				fault.fail = "directory-parent-fsync"
			}
			created, err := writer.CreateChildDirectory("activation", activationSlotDirMode)
			if created || fault.syncCalls != 2 {
				t.Fatalf("created=%t sync_calls=%d err=%v", created, fault.syncCalls, err)
			}
			if failure && !errors.Is(err, ErrDurableCommitUnknown) {
				t.Fatalf("parent sync failure=%v", err)
			}
			if !failure && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDurableWriterCloseDetachesRootAfterFirstAttempt(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	ops := &durableCloseOps{durableOps: realDurableOps{durableRoot: osDurableRoot{root: opened}}, err: errors.New("injected root close")}
	writer, err := newDurableWriter(root, os.Getuid(), os.Getgid(), ops)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err == nil || ops.calls != 1 {
		t.Fatalf("first close=%v calls=%d", err, ops.calls)
	}
	if err := writer.Close(); err != nil || ops.calls != 1 {
		t.Fatalf("second close=%v calls=%d", err, ops.calls)
	}
}

type durableCloseOps struct {
	durableOps
	calls int
	err   error
}

func (o *durableCloseOps) Close() error {
	o.calls++
	if err := o.durableOps.Close(); err != nil {
		return err
	}
	return o.err
}

func (f *phaseFaultOps) OpenFile(name string, flag int, mode os.FileMode) (*os.File, error) {
	if f.fail == "create" {
		return nil, errors.New("injected create failure")
	}
	return f.durableOps.OpenFile(name, flag, mode)
}

func (f *phaseFaultOps) Readlink(name string) (string, error) {
	if f.fail == "readlink" {
		return "", errors.New("injected readlink failure")
	}
	return f.durableOps.Readlink(name)
}

func (f *phaseFaultOps) Remove(name string) error {
	if f.fail == "remove" {
		return errors.New("injected remove failure")
	}
	return f.durableOps.Remove(name)
}

func (f *phaseFaultOps) Write(file *os.File, value []byte) (int, error) {
	if f.fail == "write" {
		return 0, errors.New("injected write failure")
	}
	return f.durableOps.Write(file, value)
}

func (f *phaseFaultOps) Sync(file *os.File) error {
	f.syncCalls++
	if (f.fail == "fsync1" && f.syncCalls == 1) ||
		(f.fail == "fsync2" && f.syncCalls == 2) ||
		(f.fail == "parent-fsync" && f.syncCalls == 3) ||
		(f.fail == "directory-parent-fsync" && f.syncCalls == 2) ||
		(f.fail == "link-parent-fsync" && f.syncCalls == 1) {
		return errors.New("injected fsync failure")
	}
	return f.durableOps.Sync(file)
}

func (f *phaseFaultOps) Chmod(file *os.File, mode os.FileMode) error {
	if f.fail == "chmod" {
		return errors.New("injected chmod failure")
	}
	return f.durableOps.Chmod(file, mode)
}

func (f *phaseFaultOps) Chown(file *os.File, uid, gid int) error {
	if f.fail == "chown" {
		return errors.New("injected chown failure")
	}
	return f.durableOps.Chown(file, uid, gid)
}

type ownerMismatchFileInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (i ownerMismatchFileInfo) Sys() any { return &i.stat }

func (f *phaseFaultOps) Stat(file *os.File) (os.FileInfo, error) {
	info, err := f.durableOps.Stat(file)
	if err != nil || f.fail != "owner-mismatch" {
		return info, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("test could not inject file owner mismatch")
	}
	copyStat := *stat
	copyStat.Uid++
	return ownerMismatchFileInfo{FileInfo: info, stat: copyStat}, nil
}

func (f *phaseFaultOps) CloseFile(file *os.File) error {
	f.closeCalls++
	if f.fail == "close" && f.closeCalls == 1 {
		return errors.New("injected close failure")
	}
	return f.durableOps.CloseFile(file)
}

func (f *phaseFaultOps) Rename(oldName, newName string) error {
	if f.fail == "rename" || f.fail == "link-rename" {
		return errors.New("injected rename failure")
	}
	if err := f.durableOps.Rename(oldName, newName); err != nil {
		return err
	}
	if f.afterRename != nil {
		return f.afterRename()
	}
	return nil
}

func (f *phaseFaultOps) Link(oldName, newName string) error {
	if err := f.durableOps.Link(oldName, newName); err != nil {
		return err
	}
	if f.afterRename != nil {
		return f.afterRename()
	}
	return nil
}

func (f *phaseFaultOps) Symlink(target, name string) error {
	if f.fail == "symlink-create" {
		return errors.New("injected symlink failure")
	}
	return f.durableOps.Symlink(target, name)
}

func faultWriter(t *testing.T, fail string, activation bool) (*DurableWriter, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"journal", "activations", "releases"} {
		if err := os.Mkdir(filepath.Join(root, dir), durableDirMode); err != nil {
			t.Fatal(err)
		}
	}
	if activation {
		if err := os.Mkdir(filepath.Join(root, "activations", "act-1"), durableDirMode); err != nil {
			t.Fatal(err)
		}
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	base := realDurableOps{durableRoot: osDurableRoot{root: opened}}
	fault := &phaseFaultOps{durableOps: base, fail: fail}
	w, err := newDurableWriter(root, os.Getuid(), os.Getgid(), fault)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w, root
}

func renameHookWriter(t *testing.T, root string) (*DurableWriter, *phaseFaultOps) {
	t.Helper()
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	base := realDurableOps{durableRoot: osDurableRoot{root: opened}}
	fault := &phaseFaultOps{durableOps: base}
	w, err := newDurableWriter(root, os.Getuid(), os.Getgid(), fault)
	if err != nil {
		t.Fatal(err)
	}
	return w, fault
}

func TestWriteMetadataPropagatesEveryPreRenameBoundaryFailure(t *testing.T) {
	for _, phase := range []string{"create", "write", "fsync1", "chmod", "chown", "fsync2", "close", "rename"} {
		t.Run(phase, func(t *testing.T) {
			w, root := faultWriter(t, phase, false)
			if err := w.WriteMetadata("journal/transaction.json", []byte("value")); err == nil {
				t.Fatal("accepted injected persistence failure")
			}
			if _, err := os.Lstat(filepath.Join(root, "journal", "transaction.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("target exists or could not be inspected after %s: %v", phase, err)
			}
		})
	}
}

type durableShortWriteOps struct{ durableOps }

func (o durableShortWriteOps) Write(file *os.File, value []byte) (int, error) {
	n, err := o.durableOps.Write(file, value)
	if err == nil && len(value) > 0 && n > 0 {
		return n - 1, nil
	}
	return n, err
}

func shortWriteWriter(t *testing.T) (*DurableWriter, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "journal"), durableDirMode); err != nil {
		t.Fatal(err)
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	base := realDurableOps{durableRoot: osDurableRoot{root: opened}}
	writer, err := newDurableWriter(root, os.Getuid(), os.Getgid(), durableShortWriteOps{durableOps: base})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	return writer, root
}

func TestDurableMetadataRejectsNilErrorShortWrites(t *testing.T) {
	for name, write := range map[string]func(*DurableWriter) error{
		"metadata": func(w *DurableWriter) error { return w.WriteMetadata("journal/short.json", []byte("value")) },
		"unit":     func(w *DurableWriter) error { return w.WriteSystemdServerUnit([]byte("value")) },
		"create":   func(w *DurableWriter) error { return w.CreateMetadata("journal/short-create.json", []byte("value")) },
	} {
		t.Run(name, func(t *testing.T) {
			writer, root := shortWriteWriter(t)
			if err := write(writer); !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("short write=%v", err)
			}
			for _, path := range []string{"journal/short.json", "journal/short-create.json", systemdServerUnitName} {
				if _, err := os.Lstat(filepath.Join(root, path)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("short write published %s: %v", path, err)
				}
			}
			for _, directory := range []string{root, filepath.Join(root, "journal")} {
				entries, err := os.ReadDir(directory)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".open-card-") {
						t.Fatalf("short write leaked temporary %s", entry.Name())
					}
				}
			}
		})
	}
}

func TestCreateMetadataAcceptsEmptyValue(t *testing.T) {
	writer, root := shortWriteWriter(t)
	// Use the regular writer because the injected short writer correctly reports
	// zero bytes for an empty value and this regression is about normal behavior.
	_ = writer.Close()
	regular, err := TaskDurableWriter(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if err := regular.CreateMetadata("journal/empty", nil); err != nil {
		t.Fatal(err)
	}
	if value, err := regular.ReadMetadata("journal/empty"); err != nil || len(value) != 0 {
		t.Fatalf("empty value=%q err=%v", value, err)
	}
}

func TestCreateMetadataDoesNotReplaceExistingDestination(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "journal"), durableDirMode); err != nil {
		t.Fatal(err)
	}
	w, err := TaskDurableWriter(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.CreateMetadata("journal/item", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := w.CreateMetadata("journal/item", []byte("second")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("err=%v", err)
	}
	got, err := w.ReadMetadata("journal/item")
	if err != nil || string(got) != "first" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestRemoveMetadataValidatesLeafAndDistinguishesMissing(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "meta"), durableDirMode); err != nil {
		t.Fatal(err)
	}
	w, err := TaskDurableWriter(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.CreateMetadata("meta/item", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := w.RemoveMetadata("meta/item"); err != nil {
		t.Fatal(err)
	}
	if err := w.RemoveMetadata("meta/item"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing err=%v", err)
	}
	if err := os.Symlink("/tmp", filepath.Join(root, "meta", "link")); err != nil {
		t.Fatal(err)
	}
	if err := w.RemoveMetadata("meta/link"); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestPostRenameSyncFailureIsReconciledByReread(t *testing.T) {
	w, _ := faultWriter(t, "parent-fsync", false)
	err := w.WriteMetadata("journal/transaction.json", []byte("committed"))
	if !errors.Is(err, ErrDurableCommitUnknown) {
		t.Fatalf("err=%v", err)
	}
	value, readErr := w.ReadMetadata("journal/transaction.json")
	if readErr != nil || string(value) != "committed" {
		t.Fatalf("reconcile value=%q err=%v", value, readErr)
	}
}

func TestReadMetadataRejectsInjectedFileOwnerMismatch(t *testing.T) {
	w, root := taskWriter(t)
	if err := w.WriteMetadata("journal/transaction.json", []byte("committed")); err != nil {
		t.Fatal(err)
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	base := realDurableOps{durableRoot: osDurableRoot{root: opened}}
	fault := &phaseFaultOps{durableOps: base, fail: "owner-mismatch"}
	readWriter, err := newDurableWriter(root, os.Getuid(), os.Getgid(), fault)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = readWriter.Close() })
	if _, err := readWriter.ReadMetadata("journal/transaction.json"); err == nil {
		t.Fatal("read accepted an injected file-owner mismatch")
	}
}

func TestSwapActivationLinkPropagatesCreateRenameAndSyncFailures(t *testing.T) {
	for _, phase := range []string{"symlink-create", "link-rename", "link-parent-fsync"} {
		t.Run(phase, func(t *testing.T) {
			w, root := faultWriter(t, phase, true)
			err := w.SwapActivationLink(ActivationLinkActive, "act-1", "")
			if phase == "link-parent-fsync" {
				if !errors.Is(err, ErrDurableCommitUnknown) {
					t.Fatalf("err=%v", err)
				}
				if target, readErr := os.Readlink(filepath.Join(root, "active")); readErr != nil || target != "activations/act-1" {
					t.Fatalf("reconcile target=%q err=%v", target, readErr)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted injected symlink persistence failure")
			}
			if _, err := os.Lstat(filepath.Join(root, "active")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("active link exists or could not be inspected after %s: %v", phase, err)
			}
		})
	}
}

func TestUpgradeMarkerIsFixedAndStrict(t *testing.T) {
	w, root := taskWriter(t)
	if err := w.WriteUpgradeInProgress("transaction-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(upgradeInProgressPath))); err != nil {
		t.Fatalf("marker was not written at its fixed path: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "upgrade-in-progress")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker was unexpectedly written at the durable root: %v", err)
	}
	value, err := w.ReadUpgradeInProgress()
	if err != nil || string(value) != "transaction-1\n" {
		t.Fatalf("marker=%q err=%v", value, err)
	}
	if err := w.WriteUpgradeInProgress("../transaction"); err == nil {
		t.Fatal("accepted unsafe transaction id")
	}
	if err := w.ClearUpgradeInProgress(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(upgradeInProgressPath))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker still exists or could not be inspected: %v", err)
	}
	if err := os.Symlink("journal/transaction.json", filepath.Join(root, filepath.FromSlash(upgradeInProgressPath))); err != nil {
		t.Fatal(err)
	}
	if err := w.ClearUpgradeInProgress(); err == nil {
		t.Fatal("clear accepted a symlink marker")
	}
}

func TestUpgradeMarkerRequiresExplicitPreparedParent(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	w, err := TaskDurableWriter(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	if err := w.WriteUpgradeInProgress("transaction-1"); err == nil {
		t.Fatal("marker writer created an unprepared parent path")
	}
	if _, err := os.Lstat(filepath.Join(root, "var")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker writer created an unexpected parent directory: %v", err)
	}
}

func TestPublishedMetadataAndLinkRejectPostRenameRootReplacement(t *testing.T) {
	for _, operation := range []string{"metadata", "systemd-unit", "link"} {
		t.Run(operation, func(t *testing.T) {
			w, root := faultWriter(t, "", operation == "link")
			fault, ok := w.ops.(*phaseFaultOps)
			if !ok {
				t.Fatal("test writer does not expose fault operations")
			}
			fault.afterRename = func() error {
				moved := root + "-moved"
				if err := os.Rename(root, moved); err != nil {
					return err
				}
				return os.Mkdir(root, durableDirMode)
			}
			var err error
			if operation == "metadata" {
				err = w.WriteMetadata("journal/published.json", []byte("published"))
			} else if operation == "systemd-unit" {
				err = w.WriteSystemdServerUnit([]byte("[Service]\n"))
			} else {
				err = w.SwapActivationLink(ActivationLinkActive, "act-1", "")
			}
			if !errors.Is(err, ErrDurableCommitUnknown) {
				t.Fatalf("operation=%s err=%v", operation, err)
			}
		})
	}
}
