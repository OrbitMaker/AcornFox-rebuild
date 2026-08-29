package install

import (
	"errors"
	"os"
	"path/filepath"
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

type phaseFaultOps struct {
	durableOps
	fail       string
	syncCalls  int
	closeCalls int
}

func (f *phaseFaultOps) OpenFile(name string, flag int, mode os.FileMode) (*os.File, error) {
	if f.fail == "create" {
		return nil, errors.New("injected create failure")
	}
	return f.durableOps.OpenFile(name, flag, mode)
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
	return f.durableOps.Rename(oldName, newName)
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
