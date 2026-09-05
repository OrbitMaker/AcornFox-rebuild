package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
)

func TestAcornFoxProductionManagedScopeIsExactAndBounded(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, acornFoxProductionScopeFixture)
		want   error
	}{
		{"shared-and-unrelated-ignored", func(t *testing.T, f acornFoxProductionScopeFixture) {
			if err := os.WriteFile(filepath.Join(f.host, "etc", "unrelated"), []byte("x"), durableFileMode); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(f.host, "etc", "systemd", "system", "other.service"), []byte("x"), durableFileMode); err != nil {
				t.Fatal(err)
			}
		}, nil},
		{"extra-acornfox-unit", func(t *testing.T, f acornFoxProductionScopeFixture) {
			if err := os.WriteFile(filepath.Join(f.host, "etc", "systemd", "system", "acornfox-extra.service"), []byte("x"), durableFileMode); err != nil {
				t.Fatal(err)
			}
		}, ErrAcornFoxLiveConflict},
		{"foreign-in-each-managed-root", func(t *testing.T, f acornFoxProductionScopeFixture) {
			for _, root := range acornFoxProductionManagedRoots() {
				if err := os.WriteFile(filepath.Join(f.host, filepath.FromSlash(root), "foreign"), []byte("x"), durableFileMode); err != nil {
					t.Fatal(err)
				}
			}
		}, ErrAcornFoxLiveConflict},
		{"expected-file-mode", func(t *testing.T, f acornFoxProductionScopeFixture) {
			path := f.firstFile(t)
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
		}, ErrAcornFoxLiveConflict},
		{"expected-file-owner-observation", func(t *testing.T, f acornFoxProductionScopeFixture) {
			delete(f.owners, acornFoxTestInodeKey(t, f.firstFile(t)))
		}, ErrAcornFoxLiveConflict},
		{"expected-file-hardlink", func(t *testing.T, f acornFoxProductionScopeFixture) {
			path := f.firstFile(t)
			if err := os.Link(path, path+".link"); err != nil {
				t.Fatal(err)
			}
		}, ErrAcornFoxLiveConflict},
		{"expected-file-symlink", func(t *testing.T, f acornFoxProductionScopeFixture) {
			path := f.firstFile(t)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("elsewhere", path); err != nil {
				t.Fatal(err)
			}
		}, ErrAcornFoxLiveConflict},
		{"state-root-replaced", func(t *testing.T, f acornFoxProductionScopeFixture) {
			state := filepath.Join(f.host, "var", "lib", "acornfox", "install")
			if err := os.Rename(state, state+"-old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(state, durableDirMode); err != nil {
				t.Fatal(err)
			}
		}, ErrAcornFoxLiveConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newAcornFoxProductionScopeFixture(t)
			test.mutate(t, f)
			root, err := f.store.openHostRoot()
			if err != nil && test.want == nil {
				t.Fatal(err)
			}
			if err == nil {
				err = acornFoxValidateProductionManagedScope(root, f.store, f.entries)
				_ = root.Close()
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("scope err=%v want=%v", err, test.want)
			}
		})
	}
}

type acornFoxProductionScopeFixture struct {
	host    string
	store   *TaskAcornFoxRepoStore
	entries []SubstrateEntry
	owners  map[[2]uint64]acornFoxInstallPrincipal
}

func (f acornFoxProductionScopeFixture) firstFile(t *testing.T) string {
	t.Helper()
	for _, entry := range f.entries {
		if entry.Kind == SubstrateEntryFile && !acornFoxProductionStateChild(entry.Path) {
			return filepath.Join(f.host, filepath.FromSlash(entry.Path))
		}
	}
	t.Fatal("no managed file")
	return ""
}

func newAcornFoxProductionScopeFixture(t *testing.T) acornFoxProductionScopeFixture {
	t.Helper()
	_, _, published, substrate := newAcornFox03CPublished(t)
	parent, host := t.TempDir(), ""
	host = filepath.Join(parent, "host")
	state := filepath.Join(host, "var", "lib", "acornfox", "install")
	if err := os.Mkdir(host, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(state, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, durableDirMode); err != nil {
		t.Fatal(err)
	}
	layout, err := newTestProductionAcornFoxLayout(state, host, os.Getuid(), os.Getgid(), acornFoxTestLayoutPrincipals())
	if err != nil {
		t.Fatal(err)
	}
	store, err := newAcornFoxRepoStoreForLayout(layout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	entries, err := acornFoxLiveExpectedEntriesForLayout(layout, published)
	if err != nil {
		t.Fatal(err)
	}
	source, err := published.openLiveSourceRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	for _, entry := range entries {
		if entry.Kind == SubstrateEntryDirectory {
			path := filepath.Join(host, filepath.FromSlash(entry.Path))
			if err := os.MkdirAll(path, os.FileMode(entry.Mode)); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, os.FileMode(entry.Mode)); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, entry := range entries {
		if entry.Kind != SubstrateEntryFile {
			continue
		}
		raw, err := acornFoxLiveReadSource(source, published, entry)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(host, filepath.FromSlash(entry.Path))
		if err := os.WriteFile(path, raw, os.FileMode(entry.Mode)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, os.FileMode(entry.Mode)); err != nil {
			t.Fatal(err)
		}
	}
	owners := map[[2]uint64]acornFoxInstallPrincipal{}
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(host, filepath.FromSlash(entry.Path)))
		if err != nil {
			t.Fatal(err)
		}
		owners[acornFoxTestInfoKey(t, info)] = acornFoxLivePrincipalForEntry(layout, entry)
	}
	store.ownership = acornFoxOwnershipEdge{
		chown: func(file acornFoxRepoFile, uid, gid int) error {
			info, err := file.Stat()
			if err != nil {
				return err
			}
			owners[acornFoxTestInfoKey(t, info)] = acornFoxInstallPrincipal{uid: uid, gid: gid}
			return nil
		},
		observe: func(info os.FileInfo) (acornFoxInstallPrincipal, bool) {
			value, ok := owners[acornFoxTestInfoKey(t, info)]
			return value, ok
		},
	}
	// The state store must itself be valid before the validator may skip its
	// exact subtree.  A minimal PREPARED journal is enough for this pure check.
	lock, err := store.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalInactiveSubstrateReceiptV1(substrate)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := newAcornFoxRepoJournalForLayout(layout, substrate.CandidateReceipt.BindingSHA256, sha256Hex(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(context.Background(), journal); err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	return acornFoxProductionScopeFixture{host: host, store: store, entries: entries, owners: owners}
}

func acornFoxTestInfoKey(t *testing.T, info os.FileInfo) [2]uint64 {
	t.Helper()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("missing stat")
	}
	return [2]uint64{uint64(stat.Dev), uint64(stat.Ino)}
}

func acornFoxTestInodeKey(t *testing.T, path string) [2]uint64 {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return acornFoxTestInfoKey(t, info)
}

func TestAcornFoxProductionManagedScopeSystemdInventoryIsDerived(t *testing.T) {
	f := newAcornFoxProductionScopeFixture(t)
	paths := make([]string, 0)
	for _, entry := range f.entries {
		if strings.HasPrefix(entry.Path, "etc/systemd/system/acornfox-") {
			paths = append(paths, entry.Path)
		}
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatal("fixture has no derived systemd entries")
	}
	root, err := f.store.openHostRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := acornFoxValidateProductionManagedScope(root, f.store, f.entries); err != nil {
		t.Fatal(err)
	}
}

func TestAcornFoxLiveOwnedEntriesObserveExistingAndTemporaryInodes(t *testing.T) {
	f := newAcornFoxProductionScopeFixture(t)
	root, err := f.store.openHostRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	server, ok := f.store.layout.owner(AcornFoxLiveServerRole)
	if !ok {
		t.Fatal("missing server principal")
	}
	mark := func() {}
	path, raw := "opt/acornfox/owned-live-test", []byte("owned")
	if err := acornFoxLiveWriteFileOwned(root, f.store, "txn-owned", path, raw, 0o644, server, mark); err != nil {
		t.Fatalf("new owned file=%v", err)
	}
	if err := acornFoxLiveWriteFileOwned(root, f.store, "txn-owned", path, raw, 0o644, server, mark); err != nil {
		t.Fatalf("existing owned file=%v", err)
	}
	if info, err := root.Lstat(path); err != nil || acornFoxRepoNlink(info) != 1 {
		t.Fatalf("final info=%v err=%v", info, err)
	}
	f.owners[acornFoxTestInodeKey(t, filepath.Join(f.host, filepath.FromSlash(path)))] = acornFoxInstallPrincipal{uid: 77, gid: 77}
	if err := acornFoxLiveWriteFileOwned(root, f.store, "txn-owned", path, raw, 0o644, server, mark); !errors.Is(err, ErrAcornFoxLiveConflict) {
		t.Fatalf("owner drift=%v", err)
	}

	tempPath, tempRaw := "opt/acornfox/temp-owned-test", []byte("temporary")
	temp := acornFoxLiveTemp("txn-temp", tempPath)
	if err := os.WriteFile(filepath.Join(f.host, filepath.FromSlash(temp)), tempRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	f.owners[acornFoxTestInodeKey(t, filepath.Join(f.host, filepath.FromSlash(temp)))] = server
	if err := acornFoxLiveWriteFileOwned(root, f.store, "txn-temp", tempPath, tempRaw, 0o644, server, mark); err != nil {
		t.Fatalf("temporary resume=%v", err)
	}
	if _, err := root.Lstat(temp); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary remained err=%v", err)
	}
	if err := acornFoxLiveEnsureDirOwned(root, f.store, "var/log/acornfox/owned-dir-test", 0o750, server, mark); err != nil {
		t.Fatalf("new owned dir=%v", err)
	}
	if err := acornFoxLiveEnsureDirOwned(root, f.store, "var/log/acornfox/owned-dir-test", 0o750, server, mark); err != nil {
		t.Fatalf("existing owned dir=%v", err)
	}
}
