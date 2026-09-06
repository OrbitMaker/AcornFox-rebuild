package install

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAcornFoxLivePrincipalCombinesUserRoleAndGroupRole(t *testing.T) {
	layout := acornFoxInstallLayout{mode: acornFoxInstallLayoutProduction, principals: acornFoxTestLayoutPrincipals()}
	entry := SubstrateEntry{Role: OwnerRoleRoot, Group: GroupRoleEdge}
	got := acornFoxLivePrincipalForEntry(layout, entry)
	if got.uid != layout.principals[AcornFoxLiveRootRole].uid || got.gid != layout.principals[AcornFoxLiveEdgeRole].gid || got.gid == got.uid {
		t.Fatal("mixed root:edge principal lost its group")
	}
	entry.Group = GroupRole("foreign")
	if got := acornFoxLivePrincipalForEntry(layout, entry); got.uid != -1 || got.gid != -1 {
		t.Fatal("unknown group accepted")
	}
}
func TestAcornFoxUpgradeAtomicFilePreservesActualNonRootGroup(t *testing.T) {
	gid := -1
	if os.Geteuid() == 0 {
		gid = 12345
	} else {
		groups, e := os.Getgroups()
		if e != nil {
			t.Fatal(e)
		}
		for _, candidate := range groups {
			if candidate != 0 && candidate != os.Getgid() {
				gid = candidate
				break
			}
		}
	}
	if gid < 0 {
		t.Skip("requires root or membership in a second non-root group")
	}
	directory := t.TempDir()
	if e := os.Chmod(directory, 0700); e != nil {
		t.Fatal(e)
	}
	layout, e := newTaskAcornFoxLayout(directory, os.Getuid(), os.Getgid())
	if e != nil {
		t.Fatal(e)
	}
	s, e := newAcornFoxRepoStoreForLayout(layout)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	lock, e := s.Acquire(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Release()
	u := newAcornFoxUpgrade(layout)
	path := filepath.Join(directory, "edge.env")
	old, next := []byte("previous environment\n"), []byte("next environment\n")
	if e = os.WriteFile(path, old, 0640); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(path, os.Getuid(), gid); e != nil {
		t.Fatal(e)
	}
	principal := acornFoxInstallPrincipal{os.Getuid(), gid}
	if _, e = u.read(s.root, "edge.env", 0640, 1024); e == nil {
		t.Fatal("state-root owner incorrectly accepted mixed-group file")
	}
	if e = u.atomicFileOwned(s, s.root, "edge.env", old, next, 0640, principal); e != nil {
		t.Fatal(e)
	}
	info, e := os.Lstat(path)
	if e != nil {
		t.Fatal(e)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if int(stat.Uid) != os.Getuid() || int(stat.Gid) != gid || info.Mode().Perm() != 0640 {
		t.Fatal("actual group/mode lost during atomic replacement")
	}
	if raw, e := u.readPrincipal(s.root, "edge.env", 0640, 1024, principal); e != nil || string(raw) != string(next) {
		t.Fatal("cannot read exact group-owned replacement", e)
	}

	if e := u.atomicFileOwned(s, s.root, "empty.env", nil, []byte{}, 0640, principal); e != nil {
		t.Fatal(e)
	}
	if info, e := os.Stat(filepath.Join(directory, "empty.env")); e != nil || info.Size() != 0 || int(info.Sys().(*syscall.Stat_t).Gid) != gid {
		t.Fatal("empty bound file was mistaken for absent", e)
	}
}
