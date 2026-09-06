package install

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAcornFoxPreparedRecoveryPreservesOSParentsAndServiceData(t *testing.T) {
	f := newAcornFoxProductionPreparedFixture(t)
	ctx := context.Background()
	if err := prepareAcornFoxRepository(ctx, f.store, f.published, f.binding); err != nil {
		t.Fatal(err)
	}
	requires := filepath.Join(f.host, "etc/systemd/system/acornfox-server.service.requires")
	if err := os.Mkdir(requires, 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(requires)
	if err != nil {
		t.Fatal(err)
	}
	f.owners.set(info, acornFoxInstallPrincipal{})
	link := filepath.Join(requires, "acornfox-upgrade-safe.target")
	if err := os.Symlink("/etc/systemd/system/acornfox-upgrade-safe.target", link); err != nil {
		t.Fatal(err)
	}
	info, err = os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	f.owners.set(info, acornFoxInstallPrincipal{})
	logParent := filepath.Join(f.host, "var/log")
	if err := os.Chmod(logParent, 0o775); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"var/lib/acornfox/buildkit/state.db", "var/lib/acornfox/uploads/new-app", "var/lib/acornfox/edge/data/certificates", "var/log/acornfox/server/server.log"} {
		if err := os.WriteFile(filepath.Join(f.host, path), []byte("untrusted runtime bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Unknown symlinks are not traversed or adopted as root-owned evidence.
	if err := os.Symlink(f.sentinel, filepath.Join(f.host, "var/lib/acornfox/workspaces/untrusted-link")); err != nil {
		t.Fatal(err)
	}
	if err := prepareAcornFoxRepository(ctx, f.store, f.published, f.binding); err != nil {
		t.Fatalf("running-state recovery: %v", err)
	}
	info, err = os.Stat(logParent)
	if err != nil || info.Mode().Perm() != 0o775 {
		t.Fatal("OS log permissions changed")
	}
	f.assertExternalSentinel(t)
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/systemd/system/other.target", link); err != nil {
		t.Fatal(err)
	}
	info, err = os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	f.owners.set(info, acornFoxInstallPrincipal{})
	if err := prepareAcornFoxRepository(ctx, f.store, f.published, f.binding); err == nil {
		t.Fatal("foreign enable link accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"var/lib/acornfox/buildkit", "var/lib/acornfox/edge/home"} {
		p := filepath.Join(f.host, path)
		before, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := prepareAcornFoxRepository(ctx, f.store, f.published, f.binding); err == nil {
			t.Fatalf("unsafe fixed data root accepted: %s", path)
		}
		if err := os.Chmod(p, before.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(f.host, "etc/acornfox/unexpected.env")
	if err := os.WriteFile(p, []byte("unknown"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareAcornFoxRepository(ctx, f.store, f.published, f.binding); err == nil {
		t.Fatal("unknown configuration accepted")
	}
}

func TestAcornFoxLiveReceiptDoesNotClaimOwnershipOfOSParents(t *testing.T) {
	f := newAcornFoxProductionPreparedFixture(t)
	root, err := f.store.openHostRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	raw, err := f.store.readExactLiveReceipt(root)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseAcornFoxLiveReceiptV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range r.Entries {
		if acornFoxProductionSharedParent(entry.Path) {
			t.Fatalf("OS ancestor claimed as owned: %s", entry.Path)
		}
	}
}
