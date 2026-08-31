package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type installationIdentityLockFake struct {
	pending    PendingTransaction
	err        error
	releaseErr error
	released   int
}

func (f *installationIdentityLockFake) Acquire(context.Context, string) (UpgradeLock, error) {
	if f.err != nil {
		return nil, f.err
	}
	return installationIdentityLockHandle{fake: f}, nil
}
func (f *installationIdentityLockFake) PendingTransaction(context.Context) (PendingTransaction, error) {
	if f.err != nil {
		return PendingTransaction{}, f.err
	}
	if f.pending.Marker == "" {
		return PendingTransaction{Marker: UpgradeMarkerAbsent}, nil
	}
	return f.pending, nil
}

type installationIdentityLockHandle struct{ fake *installationIdentityLockFake }

func (h installationIdentityLockHandle) Release() error {
	h.fake.released++
	return h.fake.releaseErr
}

func identityTaskStore(t *testing.T, locker InstallationIdentityLocker) (*InstallationIdentityStore, string, string) {
	t.Helper()
	root := t.TempDir()
	canonical := filepath.Join(root, "etc/open-card")
	legacy := filepath.Join(root, "var/lib/open-card")
	for _, path := range []string{canonical, legacy} {
		if err := os.MkdirAll(path, durableDirMode); err != nil {
			t.Fatal(err)
		}
	}
	store, err := NewTaskInstallationIdentityStore(canonical, legacy, os.Getuid(), os.Getgid(), locker)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, canonical, legacy
}

func writeIdentity(t *testing.T, root, value string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, installationIdentityFile), []byte(value+"\n"), durableFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, installationIdentityFile), durableFileMode); err != nil {
		t.Fatal(err)
	}
}

func TestInstallationIdentityMigrationPresenceMatrix(t *testing.T) {
	first := strings.Repeat("a", 48)
	second := strings.Repeat("b", 48)
	for _, tc := range []struct {
		name, canonical, legacy string
		want                    string
		ok                      bool
	}{
		{name: "canonical only", canonical: first, want: first, ok: true},
		{name: "legacy only migrates", legacy: first, want: first, ok: true},
		{name: "both equal", canonical: first, legacy: first, want: first, ok: true},
		{name: "both different", canonical: first, legacy: second},
		{name: "both absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lock := &installationIdentityLockFake{}
			store, canonicalRoot, legacyRoot := identityTaskStore(t, lock)
			if tc.canonical != "" {
				writeIdentity(t, canonicalRoot, tc.canonical)
			}
			if tc.legacy != "" {
				writeIdentity(t, legacyRoot, tc.legacy)
			}
			got, err := store.Migrate(context.Background())
			if tc.ok != (err == nil) {
				t.Fatalf("identity=%v err=%v", got, err)
			}
			if !tc.ok {
				return
			}
			if got.value != tc.want || lock.released != 1 {
				t.Fatalf("identity=%#v releases=%d", got, lock.released)
			}
			canonicalRaw, readErr := os.ReadFile(filepath.Join(canonicalRoot, installationIdentityFile))
			if readErr != nil || string(canonicalRaw) != tc.want+"\n" {
				t.Fatalf("canonical identity mismatch: bytes=%d err=%v", len(canonicalRaw), readErr)
			}
			if tc.legacy != "" {
				legacyRaw, readErr := os.ReadFile(filepath.Join(legacyRoot, installationIdentityFile))
				if readErr != nil || string(legacyRaw) != tc.legacy+"\n" {
					t.Fatalf("legacy identity changed: bytes=%d err=%v", len(legacyRaw), readErr)
				}
			}
		})
	}
}

func TestInstallationIdentityMigrationRejectsUnsafeFilesAndOwnerInjection(t *testing.T) {
	secret := strings.Repeat("c", 48)
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{name: "invalid content", mutate: func(t *testing.T, root string) { writeIdentity(t, root, strings.Repeat("C", 48)) }},
		{name: "symlink", mutate: func(t *testing.T, root string) {
			writeIdentity(t, root, secret)
			path := filepath.Join(root, installationIdentityFile)
			if err := os.Rename(path, path+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+".real", path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "mode", mutate: func(t *testing.T, root string) {
			writeIdentity(t, root, secret)
			if err := os.Chmod(filepath.Join(root, installationIdentityFile), 0o640); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, _, legacyRoot := identityTaskStore(t, &installationIdentityLockFake{})
			tc.mutate(t, legacyRoot)
			if _, err := store.Migrate(context.Background()); !errors.Is(err, ErrInstallationIdentityConflict) {
				t.Fatalf("err=%v", err)
			}
		})
	}

	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if _, err := NewTaskInstallationIdentityStore(root, root, os.Getuid()+1, os.Getgid(), &installationIdentityLockFake{}); !errors.Is(err, ErrInstallationIdentityConflict) {
		t.Fatalf("foreign owner constructor err=%v", err)
	}

	canonical, _ := faultWriter(t, "owner-mismatch", false)
	legacyRoot := t.TempDir()
	if err := os.Chmod(legacyRoot, durableDirMode); err != nil {
		t.Fatal(err)
	}
	legacy, err := TaskDurableWriter(legacyRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	writeIdentity(t, legacyRoot, secret)
	ownerInjected := &InstallationIdentityStore{canonical: canonical, legacy: legacy, locker: &installationIdentityLockFake{}}
	if _, err := ownerInjected.Migrate(context.Background()); !errors.Is(err, ErrInstallationIdentityConflict) {
		t.Fatalf("injected owner mismatch err=%v", err)
	}
}

func TestInstallationIdentityMigrationLockAndMarkerBoundaries(t *testing.T) {
	secret := strings.Repeat("d", 48)
	t.Run("lock conflict", func(t *testing.T) {
		store, _, legacy := identityTaskStore(t, &installationIdentityLockFake{err: ErrUpgradeLocked})
		writeIdentity(t, legacy, secret)
		if _, err := store.Migrate(context.Background()); !errors.Is(err, ErrInstallationIdentityConflict) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("marker refused and lock released", func(t *testing.T) {
		lock := &installationIdentityLockFake{pending: PendingTransaction{TransactionID: "upgrade-1", Marker: UpgradeMarkerSame}}
		store, canonical, legacy := identityTaskStore(t, lock)
		writeIdentity(t, legacy, secret)
		if _, err := store.Migrate(context.Background()); !errors.Is(err, ErrInstallationIdentityConflict) {
			t.Fatalf("err=%v", err)
		}
		if lock.released != 1 {
			t.Fatalf("releases=%d", lock.released)
		}
		if _, err := os.Lstat(filepath.Join(canonical, installationIdentityFile)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("canonical mutation err=%v", err)
		}
	})
	t.Run("release ambiguity is surfaced", func(t *testing.T) {
		lock := &installationIdentityLockFake{releaseErr: errors.New("injected release ambiguity")}
		store, _, legacy := identityTaskStore(t, lock)
		writeIdentity(t, legacy, secret)
		if _, err := store.Migrate(context.Background()); !errors.Is(err, ErrInstallationIdentityConflict) {
			t.Fatalf("err=%v", err)
		}
		if lock.released != 1 {
			t.Fatalf("releases=%d", lock.released)
		}
	})
}

func TestInstallationIdentityMigrationUsesPreparedGlobalUpgradeLock(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{
		"etc/open-card", "var/lib/open-card", "opt/open-card", "etc/systemd/system",
	} {
		if err := os.MkdirAll(filepath.Join(root, path), durableDirMode); err != nil {
			t.Fatal(err)
		}
	}
	if err := PrepareTaskUpgradeLock(root, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	upgrade, err := TaskUpgradeStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer upgrade.Close()
	store, err := NewTaskInstallationIdentityStore(filepath.Join(root, "etc/open-card"), filepath.Join(root, "var/lib/open-card"), os.Getuid(), os.Getgid(), upgrade)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	writeIdentity(t, filepath.Join(root, "var/lib/open-card"), strings.Repeat("7", 48))
	if _, err := store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	lock, err := upgrade.Acquire(context.Background(), "upgrade-after-identity")
	if err != nil {
		t.Fatalf("migration did not release global lock: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestInstallationIdentityMigrationReconcilesNoReplaceRaceAndCommitUnknown(t *testing.T) {
	secret := strings.Repeat("e", 48)
	for _, tc := range []struct {
		name, raced string
		ok          bool
	}{
		{name: "no replace race converges only on exact value", raced: secret, ok: true},
		{name: "no replace race rejects different value", raced: strings.Repeat("9", 48)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, canonical, legacy := identityTaskStore(t, &installationIdentityLockFake{})
			writeIdentity(t, legacy, secret)
			store.beforeCreate = func() { writeIdentity(t, canonical, tc.raced) }
			got, err := store.Migrate(context.Background())
			if tc.ok != (err == nil) || (tc.ok && got.value != secret) {
				t.Fatalf("identity=%#v err=%v", got, err)
			}
		})
	}
	t.Run("durable commit unknown rereads exact canonical", func(t *testing.T) {
		canonical, root := faultWriter(t, "parent-fsync", false)
		legacyRoot := t.TempDir()
		if err := os.Chmod(legacyRoot, durableDirMode); err != nil {
			t.Fatal(err)
		}
		legacy, err := TaskDurableWriter(legacyRoot, os.Getuid(), os.Getgid())
		if err != nil {
			t.Fatal(err)
		}
		defer legacy.Close()
		writeIdentity(t, legacyRoot, secret)
		store := &InstallationIdentityStore{canonical: canonical, legacy: legacy, locker: &installationIdentityLockFake{}}
		got, err := store.Migrate(context.Background())
		if err != nil || got.value != secret {
			t.Fatalf("identity=%#v err=%v", got, err)
		}
		if _, err := os.Stat(filepath.Join(root, installationIdentityFile)); err != nil {
			t.Fatal(err)
		}
	})
}

func TestInstallationIdentityResolveCanonicalOnlyAndDoesNotLeak(t *testing.T) {
	secret := strings.Repeat("f", 48)
	store, canonical, legacy := identityTaskStore(t, &installationIdentityLockFake{})
	writeIdentity(t, legacy, secret)
	if _, err := store.Resolve(context.Background()); !errors.Is(err, ErrInstallationIdentityConflict) {
		t.Fatalf("legacy fallback err=%v", err)
	}
	writeIdentity(t, canonical, secret)
	identity, err := store.Resolve(context.Background())
	if err != nil || identity.SHA256() == "" {
		t.Fatalf("identity=%v err=%v", identity, err)
	}
	encoded, err := json.Marshal(identity)
	if err != nil || strings.Contains(string(encoded), secret) {
		t.Fatalf("json=%q err=%v", encoded, err)
	}
	for _, rendered := range []string{identity.String(), fmt.Sprintf("%v", identity), fmt.Sprintf("%#v", identity), fmt.Sprintf("%+v", identity), fmt.Sprint(ErrInstallationIdentityConflict)} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("secret leaked in %q", rendered)
		}
	}
}
