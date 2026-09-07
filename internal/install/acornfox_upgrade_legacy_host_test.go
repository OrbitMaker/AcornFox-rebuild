package install

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func legacy0034IdentityFixture(t *testing.T) acornFoxLegacy0034Identity {
	t.Helper()
	old := AcornFoxCandidateBindingV1{SchemaVersion: 1, Product: AcornFoxV1Product, Version: "1.2.3-test.1", ReleaseID: "release-1.2.3-test.1", SourceRepository: "https://github.com/acornfox/acornfox", SourceCommit: strings.Repeat("a", 40), Architecture: AcornFoxV1Architecture, MigrationVersion: AcornFoxLegacyPredecessorMigration, ManifestSHA256: strings.Repeat("b", 64), ArchiveSHA256: strings.Repeat("c", 64), BundleManifestSHA256: strings.Repeat("d", 64)}
	oldRaw, _ := json.Marshal(old)
	oldSHA := sha256Hex(oldRaw)
	next := AcornFoxCandidateBindingV1{SchemaVersion: 1, Product: AcornFoxV1Product, Version: "1.2.4-test.1", ReleaseID: "release-1.2.4-test.1", SourceRepository: old.SourceRepository, SourceCommit: strings.Repeat("e", 40), Architecture: AcornFoxV1Architecture, MigrationVersion: AcornFoxV1MigrationVersion, ManifestSHA256: strings.Repeat("f", 64), ArchiveSHA256: strings.Repeat("1", 64), BundleManifestSHA256: strings.Repeat("2", 64), NMinusOne: &AcornFoxNMinusOneV1{Version: old.Version, MigrationVersion: old.MigrationVersion, SourceCommit: old.SourceCommit, ReleaseManifestSHA256: old.ManifestSHA256, ArchiveSHA256: old.ArchiveSHA256, BundleManifestSHA256: old.BundleManifestSHA256, BindingSHA256: oldSHA}}
	nextRaw, _ := json.Marshal(next)
	verified, err := ParseAcornFoxCandidateBindingV1(nextRaw, sha256Hex(nextRaw))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := newAcornFoxLegacy0034Identity(oldRaw, oldSHA, verified)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

type legacyHostFixture struct {
	host, state string
	p           *acornFoxLegacyHostProvisioner
	identity    acornFoxLegacy0034Identity
	commands    []string
	account     *user.User
	group       *user.Group
	owners      map[[2]uint64]acornFoxInstallPrincipal
	verified    int
}

func newLegacyHostFixture(t *testing.T) *legacyHostFixture {
	t.Helper()
	host := t.TempDir()
	state := filepath.Join(host, "var/lib/acornfox/install")
	for _, path := range []string{state, filepath.Join(host, "etc/acornfox"), filepath.Join(host, "etc/systemd/system"), filepath.Join(host, "run")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	principals := acornFoxTestLayoutPrincipals()
	delete(principals, AcornFoxLivePIRole)
	legacy, err := newTestProductionAcornFoxLegacy0034Layout(state, host, os.Getuid(), os.Getgid(), principals)
	if err != nil {
		t.Fatal(err)
	}
	f := &legacyHostFixture{host: host, state: state, identity: legacy0034IdentityFixture(t), owners: map[[2]uint64]acornFoxInstallPrincipal{}}
	p := newAcornFoxLegacyHostProvisioner(legacy)
	p.lookupGroup = func(name string) (*user.Group, error) {
		if f.group == nil {
			return nil, user.UnknownGroupError(name)
		}
		copy := *f.group
		return &copy, nil
	}
	p.lookupUser = func(name string) (*user.User, error) {
		if f.account == nil {
			return nil, user.UnknownUserError(name)
		}
		copy := *f.account
		return &copy, nil
	}
	p.unitAbsent = func(context.Context) (bool, error) { return true, nil }
	p.run = func(_ context.Context, path string, args ...string) error {
		call := path + " " + strings.Join(args, " ")
		f.commands = append(f.commands, call)
		switch call {
		case "/usr/sbin/groupadd --system acornfox-pi":
			f.group = &user.Group{Name: "acornfox-pi", Gid: "2006"}
		case "/usr/sbin/useradd --system --gid acornfox-pi --home-dir /var/lib/acornfox/pi --shell /usr/sbin/nologin --no-create-home acornfox-pi":
			f.account = &user.User{Username: "acornfox-pi", Uid: "2006", Gid: "2006", HomeDir: "/var/lib/acornfox/pi"}
		default:
			return errors.New("unexpected command")
		}
		return nil
	}
	p.verifyHost = func(got acornFoxLegacy0034Identity) error {
		f.verified++
		if got.oldSHA256 != f.identity.oldSHA256 || got.candidate.digest != f.identity.candidate.digest {
			return ErrAcornFoxUpgradeConflict
		}
		return nil
	}
	p.chown = func(file *os.File, uid, gid int) error {
		info, err := file.Stat()
		if err == nil {
			f.owners[legacyOwnerKey(info)] = acornFoxInstallPrincipal{uid: uid, gid: gid}
		}
		return err
	}
	p.observe = func(info os.FileInfo) (acornFoxInstallPrincipal, bool) {
		if info == nil {
			return acornFoxInstallPrincipal{}, false
		}
		if owner, ok := f.owners[legacyOwnerKey(info)]; ok {
			return owner, true
		}
		stat := info.Sys().(*syscall.Stat_t)
		return acornFoxInstallPrincipal{uid: int(stat.Uid), gid: int(stat.Gid)}, true
	}
	p.fault = func(string) error { return nil }
	f.p = p
	return f
}

func legacyOwnerKey(info os.FileInfo) [2]uint64 {
	stat := info.Sys().(*syscall.Stat_t)
	return [2]uint64{uint64(stat.Dev), uint64(stat.Ino)}
}

func TestAcornFoxLegacyHostProvisionIsExactAndIdempotent(t *testing.T) {
	f := newLegacyHostFixture(t)
	layout, evidence, err := f.p.ensure(context.Background(), f.identity)
	if err != nil || layout.validate() != nil || evidence.validate(f.identity, f.p.legacy, layout) != nil {
		t.Fatalf("layout=%#v evidence=%#v err=%v", layout, evidence, err)
	}
	want := []string{"/usr/sbin/groupadd --system acornfox-pi", "/usr/sbin/useradd --system --gid acornfox-pi --home-dir /var/lib/acornfox/pi --shell /usr/sbin/nologin --no-create-home acornfox-pi"}
	if !reflect.DeepEqual(f.commands, want) || f.verified != 1 {
		t.Fatalf("commands=%q verified=%d", f.commands, f.verified)
	}
	for _, path := range acornFoxLegacyPIDataDirectories {
		info, statErr := os.Lstat(filepath.Join(f.host, filepath.FromSlash(path)))
		if statErr != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("path=%s info=%#v err=%v", path, info, statErr)
		}
	}
	if info, statErr := os.Lstat(filepath.Join(f.state, acornFoxLegacyHostJournalPath)); statErr != nil || info.Mode().Perm() != 0o600 || info.Size() == 0 {
		t.Fatalf("journal=%#v err=%v", info, statErr)
	}
	again, againEvidence, err := f.p.ensure(context.Background(), f.identity)
	if err != nil || !layout.equivalent(again) || evidence != againEvidence || !reflect.DeepEqual(f.commands, want) || f.verified != 1 {
		t.Fatalf("second err=%v commands=%q verified=%d", err, f.commands, f.verified)
	}
}

func TestAcornFoxLegacyHostProvisionRecoversEffectPrefixes(t *testing.T) {
	for _, step := range []string{"journal-prepared", "group-created", "account-created", "directory-created-0", "directory-created-1", "directory-created-2", "directory-created-3"} {
		t.Run(step, func(t *testing.T) {
			f := newLegacyHostFixture(t)
			fired := false
			f.p.fault = func(got string) error {
				if got == step && !fired {
					fired = true
					return errors.New("power loss")
				}
				return nil
			}
			if _, _, err := f.p.ensure(context.Background(), f.identity); !errors.Is(err, ErrAcornFoxUpgradeUnknown) || !fired {
				t.Fatalf("first err=%v fired=%t", err, fired)
			}
			fresh := newAcornFoxLegacyHostProvisioner(f.p.legacy)
			fresh.lookupUser, fresh.lookupGroup, fresh.unitAbsent, fresh.run = f.p.lookupUser, f.p.lookupGroup, f.p.unitAbsent, f.p.run
			fresh.verifyHost, fresh.chown, fresh.observe = f.p.verifyHost, f.p.chown, f.p.observe
			fresh.fault = func(string) error { return nil }
			layout, evidence, err := fresh.ensure(context.Background(), f.identity)
			if err != nil || evidence.validate(f.identity, fresh.legacy, layout) != nil {
				t.Fatalf("recovery err=%v", err)
			}
			if countLegacyCommand(f.commands, "/usr/sbin/groupadd --system acornfox-pi") != 1 || countLegacyCommand(f.commands, "/usr/sbin/useradd --system --gid acornfox-pi --home-dir /var/lib/acornfox/pi --shell /usr/sbin/nologin --no-create-home acornfox-pi") != 1 {
				t.Fatalf("effects repeated: %q", f.commands)
			}
		})
	}
}

func countLegacyCommand(values []string, want string) int {
	count := 0
	for _, value := range values {
		if value == want {
			count++
		}
	}
	return count
}

func TestAcornFoxLegacyHostPreflightDistinguishesPresenceAndFailure(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		f := newLegacyHostFixture(t)
		f.account = &user.User{Username: "acornfox-pi", Uid: "2006", Gid: "2006", HomeDir: "/var/lib/acornfox/pi"}
		if _, _, err := f.p.ensure(context.Background(), f.identity); !errors.Is(err, ErrAcornFoxUpgradeConflict) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("lookup-error", func(t *testing.T) {
		f := newLegacyHostFixture(t)
		f.p.lookupUser = func(string) (*user.User, error) { return nil, errors.New("nss unavailable") }
		if _, _, err := f.p.ensure(context.Background(), f.identity); !errors.Is(err, ErrAcornFoxUpgradeUnknown) {
			t.Fatalf("err=%v", err)
		}
		if _, statErr := os.Lstat(filepath.Join(f.state, acornFoxLegacyHostJournalPath)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("query failure wrote journal: %v", statErr)
		}
	})
	t.Run("unit-query-error", func(t *testing.T) {
		f := newLegacyHostFixture(t)
		f.p.unitAbsent = func(context.Context) (bool, error) { return false, errors.New("systemd unavailable") }
		if _, _, err := f.p.ensure(context.Background(), f.identity); !errors.Is(err, ErrAcornFoxUpgradeUnknown) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("config-present", func(t *testing.T) {
		f := newLegacyHostFixture(t)
		if err := os.Mkdir(filepath.Join(f.host, "etc/acornfox/pi"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.p.ensure(context.Background(), f.identity); !errors.Is(err, ErrAcornFoxUpgradeConflict) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("dangling-enable-link", func(t *testing.T) {
		f := newLegacyHostFixture(t)
		wants := filepath.Join(f.host, "etc/systemd/system/graphical.target.wants")
		if err := os.MkdirAll(wants, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../acornfox-pi-worker.service", filepath.Join(wants, "acornfox-pi-worker.service")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.p.ensure(context.Background(), f.identity); !errors.Is(err, ErrAcornFoxUpgradeConflict) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestAcornFoxLegacyHostRejectsTaskLayoutAndJournalDrift(t *testing.T) {
	identity := legacy0034IdentityFixture(t)
	root := t.TempDir()
	task, err := newTaskAcornFoxLayout(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := newAcornFoxLegacyHostProvisioner(task).ensure(context.Background(), identity); !errors.Is(err, ErrAcornFoxUpgradeConflict) {
		t.Fatalf("task layout err=%v", err)
	}
	f := newLegacyHostFixture(t)
	if _, _, err := f.p.ensure(context.Background(), f.identity); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.state, acornFoxLegacyHostJournalPath)
	raw, _ := os.ReadFile(path)
	var journal acornFoxLegacyHostJournal
	_ = json.Unmarshal(raw, &journal)
	journal.PIUID++
	raw, _ = json.Marshal(journal)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.p.ensure(context.Background(), f.identity); !errors.Is(err, ErrAcornFoxUpgradeConflict) {
		t.Fatalf("journal drift err=%v", err)
	}
}

func TestAcornFoxLegacyProvisionedUIDMustBeDistinct(t *testing.T) {
	f := newLegacyHostFixture(t)
	legacyUID := f.p.legacy.principals[AcornFoxLiveServerRole].uid
	f.p.run = func(_ context.Context, path string, args ...string) error {
		if strings.HasSuffix(path, "groupadd") {
			f.group = &user.Group{Name: "acornfox-pi", Gid: "2006"}
		} else {
			f.account = &user.User{Username: "acornfox-pi", Uid: strconv.Itoa(legacyUID), Gid: "2006", HomeDir: "/var/lib/acornfox/pi"}
		}
		return nil
	}
	if _, _, err := f.p.ensure(context.Background(), f.identity); !errors.Is(err, ErrAcornFoxUpgradeConflict) {
		t.Fatalf("err=%v", err)
	}
}
