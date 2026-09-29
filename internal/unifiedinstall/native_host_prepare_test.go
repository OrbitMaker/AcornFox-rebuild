package unifiedinstall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/open-card/open-card/internal/install"
)

func fixtureNativeHostDeps(t *testing.T, stageRoot string) nativeHostDeps {
	t.Helper()
	root := t.TempDir()
	groups := map[string]int{}
	users := map[string][2]int{}
	uid, gid := os.Getuid(), os.Getgid()
	return nativeHostDeps{
		root: root, stageRoot: stageRoot, ownerUID: uid, ownerGID: gid,
		lookupGroup: func(name string) (int, bool, error) { v, ok := groups[name]; return v, ok, nil },
		lookupUser:  func(name string) (int, int, bool, error) { v, ok := users[name]; return v[0], v[1], ok, nil },
		inspectUser: func(name string) (nativeHostAccountFact, error) {
			v, ok := users[name]
			if !ok {
				return nativeHostAccountFact{}, errors.New("missing fixture user")
			}
			actualGroups := []int{v[1]}
			if name != "acornfox-buildkit" {
				actualGroups = append(actualGroups, groups[install.AccountPeerIPC])
			}
			if name == install.AccountSourceBuild {
				actualGroups = append(actualGroups, groups["acornfox-buildkit"])
			}
			return nativeHostAccountFact{UID: v[0], GID: v[1], Home: "/nonexistent", Shell: "/usr/sbin/nologin", Groups: actualGroups}, nil
		},
		createGroup: func(_ context.Context, name string) error {
			if _, ok := groups[name]; ok {
				return errors.New("duplicate group")
			}
			groups[name] = gid
			return nil
		},
		createUser: func(_ context.Context, name, group string, extra []string) error {
			if _, ok := users[name]; ok {
				return errors.New("duplicate user")
			}
			if name == install.AccountSourceBuild && (len(extra) != 2 || extra[0] != install.AccountPeerIPC || extra[1] != "acornfox-buildkit") {
				return errors.New("Source account lacks fixed IPC and BuildKit groups")
			}
			users[name] = [2]int{uid, groups[group]}
			return nil
		},
	}
}

func TestNativeHostPrepareUsesReadyBytesAndNeverStartsOrSwitches(t *testing.T) {
	ctx := context.Background()
	input, _ := intakeFixture(t)
	stageRoot := t.TempDir()
	if err := os.Chmod(stageRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	stage, err := stageCandidate(ctx, input, stageRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	d := fixtureNativeHostDeps(t, stageRoot)
	prepared, err := prepareNativeHostAt(ctx, stage.Path, input.TrustedPin, d)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Status != "prepared_not_started" || prepared.InstallationID == "" || len(prepared.DependencyEvidencePending) != 4 || !prepared.RuntimeParentsRequireReprepare {
		t.Fatalf("false prepare result: %+v", prepared)
	}
	if _, err := os.Lstat(d.path(install.UnifiedCurrentSymlink)); !os.IsNotExist(err) {
		t.Fatal("prepare switched current")
	}
	if _, err := os.Lstat(d.path("/etc/systemd/system/multi-user.target.wants")); !os.IsNotExist(err) {
		t.Fatal("prepare enabled a service")
	}
	if _, err := os.Lstat(d.path("/var/lib/acornfox/core/acornfox.db")); !os.IsNotExist(err) {
		t.Fatal("prepare opened a DB")
	}
	reopened, err := verifyStagedRelease(ctx, stage.Path, stageRoot, input.TrustedPin, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	verified, err := readCompletedHostPreparation(ctx, stage.Path, reopened, d, filepath.Join(stageRoot, nativeHostPrepareRecords, "prepare-"+stage.ManifestSHA256+"-complete.json"))
	if err != nil || !reflect.DeepEqual(verified, prepared) {
		t.Fatalf("completed receipt differs: %v", err)
	}
	replayed, err := prepareNativeHostAt(ctx, stage.Path, input.TrustedPin, d)
	if err != nil || !reflect.DeepEqual(replayed, prepared) {
		t.Fatalf("same-byte replay not stable: %v", err)
	}
	stageRoot2 := t.TempDir()
	if err := os.Chmod(stageRoot2, 0o700); err != nil {
		t.Fatal(err)
	}
	stage2, err := stageCandidate(ctx, input, stageRoot2, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}

	// A new host root with a foreign unit must be rejected before creating an
	// installation ID, role account or release directory.
	foreign := fixtureNativeHostDeps(t, stageRoot2)
	path := foreign.path("/etc/systemd/system/acornfox-core.service")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("foreign"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareNativeHostAt(ctx, stage2.Path, input.TrustedPin, foreign); err == nil {
		t.Fatal("foreign unit was adopted")
	}
	if _, err := os.Lstat(foreign.path(UnifiedInstallationIDPath)); !os.IsNotExist(err) {
		t.Fatal("foreign refusal created an installation ID")
	}
	if _, err := os.Lstat(foreign.path(install.UnifiedCurrentSymlink)); !os.IsNotExist(err) {
		t.Fatal("foreign refusal changed current")
	}

	// A same-size changed member cannot become a host preparation fact.
	member := filepath.Join(stage2.Path, "payload", filepath.FromSlash(input.Inventory[0].RelativePath))
	content, err := os.ReadFile(member)
	if err != nil || len(content) == 0 {
		t.Fatal("missing fixture member", err)
	}
	content[0] ^= 1
	if err := os.WriteFile(member, content, 0o600); err != nil {
		t.Fatal(err)
	}
	changed := fixtureNativeHostDeps(t, stageRoot2)
	if _, err := prepareNativeHostAt(ctx, stage2.Path, input.TrustedPin, changed); err == nil {
		t.Fatal("changed trusted stage artifact was prepared")
	}
	if _, err := os.Lstat(changed.path(UnifiedInstallationIDPath)); !os.IsNotExist(err) {
		t.Fatal("changed stage created installation identity")
	}

	// An existing root-owned but unreceipted installation identity is foreign.
	foreignID := fixtureNativeHostDeps(t, stageRoot2)
	idPath := foreignID.path(UnifiedInstallationIDPath)
	if err := os.MkdirAll(filepath.Dir(idPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idPath, []byte(`{"installation_id":"foreign-installation"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// Restore the trusted stage bytes for this separate preflight refusal.
	content[0] ^= 1
	if err := os.WriteFile(member, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareNativeHostAt(ctx, stage2.Path, input.TrustedPin, foreignID); err == nil {
		t.Fatal("unreceipted installation ID was adopted")
	}
	if _, err := os.Lstat(filepath.Join(stageRoot2, nativeHostPrepareRecords, "prepare-"+stage2.ManifestSHA256+"-intent.json")); !os.IsNotExist(err) {
		t.Fatal("foreign ID caused an intent")
	}

	// A pre-existing wrong-mode base parent must fail before any new intent.
	wrongBase := fixtureNativeHostDeps(t, stageRoot2)
	bad := wrongBase.path("/opt")
	if err := os.Mkdir(bad, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareNativeHostAt(ctx, stage2.Path, input.TrustedPin, wrongBase); err == nil {
		t.Fatal("wrong-mode base parent was adopted")
	}
	if _, err := os.Lstat(wrongBase.path(UnifiedInstallationIDPath)); !os.IsNotExist(err) {
		t.Fatal("foreign base parent caused installation ID creation")
	}

	// Completed receipt must reject a role that later gains a privileged group.
	oldInspect := d.inspectUser
	d.inspectUser = func(name string) (nativeHostAccountFact, error) {
		got, e := oldInspect(name)
		if e == nil && name == install.AccountSourceBuild {
			got.Groups = append(got.Groups, 424242)
		}
		return got, e
	}
	if _, err := prepareNativeHostAt(ctx, stage.Path, input.TrustedPin, d); err == nil {
		t.Fatal("privileged Source group passed completed receipt replay")
	}
}
