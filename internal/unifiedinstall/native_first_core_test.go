package unifiedinstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-card/open-card/internal/acornfoxsetup"
	"github.com/open-card/open-card/internal/install"
)

func TestNativeFirstCoreRejectsRootMainPIDAsChild(t *testing.T) {
	const corePath = "/opt/acornfox/releases/release-1/bin/acornfox-core"
	const launcherPath = "/opt/acornfox/releases/release-1/bin/acornfox-host-update"
	const coreSHA = "core-digest-fixture"
	const launcherSHA = "launcher-digest-fixture"
	good := nativeCoreChildFacts{PID: 402, ParentPID: 401, UID: 1001, GID: 1002, ExecutablePath: corePath, ExecutableSHA256: coreSHA, StartTime: "12345", ParentUID: 0, ParentExecutablePath: launcherPath, ParentExecutableSHA256: launcherSHA, ParentStartTime: "12344"}
	if err := validateNativeCoreChildFacts(good, 401, 1001, 1002, corePath, coreSHA, launcherPath, launcherSHA); err != nil {
		t.Fatalf("valid separate Core child refused: %v", err)
	}
	rootMain := good
	rootMain.PID, rootMain.ParentPID, rootMain.UID = 401, 0, 0
	if err := validateNativeCoreChildFacts(rootMain, 401, 1001, 1002, corePath, coreSHA, launcherPath, launcherSHA); err == nil {
		t.Fatal("root MainPID was accepted as Core child")
	}
	wrong := good
	wrong.ExecutableSHA256 = "foreign-child"
	if err := validateNativeCoreChildFacts(wrong, 401, 1001, 1002, corePath, coreSHA, launcherPath, launcherSHA); err == nil {
		t.Fatal("wrong child executable accepted")
	}
}

func TestNativeFirstCoreRefusesExistingDatabaseBeforeStart(t *testing.T) {
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
	host := fixtureNativeHostDeps(t, stageRoot)
	prepared, err := prepareNativeHostAt(ctx, stage.Path, input.TrustedPin, host)
	if err != nil {
		t.Fatal(err)
	}
	db := host.path(filepath.Join(install.UnifiedCoreDataDir, install.UnifiedDefaultDBName))
	if err := os.WriteFile(db, []byte("foreign database"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	d := nativeFirstCoreDeps{host: host,
		unitState: func(context.Context) (nativeCoreUnitState, error) {
			calls++
			return nativeCoreUnitState{Loaded: true}, nil
		},
		daemonReload: func(context.Context) error { calls++; return nil },
		startCore:    func(context.Context) error { calls++; return nil },
		childFacts:   func(int32) (nativeCoreChildFacts, error) { calls++; return nativeCoreChildFacts{}, nil },
		ownsLoopback: func(int32) error { calls++; return nil },
		setupState:   func(context.Context) error { calls++; return nil },
	}
	if _, err := startNativeFirstCoreAt(ctx, stage.Path, input.TrustedPin, d); err == nil {
		t.Fatal("foreign preexisting database accepted")
	}
	if calls != 0 {
		t.Fatal("foreign database triggered service or observation effects")
	}
	for _, path := range []string{host.path(install.UnifiedCurrentSymlink), host.path(nativeCoreSetupTokenSource)} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("foreign database triggered first-Core write")
		}
	}
	if err := os.Remove(db); err != nil {
		t.Fatal(err)
	}
	current := host.path(install.UnifiedCurrentSymlink)
	if err := os.Symlink(host.path(filepath.Join(install.UnifiedReleasesDir, stage.ReleaseID)), current); err != nil {
		t.Fatal(err)
	}
	token, err := acornfoxsetup.GenerateSetupToken(bytes.NewReader(bytes.Repeat([]byte{0x31}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(host.path(nativeCoreSetupTokenSource), token, 0o600); err != nil {
		t.Fatal(err)
	}
	calls = 0
	if _, err := startNativeFirstCoreAt(ctx, stage.Path, input.TrustedPin, d); err == nil {
		t.Fatal("foreign current/token pair without first-Core intent adopted")
	}
	if calls != 0 {
		t.Fatal("foreign pair reached systemd or child observation")
	}
	digest := sha256.Sum256(token)
	intent := nativeFirstCoreIntent{InstallationID: prepared.InstallationID, StagePath: stage.Path, ReleaseID: stage.ReleaseID, ManifestSHA256: stage.ManifestSHA256, TokenSHA256: hex.EncodeToString(digest[:])}
	raw, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	intentPath := filepath.Join(stageRoot, nativeHostPrepareRecords, "first-core-"+stage.ManifestSHA256+"-intent.json")
	if err := os.WriteFile(intentPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := acornfoxsetup.GenerateSetupToken(bytes.NewReader(bytes.Repeat([]byte{0x32}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(host.path(nativeCoreSetupTokenSource), other, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := startNativeFirstCoreAt(ctx, stage.Path, input.TrustedPin, d); err == nil {
		t.Fatal("replacement token passed bound intent replay")
	}
	if calls != 0 {
		t.Fatal("replacement token reached service or child observation")
	}
}
