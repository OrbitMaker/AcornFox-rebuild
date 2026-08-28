package install_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/install"
)

func TestRCArchitectureAndMigrationContracts(t *testing.T) {
	manifest := install.Manifest{Architecture: "amd64"}
	if runtime.GOARCH == "amd64" {
		if err := install.CheckArchitecture(manifest, "x86_64"); err != nil {
			t.Fatalf("amd64 alias rejected: %v", err)
		}
		manifest.Architecture = "arm64"
		if err := install.CheckArchitecture(manifest, "x86_64"); err == nil || !strings.Contains(err.Error(), "incompatible") {
			t.Fatal("wrong architecture was accepted")
		}
	}
	if err := install.CheckCurrentMigration("0020"); err == nil {
		t.Fatal("stale migration was accepted as current RC migration")
	}
	if err := install.CheckCurrentMigration(install.CurrentMigrationVersion); err != nil {
		t.Fatal(err)
	}
}

func TestRCLatestMigrationRejectsMissingOrStaleDirectory(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"0001_foundation.sql", "0020_m5_usage.sql", "0021_m6_controlled_ai.sql", "0022_admin_auth.sql"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("-- fixture\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	latest, err := install.LatestMigrationVersion(directory)
	if err != nil || latest != install.CurrentMigrationVersion {
		t.Fatalf("latest migration = %q, %v", latest, err)
	}
	if err := install.RequireCurrentMigration(directory); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(directory, "0022_admin_auth.sql")); err != nil {
		t.Fatal(err)
	}
	if err := install.RequireCurrentMigration(directory); err == nil {
		t.Fatal("stale migration directory was accepted")
	}
}

func TestInstallerRejectsWrongArchitectureBeforeStaging(t *testing.T) {
	current := runtime.GOARCH
	var wrong string
	switch current {
	case "amd64":
		wrong = "arm64"
	case "arm64":
		wrong = "amd64"
	default:
		t.Skip("unsupported test host architecture")
	}
	directory := t.TempDir()
	bundle := filepath.Join(directory, "bundle")
	if err := os.MkdirAll(filepath.Join(bundle, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	server := filepath.Join(bundle, "bin", "open-card-server")
	if err := os.WriteFile(server, []byte("wrong-arch\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	digest, err := install.SHA256File(server)
	if err != nil {
		t.Fatal(err)
	}
	manifest := install.Manifest{
		SchemaVersion: install.ManifestSchemaVersion,
		Product:       install.ManifestProduct,
		Version:       "1.0.0",
		ReleaseID:     "wrong-arch",
		Architecture:  wrong,
		Protocol:      install.AgentProtocolVersion,
		ConfigDir:     install.DefaultConfigDir,
		DataDir:       install.DefaultDataDir,
		Compatibility: install.Compatibility{MinDataVersion: 1, MaxDataVersion: 8, MinAgentProtocol: install.PreviousAgentProtocol, MaxAgentProtocol: install.AgentProtocolVersion},
		Files:         []install.FileDigest{{Path: "bin/open-card-server", SHA256: digest, Mode: 0o755}},
	}
	if err := install.SaveManifest(filepath.Join(bundle, "manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(directory, "root")
	_, sourceFile, _, _ := runtime.Caller(0)
	script := filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", "scripts", "mvp", "install.sh")
	command := exec.Command("bash", script, "--root", root, "--bundle", bundle, "--dry-run", "--test-safe-prefix", directory)
	output, runErr := command.CombinedOutput()
	if runErr == nil || !strings.Contains(string(output), "architecture") {
		t.Fatalf("wrong architecture result: %v\n%s", runErr, output)
	}
	if _, statErr := os.Stat(root); !os.IsNotExist(statErr) {
		t.Fatalf("wrong-architecture preflight created root: %v", statErr)
	}
}

func TestInstallerRejectsUnauthorizedDowngrade(t *testing.T) {
	directory := t.TempDir()
	root := filepath.Join(directory, "root")
	currentRelease := filepath.Join(root, "opt", "open-card", "releases", "release-1.1.0")
	if err := os.MkdirAll(filepath.Join(currentRelease, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	currentServer := filepath.Join(currentRelease, "bin", "open-card-server")
	if err := os.WriteFile(currentServer, []byte("current\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	currentDigest, err := install.SHA256File(currentServer)
	if err != nil {
		t.Fatal(err)
	}
	currentManifest := install.Manifest{SchemaVersion: install.ManifestSchemaVersion, Product: install.ManifestProduct, Version: "1.1.0", ReleaseID: "release-1.1.0", Protocol: install.AgentProtocolVersion, ConfigDir: install.DefaultConfigDir, DataDir: install.DefaultDataDir, Compatibility: install.Compatibility{MinDataVersion: 1, MaxDataVersion: 8, MinAgentProtocol: install.PreviousAgentProtocol, MaxAgentProtocol: install.AgentProtocolVersion}, Files: []install.FileDigest{{Path: "bin/open-card-server", SHA256: currentDigest, Mode: 0o755}}}
	if err := install.SaveManifest(filepath.Join(currentRelease, "manifest.json"), currentManifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("releases/release-1.1.0", filepath.Join(root, "opt", "open-card", "current")); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(directory, "bundle")
	if err := os.MkdirAll(filepath.Join(bundle, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	candidateServer := filepath.Join(bundle, "bin", "open-card-server")
	if err := os.WriteFile(candidateServer, []byte("candidate\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	candidateDigest, err := install.SHA256File(candidateServer)
	if err != nil {
		t.Fatal(err)
	}
	candidateManifest := currentManifest
	candidateManifest.Version = "1.0.0"
	candidateManifest.ReleaseID = "release-1.0.0"
	candidateManifest.Files = []install.FileDigest{{Path: "bin/open-card-server", SHA256: candidateDigest, Mode: 0o755}}
	if err := install.SaveManifest(filepath.Join(bundle, "manifest.json"), candidateManifest); err != nil {
		t.Fatal(err)
	}
	_, sourceFile, _, _ := runtime.Caller(0)
	script := filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", "scripts", "mvp", "install.sh")
	args := []string{script, "--root", root, "--bundle", bundle, "--dry-run", "--test-safe-prefix", directory}
	command := exec.Command("bash", args...)
	output, runErr := command.CombinedOutput()
	if runErr == nil || !strings.Contains(string(output), "downgrade") {
		t.Fatalf("unauthorized downgrade result: %v\n%s", runErr, output)
	}
	command = exec.Command("bash", append(args, "--allow-downgrade")...)
	command.Env = append(os.Environ(), "OPEN_CARD_ALLOW_DOWNGRADE=1")
	if output, runErr = command.CombinedOutput(); runErr != nil {
		t.Fatalf("authorized downgrade was rejected: %v\n%s", runErr, output)
	}
}

func writeRCBundle(t *testing.T, directory, version, releaseID, migration string) string {
	t.Helper()
	bundle := filepath.Join(directory, "bundle-"+releaseID)
	if err := os.MkdirAll(filepath.Join(bundle, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	server := filepath.Join(bundle, "bin", "open-card-server")
	if err := os.WriteFile(server, []byte("server-"+version+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(bundle, "systemd"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, sourceFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	files := []install.FileDigest{}
	digest, err := install.SHA256File(server)
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, install.FileDigest{Path: "bin/open-card-server", SHA256: digest, Mode: 0o755})
	for _, unit := range []string{"open-card-server.service", "open-card-agent.service", "open-card-buildkit.service", "open-card-caddy.service"} {
		contents, readErr := os.ReadFile(filepath.Join(repoRoot, "deploy", "systemd", unit))
		if readErr != nil {
			t.Fatal(readErr)
		}
		path := filepath.Join(bundle, "systemd", unit)
		if writeErr := os.WriteFile(path, contents, 0o644); writeErr != nil {
			t.Fatal(writeErr)
		}
		digest, digestErr := install.SHA256File(path)
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		files = append(files, install.FileDigest{Path: filepath.ToSlash(filepath.Join("systemd", unit)), SHA256: digest, Mode: 0o644})
	}
	manifest := install.Manifest{SchemaVersion: install.ManifestSchemaVersion, Product: install.ManifestProduct, Version: version, ReleaseID: releaseID, MigrationVersion: migration, Protocol: install.AgentProtocolVersion, ConfigDir: install.DefaultConfigDir, DataDir: install.DefaultDataDir, Compatibility: install.Compatibility{MinDataVersion: 1, MaxDataVersion: 21, MinAgentProtocol: install.PreviousAgentProtocol, MaxAgentProtocol: install.AgentProtocolVersion}, Files: files}
	if err := install.SaveManifest(filepath.Join(bundle, "manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func writeExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/usr/bin/env bash\nset -euo pipefail\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeMigrationAndHealthFailureRestorePointerDataAndConfig(t *testing.T) {
	directory := t.TempDir()
	root := filepath.Join(directory, "root")
	oldBundle := writeRCBundle(t, directory, "1.0.0", "release-1.0.0", "0020")
	_, sourceFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	installScript := filepath.Join(repoRoot, "scripts", "mvp", "install.sh")
	upgradeScript := filepath.Join(repoRoot, "scripts", "mvp", "upgrade.sh")
	common := []string{"--root", root, "--bundle", oldBundle, "--test-safe-prefix", directory}
	if output, err := exec.Command("bash", append([]string{installScript}, common...)...).CombinedOutput(); err != nil {
		t.Fatalf("initial install: %v\n%s", err, output)
	}
	dataDir := filepath.Join(root, "var", "lib", "open-card")
	configDir := filepath.Join(root, "etc", "open-card")
	if err := os.WriteFile(filepath.Join(dataDir, "control-plane.db"), []byte("old-db\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "migration.version"), []byte("0020\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "schema.version"), []byte("20\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "tls-reference"), []byte("old-cert-ref\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	newBundle := writeRCBundle(t, directory, "1.1.0", "release-1.1.0", "0022")
	migrate := filepath.Join(directory, "migrate.sh")
	writeExecutable(t, migrate, `printf '0022_admin_auth.sql\tfixture\n'; printf 'new-db\n' > "$OPEN_CARD_DATA_DIR/control-plane.db"; printf '0022\n' > "$OPEN_CARD_DATA_DIR/migration.version"`)
	health := filepath.Join(directory, "health-fail.sh")
	writeExecutable(t, health, "exit 42")
	dump := filepath.Join(directory, "dump.sh")
	writeExecutable(t, dump, "printf 'dump-before\\n'")
	restore := filepath.Join(directory, "restore.sh")
	restoreMarker := filepath.Join(directory, "restore-called")
	writeExecutable(t, restore, `printf '%s|%s\n' "$1" "$2" > "$RESTORE_MARKER"`)
	args := []string{upgradeScript, "--root", root, "--bundle", newBundle, "--migration-command", migrate, "--health-command", health, "--database-dump-command", dump, "--database-restore-command", restore, "--test-safe-prefix", directory}
	command := exec.Command("bash", args...)
	command.Env = append(os.Environ(), "OPEN_CARD_DATABASE_URL=postgres://fixture.invalid/db", "RESTORE_MARKER="+restoreMarker)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "rolling back") {
		t.Fatalf("failed health upgrade did not roll back: %v\n%s", err, output)
	}
	current, err := os.Readlink(filepath.Join(root, "opt", "open-card", "current"))
	if err != nil || current != "releases/release-1.0.0" {
		t.Fatalf("current pointer after failed upgrade: %q %v", current, err)
	}
	for path, want := range map[string]string{filepath.Join(dataDir, "control-plane.db"): "old-db\n", filepath.Join(dataDir, "migration.version"): "0020\n", filepath.Join(dataDir, "schema.version"): "20\n", filepath.Join(configDir, "tls-reference"): "old-cert-ref\n"} {
		value, readErr := os.ReadFile(path)
		if readErr != nil || string(value) != want {
			t.Fatalf("restored %s = %q, %v", path, value, readErr)
		}
	}
	if _, readErr := os.Stat(restoreMarker); readErr != nil {
		t.Fatalf("database restore command was not invoked: %v", readErr)
	}
	healthOK := filepath.Join(directory, "health-ok.sh")
	writeExecutable(t, healthOK, "exit 0")
	successArgs := []string{upgradeScript, "--root", root, "--bundle", newBundle, "--migration-command", migrate, "--health-command", healthOK, "--database-dump-command", dump, "--database-restore-command", restore, "--test-safe-prefix", directory}
	successCommand := exec.Command("bash", successArgs...)
	successCommand.Env = append(os.Environ(), "OPEN_CARD_DATABASE_URL=postgres://fixture.invalid/db", "RESTORE_MARKER="+restoreMarker)
	if output, successErr := successCommand.CombinedOutput(); successErr != nil {
		t.Fatalf("successful migration/health upgrade: %v\n%s", successErr, output)
	}
	if current, readErr := os.Readlink(filepath.Join(root, "opt", "open-card", "current")); readErr != nil || current != "releases/release-1.1.0" {
		t.Fatalf("current pointer after successful upgrade: %q %v", current, readErr)
	}
	for path, want := range map[string]string{filepath.Join(dataDir, "migration.version"): "0022\n", filepath.Join(dataDir, "schema.version"): "22\n"} {
		value, readErr := os.ReadFile(path)
		if readErr != nil || string(value) != want {
			t.Fatalf("persisted %s = %q, %v", path, value, readErr)
		}
	}
}

func TestUpgradeRestoreFailureCreatesFailClosedRecoveryMarker(t *testing.T) {
	directory := t.TempDir()
	root := filepath.Join(directory, "root")
	oldBundle := writeRCBundle(t, directory, "1.0.0", "release-1.0.0", "0020")
	_, sourceFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	installScript := filepath.Join(repoRoot, "scripts", "mvp", "install.sh")
	upgradeScript := filepath.Join(repoRoot, "scripts", "mvp", "upgrade.sh")
	if output, err := exec.Command("bash", installScript, "--root", root, "--bundle", oldBundle, "--test-safe-prefix", directory).CombinedOutput(); err != nil {
		t.Fatalf("initial install: %v\n%s", err, output)
	}
	dataDir := filepath.Join(root, "var", "lib", "open-card")
	if err := os.WriteFile(filepath.Join(dataDir, "control-plane.db"), []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	newBundle := writeRCBundle(t, directory, "1.1.0", "release-1.1.0", "0022")
	migrate := filepath.Join(directory, "migrate.sh")
	writeExecutable(t, migrate, `printf '0022_admin_auth.sql\tfixture\n'; printf 'new\n' > "$OPEN_CARD_DATA_DIR/control-plane.db"; printf '0022\n' > "$OPEN_CARD_DATA_DIR/schema.version"`)
	dump := filepath.Join(directory, "dump.sh")
	writeExecutable(t, dump, "printf 'dump\\n'")
	restore := filepath.Join(directory, "restore-fail.sh")
	writeExecutable(t, restore, "exit 42")
	health := filepath.Join(directory, "health-fail.sh")
	writeExecutable(t, health, "exit 42")
	command := exec.Command("bash", upgradeScript, "--root", root, "--bundle", newBundle, "--migration-command", migrate, "--health-command", health, "--database-dump-command", dump, "--database-restore-command", restore, "--test-safe-prefix", directory)
	command.Env = append(os.Environ(), "OPEN_CARD_DATABASE_URL=postgres://fixture.invalid/db")
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "recovery required") {
		t.Fatalf("restore failure was not fail-closed: %v\n%s", err, output)
	}
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 78 {
		t.Fatalf("restore failure exit code = %v, want 78", err)
	}
	marker := filepath.Join(dataDir, "recovery-required.json")
	contents, readErr := os.ReadFile(marker)
	if readErr != nil {
		t.Fatalf("recovery marker missing: %v", readErr)
	}
	var value map[string]any
	if err := json.Unmarshal(contents, &value); err != nil || value["state"] != "recovery_required" || value["phase"] != "control_plane_restore_failed" {
		t.Fatalf("invalid recovery marker: %s (%v)", contents, err)
	}
}

func TestManifestDigestIsRequiredForURLAndHostEntryPoint(t *testing.T) {
	directory := t.TempDir()
	bundle := writeRCBundle(t, directory, "1.0.0", "digest-bundle", "0022")
	_, sourceFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	installScript := filepath.Join(repoRoot, "scripts", "mvp", "install.sh")
	command := exec.Command("bash", installScript, "--root", filepath.Join(directory, "root"), "--url", "https://example.invalid/release.tar.gz", "--dry-run", "--test-safe-prefix", directory)
	if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), "expected-manifest-sha256") {
		t.Fatalf("URL install without external digest was accepted: %v\n%s", err, output)
	}
	command = exec.Command("bash", installScript, "--root", filepath.Join(directory, "root"), "--bundle", bundle, "--expected-manifest-sha256", strings.Repeat("0", 64), "--dry-run", "--test-safe-prefix", directory)
	if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), "manifest sha256 mismatch") {
		t.Fatalf("payload replacement digest mismatch was not rejected: %v\n%s", err, output)
	}
	hostScript := filepath.Join(repoRoot, "scripts", "mvp", "install-host.sh")
	command = exec.Command("bash", hostScript, "--bundle", bundle, "--expected-manifest-sha256", strings.Repeat("0", 64))
	if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), "OPEN-CARD-INSTALL") {
		t.Fatalf("portable host entry did not require explicit confirmation: %v\n%s", err, output)
	}
}

func TestUninstallRemovesProgramRuntimeResidueButPreservesData(t *testing.T) {
	directory := t.TempDir()
	root := filepath.Join(directory, "root")
	paths := []string{
		"opt/open-card",
		"etc/open-card",
		"etc/systemd/system",
		"var/lib/open-card",
		"var/lib/open-card-agent",
		"var/log/open-card-agent",
		"var/lib/open-card-caddy",
		"var/log/open-card-caddy",
		"var/log/open-card",
		"var/lib/open-card-buildkit",
		"run/open-card-buildkit",
		"etc/buildkit",
		"etc/apparmor.d",
		"etc",
	}
	for _, relative := range paths {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(relative)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	data := filepath.Join(root, "var/lib/open-card/sentinel")
	if err := os.WriteFile(data, []byte("preserve\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{"etc/buildkit/buildkitd.toml", "etc/apparmor.d/opencard-rootlesskit", "etc/systemd/system/open-card-caddy-fixture.service"} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(relative)), []byte("owned\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fstab := filepath.Join(root, "etc/fstab")
	if err := os.WriteFile(fstab, []byte("# keep\n/var/lib/open-card-buildkit-state.img /var/lib/open-card-buildkit ext4 loop,nodev,nosuid 0 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, sourceFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	command := exec.Command("bash", filepath.Join(repoRoot, "scripts/mvp/uninstall.sh"), "--root", root, "--test-safe-prefix", directory)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, output)
	}
	if value, err := os.ReadFile(data); err != nil || string(value) != "preserve\n" {
		t.Fatalf("data was not preserved: %q %v", value, err)
	}
	for _, relative := range []string{"opt/open-card", "etc/open-card", "var/lib/open-card-agent", "var/log/open-card-agent", "var/lib/open-card-caddy", "var/log/open-card-caddy", "var/log/open-card", "var/lib/open-card-buildkit", "run/open-card-buildkit", "etc/buildkit/buildkitd.toml", "etc/apparmor.d/opencard-rootlesskit", "etc/systemd/system/open-card-caddy-fixture.service"} {
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(relative))); !os.IsNotExist(err) {
			t.Fatalf("runtime residue remained at %s: %v", relative, err)
		}
	}
	fstabValue, err := os.ReadFile(fstab)
	if err != nil || strings.Contains(string(fstabValue), "open-card-buildkit-state.img") || !strings.Contains(string(fstabValue), "# keep") {
		t.Fatalf("fstab cleanup was unsafe: %q %v", fstabValue, err)
	}
	repeat := exec.Command("bash", filepath.Join(repoRoot, "scripts/mvp/uninstall.sh"), "--root", root, "--test-safe-prefix", directory)
	if output, err := repeat.CombinedOutput(); err != nil {
		t.Fatalf("idempotent uninstall: %v\n%s", err, output)
	}
}
