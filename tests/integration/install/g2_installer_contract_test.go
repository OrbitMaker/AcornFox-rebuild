package install_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/install"
)

func writeG2CandidateBundle(t *testing.T, directory string, includeEdge bool) string {
	t.Helper()
	bundle := filepath.Join(directory, "candidate")
	files := []struct {
		path string
		mode os.FileMode
	}{
		{"bin/open-card-server", 0o755}, {"bin/open-card-agent", 0o755}, {"bin/open-card-buildkit", 0o755}, {"bin/open-card-caddy", 0o755}, {"bin/open-card-admin", 0o755}, {"bin/open-card-upgrade", 0o755},
		{"caddy/open-card-edge.Caddyfile.example", 0o644}, {"caddy/open-card-edge.env.example", 0o640}, {"migrations/control-plane/0024_dns_change_ledger.sql", 0o644}, {"web/dist/index.html", 0o644}, {"docs/licenses/licenses-manifest.json", 0o644}, {"sbom.spdx.json", 0o644}, {"source-manifest.sha256", 0o640},
	}
	for _, item := range files {
		path := filepath.Join(bundle, filepath.FromSlash(item.path))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(item.path+"\n"), item.mode); err != nil {
			t.Fatal(err)
		}
	}
	_, sourceFile, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	units := []string{
		"open-card-server.service",
		"open-card-agent.service",
		"open-card-buildkit.service",
		"open-card-caddy.service",
		"open-card-upgrade-recover.service",
		"open-card-upgrade-safe.target",
		"open-card-upgrade-finalize.service",
		"open-card-edge.service.d/10-upgrade-marker.conf",
	}
	if includeEdge {
		units = append(units, "open-card-edge.service")
	}
	entries := make([]install.FileDigest, 0, len(files)+len(units))
	for _, item := range files {
		path := filepath.Join(bundle, filepath.FromSlash(item.path))
		digest, err := install.SHA256File(path)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, install.FileDigest{Path: item.path, SHA256: digest, Mode: uint32(item.mode)})
	}
	for _, unit := range units {
		data, err := os.ReadFile(filepath.Join(repo, "deploy", "systemd", unit))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(bundle, "systemd", unit)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		digest, err := install.SHA256File(path)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, install.FileDigest{Path: "systemd/" + unit, SHA256: digest, Mode: 0o644})
	}
	manifest := install.Manifest{SchemaVersion: install.ManifestSchemaVersion, Product: install.ManifestProduct, Version: install.ProductionCandidateVersion, ReleaseID: "release-0.8.0-rc.1", Architecture: install.RuntimeArchitecture(), MigrationVersion: install.CurrentMigrationVersion, SourceCommit: strings.Repeat("a", 40), NMinusOne: &install.NMinusOne{Version: install.ProductionNMinusOneVersion, MigrationVersion: "0023", SourceCommit: install.RC0SourceCommit, ReleaseManifestSHA256: install.RC0ReleaseManifestSHA256, ArchiveSHA256: install.RC0ArchiveSHA256, BundleManifestSHA256: install.RC0BundleManifestSHA256}, Protocol: install.AgentProtocolVersion, ConfigDir: install.DefaultConfigDir, DataDir: install.DefaultDataDir, Compatibility: install.Compatibility{MinDataVersion: 1, MaxDataVersion: 24, MinAgentProtocol: install.PreviousAgentProtocol, MaxAgentProtocol: install.AgentProtocolVersion}, Files: entries}
	if err := install.SaveManifest(filepath.Join(bundle, "manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func TestG2CandidateStagesEdgeAndRequires0024WithoutActivation(t *testing.T) {
	directory := t.TempDir()
	bundle := writeG2CandidateBundle(t, directory, true)
	migrations := filepath.Join(directory, "migrations")
	if err := os.MkdirAll(migrations, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(migrations, "0024_dns_change_ledger.sql"), []byte("-- fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	migrate := filepath.Join(directory, "migrate.sh")
	if err := os.WriteFile(migrate, []byte("#!/usr/bin/env bash\nprintf '0024_dns_change_ledger.sql\\tfixture\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, sourceFile, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	root := filepath.Join(directory, "root")
	command := exec.Command("bash", filepath.Join(repo, "scripts/mvp/install.sh"), "--root", root, "--bundle", bundle, "--migration-command", migrate, "--migration-dir", migrations, "--test-safe-prefix", directory)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("install candidate: %v\n%s", err, output)
	}
	for _, relative := range []string{
		"etc/systemd/system/open-card-edge.service",
		"etc/systemd/system/open-card-upgrade-recover.service",
		"etc/systemd/system/open-card-upgrade-safe.target",
		"etc/systemd/system/open-card-upgrade-finalize.service",
		"etc/systemd/system/open-card-edge.service.d/10-upgrade-marker.conf",
		"opt/open-card/current/bin/open-card-admin",
		"opt/open-card/current/migrations/control-plane/0024_dns_change_ledger.sql",
		"opt/open-card/current/web/dist/index.html",
		"opt/open-card/upgrade-tools/open-card-upgrade",
		"run/lock/open-card-upgrade.lock",
	} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative))); err != nil {
			t.Fatalf("missing staged %s: %v", relative, err)
		}
	}
	for relative, mode := range map[string]os.FileMode{
		"etc/systemd/system/open-card-upgrade-recover.service":               0o644,
		"etc/systemd/system/open-card-upgrade-safe.target":                   0o644,
		"etc/systemd/system/open-card-upgrade-finalize.service":              0o644,
		"etc/systemd/system/open-card-edge.service.d/10-upgrade-marker.conf": 0o644,
		"opt/open-card/upgrade-tools/open-card-upgrade":                      0o755,
		"run/lock/open-card-upgrade.lock":                                    0o600,
	} {
		if info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(relative))); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
			t.Fatalf("stable %s mode=%v err=%v", relative, info.Mode(), err)
		}
	}
	replay := exec.Command("bash", filepath.Join(repo, "scripts", "mvp", "install.sh"), "--root", root, "--bundle", bundle, "--migration-command", migrate, "--migration-dir", migrations, "--test-safe-prefix", directory)
	if output, err := replay.CombinedOutput(); err != nil || !strings.Contains(string(output), "idempotent") {
		t.Fatalf("candidate replay: %v\n%s", err, output)
	}
	if value, err := os.ReadFile(filepath.Join(root, "var/lib/open-card/migration.version")); err != nil || string(value) != "0024\n" {
		t.Fatalf("migration state=%q err=%v", value, err)
	}
}

func TestG2CandidateRejectsMissingEdgeUnit(t *testing.T) {
	directory := t.TempDir()
	bundle := writeG2CandidateBundle(t, directory, false)
	_, sourceFile, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	command := exec.Command("bash", filepath.Join(repo, "scripts/mvp/install.sh"), "--root", filepath.Join(directory, "root"), "--bundle", bundle, "--test-safe-prefix", directory)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "open-card-edge.service") {
		t.Fatalf("missing Edge unit was accepted: %v\n%s", err, output)
	}
}

func TestG2CandidateRejectsUnsafeStableRecoveryArtifacts(t *testing.T) {
	directory := t.TempDir()
	bundle := writeG2CandidateBundle(t, directory, true)
	_, sourceFile, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	installScript := filepath.Join(repo, "scripts", "mvp", "install.sh")
	type fixture struct {
		expected string
		prepare  func(string)
	}
	for name, item := range map[string]fixture{
		"binary symlink": {expected: "unsafe", prepare: func(root string) {
			path := filepath.Join(root, "opt/open-card/upgrade-tools")
			if err := os.MkdirAll(path, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/tmp/foreign-upgrade", filepath.Join(path, "open-card-upgrade")); err != nil {
				t.Fatal(err)
			}
		}},
		"unit conflict": {expected: "conflicts", prepare: func(root string) {
			path := filepath.Join(root, "etc/systemd/system")
			if err := os.MkdirAll(path, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, "open-card-upgrade-recover.service"), []byte("foreign\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		"safe target conflict": {expected: "conflicts", prepare: func(root string) {
			path := filepath.Join(root, "etc/systemd/system")
			if err := os.MkdirAll(path, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, "open-card-upgrade-safe.target"), []byte("foreign\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		"finalizer symlink": {expected: "unsafe", prepare: func(root string) {
			path := filepath.Join(root, "etc/systemd/system")
			if err := os.MkdirAll(path, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/tmp/foreign-finalizer", filepath.Join(path, "open-card-upgrade-finalize.service")); err != nil {
				t.Fatal(err)
			}
		}},
		"edge dropin mode": {expected: "mode mismatch", prepare: func(root string) {
			path := filepath.Join(root, "etc/systemd/system/open-card-edge.service.d")
			if err := os.MkdirAll(path, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, "10-upgrade-marker.conf"), []byte("foreign\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		"binary mode": {expected: "mode mismatch", prepare: func(root string) {
			path := filepath.Join(root, "opt/open-card/upgrade-tools")
			if err := os.MkdirAll(path, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, "open-card-upgrade"), []byte("foreign\n"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		"lock symlink": {expected: "unsafe", prepare: func(root string) {
			path := filepath.Join(root, "run/lock")
			if err := os.MkdirAll(path, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/tmp/foreign-lock", filepath.Join(path, "open-card-upgrade.lock")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(directory, strings.ReplaceAll(name, " ", "-"))
			item.prepare(root)
			command := exec.Command("bash", installScript, "--root", root, "--bundle", bundle, "--test-safe-prefix", directory)
			output, err := command.CombinedOutput()
			if err == nil || !strings.Contains(string(output), item.expected) {
				t.Fatalf("unsafe stable artifact was accepted: %v\n%s", err, output)
			}
		})
	}
}

func TestG2StageUpgradeSubstrateLeavesLegacyRuntimeUntouched(t *testing.T) {
	directory := t.TempDir()
	bundle := writeG2CandidateBundle(t, directory, true)
	_, sourceFile, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	installScript := filepath.Join(repo, "scripts", "mvp", "install.sh")
	root := filepath.Join(directory, "root")
	legacyRelease := filepath.Join(root, "opt/open-card/releases/release-0.8.0-rc.0")
	if err := os.MkdirAll(legacyRelease, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("releases/release-0.8.0-rc.0", filepath.Join(root, "opt/open-card/current")); err != nil {
		t.Fatal(err)
	}
	serverUnit := filepath.Join(root, "etc/systemd/system/open-card-server.service")
	if err := os.MkdirAll(filepath.Dir(serverUnit), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(serverUnit, []byte("legacy-unit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	migrationState := filepath.Join(root, "var/lib/open-card/migration.version")
	if err := os.MkdirAll(filepath.Dir(migrationState), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(migrationState, []byte("0023\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", installScript, "--root", root, "--bundle", bundle, "--stage-upgrade-substrate", "--test-safe-prefix", directory)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("stage upgrade substrate: %v\n%s", err, output)
	}
	if current, err := os.Readlink(filepath.Join(root, "opt/open-card/current")); err != nil || current != "releases/release-0.8.0-rc.0" {
		t.Fatalf("stage changed current pointer=%q err=%v", current, err)
	}
	for _, relative := range []string{"opt/open-card/active", "opt/open-card/previous", "etc/systemd/system/open-card-agent.service", "etc/systemd/system/open-card-edge.service"} {
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(relative))); !os.IsNotExist(err) {
			t.Fatalf("stage unexpectedly created or changed %s: %v", relative, err)
		}
	}
	if got, err := os.ReadFile(serverUnit); err != nil || string(got) != "legacy-unit\n" {
		t.Fatalf("stage replaced legacy server unit=%q err=%v", got, err)
	}
	if got, err := os.ReadFile(migrationState); err != nil || string(got) != "0023\n" {
		t.Fatalf("stage changed migration state=%q err=%v", got, err)
	}
	for relative, mode := range map[string]os.FileMode{
		"opt/open-card/activations":                                          0o711,
		"var/lib/open-card":                                                  0o711,
		"var/lib/open-card/upgrade-transactions":                             0o700,
		"var/lib/open-card/upgrade-artifacts":                                0o700,
		"opt/open-card/upgrade-tools/open-card-upgrade":                      0o755,
		"etc/systemd/system/open-card-upgrade-recover.service":               0o644,
		"etc/systemd/system/open-card-upgrade-safe.target":                   0o644,
		"etc/systemd/system/open-card-upgrade-finalize.service":              0o644,
		"etc/systemd/system/open-card-edge.service.d/10-upgrade-marker.conf": 0o644,
		"run/lock/open-card-upgrade.lock":                                    0o600,
	} {
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode {
			t.Fatalf("stage %s mode=%v err=%v", relative, info.Mode(), err)
		}
	}
	replay := exec.Command("bash", installScript, "--root", root, "--bundle", bundle, "--stage-upgrade-substrate", "--test-safe-prefix", directory)
	if output, err := replay.CombinedOutput(); err != nil || !strings.Contains(string(output), "staged verified upgrade recovery substrate") {
		t.Fatalf("stage replay: %v\n%s", err, output)
	}
}

func TestG2StageUpgradeSubstrateFailsClosedOnDurabilityUncertainty(t *testing.T) {
	directory := t.TempDir()
	bundle := writeG2CandidateBundle(t, directory, true)
	_, sourceFile, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	installScript := filepath.Join(repo, "scripts", "mvp", "install.sh")
	root := filepath.Join(directory, "root")
	command := exec.Command("bash", installScript, "--root", root, "--bundle", bundle, "--stage-upgrade-substrate", "--test-safe-prefix", directory)
	command.Env = append(os.Environ(), "OPEN_CARD_INSTALL_TEST_FAIL_DURABLE_SYNC=1")
	if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), "durability outcome is unknown") {
		t.Fatalf("durability uncertainty was accepted: %v\n%s", err, output)
	}
	if _, err := os.Lstat(filepath.Join(root, "opt/open-card/current")); !os.IsNotExist(err) {
		t.Fatalf("failed stage created current pointer: %v", err)
	}
	retry := exec.Command("bash", installScript, "--root", root, "--bundle", bundle, "--stage-upgrade-substrate", "--test-safe-prefix", directory)
	if output, err := retry.CombinedOutput(); err != nil {
		t.Fatalf("retry after durable uncertainty: %v\n%s", err, output)
	}
}

func TestG2StageUpgradeSubstrateRejectsWritableLayoutParent(t *testing.T) {
	directory := t.TempDir()
	bundle := writeG2CandidateBundle(t, directory, true)
	_, sourceFile, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	root := filepath.Join(directory, "root")
	data := filepath.Join(root, "var/lib/open-card")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(data, 0o777); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", filepath.Join(repo, "scripts", "mvp", "install.sh"), "--root", root, "--bundle", bundle, "--stage-upgrade-substrate", "--test-safe-prefix", directory)
	if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), "writable by group or others") {
		t.Fatalf("writable layout parent was accepted: %v\n%s", err, output)
	}
}

func TestG2StageUpgradeSubstrateDataRootFaultsFailClosed(t *testing.T) {
	for _, phase := range []string{"before-chmod", "after-chmod-before-chown", "chown", "post-chown-sync"} {
		t.Run(phase, func(t *testing.T) {
			directory := t.TempDir()
			bundle := writeG2CandidateBundle(t, directory, true)
			_, sourceFile, _, _ := runtime.Caller(0)
			repo := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
			root := filepath.Join(directory, "root")
			data := filepath.Join(root, "var/lib/open-card")
			child := filepath.Join(data, "uploads/sentinel")
			if err := os.MkdirAll(filepath.Dir(child), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(data, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(child, []byte("still-accessible\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("bash", filepath.Join(repo, "scripts", "mvp", "install.sh"), "--root", root, "--bundle", bundle, "--stage-upgrade-substrate", "--test-safe-prefix", directory)
			command.Env = append(os.Environ(), "OPEN_CARD_INSTALL_TEST_DATA_ROOT_FAULT="+phase, "OPEN_CARD_INSTALL_TEST_DATA_ROOT_FORCE_TRANSITION=1")
			output, err := command.CombinedOutput()
			if err == nil || !strings.Contains(string(output), "upgrade data root fault") {
				t.Fatalf("data root %s fault was accepted: %v\n%s", phase, err, output)
			}
			info, err := os.Stat(data)
			if err != nil || info.Mode().Perm()&0o022 != 0 || (phase != "before-chmod" && info.Mode().Perm() != 0o711) {
				t.Fatalf("data root after %s mode=%v err=%v", phase, info.Mode(), err)
			}
			if got, err := os.ReadFile(child); err != nil || string(got) != "still-accessible\n" {
				t.Fatalf("data child lost access after %s: %q %v", phase, got, err)
			}
		})
	}
}

func TestG2StageUpgradeSubstrateRequiresRC1Candidate(t *testing.T) {
	directory := t.TempDir()
	bundle := writeG2CandidateBundle(t, directory, true)
	manifestPath := filepath.Join(bundle, "manifest.json")
	manifest, err := install.LoadManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Version = install.ProductionNMinusOneVersion
	manifest.MigrationVersion = "0023"
	manifest.SourceCommit = install.RC0SourceCommit
	manifest.NMinusOne = nil
	if err := install.SaveManifest(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	_, sourceFile, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	command := exec.Command("bash", filepath.Join(repo, "scripts", "mvp", "install.sh"), "--root", filepath.Join(directory, "root"), "--bundle", bundle, "--stage-upgrade-substrate", "--test-safe-prefix", directory)
	if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), "requires the 0.8.0-rc.1 production candidate") {
		t.Fatalf("RC0 substrate stage was accepted: %v\n%s", err, output)
	}
}

func TestG2ActivationIntentValidationRejectsFreshRC1WithoutMutation(t *testing.T) {
	directory := t.TempDir()
	bundle := writeG2CandidateBundle(t, directory, true)
	_, sourceFile, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	root := filepath.Join(directory, "root")
	command := exec.Command("bash", filepath.Join(repo, "scripts", "mvp", "install.sh"), "--root", root, "--bundle", bundle, "--dry-run", "--validate-activation-intent", "--test-safe-prefix", directory)
	if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), "requires native bootstrap activation support") {
		t.Fatalf("fresh RC1 activation intent was accepted: %v\n%s", err, output)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("activation intent validation created task root: %v", err)
	}
}
