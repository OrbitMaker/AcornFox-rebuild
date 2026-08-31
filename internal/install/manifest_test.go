package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testManifest(t *testing.T, version string, filePath string, fileData []byte) (Manifest, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(filePath)), 0o755); err != nil {
		t.Fatal(err)
	}
	fullPath := filepath.Join(root, filePath)
	if err := os.WriteFile(fullPath, fileData, 0o755); err != nil {
		t.Fatal(err)
	}
	digest, err := SHA256File(fullPath)
	if err != nil {
		t.Fatal(err)
	}
	return Manifest{
		SchemaVersion: ManifestSchemaVersion, Product: ManifestProduct, Version: version,
		ReleaseID: "release-" + strings.ReplaceAll(version, ".", "-"), Protocol: AgentProtocolVersion,
		ConfigDir: DefaultConfigDir, DataDir: DefaultDataDir,
		Compatibility: Compatibility{MinDataVersion: 1, MaxDataVersion: 8, MinAgentProtocol: PreviousAgentProtocol, MaxAgentProtocol: AgentProtocolVersion},
		Files:         []FileDigest{{Path: filePath, SHA256: digest, Mode: 0o755}},
	}, root
}

func TestManifestValidateAndVerifyRelease(t *testing.T) {
	manifest, release := testManifest(t, "1.2.3", "bin/open-card-server", []byte("server"))
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelease(release, manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(release, "bin/open-card-server"), []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelease(release, manifest); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch, got %v", err)
	}
}

func TestRCManifestLineageUsesOnlyFrozenTuplesAndDigests(t *testing.T) {
	for architecture, expected := range map[string]string{
		"amd64": RC0ReleaseManifestSHA256,
		"arm64": ARM64RC0ReleaseManifestSHA256,
	} {
		lineage, err := RC0LineageForArchitecture(architecture)
		if err != nil || lineage.Architecture != architecture || lineage.ReleaseManifestSHA256 != expected {
			t.Fatalf("frozen %s lineage = %#v, %v", architecture, lineage, err)
		}
	}
	if _, err := RC0LineageForArchitecture("mips64"); err == nil {
		t.Fatal("unsupported architecture has a frozen lineage")
	}
	rc0, _ := testManifest(t, "0.8.0-rc.0", "bin/open-card-server", []byte("server"))
	rc0.MigrationVersion = "0023"
	rc0.SourceCommit = RC0SourceCommit
	if err := rc0.Validate(); err != nil {
		t.Fatal(err)
	}
	rc0.NMinusOne = &NMinusOne{}
	if err := rc0.Validate(); err == nil {
		t.Fatal("rc0 accepted N-1 lineage")
	}

	rc1, _ := testManifest(t, "0.8.0-rc.1", "bin/open-card-server", []byte("server"))
	rc1.Architecture = "amd64"
	rc1.MigrationVersion = "0024"
	rc1.SourceCommit = strings.Repeat("a", 40)
	rc1.NMinusOne = &NMinusOne{Version: "0.8.0-rc.0", MigrationVersion: "0023", SourceCommit: RC0SourceCommit, ReleaseManifestSHA256: RC0ReleaseManifestSHA256, ArchiveSHA256: RC0ArchiveSHA256, BundleManifestSHA256: RC0BundleManifestSHA256}
	if err := rc1.Validate(); err != nil {
		t.Fatal(err)
	}
	arm64 := rc1
	arm64.Architecture = "arm64"
	arm64.NMinusOne = &NMinusOne{Version: "0.8.0-rc.0", MigrationVersion: "0023", SourceCommit: RC0SourceCommit, ReleaseManifestSHA256: ARM64RC0ReleaseManifestSHA256, ArchiveSHA256: ARM64RC0ArchiveSHA256, BundleManifestSHA256: ARM64RC0BundleManifestSHA256}
	if err := arm64.Validate(); err != nil {
		t.Fatalf("arm64 rc1 lineage rejected: %v", err)
	}
	arm64.NMinusOne.ReleaseManifestSHA256 = RC0ReleaseManifestSHA256
	if err := arm64.Validate(); err == nil {
		t.Fatal("arm64 rc1 accepted amd64 predecessor lineage")
	}
	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	if err := SaveManifest(manifestPath, rc1); err != nil {
		t.Fatal(err)
	}
	if loaded, err := LoadManifest(manifestPath); err != nil || loaded.NMinusOne == nil || *loaded.NMinusOne != *rc1.NMinusOne {
		t.Fatalf("strict RC1 manifest round trip failed: %#v %v", loaded, err)
	}
	if err := os.WriteFile(manifestPath, append([]byte(`{"unknown":true}`), '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(manifestPath); err == nil {
		t.Fatal("strict manifest loader accepted unknown RC1 fields")
	}
	rc1.NMinusOne.ArchiveSHA256 = strings.Repeat("0", 64)
	if err := rc1.Validate(); err == nil {
		t.Fatal("rc1 accepted an unpinned N-1 digest")
	}
	rc1.NMinusOne = nil
	if err := rc1.Validate(); err == nil {
		t.Fatal("rc1 accepted missing N-1 lineage")
	}
	rc2, _ := testManifest(t, Gate6CandidateVersion, "bin/open-card-server", []byte("server"))
	rc2.Architecture, rc2.MigrationVersion, rc2.SourceCommit = "amd64", "0024", strings.Repeat("b", 40)
	rc2.NMinusOne = &NMinusOne{Version: Gate6NMinusOneVersion, MigrationVersion: "0024", SourceCommit: RC1SourceCommit, ReleaseManifestSHA256: RC1ReleaseManifestSHA256, ArchiveSHA256: RC1ArchiveSHA256, BundleManifestSHA256: RC1BundleManifestSHA256}
	if err := rc2.Validate(); err != nil {
		t.Fatalf("rc2 lineage rejected: %v", err)
	}
	rc2ARM := rc2
	rc2ARM.Architecture = "arm64"
	rc2ARM.NMinusOne = &NMinusOne{Version: Gate6NMinusOneVersion, MigrationVersion: "0024", SourceCommit: RC1SourceCommit, ReleaseManifestSHA256: ARM64RC1ReleaseManifestSHA256, ArchiveSHA256: ARM64RC1ArchiveSHA256, BundleManifestSHA256: ARM64RC1BundleManifestSHA256}
	if err := rc2ARM.Validate(); err != nil {
		t.Fatalf("arm64 rc2 lineage rejected: %v", err)
	}
	rc2ARM.NMinusOne.ReleaseManifestSHA256 = RC1ReleaseManifestSHA256
	if err := rc2ARM.Validate(); err == nil {
		t.Fatal("arm64 rc2 accepted amd64 predecessor")
	}
	rc2.NMinusOne.SourceCommit = RC0SourceCommit
	if err := rc2.Validate(); err == nil {
		t.Fatal("rc2 accepted RC0 predecessor")
	}
	rc2.NMinusOne.SourceCommit = RC1SourceCommit
	for name, mutate := range map[string]func(*NMinusOne){
		"version":   func(n *NMinusOne) { n.Version = ProductionNMinusOneVersion },
		"migration": func(n *NMinusOne) { n.MigrationVersion = "0023" },
		"manifest":  func(n *NMinusOne) { n.ReleaseManifestSHA256 = strings.Repeat("0", 64) },
		"archive":   func(n *NMinusOne) { n.ArchiveSHA256 = strings.Repeat("0", 64) },
		"bundle":    func(n *NMinusOne) { n.BundleManifestSHA256 = strings.Repeat("0", 64) },
	} {
		t.Run("rc2-"+name, func(t *testing.T) {
			candidate := rc2
			lineage := *candidate.NMinusOne
			candidate.NMinusOne = &lineage
			mutate(candidate.NMinusOne)
			if err := candidate.Validate(); err == nil {
				t.Fatal("rc2 accepted invalid predecessor field")
			}
		})
	}
	rc3, _ := testManifest(t, Gate7CandidateVersion, "bin/open-card-server", []byte("server"))
	rc3.Architecture, rc3.MigrationVersion, rc3.SourceCommit = "amd64", "0024", strings.Repeat("c", 40)
	rc3.NMinusOne = &NMinusOne{Version: Gate7NMinusOneVersion, MigrationVersion: "0024", SourceCommit: RC2SourceCommit, ReleaseManifestSHA256: RC2ReleaseManifestSHA256, ArchiveSHA256: RC2ArchiveSHA256, BundleManifestSHA256: RC2BundleManifestSHA256}
	if err := rc3.Validate(); err != nil {
		t.Fatalf("rc3 lineage rejected: %v", err)
	}
	rc3ARM := rc3
	rc3ARM.Architecture = "arm64"
	rc3ARM.NMinusOne = &NMinusOne{Version: Gate7NMinusOneVersion, MigrationVersion: "0024", SourceCommit: RC2SourceCommit, ReleaseManifestSHA256: ARM64RC2ReleaseManifestSHA256, ArchiveSHA256: ARM64RC2ArchiveSHA256, BundleManifestSHA256: ARM64RC2BundleManifestSHA256}
	if err := rc3ARM.Validate(); err != nil {
		t.Fatalf("arm64 rc3 lineage rejected: %v", err)
	}
	rc3ARM.NMinusOne.ArchiveSHA256 = RC2ArchiveSHA256
	if err := rc3ARM.Validate(); err == nil {
		t.Fatal("arm64 rc3 accepted amd64 predecessor")
	}
	rc3.NMinusOne.SourceCommit = RC1SourceCommit
	if err := rc3.Validate(); err == nil {
		t.Fatal("rc3 accepted RC1 predecessor")
	}

	other, _ := testManifest(t, "1.2.3", "bin/open-card-server", []byte("server"))
	other.SourceCommit = strings.Repeat("a", 40)
	if err := other.Validate(); err == nil {
		t.Fatal("non-RC manifest accepted source lineage")
	}
}

func TestProductionCandidateRequires0024PayloadAndRejectsFixtures(t *testing.T) {
	manifest, _ := testManifest(t, Gate6CandidateVersion, "bin/open-card-admin", []byte("admin"))
	manifest.Architecture = "amd64"
	manifest.MigrationVersion = CurrentMigrationVersion
	manifest.SourceCommit = strings.Repeat("a", 40)
	manifest.NMinusOne = &NMinusOne{Version: Gate6NMinusOneVersion, MigrationVersion: "0024", SourceCommit: RC1SourceCommit, ReleaseManifestSHA256: RC1ReleaseManifestSHA256, ArchiveSHA256: RC1ArchiveSHA256, BundleManifestSHA256: RC1BundleManifestSHA256}
	manifest.Files = append(manifest.Files,
		FileDigest{Path: "bin/open-card-upgrade", SHA256: strings.Repeat("9", 64), Mode: 0o755},
		FileDigest{Path: "systemd/open-card-edge.service", SHA256: strings.Repeat("a", 64), Mode: 0o644},
		FileDigest{Path: "systemd/open-card-upgrade-recover.service", SHA256: strings.Repeat("0", 64), Mode: 0o644},
		FileDigest{Path: "systemd/open-card-upgrade-safe.target", SHA256: strings.Repeat("1", 64), Mode: 0o644},
		FileDigest{Path: "systemd/open-card-upgrade-finalize.service", SHA256: strings.Repeat("2", 64), Mode: 0o644},
		FileDigest{Path: "systemd/open-card-edge.service.d/10-upgrade-marker.conf", SHA256: strings.Repeat("3", 64), Mode: 0o644},
		FileDigest{Path: "caddy/open-card-edge.Caddyfile.example", SHA256: strings.Repeat("b", 64), Mode: 0o644},
		FileDigest{Path: "migrations/control-plane/0024_dns_change_ledger.sql", SHA256: strings.Repeat("c", 64), Mode: 0o644},
		FileDigest{Path: "web/dist/index.html", SHA256: strings.Repeat("d", 64), Mode: 0o644},
		FileDigest{Path: "docs/licenses/licenses-manifest.json", SHA256: strings.Repeat("e", 64), Mode: 0o644},
		FileDigest{Path: "sbom.spdx.json", SHA256: strings.Repeat("f", 64), Mode: 0o644},
		FileDigest{Path: "source-manifest.sha256", SHA256: strings.Repeat("1", 64), Mode: 0o644},
		FileDigest{Path: "scripts/mvp/host-preflight.sh", SHA256: strings.Repeat("2", 64), Mode: 0o755},
		FileDigest{Path: "scripts/mvp/buildkit-production-capacity.sh", SHA256: strings.Repeat("3", 64), Mode: 0o755},
		FileDigest{Path: "scripts/mvp/g6-staging-evidence.sh", SHA256: strings.Repeat("4", 64), Mode: 0o755},
		FileDigest{Path: "tools/evidence/g6_validate.py", SHA256: strings.Repeat("5", 64), Mode: 0o755},
		FileDigest{Path: "tools/evidence/g6_target_receipt.py", SHA256: strings.Repeat("6", 64), Mode: 0o755},
	)
	if err := ValidateProductionCandidate(manifest); err != nil {
		t.Fatalf("production candidate rejected: %v", err)
	}
	manifest.Files = append(manifest.Files, FileDigest{Path: "tests/fixture.test", SHA256: strings.Repeat("2", 64), Mode: 0o644})
	if err := ValidateProductionCandidate(manifest); err == nil {
		t.Fatal("test-only production payload was accepted")
	}
}

func TestRC3ProductionCandidateRequiresHealthcheckAssets(t *testing.T) {
	manifest, _ := testManifest(t, Gate7CandidateVersion, "bin/open-card-admin", []byte("admin"))
	manifest.Architecture, manifest.MigrationVersion, manifest.SourceCommit = "amd64", CurrentMigrationVersion, strings.Repeat("a", 40)
	manifest.NMinusOne = &NMinusOne{Version: Gate7NMinusOneVersion, MigrationVersion: "0024", SourceCommit: RC2SourceCommit, ReleaseManifestSHA256: RC2ReleaseManifestSHA256, ArchiveSHA256: RC2ArchiveSHA256, BundleManifestSHA256: RC2BundleManifestSHA256}
	for _, path := range []string{
		"bin/open-card-upgrade", "bin/open-card-healthcheck", "systemd/open-card-edge.service", "systemd/open-card-upgrade-recover.service", "systemd/open-card-upgrade-safe.target", "systemd/open-card-upgrade-finalize.service", "systemd/open-card-edge.service.d/10-upgrade-marker.conf", "systemd/open-card-healthcheck.service", "systemd/open-card-healthcheck.timer", "caddy/open-card-edge.Caddyfile.example", "migrations/control-plane/0024_dns_change_ledger.sql", "web/dist/index.html", "docs/licenses/licenses-manifest.json", "sbom.spdx.json", "source-manifest.sha256", "scripts/mvp/host-preflight.sh", "scripts/mvp/buildkit-production-capacity.sh", "scripts/mvp/g6-staging-evidence.sh", "tools/evidence/g6_validate.py", "tools/evidence/g6_target_receipt.py",
	} {
		mode := uint32(0o644)
		if strings.HasPrefix(path, "bin/") || strings.HasPrefix(path, "scripts/") || strings.HasPrefix(path, "tools/") {
			mode = 0o755
		}
		manifest.Files = append(manifest.Files, FileDigest{Path: path, SHA256: strings.Repeat("9", 64), Mode: mode})
	}
	if err := ValidateProductionCandidate(manifest); err != nil {
		t.Fatalf("rc3 production candidate rejected: %v", err)
	}
	filtered := manifest.Files[:0]
	for _, file := range manifest.Files {
		if file.Path != "systemd/open-card-healthcheck.timer" {
			filtered = append(filtered, file)
		}
	}
	manifest.Files = filtered
	if err := ValidateProductionCandidate(manifest); err == nil {
		t.Fatal("rc3 accepted missing required payload")
	}
}

func TestManifestRejectsTraversalAndSymlinks(t *testing.T) {
	manifest, release := testManifest(t, "1.0.0", "bin/open-card-agent", []byte("agent"))
	manifest.Files[0].Path = "../outside"
	if err := manifest.Validate(); err == nil {
		t.Fatal("expected traversal path rejection")
	}
	manifest, release = testManifest(t, "1.0.0", "bin/open-card-agent", []byte("agent"))
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(release, "bin/open-card-agent")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(release, "bin/open-card-agent")); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelease(release, manifest); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestManifestRejectsUnsafeOrMismatchedFileMode(t *testing.T) {
	manifest, release := testManifest(t, "1.0.0", "bin/open-card-agent", []byte("agent"))
	manifest.Files[0].Mode = 0o777
	if err := manifest.Validate(); err == nil || !strings.Contains(err.Error(), "unsafe mode") {
		t.Fatalf("expected unsafe mode rejection, got %v", err)
	}
	manifest.Files[0].Mode = 0o700
	if err := VerifyRelease(release, manifest); err == nil || !strings.Contains(err.Error(), "mode mismatch") {
		t.Fatalf("expected mode mismatch, got %v", err)
	}
}

func TestVerifyReleaseRejectsUnlistedFile(t *testing.T) {
	manifest, release := testManifest(t, "1.0.0", "bin/open-card-agent", []byte("agent"))
	if err := os.WriteFile(filepath.Join(release, "unlisted"), []byte("unexpected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelease(release, manifest); err == nil || !strings.Contains(err.Error(), "file set") {
		t.Fatalf("expected unlisted file rejection, got %v", err)
	}
}

func TestDirectoriesForRootAndAtomicReleasePointer(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	dirs, err := DirectoriesForRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if dirs.Current != filepath.Join(root, "opt/open-card/current") || dirs.Config != filepath.Join(root, "etc/open-card") {
		t.Fatalf("unexpected directory contract: %#v", dirs)
	}
	if _, err := DirectoriesForRoot("/"); err == nil {
		t.Fatal("expected root rejection")
	}
	if err := os.MkdirAll(filepath.Join(dirs.Releases, "1.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanReleasePointer(dirs, "", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := AtomicSwitchRelease(dirs, plan); err != nil {
		t.Fatal(err)
	}
	got, err := filepath.EvalSymlinks(dirs.Current)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(filepath.Join(dirs.Releases, "1.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("current points to %s, want %s", got, want)
	}
	if _, err := PlanReleasePointer(dirs, "1.0.0", "../escape"); err == nil {
		t.Fatal("expected release traversal rejection")
	}
}

func TestCompatibilityAllowsNMinusOneAndRejectsMajorOrProtocolDrift(t *testing.T) {
	current, _ := testManifest(t, "1.2.0", "bin/server", []byte("current"))
	current.Protocol = PreviousAgentProtocol
	candidate, _ := testManifest(t, "1.3.0", "bin/server", []byte("candidate"))
	if err := CheckCompatibility(current, candidate, 3, LegacyAgentProtocol); err != nil {
		t.Fatalf("expected compatible minor upgrade: %v", err)
	}
	candidate.Version = "2.0.0"
	if err := CheckCompatibility(current, candidate, 3, "v1"); err == nil {
		t.Fatal("expected major version rejection")
	}
	candidate.Version = "1.3.0"
	candidate.Compatibility.MinAgentProtocol = AgentProtocolVersion
	candidate.Compatibility.MaxAgentProtocol = AgentProtocolVersion
	if err := CheckCompatibility(current, candidate, 3, PreviousAgentProtocol); err == nil {
		t.Fatal("expected protocol rejection")
	}
}

func TestLegacyProtocolInputNormalizesToNMinusOne(t *testing.T) {
	manifest, _ := testManifest(t, "1.0.0", "bin/server", []byte("server"))
	manifest.Protocol = LegacyAgentProtocol
	manifest.Compatibility.MinAgentProtocol = LegacyAgentProtocol
	manifest.Compatibility.MaxAgentProtocol = AgentProtocolVersion
	normalized, err := NormalizeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Protocol != PreviousAgentProtocol || normalized.Compatibility.MinAgentProtocol != PreviousAgentProtocol {
		t.Fatalf("normalized manifest=%#v", normalized)
	}
}

func TestBackupMetadataChecksumValidation(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "control-plane.tar.gz")
	if err := os.WriteFile(archive, []byte("backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := SHA256File(archive)
	if err != nil {
		t.Fatal(err)
	}
	metadataPath := filepath.Join(tmp, "control-plane.json")
	metadata := BackupMetadata{SchemaVersion: ManifestSchemaVersion, BackupID: "backup-1", CreatedAt: time.Unix(1, 0).UTC(), SourceDataDir: "/var/lib/open-card", Archive: filepath.Base(archive), ArchiveSHA256: digest, Consistency: "filesystem-fixture"}
	if err := SaveBackupMetadata(metadataPath, metadata); err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyBackup(metadataPath); err != nil || got.BackupID != metadata.BackupID {
		t.Fatalf("verify backup: %#v %v", got, err)
	}
	if err := os.WriteFile(archive, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBackup(metadataPath); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected backup checksum rejection, got %v", err)
	}
}

func TestCurrentProductionMigrationRemainsPresentWhenDevelopmentMigrationsFollow(t *testing.T) {
	directory := filepath.Join("..", "..", "migrations", "control-plane")
	latest, err := LatestMigrationVersion(directory)
	if err != nil || latest < CurrentMigrationVersion {
		t.Fatalf("latest development migration=%q err=%v", latest, err)
	}
	if _, err := os.Stat(filepath.Join(directory, CurrentMigrationVersion+"_dns_change_ledger.sql")); err != nil {
		t.Fatalf("frozen production migration is absent: %v", err)
	}
}
