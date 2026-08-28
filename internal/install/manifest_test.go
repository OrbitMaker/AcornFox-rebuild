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

func TestProductionCandidateRequires0023PayloadAndRejectsFixtures(t *testing.T) {
	manifest, _ := testManifest(t, ProductionCandidateVersion, "bin/open-card-admin", []byte("admin"))
	manifest.MigrationVersion = CurrentMigrationVersion
	manifest.Files = append(manifest.Files,
		FileDigest{Path: "systemd/open-card-edge.service", SHA256: strings.Repeat("a", 64), Mode: 0o644},
		FileDigest{Path: "caddy/open-card-edge.Caddyfile.example", SHA256: strings.Repeat("b", 64), Mode: 0o644},
		FileDigest{Path: "migrations/control-plane/0023_source_uploads.sql", SHA256: strings.Repeat("c", 64), Mode: 0o644},
		FileDigest{Path: "web/dist/index.html", SHA256: strings.Repeat("d", 64), Mode: 0o644},
		FileDigest{Path: "docs/licenses/licenses-manifest.json", SHA256: strings.Repeat("e", 64), Mode: 0o644},
		FileDigest{Path: "sbom.spdx.json", SHA256: strings.Repeat("f", 64), Mode: 0o644},
		FileDigest{Path: "source-manifest.sha256", SHA256: strings.Repeat("1", 64), Mode: 0o644},
	)
	if err := ValidateProductionCandidate(manifest); err != nil {
		t.Fatalf("production candidate rejected: %v", err)
	}
	manifest.Files = append(manifest.Files, FileDigest{Path: "tests/fixture.test", SHA256: strings.Repeat("2", 64), Mode: 0o644})
	if err := ValidateProductionCandidate(manifest); err == nil {
		t.Fatal("test-only production payload was accepted")
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

func TestCurrentMigrationMatchesControlPlaneDirectory(t *testing.T) {
	directory := filepath.Join("..", "..", "migrations", "control-plane")
	if err := RequireCurrentMigration(directory); err != nil {
		t.Fatal(err)
	}
}
