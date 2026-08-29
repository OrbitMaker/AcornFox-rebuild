package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeriveUpgradeCLIIdentityIsDeterministicAndDomainSeparated(t *testing.T) {
	release := VerifiedUpgradeReleaseV1{Release: ReleaseV1{ID: "release-cli", Version: ProductionCandidateVersion, SourceCommit: "0123456789abcdef0123456789abcdef01234567", Architecture: "amd64", ManifestSHA256: strings.Repeat("a", 64)}, UpgradeExecutableSHA256: strings.Repeat("b", 64)}
	first, err := DeriveUpgradeCLIIdentity("upgrade-cli", release)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DeriveUpgradeCLIIdentity("upgrade-cli", release)
	if err != nil || first != second || !strings.HasPrefix(first.Request.CandidateActivationID, "act-") || !candidateDatabaseName.MatchString(first.Request.CandidateDatabaseName) || first.Request.RequestedManifestSHA256 != release.Release.ManifestSHA256 || first.Request.RecoveryEvidenceSHA256 != first.RecoveryEvidenceSHA256 || !validSHA(first.RecoveryEvidenceSHA256) {
		t.Fatalf("unexpected identity: %#v %v", first, err)
	}
	different, err := DeriveUpgradeCLIIdentity("upgrade-cli-other", release)
	if err != nil || different.Request.CandidateActivationID == first.Request.CandidateActivationID || different.RecoveryEvidenceSHA256 == first.RecoveryEvidenceSHA256 {
		t.Fatalf("transaction was not domain-separated: %#v %v", different, err)
	}
	for _, input := range []struct {
		tx      string
		release VerifiedUpgradeReleaseV1
	}{
		{"../bad", release},
		{"upgrade-cli", VerifiedUpgradeReleaseV1{}},
	} {
		if _, err := DeriveUpgradeCLIIdentity(input.tx, input.release); err == nil {
			t.Fatalf("accepted unsafe identity %#v", input)
		}
	}
}

func TestLoadVerifiedUpgradeReleaseRejectsManifestAndPayloadDrift(t *testing.T) {
	prefix := t.TempDir()
	releaseID := "release-cli-contract"
	releaseDir := filepath.Join(prefix, "releases", releaseID)
	files := map[string]struct {
		data []byte
		mode os.FileMode
	}{
		"bin/open-card-admin":                                     {[]byte("admin"), 0o755},
		"bin/open-card-upgrade":                                   {[]byte("upgrade"), 0o755},
		"systemd/open-card-edge.service":                          {[]byte("edge unit"), 0o644},
		"systemd/open-card-upgrade-recover.service":               {ProductionUpgradeRecoveryUnitBytes(), 0o644},
		"systemd/open-card-upgrade-safe.target":                   {ProductionUpgradeSafeBootTargetBytes(), 0o644},
		"systemd/open-card-upgrade-finalize.service":              {ProductionUpgradeFinalizeUnitBytes(), 0o644},
		"systemd/open-card-edge.service.d/10-upgrade-marker.conf": {ProductionUpgradeEdgeMarkerDropInBytes(), 0o644},
		"caddy/open-card-edge.Caddyfile.example":                  {[]byte("edge caddy"), 0o644},
		"migrations/control-plane/0024_dns_change_ledger.sql":     {[]byte("migration"), 0o644},
		"web/dist/index.html":                                     {[]byte("web"), 0o644},
		"docs/licenses/licenses-manifest.json":                    {[]byte("licenses"), 0o644},
		"sbom.spdx.json":                                          {[]byte("sbom"), 0o644},
		"source-manifest.sha256":                                  {[]byte("source"), 0o644},
	}
	manifest := Manifest{SchemaVersion: ManifestSchemaVersion, Product: ManifestProduct, Version: ProductionCandidateVersion, ReleaseID: releaseID, Architecture: "amd64", MigrationVersion: CurrentMigrationVersion, SourceCommit: strings.Repeat("a", 40), NMinusOne: &NMinusOne{Version: ProductionNMinusOneVersion, MigrationVersion: "0023", SourceCommit: RC0SourceCommit, ReleaseManifestSHA256: RC0ReleaseManifestSHA256, ArchiveSHA256: RC0ArchiveSHA256, BundleManifestSHA256: RC0BundleManifestSHA256}, Protocol: AgentProtocolVersion, ConfigDir: DefaultConfigDir, DataDir: DefaultDataDir, Compatibility: Compatibility{MinDataVersion: 1, MaxDataVersion: 8, MinAgentProtocol: PreviousAgentProtocol, MaxAgentProtocol: AgentProtocolVersion}}
	for path, file := range files {
		full := filepath.Join(releaseDir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, file.data, file.mode); err != nil {
			t.Fatal(err)
		}
		digest, err := SHA256File(full)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Files = append(manifest.Files, FileDigest{Path: path, SHA256: digest, Mode: uint32(file.mode)})
	}
	manifestPath := filepath.Join(releaseDir, "manifest.json")
	if err := SaveManifest(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	digest, err := SHA256File(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loadVerifiedUpgradeReleaseAt(prefix, releaseID, digest, os.Getuid(), os.Getgid())
	if err != nil || loaded.Release.ID != releaseID || loaded.Release.ManifestSHA256 != digest || !validSHA(loaded.UpgradeExecutableSHA256) {
		t.Fatalf("verified release failed: %#v %v", loaded, err)
	}
	if _, err := loadVerifiedUpgradeReleaseAt(prefix, releaseID, strings.Repeat("b", 64), os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("wrong manifest digest accepted")
	}
	if err := os.WriteFile(filepath.Join(releaseDir, "web/dist/index.html"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVerifiedUpgradeReleaseAt(prefix, releaseID, digest, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("payload drift accepted")
	}
	if err := os.Remove(filepath.Join(releaseDir, "web/dist/index.html")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(prefix, "outside"), filepath.Join(releaseDir, "web/dist/index.html")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVerifiedUpgradeReleaseAt(prefix, releaseID, digest, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("symlink swap accepted")
	}
}
