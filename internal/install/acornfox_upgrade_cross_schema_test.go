package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func acornFoxCrossSchemaManifestFixture(t *testing.T) (acornFoxFixture, Manifest, acornFoxFixture, Manifest) {
	t.Helper()
	old := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	var oldManifest Manifest
	if err := strictCanonicalJSON(old.manifestRaw, &oldManifest, "old fixture"); err != nil {
		t.Fatal(err)
	}
	oldManifest.MigrationVersion = AcornFoxLegacyPredecessorMigration
	oldManifest.Compatibility.MinDataVersion = 34
	oldManifest.Compatibility.MaxDataVersion = 34
	oldManifest.NMinusOne = nil
	allowed := map[string]bool{}
	for _, file := range acornFoxLegacy0034RequiredFiles() {
		allowed[file.Path] = true
	}
	files := oldManifest.Files[:0]
	for _, file := range oldManifest.Files {
		if !allowed[file.Path] && !strings.HasPrefix(file.Path, "web/dist/assets/") {
			continue
		}
		files = append(files, file)
	}
	oldManifest.Files = files
	old.manifestRaw = acornFoxUpgradeJSON(oldManifest)
	old.binding.MigrationVersion = AcornFoxLegacyPredecessorMigration
	old.binding.ManifestSHA256 = sha256Hex(old.manifestRaw)
	old.binding.NMinusOne = nil
	refreshAcornFoxBinding(t, &old)
	next := newAcornFoxFixture(t, "1.2.4-test.1", &old)
	var nextManifest Manifest
	if err := strictCanonicalJSON(next.manifestRaw, &nextManifest, "next fixture"); err != nil {
		t.Fatal(err)
	}
	return old, oldManifest, next, nextManifest
}

func TestAcornFoxCrossSchemaManifestsAcceptOnlyExact0034Prefix(t *testing.T) {
	old, oldManifest, next, nextManifest := acornFoxCrossSchemaManifestFixture(t)
	if _, _, ok := acornFoxCrossSchemaManifests(acornFoxUpgradeJSON(oldManifest), acornFoxUpgradeJSON(nextManifest), old.binding, next.binding); !ok {
		t.Fatal("exact 0034 predecessor was rejected")
	}
	tests := []struct {
		name   string
		mutate func(*Manifest, *Manifest)
	}{
		{"old-extra-migration", func(old, _ *Manifest) {
			old.Files = append(old.Files, FileDigest{Path: "migrations/control-plane/0035_foreign.sql", SHA256: strings.Repeat("1", 64), Mode: 0o640})
		}},
		{"prefix-checksum-drift", func(_, next *Manifest) {
			for index := range next.Files {
				if strings.HasPrefix(next.Files[index].Path, "migrations/control-plane/") && next.Files[index].Path <= "migrations/control-plane/0034_artifacts_per_build.sql" {
					next.Files[index].SHA256 = strings.Repeat("2", 64)
					break
				}
			}
		}},
		{"old-compatibility-drift", func(old, _ *Manifest) { old.Compatibility.MaxDataVersion = 39 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			forgedOld, forgedNext := oldManifest, nextManifest
			forgedOld.Files = append([]FileDigest(nil), oldManifest.Files...)
			forgedNext.Files = append([]FileDigest(nil), nextManifest.Files...)
			test.mutate(&forgedOld, &forgedNext)
			if _, _, ok := acornFoxCrossSchemaManifests(acornFoxUpgradeJSON(forgedOld), acornFoxUpgradeJSON(forgedNext), old.binding, next.binding); ok {
				t.Fatal("forged migration pair was accepted")
			}
		})
	}
}

func TestAcornFoxCrossSchemaEvidenceContainsNoDatabaseEnvironment(t *testing.T) {
	evidence := acornFoxCrossSchemaUpgradeV1{
		SchemaVersion: 1, HostProvisionSHA256: strings.Repeat("1", 64), OldMigrationVersion: AcornFoxLegacyPredecessorMigration,
		NextMigrationVersion: AcornFoxV1MigrationVersion, TargetRowsSHA256: strings.Repeat("2", 64),
	}
	raw, err := json.Marshal(evidence)
	if err != nil || strings.Contains(string(raw), "DATABASE_URL") || strings.Contains(string(raw), "postgresql://") {
		t.Fatalf("public evidence leaked private database input: %s err=%v", raw, err)
	}
}

func TestAcornFoxCrossSchemaSourceVersionsAreClosed(t *testing.T) {
	if version, ok := acornFoxCrossSchemaSourceDataVersion(AcornFoxLegacyPredecessorMigration); !ok || version != 34 {
		t.Fatalf("0034 source version=%d ok=%t", version, ok)
	}
	recent, recentOK := acornFoxCrossSchemaSourceDataVersion(acornFoxRecentPredecessorMigration)
	if AcornFoxV1MigrationVersion == acornFoxRecentPredecessorMigration {
		if recentOK || recent != 39 {
			t.Fatalf("current 0039 unexpectedly became a cross-schema source: %d/%t", recent, recentOK)
		}
	} else if !recentOK || recent != 39 {
		t.Fatalf("frozen 0039 source version=%d ok=%t", recent, recentOK)
	}
	for _, migration := range []string{"", "0035", "0038", "0041", "latest"} {
		if _, ok := acornFoxCrossSchemaSourceDataVersion(migration); ok {
			t.Fatalf("untrusted source migration %q accepted", migration)
		}
	}
}

func TestAcornFoxUpgradeHealthUsesFrozenPredecessorUnits(t *testing.T) {
	units, err := acornFoxUpgradeHealthyUnits(acornFoxUpgradeImage{Substrate: InactiveSubstrateReceiptV1{CandidateReceipt: AcornFoxStageReceiptV1{MigrationVersion: AcornFoxLegacyPredecessorMigration}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, unit := range units {
		if unit == "acornfox-runtime-network.service" {
			t.Fatal("0034 health required a future unit")
		}
	}
	current, err := acornFoxUpgradeHealthyUnits(acornFoxUpgradeImage{Substrate: InactiveSubstrateReceiptV1{CandidateReceipt: AcornFoxStageReceiptV1{MigrationVersion: AcornFoxV1MigrationVersion}}})
	if err != nil || !containsString(current, "acornfox-runtime-network.service") {
		t.Fatalf("0040 units=%q err=%v", current, err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestAcornFoxRecent0039PredecessorPolicyIsFrozen(t *testing.T) {
	predecessor := newAcornFoxFixture(t, "1.2.2-test.1", nil)
	predecessor.binding.MigrationVersion = AcornFoxLegacyPredecessorMigration
	refreshAcornFoxBinding(t, &predecessor)
	recent := newAcornFoxFixture(t, "1.2.3-test.1", &predecessor)
	var manifest Manifest
	if err := strictCanonicalJSON(recent.manifestRaw, &manifest, "0039 fixture"); err != nil {
		t.Fatal(err)
	}
	manifest.MigrationVersion = acornFoxRecentPredecessorMigration
	manifest.Compatibility.MinDataVersion, manifest.Compatibility.MaxDataVersion = 39, 39
	files := manifest.Files[:0]
	for _, file := range manifest.Files {
		if file.Path != "migrations/control-plane/0040_acornfox_fix_candidates.sql" {
			files = append(files, file)
		}
	}
	manifest.Files = files
	recent.manifestRaw = acornFoxUpgradeJSON(manifest)
	recent.binding.MigrationVersion = acornFoxRecentPredecessorMigration
	recent.binding.ManifestSHA256 = sha256Hex(recent.manifestRaw)
	refreshAcornFoxBinding(t, &recent)
	if validateAcornFoxRecent0039Binding(recent.binding) != nil || validateAcornFoxRecent0039Manifest(manifest, recent.binding) != nil || len(acornFoxRecent0039Migrations) != 39 || acornFoxRecent0039Migrations[38] != "0039_acornfox_access_observations.sql" {
		t.Fatal("0039 predecessor policy rejected its frozen package")
	}
	next := newAcornFoxFixture(t, "1.2.4-test.1", &recent)
	var nextManifest Manifest
	if err := strictCanonicalJSON(next.manifestRaw, &nextManifest, "0040 fixture"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := acornFoxCrossSchemaManifests(acornFoxUpgradeJSON(manifest), acornFoxUpgradeJSON(nextManifest), recent.binding, next.binding); !ok {
		t.Fatal("exact 0039 to 0040 migration pair was rejected")
	}
	if _, err := ParseAcornFoxCandidateBindingV1(next.bindingRaw, next.bindingSHA); err != nil {
		t.Fatalf("0040 candidate rejected exact 0039 predecessor: %v", err)
	}
	forged := manifest
	forged.Files = append([]FileDigest(nil), manifest.Files...)
	forged.Files = append(forged.Files, FileDigest{Path: "migrations/control-plane/0040_untrusted.sql", SHA256: strings.Repeat("3", 64), Mode: 0o640})
	if validateAcornFoxRecent0039Manifest(forged, recent.binding) == nil {
		t.Fatal("0039 predecessor policy accepted a future migration")
	}
	broken := recent.binding
	broken.NMinusOne = &AcornFoxNMinusOneV1{Version: "1.2.2", MigrationVersion: "0038", SourceCommit: strings.Repeat("a", 40), ReleaseManifestSHA256: strings.Repeat("b", 64), ArchiveSHA256: strings.Repeat("c", 64), BundleManifestSHA256: strings.Repeat("d", 64), BindingSHA256: strings.Repeat("e", 64)}
	if validateAcornFoxRecent0039Binding(broken) == nil {
		t.Fatal("0039 predecessor accepted an untrusted n_minus_one schema")
	}
}

func TestAcornFoxRecent0039ReceiptsAreExact(t *testing.T) {
	prepared := newAcornFoxProductionPreparedFixture(t)
	bindingRaw, err := os.ReadFile(filepath.Join(prepared.state, "bindings", prepared.binding+".json"))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := parseAcornFoxCandidateBindingV1(bindingRaw, prepared.binding)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(prepared.host, "opt/acornfox/releases", binding.ReleaseID, "manifest.json")
	manifestRaw, err := os.ReadFile(manifestPath)
	var manifest Manifest
	if err != nil || strictCanonicalJSON(manifestRaw, &manifest, "current manifest") != nil {
		t.Fatal("manifest unavailable", err)
	}
	manifest.MigrationVersion = acornFoxRecentPredecessorMigration
	manifest.Compatibility.MinDataVersion, manifest.Compatibility.MaxDataVersion = 39, 39
	manifestFiles := manifest.Files[:0]
	for _, file := range manifest.Files {
		if file.Path != "migrations/control-plane/0040_acornfox_fix_candidates.sql" {
			manifestFiles = append(manifestFiles, file)
		}
	}
	manifest.Files = manifestFiles
	manifestRaw = acornFoxUpgradeJSON(manifest)
	binding.MigrationVersion = acornFoxRecentPredecessorMigration
	binding.ManifestSHA256 = sha256Hex(manifestRaw)
	bindingRaw = acornFoxUpgradeJSON(binding)
	bindingSHA := sha256Hex(bindingRaw)
	substrate := prepared.published.receipt
	substrate.CandidateReceipt.MigrationVersion = acornFoxRecentPredecessorMigration
	substrate.CandidateReceipt.ManifestSHA256 = binding.ManifestSHA256
	substrate.CandidateReceipt.BindingSHA256 = bindingSHA
	substrate.CandidateReceipt.FileCount--
	entries := substrate.Entries[:0]
	manifestEntryPath := "opt/acornfox/releases/" + binding.ReleaseID + "/manifest.json"
	migration40Path := "opt/acornfox/releases/" + binding.ReleaseID + "/migrations/control-plane/0040_acornfox_fix_candidates.sql"
	for _, entry := range substrate.Entries {
		if entry.Path == migration40Path {
			continue
		}
		if entry.Path == manifestEntryPath {
			entry.SHA256 = sha256Hex(manifestRaw)
			entry.Size = int64(len(manifestRaw))
		}
		entries = append(entries, entry)
	}
	substrate.Entries = entries
	releaseTree, err := ComputeAcornFoxReleaseTreeSHA256(substrate.CandidateReceipt, substrate.Entries)
	if err != nil {
		t.Fatal(err)
	}
	substrate.CandidateReceipt.TreeSHA256 = releaseTree
	substrate.ReleaseTreeSHA256 = releaseTree
	substrate.InstalledTreeSHA256, err = ComputeAcornFoxSubstrateTreeSHA256(substrate.Entries)
	if err != nil {
		t.Fatal(err)
	}
	if validateAcornFoxRecent0039SubstrateReceipt(substrate, binding, bindingSHA) != nil {
		t.Fatal("0039 substrate receipt rejected")
	}
	source, err := acornFoxRecent0039ExpectedEntries(prepared.layout, substrate)
	if err != nil {
		t.Fatal(err)
	}
	liveEntries := make([]AcornFoxLiveEntryV1, 0, len(source))
	for _, entry := range source {
		if acornFoxProductionSharedParent(entry.Path) {
			continue
		}
		converted, convertErr := acornFoxLiveEntryForLayout(prepared.layout, entry)
		if convertErr != nil {
			t.Fatal(convertErr)
		}
		liveEntries = append(liveEntries, converted)
	}
	liveTree, err := acornFoxLiveDigest(liveEntries)
	if err != nil {
		t.Fatal(err)
	}
	ownership, err := acornFoxLiveOwnershipDigest(liveEntries)
	if err != nil {
		t.Fatal(err)
	}
	static, err := acornFoxLiveStaticDigest(liveEntries)
	if err != nil {
		t.Fatal(err)
	}
	substrateRaw := acornFoxUpgradeJSON(substrate)
	live := AcornFoxLiveReceiptV1{SchemaVersion: AcornFoxLiveReceiptV1Schema, State: "host_live_materialized", BindingSHA256: bindingSHA, SubstrateReceiptSHA256: sha256Hex(substrateRaw), ReleaseID: binding.ReleaseID, LiveTreeSHA256: liveTree, OwnershipPlanSHA256: ownership, StaticSetSHA256: static, LayoutSHA256: prepared.layout.evidence(), OwnershipEvidence: "host_uid_gid_verified", Entries: liveEntries}
	if validateAcornFoxRecent0039LiveReceiptForLayout(prepared.layout, substrate, binding, bindingSHA, live) != nil {
		t.Fatal("0039 live receipt rejected")
	}
	forged := substrate
	forged.Entries = append([]SubstrateEntry(nil), substrate.Entries...)
	forged.Entries = append(forged.Entries, SubstrateEntry{Path: "etc/acornfox/foreign", Kind: SubstrateEntryFile, Mode: 0o600, Role: OwnerRoleRoot, Group: GroupRoleRoot, Size: 1, SHA256: strings.Repeat("4", 64)})
	if validateAcornFoxRecent0039SubstrateReceipt(forged, binding, bindingSHA) == nil {
		t.Fatal("0039 substrate accepted a foreign path")
	}
}

func TestAcornFoxRecent0039HostEvidenceBindsBothReleases(t *testing.T) {
	prepared := newAcornFoxProductionPreparedFixture(t)
	old := strings.Repeat("1", 64)
	next := strings.Repeat("2", 64)
	first, err := acornFoxRecent0039HostEvidenceSHA(old, next, prepared.layout)
	again, againErr := acornFoxRecent0039HostEvidenceSHA(old, next, prepared.layout)
	drift, driftErr := acornFoxRecent0039HostEvidenceSHA(old, strings.Repeat("3", 64), prepared.layout)
	if err != nil || againErr != nil || driftErr != nil || !validSHA(first) || first != again || first == drift {
		t.Fatalf("first=%q again=%q drift=%q errors=%v/%v/%v", first, again, drift, err, againErr, driftErr)
	}
	if _, err := acornFoxRecent0039HostEvidenceSHA(old, old, prepared.layout); err == nil {
		t.Fatal("same-release host evidence accepted")
	}
}
