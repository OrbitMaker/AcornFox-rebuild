package install

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func substrateDigest(value string) string { return strings.Repeat(value, 64) }

func substrateEntry(path string, kind SubstrateEntryKind, mode uint32, role OwnerRole) SubstrateEntry {
	return SubstrateEntry{Path: path, Kind: kind, Mode: mode, Role: role, Group: GroupRole(role), Size: 1, SHA256: substrateDigest("a")}
}

func substrateReceiptFixture() InactiveSubstrateReceiptV1 {
	manifestDigest := sha256Hex([]byte("manifest"))
	candidate := AcornFoxStageReceiptV1{SchemaVersion: 1, Product: AcornFoxV1Product, Version: "1.2.3-test.1", ReleaseID: "release-1.2.3-test.1", ManifestSHA256: manifestDigest, ArchiveSHA256: substrateDigest("c"), BindingSHA256: substrateDigest("d"), BundleManifestSHA256: substrateDigest("e"), SourceCommit: strings.Repeat("a", 40), Architecture: AcornFoxV1Architecture, MigrationVersion: AcornFoxV1MigrationVersion, TreeSHA256: substrateDigest("f")}
	releasePrefix := "opt/acornfox/releases/" + candidate.ReleaseID + "/"
	entries := []SubstrateEntry{}
	addRelease := func(path string, mode uint32, digest string, size int64) {
		entries = append(entries, SubstrateEntry{Path: releasePrefix + path, Kind: SubstrateEntryFile, Mode: mode, Role: OwnerRoleRoot, Group: GroupRoleRoot, Size: size, SHA256: digest})
	}
	addRelease("manifest.json", 0o644, manifestDigest, int64(len("manifest")))
	for _, required := range AcornFoxV1RequiredFiles() {
		digest := sha256Hex([]byte(required.Path))
		addRelease(required.Path, required.Mode, digest, int64(len(required.Path)))
	}
	addRelease("web/dist/assets/app-12345678.js", 0o644, sha256Hex([]byte("asset")), int64(len("asset")))
	candidate.FileCount = len(AcornFoxV1RequiredFiles()) + 1
	releaseDirs := map[string]struct{}{}
	for _, file := range append([]SubstrateEntry(nil), entries...) {
		for parent := parentDirectory(file.Path); strings.HasPrefix(parent, "opt/acornfox/releases/"+candidate.ReleaseID); parent = parentDirectory(parent) {
			releaseDirs[parent] = struct{}{}
			if parent == "opt/acornfox/releases/"+candidate.ReleaseID {
				break
			}
		}
	}
	for path := range releaseDirs {
		if path == "opt/acornfox/releases/"+candidate.ReleaseID {
			continue // fixed table contributes the release root exactly once.
		}
		entries = append(entries, SubstrateEntry{Path: path, Kind: SubstrateEntryDirectory, Mode: 0o755, Role: OwnerRoleRoot, Group: GroupRoleRoot})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	candidate.TreeSHA256, _ = ComputeAcornFoxReleaseTreeSHA256(candidate, entries)
	for path, fixed := range acornFoxFixedSubstrateEntries(candidate) {
		if fixed.Kind == SubstrateEntryDirectory {
			entries = append(entries, fixed)
			continue
		}
		source := acornFoxInstalledSource(candidate, path)
		for _, release := range entries {
			if release.Path == releasePrefix+source {
				fixed.Size, fixed.SHA256 = release.Size, release.SHA256
				entries = append(entries, fixed)
				break
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	upgrade := substrateEntryAt(entries, AcornFoxUpgradeHelperPath)
	health := substrateEntryAt(entries, AcornFoxHealthcheckHelperPath(candidate))
	receipt := InactiveSubstrateReceiptV1{
		SchemaVersion: InactiveSubstrateReceiptV1Schema, State: "inactive_complete", LayoutVersion: AcornFoxSubstrateLayoutV1,
		CandidateReceipt: candidate, ReleaseTreeSHA256: candidate.TreeSHA256, UpgradeHelperSHA256: upgrade.SHA256, HealthHelperSHA256: health.SHA256, Entries: entries,
	}
	receipt.InstalledTreeSHA256, _ = ComputeAcornFoxSubstrateTreeSHA256(receipt.Entries)
	return receipt
}

func TestInactiveSubstrateReceiptV1CanonicalAndSecretFree(t *testing.T) {
	receipt := substrateReceiptFixture()
	raw, err := MarshalInactiveSubstrateReceiptV1(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseInactiveSubstrateReceiptV1(raw); err != nil || !reflect.DeepEqual(parsed, receipt) {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
	for _, forbidden := range []string{"/opt/", "postgresql://", "uid", "gid", "password"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("receipt leaked %q: %s", forbidden, raw)
		}
	}
	for _, mutate := range [][]byte{
		append(append([]byte(nil), raw...), '\n'),
		append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":true}`)...),
		bytes.Replace(raw, []byte(`"schema_version":1,`), []byte(`"schema_version":1,"schema_version":1,`), 1),
	} {
		if _, err := ParseInactiveSubstrateReceiptV1(mutate); err == nil {
			t.Fatalf("noncanonical receipt accepted: %s", mutate)
		}
	}
}

func TestAcornFoxSubstrateTreeEnvelopeRejectsOrderPathModeAndDigest(t *testing.T) {
	good := acornFoxSubstrateTreeEnvelopeV1{SchemaVersion: AcornFoxSubstrateTreeV1Schema, Entries: []SubstrateEntry{substrateEntry("a", SubstrateEntryFile, 0o700, OwnerRoleRoot), substrateEntry("b", SubstrateEntryFile, 0o700, OwnerRoleServer)}}
	raw, err := marshalAcornFoxSubstrateTreeEnvelopeV1(good)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := parseAcornFoxSubstrateTreeEnvelopeV1(raw); err != nil || !reflect.DeepEqual(parsed, good) {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
	for _, mutate := range []func(*acornFoxSubstrateTreeEnvelopeV1){
		func(v *acornFoxSubstrateTreeEnvelopeV1) { v.Entries[1].Path = "a" },
		func(v *acornFoxSubstrateTreeEnvelopeV1) { v.Entries[0].Path = "../escape" },
		func(v *acornFoxSubstrateTreeEnvelopeV1) { v.Entries[0].Mode = 0o722 },
		func(v *acornFoxSubstrateTreeEnvelopeV1) { v.Entries[0].SHA256 = "bad" },
	} {
		changed := good
		changed.Entries = append([]SubstrateEntry(nil), good.Entries...)
		mutate(&changed)
		if _, err := marshalAcornFoxSubstrateTreeEnvelopeV1(changed); err == nil {
			t.Fatalf("invalid tree accepted: %#v", changed)
		}
	}
	var reordered map[string]any
	if err := json.Unmarshal(raw, &reordered); err != nil {
		t.Fatal(err)
	}
	alias, err := json.Marshal(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(alias, raw) {
		t.Fatal("fixture did not produce a field-order alias")
	}
	if _, err := parseAcornFoxSubstrateTreeEnvelopeV1(alias); err == nil {
		t.Fatal("field-order alias accepted")
	}
}

func TestInactiveSubstrateIntentAndReconciliationOutcomesAreFixed(t *testing.T) {
	receipt := substrateReceiptFixture()
	intent := AcornFoxInactiveSubstrateIntentV1{SchemaVersion: InactiveSubstrateReceiptV1Schema, LayoutVersion: AcornFoxSubstrateLayoutV1, CandidateReceipt: receipt.CandidateReceipt, ExpectedEntryEnvelopeSHA256: receipt.InstalledTreeSHA256}
	raw, err := MarshalAcornFoxInactiveSubstrateIntentV1(intent)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseAcornFoxInactiveSubstrateIntentV1(raw); err != nil || !reflect.DeepEqual(parsed, intent) {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
}

func TestInactiveSubstrateReceiptRejectsUnrelatedTreeAndHelperHashes(t *testing.T) {
	for _, mutate := range []func(*InactiveSubstrateReceiptV1){
		func(receipt *InactiveSubstrateReceiptV1) { receipt.InstalledTreeSHA256 = substrateDigest("9") },
		func(receipt *InactiveSubstrateReceiptV1) { receipt.ReleaseTreeSHA256 = substrateDigest("8") },
		func(receipt *InactiveSubstrateReceiptV1) { receipt.UpgradeHelperSHA256 = substrateDigest("7") },
		func(receipt *InactiveSubstrateReceiptV1) { receipt.HealthHelperSHA256 = substrateDigest("6") },
	} {
		receipt := substrateReceiptFixture()
		mutate(&receipt)
		if err := receipt.Validate(); err == nil {
			t.Fatalf("unrelated placeholder digest accepted: %#v", receipt)
		}
	}
}

func TestAcornFoxV1SubstrateInventoryRejectsMissingExtraAndBadMappings(t *testing.T) {
	for _, mutate := range []func(*InactiveSubstrateReceiptV1){
		func(receipt *InactiveSubstrateReceiptV1) {
			receipt.Entries = append([]SubstrateEntry(nil), receipt.Entries[1:]...)
		},
		func(receipt *InactiveSubstrateReceiptV1) {
			receipt.Entries = append(receipt.Entries, SubstrateEntry{Path: "var/lib/acornfox/extra", Kind: SubstrateEntryDirectory, Mode: 0o750, Role: OwnerRoleServer, Group: GroupRoleServer})
			sort.Slice(receipt.Entries, func(i, j int) bool { return receipt.Entries[i].Path < receipt.Entries[j].Path })
		},
		func(receipt *InactiveSubstrateReceiptV1) {
			entry := substrateEntryAt(receipt.Entries, AcornFoxUpgradeHelperPath)
			entry.Role = OwnerRoleServer
		},
		func(receipt *InactiveSubstrateReceiptV1) {
			entry := substrateEntryAt(receipt.Entries, AcornFoxUpgradeHelperPath)
			entry.Group = GroupRoleServer
		},
		func(receipt *InactiveSubstrateReceiptV1) {
			entry := substrateEntryAt(receipt.Entries, AcornFoxUpgradeHelperPath)
			entry.Group = ""
		},
		func(receipt *InactiveSubstrateReceiptV1) {
			entry := substrateEntryAt(receipt.Entries, AcornFoxUpgradeHelperPath)
			entry.Mode = 0o700
		},
		func(receipt *InactiveSubstrateReceiptV1) {
			entry := substrateEntryAt(receipt.Entries, AcornFoxUpgradeHelperPath)
			entry.SHA256 = substrateDigest("9")
		},
	} {
		receipt := substrateReceiptFixture()
		mutate(&receipt)
		receipt.InstalledTreeSHA256, _ = ComputeAcornFoxSubstrateTreeSHA256(receipt.Entries)
		if err := receipt.Validate(); err == nil {
			t.Fatalf("invalid closed inventory accepted: %#v", receipt)
		}
	}
}

func TestAcornFoxV1SubstrateInventoryRequiresExactReleaseDirectories(t *testing.T) {
	for _, mutate := range []func(*InactiveSubstrateReceiptV1){
		func(receipt *InactiveSubstrateReceiptV1) {
			path := "opt/acornfox/releases/" + receipt.CandidateReceipt.ReleaseID + "/bin"
			entries := receipt.Entries[:0]
			for _, entry := range receipt.Entries {
				if entry.Path != path {
					entries = append(entries, entry)
				}
			}
			receipt.Entries = entries
		},
		func(receipt *InactiveSubstrateReceiptV1) {
			path := "opt/acornfox/releases/" + receipt.CandidateReceipt.ReleaseID + "/unused"
			receipt.Entries = append(receipt.Entries, SubstrateEntry{Path: path, Kind: SubstrateEntryDirectory, Mode: 0o755, Role: OwnerRoleRoot, Group: GroupRoleRoot})
			sort.Slice(receipt.Entries, func(i, j int) bool { return receipt.Entries[i].Path < receipt.Entries[j].Path })
		},
		func(receipt *InactiveSubstrateReceiptV1) {
			entry := substrateEntryAt(receipt.Entries, "opt/acornfox/releases/"+receipt.CandidateReceipt.ReleaseID+"/bin")
			entry.Mode = 0o750
		},
	} {
		receipt := substrateReceiptFixture()
		mutate(&receipt)
		receipt.InstalledTreeSHA256, _ = ComputeAcornFoxSubstrateTreeSHA256(receipt.Entries)
		if err := receipt.Validate(); err == nil {
			t.Fatal("invalid release directory set accepted")
		}
	}
}

func TestAcornFoxSubstrateEntryBoundIsDerivedAndFinite(t *testing.T) {
	entries := make([]SubstrateEntry, 0, acornFoxSubstrateMaxEntries)
	for index := 0; index < acornFoxSubstrateMaxEntries; index++ {
		entries = append(entries, SubstrateEntry{Path: fmt.Sprintf("bounded/%05d", index), Kind: SubstrateEntryDirectory, Mode: 0o755, Role: OwnerRoleRoot, Group: GroupRoleRoot})
	}
	if err := validateAcornFoxSubstrateEntries(entries); err != nil {
		t.Fatalf("derived maximum rejected: %v", err)
	}
	entries = append(entries, SubstrateEntry{Path: "bounded/overflow", Kind: SubstrateEntryDirectory, Mode: 0o755, Role: OwnerRoleRoot, Group: GroupRoleRoot})
	if err := validateAcornFoxSubstrateEntries(entries); err == nil {
		t.Fatal("derived maximum plus one accepted")
	}
}

func TestAcornFoxV1SubstrateInventoryAcceptsArchiveBoundDynamicAssets(t *testing.T) {
	receipt := substrateReceiptFixture()
	prefix := "opt/acornfox/releases/" + receipt.CandidateReceipt.ReleaseID + "/web/dist/assets/"
	for index := receipt.CandidateReceipt.FileCount; index < acornFoxArchiveMaxMembers-1; index++ {
		entries := append(receipt.Entries, SubstrateEntry{Path: fmt.Sprintf("%sextra-%08d.js", prefix, index), Kind: SubstrateEntryFile, Mode: 0o644, Role: OwnerRoleRoot, Group: GroupRoleRoot, Size: 1, SHA256: sha256Hex([]byte(fmt.Sprintf("asset-%d", index)))})
		receipt.Entries = entries
		receipt.CandidateReceipt.FileCount++
	}
	sort.Slice(receipt.Entries, func(i, j int) bool { return receipt.Entries[i].Path < receipt.Entries[j].Path })
	receipt.CandidateReceipt.TreeSHA256, _ = ComputeAcornFoxReleaseTreeSHA256(receipt.CandidateReceipt, receipt.Entries)
	receipt.ReleaseTreeSHA256 = receipt.CandidateReceipt.TreeSHA256
	receipt.InstalledTreeSHA256, _ = ComputeAcornFoxSubstrateTreeSHA256(receipt.Entries)
	if err := receipt.Validate(); err != nil {
		t.Fatalf("archive-bound dynamic assets rejected: %v", err)
	}
	receipt.CandidateReceipt.FileCount++
	if err := receipt.Validate(); err == nil {
		t.Fatal("archive-bound dynamic assets plus one accepted")
	}
}

func TestAcornFoxV1SubstrateInventoryUsesActualStageReceiptFileCount(t *testing.T) {
	taskRoot := t.TempDir()
	if err := os.Chmod(taskRoot, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	stager, err := NewTaskAcornFoxStager(taskRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	fixture := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	handle, staged, err := stager.Stage(fixture.input(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	if staged.FileCount != len(AcornFoxV1RequiredFiles())+1 {
		t.Fatalf("stage receipt FileCount=%d want manifest.Files=%d", staged.FileCount, len(AcornFoxV1RequiredFiles())+1)
	}
	receipt := substrateReceiptFixture()
	receipt.CandidateReceipt = staged
	receipt.ReleaseTreeSHA256 = staged.TreeSHA256
	var manifestData Manifest
	if err := json.Unmarshal(fixture.manifestRaw, &manifestData); err != nil {
		t.Fatal(err)
	}
	for _, member := range manifestData.Files {
		entry := substrateEntryAt(receipt.Entries, "opt/acornfox/releases/"+staged.ReleaseID+"/"+member.Path)
		if entry == nil {
			t.Fatalf("fixture lacks actual release member %s", member.Path)
		}
		entry.Mode, entry.SHA256 = member.Mode, member.SHA256
	}
	for path, fixed := range acornFoxFixedSubstrateEntries(staged) {
		if fixed.Kind != SubstrateEntryFile {
			continue
		}
		source := acornFoxInstalledSource(staged, path)
		installed, release := substrateEntryAt(receipt.Entries, path), substrateEntryAt(receipt.Entries, "opt/acornfox/releases/"+staged.ReleaseID+"/"+source)
		if installed == nil || release == nil {
			t.Fatalf("fixture lacks installed mapping %s", path)
		}
		installed.SHA256, installed.Size = release.SHA256, release.Size
	}
	receipt.UpgradeHelperSHA256 = substrateEntryAt(receipt.Entries, AcornFoxUpgradeHelperPath).SHA256
	receipt.HealthHelperSHA256 = substrateEntryAt(receipt.Entries, AcornFoxHealthcheckHelperPath(staged)).SHA256
	manifest := substrateEntryAt(receipt.Entries, "opt/acornfox/releases/"+staged.ReleaseID+"/manifest.json")
	if manifest == nil {
		t.Fatal("fixture lacks release manifest")
	}
	manifest.SHA256 = staged.ManifestSHA256
	receipt.InstalledTreeSHA256, err = ComputeAcornFoxSubstrateTreeSHA256(receipt.Entries)
	if err != nil || receipt.Validate() != nil {
		t.Fatalf("actual stage derived inventory err=%v validate=%v", err, receipt.Validate())
	}
	missing := receipt
	missing.Entries = append([]SubstrateEntry(nil), receipt.Entries[1:]...)
	missing.InstalledTreeSHA256, _ = ComputeAcornFoxSubstrateTreeSHA256(missing.Entries)
	if err := missing.Validate(); err == nil {
		t.Fatal("actual receipt accepted missing entry")
	}
	extra := receipt
	extra.Entries = append(extra.Entries, SubstrateEntry{Path: "var/log/acornfox/extra", Kind: SubstrateEntryDirectory, Mode: 0o750, Role: OwnerRoleServer, Group: GroupRoleServer})
	sort.Slice(extra.Entries, func(i, j int) bool { return extra.Entries[i].Path < extra.Entries[j].Path })
	extra.InstalledTreeSHA256, _ = ComputeAcornFoxSubstrateTreeSHA256(extra.Entries)
	if err := extra.Validate(); err == nil {
		t.Fatal("actual receipt accepted extra entry")
	}
	drift := receipt
	drift.Entries = append([]SubstrateEntry(nil), receipt.Entries...)
	entry := substrateEntryAt(drift.Entries, "opt/acornfox/releases/"+staged.ReleaseID+"/bin/acornfox-server")
	entry.SHA256 = substrateDigest("9")
	drift.InstalledTreeSHA256, _ = ComputeAcornFoxSubstrateTreeSHA256(drift.Entries)
	if err := drift.Validate(); err == nil {
		t.Fatal("actual receipt accepted a single release digest drift")
	}
}

func TestAcornFoxV1SubstrateDirectoriesCoverSystemdWritablePathsWithoutRun(t *testing.T) {
	fixed := acornFoxFixedSubstrateEntries(substrateReceiptFixture().CandidateReceipt)
	for _, unit := range acornFoxSystemdFiles {
		_, sections := readAcornFoxUnit(t, unit)
		for _, value := range sections["Service"]["ReadWritePaths"] {
			for _, absolute := range strings.Fields(value) {
				if strings.HasPrefix(absolute, "/run/") {
					continue // RuntimeDirectory creates volatile runtime state.
				}
				path := strings.TrimPrefix(absolute, "/")
				entry, ok := fixed[path]
				if !ok || entry.Kind != SubstrateEntryDirectory {
					t.Fatalf("%s writable path %q is absent from closed directory table", unit, absolute)
				}
			}
		}
	}
	if _, exists := fixed["run/acornfox-buildkit"]; exists {
		t.Fatal("closed substrate incorrectly persists RuntimeDirectory")
	}
}
