package install

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func substrateDigest(value string) string { return strings.Repeat(value, 64) }

func substrateEntry(path string, kind SubstrateEntryKind, mode uint32, role OwnerRole) SubstrateEntry {
	return SubstrateEntry{Path: path, Kind: kind, Mode: mode, Role: role, Size: 1, SHA256: substrateDigest("a")}
}

func substrateReceiptFixture() InactiveSubstrateReceiptV1 {
	receipt := InactiveSubstrateReceiptV1{
		SchemaVersion: InactiveSubstrateReceiptV1Schema, State: "inactive_complete", LayoutVersion: AcornFoxSubstrateLayoutV1,
		CandidateReceipt:  AcornFoxStageReceiptV1{SchemaVersion: 1, Product: AcornFoxV1Product, Version: "1.2.3-test.1", ReleaseID: "release-1.2.3-test.1", ManifestSHA256: substrateDigest("b"), ArchiveSHA256: substrateDigest("c"), BindingSHA256: substrateDigest("d"), BundleManifestSHA256: substrateDigest("e"), SourceCommit: strings.Repeat("a", 40), Architecture: AcornFoxV1Architecture, MigrationVersion: AcornFoxV1MigrationVersion, FileCount: 1, TreeSHA256: substrateDigest("f")},
		ReleaseTreeSHA256: substrateDigest("f"), UpgradeHelperSHA256: substrateDigest("1"), HealthHelperSHA256: substrateDigest("2"),
		Entries: []SubstrateEntry{{Path: AcornFoxHealthcheckHelperPath, Kind: SubstrateEntryFile, Mode: 0o700, Role: OwnerRoleHealthcheck, Size: 1, SHA256: substrateDigest("2")}, {Path: AcornFoxUpgradeHelperPath, Kind: SubstrateEntryFile, Mode: 0o700, Role: OwnerRoleRoot, Size: 1, SHA256: substrateDigest("1")}},
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
	good := AcornFoxSubstrateTreeEnvelopeV1{SchemaVersion: AcornFoxSubstrateTreeV1Schema, Entries: []SubstrateEntry{substrateEntry("a", SubstrateEntryFile, 0o700, OwnerRoleRoot), substrateEntry("b", SubstrateEntryFile, 0o700, OwnerRoleServer)}}
	raw, err := MarshalAcornFoxSubstrateTreeEnvelopeV1(good)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseAcornFoxSubstrateTreeEnvelopeV1(raw); err != nil || !reflect.DeepEqual(parsed, good) {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
	for _, mutate := range []func(*AcornFoxSubstrateTreeEnvelopeV1){
		func(v *AcornFoxSubstrateTreeEnvelopeV1) { v.Entries[1].Path = "a" },
		func(v *AcornFoxSubstrateTreeEnvelopeV1) { v.Entries[0].Path = "../escape" },
		func(v *AcornFoxSubstrateTreeEnvelopeV1) { v.Entries[0].Mode = 0o722 },
		func(v *AcornFoxSubstrateTreeEnvelopeV1) { v.Entries[0].SHA256 = "bad" },
	} {
		changed := good
		changed.Entries = append([]SubstrateEntry(nil), good.Entries...)
		mutate(&changed)
		if _, err := MarshalAcornFoxSubstrateTreeEnvelopeV1(changed); err == nil {
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
	if _, err := ParseAcornFoxSubstrateTreeEnvelopeV1(alias); err == nil {
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
	for _, outcome := range []AcornFoxReconciliationOutcome{AcornFoxReconcileAbsent, AcornFoxReconcileResume, AcornFoxReconcileCompleted, AcornFoxReconcileRecoveryRequired, AcornFoxReconcileConflict, AcornFoxReconcileCommitUnknown, AcornFoxReconcileCleanupUnknown} {
		if err := outcome.Validate(); err != nil {
			t.Fatalf("outcome %q: %v", outcome, err)
		}
	}
	if err := AcornFoxReconciliationOutcome("mutable_journal").Validate(); err == nil {
		t.Fatal("unknown reconciliation outcome accepted")
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
