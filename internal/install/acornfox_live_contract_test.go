package install

import (
	"strings"
	"testing"
)

func TestAcornFoxLiveReceiptIsCanonicalAndSymbolic(t *testing.T) {
	_, _, published, substrate := newAcornFox03CPublished(t)
	entries, err := acornFoxLiveExpectedEntries(published)
	if err != nil {
		t.Fatal(err)
	}
	journal := newAcornFoxRepoJournal()
	raw, err := MarshalInactiveSubstrateReceiptV1(substrate)
	if err != nil {
		t.Fatal(err)
	}
	journal.BindingSHA256, journal.SubstrateReceiptSHA256 = substrate.CandidateReceipt.BindingSHA256, sha256Hex(raw)
	prepared, err := AcornFoxRepoPreparedEvidence(journal.BindingSHA256, journal.SubstrateReceiptSHA256)
	if err != nil {
		t.Fatal(err)
	}
	journal.History[0].EvidenceSHA256 = prepared
	receipt, err := acornFoxLiveMakeReceipt(journal, published, entries)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := MarshalAcornFoxLiveReceiptV1(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseAcornFoxLiveReceiptV1(append(encoded, ' ')); err == nil {
		t.Fatal("noncanonical live receipt accepted")
	}
	for _, entry := range receipt.Entries {
		if entry.PhysicalOwnerObservation != "task_root_owner" || entry.Role == "" || entry.Group == "" {
			t.Fatalf("ownership observation=%#v", entry)
		}
	}
	bad := receipt
	bad.Entries[0].Role = "not-an-acornfox-role"
	if bad.Validate() == nil {
		t.Fatal("symbolic ownership mutation was accepted")
	}
}

func TestAcornFoxLiveSymbolicOwnerAndGroupAreIndependent(t *testing.T) {
	for _, source := range []SubstrateEntry{{Path: "etc/acornfox/acornfox-edge.env", Kind: SubstrateEntryFile, Mode: 0o640, Role: OwnerRoleRoot, Group: GroupRoleEdge, Size: 1, SHA256: sha256Hex([]byte("x"))}, {Path: "var/lib/acornfox/uploads", Kind: SubstrateEntryDirectory, Mode: 0o750, Role: OwnerRoleServer, Group: GroupRoleServer}} {
		entry, err := acornFoxLiveEntryFor(source)
		if err != nil {
			t.Fatal(err)
		}
		if entry.Role == "" || entry.Group == "" {
			t.Fatalf("routing=%#v", entry)
		}
		if source.Group == GroupRoleEdge && (entry.Role != AcornFoxLiveRootRole || entry.Group != AcornFoxLiveEdgeRole) {
			t.Fatalf("mixed root:edge symbolic plan lost: %#v", entry)
		}
	}
}

func TestAcornFoxLiveReceiptBindsReleaseIDToEntries(t *testing.T) {
	_, _, published, substrate := newAcornFox03CPublished(t)
	entries, err := acornFoxLiveExpectedEntries(published)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalInactiveSubstrateReceiptV1(substrate)
	if err != nil {
		t.Fatal(err)
	}
	journal := newAcornFoxRepoJournal()
	journal.BindingSHA256, journal.SubstrateReceiptSHA256 = substrate.CandidateReceipt.BindingSHA256, sha256Hex(raw)
	prepared, _ := AcornFoxRepoPreparedEvidence(journal.BindingSHA256, journal.SubstrateReceiptSHA256)
	journal.History[0].EvidenceSHA256 = prepared
	receipt, err := acornFoxLiveMakeReceipt(journal, published, entries)
	if err != nil {
		t.Fatal(err)
	}
	wrong := receipt
	wrong.ReleaseID = "other-release"
	if wrong.Validate() == nil {
		t.Fatal("top-level release id detached from entries")
	}
	wrong = receipt
	for i := range wrong.Entries {
		wrong.Entries[i].Path = strings.Replace(wrong.Entries[i].Path, "opt/acornfox/releases/"+receipt.ReleaseID+"/", "opt/acornfox/releases/other-release/", 1)
	}
	if wrong.Validate() == nil {
		t.Fatal("second release tree accepted")
	}
}
