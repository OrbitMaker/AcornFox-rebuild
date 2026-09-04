package install

import "testing"

func TestAcornFoxLiveReceiptIsCanonicalAndModeled(t *testing.T) {
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
		if entry.PhysicalOwnerObservation != "task_root_owner" || entry.RequestedModeledUser.Role != entry.Role || entry.RequestedModeledGroup.Role != entry.Group {
			t.Fatalf("ownership observation=%#v", entry)
		}
	}
	bad := receipt
	bad.Entries[0].RequestedModeledUser.UID++
	if bad.Validate() == nil {
		t.Fatal("host-like modeled-id mutation was accepted")
	}
}

func TestAcornFoxLiveModeledOwnerAndGroupAreIndependent(t *testing.T) {
	for _, source := range []SubstrateEntry{{Path: "etc/acornfox/acornfox-edge.env", Kind: SubstrateEntryFile, Mode: 0o640, Role: OwnerRoleRoot, Group: GroupRoleEdge, Size: 1, SHA256: sha256Hex([]byte("x"))}, {Path: "var/lib/acornfox/uploads", Kind: SubstrateEntryDirectory, Mode: 0o750, Role: OwnerRoleServer, Group: GroupRoleServer}} {
		entry, err := acornFoxLiveEntryFor(source)
		if err != nil {
			t.Fatal(err)
		}
		if entry.RequestedModeledUser.Role != entry.Role || entry.RequestedModeledGroup.Role != entry.Group {
			t.Fatalf("routing=%#v", entry)
		}
		if source.Group == GroupRoleEdge && entry.RequestedModeledUser.UID == entry.RequestedModeledGroup.GID {
			t.Fatal("mixed root:edge reused modeled identity")
		}
	}
}
