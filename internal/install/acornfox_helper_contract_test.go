package install

import (
	"bytes"
	"reflect"
	"testing"
)

func TestAcornFoxHelperContractsAreStrictAndExternalDigestBound(t *testing.T) {
	evidence := HelperContractEvidenceV1{SchemaVersion: AcornFoxHelperContractV1Schema, Helper: "upgrade", CandidateReceiptSHA256: substrateDigest("a"), InputTreeSHA256: substrateDigest("b"), OutputSHA256: substrateDigest("c")}
	raw, err := MarshalHelperContractEvidenceV1(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseHelperContractEvidenceV1(raw); err != nil || parsed != evidence {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
	if bytes.Contains(raw, []byte("archive")) || bytes.Contains(raw, []byte("manifest")) || bytes.Contains(raw, []byte("binding")) {
		t.Fatalf("evidence embeds circular binary topology: %s", raw)
	}
	output := HelperContractOutputV1{SchemaVersion: AcornFoxHelperContractV1Schema, Helper: "healthcheck", State: "inactive_complete", TreeSHA256: substrateDigest("d"), Entries: []SubstrateEntry{substrateEntry("helpers/healthcheck", SubstrateEntryFile, 0o700, OwnerRoleHealthcheck)}}
	outputRaw, err := MarshalHelperContractOutputV1(output)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseHelperContractOutputV1(outputRaw); err != nil || !reflect.DeepEqual(parsed, output) {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
	for _, invalid := range [][]byte{append(outputRaw, '\n'), append(append([]byte(nil), outputRaw[:len(outputRaw)-1]...), []byte(`,"unknown":true}`)...)} {
		if _, err := ParseHelperContractOutputV1(invalid); err == nil {
			t.Fatalf("noncanonical output accepted: %s", invalid)
		}
	}
}
