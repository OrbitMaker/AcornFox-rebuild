package install

import (
	"bytes"
	"strings"
	"testing"
)

func TestAcornFoxHelperContractsAreStrictAndExternalDigestBound(t *testing.T) {
	result := AcornFoxHelperContractResultV1{SchemaVersion: AcornFoxHelperContractV1Schema, OK: true, Code: "ok", Identity: AcornFoxBuildIdentityV1{SchemaVersion: AcornFoxHelperContractV1Schema, Product: AcornFoxV1Product, LayoutVersion: AcornFoxSubstrateLayoutV1, Role: "upgrade", Version: "1.2.3-test.1", ReleaseID: "release-1.2.3-test.1", SourceCommit: strings.Repeat("a", 40)}, BindingSHA256: substrateDigest("a"), ExecutableSHA256: substrateDigest("b"), SubstrateReceiptSHA256: substrateDigest("c")}
	raw, err := MarshalAcornFoxHelperContractResultV1(result)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseAcornFoxHelperContractResultV1(raw); err != nil || parsed != result {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
	if bytes.Contains(raw, []byte("archive")) || bytes.Contains(raw, []byte("manifest")) || bytes.Contains(raw, []byte("receipt_content")) {
		t.Fatalf("result embeds circular binary topology: %s", raw)
	}
	for _, invalid := range [][]byte{append(raw, '\n'), append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":true}`)...)} {
		if _, err := ParseAcornFoxHelperContractResultV1(invalid); err == nil {
			t.Fatalf("noncanonical result accepted: %s", invalid)
		}
	}
}
