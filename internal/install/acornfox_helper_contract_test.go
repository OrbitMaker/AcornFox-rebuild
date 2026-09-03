package install

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestAcornFoxHelperContractsAreStrictAndExternalDigestBound(t *testing.T) {
	identity := &AcornFoxBuildIdentityV1{SchemaVersion: AcornFoxHelperContractV1Schema, Product: AcornFoxV1Product, LayoutVersion: AcornFoxSubstrateLayoutV1, Role: "upgrade", Version: "1.2.3-test.1", ReleaseID: "release-1.2.3-test.1", SourceCommit: strings.Repeat("a", 40)}
	result := AcornFoxHelperContractResultV1{SchemaVersion: AcornFoxHelperContractV1Schema, OK: true, Code: AcornFoxHelperCodeOK, Identity: identity, BindingSHA256: substrateDigest("a"), ExecutableSHA256: substrateDigest("b"), SubstrateReceiptSHA256: substrateDigest("c")}
	raw, err := MarshalAcornFoxHelperContractResultV1(result)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseAcornFoxHelperContractResultV1(raw); err != nil || !reflect.DeepEqual(parsed, result) {
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

func TestAcornFoxHelperFailureCodesRejectPartialEvidence(t *testing.T) {
	for _, code := range []string{AcornFoxHelperCodeInvalidArguments, AcornFoxHelperCodeIdentityMismatch, AcornFoxHelperCodeReceiptUnavailable, AcornFoxHelperCodeReceiptInvalid, AcornFoxHelperCodeBindingMismatch, AcornFoxHelperCodeExecutableUnavailable, AcornFoxHelperCodeExecutableMismatch, AcornFoxHelperCodeInternalError} {
		failure := AcornFoxHelperContractResultV1{SchemaVersion: AcornFoxHelperContractV1Schema, Code: code}
		if err := failure.Validate(); err != nil {
			t.Fatalf("failure code %s: %v", code, err)
		}
		raw, err := MarshalAcornFoxHelperContractResultV1(failure)
		if err != nil {
			t.Fatal(err)
		}
		if parsed, err := ParseAcornFoxHelperContractResultV1(raw); err != nil || !reflect.DeepEqual(parsed, failure) {
			t.Fatalf("failure %s parsed=%#v err=%v", code, parsed, err)
		}
	}
	partial := AcornFoxHelperContractResultV1{SchemaVersion: AcornFoxHelperContractV1Schema, Code: AcornFoxHelperCodeBindingMismatch, BindingSHA256: substrateDigest("a")}
	if err := partial.Validate(); err == nil {
		t.Fatal("partial failure evidence accepted")
	}
	if err := (AcornFoxHelperContractResultV1{SchemaVersion: AcornFoxHelperContractV1Schema, Code: "argv=/secret"}).Validate(); err == nil {
		t.Fatal("unbounded failure code accepted")
	}
}
