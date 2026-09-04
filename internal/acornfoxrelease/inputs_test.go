package acornfoxrelease

import (
	"strings"
	"testing"
)

func witnessForInputs(t *testing.T, source SourcePolicyV1, tool ToolchainInputsV1, runtime RuntimeInputsV1, license LicenseInputsV1) Witness {
	t.Helper()
	sr, _ := CanonicalSourcePolicyV1(source)
	tr, _ := CanonicalToolchainInputsV1(tool)
	rr, _ := CanonicalRuntimeInputsV1(runtime)
	lr, _ := CanonicalLicenseInputsV1(license)
	d := decisionFixture()
	d.SourcePolicySHA256 = sha256Text(sr)
	d.ToolchainSHA256 = sha256Text(tr)
	d.RuntimeInputSHA256 = sha256Text(rr)
	d.LicenseInputSHA256 = sha256Text(lr)
	raw, err := CanonicalDecisionV1(d)
	if err != nil {
		t.Fatal(err)
	}
	w, err := ParseDecisionV1(raw, sha256Text(raw))
	if err != nil {
		t.Fatal(err)
	}
	return w
}
func TestInputManifestsBindOnlyTheirWitnessDigest(t *testing.T) {
	source := sourcePolicyFixture()
	tool := ToolchainInputsV1{SchemaVersion: 1, Product: Product, Architecture: Architecture, GoVersion: "go1.25", NodeVersion: "v22", NPMVersion: "10", BuildPolicy: []string{"cgo_disabled", "trimpath"}}
	runtime := RuntimeInputsV1{SchemaVersion: 1, Product: Product, Architecture: Architecture, Files: []FileEntryV1{{Path: "etc/runtime.conf", SHA256: strings.Repeat("a", 64), Mode: 0o644}}}
	license := LicenseInputsV1{SchemaVersion: 1, Product: Product, Files: []FileEntryV1{{Path: "LICENSE", SHA256: strings.Repeat("b", 64), Mode: 0o644}}}
	w := witnessForInputs(t, source, tool, runtime, license)
	sr, _ := CanonicalSourcePolicyV1(source)
	tr, _ := CanonicalToolchainInputsV1(tool)
	rr, _ := CanonicalRuntimeInputsV1(runtime)
	lr, _ := CanonicalLicenseInputsV1(license)
	if _, e := ParseSourcePolicyV1(w, sr); e != nil {
		t.Fatal(e)
	}
	if _, e := ParseToolchainInputsV1(w, tr); e != nil {
		t.Fatal(e)
	}
	if _, e := ParseRuntimeInputsV1(w, rr); e != nil {
		t.Fatal(e)
	}
	if _, e := ParseLicenseInputsV1(w, lr); e != nil {
		t.Fatal(e)
	}
	if _, e := ParseRuntimeInputsV1(w, sr); e == nil {
		t.Fatal("source substituted for runtime")
	}
	var zero Witness
	if _, e := ParseLicenseInputsV1(zero, lr); e == nil {
		t.Fatal("zero witness accepted")
	}
}
