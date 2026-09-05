package acornfoxrelease

import (
	"os"
	"path/filepath"
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

func TestRuntimeLimitExceedsSourceLimit(t *testing.T) {
	root := t.TempDir()
	body := make([]byte, sourceFileBytes+1)
	for i := range body {
		body[i] = 'x'
	}
	path := filepath.Join(root, "payload")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	entry := FileEntryV1{Path: "payload", SHA256: sha256Text(body), Mode: 0o644}
	source := SourcePolicyV1{SchemaVersion: 1, Product: Product, ModulePath: "github.com/acme/acornfox-fixture", Files: []FileEntryV1{entry}}
	runtime := RuntimeInputsV1{SchemaVersion: 1, Product: Product, Architecture: Architecture, Files: []FileEntryV1{entry}}
	if err := VerifySourceTree(root, source); err == nil {
		t.Fatal("source accepted oversized member")
	}
	if err := VerifyRuntimeTree(root, runtime); err != nil {
		t.Fatal(err)
	}
}
func TestInputManifestsBindOnlyTheirWitnessDigest(t *testing.T) {
	source := sourcePolicyFixture()
	tool := ToolchainInputsV1{SchemaVersion: 1, Product: Product, Architecture: Architecture, GoVersion: "go1.25.0", GoBinarySHA256: strings.Repeat("c", 64), GitVersion: "2.40.0", GitBinarySHA256: strings.Repeat("d", 64), NodeVersion: "v22.0.0", NodeBinarySHA256: strings.Repeat("e", 64), NPMVersion: "10.0.0", NPMCLISHA256: strings.Repeat("f", 64), BuildPolicy: []string{"build_id_empty", "build_vcs_disabled", "cgo_disabled", "trimpath"}}
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

func TestToolchainRejectsLooseVersionsAndPolicy(t *testing.T) {
	v := ToolchainInputsV1{SchemaVersion: 1, Product: Product, Architecture: Architecture, GoVersion: "go1.2.3", GoBinarySHA256: strings.Repeat("c", 64), GitVersion: "2.3.4", GitBinarySHA256: strings.Repeat("d", 64), NodeVersion: "v2.3.4", NodeBinarySHA256: strings.Repeat("e", 64), NPMVersion: "3.4.5", NPMCLISHA256: strings.Repeat("f", 64), BuildPolicy: []string{"build_id_empty", "build_vcs_disabled", "cgo_disabled", "trimpath"}}
	for _, mutate := range []func(*ToolchainInputsV1){func(v *ToolchainInputsV1) { v.GoVersion = "go1.2" }, func(v *ToolchainInputsV1) { v.GoBinarySHA256 = "missing" }, func(v *ToolchainInputsV1) { v.GitVersion = "2.3" }, func(v *ToolchainInputsV1) { v.GitBinarySHA256 = "missing" }, func(v *ToolchainInputsV1) { v.NodeVersion = "v2.3.4\n" }, func(v *ToolchainInputsV1) { v.BuildPolicy = []string{"network_enabled"} }} {
		copy := v
		mutate(&copy)
		if copy.Validate() == nil {
			t.Fatal("accepted")
		}
	}
}
