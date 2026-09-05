package acornfoxrelease

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func uncheckedCanonicalLine(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func readProductBuildLockFiles(t *testing.T) ([]byte, []byte) {
	t.Helper()
	releaseRoot := filepath.Join("..", "..", "release")
	inputs, err := os.ReadFile(filepath.Join(releaseRoot, "acornfox-product-build-inputs-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := os.ReadFile(filepath.Join(releaseRoot, "acornfox-controlled-egress-policy-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	return inputs, policy
}

func TestProductBuildInputLockIsCanonicalAndPolicyBound(t *testing.T) {
	inputsRaw, policyRaw := readProductBuildLockFiles(t)
	inputs, policy, err := ParseProductBuildInputsV1(inputsRaw, policyRaw)
	if err != nil {
		t.Fatal(err)
	}
	canonicalInputs, err := CanonicalProductBuildInputsV1(inputs)
	if err != nil || !bytes.Equal(canonicalInputs, inputsRaw) {
		t.Fatal("input lock was not canonical")
	}
	canonicalPolicy, err := CanonicalControlledEgressPolicyV1(policy)
	if err != nil || !bytes.Equal(canonicalPolicy, policyRaw) {
		t.Fatal("egress policy was not canonical")
	}
	digest, err := ControlledEgressPolicyDigestV1(policy)
	if err != nil || digest != inputs.ControlledEgressPolicySHA || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("unexpected policy digest %q", digest)
	}
}

func TestProductBuildInputLockRejectsStructuralAndFactDrift(t *testing.T) {
	inputsRaw, policyRaw := readProductBuildLockFiles(t)
	inputs, policy, err := ParseProductBuildInputsV1(inputsRaw, policyRaw)
	if err != nil {
		t.Fatal(err)
	}
	inputsCases := []struct {
		name   string
		mutate func(*ProductBuildInputsV1)
	}{
		{"uppercase lock digest", func(v *ProductBuildInputsV1) { v.LockFiles[0].SHA256 = strings.ToUpper(v.LockFiles[0].SHA256) }},
		{"extra lock", func(v *ProductBuildInputsV1) {
			v.LockFiles = append(v.LockFiles, ProductBuildLockFileV1{Path: "z", SHA256: strings.Repeat("a", 64)})
		}},
		{"missing lock", func(v *ProductBuildInputsV1) { v.LockFiles = v.LockFiles[:len(v.LockFiles)-1] }},
		{"unsafe url", func(v *ProductBuildInputsV1) { v.Toolchains[0].URL = "http://dl.google.com/go.tar.gz" }},
		{"toolchain version", func(v *ProductBuildInputsV1) { v.Toolchains[1].Version = "v22.22.1" }},
		{"source commit", func(v *ProductBuildInputsV1) { v.SourceCommit = strings.Repeat("a", 40) }},
	}
	for _, tc := range inputsCases {
		t.Run(tc.name, func(t *testing.T) {
			copy := inputs
			copy.LockFiles = append([]ProductBuildLockFileV1(nil), inputs.LockFiles...)
			copy.Toolchains = append([]ProductBuildToolchainV1(nil), inputs.Toolchains...)
			tc.mutate(&copy)
			raw := uncheckedCanonicalLine(t, copy)
			if _, _, err := ParseProductBuildInputsV1(raw, policyRaw); err == nil {
				t.Fatal("drift accepted")
			}
		})
	}

	policyCases := []struct {
		name   string
		mutate func(*ControlledEgressPolicyV1)
	}{
		{"extra domain", func(v *ControlledEgressPolicyV1) { v.DownloadDNSDomains = append(v.DownloadDNSDomains, "example.com") }},
		{"reordered resolver", func(v *ControlledEgressPolicyV1) {
			v.ResolverIPv4[0], v.ResolverIPv4[1] = v.ResolverIPv4[1], v.ResolverIPv4[0]
		}},
		{"ipv6 enabled", func(v *ControlledEgressPolicyV1) { v.DenyIPv6 = false }},
		{"offline build disabled", func(v *ControlledEgressPolicyV1) { v.OfflineBuildRequired = false }},
	}
	for _, tc := range policyCases {
		t.Run(tc.name, func(t *testing.T) {
			copy := policy
			copy.ResolverIPv4 = append([]string(nil), policy.ResolverIPv4...)
			copy.DownloadDNSDomains = append([]string(nil), policy.DownloadDNSDomains...)
			tc.mutate(&copy)
			raw := uncheckedCanonicalLine(t, copy)
			if _, _, err := ParseProductBuildInputsV1(inputsRaw, raw); err == nil {
				t.Fatal("policy drift accepted")
			}
		})
	}

	unknown := bytes.Replace(inputsRaw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"unknown":true`), 1)
	if _, _, err := ParseProductBuildInputsV1(unknown, policyRaw); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, _, err := ParseProductBuildInputsV1(bytes.TrimSuffix(inputsRaw, []byte{'\n'}), policyRaw); err == nil {
		t.Fatal("missing newline accepted")
	}
}
