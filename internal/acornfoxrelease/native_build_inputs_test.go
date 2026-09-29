package acornfoxrelease

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestNativePartialPinsTargetsAndCoreMetadata(t *testing.T) {
	policy := sourcePolicyFixture()
	policyRaw, err := CanonicalSourcePolicyV1(policy)
	if err != nil {
		t.Fatal(err)
	}
	inputs := NativeBuildInputsV1{1, "native_partial", "1.2.3", "https://github.com/acme/acornfox-fixture", strings.Repeat("a", 40), sha256Text(policyRaw), strings.Repeat("b", 64)}
	raw, err := CanonicalNativeBuildInputsV1(inputs)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := ParseNativeBuildInputsV1(raw, sha256Text(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNativeBuildInputsV1(raw, strings.Repeat("c", 64)); err == nil {
		t.Fatal("untrusted native input pin accepted")
	}
	if _, err := ParseNativeSourcePolicyV1(witness, policyRaw); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNativeSourcePolicyV1(witness, append(policyRaw, '\n')); err == nil {
		t.Fatal("source policy drift accepted")
	}
	inputs.SourceCommit = "dirty"
	if inputs.Validate() == nil {
		t.Fatal("non-commit native source accepted")
	}
	module := policy.ModulePath
	targets := nativeTargets()
	packages := nativePackagePaths(module)
	if !nativeTargetsMatch(targets, packages, module) {
		t.Fatal("fixed targets rejected")
	}
	if targets[3].Package != "./cmd/acornfox-container" || targets[3].Output != "bin/acornfox-container" {
		t.Fatal("container entry drift")
	}
	if nativeTargetsMatch(append(targets, targets[0]), packages, module) {
		t.Fatal("extra target accepted")
	}
	targets[0].Ldflags = append(targets[0].Ldflags, "-X=main.processIdentity=acornfox")
	if nativeTargetsMatch(targets, packages, module) {
		t.Fatal("caller ldflags accepted")
	}
	var binaries []FileEntryV1
	for _, v := range nativeFixedTargets {
		binaries = append(binaries, FileEntryV1{"bin/" + v.name, strings.Repeat("d", 64), 0o755})
	}
	sort.Slice(binaries, func(i, j int) bool { return binaries[i].Path < binaries[j].Path })
	tree, _ := canonicalBinaryTree(binaries)
	receipt := GoBinaryReceiptV1{1, Product, Architecture, strings.Repeat("a", 40), witness.sha, witness.inputs.SourcePolicySHA256, witness.inputs.ToolchainSHA256, sha256Text(tree), binaries}
	if receipt.validate(true) != nil || receipt.Validate() == nil {
		t.Fatal("native binaries confused with legacy receipt")
	}
	plan := testWebPlan()
	plan.nativePartial = true
	root := t.TempDir()
	writeValidWebDist(t, root, plan)
	if _, err := inspectWebDist(root, plan); err == nil {
		t.Fatal("legacy metadata accepted for Core")
	}
	metadata := map[string]string{"apiBaseUrl": "/api/v1", "mode": "live", "product": "acornfox-core", "releaseId": "release-" + plan.releaseVersion, "schemaVersion": "acornfox-core-release-build-attestation.v1", "sourceCommit": plan.sourceCommit, "sourceRepository": plan.sourceRepositoryURL, "version": plan.releaseVersion}
	coreRaw, _ := json.Marshal(metadata)
	if err := os.WriteFile(filepath.Join(root, "build-metadata.json"), coreRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectWebDist(root, plan); err == nil {
		t.Fatal("missing Core entry accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "core.html"), []byte("core"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectWebDist(root, plan); err != nil {
		t.Fatal(err)
	}
	metadata["sourceCommit"] = strings.Repeat("f", 40)
	coreRaw, _ = json.Marshal(metadata)
	if parseWebMetadata(coreRaw, plan) == nil {
		t.Fatal("Core source attestation drift accepted")
	}
}

func TestNativeProductPinsEightTargetsWithoutClaimingFullRelease(t *testing.T) {
	module := "github.com/open-card/open-card"
	targets := nativeProductTargets()
	packages := nativeProductPackagePaths(module)
	if !nativeProductTargetsMatch(targets, packages, module) || nativeTargetsMatch(targets, packages, module) || len(targets) != 8 {
		t.Fatal("eight-target product profile identity changed")
	}
	if targets[4].Output != "bin/acornfox-source-build" || targets[5].Output != "bin/acornfox-gateway" || targets[6].Output != "bin/acornfox-host-update" || targets[7].Output != "bin/acornfox-build-network" {
		t.Fatal("new product runner paths drifted")
	}
	if nativeProductTargetsMatch(append(append([]GoBuildTargetV1(nil), targets...), targets[0]), packages, module) || nativeProductTargetsMatch(targets[:7], packages, module) {
		t.Fatal("extra or omitted product target accepted")
	}
	var files []FileEntryV1
	for _, target := range nativeProductFixedTargets {
		files = append(files, FileEntryV1{Path: "bin/" + target.name, SHA256: strings.Repeat("a", 64), Mode: 0755})
	}
	files = append(files, FileEntryV1{Path: "web/core.html", SHA256: strings.Repeat("b", 64), Mode: 0644}, FileEntryV1{Path: "web/build-metadata.json", SHA256: strings.Repeat("c", 64), Mode: 0644})
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	raw, _ := json.Marshal(files)
	product := NativeProductReceiptV1{SchemaVersion: 1, Profile: "native_product", Architecture: Architecture, Version: "1.2.3", SourceRepository: "https://github.com/acme/acornfox-fixture", SourceCommit: strings.Repeat("d", 40), InputsSHA256: strings.Repeat("e", 64), SourcePolicySHA256: strings.Repeat("f", 64), ToolchainSHA256: strings.Repeat("1", 64), TreeSHA256: sha256Text(raw), Files: files}
	if product.Validate() != nil || NativePartialReceiptV1(product).Validate() == nil {
		t.Fatal("product inventory rejected or mistaken for native partial")
	}
	binaries := append([]FileEntryV1(nil), files[:8]...)
	binaryTree, _ := canonicalBinaryTree(binaries)
	goReceipt := GoBinaryReceiptV1{SchemaVersion: 1, Product: Product, Architecture: Architecture, SourceCommit: product.SourceCommit, DecisionSHA256: product.InputsSHA256, SourcePolicySHA256: product.SourcePolicySHA256, ToolchainSHA256: product.ToolchainSHA256, TreeSHA256: sha256Text(binaryTree), Files: binaries}
	if goReceipt.validateBuildProfile(true, true) != nil || goReceipt.validate(true) == nil {
		t.Fatal("eight binary stage confused with four-target Native stage")
	}
	missingPolicy := product
	missingPolicy.Files = nil
	for _, file := range product.Files {
		if file.Path != "bin/acornfox-build-network" {
			missingPolicy.Files = append(missingPolicy.Files, file)
		}
	}
	raw, _ = json.Marshal(missingPolicy.Files)
	missingPolicy.TreeSHA256 = sha256Text(raw)
	if missingPolicy.Validate() == nil {
		t.Fatal("policy executor omitted from product inventory")
	}
	product.Files = append(product.Files, FileEntryV1{Path: "bin/unapproved", SHA256: strings.Repeat("2", 64), Mode: 0755})
	sort.Slice(product.Files, func(i, j int) bool { return product.Files[i].Path < product.Files[j].Path })
	raw, _ = json.Marshal(product.Files)
	product.TreeSHA256 = sha256Text(raw)
	if product.Validate() == nil {
		t.Fatal("extra executable accepted into product inventory")
	}
}

func TestNativePartialRejectsOutputReplacementDuringFinalSourceObservation(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	parentPin, err := pinDirectory(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer parentPin.close()
	output := filepath.Join(parent, "output")
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	outputPin, err := pinDirectory(output)
	if err != nil {
		t.Fatal(err)
	}
	defer outputPin.close()
	body := []byte("native output fixture")
	files := []FileEntryV1{{"core.html", sha256Text(body), 0o644}}
	if err := os.WriteFile(filepath.Join(output, "core.html"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	err = finishNativePartialOutput(parent, parentPin, output, outputPin, files, func() error {
		if err := os.Rename(output, output+"-original"); err != nil {
			return err
		}
		if err := os.Mkdir(output, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(output, "core.html"), body, 0o644)
	})
	if err == nil {
		t.Fatal("replacement output accepted after final source observation")
	}
	original, err := os.Lstat(output + "-original")
	pinned, pinErr := outputPin.file.Stat()
	if err != nil || pinErr != nil || !os.SameFile(original, pinned) {
		t.Fatal("original pinned inventory was lost")
	}
	if raw, err := os.ReadFile(filepath.Join(output, "core.html")); err != nil || string(raw) != string(body) {
		t.Fatal("replacement tree was removed")
	}
}
