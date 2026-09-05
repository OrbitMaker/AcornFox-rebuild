package acornfoxrelease

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/open-card/open-card/internal/install"
)

func TestBuildCandidateTreeV1MaterializesDeterministicSyntheticTree(t *testing.T) {
	plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license := candidateTreeFixture(t)
	defer goStage.Close()
	defer webStage.Close()
	if !plan.Valid() || VerifyRuntimeTree(runtimeRoot, runtime) != nil || VerifyLicenseTree(licenseRoot, license) != nil {
		t.Fatal("fixture inputs invalid")
	}
	first, err := BuildCandidateTreeV1(plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license, buildTaskRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := BuildCandidateTreeV1(plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license, buildTaskRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	left, err := first.Receipt()
	if err != nil || left.Validate() != nil {
		t.Fatalf("receipt=%#v err=%v", left, err)
	}
	right, err := second.Receipt()
	if err != nil || left.TreeSHA256 != right.TreeSHA256 || !sameCandidateFiles(left.Files, right.Files) {
		t.Fatalf("synthetic trees differ: %#v %#v %v", left, right, err)
	}
	if len(left.Files) != len(install.AcornFoxV1RequiredFiles())+1 { // one direct hashed web asset
		t.Fatalf("files=%d", len(left.Files))
	}
	for _, required := range install.AcornFoxV1RequiredFiles() {
		if !candidateFilePresent(left.Files, required.Path, required.Mode) {
			t.Fatalf("missing required file %s", required.Path)
		}
	}
	source, err := os.ReadFile(filepath.Join(first.root, "release", "source-manifest.sha256"))
	if err != nil || string(source) != string(sourceManifest(plan.sourcePolicy)) {
		t.Fatalf("source manifest mismatch: %q %v", source, err)
	}
	sbom, err := os.ReadFile(filepath.Join(first.root, "release", "sbom.spdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(sbom, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace", "comment", "creationInfo", "documentDescribes", "packages", "files", "relationships"} {
		if _, ok := parsed[key]; !ok {
			t.Fatalf("missing SPDX key %q", key)
		}
	}
	for _, legacy := range []string{"SPDXVersion", "DataLicense", "DocumentNamespace", "Packages", "Files", "Relationships"} {
		if _, ok := parsed[legacy]; ok {
			t.Fatalf("legacy uppercase SPDX key %q", legacy)
		}
	}
	packages := parsed["packages"].([]any)
	files := parsed["files"].([]any)
	relationships := parsed["relationships"].([]any)
	if len(packages) != 1 || len(files) != len(left.Files)-1 || !strings.Contains(parsed["comment"].(string), "RELEASE-12B") {
		t.Fatalf("invalid SPDX payload: %s", sbom)
	}
	rootPackage := packages[0].(map[string]any)
	for _, key := range []string{"SPDXID", "name", "downloadLocation", "filesAnalyzed", "licenseConcluded", "licenseDeclared", "copyrightText", "packageVerificationCode"} {
		if _, ok := rootPackage[key]; !ok {
			t.Fatalf("package missing %s", key)
		}
	}
	verification := rootPackage["packageVerificationCode"].(map[string]any)
	if verification["packageVerificationCodeExcludedFiles"].([]any)[0] != "./sbom.spdx.json" {
		t.Fatalf("missing self exclusion %#v", verification)
	}
	var sha1Values []string
	for _, rawFile := range files {
		file := rawFile.(map[string]any)
		for _, key := range []string{"SPDXID", "fileName", "checksums", "licenseConcluded", "copyrightText"} {
			if _, ok := file[key]; !ok {
				t.Fatalf("file missing %s", key)
			}
		}
		if file["fileName"] == "./sbom.spdx.json" {
			t.Fatal("SPDX self-reference")
		}
		path := strings.TrimPrefix(file["fileName"].(string), "./")
		body, err := os.ReadFile(filepath.Join(first.root, "release", filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		sha1Sum := sha1.Sum(body)
		expectedSHA1 := hex.EncodeToString(sha1Sum[:])
		expectedSHA256 := sha256Text(body)
		checksums := file["checksums"].([]any)
		if len(checksums) != 2 {
			t.Fatalf("unexpected checksums %#v", checksums)
		}
		firstChecksum, secondChecksum := checksums[0].(map[string]any), checksums[1].(map[string]any)
		if firstChecksum["algorithm"] != "SHA1" || firstChecksum["checksumValue"] != expectedSHA1 || secondChecksum["algorithm"] != "SHA256" || secondChecksum["checksumValue"] != expectedSHA256 {
			t.Fatalf("checksum mismatch for %s: %#v", path, checksums)
		}
		sha1Values = append(sha1Values, expectedSHA1)
	}
	sort.Strings(sha1Values)
	verificationSum := sha1.Sum([]byte(strings.Join(sha1Values, "")))
	if verification["packageVerificationCodeValue"] != hex.EncodeToString(verificationSum[:]) {
		t.Fatalf("package verification code mismatch %#v", verification)
	}
	for _, rawRelationship := range relationships {
		relationship := rawRelationship.(map[string]any)
		if relationship["relationshipType"] != "CONTAINS" || relationship["relationshipType"] == "DEPENDS_ON" {
			t.Fatalf("unexpected relationship %#v", relationship)
		}
	}
}

func TestBuildCandidateTreeV1FailsClosedOnMissingScriptAndStageTamper(t *testing.T) {
	plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license := candidateTreeFixture(t)
	defer goStage.Close()
	defer webStage.Close()
	script := filepath.Join(plan.sourceRoot, "scripts", "acornfox", "install.sh")
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	if stage, err := BuildCandidateTreeV1(plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license, buildTaskRoot(t)); err == nil || stage != nil {
		t.Fatal("missing script accepted")
	}

	plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license = candidateTreeFixture(t)
	defer goStage.Close()
	defer webStage.Close()
	if err := os.WriteFile(filepath.Join(goStage.root, "bin", "acornfox-server"), []byte("changed"), 0o755); err != nil {
		t.Fatal(err)
	}
	if stage, err := BuildCandidateTreeV1(plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license, buildTaskRoot(t)); err == nil || stage != nil {
		t.Fatal("tampered Go stage accepted")
	}
}

func TestCandidateTreeStageRejectsReplacementAndCloseIsSafe(t *testing.T) {
	plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license := candidateTreeFixture(t)
	defer goStage.Close()
	defer webStage.Close()
	stage, err := BuildCandidateTreeV1(plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license, buildTaskRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	moved := stage.root + "-moved"
	if err := os.Rename(stage.root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stage.root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage.root, "foreign"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stage.Receipt(); err == nil {
		t.Fatal("replacement accepted")
	}
	if err := stage.Close(); err == nil {
		t.Fatal("replacement close accepted")
	}
	if body, err := os.ReadFile(filepath.Join(stage.root, "foreign")); err != nil || string(body) != "keep" {
		t.Fatalf("foreign replacement removed: %q %v", body, err)
	}
}

func TestBuildCandidateTreeV1OverridesRestrictiveUmask(t *testing.T) {
	plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license := candidateTreeFixture(t)
	defer goStage.Close()
	defer webStage.Close()
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	stage, err := BuildCandidateTreeV1(plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license, buildTaskRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	second, err := BuildCandidateTreeV1(plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license, buildTaskRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if receipt, err := second.Receipt(); err != nil || receipt.TreeSHA256 != stage.receipt.TreeSHA256 || !sameCandidateFiles(receipt.Files, stage.receipt.Files) {
		t.Fatalf("umask changed synthetic tree: %#v %v", receipt, err)
	}
	for _, file := range stage.receipt.Files {
		info, err := os.Lstat(filepath.Join(stage.root, "release", filepath.FromSlash(file.Path)))
		if err != nil || info.Mode().Perm() != os.FileMode(file.Mode) {
			t.Fatalf("mode %s=%o want=%o err=%v", file.Path, info.Mode().Perm(), file.Mode, err)
		}
	}
}

func candidateTreeFixture(t *testing.T) (GoBuildPlanV1, *GoBinaryStageV1, *WebAssetStageV1, string, RuntimeInputsV1, string, LicenseInputsV1) {
	t.Helper()
	root, cache, _, _, toolchain := syntheticGoReleaseRepository(t)
	for _, required := range install.AcornFoxV1RequiredFiles() {
		source, ok := staticSourcePath(required.Path)
		if !ok {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(source))
		if _, err := os.Lstat(path); err == nil {
			continue
		}
		writeReleaseFile(t, path, required.Path+"\n")
		if required.Mode == 0o755 {
			if err := os.Chmod(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	gitRun(t, root, "add", ".")
	gitRun(t, root, "commit", "-qm", "candidate-tree-inputs")
	gitRun(t, root, "checkout", "-q", "--detach")
	runtimeRoot, runtime := candidateInputRoot(t, candidateRuntimeFixturePaths(), 0o755)
	licensePaths := installerFixturePaths(func(path string) bool { return strings.HasPrefix(path, "docs/licenses/") })
	licenseRoot, license := candidateLicenseRoot(t, licensePaths)
	policy := policyForTree(t, root, "github.com/acme/acornfox-fixture")
	commit := gitRun(t, root, "rev-parse", "HEAD")
	witness := witnessForInputs(t, policy, toolchain, runtime, license)
	witness.decision.SourceCommit = commit
	raw, err := CanonicalDecisionV1(witness.decision)
	if err != nil {
		t.Fatal(err)
	}
	witness, err = ParseDecisionV1(raw, sha256Text(raw))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PrepareGoBuildPlanV1(context.Background(), witness, policy, toolchain, root, cache, localNPMCLIPath(t))
	if err != nil || !plan.Valid() {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}
	return plan, fakeCandidateGoStage(t, plan), fakeCandidateWebStage(t, plan), runtimeRoot, runtime, licenseRoot, license
}

func candidateRuntimeFixturePaths() []string {
	goFiles := map[string]bool{}
	for _, target := range fixedTargets {
		goFiles["bin/"+target.name] = true
	}
	return installerFixturePaths(func(path string) bool { return strings.HasPrefix(path, "bin/") && !goFiles[path] })
}

func installerFixturePaths(match func(string) bool) []string {
	var paths []string
	for _, file := range install.AcornFoxV1RequiredFiles() {
		if match(file.Path) {
			paths = append(paths, file.Path)
		}
	}
	sort.Strings(paths)
	return paths
}

func candidateInputRoot(t *testing.T, paths []string, mode os.FileMode) (string, RuntimeInputsV1) {
	t.Helper()
	root := buildTaskRoot(t)
	files := make([]FileEntryV1, 0, len(paths))
	for _, path := range paths {
		body := []byte("input " + path + "\n")
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, body, mode); err != nil {
			t.Fatal(err)
		}
		files = append(files, FileEntryV1{Path: path, SHA256: sha256Text(body), Mode: uint32(mode)})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return root, RuntimeInputsV1{SchemaVersion: 1, Product: Product, Architecture: Architecture, Files: files}
}

func candidateLicenseRoot(t *testing.T, paths []string) (string, LicenseInputsV1) {
	t.Helper()
	root := buildTaskRoot(t)
	files := make([]FileEntryV1, 0, len(paths))
	for _, path := range paths {
		body := []byte("license " + path + "\n")
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, body, 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, FileEntryV1{Path: path, SHA256: sha256Text(body), Mode: 0o644})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return root, LicenseInputsV1{SchemaVersion: 1, Product: Product, Files: files}
}

func fakeCandidateGoStage(t *testing.T, plan GoBuildPlanV1) *GoBinaryStageV1 {
	t.Helper()
	parent := buildTaskRoot(t)
	root := filepath.Join(parent, "go")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := make([]FileEntryV1, 0, len(fixedTargets))
	for _, target := range fixedTargets {
		body := []byte("synthetic " + target.name + "\n")
		path := "bin/" + target.name
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(path)), body, 0o755); err != nil {
			t.Fatal(err)
		}
		files = append(files, FileEntryV1{Path: path, SHA256: sha256Text(body), Mode: 0o755})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	tree, err := canonicalBinaryTree(files)
	if err != nil {
		t.Fatal(err)
	}
	parentInfo, _ := os.Lstat(parent)
	stageInfo, _ := os.Lstat(root)
	return &GoBinaryStageV1{root: root, parent: parent, parentInfo: parentInfo, stageInfo: stageInfo, receipt: GoBinaryReceiptV1{SchemaVersion: 1, Product: Product, Architecture: Architecture, SourceCommit: plan.sourceCommit, DecisionSHA256: plan.decisionSHA256, SourcePolicySHA256: plan.sourcePolicySHA256, ToolchainSHA256: plan.toolchainSHA256, TreeSHA256: sha256Text(tree), Files: files}}
}

func fakeCandidateWebStage(t *testing.T, plan GoBuildPlanV1) *WebAssetStageV1 {
	t.Helper()
	parent, cache := buildTaskRoot(t), buildTaskRoot(t)
	root, dist := filepath.Join(parent, "web"), filepath.Join(parent, "web", "dist")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dist, "assets"), 0o700); err != nil {
		t.Fatal(err)
	}
	metadata, _ := json.Marshal(map[string]string{"apiBaseUrl": "/api/v1", "mode": "live", "product": Product, "releaseId": "release-" + plan.releaseVersion, "schemaVersion": webReleaseSchemaVersion, "sourceCommit": plan.sourceCommit, "sourceRepository": plan.sourceRepositoryURL, "version": plan.releaseVersion})
	content := map[string][]byte{"index.html": []byte("<main>AcornFox</main>\n"), "build-metadata.json": metadata, "assets/app-abcdefgh.js": []byte("asset\n")}
	files := make([]FileEntryV1, 0, len(content))
	for path, body := range content {
		if err := os.WriteFile(filepath.Join(dist, filepath.FromSlash(path)), body, 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, FileEntryV1{Path: path, SHA256: sha256Text(body), Mode: 0o644})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	tree, _ := json.Marshal(files)
	parentInfo, _ := os.Lstat(parent)
	stageInfo, _ := os.Lstat(root)
	pinned, err := pinNPMCache(cache)
	if err != nil {
		t.Fatal(err)
	}
	return &WebAssetStageV1{root: root, parent: parent, parentInfo: parentInfo, stageInfo: stageInfo, dist: dist, plan: plan, npmCache: pinned, receipt: WebBuildReceiptV1{SchemaVersion: 1, Product: Product, Architecture: Architecture, Version: plan.releaseVersion, ReleaseID: "release-" + plan.releaseVersion, SourceRepository: plan.sourceRepositoryURL, SourceCommit: plan.sourceCommit, DecisionSHA256: plan.decisionSHA256, SourcePolicySHA256: plan.sourcePolicySHA256, ToolchainSHA256: plan.toolchainSHA256, TreeSHA256: sha256Text(tree), Files: files}}
}

func sameCandidateFiles(left, right []install.FileDigest) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
func candidateFilePresent(files []install.FileDigest, path string, mode uint32) bool {
	for _, file := range files {
		if file.Path == path && file.Mode == mode {
			return true
		}
	}
	return false
}
