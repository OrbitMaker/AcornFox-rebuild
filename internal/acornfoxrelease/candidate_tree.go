package acornfoxrelease

import (
	"bytes"
	"crypto/sha1" // SPDX package verification compatibility; release integrity remains SHA-256.
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/open-card/open-card/internal/install"
)

var ErrCandidateTree = errors.New("acornfox synthetic candidate tree is invalid")

type CandidateTreeReceiptV1 struct {
	SchemaVersion      int                  `json:"schema_version"`
	Product            string               `json:"product"`
	Architecture       string               `json:"architecture"`
	Version            string               `json:"version"`
	ReleaseID          string               `json:"release_id"`
	SourceRepository   string               `json:"source_repository"`
	SourceCommit       string               `json:"source_commit"`
	DecisionSHA256     string               `json:"decision_sha256"`
	SourcePolicySHA256 string               `json:"source_policy_sha256"`
	ToolchainSHA256    string               `json:"toolchain_sha256"`
	RuntimeInputSHA256 string               `json:"runtime_input_sha256"`
	LicenseInputSHA256 string               `json:"license_input_sha256"`
	TreeSHA256         string               `json:"tree_sha256"`
	Files              []install.FileDigest `json:"files"`
}

func (r CandidateTreeReceiptV1) Validate() error {
	if r.SchemaVersion != 1 || r.Product != Product || r.Architecture != Architecture || !versionText.MatchString(r.Version) || r.ReleaseID != "release-"+r.Version || !validGitHubRepository(r.SourceRepository) || !commitText.MatchString(r.SourceCommit) {
		return ErrCandidateTree
	}
	for _, digest := range []string{r.DecisionSHA256, r.SourcePolicySHA256, r.ToolchainSHA256, r.RuntimeInputSHA256, r.LicenseInputSHA256, r.TreeSHA256} {
		if !digestText.MatchString(digest) {
			return ErrCandidateTree
		}
	}
	if validateCandidateDigests(r.Files) != nil {
		return ErrCandidateTree
	}
	raw, err := json.Marshal(r.Files)
	if err != nil || sha256Text(raw) != r.TreeSHA256 {
		return ErrCandidateTree
	}
	return nil
}

func validateCandidateDigests(files []install.FileDigest) error {
	if len(files) == 0 || len(files) > 256 {
		return ErrCandidateTree
	}
	for index, file := range files {
		if !validRelativeFile(file.Path) || !digestText.MatchString(file.SHA256) || (file.Mode != 0o640 && file.Mode != 0o644 && file.Mode != 0o755) || index > 0 && files[index-1].Path >= file.Path {
			return ErrCandidateTree
		}
	}
	return nil
}

type CandidateTreeStageV1 struct {
	root, parent          string
	parentInfo, stageInfo os.FileInfo
	receipt               CandidateTreeReceiptV1
	closed                bool
}

// BuildCandidateTreeV1 only produces a private synthetic tree for later
// packaging tests. It does not write an archive, binding, candidate, or host.
func BuildCandidateTreeV1(plan GoBuildPlanV1, goStage *GoBinaryStageV1, webStage *WebAssetStageV1, runtimeRoot string, runtime RuntimeInputsV1, licenseRoot string, license LicenseInputsV1, taskRoot string) (*CandidateTreeStageV1, error) {
	if !plan.Valid() || goStage == nil || webStage == nil || VerifyRuntimeTree(runtimeRoot, runtime) != nil || VerifyLicenseTree(licenseRoot, license) != nil || inputDigest(runtime, CanonicalRuntimeInputsV1) != plan.runtimeInputSHA256 || inputDigest(license, CanonicalLicenseInputsV1) != plan.licenseInputSHA256 {
		return nil, ErrCandidateTree
	}
	parent, parentInfo, err := pinCandidateParent(taskRoot)
	if err != nil {
		return nil, ErrCandidateTree
	}
	stageRoot, err := os.MkdirTemp(parent, ".acornfox-candidate-tree-")
	if err != nil {
		return nil, ErrCandidateTree
	}
	stageInfo, err := os.Lstat(stageRoot)
	stage := &CandidateTreeStageV1{root: stageRoot, parent: parent, parentInfo: parentInfo, stageInfo: stageInfo}
	fail := func() (*CandidateTreeStageV1, error) {
		if samePinnedDirectory(stage.parent, stage.parentInfo) && samePinnedDirectory(stage.root, stage.stageInfo) {
			_ = os.RemoveAll(stage.root)
		}
		return nil, ErrCandidateTree
	}
	failWith := func(reason string) (*CandidateTreeStageV1, error) {
		_, _ = fail()
		return nil, fmt.Errorf("%w: %s", ErrCandidateTree, reason)
	}
	if err != nil || os.Chmod(stageRoot, 0o700) != nil {
		return fail()
	}
	release := filepath.Join(stageRoot, "release")
	if err := os.Mkdir(release, 0o700); err != nil {
		return fail()
	}
	target, err := os.OpenRoot(release)
	if err != nil {
		return fail()
	}
	defer target.Close()
	required, err := requiredCandidatePaths()
	if err != nil {
		return fail()
	}
	entries := make([]install.FileDigest, 0, len(required)+16)
	added := make(map[string]bool, len(required)+16)
	add := func(path string, mode uint32, sourceRoot, sourcePath string, expected FileEntryV1, maximum int64) error {
		requiredMode, isRequired := required[path]
		if added[path] || (!isRequired && !validCandidateWebAsset(path)) || (isRequired && requiredMode != mode) {
			return ErrCandidateTree
		}
		if err := copyCandidateFile(sourceRoot, sourcePath, target, path, expected, mode, maximum); err != nil {
			return err
		}
		added[path] = true
		entries = append(entries, install.FileDigest{Path: path, SHA256: expected.SHA256, Mode: mode})
		return nil
	}

	if err := copyGoStage(plan, goStage, add); err != nil {
		return failWith("go stage")
	}
	if err := copyWebStage(plan, webStage, add); err != nil {
		return failWith("web stage")
	}
	if err := copyInputGroup(runtimeRoot, runtime.Files, installerPaths(required, added, func(path string) bool { return strings.HasPrefix(path, "bin/") }), add, runtimeFileBytes); err != nil {
		return failWith("runtime input")
	}
	if err := copyInputGroup(licenseRoot, license.Files, installerPaths(required, added, func(path string) bool { return strings.HasPrefix(path, "docs/licenses/") }), add, licenseFileBytes); err != nil {
		return failWith("license input")
	}
	if err := copyStaticSource(plan, required, added, add); err != nil || VerifySourceTree(plan.sourceRoot, plan.sourcePolicy) != nil || VerifyRuntimeTree(runtimeRoot, runtime) != nil || VerifyLicenseTree(licenseRoot, license) != nil {
		return failWith("static source")
	}
	if err := addGenerated(target, "source-manifest.sha256", 0o644, sourceManifest(plan.sourcePolicy), &entries, added); err != nil {
		return failWith("source manifest")
	}
	sbom, err := syntheticSPDX(plan, release, entries)
	if err != nil || addGenerated(target, "sbom.spdx.json", 0o644, sbom, &entries, added) != nil {
		return failWith("SPDX")
	}
	for path := range required {
		if !added[path] {
			return failWith("missing required " + path)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	if err := verifyCandidateTree(release, entries); err != nil {
		return failWith("candidate tree verify: " + err.Error())
	}
	tree, err := json.Marshal(entries)
	if err != nil {
		return failWith("tree receipt")
	}
	stage.receipt = CandidateTreeReceiptV1{SchemaVersion: 1, Product: Product, Architecture: Architecture, Version: plan.releaseVersion, ReleaseID: "release-" + plan.releaseVersion, SourceRepository: plan.sourceRepositoryURL, SourceCommit: plan.sourceCommit, DecisionSHA256: plan.decisionSHA256, SourcePolicySHA256: plan.sourcePolicySHA256, ToolchainSHA256: plan.toolchainSHA256, RuntimeInputSHA256: plan.runtimeInputSHA256, LicenseInputSHA256: plan.licenseInputSHA256, TreeSHA256: sha256Text(tree), Files: append([]install.FileDigest(nil), entries...)}
	if stage.receipt.Validate() != nil || !stage.valid() {
		return failWith("stage receipt")
	}
	return stage, nil
}

func inputDigest[T any](value T, canonical func(T) ([]byte, error)) string {
	raw, err := canonical(value)
	if err != nil {
		return ""
	}
	return sha256Text(raw)
}

func pinCandidateParent(path string) (string, os.FileInfo, error) {
	path, info, err := pinStageParent(path)
	if err != nil {
		return "", nil, ErrCandidateTree
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		return "", nil, ErrCandidateTree
	}
	return path, info, nil
}

func requiredCandidatePaths() (map[string]uint32, error) {
	required := make(map[string]uint32)
	for _, file := range install.AcornFoxV1RequiredFiles() {
		_, duplicate := required[file.Path]
		if !validRelativeFile(file.Path) || (file.Mode != 0o640 && file.Mode != 0o644 && file.Mode != 0o755) || duplicate {
			return nil, ErrCandidateTree
		}
		required[file.Path] = file.Mode
	}
	return required, nil
}

func copyGoStage(plan GoBuildPlanV1, stage *GoBinaryStageV1, add func(string, uint32, string, string, FileEntryV1, int64) error) error {
	receipt, err := stage.Receipt()
	if err != nil || receipt.SourceCommit != plan.sourceCommit || receipt.DecisionSHA256 != plan.decisionSHA256 || receipt.SourcePolicySHA256 != plan.sourcePolicySHA256 || receipt.ToolchainSHA256 != plan.toolchainSHA256 || receipt.TreeSHA256 == "" {
		return ErrCandidateTree
	}
	for _, file := range receipt.Files {
		if !strings.HasPrefix(file.Path, "bin/acornfox") || file.Mode != 0o755 || add(file.Path, 0o755, stage.root, file.Path, file, maxGoBinaryOutputBytes) != nil {
			return ErrCandidateTree
		}
	}
	return boolError(len(receipt.Files) == len(fixedTargets))
}

func copyWebStage(plan GoBuildPlanV1, stage *WebAssetStageV1, add func(string, uint32, string, string, FileEntryV1, int64) error) error {
	receipt, err := stage.Receipt()
	if err != nil || receipt.Version != plan.releaseVersion || receipt.ReleaseID != "release-"+plan.releaseVersion || receipt.SourceRepository != plan.sourceRepositoryURL || receipt.SourceCommit != plan.sourceCommit || receipt.DecisionSHA256 != plan.decisionSHA256 || receipt.SourcePolicySHA256 != plan.sourcePolicySHA256 || receipt.ToolchainSHA256 != plan.toolchainSHA256 {
		return ErrCandidateTree
	}
	for _, file := range receipt.Files {
		destination := "web/dist/" + file.Path
		if file.Mode != 0o644 || !validWebReceiptPath(destination) || add(destination, 0o644, stage.dist, file.Path, file, maxWebDistMemberBytes) != nil {
			return ErrCandidateTree
		}
	}
	return nil
}

func validWebReceiptPath(path string) bool {
	if path == "web/dist/index.html" || path == "web/dist/build-metadata.json" {
		return true
	}
	return install.IsAcornFoxV1WebAssetPath(path)
}
func validCandidateWebAsset(path string) bool { return install.IsAcornFoxV1WebAssetPath(path) }

func installerPaths(required map[string]uint32, added map[string]bool, match func(string) bool) map[string]uint32 {
	want := map[string]uint32{}
	for path, mode := range required {
		if !added[path] && match(path) {
			want[path] = mode
		}
	}
	return want
}

func copyInputGroup(root string, files []FileEntryV1, want map[string]uint32, add func(string, uint32, string, string, FileEntryV1, int64) error, maximum int64) error {
	if len(files) != len(want) {
		return ErrCandidateTree
	}
	for _, file := range files {
		mode, ok := want[file.Path]
		if !ok || file.Mode != mode || add(file.Path, mode, root, file.Path, file, maximum) != nil {
			return ErrCandidateTree
		}
		delete(want, file.Path)
	}
	return boolError(len(want) == 0)
}

func copyStaticSource(plan GoBuildPlanV1, required map[string]uint32, added map[string]bool, add func(string, uint32, string, string, FileEntryV1, int64) error) error {
	source := make(map[string]FileEntryV1, len(plan.sourcePolicy.Files))
	for _, entry := range plan.sourcePolicy.Files {
		source[entry.Path] = entry
	}
	for destination := range required {
		if added[destination] || destination == "source-manifest.sha256" || destination == "sbom.spdx.json" {
			continue
		}
		sourcePath, ok := staticSourcePath(destination)
		entry, found := source[sourcePath]
		if !ok || !found || add(destination, required[destination], plan.sourceRoot, sourcePath, entry, sourceFileBytes) != nil {
			return ErrCandidateTree
		}
	}
	return nil
}

func staticSourcePath(destination string) (string, bool) {
	switch {
	case strings.HasPrefix(destination, "systemd/"):
		return "deploy/systemd/" + strings.TrimPrefix(destination, "systemd/"), true
	case destination == "config/acornfox-buildkitd.toml":
		return "deploy/buildkit/acornfox-buildkitd.toml", true
	case strings.HasPrefix(destination, "caddy/"):
		return "deploy/caddy/" + strings.TrimPrefix(destination, "caddy/"), true
	case strings.HasPrefix(destination, "api/") || strings.HasPrefix(destination, "migrations/") || strings.HasPrefix(destination, "scripts/acornfox/"):
		return destination, true
	default:
		return "", false
	}
}

func boolError(ok bool) error {
	if !ok {
		return ErrCandidateTree
	}
	return nil
}

func copyCandidateFile(sourceRoot, sourcePath string, target *os.Root, destination string, expected FileEntryV1, targetMode uint32, maximum int64) error {
	if !validRelativeFile(sourcePath) || !validRelativeFile(destination) || expected.Mode == 0 || maximum <= 0 {
		return ErrCandidateTree
	}
	source, err := os.OpenRoot(sourceRoot)
	if err != nil {
		return ErrCandidateTree
	}
	defer source.Close()
	before, err := source.Lstat(sourcePath)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != os.FileMode(expected.Mode) || linkCount(before) != 1 || before.Size() < 0 || before.Size() > maximum {
		return ErrCandidateTree
	}
	input, err := source.OpenFile(sourcePath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrCandidateTree
	}
	opened, statErr := input.Stat()
	if statErr != nil || !os.SameFile(before, opened) {
		_ = input.Close()
		return ErrCandidateTree
	}
	if err := ensureCandidateDirectories(target, destination); err != nil {
		_ = input.Close()
		return err
	}
	output, err := target.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(targetMode))
	if err != nil {
		_ = input.Close()
		return ErrCandidateTree
	}
	if err := output.Chmod(os.FileMode(targetMode)); err != nil {
		_ = output.Close()
		_ = input.Close()
		return ErrCandidateTree
	}
	targetOpened, targetStatErr := output.Stat()
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(input, maximum+1))
	closeOut, closeIn := output.Close(), input.Close()
	after, afterErr := source.Lstat(sourcePath)
	targetInfo, targetErr := target.Lstat(destination)
	if targetStatErr != nil || !targetOpened.Mode().IsRegular() || targetOpened.Mode().Perm() != os.FileMode(targetMode) || copyErr != nil || closeOut != nil || closeIn != nil || afterErr != nil || targetErr != nil || n != before.Size() || n > maximum || !os.SameFile(before, opened) || !os.SameFile(before, after) || !os.SameFile(targetOpened, targetInfo) || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 || !targetInfo.Mode().IsRegular() || targetInfo.Mode().Perm() != os.FileMode(targetMode) || linkCount(targetInfo) != 1 {
		return ErrCandidateTree
	}
	return nil
}

func ensureCandidateDirectories(root *os.Root, path string) error {
	dir := filepath.ToSlash(filepath.Dir(path))
	if dir == "." {
		return nil
	}
	current := ""
	for _, part := range strings.Split(dir, "/") {
		if current != "" {
			current += "/"
		}
		current += part
		if err := root.Mkdir(current, 0o700); err != nil && !os.IsExist(err) {
			return ErrCandidateTree
		}
		info, err := root.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrCandidateTree
		}
	}
	return nil
}

func addGenerated(root *os.Root, path string, mode uint32, body []byte, entries *[]install.FileDigest, added map[string]bool) error {
	if added[path] || len(body) == 0 || int64(len(body)) > runtimeFileBytes || ensureCandidateDirectories(root, path) != nil {
		return ErrCandidateTree
	}
	file, err := root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(mode))
	if err != nil {
		return ErrCandidateTree
	}
	if err := file.Chmod(os.FileMode(mode)); err != nil {
		_ = file.Close()
		return ErrCandidateTree
	}
	opened, openErr := file.Stat()
	_, writeErr := file.Write(body)
	closeErr := file.Close()
	info, statErr := root.Lstat(path)
	if openErr != nil || !opened.Mode().IsRegular() || opened.Mode().Perm() != os.FileMode(mode) || writeErr != nil || closeErr != nil || statErr != nil || !os.SameFile(opened, info) || !info.Mode().IsRegular() || info.Mode().Perm() != os.FileMode(mode) || linkCount(info) != 1 || info.Size() != int64(len(body)) {
		return ErrCandidateTree
	}
	added[path] = true
	*entries = append(*entries, install.FileDigest{Path: path, SHA256: sha256Text(body), Mode: mode})
	return nil
}

func sourceManifest(policy SourcePolicyV1) []byte {
	var out bytes.Buffer
	for _, file := range policy.Files {
		_, _ = out.WriteString(file.SHA256 + "  " + file.Path + "\n")
	}
	return out.Bytes()
}

func syntheticSPDX(plan GoBuildPlanV1, root string, files []install.FileDigest) ([]byte, error) {
	checksums, err := spdxPayloadChecksums(root, files)
	if err != nil {
		return nil, ErrCandidateTree
	}
	type checksum struct {
		Algorithm     string `json:"algorithm"`
		ChecksumValue string `json:"checksumValue"`
	}
	type file struct {
		SPDXID           string     `json:"SPDXID"`
		FileName         string     `json:"fileName"`
		Checksums        []checksum `json:"checksums"`
		LicenseConcluded string     `json:"licenseConcluded"`
		CopyrightText    string     `json:"copyrightText"`
	}
	type relationship struct {
		SpdxElementID      string `json:"spdxElementId"`
		RelationshipType   string `json:"relationshipType"`
		RelatedSpdxElement string `json:"relatedSpdxElement"`
	}
	type pkg struct {
		SPDXID                  string `json:"SPDXID"`
		Name                    string `json:"name"`
		DownloadLocation        string `json:"downloadLocation"`
		FilesAnalyzed           bool   `json:"filesAnalyzed"`
		LicenseConcluded        string `json:"licenseConcluded"`
		LicenseDeclared         string `json:"licenseDeclared"`
		CopyrightText           string `json:"copyrightText"`
		PackageVerificationCode struct {
			Value         string   `json:"packageVerificationCodeValue"`
			ExcludedFiles []string `json:"packageVerificationCodeExcludedFiles"`
		} `json:"packageVerificationCode"`
	}
	document := struct {
		SPDXVersion       string `json:"spdxVersion"`
		DataLicense       string `json:"dataLicense"`
		SPDXID            string `json:"SPDXID"`
		Name              string `json:"name"`
		DocumentNamespace string `json:"documentNamespace"`
		Comment           string `json:"comment"`
		CreationInfo      struct {
			Created  string   `json:"created"`
			Creators []string `json:"creators"`
		} `json:"creationInfo"`
		DocumentDescribes []string       `json:"documentDescribes"`
		Packages          []pkg          `json:"packages"`
		Files             []file         `json:"files"`
		Relationships     []relationship `json:"relationships"`
	}{SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: "AcornFox synthetic release tree", DocumentNamespace: "https://acornfox.invalid/spdx/" + plan.decisionSHA256, Comment: "Synthetic release-tree evidence only; legal and dependency completeness are deferred to RELEASE-12B."}
	document.CreationInfo.Created, document.CreationInfo.Creators = "1970-01-01T00:00:00Z", []string{"Tool: AcornFox synthetic release tree"}
	document.DocumentDescribes = []string{"SPDXRef-Package-AcornFox"}
	rootPackage := pkg{SPDXID: "SPDXRef-Package-AcornFox", Name: "AcornFox", DownloadLocation: "NOASSERTION", FilesAnalyzed: true, LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION"}
	sha1Values := make([]string, 0, len(checksums))
	for _, entry := range checksums {
		sha1Values = append(sha1Values, entry.SHA1)
	}
	sort.Strings(sha1Values)
	verification := sha1.Sum([]byte(strings.Join(sha1Values, "")))
	rootPackage.PackageVerificationCode.Value = hex.EncodeToString(verification[:])
	rootPackage.PackageVerificationCode.ExcludedFiles = []string{"./sbom.spdx.json"}
	document.Packages = append(document.Packages, rootPackage)
	for index, entry := range checksums {
		id := "SPDXRef-File-" + fmtSPDXIndex(index+1)
		document.Files = append(document.Files, file{SPDXID: id, FileName: "./" + entry.Path, Checksums: []checksum{{Algorithm: "SHA1", ChecksumValue: entry.SHA1}, {Algorithm: "SHA256", ChecksumValue: entry.SHA256}}, LicenseConcluded: "NOASSERTION", CopyrightText: "NOASSERTION"})
		document.Relationships = append(document.Relationships, relationship{SpdxElementID: "SPDXRef-Package-AcornFox", RelationshipType: "CONTAINS", RelatedSpdxElement: id})
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, ErrCandidateTree
	}
	return append(raw, '\n'), nil
}

type spdxPayloadChecksum struct{ Path, SHA1, SHA256 string }

func spdxPayloadChecksums(root string, files []install.FileDigest) ([]spdxPayloadChecksum, error) {
	files = append([]install.FileDigest(nil), files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	anchored, err := os.OpenRoot(root)
	if err != nil {
		return nil, ErrCandidateTree
	}
	defer anchored.Close()
	out := make([]spdxPayloadChecksum, 0, len(files))
	for _, expected := range files {
		if expected.Path == "sbom.spdx.json" || !validRelativeFile(expected.Path) {
			return nil, ErrCandidateTree
		}
		before, err := anchored.Lstat(expected.Path)
		if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != os.FileMode(expected.Mode) || linkCount(before) != 1 || before.Size() < 0 || before.Size() > runtimeFileBytes {
			return nil, ErrCandidateTree
		}
		file, err := anchored.OpenFile(expected.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, ErrCandidateTree
		}
		opened, statErr := file.Stat()
		sha1Hash, sha256Hash := sha1.New(), sha256.New()
		n, readErr := io.Copy(io.MultiWriter(sha1Hash, sha256Hash), io.LimitReader(file, runtimeFileBytes+1))
		closeErr := file.Close()
		after, afterErr := anchored.Lstat(expected.Path)
		if statErr != nil || readErr != nil || closeErr != nil || afterErr != nil || n != before.Size() || n > runtimeFileBytes || !os.SameFile(before, opened) || !os.SameFile(before, after) || hex.EncodeToString(sha256Hash.Sum(nil)) != expected.SHA256 {
			return nil, ErrCandidateTree
		}
		out = append(out, spdxPayloadChecksum{Path: expected.Path, SHA1: hex.EncodeToString(sha1Hash.Sum(nil)), SHA256: expected.SHA256})
	}
	return out, nil
}

func fmtSPDXIndex(index int) string {
	return strings.Repeat("0", 4-len(strconv.Itoa(index))) + strconv.Itoa(index)
}

func verifyCandidateTree(root string, files []install.FileDigest) error {
	parents := map[string]bool{".": true}
	want := make(map[string]install.FileDigest, len(files))
	if validateCandidateDigests(files) != nil {
		return ErrCandidateTree
	}
	for _, file := range files {
		want[file.Path] = file
		for parent := filepath.ToSlash(filepath.Dir(file.Path)); parent != "."; parent = filepath.ToSlash(filepath.Dir(parent)) {
			parents[parent] = true
		}
	}
	outer, err := os.Lstat(root)
	if err != nil || !outer.IsDir() || outer.Mode()&os.ModeSymlink != 0 {
		return ErrCandidateTree
	}
	anchored, err := os.OpenRoot(root)
	if err != nil {
		return ErrCandidateTree
	}
	defer anchored.Close()
	opened, err := anchored.Stat(".")
	if err != nil || !os.SameFile(outer, opened) {
		return ErrCandidateTree
	}
	seen := map[string]bool{}
	var total int64
	var walk func(string) error
	walk = func(dir string) error {
		directory, err := anchored.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return ErrCandidateTree
		}
		children, readErr := directory.ReadDir(-1)
		closeErr := directory.Close()
		if readErr != nil || closeErr != nil {
			return ErrCandidateTree
		}
		for _, child := range children {
			path := child.Name()
			if dir != "." {
				path = dir + "/" + path
			}
			before, err := anchored.Lstat(path)
			if err != nil || before.Mode()&os.ModeSymlink != 0 {
				return ErrCandidateTree
			}
			if before.IsDir() {
				if !parents[path] || walk(path) != nil {
					return ErrCandidateTree
				}
				continue
			}
			expected, ok := want[path]
			if !ok || !before.Mode().IsRegular() || before.Mode().Perm() != os.FileMode(expected.Mode) || linkCount(before) != 1 || before.Size() < 0 || before.Size() > runtimeFileBytes || before.Size() > runtimeTreeBytes-total {
				return ErrCandidateTree
			}
			total += before.Size()
			input, err := anchored.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			if err != nil {
				return ErrCandidateTree
			}
			opened, statErr := input.Stat()
			hash := sha256.New()
			n, copyErr := io.Copy(hash, io.LimitReader(input, runtimeFileBytes+1))
			closeErr := input.Close()
			after, afterErr := anchored.Lstat(path)
			if statErr != nil || copyErr != nil || closeErr != nil || afterErr != nil || n != before.Size() || n > runtimeFileBytes || !os.SameFile(before, opened) || !os.SameFile(before, after) || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
				return ErrCandidateTree
			}
			seen[path] = true
		}
		return nil
	}
	if walk(".") != nil || len(seen) != len(want) {
		return ErrCandidateTree
	}
	return nil
}

func (stage *CandidateTreeStageV1) Receipt() (CandidateTreeReceiptV1, error) {
	if stage == nil || stage.closed || !stage.valid() {
		return CandidateTreeReceiptV1{}, ErrCandidateTree
	}
	copy := stage.receipt
	copy.Files = append([]install.FileDigest(nil), stage.receipt.Files...)
	return copy, nil
}
func (stage *CandidateTreeStageV1) Close() error {
	if stage == nil || stage.closed {
		return nil
	}
	if !stage.valid() {
		return ErrCandidateTree
	}
	if err := os.RemoveAll(stage.root); err != nil {
		return ErrCandidateTree
	}
	stage.closed = true
	return nil
}
func (stage *CandidateTreeStageV1) valid() bool {
	if stage == nil || stage.closed || stage.receipt.Validate() != nil || !samePinnedDirectory(stage.parent, stage.parentInfo) || !samePinnedDirectory(stage.root, stage.stageInfo) {
		return false
	}
	return verifyCandidateTree(filepath.Join(stage.root, "release"), stage.receipt.Files) == nil
}
