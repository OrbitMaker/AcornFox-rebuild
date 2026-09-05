package acornfoxrelease

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/open-card/open-card/internal/install"
)

var ErrCandidateTree = errors.New("acornfox synthetic candidate tree is invalid")

var candidateWebAssetName = regexp.MustCompile(`^[A-Za-z0-9_.-]+-[A-Za-z0-9_-]{8,}\.(?:css|js|map|png|jpe?g|svg|gif|webp|ico|woff2?|ttf)$`)

var candidateRuntimePaths = []string{
	"bin/buildkitd", "bin/buildctl", "bin/buildkit-runc", "bin/rootlesskit", "bin/docker-buildx", "bin/caddy",
}

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
		if added[path] || (!required[path] && !validCandidateWebAsset(path)) {
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
	if err := copyInputGroup(runtimeRoot, runtime.Files, candidateRuntimePaths, add, runtimeFileBytes); err != nil {
		return failWith("runtime input")
	}
	if err := copyLicenseGroup(licenseRoot, license.Files, add); err != nil {
		return failWith("license input")
	}
	if err := copyStaticSource(plan, required, added, add); err != nil || VerifySourceTree(plan.sourceRoot, plan.sourcePolicy) != nil || VerifyRuntimeTree(runtimeRoot, runtime) != nil || VerifyLicenseTree(licenseRoot, license) != nil {
		return failWith("static source")
	}
	if err := addGenerated(target, "source-manifest.sha256", 0o644, sourceManifest(plan.sourcePolicy), &entries, added); err != nil {
		return failWith("source manifest")
	}
	if err := addGenerated(target, "sbom.spdx.json", 0o644, syntheticSPDX(plan, entries), &entries, added); err != nil {
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

func requiredCandidatePaths() (map[string]bool, error) {
	required := make(map[string]bool)
	for _, file := range install.AcornFoxV1RequiredFiles() {
		if !validRelativeFile(file.Path) || (file.Mode != 0o640 && file.Mode != 0o644 && file.Mode != 0o755) || required[file.Path] {
			return nil, ErrCandidateTree
		}
		required[file.Path] = true
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
	name := strings.TrimPrefix(path, "web/dist/assets/")
	return name != path && name != "" && !strings.Contains(name, "/") && candidateWebAssetName.MatchString(name)
}
func validCandidateWebAsset(path string) bool {
	return validWebReceiptPath(path) && strings.HasPrefix(path, "web/dist/assets/")
}

func copyInputGroup(root string, files []FileEntryV1, paths []string, add func(string, uint32, string, string, FileEntryV1, int64) error, maximum int64) error {
	want := make(map[string]bool, len(paths))
	for _, path := range paths {
		want[path] = true
	}
	if len(files) != len(want) {
		return ErrCandidateTree
	}
	for _, file := range files {
		if !want[file.Path] || file.Mode != 0o755 || add(file.Path, 0o755, root, file.Path, file, maximum) != nil {
			return ErrCandidateTree
		}
		delete(want, file.Path)
	}
	return boolError(len(want) == 0)
}

func copyLicenseGroup(root string, files []FileEntryV1, add func(string, uint32, string, string, FileEntryV1, int64) error) error {
	want := map[string]bool{"docs/licenses/licenses-manifest.json": true, "docs/licenses/README.md": true, "docs/licenses/THIRD_PARTY_NOTICES.md": true}
	if len(files) != len(want) {
		return ErrCandidateTree
	}
	for _, file := range files {
		if !want[file.Path] || file.Mode != 0o644 || add(file.Path, 0o644, root, file.Path, file, licenseFileBytes) != nil {
			return ErrCandidateTree
		}
		delete(want, file.Path)
	}
	return boolError(len(want) == 0)
}

func copyStaticSource(plan GoBuildPlanV1, required, added map[string]bool, add func(string, uint32, string, string, FileEntryV1, int64) error) error {
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
		if !ok || !found || add(destination, requiredMode(destination), plan.sourceRoot, sourcePath, entry, sourceFileBytes) != nil {
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

func requiredMode(path string) uint32 {
	for _, file := range install.AcornFoxV1RequiredFiles() {
		if file.Path == path {
			return file.Mode
		}
	}
	return 0
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
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(input, maximum+1))
	closeOut, closeIn := output.Close(), input.Close()
	after, afterErr := source.Lstat(sourcePath)
	targetInfo, targetErr := target.Lstat(destination)
	if copyErr != nil || closeOut != nil || closeIn != nil || afterErr != nil || targetErr != nil || n != before.Size() || n > maximum || !os.SameFile(before, opened) || !os.SameFile(before, after) || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 || !targetInfo.Mode().IsRegular() || targetInfo.Mode().Perm() != os.FileMode(targetMode) || linkCount(targetInfo) != 1 {
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
	_, writeErr := file.Write(body)
	closeErr := file.Close()
	info, statErr := root.Lstat(path)
	if writeErr != nil || closeErr != nil || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != os.FileMode(mode) || linkCount(info) != 1 || info.Size() != int64(len(body)) {
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

func syntheticSPDX(plan GoBuildPlanV1, files []install.FileDigest) []byte {
	files = append([]install.FileDigest(nil), files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	type checksum struct{ Algorithm, ChecksumValue string }
	type file struct {
		SPDXID, FileName string
		Checksums        []checksum
	}
	type relationship struct{ SpdxElementID, RelationshipType, RelatedSpdxElement string }
	document := struct {
		SPDXVersion, DataLicense, SPDXID, Name, DocumentNamespace, Comment string
		CreationInfo                                                       struct {
			Created  string
			Creators []string
		}
		DocumentDescribes []string
		Packages          []struct{ SPDXID, Name, DownloadLocation string }
		Files             []file
		Relationships     []relationship
	}{SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: "AcornFox synthetic release tree", DocumentNamespace: "https://acornfox.invalid/spdx/" + plan.decisionSHA256, Comment: "Synthetic release-tree evidence only; legal and dependency completeness are deferred to RELEASE-12B."}
	document.CreationInfo.Created, document.CreationInfo.Creators = "1970-01-01T00:00:00Z", []string{"Tool: AcornFox synthetic release tree"}
	document.DocumentDescribes = []string{"SPDXRef-Package-AcornFox"}
	document.Packages = append(document.Packages, struct{ SPDXID, Name, DownloadLocation string }{"SPDXRef-Package-AcornFox", "AcornFox", "NOASSERTION"})
	for index, entry := range files {
		id := "SPDXRef-File-" + fmtSPDXIndex(index+1)
		document.Files = append(document.Files, file{SPDXID: id, FileName: "./" + entry.Path, Checksums: []checksum{{Algorithm: "SHA256", ChecksumValue: entry.SHA256}}})
		document.Relationships = append(document.Relationships, relationship{SpdxElementID: "SPDXRef-Package-AcornFox", RelationshipType: "CONTAINS", RelatedSpdxElement: id})
	}
	raw, _ := json.Marshal(document)
	return append(raw, '\n')
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
