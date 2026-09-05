package acornfoxrelease

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/install"
)

var ErrCandidateArtifacts = errors.New("acornfox synthetic artifacts are invalid")

// candidateBuildRecordV1 is intentionally private: a synthetic build record
// documents private construction bytes, not an approval or publication claim.
type candidateBuildRecordV1 struct {
	SchemaVersion      int    `json:"schema_version"`
	Product            string `json:"product"`
	Version            string `json:"version"`
	ReleaseID          string `json:"release_id"`
	SourceRepository   string `json:"source_repository"`
	SourceCommit       string `json:"source_commit"`
	Architecture       string `json:"architecture"`
	MigrationVersion   string `json:"migration_version"`
	Synthetic          bool   `json:"synthetic"`
	State              string `json:"state"`
	ProductionAccepted bool   `json:"production_accepted"`
	CandidateAccepted  bool   `json:"candidate_accepted"`
	DecisionSHA256     string `json:"decision_sha256"`
	SourcePolicySHA256 string `json:"source_policy_sha256"`
	ToolchainSHA256    string `json:"toolchain_sha256"`
	RuntimeInputSHA256 string `json:"runtime_input_sha256"`
	LicenseInputSHA256 string `json:"license_input_sha256"`
	TreeSHA256         string `json:"tree_sha256"`
	ManifestSHA256     string `json:"manifest_sha256"`
	ArchiveSHA256      string `json:"archive_sha256"`
	BundleSHA256       string `json:"bundle_sha256"`
	BindingSHA256      string `json:"binding_sha256"`
}

func (r candidateBuildRecordV1) ValidateAgainst(receipt CandidateArtifactReceiptV1, tree CandidateTreeReceiptV1) error {
	if r.SchemaVersion != 1 || r.Product != Product || r.Version != receipt.Version || r.ReleaseID != receipt.ReleaseID || r.SourceRepository != receipt.SourceRepository || r.SourceCommit != receipt.SourceCommit || r.Architecture != Architecture || r.MigrationVersion != Migration || !r.Synthetic || r.State != "BUILT_UNAPPROVED" || r.ProductionAccepted || r.CandidateAccepted || r.DecisionSHA256 != tree.DecisionSHA256 || r.SourcePolicySHA256 != tree.SourcePolicySHA256 || r.ToolchainSHA256 != tree.ToolchainSHA256 || r.RuntimeInputSHA256 != tree.RuntimeInputSHA256 || r.LicenseInputSHA256 != tree.LicenseInputSHA256 || r.TreeSHA256 != tree.TreeSHA256 || r.ManifestSHA256 != receipt.ManifestSHA256 || r.ArchiveSHA256 != receipt.ArchiveSHA256 || r.BundleSHA256 != receipt.BundleSHA256 || r.BindingSHA256 != receipt.BindingSHA256 {
		return ErrCandidateArtifacts
	}
	return nil
}

type CandidateArtifactReceiptV1 struct {
	SchemaVersion      int           `json:"schema_version"`
	Product            string        `json:"product"`
	Version            string        `json:"version"`
	ReleaseID          string        `json:"release_id"`
	SourceRepository   string        `json:"source_repository"`
	SourceCommit       string        `json:"source_commit"`
	Architecture       string        `json:"architecture"`
	MigrationVersion   string        `json:"migration_version"`
	DecisionSHA256     string        `json:"decision_sha256"`
	SourcePolicySHA256 string        `json:"source_policy_sha256"`
	ToolchainSHA256    string        `json:"toolchain_sha256"`
	RuntimeInputSHA256 string        `json:"runtime_input_sha256"`
	LicenseInputSHA256 string        `json:"license_input_sha256"`
	TreeSHA256         string        `json:"tree_sha256"`
	ManifestSHA256     string        `json:"manifest_sha256"`
	ArchiveSHA256      string        `json:"archive_sha256"`
	BundleSHA256       string        `json:"bundle_sha256"`
	BindingSHA256      string        `json:"binding_sha256"`
	BuildRecordSHA256  string        `json:"build_record_sha256"`
	Files              []FileEntryV1 `json:"files"`
}

func (r CandidateArtifactReceiptV1) Validate() error {
	if r.SchemaVersion != 1 || r.Product != Product || r.Architecture != Architecture || r.MigrationVersion != Migration || !versionText.MatchString(r.Version) || r.ReleaseID != "release-"+r.Version || !validGitHubRepository(r.SourceRepository) || !commitText.MatchString(r.SourceCommit) {
		return ErrCandidateArtifacts
	}
	for _, value := range []string{r.DecisionSHA256, r.SourcePolicySHA256, r.ToolchainSHA256, r.RuntimeInputSHA256, r.LicenseInputSHA256, r.TreeSHA256, r.ManifestSHA256, r.ArchiveSHA256, r.BundleSHA256, r.BindingSHA256, r.BuildRecordSHA256} {
		if !digestText.MatchString(value) {
			return ErrCandidateArtifacts
		}
	}
	return validateArtifactFiles(r.Files, r)
}
func candidateArtifactNames(version string) []string {
	names := []string{
		"acornfox-" + version + "-production.tar.gz",
		"build-record.json",
		"bundle-manifest.sha256",
		"candidate-binding.json",
		"candidate-binding.sha256",
		"release-manifest.json",
	}
	sort.Strings(names)
	return names
}

func candidateArtifactDigests(r CandidateArtifactReceiptV1) map[string]string {
	archive := "acornfox-" + r.Version + "-production.tar.gz"
	return map[string]string{
		archive:                    r.ArchiveSHA256,
		"release-manifest.json":    r.ManifestSHA256,
		"bundle-manifest.sha256":   r.BundleSHA256,
		"candidate-binding.json":   r.BindingSHA256,
		"candidate-binding.sha256": sha256Text([]byte(r.BindingSHA256 + "\n")),
		"build-record.json":        r.BuildRecordSHA256,
	}
}

func validateArtifactFiles(files []FileEntryV1, receipt CandidateArtifactReceiptV1) error {
	names, expected := candidateArtifactNames(receipt.Version), candidateArtifactDigests(receipt)
	if len(files) != len(names) {
		return ErrCandidateArtifacts
	}
	for i, f := range files {
		if f.Path != names[i] || !digestText.MatchString(f.SHA256) || f.Mode != 0o644 || expected[f.Path] != f.SHA256 {
			return ErrCandidateArtifacts
		}
	}
	return nil
}

type CandidateArtifactStageV1 struct {
	root, parent          string
	parentInfo, stageInfo os.FileInfo
	receipt               CandidateArtifactReceiptV1
	treeReceipt           CandidateTreeReceiptV1
	closed                bool
}

func SealCandidateArtifactsV1(tree *CandidateTreeStageV1, taskRoot string) (*CandidateArtifactStageV1, error) {
	treeReceipt, err := tree.Receipt()
	if err != nil {
		return nil, ErrCandidateArtifacts
	}
	parent, parentInfo, err := pinCandidateParent(taskRoot)
	if err != nil {
		return nil, ErrCandidateArtifacts
	}
	stageRoot, err := os.MkdirTemp(parent, ".acornfox-candidate-artifacts-")
	if err != nil {
		return nil, ErrCandidateArtifacts
	}
	stageInfo, err := os.Lstat(stageRoot)
	stage := &CandidateArtifactStageV1{root: stageRoot, parent: parent, parentInfo: parentInfo, stageInfo: stageInfo, treeReceipt: treeReceipt}
	fail := func() (*CandidateArtifactStageV1, error) {
		if samePinnedDirectory(parent, parentInfo) && samePinnedDirectory(stageRoot, stageInfo) {
			_ = os.RemoveAll(stageRoot)
		}
		return nil, ErrCandidateArtifacts
	}
	failWith := func(reason string) (*CandidateArtifactStageV1, error) {
		_, _ = fail()
		return nil, errors.New("acornfox synthetic artifacts are invalid: " + reason)
	}
	if err != nil || os.Chmod(stageRoot, 0o700) != nil {
		return fail()
	}
	root, err := os.OpenRoot(stageRoot)
	if err != nil {
		return fail()
	}
	defer root.Close()
	if err := root.Mkdir("payload", 0o700); err != nil {
		return fail()
	}
	if err := root.Mkdir("payload/release", 0o700); err != nil {
		return fail()
	}
	payload, err := root.OpenRoot("payload/release")
	if err != nil {
		return fail()
	}
	defer payload.Close()
	entries := append([]install.FileDigest(nil), treeReceipt.Files...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	for _, entry := range entries {
		if err := copyCandidateFile(filepath.Join(tree.root, "release"), entry.Path, payload, entry.Path, FileEntryV1{Path: entry.Path, SHA256: entry.SHA256, Mode: entry.Mode}, entry.Mode, runtimeFileBytes); err != nil {
			return failWith("copy tree")
		}
	}
	manifest := install.Manifest{SchemaVersion: install.ManifestSchemaVersion, Product: Product, Version: treeReceipt.Version, ReleaseID: treeReceipt.ReleaseID, Architecture: Architecture, MigrationVersion: Migration, SourceCommit: treeReceipt.SourceCommit, Protocol: install.AgentProtocolVersion, ConfigDir: install.AcornFoxV1ConfigDir, DataDir: install.AcornFoxV1DataDir, Compatibility: install.Compatibility{MinDataVersion: 33, MaxDataVersion: 33, MinAgentProtocol: install.PreviousAgentProtocol, MaxAgentProtocol: install.AgentProtocolVersion}, Files: entries}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return fail()
	}
	if err := writeRootFile(payload, "manifest.json", manifestRaw, 0o644); err != nil {
		return failWith("manifest")
	}
	archiveName := "acornfox-" + treeReceipt.Version + "-production.tar.gz"
	archiveSHA, archiveSize, err := writeArchive(root, "payload", archiveName, entries, manifestRaw)
	if err != nil || archiveSize <= 0 {
		return failWith("archive")
	}
	bundle := []byte(archiveSHA + "  " + archiveName + "\n" + sha256Text(manifestRaw) + "  release/manifest.json\n")
	binding := install.AcornFoxCandidateBindingV1{SchemaVersion: install.AcornFoxCandidateBindingV1Schema, Product: Product, Version: treeReceipt.Version, ReleaseID: treeReceipt.ReleaseID, SourceRepository: treeReceipt.SourceRepository, SourceCommit: treeReceipt.SourceCommit, Architecture: Architecture, MigrationVersion: Migration, ManifestSHA256: sha256Text(manifestRaw), ArchiveSHA256: archiveSHA, BundleManifestSHA256: sha256Text(bundle)}
	bindingRaw, err := json.Marshal(binding)
	if err != nil {
		return fail()
	}
	recordRaw, err := json.Marshal(candidateBuildRecordV1{SchemaVersion: 1, Product: Product, Version: treeReceipt.Version, ReleaseID: treeReceipt.ReleaseID, SourceRepository: treeReceipt.SourceRepository, SourceCommit: treeReceipt.SourceCommit, Architecture: Architecture, MigrationVersion: Migration, Synthetic: true, State: "BUILT_UNAPPROVED", ProductionAccepted: false, CandidateAccepted: false, DecisionSHA256: treeReceipt.DecisionSHA256, SourcePolicySHA256: treeReceipt.SourcePolicySHA256, ToolchainSHA256: treeReceipt.ToolchainSHA256, RuntimeInputSHA256: treeReceipt.RuntimeInputSHA256, LicenseInputSHA256: treeReceipt.LicenseInputSHA256, TreeSHA256: treeReceipt.TreeSHA256, ManifestSHA256: sha256Text(manifestRaw), ArchiveSHA256: archiveSHA, BundleSHA256: sha256Text(bundle), BindingSHA256: sha256Text(bindingRaw)})
	if err != nil {
		return fail()
	}
	outputs := map[string][]byte{"release-manifest.json": manifestRaw, "bundle-manifest.sha256": bundle, "candidate-binding.json": bindingRaw, "candidate-binding.sha256": []byte(sha256Text(bindingRaw) + "\n"), "build-record.json": recordRaw}
	for name, body := range outputs {
		if err := writeRootFile(root, name, body, 0o644); err != nil {
			return failWith("output")
		}
	}
	files, err := inspectArtifactFiles(stageRoot, append([]string{archiveName}, mapKeys(outputs)...))
	if err != nil {
		return failWith("artifact inspection")
	}
	stage.receipt = CandidateArtifactReceiptV1{SchemaVersion: 1, Product: Product, Version: treeReceipt.Version, ReleaseID: treeReceipt.ReleaseID, SourceRepository: treeReceipt.SourceRepository, SourceCommit: treeReceipt.SourceCommit, Architecture: Architecture, MigrationVersion: Migration, DecisionSHA256: treeReceipt.DecisionSHA256, SourcePolicySHA256: treeReceipt.SourcePolicySHA256, ToolchainSHA256: treeReceipt.ToolchainSHA256, RuntimeInputSHA256: treeReceipt.RuntimeInputSHA256, LicenseInputSHA256: treeReceipt.LicenseInputSHA256, TreeSHA256: treeReceipt.TreeSHA256, ManifestSHA256: sha256Text(manifestRaw), ArchiveSHA256: archiveSHA, BundleSHA256: sha256Text(bundle), BindingSHA256: sha256Text(bindingRaw), BuildRecordSHA256: sha256Text(recordRaw), Files: files}
	if stage.receipt.Validate() != nil || !stage.valid() {
		return failWith("receipt")
	}
	return stage, nil
}

func mapKeys(values map[string][]byte) []string {
	out := make([]string, 0, len(values))
	for k := range values {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func writeRootFile(root *os.Root, path string, body []byte, mode uint32) error {
	if ensureCandidateDirectories(root, path) != nil {
		return ErrCandidateArtifacts
	}
	f, err := root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(mode))
	if err != nil {
		return ErrCandidateArtifacts
	}
	if err = f.Chmod(os.FileMode(mode)); err != nil {
		_ = f.Close()
		return ErrCandidateArtifacts
	}
	_, err = f.Write(body)
	closeErr := f.Close()
	info, statErr := root.Lstat(path)
	if err != nil || closeErr != nil || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != os.FileMode(mode) || linkCount(info) != 1 {
		return ErrCandidateArtifacts
	}
	return nil
}

func writeArchive(root *os.Root, payload, archive string, entries []install.FileDigest, manifest []byte) (string, int64, error) {
	out, err := root.OpenFile(archive, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", 0, ErrCandidateArtifacts
	}
	if err = out.Chmod(0o644); err != nil {
		_ = out.Close()
		return "", 0, ErrCandidateArtifacts
	}
	hash := sha256.New()
	count := &countWriter{w: io.MultiWriter(out, hash)}
	gz, err := gzip.NewWriterLevel(count, gzip.BestCompression)
	if err != nil {
		_ = out.Close()
		return "", 0, ErrCandidateArtifacts
	}
	gz.Header.ModTime = time.Unix(0, 0)
	gz.Header.OS = 255
	tw := tar.NewWriter(gz)
	payloadRoot, err := root.OpenRoot(payload + "/release")
	if err != nil {
		return "", 0, ErrCandidateArtifacts
	}
	defer payloadRoot.Close()
	members := make([]FileEntryV1, 0, len(entries)+1)
	members = append(members, FileEntryV1{Path: "manifest.json", SHA256: sha256Text(manifest), Mode: 0o644})
	for _, e := range entries {
		members = append(members, FileEntryV1{Path: e.Path, SHA256: e.SHA256, Mode: e.Mode})
	}
	sort.Slice(members, func(i, j int) bool { return members[i].Path < members[j].Path })
	for _, m := range members {
		if err := writeTarMember(tw, payloadRoot, "release/"+m.Path, m); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			_ = out.Close()
			return "", 0, ErrCandidateArtifacts
		}
	}
	if err = tw.Close(); err != nil {
		_ = gz.Close()
		_ = out.Close()
		return "", 0, ErrCandidateArtifacts
	}
	if err = gz.Close(); err != nil {
		_ = out.Close()
		return "", 0, ErrCandidateArtifacts
	}
	if err = out.Sync(); err != nil {
		_ = out.Close()
		return "", 0, ErrCandidateArtifacts
	}
	if err = out.Close(); err != nil {
		return "", 0, ErrCandidateArtifacts
	}
	return hex.EncodeToString(hash.Sum(nil)), count.n, nil
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, e := c.w.Write(p)
	c.n += int64(n)
	if c.n > 512<<20 {
		return n, ErrCandidateArtifacts
	}
	return n, e
}
func writeTarMember(tw *tar.Writer, root *os.Root, name string, entry FileEntryV1) error {
	f, err := root.OpenFile(entry.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrCandidateArtifacts
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != os.FileMode(entry.Mode) || linkCount(info) != 1 {
		_ = f.Close()
		return ErrCandidateArtifacts
	}
	h := &tar.Header{Name: name, Mode: int64(entry.Mode), Size: info.Size(), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR, ModTime: time.Unix(0, 0), Uid: 0, Gid: 0, Uname: "", Gname: ""}
	if err = tw.WriteHeader(h); err != nil {
		_ = f.Close()
		return ErrCandidateArtifacts
	}
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(tw, hash), io.LimitReader(f, runtimeFileBytes+1))
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil || n != info.Size() || n > runtimeFileBytes || hex.EncodeToString(hash.Sum(nil)) != entry.SHA256 {
		return ErrCandidateArtifacts
	}
	return nil
}
func inspectArtifactFiles(root string, names []string) ([]FileEntryV1, error) {
	sort.Strings(names)
	anchored, err := os.OpenRoot(root)
	if err != nil {
		return nil, ErrCandidateArtifacts
	}
	defer anchored.Close()
	out := make([]FileEntryV1, 0, len(names))
	for _, name := range names {
		before, err := anchored.Lstat(name)
		if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0o644 || linkCount(before) != 1 || before.Size() < 0 || before.Size() > 512<<20 {
			return nil, ErrCandidateArtifacts
		}
		file, err := anchored.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, ErrCandidateArtifacts
		}
		opened, statErr := file.Stat()
		hash := sha256.New()
		n, readErr := io.Copy(hash, io.LimitReader(file, (512<<20)+1))
		closeErr := file.Close()
		after, afterErr := anchored.Lstat(name)
		if statErr != nil || readErr != nil || closeErr != nil || afterErr != nil || n != before.Size() || n > 512<<20 || !os.SameFile(before, opened) || !os.SameFile(before, after) {
			return nil, ErrCandidateArtifacts
		}
		out = append(out, FileEntryV1{Path: name, SHA256: hex.EncodeToString(hash.Sum(nil)), Mode: 0o644})
	}
	return out, nil
}
func (stage *CandidateArtifactStageV1) Receipt() (CandidateArtifactReceiptV1, error) {
	if stage == nil || stage.closed || !stage.valid() {
		return CandidateArtifactReceiptV1{}, ErrCandidateArtifacts
	}
	copy := stage.receipt
	copy.Files = append([]FileEntryV1(nil), stage.receipt.Files...)
	return copy, nil
}
func (stage *CandidateArtifactStageV1) Close() error {
	if stage == nil || stage.closed {
		return nil
	}
	if !stage.valid() {
		return ErrCandidateArtifacts
	}
	if err := os.RemoveAll(stage.root); err != nil {
		return ErrCandidateArtifacts
	}
	stage.closed = true
	return nil
}
func (stage *CandidateArtifactStageV1) valid() bool {
	if stage == nil || stage.closed || stage.receipt.Validate() != nil || stage.treeReceipt.Validate() != nil || !samePinnedDirectory(stage.parent, stage.parentInfo) || !samePinnedDirectory(stage.root, stage.stageInfo) {
		return false
	}
	if !verifyArtifactRoot(stage.root, stage.receipt) {
		return false
	}
	files, err := inspectArtifactFiles(stage.root, candidateArtifactNames(stage.receipt.Version))
	if err != nil || !sameFileEntries(files, stage.receipt.Files) {
		return false
	}
	manifest, err := verifyPayloadTree(filepath.Join(stage.root, "payload", "release"), stage.treeReceipt, stage.receipt)
	if err != nil || !verifyManifest(manifest, stage.treeReceipt, stage.receipt) {
		return false
	}
	return verifyArtifactSemantics(stage.root, manifest, stage.receipt, stage.treeReceipt)
}

func verifyArtifactRoot(root string, receipt CandidateArtifactReceiptV1) bool {
	outer, err := os.Lstat(root)
	if err != nil || !outer.IsDir() || outer.Mode()&os.ModeSymlink != 0 {
		return false
	}
	anchored, err := os.OpenRoot(root)
	if err != nil {
		return false
	}
	defer anchored.Close()
	opened, err := anchored.Stat(".")
	if err != nil || !os.SameFile(outer, opened) {
		return false
	}
	dir, err := anchored.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	children, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil || closeErr != nil || len(children) != len(receipt.Files)+1 {
		return false
	}
	want := map[string]bool{"payload": true}
	for _, name := range candidateArtifactNames(receipt.Version) {
		want[name] = true
	}
	for _, child := range children {
		before, err := anchored.Lstat(child.Name())
		if err != nil || before.Mode()&os.ModeSymlink != 0 || !want[child.Name()] {
			return false
		}
		if child.Name() == "payload" {
			if !before.IsDir() || !verifyPayloadContainer(anchored) {
				return false
			}
		} else if !before.Mode().IsRegular() || before.Mode().Perm() != 0o644 || linkCount(before) != 1 {
			return false
		}
	}
	return true
}

func verifyPayloadContainer(root *os.Root) bool {
	payload, err := root.OpenRoot("payload")
	if err != nil {
		return false
	}
	defer payload.Close()
	dir, err := payload.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	children, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil || closeErr != nil || len(children) != 1 || children[0].Name() != "release" {
		return false
	}
	info, err := payload.Lstat("release")
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func verifyPayloadTree(root string, tree CandidateTreeReceiptV1, receipt CandidateArtifactReceiptV1) ([]byte, error) {
	if tree.Validate() != nil {
		return nil, ErrCandidateArtifacts
	}
	want := make(map[string]FileEntryV1, len(tree.Files)+1)
	parents := map[string]bool{".": true}
	for _, file := range tree.Files {
		want[file.Path] = FileEntryV1{Path: file.Path, SHA256: file.SHA256, Mode: file.Mode}
		for parent := filepath.ToSlash(filepath.Dir(file.Path)); parent != "."; parent = filepath.ToSlash(filepath.Dir(parent)) {
			parents[parent] = true
		}
	}
	if _, exists := want["manifest.json"]; exists {
		return nil, ErrCandidateArtifacts
	}
	want["manifest.json"] = FileEntryV1{Path: "manifest.json", SHA256: receipt.ManifestSHA256, Mode: 0o644}
	outer, err := os.Lstat(root)
	if err != nil || !outer.IsDir() || outer.Mode()&os.ModeSymlink != 0 {
		return nil, ErrCandidateArtifacts
	}
	anchored, err := os.OpenRoot(root)
	if err != nil {
		return nil, ErrCandidateArtifacts
	}
	defer anchored.Close()
	openedRoot, err := anchored.Stat(".")
	if err != nil || !os.SameFile(outer, openedRoot) {
		return nil, ErrCandidateArtifacts
	}
	seen := map[string]bool{}
	var total int64
	var manifest []byte
	var walk func(string) error
	walk = func(dir string) error {
		directory, err := anchored.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return ErrCandidateArtifacts
		}
		children, readErr := directory.ReadDir(-1)
		closeErr := directory.Close()
		if readErr != nil || closeErr != nil {
			return ErrCandidateArtifacts
		}
		for _, child := range children {
			path := child.Name()
			if dir != "." {
				path = dir + "/" + path
			}
			before, err := anchored.Lstat(path)
			if err != nil || before.Mode()&os.ModeSymlink != 0 {
				return ErrCandidateArtifacts
			}
			if before.IsDir() {
				if !parents[path] || walk(path) != nil {
					return ErrCandidateArtifacts
				}
				continue
			}
			expected, ok := want[path]
			if !ok || !before.Mode().IsRegular() || before.Mode().Perm() != os.FileMode(expected.Mode) || linkCount(before) != 1 || before.Size() < 0 || before.Size() > runtimeFileBytes || before.Size() > runtimeTreeBytes-total {
				return ErrCandidateArtifacts
			}
			input, err := anchored.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			if err != nil {
				return ErrCandidateArtifacts
			}
			opened, statErr := input.Stat()
			hash := sha256.New()
			var body bytes.Buffer
			writer := io.Writer(hash)
			if path == "manifest.json" {
				writer = io.MultiWriter(hash, &body)
			}
			n, readErr := io.Copy(writer, io.LimitReader(input, runtimeFileBytes+1))
			closeErr := input.Close()
			after, afterErr := anchored.Lstat(path)
			if statErr != nil || readErr != nil || closeErr != nil || afterErr != nil || n != before.Size() || n > runtimeFileBytes || !os.SameFile(before, opened) || !os.SameFile(before, after) || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
				return ErrCandidateArtifacts
			}
			total += n
			seen[path] = true
			if path == "manifest.json" {
				manifest = append([]byte(nil), body.Bytes()...)
			}
		}
		return nil
	}
	if walk(".") != nil || len(seen) != len(want) || len(manifest) == 0 {
		return nil, ErrCandidateArtifacts
	}
	return manifest, nil
}

func verifyManifest(raw []byte, tree CandidateTreeReceiptV1, receipt CandidateArtifactReceiptV1) bool {
	var manifest install.Manifest
	if strictCandidateJSON(raw, &manifest) != nil || manifest.SchemaVersion != install.ManifestSchemaVersion || manifest.Product != Product || manifest.Version != receipt.Version || manifest.ReleaseID != receipt.ReleaseID || manifest.Architecture != Architecture || manifest.MigrationVersion != Migration || manifest.SourceCommit != receipt.SourceCommit || manifest.Protocol != install.AgentProtocolVersion || manifest.ConfigDir != install.AcornFoxV1ConfigDir || manifest.DataDir != install.AcornFoxV1DataDir || manifest.NMinusOne != nil || manifest.Compatibility.MinDataVersion != 33 || manifest.Compatibility.MaxDataVersion != 33 || manifest.Compatibility.MinAgentProtocol != install.PreviousAgentProtocol || manifest.Compatibility.MaxAgentProtocol != install.AgentProtocolVersion || len(manifest.Files) != len(tree.Files) {
		return false
	}
	return sameInstallFileEntries(manifest.Files, tree.Files)
}

func verifyArtifactSemantics(root string, manifest []byte, receipt CandidateArtifactReceiptV1, tree CandidateTreeReceiptV1) bool {
	read := func(name string) ([]byte, bool) {
		body, err := readCandidateSmallFile(root, name)
		return body, err == nil
	}
	bundle, ok := read("bundle-manifest.sha256")
	if !ok || !bytes.Equal(bundle, []byte(receipt.ArchiveSHA256+"  acornfox-"+receipt.Version+"-production.tar.gz\n"+receipt.ManifestSHA256+"  release/manifest.json\n")) {
		return false
	}
	bindingRaw, ok := read("candidate-binding.json")
	if !ok || sha256Text(bindingRaw) != receipt.BindingSHA256 {
		return false
	}
	if _, err := install.ParseAcornFoxCandidateBindingV1(bindingRaw, receipt.BindingSHA256); err != nil {
		return false
	}
	var binding install.AcornFoxCandidateBindingV1
	if strictCandidateJSON(bindingRaw, &binding) != nil || binding.SchemaVersion != install.AcornFoxCandidateBindingV1Schema || binding.Product != Product || binding.Version != receipt.Version || binding.ReleaseID != receipt.ReleaseID || binding.SourceRepository != receipt.SourceRepository || binding.SourceCommit != receipt.SourceCommit || binding.Architecture != Architecture || binding.MigrationVersion != Migration || binding.ManifestSHA256 != receipt.ManifestSHA256 || binding.ArchiveSHA256 != receipt.ArchiveSHA256 || binding.BundleManifestSHA256 != receipt.BundleSHA256 || binding.NMinusOne != nil {
		return false
	}
	bindingDigest, ok := read("candidate-binding.sha256")
	if !ok || !bytes.Equal(bindingDigest, []byte(receipt.BindingSHA256+"\n")) {
		return false
	}
	recordRaw, ok := read("build-record.json")
	if !ok || sha256Text(recordRaw) != receipt.BuildRecordSHA256 {
		return false
	}
	var record candidateBuildRecordV1
	if strictCandidateJSON(recordRaw, &record) != nil || record.ValidateAgainst(receipt, tree) != nil {
		return false
	}
	return sha256Text(manifest) == receipt.ManifestSHA256
}

func readCandidateSmallFile(root, name string) ([]byte, error) {
	anchored, err := os.OpenRoot(root)
	if err != nil {
		return nil, ErrCandidateArtifacts
	}
	defer anchored.Close()
	before, err := anchored.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0o644 || linkCount(before) != 1 || before.Size() < 0 || before.Size() > 1<<20 {
		return nil, ErrCandidateArtifacts
	}
	file, err := anchored.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrCandidateArtifacts
	}
	opened, statErr := file.Stat()
	body, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	closeErr := file.Close()
	after, afterErr := anchored.Lstat(name)
	if statErr != nil || readErr != nil || closeErr != nil || afterErr != nil || int64(len(body)) != before.Size() || len(body) > 1<<20 || !os.SameFile(before, opened) || !os.SameFile(before, after) {
		return nil, ErrCandidateArtifacts
	}
	return body, nil
}

func strictCandidateJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode candidate JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrCandidateArtifacts
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ErrCandidateArtifacts
	}
	return nil
}

func sameInstallFileEntries(left, right []install.FileDigest) bool {
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
