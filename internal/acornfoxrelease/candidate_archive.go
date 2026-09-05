package acornfoxrelease

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/install"
)

var ErrCandidateArtifacts = errors.New("acornfox synthetic artifacts are invalid")

type CandidateArtifactReceiptV1 struct {
	SchemaVersion                                                                                           int `json:"schema_version"`
	Product, Version, ReleaseID, SourceRepository, SourceCommit                                             string
	DecisionSHA256, SourcePolicySHA256, ToolchainSHA256, RuntimeInputSHA256, LicenseInputSHA256, TreeSHA256 string
	ManifestSHA256, ArchiveSHA256, BundleSHA256, BindingSHA256, BuildRecordSHA256                           string
	Files                                                                                                   []FileEntryV1 `json:"files"`
}

func (r CandidateArtifactReceiptV1) Validate() error {
	if r.SchemaVersion != 1 || r.Product != Product || !versionText.MatchString(r.Version) || r.ReleaseID != "release-"+r.Version || !validGitHubRepository(r.SourceRepository) || !commitText.MatchString(r.SourceCommit) || len(r.Files) != 6 || validateArtifactFiles(r.Files) != nil {
		return ErrCandidateArtifacts
	}
	for _, value := range []string{r.DecisionSHA256, r.SourcePolicySHA256, r.ToolchainSHA256, r.RuntimeInputSHA256, r.LicenseInputSHA256, r.TreeSHA256, r.ManifestSHA256, r.ArchiveSHA256, r.BundleSHA256, r.BindingSHA256, r.BuildRecordSHA256} {
		if !digestText.MatchString(value) {
			return ErrCandidateArtifacts
		}
	}
	return nil
}
func validateArtifactFiles(files []FileEntryV1) error {
	for i, f := range files {
		if !validRelativeFile(f.Path) || !digestText.MatchString(f.SHA256) || f.Mode != 0o644 || (i > 0 && files[i-1].Path >= f.Path) {
			return ErrCandidateArtifacts
		}
	}
	return nil
}

type CandidateArtifactStageV1 struct {
	root, parent          string
	parentInfo, stageInfo os.FileInfo
	receipt               CandidateArtifactReceiptV1
	tree                  *CandidateTreeStageV1
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
	stage := &CandidateArtifactStageV1{root: stageRoot, parent: parent, parentInfo: parentInfo, stageInfo: stageInfo, tree: tree}
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
	type record struct {
		SchemaVersion      int    `json:"schema_version"`
		State              string `json:"state"`
		ProductionAccepted bool   `json:"production_accepted"`
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
	recordRaw, err := json.Marshal(record{1, "SYNTHETIC_UNAPPROVED", false, treeReceipt.DecisionSHA256, treeReceipt.SourcePolicySHA256, treeReceipt.ToolchainSHA256, treeReceipt.RuntimeInputSHA256, treeReceipt.LicenseInputSHA256, treeReceipt.TreeSHA256, sha256Text(manifestRaw), archiveSHA, sha256Text(bundle), sha256Text(bindingRaw)})
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
	stage.receipt = CandidateArtifactReceiptV1{1, Product, treeReceipt.Version, treeReceipt.ReleaseID, treeReceipt.SourceRepository, treeReceipt.SourceCommit, treeReceipt.DecisionSHA256, treeReceipt.SourcePolicySHA256, treeReceipt.ToolchainSHA256, treeReceipt.RuntimeInputSHA256, treeReceipt.LicenseInputSHA256, treeReceipt.TreeSHA256, sha256Text(manifestRaw), archiveSHA, sha256Text(bundle), sha256Text(bindingRaw), sha256Text(recordRaw), files}
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
	if stage == nil || stage.closed || stage.receipt.Validate() != nil || !samePinnedDirectory(stage.parent, stage.parentInfo) || !samePinnedDirectory(stage.root, stage.stageInfo) || stage.tree == nil {
		return false
	}
	if _, err := stage.tree.Receipt(); err != nil {
		return false
	}
	files, err := inspectArtifactFiles(stage.root, func() []string {
		out := make([]string, 0, len(stage.receipt.Files))
		for _, f := range stage.receipt.Files {
			out = append(out, f.Path)
		}
		return out
	}())
	return err == nil && sameFileEntries(files, stage.receipt.Files)
}
