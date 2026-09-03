package install

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

var ErrAcornFoxStageCleanupUnknown = errors.New("AcornFox stage cleanup outcome is unknown")

const (
	acornFoxStageDirMode  = 0o700
	acornFoxSpoolFileMode = 0o600
)

// TaskAcornFoxStager owns one already-created task root. It only creates
// private spool/stage entries below the pinned descriptor; it cannot publish a
// release, alter a pointer, or access a host installation root.
type TaskAcornFoxStager struct {
	rootPath string
	rootInfo os.FileInfo
	root     *os.Root
	uid      int
	gid      int
}

// AcornFoxStageReceiptV1 identifies staged bytes without carrying a path,
// archive body, credential, DSN, or other host-local secret.
type AcornFoxStageReceiptV1 struct {
	SchemaVersion            int    `json:"schema_version"`
	Product                  string `json:"product"`
	Version                  string `json:"version"`
	ReleaseID                string `json:"release_id"`
	ManifestSHA256           string `json:"manifest_sha256"`
	ArchiveSHA256            string `json:"archive_sha256"`
	BindingSHA256            string `json:"binding_sha256"`
	BundleManifestSHA256     string `json:"bundle_manifest_sha256"`
	SourceCommit             string `json:"source_commit"`
	Architecture             string `json:"architecture"`
	MigrationVersion         string `json:"migration_version"`
	PredecessorBindingSHA256 string `json:"predecessor_binding_sha256,omitempty"`
	FileCount                int    `json:"file_count"`
	TreeSHA256               string `json:"tree_sha256"`
}

// StagedAcornFoxCandidateV1 is intentionally opaque. A later closed leaf may
// consume its pinned directory descriptor, but this leaf exposes no stage path
// and no production applier.
type StagedAcornFoxCandidateV1 struct {
	root      *os.Root
	parent    *os.Root
	stageName string
	receipt   AcornFoxStageReceiptV1
}

func (s StagedAcornFoxCandidateV1) valid() bool {
	return s.root != nil && s.receipt.SchemaVersion == 1 && s.receipt.Product == AcornFoxV1Product && digestPattern.MatchString(s.receipt.ManifestSHA256) && digestPattern.MatchString(s.receipt.ArchiveSHA256) && digestPattern.MatchString(s.receipt.TreeSHA256) && s.receipt.FileCount > 0
}

func (s *StagedAcornFoxCandidateV1) Close() error {
	if s == nil || s.root == nil {
		return nil
	}
	root := s.root
	parent := s.parent
	name := s.stageName
	s.root = nil
	s.parent = nil
	closeErr := root.Close()
	if parent == nil || name == "" {
		return closeErr
	}
	removeErr := parent.RemoveAll(name)
	syncErr := syncAcornFoxRoot(parent)
	parentErr := parent.Close()
	if closeErr != nil || removeErr != nil || syncErr != nil || parentErr != nil {
		return ErrAcornFoxStageCleanupUnknown
	}
	return nil
}

func NewTaskAcornFoxStager(taskRoot string, uid, gid int) (*TaskAcornFoxStager, error) {
	if uid < 0 || gid < 0 || !safeAbsoluteDurableRoot(taskRoot) || forbiddenAcornFoxStageRoot(taskRoot) {
		return nil, errors.New("AcornFox task root is unsafe")
	}
	info, err := os.Lstat(taskRoot)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || verifyOwner(info, uid, gid) != nil {
		return nil, errors.New("AcornFox task root is unsafe")
	}
	root, err := os.OpenRoot(taskRoot)
	if err != nil {
		return nil, err
	}
	return &TaskAcornFoxStager{rootPath: taskRoot, rootInfo: info, root: root, uid: uid, gid: gid}, nil
}

func (s *TaskAcornFoxStager) Close() error {
	if s == nil || s.root == nil {
		return nil
	}
	root := s.root
	s.root = nil
	return root.Close()
}

func (s *TaskAcornFoxStager) verifyLiveRoot() error {
	if s == nil || s.root == nil || s.rootInfo == nil {
		return errors.New("AcornFox stager is not initialized")
	}
	info, err := os.Lstat(s.rootPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || !os.SameFile(info, s.rootInfo) || verifyOwner(info, s.uid, s.gid) != nil {
		return errors.New("AcornFox task root identity changed")
	}
	return nil
}

func (s *TaskAcornFoxStager) Stage(input VerifyAcornFoxCandidateArtifactsV1Input) (StagedAcornFoxCandidateV1, AcornFoxStageReceiptV1, error) {
	if input.Archive == nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, errors.New("AcornFox archive is required")
	}
	if err := s.verifyLiveRoot(); err != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, err
	}
	spoolName, err := durableTempName("", ".acornfox-spool-")
	if err != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, err
	}
	spool, err := s.root.OpenFile(spoolName, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, acornFoxSpoolFileMode)
	if err != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, err
	}
	spoolClosed, spoolRemoved := false, false
	defer func() {
		if !spoolClosed {
			_ = spool.Close()
		}
		if !spoolRemoved {
			_ = s.root.Remove(spoolName)
		}
	}()
	if err := spool.Chmod(acornFoxSpoolFileMode); err != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, err
	}
	if err := spool.Chown(s.uid, s.gid); err != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, err
	}
	if info, err := spool.Stat(); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != acornFoxSpoolFileMode || verifyOwner(info, s.uid, s.gid) != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, errors.New("AcornFox spool is unsafe")
	}

	spooledInput := input
	spooledInput.Archive = io.TeeReader(input.Archive, spool)
	verified, err := VerifyAcornFoxCandidateArtifactsV1(spooledInput)
	if err != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, err
	}
	if err := spool.Sync(); err != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, err
	}
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, err
	}
	if err := s.verifyLiveRoot(); err != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, err
	}

	var manifest Manifest
	if err := strictCanonicalJSON(input.Manifest, &manifest, "AcornFox manifest"); err != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, err
	}
	stageName, err := durableTempName("", ".acornfox-stage-")
	if err != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, err
	}
	stage, err := s.createStage(stageName)
	if err != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, err
	}
	stagePublished := false
	defer func() {
		if !stagePublished {
			_ = stage.Close()
			_ = s.root.RemoveAll(stageName)
			_ = syncAcornFoxRoot(s.root)
		}
	}()
	sink := &acornFoxStageSink{root: stage, uid: s.uid, gid: s.gid}
	if err := verifyAcornFoxArchive(spool, input.ArchiveSize, verified.archiveSHA256, input.Manifest, manifest, sink); err != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, err
	}
	if err := syncAcornFoxRoot(stage); err != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, err
	}
	receipt, err := readAcornFoxStageReceipt(stage, manifest, verified, s.uid, s.gid)
	if err != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, err
	}
	if err := writeAcornFoxStageCompletion(stage, receipt, s.uid, s.gid); err != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, err
	}
	if err := s.root.Remove(spoolName); err != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, err
	}
	spoolRemoved = true
	if err := spool.Close(); err != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, err
	}
	spoolClosed = true
	if err := syncAcornFoxRoot(s.root); err != nil || s.verifyLiveRoot() != nil {
		return StagedAcornFoxCandidateV1{}, AcornFoxStageReceiptV1{}, errors.New("AcornFox task stage publication is unknown")
	}
	stagePublished = true
	return StagedAcornFoxCandidateV1{root: stage, parent: s.root, stageName: stageName, receipt: receipt}, receipt, nil
}

func forbiddenAcornFoxStageRoot(path string) bool {
	if path == string(filepath.Separator) {
		return true
	}
	for _, root := range []string{AcornFoxV1InstallPrefix, AcornFoxV1ConfigDir, AcornFoxV1DataDir, AcornFoxV1LogDir} {
		if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func (s *TaskAcornFoxStager) createStage(name string) (*os.Root, error) {
	if err := s.root.Mkdir(name, acornFoxStageDirMode); err != nil {
		return nil, err
	}
	stage, err := s.root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	directory, err := stage.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		_ = stage.Close()
		return nil, err
	}
	defer directory.Close()
	if err := directory.Chmod(acornFoxStageDirMode); err != nil {
		_ = stage.Close()
		return nil, err
	}
	if err := directory.Chown(s.uid, s.gid); err != nil {
		_ = stage.Close()
		return nil, err
	}
	info, err := directory.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != acornFoxStageDirMode || verifyOwner(info, s.uid, s.gid) != nil || directory.Sync() != nil {
		_ = stage.Close()
		return nil, errors.New("AcornFox stage directory is unsafe")
	}
	if err := syncAcornFoxRoot(s.root); err != nil {
		_ = stage.Close()
		return nil, err
	}
	return stage, nil
}

type acornFoxStageSink struct {
	root     *os.Root
	uid, gid int
}

type acornFoxStageMember struct {
	file   *os.File
	root   *os.Root
	parent string
}

func (m *acornFoxStageMember) Write(data []byte) (int, error) { return m.file.Write(data) }
func (m *acornFoxStageMember) Sync() error {
	if err := m.file.Sync(); err != nil {
		return err
	}
	return syncAcornFoxDirectory(m.root, m.parent)
}
func (m *acornFoxStageMember) Close() error { return m.file.Close() }

func (s *acornFoxStageSink) OpenMember(name string, mode uint32) (acornFoxArchiveMember, error) {
	if s == nil || s.root == nil || !strings.HasPrefix(name, "release/") {
		return nil, errors.New("AcornFox stage member is unsafe")
	}
	relative := strings.TrimPrefix(name, "release/")
	if err := validateRelativePath(relative); err != nil {
		return nil, err
	}
	if err := ensureAcornFoxStageParents(s.root, filepath.ToSlash(filepath.Dir(relative)), s.uid, s.gid); err != nil {
		return nil, err
	}
	file, err := s.root.OpenFile(relative, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, os.FileMode(mode))
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(os.FileMode(mode)); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Chown(s.uid, s.gid); err != nil {
		_ = file.Close()
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != os.FileMode(mode) || verifyOwner(info, s.uid, s.gid) != nil {
		_ = file.Close()
		return nil, errors.New("AcornFox stage member is unsafe")
	}
	return &acornFoxStageMember{file: file, root: s.root, parent: filepath.ToSlash(filepath.Dir(relative))}, nil
}

func ensureAcornFoxStageParents(root *os.Root, directory string, uid, gid int) error {
	if directory == "." || directory == "" {
		return nil
	}
	parts := strings.Split(filepath.ToSlash(directory), "/")
	current := ""
	for _, part := range parts {
		current = filepath.ToSlash(filepath.Join(current, part))
		if err := root.Mkdir(current, acornFoxStageDirMode); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		dir, err := root.OpenFile(current, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		if err := dir.Chmod(acornFoxStageDirMode); err != nil {
			_ = dir.Close()
			return err
		}
		if err := dir.Chown(uid, gid); err != nil {
			_ = dir.Close()
			return err
		}
		info, err := dir.Stat()
		if err != nil || !info.IsDir() || info.Mode().Perm() != acornFoxStageDirMode || verifyOwner(info, uid, gid) != nil || dir.Sync() != nil {
			_ = dir.Close()
			return errors.New("AcornFox stage parent is unsafe")
		}
		if err := dir.Close(); err != nil {
			return err
		}
	}
	return nil
}

func syncAcornFoxRoot(root *os.Root) error {
	return syncAcornFoxDirectory(root, ".")
}

func syncAcornFoxDirectory(root *os.Root, directory string) error {
	dir, err := root.OpenFile(directory, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func readAcornFoxStageReceipt(root *os.Root, manifest Manifest, verified VerifiedAcornFoxCandidateV1, uid, gid int) (AcornFoxStageReceiptV1, error) {
	files := append([]FileDigest(nil), manifest.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	hash := sha256.New()
	manifestFile, err := root.OpenFile("manifest.json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return AcornFoxStageReceiptV1{}, err
	}
	manifestInfo, err := manifestFile.Stat()
	if err != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Mode().Perm() != 0o644 || verifyOwner(manifestInfo, uid, gid) != nil {
		_ = manifestFile.Close()
		return AcornFoxStageReceiptV1{}, errors.New("AcornFox staged manifest is unsafe")
	}
	manifestDigest, err := sha256AcornFoxOpenFile(manifestFile)
	if err != nil || manifestDigest != verified.manifestSHA256 {
		_ = manifestFile.Close()
		return AcornFoxStageReceiptV1{}, errors.New("AcornFox staged manifest digest is invalid")
	}
	if err := manifestFile.Close(); err != nil {
		return AcornFoxStageReceiptV1{}, err
	}
	_, _ = fmt.Fprintf(hash, "manifest.json\x00%04o\x00%s\n", 0o644, manifestDigest)
	for _, expected := range files {
		file, err := root.OpenFile(expected.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return AcornFoxStageReceiptV1{}, err
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != os.FileMode(expected.Mode) || verifyOwner(info, uid, gid) != nil {
			_ = file.Close()
			return AcornFoxStageReceiptV1{}, errors.New("AcornFox staged member is unsafe")
		}
		digest, err := sha256AcornFoxOpenFile(file)
		if err != nil || digest != expected.SHA256 {
			_ = file.Close()
			return AcornFoxStageReceiptV1{}, errors.New("AcornFox staged member digest is invalid")
		}
		if err := file.Close(); err != nil {
			return AcornFoxStageReceiptV1{}, err
		}
		_, _ = fmt.Fprintf(hash, "%s\x00%04o\x00%s\n", expected.Path, expected.Mode, digest)
	}
	binding := verified.binding.binding
	receipt := AcornFoxStageReceiptV1{SchemaVersion: 1, Product: AcornFoxV1Product, Version: binding.Version, ReleaseID: binding.ReleaseID, ManifestSHA256: verified.manifestSHA256, ArchiveSHA256: verified.archiveSHA256, BindingSHA256: verified.binding.digest, BundleManifestSHA256: binding.BundleManifestSHA256, SourceCommit: binding.SourceCommit, Architecture: binding.Architecture, MigrationVersion: binding.MigrationVersion, FileCount: len(files), TreeSHA256: hex.EncodeToString(hash.Sum(nil))}
	if binding.NMinusOne != nil {
		receipt.PredecessorBindingSHA256 = binding.NMinusOne.BindingSHA256
	}
	return receipt, nil
}

func writeAcornFoxStageCompletion(root *os.Root, receipt AcornFoxStageReceiptV1, uid, gid int) error {
	raw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	file, err := root.OpenFile(".acornfox-stage-complete.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, acornFoxSpoolFileMode)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	if written, err := file.Write(raw); err != nil || written != len(raw) {
		if err != nil {
			return err
		}
		return io.ErrShortWrite
	}
	if err := file.Chmod(acornFoxSpoolFileMode); err != nil {
		return err
	}
	if err := file.Chown(uid, gid); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closed = true
	if err := syncAcornFoxRoot(root); err != nil {
		return err
	}
	read, err := root.ReadFile(".acornfox-stage-complete.json")
	if err != nil {
		return err
	}
	var reread AcornFoxStageReceiptV1
	if err := json.Unmarshal(read, &reread); err != nil || reread != receipt {
		return errors.New("AcornFox stage completion receipt is invalid")
	}
	return nil
}

func sha256AcornFoxOpenFile(file *os.File) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
