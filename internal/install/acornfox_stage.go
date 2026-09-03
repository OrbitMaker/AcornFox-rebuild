package install

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
	"sort"
	"strings"
	"syscall"
)

var ErrAcornFoxStageCleanupUnknown = errors.New("AcornFox stage cleanup outcome is unknown")

// acornFoxStageFaultStep is deliberately narrow: it is a package-private test
// seam for the durable operations this leaf owns, not a general filesystem
// abstraction. Production stagers leave fault nil and use the real operations.
type acornFoxStageFaultStep uint8

const (
	acornFoxStageFaultSpoolWrite acornFoxStageFaultStep = iota + 1
	acornFoxStageFaultSpoolSync
	acornFoxStageFaultSpoolSeek
	acornFoxStageFaultSpoolClose
	acornFoxStageFaultSpoolRemove
	acornFoxStageFaultStageMkdir
	acornFoxStageFaultStageOpen
	acornFoxStageFaultStageMetadata
	acornFoxStageFaultStageParentEntrySync
	acornFoxStageFaultParentMkdir
	acornFoxStageFaultParentEntrySync
	acornFoxStageFaultParentMetadata
	acornFoxStageFaultParentDirectorySync
	acornFoxStageFaultStageDirectorySync
	acornFoxStageFaultMemberWrite
	acornFoxStageFaultMemberSync
	acornFoxStageFaultMemberDirectorySync
	acornFoxStageFaultMemberClose
	acornFoxStageFaultReceiptCreate
	acornFoxStageFaultReceiptWrite
	acornFoxStageFaultReceiptSync
	acornFoxStageFaultReceiptRootSync
	acornFoxStageFaultReceiptReread
	acornFoxStageFaultReceiptClose
	acornFoxStageFaultFinalRootSync
	acornFoxStageFaultFinalStageSync
	acornFoxStageFaultHandleClose
	acornFoxStageFaultHandleRemove
	acornFoxStageFaultHandleSync
	acornFoxStageFaultHandleParentClose
	acornFoxStageFaultCleanupSpoolClose
	acornFoxStageFaultCleanupSpoolRemove
	acornFoxStageFaultCleanupStageClose
	acornFoxStageFaultCleanupStageRemove
	acornFoxStageFaultCleanupRootSync
)

var errAcornFoxStageShortWrite = errors.New("AcornFox stage injected short write")

type acornFoxStageFault func(acornFoxStageFaultStep) error

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
	fault    acornFoxStageFault
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
	uid       int
	gid       int
	fault     acornFoxStageFault
	seal      *acornFoxStageSeal
}

// acornFoxStageSeal is a capability minted only after the completion receipt
// has been durably written and reread. It prevents a package-local synthetic
// tree plus a copied receipt from becoming a consumable handle.
type acornFoxStageSeal struct{}

func (s StagedAcornFoxCandidateV1) valid() bool {
	return s.root != nil && s.parent != nil && s.stageName != "" && s.seal != nil && s.receipt.SchemaVersion == 1 && s.receipt.Product == AcornFoxV1Product && digestPattern.MatchString(s.receipt.ManifestSHA256) && digestPattern.MatchString(s.receipt.ArchiveSHA256) && digestPattern.MatchString(s.receipt.TreeSHA256) && s.receipt.FileCount > 0 && acornFoxStageCompletionMatches(s.root, s.receipt, s.uid, s.gid)
}

func (s *StagedAcornFoxCandidateV1) Close() error {
	if s == nil || (s.root == nil && s.parent == nil) {
		return nil
	}
	if s.root != nil {
		if err := acornFoxStageRun(s.fault, acornFoxStageFaultHandleClose, s.root.Close); err != nil {
			return ErrAcornFoxStageCleanupUnknown
		}
		s.root = nil
	}
	if s.parent == nil || s.stageName == "" {
		return nil
	}
	if err := acornFoxStageRun(s.fault, acornFoxStageFaultHandleRemove, func() error { return s.parent.RemoveAll(s.stageName) }); err != nil {
		return ErrAcornFoxStageCleanupUnknown
	}
	if err := acornFoxStageRun(s.fault, acornFoxStageFaultHandleSync, func() error { return syncAcornFoxRoot(s.parent) }); err != nil {
		return ErrAcornFoxStageCleanupUnknown
	}
	if err := acornFoxStageRun(s.fault, acornFoxStageFaultHandleParentClose, s.parent.Close); err != nil {
		return ErrAcornFoxStageCleanupUnknown
	}
	s.parent = nil
	s.stageName = ""
	s.seal = nil
	return nil
}

func (s *TaskAcornFoxStager) faultAt(step acornFoxStageFaultStep) error {
	if s != nil && s.fault != nil {
		return s.fault(step)
	}
	return nil
}

func acornFoxStageRun(fault acornFoxStageFault, step acornFoxStageFaultStep, operation func() error) error {
	if fault != nil {
		if err := fault(step); err != nil {
			return err
		}
	}
	return operation()
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

// openHandleParent pins a fresh descriptor to the verified task root. Handles
// must not borrow s.root: callers may close the stager before discarding a
// previously minted handle, and independently minted handles close in either
// order.
func (s *TaskAcornFoxStager) openHandleParent() (*os.Root, error) {
	if err := s.verifyLiveRoot(); err != nil {
		return nil, err
	}
	parent, err := os.OpenRoot(s.rootPath)
	if err != nil {
		return nil, err
	}
	directory, err := parent.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		_ = parent.Close()
		return nil, err
	}
	info, statErr := directory.Stat()
	closeErr := directory.Close()
	if statErr != nil || closeErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || !os.SameFile(info, s.rootInfo) || verifyOwner(info, s.uid, s.gid) != nil {
		_ = parent.Close()
		return nil, errors.New("AcornFox task root identity changed")
	}
	return parent, nil
}

func (s *TaskAcornFoxStager) Stage(input VerifyAcornFoxCandidateArtifactsV1Input) (handle StagedAcornFoxCandidateV1, receipt AcornFoxStageReceiptV1, err error) {
	if input.Archive == nil {
		return handle, receipt, errors.New("AcornFox archive is required")
	}
	if err = s.verifyLiveRoot(); err != nil {
		return handle, receipt, err
	}
	spoolName, err := durableTempName("", ".acornfox-spool-")
	if err != nil {
		return handle, receipt, err
	}
	spool, err := s.root.OpenFile(spoolName, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, acornFoxSpoolFileMode)
	if err != nil {
		return handle, receipt, err
	}
	spoolClosed, spoolRemoved := false, false
	var stage *os.Root
	var stageName string
	stagePublished := false
	defer func() {
		if err == nil && stagePublished {
			return
		}
		cleanupFailed := false
		if stage != nil {
			if acornFoxStageRun(s.fault, acornFoxStageFaultCleanupStageClose, stage.Close) != nil {
				cleanupFailed = true
			}
		}
		if stageName != "" {
			if acornFoxStageRun(s.fault, acornFoxStageFaultCleanupStageRemove, func() error { return s.root.RemoveAll(stageName) }) != nil {
				cleanupFailed = true
			}
		}
		if !spoolClosed {
			if acornFoxStageRun(s.fault, acornFoxStageFaultCleanupSpoolClose, spool.Close) != nil {
				cleanupFailed = true
			}
		}
		if !spoolRemoved {
			if acornFoxStageRun(s.fault, acornFoxStageFaultCleanupSpoolRemove, func() error { return s.root.Remove(spoolName) }) != nil {
				cleanupFailed = true
			}
		}
		if acornFoxStageRun(s.fault, acornFoxStageFaultCleanupRootSync, func() error { return syncAcornFoxRoot(s.root) }) != nil {
			cleanupFailed = true
		}
		handle = StagedAcornFoxCandidateV1{}
		receipt = AcornFoxStageReceiptV1{}
		if cleanupFailed {
			err = ErrAcornFoxStageCleanupUnknown
		}
	}()
	if err := spool.Chmod(acornFoxSpoolFileMode); err != nil {
		return handle, receipt, err
	}
	if err := spool.Chown(s.uid, s.gid); err != nil {
		return handle, receipt, err
	}
	if info, err := spool.Stat(); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != acornFoxSpoolFileMode || verifyOwner(info, s.uid, s.gid) != nil {
		return handle, receipt, errors.New("AcornFox spool is unsafe")
	}

	spooledInput := input
	spooledInput.Archive = io.TeeReader(input.Archive, acornFoxStageWriter{file: spool, fault: s.fault, step: acornFoxStageFaultSpoolWrite})
	verified, err := VerifyAcornFoxCandidateArtifactsV1(spooledInput)
	if err != nil {
		return handle, receipt, err
	}
	if err = acornFoxStageRun(s.fault, acornFoxStageFaultSpoolSync, spool.Sync); err != nil {
		return handle, receipt, err
	}
	if err = s.faultAt(acornFoxStageFaultSpoolSeek); err != nil {
		return handle, receipt, err
	}
	if _, err = spool.Seek(0, io.SeekStart); err != nil {
		return handle, receipt, err
	}
	if err = s.verifyLiveRoot(); err != nil {
		return handle, receipt, err
	}

	var manifest Manifest
	if err = strictCanonicalJSON(input.Manifest, &manifest, "AcornFox manifest"); err != nil {
		return handle, receipt, err
	}
	stageName, err = durableTempName("", ".acornfox-stage-")
	if err != nil {
		return handle, receipt, err
	}
	stage, err = s.createStage(stageName)
	if err != nil {
		stageName = ""
		return handle, receipt, err
	}
	sink := &acornFoxStageSink{root: stage, uid: s.uid, gid: s.gid, fault: s.fault}
	if err = verifyAcornFoxArchive(spool, input.ArchiveSize, verified.archiveSHA256, input.Manifest, manifest, sink); err != nil {
		return handle, receipt, err
	}
	if err = acornFoxStageRun(s.fault, acornFoxStageFaultFinalStageSync, func() error { return syncAcornFoxRoot(stage) }); err != nil {
		return handle, receipt, err
	}
	receipt, err = readAcornFoxStageReceipt(stage, manifest, verified, s.uid, s.gid)
	if err != nil {
		return handle, receipt, err
	}
	if err = writeAcornFoxStageCompletion(stage, receipt, s.uid, s.gid, s.fault); err != nil {
		return handle, receipt, err
	}
	if err = acornFoxStageRun(s.fault, acornFoxStageFaultSpoolRemove, func() error { return s.root.Remove(spoolName) }); err != nil {
		return handle, receipt, err
	}
	spoolRemoved = true
	if err = acornFoxStageRun(s.fault, acornFoxStageFaultSpoolClose, spool.Close); err != nil {
		return handle, receipt, err
	}
	spoolClosed = true
	if err = acornFoxStageRun(s.fault, acornFoxStageFaultFinalRootSync, func() error { return syncAcornFoxRoot(s.root) }); err != nil {
		return handle, receipt, err
	}
	if err = s.verifyLiveRoot(); err != nil {
		return handle, receipt, errors.New("AcornFox task stage publication is unknown")
	}
	parent, err := s.openHandleParent()
	if err != nil {
		return handle, receipt, errors.New("AcornFox task stage publication is unknown")
	}
	stagePublished = true
	handle = StagedAcornFoxCandidateV1{root: stage, parent: parent, stageName: stageName, receipt: receipt, uid: s.uid, gid: s.gid, fault: s.fault, seal: &acornFoxStageSeal{}}
	return handle, receipt, nil
}

func forbiddenAcornFoxStageRoot(path string) bool {
	if path == string(filepath.Separator) {
		return true
	}
	for _, root := range []string{
		AcornFoxV1InstallPrefix, AcornFoxV1ConfigDir, AcornFoxV1DataDir, AcornFoxV1LogDir,
		"/opt/open-card", "/etc/open-card", "/var/lib/open-card", "/var/log/open-card", "/etc/systemd/system",
	} {
		if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func (s *TaskAcornFoxStager) createStage(name string) (stage *os.Root, err error) {
	created := false
	defer func() {
		if err == nil || !created {
			return
		}
		cleanupFailed := false
		if stage != nil && acornFoxStageRun(s.fault, acornFoxStageFaultCleanupStageClose, stage.Close) != nil {
			cleanupFailed = true
		}
		if acornFoxStageRun(s.fault, acornFoxStageFaultCleanupStageRemove, func() error { return s.root.RemoveAll(name) }) != nil {
			cleanupFailed = true
		}
		if acornFoxStageRun(s.fault, acornFoxStageFaultCleanupRootSync, func() error { return syncAcornFoxRoot(s.root) }) != nil {
			cleanupFailed = true
		}
		stage = nil
		if cleanupFailed {
			err = ErrAcornFoxStageCleanupUnknown
		}
	}()
	if err = s.faultAt(acornFoxStageFaultStageMkdir); err != nil {
		return nil, err
	}
	if err = s.root.Mkdir(name, acornFoxStageDirMode); err != nil {
		return nil, err
	}
	created = true
	// A newly-created entry is durable in its parent before it is opened and
	// populated. This makes every later failure removable as an exact entry.
	if err = acornFoxStageRun(s.fault, acornFoxStageFaultStageParentEntrySync, func() error { return syncAcornFoxRoot(s.root) }); err != nil {
		return nil, err
	}
	if err = s.faultAt(acornFoxStageFaultStageOpen); err != nil {
		return nil, err
	}
	stage, err = s.root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	directory, err := stage.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	directoryClosed := false
	defer func() {
		if !directoryClosed {
			if closeErr := directory.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
		}
	}()
	if err = s.faultAt(acornFoxStageFaultStageMetadata); err != nil {
		return nil, err
	}
	if err = directory.Chmod(acornFoxStageDirMode); err != nil {
		return nil, err
	}
	if err = directory.Chown(s.uid, s.gid); err != nil {
		return nil, err
	}
	info, statErr := directory.Stat()
	if statErr != nil || !info.IsDir() || info.Mode().Perm() != acornFoxStageDirMode || verifyOwner(info, s.uid, s.gid) != nil {
		return nil, errors.New("AcornFox stage directory is unsafe")
	}
	if err = acornFoxStageRun(s.fault, acornFoxStageFaultStageDirectorySync, directory.Sync); err != nil {
		return nil, err
	}
	if err = directory.Close(); err != nil {
		return nil, err
	}
	directoryClosed = true
	return stage, nil
}

type acornFoxStageSink struct {
	root     *os.Root
	uid, gid int
	fault    acornFoxStageFault
}

type acornFoxStageMember struct {
	file   *os.File
	root   *os.Root
	parent string
	fault  acornFoxStageFault
}

func (m *acornFoxStageMember) Write(data []byte) (int, error) {
	return acornFoxStageWrite(m.file, m.fault, acornFoxStageFaultMemberWrite, data)
}
func (m *acornFoxStageMember) Sync() error {
	if err := acornFoxStageRun(m.fault, acornFoxStageFaultMemberSync, m.file.Sync); err != nil {
		return err
	}
	return acornFoxStageRun(m.fault, acornFoxStageFaultMemberDirectorySync, func() error { return syncAcornFoxDirectory(m.root, m.parent) })
}
func (m *acornFoxStageMember) Close() error {
	return acornFoxStageRun(m.fault, acornFoxStageFaultMemberClose, m.file.Close)
}

type acornFoxStageWriter struct {
	file  *os.File
	fault acornFoxStageFault
	step  acornFoxStageFaultStep
}

func (w acornFoxStageWriter) Write(data []byte) (int, error) {
	return acornFoxStageWrite(w.file, w.fault, w.step, data)
}

func acornFoxStageWrite(file *os.File, fault acornFoxStageFault, step acornFoxStageFaultStep, data []byte) (int, error) {
	if fault != nil {
		if err := fault(step); err != nil {
			if errors.Is(err, errAcornFoxStageShortWrite) && len(data) > 0 {
				return len(data) - 1, nil
			}
			return 0, err
		}
	}
	return file.Write(data)
}

func (s *acornFoxStageSink) OpenMember(name string, mode uint32) (acornFoxArchiveMember, error) {
	if s == nil || s.root == nil || !strings.HasPrefix(name, "release/") {
		return nil, errors.New("AcornFox stage member is unsafe")
	}
	relative := strings.TrimPrefix(name, "release/")
	if err := validateRelativePath(relative); err != nil {
		return nil, err
	}
	if err := ensureAcornFoxStageParents(s.root, filepath.ToSlash(filepath.Dir(relative)), s.uid, s.gid, s.fault); err != nil {
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
	return &acornFoxStageMember{file: file, root: s.root, parent: filepath.ToSlash(filepath.Dir(relative)), fault: s.fault}, nil
}

func ensureAcornFoxStageParents(root *os.Root, directory string, uid, gid int, fault acornFoxStageFault) error {
	if directory == "." || directory == "" {
		return nil
	}
	parts := strings.Split(filepath.ToSlash(directory), "/")
	current := ""
	for _, part := range parts {
		parent := current
		if parent == "" {
			parent = "."
		}
		current = filepath.ToSlash(filepath.Join(current, part))
		if err := acornFoxStageRun(fault, acornFoxStageFaultParentMkdir, func() error { return root.Mkdir(current, acornFoxStageDirMode) }); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		// A mkdir changes its parent entry. Sync that parent before opening the
		// child, then sync the child after metadata is checked below.
		if err := acornFoxStageRun(fault, acornFoxStageFaultParentEntrySync, func() error { return syncAcornFoxDirectory(root, parent) }); err != nil {
			return err
		}
		dir, err := root.OpenFile(current, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		if err := acornFoxStageRun(fault, acornFoxStageFaultParentMetadata, func() error { return dir.Chmod(acornFoxStageDirMode) }); err != nil {
			_ = dir.Close()
			return err
		}
		if err := dir.Chown(uid, gid); err != nil {
			_ = dir.Close()
			return err
		}
		info, err := dir.Stat()
		if err != nil || !info.IsDir() || info.Mode().Perm() != acornFoxStageDirMode || verifyOwner(info, uid, gid) != nil || acornFoxStageRun(fault, acornFoxStageFaultParentDirectorySync, dir.Sync) != nil {
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

func writeAcornFoxStageCompletion(root *os.Root, receipt AcornFoxStageReceiptV1, uid, gid int, fault acornFoxStageFault) error {
	raw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	if err := acornFoxStageRun(fault, acornFoxStageFaultReceiptCreate, func() error { return nil }); err != nil {
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
	if written, err := acornFoxStageWrite(file, fault, acornFoxStageFaultReceiptWrite, raw); err != nil || written != len(raw) {
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
	if err := acornFoxStageRun(fault, acornFoxStageFaultReceiptSync, file.Sync); err != nil {
		return err
	}
	if err := acornFoxStageRun(fault, acornFoxStageFaultReceiptClose, file.Close); err != nil {
		return err
	}
	closed = true
	if err := acornFoxStageRun(fault, acornFoxStageFaultReceiptRootSync, func() error { return syncAcornFoxRoot(root) }); err != nil {
		return err
	}
	if err := acornFoxStageRun(fault, acornFoxStageFaultReceiptReread, func() error { return nil }); err != nil {
		return err
	}
	if !acornFoxStageCompletionMatches(root, receipt, uid, gid) {
		return errors.New("AcornFox stage completion receipt is invalid")
	}
	return nil
}

func acornFoxStageCompletionMatches(root *os.Root, receipt AcornFoxStageReceiptV1, uid, gid int) bool {
	if root == nil {
		return false
	}
	want, err := json.Marshal(receipt)
	if err != nil {
		return false
	}
	file, err := root.OpenFile(".acornfox-stage-complete.json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != acornFoxSpoolFileMode || info.Size() != int64(len(want)) || verifyOwner(info, uid, gid) != nil {
		return false
	}
	read, err := io.ReadAll(io.LimitReader(file, int64(len(want))+1))
	if err != nil || len(read) != len(want) {
		return false
	}
	return bytes.Equal(read, want)
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
