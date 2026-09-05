package install

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// A candidate-set is intentionally a closed, flat directory.  The binding
// digest comes from the caller, not from the adjacent convenience sidecar.
const (
	acornFoxCandidateBindingFile       = "candidate-binding.json"
	acornFoxCandidateBindingDigestFile = "candidate-binding.sha256"
	acornFoxCandidateManifestFile      = "release-manifest.json"
	acornFoxCandidateBundleFile        = "bundle-manifest.sha256"
	acornFoxCandidateBuildRecordFile   = "build-record.json"
	acornFoxCandidateSetMaxFileBytes   = 2 << 20
)

// AcornFoxCandidateSetRequestV1 is the complete caller authority for a
// bootstrap candidate.  It intentionally has no root, account, unit, or
// executable override: those are fixed by the host bridge.
type AcornFoxCandidateSetRequestV1 struct {
	Directory     string
	BindingSHA256 string
	SelfSHA256    string
}

// Keep the old package-local spelling for the existing focused tests while
// exposing only the sealed three-field request to bridge callers.
type acornFoxCandidateSetRequest = AcornFoxCandidateSetRequestV1

// acornFoxCandidateSet is a short-lived sealed input to the later stager. Its
// archive descriptor is rewound after verification; callers cannot substitute
// a different archive stream after the manifest and binding were checked.
type acornFoxCandidateSet struct {
	bindingRaw, manifestRaw, bundleRaw, buildRecordRaw []byte
	bindingSHA256                                      string
	binding                                            VerifiedAcornFoxBindingV1
	archive                                            *os.File
	archiveSize                                        int64
}

func (s *acornFoxCandidateSet) Close() error {
	if s == nil || s.archive == nil {
		return nil
	}
	file := s.archive
	s.archive = nil
	return file.Close()
}

func acornFoxCandidateArchiveName(version string) string {
	return "acornfox-" + version + "-production.tar.gz"
}

func loadAcornFoxCandidateSet(request acornFoxCandidateSetRequest, predecessor []byte, self acornFoxSelfVerifier) (*acornFoxCandidateSet, error) {
	if !validSHA(request.BindingSHA256) || !validSHA(request.SelfSHA256) || !safeAbsoluteDurableRoot(request.Directory) || filepath.Clean(request.Directory) == string(filepath.Separator) {
		return nil, errors.New("AcornFox candidate set request is invalid")
	}
	before, err := os.Lstat(request.Directory)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("AcornFox candidate set directory is unsafe")
	}
	root, err := os.OpenRoot(request.Directory)
	if err != nil {
		return nil, errors.New("AcornFox candidate set directory is unsafe")
	}
	defer root.Close()

	read := func(name string, limit int64) ([]byte, error) {
		return readAcornFoxCandidateSetFile(root, name, limit)
	}
	bindingRaw, err := read(acornFoxCandidateBindingFile, acornFoxCandidateBindingMaxBytes)
	if err != nil {
		return nil, err
	}
	// The sidecar is retained for operator ergonomics, but must exactly repeat
	// the independently supplied authority and can never replace it.
	sidecar, err := read(acornFoxCandidateBindingDigestFile, 128)
	if err != nil || !bytes.Equal(sidecar, []byte(request.BindingSHA256+"\n")) {
		return nil, errors.New("AcornFox candidate binding sidecar is invalid")
	}
	binding, err := ParseAcornFoxCandidateBindingV1(bindingRaw, request.BindingSHA256)
	if err != nil {
		return nil, err
	}
	manifestRaw, err := read(acornFoxCandidateManifestFile, acornFoxManifestMaxBytes)
	if err != nil {
		return nil, err
	}
	bundleRaw, err := read(acornFoxCandidateBundleFile, acornFoxBundleManifestMaxBytes)
	if err != nil {
		return nil, err
	}
	buildRecordRaw, err := read(acornFoxCandidateBuildRecordFile, acornFoxCandidateSetMaxFileBytes)
	if err != nil || len(buildRecordRaw) == 0 {
		return nil, errors.New("AcornFox candidate build record is invalid")
	}
	archiveName := acornFoxCandidateArchiveName(binding.binding.Version)
	if err := validateAcornFoxCandidateSetNames(root, archiveName); err != nil {
		return nil, err
	}
	archiveInfo, err := root.Lstat(archiveName)
	if err != nil || !safeAcornFoxCandidateSetFile(archiveInfo, acornFoxArchiveMaxBytes) {
		return nil, errors.New("AcornFox candidate archive is unsafe")
	}
	archive, err := root.OpenFile(archiveName, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("AcornFox candidate archive is unsafe")
	}
	fail := func() (*acornFoxCandidateSet, error) {
		_ = archive.Close()
		return nil, errors.New("AcornFox candidate set verification failed")
	}
	opened, err := archive.Stat()
	if err != nil || !safeAcornFoxCandidateSetFile(opened, acornFoxArchiveMaxBytes) || !os.SameFile(archiveInfo, opened) {
		return fail()
	}
	if binding.binding.NMinusOne == nil && len(predecessor) != 0 {
		return fail()
	}
	if _, err = VerifyAcornFoxCandidateArtifactsV1(VerifyAcornFoxCandidateArtifactsV1Input{Binding: bindingRaw, BindingSHA256: request.BindingSHA256, Manifest: manifestRaw, BundleManifest: bundleRaw, Archive: archive, ArchiveSize: opened.Size(), PredecessorBinding: predecessor}); err != nil {
		return fail()
	}
	if _, err = archive.Seek(0, io.SeekStart); err != nil {
		return fail()
	}
	if err = self.verify(request.SelfSHA256, manifestRaw); err != nil {
		return fail()
	}
	after, err := os.Lstat(request.Directory)
	if err != nil || !os.SameFile(before, after) || !after.IsDir() || after.Mode()&os.ModeSymlink != 0 {
		return fail()
	}
	archiveAfter, err := root.Lstat(archiveName)
	if err != nil || !safeAcornFoxCandidateSetFile(archiveAfter, acornFoxArchiveMaxBytes) || !os.SameFile(archiveInfo, archiveAfter) {
		return fail()
	}
	return &acornFoxCandidateSet{bindingRaw: bindingRaw, manifestRaw: manifestRaw, bundleRaw: bundleRaw, buildRecordRaw: buildRecordRaw, bindingSHA256: request.BindingSHA256, binding: binding, archive: archive, archiveSize: opened.Size()}, nil
}

// stageInput returns a single pinned, rewound archive descriptor. The caller
// cannot replace the stream after the closed candidate set was verified.
func (s *acornFoxCandidateSet) stageInput() (VerifyAcornFoxCandidateArtifactsV1Input, error) {
	if s == nil || !s.binding.valid() || s.archive == nil || !validSHA(s.bindingSHA256) {
		return VerifyAcornFoxCandidateArtifactsV1Input{}, errors.New("AcornFox candidate set is invalid")
	}
	if _, err := s.archive.Seek(0, io.SeekStart); err != nil {
		return VerifyAcornFoxCandidateArtifactsV1Input{}, errors.New("AcornFox candidate archive cannot rewind")
	}
	return VerifyAcornFoxCandidateArtifactsV1Input{Binding: s.bindingRaw, BindingSHA256: s.bindingSHA256, Manifest: s.manifestRaw, BundleManifest: s.bundleRaw, Archive: s.archive, ArchiveSize: s.archiveSize}, nil
}

func validateAcornFoxCandidateSetNames(root *os.Root, archiveName string) error {
	if root == nil || archiveName == "" {
		return errors.New("AcornFox candidate set names are invalid")
	}
	dir, err := root.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("AcornFox candidate set names are invalid")
	}
	children, readErr := dir.ReadDir(7)
	closeErr := dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(children) != 6 {
		return errors.New("AcornFox candidate set is not closed")
	}
	want := map[string]bool{acornFoxCandidateBindingFile: true, acornFoxCandidateBindingDigestFile: true, acornFoxCandidateManifestFile: true, acornFoxCandidateBundleFile: true, acornFoxCandidateBuildRecordFile: true, archiveName: true}
	for _, child := range children {
		if !want[child.Name()] {
			return errors.New("AcornFox candidate set has an unknown entry")
		}
		delete(want, child.Name())
	}
	if len(want) != 0 {
		return errors.New("AcornFox candidate set misses an entry")
	}
	return nil
}

func safeAcornFoxCandidateSetFile(info os.FileInfo, limit int64) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o644 && acornFoxRepoNlink(info) == 1 && info.Size() >= 0 && info.Size() <= limit
}

// ValidateAcornFoxCandidateSetLayoutV1 exposes the installer's read-only flat
// six-file layout check. VerifyAcornFoxCandidateArtifactsV1 checks the contents.
func ValidateAcornFoxCandidateSetLayoutV1(root *os.Root, version string) error {
	if ParseVersion(version) != nil {
		return errors.New("candidate version is invalid")
	}
	return validateAcornFoxCandidateSetNames(root, acornFoxCandidateArchiveName(version))
}

func readAcornFoxCandidateSetFile(root *os.Root, name string, limit int64) ([]byte, error) {
	if root == nil || name == "" || strings.Contains(name, "/") || limit < 1 {
		return nil, errors.New("AcornFox candidate set file name is invalid")
	}
	before, err := root.Lstat(name)
	if err != nil || !safeAcornFoxCandidateSetFile(before, limit) {
		return nil, errors.New("AcornFox candidate set file is unsafe")
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("AcornFox candidate set file is unsafe")
	}
	opened, statErr := file.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	after, afterErr := root.Lstat(name)
	if statErr != nil || readErr != nil || closeErr != nil || afterErr != nil || !safeAcornFoxCandidateSetFile(opened, limit) || !safeAcornFoxCandidateSetFile(after, limit) || !os.SameFile(before, opened) || !os.SameFile(before, after) || int64(len(raw)) != before.Size() || int64(len(raw)) > limit {
		return nil, errors.New("AcornFox candidate set file changed during read")
	}
	return raw, nil
}
