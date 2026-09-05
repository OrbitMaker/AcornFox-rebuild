package acornfoxrelease

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/open-card/open-card/internal/install"
)

const syntheticCandidateInternallyVerified = "SYNTHETIC_CANDIDATE_INTERNALLY_VERIFIED"
const releaseCandidateInternallyVerified = "RELEASE_CANDIDATE_INTERNALLY_VERIFIED"

var ErrVerifiedCandidate = errors.New("acornfox candidate verification is invalid")

// VerifiedCandidateReceiptV1 records only the local verification result. It is
// deliberately not a publication, installation, or production-acceptance
// receipt.
type VerifiedCandidateReceiptV1 struct {
	SchemaVersion      int                        `json:"schema_version"`
	State              string                     `json:"state"`
	Synthetic          bool                       `json:"synthetic"`
	InstallerVerified  bool                       `json:"installer_verified"`
	ProductionAccepted bool                       `json:"production_accepted"`
	PublicReleased     bool                       `json:"public_released"`
	Artifact           CandidateArtifactReceiptV1 `json:"artifact"`
	VerificationSHA256 string                     `json:"verification_sha256"`
}

func (r VerifiedCandidateReceiptV1) Validate() error {
	if r.SchemaVersion != 1 || r.State != candidateVerifiedState(r.Synthetic) || r.Synthetic != r.Artifact.Synthetic || !r.InstallerVerified || r.ProductionAccepted || r.PublicReleased || r.Artifact.Validate() != nil || !digestText.MatchString(r.VerificationSHA256) {
		return ErrVerifiedCandidate
	}
	if r.VerificationSHA256 != candidateVerificationDigest(r.Artifact) {
		return ErrVerifiedCandidate
	}
	return nil
}

func candidateVerificationDigest(artifact CandidateArtifactReceiptV1) string {
	raw, err := json.Marshal(artifact)
	if err != nil {
		return ""
	}
	hash := sha256.New()
	_, _ = hash.Write(raw)
	_, _ = hash.Write([]byte("\n" + candidateVerifiedState(artifact.Synthetic)))
	return hex.EncodeToString(hash.Sum(nil))
}

func candidateVerifiedState(synthetic bool) string {
	if synthetic {
		return syntheticCandidateInternallyVerified
	}
	return releaseCandidateInternallyVerified
}

// VerifiedCandidateStageV1 owns a successfully re-verified private stage.
// It has no installation, activation, or publication operation.
type VerifiedCandidateStageV1 struct {
	stage   *CandidateArtifactStageV1
	receipt VerifiedCandidateReceiptV1
	closed  bool
}

// VerifySyntheticCandidateV1 runs the real installer artifact verifier over
// descriptor-pinned bytes. On success it transfers the one cleanup right from
// stage to the returned wrapper; on failure stage remains valid and caller-owned.
func VerifySyntheticCandidateV1(stage *CandidateArtifactStageV1) (*VerifiedCandidateStageV1, error) {
	if stage == nil || !stage.receipt.Synthetic {
		return nil, ErrVerifiedCandidate
	}
	return verifyCandidateV1(stage)
}

// VerifyReleaseCandidateV1 checks a real candidate with the same installer
// verifier. It does not grant host acceptance or publish anything.
func VerifyReleaseCandidateV1(stage *CandidateArtifactStageV1) (*VerifiedCandidateStageV1, error) {
	if stage == nil || stage.receipt.Synthetic {
		return nil, ErrVerifiedCandidate
	}
	return verifyCandidateV1(stage)
}

func verifyCandidateV1(stage *CandidateArtifactStageV1) (*VerifiedCandidateStageV1, error) {
	if stage == nil || !stage.validOwned() {
		return nil, ErrVerifiedCandidate
	}
	binding, err := readCandidateSmallFile(stage.root, "candidate-binding.json")
	if err != nil {
		return nil, ErrVerifiedCandidate
	}
	manifest, err := readCandidateSmallFile(stage.root, "release-manifest.json")
	if err != nil {
		return nil, ErrVerifiedCandidate
	}
	bundle, err := readCandidateSmallFile(stage.root, "bundle-manifest.sha256")
	if err != nil {
		return nil, ErrVerifiedCandidate
	}
	predecessor, err := readCandidatePredecessor(stage.root, stage.receipt)
	if err != nil {
		return nil, ErrVerifiedCandidate
	}
	root, archive, before, err := openCandidateArchive(stage)
	if err != nil {
		return nil, ErrVerifiedCandidate
	}
	verifyErr := func() error {
		_, err := install.VerifyAcornFoxCandidateArtifactsV1(install.VerifyAcornFoxCandidateArtifactsV1Input{
			Binding: binding, BindingSHA256: stage.receipt.BindingSHA256, Manifest: manifest, BundleManifest: bundle,
			Archive: io.NewSectionReader(archive, 0, before.Size()), ArchiveSize: before.Size(), PredecessorBinding: predecessor,
		})
		return err
	}()
	opened, statErr := archive.Stat()
	closeErr := archive.Close()
	after, afterErr := root.Lstat(candidateArchiveName(stage.receipt.Version))
	rootCloseErr := root.Close()
	if verifyErr != nil || statErr != nil || closeErr != nil || afterErr != nil || rootCloseErr != nil || !os.SameFile(before, opened) || !os.SameFile(before, after) {
		return nil, ErrVerifiedCandidate
	}
	if !stage.validOwned() {
		return nil, ErrVerifiedCandidate
	}
	receipt := VerifiedCandidateReceiptV1{SchemaVersion: 1, State: candidateVerifiedState(stage.receipt.Synthetic), Synthetic: stage.receipt.Synthetic, InstallerVerified: true, ProductionAccepted: false, PublicReleased: false, Artifact: cloneArtifactReceipt(stage.receipt)}
	receipt.VerificationSHA256 = candidateVerificationDigest(receipt.Artifact)
	if receipt.Validate() != nil {
		return nil, ErrVerifiedCandidate
	}
	stage.transferred = true
	return &VerifiedCandidateStageV1{stage: stage, receipt: receipt}, nil
}

func candidateArchiveName(version string) string {
	return "acornfox-" + version + "-production.tar.gz"
}

func openCandidateArchive(stage *CandidateArtifactStageV1) (*os.Root, *os.File, os.FileInfo, error) {
	root, err := os.OpenRoot(stage.root)
	if err != nil {
		return nil, nil, nil, ErrVerifiedCandidate
	}
	name := candidateArchiveName(stage.receipt.Version)
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0o644 || linkCount(before) != 1 || before.Size() < 1 || before.Size() > 512<<20 {
		_ = root.Close()
		return nil, nil, nil, ErrVerifiedCandidate
	}
	archive, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		_ = root.Close()
		return nil, nil, nil, ErrVerifiedCandidate
	}
	opened, statErr := archive.Stat()
	if statErr != nil || !os.SameFile(before, opened) {
		_ = archive.Close()
		_ = root.Close()
		return nil, nil, nil, ErrVerifiedCandidate
	}
	return root, archive, before, nil
}

func cloneArtifactReceipt(receipt CandidateArtifactReceiptV1) CandidateArtifactReceiptV1 {
	copy := receipt
	copy.Files = append([]FileEntryV1(nil), receipt.Files...)
	return copy
}

func (stage *VerifiedCandidateStageV1) Receipt() (VerifiedCandidateReceiptV1, error) {
	if stage == nil || stage.closed || stage.stage == nil || !stage.stage.transferred || !stage.stage.validStage() || stage.receipt.Validate() != nil || !sameArtifactReceipt(stage.receipt.Artifact, stage.stage.receipt) {
		return VerifiedCandidateReceiptV1{}, ErrVerifiedCandidate
	}
	copy := stage.receipt
	copy.Artifact = cloneArtifactReceipt(stage.receipt.Artifact)
	return copy, nil
}

func (stage *VerifiedCandidateStageV1) Close() error {
	if stage == nil || stage.closed {
		return nil
	}
	defer func() {
		stage.closed = true
		if stage.stage != nil {
			stage.stage.closed = true
			stage.stage.stagePin.close()
			stage.stage.parentPin.close()
		}
	}()
	if stage.stage == nil || !stage.stage.transferred || !stage.stage.validStage() || stage.receipt.Validate() != nil || !sameArtifactReceipt(stage.receipt.Artifact, stage.stage.receipt) {
		return ErrVerifiedCandidate
	}
	if err := os.RemoveAll(stage.stage.root); err != nil {
		return ErrVerifiedCandidate
	}
	stage.stage.closed = true
	stage.closed = true
	return nil
}

func sameArtifactReceipt(left, right CandidateArtifactReceiptV1) bool {
	if left.SchemaVersion != right.SchemaVersion || left.Synthetic != right.Synthetic || left.Product != right.Product || left.Version != right.Version || left.ReleaseID != right.ReleaseID || left.SourceRepository != right.SourceRepository || left.SourceCommit != right.SourceCommit || left.Architecture != right.Architecture || left.MigrationVersion != right.MigrationVersion || left.DecisionSHA256 != right.DecisionSHA256 || left.SourcePolicySHA256 != right.SourcePolicySHA256 || left.ToolchainSHA256 != right.ToolchainSHA256 || left.RuntimeInputSHA256 != right.RuntimeInputSHA256 || left.LicenseInputSHA256 != right.LicenseInputSHA256 || left.TreeSHA256 != right.TreeSHA256 || left.ManifestSHA256 != right.ManifestSHA256 || left.ArchiveSHA256 != right.ArchiveSHA256 || left.BundleSHA256 != right.BundleSHA256 || left.BindingSHA256 != right.BindingSHA256 || left.BuildRecordSHA256 != right.BuildRecordSHA256 || left.PredecessorBindingSHA256 != right.PredecessorBindingSHA256 {
		return false
	}
	return sameFileEntries(left.Files, right.Files)
}
