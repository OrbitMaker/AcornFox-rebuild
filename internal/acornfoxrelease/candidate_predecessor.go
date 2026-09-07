package acornfoxrelease

import (
	"encoding/json"

	"github.com/open-card/open-card/internal/install"
)

// This control file stays inside the pinned private stage, outside payload and
// the six exported artifacts. The installed binding supplies it at upgrade time.
const predecessorBindingFile = "predecessor-binding.json"

func candidatePredecessor(raw []byte, expectedSHA256 string) (*install.AcornFoxNMinusOneV1, *install.NMinusOne, error) {
	if len(raw) == 0 && expectedSHA256 == "" {
		return nil, nil, nil
	}
	if err := install.ParseAcornFoxPredecessorBindingV1(raw, expectedSHA256); err != nil {
		return nil, nil, ErrCandidateArtifacts
	}
	// Decode only after the installer's exact-SHA canonical parser has accepted
	// these bytes; the parser's opaque result intentionally has no public fields.
	var predecessor install.AcornFoxCandidateBindingV1
	if json.Unmarshal(raw, &predecessor) != nil {
		return nil, nil, ErrCandidateArtifacts
	}
	n := &install.AcornFoxNMinusOneV1{
		Version: predecessor.Version, MigrationVersion: predecessor.MigrationVersion,
		SourceCommit: predecessor.SourceCommit, ReleaseManifestSHA256: predecessor.ManifestSHA256,
		ArchiveSHA256: predecessor.ArchiveSHA256, BundleManifestSHA256: predecessor.BundleManifestSHA256,
		BindingSHA256: expectedSHA256,
	}
	m := &install.NMinusOne{
		Version: n.Version, MigrationVersion: n.MigrationVersion, SourceCommit: n.SourceCommit,
		ReleaseManifestSHA256: n.ReleaseManifestSHA256, ArchiveSHA256: n.ArchiveSHA256,
		BundleManifestSHA256: n.BundleManifestSHA256,
	}
	return n, m, nil
}

func readCandidatePredecessor(root string, receipt CandidateArtifactReceiptV1) ([]byte, error) {
	if receipt.PredecessorBindingSHA256 == "" {
		return nil, nil
	}
	raw, err := readCandidateSmallFile(root, predecessorBindingFile)
	if err != nil {
		return nil, ErrCandidateArtifacts
	}
	if _, _, err := candidatePredecessor(raw, receipt.PredecessorBindingSHA256); err != nil {
		return nil, err
	}
	return raw, nil
}

func sameCandidatePredecessor(left, right *install.AcornFoxNMinusOneV1) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func sameManifestPredecessor(left, right *install.NMinusOne) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
