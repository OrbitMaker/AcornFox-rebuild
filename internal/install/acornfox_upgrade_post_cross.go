package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// This is a bounded continuation of one authenticated cross-schema migration,
// not general retention collection. Ordinary same-schema installations keep
// their existing two-release guard.
const acornFoxPostCrossMaxDepth = 8
const acornFoxPostCrossArchivePrefix = "post-cross-"

type acornFoxPostCrossUpgrade struct {
	Depth         int             `json:"depth"`
	JournalSHA256 string          `json:"journal_sha256"`
	Journal       json.RawMessage `json:"journal"`
}

func (acornFoxPostCrossUpgrade) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "post-cross upgrade history [redacted]")
}

func (h acornFoxPostCrossUpgrade) previous(j acornFoxUpgradeJournal) (acornFoxUpgradeJournal, error) {
	var previous acornFoxUpgradeJournal
	if h.Depth < 1 || h.Depth > acornFoxPostCrossMaxDepth || !validSHA(h.JournalSHA256) || len(h.Journal) > acornFoxUpgradeMaxJournal || sha256Hex(h.Journal) != h.JournalSHA256 || strictCanonicalJSON(h.Journal, &previous, "post-cross predecessor") != nil {
		return previous, ErrAcornFoxUpgradeConflict
	}
	// Check the decreasing depth before recursively validating any predecessor.
	if h.Depth == 1 {
		if previous.CrossSchema == nil || previous.PostCross != nil {
			return previous, ErrAcornFoxUpgradeConflict
		}
	} else if previous.CrossSchema != nil || previous.PostCross == nil || previous.PostCross.Depth != h.Depth-1 {
		return previous, ErrAcornFoxUpgradeConflict
	}
	if j.CrossSchema != nil || j.Retired0039 != nil || previous.Phase != "UPGRADED" || previous.SchemaVersion != 1 || j.LayoutSHA256 != previous.LayoutSHA256 || !bytes.Equal(acornFoxUpgradeJSON(j.Old), acornFoxUpgradeJSON(previous.Next)) {
		return previous, ErrAcornFoxUpgradeConflict
	}
	if j.Old.ControlPlane.MigrationVersion != "0040" || j.Next.ControlPlane.MigrationVersion != "0040" || len(j.Old.DatabaseEnv) == 0 || !bytes.Equal(j.Old.DatabaseEnv, j.Next.DatabaseEnv) || j.Old.ControlPlane.DatabaseEnvSHA256 != j.Next.ControlPlane.DatabaseEnvSHA256 || j.Old.ControlPlane.DatabaseIdentitySHA256 != j.Next.ControlPlane.DatabaseIdentitySHA256 || j.Old.ControlPlane.MigrationRowsSHA256 != j.Next.ControlPlane.MigrationRowsSHA256 {
		return previous, ErrAcornFoxUpgradeConflict
	}
	return previous, nil
}
func (h acornFoxPostCrossUpgrade) validate(j acornFoxUpgradeJournal, layout acornFoxInstallLayout) error {
	previous, err := h.previous(j)
	if err != nil {
		return err
	}
	if previous.validate(layout) != nil {
		return ErrAcornFoxUpgradeConflict
	}
	origin, err := acornFoxPostCrossOrigin(j)
	if err != nil {
		return err
	}
	if err := validateAcornFoxPostCrossHostOrigin(origin, layout); err != nil {
		return err
	}
	evidence := origin.CrossSchema.Database
	for _, image := range []acornFoxUpgradeImage{j.Old, j.Next} {
		if !validAcornFoxBoundControlPlaneEnvironment(image.DatabaseEnv, image.ControlPlane, evidence.ShadowDatabase) || image.ControlPlane.DatabaseEnvSHA256 != evidence.CandidateDatabaseEnvSHA256 || image.ControlPlane.MigrationRowsSHA256 != origin.CrossSchema.TargetRowsSHA256 {
			return ErrAcornFoxUpgradeConflict
		}
	}
	return nil
}

// Origin can be inspected without a live store, but every hop must preserve
// the exact prior next-image, canonical journal bytes and database identity.
func acornFoxPostCrossOrigin(j acornFoxUpgradeJournal) (acornFoxUpgradeJournal, error) {
	for count := 0; count <= acornFoxPostCrossMaxDepth; count++ {
		if j.PostCross == nil {
			if j.Phase != "UPGRADED" || j.CrossSchema == nil || j.CrossSchema.validate(j) != nil || j.CrossSchema.Database.State != acornFoxUpgradeDatabaseHealthValidated {
				return acornFoxUpgradeJournal{}, ErrAcornFoxUpgradeConflict
			}
			return j, nil
		}
		previous, err := j.PostCross.previous(j)
		if err != nil {
			return acornFoxUpgradeJournal{}, err
		}
		j = previous
	}
	return acornFoxUpgradeJournal{}, ErrAcornFoxUpgradeConflict
}

func acornFoxNewPostCrossUpgrade(previous acornFoxUpgradeJournal) (*acornFoxPostCrossUpgrade, error) {
	if previous.Phase != "UPGRADED" {
		return nil, ErrAcornFoxUpgradeRetentionFull
	}
	if _, err := acornFoxPostCrossOrigin(previous); err != nil {
		return nil, ErrAcornFoxUpgradeRetentionFull
	}
	depth := 1
	if previous.PostCross != nil {
		depth = previous.PostCross.Depth + 1
	}
	if depth > acornFoxPostCrossMaxDepth {
		return nil, ErrAcornFoxUpgradeRetentionFull
	}
	raw := acornFoxUpgradeJSON(previous)
	return &acornFoxPostCrossUpgrade{Depth: depth, JournalSHA256: sha256Hex(raw), Journal: raw}, nil
}

type acornFoxPostCrossArchive struct {
	path  string
	image acornFoxUpgradeImage
}

func acornFoxPostCrossArchives(j acornFoxUpgradeJournal) ([]acornFoxPostCrossArchive, acornFoxUpgradeJournal, error) {
	archives := []acornFoxPostCrossArchive{}
	seen := map[string]bool{}
	for j.PostCross != nil {
		previous, err := j.PostCross.previous(j)
		if err != nil {
			return nil, acornFoxUpgradeJournal{}, err
		}
		binding := previous.Old.Repo.BindingSHA256
		if !validSHA(binding) || seen[binding] {
			return nil, acornFoxUpgradeJournal{}, ErrAcornFoxUpgradeConflict
		}
		seen[binding] = true
		archives = append(archives, acornFoxPostCrossArchive{path: "upgrade/" + acornFoxPostCrossArchivePrefix + binding, image: previous.Old})
		j = previous
	}
	origin, err := acornFoxPostCrossOrigin(j)
	return archives, origin, err
}

func (u *acornFoxUpgrade) retirePostCrossStash(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal) error {
	if j.PostCross == nil {
		return nil
	}
	if !s.ownsLock() || j.validate(u.layout) != nil {
		return ErrAcornFoxUpgradeConflict
	}
	archives, _, err := acornFoxPostCrossArchives(j)
	if err != nil || len(archives) == 0 {
		return ErrAcornFoxUpgradeConflict
	}
	first := archives[0]
	if _, err := s.root.Lstat(first.path); err == nil {
		return u.retired0039SubstrateAt(s, first.path, first.image)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrAcornFoxUpgradeConflict
	}
	if err := u.retired0039SubstrateAt(s, "upgrade/old-state", first.image); err != nil {
		return err
	}
	if err := s.root.Rename("upgrade/old-state", first.path); err != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	if err := acornFoxLiveSyncDir(s.root, acornFoxUpgradeDirectory); err != nil {
		return err
	}
	return u.fault("post-cross-stash-retired")
}

func (u *acornFoxUpgrade) verifyPostCrossArchives(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal) error {
	archives, origin, err := acornFoxPostCrossArchives(j)
	if err != nil {
		return err
	}
	for _, archive := range archives {
		if err := u.retired0039SubstrateAt(s, archive.path, archive.image); err != nil {
			return err
		}
	}
	if origin.Retired0039 != nil {
		if err := u.verifyRetired0039Stash(s, origin); err != nil {
			return err
		}
	}
	return u.verifyCrossSchemaDatabaseArtifacts(s, *origin.CrossSchema)
}

func (j acornFoxUpgradeJournal) retainsSuccessorHelper() bool {
	return j.CrossSchema != nil || j.PostCross != nil
}

func validateAcornFoxPostCrossHostOrigin(origin acornFoxUpgradeJournal, layout acornFoxInstallLayout) error {
	if origin.CrossSchema == nil {
		return ErrAcornFoxUpgradeConflict
	}
	expected := ""
	switch origin.CrossSchema.OldMigrationVersion {
	case acornFoxRecentPredecessorMigration:
		var err error
		expected, err = acornFoxRecent0039HostEvidenceSHA(origin.Old.Repo.BindingSHA256, origin.Next.Repo.BindingSHA256, layout)
		if err != nil {
			return err
		}
	case AcornFoxLegacyPredecessorMigration:
		legacy, err := acornFoxLegacy0034LayoutFromCurrent(layout)
		if err != nil {
			return err
		}
		pi, ok := layout.owner(AcornFoxLivePIRole)
		if !ok {
			return ErrAcornFoxUpgradeConflict
		}
		evidence := acornFoxLegacyHostProvisionEvidence{1, origin.Old.Repo.BindingSHA256, origin.Next.Repo.BindingSHA256, legacy.evidence(), layout.evidence(), pi.uid, pi.gid, acornFoxLegacyPIDirectorySetSHA256()}
		expected = sha256Hex(acornFoxUpgradeJSON(evidence))
	default:
		return ErrAcornFoxUpgradeConflict
	}
	if origin.CrossSchema.HostProvisionSHA256 != expected {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}
