package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// The installed rollback helper must already understand the single transient
// envelope. The first release carrying this reader is reserved as beta.13.
const acornFoxLocalRolloverReader = "0.1.0-beta.13"

type acornFoxLocalRollover struct {
	State                 string          `json:"state"`
	PreviousJournalSHA256 string          `json:"previous_journal_sha256"`
	PreviousJournal       json.RawMessage `json:"previous_journal"`
}

func (acornFoxLocalRollover) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "local rollover history [redacted]")
}
func acornFoxPlainLocal(j acornFoxUpgradeJournal) bool {
	return j.isLocal() && j.CrossSchema == nil && j.Retired0039 == nil && j.PostCross == nil && j.Old.ControlPlane.MigrationVersion == "0040" && j.Next.ControlPlane.MigrationVersion == "0040"
}
func acornFoxLocalCurrent(j acornFoxUpgradeJournal) acornFoxUpgradeImage {
	if j.Phase == "ROLLED_BACK" {
		return j.Old
	}
	return j.Next
}
func acornFoxLocalNonCurrent(j acornFoxUpgradeJournal) acornFoxUpgradeImage {
	if j.Phase == "ROLLED_BACK" {
		return j.Next
	}
	return j.Old
}
func acornFoxLocalRolloverEligible(j acornFoxUpgradeJournal, current string) bool {
	version := acornFoxLocalCurrent(j).identity().Version
	return acornFoxPlainLocal(j) && j.LocalRollover == nil && (j.Phase == "UPGRADED" || j.Phase == "ROLLED_BACK") && acornFoxLocalCurrent(j).Repo.BindingSHA256 == current && (version == acornFoxLocalRolloverReader || acornFoxUpgradeVersionAfter(version, acornFoxLocalRolloverReader))
}
func acornFoxNewLocalRollover(j acornFoxUpgradeJournal) *acornFoxLocalRollover {
	raw := acornFoxUpgradeJSON(j)
	return &acornFoxLocalRollover{"RETAINING", sha256Hex(raw), raw}
}
func (r acornFoxLocalRollover) previous(j acornFoxUpgradeJournal) (acornFoxUpgradeJournal, error) {
	var previous acornFoxUpgradeJournal
	if !validSHA(r.PreviousJournalSHA256) || len(r.PreviousJournal) > acornFoxUpgradeMaxJournal || sha256Hex(r.PreviousJournal) != r.PreviousJournalSHA256 || strictCanonicalJSON(r.PreviousJournal, &previous, "local rollover predecessor") != nil {
		return previous, ErrAcornFoxUpgradeConflict
	}
	// Reject nesting before validation can recurse.
	if !acornFoxLocalRolloverEligible(previous, j.Old.Repo.BindingSHA256) || !acornFoxPlainLocal(j) || previous.LayoutSHA256 != j.LayoutSHA256 || !bytes.Equal(acornFoxUpgradeJSON(acornFoxLocalCurrent(previous)), acornFoxUpgradeJSON(j.Old)) || !bytes.Equal(j.Old.DatabaseEnv, j.Next.DatabaseEnv) || j.Old.ControlPlane.DatabaseIdentitySHA256 != j.Next.ControlPlane.DatabaseIdentitySHA256 {
		return previous, ErrAcornFoxUpgradeConflict
	}
	if !isSchema2Image(j.Old) && previous.PIEnabled != j.PIEnabled {
		return previous, ErrAcornFoxUpgradeConflict
	}
	if isSchema2Image(j.Old) && j.PIEnabled {
		return previous, ErrAcornFoxUpgradeConflict
	}
	retiring := acornFoxLocalNonCurrent(previous)
	// Collection must never address a current/rollback release or activation.
	// Exact failed-candidate retry stays in admission's existing retry branch.
	if j.Next.Repo.BindingSHA256 == retiring.Repo.BindingSHA256 || j.Next.Activation.ReleaseID == retiring.Activation.ReleaseID || j.Next.Activation.ActivationID == retiring.Activation.ActivationID {
		return previous, ErrAcornFoxUpgradeConflict
	}
	switch r.State {
	case "RETAINING":
	case "PRUNING":
		if j.Phase != "UPGRADED" {
			return previous, ErrAcornFoxUpgradeConflict
		}
	case "RESETTING":
		if j.Phase != "ROLLED_BACK" {
			return previous, ErrAcornFoxUpgradeConflict
		}
	default:
		return previous, ErrAcornFoxUpgradeConflict
	}
	return previous, nil
}
func (r acornFoxLocalRollover) validate(j acornFoxUpgradeJournal, layout acornFoxInstallLayout) error {
	previous, err := r.previous(j)
	if err != nil {
		return err
	}
	return previous.validate(layout)
}

func (u *acornFoxUpgrade) retireLocalRolloverStash(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal) error {
	if j.LocalRollover == nil {
		return nil
	}
	previous, err := j.LocalRollover.previous(j)
	if err != nil || !s.ownsLock() || j.LocalRollover.State != "RETAINING" {
		return ErrAcornFoxUpgradeConflict
	}
	if err := u.verifyLocalRolloverIntent(s, j); err != nil {
		return err
	}
	image := acornFoxLocalNonCurrent(previous)
	source := "upgrade/old-state"
	if previous.Phase == "ROLLED_BACK" {
		source = "upgrade/new-state"
	}
	target := "upgrade/local-retiring"
	if _, err := s.root.Lstat(target); err == nil {
		if err := u.retired0039SubstrateAt(s, target, image); err != nil {
			return err
		}
		// After copy, source may legitimately hold the new pair's substrate.
		if raw, err := u.read(s.root, source+"/substrate/receipt.json", 0600, acornFoxUpgradeMaxJournal); err == nil && bytes.Equal(raw, acornFoxUpgradeJSON(image.Substrate)) {
			return ErrAcornFoxUpgradeConflict
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrAcornFoxUpgradeConflict
	}
	if err := u.retired0039SubstrateAt(s, source, image); err != nil {
		return err
	}
	if err := u.fault("local-retiring-before"); err != nil {
		return err
	}
	if err := s.root.Rename(source, target); err != nil {
		return err
	}
	if err := acornFoxLiveSyncDir(s.root, "upgrade"); err != nil {
		return err
	}
	return u.fault("local-retiring-after")
}

// Terminal receipts are released only after the bounded collection/reset is
// durable. A terminal state carrying the envelope is unfinished work at boot.
func (u *acornFoxUpgrade) finishLocalRollover(s *TaskAcornFoxRepoStore, j *acornFoxUpgradeJournal) error {
	if j.LocalRollover == nil {
		return nil
	}
	previous, err := j.LocalRollover.previous(*j)
	if err != nil || !s.ownsLock() {
		return ErrAcornFoxUpgradeConflict
	}
	if j.Phase != "UPGRADED" && j.Phase != "ROLLED_BACK" {
		return ErrAcornFoxUpgradeConflict
	}
	if err := u.verifyLocalRolloverIntent(s, *j); err != nil {
		return err
	}
	success := j.Phase == "UPGRADED"
	image := j.Next
	stash := "upgrade/new-state"
	if success {
		image = acornFoxLocalNonCurrent(previous)
		stash = "upgrade/local-retiring"
	}
	inventory, err := u.localGarbageInventory(s, image, stash, success)
	if err != nil {
		return err
	}
	if j.LocalRollover.State == "RESETTING" && previous.Phase == "ROLLED_BACK" {
		if _, err := s.root.Lstat("upgrade/local-retiring"); errors.Is(err, os.ErrNotExist) {
			if err := u.retired0039SubstrateAt(s, "upgrade/new-state", acornFoxLocalNonCurrent(previous)); err != nil {
				return err
			}
			inventory = inventory[:len(inventory)-1]
		}
	}
	bindingStore := newAcornFoxBindingStore(s)
	bindingLock, err := bindingStore.lock(s.root)
	if err != nil {
		return err
	}
	defer bindingLock.Close()
	if err := bindingStore.validate(s.root); err != nil {
		return err
	}
	if j.LocalRollover.State == "RETAINING" {
		if err := u.verifyImage(s, *j, success); err != nil {
			return err
		}
		if err := u.validateLocalGarbage(s, inventory, false); err != nil {
			return err
		}
		if success {
			j.LocalRollover.State = "PRUNING"
		} else {
			j.LocalRollover.State = "RESETTING"
		}
		if err := u.save(s, *j, false); err != nil {
			return err
		}
		if err := u.fault("local-collection-started"); err != nil {
			return err
		}
	}
	if err := u.deleteLocalGarbage(s, inventory); err != nil {
		return err
	}
	if success {
		settled := *j
		settled.LocalRollover = nil
		if err := u.verifyImage(s, settled, true); err != nil {
			return err
		}
		if err := u.clearLocalRolloverIntent(s, *j); err != nil {
			return err
		}
		if err := u.atomicFileOwnedAtTemp(s, s.root, acornFoxUpgradeJournalPath, acornFoxUpgradeJSON(*j), acornFoxUpgradeJSON(settled), 0600, acornFoxInstallPrincipal{}, ".acornfox-local-settle-"+j.Next.Repo.BindingSHA256); err != nil {
			return err
		}
		*j = settled
		return nil
	}
	destination := "upgrade/old-state"
	if previous.Phase == "ROLLED_BACK" {
		destination = "upgrade/new-state"
	}
	if _, err := s.root.Lstat("upgrade/local-retiring"); err == nil {
		if err := u.retired0039SubstrateAt(s, "upgrade/local-retiring", acornFoxLocalNonCurrent(previous)); err != nil {
			return err
		}
		if err := u.removeLocalEmptyDirectory(s, destination); err != nil {
			return err
		}
		if err := u.fault("local-reset-before-restore"); err != nil {
			return err
		}
		if err := s.root.Rename("upgrade/local-retiring", destination); err != nil {
			return err
		}
		if err := acornFoxLiveSyncDir(s.root, "upgrade"); err != nil {
			return err
		}
		if err := u.fault("local-reset-restored"); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrAcornFoxUpgradeConflict
	}
	if err := u.verifyImage(s, previous, previous.Phase == "UPGRADED"); err != nil {
		return err
	}
	if err := u.clearLocalRolloverIntent(s, *j); err != nil {
		return err
	}
	if err := u.fault("local-reset-before-journal"); err != nil {
		return err
	}
	if err := u.atomicFileOwnedAtTemp(s, s.root, acornFoxUpgradeJournalPath, acornFoxUpgradeJSON(*j), j.LocalRollover.PreviousJournal, 0600, acornFoxInstallPrincipal{}, ".acornfox-local-settle-"+j.Next.Repo.BindingSHA256); err != nil {
		return err
	}
	*j = previous
	return u.fault("local-reset-complete")
}

func (u *acornFoxUpgrade) recoverLocalRolloverPending(ctx context.Context, s *TaskAcornFoxRepoStore, previous acornFoxUpgradeJournal, expected AcornFoxBuildIdentityV1) (acornFoxUpgradeJournal, bool, error) {
	if !acornFoxLocalRolloverEligible(previous, acornFoxLocalCurrent(previous).Repo.BindingSHA256) {
		return previous, false, nil
	}
	previousSHA := sha256Hex(acornFoxUpgradeJSON(previous))
	intent, hasIntent, intentErr := u.readLocalRolloverIntent(s, previousSHA)
	if intentErr != nil {
		return previous, true, intentErr
	}
	path := ".acornfox-local-rollover-" + previousSHA
	raw, err := u.read(s.root, path, 0600, acornFoxUpgradeMaxJournal)
	if errors.Is(err, os.ErrNotExist) {
		if !hasIntent {
			return previous, false, nil
		}
		raw = nil
	} else if err != nil {
		return previous, true, err
	}
	if !hasIntent {
		return previous, true, ErrAcornFoxUpgradeConflict
	}
	var pending acornFoxUpgradeJournal
	if strictCanonicalJSON(raw, &pending, "pending local rollover") != nil {
		pending, err = u.reconstructLocalRolloverPrefix(s, previous, raw, intent)
		if err != nil {
			return previous, true, err
		}
	}
	if pending.validate(u.layout) != nil || pending.Phase != "PREPARED" || pending.LocalRollover == nil || pending.LocalRollover.State != "RETAINING" || !bytes.Equal(pending.LocalRollover.PreviousJournal, acornFoxUpgradeJSON(previous)) || expected != pending.Old.identity() || pending.Next.Repo.BindingSHA256 != intent.NextBindingSHA256 || sha256Hex(acornFoxUpgradeJSON(pending)) != intent.PendingJournalSHA256 {
		return previous, true, ErrAcornFoxUpgradeConflict
	}
	manifest, err := u.imageManifest(s, previous, acornFoxLocalCurrent(previous))
	if err != nil || u.self.verify(pending.Old.Substrate.UpgradeHelperSHA256, manifest) != nil {
		return previous, true, ErrAcornFoxUpgradeConflict
	}
	if err := u.fault("local-pending-verified"); err != nil {
		return previous, true, err
	}
	lock, err := s.Acquire(ctx)
	if err != nil {
		return previous, true, err
	}
	defer lock.Release()
	actual, err := u.load(s)
	if err != nil || !bytes.Equal(acornFoxUpgradeJSON(actual), acornFoxUpgradeJSON(previous)) {
		return previous, true, ErrAcornFoxUpgradeConflict
	}
	// Reset restores the exact previous journal (an ABA). A concurrent reader
	// must not recreate an already-consumed pending transaction from stale reads.
	lockedIntent, present, intentErr := u.readLocalRolloverIntent(s, previousSHA)
	if intentErr != nil || !present || lockedIntent != intent {
		return previous, true, ErrAcornFoxUpgradeConflict
	}
	if err := u.verifyImage(s, previous, previous.Phase == "UPGRADED"); err != nil {
		return previous, true, err
	}
	if err := u.save(s, pending, true); err != nil {
		return previous, true, err
	}
	return pending, true, nil
}

// The durable small intent pins both the candidate and the complete pending
// bytes. There is deliberately no stage enumeration or substitute selection.
func (u *acornFoxUpgrade) reconstructLocalRolloverPrefix(s *TaskAcornFoxRepoStore, previous acornFoxUpgradeJournal, prefix []byte, intent acornFoxLocalRolloverIntent) (acornFoxUpgradeJournal, error) {
	var result acornFoxUpgradeJournal
	if !intent.valid(sha256Hex(acornFoxUpgradeJSON(previous))) {
		return result, ErrAcornFoxUpgradeConflict
	}
	current := acornFoxLocalCurrent(previous)
	old, err := verifiedAcornFoxUpgradePredecessor(current.Binding, current.Repo.BindingSHA256)
	if err != nil || old.binding.MigrationVersion != AcornFoxV1MigrationVersion || (old.binding.SchemaVersion != AcornFoxCandidateBindingV1Schema && old.binding.SchemaVersion != AcornFoxCandidateBindingV2Schema) {
		return result, ErrAcornFoxUpgradeConflict
	}
	sha := intent.NextBindingSHA256
	stage, err := u.openStageRoot(s, sha)
	if err != nil {
		return result, err
	}
	raw, err := u.read(stage, acornFoxSubstrateReceipt, 0600, acornFoxUpgradeMaxJournal)
	var receipt InactiveSubstrateReceiptV1
	if err != nil || strictCanonicalJSON(raw, &receipt, "local pending stage") != nil || receipt.Validate() != nil || receipt.CandidateReceipt.BindingSHA256 != sha {
		stage.Close()
		return result, ErrAcornFoxUpgradeConflict
	}
	c := receipt.CandidateReceipt
	if c.PredecessorBindingSHA256 != current.Repo.BindingSHA256 {
		stage.Close()
		return result, ErrAcornFoxUpgradeConflict
	}
	b := AcornFoxCandidateBindingV1{SchemaVersion: AcornFoxCandidateBindingCurrentSchema, Product: c.Product, Version: c.Version, ReleaseID: c.ReleaseID, SourceRepository: old.binding.SourceRepository, SourceCommit: c.SourceCommit, Architecture: c.Architecture, MigrationVersion: c.MigrationVersion, ManifestSHA256: c.ManifestSHA256, ArchiveSHA256: c.ArchiveSHA256, BundleManifestSHA256: c.BundleManifestSHA256, NMinusOne: &AcornFoxNMinusOneV1{Version: old.binding.Version, MigrationVersion: old.binding.MigrationVersion, SourceCommit: old.binding.SourceCommit, ReleaseManifestSHA256: old.binding.ManifestSHA256, ArchiveSHA256: old.binding.ArchiveSHA256, BundleManifestSHA256: old.binding.BundleManifestSHA256, BindingSHA256: old.digest}}
	bindingRaw := acornFoxUpgradeJSON(b)
	binding, err := ParseAcornFoxCandidateBindingV1(bindingRaw, sha)
	if err != nil {
		stage.Close()
		return result, ErrAcornFoxUpgradeConflict
	}
	sub := &PublishedAcornFoxSubstrateV1{root: stage, receipt: receipt, uid: s.uid, gid: s.gid, layout: u.layout, fs: newAcornFoxSubstrateFS()}
	if sub.Verify() != nil {
		sub.Close()
		return result, ErrAcornFoxUpgradeConflict
	}
	next, err := u.nextImage(current, &acornFoxCandidateSet{bindingRaw: bindingRaw, bindingSHA256: sha, binding: binding}, sub, nil, acornFoxControlPlaneMigrations{})
	sub.Close()
	if err != nil {
		return result, err
	}
	piEnabled := previous.PIEnabled
	if isSchema2Image(current) {
		piEnabled = false
	}
	pending := acornFoxUpgradeJournal{SchemaVersion: 1, Phase: "PREPARED", LayoutSHA256: previous.LayoutSHA256, PIEnabled: piEnabled, LocalRollover: acornFoxNewLocalRollover(previous), Old: current, Next: next}
	full := acornFoxUpgradeJSON(pending)
	if pending.validate(u.layout) != nil || sha256Hex(full) != intent.PendingJournalSHA256 || !bytes.HasPrefix(full, prefix) {
		return result, ErrAcornFoxUpgradeConflict
	}
	return pending, nil
}
