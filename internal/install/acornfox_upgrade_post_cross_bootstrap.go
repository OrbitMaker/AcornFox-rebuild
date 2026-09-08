package install

import (
	"bytes"
	"context"
	"errors"
	"os"
	"syscall"
)

func validateAcornFoxPostCrossPendingPair(previous, pending acornFoxUpgradeJournal, layout acornFoxInstallLayout) error {
	if previous.Phase != "UPGRADED" || pending.Phase != "PREPARED" || pending.PostCross == nil || previous.validate(layout) != nil || pending.validate(layout) != nil || !bytes.Equal(pending.PostCross.Journal, acornFoxUpgradeJSON(previous)) {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}

// The pending journal is durably named before replacing the boot reader. Its
// fixed path is derived solely from the currently authenticated prior journal.
func (u *acornFoxUpgrade) preparePostCrossHelper(s *TaskAcornFoxRepoStore, oldRaw, nextRaw []byte, temp string) error {
	var previous, pending acornFoxUpgradeJournal
	if !s.ownsLock() || strictCanonicalJSON(oldRaw, &previous, "post-cross current") != nil || strictCanonicalJSON(nextRaw, &pending, "post-cross pending") != nil || validateAcornFoxPostCrossPendingPair(previous, pending, u.layout) != nil || temp != ".acornfox-post-cross-"+pending.PostCross.JournalSHA256 {
		return ErrAcornFoxUpgradeConflict
	}
	durable, err := u.read(s.root, temp, 0600, acornFoxUpgradeMaxJournal)
	if err != nil || !bytes.Equal(durable, nextRaw) {
		return ErrAcornFoxUpgradeConflict
	}
	if err := acornFoxLiveSyncDir(s.root, "."); err != nil {
		return err
	}
	oldManifest, err := u.imageManifest(s, pending, pending.Old)
	if err != nil {
		return err
	}
	nextManifest, err := u.imageManifest(s, pending, pending.Next)
	if err != nil || acornFoxUpgradeSameMigrations(oldManifest, nextManifest) != nil {
		return ErrAcornFoxUpgradeConflict
	}
	if err := u.verifyImage(s, previous, true); err != nil {
		if err := u.verifyImageWithPending(s, previous, true, &pending); err != nil {
			return err
		}
	}
	_, nextHelper, err := u.crossSchemaRecoveryHelper(s, pending)
	if err != nil {
		return err
	}
	oldSub, err := u.locateSubstrate(s, previous, previous.Next)
	if err != nil {
		return err
	}
	defer oldSub.Close()
	oldEntry := substrateEntryAt(previous.Next.Substrate.Entries, AcornFoxUpgradeHelperPath)
	if oldEntry == nil {
		return ErrAcornFoxUpgradeConflict
	}
	oldHelper, err := acornFoxLiveReadSource(oldSub.root, oldSub, *oldEntry)
	if err != nil {
		return err
	}
	// /opt is outside the managed AcornFox subtree. Refuse a cross-filesystem
	// replacement rather than exposing a partial file inside the old host scope.
	parent, err := s.hostRoot.Lstat("opt")
	if err != nil {
		return ErrAcornFoxUpgradeConflict
	}
	target, err := s.hostRoot.Lstat(acornFoxUpgradeParent(AcornFoxUpgradeHelperPath))
	if err != nil {
		return ErrAcornFoxUpgradeConflict
	}
	a, okA := parent.Sys().(*syscall.Stat_t)
	b, okB := target.Sys().(*syscall.Stat_t)
	if !okA || !okB || a.Dev != b.Dev || !acornFoxSharedParentSafe(s.hostRoot, s, "opt") {
		return ErrAcornFoxUpgradeConflict
	}
	helperTemp := "opt/.acornfox-post-cross-helper-" + pending.Next.Repo.BindingSHA256
	if err := u.atomicFileOwnedAtTemp(s, s.hostRoot, AcornFoxUpgradeHelperPath, oldHelper, nextHelper, 0755, acornFoxInstallPrincipal{}, helperTemp); err != nil {
		return err
	}
	if err := u.verifyImageWithPending(s, previous, true, &pending); err != nil {
		return err
	}
	return u.fault("post-cross-helper-published")
}

// A newly published fixed reader may start before the pending journal rename.
// Only that exact successor identity/self digest can promote the retained
// pending transaction; the old reader continues to accept the prior host.
func (u *acornFoxUpgrade) recoverPostCrossPending(ctx context.Context, s *TaskAcornFoxRepoStore, previous acornFoxUpgradeJournal, expected AcornFoxBuildIdentityV1) (acornFoxUpgradeJournal, bool, error) {
	if expected == previous.Old.identity() || expected == previous.Next.identity() {
		return previous, false, nil
	}
	path := ".acornfox-post-cross-" + sha256Hex(acornFoxUpgradeJSON(previous))
	raw, err := u.read(s.root, path, 0600, acornFoxUpgradeMaxJournal)
	if errors.Is(err, os.ErrNotExist) {
		return previous, false, nil
	}
	if err != nil {
		return previous, true, err
	}
	var pending acornFoxUpgradeJournal
	if strictCanonicalJSON(raw, &pending, "pending post-cross recovery") != nil || validateAcornFoxPostCrossPendingPair(previous, pending, u.layout) != nil || expected != pending.Next.identity() {
		return previous, true, ErrAcornFoxUpgradeConflict
	}
	manifest, err := u.imageManifest(s, pending, pending.Next)
	if err != nil || u.self.verify(pending.Next.Substrate.UpgradeHelperSHA256, manifest) != nil {
		return previous, true, ErrAcornFoxUpgradeConflict
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
	if err := u.save(s, pending, true); err != nil {
		return previous, true, err
	}
	return pending, true, nil
}
