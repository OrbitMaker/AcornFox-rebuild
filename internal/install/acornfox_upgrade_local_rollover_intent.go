package install

import (
	"bytes"
	"errors"
	"os"
)

const acornFoxLocalIntentPrefix = ".acornfox-local-intent-"
const acornFoxLocalIntentMax = 1024

type acornFoxLocalRolloverIntent struct {
	SchemaVersion         int    `json:"schema_version"`
	PreviousJournalSHA256 string `json:"previous_journal_sha256"`
	NextBindingSHA256     string `json:"next_binding_sha256"`
	PendingJournalSHA256  string `json:"pending_journal_sha256"`
}

func acornFoxLocalIntentPaths(previousSHA string) (string, string) {
	return acornFoxLocalIntentPrefix + previousSHA, acornFoxLocalIntentPrefix + "pending-" + previousSHA
}
func acornFoxLocalIntentFor(j acornFoxUpgradeJournal) acornFoxLocalRolloverIntent {
	prepared := j
	rollover := *j.LocalRollover
	prepared.LocalRollover = &rollover
	prepared.Phase = "PREPARED"
	rollover.State = "RETAINING"
	return acornFoxLocalRolloverIntent{1, rollover.PreviousJournalSHA256, j.Next.Repo.BindingSHA256, sha256Hex(acornFoxUpgradeJSON(prepared))}
}
func (i acornFoxLocalRolloverIntent) valid(previousSHA string) bool {
	return i.SchemaVersion == 1 && i.PreviousJournalSHA256 == previousSHA && validSHA(previousSHA) && validSHA(i.NextBindingSHA256) && validSHA(i.PendingJournalSHA256)
}

// This small record is durably bound before a byte of the large journal is
// written. A torn journal can never authorize a different cached candidate.
func (u *acornFoxUpgrade) prepareLocalRolloverIntent(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal) error {
	if !s.ownsLock() || j.LocalRollover == nil || j.Phase != "PREPARED" || j.LocalRollover.State != "RETAINING" || j.validate(u.layout) != nil {
		return ErrAcornFoxUpgradeConflict
	}
	intent := acornFoxLocalIntentFor(j)
	path, temp := acornFoxLocalIntentPaths(intent.PreviousJournalSHA256)
	return u.atomicFileOwnedAtTemp(s, s.root, path, nil, acornFoxUpgradeJSON(intent), 0600, acornFoxInstallPrincipal{}, temp)
}
func (u *acornFoxUpgrade) readLocalRolloverIntent(s *TaskAcornFoxRepoStore, previousSHA string) (acornFoxLocalRolloverIntent, bool, error) {
	var result acornFoxLocalRolloverIntent
	path, temp := acornFoxLocalIntentPaths(previousSHA)
	var canonical []byte
	for _, name := range []string{path, temp} {
		raw, err := u.read(s.root, name, 0600, acornFoxLocalIntentMax)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return result, true, ErrAcornFoxUpgradeConflict
		}
		var parsed acornFoxLocalRolloverIntent
		if strictCanonicalJSON(raw, &parsed, "local rollover intent") != nil || !parsed.valid(previousSHA) || canonical != nil && !bytes.Equal(canonical, raw) {
			return result, true, ErrAcornFoxUpgradeConflict
		}
		canonical = raw
		result = parsed
	}
	return result, canonical != nil, nil
}
func (u *acornFoxUpgrade) verifyLocalRolloverIntent(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal) error {
	if j.LocalRollover == nil {
		return ErrAcornFoxUpgradeConflict
	}
	expected := acornFoxUpgradeJSON(acornFoxLocalIntentFor(j))
	path, temp := acornFoxLocalIntentPaths(j.LocalRollover.PreviousJournalSHA256)
	present := false
	for _, name := range []string{path, temp} {
		raw, err := u.read(s.root, name, 0600, acornFoxLocalIntentMax)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !bytes.Equal(raw, expected) {
			return ErrAcornFoxUpgradeConflict
		}
		present = true
	}
	// Once the main journal is committed its own authenticated envelope carries
	// the identity, even in PREPARED. Prove that complete durable authority here;
	// a draft/partial candidate may never use absence as permission to proceed.
	if !present {
		raw, err := u.read(s.root, acornFoxUpgradeJournalPath, 0600, acornFoxUpgradeMaxJournal)
		if err != nil || j.validate(u.layout) != nil || !bytes.Equal(raw, acornFoxUpgradeJSON(j)) {
			return ErrAcornFoxUpgradeConflict
		}
	}
	return nil
}
func (u *acornFoxUpgrade) clearLocalRolloverIntent(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal) error {
	if !s.ownsLock() {
		return ErrAcornFoxUpgradeConflict
	}
	if err := u.verifyLocalRolloverIntent(s, j); err != nil {
		return err
	}
	path, temp := acornFoxLocalIntentPaths(j.LocalRollover.PreviousJournalSHA256)
	expected := acornFoxUpgradeJSON(acornFoxLocalIntentFor(j))
	for _, name := range []string{temp, path} {
		raw, err := u.read(s.root, name, 0600, acornFoxLocalIntentMax)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !bytes.Equal(raw, expected) {
			return ErrAcornFoxUpgradeConflict
		}
		if err := s.root.Remove(name); err != nil {
			return err
		}
		if err := acornFoxLiveSyncDir(s.root, "."); err != nil {
			return err
		}
	}
	return u.fault("local-intent-cleared")
}
