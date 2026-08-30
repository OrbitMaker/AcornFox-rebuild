package install

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func statusStore(t *testing.T) (*UpgradeStore, ActivationV1, ActivationV1, UpgradeLock, func()) {
	t.Helper()
	store, _, old, candidate, _, lock, cleanup := seededPointerStore(t)
	return store, old, candidate, lock, cleanup
}

func activationDigest(t *testing.T, activation ActivationV1) string {
	t.Helper()
	digest, err := CanonicalActivationJSONSHA256(activation)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func writeStatusJournal(t *testing.T, store *UpgradeStore, journal UpgradeJournalV1) {
	t.Helper()
	if err := store.CreateJournal(context.Background(), journal); err != nil {
		t.Fatal(err)
	}
}

func statusJournal(old, candidate ActivationV1, state JournalState) UpgradeJournalV1 {
	var journal UpgradeJournalV1
	switch state {
	case JournalPreflighted:
		journal = journalFixture()
	case JournalCommitted:
		journal = journalAt(JournalCommitted, false)
	case JournalAbortedPreSwitch:
		journal = terminalJournal(JournalAbortedPreSwitch, JournalPreflighted, false)
	case JournalRolledBack:
		journal = journalAt(JournalActiveSwitched, false)
		appendTransition(&journal, JournalRollbackSwitched)
		addEvidence(&journal)
		appendTransition(&journal, JournalRolledBack)
		addEvidence(&journal)
	case JournalRecoveryRequired:
		journal = terminalJournal(JournalRecoveryRequired, JournalPreflighted, false)
	default:
		panic("unsupported status state")
	}
	journal.OldActivationID = old.ActivationID
	journal.OldActivationJSONSHA256 = mustCanonicalActivationSHA256(old)
	journal.CandidateActivationID = candidate.ActivationID
	if journal.CandidateActivationJSONSHA256 != "" {
		journal.CandidateActivationJSONSHA256 = mustCanonicalActivationSHA256(candidate)
	}
	return journal
}

func mustCanonicalActivationSHA256(activation ActivationV1) string {
	digest, _ := CanonicalActivationJSONSHA256(activation)
	return digest
}

func TestUpgradeStatusPreflightNeverTouchesHeldUpgradeLock(t *testing.T) {
	store, old, candidate, lock, cleanup := statusStore(t)
	defer cleanup()
	journal := statusJournal(old, candidate, JournalPreflighted)
	writeStatusJournal(t, store, journal)

	for range 3 {
		status, err := store.ReadUpgradeStatus(context.Background(), journal.TransactionID)
		if err != nil || status.Disposition != UpgradeStatusRecoveryRequired || !status.Recovery {
			t.Fatalf("held-lock status=%#v err=%v", status, err)
		}
	}
	secondStore, err := TaskUpgradeStore(store.root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer secondStore.Close()
	if _, err := secondStore.Acquire(context.Background(), "txn-2"); !errors.Is(err, ErrUpgradeLocked) {
		t.Fatalf("status disturbed held lock: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	status, err := store.ReadUpgradeStatus(context.Background(), journal.TransactionID)
	if err != nil || status.Disposition != UpgradeStatusRecoveryRequired || !status.Recovery {
		t.Fatalf("unlocked status=%#v err=%v", status, err)
	}
	raw, err := json.Marshal(status)
	if err != nil || strings.Contains(string(raw), "postgres") || strings.Contains(string(raw), "password") || strings.Contains(string(raw), "failure") || strings.Contains(string(raw), "database") {
		t.Fatalf("status leaked sensitive data: %#v", status)
	}
}

func TestPendingAndStatusForeignUnknownMarkerSemantics(t *testing.T) {
	store, old, candidate, lock, cleanup := statusStore(t)
	defer cleanup()
	defer lock.Release()
	journal := statusJournal(old, candidate, JournalPreflighted)
	writeStatusJournal(t, store, journal)
	if pending, err := store.PendingTransaction(context.Background()); err != nil || pending.Marker != UpgradeMarkerAbsent {
		t.Fatalf("absent pending=%#v err=%v", pending, err)
	}
	if err := store.EnsureMarker(context.Background(), journal.TransactionID); err != nil {
		t.Fatal(err)
	}
	if status, err := store.ReadUpgradeStatus(context.Background(), journal.TransactionID); err != nil || status.Marker != UpgradeMarkerSame || status.Disposition != UpgradeStatusUnknown {
		t.Fatalf("same status=%#v err=%v", status, err)
	}
	if err := store.dataWriter.RemoveMetadata(storeUpgradeInProgressPath); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureMarker(context.Background(), "txn-2"); err != nil {
		t.Fatal(err)
	}
	if status, err := store.ReadUpgradeStatus(context.Background(), journal.TransactionID); err != nil || status.Marker != UpgradeMarkerForeign || status.Disposition != UpgradeStatusRecoveryRequired {
		t.Fatalf("foreign status=%#v err=%v", status, err)
	}
	if err := store.dataWriter.WriteMetadata(storeUpgradeInProgressPath, []byte("bad\nmarker\n")); err != nil {
		t.Fatal(err)
	}
	if pending, err := store.PendingTransaction(context.Background()); err != nil || pending.Marker != UpgradeMarkerUnknown || pending.TransactionID != "" {
		t.Fatalf("unknown pending=%#v err=%v", pending, err)
	}
	if status, err := store.ReadUpgradeStatus(context.Background(), journal.TransactionID); err != nil || status.Marker != UpgradeMarkerUnknown || status.Disposition != UpgradeStatusUnknown || !status.Recovery {
		t.Fatalf("unknown status=%#v err=%v", status, err)
	}
}

func TestUpgradeStatusTerminalPointerMatrixAndStableRead(t *testing.T) {
	t.Run("only planned legacy preflight may lack active", func(t *testing.T) {
		store, _, old, candidate, _, lock, cleanup := seededPointerStore(t)
		defer cleanup()
		defer lock.Release()
		if err := store.activationWriter.ops.Remove("active"); err != nil {
			t.Fatal(err)
		}
		if err := store.activationWriter.ops.Remove("current"); err != nil {
			t.Fatal(err)
		}
		if err := store.activationWriter.ops.Symlink("releases/"+old.Release.ID, "current"); err != nil {
			t.Fatal(err)
		}
		env := engineActiveDatabaseEnv()
		planned := ActivationV1{SchemaVersion: ActivationSchemaVersion, ActivationID: "legacy-status", Origin: "rc0_compat_projection", Release: ReleaseV1{ID: old.Release.ID, Version: ProductionNMinusOneVersion, SourceCommit: RC0SourceCommit, Architecture: "amd64", ManifestSHA256: RC0ReleaseManifestSHA256}, Database: DatabaseV1{Name: "open_card", Migration: "0023", SchemaMigrationsSHA256: strings.Repeat("a", 64)}, DatabaseEnvSHA256: sha256Bytes(env), CreatedAt: time.Unix(1, 0).UTC(), CreatedByTransactionID: "txn-1", LegacyProjection: &LegacyProjectionV1{Target: legacyReleaseTarget(ReleaseV1{ID: old.Release.ID}), ServerEnvBeforeSHA256: strings.Repeat("b", 64), ServerEnvAfterSHA256: strings.Repeat("c", 64), ServerUnitBeforeSHA256: strings.Repeat("d", 64), ServerUnitAfterSHA256: strings.Repeat("e", 64), ServerUnitReleaseID: candidate.Release.ID}}
		journal := statusJournal(old, candidate, JournalPreflighted)
		journal.OldActivationID = planned.ActivationID
		journal.OldActivationJSONSHA256 = activationDigest(t, planned)
		journal.PlannedOldActivation = &planned
		transition := edgeTransitionFixture(journal.TransactionID, planned.Release.ID, "release-status-candidate")
		journal.EdgeConfigTransition = &transition
		writeStatusJournal(t, store, journal)
		status, err := store.ReadUpgradeStatus(context.Background(), journal.TransactionID)
		if err != nil || status.Disposition != UpgradeStatusRecoveryRequired || status.ActiveID != "" || !status.Recovery {
			t.Fatalf("status=%#v err=%v", status, err)
		}
	})
	t.Run("missing active is unknown", func(t *testing.T) {
		store, old, candidate, lock, cleanup := statusStore(t)
		defer cleanup()
		defer lock.Release()
		journal := statusJournal(old, candidate, JournalPreflighted)
		writeStatusJournal(t, store, journal)
		if err := store.activationWriter.ops.Remove("active"); err != nil {
			t.Fatal(err)
		}
		status, err := store.ReadUpgradeStatus(context.Background(), journal.TransactionID)
		if err != nil || status.Disposition != UpgradeStatusUnknown || !status.Recovery {
			t.Fatalf("status=%#v err=%v", status, err)
		}
	})
	t.Run("committed wrong active is recovery", func(t *testing.T) {
		store, old, candidate, lock, cleanup := statusStore(t)
		defer cleanup()
		defer lock.Release()
		journal := statusJournal(old, candidate, JournalCommitted)
		writeStatusJournal(t, store, journal)
		status, err := store.ReadUpgradeStatus(context.Background(), journal.TransactionID)
		if err != nil || status.Disposition != UpgradeStatusRecoveryRequired || !status.Recovery {
			t.Fatalf("status=%#v err=%v", status, err)
		}
	})
	t.Run("aborted coherent", func(t *testing.T) {
		store, old, candidate, lock, cleanup := statusStore(t)
		defer cleanup()
		defer lock.Release()
		if err := store.SetPrevious(context.Background(), old.ActivationID); err != nil {
			t.Fatal(err)
		}
		journal := statusJournal(old, candidate, JournalAbortedPreSwitch)
		journal.PreUpgradePreviousActivationID = old.ActivationID
		journal.PreUpgradePreviousActivationJSONSHA256 = activationDigest(t, old)
		writeStatusJournal(t, store, journal)
		status, err := store.ReadUpgradeStatus(context.Background(), journal.TransactionID)
		if err != nil || status.Disposition != UpgradeStatusTerminal || status.Recovery {
			t.Fatalf("status=%#v err=%v", status, err)
		}
	})
	t.Run("rolled back coherent", func(t *testing.T) {
		store, old, candidate, lock, cleanup := statusStore(t)
		defer cleanup()
		defer lock.Release()
		if err := store.SetPrevious(context.Background(), old.ActivationID); err != nil {
			t.Fatal(err)
		}
		if err := store.SwapActive(context.Background(), candidate.ActivationID); err != nil {
			t.Fatal(err)
		}
		if err := store.RestoreActive(context.Background(), old.ActivationID, candidate.ActivationID); err != nil {
			t.Fatal(err)
		}
		journal := statusJournal(old, candidate, JournalRolledBack)
		writeStatusJournal(t, store, journal)
		status, err := store.ReadUpgradeStatus(context.Background(), journal.TransactionID)
		if err != nil || status.Disposition != UpgradeStatusTerminal || status.Recovery {
			t.Fatalf("status=%#v err=%v", status, err)
		}
	})
	t.Run("same id metadata mutation is rejected", func(t *testing.T) {
		store, old, candidate, lock, cleanup := statusStore(t)
		defer cleanup()
		defer lock.Release()
		journal := statusJournal(old, candidate, JournalPreflighted)
		writeStatusJournal(t, store, journal)
		store.statusReadHook = func() {
			store.statusReadHook = nil
			updated := old
			updated.CreatedAt = updated.CreatedAt.Add(time.Second)
			raw, err := MarshalActivationV1(updated)
			if err == nil {
				_ = store.activationSlotWriterWriteForStatusTest(old.ActivationID, raw)
			}
		}
		if _, err := store.ReadUpgradeStatus(context.Background(), journal.TransactionID); !errors.Is(err, ErrUpgradeJournalConflict) {
			t.Fatalf("same-id mutation err=%v", err)
		}
	})
}

func (s *UpgradeStore) activationSlotWriterWriteForStatusTest(id string, raw []byte) error {
	slot, err := s.activationSlotWriter(id)
	if err != nil {
		return err
	}
	defer slot.Close()
	return slot.WriteMetadata("activation.json", raw)
}
