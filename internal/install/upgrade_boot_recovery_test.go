package install

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type bootUnitReloaderFake struct {
	events *[]string
	fail   bool
}

func (r bootUnitReloaderFake) ReloadServerUnit(_ context.Context, digest string) error {
	*r.events = append(*r.events, "boot:unit:"+digest)
	if r.fail {
		return errEngineFake
	}
	return nil
}

func bootFixture(t *testing.T, state JournalState, candidate bool) (*UpgradeEngine, *engineStoreFake, *engineServiceFake, *[]string) {
	t.Helper()
	e, store, _, services, events := engineFixture(false)
	e.Now = func() time.Time { return time.Now().UTC().Add(time.Hour) }
	var j UpgradeJournalV1
	switch state {
	case JournalRollbackSwitched:
		j = journalAt(JournalActiveSwitched, false)
		appendTransition(&j, JournalRollbackSwitched)
		addEvidence(&j)
	case JournalAbortedPreSwitch:
		j = terminalJournal(JournalAbortedPreSwitch, JournalSnapshotCreated, false)
	case JournalRolledBack:
		j = journalAt(JournalActiveSwitched, false)
		appendTransition(&j, JournalRollbackSwitched)
		appendTransition(&j, JournalRolledBack)
		addEvidence(&j)
	default:
		j = journalAt(state, false)
	}
	j.OldActivationID, j.OldActivationJSONSHA256 = store.old.ActivationID, store.oldDigest
	j.CandidateActivationID = "activation-new"
	j.CandidateDatabaseName = engineRequest().CandidateDatabaseName
	if j.CandidateDatabase != nil {
		j.CandidateDatabase.Name = j.CandidateDatabaseName
	}
	if j.CandidateActivationJSONSHA256 != "" {
		j.CandidateActivationJSONSHA256 = strings.Repeat("b", 64)
	}
	store.saved = []UpgradeJournalV1{j}
	store.state.Marker = true
	if state == JournalRollbackSwitched || state == JournalRolledBack {
		store.state.PreviousID, store.state.PreviousJSONSHA256 = "activation-new", strings.Repeat("b", 64)
	}
	if candidate {
		store.state.ActiveID, store.state.ActiveActivationJSONSHA256 = "activation-new", strings.Repeat("b", 64)
		store.state.PreviousID, store.state.PreviousJSONSHA256 = "activation-old", store.oldDigest
	}
	return e, store, services, events
}

func TestReconcileBootStateMatrixNeverCallsServices(t *testing.T) {
	for _, tc := range []struct {
		name      string
		state     JournalState
		candidate bool
		want      JournalState
	}{
		{"committed", JournalCommitted, true, JournalCommitted},
		{"pre-switch-old", JournalSnapshotCreated, false, JournalAbortedPreSwitch},
		{"candidate", JournalActiveSwitched, true, JournalRolledBack},
		{"rollback-switched", JournalRollbackSwitched, false, JournalRolledBack},
		{"terminal-old", JournalAbortedPreSwitch, false, JournalAbortedPreSwitch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, store, _, events := bootFixture(t, tc.state, tc.candidate)
			result, err := e.ReconcilePendingBoot(context.Background(), nil)
			if err != nil || result.State != tc.want || !result.MarkerRetained || !store.state.Marker {
				t.Fatalf("result=%+v err=%v state=%+v events=%v", result, err, store.state, *events)
			}
			for _, forbidden := range []string{"capture", "quiesce", "restore:snapshot", "internal:start", "internal:health", "edge:start", "edge:health", "edge:guard", "marker:off"} {
				if eventIndex(*events, forbidden) >= 0 {
					t.Fatalf("prepare called service action %s: %v", forbidden, *events)
				}
			}
		})
	}
}

func TestReconcilePendingBootNoMarkerIsTypedNoOp(t *testing.T) {
	e, store, _, events := bootFixture(t, JournalSnapshotCreated, false)
	store.state.Marker = false
	result, err := e.ReconcilePendingBoot(context.Background(), nil)
	if err != nil || !result.Skipped || result.MarkerRetained || result.FinalizeRequired || result.TransactionID != "" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	for _, forbidden := range []string{"load", "actual", "ensure-marker", "save:", "marker:"} {
		if eventIndex(*events, forbidden) >= 0 {
			t.Fatalf("absent marker mutated or read durable recovery state: %v", *events)
		}
	}
}

func TestReconcilePendingBootRejectsUnknownMarkerBeforeJournal(t *testing.T) {
	e, store, _, events := bootFixture(t, JournalSnapshotCreated, false)
	store.bootPending = &PendingTransaction{Marker: UpgradeMarkerUnknown}
	_, err := e.ReconcilePendingBoot(context.Background(), nil)
	var phase UpgradePhaseError
	if !errors.As(err, &phase) || phase.Phase != JournalRecoveryRequired || eventIndex(*events, "load") >= 0 {
		t.Fatalf("err=%v events=%v", err, *events)
	}
}

func TestReconcileBootRejectsForeignAndUnprovableState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*engineStoreFake)
	}{
		{"foreign-marker", func(store *engineStoreFake) { store.markerTx = "foreign" }},
		{"unprovable", func(store *engineStoreFake) { store.state.ActiveID = "foreign" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, store, _, events := bootFixture(t, JournalValidated, false)
			tc.mutate(store)
			_, err := e.ReconcilePendingBoot(context.Background(), nil)
			if err == nil || strings.Contains(err.Error(), "postgres") || eventIndex(*events, "edge:guard") >= 0 {
				t.Fatalf("err=%v events=%v", err, *events)
			}
		})
	}
}

func TestReconcileBootRetriesUnknownJournalSaveByReread(t *testing.T) {
	e, store, _, _ := bootFixture(t, JournalSnapshotCreated, false)
	store.fail, store.remaining, store.unknown, store.persistBeforeFailure = "save:"+string(JournalAbortedPreSwitch), 1, true, true
	result, err := e.ReconcilePendingBoot(context.Background(), nil)
	if err != nil || result.State != JournalAbortedPreSwitch || len(store.saved) == 0 || store.saved[len(store.saved)-1].State != JournalAbortedPreSwitch {
		t.Fatalf("result=%+v err=%v journals=%+v", result, err, store.saved)
	}
}

func TestReconcileBootLegacyProjectionDoesNotCallServices(t *testing.T) {
	e, store, _, services, events := engineFixture(true)
	e.Now = func() time.Time { return time.Now().UTC().Add(time.Hour) }
	request := engineRequest()
	request.ExpectedLegacy = true
	preflight, err := store.PreflightPlan(context.Background(), UpgradePreflightRequest{TransactionID: request.TransactionID, CandidateRelease: request.CandidateRelease})
	if err != nil || preflight.Legacy == nil {
		t.Fatal(err)
	}
	database := DatabaseV1{Name: "open_card", Migration: "0023", SchemaMigrationsSHA256: preflight.Legacy.ExpectedRowsSHA256}
	old, digest, err := legacyActivation(*preflight.Legacy, database, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	j := journalAt(JournalPreflighted, true)
	j.OldActivationID, j.OldActivationJSONSHA256, j.PlannedOldActivation = old.ActivationID, digest, &old
	j.CandidateActivationID, j.CandidateDatabaseName = request.CandidateActivationID, request.CandidateDatabaseName
	j.PreUpgradePreviousActivationID, j.PreUpgradePreviousActivationJSONSHA256 = preflight.Previous.ID, preflight.Previous.JSONSHA256
	transition := preflight.Legacy.EdgeConfigTransition.Evidence
	j.EdgeConfigTransition = &transition
	store.created = []UpgradeJournalV1{j}
	store.old, store.oldDigest, store.state.Marker = old, digest, true
	result, err := e.ReconcilePendingBoot(context.Background(), bootUnitReloaderFake{events: events})
	unitReloaded := false
	for _, event := range *events {
		unitReloaded = unitReloaded || strings.HasPrefix(event, "boot:unit:")
	}
	if err != nil || result.State != JournalAbortedPreSwitch || !store.legacyFinalized || !unitReloaded {
		t.Fatalf("result=%+v err=%v finalized=%v events=%v", result, err, store.legacyFinalized, *events)
	}
	if eventIndex(*events, "ensure-marker") < 0 || eventIndex(*events, "actual") < eventIndex(*events, "legacy:read") {
		t.Fatalf("legacy boot read activation state before projection: %v", *events)
	}
	for _, forbidden := range []string{"capture", "quiesce", "restore:snapshot", "internal:start", "edge:start", "edge:guard", "marker:off"} {
		if eventIndex(*events, forbidden) >= 0 {
			t.Fatalf("legacy prepare called service action %s: %v", forbidden, *events)
		}
	}
	if raw, err := MarshalUpgradeJournalV1(store.saved[len(store.saved)-1]); err != nil || strings.Contains(string(raw), "user:pass") || strings.Contains(string(raw), "postgresql://") {
		t.Fatalf("journal leaked legacy environment: %q %v", raw, err)
	}
	_ = services
}

func TestFinalizeBootTerminalPoliciesAndPublicOrdering(t *testing.T) {
	for _, tc := range []struct {
		name      string
		state     JournalState
		candidate bool
	}{
		{"committed", JournalCommitted, true},
		{"aborted", JournalAbortedPreSwitch, false},
		{"rolled-back", JournalRolledBack, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, store, _, events := bootFixture(t, tc.state, tc.candidate)
			result, err := e.FinalizeBoot(context.Background(), "txn-1")
			if err != nil || result.State != tc.state || result.MarkerRetained || result.FinalizeRequired || store.state.Marker {
				t.Fatalf("result=%+v err=%v state=%+v events=%v", result, err, store.state, *events)
			}
			if tc.state == JournalCommitted {
				if eventIndex(*events, "internal:start") < 0 || eventIndex(*events, "internal:health") < 0 || eventIndex(*events, "marker:off") > eventIndex(*events, "edge:start") {
					t.Fatalf("committed finalization order=%v", *events)
				}
			} else if eventIndex(*events, "restore:snapshot") < 0 || eventIndex(*events, "restore:internal-health") < 0 || eventIndex(*events, "restore:legacy-internal-health") >= 0 || eventIndex(*events, "marker:off") < 0 || eventIndex(*events, "edge:health") < 0 || eventIndex(*events, "restore:edge-health") >= 0 {
				t.Fatalf("native old finalization missing current Edge health=%v", *events)
			}
		})
	}
}

func TestFinalizeBootLegacyRollbackUsesRC0CompatibleEdgeReadiness(t *testing.T) {
	e, store, _, services, events := engineFixture(true)
	services.fail, services.remaining = "internal:start", 1
	request := engineRequest()
	request.ExpectedLegacy = true
	if got := enginePhase(t, e.RunNew(context.Background(), request)); got.Phase != JournalRolledBack {
		t.Fatalf("run phase=%#v", got)
	}
	store.state.Marker, store.markerTx = true, request.TransactionID
	*events = nil
	result, err := e.FinalizeBoot(context.Background(), request.TransactionID)
	if err != nil || result.State != JournalRolledBack || result.MarkerRetained || store.state.Marker {
		t.Fatalf("result=%+v err=%v state=%+v events=%v", result, err, store.state, *events)
	}
	if eventIndex(*events, "restore:legacy-internal-health") < 0 || eventIndex(*events, "restore:internal-health") >= 0 || eventIndex(*events, "restore:edge-health") < 0 || eventIndex(*events, "edge:health") >= 0 {
		t.Fatalf("legacy rollback used a native health contract: %v", *events)
	}
}

func TestReconcileBootPersistsTypedBootRecoveredFailure(t *testing.T) {
	e, store, _, _ := bootFixture(t, JournalValidated, true)
	result, err := e.ReconcilePendingBoot(context.Background(), nil)
	if err != nil || result.State != JournalRolledBack {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	journal := store.saved[len(store.saved)-1]
	if journal.Failure == nil || journal.Failure.Code != "boot_recovered" || journal.Failure.Phase != JournalActiveSwitched {
		t.Fatalf("failure=%+v", journal.Failure)
	}
}

func TestFinalizeBootNonterminalGuardsAndRetainsMarker(t *testing.T) {
	e, store, _, events := bootFixture(t, JournalValidated, false)
	_, err := e.FinalizeBoot(context.Background(), "txn-1")
	var phase UpgradePhaseError
	if !errors.As(err, &phase) || phase.Phase != JournalRecoveryRequired || !store.state.Marker || eventIndex(*events, "edge:guard") < 0 || eventIndex(*events, "marker:off") >= 0 {
		t.Fatalf("err=%v state=%+v events=%v", err, store.state, *events)
	}
}

func TestFinalizeBootRepeatsCommittedEdgeConfigConvergenceBeforeMarkerRemoval(t *testing.T) {
	e, store, _, _, events := engineFixture(true)
	request := engineRequest()
	request.ExpectedLegacy = true
	store.fail, store.remaining = "marker:off", 1
	if err := e.RunNew(context.Background(), request); err == nil || !store.state.Marker || !store.edgeInstalledAfter {
		t.Fatalf("expected postcommit marker failure with finalized config: err=%v state=%+v", err, store.state)
	}
	store.fail, store.remaining = "", 0
	*events = nil
	result, err := e.FinalizeBoot(context.Background(), request.TransactionID)
	if err != nil || result.MarkerRetained || store.state.Marker {
		t.Fatalf("result=%+v err=%v state=%+v", result, err, store.state)
	}
	if eventIndex(*events, "edge:finalize") < 0 || eventIndex(*events, "edge:read") < 0 || eventIndex(*events, "edge:read") > eventIndex(*events, "marker:off") {
		t.Fatalf("edge config was not reread before marker removal: %v", *events)
	}
}
