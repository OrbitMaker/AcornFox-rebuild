package install

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var errEngineFake = errors.New("engine fake failure")

type engineLock struct{ released *int }

func (l engineLock) Release() error { *l.released++; return nil }

type engineStoreFake struct {
	events                                         *[]string
	fail                                           string
	remaining                                      int
	unknown                                        bool
	legacy                                         bool
	conflict                                       bool
	released                                       int
	created                                        []UpgradeJournalV1
	saved                                          []UpgradeJournalV1
	old                                            ActivationV1
	candidateEnv                                   []byte
	state                                          UpgradeActivationState
	markerTx                                       string
	restoreCurrent, restorePrevious, restoreDigest string
}

func (s *engineStoreFake) event(name string) error {
	*s.events = append(*s.events, name)
	if s.fail == name && s.remaining != 0 {
		if s.remaining > 0 {
			s.remaining--
		}
		if s.unknown {
			return ErrDurableCommitUnknown
		}
		return errEngineFake
	}
	return nil
}
func (s *engineStoreFake) Acquire(context.Context, string) (UpgradeLock, error) {
	if err := s.event("acquire"); err != nil {
		return nil, err
	}
	return engineLock{&s.released}, nil
}
func (s *engineStoreFake) LoadJournal(context.Context, string) (UpgradeJournalV1, error) {
	if err := s.event("load"); err != nil {
		return UpgradeJournalV1{}, err
	}
	if len(s.saved) > 0 {
		return s.saved[len(s.saved)-1], nil
	}
	if len(s.created) > 0 {
		return s.created[len(s.created)-1], nil
	}
	return UpgradeJournalV1{}, errEngineFake
}
func (s *engineStoreFake) ReadActualState(_ context.Context, oldID, candidateID string) (UpgradeActualState, error) {
	if err := s.event("actual"); err != nil {
		return UpgradeActualState{}, err
	}
	markerTx := s.markerTx
	if markerTx == "" && s.state.Marker {
		markerTx = "txn-1"
	}
	return UpgradeActualState{ActiveID: s.state.ActiveID, PreviousID: s.state.PreviousID, MarkerTransactionID: markerTx, OldActivationJSONSHA256: strings.Repeat("a", 64), CandidateActivationJSONSHA256: strings.Repeat("b", 64), PreviousActivationJSONSHA256: s.state.PreviousJSONSHA256, OldActivationExists: oldID == "activation-old", CandidateActivationExists: candidateID == "activation-new"}, nil
}
func (s *engineStoreFake) EnsureMarker(_ context.Context, tx string) error {
	if err := s.event("ensure-marker"); err != nil {
		return err
	}
	s.state.Marker = true
	return nil
}
func (s *engineStoreFake) Preflight(context.Context, string) (ActivationV1, string, bool, error) {
	if err := s.event("preflight"); err != nil {
		return ActivationV1{}, "", false, err
	}
	return s.old, strings.Repeat("a", 64), s.legacy, nil
}
func (s *engineStoreFake) ProjectLegacy(context.Context, string, ActivationV1) (string, error) {
	if err := s.event("project-legacy"); err != nil {
		return "", err
	}
	return strings.Repeat("a", 64), nil
}
func (s *engineStoreFake) ReadActivationState(context.Context) (UpgradeActivationState, error) {
	if err := s.event("read"); err != nil {
		return UpgradeActivationState{}, err
	}
	return s.state, nil
}
func (s *engineStoreFake) CreateJournal(_ context.Context, j UpgradeJournalV1) error {
	if err := s.event("create"); err != nil {
		return err
	}
	if s.conflict {
		return ErrUpgradeConflict
	}
	s.created = append(s.created, j)
	return nil
}
func (s *engineStoreFake) SaveJournal(_ context.Context, j UpgradeJournalV1) error {
	if err := s.event("save:" + string(j.State)); err != nil {
		return err
	}
	s.saved = append(s.saved, j)
	return nil
}
func (s *engineStoreFake) Marker(_ context.Context, set bool) error {
	name := "marker:on"
	if !set {
		name = "marker:off"
	}
	if err := s.event(name); err != nil {
		return err
	}
	s.state.Marker = set
	return nil
}
func (s *engineStoreFake) WriteCandidateActivation(_ context.Context, _ ActivationV1, env []byte) (string, error) {
	s.candidateEnv = append([]byte(nil), env...)
	if err := s.event("write"); err != nil {
		return "", err
	}
	return strings.Repeat("b", 64), nil
}
func (s *engineStoreFake) SetPrevious(_ context.Context, id string) error {
	if err := s.event("previous"); err != nil {
		return err
	}
	s.state.PreviousID = id
	s.state.PreviousJSONSHA256 = strings.Repeat("a", 64)
	return nil
}
func (s *engineStoreFake) RestorePrevious(_ context.Context, current, previous, digest string) error {
	if err := s.event("restore-previous"); err != nil {
		return err
	}
	s.restoreCurrent, s.restorePrevious, s.restoreDigest = current, previous, digest
	if s.state.ActiveID != current {
		return errEngineFake
	}
	s.state.PreviousID, s.state.PreviousJSONSHA256 = previous, digest
	return nil
}
func (s *engineStoreFake) SwapActive(_ context.Context, id string) error {
	if err := s.event("swap"); err != nil {
		return err
	}
	s.state.ActiveID = id
	s.state.ActiveActivationJSONSHA256 = strings.Repeat("b", 64)
	return nil
}
func (s *engineStoreFake) RestoreActive(_ context.Context, old, candidate string) error {
	if err := s.event("restore-active"); err != nil {
		return err
	}
	s.state.ActiveID = old
	s.state.ActiveActivationJSONSHA256 = strings.Repeat("a", 64)
	s.state.PreviousID = candidate
	s.state.PreviousJSONSHA256 = strings.Repeat("b", 64)
	return nil
}

type engineDBFake struct {
	events    *[]string
	fail      string
	remaining int
	unknown   bool
}

func (d *engineDBFake) event(name string) error {
	*d.events = append(*d.events, name)
	if d.fail == name && d.remaining != 0 {
		if d.remaining > 0 {
			d.remaining--
		}
		if d.unknown {
			return ErrDurableCommitUnknown
		}
		return errEngineFake
	}
	return nil
}
func (d *engineDBFake) Drain(context.Context) error { return d.event("drain") }
func (d *engineDBFake) Snapshot(context.Context) (SnapshotEvidence, string, error) {
	if err := d.event("snapshot"); err != nil {
		return SnapshotEvidence{}, "", err
	}
	return SnapshotEvidence{SHA256: strings.Repeat("c", 64), Size: 17}, "open_card", nil
}
func (d *engineDBFake) CreateRestore(context.Context, string) error { return d.event("candidate") }
func (d *engineDBFake) Migrate(context.Context) (UpgradeMigrationEvidence, error) {
	if err := d.event("migrate"); err != nil {
		return UpgradeMigrationEvidence{}, err
	}
	return UpgradeMigrationEvidence{From: "0023", To: "0024", RowsSHA256: strings.Repeat("d", 64), ReleaseManifestSHA256: strings.Repeat("f", 64)}, nil
}
func (d *engineDBFake) Validate(context.Context, string) (ArtifactV1, error) {
	if err := d.event("validate"); err != nil {
		return ArtifactV1{}, err
	}
	return ArtifactV1{Path: artifactPath("txn-1", "validation.json"), SHA256: strings.Repeat("e", 64), Size: 9}, nil
}

type engineServiceFake struct {
	events     *[]string
	fail       string
	remaining  int
	unknown    bool
	edgeActive bool
}

func (s *engineServiceFake) event(name string) error {
	*s.events = append(*s.events, name)
	if s.fail == name && s.remaining != 0 {
		if s.remaining > 0 {
			s.remaining--
		}
		if s.unknown {
			return ErrServiceOutcomeUnknown
		}
		return errEngineFake
	}
	return nil
}
func (s *engineServiceFake) Capture(context.Context) (ServiceSnapshotV1, error) {
	if err := s.event("capture"); err != nil {
		return ServiceSnapshotV1{}, err
	}
	return ServiceSnapshotV1{Edge: UnitSnapshotV1{Active: s.edgeActive, Enabled: s.edgeActive}, Agent: UnitSnapshotV1{Active: true}, Server: UnitSnapshotV1{Enabled: true}, Caddy: UnitSnapshotV1{Active: true, Enabled: true}}, nil
}
func (s *engineServiceFake) Quiesce(context.Context) error        { return s.event("quiesce") }
func (s *engineServiceFake) StartInternal(context.Context) error  { return s.event("internal:start") }
func (s *engineServiceFake) HealthInternal(context.Context) error { return s.event("internal:health") }
func (s *engineServiceFake) StartEdge(context.Context) error      { return s.event("edge:start") }
func (s *engineServiceFake) HealthEdge(context.Context) error     { return s.event("edge:health") }
func (s *engineServiceFake) GuardEdge(context.Context) error      { return s.event("edge:guard") }
func (s *engineServiceFake) RestoreSnapshot(context.Context, ServiceSnapshotV1) error {
	return s.event("restore:snapshot")
}
func (s *engineServiceFake) HealthRestoredInternal(context.Context) error {
	return s.event("restore:internal-health")
}
func (s *engineServiceFake) RestoreEdge(context.Context, ServiceSnapshotV1) error {
	return s.event("restore:edge")
}

func engineOldActivation() ActivationV1 {
	return ActivationV1{SchemaVersion: 1, ActivationID: "activation-old", Origin: "install", Release: ReleaseV1{ID: "release-old", Version: "0.8.0-rc.0", SourceCommit: strings.Repeat("a", 40), Architecture: "amd64", ManifestSHA256: strings.Repeat("b", 64)}, Database: DatabaseV1{Name: "open_card", Migration: "0023", SchemaMigrationsSHA256: strings.Repeat("c", 64)}, DatabaseEnvSHA256: strings.Repeat("d", 64), CreatedAt: time.Unix(1, 0).UTC(), CreatedByTransactionID: "old-txn"}
}
func engineRequest() UpgradeRequest {
	return UpgradeRequest{TransactionID: "txn-1", CandidateRelease: ReleaseV1{ID: "release-new", Version: "0.8.0-rc.1", SourceCommit: strings.Repeat("e", 40), Architecture: "amd64", ManifestSHA256: strings.Repeat("f", 64)}, CandidateActivationID: "activation-new", CandidateDatabaseName: "open_card_act_0123456789abcdef", CandidateDatabaseEnv: []byte("OPEN_CARD_DATABASE_URL=postgresql://user:pass@localhost:5432/open_card?sslmode=disable\n"), RequestedManifestSHA256: strings.Repeat("f", 64)}
}
func engineFixture(legacy bool) (*UpgradeEngine, *engineStoreFake, *engineDBFake, *engineServiceFake, *[]string) {
	events := []string{}
	s := &engineStoreFake{events: &events, old: engineOldActivation(), legacy: legacy, state: UpgradeActivationState{ActiveID: "activation-old", ActiveActivationJSONSHA256: strings.Repeat("a", 64)}}
	d := &engineDBFake{events: &events}
	svc := &engineServiceFake{events: &events, edgeActive: true}
	n := 1
	return &UpgradeEngine{Store: s, Database: d, Services: svc, Now: func() time.Time { n++; return time.Unix(int64(n), 0).UTC() }}, s, d, svc, &events
}
func enginePhase(t *testing.T, err error) UpgradePhaseError {
	t.Helper()
	var phase UpgradePhaseError
	if !errors.As(err, &phase) {
		t.Fatalf("expected safe phase error, got %v", err)
	}
	if !validID(phase.Code) {
		t.Fatalf("unsafe code %q", phase.Code)
	}
	return phase
}
func eventIndex(events []string, want string) int {
	for i, got := range events {
		if got == want {
			return i
		}
	}
	return -1
}

func TestAdvanceDoesNotMutateCallerWhenDurableSaveIsUnknown(t *testing.T) {
	e, store, _, _, _ := engineFixture(false)
	e.Now = func() time.Time { return time.Now().UTC().Add(time.Hour) }
	for _, tc := range []struct {
		from, to JournalState
	}{
		{JournalPreflighted, JournalQuiesced},
		{JournalEdgeArmed, JournalCommitted},
		{JournalPreflighted, JournalRecoveryRequired},
	} {
		t.Run(string(tc.to), func(t *testing.T) {
			j := journalAt(tc.from, false)
			if tc.to == JournalRecoveryRequired {
				j.Failure = &FailureV1{Code: "upgrade_failure", Phase: tc.from, MessageDigest: strings.Repeat("a", 64)}
			}
			before := j
			store.fail, store.remaining, store.unknown = "save:"+string(tc.to), 1, true
			if err := e.advance(context.Background(), &j, tc.to); !errors.Is(err, ErrDurableCommitUnknown) {
				t.Fatalf("err=%v", err)
			}
			if j.State != before.State || j.Revision != before.Revision {
				t.Fatalf("caller journal advanced: before=%s/%d after=%s/%d", before.State, before.Revision, j.State, j.Revision)
			}
			store.fail, store.remaining, store.unknown = "", 0, false
		})
	}
}

func TestAbortWithInactiveEdgeNeverHealthChecksEdge(t *testing.T) {
	e, store, _, svc, events := engineFixture(false)
	svc.edgeActive = false
	// Force an inactive-edge snapshot while failing before the switch.
	store.fail, store.remaining = "marker:on", 1
	err := e.RunNew(context.Background(), engineRequest())
	if err == nil {
		t.Fatal("expected pre-switch abort")
	}
	if eventIndex(*events, "edge:health") >= 0 {
		t.Fatalf("inactive edge was health-checked: %v", *events)
	}
}

func TestRunNewCommittedWithInactiveEdgeGuardsWithoutStartingEdge(t *testing.T) {
	e, store, _, svc, events := engineFixture(false)
	svc.edgeActive = false
	if err := e.RunNew(context.Background(), engineRequest()); err != nil {
		t.Fatal(err)
	}
	if store.state.ActiveID != "activation-new" || store.state.Marker {
		t.Fatalf("state=%+v", store.state)
	}
	if eventIndex(*events, "edge:start") >= 0 || eventIndex(*events, "edge:health") >= 0 || eventIndex(*events, "edge:guard") < 0 {
		t.Fatalf("edge convergence=%v", *events)
	}
	if len(store.saved) == 0 || store.saved[len(store.saved)-1].State != JournalCommitted {
		t.Fatalf("journal=%v", store.saved)
	}
}

func TestRecoverCommittedInactiveEdgeGuardsWithoutHealth(t *testing.T) {
	e, store, _, svc, events := engineFixture(false)
	svc.edgeActive = false
	if err := e.RunNew(context.Background(), engineRequest()); err != nil {
		t.Fatal(err)
	}
	*events = nil
	if err := e.Recover(context.Background(), "txn-1"); err != nil {
		t.Fatal(err)
	}
	if eventIndex(*events, "edge:guard") < 0 || eventIndex(*events, "edge:start") >= 0 || eventIndex(*events, "edge:health") >= 0 {
		t.Fatalf("edge convergence=%v", *events)
	}
	_ = store
}

func TestRecoverCommittedMissingMarkerActiveEdgeConvergesInOneCall(t *testing.T) {
	e, store, _, svc, events := engineFixture(false)
	if err := e.RunNew(context.Background(), engineRequest()); err != nil {
		t.Fatal(err)
	}
	store.state.Marker = false
	store.markerTx = ""
	*events = nil
	if err := e.Recover(context.Background(), "txn-1"); err != nil {
		t.Fatal(err)
	}
	if eventIndex(*events, "edge:start") < 0 || eventIndex(*events, "edge:health") < 0 {
		t.Fatalf("edge was not converged=%v", *events)
	}
	_ = svc
}

func TestCommittedPublicFailureKeepsCandidateAndGuards(t *testing.T) {
	for _, failure := range []string{"marker:off", "edge:start", "edge:health"} {
		t.Run(failure, func(t *testing.T) {
			e, store, _, svc, events := engineFixture(false)
			store.fail, store.remaining = failure, 1
			svc.fail, svc.remaining = failure, 1
			if err := e.RunNew(context.Background(), engineRequest()); err == nil {
				t.Fatal("expected public failure")
			}
			if store.state.ActiveID != "activation-new" || eventIndex(*events, "restore-active") >= 0 || eventIndex(*events, "edge:guard") < 0 || eventIndex(*events, "ensure-marker") < 0 {
				t.Fatalf("events=%v state=%+v", *events, store.state)
			}
		})
	}
}

func TestRecoveryRequiredMissingMarkerEnsuresMarkerAndGuards(t *testing.T) {
	e, store, _, _, events := engineFixture(false)
	j := journalAt(JournalPreflighted, false)
	j.Failure = &FailureV1{Code: "upgrade_failure", Phase: JournalPreflighted, MessageDigest: strings.Repeat("a", 64)}
	appendTransition(&j, JournalRecoveryRequired)
	store.saved = []UpgradeJournalV1{j}
	store.state.Marker = false
	if got := enginePhase(t, e.Recover(context.Background(), "txn-1")); got.Phase != JournalRecoveryRequired {
		t.Fatal(got)
	}
	if eventIndex(*events, "ensure-marker") < 0 || eventIndex(*events, "edge:guard") < 0 {
		t.Fatalf("events=%v", *events)
	}
}

func TestUpgradeEngineHappyJournalAndOrdering(t *testing.T) {
	e, store, _, _, events := engineFixture(false)
	if err := e.RunNew(context.Background(), engineRequest()); err != nil {
		t.Fatal(err)
	}
	if store.released != 1 || len(store.created) != 1 || len(store.saved) != 9 {
		t.Fatalf("release/create/save = %d/%d/%d", store.released, len(store.created), len(store.saved))
	}
	for _, journal := range append(store.created, store.saved...) {
		if err := journal.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if eventIndex(*events, "marker:on") > eventIndex(*events, "quiesce") || eventIndex(*events, "marker:off") < eventIndex(*events, "save:EDGE_ARMED") || eventIndex(*events, "marker:off") > eventIndex(*events, "edge:start") {
		t.Fatalf("bad marker order: %v", *events)
	}
	last := store.saved[len(store.saved)-1]
	raw, err := MarshalUpgradeJournalV1(last)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "postgresql://user:pass") || !strings.EqualFold(string(store.candidateEnv), string(engineRequest().CandidateDatabaseEnv)) {
		t.Fatal("database env leaked or was not passed")
	}
	if last.Snapshot == nil || last.Migration == nil || last.Validation == nil || last.CandidateDatabase == nil || last.CandidateActivationJSONSHA256 == "" {
		t.Fatal("zero progressive evidence")
	}
	if last.CandidateDatabase.SchemaMigrationsSHA256 != strings.Repeat("d", 64) || last.Migration.ManifestSHA256 != strings.Repeat("f", 64) || last.CandidateDatabase.SchemaMigrationsSHA256 == last.Migration.ManifestSHA256 {
		t.Fatalf("rows/manifest evidence=%+v %+v", last.CandidateDatabase, last.Migration)
	}
}

func TestRunNewRecordsInitialPreviousBaseline(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(fmt.Sprintf("present-%v", present), func(t *testing.T) {
			e, store, _, _, _ := engineFixture(false)
			if present {
				store.state.PreviousID, store.state.PreviousJSONSHA256 = "activation-before", strings.Repeat("9", 64)
			}
			if err := e.RunNew(context.Background(), engineRequest()); err != nil {
				t.Fatal(err)
			}
			j := store.created[0]
			if present != (j.PreUpgradePreviousActivationID != "") || j.PreUpgradePreviousActivationID != store.created[0].PreUpgradePreviousActivationID {
				t.Fatalf("journal baseline=%q/%q", j.PreUpgradePreviousActivationID, j.PreUpgradePreviousActivationJSONSHA256)
			}
		})
	}
}

func TestAbortedRecoveryBaselineDriftGuardsAndDoesNotAbortAgain(t *testing.T) {
	e, store, _, _, events := engineFixture(false)
	j := terminalJournal(JournalAbortedPreSwitch, JournalQuiesced, false)
	j.PreUpgradePreviousActivationID, j.PreUpgradePreviousActivationJSONSHA256 = "activation-before", strings.Repeat("9", 64)
	store.saved = []UpgradeJournalV1{j}
	store.state.ActiveID, store.state.ActiveActivationJSONSHA256 = "activation-old", strings.Repeat("a", 64)
	store.state.PreviousID, store.state.PreviousJSONSHA256, store.state.Marker = "unexpected", strings.Repeat("8", 64), true
	if got := enginePhase(t, e.Recover(context.Background(), "txn-1")); got.Code != "integrity_failed" {
		t.Fatal(got)
	}
	if eventIndex(*events, "edge:guard") < 0 || len(store.saved) != 1 {
		t.Fatalf("events=%v saved=%s", *events, store.saved[len(store.saved)-1].State)
	}
}

func TestValidatedCrashRestoresPreviousBaselineBeforeAbort(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(fmt.Sprintf("baseline-present-%v", present), func(t *testing.T) {
			e, store, _, _, events := engineFixture(false)
			e.Now = func() time.Time { return time.Now().UTC().Add(time.Hour) }
			j := journalAt(JournalValidated, false)
			j.OldActivationJSONSHA256 = strings.Repeat("a", 64)
			store.state.PreviousID, store.state.PreviousJSONSHA256 = "activation-old", strings.Repeat("a", 64)
			if present {
				j.PreUpgradePreviousActivationID, j.PreUpgradePreviousActivationJSONSHA256 = "activation-before", strings.Repeat("9", 64)
			}
			store.saved = []UpgradeJournalV1{j}
			store.state.Marker = true
			gotErr := e.Recover(context.Background(), "txn-1")
			if got := enginePhase(t, gotErr); got.Phase != JournalAbortedPreSwitch {
				t.Fatalf("%v events=%v", got, *events)
			}
			if eventIndex(*events, "restore-previous") < 0 || store.restoreCurrent != "activation-old" || store.restorePrevious != j.PreUpgradePreviousActivationID || store.restoreDigest != j.PreUpgradePreviousActivationJSONSHA256 {
				t.Fatalf("restore=%q/%q/%q events=%v", store.restoreCurrent, store.restorePrevious, store.restoreDigest, *events)
			}
		})
	}
}

func TestForeignPreviousPointerRequiresRecoveryAndNeverRestoresPrevious(t *testing.T) {
	e, store, _, _, events := engineFixture(false)
	j := journalAt(JournalValidated, false)
	store.saved = []UpgradeJournalV1{j}
	store.state.Marker = true
	store.state.PreviousID, store.state.PreviousJSONSHA256 = "foreign", strings.Repeat("8", 64)
	if got := enginePhase(t, e.Recover(context.Background(), "txn-1")); got.Phase != JournalRecoveryRequired {
		t.Fatal(got)
	}
	if eventIndex(*events, "restore-previous") >= 0 || eventIndex(*events, "edge:guard") < 0 {
		t.Fatalf("events=%v", *events)
	}
}

func TestRestorePreviousFailureRequiresRecoveryAndGuards(t *testing.T) {
	e, store, _, _, events := engineFixture(false)
	j := journalAt(JournalValidated, false)
	store.saved = []UpgradeJournalV1{j}
	store.state.Marker = true
	store.state.PreviousID, store.state.PreviousJSONSHA256 = "activation-old", strings.Repeat("a", 64)
	store.fail, store.remaining = "restore-previous", 1
	if got := enginePhase(t, e.Recover(context.Background(), "txn-1")); got.Phase != JournalRecoveryRequired {
		t.Fatal(got)
	}
	if eventIndex(*events, "edge:guard") < 0 {
		t.Fatalf("events=%v", *events)
	}
}

func TestRecoverActualStateFailureEnsuresMarkerAndGuards(t *testing.T) {
	e, store, _, _, events := engineFixture(false)
	j := journalAt(JournalValidated, false)
	store.saved = []UpgradeJournalV1{j}
	store.state.Marker = false
	store.fail, store.remaining = "actual", 1
	if got := enginePhase(t, e.Recover(context.Background(), "txn-1")); got.Phase != JournalRecoveryRequired {
		t.Fatal(got)
	}
	if eventIndex(*events, "ensure-marker") < 0 || eventIndex(*events, "edge:guard") < 0 {
		t.Fatalf("events=%v", *events)
	}
}

func TestRecoverRecoveryGuardsAfterRecoveryJournalIsPersisted(t *testing.T) {
	e, store, _, _, events := engineFixture(false)
	e.Now = func() time.Time { return time.Now().UTC().Add(time.Hour) }
	j := journalAt(JournalValidated, false)
	store.state.Marker = false
	if err := e.recoverRecovery(context.Background(), &j, "txn-1", JournalValidated, errors.New("state uncertain")); err == nil {
		t.Fatal("expected recovery-required error")
	}
	if len(store.saved) != 1 || store.saved[0].State != JournalRecoveryRequired || j.State != JournalRecoveryRequired {
		t.Fatalf("recovery journal was not persisted: saved=%v state=%s", store.saved, j.State)
	}
	if eventIndex(*events, "ensure-marker") < 0 || eventIndex(*events, "edge:guard") < 0 || eventIndex(*events, "edge:guard") <= eventIndex(*events, "save:RECOVERY_REQUIRED") {
		t.Fatalf("guard did not follow durable recovery state: %v", *events)
	}
}

func TestUpgradeEngineLegacyBranch(t *testing.T) {
	e, store, _, _, _ := engineFixture(true)
	r := engineRequest()
	r.ExpectedLegacy = true
	if err := e.RunNew(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if len(store.saved) != 10 || store.saved[0].State != JournalLegacyProjected || store.saved[5].State != JournalValidated {
		t.Fatalf("unexpected legacy journals: %#v", store.saved)
	}
}

func TestUpgradeEngineLegacySaveFailureStopsBeforeMarker(t *testing.T) {
	e, store, _, _, events := engineFixture(true)
	store.fail = "save:LEGACY_PROJECTED"
	store.remaining = 1
	r := engineRequest()
	r.ExpectedLegacy = true
	if got := enginePhase(t, e.RunNew(context.Background(), r)); got.Phase != JournalRecoveryRequired {
		t.Fatal(got)
	}
	if eventIndex(*events, "save:LEGACY_PROJECTED") < 0 || eventIndex(*events, "marker:on") < 0 {
		t.Fatalf("legacy save failure advanced: %v", *events)
	}
}

func TestUpgradeEngineFailureStopsAtBoundary(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
		phase  JournalState
	}{
		{"acquire", "acquire", JournalPreflighted}, {"preflight", "preflight", JournalPreflighted}, {"capture", "capture", JournalPreflighted}, {"create", "create", JournalPreflighted}, {"marker", "marker:on", JournalAbortedPreSwitch}, {"quiesce", "quiesce", JournalAbortedPreSwitch}, {"drain", "drain", JournalAbortedPreSwitch}, {"save-quiesced", "save:QUIESCED", JournalRecoveryRequired}, {"snapshot", "snapshot", JournalAbortedPreSwitch}, {"save-snapshot", "save:SNAPSHOT_CREATED", JournalRecoveryRequired}, {"candidate", "candidate", JournalAbortedPreSwitch}, {"save-candidate", "save:CANDIDATE_DB_READY", JournalRecoveryRequired}, {"migrate", "migrate", JournalAbortedPreSwitch}, {"save-migrated", "save:MIGRATED", JournalRecoveryRequired}, {"write", "write", JournalAbortedPreSwitch}, {"validate", "validate", JournalAbortedPreSwitch}, {"save-validated", "save:VALIDATED", JournalRecoveryRequired}, {"previous", "previous", JournalAbortedPreSwitch}, {"swap", "swap", JournalAbortedPreSwitch}, {"save-active", "save:ACTIVE_SWITCHED", JournalRecoveryRequired}, {"start-internal", "internal:start", JournalRolledBack}, {"health-internal", "internal:health", JournalRolledBack}, {"save-healthy", "save:HEALTHY", JournalRecoveryRequired}, {"save-edge", "save:EDGE_ARMED", JournalRecoveryRequired}, {"unmarker", "marker:off", JournalCommitted}, {"start-edge", "edge:start", JournalCommitted}, {"health-edge", "edge:health", JournalCommitted}, {"save-committed", "save:COMMITTED", JournalRecoveryRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, store, db, svc, events := engineFixture(false)
			store.fail, store.remaining = tc.target, 1
			db.fail, db.remaining = tc.target, 1
			svc.fail, svc.remaining = tc.target, 1
			err := e.RunNew(context.Background(), engineRequest())
			if tc.target == "acquire" {
				if !errors.Is(err, ErrUpgradeLocked) {
					t.Fatal(err)
				}
			} else if got := enginePhase(t, err); got.Phase != tc.phase {
				t.Fatalf("phase=%s want %s", got.Phase, tc.phase)
			}
			if eventIndex(*events, tc.target) < 0 {
				t.Fatalf("missing failure call %s: %v", tc.target, *events)
			}
			wantReleased := 1
			if tc.target == "acquire" {
				wantReleased = 0
			}
			if store.released != wantReleased {
				t.Fatalf("release count = %d, want %d", store.released, wantReleased)
			}
		})
	}
}

func TestUpgradeEngineConflictAndLegacyMismatchFailClosed(t *testing.T) {
	e, store, _, _, events := engineFixture(false)
	store.conflict = true
	if err := e.RunNew(context.Background(), engineRequest()); !errors.Is(err, ErrUpgradeConflict) {
		t.Fatal(err)
	}
	if eventIndex(*events, "marker:on") >= 0 {
		t.Fatal("conflict reached marker")
	}
	e, _, _, _, _ = engineFixture(true)
	if got := enginePhase(t, e.RunNew(context.Background(), engineRequest())); got.Phase != JournalPreflighted {
		t.Fatal(got)
	}
}

func TestUpgradeEngineUnknownOutcomeRequiresRecoveryAndNeverLeaksError(t *testing.T) {
	for _, target := range []string{"marker:on", "quiesce", "drain", "save:QUIESCED", "snapshot", "save:SNAPSHOT_CREATED", "candidate", "save:CANDIDATE_DB_READY", "migrate", "save:MIGRATED", "write", "validate", "save:VALIDATED", "previous", "swap", "save:ACTIVE_SWITCHED", "internal:start", "internal:health", "save:HEALTHY", "save:EDGE_ARMED", "save:COMMITTED"} {
		t.Run(target, func(t *testing.T) {
			e, store, db, svc, _ := engineFixture(false)
			store.fail, store.remaining, store.unknown = target, 1, true
			db.fail, db.remaining, db.unknown = target, 1, true
			svc.fail, svc.remaining, svc.unknown = target, 1, true
			err := e.RunNew(context.Background(), engineRequest())
			if got := enginePhase(t, err); got.Phase != JournalRecoveryRequired || strings.Contains(err.Error(), "user:pass") {
				t.Fatalf("unsafe unknown result %v", err)
			}
			if !store.state.Marker {
				t.Fatal("unknown outcome did not retain marker")
			}
			for _, journal := range append(store.created, store.saved...) {
				if err := journal.Validate(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestUpgradeEnginePointerMismatchRequiresRecovery(t *testing.T) {
	e, store, _, _, _ := engineFixture(false)
	j := journalAt(JournalQuiesced, false)
	j.OldActivationID, j.OldActivationJSONSHA256 = "activation-old", strings.Repeat("a", 64)
	store.state.ActiveID = "activation-unexpected"
	if got := enginePhase(t, e.handleFailure(context.Background(), &j, store.old, UpgradeActivationState{ActiveID: "activation-old", ActiveActivationJSONSHA256: strings.Repeat("a", 64)}, JournalQuiesced, "service_quiesce_failed", errors.New("database-password"))); got.Phase != JournalRecoveryRequired {
		t.Fatal(got)
	}
	if !store.state.Marker || j.State != JournalRecoveryRequired || j.Failure == nil || !validSHA(j.Failure.MessageDigest) {
		t.Fatal("mismatch was not durably recoverable")
	}
	raw, err := MarshalUpgradeJournalV1(j)
	if err != nil || strings.Contains(string(raw), "database-password") {
		t.Fatalf("failure leaked secret: %v %s", err, raw)
	}
}

func TestUpgradeEngineEdgeFailureAfterCommitNeverRollsBack(t *testing.T) {
	e, store, _, svc, events := engineFixture(false)
	svc.fail, svc.remaining = "edge:start", 1
	if got := enginePhase(t, e.RunNew(context.Background(), engineRequest())); got.Phase != JournalCommitted {
		t.Fatal(got)
	}
	order := []string{"save:EDGE_ARMED", "save:COMMITTED", "marker:off", "edge:start", "ensure-marker", "edge:guard"}
	last := -1
	for _, want := range order {
		next := eventIndex((*events)[last+1:], want)
		if next < 0 {
			t.Fatalf("missing %s in %v", want, *events)
		}
		last += next + 1
	}
	if !store.state.Marker || store.state.ActiveID != "activation-new" || len(store.saved) == 0 || store.saved[len(store.saved)-1].State != JournalCommitted {
		t.Fatalf("committed candidate was altered: %#v %#v", store.state, store.saved)
	}
}

func TestUpgradeEngineRecoverTerminalAndDrift(t *testing.T) {
	e, store, _, _, _ := engineFixture(false)
	if err := e.RunNew(context.Background(), engineRequest()); err != nil {
		t.Fatal(err)
	}
	if err := e.Recover(context.Background(), "txn-1"); err != nil {
		t.Fatal(err)
	}
	store.state.ActiveID = "activation-old"
	if got := enginePhase(t, e.Recover(context.Background(), "txn-1")); got.Phase != JournalCommitted || got.Code != "integrity_failed" {
		t.Fatal(got)
	}
}

func TestUpgradeEngineRecoverPreSwitchAndLostActiveSave(t *testing.T) {
	e, store, _, _, _ := engineFixture(false)
	if err := e.RunNew(context.Background(), engineRequest()); err != nil {
		t.Fatal(err)
	}
	store.saved = append([]UpgradeJournalV1(nil), store.saved[:5]...)
	store.state.ActiveID, store.state.ActiveActivationJSONSHA256, store.state.PreviousID, store.state.PreviousJSONSHA256, store.state.Marker = "activation-old", strings.Repeat("a", 64), "", "", true
	if got := enginePhase(t, e.Recover(context.Background(), "txn-1")); got.Phase != JournalAbortedPreSwitch {
		t.Fatal(got)
	}
	if store.saved[len(store.saved)-1].State != JournalAbortedPreSwitch || store.state.Marker {
		t.Fatal("pre-switch recovery did not abort safely")
	}

	e, store, _, _, _ = engineFixture(false)
	if err := e.RunNew(context.Background(), engineRequest()); err != nil {
		t.Fatal(err)
	}
	store.saved = append([]UpgradeJournalV1(nil), store.saved[:5]...)
	store.state.ActiveID, store.state.ActiveActivationJSONSHA256, store.state.PreviousID, store.state.PreviousJSONSHA256, store.state.Marker = "activation-new", strings.Repeat("b", 64), "activation-old", strings.Repeat("a", 64), true
	if got := enginePhase(t, e.Recover(context.Background(), "txn-1")); got.Phase != JournalRolledBack {
		t.Fatal(got)
	}
	if store.saved[len(store.saved)-1].State != JournalRolledBack || store.state.ActiveID != "activation-old" {
		t.Fatal("lost active save did not roll back")
	}
}

func TestUpgradeEngineRecoverCrashBoundariesAndIntegrityStops(t *testing.T) {
	for _, tc := range []struct {
		index     int
		candidate bool
		want      JournalState
	}{
		{0, false, JournalAbortedPreSwitch}, {1, false, JournalAbortedPreSwitch}, {2, false, JournalAbortedPreSwitch}, {3, false, JournalAbortedPreSwitch}, {4, true, JournalRolledBack}, {5, true, JournalRolledBack}, {6, true, JournalRolledBack}, {7, true, JournalRolledBack},
	} {
		t.Run(string(rune('0'+tc.index)), func(t *testing.T) {
			e, store, _, _, _ := engineFixture(false)
			if err := e.RunNew(context.Background(), engineRequest()); err != nil {
				t.Fatal(err)
			}
			store.saved = append([]UpgradeJournalV1(nil), store.saved[:tc.index+1]...)
			store.state.Marker = true
			if tc.candidate {
				store.state.ActiveID, store.state.ActiveActivationJSONSHA256, store.state.PreviousID, store.state.PreviousJSONSHA256 = "activation-new", strings.Repeat("b", 64), "activation-old", strings.Repeat("a", 64)
			} else {
				store.state.ActiveID, store.state.ActiveActivationJSONSHA256, store.state.PreviousID, store.state.PreviousJSONSHA256 = "activation-old", strings.Repeat("a", 64), "", ""
			}
			if got := enginePhase(t, e.Recover(context.Background(), "txn-1")); got.Phase != tc.want {
				t.Fatal(got)
			}
		})
	}
	// A foreign marker, unknown pointers, and failed restoration remain recovery-only.
	e, store, _, _, _ := engineFixture(false)
	if err := e.RunNew(context.Background(), engineRequest()); err != nil {
		t.Fatal(err)
	}
	store.saved = store.saved[:1]
	store.state.Marker = true
	store.markerTx = "other-txn"
	if got := enginePhase(t, e.Recover(context.Background(), "txn-1")); got.Phase != JournalRecoveryRequired {
		t.Fatal(got)
	}
	e2, store2, _, svc, _ := engineFixture(false)
	if err := e2.RunNew(context.Background(), engineRequest()); err != nil {
		t.Fatal(err)
	}
	store2.saved = store2.saved[:1]
	store2.state.Marker = true
	svc.fail, svc.remaining = "restore:snapshot", 1
	if got := enginePhase(t, e2.Recover(context.Background(), "txn-1")); got.Phase != JournalRecoveryRequired || !store2.state.Marker {
		t.Fatal(got)
	}
}
