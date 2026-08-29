package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var errEngineFake = errors.New("engine fake failure")

type engineLock struct {
	released *int
	err      error
}

func (l engineLock) Release() error { *l.released++; return l.err }

type engineStoreFake struct {
	events                                         *[]string
	fail                                           string
	remaining                                      int
	unknown                                        bool
	persistBeforeFailure                           bool
	legacy                                         bool
	conflict                                       bool
	released                                       int
	releaseErr                                     error
	created                                        []UpgradeJournalV1
	saved                                          []UpgradeJournalV1
	old                                            ActivationV1
	oldDigest                                      string
	legacyPlan                                     *LegacyProjectionPlan
	legacyActivation                               ActivationV1
	legacyDigest                                   string
	writtenCandidate                               ActivationV1
	legacyFinalized                                bool
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
	return engineLock{released: &s.released, err: s.releaseErr}, nil
}
func (s *engineStoreFake) LoadJournal(context.Context, string) (UpgradeJournalV1, error) {
	if err := s.event("load"); err != nil {
		return UpgradeJournalV1{}, err
	}
	var journal UpgradeJournalV1
	if len(s.saved) > 0 {
		journal = s.saved[len(s.saved)-1]
	} else if len(s.created) > 0 {
		journal = s.created[len(s.created)-1]
	} else {
		return UpgradeJournalV1{}, errEngineFake
	}
	// Old fixture journals predate strict canonical activation digests. Keep
	// their state-machine coverage while presenting the concrete activation
	// identity the typed preflight now requires.
	if journal.OldActivationJSONSHA256 == strings.Repeat("a", 64) && s.oldDigest != "" {
		journal.OldActivationJSONSHA256 = s.oldDigest
	}
	return journal, nil
}
func (s *engineStoreFake) ReadActualState(_ context.Context, oldID, candidateID string) (UpgradeActualState, error) {
	if err := s.event("actual"); err != nil {
		return UpgradeActualState{}, err
	}
	markerTx := s.markerTx
	if markerTx == "" && s.state.Marker {
		markerTx = "txn-1"
	}
	oldDigest := s.oldDigest
	if oldDigest == "" {
		oldDigest = strings.Repeat("a", 64)
	}
	previousDigest := s.state.PreviousJSONSHA256
	if s.state.PreviousID == s.old.ActivationID && previousDigest == strings.Repeat("a", 64) {
		previousDigest = oldDigest
	}
	return UpgradeActualState{ActiveID: s.state.ActiveID, PreviousID: s.state.PreviousID, MarkerTransactionID: markerTx, OldActivationJSONSHA256: oldDigest, CandidateActivationJSONSHA256: strings.Repeat("b", 64), PreviousActivationJSONSHA256: previousDigest, OldActivationExists: oldID == s.old.ActivationID || oldID == s.legacyActivation.ActivationID, CandidateActivationExists: candidateID == "activation-new"}, nil
}
func (s *engineStoreFake) EnsureMarker(_ context.Context, tx string) error {
	if err := s.event("ensure-marker"); err != nil {
		return err
	}
	s.state.Marker = true
	return nil
}
func (s *engineStoreFake) PreflightPlan(_ context.Context, request UpgradePreflightRequest) (UpgradePreflight, error) {
	if err := s.event("preflight"); err != nil {
		return UpgradePreflight{}, err
	}
	if !s.legacy {
		return UpgradePreflight{Existing: &ExistingActivationPreflight{Activation: s.old, JSONSHA256: s.oldDigest, DatabaseEnv: engineActiveDatabaseEnv()}, Previous: ActivationPointerIdentity{ID: s.state.PreviousID, JSONSHA256: s.state.PreviousJSONSHA256}}, nil
	}
	plan := &LegacyProjectionPlan{
		TransactionID: request.TransactionID, ActivationID: "legacy-0123456789abcdef012345", Release: ReleaseV1{ID: "release-rc0", Version: ProductionNMinusOneVersion, SourceCommit: RC0SourceCommit, Architecture: "amd64", ManifestSHA256: RC0ReleaseManifestSHA256}, CurrentTarget: "/opt/open-card/releases/release-rc0", ExpectedMigration: "0023", ExpectedRowsSHA256: strings.Repeat("c", 64), DatabaseEnv: []byte("OPEN_CARD_DATABASE_URL=postgresql://user:pass@localhost:5432/open_card?sslmode=disable\n"), ServerEnvBeforeSHA256: strings.Repeat("1", 64), ServerEnvAfterSHA256: strings.Repeat("2", 64), ServerUnitBeforeSHA256: strings.Repeat("3", 64), ServerUnitAfterSHA256: strings.Repeat("4", 64), ServerUnitReleaseID: request.CandidateRelease.ID,
	}
	plan.Previous = ActivationPointerIdentity{ID: s.state.PreviousID, JSONSHA256: s.state.PreviousJSONSHA256}
	plan.DatabaseEnvSHA256 = sha256Bytes(plan.DatabaseEnv)
	s.legacyPlan = plan
	return UpgradePreflight{Legacy: plan, Previous: plan.Previous}, nil
}
func (s *engineStoreFake) PrepareLegacyProjection(_ context.Context, plan LegacyProjectionPlan, activation ActivationV1) (LegacyProjectionObservation, error) {
	if err := s.event("legacy:prepare"); err != nil {
		return LegacyProjectionObservation{}, err
	}
	s.legacyPlan = &plan
	s.legacyActivation = activation
	digest, err := CanonicalActivationJSONSHA256(activation)
	if err != nil {
		return LegacyProjectionObservation{}, err
	}
	s.legacyDigest = digest
	s.oldDigest = digest
	s.state.ActiveID, s.state.ActiveActivationJSONSHA256 = activation.ActivationID, digest
	return expectedLegacyObservation(plan, activation, digest), nil
}
func (s *engineStoreFake) FinalizeLegacyProjection(_ context.Context, plan LegacyProjectionPlan, activation ActivationV1) (LegacyProjectionObservation, error) {
	if err := s.event("legacy:finalize"); err != nil {
		return LegacyProjectionObservation{}, err
	}
	s.legacyFinalized = true
	return expectedLegacyObservation(plan, activation, s.legacyDigest), nil
}
func (s *engineStoreFake) ReadLegacyProjection(_ context.Context, plan LegacyProjectionPlan, activation ActivationV1) (LegacyProjectionObservation, error) {
	if err := s.event("legacy:read"); err != nil {
		return LegacyProjectionObservation{}, err
	}
	return expectedLegacyObservation(plan, activation, s.legacyDigest), nil
}
func (s *engineStoreFake) RecoverLegacyPlan(_ context.Context, old ActivationV1, _ string) (LegacyProjectionPlan, error) {
	if err := s.event("legacy:recover-plan"); err != nil {
		return LegacyProjectionPlan{}, err
	}
	if s.legacyPlan == nil || old.ActivationID != s.legacyPlan.ActivationID {
		return LegacyProjectionPlan{}, errEngineFake
	}
	plan := *s.legacyPlan
	plan.Previous = ActivationPointerIdentity{ID: s.state.PreviousID, JSONSHA256: s.state.PreviousJSONSHA256}
	return plan, nil
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
	if s.fail == "save:"+string(j.State) && s.remaining != 0 && s.persistBeforeFailure {
		s.saved = append(s.saved, j)
		return s.event("save:" + string(j.State))
	}
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
func (s *engineStoreFake) WriteCandidateActivation(_ context.Context, candidate ActivationV1, env []byte) (string, error) {
	s.writtenCandidate = candidate
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
	s.state.PreviousJSONSHA256 = s.oldDigest
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
	s.state.ActiveActivationJSONSHA256 = s.oldDigest
	s.state.PreviousID = candidate
	s.state.PreviousJSONSHA256 = strings.Repeat("b", 64)
	return nil
}

type engineDBFake struct {
	events          *[]string
	fail            string
	remaining       int
	unknown         bool
	inspectCalls    int
	inspectDrift    bool
	inspectMismatch bool
	candidateEnv    []byte
	snapshotSource  string
	closed          int
	closeErr        error
}

func (d *engineDBFake) InspectActive(_ context.Context, request ActiveDatabaseInspectionRequest) (DatabaseV1, error) {
	if err := d.event("inspect-active"); err != nil {
		return DatabaseV1{}, err
	}
	d.inspectCalls++
	if d.inspectMismatch {
		return DatabaseV1{Name: "open_card_other", Migration: request.ExpectedMigration, SchemaMigrationsSHA256: request.ExpectedRowsSHA256}, nil
	}
	if d.inspectDrift && d.inspectCalls > 1 {
		return DatabaseV1{Name: "open_card", Migration: request.ExpectedMigration, SchemaMigrationsSHA256: strings.Repeat("9", 64)}, nil
	}
	return DatabaseV1{Name: "open_card", Migration: request.ExpectedMigration, SchemaMigrationsSHA256: request.ExpectedRowsSHA256}, nil
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
	source := d.snapshotSource
	if source == "" {
		source = "open_card"
	}
	return SnapshotEvidence{SHA256: strings.Repeat("c", 64), Size: 17}, source, nil
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

func (d *engineDBFake) CandidateDatabaseEnv() []byte { return append([]byte(nil), d.candidateEnv...) }
func (d *engineDBFake) Close() error                 { d.closed++; return d.closeErr }

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
func (s *engineServiceFake) ReloadServerUnit(context.Context, string) error {
	return s.event("unit:reload")
}
func (s *engineServiceFake) RestoreSnapshot(context.Context, ServiceSnapshotV1) error {
	return s.event("restore:snapshot")
}
func (s *engineServiceFake) HealthRestoredInternal(context.Context) error {
	return s.event("restore:internal-health")
}
func (s *engineServiceFake) RestoreEdge(context.Context, ServiceSnapshotV1) error {
	return s.event("restore:edge")
}

func engineActiveDatabaseEnv() []byte {
	return []byte("OPEN_CARD_DATABASE_URL=postgresql://user:pass@localhost:5432/open_card?sslmode=disable\n")
}

func engineOldActivation() ActivationV1 {
	return ActivationV1{SchemaVersion: 1, ActivationID: "activation-old", Origin: "native", Release: ReleaseV1{ID: "release-old", Version: "0.8.0-rc.0", SourceCommit: strings.Repeat("a", 40), Architecture: "amd64", ManifestSHA256: strings.Repeat("b", 64)}, Database: DatabaseV1{Name: "open_card", Migration: "0023", SchemaMigrationsSHA256: strings.Repeat("c", 64)}, DatabaseEnvSHA256: sha256Bytes(engineActiveDatabaseEnv()), CreatedAt: time.Unix(1, 0).UTC(), CreatedByTransactionID: "old-txn"}
}
func engineRequest() UpgradeRequest {
	name, err := CandidateDatabaseName("activation-new")
	if err != nil {
		panic(err)
	}
	return UpgradeRequest{TransactionID: "txn-1", CandidateRelease: ReleaseV1{ID: "release-new", Version: "0.8.0-rc.1", SourceCommit: strings.Repeat("e", 40), Architecture: "amd64", ManifestSHA256: strings.Repeat("f", 64)}, CandidateActivationID: "activation-new", CandidateDatabaseName: name, RequestedManifestSHA256: strings.Repeat("f", 64)}
}
func engineFixture(legacy bool) (*UpgradeEngine, *engineStoreFake, *engineDBFake, *engineServiceFake, *[]string) {
	events := []string{}
	old := engineOldActivation()
	oldDigest, err := CanonicalActivationJSONSHA256(old)
	if err != nil {
		panic(err)
	}
	state := UpgradeActivationState{ActiveID: old.ActivationID, ActiveActivationJSONSHA256: oldDigest}
	if legacy {
		state = UpgradeActivationState{}
	}
	s := &engineStoreFake{events: &events, old: old, oldDigest: oldDigest, legacy: legacy, state: state}
	d := &engineDBFake{events: &events}
	candidateEnv, err := CandidateDatabaseEnv(engineActiveDatabaseEnv(), engineRequest().CandidateDatabaseName)
	if err != nil {
		panic(err)
	}
	d.candidateEnv = candidateEnv
	factory := UpgradeDatabaseOpenFunc(func(_ context.Context, request UpgradeDatabaseOpenRequest) (UpgradeDatabaseSession, error) {
		if request.Validate() != nil {
			return nil, errEngineFake
		}
		return d, nil
	})
	svc := &engineServiceFake{events: &events, edgeActive: true}
	n := 1
	return &UpgradeEngine{Store: s, DatabaseFactory: factory, Services: svc, Now: func() time.Time { n++; return time.Unix(int64(n), 0).UTC() }}, s, d, svc, &events
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

func TestUpgradeEnginePreflightIsLockedReadOnlyAndRedacted(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "native", true: "legacy"}[legacy], func(t *testing.T) {
			e, store, database, _, events := engineFixture(legacy)
			request := engineRequest()
			request.ExpectedLegacy = legacy
			eligibility, err := e.Preflight(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if eligibility.Layout != map[bool]string{false: "native", true: "rc0_compat_projection"}[legacy] || eligibility.TransactionID != request.TransactionID || eligibility.CandidateReleaseID != request.CandidateRelease.ID || eligibility.CandidateReleaseManifestSHA256 != request.RequestedManifestSHA256 || eligibility.CandidateActivationID != request.CandidateActivationID || eligibility.OldActivationID == "" || !validSHA(eligibility.OldEligibilitySHA256) || !legacy && eligibility.OldEligibilitySHA256 != eligibility.OldActivationJSONSHA256 || legacy && eligibility.OldActivationJSONSHA256 != "" {
				t.Fatalf("eligibility=%#v", eligibility)
			}
			if len(store.created) != 0 || len(store.saved) != 0 || store.state.Marker || store.writtenCandidate.ActivationID != "" || database.closed != 1 || store.released != 1 {
				t.Fatalf("preflight mutated state: journals=%d/%d marker=%v candidate=%q closed=%d released=%d events=%v", len(store.created), len(store.saved), store.state.Marker, store.writtenCandidate.ActivationID, database.closed, store.released, *events)
			}
			for _, forbidden := range []string{"capture", "marker:on", "quiesce", "drain", "snapshot", "candidate", "migrate", "validate", "previous", "swap", "start-internal"} {
				if eventIndex(*events, forbidden) >= 0 {
					t.Fatalf("preflight invoked %s: %v", forbidden, *events)
				}
			}
			raw, marshalErr := json.Marshal(eligibility)
			if marshalErr != nil || strings.Contains(string(raw), "postgres") || strings.Contains(string(raw), "user:pass") {
				t.Fatalf("eligibility leaked a DSN: %q", raw)
			}
		})
	}
}

func TestUpgradeEngineLegacyPreflightEligibilityIsTimeIndependent(t *testing.T) {
	e, _, _, _, _ := engineFixture(true)
	request := engineRequest()
	request.ExpectedLegacy = true
	first, err := e.Preflight(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.Preflight(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.OldActivationID != second.OldActivationID || first.OldEligibilitySHA256 != second.OldEligibilitySHA256 || first.OldActivationJSONSHA256 != "" || second.OldActivationJSONSHA256 != "" {
		t.Fatalf("legacy eligibility drifted: first=%#v second=%#v", first, second)
	}
}

func TestUpgradeEnginePreflightCloseFailureIsSanitized(t *testing.T) {
	e, store, database, service, _ := engineFixture(false)
	database.closeErr = errors.New("postgresql://user:password@localhost/open_card")
	_, err := e.Preflight(context.Background(), engineRequest())
	phase := enginePhase(t, err)
	if phase.Phase != JournalPreflighted || phase.Code != "preflight_database_close_failed" || strings.Contains(err.Error(), "postgres") || len(store.created) != 0 || len(store.saved) != 0 || store.state.Marker || store.released != 1 {
		t.Fatalf("close error=%v phase=%#v events=%v", err, phase, *service.events)
	}
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

func TestUpgradeEngineObservesLockReleaseFailuresWithoutReplacingPrimaryErrors(t *testing.T) {
	e, store, _, svc, _ := engineFixture(false)
	store.releaseErr = errors.New("release secret")
	phase := enginePhase(t, e.RunNew(context.Background(), engineRequest()))
	if phase.Phase != JournalCommitted || phase.Code != "lock_release_failed" || strings.Contains(phase.Error(), "secret") || store.released != 1 {
		t.Fatalf("run release error=%#v released=%d", phase, store.released)
	}

	e, store, _, svc, _ = engineFixture(false)
	store.releaseErr = errors.New("release secret")
	svc.fail, svc.remaining = "capture", 1
	phase = enginePhase(t, e.RunNew(context.Background(), engineRequest()))
	if phase.Code != "service_capture_failed" || store.released != 1 {
		t.Fatalf("primary error replaced=%#v released=%d", phase, store.released)
	}

	e, store, _, _, _ = engineFixture(false)
	if err := e.RunNew(context.Background(), engineRequest()); err != nil {
		t.Fatal(err)
	}
	store.releaseErr = errors.New("release secret")
	phase = enginePhase(t, e.Recover(context.Background(), "txn-1"))
	if phase.Phase != JournalRecoveryRequired || phase.Code != "lock_release_failed" || store.released != 2 {
		t.Fatalf("recover release error=%#v released=%d", phase, store.released)
	}

	e, store, _, _, _ = engineFixture(false)
	store.releaseErr = errors.New("release secret")
	store.fail, store.remaining = "load", 1
	phase = enginePhase(t, e.Recover(context.Background(), "txn-1"))
	if phase.Code != "integrity_failed" || store.released != 1 {
		t.Fatalf("recover primary error replaced=%#v released=%d", phase, store.released)
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
	e, store, database, _, events := engineFixture(false)
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
	if strings.Contains(string(raw), "postgresql://user:pass") || !strings.EqualFold(string(store.candidateEnv), string(database.CandidateDatabaseEnv())) {
		t.Fatal("database env leaked or was not passed")
	}
	if last.Snapshot == nil || last.Migration == nil || last.Validation == nil || last.CandidateDatabase == nil || last.CandidateActivationJSONSHA256 == "" {
		t.Fatal("zero progressive evidence")
	}
	if last.CandidateDatabase.SchemaMigrationsSHA256 != strings.Repeat("d", 64) || last.Migration.ManifestSHA256 != strings.Repeat("f", 64) || last.CandidateDatabase.SchemaMigrationsSHA256 == last.Migration.ManifestSHA256 {
		t.Fatalf("rows/manifest evidence=%+v %+v", last.CandidateDatabase, last.Migration)
	}
}

func TestUpgradeEngineFactoryPrecedesJournalAndSessionAlwaysCloses(t *testing.T) {
	e, store, database, _, events := engineFixture(false)
	e.DatabaseFactory = UpgradeDatabaseOpenFunc(func(_ context.Context, request UpgradeDatabaseOpenRequest) (UpgradeDatabaseSession, error) {
		*events = append(*events, "factory:open")
		if request.Validate() != nil {
			return nil, errEngineFake
		}
		return database, nil
	})
	if err := e.RunNew(context.Background(), engineRequest()); err != nil {
		t.Fatal(err)
	}
	open, inspect, create := eventIndex(*events, "factory:open"), eventIndex(*events, "inspect-active"), eventIndex(*events, "create")
	secondInspect := -1
	for i, event := range *events {
		if event == "inspect-active" && i > inspect {
			secondInspect = i
			break
		}
	}
	drain, snapshot := eventIndex(*events, "drain"), eventIndex(*events, "snapshot")
	if open < 0 || inspect < open || create < inspect || drain < create || secondInspect < drain || snapshot < secondInspect || database.closed != 1 {
		t.Fatalf("events=%v closes=%d", *events, database.closed)
	}
	if len(store.created) != 1 {
		t.Fatalf("journal was not created: %#v", store.created)
	}
}

func TestUpgradeEngineNativeInspectionMismatchCreatesNoJournalAndCloses(t *testing.T) {
	e, store, database, _, _ := engineFixture(false)
	database.inspectMismatch = true
	if got := enginePhase(t, e.RunNew(context.Background(), engineRequest())); got.Code != "preflight_failed" {
		t.Fatal(got)
	}
	if len(store.created) != 0 || database.closed != 1 {
		t.Fatalf("created=%#v closes=%d", store.created, database.closed)
	}
}

func TestUpgradeEngineFactoryFailureCreatesNoJournal(t *testing.T) {
	e, store, _, _, _ := engineFixture(false)
	e.DatabaseFactory = UpgradeDatabaseOpenFunc(func(context.Context, UpgradeDatabaseOpenRequest) (UpgradeDatabaseSession, error) {
		return nil, errEngineFake
	})
	if got := enginePhase(t, e.RunNew(context.Background(), engineRequest())); got.Code != "database_open_failed" {
		t.Fatal(got)
	}
	if len(store.created) != 0 {
		t.Fatalf("journal was created: %#v", store.created)
	}
}

func TestUpgradeEngineClosesSessionAfterPostJournalFailure(t *testing.T) {
	e, _, database, _, _ := engineFixture(false)
	database.fail, database.remaining = "snapshot", 1
	if err := e.RunNew(context.Background(), engineRequest()); err == nil {
		t.Fatal("expected snapshot failure")
	}
	if database.closed != 1 {
		t.Fatalf("database session closes=%d", database.closed)
	}
}

func TestUpgradeEngineCloseFailureDoesNotHidePriorFailure(t *testing.T) {
	e, _, database, _, _ := engineFixture(false)
	database.closeErr = errEngineFake
	if got := enginePhase(t, e.RunNew(context.Background(), engineRequest())); got.Code != "database_close_failed" || got.Phase != JournalCommitted {
		t.Fatal(got)
	}
	e, _, database, _, _ = engineFixture(false)
	database.fail, database.remaining, database.closeErr = "snapshot", 1, errEngineFake
	if got := enginePhase(t, e.RunNew(context.Background(), engineRequest())); got.Code != "snapshot_failed" {
		t.Fatal(got)
	}
}

func TestUpgradeEngineRejectsSessionCandidateEnvironmentOutsideCandidateDatabase(t *testing.T) {
	e, store, database, _, events := engineFixture(false)
	database.candidateEnv = engineActiveDatabaseEnv()
	if err := e.RunNew(context.Background(), engineRequest()); err == nil {
		t.Fatal("expected invalid candidate environment")
	}
	if store.writtenCandidate.ActivationID != "" || eventIndex(*events, "write") >= 0 {
		t.Fatalf("candidate activation was written: %#v events=%v", store.writtenCandidate, *events)
	}
}

func TestUpgradeEngineNativeSecondInspectionDriftBlocksSnapshot(t *testing.T) {
	e, _, database, _, events := engineFixture(false)
	database.inspectDrift = true
	if got := enginePhase(t, e.RunNew(context.Background(), engineRequest())); got.Phase != JournalRecoveryRequired {
		t.Fatal(got)
	}
	if database.inspectCalls != 2 || eventIndex(*events, "snapshot") >= 0 {
		t.Fatalf("inspects=%d events=%v", database.inspectCalls, *events)
	}
}

func TestUpgradeEngineRejectsForeignSnapshotSourceBeforeSnapshotJournal(t *testing.T) {
	e, store, database, _, events := engineFixture(false)
	database.snapshotSource = "open_card_foreign"
	if err := e.RunNew(context.Background(), engineRequest()); err == nil {
		t.Fatal("expected source mismatch")
	}
	for _, forbidden := range []string{"save:SNAPSHOT_CREATED", "candidate", "migrate", "write", "validate"} {
		if eventIndex(*events, forbidden) >= 0 {
			t.Fatalf("foreign snapshot source reached %s: %v", forbidden, *events)
		}
	}
	for _, journal := range store.saved {
		if journal.State == JournalSnapshotCreated || journal.Snapshot != nil {
			t.Fatalf("snapshot evidence was journaled: %#v", journal)
		}
	}
}

func TestRecoverNonLegacyTerminalDoesNotOpenDatabase(t *testing.T) {
	e, store, _, _, _ := engineFixture(false)
	if err := e.RunNew(context.Background(), engineRequest()); err != nil {
		t.Fatal(err)
	}
	opened := 0
	e.DatabaseFactory = UpgradeDatabaseOpenFunc(func(context.Context, UpgradeDatabaseOpenRequest) (UpgradeDatabaseSession, error) {
		opened++
		return nil, errEngineFake
	})
	if err := e.Recover(context.Background(), "txn-1"); err != nil {
		t.Fatal(err)
	}
	if opened != 0 || len(store.saved) == 0 || store.saved[len(store.saved)-1].State != JournalCommitted {
		t.Fatalf("opens=%d journal=%#v", opened, store.saved)
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
	e, store, database, _, events := engineFixture(true)
	r := engineRequest()
	r.ExpectedLegacy = true
	if err := e.RunNew(context.Background(), r); err != nil {
		t.Fatalf("%v events=%v", err, *events)
	}
	if len(store.saved) != 10 || store.saved[0].State != JournalLegacyProjected || store.saved[5].State != JournalValidated {
		t.Fatalf("unexpected legacy journals: %#v", store.saved)
	}
	if store.writtenCandidate.Origin != "native" || store.writtenCandidate.LegacyProjection != nil {
		t.Fatalf("candidate was not native: %#v", store.writtenCandidate)
	}
	want := []string{"acquire", "preflight", "inspect-active", "capture", "create", "marker:on", "quiesce", "drain", "inspect-active", "legacy:prepare", "unit:reload", "legacy:finalize", "legacy:read", "save:LEGACY_PROJECTED", "save:QUIESCED"}
	for i, event := range want {
		if i >= len(*events) || (*events)[i] != event {
			t.Fatalf("legacy order at %d = %v, want prefix %v", i, *events, want)
		}
	}
	if raw, err := MarshalUpgradeJournalV1(store.created[0]); err != nil || strings.Contains(string(raw), "user:pass") || strings.Contains(string(raw), "postgresql://") {
		t.Fatalf("planned legacy journal leaked database env: %v %s", err, raw)
	}
	if database.closed != 1 {
		t.Fatalf("legacy session closes=%d", database.closed)
	}
}

func TestUpgradeEngineLegacyInspectionDriftRequiresRecoveryBeforeProjection(t *testing.T) {
	e, store, db, _, events := engineFixture(true)
	db.inspectDrift = true
	r := engineRequest()
	r.ExpectedLegacy = true
	if got := enginePhase(t, e.RunNew(context.Background(), r)); got.Phase != JournalRecoveryRequired {
		t.Fatal(got)
	}
	if db.inspectCalls != 2 || eventIndex(*events, "legacy:prepare") >= 0 || !store.state.Marker {
		t.Fatalf("drift reached projection or lost marker: calls=%d events=%v marker=%v", db.inspectCalls, *events, store.state.Marker)
	}
}

func TestUpgradeEngineLegacyReloadFailureRetainsPreFinalizeRecoveryState(t *testing.T) {
	e, store, _, svc, events := engineFixture(true)
	svc.fail, svc.remaining = "unit:reload", 1
	r := engineRequest()
	r.ExpectedLegacy = true
	if got := enginePhase(t, e.RunNew(context.Background(), r)); got.Phase != JournalPreflighted {
		t.Fatal(got)
	}
	if !store.state.Marker || store.legacyFinalized || eventIndex(*events, "legacy:finalize") >= 0 {
		t.Fatalf("reload failure finalized legacy environment: marker=%v finalized=%v events=%v", store.state.Marker, store.legacyFinalized, *events)
	}
}

func TestRecoverLegacyPreflightProjectsThenAbortsWithoutCandidate(t *testing.T) {
	e, store, database, _, events := engineFixture(true)
	// Fail just before the first projection mutation, then simulate a restart
	// with the durable PREFLIGHTED journal as the only authority.
	store.fail, store.remaining = "legacy:prepare", 1
	r := engineRequest()
	r.ExpectedLegacy = true
	if err := e.RunNew(context.Background(), r); err == nil {
		t.Fatal("expected injected legacy prepare failure")
	}
	if len(store.created) != 1 || store.created[0].PlannedOldActivation == nil {
		t.Fatalf("missing planned legacy journal: %#v", store.created)
	}
	store.fail, store.remaining = "", 0
	store.saved = []UpgradeJournalV1{store.created[0]}
	store.state = UpgradeActivationState{Marker: true}
	database.closeErr = errEngineFake
	if got := enginePhase(t, e.Recover(context.Background(), "txn-1")); got.Phase != JournalAbortedPreSwitch {
		t.Fatalf("%v events=%v", got, *events)
	}
	if store.writtenCandidate.ActivationID != "" || store.state.ActiveID != store.created[0].OldActivationID || store.state.Marker {
		t.Fatalf("legacy recovery continued candidate work: candidate=%q state=%#v", store.writtenCandidate.ActivationID, store.state)
	}
	if len(store.saved) == 0 || store.saved[len(store.saved)-1].State != JournalAbortedPreSwitch {
		t.Fatalf("legacy recovery did not terminally abort: %#v", store.saved)
	}
	if database.closed != 2 {
		t.Fatalf("legacy recovery session closes=%d", database.closed)
	}
}

func legacyPreflightForRecovery(t *testing.T, baseline ActivationPointerIdentity) (*UpgradeEngine, *engineStoreFake, *engineServiceFake, *[]string) {
	t.Helper()
	e, store, _, service, events := engineFixture(true)
	store.state.PreviousID, store.state.PreviousJSONSHA256 = baseline.ID, baseline.JSONSHA256
	store.fail, store.remaining = "legacy:prepare", 1
	r := engineRequest()
	r.ExpectedLegacy = true
	runErr := e.RunNew(context.Background(), r)
	if runErr == nil {
		t.Fatal("expected injected legacy prepare failure")
	}
	if len(store.created) != 1 || store.created[0].PlannedOldActivation == nil {
		t.Fatalf("missing legacy preflight journal: err=%v created=%#v events=%v", runErr, store.created, *events)
	}
	if store.created[0].PlannedOldActivation.Release.ID == r.CandidateRelease.ID || store.created[0].PlannedOldActivation.Release.Version != ProductionNMinusOneVersion {
		t.Fatalf("legacy and candidate release identities collapsed: old=%#v candidate=%#v", store.created[0].PlannedOldActivation.Release, r.CandidateRelease)
	}
	store.fail, store.remaining = "", 0
	store.saved = []UpgradeJournalV1{store.created[0]}
	store.state = UpgradeActivationState{PreviousID: baseline.ID, PreviousJSONSHA256: baseline.JSONSHA256, Marker: true}
	*events = nil
	return e, store, service, events
}

func TestRecoverLegacyPreflightBindsPreviousBaseline(t *testing.T) {
	for _, baseline := range []ActivationPointerIdentity{
		{},
		{ID: "activation-before", JSONSHA256: strings.Repeat("9", 64)},
	} {
		t.Run(fmt.Sprintf("baseline-%q", baseline.ID), func(t *testing.T) {
			e, store, _, events := legacyPreflightForRecovery(t, baseline)
			if got := enginePhase(t, e.Recover(context.Background(), "txn-1")); got.Phase != JournalAbortedPreSwitch {
				t.Fatalf("%v events=%v", got, *events)
			}
			if eventIndex(*events, "legacy:prepare") < 0 || store.state.PreviousID != baseline.ID || store.state.PreviousJSONSHA256 != baseline.JSONSHA256 {
				t.Fatalf("baseline was not preserved: state=%#v events=%v", store.state, *events)
			}
		})
	}
}

func TestRecoverLegacyPreflightRejectsForeignPreviousBeforeProjection(t *testing.T) {
	e, store, _, events := legacyPreflightForRecovery(t, ActivationPointerIdentity{})
	store.state.PreviousID, store.state.PreviousJSONSHA256 = "activation-foreign", strings.Repeat("8", 64)
	if got := enginePhase(t, e.Recover(context.Background(), "txn-1")); got.Phase != JournalRecoveryRequired {
		t.Fatalf("%v events=%v", got, *events)
	}
	if eventIndex(*events, "legacy:prepare") >= 0 || eventIndex(*events, "unit:reload") >= 0 || eventIndex(*events, "legacy:finalize") >= 0 || !store.state.Marker || eventIndex(*events, "edge:guard") < 0 {
		t.Fatalf("foreign previous reached projection: state=%#v events=%v", store.state, *events)
	}
}

func TestUpgradeEngineLegacyProjectionUnknownBoundariesRemainRecoverable(t *testing.T) {
	for _, target := range []string{"legacy:prepare", "unit:reload", "legacy:finalize", "legacy:read", "save:LEGACY_PROJECTED"} {
		t.Run(target, func(t *testing.T) {
			e, store, _, service, _ := engineFixture(true)
			store.fail, store.remaining, store.unknown = target, 1, true
			service.fail, service.remaining, service.unknown = target, 1, true
			r := engineRequest()
			r.ExpectedLegacy = true
			if got := enginePhase(t, e.RunNew(context.Background(), r)); got.Phase != JournalPreflighted || !store.state.Marker {
				t.Fatalf("%v marker=%v", got, store.state.Marker)
			}
			for _, journal := range append(store.created, store.saved...) {
				raw, err := MarshalUpgradeJournalV1(journal)
				if err != nil || strings.Contains(string(raw), "user:pass") || strings.Contains(string(raw), "postgresql://") {
					t.Fatalf("journal leaked secret: %v %s", err, raw)
				}
			}
		})
	}
}

func TestUpgradeEngineLegacyOperationalFailuresResumeFromJournal(t *testing.T) {
	for _, target := range []string{"legacy:prepare", "unit:reload", "legacy:finalize", "legacy:read", "save:LEGACY_PROJECTED"} {
		t.Run(target, func(t *testing.T) {
			e, store, _, service, _ := engineFixture(true)
			store.fail, store.remaining = target, 1
			service.fail, service.remaining = target, 1
			r := engineRequest()
			r.ExpectedLegacy = true
			if got := enginePhase(t, e.RunNew(context.Background(), r)); got.Phase != JournalPreflighted || !store.state.Marker {
				t.Fatalf("%v marker=%v", got, store.state.Marker)
			}
			if len(store.created) != 1 || store.created[0].State != JournalPreflighted || store.created[0].PlannedOldActivation == nil {
				t.Fatalf("legacy failure did not retain preflight journal: %#v", store.created)
			}
			store.fail, store.remaining, store.unknown = "", 0, false
			service.fail, service.remaining, service.unknown = "", 0, false
			if got := enginePhase(t, e.Recover(context.Background(), "txn-1")); got.Phase != JournalAbortedPreSwitch {
				t.Fatal(got)
			}
			if store.writtenCandidate.ActivationID != "" || store.state.Marker || store.saved[len(store.saved)-1].State != JournalAbortedPreSwitch {
				t.Fatalf("recovery continued candidate or lost terminal state: candidate=%q state=%#v saved=%#v", store.writtenCandidate.ActivationID, store.state, store.saved)
			}
			for _, journal := range append(store.created, store.saved...) {
				raw, err := MarshalUpgradeJournalV1(journal)
				if err != nil || strings.Contains(string(raw), "user:pass") || strings.Contains(string(raw), "postgresql://") {
					t.Fatalf("journal leaked secret: %v %s", err, raw)
				}
			}
		})
	}
}

func TestUpgradeEngineLegacyProjectedSaveUnknownReconcilesLatestJournal(t *testing.T) {
	for _, persisted := range []bool{false, true} {
		t.Run(fmt.Sprintf("persisted-%v", persisted), func(t *testing.T) {
			e, store, _, _, _ := engineFixture(true)
			store.fail, store.remaining, store.unknown, store.persistBeforeFailure = "save:LEGACY_PROJECTED", 1, true, persisted
			r := engineRequest()
			r.ExpectedLegacy = true
			phase := enginePhase(t, e.RunNew(context.Background(), r))
			want := JournalPreflighted
			if persisted {
				want = JournalLegacyProjected
			}
			if phase.Phase != want || !store.state.Marker {
				t.Fatalf("phase=%s want=%s marker=%v", phase.Phase, want, store.state.Marker)
			}
			store.fail, store.remaining, store.unknown, store.persistBeforeFailure = "", 0, false, false
			if got := enginePhase(t, e.Recover(context.Background(), "txn-1")); got.Phase != JournalAbortedPreSwitch {
				t.Fatal(got)
			}
			if store.writtenCandidate.ActivationID != "" || store.state.Marker || store.saved[len(store.saved)-1].State != JournalAbortedPreSwitch {
				t.Fatalf("save ambiguity recovery was unsafe: candidate=%q state=%#v saved=%#v", store.writtenCandidate.ActivationID, store.state, store.saved)
			}
		})
	}
}

func TestUpgradeEngineLegacySaveFailureStopsBeforeMarker(t *testing.T) {
	e, store, _, _, events := engineFixture(true)
	store.fail = "save:LEGACY_PROJECTED"
	store.remaining = 1
	r := engineRequest()
	r.ExpectedLegacy = true
	if got := enginePhase(t, e.RunNew(context.Background(), r)); got.Phase != JournalPreflighted {
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
				if got := enginePhase(t, err); got.Phase != JournalPreflighted || got.Code != "upgrade_lock_invalid" {
					t.Fatalf("phase=%#v", got)
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

func TestUpgradeEngineRecoverRejectsWrongPreviousDigest(t *testing.T) {
	e, store, _, _, events := engineFixture(false)
	if err := e.RunNew(context.Background(), engineRequest()); err != nil {
		t.Fatal(err)
	}
	store.state.PreviousID, store.state.PreviousJSONSHA256 = "activation-old", strings.Repeat("8", 64)
	if got := enginePhase(t, e.Recover(context.Background(), "txn-1")); got.Phase != JournalCommitted || got.Code != "integrity_failed" {
		t.Fatalf("%v events=%v", got, *events)
	}
	if eventIndex(*events, "edge:guard") < 0 {
		t.Fatalf("wrong previous digest did not guard edge: %v", *events)
	}
}

func TestUpgradeEngineRecoverCandidateStateRejectsWrongPreviousDigest(t *testing.T) {
	e, store, _, _, events := engineFixture(false)
	if err := e.RunNew(context.Background(), engineRequest()); err != nil {
		t.Fatal(err)
	}
	for _, journal := range store.saved {
		if journal.State == JournalValidated {
			store.saved = []UpgradeJournalV1{journal}
			break
		}
	}
	if len(store.saved) != 1 || store.saved[0].State != JournalValidated {
		t.Fatalf("missing validated journal: %#v", store.saved)
	}
	store.state.Marker = true
	store.state.PreviousID, store.state.PreviousJSONSHA256 = "activation-old", strings.Repeat("8", 64)
	if got := enginePhase(t, e.Recover(context.Background(), "txn-1")); got.Phase != JournalRecoveryRequired {
		t.Fatalf("%v events=%v", got, *events)
	}
	if eventIndex(*events, "edge:guard") < 0 || !store.state.Marker {
		t.Fatalf("candidate pointer drift was not fail-closed: state=%#v events=%v", store.state, *events)
	}
}

func TestRecoverLegacyPreflightWithoutDatabaseFailsClosed(t *testing.T) {
	e, store, _, _ := legacyPreflightForRecovery(t, ActivationPointerIdentity{})
	e.DatabaseFactory = nil
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("legacy recovery panicked: %v", recovered)
		}
	}()
	if got := enginePhase(t, e.Recover(context.Background(), "txn-1")); got.Phase != JournalRecoveryRequired {
		t.Fatal(got)
	}
	if !store.state.Marker {
		t.Fatal("missing database driver cleared legacy recovery marker")
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
