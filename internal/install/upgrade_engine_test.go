package install

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var errEngineFake = errors.New("engine fake failure")

type engineLock struct{ released *int }

func (l engineLock) Release() error { *l.released++; return nil }

type engineStoreFake struct {
	events       *[]string
	fail         string
	legacy       bool
	conflict     bool
	released     int
	created      []UpgradeJournalV1
	saved        []UpgradeJournalV1
	old          ActivationV1
	candidateEnv []byte
}

func (s *engineStoreFake) event(name string) error {
	*s.events = append(*s.events, name)
	if s.fail == name {
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
func (s *engineStoreFake) Preflight(context.Context, string) (ActivationV1, string, bool, error) {
	if err := s.event("preflight"); err != nil {
		return ActivationV1{}, "", false, err
	}
	return s.old, strings.Repeat("a", 64), s.legacy, nil
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
	return s.event(name)
}
func (s *engineStoreFake) WriteCandidateActivation(_ context.Context, _ ActivationV1, env []byte) (string, error) {
	s.candidateEnv = append([]byte(nil), env...)
	if err := s.event("write"); err != nil {
		return "", err
	}
	return strings.Repeat("b", 64), nil
}
func (s *engineStoreFake) SetPrevious(context.Context, string) error { return s.event("previous") }
func (s *engineStoreFake) SwapActive(context.Context, string) error  { return s.event("swap") }

type engineDBFake struct {
	events *[]string
	fail   string
}

func (d *engineDBFake) event(name string) error {
	*d.events = append(*d.events, name)
	if d.fail == name {
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
func (d *engineDBFake) Migrate(context.Context) (MigrationEvidence, error) {
	if err := d.event("migrate"); err != nil {
		return MigrationEvidence{}, err
	}
	return MigrationEvidence{From: "0023", To: "0024", RowsSHA256: strings.Repeat("d", 64)}, nil
}
func (d *engineDBFake) Validate(context.Context, string) (ArtifactV1, error) {
	if err := d.event("validate"); err != nil {
		return ArtifactV1{}, err
	}
	return ArtifactV1{Path: artifactPath("txn-1", "validation.json"), SHA256: strings.Repeat("e", 64), Size: 9}, nil
}

type engineServiceFake struct {
	events *[]string
	fail   string
}

func (s *engineServiceFake) event(name string) error {
	*s.events = append(*s.events, name)
	if s.fail == name {
		return errEngineFake
	}
	return nil
}
func (s *engineServiceFake) Capture(context.Context) (ServiceSnapshotV1, error) {
	if err := s.event("capture"); err != nil {
		return ServiceSnapshotV1{}, err
	}
	return ServiceSnapshotV1{Edge: UnitSnapshotV1{Active: true, Enabled: true}, Agent: UnitSnapshotV1{Active: true}, Server: UnitSnapshotV1{Enabled: true}, Caddy: UnitSnapshotV1{Active: true, Enabled: true}}, nil
}
func (s *engineServiceFake) Quiesce(context.Context) error        { return s.event("quiesce") }
func (s *engineServiceFake) StartInternal(context.Context) error  { return s.event("internal:start") }
func (s *engineServiceFake) HealthInternal(context.Context) error { return s.event("internal:health") }
func (s *engineServiceFake) StartEdge(context.Context) error      { return s.event("edge:start") }
func (s *engineServiceFake) HealthEdge(context.Context) error     { return s.event("edge:health") }

func engineOldActivation() ActivationV1 {
	return ActivationV1{SchemaVersion: 1, ActivationID: "activation-old", Origin: "install", Release: ReleaseV1{ID: "release-old", Version: "0.7.0", SourceCommit: strings.Repeat("a", 64), Architecture: "amd64", ManifestSHA256: strings.Repeat("b", 64)}, Database: DatabaseV1{Name: "open_card", Migration: "0024", SchemaMigrationsSHA256: strings.Repeat("c", 64)}, DatabaseEnvSHA256: strings.Repeat("d", 64), CreatedAt: time.Unix(1, 0).UTC(), CreatedByTransactionID: "old-txn"}
}
func engineRequest() UpgradeRequest {
	return UpgradeRequest{TransactionID: "txn-1", CandidateRelease: ReleaseV1{ID: "release-new", Version: "0.8.0-rc.1", SourceCommit: strings.Repeat("e", 64), Architecture: "amd64", ManifestSHA256: strings.Repeat("f", 64)}, CandidateActivationID: "activation-new", CandidateDatabaseName: "open_card_act_0123456789abcdef", CandidateDatabaseEnv: []byte("OPEN_CARD_DATABASE_URL=postgresql://user:pass@localhost:5432/open_card?sslmode=disable\n"), RequestedManifestSHA256: strings.Repeat("f", 64)}
}
func engineFixture(legacy bool) (*UpgradeEngine, *engineStoreFake, *engineDBFake, *engineServiceFake, *[]string) {
	events := []string{}
	s := &engineStoreFake{events: &events, old: engineOldActivation(), legacy: legacy}
	d := &engineDBFake{events: &events}
	svc := &engineServiceFake{events: &events}
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
	r := engineRequest()
	r.ExpectedLegacy = true
	if got := enginePhase(t, e.RunNew(context.Background(), r)); got.Phase != JournalLegacyProjected {
		t.Fatal(got)
	}
	if (*events)[len(*events)-1] != "save:LEGACY_PROJECTED" || eventIndex(*events, "marker:on") >= 0 {
		t.Fatalf("legacy save failure advanced: %v", *events)
	}
}

func TestUpgradeEngineFailureStopsAtBoundary(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
		phase  JournalState
	}{
		{"acquire", "acquire", JournalPreflighted}, {"preflight", "preflight", JournalPreflighted}, {"capture", "capture", JournalPreflighted}, {"create", "create", JournalPreflighted}, {"marker", "marker:on", JournalPreflighted}, {"quiesce", "quiesce", JournalQuiesced}, {"drain", "drain", JournalQuiesced}, {"save-quiesced", "save:QUIESCED", JournalQuiesced}, {"snapshot", "snapshot", JournalSnapshotCreated}, {"save-snapshot", "save:SNAPSHOT_CREATED", JournalSnapshotCreated}, {"candidate", "candidate", JournalCandidateDBReady}, {"save-candidate", "save:CANDIDATE_DB_READY", JournalCandidateDBReady}, {"migrate", "migrate", JournalMigrated}, {"save-migrated", "save:MIGRATED", JournalMigrated}, {"write", "write", JournalValidated}, {"validate", "validate", JournalValidated}, {"save-validated", "save:VALIDATED", JournalValidated}, {"previous", "previous", JournalActiveSwitched}, {"swap", "swap", JournalActiveSwitched}, {"save-active", "save:ACTIVE_SWITCHED", JournalActiveSwitched}, {"start-internal", "internal:start", JournalHealthy}, {"health-internal", "internal:health", JournalHealthy}, {"save-healthy", "save:HEALTHY", JournalHealthy}, {"save-edge", "save:EDGE_ARMED", JournalEdgeArmed}, {"unmarker", "marker:off", JournalEdgeArmed}, {"start-edge", "edge:start", JournalEdgeArmed}, {"health-edge", "edge:health", JournalEdgeArmed}, {"save-committed", "save:COMMITTED", JournalCommitted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, store, db, svc, events := engineFixture(false)
			store.fail = tc.target
			db.fail = tc.target
			svc.fail = tc.target
			err := e.RunNew(context.Background(), engineRequest())
			if tc.target == "acquire" {
				if !errors.Is(err, ErrUpgradeLocked) {
					t.Fatal(err)
				}
			} else if got := enginePhase(t, err); got.Phase != tc.phase {
				t.Fatalf("phase=%s want %s", got.Phase, tc.phase)
			}
			if (*events)[len(*events)-1] != tc.target {
				t.Fatalf("later call after %s: %v", tc.target, *events)
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
