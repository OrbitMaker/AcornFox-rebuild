package install

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type bootstrapEngineLock struct{ store *bootstrapEngineStoreFake }

func (l bootstrapEngineLock) Release() error { l.store.locked = false; return nil }

type bootstrapEngineStoreFake struct {
	mu                             sync.Mutex
	journal                        *BootstrapJournalV1
	locked, marker                 bool
	ensureCalls                    int
	activationID, activationDigest string
	activeID                       string
	current, previous              bool
	fail                           string
}

func (s *bootstrapEngineStoreFake) Acquire(_ context.Context, _ string) (UpgradeLock, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return nil, ErrUpgradeLocked
	}
	s.locked = true
	return bootstrapEngineLock{s}, nil
}
func (s *bootstrapEngineStoreFake) EnsureMarker(_ context.Context, _ string) error {
	s.ensureCalls++
	if s.fail == "marker" && s.ensureCalls == 1 {
		return errors.New("marker secret")
	}
	s.marker = true
	return nil
}
func (s *bootstrapEngineStoreFake) Marker(_ context.Context, set bool) error {
	if s.fail == "marker-remove" && !set {
		return errors.New("marker secret")
	}
	s.marker = set
	return nil
}
func (s *bootstrapEngineStoreFake) Load(_ context.Context, _ string) (BootstrapJournalV1, error) {
	if s.journal == nil {
		return BootstrapJournalV1{}, os.ErrNotExist
	}
	return *s.journal, nil
}
func (s *bootstrapEngineStoreFake) Create(_ context.Context, j BootstrapJournalV1) error {
	if s.journal != nil || s.fail == "create-journal" {
		return ErrUpgradeJournalConflict
	}
	copy := j
	s.journal = &copy
	return nil
}
func (s *bootstrapEngineStoreFake) Save(_ context.Context, j BootstrapJournalV1) error {
	if s.fail == "save" {
		return errors.New("journal secret")
	}
	copy := j
	s.journal = &copy
	return nil
}
func (s *bootstrapEngineStoreFake) WriteInitialActivation(_ context.Context, j BootstrapJournalV1, a ActivationV1, _ []byte) (string, error) {
	if s.fail == "write" || j.State != BootstrapMigrated0024 || s.activationID != "" {
		return "", ErrUpgradeJournalConflict
	}
	digest, err := CanonicalActivationJSONSHA256(a)
	if err != nil {
		return "", err
	}
	s.activationID, s.activationDigest = a.ActivationID, digest
	return digest, nil
}
func (s *bootstrapEngineStoreFake) PublishInitialPointers(_ context.Context, j BootstrapJournalV1, a ActivationV1) (string, error) {
	if s.fail == "pointer" || j.State != BootstrapActivationWritten || s.activationID != a.ActivationID || s.activationDigest != j.ActivationJSONSHA256 {
		return "", ErrUpgradeJournalConflict
	}
	s.activeID, s.current = a.ActivationID, true
	return bootstrapPointerDigest(a.ActivationID, s.activationDigest), nil
}
func (s *bootstrapEngineStoreFake) ReadInitialPointerState(_ context.Context, id string) (BootstrapInitialPointerState, error) {
	if s.fail == "read" {
		return BootstrapInitialPointerState{}, ErrUpgradeJournalConflict
	}
	state := BootstrapInitialPointerState{ActivationExists: s.activationID == id, ActivationJSONSHA256: s.activationDigest, ActiveID: s.activeID, CurrentPresent: s.current, PreviousPresent: s.previous, MarkerTransactionID: func() string {
		if s.marker && s.journal != nil {
			return s.journal.TransactionID
		}
		return ""
	}()}
	if state.ActivationExists && state.ActiveID == id && state.CurrentPresent && !state.PreviousPresent {
		state.PointerStateSHA256 = bootstrapPointerDigest(id, s.activationDigest)
	}
	return state, nil
}

func bootstrapPointerDigest(id, digest string) string { return sha256Bytes([]byte(id + "\n" + digest)) }

type bootstrapEngineDatabaseFake struct {
	candidate         BootstrapCandidateDatabase
	result            BootstrapDatabaseResult
	fail              string
	creates, migrates int
}

func (d *bootstrapEngineDatabaseFake) Create(context.Context) (BootstrapCandidateDatabase, error) {
	d.creates++
	if d.fail == "create" {
		return BootstrapCandidateDatabase{}, errors.New("database-password")
	}
	return d.candidate, nil
}
func (d *bootstrapEngineDatabaseFake) Migrate(context.Context, BootstrapCandidateDatabase) (BootstrapDatabaseResult, error) {
	d.migrates++
	if d.fail == "migrate" {
		return BootstrapDatabaseResult{}, errors.New("migration-password")
	}
	return d.result, nil
}

type bootstrapEngineServicesFake struct {
	fail   string
	events []string
	state  ServiceSnapshotV1
}

func (s *bootstrapEngineServicesFake) event(name string) error {
	s.events = append(s.events, name)
	if s.fail == name {
		return errors.New("service-password")
	}
	return nil
}
func (s *bootstrapEngineServicesFake) GuardEdge(context.Context) error {
	s.state.Edge.Active = false
	return s.event("guard")
}
func (s *bootstrapEngineServicesFake) EnableInternal(context.Context) error {
	s.state.Agent.Enabled, s.state.Server.Enabled, s.state.Caddy.Enabled, s.state.BuildKit.Enabled = true, true, true, true
	return s.event("enable-internal")
}
func (s *bootstrapEngineServicesFake) StartInternal(context.Context) error {
	s.state.Agent.Active, s.state.Server.Active, s.state.Caddy.Active, s.state.BuildKit.Active = true, true, true, true
	return s.event("start-internal")
}
func (s *bootstrapEngineServicesFake) HealthInternal(context.Context) error {
	return s.event("health-internal")
}
func (s *bootstrapEngineServicesFake) EnableEdge(context.Context) error {
	s.state.Edge.Enabled = true
	return s.event("enable-edge")
}
func (s *bootstrapEngineServicesFake) StartEdge(context.Context) error {
	s.state.Edge.Active = true
	return s.event("start-edge")
}
func (s *bootstrapEngineServicesFake) HealthEdge(context.Context) error {
	return s.event("health-edge")
}
func (s *bootstrapEngineServicesFake) Capture(context.Context) (ServiceSnapshotV1, error) {
	if err := s.event("capture"); err != nil {
		return ServiceSnapshotV1{}, err
	}
	return s.state, nil
}

func bootstrapEngineFixture(t *testing.T) (*BootstrapEngine, *bootstrapEngineStoreFake, *bootstrapEngineDatabaseFake, *bootstrapEngineServicesFake, BootstrapRequest) {
	t.Helper()
	release, _ := bootstrapRC2Release(t)
	request := BootstrapRequest{TransactionID: "bootstrap-txn-engine", InstallationIDSHA256: strings.Repeat("a", 64), CandidateActivationID: "activation-bootstrap-engine", Release: release}
	name, err := CandidateDatabaseName(request.CandidateActivationID)
	if err != nil {
		t.Fatal(err)
	}
	env := bootstrapRuntimeEnv(t)
	candidateEnv, err := CandidateDatabaseEnv(env, name)
	if err != nil {
		t.Fatal(err)
	}
	evidence := bootstrapRecoveryEvidence(request.databaseInput(), name, sha256Bytes(env), strings.Repeat("c", 64))
	candidate := BootstrapCandidateDatabase{Name: name, DatabaseEnv: candidateEnv, RuntimeDatabaseEnvSHA256: sha256Bytes(env), ControlDatabaseIdentitySHA256: strings.Repeat("c", 64), RecoveryEvidenceSHA256: evidence}
	rows := migrationRows(24)
	database := BootstrapDatabaseResult{Database: DatabaseV1{Name: name, Migration: CurrentMigrationVersion, SchemaMigrationsSHA256: migrationDigest(rows)}, DatabaseEnv: candidateEnv, CandidateDatabaseName: name, RuntimeDatabaseEnvSHA256: candidate.RuntimeDatabaseEnvSHA256, ControlDatabaseIdentitySHA256: candidate.ControlDatabaseIdentitySHA256, RecoveryEvidenceSHA256: candidate.RecoveryEvidenceSHA256}
	if candidate.Validate() != nil || database.Validate() != nil {
		t.Fatal("invalid fixture database")
	}
	store, db, services := &bootstrapEngineStoreFake{}, &bootstrapEngineDatabaseFake{candidate: candidate, result: database}, &bootstrapEngineServicesFake{}
	now := time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
	engine := &BootstrapEngine{Store: store, Database: db, Services: services, Now: func() time.Time { now = now.Add(time.Second); return now }}
	return engine, store, db, services, request
}

func TestBootstrapEngineRunsCanonicalSequenceAndCommittedReplay(t *testing.T) {
	engine, store, db, services, request := bootstrapEngineFixture(t)
	if err := engine.Run(context.Background(), request); err != nil {
		t.Fatalf("%v journal=%#v events=%v", err, store.journal, services.events)
	}
	if store.journal == nil || store.journal.State != BootstrapCommitted || store.marker || store.activeID != request.CandidateActivationID || !store.current || store.previous || db.creates < 2 || db.migrates < 2 {
		t.Fatalf("state=%#v db=%#v", store, db)
	}
	want := []string{"guard", "enable-internal", "start-internal", "health-internal", "capture", "enable-internal", "start-internal", "health-internal", "capture", "enable-edge", "start-edge", "health-edge", "capture", "health-internal", "health-edge", "capture", "health-internal", "health-edge", "capture"}
	if strings.Join(services.events, ",") != strings.Join(want, ",") {
		t.Fatalf("events=%v", services.events)
	}
	beforeEnable := strings.Count(strings.Join(services.events, ","), "enable-internal")
	if err := engine.Run(context.Background(), request); err != nil {
		t.Fatalf("committed replay failed: %v", err)
	}
	if strings.Count(strings.Join(services.events, ","), "enable-internal") != beforeEnable {
		t.Fatal("committed replay mutated services")
	}
}

func TestBootstrapEngineFailsClosedAtEveryMutationBoundary(t *testing.T) {
	for _, failure := range []string{"marker", "create", "migrate", "write", "pointer", "enable-internal", "start-internal", "health-internal", "enable-edge", "start-edge", "health-edge"} {
		t.Run(failure, func(t *testing.T) {
			engine, store, db, services, request := bootstrapEngineFixture(t)
			switch failure {
			case "create", "migrate":
				db.fail = failure
			case "marker", "write", "pointer":
				store.fail = failure
			default:
				services.fail = failure
			}
			err := engine.Run(context.Background(), request)
			if !errors.Is(err, ErrBootstrapRecoveryRequired) || store.journal == nil || store.journal.State != BootstrapRecoveryRequired || !store.marker || !containsEvent(services.events, "guard") || strings.Contains(err.Error(), "password") {
				t.Fatalf("err=%v state=%#v events=%v", err, store.journal, services.events)
			}
		})
	}
}

func TestBootstrapEngineHealthyReplayRechecksEndpointsAndGuardsFailure(t *testing.T) {
	for _, tc := range []struct {
		state BootstrapState
		fail  string
	}{
		{BootstrapInternalHealthy, "health-internal"},
		{BootstrapEdgeHealthy, "health-edge"},
		{BootstrapCommitted, "health-edge"},
	} {
		t.Run(string(tc.state), func(t *testing.T) {
			engine, store, _, services, request := bootstrapEngineFixture(t)
			if err := engine.Run(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			if tc.state != BootstrapCommitted {
				prefix := bootstrapJournalPrefix(t, *store.journal, tc.state)
				store.journal = &prefix
				store.marker = tc.state == BootstrapInternalHealthy
			}
			services.fail = tc.fail
			err := engine.Run(context.Background(), request)
			if !errors.Is(err, ErrBootstrapRecoveryRequired) || !store.marker || !containsEvent(services.events, "guard") {
				t.Fatalf("state=%s err=%v marker=%v events=%v", tc.state, err, store.marker, services.events)
			}
			if tc.state == BootstrapCommitted {
				if store.journal.State != BootstrapCommitted {
					t.Fatalf("committed journal mutated to %s", store.journal.State)
				}
			} else if store.journal.State != BootstrapRecoveryRequired {
				t.Fatalf("state=%s", store.journal.State)
			}
		})
	}
}

func TestBootstrapEngineSaveFailureDoesNotInventRecoveryJournal(t *testing.T) {
	engine, store, _, services, request := bootstrapEngineFixture(t)
	store.fail = "save"
	err := engine.Run(context.Background(), request)
	if !errors.Is(err, ErrBootstrapRecoveryRequired) || store.journal == nil || store.journal.State != BootstrapPrepared || !store.marker || !containsEvent(services.events, "guard") {
		t.Fatalf("err=%v journal=%+v marker=%v events=%v", err, store.journal, store.marker, services.events)
	}
}

func TestBootstrapEngineVerifiesPointerDigestAndTransitionEvidence(t *testing.T) {
	engine, store, db, services, request := bootstrapEngineFixture(t)
	if err := engine.Run(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	history := store.journal.History
	if history[1].EvidenceSHA256 != bootstrapTypedEvidence(db.candidate) || history[2].EvidenceSHA256 != bootstrapTypedEvidence(db.result) || history[3].EvidenceSHA256 != store.journal.ActivationJSONSHA256 || history[4].EvidenceSHA256 != store.journal.PointerStateSHA256 || history[5].EvidenceSHA256 != store.journal.InternalHealthSHA256 || history[6].EvidenceSHA256 != store.journal.EdgeHealthSHA256 {
		t.Fatalf("history does not bind actual postconditions: %+v", history)
	}
	drifted := *store.journal
	drifted.PointerStateSHA256 = strings.Repeat("f", 64)
	store.journal = &drifted
	services.events = nil
	if err := engine.Run(context.Background(), request); !errors.Is(err, ErrBootstrapRecoveryRequired) || !store.marker || !containsEvent(services.events, "guard") {
		t.Fatalf("pointer digest drift err=%v marker=%v events=%v", err, store.marker, services.events)
	}
}

func TestBootstrapRequestRejectsForeignArchitecture(t *testing.T) {
	engine, _, _, _, request := bootstrapEngineFixture(t)
	if request.Release.Architecture == "amd64" {
		request.Release.Architecture = "arm64"
	} else {
		request.Release.Architecture = "amd64"
	}
	if err := engine.Run(context.Background(), request); !errors.Is(err, ErrBootstrapConflict) {
		t.Fatalf("foreign architecture err=%v", err)
	}
}

func TestBootstrapEngineReplaysEachDurablePrefixAndRejectsDrift(t *testing.T) {
	engine, store, _, _, request := bootstrapEngineFixture(t)
	if err := engine.Run(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	for _, state := range []BootstrapState{BootstrapPrepared, BootstrapCandidateDBCreated, BootstrapMigrated0024, BootstrapActivationWritten, BootstrapPointersPublished, BootstrapInternalHealthy, BootstrapEdgeHealthy} {
		t.Run(string(state), func(t *testing.T) {
			e, s, _, _, r := bootstrapEngineFixture(t)
			// Build the requested prefix with real engine transitions, then restart
			// from an exact durable copy rather than inventing an inconsistent state.
			if err := e.Run(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			prefix := bootstrapJournalPrefix(t, *s.journal, state)
			s.journal = &prefix
			s.marker = state != BootstrapEdgeHealthy
			if state == BootstrapPrepared || state == BootstrapCandidateDBCreated || state == BootstrapMigrated0024 {
				s.activationID, s.activationDigest, s.activeID, s.current = "", "", "", false
			}
			if state == BootstrapActivationWritten {
				s.activeID, s.current = "", false
			}
			if err := e.Run(context.Background(), r); err != nil {
				t.Fatalf("replay=%v", err)
			}
			if s.journal.State != BootstrapCommitted {
				t.Fatalf("state=%s", s.journal.State)
			}
		})
	}
	bad := *store.journal
	bad.CandidateDatabaseName = "open_card_act_ffffffffffffffff"
	store.journal = &bad
	before, _ := MarshalBootstrapJournalV1(*store.journal)
	if err := engine.Run(context.Background(), request); !errors.Is(err, ErrBootstrapConflict) {
		t.Fatalf("drift=%v", err)
	}
	after, _ := MarshalBootstrapJournalV1(*store.journal)
	if string(before) != string(after) {
		t.Fatal("mismatched request mutated durable journal")
	}
}

func bootstrapJournalPrefix(t *testing.T, journal BootstrapJournalV1, state BootstrapState) BootstrapJournalV1 {
	t.Helper()
	out := journal
	index := 0
	for i, h := range journal.History {
		if h.To == state {
			index = i
			break
		}
	}
	out.History = append([]BootstrapHistoryV1(nil), journal.History[:index+1]...)
	out.Revision = int64(len(out.History))
	out.State, out.UpdatedAt = state, out.History[index].At
	if bootstrapRank(state) < 2 {
		out.CandidateDatabaseSchemaSHA256 = ""
	}
	if bootstrapRank(state) < 3 {
		out.ActivationJSONSHA256 = ""
	}
	if bootstrapRank(state) < 4 {
		out.PointerStateSHA256 = ""
	}
	if bootstrapRank(state) < 5 {
		out.InternalHealthSHA256, out.ServiceSnapshot = "", nil
	}
	if bootstrapRank(state) < 6 {
		out.EdgeHealthSHA256 = ""
	}
	if out.Validate() != nil {
		t.Fatalf("invalid prefix %s: %#v", state, out)
	}
	return out
}
func containsEvent(events []string, want string) bool {
	for _, event := range events {
		if event == want {
			return true
		}
	}
	return false
}

func TestBootstrapEngineJournalAndErrorsAreSecretFree(t *testing.T) {
	engine, store, db, services, request := bootstrapEngineFixture(t)
	db.fail = "create"
	err := engine.Run(context.Background(), request)
	if !errors.Is(err, ErrBootstrapRecoveryRequired) {
		t.Fatal(err)
	}
	raw, marshalErr := MarshalBootstrapJournalV1(*store.journal)
	if marshalErr != nil || strings.Contains(string(raw), "postgresql://") || strings.Contains(string(raw), "password") || strings.Contains(string(raw), "/opt/open-card") || strings.Contains(err.Error(), "password") {
		t.Fatalf("journal/error leaks secret or path: %s %v %v", raw, err, marshalErr)
	}
	if !containsEvent(services.events, "guard") {
		t.Fatal("failure did not guard edge")
	}
}

func TestBootstrapEngineHasNoDestructiveOrLegacyFallbackSurface(t *testing.T) {
	raw, err := os.ReadFile("bootstrap_engine.go")
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{"drop database", "removeactivationlink", "projectlegacy", "server.env", "open_card_database_url"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("bootstrap engine contains forbidden surface %q", forbidden)
		}
	}
}
