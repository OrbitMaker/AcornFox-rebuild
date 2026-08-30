package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"time"
)

var ErrBootstrapRecoveryRequired = errors.New("bootstrap requires recovery")
var ErrBootstrapConflict = errors.New("bootstrap transaction conflicts with durable state")

// BootstrapRequest is deliberately data-only. Paths, DSNs, unit names and
// SQL are all derived by the typed store/database/service implementations.
type BootstrapRequest struct {
	TransactionID         string
	InstallationIDSHA256  string
	CandidateActivationID string
	Release               ReleaseV1
}

func (r BootstrapRequest) Validate() error {
	if (BootstrapDatabaseInput{TransactionID: r.TransactionID, InstallationIDSHA256: r.InstallationIDSHA256, CandidateActivationID: r.CandidateActivationID, Release: r.Release}).Validate() != nil {
		return ErrBootstrapConflict
	}
	architecture, err := NormalizeArchitecture(r.Release.Architecture)
	if err != nil || architecture != r.Release.Architecture || architecture != RuntimeArchitecture() {
		return ErrBootstrapConflict
	}
	return nil
}

func (r BootstrapRequest) databaseInput() BootstrapDatabaseInput {
	return BootstrapDatabaseInput{TransactionID: r.TransactionID, InstallationIDSHA256: r.InstallationIDSHA256, CandidateActivationID: r.CandidateActivationID, Release: r.Release}
}

type BootstrapEngineStore interface {
	Acquire(context.Context, string) (UpgradeLock, error)
	EnsureMarker(context.Context, string) error
	Marker(context.Context, bool) error
	Load(context.Context, string) (BootstrapJournalV1, error)
	Create(context.Context, BootstrapJournalV1) error
	Save(context.Context, BootstrapJournalV1) error
	WriteInitialActivation(context.Context, BootstrapJournalV1, ActivationV1, []byte) (string, error)
	PublishInitialPointers(context.Context, BootstrapJournalV1, ActivationV1) (string, error)
	ReadInitialPointerState(context.Context, string) (BootstrapInitialPointerState, error)
}

type BootstrapDatabaseDriver interface {
	Create(context.Context) (BootstrapCandidateDatabase, error)
	Migrate(context.Context, BootstrapCandidateDatabase) (BootstrapDatabaseResult, error)
}

// BootstrapServiceDriver exposes the only service mutations the initial
// bootstrap state machine can make. Unit selection remains inside the driver.
type BootstrapServiceDriver interface {
	GuardEdge(context.Context) error
	EnableInternal(context.Context) error
	StartInternal(context.Context) error
	HealthInternal(context.Context) error
	EnableEdge(context.Context) error
	StartEdge(context.Context) error
	HealthEdge(context.Context) error
	Capture(context.Context) (ServiceSnapshotV1, error)
}

// BootstrapEngine owns one globally locked, journaled first activation.
// It intentionally has no delete, rollback-to-legacy, or global-env fallback.
type BootstrapEngine struct {
	Store    BootstrapEngineStore
	Database BootstrapDatabaseDriver
	Services BootstrapServiceDriver
	Now      func() time.Time
}

func (e *BootstrapEngine) Run(ctx context.Context, request BootstrapRequest) (result error) {
	if e == nil || e.Store == nil || e.Database == nil || e.Services == nil || e.Now == nil || request.Validate() != nil {
		return ErrBootstrapConflict
	}
	lock, err := e.Store.Acquire(ctx, request.TransactionID)
	if err != nil {
		if errors.Is(err, ErrUpgradeLocked) {
			return ErrUpgradeLocked
		}
		return ErrBootstrapConflict
	}
	defer func() {
		if err := lock.Release(); err != nil && result == nil {
			result = ErrBootstrapRecoveryRequired
		}
	}()

	journal, err := e.Store.Load(ctx, request.TransactionID)
	if errors.Is(err, os.ErrNotExist) {
		journal = e.initial(request)
		if journal.Validate() != nil || e.Store.Create(ctx, journal) != nil {
			return ErrBootstrapConflict
		}
	} else if err != nil {
		return ErrBootstrapConflict
	}
	if !sameBootstrapRequest(journal, request) {
		return ErrBootstrapConflict
	}
	if journal.Validate() != nil {
		return e.recovery(ctx, &journal, "journal_invalid")
	}
	if journal.State == BootstrapRecoveryRequired {
		_ = e.Store.EnsureMarker(ctx, request.TransactionID)
		_ = e.Services.GuardEdge(ctx)
		return ErrBootstrapRecoveryRequired
	}
	return e.resume(ctx, request, &journal)
}

func (e *BootstrapEngine) initial(r BootstrapRequest) BootstrapJournalV1 {
	at := e.now()
	j := BootstrapJournalV1{SchemaVersion: 1, TransactionID: r.TransactionID, Revision: 1, State: BootstrapPrepared, CreatedAt: at, UpdatedAt: at, InstallationIDSHA256: r.InstallationIDSHA256, Release: r.Release, CandidateActivationID: r.CandidateActivationID, MarkerTransactionID: r.TransactionID}
	name, _ := CandidateDatabaseName(r.CandidateActivationID)
	j.CandidateDatabaseName = name
	j.History = []BootstrapHistoryV1{{Revision: 1, To: BootstrapPrepared, At: at, EvidenceSHA256: bootstrapEvidence(j, "", BootstrapPrepared)}}
	return j
}

func sameBootstrapRequest(j BootstrapJournalV1, r BootstrapRequest) bool {
	name, err := CandidateDatabaseName(r.CandidateActivationID)
	return err == nil && j.TransactionID == r.TransactionID && j.InstallationIDSHA256 == r.InstallationIDSHA256 && j.Release == r.Release && j.CandidateActivationID == r.CandidateActivationID && j.CandidateDatabaseName == name && j.MarkerTransactionID == r.TransactionID
}

func (e *BootstrapEngine) resume(ctx context.Context, request BootstrapRequest, j *BootstrapJournalV1) error {
	// Before public Edge health is durably recorded, the marker and a stopped
	// Edge are mandatory. EDGE_HEALTHY/COMMITTED are the only public states and
	// must be verified without rearming the marker or disrupting Edge traffic.
	if j.State != BootstrapEdgeHealthy && j.State != BootstrapCommitted {
		if err := e.ensureGuard(ctx, request.TransactionID); err != nil {
			return e.recovery(ctx, j, "guard_edge_failed")
		}
	}
	var candidate BootstrapCandidateDatabase
	var database BootstrapDatabaseResult
	var activation ActivationV1
	for {
		switch j.State {
		case BootstrapPrepared:
			var err error
			candidate, err = e.Database.Create(ctx)
			if err != nil || candidate.Validate() != nil || candidate.Name != j.CandidateDatabaseName {
				return e.recovery(ctx, j, "candidate_create_failed")
			}
			if err := e.advance(ctx, j, BootstrapCandidateDBCreated, bootstrapTypedEvidence(candidate)); err != nil {
				return e.recovery(ctx, j, "candidate_journal_failed")
			}
		case BootstrapCandidateDBCreated:
			var err error
			candidate, err = e.Database.Create(ctx)
			if err != nil || candidate.Validate() != nil || candidate.Name != j.CandidateDatabaseName {
				return e.recovery(ctx, j, "candidate_replay_failed")
			}
			database, err = e.Database.Migrate(ctx, candidate)
			if err != nil || database.Validate() != nil || database.Database.Name != j.CandidateDatabaseName {
				return e.recovery(ctx, j, "migration_failed")
			}
			j.CandidateDatabaseSchemaSHA256 = database.Database.SchemaMigrationsSHA256
			if err := e.advance(ctx, j, BootstrapMigrated0024, bootstrapTypedEvidence(database)); err != nil {
				return e.recovery(ctx, j, "migration_journal_failed")
			}
		case BootstrapMigrated0024:
			var err error
			candidate, err = e.Database.Create(ctx)
			if err != nil || candidate.Validate() != nil {
				return e.recovery(ctx, j, "candidate_replay_failed")
			}
			database, err = e.Database.Migrate(ctx, candidate)
			if err != nil || database.Validate() != nil || database.Database.SchemaMigrationsSHA256 != j.CandidateDatabaseSchemaSHA256 {
				return e.recovery(ctx, j, "migration_replay_failed")
			}
			activation = e.activation(*j, database)
			digest, err := e.Store.WriteInitialActivation(ctx, *j, activation, database.DatabaseEnv)
			if err != nil || !validSHA(digest) {
				return e.recovery(ctx, j, "activation_write_failed")
			}
			j.ActivationJSONSHA256 = digest
			if err := e.advance(ctx, j, BootstrapActivationWritten, digest); err != nil {
				return e.recovery(ctx, j, "activation_journal_failed")
			}
		case BootstrapActivationWritten:
			database, candidate = e.replayDatabase(ctx, j)
			if database.Database.Name == "" {
				return e.recovery(ctx, j, "migration_replay_failed")
			}
			activation = e.activation(*j, database)
			if err := e.verifySlot(ctx, *j); err != nil {
				return e.recovery(ctx, j, "activation_state_failed")
			}
			pointer, err := e.Store.PublishInitialPointers(ctx, *j, activation)
			if err != nil || !validSHA(pointer) {
				return e.recovery(ctx, j, "pointer_publish_failed")
			}
			j.PointerStateSHA256 = pointer
			if err := e.advance(ctx, j, BootstrapPointersPublished, pointer); err != nil {
				return e.recovery(ctx, j, "pointer_journal_failed")
			}
		case BootstrapPointersPublished:
			if err := e.verifyPointers(ctx, *j, true); err != nil {
				return e.recovery(ctx, j, "pointer_state_failed")
			}
			if err := e.Services.EnableInternal(ctx); err != nil {
				return e.recovery(ctx, j, "internal_enable_failed")
			}
			if err := e.Services.StartInternal(ctx); err != nil {
				return e.recovery(ctx, j, "internal_start_failed")
			}
			if err := e.Services.HealthInternal(ctx); err != nil {
				return e.recovery(ctx, j, "internal_health_failed")
			}
			snapshot, err := e.Services.Capture(ctx)
			if err != nil || !bootstrapInternalSnapshot(snapshot) {
				return e.recovery(ctx, j, "internal_snapshot_failed")
			}
			j.ServiceSnapshot, j.InternalHealthSHA256 = &snapshot, bootstrapServiceEvidence(snapshot, "internal")
			if err := e.advance(ctx, j, BootstrapInternalHealthy, j.InternalHealthSHA256); err != nil {
				return e.recovery(ctx, j, "internal_journal_failed")
			}
		case BootstrapInternalHealthy:
			if err := e.verifyPointers(ctx, *j, true); err != nil || j.ServiceSnapshot == nil || !bootstrapInternalSnapshot(*j.ServiceSnapshot) {
				return e.recovery(ctx, j, "internal_state_failed")
			}
			if err := e.Services.EnableInternal(ctx); err != nil {
				return e.recovery(ctx, j, "internal_enable_failed")
			}
			if err := e.Services.StartInternal(ctx); err != nil {
				return e.recovery(ctx, j, "internal_start_failed")
			}
			if err := e.Services.HealthInternal(ctx); err != nil {
				return e.recovery(ctx, j, "internal_health_failed")
			}
			internalSnapshot, err := e.Services.Capture(ctx)
			if err != nil || !bootstrapInternalSnapshot(internalSnapshot) || j.InternalHealthSHA256 != bootstrapServiceEvidence(internalSnapshot, "internal") {
				return e.recovery(ctx, j, "internal_snapshot_failed")
			}
			if err := e.Store.Marker(ctx, false); err != nil {
				return e.recovery(ctx, j, "marker_remove_failed")
			}
			if err := e.Services.EnableEdge(ctx); err != nil {
				return e.recovery(ctx, j, "edge_enable_failed")
			}
			if err := e.Services.StartEdge(ctx); err != nil {
				return e.recovery(ctx, j, "edge_start_failed")
			}
			if err := e.Services.HealthEdge(ctx); err != nil {
				return e.recovery(ctx, j, "edge_health_failed")
			}
			snapshot, err := e.Services.Capture(ctx)
			if err != nil || !bootstrapFinalSnapshot(snapshot) {
				return e.recovery(ctx, j, "edge_snapshot_failed")
			}
			j.EdgeHealthSHA256 = bootstrapServiceEvidence(snapshot, "edge")
			if err := e.advance(ctx, j, BootstrapEdgeHealthy, j.EdgeHealthSHA256); err != nil {
				return e.recovery(ctx, j, "edge_journal_failed")
			}
		case BootstrapEdgeHealthy:
			if err := e.verifyPointers(ctx, *j, false); err != nil {
				return e.recovery(ctx, j, "commit_pointer_failed")
			}
			if err := e.Services.HealthInternal(ctx); err != nil {
				return e.recovery(ctx, j, "commit_internal_health_failed")
			}
			if err := e.Services.HealthEdge(ctx); err != nil {
				return e.recovery(ctx, j, "commit_edge_health_failed")
			}
			snapshot, err := e.Services.Capture(ctx)
			if err != nil || !bootstrapFinalSnapshot(snapshot) || j.EdgeHealthSHA256 != bootstrapServiceEvidence(snapshot, "edge") {
				return e.recovery(ctx, j, "commit_service_failed")
			}
			if err := e.advance(ctx, j, BootstrapCommitted, bootstrapEvidence(*j, BootstrapEdgeHealthy, BootstrapCommitted)); err != nil {
				return e.recovery(ctx, j, "commit_journal_failed")
			}
		case BootstrapCommitted:
			if err := e.convergeCommitted(ctx, *j); err != nil {
				return e.committedFailure(ctx, j.TransactionID)
			}
			return nil
		default:
			return e.recovery(ctx, j, "invalid_state")
		}
	}
}

func (e *BootstrapEngine) replayDatabase(ctx context.Context, j *BootstrapJournalV1) (BootstrapDatabaseResult, BootstrapCandidateDatabase) {
	candidate, err := e.Database.Create(ctx)
	if err != nil || candidate.Validate() != nil || candidate.Name != j.CandidateDatabaseName {
		return BootstrapDatabaseResult{}, BootstrapCandidateDatabase{}
	}
	database, err := e.Database.Migrate(ctx, candidate)
	if err != nil || database.Validate() != nil || database.Database.Name != j.CandidateDatabaseName || database.Database.SchemaMigrationsSHA256 != j.CandidateDatabaseSchemaSHA256 {
		return BootstrapDatabaseResult{}, BootstrapCandidateDatabase{}
	}
	return database, candidate
}

func (e *BootstrapEngine) activation(j BootstrapJournalV1, database BootstrapDatabaseResult) ActivationV1 {
	return ActivationV1{SchemaVersion: ActivationSchemaVersion, ActivationID: j.CandidateActivationID, Origin: "native", Release: j.Release, Database: database.Database, DatabaseEnvSHA256: sha256Bytes(database.DatabaseEnv), CreatedAt: j.CreatedAt, CreatedByTransactionID: j.TransactionID}
}

func (e *BootstrapEngine) ensureGuard(ctx context.Context, tx string) error {
	if err := e.Store.EnsureMarker(ctx, tx); err != nil {
		_ = e.Services.GuardEdge(ctx)
		return err
	}
	return e.Services.GuardEdge(ctx)
}

func (e *BootstrapEngine) committedFailure(ctx context.Context, tx string) error {
	_ = e.Store.EnsureMarker(ctx, tx)
	_ = e.Services.GuardEdge(ctx)
	return ErrBootstrapRecoveryRequired
}

func (e *BootstrapEngine) convergeCommitted(ctx context.Context, j BootstrapJournalV1) error {
	state, err := e.Store.ReadInitialPointerState(ctx, j.CandidateActivationID)
	if err != nil || !state.ActivationExists || state.ActivationJSONSHA256 != j.ActivationJSONSHA256 || state.ActiveID != j.CandidateActivationID || !state.CurrentPresent || state.PreviousPresent || state.PointerStateSHA256 != j.PointerStateSHA256 {
		return ErrBootstrapConflict
	}
	switch state.MarkerTransactionID {
	case "":
	case j.TransactionID:
		if err := e.Services.GuardEdge(ctx); err != nil || e.Store.Marker(ctx, false) != nil {
			return ErrBootstrapRecoveryRequired
		}
	default:
		return ErrBootstrapConflict
	}
	if err := e.Services.EnableInternal(ctx); err != nil {
		return err
	}
	if err := e.Services.StartInternal(ctx); err != nil {
		return err
	}
	if err := e.Services.HealthInternal(ctx); err != nil {
		return err
	}
	if err := e.Services.EnableEdge(ctx); err != nil {
		return err
	}
	if err := e.Services.StartEdge(ctx); err != nil {
		return err
	}
	if err := e.Services.HealthEdge(ctx); err != nil {
		return err
	}
	snapshot, err := e.Services.Capture(ctx)
	if err != nil || !bootstrapFinalSnapshot(snapshot) || j.InternalHealthSHA256 != bootstrapServiceEvidence(snapshot, "internal") || j.EdgeHealthSHA256 != bootstrapServiceEvidence(snapshot, "edge") {
		return ErrBootstrapRecoveryRequired
	}
	return nil
}

func (e *BootstrapEngine) verifySlot(ctx context.Context, j BootstrapJournalV1) error {
	state, err := e.Store.ReadInitialPointerState(ctx, j.CandidateActivationID)
	if err != nil || !state.ActivationExists || state.ActivationJSONSHA256 != j.ActivationJSONSHA256 || state.ActiveID != "" || state.CurrentPresent || state.PreviousPresent || state.MarkerTransactionID != j.TransactionID {
		return ErrBootstrapConflict
	}
	return nil
}

func (e *BootstrapEngine) verifyPointers(ctx context.Context, j BootstrapJournalV1, marker bool) error {
	state, err := e.Store.ReadInitialPointerState(ctx, j.CandidateActivationID)
	if err != nil || !state.ActivationExists || state.ActivationJSONSHA256 != j.ActivationJSONSHA256 || state.ActiveID != j.CandidateActivationID || !state.CurrentPresent || state.PreviousPresent || state.PointerStateSHA256 != j.PointerStateSHA256 {
		return ErrBootstrapConflict
	}
	if marker && state.MarkerTransactionID != j.TransactionID || !marker && state.MarkerTransactionID != "" {
		return ErrBootstrapConflict
	}
	return nil
}

func (e *BootstrapEngine) advance(ctx context.Context, j *BootstrapJournalV1, to BootstrapState, evidenceSHA256 string) error {
	next := *j
	next.History = append([]BootstrapHistoryV1(nil), j.History...)
	if ValidateBootstrapTransition(next.State, to) != nil || !validSHA(evidenceSHA256) {
		return ErrBootstrapConflict
	}
	at := e.now()
	if at.Before(next.UpdatedAt) {
		return ErrBootstrapConflict
	}
	next.Revision++
	next.History = append(next.History, BootstrapHistoryV1{Revision: next.Revision, From: next.State, To: to, At: at, EvidenceSHA256: evidenceSHA256})
	next.State, next.UpdatedAt = to, at
	if next.Validate() != nil || e.Store.Save(ctx, next) != nil {
		return ErrBootstrapConflict
	}
	*j = next
	return nil
}

func (e *BootstrapEngine) recovery(ctx context.Context, j *BootstrapJournalV1, code string) error {
	if j == nil {
		_ = e.Services.GuardEdge(ctx)
		return ErrBootstrapRecoveryRequired
	}
	if j.State == BootstrapRecoveryRequired {
		_ = e.Store.EnsureMarker(ctx, j.TransactionID)
		_ = e.Services.GuardEdge(ctx)
		return ErrBootstrapRecoveryRequired
	}
	_ = e.Store.EnsureMarker(ctx, j.TransactionID)
	_ = e.Services.GuardEdge(ctx)
	next := *j
	next.History = append([]BootstrapHistoryV1(nil), j.History...)
	at := e.now()
	if at.Before(next.UpdatedAt) {
		at = next.UpdatedAt
	}
	failureDigest := bootstrapFailureDigest(code)
	next.Revision++
	next.History = append(next.History, BootstrapHistoryV1{Revision: next.Revision, From: next.State, To: BootstrapRecoveryRequired, At: at, EvidenceSHA256: failureDigest})
	next.State, next.UpdatedAt = BootstrapRecoveryRequired, at
	next.Failure = &BootstrapFailureV1{Code: sanitizeBootstrapCode(code), Digest: failureDigest}
	if next.Validate() == nil {
		if err := e.Store.Save(ctx, next); err == nil {
			*j = next
		}
	}
	return ErrBootstrapRecoveryRequired
}

func (e *BootstrapEngine) now() time.Time { return e.Now().UTC() }

func bootstrapInternalSnapshot(s ServiceSnapshotV1) bool {
	return s.Agent.Active && s.Agent.Enabled && s.Server.Active && s.Server.Enabled && s.Caddy.Active && s.Caddy.Enabled && s.BuildKit.Active && s.BuildKit.Enabled && !s.Edge.Active
}
func bootstrapFinalSnapshot(s ServiceSnapshotV1) bool {
	return s.Agent.Active && s.Agent.Enabled && s.Server.Active && s.Server.Enabled && s.Caddy.Active && s.Caddy.Enabled && s.BuildKit.Active && s.BuildKit.Enabled && s.Edge.Active && s.Edge.Enabled
}

func bootstrapServiceEvidence(s ServiceSnapshotV1, phase string) string {
	if phase == "internal" {
		// The public unit may already be enabled after a crash, while the marker
		// still guarantees it is stopped. Internal health evidence binds only
		// its stopped state; final Edge evidence binds enabled+active policy.
		s.Edge = UnitSnapshotV1{}
	}
	payload := struct {
		Phase string            `json:"phase"`
		Units ServiceSnapshotV1 `json:"units"`
	}{phase, s}
	raw, _ := json.Marshal(payload)
	return sha256Bytes(raw)
}

func bootstrapTypedEvidence(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return sha256Bytes(raw)
}

func bootstrapEvidence(j BootstrapJournalV1, from, to BootstrapState) string {
	payload := struct {
		Revision     int64          `json:"revision"`
		From         BootstrapState `json:"from"`
		To           BootstrapState `json:"to"`
		Installation string         `json:"installation"`
		Manifest     string         `json:"manifest"`
		Activation   string         `json:"activation"`
		Database     string         `json:"database"`
		Schema       string         `json:"schema,omitempty"`
		Pointer      string         `json:"pointer,omitempty"`
		Internal     string         `json:"internal,omitempty"`
		Edge         string         `json:"edge,omitempty"`
	}{j.Revision, from, to, j.InstallationIDSHA256, j.Release.ManifestSHA256, j.CandidateActivationID, j.CandidateDatabaseName, j.CandidateDatabaseSchemaSHA256, j.PointerStateSHA256, j.InternalHealthSHA256, j.EdgeHealthSHA256}
	raw, _ := json.Marshal(payload)
	return sha256Bytes(raw)
}

func bootstrapFailureDigest(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}
func sanitizeBootstrapCode(code string) string {
	if validID(code) {
		return code
	}
	return "bootstrap_failure"
}
