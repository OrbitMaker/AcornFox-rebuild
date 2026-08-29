package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

var ErrUpgradeLocked = errors.New("upgrade lock is unavailable")
var ErrUpgradeConflict = errors.New("upgrade transaction conflicts with existing journal")

type UpgradePhaseError struct {
	Phase JournalState
	Code  string
}

func (e UpgradePhaseError) Error() string {
	return "upgrade stopped at " + string(e.Phase) + ": " + e.Code
}

type UpgradeRequest struct {
	TransactionID           string
	CandidateRelease        ReleaseV1
	CandidateActivationID   string
	CandidateDatabaseName   string
	CandidateDatabaseEnv    []byte
	RequestedManifestSHA256 string
	ExpectedLegacy          bool
}

type UpgradeLock interface{ Release() error }

type UpgradeJournalStore interface {
	Acquire(context.Context, string) (UpgradeLock, error)
	Preflight(context.Context, string) (ActivationV1, string, bool, error)
	CreateJournal(context.Context, UpgradeJournalV1) error
	SaveJournal(context.Context, UpgradeJournalV1) error
	Marker(context.Context, bool) error
	WriteCandidateActivation(context.Context, ActivationV1, []byte) (string, error)
	SetPrevious(context.Context, string) error
	SwapActive(context.Context, string) error
}

type UpgradeDatabaseDriver interface {
	Drain(context.Context) error
	Snapshot(context.Context) (SnapshotEvidence, string, error)
	CreateRestore(context.Context, string) error
	Migrate(context.Context) (MigrationEvidence, error)
	Validate(context.Context, string) (ArtifactV1, error)
}

type UpgradeServiceDriver interface {
	Capture(context.Context) (ServiceSnapshotV1, error)
	Quiesce(context.Context) error
	StartInternal(context.Context) error
	HealthInternal(context.Context) error
	StartEdge(context.Context) error
	HealthEdge(context.Context) error
}

type UpgradeEngine struct {
	Store    UpgradeJournalStore
	Database UpgradeDatabaseDriver
	Services UpgradeServiceDriver
	Now      func() time.Time
}

func upgradeError(phase JournalState, code string) error {
	return UpgradePhaseError{Phase: phase, Code: code}
}

func sha256Bytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func validUpgradeRequest(r UpgradeRequest) bool {
	if !validID(r.TransactionID) || !r.CandidateRelease.valid() || !validID(r.CandidateActivationID) || !candidateDatabaseName.MatchString(r.CandidateDatabaseName) || !validSHA(r.RequestedManifestSHA256) || r.CandidateRelease.ManifestSHA256 != r.RequestedManifestSHA256 {
		return false
	}
	_, err := ParseDatabaseEnv(r.CandidateDatabaseEnv)
	return err == nil
}

func transitionEvidenceSHA256(j UpgradeJournalV1, from, to JournalState) string {
	// This canonical envelope intentionally contains only durable identifiers and
	// digests. In particular it never serializes database.env or its decoded DSN.
	payload := struct {
		Revision                   int64        `json:"revision"`
		From                       JournalState `json:"from"`
		To                         JournalState `json:"to"`
		RequestedManifestSHA256    string       `json:"requested_manifest_sha256"`
		OldActivationJSONSHA256    string       `json:"old_activation_json_sha256"`
		CandidateActivationID      string       `json:"candidate_activation_id"`
		CandidateActivationJSONSHA string       `json:"candidate_activation_json_sha256,omitempty"`
		CandidateDatabaseName      string       `json:"candidate_database_name"`
		SnapshotSHA256             string       `json:"snapshot_sha256,omitempty"`
		MigrationManifestSHA256    string       `json:"migration_manifest_sha256,omitempty"`
		ValidationSHA256           string       `json:"validation_sha256,omitempty"`
		ServiceSnapshotSHA256      string       `json:"service_snapshot_sha256"`
	}{
		Revision:                   j.Revision + 1,
		From:                       from,
		To:                         to,
		RequestedManifestSHA256:    j.RequestedManifestSHA256,
		OldActivationJSONSHA256:    j.OldActivationJSONSHA256,
		CandidateActivationID:      j.CandidateActivationID,
		CandidateActivationJSONSHA: j.CandidateActivationJSONSHA256,
		CandidateDatabaseName:      j.CandidateDatabaseName,
		ServiceSnapshotSHA256:      CanonicalServiceSnapshotSHA256(j.ServiceSnapshot),
	}
	if j.Snapshot != nil {
		payload.SnapshotSHA256 = j.Snapshot.SHA256
	}
	if j.Migration != nil {
		payload.MigrationManifestSHA256 = j.Migration.ManifestSHA256
	}
	if j.Validation != nil {
		payload.ValidationSHA256 = j.Validation.SHA256
	}
	raw, _ := json.Marshal(payload)
	return sha256Bytes(raw)
}

func (e *UpgradeEngine) now() time.Time { return e.Now().UTC() }

func (e *UpgradeEngine) advance(ctx context.Context, j *UpgradeJournalV1, to JournalState) error {
	from := j.State
	if err := ValidateJournalTransition(from, to); err != nil {
		return upgradeError(to, "invalid_transition")
	}
	at := e.now()
	if at.Before(j.UpdatedAt) {
		return upgradeError(to, "clock_regressed")
	}
	j.History = append(j.History, JournalTransitionV1{Revision: j.Revision + 1, From: from, To: to, At: at, EvidenceSHA256: transitionEvidenceSHA256(*j, from, to)})
	j.Revision++
	j.State, j.UpdatedAt = to, at
	if err := j.Validate(); err != nil {
		return upgradeError(to, "invalid_journal")
	}
	if err := e.Store.SaveJournal(ctx, *j); err != nil {
		return upgradeError(to, "save_journal_failed")
	}
	return nil
}

func (e *UpgradeEngine) RunNew(ctx context.Context, r UpgradeRequest) error {
	if e == nil || e.Store == nil || e.Database == nil || e.Services == nil || e.Now == nil || !validUpgradeRequest(r) {
		return upgradeError(JournalPreflighted, "invalid_request")
	}
	lock, err := e.Store.Acquire(ctx, r.TransactionID)
	if err != nil || lock == nil {
		return ErrUpgradeLocked
	}
	defer lock.Release()

	old, oldJSONSHA256, actualLegacy, err := e.Store.Preflight(ctx, r.TransactionID)
	if err != nil || old.Validate() != nil || !validSHA(oldJSONSHA256) || actualLegacy != r.ExpectedLegacy {
		return upgradeError(JournalPreflighted, "preflight_failed")
	}
	serviceSnapshot, err := e.Services.Capture(ctx)
	if err != nil {
		return upgradeError(JournalPreflighted, "service_capture_failed")
	}
	now := e.now()
	j := UpgradeJournalV1{
		SchemaVersion:           ActivationSchemaVersion,
		TransactionID:           r.TransactionID,
		Revision:                1,
		State:                   JournalPreflighted,
		CreatedAt:               now,
		UpdatedAt:               now,
		RequestedManifestSHA256: r.RequestedManifestSHA256,
		OldActivationID:         old.ActivationID,
		OldActivationJSONSHA256: oldJSONSHA256,
		CandidateActivationID:   r.CandidateActivationID,
		CandidateDatabaseName:   r.CandidateDatabaseName,
		ServiceSnapshot:         serviceSnapshot,
		History:                 []JournalTransitionV1{},
	}
	if err := j.Validate(); err != nil {
		return upgradeError(JournalPreflighted, "invalid_journal")
	}
	if err := e.Store.CreateJournal(ctx, j); err != nil {
		if errors.Is(err, ErrUpgradeConflict) {
			return ErrUpgradeConflict
		}
		return upgradeError(JournalPreflighted, "create_journal_failed")
	}
	if actualLegacy {
		if err := e.advance(ctx, &j, JournalLegacyProjected); err != nil {
			return err
		}
	}
	if err := e.Store.Marker(ctx, true); err != nil {
		return upgradeError(j.State, "marker_create_failed")
	}
	if err := e.Services.Quiesce(ctx); err != nil {
		return upgradeError(JournalQuiesced, "service_quiesce_failed")
	}
	if err := e.Database.Drain(ctx); err != nil {
		return upgradeError(JournalQuiesced, "database_drain_failed")
	}
	if err := e.advance(ctx, &j, JournalQuiesced); err != nil {
		return err
	}
	if evidence, sourceDatabase, err := e.Database.Snapshot(ctx); err != nil {
		return upgradeError(JournalSnapshotCreated, "snapshot_failed")
	} else {
		j.Snapshot = &ArtifactV1{Path: artifactPath(j.TransactionID, "control-plane.dump"), SHA256: evidence.SHA256, Size: evidence.Size, SourceDatabase: sourceDatabase}
		if err := e.advance(ctx, &j, JournalSnapshotCreated); err != nil {
			return err
		}
	}
	if err := e.Database.CreateRestore(ctx, r.CandidateDatabaseName); err != nil {
		return upgradeError(JournalCandidateDBReady, "candidate_database_failed")
	}
	if err := e.advance(ctx, &j, JournalCandidateDBReady); err != nil {
		return err
	}
	if evidence, err := e.Database.Migrate(ctx); err != nil {
		return upgradeError(JournalMigrated, "migration_failed")
	} else {
		j.CandidateDatabase = &DatabaseV1{Name: r.CandidateDatabaseName, Migration: evidence.To, SchemaMigrationsSHA256: evidence.RowsSHA256}
		j.Migration = &MigrationV1{From: evidence.From, To: evidence.To, ManifestSHA256: evidence.RowsSHA256}
		if err := e.advance(ctx, &j, JournalMigrated); err != nil {
			return err
		}
	}
	candidate := ActivationV1{SchemaVersion: ActivationSchemaVersion, ActivationID: r.CandidateActivationID, Origin: "upgrade", Release: r.CandidateRelease, Database: *j.CandidateDatabase, DatabaseEnvSHA256: sha256Bytes(r.CandidateDatabaseEnv), CreatedAt: e.now(), CreatedByTransactionID: r.TransactionID}
	if actualLegacy {
		candidate.LegacyProjection = &LegacyProjectionV1{Target: "/opt/open-card/releases/" + r.CandidateRelease.ID}
	}
	if err := candidate.Validate(); err != nil {
		return upgradeError(JournalValidated, "invalid_candidate_activation")
	}
	candidateJSONSHA256, err := e.Store.WriteCandidateActivation(ctx, candidate, r.CandidateDatabaseEnv)
	if err != nil || !validSHA(candidateJSONSHA256) {
		return upgradeError(JournalValidated, "write_candidate_activation_failed")
	}
	validation, err := e.Database.Validate(ctx, r.CandidateActivationID)
	if err != nil {
		return upgradeError(JournalValidated, "validation_failed")
	}
	j.CandidateActivationJSONSHA256, j.Validation = candidateJSONSHA256, &validation
	if err := e.advance(ctx, &j, JournalValidated); err != nil {
		return err
	}
	if err := e.Store.SetPrevious(ctx, old.ActivationID); err != nil {
		return upgradeError(JournalActiveSwitched, "set_previous_failed")
	}
	if err := e.Store.SwapActive(ctx, r.CandidateActivationID); err != nil {
		return upgradeError(JournalActiveSwitched, "swap_active_failed")
	}
	if err := e.advance(ctx, &j, JournalActiveSwitched); err != nil {
		return err
	}
	if err := e.Services.StartInternal(ctx); err != nil {
		return upgradeError(JournalHealthy, "start_internal_failed")
	}
	if err := e.Services.HealthInternal(ctx); err != nil {
		return upgradeError(JournalHealthy, "internal_health_failed")
	}
	if err := e.advance(ctx, &j, JournalHealthy); err != nil {
		return err
	}
	if err := e.advance(ctx, &j, JournalEdgeArmed); err != nil {
		return err
	}
	if err := e.Store.Marker(ctx, false); err != nil {
		return upgradeError(JournalEdgeArmed, "marker_remove_failed")
	}
	if err := e.Services.StartEdge(ctx); err != nil {
		return upgradeError(JournalEdgeArmed, "start_edge_failed")
	}
	if err := e.Services.HealthEdge(ctx); err != nil {
		return upgradeError(JournalEdgeArmed, "edge_health_failed")
	}
	if err := e.advance(ctx, &j, JournalCommitted); err != nil {
		return err
	}
	return nil
}
