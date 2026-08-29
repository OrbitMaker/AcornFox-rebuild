package install

import (
	"bytes"
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
	cause error
}

func (e UpgradePhaseError) Error() string {
	return "upgrade stopped at " + string(e.Phase) + ": " + e.Code
}
func (e UpgradePhaseError) Unwrap() error { return e.cause }

type UpgradeActivationState struct {
	ActiveID, PreviousID                           string
	ActiveActivationJSONSHA256, PreviousJSONSHA256 string
	Marker                                         bool
}

type UpgradeActualState struct {
	ActiveID, PreviousID                                   string
	MarkerTransactionID                                    string
	OldActivationJSONSHA256, CandidateActivationJSONSHA256 string
	PreviousActivationJSONSHA256                           string
	OldActivationExists, CandidateActivationExists         bool
}

type UpgradeRequest struct {
	TransactionID           string
	CandidateRelease        ReleaseV1
	CandidateActivationID   string
	CandidateDatabaseName   string
	RequestedManifestSHA256 string
	ExpectedLegacy          bool
}

// UpgradeEligibilityV1 is the secret-free result of a locked, read-only
// preflight. It proves only the immutable identities needed to decide whether
// a later upgrade run may be attempted; it never publishes an activation,
// creates a journal, or retains database environment bytes.
type UpgradeEligibilityV1 struct {
	SchemaVersion                  int    `json:"schema_version"`
	TransactionID                  string `json:"transaction_id"`
	Layout                         string `json:"layout"`
	CandidateReleaseID             string `json:"candidate_release_id"`
	CandidateReleaseManifestSHA256 string `json:"candidate_release_manifest_sha256"`
	OldActivationID                string `json:"old_activation_id"`
	OldActivationJSONSHA256        string `json:"old_activation_json_sha256"`
	OldEligibilitySHA256           string `json:"old_eligibility_sha256"`
	CandidateActivationID          string `json:"candidate_activation_id"`
}

type UpgradeLock interface{ Release() error }

type UpgradeJournalStore interface {
	Acquire(context.Context, string) (UpgradeLock, error)
	LoadJournal(context.Context, string) (UpgradeJournalV1, error)
	ReadActualState(context.Context, string, string) (UpgradeActualState, error)
	EnsureMarker(context.Context, string) error
	PreflightPlan(context.Context, UpgradePreflightRequest) (UpgradePreflight, error)
	PrepareLegacyProjection(context.Context, LegacyProjectionPlan, ActivationV1) (LegacyProjectionObservation, error)
	FinalizeLegacyProjection(context.Context, LegacyProjectionPlan, ActivationV1) (LegacyProjectionObservation, error)
	ReadLegacyProjection(context.Context, LegacyProjectionPlan, ActivationV1) (LegacyProjectionObservation, error)
	RecoverLegacyPlan(context.Context, ActivationV1, string) (LegacyProjectionPlan, error)
	ReadActivationState(context.Context) (UpgradeActivationState, error)
	CreateJournal(context.Context, UpgradeJournalV1) error
	SaveJournal(context.Context, UpgradeJournalV1) error
	Marker(context.Context, bool) error
	WriteCandidateActivation(context.Context, ActivationV1, []byte) (string, error)
	SetPrevious(context.Context, string) error
	RestorePrevious(context.Context, string, string, string) error
	SwapActive(context.Context, string) error
	RestoreActive(context.Context, string, string) error
}

type UpgradeDatabaseDriver interface {
	InspectActive(context.Context, ActiveDatabaseInspectionRequest) (DatabaseV1, error)
	Drain(context.Context) error
	Snapshot(context.Context) (SnapshotEvidence, string, error)
	CreateRestore(context.Context, string) error
	Migrate(context.Context) (UpgradeMigrationEvidence, error)
	Validate(context.Context, string) (ArtifactV1, error)
}

// UpgradeDatabaseOpenRequest is the complete non-secret identity a locked
// database session may use.  The active environment is supplied only from a
// validated preflight result and remains in memory.
type UpgradeDatabaseOpenRequest struct {
	TransactionID         string
	CandidateRelease      ReleaseV1
	CandidateActivationID string
	CandidateDatabaseName string
	ActiveDatabaseEnv     []byte `json:"-"`
}

func (r UpgradeDatabaseOpenRequest) Validate() error {
	if !validID(r.TransactionID) || !validID(r.CandidateActivationID) || !candidateDatabaseName.MatchString(r.CandidateDatabaseName) {
		return errors.New("invalid upgrade database open request")
	}
	name, err := CandidateDatabaseName(r.CandidateActivationID)
	if err != nil || name != r.CandidateDatabaseName {
		return errors.New("invalid upgrade database candidate")
	}
	if r.CandidateRelease.ID != "" && !r.CandidateRelease.valid() {
		return errors.New("invalid upgrade database release")
	}
	_, err = ParseDatabaseEnv(r.ActiveDatabaseEnv)
	return err
}

// UpgradeDatabaseSession binds all mutable candidate work to one active
// database identity for the lifetime of the upgrade lock.
type UpgradeDatabaseSession interface {
	UpgradeDatabaseDriver
	CandidateDatabaseEnv() []byte
	Close() error
}

type UpgradeDatabaseFactory interface {
	Open(context.Context, UpgradeDatabaseOpenRequest) (UpgradeDatabaseSession, error)
}

// UpgradeMigrationEvidence keeps the independently verified candidate schema
// rows distinct from the release manifest that authorized their migration.
type UpgradeMigrationEvidence struct {
	From, To              string
	RowsSHA256            string
	ReleaseManifestSHA256 string
}

type UpgradeServiceDriver interface {
	Capture(context.Context) (ServiceSnapshotV1, error)
	Quiesce(context.Context) error
	StartInternal(context.Context) error
	HealthInternal(context.Context) error
	StartEdge(context.Context) error
	HealthEdge(context.Context) error
	GuardEdge(context.Context) error
	ReloadServerUnit(context.Context, string) error
	RestoreSnapshot(context.Context, ServiceSnapshotV1) error
	HealthRestoredInternal(context.Context) error
	RestoreEdge(context.Context, ServiceSnapshotV1) error
}

func legacyActivation(plan LegacyProjectionPlan, database DatabaseV1, createdAt time.Time) (ActivationV1, string, error) {
	if plan.Validate() != nil || database.Migration != plan.ExpectedMigration || database.SchemaMigrationsSHA256 != plan.ExpectedRowsSHA256 || !database.valid() {
		return ActivationV1{}, "", errors.New("invalid legacy activation facts")
	}
	activation := ActivationV1{
		SchemaVersion:          ActivationSchemaVersion,
		ActivationID:           plan.ActivationID,
		Origin:                 "rc0_compat_projection",
		Release:                plan.Release,
		Database:               database,
		DatabaseEnvSHA256:      plan.DatabaseEnvSHA256,
		CreatedAt:              createdAt.UTC(),
		CreatedByTransactionID: plan.TransactionID,
		LegacyProjection: &LegacyProjectionV1{
			Target:                 plan.CurrentTarget,
			ServerEnvBeforeSHA256:  plan.ServerEnvBeforeSHA256,
			ServerEnvAfterSHA256:   plan.ServerEnvAfterSHA256,
			ServerUnitBeforeSHA256: plan.ServerUnitBeforeSHA256,
			ServerUnitAfterSHA256:  plan.ServerUnitAfterSHA256,
			ServerUnitReleaseID:    plan.ServerUnitReleaseID,
		},
	}
	digest, err := CanonicalActivationJSONSHA256(activation)
	if err != nil || activation.Validate() != nil {
		return ActivationV1{}, "", errors.New("invalid legacy activation")
	}
	return activation, digest, nil
}

func sameDatabase(left, right DatabaseV1) bool {
	return left.Name == right.Name && left.Migration == right.Migration && left.SchemaMigrationsSHA256 == right.SchemaMigrationsSHA256
}

func inspectionRequestForActivation(databaseEnv []byte, activation ActivationV1) (ActiveDatabaseInspectionRequest, error) {
	count := 0
	switch activation.Database.Migration {
	case "0023":
		count = 23
	case "0024":
		count = 24
	default:
		return ActiveDatabaseInspectionRequest{}, errors.New("unsupported active migration")
	}
	request := ActiveDatabaseInspectionRequest{DatabaseEnv: append([]byte(nil), databaseEnv...), ExpectedMigration: activation.Database.Migration, ExpectedRowsSHA256: activation.Database.SchemaMigrationsSHA256, ExpectedRowCount: count}
	if err := request.Validate(); err != nil {
		return ActiveDatabaseInspectionRequest{}, err
	}
	return request, nil
}

func expectedLegacyObservation(plan LegacyProjectionPlan, activation ActivationV1, digest string) LegacyProjectionObservation {
	return LegacyProjectionObservation{
		ActivationID:         activation.ActivationID,
		ActivationJSONSHA256: digest,
		DatabaseEnvSHA256:    activation.DatabaseEnvSHA256,
		Active:               ActivationPointerIdentity{ID: activation.ActivationID, JSONSHA256: digest},
		Previous:             plan.Previous,
		CurrentTarget:        legacyCurrentTarget,
		ServerEnvSHA256:      plan.ServerEnvAfterSHA256,
		ServerUnitSHA256:     plan.ServerUnitAfterSHA256,
	}
}

func sameLegacyObservation(left, right LegacyProjectionObservation) bool {
	return left.ActivationID == right.ActivationID && left.ActivationJSONSHA256 == right.ActivationJSONSHA256 && left.DatabaseEnvSHA256 == right.DatabaseEnvSHA256 && left.Active.equal(right.Active) && left.Previous.equal(right.Previous) && left.CurrentTarget == right.CurrentTarget && left.ServerEnvSHA256 == right.ServerEnvSHA256 && left.ServerUnitSHA256 == right.ServerUnitSHA256
}

type UpgradeEngine struct {
	Store           UpgradeJournalStore
	DatabaseFactory UpgradeDatabaseFactory
	Services        UpgradeServiceDriver
	Now             func() time.Time
}

// Preflight performs the minimum locked inspection needed to decide upgrade
// eligibility. It deliberately has no journal, marker, pointer, unit,
// artifact, service, snapshot, drain, or candidate-database side effects.
func (e *UpgradeEngine) Preflight(ctx context.Context, r UpgradeRequest) (result UpgradeEligibilityV1, returnErr error) {
	if e == nil || e.Store == nil || e.DatabaseFactory == nil || e.Now == nil || !validUpgradeRequest(r) {
		return UpgradeEligibilityV1{}, upgradeError(JournalPreflighted, "invalid_request")
	}
	lock, err := acquireUpgradeLock(ctx, e.Store, r.TransactionID, JournalPreflighted)
	if err != nil {
		return UpgradeEligibilityV1{}, err
	}
	defer func() {
		if err := lock.Release(); err != nil && returnErr == nil {
			result = UpgradeEligibilityV1{}
			returnErr = upgradeError(JournalPreflighted, "preflight_lock_release_failed")
		}
	}()

	preflight, err := e.Store.PreflightPlan(ctx, UpgradePreflightRequest{TransactionID: r.TransactionID, CandidateRelease: r.CandidateRelease})
	if err != nil || preflight.ValidateForRequest(UpgradePreflightRequest{TransactionID: r.TransactionID, CandidateRelease: r.CandidateRelease}) != nil || (preflight.Legacy != nil) != r.ExpectedLegacy {
		return UpgradeEligibilityV1{}, upgradeError(JournalPreflighted, "preflight_failed")
	}

	var old ActivationV1
	var oldDigest string
	var oldEligibility string
	var databaseEnv []byte
	var inspectRequest ActiveDatabaseInspectionRequest
	if preflight.Legacy != nil {
		databaseEnv = append([]byte(nil), preflight.Legacy.DatabaseEnv...)
		inspectRequest = ActiveDatabaseInspectionRequest{DatabaseEnv: databaseEnv, ExpectedMigration: preflight.Legacy.ExpectedMigration, ExpectedRowsSHA256: preflight.Legacy.ExpectedRowsSHA256, ExpectedRowCount: 23}
	} else {
		old, oldDigest = preflight.Existing.Activation, preflight.Existing.JSONSHA256
		oldEligibility = oldDigest
		databaseEnv = append([]byte(nil), preflight.Existing.DatabaseEnv...)
		inspectRequest, err = inspectionRequestForActivation(databaseEnv, old)
		if err != nil {
			return UpgradeEligibilityV1{}, upgradeError(JournalPreflighted, "preflight_failed")
		}
	}

	// An empty CandidateRelease selects the factory's inspection-only session.
	// This keeps preflight from constructing candidate tooling or artifact paths.
	database, err := e.DatabaseFactory.Open(ctx, UpgradeDatabaseOpenRequest{
		TransactionID:         r.TransactionID,
		CandidateActivationID: r.CandidateActivationID,
		CandidateDatabaseName: r.CandidateDatabaseName,
		ActiveDatabaseEnv:     databaseEnv,
	})
	if err != nil || database == nil {
		return UpgradeEligibilityV1{}, upgradeError(JournalPreflighted, "database_open_failed")
	}
	defer func() {
		if err := database.Close(); err != nil && returnErr == nil {
			result = UpgradeEligibilityV1{}
			returnErr = upgradeError(JournalPreflighted, "preflight_database_close_failed")
		}
	}()
	inspected, err := database.InspectActive(ctx, inspectRequest)
	if err != nil {
		return UpgradeEligibilityV1{}, upgradeError(JournalPreflighted, "preflight_failed")
	}
	if preflight.Legacy != nil {
		if !inspected.valid() || inspected.Migration != preflight.Legacy.ExpectedMigration || inspected.SchemaMigrationsSHA256 != preflight.Legacy.ExpectedRowsSHA256 {
			return UpgradeEligibilityV1{}, upgradeError(JournalPreflighted, "preflight_failed")
		}
		old.ActivationID = preflight.Legacy.ActivationID
		oldEligibility = legacyPreflightEligibilitySHA256(*preflight.Legacy, inspected)
	} else if !sameDatabase(inspected, old.Database) {
		return UpgradeEligibilityV1{}, upgradeError(JournalPreflighted, "preflight_failed")
	}

	layout := "native"
	if preflight.Legacy != nil {
		layout = "rc0_compat_projection"
	}
	return UpgradeEligibilityV1{
		SchemaVersion:                  ActivationSchemaVersion,
		TransactionID:                  r.TransactionID,
		Layout:                         layout,
		CandidateReleaseID:             r.CandidateRelease.ID,
		CandidateReleaseManifestSHA256: r.CandidateRelease.ManifestSHA256,
		OldActivationID:                old.ActivationID,
		OldActivationJSONSHA256:        oldDigest,
		OldEligibilitySHA256:           oldEligibility,
		CandidateActivationID:          r.CandidateActivationID,
	}, nil
}

func acquireUpgradeLock(ctx context.Context, store UpgradeJournalStore, transactionID string, phase JournalState) (UpgradeLock, error) {
	lock, err := store.Acquire(ctx, transactionID)
	if err != nil || lock == nil {
		if errors.Is(err, ErrUpgradeLocked) {
			return nil, ErrUpgradeLocked
		}
		return nil, upgradeError(phase, "upgrade_lock_invalid")
	}
	return lock, nil
}

func legacyPreflightEligibilitySHA256(plan LegacyProjectionPlan, database DatabaseV1) string {
	payload := struct {
		TransactionID      string     `json:"transaction_id"`
		ActivationID       string     `json:"activation_id"`
		Release            ReleaseV1  `json:"release"`
		Database           DatabaseV1 `json:"database"`
		DatabaseEnvSHA256  string     `json:"database_env_sha256"`
		ExpectedRowsSHA256 string     `json:"expected_rows_sha256"`
	}{plan.TransactionID, plan.ActivationID, plan.Release, database, plan.DatabaseEnvSHA256, plan.ExpectedRowsSHA256}
	raw, _ := json.Marshal(payload)
	return sha256Bytes(raw)
}

func upgradeError(phase JournalState, code string) error {
	return UpgradePhaseError{Phase: phase, Code: code}
}
func upgradeErrorWith(phase JournalState, code string, cause error) error {
	return UpgradePhaseError{Phase: phase, Code: code, cause: cause}
}

func sha256Bytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func validUpgradeRequest(r UpgradeRequest) bool {
	if !validID(r.TransactionID) || !r.CandidateRelease.valid() || !validID(r.CandidateActivationID) || !candidateDatabaseName.MatchString(r.CandidateDatabaseName) || !validSHA(r.RequestedManifestSHA256) || r.CandidateRelease.ManifestSHA256 != r.RequestedManifestSHA256 {
		return false
	}
	return true
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
	next := *j
	next.History = append([]JournalTransitionV1(nil), j.History...)
	from := next.State
	if err := ValidateJournalTransition(from, to); err != nil {
		return upgradeError(to, "invalid_transition")
	}
	at := e.now()
	if at.Before(next.UpdatedAt) {
		return upgradeError(to, "clock_regressed")
	}
	next.History = append(next.History, JournalTransitionV1{Revision: next.Revision + 1, From: from, To: to, At: at, EvidenceSHA256: transitionEvidenceSHA256(next, from, to)})
	next.Revision++
	next.State, next.UpdatedAt = to, at
	if err := next.Validate(); err != nil {
		return upgradeError(to, "invalid_journal")
	}
	if err := e.Store.SaveJournal(ctx, next); err != nil {
		return upgradeErrorWith(to, "save_journal_failed", err)
	}
	*j = next
	return nil
}

func outcomeUnknown(err error) bool {
	if err == nil {
		return false
	}
	var phase UpgradePhaseError
	return errors.Is(err, ErrDurableCommitUnknown) || errors.Is(err, ErrPostgresOutcomeUnknown) || errors.Is(err, ErrServiceOutcomeUnknown) || errors.As(err, &phase) && phase.Code == "save_journal_failed"
}

func failureDigest(err error) string {
	var phase UpgradePhaseError
	if errors.As(err, &phase) && phase.cause != nil {
		err = phase.cause
	}
	if err == nil {
		return sha256Bytes(nil)
	}
	return sha256Bytes([]byte(err.Error()))
}

var upgradeFailureCodes = map[string]struct{}{
	"legacy_projection_failed": {}, "marker_create_failed": {}, "service_quiesce_failed": {}, "database_drain_failed": {}, "quiesce_journal_failed": {}, "snapshot_failed": {}, "snapshot_journal_failed": {}, "candidate_database_failed": {}, "candidate_journal_failed": {}, "migration_failed": {}, "migration_journal_failed": {}, "invalid_candidate_activation": {}, "write_candidate_activation_failed": {}, "validation_failed": {}, "validation_journal_failed": {}, "set_previous_failed": {}, "swap_active_failed": {}, "active_journal_failed": {}, "start_internal_failed": {}, "internal_health_failed": {}, "healthy_journal_failed": {}, "edge_journal_failed": {}, "marker_remove_failed": {}, "start_edge_failed": {}, "edge_health_failed": {}, "commit_journal_failed": {},
}

func failureFor(phase JournalState, code string, err error) *FailureV1 {
	if _, ok := upgradeFailureCodes[code]; !ok {
		code = "upgrade_failure"
	}
	return &FailureV1{Code: code, Phase: phase, MessageDigest: failureDigest(err)}
}

func coherentState(s UpgradeActivationState) bool {
	if !validID(s.ActiveID) || !validSHA(s.ActiveActivationJSONSHA256) {
		return false
	}
	if s.PreviousID == "" && s.PreviousJSONSHA256 == "" {
		return true
	}
	return validID(s.PreviousID) && validSHA(s.PreviousJSONSHA256)
}

func sameOldState(s, baseline UpgradeActivationState, old ActivationV1, oldDigest string) bool {
	if !coherentState(s) || s.ActiveID != old.ActivationID || s.ActiveActivationJSONSHA256 != oldDigest {
		return false
	}
	return s.PreviousID == baseline.PreviousID && s.PreviousJSONSHA256 == baseline.PreviousJSONSHA256 || s.PreviousID == old.ActivationID && s.PreviousJSONSHA256 == oldDigest
}

func (e *UpgradeEngine) recoveryRequired(ctx context.Context, j *UpgradeJournalV1, phase JournalState, code string, cause error) error {
	if j == nil {
		_ = e.Services.GuardEdge(ctx)
		return upgradeErrorWith(JournalRecoveryRequired, "recovery_required", cause)
	}
	if err := e.Store.Marker(ctx, true); err != nil {
		_ = e.Services.GuardEdge(ctx)
		return upgradeErrorWith(JournalRecoveryRequired, "recovery_required", cause)
	}
	if err := e.Services.GuardEdge(ctx); err != nil {
		return upgradeErrorWith(JournalRecoveryRequired, "recovery_required", cause)
	}
	if terminal(j.State) {
		return upgradeErrorWith(JournalRecoveryRequired, "recovery_required", cause)
	}
	j.Failure = failureFor(phase, code, cause)
	if err := e.advance(ctx, j, JournalRecoveryRequired); err != nil {
		return upgradeErrorWith(JournalRecoveryRequired, "recovery_required", cause)
	}
	return upgradeErrorWith(JournalRecoveryRequired, "recovery_required", cause)
}

// legacyProjectionPending preserves PREFLIGHTED until the compatibility
// projection has been durably recorded. Prepare/reload/finalize/read errors
// can be retried idempotently; terminalizing them would make the specifically
// journaled legacy recovery path unreachable. Only an unprovable journal
// outcome is escalated to RECOVERY_REQUIRED.
func (e *UpgradeEngine) legacyProjectionPending(ctx context.Context, j *UpgradeJournalV1, transactionID string, cause error) error {
	if err := e.Store.EnsureMarker(ctx, transactionID); err != nil {
		_ = e.Services.GuardEdge(ctx)
		return e.recoveryRequired(ctx, j, JournalLegacyProjected, "legacy_projection_failed", err)
	}
	if err := e.Services.GuardEdge(ctx); err != nil {
		return e.recoveryRequired(ctx, j, JournalLegacyProjected, "legacy_projection_failed", err)
	}
	phase := JournalPreflighted
	if outcomeUnknown(cause) {
		latest, err := e.Store.LoadJournal(ctx, transactionID)
		if err != nil || latest.Validate() != nil || latest.TransactionID != transactionID {
			return e.recoveryRequired(ctx, j, JournalLegacyProjected, "legacy_projection_failed", cause)
		}
		switch latest.State {
		case JournalPreflighted:
		case JournalLegacyProjected:
			phase = JournalLegacyProjected
		default:
			return e.recoveryRequired(ctx, j, JournalLegacyProjected, "legacy_projection_failed", cause)
		}
	}
	return upgradeErrorWith(phase, "legacy_projection_pending", cause)
}

func (e *UpgradeEngine) abortPreSwitch(ctx context.Context, j *UpgradeJournalV1, old ActivationV1, baseline UpgradeActivationState, phase JournalState, code string, cause error) error {
	current, err := e.Store.ReadActivationState(ctx)
	if err != nil || current.ActiveID != old.ActivationID || current.ActiveActivationJSONSHA256 != j.OldActivationJSONSHA256 {
		return e.recoveryRequired(ctx, j, phase, code, cause)
	}
	if current.PreviousID != baseline.PreviousID || current.PreviousJSONSHA256 != baseline.PreviousJSONSHA256 {
		if current.PreviousID != old.ActivationID || current.PreviousJSONSHA256 != j.OldActivationJSONSHA256 {
			return e.recoveryRequired(ctx, j, phase, code, cause)
		}
		if err := e.Store.RestorePrevious(ctx, old.ActivationID, baseline.PreviousID, baseline.PreviousJSONSHA256); err != nil {
			return e.recoveryRequired(ctx, j, phase, code, err)
		}
		current, err = e.Store.ReadActivationState(ctx)
		if err != nil || current.PreviousID != baseline.PreviousID || current.PreviousJSONSHA256 != baseline.PreviousJSONSHA256 {
			return e.recoveryRequired(ctx, j, phase, code, err)
		}
	}
	if err := e.Services.RestoreSnapshot(ctx, j.ServiceSnapshot); err != nil {
		return e.recoveryRequired(ctx, j, phase, code, err)
	}
	if err := e.Services.HealthRestoredInternal(ctx); err != nil {
		return e.recoveryRequired(ctx, j, phase, code, err)
	}
	if err := e.Store.Marker(ctx, false); err != nil {
		return e.recoveryRequired(ctx, j, phase, code, err)
	}
	if !j.ServiceSnapshot.Edge.Active {
		if err := e.Services.GuardEdge(ctx); err != nil {
			return e.recoveryRequired(ctx, j, phase, code, err)
		}
	} else {
		if err := e.Services.RestoreEdge(ctx, j.ServiceSnapshot); err != nil {
			return e.recoveryRequired(ctx, j, phase, code, err)
		}
		if err := e.Services.HealthEdge(ctx); err != nil {
			return e.recoveryRequired(ctx, j, phase, code, err)
		}
	}
	j.Failure = failureFor(phase, code, cause)
	if err := e.advance(ctx, j, JournalAbortedPreSwitch); err != nil {
		return e.recoveryRequired(ctx, j, phase, code, err)
	}
	return upgradeErrorWith(JournalAbortedPreSwitch, code, cause)
}

func (e *UpgradeEngine) rollback(ctx context.Context, j *UpgradeJournalV1, old ActivationV1, phase JournalState, code string, cause error) error {
	if err := e.Store.Marker(ctx, true); err != nil {
		return e.recoveryRequired(ctx, j, phase, code, err)
	}
	if err := e.Services.GuardEdge(ctx); err != nil {
		return e.recoveryRequired(ctx, j, phase, code, err)
	}
	if err := e.Store.RestoreActive(ctx, old.ActivationID, j.CandidateActivationID); err != nil {
		return e.recoveryRequired(ctx, j, phase, code, err)
	}
	current, err := e.Store.ReadActivationState(ctx)
	if err != nil || !coherentState(current) || current.ActiveID != old.ActivationID || current.ActiveActivationJSONSHA256 != j.OldActivationJSONSHA256 || current.PreviousID != j.CandidateActivationID || current.PreviousJSONSHA256 != j.CandidateActivationJSONSHA256 {
		return e.recoveryRequired(ctx, j, phase, code, cause)
	}
	j.Failure = failureFor(phase, code, cause)
	if err := e.advance(ctx, j, JournalRollbackSwitched); err != nil {
		return e.recoveryRequired(ctx, j, phase, code, err)
	}
	if err := e.Services.RestoreSnapshot(ctx, j.ServiceSnapshot); err != nil {
		return e.recoveryRequired(ctx, j, phase, code, err)
	}
	if err := e.Services.HealthRestoredInternal(ctx); err != nil {
		return e.recoveryRequired(ctx, j, phase, code, err)
	}
	if err := e.Store.Marker(ctx, false); err != nil {
		return e.recoveryRequired(ctx, j, phase, code, err)
	}
	if !j.ServiceSnapshot.Edge.Active {
		if err := e.Services.GuardEdge(ctx); err != nil {
			return e.recoveryRequired(ctx, j, phase, code, err)
		}
	} else {
		if err := e.Services.RestoreEdge(ctx, j.ServiceSnapshot); err != nil {
			return e.recoveryRequired(ctx, j, phase, code, err)
		}
		if err := e.Services.HealthEdge(ctx); err != nil {
			return e.recoveryRequired(ctx, j, phase, code, err)
		}
	}
	if err := e.advance(ctx, j, JournalRolledBack); err != nil {
		return e.recoveryRequired(ctx, j, phase, code, err)
	}
	return upgradeErrorWith(JournalRolledBack, code, cause)
}

func (e *UpgradeEngine) handleFailure(ctx context.Context, j *UpgradeJournalV1, old ActivationV1, baseline UpgradeActivationState, phase JournalState, code string, cause error) error {
	if outcomeUnknown(cause) {
		return e.recoveryRequired(ctx, j, phase, code, cause)
	}
	current, err := e.Store.ReadActivationState(ctx)
	if err != nil {
		return e.recoveryRequired(ctx, j, phase, code, cause)
	}
	if sameOldState(current, baseline, old, j.OldActivationJSONSHA256) {
		return e.abortPreSwitch(ctx, j, old, baseline, phase, code, cause)
	}
	if coherentState(current) && current.ActiveID == j.CandidateActivationID && current.ActiveActivationJSONSHA256 == j.CandidateActivationJSONSHA256 && current.PreviousID == old.ActivationID && current.PreviousJSONSHA256 == j.OldActivationJSONSHA256 {
		return e.rollback(ctx, j, old, phase, code, cause)
	}
	return e.recoveryRequired(ctx, j, phase, code, cause)
}

func (e *UpgradeEngine) RunNew(ctx context.Context, r UpgradeRequest) (result error) {
	if e == nil || e.Store == nil || e.DatabaseFactory == nil || e.Services == nil || e.Now == nil || !validUpgradeRequest(r) {
		return upgradeError(JournalPreflighted, "invalid_request")
	}
	lock, err := acquireUpgradeLock(ctx, e.Store, r.TransactionID, JournalPreflighted)
	if err != nil {
		return err
	}
	defer func() {
		if err := lock.Release(); err != nil && result == nil {
			result = upgradeError(JournalCommitted, "lock_release_failed")
		}
	}()

	preflight, err := e.Store.PreflightPlan(ctx, UpgradePreflightRequest{TransactionID: r.TransactionID, CandidateRelease: r.CandidateRelease})
	if err != nil || preflight.ValidateForRequest(UpgradePreflightRequest{TransactionID: r.TransactionID, CandidateRelease: r.CandidateRelease}) != nil || (preflight.Legacy != nil) != r.ExpectedLegacy {
		return upgradeError(JournalPreflighted, "preflight_failed")
	}
	actualLegacy := preflight.Legacy != nil
	var old ActivationV1
	var oldJSONSHA256 string
	var activeDatabaseEnv []byte
	var database UpgradeDatabaseSession
	baseline := UpgradeActivationState{PreviousID: preflight.Previous.ID, PreviousJSONSHA256: preflight.Previous.JSONSHA256}
	now := e.now()
	if actualLegacy {
		activeDatabaseEnv = append([]byte(nil), preflight.Legacy.DatabaseEnv...)
		request := ActiveDatabaseInspectionRequest{DatabaseEnv: activeDatabaseEnv, ExpectedMigration: preflight.Legacy.ExpectedMigration, ExpectedRowsSHA256: preflight.Legacy.ExpectedRowsSHA256, ExpectedRowCount: 23}
		var openErr error
		database, openErr = e.DatabaseFactory.Open(ctx, UpgradeDatabaseOpenRequest{TransactionID: r.TransactionID, CandidateRelease: r.CandidateRelease, CandidateActivationID: r.CandidateActivationID, CandidateDatabaseName: r.CandidateDatabaseName, ActiveDatabaseEnv: activeDatabaseEnv})
		if openErr != nil || database == nil {
			return upgradeError(JournalPreflighted, "database_open_failed")
		}
		defer func() {
			if closeErr := database.Close(); closeErr != nil && result == nil {
				result = upgradeError(JournalCommitted, "database_close_failed")
			}
		}()
		inspected, inspectErr := database.InspectActive(ctx, request)
		if inspectErr != nil {
			return upgradeError(JournalPreflighted, "preflight_failed")
		}
		old, oldJSONSHA256, err = legacyActivation(*preflight.Legacy, inspected, now)
		if err != nil {
			return upgradeError(JournalPreflighted, "preflight_failed")
		}
	} else {
		old, oldJSONSHA256 = preflight.Existing.Activation, preflight.Existing.JSONSHA256
		activeDatabaseEnv = append([]byte(nil), preflight.Existing.DatabaseEnv...)
	}
	if actualLegacy {
		// The legacy branch opened and inspected its session above so that the
		// planned old activation can be journaled before any host mutation.
		// Re-open below only for the common continuation is intentionally avoided.
	} else {
		database, err = e.DatabaseFactory.Open(ctx, UpgradeDatabaseOpenRequest{TransactionID: r.TransactionID, CandidateRelease: r.CandidateRelease, CandidateActivationID: r.CandidateActivationID, CandidateDatabaseName: r.CandidateDatabaseName, ActiveDatabaseEnv: activeDatabaseEnv})
		if err != nil || database == nil {
			return upgradeError(JournalPreflighted, "database_open_failed")
		}
		defer func() {
			if closeErr := database.Close(); closeErr != nil && result == nil {
				result = upgradeError(JournalCommitted, "database_close_failed")
			}
		}()
		request, requestErr := inspectionRequestForActivation(activeDatabaseEnv, old)
		if requestErr != nil {
			return upgradeError(JournalPreflighted, "preflight_failed")
		}
		inspected, inspectErr := database.InspectActive(ctx, request)
		if inspectErr != nil || !sameDatabase(inspected, old.Database) {
			return upgradeError(JournalPreflighted, "preflight_failed")
		}
	}
	if !actualLegacy {
		baseline, err = e.Store.ReadActivationState(ctx)
		if err != nil || baseline.Marker || !sameOldState(baseline, baseline, old, oldJSONSHA256) {
			return upgradeError(JournalPreflighted, "preflight_failed")
		}
	}
	serviceSnapshot, err := e.Services.Capture(ctx)
	if err != nil {
		return upgradeError(JournalPreflighted, "service_capture_failed")
	}
	j := UpgradeJournalV1{
		SchemaVersion:                          ActivationSchemaVersion,
		TransactionID:                          r.TransactionID,
		Revision:                               1,
		State:                                  JournalPreflighted,
		CreatedAt:                              now,
		UpdatedAt:                              now,
		RequestedManifestSHA256:                r.RequestedManifestSHA256,
		OldActivationID:                        old.ActivationID,
		OldActivationJSONSHA256:                oldJSONSHA256,
		PreUpgradePreviousActivationID:         baseline.PreviousID,
		PreUpgradePreviousActivationJSONSHA256: baseline.PreviousJSONSHA256,
		CandidateActivationID:                  r.CandidateActivationID,
		CandidateDatabaseName:                  r.CandidateDatabaseName,
		ServiceSnapshot:                        serviceSnapshot,
		History:                                []JournalTransitionV1{},
	}
	if actualLegacy {
		planned := old
		j.PlannedOldActivation = &planned
	}
	if err := j.Validate(); err != nil {
		return upgradeError(JournalPreflighted, "invalid_journal")
	}
	if err := e.Store.CreateJournal(ctx, j); err != nil {
		if errors.Is(err, ErrUpgradeConflict) {
			return ErrUpgradeConflict
		}
		if outcomeUnknown(err) {
			loaded, loadErr := e.Store.LoadJournal(ctx, r.TransactionID)
			expectedRaw, expectedErr := MarshalUpgradeJournalV1(j)
			actualRaw, actualErr := MarshalUpgradeJournalV1(loaded)
			if loadErr != nil || expectedErr != nil || actualErr != nil || !bytes.Equal(expectedRaw, actualRaw) {
				return upgradeErrorWith(JournalPreflighted, "create_journal_unknown", err)
			}
		} else {
			return upgradeError(JournalPreflighted, "create_journal_failed")
		}
	}
	fail := func(phase JournalState, code string, cause error) error {
		if actualLegacy && j.State == JournalPreflighted {
			return e.recoveryRequired(ctx, &j, phase, code, cause)
		}
		return e.handleFailure(ctx, &j, old, baseline, phase, code, cause)
	}
	if err := e.Store.Marker(ctx, true); err != nil {
		return fail(j.State, "marker_create_failed", err)
	}
	if err := e.Services.Quiesce(ctx); err != nil {
		return fail(JournalQuiesced, "service_quiesce_failed", err)
	}
	if err := database.Drain(ctx); err != nil {
		return fail(JournalQuiesced, "database_drain_failed", err)
	}
	if actualLegacy {
		plan := *preflight.Legacy
		inspected, inspectErr := database.InspectActive(ctx, ActiveDatabaseInspectionRequest{DatabaseEnv: plan.DatabaseEnv, ExpectedMigration: plan.ExpectedMigration, ExpectedRowsSHA256: plan.ExpectedRowsSHA256, ExpectedRowCount: 23})
		if inspectErr != nil || !sameDatabase(inspected, old.Database) {
			return e.recoveryRequired(ctx, &j, JournalLegacyProjected, "legacy_projection_failed", inspectErr)
		}
		if _, err := e.Store.PrepareLegacyProjection(ctx, plan, old); err != nil {
			return e.legacyProjectionPending(ctx, &j, r.TransactionID, err)
		}
		if err := e.Services.ReloadServerUnit(ctx, plan.ServerUnitAfterSHA256); err != nil {
			return e.legacyProjectionPending(ctx, &j, r.TransactionID, err)
		}
		if _, err := e.Store.FinalizeLegacyProjection(ctx, plan, old); err != nil {
			return e.legacyProjectionPending(ctx, &j, r.TransactionID, err)
		}
		observation, err := e.Store.ReadLegacyProjection(ctx, plan, old)
		if err != nil || observation.Validate() != nil || !sameLegacyObservation(observation, expectedLegacyObservation(plan, old, oldJSONSHA256)) {
			if err == nil {
				err = errors.New("legacy projection observation mismatch")
			}
			return e.legacyProjectionPending(ctx, &j, r.TransactionID, err)
		}
		if err := e.advance(ctx, &j, JournalLegacyProjected); err != nil {
			return e.legacyProjectionPending(ctx, &j, r.TransactionID, err)
		}
	} else {
		request, requestErr := inspectionRequestForActivation(activeDatabaseEnv, old)
		if requestErr != nil {
			return e.recoveryRequired(ctx, &j, JournalSnapshotCreated, "native_database_drift", requestErr)
		}
		inspected, inspectErr := database.InspectActive(ctx, request)
		if inspectErr != nil || !sameDatabase(inspected, old.Database) {
			return e.recoveryRequired(ctx, &j, JournalSnapshotCreated, "native_database_drift", inspectErr)
		}
	}
	if err := e.advance(ctx, &j, JournalQuiesced); err != nil {
		return fail(JournalQuiesced, "quiesce_journal_failed", err)
	}
	if evidence, sourceDatabase, err := database.Snapshot(ctx); err != nil {
		return fail(JournalSnapshotCreated, "snapshot_failed", err)
	} else if sourceDatabase != old.Database.Name {
		return fail(JournalSnapshotCreated, "snapshot_failed", errors.New("snapshot source database mismatch"))
	} else {
		j.Snapshot = &ArtifactV1{Path: artifactPath(j.TransactionID, "control-plane.dump"), SHA256: evidence.SHA256, Size: evidence.Size, SourceDatabase: sourceDatabase}
		if err := e.advance(ctx, &j, JournalSnapshotCreated); err != nil {
			return fail(JournalSnapshotCreated, "snapshot_journal_failed", err)
		}
	}
	if err := database.CreateRestore(ctx, r.CandidateDatabaseName); err != nil {
		return fail(JournalCandidateDBReady, "candidate_database_failed", err)
	}
	if err := e.advance(ctx, &j, JournalCandidateDBReady); err != nil {
		return fail(JournalCandidateDBReady, "candidate_journal_failed", err)
	}
	if evidence, err := database.Migrate(ctx); err != nil {
		return fail(JournalMigrated, "migration_failed", err)
	} else {
		j.CandidateDatabase = &DatabaseV1{Name: r.CandidateDatabaseName, Migration: evidence.To, SchemaMigrationsSHA256: evidence.RowsSHA256}
		j.Migration = &MigrationV1{From: evidence.From, To: evidence.To, ManifestSHA256: evidence.ReleaseManifestSHA256}
		if err := e.advance(ctx, &j, JournalMigrated); err != nil {
			return fail(JournalMigrated, "migration_journal_failed", err)
		}
	}
	candidateEnv := database.CandidateDatabaseEnv()
	candidateEnvironment, candidateEnvErr := PostgresEnvironment(candidateEnv)
	if candidateEnvErr != nil || candidateEnvironment.Descriptor.Database != r.CandidateDatabaseName {
		return fail(JournalValidated, "invalid_candidate_database_env", candidateEnvErr)
	}
	candidate := ActivationV1{SchemaVersion: ActivationSchemaVersion, ActivationID: r.CandidateActivationID, Origin: "native", Release: r.CandidateRelease, Database: *j.CandidateDatabase, DatabaseEnvSHA256: sha256Bytes(candidateEnv), CreatedAt: e.now(), CreatedByTransactionID: r.TransactionID}
	if err := candidate.Validate(); err != nil {
		return fail(JournalValidated, "invalid_candidate_activation", err)
	}
	candidateJSONSHA256, err := e.Store.WriteCandidateActivation(ctx, candidate, candidateEnv)
	if err != nil || !validSHA(candidateJSONSHA256) {
		return fail(JournalValidated, "write_candidate_activation_failed", err)
	}
	validation, err := database.Validate(ctx, r.CandidateActivationID)
	if err != nil {
		return fail(JournalValidated, "validation_failed", err)
	}
	j.CandidateActivationJSONSHA256, j.Validation = candidateJSONSHA256, &validation
	if err := e.advance(ctx, &j, JournalValidated); err != nil {
		return fail(JournalValidated, "validation_journal_failed", err)
	}
	if err := e.Store.SetPrevious(ctx, old.ActivationID); err != nil {
		return fail(JournalActiveSwitched, "set_previous_failed", err)
	}
	actualPointers, err := e.Store.ReadActivationState(ctx)
	if err != nil || actualPointers.PreviousID != old.ActivationID || actualPointers.PreviousJSONSHA256 != oldJSONSHA256 {
		return e.recoveryRequired(ctx, &j, JournalActiveSwitched, "set_previous_failed", err)
	}
	if err := e.Store.SwapActive(ctx, r.CandidateActivationID); err != nil {
		return fail(JournalActiveSwitched, "swap_active_failed", err)
	}
	actualPointers, err = e.Store.ReadActivationState(ctx)
	if err != nil || actualPointers.ActiveID != r.CandidateActivationID || actualPointers.ActiveActivationJSONSHA256 != candidateJSONSHA256 || actualPointers.PreviousID != old.ActivationID || actualPointers.PreviousJSONSHA256 != oldJSONSHA256 {
		return e.recoveryRequired(ctx, &j, JournalActiveSwitched, "swap_active_failed", err)
	}
	if err := e.advance(ctx, &j, JournalActiveSwitched); err != nil {
		return fail(JournalActiveSwitched, "active_journal_failed", err)
	}
	if err := e.Services.StartInternal(ctx); err != nil {
		return fail(JournalHealthy, "start_internal_failed", err)
	}
	if err := e.Services.HealthInternal(ctx); err != nil {
		return fail(JournalHealthy, "internal_health_failed", err)
	}
	if err := e.advance(ctx, &j, JournalHealthy); err != nil {
		return fail(JournalHealthy, "healthy_journal_failed", err)
	}
	if err := e.advance(ctx, &j, JournalEdgeArmed); err != nil {
		return fail(JournalEdgeArmed, "edge_journal_failed", err)
	}
	actualPointers, err = e.Store.ReadActivationState(ctx)
	if err != nil || actualPointers.ActiveID != r.CandidateActivationID || actualPointers.ActiveActivationJSONSHA256 != candidateJSONSHA256 || actualPointers.PreviousID != old.ActivationID || actualPointers.PreviousJSONSHA256 != oldJSONSHA256 {
		return e.recoveryRequired(ctx, &j, JournalCommitted, "commit_journal_failed", err)
	}
	if err := e.advance(ctx, &j, JournalCommitted); err != nil {
		return e.recoveryRequired(ctx, &j, JournalCommitted, "commit_journal_failed", err)
	}
	return e.convergeCommittedPublic(ctx, &j, r.TransactionID, r.TransactionID)
}

func actualMatchesOld(s UpgradeActualState, j UpgradeJournalV1) bool {
	return s.OldActivationExists && validSHA(s.OldActivationJSONSHA256) && s.ActiveID == j.OldActivationID && s.OldActivationJSONSHA256 == j.OldActivationJSONSHA256
}

func actualMatchesCandidate(s UpgradeActualState, j UpgradeJournalV1) bool {
	return s.CandidateActivationExists && validSHA(s.CandidateActivationJSONSHA256) && s.ActiveID == j.CandidateActivationID && s.CandidateActivationJSONSHA256 == j.CandidateActivationJSONSHA256
}

func actualPreviousOld(s UpgradeActualState, j UpgradeJournalV1) bool {
	return s.PreviousID == j.OldActivationID && s.PreviousActivationJSONSHA256 == j.OldActivationJSONSHA256
}

func actualBaselinePrevious(s UpgradeActualState, j UpgradeJournalV1) bool {
	return s.PreviousID == j.PreUpgradePreviousActivationID && s.PreviousActivationJSONSHA256 == j.PreUpgradePreviousActivationJSONSHA256
}

func recoveredFailure(phase JournalState, err error) *FailureV1 {
	return failureFor(phase, "recovered", err)
}

func (e *UpgradeEngine) recoverRecovery(ctx context.Context, j *UpgradeJournalV1, tx string, phase JournalState, cause error) error {
	if err := e.Store.EnsureMarker(ctx, tx); err != nil {
		_ = e.Services.GuardEdge(ctx)
		return upgradeErrorWith(JournalRecoveryRequired, "recovery_required", cause)
	}
	if terminal(j.State) {
		_ = e.Services.GuardEdge(ctx)
		return upgradeErrorWith(JournalRecoveryRequired, "recovery_required", cause)
	}
	j.Failure = recoveredFailure(phase, cause)
	if err := e.advance(ctx, j, JournalRecoveryRequired); err != nil {
		_ = e.Services.GuardEdge(ctx)
		return upgradeErrorWith(JournalRecoveryRequired, "recovery_required", cause)
	}
	_ = e.Services.GuardEdge(ctx)
	return upgradeErrorWith(JournalRecoveryRequired, "recovery_required", cause)
}

func (e *UpgradeEngine) restoreOldServices(ctx context.Context, j *UpgradeJournalV1) error {
	if err := e.Services.RestoreSnapshot(ctx, j.ServiceSnapshot); err != nil {
		return err
	}
	if err := e.Services.HealthRestoredInternal(ctx); err != nil {
		return err
	}
	if err := e.Store.Marker(ctx, false); err != nil {
		return err
	}
	if !j.ServiceSnapshot.Edge.Active {
		return e.Services.GuardEdge(ctx)
	}
	if err := e.Services.RestoreEdge(ctx, j.ServiceSnapshot); err != nil {
		return err
	}
	return e.Services.HealthEdge(ctx)
}

func (e *UpgradeEngine) convergeCommittedPublic(ctx context.Context, j *UpgradeJournalV1, tx, markerTx string) error {
	fail := func(err error) error {
		_ = e.Store.EnsureMarker(ctx, tx)
		_ = e.Services.GuardEdge(ctx)
		return upgradeErrorWith(JournalCommitted, "public_activation_failed", err)
	}
	if markerTx != "" && markerTx != tx {
		_ = e.Services.GuardEdge(ctx)
		return upgradeError(JournalCommitted, "integrity_failed")
	}
	if markerTx == tx {
		if err := e.Store.Marker(ctx, false); err != nil {
			return fail(err)
		}
	}
	if !j.ServiceSnapshot.Edge.Active {
		if err := e.Services.GuardEdge(ctx); err != nil {
			return fail(err)
		}
		return nil
	}
	if err := e.Services.StartEdge(ctx); err != nil {
		return fail(err)
	}
	if err := e.Services.HealthEdge(ctx); err != nil {
		return fail(err)
	}
	return nil
}

// recoverLegacyPreflight finishes only the compatibility projection that was
// already journaled. It deliberately restores the old service policy and
// stops at ABORTED_PRE_SWITCH rather than silently resuming a new candidate
// upgrade after a host crash.
func (e *UpgradeEngine) recoverLegacyPreflight(ctx context.Context, j *UpgradeJournalV1, transactionID string) (result error) {
	if e.DatabaseFactory == nil {
		return e.recoverRecovery(ctx, j, transactionID, JournalPreflighted, errors.New("legacy database driver unavailable"))
	}
	if j.PlannedOldActivation == nil || j.PlannedOldActivation.Validate() != nil || j.PlannedOldActivation.LegacyProjection == nil {
		return e.recoverRecovery(ctx, j, transactionID, j.State, errors.New("missing planned legacy activation"))
	}
	old := *j.PlannedOldActivation
	if err := e.Store.EnsureMarker(ctx, transactionID); err != nil {
		_ = e.Services.GuardEdge(ctx)
		return upgradeErrorWith(JournalRecoveryRequired, "recovery_required", err)
	}
	if err := e.Services.GuardEdge(ctx); err != nil {
		return e.recoverRecovery(ctx, j, transactionID, j.State, err)
	}
	plan, err := e.Store.RecoverLegacyPlan(ctx, old, j.RequestedManifestSHA256)
	if err != nil || plan.TransactionID != transactionID || plan.ActivationID != old.ActivationID || plan.Validate() != nil || plan.ServerUnitReleaseID != old.LegacyProjection.ServerUnitReleaseID {
		return e.recoverRecovery(ctx, j, transactionID, j.State, err)
	}
	baseline := ActivationPointerIdentity{ID: j.PreUpgradePreviousActivationID, JSONSHA256: j.PreUpgradePreviousActivationJSONSHA256}
	if baseline.Validate() != nil || !plan.Previous.equal(baseline) {
		return e.recoverRecovery(ctx, j, transactionID, j.State, errors.New("legacy previous pointer drift"))
	}
	database, err := e.DatabaseFactory.Open(ctx, UpgradeDatabaseOpenRequest{TransactionID: transactionID, CandidateActivationID: j.CandidateActivationID, CandidateDatabaseName: j.CandidateDatabaseName, ActiveDatabaseEnv: plan.DatabaseEnv})
	if err != nil || database == nil {
		return e.recoverRecovery(ctx, j, transactionID, j.State, err)
	}
	defer func() {
		// Recovery already has a durable terminal/error outcome.  A close failure
		// must not hide that outcome, but a future successful path fails closed.
		if closeErr := database.Close(); closeErr != nil && result == nil {
			result = upgradeError(JournalRecoveryRequired, "database_close_failed")
		}
	}()
	inspected, err := database.InspectActive(ctx, ActiveDatabaseInspectionRequest{DatabaseEnv: plan.DatabaseEnv, ExpectedMigration: plan.ExpectedMigration, ExpectedRowsSHA256: plan.ExpectedRowsSHA256, ExpectedRowCount: 23})
	if err != nil || !sameDatabase(inspected, old.Database) {
		return e.recoverRecovery(ctx, j, transactionID, j.State, err)
	}
	if _, err := e.Store.PrepareLegacyProjection(ctx, plan, old); err != nil {
		return e.recoverRecovery(ctx, j, transactionID, j.State, err)
	}
	if err := e.Services.ReloadServerUnit(ctx, plan.ServerUnitAfterSHA256); err != nil {
		return e.recoverRecovery(ctx, j, transactionID, j.State, err)
	}
	if _, err := e.Store.FinalizeLegacyProjection(ctx, plan, old); err != nil {
		return e.recoverRecovery(ctx, j, transactionID, j.State, err)
	}
	observation, err := e.Store.ReadLegacyProjection(ctx, plan, old)
	if err != nil || observation.Validate() != nil || !sameLegacyObservation(observation, expectedLegacyObservation(plan, old, j.OldActivationJSONSHA256)) {
		return e.recoverRecovery(ctx, j, transactionID, j.State, err)
	}
	if err := e.advance(ctx, j, JournalLegacyProjected); err != nil {
		return e.recoverRecovery(ctx, j, transactionID, j.State, err)
	}
	if err := e.restoreOldServices(ctx, j); err != nil {
		return e.recoverRecovery(ctx, j, transactionID, j.State, err)
	}
	j.Failure = recoveredFailure(JournalLegacyProjected, errors.New("recovered legacy projection"))
	if err := e.advance(ctx, j, JournalAbortedPreSwitch); err != nil {
		return e.recoverRecovery(ctx, j, transactionID, j.State, err)
	}
	return upgradeError(JournalAbortedPreSwitch, "recovered")
}

// Recover reconciles one durable journal against observed activation and marker
// state. It never removes upgrade artifacts; ambiguity is preserved as a
// RECOVERY_REQUIRED journal rather than guessed away.
func (e *UpgradeEngine) Recover(ctx context.Context, transactionID string) (result error) {
	if e == nil || e.Store == nil || e.Services == nil || e.Now == nil || !validID(transactionID) {
		return upgradeError(JournalRecoveryRequired, "invalid_request")
	}
	lock, err := acquireUpgradeLock(ctx, e.Store, transactionID, JournalRecoveryRequired)
	if err != nil {
		return err
	}
	defer func() {
		if err := lock.Release(); err != nil && result == nil {
			result = upgradeError(JournalRecoveryRequired, "lock_release_failed")
		}
	}()
	j, err := e.Store.LoadJournal(ctx, transactionID)
	if err != nil || j.TransactionID != transactionID || j.Validate() != nil {
		_ = e.Services.GuardEdge(ctx)
		return upgradeError(JournalRecoveryRequired, "integrity_failed")
	}
	if j.State == JournalPreflighted && j.PlannedOldActivation != nil {
		return e.recoverLegacyPreflight(ctx, &j, transactionID)
	}
	actual, err := e.Store.ReadActualState(ctx, j.OldActivationID, j.CandidateActivationID)
	if err != nil {
		return e.recoverRecovery(ctx, &j, transactionID, j.State, err)
	}
	if j.State == JournalRecoveryRequired {
		_ = e.Store.EnsureMarker(ctx, transactionID)
		_ = e.Services.GuardEdge(ctx)
		return upgradeError(JournalRecoveryRequired, "recovery_required")
	}
	if j.State == JournalCommitted {
		if !actualMatchesCandidate(actual, j) || !actualPreviousOld(actual, j) {
			if actual.MarkerTransactionID == "" {
				_ = e.Store.EnsureMarker(ctx, transactionID)
			}
			_ = e.Services.GuardEdge(ctx)
			return upgradeError(JournalCommitted, "integrity_failed")
		}
		return e.convergeCommittedPublic(ctx, &j, transactionID, actual.MarkerTransactionID)
	}
	if terminal(j.State) {
		if !actualMatchesOld(actual, j) || j.State == JournalAbortedPreSwitch && !actualBaselinePrevious(actual, j) || actual.MarkerTransactionID != "" && actual.MarkerTransactionID != transactionID {
			if actual.MarkerTransactionID == "" {
				_ = e.Store.EnsureMarker(ctx, transactionID)
			}
			_ = e.Services.GuardEdge(ctx)
			return upgradeError(j.State, "integrity_failed")
		}
		if err := e.restoreOldServices(ctx, &j); err != nil {
			return e.recoverRecovery(ctx, &j, transactionID, j.State, err)
		}
		return nil
	}
	if actual.MarkerTransactionID != "" && actual.MarkerTransactionID != transactionID {
		_ = e.Services.GuardEdge(ctx)
		return upgradeError(JournalRecoveryRequired, "integrity_failed")
	}
	if actual.MarkerTransactionID == "" {
		if err := e.Store.EnsureMarker(ctx, transactionID); err != nil {
			_ = e.Services.GuardEdge(ctx)
			return upgradeErrorWith(JournalRecoveryRequired, "recovery_required", err)
		}
	}
	if err := e.Services.GuardEdge(ctx); err != nil {
		return e.recoverRecovery(ctx, &j, transactionID, j.State, err)
	}
	if j.State == JournalRollbackSwitched && actualMatchesOld(actual, j) && actual.PreviousID == j.CandidateActivationID && actual.CandidateActivationJSONSHA256 == j.CandidateActivationJSONSHA256 {
		if err := e.restoreOldServices(ctx, &j); err != nil {
			return e.recoverRecovery(ctx, &j, transactionID, j.State, err)
		}
		if err := e.advance(ctx, &j, JournalRolledBack); err != nil {
			return e.recoverRecovery(ctx, &j, transactionID, j.State, err)
		}
		return upgradeError(JournalRolledBack, "recovered")
	}
	if (j.State == JournalActiveSwitched || j.State == JournalHealthy || j.State == JournalEdgeArmed) && actualMatchesOld(actual, j) && actual.PreviousID == j.CandidateActivationID && actual.CandidateActivationJSONSHA256 == j.CandidateActivationJSONSHA256 {
		j.Failure = recoveredFailure(j.State, errors.New("recovered completed rollback pointer"))
		if err := e.advance(ctx, &j, JournalRollbackSwitched); err != nil {
			return e.recoverRecovery(ctx, &j, transactionID, j.State, err)
		}
		if err := e.restoreOldServices(ctx, &j); err != nil {
			return e.recoverRecovery(ctx, &j, transactionID, j.State, err)
		}
		if err := e.advance(ctx, &j, JournalRolledBack); err != nil {
			return e.recoverRecovery(ctx, &j, transactionID, j.State, err)
		}
		return upgradeError(JournalRolledBack, "recovered")
	}
	if actualMatchesOld(actual, j) {
		if !actualBaselinePrevious(actual, j) {
			if actual.PreviousID != j.OldActivationID || actual.PreviousActivationJSONSHA256 != j.OldActivationJSONSHA256 {
				return e.recoverRecovery(ctx, &j, transactionID, j.State, errors.New("pre-upgrade previous pointer drift"))
			}
			if err := e.Store.RestorePrevious(ctx, j.OldActivationID, j.PreUpgradePreviousActivationID, j.PreUpgradePreviousActivationJSONSHA256); err != nil {
				return e.recoverRecovery(ctx, &j, transactionID, j.State, err)
			}
			actual, err = e.Store.ReadActualState(ctx, j.OldActivationID, j.CandidateActivationID)
			if err != nil || !actualBaselinePrevious(actual, j) {
				return e.recoverRecovery(ctx, &j, transactionID, j.State, err)
			}
		}
		if err := e.restoreOldServices(ctx, &j); err != nil {
			return e.recoverRecovery(ctx, &j, transactionID, j.State, err)
		}
		j.Failure = recoveredFailure(j.State, errors.New("recovered pre-switch state"))
		if err := e.advance(ctx, &j, JournalAbortedPreSwitch); err != nil {
			return e.recoverRecovery(ctx, &j, transactionID, j.State, err)
		}
		return upgradeError(JournalAbortedPreSwitch, "recovered")
	}
	if !actualMatchesCandidate(actual, j) || !actualPreviousOld(actual, j) || j.CandidateActivationJSONSHA256 == "" || j.Validation == nil {
		return e.recoverRecovery(ctx, &j, transactionID, j.State, errors.New("actual activation state is not provable"))
	}
	if j.State == JournalValidated {
		if err := e.advance(ctx, &j, JournalActiveSwitched); err != nil {
			return e.recoverRecovery(ctx, &j, transactionID, j.State, err)
		}
	}
	if j.State != JournalActiveSwitched && j.State != JournalHealthy && j.State != JournalEdgeArmed && j.State != JournalRollbackSwitched {
		return e.recoverRecovery(ctx, &j, transactionID, j.State, errors.New("candidate active before validated journal state"))
	}
	if err := e.Store.RestoreActive(ctx, j.OldActivationID, j.CandidateActivationID); err != nil {
		return e.recoverRecovery(ctx, &j, transactionID, j.State, err)
	}
	actual, err = e.Store.ReadActualState(ctx, j.OldActivationID, j.CandidateActivationID)
	if err != nil || !actualMatchesOld(actual, j) || actual.PreviousID != j.CandidateActivationID || actual.CandidateActivationJSONSHA256 != j.CandidateActivationJSONSHA256 {
		return e.recoverRecovery(ctx, &j, transactionID, j.State, err)
	}
	if j.State != JournalRollbackSwitched {
		j.Failure = recoveredFailure(j.State, errors.New("recovered candidate activation"))
		if err := e.advance(ctx, &j, JournalRollbackSwitched); err != nil {
			return e.recoverRecovery(ctx, &j, transactionID, j.State, err)
		}
	}
	if err := e.restoreOldServices(ctx, &j); err != nil {
		return e.recoverRecovery(ctx, &j, transactionID, j.State, err)
	}
	if j.State == JournalRollbackSwitched {
		if err := e.advance(ctx, &j, JournalRolledBack); err != nil {
			return e.recoverRecovery(ctx, &j, transactionID, j.State, err)
		}
	}
	return upgradeError(JournalRolledBack, "recovered")
}
