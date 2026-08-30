package install

import (
	"context"
	"errors"
)

// UpgradeBootUnitReloader is deliberately narrower than UpgradeServiceDriver.
// The early-boot reconciliation pass may update only the already-journaled
// legacy unit boundary; it must not start, stop, probe, or otherwise touch a
// business service.
type UpgradeBootUnitReloader interface {
	ReloadServerUnit(context.Context, string) error
}

// BootRecoveryResultV1 is the secret-free result emitted by the prepare and
// finalize boot commands. A successful reconcile always retains the marker;
// only a later terminal finalization is allowed to remove it.
type BootRecoveryResultV1 struct {
	SchemaVersion    int          `json:"schema_version"`
	TransactionID    string       `json:"transaction_id"`
	State            JournalState `json:"state"`
	MarkerRetained   bool         `json:"marker_retained"`
	FinalizeRequired bool         `json:"finalize_required"`
	Skipped          bool         `json:"skipped,omitempty"`
}

func bootResult(j UpgradeJournalV1) BootRecoveryResultV1 {
	return BootRecoveryResultV1{SchemaVersion: ActivationSchemaVersion, TransactionID: j.TransactionID, State: j.State, MarkerRetained: true, FinalizeRequired: j.State == JournalCommitted || j.State == JournalAbortedPreSwitch || j.State == JournalRolledBack}
}

func finalizedBootResult(j UpgradeJournalV1) BootRecoveryResultV1 {
	return BootRecoveryResultV1{SchemaVersion: ActivationSchemaVersion, TransactionID: j.TransactionID, State: j.State, MarkerRetained: false, FinalizeRequired: false}
}

func skippedBootResult() BootRecoveryResultV1 {
	return BootRecoveryResultV1{SchemaVersion: ActivationSchemaVersion, Skipped: true}
}

func bootMarkerSame(actual UpgradeActualState, tx string) bool {
	return actual.MarkerTransactionID == tx
}

// bootAdvance reconciles the only ambiguous durable operation used by boot
// recovery. A directory fsync may report an unknown outcome after the journal
// rename reached disk, so reread the canonical journal before retrying.
func (e *UpgradeEngine) bootAdvance(ctx context.Context, j *UpgradeJournalV1, to JournalState) error {
	err := e.advance(ctx, j, to)
	if err == nil || !outcomeUnknown(err) {
		return err
	}
	loaded, loadErr := e.Store.LoadJournal(ctx, j.TransactionID)
	if loadErr == nil && loaded.Validate() == nil && loaded.State == to && loaded.Revision == j.Revision+1 {
		*j = loaded
		return nil
	}
	return err
}

func (e *UpgradeEngine) bootRecoveryRequired(ctx context.Context, j *UpgradeJournalV1, phase JournalState, cause error) error {
	if j.State != JournalRecoveryRequired && !terminal(j.State) {
		j.Failure = failureFor(phase, "boot_recovery_required", cause)
		if err := e.bootAdvance(ctx, j, JournalRecoveryRequired); err != nil {
			return upgradeErrorWith(JournalRecoveryRequired, "recovery_required", cause)
		}
	}
	return upgradeErrorWith(JournalRecoveryRequired, "recovery_required", cause)
}

func (e *UpgradeEngine) bootRestoreBaselinePrevious(ctx context.Context, j *UpgradeJournalV1, actual UpgradeActualState) error {
	if actualBaselinePrevious(actual, *j) {
		return nil
	}
	if !actualPreviousOld(actual, *j) {
		return errors.New("previous activation is not an authorized pre-switch value")
	}
	if err := e.Store.RestorePrevious(ctx, j.OldActivationID, j.PreUpgradePreviousActivationID, j.PreUpgradePreviousActivationJSONSHA256); err != nil {
		return err
	}
	verified, err := e.Store.ReadActualState(ctx, j.OldActivationID, j.CandidateActivationID)
	if err != nil || !actualMatchesOld(verified, *j) || !actualBaselinePrevious(verified, *j) {
		return errors.New("previous activation restore was not provable")
	}
	return nil
}

func (e *UpgradeEngine) bootAbortOld(ctx context.Context, j *UpgradeJournalV1, actual UpgradeActualState) error {
	if !actualMatchesOld(actual, *j) {
		return errors.New("old activation is not active")
	}
	if err := e.bootRestoreBaselinePrevious(ctx, j, actual); err != nil {
		return err
	}
	if j.State == JournalAbortedPreSwitch {
		return nil
	}
	j.Failure = failureFor(j.State, "boot_recovered", errors.New("boot reconciled old activation"))
	return e.bootAdvance(ctx, j, JournalAbortedPreSwitch)
}

func (e *UpgradeEngine) bootRollbackCandidate(ctx context.Context, j *UpgradeJournalV1, actual UpgradeActualState) error {
	if !actualMatchesCandidate(actual, *j) || !actualPreviousOld(actual, *j) {
		return errors.New("candidate activation is not provable")
	}
	if j.State == JournalValidated {
		if err := e.bootAdvance(ctx, j, JournalActiveSwitched); err != nil {
			return err
		}
	}
	if j.State != JournalActiveSwitched && j.State != JournalHealthy && j.State != JournalEdgeArmed && j.State != JournalRollbackSwitched {
		return errors.New("candidate activation is not recoverable from this state")
	}
	if j.State != JournalRollbackSwitched {
		j.Failure = failureFor(j.State, "boot_recovered", errors.New("boot rolling candidate activation back"))
		if err := e.Store.RestoreActive(ctx, j.OldActivationID, j.CandidateActivationID); err != nil {
			return err
		}
		verified, err := e.Store.ReadActualState(ctx, j.OldActivationID, j.CandidateActivationID)
		if err != nil || !actualMatchesOld(verified, *j) || verified.PreviousID != j.CandidateActivationID || verified.PreviousActivationJSONSHA256 != j.CandidateActivationJSONSHA256 {
			return errors.New("active restore was not provable")
		}
		if err := e.bootAdvance(ctx, j, JournalRollbackSwitched); err != nil {
			return err
		}
	}
	if err := e.bootAdvance(ctx, j, JournalRolledBack); err != nil {
		return err
	}
	return nil
}

func (e *UpgradeEngine) bootReconcileLegacy(ctx context.Context, j *UpgradeJournalV1, reloader UpgradeBootUnitReloader) error {
	if e.DatabaseFactory == nil || reloader == nil || j.PlannedOldActivation == nil || j.PlannedOldActivation.Validate() != nil || j.PlannedOldActivation.LegacyProjection == nil {
		return errors.New("legacy boot dependencies are unavailable")
	}
	old := *j.PlannedOldActivation
	plan, err := e.Store.RecoverLegacyPlan(ctx, old, j.RequestedManifestSHA256)
	if err != nil || plan.Validate() != nil || plan.TransactionID != j.TransactionID || plan.ActivationID != old.ActivationID {
		return errors.New("legacy plan is not recoverable")
	}
	if !plan.Previous.equal(ActivationPointerIdentity{ID: j.PreUpgradePreviousActivationID, JSONSHA256: j.PreUpgradePreviousActivationJSONSHA256}) {
		return errors.New("legacy previous activation drift")
	}
	database, err := e.DatabaseFactory.Open(ctx, UpgradeDatabaseOpenRequest{TransactionID: j.TransactionID, CandidateActivationID: j.CandidateActivationID, CandidateDatabaseName: j.CandidateDatabaseName, ActiveDatabaseEnv: plan.DatabaseEnv})
	if err != nil || database == nil {
		return errors.New("legacy database session unavailable")
	}
	defer database.Close() // Close is not a service action; the journal remains recoverable on failure.
	if !recoveryControlIdentityMatches(*j, database) {
		return errors.New("upgrade control identity mismatch")
	}
	request := ActiveDatabaseInspectionRequest{DatabaseEnv: plan.DatabaseEnv, ExpectedMigration: plan.ExpectedMigration, ExpectedRowsSHA256: plan.ExpectedRowsSHA256, ExpectedRowCount: 23}
	inspected, err := database.InspectActive(ctx, request)
	if err != nil || !sameDatabase(inspected, old.Database) {
		return errors.New("legacy database drift")
	}
	if _, err := e.Store.PrepareLegacyProjection(ctx, plan, old); err != nil {
		return err
	}
	if err := reloader.ReloadServerUnit(ctx, plan.ServerUnitAfterSHA256); err != nil {
		return err
	}
	if _, err := e.Store.FinalizeLegacyProjection(ctx, plan, old); err != nil {
		return err
	}
	observation, err := e.Store.ReadLegacyProjection(ctx, plan, old)
	if err != nil || observation.Validate() != nil || !sameLegacyObservation(observation, expectedLegacyObservation(plan, old, j.OldActivationJSONSHA256)) {
		return errors.New("legacy projection observation mismatch")
	}
	if err := e.bootAdvance(ctx, j, JournalLegacyProjected); err != nil {
		return err
	}
	actual, err := e.Store.ReadActualState(ctx, j.OldActivationID, j.CandidateActivationID)
	if err != nil {
		return err
	}
	return e.bootAbortOld(ctx, j, actual)
}

// ReconcilePendingBoot acquires the global flock before reading the marker.
// An absent marker is a typed no-op while the lock is held; a present marker
// binds the lock to that exact transaction before journal reconciliation.
func (e *UpgradeEngine) ReconcilePendingBoot(ctx context.Context, reloader UpgradeBootUnitReloader) (result BootRecoveryResultV1, returnErr error) {
	if e == nil || e.Store == nil || e.Now == nil {
		return BootRecoveryResultV1{}, upgradeError(JournalRecoveryRequired, "invalid_request")
	}
	pendingStore, ok := e.Store.(UpgradePendingBootStore)
	if !ok {
		return BootRecoveryResultV1{}, upgradeError(JournalRecoveryRequired, "integrity_failed")
	}
	lock, pending, err := pendingStore.AcquirePendingBoot(ctx)
	if err != nil {
		return BootRecoveryResultV1{}, err
	}
	defer func() {
		if err := lock.Release(); err != nil && returnErr == nil {
			result = BootRecoveryResultV1{}
			returnErr = upgradeError(JournalRecoveryRequired, "lock_release_failed")
		}
	}()
	if pending.Marker == UpgradeMarkerAbsent {
		return skippedBootResult(), nil
	}
	if pending.Marker != UpgradeMarkerSame || !validID(pending.TransactionID) {
		return BootRecoveryResultV1{}, upgradeError(JournalRecoveryRequired, "integrity_failed")
	}
	return e.reconcileBootLocked(ctx, pending.TransactionID, reloader)
}

// reconcileBootLocked repairs only durable activation/journal state while
// AcquirePendingBoot holds the flock bound to transactionID. It intentionally
// has no ServiceDriver calls.
func (e *UpgradeEngine) reconcileBootLocked(ctx context.Context, transactionID string, reloader UpgradeBootUnitReloader) (BootRecoveryResultV1, error) {
	j, err := e.Store.LoadJournal(ctx, transactionID)
	if err != nil || j.TransactionID != transactionID || j.Validate() != nil {
		return BootRecoveryResultV1{}, upgradeError(JournalRecoveryRequired, "integrity_failed")
	}
	// A PREFLIGHTED legacy transaction intentionally has no active activation
	// yet. ReadActualState would therefore fail before the projection can make
	// the old RC0 identity durable. EnsureMarker itself rejects a foreign
	// marker; the projection rereads actual state after it creates the slot.
	if j.State == JournalPreflighted && j.PlannedOldActivation != nil {
		if err := e.Store.EnsureMarker(ctx, transactionID); err != nil {
			return BootRecoveryResultV1{}, e.bootRecoveryRequired(ctx, &j, JournalPreflighted, err)
		}
		if err := e.bootReconcileLegacy(ctx, &j, reloader); err != nil {
			return BootRecoveryResultV1{}, e.bootRecoveryRequired(ctx, &j, JournalPreflighted, err)
		}
		return bootResult(j), nil
	}
	actual, actualErr := e.Store.ReadActualState(ctx, j.OldActivationID, j.CandidateActivationID)
	if actualErr != nil {
		return BootRecoveryResultV1{}, e.bootRecoveryRequired(ctx, &j, j.State, actualErr)
	}
	if actual.MarkerTransactionID != "" && !bootMarkerSame(actual, transactionID) {
		return BootRecoveryResultV1{}, upgradeError(JournalRecoveryRequired, "integrity_failed")
	}
	if actual.MarkerTransactionID == "" {
		if err := e.Store.EnsureMarker(ctx, transactionID); err != nil {
			return BootRecoveryResultV1{}, e.bootRecoveryRequired(ctx, &j, j.State, err)
		}
		actual, actualErr = e.Store.ReadActualState(ctx, j.OldActivationID, j.CandidateActivationID)
		if actualErr != nil || !bootMarkerSame(actual, transactionID) {
			return BootRecoveryResultV1{}, e.bootRecoveryRequired(ctx, &j, j.State, errors.New("boot marker was not provable"))
		}
	}
	if j.State == JournalCommitted {
		if !actualMatchesCandidate(actual, j) || !actualPreviousOld(actual, j) {
			return BootRecoveryResultV1{}, e.bootRecoveryRequired(ctx, &j, j.State, errors.New("committed activation drift"))
		}
		return bootResult(j), nil
	}
	if j.State == JournalRecoveryRequired {
		return BootRecoveryResultV1{}, upgradeError(JournalRecoveryRequired, "recovery_required")
	}
	if j.State == JournalRollbackSwitched {
		if !actualMatchesOld(actual, j) || actual.PreviousID != j.CandidateActivationID || actual.PreviousActivationJSONSHA256 != j.CandidateActivationJSONSHA256 {
			return BootRecoveryResultV1{}, e.bootRecoveryRequired(ctx, &j, j.State, errors.New("rollback pointer drift"))
		}
		if err := e.bootAdvance(ctx, &j, JournalRolledBack); err != nil {
			return BootRecoveryResultV1{}, e.bootRecoveryRequired(ctx, &j, j.State, err)
		}
		return bootResult(j), nil
	}
	if j.State == JournalAbortedPreSwitch || j.State == JournalRolledBack {
		if !actualMatchesOld(actual, j) {
			return BootRecoveryResultV1{}, e.bootRecoveryRequired(ctx, &j, j.State, errors.New("terminal old activation drift"))
		}
		if j.State == JournalAbortedPreSwitch && !actualBaselinePrevious(actual, j) || j.State == JournalRolledBack && !actualPreviousOld(actual, j) {
			return BootRecoveryResultV1{}, e.bootRecoveryRequired(ctx, &j, j.State, errors.New("terminal previous activation drift"))
		}
		return bootResult(j), nil
	}
	if actualMatchesOld(actual, j) {
		if err := e.bootAbortOld(ctx, &j, actual); err != nil {
			return BootRecoveryResultV1{}, e.bootRecoveryRequired(ctx, &j, j.State, err)
		}
		return bootResult(j), nil
	}
	if actualMatchesCandidate(actual, j) {
		if err := e.bootRollbackCandidate(ctx, &j, actual); err != nil {
			return BootRecoveryResultV1{}, e.bootRecoveryRequired(ctx, &j, j.State, err)
		}
		return bootResult(j), nil
	}
	return BootRecoveryResultV1{}, e.bootRecoveryRequired(ctx, &j, j.State, errors.New("activation state is not provable"))
}

// FinalizeBoot is the only boot phase permitted to restore services or remove
// the marker. It accepts only a coherent terminal transaction with that same
// marker still present.
func (e *UpgradeEngine) FinalizeBoot(ctx context.Context, transactionID string) (result BootRecoveryResultV1, returnErr error) {
	if e == nil || e.Store == nil || e.Services == nil || e.Now == nil || !validID(transactionID) {
		return BootRecoveryResultV1{}, upgradeError(JournalRecoveryRequired, "invalid_request")
	}
	lock, err := acquireUpgradeLock(ctx, e.Store, transactionID, JournalRecoveryRequired)
	if err != nil {
		return BootRecoveryResultV1{}, err
	}
	defer func() {
		if err := lock.Release(); err != nil && returnErr == nil {
			result = BootRecoveryResultV1{}
			returnErr = upgradeError(JournalRecoveryRequired, "lock_release_failed")
		}
	}()
	j, err := e.Store.LoadJournal(ctx, transactionID)
	if err != nil || j.TransactionID != transactionID || j.Validate() != nil {
		_ = e.Services.GuardEdge(ctx)
		return BootRecoveryResultV1{}, upgradeError(JournalRecoveryRequired, "integrity_failed")
	}
	actual, err := e.Store.ReadActualState(ctx, j.OldActivationID, j.CandidateActivationID)
	if err != nil || !bootMarkerSame(actual, transactionID) {
		_ = e.Store.EnsureMarker(ctx, transactionID)
		_ = e.Services.GuardEdge(ctx)
		return BootRecoveryResultV1{}, upgradeError(JournalRecoveryRequired, "recovery_required")
	}
	switch j.State {
	case JournalCommitted:
		if !actualMatchesCandidate(actual, j) || !actualPreviousOld(actual, j) {
			_ = e.Services.GuardEdge(ctx)
			return BootRecoveryResultV1{}, upgradeError(JournalCommitted, "integrity_failed")
		}
		if err := e.Services.StartInternal(ctx); err != nil {
			_ = e.Services.GuardEdge(ctx)
			return BootRecoveryResultV1{}, upgradeErrorWith(JournalCommitted, "internal_start_failed", err)
		}
		if err := e.Services.HealthInternal(ctx); err != nil {
			_ = e.Services.GuardEdge(ctx)
			return BootRecoveryResultV1{}, upgradeErrorWith(JournalCommitted, "internal_health_failed", err)
		}
		if err := e.convergeCommittedPublic(ctx, &j, transactionID, actual.MarkerTransactionID); err != nil {
			return BootRecoveryResultV1{}, err
		}
		return finalizedBootResult(j), nil
	case JournalAbortedPreSwitch, JournalRolledBack:
		if !actualMatchesOld(actual, j) || j.State == JournalAbortedPreSwitch && !actualBaselinePrevious(actual, j) || j.State == JournalRolledBack && (actual.PreviousID != j.CandidateActivationID || actual.PreviousActivationJSONSHA256 != j.CandidateActivationJSONSHA256) {
			_ = e.Services.GuardEdge(ctx)
			return BootRecoveryResultV1{}, upgradeError(j.State, "integrity_failed")
		}
		if err := e.restoreOldServices(ctx, &j); err != nil {
			_ = e.Store.EnsureMarker(ctx, transactionID)
			_ = e.Services.GuardEdge(ctx)
			return BootRecoveryResultV1{}, upgradeErrorWith(j.State, "finalize_failed", err)
		}
		return finalizedBootResult(j), nil
	default:
		_ = e.Store.EnsureMarker(ctx, transactionID)
		_ = e.Services.GuardEdge(ctx)
		return BootRecoveryResultV1{}, upgradeError(JournalRecoveryRequired, "recovery_required")
	}
}
