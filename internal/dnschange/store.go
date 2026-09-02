package dnschange

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrIdempotencyConflict = errors.New("DNS change idempotency key reused with different input")
var ErrNotFound = errors.New("DNS change ownership not found")
var ErrOwnershipConflict = errors.New("DNS ownership identity cannot be rewritten")

type Store struct{ db *sql.DB }

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

func (s *Store) SavePlan(ctx context.Context, plan Plan) (Plan, bool, error) {
	if s == nil || s.db == nil {
		return Plan{}, false, errors.New("DNS change store is unavailable")
	}
	if plan.IdempotencyKey == "" || plan.InputDigest == "" || plan.ID == "" {
		return Plan{}, false, errors.New("DNS change plan is incomplete")
	}
	payload, err := json.Marshal(plan.Changes)
	if err != nil {
		return Plan{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Plan{}, false, err
	}
	rollback := func(cause error) (Plan, bool, error) { _ = tx.Rollback(); return Plan{}, false, cause }
	result, err := tx.ExecContext(ctx, `INSERT INTO dns_change_plans(id,idempotency_key,input_digest,changes,created_at) VALUES($1,$2,$3,$4::jsonb,$5) ON CONFLICT(idempotency_key) DO NOTHING`, plan.ID, plan.IdempotencyKey, plan.InputDigest, payload, plan.CreatedAt.UTC())
	if err != nil {
		return rollback(err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return rollback(err)
	}
	if rows == 1 {
		if err := tx.Commit(); err != nil {
			return Plan{}, false, err
		}
		return plan, false, nil
	}
	var stored Plan
	var changes []byte
	if err := tx.QueryRowContext(ctx, `SELECT id,idempotency_key,input_digest,changes,created_at FROM dns_change_plans WHERE idempotency_key=$1 FOR UPDATE`, plan.IdempotencyKey).Scan(&stored.ID, &stored.IdempotencyKey, &stored.InputDigest, &changes, &stored.CreatedAt); err != nil {
		return rollback(err)
	}
	if stored.InputDigest != plan.InputDigest {
		return rollback(ErrIdempotencyConflict)
	}
	if err := json.Unmarshal(changes, &stored.Changes); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return Plan{}, false, err
	}
	return stored, true, nil
}

// FindPlan returns the immutable plan recorded for an idempotency key.  An
// executor uses it before computing a new plan so a replay never turns a
// successfully applied create into a second provider write.
func (s *Store) FindPlan(ctx context.Context, idempotencyKey string) (Plan, bool, error) {
	if s == nil || s.db == nil || strings.TrimSpace(idempotencyKey) == "" {
		return Plan{}, false, errors.New("DNS change plan lookup is invalid")
	}
	var plan Plan
	var changes []byte
	err := s.db.QueryRowContext(ctx, `SELECT id,idempotency_key,input_digest,changes,created_at FROM dns_change_plans WHERE idempotency_key=$1`, idempotencyKey).Scan(&plan.ID, &plan.IdempotencyKey, &plan.InputDigest, &changes, &plan.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Plan{}, false, nil
	}
	if err != nil {
		return Plan{}, false, err
	}
	if err := json.Unmarshal(changes, &plan.Changes); err != nil {
		return Plan{}, false, err
	}
	return plan, true, nil
}

func (s *Store) EnsureExecutionSteps(ctx context.Context, plan Plan) ([]ExecutionStep, error) {
	if s == nil || s.db == nil || plan.ID == "" || plan.InputDigest == "" {
		return nil, errors.New("DNS execution plan is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	rollback := func(cause error) ([]ExecutionStep, error) { _ = tx.Rollback(); return nil, cause }
	for index, change := range plan.Changes {
		fingerprint := changeFingerprint(plan, index, change)
		if _, err := tx.ExecContext(ctx, `INSERT INTO dns_change_execution_steps(plan_id,change_index,request_fingerprint,phase,updated_at)
			VALUES($1,$2,$3,'planned',now()) ON CONFLICT(plan_id,change_index) DO NOTHING`, plan.ID, index, fingerprint); err != nil {
			return rollback(err)
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT plan_id,change_index,request_fingerprint,phase FROM dns_change_execution_steps WHERE plan_id=$1 ORDER BY change_index`, plan.ID)
	if err != nil {
		return rollback(err)
	}
	defer rows.Close()
	steps := make([]ExecutionStep, 0, len(plan.Changes))
	for rows.Next() {
		var step ExecutionStep
		if err := rows.Scan(&step.PlanID, &step.ChangeIndex, &step.RequestFingerprint, &step.Phase); err != nil {
			return rollback(err)
		}
		if step.ChangeIndex < 0 || step.ChangeIndex >= len(plan.Changes) || step.RequestFingerprint != changeFingerprint(plan, step.ChangeIndex, plan.Changes[step.ChangeIndex]) || !validExecutionPhase(step.Phase) {
			return rollback(ErrExecutionConflict)
		}
		steps = append(steps, step)
	}
	if err := rows.Err(); err != nil {
		return rollback(err)
	}
	if len(steps) != len(plan.Changes) {
		return rollback(ErrExecutionConflict)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return steps, nil
}

// ClaimProviderWrite atomically performs the only transition which grants
// permission to send a provider mutation. A separate Executor process may
// read the same planned step, but only one transaction can win this CAS.
func (s *Store) ClaimProviderWrite(ctx context.Context, zone ManagedZone, step ExecutionStep) (ExecutionPhase, bool, error) {
	if s == nil || s.db == nil || zone.Validate() != nil || step.PlanID == "" || step.ChangeIndex < 0 || !validExecutionPhase(step.Phase) || !strings.HasPrefix(step.RequestFingerprint, "sha256:") {
		return "", false, errors.New("DNS execution write claim is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, err
	}
	rollback := func(cause error) (ExecutionPhase, bool, error) { _ = tx.Rollback(); return "", false, cause }
	var current ExecutionPhase
	if err := tx.QueryRowContext(ctx, `SELECT phase FROM dns_change_execution_steps WHERE plan_id=$1 AND change_index=$2 AND request_fingerprint=$3 FOR UPDATE`, step.PlanID, step.ChangeIndex, step.RequestFingerprint).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return rollback(ErrNotFound)
		}
		return rollback(err)
	}
	if !validExecutionPhase(current) {
		return rollback(ErrExecutionConflict)
	}
	if current != ExecutionPlanned {
		if err := tx.Commit(); err != nil {
			return "", false, err
		}
		return current, false, nil
	}
	claim, err := tx.ExecContext(ctx, `INSERT INTO dns_change_execution_scopes(installation_id,provider,zone_id,plan_id,change_index,request_fingerprint)
		VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(installation_id,provider,zone_id) DO NOTHING`,
		zone.InstallationID, zone.Provider, zone.ZoneID, step.PlanID, step.ChangeIndex, step.RequestFingerprint)
	if err != nil {
		return rollback(err)
	}
	claimedRows, err := claim.RowsAffected()
	if err != nil {
		return rollback(err)
	}
	if claimedRows != 1 {
		if err := tx.Commit(); err != nil {
			return "", false, err
		}
		// This caller's step remains planned. The executor treats this as a
		// read-only reconciliation-required outcome, never as permission to
		// issue a second zone mutation.
		return ExecutionReconcileRequired, false, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dns_change_execution_steps SET phase='write_started',updated_at=now() WHERE plan_id=$1 AND change_index=$2 AND request_fingerprint=$3 AND phase='planned'`, step.PlanID, step.ChangeIndex, step.RequestFingerprint); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return "", false, err
	}
	return ExecutionWriteStarted, true, nil
}

// SetExecutionPhase performs the transition only for the exact immutable
// change fingerprint. A stale process cannot mark another plan's mutation as
// applied merely because it has the same ordinal position.
func (s *Store) SetExecutionPhase(ctx context.Context, step ExecutionStep, next ExecutionPhase) error {
	if s == nil || s.db == nil || step.PlanID == "" || step.ChangeIndex < 0 || !validExecutionPhase(step.Phase) || !validExecutionPhase(next) || !strings.HasPrefix(step.RequestFingerprint, "sha256:") {
		return errors.New("DNS execution phase is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	rollback := func(cause error) error { _ = tx.Rollback(); return cause }
	var current ExecutionPhase
	if err := tx.QueryRowContext(ctx, `SELECT phase FROM dns_change_execution_steps WHERE plan_id=$1 AND change_index=$2 AND request_fingerprint=$3 FOR UPDATE`, step.PlanID, step.ChangeIndex, step.RequestFingerprint).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return rollback(ErrNotFound)
		}
		return rollback(err)
	}
	if !validExecutionPhase(current) || !validExecutionTransition(current, next) {
		return rollback(ErrExecutionConflict)
	}
	if current != next {
		if _, err := tx.ExecContext(ctx, `UPDATE dns_change_execution_steps SET phase=$4,updated_at=now() WHERE plan_id=$1 AND change_index=$2 AND request_fingerprint=$3`, step.PlanID, step.ChangeIndex, step.RequestFingerprint, next); err != nil {
			return rollback(err)
		}
	}
	if next == ExecutionApplied {
		if _, err := tx.ExecContext(ctx, `DELETE FROM dns_change_execution_scopes WHERE plan_id=$1 AND change_index=$2 AND request_fingerprint=$3`, step.PlanID, step.ChangeIndex, step.RequestFingerprint); err != nil {
			return rollback(err)
		}
	}
	return tx.Commit()
}

func validExecutionPhase(phase ExecutionPhase) bool {
	return phase == ExecutionPlanned || phase == ExecutionWriteStarted || phase == ExecutionReconcileRequired || phase == ExecutionApplied
}

func validExecutionTransition(current, next ExecutionPhase) bool {
	if current == next {
		return current == ExecutionReconcileRequired || current == ExecutionApplied
	}
	switch current {
	case ExecutionPlanned:
		return next == ExecutionWriteStarted || next == ExecutionApplied || next == ExecutionReconcileRequired
	case ExecutionWriteStarted:
		return next == ExecutionReconcileRequired || next == ExecutionApplied
	case ExecutionReconcileRequired:
		return next == ExecutionApplied
	default:
		return false
	}
}

func (s *Store) ListOwned(ctx context.Context, installationID, provider, zoneID string) ([]OwnedRecord, error) {
	if s == nil || s.db == nil || !validInstallationID(installationID) || !validProvider(provider) || !validOpaqueID(zoneID) {
		return nil, errors.New("DNS change store is unavailable")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT installation_id,owner_key,provider,zone_id,domain,record_id,name,record_type,value,ttl,last_request_id,created_at,updated_at,COALESCE(last_plan_id,'') FROM dns_change_owned_records WHERE installation_id=$1 AND provider=$2 AND zone_id=$3 ORDER BY owner_key`, installationID, provider, zoneID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []OwnedRecord{}
	for rows.Next() {
		var item OwnedRecord
		if err := rows.Scan(&item.Record.InstallationID, &item.OwnerKey, &item.Record.Provider, &item.Record.ZoneID, &item.Record.Domain, &item.Record.RecordID, &item.Record.Name, &item.Record.Type, &item.Record.Value, &item.Record.TTL, &item.Record.RequestID, &item.Record.CreatedAt, &item.UpdatedAt, &item.LastPlanID); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// UpsertOwned is deliberately local-only. A future confirmed operator writer
// must call it with the provider-returned RecordId and RequestId after a write.
func (s *Store) UpsertOwned(ctx context.Context, owned OwnedRecord) error {
	if s == nil || s.db == nil {
		return errors.New("DNS change store is unavailable")
	}
	if !ownerKeyPattern.MatchString(owned.OwnerKey) || owned.Validate() != nil {
		return errors.New("DNS ownership record is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	rollback := func(cause error) error { _ = tx.Rollback(); return cause }
	var current OwnedRecord
	err = tx.QueryRowContext(ctx, `SELECT installation_id,owner_key,provider,zone_id,domain,record_id,name,record_type,value,ttl,last_request_id,created_at,updated_at,COALESCE(last_plan_id,'') FROM dns_change_owned_records WHERE installation_id=$1 AND owner_key=$2 FOR UPDATE`, owned.Record.InstallationID, owned.OwnerKey).Scan(&current.Record.InstallationID, &current.OwnerKey, &current.Record.Provider, &current.Record.ZoneID, &current.Record.Domain, &current.Record.RecordID, &current.Record.Name, &current.Record.Type, &current.Record.Value, &current.Record.TTL, &current.Record.RequestID, &current.Record.CreatedAt, &current.UpdatedAt, &current.LastPlanID)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO dns_change_owned_records(installation_id,owner_key,provider,zone_id,domain,record_id,name,record_type,value,ttl,last_request_id,created_at,updated_at,last_plan_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, owned.Record.InstallationID, owned.OwnerKey, owned.Record.Provider, owned.Record.ZoneID, owned.Record.Domain, owned.Record.RecordID, owned.Record.Name, owned.Record.Type, owned.Record.Value, owned.Record.TTL, owned.Record.RequestID, owned.Record.CreatedAt.UTC(), owned.UpdatedAt.UTC(), nullable(owned.LastPlanID)); err != nil {
			return rollback(err)
		}
		return tx.Commit()
	}
	if err != nil {
		return rollback(err)
	}
	if !sameOwnershipIdentity(current, owned) {
		return rollback(ErrOwnershipConflict)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dns_change_owned_records SET value=$3,ttl=$4,last_request_id=$5,updated_at=$6,last_plan_id=$7 WHERE installation_id=$1 AND owner_key=$2`, owned.Record.InstallationID, owned.OwnerKey, owned.Record.Value, owned.Record.TTL, owned.Record.RequestID, owned.UpdatedAt.UTC(), nullable(owned.LastPlanID)); err != nil {
		return rollback(err)
	}
	return tx.Commit()
}

// DeleteOwnedExact removes only the exact ownership fact which was just
// verified against the provider.  It cannot remove another provider record
// merely because it has the same owner key.
func (s *Store) DeleteOwnedExact(ctx context.Context, owned OwnedRecord) error {
	if s == nil || s.db == nil || owned.Validate() != nil {
		return errors.New("DNS ownership record is invalid")
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM dns_change_owned_records
		WHERE installation_id=$1 AND owner_key=$2 AND provider=$3 AND zone_id=$4
		  AND domain=$5 AND record_id=$6 AND name=$7 AND record_type=$8
		  AND value=$9 AND ttl=$10 AND last_request_id=$11`,
		owned.Record.InstallationID, owned.OwnerKey, owned.Record.Provider,
		owned.Record.ZoneID, owned.Record.Domain, owned.Record.RecordID,
		owned.Record.Name, owned.Record.Type, owned.Record.Value, owned.Record.TTL,
		owned.Record.RequestID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrNotFound
	}
	return nil
}

func sameOwnershipIdentity(left, right OwnedRecord) bool {
	return left.OwnerKey == right.OwnerKey && left.Record.InstallationID == right.Record.InstallationID && left.Record.Provider == right.Record.Provider && left.Record.ZoneID == right.Record.ZoneID && left.Record.Domain == right.Record.Domain && left.Record.RecordID == right.Record.RecordID && left.Record.Name == right.Record.Name && left.Record.Type == right.Record.Type
}

func (s *Store) LastReconcile(ctx context.Context, scope string) (time.Time, error) {
	if s == nil || s.db == nil {
		return time.Time{}, errors.New("DNS change store is unavailable")
	}
	var value time.Time
	err := s.db.QueryRowContext(ctx, `SELECT last_run_at FROM dns_change_reconcile_state WHERE scope=$1`, strings.TrimSpace(scope)).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	return value.UTC(), err
}

func (s *Store) SetLastReconcile(ctx context.Context, scope string, now time.Time) error {
	if s == nil || s.db == nil || strings.TrimSpace(scope) == "" {
		return errors.New("DNS reconcile scope is invalid")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO dns_change_reconcile_state(scope,last_run_at) VALUES($1,$2) ON CONFLICT(scope) DO UPDATE SET last_run_at=EXCLUDED.last_run_at`, scope, now.UTC())
	return err
}

func nullable(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func (s *Store) String() string { return fmt.Sprintf("dnschange.Store{%t}", s != nil && s.db != nil) }
