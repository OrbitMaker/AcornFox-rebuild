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

func (s *Store) ListOwned(ctx context.Context, domainID int64) ([]OwnedRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("DNS change store is unavailable")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT owner_key,provider,domain_id,domain,record_id,host,record_type,value,ttl,last_request_id,created_at,updated_at,last_plan_id FROM dns_change_owned_records WHERE domain_id=$1 ORDER BY owner_key`, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []OwnedRecord{}
	for rows.Next() {
		var item OwnedRecord
		if err := rows.Scan(&item.OwnerKey, &item.Record.Provider, &item.Record.DomainID, &item.Record.Domain, &item.Record.RecordID, &item.Record.Host, &item.Record.Type, &item.Record.Value, &item.Record.TTL, &item.Record.RequestID, &item.Record.CreatedAt, &item.UpdatedAt, &item.LastPlanID); err != nil {
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
	err = tx.QueryRowContext(ctx, `SELECT owner_key,provider,domain_id,domain,record_id,host,record_type,value,ttl,last_request_id,created_at,updated_at,last_plan_id FROM dns_change_owned_records WHERE owner_key=$1 FOR UPDATE`, owned.OwnerKey).Scan(&current.OwnerKey, &current.Record.Provider, &current.Record.DomainID, &current.Record.Domain, &current.Record.RecordID, &current.Record.Host, &current.Record.Type, &current.Record.Value, &current.Record.TTL, &current.Record.RequestID, &current.Record.CreatedAt, &current.UpdatedAt, &current.LastPlanID)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO dns_change_owned_records(owner_key,provider,domain_id,domain,record_id,host,record_type,value,ttl,last_request_id,created_at,updated_at,last_plan_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, owned.OwnerKey, owned.Record.Provider, owned.Record.DomainID, owned.Record.Domain, owned.Record.RecordID, owned.Record.Host, owned.Record.Type, owned.Record.Value, owned.Record.TTL, owned.Record.RequestID, owned.Record.CreatedAt.UTC(), owned.UpdatedAt.UTC(), nullable(owned.LastPlanID)); err != nil {
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
	if _, err := tx.ExecContext(ctx, `UPDATE dns_change_owned_records SET value=$2,ttl=$3,last_request_id=$4,updated_at=$5,last_plan_id=$6 WHERE owner_key=$1`, owned.OwnerKey, owned.Record.Value, owned.Record.TTL, owned.Record.RequestID, owned.UpdatedAt.UTC(), nullable(owned.LastPlanID)); err != nil {
		return rollback(err)
	}
	return tx.Commit()
}

func sameOwnershipIdentity(left, right OwnedRecord) bool {
	return left.OwnerKey == right.OwnerKey && left.Record.Provider == right.Record.Provider && left.Record.DomainID == right.Record.DomainID && left.Record.Domain == right.Record.Domain && left.Record.RecordID == right.Record.RecordID && left.Record.Host == right.Record.Host && left.Record.Type == right.Record.Type
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
