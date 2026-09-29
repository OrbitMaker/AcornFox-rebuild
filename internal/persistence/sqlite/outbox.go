package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	contracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/compatibility"
)

var _ contracts.OutboxRepository = (*Store)(nil)

// appendOutboxTx owns both sequence allocations and the immutable insert. The
// private encoder lets application creation include the allocated cursor in
// its durable Event without a separate update or post-commit write.
func appendOutboxTx(ctx context.Context, tx *sql.Tx, event contracts.OutboxEvent, encode func(string, int64) ([]byte, error)) (contracts.OutboxEvent, error) {
	if strings.TrimSpace(event.AggregateType) == "" || strings.TrimSpace(event.AggregateID) == "" || strings.TrimSpace(event.EventType) == "" || event.AggregateVersion <= 0 || event.Sequence < 0 || event.StreamSequence < 0 || event.PublishedAt != nil {
		return event, errors.New("invalid unpublished outbox identity")
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	event.CreatedAt = event.CreatedAt.UTC()
	if event.PayloadVersion == "" {
		event.PayloadVersion = "1.0"
	}
	version, err := compatibility.Parse(event.PayloadVersion)
	if err != nil || version.Major != 1 || version.Minor > 1 {
		return event, errors.New("outbox payload version is incompatible")
	}
	var local, global int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence),0) FROM outbox_events WHERE aggregate_type=? AND aggregate_id=?`, event.AggregateType, event.AggregateID).Scan(&local); err != nil {
		return event, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(stream_sequence),0) FROM outbox_events`).Scan(&global); err != nil {
		return event, err
	}
	if local == math.MaxInt64 || global == math.MaxInt64 {
		return event, errors.New("outbox sequence exhausted")
	}
	local++
	global++
	if (event.Sequence != 0 && event.Sequence != local) || (event.StreamSequence != 0 && event.StreamSequence != global) {
		return event, errors.New("outbox sequence must match next durable cursor")
	}
	event.Sequence = local
	event.StreamSequence = global
	if event.ID == "" {
		event.ID = "evt-" + formatSequence(uint64(global))
	}
	if encode != nil {
		event.Payload, err = encode(event.ID, global)
		if err != nil {
			return event, err
		}
	} else {
		event.Payload = append(json.RawMessage(nil), event.Payload...)
	}
	if !json.Valid(event.Payload) {
		return event, errors.New("outbox payload must be valid JSON")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO outbox_events(id,aggregate_type,aggregate_id,aggregate_version,sequence,stream_sequence,event_type,payload,created_at,payload_version) VALUES(?,?,?,?,?,?,?,?,?,?)`, event.ID, event.AggregateType, event.AggregateID, event.AggregateVersion, event.Sequence, event.StreamSequence, event.EventType, string(event.Payload), FormatTime(event.CreatedAt), event.PayloadVersion)
	return event, err
}
func (s *Store) AppendOutboxEvent(ctx context.Context, event contracts.OutboxEvent) (contracts.OutboxEvent, error) {
	if err := s.checkOpen(); err != nil {
		return event, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return event, err
	}
	defer tx.Rollback()
	stored, err := appendOutboxTx(ctx, tx, event, nil)
	if err != nil {
		return contracts.OutboxEvent{}, err
	}
	if err := tx.Commit(); err != nil {
		return contracts.OutboxEvent{}, fmt.Errorf("%w: commit outbox append: %v", ErrOutcomeUnknown, err)
	}
	return stored, nil
}
func (s *Store) FetchOutboxAfter(ctx context.Context, after int64, limit int) ([]contracts.OutboxEvent, error) {
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	if after < 0 {
		return nil, errors.New("outbox cursor must not be negative")
	}
	if limit <= 0 {
		limit = defaultQueryLimit
	}
	if limit > maxQueryLimit {
		return nil, errors.New("outbox limit exceeds maximum")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,aggregate_type,aggregate_id,aggregate_version,sequence,stream_sequence,event_type,payload,created_at,payload_version FROM outbox_events WHERE published_at IS NULL AND stream_sequence>? ORDER BY stream_sequence LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]contracts.OutboxEvent, 0)
	for rows.Next() {
		var e contracts.OutboxEvent
		var payload, created string
		if err := rows.Scan(&e.ID, &e.AggregateType, &e.AggregateID, &e.AggregateVersion, &e.Sequence, &e.StreamSequence, &e.EventType, &payload, &created, &e.PayloadVersion); err != nil {
			return nil, err
		}
		e.CreatedAt, err = ParseTime(created)
		if err != nil {
			return nil, err
		}
		if !json.Valid([]byte(payload)) {
			return nil, ErrIdempotencyCorrupt
		}
		e.Payload = json.RawMessage(payload)
		result = append(result, e)
	}
	return result, rows.Err()
}

// MarkOutboxPublished must be called only after delivery acknowledgement.
// Transactional first-write marking preserves history under retries.
func (s *Store) MarkOutboxPublished(ctx context.Context, id string, at time.Time) (bool, error) {
	if err := s.checkOpen(); err != nil {
		return false, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return false, errors.New("outbox event id required")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE outbox_events SET published_at=? WHERE id=? AND published_at IS NULL`, FormatTime(at.UTC()), id)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("%w: commit outbox publication: %v", ErrOutcomeUnknown, err)
	}
	return n == 1, nil
}
