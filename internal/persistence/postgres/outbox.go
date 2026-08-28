package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/compatibility"
)

// OutboxEvent is the persistence-shaped event record. Sequence is the
// aggregate-local sequence retained by the original M0 schema; StreamSequence
// is the global replay cursor added by migration 0004.
type OutboxEvent struct {
	ID               string
	AggregateType    string
	AggregateID      string
	AggregateVersion int64
	Sequence         int64
	StreamSequence   int64
	EventType        string
	Payload          json.RawMessage
	CreatedAt        time.Time
	PublishedAt      *time.Time
	PayloadVersion   string
}

// AppendOutboxEvent appends one event and allocates a global stream sequence.
// Aggregate sequence allocation is serialized by a transaction-scoped
// advisory lock, so concurrent writers cannot create duplicate local
// versions. The payload and all identifying fields are immutable after insert;
// only published_at may be changed by MarkOutboxPublished.
func (s *Store) AppendOutboxEvent(ctx context.Context, event OutboxEvent) (OutboxEvent, error) {
	if err := s.requireDB(); err != nil {
		return OutboxEvent{}, err
	}
	if err := validateOutboxEvent(event); err != nil {
		return OutboxEvent{}, err
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = s.now().UTC()
	} else {
		event.CreatedAt = event.CreatedAt.UTC()
	}
	if event.Payload == nil {
		event.Payload = json.RawMessage(`{}`)
	}
	if event.PayloadVersion == "" {
		event.PayloadVersion = "1.0"
	}
	if !json.Valid(event.Payload) {
		return OutboxEvent{}, errors.New("outbox payload must be valid JSON")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OutboxEvent{}, fmt.Errorf("begin append outbox transaction: %w", err)
	}
	rollback := func(cause error) (OutboxEvent, error) {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			return OutboxEvent{}, fmt.Errorf("%w (rollback: %v)", cause, rollbackErr)
		}
		return OutboxEvent{}, cause
	}
	lockKey := "open-card-outbox:" + event.AggregateType + ":" + event.AggregateID
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return rollback(fmt.Errorf("serialize aggregate event sequence: %w", err))
	}
	if event.Sequence <= 0 {
		if err := tx.QueryRowContext(ctx, `
			SELECT COALESCE(MAX(sequence), 0) + 1
			  FROM outbox_events
			 WHERE aggregate_type = $1 AND aggregate_id = $2
		`, event.AggregateType, event.AggregateID).Scan(&event.Sequence); err != nil {
			return rollback(fmt.Errorf("allocate aggregate event sequence: %w", err))
		}
	}
	if event.StreamSequence <= 0 {
		event.StreamSequence, err = s.nextStreamSequence(ctx, tx)
		if err != nil {
			return rollback(err)
		}
	}
	if event.StreamSequence <= 0 {
		return rollback(errors.New("outbox stream sequence must be positive"))
	}
	if event.ID == "" {
		event.ID = "evt-" + formatSequence(uint64(event.StreamSequence))
	}
	if event.PublishedAt != nil {
		value := event.PublishedAt.UTC()
		event.PublishedAt = &value
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO outbox_events
			(id, aggregate_type, aggregate_id, aggregate_version, sequence,
			 stream_sequence, event_type, payload, created_at, published_at, payload_version)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11)
	`, event.ID, event.AggregateType, event.AggregateID, event.AggregateVersion, event.Sequence, event.StreamSequence, event.EventType, event.Payload, event.CreatedAt, event.PublishedAt, event.PayloadVersion); err != nil {
		return rollback(fmt.Errorf("insert outbox event: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return OutboxEvent{}, fmt.Errorf("%w: commit outbox event: %v", ErrOutcomeUnknown, err)
	}
	return cloneOutboxEvent(event), nil
}

// AppendEvent is an ergonomic alias for AppendOutboxEvent.
func (s *Store) AppendEvent(ctx context.Context, event OutboxEvent) (OutboxEvent, error) {
	return s.AppendOutboxEvent(ctx, event)
}

// FetchOutbox returns unpublished events in global stream order.
func (s *Store) FetchOutbox(ctx context.Context, limit int) ([]OutboxEvent, error) {
	return s.FetchOutboxAfter(ctx, 0, limit)
}

// FetchOutboxAfter returns unpublished events strictly after a stream cursor.
// It does not hold row locks across the method call; delivery must be
// idempotent and finalized with MarkOutboxPublished.
func (s *Store) FetchOutboxAfter(ctx context.Context, afterSequence int64, limit int) ([]OutboxEvent, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if afterSequence < 0 {
		return nil, errors.New("outbox stream cursor must not be negative")
	}
	limit, err := normalizeLimit(limit)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, aggregate_type, aggregate_id, aggregate_version, sequence,
		       stream_sequence, event_type, payload, created_at, published_at, payload_version
		  FROM outbox_events
		 WHERE published_at IS NULL AND stream_sequence > $1
		 ORDER BY stream_sequence
		 LIMIT $2
	`, afterSequence, limit)
	if err != nil {
		return nil, fmt.Errorf("fetch pending outbox events: %w", err)
	}
	defer rows.Close()
	items := make([]OutboxEvent, 0, limit)
	for rows.Next() {
		item, err := scanOutboxEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan pending outbox event: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending outbox events: %w", err)
	}
	return items, nil
}

// MarkOutboxPublished marks an event once. It returns false when the event was
// already marked (or no longer exists), making publisher retries harmless.
func (s *Store) MarkOutboxPublished(ctx context.Context, eventID string, publishedAt time.Time) (bool, error) {
	if err := s.requireDB(); err != nil {
		return false, err
	}
	eventID = strings.TrimSpace(eventID)
	if eventID == "" {
		return false, errors.New("outbox event id is required")
	}
	if publishedAt.IsZero() {
		publishedAt = s.now()
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE outbox_events
		   SET published_at = COALESCE(published_at, $2)
		 WHERE id = $1 AND published_at IS NULL
	`, eventID, publishedAt.UTC())
	if err != nil {
		return false, fmt.Errorf("mark outbox event published: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("inspect outbox publish result: %w", err)
	}
	return rows == 1, nil
}

// ListEvents replays the append-only event stream through the application
// repository contract. AfterSequence always refers to the global stream
// sequence, even when an operation filter is present.
func (s *Store) ListEvents(ctx context.Context, filter application.EventFilter) ([]application.Event, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if filter.AfterSequence > uint64(^uint64(0)>>1) {
		return nil, errors.New("event stream cursor exceeds PostgreSQL bigint")
	}
	limit, err := normalizeLimit(filter.Limit)
	if err != nil {
		return nil, err
	}
	operationID := strings.TrimSpace(filter.OperationID)
	var since any
	if !filter.Since.IsZero() {
		since = filter.Since.UTC()
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, aggregate_id, stream_sequence, event_type, payload, created_at, payload_version
		  FROM outbox_events
		 WHERE stream_sequence > $1
		   AND ($2 = '' OR (aggregate_type = 'operation' AND aggregate_id = $2))
		   AND ($3::timestamptz IS NULL OR created_at >= $3)
		 ORDER BY stream_sequence
		 LIMIT $4
	`, int64(filter.AfterSequence), operationID, since, limit)
	if err != nil {
		return nil, fmt.Errorf("replay application events: %w", err)
	}
	defer rows.Close()
	events := make([]application.Event, 0, limit)
	for rows.Next() {
		var id, operationID string
		var streamSequence int64
		var eventType string
		var payload []byte
		var createdAt time.Time
		var payloadVersion string
		if err := rows.Scan(&id, &operationID, &streamSequence, &eventType, &payload, &createdAt, &payloadVersion); err != nil {
			return nil, fmt.Errorf("scan replay event: %w", err)
		}
		if streamSequence <= 0 {
			return nil, fmt.Errorf("%w: event %q has invalid stream sequence", ErrIdempotencyCorrupt, id)
		}
		var event application.Event
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, fmt.Errorf("%w: event %q payload is invalid JSON", ErrIdempotencyCorrupt, id)
		}
		event.ID = id
		event.OperationID = operationID
		event.Sequence = uint64(streamSequence)
		event.Kind = eventType
		if event.OccurredAt.IsZero() {
			event.OccurredAt = createdAt.UTC()
		} else {
			event.OccurredAt = event.OccurredAt.UTC()
		}
		version, err := compatibility.Parse(payloadVersion)
		if err != nil || version.Major != 1 || version.Minor > 1 {
			return nil, fmt.Errorf("%w: event %q payload version is incompatible", ErrIdempotencyCorrupt, id)
		}
		if event.SchemaVersion == "" {
			event.SchemaVersion = version.String()
		} else if event.SchemaVersion != version.String() {
			return nil, fmt.Errorf("%w: event %q schema version disagrees with durable metadata", ErrIdempotencyCorrupt, id)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate replay events: %w", err)
	}
	return events, nil
}

// ReplayEvents is an explicit alias for ListEvents.
func (s *Store) ReplayEvents(ctx context.Context, filter application.EventFilter) ([]application.Event, error) {
	return s.ListEvents(ctx, filter)
}

// ReplayOperationEvents is a convenience for SSE handlers.
func (s *Store) ReplayOperationEvents(ctx context.Context, operationID string, afterSequence uint64, limit int) ([]application.Event, error) {
	return s.ListEvents(ctx, application.EventFilter{OperationID: operationID, AfterSequence: afterSequence, Limit: limit})
}

func validateOutboxEvent(event OutboxEvent) error {
	if strings.TrimSpace(event.AggregateType) == "" || strings.TrimSpace(event.AggregateID) == "" {
		return errors.New("outbox aggregate type and id are required")
	}
	if event.AggregateVersion <= 0 || event.Sequence < 0 || event.StreamSequence < 0 {
		return errors.New("outbox versions and sequences are invalid")
	}
	if strings.TrimSpace(event.EventType) == "" {
		return errors.New("outbox event type is required")
	}
	return nil
}

func normalizeLimit(limit int) (int, error) {
	if limit <= 0 {
		return defaultQueryLimit, nil
	}
	if limit > maxQueryLimit {
		return 0, fmt.Errorf("query limit exceeds maximum %d", maxQueryLimit)
	}
	return limit, nil
}

func scanOutboxEvent(scanner interface{ Scan(...any) error }) (OutboxEvent, error) {
	var item OutboxEvent
	var payload []byte
	var publishedAt sql.NullTime
	if err := scanner.Scan(&item.ID, &item.AggregateType, &item.AggregateID, &item.AggregateVersion, &item.Sequence, &item.StreamSequence, &item.EventType, &payload, &item.CreatedAt, &publishedAt, &item.PayloadVersion); err != nil {
		return OutboxEvent{}, err
	}
	if !json.Valid(payload) {
		return OutboxEvent{}, errors.New("outbox payload is invalid JSON")
	}
	item.Payload = append(json.RawMessage(nil), payload...)
	if publishedAt.Valid {
		value := publishedAt.Time.UTC()
		item.PublishedAt = &value
	}
	item.CreatedAt = item.CreatedAt.UTC()
	return item, nil
}

func cloneOutboxEvent(event OutboxEvent) OutboxEvent {
	event.Payload = append(json.RawMessage(nil), event.Payload...)
	if event.PublishedAt != nil {
		value := event.PublishedAt.UTC()
		event.PublishedAt = &value
	}
	return event
}
