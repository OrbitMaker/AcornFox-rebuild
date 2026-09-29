package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	application "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/compatibility"
	"github.com/acornfox/acornfox/internal/domain"
)

const (
	defaultEnvironmentName   = "default"
	defaultTaskMaxAttempts   = 3
	defaultQueryLimit        = 1000
	maxQueryLimit            = 10000
	createApplicationScope   = "application.create"
	createApplicationEvent   = "operation.created"
	createApplicationOpType  = "create_application"
	createApplicationTaskTag = "application.create"
)

var (
	ErrNotFound              = domain.ErrObjectNotFound
	ErrIdempotencyConflict   = application.ErrIdempotencyConflict
	ErrIdempotencyInProgress = application.ErrIdempotencyInProgress
	ErrIdempotencyCorrupt    = application.ErrIdempotencyCorrupt
	ErrOutcomeUnknown        = application.ErrOutcomeUnknown
)

var _ application.Repository = (*Store)(nil)

// PreflightCreateApplication performs a side-effect-free read of the idempotency record.
// Rejects any non-nil source input before side effects.
func (s *Store) PreflightCreateApplication(ctx context.Context, input application.CreateApplicationPreflight) (application.CreateApplicationResult, bool, error) {
	if err := s.checkOpen(); err != nil {
		return application.CreateApplicationResult{}, false, err
	}
	key, digest := strings.TrimSpace(input.IdempotencyKey), strings.TrimSpace(input.RequestDigest)
	if key == "" || digest == "" {
		return application.CreateApplicationResult{}, false, domain.ValidationError("application idempotency preflight is incomplete")
	}
	if input.Source != nil {
		return application.CreateApplicationResult{}, false, domain.NewError(domain.ErrUnsupportedCapability, "source application creation is unsupported in sqlite repository")
	}

	var storedDigest, status string
	var response sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT request_digest, status, response
		  FROM idempotency_records
		 WHERE scope = ? AND idempotency_key = ?;
	`, createApplicationScope, key).Scan(&storedDigest, &status, &response)
	if err == nil {
		if storedDigest != digest {
			return application.CreateApplicationResult{}, false, ErrIdempotencyConflict
		}
		switch status {
		case "completed":
			if !response.Valid || len(response.String) == 0 {
				return application.CreateApplicationResult{}, false, ErrIdempotencyCorrupt
			}
			result, decodeErr := decodeCreateApplicationResult([]byte(response.String))
			if decodeErr != nil {
				return application.CreateApplicationResult{}, false, decodeErr
			}
			return result, true, nil
		case "in_progress":
			return application.CreateApplicationResult{}, false, ErrIdempotencyInProgress
		default:
			return application.CreateApplicationResult{}, false, fmt.Errorf("%w: unsupported status %q", ErrIdempotencyCorrupt, status)
		}
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return application.CreateApplicationResult{}, false, fmt.Errorf("read application idempotency preflight: %w", err)
	}
	return application.CreateApplicationResult{}, false, nil
}

// CreateApplication creates the application, its default environment, initial operation and ready task,
// the first outbox event, and completed idempotency response within one short transaction.
// Follows the PostgreSQL source=nil path exactly. Rejects any non-nil source before side effects.
func (s *Store) CreateApplication(ctx context.Context, record application.CreateApplicationRecord) (application.CreateApplicationResult, error) {
	if err := s.checkOpen(); err != nil {
		return application.CreateApplicationResult{}, err
	}
	if err := validateCreateRecord(record); err != nil {
		return application.CreateApplicationResult{}, err
	}

	if err := validateAuditContext(record.Audit); err != nil {
		return application.CreateApplicationResult{}, err
	}
	digest := strings.TrimSpace(record.RequestDigest)
	if digest == "" {
		digest = applicationNameDigest(record.Application.Name)
	}
	createdAt := record.Application.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
		record.Application.CreatedAt = createdAt
	}
	if record.Application.UpdatedAt.IsZero() {
		record.Application.UpdatedAt = createdAt
	}
	if record.Event.OccurredAt.IsZero() {
		record.Event.OccurredAt = createdAt
	}
	if record.Event.ApplicationID == "" {
		record.Event.ApplicationID = record.Application.ID.String()
	}
	if record.Event.OperationID == "" {
		record.Event.OperationID = record.OperationID.String()
	}
	if record.Event.Kind == "" {
		record.Event.Kind = createApplicationEvent
	}
	if record.Event.SchemaVersion == "" {
		record.Event.SchemaVersion = "1.0"
	}

	createdAtStr := FormatTime(createdAt)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return application.CreateApplicationResult{}, fmt.Errorf("begin create application transaction: %w", err)
	}
	rollback := func(cause error) (application.CreateApplicationResult, error) {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			return application.CreateApplicationResult{}, fmt.Errorf("%w (rollback: %v)", cause, rollbackErr)
		}
		return application.CreateApplicationResult{}, cause
	}

	reservation, err := tx.ExecContext(ctx, `
		INSERT INTO idempotency_records
			(scope, idempotency_key, request_digest, status, created_at, updated_at)
		VALUES (?, ?, ?, 'in_progress', ?, ?)
		ON CONFLICT (scope, idempotency_key) DO NOTHING;
	`, createApplicationScope, record.IdempotencyKey, digest, createdAtStr, createdAtStr)
	if err != nil {
		return rollback(fmt.Errorf("reserve application idempotency key: %w", err))
	}
	inserted, err := reservation.RowsAffected()
	if err != nil {
		return rollback(fmt.Errorf("inspect application idempotency reservation: %w", err))
	}

	var storedDigest, storedStatus string
	var storedResponse sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT request_digest, status, response
		  FROM idempotency_records
		 WHERE scope = ? AND idempotency_key = ?;
	`, createApplicationScope, record.IdempotencyKey).Scan(&storedDigest, &storedStatus, &storedResponse); err != nil {
		return rollback(fmt.Errorf("read application idempotency record: %w", err))
	}
	if storedDigest != digest {
		return rollback(ErrIdempotencyConflict)
	}
	if inserted == 0 {
		switch storedStatus {
		case "completed":
			if !storedResponse.Valid || len(storedResponse.String) == 0 {
				return rollback(ErrIdempotencyCorrupt)
			}
			result, decodeErr := decodeCreateApplicationResult([]byte(storedResponse.String))
			if decodeErr != nil {
				return rollback(decodeErr)
			}
			if err := tx.Commit(); err != nil {
				return application.CreateApplicationResult{}, fmt.Errorf("%w: commit idempotent replay: %v", ErrOutcomeUnknown, err)
			}
			return result, nil
		case "in_progress":
			return rollback(ErrIdempotencyInProgress)
		default:
			return rollback(fmt.Errorf("%w: unsupported status %q", ErrIdempotencyCorrupt, storedStatus))
		}
	}
	if storedStatus != "in_progress" {
		return rollback(fmt.Errorf("%w: newly inserted record has status %q", ErrIdempotencyCorrupt, storedStatus))
	}

	// The in-progress record belongs to this transaction. Write all facts and complete the response.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO applications (id, name, version, created_at, updated_at)
		VALUES (?, ?, 1, ?, ?);
	`, record.Application.ID.String(), record.Application.Name, createdAtStr, FormatTime(record.Application.UpdatedAt.UTC())); err != nil {
		return rollback(fmt.Errorf("insert application: %w", err))
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO environments (id, application_id, name, created_at)
		VALUES (?, ?, ?, ?);
	`, record.EnvironmentID.String(), record.Application.ID.String(), defaultEnvironmentName, createdAtStr); err != nil {
		return rollback(fmt.Errorf("insert default environment: %w", err))
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO operations
			(id, application_id, environment_id, operation_type, idempotency_key,
			 state, version, target_ref, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 'pending', 1, ?, ?, ?);
	`, record.OperationID.String(), record.Application.ID.String(), record.EnvironmentID.String(), createApplicationOpType, record.IdempotencyKey, record.Application.ID.String(), createdAtStr, createdAtStr); err != nil {
		return rollback(fmt.Errorf("insert application operation: %w", err))
	}

	taskPayload, err := json.Marshal(map[string]string{
		"kind":               createApplicationTaskTag,
		"application_id":     record.Application.ID.String(),
		"operation_id":       record.OperationID.String(),
		"source_revision_id": "",
	})
	if err != nil {
		return rollback(fmt.Errorf("encode application task payload: %w", err))
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO task_leases
			(task_id, operation_id, lease_owner, lease_until, attempt, max_attempts,
			 state, payload, created_at, updated_at)
		VALUES (?, ?, NULL, NULL, 0, ?, 'ready', ?, ?, ?);
	`, record.TaskID.String(), record.OperationID.String(), defaultTaskMaxAttempts, string(taskPayload), createdAtStr, createdAtStr); err != nil {
		return rollback(fmt.Errorf("insert application task: %w", err))
	}

	event := record.Event
	_, err = appendOutboxTx(ctx, tx, application.OutboxEvent{
		ID: event.ID, AggregateType: "operation", AggregateID: record.OperationID.String(), AggregateVersion: 1,
		EventType: event.Kind, CreatedAt: event.OccurredAt.UTC(), PayloadVersion: event.SchemaVersion,
	}, func(id string, cursor int64) ([]byte, error) {
		event.ID = id
		event.Sequence = uint64(cursor)
		return json.Marshal(event)
	})
	if err != nil {
		return rollback(fmt.Errorf("insert application outbox event: %w", err))
	}

	auditID, err := domain.NewID("audit")
	if err != nil {
		return rollback(err)
	}
	if _, err := appendAuditTx(ctx, tx, auditInput{ID: auditID.String(), Actor: record.Audit, Action: "application.created", InputDigest: digest, Result: "accepted", EvidenceRefs: []string{record.Application.ID.String(), record.OperationID.String(), record.TaskID.String(), event.ID}, CreatedAt: createdAt}); err != nil {
		return rollback(fmt.Errorf("append application audit: %w", err))
	}

	result := application.CreateApplicationResult{
		Application:      record.Application,
		EnvironmentID:    record.EnvironmentID,
		OperationID:      record.OperationID,
		SourceRevisionID: "",
		Event:            event,
	}

	resultPayload, err := json.Marshal(result)
	if err != nil {
		return rollback(fmt.Errorf("encode application idempotency response: %w", err))
	}

	completedAt := time.Now().UTC()
	if completedAt.Before(createdAt) {
		completedAt = createdAt
	}
	completion, err := tx.ExecContext(ctx, `
		UPDATE idempotency_records
		   SET status = 'completed', response = ?, updated_at = ?
		 WHERE scope = ? AND idempotency_key = ? AND status = 'in_progress';
	`, string(resultPayload), FormatTime(completedAt), createApplicationScope, record.IdempotencyKey)
	if err != nil {
		return rollback(fmt.Errorf("complete application idempotency record: %w", err))
	}
	completedRows, err := completion.RowsAffected()
	if err != nil {
		return rollback(fmt.Errorf("inspect application idempotency completion: %w", err))
	}
	if completedRows != 1 {
		return rollback(ErrIdempotencyCorrupt)
	}

	if err := tx.Commit(); err != nil {
		return application.CreateApplicationResult{}, fmt.Errorf("%w: commit create application: %v", ErrOutcomeUnknown, err)
	}
	return result, nil
}

// ListApplications returns durable applications in creation order. The
// secondary ID ordering keeps results deterministic when timestamps tie.
func (s *Store) ListApplications(ctx context.Context) ([]domain.Application, error) {
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, created_at, updated_at
		  FROM applications
		 ORDER BY created_at, id;
	`)
	if err != nil {
		return nil, fmt.Errorf("list applications: %w", err)
	}
	defer rows.Close()

	items := make([]domain.Application, 0)
	for rows.Next() {
		var idStr, name, createdStr, updatedStr string
		if err := rows.Scan(&idStr, &name, &createdStr, &updatedStr); err != nil {
			return nil, fmt.Errorf("scan application: %w", err)
		}
		createdAt, err := ParseTime(createdStr)
		if err != nil {
			return nil, fmt.Errorf("parse application created_at: %w", ErrCorruptData)
		}
		updatedAt, err := ParseTime(updatedStr)
		if err != nil {
			return nil, fmt.Errorf("parse application updated_at: %w", ErrCorruptData)
		}
		item := domain.Application{
			ID:              domain.ID(idStr),
			Name:            name,
			ManagementState: domain.ApplicationManagementActive,
			CreatedAt:       createdAt,
			UpdatedAt:       updatedAt,
		}
		if err := item.Validate(); err != nil {
			return nil, fmt.Errorf("validate application %s: %w", idStr, ErrCorruptData)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate applications: %w", err)
	}
	return items, nil
}

// GetApplication returns one durable application or ErrNotFound.
func (s *Store) GetApplication(ctx context.Context, id domain.ID) (domain.Application, error) {
	if err := s.checkOpen(); err != nil {
		return domain.Application{}, err
	}
	if err := domain.RequireID(id, "application id"); err != nil {
		return domain.Application{}, err
	}
	var idStr, name, createdStr, updatedStr string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, created_at, updated_at
		  FROM applications
		 WHERE id = ?;
	`, id.String()).Scan(&idStr, &name, &createdStr, &updatedStr)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Application{}, ErrNotFound
	}
	if err != nil {
		return domain.Application{}, fmt.Errorf("get application %s: %w", id, err)
	}
	createdAt, err := ParseTime(createdStr)
	if err != nil {
		return domain.Application{}, fmt.Errorf("parse application created_at: %w", ErrCorruptData)
	}
	updatedAt, err := ParseTime(updatedStr)
	if err != nil {
		return domain.Application{}, fmt.Errorf("parse application updated_at: %w", ErrCorruptData)
	}
	item := domain.Application{
		ID:              domain.ID(idStr),
		Name:            name,
		ManagementState: domain.ApplicationManagementActive,
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
	}
	if err := item.Validate(); err != nil {
		return domain.Application{}, fmt.Errorf("validate application %s: %w", id, ErrCorruptData)
	}
	return item, nil
}

type outboxEventRow struct {
	id             string
	operationID    string
	streamSequence int64
	eventType      string
	payload        string
	createdAt      string
	payloadVersion string
}

func decodeOutboxEventRow(row outboxEventRow) (application.Event, error) {
	if row.streamSequence <= 0 {
		return application.Event{}, fmt.Errorf("%w: event %q has invalid stream sequence %d", ErrIdempotencyCorrupt, row.id, row.streamSequence)
	}
	createdAt, err := ParseTime(row.createdAt)
	if err != nil {
		return application.Event{}, fmt.Errorf("%w: event %q created_at is corrupt: %v", ErrIdempotencyCorrupt, row.id, err)
	}
	var event application.Event
	if err := json.Unmarshal([]byte(row.payload), &event); err != nil {
		return application.Event{}, fmt.Errorf("%w: event %q payload is invalid JSON: %v", ErrIdempotencyCorrupt, row.id, err)
	}
	event.ID = row.id
	event.OperationID = row.operationID
	event.Sequence = uint64(row.streamSequence)
	event.Kind = row.eventType
	if event.OccurredAt.IsZero() {
		event.OccurredAt = createdAt.UTC()
	} else {
		event.OccurredAt = event.OccurredAt.UTC()
	}
	version, err := compatibility.Parse(row.payloadVersion)
	if err != nil || version.Major != 1 || version.Minor > 1 {
		return application.Event{}, fmt.Errorf("%w: event %q payload version is incompatible", ErrIdempotencyCorrupt, row.id)
	}
	if event.SchemaVersion == "" {
		event.SchemaVersion = version.String()
	} else if event.SchemaVersion != version.String() {
		return application.Event{}, fmt.Errorf("%w: event %q schema version disagrees with durable metadata", ErrIdempotencyCorrupt, row.id)
	}
	return event, nil
}

// ListEvents replays the append-only event stream through the application
// repository contract. AfterSequence always refers to the global stream
// sequence, even when an operation filter is present.
func (s *Store) ListEvents(ctx context.Context, filter application.EventFilter) ([]application.Event, error) {
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	if filter.AfterSequence > uint64(^uint64(0)>>1) {
		return nil, errors.New("event stream cursor exceeds SQLite integer")
	}
	limit, err := normalizeQueryLimit(filter.Limit)
	if err != nil {
		return nil, err
	}
	operationID := strings.TrimSpace(filter.OperationID)
	var sinceStr sql.NullString
	if !filter.Since.IsZero() {
		sinceStr = sql.NullString{String: FormatTime(filter.Since.UTC()), Valid: true}
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, aggregate_id, stream_sequence, event_type, payload, created_at, payload_version
		  FROM outbox_events
		 WHERE aggregate_type = 'operation' AND stream_sequence > ?
		   AND (? = '' OR (aggregate_type = 'operation' AND aggregate_id = ?))
		   AND (? IS NULL OR created_at >= ?)
		 ORDER BY stream_sequence
		 LIMIT ?;
	`, int64(filter.AfterSequence), operationID, operationID, sinceStr, sinceStr, limit)
	if err != nil {
		return nil, fmt.Errorf("replay application events: %w", err)
	}
	defer rows.Close()

	events := make([]application.Event, 0, limit)
	for rows.Next() {
		var row outboxEventRow
		if err := rows.Scan(&row.id, &row.operationID, &row.streamSequence, &row.eventType, &row.payload, &row.createdAt, &row.payloadVersion); err != nil {
			return nil, fmt.Errorf("scan replay event: %w", err)
		}
		event, err := decodeOutboxEventRow(row)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate replay events: %w", err)
	}
	return events, nil
}

func validateCreateRecord(record application.CreateApplicationRecord) error {
	if record.Source != nil || record.PreparedSource != nil || record.PublicSourceProvenance != nil {
		return domain.NewError(domain.ErrUnsupportedCapability, "source application creation is unsupported in sqlite repository")
	}
	if err := record.Application.Validate(); err != nil {
		return err
	}
	if err := domain.RequireID(record.EnvironmentID, "environment id"); err != nil {
		return err
	}
	if err := domain.RequireID(record.OperationID, "operation id"); err != nil {
		return err
	}
	if err := domain.RequireID(record.TaskID, "task id"); err != nil {
		return err
	}
	if strings.TrimSpace(record.IdempotencyKey) == "" {
		return domain.ValidationError("idempotency key is required")
	}
	if record.Event.OperationID != "" && record.Event.OperationID != record.OperationID.String() {
		return domain.ValidationError("event operation does not match operation id")
	}
	if record.Event.ApplicationID != "" && record.Event.ApplicationID != record.Application.ID.String() {
		return domain.ValidationError("event application does not match application id")
	}
	if strings.TrimSpace(record.Event.Kind) == "" {
		return domain.ValidationError("event kind is required")
	}
	if strings.TrimSpace(record.Event.Status) == "" {
		return domain.ValidationError("event status is required")
	}
	return nil
}

func applicationNameDigest(name string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(name)))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func decodeCreateApplicationResult(response []byte) (application.CreateApplicationResult, error) {
	result, err := application.DecodeCreateApplicationResult(response)
	if err != nil {
		return application.CreateApplicationResult{}, err
	}
	if !result.SourceRevisionID.Empty() {
		return application.CreateApplicationResult{}, fmt.Errorf("%w: source-backed result is not supported in sqlite repository", ErrIdempotencyCorrupt)
	}
	return result, nil
}

func formatSequence(sequence uint64) string {
	if sequence == 0 {
		return "0"
	}
	var digits [20]byte
	position := len(digits)
	for sequence > 0 {
		position--
		digits[position] = byte('0' + sequence%10)
		sequence /= 10
	}
	return string(digits[position:])
}

func normalizeQueryLimit(limit int) (int, error) {
	if limit <= 0 {
		return defaultQueryLimit, nil
	}
	if limit > maxQueryLimit {
		return 0, fmt.Errorf("query limit exceeds maximum %d", maxQueryLimit)
	}
	return limit, nil
}
