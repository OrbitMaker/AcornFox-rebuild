// Package postgres contains the PostgreSQL-backed control-plane repository.
//
// The package deliberately depends on database/sql rather than a PostgreSQL
// driver package. The main binary is responsible for registering the driver
// under the name "pgx" before opening a Store.
package postgres

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

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/domain"
)

const (
	postgresDriverName       = "pgx"
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
	// These aliases keep callers from having to import application for common
	// repository errors while preserving errors.Is compatibility with the
	// application layer.
	ErrNotFound            = application.ErrNotFound
	ErrIdempotencyConflict = application.ErrIdempotencyConflict

	ErrIdempotencyInProgress = errors.New("idempotency request is already in progress")
	ErrIdempotencyCorrupt    = errors.New("idempotency record is corrupt")
	ErrOutcomeUnknown        = errors.New("transaction outcome is unknown")
	ErrLeaseLost             = errors.New("task lease is not owned or has expired")
	ErrMaxAttempts           = errors.New("task has reached its maximum attempts")
)

// Store is safe for concurrent use. The *sql.DB supplied to NewStore is
// managed by the caller; OpenStore owns the database handle and closes it
// from Close.
type Store struct {
	db      *sql.DB
	ownedDB bool
	clock   func() time.Time
}

var _ application.Repository = (*Store)(nil)

// NewStore wraps an existing database handle. The caller remains responsible
// for closing db.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db, clock: time.Now}
}

// New is a short alias for NewStore.
func New(db *sql.DB) *Store { return NewStore(db) }

// NewRepository is kept as an explicit constructor for callers that name
// concrete implementations after their repository role.
func NewRepository(db *sql.DB) *Store { return NewStore(db) }

// OpenStore opens a PostgreSQL connection through database/sql. The driver is
// intentionally not imported here; the application registers "pgx" before
// calling this function.
func OpenStore(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open(postgresDriverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres database: %w", err)
	}
	store := &Store{db: db, ownedDB: true, clock: time.Now}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres database: %w", err)
	}
	return store, nil
}

// Open is a short alias for OpenStore.
func Open(ctx context.Context, dsn string) (*Store, error) { return OpenStore(ctx, dsn) }

// DB exposes the wrapped handle for health/readiness wiring. Callers must not
// close it when the Store was created with NewStore.
func (s *Store) DB() *sql.DB {
	if s == nil {
		return nil
	}
	return s.db
}

// Close closes a handle opened by OpenStore. A Store wrapping an external
// handle is a no-op, so ownership remains unambiguous.
func (s *Store) Close() error {
	if s == nil || !s.ownedDB || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// PingContext is useful for readiness checks without exposing driver details.
func (s *Store) PingContext(ctx context.Context) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	return s.db.PingContext(ctx)
}

// SetClock replaces the clock used only for repository-generated timestamps.
// It is intended for deterministic tests and should not be used to bypass
// PostgreSQL's lease predicates, which receive the caller's explicit Now.
func (s *Store) SetClock(clock func() time.Time) {
	if clock == nil {
		s.clock = time.Now
		return
	}
	s.clock = clock
}

func (s *Store) requireDB() error {
	if s == nil || s.db == nil {
		return errors.New("postgres store is not initialized")
	}
	return nil
}

// PreflightCreateApplication is intentionally read-only. The controller calls
// it before a SourceProvider may publish an immutable workspace, so completed
// idempotent replays and known unusable uploads cannot create orphaned source
// material. CreateApplication still rechecks and claims inside its transaction.
func (s *Store) PreflightCreateApplication(ctx context.Context, input application.CreateApplicationPreflight) (application.CreateApplicationResult, bool, error) {
	if err := s.requireDB(); err != nil {
		return application.CreateApplicationResult{}, false, err
	}
	key, digest := strings.TrimSpace(input.IdempotencyKey), strings.TrimSpace(input.RequestDigest)
	if key == "" || digest == "" {
		return application.CreateApplicationResult{}, false, domain.ValidationError("application idempotency preflight is incomplete")
	}
	if input.Source != nil {
		if err := input.Source.Validate(); err != nil {
			return application.CreateApplicationResult{}, false, err
		}
	}
	var storedDigest, status string
	var response []byte
	err := s.db.QueryRowContext(ctx, `SELECT request_digest,status,response FROM idempotency_records WHERE scope=$1 AND idempotency_key=$2`, createApplicationScope, key).Scan(&storedDigest, &status, &response)
	if err == nil {
		if storedDigest != digest {
			return application.CreateApplicationResult{}, false, ErrIdempotencyConflict
		}
		switch status {
		case "completed":
			result, decodeErr := decodeCreateApplicationResult(response)
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
		return application.CreateApplicationResult{}, false, err
	}
	if input.Source != nil && input.Source.Kind == application.CreateApplicationSourceUpload {
		upload, getErr := s.GetSourceUpload(ctx, input.Source.UploadID)
		if getErr != nil {
			return application.CreateApplicationResult{}, false, getErr
		}
		if upload.Status == domain.SourceUploadClaimed {
			return application.CreateApplicationResult{}, false, domain.WrapError(domain.ErrConflict, "source upload is already claimed", domain.ErrSourceUploadClaimed)
		}
		now := input.Now
		if now.IsZero() {
			now = s.now()
		}
		if upload.Status != domain.SourceUploadReady || !now.Before(upload.ExpiresAt) {
			return application.CreateApplicationResult{}, false, domain.NewError(domain.ErrConflict, "source upload is not ready")
		}
	}
	return application.CreateApplicationResult{}, false, nil
}

// CreateApplication writes the application, its default environment, the
// initial operation and task, the first outbox event, and the completed
// idempotency response in one transaction. An existing request with a
// different digest is rejected; an incomplete or malformed record is never
// guessed at or silently replayed.
func (s *Store) CreateApplication(ctx context.Context, record application.CreateApplicationRecord) (application.CreateApplicationResult, error) {
	if err := s.requireDB(); err != nil {
		return application.CreateApplicationResult{}, err
	}
	if err := validateCreateRecord(record); err != nil {
		return application.CreateApplicationResult{}, err
	}

	digest := strings.TrimSpace(record.RequestDigest)
	if digest == "" {
		digest = applicationNameDigest(record.Application.Name)
	}
	createdAt := record.Application.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = s.now().UTC()
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
		VALUES ($1, $2, $3, 'in_progress', $4, $4)
		ON CONFLICT (scope, idempotency_key) DO NOTHING
	`, createApplicationScope, record.IdempotencyKey, digest, createdAt)
	if err != nil {
		return rollback(fmt.Errorf("reserve application idempotency key: %w", err))
	}
	inserted, err := reservation.RowsAffected()
	if err != nil {
		return rollback(fmt.Errorf("inspect application idempotency reservation: %w", err))
	}

	var storedDigest, storedStatus string
	var storedResponse []byte
	if err := tx.QueryRowContext(ctx, `
		SELECT request_digest, status, response
		  FROM idempotency_records
		 WHERE scope = $1 AND idempotency_key = $2
		 FOR UPDATE
	`, createApplicationScope, record.IdempotencyKey).Scan(&storedDigest, &storedStatus, &storedResponse); err != nil {
		return rollback(fmt.Errorf("read application idempotency record: %w", err))
	}
	if storedDigest != digest {
		return rollback(ErrIdempotencyConflict)
	}
	if inserted == 0 {
		switch storedStatus {
		case "completed":
			if len(storedResponse) == 0 {
				return rollback(ErrIdempotencyCorrupt)
			}
			var result application.CreateApplicationResult
			if err := json.Unmarshal(storedResponse, &result); err != nil || result.Application.ID.Empty() || result.EnvironmentID.Empty() || result.OperationID.Empty() || result.Event.ID == "" || result.Event.Sequence == 0 {
				return rollback(fmt.Errorf("%w: invalid stored response", ErrIdempotencyCorrupt))
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

	// From this point onward the idempotency row belongs to this transaction.
	// Every business row and the response update below must commit together.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO applications (id, name, version, created_at, updated_at)
		VALUES ($1, $2, 1, $3, $4)
	`, record.Application.ID.String(), record.Application.Name, record.Application.CreatedAt.UTC(), record.Application.UpdatedAt.UTC()); err != nil {
		return rollback(fmt.Errorf("insert application: %w", err))
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO environments (id, application_id, name, created_at)
		VALUES ($1, $2, $3, $4)
	`, record.EnvironmentID.String(), record.Application.ID.String(), defaultEnvironmentName, record.Application.CreatedAt.UTC()); err != nil {
		return rollback(fmt.Errorf("insert default environment: %w", err))
	}
	if record.Source != nil {
		switch record.Source.Kind {
		case application.CreateApplicationSourceUpload:
			upload, err := readySourceUploadTx(ctx, tx, record.Source.UploadID, createdAt)
			if err != nil {
				return rollback(fmt.Errorf("claim source upload: %w", err))
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable)
				VALUES($1,$2,'upload','upload',$3,$4,$5,$6,'prepared',true)
			`, record.PreparedSource.ID.String(), record.Application.ID.String(), record.PreparedSource.Locator, upload.ID.String(), record.PreparedSource.ContentDigest, record.PreparedSource.WorkspaceRef); err != nil {
				return rollback(fmt.Errorf("insert upload source revision: %w", err))
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO source_workspace_events(source_revision_id,sequence,workspace_ref,state,created_at) VALUES($1,1,$2,'prepared',$3)`, record.PreparedSource.ID.String(), record.PreparedSource.WorkspaceRef, createdAt); err != nil {
				return rollback(fmt.Errorf("record upload source preparation: %w", err))
			}
			if _, err := claimSourceUploadTx(ctx, tx, upload.ID, record.Application.ID, record.PreparedSource.ID, createdAt); err != nil {
				return rollback(fmt.Errorf("finalize source upload claim: %w", err))
			}
		case application.CreateApplicationSourceGit:
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO source_revisions
					(id,application_id,provider,git_commit,content_digest,workspace_manifest,
					 source_kind,locator,source_ref,workspace_ref,workspace_lifecycle,immutable)
				VALUES($1,$2,'git',$3,$4,'{}'::jsonb,'git_https',$5,$6,$7,'prepared',true)
			`, record.PreparedSource.ID.String(), record.Application.ID.String(), record.PreparedSource.Commit, record.PreparedSource.ContentDigest, record.PreparedSource.Locator, record.PreparedSource.Ref, record.PreparedSource.WorkspaceRef); err != nil {
				return rollback(fmt.Errorf("insert public Git source revision: %w", err))
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO source_workspace_events(source_revision_id,sequence,workspace_ref,state,created_at) VALUES($1,1,$2,'prepared',$3)`, record.PreparedSource.ID.String(), record.PreparedSource.WorkspaceRef, createdAt); err != nil {
				return rollback(fmt.Errorf("record public Git source preparation: %w", err))
			}
		default:
			return rollback(domain.ValidationError("application source kind is unsupported"))
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO operations
			(id, application_id, environment_id, operation_type, idempotency_key,
			 state, version, target_ref, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, 'pending', 1, $6, $7, $7)
	`, record.OperationID.String(), record.Application.ID.String(), record.EnvironmentID.String(), createApplicationOpType, record.IdempotencyKey, record.Application.ID.String(), record.Application.CreatedAt.UTC()); err != nil {
		return rollback(fmt.Errorf("insert application operation: %w", err))
	}
	taskPayload, err := json.Marshal(map[string]string{
		"kind":               createApplicationTaskTag,
		"application_id":     record.Application.ID.String(),
		"operation_id":       record.OperationID.String(),
		"source_revision_id": preparedSourceID(record.PreparedSource).String(),
	})
	if err != nil {
		return rollback(fmt.Errorf("encode application task payload: %w", err))
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO task_leases
			(task_id, operation_id, lease_owner, lease_until, attempt, max_attempts,
			 state, payload, created_at, updated_at)
		VALUES ($1, $2, NULL, NULL, 0, $3, 'ready', $4::jsonb, $5, $5)
	`, record.TaskID.String(), record.OperationID.String(), defaultTaskMaxAttempts, taskPayload, record.Application.CreatedAt.UTC()); err != nil {
		return rollback(fmt.Errorf("insert application task: %w", err))
	}

	streamSequence, err := s.nextStreamSequence(ctx, tx)
	if err != nil {
		return rollback(err)
	}
	if streamSequence <= 0 {
		return rollback(fmt.Errorf("%w: invalid outbox stream sequence %d", ErrOutcomeUnknown, streamSequence))
	}
	event := record.Event
	event.Sequence = uint64(streamSequence)
	if event.ID == "" {
		event.ID = "evt-" + formatSequence(uint64(streamSequence))
	}
	eventPayload, err := json.Marshal(event)
	if err != nil {
		return rollback(fmt.Errorf("encode application event: %w", err))
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO outbox_events
			(id, aggregate_type, aggregate_id, aggregate_version, sequence,
			 stream_sequence, event_type, payload, created_at, payload_version)
		VALUES ($1, 'operation', $2, 1, 1, $3, $4, $5::jsonb, $6, $7)
	`, event.ID, record.OperationID.String(), streamSequence, event.Kind, eventPayload, event.OccurredAt.UTC(), event.SchemaVersion); err != nil {
		return rollback(fmt.Errorf("insert application outbox event: %w", err))
	}
	result := application.CreateApplicationResult{Application: record.Application, EnvironmentID: record.EnvironmentID, OperationID: record.OperationID, SourceRevisionID: preparedSourceID(record.PreparedSource), Event: event}
	resultPayload, err := json.Marshal(result)
	if err != nil {
		return rollback(fmt.Errorf("encode application idempotency response: %w", err))
	}
	completion, err := tx.ExecContext(ctx, `
		UPDATE idempotency_records
		   SET status = 'completed', response = $3::jsonb, updated_at = $4
		 WHERE scope = $1 AND idempotency_key = $2 AND status = 'in_progress'
	`, createApplicationScope, record.IdempotencyKey, resultPayload, s.now().UTC())
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

func validateCreateRecord(record application.CreateApplicationRecord) error {
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
	if record.Source != nil {
		if err := record.Source.Validate(); err != nil {
			return err
		}
		if record.Source.Kind == application.CreateApplicationSourceUpload {
			if record.PreparedSource == nil || record.PreparedSource.ID.Empty() || record.PreparedSource.ApplicationID != record.Application.ID || record.PreparedSource.Kind != domain.SourceUpload || record.PreparedSource.Locator != "upload://"+record.Source.UploadID.String() {
				return domain.ValidationError("upload source requires a prepared immutable source revision")
			}
			if err := record.PreparedSource.Validate(); err != nil {
				return err
			}
		}
		if record.Source.Kind == application.CreateApplicationSourceGit {
			if record.PreparedSource == nil || !application.PreparedSourceMatches(*record.Source, *record.PreparedSource) {
				return domain.ValidationError("git source requires a prepared immutable source revision")
			}
			if err := record.PreparedSource.Validate(); err != nil {
				return err
			}
		}
	} else if record.PreparedSource != nil {
		return domain.ValidationError("source revision requires a source input")
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
	if len(response) == 0 {
		return application.CreateApplicationResult{}, ErrIdempotencyCorrupt
	}
	var result application.CreateApplicationResult
	if err := json.Unmarshal(response, &result); err != nil || result.Application.ID.Empty() || result.EnvironmentID.Empty() || result.OperationID.Empty() || result.Event.ID == "" || result.Event.Sequence == 0 {
		return application.CreateApplicationResult{}, fmt.Errorf("%w: invalid stored response", ErrIdempotencyCorrupt)
	}
	return result, nil
}

func preparedSourceID(source *domain.SourceRevision) domain.ID {
	if source == nil {
		return ""
	}
	return source.ID
}

func (s *Store) now() time.Time {
	if s != nil && s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

func (s *Store) nextStreamSequence(ctx context.Context, tx *sql.Tx) (int64, error) {
	var sequence int64
	if err := tx.QueryRowContext(ctx, `SELECT nextval('outbox_events_stream_sequence'::regclass)`).Scan(&sequence); err != nil {
		return 0, fmt.Errorf("allocate outbox stream sequence: %w", err)
	}
	return sequence, nil
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
