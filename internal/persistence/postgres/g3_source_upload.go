package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

// CreateSourceUpload persists immutable upload metadata only after the file
// provider has atomically published its private directory. The caller removes
// that directory when this method reports an idempotent replay or failure.
func (s *Store) CreateSourceUpload(ctx context.Context, upload domain.SourceUploadRecord) (domain.SourceUploadRecord, bool, error) {
	if err := s.requireDB(); err != nil {
		return domain.SourceUploadRecord{}, false, err
	}
	if err := upload.Validate(); err != nil {
		return domain.SourceUploadRecord{}, false, err
	}
	if upload.Status != domain.SourceUploadReady {
		return domain.SourceUploadRecord{}, false, domain.ValidationError("new source upload must be ready")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.SourceUploadRecord{}, false, err
	}
	rollback := func(cause error) (domain.SourceUploadRecord, bool, error) {
		return domain.SourceUploadRecord{}, false, rollbackTx(tx, cause)
	}
	inserted, err := tx.ExecContext(ctx, `INSERT INTO source_uploads(id,upload_kind,status,content_digest,total_bytes,file_count,storage_ref,idempotency_key,request_digest,expires_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(idempotency_key) DO NOTHING`, upload.ID.String(), upload.Kind, upload.Status, upload.Digest, upload.Bytes, upload.FileCount, upload.StorageRef, upload.IdempotencyKey, upload.RequestDigest, upload.ExpiresAt.UTC(), upload.CreatedAt.UTC(), upload.UpdatedAt.UTC())
	if err != nil {
		return rollback(err)
	}
	rows, err := inserted.RowsAffected()
	if err != nil {
		return rollback(err)
	}
	if rows == 0 {
		existing, err := sourceUploadByKeyTx(ctx, tx, upload.IdempotencyKey)
		if err != nil {
			return rollback(err)
		}
		if existing.RequestDigest != upload.RequestDigest || existing.Digest != upload.Digest {
			return rollback(ErrIdempotencyConflict)
		}
		if err := tx.Commit(); err != nil {
			return domain.SourceUploadRecord{}, false, err
		}
		return existing, true, nil
	}
	for _, file := range upload.Files {
		if _, err := tx.ExecContext(ctx, `INSERT INTO source_upload_files(upload_id,relative_path,byte_count,content_digest) VALUES($1,$2,$3,$4)`, upload.ID.String(), file.Path, file.Bytes, file.Digest); err != nil {
			return rollback(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return domain.SourceUploadRecord{}, false, err
	}
	return upload, false, nil
}

func (s *Store) GetSourceUpload(ctx context.Context, id domain.ID) (domain.SourceUploadRecord, error) {
	if err := s.requireDB(); err != nil {
		return domain.SourceUploadRecord{}, err
	}
	if err := domain.RequireID(id, "source upload id"); err != nil {
		return domain.SourceUploadRecord{}, err
	}
	upload, err := sourceUploadByID(ctx, s.db, id)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.SourceUploadRecord{}, ErrNotFound
	}
	if err != nil {
		return domain.SourceUploadRecord{}, err
	}
	return upload, nil
}

// ListSourceUploadCleanupCandidates is side-effect free. A later scheduler may
// mark and remove only these ready-expired, expired, or failed records.
func (s *Store) ListSourceUploadCleanupCandidates(ctx context.Context, now time.Time, limit int) ([]domain.SourceUploadRecord, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	limit, err := normalizeLimit(limit)
	if err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = s.now()
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,upload_kind,status,content_digest,total_bytes,file_count,storage_ref,idempotency_key,request_digest,expires_at,claimed_application_id,claimed_source_revision_id,created_at,updated_at FROM source_uploads WHERE (status='ready' AND expires_at <= $1) OR status IN ('expired','failed') ORDER BY expires_at,id LIMIT $2`, now.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]domain.SourceUploadRecord, 0)
	for rows.Next() {
		item, err := scanSourceUpload(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) MarkSourceUploadExpired(ctx context.Context, id domain.ID, now time.Time) (bool, error) {
	if err := s.requireDB(); err != nil {
		return false, err
	}
	if err := domain.RequireID(id, "source upload id"); err != nil {
		return false, err
	}
	if now.IsZero() {
		now = s.now()
	}
	result, err := s.db.ExecContext(ctx, `UPDATE source_uploads SET status='expired',updated_at=$2 WHERE id=$1 AND status='ready' AND expires_at <= $2`, id.String(), now.UTC())
	if err != nil {
		return false, err
	}
	rows, _ := result.RowsAffected()
	return rows == 1, nil
}

// DeleteExpiredSourceUpload removes only a terminal unclaimed record. It does
// not delete filesystem data; callers must use the provider's explicit safe
// discard operation after this durable deletion succeeds.
func (s *Store) DeleteExpiredSourceUpload(ctx context.Context, id domain.ID) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM source_uploads WHERE id=$1 AND status IN ('expired','failed') AND claimed_application_id IS NULL`, id.String())
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return ErrNotFound
	}
	return nil
}

func claimSourceUploadTx(ctx context.Context, tx *sql.Tx, uploadID, applicationID, sourceRevisionID domain.ID, now time.Time) (domain.SourceUploadRecord, error) {
	upload, err := readySourceUploadTx(ctx, tx, uploadID, now)
	if err != nil {
		return domain.SourceUploadRecord{}, err
	}
	upload.Status, upload.ClaimedApplicationID, upload.ClaimedSourceID, upload.UpdatedAt = domain.SourceUploadClaimed, applicationID, sourceRevisionID, now.UTC()
	result, err := tx.ExecContext(ctx, `UPDATE source_uploads SET status='claimed',claimed_application_id=$2,claimed_source_revision_id=$3,updated_at=$4 WHERE id=$1 AND status='ready'`, upload.ID.String(), applicationID.String(), sourceRevisionID.String(), now.UTC())
	if err != nil {
		return domain.SourceUploadRecord{}, err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return domain.SourceUploadRecord{}, domain.WrapError(domain.ErrConflict, "source upload is already claimed", domain.ErrSourceUploadClaimed)
	}
	return upload, nil
}

func readySourceUploadTx(ctx context.Context, tx *sql.Tx, uploadID domain.ID, now time.Time) (domain.SourceUploadRecord, error) {
	upload, err := sourceUploadByIDTx(ctx, tx, uploadID, true)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.SourceUploadRecord{}, ErrNotFound
	}
	if err != nil {
		return domain.SourceUploadRecord{}, err
	}
	if upload.Status == domain.SourceUploadClaimed {
		return domain.SourceUploadRecord{}, domain.WrapError(domain.ErrConflict, "source upload is already claimed", domain.ErrSourceUploadClaimed)
	}
	if upload.Status != domain.SourceUploadReady {
		return domain.SourceUploadRecord{}, domain.NewError(domain.ErrConflict, "source upload is not ready")
	}
	if !now.Before(upload.ExpiresAt) {
		if _, err := tx.ExecContext(ctx, `UPDATE source_uploads SET status='expired',updated_at=$2 WHERE id=$1 AND status='ready'`, upload.ID.String(), now.UTC()); err != nil {
			return domain.SourceUploadRecord{}, err
		}
		return domain.SourceUploadRecord{}, domain.NewError(domain.ErrConflict, "source upload has expired")
	}
	return upload, nil
}

type sourceUploadScanner interface{ Scan(...any) error }

func sourceUploadByKeyTx(ctx context.Context, tx *sql.Tx, key string) (domain.SourceUploadRecord, error) {
	return scanSourceUploadRow(tx.QueryRowContext(ctx, `SELECT id,upload_kind,status,content_digest,total_bytes,file_count,storage_ref,idempotency_key,request_digest,expires_at,claimed_application_id,claimed_source_revision_id,created_at,updated_at FROM source_uploads WHERE idempotency_key=$1 FOR UPDATE`, strings.TrimSpace(key)))
}

func sourceUploadByID(ctx context.Context, db *sql.DB, id domain.ID) (domain.SourceUploadRecord, error) {
	return scanSourceUploadRow(db.QueryRowContext(ctx, `SELECT id,upload_kind,status,content_digest,total_bytes,file_count,storage_ref,idempotency_key,request_digest,expires_at,claimed_application_id,claimed_source_revision_id,created_at,updated_at FROM source_uploads WHERE id=$1`, id.String()))
}

func sourceUploadByIDTx(ctx context.Context, tx *sql.Tx, id domain.ID, lock bool) (domain.SourceUploadRecord, error) {
	query := `SELECT id,upload_kind,status,content_digest,total_bytes,file_count,storage_ref,idempotency_key,request_digest,expires_at,claimed_application_id,claimed_source_revision_id,created_at,updated_at FROM source_uploads WHERE id=$1`
	if lock {
		query += " FOR UPDATE"
	}
	return scanSourceUploadRow(tx.QueryRowContext(ctx, query, id.String()))
}

func scanSourceUploadRow(scanner sourceUploadScanner) (domain.SourceUploadRecord, error) {
	var upload domain.SourceUploadRecord
	var applicationID, sourceID sql.NullString
	if err := scanner.Scan(&upload.ID, &upload.Kind, &upload.Status, &upload.Digest, &upload.Bytes, &upload.FileCount, &upload.StorageRef, &upload.IdempotencyKey, &upload.RequestDigest, &upload.ExpiresAt, &applicationID, &sourceID, &upload.CreatedAt, &upload.UpdatedAt); err != nil {
		return domain.SourceUploadRecord{}, err
	}
	if applicationID.Valid {
		upload.ClaimedApplicationID = domain.ID(applicationID.String)
	}
	if sourceID.Valid {
		upload.ClaimedSourceID = domain.ID(sourceID.String)
	}
	upload.ExpiresAt, upload.CreatedAt, upload.UpdatedAt = upload.ExpiresAt.UTC(), upload.CreatedAt.UTC(), upload.UpdatedAt.UTC()
	return upload, nil
}

func scanSourceUpload(scanner sourceUploadScanner) (domain.SourceUploadRecord, error) {
	return scanSourceUploadRow(scanner)
}
