package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

type acornFoxSourceUpdateLease struct {
	conn          *sql.Conn
	applicationID domain.ID
}

func (*acornFoxSourceUpdateLease) AcornFoxSourceUpdateLease() {}

func (s *Store) AcquireAcornFoxSourceUpdate(ctx context.Context, request application.AcornFoxSourceUpdateRequest, digest string, now time.Time) (application.AcornFoxSourceUpdateReservation, application.AcornFoxSourceUpdateLease, error) {
	if err := s.requireDB(); err != nil {
		return application.AcornFoxSourceUpdateReservation{}, nil, err
	}
	if err := validateAcornFoxSourceUpdateRequest(request, digest); err != nil {
		return application.AcornFoxSourceUpdateReservation{}, nil, err
	}
	if !request.UploadID.Empty() {
		if _, err := s.GetAcornFoxSourceRevision(ctx, request.ApplicationID, request.BaseSourceRevisionID); err != nil {
			return application.AcornFoxSourceUpdateReservation{}, nil, err
		}
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return application.AcornFoxSourceUpdateReservation{}, nil, err
	}
	lease := &acornFoxSourceUpdateLease{conn: conn, applicationID: request.ApplicationID}
	var held bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, "open-card:acornfox-source-update:"+request.ApplicationID.String()).Scan(&held); err != nil || !held {
		conn.Close()
		return application.AcornFoxSourceUpdateReservation{}, nil, application.ErrAcornFoxSourceUpdateInProgress
	}
	reservation, err := s.beginAcornFoxSourceUpdate(ctx, conn, request, digest, now)
	if err != nil || reservation.Replay != nil {
		s.ReleaseAcornFoxSourceUpdate(context.Background(), lease)
		return reservation, nil, err
	}
	return reservation, lease, nil
}

func (s *Store) beginAcornFoxSourceUpdate(ctx context.Context, conn *sql.Conn, request application.AcornFoxSourceUpdateRequest, digest string, now time.Time) (application.AcornFoxSourceUpdateReservation, error) {
	if err := s.requireDB(); err != nil {
		return application.AcornFoxSourceUpdateReservation{}, err
	}
	if err := validateAcornFoxSourceUpdateRequest(request, digest); err != nil {
		return application.AcornFoxSourceUpdateReservation{}, err
	}
	if now.IsZero() {
		now = s.now()
	}
	now = now.UTC()
	if !request.UploadID.Empty() {
		return s.beginAcornFoxUploadSourceUpdate(ctx, conn, request, digest, now)
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return application.AcornFoxSourceUpdateReservation{}, err
	}
	rollback := func(cause error) (application.AcornFoxSourceUpdateReservation, error) {
		return application.AcornFoxSourceUpdateReservation{}, rollbackTx(tx, cause)
	}
	var appManagementState string
	if err := tx.QueryRowContext(ctx, `SELECT management_state FROM applications WHERE id = $1 FOR UPDATE`, request.ApplicationID.String()).Scan(&appManagementState); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return rollback(ErrNotFound)
		}
		return rollback(err)
	}
	if appManagementState != "active" {
		return rollback(domain.NewError(domain.ErrConflict, "application is archiving or archived"))
	}
	var activeMgmtID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM acornfox_management_commands WHERE application_id = $1 AND phase NOT IN ('completed', 'failed') FOR UPDATE`, request.ApplicationID.String()).Scan(&activeMgmtID); err == nil {
		return rollback(domain.NewError(domain.ErrConflict, "application management operation in progress"))
	} else if !errors.Is(err, sql.ErrNoRows) {
		return rollback(err)
	}
	var repositoryURL string
	err = tx.QueryRowContext(ctx, `SELECT metadata.repository_url FROM source_revisions source JOIN acornfox_source_metadata metadata ON metadata.source_revision_id=source.id WHERE source.id=$1 AND source.application_id=$2 AND source.source_kind='git_https'`, request.BaseSourceRevisionID.String(), request.ApplicationID.String()).Scan(&repositoryURL)
	if errors.Is(err, sql.ErrNoRows) {
		return rollback(ErrNotFound)
	}
	if err != nil {
		return rollback(fmt.Errorf("load public update base: %w", err))
	}
	if canonical, err := contracts.CanonicalAcornFoxPublicRepositoryURL(repositoryURL); err != nil || canonical != repositoryURL {
		return rollback(domain.ValidationError("persisted public source provenance is invalid"))
	}
	inserted, err := tx.ExecContext(ctx, `INSERT INTO acornfox_source_updates(application_id,idempotency_key,request_digest,base_source_revision_id,requested_ref,state,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'preparing',$6,$6) ON CONFLICT(application_id,idempotency_key) DO NOTHING`, request.ApplicationID.String(), request.IdempotencyKey, digest, request.BaseSourceRevisionID.String(), request.Ref, now)
	if err != nil {
		return rollback(fmt.Errorf("reserve source update: %w", err))
	}
	rows, err := inserted.RowsAffected()
	if err != nil {
		return rollback(err)
	}
	if rows == 1 {
		if err := tx.Commit(); err != nil {
			return application.AcornFoxSourceUpdateReservation{}, fmt.Errorf("%w: commit source update reservation: %v", application.ErrAcornFoxSourceUpdateUnknown, err)
		}
		return application.AcornFoxSourceUpdateReservation{RepositoryURL: repositoryURL}, nil
	}
	var storedDigest, state string
	var sourceID sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT request_digest,state,source_revision_id FROM acornfox_source_updates WHERE application_id=$1 AND idempotency_key=$2 FOR UPDATE`, request.ApplicationID.String(), request.IdempotencyKey).Scan(&storedDigest, &state, &sourceID)
	if err != nil {
		return rollback(fmt.Errorf("load source update replay: %w", err))
	}
	if storedDigest != digest {
		return rollback(ErrIdempotencyConflict)
	}
	if state == "imported" && sourceID.Valid {
		result := contracts.AcornFoxSourceUpdateResult{SourceRevisionID: domain.ID(sourceID.String), Status: contracts.AcornFoxSourceUpdateImported}
		if result.Validate() != nil {
			return rollback(domain.ValidationError("stored source update result is invalid"))
		}
		if err := tx.Commit(); err != nil {
			return application.AcornFoxSourceUpdateReservation{}, fmt.Errorf("%w: commit source update replay: %v", application.ErrAcornFoxSourceUpdateUnknown, err)
		}
		return application.AcornFoxSourceUpdateReservation{Replay: &result}, nil
	}
	if state == "preparing" {
		return rollback(application.ErrAcornFoxSourceUpdateInProgress)
	}
	if state == "unknown" {
		return rollback(application.ErrAcornFoxSourceUpdateUnknown)
	}
	return rollback(application.ErrAcornFoxSourceUpdateFailed)
}

func (s *Store) CompleteAcornFoxSourceUpdate(ctx context.Context, raw application.AcornFoxSourceUpdateLease, request application.AcornFoxSourceUpdateRequest, digest string, revision domain.SourceRevision, now time.Time) (contracts.AcornFoxSourceUpdateResult, error) {
	lease, ok := raw.(*acornFoxSourceUpdateLease)
	if !ok || lease.conn == nil || lease.applicationID != request.ApplicationID {
		return contracts.AcornFoxSourceUpdateResult{}, application.ErrAcornFoxSourceUpdateUnknown
	}
	if err := s.requireDB(); err != nil {
		return contracts.AcornFoxSourceUpdateResult{}, err
	}
	if err := validateAcornFoxSourceUpdateRequest(request, digest); err != nil {
		return contracts.AcornFoxSourceUpdateResult{}, err
	}
	if !request.UploadID.Empty() {
		if now.IsZero() {
			now = s.now()
		}
		return s.completeAcornFoxUploadSourceUpdate(ctx, lease, request, digest, revision, now.UTC())
	}
	if err := revision.Validate(); err != nil {
		return contracts.AcornFoxSourceUpdateResult{}, err
	}
	if revision.ApplicationID != request.ApplicationID || revision.Kind != domain.SourceGitHTTPS || revision.Ref != request.Ref {
		return contracts.AcornFoxSourceUpdateResult{}, domain.ValidationError("prepared update source is invalid")
	}
	if now.IsZero() {
		now = s.now()
	}
	now = now.UTC()
	tx, err := lease.conn.BeginTx(ctx, nil)
	if err != nil {
		return contracts.AcornFoxSourceUpdateResult{}, application.ErrAcornFoxSourceUpdateUnknown
	}
	rollback := func(cause error) (contracts.AcornFoxSourceUpdateResult, error) {
		return contracts.AcornFoxSourceUpdateResult{}, rollbackTx(tx, cause)
	}
	var state, repositoryURL string
	var storedDigest string
	if err := tx.QueryRowContext(ctx, `SELECT update.request_digest,update.state,metadata.repository_url FROM acornfox_source_updates update JOIN acornfox_source_metadata metadata ON metadata.source_revision_id=update.base_source_revision_id WHERE update.application_id=$1 AND update.idempotency_key=$2 FOR UPDATE`, request.ApplicationID.String(), request.IdempotencyKey).Scan(&storedDigest, &state, &repositoryURL); err != nil {
		return rollback(fmt.Errorf("load source update completion: %w", err))
	}
	if storedDigest != digest {
		return rollback(ErrIdempotencyConflict)
	}
	if state == "imported" {
		var id string
		if err := tx.QueryRowContext(ctx, `SELECT source_revision_id FROM acornfox_source_updates WHERE application_id=$1 AND idempotency_key=$2`, request.ApplicationID.String(), request.IdempotencyKey).Scan(&id); err != nil {
			return rollback(err)
		}
		result := contracts.AcornFoxSourceUpdateResult{SourceRevisionID: domain.ID(id), Status: contracts.AcornFoxSourceUpdateImported}
		if err := tx.Commit(); err != nil {
			return contracts.AcornFoxSourceUpdateResult{}, fmt.Errorf("%w: commit source update replay: %v", application.ErrAcornFoxSourceUpdateUnknown, err)
		}
		return result, nil
	}
	if state != "preparing" {
		return rollback(application.ErrAcornFoxSourceUpdateUnknown)
	}
	if revision.Locator != repositoryURL {
		return rollback(domain.ValidationError("prepared source does not match public provenance"))
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO source_revisions(id,application_id,provider,git_commit,content_digest,workspace_manifest,source_kind,locator,source_ref,workspace_ref,workspace_lifecycle,immutable,created_at) VALUES($1,$2,'git',$3,$4,'{}'::jsonb,'git_https',$5,$6,$7,'prepared',true,$8)`, revision.ID.String(), revision.ApplicationID.String(), revision.Commit, revision.ContentDigest, revision.Locator, revision.Ref, revision.WorkspaceRef, revision.CreatedAt.UTC()); err != nil {
		return rollback(fmt.Errorf("insert updated source revision: %w", err))
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO source_workspace_events(source_revision_id,sequence,workspace_ref,state,created_at) VALUES($1,1,$2,'prepared',$3)`, revision.ID.String(), revision.WorkspaceRef, revision.CreatedAt.UTC()); err != nil {
		return rollback(fmt.Errorf("record updated source workspace: %w", err))
	}
	if err := s.RecordAcornFoxPublicSourceProvenanceTx(ctx, tx, contracts.AcornFoxPublicSourceProvenance{SourceRevisionID: revision.ID, RepositoryURL: repositoryURL}); err != nil {
		return rollback(err)
	}
	if err := execExactlyOneTx(ctx, tx, `UPDATE acornfox_source_updates SET state='imported',source_revision_id=$1,updated_at=$2 WHERE application_id=$3 AND idempotency_key=$4 AND state='preparing'`, revision.ID.String(), now, request.ApplicationID.String(), request.IdempotencyKey); err != nil {
		return rollback(err)
	}
	result := contracts.AcornFoxSourceUpdateResult{SourceRevisionID: revision.ID, Status: contracts.AcornFoxSourceUpdateImported}
	if err := tx.Commit(); err != nil {
		return contracts.AcornFoxSourceUpdateResult{}, fmt.Errorf("%w: commit source update: %v", application.ErrAcornFoxSourceUpdateUnknown, err)
	}
	return result, nil
}

func (s *Store) FailAcornFoxSourceUpdate(ctx context.Context, raw application.AcornFoxSourceUpdateLease, request application.AcornFoxSourceUpdateRequest, digest string, now time.Time) error {
	lease, ok := raw.(*acornFoxSourceUpdateLease)
	if !ok || lease.conn == nil || lease.applicationID != request.ApplicationID {
		return application.ErrAcornFoxSourceUpdateUnknown
	}
	if err := s.requireDB(); err != nil {
		return err
	}
	if err := validateAcornFoxSourceUpdateRequest(request, digest); err != nil {
		return err
	}
	if now.IsZero() {
		now = s.now()
	}
	result, err := lease.conn.ExecContext(ctx, `UPDATE acornfox_source_updates SET state='failed',updated_at=$1 WHERE application_id=$2 AND idempotency_key=$3 AND request_digest=$4 AND state='preparing'`, now.UTC(), request.ApplicationID.String(), request.IdempotencyKey, digest)
	if err != nil {
		return application.ErrAcornFoxSourceUpdateUnknown
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return application.ErrAcornFoxSourceUpdateUnknown
	}
	return nil
}

func (s *Store) ReleaseAcornFoxSourceUpdate(ctx context.Context, raw application.AcornFoxSourceUpdateLease) {
	lease, ok := raw.(*acornFoxSourceUpdateLease)
	if !ok || lease.conn == nil {
		return
	}
	conn := lease.conn
	lease.conn = nil
	releaseCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var unlocked bool
	err := conn.QueryRowContext(releaseCtx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, "open-card:acornfox-source-update:"+lease.applicationID.String()).Scan(&unlocked)
	if err != nil || !unlocked {
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	}
	_ = conn.Close()
}

// RecoverAcornFoxSourceUpdates is a startup-only single-process recovery step.
// It never uses elapsed time to steal a live clone. A preparing command is
// recovered only after its per-app session lock can be acquired.
func (s *Store) RecoverAcornFoxSourceUpdates(ctx context.Context, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	if now.IsZero() {
		now = s.now()
	}
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT application_id FROM acornfox_source_updates WHERE state='preparing' LIMIT 1025`)
	if err != nil {
		return err
	}
	apps := make([]domain.ID, 0, 16)
	for rows.Next() {
		var app domain.ID
		if err := rows.Scan(&app); err != nil {
			rows.Close()
			return err
		}
		apps = append(apps, app)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(apps) > 1024 {
		return domain.NewError(domain.ErrUnavailable, "source update recovery is bounded")
	}
	for _, app := range apps {
		conn, e := s.db.Conn(ctx)
		if e != nil {
			return e
		}
		var held bool
		e = conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, `open-card:acornfox-source-update:`+app.String()).Scan(&held)
		if e == nil && held {
			_, e = conn.ExecContext(ctx, `UPDATE acornfox_source_updates SET state='unknown',updated_at=$1 WHERE application_id=$2 AND state='preparing'`, now.UTC(), app.String())
			_, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, `open-card:acornfox-source-update:`+app.String())
		}
		conn.Close()
		if e != nil {
			return e
		}
	}
	return rows.Err()
}

func validateAcornFoxSourceUpdateRequest(request application.AcornFoxSourceUpdateRequest, digest string) error {
	if domain.RequireID(request.ApplicationID, "application id") != nil || domain.RequireID(request.BaseSourceRevisionID, "base source revision id") != nil || strings.TrimSpace(request.IdempotencyKey) == "" {
		return domain.ValidationError("source update request is invalid")
	}
	if request.UploadID.Empty() {
		ref, err := contracts.NormalizeAcornFoxSourceUpdateRef(request.Ref)
		if err != nil || ref != request.Ref {
			return domain.ValidationError("source update request is invalid")
		}
	} else if err := validateAcornFoxUploadUpdateInput(request); err != nil {
		return err
	}
	if len(digest) != 71 || !strings.HasPrefix(digest, "sha256:") {
		return domain.ValidationError("source update digest is invalid")
	}
	return nil
}
