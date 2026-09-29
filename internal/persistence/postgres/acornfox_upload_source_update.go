package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

// beginAcornFoxUploadSourceUpdate runs under the existing app writer lease.
// The base source was proof-read before acquiring a dedicated connection.
func (s *Store) beginAcornFoxUploadSourceUpdate(ctx context.Context, conn *sql.Conn, request application.AcornFoxSourceUpdateRequest, digest string, now time.Time) (application.AcornFoxSourceUpdateReservation, error) {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return application.AcornFoxSourceUpdateReservation{}, err
	}
	defer tx.Rollback()
	var appManagementState string
	if err := tx.QueryRowContext(ctx, `SELECT management_state FROM applications WHERE id = $1 FOR UPDATE`, request.ApplicationID.String()).Scan(&appManagementState); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return application.AcornFoxSourceUpdateReservation{}, ErrNotFound
		}
		return application.AcornFoxSourceUpdateReservation{}, err
	}
	if appManagementState != "active" {
		return application.AcornFoxSourceUpdateReservation{}, domain.NewError(domain.ErrConflict, "application is archiving or archived")
	}
	var activeMgmtID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM acornfox_management_commands WHERE application_id = $1 AND phase NOT IN ('completed', 'failed') FOR UPDATE`, request.ApplicationID.String()).Scan(&activeMgmtID); err == nil {
		return application.AcornFoxSourceUpdateReservation{}, domain.NewError(domain.ErrConflict, "application management operation in progress")
	} else if !errors.Is(err, sql.ErrNoRows) {
		return application.AcornFoxSourceUpdateReservation{}, err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO acornfox_source_updates(application_id,idempotency_key,request_digest,base_source_revision_id,requested_ref,state,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'preparing',$6,$6) ON CONFLICT(application_id,idempotency_key) DO NOTHING`, request.ApplicationID.String(), request.IdempotencyKey, digest, request.BaseSourceRevisionID.String(), "upload:"+request.UploadID.String(), now)
	if err != nil {
		return application.AcornFoxSourceUpdateReservation{}, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return application.AcornFoxSourceUpdateReservation{}, err
	}
	if inserted == 1 {
		if _, err := readySourceUploadTx(ctx, tx, request.UploadID, now); err != nil {
			return application.AcornFoxSourceUpdateReservation{}, err
		}
		if err := tx.Commit(); err != nil {
			return application.AcornFoxSourceUpdateReservation{}, application.ErrAcornFoxSourceUpdateUnknown
		}
		return application.AcornFoxSourceUpdateReservation{}, nil
	}
	var storedDigest, state, requested string
	var sourceID sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT request_digest,state,requested_ref,source_revision_id FROM acornfox_source_updates WHERE application_id=$1 AND idempotency_key=$2 FOR UPDATE`, request.ApplicationID.String(), request.IdempotencyKey).Scan(&storedDigest, &state, &requested, &sourceID); err != nil {
		return application.AcornFoxSourceUpdateReservation{}, err
	}
	if storedDigest != digest || requested != "upload:"+request.UploadID.String() {
		return application.AcornFoxSourceUpdateReservation{}, ErrIdempotencyConflict
	}
	if state == "imported" && sourceID.Valid {
		replay := contracts.AcornFoxSourceUpdateResult{SourceRevisionID: domain.ID(sourceID.String), Status: contracts.AcornFoxSourceUpdateImported}
		if replay.Validate() != nil {
			return application.AcornFoxSourceUpdateReservation{}, domain.ValidationError("source update replay is invalid")
		}
		if err := tx.Commit(); err != nil {
			return application.AcornFoxSourceUpdateReservation{}, application.ErrAcornFoxSourceUpdateUnknown
		}
		return application.AcornFoxSourceUpdateReservation{Replay: &replay}, nil
	}
	if state == "preparing" {
		return application.AcornFoxSourceUpdateReservation{}, application.ErrAcornFoxSourceUpdateInProgress
	}
	if state == "unknown" {
		return application.AcornFoxSourceUpdateReservation{}, application.ErrAcornFoxSourceUpdateUnknown
	}
	return application.AcornFoxSourceUpdateReservation{}, application.ErrAcornFoxSourceUpdateFailed
}

func (s *Store) completeAcornFoxUploadSourceUpdate(ctx context.Context, lease *acornFoxSourceUpdateLease, request application.AcornFoxSourceUpdateRequest, digest string, revision domain.SourceRevision, now time.Time) (contracts.AcornFoxSourceUpdateResult, error) {
	if revision.Validate() != nil || revision.ApplicationID != request.ApplicationID || revision.Kind != domain.SourceUpload || revision.Locator != "upload://"+request.UploadID.String() || revision.Commit != "" || !revision.Immutable || (revision.Ref != "" && revision.Ref != request.UploadID.String()) {
		return contracts.AcornFoxSourceUpdateResult{}, domain.ValidationError("prepared upload revision is invalid")
	}
	tx, err := lease.conn.BeginTx(ctx, nil)
	if err != nil {
		return contracts.AcornFoxSourceUpdateResult{}, application.ErrAcornFoxSourceUpdateUnknown
	}
	defer tx.Rollback()
	var state, storedDigest, requested string
	var existing sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT state,request_digest,requested_ref,source_revision_id FROM acornfox_source_updates WHERE application_id=$1 AND idempotency_key=$2 FOR UPDATE`, request.ApplicationID.String(), request.IdempotencyKey).Scan(&state, &storedDigest, &requested, &existing); err != nil {
		return contracts.AcornFoxSourceUpdateResult{}, err
	}
	if storedDigest != digest || requested != "upload:"+request.UploadID.String() {
		return contracts.AcornFoxSourceUpdateResult{}, ErrIdempotencyConflict
	}
	if state == "imported" && existing.Valid {
		return contracts.AcornFoxSourceUpdateResult{SourceRevisionID: domain.ID(existing.String), Status: contracts.AcornFoxSourceUpdateImported}, nil
	}
	if state != "preparing" {
		return contracts.AcornFoxSourceUpdateResult{}, application.ErrAcornFoxSourceUpdateUnknown
	}
	if _, err := readySourceUploadTx(ctx, tx, request.UploadID, now); err != nil {
		return contracts.AcornFoxSourceUpdateResult{}, err
	}
	// Identical uploaded content reuses the already-proven immutable source.
	// The redundant upload remains unclaimed for the normal bounded expiry cleanup.
	var sameSource string
	sameErr := tx.QueryRowContext(ctx, `SELECT source.id FROM source_revisions source
 JOIN source_uploads upload ON upload.id=source.source_ref
 JOIN source_workspace_events workspace ON workspace.source_revision_id=source.id AND workspace.sequence=1
 WHERE source.application_id=$1 AND source.source_kind='upload' AND source.provider='upload'
 AND source.content_digest=$2 AND source.workspace_ref=$3 AND source.immutable=true AND source.workspace_lifecycle='prepared'
 AND source.locator='upload://' || upload.id AND COALESCE(source.git_commit,'')=''
 AND upload.status='claimed' AND upload.claimed_application_id=source.application_id AND upload.claimed_source_revision_id=source.id
 AND upload.storage_ref=source.locator AND workspace.state='prepared' AND workspace.workspace_ref=source.workspace_ref`, request.ApplicationID.String(), revision.ContentDigest, revision.WorkspaceRef).Scan(&sameSource)
	if sameErr == nil {
		if err := execExactlyOneTx(ctx, tx, `UPDATE acornfox_source_updates SET state='imported',source_revision_id=$1,updated_at=$2 WHERE application_id=$3 AND idempotency_key=$4 AND state='preparing'`, sameSource, now, request.ApplicationID.String(), request.IdempotencyKey); err != nil {
			return contracts.AcornFoxSourceUpdateResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return contracts.AcornFoxSourceUpdateResult{}, application.ErrAcornFoxSourceUpdateUnknown
		}
		return contracts.AcornFoxSourceUpdateResult{SourceRevisionID: domain.ID(sameSource), Status: contracts.AcornFoxSourceUpdateImported}, nil
	}
	if sameErr != sql.ErrNoRows {
		return contracts.AcornFoxSourceUpdateResult{}, sameErr
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable,created_at) VALUES($1,$2,'upload','upload',$3,$4,$5,$6,'prepared',true,$7)`, revision.ID.String(), request.ApplicationID.String(), revision.Locator, request.UploadID.String(), revision.ContentDigest, revision.WorkspaceRef, revision.CreatedAt.UTC()); err != nil {
		return contracts.AcornFoxSourceUpdateResult{}, fmt.Errorf("record uploaded revision: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO source_workspace_events(source_revision_id,sequence,workspace_ref,state,created_at) VALUES($1,1,$2,'prepared',$3)`, revision.ID.String(), revision.WorkspaceRef, now); err != nil {
		return contracts.AcornFoxSourceUpdateResult{}, err
	}
	if _, err := claimSourceUploadTx(ctx, tx, request.UploadID, request.ApplicationID, revision.ID, now); err != nil {
		return contracts.AcornFoxSourceUpdateResult{}, err
	}
	if err := execExactlyOneTx(ctx, tx, `UPDATE acornfox_source_updates SET state='imported',source_revision_id=$1,updated_at=$2 WHERE application_id=$3 AND idempotency_key=$4 AND state='preparing'`, revision.ID.String(), now, request.ApplicationID.String(), request.IdempotencyKey); err != nil {
		return contracts.AcornFoxSourceUpdateResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return contracts.AcornFoxSourceUpdateResult{}, application.ErrAcornFoxSourceUpdateUnknown
	}
	return contracts.AcornFoxSourceUpdateResult{SourceRevisionID: revision.ID, Status: contracts.AcornFoxSourceUpdateImported}, nil
}

func validateAcornFoxUploadUpdateInput(request application.AcornFoxSourceUpdateRequest) error {
	if request.UploadID.Empty() || request.Ref != "" || domain.ValidateSourceUploadStorageRef("upload://"+request.UploadID.String(), request.UploadID) != nil {
		return domain.ValidationError("upload source update is invalid")
	}
	return nil
}
