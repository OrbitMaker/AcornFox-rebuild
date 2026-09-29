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
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func mgmtHashID(prefix string, parts ...string) domain.ID {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return domain.ID(prefix + "_" + hex.EncodeToString(h[:16]))
}

// verifyManagementLeaseTx checks in-transaction that the caller holds an unexpired,
// matching lease token and phase version.
func verifyManagementLeaseTx(ctx context.Context, tx *sql.Tx, lease application.AcornFoxManagementCommandLease, expectedPhase string) error {
	if lease.CommandID.Empty() || strings.TrimSpace(lease.Token) == "" || strings.TrimSpace(lease.Owner) == "" {
		return application.ErrManagementLeaseLost
	}
	var currentPhaseVersion int64
	err := tx.QueryRowContext(ctx, `
		SELECT phase_version
		  FROM acornfox_management_commands
		 WHERE id = $1
		   AND lease_owner = $2
		   AND lease_token = $3
		   AND lease_expires_at > clock_timestamp()
		   AND phase_version = $4
		   AND phase = $5
		   FOR UPDATE
	`, lease.CommandID.String(), lease.Owner, lease.Token, lease.PhaseVersion, expectedPhase).Scan(&currentPhaseVersion)
	if err != nil {
		return application.ErrManagementLeaseLost
	}
	return nil
}

// BeginManagementCommand reserves a command under the application row lock.
// It checks (app, key) immediately after locking the application row to ensure
// idempotent replays return the stored immutable snapshot targets without re-evaluating
// post-action states or comparing with mutated current deployment versions.
func (s *Store) BeginManagementCommand(ctx context.Context, request application.AcornFoxManagementRequest, digest string, now time.Time) (application.AcornFoxManagementResult, bool, error) {
	if s.requireDB() != nil {
		return application.AcornFoxManagementResult{}, false, s.requireDB()
	}
	if err := request.Validate(); err != nil {
		return application.AcornFoxManagementResult{}, false, err
	}
	if now.IsZero() {
		now = s.now()
	}

	calculatedDigest := application.AcornFoxManagementRequestDigest(request.Action, request.ApplicationID, request.DeploymentID)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return application.AcornFoxManagementResult{}, false, err
	}
	fail := func(cause error) (application.AcornFoxManagementResult, bool, error) {
		return application.AcornFoxManagementResult{}, false, rollbackTx(tx, cause)
	}

	// 1. Lock applications row
	var managementState string
	if err := tx.QueryRowContext(ctx, `SELECT management_state FROM applications WHERE id = $1 FOR UPDATE`, request.ApplicationID.String()).Scan(&managementState); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fail(domain.NewError(domain.ErrNotFound, "application not found"))
		}
		return fail(err)
	}

	// 2. Immediate front-loaded replay check: must precede archived/paused/busy checks
	var existingID, storedDigest, existingAction, existingPhase string
	var existingFailure sql.NullString
	var existingCreatedAt, existingUpdatedAt time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT id, request_digest, action, phase, failure_reason, created_at, updated_at
		  FROM acornfox_management_commands
		 WHERE application_id = $1 AND idempotency_key = $2
		   FOR UPDATE
	`, request.ApplicationID.String(), request.IdempotencyKey).Scan(&existingID, &storedDigest, &existingAction, &existingPhase, &existingFailure, &existingCreatedAt, &existingUpdatedAt)
	if err == nil {
		if storedDigest != calculatedDigest || existingAction != request.Action {
			return fail(domain.NewError(domain.ErrConflict, "management command idempotency conflict"))
		}
		res, readErr := readManagementCommandTx(ctx, tx, request.ApplicationID, domain.ID(existingID))
		if readErr != nil {
			return fail(readErr)
		}
		if err := tx.Commit(); err != nil {
			return application.AcornFoxManagementResult{}, false, err
		}
		return res, true, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fail(err)
	}

	// 3. New key only: validate application management state vs requested action
	switch request.Action {
	case "stop", "start":
		if managementState != string(domain.ApplicationManagementActive) {
			return fail(domain.NewError(domain.ErrConflict, "application is archiving or archived"))
		}
	case "archive":
		if managementState == string(domain.ApplicationManagementArchived) {
			return fail(domain.NewError(domain.ErrConflict, "application is already archived"))
		}
		// Check for in-progress operations/publishes/builds/candidates
		var inProgressCount int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM m1_publish_requests WHERE application_id = $1 AND status = 'in_progress'`, request.ApplicationID.String()).Scan(&inProgressCount); err != nil {
			return fail(err)
		}
		if inProgressCount > 0 {
			return fail(domain.NewError(domain.ErrConflict, "application has in-progress publish"))
		}

		var activeBuildsCount int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM builds WHERE application_id = $1 AND state IN ('pending', 'running')`, request.ApplicationID.String()).Scan(&activeBuildsCount); err != nil {
			return fail(err)
		}
		if activeBuildsCount > 0 {
			return fail(domain.NewError(domain.ErrConflict, "application has active builds"))
		}

		var activeOpsCount int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM operations WHERE application_id = $1 AND state IN ('pending', 'leased', 'running', 'waiting', 'cancelling')`, request.ApplicationID.String()).Scan(&activeOpsCount); err != nil {
			return fail(err)
		}
		if activeOpsCount > 0 {
			return fail(domain.NewError(domain.ErrConflict, "application has active operations"))
		}

		var activeCandidatesCount int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM acornfox_fix_candidates WHERE application_id = $1 AND state = 'preparing'`, request.ApplicationID.String()).Scan(&activeCandidatesCount); err != nil {
			return fail(err)
		}
		if activeCandidatesCount > 0 {
			return fail(domain.NewError(domain.ErrConflict, "application has active fix candidate validation"))
		}

		if managementState == string(domain.ApplicationManagementActive) {
			if _, err := tx.ExecContext(ctx, `UPDATE applications SET management_state = 'archiving', updated_at = clock_timestamp() WHERE id = $1`, request.ApplicationID.String()); err != nil {
				return fail(err)
			}
		}
	}

	// 4. Check if any nonterminal command is currently active on this application
	var activeID, activeAction, activePhase string
	err = tx.QueryRowContext(ctx, `
		SELECT id, action, phase
		  FROM acornfox_management_commands
		 WHERE application_id = $1 AND phase NOT IN ('completed', 'failed')
		   FOR UPDATE
	`, request.ApplicationID.String()).Scan(&activeID, &activeAction, &activePhase)
	if err == nil {
		return fail(domain.NewError(domain.ErrConflict, "another management command is already in progress for this application"))
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fail(err)
	}

	// 5. Select target deployment(s) and capture immutable snapshot fields
	type targetSnapshot struct {
		deploymentID              string
		releaseID                 string
		snapshotDeploymentVersion int64
		state                     string
		configDigest              string
	}
	var targets []targetSnapshot
	var targetSetDigest string

	switch request.Action {
	case "stop":
		var t targetSnapshot
		err = tx.QueryRowContext(ctx, `
			SELECT d.id, d.release_id, d.version, d.state, COALESCE(r.config_digest, '')
			  FROM deployments d
			  JOIN environments e ON e.id = d.environment_id
			  JOIN releases r ON r.id = d.release_id
			 WHERE e.application_id = $1 AND d.id = $2
			   FOR UPDATE
		`, request.ApplicationID.String(), request.DeploymentID.String()).Scan(&t.deploymentID, &t.releaseID, &t.snapshotDeploymentVersion, &t.state, &t.configDigest)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fail(domain.NewError(domain.ErrNotFound, "deployment not found for application"))
			}
			return fail(err)
		}
		if t.state == "paused" {
			return fail(domain.NewError(domain.ErrConflict, "deployment is already paused"))
		}
		if t.state != "runtime_ready" && t.state != "serving" && t.state != "degraded" && t.state != "deploying" {
			return fail(domain.NewError(domain.ErrConflict, "deployment is not in an active state"))
		}
		targets = append(targets, t)

	case "start":
		var t targetSnapshot
		err = tx.QueryRowContext(ctx, `
			SELECT d.id, d.release_id, d.version, d.state, COALESCE(r.config_digest, '')
			  FROM deployments d
			  JOIN environments e ON e.id = d.environment_id
			  JOIN releases r ON r.id = d.release_id
			 WHERE e.application_id = $1 AND d.id = $2
			   FOR UPDATE
		`, request.ApplicationID.String(), request.DeploymentID.String()).Scan(&t.deploymentID, &t.releaseID, &t.snapshotDeploymentVersion, &t.state, &t.configDigest)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fail(domain.NewError(domain.ErrNotFound, "deployment not found for application"))
			}
			return fail(err)
		}
		if t.state != "paused" {
			return fail(domain.NewError(domain.ErrConflict, "deployment is not paused"))
		}
		targets = append(targets, t)

	case "archive":
		rows, qErr := tx.QueryContext(ctx, `
			SELECT d.id, d.release_id, d.version, d.state, COALESCE(r.config_digest, '')
			  FROM deployments d
			  JOIN environments e ON e.id = d.environment_id
			  JOIN releases r ON r.id = d.release_id
			 WHERE e.application_id = $1
			 ORDER BY d.created_at ASC, d.id ASC
			   FOR UPDATE
		`, request.ApplicationID.String())
		if qErr != nil {
			return fail(qErr)
		}
		defer rows.Close()
		var targetDescriptors []string
		for rows.Next() {
			var t targetSnapshot
			if err := rows.Scan(&t.deploymentID, &t.releaseID, &t.snapshotDeploymentVersion, &t.state, &t.configDigest); err != nil {
				return fail(err)
			}
			targets = append(targets, t)
			targetDescriptors = append(targetDescriptors, fmt.Sprintf("%s:%s:%s:%d", t.deploymentID, t.releaseID, t.configDigest, t.snapshotDeploymentVersion))
		}
		rows.Close()
		targetSetDigest = application.TargetSetDigest(targetDescriptors)
	}

	commandID := mgmtHashID("mgmt_cmd", request.ApplicationID.String(), request.IdempotencyKey)
	_, err = tx.ExecContext(ctx, `
		INSERT INTO acornfox_management_commands
			(id, application_id, idempotency_key, request_digest, target_set_digest, action, phase, phase_version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'accepted', 1, clock_timestamp(), clock_timestamp())
	`, commandID.String(), request.ApplicationID.String(), request.IdempotencyKey, calculatedDigest, targetSetDigest, request.Action)
	if err != nil {
		return fail(fmt.Errorf("insert management command: %w", err))
	}

	resultTargets := make([]application.AcornFoxManagementTarget, 0, len(targets))
	for _, t := range targets {
		var desiredPublic bool
		var routeIntentJSON sql.NullString
		_ = tx.QueryRowContext(ctx, `
			SELECT requested_enabled
			  FROM acornfox_public_access_commands
			 WHERE application_id = $1 AND deployment_id = $2 AND phase = 'completed'
			 ORDER BY created_at DESC LIMIT 1
		`, request.ApplicationID.String(), t.deploymentID).Scan(&desiredPublic)

		if desiredPublic {
			var intent contracts.AcornFoxPublicRouteIntent
			var found bool
			intent, _, found, err = afpaRouteIntentTx(ctx, tx, request.ApplicationID, domain.ID(t.deploymentID), afpaID("route", request.ApplicationID.String(), t.deploymentID), false)
			if err == nil && found {
				raw, _ := json.Marshal(intent)
				routeIntentJSON = sql.NullString{String: string(raw), Valid: true}
			}
		}

		targetID := mgmtHashID("mgmt_tgt", commandID.String(), t.deploymentID)
		initialStatus := "pending"
		if request.Action == "archive" && t.state == "stopped" {
			initialStatus = "completed"
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO acornfox_management_targets
				(id, command_id, deployment_id, release_id, snapshot_deployment_version, revision, route_phase, original_desired_public, original_route_intent, config_identity, status, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, 1, 'initial', $6, $7, $8, $9, clock_timestamp(), clock_timestamp())
		`, targetID.String(), commandID.String(), t.deploymentID, t.releaseID, t.snapshotDeploymentVersion, desiredPublic, routeIntentJSON, nullableString(t.configDigest), initialStatus)
		if err != nil {
			return fail(fmt.Errorf("insert management target: %w", err))
		}
		resultTargets = append(resultTargets, application.AcornFoxManagementTarget{
			ID:                        targetID,
			CommandID:                 commandID,
			DeploymentID:              domain.ID(t.deploymentID),
			ReleaseID:                 domain.ID(t.releaseID),
			SnapshotDeploymentVersion: t.snapshotDeploymentVersion,
			Revision:                  1,
			RoutePhase:                "initial",
			OriginalDesiredPublic:     desiredPublic,
			OriginalRouteIntent:       routeIntentJSON.String,
			ConfigIdentity:            t.configDigest,
			Status:                    initialStatus,
			CreatedAt:                 now.UTC(),
			UpdatedAt:                 now.UTC(),
		})
	}

	if err := tx.Commit(); err != nil {
		return application.AcornFoxManagementResult{}, false, err
	}

	return application.AcornFoxManagementResult{
		CommandID:       commandID,
		ApplicationID:   request.ApplicationID,
		Action:          request.Action,
		Phase:           "accepted",
		TargetSetDigest: targetSetDigest,
		Targets:         resultTargets,
		CreatedAt:       now.UTC(),
		UpdatedAt:       now.UTC(),
	}, false, nil
}

func readManagementCommandTx(ctx context.Context, tx *sql.Tx, appID, commandID domain.ID) (application.AcornFoxManagementResult, error) {
	var cmdID, applicationID, action, phase, targetSetDigest string
	var failureReason sql.NullString
	var createdAt, updatedAt time.Time
	err := tx.QueryRowContext(ctx, `
		SELECT id, application_id, action, phase, target_set_digest, failure_reason, created_at, updated_at
		  FROM acornfox_management_commands
		 WHERE application_id = $1 AND id = $2
	`, appID.String(), commandID.String()).Scan(&cmdID, &applicationID, &action, &phase, &targetSetDigest, &failureReason, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return application.AcornFoxManagementResult{}, domain.NewError(domain.ErrNotFound, "management command not found")
		}
		return application.AcornFoxManagementResult{}, err
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT id, deployment_id, release_id, snapshot_deployment_version, revision, route_phase,
		       COALESCE(runtime_task_id, ''), COALESCE(probe_task_id, ''),
		       original_desired_public, COALESCE(original_route_intent::text, ''), COALESCE(config_identity, ''),
		       status, COALESCE(failure_reason, ''), created_at, updated_at
		  FROM acornfox_management_targets
		 WHERE command_id = $1
		 ORDER BY created_at
	`, cmdID)
	if err != nil {
		return application.AcornFoxManagementResult{}, err
	}
	defer rows.Close()

	var targets []application.AcornFoxManagementTarget
	for rows.Next() {
		var tgt application.AcornFoxManagementTarget
		var tid, did, rid, rtid, ptid string
		if err := rows.Scan(&tid, &did, &rid, &tgt.SnapshotDeploymentVersion, &tgt.Revision, &tgt.RoutePhase, &rtid, &ptid, &tgt.OriginalDesiredPublic, &tgt.OriginalRouteIntent, &tgt.ConfigIdentity, &tgt.Status, &tgt.FailureReason, &tgt.CreatedAt, &tgt.UpdatedAt); err != nil {
			return application.AcornFoxManagementResult{}, err
		}
		tgt.ID = domain.ID(tid)
		tgt.CommandID = domain.ID(cmdID)
		tgt.DeploymentID = domain.ID(did)
		tgt.ReleaseID = domain.ID(rid)
		if rtid != "" {
			tgt.RuntimeTaskID = domain.ID(rtid)
		}
		if ptid != "" {
			tgt.ProbeTaskID = domain.ID(ptid)
		}
		targets = append(targets, tgt)
	}
	rows.Close()

	retained, err := readRetainedVolumesTx(ctx, tx, appID)
	if err != nil {
		return application.AcornFoxManagementResult{}, err
	}

	return application.AcornFoxManagementResult{
		CommandID:       domain.ID(cmdID),
		ApplicationID:   domain.ID(applicationID),
		Action:          action,
		Phase:           phase,
		TargetSetDigest: targetSetDigest,
		Targets:         targets,
		RetainedVolumes: retained,
		FailureReason:   failureReason.String,
		CreatedAt:       createdAt.UTC(),
		UpdatedAt:       updatedAt.UTC(),
	}, nil
}

func readRetainedVolumesTx(ctx context.Context, tx *sql.Tx, appID domain.ID) ([]contracts.AcornFoxRetainedVolumeReceipt, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT application_id, logical_name, managed_volume_name, volume_driver, receipt_digest, verified_at
		  FROM acornfox_retained_volumes
		 WHERE application_id = $1
		 ORDER BY logical_name
	`, appID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []contracts.AcornFoxRetainedVolumeReceipt
	for rows.Next() {
		var r contracts.AcornFoxRetainedVolumeReceipt
		var aid string
		if err := rows.Scan(&aid, &r.LogicalName, &r.ManagedVolumeName, &r.VolumeDriver, &r.ReceiptDigest, &r.VerifiedAt); err != nil {
			return nil, err
		}
		r.ApplicationID = domain.ID(aid)
		out = append(out, r)
	}
	return out, nil
}

func (s *Store) GetManagementCommand(ctx context.Context, appID, commandID domain.ID) (application.AcornFoxManagementResult, error) {
	if s.requireDB() != nil {
		return application.AcornFoxManagementResult{}, s.requireDB()
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return application.AcornFoxManagementResult{}, err
	}
	defer tx.Rollback()
	return readManagementCommandTx(ctx, tx, appID, commandID)
}

// ClaimManagementCommandLeases acquires unexpired leases with unique non-reusable tokens.
func (s *Store) ClaimManagementCommandLeases(ctx context.Context, owner string, lease time.Duration, limit int, now time.Time) ([]application.AcornFoxManagementCommandLease, error) {
	if s.requireDB() != nil {
		return nil, s.requireDB()
	}
	if strings.TrimSpace(owner) == "" || lease <= 0 || limit <= 0 {
		return nil, domain.ValidationError("claim management command lease arguments invalid")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `
		SELECT id, application_id, action, phase, phase_version
		  FROM acornfox_management_commands
		 WHERE phase NOT IN ('completed', 'failed')
		   AND (lease_expires_at IS NULL OR lease_expires_at < clock_timestamp())
		 ORDER BY created_at
		 LIMIT $1
		   FOR UPDATE SKIP LOCKED
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type commandRow struct {
		id            string
		applicationID string
		action        string
		phase         string
		phaseVersion  int64
	}
	var cmds []commandRow
	for rows.Next() {
		var c commandRow
		if err := rows.Scan(&c.id, &c.applicationID, &c.action, &c.phase, &c.phaseVersion); err != nil {
			return nil, err
		}
		cmds = append(cmds, c)
	}
	rows.Close()

	if len(cmds) == 0 {
		return nil, nil
	}

	var leases []application.AcornFoxManagementCommandLease
	for _, c := range cmds {
		token := domain.MustNewID("tok").String()
		expiresAt := time.Now().UTC().Add(lease)
		_, err := tx.ExecContext(ctx, `
			UPDATE acornfox_management_commands
			   SET lease_owner = $1,
			       lease_token = $2,
			       lease_expires_at = clock_timestamp() + $3::interval,
			       updated_at = clock_timestamp()
			 WHERE id = $4
		`, owner, token, fmt.Sprintf("%d seconds", int(lease.Seconds())), c.id)
		if err != nil {
			return nil, err
		}

		targetRows, err := tx.QueryContext(ctx, `
			SELECT id, deployment_id, release_id, snapshot_deployment_version, revision, route_phase,
			       COALESCE(runtime_task_id, ''), COALESCE(probe_task_id, ''),
			       original_desired_public, COALESCE(original_route_intent::text, ''), COALESCE(config_identity, ''),
			       status, COALESCE(failure_reason, ''), created_at, updated_at
			  FROM acornfox_management_targets
			 WHERE command_id = $1
			 ORDER BY created_at
		`, c.id)
		if err != nil {
			return nil, err
		}
		var targets []application.AcornFoxManagementTarget
		for targetRows.Next() {
			var tgt application.AcornFoxManagementTarget
			var tid, did, rid, rtid, ptid string
			if err := targetRows.Scan(&tid, &did, &rid, &tgt.SnapshotDeploymentVersion, &tgt.Revision, &tgt.RoutePhase, &rtid, &ptid, &tgt.OriginalDesiredPublic, &tgt.OriginalRouteIntent, &tgt.ConfigIdentity, &tgt.Status, &tgt.FailureReason, &tgt.CreatedAt, &tgt.UpdatedAt); err != nil {
				targetRows.Close()
				return nil, err
			}
			tgt.ID = domain.ID(tid)
			tgt.CommandID = domain.ID(c.id)
			tgt.DeploymentID = domain.ID(did)
			tgt.ReleaseID = domain.ID(rid)
			if rtid != "" {
				tgt.RuntimeTaskID = domain.ID(rtid)
			}
			if ptid != "" {
				tgt.ProbeTaskID = domain.ID(ptid)
			}
			targets = append(targets, tgt)
		}
		targetRows.Close()

		leases = append(leases, application.AcornFoxManagementCommandLease{
			CommandID:     domain.ID(c.id),
			ApplicationID: domain.ID(c.applicationID),
			Action:        c.action,
			Phase:         c.phase,
			PhaseVersion:  c.phaseVersion,
			Owner:         owner,
			Token:         token,
			ExpiresAt:     expiresAt,
			Targets:       targets,
		})
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return leases, nil
}

// UpdateManagementCommandPhase executes a fenced CAS update validating owner, token,
// unexpired lease (via clock_timestamp), and expected phase version.
// For non-terminal transitions, it releases the lease immediately so that the next phase
// can be claimed without waiting for a lease timeout.
func (s *Store) UpdateManagementCommandPhase(ctx context.Context, lease application.AcornFoxManagementCommandLease, expectedPhase, newPhase, failureReason string) error {
	if s.requireDB() != nil {
		return s.requireDB()
	}
	if lease.CommandID.Empty() || strings.TrimSpace(newPhase) == "" || strings.TrimSpace(lease.Token) == "" {
		return domain.ValidationError("command phase update invalid")
	}
	var failRef any
	if failureReason != "" {
		failRef = failureReason
	}

	res, err := s.db.ExecContext(ctx, `
		UPDATE acornfox_management_commands
		   SET phase = $1,
		       phase_version = phase_version + 1,
		       failure_reason = $2,
		       lease_owner = NULL,
		       lease_token = NULL,
		       lease_expires_at = NULL,
		       updated_at = clock_timestamp()
		 WHERE id = $3
		   AND lease_owner = $4
		   AND lease_token = $5
		   AND lease_expires_at > clock_timestamp()
		   AND phase_version = $6
		   AND phase = $7
	`, newPhase, failRef, lease.CommandID.String(), lease.Owner, lease.Token, lease.PhaseVersion, expectedPhase)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return application.ErrManagementLeaseLost
	}
	return nil
}

// UpdateManagementTarget updates target attributes under target revision CAS.
func (s *Store) UpdateManagementTarget(ctx context.Context, lease application.AcornFoxManagementCommandLease, target application.AcornFoxManagementTarget, expectedRevision int64) error {
	if s.requireDB() != nil {
		return s.requireDB()
	}
	if target.ID.Empty() {
		return domain.ValidationError("target id is required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. Lock applications row
	var appState string
	if err := tx.QueryRowContext(ctx, `SELECT management_state FROM applications WHERE id = $1 FOR UPDATE`, lease.ApplicationID.String()).Scan(&appState); err != nil {
		return err
	}

	// 2. Verify command lease
	if err := verifyManagementLeaseTx(ctx, tx, lease, lease.Phase); err != nil {
		return err
	}

	// 3. Fenced target update
	var rtid, ptid, failRef any
	if !target.RuntimeTaskID.Empty() {
		rtid = target.RuntimeTaskID.String()
	}
	if !target.ProbeTaskID.Empty() {
		ptid = target.ProbeTaskID.String()
	}
	if target.FailureReason != "" {
		failRef = target.FailureReason
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE acornfox_management_targets
		   SET route_phase = $1,
		       runtime_task_id = $2,
		       probe_task_id = $3,
		       status = $4,
		       failure_reason = $5,
		       revision = revision + 1,
		       updated_at = clock_timestamp()
		 WHERE id = $6
		   AND command_id = $7
		   AND revision = $8
	`, target.RoutePhase, rtid, ptid, target.Status, failRef, target.ID.String(), lease.CommandID.String(), expectedRevision)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return application.ErrManagementTargetConflict
	}

	return tx.Commit()
}

// EnqueueTargetTask executes an atomic transaction locking application -> command -> target,
// enqueuing the controller task with explicit management authorization, and binding the task ID.
func (s *Store) EnqueueTargetTask(ctx context.Context, lease application.AcornFoxManagementCommandLease, target application.AcornFoxManagementTarget, task application.AcornFoxQueuedTask) error {
	if s.requireDB() != nil {
		return s.requireDB()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. Lock applications row
	var appState string
	if err := tx.QueryRowContext(ctx, `SELECT management_state FROM applications WHERE id = $1 FOR UPDATE`, lease.ApplicationID.String()).Scan(&appState); err != nil {
		return err
	}

	// 2. Verify command lease
	if err := verifyManagementLeaseTx(ctx, tx, lease, lease.Phase); err != nil {
		return err
	}

	// 3. Verify target revision
	var targetRevision int64
	err = tx.QueryRowContext(ctx, `
		SELECT revision
		  FROM acornfox_management_targets
		 WHERE id = $1 AND command_id = $2
		   FOR UPDATE
	`, target.ID.String(), lease.CommandID.String()).Scan(&targetRevision)
	if err != nil || targetRevision != target.Revision {
		return application.ErrManagementTargetConflict
	}

	// 4. Enqueue controller task with explicit management authorization
	req := EnqueueControllerTaskRequest{
		Operation:            task.Operation,
		Deployment:           task.Deployment,
		ExistingDeploymentID: task.ExistingDeploymentID,
		TaskID:               task.TaskID,
		Payload:              task.Payload,
		MaxAttempts:          task.MaxAttempts,
		InitialPublishStatus: domain.PublishDeploying,
		ManagementAuth: &ManagementAuthorization{
			CommandID: lease.CommandID,
			TargetID:  target.ID,
			Action:    lease.Action,
		},
	}
	if _, err := s.enqueueControllerTaskTx(ctx, tx, req); err != nil {
		return err
	}

	// 5. Update target with task ID and increment revision
	res, err := tx.ExecContext(ctx, `
		UPDATE acornfox_management_targets
		   SET runtime_task_id = $1,
		       status = 'running',
		       revision = revision + 1,
		       updated_at = clock_timestamp()
		 WHERE id = $2 AND revision = $3
	`, task.TaskID.String(), target.ID.String(), target.Revision)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil || rows == 0 {
		return application.ErrManagementTargetConflict
	}

	return tx.Commit()
}

func (s *Store) GetTaskState(ctx context.Context, taskID domain.ID) (string, string, json.RawMessage, error) {
	if s.requireDB() != nil {
		return "", "", nil, s.requireDB()
	}
	if taskID.Empty() {
		return "", "", nil, domain.ValidationError("task id is required")
	}
	var state string
	var failureReason sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT t.state, o.failure_reason
		  FROM task_leases t
		  JOIN operations o ON o.id = t.operation_id
		 WHERE t.task_id = $1
	`, taskID.String()).Scan(&state, &failureReason)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", nil, domain.NewError(domain.ErrNotFound, "task not found")
		}
		return "", "", nil, err
	}

	var payload []byte
	_ = s.db.QueryRowContext(ctx, `
		SELECT payload
		  FROM task_agent_events
		 WHERE task_id = $1
		 ORDER BY sequence DESC
		 LIMIT 1
	`, taskID.String()).Scan(&payload)

	return state, failureReason.String, payload, nil
}

// SavePauseReceipt saves a pause receipt bound to the active stop command and target.
// In-transaction, it pulls the legal release_id from the locked deployment to prevent FK errors.
// Same stop command retry is strictly idempotent without incrementing epoch or altering intent.
func (s *Store) SavePauseReceipt(ctx context.Context, lease application.AcornFoxManagementCommandLease, target application.AcornFoxManagementTarget, receipt application.AcornFoxPauseReceipt) error {
	if s.requireDB() != nil {
		return s.requireDB()
	}
	if receipt.DeploymentID.Empty() || receipt.ApplicationID.Empty() {
		return domain.ValidationError("pause receipt identity is invalid")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. Lock application
	var appState string
	if err := tx.QueryRowContext(ctx, `SELECT management_state FROM applications WHERE id = $1 FOR UPDATE`, lease.ApplicationID.String()).Scan(&appState); err != nil {
		return err
	}

	// 2. Verify command lease
	if err := verifyManagementLeaseTx(ctx, tx, lease, lease.Phase); err != nil {
		return err
	}

	// 3. Verify target and read legal release_id from deployment
	var depReleaseID, depConfigDigest string
	err = tx.QueryRowContext(ctx, `
		SELECT d.release_id, COALESCE(r.config_digest, '')
		  FROM deployments d
		  JOIN releases r ON r.id = d.release_id
		 WHERE d.id = $1 AND d.environment_id IN (SELECT id FROM environments WHERE application_id = $2)
		   FOR UPDATE
	`, receipt.DeploymentID.String(), receipt.ApplicationID.String()).Scan(&depReleaseID, &depConfigDigest)
	if err != nil {
		return fmt.Errorf("verify deployment for pause receipt: %w", err)
	}

	var canonicalRaw sql.NullString
	if receipt.CanonicalIntent != nil {
		raw, err := json.Marshal(receipt.CanonicalIntent)
		if err != nil {
			return err
		}
		canonicalRaw = sql.NullString{String: string(raw), Valid: true}
	}

	// 4. Check if pause receipt already exists
	var existingStopCmd, existingIntentDigest string
	var existingDesiredPublic bool
	var existingEpoch int64
	err = tx.QueryRowContext(ctx, `
		SELECT stop_command_id, pause_epoch, COALESCE(intent_digest, ''), original_desired_public
		  FROM acornfox_pause_receipts
		 WHERE deployment_id = $1
		   FOR UPDATE
	`, receipt.DeploymentID.String()).Scan(&existingStopCmd, &existingEpoch, &existingIntentDigest, &existingDesiredPublic)
	if err == nil {
		if existingStopCmd == lease.CommandID.String() {
			// Idempotent retry: verify intent and desired public match exactly
			if existingIntentDigest != receipt.IntentDigest || existingDesiredPublic != receipt.OriginalDesiredPublic {
				return domain.NewError(domain.ErrConflict, "pause receipt intent conflict on retry")
			}
			return tx.Commit() // no-op, epoch unchanged
		}
		return domain.NewError(domain.ErrConflict, "pause receipt belongs to another stop command")
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	// 5. Insert new pause receipt
	_, err = tx.ExecContext(ctx, `
		INSERT INTO acornfox_pause_receipts
			(deployment_id, application_id, stop_command_id, config_identity, release_id, original_desired_public, canonical_intent, intent_digest, pause_epoch, consumed, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, false, clock_timestamp(), clock_timestamp())
	`, receipt.DeploymentID.String(), receipt.ApplicationID.String(), lease.CommandID.String(), depConfigDigest, depReleaseID, receipt.OriginalDesiredPublic, canonicalRaw, nullableString(receipt.IntentDigest))
	if err != nil {
		return fmt.Errorf("insert pause receipt: %w", err)
	}

	return tx.Commit()
}

func (s *Store) GetPauseReceipt(ctx context.Context, appID, deploymentID domain.ID) (application.AcornFoxPauseReceipt, bool, error) {
	if s.requireDB() != nil {
		return application.AcornFoxPauseReceipt{}, false, s.requireDB()
	}
	var r application.AcornFoxPauseReceipt
	var aid, did, scid, rid string
	var canonicalRaw, intentDigest sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT deployment_id, application_id, stop_command_id, config_identity, release_id, original_desired_public, canonical_intent::text, intent_digest, pause_epoch, consumed, created_at, updated_at
		  FROM acornfox_pause_receipts
		 WHERE application_id = $1 AND deployment_id = $2
	`, appID.String(), deploymentID.String()).Scan(&did, &aid, &scid, &r.ConfigIdentity, &rid, &r.OriginalDesiredPublic, &canonicalRaw, &intentDigest, &r.PauseEpoch, &r.Consumed, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return application.AcornFoxPauseReceipt{}, false, nil
		}
		return application.AcornFoxPauseReceipt{}, false, err
	}
	r.DeploymentID = domain.ID(did)
	r.ApplicationID = domain.ID(aid)
	r.StopCommandID = domain.ID(scid)
	r.ReleaseID = domain.ID(rid)
	r.IntentDigest = intentDigest.String
	if canonicalRaw.Valid && canonicalRaw.String != "" {
		var intent contracts.AcornFoxPublicRouteIntent
		if err := json.Unmarshal([]byte(canonicalRaw.String), &intent); err == nil {
			r.CanonicalIntent = &intent
		}
	}
	return r, true, nil
}

// ConsumePauseReceipt consumes a pause receipt under command lease fence and matching epoch.
func (s *Store) ConsumePauseReceipt(ctx context.Context, lease application.AcornFoxManagementCommandLease, target application.AcornFoxManagementTarget, expectedEpoch int64) error {
	if s.requireDB() != nil {
		return s.requireDB()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. Lock application
	var appState string
	if err := tx.QueryRowContext(ctx, `SELECT management_state FROM applications WHERE id = $1 FOR UPDATE`, lease.ApplicationID.String()).Scan(&appState); err != nil {
		return err
	}

	// 2. Verify command lease
	if err := verifyManagementLeaseTx(ctx, tx, lease, lease.Phase); err != nil {
		return err
	}

	// 3. Consume receipt
	res, err := tx.ExecContext(ctx, `
		UPDATE acornfox_pause_receipts
		   SET consumed = true, updated_at = clock_timestamp()
		 WHERE application_id = $1 AND deployment_id = $2 AND pause_epoch = $3 AND consumed = false
	`, lease.ApplicationID.String(), target.DeploymentID.String(), expectedEpoch)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		var consumed bool
		err = tx.QueryRowContext(ctx, `SELECT consumed FROM acornfox_pause_receipts WHERE application_id = $1 AND deployment_id = $2 AND pause_epoch = $3`, lease.ApplicationID.String(), target.DeploymentID.String(), expectedEpoch).Scan(&consumed)
		if err == nil && consumed {
			return tx.Commit() // idempotent retry
		}
		return domain.NewError(domain.ErrConflict, "pause receipt already consumed or epoch mismatch")
	}

	return tx.Commit()
}

// GetValidatedManagementDestroyEvidence strictly validates the destroy observation event,
// verifies volume specs against persisted configuration, projects retained volume records,
// and records retention evidence.
func (s *Store) GetValidatedManagementDestroyEvidence(ctx context.Context, lease application.AcornFoxManagementCommandLease, target application.AcornFoxManagementTarget) ([]contracts.AcornFoxRetainedVolumeReceipt, error) {
	if s.requireDB() != nil {
		return nil, s.requireDB()
	}
	if target.RuntimeTaskID.Empty() {
		return nil, errors.New("target runtime task id is missing")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Check task completion
	var taskState string
	err = tx.QueryRowContext(ctx, `SELECT state FROM task_leases WHERE task_id = $1`, target.RuntimeTaskID.String()).Scan(&taskState)
	if err != nil || taskState != "completed" {
		return nil, errors.New("destroy task is not completed")
	}

	// Query observation event
	var seq int64
	var eventDigest string
	var payloadBytes []byte
	err = tx.QueryRowContext(ctx, `
		SELECT sequence, event_digest, payload
		  FROM task_agent_events
		 WHERE task_id = $1 AND event_type = 'observation'
		 ORDER BY sequence DESC
		 LIMIT 1
	`, target.RuntimeTaskID.String()).Scan(&seq, &eventDigest, &payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("destroy observation event missing: %w", err)
	}

	var obs struct {
		TargetRef string          `json:"target_ref"`
		Status    string          `json:"status"`
		Details   json.RawMessage `json:"details"`
	}
	if err := json.Unmarshal(payloadBytes, &obs); err != nil {
		return nil, fmt.Errorf("destroy observation payload invalid: %w", err)
	}
	if obs.TargetRef != "deployment/"+target.DeploymentID.String() || obs.Status != "stopped" {
		return nil, fmt.Errorf("destroy observation target or status invalid: ref=%s status=%s", obs.TargetRef, obs.Status)
	}

	var details struct {
		DeploymentID    string                                    `json:"deployment_id"`
		RuntimeState    string                                    `json:"runtime_state"`
		RetainedVolumes []contracts.AcornFoxRetainedVolumeReceipt `json:"retained_volumes"`
	}
	if len(obs.Details) > 0 {
		if err := json.Unmarshal(obs.Details, &details); err != nil {
			return nil, fmt.Errorf("destroy observation details invalid: %w", err)
		}
	}

	deployReq, err := s.GetAcornFoxRuntimeRequest(ctx, lease.ApplicationID, target.DeploymentID)
	if err != nil {
		return nil, fmt.Errorf("load deploy request: %w", err)
	}

	var expectedVolumes []contracts.AcornFoxRuntimeVolume
	if deployReq.Fact.Configuration != nil {
		expectedVolumes = deployReq.Fact.Configuration.Volumes
	}

	if len(expectedVolumes) == 0 {
		if len(details.RetainedVolumes) != 0 {
			return nil, errors.New("observation reported retained volumes for zero-volume deployment")
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO acornfox_management_retention_evidence
				(command_id, target_id, task_id, deployment_id, sequence, event_digest, verified_retained_volumes, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, '[]'::jsonb, clock_timestamp())
			ON CONFLICT (target_id, task_id) DO NOTHING
		`, lease.CommandID.String(), target.ID.String(), target.RuntimeTaskID.String(), target.DeploymentID.String(), seq, eventDigest)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, nil
	}

	if len(details.RetainedVolumes) != len(expectedVolumes) {
		return nil, fmt.Errorf("retained volumes count (%d) does not match expected (%d)", len(details.RetainedVolumes), len(expectedVolumes))
	}

	receiptsByLogical := make(map[string]contracts.AcornFoxRetainedVolumeReceipt)
	for _, r := range details.RetainedVolumes {
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("retained volume receipt invalid: %w", err)
		}
		if r.ApplicationID != lease.ApplicationID {
			return nil, errors.New("retained volume application id mismatch")
		}
		receiptsByLogical[r.LogicalName] = r
	}

	for _, v := range expectedVolumes {
		receipt, ok := receiptsByLogical[v.Name]
		if !ok {
			return nil, fmt.Errorf("missing retained volume receipt for volume %s", v.Name)
		}
		volID := mgmtHashID("vol_ret", lease.ApplicationID.String(), receipt.LogicalName)
		res, err := tx.ExecContext(ctx, `
			INSERT INTO acornfox_retained_volumes
				(id, application_id, logical_name, managed_volume_name, volume_driver, receipt_digest, verified_at, last_verified_deployment_id, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, clock_timestamp(), clock_timestamp())
			ON CONFLICT (application_id, logical_name) DO UPDATE
			   SET verified_at = EXCLUDED.verified_at,
			       last_verified_deployment_id = EXCLUDED.last_verified_deployment_id,
			       updated_at = EXCLUDED.updated_at
			 WHERE acornfox_retained_volumes.managed_volume_name = EXCLUDED.managed_volume_name
			   AND acornfox_retained_volumes.receipt_digest = EXCLUDED.receipt_digest
		`, volID.String(), lease.ApplicationID.String(), receipt.LogicalName, receipt.ManagedVolumeName, receipt.VolumeDriver, receipt.ReceiptDigest, receipt.VerifiedAt.UTC(), target.DeploymentID.String())
		if err != nil {
			return nil, err
		}
		rows, err := res.RowsAffected()
		if err != nil || rows == 0 {
			return nil, domain.NewError(domain.ErrConflict, "shared volume receipt or managed volume name mismatch across deployments")
		}
	}

	evidenceJSON, _ := json.Marshal(details.RetainedVolumes)
	_, err = tx.ExecContext(ctx, `
		INSERT INTO acornfox_management_retention_evidence
			(command_id, target_id, task_id, deployment_id, sequence, event_digest, verified_retained_volumes, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, clock_timestamp())
		ON CONFLICT (target_id, task_id) DO NOTHING
	`, lease.CommandID.String(), target.ID.String(), target.RuntimeTaskID.String(), target.DeploymentID.String(), seq, eventDigest, evidenceJSON)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return details.RetainedVolumes, nil
}

// FinalizeArchive executes an atomic transaction that locks the application,
// asserts all targets are confirmed destroyed with retention evidence,
// transitions the application to archived, and completes the management command.
func (s *Store) FinalizeArchive(ctx context.Context, lease application.AcornFoxManagementCommandLease) error {
	if s.requireDB() != nil {
		return s.requireDB()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. Lock applications row
	var appState string
	if err := tx.QueryRowContext(ctx, `SELECT management_state FROM applications WHERE id = $1 FOR UPDATE`, lease.ApplicationID.String()).Scan(&appState); err != nil {
		return err
	}

	// 2. Fenced CAS on command
	if err := verifyManagementLeaseTx(ctx, tx, lease, "archived"); err != nil {
		return err
	}

	// 3. Verify all targets are destroyed with retention evidence
	var unconfirmedCount int
	err = tx.QueryRowContext(ctx, `
		SELECT count(*)
		  FROM acornfox_management_targets t
		 WHERE t.command_id = $1
		   AND t.status != 'completed'
		   AND NOT EXISTS (
		       SELECT 1 FROM acornfox_management_retention_evidence e
		        WHERE e.command_id = t.command_id AND e.target_id = t.id
		   )
	`, lease.CommandID.String()).Scan(&unconfirmedCount)
	if err != nil {
		return err
	}
	if unconfirmedCount > 0 {
		return domain.NewError(domain.ErrConflict, "cannot finalize archive: unconfirmed targets exist")
	}

	// 4. Update application state
	if _, err := tx.ExecContext(ctx, `
		UPDATE applications
		   SET management_state = 'archived', archived_at = clock_timestamp(), updated_at = clock_timestamp()
		 WHERE id = $1
	`, lease.ApplicationID.String()); err != nil {
		return err
	}

	// 5. Complete management command and clear lease
	res, err := tx.ExecContext(ctx, `
		UPDATE acornfox_management_commands
		   SET phase = 'completed',
		       phase_version = phase_version + 1,
		       lease_owner = NULL,
		       lease_token = NULL,
		       lease_expires_at = NULL,
		       updated_at = clock_timestamp()
		 WHERE id = $1
		   AND lease_owner = $2
		   AND lease_token = $3
		   AND phase_version = $4
	`, lease.CommandID.String(), lease.Owner, lease.Token, lease.PhaseVersion)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil || rows == 0 {
		return application.ErrManagementLeaseLost
	}

	// 6. Complete all targets
	_, err = tx.ExecContext(ctx, `
		UPDATE acornfox_management_targets
		   SET status = 'completed', revision = revision + 1, updated_at = clock_timestamp()
		 WHERE command_id = $1
	`, lease.CommandID.String())
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) GetRetainedVolumes(ctx context.Context, appID domain.ID) ([]contracts.AcornFoxRetainedVolumeReceipt, error) {
	if s.requireDB() != nil {
		return nil, s.requireDB()
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return readRetainedVolumesTx(ctx, tx, appID)
}
