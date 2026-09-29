package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	contracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/packprotocol"
)

var _ contracts.PackExecutionRepository = (*Store)(nil)

const packCheckScope = "pack.protocol.check"

func validHexDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'f' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func decodeCheckResult(b []byte) (contracts.BeginPackProtocolCheckResult, error) {
	var r contracts.BeginPackProtocolCheckResult
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&r); err != nil {
		return r, ErrIdempotencyCorrupt
	}
	var tail any
	if decoder.Decode(&tail) != io.EOF || r.TaskID == "" || r.OperationID == "" || r.InstanceID == "" || !validHexDigest(r.InputDigest) {
		return r, ErrIdempotencyCorrupt
	}
	return r, nil
}

func (s *Store) RegisterPackProtocolInstance(ctx context.Context, req contracts.RegisterPackProtocolInstanceRequest) (contracts.PackProtocolInstance, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.PackProtocolInstance{}, err
	}
	if !packprotocol.ValidPackID(req.PackID) || req.InstanceID == "" || req.OperationID == "" || req.ExecutablePath == "" || req.ExpectedPID <= 0 || !validHexDigest(req.ExecutableSHA256) || strings.TrimSpace(req.ProcessStartTime) == "" || strings.TrimSpace(req.SocketPath) == "" {
		return contracts.PackProtocolInstance{}, errors.New("invalid pack protocol instance registration parameters")
	}
	if len(req.ManifestRaw) == 0 {
		return contracts.PackProtocolInstance{}, errors.New("missing verified manifest proof")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return contracts.PackProtocolInstance{}, err
	}
	defer tx.Rollback()

	// 1. Check existing install operation
	var opKind, opPackID, opState string
	err = tx.QueryRowContext(ctx, `SELECT target_kind, pack_id, state FROM operations WHERE id=?`, req.OperationID).Scan(&opKind, &opPackID, &opState)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return contracts.PackProtocolInstance{}, errors.New("install operation not found")
		}
		return contracts.PackProtocolInstance{}, err
	}
	if opKind != "pack" || opPackID != req.PackID {
		return contracts.PackProtocolInstance{}, errors.New("operation does not match pack")
	}
	if opState != "pending" && opState != "leased" && opState != "running" && opState != "waiting" {
		return contracts.PackProtocolInstance{}, errors.New("operation is not active")
	}

	// 2. Check pack record and install intent
	var packState, installationBinding, manifestSHA256, desiredVersion string
	err = tx.QueryRowContext(ctx, `SELECT state, installation_binding, manifest_sha256, desired_version FROM pack_records WHERE pack_id=?`, req.PackID).Scan(&packState, &installationBinding, &manifestSHA256, &desiredVersion)
	if err != nil {
		return contracts.PackProtocolInstance{}, err
	}
	if packState != "planned" {
		return contracts.PackProtocolInstance{}, errors.New("pack record not in planned state")
	}

	var selectedJSON string
	err = tx.QueryRowContext(ctx, `SELECT selected_identity FROM pack_install_intents WHERE operation_id=?`, req.OperationID).Scan(&selectedJSON)
	if err != nil {
		return contracts.PackProtocolInstance{}, err
	}

	var selected packprotocol.Selection
	if err := json.Unmarshal([]byte(selectedJSON), &selected); err != nil {
		return contracts.PackProtocolInstance{}, fmt.Errorf("corrupt selected identity: %w", err)
	}

	// 3. Cryptographic binding check: manifest raw bytes SHA256 must match persisted intent
	manifestHash := sha256.Sum256(req.ManifestRaw)
	manifestDigest := hex.EncodeToString(manifestHash[:])
	if manifestDigest != selected.ManifestSHA256 || manifestDigest != manifestSHA256 {
		return contracts.PackProtocolInstance{}, errors.New("manifest digest mismatch with install intent")
	}

	manifest, err := packprotocol.ParseManifest(req.ManifestRaw)
	if err != nil {
		return contracts.PackProtocolInstance{}, fmt.Errorf("invalid manifest: %w", err)
	}
	if manifest.PackID != req.PackID || manifest.Version != desiredVersion {
		return contracts.PackProtocolInstance{}, errors.New("manifest identity mismatch with pack record")
	}

	// 4. Verify executable exists in manifest files, sha matches, and entry is declared adapter/helper
	var executableFound bool
	for _, f := range manifest.Files {
		if f.Path == req.ExecutablePath {
			if f.SHA256 != req.ExecutableSHA256 {
				return contracts.PackProtocolInstance{}, errors.New("executable sha256 mismatch with manifest file")
			}
			executableFound = true
			break
		}
	}
	if !executableFound {
		return contracts.PackProtocolInstance{}, errors.New("executable not found in verified manifest files")
	}

	var entryRoleFound bool
	for _, e := range manifest.Entries {
		if e.Path == req.ExecutablePath && (e.Role == "adapter" || e.Role == "helper") {
			entryRoleFound = true
			break
		}
	}
	if !entryRoleFound {
		return contracts.PackProtocolInstance{}, errors.New("executable path is not declared as adapter/helper entry")
	}

	capabilitiesJSON, err := json.Marshal(manifest.Capabilities)
	if err != nil {
		return contracts.PackProtocolInstance{}, err
	}

	now := time.Now().UTC()
	nowStr := FormatTime(now)

	// Retire any active instance for this pack
	if _, err := tx.ExecContext(ctx, `UPDATE pack_protocol_instances SET retired_at=?, updated_at=? WHERE pack_id=? AND retired_at IS NULL`, nowStr, nowStr, req.PackID); err != nil {
		return contracts.PackProtocolInstance{}, err
	}

	// Allocate monotonic instance generation
	var maxGen sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT max(instance_generation) FROM pack_protocol_instances WHERE pack_id=?`, req.PackID).Scan(&maxGen); err != nil {
		return contracts.PackProtocolInstance{}, err
	}
	nextGen := int64(1)
	if maxGen.Valid {
		nextGen = maxGen.Int64 + 1
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO pack_protocol_instances (
			pack_id, operation_id, instance_id, instance_generation,
			installation_binding, manifest_sha256, executable_sha256, executable_path,
			protocol_version, capabilities, expected_uid, expected_pid,
			process_start_identity, socket_path, core_generation, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '1.0', ?, ?, ?, ?, ?, ?, ?, ?)
	`, req.PackID, req.OperationID, req.InstanceID, nextGen,
		installationBinding, manifestSHA256, req.ExecutableSHA256, req.ExecutablePath,
		string(capabilitiesJSON), req.ExpectedUID, req.ExpectedPID,
		req.ProcessStartTime, req.SocketPath, s.coreGeneration, nowStr, nowStr)
	if err != nil {
		return contracts.PackProtocolInstance{}, err
	}

	if err := tx.Commit(); err != nil {
		return contracts.PackProtocolInstance{}, fmt.Errorf("%w: register pack protocol instance: %v", ErrOutcomeUnknown, err)
	}

	return contracts.PackProtocolInstance{
		InstanceID:          req.InstanceID,
		PackID:              req.PackID,
		Version:             desiredVersion,
		OperationID:         req.OperationID,
		InstallationBinding: installationBinding,
		ManifestSHA256:      manifestSHA256,
		ExecutableSHA256:    req.ExecutableSHA256,
		ExecutablePath:      req.ExecutablePath,
		ProtocolVersion:     "1.0",
		Capabilities:        manifest.Capabilities,
		ExpectedUID:         req.ExpectedUID,
		ExpectedPID:         req.ExpectedPID,
		ProcessStartTime:    req.ProcessStartTime,
		SocketPath:          req.SocketPath,
		CoreGeneration:      s.coreGeneration,
		InstanceGeneration:  nextGen,
		CreatedAt:           now,
		UpdatedAt:           now,
	}, nil
}

func (s *Store) BeginPackProtocolCheck(ctx context.Context, req contracts.BeginPackProtocolCheckRequest) (contracts.BeginPackProtocolCheckResult, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.BeginPackProtocolCheckResult{}, err
	}
	if !packprotocol.ValidPackID(req.PackID) || req.OperationID == "" || req.InstanceID == "" || strings.TrimSpace(req.IdempotencyKey) != req.IdempotencyKey || req.IdempotencyKey == "" {
		return contracts.BeginPackProtocolCheckResult{}, errors.New("invalid begin pack protocol check parameters")
	}
	if req.Kind != packprotocol.KindDiagnosticObserve {
		return contracts.BeginPackProtocolCheckResult{}, errors.New("unsupported task kind for protocol check")
	}
	if req.Capability != packprotocol.CapabilityDiagnosticObserve {
		return contracts.BeginPackProtocolCheckResult{}, errors.New("unsupported capability for protocol check")
	}
	if err := validateAuditContext(req.Audit); err != nil {
		return contracts.BeginPackProtocolCheckResult{}, err
	}

	inputDigest, inputBytes, err := packprotocol.DigestDiagnosticInput(req.InputContext)
	if err != nil {
		return contracts.BeginPackProtocolCheckResult{}, err
	}

	// Bind normalized complete caller intent into the idempotency request digest
	h := sha256.New()
	fmt.Fprintf(h, "pack:%s\nop:%s\ninst:%s\nkind:%s\ncap:%s\ninput:%s\n",
		req.PackID, req.OperationID, req.InstanceID, req.Kind, req.Capability, inputDigest)
	normalizedRequestDigest := hex.EncodeToString(h.Sum(nil))

	taskID, err := domain.NewID("task")
	if err != nil {
		return contracts.BeginPackProtocolCheckResult{}, err
	}
	auditID, err := domain.NewID("audit")
	if err != nil {
		return contracts.BeginPackProtocolCheckResult{}, err
	}

	now := time.Now().UTC()
	nowStr := FormatTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return contracts.BeginPackProtocolCheckResult{}, err
	}
	defer tx.Rollback()

	// 1. Idempotency reservation with normalized intent digest
	res, err := tx.ExecContext(ctx, `
		INSERT INTO idempotency_records (scope, idempotency_key, request_digest, status, created_at, updated_at)
		VALUES (?, ?, ?, 'in_progress', ?, ?)
		ON CONFLICT(scope, idempotency_key) DO NOTHING
	`, packCheckScope, req.IdempotencyKey, normalizedRequestDigest, nowStr, nowStr)
	if err != nil {
		return contracts.BeginPackProtocolCheckResult{}, err
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return contracts.BeginPackProtocolCheckResult{}, err
	}
	if rowsAffected == 0 {
		var storedDigest, status string
		var storedResponse sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT request_digest, status, response FROM idempotency_records WHERE scope=? AND idempotency_key=?`, packCheckScope, req.IdempotencyKey).Scan(&storedDigest, &status, &storedResponse)
		if err != nil {
			return contracts.BeginPackProtocolCheckResult{}, ErrIdempotencyCorrupt
		}
		if storedDigest != normalizedRequestDigest {
			return contracts.BeginPackProtocolCheckResult{}, ErrIdempotencyConflict
		}
		if status != "completed" || !storedResponse.Valid {
			return contracts.BeginPackProtocolCheckResult{}, ErrIdempotencyInProgress
		}
		return decodeCheckResult([]byte(storedResponse.String))
	}

	// 2. Validate instance identity, Core generation, capabilities, and active status
	var instPackID, instOpID, capsJSON string
	var instGen, instCoreGen int64
	var retiredAt sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT pack_id, operation_id, instance_generation, core_generation, capabilities, retired_at
		FROM pack_protocol_instances
		WHERE instance_id=?
	`, req.InstanceID).Scan(&instPackID, &instOpID, &instGen, &instCoreGen, &capsJSON, &retiredAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return contracts.BeginPackProtocolCheckResult{}, errors.New("instance not found")
		}
		return contracts.BeginPackProtocolCheckResult{}, err
	}
	if instPackID != req.PackID || instOpID != req.OperationID {
		return contracts.BeginPackProtocolCheckResult{}, errors.New("instance does not match pack or operation")
	}
	if instCoreGen != s.coreGeneration {
		return contracts.BeginPackProtocolCheckResult{}, errors.New("instance belongs to an older core generation")
	}
	if retiredAt.Valid {
		return contracts.BeginPackProtocolCheckResult{}, errors.New("instance is retired")
	}

	// Verify capability is present in instance capabilities
	var capabilities []string
	if err := json.Unmarshal([]byte(capsJSON), &capabilities); err != nil {
		return contracts.BeginPackProtocolCheckResult{}, fmt.Errorf("corrupt instance capabilities: %w", err)
	}
	capFound := false
	for _, c := range capabilities {
		if c == req.Capability {
			capFound = true
			break
		}
	}
	if !capFound {
		return contracts.BeginPackProtocolCheckResult{}, errors.New("capability not permitted for this instance")
	}

	// 3. Validate parent install operation is still active and unmodified
	var opState string
	err = tx.QueryRowContext(ctx, `SELECT state FROM operations WHERE id=? AND target_kind='pack' AND pack_id=?`, req.OperationID, req.PackID).Scan(&opState)
	if err != nil {
		return contracts.BeginPackProtocolCheckResult{}, errors.New("parent install operation not found")
	}
	if opState != "pending" && opState != "leased" && opState != "running" && opState != "waiting" {
		return contracts.BeginPackProtocolCheckResult{}, errors.New("parent install operation is terminal")
	}

	// 4. Create child task in task_leases pointing to the existing install operation
	taskPayload, _ := json.Marshal(struct {
		Kind        string `json:"kind"`
		Capability  string `json:"capability"`
		PackID      string `json:"pack_id"`
		OperationID string `json:"operation_id"`
		InstanceID  string `json:"instance_id"`
		InputDigest string `json:"input_digest"`
	}{
		Kind:        req.Kind,
		Capability:  req.Capability,
		PackID:      req.PackID,
		OperationID: req.OperationID,
		InstanceID:  req.InstanceID,
		InputDigest: inputDigest,
	})

	_, err = tx.ExecContext(ctx, `
		INSERT INTO task_leases (task_id, operation_id, state, payload, created_at, updated_at)
		VALUES (?, ?, 'ready', ?, ?, ?)
	`, taskID.String(), req.OperationID, string(taskPayload), nowStr, nowStr)
	if err != nil {
		return contracts.BeginPackProtocolCheckResult{}, err
	}

	// 5. Insert pack_protocol_checks record
	_, err = tx.ExecContext(ctx, `
		INSERT INTO pack_protocol_checks (
			task_id, operation_id, pack_id, instance_id, instance_generation,
			kind, capability, scope, idempotency_key, input_digest, input_context,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, taskID.String(), req.OperationID, req.PackID, req.InstanceID, instGen,
		req.Kind, req.Capability, packCheckScope, req.IdempotencyKey, inputDigest, string(inputBytes),
		nowStr, nowStr)
	if err != nil {
		return contracts.BeginPackProtocolCheckResult{}, err
	}

	// 6. Outbox and Audit (Audit InputDigest requires sha256: prefix, evidence refs must be safe prefixes)
	event := struct {
		SchemaVersion string `json:"schema_version"`
		TaskID        string `json:"task_id"`
		OperationID   string `json:"operation_id"`
		PackID        string `json:"pack_id"`
		Kind          string `json:"kind"`
		InputDigest   string `json:"input_digest"`
		CreatedAt     string `json:"created_at"`
	}{
		SchemaVersion: "1.1",
		TaskID:        taskID.String(),
		OperationID:   req.OperationID,
		PackID:        req.PackID,
		Kind:          "pack.check.created",
		InputDigest:   inputDigest,
		CreatedAt:     nowStr,
	}

	if _, err := appendOutboxTx(ctx, tx, contracts.OutboxEvent{
		AggregateType:    "pack_check",
		AggregateID:      taskID.String(),
		AggregateVersion: 1,
		EventType:        "pack.check.created",
		CreatedAt:        now,
		PayloadVersion:   "1.1",
	}, func(id string, cursor int64) ([]byte, error) {
		return json.Marshal(event)
	}); err != nil {
		return contracts.BeginPackProtocolCheckResult{}, err
	}

	if _, err := appendAuditTx(ctx, tx, auditInput{
		ID:           auditID.String(),
		Actor:        req.Audit,
		Action:       "pack.check.created",
		InputDigest:  "sha256:" + normalizedRequestDigest,
		Result:       "accepted",
		EvidenceRefs: []string{"pack:" + req.PackID, req.OperationID, taskID.String()},
		CreatedAt:    now,
	}); err != nil {
		return contracts.BeginPackProtocolCheckResult{}, err
	}

	// 7. Complete idempotency record
	result := contracts.BeginPackProtocolCheckResult{
		TaskID:      taskID.String(),
		OperationID: req.OperationID,
		InstanceID:  req.InstanceID,
		InputDigest: inputDigest,
		State:       contracts.TaskReady,
		CreatedAt:   now,
	}
	respBytes, _ := json.Marshal(result)
	_, err = tx.ExecContext(ctx, `
		UPDATE idempotency_records
		SET status='completed', response=?, updated_at=?
		WHERE scope=? AND idempotency_key=? AND status='in_progress'
	`, string(respBytes), nowStr, packCheckScope, req.IdempotencyKey)
	if err != nil {
		return contracts.BeginPackProtocolCheckResult{}, err
	}

	if err := tx.Commit(); err != nil {
		return contracts.BeginPackProtocolCheckResult{}, fmt.Errorf("%w: commit begin pack protocol check: %v", ErrOutcomeUnknown, err)
	}

	return result, nil
}

func (s *Store) CommitPackProtocolEvent(ctx context.Context, req contracts.CommitPackProtocolEventRequest) (contracts.PackProtocolReceipt, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.PackProtocolReceipt{}, err
	}
	if req.TaskID.String() == "" || req.InstanceID == "" || req.Owner == "" || req.Sequence == 0 || !validHexDigest(req.InputDigest) || !validHexDigest(req.EventDigest) {
		return contracts.PackProtocolReceipt{}, errors.New("invalid commit pack protocol event parameters")
	}
	if err := validateAuditContext(req.Audit); err != nil {
		return contracts.PackProtocolReceipt{}, err
	}

	// Derive and enforce terminal state consistency from observation
	var derivedTerminalState contracts.TaskState
	if req.Terminal {
		if req.TerminalStatus == "succeeded" {
			if req.Observation.Status != "healthy" && req.Observation.Status != "ok" {
				return contracts.PackProtocolReceipt{}, errors.New("terminal status succeeded requires healthy observation status")
			}
			derivedTerminalState = contracts.TaskCompleted
		} else if req.TerminalStatus == "failed" {
			if req.Observation.Status == "cancelled" {
				derivedTerminalState = contracts.TaskCancelled
			} else {
				derivedTerminalState = contracts.TaskFailed
			}
		} else {
			return contracts.PackProtocolReceipt{}, errors.New("terminal status must be succeeded or failed")
		}
		if req.TerminalState != "" && req.TerminalState != derivedTerminalState {
			return contracts.PackProtocolReceipt{}, errors.New("terminal state inconsistent with observation status")
		}
	} else {
		if req.TerminalState != "" || req.TerminalStatus != "" {
			return contracts.PackProtocolReceipt{}, errors.New("nonterminal event must not carry terminal state or status")
		}
	}

	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nowStr := FormatTime(now)

	// Validate typed observation digest and compute expected full event digest
	obsDigest, obsBytes, err := packprotocol.DigestDiagnosticObservation(req.Observation)
	if err != nil {
		return contracts.PackProtocolReceipt{}, err
	}
	occurredAtStr := packprotocol.FormatCanonicalTime(req.OccurredAt)
	expectedEventDigest := packprotocol.ComputeEventDigest(
		req.TaskID.String(), req.InstanceID,
		req.CoreGeneration, req.LeaseGeneration, req.InstanceGeneration,
		req.Sequence, req.Kind, req.InputDigest,
		req.Terminal, req.TerminalStatus, occurredAtStr, obsDigest,
	)
	if req.EventDigest != expectedEventDigest {
		return contracts.PackProtocolReceipt{}, errors.New("event digest does not match semantic fields")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return contracts.PackProtocolReceipt{}, err
	}
	defer tx.Rollback()

	// 1. Verify pack_protocol_checks binding
	var chkOpID, chkPackID, chkInstID, chkKind, chkInputDigest string
	var chkInstGen int64
	err = tx.QueryRowContext(ctx, `
		SELECT operation_id, pack_id, instance_id, instance_generation, kind, input_digest
		FROM pack_protocol_checks
		WHERE task_id=?
	`, req.TaskID.String()).Scan(&chkOpID, &chkPackID, &chkInstID, &chkInstGen, &chkKind, &chkInputDigest)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return contracts.PackProtocolReceipt{}, errors.New("pack protocol check not found")
		}
		return contracts.PackProtocolReceipt{}, err
	}
	if chkInstID != req.InstanceID {
		return contracts.PackProtocolReceipt{}, errors.New("instance mismatch with check binding")
	}
	if chkInputDigest != req.InputDigest {
		return contracts.PackProtocolReceipt{}, errors.New("input digest mismatch with check binding")
	}
	if chkKind != req.Kind {
		return contracts.PackProtocolReceipt{}, errors.New("kind mismatch with check binding")
	}
	if chkInstGen != req.InstanceGeneration {
		return contracts.PackProtocolReceipt{}, errors.New("instance generation mismatch with check binding")
	}

	// 2. Check if this exact sequence was already committed (complete semantic replay)
	var priorReceiptID, priorDigest, priorCommittedAt string
	var priorTermInt int
	var priorTermStatus sql.NullString
	var priorPayload string
	err = tx.QueryRowContext(ctx, `
		SELECT receipt_id, event_digest, terminal, terminal_status, payload, committed_at
		FROM pack_protocol_events
		WHERE task_id=? AND sequence=?
	`, req.TaskID.String(), req.Sequence).Scan(&priorReceiptID, &priorDigest, &priorTermInt, &priorTermStatus, &priorPayload, &priorCommittedAt)
	if err == nil {
		reqTermInt := 0
		if req.Terminal {
			reqTermInt = 1
		}
		if priorDigest == req.EventDigest && priorTermInt == reqTermInt && priorTermStatus.String == req.TerminalStatus && priorPayload == string(obsBytes) {
			committedTime, _ := ParseTime(priorCommittedAt)
			_ = tx.Rollback()
			return contracts.PackProtocolReceipt{
				ReceiptID:   priorReceiptID,
				TaskID:      req.TaskID.String(),
				InstanceID:  req.InstanceID,
				Sequence:    req.Sequence,
				EventDigest: priorDigest,
				CommittedAt: committedTime,
				Status:      "persisted",
			}, nil
		}
		return contracts.PackProtocolReceipt{}, errors.New("event conflict for existing sequence")
	} else if !errors.Is(err, sql.ErrNoRows) {
		return contracts.PackProtocolReceipt{}, err
	}

	// 3. Verify instance is current, not retired, and core/instance generation matches
	var instCoreGen, storedInstGen int64
	var instRetiredAt sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT core_generation, instance_generation, retired_at
		FROM pack_protocol_instances
		WHERE instance_id=?
	`, req.InstanceID).Scan(&instCoreGen, &storedInstGen, &instRetiredAt)
	if err != nil {
		return contracts.PackProtocolReceipt{}, errors.New("instance record not found")
	}
	if instCoreGen != s.coreGeneration || req.CoreGeneration != s.coreGeneration {
		return contracts.PackProtocolReceipt{}, errors.New("core generation mismatch or stale instance")
	}
	if storedInstGen != req.InstanceGeneration {
		return contracts.PackProtocolReceipt{}, errors.New("instance generation mismatch with registered instance")
	}
	if instRetiredAt.Valid {
		return contracts.PackProtocolReceipt{}, errors.New("instance is retired")
	}

	// 4. Sequence must be stored_max + 1
	var lastSeq uint64
	var taskState string
	var leaseOwner sql.NullString
	var leaseUntil sql.NullString
	var taskCoreGen, taskLeaseGen int64
	err = tx.QueryRowContext(ctx, `
		SELECT last_agent_sequence, state, lease_owner, lease_until, core_generation, lease_generation
		FROM task_leases
		WHERE task_id=?
	`, req.TaskID.String()).Scan(&lastSeq, &taskState, &leaseOwner, &leaseUntil, &taskCoreGen, &taskLeaseGen)
	if err != nil {
		return contracts.PackProtocolReceipt{}, err
	}

	if req.Sequence != lastSeq+1 {
		return contracts.PackProtocolReceipt{}, fmt.Errorf("invalid sequence: got %d, expected %d", req.Sequence, lastSeq+1)
	}

	// 5. Must hold active, unexpired lease matching owner and generations
	if taskState != string(contracts.TaskLeased) {
		return contracts.PackProtocolReceipt{}, errors.New("task is not in leased state")
	}
	if !leaseOwner.Valid || leaseOwner.String != req.Owner {
		return contracts.PackProtocolReceipt{}, errors.New("lease owner mismatch")
	}
	if taskCoreGen != req.CoreGeneration || taskLeaseGen != req.LeaseGeneration {
		return contracts.PackProtocolReceipt{}, errors.New("task generation fencing mismatch")
	}
	if !leaseUntil.Valid {
		return contracts.PackProtocolReceipt{}, errors.New("lease has no expiration")
	}
	until, err := ParseTime(leaseUntil.String)
	if err != nil {
		return contracts.PackProtocolReceipt{}, err
	}
	if !until.After(now) {
		return contracts.PackProtocolReceipt{}, errors.New("task lease expired")
	}

	// 6. Generate receipt and insert pack_protocol_events
	receiptID, err := domain.NewID("rcpt")
	if err != nil {
		return contracts.PackProtocolReceipt{}, err
	}
	auditID, err := domain.NewID("audit")
	if err != nil {
		return contracts.PackProtocolReceipt{}, err
	}

	termInt := 0
	var termStatus sql.NullString
	if req.Terminal {
		termInt = 1
		termStatus = sql.NullString{String: req.TerminalStatus, Valid: true}
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO pack_protocol_events (
			receipt_id, task_id, instance_id, core_generation, lease_generation,
			instance_generation, sequence, input_digest, event_digest, kind,
			terminal, terminal_status, payload, committed_at, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, receiptID.String(), req.TaskID.String(), req.InstanceID, req.CoreGeneration, req.LeaseGeneration,
		req.InstanceGeneration, req.Sequence, req.InputDigest, req.EventDigest, req.Kind,
		termInt, termStatus, string(obsBytes), nowStr, nowStr)
	if err != nil {
		return contracts.PackProtocolReceipt{}, err
	}

	// 7. Update task_leases: sequence, and if terminal, transition state & release lease
	if req.Terminal {
		terminalState := string(derivedTerminalState)
		_, err = tx.ExecContext(ctx, `
			UPDATE task_leases
			SET last_agent_sequence=?, state=?, lease_owner=NULL, lease_until=NULL, updated_at=?
			WHERE task_id=? AND core_generation=? AND lease_generation=? AND lease_owner=?
		`, req.Sequence, terminalState, nowStr, req.TaskID.String(), req.CoreGeneration, req.LeaseGeneration, req.Owner)
	} else {
		_, err = tx.ExecContext(ctx, `
			UPDATE task_leases
			SET last_agent_sequence=?, updated_at=?
			WHERE task_id=? AND core_generation=? AND lease_generation=? AND lease_owner=?
		`, req.Sequence, nowStr, req.TaskID.String(), req.CoreGeneration, req.LeaseGeneration, req.Owner)
	}
	if err != nil {
		return contracts.PackProtocolReceipt{}, err
	}

	// 8. Outbox and Audit
	eventPayload := struct {
		ReceiptID   string `json:"receipt_id"`
		TaskID      string `json:"task_id"`
		Sequence    uint64 `json:"sequence"`
		EventDigest string `json:"event_digest"`
		Terminal    bool   `json:"terminal"`
		Status      string `json:"status"`
	}{
		ReceiptID:   receiptID.String(),
		TaskID:      req.TaskID.String(),
		Sequence:    req.Sequence,
		EventDigest: req.EventDigest,
		Terminal:    req.Terminal,
		Status:      "persisted",
	}

	if _, err := appendOutboxTx(ctx, tx, contracts.OutboxEvent{
		AggregateType:    "pack_check",
		AggregateID:      req.TaskID.String(),
		AggregateVersion: int64(req.Sequence),
		EventType:        "pack.check.event",
		CreatedAt:        now,
		PayloadVersion:   "1.1",
	}, func(id string, cursor int64) ([]byte, error) {
		return json.Marshal(eventPayload)
	}); err != nil {
		return contracts.PackProtocolReceipt{}, err
	}

	if _, err := appendAuditTx(ctx, tx, auditInput{
		ID:           auditID.String(),
		Actor:        req.Audit,
		Action:       "pack.check.event",
		InputDigest:  "sha256:" + req.EventDigest,
		Result:       "accepted",
		EvidenceRefs: []string{req.TaskID.String(), chkOpID},
		CreatedAt:    now,
	}); err != nil {
		return contracts.PackProtocolReceipt{}, err
	}

	if err := tx.Commit(); err != nil {
		return contracts.PackProtocolReceipt{}, fmt.Errorf("%w: commit pack protocol event: %v", ErrOutcomeUnknown, err)
	}

	return contracts.PackProtocolReceipt{
		ReceiptID:   receiptID.String(),
		TaskID:      req.TaskID.String(),
		InstanceID:  req.InstanceID,
		Sequence:    req.Sequence,
		EventDigest: req.EventDigest,
		CommittedAt: now,
		Status:      "persisted",
	}, nil
}

func (s *Store) GetPackProtocolCheck(ctx context.Context, taskID domain.ID) (contracts.PackProtocolCheck, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.PackProtocolCheck{}, err
	}

	var opID, packID, instID, kind, capability, scope, idemKey, inputDigest, inputContextJSON, createdAt, updatedAt string
	var instGen int64
	var cancelReq int
	var cancelReason, cancelAt sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT operation_id, pack_id, instance_id, instance_generation,
		       kind, capability, scope, idempotency_key, input_digest, input_context,
		       cancellation_requested, cancellation_reason, cancellation_requested_at,
		       created_at, updated_at
		FROM pack_protocol_checks
		WHERE task_id=?
	`, taskID.String()).Scan(
		&opID, &packID, &instID, &instGen,
		&kind, &capability, &scope, &idemKey, &inputDigest, &inputContextJSON,
		&cancelReq, &cancelReason, &cancelAt,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return contracts.PackProtocolCheck{}, err
	}

	var inputCtx contracts.DiagnosticInputContext
	_ = json.Unmarshal([]byte(inputContextJSON), &inputCtx)

	createdTime, _ := ParseTime(createdAt)
	updatedTime, _ := ParseTime(updatedAt)
	var cancelTime *time.Time
	if cancelAt.Valid {
		t, e := ParseTime(cancelAt.String)
		if e == nil {
			cancelTime = &t
		}
	}

	opDomainID := domain.ID(opID)

	return contracts.PackProtocolCheck{
		TaskID:                  taskID,
		OperationID:             opDomainID,
		PackID:                  packID,
		InstanceID:              instID,
		InstanceGeneration:      instGen,
		Kind:                    kind,
		Capability:              capability,
		Scope:                   scope,
		IdempotencyKey:          idemKey,
		InputDigest:             inputDigest,
		InputContext:            inputCtx,
		CancellationRequested:   cancelReq == 1,
		CancellationReason:      cancelReason.String,
		CancellationRequestedAt: cancelTime,
		CreatedAt:               createdTime,
		UpdatedAt:               updatedTime,
	}, nil
}

func (s *Store) RequestPackProtocolCancellation(ctx context.Context, taskID domain.ID, reason string) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	now := time.Now().UTC()
	nowStr := FormatTime(now)

	res, err := s.db.ExecContext(ctx, `
		UPDATE pack_protocol_checks
		SET cancellation_requested=1, cancellation_reason=?, cancellation_requested_at=?, updated_at=?
		WHERE task_id=?
	`, reason, nowStr, nowStr, taskID.String())
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("check task not found for cancellation")
	}
	return nil
}

func (s *Store) AuthorizePackProtocolDispatch(ctx context.Context, req contracts.AuthorizePackProtocolDispatchRequest) (contracts.PackProtocolDispatchAuthorization, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.PackProtocolDispatchAuthorization{}, err
	}
	if req.TaskID.String() == "" || req.InstanceID == "" || req.Owner == "" || req.CoreGeneration <= 0 || req.LeaseGeneration <= 0 {
		return contracts.PackProtocolDispatchAuthorization{}, errors.New("invalid authorization dispatch parameters")
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// 1. Query check facts
	var opID, packID, instID, kind, capability, inputDigest, inputContextJSON string
	var chkInstGen int64
	err := s.db.QueryRowContext(ctx, `
		SELECT operation_id, pack_id, instance_id, instance_generation, kind, capability, input_digest, input_context
		FROM pack_protocol_checks
		WHERE task_id=?
	`, req.TaskID.String()).Scan(&opID, &packID, &instID, &chkInstGen, &kind, &capability, &inputDigest, &inputContextJSON)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return contracts.PackProtocolDispatchAuthorization{}, errors.New("pack protocol check not found")
		}
		return contracts.PackProtocolDispatchAuthorization{}, err
	}

	if instID != req.InstanceID {
		return contracts.PackProtocolDispatchAuthorization{}, errors.New("dispatch instance mismatch with check")
	}
	if kind != packprotocol.KindDiagnosticObserve || capability != packprotocol.CapabilityDiagnosticObserve {
		return contracts.PackProtocolDispatchAuthorization{}, errors.New("unauthorized check task kind or capability")
	}

	// 2. Query task lease facts directly from task_leases
	var taskState string
	var leaseOwner, leaseUntil sql.NullString
	var taskCoreGen, taskLeaseGen int64
	var taskPayload string
	err = s.db.QueryRowContext(ctx, `
		SELECT state, lease_owner, lease_until, core_generation, lease_generation, payload
		FROM task_leases
		WHERE task_id=?
	`, req.TaskID.String()).Scan(&taskState, &leaseOwner, &leaseUntil, &taskCoreGen, &taskLeaseGen, &taskPayload)
	if err != nil {
		return contracts.PackProtocolDispatchAuthorization{}, err
	}

	if taskState != string(contracts.TaskLeased) {
		return contracts.PackProtocolDispatchAuthorization{}, errors.New("task is not currently leased")
	}
	if !leaseOwner.Valid || leaseOwner.String != req.Owner {
		return contracts.PackProtocolDispatchAuthorization{}, errors.New("task lease owner mismatch")
	}
	if taskCoreGen != s.coreGeneration || req.CoreGeneration != s.coreGeneration {
		return contracts.PackProtocolDispatchAuthorization{}, errors.New("task core generation mismatch with store")
	}
	if taskLeaseGen != req.LeaseGeneration {
		return contracts.PackProtocolDispatchAuthorization{}, errors.New("task lease generation mismatch")
	}
	if !leaseUntil.Valid {
		return contracts.PackProtocolDispatchAuthorization{}, errors.New("task lease expiration missing")
	}
	until, err := ParseTime(leaseUntil.String)
	if err != nil {
		return contracts.PackProtocolDispatchAuthorization{}, err
	}
	if !until.After(now) {
		return contracts.PackProtocolDispatchAuthorization{}, errors.New("task lease is expired")
	}

	var payloadObj struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal([]byte(taskPayload), &payloadObj); err == nil {
		if payloadObj.Kind == PackInstallTaskKind {
			return contracts.PackProtocolDispatchAuthorization{}, errors.New("cannot dispatch core pack install task as protocol check")
		}
	}

	// 3. Query instance facts directly from pack_protocol_instances
	var instCoreGen, storedInstGen int64
	var expectedUID uint32
	var expectedPID int32
	var procStartTime, exeSHA, socketPath, capsJSON string
	var retiredAt sql.NullString
	err = s.db.QueryRowContext(ctx, `
		SELECT core_generation, instance_generation, expected_uid, expected_pid,
		       process_start_identity, executable_sha256, socket_path, capabilities, retired_at
		FROM pack_protocol_instances
		WHERE instance_id=?
	`, req.InstanceID).Scan(
		&instCoreGen, &storedInstGen, &expectedUID, &expectedPID,
		&procStartTime, &exeSHA, &socketPath, &capsJSON, &retiredAt,
	)
	if err != nil {
		return contracts.PackProtocolDispatchAuthorization{}, errors.New("instance record not found")
	}

	if instCoreGen != s.coreGeneration {
		return contracts.PackProtocolDispatchAuthorization{}, errors.New("instance core generation mismatch with store")
	}
	if storedInstGen != chkInstGen {
		return contracts.PackProtocolDispatchAuthorization{}, errors.New("instance generation mismatch with check binding")
	}
	if retiredAt.Valid {
		return contracts.PackProtocolDispatchAuthorization{}, errors.New("instance is retired")
	}

	var capabilities []string
	if err := json.Unmarshal([]byte(capsJSON), &capabilities); err != nil {
		return contracts.PackProtocolDispatchAuthorization{}, fmt.Errorf("corrupt instance capabilities: %w", err)
	}
	capPermitted := false
	for _, c := range capabilities {
		if c == capability {
			capPermitted = true
			break
		}
	}
	if !capPermitted {
		return contracts.PackProtocolDispatchAuthorization{}, errors.New("instance does not have required capability")
	}

	var inputCtx contracts.DiagnosticInputContext
	_ = json.Unmarshal([]byte(inputContextJSON), &inputCtx)

	opDomainID := domain.ID(opID)

	return contracts.PackProtocolDispatchAuthorization{
		TaskID:             req.TaskID,
		OperationID:        opDomainID,
		PackID:             packID,
		InstanceID:         req.InstanceID,
		InstanceGeneration: storedInstGen,
		CoreGeneration:     taskCoreGen,
		LeaseGeneration:    taskLeaseGen,
		LeaseOwner:         req.Owner,
		LeaseUntil:         until,
		Kind:               kind,
		Capability:         capability,
		InputDigest:        inputDigest,
		InputContext:       inputCtx,
		SocketPath:         socketPath,
		ExpectedPID:        expectedPID,
		ExpectedUID:        expectedUID,
		ExecutableSHA256:   exeSHA,
		ProcessStartTime:   procStartTime,
	}, nil
}
