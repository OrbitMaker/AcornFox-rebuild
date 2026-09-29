package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	contracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/packprotocol"
)

var _ contracts.PackLifecycleRepository = (*Store)(nil)

type taskLeaseFencing struct {
	OperationID     string
	TaskID          string
	CoreGeneration  int64
	LeaseGeneration int64
	OwnerID         string
}

func (s *Store) verifyPackLifecycleTaskLeaseTx(ctx context.Context, tx *sql.Tx, f taskLeaseFencing, now time.Time) (string, error) {
	if f.OperationID == "" || f.TaskID == "" || f.OwnerID == "" || f.CoreGeneration <= 0 || f.LeaseGeneration <= 0 {
		return "", errors.New("positive caller tokens, task id and owner are required")
	}

	// 1. Verify Store Core generation
	if s.coreGeneration != f.CoreGeneration {
		return "", errors.New("core generation mismatch or stale instance")
	}
	var dbCoreGen int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM core_generation WHERE singleton=1`).Scan(&dbCoreGen); err != nil {
		return "", err
	}
	if dbCoreGen != f.CoreGeneration {
		return "", errors.New("core generation mismatch or stale instance")
	}

	// 2. Query exact task lease
	var opID, state string
	var owner, untilStr sql.NullString
	var taskCoreGen, taskLeaseGen int64
	var payloadStr string
	err := tx.QueryRowContext(ctx, `
		SELECT operation_id, state, lease_owner, lease_until, core_generation, lease_generation, payload
		  FROM task_leases
		 WHERE task_id=?
	`, f.TaskID).Scan(&opID, &state, &owner, &untilStr, &taskCoreGen, &taskLeaseGen, &payloadStr)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("task lease not found")
	}
	if err != nil {
		return "", err
	}

	if opID != f.OperationID {
		return "", errors.New("task operation mismatch")
	}
	if taskCoreGen != f.CoreGeneration {
		return "", errors.New("core generation mismatch or stale instance")
	}
	if taskLeaseGen != f.LeaseGeneration || !owner.Valid || owner.String != f.OwnerID {
		return "", errors.New("lease generation mismatch or stale lease")
	}
	if state != "leased" && state != "running" {
		return "", fmt.Errorf("task not in leased or running state: %s", state)
	}

	if !untilStr.Valid {
		return "", errors.New("task lease has no deadline")
	}
	until, err := ParseTime(untilStr.String)
	if err != nil {
		return "", fmt.Errorf("parse lease deadline: %w", err)
	}
	if !until.After(now) {
		return "", errors.New("task lease expired")
	}

	var payload struct {
		Kind        string `json:"kind"`
		OperationID string `json:"operation_id"`
		PackID      string `json:"pack_id"`
	}
	if err := json.Unmarshal([]byte(payloadStr), &payload); err != nil {
		return "", fmt.Errorf("corrupt task payload: %w", err)
	}
	if payload.Kind != PackInstallTaskKind || payload.OperationID != f.OperationID {
		return "", errors.New("task kind or operation binding mismatch")
	}

	return payload.PackID, nil
}

func (s *Store) RecordStageIntent(ctx context.Context, intent contracts.StageArtifactIntent) (int64, error) {
	if err := s.checkOpen(); err != nil {
		return 0, err
	}
	if intent.OperationID == "" || intent.TaskID == "" || intent.PackID == "" || intent.Version == "" ||
		len(intent.PlanSHA256) != 64 || intent.StageDirectory == "" ||
		len(intent.AuthorityCatalogSHA256) != 64 || intent.AuthoritySequence <= 0 {
		return 0, errors.New("invalid stage artifact intent")
	}
	if err := validateAuditContext(intent.Audit); err != nil {
		return 0, err
	}

	now := time.Now().UTC()
	nowStr := FormatTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// 1. Task fencing guard
	taskPackID, err := s.verifyPackLifecycleTaskLeaseTx(ctx, tx, taskLeaseFencing{
		OperationID:     intent.OperationID,
		TaskID:          intent.TaskID,
		CoreGeneration:  intent.CoreGeneration,
		LeaseGeneration: intent.LeaseGeneration,
		OwnerID:         intent.OwnerID,
	}, now)
	if err != nil {
		return 0, err
	}
	if taskPackID != intent.PackID {
		return 0, errors.New("task pack id mismatch")
	}

	// 2. Validate against immutable intent and pack record
	var plannedPackID, plannedVersion, plannedPlanSHA, opState string
	err = tx.QueryRowContext(ctx, `
		SELECT i.pack_id, i.version, i.plan_sha256, o.state
		  FROM pack_install_intents i
		  JOIN operations o ON i.operation_id = o.id
		 WHERE i.operation_id=?
	`, intent.OperationID).Scan(&plannedPackID, &plannedVersion, &plannedPlanSHA, &opState)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errors.New("planned pack intent not found")
	}
	if err != nil {
		return 0, err
	}

	if intent.PackID != plannedPackID || intent.Version != plannedVersion || intent.PlanSHA256 != plannedPlanSHA {
		return 0, errors.New("intent target does not match planned operation")
	}

	// 3. Validate authority matches registered trust materials, check sequence floor, and derive expiry
	var matCatalogSHA, matEnvelopeStr string
	var matCatSeq int64
	err = tx.QueryRowContext(ctx, `
		SELECT catalog_sha256, catalog_sequence, catalog_envelope
		  FROM pack_trust_materials
		 WHERE operation_id=? AND authority_sequence=?
	`, intent.OperationID, intent.AuthoritySequence).Scan(&matCatalogSHA, &matCatSeq, &matEnvelopeStr)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errors.New("authority material not found for sequence")
	}
	if err != nil {
		return 0, err
	}
	if matCatalogSHA != intent.AuthorityCatalogSHA256 {
		return 0, errors.New("authority catalog sha256 mismatch")
	}

	var maxAcceptedSeq int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(catalog_sequence), 0) FROM pack_trust_materials WHERE operation_id=?`, intent.OperationID).Scan(&maxAcceptedSeq); err != nil {
		return 0, err
	}
	if matCatSeq < maxAcceptedSeq {
		return 0, errors.New("cannot stage with superseded authority: catalog sequence is below accepted floor")
	}

	var env packprotocol.CatalogEnvelope
	if err := json.Unmarshal([]byte(matEnvelopeStr), &env); err != nil {
		return 0, errors.New("corrupt catalog envelope in trust materials")
	}
	payRaw, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if err != nil {
		return 0, errors.New("corrupt payload in catalog envelope")
	}
	var catPay packprotocol.CatalogPayload
	if err := json.Unmarshal(payRaw, &catPay); err != nil {
		return 0, errors.New("corrupt catalog payload in trust materials")
	}
	parsedExpires, err := time.Parse(time.RFC3339Nano, catPay.ExpiresAt)
	if err != nil {
		return 0, errors.New("corrupt expires_at in catalog payload")
	}
	if !now.Before(parsedExpires) {
		return 0, errors.New("catalog authority is expired")
	}
	expiresStr := FormatTime(parsedExpires)

	// 4. Update or insert journal
	var existingID, existingPhase, existingStageDir string
	var existingRev int64
	err = tx.QueryRowContext(ctx, `
		SELECT journal_id, phase, stage_directory, revision
		  FROM pack_lifecycle_journal
		 WHERE operation_id=?
	`, intent.OperationID).Scan(&existingID, &existingPhase, &existingStageDir, &existingRev)

	var nextRev int64
	if errors.Is(err, sql.ErrNoRows) {
		journalID, err := domain.NewID("jnl")
		if err != nil {
			return 0, err
		}
		nextRev = 1
		_, err = tx.ExecContext(ctx, `
			INSERT INTO pack_lifecycle_journal (
				journal_id, operation_id, pack_id, version, plan_sha256, phase, revision,
				core_generation, lease_generation, owner_id, stage_directory,
				authority_catalog_sha256, authority_sequence, authority_expires_at,
				created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, 'staging', 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, journalID.String(), intent.OperationID, intent.PackID, intent.Version, intent.PlanSHA256,
			intent.CoreGeneration, intent.LeaseGeneration, intent.OwnerID, intent.StageDirectory,
			intent.AuthorityCatalogSHA256, intent.AuthoritySequence, expiresStr,
			nowStr, nowStr)
		if err != nil {
			return 0, err
		}
	} else if err != nil {
		return 0, err
	} else {
		if existingPhase == "verified" {
			_ = tx.Rollback()
			return existingRev, nil
		}
		if existingStageDir != intent.StageDirectory {
			return 0, errors.New("stage directory location is immutable for operation")
		}
		nextRev = existingRev + 1
		res, err := tx.ExecContext(ctx, `
			UPDATE pack_lifecycle_journal
			   SET phase='staging',
			       core_generation=?,
			       lease_generation=?,
			       owner_id=?,
			       authority_catalog_sha256=?,
			       authority_sequence=?,
			       authority_expires_at=?,
			       failure_reason=NULL,
			       revision=?,
			       updated_at=?
			 WHERE operation_id=? AND revision=?
		`, intent.CoreGeneration, intent.LeaseGeneration, intent.OwnerID,
			intent.AuthorityCatalogSHA256, intent.AuthoritySequence, expiresStr,
			nextRev, nowStr, intent.OperationID, existingRev)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil || n != 1 {
			return 0, errors.New("lifecycle journal revision conflict")
		}
	}

	// 5. Append audit
	auditID, err := domain.NewID("audit")
	if err != nil {
		return 0, err
	}
	if _, err := appendAuditTx(ctx, tx, auditInput{
		ID:           auditID.String(),
		Actor:        intent.Audit,
		Action:       "pack.stage.initiated",
		InputDigest:  "sha256:" + intent.AuthorityCatalogSHA256,
		Result:       "accepted",
		EvidenceRefs: []string{"pack:" + intent.PackID, intent.OperationID, intent.TaskID},
		CreatedAt:    now,
	}); err != nil {
		return 0, err
	}

	// 6. Append outbox
	event := contracts.PackEvent{
		SchemaVersion: "1.1",
		OperationID:   intent.OperationID,
		PackID:        intent.PackID,
		OccurredAt:    now,
		Kind:          "pack.stage.initiated",
		Status:        "staging",
	}
	if _, err := appendOutboxTx(ctx, tx, contracts.OutboxEvent{
		AggregateType:    "pack_operation",
		AggregateID:      intent.OperationID,
		AggregateVersion: 2,
		EventType:        event.Kind,
		CreatedAt:        now,
		PayloadVersion:   "1.1",
	}, func(id string, cursor int64) ([]byte, error) {
		event.ID = id
		event.Sequence = uint64(cursor)
		return json.Marshal(event)
	}); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("%w: commit stage intent: %v", ErrOutcomeUnknown, err)
	}
	return nextRev, nil
}

func (s *Store) CommitArtifactReceipt(ctx context.Context, record contracts.CommitArtifactReceiptRecord) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	rcpt := record.Receipt
	if record.TaskID == "" || rcpt.ReceiptID == "" || rcpt.OperationID == "" || rcpt.PackID == "" || rcpt.Version == "" ||
		len(rcpt.PlanSHA256) != 64 || len(rcpt.ArchiveSHA256) != 64 || len(rcpt.ManifestSHA256) != 64 ||
		len(rcpt.ExecutableSHA256) != 64 || rcpt.ExecutablePath == "" || len(rcpt.CatalogSHA256) != 64 ||
		rcpt.CatalogSequence <= 0 || rcpt.ArchiveSize <= 0 || rcpt.UnpackedTotalBytes <= 0 ||
		rcpt.RelativeStagePath == "" || rcpt.StageIdentity == "" || rcpt.MemberCount <= 0 {
		return errors.New("invalid commit artifact receipt record")
	}
	if err := validateAuditContext(record.Audit); err != nil {
		return err
	}

	now := time.Now().UTC()
	nowStr := FormatTime(now)
	verifiedStr := FormatTime(rcpt.VerifiedAt)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. Task fencing guard
	taskPackID, err := s.verifyPackLifecycleTaskLeaseTx(ctx, tx, taskLeaseFencing{
		OperationID:     rcpt.OperationID,
		TaskID:          record.TaskID,
		CoreGeneration:  record.CoreGeneration,
		LeaseGeneration: record.LeaseGeneration,
		OwnerID:         record.OwnerID,
	}, now)
	if err != nil {
		return err
	}
	if taskPackID != rcpt.PackID {
		return errors.New("task pack id mismatch")
	}

	// 2. Validate against immutable intent and pack records
	var plannedPackID, plannedVersion, plannedPlanSHA, pManifestSHA, pArtifactSHA string
	err = tx.QueryRowContext(ctx, `
		SELECT i.pack_id, i.version, i.plan_sha256, p.manifest_sha256, p.artifact_sha256
		  FROM pack_install_intents i
		  JOIN pack_records p ON i.pack_id = p.pack_id
		 WHERE i.operation_id=?
	`, rcpt.OperationID).Scan(&plannedPackID, &plannedVersion, &plannedPlanSHA, &pManifestSHA, &pArtifactSHA)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("planned pack intent not found")
	}
	if err != nil {
		return err
	}

	if rcpt.PackID != plannedPackID || rcpt.Version != plannedVersion || rcpt.PlanSHA256 != plannedPlanSHA {
		return errors.New("receipt does not match planned operation identity")
	}
	if rcpt.ManifestSHA256 != pManifestSHA || rcpt.ArchiveSHA256 != pArtifactSHA {
		return errors.New("receipt digests do not match frozen plan")
	}

	// 3. Check journal phase, revision, stage location, exact lease ownership, and extract staged authority
	var curPhase, curStageDir, curOwner, curJournalCatSHA string
	var curRev, curCoreGen, curLeaseGen, curJournalAuthSeq int64
	err = tx.QueryRowContext(ctx, `
		SELECT phase, stage_directory, revision, core_generation, lease_generation, owner_id,
		       authority_sequence, authority_catalog_sha256
		  FROM pack_lifecycle_journal
		 WHERE operation_id=?
	`, rcpt.OperationID).Scan(&curPhase, &curStageDir, &curRev, &curCoreGen, &curLeaseGen, &curOwner,
		&curJournalAuthSeq, &curJournalCatSHA)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("pack lifecycle journal not found")
		}
		return err
	}
	if curRev != record.ExpectedJournalRevision {
		return errors.New("lifecycle journal revision conflict")
	}
	if curPhase != "staging" {
		return fmt.Errorf("lifecycle journal invalid phase for receipt: %s", curPhase)
	}
	if curStageDir != rcpt.RelativeStagePath {
		return errors.New("receipt stage path does not match claimed journal stage path")
	}
	if curCoreGen != record.CoreGeneration || curLeaseGen != record.LeaseGeneration || curOwner != record.OwnerID {
		return errors.New("claimed journal lease or owner mismatch: requires stage mutation under current lease")
	}

	// 4. Validate authority matches the EXACT authority material staged in the journal
	var matCatalogSHA, matEnvelopeStr, matManifestStr string
	var matCatalogSeq int64
	err = tx.QueryRowContext(ctx, `
		SELECT catalog_sha256, catalog_sequence, catalog_envelope, manifest_bytes
		  FROM pack_trust_materials
		 WHERE operation_id=? AND authority_sequence=?
	`, rcpt.OperationID, curJournalAuthSeq).Scan(&matCatalogSHA, &matCatalogSeq, &matEnvelopeStr, &matManifestStr)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("staged authority material not found in registered materials")
	}
	if err != nil {
		return err
	}
	if matCatalogSHA != curJournalCatSHA {
		return errors.New("journal authority digest mismatch with registered material")
	}
	if rcpt.CatalogSHA256 != matCatalogSHA || rcpt.CatalogSequence != matCatalogSeq {
		return errors.New("receipt catalog authority does not match journal staged authority material")
	}

	var env packprotocol.CatalogEnvelope
	if err := json.Unmarshal([]byte(matEnvelopeStr), &env); err != nil {
		return errors.New("corrupt catalog envelope in trust materials")
	}
	payRaw, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if err != nil {
		return errors.New("corrupt payload in catalog envelope")
	}
	payHash := sha256.Sum256(payRaw)
	payHashHex := hex.EncodeToString(payHash[:])
	if payHashHex != rcpt.CatalogSHA256 {
		return errors.New("catalog sha256 mismatch with verified payload")
	}

	var catPay packprotocol.CatalogPayload
	if err := json.Unmarshal(payRaw, &catPay); err != nil {
		return errors.New("corrupt catalog payload in trust materials")
	}
	if rcpt.ArchiveSize != catPay.ArtifactSize {
		return errors.New("receipt archive size does not match signed catalog artifact size")
	}

	// Validate manifest-declared inventory, executable path, executable SHA256 and total unpacked bytes
	manifestObj, err := packprotocol.ParseManifest([]byte(matManifestStr))
	if err != nil {
		return fmt.Errorf("corrupt manifest in trust materials: %w", err)
	}

	var adapterPath string
	for _, entry := range manifestObj.Entries {
		if entry.Role == "adapter" {
			adapterPath = entry.Path
			break
		}
	}
	if adapterPath == "" || adapterPath != rcpt.ExecutablePath {
		return errors.New("receipt executable path does not match manifest adapter entry")
	}

	var adapterSHA string
	var expectedTotalBytes int64 = int64(len(matManifestStr))
	for _, f := range manifestObj.Files {
		expectedTotalBytes += f.Size
		if f.Path == adapterPath {
			adapterSHA = f.SHA256
		}
	}
	if adapterSHA == "" || adapterSHA != rcpt.ExecutableSHA256 {
		return errors.New("receipt executable sha256 does not match manifest file declaration")
	}
	if rcpt.MemberCount != len(manifestObj.Files)+1 {
		return errors.New("receipt member count does not match manifest file count")
	}
	if rcpt.UnpackedTotalBytes != expectedTotalBytes {
		return errors.New("receipt unpacked total bytes does not match manifest file sizes")
	}

	// 5. Update journal to verified
	newRev := curRev + 1
	res, err := tx.ExecContext(ctx, `
		UPDATE pack_lifecycle_journal
		   SET phase='verified',
		       revision=?,
		       updated_at=?
		 WHERE operation_id=? AND revision=?
	`, newRev, nowStr, rcpt.OperationID, curRev)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return errors.New("lifecycle journal revision conflict on commit")
	}

	// 6. Insert receipt
	_, err = tx.ExecContext(ctx, `
		INSERT INTO pack_artifact_receipts (
			receipt_id, operation_id, pack_id, version, plan_sha256,
			archive_sha256, manifest_sha256, executable_sha256, executable_path,
			catalog_sha256, catalog_sequence, archive_size, unpacked_total_bytes,
			relative_stage_path, stage_identity, member_count, verified_at, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, rcpt.ReceiptID, rcpt.OperationID, rcpt.PackID, rcpt.Version, rcpt.PlanSHA256,
		rcpt.ArchiveSHA256, rcpt.ManifestSHA256, rcpt.ExecutableSHA256, rcpt.ExecutablePath,
		rcpt.CatalogSHA256, rcpt.CatalogSequence, rcpt.ArchiveSize, rcpt.UnpackedTotalBytes,
		rcpt.RelativeStagePath, rcpt.StageIdentity, rcpt.MemberCount, verifiedStr, nowStr)
	if err != nil {
		return err
	}

	// 7. Append outbox event (generated event ID is a valid evt_ ID for audit ref)
	event := contracts.PackEvent{
		SchemaVersion: "1.1",
		OperationID:   rcpt.OperationID,
		PackID:        rcpt.PackID,
		OccurredAt:    now,
		Kind:          "pack.artifact.verified",
		Status:        "verified",
	}
	outboxRes, err := appendOutboxTx(ctx, tx, contracts.OutboxEvent{
		AggregateType:    "pack_operation",
		AggregateID:      rcpt.OperationID,
		AggregateVersion: 2,
		EventType:        event.Kind,
		CreatedAt:        now,
		PayloadVersion:   "1.1",
	}, func(id string, cursor int64) ([]byte, error) {
		event.ID = id
		event.Sequence = uint64(cursor)
		return json.Marshal(event)
	})
	if err != nil {
		return err
	}

	// 8. Append audit (safe refs only: pack, op, task, evt - NO rcpt_ prefix)
	auditID, err := domain.NewID("audit")
	if err != nil {
		return err
	}
	if _, err := appendAuditTx(ctx, tx, auditInput{
		ID:           auditID.String(),
		Actor:        record.Audit,
		Action:       "pack.artifact.staged",
		InputDigest:  "sha256:" + rcpt.ArchiveSHA256,
		Result:       "verified",
		EvidenceRefs: []string{"pack:" + rcpt.PackID, rcpt.OperationID, record.TaskID, outboxRes.ID},
		CreatedAt:    now,
	}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit artifact receipt: %v", ErrOutcomeUnknown, err)
	}
	return nil
}

func (s *Store) RecordLifecycleFailure(ctx context.Context, record contracts.LifecycleFailureRecord) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if err := validateAuditContext(record.Audit); err != nil {
		return err
	}
	now := time.Now().UTC()
	nowStr := FormatTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	taskPackID, err := s.verifyPackLifecycleTaskLeaseTx(ctx, tx, taskLeaseFencing{
		OperationID:     record.OperationID,
		TaskID:          record.TaskID,
		CoreGeneration:  record.CoreGeneration,
		LeaseGeneration: record.LeaseGeneration,
		OwnerID:         record.OwnerID,
	}, now)
	if err != nil {
		return err
	}

	var curPhase string
	var curRev int64
	err = tx.QueryRowContext(ctx, `
		SELECT phase, revision
		  FROM pack_lifecycle_journal
		 WHERE operation_id=?
	`, record.OperationID).Scan(&curPhase, &curRev)
	if errors.Is(err, sql.ErrNoRows) {
		var plannedVersion, plannedPlanSHA, matEnvelopeStr string
		var matCatalogSHA string
		var matSeq int64
		_ = tx.QueryRowContext(ctx, `SELECT version, plan_sha256 FROM pack_install_intents WHERE operation_id=?`, record.OperationID).Scan(&plannedVersion, &plannedPlanSHA)
		_ = tx.QueryRowContext(ctx, `SELECT catalog_sha256, catalog_sequence, catalog_envelope FROM pack_trust_materials WHERE operation_id=? ORDER BY authority_sequence DESC LIMIT 1`, record.OperationID).Scan(&matCatalogSHA, &matSeq, &matEnvelopeStr)
		matExpiresStr := nowStr
		if matEnvelopeStr != "" {
			var env packprotocol.CatalogEnvelope
			if json.Unmarshal([]byte(matEnvelopeStr), &env) == nil {
				if raw, err := base64.StdEncoding.Strict().DecodeString(env.Payload); err == nil {
					var catPay packprotocol.CatalogPayload
					if json.Unmarshal(raw, &catPay) == nil && catPay.ExpiresAt != "" {
						if pt, err := time.Parse(time.RFC3339Nano, catPay.ExpiresAt); err == nil {
							matExpiresStr = FormatTime(pt)
						}
					}
				}
			}
		}
		if matCatalogSHA == "" {
			matCatalogSHA = strings.Repeat("0", 64)
		}
		if matSeq <= 0 {
			matSeq = 1
		}
		stageDir := "staging/" + record.OperationID
		journalID, err := domain.NewID("jnl")
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO pack_lifecycle_journal (
				journal_id, operation_id, pack_id, version, plan_sha256, phase, revision,
				core_generation, lease_generation, owner_id, stage_directory,
				authority_catalog_sha256, authority_sequence, authority_expires_at,
				failure_reason, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, 'failed', 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, journalID.String(), record.OperationID, taskPackID, plannedVersion, plannedPlanSHA,
			record.CoreGeneration, record.LeaseGeneration, record.OwnerID, stageDir,
			matCatalogSHA, matSeq, matExpiresStr, record.Reason, nowStr, nowStr)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		if curPhase == "verified" {
			return errors.New("cannot transition verified journal to failed")
		}

		newRev := curRev + 1
		res, err := tx.ExecContext(ctx, `
			UPDATE pack_lifecycle_journal
			   SET phase='failed',
			       failure_reason=?,
			       revision=?,
			       updated_at=?
			 WHERE operation_id=? AND revision=?
		`, record.Reason, newRev, nowStr, record.OperationID, curRev)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil || n != 1 {
			return errors.New("lifecycle journal revision conflict on failure")
		}
	}

	outboxRes, err := appendOutboxTx(ctx, tx, contracts.OutboxEvent{
		AggregateType:    "pack_operation",
		AggregateID:      record.OperationID,
		AggregateVersion: 2,
		EventType:        "pack.stage.failed",
		CreatedAt:        now,
		PayloadVersion:   "1.1",
	}, func(id string, cursor int64) ([]byte, error) {
		evt := contracts.PackEvent{
			SchemaVersion: "1.1",
			ID:            id,
			OperationID:   record.OperationID,
			PackID:        taskPackID,
			Sequence:      uint64(cursor),
			OccurredAt:    now,
			Kind:          "pack.stage.failed",
			Status:        "failed",
		}
		return json.Marshal(evt)
	})
	if err != nil {
		return err
	}

	auditID, err := domain.NewID("audit")
	if err != nil {
		return err
	}
	if _, err := appendAuditTx(ctx, tx, auditInput{
		ID:           auditID.String(),
		Actor:        record.Audit,
		Action:       "pack.lifecycle.failed",
		InputDigest:  "sha256:" + strings.Repeat("0", 64),
		Result:       "failed",
		EvidenceRefs: []string{"pack:" + taskPackID, record.OperationID, record.TaskID, outboxRes.ID},
		CreatedAt:    now,
	}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit lifecycle failure: %v", ErrOutcomeUnknown, err)
	}
	return nil
}

func (s *Store) RecordAuthorizationRequired(ctx context.Context, record contracts.AuthorizationRequiredRecord) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if err := validateAuditContext(record.Audit); err != nil {
		return err
	}
	now := time.Now().UTC()
	nowStr := FormatTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	taskPackID, err := s.verifyPackLifecycleTaskLeaseTx(ctx, tx, taskLeaseFencing{
		OperationID:     record.OperationID,
		TaskID:          record.TaskID,
		CoreGeneration:  record.CoreGeneration,
		LeaseGeneration: record.LeaseGeneration,
		OwnerID:         record.OwnerID,
	}, now)
	if err != nil {
		return err
	}

	var curPhase string
	var curRev int64
	err = tx.QueryRowContext(ctx, `
		SELECT phase, revision
		  FROM pack_lifecycle_journal
		 WHERE operation_id=?
	`, record.OperationID).Scan(&curPhase, &curRev)
	if errors.Is(err, sql.ErrNoRows) {
		var plannedVersion, plannedPlanSHA, matEnvelopeStr string
		var matCatalogSHA string
		var matSeq int64
		_ = tx.QueryRowContext(ctx, `SELECT version, plan_sha256 FROM pack_install_intents WHERE operation_id=?`, record.OperationID).Scan(&plannedVersion, &plannedPlanSHA)
		_ = tx.QueryRowContext(ctx, `SELECT catalog_sha256, catalog_sequence, catalog_envelope FROM pack_trust_materials WHERE operation_id=? ORDER BY authority_sequence DESC LIMIT 1`, record.OperationID).Scan(&matCatalogSHA, &matSeq, &matEnvelopeStr)
		matExpiresStr := nowStr
		if matEnvelopeStr != "" {
			var env packprotocol.CatalogEnvelope
			if json.Unmarshal([]byte(matEnvelopeStr), &env) == nil {
				if raw, err := base64.StdEncoding.Strict().DecodeString(env.Payload); err == nil {
					var catPay packprotocol.CatalogPayload
					if json.Unmarshal(raw, &catPay) == nil && catPay.ExpiresAt != "" {
						if pt, err := time.Parse(time.RFC3339Nano, catPay.ExpiresAt); err == nil {
							matExpiresStr = FormatTime(pt)
						}
					}
				}
			}
		}
		if matCatalogSHA == "" {
			matCatalogSHA = strings.Repeat("0", 64)
		}
		if matSeq <= 0 {
			matSeq = 1
		}
		stageDir := "staging/" + record.OperationID
		journalID, err := domain.NewID("jnl")
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO pack_lifecycle_journal (
				journal_id, operation_id, pack_id, version, plan_sha256, phase, revision,
				core_generation, lease_generation, owner_id, stage_directory,
				authority_catalog_sha256, authority_sequence, authority_expires_at,
				failure_reason, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, 'authorization_required', 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, journalID.String(), record.OperationID, taskPackID, plannedVersion, plannedPlanSHA,
			record.CoreGeneration, record.LeaseGeneration, record.OwnerID, stageDir,
			matCatalogSHA, matSeq, matExpiresStr, record.Reason, nowStr, nowStr)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		if curPhase == "verified" {
			return errors.New("cannot transition verified journal to authorization_required")
		}

		newRev := curRev + 1
		res, err := tx.ExecContext(ctx, `
			UPDATE pack_lifecycle_journal
			   SET phase='authorization_required',
			       failure_reason=?,
			       revision=?,
			       updated_at=?
			 WHERE operation_id=? AND revision=?
		`, record.Reason, newRev, nowStr, record.OperationID, curRev)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil || n != 1 {
			return errors.New("lifecycle journal revision conflict on authorization_required")
		}
	}

	outboxRes, err := appendOutboxTx(ctx, tx, contracts.OutboxEvent{
		AggregateType:    "pack_operation",
		AggregateID:      record.OperationID,
		AggregateVersion: 2,
		EventType:        "pack.stage.authorization_required",
		CreatedAt:        now,
		PayloadVersion:   "1.1",
	}, func(id string, cursor int64) ([]byte, error) {
		evt := contracts.PackEvent{
			SchemaVersion: "1.1",
			ID:            id,
			OperationID:   record.OperationID,
			PackID:        taskPackID,
			Sequence:      uint64(cursor),
			OccurredAt:    now,
			Kind:          "pack.stage.authorization_required",
			Status:        "action_required",
		}
		return json.Marshal(evt)
	})
	if err != nil {
		return err
	}

	auditID, err := domain.NewID("audit")
	if err != nil {
		return err
	}
	if _, err := appendAuditTx(ctx, tx, auditInput{
		ID:           auditID.String(),
		Actor:        record.Audit,
		Action:       "pack.lifecycle.authorization_required",
		InputDigest:  "sha256:" + strings.Repeat("0", 64),
		Result:       "action_required",
		EvidenceRefs: []string{"pack:" + taskPackID, record.OperationID, record.TaskID, outboxRes.ID},
		CreatedAt:    now,
	}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit authorization required: %v", ErrOutcomeUnknown, err)
	}
	return nil
}

func (s *Store) GetArtifactReceipt(ctx context.Context, operationID string) (contracts.PackArtifactReceipt, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.PackArtifactReceipt{}, err
	}
	var r contracts.PackArtifactReceipt
	var verifiedStr, createdStr string
	err := s.db.QueryRowContext(ctx, `
		SELECT receipt_id, operation_id, pack_id, version, plan_sha256,
		       archive_sha256, manifest_sha256, executable_sha256, executable_path,
		       catalog_sha256, catalog_sequence, archive_size, unpacked_total_bytes,
		       relative_stage_path, stage_identity, member_count, verified_at, created_at
		  FROM pack_artifact_receipts
		 WHERE operation_id=?
	`, operationID).Scan(&r.ReceiptID, &r.OperationID, &r.PackID, &r.Version, &r.PlanSHA256,
		&r.ArchiveSHA256, &r.ManifestSHA256, &r.ExecutableSHA256, &r.ExecutablePath,
		&r.CatalogSHA256, &r.CatalogSequence, &r.ArchiveSize, &r.UnpackedTotalBytes,
		&r.RelativeStagePath, &r.StageIdentity, &r.MemberCount, &verifiedStr, &createdStr)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.PackArtifactReceipt{}, ErrNotFound
	}
	if err != nil {
		return contracts.PackArtifactReceipt{}, err
	}
	vTime, err := ParseTime(verifiedStr)
	if err != nil {
		return contracts.PackArtifactReceipt{}, err
	}
	cTime, err := ParseTime(createdStr)
	if err != nil {
		return contracts.PackArtifactReceipt{}, err
	}
	r.VerifiedAt = vTime
	r.CreatedAt = cTime
	return r, nil
}

func (s *Store) GetPackLifecycleJournal(ctx context.Context, operationID string) (contracts.PackLifecycleJournalRecord, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.PackLifecycleJournalRecord{}, err
	}
	var r contracts.PackLifecycleJournalRecord
	var expiresStr, createdStr, updatedStr string
	var failReason sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT journal_id, operation_id, pack_id, version, plan_sha256, phase, revision,
		       core_generation, lease_generation, owner_id, stage_directory,
		       authority_catalog_sha256, authority_sequence, authority_expires_at,
		       failure_reason, created_at, updated_at
		  FROM pack_lifecycle_journal
		 WHERE operation_id=?
	`, operationID).Scan(&r.JournalID, &r.OperationID, &r.PackID, &r.Version, &r.PlanSHA256, &r.Phase, &r.Revision,
		&r.CoreGeneration, &r.LeaseGeneration, &r.OwnerID, &r.StageDirectory,
		&r.AuthorityCatalogSHA256, &r.AuthoritySequence, &expiresStr,
		&failReason, &createdStr, &updatedStr)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.PackLifecycleJournalRecord{}, ErrNotFound
	}
	if err != nil {
		return contracts.PackLifecycleJournalRecord{}, err
	}
	expTime, err := ParseTime(expiresStr)
	if err != nil {
		return contracts.PackLifecycleJournalRecord{}, err
	}
	cTime, err := ParseTime(createdStr)
	if err != nil {
		return contracts.PackLifecycleJournalRecord{}, err
	}
	uTime, err := ParseTime(updatedStr)
	if err != nil {
		return contracts.PackLifecycleJournalRecord{}, err
	}
	r.AuthorityExpiresAt = expTime
	r.CreatedAt = cTime
	r.UpdatedAt = uTime
	if failReason.Valid {
		r.FailureReason = failReason.String
	}
	return r, nil
}

func (s *Store) GetPackTrustMaterial(ctx context.Context, operationID string) (contracts.PackTrustMaterialRecord, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.PackTrustMaterialRecord{}, err
	}
	var r contracts.PackTrustMaterialRecord
	var envStr, manStr, createdStr string
	err := s.db.QueryRowContext(ctx, `
		SELECT material_id, operation_id, pack_id, version, plan_sha256,
		       catalog_sha256, catalog_sequence, manifest_sha256, artifact_sha256,
		       catalog_envelope, manifest_bytes, authority_kind, authority_sequence, created_at
		  FROM pack_trust_materials
		 WHERE operation_id=?
		 ORDER BY catalog_sequence DESC, authority_sequence DESC
		 LIMIT 1
	`, operationID).Scan(&r.MaterialID, &r.OperationID, &r.PackID, &r.Version, &r.PlanSHA256,
		&r.CatalogSHA256, &r.CatalogSequence, &r.ManifestSHA256, &r.ArtifactSHA256,
		&envStr, &manStr, &r.AuthorityKind, &r.AuthoritySequence, &createdStr)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.PackTrustMaterialRecord{}, ErrNotFound
	}
	if err != nil {
		return contracts.PackTrustMaterialRecord{}, err
	}
	cTime, err := ParseTime(createdStr)
	if err != nil {
		return contracts.PackTrustMaterialRecord{}, err
	}
	r.CatalogEnvelope = []byte(envStr)
	r.ManifestBytes = []byte(manStr)
	r.CreatedAt = cTime
	return r, nil
}

func (s *Store) ResupplyPackTrustMaterial(ctx context.Context, operationID string, selection packprotocol.VerifiedPackSelection, authorityKind string) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if authorityKind != "original_plan" && authorityKind != "renewed_catalog" {
		return errors.New("invalid authority kind")
	}

	rawEnv, rawMan, hasMat := selection.VerificationMaterial()
	if !hasMat || len(rawEnv) == 0 || len(rawMan) == 0 {
		return errors.New("unverified selection has no trust material")
	}

	binding, err := s.InstallationBinding(ctx)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if s.packCoreVersion == "" || s.packProtocolVersion == "" {
		return errors.New("explicit package compatibility configuration required")
	}
	if err := selection.Authorize(binding, s.packCoreVersion, s.packProtocolVersion, now); err != nil {
		return fmt.Errorf("resupplied selection not authorized: %w", err)
	}

	snap, _, ok := selection.Snapshot()
	if !ok {
		return errors.New("selection snapshot invalid")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var plannedPackID, plannedVersion, plannedPlanSHA, selectedIdentJSON, pManifestSHA, pArtifactSHA, pCatalogSHA string
	var pCatalogSeq int64
	err = tx.QueryRowContext(ctx, `
		SELECT i.pack_id, i.version, i.plan_sha256, i.selected_identity,
		       p.manifest_sha256, p.artifact_sha256, p.catalog_sha256, p.catalog_sequence
		  FROM pack_install_intents i
		  JOIN pack_records p ON i.pack_id = p.pack_id
		 WHERE i.operation_id=?
	`, operationID).Scan(&plannedPackID, &plannedVersion, &plannedPlanSHA, &selectedIdentJSON,
		&pManifestSHA, &pArtifactSHA, &pCatalogSHA, &pCatalogSeq)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}

	var originalSel packprotocol.Selection
	if err := json.Unmarshal([]byte(selectedIdentJSON), &originalSel); err != nil {
		return fmt.Errorf("corrupt selected identity in planned intent: %w", err)
	}

	if snap.PackID != plannedPackID || strings.TrimPrefix(snap.Version, "v") != strings.TrimPrefix(plannedVersion, "v") {
		return errors.New("resupplied selection does not match planned pack identity")
	}
	if snap.ManifestSHA256 != pManifestSHA || snap.ArtifactSHA256 != pArtifactSHA {
		return errors.New("resupplied selection does not match planned artifact digests")
	}
	if snap.Publisher != originalSel.Publisher || snap.OS != originalSel.OS || snap.Arch != originalSel.Arch ||
		snap.ArtifactSize != originalSel.ArtifactSize || snap.InstallationBinding != binding {
		return errors.New("resupplied selection does not match planned artifact identity")
	}

	if authorityKind == "original_plan" {
		if snap.CatalogSHA256 != pCatalogSHA || snap.CatalogSequence != pCatalogSeq {
			return errors.New("original_plan resupply must match planned catalog authority exactly")
		}
		var existingOrigCount int
		err := tx.QueryRowContext(ctx, `SELECT count(*) FROM pack_trust_materials WHERE operation_id=? AND authority_kind='original_plan'`, operationID).Scan(&existingOrigCount)
		if err != nil {
			return err
		}
		if existingOrigCount > 0 {
			// Idempotent resupply of original plan material
			return tx.Commit()
		}
	} else if authorityKind == "renewed_catalog" {
		// Floor and anti-equivocation check against highest sequence recorded across all sources
		var maxSeq int64
		var maxCatalogSHA string
		err = tx.QueryRowContext(ctx, `
			SELECT catalog_sequence, catalog_sha256
			  FROM (
				SELECT catalog_sequence, catalog_sha256 FROM pack_records WHERE pack_id=?
				UNION ALL
				SELECT catalog_sequence, catalog_sha256 FROM pack_trust_materials WHERE pack_id=?
				UNION ALL
				SELECT catalog_sequence, catalog_sha256 FROM pack_artifact_receipts WHERE pack_id=?
			  )
			 ORDER BY catalog_sequence DESC
			 LIMIT 1
		`, plannedPackID, plannedPackID, plannedPackID).Scan(&maxSeq, &maxCatalogSHA)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil {
			if snap.CatalogSequence < maxSeq || (snap.CatalogSequence == maxSeq && snap.CatalogSHA256 != maxCatalogSHA) {
				return errors.New("catalog rollback or equivocation on resupply")
			}
		}
	}

	var nextSeq int64
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(authority_sequence), 0) + 1 FROM pack_trust_materials WHERE operation_id=?`, operationID).Scan(&nextSeq)
	if err != nil {
		return err
	}

	matID, err := domain.NewID("mat")
	if err != nil {
		return err
	}

	nowStr := FormatTime(now)
	_, err = tx.ExecContext(ctx, `
		INSERT INTO pack_trust_materials (
			material_id, operation_id, pack_id, version, plan_sha256,
			catalog_sha256, catalog_sequence, manifest_sha256, artifact_sha256,
			catalog_envelope, manifest_bytes, authority_kind, authority_sequence, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, matID.String(), operationID, snap.PackID, snap.Version, plannedPlanSHA,
		snap.CatalogSHA256, snap.CatalogSequence, snap.ManifestSHA256, snap.ArtifactSHA256,
		string(rawEnv), string(rawMan), authorityKind, nextSeq, nowStr)
	if err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit resupplied trust material: %v", ErrOutcomeUnknown, err)
	}
	return nil
}

func (s *Store) GetPackStatus(ctx context.Context, packID string) (string, *contracts.PackArtifactReceipt, error) {
	if err := s.checkOpen(); err != nil {
		return "", nil, err
	}

	var storedState string
	err := s.db.QueryRowContext(ctx, `SELECT state FROM pack_records WHERE pack_id=?`, packID).Scan(&storedState)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, ErrNotFound
	}
	if err != nil {
		return "", nil, err
	}

	var r contracts.PackArtifactReceipt
	var verifiedStr, createdStr string
	err = s.db.QueryRowContext(ctx, `
		SELECT r.receipt_id, r.operation_id, r.pack_id, r.version, r.plan_sha256,
		       r.archive_sha256, r.manifest_sha256, r.executable_sha256, r.executable_path,
		       r.catalog_sha256, r.catalog_sequence, r.archive_size, r.unpacked_total_bytes,
		       r.relative_stage_path, r.stage_identity, r.member_count, r.verified_at, r.created_at
		  FROM pack_artifact_receipts r
		  JOIN pack_lifecycle_journal j ON r.operation_id = j.operation_id
		 WHERE r.pack_id=? AND j.phase='verified'
		 ORDER BY r.created_at DESC
		 LIMIT 1
	`, packID).Scan(&r.ReceiptID, &r.OperationID, &r.PackID, &r.Version, &r.PlanSHA256,
		&r.ArchiveSHA256, &r.ManifestSHA256, &r.ExecutableSHA256, &r.ExecutablePath,
		&r.CatalogSHA256, &r.CatalogSequence, &r.ArchiveSize, &r.UnpackedTotalBytes,
		&r.RelativeStagePath, &r.StageIdentity, &r.MemberCount, &verifiedStr, &createdStr)
	if errors.Is(err, sql.ErrNoRows) {
		return storedState, nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	vTime, err := ParseTime(verifiedStr)
	if err != nil {
		return "", nil, err
	}
	cTime, err := ParseTime(createdStr)
	if err != nil {
		return "", nil, err
	}
	r.VerifiedAt = vTime
	r.CreatedAt = cTime
	return "artifact_verified", &r, nil
}

func (s *Store) RecordActivationJournal(ctx context.Context, intent contracts.RecordActivationJournalIntent) (int64, error) {
	if err := s.checkOpen(); err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	nowStr := FormatTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	taskPackID, err := s.verifyPackLifecycleTaskLeaseTx(ctx, tx, taskLeaseFencing{
		OperationID:     intent.OperationID,
		TaskID:          intent.TaskID,
		CoreGeneration:  intent.CoreGeneration,
		LeaseGeneration: intent.LeaseGeneration,
		OwnerID:         intent.OwnerID,
	}, now)
	if err != nil {
		return 0, err
	}

	var curRev int64
	var curPhase string
	err = tx.QueryRowContext(ctx, `SELECT revision, phase FROM pack_activation_journal WHERE operation_id=?`, intent.OperationID).Scan(&curRev, &curPhase)
	if errors.Is(err, sql.ErrNoRows) {
		// First insert must have ExpectedJournalRevision == 0
		if intent.ExpectedJournalRevision != 0 {
			return 0, errors.New("initial activation journal creation requires ExpectedJournalRevision == 0")
		}
		if intent.Phase != "publishing" {
			return 0, fmt.Errorf("initial activation journal phase must be 'publishing' (got %q)", intent.Phase)
		}

		// Verify against frozen pack_install_intents
		var plannedVer, plannedPlan string
		err = tx.QueryRowContext(ctx, `SELECT version, plan_sha256 FROM pack_install_intents WHERE operation_id=? AND pack_id=?`, intent.OperationID, taskPackID).Scan(&plannedVer, &plannedPlan)
		if err != nil {
			return 0, fmt.Errorf("verify install intent: %w", err)
		}
		if plannedVer != intent.Version || plannedPlan != intent.PlanSHA256 {
			return 0, errors.New("activation journal parameters do not match persisted install intent")
		}

		// Verify artifact receipt exists
		var artRcptID string
		err = tx.QueryRowContext(ctx, `SELECT receipt_id FROM pack_artifact_receipts WHERE operation_id=? AND pack_id=? AND version=?`, intent.OperationID, taskPackID, intent.Version).Scan(&artRcptID)
		if err != nil {
			return 0, fmt.Errorf("verify artifact receipt: %w", err)
		}
		if artRcptID != intent.ArtifactReceiptID {
			return 0, errors.New("artifact receipt id mismatch")
		}

		journalID, err := domain.NewID("actjnl")
		if err != nil {
			return 0, err
		}
		var capsJSON any = nil
		if len(intent.CandidateCapabilities) > 0 {
			b, _ := json.Marshal(intent.CandidateCapabilities)
			capsJSON = string(b)
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO pack_activation_journal (
				journal_id, operation_id, pack_id, version, plan_sha256, artifact_receipt_id,
				phase, revision, core_generation, lease_generation, owner_id, publish_id,
				installed_root, unit_name, instance_id, main_pid, socket_path, process_start_identity,
				candidate_capabilities, current_pointer_effect, activation_generation, failure_reason,
				created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, journalID.String(), intent.OperationID, taskPackID, intent.Version, intent.PlanSHA256, intent.ArtifactReceiptID,
			intent.Phase, intent.CoreGeneration, intent.LeaseGeneration, intent.OwnerID, intent.PublishID,
			intent.InstalledRoot, intent.UnitName, intent.InstanceID, intent.MainPID, intent.SocketPath, intent.ProcessStartIdentity,
			capsJSON, intent.CurrentPointerEffect, intent.ActivationGeneration, intent.FailureReason, nowStr, nowStr)
		if err != nil {
			return 0, err
		}
		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("%w: commit initial activation journal: %v", ErrOutcomeUnknown, err)
		}
		return 1, nil
	} else if err != nil {
		return 0, err
	}

	// Update existing: ExpectedJournalRevision must match curRev exactly (no 0 bypass)
	if intent.ExpectedJournalRevision <= 0 || intent.ExpectedJournalRevision != curRev {
		return 0, fmt.Errorf("activation journal revision conflict: expected %d, current is %d", intent.ExpectedJournalRevision, curRev)
	}
	if intent.Phase == "active" {
		return 0, errors.New("cannot transition journal to active phase directly via RecordActivationJournal; must use CommitActivation")
	}

	// Valid phase transition edges:
	// publishing -> published -> starting -> started -> ready
	// or -> failed, or idempotent same phase
	validTransition := false
	switch curPhase {
	case "publishing":
		validTransition = (intent.Phase == "publishing" || intent.Phase == "published" || intent.Phase == "starting" || intent.Phase == "failed")
	case "published":
		validTransition = (intent.Phase == "published" || intent.Phase == "starting" || intent.Phase == "failed")
	case "starting":
		validTransition = (intent.Phase == "starting" || intent.Phase == "started" || intent.Phase == "ready" || intent.Phase == "failed")
	case "started":
		validTransition = (intent.Phase == "started" || intent.Phase == "ready" || intent.Phase == "failed")
	case "ready":
		validTransition = (intent.Phase == "ready" || intent.Phase == "failed")
	default:
		validTransition = (curPhase == intent.Phase)
	}
	if !validTransition {
		return 0, fmt.Errorf("invalid activation journal phase transition: %s -> %s", curPhase, intent.Phase)
	}

	newRev := curRev + 1
	var capsJSON any = nil
	if len(intent.CandidateCapabilities) > 0 {
		b, _ := json.Marshal(intent.CandidateCapabilities)
		capsJSON = string(b)
	}
	// Atomically adopt the verified caller tokens on crash recovery update
	res, err := tx.ExecContext(ctx, `
		UPDATE pack_activation_journal
		   SET phase=?, revision=?, core_generation=?, lease_generation=?, owner_id=?, updated_at=?,
		       instance_id=?, main_pid=?, socket_path=?, process_start_identity=?,
		       candidate_capabilities=?, current_pointer_effect=?,
		       activation_generation=?, failure_reason=?
		 WHERE operation_id=? AND revision=?
	`, intent.Phase, newRev, intent.CoreGeneration, intent.LeaseGeneration, intent.OwnerID, nowStr,
		intent.InstanceID, intent.MainPID, intent.SocketPath,
		intent.ProcessStartIdentity, capsJSON, intent.CurrentPointerEffect,
		intent.ActivationGeneration, intent.FailureReason, intent.OperationID, curRev)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return 0, errors.New("activation journal update conflict")
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("%w: commit updated activation journal: %v", ErrOutcomeUnknown, err)
	}
	return newRev, nil
}

func (s *Store) CommitActivation(ctx context.Context, record contracts.CommitActivationRecord) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if err := validateAuditContext(record.Audit); err != nil {
		return err
	}
	now := time.Now().UTC()
	nowStr := FormatTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	rcpt := record.Receipt
	taskPackID, err := s.verifyPackLifecycleTaskLeaseTx(ctx, tx, taskLeaseFencing{
		OperationID:     rcpt.OperationID,
		TaskID:          record.TaskID,
		CoreGeneration:  record.CoreGeneration,
		LeaseGeneration: record.LeaseGeneration,
		OwnerID:         record.OwnerID,
	}, now)
	if err != nil {
		return err
	}

	// 1. Verify operation is active and matches pack
	var opKind, opPackID, opState string
	err = tx.QueryRowContext(ctx, `SELECT target_kind, pack_id, state FROM operations WHERE id=?`, rcpt.OperationID).Scan(&opKind, &opPackID, &opState)
	if err != nil {
		return err
	}
	if opKind != "pack" || opPackID != taskPackID {
		return errors.New("operation does not match task pack")
	}
	if opState != "pending" && opState != "leased" && opState != "running" && opState != "waiting" {
		return errors.New("operation is not active for activation commit")
	}

	// 2. Verify artifact receipt exists and matches
	var artRcptID, artManifestSHA, artExeSHA, artExePath string
	err = tx.QueryRowContext(ctx, `SELECT receipt_id, manifest_sha256, executable_sha256, executable_path FROM pack_artifact_receipts WHERE operation_id=? AND pack_id=? AND version=?`, rcpt.OperationID, taskPackID, rcpt.Version).Scan(&artRcptID, &artManifestSHA, &artExeSHA, &artExePath)
	if err != nil {
		return fmt.Errorf("artifact receipt not found: %w", err)
	}
	if artRcptID != rcpt.ArtifactReceiptID {
		return errors.New("artifact receipt id mismatch")
	}

	var instBinding string
	err = tx.QueryRowContext(ctx, `SELECT installation_binding FROM pack_records WHERE pack_id=?`, taskPackID).Scan(&instBinding)
	if err != nil {
		return fmt.Errorf("pack record not found: %w", err)
	}

	// 3. Must have existing ready journal, exact match of all fields
	var jnl contracts.PackActivationJournalRecord
	var jnlCapsJSON sql.NullString
	var jnlPIDVal sql.NullInt64
	var jnlActGenVal sql.NullInt64
	var jnlInstID, jnlSockPath, jnlStartIdent, jnlPtrEffect, jnlFailReason sql.NullString
	var jnlCreatedStr, jnlUpdatedStr string
	err = tx.QueryRowContext(ctx, `
		SELECT journal_id, operation_id, pack_id, version, plan_sha256, artifact_receipt_id,
		       phase, revision, core_generation, lease_generation, owner_id, publish_id,
		       installed_root, unit_name, instance_id, main_pid, socket_path, process_start_identity,
		       candidate_capabilities, current_pointer_effect, activation_generation, failure_reason,
		       created_at, updated_at
		  FROM pack_activation_journal
		 WHERE operation_id=?
	`, rcpt.OperationID).Scan(&jnl.JournalID, &jnl.OperationID, &jnl.PackID, &jnl.Version, &jnl.PlanSHA256, &jnl.ArtifactReceiptID,
		&jnl.Phase, &jnl.Revision, &jnl.CoreGeneration, &jnl.LeaseGeneration, &jnl.OwnerID, &jnl.PublishID,
		&jnl.InstalledRoot, &jnl.UnitName, &jnlInstID, &jnlPIDVal, &jnlSockPath, &jnlStartIdent,
		&jnlCapsJSON, &jnlPtrEffect, &jnlActGenVal, &jnlFailReason, &jnlCreatedStr, &jnlUpdatedStr)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("cannot commit activation without existing ready activation journal")
	}
	if err != nil {
		return err
	}
	if jnl.Phase != "ready" {
		return fmt.Errorf("activation journal phase must be ready to commit (got %s)", jnl.Phase)
	}
	if jnl.Revision != record.ExpectedJournalRevision {
		return errors.New("activation journal revision conflict on activation commit")
	}
	if jnl.PackID != taskPackID || rcpt.PackID != taskPackID || jnl.Version != rcpt.Version || jnl.PlanSHA256 != rcpt.PlanSHA256 ||
		jnl.ArtifactReceiptID != rcpt.ArtifactReceiptID || jnl.CoreGeneration != record.CoreGeneration ||
		jnl.LeaseGeneration != record.LeaseGeneration || jnl.OwnerID != record.OwnerID ||
		jnl.InstalledRoot != rcpt.InstalledRoot || jnl.UnitName != rcpt.UnitName ||
		rcpt.RelativeCurrentTarget != rcpt.Version || rcpt.ServiceIdentity != "systemd:"+rcpt.UnitName ||
		!jnlPtrEffect.Valid || (jnlPtrEffect.String != "created" && jnlPtrEffect.String != "existing_matched") ||
		!jnlActGenVal.Valid || jnlActGenVal.Int64 != rcpt.ActivationGeneration ||
		!jnlInstID.Valid || jnlInstID.String != rcpt.InstanceID ||
		!jnlPIDVal.Valid || int32(jnlPIDVal.Int64) != rcpt.MainPID ||
		!jnlSockPath.Valid || jnlSockPath.String != rcpt.SocketPath ||
		!jnlStartIdent.Valid || jnlStartIdent.String != rcpt.ProcessStartIdentity {
		return errors.New("activation receipt details mismatch with verified ready journal")
	}

	if !jnlCapsJSON.Valid {
		return errors.New("ready journal missing verified candidate capabilities")
	}
	var jnlCaps []string
	if err := json.Unmarshal([]byte(jnlCapsJSON.String), &jnlCaps); err != nil {
		return fmt.Errorf("unmarshal ready journal capabilities: %w", err)
	}
	if len(jnlCaps) != len(rcpt.Capabilities) {
		return errors.New("activation receipt capabilities count mismatch with ready journal")
	}
	for i, c := range jnlCaps {
		if c != rcpt.Capabilities[i] {
			return errors.New("activation receipt capabilities mismatch with ready journal")
		}
	}

	newRev := jnl.Revision + 1
	res, err := tx.ExecContext(ctx, `
		UPDATE pack_activation_journal
		   SET phase='active', revision=?, updated_at=?
		 WHERE operation_id=? AND revision=? AND phase='ready'
	`, newRev, nowStr, rcpt.OperationID, jnl.Revision)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return errors.New("activation journal update conflict on commit")
	}

	// 4. Insert pack_activation_receipts
	capsBytes, err := json.Marshal(rcpt.Capabilities)
	if err != nil {
		return err
	}
	activatedStr := FormatTime(rcpt.ActivatedAt)
	_, err = tx.ExecContext(ctx, `
		INSERT INTO pack_activation_receipts (
			receipt_id, operation_id, pack_id, version, plan_sha256, artifact_receipt_id,
			installed_root, relative_current_target, unit_name, service_identity,
			instance_id, main_pid, process_start_identity, socket_path, capabilities,
			activation_generation, activated_at, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, rcpt.ReceiptID, rcpt.OperationID, taskPackID, rcpt.Version, rcpt.PlanSHA256, rcpt.ArtifactReceiptID,
		rcpt.InstalledRoot, rcpt.RelativeCurrentTarget, rcpt.UnitName, rcpt.ServiceIdentity,
		rcpt.InstanceID, rcpt.MainPID, rcpt.ProcessStartIdentity, rcpt.SocketPath, string(capsBytes),
		rcpt.ActivationGeneration, activatedStr, nowStr)
	if err != nil {
		return err
	}

	// 5. Check pack_active_runtimes: B first-time CAS check
	var existingActiveVer, existingOpID, existingRcptID, existingInstID string
	err = tx.QueryRowContext(ctx, `SELECT active_version, operation_id, activation_receipt_id, instance_id FROM pack_active_runtimes WHERE pack_id=?`, taskPackID).Scan(&existingActiveVer, &existingOpID, &existingRcptID, &existingInstID)
	if errors.Is(err, sql.ErrNoRows) {
		// First-time activation: insert
		_, err = tx.ExecContext(ctx, `
			INSERT INTO pack_active_runtimes (
				pack_id, active_version, activation_receipt_id, operation_id,
				instance_id, unit_name, socket_path, capabilities,
				runtime_status, core_generation, last_observed_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ready', ?, ?, ?)
		`, taskPackID, rcpt.Version, rcpt.ReceiptID, rcpt.OperationID,
			rcpt.InstanceID, rcpt.UnitName, rcpt.SocketPath, string(capsBytes),
			record.CoreGeneration, nowStr, nowStr)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		// Existing active record: only exact idempotent replay of same operation, same version, same receipt and instance
		if existingOpID != rcpt.OperationID || existingActiveVer != rcpt.Version {
			return errors.New("pack already has an active version; multi-version upgrade or takeover requires TP02C")
		}
		if existingRcptID != rcpt.ReceiptID || existingInstID != rcpt.InstanceID {
			return errors.New("cannot mutate existing active runtime instance or receipt under same operation; requires TP02C")
		}
		// Exact same operation replay
		_, err = tx.ExecContext(ctx, `
			UPDATE pack_active_runtimes
			   SET runtime_status='ready', core_generation=?, last_observed_at=?, updated_at=?
			 WHERE pack_id=? AND operation_id=? AND active_version=? AND activation_receipt_id=? AND instance_id=?
		`, record.CoreGeneration, nowStr, nowStr, taskPackID, rcpt.OperationID, rcpt.Version, rcpt.ReceiptID, rcpt.InstanceID)
		if err != nil {
			return err
		}
	}

	// 5b. Register verified candidate in 0006 pack_protocol_instances
	if record.ExpectedUID == 0 {
		return errors.New("expected UID must be non-zero and verified from host helper")
	}

	var activeInstID string
	err = tx.QueryRowContext(ctx, `SELECT instance_id FROM pack_protocol_instances WHERE pack_id=? AND retired_at IS NULL`, taskPackID).Scan(&activeInstID)
	if err == nil {
		if activeInstID != rcpt.InstanceID {
			return errors.New("pack already has an active protocol instance; takeover or multi-instance retirement requires TP02C")
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	var existingInst contracts.PackProtocolInstance
	var existingCapsStr string
	var existingRetiredAt sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT instance_id, pack_id, operation_id, instance_generation,
		       installation_binding, manifest_sha256, executable_sha256, executable_path,
		       protocol_version, capabilities, expected_uid, expected_pid,
		       process_start_identity, socket_path, core_generation, retired_at
		  FROM pack_protocol_instances
		 WHERE instance_id=?
	`, rcpt.InstanceID).Scan(
		&existingInst.InstanceID, &existingInst.PackID, &existingInst.OperationID, &existingInst.InstanceGeneration,
		&existingInst.InstallationBinding, &existingInst.ManifestSHA256, &existingInst.ExecutableSHA256, &existingInst.ExecutablePath,
		&existingInst.ProtocolVersion, &existingCapsStr, &existingInst.ExpectedUID, &existingInst.ExpectedPID,
		&existingInst.ProcessStartTime, &existingInst.SocketPath, &existingInst.CoreGeneration, &existingRetiredAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		var maxInstGen sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT max(instance_generation) FROM pack_protocol_instances WHERE pack_id=?`, taskPackID).Scan(&maxInstGen); err != nil {
			return err
		}
		nextInstGen := int64(1)
		if maxInstGen.Valid {
			nextInstGen = maxInstGen.Int64 + 1
		}

		_, err = tx.ExecContext(ctx, `
			INSERT INTO pack_protocol_instances (
				pack_id, operation_id, instance_id, instance_generation,
				installation_binding, manifest_sha256, executable_sha256, executable_path,
				protocol_version, capabilities, expected_uid, expected_pid,
				process_start_identity, socket_path, core_generation, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '1.0', ?, ?, ?, ?, ?, ?, ?, ?)
		`, taskPackID, rcpt.OperationID, rcpt.InstanceID, nextInstGen,
			instBinding, artManifestSHA, artExeSHA, artExePath,
			string(capsBytes), record.ExpectedUID, rcpt.MainPID,
			rcpt.ProcessStartIdentity, rcpt.SocketPath, record.CoreGeneration, nowStr, nowStr)
		if err != nil {
			return fmt.Errorf("register pack protocol instance: %w", err)
		}
	} else if err != nil {
		return err
	} else {
		if existingRetiredAt.Valid {
			return errors.New("cannot commit activation on retired protocol instance")
		}
		if existingInst.PackID != taskPackID || existingInst.OperationID != rcpt.OperationID ||
			existingInst.ExpectedUID != record.ExpectedUID || existingInst.ExpectedPID != rcpt.MainPID ||
			existingInst.ProcessStartTime != rcpt.ProcessStartIdentity || existingInst.SocketPath != rcpt.SocketPath ||
			existingInst.InstallationBinding != instBinding || existingInst.ManifestSHA256 != artManifestSHA ||
			existingInst.ExecutableSHA256 != artExeSHA || existingInst.ExecutablePath != artExePath ||
			existingInst.CoreGeneration != record.CoreGeneration || existingCapsStr != string(capsBytes) {
			return errors.New("cannot mutate existing protocol instance fields on activation commit replay")
		}
	}

	// 6. Complete task lease with terminal semantics (clear lease_owner and lease_until)
	_, err = tx.ExecContext(ctx, `UPDATE task_leases SET state='completed', lease_owner=NULL, lease_until=NULL, updated_at=? WHERE task_id=?`, nowStr, record.TaskID)
	if err != nil {
		return err
	}

	// 7. Complete operation
	_, err = tx.ExecContext(ctx, `UPDATE operations SET state='succeeded', version=version+1, updated_at=? WHERE id=?`, nowStr, rcpt.OperationID)
	if err != nil {
		return err
	}

	// 8. Append outbox event
	event := contracts.PackEvent{
		SchemaVersion: "1.1",
		OperationID:   rcpt.OperationID,
		PackID:        taskPackID,
		OccurredAt:    now,
		Kind:          "pack.activated",
		Status:        "active",
	}
	outboxRes, err := appendOutboxTx(ctx, tx, contracts.OutboxEvent{
		AggregateType:    "pack_operation",
		AggregateID:      rcpt.OperationID,
		AggregateVersion: 2,
		EventType:        event.Kind,
		CreatedAt:        now,
		PayloadVersion:   "1.1",
	}, func(id string, cursor int64) ([]byte, error) {
		event.ID = id
		event.Sequence = uint64(cursor)
		return json.Marshal(event)
	})
	if err != nil {
		return err
	}

	// 9. Append audit
	auditID, err := domain.NewID("audit")
	if err != nil {
		return err
	}
	if _, err := appendAuditTx(ctx, tx, auditInput{
		ID:           auditID.String(),
		Actor:        record.Audit,
		Action:       "pack.activation.committed",
		InputDigest:  "sha256:" + rcpt.PlanSHA256,
		Result:       "active",
		EvidenceRefs: []string{"pack:" + taskPackID, rcpt.OperationID, record.TaskID, outboxRes.ID},
		CreatedAt:    now,
	}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit pack activation: %v", ErrOutcomeUnknown, err)
	}
	return nil
}

func (s *Store) AuthorizePackActivationAction(ctx context.Context, req contracts.AuthorizePackActivationActionRequest) (contracts.AuthorizePackActivationActionResult, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.AuthorizePackActivationActionResult{}, err
	}
	now := time.Now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return contracts.AuthorizePackActivationActionResult{}, err
	}
	defer tx.Rollback()

	// 1. Verify task lease fencing
	taskPackID, err := s.verifyPackLifecycleTaskLeaseTx(ctx, tx, taskLeaseFencing{
		OperationID:     req.OperationID,
		TaskID:          req.TaskID,
		CoreGeneration:  req.CoreGeneration,
		LeaseGeneration: req.LeaseGeneration,
		OwnerID:         req.OwnerID,
	}, now)
	if err != nil {
		return contracts.AuthorizePackActivationActionResult{}, err
	}
	if taskPackID != req.PackID {
		return contracts.AuthorizePackActivationActionResult{}, errors.New("task pack ID mismatch")
	}

	// 2. Verify target pack and frozen install intent
	var plannedVer, plannedPlan string
	err = tx.QueryRowContext(ctx, `SELECT version, plan_sha256 FROM pack_install_intents WHERE operation_id=? AND pack_id=?`, req.OperationID, req.PackID).Scan(&plannedVer, &plannedPlan)
	if err != nil {
		return contracts.AuthorizePackActivationActionResult{}, fmt.Errorf("verify install intent: %w", err)
	}
	if plannedVer != req.Version || plannedPlan != req.PlanSHA256 {
		return contracts.AuthorizePackActivationActionResult{}, errors.New("action target mismatch with persisted install intent")
	}

	// 3. Query operation state
	var opState string
	err = tx.QueryRowContext(ctx, `SELECT state FROM operations WHERE id=?`, req.OperationID).Scan(&opState)
	if err != nil {
		return contracts.AuthorizePackActivationActionResult{}, err
	}

	// 4. Action permissions by state
	switch req.Action {
	case "prepare", "publish", "start", "switch":
		if opState == "cancelling" {
			return contracts.AuthorizePackActivationActionResult{}, errors.New("action rejected: operation is cancelling")
		}
		if opState == "waiting" {
			return contracts.AuthorizePackActivationActionResult{}, errors.New("action rejected: operation is waiting")
		}
		if opState != "pending" && opState != "leased" && opState != "running" {
			return contracts.AuthorizePackActivationActionResult{}, fmt.Errorf("action rejected: operation is in %s state", opState)
		}
	case "stop", "abort":
		if opState != "cancelling" && opState != "pending" && opState != "leased" && opState != "running" {
			return contracts.AuthorizePackActivationActionResult{}, fmt.Errorf("cleanup action rejected: operation is in %s state", opState)
		}
	default:
		return contracts.AuthorizePackActivationActionResult{}, fmt.Errorf("unrecognized action: %s", req.Action)
	}

	// 5. Query task lease deadline
	var leaseUntilStr string
	err = tx.QueryRowContext(ctx, `SELECT lease_until FROM task_leases WHERE task_id=?`, req.TaskID).Scan(&leaseUntilStr)
	if err != nil {
		return contracts.AuthorizePackActivationActionResult{}, err
	}
	leaseUntil, err := ParseTime(leaseUntilStr)
	if err != nil {
		return contracts.AuthorizePackActivationActionResult{}, err
	}
	if !leaseUntil.After(now) {
		return contracts.AuthorizePackActivationActionResult{}, errors.New("task lease expired")
	}

	// 6. Check journal: all host mutations require an existing activation journal and exact positive expected revision
	var curRev int64
	var curPhase string
	err = tx.QueryRowContext(ctx, `SELECT revision, phase FROM pack_activation_journal WHERE operation_id=?`, req.OperationID).Scan(&curRev, &curPhase)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.AuthorizePackActivationActionResult{}, fmt.Errorf("host action %s requires existing activation journal", req.Action)
	} else if err != nil {
		return contracts.AuthorizePackActivationActionResult{}, err
	}
	if req.ExpectedJournalRevision <= 0 || curRev != req.ExpectedJournalRevision {
		return contracts.AuthorizePackActivationActionResult{}, fmt.Errorf("journal revision conflict: expected %d, got %d", req.ExpectedJournalRevision, curRev)
	}

	if err := tx.Commit(); err != nil {
		return contracts.AuthorizePackActivationActionResult{}, err
	}

	return contracts.AuthorizePackActivationActionResult{
		Authorized:      true,
		Deadline:        leaseUntil,
		JournalRevision: curRev,
	}, nil
}

func (s *Store) RequestPackInstallCancellation(ctx context.Context, record contracts.RequestPackInstallCancellationRecord) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if err := validateAuditContext(record.Audit); err != nil {
		return err
	}
	if record.Reason == "" {
		record.Reason = "cancellation requested"
	}
	now := time.Now().UTC()
	nowStr := FormatTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var opState, packID string
	var opVer int64
	err = tx.QueryRowContext(ctx, `SELECT state, pack_id, version FROM operations WHERE id=?`, record.OperationID).Scan(&opState, &packID, &opVer)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("operation not found")
	}
	if err != nil {
		return err
	}

	if opState == "succeeded" || opState == "failed" || opState == "cancelled" {
		return fmt.Errorf("cannot request cancellation: operation is already in terminal state %s", opState)
	}

	if opState == "cancelling" {
		return tx.Commit()
	}

	if record.ExpectedOperationVersion <= 0 || opVer != record.ExpectedOperationVersion {
		return fmt.Errorf("operation version conflict on cancel request: expected %d, got %d", record.ExpectedOperationVersion, opVer)
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE operations
		   SET state='cancelling', failure_reason=?, version=version+1, updated_at=?
		 WHERE id=? AND version=? AND state IN ('pending','leased','running','waiting')
	`, record.Reason, nowStr, record.OperationID, opVer)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return errors.New("operation cancellation CAS update failed")
	}

	event := contracts.PackEvent{
		SchemaVersion: "1.1",
		OperationID:   record.OperationID,
		PackID:        packID,
		OccurredAt:    now,
		Kind:          "pack.cancellation.requested",
		Status:        "cancelling",
	}
	outboxRes, err := appendOutboxTx(ctx, tx, contracts.OutboxEvent{
		AggregateType:    "pack_operation",
		AggregateID:      record.OperationID,
		AggregateVersion: opVer + 1,
		EventType:        event.Kind,
		CreatedAt:        now,
		PayloadVersion:   "1.1",
	}, func(id string, cursor int64) ([]byte, error) {
		event.ID = id
		event.Sequence = uint64(cursor)
		return json.Marshal(event)
	})
	if err != nil {
		return err
	}

	auditID, err := domain.NewID("audit")
	if err != nil {
		return err
	}
	if _, err := appendAuditTx(ctx, tx, auditInput{
		ID:           auditID.String(),
		Actor:        record.Audit,
		Action:       "pack.cancellation.requested",
		InputDigest:  "sha256:" + strings.Repeat("0", 64),
		Result:       "cancelling",
		EvidenceRefs: []string{"pack:" + packID, record.OperationID, outboxRes.ID},
		CreatedAt:    now,
	}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit cancellation request: %v", ErrOutcomeUnknown, err)
	}
	return nil
}

func (s *Store) CancelActivation(ctx context.Context, record contracts.CancelActivationRecord) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if err := validateAuditContext(record.Audit); err != nil {
		return err
	}
	now := time.Now().UTC()
	nowStr := FormatTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	taskPackID, err := s.verifyPackLifecycleTaskLeaseTx(ctx, tx, taskLeaseFencing{
		OperationID:     record.OperationID,
		TaskID:          record.TaskID,
		CoreGeneration:  record.CoreGeneration,
		LeaseGeneration: record.LeaseGeneration,
		OwnerID:         record.OwnerID,
	}, now)
	if err != nil {
		return err
	}

	var curRev int64
	var curPhase, curUnit, curInst sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT revision, phase, unit_name, instance_id FROM pack_activation_journal WHERE operation_id=?`, record.OperationID).Scan(&curRev, &curPhase, &curUnit, &curInst)
	if errors.Is(err, sql.ErrNoRows) {
		// NoJournal branch: permitted ONLY when no host action was ever authorized/created (no journal) AND operation is confirmed cancelling
		var opState string
		err = tx.QueryRowContext(ctx, `SELECT state FROM operations WHERE id=?`, record.OperationID).Scan(&opState)
		if err != nil {
			return err
		}
		if opState != "cancelling" {
			return fmt.Errorf("cannot cancel task with no journal when operation state is %s (must be cancelling)", opState)
		}
	} else if err != nil {
		return fmt.Errorf("read activation journal for cancel: %w", err)
	} else {
		if curPhase.String == "active" || curPhase.String == "cancelled" {
			return fmt.Errorf("cannot cancel pack activation in %s phase", curPhase.String)
		}
		if record.ExpectedJournalRevision <= 0 || curRev != record.ExpectedJournalRevision {
			return fmt.Errorf("activation journal revision conflict on cancel: expected %d, current is %d", record.ExpectedJournalRevision, curRev)
		}
		if record.AbortReceiptID == "" {
			return errors.New("cannot cancel activation without persisted helper abort receipt")
		}
		if !record.ObservedStopped || record.ObservedStoppedAt.IsZero() {
			return errors.New("cannot cancel activation without verified stop confirmation and timestamp")
		}
		if curUnit.Valid && curUnit.String != "" {
			if record.UnitName == "" || record.UnitName != curUnit.String {
				return errors.New("cancel unit name mismatch with activation journal")
			}
		}
		if curInst.Valid && curInst.String != "" {
			if record.InstanceID == "" || record.InstanceID != curInst.String {
				return errors.New("cancel instance ID mismatch with activation journal")
			}
		}

		res, err := tx.ExecContext(ctx, `
			UPDATE pack_activation_journal
			   SET phase='cancelled', failure_reason=?, revision=?, core_generation=?, lease_generation=?, owner_id=?, updated_at=?
			 WHERE operation_id=? AND revision=? AND phase NOT IN ('active', 'cancelled')
		`, record.Reason+" (abort receipt: "+record.AbortReceiptID+")", curRev+1, record.CoreGeneration, record.LeaseGeneration, record.OwnerID, nowStr, record.OperationID, curRev)
		if err != nil {
			return fmt.Errorf("update activation journal on cancel: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil || n != 1 {
			return errors.New("activation journal cancellation update conflict")
		}
	}

	_, err = tx.ExecContext(ctx, `UPDATE task_leases SET state='cancelled', lease_owner=NULL, lease_until=NULL, updated_at=? WHERE task_id=?`, nowStr, record.TaskID)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `UPDATE operations SET state='cancelled', failure_reason=?, version=version+1, updated_at=? WHERE id=?`, record.Reason, nowStr, record.OperationID)
	if err != nil {
		return err
	}

	event := contracts.PackEvent{
		SchemaVersion: "1.1",
		OperationID:   record.OperationID,
		PackID:        taskPackID,
		OccurredAt:    now,
		Kind:          "pack.activation.cancelled",
		Status:        "cancelled",
	}
	outboxRes, err := appendOutboxTx(ctx, tx, contracts.OutboxEvent{
		AggregateType:    "pack_operation",
		AggregateID:      record.OperationID,
		AggregateVersion: 2,
		EventType:        event.Kind,
		CreatedAt:        now,
		PayloadVersion:   "1.1",
	}, func(id string, cursor int64) ([]byte, error) {
		event.ID = id
		event.Sequence = uint64(cursor)
		return json.Marshal(event)
	})
	if err != nil {
		return err
	}

	auditID, err := domain.NewID("audit")
	if err != nil {
		return err
	}
	if _, err := appendAuditTx(ctx, tx, auditInput{
		ID:           auditID.String(),
		Actor:        record.Audit,
		Action:       "pack.activation.cancelled",
		InputDigest:  "sha256:" + strings.Repeat("0", 64),
		Result:       "cancelled",
		EvidenceRefs: []string{"pack:" + taskPackID, record.OperationID, record.TaskID, outboxRes.ID},
		CreatedAt:    now,
	}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit cancel activation: %v", ErrOutcomeUnknown, err)
	}
	return nil
}

func (s *Store) FailPackInstall(ctx context.Context, record contracts.FailPackInstallRecord) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if err := validateAuditContext(record.Audit); err != nil {
		return err
	}
	if record.Classification != "known_failure" && record.Classification != "waiting_authorization" && record.Classification != "waiting_reconcile" {
		return fmt.Errorf("invalid fail classification: %s", record.Classification)
	}
	now := time.Now().UTC()
	nowStr := FormatTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	taskPackID, err := s.verifyPackLifecycleTaskLeaseTx(ctx, tx, taskLeaseFencing{
		OperationID:     record.OperationID,
		TaskID:          record.TaskID,
		CoreGeneration:  record.CoreGeneration,
		LeaseGeneration: record.LeaseGeneration,
		OwnerID:         record.OwnerID,
	}, now)
	if err != nil {
		return err
	}

	var curRev int64
	var curPhase string
	err = tx.QueryRowContext(ctx, `SELECT revision, phase FROM pack_activation_journal WHERE operation_id=?`, record.OperationID).Scan(&curRev, &curPhase)
	hasJournal := (err == nil)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	if record.Classification == "known_failure" {
		if hasJournal {
			if record.ExpectedJournalRevision <= 0 || curRev != record.ExpectedJournalRevision {
				return fmt.Errorf("journal revision conflict on failure: expected %d, got %d", record.ExpectedJournalRevision, curRev)
			}
			res, err := tx.ExecContext(ctx, `
				UPDATE pack_activation_journal
				   SET phase='failed', failure_reason=?, revision=?, core_generation=?, lease_generation=?, owner_id=?, updated_at=?
				 WHERE operation_id=? AND revision=?
			`, record.Reason, curRev+1, record.CoreGeneration, record.LeaseGeneration, record.OwnerID, nowStr, record.OperationID, curRev)
			if err != nil {
				return fmt.Errorf("update activation journal on failure: %w", err)
			}
			n, err := res.RowsAffected()
			if err != nil || n != 1 {
				return errors.New("activation journal update conflict on failure")
			}
		}

		_, err = tx.ExecContext(ctx, `UPDATE task_leases SET state='failed', lease_owner=NULL, lease_until=NULL, last_error=?, updated_at=? WHERE task_id=?`, record.Reason, nowStr, record.TaskID)
		if err != nil {
			return err
		}

		_, err = tx.ExecContext(ctx, `UPDATE operations SET state='failed', failure_reason=?, version=version+1, updated_at=? WHERE id=?`, record.Reason, nowStr, record.OperationID)
		if err != nil {
			return err
		}

		event := contracts.PackEvent{
			SchemaVersion: "1.1",
			OperationID:   record.OperationID,
			PackID:        taskPackID,
			OccurredAt:    now,
			Kind:          "pack.activation.failed",
			Status:        "failed",
		}
		outboxRes, err := appendOutboxTx(ctx, tx, contracts.OutboxEvent{
			AggregateType:    "pack_operation",
			AggregateID:      record.OperationID,
			AggregateVersion: 2,
			EventType:        event.Kind,
			CreatedAt:        now,
			PayloadVersion:   "1.1",
		}, func(id string, cursor int64) ([]byte, error) {
			event.ID = id
			event.Sequence = uint64(cursor)
			return json.Marshal(event)
		})
		if err != nil {
			return err
		}

		auditID, err := domain.NewID("audit")
		if err != nil {
			return err
		}
		if _, err := appendAuditTx(ctx, tx, auditInput{
			ID:           auditID.String(),
			Actor:        record.Audit,
			Action:       "pack.activation.failed",
			InputDigest:  "sha256:" + strings.Repeat("0", 64),
			Result:       "failed",
			EvidenceRefs: []string{"pack:" + taskPackID, record.OperationID, record.TaskID, outboxRes.ID},
			CreatedAt:    now,
		}); err != nil {
			return err
		}
	} else {
		// Waiting classification: "waiting_authorization" or "waiting_reconcile"
		// Transition operation to 'waiting' (or preserve 'cancelling' if already cancelling so cancellation intent survives uncertainty!)
		// Release task to 'ready' WITHOUT incrementing attempt!
		reason := fmt.Sprintf("[%s] %s", record.Classification, record.Reason)

		var curOpState string
		err = tx.QueryRowContext(ctx, `SELECT state FROM operations WHERE id=?`, record.OperationID).Scan(&curOpState)
		if err != nil {
			return err
		}
		newOpState := "waiting"
		eventKind := "pack.activation.waiting"
		eventStatus := "waiting"
		if curOpState == "cancelling" {
			newOpState = "cancelling"
			eventKind = "pack.cancellation.waiting"
			eventStatus = "cancelling"
		}

		if hasJournal {
			if record.ExpectedJournalRevision <= 0 || curRev != record.ExpectedJournalRevision {
				return fmt.Errorf("journal revision conflict on waiting: expected %d, got %d", record.ExpectedJournalRevision, curRev)
			}
			res, err := tx.ExecContext(ctx, `
				UPDATE pack_activation_journal
				   SET phase=?, failure_reason=?, revision=?, core_generation=?, lease_generation=?, owner_id=?, updated_at=?
				 WHERE operation_id=? AND revision=?
			`, curPhase, reason, curRev+1, record.CoreGeneration, record.LeaseGeneration, record.OwnerID, nowStr, record.OperationID, curRev)
			if err != nil {
				return fmt.Errorf("update activation journal on waiting: %w", err)
			}
			n, err := res.RowsAffected()
			if err != nil || n != 1 {
				return errors.New("activation journal update conflict on waiting")
			}
		}

		_, err = tx.ExecContext(ctx, `
			UPDATE task_leases
			   SET state='ready', lease_owner=NULL, lease_until=NULL, last_error=?, updated_at=?
			 WHERE task_id=?
		`, reason, nowStr, record.TaskID)
		if err != nil {
			return err
		}

		_, err = tx.ExecContext(ctx, `
			UPDATE operations
			   SET state=?, failure_reason=?, version=version+1, updated_at=?
			 WHERE id=?
		`, newOpState, reason, nowStr, record.OperationID)
		if err != nil {
			return err
		}

		event := contracts.PackEvent{
			SchemaVersion: "1.1",
			OperationID:   record.OperationID,
			PackID:        taskPackID,
			OccurredAt:    now,
			Kind:          eventKind,
			Status:        eventStatus,
		}
		outboxRes, err := appendOutboxTx(ctx, tx, contracts.OutboxEvent{
			AggregateType:    "pack_operation",
			AggregateID:      record.OperationID,
			AggregateVersion: 2,
			EventType:        event.Kind,
			CreatedAt:        now,
			PayloadVersion:   "1.1",
		}, func(id string, cursor int64) ([]byte, error) {
			event.ID = id
			event.Sequence = uint64(cursor)
			return json.Marshal(event)
		})
		if err != nil {
			return err
		}

		auditID, err := domain.NewID("audit")
		if err != nil {
			return err
		}
		if _, err := appendAuditTx(ctx, tx, auditInput{
			ID:           auditID.String(),
			Actor:        record.Audit,
			Action:       eventKind,
			InputDigest:  "sha256:" + strings.Repeat("0", 64),
			Result:       eventStatus,
			EvidenceRefs: []string{"pack:" + taskPackID, record.OperationID, record.TaskID, outboxRes.ID},
			CreatedAt:    now,
		}); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit fail/wait pack install: %v", ErrOutcomeUnknown, err)
	}
	return nil
}

func (s *Store) GetActivationJournal(ctx context.Context, operationID string) (contracts.PackActivationJournalRecord, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.PackActivationJournalRecord{}, err
	}
	var r contracts.PackActivationJournalRecord
	var instID, sockPath, startIdent, capsJSON, ptrEffect, failReason sql.NullString
	var pidVal sql.NullInt64
	var actGenVal sql.NullInt64
	var createdStr, updatedStr string
	err := s.db.QueryRowContext(ctx, `
		SELECT journal_id, operation_id, pack_id, version, plan_sha256, artifact_receipt_id,
		       phase, revision, core_generation, lease_generation, owner_id, publish_id,
		       installed_root, unit_name, instance_id, main_pid, socket_path, process_start_identity,
		       candidate_capabilities, current_pointer_effect, activation_generation, failure_reason,
		       created_at, updated_at
		  FROM pack_activation_journal
		 WHERE operation_id=?
	`, operationID).Scan(&r.JournalID, &r.OperationID, &r.PackID, &r.Version, &r.PlanSHA256, &r.ArtifactReceiptID,
		&r.Phase, &r.Revision, &r.CoreGeneration, &r.LeaseGeneration, &r.OwnerID, &r.PublishID,
		&r.InstalledRoot, &r.UnitName, &instID, &pidVal, &sockPath, &startIdent,
		&capsJSON, &ptrEffect, &actGenVal, &failReason, &createdStr, &updatedStr)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.PackActivationJournalRecord{}, ErrNotFound
	}
	if err != nil {
		return contracts.PackActivationJournalRecord{}, err
	}
	if instID.Valid {
		r.InstanceID = instID.String
	}
	if pidVal.Valid {
		r.MainPID = int32(pidVal.Int64)
	}
	if sockPath.Valid {
		r.SocketPath = sockPath.String
	}
	if startIdent.Valid {
		r.ProcessStartIdentity = startIdent.String
	}
	if capsJSON.Valid && capsJSON.String != "" {
		_ = json.Unmarshal([]byte(capsJSON.String), &r.CandidateCapabilities)
	}
	if ptrEffect.Valid {
		r.CurrentPointerEffect = ptrEffect.String
	}
	if actGenVal.Valid {
		r.ActivationGeneration = actGenVal.Int64
	}
	if failReason.Valid {
		r.FailureReason = failReason.String
	}
	cTime, err := ParseTime(createdStr)
	if err != nil {
		return contracts.PackActivationJournalRecord{}, err
	}
	uTime, err := ParseTime(updatedStr)
	if err != nil {
		return contracts.PackActivationJournalRecord{}, err
	}
	r.CreatedAt = cTime
	r.UpdatedAt = uTime
	return r, nil
}

func (s *Store) GetActivationReceipt(ctx context.Context, operationID string) (contracts.PackActivationReceipt, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.PackActivationReceipt{}, err
	}
	var r contracts.PackActivationReceipt
	var capsJSON string
	var actStr, createStr string
	err := s.db.QueryRowContext(ctx, `
		SELECT receipt_id, operation_id, pack_id, version, plan_sha256, artifact_receipt_id,
		       installed_root, relative_current_target, unit_name, service_identity,
		       instance_id, main_pid, process_start_identity, socket_path, capabilities,
		       activation_generation, activated_at, created_at
		  FROM pack_activation_receipts
		 WHERE operation_id=?
	`, operationID).Scan(&r.ReceiptID, &r.OperationID, &r.PackID, &r.Version, &r.PlanSHA256, &r.ArtifactReceiptID,
		&r.InstalledRoot, &r.RelativeCurrentTarget, &r.UnitName, &r.ServiceIdentity,
		&r.InstanceID, &r.MainPID, &r.ProcessStartIdentity, &r.SocketPath, &capsJSON,
		&r.ActivationGeneration, &actStr, &createStr)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.PackActivationReceipt{}, ErrNotFound
	}
	if err != nil {
		return contracts.PackActivationReceipt{}, err
	}
	_ = json.Unmarshal([]byte(capsJSON), &r.Capabilities)
	aTime, err := ParseTime(actStr)
	if err != nil {
		return contracts.PackActivationReceipt{}, err
	}
	cTime, err := ParseTime(createStr)
	if err != nil {
		return contracts.PackActivationReceipt{}, err
	}
	r.ActivatedAt = aTime
	r.CreatedAt = cTime
	return r, nil
}

func (s *Store) GetActiveRuntime(ctx context.Context, packID string) (contracts.PackActiveRuntimeRecord, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.PackActiveRuntimeRecord{}, err
	}
	var r contracts.PackActiveRuntimeRecord
	var capsJSON, obsStr, upStr string
	err := s.db.QueryRowContext(ctx, `
		SELECT pack_id, active_version, activation_receipt_id, operation_id,
		       instance_id, unit_name, socket_path, capabilities, runtime_status,
		       core_generation, last_observed_at, updated_at
		  FROM pack_active_runtimes
		 WHERE pack_id=?
	`, packID).Scan(&r.PackID, &r.ActiveVersion, &r.ActivationReceiptID, &r.OperationID,
		&r.InstanceID, &r.UnitName, &r.SocketPath, &capsJSON, &r.RuntimeStatus,
		&r.CoreGeneration, &obsStr, &upStr)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.PackActiveRuntimeRecord{}, ErrNotFound
	}
	if err != nil {
		return contracts.PackActiveRuntimeRecord{}, err
	}
	_ = json.Unmarshal([]byte(capsJSON), &r.Capabilities)
	oTime, err := ParseTime(obsStr)
	if err != nil {
		return contracts.PackActiveRuntimeRecord{}, err
	}
	uTime, err := ParseTime(upStr)
	if err != nil {
		return contracts.PackActiveRuntimeRecord{}, err
	}
	r.LastObservedAt = oTime
	r.UpdatedAt = uTime
	return r, nil
}

func (s *Store) ListActiveRuntimes(ctx context.Context, cursorPackID string, limit int) ([]contracts.PackActiveRuntimeRecord, error) {
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 16 {
		limit = 16
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT pack_id, active_version, activation_receipt_id, operation_id,
		       instance_id, unit_name, socket_path, capabilities, runtime_status,
		       core_generation, last_observed_at, updated_at
		  FROM pack_active_runtimes
		 WHERE pack_id > ?
		 ORDER BY pack_id ASC
		 LIMIT ?
	`, cursorPackID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []contracts.PackActiveRuntimeRecord
	for rows.Next() {
		var r contracts.PackActiveRuntimeRecord
		var capsJSON, obsStr, upStr string
		if err := rows.Scan(&r.PackID, &r.ActiveVersion, &r.ActivationReceiptID, &r.OperationID,
			&r.InstanceID, &r.UnitName, &r.SocketPath, &capsJSON, &r.RuntimeStatus,
			&r.CoreGeneration, &obsStr, &upStr); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(capsJSON), &r.Capabilities)
		oTime, err := ParseTime(obsStr)
		if err != nil {
			return nil, err
		}
		uTime, err := ParseTime(upStr)
		if err != nil {
			return nil, err
		}
		r.LastObservedAt = oTime
		r.UpdatedAt = uTime
		results = append(results, r)
	}
	return results, rows.Err()
}

func (s *Store) UpdateActiveRuntimeStatus(ctx context.Context, req contracts.UpdateActiveRuntimeStatusRequest) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if req.RuntimeStatus != "ready" && req.RuntimeStatus != "unknown" && req.RuntimeStatus != "stopped" && req.RuntimeStatus != "failed" {
		return errors.New("invalid runtime status")
	}
	if req.CoreGeneration <= 0 || req.ActivationReceiptID == "" || req.InstanceID == "" {
		return errors.New("missing required runtime identification fencing")
	}
	if req.CoreGeneration != s.coreGeneration {
		return fmt.Errorf("core generation mismatch: caller %d != store %d", req.CoreGeneration, s.coreGeneration)
	}
	now := time.Now().UTC()
	obsStr := FormatTime(req.ObservedAt)
	upStr := FormatTime(now)
	res, err := s.db.ExecContext(ctx, `
		UPDATE pack_active_runtimes
		   SET runtime_status=?, core_generation=?, last_observed_at=?, updated_at=?
		 WHERE pack_id=?
		   AND activation_receipt_id=?
		   AND instance_id=?
		   AND core_generation<=?
		   AND last_observed_at<=?
	`, req.RuntimeStatus, req.CoreGeneration, obsStr, upStr,
		req.PackID, req.ActivationReceiptID, req.InstanceID, req.CoreGeneration, obsStr)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return errors.New("active runtime status update conflict or fencing rejected")
	}
	return nil
}

func (s *Store) GetPackUnifiedStatus(ctx context.Context, packID string) (contracts.PackUnifiedStatus, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.PackUnifiedStatus{}, err
	}

	var desiredVersion string
	err := s.db.QueryRowContext(ctx, `SELECT desired_version FROM pack_records WHERE pack_id=?`, packID).Scan(&desiredVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.PackUnifiedStatus{}, ErrNotFound
	}
	if err != nil {
		return contracts.PackUnifiedStatus{}, err
	}

	status := contracts.PackUnifiedStatus{
		PackID:         packID,
		DesiredVersion: desiredVersion,
		IntentPhase:    "planned",
		ArtifactStatus: "pending",
		RuntimeReady:   false,
	}

	// 1. Check artifact receipt
	artStatus, artRcpt, err := s.GetPackStatus(ctx, packID)
	if err == nil && artRcpt != nil {
		status.ArtifactStatus = artStatus
		status.ArtifactReceipt = artRcpt
	}

	// 2. Check active runtime
	rt, err := s.GetActiveRuntime(ctx, packID)
	if err == nil {
		status.ActiveRuntime = &rt
		status.InstalledVersion = rt.ActiveVersion

		// If runtime was observed in an earlier core generation, stale (>30s), in future or not observed:
		observedAge := time.Since(rt.LastObservedAt)
		isFresh := rt.CoreGeneration == s.coreGeneration &&
			!rt.LastObservedAt.IsZero() &&
			observedAge >= 0 &&
			observedAge <= 30*time.Second

		if rt.RuntimeStatus == "ready" && isFresh {
			status.RuntimeReady = true
			status.RuntimeStatus = "ready"
		} else if rt.RuntimeStatus == "ready" && !isFresh {
			status.RuntimeReady = false
			status.RuntimeStatus = "unknown"
		} else {
			status.RuntimeReady = false
			status.RuntimeStatus = rt.RuntimeStatus
		}

		// Load activation receipt
		if actRcpt, err := s.GetActivationReceipt(ctx, rt.OperationID); err == nil {
			status.ActivationReceipt = &actRcpt
		}
	}

	return status, nil
}

func (s *Store) GetActivePackSource(ctx context.Context, packID string) (contracts.ActivePackSource, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.ActivePackSource{}, err
	}

	var src contracts.ActivePackSource
	var capsJSON, lastObsStr string
	err := s.db.QueryRowContext(ctx, `
		SELECT r.pack_id, r.active_version, r.activation_receipt_id, r.operation_id,
		       r.instance_id, i.instance_generation, r.unit_name, r.socket_path,
		       r.capabilities, r.runtime_status, r.core_generation, r.last_observed_at,
		       i.expected_uid, i.expected_pid, i.executable_sha256, i.executable_path,
		       i.process_start_identity
		  FROM pack_active_runtimes r
		  JOIN pack_activation_receipts a ON a.receipt_id = r.activation_receipt_id AND a.operation_id = r.operation_id
		  JOIN pack_protocol_instances i ON i.instance_id = r.instance_id AND i.pack_id = r.pack_id AND i.retired_at IS NULL
		 WHERE r.pack_id = ?
	`, packID).Scan(
		&src.PackID, &src.ActiveVersion, &src.ActivationReceiptID, &src.OperationID,
		&src.InstanceID, &src.InstanceGeneration, &src.UnitName, &src.SocketPath,
		&capsJSON, &src.RuntimeStatus, &src.CoreGeneration, &lastObsStr,
		&src.ExpectedUID, &src.ExpectedPID, &src.ExecutableSHA256, &src.ExecutablePath,
		&src.ProcessStartIdentity,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.ActivePackSource{}, ErrNotFound
	}
	if err != nil {
		return contracts.ActivePackSource{}, err
	}

	if err := json.Unmarshal([]byte(capsJSON), &src.Capabilities); err != nil {
		return contracts.ActivePackSource{}, fmt.Errorf("corrupt active source capabilities: %w", err)
	}
	t, err := ParseTime(lastObsStr)
	if err != nil {
		return contracts.ActivePackSource{}, fmt.Errorf("corrupt active source last_observed_at: %w", err)
	}
	src.LastObservedAt = t

	return src, nil
}

func (s *Store) ResumePackInstall(ctx context.Context, req contracts.ResumePackInstallRequest) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if err := validateAuditContext(req.Audit); err != nil {
		return err
	}
	now := time.Now().UTC()
	nowStr := FormatTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var targetKind, packID, curState string
	var curVersion int64
	err = tx.QueryRowContext(ctx, `SELECT target_kind, pack_id, state, version FROM operations WHERE id=?`, req.OperationID).Scan(&targetKind, &packID, &curState, &curVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if targetKind != "pack" || packID != req.PackID {
		return errors.New("operation pack target mismatch on resume")
	}
	if curState != "waiting" {
		return fmt.Errorf("cannot resume operation in state %q; only waiting operations can be resumed", curState)
	}
	if curVersion != req.ExpectedOperationVersion {
		return errors.New("operation version conflict on resume")
	}

	var dbGen int64
	err = tx.QueryRowContext(ctx, `SELECT generation FROM core_generation WHERE singleton=1`).Scan(&dbGen)
	if err != nil {
		return fmt.Errorf("query core generation: %w", err)
	}
	if req.CoreGeneration != s.coreGeneration || s.coreGeneration != dbGen {
		return fmt.Errorf("core generation mismatch on resume: caller %d, store %d, db %d", req.CoreGeneration, s.coreGeneration, dbGen)
	}

	// 1. Verify frozen target & plan in pack_install_intents
	var intentPackID, intentVer, intentPlanSHA string
	err = tx.QueryRowContext(ctx, `SELECT pack_id, version, plan_sha256 FROM pack_install_intents WHERE operation_id=?`, req.OperationID).Scan(&intentPackID, &intentVer, &intentPlanSHA)
	if err != nil {
		return fmt.Errorf("query install intent for resume: %w", err)
	}
	if intentPackID != req.PackID || intentVer != req.Version || intentPlanSHA != req.PlanSHA256 {
		return errors.New("frozen plan or version mismatch on resume")
	}

	// 2. Verify original task lease identity, kind, state, attempt snapshot, core/lease generation, and frozen payload
	var taskState, taskPayloadStr string
	var taskAttempt int
	var taskCoreGen, taskLeaseGen int64
	err = tx.QueryRowContext(ctx, `SELECT state, attempt, payload, core_generation, lease_generation FROM task_leases WHERE task_id=? AND operation_id=?`, req.TaskID, req.OperationID).Scan(&taskState, &taskAttempt, &taskPayloadStr, &taskCoreGen, &taskLeaseGen)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("bound original task lease not found")
	}
	if err != nil {
		return fmt.Errorf("query task for operation: %w", err)
	}
	if taskState != string(contracts.TaskReady) {
		return fmt.Errorf("bound task %s state is %s; cannot resume waiting operation", req.TaskID, taskState)
	}
	if taskAttempt != req.ExpectedTaskAttempt {
		return errors.New("task attempt snapshot mismatch on resume")
	}
	if taskCoreGen != req.ExpectedTaskCoreGeneration || taskLeaseGen != req.ExpectedTaskLeaseGeneration {
		return errors.New("task lease generations mismatch on resume")
	}

	var taskPayload struct {
		Kind        string `json:"kind"`
		PackID      string `json:"pack_id"`
		OperationID string `json:"operation_id"`
		PlanSHA256  string `json:"plan_sha256"`
	}
	if err := json.Unmarshal([]byte(taskPayloadStr), &taskPayload); err != nil {
		return fmt.Errorf("corrupt task payload on resume: %w", err)
	}
	if taskPayload.Kind != PackInstallTaskKind {
		return fmt.Errorf("bound task kind %s mismatch (expected %s)", taskPayload.Kind, PackInstallTaskKind)
	}
	if taskPayload.PackID != req.PackID || taskPayload.OperationID != req.OperationID || taskPayload.PlanSHA256 != req.PlanSHA256 {
		return errors.New("bound task payload facts mismatch on resume")
	}

	// 3. Verify current authority via Selection and authority head
	binding, err := readInstallationBinding(ctx, tx)
	if err != nil {
		return fmt.Errorf("read installation binding: %w", err)
	}
	if err := req.Selection.Authorize(binding, s.packCoreVersion, s.packProtocolVersion, now); err != nil {
		return fmt.Errorf("selection authorization invalid on resume: %w", err)
	}
	snap, _, ok := req.Selection.Snapshot()
	if !ok {
		return errors.New("failed to snapshot verified selection on resume")
	}

	var matCatSHA string
	var matCatSeq, matAuthSeq int64
	err = tx.QueryRowContext(ctx, `SELECT catalog_sha256, catalog_sequence, authority_sequence FROM pack_trust_materials WHERE operation_id=? ORDER BY catalog_sequence DESC, authority_sequence DESC LIMIT 1`, req.OperationID).Scan(&matCatSHA, &matCatSeq, &matAuthSeq)
	if err != nil {
		return fmt.Errorf("query trust material head on resume: %w", err)
	}
	if req.ExpectedAuthoritySequence <= 0 || req.ExpectedAuthoritySequence != matAuthSeq {
		return errors.New("authority sequence mismatch with trust material head on resume")
	}
	if matCatSHA != snap.CatalogSHA256 || matCatSeq != snap.CatalogSequence {
		return errors.New("trust material head mismatch with verified selection on resume")
	}

	// Floor and anti-equivocation check across all sources in the pack
	var maxSeq int64
	var maxCatalogSHA string
	err = tx.QueryRowContext(ctx, `
		SELECT catalog_sequence, catalog_sha256
		  FROM (
			SELECT catalog_sequence, catalog_sha256 FROM pack_records WHERE pack_id=?
			UNION ALL
			SELECT catalog_sequence, catalog_sha256 FROM pack_trust_materials WHERE pack_id=?
			UNION ALL
			SELECT catalog_sequence, catalog_sha256 FROM pack_artifact_receipts WHERE pack_id=?
		  )
		 ORDER BY catalog_sequence DESC
		 LIMIT 1
	`, req.PackID, req.PackID, req.PackID).Scan(&maxSeq, &maxCatalogSHA)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("query pack authority floor on resume: %w", err)
	}
	if err == nil {
		if snap.CatalogSequence < maxSeq || (snap.CatalogSequence == maxSeq && snap.CatalogSHA256 != maxCatalogSHA) {
			return errors.New("authority sequence or digest below recorded pack floor on resume")
		}
	}

	// 4. Verify exact journal phase, revision, and durable evidence
	var jnlPhase string
	var jnlRev int64
	var jnlArtID, jnlPlanSHA, jnlVer, jnlUnit, jnlInstID, jnlStartIdent, jnlSockPath, jnlInstalledRoot sql.NullString
	var jnlPID, jnlCoreGen, jnlLeaseGen sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT phase, revision, artifact_receipt_id, plan_sha256, version,
		       unit_name, instance_id, main_pid, socket_path, process_start_identity,
		       core_generation, lease_generation, installed_root
		  FROM pack_activation_journal
		 WHERE operation_id=?
	`, req.OperationID).Scan(&jnlPhase, &jnlRev, &jnlArtID, &jnlPlanSHA, &jnlVer, &jnlUnit, &jnlInstID, &jnlPID, &jnlSockPath, &jnlStartIdent, &jnlCoreGen, &jnlLeaseGen, &jnlInstalledRoot)
	if errors.Is(err, sql.ErrNoRows) {
		if req.ExpectedJournalRevision != 0 || req.ExpectedPhase != "" {
			return errors.New("expected journal revision on resume but no activation journal exists")
		}
	} else if err != nil {
		return fmt.Errorf("query activation journal on resume: %w", err)
	} else {
		if jnlRev != req.ExpectedJournalRevision || jnlPhase != req.ExpectedPhase {
			return fmt.Errorf("journal revision or phase mismatch on resume: got (%d, %s) want (%d, %s)",
				jnlRev, jnlPhase, req.ExpectedJournalRevision, req.ExpectedPhase)
		}
		if jnlPhase == "active" || jnlPhase == "failed" || jnlPhase == "cancelled" {
			return fmt.Errorf("cannot resume operation with terminal journal phase %q", jnlPhase)
		}

		if req.ArtifactReceiptID == "" || !jnlArtID.Valid || req.ArtifactReceiptID != jnlArtID.String {
			return errors.New("artifact receipt id required and must match activation journal on resume")
		}
		var artID, artExeSHA, artExePath string
		err = tx.QueryRowContext(ctx, `SELECT receipt_id, executable_sha256, executable_path FROM pack_artifact_receipts WHERE operation_id=? AND pack_id=? AND version=?`, req.OperationID, req.PackID, req.Version).Scan(&artID, &artExeSHA, &artExePath)
		if err != nil || artID != req.ArtifactReceiptID {
			return errors.New("artifact receipt mismatch or missing on resume")
		}

		if req.ObservedEffects == nil {
			return errors.New("observed effects snapshot required on resume with existing journal")
		}
		obs := req.ObservedEffects
		if obs.OperationID != req.OperationID || obs.PackID != req.PackID || obs.Version != req.Version {
			return errors.New("observed effects scope mismatch on resume")
		}
		obsAge := time.Since(obs.ObservedAt)
		if obs.ObservedAt.IsZero() || obsAge < 0 || obsAge > time.Minute {
			return errors.New("observed effects snapshot has invalid or stale timestamp")
		}
		if obs.AbortEffect != nil && obs.AbortEffect.Status == "aborted" {
			return errors.New("cannot resume operation: helper reports aborted effect")
		}

		validateEffect := func(eff *contracts.PackObservedEffect, expectedAction, expectedStatus string) error {
			if eff == nil {
				return fmt.Errorf("missing %s effect on resume", expectedAction)
			}
			if eff.OperationID != req.OperationID || eff.PackID != req.PackID || eff.Version != req.Version {
				return fmt.Errorf("%s effect scope mismatch on resume", expectedAction)
			}
			if eff.Action != expectedAction || eff.Status != expectedStatus {
				return fmt.Errorf("%s effect action/status mismatch (got %s/%s, want %s/%s)", expectedAction, eff.Action, eff.Status, expectedAction, expectedStatus)
			}
			if strings.TrimSpace(eff.ActionID) == "" || !validHexDigest(eff.RequestDigest) {
				return fmt.Errorf("%s effect action ID empty or request digest not valid hex on resume", expectedAction)
			}
			if eff.Sequence <= 0 || eff.Sequence > obs.MaxOperationSequence {
				return fmt.Errorf("%s effect sequence %d invalid or exceeds max %d", expectedAction, eff.Sequence, obs.MaxOperationSequence)
			}
			if eff.CoreGeneration <= 0 || eff.LeaseGeneration <= 0 {
				return fmt.Errorf("%s effect epochs invalid (core=%d, lease=%d)", expectedAction, eff.CoreGeneration, eff.LeaseGeneration)
			}
			if expectedAction == "start" && (strings.TrimSpace(eff.InstanceID) == "" || eff.MainPID <= 0 || strings.TrimSpace(eff.ProcessStartTime) == "" || strings.TrimSpace(eff.SocketPath) == "") {
				return errors.New("start effect requires a complete instance, pid, start identity and socket on resume")
			}
			return nil
		}

		switch jnlPhase {
		case "publishing", "published":
			if err := validateEffect(obs.PublishEffect, "publish", "succeeded"); err != nil {
				return fmt.Errorf("cannot resume %s journal: %w", jnlPhase, err)
			}
			if obs.PublishEffect.ExecutableSHA == "" || obs.PublishEffect.ExecutableSHA != artExeSHA {
				return errors.New("publish effect executable sha mismatch with artifact receipt")
			}
			if obs.UID == 0 || !jnlInstalledRoot.Valid || obs.PublishEffect.ExecutablePath != filepath.Join(jnlInstalledRoot.String, artExePath) {
				return errors.New("publish effect requires its owned UID and exact installed executable path")
			}
		case "starting", "started":
			if obs.UID == 0 {
				return errors.New("observed snapshot UID must be non-zero on starting/started resume")
			}
			if err := validateEffect(obs.StartEffect, "start", "succeeded"); err != nil {
				return fmt.Errorf("cannot resume starting/started journal: %w", err)
			}
			if obs.StartEffect.ExecutableSHA == "" || obs.StartEffect.ExecutableSHA != artExeSHA {
				return errors.New("start effect executable sha mismatch with artifact receipt")
			}
			if !jnlInstalledRoot.Valid || obs.StartEffect.ExecutablePath != filepath.Join(jnlInstalledRoot.String, artExePath) {
				return errors.New("start effect executable path mismatch with installed root entry")
			}
			if jnlInstID.Valid && obs.StartEffect.InstanceID != jnlInstID.String {
				return errors.New("start effect instance mismatch with journal")
			}
			if jnlPID.Valid && obs.StartEffect.MainPID != int32(jnlPID.Int64) {
				return errors.New("start effect pid mismatch with journal")
			}
			if jnlStartIdent.Valid && obs.StartEffect.ProcessStartTime != jnlStartIdent.String {
				return errors.New("start effect process start identity mismatch with journal")
			}
			if jnlSockPath.Valid && obs.StartEffect.SocketPath != jnlSockPath.String {
				return errors.New("start effect socket path mismatch with journal")
			}
			if obs.StopEffect != nil {
				if err := validateEffect(obs.StopEffect, "stop_for_recovery", "stopped_for_recovery"); err != nil {
					return fmt.Errorf("invalid stop effect on resume: %w", err)
				}
				if obs.StopEffect.Sequence > obs.StartEffect.Sequence {
					return errors.New("cannot resume started journal: stop effect exists after start effect")
				}
			}
		case "ready":
			if obs.UID == 0 {
				return errors.New("observed snapshot UID must be non-zero on ready resume")
			}
			if err := validateEffect(obs.StartEffect, "start", "succeeded"); err != nil {
				return fmt.Errorf("cannot resume ready journal: %w", err)
			}
			if obs.StartEffect.ExecutableSHA == "" || obs.StartEffect.ExecutableSHA != artExeSHA {
				return errors.New("start effect executable sha mismatch with artifact receipt")
			}
			if !jnlInstalledRoot.Valid || obs.StartEffect.ExecutablePath != filepath.Join(jnlInstalledRoot.String, artExePath) {
				return errors.New("start effect executable path mismatch with installed root entry")
			}
			if jnlInstID.Valid && obs.StartEffect.InstanceID != jnlInstID.String {
				return errors.New("start effect instance mismatch with journal")
			}
			if jnlPID.Valid && obs.StartEffect.MainPID != int32(jnlPID.Int64) {
				return errors.New("start effect pid mismatch with journal")
			}
			if jnlStartIdent.Valid && obs.StartEffect.ProcessStartTime != jnlStartIdent.String {
				return errors.New("start effect process start identity mismatch with journal")
			}
			if jnlSockPath.Valid && obs.StartEffect.SocketPath != jnlSockPath.String {
				return errors.New("start effect socket path mismatch with journal")
			}
			if err := validateEffect(obs.SwitchEffect, "switch", "succeeded"); err != nil {
				return fmt.Errorf("cannot resume ready journal: %w", err)
			}
			if obs.SwitchEffect.CurrentTarget != req.Version {
				return errors.New("cannot resume ready journal: current switch target mismatch")
			}
			if obs.SwitchEffect.Sequence <= obs.StartEffect.Sequence {
				return errors.New("cannot resume ready journal: switch sequence before start sequence")
			}
			if obs.StopEffect != nil && obs.StopEffect.Sequence > obs.StartEffect.Sequence {
				return errors.New("cannot resume ready journal: stop effect after start")
			}
		default:
			return fmt.Errorf("cannot resume unverified journal phase %q", jnlPhase)
		}
	}

	newVersion := curVersion + 1
	res, err := tx.ExecContext(ctx, `
		UPDATE operations
		   SET state='pending', version=?, updated_at=?
		 WHERE id=? AND version=? AND state='waiting'
	`, newVersion, nowStr, req.OperationID, curVersion)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return errors.New("operation revision conflict on resume")
	}

	event := contracts.PackEvent{
		SchemaVersion: "1.1",
		OperationID:   req.OperationID,
		PackID:        packID,
		OccurredAt:    now,
		Kind:          "pack.install.resumed",
		Status:        "resumed",
	}
	outboxRes, err := appendOutboxTx(ctx, tx, contracts.OutboxEvent{
		AggregateType:    "pack_operation",
		AggregateID:      req.OperationID,
		AggregateVersion: newVersion,
		EventType:        event.Kind,
		CreatedAt:        now,
		PayloadVersion:   "1.1",
	}, func(id string, cursor int64) ([]byte, error) {
		event.ID = id
		event.Sequence = uint64(cursor)
		return json.Marshal(event)
	})
	if err != nil {
		return err
	}

	auditID, err := domain.NewID("audit")
	if err != nil {
		return err
	}
	auditDigest := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%d:%d", req.PackID, req.TaskID, req.PlanSHA256, req.ExpectedOperationVersion, req.ExpectedJournalRevision)))
	if _, err := appendAuditTx(ctx, tx, auditInput{
		ID:           auditID.String(),
		Actor:        req.Audit,
		Action:       "pack.install.resumed",
		InputDigest:  "sha256:" + hex.EncodeToString(auditDigest[:]),
		Result:       "resumed",
		EvidenceRefs: []string{"pack:" + packID, req.OperationID, req.TaskID, outboxRes.ID},
		CreatedAt:    now,
	}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit resume pack install: %v", ErrOutcomeUnknown, err)
	}
	return nil
}

func (s *Store) ListWaitingOperations(ctx context.Context, limit int) ([]contracts.WaitingOperationRecord, error) {
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 16 {
		limit = 16
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT o.id, o.version, o.pack_id, t.task_id, t.attempt, t.core_generation, t.lease_generation, i.version, i.plan_sha256
		  FROM operations o
		  JOIN task_leases t ON t.operation_id = o.id AND t.state = 'ready'
		  JOIN pack_install_intents i ON i.operation_id = o.id
		 WHERE o.state = 'waiting' AND o.target_kind = 'pack'
		 ORDER BY o.id ASC
		 LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []contracts.WaitingOperationRecord
	for rows.Next() {
		var r contracts.WaitingOperationRecord
		if err := rows.Scan(&r.OperationID, &r.OperationVersion, &r.PackID, &r.TaskID, &r.TaskAttempt, &r.TaskCoreGeneration, &r.TaskLeaseGeneration, &r.Version, &r.PlanSHA256); err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return list, nil
}
