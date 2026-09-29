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

	contracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/packprotocol"
	"github.com/acornfox/acornfox/internal/versionpolicy"
)

var _ contracts.PackRepository = (*Store)(nil)
var ErrPackBusy = errors.New("package has a nonterminal operation")

const packIntentScope = "pack.install.intent"
const PackInstallTaskKind = "core.pack.install"

func (s *Store) InstallationBinding(ctx context.Context) (string, error) {
	if err := s.checkOpen(); err != nil {
		return "", err
	}
	return readInstallationBinding(ctx, s.db)
}
func packIntentDigest(i contracts.PackInstallIntent) (string, error) {
	if !packprotocol.ValidPackID(i.PackID) || strings.TrimSpace(i.IdempotencyKey) != i.IdempotencyKey || i.IdempotencyKey == "" || len(i.IdempotencyKey) > 512 {
		return "", errors.New("invalid package user intent")
	}
	if _, err := versionpolicy.ParseSemver(i.Version); err != nil {
		return "", err
	}
	if i.OS != "linux" {
		return "", errors.New("unsupported package platform")
	}
	if _, _, err := versionpolicy.CanonicalizePlatform(i.OS, i.Arch); err != nil {
		return "", err
	}
	value := struct{ Action, PackID, Version, OS, Arch string }{"install", i.PackID, strings.TrimPrefix(i.Version, "v"), i.OS, i.Arch}
	b, _ := json.Marshal(value)
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}
func decodePackResult(b []byte) (contracts.PlanPackInstallResult, error) {
	var r contracts.PlanPackInstallResult
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&r) != nil {
		return r, ErrIdempotencyCorrupt
	}
	var tail any
	if decoder.Decode(&tail) != io.EOF || !packprotocol.ValidPackID(r.PackID) || r.State != "planned" || r.OperationID == "" || r.TaskID == "" || r.Event.ID == "" || r.Event.PackID != r.PackID || r.Event.OperationID != r.OperationID || r.Event.Sequence == 0 || r.Event.Kind != "pack.install.planned" {
		return r, ErrIdempotencyCorrupt
	}
	return r, nil
}
func (s *Store) PreflightPackInstall(ctx context.Context, intent contracts.PackInstallIntent) (contracts.PlanPackInstallResult, bool, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.PlanPackInstallResult{}, false, err
	}
	digest, err := packIntentDigest(intent)
	if err != nil {
		return contracts.PlanPackInstallResult{}, false, err
	}
	var stored, status string
	var response sql.NullString
	err = s.db.QueryRowContext(ctx, `SELECT request_digest,status,response FROM idempotency_records WHERE scope=? AND idempotency_key=?`, packIntentScope, intent.IdempotencyKey).Scan(&stored, &status, &response)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.PlanPackInstallResult{}, false, nil
	}
	if err != nil {
		return contracts.PlanPackInstallResult{}, false, err
	}
	if stored != digest {
		return contracts.PlanPackInstallResult{}, false, ErrIdempotencyConflict
	}
	if status != "completed" {
		return contracts.PlanPackInstallResult{}, false, ErrIdempotencyInProgress
	}
	if !response.Valid {
		return contracts.PlanPackInstallResult{}, false, ErrIdempotencyCorrupt
	}
	r, err := decodePackResult([]byte(response.String))
	return r, err == nil, err
}
func (s *Store) PlanPackInstall(ctx context.Context, r contracts.PlanPackInstallRecord) (contracts.PlanPackInstallResult, error) {
	// Replay before reauthorizing an expired catalog or requiring a fresh selection.
	if replay, found, err := s.PreflightPackInstall(ctx, r.Intent); err != nil || found {
		return replay, err
	}
	if err := validateAuditContext(r.Audit); err != nil {
		return contracts.PlanPackInstallResult{}, err
	}
	binding, err := s.InstallationBinding(ctx)
	if err != nil {
		return contracts.PlanPackInstallResult{}, err
	}
	now := time.Now().UTC()
	if s.packCoreVersion == "" || s.packProtocolVersion == "" {
		return contracts.PlanPackInstallResult{}, errors.New("explicit package compatibility configuration required")
	}
	if err := r.Selection.Authorize(binding, s.packCoreVersion, s.packProtocolVersion, now); err != nil {
		return contracts.PlanPackInstallResult{}, err
	}
	selected, _, ok := r.Selection.Snapshot()
	if !ok || selected.PackID != r.Intent.PackID || strings.TrimPrefix(selected.Version, "v") != strings.TrimPrefix(r.Intent.Version, "v") || selected.OS != r.Intent.OS || selected.Arch != r.Intent.Arch {
		return contracts.PlanPackInstallResult{}, errors.New("selection does not match user intent")
	}
	digest, err := packIntentDigest(r.Intent)
	if err != nil {
		return contracts.PlanPackInstallResult{}, err
	}
	identity, _ := json.Marshal(selected)
	planHash := sha256.Sum256(identity)
	planSHA := hex.EncodeToString(planHash[:]) // verified metadata is digest-bound; archive bytes have not been fetched.
	operationID, err := domain.NewID("op")
	if err != nil {
		return contracts.PlanPackInstallResult{}, err
	}
	taskID, err := domain.NewID("task")
	if err != nil {
		return contracts.PlanPackInstallResult{}, err
	}
	auditID, err := domain.NewID("audit")
	if err != nil {
		return contracts.PlanPackInstallResult{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return contracts.PlanPackInstallResult{}, err
	}
	defer tx.Rollback()
	reservation, err := tx.ExecContext(ctx, `INSERT INTO idempotency_records(scope,idempotency_key,request_digest,status,created_at,updated_at) VALUES(?,?,?,'in_progress',?,?) ON CONFLICT(scope,idempotency_key) DO NOTHING`, packIntentScope, r.Intent.IdempotencyKey, digest, FormatTime(now), FormatTime(now))
	if err != nil {
		return contracts.PlanPackInstallResult{}, err
	}
	inserted, err := reservation.RowsAffected()
	if err != nil {
		return contracts.PlanPackInstallResult{}, err
	}
	if inserted == 0 {
		var prior, status string
		var response sql.NullString
		if tx.QueryRowContext(ctx, `SELECT request_digest,status,response FROM idempotency_records WHERE scope=? AND idempotency_key=?`, packIntentScope, r.Intent.IdempotencyKey).Scan(&prior, &status, &response) != nil {
			return contracts.PlanPackInstallResult{}, ErrIdempotencyCorrupt
		}
		if prior != digest {
			return contracts.PlanPackInstallResult{}, ErrIdempotencyConflict
		}
		if status != "completed" || !response.Valid {
			return contracts.PlanPackInstallResult{}, ErrIdempotencyInProgress
		}
		return decodePackResult([]byte(response.String))
	}
	if err := r.Selection.Authorize(binding, s.packCoreVersion, s.packProtocolVersion, time.Now().UTC()); err != nil {
		return contracts.PlanPackInstallResult{}, err
	}
	var floor int64
	var priorDigest, desired string
	err = tx.QueryRowContext(ctx, `SELECT catalog_sequence,catalog_sha256,desired_version FROM pack_records WHERE pack_id=?`, selected.PackID).Scan(&floor, &priorDigest, &desired)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return contracts.PlanPackInstallResult{}, err
	}
	if exists {
		if selected.CatalogSequence < floor || (selected.CatalogSequence == floor && selected.CatalogSHA256 != priorDigest) {
			return contracts.PlanPackInstallResult{}, errors.New("catalog rollback or equivocation")
		}
		old, _ := versionpolicy.ParseSemver(desired)
		next, _ := versionpolicy.ParseSemver(selected.Version)
		if next.Compare(old) < 0 {
			return contracts.PlanPackInstallResult{}, errors.New("package version rollback")
		}
		var active int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM operations WHERE pack_id=? AND state IN ('pending','leased','running','waiting','cancelling')`, selected.PackID).Scan(&active); err != nil {
			return contracts.PlanPackInstallResult{}, err
		}
		if active > 0 {
			return contracts.PlanPackInstallResult{}, ErrPackBusy
		}
	}
	if !exists {
		_, err = tx.ExecContext(ctx, `INSERT INTO pack_records(pack_id,desired_version,manifest_sha256,artifact_sha256,catalog_sha256,catalog_sequence,state,installation_binding,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,'planned',?,1,?,?)`, selected.PackID, selected.Version, selected.ManifestSHA256, selected.ArtifactSHA256, selected.CatalogSHA256, selected.CatalogSequence, binding, FormatTime(now), FormatTime(now))
	} else {
		var update sql.Result
		update, err = tx.ExecContext(ctx, `UPDATE pack_records SET desired_version=?,manifest_sha256=?,artifact_sha256=?,catalog_sha256=?,catalog_sequence=?,revision=revision+1,updated_at=? WHERE pack_id=? AND revision<9223372036854775807`, selected.Version, selected.ManifestSHA256, selected.ArtifactSHA256, selected.CatalogSHA256, selected.CatalogSequence, FormatTime(now), selected.PackID)
		if err == nil {
			n, e := update.RowsAffected()
			if e != nil || n != 1 {
				return contracts.PlanPackInstallResult{}, errors.New("package revision exhausted")
			}
		}
	}
	if err != nil {
		return contracts.PlanPackInstallResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations(id,operation_type,idempotency_key,state,version,target_ref,created_at,updated_at,target_kind,pack_id) VALUES(?,'pack_install',?,'pending',1,?,?,?,'pack',?)`, operationID.String(), r.Intent.IdempotencyKey, selected.PackID, FormatTime(now), FormatTime(now), selected.PackID); err != nil {
		return contracts.PlanPackInstallResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO pack_install_intents(operation_id,pack_id,version,plan_sha256,phase,selected_identity,created_at) VALUES(?,?,?,?,'planned',?,?)`, operationID.String(), selected.PackID, selected.Version, planSHA, string(identity), FormatTime(now)); err != nil {
		return contracts.PlanPackInstallResult{}, err
	}
	rawEnv, rawMan, hasMat := r.Selection.VerificationMaterial()
	if hasMat && len(rawEnv) > 0 && len(rawMan) > 0 {
		var hasTable int
		_ = tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='pack_trust_materials'`).Scan(&hasTable)
		if hasTable > 0 {
			matID, err := domain.NewID("mat")
			if err != nil {
				return contracts.PlanPackInstallResult{}, err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO pack_trust_materials(material_id,operation_id,pack_id,version,plan_sha256,catalog_sha256,catalog_sequence,manifest_sha256,artifact_sha256,catalog_envelope,manifest_bytes,authority_kind,authority_sequence,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'original_plan',1,?)`, matID.String(), operationID.String(), selected.PackID, selected.Version, planSHA, selected.CatalogSHA256, selected.CatalogSequence, selected.ManifestSHA256, selected.ArtifactSHA256, string(rawEnv), string(rawMan), FormatTime(now)); err != nil {
				return contracts.PlanPackInstallResult{}, err
			}
		}
	}
	taskPayload, _ := json.Marshal(struct {
		Kind        string `json:"kind"`
		PackID      string `json:"pack_id"`
		OperationID string `json:"operation_id"`
		PlanSHA256  string `json:"plan_sha256"`
	}{PackInstallTaskKind, selected.PackID, operationID.String(), planSHA})
	if _, err := tx.ExecContext(ctx, `INSERT INTO task_leases(task_id,operation_id,state,payload,created_at,updated_at) VALUES(?,?,'ready',?,?,?)`, taskID.String(), operationID.String(), string(taskPayload), FormatTime(now), FormatTime(now)); err != nil {
		return contracts.PlanPackInstallResult{}, err
	}
	event := contracts.PackEvent{SchemaVersion: "1.1", OperationID: operationID.String(), PackID: selected.PackID, OccurredAt: now, Kind: "pack.install.planned", Status: "accepted"}
	if _, err := appendOutboxTx(ctx, tx, contracts.OutboxEvent{AggregateType: "pack_operation", AggregateID: operationID.String(), AggregateVersion: 1, EventType: event.Kind, CreatedAt: now, PayloadVersion: "1.1"}, func(id string, cursor int64) ([]byte, error) {
		event.ID = id
		event.Sequence = uint64(cursor)
		return json.Marshal(event)
	}); err != nil {
		return contracts.PlanPackInstallResult{}, err
	}
	if _, err := appendAuditTx(ctx, tx, auditInput{ID: auditID.String(), Actor: r.Audit, Action: "pack.install.planned", InputDigest: digest, Result: "accepted", EvidenceRefs: []string{"pack:" + selected.PackID, operationID.String(), taskID.String(), event.ID}, CreatedAt: now}); err != nil {
		return contracts.PlanPackInstallResult{}, err
	}
	result := contracts.PlanPackInstallResult{PackID: selected.PackID, Version: selected.Version, OperationID: operationID.String(), TaskID: taskID.String(), ManifestSHA256: selected.ManifestSHA256, ArtifactSHA256: selected.ArtifactSHA256, PlanSHA256: planSHA, State: "planned", CatalogSequence: selected.CatalogSequence, Event: event}
	response, _ := json.Marshal(result)
	if _, err := tx.ExecContext(ctx, `UPDATE idempotency_records SET status='completed',response=?,updated_at=? WHERE scope=? AND idempotency_key=? AND status='in_progress'`, string(response), FormatTime(now), packIntentScope, r.Intent.IdempotencyKey); err != nil {
		return contracts.PlanPackInstallResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return contracts.PlanPackInstallResult{}, fmt.Errorf("%w: commit planned pack intent: %v", ErrOutcomeUnknown, err)
	}
	return result, nil
}
func (s *Store) GetPack(ctx context.Context, id string) (contracts.PackRecord, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.PackRecord{}, err
	}
	var r contracts.PackRecord
	err := s.db.QueryRowContext(ctx, `SELECT pack_id,desired_version,manifest_sha256,artifact_sha256,catalog_sha256,catalog_sequence,state,installation_binding,revision FROM pack_records WHERE pack_id=?`, id).Scan(&r.PackID, &r.DesiredVersion, &r.ManifestSHA256, &r.ArtifactSHA256, &r.CatalogSHA256, &r.CatalogSequence, &r.State, &r.InstallationBinding, &r.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return r, err
}
func (s *Store) GetPackIntent(ctx context.Context, operation string) (contracts.PackIntentRecord, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.PackIntentRecord{}, err
	}
	var r contracts.PackIntentRecord
	err := s.db.QueryRowContext(ctx, `SELECT operation_id,pack_id,version,plan_sha256,phase FROM pack_install_intents WHERE operation_id=?`, operation).Scan(&r.OperationID, &r.PackID, &r.Version, &r.PlanSHA256, &r.Phase)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return r, err
}
