package rules

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type PostgresRegistry struct{ db *sql.DB }

func NewPostgres(db *sql.DB) *PostgresRegistry         { return &PostgresRegistry{db: db} }
func NewPostgresRegistry(db *sql.DB) *PostgresRegistry { return NewPostgres(db) }
func (r *PostgresRegistry) DB() *sql.DB {
	if r == nil {
		return nil
	}
	return r.db
}
func (r *PostgresRegistry) requireDB() error {
	if r == nil || r.db == nil {
		return ErrInvalid
	}
	return nil
}

func appendRuleRow(ctx context.Context, exec interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, table, id, key, digest string, payload any, query string, args ...any) (bool, []byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return false, nil, err
	}
	if err := validateSafe(payload); err != nil {
		return false, nil, err
	}
	result, err := exec.ExecContext(ctx, query, argsWithPayload(args, data)...)
	if err != nil {
		return false, nil, err
	}
	n, _ := result.RowsAffected()
	if n == 1 {
		return false, data, nil
	}
	var storedDigest string
	var stored []byte
	if err := exec.QueryRowContext(ctx, fmt.Sprintf("SELECT request_digest,payload FROM %s WHERE idempotency_key=$1", table), key).Scan(&storedDigest, &stored); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil, ErrConflict
		}
		return false, nil, err
	}
	if storedDigest != digest {
		return false, nil, ErrConflict
	}
	return true, stored, nil
}
func argsWithPayload(args []any, payload []byte) []any { return append(args, payload) }
func insertQuery(table, columns string, count int) string {
	values := make([]string, count+1)
	for i := range values {
		values[i] = fmt.Sprintf("$%d", i+1)
	}
	values[len(values)-1] = fmt.Sprintf("$%d::jsonb", count+1)
	return fmt.Sprintf("INSERT INTO %s (%s,payload) VALUES (%s) ON CONFLICT(idempotency_key) DO NOTHING", table, columns, strings.Join(values, ","))
}

func (r *PostgresRegistry) Aggregate(ctx context.Context, observation Observation) (RuleCandidate, bool, error) {
	if err := checkContext(ctx); err != nil {
		return RuleCandidate{}, false, err
	}
	if err := r.requireDB(); err != nil {
		return RuleCandidate{}, false, err
	}
	observation.Fingerprint = strings.TrimSpace(observation.Fingerprint)
	if observation.Fingerprint == "" {
		return RuleCandidate{}, false, ErrInvalid
	}
	key, digest, err := ensureRequest(observation.IdempotencyKey, observation.RequestDigest, observation, observation.ID)
	if err != nil {
		return RuleCandidate{}, false, err
	}
	observation.IdempotencyKey, observation.RequestDigest = key, digest
	observation.ID = firstNonEmpty(observation.ID, deterministicID("observation", key, digest))
	observation.At = normalizeTime(observation.At)
	if err := validateSafe(observation); err != nil {
		return RuleCandidate{}, false, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return RuleCandidate{}, false, err
	}
	rollback := func(cause error) (RuleCandidate, bool, error) {
		_ = tx.Rollback()
		return RuleCandidate{}, false, cause
	}
	var candidateID string
	var payload []byte
	err = tx.QueryRowContext(ctx, `SELECT id,payload FROM m6_rule_candidates WHERE fingerprint=$1 AND status <> 'promoted' ORDER BY created_at DESC,id DESC LIMIT 1`, observation.Fingerprint).Scan(&candidateID, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		candidateID = deterministicID("candidate", observation.Fingerprint, key)
		candidate := RuleCandidate{ID: candidateID, Fingerprint: observation.Fingerprint, Name: strings.TrimSpace(observation.Name), Status: StatusDraft, CreatedAt: observation.At, UpdatedAt: observation.At}
		data, _ := json.Marshal(candidate)
		if _, err = tx.ExecContext(ctx, `INSERT INTO m6_rule_candidates(id,fingerprint,name,status,payload,created_at,updated_at) VALUES($1,$2,$3,'draft',$4::jsonb,$5,$5) ON CONFLICT(id) DO NOTHING`, candidate.ID, candidate.Fingerprint, candidate.Name, data, candidate.CreatedAt); err != nil {
			return rollback(err)
		}
	} else if err != nil {
		return rollback(err)
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO m6_rule_candidate_observations(id,idempotency_key,request_digest,candidate_id,fingerprint,invocation_id,application_id,success,evidence,payload,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11) ON CONFLICT(idempotency_key) DO NOTHING`, observation.ID, key, digest, candidateID, observation.Fingerprint, observation.InvocationID, observation.ApplicationID, observation.Success, mustJSON(observation.Evidence), mustJSON(observation), observation.At)
	if err != nil {
		return rollback(err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		var storedDigest string
		if err := tx.QueryRowContext(ctx, `SELECT request_digest FROM m6_rule_candidate_observations WHERE idempotency_key=$1`, key).Scan(&storedDigest); err != nil {
			return rollback(err)
		}
		if storedDigest != digest {
			return rollback(ErrConflict)
		}
	}
	if err = tx.Commit(); err != nil {
		return RuleCandidate{}, false, err
	}
	candidate, err := r.GetCandidate(ctx, candidateID)
	if err != nil {
		return RuleCandidate{}, false, err
	}
	return candidate, rows == 0, nil
}

func (r *PostgresRegistry) GetCandidate(ctx context.Context, id string) (RuleCandidate, error) {
	if err := checkContext(ctx); err != nil {
		return RuleCandidate{}, err
	}
	if err := r.requireDB(); err != nil {
		return RuleCandidate{}, err
	}
	var payload []byte
	if err := r.db.QueryRowContext(ctx, `SELECT payload FROM m6_rule_candidates WHERE id=$1`, strings.TrimSpace(id)).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RuleCandidate{}, ErrNotFound
		}
		return RuleCandidate{}, err
	}
	var candidate RuleCandidate
	if json.Unmarshal(payload, &candidate) != nil {
		return RuleCandidate{}, ErrInvalid
	}
	var latest []byte
	err := r.db.QueryRowContext(ctx, `SELECT payload FROM m6_rule_candidate_events WHERE candidate_id=$1 ORDER BY sequence DESC LIMIT 1`, candidate.ID).Scan(&latest)
	if err == nil {
		if json.Unmarshal(latest, &candidate) != nil {
			return RuleCandidate{}, ErrInvalid
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return RuleCandidate{}, err
	}
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FILTER(WHERE success),COUNT(DISTINCT NULLIF(application_id,'')) FROM m6_rule_candidate_observations WHERE candidate_id=$1`, candidate.ID).Scan(&candidate.SuccessCount, &candidate.ApplicationCount); err != nil {
		return RuleCandidate{}, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT payload FROM m6_rule_evaluations WHERE candidate_id=$1 AND passed=true ORDER BY created_at,id`, candidate.ID)
	if err != nil {
		return RuleCandidate{}, err
	}
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			rows.Close()
			return RuleCandidate{}, err
		}
		var evaluation EvaluationEvidence
		if json.Unmarshal(data, &evaluation) != nil {
			rows.Close()
			return RuleCandidate{}, ErrInvalid
		}
		candidate.RegressionPassed = true
		if len(evaluation.Evidence) == 0 {
			evaluation.Evidence = []EvidenceRef{{ID: evaluation.ID, Kind: "regression"}}
		}
		for _, ref := range evaluation.Evidence {
			found := false
			for _, old := range candidate.TestEvidence {
				if old.ID == ref.ID {
					found = true
					break
				}
			}
			if !found {
				candidate.TestEvidence = append(candidate.TestEvidence, ref)
			}
		}
	}
	if err := rows.Close(); err != nil {
		return RuleCandidate{}, err
	}
	return candidate, nil
}

func (r *PostgresRegistry) Transition(ctx context.Context, request TransitionRequest) (RuleCandidate, error) {
	if err := checkContext(ctx); err != nil {
		return RuleCandidate{}, err
	}
	if err := r.requireDB(); err != nil {
		return RuleCandidate{}, err
	}
	request.CandidateID = strings.TrimSpace(request.CandidateID)
	if request.CandidateID == "" {
		return RuleCandidate{}, ErrInvalid
	}
	key, digest, err := ensureRequest(request.IdempotencyKey, request.RequestDigest, request, request.CandidateID+":"+string(request.To))
	if err != nil {
		return RuleCandidate{}, err
	}
	request.At = normalizeTime(request.At)
	candidate, err := r.GetCandidate(ctx, request.CandidateID)
	if err != nil {
		return RuleCandidate{}, err
	}
	next := candidate
	if request.ReviewedBy != "" {
		next.ReviewedBy = strings.TrimSpace(request.ReviewedBy)
	}
	if request.Actor != "" && next.ReviewedBy == "" {
		next.ReviewedBy = strings.TrimSpace(request.Actor)
	}
	if request.ReviewDecision != "" {
		next.ReviewDecision = strings.TrimSpace(request.ReviewDecision)
	}
	if request.ProposedVersion != "" {
		next.ProposedVersion = strings.TrimSpace(request.ProposedVersion)
	}
	if request.RegressionPassed {
		next.RegressionPassed = true
	}
	if request.ShadowPassed {
		next.ShadowPassed = true
	}
	if len(request.TestEvidence) > 0 {
		next.TestEvidence = append([]EvidenceRef(nil), request.TestEvidence...)
	}
	if err := next.Transition(request.To); err != nil {
		return RuleCandidate{}, err
	}
	next.UpdatedAt = request.At
	data, _ := json.Marshal(next)
	result, err := r.db.ExecContext(ctx, `INSERT INTO m6_rule_candidate_events(id,idempotency_key,request_digest,candidate_id,fingerprint,from_status,to_status,actor,reason,payload,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11) ON CONFLICT(idempotency_key) DO NOTHING`, deterministicID("rule-event", key, digest), key, digest, next.ID, next.Fingerprint, candidate.Status, next.Status, strings.TrimSpace(request.Actor), strings.TrimSpace(request.Reason), data, request.At)
	if err != nil {
		return RuleCandidate{}, err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		var storedDigest string
		if err := r.db.QueryRowContext(ctx, `SELECT request_digest FROM m6_rule_candidate_events WHERE idempotency_key=$1`, key).Scan(&storedDigest); err != nil {
			return RuleCandidate{}, err
		}
		if storedDigest != digest {
			return RuleCandidate{}, ErrConflict
		}
		return r.GetCandidate(ctx, next.ID)
	}
	return next, nil
}

func (r *PostgresRegistry) RecordEvaluation(ctx context.Context, evidence EvaluationEvidence) (EvaluationEvidence, bool, error) {
	if err := checkContext(ctx); err != nil {
		return EvaluationEvidence{}, false, err
	}
	if err := r.requireDB(); err != nil {
		return EvaluationEvidence{}, false, err
	}
	evidence.CandidateID = strings.TrimSpace(evidence.CandidateID)
	evidence.TestName = strings.TrimSpace(evidence.TestName)
	if evidence.CandidateID == "" || evidence.TestName == "" {
		return EvaluationEvidence{}, false, ErrInvalid
	}
	key, digest, err := ensureRequest(evidence.IdempotencyKey, evidence.RequestDigest, evidence, evidence.ID)
	if err != nil {
		return EvaluationEvidence{}, false, err
	}
	evidence.IdempotencyKey, evidence.RequestDigest = key, digest
	evidence.ID = firstNonEmpty(evidence.ID, deterministicID("evaluation", key, digest))
	evidence.CreatedAt = normalizeTime(evidence.CreatedAt)
	if _, err := r.GetCandidate(ctx, evidence.CandidateID); err != nil {
		return EvaluationEvidence{}, false, err
	}
	data, _ := json.Marshal(evidence)
	refs := mustJSON(evidence.Evidence)
	result, err := r.db.ExecContext(ctx, `INSERT INTO m6_rule_evaluations(id,idempotency_key,request_digest,candidate_id,test_name,kind,passed,evidence,payload,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10) ON CONFLICT(idempotency_key) DO NOTHING`, evidence.ID, key, digest, evidence.CandidateID, evidence.TestName, evidence.Kind, evidence.Passed, refs, data, evidence.CreatedAt)
	if err != nil {
		return EvaluationEvidence{}, false, err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		var stored []byte
		if err := r.db.QueryRowContext(ctx, `SELECT payload FROM m6_rule_evaluations WHERE idempotency_key=$1`, key).Scan(&stored); err != nil {
			return EvaluationEvidence{}, false, err
		}
		if json.Unmarshal(stored, &evidence) != nil {
			return EvaluationEvidence{}, false, ErrInvalid
		}
		return evidence, true, nil
	}
	return evidence, false, nil
}

func (r *PostgresRegistry) Promote(ctx context.Context, request PromotionRequest) (RuleVersion, bool, error) {
	if err := checkContext(ctx); err != nil {
		return RuleVersion{}, false, err
	}
	if err := r.requireDB(); err != nil {
		return RuleVersion{}, false, err
	}
	request.CandidateID = strings.TrimSpace(request.CandidateID)
	request.Version = strings.TrimSpace(request.Version)
	if request.CandidateID == "" || request.Version == "" {
		return RuleVersion{}, false, ErrPromotionGate
	}
	key, digest, err := ensureRequest(request.IdempotencyKey, request.RequestDigest, request, request.CandidateID+":"+request.Version)
	if err != nil {
		return RuleVersion{}, false, err
	}
	var replayDigest, replayVersionID string
	if replayErr := r.db.QueryRowContext(ctx, `SELECT request_digest,rule_version_id FROM m6_rule_registry_events WHERE idempotency_key=$1`, key).Scan(&replayDigest, &replayVersionID); replayErr == nil {
		if replayDigest != digest {
			return RuleVersion{}, false, ErrConflict
		}
		version, versionErr := r.getVersion(ctx, replayVersionID)
		if versionErr != nil {
			return RuleVersion{}, false, versionErr
		}
		return version, true, nil
	} else if !errors.Is(replayErr, sql.ErrNoRows) {
		return RuleVersion{}, false, replayErr
	}
	request.At = normalizeTime(request.At)
	candidate, err := r.GetCandidate(ctx, request.CandidateID)
	if err != nil {
		return RuleVersion{}, false, err
	}
	if candidate.Status != StatusApproved {
		return RuleVersion{}, false, ErrPromotionGate
	}
	candidate.ProposedVersion = request.Version
	if request.CodeDigest == "" {
		request.CodeDigest = requestDigest(request.Definition)
	}
	if err := candidate.CanPromote(); err != nil {
		return RuleVersion{}, false, err
	}
	if active, activeErr := r.Active(ctx, candidate.Fingerprint); activeErr == nil && active.ID != "" {
		return RuleVersion{}, false, fmt.Errorf("%w: a version is already active", ErrConflict)
	}
	version := RuleVersion{ID: deterministicID("rule-version", candidate.ID, request.Version), CandidateID: candidate.ID, Fingerprint: candidate.Fingerprint, Version: request.Version, CodeDigest: request.CodeDigest, Definition: cloneMap(request.Definition), CreatedAt: request.At}
	if err := version.Validate(); err != nil {
		return RuleVersion{}, false, err
	}
	data, _ := json.Marshal(version)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return RuleVersion{}, false, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO m6_rule_versions(id,candidate_id,fingerprint,version,code_digest,definition,payload,created_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8) ON CONFLICT(candidate_id,version) DO NOTHING`, version.ID, version.CandidateID, version.Fingerprint, version.Version, version.CodeDigest, mustJSON(version.Definition), data, version.CreatedAt); err != nil {
		_ = tx.Rollback()
		return RuleVersion{}, false, err
	}
	eventCandidate := candidate
	eventCandidate.Status = StatusPromoted
	eventCandidate.UpdatedAt = request.At
	candidateData, _ := json.Marshal(eventCandidate)
	if _, err = tx.ExecContext(ctx, `INSERT INTO m6_rule_candidate_events(id,idempotency_key,request_digest,candidate_id,fingerprint,from_status,to_status,actor,reason,payload,created_at) VALUES($1,$2,$3,$4,$5,'approved','promoted',$6,$7,$8::jsonb,$9) ON CONFLICT(idempotency_key) DO NOTHING`, deterministicID("rule-event", key, digest), key, digest, candidate.ID, candidate.Fingerprint, strings.TrimSpace(request.Actor), strings.TrimSpace(request.Reason), candidateData, request.At); err != nil {
		_ = tx.Rollback()
		return RuleVersion{}, false, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO m6_rule_registry_events(id,idempotency_key,request_digest,rule_version_id,candidate_id,fingerprint,kind,previous_id,actor,reason,payload,created_at) VALUES($1,$2,$3,$4,$5,$6,'promoted','',$7,$8,$9::jsonb,$10) ON CONFLICT(idempotency_key) DO NOTHING`, deterministicID("registry-event", key, digest), key, digest, version.ID, candidate.ID, candidate.Fingerprint, strings.TrimSpace(request.Actor), strings.TrimSpace(request.Reason), data, request.At); err != nil {
		_ = tx.Rollback()
		return RuleVersion{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return RuleVersion{}, false, err
	}
	return version, false, nil
}

func (r *PostgresRegistry) Enable(ctx context.Context, request RegistryRequest) (RuleVersion, error) {
	return r.registryChange(ctx, request, "enabled")
}
func (r *PostgresRegistry) Disable(ctx context.Context, request RegistryRequest) (RuleVersion, error) {
	return r.registryChange(ctx, request, "disabled")
}
func (r *PostgresRegistry) registryChange(ctx context.Context, request RegistryRequest, kind string) (RuleVersion, error) {
	if err := checkContext(ctx); err != nil {
		return RuleVersion{}, err
	}
	if err := r.requireDB(); err != nil {
		return RuleVersion{}, err
	}
	request.RuleVersionID = strings.TrimSpace(request.RuleVersionID)
	if request.RuleVersionID == "" {
		return RuleVersion{}, ErrInvalid
	}
	key, digest, err := ensureRequest(request.IdempotencyKey, request.RequestDigest, request, request.RuleVersionID+":"+kind)
	if err != nil {
		return RuleVersion{}, err
	}
	var replayDigest, replayVersionID string
	if replayErr := r.db.QueryRowContext(ctx, `SELECT request_digest,rule_version_id FROM m6_rule_registry_events WHERE idempotency_key=$1`, key).Scan(&replayDigest, &replayVersionID); replayErr == nil {
		if replayDigest != digest {
			return RuleVersion{}, ErrConflict
		}
		return r.getVersion(ctx, replayVersionID)
	} else if !errors.Is(replayErr, sql.ErrNoRows) {
		return RuleVersion{}, replayErr
	}
	request.At = normalizeTime(request.At)
	version, err := r.getVersion(ctx, request.RuleVersionID)
	if err != nil {
		return RuleVersion{}, err
	}
	candidate, err := r.GetCandidate(ctx, version.CandidateID)
	if err != nil {
		return RuleVersion{}, err
	}
	if candidate.Status != StatusPromoted {
		return RuleVersion{}, ErrPromotionGate
	}
	active, activeErr := r.Active(ctx, version.Fingerprint)
	if kind == "enabled" && activeErr == nil && active.ID != version.ID {
		return RuleVersion{}, ErrConflict
	}
	if kind == "disabled" && (activeErr != nil || active.ID != version.ID) {
		return RuleVersion{}, ErrDisabled
	}
	previous := ""
	if activeErr == nil {
		previous = active.ID
	}
	data, _ := json.Marshal(RegistryEvent{RuleVersionID: version.ID, CandidateID: version.CandidateID, Fingerprint: version.Fingerprint, Kind: kind, PreviousID: previous, Actor: request.Actor, Reason: request.Reason, CreatedAt: request.At})
	_, err = r.db.ExecContext(ctx, `INSERT INTO m6_rule_registry_events(id,idempotency_key,request_digest,rule_version_id,candidate_id,fingerprint,kind,previous_id,actor,reason,payload,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12) ON CONFLICT(idempotency_key) DO NOTHING`, deterministicID("registry-event", key, digest), key, digest, version.ID, version.CandidateID, version.Fingerprint, kind, previous, strings.TrimSpace(request.Actor), strings.TrimSpace(request.Reason), data, request.At)
	if err != nil {
		return RuleVersion{}, err
	}
	return version, nil
}

func (r *PostgresRegistry) Rollback(ctx context.Context, request RegistryRequest) (RuleVersion, error) {
	if err := checkContext(ctx); err != nil {
		return RuleVersion{}, err
	}
	if err := r.requireDB(); err != nil {
		return RuleVersion{}, err
	}
	request.RuleVersionID = strings.TrimSpace(request.RuleVersionID)
	if request.RuleVersionID == "" {
		return RuleVersion{}, ErrInvalid
	}
	key, digest, err := ensureRequest(request.IdempotencyKey, request.RequestDigest, request, request.RuleVersionID+":rollback")
	if err != nil {
		return RuleVersion{}, err
	}
	var replayDigest, replayVersionID string
	if replayErr := r.db.QueryRowContext(ctx, `SELECT request_digest,rule_version_id FROM m6_rule_registry_events WHERE idempotency_key=$1`, key).Scan(&replayDigest, &replayVersionID); replayErr == nil {
		if replayDigest != digest {
			return RuleVersion{}, ErrConflict
		}
		return r.getVersion(ctx, replayVersionID)
	} else if !errors.Is(replayErr, sql.ErrNoRows) {
		return RuleVersion{}, replayErr
	}
	current, err := r.getVersion(ctx, request.RuleVersionID)
	if err != nil {
		return RuleVersion{}, err
	}
	active, err := r.Active(ctx, current.Fingerprint)
	if err != nil || active.ID != current.ID {
		return RuleVersion{}, ErrDisabled
	}
	var previousID string
	err = r.db.QueryRowContext(ctx, `SELECT rule_version_id FROM m6_rule_registry_events WHERE fingerprint=$1 AND rule_version_id<>$2 AND kind IN ('promoted','enabled','rollback') ORDER BY sequence DESC LIMIT 1`, current.Fingerprint, current.ID).Scan(&previousID)
	if errors.Is(err, sql.ErrNoRows) {
		return RuleVersion{}, ErrNoPrevious
	}
	if err != nil {
		return RuleVersion{}, err
	}
	previous, err := r.getVersion(ctx, previousID)
	if err != nil {
		return RuleVersion{}, err
	}
	request.At = normalizeTime(request.At)
	payload, _ := json.Marshal(RegistryEvent{RuleVersionID: previous.ID, CandidateID: previous.CandidateID, Fingerprint: previous.Fingerprint, Kind: "rollback", PreviousID: current.ID, Actor: request.Actor, Reason: request.Reason, CreatedAt: request.At})
	_, err = r.db.ExecContext(ctx, `INSERT INTO m6_rule_registry_events(id,idempotency_key,request_digest,rule_version_id,candidate_id,fingerprint,kind,previous_id,actor,reason,payload,created_at) VALUES($1,$2,$3,$4,$5,$6,'rollback',$7,$8,$9,$10::jsonb,$11) ON CONFLICT(idempotency_key) DO NOTHING`, deterministicID("registry-event", key, digest), key, digest, previous.ID, previous.CandidateID, previous.Fingerprint, current.ID, strings.TrimSpace(request.Actor), strings.TrimSpace(request.Reason), payload, request.At)
	if err != nil {
		return RuleVersion{}, err
	}
	return previous, nil
}

func (r *PostgresRegistry) getVersion(ctx context.Context, id string) (RuleVersion, error) {
	var payload []byte
	if err := r.db.QueryRowContext(ctx, `SELECT payload FROM m6_rule_versions WHERE id=$1`, id).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RuleVersion{}, ErrNotFound
		}
		return RuleVersion{}, err
	}
	var version RuleVersion
	if json.Unmarshal(payload, &version) != nil {
		return RuleVersion{}, ErrInvalid
	}
	return version, nil
}
func (r *PostgresRegistry) Active(ctx context.Context, fingerprint string) (RuleVersion, error) {
	if err := checkContext(ctx); err != nil {
		return RuleVersion{}, err
	}
	if err := r.requireDB(); err != nil {
		return RuleVersion{}, err
	}
	var id, kind string
	if err := r.db.QueryRowContext(ctx, `SELECT rule_version_id,kind FROM m6_rule_registry_events WHERE fingerprint=$1 ORDER BY sequence DESC LIMIT 1`, strings.TrimSpace(fingerprint)).Scan(&id, &kind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RuleVersion{}, ErrNotFound
		}
		return RuleVersion{}, err
	}
	if kind == "disabled" {
		return RuleVersion{}, ErrNotFound
	}
	return r.getVersion(ctx, id)
}
func (r *PostgresRegistry) Metrics(ctx context.Context) (Metrics, error) {
	if err := checkContext(ctx); err != nil {
		return Metrics{}, err
	}
	if err := r.requireDB(); err != nil {
		return Metrics{}, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id FROM m6_rule_candidates ORDER BY id`)
	if err != nil {
		return Metrics{}, err
	}
	defer rows.Close()
	var m Metrics
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return Metrics{}, err
		}
		candidate, err := r.GetCandidate(ctx, id)
		if err != nil {
			return Metrics{}, err
		}
		m.Candidates++
		switch candidate.Status {
		case StatusDraft:
			m.Draft++
		case StatusTesting:
			m.Testing++
		case StatusReviewed:
			m.Reviewed++
		case StatusShadow:
			m.Shadow++
		case StatusApproved:
			m.Approved++
		case StatusPromoted:
			m.Promoted++
		}
		m.Observations += candidate.SuccessCount
	}
	if err := rows.Err(); err != nil {
		return Metrics{}, err
	}
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM m6_rule_versions`).Scan(&m.Versions); err != nil {
		return Metrics{}, err
	}
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM m6_rule_registry_events WHERE kind='rollback'`).Scan(&m.Rollbacks); err != nil {
		return Metrics{}, err
	}
	return m, nil
}

func mustJSON(value any) []byte { data, _ := json.Marshal(value); return data }

var _ Registry = (*PostgresRegistry)(nil)
var _ = time.Time{}
