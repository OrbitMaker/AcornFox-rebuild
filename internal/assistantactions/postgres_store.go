package assistantactions

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/open-card/open-card/internal/assistant"
	"github.com/open-card/open-card/internal/domain"
)

type PostgresStore struct{ DB *sql.DB }

func NewPostgresStore(db *sql.DB) *PostgresStore { return &PostgresStore{DB: db} }

const proposalColumns = `id,owner_admin_id,assistant_session_id,assistant_run_id,proposal_key,request_digest,execution_key,action,application_id,deployment_id,target_release_id,target_release_version,safe_application_name,state,COALESCE(operation_id,''),verification_state,verification_verdict,verification_observed_at,expires_at,created_at,updated_at`

func (s *PostgresStore) GetPrepared(ctx context.Context, actor assistant.Actor, key, requestDigest string) (Proposal, bool, error) {
	if s == nil || s.DB == nil || actor.AdminID.Empty() {
		return Proposal{}, false, ErrInvalid
	}
	p, err := scanProposal(s.DB.QueryRowContext(ctx, `SELECT `+proposalColumns+` FROM acornfox_assistant_actions WHERE proposal_key=$1`, key))
	if errors.Is(err, sql.ErrNoRows) {
		return Proposal{}, false, nil
	}
	if err != nil {
		return Proposal{}, false, ErrUnavailable
	}
	if p.owner.AdminID != actor.AdminID || subtle.ConstantTimeCompare([]byte(p.requestDigest), []byte(requestDigest)) != 1 {
		return Proposal{}, false, ErrConflict
	}
	return p, true, nil
}

func (s *PostgresStore) ResolveExact(ctx context.Context, appID, deploymentID domain.ID) (Target, error) {
	if s == nil || s.DB == nil || appID.Empty() || deploymentID.Empty() {
		return Target{}, ErrInvalid
	}
	var target Target
	var name string
	err := s.DB.QueryRowContext(ctx, `SELECT a.id,d.id,r.id,r.version,a.name FROM deployments d JOIN environments e ON e.id=d.environment_id JOIN applications a ON a.id=e.application_id JOIN releases r ON r.id=d.release_id AND r.application_id=a.id WHERE a.id=$1 AND d.id=$2`, appID.String(), deploymentID.String()).Scan(&target.ApplicationID, &target.DeploymentID, &target.ReleaseID, &target.ReleaseVersion, &name)
	if errors.Is(err, sql.ErrNoRows) {
		return Target{}, ErrNotFound
	}
	if err != nil {
		return Target{}, ErrUnavailable
	}
	safe, ok := safeApplicationName(name)
	if !ok {
		return Target{}, ErrUnavailable
	}
	target.ApplicationName = safe
	return target, nil
}

func (s *PostgresStore) PrepareOrReplay(ctx context.Context, actor assistant.Actor, p Proposal) (Proposal, bool, error) {
	if s == nil || s.DB == nil || actor.AdminID.Empty() || !validTarget(p.Target) {
		return Proposal{}, false, ErrInvalid
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Proposal{}, false, ErrUnavailable
	}
	defer tx.Rollback()
	var owns bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM acornfox_assistant_runs r JOIN acornfox_assistant_sessions s ON s.id=r.session_id WHERE s.id=$1 AND r.id=$2 AND s.owner_admin_id=$3)`, p.SessionID.String(), p.RunID.String(), actor.AdminID.String()).Scan(&owns)
	if err != nil {
		return Proposal{}, false, ErrUnavailable
	}
	if !owns {
		return Proposal{}, false, ErrNotFound
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO acornfox_assistant_actions(id,owner_admin_id,assistant_session_id,assistant_run_id,proposal_key,request_digest,execution_key,action,application_id,deployment_id,target_release_id,target_release_version,safe_application_name,state,expires_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'pending',$14,$15,$15) ON CONFLICT(proposal_key) DO NOTHING`, p.ID.String(), actor.AdminID.String(), p.SessionID.String(), p.RunID.String(), p.proposalKey, p.requestDigest, p.executionKey, string(p.Action), p.Target.ApplicationID.String(), p.Target.DeploymentID.String(), p.Target.ReleaseID.String(), p.Target.ReleaseVersion, p.Target.ApplicationName, p.ExpiresAt.UTC(), p.CreatedAt.UTC())
	if err != nil {
		return Proposal{}, false, ErrUnavailable
	}
	stored, err := scanProposal(tx.QueryRowContext(ctx, `SELECT `+proposalColumns+` FROM acornfox_assistant_actions WHERE proposal_key=$1`, p.proposalKey))
	if err != nil {
		return Proposal{}, false, ErrUnavailable
	}
	if stored.owner.AdminID != actor.AdminID || subtle.ConstantTimeCompare([]byte(stored.requestDigest), []byte(p.requestDigest)) != 1 {
		return Proposal{}, false, ErrConflict
	}
	if err = tx.Commit(); err != nil {
		return Proposal{}, false, ErrUnavailable
	}
	return stored, stored.ID != p.ID || stored.CreatedAt != p.CreatedAt, nil
}

func (s *PostgresStore) List(ctx context.Context, actor assistant.Actor, sid domain.ID, now time.Time) ([]Proposal, error) {
	if s == nil || s.DB == nil || actor.AdminID.Empty() || sid.Empty() {
		return nil, ErrInvalid
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `UPDATE acornfox_assistant_actions SET state='expired',updated_at=$3 WHERE owner_admin_id=$1 AND assistant_session_id=$2 AND state='pending' AND expires_at<=$3`, actor.AdminID.String(), sid.String(), now.UTC())
	if err != nil {
		return nil, ErrUnavailable
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+proposalColumns+` FROM acornfox_assistant_actions WHERE owner_admin_id=$1 AND assistant_session_id=$2 ORDER BY created_at,id`, actor.AdminID.String(), sid.String())
	if err != nil {
		return nil, ErrUnavailable
	}
	items := []Proposal{}
	for rows.Next() {
		p, e := scanProposal(rows)
		if e != nil {
			rows.Close()
			return nil, ErrUnavailable
		}
		items = append(items, p)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, ErrUnavailable
	}
	if err = rows.Close(); err != nil {
		return nil, ErrUnavailable
	}
	if err = tx.Commit(); err != nil {
		return nil, ErrUnavailable
	}
	return items, nil
}

func (s *PostgresStore) Reject(ctx context.Context, actor assistant.Actor, sid, id domain.ID, now time.Time) (Proposal, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Proposal{}, ErrUnavailable
	}
	defer tx.Rollback()
	p, err := scanProposal(tx.QueryRowContext(ctx, `SELECT `+proposalColumns+` FROM acornfox_assistant_actions WHERE id=$1 FOR UPDATE`, id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return Proposal{}, ErrNotFound
	}
	if err != nil {
		return Proposal{}, ErrUnavailable
	}
	if p.owner.AdminID != actor.AdminID || p.SessionID != sid {
		return Proposal{}, ErrNotFound
	}
	if p.State == StateRejected {
		return p, nil
	}
	if p.State != StatePending {
		return Proposal{}, ErrConflict
	}
	state := StateRejected
	resultErr := error(nil)
	if !now.Before(p.ExpiresAt) {
		state = StateExpired
		resultErr = ErrExpired
	}
	_, err = tx.ExecContext(ctx, `UPDATE acornfox_assistant_actions SET state=$2,updated_at=$3 WHERE id=$1`, id.String(), string(state), now.UTC())
	if err != nil {
		return Proposal{}, ErrUnavailable
	}
	if err = tx.Commit(); err != nil {
		return Proposal{}, ErrUnavailable
	}
	p.State, p.UpdatedAt = state, now.UTC()
	return p, resultErr
}

func (s *PostgresStore) BeginExecution(ctx context.Context, actor assistant.Actor, sid, id domain.ID, current Target, now time.Time) (Proposal, bool, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Proposal{}, false, ErrUnavailable
	}
	defer tx.Rollback()
	p, err := scanProposal(tx.QueryRowContext(ctx, `SELECT `+proposalColumns+` FROM acornfox_assistant_actions WHERE id=$1 FOR UPDATE`, id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return Proposal{}, false, ErrNotFound
	}
	if err != nil {
		return Proposal{}, false, ErrUnavailable
	}
	if p.owner.AdminID != actor.AdminID || p.SessionID != sid {
		return Proposal{}, false, ErrNotFound
	}
	if p.State == StateExecuting || p.State == StateUnknown {
		return p, true, nil
	}
	if p.State != StatePending {
		return p, false, nil
	}
	if !now.Before(p.ExpiresAt) {
		return updateDecisionFailure(ctx, tx, p, StateExpired, "", now, ErrExpired)
	}
	if !p.Target.Equal(current) {
		return updateDecisionFailure(ctx, tx, p, StateExpired, "target_changed", now, ErrTargetChanged)
	}
	var occupied bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM acornfox_assistant_actions WHERE application_id=$1 AND id<>$2 AND state IN ('executing','accepted','unknown'))`, p.Target.ApplicationID.String(), p.ID.String()).Scan(&occupied); err != nil {
		return Proposal{}, false, ErrUnavailable
	}
	if occupied {
		return Proposal{}, false, ErrConflict
	}
	_, err = tx.ExecContext(ctx, `UPDATE acornfox_assistant_actions SET state='executing',updated_at=$2 WHERE id=$1`, p.ID.String(), now.UTC())
	if err != nil {
		return Proposal{}, false, ErrConflict
	}
	if err = tx.Commit(); err != nil {
		return Proposal{}, false, ErrUnavailable
	}
	p.State, p.UpdatedAt = StateExecuting, now.UTC()
	return p, true, nil
}
func updateDecisionFailure(ctx context.Context, tx *sql.Tx, p Proposal, state State, verdict string, now time.Time, cause error) (Proposal, bool, error) {
	_, err := tx.ExecContext(ctx, `UPDATE acornfox_assistant_actions SET state=$2,verification_state=CASE WHEN $3='' THEN verification_state ELSE 'failed' END,verification_verdict=$3,updated_at=$4 WHERE id=$1`, p.ID.String(), string(state), verdict, now.UTC())
	if err != nil {
		return Proposal{}, false, ErrUnavailable
	}
	if err = tx.Commit(); err != nil {
		return Proposal{}, false, ErrUnavailable
	}
	p.State, p.UpdatedAt = state, now.UTC()
	if verdict != "" {
		p.Verification = Verification{State: VerificationFailed, Verdict: verdict}
	}
	return p, false, cause
}

func (s *PostgresStore) FinishExecution(ctx context.Context, id, operationID domain.ID, state State, now time.Time) (Proposal, error) {
	if state != StateAccepted && state != StateUnknown && state != StateFailed {
		return Proposal{}, ErrInvalid
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Proposal{}, ErrUnavailable
	}
	defer tx.Rollback()
	p, err := scanProposal(tx.QueryRowContext(ctx, `SELECT `+proposalColumns+` FROM acornfox_assistant_actions WHERE id=$1 FOR UPDATE`, id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return Proposal{}, ErrNotFound
	}
	if err != nil {
		return Proposal{}, ErrUnavailable
	}
	if p.State == StateAccepted || p.State == StateFailed {
		return p, nil
	}
	if p.State != StateExecuting && p.State != StateUnknown {
		return Proposal{}, ErrConflict
	}
	_, err = tx.ExecContext(ctx, `UPDATE acornfox_assistant_actions SET state=$2,operation_id=COALESCE($3,operation_id),updated_at=$4 WHERE id=$1`, id.String(), string(state), nullableID(operationID), now.UTC())
	if err != nil {
		return Proposal{}, ErrUnavailable
	}
	if err = tx.Commit(); err != nil {
		return Proposal{}, ErrUnavailable
	}
	p.State, p.UpdatedAt = state, now.UTC()
	if !operationID.Empty() {
		p.OperationID = operationID
	}
	return p, nil
}
func (s *PostgresStore) FinishVerification(ctx context.Context, id, operationID domain.ID, v Verification, now time.Time) (Proposal, error) {
	if (v.State != VerificationVerified && v.State != VerificationFailed) || len(v.Verdict) > 256 {
		return Proposal{}, ErrInvalid
	}
	state := StateVerified
	if v.State == VerificationFailed {
		state = StateFailed
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Proposal{}, ErrUnavailable
	}
	defer tx.Rollback()
	p, err := scanProposal(tx.QueryRowContext(ctx, `SELECT `+proposalColumns+` FROM acornfox_assistant_actions WHERE id=$1 FOR UPDATE`, id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return Proposal{}, ErrNotFound
	}
	if err != nil {
		return Proposal{}, ErrUnavailable
	}
	if p.OperationID != operationID {
		return Proposal{}, ErrNotFound
	}
	if p.State == StateVerified || p.State == StateFailed {
		return p, nil
	}
	if p.State != StateAccepted && p.State != StateUnknown {
		return Proposal{}, ErrConflict
	}
	_, err = tx.ExecContext(ctx, `UPDATE acornfox_assistant_actions SET state=$2,verification_state=$3,verification_verdict=$4,verification_observed_at=$5,updated_at=$6 WHERE id=$1`, id.String(), string(state), string(v.State), v.Verdict, v.ObservedAt, now.UTC())
	if err != nil {
		return Proposal{}, ErrUnavailable
	}
	if err = tx.Commit(); err != nil {
		return Proposal{}, ErrUnavailable
	}
	p.State, p.Verification, p.UpdatedAt = state, v, now.UTC()
	return p, nil
}

type scanner interface{ Scan(...any) error }

func scanProposal(row scanner) (Proposal, error) {
	var p Proposal
	var owner, action, state, verification string
	var operation string
	var observed sql.NullTime
	err := row.Scan(&p.ID, &owner, &p.SessionID, &p.RunID, &p.proposalKey, &p.requestDigest, &p.executionKey, &action, &p.Target.ApplicationID, &p.Target.DeploymentID, &p.Target.ReleaseID, &p.Target.ReleaseVersion, &p.Target.ApplicationName, &state, &operation, &verification, &p.Verification.Verdict, &observed, &p.ExpiresAt, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return Proposal{}, err
	}
	p.owner = assistant.Actor{AdminID: domain.ID(owner)}
	p.Action = Action(action)
	p.State = State(state)
	p.OperationID = domain.ID(operation)
	p.Verification.State = VerificationState(verification)
	if observed.Valid {
		at := observed.Time
		p.Verification.ObservedAt = &at
	}
	return p, nil
}
func nullableID(id domain.ID) any {
	if id.Empty() {
		return nil
	}
	return id.String()
}
func safeApplicationName(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || !utf8.ValidString(value) {
		return "", false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return value, true
}

var _ Store = (*PostgresStore)(nil)
var _ TargetResolver = (*PostgresStore)(nil)
