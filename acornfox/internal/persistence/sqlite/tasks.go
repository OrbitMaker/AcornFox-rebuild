package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	contracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/foundation"
)

var _ contracts.TaskRepository = (*Store)(nil)

const taskColumns = `task_id, operation_id, lease_owner, lease_until, attempt, max_attempts, state, payload, created_at, updated_at, last_agent_sequence, core_generation, lease_generation, last_error`

func scanSQLiteTask(row interface{ Scan(...any) error }) (contracts.Task, error) {
	var t contracts.Task
	var owner, until sql.NullString
	var created, updated, state, payload string
	var sequence int64
	if err := row.Scan(&t.ID, &t.OperationID, &owner, &until, &t.Attempt, &t.MaxAttempts, &state, &payload, &created, &updated, &sequence, &t.CoreGeneration, &t.LeaseGeneration, &t.LastError); err != nil {
		return t, err
	}
	if !json.Valid([]byte(payload)) || sequence < 0 {
		return contracts.Task{}, fmt.Errorf("%w: corrupt task projection", ErrIdempotencyCorrupt)
	}
	var err error
	t.CreatedAt, err = ParseTime(created)
	if err != nil {
		return t, err
	}
	t.UpdatedAt, err = ParseTime(updated)
	if err != nil {
		return t, err
	}
	if until.Valid {
		v, e := ParseTime(until.String)
		if e != nil {
			return t, e
		}
		t.LeaseUntil = &v
	}
	t.LeaseOwner = owner.String
	t.State = contracts.TaskState(state)
	t.Payload = json.RawMessage(payload)
	t.LastAgentSequence = uint64(sequence)
	return t, nil
}

// ClaimTask serializes selection/update inside the store's single write connection.
// Reopening with a new core generation can reclaim an old lease immediately;
// neither reopening nor same-owner reacquisition resets its attempt budget.
func (s *Store) ClaimTask(ctx context.Context, r contracts.ClaimTaskRequest) (contracts.Task, bool, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.Task{}, false, err
	}
	r.Owner = strings.TrimSpace(r.Owner)
	kinds := []string{}
	seen := map[string]bool{}
	for _, k := range r.Kinds {
		k = strings.TrimSpace(k)
		if k == "" {
			return contracts.Task{}, false, domain.ValidationError("task kind must not be empty")
		}
		if !seen[k] {
			seen[k] = true
			kinds = append(kinds, k)
		}
	}
	if r.Owner == "" || r.Duration <= 0 || r.MaxAttempts <= 0 {
		return contracts.Task{}, false, domain.ValidationError("owner and positive lease policy are required")
	}
	if r.Now.IsZero() {
		r.Now = time.Now().UTC()
	}
	r.Now = r.Now.UTC()
	leaseUntil := r.Now.Add(r.Duration)
	if !leaseUntil.After(r.Now) {
		return contracts.Task{}, false, domain.ValidationError("lease deadline must advance")
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(kinds)), ",")
	kindFilter := ""
	if len(kinds) > 0 {
		kindFilter = " AND json_extract(payload,'$.kind') IN (" + placeholders + ")"
	}
	opStateFilter := ""
	opStateArgs := []any{}
	if len(r.AllowedOperationStates) > 0 {
		cleanStates := []string{}
		seenState := map[string]bool{}
		for _, st := range r.AllowedOperationStates {
			st = strings.TrimSpace(st)
			if st != "" && !seenState[st] {
				seenState[st] = true
				cleanStates = append(cleanStates, st)
			}
		}
		if len(cleanStates) > 0 {
			opPlaceholders := strings.TrimSuffix(strings.Repeat("?,", len(cleanStates)), ",")
			opStateFilter = " AND EXISTS (SELECT 1 FROM operations o WHERE o.id = task_leases.operation_id AND o.state IN (" + opPlaceholders + "))"
			for _, st := range cleanStates {
				opStateArgs = append(opStateArgs, st)
			}
		}
	}
	args := []any{r.MaxAttempts, FormatTime(r.Now), s.coreGeneration}
	for _, k := range kinds {
		args = append(args, k)
	}
	for _, a := range opStateArgs {
		args = append(args, a)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return contracts.Task{}, false, err
	}
	defer tx.Rollback()
	row := tx.QueryRowContext(ctx, `SELECT `+taskColumns+` FROM task_leases
 WHERE attempt < min(max_attempts,?) AND lease_generation < 9223372036854775807
 AND (state='ready' OR (state='leased' AND (lease_until <= ? OR core_generation < ?)))
`+kindFilter+opStateFilter+` ORDER BY created_at,task_id LIMIT 1`, args...)
	task, err := scanSQLiteTask(row)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return contracts.Task{}, false, fmt.Errorf("%w: commit empty task claim: %v", ErrOutcomeUnknown, err)
		}
		return contracts.Task{}, false, nil
	}
	if err != nil {
		return contracts.Task{}, false, err
	}
	updated := r.Now
	if updated.Before(task.CreatedAt) {
		updated = task.CreatedAt
	}
	claimed, err := scanSQLiteTask(tx.QueryRowContext(ctx, `UPDATE task_leases SET lease_owner=?,lease_until=?,attempt=attempt+1,max_attempts=min(max_attempts,?),state='leased',updated_at=?,core_generation=?,lease_generation=lease_generation+1 WHERE task_id=? RETURNING `+taskColumns, r.Owner, FormatTime(leaseUntil), r.MaxAttempts, FormatTime(updated), s.coreGeneration, task.ID.String()))
	if err != nil {
		return contracts.Task{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return contracts.Task{}, false, fmt.Errorf("%w: commit task claim: %v", ErrOutcomeUnknown, err)
	}
	return claimed, true, nil
}

func (s *Store) GetTask(ctx context.Context, id domain.ID) (contracts.Task, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.Task{}, err
	}
	if err := domain.RequireID(id, "task id"); err != nil {
		return contracts.Task{}, err
	}
	t, err := scanSQLiteTask(s.db.QueryRowContext(ctx, `SELECT `+taskColumns+` FROM task_leases WHERE task_id=?`, id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	return t, err
}

// verifyTaskLeaseTx checks DB core singleton and verifies that the task lease is live, leased,
// unexpired, and matches caller CoreGeneration, LeaseGeneration, and Owner inside an existing transaction.
func (s *Store) verifyTaskLeaseTx(ctx context.Context, tx *sql.Tx, r contracts.TaskMutationRequest) (contracts.Task, error) {
	if err := s.checkOpen(); err != nil {
		return contracts.Task{}, err
	}
	r.Owner = strings.TrimSpace(r.Owner)
	if err := domain.RequireID(r.TaskID, "task id"); err != nil {
		return contracts.Task{}, err
	}
	if r.Owner == "" || r.CoreGeneration <= 0 || r.LeaseGeneration <= 0 {
		return contracts.Task{}, domain.ValidationError("owner and both generation tokens are required")
	}
	if r.CoreGeneration != s.coreGeneration {
		return contracts.Task{}, contracts.ErrLeaseLost
	}
	var dbGen int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM core_generation WHERE singleton=1`).Scan(&dbGen); err != nil {
		return contracts.Task{}, fmt.Errorf("check core generation: %w", err)
	}
	if dbGen != s.coreGeneration {
		return contracts.Task{}, contracts.ErrLeaseLost
	}

	if r.Now.IsZero() {
		r.Now = time.Now().UTC()
	}
	r.Now = r.Now.UTC()

	row := tx.QueryRowContext(ctx, `SELECT `+taskColumns+` FROM task_leases WHERE task_id=?`, r.TaskID.String())
	task, err := scanSQLiteTask(row)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.Task{}, contracts.ErrLeaseLost
	}
	if err != nil {
		return contracts.Task{}, err
	}

	if task.State != contracts.TaskLeased || task.LeaseOwner != r.Owner ||
		task.CoreGeneration != r.CoreGeneration || task.LeaseGeneration != r.LeaseGeneration {
		return contracts.Task{}, contracts.ErrLeaseLost
	}
	if task.LeaseUntil == nil || !task.LeaseUntil.After(r.Now) {
		return contracts.Task{}, contracts.ErrLeaseLost
	}

	return task, nil
}

// mutateTaskTx executes task state mutation inside an existing transaction.
func (s *Store) mutateTaskTx(ctx context.Context, tx *sql.Tx, r contracts.TaskMutationRequest, state, reason string) (contracts.TaskState, error) {
	r.Owner = strings.TrimSpace(r.Owner)
	if r.Now.IsZero() {
		r.Now = time.Now().UTC()
	}
	r.Now = r.Now.UTC()

	if _, err := s.verifyTaskLeaseTx(ctx, tx, r); err != nil {
		return "", err
	}

	set := `state=?, lease_owner=NULL,lease_until=NULL,updated_at=max(updated_at,?)`
	args := []any{state, FormatTime(r.Now)}
	if state == "renew" {
		if r.Duration <= 0 {
			return "", domain.ValidationError("lease renewal duration must be positive")
		}
		until := r.Now.Add(r.Duration)
		if !until.After(r.Now) {
			return "", domain.ValidationError("lease deadline must advance")
		}
		set = `lease_until=max(lease_until,?),updated_at=max(updated_at,?)`
		args = []any{FormatTime(until), FormatTime(r.Now)}
	} else if state == "retry" {
		set = `state=CASE WHEN attempt < min(max_attempts,CASE WHEN ? > 0 THEN ? ELSE max_attempts END) THEN 'ready' ELSE 'failed' END,max_attempts=min(max_attempts,CASE WHEN ? > 0 THEN ? ELSE max_attempts END),lease_owner=NULL,lease_until=NULL,last_error=?,updated_at=max(updated_at,?)`
		args = []any{r.MaxAttempts, r.MaxAttempts, r.MaxAttempts, r.MaxAttempts, reason, FormatTime(r.Now)}
	}
	args = append(args, r.TaskID.String(), r.Owner, FormatTime(r.Now), r.CoreGeneration, r.LeaseGeneration)
	var result string
	err := tx.QueryRowContext(ctx, `UPDATE task_leases SET `+set+` WHERE task_id=? AND state='leased' AND lease_owner=? AND lease_until>? AND core_generation=? AND lease_generation=? RETURNING state`, args...).Scan(&result)
	if errors.Is(err, sql.ErrNoRows) {
		return "", contracts.ErrLeaseLost
	}
	if err != nil {
		return "", err
	}
	return contracts.TaskState(result), nil
}

// mutateTask is the only SQLite lease mutation path. Both tokens are mandatory.
func (s *Store) mutateTask(ctx context.Context, r contracts.TaskMutationRequest, state, reason string) (contracts.TaskState, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	res, err := s.mutateTaskTx(ctx, tx, r, state, reason)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("%w: commit task mutation: %v", ErrOutcomeUnknown, err)
	}
	return res, nil
}
func (s *Store) RenewTask(ctx context.Context, r contracts.TaskMutationRequest) error {
	_, err := s.mutateTask(ctx, r, "renew", "")
	return err
}
func (s *Store) CompleteTask(ctx context.Context, r contracts.TaskMutationRequest) error {
	_, err := s.mutateTask(ctx, r, "completed", "")
	return err
}
func (s *Store) CancelTask(ctx context.Context, r contracts.TaskMutationRequest) error {
	_, err := s.mutateTask(ctx, r, "cancelled", "")
	return err
}
func cleanLastErrorReason(raw string) string {
	reason := strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(foundation.RedactText(raw), "�")))
	if reason == "" {
		reason = "task failed"
	}
	// Bound by bytes as well as SQLite's character limit, preserving UTF-8.
	if len(reason) > 1024 {
		reason = reason[:1024]
		for !utf8.ValidString(reason) {
			reason = reason[:len(reason)-1]
		}
	}
	return reason
}

func (s *Store) FailTask(ctx context.Context, r contracts.FailTaskRequest) (contracts.TaskState, error) {
	return s.mutateTask(ctx, r.TaskMutationRequest, "retry", cleanLastErrorReason(r.Reason))
}
