package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

// TaskState is the durable task lifecycle stored in task_leases.
type TaskState string

const (
	TaskReady     TaskState = "ready"
	TaskLeased    TaskState = "leased"
	TaskCompleted TaskState = "completed"
	TaskFailed    TaskState = "failed"
	TaskCancelled TaskState = "cancelled"
)

// Task is the persistence projection returned to workers. Payload is copied on
// read so callers cannot mutate a value retained by a repository cache (there
// is intentionally no cache today, but the ownership rule keeps the API
// stable).
type Task struct {
	ID                domain.ID
	OperationID       domain.ID
	LeaseOwner        string
	LeaseUntil        *time.Time
	Attempt           int
	MaxAttempts       int
	State             TaskState
	Payload           json.RawMessage
	CreatedAt         time.Time
	UpdatedAt         time.Time
	LastAgentSequence uint64
}

// LeasePolicy supplies worker lease semantics. The caller normally passes a
// 30-second Duration; the repository does not hide that engineering parameter
// in a package constant.
type LeasePolicy struct {
	Duration    time.Duration
	MaxAttempts int
}

// ClaimTaskRequest is the input to ClaimTask. Now is explicit so takeover and
// expiry tests are deterministic and all workers evaluate the same clock
// boundary.
type ClaimTaskRequest struct {
	Owner string
	Now   time.Time
	// Kinds limits a shared durable queue consumer to the exact payload kinds
	// it owns. An empty slice preserves the generic worker behavior. Agent and
	// control-plane workers must use disjoint non-empty sets so one consumer
	// cannot terminally reject another consumer's task.
	Kinds []string
	LeasePolicy
}

// TaskMutationRequest supplies owner-checked state transition parameters.
type TaskMutationRequest struct {
	TaskID domain.ID
	Owner  string
	Now    time.Time
	LeasePolicy
}

// FailTaskRequest adds a redacted, bounded failure reason to a lease mutation.
type FailTaskRequest struct {
	TaskMutationRequest
	Reason string
}

// ClaimTask atomically selects one ready or expired leased task using
// FOR UPDATE SKIP LOCKED, takes/renews its lease, and increments attempt.
// A false result means there is currently no claimable task. No task is
// returned after max attempts, so a caller cannot accidentally execute a task
// forever.
func (s *Store) ClaimTask(ctx context.Context, request ClaimTaskRequest) (Task, bool, error) {
	if err := s.requireDB(); err != nil {
		return Task{}, false, err
	}
	request.Owner = strings.TrimSpace(request.Owner)
	if request.Owner == "" {
		return Task{}, false, errors.New("task lease owner is required")
	}
	if request.Duration <= 0 {
		return Task{}, false, errors.New("task lease duration must be positive")
	}
	if request.MaxAttempts <= 0 {
		return Task{}, false, errors.New("task max attempts must be positive")
	}
	if request.Now.IsZero() {
		request.Now = s.now()
	}
	request.Now = request.Now.UTC()
	leaseUntil := request.Now.Add(request.Duration)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Task{}, false, fmt.Errorf("begin claim task transaction: %w", err)
	}
	rollback := func(cause error) (Task, bool, error) {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			return Task{}, false, fmt.Errorf("%w (rollback: %v)", cause, rollbackErr)
		}
		return Task{}, false, cause
	}
	var candidate Task
	var candidateLeaseOwner sql.NullString
	var candidateLeaseUntil sql.NullTime
	var candidatePayload []byte
	var candidateState string
	err = tx.QueryRowContext(ctx, `
		SELECT task_id, operation_id, lease_owner, lease_until, attempt,
		       max_attempts, state, payload, created_at, updated_at, last_agent_sequence
		  FROM task_leases
		 WHERE (
				(state = 'ready' AND attempt < LEAST(max_attempts, $2))
				OR (state = 'leased' AND lease_until IS NOT NULL AND lease_until <= $1
					AND attempt < LEAST(max_attempts, $2))
			   )
		 ORDER BY created_at, task_id
		 LIMIT 1
		 FOR UPDATE SKIP LOCKED
	`, request.Now, request.MaxAttempts).Scan(
		&candidate.ID, &candidate.OperationID, &candidateLeaseOwner, &candidateLeaseUntil,
		&candidate.Attempt, &candidate.MaxAttempts, &candidateState, &candidatePayload,
		&candidate.CreatedAt, &candidate.UpdatedAt, &candidate.LastAgentSequence,
	)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return Task{}, false, fmt.Errorf("%w: commit empty task claim: %v", ErrOutcomeUnknown, err)
		}
		return Task{}, false, nil
	}
	if err != nil {
		return rollback(fmt.Errorf("select claimable task: %w", err))
	}
	if !json.Valid(candidatePayload) {
		return rollback(fmt.Errorf("task %s payload is invalid JSON", candidate.ID))
	}
	_ = candidateLeaseOwner
	_ = candidateLeaseUntil
	_ = candidateState

	var claimed Task
	var claimedOwner sql.NullString
	var claimedUntil sql.NullTime
	var claimedPayload []byte
	var claimedState string
	if err := tx.QueryRowContext(ctx, `
		UPDATE task_leases
		   SET lease_owner = $2,
		       lease_until = $3,
		       attempt = attempt + 1,
		       max_attempts = LEAST(max_attempts, $4),
		       state = 'leased',
		       updated_at = $1
		 WHERE task_id = $5
		RETURNING task_id, operation_id, lease_owner, lease_until, attempt,
		          max_attempts, state, payload, created_at, updated_at, last_agent_sequence
	`, request.Now, request.Owner, leaseUntil, request.MaxAttempts, candidate.ID.String()).Scan(
		&claimed.ID, &claimed.OperationID, &claimedOwner, &claimedUntil, &claimed.Attempt,
		&claimed.MaxAttempts, &claimedState, &claimedPayload, &claimed.CreatedAt, &claimed.UpdatedAt, &claimed.LastAgentSequence,
	); err != nil {
		return rollback(fmt.Errorf("claim task %s: %w", candidate.ID, err))
	}
	claimed.LeaseOwner = claimedOwner.String
	if claimedUntil.Valid {
		value := claimedUntil.Time.UTC()
		claimed.LeaseUntil = &value
	}
	claimed.State = TaskState(claimedState)
	claimed.Payload = append(json.RawMessage(nil), claimedPayload...)
	claimed.CreatedAt = claimed.CreatedAt.UTC()
	claimed.UpdatedAt = claimed.UpdatedAt.UTC()
	if err := tx.Commit(); err != nil {
		return Task{}, false, fmt.Errorf("%w: commit task claim: %v", ErrOutcomeUnknown, err)
	}
	return claimed, true, nil
}

// ClaimNextTask is a positional convenience wrapper for worker loops.
func (s *Store) ClaimNextTask(ctx context.Context, owner string, now time.Time, leaseDuration time.Duration, maxAttempts int) (Task, bool, error) {
	return s.ClaimTask(ctx, ClaimTaskRequest{Owner: owner, Now: now, LeasePolicy: LeasePolicy{Duration: leaseDuration, MaxAttempts: maxAttempts}})
}

// GetTask reads a durable task by ID.
func (s *Store) GetTask(ctx context.Context, taskID domain.ID) (Task, error) {
	if err := s.requireDB(); err != nil {
		return Task{}, err
	}
	if err := domain.RequireID(taskID, "task id"); err != nil {
		return Task{}, err
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT task_id, operation_id, lease_owner, lease_until, attempt,
		       max_attempts, state, payload, created_at, updated_at, last_agent_sequence
		  FROM task_leases WHERE task_id = $1
	`, taskID.String())
	task, err := scanTask(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Task{}, ErrNotFound
	}
	if err != nil {
		return Task{}, fmt.Errorf("get task %s: %w", taskID, err)
	}
	return task, nil
}

// RenewTask extends an unexpired lease only when the owner matches.
func (s *Store) RenewTask(ctx context.Context, request TaskMutationRequest) error {
	request, err := normalizeMutation(request)
	if err != nil {
		return err
	}
	if request.Duration <= 0 {
		return errors.New("task lease duration must be positive")
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE task_leases
		   SET lease_until = $1, updated_at = $2
		 WHERE task_id = $3 AND state = 'leased' AND lease_owner = $4
		   AND lease_until IS NOT NULL AND lease_until > $2
	`, request.Now.Add(request.Duration), request.Now, request.TaskID.String(), request.Owner)
	if err != nil {
		return fmt.Errorf("renew task %s: %w", request.TaskID, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect task renewal: %w", err)
	}
	if rows != 1 {
		return ErrLeaseLost
	}
	return nil
}

// RenewTaskLease is a positional convenience wrapper.
func (s *Store) RenewTaskLease(ctx context.Context, taskID domain.ID, owner string, now time.Time, leaseDuration time.Duration) error {
	return s.RenewTask(ctx, TaskMutationRequest{TaskID: taskID, Owner: owner, Now: now, LeasePolicy: LeasePolicy{Duration: leaseDuration}})
}

// CompleteTask transitions an owned, unexpired leased task to completed.
func (s *Store) CompleteTask(ctx context.Context, request TaskMutationRequest) error {
	request, err := normalizeMutation(request)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE task_leases
		   SET state = 'completed', lease_owner = NULL, lease_until = NULL, updated_at = $1
		 WHERE task_id = $2 AND state = 'leased' AND lease_owner = $3
		   AND lease_until IS NOT NULL AND lease_until > $1
	`, request.Now, request.TaskID.String(), request.Owner)
	if err != nil {
		return fmt.Errorf("complete task %s: %w", request.TaskID, err)
	}
	return requireOneTaskMutation(result)
}

// CompleteTaskLease is a positional convenience wrapper.
func (s *Store) CompleteTaskLease(ctx context.Context, taskID domain.ID, owner string, now time.Time) error {
	return s.CompleteTask(ctx, TaskMutationRequest{TaskID: taskID, Owner: owner, Now: now})
}

// FailTask releases a leased task for retry until max attempts is reached,
// then permanently marks it failed. The owner and expiry are checked in the
// same UPDATE that changes state, preventing a stale worker from mutating a
// task after another worker has taken it over.
func (s *Store) FailTask(ctx context.Context, request FailTaskRequest) (TaskState, error) {
	mutation, err := normalizeMutation(request.TaskMutationRequest)
	if err != nil {
		return "", err
	}
	reason := strings.TrimSpace(request.Reason)
	if reason == "" {
		reason = "task failed"
	}
	var state string
	if err := s.db.QueryRowContext(ctx, `
		UPDATE task_leases
		   SET state = CASE
					WHEN attempt >= CASE WHEN $4 > 0 THEN LEAST(max_attempts, $4) ELSE max_attempts END
					THEN 'failed' ELSE 'ready' END,
		       lease_owner = NULL, lease_until = NULL, last_error = $1, updated_at = $2
		 WHERE task_id = $3 AND state = 'leased' AND lease_owner = $5
		   AND lease_until IS NOT NULL AND lease_until > $2
		RETURNING state
	`, reason, mutation.Now, mutation.TaskID.String(), mutation.MaxAttempts, mutation.Owner).Scan(&state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrLeaseLost
		}
		return "", fmt.Errorf("fail task %s: %w", mutation.TaskID, err)
	}
	return TaskState(state), nil
}

// FailTaskLease is a positional convenience wrapper.
func (s *Store) FailTaskLease(ctx context.Context, taskID domain.ID, owner string, now time.Time, reason string, maxAttempts int) (TaskState, error) {
	return s.FailTask(ctx, FailTaskRequest{TaskMutationRequest: TaskMutationRequest{TaskID: taskID, Owner: owner, Now: now, LeasePolicy: LeasePolicy{MaxAttempts: maxAttempts}}, Reason: reason})
}

// CancelTask transitions an owned, unexpired lease to cancelled.
func (s *Store) CancelTask(ctx context.Context, request TaskMutationRequest) error {
	request, err := normalizeMutation(request)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE task_leases
		   SET state = 'cancelled', lease_owner = NULL, lease_until = NULL, updated_at = $1
		 WHERE task_id = $2 AND state = 'leased' AND lease_owner = $3
		   AND lease_until IS NOT NULL AND lease_until > $1
	`, request.Now, request.TaskID.String(), request.Owner)
	if err != nil {
		return fmt.Errorf("cancel task %s: %w", request.TaskID, err)
	}
	return requireOneTaskMutation(result)
}

// CancelTaskLease is a positional convenience wrapper.
func (s *Store) CancelTaskLease(ctx context.Context, taskID domain.ID, owner string, now time.Time) error {
	return s.CancelTask(ctx, TaskMutationRequest{TaskID: taskID, Owner: owner, Now: now})
}

func normalizeMutation(request TaskMutationRequest) (TaskMutationRequest, error) {
	if err := domain.RequireID(request.TaskID, "task id"); err != nil {
		return TaskMutationRequest{}, err
	}
	request.Owner = strings.TrimSpace(request.Owner)
	if request.Owner == "" {
		return TaskMutationRequest{}, errors.New("task lease owner is required")
	}
	if request.Now.IsZero() {
		request.Now = time.Now()
	}
	request.Now = request.Now.UTC()
	if request.Duration <= 0 && request.Duration != 0 {
		return TaskMutationRequest{}, errors.New("task lease duration must be positive")
	}
	if request.Duration < 0 {
		return TaskMutationRequest{}, errors.New("task lease duration must not be negative")
	}
	return request, nil
}

func requireOneTaskMutation(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect task state mutation: %w", err)
	}
	if rows != 1 {
		return ErrLeaseLost
	}
	return nil
}

func scanTask(scanner interface{ Scan(...any) error }) (Task, error) {
	var task Task
	var owner sql.NullString
	var leaseUntil sql.NullTime
	var state string
	var payload []byte
	if err := scanner.Scan(&task.ID, &task.OperationID, &owner, &leaseUntil, &task.Attempt, &task.MaxAttempts, &state, &payload, &task.CreatedAt, &task.UpdatedAt, &task.LastAgentSequence); err != nil {
		return Task{}, err
	}
	if !json.Valid(payload) {
		return Task{}, errors.New("task payload is invalid JSON")
	}
	task.LeaseOwner = owner.String
	if leaseUntil.Valid {
		value := leaseUntil.Time.UTC()
		task.LeaseUntil = &value
	}
	task.State = TaskState(state)
	task.Payload = append(json.RawMessage(nil), payload...)
	task.CreatedAt = task.CreatedAt.UTC()
	task.UpdatedAt = task.UpdatedAt.UTC()
	return task, nil
}
