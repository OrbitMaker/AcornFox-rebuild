package contracts

import (
	"context"
	"encoding/json"
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
	CoreGeneration    int64
	LeaseGeneration   int64
	LastError         string
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
	// AllowedOperationStates optionally filters claimed tasks to those whose
	// parent operation state is in this set (e.g. pending, leased, running, cancelling).
	// An empty slice preserves the generic task claim behavior.
	AllowedOperationStates []string
	LeasePolicy
}

// TaskMutationRequest supplies owner-checked state transition parameters.
type TaskMutationRequest struct {
	TaskID          domain.ID
	CoreGeneration  int64
	LeaseGeneration int64
	Owner           string
	Now             time.Time
	LeasePolicy
}

// FailTaskRequest adds a redacted, bounded failure reason to a lease mutation.
type FailTaskRequest struct {
	TaskMutationRequest
	Reason string
}

// TaskRepository requires explicit fencing for every lease mutation.
// Nonempty Kinds scopes a consumer to its capabilities; an empty slice keeps
// the trusted controller generic queue behavior. Package dispatch must bind kinds.
type TaskRepository interface {
	ClaimTask(context.Context, ClaimTaskRequest) (Task, bool, error)
	GetTask(context.Context, domain.ID) (Task, error)
	RenewTask(context.Context, TaskMutationRequest) error
	CompleteTask(context.Context, TaskMutationRequest) error
	FailTask(context.Context, FailTaskRequest) (TaskState, error)
	CancelTask(context.Context, TaskMutationRequest) error
}
type OutboxRepository interface {
	AppendOutboxEvent(context.Context, OutboxEvent) (OutboxEvent, error)
	FetchOutboxAfter(context.Context, int64, int) ([]OutboxEvent, error)
	MarkOutboxPublished(context.Context, string, time.Time) (bool, error)
}
