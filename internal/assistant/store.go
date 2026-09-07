package assistant

import (
	"context"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

// Store is the durability boundary. CreateOrReplayRun, ClaimNextRun,
// FinishRun, AbortSessionRuns, and RecoverInterrupted must each be atomic with
// their corresponding event append. A durable implementation must never
// automatically resubmit recovered accepted/running runs. ClaimNextRun must
// refuse a claim while that session already has a running run, including when
// separate service processes race.
type Store interface {
	CreateSession(context.Context, Actor, Session) error
	ListSessions(context.Context, Actor) ([]Session, error)
	GetSession(context.Context, Actor, domain.ID) (Session, error)
	CreateOrReplayRun(context.Context, Actor, domain.ID, string, string, Run, time.Time) (Run, bool, error)
	ClaimNextRun(context.Context, domain.ID, time.Time) (Run, bool, error)
	AppendEvent(context.Context, domain.ID, domain.ID, EventType, string, time.Time) (Event, error)
	FinishRun(context.Context, domain.ID, domain.ID, RunStatus, time.Time) (Run, error)
	AbortSessionRuns(context.Context, Actor, domain.ID, time.Time) (int, error)
	EventsAfter(context.Context, Actor, domain.ID, uint64, int) (EventSnapshot, error)
	RecoverInterrupted(context.Context, time.Time) (int, error)
}

type RunnerRun struct {
	RunID     domain.ID
	SessionID domain.ID
	Actor     Actor
	Scope     Scope
	Message   string
}

type RunnerEventKind string

const (
	RunnerDelta   RunnerEventKind = "delta"
	RunnerMessage RunnerEventKind = "message"
)

// RunnerEvent deliberately has no provider error, tool arguments, raw event,
// environment, or credential field.
type RunnerEvent struct {
	Kind RunnerEventKind
	Text string
}

type RunnerAbort struct {
	SessionID  domain.ID
	ClearQueue bool
}

// Start must honor startCtx, synchronously register one run, and return a
// handle whose Wait blocks until it finishes under runCtx. Service serializes
// starts per session. Abort interrupts the active run and clears any
// provider-side queue when ClearQueue is true.
type Runner interface {
	Start(context.Context, context.Context, RunnerRun, func(RunnerEvent) error) (RunnerHandle, error)
	Abort(context.Context, RunnerAbort) error
}

// RunnerHandle waits for an already-started run. Start must synchronously
// register the run before returning the handle, so session Abort cannot race a
// provider process that has not yet become abortable.
type RunnerHandle interface{ Wait() error }
