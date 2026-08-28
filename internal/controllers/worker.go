// Package controllers contains deterministic control-plane workers. They
// coordinate durable leases with bounded handlers and never expose arbitrary
// host commands or infrastructure APIs.
package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type WorkerStore interface {
	ClaimControllerTask(context.Context, postgres.ClaimTaskRequest) (postgres.ControllerTask, bool, error)
	StartControllerTask(context.Context, domain.ID, string, time.Time) (application.Event, error)
	RenewTaskLease(context.Context, domain.ID, string, time.Time, time.Duration) error
	RecordAgentEvent(context.Context, postgres.AgentEventRequest) (postgres.AgentEventResult, error)
	FinishControllerTask(context.Context, postgres.FinishControllerTaskRequest) (postgres.FinishControllerTaskResult, error)
	FailControllerTask(context.Context, postgres.FailControllerTaskRequest) (postgres.FinishControllerTaskResult, error)
}

type TaskHandler interface {
	Execute(context.Context, postgres.ControllerTask, *TaskReporter) HandlerResult
}

type HandlerResult struct {
	Outcome       postgres.ControllerTaskOutcome
	Retryable     bool
	FailureReason string
	EvidenceIDs   []string
	Err           error
}

type Worker struct {
	Store         WorkerStore
	Handler       TaskHandler
	Owner         string
	Kinds         []string
	LeaseDuration time.Duration
	RenewInterval time.Duration
	MaxAttempts   int
	IdlePoll      time.Duration
	Clock         func() time.Time
}

func (w *Worker) normalize() error {
	if w.Store == nil || w.Handler == nil {
		return errors.New("controller worker requires store and handler")
	}
	if w.Owner == "" {
		return errors.New("controller worker owner is required")
	}
	if w.LeaseDuration <= 0 {
		w.LeaseDuration = 30 * time.Second
	}
	if w.RenewInterval <= 0 {
		w.RenewInterval = 10 * time.Second
	}
	if w.RenewInterval >= w.LeaseDuration {
		return errors.New("controller renew interval must be shorter than lease duration")
	}
	if w.MaxAttempts <= 0 {
		w.MaxAttempts = 3
	}
	if w.IdlePoll <= 0 {
		w.IdlePoll = 250 * time.Millisecond
	}
	if w.Clock == nil {
		w.Clock = time.Now
	}
	return nil
}

// RunOne claims and resolves at most one task. The returned boolean indicates
// whether a task was claimed. A process crash before resolution leaves the
// lease durable; a new owner can take it over after expiry.
func (w *Worker) RunOne(ctx context.Context) (bool, error) {
	if err := w.normalize(); err != nil {
		return false, err
	}
	claimed, ok, err := w.Store.ClaimControllerTask(ctx, postgres.ClaimTaskRequest{
		Owner: w.Owner,
		Now:   w.Clock().UTC(),
		Kinds: append([]string(nil), w.Kinds...),
		LeasePolicy: postgres.LeasePolicy{
			Duration:    w.LeaseDuration,
			MaxAttempts: w.MaxAttempts,
		},
	})
	if err != nil || !ok {
		return ok, err
	}
	if _, err := w.Store.StartControllerTask(ctx, claimed.Task.ID, w.Owner, w.Clock().UTC()); err != nil {
		return true, err
	}

	taskContext, cancel := context.WithCancel(ctx)
	renewDone := make(chan struct{})
	renewErrors := make(chan error, 1)
	go w.renewLease(taskContext, claimed.Task.ID, cancel, renewDone, renewErrors)

	reporter := newTaskReporter(w.Store, claimed.Task.ID, w.Owner, claimed.Task.LastAgentSequence, w.Clock)
	result := executeHandler(taskContext, w.Handler, claimed, reporter)
	cancel()
	<-renewDone
	select {
	case renewErr := <-renewErrors:
		if renewErr != nil {
			return true, renewErr
		}
	default:
	}

	now := w.Clock().UTC()
	if result.Err != nil {
		_, err := w.Store.FailControllerTask(ctx, postgres.FailControllerTaskRequest{
			TaskID:        claimed.Task.ID,
			Owner:         w.Owner,
			Now:           now,
			Retryable:     result.Retryable,
			FailureReason: chooseFailureReason(result),
			EvidenceIDs:   append([]string(nil), result.EvidenceIDs...),
		})
		return true, err
	}
	if result.Outcome == "" {
		result.Outcome = postgres.ControllerTaskSucceeded
	}
	_, err = w.Store.FinishControllerTask(ctx, postgres.FinishControllerTaskRequest{
		TaskID:        claimed.Task.ID,
		Owner:         w.Owner,
		Now:           now,
		Outcome:       result.Outcome,
		FailureReason: result.FailureReason,
		EvidenceIDs:   append([]string(nil), result.EvidenceIDs...),
	})
	return true, err
}

func (w *Worker) Run(ctx context.Context) error {
	if err := w.normalize(); err != nil {
		return err
	}
	for {
		worked, err := w.RunOne(ctx)
		if err != nil {
			return err
		}
		if worked {
			continue
		}
		timer := time.NewTimer(w.IdlePoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (w *Worker) renewLease(ctx context.Context, taskID domain.ID, cancel context.CancelFunc, done chan<- struct{}, failures chan<- error) {
	defer close(done)
	ticker := time.NewTicker(w.RenewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.Store.RenewTaskLease(ctx, taskID, w.Owner, w.Clock().UTC(), w.LeaseDuration); err != nil {
				select {
				case failures <- err:
				default:
				}
				cancel()
				return
			}
		}
	}
}

type TaskReporter struct {
	store    WorkerStore
	taskID   domain.ID
	owner    string
	clock    func() time.Time
	mu       sync.Mutex
	sequence uint64
}

func newTaskReporter(store WorkerStore, taskID domain.ID, owner string, lastSequence uint64, clock func() time.Time) *TaskReporter {
	return &TaskReporter{store: store, taskID: taskID, owner: owner, sequence: lastSequence, clock: clock}
}

func (r *TaskReporter) Emit(ctx context.Context, kind string, payload any) (postgres.AgentEventResult, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return postgres.AgentEventResult{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	next := r.sequence + 1
	result, err := r.store.RecordAgentEvent(ctx, postgres.AgentEventRequest{
		TaskID: r.taskID, Owner: r.owner, Now: r.clock().UTC(), Sequence: next, Kind: kind, Payload: encoded,
	})
	if err != nil {
		return postgres.AgentEventResult{}, err
	}
	r.sequence = next
	return result, nil
}

func executeHandler(ctx context.Context, handler TaskHandler, task postgres.ControllerTask, reporter *TaskReporter) (result HandlerResult) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = HandlerResult{Err: fmt.Errorf("task handler panic: %v", recovered), Retryable: true, FailureReason: "task handler failed unexpectedly"}
		}
	}()
	return handler.Execute(ctx, task, reporter)
}

func chooseFailureReason(result HandlerResult) string {
	if result.FailureReason != "" {
		return result.FailureReason
	}
	if result.Err != nil {
		return result.Err.Error()
	}
	return "task failed"
}
