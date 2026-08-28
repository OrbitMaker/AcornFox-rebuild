package controllers

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

func TestWorkerNormalizeDefaultsAndValidation(t *testing.T) {
	clock := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	worker := Worker{Store: &fakeWorkerStore{}, Handler: workerHandlerFunc(func(context.Context, postgres.ControllerTask, *TaskReporter) HandlerResult {
		return HandlerResult{}
	}), Owner: "worker-1", Clock: clock}

	if err := worker.normalize(); err != nil {
		t.Fatal(err)
	}
	if worker.LeaseDuration != 30*time.Second {
		t.Fatalf("default lease duration = %s, want 30s", worker.LeaseDuration)
	}
	if worker.RenewInterval != 10*time.Second {
		t.Fatalf("default renew interval = %s, want 10s", worker.RenewInterval)
	}
	if worker.MaxAttempts != 3 {
		t.Fatalf("default max attempts = %d, want 3", worker.MaxAttempts)
	}
	if worker.IdlePoll != 250*time.Millisecond {
		t.Fatalf("default idle poll = %s, want 250ms", worker.IdlePoll)
	}
	if worker.Clock == nil || worker.Clock() != clock() {
		t.Fatal("normalize should preserve a configured clock")
	}

	for name, invalid := range map[string]Worker{
		"missing store":   {Handler: worker.Handler, Owner: "worker-1"},
		"missing handler": {Store: worker.Store, Owner: "worker-1"},
		"missing owner":   {Store: worker.Store, Handler: worker.Handler},
		"renew equals lease": {
			Store: &fakeWorkerStore{}, Handler: worker.Handler, Owner: "worker-1",
			LeaseDuration: time.Second, RenewInterval: time.Second,
		},
		"renew longer than lease": {
			Store: &fakeWorkerStore{}, Handler: worker.Handler, Owner: "worker-1",
			LeaseDuration: time.Second, RenewInterval: 2 * time.Second,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := invalid.normalize(); err == nil {
				t.Fatal("expected worker validation to fail")
			}
		})
	}
}

func TestWorkerRunOneSuccessfulTaskOrdersEventsAndResumesSequence(t *testing.T) {
	store := &fakeWorkerStore{
		task: postgres.ControllerTask{Task: postgres.Task{
			ID:                domain.ID("task_1"),
			LastAgentSequence: 7,
		}},
		claimOK: true,
	}
	worker := newTestWorker(store, workerHandlerFunc(func(ctx context.Context, task postgres.ControllerTask, reporter *TaskReporter) HandlerResult {
		if task.Task.ID != domain.ID("task_1") {
			t.Errorf("handler task = %s, want task_1", task.Task.ID)
		}
		if _, err := reporter.Emit(ctx, "agent.started", map[string]string{"phase": "start"}); err != nil {
			t.Fatalf("emit start event: %v", err)
		}
		if _, err := reporter.Emit(ctx, "agent.finished", map[string]string{"phase": "finish"}); err != nil {
			t.Fatalf("emit finish event: %v", err)
		}
		return HandlerResult{EvidenceIDs: []string{"evidence_1"}}
	}))

	worked, err := worker.RunOne(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !worked {
		t.Fatal("RunOne reported that no task was claimed")
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if want, got := []string{"claim", "start", "agent:agent.started", "agent:agent.finished", "finish"}, store.calls; !reflect.DeepEqual(got, want) {
		t.Fatalf("store call order = %#v, want %#v", got, want)
	}
	if got := []uint64{store.agentEvents[0].Sequence, store.agentEvents[1].Sequence}; !reflect.DeepEqual(got, []uint64{8, 9}) {
		t.Fatalf("agent event sequence = %#v, want [8 9]", got)
	}
	if got := store.finishRequests[0].Outcome; got != postgres.ControllerTaskSucceeded {
		t.Fatalf("finish outcome = %q, want %q", got, postgres.ControllerTaskSucceeded)
	}
	if got := store.finishRequests[0].EvidenceIDs; !reflect.DeepEqual(got, []string{"evidence_1"}) {
		t.Fatalf("finish evidence ids = %#v, want [evidence_1]", got)
	}
}

func TestWorkerRunOneRetryableHandlerErrorFailsTaskAsRetryable(t *testing.T) {
	store := &fakeWorkerStore{
		task:    postgres.ControllerTask{Task: postgres.Task{ID: domain.ID("task_2")}},
		claimOK: true,
	}
	handlerErr := errors.New("temporary agent outage")
	worker := newTestWorker(store, workerHandlerFunc(func(context.Context, postgres.ControllerTask, *TaskReporter) HandlerResult {
		return HandlerResult{
			Err:           handlerErr,
			Retryable:     true,
			FailureReason: "agent unavailable",
			EvidenceIDs:   []string{"evidence_retry"},
		}
	}))

	worked, err := worker.RunOne(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !worked {
		t.Fatal("RunOne reported that no task was claimed")
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.failRequests) != 1 {
		t.Fatalf("fail requests = %d, want 1", len(store.failRequests))
	}
	failure := store.failRequests[0]
	if !failure.Retryable {
		t.Fatal("handler failure should be marked retryable")
	}
	if failure.FailureReason != "agent unavailable" {
		t.Fatalf("failure reason = %q, want agent unavailable", failure.FailureReason)
	}
	if !reflect.DeepEqual(failure.EvidenceIDs, []string{"evidence_retry"}) {
		t.Fatalf("failure evidence ids = %#v, want [evidence_retry]", failure.EvidenceIDs)
	}
	if len(store.finishRequests) != 0 {
		t.Fatal("retryable handler error must not finish the task")
	}
}

func TestWorkerRunOneHandlerPanicBecomesRetryableFailure(t *testing.T) {
	store := &fakeWorkerStore{
		task:    postgres.ControllerTask{Task: postgres.Task{ID: domain.ID("task_3")}},
		claimOK: true,
	}
	worker := newTestWorker(store, workerHandlerFunc(func(context.Context, postgres.ControllerTask, *TaskReporter) HandlerResult {
		panic("unexpected handler panic")
	}))

	worked, err := worker.RunOne(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !worked {
		t.Fatal("RunOne reported that no task was claimed")
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.failRequests) != 1 {
		t.Fatalf("fail requests = %d, want 1", len(store.failRequests))
	}
	failure := store.failRequests[0]
	if !failure.Retryable {
		t.Fatal("panic failure should be marked retryable")
	}
	if failure.FailureReason != "task handler failed unexpectedly" {
		t.Fatalf("failure reason = %q, want task handler failed unexpectedly", failure.FailureReason)
	}
	if len(store.finishRequests) != 0 {
		t.Fatal("panic must not finish the task")
	}
}

func TestWorkerRunOneRenewalFailureCancelsHandlerAndReturnsError(t *testing.T) {
	store := &fakeWorkerStore{
		task:        postgres.ControllerTask{Task: postgres.Task{ID: domain.ID("task_4")}},
		claimOK:     true,
		renewErr:    errors.New("lease renewal failed"),
		renewCalled: make(chan struct{}),
	}
	handlerStarted := make(chan struct{})
	handlerCancelled := make(chan struct{})
	worker := newTestWorker(store, workerHandlerFunc(func(ctx context.Context, _ postgres.ControllerTask, _ *TaskReporter) HandlerResult {
		close(handlerStarted)
		<-ctx.Done()
		close(handlerCancelled)
		return HandlerResult{Err: ctx.Err(), Retryable: true}
	}))
	worker.RenewInterval = time.Nanosecond
	worker.LeaseDuration = time.Second

	type runResult struct {
		worked bool
		err    error
	}
	resultCh := make(chan runResult, 1)
	go func() {
		worked, err := worker.RunOne(context.Background())
		resultCh <- runResult{worked: worked, err: err}
	}()

	waitForWorkerSignal(t, handlerStarted, "handler start")
	waitForWorkerSignal(t, store.renewCalled, "lease renewal")
	waitForWorkerSignal(t, handlerCancelled, "handler cancellation")

	select {
	case result := <-resultCh:
		if !result.worked {
			t.Fatal("RunOne reported that no task was claimed")
		}
		if !errors.Is(result.err, store.renewErr) {
			t.Fatalf("RunOne error = %v, want renewal error %v", result.err, store.renewErr)
		}
	case <-time.After(time.Second):
		t.Fatal("RunOne did not return after renewal failure")
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.finishRequests) != 0 || len(store.failRequests) != 0 {
		t.Fatal("renewal failure should return before resolving the task")
	}
}

func TestWorkerRunExitsWhenIdleContextIsCancelled(t *testing.T) {
	store := &fakeWorkerStore{claimCalled: make(chan struct{})}
	worker := newTestWorker(store, workerHandlerFunc(func(context.Context, postgres.ControllerTask, *TaskReporter) HandlerResult {
		t.Fatal("idle worker should not execute a handler")
		return HandlerResult{}
	}))
	worker.IdlePoll = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultCh := make(chan error, 1)
	go func() { resultCh <- worker.Run(ctx) }()

	waitForWorkerSignal(t, store.claimCalled, "idle claim")
	cancel()
	select {
	case err := <-resultCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("idle Run did not exit after context cancellation")
	}
}

type workerHandlerFunc func(context.Context, postgres.ControllerTask, *TaskReporter) HandlerResult

func (f workerHandlerFunc) Execute(ctx context.Context, task postgres.ControllerTask, reporter *TaskReporter) HandlerResult {
	return f(ctx, task, reporter)
}

type fakeWorkerStore struct {
	mu sync.Mutex

	task    postgres.ControllerTask
	claimOK bool
	claimErr,
	startErr,
	renewErr,
	finishErr,
	failErr error

	claimCalled chan struct{}
	renewCalled chan struct{}
	claimOnce   sync.Once
	renewOnce   sync.Once

	calls          []string
	claimRequests  []postgres.ClaimTaskRequest
	startTaskIDs   []domain.ID
	renewTaskIDs   []domain.ID
	agentEvents    []postgres.AgentEventRequest
	finishRequests []postgres.FinishControllerTaskRequest
	failRequests   []postgres.FailControllerTaskRequest
}

func (s *fakeWorkerStore) ClaimControllerTask(_ context.Context, request postgres.ClaimTaskRequest) (postgres.ControllerTask, bool, error) {
	s.mu.Lock()
	s.calls = append(s.calls, "claim")
	s.claimRequests = append(s.claimRequests, request)
	task, ok, err := s.task, s.claimOK, s.claimErr
	s.mu.Unlock()
	if s.claimCalled != nil {
		s.claimOnce.Do(func() { close(s.claimCalled) })
	}
	return task, ok, err
}

func (s *fakeWorkerStore) StartControllerTask(_ context.Context, taskID domain.ID, _ string, _ time.Time) (application.Event, error) {
	s.mu.Lock()
	s.calls = append(s.calls, "start")
	s.startTaskIDs = append(s.startTaskIDs, taskID)
	err := s.startErr
	s.mu.Unlock()
	return application.Event{}, err
}

func (s *fakeWorkerStore) RenewTaskLease(_ context.Context, taskID domain.ID, _ string, _ time.Time, _ time.Duration) error {
	s.mu.Lock()
	s.renewTaskIDs = append(s.renewTaskIDs, taskID)
	err := s.renewErr
	s.mu.Unlock()
	if s.renewCalled != nil {
		s.renewOnce.Do(func() { close(s.renewCalled) })
	}
	return err
}

func (s *fakeWorkerStore) RecordAgentEvent(_ context.Context, request postgres.AgentEventRequest) (postgres.AgentEventResult, error) {
	s.mu.Lock()
	s.calls = append(s.calls, "agent:"+request.Kind)
	s.agentEvents = append(s.agentEvents, request)
	s.mu.Unlock()
	return postgres.AgentEventResult{}, nil
}

func (s *fakeWorkerStore) FinishControllerTask(_ context.Context, request postgres.FinishControllerTaskRequest) (postgres.FinishControllerTaskResult, error) {
	s.mu.Lock()
	s.calls = append(s.calls, "finish")
	s.finishRequests = append(s.finishRequests, request)
	err := s.finishErr
	s.mu.Unlock()
	return postgres.FinishControllerTaskResult{}, err
}

func (s *fakeWorkerStore) FailControllerTask(_ context.Context, request postgres.FailControllerTaskRequest) (postgres.FinishControllerTaskResult, error) {
	s.mu.Lock()
	s.calls = append(s.calls, "fail")
	s.failRequests = append(s.failRequests, request)
	err := s.failErr
	s.mu.Unlock()
	return postgres.FinishControllerTaskResult{}, err
}

func newTestWorker(store WorkerStore, handler TaskHandler) *Worker {
	return &Worker{
		Store:         store,
		Handler:       handler,
		Owner:         "worker-test",
		LeaseDuration: time.Second,
		RenewInterval: 100 * time.Millisecond,
		MaxAttempts:   3,
		IdlePoll:      time.Millisecond,
		Clock:         func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
}

func TestWorkerPassesItsClosedTaskKindSetToPersistence(t *testing.T) {
	store := &fakeWorkerStore{}
	worker := newTestWorker(store, workerHandlerFunc(func(context.Context, postgres.ControllerTask, *TaskReporter) HandlerResult { return HandlerResult{} }))
	worker.Kinds = []string{"application.create"}
	worked, err := worker.RunOne(context.Background())
	if err != nil || worked {
		t.Fatalf("empty filtered claim worked=%v err=%v", worked, err)
	}
	if len(store.claimRequests) != 1 || len(store.claimRequests[0].Kinds) != 1 || store.claimRequests[0].Kinds[0] != "application.create" {
		t.Fatalf("worker did not preserve its claim filter: %#v", store.claimRequests)
	}
}

func waitForWorkerSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}
