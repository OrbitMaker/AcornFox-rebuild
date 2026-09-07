package assistant

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

type fakeRunner struct {
	mu          sync.Mutex
	calls       []RunnerRun
	aborts      []RunnerAbort
	active      int
	maxActive   int
	started     chan RunnerRun
	permits     chan struct{}
	abortSignal chan struct{}
	emit        []RunnerEvent
	err         error
	abortOnce   sync.Once
	startGate   <-chan struct{}
	abortErr    error
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{started: make(chan RunnerRun, 32), permits: make(chan struct{}, 32), abortSignal: make(chan struct{})}
}

type fakeRunnerHandle struct{ result <-chan error }

func (h fakeRunnerHandle) Wait() error { return <-h.result }

func (r *fakeRunner) Start(_ context.Context, ctx context.Context, run RunnerRun, emit func(RunnerEvent) error) (RunnerHandle, error) {
	r.mu.Lock()
	r.calls = append(r.calls, run)
	r.active++
	if r.active > r.maxActive {
		r.maxActive = r.active
	}
	events, resultErr := append([]RunnerEvent(nil), r.emit...), r.err
	r.mu.Unlock()
	r.started <- run
	if r.startGate != nil {
		<-r.startGate
	}
	result := make(chan error, 1)
	go func() {
		for _, event := range events {
			if err := emit(event); err != nil {
				resultErr = err
				break
			}
		}
		select {
		case <-ctx.Done():
			resultErr = ctx.Err()
		case <-r.abortSignal:
			resultErr = context.Canceled
		case <-r.permits:
		}
		r.mu.Lock()
		r.active--
		r.mu.Unlock()
		result <- resultErr
	}()
	return fakeRunnerHandle{result: result}, nil
}

func (r *fakeRunner) Abort(_ context.Context, request RunnerAbort) error {
	r.mu.Lock()
	r.aborts = append(r.aborts, request)
	err := r.abortErr
	r.mu.Unlock()
	if err != nil {
		return err
	}
	r.abortOnce.Do(func() { close(r.abortSignal) })
	return nil
}

func (r *fakeRunner) counts() (calls, maxActive int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls), r.maxActive
}

func testService(t *testing.T, runner *fakeRunner, store *MemoryStore) (*Service, Actor) {
	t.Helper()
	service, err := NewService(Config{Store: store, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	return service, Actor{AdminID: "admin_owner"}
}

func createTestSession(t *testing.T, service *Service, actor Actor, scope Scope) Session {
	t.Helper()
	session, err := service.CreateSession(context.Background(), actor, scope)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func waitStarted(t *testing.T, runner *fakeRunner) RunnerRun {
	t.Helper()
	select {
	case run := <-runner.started:
		return run
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not start")
		return RunnerRun{}
	}
}

func waitRunEvent(t *testing.T, service *Service, actor Actor, sessionID string, kind EventType) EventSnapshot {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snapshot, err := service.Events(context.Background(), actor, domainID(sessionID), 0)
		if err == nil {
			for _, event := range snapshot.Events {
				if event.Type == kind {
					return snapshot
				}
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("event %q did not arrive", kind)
	return EventSnapshot{}
}

func domainID(value string) domain.ID { return domain.ID(value) }

func TestDuplicateRunReplayDoesNotResendRunner(t *testing.T) {
	runner := newFakeRunner()
	store := NewMemoryStore(MemoryStoreConfig{})
	service, actor := testService(t, runner, store)
	session := createTestSession(t, service, actor, Scope{Kind: ScopeHost})
	first, err := service.SubmitRun(context.Background(), actor, session.ID, "same-key", "inspect host health")
	if err != nil || first.Replay || first.Run.Status != RunAccepted {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	waitStarted(t, runner)
	replay, err := service.SubmitRun(context.Background(), actor, session.ID, "same-key", "inspect host health")
	if err != nil || !replay.Replay || replay.Run.ID != first.Run.ID {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	if _, err := service.SubmitRun(context.Background(), actor, session.ID, "same-key", "different message"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflict=%v", err)
	}
	runner.permits <- struct{}{}
	snapshot := waitRunEvent(t, service, actor, session.ID.String(), EventRunCompleted)
	if len(snapshot.Events) == 0 || snapshot.Events[0].Type != EventRunAccepted || snapshot.Events[0].Text != "inspect host health" {
		t.Fatalf("accepted user history=%+v", snapshot.Events)
	}
	if calls, _ := runner.counts(); calls != 1 {
		t.Fatalf("runner calls=%d", calls)
	}
}

func TestAbortWaitsForSynchronousRunnerRegistration(t *testing.T) {
	gate := make(chan struct{})
	runner := newFakeRunner()
	runner.startGate = gate
	store := NewMemoryStore(MemoryStoreConfig{})
	service, actor := testService(t, runner, store)
	session := createTestSession(t, service, actor, Scope{Kind: ScopeHost})
	if _, err := service.SubmitRun(context.Background(), actor, session.ID, "race", "registration race message"); err != nil {
		t.Fatal(err)
	}
	waitStarted(t, runner)
	abortResult := make(chan error, 1)
	go func() { _, err := service.Abort(context.Background(), actor, session.ID); abortResult <- err }()
	select {
	case err := <-abortResult:
		t.Fatalf("abort crossed Start registration gate: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(gate)
	select {
	case err := <-abortResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("abort did not finish after Start registration")
	}
	waitRunEvent(t, service, actor, session.ID.String(), EventRunAborted)
	if calls, _ := runner.counts(); calls != 1 {
		t.Fatalf("runner starts=%d", calls)
	}
}

func TestAbortUsesPerRunCancelAfterClearQueueFailure(t *testing.T) {
	runner := newFakeRunner()
	runner.abortErr = errors.New("provider abort failed with raw secret")
	store := NewMemoryStore(MemoryStoreConfig{})
	service, actor := testService(t, runner, store)
	session := createTestSession(t, service, actor, Scope{Kind: ScopeHost})
	if _, err := service.SubmitRun(context.Background(), actor, session.ID, "abort-fail", "keep running after failed abort"); err != nil {
		t.Fatal(err)
	}
	waitStarted(t, runner)
	if result, err := service.Abort(context.Background(), actor, session.ID); err != nil || result.Aborted != 1 {
		t.Fatalf("abort=%+v error=%v", result, err)
	}
	waitRunEvent(t, service, actor, session.ID.String(), EventRunAborted)
}

func TestRunsAreSerialAndInheritFixedAppScope(t *testing.T) {
	runner := newFakeRunner()
	store := NewMemoryStore(MemoryStoreConfig{})
	service, actor := testService(t, runner, store)
	scope := Scope{Kind: ScopeApp, AppID: "app_fixed"}
	session := createTestSession(t, service, actor, scope)
	if _, err := service.SubmitRun(context.Background(), actor, session.ID, "one", "first message"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SubmitRun(context.Background(), actor, session.ID, "two", "second message"); err != nil {
		t.Fatal(err)
	}
	first := waitStarted(t, runner)
	if first.Scope != scope {
		t.Fatalf("scope=%+v", first.Scope)
	}
	time.Sleep(20 * time.Millisecond)
	if calls, max := runner.counts(); calls != 1 || max != 1 {
		t.Fatalf("before release calls=%d max=%d", calls, max)
	}
	runner.permits <- struct{}{}
	second := waitStarted(t, runner)
	if second.Scope != scope {
		t.Fatalf("second scope=%+v", second.Scope)
	}
	runner.permits <- struct{}{}
	waitRunEvent(t, service, actor, session.ID.String(), EventRunCompleted)
	if calls, max := runner.counts(); calls != 2 || max != 1 {
		t.Fatalf("calls=%d max=%d", calls, max)
	}
}

func TestDefaultGlobalSlotSerializesDifferentSessions(t *testing.T) {
	runner := newFakeRunner()
	store := NewMemoryStore(MemoryStoreConfig{})
	service, actor := testService(t, runner, store)
	one := createTestSession(t, service, actor, Scope{Kind: ScopeHost})
	two := createTestSession(t, service, actor, Scope{Kind: ScopeHost})
	if _, err := service.SubmitRun(context.Background(), actor, one.ID, "one-global", "first session"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SubmitRun(context.Background(), actor, two.ID, "two-global", "second session"); err != nil {
		t.Fatal(err)
	}
	first := waitStarted(t, runner)
	time.Sleep(20 * time.Millisecond)
	if calls, max := runner.counts(); calls != 1 || max != 1 {
		t.Fatalf("before release calls=%d max=%d", calls, max)
	}
	runner.permits <- struct{}{}
	second := waitStarted(t, runner)
	if second.SessionID == first.SessionID {
		t.Fatalf("same session started twice: %+v %+v", first, second)
	}
	runner.permits <- struct{}{}
	waitRunEvent(t, service, actor, second.SessionID.String(), EventRunCompleted)
	if calls, max := runner.counts(); calls != 2 || max != 1 {
		t.Fatalf("calls=%d max=%d", calls, max)
	}
}

func TestAbortClearsRunWaitingForGlobalSlot(t *testing.T) {
	runner := newFakeRunner()
	store := NewMemoryStore(MemoryStoreConfig{})
	service, actor := testService(t, runner, store)
	one := createTestSession(t, service, actor, Scope{Kind: ScopeHost})
	two := createTestSession(t, service, actor, Scope{Kind: ScopeHost})
	service.SubmitRun(context.Background(), actor, one.ID, "active-global", "active session")
	first := waitStarted(t, runner)
	waiting := two
	if first.SessionID == two.ID {
		waiting = one
	}
	if waiting.ID == two.ID {
		service.SubmitRun(context.Background(), actor, two.ID, "waiting-global", "waiting session")
	} else {
		service.SubmitRun(context.Background(), actor, one.ID, "waiting-global", "waiting session")
	}
	time.Sleep(20 * time.Millisecond)
	result, err := service.Abort(context.Background(), actor, waiting.ID)
	if err != nil || result.Aborted != 1 {
		t.Fatalf("abort=%+v err=%v", result, err)
	}
	runner.permits <- struct{}{}
	waitRunEvent(t, service, actor, first.SessionID.String(), EventRunCompleted)
	time.Sleep(20 * time.Millisecond)
	if calls, max := runner.counts(); calls != 1 || max != 1 {
		t.Fatalf("waiting run started calls=%d max=%d", calls, max)
	}
}

func TestGlobalConcurrencyOverrideAndCloseCancelWaiters(t *testing.T) {
	runner := newFakeRunner()
	store := NewMemoryStore(MemoryStoreConfig{})
	service, err := NewService(Config{Store: store, Runner: runner, GlobalConcurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{AdminID: "admin_owner"}
	one := createTestSession(t, service, actor, Scope{Kind: ScopeHost})
	two := createTestSession(t, service, actor, Scope{Kind: ScopeHost})
	service.SubmitRun(context.Background(), actor, one.ID, "parallel-one", "one")
	service.SubmitRun(context.Background(), actor, two.ID, "parallel-two", "two")
	waitStarted(t, runner)
	waitStarted(t, runner)
	if calls, max := runner.counts(); calls != 2 || max != 2 {
		t.Fatalf("override calls=%d max=%d", calls, max)
	}
	service.Close()

	runner2 := newFakeRunner()
	store2 := NewMemoryStore(MemoryStoreConfig{})
	service2, err := NewService(Config{Store: store2, Runner: runner2})
	if err != nil {
		t.Fatal(err)
	}
	one = createTestSession(t, service2, actor, Scope{Kind: ScopeHost})
	two = createTestSession(t, service2, actor, Scope{Kind: ScopeHost})
	service2.SubmitRun(context.Background(), actor, one.ID, "close-one", "one")
	service2.SubmitRun(context.Background(), actor, two.ID, "close-two", "two")
	waitStarted(t, runner2)
	closed := make(chan struct{})
	go func() { service2.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel global slot waiter")
	}
	if calls, _ := runner2.counts(); calls != 1 {
		t.Fatalf("waiter started during close: %d", calls)
	}
}

func TestSessionQueueIsBounded(t *testing.T) {
	runner := newFakeRunner()
	store := NewMemoryStore(MemoryStoreConfig{})
	service, actor := testService(t, runner, store)
	session := createTestSession(t, service, actor, Scope{Kind: ScopeHost})
	for index := 0; index < MaxQueuedRunsPerSession; index++ {
		key := fmt.Sprintf("queued-%d", index)
		if _, err := service.SubmitRun(context.Background(), actor, session.ID, key, "bounded queued message"); err != nil {
			t.Fatalf("index=%d err=%v", index, err)
		}
	}
	if _, err := service.SubmitRun(context.Background(), actor, session.ID, "queued-overflow", "overflow queued message"); !errors.Is(err, ErrRunLimit) {
		t.Fatalf("queue overflow=%v", err)
	}
	waitStarted(t, runner)
	if result, err := service.Abort(context.Background(), actor, session.ID); err != nil || result.Aborted != MaxQueuedRunsPerSession {
		t.Fatalf("cleanup abort=%+v err=%v", result, err)
	}
}

func TestOwnerIsolationAndAbortClearQueue(t *testing.T) {
	runner := newFakeRunner()
	store := NewMemoryStore(MemoryStoreConfig{})
	service, owner := testService(t, runner, store)
	session := createTestSession(t, service, owner, Scope{Kind: ScopeHost})
	other := Actor{AdminID: "admin_other"}
	if sessions, err := service.ListSessions(context.Background(), other); err != nil || len(sessions) != 0 {
		t.Fatalf("other sessions=%v err=%v", sessions, err)
	}
	if _, err := service.SubmitRun(context.Background(), other, session.ID, "foreign", "foreign message"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign submit=%v", err)
	}
	if _, err := service.Events(context.Background(), other, session.ID, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign events=%v", err)
	}
	if _, err := service.SubmitRun(context.Background(), owner, session.ID, "active", "active message"); err != nil {
		t.Fatal(err)
	}
	waitStarted(t, runner)
	if _, err := service.SubmitRun(context.Background(), owner, session.ID, "queued", "queued message"); err != nil {
		t.Fatal(err)
	}
	result, err := service.Abort(context.Background(), owner, session.ID)
	if err != nil || result.Aborted != 2 {
		t.Fatalf("abort=%+v err=%v", result, err)
	}
	waitRunEvent(t, service, owner, session.ID.String(), EventRunAborted)
	time.Sleep(20 * time.Millisecond)
	if calls, _ := runner.counts(); calls != 1 {
		t.Fatalf("queued run reached runner; calls=%d", calls)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.aborts) != 1 || !runner.aborts[0].ClearQueue {
		t.Fatalf("runner aborts=%+v", runner.aborts)
	}
}

func TestCursorRecoverySlowConsumerAndNoResubmit(t *testing.T) {
	runner := newFakeRunner()
	store := NewMemoryStore(MemoryStoreConfig{MaxEventsPerSession: 200})
	service, actor := testService(t, runner, store)
	runner.emit = make([]RunnerEvent, 140)
	for index := range runner.emit {
		runner.emit[index] = RunnerEvent{Kind: RunnerDelta, Text: "x"}
	}
	session := createTestSession(t, service, actor, Scope{Kind: ScopeHost})
	if _, err := service.SubmitRun(context.Background(), actor, session.ID, "many", "produce many events"); err != nil {
		t.Fatal(err)
	}
	waitStarted(t, runner)
	runner.permits <- struct{}{}
	deadline := time.Now().Add(2 * time.Second)
	var snapshot EventSnapshot
	for time.Now().Before(deadline) {
		snapshot, _ = service.Events(context.Background(), actor, session.ID, 0)
		if snapshot.LatestCursor >= 143 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if snapshot.Status != CursorSlowConsumer || len(snapshot.Events) != DefaultEventPageSize {
		t.Fatalf("snapshot status=%q events=%d latest=%d", snapshot.Status, len(snapshot.Events), snapshot.LatestCursor)
	}
	after := snapshot.Events[len(snapshot.Events)-1].Cursor
	remainder, err := service.Events(context.Background(), actor, session.ID, after)
	if err != nil || len(remainder.Events) == 0 {
		t.Fatalf("remainder=%+v err=%v", remainder, err)
	}
	if calls, _ := runner.counts(); calls != 1 {
		t.Fatalf("event reconnect resubmitted runner; calls=%d", calls)
	}

	retained := NewMemoryStore(MemoryStoreConfig{MaxEventsPerSession: 3})
	runner2 := newFakeRunner()
	service2, actor2 := testService(t, runner2, retained)
	runner2.emit = []RunnerEvent{{Kind: RunnerDelta, Text: "1"}, {Kind: RunnerDelta, Text: "2"}, {Kind: RunnerDelta, Text: "3"}}
	session2 := createTestSession(t, service2, actor2, Scope{Kind: ScopeHost})
	if _, err := service2.SubmitRun(context.Background(), actor2, session2.ID, "expire", "expire old cursor"); err != nil {
		t.Fatal(err)
	}
	waitStarted(t, runner2)
	runner2.permits <- struct{}{}
	deadline = time.Now().Add(2 * time.Second)
	completed := false
	for time.Now().Before(deadline) {
		current, _ := service2.Events(context.Background(), actor2, session2.ID, 3)
		for _, event := range current.Events {
			if event.Type == EventRunCompleted {
				completed = true
			}
		}
		if completed {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !completed {
		t.Fatal("retained run did not complete")
	}
	expired, err := service2.Events(context.Background(), actor2, session2.ID, 0)
	if !errors.Is(err, ErrCursorExpired) || expired.Status != CursorExpired || expired.OldestCursor <= 1 {
		t.Fatalf("expired=%+v err=%v", expired, err)
	}
}

func TestFinalAssistantMessageCompactsRunDeltasWithoutRewritingCursor(t *testing.T) {
	runner := newFakeRunner()
	runner.emit = make([]RunnerEvent, 0, 317)
	for index := 0; index < 316; index++ {
		runner.emit = append(runner.emit, RunnerEvent{Kind: RunnerDelta, Text: "chunk"})
	}
	runner.emit = append(runner.emit, RunnerEvent{Kind: RunnerMessage, Text: "final consolidated answer"})
	store := NewMemoryStore(MemoryStoreConfig{})
	service, actor := testService(t, runner, store)
	session := createTestSession(t, service, actor, Scope{Kind: ScopeHost})
	empty, err := service.Events(context.Background(), actor, session.ID, 0)
	if err != nil || empty.Status != CursorOK || empty.OldestCursor != 1 || empty.LatestCursor != 0 || len(empty.Events) != 0 {
		t.Fatalf("empty=%+v err=%v", empty, err)
	}
	if _, err = service.SubmitRun(context.Background(), actor, session.ID, "compact", "user question retained"); err != nil {
		t.Fatal(err)
	}
	waitStarted(t, runner)
	runner.permits <- struct{}{}
	snapshot := waitRunEvent(t, service, actor, session.ID.String(), EventRunCompleted)
	deltas, messages := 0, 0
	for _, event := range snapshot.Events {
		if event.Type == EventAssistantDelta {
			deltas++
		}
		if event.Type == EventAssistantMessage {
			messages++
			if event.Text != "final consolidated answer" {
				t.Fatalf("message=%q", event.Text)
			}
		}
	}
	if deltas != 0 || messages != 1 || len(snapshot.Events) != 4 || snapshot.Events[0].Text != "user question retained" {
		t.Fatalf("compacted=%+v", snapshot)
	}
	if snapshot.Events[2].Cursor <= 2 || snapshot.LatestCursor != 320 {
		t.Fatalf("cursor was rewritten: %+v", snapshot)
	}
	resumed, err := service.Events(context.Background(), actor, session.ID, 2)
	if err != nil || len(resumed.Events) != 2 || resumed.Events[0].Type != EventAssistantMessage {
		t.Fatalf("resume=%+v err=%v", resumed, err)
	}
}

func TestRunnerFailureUnknownAndRecoveryExposeNoRawError(t *testing.T) {
	for _, test := range []struct {
		name      string
		runnerErr error
		event     EventType
	}{{"failed", errors.New("provider raw secret tool args"), EventRunFailed}, {"unknown", ErrRunnerOutcomeUnknown, EventRunUnknown}} {
		t.Run(test.name, func(t *testing.T) {
			runner := newFakeRunner()
			runner.err = test.runnerErr
			store := NewMemoryStore(MemoryStoreConfig{})
			service, actor := testService(t, runner, store)
			session := createTestSession(t, service, actor, Scope{Kind: ScopeHost})
			if _, err := service.SubmitRun(context.Background(), actor, session.ID, "key", "message long enough"); err != nil {
				t.Fatal(err)
			}
			waitStarted(t, runner)
			runner.permits <- struct{}{}
			snapshot := waitRunEvent(t, service, actor, session.ID.String(), test.event)
			encoded := fmt.Sprintf("%+v", snapshot)
			if strings.Contains(encoded, "secret") || strings.Contains(encoded, "tool args") {
				t.Fatalf("raw error leaked: %s", encoded)
			}
		})
	}

	runner := newFakeRunner()
	store := NewMemoryStore(MemoryStoreConfig{})
	service, actor := testService(t, runner, store)
	session := createTestSession(t, service, actor, Scope{Kind: ScopeHost})
	now := time.Now().UTC()
	pending := Run{ID: "asst_run_pending", SessionID: session.ID, Status: RunAccepted, CreatedAt: now, UpdatedAt: now, message: "do not resend"}
	if _, _, err := store.CreateOrReplayRun(context.Background(), actor, session.ID, "pending", messageDigest(pending.message), pending, now); err != nil {
		t.Fatal(err)
	}
	if count, err := service.Recover(context.Background()); err != nil || count != 1 {
		t.Fatalf("recover count=%d err=%v", count, err)
	}
	waitRunEvent(t, service, actor, session.ID.String(), EventRunUnknown)
	if calls, _ := runner.counts(); calls != 0 {
		t.Fatalf("recovery resent runner calls=%d", calls)
	}
}

type finishFailStore struct {
	*MemoryStore
	mu       sync.Mutex
	failures int
}

func (s *finishFailStore) FinishRun(ctx context.Context, sessionID, runID domain.ID, status RunStatus, at time.Time) (Run, error) {
	s.mu.Lock()
	if s.failures > 0 {
		s.failures--
		s.mu.Unlock()
		return Run{}, errors.New("finish unavailable")
	}
	s.mu.Unlock()
	return s.MemoryStore.FinishRun(ctx, sessionID, runID, status, at)
}

func TestFinishPersistenceFailureHaltsLaneForRestartRecovery(t *testing.T) {
	runner := newFakeRunner()
	store := &finishFailStore{MemoryStore: NewMemoryStore(MemoryStoreConfig{}), failures: 3}
	service, err := NewService(Config{Store: store, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	actor := Actor{AdminID: "admin_owner"}
	session := createTestSession(t, service, actor, Scope{Kind: ScopeHost})
	if _, err := service.SubmitRun(context.Background(), actor, session.ID, "first", "finish failure first"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SubmitRun(context.Background(), actor, session.ID, "second", "must not start second"); err != nil {
		t.Fatal(err)
	}
	waitStarted(t, runner)
	runner.permits <- struct{}{}
	time.Sleep(30 * time.Millisecond)
	if calls, _ := runner.counts(); calls != 1 {
		t.Fatalf("lane continued after finish failure: %d", calls)
	}
	if _, err := service.SubmitRun(context.Background(), actor, session.ID, "third", "halted lane submit"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("halted submit=%v", err)
	}
	if count, err := service.Recover(context.Background()); err != nil || count != 2 {
		t.Fatalf("recover count=%d err=%v", count, err)
	}
	if calls, _ := runner.counts(); calls != 1 {
		t.Fatalf("recovery resent runner calls=%d", calls)
	}
}

func TestStoreClaimRefusesSecondRunningRunAcrossWorkers(t *testing.T) {
	store := NewMemoryStore(MemoryStoreConfig{})
	actor := Actor{AdminID: "admin_owner"}
	now := time.Now().UTC()
	session := Session{ID: "asst_session_shared", Scope: Scope{Kind: ScopeHost}, CreatedAt: now, UpdatedAt: now, ownerID: actor.AdminID}
	if err := store.CreateSession(context.Background(), actor, session); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"one", "two"} {
		run := Run{ID: domain.ID("asst_run_" + key), SessionID: session.ID, Status: RunAccepted, CreatedAt: now, UpdatedAt: now, message: key}
		if _, _, err := store.CreateOrReplayRun(context.Background(), actor, session.ID, key, messageDigest(key), run, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, found, err := store.ClaimNextRun(context.Background(), session.ID, now); err != nil || !found {
		t.Fatalf("first claim found=%v err=%v", found, err)
	}
	if _, found, err := store.ClaimNextRun(context.Background(), session.ID, now); err != nil || found {
		t.Fatalf("second claim found=%v err=%v", found, err)
	}
}
