package assistantactions

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/assistant"
	"github.com/open-card/open-card/internal/domain"
)

type fakeResolver struct {
	mu      sync.Mutex
	targets map[domain.ID]Target
	calls   int
	err     error
}

func (r *fakeResolver) ResolveExact(_ context.Context, app, dep domain.ID) (Target, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return Target{}, r.err
	}
	target, ok := r.targets[dep]
	if !ok || target.ApplicationID != app {
		return Target{}, ErrNotFound
	}
	return target, nil
}

type fakeExecutor struct {
	mu      sync.Mutex
	calls   []ExecutionRequest
	results []ExecutionResult
	errors  []error
	block   chan struct{}
}

func (e *fakeExecutor) Execute(_ context.Context, r ExecutionRequest) (ExecutionResult, error) {
	e.mu.Lock()
	index := len(e.calls)
	e.calls = append(e.calls, r)
	var result ExecutionResult
	var err error
	if index < len(e.results) {
		result = e.results[index]
	}
	if index < len(e.errors) {
		err = e.errors[index]
	}
	block := e.block
	e.mu.Unlock()
	if block != nil {
		<-block
	}
	return result, err
}

type fakeVerifier struct {
	verification Verification
	err          error
}

func (v fakeVerifier) Verify(context.Context, Action, Target, domain.ID) (Verification, error) {
	return v.verification, v.err
}

func actionFixture(t *testing.T) (*Service, *MemoryStore, *fakeResolver, *fakeExecutor, assistant.Actor, *time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 7, 14, 0, 0, 0, time.UTC)
	resolver := &fakeResolver{targets: map[domain.ID]Target{"dep_1": {ApplicationID: "app_1", DeploymentID: "dep_1", ReleaseID: "release_1", ReleaseVersion: 7, ApplicationName: "Safe App"}, "dep_2": {ApplicationID: "app_1", DeploymentID: "dep_2", ReleaseID: "release_2", ReleaseVersion: 8, ApplicationName: "Safe App"}}}
	executor := &fakeExecutor{results: []ExecutionResult{{OperationID: "operation_1", Accepted: true}}}
	store := NewMemoryStore()
	service, err := NewService(Config{Store: store, Resolver: resolver, Executor: executor, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return service, store, resolver, executor, assistant.Actor{AdminID: "admin_1"}, &now
}
func prepare(t *testing.T, s *Service, a assistant.Actor, sid, rid, dep string) (Proposal, error) {
	t.Helper()
	return s.PrepareProposal(context.Background(), a, domain.ID(sid), domain.ID(rid), PrepareInput{Action: ActionRestart, ApplicationID: "app_1", DeploymentID: domain.ID(dep)}, "tool-call")
}

func TestPrepareOnlyCreatesReplayablePendingProposal(t *testing.T) {
	s, _, resolver, executor, actor, _ := actionFixture(t)
	first, err := prepare(t, s, actor, "session_1", "run_1", "dep_1")
	if err != nil || first.State != StatePending || first.Target.ReleaseID != "release_1" {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	if len(executor.calls) != 0 {
		t.Fatal("prepare executed action")
	}
	resolver.err = errors.New("target later unavailable")
	second, err := s.PrepareProposal(context.Background(), actor, "session_1", "run_1", PrepareInput{Action: ActionRestart, ApplicationID: "app_1", DeploymentID: "dep_1"}, "new-call-id")
	if err != nil || second.ID != first.ID {
		t.Fatalf("replay=%+v err=%v", second, err)
	}
	resolver.mu.Lock()
	calls := resolver.calls
	resolver.mu.Unlock()
	if calls != 1 {
		t.Fatalf("replay resolved target %d times", calls)
	}
}

func TestConcurrentApprovalExecutesOnceWithFixedKey(t *testing.T) {
	s, _, _, executor, actor, _ := actionFixture(t)
	p, err := prepare(t, s, actor, "session_1", "run_1", "dep_1")
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan Proposal, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			value, e := s.Decide(context.Background(), actor, p.SessionID, p.ID, true)
			results <- value
			errs <- e
		}()
	}
	for i := 0; i < 2; i++ {
		if e := <-errs; e != nil {
			t.Fatal(e)
		}
		if value := <-results; value.State != StateAccepted {
			t.Fatalf("decision=%+v", value)
		}
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if len(executor.calls) != 1 || executor.calls[0].IdempotencyKey != "assistant-action:"+p.ID.String() {
		t.Fatalf("calls=%+v", executor.calls)
	}
}

func TestOwnerExpiryTargetDriftAndAppSlot(t *testing.T) {
	s, _, resolver, executor, actor, now := actionFixture(t)
	p, err := prepare(t, s, actor, "session_1", "run_1", "dep_1")
	if err != nil {
		t.Fatal(err)
	}
	other := assistant.Actor{AdminID: "admin_2"}
	if _, err = s.Decide(context.Background(), other, p.SessionID, p.ID, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("owner decision=%v", err)
	}
	resolver.targets["dep_1"] = Target{ApplicationID: "app_1", DeploymentID: "dep_1", ReleaseID: "release_changed", ReleaseVersion: 9, ApplicationName: "Safe App"}
	if _, err = s.Decide(context.Background(), actor, p.SessionID, p.ID, true); !errors.Is(err, ErrTargetChanged) {
		t.Fatalf("drift=%v", err)
	}
	if len(executor.calls) != 0 {
		t.Fatal("drift executed")
	}
	p2, err := prepare(t, s, actor, "session_1", "run_2", "dep_2")
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(ProposalTTL)
	if _, err = s.Decide(context.Background(), actor, p2.SessionID, p2.ID, true); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry=%v", err)
	}
	*now = now.Add(-ProposalTTL)
	p3, err := s.PrepareProposal(context.Background(), actor, "session_2", "run_3", PrepareInput{Action: ActionRedeploy, ApplicationID: "app_1", DeploymentID: "dep_2"}, "call3")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Decide(context.Background(), actor, p3.SessionID, p3.ID, true); err != nil {
		t.Fatal(err)
	}
	resolver.targets["dep_1"] = Target{ApplicationID: "app_1", DeploymentID: "dep_1", ReleaseID: "release_changed", ReleaseVersion: 9, ApplicationName: "Safe App"}
	p4, err := s.PrepareProposal(context.Background(), actor, "session_3", "run_4", PrepareInput{Action: ActionRestart, ApplicationID: "app_1", DeploymentID: "dep_1"}, "call4")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Decide(context.Background(), actor, p4.SessionID, p4.ID, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("app slot=%v", err)
	}
}

func TestUnknownRetryUsesSameKeyAndVerificationReleasesSlot(t *testing.T) {
	s, store, resolver, executor, actor, _ := actionFixture(t)
	executor.results = []ExecutionResult{{OperationID: "operation_1"}, {OperationID: "operation_1", Accepted: true}}
	executor.errors = []error{errors.New("commit acknowledgement lost"), nil}
	p, err := prepare(t, s, actor, "session_1", "run_1", "dep_1")
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := s.Decide(context.Background(), actor, p.SessionID, p.ID, true)
	if err != nil || unknown.State != StateUnknown || unknown.OperationID != "operation_1" {
		t.Fatalf("unknown=%+v err=%v", unknown, err)
	}
	resolver.targets["dep_1"] = Target{ApplicationID: "app_1", DeploymentID: "dep_1", ReleaseID: "release_changed", ReleaseVersion: 9, ApplicationName: "Safe App"}
	accepted, err := s.Decide(context.Background(), actor, p.SessionID, p.ID, true)
	if err != nil || accepted.State != StateAccepted {
		t.Fatalf("retry=%+v err=%v", accepted, err)
	}
	executor.mu.Lock()
	if len(executor.calls) != 2 || executor.calls[0].IdempotencyKey != executor.calls[1].IdempotencyKey {
		t.Fatalf("keys=%+v", executor.calls)
	}
	if executor.calls[1].Target.ReleaseID != "release_1" {
		t.Fatalf("unknown retry target changed: %+v", executor.calls[1].Target)
	}
	executor.mu.Unlock()
	at := time.Now().UTC()
	s.verifier = fakeVerifier{verification: Verification{State: VerificationVerified, Verdict: "operation completed; application health is separate", ObservedAt: &at}}
	items, err := s.List(context.Background(), actor, p.SessionID)
	if err != nil || len(items) != 1 || items[0].State != StateVerified || items[0].Verification.Verdict == "" {
		t.Fatalf("verified=%+v err=%v", items, err)
	}
	_ = store
}

func TestExplicitNoSideEffectRejectionIsFailed(t *testing.T) {
	s, _, _, executor, actor, _ := actionFixture(t)
	executor.results = []ExecutionResult{{}}
	executor.errors = []error{ErrExecutionRejected}
	p, _ := prepare(t, s, actor, "session_1", "run_1", "dep_1")
	result, err := s.Decide(context.Background(), actor, p.SessionID, p.ID, true)
	if err != nil || result.State != StateFailed || !result.OperationID.Empty() {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
