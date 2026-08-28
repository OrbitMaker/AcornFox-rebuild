package controllers

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

type m4StoredOperation struct {
	digest string
	active bool
	result *M4OperationResult
}

type m4TestStore struct {
	mu       sync.Mutex
	env      M4Environment
	records  map[string]m4StoredOperation
	commits  []M4OperationCommit
	active   bool
	acquires int
}

func (s *m4TestStore) AcquireM4Operation(_ context.Context, request M4OperationAcquire) (M4OperationReservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = make(map[string]m4StoredOperation)
	}
	if existing, ok := s.records[request.IdempotencyKey]; ok {
		if existing.digest != request.RequestDigest {
			return M4OperationReservation{}, application.ErrIdempotencyConflict
		}
		if existing.result != nil {
			copy := cloneM4Result(*existing.result)
			return M4OperationReservation{Replay: &copy}, nil
		}
		return M4OperationReservation{}, ErrM4ActiveOperation
	}
	if s.active {
		return M4OperationReservation{}, ErrM4ActiveOperation
	}
	s.acquires++
	s.active = true
	op := domain.Operation{ID: domain.ID("op_" + request.IdempotencyKey), ApplicationID: request.ApplicationID, EnvironmentID: request.EnvironmentID, Type: request.Type, TargetRef: request.TargetRef, IdempotencyKey: request.IdempotencyKey, Status: domain.OperationRunning, CreatedAt: request.Now, UpdatedAt: request.Now}
	s.records[request.IdempotencyKey] = m4StoredOperation{digest: request.RequestDigest, active: true}
	return M4OperationReservation{Operation: op, Environment: s.env}, nil
}

func (s *m4TestStore) CommitM4Operation(_ context.Context, commit M4OperationCommit) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = false
	record := s.records[commit.Operation.IdempotencyKey]
	result := cloneM4Result(commit.Result)
	record.active, record.result = false, &result
	s.records[commit.Operation.IdempotencyKey] = record
	s.commits = append(s.commits, commit)
	return nil
}

type m4Runtime struct {
	mu           sync.Mutex
	serviceCalls []M4RuntimeAction
	appCalls     []M4RuntimeAction
	redeploys    []M4RuntimeAction
	rollbacks    []M4RuntimeAction
	fail         error
	deferred     bool
}

func (r *m4Runtime) result(action M4RuntimeAction, rollback bool) (M4RuntimeResult, error) {
	r.mu.Lock()
	failure := r.fail
	r.mu.Unlock()
	if failure != nil {
		return M4RuntimeResult{}, failure
	}
	deployment := action.Current.Deployment
	if rollback {
		deployment = action.PreviousSuccessful.Deployment
		deployment.Status = domain.DeploymentServing
	}
	if r.deferred {
		deployment.ID = "dep_candidate"
		deployment.Status = domain.DeploymentRuntimeReady
	}
	return M4RuntimeResult{Deployment: deployment, Evidence: []domain.EvidenceRef{{ID: "evidence_m4", Kind: "runtime.operation"}}, Deferred: r.deferred}, nil
}

func (r *m4Runtime) RestartService(ctx context.Context, action M4RuntimeAction) (M4RuntimeResult, error) {
	r.mu.Lock()
	r.serviceCalls = append(r.serviceCalls, action)
	r.mu.Unlock()
	return r.result(action, false)
}
func (r *m4Runtime) RestartApplication(ctx context.Context, action M4RuntimeAction) (M4RuntimeResult, error) {
	r.mu.Lock()
	r.appCalls = append(r.appCalls, action)
	r.mu.Unlock()
	return r.result(action, false)
}
func (r *m4Runtime) Redeploy(ctx context.Context, action M4RuntimeAction) (M4RuntimeResult, error) {
	r.mu.Lock()
	r.redeploys = append(r.redeploys, action)
	r.mu.Unlock()
	return r.result(action, false)
}
func (r *m4Runtime) Rollback(ctx context.Context, action M4RuntimeAction) (M4RuntimeResult, error) {
	r.mu.Lock()
	r.rollbacks = append(r.rollbacks, action)
	r.mu.Unlock()
	return r.result(action, true)
}

func m4Environment(t *testing.T) M4Environment {
	t.Helper()
	image := domain.ImageDigest{Repository: "registry.example.test/app", Digest: "sha256:" + strings.Repeat("a", 64)}
	previous, err := domain.NewRelease("app_m4", "group_m4", 1, "sha256:"+strings.Repeat("b", 64), map[string]domain.ImageDigest{"frontend": image}, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	previous.ID = "rel_previous"
	current, err := domain.NewRelease("app_m4", "group_m4", 2, "sha256:"+strings.Repeat("c", 64), map[string]domain.ImageDigest{"frontend": image}, time.Unix(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	current.ID = "rel_current"
	previousDeployment := domain.Deployment{ID: "dep_previous", ApplicationID: "app_m4", EnvironmentID: "env_m4", ReleaseID: previous.ID, Status: domain.DeploymentServing, CreatedAt: time.Unix(1, 0), UpdatedAt: time.Unix(1, 0)}
	currentDeployment := domain.Deployment{ID: "dep_current", ApplicationID: "app_m4", EnvironmentID: "env_m4", ReleaseID: current.ID, Status: domain.DeploymentServing, CreatedAt: time.Unix(2, 0), UpdatedAt: time.Unix(2, 0)}
	return M4Environment{FactVersion: "facts-v1", ApplicationID: "app_m4", EnvironmentID: "env_m4", CurrentRelease: *current, CurrentDeployment: currentDeployment, PreviousSuccessful: &M4ReleaseDeployment{Release: *previous, Deployment: previousDeployment}, Services: []M4ServiceState{{Name: "frontend", Healthy: true}}}
}

func m4Request(key string) M4OperationRequest {
	return M4OperationRequest{ApplicationID: "app_m4", EnvironmentID: "env_m4", IdempotencyKey: key, ExpectedVersion: "facts-v1", Actor: "user_m4", Reason: "recover a failed service"}
}

func newM4Controller(t *testing.T, environment M4Environment) (*M4OperationsController, *m4TestStore, *m4Runtime) {
	t.Helper()
	store := &m4TestStore{env: environment}
	runtime := &m4Runtime{}
	return &M4OperationsController{Store: store, Runtime: runtime, Clock: func() time.Time { return time.Unix(10, 0).UTC() }}, store, runtime
}

func TestM4RestartPrefersSingleUnhealthyServiceAndAppendsAuditOutbox(t *testing.T) {
	environment := m4Environment(t)
	environment.Services = []M4ServiceState{{Name: "frontend", Healthy: true}, {Name: "worker", Healthy: false}}
	controller, store, runtime := newM4Controller(t, environment)

	result, err := controller.Restart(context.Background(), m4Request("restart-worker"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "service_restart" || result.Scope != "service" || result.ServiceName != "worker" || result.Operation.Status != domain.OperationSucceeded || result.RollbackData || result.KeptLastUsable {
		t.Fatalf("unexpected restart result: %#v", result)
	}
	if len(runtime.serviceCalls) != 1 || len(runtime.appCalls) != 0 || runtime.serviceCalls[0].ServiceName != "worker" {
		t.Fatalf("restart was not limited to the unhealthy service: %+v %+v", runtime.serviceCalls, runtime.appCalls)
	}
	if len(store.commits) != 1 || !store.commits[0].Succeeded || store.commits[0].Audit.Actor != "user_m4" || store.commits[0].Outbox.Kind != "operations.service_restart.succeeded" {
		t.Fatalf("audit/outbox was not appended with the operation: %#v", store.commits)
	}
}

func TestM4RestartFallsBackToApplicationWhenNotSingleService(t *testing.T) {
	environment := m4Environment(t)
	environment.Services = []M4ServiceState{{Name: "frontend", Healthy: false}, {Name: "worker", Healthy: false}}
	controller, _, runtime := newM4Controller(t, environment)
	result, err := controller.Restart(context.Background(), m4Request("restart-app"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "application_restart" || result.Scope != "application" || len(runtime.serviceCalls) != 0 || len(runtime.appCalls) != 1 {
		t.Fatalf("multiple service outage did not use application fallback: %#v runtime=%#v", result, runtime)
	}
}

func TestM4RedeployUsesCurrentCompleteReleaseAndIdempotentReplay(t *testing.T) {
	controller, store, runtime := newM4Controller(t, m4Environment(t))
	request := m4Request("redeploy-current")
	first, err := controller.Redeploy(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := controller.Redeploy(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.ReleaseID != "rel_current" || second.Operation.ID != first.Operation.ID || len(runtime.redeploys) != 1 || runtime.redeploys[0].Current.Release.ID != "rel_current" || store.acquires != 1 {
		t.Fatalf("redeploy did not preserve current immutable release/idempotency: first=%#v second=%#v runtime=%#v acquires=%d", first, second, runtime.redeploys, store.acquires)
	}
	conflict := request
	conflict.Reason = "different input"
	if _, err := controller.Redeploy(context.Background(), conflict); !errors.Is(err, application.ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict was not rejected: %v", err)
	}
}

func TestM4DeferredReplacementLeavesTerminalOwnershipToReconciler(t *testing.T) {
	controller, store, runtime := newM4Controller(t, m4Environment(t))
	runtime.deferred = true
	result, err := controller.Redeploy(context.Background(), m4Request("redeploy-deferred"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Operation.Status != domain.OperationRunning || result.Deployment.Serving() || result.ReleaseID != "rel_current" || len(store.commits) != 0 {
		t.Fatalf("replacement task stole reconciler terminal ownership: result=%#v commits=%#v", result, store.commits)
	}
}

func TestM4RollbackUsesOnlyPreviousSuccessAndNeverPromisesDataRollback(t *testing.T) {
	controller, store, runtime := newM4Controller(t, m4Environment(t))
	result, err := controller.Rollback(context.Background(), m4Request("rollback-previous"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Operation.Status != domain.OperationRolledBack || result.ReleaseID != "rel_previous" || result.Deployment.ReleaseID != "rel_previous" || result.RollbackData || !strings.Contains(result.DataNotice, "not rolled back") || len(runtime.rollbacks) != 1 || runtime.rollbacks[0].PreviousSuccessful.Release.ID != "rel_previous" {
		t.Fatalf("rollback was not constrained to prior successful code/config: %#v %#v", result, runtime.rollbacks)
	}
	if len(store.commits) != 1 || store.commits[0].Audit.Action != "operations.rollback" {
		t.Fatalf("rollback audit missing: %#v", store.commits)
	}

	noPrevious := m4Environment(t)
	noPrevious.PreviousSuccessful = nil
	controller, failedStore, failedRuntime := newM4Controller(t, noPrevious)
	if _, err := controller.Rollback(context.Background(), m4Request("rollback-none")); !errors.Is(err, ErrM4NoRollbackTarget) {
		t.Fatalf("arbitrary/no rollback target was accepted: %v", err)
	}
	if len(failedRuntime.rollbacks) != 0 || len(failedStore.commits) != 1 || failedStore.commits[0].Succeeded || !failedStore.commits[0].Result.KeptLastUsable {
		t.Fatalf("failed rollback did not retain/audit latest usable state: runtime=%#v commits=%#v", failedRuntime, failedStore.commits)
	}
}

func TestM4RollbackAcceptsPreviousImmutableServiceGroupRevision(t *testing.T) {
	environment := m4Environment(t)
	environment.PreviousSuccessful.Release.ServiceGroupID = "group_previous_revision"
	environment.CurrentRelease.ServiceGroupID = "group_current_revision"
	controller, _, runtime := newM4Controller(t, environment)
	result, err := controller.Rollback(context.Background(), m4Request("rollback-prior-group-revision"))
	if err != nil || result.Operation.Status != domain.OperationRolledBack || len(runtime.rollbacks) != 1 || runtime.rollbacks[0].PreviousSuccessful.Release.ServiceGroupID != "group_previous_revision" {
		t.Fatalf("previous immutable ServiceGroup revision rollback rejected: result=%#v calls=%#v err=%v", result, runtime.rollbacks, err)
	}
}

func TestM4RuntimeFailureRetainsLatestUsableAndRedactsAudit(t *testing.T) {
	controller, store, runtime := newM4Controller(t, m4Environment(t))
	runtime.fail = errors.New("token=super-secret runtime restart failed")
	request := m4Request("redeploy-fail")
	request.Reason = "operator supplied token=another-secret while describing failure"
	result, err := controller.Redeploy(context.Background(), request)
	if err == nil || !result.KeptLastUsable || result.RollbackData || len(store.commits) != 1 || store.commits[0].Succeeded {
		t.Fatalf("failed redeploy did not preserve recent usable deployment: result=%#v err=%v commits=%#v", result, err, store.commits)
	}
	if strings.Contains(store.commits[0].Failure, "super-secret") || strings.Contains(store.commits[0].Audit.Reason, "another-secret") || !strings.Contains(store.commits[0].Failure, foundation.RedactedValue) || !strings.Contains(store.commits[0].Audit.Reason, foundation.RedactedValue) {
		t.Fatalf("failure audit leaked secret: %#v", store.commits[0])
	}
}

func TestM4StoreEnforcesOneActiveOperationPerEnvironment(t *testing.T) {
	controller, store, _ := newM4Controller(t, m4Environment(t))
	store.active = true
	if _, err := controller.Restart(context.Background(), m4Request("blocked-by-active")); !errors.Is(err, ErrM4ActiveOperation) {
		t.Fatalf("concurrent environment operation was accepted: %v", err)
	}
}

func TestM4RejectsStaleFactVersionBeforeRuntimeEffect(t *testing.T) {
	controller, store, runtime := newM4Controller(t, m4Environment(t))
	request := m4Request("stale-facts")
	request.ExpectedVersion = "facts-old"
	result, err := controller.Restart(context.Background(), request)
	if !domain.IsCode(err, domain.ErrConflict) || !result.KeptLastUsable || len(runtime.serviceCalls)+len(runtime.appCalls) != 0 {
		t.Fatalf("stale facts were not rejected safely: result=%#v err=%v runtime=%#v", result, err, runtime)
	}
	if len(store.commits) != 1 || store.commits[0].Succeeded {
		t.Fatalf("stale fact rejection was not audited: %#v", store.commits)
	}
}
