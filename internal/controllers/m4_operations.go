package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

var (
	ErrM4ActiveOperation  = errors.New("an operations task is already active for this environment")
	ErrM4NoRollbackTarget = errors.New("no previous successful release is available for rollback")
	ErrM4StoreProtocol    = errors.New("operations store returned an invalid active operation")
)

// M4OperationStore is the only durability boundary of this controller. Acquire
// must atomically enforce one active operation per environment, compare the
// request digest for a reused idempotency key, and return a completed replay
// without creating another active operation. Commit must atomically change the
// operation outcome and append its audit-chain record and outbox event.
type M4OperationStore interface {
	AcquireM4Operation(context.Context, M4OperationAcquire) (M4OperationReservation, error)
	CommitM4Operation(context.Context, M4OperationCommit) error
}

// M4RuntimeExecutor is intentionally smaller than a Docker or HTTP adapter.
// Its implementation must preserve the current usable deployment until a
// replacement action has independently passed the runtime health checks.
type M4RuntimeExecutor interface {
	RestartService(context.Context, M4RuntimeAction) (M4RuntimeResult, error)
	RestartApplication(context.Context, M4RuntimeAction) (M4RuntimeResult, error)
	Redeploy(context.Context, M4RuntimeAction) (M4RuntimeResult, error)
	Rollback(context.Context, M4RuntimeAction) (M4RuntimeResult, error)
}

type M4ServiceState struct {
	Name    string
	Healthy bool
}

type M4ReleaseDeployment struct {
	Release    domain.Release
	Deployment domain.Deployment
}

// M4Environment is a store-provided fact snapshot. PreviousSuccessful is
// deliberately singular: MVP does not allow arbitrary historical rollbacks.
type M4Environment struct {
	FactVersion        string
	ApplicationID      domain.ID
	EnvironmentID      domain.ID
	CurrentRelease     domain.Release
	CurrentDeployment  domain.Deployment
	PreviousSuccessful *M4ReleaseDeployment
	Services           []M4ServiceState
}

type M4OperationRequest struct {
	ApplicationID   domain.ID
	EnvironmentID   domain.ID
	IdempotencyKey  string
	ExpectedVersion string
	Actor           string
	Reason          string
}

type M4OperationAcquire struct {
	ApplicationID   domain.ID
	EnvironmentID   domain.ID
	Type            domain.OperationType
	TargetRef       string
	IdempotencyKey  string
	RequestDigest   string
	ExpectedVersion string
	Actor           string
	Reason          string
	Now             time.Time
}

type M4OperationReservation struct {
	Operation   domain.Operation
	Environment M4Environment
	Replay      *M4OperationResult
}

type M4RuntimeAction struct {
	Operation          domain.Operation
	Current            M4ReleaseDeployment
	PreviousSuccessful *M4ReleaseDeployment
	ServiceName        string
}

type M4RuntimeResult struct {
	Deployment domain.Deployment
	Evidence   []domain.EvidenceRef
	// Deferred means the replacement task established runtime readiness but a
	// durable rollout reconciler still owns route commit and terminal outcome.
	Deferred bool
}

type M4AuditRecord struct {
	Actor        string
	Reason       string
	Action       string
	InputDigest  string
	ResultDigest string
	Evidence     []domain.EvidenceRef
}

type M4OperationCommit struct {
	Operation domain.Operation
	Succeeded bool
	Result    M4OperationResult
	Failure   string
	Audit     M4AuditRecord
	Outbox    application.Event
}

type M4OperationResult struct {
	Operation      domain.Operation     `json:"operation"`
	Action         string               `json:"action"`
	Scope          string               `json:"scope"`
	ServiceName    string               `json:"service_name,omitempty"`
	ReleaseID      domain.ID            `json:"release_id,omitempty"`
	Deployment     domain.Deployment    `json:"deployment"`
	RollbackData   bool                 `json:"rollback_data"`
	DataNotice     string               `json:"data_notice"`
	KeptLastUsable bool                 `json:"kept_last_usable"`
	Evidence       []domain.EvidenceRef `json:"evidence,omitempty"`
}

// M4OperationsController owns user-triggered recovery decisions. It never
// talks to PostgreSQL or HTTP directly; stores make state/audit/outbox commits
// durable and runtime executors perform only typed recovery effects.
type M4OperationsController struct {
	Store   M4OperationStore
	Runtime M4RuntimeExecutor
	Clock   func() time.Time

	mu      sync.Mutex
	running map[string]*m4Run
}

type m4Run struct {
	digest string
	done   chan struct{}
	result M4OperationResult
	err    error
}

func (c *M4OperationsController) Restart(ctx context.Context, request M4OperationRequest) (M4OperationResult, error) {
	return c.execute(ctx, domain.OperationRestart, request, func(environment M4Environment, operation domain.Operation) (M4RuntimeAction, string, string, error) {
		if err := validateM4Environment(environment); err != nil {
			return M4RuntimeAction{}, "", "", err
		}
		unhealthy := unhealthyServices(environment.Services)
		action := M4RuntimeAction{Operation: operation, Current: M4ReleaseDeployment{Release: environment.CurrentRelease, Deployment: environment.CurrentDeployment}}
		if len(unhealthy) == 1 {
			action.ServiceName = unhealthy[0]
			return action, "service_restart", "service", nil
		}
		return action, "application_restart", "application", nil
	})
}

func (c *M4OperationsController) Redeploy(ctx context.Context, request M4OperationRequest) (M4OperationResult, error) {
	return c.execute(ctx, domain.OperationRedeploy, request, func(environment M4Environment, operation domain.Operation) (M4RuntimeAction, string, string, error) {
		if err := validateM4Environment(environment); err != nil {
			return M4RuntimeAction{}, "", "", err
		}
		return M4RuntimeAction{Operation: operation, Current: M4ReleaseDeployment{Release: environment.CurrentRelease, Deployment: environment.CurrentDeployment}}, "redeploy", "application", nil
	})
}

func (c *M4OperationsController) Rollback(ctx context.Context, request M4OperationRequest) (M4OperationResult, error) {
	return c.execute(ctx, domain.OperationRollback, request, func(environment M4Environment, operation domain.Operation) (M4RuntimeAction, string, string, error) {
		if err := validateM4Environment(environment); err != nil {
			return M4RuntimeAction{}, "", "", err
		}
		previous := environment.PreviousSuccessful
		if previous == nil || previous.Release.ID.Empty() || previous.Release.ID == environment.CurrentRelease.ID || previous.Release.Status != domain.ReleaseReady {
			return M4RuntimeAction{}, "", "", ErrM4NoRollbackTarget
		}
		if err := previous.Release.Validate(); err != nil {
			return M4RuntimeAction{}, "", "", err
		}
		if err := previous.Deployment.Validate(); err != nil {
			return M4RuntimeAction{}, "", "", err
		}
		// M2 stores immutable ServiceGroup revisions under distinct IDs. A
		// recovery rollback therefore binds the immediately previous successful
		// *release* for this same application/environment; it must not require
		// a mutable in-place ServiceGroup identity that M2 intentionally lacks.
		if previous.Release.ApplicationID != environment.ApplicationID || previous.Deployment.ApplicationID != environment.ApplicationID || previous.Deployment.EnvironmentID != environment.EnvironmentID {
			return M4RuntimeAction{}, "", "", domain.ValidationError("previous successful release does not match the active environment")
		}
		return M4RuntimeAction{Operation: operation, Current: M4ReleaseDeployment{Release: environment.CurrentRelease, Deployment: environment.CurrentDeployment}, PreviousSuccessful: previous}, "rollback", "application", nil
	})
}

type m4Plan func(M4Environment, domain.Operation) (M4RuntimeAction, string, string, error)

func (c *M4OperationsController) execute(ctx context.Context, operationType domain.OperationType, request M4OperationRequest, plan m4Plan) (M4OperationResult, error) {
	if c.Store == nil || c.Runtime == nil {
		return M4OperationResult{}, errors.New("M4 operations controller requires store and runtime executor")
	}
	if err := validateM4Request(request); err != nil {
		return M4OperationResult{}, err
	}
	// Reasons are durable audit input. Preserve their operational meaning but
	// never let a pasted credential enter the store/outbox boundary.
	request.Reason = foundation.RedactText(request.Reason)
	if c.Clock == nil {
		c.Clock = time.Now
	}
	digest := m4Digest(string(operationType), request.ApplicationID.String(), request.EnvironmentID.String(), request.IdempotencyKey, request.ExpectedVersion, request.Actor, request.Reason)
	runKey := request.ApplicationID.String() + "\x00" + request.EnvironmentID.String() + "\x00" + request.IdempotencyKey
	c.mu.Lock()
	if c.running == nil {
		c.running = make(map[string]*m4Run)
	}
	if previous := c.running[runKey]; previous != nil {
		if previous.digest != digest {
			c.mu.Unlock()
			return M4OperationResult{}, application.ErrIdempotencyConflict
		}
		c.mu.Unlock()
		select {
		case <-previous.done:
			return previous.result, previous.err
		case <-ctx.Done():
			return M4OperationResult{}, ctx.Err()
		}
	}
	run := &m4Run{digest: digest, done: make(chan struct{})}
	c.running[runKey] = run
	c.mu.Unlock()

	run.result, run.err = c.executeOnce(ctx, operationType, request, digest, plan)
	close(run.done)
	c.mu.Lock()
	if c.running[runKey] == run {
		delete(c.running, runKey)
	}
	c.mu.Unlock()
	return run.result, run.err
}

func (c *M4OperationsController) executeOnce(ctx context.Context, operationType domain.OperationType, request M4OperationRequest, digest string, plan m4Plan) (M4OperationResult, error) {
	now := c.Clock().UTC()
	reservation, err := c.Store.AcquireM4Operation(ctx, M4OperationAcquire{ApplicationID: request.ApplicationID, EnvironmentID: request.EnvironmentID, Type: operationType, TargetRef: "environment/" + request.EnvironmentID.String(), IdempotencyKey: request.IdempotencyKey, RequestDigest: digest, ExpectedVersion: request.ExpectedVersion, Actor: request.Actor, Reason: request.Reason, Now: now})
	if err != nil {
		return M4OperationResult{}, err
	}
	if reservation.Replay != nil {
		return cloneM4Result(*reservation.Replay), nil
	}
	if reservation.Operation.ApplicationID != request.ApplicationID || reservation.Operation.EnvironmentID != request.EnvironmentID || reservation.Operation.Type != operationType || reservation.Operation.Status != domain.OperationRunning {
		return M4OperationResult{}, ErrM4StoreProtocol
	}
	if reservation.Environment.FactVersion != request.ExpectedVersion {
		return c.fail(ctx, reservation, request, digest, actionNameFor(operationType), scopeFor(operationType), domain.NewError(domain.ErrConflict, "operations facts changed; refresh before retrying"))
	}
	action, actionName, scope, err := plan(reservation.Environment, reservation.Operation)
	if err != nil {
		return c.fail(ctx, reservation, request, digest, actionNameFor(operationType), scopeFor(operationType), err)
	}
	var runtimeResult M4RuntimeResult
	switch actionName {
	case "service_restart":
		runtimeResult, err = c.Runtime.RestartService(ctx, action)
	case "application_restart":
		runtimeResult, err = c.Runtime.RestartApplication(ctx, action)
	case "redeploy":
		runtimeResult, err = c.Runtime.Redeploy(ctx, action)
	case "rollback":
		runtimeResult, err = c.Runtime.Rollback(ctx, action)
	default:
		err = ErrM4StoreProtocol
	}
	if err != nil {
		return c.fail(ctx, reservation, request, digest, actionName, scope, err)
	}
	if err := validateM4RuntimeResult(runtimeResult, reservation.Environment, operationType); err != nil {
		return c.fail(ctx, reservation, request, digest, actionName, scope, err)
	}
	if runtimeResult.Deferred {
		return M4OperationResult{Operation: reservation.Operation, Action: actionName, Scope: scope, ServiceName: action.ServiceName, ReleaseID: releaseFor(action, operationType), Deployment: runtimeResult.Deployment, RollbackData: false, DataNotice: "Application code/configuration only; persistent data is not rolled back.", Evidence: append([]domain.EvidenceRef(nil), runtimeResult.Evidence...)}, nil
	}
	terminal := domain.OperationSucceeded
	if operationType == domain.OperationRollback {
		terminal = domain.OperationRolledBack
	}
	result := M4OperationResult{Operation: terminalM4Operation(reservation.Operation, terminal, c.Clock().UTC()), Action: actionName, Scope: scope, ServiceName: action.ServiceName, ReleaseID: releaseFor(action, operationType), Deployment: runtimeResult.Deployment, RollbackData: false, DataNotice: "Application code/configuration only; persistent data is not rolled back.", Evidence: append([]domain.EvidenceRef(nil), runtimeResult.Evidence...)}
	if err := c.Store.CommitM4Operation(ctx, c.commit(result, request, digest, true, "")); err != nil {
		return M4OperationResult{}, err
	}
	return result, nil
}

func (c *M4OperationsController) fail(ctx context.Context, reservation M4OperationReservation, request M4OperationRequest, digest, action, scope string, cause error) (M4OperationResult, error) {
	if action == "" {
		action = actionNameFor(reservation.Operation.Type)
	}
	if scope == "" {
		scope = scopeFor(reservation.Operation.Type)
	}
	safe := foundation.RedactText(cause.Error())
	result := M4OperationResult{Operation: terminalM4Operation(reservation.Operation, domain.OperationFailed, c.Clock().UTC()), Action: action, Scope: scope, ReleaseID: reservation.Environment.CurrentRelease.ID, Deployment: reservation.Environment.CurrentDeployment, RollbackData: false, DataNotice: "Operation failed; the most recently usable deployment remains the recovery target. Persistent data is not rolled back.", KeptLastUsable: true}
	if commitErr := c.Store.CommitM4Operation(ctx, c.commit(result, request, digest, false, safe)); commitErr != nil {
		return result, fmt.Errorf("operation failed: %w; persist failure: %v", cause, commitErr)
	}
	return result, cause
}

func (c *M4OperationsController) commit(result M4OperationResult, request M4OperationRequest, inputDigest string, succeeded bool, failure string) M4OperationCommit {
	encoded, _ := json.Marshal(result)
	resultDigest := m4Digest(string(encoded))
	status := "succeeded"
	message := result.Action + " completed"
	if !succeeded {
		status, message = "failed", result.Action+" failed; latest usable deployment retained"
	}
	return M4OperationCommit{Operation: result.Operation, Succeeded: succeeded, Result: cloneM4Result(result), Failure: failure, Audit: M4AuditRecord{Actor: request.Actor, Reason: request.Reason, Action: "operations." + result.Action, InputDigest: inputDigest, ResultDigest: resultDigest, Evidence: append([]domain.EvidenceRef(nil), result.Evidence...)}, Outbox: application.Event{SchemaVersion: "1.1", OperationID: result.Operation.ID.String(), ApplicationID: request.ApplicationID.String(), OccurredAt: c.Clock().UTC(), Kind: "operations." + result.Action + "." + status, Status: status, Message: message}}
}

func validateM4Request(request M4OperationRequest) error {
	if request.ApplicationID.Empty() || request.EnvironmentID.Empty() || strings.TrimSpace(request.IdempotencyKey) == "" || strings.TrimSpace(request.ExpectedVersion) == "" || strings.TrimSpace(request.Actor) == "" || strings.TrimSpace(request.Reason) == "" {
		return domain.ValidationError("operations application, environment, idempotency key, expected fact version, actor, and reason are required")
	}
	return nil
}

func validateM4Environment(environment M4Environment) error {
	if strings.TrimSpace(environment.FactVersion) == "" || environment.ApplicationID.Empty() || environment.EnvironmentID.Empty() || environment.CurrentDeployment.ApplicationID != environment.ApplicationID || environment.CurrentDeployment.EnvironmentID != environment.EnvironmentID || environment.CurrentRelease.ApplicationID != environment.ApplicationID || environment.CurrentDeployment.ReleaseID != environment.CurrentRelease.ID {
		return domain.ValidationError("operations environment facts are inconsistent")
	}
	if err := environment.CurrentRelease.Validate(); err != nil {
		return err
	}
	if err := environment.CurrentDeployment.Validate(); err != nil {
		return err
	}
	if !environment.CurrentDeployment.RuntimeReady() || environment.CurrentRelease.Status != domain.ReleaseReady {
		return domain.NewError(domain.ErrInvalidTransition, "operations require a runtime-ready deployment and current successful release")
	}
	return nil
}

func validateM4RuntimeResult(result M4RuntimeResult, environment M4Environment, operationType domain.OperationType) error {
	if result.Deployment.ID.Empty() || result.Deployment.ApplicationID != environment.ApplicationID || result.Deployment.EnvironmentID != environment.EnvironmentID || !result.Deployment.RuntimeReady() {
		return domain.ValidationError("runtime operation did not return a runtime-ready deployment")
	}
	want := environment.CurrentRelease.ID
	if operationType == domain.OperationRollback {
		want = environment.PreviousSuccessful.Release.ID
	}
	if result.Deployment.ReleaseID != want {
		return domain.ValidationError("runtime operation returned a deployment for an unexpected release")
	}
	return nil
}

func unhealthyServices(services []M4ServiceState) []string {
	values := make([]string, 0, len(services))
	for _, service := range services {
		if !service.Healthy && strings.TrimSpace(service.Name) != "" {
			values = append(values, strings.TrimSpace(service.Name))
		}
	}
	sort.Strings(values)
	return values
}

func terminalM4Operation(operation domain.Operation, status domain.OperationStatus, now time.Time) domain.Operation {
	copy := operation
	if copy.Status == domain.OperationRunning {
		if status == domain.OperationRolledBack {
			_ = copy.Transition(domain.OperationRollingBack, now)
		}
		_ = copy.Transition(status, now)
	}
	return copy
}

func releaseFor(action M4RuntimeAction, operationType domain.OperationType) domain.ID {
	if operationType == domain.OperationRollback && action.PreviousSuccessful != nil {
		return action.PreviousSuccessful.Release.ID
	}
	return action.Current.Release.ID
}

func actionNameFor(operationType domain.OperationType) string {
	switch operationType {
	case domain.OperationRestart:
		return "restart"
	case domain.OperationRedeploy:
		return "redeploy"
	case domain.OperationRollback:
		return "rollback"
	default:
		return "operation"
	}
}

func scopeFor(operationType domain.OperationType) string {
	if operationType == domain.OperationRestart {
		return "application"
	}
	return "application"
}

func m4Digest(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(value))
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func cloneM4Result(result M4OperationResult) M4OperationResult {
	result.Evidence = append([]domain.EvidenceRef(nil), result.Evidence...)
	return result
}
