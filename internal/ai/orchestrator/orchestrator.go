package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

var (
	ErrDisabled             = errors.New("controlled AI is disabled")
	ErrManualFallback       = errors.New("controlled AI requires manual fallback")
	ErrConfirmationRequired = errors.New("controlled AI confirmation is required")
	ErrControllerHandoff    = errors.New("production action requires controller handoff")
	ErrPolicyDenied         = errors.New("controlled AI policy denied the plan")
	ErrVerificationFailed   = errors.New("controlled AI independent verification failed")
)

type TriggerReason string

const (
	TriggerRuleMiss          TriggerReason = "rule_miss"
	TriggerRuleConflict      TriggerReason = "rule_conflict"
	TriggerValidationFailure TriggerReason = "validation_failed"
)

type Request struct {
	ApplicationID      domain.ID
	TaskType           string
	Reason             TriggerReason
	ProblemFingerprint string
	ObjectVersions     map[string]string
	Profile            string
	IdempotencyKey     string
	Actor              string
	Confirmed          bool
	MaxTokens          int
	MaxDuration        time.Duration
	RuleResolved       bool
	ContextInput       any
}

type ContextBuilder interface {
	Build(context.Context, Request) (domain.AIContextPackage, error)
}

type CatalogAuthorizer interface {
	Authorize(context.Context, domain.AIActionPlan, Request) error
}

type ExecutionResult struct {
	ActionEvidence   []domain.EvidenceRef
	Verification     []domain.EvidenceRef
	RollbackEvidence []domain.EvidenceRef
	CandidateDiff    string
	Verified         bool
	RolledBack       bool
}

type Runner interface {
	Execute(context.Context, domain.AIActionPlan, Request) (ExecutionResult, error)
	Rollback(context.Context, domain.AIActionPlan, Request) ([]domain.EvidenceRef, error)
}

type Ledger interface {
	Append(context.Context, LedgerEntry) (LedgerEntry, error)
	Lookup(context.Context, domain.ID) (LedgerEntry, bool, error)
}

type LedgerEntry struct {
	Record         domain.AIInterventionRecord
	Invocation     domain.AIInvocation
	Context        domain.AIContextPackage
	Plan           domain.AIActionPlan
	Execution      *ExecutionResult
	IdempotencyKey string
	RequestDigest  string
}

type CandidateSink interface {
	Evaluate(context.Context, domain.AIInterventionRecord, string) (*domain.RuleCandidate, error)
}

type Result struct {
	Status            string                       `json:"status"`
	Degraded          bool                         `json:"degraded"`
	ManualQuestion    string                       `json:"manual_question,omitempty"`
	ControllerHandoff bool                         `json:"controller_handoff"`
	Invocation        *domain.AIInvocation         `json:"invocation,omitempty"`
	Plan              *domain.AIActionPlan         `json:"plan,omitempty"`
	Execution         *ExecutionResult             `json:"execution,omitempty"`
	Ledger            *domain.AIInterventionRecord `json:"ledger,omitempty"`
	Candidate         *domain.RuleCandidate        `json:"candidate,omitempty"`
}

type Orchestrator struct {
	Enabled       bool
	Context       ContextBuilder
	Provider      contracts.AIProvider
	Catalog       CatalogAuthorizer
	Runner        Runner
	Ledger        Ledger
	Candidates    CandidateSink
	PolicyVersion string
	Clock         func() time.Time
}

func (o *Orchestrator) Process(ctx context.Context, request Request) (Result, error) {
	if request.RuleResolved {
		return Result{Status: "rule_resolved"}, nil
	}
	if err := validateRequest(request); err != nil {
		return Result{}, err
	}
	if o == nil || !o.Enabled || o.Provider == nil {
		return degradedResult(request, "AI service is disabled; provide the minimum missing field or continue with a manual draft"), ErrDisabled
	}
	if o.Context == nil || o.Catalog == nil || o.Runner == nil || o.Ledger == nil {
		return degradedResult(request, "AI control dependencies are unavailable; continue with deterministic rules or manual review"), ErrManualFallback
	}
	if existing, ok, err := o.Ledger.Lookup(ctx, recordIDFor(request)); err != nil {
		return Result{}, err
	} else if ok {
		return Result{Status: existing.Record.Outcome, Ledger: &existing.Record, Invocation: &existing.Invocation, Plan: &existing.Plan, Execution: existing.Execution, Degraded: existing.Record.Outcome != "succeeded"}, nil
	}
	contextPackage, err := o.Context.Build(ctx, request)
	if err != nil {
		return degradedResult(request, "Only the missing field can be requested manually; no AI action was executed"), fmt.Errorf("build controlled AI context: %w", err)
	}
	if err := contextPackage.Validate(); err != nil {
		return degradedResult(request, "Context validation failed; no AI action was executed"), err
	}
	call, err := o.Provider.StructuredCall(ctx, contracts.AIRequest{TaskType: request.TaskType, Context: contextPackage, Budget: contracts.TokenBudget{MaxTokens: request.MaxTokens, MaxDuration: request.MaxDuration}, Operation: contracts.OperationContext{IdempotencyKey: request.IdempotencyKey, Deadline: deadline(request), Actor: request.Actor}})
	if err != nil {
		return degradedResult(request, "AI service is unavailable; deterministic rules and manual review remain available"), err
	}
	if err := call.Plan.Validate(); err != nil {
		record, appendErr := o.record(ctx, request, contextPackage, call, "plan_rejected", nil, false)
		result := Result{Status: "plan_rejected", Degraded: true, Invocation: &call.Invocation, Plan: &call.Plan, Ledger: record, ManualQuestion: "The AI plan was invalid and was not executed"}
		if appendErr != nil {
			return result, errors.Join(err, appendErr)
		}
		return result, err
	}
	decision, err := o.validatePolicy(ctx, request, call.Plan)
	if err != nil {
		record, appendErr := o.record(ctx, request, contextPackage, call, decision, nil, false)
		result := Result{Status: decision, Degraded: true, Invocation: &call.Invocation, Plan: &call.Plan, Ledger: record, ManualQuestion: policyMessage(decision)}
		if errors.Is(err, ErrControllerHandoff) {
			result.ControllerHandoff = true
		}
		if appendErr != nil {
			return result, errors.Join(err, appendErr)
		}
		return result, err
	}
	execution, runErr := o.Runner.Execute(ctx, call.Plan, request)
	if runErr != nil || !execution.Verified {
		rollbackEvidence, rollbackErr := o.Runner.Rollback(ctx, call.Plan, request)
		execution.RollbackEvidence = append(execution.RollbackEvidence, rollbackEvidence...)
		execution.RolledBack = rollbackErr == nil
		record, appendErr := o.record(ctx, request, contextPackage, call, "rolled_back", &execution, execution.RolledBack)
		result := Result{Status: "rolled_back", Degraded: true, Invocation: &call.Invocation, Plan: &call.Plan, Execution: &execution, Ledger: record, ManualQuestion: "Sandbox verification failed; the candidate was rolled back and production was unchanged"}
		return result, errors.Join(ErrVerificationFailed, runErr, rollbackErr, appendErr)
	}
	record, err := o.record(ctx, request, contextPackage, call, "succeeded", &execution, false)
	if err != nil {
		return Result{}, err
	}
	result := Result{Status: "succeeded", Invocation: &call.Invocation, Plan: &call.Plan, Execution: &execution, Ledger: record}
	if o.Candidates != nil {
		candidate, candidateErr := o.Candidates.Evaluate(ctx, *record, execution.CandidateDiff)
		if candidateErr != nil {
			return result, candidateErr
		}
		result.Candidate = candidate
	}
	return result, nil
}

func (o *Orchestrator) validatePolicy(ctx context.Context, request Request, plan domain.AIActionPlan) (string, error) {
	if plan.PolicyVersion != o.PolicyVersion || plan.TaskType != request.TaskType || request.MaxTokens <= 0 || request.MaxDuration <= 0 || plan.Budget.MaxTokens > request.MaxTokens || time.Duration(plan.Budget.MaxDurationMS)*time.Millisecond > request.MaxDuration {
		return "budget_or_policy_denied", ErrPolicyDenied
	}
	for _, action := range plan.Actions {
		if action.Risk == domain.AIRiskProductionChange {
			return "controller_handoff", ErrControllerHandoff
		}
		if action.Risk == domain.AIRiskCandidateChange && !request.Confirmed {
			return "awaiting_confirmation", ErrConfirmationRequired
		}
	}
	if err := o.Catalog.Authorize(ctx, plan, request); err != nil {
		return "tool_denied", errors.Join(ErrPolicyDenied, err)
	}
	return "policy_validated", nil
}

func (o *Orchestrator) record(ctx context.Context, request Request, contextPackage domain.AIContextPackage, call contracts.AIResult, outcome string, execution *ExecutionResult, rolledBack bool) (*domain.AIInterventionRecord, error) {
	recordID := recordIDFor(request)
	record := domain.AIInterventionRecord{ID: recordID, ApplicationID: request.ApplicationID, ProblemFingerprint: request.ProblemFingerprint, InvocationID: call.Invocation.ID, PlanID: call.Plan.ID, Outcome: outcome, Tokens: call.Invocation.Tokens, DurationMS: call.Invocation.DurationMS, RolledBack: rolledBack}
	if execution != nil {
		record.Verification = append([]domain.EvidenceRef(nil), execution.Verification...)
		record.RollbackEvidence = append([]domain.EvidenceRef(nil), execution.RollbackEvidence...)
	}
	stored, err := o.Ledger.Append(ctx, LedgerEntry{Record: record, Invocation: call.Invocation, Context: contextPackage, Plan: call.Plan, Execution: execution, IdempotencyKey: request.IdempotencyKey, RequestDigest: request.ProblemFingerprint})
	if err != nil {
		return nil, err
	}
	return &stored.Record, nil
}

func recordIDFor(request Request) domain.ID {
	recordID := domain.ID("airec_" + strings.TrimPrefix(request.IdempotencyKey, "ai:"))
	if err := domain.RequireID(recordID, "AI intervention record id"); err == nil {
		return recordID
	}
	return domain.ID("airec_fallback")
}

func validateRequest(request Request) error {
	if err := domain.RequireID(request.ApplicationID, "AI request application id"); err != nil {
		return err
	}
	if strings.TrimSpace(request.TaskType) == "" || strings.TrimSpace(request.ProblemFingerprint) == "" || strings.TrimSpace(request.Profile) == "" || strings.TrimSpace(request.IdempotencyKey) == "" || strings.TrimSpace(request.Actor) == "" || len(request.ObjectVersions) == 0 {
		return errors.New("controlled AI request identity, task, versions, profile, and actor are required")
	}
	switch request.Reason {
	case TriggerRuleMiss, TriggerRuleConflict, TriggerValidationFailure:
	default:
		return errors.New("controlled AI can only be triggered after a deterministic rule miss, conflict, or validation failure")
	}
	return nil
}

func degradedResult(request Request, message string) Result {
	return Result{Status: "manual_fallback", Degraded: true, ManualQuestion: message}
}

func policyMessage(decision string) string {
	switch decision {
	case "awaiting_confirmation":
		return "Review the candidate diff and explicitly confirm before any R2 sandbox change"
	case "controller_handoff":
		return "Use the existing operations controller and confirmation flow for production changes"
	default:
		return "The plan was denied; deterministic rules and manual review remain available"
	}
}

func deadline(request Request) time.Time {
	if request.MaxDuration <= 0 {
		return time.Time{}
	}
	return time.Now().UTC().Add(request.MaxDuration)
}
