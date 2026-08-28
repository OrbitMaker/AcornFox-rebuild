package ledger

import (
	"context"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/ai/orchestrator"
	"github.com/open-card/open-card/internal/domain"
)

// Append implements the orchestrator.Ledger contract while keeping the
// durable representation owned by this package.  The adapter copies only
// domain metadata and evidence references; source/log bodies never cross the
// persistence boundary.
func (s *LocalStore) Append(ctx context.Context, entry orchestrator.LedgerEntry) (orchestrator.LedgerEntry, error) {
	return appendOrchestratorEntry(ctx, s, entry)
}
func (s *PostgresStore) Append(ctx context.Context, entry orchestrator.LedgerEntry) (orchestrator.LedgerEntry, error) {
	return appendOrchestratorEntry(ctx, s, entry)
}

func (s *LocalStore) Lookup(ctx context.Context, id domain.ID) (orchestrator.LedgerEntry, bool, error) {
	return lookupOrchestratorEntry(ctx, s, id)
}
func (s *PostgresStore) Lookup(ctx context.Context, id domain.ID) (orchestrator.LedgerEntry, bool, error) {
	return lookupOrchestratorEntry(ctx, s, id)
}

func appendOrchestratorEntry(ctx context.Context, repository Repository, entry orchestrator.LedgerEntry) (orchestrator.LedgerEntry, error) {
	now := time.Now().UTC()
	if entry.Invocation.ID.Empty() {
		entry.Invocation.ID = domain.ID("aiinv_" + strings.TrimSpace(entry.Record.InvocationID.String()))
	}
	invocation := Invocation{
		ID: string(entry.Invocation.ID), IdempotencyKey: entry.IdempotencyKey, RequestDigest: entry.RequestDigest,
		TaskType: entry.Plan.TaskType, ApplicationID: string(entry.Record.ApplicationID),
		ProblemFingerprint: entry.Record.ProblemFingerprint, VersionKey: VersionKeyFromDomain(entry.Context, entry.Plan),
		Provider: entry.Invocation.Provider, Model: entry.Invocation.Model, PolicyVersion: entry.Invocation.PolicyVersion,
		Profile: entry.Invocation.Profile, ContextID: string(entry.Invocation.ContextID), Status: normalizeOutcome(entry.Invocation.Status),
		Outcome: normalizeOutcome(entry.Record.Outcome), Tokens: safeInt64(entry.Invocation.Tokens), DurationMS: entry.Invocation.DurationMS,
		CreatedAt: now,
	}
	if invocation.TaskType == "" {
		invocation.TaskType = entry.Plan.TaskType
	}
	if invocation.ProblemFingerprint == "" {
		invocation.ProblemFingerprint = "sha256:unknown"
	}
	if invocation.VersionKey == "" {
		invocation.VersionKey = "sha256:unknown"
	}
	childNamespace := strings.TrimSpace(string(entry.Record.ID))
	if childNamespace == "" {
		childNamespace = strings.TrimSpace(string(entry.Invocation.ID))
	}
	// Providers may deterministically reuse an invocation/plan ID for the
	// same problem fingerprint.  The intervention record is the durable
	// occurrence identity, so namespace provider IDs here to keep repeated
	// successful cases append-only rather than colliding on a primary key.
	invocation.ID = "aiinv_" + childNamespace + "_" + strings.TrimSpace(invocation.ID)
	contextRecord := ContextPackage{
		ID: "aictx_" + childNamespace + "_" + strings.TrimSpace(string(entry.Context.ID)), InvocationID: invocation.ID, IdempotencyKey: entry.IdempotencyKey + ":context",
		Scope: append([]string(nil), entry.Context.Scope...), Authorized: entry.Context.Authorized, Redacted: entry.Context.Redacted,
		TemplateVersion: entry.Context.TemplateVersion, Profile: entry.Context.Profile, CreatedAt: now,
		SourceRefs:    domainReferences(entry.Context.SourceRefs),
		ApplicationID: string(entry.Context.ApplicationID), TaskType: entry.Context.TaskType,
		ObjectVersions: cloneStringMap(entry.Context.ObjectVersions), ManifestDigest: entry.Context.ManifestDigest,
		Bytes: entry.Context.Bytes, UntrustedData: entry.Context.UntrustedData,
	}
	invocation.ContextID = contextRecord.ID
	planRecord := ActionPlan{
		ID: "aiplan_" + childNamespace + "_" + strings.TrimSpace(string(entry.Plan.ID)), InvocationID: invocation.ID, IdempotencyKey: entry.IdempotencyKey + ":plan",
		TaskType: entry.Plan.TaskType, PolicyVersion: entry.Plan.PolicyVersion, Sources: append([]string(nil), entry.Plan.Sources...), TargetRefs: cloneStringMap(entry.Plan.TargetRefs), Assumptions: append([]string(nil), entry.Plan.Assumptions...),
		EvidenceRefs: domainReferences(entry.Plan.EvidenceRefs), RollbackID: entry.Plan.RollbackID, Confidence: entry.Plan.Confidence,
		RequiresUserConfirmation: entry.Plan.RequiresUserConfirmation, Budget: PlanBudget{MaxTokens: entry.Plan.Budget.MaxTokens, MaxDurationMS: entry.Plan.Budget.MaxDurationMS, MaxActions: entry.Plan.Budget.MaxActions}, SchemaVersion: entry.Plan.SchemaVersion, CreatedAt: now,
	}
	var actions []ToolAction
	for i, action := range entry.Plan.Actions {
		actionID := "aiaction_" + childNamespace + "_" + itoa(i)
		planRecord.Actions = append(planRecord.Actions, actionID)
		invocationAction := ToolAction{ID: actionID, InvocationID: invocation.ID, PlanID: planRecord.ID, IdempotencyKey: entry.IdempotencyKey + ":action:" + itoa(i), ToolID: action.ToolID, ToolVersion: action.ToolVersion, Parameters: cloneMap(action.Parameters), ExpectedResult: action.ExpectedResult, RiskClass: action.Risk, ValidationID: action.ValidationID, Status: invocation.Outcome, CreatedAt: now}
		if entry.Execution != nil && !entry.Execution.Verified {
			invocationAction.Status = OutcomeFailed
		}
		invocationAction.OutputDigest = firstDomainDigest(entry.Execution)
		actions = append(actions, invocationAction)
	}
	intervention := Intervention{ID: string(entry.Record.ID), Invocation: invocation, Context: &contextRecord, Plan: &planRecord, Actions: actions}
	if entry.Execution != nil {
		for i, ref := range entry.Execution.Verification {
			intervention.Verifications = append(intervention.Verifications, Verification{ID: "aiver_" + childNamespace + "_" + itoa(i), InvocationID: invocation.ID, PlanID: planRecord.ID, ValidatorID: "independent", Passed: entry.Execution.Verified, EvidenceRefs: domainReferences([]domain.EvidenceRef{ref}), CreatedAt: now})
		}
		if len(entry.Execution.RollbackEvidence) > 0 || entry.Execution.RolledBack {
			intervention.Rollback = &Rollback{ID: "airollback_" + childNamespace, InvocationID: invocation.ID, PlanID: planRecord.ID, RollbackID: firstNonEmpty(entry.Plan.RollbackID, "rollback_"+childNamespace), Status: map[bool]string{true: OutcomeSucceeded, false: OutcomeFailed}[entry.Execution.RolledBack], Reason: "independent verification recovery", EvidenceRefs: domainReferences(entry.Execution.RollbackEvidence), CreatedAt: now}
		}
	}
	intervention.Outcome = &Outcome{ID: "aioutcome_" + string(entry.Record.ID), InvocationID: invocation.ID, Status: normalizeOutcome(entry.Record.Outcome), Summary: entry.Record.Outcome, RolledBack: entry.Record.RolledBack, Tokens: safeInt64(entry.Invocation.Tokens), DurationMS: entry.Invocation.DurationMS, CreatedAt: now}
	stored, replayed, err := repository.AppendIntervention(ctx, AppendInterventionRequest{IdempotencyKey: entry.IdempotencyKey, RequestDigest: entry.RequestDigest, Record: intervention})
	if err != nil {
		return entry, err
	}
	entry.IdempotencyKey = stored.Invocation.IdempotencyKey
	entry.RequestDigest = stored.Invocation.RequestDigest
	if replayed {
		entry.Record.Outcome = stored.Invocation.Outcome
	}
	return entry, nil
}

func lookupOrchestratorEntry(ctx context.Context, repository Repository, id domain.ID) (orchestrator.LedgerEntry, bool, error) {
	item, err := repository.GetIntervention(ctx, string(id))
	if err != nil {
		if err == ErrNotFound {
			return orchestrator.LedgerEntry{}, false, nil
		}
		return orchestrator.LedgerEntry{}, false, err
	}
	entry := orchestrator.LedgerEntry{IdempotencyKey: item.Invocation.IdempotencyKey, RequestDigest: item.Invocation.RequestDigest}
	entry.Record = domain.AIInterventionRecord{ID: domain.ID(item.ID), ApplicationID: domain.ID(item.Invocation.ApplicationID), ProblemFingerprint: item.Invocation.ProblemFingerprint, InvocationID: domain.ID(item.Invocation.ID), Outcome: item.Invocation.Outcome, Tokens: uint64(maxInt64(item.Invocation.Tokens)), DurationMS: item.Invocation.DurationMS}
	entry.Invocation = domain.AIInvocation{ID: domain.ID(item.Invocation.ID), Provider: item.Invocation.Provider, Model: item.Invocation.Model, Profile: item.Invocation.Profile, PolicyVersion: item.Invocation.PolicyVersion, ProblemFingerprint: item.Invocation.ProblemFingerprint, ContextID: domain.ID(item.Invocation.ContextID), Tokens: uint64(maxInt64(item.Invocation.Tokens)), DurationMS: item.Invocation.DurationMS, Status: item.Invocation.Status}
	if item.Context != nil {
		entry.Context = domain.AIContextPackage{ID: domain.ID(item.Context.ID), ApplicationID: domain.ID(item.Context.ApplicationID), TaskType: item.Context.TaskType, Profile: item.Context.Profile, Scope: append([]string(nil), item.Context.Scope...), SourceRefs: domainReferencesBack(item.Context.SourceRefs), TemplateVersion: item.Context.TemplateVersion, Authorized: item.Context.Authorized, Redacted: item.Context.Redacted, UntrustedData: item.Context.UntrustedData, ObjectVersions: cloneStringMap(item.Context.ObjectVersions), ManifestDigest: item.Context.ManifestDigest, Bytes: item.Context.Bytes}
	}
	if item.Plan != nil {
		entry.Plan = domain.AIActionPlan{ID: domain.ID(item.Plan.ID), PolicyVersion: item.Plan.PolicyVersion, TaskType: item.Plan.TaskType, Sources: append([]string(nil), item.Plan.Sources...), TargetRefs: cloneStringMap(item.Plan.TargetRefs), Assumptions: append([]string(nil), item.Plan.Assumptions...), EvidenceRefs: domainReferencesBack(item.Plan.EvidenceRefs), RollbackID: item.Plan.RollbackID, Confidence: item.Plan.Confidence, RequiresUserConfirmation: item.Plan.RequiresUserConfirmation, Budget: domain.AIPlanBudget{MaxTokens: item.Plan.Budget.MaxTokens, MaxDurationMS: item.Plan.Budget.MaxDurationMS, MaxActions: item.Plan.Budget.MaxActions}, SchemaVersion: item.Plan.SchemaVersion}
		for _, action := range item.Actions {
			entry.Plan.Actions = append(entry.Plan.Actions, domain.AIAction{ToolID: action.ToolID, ToolVersion: action.ToolVersion, Parameters: cloneMap(action.Parameters), Risk: action.RiskClass, ExpectedResult: action.ExpectedResult, ValidationID: action.ValidationID})
		}
	}
	if item.Outcome != nil {
		entry.Record.Outcome = item.Outcome.Status
		entry.Record.RolledBack = item.Outcome.RolledBack
		entry.Record.Tokens = uint64(maxInt64(item.Outcome.Tokens))
		entry.Record.DurationMS = item.Outcome.DurationMS
	}
	if len(item.Verifications) > 0 || item.Rollback != nil {
		execution := &orchestrator.ExecutionResult{Verified: true}
		for _, verification := range item.Verifications {
			execution.Verification = append(execution.Verification, domainReferencesBack(verification.EvidenceRefs)...)
			if !verification.Passed {
				execution.Verified = false
			}
		}
		if item.Rollback != nil {
			execution.RolledBack = item.Rollback.Status == OutcomeSucceeded
			execution.RollbackEvidence = domainReferencesBack(item.Rollback.EvidenceRefs)
		}
		entry.Execution = execution
	}
	return entry, true, nil
}

func normalizeOutcome(value string) string {
	switch value {
	case OutcomeSucceeded:
		return OutcomeSucceeded
	case OutcomeRolledBack:
		return OutcomeRolledBack
	case OutcomePending, OutcomeRunning:
		return value
	default:
		if value == "" {
			return OutcomeUnknown
		}
		return OutcomeFailed
	}
}
func safeInt64(value uint64) int64 {
	if value > uint64(^uint64(0)>>1) {
		return int64(^uint64(0) >> 1)
	}
	return int64(value)
}
func maxInt64(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	out := ""
	for value > 0 {
		out = string(rune('0'+value%10)) + out
		value /= 10
	}
	return out
}
func domainReferences(refs []domain.EvidenceRef) []Reference {
	out := make([]Reference, 0, len(refs))
	for _, ref := range refs {
		out = append(out, Reference{ID: string(ref.ID), Kind: ref.Kind, Digest: ref.Digest, Locator: ref.Locator})
	}
	return out
}
func domainReferencesBack(refs []Reference) []domain.EvidenceRef {
	out := make([]domain.EvidenceRef, 0, len(refs))
	for _, ref := range refs {
		out = append(out, domain.EvidenceRef{ID: domain.ID(ref.ID), Kind: ref.Kind, Digest: ref.Digest, Locator: ref.Locator})
	}
	return out
}
func VersionKeyFromDomain(contextPackage domain.AIContextPackage, plan domain.AIActionPlan) string {
	if contextPackage.ManifestDigest != "" {
		return contextPackage.ManifestDigest
	}
	if plan.PolicyVersion != "" {
		return plan.PolicyVersion
	}
	return "sha256:unknown"
}
func firstDomainDigest(execution *orchestrator.ExecutionResult) string {
	if execution == nil || len(execution.ActionEvidence) == 0 {
		return ""
	}
	return execution.ActionEvidence[0].Digest
}
