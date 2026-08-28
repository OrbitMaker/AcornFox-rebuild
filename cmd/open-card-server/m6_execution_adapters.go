package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	aicontext "github.com/open-card/open-card/internal/ai/context"
	"github.com/open-card/open-card/internal/ai/orchestrator"
	airunner "github.com/open-card/open-card/internal/ai/runner"
	aitools "github.com/open-card/open-card/internal/ai/tools"
	"github.com/open-card/open-card/internal/domain"
)

type m6ExecutionInput struct {
	Context   aicontext.Input
	Workspace airunner.Workspace
}

type m6ContextAdapter struct{ builder *aicontext.Builder }

func (a *m6ContextAdapter) Build(_ context.Context, request orchestrator.Request) (domain.AIContextPackage, error) {
	input, ok := request.ContextInput.(m6ExecutionInput)
	if !ok || a == nil || a.builder == nil {
		return domain.AIContextPackage{}, errors.New("controlled AI context input is unavailable")
	}
	input.Context.ApplicationID = request.ApplicationID
	input.Context.TaskType = request.TaskType
	input.Context.Profile = request.Profile
	if len(input.Context.Objects) == 0 {
		for kind, version := range request.ObjectVersions {
			input.Context.Objects = append(input.Context.Objects, aicontext.ObjectVersion{ApplicationID: request.ApplicationID, Scope: aicontext.ScopeObjectVersions, Kind: kind, ID: kind, Version: version})
		}
	}
	return a.builder.BuildContext(input.Context)
}

type m6CatalogAdapter struct{ catalog *aitools.ToolCatalog }

func (a *m6CatalogAdapter) Authorize(_ context.Context, plan domain.AIActionPlan, _ orchestrator.Request) error {
	if a == nil || a.catalog == nil {
		return errors.New("AI tool catalog is unavailable")
	}
	return a.catalog.ValidatePlan(plan)
}

type m6RunnerAdapter struct {
	runner *airunner.ActionRunner
	mu     sync.Mutex
	last   map[string][]airunner.RunResult
}

func (a *m6RunnerAdapter) Execute(ctx context.Context, plan domain.AIActionPlan, request orchestrator.Request) (orchestrator.ExecutionResult, error) {
	input, ok := request.ContextInput.(m6ExecutionInput)
	if !ok || a == nil || a.runner == nil {
		return orchestrator.ExecutionResult{}, errors.New("controlled AI runner input is unavailable")
	}
	result := orchestrator.ExecutionResult{Verified: true}
	runs := make([]airunner.RunResult, 0, len(plan.Actions))
	for index, action := range plan.Actions {
		run, err := a.runner.Run(ctx, airunner.ActionRequest{Action: action, Workspace: input.Workspace, IdempotencyKey: fmt.Sprintf("%s:action:%d", request.IdempotencyKey, index), Confirmed: request.Confirmed, TokenCount: int64(plan.Budget.MaxTokens)})
		runs = append(runs, run)
		result.ActionEvidence = append(result.ActionEvidence, m6RunnerEvidence("action", run.Evidence, index))
		result.Verification = append(result.Verification, m6RunnerEvidence("verification", run.Verification, index))
		if run.Diff != "" {
			if result.CandidateDiff != "" {
				result.CandidateDiff += "\n"
			}
			result.CandidateDiff += run.Diff
		}
		if run.RolledBack {
			result.RolledBack = true
			result.RollbackEvidence = append(result.RollbackEvidence, m6RunnerEvidence("rollback", run.Evidence, index))
		}
		if err != nil || !run.Verification.Independent || run.Status != airunner.StatusSucceeded {
			result.Verified = false
			a.remember(request.IdempotencyKey, runs)
			return result, err
		}
	}
	a.remember(request.IdempotencyKey, runs)
	return result, nil
}

func (a *m6RunnerAdapter) Rollback(_ context.Context, _ domain.AIActionPlan, request orchestrator.Request) ([]domain.EvidenceRef, error) {
	a.mu.Lock()
	runs := append([]airunner.RunResult(nil), a.last[request.IdempotencyKey]...)
	a.mu.Unlock()
	refs := []domain.EvidenceRef{}
	for index, run := range runs {
		if run.RolledBack || run.Cleanup {
			refs = append(refs, m6RunnerEvidence("rollback", run.Evidence, index))
		}
	}
	if len(refs) == 0 {
		return nil, errors.New("runner produced no rollback or cleanup evidence")
	}
	return refs, nil
}

func (a *m6RunnerAdapter) remember(key string, runs []airunner.RunResult) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.last == nil {
		a.last = map[string][]airunner.RunResult{}
	}
	a.last[key] = append([]airunner.RunResult(nil), runs...)
}

func m6RunnerEvidence(kind string, evidence airunner.Evidence, index int) domain.EvidenceRef {
	digest := strings.TrimSpace(evidence.Digest)
	if digest == "" {
		sum := sha256.Sum256([]byte(kind + string([]byte{0}) + evidence.Summary))
		digest = "sha256:" + hex.EncodeToString(sum[:])
	}
	return domain.EvidenceRef{ID: domain.ID(fmt.Sprintf("ev_ai_%s_%d", kind, index)), Kind: "ai." + kind, Digest: digest, Locator: "ledger://runner/" + kind}
}
