package runner

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-card/open-card/internal/ai/tools"
	"github.com/open-card/open-card/internal/domain"
)

// PlanRequest is the runner-facing bridge for the shared AIActionPlan
// contract. Policy validation remains separate from execution, and actions
// stop at the first failure or controller handoff.
type PlanRequest struct {
	Plan           domain.AIActionPlan
	Workspace      Workspace
	IdempotencyKey string
	Confirmed      bool
	TokenCount     int64
	Limits         tools.ResourceLimits
}

// PlanResult is an evidence-friendly aggregate. Each action retains its
// independent verification and rollback result in Actions.
type PlanResult struct {
	PlanID  domain.ID   `json:"plan_id"`
	Status  string      `json:"status"`
	Actions []RunResult `json:"actions"`
}

func (r *ActionRunner) RunPlan(ctx context.Context, request PlanRequest) (PlanResult, error) {
	result := PlanResult{PlanID: request.Plan.ID, Status: "rejected"}
	if err := r.catalog.ValidatePlan(request.Plan); err != nil {
		return result, err
	}
	base := strings.TrimSpace(request.IdempotencyKey)
	if base == "" {
		base = string(request.Plan.ID)
	}
	if base == "" {
		return result, fmt.Errorf("%w: plan idempotency key is required", ErrInvalidRequest)
	}
	for index, action := range request.Plan.Actions {
		key := fmt.Sprintf("%s/action-%d", base, index)
		actionResult, err := r.Run(ctx, ActionRequest{Action: action, Workspace: request.Workspace, IdempotencyKey: key, Confirmed: request.Confirmed, TokenCount: request.TokenCount, Limits: request.Limits})
		result.Actions = append(result.Actions, actionResult)
		if err != nil {
			result.Status = string(actionResult.Status)
			return result, err
		}
	}
	result.Status = string(StatusSucceeded)
	return result, nil
}

func (r *ActionRunner) ExecutePlan(ctx context.Context, request PlanRequest) (PlanResult, error) {
	return r.RunPlan(ctx, request)
}
