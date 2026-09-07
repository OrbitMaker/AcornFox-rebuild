package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/open-card/open-card/internal/assistant"
	"github.com/open-card/open-card/internal/assistantactions"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

type AcornFoxAssistantActionsHTTPHandler struct{ Service *assistantactions.Service }
type assistantActionDecisionInput struct {
	Approve *bool `json:"approve"`
}

// Handle must be called after AcornFox session/origin/CSRF authentication and
// before the broader assistant sessions handler. It trusts only the Actor
// injected by that parent boundary.
func (h *AcornFoxAssistantActionsHTTPHandler) Handle(w http.ResponseWriter, r *http.Request) bool {
	base := assistant.HTTPBasePath + "/sessions/"
	if !strings.HasPrefix(r.URL.Path, base) {
		return false
	}
	relative := strings.TrimPrefix(r.URL.Path, base)
	parts := strings.Split(relative, "/")
	if len(parts) == 0 || parts[0] == "" || ((len(parts) != 2 || parts[1] != "actions") && (len(parts) != 4 || parts[1] != "actions" || parts[2] == "" || parts[3] != "decision")) {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := assistant.ActorFromContext(r.Context())
	if !ok {
		assistantActionError(w, http.StatusUnauthorized, "assistant_action_unauthorized", "authentication required")
		return true
	}
	if h == nil || h.Service == nil {
		assistantActionError(w, http.StatusServiceUnavailable, "assistant_action_unavailable", "assistant action unavailable")
		return true
	}
	if r.URL.RawQuery != "" {
		assistantActionError(w, http.StatusBadRequest, "assistant_action_invalid", "invalid request")
		return true
	}
	sid := domain.ID(parts[0])
	if len(parts) == 2 {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			assistantActionError(w, http.StatusMethodNotAllowed, "assistant_action_method", "method not allowed")
			return true
		}
		items, err := h.Service.List(r.Context(), actor, sid)
		if err != nil {
			writeAssistantActionServiceError(w, err)
			return true
		}
		writeJSON(w, http.StatusOK, map[string]any{"actions": items})
		return true
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		assistantActionError(w, http.StatusMethodNotAllowed, "assistant_action_method", "method not allowed")
		return true
	}
	var input assistantActionDecisionInput
	if !decodeAssistantActionJSON(w, r, &input) {
		return true
	}
	if input.Approve == nil {
		assistantActionError(w, http.StatusBadRequest, "assistant_action_invalid", "invalid request")
		return true
	}
	proposal, err := h.Service.Decide(r.Context(), actor, sid, domain.ID(parts[2]), *input.Approve)
	if err != nil {
		writeAssistantActionServiceError(w, err)
		return true
	}
	status := http.StatusOK
	if *input.Approve && (proposal.State == assistantactions.StateAccepted || proposal.State == assistantactions.StateUnknown || proposal.State == assistantactions.StateExecuting) {
		status = http.StatusAccepted
	}
	writeJSON(w, status, proposal)
	return true
}

type acornFoxAssistantActionExecutor struct{ Command acornFoxDeliveryCommand }

func (e acornFoxAssistantActionExecutor) Execute(ctx context.Context, request assistantactions.ExecutionRequest) (assistantactions.ExecutionResult, error) {
	if e.Command == nil {
		return assistantactions.ExecutionResult{}, assistantactions.ErrExecutionRejected
	}
	var result acornFoxDeliveryResult
	var err error
	switch request.Action {
	case assistantactions.ActionRestart:
		result, err = e.Command.Restart(ctx, request.Target.ApplicationID, request.Target.DeploymentID, request.IdempotencyKey, request.Actor.AdminID.String())
	case assistantactions.ActionRedeploy:
		result, err = e.Command.Redeploy(ctx, request.Target.ApplicationID, request.Target.DeploymentID, request.IdempotencyKey, request.Actor.AdminID.String())
	default:
		return assistantactions.ExecutionResult{}, assistantactions.ErrExecutionRejected
	}
	return assistantactions.ExecutionResult{OperationID: result.OperationID, Accepted: err == nil && !result.OperationID.Empty()}, err
}

func decodeAssistantActionJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.Body == nil {
		assistantActionError(w, http.StatusBadRequest, "assistant_action_invalid", "invalid request")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(target); err != nil {
		assistantActionError(w, http.StatusBadRequest, "assistant_action_invalid", "invalid request")
		return false
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		assistantActionError(w, http.StatusBadRequest, "assistant_action_invalid", "invalid request")
		return false
	}
	return true
}
func writeAssistantActionServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, assistantactions.ErrInvalid):
		assistantActionError(w, http.StatusBadRequest, "assistant_action_invalid", "invalid request")
	case errors.Is(err, assistantactions.ErrNotFound):
		assistantActionError(w, http.StatusNotFound, "assistant_action_not_found", "assistant action not found")
	case errors.Is(err, assistantactions.ErrConflict), errors.Is(err, assistantactions.ErrExpired), errors.Is(err, assistantactions.ErrTargetChanged):
		assistantActionError(w, http.StatusConflict, "assistant_action_conflict", "assistant action cannot be executed")
	default:
		assistantActionError(w, http.StatusServiceUnavailable, "assistant_action_unavailable", "assistant action unavailable")
	}
}
func assistantActionError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"code": code, "message": message})
}

var _ assistantactions.Executor = acornFoxAssistantActionExecutor{}

// Action verification is tied to the exact app, action and deployment selected
// in the approved proposal. A probe or another deployment is never its proof.
type acornFoxAssistantActionVerifier struct{ Reader acornFoxOperationReader }

func (v acornFoxAssistantActionVerifier) Verify(ctx context.Context, action assistantactions.Action, target assistantactions.Target, operationID domain.ID) (assistantactions.Verification, error) {
	pending := assistantactions.Verification{State: assistantactions.VerificationPending}
	if v.Reader == nil {
		return pending, assistantactions.ErrUnavailable
	}
	result, err := v.Reader.GetAcornFoxOperationResult(ctx, target.ApplicationID, operationID)
	if err != nil || result.Validate() != nil || result.OperationID != operationID || result.DeploymentID != target.DeploymentID || result.OperationType != string(action) {
		return pending, assistantactions.ErrUnavailable
	}
	switch result.Status {
	case contracts.AcornFoxOperationVerified:
		at := result.Evidence.ObservedAt
		return assistantactions.Verification{State: assistantactions.VerificationVerified, Verdict: string(result.Evidence.Verdict), ObservedAt: &at}, nil
	case contracts.AcornFoxOperationFailed:
		return assistantactions.Verification{State: assistantactions.VerificationFailed, Verdict: "failed"}, nil
	default:
		return pending, nil
	}
}
