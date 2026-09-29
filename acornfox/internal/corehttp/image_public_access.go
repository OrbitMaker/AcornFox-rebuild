package corehttp

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/acornfox/acornfox/internal/application"
	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/auth"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/persistence/sqlite"
)

const ImageDomainOperationsAPIBase = "/api/v1/acornfox/image-domain-operations/"

// ImagePublicAccessHandler exposes only the domain command and current local
// route fact. It cannot claim DNS, HTTPS or current endpoint reachability.
type ImagePublicAccessHandler struct {
	Commands  *application.ImagePublicAccessCommands
	Store     appcontracts.ImagePublicAccessStore
	Available func(context.Context) error
	Auth      *auth.Service
	Config    AuthRouteConfig
}

func publicImageDomainCommand(b appcontracts.ImagePublicAccessCommand) appcontracts.ImagePublicAccessOperation {
	return appcontracts.ImagePublicAccessOperation{OperationID: b.OperationID, TaskID: b.TaskID, ApprovalID: b.ApprovalID, DeploymentID: b.DeploymentID, Hostname: b.Hostname, Action: b.Action, State: b.State, CreatedAt: b.CreatedAt}
}

func domainAvailability(a appcontracts.ImagePublicAccessApproval) string {
	if a.LocalRouteState == "disabled" {
		return "disabled"
	}
	if a.DeploymentStatus != "running" || a.LocalRouteState == "reconcile_required" || a.Command.State == "waiting" || a.Command.State == "failed" {
		return "degraded"
	}
	if !a.DesiredPublic {
		return "pending"
	}
	if a.LocalRouteState == "configured" && a.Command.State == "succeeded" {
		return "unverified"
	}
	return "pending"
}

func (h *ImagePublicAccessHandler) Handle(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	isOperation := strings.HasPrefix(path, ImageDomainOperationsAPIBase)
	var deploymentID string
	var action string
	if !isOperation && strings.HasPrefix(path, ImageDeploymentsAPIBase) {
		parts := strings.Split(strings.TrimPrefix(path, ImageDeploymentsAPIBase), "/")
		if len(parts) == 2 && parts[0] != "" && (parts[1] == "domain" || parts[1] == "domain-commands") {
			deploymentID, action = parts[0], parts[1]
		}
	}
	if !isOperation && deploymentID == "" {
		return false
	}
	req, ok := AuthenticateControlPlane(h.Auth, h.Config, w, r)
	if !ok {
		return true
	}
	identity, ok := ControlPlaneIdentityFromContext(req.Context())
	if !ok || identity.AdminID.Empty() {
		AuthHTTPError(w, http.StatusUnauthorized, "authentication failed")
		return true
	}
	if req.URL.RawQuery != "" {
		WriteJSONError(w, http.StatusBadRequest, "invalid_request", "query parameters are not supported")
		return true
	}
	if h.Store == nil {
		WriteJSONError(w, http.StatusServiceUnavailable, "service_unavailable", "domain service unavailable")
		return true
	}
	if isOperation {
		opID := strings.TrimPrefix(path, ImageDomainOperationsAPIBase)
		if opID == "" || strings.Contains(opID, "/") {
			WriteJSONError(w, http.StatusNotFound, "not_found", "route not found")
			return true
		}
		if req.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			WriteJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return true
		}
		value, err := h.Store.ReadImagePublicAccessOperation(req.Context(), identity.AdminID, domain.ID(opID))
		if err != nil {
			h.writeError(w, err)
			return true
		}
		WriteJSON(w, http.StatusOK, value)
		return true
	}
	if action == "domain" {
		if req.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			WriteJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return true
		}
		approval, err := h.Store.GetImagePublicAccess(req.Context(), identity.AdminID, domain.ID(deploymentID))
		if err != nil {
			h.writeError(w, err)
			return true
		}
		operation, err := h.Store.ReadImagePublicAccessOperation(req.Context(), identity.AdminID, approval.Command.OperationID)
		if err != nil || operation.OperationID != approval.Command.OperationID {
			WriteJSONError(w, http.StatusConflict, "conflict", "domain state changed; refresh")
			return true
		}
		WriteJSON(w, http.StatusOK, appcontracts.ImagePublicAccessCurrent{Operation: operation, DesiredPublic: approval.DesiredPublic, LocalRouteState: approval.LocalRouteState, DeploymentStatus: approval.DeploymentStatus, Availability: domainAvailability(approval)})
		return true
	}
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		WriteJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return true
	}
	var input appcontracts.ImagePublicAccessCommandInput
	if decodeStrictJSON(req.Body, &input) != nil || input.IdempotencyKey == "" || len(input.IdempotencyKey) > 256 || req.Header.Get("Idempotency-Key") == "" || req.Header.Get("Idempotency-Key") != input.IdempotencyKey || appcontracts.ValidateImagePublicHostname(input.Hostname) != nil || (input.Action != appcontracts.ImagePublicAccessEnsure && input.Action != appcontracts.ImagePublicAccessRemove) {
		WriteJSONError(w, http.StatusBadRequest, "invalid_request", "exact hostname, action and matching idempotency key required")
		return true
	}
	create := appcontracts.ImagePublicAccessRequest{DeploymentID: domain.ID(deploymentID), Hostname: input.Hostname, Action: input.Action, IdempotencyKey: input.IdempotencyKey}
	if h.Commands == nil || h.Available == nil || h.Available(req.Context()) != nil {
		// A lost 202 response remains recoverable under the same key/body even
		// when Gateway goes away. New intents cannot be created on this path.
		original, replayErr := h.Store.ReplayImagePublicAccess(req.Context(), identity.AdminID, create)
		if replayErr == nil {
			WriteJSON(w, http.StatusAccepted, publicImageDomainCommand(original))
		} else if errors.Is(replayErr, sqlite.ErrNotFound) {
			WriteJSONError(w, http.StatusServiceUnavailable, "service_unavailable", "Gateway unavailable; retry the same command later")
		} else {
			h.writeError(w, replayErr)
		}
		return true
	}
	b, err := h.Commands.Begin(req.Context(), identity.AdminID, create)
	if err != nil {
		h.writeError(w, err)
		return true
	}
	WriteJSON(w, http.StatusAccepted, publicImageDomainCommand(b))
	return true
}

func (h *ImagePublicAccessHandler) writeError(w http.ResponseWriter, err error) {
	if errors.Is(err, sqlite.ErrImagePublicAccessUnavailable) {
		WriteJSONError(w, http.StatusServiceUnavailable, "service_unavailable", "domain schema unavailable")
		return
	}
	writeDeliveryError(w, err)
}
