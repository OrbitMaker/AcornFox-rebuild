package corehttp

import (
	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/domain"
	"net/http"
	"strings"
)

const ImageDeploymentsAPIBase = "/api/v1/acornfox/image-deployments/"
const ImageLifecycleOperationsAPIBase = "/api/v1/acornfox/image-lifecycle-operations/"

func publicImageLifecycle(b appcontracts.ImageLifecycleBinding) appcontracts.ImageLifecycleOperation {
	state := b.State
	if state == "waiting" {
		state = "unknown"
	}
	reason := ""
	if state == "failed" || state == "unknown" {
		reason = b.Reason
	}
	return appcontracts.ImageLifecycleOperation{Reason: reason, OperationID: b.OperationID, TaskID: b.TaskID, DeploymentID: b.DeploymentID, ReleaseID: b.ReleaseID, ApplicationID: b.ApplicationID, EnvironmentID: b.EnvironmentID, DeployOperationID: b.DeployOperationID, PlanID: b.PlanID, PlanDigest: b.PlanDigest, ManifestDigest: b.ManifestDigest, ContainerID: b.ContainerID, ImageID: b.ImageID, HostPort: b.HostPort, ContainerPort: b.ContainerPort, Action: b.Action, State: state, CreatedAt: b.CreatedAt, RecoveryRequired: b.RecoveryRequired, Result: b.Result}
}
func (h *ImageDeliveryHandler) handleImageLifecycle(w http.ResponseWriter, r *http.Request) {
	req, ok := AuthenticateControlPlane(h.Auth, h.Config, w, r)
	if !ok {
		return
	}
	identity, ok := ControlPlaneIdentityFromContext(req.Context())
	if !ok || identity.AdminID.Empty() {
		AuthHTTPError(w, http.StatusUnauthorized, "authentication failed")
		return
	}
	if h.Store == nil {
		WriteJSONError(w, http.StatusServiceUnavailable, "service_unavailable", "store unavailable")
		return
	}
	if req.URL.RawQuery != "" {
		WriteJSONError(w, http.StatusBadRequest, "invalid_request", "query parameters are not supported")
		return
	}
	if strings.HasPrefix(req.URL.Path, ImageDeploymentsAPIBase) {
		parts := strings.Split(strings.TrimPrefix(req.URL.Path, ImageDeploymentsAPIBase), "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] != "lifecycle" {
			WriteJSONError(w, http.StatusNotFound, "not_found", "route not found")
			return
		}
		if req.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			WriteJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		var input appcontracts.ImageLifecycleCommandInput
		if err := decodeStrictJSON(req.Body, &input); err != nil {
			WriteJSONError(w, http.StatusBadRequest, "invalid_request", "invalid lifecycle command body")
			return
		}
		if key := req.Header.Get("Idempotency-Key"); key != "" && key != input.IdempotencyKey {
			WriteJSONError(w, http.StatusBadRequest, "invalid_request", "idempotency header differs from body")
			return
		}
		binding, err := h.Store.CreateImageLifecycle(req.Context(), identity.AdminID, appcontracts.CreateImageLifecycleInput{DeploymentID: domain.ID(parts[0]), Action: input.Action, IdempotencyKey: input.IdempotencyKey})
		if err != nil {
			writeDeliveryError(w, err)
			return
		}
		WriteJSON(w, http.StatusOK, publicImageLifecycle(binding))
		return
	}
	opID := strings.TrimPrefix(req.URL.Path, ImageLifecycleOperationsAPIBase)
	if opID == "" || strings.Contains(opID, "/") {
		WriteJSONError(w, http.StatusNotFound, "not_found", "route not found")
		return
	}
	if req.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		WriteJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	binding, err := h.Store.ReadImageLifecycle(req.Context(), identity.AdminID, domain.ID(opID))
	if err != nil {
		writeDeliveryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, publicImageLifecycle(binding))
}
