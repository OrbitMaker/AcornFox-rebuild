package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
)

const m4OperationsBase = "/api/v1/operations/"

type m4OperationsAPI interface {
	Restart(context.Context, controllers.M4OperationRequest) (controllers.M4OperationResult, error)
	Redeploy(context.Context, controllers.M4OperationRequest) (controllers.M4OperationResult, error)
	Rollback(context.Context, controllers.M4OperationRequest) (controllers.M4OperationResult, error)
}

type m4OperationsViewReader interface {
	GetApplicationOperationsView(context.Context, domain.ID, domain.ID) (domain.ApplicationOperationsView, error)
}

type m4DefaultEnvironmentReader interface {
	GetDefaultEnvironmentID(context.Context, domain.ID) (domain.ID, error)
}

type M4OperationsHTTPHandler struct {
	Operations m4OperationsAPI
	Views      m4OperationsViewReader
}

type m4OperationInput struct {
	ApplicationID   domain.ID `json:"application_id"`
	EnvironmentID   domain.ID `json:"environment_id"`
	ExpectedVersion string    `json:"expected_version"`
	Reason          string    `json:"reason"`
}

type m4ApplicationOperationInput struct {
	Action          string `json:"action"`
	TargetServiceID string `json:"target_service_id,omitempty"`
	ExpectedVersion string `json:"expected_version"`
	Reason          string `json:"reason"`
}

func (h *M4OperationsHTTPHandler) Handle(writer http.ResponseWriter, request *http.Request) bool {
	if !strings.HasPrefix(request.URL.Path, m4OperationsBase) {
		return false
	}
	if h == nil || h.Operations == nil || h.Views == nil {
		writeJSONError(writer, http.StatusServiceUnavailable, "m4_operations_unavailable", "M4 operations are not configured")
		return true
	}
	if strings.HasPrefix(request.URL.Path, m4OperationsBase+"views/") {
		h.handleView(writer, request)
		return true
	}
	action := strings.TrimPrefix(request.URL.Path, m4OperationsBase)
	if action != "restart" && action != "redeploy" && action != "rollback" {
		writeJSONError(writer, http.StatusNotFound, "not_found", "M4 operations route not found")
		return true
	}
	h.handleAction(writer, request, action)
	return true
}

// HandleApplication exposes the browser-facing M4 contract. It resolves the
// sole default environment server-side, so a normal user never invents an
// environment ID in the browser. Server.serveHTTP calls this before the
// generic application reader claims the path.
func (h *M4OperationsHTTPHandler) HandleApplication(writer http.ResponseWriter, request *http.Request) bool {
	const suffix = "/operations"
	if !strings.HasPrefix(request.URL.Path, apiPrefix+"applications/") || !strings.HasSuffix(request.URL.Path, suffix) {
		return false
	}
	if h == nil || h.Operations == nil || h.Views == nil {
		writeJSONError(writer, http.StatusServiceUnavailable, "m4_operations_unavailable", "M4 operations are not configured")
		return true
	}
	applicationID := domain.ID(strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, apiPrefix+"applications/"), suffix))
	if domain.RequireID(applicationID, "operations application id") != nil {
		writeJSONError(writer, http.StatusBadRequest, "validation_failed", "application ID is required")
		return true
	}
	resolver, ok := h.Views.(m4DefaultEnvironmentReader)
	if !ok {
		writeJSONError(writer, http.StatusServiceUnavailable, "m4_operations_unavailable", "M4 default environment resolver is not configured")
		return true
	}
	environmentID, err := resolver.GetDefaultEnvironmentID(request.Context(), applicationID)
	if err != nil {
		writeDomainError(writer, err)
		return true
	}
	switch request.Method {
	case http.MethodGet:
		view, err := h.Views.GetApplicationOperationsView(request.Context(), applicationID, environmentID)
		if err != nil {
			writeDomainError(writer, err)
			return true
		}
		if err := view.Validate(); err != nil {
			writeJSONError(writer, http.StatusServiceUnavailable, "invalid_operations_fact", "stored operations facts are invalid")
			return true
		}
		writeJSON(writer, http.StatusOK, m4BrowserFacts(view))
	case http.MethodPost:
		h.handleApplicationAction(writer, request, applicationID, environmentID)
	default:
		writer.Header().Set("Allow", "GET, POST, OPTIONS")
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "operations requires GET or POST")
	}
	return true
}

func (h *M4OperationsHTTPHandler) handleView(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "operations view requires GET")
		return
	}
	applicationID := domain.ID(strings.TrimPrefix(request.URL.Path, m4OperationsBase+"views/"))
	environmentID := domain.ID(request.URL.Query().Get("environment_id"))
	if domain.RequireID(applicationID, "operations application id") != nil || domain.RequireID(environmentID, "operations environment id") != nil {
		writeJSONError(writer, http.StatusBadRequest, "validation_failed", "application and environment IDs are required")
		return
	}
	mode := request.URL.Query().Get("mode")
	if mode == "" {
		mode = "ordinary"
	}
	if mode != "ordinary" && mode != "operator" {
		writeJSONError(writer, http.StatusBadRequest, "validation_failed", "operations view mode is unsupported")
		return
	}
	if mode == "operator" && !m4Operator(request) {
		writeJSONError(writer, http.StatusForbidden, "forbidden", "operator view requires operator role")
		return
	}
	view, err := h.Views.GetApplicationOperationsView(request.Context(), applicationID, environmentID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if err := view.Validate(); err != nil {
		writeJSONError(writer, http.StatusServiceUnavailable, "invalid_operations_fact", "stored operations facts are invalid")
		return
	}
	if mode == "ordinary" {
		writeJSON(writer, http.StatusOK, map[string]any{"mode": mode, "facts": view.Ordinary()})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"mode": mode, "facts": view.Operator()})
}

func (h *M4OperationsHTTPHandler) handleAction(writer http.ResponseWriter, request *http.Request, action string) {
	if request.Method != http.MethodPost {
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "operations action requires POST")
		return
	}
	if !m4Operator(request) {
		writeJSONError(writer, http.StatusForbidden, "forbidden", "operations action requires operator role")
		return
	}
	key := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	actor := m4Actor(request)
	if key == "" || actor == "" {
		writeJSONError(writer, http.StatusBadRequest, "validation_failed", "Idempotency-Key is required")
		return
	}
	if !strings.HasPrefix(strings.ToLower(request.Header.Get("Content-Type")), "application/json") {
		writeJSONError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	var input m4OperationInput
	if err := decoder.Decode(&input); err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_json", "request body must be one JSON object with known fields")
		return
	}
	var trailing any
	if decoder.Decode(&trailing) == nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_json", "request body must contain one JSON object")
		return
	}
	operation := controllers.M4OperationRequest{ApplicationID: input.ApplicationID, EnvironmentID: input.EnvironmentID, IdempotencyKey: key, ExpectedVersion: strings.TrimSpace(input.ExpectedVersion), Actor: actor, Reason: input.Reason}
	var result controllers.M4OperationResult
	var err error
	switch action {
	case "restart":
		result, err = h.Operations.Restart(request.Context(), operation)
	case "redeploy":
		result, err = h.Operations.Redeploy(request.Context(), operation)
	case "rollback":
		result, err = h.Operations.Rollback(request.Context(), operation)
	}
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"operation": result})
}

func (h *M4OperationsHTTPHandler) handleApplicationAction(writer http.ResponseWriter, request *http.Request, applicationID, environmentID domain.ID) {
	if !m4Operator(request) {
		writeJSONError(writer, http.StatusForbidden, "forbidden", "operations action requires operator role")
		return
	}
	key := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	actor := m4Actor(request)
	if key == "" || actor == "" {
		writeJSONError(writer, http.StatusBadRequest, "validation_failed", "Idempotency-Key is required")
		return
	}
	if !strings.HasPrefix(strings.ToLower(request.Header.Get("Content-Type")), "application/json") {
		writeJSONError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	var input m4ApplicationOperationInput
	if err := decoder.Decode(&input); err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_json", "request body must be one JSON object with known fields")
		return
	}
	var trailing any
	if decoder.Decode(&trailing) == nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_json", "request body must contain one JSON object")
		return
	}
	if strings.TrimSpace(input.Reason) == "" {
		writeJSONError(writer, http.StatusBadRequest, "validation_failed", "operation reason is required for audit")
		return
	}
	operation := controllers.M4OperationRequest{ApplicationID: applicationID, EnvironmentID: environmentID, IdempotencyKey: key, ExpectedVersion: strings.TrimSpace(input.ExpectedVersion), Actor: actor, Reason: input.Reason}
	var result controllers.M4OperationResult
	var err error
	switch input.Action {
	case "restart":
		result, err = h.Operations.Restart(request.Context(), operation)
	case "redeploy":
		result, err = h.Operations.Redeploy(request.Context(), operation)
	case "rollback":
		result, err = h.Operations.Rollback(request.Context(), operation)
	default:
		writeJSONError(writer, http.StatusBadRequest, "validation_failed", "operation action is unsupported")
		return
	}
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"operation_id": result.Operation.ID, "operation": result, "target_service_id": strings.TrimSpace(input.TargetServiceID)})
}

func m4BrowserFacts(view domain.ApplicationOperationsView) map[string]any {
	services := make([]map[string]any, 0, len(view.Services))
	for _, service := range view.Services {
		health := "unhealthy"
		if service.Healthy {
			health = "healthy"
		} else if service.Status == "unknown" {
			health = "unknown"
		}
		services = append(services, map[string]any{
			"id": service.DeploymentID.String() + ":" + service.Name, "name": service.Name, "health": health, "required": service.Required,
			"release_id": service.ReleaseID, "exit_reason": service.NextAction,
			"resources": map[string]any{"cpu_millicores": int64(service.Actual.CPUCores * 1000), "memory_bytes": service.Actual.MemoryBytes, "disk_bytes": service.Actual.DiskBytes, "network_rx_bytes": service.Actual.NetworkRxBytes, "network_tx_bytes": service.Actual.NetworkTxBytes, "restart_count": service.Actual.RestartCount, "pids_current": service.Actual.PIDsCurrent, "applied_cpu_millicores": service.Actual.AppliedCPUMillicores, "applied_memory_bytes": service.Actual.AppliedMemoryBytes, "applied_pids": service.Actual.AppliedPIDs, "changed_path_count": service.Actual.ChangedPathCount, "cgroup_verified": service.Actual.CgroupVerified, "metrics_known": service.Actual.MetricsKnown},
		})
	}
	actions := make([]map[string]any, 0, 3)
	actions = append(actions, map[string]any{"action": "restart", "status": "idle", "target_service_id": firstM4RestartService(view), "enabled": len(view.AllowedActions.RestartServices) > 0})
	actions = append(actions, map[string]any{"action": "redeploy", "status": "idle", "enabled": view.AllowedActions.Redeploy})
	actions = append(actions, map[string]any{"action": "rollback", "status": "idle", "enabled": view.AllowedActions.Rollback})
	return map[string]any{"version": view.Version, "observed_at": view.ObservedAt, "application_id": view.ApplicationID, "application_name": view.ApplicationName, "serving": view.Serving, "impact": view.Impact, "next_step": view.NextStep, "services": services, "actions": actions, "data_rollback_supported": false}
}

func firstM4RestartService(view domain.ApplicationOperationsView) string {
	if len(view.AllowedActions.RestartServices) == 0 {
		return ""
	}
	return view.AllowedActions.RestartServices[0]
}

func m4Operator(request *http.Request) bool {
	return controlPlaneOperator(request)
}

func m4Actor(request *http.Request) string {
	return controlPlaneActor(request)
}
