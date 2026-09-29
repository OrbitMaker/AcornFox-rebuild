package corehttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/acornfox/acornfox/internal/application"
	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/auth"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/persistence/sqlite"
)

const (
	ImagePlansAPIBase = "/api/v1/acornfox/image-plans"
	OperationsAPIBase = "/api/v1/acornfox/operations/"
	maxStrictJSONBody = 64 << 10 // 64 KB
)

type ImageDeliveryHandler struct {
	Domain      *ImagePublicAccessHandler
	Observation *ImageObservationHandler
	Metrics     *ImageMetricsHandler
	Service     *application.ImageDeliveryService
	Store       *sqlite.Store
	Auth        *auth.Service
	Config      AuthRouteConfig
}

func (h *ImageDeliveryHandler) Handle(w http.ResponseWriter, r *http.Request) bool {
	if h.Domain != nil && h.Domain.Handle(w, r) {
		return true
	}
	if h.Observation != nil && h.Observation.Handle(w, r) {
		return true
	}
	if h.Metrics != nil && h.Metrics.Handle(w, r) {
		return true
	}
	path := r.URL.Path
	if path == "/api/v1/acornfox/image-apps" {
		h.handleManagedImageApplications(w, r)
		return true
	}
	if strings.HasPrefix(path, ImageDeploymentsAPIBase) || strings.HasPrefix(path, ImageLifecycleOperationsAPIBase) {
		h.handleImageLifecycle(w, r)
		return true
	}

	// 1. Route: /api/v1/acornfox/image-plans and subpaths
	if path == ImagePlansAPIBase || strings.HasPrefix(path, ImagePlansAPIBase+"/") {
		h.handleImagePlans(w, r)
		return true
	}

	// 2. Route: /api/v1/acornfox/operations/{id}
	if strings.HasPrefix(path, OperationsAPIBase) {
		h.handleOperations(w, r)
		return true
	}

	return false
}

func (h *ImageDeliveryHandler) handleImagePlans(w http.ResponseWriter, r *http.Request) {
	req, ok := AuthenticateControlPlane(h.Auth, h.Config, w, r)
	if !ok {
		return
	}

	identity, ok := ControlPlaneIdentityFromContext(req.Context())
	if !ok || identity.AdminID.Empty() {
		AuthHTTPError(w, http.StatusUnauthorized, "authentication failed")
		return
	}

	path := r.URL.Path
	subpath := strings.TrimPrefix(path, ImagePlansAPIBase)

	switch {
	case subpath == "" || subpath == "/":
		if req.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			WriteJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		h.createPlan(w, req, identity.AdminID)

	case subpath == "/confirm":
		if req.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			WriteJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		h.confirmPlan(w, req, identity.AdminID, "")

	default:
		// Subpath could be /{id} or /{id}/confirm
		parts := strings.Split(strings.Trim(subpath, "/"), "/")
		if len(parts) == 1 {
			// GET /api/v1/acornfox/image-plans/{id}
			planID := parts[0]
			if req.Method != http.MethodGet {
				w.Header().Set("Allow", http.MethodGet)
				WriteJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
				return
			}
			h.getPlan(w, req, identity.AdminID, domain.ID(planID))
		} else if len(parts) == 2 && parts[1] == "confirm" {
			// POST /api/v1/acornfox/image-plans/{id}/confirm
			planID := parts[0]
			if req.Method != http.MethodPost {
				w.Header().Set("Allow", http.MethodPost)
				WriteJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
				return
			}
			h.confirmPlan(w, req, identity.AdminID, domain.ID(planID))
		} else {
			WriteJSONError(w, http.StatusNotFound, "not_found", "route not found")
		}
	}
}

func (h *ImageDeliveryHandler) createPlan(w http.ResponseWriter, r *http.Request, adminID domain.ID) {
	if h.Service == nil || h.Store == nil {
		WriteJSONError(w, http.StatusServiceUnavailable, "service_unavailable", "image delivery service unavailable")
		return
	}

	var input appcontracts.ImagePlanInput
	if err := decodeStrictJSON(r.Body, &input); err != nil {
		WriteJSONError(w, http.StatusBadRequest, "invalid_request", "invalid JSON request body: "+err.Error())
		return
	}

	plan, err := h.Service.CreatePlan(r.Context(), adminID, input)
	if err != nil {
		writeDeliveryError(w, err)
		return
	}

	if err := h.Store.CreateImagePlan(r.Context(), plan); err != nil {
		writeDeliveryError(w, err)
		return
	}

	WriteJSON(w, http.StatusCreated, plan)
}

func (h *ImageDeliveryHandler) getPlan(w http.ResponseWriter, r *http.Request, adminID domain.ID, planID domain.ID) {
	if h.Store == nil {
		WriteJSONError(w, http.StatusServiceUnavailable, "service_unavailable", "store unavailable")
		return
	}

	plan, err := h.Store.GetImagePlan(r.Context(), planID, adminID)
	if err != nil {
		writeDeliveryError(w, err)
		return
	}

	WriteJSON(w, http.StatusOK, plan)
}

func (h *ImageDeliveryHandler) confirmPlan(w http.ResponseWriter, r *http.Request, adminID domain.ID, pathPlanID domain.ID) {
	if h.Store == nil {
		WriteJSONError(w, http.StatusServiceUnavailable, "service_unavailable", "store unavailable")
		return
	}

	var input appcontracts.ConfirmImagePlanInput
	if err := decodeStrictJSON(r.Body, &input); err != nil {
		WriteJSONError(w, http.StatusBadRequest, "invalid_request", "invalid JSON request body: "+err.Error())
		return
	}

	if !pathPlanID.Empty() {
		if input.PlanID.Empty() {
			input.PlanID = pathPlanID
		} else if input.PlanID != pathPlanID {
			WriteJSONError(w, http.StatusBadRequest, "invalid_request", "path plan id does not match body plan id")
			return
		}
	}

	result, err := h.Store.ConfirmImagePlan(r.Context(), adminID, input)
	if err != nil {
		writeDeliveryError(w, err)
		return
	}

	WriteJSON(w, http.StatusOK, result)
}

func (h *ImageDeliveryHandler) handleOperations(w http.ResponseWriter, r *http.Request) {
	req, ok := AuthenticateControlPlane(h.Auth, h.Config, w, r)
	if !ok {
		return
	}

	identity, ok := ControlPlaneIdentityFromContext(req.Context())
	if !ok || identity.AdminID.Empty() {
		AuthHTTPError(w, http.StatusUnauthorized, "authentication failed")
		return
	}

	if req.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		WriteJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	subpath := strings.TrimPrefix(r.URL.Path, OperationsAPIBase)
	opID := strings.Trim(subpath, "/")
	if opID == "" || strings.Contains(opID, "/") {
		WriteJSONError(w, http.StatusNotFound, "not_found", "route not found")
		return
	}

	if h.Store == nil {
		WriteJSONError(w, http.StatusServiceUnavailable, "service_unavailable", "store unavailable")
		return
	}

	detail, err := h.Store.GetImageOperation(r.Context(), identity.AdminID, domain.ID(opID))
	if err != nil {
		writeDeliveryError(w, err)
		return
	}

	// The original deploy operation remains succeeded; its associated deployment
	// carries the latest lifecycle state. Retained allocation is not a ready URL.
	if detail.Result != nil && detail.Result.Status != "running" {
		detail.Result.Endpoint = ""
	}
	WriteJSON(w, http.StatusOK, detail)
}

func decodeStrictJSON(body io.Reader, dst any) error {
	data, err := io.ReadAll(io.LimitReader(body, maxStrictJSONBody+1))
	if err != nil {
		return err
	}
	if len(data) > maxStrictJSONBody {
		return errors.New("request body exceeds limit (64KB)")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("extraneous trailing content after JSON object")
	}
	return nil
}

func writeDeliveryError(w http.ResponseWriter, err error) {
	if errors.Is(err, sqlite.ErrNotFound) || errors.Is(err, domain.ErrObjectNotFound) {
		WriteJSONError(w, http.StatusNotFound, "not_found", "requested object not found")
		return
	}
	if errors.Is(err, sqlite.ErrIdempotencyConflict) {
		WriteJSONError(w, http.StatusConflict, "conflict", "idempotency key was reused with different parameters")
		return
	}
	if errors.Is(err, sqlite.ErrIdempotencyInProgress) {
		WriteJSONError(w, http.StatusConflict, "conflict", "operation is already in progress")
		return
	}

	var domErr *domain.DomainError
	if errors.As(err, &domErr) {
		switch domErr.Code {
		case domain.ErrValidation, domain.ErrInvalidArgument:
			WriteJSONError(w, http.StatusBadRequest, "invalid_request", domErr.Message)
		case domain.ErrUnauthorized:
			WriteJSONError(w, http.StatusUnauthorized, "unauthorized", domErr.Message)
		case domain.ErrForbidden:
			WriteJSONError(w, http.StatusForbidden, "forbidden", domErr.Message)
		case domain.ErrConflict:
			WriteJSONError(w, http.StatusConflict, "conflict", domErr.Message)
		case domain.ErrNotFound:
			WriteJSONError(w, http.StatusNotFound, "not_found", domErr.Message)
		case domain.ErrTimeout:
			WriteJSONError(w, http.StatusGatewayTimeout, "timeout", domErr.Message)
		default:
			WriteJSONError(w, http.StatusServiceUnavailable, "service_unavailable", domErr.Message)
		}
		return
	}

	WriteJSONError(w, http.StatusInternalServerError, "internal_error", "an unexpected error occurred")
}

func (h *ImageDeliveryHandler) handleManagedImageApplications(w http.ResponseWriter, r *http.Request) {
	req, ok := AuthenticateControlPlane(h.Auth, h.Config, w, r)
	if !ok {
		return
	}
	identity, ok := ControlPlaneIdentityFromContext(req.Context())
	if !ok || identity.AdminID.Empty() {
		AuthHTTPError(w, http.StatusUnauthorized, "authentication failed")
		return
	}
	if req.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		WriteJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if h.Store == nil {
		WriteJSONError(w, http.StatusServiceUnavailable, "service_unavailable", "store unavailable")
		return
	}
	query, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil || len(query) > 1 {
		WriteJSONError(w, http.StatusBadRequest, "invalid_request", "only limit is supported")
		return
	}
	limit := 50
	for key, values := range query {
		if key != "limit" || len(values) != 1 {
			WriteJSONError(w, http.StatusBadRequest, "invalid_request", "only one limit is supported")
			return
		}
		limit, err = strconv.Atoi(values[0])
		if err != nil || limit < 1 || limit > 100 || strconv.Itoa(limit) != values[0] {
			WriteJSONError(w, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 100")
			return
		}
	}
	result, err := h.Store.ListManagedImageApplications(req.Context(), identity.AdminID, limit)
	if err != nil {
		writeDeliveryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, result)
}
