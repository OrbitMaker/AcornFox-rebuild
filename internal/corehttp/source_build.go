package corehttp

import (
	"errors"
	"net/http"
	"strings"

	"github.com/open-card/open-card/internal/application"
	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/auth"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/sqlite"
)

const SourceBuildAPIBase = "/api/v1/acornfox/source-build"

type SourceBuildHandler struct {
	Service *application.SourceBuildService
	Auth    *auth.Service
	Config  AuthRouteConfig
}

func (h *SourceBuildHandler) Handle(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != SourceBuildAPIBase && !strings.HasPrefix(r.URL.Path, SourceBuildAPIBase+"/") {
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
	if h.Service == nil {
		WriteJSONError(w, http.StatusServiceUnavailable, "unavailable", "source-build integration unavailable")
		return true
	}
	if req.URL.RawQuery != "" {
		WriteJSONError(w, http.StatusBadRequest, "invalid_request", "unexpected query input")
		return true
	}
	sub := strings.TrimPrefix(req.URL.Path, SourceBuildAPIBase)
	var out appcontracts.SourceBuildPublicIntent
	var err error
	switch {
	case sub == "/prepare":
		if req.Method != http.MethodPost {
			sourceMethod(w, http.MethodPost)
			return true
		}
		var in appcontracts.CreateSourcePrepareIntentInput
		if decodeStrictJSON(req.Body, &in) != nil {
			WriteJSONError(w, http.StatusBadRequest, "invalid_request", "invalid source prepare request")
			return true
		}
		if !sourceKeyMatches(req, in.IdempotencyKey) {
			WriteJSONError(w, http.StatusBadRequest, "invalid_request", "explicit matching idempotency key required")
			return true
		}
		out, err = h.Service.Prepare(req.Context(), identity.AdminID, in)
	case sub == "/approve":
		if req.Method != http.MethodPost {
			sourceMethod(w, http.MethodPost)
			return true
		}
		var in appcontracts.SourceBuildPublicApprovalInput
		if decodeStrictJSON(req.Body, &in) != nil {
			WriteJSONError(w, http.StatusBadRequest, "invalid_request", "invalid source build approval request")
			return true
		}
		if !sourceKeyMatches(req, in.IdempotencyKey) {
			WriteJSONError(w, http.StatusBadRequest, "invalid_request", "explicit matching idempotency key required")
			return true
		}
		out, err = h.Service.ApproveBuild(req.Context(), identity.AdminID, in)
	case sub == "/run-plans":
		if req.Method != http.MethodPost {
			sourceMethod(w, http.MethodPost)
			return true
		}
		var input appcontracts.SourceRunPlanInput
		if decodeStrictJSON(req.Body, &input) != nil {
			WriteJSONError(w, http.StatusBadRequest, "invalid_request", "invalid source-run plan input")
			return true
		}
		if !sourceKeyMatches(req, input.IdempotencyKey) {
			WriteJSONError(w, http.StatusBadRequest, "invalid_request", "explicit matching idempotency key required")
			return true
		}
		plan, planErr := h.Service.PreviewRun(req.Context(), identity.AdminID, input)
		if planErr != nil {
			sourceBuildHTTPError(w, planErr)
			return true
		}
		WriteJSON(w, http.StatusCreated, plan)
		return true
	case strings.HasPrefix(sub, "/run-plans/"):
		suffix := strings.TrimPrefix(sub, "/run-plans/")
		if strings.HasSuffix(suffix, "/confirm") {
			id := strings.TrimSuffix(suffix, "/confirm")
			if id == "" || strings.Contains(id, "/") {
				WriteJSONError(w, http.StatusNotFound, "not_found", "source-run plan not found")
				return true
			}
			if req.Method != http.MethodPost {
				sourceMethod(w, http.MethodPost)
				return true
			}
			var input appcontracts.ConfirmImagePlanInput
			if decodeStrictJSON(req.Body, &input) != nil {
				WriteJSONError(w, http.StatusBadRequest, "invalid_request", "invalid source-run confirmation")
				return true
			}
			if input.PlanID != domain.ID(id) || !sourceKeyMatches(req, input.IdempotencyKey) {
				WriteJSONError(w, http.StatusBadRequest, "invalid_request", "original plan ID and matching idempotency key required")
				return true
			}
			confirmed, confirmErr := h.Service.ConfirmRun(req.Context(), identity.AdminID, input)
			if confirmErr != nil {
				sourceBuildHTTPError(w, confirmErr)
				return true
			}
			WriteJSON(w, http.StatusAccepted, confirmed)
			return true
		}
		if suffix == "" || strings.Contains(suffix, "/") {
			WriteJSONError(w, http.StatusNotFound, "not_found", "source-run plan not found")
			return true
		}
		if req.Method != http.MethodGet {
			sourceMethod(w, http.MethodGet)
			return true
		}
		plan, planErr := h.Service.ReadRunPlan(req.Context(), identity.AdminID, domain.ID(suffix))
		if planErr != nil {
			sourceBuildHTTPError(w, planErr)
			return true
		}
		WriteJSON(w, http.StatusOK, plan)
		return true
	case strings.HasPrefix(sub, "/intents/"):
		if req.Method != http.MethodGet {
			sourceMethod(w, http.MethodGet)
			return true
		}
		id := strings.TrimPrefix(sub, "/intents/")
		if id == "" || strings.Contains(id, "/") {
			WriteJSONError(w, http.StatusNotFound, "not_found", "source intent not found")
			return true
		}
		out, err = h.Service.Read(req.Context(), identity.AdminID, domain.ID(id))
	default:
		WriteJSONError(w, http.StatusNotFound, "not_found", "route not found")
		return true
	}
	if err != nil {
		sourceBuildHTTPError(w, err)
		return true
	}
	status := http.StatusOK
	if req.Method == http.MethodPost {
		status = http.StatusCreated
	}
	WriteJSON(w, status, out)
	return true
}
func sourceKeyMatches(r *http.Request, key string) bool {
	return key != "" && key == strings.TrimSpace(key) && r.Header.Get("Idempotency-Key") == key
}
func sourceMethod(w http.ResponseWriter, method string) {
	w.Header().Set("Allow", method)
	WriteJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}
func sourceBuildHTTPError(w http.ResponseWriter, err error) {
	if errors.Is(err, sqlite.ErrOutcomeUnknown) {
		WriteJSONError(w, http.StatusServiceUnavailable, "outcome_unknown", "outcome unknown; retry the same request with the same idempotency key")
		return
	}
	if errors.Is(err, sqlite.ErrIdempotencyConflict) || errors.Is(err, sqlite.ErrIdempotencyInProgress) {
		WriteJSONError(w, http.StatusConflict, "conflict", "idempotency request conflicts or is in progress")
		return
	}
	if errors.Is(err, sqlite.ErrSourceDefinitionNeedsInput) {
		WriteJSONError(w, http.StatusConflict, "needs_input", "root Dockerfile is missing or unsupported")
		return
	}
	if errors.Is(err, sqlite.ErrNotFound) {
		WriteJSONError(w, http.StatusNotFound, "not_found", "source intent not found")
		return
	}
	var e *domain.DomainError
	if errors.As(err, &e) {
		switch e.Code {
		case domain.ErrValidation, domain.ErrInvalidArgument:
			WriteJSONError(w, http.StatusBadRequest, "invalid_request", "invalid fixed source-build input")
		case domain.ErrUnauthorized:
			WriteJSONError(w, http.StatusUnauthorized, "unauthorized", "authentication failed")
		case domain.ErrForbidden:
			WriteJSONError(w, http.StatusForbidden, "forbidden", "source intent access denied")
		case domain.ErrConflict:
			WriteJSONError(w, http.StatusConflict, "conflict", "source/build facts do not permit this approval")
		case domain.ErrNotFound:
			WriteJSONError(w, http.StatusNotFound, "not_found", "source intent not found")
		default:
			WriteJSONError(w, http.StatusServiceUnavailable, "unavailable", "source-build integration unavailable")
		}
		return
	}
	WriteJSONError(w, http.StatusServiceUnavailable, "unavailable", "source-build integration unavailable")
}
