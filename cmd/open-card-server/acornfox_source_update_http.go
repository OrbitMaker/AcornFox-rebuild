package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type acornFoxSourceUpdateCommand interface {
	Update(context.Context, application.AcornFoxSourceUpdateRequest) (contracts.AcornFoxSourceUpdateResult, error)
}

type AcornFoxSourceUpdateHTTPHandler struct{ Service acornFoxSourceUpdateCommand }

func newAcornFoxSourceUpdateHTTPHandler(service acornFoxSourceUpdateCommand) *AcornFoxSourceUpdateHTTPHandler {
	return &AcornFoxSourceUpdateHTTPHandler{Service: service}
}

func (h *AcornFoxSourceUpdateHTTPHandler) Handle(w http.ResponseWriter, r *http.Request, applicationID domain.ID) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, OPTIONS")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if h == nil || h.Service == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "source_update_unavailable", "source update is unavailable")
		return
	}
	var input struct {
		BaseSourceRevisionID domain.ID       `json:"base_source_revision_id"`
		Ref                  json.RawMessage `json:"ref"`
		UploadID             json.RawMessage `json:"upload_id"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	var ref string
	var uploadID domain.ID
	if len(input.UploadID) > 0 {
		if len(input.Ref) > 0 || json.Unmarshal(input.UploadID, &uploadID) != nil || uploadID.Empty() {
			writeJSONError(w, http.StatusUnprocessableEntity, "validation_failed", "choose exactly one Git ref or upload ID")
			return
		}
	} else if json.Unmarshal(input.Ref, &ref) != nil {
		writeJSONError(w, http.StatusUnprocessableEntity, "validation_failed", "Git ref or upload ID is required")
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		writeJSONError(w, http.StatusUnprocessableEntity, "validation_failed", "Idempotency-Key is required")
		return
	}
	result, err := h.Service.Update(r.Context(), application.AcornFoxSourceUpdateRequest{ApplicationID: applicationID, BaseSourceRevisionID: input.BaseSourceRevisionID, Ref: ref, UploadID: uploadID, IdempotencyKey: key})
	if err != nil {
		switch {
		case errors.Is(err, application.ErrAcornFoxSourceUpdateInProgress):
			writeJSONError(w, http.StatusConflict, "source_update_in_progress", "source update is in progress")
		case errors.Is(err, application.ErrAcornFoxSourceUpdateUnknown):
			writeJSONError(w, http.StatusServiceUnavailable, "source_update_unknown", "source update outcome is unknown")
		case errors.Is(err, application.ErrAcornFoxSourceUpdateFailed):
			writeJSONError(w, http.StatusUnprocessableEntity, "source_update_failed", "source update failed")
		case errors.Is(err, postgres.ErrNotFound):
			writeJSONError(w, http.StatusNotFound, "not_found", "resource not found")
		default:
			writeAcornFoxError(w, err)
		}
		return
	}
	if result.Validate() != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "source_update_unavailable", "source update is unavailable")
		return
	}
	writeJSON(w, http.StatusCreated, result)
}
