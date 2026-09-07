package main

import (
	"context"
	"errors"
	"net/http"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// acornFoxOperationReader is deliberately read-only so a Pi or browser read
// cannot queue, retry, or otherwise influence an operation.
type acornFoxOperationReader interface {
	GetAcornFoxOperationResult(context.Context, domain.ID, domain.ID) (contracts.AcornFoxOperationResult, error)
}

// AcornFoxOperationHTTPHandler is composed after the server's existing
// AcornFox authentication boundary. It exposes no task payload, raw error, or
// Agent envelope even to an authenticated caller.
type AcornFoxOperationHTTPHandler struct{ Store acornFoxOperationReader }

func newAcornFoxOperationHTTPHandler(store acornFoxOperationReader) *AcornFoxOperationHTTPHandler {
	return &AcornFoxOperationHTTPHandler{Store: store}
}

func (h *AcornFoxOperationHTTPHandler) Handle(w http.ResponseWriter, r *http.Request, applicationID, operationID domain.ID) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, OPTIONS")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if h == nil || h.Store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "operation_result_unavailable", "operation result is unavailable")
		return
	}
	result, err := h.Store.GetAcornFoxOperationResult(r.Context(), applicationID, operationID)
	if errors.Is(err, postgres.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if err != nil || result.OperationID != operationID || result.Validate() != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "operation_result_unavailable", "operation result is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, result)
}
