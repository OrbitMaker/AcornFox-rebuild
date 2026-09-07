package main

import (
	"context"
	"errors"
	"net/http"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// acornFoxSourceMetadataReader scopes every lookup by the application parsed
// from the authenticated route. The store must return ErrNotFound for a
// foreign resource so this small handler cannot become an ownership oracle.
type acornFoxSourceMetadataReader interface {
	GetAcornFoxSourceMetadata(context.Context, domain.ID, domain.ID) (contracts.AcornFoxSourceMetadata, error)
	GetAcornFoxDeploymentSource(context.Context, domain.ID, domain.ID) (contracts.AcornFoxDeploymentSource, error)
}

// AcornFoxSourceMetadataHTTPHandler serves the dedicated metadata capability.
// Authentication is intentionally composed by Server before its route dispatch.
type AcornFoxSourceMetadataHTTPHandler struct{ Store acornFoxSourceMetadataReader }

func newAcornFoxSourceMetadataHTTPHandler(store acornFoxSourceMetadataReader) *AcornFoxSourceMetadataHTTPHandler {
	return &AcornFoxSourceMetadataHTTPHandler{Store: store}
}

func (h *AcornFoxSourceMetadataHTTPHandler) HandleSourceMetadata(w http.ResponseWriter, r *http.Request, applicationID, sourceRevisionID domain.ID) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, OPTIONS")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if h == nil || h.Store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "source_metadata_unavailable", "source metadata is unavailable")
		return
	}
	metadata, err := h.Store.GetAcornFoxSourceMetadata(r.Context(), applicationID, sourceRevisionID)
	if errors.Is(err, postgres.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if err != nil || metadata.Validate() != nil || metadata.SourceRevisionID != sourceRevisionID {
		writeJSONError(w, http.StatusServiceUnavailable, "source_metadata_unavailable", "source metadata is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, metadata)
}

func (h *AcornFoxSourceMetadataHTTPHandler) HandleDeploymentSource(w http.ResponseWriter, r *http.Request, applicationID, deploymentID domain.ID) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, OPTIONS")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if h == nil || h.Store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "source_metadata_unavailable", "source metadata is unavailable")
		return
	}
	source, err := h.Store.GetAcornFoxDeploymentSource(r.Context(), applicationID, deploymentID)
	if errors.Is(err, postgres.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if err != nil || source.Validate() != nil || source.DeploymentID != deploymentID {
		writeJSONError(w, http.StatusServiceUnavailable, "source_metadata_unavailable", "source metadata is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, source)
}
