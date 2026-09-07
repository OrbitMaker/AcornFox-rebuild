package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/open-card/open-card/internal/acornfoxcandidate"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

const acornFoxFixCandidateMaxBody = 160 << 10

type acornFoxFixCandidateCommand interface {
	ReadSource(context.Context, domain.ID, domain.ID, []string) (acornfoxcandidate.ReadResult, error)
	ReadSourceForAI(context.Context, domain.ID, domain.ID, []string) (acornfoxcandidate.ReadResult, error)
	Create(context.Context, application.AcornFoxFixCandidateCreateRequest) (application.AcornFoxFixCandidate, error)
	MatchSource(context.Context, domain.ID, domain.ID, domain.ID, domain.ID) (application.AcornFoxFixCandidate, error)
	Publish(context.Context, domain.ID, domain.ID, domain.ID, string) (application.AcornFoxDeliveryResult, error)
}

type acornFoxFixCandidateReader interface {
	GetAcornFoxFixCandidate(context.Context, domain.ID, domain.ID) (application.AcornFoxFixCandidate, error)
	ListAcornFoxFixCandidates(context.Context, domain.ID, domain.ID) ([]application.AcornFoxFixCandidate, error)
}

type AcornFoxFixCandidateHTTPHandler struct {
	Service acornFoxFixCandidateCommand
	Store   acornFoxFixCandidateReader
}

func (h *AcornFoxFixCandidateHTTPHandler) HandleCollection(w http.ResponseWriter, r *http.Request, applicationID domain.ID) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	identity, ok := controlPlaneIdentityFromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "authentication_required", "administrator authentication is required")
		return
	}
	if h == nil || h.Store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "fix_candidate_unavailable", "fix candidate is unavailable")
		return
	}
	if r.Method == http.MethodGet {
		if r.URL.RawQuery != "" {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", "fix candidate list does not accept query parameters")
			return
		}
		items, err := h.Store.ListAcornFoxFixCandidates(r.Context(), applicationID, identity.AdminID)
		if err != nil {
			writeAcornFoxFixCandidateError(w, err)
			return
		}
		for _, candidate := range items {
			if candidate.Validate() != nil || candidate.ApplicationID != applicationID || candidate.OwnerAdminID != identity.AdminID {
				writeJSONError(w, http.StatusServiceUnavailable, "fix_candidate_unavailable", "fix candidate is unavailable")
				return
			}
		}
		writeJSON(w, http.StatusOK, struct {
			Items []application.AcornFoxFixCandidate `json:"items"`
		}{Items: items})
		return
	}
	if h.Service == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "fix_candidate_unavailable", "fix candidate execution is unavailable on this server")
		return
	}
	var input struct {
		BaseSourceRevisionID domain.ID `json:"base_source_revision_id"`
		Paths                []string  `json:"paths"`
		UnifiedDiff          string    `json:"unified_diff"`
		ContainerPort        int       `json:"container_port"`
	}
	if err := decodeAcornFoxFixCandidateJSON(w, r, &input); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	candidate, err := h.Service.Create(r.Context(), application.AcornFoxFixCandidateCreateRequest{ApplicationID: applicationID, BaseSourceRevisionID: input.BaseSourceRevisionID, Paths: input.Paths, UnifiedDiff: []byte(input.UnifiedDiff), ContainerPort: input.ContainerPort, IdempotencyKey: key, OwnerAdminID: identity.AdminID})
	if err != nil {
		writeAcornFoxFixCandidateError(w, err)
		return
	}
	if candidate.Validate() != nil || candidate.ApplicationID != applicationID || candidate.OwnerAdminID != identity.AdminID {
		writeJSONError(w, http.StatusServiceUnavailable, "fix_candidate_unavailable", "fix candidate is unavailable")
		return
	}
	writeJSON(w, http.StatusAccepted, candidate)
}

func (h *AcornFoxFixCandidateHTTPHandler) HandleItem(w http.ResponseWriter, r *http.Request, applicationID, candidateID domain.ID, action string) {
	identity, ok := controlPlaneIdentityFromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "authentication_required", "administrator authentication is required")
		return
	}
	if h == nil || h.Store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "fix_candidate_unavailable", "fix candidate is unavailable")
		return
	}
	if action == "" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		candidate, err := h.Store.GetAcornFoxFixCandidate(r.Context(), applicationID, candidateID)
		if err != nil {
			writeAcornFoxFixCandidateError(w, err)
			return
		}
		if candidate.OwnerAdminID != identity.AdminID {
			writeJSONError(w, http.StatusNotFound, "not_found", "resource not found")
			return
		}
		if candidate.Validate() != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "fix_candidate_unavailable", "fix candidate is unavailable")
			return
		}
		writeJSON(w, http.StatusOK, candidate)
		return
	}
	if action != "source-match" && action != "publish" || r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if h.Service == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "fix_candidate_unavailable", "fix candidate execution is unavailable on this server")
		return
	}
	if action == "publish" {
		if r.Body != nil {
			var extra any
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1))
			if err := decoder.Decode(&extra); err != io.EOF {
				writeJSONError(w, http.StatusBadRequest, "invalid_request", "request body must be empty")
				return
			}
		}
		result, err := h.Service.Publish(r.Context(), applicationID, candidateID, identity.AdminID, strings.TrimSpace(r.Header.Get("Idempotency-Key")))
		if err != nil {
			writeAcornFoxFixCandidateError(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, result)
		return
	}
	var input struct {
		SourceRevisionID domain.ID `json:"source_revision_id"`
	}
	if err := decodeAcornFoxFixCandidateJSON(w, r, &input); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	candidate, err := h.Service.MatchSource(r.Context(), applicationID, candidateID, input.SourceRevisionID, identity.AdminID)
	if err != nil {
		writeAcornFoxFixCandidateError(w, err)
		return
	}
	if candidate.Validate() != nil || candidate.Status != application.AcornFoxFixCandidateSourceMatched || candidate.ApplicationID != applicationID || candidate.ID != candidateID || candidate.OwnerAdminID != identity.AdminID {
		writeJSONError(w, http.StatusServiceUnavailable, "fix_candidate_unavailable", "fix candidate is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, candidate)
}

func decodeAcornFoxFixCandidateJSON(w http.ResponseWriter, r *http.Request, target any) error {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.Body == nil {
		return errors.New("JSON body is required")
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, acornFoxFixCandidateMaxBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func writeAcornFoxFixCandidateError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, postgres.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, postgres.ErrIdempotencyConflict), errors.Is(err, application.ErrAcornFoxFixCandidateInProgress), domain.IsCode(err, domain.ErrConflict):
		writeJSONError(w, http.StatusConflict, "fix_candidate_conflict", "fix candidate conflicts with existing work")
	case errors.Is(err, application.ErrAcornFoxFixCandidateMismatch):
		writeJSONError(w, http.StatusConflict, "fix_candidate_source_mismatch", "imported source does not match the verified candidate")
	case domain.IsCode(err, domain.ErrValidation):
		writeJSONError(w, http.StatusUnprocessableEntity, "validation_failed", "fix candidate request is invalid")
	default:
		writeJSONError(w, http.StatusServiceUnavailable, "fix_candidate_unavailable", "fix candidate is unavailable")
	}
}
