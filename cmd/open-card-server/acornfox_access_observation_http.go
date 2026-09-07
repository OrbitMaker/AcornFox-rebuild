package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

const acornFoxAccessObservationMaxBody = 16 << 10

type acornFoxAccessObservationStore interface {
	CreateAcornFoxAccessObservation(context.Context, domain.ID, domain.ID, domain.ID, contracts.AcornFoxAccessObservationReport, time.Time) (contracts.AcornFoxAccessObservation, bool, error)
	GetCurrentAcornFoxAccessObservation(context.Context, domain.ID, domain.ID, time.Time) (contracts.AcornFoxAccessObservation, bool, error)
}

type AcornFoxAccessObservationHTTPHandler struct {
	Store acornFoxAccessObservationStore
	Clock func() time.Time
}

func (h *AcornFoxAccessObservationHTTPHandler) Handle(w http.ResponseWriter, r *http.Request, applicationID, deploymentID domain.ID) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	identity, authenticated := controlPlaneIdentityFromContext(r.Context())
	if !authenticated {
		writeJSONError(w, http.StatusUnauthorized, "authentication_required", "administrator authentication is required")
		return
	}
	if h == nil || h.Store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "access_observation_unavailable", "access observation is unavailable")
		return
	}
	now := time.Now().UTC()
	if h.Clock != nil {
		now = h.Clock().UTC()
	}

	if r.Method == http.MethodGet {
		h.get(w, r, applicationID, deploymentID, now)
		return
	}
	var report contracts.AcornFoxAccessObservationReport
	if err := decodeAcornFoxAccessObservationJSON(w, r, &report); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "request body must be one bounded JSON object with known fields")
		return
	}
	observation, replayed, err := h.Store.CreateAcornFoxAccessObservation(r.Context(), applicationID, deploymentID, identity.AdminID, report, now)
	if err != nil {
		writeAcornFoxAccessObservationError(w, err)
		return
	}
	if err := validateAcornFoxAccessObservationTarget(observation, applicationID, deploymentID); err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "access_observation_unavailable", "access observation is unavailable")
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	writeJSON(w, status, observation)
}

func (h *AcornFoxAccessObservationHTTPHandler) get(w http.ResponseWriter, r *http.Request, applicationID, deploymentID domain.ID, now time.Time) {
	observation, found, err := h.Store.GetCurrentAcornFoxAccessObservation(r.Context(), applicationID, deploymentID, now)
	if err != nil {
		writeAcornFoxAccessObservationError(w, err)
		return
	}
	if !found {
		writeJSON(w, http.StatusOK, contracts.AcornFoxAccessObservationView{Availability: contracts.AcornFoxAccessObservationNotObserved})
		return
	}
	if err := validateAcornFoxAccessObservationTarget(observation, applicationID, deploymentID); err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "access_observation_unavailable", "access observation is unavailable")
		return
	}
	availability := contracts.AcornFoxAccessObservationAvailable
	if !now.Before(observation.ExpiresAt) {
		availability = contracts.AcornFoxAccessObservationExpired
	}
	writeJSON(w, http.StatusOK, contracts.AcornFoxAccessObservationView{Availability: availability, Observation: &observation})
}

func decodeAcornFoxAccessObservationJSON(w http.ResponseWriter, r *http.Request, target any) error {
	if r.Body == nil {
		return errors.New("request body is required")
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, acornFoxAccessObservationMaxBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func validateAcornFoxAccessObservationTarget(observation contracts.AcornFoxAccessObservation, applicationID, deploymentID domain.ID) error {
	if err := observation.Validate(); err != nil || observation.ApplicationID != applicationID.String() || observation.DeploymentID != deploymentID.String() {
		return errors.New("access observation target mismatch")
	}
	return nil
}

func writeAcornFoxAccessObservationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, postgres.ErrNotFound) || domain.IsCode(err, domain.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, postgres.ErrIdempotencyConflict):
		writeJSONError(w, http.StatusConflict, "idempotency_conflict", "report_id conflicts with a prior observation")
	case domain.IsCode(err, domain.ErrConflict):
		writeJSONError(w, http.StatusConflict, "target_conflict", "the public access target is not current")
	case domain.IsCode(err, domain.ErrValidation):
		writeJSONError(w, http.StatusUnprocessableEntity, "validation_failed", "access observation is invalid")
	default:
		writeJSONError(w, http.StatusServiceUnavailable, "access_observation_unavailable", "access observation is unavailable")
	}
}
