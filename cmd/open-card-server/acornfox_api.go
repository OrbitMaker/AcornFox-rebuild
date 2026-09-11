package main

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

const acornFoxAPIBase = "/api/v1/acornfox/apps"

// acornFoxDeploymentStore is deliberately a read-only API projection seam.
// Commands are supplied separately so status can never manufacture lifecycle
// facts from a client request.
type acornFoxDeploymentStore interface {
	GetAcornFoxSourceRevision(context.Context, domain.ID, domain.ID) (domain.SourceRevision, error)
	GetAcornFoxDeployment(context.Context, domain.ID, domain.ID) (domain.Deployment, error)
	GetAcornFoxRuntimeRequest(context.Context, domain.ID, domain.ID) (contracts.AcornFoxRuntimeDeployRequest, error)
	GetAcornFoxRuntimeObservation(context.Context, domain.ID, domain.ID) (contracts.AcornFoxRuntimeObservation, error)
	GetLatestAcornFoxProbeObservation(context.Context, domain.ID, domain.ID) (postgres.AcornFoxProbeObservation, error)
}

type acornFoxDeliveryCommand interface {
	Create(context.Context, domain.ID, acornFoxDeliveryInput, string, string) (acornFoxDeliveryResult, error)
	Restart(context.Context, domain.ID, domain.ID, string, string) (acornFoxDeliveryResult, error)
	Redeploy(context.Context, domain.ID, domain.ID, string, string) (acornFoxDeliveryResult, error)
	Probe(context.Context, domain.ID, domain.ID, acornFoxProbeInput, string, string) (acornFoxDeliveryResult, error)
}

type acornFoxDeliveryInput struct {
	SourceRevisionID domain.ID `json:"source_revision_id"`
	ContainerPort    int       `json:"container_port,omitempty"`
}

// Probe input has no target, port, address, URL, runtime fact or observation.
// The delivery service must derive all of those from durable Agent/runtime facts.
type acornFoxProbeInput struct {
	Protocol contracts.AcornFoxProbeProtocol `json:"protocol"`
	Path     string                          `json:"path,omitempty"`
}

type acornFoxDeliveryResult struct {
	DeploymentID domain.ID `json:"deployment_id"`
	OperationID  domain.ID `json:"operation_id"`
	TaskID       domain.ID `json:"task_id"`
	Status       string    `json:"status"`
}

func (s *Server) SetAcornFoxDeliveryCommand(command acornFoxDeliveryCommand) {
	if s == nil {
		return
	}
	s.acornFoxDeliveryCommand = command
}

func (s *Server) handleAcornFoxAPI(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != acornFoxAPIBase && !strings.HasPrefix(r.URL.Path, acornFoxAPIBase+"/") {
		return false
	}
	// Routes are canonical exact strings. In particular, do not accept a
	// trailing or repeated slash as a second spelling of a mutable endpoint.
	if strings.HasSuffix(r.URL.Path, "/") || strings.Contains(strings.TrimPrefix(r.URL.Path, acornFoxAPIBase), "//") {
		writeJSONError(w, http.StatusNotFound, "not_found", "route not found")
		return true
	}
	path := strings.TrimPrefix(r.URL.Path, acornFoxAPIBase)
	path = strings.TrimPrefix(path, "/")
	if r.Method == http.MethodOptions {
		if allow, ok := acornFoxRouteAllow(path); ok {
			w.Header().Set("Allow", allow+", OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return true
		}
		writeJSONError(w, http.StatusNotFound, "not_found", "route not found")
		return true
	}
	if path == "" {
		s.handleAcornFoxApps(w, r)
		return true
	}
	parts := strings.Split(path, "/")
	if len(parts) == 1 {
		s.handleAcornFoxApp(w, r, domain.ID(parts[0]))
		return true
	}
	if len(parts) == 4 && parts[1] == "sources" && parts[3] == "metadata" {
		s.acornFoxSourceMetadata.HandleSourceMetadata(w, r, domain.ID(parts[0]), domain.ID(parts[2]))
		return true
	}
	if len(parts) == 4 && parts[1] == "sources" && parts[3] == "deployment-plan" {
		s.handleAcornFoxDeploymentPlan(w, r, domain.ID(parts[0]), domain.ID(parts[2]))
		return true
	}
	if len(parts) == 3 && parts[1] == "operations" {
		s.acornFoxOperation.Handle(w, r, domain.ID(parts[0]), domain.ID(parts[2]))
		return true
	}
	if len(parts) == 3 && parts[1] == "sources" {
		s.handleAcornFoxSource(w, r, domain.ID(parts[0]), domain.ID(parts[2]))
		return true
	}
	if len(parts) == 2 && parts[1] == "sources" {
		if r.Method == http.MethodPost {
			s.acornFoxSourceUpdate.Handle(w, r, domain.ID(parts[0]))
		} else if r.Method == http.MethodGet {
			s.handleAcornFoxSources(w, r, domain.ID(parts[0]))
		} else {
			w.Header().Set("Allow", "GET, POST, OPTIONS")
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		}
		return true
	}
	if len(parts) == 2 && parts[1] == "fix-candidates" {
		if s.acornFoxFixCandidate == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "fix_candidate_unavailable", "fix candidate is unavailable")
		} else {
			s.acornFoxFixCandidate.HandleCollection(w, r, domain.ID(parts[0]))
		}
		return true
	}
	if len(parts) == 3 && parts[1] == "fix-candidates" {
		if s.acornFoxFixCandidate == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "fix_candidate_unavailable", "fix candidate is unavailable")
		} else {
			s.acornFoxFixCandidate.HandleItem(w, r, domain.ID(parts[0]), domain.ID(parts[2]), "")
		}
		return true
	}
	if len(parts) == 4 && parts[1] == "fix-candidates" && (parts[3] == "source-match" || parts[3] == "publish") {
		if s.acornFoxFixCandidate == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "fix_candidate_unavailable", "fix candidate is unavailable")
		} else {
			s.acornFoxFixCandidate.HandleItem(w, r, domain.ID(parts[0]), domain.ID(parts[2]), parts[3])
		}
		return true
	}
	if len(parts) == 2 && parts[1] == "deliveries" {
		if r.Method == http.MethodGet {
			s.handleAcornFoxDeliveries(w, r, domain.ID(parts[0]))
		} else {
			s.handleAcornFoxDeliveryCreate(w, r, domain.ID(parts[0]))
		}
		return true
	}
	if len(parts) == 3 && parts[1] == "deliveries" {
		s.handleAcornFoxDeliveryStatus(w, r, domain.ID(parts[0]), domain.ID(parts[2]))
		return true
	}
	if len(parts) == 4 && parts[1] == "deliveries" {
		if parts[3] == "source" {
			s.acornFoxSourceMetadata.HandleDeploymentSource(w, r, domain.ID(parts[0]), domain.ID(parts[2]))
			return true
		}
		if parts[3] == "logs" {
			s.handleAcornFoxDeliveryLogs(w, r, domain.ID(parts[0]), domain.ID(parts[2]))
			return true
		}
		if parts[3] == "access-observation" {
			s.acornFoxAccessObservation.Handle(w, r, domain.ID(parts[0]), domain.ID(parts[2]))
			return true
		}
		if parts[3] == "public-access" {
			s.handleAcornFoxDeliveryPublicAccess(w, r, domain.ID(parts[0]), domain.ID(parts[2]))
			return true
		}
		s.handleAcornFoxDeliveryAction(w, r, domain.ID(parts[0]), domain.ID(parts[2]), parts[3])
		return true
	}
	writeJSONError(w, http.StatusNotFound, "not_found", "route not found")
	return true
}

func acornFoxRouteAllow(path string) (string, bool) {
	if path == "" {
		return "GET, POST", true
	}
	parts := strings.Split(path, "/")
	if len(parts) == 1 && parts[0] != "" {
		return "GET", true
	}
	if len(parts) == 4 && parts[0] != "" && parts[1] == "sources" && parts[2] != "" && parts[3] == "metadata" {
		return "GET", true
	}
	if len(parts) == 4 && parts[0] != "" && parts[1] == "sources" && parts[2] != "" && parts[3] == "deployment-plan" {
		return "GET", true
	}
	if len(parts) == 3 && parts[0] != "" && (parts[1] == "sources" || parts[1] == "operations") && parts[2] != "" {
		return "GET", true
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] == "sources" {
		return "GET, POST", true
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] == "fix-candidates" {
		return "POST", true
	}
	if len(parts) == 3 && parts[0] != "" && parts[1] == "fix-candidates" && parts[2] != "" {
		return "GET", true
	}
	if len(parts) == 4 && parts[0] != "" && parts[1] == "fix-candidates" && parts[2] != "" && (parts[3] == "source-match" || parts[3] == "publish") {
		return "POST", true
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] == "deliveries" {
		return "GET, POST", true
	}
	if len(parts) == 3 && parts[0] != "" && parts[1] == "deliveries" && parts[2] != "" {
		return "GET", true
	}
	if len(parts) == 4 && parts[0] != "" && parts[1] == "deliveries" && parts[2] != "" {
		switch parts[3] {
		case "restart", "redeploy", "probes":
			return "POST", true
		case "logs", "source":
			return "GET", true
		case "public-access":
			return "GET, PUT", true
		case "access-observation":
			return "GET, POST", true
		}
	}
	return "", false
}

func (s *Server) handleAcornFoxSources(w http.ResponseWriter, r *http.Request, applicationID domain.ID) {
	if s.acornFoxDiscovery == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "discovery_unavailable", "source discovery is unavailable")
		return
	}
	s.acornFoxDiscovery.HandleSources(w, r, applicationID)
}

func (s *Server) handleAcornFoxDeliveries(w http.ResponseWriter, r *http.Request, applicationID domain.ID) {
	if s.acornFoxDiscovery == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "discovery_unavailable", "delivery discovery is unavailable")
		return
	}
	s.acornFoxDiscovery.HandleDeliveries(w, r, applicationID)
}

func (s *Server) handleAcornFoxDeliveryPublicAccess(w http.ResponseWriter, r *http.Request, applicationID, deploymentID domain.ID) {
	if s.acornFoxPublicAccess == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "public_access_unavailable", "public access is unavailable")
		return
	}
	// Exact app/deployment ownership is verified by the public-access store.
	// The handler neither probes runtime nor invokes DNS/Caddy directly.
	s.acornFoxPublicAccess.Handle(w, r, applicationID, deploymentID)
}

func (s *Server) handleAcornFoxDeliveryLogs(w http.ResponseWriter, r *http.Request, applicationID, deploymentID domain.ID) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, OPTIONS")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if s.acornFoxLogs == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "logs_unavailable", "logs are unavailable")
		return
	}
	s.acornFoxLogs.Handle(w, r, applicationID, deploymentID)
}

func (s *Server) handleAcornFoxApps(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.controller.ListApplications(r.Context())
		if err != nil {
			writeAcornFoxError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		var input struct {
			Name   string `json:"name"`
			Source struct {
				Type          string `json:"type"`
				RepositoryURL string `json:"repository_url"`
				Ref           string `json:"ref"`
			} `json:"source"`
		}
		if err := decodeJSON(r, &input); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", "request body is invalid")
			return
		}
		key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if key == "" || input.Source.Type != "public_git" {
			writeJSONError(w, http.StatusUnprocessableEntity, "validation_failed", "name, public_git source, and Idempotency-Key are required")
			return
		}
		result, err := s.controller.CreateApplicationWithSource(r.Context(), input.Name, &application.CreateApplicationSource{Kind: application.CreateApplicationSourceGit, PublicGit: true, RepositoryURL: input.Source.RepositoryURL, Ref: input.Source.Ref}, key)
		if err != nil {
			writeAcornFoxError(w, err)
			return
		}
		s.broker.publish(result.Event)
		writeJSON(w, http.StatusCreated, map[string]any{"application": result.Application, "source_revision_id": result.SourceRevisionID, "operation_id": result.OperationID})
	default:
		w.Header().Set("Allow", "GET, POST, OPTIONS")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (s *Server) handleAcornFoxApp(w http.ResponseWriter, r *http.Request, applicationID domain.ID) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, OPTIONS")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	item, err := s.controller.GetApplication(r.Context(), applicationID)
	if err != nil {
		writeAcornFoxError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleAcornFoxSource(w http.ResponseWriter, r *http.Request, applicationID, sourceID domain.ID) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, OPTIONS")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if s.acornFoxDeployments == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "capability_unavailable", "source readback is unavailable")
		return
	}
	source, err := s.acornFoxDeployments.GetAcornFoxSourceRevision(r.Context(), applicationID, sourceID)
	if err != nil {
		writeAcornFoxError(w, errOrNotFound(err))
		return
	}
	projected, err := contracts.ProjectAcornFoxInputRevision(source)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "source readback is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, projected)
}

func (s *Server) handleAcornFoxDeliveryCreate(w http.ResponseWriter, r *http.Request, applicationID domain.ID) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, OPTIONS")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	var input acornFoxDeliveryInput
	if err := decodeJSON(r, &input); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	s.acornFoxCommand(w, r, applicationID, "create", input, "")
}

func (s *Server) handleAcornFoxDeliveryStatus(w http.ResponseWriter, r *http.Request, applicationID, deploymentID domain.ID) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, OPTIONS")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if s.acornFoxDeployments == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "capability_unavailable", "delivery readback is unavailable")
		return
	}
	deployment, err := s.acornFoxDeployments.GetAcornFoxDeployment(r.Context(), applicationID, deploymentID)
	if err != nil {
		writeAcornFoxError(w, errOrNotFound(err))
		return
	}
	// Runtime and response are distinct persisted facts. Neither is converted
	// into health, public URL, DNS, TLS, or business-success language here.
	projected, projectionErr := contracts.ProjectAcornFoxDeploymentRuntimeState(deployment)
	if projectionErr != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "delivery readback is unavailable")
		return
	}
	status := map[string]any{"deployment": projected, "desired": nil, "runtime": nil, "response": nil}
	if desired, err := s.acornFoxDeployments.GetAcornFoxRuntimeRequest(r.Context(), applicationID, deploymentID); err == nil {
		status["desired"] = desired.Fact
	} else if !errors.Is(err, postgres.ErrNotFound) {
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "delivery readback is unavailable")
		return
	}
	if runtime, err := s.acornFoxDeployments.GetAcornFoxRuntimeObservation(r.Context(), applicationID, deploymentID); err == nil {
		status["runtime"] = runtime
	} else if !errors.Is(err, postgres.ErrNotFound) {
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "delivery readback is unavailable")
		return
	}
	if response, err := s.acornFoxDeployments.GetLatestAcornFoxProbeObservation(r.Context(), applicationID, deploymentID); err == nil {
		status["response"] = acornFoxProbePublicResponse(response)
	} else if !errors.Is(err, postgres.ErrNotFound) {
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "delivery readback is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func acornFoxProbePublicResponse(item postgres.AcornFoxProbeObservation) map[string]any {
	return map[string]any{"protocol": item.Protocol, "outcome": item.Outcome, "http_status": item.HTTPStatus, "latency_ms": item.LatencyMS, "error_code": item.ErrorCode, "observed_at": item.ObservedAt, "fact_digest": item.FactDigest}
}

func (s *Server) handleAcornFoxDeliveryAction(w http.ResponseWriter, r *http.Request, applicationID, deploymentID domain.ID, action string) {
	if action != "restart" && action != "redeploy" && action != "probes" {
		writeJSONError(w, http.StatusNotFound, "not_found", "route not found")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, OPTIONS")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if action == "probes" {
		var input acornFoxProbeInput
		if err := decodeJSON(r, &input); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", "request body is invalid")
			return
		}
		s.acornFoxCommand(w, r, applicationID, action, input, deploymentID)
		return
	}
	if err := rejectNonEmptyJSON(r); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "request body must be empty")
		return
	}
	s.acornFoxCommand(w, r, applicationID, action, nil, deploymentID)
}

func (s *Server) acornFoxCommand(w http.ResponseWriter, r *http.Request, applicationID domain.ID, action string, input any, deploymentID domain.ID) {
	key, actor := strings.TrimSpace(r.Header.Get("Idempotency-Key")), controlPlaneActor(r)
	if key == "" {
		writeJSONError(w, http.StatusUnprocessableEntity, "validation_failed", "Idempotency-Key is required")
		return
	}
	if actor == "" || s.acornFoxDeliveryCommand == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "capability_unavailable", "delivery command is unavailable")
		return
	}
	var result acornFoxDeliveryResult
	var err error
	switch action {
	case "create":
		result, err = s.acornFoxDeliveryCommand.Create(r.Context(), applicationID, input.(acornFoxDeliveryInput), key, actor)
	case "restart":
		result, err = s.acornFoxDeliveryCommand.Restart(r.Context(), applicationID, deploymentID, key, actor)
	case "redeploy":
		result, err = s.acornFoxDeliveryCommand.Redeploy(r.Context(), applicationID, deploymentID, key, actor)
	case "probes":
		result, err = s.acornFoxDeliveryCommand.Probe(r.Context(), applicationID, deploymentID, input.(acornFoxProbeInput), key, actor)
	}
	if err != nil {
		writeAcornFoxError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, result)
}

func rejectNonEmptyJSON(r *http.Request) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	var input map[string]any
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	if len(input) != 0 {
		return errors.New("nonempty")
	}
	return nil
}

func errOrNotFound(err error) error {
	if err != nil {
		return err
	}
	return application.ErrNotFound
}
func writeAcornFoxError(w http.ResponseWriter, err error) {
	if errors.Is(err, postgres.ErrEnvironmentOperationActive) {
		writeJSONError(w, http.StatusConflict, "operation_conflict", "another operation is still running for this application")
		return
	}
	// Built-in providers publish fixed, sanitized source/build failure messages.
	// Keep their actionable reason while withholding causes and private details.
	var providerErr *contracts.ProviderError
	if errors.As(err, &providerErr) && (providerErr.Provider == "bounded-source" || providerErr.Provider == "rootless-buildkit-buildctl") {
		writeDomainError(w, providerErr)
		return
	}
	if errors.Is(err, application.ErrNotFound) || errors.Is(err, postgres.ErrNotFound) || domain.IsCode(err, domain.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if errors.Is(err, application.ErrIdempotencyConflict) || errors.Is(err, postgres.ErrIdempotencyConflict) || domain.IsCode(err, domain.ErrConflict) {
		writeJSONError(w, http.StatusConflict, "idempotency_conflict", "idempotency key conflicts with a prior request")
		return
	}
	if errors.Is(err, postgres.ErrIdempotencyInProgress) {
		writeJSONError(w, http.StatusConflict, "operation_conflict", "operation is already in progress")
		return
	}
	if domain.IsCode(err, domain.ErrValidation) {
		writeJSONError(w, http.StatusUnprocessableEntity, "validation_failed", "request is invalid")
		return
	}
	writeJSONError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
}
