package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/open-card/open-card/internal/agenttransport"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

const (
	apiPrefix   = "/api/v1/"
	maxJSONBody = 1 << 20
)

type eventBroker struct {
	mu          sync.Mutex
	subscribers map[chan application.Event]string
}

func newEventBroker() *eventBroker {
	return &eventBroker{subscribers: make(map[chan application.Event]string)}
}

func (b *eventBroker) publish(value application.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for subscriber, operationID := range b.subscribers {
		if operationID != "" && operationID != value.OperationID {
			continue
		}
		select {
		case subscriber <- value:
		default: /* a slow UI cannot block the control plane */
		}
	}
}

func (b *eventBroker) subscribe(operationID string) (chan application.Event, func()) {
	channel := make(chan application.Event, 16)
	b.mu.Lock()
	b.subscribers[channel] = operationID
	b.mu.Unlock()
	return channel, func() {
		b.mu.Lock()
		if _, ok := b.subscribers[channel]; ok {
			delete(b.subscribers, channel)
			close(channel)
		}
		b.mu.Unlock()
	}
}

type Server struct {
	controller *application.Controller
	// legacyRoutesEnabled is intentionally opt-in. A new AcornFox install
	// exposes only its small /api/v1/acornfox façade; upgraded installations
	// can enable their historical Open Card routes explicitly during migration.
	legacyRoutesEnabled bool
	releaseController   *controllers.ReleaseController
	m2Controller        *controllers.M2ReleaseController
	m2Store             interface {
		GetSourceRevision(context.Context, domain.ID) (domain.SourceRevision, error)
		GetSourceWorkspaceLifecycle(context.Context, domain.ID) (postgres.WorkspaceLifecycle, error)
		CreateDeliveryDefinition(context.Context, domain.ApplicationDeliveryDefinition) (domain.ApplicationDeliveryDefinition, error)
		GetDeliveryDefinition(context.Context, domain.ID) (domain.ApplicationDeliveryDefinition, error)
		GetServiceGroupRecord(context.Context, domain.ID) (postgres.ServiceGroupRecord, error)
		GetServiceGroupIdentity(context.Context, domain.ID) (postgres.M2ServiceGroupIdentity, error)
		GetCompleteRelease(context.Context, domain.ID) (domain.Release, error)
		GetM2ReleaseRuntimeSpec(context.Context, domain.ID) (contracts.ServiceGroupRuntimeSpec, string, error)
		GetDeployment(context.Context, domain.ID) (domain.Deployment, error)
		GetDeploymentEndpoint(context.Context, domain.ID) (postgres.DeploymentEndpoint, error)
		GetDefaultEnvironmentID(context.Context, domain.ID) (domain.ID, error)
		GetDeploymentOperationID(context.Context, domain.ID) (domain.ID, error)
		ListM2ReleaseVolumeClaims(context.Context, domain.ID) ([]postgres.M2ServiceGroupVolumeClaim, error)
	}
	m2Registry                 contracts.RegistryImageProvider
	m2UploadRoot               string
	m2TaskPrefix               string
	m2AgentInstance            string
	m2AgentNode                string
	m2Lifecycle                *M2LifecycleHandler
	auth                       *AuthHTTPHandler
	m3Access                   *M3AccessHTTPHandler
	g3Access                   *G3AccessHTTPHandler
	g3SourceUpload             *G3SourceUploadHTTPHandler
	tlsAllow                   *TLSAllowHTTPHandler
	m4Operations               *M4OperationsHTTPHandler
	m4Webhooks                 *M4WebhookHTTPHandler
	m4Logs                     *M4LogsHTTPHandler
	m5Usage                    *M5UsageHTTPHandler
	m6AI                       *M6AIHTTPHandler
	systemStatusStore          systemStatusStore
	systemStatusInstanceID     string
	systemStatusNodeID         string
	applicationProjectionStore applicationProjectionStore
	applicationAccessProvider  applicationAccessProvider
	publishInputStore          publishInputStore
	applicationPublisher       applicationPublisher
	acornFoxDeployments        acornFoxDeploymentStore
	acornFoxDeliveryCommand    acornFoxDeliveryCommand
	acornFoxLogs               *AcornFoxLogsHTTPHandler
	acornFoxPublicAccess       *AcornFoxPublicAccessHTTPHandler
	broker                     *eventBroker
	agentGateway               *agenttransport.Gateway
	repositoryHealth           interface {
		PingContext(context.Context) error
	}
	ready  atomic.Bool
	logger *log.Logger
}

func NewServer() *Server {
	// NewServer preserves the historical compatibility constructor for existing
	// upgraded-install integrations and tests. New product composition must use
	// NewAcornFoxServer instead.
	return newServerWithRepository(application.NewMemoryRepository(), true)
}

func NewServerWithRepository(repository application.Repository) *Server {
	return newServerWithRepository(repository, true)
}

func NewAcornFoxServer() *Server {
	return newServerWithRepository(application.NewMemoryRepository(), false)
}

func NewAcornFoxServerWithRepository(repository application.Repository) *Server {
	return newServerWithRepository(repository, false)
}

func newServerWithRepository(repository application.Repository, legacyRoutesEnabled bool) *Server {
	server := &Server{controller: application.NewController(repository), legacyRoutesEnabled: legacyRoutesEnabled, broker: newEventBroker(), agentGateway: agenttransport.NewStrictGateway(nil), logger: log.Default()}
	if health, ok := repository.(interface {
		PingContext(context.Context) error
	}); ok {
		server.repositoryHealth = health
	}
	server.ready.Store(true)
	if memory, ok := repository.(*application.MemoryRepository); ok {
		server.applicationProjectionStore = memoryApplicationProjectionStore{repository: memory}
	}
	return server
}

func (s *Server) SetReady(ready bool) { s.ready.Store(ready) }
func (s *Server) SetReleaseController(controller *controllers.ReleaseController) {
	s.releaseController = controller
}
func (s *Server) SetM2(controller *controllers.M2ReleaseController, store *postgres.Store, registry contracts.RegistryImageProvider, uploadRoot, taskPrefix, agentInstance, agentNode string) {
	s.m2Controller, s.m2Store, s.m2Registry = controller, store, registry
	s.m2UploadRoot, s.m2TaskPrefix = uploadRoot, taskPrefix
	s.m2AgentInstance, s.m2AgentNode = agentInstance, agentNode
}
func (s *Server) SetM2Lifecycle(handler *M2LifecycleHandler)           { s.m2Lifecycle = handler }
func (s *Server) SetAuth(handler *AuthHTTPHandler)                     { s.auth = handler }
func (s *Server) SetM3Access(handler *M3AccessHTTPHandler)             { s.m3Access = handler }
func (s *Server) SetG3Access(handler *G3AccessHTTPHandler)             { s.g3Access = handler }
func (s *Server) SetG3SourceUpload(handler *G3SourceUploadHTTPHandler) { s.g3SourceUpload = handler }
func (s *Server) SetTLSAllow(handler *TLSAllowHTTPHandler)             { s.tlsAllow = handler }
func (s *Server) SetM4Operations(handler *M4OperationsHTTPHandler)     { s.m4Operations = handler }
func (s *Server) SetM4Webhooks(handler *M4WebhookHTTPHandler)          { s.m4Webhooks = handler }
func (s *Server) SetM4Logs(handler *M4LogsHTTPHandler)                 { s.m4Logs = handler }
func (s *Server) SetM5Usage(handler *M5UsageHTTPHandler)               { s.m5Usage = handler }
func (s *Server) SetM6AI(handler *M6AIHTTPHandler)                     { s.m6AI = handler }
func (s *Server) SetSystemStatusStore(store systemStatusStore)         { s.systemStatusStore = store }
func (s *Server) SetSystemStatusNode(instanceID, nodeID string) {
	s.systemStatusInstanceID, s.systemStatusNodeID = instanceID, nodeID
}
func (s *Server) SetApplicationProjectionStore(store applicationProjectionStore) {
	s.applicationProjectionStore = store
}
func (s *Server) SetApplicationAccessProvider(provider applicationAccessProvider) {
	s.applicationAccessProvider = provider
}
func (s *Server) SetApplicationPublisher(store publishInputStore, publisher applicationPublisher) {
	s.publishInputStore, s.applicationPublisher = store, publisher
}
func (s *Server) SetAcornFoxDeploymentStore(store acornFoxDeploymentStore) {
	s.acornFoxDeployments = store
}
func (s *Server) SetAcornFoxLogs(handler *AcornFoxLogsHTTPHandler) { s.acornFoxLogs = handler }
func (s *Server) SetAcornFoxPublicAccess(handler *AcornFoxPublicAccessHTTPHandler) {
	s.acornFoxPublicAccess = handler
}
func (s *Server) SetLegacyRoutesEnabled(enabled bool)   { s.legacyRoutesEnabled = enabled }
func (s *Server) Handler() http.Handler                 { return http.HandlerFunc(s.serveHTTP) }
func (s *Server) AgentGateway() *agenttransport.Gateway { return s.agentGateway }
func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 0, IdleTimeout: 60 * time.Second}
}

func (s *Server) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	if s.tlsAllow != nil && s.tlsAllow.Handle(writer, request) {
		return
	}
	if request.URL.Path == "/healthz" || request.URL.Path == "/readyz" {
		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", http.MethodGet)
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.handleHealth(writer, request, request.URL.Path == "/readyz")
		return
	}
	// A clean install exposes no legacy API path, including unauthenticated
	// aliases. Reject before session authentication so route discovery does not
	// turn a known-absent route into an authentication-dependent response.
	if !s.legacyRoutesEnabled && strings.HasPrefix(request.URL.Path, apiPrefix) && !strings.HasPrefix(request.URL.Path, "/api/v1/acornfox/") {
		writeJSONError(writer, http.StatusNotFound, "not_found", "route not found")
		return
	}
	if s.legacyRoutesEnabled && isAuthRoute(request.URL.Path) && strings.HasPrefix(request.URL.Path, apiPrefix) {
		version, disabled, err := negotiateAPIRequest(request)
		if err != nil {
			writeJSONError(writer, http.StatusUpgradeRequired, "api_version_incompatible", err.Error())
			return
		}
		writer.Header().Set(apiVersionHeader, version)
		if len(disabled) > 0 {
			writer.Header().Set("Open-Card-Disabled-Capabilities", strings.Join(disabled, ","))
		}
		request = withAPIVersion(request, version)
	}
	if isAuthRoute(request.URL.Path) {
		if s.auth != nil && s.auth.Handle(writer, request) {
			return
		}
		authNoStore(writer)
		authHTTPError(writer, http.StatusServiceUnavailable, "authentication unavailable")
		return
	}
	if isAcornFoxAuthRoute(request.URL.Path) {
		if s.auth != nil && s.auth.HandleAcornFox(writer, request) {
			return
		}
		authNoStore(writer)
		authHTTPError(writer, http.StatusServiceUnavailable, "authentication unavailable")
		return
	}
	var authenticated bool
	if strings.HasPrefix(request.URL.Path, "/api/v1/acornfox/") {
		request, authenticated = s.authenticateAcornFoxControlPlane(writer, request)
	} else {
		request, authenticated = s.authenticateControlPlane(writer, request)
	}
	if !authenticated {
		return
	}
	if strings.HasPrefix(request.URL.Path, apiPrefix) && s.legacyRoutesEnabled {
		version, disabled, err := negotiateAPIRequest(request)
		if err != nil {
			writeJSONError(writer, http.StatusUpgradeRequired, "api_version_incompatible", err.Error())
			return
		}
		writer.Header().Set(apiVersionHeader, version)
		if len(disabled) > 0 {
			writer.Header().Set("Open-Card-Disabled-Capabilities", strings.Join(disabled, ","))
		}
		request = withAPIVersion(request, version)
	}
	if s.handleAcornFoxAPI(writer, request) {
		return
	}
	if request.Method == http.MethodOptions {
		if strings.HasPrefix(request.URL.Path, apiPrefix) && !s.legacyRoutesEnabled {
			writeJSONError(writer, http.StatusNotFound, "not_found", "route not found")
			return
		}
		writer.Header().Set("Allow", "GET, POST, OPTIONS")
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if strings.HasPrefix(request.URL.Path, apiPrefix) && !s.legacyRoutesEnabled {
		writeJSONError(writer, http.StatusNotFound, "not_found", "route not found")
		return
	}
	switch request.URL.Path {
	case "/api/v1/settings/system-status":
		s.handleSystemStatus(writer, request)
		return
	case "/api/v1/events":
		s.handleEvents(writer, request, "")
		return
	case "/api/v1/applications", "/api/v1/applications/":
		if request.Method == http.MethodGet {
			s.handleApplicationProjectionList(writer, request)
			return
		}
		s.handleApplications(writer, request)
		return
	case "/api/v1/publishes", "/api/v1/publishes/":
		writeJSONError(writer, http.StatusGone, "publish_endpoint_replaced", "use the application publish endpoint")
		return
	}
	if strings.HasPrefix(request.URL.Path, apiPrefix+"operations/") && strings.HasSuffix(request.URL.Path, "/events") {
		operationID := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, apiPrefix+"operations/"), "/events")
		if operationID == "" {
			writeJSONError(writer, http.StatusNotFound, "not_found", "operation not found")
			return
		}
		s.handleEvents(writer, request, operationID)
		return
	}
	if s.m4Operations != nil && s.m4Operations.Handle(writer, request) {
		return
	}
	if s.m6AI != nil && s.m6AI.Handle(writer, request) {
		return
	}
	if strings.HasPrefix(request.URL.Path, apiPrefix+"applications/") {
		parts := strings.Split(strings.TrimPrefix(request.URL.Path, apiPrefix+"applications/"), "/")
		if len(parts) == 2 && parts[0] != "" && parts[1] == "publishes" {
			handleApplicationPublish(writer, request, domain.ID(parts[0]), s.publishInputStore, s.applicationPublisher, controlPlaneActor(request), time.Now)
			return
		}
		identifier := strings.Trim(strings.TrimPrefix(request.URL.Path, apiPrefix+"applications/"), "/")
		if request.Method == http.MethodGet && identifier != "" && !strings.Contains(identifier, "/") {
			s.handleApplicationProjectionDetail(writer, request, domain.ID(identifier))
			return
		}
		if s.g3Access != nil && s.g3Access.Handle(writer, request) {
			return
		}
		if s.m5Usage != nil && s.m5Usage.HandleApplication(writer, request) {
			return
		}
		if s.m4Logs != nil && s.m4Logs.HandleApplication(writer, request) {
			return
		}
		if s.m4Webhooks != nil && s.m4Webhooks.HandleApplication(writer, request) {
			return
		}
		if s.m4Operations != nil && s.m4Operations.HandleApplication(writer, request) {
			return
		}
		s.handleApplication(writer, request)
		return
	}
	if s.g3SourceUpload != nil && s.g3SourceUpload.Handle(writer, request) {
		return
	}
	if s.m2Lifecycle != nil && s.m2Lifecycle.Handle(writer, request) {
		return
	}
	if s.m3Access != nil && s.m3Access.Handle(writer, request) {
		return
	}
	if s.g3Access != nil && s.g3Access.Handle(writer, request) {
		return
	}
	if s.m2Controller != nil && s.handleM2(writer, request) {
		return
	}
	writeJSONError(writer, http.StatusNotFound, "not_found", "route not found")
}

func (s *Server) handlePublish(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST, OPTIONS")
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if s.releaseController == nil {
		writeJSONError(writer, http.StatusServiceUnavailable, "publish_unavailable", "M1 publish controller is not configured")
		return
	}
	var input controllers.PublishRequest
	if err := decodeJSON(request, &input); err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_argument", err.Error())
		return
	}
	input.IdempotencyKey = strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if input.IdempotencyKey == "" {
		writeJSONError(writer, http.StatusBadRequest, "invalid_argument", "Idempotency-Key is required")
		return
	}
	result, err := s.releaseController.Publish(request.Context(), input)
	if err != nil {
		writeApplicationError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, result)
}

func (s *Server) handleHealth(writer http.ResponseWriter, request *http.Request, ready bool) {
	if ready && !s.ready.Load() {
		writeJSONError(writer, http.StatusServiceUnavailable, "not_ready", "control plane is not ready")
		return
	}
	if ready && s.repositoryHealth != nil {
		ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
		err := s.repositoryHealth.PingContext(ctx)
		cancel()
		if err != nil {
			s.logger.Printf("repository readiness failed: %v", err)
			writeJSONError(writer, http.StatusServiceUnavailable, "repository_not_ready", "control-plane repository is not ready")
			return
		}
	}
	writeJSON(writer, http.StatusOK, map[string]any{"status": "ok", "ready": s.ready.Load()})
}

func (s *Server) handleApplications(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		items, err := s.controller.ListApplications(request.Context())
		if err != nil {
			writeApplicationError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		var input struct {
			Name   string `json:"name"`
			Source *struct {
				Kind          string `json:"kind"`
				UploadID      string `json:"upload_id"`
				RepositoryURL string `json:"repository_url"`
				Ref           string `json:"ref"`
			} `json:"source"`
		}
		if err := decodeJSON(request, &input); err != nil {
			writeJSONError(writer, http.StatusBadRequest, "invalid_argument", err.Error())
			return
		}
		var source *application.CreateApplicationSource
		if input.Source != nil {
			source = &application.CreateApplicationSource{Kind: application.CreateApplicationSourceKind(input.Source.Kind), UploadID: domain.ID(input.Source.UploadID), RepositoryURL: input.Source.RepositoryURL, Ref: input.Source.Ref}
		} else {
			writeJSONError(writer, http.StatusUnprocessableEntity, "validation_failed", "source is required")
			return
		}
		result, err := s.controller.CreateApplicationWithSource(request.Context(), input.Name, source, request.Header.Get("Idempotency-Key"))
		if err != nil {
			writeCreateApplicationError(writer, err)
			return
		}
		s.broker.publish(result.Event)
		if s.applicationProjectionStore == nil {
			writeJSONError(writer, http.StatusServiceUnavailable, "application_projection_unavailable", "application projection is unavailable")
			return
		}
		projection, projectionErr := s.applicationProjectionStore.ApplicationProjection(request.Context(), result.Application.ID)
		if projectionErr != nil {
			writeJSONError(writer, http.StatusServiceUnavailable, "application_projection_unavailable", "application projection is unavailable")
			return
		}
		summary, summaryErr := s.applicationSummary(request.Context(), projection)
		if summaryErr != nil {
			writeJSONError(writer, http.StatusServiceUnavailable, "application_projection_unavailable", "application projection is unavailable")
			return
		}
		response := map[string]any{"application": summary, "environment_id": result.EnvironmentID.String(), "operation_id": result.OperationID.String(), "source_revision_id": result.SourceRevisionID.String()}
		writeJSON(writer, http.StatusCreated, response)
	default:
		writer.Header().Set("Allow", "GET, POST, OPTIONS")
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (s *Server) handleApplication(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", "GET, OPTIONS")
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	identifier := strings.TrimPrefix(request.URL.Path, apiPrefix+"applications/")
	identifier = strings.Trim(identifier, "/")
	if identifier == "" {
		writeJSONError(writer, http.StatusNotFound, "not_found", "application not found")
		return
	}
	item, err := s.controller.GetApplication(request.Context(), domain.ID(identifier))
	if err != nil {
		writeApplicationError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, item)
}

func (s *Server) handleEvents(writer http.ResponseWriter, request *http.Request, operationID string) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", "GET, OPTIONS")
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	flusher, ok := writer.(http.Flusher)
	if !ok {
		writeJSONError(writer, http.StatusInternalServerError, "stream_unsupported", "server does not support event streaming")
		return
	}
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")
	writer.Header().Set("X-Accel-Buffering", "no")
	if lastEventID := request.Header.Get("Last-Event-ID"); lastEventID != "" {
		fmt.Fprintf(writer, ": last-event-id=%s\n\n", sanitizeSSEComment(lastEventID))
	} else {
		io.WriteString(writer, ": connected\n\n")
	}
	flusher.Flush()
	afterSequence := parseSSESequence(request.Header.Get("Last-Event-ID"))
	channel, unsubscribe := s.broker.subscribe(operationID)
	defer unsubscribe()
	replayed, err := s.controller.ListEvents(request.Context(), operationID, afterSequence)
	if err != nil {
		s.logger.Printf("event replay failed: %v", err)
		return
	}
	lastSequence := afterSequence
	for _, value := range replayed {
		if err := writeSSE(writer, value, apiVersionFromContext(request.Context())); err != nil {
			return
		}
		lastSequence = value.Sequence
	}
	flusher.Flush()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-request.Context().Done():
			return
		case <-heartbeat.C:
			if _, err := io.WriteString(writer, ": heartbeat\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case value, open := <-channel:
			if !open {
				return
			}
			if value.Sequence <= lastSequence {
				continue
			}
			if err := writeSSE(writer, value, apiVersionFromContext(request.Context())); err != nil {
				return
			}
			lastSequence = value.Sequence
			flusher.Flush()
		}
	}
}

func writeSSE(writer io.Writer, value application.Event, apiVersion string) error {
	if apiVersion == apiPreviousVersion {
		value.SchemaVersion = ""
	} else if value.SchemaVersion == "" {
		value.SchemaVersion = apiPreviousVersion
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(writer, "id: %s\nevent: message\ndata: %s\n\n", sanitizeSSEComment(value.ID), data)
	return err
}

func sanitizeSSEComment(value string) string {
	return strings.NewReplacer("\r", "", "\n", "", ":", "").Replace(value)
}

func parseSSESequence(value string) uint64 {
	value = strings.TrimPrefix(strings.TrimSpace(value), "evt-")
	var sequence uint64
	if _, err := fmt.Sscanf(value, "%d", &sequence); err != nil {
		return 0
	}
	return sequence
}

func decodeJSON(request *http.Request, target any) error {
	if request.Body == nil {
		return errors.New("request body is required")
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, maxJSONBody))
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

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeJSONError(writer http.ResponseWriter, status int, code, message string) {
	writeJSON(writer, status, map[string]string{"code": code, "message": message})
}

func writeApplicationError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, application.ErrNotFound):
		writeJSONError(writer, http.StatusNotFound, "not_found", "application not found")
	case errors.Is(err, application.ErrIdempotencyConflict):
		writeJSONError(writer, http.StatusConflict, "idempotency_conflict", "idempotency key was reused with different input")
	default:
		writeDomainError(writer, err)
	}
}

func writeCreateApplicationError(writer http.ResponseWriter, err error) {
	var providerError *contracts.ProviderError
	if errors.As(err, &providerError) && providerError.Code == contracts.ErrValidation {
		writeJSONError(writer, http.StatusUnprocessableEntity, string(providerError.Code), providerError.Message)
		return
	}
	if domain.IsCode(err, domain.ErrValidation) {
		writeJSONError(writer, http.StatusUnprocessableEntity, string(domain.ErrValidation), "application source is invalid")
		return
	}
	writeApplicationError(writer, err)
}

func writeDomainError(writer http.ResponseWriter, err error) {
	if errors.Is(err, controllers.ErrM4ActiveOperation) {
		writeJSONError(writer, http.StatusConflict, "active_operation_conflict", "an operations task is already active for this environment")
		return
	}
	var providerError *contracts.ProviderError
	if errors.As(err, &providerError) {
		status := http.StatusBadRequest
		switch providerError.Code {
		case contracts.ErrNotFound:
			status = http.StatusNotFound
		case contracts.ErrConflict, contracts.ErrCapacity:
			status = http.StatusConflict
		case contracts.ErrUnauthorized, contracts.ErrForbidden:
			status = http.StatusForbidden
		case contracts.ErrUnavailable, contracts.ErrTimeout:
			status = http.StatusServiceUnavailable
		}
		writeJSONError(writer, status, string(providerError.Code), providerError.Message)
		return
	}
	var domainError *domain.DomainError
	if errors.As(err, &domainError) {
		status := http.StatusBadRequest
		switch domainError.Code {
		case domain.ErrNotFound:
			status = http.StatusNotFound
		case domain.ErrConflict:
			status = http.StatusConflict
		case domain.ErrUnauthorized, domain.ErrForbidden:
			status = http.StatusForbidden
		case domain.ErrUnavailable:
			status = http.StatusServiceUnavailable
		}
		writeJSONError(writer, status, string(domainError.Code), domainError.Message)
		return
	}
	log.Printf("internal request error: %s", foundation.RedactText(err.Error()))
	writeJSONError(writer, http.StatusInternalServerError, "internal_error", "internal server error")
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.ready.Store(false)
	return nil
}
