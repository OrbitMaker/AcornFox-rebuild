package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
	"github.com/open-card/open-card/internal/providers/publicdns"
)

// G3AccessHTTPHandler exposes the frozen UI-facing domain/access contract. It
// delegates all authorization to authenticateControlPlane, so actor identity
// is derived only from the verified session context.
type G3AccessHTTPHandler struct {
	Controller *controllers.G3AccessController
}

func (h *G3AccessHTTPHandler) Handle(writer http.ResponseWriter, request *http.Request) bool {
	if h == nil || h.Controller == nil {
		return false
	}
	if request.URL.Path == apiPrefix+"settings/platform-domain" {
		h.handlePlatformDomain(writer, request)
		return true
	}
	applicationID, domainID, action, ok := g3ApplicationPath(request.URL.Path)
	if !ok {
		return false
	}
	switch action {
	case "domains":
		h.handleDomains(writer, request, applicationID)
	case "verify":
		h.handleVerify(writer, request, applicationID, domainID)
	case "unbind":
		h.handleUnbind(writer, request, applicationID, domainID)
	case "access":
		h.handleAccess(writer, request, applicationID)
	default:
		return false
	}
	return true
}

func (h *G3AccessHTTPHandler) handlePlatformDomain(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		value, err := h.Controller.GetPlatformSettings(request.Context())
		if err != nil {
			writeG3Error(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, value)
	case http.MethodPut:
		key, ok := g3MutationRequest(writer, request, http.MethodPut)
		if !ok {
			return
		}
		var input struct {
			BaseDomain string `json:"base_domain"`
		}
		if !g3DecodeJSON(writer, request, &input) {
			return
		}
		value, replay, err := h.Controller.ConfigurePlatformDomain(request.Context(), input.BaseDomain, key, controlPlaneActor(request))
		if err != nil {
			writeG3Error(writer, err)
			return
		}
		status := http.StatusAccepted
		if replay {
			status = http.StatusOK
		}
		writeJSON(writer, status, value)
	default:
		writer.Header().Set("Allow", "GET, PUT, OPTIONS")
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (h *G3AccessHTTPHandler) handleDomains(writer http.ResponseWriter, request *http.Request, applicationID domain.ID) {
	switch request.Method {
	case http.MethodGet:
		items, err := h.Controller.ListApplicationDomains(request.Context(), applicationID)
		if err != nil {
			writeG3Error(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		key, ok := g3MutationRequest(writer, request, http.MethodPost)
		if !ok {
			return
		}
		var input struct {
			Hostname string `json:"hostname"`
		}
		if !g3DecodeJSON(writer, request, &input) {
			return
		}
		value, _, err := h.Controller.BindCustomDomain(request.Context(), applicationID, input.Hostname, key, controlPlaneActor(request))
		if err != nil {
			writeG3Error(writer, err)
			return
		}
		writeJSON(writer, http.StatusAccepted, map[string]any{"domain": value})
	default:
		writer.Header().Set("Allow", "GET, POST, OPTIONS")
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (h *G3AccessHTTPHandler) handleVerify(writer http.ResponseWriter, request *http.Request, applicationID, domainID domain.ID) {
	if _, ok := g3MutationRequest(writer, request, http.MethodPost); !ok {
		return
	}
	if g3RequestHasBody(request) {
		writeJSONError(writer, http.StatusUnprocessableEntity, "validation_failed", "verification request must not contain a body")
		return
	}
	value, err := h.Controller.VerifyApplicationDomain(request.Context(), applicationID, domainID, strings.TrimSpace(request.Header.Get("Idempotency-Key")), controlPlaneActor(request))
	if err != nil {
		writeG3Error(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"domain": value})
}

func g3RequestHasBody(request *http.Request) bool {
	if request.Body == nil || request.Body == http.NoBody {
		return false
	}
	var buffer [1]byte
	count, err := request.Body.Read(buffer[:])
	return count > 0 || (err != nil && err != io.EOF)
}

func (h *G3AccessHTTPHandler) handleUnbind(writer http.ResponseWriter, request *http.Request, applicationID, domainID domain.ID) {
	key, ok := g3MutationRequest(writer, request, http.MethodDelete)
	if !ok {
		return
	}
	value, err := h.Controller.UnbindCustomDomain(request.Context(), applicationID, domainID, key, controlPlaneActor(request))
	if err != nil {
		writeG3Error(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"operation": value})
}

func (h *G3AccessHTTPHandler) handleAccess(writer http.ResponseWriter, request *http.Request, applicationID domain.ID) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", "GET, OPTIONS")
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	value, err := h.Controller.ApplicationAccess(request.Context(), applicationID)
	if err != nil {
		writeG3Error(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, value)
}

func g3ApplicationPath(path string) (domain.ID, domain.ID, string, bool) {
	prefix := apiPrefix + "applications/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) < 2 || parts[0] == "" {
		return "", "", "", false
	}
	applicationID := domain.ID(parts[0])
	switch {
	case len(parts) == 2 && parts[1] == "domains":
		return applicationID, "", "domains", true
	case len(parts) == 2 && parts[1] == "access":
		return applicationID, "", "access", true
	case len(parts) == 3 && parts[1] == "domains":
		return applicationID, domain.ID(parts[2]), "unbind", parts[2] != ""
	case len(parts) == 4 && parts[1] == "domains" && parts[3] == "verify":
		return applicationID, domain.ID(parts[2]), "verify", parts[2] != ""
	default:
		return "", "", "", false
	}
}

func g3MutationRequest(writer http.ResponseWriter, request *http.Request, method string) (string, bool) {
	if request.Method != method {
		writer.Header().Set("Allow", method+", OPTIONS")
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return "", false
	}
	key := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if key == "" {
		writeJSONError(writer, http.StatusUnprocessableEntity, "validation_failed", "Idempotency-Key is required")
		return "", false
	}
	return key, true
}

func g3DecodeJSON(writer http.ResponseWriter, request *http.Request, target any) bool {
	contentType := strings.ToLower(strings.TrimSpace(request.Header.Get("Content-Type")))
	if !strings.HasPrefix(contentType, "application/json") {
		writeJSONError(writer, http.StatusUnprocessableEntity, "validation_failed", "Content-Type must be application/json")
		return false
	}
	if err := decodeJSON(request, target); err != nil {
		writeJSONError(writer, http.StatusUnprocessableEntity, "validation_failed", "request body is invalid")
		return false
	}
	return true
}

func writeG3Error(writer http.ResponseWriter, err error) {
	var domainError *domain.DomainError
	if errors.As(err, &domainError) {
		switch domainError.Code {
		case domain.ErrNotFound:
			writeJSONError(writer, http.StatusNotFound, "not_found", domainError.Message)
		case domain.ErrConflict:
			writeJSONError(writer, http.StatusConflict, "conflict", domainError.Message)
		case domain.ErrValidation, domain.ErrInvalidArgument:
			writeJSONError(writer, http.StatusUnprocessableEntity, "validation_failed", domainError.Message)
		case domain.ErrUnavailable, domain.ErrTimeout:
			writeJSONError(writer, http.StatusServiceUnavailable, "dependency_unavailable", "required local dependency is unavailable")
		default:
			writeJSONError(writer, http.StatusUnauthorized, "authentication_failed", "authentication failed")
		}
		return
	}
	writeJSONError(writer, http.StatusServiceUnavailable, "dependency_unavailable", "required local dependency is unavailable")
}

// g3PostgresAdapter converts the persistence package's row-shaped facts to
// controller facts without introducing a persistence -> controller import.
type g3PostgresAdapter struct{ store *postgres.Store }

func (a *g3PostgresAdapter) ApplicationName(ctx context.Context, applicationID domain.ID) (string, bool, error) {
	name, found, err := a.store.ApplicationName(ctx, applicationID)
	return name, found, g3StoreAdapterError(err)
}
func (a *g3PostgresAdapter) PlatformDomain(ctx context.Context) (controllers.G3PlatformDomainFact, bool, error) {
	fact, found, err := a.store.PlatformDomain(ctx)
	return g3PlatformFact(fact), found, g3StoreAdapterError(err)
}
func (a *g3PostgresAdapter) ReplayG3Idempotency(ctx context.Context, request controllers.G3Idempotency) ([]byte, bool, error) {
	response, replay, err := a.store.ReplayG3Idempotency(ctx, g3PostgresIdempotency(request))
	return response, replay, g3StoreAdapterError(err)
}
func (a *g3PostgresAdapter) PutPlatformDomain(ctx context.Context, fact controllers.G3PlatformDomainFact, request controllers.G3Idempotency) (controllers.G3PlatformDomainFact, bool, error) {
	value, replay, err := a.store.PutPlatformDomain(ctx, postgres.G3PlatformDomainFact{ID: fact.ID, BaseDomain: fact.BaseDomain, VerificationRef: fact.VerificationRef, VerificationStatus: postgres.G3VerificationStatus(fact.VerificationStatus), VerifiedAt: fact.VerifiedAt, Certificate: g3PostgresCertificate(fact.Certificate), CreatedAt: fact.CreatedAt, UpdatedAt: fact.UpdatedAt}, g3PostgresIdempotency(request))
	return g3PlatformFact(value), replay, g3StoreAdapterError(err)
}
func (a *g3PostgresAdapter) ListApplicationDomains(ctx context.Context, applicationID domain.ID) ([]controllers.G3ApplicationDomainFact, error) {
	items, err := a.store.ListApplicationDomains(ctx, applicationID)
	result := make([]controllers.G3ApplicationDomainFact, 0, len(items))
	for _, item := range items {
		result = append(result, g3ApplicationFact(item))
	}
	return result, g3StoreAdapterError(err)
}
func (a *g3PostgresAdapter) ApplicationDomain(ctx context.Context, applicationID, domainID domain.ID) (controllers.G3ApplicationDomainFact, bool, error) {
	fact, found, err := a.store.ApplicationDomain(ctx, applicationID, domainID)
	return g3ApplicationFact(fact), found, g3StoreAdapterError(err)
}
func (a *g3PostgresAdapter) BindCustomDomain(ctx context.Context, fact controllers.G3ApplicationDomainFact, request controllers.G3Idempotency) (controllers.G3ApplicationDomainFact, bool, error) {
	value, created, err := a.store.BindCustomDomain(ctx, postgres.G3ApplicationDomainFact{ID: fact.ID, ApplicationID: fact.ApplicationID, Hostname: fact.Hostname, Kind: fact.Kind, CNAME: fact.CNAME, VerificationStatus: postgres.G3VerificationStatus(fact.VerificationStatus), VerifiedAt: fact.VerifiedAt, Certificate: g3PostgresCertificate(fact.Certificate), Serving: fact.Serving, RouteID: fact.RouteID, CreatedAt: fact.CreatedAt, UpdatedAt: fact.UpdatedAt}, g3PostgresIdempotency(request))
	return g3ApplicationFact(value), created, g3StoreAdapterError(err)
}
func (a *g3PostgresAdapter) SetApplicationDomainVerification(ctx context.Context, applicationID, domainID domain.ID, status controllers.G3VerificationStatus, verifiedAt *time.Time, request controllers.G3Idempotency) (controllers.G3ApplicationDomainFact, bool, error) {
	value, replay, err := a.store.SetApplicationDomainVerification(ctx, applicationID, domainID, postgres.G3VerificationStatus(status), verifiedAt, g3PostgresIdempotency(request))
	return g3ApplicationFact(value), replay, g3StoreAdapterError(err)
}
func (a *g3PostgresAdapter) BeginDomainUnbind(ctx context.Context, applicationID, domainID domain.ID, actor string, request controllers.G3Idempotency) (controllers.G3DomainUnbindOperation, bool, error) {
	intent, replay, err := a.store.BeginDomainUnbind(ctx, applicationID, domainID, actor, request.Key, time.Now().UTC())
	if err != nil {
		if errors.Is(err, postgres.ErrDomainConvergenceConflict) {
			return controllers.G3DomainUnbindOperation{}, false, controllers.ErrG3AccessConflict
		}
		return controllers.G3DomainUnbindOperation{}, false, g3StoreAdapterError(err)
	}
	if intent.Request.ApplicationID != applicationID || intent.Request.ApplicationDomainID != domainID {
		return controllers.G3DomainUnbindOperation{}, false, controllers.ErrG3AccessConflict
	}
	return controllers.G3DomainUnbindOperation{ID: intent.Request.ID, Status: g3UnbindOperationStatus(intent.Request.Phase, intent.Request.Status), DomainID: domainID}, replay, nil
}

func g3UnbindOperationStatus(phase postgres.DomainConvergencePhase, status postgres.DomainConvergenceStatus) string {
	if phase == postgres.DomainConvergenceCompleted && status == postgres.DomainConvergenceCompletedStatus {
		return "completed"
	}
	if phase == postgres.DomainConvergenceFailed && status == postgres.DomainConvergenceFailedStatus {
		return "failed"
	}
	if status == postgres.DomainConvergenceLeased || status == postgres.DomainConvergenceRecoveryStatus || phase == postgres.DomainConvergenceUnbindRouteRemoved {
		return "in_progress"
	}
	return "queued"
}
func (a *g3PostgresAdapter) ApplicationAccessFacts(ctx context.Context, applicationID domain.ID) (controllers.G3ApplicationAccessFacts, error) {
	facts, err := a.store.ApplicationAccessFacts(ctx, applicationID)
	result := controllers.G3ApplicationAccessFacts{Runtime: controllers.G3RuntimeFact{RuntimeReady: facts.Runtime.RuntimeReady, IPFallback: facts.Runtime.IPFallback}, Routes: make([]controllers.G3RouteFact, 0, len(facts.Routes))}
	for _, route := range facts.Routes {
		result.Routes = append(result.Routes, controllers.G3RouteFact{ID: route.ID, DomainID: route.DomainID, Hostname: route.Hostname, Desired: route.Desired, Serving: route.Serving, Certificate: g3ControllerCertificate(route.Certificate)})
	}
	return result, g3StoreAdapterError(err)
}

func g3PlatformFact(value postgres.G3PlatformDomainFact) controllers.G3PlatformDomainFact {
	return controllers.G3PlatformDomainFact{ID: value.ID, BaseDomain: value.BaseDomain, VerificationRef: value.VerificationRef, VerificationStatus: controllers.G3VerificationStatus(value.VerificationStatus), VerifiedAt: value.VerifiedAt, Certificate: g3ControllerCertificate(value.Certificate), CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt}
}
func g3ApplicationFact(value postgres.G3ApplicationDomainFact) controllers.G3ApplicationDomainFact {
	return controllers.G3ApplicationDomainFact{ID: value.ID, ApplicationID: value.ApplicationID, Hostname: value.Hostname, Kind: value.Kind, CNAME: value.CNAME, VerificationStatus: controllers.G3VerificationStatus(value.VerificationStatus), VerifiedAt: value.VerifiedAt, Certificate: g3ControllerCertificate(value.Certificate), Serving: value.Serving, RouteID: value.RouteID, ConvergencePhase: value.ConvergencePhase, ConvergenceStatus: value.ConvergenceStatus, ConvergenceError: value.ConvergenceError, ConvergenceID: value.ConvergenceID, ConvergenceKind: value.ConvergenceKind, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt}
}
func g3ControllerCertificate(value *postgres.G3CertificateFact) *controllers.G3CertificateFact {
	if value == nil {
		return nil
	}
	return &controllers.G3CertificateFact{ID: value.ID, Status: value.Status, Subject: value.Subject, NotAfter: value.NotAfter, Observed: value.Observed}
}
func g3PostgresCertificate(value *controllers.G3CertificateFact) *postgres.G3CertificateFact {
	if value == nil {
		return nil
	}
	return &postgres.G3CertificateFact{ID: value.ID, Status: value.Status, Subject: value.Subject, NotAfter: value.NotAfter, Observed: value.Observed}
}
func g3StoreAdapterError(err error) error {
	if errors.Is(err, postgres.ErrG3AccessConflict) {
		return controllers.ErrG3AccessConflict
	}
	if errors.Is(err, postgres.ErrIdempotencyConflict) || errors.Is(err, postgres.ErrIdempotencyInProgress) {
		return controllers.ErrG3IdempotencyConflict
	}
	return err
}

func g3PostgresIdempotency(request controllers.G3Idempotency) postgres.G3Idempotency {
	return postgres.G3Idempotency{Scope: request.Scope, Key: request.Key, Digest: request.Digest}
}

var _ controllers.G3AccessStore = (*g3PostgresAdapter)(nil)

func newG3AccessHTTPHandler(store *postgres.Store, getenv func(string) string) *G3AccessHTTPHandler {
	config := controllers.G3AccessConfig{
		ExpectedPublicIP:   strings.TrimSpace(getenv("OPEN_CARD_G3_EXPECTED_PUBLIC_IP")),
		ConsoleLabel:       strings.TrimSpace(getenv("OPEN_CARD_G3_CONSOLE_LABEL")),
		IngressLabel:       strings.TrimSpace(getenv("OPEN_CARD_G3_INGRESS_LABEL")),
		AppsLabel:          strings.TrimSpace(getenv("OPEN_CARD_G3_APPS_LABEL")),
		WildcardProbeLabel: strings.TrimSpace(getenv("OPEN_CARD_G3_WILDCARD_PROBE_LABEL")),
	}
	endpoints := g3ResolverEndpoints(getenv("OPEN_CARD_G3_PUBLIC_DNS_RESOLVERS"))
	if len(endpoints) > 0 {
		if verifier, err := publicdns.New(publicdns.Config{ResolverEndpoints: endpoints}); err == nil {
			config.PublicDNSVerifier = verifier
		} else {
			log.Printf("G3 public DNS verifier is unavailable: %v", err)
		}
	}
	return &G3AccessHTTPHandler{Controller: &controllers.G3AccessController{Store: &g3PostgresAdapter{store: store}, Config: config}}
}

func g3ResolverEndpoints(raw string) []string {
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			result = append(result, value)
		}
	}
	return result
}
