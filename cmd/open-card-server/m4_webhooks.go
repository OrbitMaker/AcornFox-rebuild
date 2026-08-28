package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
)

const m4WebhooksSuffix = "/webhooks"

// m4WebhookConfigurationStore persists an endpoint's opaque SecretReference
// metadata only. It intentionally has no plaintext secret read/write method.
type m4WebhookConfigurationStore interface {
	ConfigureM4Webhook(context.Context, domain.ID, string, domain.SecretReference, []string, string) (controllers.M4WebhookEndpoint, error)
	GetM4Webhook(context.Context, domain.ID, domain.ID) (controllers.M4WebhookEndpoint, error)
}

type m4WebhookNotificationPublisher interface {
	Publish(context.Context, controllers.M4NotificationRequest) (controllers.M4NotificationResult, error)
}

type M4WebhookHTTPHandler struct {
	Store         m4WebhookConfigurationStore
	Notifications m4WebhookNotificationPublisher
	Environments  m4DefaultEnvironmentReader
	Clock         func() time.Time
}

type m4WebhookInput struct {
	URL        string                 `json:"url"`
	SecretRef  domain.SecretReference `json:"secret_ref"`
	EventTypes []string               `json:"event_types"`
}

// HandleApplication owns only exact task API paths. It runs before the
// generic application handler so its response cannot be mistaken for an
// application update or a secret-management endpoint.
func (h *M4WebhookHTTPHandler) HandleApplication(writer http.ResponseWriter, request *http.Request) bool {
	if !strings.HasPrefix(request.URL.Path, apiPrefix+"applications/") {
		return false
	}
	path := strings.TrimPrefix(request.URL.Path, apiPrefix+"applications/")
	index := strings.Index(path, m4WebhooksSuffix)
	if index <= 0 || !strings.HasPrefix(path[index:], m4WebhooksSuffix) {
		return false
	}
	applicationID := domain.ID(path[:index])
	remainder := strings.TrimPrefix(path[index:], m4WebhooksSuffix)
	if domain.RequireID(applicationID, "M4 webhook application id") != nil || (remainder != "" && !strings.HasPrefix(remainder, "/")) {
		writeJSONError(writer, http.StatusBadRequest, "validation_failed", "application ID is required")
		return true
	}
	if h == nil || h.Store == nil || h.Notifications == nil || h.Environments == nil {
		writeJSONError(writer, http.StatusServiceUnavailable, "m4_webhooks_unavailable", "M4 webhook operations are not configured")
		return true
	}
	if !m4Operator(request) {
		writeJSONError(writer, http.StatusForbidden, "forbidden", "webhook configuration requires operator role")
		return true
	}
	actor := m4Actor(request)
	key := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if actor == "" || key == "" {
		writeJSONError(writer, http.StatusBadRequest, "validation_failed", "Idempotency-Key is required")
		return true
	}
	if remainder == "" {
		h.configure(writer, request, applicationID, actor)
		return true
	}
	parts := strings.Split(strings.TrimPrefix(remainder, "/"), "/")
	if len(parts) == 2 && parts[1] == "test" {
		h.test(writer, request, applicationID, domain.ID(parts[0]), actor, key)
		return true
	}
	writeJSONError(writer, http.StatusNotFound, "not_found", "M4 webhook route not found")
	return true
}

func (h *M4WebhookHTTPHandler) configure(writer http.ResponseWriter, request *http.Request, applicationID domain.ID, actor string) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST, OPTIONS")
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "webhook configuration requires POST")
		return
	}
	if !strings.HasPrefix(strings.ToLower(request.Header.Get("Content-Type")), "application/json") {
		writeJSONError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	var input m4WebhookInput
	if err := decoder.Decode(&input); err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_json", "request body must be one JSON object with known fields")
		return
	}
	var trailing any
	if decoder.Decode(&trailing) == nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_json", "request body must contain one JSON object")
		return
	}
	if err := input.SecretRef.Validate(); err != nil || !m4WebhookEventTypesAllowed(input.EventTypes) {
		writeJSONError(writer, http.StatusBadRequest, "validation_failed", "webhook requires an opaque SecretReference and supported notification event types")
		return
	}
	endpoint, err := h.Store.ConfigureM4Webhook(request.Context(), applicationID, strings.TrimSpace(input.URL), input.SecretRef, input.EventTypes, actor)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"endpoint": endpoint})
}

func (h *M4WebhookHTTPHandler) test(writer http.ResponseWriter, request *http.Request, applicationID, endpointID domain.ID, actor, key string) {
	if request.Method != http.MethodPost || endpointID.Empty() {
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "webhook test requires POST and endpoint ID")
		return
	}
	endpoint, err := h.Store.GetM4Webhook(request.Context(), applicationID, endpointID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	environmentID, err := h.Environments.GetDefaultEnvironmentID(request.Context(), applicationID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	now := time.Now().UTC()
	if h.Clock != nil {
		now = h.Clock().UTC()
	}
	result, err := h.Notifications.Publish(request.Context(), controllers.M4NotificationRequest{Endpoint: endpoint, Event: controllers.M4NotificationEvent{ApplicationID: applicationID, EnvironmentID: environmentID, IncidentID: m4WebhookTestIncidentID(endpointID, key), Kind: controllers.M4NotificationOccurrence, Severity: "info", Message: "Operator requested a webhook connectivity test.", OccurredAt: now}, IdempotencyKey: "m4-webhook-test:" + key, Actor: actor})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"delivery": result})
}

// m4WebhookTestIncidentID keeps one operator test's logical event stable
// across retries while preventing two independently keyed tests made in the
// same second from colliding in the receiver-visible event ID. The raw HTTP
// Idempotency-Key never becomes webhook payload data.
func m4WebhookTestIncidentID(endpointID domain.ID, key string) string {
	sum := sha256.Sum256([]byte(endpointID.String() + "\x00" + strings.TrimSpace(key)))
	return "webhook-test-" + hex.EncodeToString(sum[:12])
}

func m4WebhookEventTypesAllowed(eventTypes []string) bool {
	if len(eventTypes) == 0 || len(eventTypes) > 3 {
		return false
	}
	seen := map[string]struct{}{}
	for _, eventType := range eventTypes {
		value := strings.TrimSpace(eventType)
		if value != "notification.occurrence" && value != "notification.escalation" && value != "notification.recovery" {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
