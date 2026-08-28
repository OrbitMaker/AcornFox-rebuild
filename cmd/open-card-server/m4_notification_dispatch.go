package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

// M4NotificationPublisher is the narrow projection boundary used by the
// operation-event dispatcher. The durable controller implements this
// interface; keeping it here lets an outbox consumer depend on the controller
// contract without knowing its PostgreSQL ledger or secret resolver.
type M4NotificationPublisher interface {
	Publish(context.Context, controllers.M4NotificationRequest) (controllers.M4NotificationResult, error)
}

var _ M4NotificationPublisher = (*controllers.M4NotificationController)(nil)

// M4OperationLifecycleKind is the small set of lifecycle facts that may
// produce an external notification. There is intentionally no payload field:
// raw logs, command output, headers, and secret material cannot be forwarded
// by this adapter.
type M4OperationLifecycleKind string

const (
	M4OperationLifecycleFailure    M4OperationLifecycleKind = "failure"
	M4OperationLifecycleEscalation M4OperationLifecycleKind = "escalation"
	M4OperationLifecycleRetry      M4OperationLifecycleKind = "retry"
	M4OperationLifecycleRecovery   M4OperationLifecycleKind = "recovery"
)

// M4OperationLifecycleEvent is the typed projection an outbox consumer gives
// to the dispatcher. EventID must be the immutable persisted outbox/event ID;
// it is used to make duplicate replay requests share one idempotency key.
// Message is a short lifecycle summary, not a log field.
type M4OperationLifecycleEvent struct {
	EventID       string
	ApplicationID domain.ID
	EnvironmentID domain.ID
	OperationID   domain.ID
	Kind          M4OperationLifecycleKind
	Status        string
	Severity      string
	Message       string
	OccurredAt    time.Time
}

// M4OperationLifecycleDispatchRequest joins an immutable lifecycle event to
// one durable endpoint projection. Endpoint contains only an opaque
// SecretReference; plaintext signing material is never accepted here.
type M4OperationLifecycleDispatchRequest struct {
	Event    M4OperationLifecycleEvent
	Endpoint controllers.M4WebhookEndpoint
	Actor    string
}

// M4OperationNotificationDispatcher maps persisted operation events onto the
// canonical controller request. It does not deliver synchronously and does
// not swallow controller errors: Publish only reserves a durable delivery,
// while the controller's worker owns secret resolution, retry, and transport.
type M4OperationNotificationDispatcher struct {
	Publisher M4NotificationPublisher
}

// NewM4OperationNotificationDispatcher creates an outbox projection adapter.
// A nil publisher is rejected here rather than producing a partially wired
// dispatcher that could silently drop lifecycle events.
func NewM4OperationNotificationDispatcher(publisher M4NotificationPublisher) (*M4OperationNotificationDispatcher, error) {
	if publisher == nil {
		return nil, errors.New("M4 notification dispatcher requires a publisher")
	}
	return &M4OperationNotificationDispatcher{Publisher: publisher}, nil
}

// Dispatch reserves one canonical notification delivery for a lifecycle
// event. Failure maps to occurrence, escalation/retry maps to escalation, and
// recovery/success maps to recovery, matching the M4 webhook contract.
func (d *M4OperationNotificationDispatcher) Dispatch(ctx context.Context, request M4OperationLifecycleDispatchRequest) (controllers.M4NotificationResult, error) {
	if d == nil || d.Publisher == nil {
		return controllers.M4NotificationResult{}, errors.New("M4 notification dispatcher requires a publisher")
	}
	notification, err := m4OperationLifecycleNotification(request)
	if err != nil {
		return controllers.M4NotificationResult{}, err
	}
	return d.Publisher.Publish(ctx, notification)
}

// NewM4OperationLifecycleEvent projects the common application outbox event
// into the dispatcher input. application.Event does not carry an environment
// ID, so the caller must provide the environment fact from the same durable
// projection; this prevents guessing an environment from a user payload.
func NewM4OperationLifecycleEvent(event application.Event, environmentID domain.ID, severity string) (M4OperationLifecycleEvent, error) {
	if strings.TrimSpace(event.ID) == "" {
		return M4OperationLifecycleEvent{}, domain.ValidationError("operation lifecycle event id is required")
	}
	if strings.TrimSpace(event.OperationID) == "" {
		return M4OperationLifecycleEvent{}, domain.ValidationError("operation lifecycle operation id is required")
	}
	return M4OperationLifecycleEvent{
		EventID:       strings.TrimSpace(event.ID),
		ApplicationID: domain.ID(strings.TrimSpace(event.ApplicationID)),
		EnvironmentID: environmentID,
		OperationID:   domain.ID(strings.TrimSpace(event.OperationID)),
		Kind:          M4OperationLifecycleKind(strings.TrimSpace(event.Kind)),
		Status:        strings.TrimSpace(event.Status),
		Severity:      severity,
		Message:       event.Message,
		OccurredAt:    event.OccurredAt,
	}, nil
}

func m4OperationLifecycleNotification(request M4OperationLifecycleDispatchRequest) (controllers.M4NotificationRequest, error) {
	event := request.Event
	if err := validateM4OperationLifecycleEvent(event); err != nil {
		return controllers.M4NotificationRequest{}, err
	}
	if err := validateM4NotificationDispatchEndpoint(request.Endpoint); err != nil {
		return controllers.M4NotificationRequest{}, err
	}
	if strings.TrimSpace(request.Actor) == "" {
		return controllers.M4NotificationRequest{}, domain.ValidationError("operation lifecycle notification actor is required")
	}
	kind, err := m4MapOperationLifecycleKind(event.Kind, event.Status)
	if err != nil {
		return controllers.M4NotificationRequest{}, err
	}
	message, err := m4CanonicalLifecycleMessage(event.Message)
	if err != nil {
		return controllers.M4NotificationRequest{}, err
	}
	severity, err := m4CanonicalLifecycleSeverity(event.Severity, kind)
	if err != nil {
		return controllers.M4NotificationRequest{}, err
	}
	// Hashing the immutable identifiers keeps the idempotency key opaque and
	// bounded. It is stable across outbox replay and contains no event text.
	idempotencyKey := m4LifecycleIdempotencyKey(request.Endpoint.ID, event.EventID)
	return controllers.M4NotificationRequest{
		Endpoint: request.Endpoint,
		Event: controllers.M4NotificationEvent{
			ApplicationID: event.ApplicationID,
			EnvironmentID: event.EnvironmentID,
			IncidentID:    event.OperationID.String(),
			Kind:          kind,
			Severity:      severity,
			Message:       message,
			OccurredAt:    event.OccurredAt.UTC(),
		},
		IdempotencyKey: idempotencyKey,
		Actor:          strings.TrimSpace(request.Actor),
	}, nil
}

func validateM4OperationLifecycleEvent(event M4OperationLifecycleEvent) error {
	if err := requireM4LifecycleOpaqueID(event.EventID, "operation lifecycle event id"); err != nil {
		return err
	}
	if event.ApplicationID.Empty() || event.EnvironmentID.Empty() || event.OperationID.Empty() {
		return domain.ValidationError("operation lifecycle application, environment, and operation IDs are required")
	}
	identifiers := []struct {
		value domain.ID
		field string
	}{
		{value: event.ApplicationID, field: "operation lifecycle application id"},
		{value: event.EnvironmentID, field: "operation lifecycle environment id"},
		{value: event.OperationID, field: "operation lifecycle operation id"},
	}
	for _, identifier := range identifiers {
		if err := requireM4LifecycleOpaqueID(identifier.value.String(), identifier.field); err != nil {
			return err
		}
	}
	if event.OccurredAt.IsZero() {
		return domain.ValidationError("operation lifecycle occurrence time is required")
	}
	if err := validateM4LifecycleText(event.Status, "operation lifecycle status", 64, false); err != nil {
		return err
	}
	return nil
}

func validateM4NotificationDispatchEndpoint(endpoint controllers.M4WebhookEndpoint) error {
	if err := requireM4LifecycleOpaqueID(endpoint.ID, "operation lifecycle endpoint id"); err != nil {
		return err
	}
	if !endpoint.Enabled {
		return domain.ValidationError("operation lifecycle endpoint must be enabled")
	}
	if err := endpoint.SecretRef.Validate(); err != nil {
		return domain.ValidationError("operation lifecycle endpoint secret reference is invalid")
	}
	parsed, err := url.Parse(strings.TrimSpace(endpoint.URL))
	if err != nil || parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.Hostname() == "" || parsed.RawQuery != "" {
		return domain.ValidationError("operation lifecycle endpoint must be an HTTP(S) URL without credentials")
	}
	return nil
}

func requireM4LifecycleOpaqueID(value, field string) error {
	return validateM4LifecycleText(value, field, 256, true)
}

func validateM4LifecycleText(value, field string, maxBytes int, required bool) error {
	value = strings.TrimSpace(value)
	if required && value == "" {
		return domain.ValidationError(field + " is required")
	}
	if len(value) > maxBytes {
		return domain.ValidationError(field + " is too long")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return domain.ValidationError(field + " contains control characters")
		}
	}
	return nil
}

func m4MapOperationLifecycleKind(raw M4OperationLifecycleKind, status string) (controllers.M4NotificationKind, error) {
	value := strings.ToLower(strings.TrimSpace(string(raw)))
	status = strings.ToLower(strings.TrimSpace(status))
	if value == "" {
		value = status
	}
	// Outbox kinds are generally dotted (operations.redeploy.failed), while
	// direct projections may use the short names above. Retry/escalation wins
	// over failure when a compound kind explicitly says it is retrying.
	switch {
	case value == string(M4OperationLifecycleFailure), strings.HasSuffix(value, ".failure"), strings.HasSuffix(value, ".failed"), value == "failure", value == "failed":
		return controllers.M4NotificationOccurrence, nil
	case value == string(M4OperationLifecycleEscalation), strings.Contains(value, "escalat"), value == string(M4OperationLifecycleRetry), strings.Contains(value, "retry"):
		return controllers.M4NotificationEscalation, nil
	case value == string(M4OperationLifecycleRecovery), strings.Contains(value, "recover"):
		return controllers.M4NotificationRecovery, nil
	}
	// A status can be the only lifecycle signal on older outbox records.
	if value != status {
		return m4MapOperationLifecycleKind(M4OperationLifecycleKind(status), "")
	}
	return "", domain.ValidationError("operation lifecycle kind is unsupported")
}

func m4CanonicalLifecycleMessage(value string) (string, error) {
	value = foundation.RedactText(strings.TrimSpace(value))
	if value == "" {
		return "", domain.ValidationError("operation lifecycle message is required")
	}
	// A lifecycle summary is intentionally one line and bounded. Multi-line
	// command output belongs in LogStore and must never enter a webhook.
	if err := validateM4LifecycleText(value, "operation lifecycle message", 512, true); err != nil {
		return "", err
	}
	return strings.Join(strings.Fields(value), " "), nil
}

func m4CanonicalLifecycleSeverity(value string, kind controllers.M4NotificationKind) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		switch kind {
		case controllers.M4NotificationOccurrence:
			return "error", nil
		case controllers.M4NotificationEscalation:
			return "warning", nil
		case controllers.M4NotificationRecovery:
			return "info", nil
		default:
			return "", domain.ValidationError("operation lifecycle notification kind is unsupported")
		}
	}
	if err := validateM4LifecycleText(value, "operation lifecycle severity", 32, true); err != nil {
		return "", err
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return "", domain.ValidationError("operation lifecycle severity must be one token")
	}
	return value, nil
}

func m4LifecycleIdempotencyKey(endpointID, eventID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(endpointID) + "\x00" + strings.TrimSpace(eventID)))
	return "m4-operation-lifecycle:" + hex.EncodeToString(sum[:])
}
