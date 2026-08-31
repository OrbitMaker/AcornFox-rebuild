package healthcheck

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const (
	webhookDispatchPayloadSchema = "open_card.host_alert_webhook.notification.v1"
	webhookDispatchEventType     = "system.host_health"
	webhookDispatchActor         = "system-healthcheck"
	webhookDispatchAttemptLimit  = 30 * time.Second
)

// ErrWebhookDispatch is intentionally the sole dispatcher error exposed to a
// caller. Store, resolver, provider, and acknowledgement details may include
// infrastructure-specific material and are represented durably only by the
// bounded delivery status.
var ErrWebhookDispatch = errors.New("webhook dispatch failed")

// WebhookDeliveryStore is the narrow durable boundary required by the
// dispatcher. WebhookFileStore implements it; a task fake can prove ordering
// without reading a production configuration or resolving a secret.
type WebhookDeliveryStore interface {
	BeginDelivery(WebhookConfigV1, WebhookDeliveryEventV1, time.Time) (DeliveryHealthV1, error)
	RecordDeliveryAttempt(WebhookConfigV1, WebhookDeliveryEventV1, int64, time.Time, WebhookDeliveryAttemptResult) (DeliveryHealthV1, error)
}

// WebhookProviderResolver composes an opaque validated configuration with the
// secret-owning provider boundary. It returns a NotificationProvider capability
// rather than webhook material.
type WebhookProviderResolver interface {
	ResolveWebhookNotificationProvider(context.Context, WebhookConfigV1, contracts.OperationContext) (contracts.NotificationProvider, error)
}

// WebhookIncidentAcknowledger persists acknowledgement only for an exact
// pending event. TaskHostCollector implements this interface.
type WebhookIncidentAcknowledger interface {
	AcknowledgeEvent(WebhookDeliveryEventV1) (IncidentState, error)
}

// WebhookDispatcher coordinates one durable host-health event. It deliberately
// has no filesystem, secret, process, or network construction logic; those
// concerns remain behind the injected boundaries.
type WebhookDispatcher struct {
	mu           sync.Mutex
	Store        WebhookDeliveryStore
	Resolver     WebhookProviderResolver
	Acknowledger WebhookIncidentAcknowledger
	Clock        func() time.Time
}

// Dispatch records an accepted event before any resolution or send attempt.
// A delivered event observed after a crash is acknowledged without sending it
// again. Failures are durably classified but never expose their raw cause.
func (d *WebhookDispatcher) Dispatch(ctx context.Context, config WebhookConfigV1, incident IncidentState) (DeliveryHealthV1, error) {
	if d == nil || d.Store == nil || d.Resolver == nil || d.Acknowledger == nil || ctx == nil || ctx.Err() != nil || config.Validate() != nil || !config.Enabled || incident.Validate() != nil || incident.PendingNotification == "" {
		return DeliveryHealthV1{}, ErrWebhookDispatch
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return DeliveryHealthV1{}, ErrWebhookDispatch
	}
	event, err := WebhookDeliveryEventFromIncident(incident)
	if err != nil {
		return DeliveryHealthV1{}, ErrWebhookDispatch
	}
	configDigest, err := CanonicalWebhookConfigDigest(config)
	if err != nil {
		return DeliveryHealthV1{}, ErrWebhookDispatch
	}
	occurredAt, err := webhookDispatchOccurredAt(incident, event)
	if err != nil {
		return DeliveryHealthV1{}, ErrWebhookDispatch
	}
	delivery, err := d.Store.BeginDelivery(config, event, occurredAt)
	if err != nil || !webhookDispatchDeliveryMatches(delivery, event, configDigest) {
		return DeliveryHealthV1{}, ErrWebhookDispatch
	}
	if delivery.Status == WebhookDeliveryDelivered {
		if _, err := d.Acknowledger.AcknowledgeEvent(event); err != nil {
			return delivery, ErrWebhookDispatch
		}
		return delivery, nil
	}
	if delivery.Status != WebhookDeliveryPending && delivery.Status != WebhookDeliveryRetryableFailure {
		return delivery, ErrWebhookDispatch
	}

	attemptAt, err := d.attemptTime(delivery, occurredAt)
	if err != nil {
		return delivery, ErrWebhookDispatch
	}
	attempt := delivery.ConsecutiveFailureCount + 1
	operation := webhookDispatchOperation(event, delivery.Revision, attempt, attemptAt)
	attemptContext, cancel := context.WithDeadline(ctx, operation.Deadline)
	defer cancel()

	var sendErr error
	if err := attemptContext.Err(); err != nil {
		sendErr = err
	} else {
		provider, resolveErr := d.Resolver.ResolveWebhookNotificationProvider(attemptContext, config, operation)
		if resolveErr != nil {
			sendErr = resolveErr
		} else if provider == nil {
			sendErr = errors.New("webhook provider is unavailable")
		} else {
			sendErr = provider.Send(attemptContext, webhookDispatchNotification(event, incident, occurredAt), operation)
		}
	}
	result := webhookDispatchAttemptResult(sendErr)
	recorded, recordErr := d.Store.RecordDeliveryAttempt(config, event, delivery.Revision, attemptAt, result)
	if recordErr != nil || !webhookDispatchRecordedMatches(recorded, event, configDigest, delivery.Revision+1, result) {
		return DeliveryHealthV1{}, ErrWebhookDispatch
	}
	if result != WebhookDeliveryAttemptDelivered {
		return recorded, ErrWebhookDispatch
	}
	if _, err := d.Acknowledger.AcknowledgeEvent(event); err != nil {
		return recorded, ErrWebhookDispatch
	}
	return recorded, nil
}

func (d *WebhookDispatcher) attemptTime(delivery DeliveryHealthV1, occurredAt time.Time) (time.Time, error) {
	now := time.Now().UTC()
	if d.Clock != nil {
		now = d.Clock()
	}
	if !utc(now) {
		return time.Time{}, errors.New("invalid webhook dispatch clock")
	}
	at := now
	for _, floor := range []*time.Time{&occurredAt, delivery.OldestPendingAt, delivery.LastAttemptAt} {
		if floor != nil && !at.After(*floor) {
			return time.Time{}, errors.New("webhook dispatch clock did not advance")
		}
	}
	return at, nil
}

func webhookDispatchOccurredAt(incident IncidentState, event WebhookDeliveryEventV1) (time.Time, error) {
	if incident.Validate() != nil || event.Validate() != nil {
		return time.Time{}, errors.New("invalid webhook dispatch event")
	}
	switch event.PendingNotification {
	case "occurrence":
		return incident.FirstObserved, nil
	case "escalation", "recovery":
		return incident.LastObserved, nil
	default:
		return time.Time{}, errors.New("invalid webhook dispatch event")
	}
}

func webhookDispatchDeliveryMatches(delivery DeliveryHealthV1, event WebhookDeliveryEventV1, configDigest string) bool {
	return delivery.Validate() == nil && delivery.ConfigDigest == configDigest && delivery.Event != nil && sameWebhookDeliveryEvent(*delivery.Event, event)
}

func webhookDispatchRecordedMatches(delivery DeliveryHealthV1, event WebhookDeliveryEventV1, configDigest string, expectedGeneration int64, result WebhookDeliveryAttemptResult) bool {
	if !webhookDispatchDeliveryMatches(delivery, event, configDigest) || delivery.Revision != expectedGeneration {
		return false
	}
	switch result {
	case WebhookDeliveryAttemptDelivered:
		return delivery.Status == WebhookDeliveryDelivered
	case WebhookDeliveryAttemptRetryableFailure:
		return delivery.Status == WebhookDeliveryRetryableFailure
	case WebhookDeliveryAttemptFailed:
		return delivery.Status == WebhookDeliveryFailed
	default:
		return false
	}
}

func webhookDispatchAttemptResult(err error) WebhookDeliveryAttemptResult {
	if err == nil {
		return WebhookDeliveryAttemptDelivered
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return WebhookDeliveryAttemptRetryableFailure
	}
	var providerErr *contracts.ProviderError
	if errors.As(err, &providerErr) && providerErr.Retryable {
		return WebhookDeliveryAttemptRetryableFailure
	}
	return WebhookDeliveryAttemptFailed
}

func webhookDispatchNotification(event WebhookDeliveryEventV1, incident IncidentState, occurredAt time.Time) contracts.Notification {
	return contracts.Notification{
		EventID:   webhookDispatchDomainEventID(event),
		EventType: webhookDispatchEventType + "." + event.PendingNotification,
		Payload: map[string]any{
			"schema_version":     webhookDispatchPayloadSchema,
			"scope":              "system",
			"incident_id":        event.IncidentFingerprint,
			"incident_revision":  event.IncidentRevision,
			"kind":               event.PendingNotification,
			"severity":           string(incident.Severity),
			"notification_stage": event.NotificationStage,
			"occurred_at":        occurredAt.UTC().Format(time.RFC3339Nano),
		},
		OccurredAt: occurredAt,
	}
}

func webhookDispatchDomainEventID(event WebhookDeliveryEventV1) domain.ID {
	return domain.ID("host_alert_" + strings.TrimPrefix(event.EventID, "sha256:"))
}

func webhookDispatchOperation(event WebhookDeliveryEventV1, generation, attempt int64, at time.Time) contracts.OperationContext {
	return contracts.OperationContext{
		IdempotencyKey: "host-alert-webhook:" + strings.TrimPrefix(event.EventID, "sha256:") + ":" + strconv.FormatInt(generation, 10) + ":" + strconv.FormatInt(attempt, 10),
		Actor:          webhookDispatchActor,
		Deadline:       at.Add(webhookDispatchAttemptLimit),
	}
}
