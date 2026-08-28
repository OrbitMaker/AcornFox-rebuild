package main

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// m4LifecycleOutboxStore is intentionally separate from the global outbox
// publisher. M4 webhook dispatch keeps endpoint-local durable receipts and
// never marks an SSE event as globally published.
type m4LifecycleOutboxStore interface {
	ListPendingWebhookLifecycleEvents(context.Context, int) ([]postgres.WebhookLifecycleEvent, error)
	MarkWebhookLifecycleDispatched(context.Context, string, domain.ID, time.Time) (bool, error)
}

// M4NotificationOutboxWorker converts durable operation lifecycle events into
// ledger reservations. It does no network work itself; the notification
// controller's separately leased worker resolves the short-lived signing key
// and performs bounded retries after this handoff.
type M4NotificationOutboxWorker struct {
	Store      m4LifecycleOutboxStore
	Dispatcher *M4OperationNotificationDispatcher
	Clock      func() time.Time
}

func (w *M4NotificationOutboxWorker) ProcessOnce(ctx context.Context, limit int) (int, error) {
	if w == nil || w.Store == nil || w.Dispatcher == nil {
		return 0, errors.New("M4 notification outbox worker dependencies are incomplete")
	}
	if limit <= 0 || limit > 100 {
		return 0, domain.ValidationError("M4 notification outbox worker limit must be between 1 and 100")
	}
	items, err := w.Store.ListPendingWebhookLifecycleEvents(ctx, limit)
	if err != nil {
		return 0, err
	}
	processed := 0
	for _, item := range items {
		if err := w.process(ctx, item); err != nil {
			return processed, err
		}
		processed++
	}
	return processed, nil
}

func (w *M4NotificationOutboxWorker) process(ctx context.Context, item postgres.WebhookLifecycleEvent) error {
	if strings.TrimSpace(item.OutboxEventID) == "" || item.OperationID.Empty() || item.ApplicationID.Empty() || item.EnvironmentID.Empty() || item.Endpoint.ID.Empty() {
		return domain.ValidationError("M4 webhook lifecycle projection is incomplete")
	}
	kind, err := m4MapOperationLifecycleKind(M4OperationLifecycleKind(item.Kind), item.Status)
	if err != nil {
		return err
	}
	// An endpoint opts into canonical notification lifecycle types. A record
	// outside that opt-in is intentionally consumed with a receipt: re-enabling
	// or editing a subscription must not backfill historic incidents silently.
	if !m4LifecycleEndpointWants(item.Endpoint.EventTypes, kind) {
		_, err := w.Store.MarkWebhookLifecycleDispatched(ctx, item.OutboxEventID, item.Endpoint.ID, w.now())
		return err
	}
	secret := domain.SecretReference{ID: item.Endpoint.SecretReferenceID, Name: item.Endpoint.SecretName, Provider: item.Endpoint.SecretProvider, Version: item.Endpoint.SecretVersion}
	if err := secret.Validate(); err != nil || secret.ID != item.Endpoint.SecretReferenceID {
		return domain.ValidationError("M4 webhook lifecycle secret reference did not resolve")
	}
	event := M4OperationLifecycleEvent{EventID: item.EventID, ApplicationID: item.ApplicationID, EnvironmentID: item.EnvironmentID, OperationID: item.OperationID, Kind: M4OperationLifecycleKind(item.Kind), Status: item.Status, Message: item.Message, OccurredAt: item.OccurredAt}
	endpoint := controllers.M4WebhookEndpoint{ID: item.Endpoint.ID.String(), URL: item.Endpoint.URL, Enabled: item.Endpoint.Enabled, SecretRef: secret}
	if _, err := w.Dispatcher.Dispatch(ctx, M4OperationLifecycleDispatchRequest{Event: event, Endpoint: endpoint, Actor: "m4-notification-outbox"}); err != nil {
		return err
	}
	_, err = w.Store.MarkWebhookLifecycleDispatched(ctx, item.OutboxEventID, item.Endpoint.ID, w.now())
	return err
}

func m4LifecycleEndpointWants(eventTypes []string, kind controllers.M4NotificationKind) bool {
	want := "notification." + string(kind)
	for _, eventType := range eventTypes {
		if strings.TrimSpace(eventType) == want {
			return true
		}
	}
	return false
}

func (w *M4NotificationOutboxWorker) now() time.Time {
	if w.Clock == nil {
		return time.Now().UTC()
	}
	return w.Clock().UTC()
}
