package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type m4OutboxStoreFixture struct {
	items    []postgres.WebhookLifecycleEvent
	receipts [][2]string
	err      error
}

func (s *m4OutboxStoreFixture) ListPendingWebhookLifecycleEvents(_ context.Context, limit int) ([]postgres.WebhookLifecycleEvent, error) {
	if s.err != nil {
		return nil, s.err
	}
	if limit < len(s.items) {
		return append([]postgres.WebhookLifecycleEvent(nil), s.items[:limit]...), nil
	}
	return append([]postgres.WebhookLifecycleEvent(nil), s.items...), nil
}
func (s *m4OutboxStoreFixture) MarkWebhookLifecycleDispatched(_ context.Context, eventID string, endpointID domain.ID, _ time.Time) (bool, error) {
	s.receipts = append(s.receipts, [2]string{eventID, endpointID.String()})
	return true, nil
}

type m4OutboxPublisher struct {
	requests []controllers.M4NotificationRequest
	err      error
}

func (p *m4OutboxPublisher) Publish(_ context.Context, request controllers.M4NotificationRequest) (controllers.M4NotificationResult, error) {
	p.requests = append(p.requests, request)
	return controllers.M4NotificationResult{DeliveryID: "delivery_fixture"}, p.err
}

func m4OutboxLifecycle(kind, status string, eventTypes []string) postgres.WebhookLifecycleEvent {
	secret := domain.ID("secret_outbox")
	return postgres.WebhookLifecycleEvent{OutboxEventID: "evt_outbox_1", EventID: "evt_outbox_1", OperationID: "op_outbox", ApplicationID: "app_outbox", EnvironmentID: "env_outbox", Kind: kind, Status: status, Message: "recovery token=outbox-canary", OccurredAt: time.Unix(1_700_000_123, 0).UTC(), Endpoint: postgres.WebhookEndpoint{ID: "endpoint_outbox", ApplicationID: "app_outbox", URL: "https://hooks.example.test/open-card", SecretReferenceID: secret, SecretName: "webhook", SecretProvider: "fixture-secret", SecretVersion: "v1", EventTypes: eventTypes, Enabled: true}}
}

func TestM4NotificationOutboxWorkerReservesCanonicalLifecycleAndWritesReceipt(t *testing.T) {
	store := &m4OutboxStoreFixture{items: []postgres.WebhookLifecycleEvent{m4OutboxLifecycle("operations.restart.failed", "failed", []string{"notification.occurrence"})}}
	publisher := &m4OutboxPublisher{}
	dispatcher, err := NewM4OperationNotificationDispatcher(publisher)
	if err != nil {
		t.Fatal(err)
	}
	worker := &M4NotificationOutboxWorker{Store: store, Dispatcher: dispatcher, Clock: func() time.Time { return time.Unix(1_700_000_124, 0).UTC() }}
	processed, err := worker.ProcessOnce(context.Background(), 10)
	if err != nil || processed != 1 || len(store.receipts) != 1 || len(publisher.requests) != 1 {
		t.Fatalf("outbox process=%d err=%v receipts=%v requests=%#v", processed, err, store.receipts, publisher.requests)
	}
	request := publisher.requests[0]
	if request.Event.Kind != controllers.M4NotificationOccurrence || request.Event.IncidentID != "op_outbox" || request.Endpoint.SecretRef.ID != "secret_outbox" {
		t.Fatalf("unsafe lifecycle projection: %#v", request)
	}
	if request.Event.Message == "recovery token=outbox-canary" {
		t.Fatalf("outbox message did not cross canonical redaction boundary: %#v", request.Event)
	}
}

func TestM4NotificationOutboxWorkerConsumesUnsubscribedEventWithoutDelivery(t *testing.T) {
	store := &m4OutboxStoreFixture{items: []postgres.WebhookLifecycleEvent{m4OutboxLifecycle("operations.restart.recovered", "recovered", []string{"notification.occurrence"})}}
	publisher := &m4OutboxPublisher{}
	dispatcher, _ := NewM4OperationNotificationDispatcher(publisher)
	worker := &M4NotificationOutboxWorker{Store: store, Dispatcher: dispatcher}
	processed, err := worker.ProcessOnce(context.Background(), 1)
	if err != nil || processed != 1 || len(store.receipts) != 1 || len(publisher.requests) != 0 {
		t.Fatalf("unsubscribed lifecycle was not safely consumed: processed=%d err=%v receipts=%v requests=%#v", processed, err, store.receipts, publisher.requests)
	}
}

func TestM4NotificationOutboxWorkerFailsClosedBeforeReceipt(t *testing.T) {
	store := &m4OutboxStoreFixture{items: []postgres.WebhookLifecycleEvent{m4OutboxLifecycle("operations.restart.failed", "failed", []string{"notification.occurrence"})}}
	publisher := &m4OutboxPublisher{err: errors.New("ledger unavailable")}
	dispatcher, _ := NewM4OperationNotificationDispatcher(publisher)
	worker := &M4NotificationOutboxWorker{Store: store, Dispatcher: dispatcher}
	if _, err := worker.ProcessOnce(context.Background(), 1); err == nil || len(store.receipts) != 0 {
		t.Fatalf("failed lifecycle dispatch was acknowledged: err=%v receipts=%v", err, store.receipts)
	}
}

func TestM4NotificationOutboxWorkerPreservesLifecycleOrderAndStableReplayKeys(t *testing.T) {
	endpointTypes := []string{"notification.occurrence", "notification.escalation", "notification.recovery"}
	items := []postgres.WebhookLifecycleEvent{
		m4OutboxLifecycle("operations.service_restart.failed", "failed", endpointTypes),
		m4OutboxLifecycle("operations.service_restart.retry", "retry", endpointTypes),
		m4OutboxLifecycle("operations.service_restart.recovered", "recovered", endpointTypes),
	}
	for index := range items {
		items[index].OutboxEventID = "evt_outbox_" + string(rune('1'+index))
		items[index].EventID = items[index].OutboxEventID
	}
	store := &m4OutboxStoreFixture{items: items}
	publisher := &m4OutboxPublisher{}
	dispatcher, err := NewM4OperationNotificationDispatcher(publisher)
	if err != nil {
		t.Fatal(err)
	}
	worker := &M4NotificationOutboxWorker{Store: store, Dispatcher: dispatcher}
	processed, err := worker.ProcessOnce(context.Background(), len(items))
	if err != nil || processed != len(items) || len(store.receipts) != len(items) || len(publisher.requests) != len(items) {
		t.Fatalf("ordered lifecycle dispatch failed: processed=%d receipts=%v requests=%#v err=%v", processed, store.receipts, publisher.requests, err)
	}
	want := []controllers.M4NotificationKind{controllers.M4NotificationOccurrence, controllers.M4NotificationEscalation, controllers.M4NotificationRecovery}
	keys := map[string]struct{}{}
	for index, request := range publisher.requests {
		if request.Event.Kind != want[index] {
			t.Fatalf("lifecycle event %d kind=%q want=%q", index, request.Event.Kind, want[index])
		}
		if _, duplicate := keys[request.IdempotencyKey]; duplicate {
			t.Fatalf("different immutable outbox events reused an idempotency key: %#v", publisher.requests)
		}
		keys[request.IdempotencyKey] = struct{}{}
	}
	// Replaying the exact immutable event must preserve its opaque request key;
	// the durable ledger, rather than the outbox worker, then increments the
	// same logical event's received count without sending a second payload.
	first, err := m4OperationLifecycleNotification(M4OperationLifecycleDispatchRequest{Event: M4OperationLifecycleEvent{EventID: items[0].EventID, ApplicationID: items[0].ApplicationID, EnvironmentID: items[0].EnvironmentID, OperationID: items[0].OperationID, Kind: M4OperationLifecycleKind(items[0].Kind), Status: items[0].Status, Severity: "error", Message: items[0].Message, OccurredAt: items[0].OccurredAt}, Endpoint: controllers.M4WebhookEndpoint{ID: items[0].Endpoint.ID.String(), URL: items[0].Endpoint.URL, Enabled: true, SecretRef: domain.SecretReference{ID: items[0].Endpoint.SecretReferenceID, Name: items[0].Endpoint.SecretName, Provider: items[0].Endpoint.SecretProvider, Version: items[0].Endpoint.SecretVersion}}, Actor: "m4-notification-outbox"})
	if err != nil || first.IdempotencyKey != publisher.requests[0].IdempotencyKey {
		t.Fatalf("exact lifecycle replay did not preserve the durable key: first=%#v published=%#v err=%v", first, publisher.requests[0], err)
	}
}
