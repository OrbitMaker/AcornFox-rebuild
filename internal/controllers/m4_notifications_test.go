package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

func TestM4WebhookEndpointUsesStableLowercaseJSONContract(t *testing.T) {
	encoded, err := json.Marshal(M4WebhookEndpoint{ID: "webhook_1", URL: "https://fixture.test/events", SecretRef: domain.SecretReference{ID: "secret_1", Name: "webhook", Provider: "filesystem", Version: "v1"}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, field := range []string{`"id":"webhook_1"`, `"url":"https://fixture.test/events"`, `"secret_ref":`, `"enabled":true`} {
		if !strings.Contains(text, field) {
			t.Fatalf("webhook endpoint JSON omitted %s: %s", field, text)
		}
	}
	for _, legacy := range []string{`"ID":`, `"URL":`, `"SecretRef":`, `"Enabled":`} {
		if strings.Contains(text, legacy) {
			t.Fatalf("webhook endpoint leaked Go field name %s: %s", legacy, text)
		}
	}
}

type m4NotificationStoreRecord struct {
	digest   string
	delivery M4NotificationDelivery
}

type m4NotificationStore struct {
	mu       sync.Mutex
	byKey    map[string]m4NotificationStoreRecord
	byID     map[string]string
	byEvent  map[string]string
	attempts []M4NotificationAttempt
}

func (s *m4NotificationStore) ReserveM4Notification(_ context.Context, request M4NotificationReservationRequest) (M4NotificationReservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byKey == nil {
		s.byKey, s.byID, s.byEvent = map[string]m4NotificationStoreRecord{}, map[string]string{}, map[string]string{}
	}
	if previous, exists := s.byKey[request.Delivery.IdempotencyKey]; exists {
		if previous.digest != request.Delivery.RequestDigest {
			return M4NotificationReservation{}, application.ErrIdempotencyConflict
		}
		return M4NotificationReservation{Delivery: cloneM4Delivery(previous.delivery), Replay: true}, nil
	}
	eventKey := request.Delivery.Endpoint.ID + "\x00" + request.Delivery.EventID.String()
	if identifier, exists := s.byEvent[eventKey]; exists {
		existing := s.byKey[s.byID[identifier]]
		s.byKey[request.Delivery.IdempotencyKey] = m4NotificationStoreRecord{digest: request.Delivery.RequestDigest, delivery: existing.delivery}
		return M4NotificationReservation{Delivery: cloneM4Delivery(existing.delivery), Replay: true}, nil
	}
	stored := cloneM4Delivery(request.Delivery)
	s.byKey[stored.IdempotencyKey] = m4NotificationStoreRecord{digest: stored.RequestDigest, delivery: stored}
	s.byID[stored.ID] = stored.IdempotencyKey
	s.byEvent[eventKey] = stored.ID
	return M4NotificationReservation{Delivery: cloneM4Delivery(stored)}, nil
}

func (s *m4NotificationStore) ClaimDueM4Notifications(_ context.Context, worker string, now time.Time, limit int) ([]M4NotificationDelivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]M4NotificationDelivery, 0, limit)
	for key, record := range s.byKey {
		delivery := record.delivery
		if delivery.Status != M4NotificationPending || (!delivery.NextAttemptAt.IsZero() && delivery.NextAttemptAt.After(now)) || delivery.LeaseOwner != "" {
			continue
		}
		delivery.LeaseOwner, delivery.LeaseUntil = worker, now.Add(time.Minute)
		record.delivery = delivery
		s.byKey[key] = record
		result = append(result, cloneM4Delivery(delivery))
		if len(result) == limit {
			break
		}
	}
	return result, nil
}

func (s *m4NotificationStore) AppendM4NotificationAttempt(_ context.Context, attempt M4NotificationAttempt) (M4NotificationDelivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, exists := s.byID[attempt.DeliveryID]
	if !exists {
		return M4NotificationDelivery{}, errors.New("unknown delivery")
	}
	record := s.byKey[key]
	if record.delivery.EventID != attempt.EventID || attempt.Attempt != record.delivery.Attempts+1 || attempt.LeaseOwner == "" || attempt.LeaseOwner != record.delivery.LeaseOwner {
		return M4NotificationDelivery{}, errors.New("invalid notification attempt")
	}
	record.delivery.Attempts, record.delivery.Status, record.delivery.NextAttemptAt = attempt.Attempt, attempt.Status, attempt.NextAttemptAt
	record.delivery.Failure, record.delivery.LeaseOwner, record.delivery.LeaseUntil = attempt.Failure, "", time.Time{}
	s.byKey[key] = record
	s.attempts = append(s.attempts, attempt)
	return cloneM4Delivery(record.delivery), nil
}

type m4NotificationResolver struct {
	provider  contracts.NotificationProvider
	err       error
	endpoints []M4WebhookEndpoint
}

func (r *m4NotificationResolver) ResolveWebhookNotificationProvider(_ context.Context, endpoint M4WebhookEndpoint, _ contracts.OperationContext) (contracts.NotificationProvider, error) {
	r.endpoints = append(r.endpoints, endpoint)
	return r.provider, r.err
}

type m4NotificationSender struct {
	mu      sync.Mutex
	calls   []contracts.Notification
	results []error
}

func (s *m4NotificationSender) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "m4-test-notify", Version: "m4", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilityNotification)}
}
func (s *m4NotificationSender) Send(_ context.Context, notification contracts.Notification, _ contracts.OperationContext) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, notification)
	if len(s.results) == 0 {
		return nil
	}
	result := s.results[0]
	s.results = s.results[1:]
	return result
}
func (s *m4NotificationSender) Test(context.Context, contracts.OperationContext) error { return nil }

func m4NotificationEndpoint() M4WebhookEndpoint {
	return M4WebhookEndpoint{ID: "endpoint_m4", URL: "https://hooks.example.test/open-card", Enabled: true, SecretRef: domain.SecretReference{ID: "secret_webhook", Name: "webhook_signing", Provider: "secret-provider", Version: "v1"}}
}
func m4NotificationRequest(key string, kind M4NotificationKind, at time.Time) M4NotificationRequest {
	return M4NotificationRequest{Endpoint: m4NotificationEndpoint(), Event: M4NotificationEvent{ApplicationID: "app_m4", EnvironmentID: "env_m4", IncidentID: "incident_1", Kind: kind, Severity: "warning", Message: "runtime token=canary-secret failed", OccurredAt: at}, IdempotencyKey: key, Actor: "controller_m4"}
}
func newM4NotificationController(now *time.Time, sender *m4NotificationSender) (*M4NotificationController, *m4NotificationStore, *m4NotificationResolver) {
	store := &m4NotificationStore{}
	resolver := &m4NotificationResolver{provider: sender}
	return &M4NotificationController{Ledger: store, Resolver: resolver, Clock: func() time.Time { return *now }}, store, resolver
}

func TestM4NotificationOccurrenceIsCanonicalRedactedAndDeliveredOnce(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	sender := &m4NotificationSender{}
	controller, store, resolver := newM4NotificationController(&now, sender)
	request := m4NotificationRequest("occurrence-1", M4NotificationOccurrence, now)
	first, err := controller.Publish(context.Background(), request)
	if err != nil || first.Delivered || first.Status != M4NotificationPending || first.Attempts != 0 || len(sender.calls) != 0 {
		t.Fatalf("occurrence was not reserved without direct delivery: %#v %v", first, err)
	}
	delivered, err := controller.RunPending(context.Background(), "worker_m4", 10)
	if err != nil || len(delivered) != 1 || !delivered[0].Delivered || delivered[0].Attempts != 1 {
		t.Fatalf("claimed occurrence did not deliver: %#v %v", delivered, err)
	}
	second := request
	second.IdempotencyKey = "occurrence-duplicate-event"
	duplicate, err := controller.Publish(context.Background(), second)
	if err != nil || !duplicate.Delivered || duplicate.EventID != first.EventID {
		t.Fatalf("same logical event was not replayed: %#v %v", duplicate, err)
	}
	if len(sender.calls) != 1 || len(store.attempts) != 1 || len(resolver.endpoints) != 1 {
		t.Fatalf("delivery was repeated: sender=%d attempts=%d resolved=%d", len(sender.calls), len(store.attempts), len(resolver.endpoints))
	}
	payload := sender.calls[0].Payload
	if payload["schema_version"] != "m4.notification.v1" || payload["kind"] != "occurrence" || strings.Contains(fmtSprint(payload), "canary-secret") || !strings.Contains(fmtSprint(payload["message"]), foundation.RedactedValue) {
		t.Fatalf("notification payload was not canonical/redacted: %#v", payload)
	}
	if resolver.endpoints[0].SecretRef != request.Endpoint.SecretRef || sender.calls[0].EventType != "notification.occurrence" {
		t.Fatalf("endpoint secret reference or event type changed: %#v %#v", resolver.endpoints[0], sender.calls[0])
	}
}

func TestM4NotificationFailureSchedulesDurableRetriesWithoutApplicationFailure(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	sender := &m4NotificationSender{results: []error{&contracts.ProviderError{Provider: "test", Code: contracts.ErrUnavailable, Message: "token=receiver-secret down", Retryable: true}, nil}}
	controller, store, _ := newM4NotificationController(&now, sender)
	reserved, err := controller.Publish(context.Background(), m4NotificationRequest("failure-1", M4NotificationEscalation, now))
	if err != nil || reserved.Delivered || reserved.Status != M4NotificationPending || reserved.Attempts != 0 || len(sender.calls) != 0 {
		t.Fatalf("failure event was not reserved: %#v %v", reserved, err)
	}
	failed, err := controller.RunPending(context.Background(), "worker_m4", 10)
	if err != nil || len(failed) != 1 {
		t.Fatalf("claimed first attempt failed unexpectedly: %#v %v", failed, err)
	}
	result := failed[0]
	if result.Delivered || result.Status != M4NotificationPending || result.Attempts != 1 || !result.NextAttemptAt.Equal(now.Add(time.Second)) || strings.Contains(result.Failure, "receiver-secret") {
		t.Fatalf("delivery failure did not become pending retry: %#v", result)
	}
	if len(store.attempts) != 1 || store.attempts[0].FailureCode != contracts.ErrUnavailable {
		t.Fatalf("failure attempt was not persisted: %#v", store.attempts)
	}
	now = result.NextAttemptAt
	pending, err := controller.RunPending(context.Background(), "worker_m4", 10)
	if err != nil || len(pending) != 1 || !pending[0].Delivered || pending[0].Attempts != 2 {
		t.Fatalf("due retry did not recover independently: %#v %v", pending, err)
	}
	if len(sender.calls) != 2 || len(store.attempts) != 2 {
		t.Fatalf("retry sends/attempts incorrect: calls=%d attempts=%d", len(sender.calls), len(store.attempts))
	}
}

func TestM4NotificationIdempotencySurvivesControllerClockReplay(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	sender := &m4NotificationSender{}
	controller, store, _ := newM4NotificationController(&now, sender)
	request := m4NotificationRequest("clock-stable", M4NotificationOccurrence, now)
	first, err := controller.Publish(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.RunPending(context.Background(), "worker_m4", 10); err != nil {
		t.Fatal(err)
	}
	// The HTTP endpoint obtains occurrence time at request handling time. A
	// client retry may therefore arrive later while still carrying the exact
	// same idempotency key and all caller-supplied lifecycle facts.
	now = now.Add(2 * time.Second)
	replayRequest := request
	replayRequest.Event.OccurredAt = now
	replayed, err := controller.Publish(context.Background(), replayRequest)
	if err != nil || !replayed.Delivered || replayed.EventID != first.EventID || len(sender.calls) != 1 || len(store.attempts) != 1 {
		t.Fatalf("clock-only retry did not replay the original delivery: first=%#v replay=%#v sends=%d attempts=%d err=%v", first, replayed, len(sender.calls), len(store.attempts), err)
	}
}

func TestM4NotificationRetryDelaysAreDurableOneFiveThirtySeconds(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	for attempt, delay := range []time.Duration{time.Second, 5 * time.Second, 30 * time.Second} {
		status, next := m4NotificationRetryStatus(attempt+1, now)
		if status != M4NotificationPending || !next.Equal(now.Add(delay)) {
			t.Fatalf("attempt %d: %s %s", attempt+1, status, next)
		}
	}
	if status, next := m4NotificationRetryStatus(4, now); status != M4NotificationFailed || !next.IsZero() {
		t.Fatalf("max attempts: %s %s", status, next)
	}
}

func TestM4NotificationSeparatesLifecycleKindsAndRejectsRawPrivateKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	sender := &m4NotificationSender{}
	controller, _, _ := newM4NotificationController(&now, sender)
	occurrence, err := controller.Publish(context.Background(), m4NotificationRequest("kind-occurrence", M4NotificationOccurrence, now))
	if err != nil {
		t.Fatal(err)
	}
	recoveryRequest := m4NotificationRequest("kind-recovery", M4NotificationRecovery, now)
	recovery, err := controller.Publish(context.Background(), recoveryRequest)
	if err != nil || occurrence.EventID == recovery.EventID {
		t.Fatalf("recovery was not a distinct lifecycle event: occurrence=%#v recovery=%#v err=%v", occurrence, recovery, err)
	}
	if _, err := controller.RunPending(context.Background(), "worker_m4", 10); err != nil {
		t.Fatal(err)
	}
	if len(sender.calls) != 2 || !notificationTypePresent(sender.calls, "notification.occurrence") || !notificationTypePresent(sender.calls, "notification.recovery") {
		t.Fatalf("lifecycle events were not delivered through claimed worker: %#v", sender.calls)
	}
	privateKey := m4NotificationRequest("raw-key", M4NotificationOccurrence, now)
	privateKey.Event.IncidentID = "incident_key"
	privateKey.Event.Message = "-----BEGIN PRIVATE KEY-----\nraw\n-----END PRIVATE KEY-----"
	if _, err := controller.Publish(context.Background(), privateKey); err != nil {
		t.Fatalf("canonical redaction should not block notification: %v", err)
	}
	if _, err := controller.RunPending(context.Background(), "worker_m4", 10); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmtSprint(sender.calls[2].Payload), "PRIVATE KEY") || sender.calls[2].Payload["message"] != foundation.RedactedValue {
		t.Fatalf("raw private key reached sender payload: %#v", sender.calls[2].Payload)
	}
}

func TestM4NotificationDoesNotRetryNonRetryableOrCredentialURL(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	sender := &m4NotificationSender{results: []error{&contracts.ProviderError{Provider: "test", Code: contracts.ErrForbidden, Message: "receiver rejected request", Retryable: false}}}
	controller, store, _ := newM4NotificationController(&now, sender)
	if _, err := controller.Publish(context.Background(), m4NotificationRequest("forbidden", M4NotificationOccurrence, now)); err != nil {
		t.Fatal(err)
	}
	failed, err := controller.RunPending(context.Background(), "worker_m4", 10)
	if err != nil || len(failed) != 1 {
		t.Fatalf("non-retryable failure did not run: %#v %v", failed, err)
	}
	result := failed[0]
	if result.Status != M4NotificationFailed || !result.NextAttemptAt.IsZero() || len(store.attempts) != 1 {
		t.Fatalf("non-retryable rejection entered retry schedule: %#v attempts=%#v", result, store.attempts)
	}
	unsafe := m4NotificationRequest("unsafe-url", M4NotificationOccurrence, now)
	unsafe.Endpoint.URL += "?token=secret"
	if _, err := controller.Publish(context.Background(), unsafe); err == nil {
		t.Fatal("endpoint URL query that could carry a credential was accepted")
	}
}

func fmtSprint(value any) string { return fmt.Sprintf("%#v", value) }

func notificationTypePresent(values []contracts.Notification, eventType string) bool {
	for _, value := range values {
		if value.EventType == eventType {
			return true
		}
	}
	return false
}

func cloneM4Delivery(value M4NotificationDelivery) M4NotificationDelivery {
	value.Payload = cloneM4NotificationPayload(value.Payload)
	return value
}
