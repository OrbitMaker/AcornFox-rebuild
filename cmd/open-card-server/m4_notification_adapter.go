package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
	"github.com/open-card/open-card/internal/persistence/postgres"
	webhookprovider "github.com/open-card/open-card/internal/providers/notification/webhook"
)

const maxM4WebhookSecretBytes = 64 << 10

// m4WebhookProviderResolver is the restricted bridge between the durable M4
// endpoint fact and the concrete HTTP provider. Each resolve creates one
// short-lived provider with retries disabled: the controller ledger, rather
// than an in-memory HTTP client, owns the durable 1/5/30-second retry
// scheduling.
type m4WebhookProviderResolver struct {
	Secrets contracts.BuildSecretResolver

	// This flag and optional resolver exist solely for task-local HTTP tests.
	// Normal composition must leave both at their zero value.
	AllowLoopbackFixture bool
	LookupIP             func(context.Context, string) ([]net.IPAddr, error)
}

var _ controllers.M4WebhookResolver = (*m4WebhookProviderResolver)(nil)

// m4PostgresNotificationLedger persists only canonical, already-redacted
// lifecycle JSON and opaque secret IDs. It never handles signing material.
type m4PostgresNotificationLedger struct {
	store *postgres.Store
	lease time.Duration
}

var _ controllers.M4NotificationLedger = (*m4PostgresNotificationLedger)(nil)

func (a *m4PostgresNotificationLedger) ReserveM4Notification(ctx context.Context, request controllers.M4NotificationReservationRequest) (controllers.M4NotificationReservation, error) {
	if err := a.validate(); err != nil {
		return controllers.M4NotificationReservation{}, err
	}
	endpoint, err := a.endpoint(ctx, request.Delivery.Endpoint, request.Delivery.EventType)
	if err != nil {
		return controllers.M4NotificationReservation{}, err
	}
	payload, err := json.Marshal(request.Delivery.Payload)
	if err != nil {
		return controllers.M4NotificationReservation{}, errors.New("canonical notification payload could not be encoded")
	}
	stored, replay, err := a.store.ReserveWebhookDelivery(ctx, postgres.WebhookDeliveryRequest{DeliveryID: request.Delivery.ID, EndpointID: endpoint.ID, EventID: request.Delivery.EventID, EventType: request.Delivery.EventType, PayloadDigest: request.Delivery.PayloadDigest, Payload: payload, IdempotencyKey: request.Delivery.IdempotencyKey, RequestDigest: m4WebhookDigest(request.Delivery.RequestDigest), OccurredAt: request.Delivery.OccurredAt}, request.Now)
	if err != nil {
		return controllers.M4NotificationReservation{}, err
	}
	delivery, err := a.delivery(stored, request.Delivery.Endpoint)
	if err != nil {
		return controllers.M4NotificationReservation{}, err
	}
	return controllers.M4NotificationReservation{Delivery: delivery, Replay: replay}, nil
}

func (a *m4PostgresNotificationLedger) ClaimDueM4Notifications(ctx context.Context, workerID string, now time.Time, limit int) ([]controllers.M4NotificationDelivery, error) {
	if err := a.validate(); err != nil {
		return nil, err
	}
	stored, err := a.store.ClaimDueWebhookDeliveries(ctx, workerID, now, a.leaseDuration(), limit)
	if err != nil {
		return nil, err
	}
	result := make([]controllers.M4NotificationDelivery, 0, len(stored))
	for _, item := range stored {
		endpoint, err := a.endpointByID(ctx, item.EndpointID, contracts.OperationContext{IdempotencyKey: "m4-notification:" + item.DeliveryID + ":claim-reference", Actor: workerID})
		if err != nil {
			return nil, err
		}
		delivery, err := a.delivery(item, endpoint)
		if err != nil {
			return nil, err
		}
		result = append(result, delivery)
	}
	return result, nil
}

func (a *m4PostgresNotificationLedger) AppendM4NotificationAttempt(ctx context.Context, attempt controllers.M4NotificationAttempt) (controllers.M4NotificationDelivery, error) {
	if err := a.validate(); err != nil {
		return controllers.M4NotificationDelivery{}, err
	}
	stored, err := a.store.AppendWebhookDeliveryAttempt(ctx, postgres.WebhookDeliveryAttempt{DeliveryID: attempt.DeliveryID, EventID: attempt.EventID, Attempt: attempt.Attempt, LeaseOwner: attempt.LeaseOwner, At: attempt.At, Succeeded: attempt.Succeeded, Status: postgres.WebhookDeliveryStatus(attempt.Status), NextAttemptAt: attempt.NextAttemptAt, Failure: redactM4WebhookText(attempt.Failure), FailureCode: string(attempt.FailureCode)})
	if err != nil {
		return controllers.M4NotificationDelivery{}, err
	}
	endpoint, err := a.endpointByID(ctx, stored.EndpointID, contracts.OperationContext{IdempotencyKey: "m4-notification:" + stored.DeliveryID + ":append-reference", Actor: attempt.LeaseOwner})
	if err != nil {
		return controllers.M4NotificationDelivery{}, err
	}
	return a.delivery(stored, endpoint)
}

func (a *m4PostgresNotificationLedger) validate() error {
	if a == nil || a.store == nil || a.store.DB() == nil {
		return errors.New("M4 notification PostgreSQL ledger requires a store")
	}
	return nil
}
func (a *m4PostgresNotificationLedger) leaseDuration() time.Duration {
	if a.lease <= 0 {
		return 30 * time.Second
	}
	return a.lease
}

func (a *m4PostgresNotificationLedger) endpoint(ctx context.Context, value controllers.M4WebhookEndpoint, eventType string) (postgres.WebhookEndpoint, error) {
	stored, err := a.store.GetWebhookEndpoint(ctx, domain.ID(value.ID))
	if err != nil {
		return postgres.WebhookEndpoint{}, err
	}
	if !stored.Enabled || stored.URL != value.URL || stored.SecretReferenceID != value.SecretRef.ID || !m4WebhookEventAllowed(stored.EventTypes, eventType) {
		return postgres.WebhookEndpoint{}, domain.ValidationError("notification endpoint does not match durable configuration")
	}
	return stored, nil
}

func (a *m4PostgresNotificationLedger) endpointByID(ctx context.Context, id domain.ID, operation contracts.OperationContext) (controllers.M4WebhookEndpoint, error) {
	_ = operation
	stored, err := a.store.GetWebhookEndpoint(ctx, id)
	if err != nil {
		return controllers.M4WebhookEndpoint{}, err
	}
	reference := domain.SecretReference{ID: stored.SecretReferenceID, Name: stored.SecretName, Provider: stored.SecretProvider, Version: stored.SecretVersion}
	if err := reference.Validate(); err != nil || reference.ID != stored.SecretReferenceID {
		return controllers.M4WebhookEndpoint{}, domain.ValidationError("durable webhook secret reference did not resolve")
	}
	return controllers.M4WebhookEndpoint{ID: stored.ID.String(), URL: stored.URL, SecretRef: reference, Enabled: stored.Enabled}, nil
}

func (a *m4PostgresNotificationLedger) delivery(stored postgres.WebhookEventLedger, endpoint controllers.M4WebhookEndpoint) (controllers.M4NotificationDelivery, error) {
	var payload map[string]any
	if err := json.Unmarshal(stored.Payload, &payload); err != nil {
		return controllers.M4NotificationDelivery{}, errors.New("durable webhook payload is invalid")
	}
	status, err := m4ControllerNotificationStatus(stored.Status)
	if err != nil {
		return controllers.M4NotificationDelivery{}, err
	}
	next := time.Time{}
	if stored.NextAttemptAt != nil {
		next = stored.NextAttemptAt.UTC()
	}
	return controllers.M4NotificationDelivery{ID: stored.DeliveryID, Endpoint: endpoint, EventID: stored.EventID, EventType: stored.EventType, Payload: payload, PayloadDigest: stored.PayloadDigest, OccurredAt: stored.OccurredAt.UTC(), Status: status, Attempts: stored.AttemptCount, NextAttemptAt: next, LeaseOwner: stored.LeaseOwner, IdempotencyKey: stored.IdempotencyKey, RequestDigest: strings.TrimPrefix(stored.RequestDigest, "sha256:")}, nil
}

func m4ControllerNotificationStatus(value postgres.WebhookDeliveryStatus) (controllers.M4NotificationStatus, error) {
	switch value {
	case postgres.WebhookDeliveryPending, postgres.WebhookDeliveryRetryWait:
		return controllers.M4NotificationPending, nil
	case postgres.WebhookDeliveryDelivered:
		return controllers.M4NotificationDelivered, nil
	case postgres.WebhookDeliveryFailed:
		return controllers.M4NotificationFailed, nil
	default:
		return "", domain.ValidationError("durable webhook delivery status is invalid")
	}
}
func m4WebhookEventAllowed(values []string, eventType string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == eventType {
			return true
		}
	}
	return false
}
func m4WebhookDigest(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "sha256:") {
		return value
	}
	return "sha256:" + value
}

func (r *m4WebhookProviderResolver) ResolveWebhookNotificationProvider(ctx context.Context, endpoint controllers.M4WebhookEndpoint, operation contracts.OperationContext) (contracts.NotificationProvider, error) {
	if r == nil || r.Secrets == nil {
		return nil, errors.New("M4 webhook resolver requires a material resolver")
	}
	if err := endpoint.SecretRef.Validate(); err != nil {
		return nil, domain.ValidationError("webhook endpoint opaque secret reference is invalid")
	}
	reference := endpoint.SecretRef
	if err := reference.Validate(); err != nil || reference.ID != endpoint.SecretRef.ID {
		return nil, domain.ValidationError("webhook secret reference did not match endpoint opaque id")
	}
	material, err := r.Secrets.ResolveBuildSecret(ctx, reference, operation)
	if err != nil {
		return nil, redactM4WebhookError("resolve webhook secret material", err)
	}
	defer func() {
		_ = r.Secrets.RevokeBuildSecret(context.Background(), material, contracts.OperationContext{IdempotencyKey: operation.IdempotencyKey + ":revoke", Actor: operation.Actor})
	}()
	if material.Reference.ID != reference.ID || strings.TrimSpace(material.Path) == "" {
		return nil, errors.New("webhook secret material did not match requested reference")
	}
	contents, err := os.ReadFile(material.Path)
	if err != nil {
		return nil, errors.New("webhook secret material could not be read")
	}
	defer zeroM4WebhookBytes(contents)
	if len(contents) == 0 || len(contents) > maxM4WebhookSecretBytes {
		return nil, errors.New("webhook signing secret is invalid")
	}
	secret := string(bytes.TrimSpace(contents))
	if secret == "" {
		return nil, errors.New("webhook signing secret is invalid")
	}
	provider, err := webhookprovider.New(webhookprovider.Config{Endpoint: endpoint.URL, Secret: secret, RetryDelays: []time.Duration{}, AllowLoopbackFixture: r.AllowLoopbackFixture, LookupIP: r.LookupIP})
	if err != nil {
		return nil, redactM4WebhookError("initialize webhook provider", err)
	}
	return provider, nil
}

func zeroM4WebhookBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func redactM4WebhookError(action string, err error) error {
	if err == nil {
		return nil
	}
	// The full underlying error may include filesystem/provider detail. Keep
	// errors useful to the worker without making secret material observable.
	return fmt.Errorf("%s failed: %s", action, redactM4WebhookText(err.Error()))
}

func redactM4WebhookText(value string) string {
	value = foundation.RedactText(strings.TrimSpace(value))
	upper := strings.ToUpper(value)
	if strings.Contains(upper, "PRIVATE KEY") || strings.Contains(upper, "BEGIN") {
		return "[REDACTED]"
	}
	return strings.ReplaceAll(value, "\n", " ")
}
