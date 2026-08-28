package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

const (
	M4NotificationOccurrence M4NotificationKind = "occurrence"
	M4NotificationEscalation M4NotificationKind = "escalation"
	M4NotificationRecovery   M4NotificationKind = "recovery"

	M4NotificationPending   M4NotificationStatus = "pending"
	M4NotificationDelivered M4NotificationStatus = "delivered"
	M4NotificationFailed    M4NotificationStatus = "failed"
)

var m4NotificationRetryDelays = []time.Duration{time.Second, 5 * time.Second, 30 * time.Second}

// M4WebhookEndpoint is durable configuration metadata only. The signing
// secret remains a SecretReference; no controller method receives plaintext.
type M4WebhookEndpoint struct {
	ID        string                 `json:"id"`
	URL       string                 `json:"url"`
	SecretRef domain.SecretReference `json:"secret_ref"`
	Enabled   bool                   `json:"enabled"`
}

type M4NotificationKind string
type M4NotificationStatus string

// M4NotificationEvent is deliberately constrained to lifecycle facts. Raw
// logs, command output, headers, certificates, and arbitrary payload fields
// cannot enter a notification request.
type M4NotificationEvent struct {
	ApplicationID domain.ID
	EnvironmentID domain.ID
	IncidentID    string
	Kind          M4NotificationKind
	Severity      string
	Message       string
	OccurredAt    time.Time
}

type M4NotificationRequest struct {
	Endpoint       M4WebhookEndpoint
	Event          M4NotificationEvent
	IdempotencyKey string
	Actor          string
}

type M4NotificationDelivery struct {
	ID             string
	Endpoint       M4WebhookEndpoint
	EventID        domain.ID
	EventType      string
	Payload        map[string]any
	PayloadDigest  string
	OccurredAt     time.Time
	Status         M4NotificationStatus
	Attempts       int
	NextAttemptAt  time.Time
	LeaseOwner     string
	LeaseUntil     time.Time
	Failure        string
	IdempotencyKey string
	RequestDigest  string
}

type M4NotificationReservationRequest struct {
	Delivery M4NotificationDelivery
	Actor    string
	Now      time.Time
}

type M4NotificationReservation struct {
	Delivery M4NotificationDelivery
	Replay   bool
}

type M4NotificationAttempt struct {
	DeliveryID    string
	EventID       domain.ID
	Attempt       int
	LeaseOwner    string
	At            time.Time
	Succeeded     bool
	Status        M4NotificationStatus
	NextAttemptAt time.Time
	Failure       string
	FailureCode   contracts.ErrorCode
}

// M4NotificationLedger is the persistence contract. Reserve atomically
// deduplicates an idempotency key and logical endpoint/event delivery. Claim
// must lease only due pending entries. AppendAttempt must atomically persist
// the attempt, clear its lease, and update status/next retry time.
type M4NotificationLedger interface {
	ReserveM4Notification(context.Context, M4NotificationReservationRequest) (M4NotificationReservation, error)
	ClaimDueM4Notifications(context.Context, string, time.Time, int) ([]M4NotificationDelivery, error)
	AppendM4NotificationAttempt(context.Context, M4NotificationAttempt) (M4NotificationDelivery, error)
}

// M4WebhookResolver constructs a configured sender after resolving the
// endpoint SecretReference in restricted composition code. It returns a
// capability, not plaintext signing material.
type M4WebhookResolver interface {
	ResolveWebhookNotificationProvider(context.Context, M4WebhookEndpoint, contracts.OperationContext) (contracts.NotificationProvider, error)
}

type M4NotificationResult struct {
	DeliveryID    string
	EventID       domain.ID
	Status        M4NotificationStatus
	Attempts      int
	NextAttemptAt time.Time
	Delivered     bool
	Failure       string
	PayloadDigest string
}

// M4NotificationController sends lifecycle notifications out of the release
// path. A receiver/resolver failure records a retryable ledger fact and returns
// a result with nil error, so it can never make an application unhealthy.
type M4NotificationController struct {
	Ledger   M4NotificationLedger
	Resolver M4WebhookResolver
	Clock    func() time.Time
}

func (c *M4NotificationController) Publish(ctx context.Context, request M4NotificationRequest) (M4NotificationResult, error) {
	if err := c.validate(); err != nil {
		return M4NotificationResult{}, err
	}
	if err := validateM4NotificationRequest(request); err != nil {
		return M4NotificationResult{}, err
	}
	now := c.now()
	delivery, err := newM4NotificationDelivery(request)
	if err != nil {
		return M4NotificationResult{}, err
	}
	reservation, err := c.Ledger.ReserveM4Notification(ctx, M4NotificationReservationRequest{Delivery: delivery, Actor: request.Actor, Now: now})
	if err != nil {
		return M4NotificationResult{}, err
	}
	// Reserve is deliberately the whole synchronous path. A worker must claim
	// the due delivery before it resolves a secret or opens the network; this
	// keeps retries safe across a server crash and avoids an unleased first send.
	return m4NotificationResult(reservation.Delivery), nil
}

// RunPending claims due retries. Individual transport failures remain result
// facts; only a ledger protocol failure returns an error to the worker.
func (c *M4NotificationController) RunPending(ctx context.Context, workerID string, limit int) ([]M4NotificationResult, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(workerID) == "" || limit <= 0 || limit > 100 {
		return nil, domain.ValidationError("notification worker id and a limit up to 100 are required")
	}
	now := c.now()
	deliveries, err := c.Ledger.ClaimDueM4Notifications(ctx, workerID, now, limit)
	if err != nil {
		return nil, err
	}
	results := make([]M4NotificationResult, 0, len(deliveries))
	for _, delivery := range deliveries {
		if err := validateM4NotificationDelivery(delivery); err != nil {
			return results, err
		}
		result, err := c.deliver(ctx, delivery, now)
		if err != nil {
			return results, err
		}
		results = append(results, result)
	}
	return results, nil
}

func (c *M4NotificationController) deliver(ctx context.Context, delivery M4NotificationDelivery, now time.Time) (M4NotificationResult, error) {
	if strings.TrimSpace(delivery.LeaseOwner) == "" {
		return M4NotificationResult{}, domain.ValidationError("claimed notification delivery has no lease owner")
	}
	attempt := delivery.Attempts + 1
	provider, resolveErr := c.Resolver.ResolveWebhookNotificationProvider(ctx, delivery.Endpoint, m4NotificationOperation(delivery, attempt, "resolve"))
	var sendErr error
	if resolveErr == nil && provider == nil {
		resolveErr = errors.New("webhook resolver returned no provider")
	}
	if resolveErr == nil {
		sendErr = provider.Send(ctx, contracts.Notification{EventID: delivery.EventID, EventType: delivery.EventType, Payload: cloneM4NotificationPayload(delivery.Payload), OccurredAt: delivery.OccurredAt}, m4NotificationOperation(delivery, attempt, "send"))
	}
	succeeded := resolveErr == nil && sendErr == nil
	status, next := M4NotificationDelivered, time.Time{}
	failure, code := "", contracts.ErrorCode("")
	if !succeeded {
		cause := sendErr
		if cause == nil {
			cause = resolveErr
		}
		failure = redactM4NotificationText(cause.Error())
		code = notificationErrorCode(cause)
		if notificationRetryable(cause) {
			status, next = m4NotificationRetryStatus(attempt, now)
		} else {
			status, next = M4NotificationFailed, time.Time{}
		}
	}
	updated, err := c.Ledger.AppendM4NotificationAttempt(ctx, M4NotificationAttempt{DeliveryID: delivery.ID, EventID: delivery.EventID, Attempt: attempt, LeaseOwner: delivery.LeaseOwner, At: now, Succeeded: succeeded, Status: status, NextAttemptAt: next, Failure: failure, FailureCode: code})
	if err != nil {
		return M4NotificationResult{}, err
	}
	return m4NotificationResult(updated), nil
}

func (c *M4NotificationController) validate() error {
	if c == nil || c.Ledger == nil || c.Resolver == nil {
		return errors.New("M4 notification controller requires ledger and webhook resolver")
	}
	return nil
}
func (c *M4NotificationController) now() time.Time {
	if c.Clock == nil {
		return time.Now().UTC()
	}
	return c.Clock().UTC()
}

func newM4NotificationDelivery(request M4NotificationRequest) (M4NotificationDelivery, error) {
	payload, digest, err := canonicalM4NotificationPayload(request.Event)
	if err != nil {
		return M4NotificationDelivery{}, err
	}
	eventID := domain.ID("notify_" + foundation.WebhookEventID("notification."+string(request.Event.Kind), request.Event.ApplicationID.String()+":"+request.Event.EnvironmentID.String()+":"+request.Event.IncidentID, request.Event.OccurredAt))
	// occurred_at is controller-generated delivery metadata, not caller intent.
	// Including its payload digest in the idempotency fingerprint would turn a
	// perfectly valid HTTP retry (which naturally obtains a later clock value)
	// into an idempotency conflict.  The canonical payload still persists the
	// timestamp, while request identity stays bound to every caller-controlled
	// lifecycle fact and the redacted message.
	requestDigest := m4NotificationDigest(request.Endpoint.ID, string(request.Event.Kind), request.Event.ApplicationID.String(), request.Event.EnvironmentID.String(), request.Event.IncidentID, request.Event.Severity, foundation.RedactText(request.Event.Message), request.IdempotencyKey, request.Actor)
	identifier := "delivery_" + m4NotificationDigest(request.Endpoint.ID, eventID.String())[:32]
	return M4NotificationDelivery{ID: identifier, Endpoint: request.Endpoint, EventID: eventID, EventType: "notification." + string(request.Event.Kind), Payload: payload, PayloadDigest: digest, OccurredAt: request.Event.OccurredAt.UTC(), Status: M4NotificationPending, IdempotencyKey: request.IdempotencyKey, RequestDigest: requestDigest}, nil
}

func canonicalM4NotificationPayload(event M4NotificationEvent) (map[string]any, string, error) {
	message := redactM4NotificationText(event.Message)
	payload := map[string]any{"schema_version": "m4.notification.v1", "application_id": event.ApplicationID.String(), "environment_id": event.EnvironmentID.String(), "incident_id": event.IncidentID, "kind": string(event.Kind), "severity": event.Severity, "message": message, "occurred_at": event.OccurredAt.UTC().Format(time.RFC3339Nano)}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(encoded)
	return payload, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func validateM4NotificationRequest(request M4NotificationRequest) error {
	if strings.TrimSpace(request.IdempotencyKey) == "" || strings.TrimSpace(request.Actor) == "" {
		return domain.ValidationError("notification idempotency key and actor are required")
	}
	if strings.TrimSpace(request.Endpoint.ID) == "" || strings.TrimSpace(request.Endpoint.URL) == "" || !request.Endpoint.Enabled {
		return domain.ValidationError("enabled notification endpoint id and URL are required")
	}
	endpoint, err := url.Parse(request.Endpoint.URL)
	if err != nil || endpoint == nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.User != nil || endpoint.Hostname() == "" || endpoint.RawQuery != "" {
		return domain.ValidationError("notification endpoint must be an HTTP(S) URL without user info or query credentials")
	}
	if err := request.Endpoint.SecretRef.Validate(); err != nil {
		return domain.ValidationError("notification endpoint secret reference is invalid")
	}
	event := request.Event
	if event.ApplicationID.Empty() || event.EnvironmentID.Empty() || strings.TrimSpace(event.IncidentID) == "" || strings.TrimSpace(event.Severity) == "" || strings.TrimSpace(event.Message) == "" || event.OccurredAt.IsZero() {
		return domain.ValidationError("notification event application, environment, incident, severity, message, and time are required")
	}
	switch event.Kind {
	case M4NotificationOccurrence, M4NotificationEscalation, M4NotificationRecovery:
	default:
		return domain.ValidationError("notification event kind is unsupported")
	}
	return nil
}

func validateM4NotificationDelivery(delivery M4NotificationDelivery) error {
	if strings.TrimSpace(delivery.ID) == "" || delivery.EventID.Empty() || strings.TrimSpace(delivery.EventType) == "" || delivery.OccurredAt.IsZero() || delivery.Status != M4NotificationPending || delivery.Attempts < 0 {
		return domain.ValidationError("pending notification delivery is invalid")
	}
	if err := delivery.Endpoint.SecretRef.Validate(); err != nil {
		return domain.ValidationError("pending notification secret reference is invalid")
	}
	if !delivery.Endpoint.Enabled || strings.TrimSpace(delivery.Endpoint.ID) == "" || strings.TrimSpace(delivery.Endpoint.URL) == "" || len(delivery.Payload) == 0 || !strings.HasPrefix(delivery.PayloadDigest, "sha256:") {
		return domain.ValidationError("pending notification delivery has incomplete endpoint or payload facts")
	}
	return nil
}

func m4NotificationRetryStatus(attempt int, now time.Time) (M4NotificationStatus, time.Time) {
	if attempt <= len(m4NotificationRetryDelays) {
		return M4NotificationPending, now.Add(m4NotificationRetryDelays[attempt-1])
	}
	return M4NotificationFailed, time.Time{}
}
func m4NotificationOperation(delivery M4NotificationDelivery, attempt int, action string) contracts.OperationContext {
	return contracts.OperationContext{IdempotencyKey: "m4-notification:" + delivery.ID + ":" + fmt.Sprint(attempt) + ":" + action, Actor: "m4-notification-worker"}
}
func m4NotificationResult(delivery M4NotificationDelivery) M4NotificationResult {
	return M4NotificationResult{DeliveryID: delivery.ID, EventID: delivery.EventID, Status: delivery.Status, Attempts: delivery.Attempts, NextAttemptAt: delivery.NextAttemptAt, Delivered: delivery.Status == M4NotificationDelivered, Failure: redactM4NotificationText(delivery.Failure), PayloadDigest: delivery.PayloadDigest}
}

func notificationRetryable(err error) bool {
	var providerErr *contracts.ProviderError
	if errors.As(err, &providerErr) {
		return providerErr.Retryable
	}
	return true
}

func redactM4NotificationText(value string) string {
	redacted := foundation.RedactText(value)
	upper := strings.ToUpper(redacted)
	if strings.Contains(upper, "-----BEGIN") && strings.Contains(upper, "PRIVATE KEY-----") {
		return foundation.RedactedValue
	}
	return redacted
}
func notificationErrorCode(err error) contracts.ErrorCode {
	var providerErr *contracts.ProviderError
	if errors.As(err, &providerErr) {
		return providerErr.Code
	}
	return contracts.ErrUnavailable
}
func cloneM4NotificationPayload(value map[string]any) map[string]any {
	copied := make(map[string]any, len(value))
	for key, item := range value {
		copied[key] = item
	}
	return copied
}
func m4NotificationDigest(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}
