package postgres

// M4 operations persistence contains metadata and delivery facts only. It
// deliberately never stores webhook secrets, webhook payload bodies, log
// content, or log response bodies.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

var (
	ErrWebhookPayloadConflict  = errors.New("webhook event id was reused with a different payload")
	ErrWebhookEndpointDisabled = errors.New("webhook endpoint is disabled")
	ErrWebhookEventDelivered   = errors.New("webhook event is already delivered")
	ErrWebhookAttemptOrder     = errors.New("webhook attempt is out of order")
	ErrAuditLogImmutable       = errors.New("audit log index cannot be retired")
)

type WebhookDeliveryStatus string

const (
	WebhookDeliveryPending   WebhookDeliveryStatus = "pending"
	WebhookDeliveryRetryWait WebhookDeliveryStatus = "retry_wait"
	WebhookDeliveryDelivered WebhookDeliveryStatus = "delivered"
	WebhookDeliveryFailed    WebhookDeliveryStatus = "failed"
)

type WebhookAttemptStatus string

const (
	WebhookAttemptDelivered WebhookAttemptStatus = "delivered"
	WebhookAttemptRetryable WebhookAttemptStatus = "retryable_failure"
	WebhookAttemptFailed    WebhookAttemptStatus = "failed"
)

// WebhookEndpoint stores a HTTPS destination and opaque secret reference. No
// signing secret value exists in this type or in its database representation.
type WebhookEndpoint struct {
	ID                domain.ID `json:"id"`
	ApplicationID     domain.ID `json:"application_id"`
	URL               string    `json:"url"`
	SecretReferenceID domain.ID `json:"secret_reference_id"`
	SecretName        string    `json:"secret_name"`
	SecretProvider    string    `json:"secret_provider"`
	SecretVersion     string    `json:"secret_version,omitempty"`
	EventTypes        []string  `json:"event_types"`
	Enabled           bool      `json:"enabled"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// WebhookLifecycleEvent is the restricted M4 projection of one operation
// outbox record to one configured endpoint. It has no raw logs, headers,
// response bodies, or secret material; callers still canonicalize/redact the
// short message before reserving a delivery.
type WebhookLifecycleEvent struct {
	OutboxEventID string          `json:"outbox_event_id"`
	EventID       string          `json:"event_id"`
	OperationID   domain.ID       `json:"operation_id"`
	ApplicationID domain.ID       `json:"application_id"`
	EnvironmentID domain.ID       `json:"environment_id"`
	Kind          string          `json:"kind"`
	Status        string          `json:"status"`
	Message       string          `json:"message"`
	OccurredAt    time.Time       `json:"occurred_at"`
	Endpoint      WebhookEndpoint `json:"endpoint"`
}

// M4ObservationCandidate is a live M2 ServiceGroup deployment that needs a
// fresh Agent observation. It is not a user-requested release action.
type M4ObservationCandidate struct {
	Deployment domain.Deployment
}

// M4LogCollectionCandidate is one service in a live M2 deployment whose
// runtime log snapshot is older than the configured collection interval.
// Selection is durable and excludes environments with an active operation or
// rollout so background collection cannot race recovery actions.
type M4LogCollectionCandidate struct {
	Deployment  domain.Deployment
	ServiceName string
}

// WebhookEventLedger is one logical notification. PayloadDigest identifies
// redacted/canonical payload bytes but does not expose the payload itself.
type WebhookEventLedger struct {
	EndpointID     domain.ID             `json:"endpoint_id"`
	DeliveryID     string                `json:"delivery_id,omitempty"`
	EventID        domain.ID             `json:"event_id"`
	EventType      string                `json:"event_type"`
	PayloadDigest  string                `json:"payload_digest"`
	Payload        json.RawMessage       `json:"-"`
	IdempotencyKey string                `json:"idempotency_key,omitempty"`
	RequestDigest  string                `json:"request_digest,omitempty"`
	OccurredAt     time.Time             `json:"occurred_at"`
	Status         WebhookDeliveryStatus `json:"status"`
	ReceivedCount  int64                 `json:"received_count"`
	AttemptCount   int                   `json:"attempt_count"`
	NextAttemptAt  *time.Time            `json:"next_attempt_at,omitempty"`
	LeaseOwner     string                `json:"lease_owner,omitempty"`
	LeaseUntil     *time.Time            `json:"lease_until,omitempty"`
	LastAttemptAt  *time.Time            `json:"last_attempt_at,omitempty"`
	DeliveredAt    *time.Time            `json:"delivered_at,omitempty"`
	FailureReason  string                `json:"failure_reason,omitempty"`
	CreatedAt      time.Time             `json:"created_at"`
	UpdatedAt      time.Time             `json:"updated_at"`
}

// WebhookDeliveryRequest is the durable handoff used by a notification
// controller adapter. Payload is strictly canonical, already-redacted
// lifecycle JSON; it never contains raw logs, headers, responses, PEM, or a
// secret value.
type WebhookDeliveryRequest struct {
	DeliveryID     string          `json:"delivery_id"`
	EndpointID     domain.ID       `json:"endpoint_id"`
	EventID        domain.ID       `json:"event_id"`
	EventType      string          `json:"event_type"`
	PayloadDigest  string          `json:"payload_digest"`
	Payload        json.RawMessage `json:"-"`
	IdempotencyKey string          `json:"idempotency_key"`
	RequestDigest  string          `json:"request_digest"`
	OccurredAt     time.Time       `json:"occurred_at"`
}

type WebhookDeliveryAttempt struct {
	DeliveryID    string                `json:"delivery_id"`
	EventID       domain.ID             `json:"event_id"`
	Attempt       int                   `json:"attempt"`
	LeaseOwner    string                `json:"lease_owner"`
	At            time.Time             `json:"at"`
	Succeeded     bool                  `json:"succeeded"`
	Status        WebhookDeliveryStatus `json:"status"`
	NextAttemptAt time.Time             `json:"next_attempt_at,omitempty"`
	Failure       string                `json:"failure,omitempty"`
	FailureCode   string                `json:"failure_code,omitempty"`
}

type WebhookAttempt struct {
	ID            domain.ID            `json:"id"`
	EndpointID    domain.ID            `json:"endpoint_id"`
	EventID       domain.ID            `json:"event_id"`
	AttemptNumber int                  `json:"attempt_number"`
	RequestDigest string               `json:"request_digest"`
	Status        WebhookAttemptStatus `json:"status"`
	HTTPStatus    *int                 `json:"http_status,omitempty"`
	ErrorCode     string               `json:"error_code,omitempty"`
	CreatedAt     time.Time            `json:"created_at"`
}

type LogIndexCategory string

const (
	LogIndexBuild   LogIndexCategory = "build"
	LogIndexRuntime LogIndexCategory = "runtime"
	LogIndexAudit   LogIndexCategory = "audit"
)

// LogIndex is metadata for an on-disk segment. It must not be used to place
// log content in PostgreSQL or to copy audit evidence into ordinary GC state.
type LogIndex struct {
	ID            domain.ID        `json:"id"`
	ApplicationID domain.ID        `json:"application_id"`
	ServiceName   string           `json:"service_name"`
	ReleaseID     domain.ID        `json:"release_id,omitempty"`
	DeploymentID  domain.ID        `json:"deployment_id,omitempty"`
	OperationID   domain.ID        `json:"operation_id,omitempty"`
	Category      LogIndexCategory `json:"category"`
	Path          string           `json:"path"`
	Segment       int              `json:"segment"`
	ByteSize      int64            `json:"byte_size"`
	RetiredAt     *time.Time       `json:"retired_at,omitempty"`
	CreatedAt     time.Time        `json:"created_at"`
}

// OperationFact is deliberately a single shared projection for ordinary and
// operator views. It contains no authorization decision or mutable UI state.
type OperationFact struct {
	Operation       domain.Operation        `json:"operation"`
	DeploymentID    domain.ID               `json:"deployment_id,omitempty"`
	DeploymentState domain.DeploymentStatus `json:"deployment_state,omitempty"`
	ReleaseID       domain.ID               `json:"release_id,omitempty"`
	ReleaseVersion  int64                   `json:"release_version,omitempty"`
	RuntimeHealthy  bool                    `json:"runtime_healthy"`
	LastObservedAt  *time.Time              `json:"last_observed_at,omitempty"`
}

func (v WebhookEndpoint) Validate() error {
	if err := domain.RequireID(v.ID, "webhook endpoint id"); err != nil {
		return err
	}
	if err := domain.RequireID(v.ApplicationID, "webhook endpoint application id"); err != nil {
		return err
	}
	if err := domain.RequireID(v.SecretReferenceID, "webhook endpoint secret reference id"); err != nil {
		return err
	}
	if err := (domain.SecretReference{ID: v.SecretReferenceID, Name: v.SecretName, Provider: v.SecretProvider, Version: v.SecretVersion}).Validate(); err != nil {
		return fmt.Errorf("webhook endpoint opaque secret reference: %w", err)
	}
	if err := validateWebhookURL(v.URL); err != nil {
		return err
	}
	if len(v.EventTypes) == 0 {
		return domain.ValidationError("webhook endpoint event types are required")
	}
	seen := map[string]struct{}{}
	for _, eventType := range v.EventTypes {
		eventType = strings.TrimSpace(eventType)
		if eventType == "" || strings.ContainsAny(eventType, "\r\n\x00") {
			return domain.ValidationError("webhook event type is invalid")
		}
		if _, ok := seen[eventType]; ok {
			return domain.ValidationError("webhook event types must be unique")
		}
		seen[eventType] = struct{}{}
	}
	return nil
}

func validateWebhookURL(value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return domain.ValidationError("webhook endpoint must be a canonical HTTPS URL without credentials, query, or fragment")
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return domain.ValidationError("webhook endpoint host is not public")
	}
	if ip, err := netip.ParseAddr(host); err == nil && !ip.IsGlobalUnicast() {
		return domain.ValidationError("webhook endpoint must not use a local or private address")
	}
	if strings.Contains(host, "%") || net.ParseIP(host) != nil {
		return domain.ValidationError("webhook endpoint literal IP is not allowed")
	}
	return nil
}

func (v WebhookEventLedger) Validate() error {
	if err := domain.RequireID(v.EndpointID, "webhook event endpoint id"); err != nil {
		return err
	}
	if err := domain.RequireID(v.EventID, "webhook event id"); err != nil {
		return err
	}
	if strings.TrimSpace(v.EventType) == "" || !m4SHA256(v.PayloadDigest) || v.OccurredAt.IsZero() {
		return domain.ValidationError("webhook event type, digest, and time are required")
	}
	if v.ReceivedCount < 1 || v.AttemptCount < 0 {
		return domain.ValidationError("webhook event counts are invalid")
	}
	if v.Status != WebhookDeliveryPending && v.Status != WebhookDeliveryRetryWait && v.Status != WebhookDeliveryDelivered && v.Status != WebhookDeliveryFailed {
		return domain.ValidationError("webhook event status is unsupported")
	}
	if v.Status == WebhookDeliveryDelivered && v.DeliveredAt == nil {
		return domain.ValidationError("delivered webhook event requires timestamp")
	}
	if v.Status == WebhookDeliveryFailed && strings.TrimSpace(v.FailureReason) == "" {
		return domain.ValidationError("failed webhook event requires redacted reason")
	}
	if len(v.Payload) > 0 {
		_, digest, err := canonicalM4WebhookPayload(v.Payload)
		if err != nil || digest != v.PayloadDigest {
			return domain.ValidationError("webhook event payload is not canonical or does not match digest")
		}
	}
	if (strings.TrimSpace(v.LeaseOwner) == "") != (v.LeaseUntil == nil) {
		return domain.ValidationError("webhook delivery lease is incomplete")
	}
	if v.LeaseUntil != nil && !v.LeaseUntil.After(v.UpdatedAt) {
		return domain.ValidationError("webhook delivery lease must be in the future of its update")
	}
	return nil
}

func (v WebhookDeliveryRequest) Validate() error {
	if strings.TrimSpace(v.DeliveryID) == "" || strings.TrimSpace(v.IdempotencyKey) == "" || !m4SHA256(v.RequestDigest) {
		return domain.ValidationError("webhook delivery id, idempotency key, and request digest are required")
	}
	canonical, digest, err := canonicalM4WebhookPayload(v.Payload)
	if err != nil || digest != v.PayloadDigest || len(canonical) == 0 {
		return domain.ValidationError("webhook delivery payload must be canonical, redacted, and match its digest")
	}
	ledger := WebhookEventLedger{EndpointID: v.EndpointID, EventID: v.EventID, EventType: v.EventType, PayloadDigest: v.PayloadDigest, OccurredAt: v.OccurredAt, Status: WebhookDeliveryPending, ReceivedCount: 1}
	return ledger.Validate()
}

func canonicalM4WebhookPayload(payload json.RawMessage) (json.RawMessage, string, error) {
	var raw map[string]json.RawMessage
	if len(payload) == 0 || json.Unmarshal(payload, &raw) != nil {
		return nil, "", domain.ValidationError("webhook payload must be JSON")
	}
	const schema = "m4.notification.v1"
	allowed := map[string]struct{}{"schema_version": {}, "application_id": {}, "environment_id": {}, "incident_id": {}, "kind": {}, "severity": {}, "message": {}, "occurred_at": {}}
	if len(raw) != len(allowed) {
		return nil, "", domain.ValidationError("webhook payload has unsupported fields")
	}
	value := make(map[string]string, len(allowed))
	for key := range allowed {
		item, ok := raw[key]
		var decoded string
		if !ok || json.Unmarshal(item, &decoded) != nil || strings.TrimSpace(decoded) == "" {
			return nil, "", domain.ValidationError("webhook payload field is invalid: " + key)
		}
		value[key] = decoded
	}
	if value["schema_version"] != schema {
		return nil, "", domain.ValidationError("webhook payload schema version is unsupported")
	}
	if err := domain.RequireID(domain.ID(value["application_id"]), "webhook payload application id"); err != nil {
		return nil, "", err
	}
	if err := domain.RequireID(domain.ID(value["environment_id"]), "webhook payload environment id"); err != nil {
		return nil, "", err
	}
	if value["kind"] != "occurrence" && value["kind"] != "escalation" && value["kind"] != "recovery" {
		return nil, "", domain.ValidationError("webhook payload lifecycle kind is unsupported")
	}
	if _, err := time.Parse(time.RFC3339Nano, value["occurred_at"]); err != nil {
		return nil, "", domain.ValidationError("webhook payload occurred_at is invalid")
	}
	if foundation.RedactText(value["message"]) != value["message"] || hasM4PEM(value["message"]) {
		return nil, "", domain.ValidationError("webhook payload message was not redacted")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	return canonical, m1Digest(canonical), nil
}

func hasM4PEM(value string) bool {
	upper := strings.ToUpper(value)
	return strings.Contains(upper, "-----BEGIN") && (strings.Contains(upper, "PRIVATE KEY-----") || strings.Contains(upper, "CERTIFICATE-----"))
}

func (v WebhookDeliveryAttempt) Validate() error {
	if strings.TrimSpace(v.DeliveryID) == "" || v.EventID.Empty() || v.Attempt < 1 || strings.TrimSpace(v.LeaseOwner) == "" || v.At.IsZero() {
		return domain.ValidationError("webhook delivery attempt identity, lease owner, and time are required")
	}
	if strings.ContainsAny(v.Failure, "\r\n\x00") || strings.ContainsAny(v.FailureCode, "\r\n\x00") {
		return domain.ValidationError("webhook delivery failure is invalid")
	}
	switch v.Status {
	case WebhookDeliveryDelivered:
		if !v.Succeeded || !v.NextAttemptAt.IsZero() || strings.TrimSpace(v.Failure) != "" {
			return domain.ValidationError("delivered webhook attempt is invalid")
		}
	case WebhookDeliveryPending:
		if v.Succeeded || !v.NextAttemptAt.After(v.At) {
			return domain.ValidationError("retry webhook attempt requires a future retry time")
		}
	case WebhookDeliveryFailed:
		if v.Succeeded || !v.NextAttemptAt.IsZero() || strings.TrimSpace(v.Failure) == "" {
			return domain.ValidationError("failed webhook attempt is invalid")
		}
	default:
		return domain.ValidationError("webhook delivery attempt status is unsupported")
	}
	return nil
}

func (v WebhookAttempt) Validate() error {
	if err := domain.RequireID(v.ID, "webhook attempt id"); err != nil {
		return err
	}
	if err := domain.RequireID(v.EndpointID, "webhook attempt endpoint id"); err != nil {
		return err
	}
	if err := domain.RequireID(v.EventID, "webhook attempt event id"); err != nil {
		return err
	}
	if v.AttemptNumber < 1 || !m4SHA256(v.RequestDigest) {
		return domain.ValidationError("webhook attempt number and request digest are required")
	}
	if v.HTTPStatus != nil && (*v.HTTPStatus < 100 || *v.HTTPStatus > 599) {
		return domain.ValidationError("webhook HTTP status is invalid")
	}
	switch v.Status {
	case WebhookAttemptDelivered:
		if v.HTTPStatus == nil || *v.HTTPStatus < 200 || *v.HTTPStatus > 299 || v.ErrorCode != "" {
			return domain.ValidationError("successful webhook attempt requires a 2xx status and no error code")
		}
	case WebhookAttemptRetryable, WebhookAttemptFailed:
		if v.HTTPStatus != nil && *v.HTTPStatus >= 200 && *v.HTTPStatus <= 299 {
			return domain.ValidationError("failed webhook attempt cannot report a 2xx status")
		}
		if strings.ContainsAny(v.ErrorCode, "\r\n\x00") {
			return domain.ValidationError("webhook error code is invalid")
		}
	default:
		return domain.ValidationError("webhook attempt status is unsupported")
	}
	return nil
}

func (v LogIndex) Validate() error {
	if err := domain.RequireID(v.ID, "log index id"); err != nil {
		return err
	}
	if err := domain.RequireID(v.ApplicationID, "log index application id"); err != nil {
		return err
	}
	if strings.TrimSpace(v.ServiceName) == "" || strings.TrimSpace(v.Path) == "" || strings.ContainsRune(v.Path, 0) || v.Segment < 0 || v.ByteSize < 0 {
		return domain.ValidationError("log index service, path, segment, and byte size are invalid")
	}
	if v.Category != LogIndexBuild && v.Category != LogIndexRuntime && v.Category != LogIndexAudit {
		return domain.ValidationError("log index category is unsupported")
	}
	if v.Category == LogIndexAudit && v.RetiredAt != nil {
		return domain.ValidationError("audit log index cannot be retired")
	}
	return nil
}

func m4SHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if !(char >= '0' && char <= '9') && !(char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func (s *Store) UpsertWebhookEndpoint(ctx context.Context, endpoint WebhookEndpoint, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	endpoint.URL = strings.TrimSpace(endpoint.URL)
	endpoint.EventTypes = m4NormalizeEventTypes(endpoint.EventTypes)
	if err := endpoint.Validate(); err != nil {
		return err
	}
	now = m4Now(s, now)
	if endpoint.CreatedAt.IsZero() {
		endpoint.CreatedAt = now
	}
	types, err := jsonM4(endpoint.EventTypes)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	var existing WebhookEndpoint
	var existingTypes []byte
	err = tx.QueryRowContext(ctx, `SELECT id,application_id,endpoint_url,secret_reference_id,secret_name,secret_provider,secret_version,event_types,enabled,created_at,updated_at FROM m4_webhook_endpoints WHERE id=$1 FOR UPDATE`, endpoint.ID.String()).Scan(&existing.ID, &existing.ApplicationID, &existing.URL, &existing.SecretReferenceID, &existing.SecretName, &existing.SecretProvider, &existing.SecretVersion, &existingTypes, &existing.Enabled, &existing.CreatedAt, &existing.UpdatedAt)
	changed := errors.Is(err, sql.ErrNoRows)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return rollbackTx(tx, fmt.Errorf("read webhook endpoint owner: %w", err))
	}
	if err == nil {
		if existing.ApplicationID != endpoint.ApplicationID {
			return rollbackTx(tx, domain.ValidationError("webhook endpoint id belongs to a different application"))
		}
		if err := decodeM4EventTypes(existingTypes, &existing.EventTypes); err != nil {
			return rollbackTx(tx, err)
		}
		changed = !m4WebhookEndpointConfigurationEqual(existing, endpoint)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO m4_webhook_endpoints(id,application_id,endpoint_url,secret_reference_id,secret_name,secret_provider,secret_version,event_types,enabled,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11) ON CONFLICT(id) DO UPDATE SET endpoint_url=EXCLUDED.endpoint_url,secret_reference_id=EXCLUDED.secret_reference_id,secret_name=EXCLUDED.secret_name,secret_provider=EXCLUDED.secret_provider,secret_version=EXCLUDED.secret_version,event_types=EXCLUDED.event_types,enabled=EXCLUDED.enabled,updated_at=EXCLUDED.updated_at`, endpoint.ID.String(), endpoint.ApplicationID.String(), endpoint.URL, endpoint.SecretReferenceID.String(), endpoint.SecretName, endpoint.SecretProvider, endpoint.SecretVersion, types, endpoint.Enabled, endpoint.CreatedAt.UTC(), now); err != nil {
		return rollbackTx(tx, err)
	}
	if changed {
		// Configuration activation is a durable cursor boundary. Events that
		// existed before this transaction commits are historical for the new
		// subscription (including disable/re-enable and event-type expansion),
		// so acknowledge them without reserving a delivery. An exact replay of
		// an unchanged configuration does not advance the cursor.
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO m4_webhook_outbox_receipts(outbox_event_id,endpoint_id,dispatched_at)
			SELECT o.id,$1,$2
			  FROM outbox_events o
			  JOIN operations op ON op.id=o.aggregate_id
			 WHERE o.aggregate_type='operation'
			   AND op.application_id=$3
			   AND (
			     lower(o.event_type) ~ '(failure|failed|retry|escalat|recover|recovered)$'
			     OR lower(COALESCE(o.payload->>'status','')) IN ('failure','failed','retry','escalation','escalated','recovery','recovered')
			   )
			ON CONFLICT(outbox_event_id,endpoint_id) DO NOTHING`, endpoint.ID.String(), now, endpoint.ApplicationID.String()); err != nil {
			return rollbackTx(tx, err)
		}
	}
	return tx.Commit()
}

func m4WebhookEndpointConfigurationEqual(left, right WebhookEndpoint) bool {
	if left.ApplicationID != right.ApplicationID || left.URL != right.URL || left.SecretReferenceID != right.SecretReferenceID || left.SecretName != right.SecretName || left.SecretProvider != right.SecretProvider || left.SecretVersion != right.SecretVersion || left.Enabled != right.Enabled {
		return false
	}
	return strings.Join(m4NormalizeEventTypes(left.EventTypes), "\x00") == strings.Join(m4NormalizeEventTypes(right.EventTypes), "\x00")
}

func (s *Store) GetWebhookEndpoint(ctx context.Context, id domain.ID) (WebhookEndpoint, error) {
	if err := s.requireDB(); err != nil {
		return WebhookEndpoint{}, err
	}
	if err := domain.RequireID(id, "webhook endpoint id"); err != nil {
		return WebhookEndpoint{}, err
	}
	var endpoint WebhookEndpoint
	var eventTypes []byte
	err := s.db.QueryRowContext(ctx, `SELECT id,application_id,endpoint_url,secret_reference_id,secret_name,secret_provider,secret_version,event_types,enabled,created_at,updated_at FROM m4_webhook_endpoints WHERE id=$1`, id.String()).Scan(&endpoint.ID, &endpoint.ApplicationID, &endpoint.URL, &endpoint.SecretReferenceID, &endpoint.SecretName, &endpoint.SecretProvider, &endpoint.SecretVersion, &eventTypes, &endpoint.Enabled, &endpoint.CreatedAt, &endpoint.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return WebhookEndpoint{}, ErrNotFound
	}
	if err != nil {
		return WebhookEndpoint{}, err
	}
	if err := decodeM4EventTypes(eventTypes, &endpoint.EventTypes); err != nil {
		return WebhookEndpoint{}, err
	}
	endpoint.CreatedAt, endpoint.UpdatedAt = endpoint.CreatedAt.UTC(), endpoint.UpdatedAt.UTC()
	if err := endpoint.Validate(); err != nil {
		return WebhookEndpoint{}, fmt.Errorf("invalid persisted webhook endpoint: %w", err)
	}
	return endpoint, nil
}

// ListPendingWebhookLifecycleEvents joins only M4 operation outbox records to
// enabled endpoint facts which do not yet have an M4 dispatch receipt. It
// never advances the global outbox `published_at` cursor: that cursor belongs
// to SSE and any other independently durable consumers.
func (s *Store) ListPendingWebhookLifecycleEvents(ctx context.Context, limit int) ([]WebhookLifecycleEvent, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	limit = normalizeM4Limit(limit)
	rows, err := s.db.QueryContext(ctx, `
		SELECT o.id,o.aggregate_id,o.event_type,o.payload,o.created_at,
		       op.application_id,op.environment_id,
		       p.id,p.application_id,p.endpoint_url,p.secret_reference_id,p.secret_name,p.secret_provider,p.secret_version,p.event_types,p.enabled,p.created_at,p.updated_at
		  FROM outbox_events o
		  JOIN operations op ON op.id=o.aggregate_id
		  JOIN m4_webhook_endpoints p ON p.application_id=op.application_id AND p.enabled=true
		  LEFT JOIN m4_webhook_outbox_receipts r ON r.outbox_event_id=o.id AND r.endpoint_id=p.id
		 WHERE o.aggregate_type='operation'
		   AND o.created_at >= p.created_at
		   -- M4 notification is a lifecycle projection, not a second consumer
		   -- for every operation event.  In particular, queued/leased/running
		   -- records must not poison this endpoint-local cursor: the dispatcher
		   -- intentionally fails closed for unknown lifecycle kinds.  Keep the
		   -- selection aligned with its explicit failure/escalation/recovery
		   -- mapping, while accepting older outbox records whose kind is generic
		   -- but whose terminal status is authoritative.
		   AND (
			     lower(o.event_type) ~ '(failure|failed|retry|escalat|recover|recovered)$'
			     OR lower(COALESCE(o.payload->>'status','')) IN ('failure','failed','retry','escalation','escalated','recovery','recovered')
		   )
		   AND r.outbox_event_id IS NULL
		 ORDER BY o.stream_sequence,p.id
		 LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending M4 webhook lifecycle events: %w", err)
	}
	defer rows.Close()
	values := make([]WebhookLifecycleEvent, 0, limit)
	for rows.Next() {
		var value WebhookLifecycleEvent
		var payload, eventTypes []byte
		if err := rows.Scan(&value.OutboxEventID, &value.OperationID, &value.Kind, &payload, &value.OccurredAt, &value.ApplicationID, &value.EnvironmentID, &value.Endpoint.ID, &value.Endpoint.ApplicationID, &value.Endpoint.URL, &value.Endpoint.SecretReferenceID, &value.Endpoint.SecretName, &value.Endpoint.SecretProvider, &value.Endpoint.SecretVersion, &eventTypes, &value.Endpoint.Enabled, &value.Endpoint.CreatedAt, &value.Endpoint.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan pending M4 webhook lifecycle event: %w", err)
		}
		if value.Endpoint.ApplicationID != value.ApplicationID || !value.Endpoint.Enabled {
			return nil, domain.ValidationError("M4 webhook endpoint ownership projection is invalid")
		}
		if err := decodeM4EventTypes(eventTypes, &value.Endpoint.EventTypes); err != nil {
			return nil, err
		}
		if err := value.Endpoint.Validate(); err != nil {
			return nil, fmt.Errorf("invalid persisted M4 webhook endpoint: %w", err)
		}
		var eventPayload struct {
			ID         string    `json:"id"`
			Status     string    `json:"status"`
			Message    string    `json:"message"`
			OccurredAt time.Time `json:"occurred_at"`
		}
		if err := json.Unmarshal(payload, &eventPayload); err != nil {
			return nil, fmt.Errorf("decode M4 operation outbox payload: %w", err)
		}
		value.EventID, value.Status, value.Message = strings.TrimSpace(eventPayload.ID), strings.TrimSpace(eventPayload.Status), strings.TrimSpace(eventPayload.Message)
		if value.EventID == "" {
			value.EventID = value.OutboxEventID
		}
		if !eventPayload.OccurredAt.IsZero() {
			value.OccurredAt = eventPayload.OccurredAt.UTC()
		} else {
			value.OccurredAt = value.OccurredAt.UTC()
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending M4 webhook lifecycle events: %w", err)
	}
	return values, nil
}

// MarkWebhookLifecycleDispatched records the endpoint-local M4 projection.
// It is idempotent because notification reservation already owns delivery
// deduplication; a process crash before this insert merely replays that safe
// reservation on the next worker pass.
func (s *Store) MarkWebhookLifecycleDispatched(ctx context.Context, outboxEventID string, endpointID domain.ID, now time.Time) (bool, error) {
	if err := s.requireDB(); err != nil {
		return false, err
	}
	if strings.TrimSpace(outboxEventID) == "" || endpointID.Empty() {
		return false, domain.ValidationError("M4 webhook lifecycle receipt identity is required")
	}
	now = m4Now(s, now)
	result, err := s.db.ExecContext(ctx, `INSERT INTO m4_webhook_outbox_receipts(outbox_event_id,endpoint_id,dispatched_at) VALUES($1,$2,$3) ON CONFLICT(outbox_event_id,endpoint_id) DO NOTHING`, strings.TrimSpace(outboxEventID), endpointID.String(), now)
	if err != nil {
		return false, fmt.Errorf("record M4 webhook lifecycle receipt: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows == 1, nil
}

// ListM4ObservationCandidates returns only M2 deployments with no active
// environment operation and no recent M4 service observation. This prevents a
// background fact refresh from racing a user recovery operation or generating
// an unbounded task stream after a control-plane restart.
func (s *Store) ListM4ObservationCandidates(ctx context.Context, olderThan time.Time, limit int) ([]M4ObservationCandidate, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	limit = normalizeM4Limit(limit)
	if olderThan.IsZero() {
		olderThan = m4Now(s, time.Time{}).Add(-5 * time.Second)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.id,e.application_id,d.environment_id,d.release_id,d.state,d.created_at,d.updated_at
		  FROM deployments d
		  JOIN environments e ON e.id=d.environment_id
		  JOIN m2_release_runtime_specs m2 ON m2.release_id=d.release_id
		 WHERE d.state IN ('runtime_ready','degraded','serving')
		   AND NOT EXISTS (
		     SELECT 1 FROM operations active
		      WHERE active.environment_id=d.environment_id
		        AND active.state IN ('pending','leased','running','waiting','cancelling','rolling_back')
		   )
		   AND NOT EXISTS (
		     SELECT 1 FROM m4_rollout_coordinations rollout
		      WHERE rollout.environment_id=d.environment_id
		        AND rollout.phase NOT IN ('completed','failed','rolled_back')
		   )
		   AND NOT EXISTS (
		     SELECT 1 FROM m4_service_observations observed
		      WHERE observed.deployment_id=d.id AND observed.observed_at>$1
		   )
		 ORDER BY d.updated_at,d.id
		 LIMIT $2`, olderThan.UTC(), limit)
	if err != nil {
		return nil, fmt.Errorf("list M4 observation candidates: %w", err)
	}
	defer rows.Close()
	values := make([]M4ObservationCandidate, 0, limit)
	for rows.Next() {
		var candidate M4ObservationCandidate
		var state string
		if err := rows.Scan(&candidate.Deployment.ID, &candidate.Deployment.ApplicationID, &candidate.Deployment.EnvironmentID, &candidate.Deployment.ReleaseID, &state, &candidate.Deployment.CreatedAt, &candidate.Deployment.UpdatedAt); err != nil {
			return nil, err
		}
		candidate.Deployment.Status = domain.DeploymentStatus(state)
		if err := candidate.Deployment.Validate(); err != nil {
			return nil, err
		}
		values = append(values, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

// ListM4LogCollectionCandidates selects at most limit service snapshots that
// need a typed Agent logs task. The service name comes from the immutable M2
// runtime spec; callers never accept a container name or command from users.
func (s *Store) ListM4LogCollectionCandidates(ctx context.Context, olderThan time.Time, limit int) ([]M4LogCollectionCandidate, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	limit = normalizeM4Limit(limit)
	if olderThan.IsZero() {
		olderThan = m4Now(s, time.Time{}).Add(-30 * time.Second)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.id,e.application_id,d.environment_id,d.release_id,d.state,d.created_at,d.updated_at,
		       service.value->>'name' AS service_name
		  FROM deployments d
		  JOIN environments e ON e.id=d.environment_id
		  JOIN m2_release_runtime_specs m2 ON m2.release_id=d.release_id
		 CROSS JOIN LATERAL jsonb_array_elements(m2.spec->'services') AS service(value)
		 WHERE d.state IN ('runtime_ready','degraded','serving')
		   AND length(trim(COALESCE(service.value->>'name',''))) > 0
		   AND NOT EXISTS (
		     SELECT 1 FROM operations active
		      WHERE active.environment_id=d.environment_id
		        AND active.state IN ('pending','leased','running','waiting','cancelling','rolling_back')
		   )
		   AND NOT EXISTS (
		     SELECT 1 FROM m4_rollout_coordinations rollout
		      WHERE rollout.environment_id=d.environment_id
		        AND rollout.phase NOT IN ('completed','failed','rolled_back')
		   )
		   AND NOT EXISTS (
		     SELECT 1 FROM m4_log_indexes logs
		      WHERE logs.deployment_id=d.id
		        AND logs.service_name=service.value->>'name'
		        AND logs.category='runtime'
		        AND logs.retired_at IS NULL
		        AND logs.created_at>$1
		   )
		 ORDER BY (
		   SELECT MAX(logs.created_at) FROM m4_log_indexes logs
		    WHERE logs.deployment_id=d.id
		      AND logs.service_name=service.value->>'name'
		      AND logs.category='runtime'
		      AND logs.retired_at IS NULL
		 ) NULLS FIRST,d.updated_at,d.id,service.value->>'name'
		 LIMIT $2`, olderThan.UTC(), limit)
	if err != nil {
		return nil, fmt.Errorf("list M4 log collection candidates: %w", err)
	}
	defer rows.Close()
	values := make([]M4LogCollectionCandidate, 0, limit)
	for rows.Next() {
		var candidate M4LogCollectionCandidate
		var state string
		if err := rows.Scan(&candidate.Deployment.ID, &candidate.Deployment.ApplicationID, &candidate.Deployment.EnvironmentID, &candidate.Deployment.ReleaseID, &state, &candidate.Deployment.CreatedAt, &candidate.Deployment.UpdatedAt, &candidate.ServiceName); err != nil {
			return nil, err
		}
		candidate.Deployment.Status = domain.DeploymentStatus(state)
		if err := candidate.Deployment.Validate(); err != nil {
			return nil, err
		}
		if strings.TrimSpace(candidate.ServiceName) == "" {
			return nil, domain.ValidationError("M4 log collection service name is empty")
		}
		values = append(values, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

// ReserveWebhookEvent creates or deduplicates a logical notification. The
// returned duplicate flag is true only for a same-digest replay.
func (s *Store) ReserveWebhookEvent(ctx context.Context, event WebhookEventLedger, now time.Time) (WebhookEventLedger, bool, error) {
	if event.DeliveryID == "" {
		event.DeliveryID = "delivery_" + strings.TrimPrefix(m1Digest([]byte(event.EndpointID.String()+"\x00"+event.EventID.String())), "sha256:")[:32]
	}
	if event.IdempotencyKey == "" {
		event.IdempotencyKey = "legacy:" + event.EventID.String()
	}
	if event.RequestDigest == "" {
		event.RequestDigest = m1Digest([]byte(event.EndpointID.String() + "\x00" + event.EventID.String() + "\x00" + event.PayloadDigest))
	}
	return s.ReserveWebhookDelivery(ctx, WebhookDeliveryRequest{DeliveryID: event.DeliveryID, EndpointID: event.EndpointID, EventID: event.EventID, EventType: event.EventType, PayloadDigest: event.PayloadDigest, Payload: event.Payload, IdempotencyKey: event.IdempotencyKey, RequestDigest: event.RequestDigest, OccurredAt: event.OccurredAt}, now)
}

// ReserveWebhookDelivery durably records an already-redacted canonical
// notification and its first due time. It deduplicates both the caller key
// and the receiver-visible endpoint/event identity across controller restarts.
func (s *Store) ReserveWebhookDelivery(ctx context.Context, request WebhookDeliveryRequest, now time.Time) (WebhookEventLedger, bool, error) {
	if err := s.requireDB(); err != nil {
		return WebhookEventLedger{}, false, err
	}
	now = m4Now(s, now)
	if request.OccurredAt.IsZero() {
		request.OccurredAt = now
	}
	request.EventType, request.PayloadDigest, request.IdempotencyKey, request.RequestDigest = strings.TrimSpace(request.EventType), strings.TrimSpace(request.PayloadDigest), strings.TrimSpace(request.IdempotencyKey), strings.TrimSpace(request.RequestDigest)
	canonical, digest, err := canonicalM4WebhookPayload(request.Payload)
	if err != nil || digest != request.PayloadDigest {
		return WebhookEventLedger{}, false, domain.ValidationError("webhook delivery payload digest does not match canonical redacted payload")
	}
	request.Payload = canonical
	if err := request.Validate(); err != nil {
		return WebhookEventLedger{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return WebhookEventLedger{}, false, err
	}
	rollback := func(cause error) (WebhookEventLedger, bool, error) {
		return WebhookEventLedger{}, false, rollbackTx(tx, cause)
	}
	var enabled bool
	if err := tx.QueryRowContext(ctx, `SELECT enabled FROM m4_webhook_endpoints WHERE id=$1 FOR SHARE`, request.EndpointID.String()).Scan(&enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return rollback(ErrNotFound)
		}
		return rollback(err)
	}
	if !enabled {
		return rollback(ErrWebhookEndpointDisabled)
	}
	var existingID, existingDigest string
	err = tx.QueryRowContext(ctx, `SELECT delivery_id,request_digest FROM m4_webhook_events WHERE endpoint_id=$1 AND idempotency_key=$2 FOR UPDATE`, request.EndpointID.String(), request.IdempotencyKey).Scan(&existingID, &existingDigest)
	if err == nil {
		if existingDigest != request.RequestDigest {
			return rollback(ErrIdempotencyConflict)
		}
		stored, err := loadM4WebhookEventByDeliveryTx(ctx, tx, existingID, false)
		if err != nil {
			return rollback(err)
		}
		if err := tx.Commit(); err != nil {
			return WebhookEventLedger{}, false, fmt.Errorf("%w: commit webhook key replay: %v", ErrOutcomeUnknown, err)
		}
		return stored, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return rollback(err)
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO m4_webhook_events(endpoint_id,delivery_id,event_id,event_type,payload_digest,payload,idempotency_key,request_digest,occurred_at,delivery_status,received_count,attempt_count,next_attempt_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,'pending',1,0,$10,$10,$10) ON CONFLICT(endpoint_id,event_id) DO NOTHING`, request.EndpointID.String(), request.DeliveryID, request.EventID.String(), request.EventType, request.PayloadDigest, request.Payload, request.IdempotencyKey, request.RequestDigest, request.OccurredAt.UTC(), now)
	if err != nil {
		return rollback(err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return rollback(err)
	}
	if inserted == 0 {
		stored, err := loadM4WebhookEventTx(ctx, tx, request.EndpointID, request.EventID, true)
		if err != nil {
			return rollback(err)
		}
		if stored.PayloadDigest != request.PayloadDigest || stored.EventType != request.EventType {
			return rollback(ErrWebhookPayloadConflict)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE m4_webhook_events SET received_count=received_count+1,updated_at=$3 WHERE endpoint_id=$1 AND event_id=$2`, request.EndpointID.String(), request.EventID.String(), now); err != nil {
			return rollback(err)
		}
		stored.ReceivedCount++
		stored.UpdatedAt = now
		if err := tx.Commit(); err != nil {
			return WebhookEventLedger{}, false, fmt.Errorf("%w: commit webhook replay: %v", ErrOutcomeUnknown, err)
		}
		return stored, true, nil
	}
	event := WebhookEventLedger{EndpointID: request.EndpointID, DeliveryID: request.DeliveryID, EventID: request.EventID, EventType: request.EventType, PayloadDigest: request.PayloadDigest, Payload: append(json.RawMessage(nil), request.Payload...), IdempotencyKey: request.IdempotencyKey, RequestDigest: request.RequestDigest, OccurredAt: request.OccurredAt.UTC(), Status: WebhookDeliveryPending, ReceivedCount: 1, NextAttemptAt: pointerM4Time(now), CreatedAt: now, UpdatedAt: now}
	if err := tx.Commit(); err != nil {
		return WebhookEventLedger{}, false, fmt.Errorf("%w: commit webhook event: %v", ErrOutcomeUnknown, err)
	}
	return event, false, nil
}

// RecordWebhookAttempt appends one immutable delivery attempt and atomically
// advances the logical event. Attempt numbers must be gap-free.
func (s *Store) RecordWebhookAttempt(ctx context.Context, attempt WebhookAttempt, now time.Time) (WebhookEventLedger, error) {
	if err := s.requireDB(); err != nil {
		return WebhookEventLedger{}, err
	}
	now = m4Now(s, now)
	if attempt.CreatedAt.IsZero() {
		attempt.CreatedAt = now
	}
	attempt.ErrorCode = foundation.RedactText(strings.TrimSpace(attempt.ErrorCode))
	if err := attempt.Validate(); err != nil {
		return WebhookEventLedger{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return WebhookEventLedger{}, err
	}
	rollback := func(cause error) (WebhookEventLedger, error) { return WebhookEventLedger{}, rollbackTx(tx, cause) }
	event, err := loadM4WebhookEventTx(ctx, tx, attempt.EndpointID, attempt.EventID, true)
	if err != nil {
		return rollback(err)
	}
	if event.Status == WebhookDeliveryDelivered {
		return rollback(ErrWebhookEventDelivered)
	}
	if attempt.AttemptNumber != event.AttemptCount+1 {
		return rollback(ErrWebhookAttemptOrder)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO m4_webhook_attempts(id,endpoint_id,event_id,attempt_number,request_digest,status,http_status,error_code,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, attempt.ID.String(), attempt.EndpointID.String(), attempt.EventID.String(), attempt.AttemptNumber, attempt.RequestDigest, attempt.Status, attempt.HTTPStatus, nullableM4String(attempt.ErrorCode), attempt.CreatedAt.UTC()); err != nil {
		return rollback(err)
	}
	event.AttemptCount, event.LastAttemptAt, event.UpdatedAt = attempt.AttemptNumber, pointerM4Time(now), now
	switch attempt.Status {
	case WebhookAttemptDelivered:
		event.Status, event.DeliveredAt, event.NextAttemptAt, event.FailureReason = WebhookDeliveryDelivered, pointerM4Time(now), nil, ""
	case WebhookAttemptRetryable:
		event.Status, event.NextAttemptAt, event.FailureReason = WebhookDeliveryRetryWait, pointerM4Time(now), attempt.ErrorCode
	case WebhookAttemptFailed:
		event.Status, event.NextAttemptAt, event.FailureReason = WebhookDeliveryFailed, nil, attempt.ErrorCode
		if event.FailureReason == "" {
			event.FailureReason = "webhook delivery failed"
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE m4_webhook_events SET delivery_status=$3,attempt_count=$4,next_attempt_at=$5,lease_owner=NULL,lease_until=NULL,last_attempt_at=$6,delivered_at=$7,failure_reason=$8,updated_at=$9 WHERE endpoint_id=$1 AND event_id=$2`, event.EndpointID.String(), event.EventID.String(), event.Status, event.AttemptCount, event.NextAttemptAt, event.LastAttemptAt, event.DeliveredAt, nullableM4String(event.FailureReason), now); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return WebhookEventLedger{}, fmt.Errorf("%w: commit webhook attempt: %v", ErrOutcomeUnknown, err)
	}
	return event, nil
}

// ClaimDueWebhookDeliveries atomically leases due pending/retry entries using
// SKIP LOCKED. A second worker cannot receive the same row, and an expired
// lease becomes claimable after a controller crash.
func (s *Store) ClaimDueWebhookDeliveries(ctx context.Context, workerID string, now time.Time, leaseDuration time.Duration, limit int) ([]WebhookEventLedger, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" || leaseDuration <= 0 {
		return nil, domain.ValidationError("webhook claim worker and lease duration are required")
	}
	limit = normalizeM4Limit(limit)
	now = m4Now(s, now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	rollback := func(cause error) ([]WebhookEventLedger, error) { return nil, rollbackTx(tx, cause) }
	rows, err := tx.QueryContext(ctx, `WITH due AS (SELECT event.endpoint_id,event.event_id FROM m4_webhook_events event JOIN m4_webhook_endpoints endpoint ON endpoint.id=event.endpoint_id WHERE endpoint.enabled AND event.delivery_status IN ('pending','retry_wait') AND event.next_attempt_at <= $1 AND (event.lease_until IS NULL OR event.lease_until <= $1) ORDER BY event.next_attempt_at,event.endpoint_id,event.event_id LIMIT $2 FOR UPDATE OF event SKIP LOCKED) UPDATE m4_webhook_events event SET lease_owner=$3,lease_until=$4,updated_at=$1 FROM due WHERE event.endpoint_id=due.endpoint_id AND event.event_id=due.event_id RETURNING event.endpoint_id,event.delivery_id,event.event_id,event.event_type,event.payload_digest,event.payload,event.idempotency_key,event.request_digest,event.occurred_at,event.delivery_status,event.received_count,event.attempt_count,event.next_attempt_at,event.lease_owner,event.lease_until,event.last_attempt_at,event.delivered_at,event.failure_reason,event.created_at,event.updated_at`, now, limit, workerID, now.Add(leaseDuration))
	if err != nil {
		return rollback(err)
	}
	defer rows.Close()
	result := make([]WebhookEventLedger, 0)
	for rows.Next() {
		item, err := scanM4WebhookEvent(rows)
		if err != nil {
			return rollback(err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("%w: commit webhook claims: %v", ErrOutcomeUnknown, err)
	}
	return result, nil
}

// AppendWebhookDeliveryAttempt is the lease-owner checked durable completion
// of one claimed send. It persists an immutable attempt, clears the lease,
// and stores the exact retry due time selected by the controller (1/5/30s).
func (s *Store) AppendWebhookDeliveryAttempt(ctx context.Context, attempt WebhookDeliveryAttempt) (WebhookEventLedger, error) {
	if err := s.requireDB(); err != nil {
		return WebhookEventLedger{}, err
	}
	attempt.Failure, attempt.FailureCode = foundation.RedactText(strings.TrimSpace(attempt.Failure)), foundation.RedactText(strings.TrimSpace(attempt.FailureCode))
	if err := attempt.Validate(); err != nil {
		return WebhookEventLedger{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return WebhookEventLedger{}, err
	}
	rollback := func(cause error) (WebhookEventLedger, error) { return WebhookEventLedger{}, rollbackTx(tx, cause) }
	event, err := loadM4WebhookEventByDeliveryTx(ctx, tx, attempt.DeliveryID, true)
	if err != nil {
		return rollback(err)
	}
	if event.EventID != attempt.EventID {
		return rollback(ErrLeaseLost)
	}
	requestDigest := m1Digest([]byte(event.RequestDigest + "\x00" + fmt.Sprint(attempt.Attempt) + "\x00" + string(attempt.Status)))
	storedStatus := WebhookAttemptRetryable
	if attempt.Status == WebhookDeliveryDelivered {
		storedStatus = WebhookAttemptDelivered
	}
	if attempt.Status == WebhookDeliveryFailed {
		storedStatus = WebhookAttemptFailed
	}
	if attempt.Attempt == event.AttemptCount {
		var storedDigest, persistedStatus string
		var persistedCode sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT request_digest,status,error_code FROM m4_webhook_attempts WHERE endpoint_id=$1 AND event_id=$2 AND attempt_number=$3`, event.EndpointID.String(), event.EventID.String(), attempt.Attempt).Scan(&storedDigest, &persistedStatus, &persistedCode)
		if err == nil && storedDigest == requestDigest && persistedStatus == string(storedStatus) && persistedCode.String == attempt.FailureCode {
			if err := tx.Commit(); err != nil {
				return WebhookEventLedger{}, fmt.Errorf("%w: commit webhook attempt replay: %v", ErrOutcomeUnknown, err)
			}
			return event, nil
		}
		return rollback(ErrWebhookAttemptOrder)
	}
	if event.LeaseOwner != attempt.LeaseOwner || event.LeaseUntil == nil || !event.LeaseUntil.After(attempt.At) {
		return rollback(ErrLeaseLost)
	}
	if event.Status == WebhookDeliveryDelivered || event.Status == WebhookDeliveryFailed {
		return rollback(ErrWebhookEventDelivered)
	}
	if attempt.Attempt != event.AttemptCount+1 {
		return rollback(ErrWebhookAttemptOrder)
	}
	attemptID := domain.ID("wha_" + strings.TrimPrefix(m1Digest([]byte(event.DeliveryID+"\x00"+fmt.Sprint(attempt.Attempt))), "sha256:")[:32])
	var httpStatus *int
	if storedStatus == WebhookAttemptDelivered {
		status := 200
		httpStatus = &status
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO m4_webhook_attempts(id,endpoint_id,event_id,attempt_number,request_digest,status,http_status,error_code,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, attemptID.String(), event.EndpointID.String(), event.EventID.String(), attempt.Attempt, requestDigest, storedStatus, httpStatus, nullableM4String(attempt.FailureCode), attempt.At.UTC()); err != nil {
		return rollback(err)
	}
	event.AttemptCount, event.LastAttemptAt, event.UpdatedAt, event.LeaseOwner, event.LeaseUntil = attempt.Attempt, pointerM4Time(attempt.At.UTC()), attempt.At.UTC(), "", nil
	switch attempt.Status {
	case WebhookDeliveryDelivered:
		event.Status, event.DeliveredAt, event.NextAttemptAt, event.FailureReason = WebhookDeliveryDelivered, pointerM4Time(attempt.At.UTC()), nil, ""
	case WebhookDeliveryPending:
		next := attempt.NextAttemptAt.UTC()
		event.Status, event.NextAttemptAt, event.FailureReason = WebhookDeliveryRetryWait, &next, attempt.Failure
	case WebhookDeliveryFailed:
		event.Status, event.NextAttemptAt, event.FailureReason = WebhookDeliveryFailed, nil, attempt.Failure
	}
	if _, err := tx.ExecContext(ctx, `UPDATE m4_webhook_events SET delivery_status=$2,attempt_count=$3,next_attempt_at=$4,lease_owner=NULL,lease_until=NULL,last_attempt_at=$5,delivered_at=$6,failure_reason=$7,updated_at=$8 WHERE delivery_id=$1`, event.DeliveryID, event.Status, event.AttemptCount, event.NextAttemptAt, event.LastAttemptAt, event.DeliveredAt, nullableM4String(event.FailureReason), event.UpdatedAt); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return WebhookEventLedger{}, fmt.Errorf("%w: commit webhook attempt: %v", ErrOutcomeUnknown, err)
	}
	return event, nil
}

func (s *Store) ListPendingWebhookEvents(ctx context.Context, limit int) ([]WebhookEventLedger, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	limit = normalizeM4Limit(limit)
	rows, err := s.db.QueryContext(ctx, `SELECT e.endpoint_id,e.delivery_id,e.event_id,e.event_type,e.payload_digest,e.payload,e.idempotency_key,e.request_digest,e.occurred_at,e.delivery_status,e.received_count,e.attempt_count,e.next_attempt_at,e.lease_owner,e.lease_until,e.last_attempt_at,e.delivered_at,e.failure_reason,e.created_at,e.updated_at FROM m4_webhook_events e JOIN m4_webhook_endpoints p ON p.id=e.endpoint_id WHERE p.enabled AND e.delivery_status IN ('pending','retry_wait') ORDER BY e.next_attempt_at,e.event_id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]WebhookEventLedger, 0)
	for rows.Next() {
		item, err := scanM4WebhookEvent(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) AppendLogIndex(ctx context.Context, index LogIndex, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	now = m4Now(s, now)
	if index.CreatedAt.IsZero() {
		index.CreatedAt = now
	}
	if err := index.Validate(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := m4ValidateLogAssociationsTx(ctx, tx, index); err != nil {
		return rollbackTx(tx, err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO m4_log_indexes(id,application_id,service_name,release_id,deployment_id,operation_id,category,path,segment,byte_size,retired_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, index.ID.String(), index.ApplicationID.String(), index.ServiceName, nullableM4ID(index.ReleaseID), nullableM4ID(index.DeploymentID), nullableM4ID(index.OperationID), index.Category, index.Path, index.Segment, index.ByteSize, index.RetiredAt, index.CreatedAt.UTC())
	if err != nil {
		return rollbackTx(tx, err)
	}
	return tx.Commit()
}

func (s *Store) RetireOrdinaryLogIndex(ctx context.Context, id domain.ID, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	if err := domain.RequireID(id, "log index id"); err != nil {
		return err
	}
	now = m4Now(s, now)
	var category string
	err := s.db.QueryRowContext(ctx, `SELECT category FROM m4_log_indexes WHERE id=$1`, id.String()).Scan(&category)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if category == string(LogIndexAudit) {
		return ErrAuditLogImmutable
	}
	result, err := s.db.ExecContext(ctx, `UPDATE m4_log_indexes SET retired_at=$2 WHERE id=$1 AND retired_at IS NULL`, id.String(), now)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListLogIndexes(ctx context.Context, applicationID domain.ID, includeRetired bool, limit int) ([]LogIndex, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if err := domain.RequireID(applicationID, "log index application id"); err != nil {
		return nil, err
	}
	limit = normalizeM4Limit(limit)
	statement := `SELECT id,application_id,service_name,release_id,deployment_id,operation_id,category,path,segment,byte_size,retired_at,created_at FROM m4_log_indexes WHERE application_id=$1`
	if !includeRetired {
		statement += ` AND retired_at IS NULL`
	}
	statement += ` ORDER BY created_at DESC,id DESC LIMIT $2`
	rows, err := s.db.QueryContext(ctx, statement, applicationID.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]LogIndex, 0)
	for rows.Next() {
		item, err := scanM4LogIndex(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

// ListActiveOrdinaryLogIndexes is the filesystem-GC reconciliation surface.
// Audit indexes are excluded by construction and can never be retired through
// this path.
func (s *Store) ListActiveOrdinaryLogIndexes(ctx context.Context, limit int) ([]LogIndex, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 10000 {
		return nil, domain.ValidationError("ordinary log reconciliation limit must be between 1 and 10000")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,application_id,service_name,release_id,deployment_id,operation_id,category,path,segment,byte_size,retired_at,created_at FROM m4_log_indexes WHERE retired_at IS NULL AND category IN ('build','runtime') ORDER BY created_at,id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]LogIndex, 0, limit)
	for rows.Next() {
		item, err := scanM4LogIndex(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) GetOperationFact(ctx context.Context, operationID domain.ID) (OperationFact, error) {
	if err := s.requireDB(); err != nil {
		return OperationFact{}, err
	}
	if err := domain.RequireID(operationID, "operation id"); err != nil {
		return OperationFact{}, err
	}
	fact, err := scanM4OperationFact(s.db.QueryRowContext(ctx, m4OperationFactQuery+` WHERE o.id=$1`, operationID.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return OperationFact{}, ErrNotFound
	}
	return fact, err
}

func (s *Store) ListOperationFacts(ctx context.Context, applicationID domain.ID, limit int) ([]OperationFact, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if err := domain.RequireID(applicationID, "operation application id"); err != nil {
		return nil, err
	}
	limit = normalizeM4Limit(limit)
	rows, err := s.db.QueryContext(ctx, m4OperationFactQuery+` WHERE o.application_id=$1 ORDER BY o.updated_at DESC,o.id DESC LIMIT $2`, applicationID.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]OperationFact, 0)
	for rows.Next() {
		item, err := scanM4OperationFact(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

// PreviousSuccessfulRelease selects the latest earlier release that has a
// runtime-ready/degraded/serving deployment for the same application. It does
// not promise data rollback; that warning remains a controller/UI concern.
func (s *Store) PreviousSuccessfulRelease(ctx context.Context, applicationID, currentReleaseID domain.ID) (domain.Release, error) {
	releaseID, err := s.PreviousSuccessfulReleaseID(ctx, applicationID, currentReleaseID)
	if err != nil {
		return domain.Release{}, err
	}
	return s.GetCompleteRelease(ctx, releaseID)
}

// PreviousSuccessfulReleaseID is the narrow rollback selector. Controllers
// that already hold immutable release details can use this ID without asking
// a legacy release reader to reconstruct an unrelated digest projection.
func (s *Store) PreviousSuccessfulReleaseID(ctx context.Context, applicationID, currentReleaseID domain.ID) (domain.ID, error) {
	if err := s.requireDB(); err != nil {
		return "", err
	}
	if err := domain.RequireID(applicationID, "release application id"); err != nil {
		return "", err
	}
	if err := domain.RequireID(currentReleaseID, "current release id"); err != nil {
		return "", err
	}
	var releaseID domain.ID
	err := s.db.QueryRowContext(ctx, `SELECT r.id FROM releases r WHERE r.application_id=$1 AND r.id<>$2 AND r.release_status='ready' AND EXISTS (SELECT 1 FROM deployments d JOIN environments e ON e.id=d.environment_id JOIN operations succeeded ON succeeded.deployment_id=d.id WHERE d.release_id=r.id AND e.application_id=$1 AND succeeded.operation_type IN ('deploy','redeploy','rollback') AND succeeded.state IN ('succeeded','rolled_back')) ORDER BY r.created_at DESC,r.id DESC LIMIT 1`, applicationID.String(), currentReleaseID.String()).Scan(&releaseID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return releaseID, nil
}

const m4OperationFactQuery = `SELECT o.id,o.application_id,o.environment_id,o.target_ref,o.operation_type,o.idempotency_key,o.state,COALESCE(o.failure_reason,''),o.created_at,o.updated_at,d.id,d.state,d.release_id,COALESCE(r.version,0),COALESCE(d.runtime_healthy,false),d.last_observed_at FROM operations o LEFT JOIN deployments d ON d.id=o.deployment_id LEFT JOIN releases r ON r.id=d.release_id`

func m4ValidateLogAssociationsTx(ctx context.Context, tx *sql.Tx, index LogIndex) error {
	checks := []struct {
		id        domain.ID
		statement string
		label     string
	}{{index.ReleaseID, `SELECT application_id FROM releases WHERE id=$1`, `release`}, {index.DeploymentID, `SELECT e.application_id FROM deployments d JOIN environments e ON e.id=d.environment_id WHERE d.id=$1`, `deployment`}, {index.OperationID, `SELECT application_id FROM operations WHERE id=$1`, `operation`}}
	for _, check := range checks {
		if check.id.Empty() {
			continue
		}
		var app string
		err := tx.QueryRowContext(ctx, check.statement, check.id.String()).Scan(&app)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if app != index.ApplicationID.String() {
			return domain.ValidationError("log index " + check.label + " does not belong to application")
		}
	}
	return nil
}

func loadM4WebhookEventTx(ctx context.Context, tx *sql.Tx, endpointID, eventID domain.ID, lock bool) (WebhookEventLedger, error) {
	query := `SELECT endpoint_id,delivery_id,event_id,event_type,payload_digest,payload,idempotency_key,request_digest,occurred_at,delivery_status,received_count,attempt_count,next_attempt_at,lease_owner,lease_until,last_attempt_at,delivered_at,failure_reason,created_at,updated_at FROM m4_webhook_events WHERE endpoint_id=$1 AND event_id=$2`
	if lock {
		query += ` FOR UPDATE`
	}
	event, err := scanM4WebhookEvent(tx.QueryRowContext(ctx, query, endpointID.String(), eventID.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return WebhookEventLedger{}, ErrNotFound
	}
	return event, err
}

func loadM4WebhookEventByDeliveryTx(ctx context.Context, tx *sql.Tx, deliveryID string, lock bool) (WebhookEventLedger, error) {
	query := `SELECT endpoint_id,delivery_id,event_id,event_type,payload_digest,payload,idempotency_key,request_digest,occurred_at,delivery_status,received_count,attempt_count,next_attempt_at,lease_owner,lease_until,last_attempt_at,delivered_at,failure_reason,created_at,updated_at FROM m4_webhook_events WHERE delivery_id=$1`
	if lock {
		query += ` FOR UPDATE`
	}
	event, err := scanM4WebhookEvent(tx.QueryRowContext(ctx, query, deliveryID))
	if errors.Is(err, sql.ErrNoRows) {
		return WebhookEventLedger{}, ErrNotFound
	}
	return event, err
}

func scanM4WebhookEvent(scanner interface{ Scan(...any) error }) (WebhookEventLedger, error) {
	var value WebhookEventLedger
	var next, leaseUntil, last, delivered sql.NullTime
	var leaseOwner, failure sql.NullString
	err := scanner.Scan(&value.EndpointID, &value.DeliveryID, &value.EventID, &value.EventType, &value.PayloadDigest, &value.Payload, &value.IdempotencyKey, &value.RequestDigest, &value.OccurredAt, &value.Status, &value.ReceivedCount, &value.AttemptCount, &next, &leaseOwner, &leaseUntil, &last, &delivered, &failure, &value.CreatedAt, &value.UpdatedAt)
	if err != nil {
		return WebhookEventLedger{}, err
	}
	if next.Valid {
		time := next.Time.UTC()
		value.NextAttemptAt = &time
	}
	value.LeaseOwner = leaseOwner.String
	if leaseUntil.Valid {
		time := leaseUntil.Time.UTC()
		value.LeaseUntil = &time
	}
	if last.Valid {
		time := last.Time.UTC()
		value.LastAttemptAt = &time
	}
	if delivered.Valid {
		time := delivered.Time.UTC()
		value.DeliveredAt = &time
	}
	value.FailureReason = failure.String
	value.OccurredAt, value.CreatedAt, value.UpdatedAt = value.OccurredAt.UTC(), value.CreatedAt.UTC(), value.UpdatedAt.UTC()
	if err := value.Validate(); err != nil {
		return WebhookEventLedger{}, fmt.Errorf("invalid persisted webhook event: %w", err)
	}
	return value, nil
}

func scanM4LogIndex(scanner interface{ Scan(...any) error }) (LogIndex, error) {
	var value LogIndex
	var release, deployment, operation sql.NullString
	var retired sql.NullTime
	err := scanner.Scan(&value.ID, &value.ApplicationID, &value.ServiceName, &release, &deployment, &operation, &value.Category, &value.Path, &value.Segment, &value.ByteSize, &retired, &value.CreatedAt)
	if err != nil {
		return LogIndex{}, err
	}
	if release.Valid {
		value.ReleaseID = domain.ID(release.String)
	}
	if deployment.Valid {
		value.DeploymentID = domain.ID(deployment.String)
	}
	if operation.Valid {
		value.OperationID = domain.ID(operation.String)
	}
	if retired.Valid {
		time := retired.Time.UTC()
		value.RetiredAt = &time
	}
	value.CreatedAt = value.CreatedAt.UTC()
	if err := value.Validate(); err != nil {
		return LogIndex{}, fmt.Errorf("invalid persisted log index: %w", err)
	}
	return value, nil
}

func scanM4OperationFact(scanner interface{ Scan(...any) error }) (OperationFact, error) {
	var fact OperationFact
	var operationType, status string
	var deploymentID, deploymentState, releaseID sql.NullString
	var last sql.NullTime
	err := scanner.Scan(&fact.Operation.ID, &fact.Operation.ApplicationID, &fact.Operation.EnvironmentID, &fact.Operation.TargetRef, &operationType, &fact.Operation.IdempotencyKey, &status, &fact.Operation.FailureReason, &fact.Operation.CreatedAt, &fact.Operation.UpdatedAt, &deploymentID, &deploymentState, &releaseID, &fact.ReleaseVersion, &fact.RuntimeHealthy, &last)
	if err != nil {
		return OperationFact{}, err
	}
	fact.Operation.Type = domain.OperationType(operationType)
	fact.Operation.Status = domain.OperationStatus(status)
	fact.Operation.CreatedAt, fact.Operation.UpdatedAt = fact.Operation.CreatedAt.UTC(), fact.Operation.UpdatedAt.UTC()
	if deploymentID.Valid {
		fact.DeploymentID = domain.ID(deploymentID.String)
		fact.DeploymentState = domain.DeploymentStatus(deploymentState.String)
	}
	if releaseID.Valid {
		fact.ReleaseID = domain.ID(releaseID.String)
	}
	if last.Valid {
		time := last.Time.UTC()
		fact.LastObservedAt = &time
	}
	if err := fact.Operation.Validate(); err != nil {
		return OperationFact{}, fmt.Errorf("invalid persisted operation fact: %w", err)
	}
	return fact, nil
}

func jsonM4(value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return payload, nil
}
func decodeM4EventTypes(payload []byte, target *[]string) error {
	if err := json.Unmarshal(payload, target); err != nil {
		return err
	}
	*target = m4NormalizeEventTypes(*target)
	return nil
}
func m4NormalizeEventTypes(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
func m4Now(s *Store, value time.Time) time.Time {
	if value.IsZero() {
		value = s.now()
	}
	return value.UTC()
}
func nullableM4ID(value domain.ID) any {
	if value.Empty() {
		return nil
	}
	return value.String()
}
func nullableM4String(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
func pointerM4Time(value time.Time) *time.Time { return &value }
func normalizeM4Limit(limit int) int {
	if limit <= 0 {
		return defaultQueryLimit
	}
	if limit > maxQueryLimit {
		return maxQueryLimit
	}
	return limit
}
