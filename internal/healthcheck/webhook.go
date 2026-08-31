package healthcheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

const (
	webhookConfigSchema         = "open_card.host_alert_webhook.config.v1"
	deliveryHealthSchema        = "open_card.host_alert_webhook.delivery_health.v1"
	webhookDeliveryEventSchema  = "open_card.host_alert_webhook.delivery_event.v1"
	webhookDeliveryEventVersion = "webhook_delivery_event_v1"
	webhookHealthSubjectVersion = "webhook_health_v1"
	maxWebhookEndpointID        = 128
	maxWebhookURL               = 2048
	maxWebhookSecretField       = 128
	maxWebhookRevision          = int64(1_000_000_000_000)
	maxWebhookFailures          = int64(1_000_000_000)
)

var (
	webhookDigestPattern     = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	webhookOpaqueIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	webhookOpaqueTextPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	webhookHostnamePattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

// WebhookConfigV1 is the root-owned, secret-free configuration identity for
// the single system-scope host-alert receiver. SecretReference is an opaque
// domain reference only; this contract never receives secret material.
type WebhookConfigV1 struct {
	Schema          string                 `json:"schema"`
	EndpointID      domain.ID              `json:"endpoint_id"`
	URL             string                 `json:"url"`
	SecretReference domain.SecretReference `json:"secret_reference"`
	Enabled         bool                   `json:"enabled"`
	ConfiguredAt    time.Time              `json:"configured_at"`
}

// WebhookDeliveryHealthStatus is the bounded delivery-health projection. It
// deliberately contains no payload, response, error, or provider details.
type WebhookDeliveryHealthStatus string

const (
	WebhookDeliveryUnproven WebhookDeliveryHealthStatus = "unproven"
	// WebhookDeliveryPending records an accepted delivery before any provider
	// attempt has been made. It is deliberately distinct from a retryable
	// failure so health can retain the oldest accepted occurrence precisely.
	WebhookDeliveryPending          WebhookDeliveryHealthStatus = "pending"
	WebhookDeliveryDelivered        WebhookDeliveryHealthStatus = "delivered"
	WebhookDeliveryRetryableFailure WebhookDeliveryHealthStatus = "retryable_failure"
	WebhookDeliveryFailed           WebhookDeliveryHealthStatus = "failed"
)

// WebhookDeliveryEventV1 is the strict, secret-free identity of one durable
// host-health notification. Recovery notifications retain the recovered
// incident fingerprint rather than the synthetic healthy fingerprint.
type WebhookDeliveryEventV1 struct {
	Schema              string `json:"schema"`
	EventID             string `json:"event_id"`
	IncidentFingerprint string `json:"incident_fingerprint"`
	IncidentRevision    int64  `json:"incident_revision"`
	PendingNotification string `json:"pending_notification"`
	NotificationStage   int    `json:"notification_stage"`
}

func (v WebhookDeliveryEventV1) Validate() error {
	if v.Schema != webhookDeliveryEventSchema || !webhookDigestPattern.MatchString(v.EventID) || !shaPattern.MatchString(v.IncidentFingerprint) || v.IncidentRevision < 1 || v.IncidentRevision > maxWebhookRevision || !validWebhookPendingNotification(v.PendingNotification) || !validWebhookNotificationStage(v.PendingNotification, v.NotificationStage) || v.EventID != canonicalWebhookDeliveryEventID(v.IncidentFingerprint, v.IncidentRevision, v.PendingNotification, v.NotificationStage) {
		return errors.New("invalid webhook delivery event")
	}
	return nil
}

// WebhookDeliveryEventFromIncident derives the one stable delivery identity
// for a currently pending host-health notification.
func WebhookDeliveryEventFromIncident(state IncidentState) (WebhookDeliveryEventV1, error) {
	if state.Validate() != nil || state.PendingNotification == "" {
		return WebhookDeliveryEventV1{}, errors.New("invalid webhook delivery incident")
	}
	fingerprint := state.Fingerprint
	if state.PendingNotification == "recovery" {
		fingerprint = state.RecoveryOf
	}
	event := WebhookDeliveryEventV1{Schema: webhookDeliveryEventSchema, IncidentFingerprint: fingerprint, IncidentRevision: state.Revision, PendingNotification: state.PendingNotification, NotificationStage: state.NotificationStage}
	event.EventID = canonicalWebhookDeliveryEventID(event.IncidentFingerprint, event.IncidentRevision, event.PendingNotification, event.NotificationStage)
	return event, event.Validate()
}

func canonicalWebhookDeliveryEventID(fingerprint string, revision int64, pending string, stage int) string {
	sum := sha256.Sum256([]byte(webhookDeliveryEventVersion + "\n" + fingerprint + "\n" + strconv.FormatInt(revision, 10) + "\n" + pending + "\n" + strconv.Itoa(stage)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validWebhookPendingNotification(value string) bool {
	return value == "occurrence" || value == "escalation" || value == "recovery"
}

func validWebhookNotificationStage(kind string, stage int) bool {
	switch kind {
	case "occurrence":
		return stage == 1
	case "escalation":
		return stage == 2 || stage == 3
	case "recovery":
		return stage == 0
	}
	return false
}

// DeliveryHealthV1 is the root-owned delivery observation associated with one
// exact WebhookConfigV1 digest. An absent observation is represented by a nil
// pointer in WebhookHealthObservation, never by a partially populated value.
type DeliveryHealthV1 struct {
	Schema                  string                      `json:"schema"`
	ConfigDigest            string                      `json:"config_digest"`
	Revision                int64                       `json:"revision"`
	OldestPendingAt         *time.Time                  `json:"oldest_pending_at,omitempty"`
	LastAttemptAt           *time.Time                  `json:"last_attempt_at,omitempty"`
	LastDeliveredAt         *time.Time                  `json:"last_delivered_at,omitempty"`
	Status                  WebhookDeliveryHealthStatus `json:"status"`
	ConsecutiveFailureCount int64                       `json:"consecutive_failure_count"`
	TerminalFailureCount    int64                       `json:"terminal_failure_count"`
	Event                   *WebhookDeliveryEventV1     `json:"event,omitempty"`
}

// WebhookHealthObservation is the only host-health read boundary for the
// system receiver. It is intentionally independent of application records and
// PostgreSQL so alerts remain observable while PostgreSQL is unavailable.
type WebhookHealthObservation struct {
	Config   *WebhookConfigV1
	Delivery *DeliveryHealthV1
}

// WebhookHealthSource returns the typed root-owned configuration and delivery
// observation. It must not resolve a secret or return raw provider output.
type WebhookHealthSource interface {
	WebhookHealth(context.Context) (WebhookHealthObservation, error)
}

func (v WebhookConfigV1) Validate() error {
	if v.Schema != webhookConfigSchema || !utc(v.ConfiguredAt) || len(v.EndpointID) == 0 || len(v.EndpointID) > maxWebhookEndpointID || !webhookOpaqueIDPattern.MatchString(v.EndpointID.String()) || len(v.URL) == 0 || len(v.URL) > maxWebhookURL || !canonicalPublicHTTPSURL(v.URL) {
		return errors.New("invalid webhook config")
	}
	if v.SecretReference.Validate() != nil || !validWebhookSecretReference(v.SecretReference) {
		return errors.New("invalid webhook config")
	}
	return nil
}

func (v DeliveryHealthV1) Validate() error {
	if v.Schema != deliveryHealthSchema || !webhookDigestPattern.MatchString(v.ConfigDigest) || v.Revision < 1 || v.Revision > maxWebhookRevision || v.ConsecutiveFailureCount < 0 || v.ConsecutiveFailureCount > maxWebhookFailures || v.TerminalFailureCount < 0 || v.TerminalFailureCount > maxWebhookFailures || !validDeliveryStatus(v.Status) {
		return errors.New("invalid webhook delivery health")
	}
	for _, value := range []*time.Time{v.OldestPendingAt, v.LastAttemptAt, v.LastDeliveredAt} {
		if value != nil && !utc(*value) {
			return errors.New("invalid webhook delivery health")
		}
	}
	if v.OldestPendingAt != nil && v.LastAttemptAt != nil && v.LastAttemptAt.Before(*v.OldestPendingAt) {
		return errors.New("invalid webhook delivery health")
	}
	if v.LastDeliveredAt != nil && v.LastAttemptAt != nil && v.LastAttemptAt.Before(*v.LastDeliveredAt) {
		return errors.New("invalid webhook delivery health")
	}
	switch v.Status {
	case WebhookDeliveryUnproven:
		if v.OldestPendingAt != nil || v.LastAttemptAt != nil || v.LastDeliveredAt != nil || v.ConsecutiveFailureCount != 0 || v.TerminalFailureCount != 0 || v.Event != nil {
			return errors.New("invalid webhook delivery health")
		}
	case WebhookDeliveryPending:
		if v.OldestPendingAt == nil || v.LastAttemptAt != nil || v.ConsecutiveFailureCount != 0 || v.TerminalFailureCount != 0 {
			return errors.New("invalid webhook delivery health")
		}
	case WebhookDeliveryDelivered:
		if v.OldestPendingAt != nil || v.LastAttemptAt == nil || v.LastDeliveredAt == nil || v.ConsecutiveFailureCount != 0 {
			return errors.New("invalid webhook delivery health")
		}
	case WebhookDeliveryRetryableFailure:
		if v.OldestPendingAt == nil || v.LastAttemptAt == nil || v.ConsecutiveFailureCount < 1 {
			return errors.New("invalid webhook delivery health")
		}
	case WebhookDeliveryFailed:
		if v.OldestPendingAt != nil || v.LastAttemptAt == nil || v.TerminalFailureCount < 1 {
			return errors.New("invalid webhook delivery health")
		}
	}
	if v.Status != WebhookDeliveryUnproven && (v.Event == nil || v.Event.Validate() != nil) {
		return errors.New("invalid webhook delivery health")
	}
	return nil
}

func validWebhookSecretReference(value domain.SecretReference) bool {
	return len(value.ID) <= maxWebhookSecretField && len(value.Name) > 0 && len(value.Name) <= maxWebhookSecretField && len(value.Provider) > 0 && len(value.Provider) <= maxWebhookSecretField && len(value.Version) <= maxWebhookSecretField && webhookOpaqueTextPattern.MatchString(value.ID.String()) && webhookOpaqueTextPattern.MatchString(value.Name) && webhookOpaqueTextPattern.MatchString(value.Provider) && (value.Version == "" || webhookOpaqueTextPattern.MatchString(value.Version))
}

func validDeliveryStatus(value WebhookDeliveryHealthStatus) bool {
	return value == WebhookDeliveryUnproven || value == WebhookDeliveryPending || value == WebhookDeliveryDelivered || value == WebhookDeliveryRetryableFailure || value == WebhookDeliveryFailed
}

// MarshalWebhookConfig emits the one strict, canonical config representation.
func MarshalWebhookConfig(value WebhookConfigV1) ([]byte, error) {
	if value.Validate() != nil {
		return nil, errors.New("invalid webhook config")
	}
	return json.Marshal(value)
}

func ParseWebhookConfig(raw []byte) (WebhookConfigV1, error) {
	var value WebhookConfigV1
	if err := strictDecode(raw, &value); err != nil {
		return value, err
	}
	if err := requireObjectFields(raw, []string{"schema", "endpoint_id", "url", "secret_reference", "enabled", "configured_at"}); err != nil {
		return value, err
	}
	var fields struct {
		SecretReference json.RawMessage `json:"secret_reference"`
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return value, err
	}
	if err := requireObjectFields(fields.SecretReference, []string{"id", "name", "provider"}); err != nil {
		return value, err
	}
	return value, value.Validate()
}

// CanonicalWebhookConfigDigest binds delivery truth to the exact validated
// config bytes without exposing the endpoint URL or secret reference in a
// health subject.
func CanonicalWebhookConfigDigest(value WebhookConfigV1) (string, error) {
	raw, err := MarshalWebhookConfig(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func MarshalDeliveryHealth(value DeliveryHealthV1) ([]byte, error) {
	if value.Validate() != nil {
		return nil, errors.New("invalid webhook delivery health")
	}
	return json.Marshal(value)
}

func ParseDeliveryHealth(raw []byte) (DeliveryHealthV1, error) {
	var value DeliveryHealthV1
	if err := strictDecode(raw, &value); err != nil {
		return value, err
	}
	if err := requireObjectFields(raw, []string{"schema", "config_digest", "revision", "status", "consecutive_failure_count", "terminal_failure_count"}); err != nil {
		return value, err
	}
	var fields struct {
		Status WebhookDeliveryHealthStatus `json:"status"`
		Event  json.RawMessage             `json:"event"`
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return value, err
	}
	if fields.Status != WebhookDeliveryUnproven {
		if err := requireObjectFields(raw, []string{"event"}); err != nil {
			return value, err
		}
		if err := requireObjectFields(fields.Event, []string{"schema", "event_id", "incident_fingerprint", "incident_revision", "pending_notification", "notification_stage"}); err != nil {
			return value, err
		}
	}
	return value, value.Validate()
}

// NewTaskWebhookProbe creates the task-testable system Webhook check. It does
// not construct a filesystem source, contact a receiver, or resolve a secret.
func NewTaskWebhookProbe(source WebhookHealthSource, clock func() time.Time) (HostProbe, error) {
	if source == nil || clock == nil {
		return HostProbe{}, errors.New("webhook probe dependencies are required")
	}
	return HostProbe{Kind: CheckWebhook, Check: func(ctx context.Context) (HostFact, error) {
		return checkWebhookHealth(ctx, source, clock)
	}}, nil
}

func checkWebhookHealth(ctx context.Context, source WebhookHealthSource, clock func() time.Time) (HostFact, error) {
	if ctx == nil {
		return webhookFact("cancelled", ""), errors.New("webhook probe context is required")
	}
	if err := ctx.Err(); err != nil {
		return webhookFact("cancelled", ""), err
	}
	observation, err := source.WebhookHealth(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return webhookFact("cancelled", ""), ctx.Err()
		}
		return webhookFact("source_failure", ""), nil
	}
	if err := ctx.Err(); err != nil {
		return webhookFact("cancelled", ""), err
	}
	if observation.Config == nil {
		return webhookFact("missing_config", ""), nil
	}
	config := *observation.Config
	if config.Validate() != nil {
		return webhookFact("invalid_config", ""), nil
	}
	digest, err := CanonicalWebhookConfigDigest(config)
	if err != nil {
		return webhookFact("invalid_config", ""), nil
	}
	if !config.Enabled {
		return webhookFact("disabled", digest), nil
	}
	if observation.Delivery == nil {
		return webhookFact("unproven", digest), nil
	}
	delivery := *observation.Delivery
	if delivery.Validate() != nil {
		return webhookFact("invalid_delivery", digest), nil
	}
	if delivery.ConfigDigest != digest {
		return webhookFact("config_drift", digest), nil
	}
	now := clock()
	if !utc(now) {
		return webhookFact("clock_failure", digest), nil
	}
	if now.Before(config.ConfiguredAt) || webhookTimesAfter(now, delivery) {
		return webhookFact("clock_regression", digest), nil
	}
	if webhookTimesBefore(config.ConfiguredAt, delivery) {
		return webhookFact("delivery_predates_config", digest), nil
	}
	if delivery.TerminalFailureCount > 0 {
		return webhookFact("terminal_failure", digest), nil
	}
	switch delivery.Status {
	case WebhookDeliveryUnproven:
		return webhookFact("unproven", digest), nil
	case WebhookDeliveryPending:
		if delivery.LastDeliveredAt == nil {
			return webhookFact("reachability_unproven", digest), nil
		}
	case WebhookDeliveryFailed:
		return webhookFact("terminal_failure", digest), nil
	}
	if delivery.LastDeliveredAt == nil {
		return webhookFact("reachability_unproven", digest), nil
	}
	if delivery.OldestPendingAt != nil {
		switch age := now.Sub(*delivery.OldestPendingAt); {
		case age >= 30*time.Minute:
			return webhookFact("pending_30m", digest), nil
		case age >= 5*time.Minute:
			return webhookFact("pending_5m", digest), nil
		case age >= time.Minute:
			return webhookFact("pending_1m", digest), nil
		}
	}
	return webhookFact("delivered", digest), nil
}

func webhookTimesBefore(configuredAt time.Time, value DeliveryHealthV1) bool {
	for _, candidate := range []*time.Time{value.OldestPendingAt, value.LastAttemptAt, value.LastDeliveredAt} {
		if candidate != nil && candidate.Before(configuredAt) {
			return true
		}
	}
	return false
}

func webhookTimesAfter(now time.Time, value DeliveryHealthV1) bool {
	for _, candidate := range []*time.Time{value.OldestPendingAt, value.LastAttemptAt, value.LastDeliveredAt} {
		if candidate != nil && candidate.After(now) {
			return true
		}
	}
	return false
}

func webhookFact(cause, configDigest string) HostFact {
	severity := SeverityEmergency
	switch cause {
	case "delivered":
		severity = SeverityOK
	case "disabled", "missing_config", "unproven", "reachability_unproven", "pending_5m":
		severity = SeverityCritical
	case "pending_1m":
		severity = SeverityWarning
	case "cancelled", "terminal_failure", "pending_30m", "source_failure", "invalid_config", "invalid_delivery", "config_drift", "clock_failure", "clock_regression", "delivery_predates_config":
		severity = SeverityEmergency
	}
	sum := sha256.Sum256([]byte(webhookHealthSubjectVersion + "\n" + cause + "\n" + configDigest))
	return HostFact{Subject: webhookHealthSubjectVersion + ":" + cause + ":" + hex.EncodeToString(sum[:]), Severity: severity}
}

func canonicalPublicHTTPSURL(value string) bool {
	// This validates the durable syntax only. The outbound provider must still
	// resolve and pin public IPs at delivery time to defeat private DNS answers
	// and rebinding; hostname syntax is never represented as SSRF proof.
	if strings.TrimSpace(value) != value || len(value) == 0 || len(value) > maxWebhookURL {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" || parsed.Hostname() == "" || parsed.String() != value {
		return false
	}
	hostname := parsed.Hostname()
	if len(hostname) > 253 || hostname != strings.ToLower(hostname) || strings.HasSuffix(hostname, ".") || net.ParseIP(hostname) != nil || strings.Trim(hostname, "0123456789.") == "" || !webhookHostnamePattern.MatchString(hostname) || hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") || hostname == "local" || strings.HasSuffix(hostname, ".local") || strings.HasSuffix(hostname, ".internal") {
		return false
	}
	if port := parsed.Port(); port != "" {
		portNumber, err := strconv.ParseUint(port, 10, 16)
		if err != nil || portNumber == 0 || portNumber == 443 || strconv.FormatUint(portNumber, 10) != port {
			return false
		}
	}
	expectedHost := hostname
	if port := parsed.Port(); port != "" {
		expectedHost += ":" + port
	}
	if parsed.Host != expectedHost {
		return false
	}
	return true
}
