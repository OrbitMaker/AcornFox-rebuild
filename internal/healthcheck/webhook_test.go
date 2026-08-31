package healthcheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

type webhookHealthSourceFunc func(context.Context) (WebhookHealthObservation, error)

func (f webhookHealthSourceFunc) WebhookHealth(ctx context.Context) (WebhookHealthObservation, error) {
	return f(ctx)
}

func TestWebhookConfigAndDeliveryStrictRoundTrip(t *testing.T) {
	now := time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC)
	config := webhookConfigFixture(now)
	raw, err := MarshalWebhookConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseWebhookConfig(raw)
	if err != nil || parsed != config {
		t.Fatalf("config=%+v err=%v", parsed, err)
	}
	digest, err := CanonicalWebhookConfigDigest(config)
	if err != nil || !webhookDigestPattern.MatchString(digest) {
		t.Fatalf("digest=%q err=%v", digest, err)
	}
	delivery := DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 9, LastAttemptAt: webhookTime(now.Add(time.Minute)), LastDeliveredAt: webhookTime(now.Add(time.Minute)), Status: WebhookDeliveryDelivered}
	deliveryRaw, err := MarshalDeliveryHealth(delivery)
	if err != nil {
		t.Fatal(err)
	}
	parsedDelivery, err := ParseDeliveryHealth(deliveryRaw)
	if err != nil || !sameDeliveryHealth(parsedDelivery, delivery) {
		t.Fatalf("delivery=%+v err=%v", parsedDelivery, err)
	}
	for _, raw := range [][]byte{
		[]byte(`{"schema":"open_card.host_alert_webhook.config.v1","endpoint_id":"system_alerts","url":"https://hooks.example.test/open-card","secret_reference":{"id":"secret_alert","name":"webhook","provider":"filesystem"},"enabled":true,"configured_at":"2026-08-31T02:00:00Z","unknown":true}`),
		[]byte(`{"schema":"open_card.host_alert_webhook.config.v1","schema":"open_card.host_alert_webhook.config.v1","endpoint_id":"system_alerts","url":"https://hooks.example.test/open-card","secret_reference":{"id":"secret_alert","name":"webhook","provider":"filesystem"},"enabled":true,"configured_at":"2026-08-31T02:00:00Z"}`),
		[]byte(`{"schema":"open_card.host_alert_webhook.config.v1","endpoint_id":"system_alerts","url":"https://hooks.example.test/open-card","secret_reference":null,"enabled":true,"configured_at":"2026-08-31T02:00:00Z"}`),
		[]byte(`{"schema":"open_card.host_alert_webhook.config.v1","endpoint_id":"system_alerts","url":"https://hooks.example.test/open-card","secret_reference":{"id":"secret_alert","name":"webhook","provider":"filesystem","extra":true},"enabled":true,"configured_at":"2026-08-31T02:00:00Z"}`),
		append(append([]byte(nil), raw...), []byte(` {}`)...),
	} {
		if _, err := ParseWebhookConfig(raw); err == nil {
			t.Fatalf("invalid config accepted: %s", raw)
		}
	}
	for _, raw := range [][]byte{
		[]byte(`{"schema":"open_card.host_alert_webhook.delivery_health.v1","config_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","revision":1,"status":"unproven","consecutive_failure_count":0,"terminal_failure_count":0,"extra":true}`),
		[]byte(`{"schema":"open_card.host_alert_webhook.delivery_health.v1","config_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","revision":1,"status":"unproven","consecutive_failure_count":0,"terminal_failure_count":null}`),
		[]byte(`{"schema":"open_card.host_alert_webhook.delivery_health.v1","config_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","revision":1,"status":"unproven","consecutive_failure_count":0,"terminal_failure_count":0} {}`),
	} {
		if _, err := ParseDeliveryHealth(raw); err == nil {
			t.Fatalf("invalid delivery accepted: %s", raw)
		}
	}
	for _, forbidden := range []string{"super-secret-value", "password=", "payload", "response", "error_message"} {
		if strings.Contains(string(raw), forbidden) || strings.Contains(string(deliveryRaw), forbidden) {
			t.Fatalf("contract leaked %q", forbidden)
		}
	}
}

func TestWebhookConfigRejectsNonPublicOrNonCanonicalURL(t *testing.T) {
	now := time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC)
	for _, target := range []string{
		"http://hooks.example.test/open-card", "https://localhost/open-card", "https://receiver.local/open-card", "https://receiver.internal/open-card", "https://127.0.0.0.1/open-card", "https://127.0.0.1/open-card", "https://[::1]/open-card", "https://169.254.169.254/open-card", "https://user:pass@hooks.example.test/open-card", "https://hooks.example.test/open-card?token=no", "https://hooks.example.test/open-card#fragment", "https://HOOKS.example.test/open-card", "https://hooks.example.test./open-card", "https://hooks.example.test:/open-card", "https://hooks.example.test:443/open-card", "https://hooks/open-card", "https://123.456.789.000/open-card", " https://hooks.example.test/open-card",
	} {
		config := webhookConfigFixture(now)
		config.URL = target
		if config.Validate() == nil {
			t.Fatalf("unsafe URL accepted: %q", target)
		}
	}
	for _, target := range []string{"https://hooks.example.test/open-card", "https://hooks.example.test:8443/open-card"} {
		config := webhookConfigFixture(now)
		config.URL = target
		if config.Validate() != nil {
			t.Fatalf("public URL rejected: %q", target)
		}
	}
}

func TestTaskWebhookProbeClassifiesHealthAndThresholds(t *testing.T) {
	now := time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC)
	config := webhookConfigFixture(now.Add(-time.Hour))
	digest, err := CanonicalWebhookConfigDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	delivered := DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 1, LastAttemptAt: webhookTime(now.Add(-time.Minute)), LastDeliveredAt: webhookTime(now.Add(-time.Minute)), Status: WebhookDeliveryDelivered}
	for _, tc := range []struct {
		name     string
		config   *WebhookConfigV1
		delivery *DeliveryHealthV1
		want     Severity
		cause    string
	}{
		{"missing", nil, nil, SeverityCritical, "missing_config"},
		{"disabled", webhookConfigPointer(disabledWebhookConfig(config)), nil, SeverityCritical, "disabled"},
		{"unproven missing", &config, nil, SeverityCritical, "unproven"},
		{"unproven state", &config, deliveryPointer(DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 1, Status: WebhookDeliveryUnproven}), SeverityCritical, "unproven"},
		{"delivered", &config, &delivered, SeverityOK, "delivered"},
		{"retryable fresh unproven", &config, deliveryPointer(retryableWebhookDelivery(digest, now.Add(-time.Second))), SeverityCritical, "reachability_unproven"},
		{"retryable fresh after delivery", &config, deliveryPointer(retryableAfterDelivery(digest, now.Add(-time.Second), now.Add(-time.Minute))), SeverityOK, "delivered"},
		{"pending one minute", &config, deliveryPointer(retryableAfterDelivery(digest, now.Add(-time.Minute), now.Add(-time.Hour))), SeverityWarning, "pending_1m"},
		{"pending five minutes", &config, deliveryPointer(retryableAfterDelivery(digest, now.Add(-5*time.Minute), now.Add(-time.Hour))), SeverityCritical, "pending_5m"},
		{"pending thirty minutes", &config, deliveryPointer(retryableAfterDelivery(digest, now.Add(-30*time.Minute), now.Add(-time.Hour))), SeverityEmergency, "pending_30m"},
		{"terminal", &config, deliveryPointer(DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 2, LastAttemptAt: webhookTime(now.Add(-time.Second)), Status: WebhookDeliveryFailed, TerminalFailureCount: 1}), SeverityEmergency, "terminal_failure"},
		{"terminal history", &config, deliveryPointer(DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 2, LastAttemptAt: webhookTime(now.Add(-time.Second)), LastDeliveredAt: webhookTime(now.Add(-time.Minute)), Status: WebhookDeliveryDelivered, TerminalFailureCount: 1}), SeverityEmergency, "terminal_failure"},
		{"config drift", &config, deliveryPointer(DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: "sha256:" + strings.Repeat("b", 64), Revision: 1, Status: WebhookDeliveryUnproven}), SeverityEmergency, "config_drift"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := taskWebhookProbe(t, webhookHealthSourceFunc(func(context.Context) (WebhookHealthObservation, error) {
				return WebhookHealthObservation{Config: tc.config, Delivery: tc.delivery}, nil
			}), now)
			fact, err := probe.Check(context.Background())
			if err != nil || fact.Severity != tc.want || !strings.Contains(fact.Subject, ":"+tc.cause+":") || strings.Contains(fact.Subject, "hooks.example") || strings.Contains(fact.Subject, "secret_alert") {
				t.Fatalf("fact=%+v err=%v", fact, err)
			}
		})
	}
}

func TestTaskWebhookProbeFailsClosedWithoutLeakingOperationalErrors(t *testing.T) {
	now := time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC)
	secret := "postgresql://user:super-secret-value@db.invalid/open-card"
	probe := taskWebhookProbe(t, webhookHealthSourceFunc(func(context.Context) (WebhookHealthObservation, error) {
		return WebhookHealthObservation{}, errors.New(secret)
	}), now)
	fact, err := probe.Check(context.Background())
	if err != nil || fact.Severity != SeverityEmergency || !strings.Contains(fact.Subject, "source_failure") || strings.Contains(fact.Subject, secret) {
		t.Fatalf("fact=%+v err=%v", fact, err)
	}
	config := webhookConfigFixture(now.Add(-time.Hour))
	digest, err := CanonicalWebhookConfigDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		config   *WebhookConfigV1
		delivery *DeliveryHealthV1
		cause    string
	}{
		{"corrupt config", webhookConfigPointer(WebhookConfigV1{Schema: webhookConfigSchema}), nil, "invalid_config"},
		{"corrupt delivery", &config, deliveryPointer(DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 1, Status: WebhookDeliveryDelivered}), "invalid_delivery"},
		{"clock regression", &config, deliveryPointer(DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 1, LastAttemptAt: webhookTime(now.Add(time.Second)), LastDeliveredAt: webhookTime(now.Add(time.Second)), Status: WebhookDeliveryDelivered}), "clock_regression"},
		{"delivery predates config", &config, deliveryPointer(DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 1, LastAttemptAt: webhookTime(config.ConfiguredAt), LastDeliveredAt: webhookTime(config.ConfiguredAt.Add(-time.Second)), Status: WebhookDeliveryDelivered}), "delivery_predates_config"},
		{"pending predates config", &config, deliveryPointer(DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 1, OldestPendingAt: webhookTime(config.ConfiguredAt.Add(-time.Second)), LastAttemptAt: webhookTime(now.Add(-time.Second)), LastDeliveredAt: webhookTime(now.Add(-time.Minute)), Status: WebhookDeliveryRetryableFailure, ConsecutiveFailureCount: 1}), "delivery_predates_config"},
		{"attempt predates config", &config, deliveryPointer(DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 1, LastAttemptAt: webhookTime(config.ConfiguredAt.Add(-time.Second)), LastDeliveredAt: webhookTime(config.ConfiguredAt.Add(-time.Second)), Status: WebhookDeliveryDelivered}), "delivery_predates_config"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := taskWebhookProbe(t, webhookHealthSourceFunc(func(context.Context) (WebhookHealthObservation, error) {
				return WebhookHealthObservation{Config: tc.config, Delivery: tc.delivery}, nil
			}), now)
			fact, err := probe.Check(context.Background())
			if err != nil || fact.Severity != SeverityEmergency || !strings.Contains(fact.Subject, tc.cause) {
				t.Fatalf("fact=%+v err=%v", fact, err)
			}
		})
	}
}

func TestTaskWebhookProbeCancellationDoesNotPersistCollectorState(t *testing.T) {
	now := time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probe := taskWebhookProbe(t, webhookHealthSourceFunc(func(context.Context) (WebhookHealthObservation, error) {
		t.Fatal("cancelled source was called")
		return WebhookHealthObservation{}, nil
	}), now)
	fact, err := probe.Check(ctx)
	if err == nil || fact.Severity != SeverityEmergency || !strings.Contains(fact.Subject, "cancelled") {
		t.Fatalf("fact=%+v err=%v", fact, err)
	}

	root := t.TempDir()
	store, err := NewTaskStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	complete := collectorProbes(nil, nil)
	for index := range complete {
		if complete[index].Kind == CheckWebhook {
			complete[index] = probe
		}
	}
	collector, err := NewTaskHostCollector(complete, store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Evaluate(ctx); err == nil {
		t.Fatal("cancelled webhook evaluation succeeded")
	}
	if _, err := os.Lstat(filepath.Join(root, incidentStateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled evaluation persisted state: %v", err)
	}
}

func TestWebhookProbeEmergencyPersistsCollectorIncident(t *testing.T) {
	now := time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC)
	probe := taskWebhookProbe(t, webhookHealthSourceFunc(func(context.Context) (WebhookHealthObservation, error) {
		return WebhookHealthObservation{}, errors.New("token=super-secret-value receiver unavailable")
	}), now)
	complete := collectorProbes(nil, nil)
	for index := range complete {
		if complete[index].Kind == CheckWebhook {
			complete[index] = probe
		}
	}
	root := t.TempDir()
	store, err := NewTaskStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := NewTaskHostCollector(complete, store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := collector.Evaluate(context.Background())
	if err != nil || !evaluation.Decision.Notify || evaluation.Snapshot.Overall != SeverityEmergency {
		t.Fatalf("evaluation=%+v err=%v", evaluation, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, incidentStateFile))
	if err != nil || strings.Contains(string(raw), "super-secret-value") || strings.Contains(string(raw), "receiver unavailable") {
		t.Fatalf("state=%q err=%v", raw, err)
	}
}

func webhookConfigFixture(configuredAt time.Time) WebhookConfigV1 {
	return WebhookConfigV1{Schema: webhookConfigSchema, EndpointID: "system_alerts", URL: "https://hooks.example.test/open-card", SecretReference: domain.SecretReference{ID: "secret_alert", Name: "webhook", Provider: "filesystem", Version: "v1"}, Enabled: true, ConfiguredAt: configuredAt}
}

func retryableWebhookDelivery(digest string, pending time.Time) DeliveryHealthV1 {
	return DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 2, OldestPendingAt: webhookTime(pending), LastAttemptAt: webhookTime(pending), Status: WebhookDeliveryRetryableFailure, ConsecutiveFailureCount: 1}
}

func retryableAfterDelivery(digest string, pending, delivered time.Time) DeliveryHealthV1 {
	value := retryableWebhookDelivery(digest, pending)
	value.LastDeliveredAt = webhookTime(delivered)
	return value
}

func webhookTime(value time.Time) *time.Time { return &value }

func webhookConfigPointer(value WebhookConfigV1) *WebhookConfigV1 { return &value }
func deliveryPointer(value DeliveryHealthV1) *DeliveryHealthV1    { return &value }

func disabledWebhookConfig(value WebhookConfigV1) WebhookConfigV1 {
	value.Enabled = false
	return value
}

func sameDeliveryHealth(left, right DeliveryHealthV1) bool {
	leftRaw, leftErr := MarshalDeliveryHealth(left)
	rightRaw, rightErr := MarshalDeliveryHealth(right)
	return leftErr == nil && rightErr == nil && string(leftRaw) == string(rightRaw)
}

func taskWebhookProbe(t *testing.T, source WebhookHealthSource, now time.Time) HostProbe {
	t.Helper()
	probe, err := NewTaskWebhookProbe(source, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return probe
}
