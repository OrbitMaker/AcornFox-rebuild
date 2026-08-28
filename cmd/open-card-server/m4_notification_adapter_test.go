package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type m4WebhookBuildSecrets struct {
	material contracts.BuildSecretMaterial
	revoked  bool
}

func (s *m4WebhookBuildSecrets) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "m4-test-secrets", Version: "test", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilitySecretResolve)}
}
func (s *m4WebhookBuildSecrets) ResolveBuildSecret(_ context.Context, reference domain.SecretReference, _ contracts.OperationContext) (contracts.BuildSecretMaterial, error) {
	if reference != s.material.Reference {
		return contracts.BuildSecretMaterial{}, errors.New("unexpected secret reference")
	}
	return s.material, nil
}
func (s *m4WebhookBuildSecrets) RevokeBuildSecret(_ context.Context, material contracts.BuildSecretMaterial, _ contracts.OperationContext) error {
	if material.Path != s.material.Path {
		return errors.New("unexpected material")
	}
	s.revoked = true
	return nil
}

func TestM4WebhookProviderResolverUsesOpaqueReferenceAndTaskLoopbackOnly(t *testing.T) {
	const secret = "m4-loopback-signing-secret"
	base := t.TempDir()
	path := filepath.Join(base, "signing.secret")
	if err := os.WriteFile(path, []byte(secret), 0o400); err != nil {
		t.Fatal(err)
	}
	reference := domain.SecretReference{ID: "secret_webhook", Name: "webhook", Provider: "fixture", Version: "v1"}
	secrets := &m4WebhookBuildSecrets{material: contracts.BuildSecretMaterial{MountID: "mount_test", Reference: reference, Path: path, ExpiresAt: time.Now().Add(time.Minute)}}
	var receivedBody string
	var receivedHeader http.Header
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		data, _ := io.ReadAll(request.Body)
		receivedBody, receivedHeader = string(data), request.Header.Clone()
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	resolver := &m4WebhookProviderResolver{Secrets: secrets, AllowLoopbackFixture: true}
	endpoint := controllers.M4WebhookEndpoint{ID: "endpoint_m4", URL: server.URL, Enabled: true, SecretRef: reference}
	provider, err := resolver.ResolveWebhookNotificationProvider(context.Background(), endpoint, contracts.OperationContext{IdempotencyKey: "resolve", Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	notification := contracts.Notification{EventID: "event_m4", EventType: "notification.occurrence", Payload: map[string]any{"token": "outbound-value", "message": "safe"}, OccurredAt: time.Unix(1_700_000_000, 0).UTC()}
	if err := provider.Send(context.Background(), notification, contracts.OperationContext{IdempotencyKey: "send", Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	if !secrets.revoked {
		t.Fatal("webhook material was not revoked after provider construction")
	}
	if strings.Contains(receivedBody, "outbound-value") || !strings.Contains(receivedBody, foundation.RedactedValue) {
		t.Fatalf("resolved provider sent unredacted payload: %s", receivedBody)
	}
	if err := foundation.VerifyWebhookSignature(secret, notification.OccurredAt.Unix(), notification.EventID.String(), []byte(receivedBody), receivedHeader.Get("X-Open-Card-Signature"), notification.OccurredAt); err != nil {
		t.Fatalf("resolved provider did not sign loopback fixture request: %v", err)
	}
}

func TestM4WebhookProviderResolverRejectsReferenceMismatchAndDoesNotRetryInternally(t *testing.T) {
	reference := domain.SecretReference{ID: "secret_webhook", Name: "webhook", Provider: "fixture"}
	base := t.TempDir()
	path := filepath.Join(base, "signing.secret")
	if err := os.WriteFile(path, []byte("secret"), 0o400); err != nil {
		t.Fatal(err)
	}
	secrets := &m4WebhookBuildSecrets{material: contracts.BuildSecretMaterial{MountID: "mount_test", Reference: reference, Path: path, ExpiresAt: time.Now().Add(time.Minute)}}
	resolver := &m4WebhookProviderResolver{Secrets: secrets, AllowLoopbackFixture: true}
	endpoint := controllers.M4WebhookEndpoint{ID: "endpoint_m4", URL: "http://127.0.0.1:1", Enabled: true, SecretRef: domain.SecretReference{ID: reference.ID, Name: "different", Provider: "fixture"}}
	if _, err := resolver.ResolveWebhookNotificationProvider(context.Background(), endpoint, contracts.OperationContext{IdempotencyKey: "mismatch"}); err == nil {
		t.Fatal("mismatched opaque reference was accepted")
	}

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	provider, err := resolver.ResolveWebhookNotificationProvider(context.Background(), controllers.M4WebhookEndpoint{ID: "endpoint_m4", URL: server.URL, Enabled: true, SecretRef: reference}, contracts.OperationContext{IdempotencyKey: "resolve-no-retry"})
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Send(context.Background(), contracts.Notification{EventID: "event_no_retry", EventType: "notification.test", Payload: map[string]any{}, OccurredAt: time.Now().UTC()}, contracts.OperationContext{IdempotencyKey: "send-no-retry"}); err == nil {
		t.Fatal("500 receiver was accepted")
	}
	if requests != 1 {
		t.Fatalf("HTTP provider retried despite durable controller ownership: %d", requests)
	}
}

func TestM4NotificationLedgerMappingNormalizesDigestAndStatuses(t *testing.T) {
	digest := strings.Repeat("a", 64)
	if got := m4WebhookDigest(digest); got != "sha256:"+digest {
		t.Fatalf("controller digest was not converted for persistence: %q", got)
	}
	if got := m4WebhookDigest("sha256:" + digest); got != "sha256:"+digest {
		t.Fatalf("already canonical digest changed: %q", got)
	}
	for source, want := range map[postgres.WebhookDeliveryStatus]controllers.M4NotificationStatus{postgres.WebhookDeliveryPending: controllers.M4NotificationPending, postgres.WebhookDeliveryRetryWait: controllers.M4NotificationPending, postgres.WebhookDeliveryDelivered: controllers.M4NotificationDelivered, postgres.WebhookDeliveryFailed: controllers.M4NotificationFailed} {
		got, err := m4ControllerNotificationStatus(source)
		if err != nil || got != want {
			t.Fatalf("status mapping %q = %q, %v", source, got, err)
		}
	}
	if value := redactM4WebhookText("token=do-not-leak"); strings.Contains(value, "do-not-leak") || !strings.Contains(value, foundation.RedactedValue) {
		t.Fatalf("adapter error redaction leaked a token: %q", value)
	}
}
