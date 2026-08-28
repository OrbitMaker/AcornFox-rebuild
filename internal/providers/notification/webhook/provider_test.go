package webhook

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

func webhookOperation(key string) contracts.OperationContext {
	return contracts.OperationContext{IdempotencyKey: key}
}

func webhookCode(err error) contracts.ErrorCode {
	var providerErr *contracts.ProviderError
	if errors.As(err, &providerErr) {
		return providerErr.Code
	}
	return ""
}

func TestSignedWebhookRedactsPayloadAndDeduplicatesEvent(t *testing.T) {
	const secret = "webhook-signing-secret"
	occurredAt := time.Unix(1_700_000_000, 0).UTC()
	var mu sync.Mutex
	var calls int
	var body string
	var headers http.Header
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		data, _ := io.ReadAll(request.Body)
		body, headers = string(data), request.Header.Clone()
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	provider, err := New(Config{Endpoint: server.URL, Secret: secret, AllowLoopbackFixture: true, Clock: func() time.Time { return occurredAt }, RetryDelays: []time.Duration{}})
	if err != nil {
		t.Fatal(err)
	}
	notification := contracts.Notification{EventID: domain.ID("event_1"), EventType: "deployment.attention", OccurredAt: occurredAt, Payload: map[string]any{"message": "healthy context", "password": "unsafe", "authorization": "Bearer unsafe", "known": secret}}
	if err := provider.Send(context.Background(), notification, webhookOperation("send-1")); err != nil {
		t.Fatal(err)
	}
	if err := provider.Send(context.Background(), notification, webhookOperation("send-2")); err != nil {
		t.Fatalf("same event was not deduplicated: %v", err)
	}
	if err := provider.Send(context.Background(), contracts.Notification{EventID: notification.EventID, EventType: "deployment.failed", OccurredAt: occurredAt, Payload: notification.Payload}, webhookOperation("send-conflict")); webhookCode(err) != contracts.ErrConflict {
		t.Fatalf("event ID content conflict was accepted: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("deduplicated event made %d requests", calls)
	}
	if strings.Contains(body, secret) || strings.Contains(body, "unsafe") || !strings.Contains(body, foundation.RedactedValue) || !strings.Contains(body, "healthy context") {
		t.Fatalf("payload was not safely redacted: %s", body)
	}
	if headers.Get("X-Open-Card-Event-ID") != "event_1" || headers.Get("X-Open-Card-Event-Type") != notification.EventType {
		t.Fatalf("missing event identity headers: %#v", headers)
	}
	if err := foundation.VerifyWebhookSignature(secret, occurredAt.Unix(), "event_1", []byte(body), headers.Get("X-Open-Card-Signature"), occurredAt); err != nil {
		t.Fatalf("signature header was invalid: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%#v", provider), secret) || strings.Contains(provider.String(), secret) {
		t.Fatal("provider formatting leaked signing secret")
	}
}

func TestWebhookRetriesFaultsAndTestEvent(t *testing.T) {
	now := time.Unix(1_700_000_100, 0).UTC()
	var mu sync.Mutex
	attempts := 0
	ids := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		ids = append(ids, request.Header.Get("X-Open-Card-Event-ID"))
		if attempts == 1 {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	provider, err := New(Config{Endpoint: server.URL, Secret: "signing-secret", AllowLoopbackFixture: true, Clock: func() time.Time { return now }, RetryDelays: []time.Duration{0}})
	if err != nil {
		t.Fatal(err)
	}
	notification := contracts.Notification{EventID: domain.ID("event_retry"), EventType: "deployment.failed", OccurredAt: now, Payload: map[string]any{"state": "failed"}}
	if err := provider.Send(context.Background(), notification, webhookOperation("retry")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if attempts != 2 || ids[0] != "event_retry" || ids[1] != "event_retry" {
		t.Fatalf("bounded retry did not retain event ID: attempts=%d ids=%v", attempts, ids)
	}
	mu.Unlock()
	if err := provider.Test(context.Background(), webhookOperation("test")); err != nil {
		t.Fatalf("real test delivery failed: %v", err)
	}
	if err := provider.Test(context.Background(), webhookOperation("test")); err != nil {
		t.Fatalf("test event was not idempotent: %v", err)
	}
}

func TestWebhookRejectsUnsafeTargetsRedirectsAndRawKeys(t *testing.T) {
	for _, endpoint := range []string{"ftp://example.test/hook", "http://secret@example.test/hook", "http://127.0.0.1:8080/hook", "http://localhost:8080/hook", "http://10.0.0.1/hook"} {
		if _, err := New(Config{Endpoint: endpoint, Secret: "secret"}); err == nil {
			t.Fatalf("unsafe endpoint was accepted: %s", endpoint)
		}
	}
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
	}
	provider, err := New(Config{Endpoint: "https://public.example/hook", Secret: "secret", LookupIP: lookup, RetryDelays: []time.Duration{}})
	if err != nil {
		t.Fatal(err)
	}
	err = provider.Send(context.Background(), contracts.Notification{EventID: domain.ID("event_ssrf"), EventType: "test", OccurredAt: time.Now().UTC(), Payload: map[string]any{}}, webhookOperation("ssrf"))
	if webhookCode(err) != contracts.ErrForbidden {
		t.Fatalf("private DNS answer was not rejected: %v", err)
	}

	redirected := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected++ }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusFound)
	}))
	defer server.Close()
	redirectProvider, err := New(Config{Endpoint: server.URL, Secret: "secret", AllowLoopbackFixture: true, RetryDelays: []time.Duration{}})
	if err != nil {
		t.Fatal(err)
	}
	err = redirectProvider.Send(context.Background(), contracts.Notification{EventID: domain.ID("event_redirect"), EventType: "test", OccurredAt: time.Now().UTC(), Payload: map[string]any{}}, webhookOperation("redirect"))
	if webhookCode(err) != contracts.ErrForbidden || redirected != 0 {
		t.Fatalf("redirect was followed or misclassified: redirected=%d err=%v", redirected, err)
	}

	keyProvider, err := New(Config{Endpoint: server.URL, Secret: "secret", AllowLoopbackFixture: true, RetryDelays: []time.Duration{}})
	if err != nil {
		t.Fatal(err)
	}
	err = keyProvider.Send(context.Background(), contracts.Notification{EventID: domain.ID("event_key"), EventType: "test", OccurredAt: time.Now().UTC(), Payload: map[string]any{"log": "-----BEGIN PRIVATE KEY-----\nraw\n-----END PRIVATE KEY-----"}}, webhookOperation("key"))
	if webhookCode(err) != contracts.ErrInvalidArgument {
		t.Fatalf("raw key payload was not rejected: %v", err)
	}
}

func TestWebhookLoopbackFixturePermitsOnlyFixedInternalHostname(t *testing.T) {
	lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host != "opencard-webhook-fixture.test" {
			return nil, errors.New("unexpected fixture hostname")
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	provider, err := New(Config{Endpoint: "https://opencard-webhook-fixture.test:19443/events", Secret: "fixture-secret", AllowLoopbackFixture: true, LookupIP: lookup, RetryDelays: []time.Duration{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.resolveTarget(context.Background()); err != nil {
		t.Fatalf("fixed loopback fixture was rejected: %v", err)
	}
	if _, err := New(Config{Endpoint: "https://other.fixture.test/events", Secret: "fixture-secret", AllowLoopbackFixture: true}); err == nil {
		t.Fatal("arbitrary fixture hostname was accepted")
	}
}

func TestWebhookHonorsCallerDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) }))
	defer server.Close()
	provider, err := New(Config{Endpoint: server.URL, Secret: "secret", AllowLoopbackFixture: true, RetryDelays: []time.Duration{}})
	if err != nil {
		t.Fatal(err)
	}
	err = provider.Send(context.Background(), contracts.Notification{EventID: domain.ID("event_timeout"), EventType: "test", OccurredAt: time.Now().UTC(), Payload: map[string]any{}}, contracts.OperationContext{IdempotencyKey: "deadline", Deadline: time.Now().Add(-time.Millisecond)})
	if webhookCode(err) != contracts.ErrTimeout {
		t.Fatalf("expired operation deadline was not classified: %v", err)
	}
}
