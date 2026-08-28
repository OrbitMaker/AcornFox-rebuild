package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

type m4LifecyclePublisherFixture struct {
	requests []controllers.M4NotificationRequest
	result   controllers.M4NotificationResult
	err      error
}

func (f *m4LifecyclePublisherFixture) Publish(_ context.Context, request controllers.M4NotificationRequest) (controllers.M4NotificationResult, error) {
	f.requests = append(f.requests, request)
	return f.result, f.err
}

func m4LifecycleDispatchRequest(kind M4OperationLifecycleKind) M4OperationLifecycleDispatchRequest {
	return M4OperationLifecycleDispatchRequest{
		Event: M4OperationLifecycleEvent{
			EventID:       "evt_m4_operation_1",
			ApplicationID: "app_m4",
			EnvironmentID: "env_m4",
			OperationID:   "op_m4",
			Kind:          kind,
			Status:        "terminal",
			Message:       "operation lifecycle summary",
			OccurredAt:    time.Unix(1_700_000_000, 0).UTC(),
		},
		Endpoint: controllers.M4WebhookEndpoint{
			ID:      "endpoint_m4",
			URL:     "https://hooks.example.test/open-card",
			Enabled: true,
			SecretRef: domain.SecretReference{
				ID:       "secret_m4",
				Name:     "webhook-signing",
				Provider: "filesystem-secret",
				Version:  "v1",
			},
		},
		Actor: "m4-operation-dispatcher",
	}
}

func TestM4OperationNotificationDispatcherMapsLifecycleKinds(t *testing.T) {
	cases := []struct {
		name        string
		kind        M4OperationLifecycleKind
		wantKind    controllers.M4NotificationKind
		wantDefault string
	}{
		{name: "failure is occurrence", kind: M4OperationLifecycleFailure, wantKind: controllers.M4NotificationOccurrence, wantDefault: "error"},
		{name: "escalation is escalation", kind: M4OperationLifecycleEscalation, wantKind: controllers.M4NotificationEscalation, wantDefault: "warning"},
		{name: "retry is escalation", kind: M4OperationLifecycleRetry, wantKind: controllers.M4NotificationEscalation, wantDefault: "warning"},
		{name: "recovery is recovery", kind: M4OperationLifecycleRecovery, wantKind: controllers.M4NotificationRecovery, wantDefault: "info"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			publisher := &m4LifecyclePublisherFixture{}
			dispatcher, err := NewM4OperationNotificationDispatcher(publisher)
			if err != nil {
				t.Fatal(err)
			}
			request := m4LifecycleDispatchRequest(testCase.kind)
			if _, err := dispatcher.Dispatch(context.Background(), request); err != nil {
				t.Fatalf("Dispatch() error = %v", err)
			}
			if len(publisher.requests) != 1 {
				t.Fatalf("Publish() calls = %d, want 1", len(publisher.requests))
			}
			published := publisher.requests[0]
			if published.Event.Kind != testCase.wantKind || published.Event.Severity != testCase.wantDefault {
				t.Fatalf("published lifecycle = %#v, want kind=%q severity=%q", published.Event, testCase.wantKind, testCase.wantDefault)
			}
			if published.Event.IncidentID != request.Event.OperationID.String() || published.Event.ApplicationID != request.Event.ApplicationID || published.Event.EnvironmentID != request.Event.EnvironmentID {
				t.Fatalf("published identity was not projected from operation facts: %#v", published.Event)
			}
			if published.Event.OccurredAt != request.Event.OccurredAt {
				t.Fatalf("published occurrence time changed: got %v want %v", published.Event.OccurredAt, request.Event.OccurredAt)
			}
			if !strings.HasPrefix(published.IdempotencyKey, "m4-operation-lifecycle:") || len(published.IdempotencyKey) != len("m4-operation-lifecycle:")+64 {
				t.Fatalf("idempotency key is not bounded/opaque: %q", published.IdempotencyKey)
			}
		})
	}
}

func TestM4OperationNotificationDispatcherAcceptsDottedOutboxKindsAndUsesStatusFallback(t *testing.T) {
	publisher := &m4LifecyclePublisherFixture{}
	dispatcher, err := NewM4OperationNotificationDispatcher(publisher)
	if err != nil {
		t.Fatal(err)
	}
	fromOutbox, err := NewM4OperationLifecycleEvent(application.Event{
		ID:            "evt_outbox_failed",
		OperationID:   "op_m4",
		ApplicationID: "app_m4",
		Kind:          "operations.service_restart.failed",
		Status:        "failed",
		Message:       "service restart failed",
		OccurredAt:    time.Unix(1_700_000_001, 0).UTC(),
	}, "env_m4", "")
	if err != nil {
		t.Fatal(err)
	}
	request := M4OperationLifecycleDispatchRequest{Event: fromOutbox, Endpoint: m4LifecycleDispatchRequest(M4OperationLifecycleFailure).Endpoint, Actor: "outbox-worker"}
	if _, err := dispatcher.Dispatch(context.Background(), request); err != nil {
		t.Fatalf("dotted outbox kind rejected: %v", err)
	}
	if got := publisher.requests[0].Event.Kind; got != controllers.M4NotificationOccurrence {
		t.Fatalf("dotted failure kind = %q, want occurrence", got)
	}

	fromStatus := fromOutbox
	fromStatus.EventID = "evt_outbox_recovery"
	fromStatus.Kind = "operations.service_restart"
	fromStatus.Status = "recovered"
	fromStatus.Message = "service restart recovered"
	request.Event = fromStatus
	if _, err := dispatcher.Dispatch(context.Background(), request); err != nil {
		t.Fatalf("status fallback rejected: %v", err)
	}
	if got := publisher.requests[1].Event.Kind; got != controllers.M4NotificationRecovery {
		t.Fatalf("status recovery kind = %q, want recovery", got)
	}
}

func TestM4OperationNotificationDispatcherCanonicalizesWithoutLogsOrSecrets(t *testing.T) {
	publisher := &m4LifecyclePublisherFixture{}
	dispatcher, err := NewM4OperationNotificationDispatcher(publisher)
	if err != nil {
		t.Fatal(err)
	}
	request := m4LifecycleDispatchRequest(M4OperationLifecycleFailure)
	request.Event.Message = "restart failed token=canary-secret; authorization: Bearer bearer-secret"
	if _, err := dispatcher.Dispatch(context.Background(), request); err != nil {
		t.Fatalf("redactable lifecycle message rejected: %v", err)
	}
	payload := publisher.requests[0].Event.Message
	if strings.Contains(payload, "canary-secret") || strings.Contains(payload, "bearer-secret") || !strings.Contains(payload, foundation.RedactedValue) {
		t.Fatalf("lifecycle message leaked sensitive assignment: %q", payload)
	}
	if strings.Contains(payload, "docker inspect") {
		t.Fatalf("raw runtime log entered lifecycle message: %q", payload)
	}

	for _, message := range []string{"docker inspect\ncontainer output", strings.Repeat("x", 513)} {
		request.Event.EventID = "evt_invalid_" + string(rune(len(message)))
		request.Event.Message = message
		if _, err := dispatcher.Dispatch(context.Background(), request); err == nil {
			t.Fatalf("unsafe/unbounded lifecycle message was accepted: %q", message[:minM4TestInt(len(message), 32)])
		}
	}
	if len(publisher.requests) != 1 {
		t.Fatalf("invalid messages reached publisher: %d requests", len(publisher.requests))
	}
}

func TestM4OperationNotificationDispatcherReplaysWithStableIdempotency(t *testing.T) {
	publisher := &m4LifecyclePublisherFixture{}
	dispatcher, err := NewM4OperationNotificationDispatcher(publisher)
	if err != nil {
		t.Fatal(err)
	}
	request := m4LifecycleDispatchRequest(M4OperationLifecycleRecovery)
	first, err := dispatcher.Dispatch(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := dispatcher.Dispatch(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(publisher.requests) != 2 || publisher.requests[0].IdempotencyKey != publisher.requests[1].IdempotencyKey {
		t.Fatalf("replay did not preserve idempotency key: %#v", publisher.requests)
	}
	if first != second {
		t.Fatalf("publisher result unexpectedly changed: first=%#v second=%#v", first, second)
	}
	changed := request
	changed.Event.EventID = "evt_m4_operation_2"
	if _, err := dispatcher.Dispatch(context.Background(), changed); err != nil {
		t.Fatal(err)
	}
	if publisher.requests[2].IdempotencyKey == publisher.requests[0].IdempotencyKey {
		t.Fatal("different persisted event reused the same idempotency key")
	}
}

func TestM4OperationNotificationDispatcherFailsClosedAndPropagatesPublisherError(t *testing.T) {
	if _, err := NewM4OperationNotificationDispatcher(nil); err == nil {
		t.Fatal("nil publisher accepted")
	}
	dispatcher := &M4OperationNotificationDispatcher{}
	if _, err := dispatcher.Dispatch(context.Background(), m4LifecycleDispatchRequest(M4OperationLifecycleFailure)); err == nil {
		t.Fatal("dispatcher without publisher accepted an event")
	}

	publisher := &m4LifecyclePublisherFixture{err: errors.New("ledger unavailable")}
	dispatcher, err := NewM4OperationNotificationDispatcher(publisher)
	if err != nil {
		t.Fatal(err)
	}
	if _, got := dispatcher.Dispatch(context.Background(), m4LifecycleDispatchRequest(M4OperationLifecycleFailure)); got == nil || got.Error() != "ledger unavailable" {
		t.Fatalf("publisher error was not propagated: %v", got)
	}
	if len(publisher.requests) != 1 {
		t.Fatalf("publisher was not called exactly once: %d", len(publisher.requests))
	}
}

func TestM4OperationNotificationDispatcherRejectsIncompleteProjection(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*M4OperationLifecycleDispatchRequest)
	}{
		{name: "event id", mutate: func(request *M4OperationLifecycleDispatchRequest) { request.Event.EventID = "" }},
		{name: "application id", mutate: func(request *M4OperationLifecycleDispatchRequest) { request.Event.ApplicationID = "" }},
		{name: "environment id", mutate: func(request *M4OperationLifecycleDispatchRequest) { request.Event.EnvironmentID = "" }},
		{name: "operation id", mutate: func(request *M4OperationLifecycleDispatchRequest) { request.Event.OperationID = "" }},
		{name: "occurred at", mutate: func(request *M4OperationLifecycleDispatchRequest) { request.Event.OccurredAt = time.Time{} }},
		{name: "actor", mutate: func(request *M4OperationLifecycleDispatchRequest) { request.Actor = "" }},
		{name: "kind", mutate: func(request *M4OperationLifecycleDispatchRequest) { request.Event.Kind = "unknown" }},
		{name: "message", mutate: func(request *M4OperationLifecycleDispatchRequest) { request.Event.Message = "" }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			publisher := &m4LifecyclePublisherFixture{}
			dispatcher, err := NewM4OperationNotificationDispatcher(publisher)
			if err != nil {
				t.Fatal(err)
			}
			request := m4LifecycleDispatchRequest(M4OperationLifecycleFailure)
			testCase.mutate(&request)
			if _, err := dispatcher.Dispatch(context.Background(), request); err == nil {
				t.Fatal("incomplete lifecycle projection was accepted")
			}
			if len(publisher.requests) != 0 {
				t.Fatalf("invalid projection reached publisher: %d", len(publisher.requests))
			}
		})
	}
}

func minM4TestInt(value, limit int) int {
	if value < limit {
		return value
	}
	return limit
}
