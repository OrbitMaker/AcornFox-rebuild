package healthcheck

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
)

func TestWebhookDispatcherDeliversRecordsAndAcknowledgesInOrder(t *testing.T) {
	now := time.Date(2026, 8, 31, 5, 0, 0, 0, time.UTC)
	config, incident, event := webhookDispatchFixture(t, now)
	config.URL = "https://hooks.example.test/super-secret-url"
	config.SecretReference.Name = "super-secret-reference"
	config.SecretReference.ID = "super-secret-id"
	trace := []string{}
	store := newWebhookDispatchStore(t, config, event, incident.FirstObserved, &trace)
	provider := &webhookDispatchProvider{trace: &trace}
	ack := &webhookDispatchAcknowledger{trace: &trace}
	dispatcher := &WebhookDispatcher{Store: store, Resolver: webhookDispatchResolver{provider: provider, trace: &trace}, Acknowledger: ack, Clock: func() time.Time { return now }}

	delivery, err := dispatcher.Dispatch(context.Background(), config, incident)
	if err != nil || delivery.Status != WebhookDeliveryDelivered {
		t.Fatalf("delivery=%+v err=%v", delivery, err)
	}
	if want := []string{"begin", "resolve", "send", "record", "ack"}; !reflect.DeepEqual(trace, want) {
		t.Fatalf("trace=%v want=%v", trace, want)
	}
	if provider.notification.EventID.Empty() || provider.notification.EventType != webhookDispatchEventType+".occurrence" || !provider.notification.OccurredAt.Equal(incident.FirstObserved) {
		t.Fatalf("notification=%+v", provider.notification)
	}
	wantPayload := map[string]any{
		"schema_version":     webhookDispatchPayloadSchema,
		"scope":              "system",
		"incident_id":        incident.Fingerprint,
		"incident_revision":  incident.Revision,
		"kind":               "occurrence",
		"severity":           string(incident.Severity),
		"notification_stage": 1,
		"occurred_at":        incident.FirstObserved.Format(time.RFC3339Nano),
	}
	if !reflect.DeepEqual(provider.notification.Payload, wantPayload) {
		t.Fatalf("payload=%#v want=%#v", provider.notification.Payload, wantPayload)
	}
	if provider.operation.Actor != webhookDispatchActor || !provider.operation.Deadline.Equal(now.Add(webhookDispatchAttemptLimit)) || !strings.Contains(provider.operation.IdempotencyKey, ":1:1") || provider.operation.IdempotencyKey == event.EventID {
		t.Fatalf("operation=%+v event=%+v", provider.operation, event)
	}
	for _, forbidden := range []string{config.URL, config.SecretReference.Name, config.SecretReference.ID.String(), config.SecretReference.Provider} {
		if strings.Contains(fmt.Sprint(provider.notification, provider.operation), forbidden) {
			t.Fatalf("provider request leaked %q: notification=%+v operation=%+v", forbidden, provider.notification, provider.operation)
		}
	}
}

func TestWebhookDispatcherUsesLastObservedAndRecoveryOf(t *testing.T) {
	now := time.Date(2026, 8, 31, 5, 0, 0, 0, time.UTC)
	config, incident, event := webhookDispatchFixture(t, now)
	incident.Revision = 2
	incident.LastObserved = now.Add(-time.Minute)
	incident.NotificationStage = 2
	incident.PendingNotification = "escalation"
	event, _ = WebhookDeliveryEventFromIncident(incident)
	for _, tc := range []struct {
		name  string
		state IncidentState
		want  string
	}{
		{name: "escalation", state: incident, want: incident.Fingerprint},
		{name: "recovery", state: IncidentState{SchemaVersion: SchemaVersion, Revision: 3, Fingerprint: HealthyFingerprint, FirstObserved: now.Add(-2 * time.Minute), LastObserved: now.Add(-time.Minute), Severity: SeverityOK, PendingNotification: "recovery", RecoveryPending: true, RecoveryOf: strings.Repeat("b", 64), Healthy: true}, want: strings.Repeat("b", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			currentEvent, err := WebhookDeliveryEventFromIncident(tc.state)
			if err != nil {
				t.Fatal(err)
			}
			store := newWebhookDispatchStore(t, config, currentEvent, tc.state.LastObserved, nil)
			provider := &webhookDispatchProvider{}
			dispatcher := &WebhookDispatcher{Store: store, Resolver: webhookDispatchResolver{provider: provider}, Acknowledger: &webhookDispatchAcknowledger{}, Clock: func() time.Time { return now }}
			if _, err := dispatcher.Dispatch(context.Background(), config, tc.state); err != nil {
				t.Fatal(err)
			}
			if provider.notification.Payload["incident_id"] != tc.want || provider.notification.Payload["occurred_at"] != tc.state.LastObserved.Format(time.RFC3339Nano) {
				t.Fatalf("notification=%+v", provider.notification)
			}
		})
	}
	_ = event
}

func TestWebhookDispatcherClassifiesFailuresWithoutAcknowledging(t *testing.T) {
	now := time.Date(2026, 8, 31, 5, 0, 0, 0, time.UTC)
	config, incident, event := webhookDispatchFixture(t, now)
	for _, tc := range []struct {
		name    string
		resolve error
		send    error
		want    WebhookDeliveryAttemptResult
	}{
		{name: "retryable resolver", resolve: &contracts.ProviderError{Retryable: true}, want: WebhookDeliveryAttemptRetryableFailure},
		{name: "terminal resolver", resolve: &contracts.ProviderError{Retryable: false}, want: WebhookDeliveryAttemptFailed},
		{name: "retryable send", send: &contracts.ProviderError{Retryable: true}, want: WebhookDeliveryAttemptRetryableFailure},
		{name: "terminal send", send: errors.New("receiver rejected"), want: WebhookDeliveryAttemptFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newWebhookDispatchStore(t, config, event, incident.FirstObserved, nil)
			provider := &webhookDispatchProvider{err: tc.send}
			ack := &webhookDispatchAcknowledger{}
			dispatcher := &WebhookDispatcher{Store: store, Resolver: webhookDispatchResolver{provider: provider, err: tc.resolve}, Acknowledger: ack, Clock: func() time.Time { return now }}
			delivery, err := dispatcher.Dispatch(context.Background(), config, incident)
			if !errors.Is(err, ErrWebhookDispatch) || delivery.Status != webhookDispatchStatus(tc.want) || store.result != tc.want || ack.calls != 0 {
				t.Fatalf("delivery=%+v err=%v result=%q ack=%d", delivery, err, store.result, ack.calls)
			}
		})
	}
}

func TestWebhookDispatcherDeliveredReplayAcknowledgesWithoutResend(t *testing.T) {
	now := time.Date(2026, 8, 31, 5, 0, 0, 0, time.UTC)
	config, incident, event := webhookDispatchFixture(t, now)
	store := newWebhookDispatchStore(t, config, event, incident.FirstObserved, nil)
	delivered := store.begin
	delivered.Status = WebhookDeliveryDelivered
	delivered.OldestPendingAt = nil
	delivered.LastAttemptAt = webhookTime(now.Add(-time.Minute))
	delivered.LastDeliveredAt = webhookTime(now.Add(-time.Minute))
	store.begin = delivered
	provider := &webhookDispatchProvider{}
	ack := &webhookDispatchAcknowledger{err: errors.New("crash before acknowledgement")}
	dispatcher := &WebhookDispatcher{Store: store, Resolver: webhookDispatchResolver{provider: provider}, Acknowledger: ack, Clock: func() time.Time { return now }}
	if replay, err := dispatcher.Dispatch(context.Background(), config, incident); !errors.Is(err, ErrWebhookDispatch) || replay.Status != WebhookDeliveryDelivered || provider.calls != 0 || store.recordCalls != 0 {
		t.Fatalf("replay=%+v err=%v sends=%d records=%d", replay, err, provider.calls, store.recordCalls)
	}
	ack.err = nil
	if _, err := dispatcher.Dispatch(context.Background(), config, incident); err != nil || provider.calls != 0 || store.recordCalls != 0 || ack.calls != 2 {
		t.Fatalf("err=%v sends=%d records=%d acks=%d", err, provider.calls, store.recordCalls, ack.calls)
	}
}

func TestWebhookDispatcherRejectsCancellationAndStoreProtocolErrors(t *testing.T) {
	now := time.Date(2026, 8, 31, 5, 0, 0, 0, time.UTC)
	config, incident, event := webhookDispatchFixture(t, now)
	for _, tc := range []struct {
		name        string
		cancelled   bool
		beginErr    error
		recordErr   error
		mismatch    bool
		wantBegins  int
		wantRecords int
		wantSends   int
	}{
		{name: "cancelled", cancelled: true},
		{name: "begin failure", beginErr: errors.New("secret=not-exposed"), wantBegins: 1},
		{name: "record failure", recordErr: errors.New("secret=not-exposed"), wantBegins: 1, wantRecords: 1, wantSends: 1},
		{name: "mismatched event", mismatch: true, wantBegins: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newWebhookDispatchStore(t, config, event, incident.FirstObserved, nil)
			store.beginErr, store.recordErr = tc.beginErr, tc.recordErr
			if tc.mismatch {
				other := event
				other.IncidentRevision++
				other.EventID = canonicalWebhookDeliveryEventID(other.IncidentFingerprint, other.IncidentRevision, other.PendingNotification, other.NotificationStage)
				store.begin.Event = &other
			}
			provider := &webhookDispatchProvider{}
			ack := &webhookDispatchAcknowledger{}
			dispatcher := &WebhookDispatcher{Store: store, Resolver: webhookDispatchResolver{provider: provider}, Acknowledger: ack, Clock: func() time.Time { return now }}
			ctx := context.Background()
			if tc.cancelled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := dispatcher.Dispatch(ctx, config, incident); !errors.Is(err, ErrWebhookDispatch) || store.beginCalls != tc.wantBegins || store.recordCalls != tc.wantRecords || provider.calls != tc.wantSends || ack.calls != 0 {
				t.Fatalf("err=%v begin=%d record=%d sends=%d acks=%d", err, store.beginCalls, store.recordCalls, provider.calls, ack.calls)
			}
		})
	}
}

func TestWebhookDispatcherRejectsNilProviderAndConcurrentDuplicateSendsOnce(t *testing.T) {
	now := time.Date(2026, 8, 31, 5, 0, 0, 0, time.UTC)
	config, incident, event := webhookDispatchFixture(t, now)
	store := newWebhookDispatchStore(t, config, event, incident.FirstObserved, nil)
	dispatcher := &WebhookDispatcher{Store: store, Resolver: webhookDispatchResolver{}, Acknowledger: &webhookDispatchAcknowledger{}, Clock: func() time.Time { return now }}
	if delivery, err := dispatcher.Dispatch(context.Background(), config, incident); !errors.Is(err, ErrWebhookDispatch) || store.result != WebhookDeliveryAttemptFailed || delivery.Status != WebhookDeliveryFailed {
		t.Fatalf("err=%v result=%q", err, store.result)
	}

	store = newWebhookDispatchStore(t, config, event, incident.FirstObserved, nil)
	provider := &webhookDispatchProvider{started: make(chan struct{}), block: make(chan struct{})}
	ack := &webhookDispatchAcknowledger{}
	dispatcher = &WebhookDispatcher{Store: store, Resolver: webhookDispatchResolver{provider: provider}, Acknowledger: ack, Clock: func() time.Time { return now }}
	firstDone := make(chan error, 1)
	go func() { _, err := dispatcher.Dispatch(context.Background(), config, incident); firstDone <- err }()
	<-provider.started
	secondDone := make(chan error, 1)
	go func() { _, err := dispatcher.Dispatch(context.Background(), config, incident); secondDone <- err }()
	close(provider.block)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	if provider.calls != 1 || store.recordCalls != 1 || ack.calls != 2 {
		t.Fatalf("sends=%d records=%d acks=%d", provider.calls, store.recordCalls, ack.calls)
	}
}

func TestWebhookDispatcherRejectsClockConfigAndGenerationDrift(t *testing.T) {
	now := time.Date(2026, 8, 31, 5, 0, 0, 0, time.UTC)
	config, incident, event := webhookDispatchFixture(t, now)
	for _, mutation := range []string{"clock", "config", "generation"} {
		t.Run(mutation, func(t *testing.T) {
			store := newWebhookDispatchStore(t, config, event, incident.FirstObserved, nil)
			clock := func() time.Time { return now }
			switch mutation {
			case "clock":
				store.begin.LastAttemptAt = webhookTime(now)
				store.begin.Status = WebhookDeliveryRetryableFailure
				store.begin.ConsecutiveFailureCount = 1
				clock = func() time.Time { return now }
			case "config":
				store.begin.ConfigDigest = "sha256:" + strings.Repeat("b", 64)
			case "generation":
				store.recordGenerationDelta = 2
			}
			provider := &webhookDispatchProvider{}
			ack := &webhookDispatchAcknowledger{}
			dispatcher := &WebhookDispatcher{Store: store, Resolver: webhookDispatchResolver{provider: provider}, Acknowledger: ack, Clock: clock}
			if _, err := dispatcher.Dispatch(context.Background(), config, incident); !errors.Is(err, ErrWebhookDispatch) || ack.calls != 0 {
				t.Fatalf("err=%v ack=%d", err, ack.calls)
			}
		})
	}
}

func TestTaskHostCollectorAcknowledgeEventRequiresExactPendingEvent(t *testing.T) {
	root := t.TempDir()
	store, err := NewTaskStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 8, 31, 5, 0, 0, 0, time.UTC)
	collector, err := NewTaskHostCollector(collectorProbes(nil, map[CheckKind]Severity{CheckDatabase: SeverityCritical}), store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := collector.Evaluate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	event, err := WebhookDeliveryEventFromIncident(evaluation.Decision.State)
	if err != nil {
		t.Fatal(err)
	}
	stale := event
	stale.IncidentRevision++
	stale.EventID = canonicalWebhookDeliveryEventID(stale.IncidentFingerprint, stale.IncidentRevision, stale.PendingNotification, stale.NotificationStage)
	if _, err := collector.AcknowledgeEvent(stale); err == nil {
		t.Fatal("stale event acknowledged")
	}
	if state, err := collector.AcknowledgeEvent(event); err != nil || state.PendingNotification != "" {
		t.Fatalf("state=%+v err=%v", state, err)
	}
}

type webhookDispatchStore struct {
	mu                    sync.Mutex
	begin                 DeliveryHealthV1
	beginErr              error
	recordErr             error
	result                WebhookDeliveryAttemptResult
	beginCalls            int
	recordCalls           int
	recordGenerationDelta int64
	trace                 *[]string
}

func newWebhookDispatchStore(t *testing.T, config WebhookConfigV1, event WebhookDeliveryEventV1, occurredAt time.Time, trace *[]string) *webhookDispatchStore {
	t.Helper()
	digest, err := CanonicalWebhookConfigDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	return &webhookDispatchStore{begin: DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 1, OldestPendingAt: webhookTime(occurredAt), Status: WebhookDeliveryPending, Event: &event}, trace: trace}
}

func (s *webhookDispatchStore) BeginDelivery(_ WebhookConfigV1, _ WebhookDeliveryEventV1, _ time.Time) (DeliveryHealthV1, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.beginCalls++
	webhookDispatchTrace(s.trace, "begin")
	return s.begin, s.beginErr
}

func (s *webhookDispatchStore) RecordDeliveryAttempt(_ WebhookConfigV1, _ WebhookDeliveryEventV1, generation int64, at time.Time, result WebhookDeliveryAttemptResult) (DeliveryHealthV1, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recordCalls++
	webhookDispatchTrace(s.trace, "record")
	if s.recordErr != nil || generation != s.begin.Revision {
		return DeliveryHealthV1{}, errors.New("unexpected generation")
	}
	s.result = result
	next := s.begin
	delta := s.recordGenerationDelta
	if delta == 0 {
		delta = 1
	}
	next.Revision += delta
	next.LastAttemptAt = webhookTime(at)
	switch result {
	case WebhookDeliveryAttemptDelivered:
		next.Status, next.OldestPendingAt, next.LastDeliveredAt = WebhookDeliveryDelivered, nil, webhookTime(at)
	case WebhookDeliveryAttemptRetryableFailure:
		next.Status, next.ConsecutiveFailureCount = WebhookDeliveryRetryableFailure, next.ConsecutiveFailureCount+1
	case WebhookDeliveryAttemptFailed:
		next.Status, next.OldestPendingAt, next.TerminalFailureCount = WebhookDeliveryFailed, nil, next.TerminalFailureCount+1
	}
	s.begin = next
	return next, nil
}

type webhookDispatchResolver struct {
	provider contracts.NotificationProvider
	err      error
	trace    *[]string
}

func (r webhookDispatchResolver) ResolveWebhookNotificationProvider(_ context.Context, _ WebhookConfigV1, _ contracts.OperationContext) (contracts.NotificationProvider, error) {
	webhookDispatchTrace(r.trace, "resolve")
	return r.provider, r.err
}

type webhookDispatchProvider struct {
	mu           sync.Mutex
	trace        *[]string
	err          error
	notification contracts.Notification
	operation    contracts.OperationContext
	calls        int
	started      chan struct{}
	block        chan struct{}
}

func (p *webhookDispatchProvider) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{}
}
func (p *webhookDispatchProvider) Test(context.Context, contracts.OperationContext) error { return nil }
func (p *webhookDispatchProvider) Send(_ context.Context, notification contracts.Notification, operation contracts.OperationContext) error {
	p.mu.Lock()
	p.calls++
	p.notification, p.operation = notification, operation
	webhookDispatchTrace(p.trace, "send")
	started, block, err := p.started, p.block, p.err
	p.mu.Unlock()
	if started != nil {
		close(started)
	}
	if block != nil {
		<-block
	}
	return err
}

type webhookDispatchAcknowledger struct {
	mu    sync.Mutex
	trace *[]string
	err   error
	calls int
}

func (a *webhookDispatchAcknowledger) AcknowledgeEvent(WebhookDeliveryEventV1) (IncidentState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	webhookDispatchTrace(a.trace, "ack")
	return IncidentState{}, a.err
}

func webhookDispatchTrace(trace *[]string, value string) {
	if trace != nil {
		*trace = append(*trace, value)
	}
}

func webhookDispatchFixture(t *testing.T, now time.Time) (WebhookConfigV1, IncidentState, WebhookDeliveryEventV1) {
	t.Helper()
	config := webhookConfigFixture(now.Add(-time.Hour))
	incident := IncidentState{SchemaVersion: SchemaVersion, Revision: 1, Fingerprint: strings.Repeat("a", 64), FirstObserved: now.Add(-2 * time.Minute), LastObserved: now.Add(-time.Minute), Severity: SeverityCritical, NotificationStage: 1, PendingNotification: "occurrence"}
	event, err := WebhookDeliveryEventFromIncident(incident)
	if err != nil {
		t.Fatal(err)
	}
	return config, incident, event
}

func webhookDispatchStatus(result WebhookDeliveryAttemptResult) WebhookDeliveryHealthStatus {
	switch result {
	case WebhookDeliveryAttemptRetryableFailure:
		return WebhookDeliveryRetryableFailure
	case WebhookDeliveryAttemptFailed:
		return WebhookDeliveryFailed
	default:
		return WebhookDeliveryDelivered
	}
}
