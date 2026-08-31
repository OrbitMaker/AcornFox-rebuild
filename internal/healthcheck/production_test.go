package healthcheck

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/providers/edgeprobe"
	secretprovider "github.com/open-card/open-card/internal/providers/secret"
)

type productionRunnerCollectorStub struct {
	evaluation Evaluation
	current    IncidentState
	err        error
	calls      int
}

func (s *productionRunnerCollectorStub) Evaluate(context.Context) (Evaluation, error) {
	s.calls++
	return s.evaluation, s.err
}
func (s *productionRunnerCollectorStub) CurrentIncident() (IncidentState, error) {
	if s.current.Validate() == nil {
		return s.current, nil
	}
	return s.evaluation.Decision.State, nil
}

type productionRunnerSourceStub struct {
	observation WebhookHealthObservation
	err         error
	calls       int
}

func (s *productionRunnerSourceStub) WebhookHealth(context.Context) (WebhookHealthObservation, error) {
	s.calls++
	return s.observation, s.err
}

type productionRunnerDispatcherStub struct {
	delivery DeliveryHealthV1
	err      error
	calls    int
}

func (s *productionRunnerDispatcherStub) Dispatch(context.Context, WebhookConfigV1, IncidentState) (DeliveryHealthV1, error) {
	s.calls++
	return s.delivery, s.err
}

type productionRunnerCloserStub struct {
	name  string
	trace *[]string
	err   error
}

func TestProductionHealthSecretMaterialRootContract(t *testing.T) {
	if productionHealthSecretMaterialRoot != "/var/lib/open-card/health-secret-materials" || productionSecretRoot != "/var/lib/open-card/secrets" || productionSecretMasterKey != "/etc/open-card/build-secret.key" || productionSecretMaterialTTL != 2*time.Minute || productionHealthMaterialUID != 0 || productionHealthMaterialGID != 0 || productionHealthMaterialMode != 0o700 {
		t.Fatal("production health secret material contract changed")
	}
	if validProductionHealthMaterialRoot(t.TempDir()) {
		t.Fatal("non-production material root accepted")
	}
}

func (s productionRunnerCloserStub) Close() error {
	*s.trace = append(*s.trace, s.name)
	return s.err
}

func TestProductionRunnerTaskNoopAndSafeFailure(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	healthy := IncidentState{SchemaVersion: SchemaVersion, Revision: 1, Fingerprint: HealthyFingerprint, FirstObserved: now, LastObserved: now, Severity: SeverityOK, Healthy: true}
	collector := &productionRunnerCollectorStub{evaluation: Evaluation{Snapshot: snapshotAt(now, nil), Decision: Decision{State: healthy, Noop: true}}}
	source := &productionRunnerSourceStub{}
	dispatcher := &productionRunnerDispatcherStub{}
	runner, err := NewTaskProductionRunner(collector, source, dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.RunOnce(context.Background())
	if err != nil || source.calls != 0 || dispatcher.calls != 0 || result.IncidentState.PendingNotification != "" || result.Snapshot.Validate() != nil {
		t.Fatalf("result=%#v source=%d dispatcher=%d err=%v", result, source.calls, dispatcher.calls, err)
	}

	incident := productionRunnerOccurrence(t, now)
	collector.evaluation = Evaluation{Snapshot: snapshotAt(now.Add(time.Minute), map[CheckKind]Severity{CheckWebhook: SeverityCritical}), Decision: Decision{State: incident, Notify: true}}
	result, err = runner.RunOnce(context.Background())
	if !errors.Is(err, ErrProductionHealthcheck) || result.IncidentState != incident || dispatcher.calls != 0 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	raw, marshalErr := json.Marshal(result)
	if marshalErr != nil || strings.Contains(string(raw), "https://") || strings.Contains(err.Error(), "https://") {
		t.Fatalf("unsafe result %s / %v", raw, marshalErr)
	}
}

func TestProductionRunnerDispatchesExactPendingEvent(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	config := webhookConfigFixture(now.Add(-time.Hour))
	incident := productionRunnerOccurrence(t, now)
	event, err := WebhookDeliveryEventFromIncident(incident)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := CanonicalWebhookConfigDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	attempt := now.Add(time.Second)
	delivery := DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 2, LastAttemptAt: &attempt, LastDeliveredAt: &attempt, Status: WebhookDeliveryDelivered, Event: &event}
	collector := &productionRunnerCollectorStub{evaluation: Evaluation{Snapshot: snapshotAt(now, map[CheckKind]Severity{CheckWebhook: SeverityCritical}), Decision: Decision{State: incident, Notify: true}}}
	collector.current, _ = AcknowledgeDelivery(incident)
	source := &productionRunnerSourceStub{observation: WebhookHealthObservation{Config: &config}}
	dispatcher := &productionRunnerDispatcherStub{delivery: delivery}
	runner, err := NewTaskProductionRunner(collector, source, dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.RunOnce(context.Background())
	if err != nil || dispatcher.calls != 1 || !result.Delivery.Delivered || result.Delivery.Generation != 2 || result.Delivery.EventID != event.EventID || result.IncidentState.PendingNotification != "" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestProductionRunnerRetainsPendingOnRetryAndTerminalDelivery(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	config := webhookConfigFixture(now.Add(-time.Hour))
	incident := productionRunnerOccurrence(t, now)
	event, err := WebhookDeliveryEventFromIncident(incident)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := CanonicalWebhookConfigDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, delivery := range []DeliveryHealthV1{
		{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 2, OldestPendingAt: productionRunnerTime(now), LastAttemptAt: productionRunnerTime(now.Add(time.Second)), Status: WebhookDeliveryRetryableFailure, ConsecutiveFailureCount: 1, Event: &event},
		{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 2, LastAttemptAt: productionRunnerTime(now.Add(time.Second)), Status: WebhookDeliveryFailed, TerminalFailureCount: 1, Event: &event},
	} {
		collector := &productionRunnerCollectorStub{evaluation: Evaluation{Snapshot: snapshotAt(now, map[CheckKind]Severity{CheckWebhook: SeverityCritical}), Decision: Decision{State: incident, Notify: true}}}
		dispatcher := &productionRunnerDispatcherStub{delivery: delivery, err: errors.New("secret provider cause")}
		runner, err := NewTaskProductionRunner(collector, &productionRunnerSourceStub{observation: WebhookHealthObservation{Config: &config}}, dispatcher)
		if err != nil {
			t.Fatal(err)
		}
		result, err := runner.RunOnce(context.Background())
		if !errors.Is(err, ErrProductionHealthcheck) || result.IncidentState != incident || result.Delivery.Status != delivery.Status || result.Delivery.Delivered || strings.Contains(err.Error(), "secret") {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	}
}

func TestProductionRunnerRequiresPersistedExactAcknowledgement(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	config := webhookConfigFixture(now.Add(-time.Hour))
	incident := productionRunnerOccurrence(t, now)
	event, err := WebhookDeliveryEventFromIncident(incident)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := CanonicalWebhookConfigDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	attempt := now.Add(time.Second)
	delivery := DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 2, LastAttemptAt: &attempt, LastDeliveredAt: &attempt, Status: WebhookDeliveryDelivered, Event: &event}
	collector := &productionRunnerCollectorStub{evaluation: Evaluation{Snapshot: snapshotAt(now, map[CheckKind]Severity{CheckWebhook: SeverityCritical}), Decision: Decision{State: incident, Notify: true}}, current: incident}
	runner, err := NewTaskProductionRunner(collector, &productionRunnerSourceStub{observation: WebhookHealthObservation{Config: &config}}, &productionRunnerDispatcherStub{delivery: delivery})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := runner.RunOnce(context.Background()); !errors.Is(err, ErrProductionHealthcheck) || result.IncidentState != incident {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestProductionRunnerRejectsMismatchedDeliveredState(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	config := webhookConfigFixture(now.Add(-time.Hour))
	incident := productionRunnerOccurrence(t, now)
	event, err := WebhookDeliveryEventFromIncident(incident)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := CanonicalWebhookConfigDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	attempt := now.Add(time.Second)
	delivered := DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 4, LastAttemptAt: &attempt, LastDeliveredAt: &attempt, Status: WebhookDeliveryDelivered, Event: &event}
	otherIncident := incident
	otherIncident.Revision = 2
	otherEvent, err := WebhookDeliveryEventFromIncident(otherIncident)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		delivery DeliveryHealthV1
		previous *DeliveryHealthV1
	}{
		{name: "event", delivery: func() DeliveryHealthV1 { value := delivered; value.Event = &otherEvent; return value }()},
		{name: "digest", delivery: func() DeliveryHealthV1 {
			value := delivered
			value.ConfigDigest = "sha256:" + strings.Repeat("b", 64)
			return value
		}()},
		{name: "generation", delivery: func() DeliveryHealthV1 { value := delivered; value.Revision = 3; return value }(), previous: func() *DeliveryHealthV1 {
			value := DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 3, OldestPendingAt: productionRunnerTime(now), Status: WebhookDeliveryPending, Event: &event}
			return &value
		}()},
		{name: "generation gap", delivery: func() DeliveryHealthV1 { value := delivered; value.Revision = 5; return value }(), previous: func() *DeliveryHealthV1 {
			value := DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 3, OldestPendingAt: productionRunnerTime(now), Status: WebhookDeliveryPending, Event: &event}
			return &value
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			collector := &productionRunnerCollectorStub{evaluation: Evaluation{Snapshot: snapshotAt(now, map[CheckKind]Severity{CheckWebhook: SeverityCritical}), Decision: Decision{State: incident, Notify: true}}, current: incident}
			source := &productionRunnerSourceStub{observation: WebhookHealthObservation{Config: &config, Delivery: tc.previous}}
			runner, err := NewTaskProductionRunner(collector, source, &productionRunnerDispatcherStub{delivery: tc.delivery})
			if err != nil {
				t.Fatal(err)
			}
			if result, err := runner.RunOnce(context.Background()); !errors.Is(err, ErrProductionHealthcheck) || result.IncidentState != incident {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
}

func TestProductionRunnerCancellationDoesNotEvaluate(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	state := IncidentState{SchemaVersion: SchemaVersion, Revision: 1, Fingerprint: HealthyFingerprint, FirstObserved: now, LastObserved: now, Severity: SeverityOK, Healthy: true}
	collector := &productionRunnerCollectorStub{evaluation: Evaluation{Snapshot: snapshotAt(now, nil), Decision: Decision{State: state}}}
	runner, err := NewTaskProductionRunner(collector, &productionRunnerSourceStub{}, &productionRunnerDispatcherStub{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runner.RunOnce(ctx); !errors.Is(err, ErrProductionHealthcheck) || collector.calls != 0 {
		t.Fatalf("error=%v calls=%d", err, collector.calls)
	}
}

func TestProductionRunnerCloseIsReverseAndDetachesOnFailure(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	state := IncidentState{SchemaVersion: SchemaVersion, Revision: 1, Fingerprint: HealthyFingerprint, FirstObserved: now, LastObserved: now, Severity: SeverityOK, Healthy: true}
	collector := &productionRunnerCollectorStub{evaluation: Evaluation{Snapshot: snapshotAt(now, nil), Decision: Decision{State: state}}}
	trace := []string{}
	runner, err := NewTaskProductionRunner(collector, &productionRunnerSourceStub{}, &productionRunnerDispatcherStub{}, productionRunnerCloserStub{name: "first", trace: &trace}, productionRunnerCloserStub{name: "second", trace: &trace, err: errors.New("close cause")})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Close(); !errors.Is(err, ErrProductionHealthcheck) || strings.Join(trace, ",") != "second,first" {
		t.Fatalf("close=%v trace=%v", err, trace)
	}
	if err := runner.Close(); err != nil || len(trace) != 2 {
		t.Fatalf("repeat close=%v trace=%v", err, trace)
	}
	if _, err := runner.RunOnce(context.Background()); !errors.Is(err, ErrProductionHealthcheck) {
		t.Fatalf("closed runner error=%v", err)
	}
}

func TestCanonicalProductionProbesRejectsMissingAndDuplicates(t *testing.T) {
	probes := make([]HostProbe, 0, len(fixedKinds))
	for _, kind := range fixedKinds {
		probes = append(probes, HostProbe{Kind: kind, Check: func(context.Context) (HostFact, error) { return HostFact{Subject: "fixed", Severity: SeverityOK}, nil }})
	}
	ordered, err := canonicalProductionProbes(probes)
	if err != nil || len(ordered) != len(fixedKinds) {
		t.Fatalf("ordered=%#v err=%v", ordered, err)
	}
	for index, kind := range fixedKinds {
		if ordered[index].Kind != kind {
			t.Fatalf("index %d: %q", index, ordered[index].Kind)
		}
	}
	probes[len(probes)-1].Kind = probes[0].Kind
	if _, err := canonicalProductionProbes(probes); !errors.Is(err, ErrProductionHealthcheck) {
		t.Fatalf("duplicate error=%v", err)
	}
}

func TestProductionConstructorUsesInjectedFactories(t *testing.T) {
	base := t.TempDir()
	config := productionRunnerConfig{Root: filepath.Join(base, "secrets"), MaterialRoot: filepath.Join(base, "materials"), MasterKey: filepath.Join(base, "master.key"), TTL: time.Minute}
	trace := []string{}
	service := productionRunnerStaticService{trace: &trace}
	backup := productionRunnerStaticBackup{trace: &trace}
	webhooks := productionRunnerStaticWebhooks{trace: &trace}
	factories := defaultProductionRunnerFactories()
	factories.upgradeService = func() (productionService, error) { return service, nil }
	factories.localProbes = func(ServiceSnapshotSource) ([]HostProbe, error) {
		return productionRunnerLocalProbes(), nil
	}
	factories.listenerSource = func() (ListenerSource, error) {
		return ListenerSourceFunc(func(context.Context) (ListenerFacts, error) { return ListenerFacts{}, nil }), nil
	}
	factories.runtimePorts = func() (RuntimePortSource, error) {
		return RuntimePortSourceFunc(func(context.Context) ([]uint16, error) { return []uint16{8080}, nil }), nil
	}
	factories.databaseProbe = func() (HostProbe, error) { return productionRunnerProbe(CheckDatabase), nil }
	factories.backupManager = func() (productionBackup, error) { return backup, nil }
	factories.certificateTargets = func() (CertificateTargetSource, error) { return productionRunnerCertificateSource{}, nil }
	factories.certificateObserve = func() edgeprobe.CertificateObserver { return productionRunnerCertificateObserver{} }
	factories.webhookStore = func() (productionWebhookStore, error) { return webhooks, nil }
	factories.stateStore = func() (*TaskStateStore, error) { return NewTaskStateStore(t.TempDir()) }
	factories.secrets = secretprovider.New
	factories.resolver = func(*secretprovider.Provider, string) (productionResolver, error) {
		return productionRunnerStaticResolver{trace: &trace}, nil
	}
	runner, err := newProductionRunner(config, factories)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(trace, ",") != "resolver,webhook,backup,service" {
		t.Fatalf("unexpected close trace %v", trace)
	}
}

func TestProductionConstructorClosesAcquiredResourcesOnFailure(t *testing.T) {
	base := t.TempDir()
	config := productionRunnerConfig{Root: filepath.Join(base, "secrets"), MaterialRoot: filepath.Join(base, "materials"), MasterKey: filepath.Join(base, "master.key"), TTL: time.Minute}
	trace := []string{}
	factories := defaultProductionRunnerFactories()
	factories.upgradeService = func() (productionService, error) { return productionRunnerStaticService{trace: &trace}, nil }
	factories.localProbes = func(ServiceSnapshotSource) ([]HostProbe, error) { return productionRunnerLocalProbes(), nil }
	factories.listenerSource = func() (ListenerSource, error) {
		return ListenerSourceFunc(func(context.Context) (ListenerFacts, error) { return ListenerFacts{}, nil }), nil
	}
	factories.runtimePorts = func() (RuntimePortSource, error) {
		return RuntimePortSourceFunc(func(context.Context) ([]uint16, error) { return []uint16{8080}, nil }), nil
	}
	factories.databaseProbe = func() (HostProbe, error) { return productionRunnerProbe(CheckDatabase), nil }
	factories.backupManager = func() (productionBackup, error) { return nil, errors.New("backup unavailable") }
	if runner, err := newProductionRunner(config, factories); runner != nil || !errors.Is(err, ErrProductionHealthcheck) || strings.Join(trace, ",") != "service" {
		t.Fatalf("runner=%v err=%v trace=%v", runner, err, trace)
	}
}

func TestProductionRunnerPersistsAcknowledgementAcrossReopen(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	root := t.TempDir()
	store, err := NewTaskStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := NewTaskHostCollector(productionRunnerIncidentProbes(), store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	config := webhookConfigFixture(now.Add(-time.Hour))
	dispatcher := &productionRunnerAcknowledgingDispatcher{collector: collector, config: config, now: now.Add(time.Second)}
	runner, err := NewTaskProductionRunner(collector, &productionRunnerSourceStub{observation: WebhookHealthObservation{Config: &config}}, dispatcher, store)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.RunOnce(context.Background())
	if err != nil || result.IncidentState.PendingNotification != "" || !result.Delivery.Delivered {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if err := runner.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewTaskStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	collector, err = NewTaskHostCollector(productionRunnerIncidentProbes(), reopened, func() time.Time { return now.Add(time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := collector.CurrentIncident()
	if err != nil || persisted.PendingNotification != "" {
		t.Fatalf("persisted=%#v err=%v", persisted, err)
	}
}

func TestProductionRunnerSerializesRunOnceAndClose(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	state := IncidentState{SchemaVersion: SchemaVersion, Revision: 1, Fingerprint: HealthyFingerprint, FirstObserved: now, LastObserved: now, Severity: SeverityOK, Healthy: true}
	started := make(chan struct{})
	release := make(chan struct{})
	collector := &productionRunnerBlockingCollector{evaluation: Evaluation{Snapshot: snapshotAt(now, nil), Decision: Decision{State: state}}, started: started, release: release}
	trace := []string{}
	runner, err := NewTaskProductionRunner(collector, &productionRunnerSourceStub{}, &productionRunnerDispatcherStub{}, productionRunnerCloserStub{name: "closed", trace: &trace})
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { _, err := runner.RunOnce(context.Background()); runDone <- err }()
	<-started
	closeDone := make(chan error, 1)
	go func() { closeDone <- runner.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close raced RunOnce: %v", err)
	default:
	}
	close(release)
	if err := <-runDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil || strings.Join(trace, ",") != "closed" {
		t.Fatalf("close=%v trace=%v", err, trace)
	}
}

func productionRunnerOccurrence(t *testing.T, now time.Time) IncidentState {
	t.Helper()
	value := IncidentState{SchemaVersion: SchemaVersion, Revision: 1, Fingerprint: strings.Repeat("a", 64), FirstObserved: now.Add(-time.Minute), LastObserved: now, Severity: SeverityCritical, NotificationStage: 1, PendingNotification: "occurrence"}
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
	return value
}

func productionRunnerTime(value time.Time) *time.Time {
	value = value.UTC()
	return &value
}

func productionRunnerProbe(kind CheckKind) HostProbe {
	return HostProbe{Kind: kind, Check: func(context.Context) (HostFact, error) {
		return HostFact{Subject: "production-test", Severity: SeverityOK}, nil
	}}
}

func productionRunnerLocalProbes() []HostProbe {
	return []HostProbe{productionRunnerProbe(CheckFiveUnits), productionRunnerProbe(CheckControlAPI), productionRunnerProbe(CheckEdge), productionRunnerProbe(CheckDisk), productionRunnerProbe(CheckInode)}
}

func productionRunnerIncidentProbes() []HostProbe {
	probes := make([]HostProbe, 0, len(fixedKinds))
	for _, kind := range fixedKinds {
		severity := SeverityOK
		if kind == CheckDatabase {
			severity = SeverityCritical
		}
		kind, severity := kind, severity
		probes = append(probes, HostProbe{Kind: kind, Check: func(context.Context) (HostFact, error) {
			return HostFact{Subject: string(kind), Severity: severity}, nil
		}})
	}
	return probes
}

type productionRunnerAcknowledgingDispatcher struct {
	collector *TaskHostCollector
	config    WebhookConfigV1
	now       time.Time
}

func (d *productionRunnerAcknowledgingDispatcher) Dispatch(_ context.Context, config WebhookConfigV1, incident IncidentState) (DeliveryHealthV1, error) {
	if config != d.config {
		return DeliveryHealthV1{}, errors.New("unexpected config")
	}
	event, err := WebhookDeliveryEventFromIncident(incident)
	if err != nil {
		return DeliveryHealthV1{}, err
	}
	digest, err := CanonicalWebhookConfigDigest(config)
	if err != nil {
		return DeliveryHealthV1{}, err
	}
	if _, err := d.collector.AcknowledgeEvent(event); err != nil {
		return DeliveryHealthV1{}, err
	}
	attempt := d.now.UTC()
	return DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: 2, LastAttemptAt: &attempt, LastDeliveredAt: &attempt, Status: WebhookDeliveryDelivered, Event: &event}, nil
}

type productionRunnerBlockingCollector struct {
	evaluation Evaluation
	started    chan struct{}
	release    chan struct{}
}

func (c *productionRunnerBlockingCollector) Evaluate(context.Context) (Evaluation, error) {
	close(c.started)
	<-c.release
	return c.evaluation, nil
}

func (c *productionRunnerBlockingCollector) CurrentIncident() (IncidentState, error) {
	return c.evaluation.Decision.State, nil
}

type productionRunnerStaticService struct{ trace *[]string }

func (s productionRunnerStaticService) Capture(context.Context) (install.ServiceSnapshotV1, error) {
	return install.ServiceSnapshotV1{}, nil
}
func (s productionRunnerStaticService) Close() error {
	*s.trace = append(*s.trace, "service")
	return nil
}

type productionRunnerStaticBackup struct{ trace *[]string }

func (s productionRunnerStaticBackup) Latest(context.Context) (install.ActiveDatabaseBackupV2, error) {
	return install.ActiveDatabaseBackupV2{}, nil
}
func (s productionRunnerStaticBackup) Close() error {
	*s.trace = append(*s.trace, "backup")
	return nil
}

type productionRunnerStaticWebhooks struct{ trace *[]string }

func (s productionRunnerStaticWebhooks) WebhookHealth(context.Context) (WebhookHealthObservation, error) {
	return WebhookHealthObservation{}, nil
}
func (s productionRunnerStaticWebhooks) BeginDelivery(WebhookConfigV1, WebhookDeliveryEventV1, time.Time) (DeliveryHealthV1, error) {
	return DeliveryHealthV1{}, errors.New("not invoked")
}
func (s productionRunnerStaticWebhooks) RecordDeliveryAttempt(WebhookConfigV1, WebhookDeliveryEventV1, int64, time.Time, WebhookDeliveryAttemptResult) (DeliveryHealthV1, error) {
	return DeliveryHealthV1{}, errors.New("not invoked")
}
func (s productionRunnerStaticWebhooks) Close() error {
	*s.trace = append(*s.trace, "webhook")
	return nil
}

type productionRunnerStaticResolver struct{ trace *[]string }

func (s productionRunnerStaticResolver) ResolveWebhookNotificationProvider(context.Context, WebhookConfigV1, contracts.OperationContext) (contracts.NotificationProvider, error) {
	return nil, errors.New("not invoked")
}
func (s productionRunnerStaticResolver) Close() error {
	*s.trace = append(*s.trace, "resolver")
	return nil
}

type productionRunnerCertificateSource struct{}

func (productionRunnerCertificateSource) CertificateTargets(context.Context) ([]CertificateTarget, error) {
	return nil, errors.New("not invoked")
}

type productionRunnerCertificateObserver struct{}

func (productionRunnerCertificateObserver) ObserveCertificate(context.Context, string) (edgeprobe.CertificateObservation, error) {
	return edgeprobe.CertificateObservation{}, errors.New("not invoked")
}
