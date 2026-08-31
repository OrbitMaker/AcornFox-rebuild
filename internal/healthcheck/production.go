package healthcheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/providers/edgeprobe"
	secretprovider "github.com/open-card/open-card/internal/providers/secret"
)

// ErrProductionHealthcheck is the sole error exposed by the production
// composition root. In particular it never exposes a host path, receiver URL,
// secret reference, database connection material, or provider failure.
var ErrProductionHealthcheck = errors.New("production healthcheck failed")

const (
	productionHealthStateRoot          = "/var/lib/open-card/healthcheck"
	productionSecretRoot               = "/var/lib/open-card/secrets"
	productionHealthSecretMaterialRoot = "/var/lib/open-card/health-secret-materials"
	productionSecretMasterKey          = "/etc/open-card/build-secret.key"
	productionSecretMaterialTTL        = 2 * time.Minute
	productionHealthMaterialUID        = 0
	productionHealthMaterialGID        = 0
	productionHealthMaterialMode       = 0o700
)

// productionRunnerConfig is the task-only construction seam. Public
// production construction always uses the installed constants below.
type productionRunnerConfig struct {
	Root         string
	MaterialRoot string
	MasterKey    string
	TTL          time.Duration
}

func (c productionRunnerConfig) valid() bool {
	if !productionCleanAbsolutePath(c.Root) || !productionCleanAbsolutePath(c.MaterialRoot) || !productionCleanAbsolutePath(c.MasterKey) || c.Root == c.MaterialRoot {
		return false
	}
	return c.TTL > 0 && c.TTL <= secretprovider.MaxMaterialTTL
}

func productionCleanAbsolutePath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value
}

// ProductionCollector is the exact collector operation the runner needs. It
// is public only to make task-local composition tests possible; production
// construction always supplies TaskHostCollector.
type ProductionCollector interface {
	Evaluate(context.Context) (Evaluation, error)
	CurrentIncident() (IncidentState, error)
}

// ProductionDispatcher is the exact one-event delivery boundary owned by the
// runner. WebhookDispatcher is the production implementation.
type ProductionDispatcher interface {
	Dispatch(context.Context, WebhookConfigV1, IncidentState) (DeliveryHealthV1, error)
}

// ProductionCloser is a resource acquired by the runner. Resources are closed
// in reverse acquisition order and detached even if Close reports ambiguity.
type ProductionCloser interface {
	Close() error
}

// ProductionDeliveryResult is the deliberately small, JSON-safe delivery
// projection. It contains no endpoint, secret reference, payload, provider
// error, filesystem root, or response data.
type ProductionDeliveryResult struct {
	Status     WebhookDeliveryHealthStatus `json:"status,omitempty"`
	Generation int64                       `json:"generation,omitempty"`
	EventID    string                      `json:"event_id,omitempty"`
	Delivered  bool                        `json:"delivered"`
}

// ProductionRunResult is safe to serialize directly. Snapshot and incident
// contracts contain only hashes and bounded health state; delivery is reduced
// to its durable identity and outcome.
type ProductionRunResult struct {
	Snapshot      Snapshot                 `json:"snapshot"`
	IncidentState IncidentState            `json:"incident_state"`
	Delivery      ProductionDeliveryResult `json:"delivery"`
}

// ProductionRunner owns the production health resources for one process. It
// evaluates exactly once per RunOnce call and dispatches only the durable
// pending notification returned by that evaluation.
type ProductionRunner struct {
	mu         sync.Mutex
	collector  ProductionCollector
	source     WebhookHealthSource
	dispatcher ProductionDispatcher
	closers    []ProductionCloser
	closed     bool
}

// NewTaskProductionRunner is an explicit task-only constructor. It accepts
// fully injected dependencies and never opens a production path or host
// resource. Closers must be supplied in acquisition order.
func NewTaskProductionRunner(collector ProductionCollector, source WebhookHealthSource, dispatcher ProductionDispatcher, closers ...ProductionCloser) (*ProductionRunner, error) {
	if collector == nil || source == nil || dispatcher == nil {
		return nil, ErrProductionHealthcheck
	}
	owned := append([]ProductionCloser(nil), closers...)
	for _, closer := range owned {
		if closer == nil {
			return nil, ErrProductionHealthcheck
		}
	}
	return &ProductionRunner{collector: collector, source: source, dispatcher: dispatcher, closers: owned}, nil
}

// RunOnce evaluates the complete fixed health snapshot and, when present,
// dispatches precisely its pending incident notification. Any failure leaves
// the collector's durable pending state intact for a later retry.
func (r *ProductionRunner) RunOnce(ctx context.Context) (ProductionRunResult, error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return ProductionRunResult{}, ErrProductionHealthcheck
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.collector == nil || r.source == nil || r.dispatcher == nil {
		return ProductionRunResult{}, ErrProductionHealthcheck
	}

	evaluation, err := r.collector.Evaluate(ctx)
	if err != nil || evaluation.Snapshot.Validate() != nil || evaluation.Decision.State.Validate() != nil {
		return ProductionRunResult{}, ErrProductionHealthcheck
	}
	result := ProductionRunResult{Snapshot: evaluation.Snapshot, IncidentState: evaluation.Decision.State}
	if evaluation.Decision.State.PendingNotification == "" {
		return result, nil
	}

	observation, err := r.source.WebhookHealth(ctx)
	if err != nil || observation.Config == nil || observation.Config.Validate() != nil || !observation.Config.Enabled {
		return result, ErrProductionHealthcheck
	}
	event, err := WebhookDeliveryEventFromIncident(evaluation.Decision.State)
	if err != nil {
		return result, ErrProductionHealthcheck
	}
	digest, err := CanonicalWebhookConfigDigest(*observation.Config)
	if err != nil {
		return result, ErrProductionHealthcheck
	}
	delivery, dispatchErr := r.dispatcher.Dispatch(ctx, *observation.Config, evaluation.Decision.State)
	result.Delivery = productionDeliveryResult(delivery)
	if dispatchErr != nil {
		return result, ErrProductionHealthcheck
	}
	if !exactProductionDelivery(delivery, event, digest, observation.Delivery) {
		return result, ErrProductionHealthcheck
	}
	expected, err := AcknowledgeDelivery(evaluation.Decision.State)
	if err != nil {
		return result, ErrProductionHealthcheck
	}
	acknowledged, err := r.collector.CurrentIncident()
	if err != nil || acknowledged != expected {
		return result, ErrProductionHealthcheck
	}
	result.IncidentState = acknowledged
	return result, nil
}

func exactProductionDelivery(delivery DeliveryHealthV1, event WebhookDeliveryEventV1, digest string, previous *DeliveryHealthV1) bool {
	if delivery.Validate() != nil || delivery.Status != WebhookDeliveryDelivered || delivery.ConfigDigest != digest || delivery.Event == nil || !sameWebhookDeliveryEvent(*delivery.Event, event) || delivery.Revision < 1 {
		return false
	}
	if previous == nil {
		return delivery.Revision == 2
	}
	if previous.Validate() != nil {
		return false
	}
	if previous.ConfigDigest != digest {
		return (previous.Status == WebhookDeliveryUnproven || previous.Status == WebhookDeliveryDelivered || previous.Status == WebhookDeliveryFailed) && delivery.Revision == previous.Revision+2
	}
	sameEvent := previous.Event != nil && sameWebhookDeliveryEvent(*previous.Event, event)
	switch previous.Status {
	case WebhookDeliveryPending, WebhookDeliveryRetryableFailure:
		return sameEvent && delivery.Revision == previous.Revision+1
	case WebhookDeliveryDelivered:
		// A crash after recording delivery but before acknowledgement replays the
		// same durable event without another generation or provider attempt.
		if sameEvent {
			return delivery.Revision == previous.Revision
		}
		return delivery.Revision == previous.Revision+2
	case WebhookDeliveryUnproven:
		return delivery.Revision == previous.Revision+2
	default:
		return false
	}
}

func productionDeliveryResult(delivery DeliveryHealthV1) ProductionDeliveryResult {
	if delivery.Validate() != nil || delivery.Event == nil {
		return ProductionDeliveryResult{}
	}
	return ProductionDeliveryResult{
		Status:     delivery.Status,
		Generation: delivery.Revision,
		EventID:    delivery.Event.EventID,
		Delivered:  delivery.Status == WebhookDeliveryDelivered,
	}
}

// Close detaches every owned resource before closing it. A close ambiguity is
// intentionally reduced to ErrProductionHealthcheck and cannot make a later
// Close retry a stale handle.
func (r *ProductionRunner) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	closers := r.closers
	r.closers = nil
	r.collector, r.source, r.dispatcher = nil, nil, nil
	r.mu.Unlock()

	var failed bool
	for index := len(closers) - 1; index >= 0; index-- {
		if closers[index] != nil && closers[index].Close() != nil {
			failed = true
		}
	}
	if failed {
		return ErrProductionHealthcheck
	}
	return nil
}

type productionWebhookStore interface {
	WebhookHealthSource
	WebhookDeliveryStore
	ProductionCloser
}

type productionService interface {
	ServiceSnapshotSource
	ProductionCloser
}

type productionBackup interface {
	LatestBackupSource
	ProductionCloser
}

type productionResolver interface {
	WebhookProviderResolver
	ProductionCloser
}

type productionRunnerFactories struct {
	upgradeService     func() (productionService, error)
	localProbes        func(ServiceSnapshotSource) ([]HostProbe, error)
	listenerSource     func() (ListenerSource, error)
	runtimePorts       func() (RuntimePortSource, error)
	databaseProbe      func() (HostProbe, error)
	backupManager      func() (productionBackup, error)
	certificateTargets func() (CertificateTargetSource, error)
	certificateObserve func() edgeprobe.CertificateObserver
	webhookStore       func() (productionWebhookStore, error)
	stateStore         func() (*TaskStateStore, error)
	secrets            func(secretprovider.Config) (*secretprovider.Provider, error)
	resolver           func(*secretprovider.Provider, string) (productionResolver, error)
}

func defaultProductionRunnerFactories() productionRunnerFactories {
	return productionRunnerFactories{
		upgradeService: func() (productionService, error) {
			return install.ProductionUpgradeServiceAdapter()
		},
		localProbes:    NewProductionLocalProbes,
		listenerSource: NewProductionListenerSource,
		runtimePorts:   NewProductionPostgresRuntimePortSource,
		databaseProbe:  NewProductionDatabaseProbe,
		backupManager: func() (productionBackup, error) {
			return install.ProductionBackupManager()
		},
		certificateTargets: NewProductionPostgresCertificateTargetSource,
		certificateObserve: edgeprobe.NewCertificateObserver,
		webhookStore: func() (productionWebhookStore, error) {
			return NewProductionWebhookFileStore()
		},
		stateStore: NewProductionStateStore,
		secrets:    secretprovider.OpenExisting,
		resolver: func(provider *secretprovider.Provider, materialRoot string) (productionResolver, error) {
			return NewProductionWebhookProviderResolver(provider, materialRoot)
		},
	}
}

// NewProductionRunner constructs the complete fixed host-health graph. It
// accepts no caller paths, URLs, DSNs, or runtime targets. The read-only
// secret preflight fails before acquiring host-facing production resources.
func NewProductionRunner() (*ProductionRunner, error) {
	config := productionRunnerConfig{Root: productionSecretRoot, MaterialRoot: productionHealthSecretMaterialRoot, MasterKey: productionSecretMasterKey, TTL: productionSecretMaterialTTL}
	if !validProductionHealthMaterialRoot(config.MaterialRoot) {
		return nil, ErrProductionHealthcheck
	}
	preflight, err := secretprovider.OpenExisting(secretprovider.Config{Root: config.Root, MaterialRoot: config.MaterialRoot, MasterKeyPath: config.MasterKey, MaterialTTL: config.TTL})
	if err != nil || preflight == nil {
		return nil, ErrProductionHealthcheck
	}
	if err := preflight.Close(); err != nil {
		return nil, ErrProductionHealthcheck
	}
	return newProductionRunner(config, defaultProductionRunnerFactories())
}

// validProductionHealthMaterialRoot enforces the dedicated root-owned 0700
// plaintext boundary before any host-facing resource acquisition. Provisioning
// this directory belongs to the separate installer command task.
func validProductionHealthMaterialRoot(path string) bool {
	if path != productionHealthSecretMaterialRoot {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != productionHealthMaterialMode {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == productionHealthMaterialUID && int(stat.Gid) == productionHealthMaterialGID
}

// newProductionRunner is intentionally package-private so tests can replace
// every production opener and prove construction without observing the live
// machine. Production callers use NewProductionRunner.
func newProductionRunner(config productionRunnerConfig, factories productionRunnerFactories) (*ProductionRunner, error) {
	if !config.valid() || !factories.valid() {
		return nil, ErrProductionHealthcheck
	}
	closers := make([]ProductionCloser, 0, 6)
	fail := func() (*ProductionRunner, error) {
		_ = closeProductionClosers(closers)
		return nil, ErrProductionHealthcheck
	}

	service, err := factories.upgradeService()
	if err != nil || service == nil {
		return fail()
	}
	closers = append(closers, service)
	local, err := factories.localProbes(service)
	if err != nil {
		return fail()
	}
	listenerSource, err := factories.listenerSource()
	if err != nil || listenerSource == nil {
		return fail()
	}
	runtimePorts, err := factories.runtimePorts()
	if err != nil || runtimePorts == nil {
		return fail()
	}
	listener, err := NewListenerProbe(listenerSource, runtimePorts, FixedSSHPort22Policy{})
	if err != nil {
		return fail()
	}
	database, err := factories.databaseProbe()
	if err != nil {
		return fail()
	}
	backupManager, err := factories.backupManager()
	if err != nil || backupManager == nil {
		return fail()
	}
	closers = append(closers, backupManager)
	now := func() time.Time { return time.Now().UTC() }
	backup, err := NewTaskBackupProbe(backupManager, now)
	if err != nil {
		return fail()
	}
	certificateTargets, err := factories.certificateTargets()
	if err != nil || certificateTargets == nil {
		return fail()
	}
	observer := factories.certificateObserve()
	if observer == nil {
		return fail()
	}
	certificate, err := NewTaskCertificateProbe(certificateTargets, observer, now)
	if err != nil {
		return fail()
	}
	webhooks, err := factories.webhookStore()
	if err != nil || webhooks == nil {
		return fail()
	}
	closers = append(closers, webhooks)
	webhook, err := NewTaskWebhookProbe(webhooks, now)
	if err != nil {
		return fail()
	}
	state, err := factories.stateStore()
	if err != nil || state == nil {
		return fail()
	}
	closers = append(closers, state)
	secrets, err := factories.secrets(secretprovider.Config{Root: config.Root, MaterialRoot: config.MaterialRoot, MasterKeyPath: config.MasterKey, MaterialTTL: config.TTL})
	if err != nil || secrets == nil {
		return fail()
	}
	closers = append(closers, secrets)
	resolver, err := factories.resolver(secrets, config.MaterialRoot)
	if err != nil || resolver == nil {
		return fail()
	}
	closers = append(closers, resolver)

	probes, err := canonicalProductionProbes(append(local, listener, database, backup, certificate, webhook))
	if err != nil {
		return fail()
	}
	collector, err := NewTaskHostCollector(probes, state, now)
	if err != nil {
		return fail()
	}
	dispatcher := &WebhookDispatcher{Store: webhooks, Resolver: resolver, Acknowledger: collector, Clock: now}
	runner, err := NewTaskProductionRunner(collector, webhooks, dispatcher, closers...)
	if err != nil {
		return fail()
	}
	return runner, nil
}

func (f productionRunnerFactories) valid() bool {
	return f.upgradeService != nil && f.localProbes != nil && f.listenerSource != nil && f.runtimePorts != nil && f.databaseProbe != nil && f.backupManager != nil && f.certificateTargets != nil && f.certificateObserve != nil && f.webhookStore != nil && f.stateStore != nil && f.secrets != nil && f.resolver != nil
}

func canonicalProductionProbes(probes []HostProbe) ([]HostProbe, error) {
	if len(probes) != len(fixedKinds) {
		return nil, ErrProductionHealthcheck
	}
	byKind := make(map[CheckKind]HostProbe, len(probes))
	for _, probe := range probes {
		if !validKind(probe.Kind) || probe.Check == nil {
			return nil, ErrProductionHealthcheck
		}
		if _, exists := byKind[probe.Kind]; exists {
			return nil, ErrProductionHealthcheck
		}
		byKind[probe.Kind] = probe
	}
	ordered := make([]HostProbe, 0, len(fixedKinds))
	for _, kind := range fixedKinds {
		probe, exists := byKind[kind]
		if !exists {
			return nil, ErrProductionHealthcheck
		}
		ordered = append(ordered, probe)
	}
	return ordered, nil
}

func closeProductionClosers(closers []ProductionCloser) error {
	var first error
	for index := len(closers) - 1; index >= 0; index-- {
		if closers[index] != nil {
			if err := closers[index].Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}
