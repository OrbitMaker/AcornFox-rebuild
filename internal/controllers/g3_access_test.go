package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

type g3MemoryStore struct {
	mu       sync.Mutex
	apps     map[domain.ID]string
	platform *G3PlatformDomainFact
	domains  map[domain.ID]G3ApplicationDomainFact
	runtime  map[domain.ID]G3ApplicationAccessFacts
	idem     map[string]g3MemoryIdempotency
	unbind   map[string]G3DomainUnbindOperation
}

type g3MemoryIdempotency struct {
	digest string
	value  []byte
}

func (s *g3MemoryStore) ApplicationName(_ context.Context, applicationID domain.ID) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name, found := s.apps[applicationID]
	return name, found, nil
}
func (s *g3MemoryStore) PlatformDomain(context.Context) (G3PlatformDomainFact, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.platform == nil {
		return G3PlatformDomainFact{}, false, nil
	}
	return *s.platform, true, nil
}
func (s *g3MemoryStore) ReplayG3Idempotency(_ context.Context, request G3Idempotency) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, found := s.idem[request.Scope+":"+request.Key]
	if !found {
		return nil, false, nil
	}
	if item.digest != request.Digest {
		return nil, false, ErrG3IdempotencyConflict
	}
	return append([]byte(nil), item.value...), true, nil
}
func (s *g3MemoryStore) PutPlatformDomain(_ context.Context, fact G3PlatformDomainFact, request G3Idempotency) (G3PlatformDomainFact, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if value, replay, err := s.platformReplayLocked(request); err != nil || replay {
		return value, replay, err
	}
	if s.platform != nil && s.platform.BaseDomain != fact.BaseDomain {
		return G3PlatformDomainFact{}, false, ErrG3AccessConflict
	}
	copy := fact
	s.platform = &copy
	return copy, false, s.completeLocked(request, copy)
}
func (s *g3MemoryStore) ListApplicationDomains(_ context.Context, applicationID domain.ID) ([]G3ApplicationDomainFact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]G3ApplicationDomainFact, 0)
	for _, item := range s.domains {
		if item.ApplicationID == applicationID {
			result = append(result, item)
		}
	}
	return result, nil
}
func (s *g3MemoryStore) ApplicationDomain(_ context.Context, applicationID, domainID domain.ID) (G3ApplicationDomainFact, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, found := s.domains[domainID]
	return item, found && item.ApplicationID == applicationID, nil
}
func (s *g3MemoryStore) BindCustomDomain(_ context.Context, fact G3ApplicationDomainFact, request G3Idempotency) (G3ApplicationDomainFact, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if value, replay, err := s.applicationReplayLocked(request); err != nil || replay {
		return value, replay, err
	}
	for _, existing := range s.domains {
		if existing.Hostname == fact.Hostname {
			if existing.ApplicationID != fact.ApplicationID {
				return G3ApplicationDomainFact{}, false, ErrG3AccessConflict
			}
			return existing, false, s.completeLocked(request, existing)
		}
	}
	s.domains[fact.ID] = fact
	return fact, true, s.completeLocked(request, fact)
}
func (s *g3MemoryStore) SetApplicationDomainVerification(_ context.Context, applicationID, domainID domain.ID, status G3VerificationStatus, at *time.Time, request G3Idempotency) (G3ApplicationDomainFact, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if value, replay, err := s.applicationReplayLocked(request); err != nil || replay {
		return value, replay, err
	}
	item, found := s.domains[domainID]
	if !found || item.ApplicationID != applicationID {
		return G3ApplicationDomainFact{}, false, domain.NewError(domain.ErrNotFound, "application domain not found")
	}
	item.VerificationStatus, item.VerifiedAt = status, at
	s.domains[domainID] = item
	return item, false, s.completeLocked(request, item)
}
func (s *g3MemoryStore) BeginDomainUnbind(_ context.Context, applicationID, domainID domain.ID, _ string, request G3Idempotency) (G3DomainUnbindOperation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unbind == nil {
		s.unbind = map[string]G3DomainUnbindOperation{}
	}
	if operation, found := s.unbind[request.Scope+":"+request.Key]; found {
		if operation.DomainID != domainID {
			return G3DomainUnbindOperation{}, false, ErrG3IdempotencyConflict
		}
		return operation, true, nil
	}
	item, found := s.domains[domainID]
	if !found || item.ApplicationID != applicationID {
		return G3DomainUnbindOperation{}, false, domain.NewError(domain.ErrNotFound, "application domain not found")
	}
	if item.Kind != "custom" {
		return G3DomainUnbindOperation{}, false, ErrG3AccessConflict
	}
	operation := G3DomainUnbindOperation{ID: domain.ID("unbind_" + domainID.String()), Status: "queued", DomainID: domainID}
	s.unbind[request.Scope+":"+request.Key] = operation
	return operation, false, nil
}
func (s *g3MemoryStore) ApplicationAccessFacts(_ context.Context, applicationID domain.ID) (G3ApplicationAccessFacts, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runtime[applicationID], nil
}

func (s *g3MemoryStore) platformReplayLocked(request G3Idempotency) (G3PlatformDomainFact, bool, error) {
	item, found := s.idem[request.Scope+":"+request.Key]
	if !found {
		return G3PlatformDomainFact{}, false, nil
	}
	if item.digest != request.Digest {
		return G3PlatformDomainFact{}, false, ErrG3IdempotencyConflict
	}
	var value G3PlatformDomainFact
	if err := json.Unmarshal(item.value, &value); err != nil {
		return G3PlatformDomainFact{}, false, err
	}
	return value, true, nil
}

func (s *g3MemoryStore) applicationReplayLocked(request G3Idempotency) (G3ApplicationDomainFact, bool, error) {
	item, found := s.idem[request.Scope+":"+request.Key]
	if !found {
		return G3ApplicationDomainFact{}, false, nil
	}
	if item.digest != request.Digest {
		return G3ApplicationDomainFact{}, false, ErrG3IdempotencyConflict
	}
	var value G3ApplicationDomainFact
	if err := json.Unmarshal(item.value, &value); err != nil {
		return G3ApplicationDomainFact{}, false, err
	}
	return value, true, nil
}

func (s *g3MemoryStore) emptyReplayLocked(request G3Idempotency) ([]byte, bool, error) {
	item, found := s.idem[request.Scope+":"+request.Key]
	if !found {
		return nil, false, nil
	}
	if item.digest != request.Digest {
		return nil, false, ErrG3IdempotencyConflict
	}
	return item.value, true, nil
}

func (s *g3MemoryStore) completeLocked(request G3Idempotency, value any) error {
	if s.idem == nil {
		s.idem = map[string]g3MemoryIdempotency{}
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	s.idem[request.Scope+":"+request.Key] = g3MemoryIdempotency{digest: request.Digest, value: payload}
	return nil
}

type g3DNSVerifier struct {
	platform map[string]contracts.PublicDNSStatus
	custom   map[string]contracts.PublicDNSStatus
	err      error
	calls    []string
}

type g3ConvergenceWakeFake struct {
	platform, custom int
	err              error
}

func (w *g3ConvergenceWakeFake) WakePlatform(context.Context, G3PlatformDomainFact) error {
	w.platform++
	return w.err
}
func (w *g3ConvergenceWakeFake) WakeCustom(context.Context, G3ApplicationDomainFact) error {
	w.custom++
	return w.err
}

func (d *g3DNSVerifier) VerifyPlatformAddress(_ context.Context, hostname, expected string) (contracts.PublicDNSVerification, error) {
	d.calls = append(d.calls, "platform:"+hostname)
	if d.err != nil {
		return contracts.PublicDNSVerification{}, d.err
	}
	return contracts.PublicDNSVerification{Hostname: hostname, Expected: expected, Status: d.platform[hostname]}, nil
}
func (d *g3DNSVerifier) VerifyCustomerIngress(_ context.Context, hostname, zone string) (contracts.PublicDNSVerification, error) {
	d.calls = append(d.calls, "custom:"+hostname+":"+zone)
	if d.err != nil {
		return contracts.PublicDNSVerification{}, d.err
	}
	return contracts.PublicDNSVerification{Hostname: hostname, Expected: "ingress." + zone, Status: d.custom[hostname]}, nil
}

func newG3Controller(store *g3MemoryStore, dns contracts.PublicDNSVerifier) *G3AccessController {
	now := time.Unix(1_700_000_000, 0).UTC()
	return &G3AccessController{Store: store, Config: G3AccessConfig{PublicDNSVerifier: dns, ExpectedPublicIP: "203.0.113.77", ConsoleLabel: "console", IngressLabel: "ingress", AppsLabel: "apps", WildcardProbeLabel: "wildcard-probe"}, Clock: func() time.Time { return now }}
}

func TestG3PlatformDomainIsUnconfiguredWithoutExplicitPublicDNS(t *testing.T) {
	store := &g3MemoryStore{apps: map[domain.ID]string{"app_1": "Demo"}, domains: map[domain.ID]G3ApplicationDomainFact{}}
	controller := &G3AccessController{Store: store}
	settings, err := controller.GetPlatformSettings(context.Background())
	if err != nil || settings.Status != "unconfigured" || settings.NextAction != "configure_base_domain" {
		t.Fatalf("settings=%+v err=%v", settings, err)
	}
	if _, _, err := controller.ConfigurePlatformDomain(context.Background(), "example.test", "key", "admin_1"); !domain.IsCode(err, domain.ErrUnavailable) {
		t.Fatalf("unconfigured write error=%v", err)
	}
}

func TestG3PlatformDomainRequiresAnExplicitConsoleLabel(t *testing.T) {
	store := &g3MemoryStore{apps: map[domain.ID]string{"app_1": "Demo"}, domains: map[domain.ID]G3ApplicationDomainFact{}}
	controller := newG3Controller(store, &g3DNSVerifier{})
	controller.Config.ConsoleLabel = ""
	settings, err := controller.GetPlatformSettings(context.Background())
	if err != nil || settings.Status != "unconfigured" || len(settings.DNSRecords) != 0 {
		t.Fatalf("settings=%+v err=%v", settings, err)
	}
	if _, _, err := controller.ConfigurePlatformDomain(context.Background(), "example.test", "put-1", "admin_1"); !domain.IsCode(err, domain.ErrUnavailable) {
		t.Fatalf("missing console label write err=%v", err)
	}
}

func TestG3PlatformDomainRequiresAnIPv4ARecordTarget(t *testing.T) {
	for _, target := range []string{"2001:db8::1", "::ffff:203.0.113.77"} {
		store := &g3MemoryStore{apps: map[domain.ID]string{"app_1": "Demo"}, domains: map[domain.ID]G3ApplicationDomainFact{}}
		controller := newG3Controller(store, &g3DNSVerifier{})
		controller.Config.ExpectedPublicIP = target
		settings, err := controller.GetPlatformSettings(context.Background())
		if err != nil || settings.Status != "unconfigured" || len(settings.DNSRecords) != 0 {
			t.Fatalf("target=%q settings=%+v err=%v", target, settings, err)
		}
		if _, _, err := controller.ConfigurePlatformDomain(context.Background(), "example.test", "ipv6-a", "admin_1"); !domain.IsCode(err, domain.ErrUnavailable) {
			t.Fatalf("target=%q configuration error=%v", target, err)
		}
	}
}

func TestG3PlatformDomainRequiresConsoleIngressAndWildcardPublicDNS(t *testing.T) {
	store := &g3MemoryStore{apps: map[domain.ID]string{"app_1": "Demo"}, domains: map[domain.ID]G3ApplicationDomainFact{}}
	dns := &g3DNSVerifier{platform: map[string]contracts.PublicDNSStatus{"console.example.test": contracts.PublicDNSVerified, "ingress.example.test": contracts.PublicDNSVerified, "wildcard-probe.apps.example.test": contracts.PublicDNSVerified}}
	controller := newG3Controller(store, dns)
	waker := &g3ConvergenceWakeFake{}
	controller.Waker = waker
	settings, replay, err := controller.ConfigurePlatformDomain(context.Background(), "example.test", "put-1", "admin_1")
	if err != nil || replay || settings.Status != "certificate_pending" || settings.ConsoleDomain == nil || *settings.ConsoleDomain != "console.example.test" || settings.WildcardPattern == nil || *settings.WildcardPattern != "*.apps.example.test" || len(settings.DNSRecords) != 3 {
		t.Fatalf("settings=%+v replay=%v err=%v", settings, replay, err)
	}
	if len(dns.calls) != 3 || dns.calls[0] != "platform:console.example.test" || dns.calls[1] != "platform:ingress.example.test" || dns.calls[2] != "platform:wildcard-probe.apps.example.test" {
		t.Fatalf("DNS calls=%v", dns.calls)
	}
	if store.platform == nil || store.platform.VerificationRef != g3PlatformDNSVerificationRef {
		t.Fatalf("platform verification ref=%+v", store.platform)
	}
	if waker.platform != 1 {
		t.Fatalf("platform wake calls=%d", waker.platform)
	}
	if replaySettings, replay, err := controller.ConfigurePlatformDomain(context.Background(), "example.test", "put-1", "admin_1"); err != nil || !replay || replaySettings.Status != "certificate_pending" || len(dns.calls) != 3 {
		t.Fatalf("replay=%+v %v %v calls=%v", replaySettings, replay, err, dns.calls)
	}
	if _, _, err := controller.ConfigurePlatformDomain(context.Background(), "other.test", "put-1", "admin_1"); !domain.IsCode(err, domain.ErrConflict) {
		t.Fatalf("same key different platform input error=%v", err)
	}
}

func TestG3PlatformDomainRechecksLegacyVerifiedFactsAgainstAllThreeRecords(t *testing.T) {
	legacyVerifiedAt := time.Unix(1_600_000_000, 0).UTC()
	store := &g3MemoryStore{
		apps:    map[domain.ID]string{"app_1": "Demo"},
		domains: map[domain.ID]G3ApplicationDomainFact{},
		platform: &G3PlatformDomainFact{
			ID:                 "platform_example",
			BaseDomain:         "example.test",
			VerificationStatus: G3VerificationVerified,
			VerifiedAt:         &legacyVerifiedAt,
			CreatedAt:          legacyVerifiedAt,
			UpdatedAt:          legacyVerifiedAt,
		},
	}
	dns := &g3DNSVerifier{platform: map[string]contracts.PublicDNSStatus{
		"console.example.test":             contracts.PublicDNSVerified,
		"ingress.example.test":             contracts.PublicDNSMismatch,
		"wildcard-probe.apps.example.test": contracts.PublicDNSVerified,
	}}
	controller := newG3Controller(store, dns)
	read, err := controller.GetPlatformSettings(context.Background())
	if err != nil || read.Status != "pending" || read.Verification.Status != "pending" || read.Verification.ObservedAt != nil || len(dns.calls) != 0 {
		t.Fatalf("legacy read=%+v err=%v calls=%v", read, err, dns.calls)
	}
	items, err := controller.ListApplicationDomains(context.Background(), "app_1")
	if err != nil || len(items) != 1 || items[0].Status != "pending" || items[0].Serving {
		t.Fatalf("legacy platform address=%+v err=%v", items, err)
	}
	settings, replay, err := controller.ConfigurePlatformDomain(context.Background(), "example.test", "new-three-record-key", "admin_1")
	if err != nil || replay || settings.Status != "failed" || settings.Failure == nil {
		t.Fatalf("settings=%+v replay=%v err=%v", settings, replay, err)
	}
	if len(dns.calls) != 3 || dns.calls[0] != "platform:console.example.test" || dns.calls[1] != "platform:ingress.example.test" || dns.calls[2] != "platform:wildcard-probe.apps.example.test" {
		t.Fatalf("DNS calls=%v", dns.calls)
	}
	if store.platform == nil || store.platform.VerificationStatus != G3VerificationFailed {
		t.Fatalf("legacy platform fact was not replaced: %+v", store.platform)
	}
}

func TestG3CustomDomainDNSAndUnbindStateMachine(t *testing.T) {
	store := &g3MemoryStore{apps: map[domain.ID]string{"app_1": "Demo", "app_2": "Other"}, domains: map[domain.ID]G3ApplicationDomainFact{}}
	dns := &g3DNSVerifier{platform: map[string]contracts.PublicDNSStatus{"console.example.test": contracts.PublicDNSVerified, "ingress.example.test": contracts.PublicDNSVerified, "wildcard-probe.apps.example.test": contracts.PublicDNSVerified}, custom: map[string]contracts.PublicDNSStatus{"www.customer.test": contracts.PublicDNSVerified}}
	controller := newG3Controller(store, dns)
	waker := &g3ConvergenceWakeFake{err: errors.New("wake unavailable")}
	controller.Waker = waker
	if _, _, err := controller.ConfigurePlatformDomain(context.Background(), "example.test", "put", "admin_1"); err != nil {
		t.Fatal(err)
	}
	bound, created, err := controller.BindCustomDomain(context.Background(), "app_1", "www.customer.test", "bind", "admin_1")
	if err != nil || !created || bound.CNAME == nil || *bound.CNAME != "ingress.example.test" || bound.Status != "pending" {
		t.Fatalf("bound=%+v created=%v err=%v", bound, created, err)
	}
	if _, _, err := controller.BindCustomDomain(context.Background(), "app_2", "www.customer.test", "bind-other", "admin_1"); !domain.IsCode(err, domain.ErrConflict) {
		t.Fatalf("cross application bind error=%v", err)
	}
	if _, _, err := controller.BindCustomDomain(context.Background(), "app_1", "api.customer.test", "bind", "admin_1"); !domain.IsCode(err, domain.ErrConflict) {
		t.Fatalf("same key different custom hostname error=%v", err)
	}
	verified, err := controller.VerifyApplicationDomain(context.Background(), "app_1", domain.ID(bound.ID), "verify", "admin_1")
	if err != nil || verified.Status != "certificate_pending" || verified.Verification.ObservedAt == nil {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}
	if waker.custom != 1 || verified.Serving {
		t.Fatalf("wake=%d verified=%+v", waker.custom, verified)
	}
	store.domains[domain.ID(bound.ID)] = G3ApplicationDomainFact{ID: domain.ID(bound.ID), ApplicationID: "app_1", Hostname: "www.customer.test", Kind: "custom", CNAME: "ingress.example.test", VerificationStatus: G3VerificationVerified, Serving: true}
	beforeUnbinds := len(store.unbind)
	if _, err := controller.UnbindCustomDomain(context.Background(), "app_2", domain.ID(bound.ID), "cross-app-unbind", "admin_1"); !domain.IsCode(err, domain.ErrNotFound) {
		t.Fatalf("cross application unbind error=%v", err)
	}
	if len(store.unbind) != beforeUnbinds {
		t.Fatalf("cross application unbind created an operation: %+v", store.unbind)
	}
	operation, err := controller.UnbindCustomDomain(context.Background(), "app_1", domain.ID(bound.ID), "unbind", "admin_1")
	if err != nil || operation.Status != "queued" || operation.DomainID != domain.ID(bound.ID) {
		t.Fatalf("serving unbind operation=%+v err=%v", operation, err)
	}
	// Model the durable worker's post-finalize binding deletion.  The original
	// idempotency key must still replay its accepted operation; a fresh key must
	// not turn the deleted binding into a newly accepted operation.
	store.mu.Lock()
	delete(store.domains, domain.ID(bound.ID))
	store.mu.Unlock()
	if _, err := controller.UnbindCustomDomain(context.Background(), "app_1", domain.ID(bound.ID), "unbind", "admin_1"); err != nil {
		t.Fatalf("idempotent unbind replay=%v", err)
	}
	if _, err := controller.UnbindCustomDomain(context.Background(), "app_1", domain.ID(bound.ID), "different-unbind-key", "admin_1"); !domain.IsCode(err, domain.ErrNotFound) {
		t.Fatalf("deleted binding with a new key error=%v", err)
	}
}

func TestG3AccessPreservesRuntimeFallbackAndNeverFakesCertificateReady(t *testing.T) {
	ip := "http://203.0.113.77:18080"
	store := &g3MemoryStore{apps: map[domain.ID]string{"app_1": "Demo"}, domains: map[domain.ID]G3ApplicationDomainFact{}, runtime: map[domain.ID]G3ApplicationAccessFacts{"app_1": {Runtime: G3RuntimeFact{RuntimeReady: true, IPFallback: &ip}, Routes: []G3RouteFact{{ID: "route_1", Desired: true, Serving: true, Certificate: &G3CertificateFact{Status: "ready", Subject: "www.customer.test"}}}}}}
	dns := &g3DNSVerifier{platform: map[string]contracts.PublicDNSStatus{"console.example.test": contracts.PublicDNSVerified, "ingress.example.test": contracts.PublicDNSVerified, "wildcard-probe.apps.example.test": contracts.PublicDNSVerified}}
	controller := newG3Controller(store, dns)
	if _, _, err := controller.ConfigurePlatformDomain(context.Background(), "example.test", "put", "admin_1"); err != nil {
		t.Fatal(err)
	}
	access, err := controller.ApplicationAccess(context.Background(), "app_1")
	if err != nil || !access.RuntimeReady || access.IPFallback == nil || *access.IPFallback != ip || !access.Route.Desired || access.Route.Serving || access.Serving || access.Certificate.Status != "pending" || access.PlatformAddress == nil || access.PlatformAddress.Status != "certificate_pending" {
		t.Fatalf("access=%+v err=%v", access, err)
	}
	if _, err := controller.ApplicationAccess(context.Background(), "missing"); !domain.IsCode(err, domain.ErrNotFound) {
		t.Fatalf("missing application error=%v", err)
	}
}

func TestG3DomainListDoesNotProjectInternalRouteServingAsPublicEdgeServing(t *testing.T) {
	host, err := domain.StableApplicationHost("Demo", "app_1", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	store := &g3MemoryStore{apps: map[domain.ID]string{"app_1": "Demo"}, domains: map[domain.ID]G3ApplicationDomainFact{}, runtime: map[domain.ID]G3ApplicationAccessFacts{"app_1": {Routes: []G3RouteFact{{ID: "route_platform", Hostname: host, Desired: true, Serving: true}}}}}
	dns := &g3DNSVerifier{platform: map[string]contracts.PublicDNSStatus{"console.example.test": contracts.PublicDNSVerified, "ingress.example.test": contracts.PublicDNSVerified, "wildcard-probe.apps.example.test": contracts.PublicDNSVerified}}
	controller := newG3Controller(store, dns)
	if _, _, err := controller.ConfigurePlatformDomain(context.Background(), "example.test", "put", "admin_1"); err != nil {
		t.Fatal(err)
	}
	items, err := controller.ListApplicationDomains(context.Background(), "app_1")
	if err != nil || len(items) != 1 || items[0].Kind != "platform" || items[0].Serving || items[0].Verification.Name == nil || *items[0].Verification.Name != "wildcard-probe.apps.example.test" {
		t.Fatalf("domains=%+v err=%v", items, err)
	}
}

func TestG3PlatformPlaceholderAndDurableDomainUseTheSameStableID(t *testing.T) {
	store := &g3MemoryStore{apps: map[domain.ID]string{"app_1": "Demo"}, domains: map[domain.ID]G3ApplicationDomainFact{}}
	dns := &g3DNSVerifier{platform: map[string]contracts.PublicDNSStatus{"console.example.test": contracts.PublicDNSVerified, "ingress.example.test": contracts.PublicDNSVerified, "wildcard-probe.apps.example.test": contracts.PublicDNSVerified}}
	controller := newG3Controller(store, dns)
	if _, _, err := controller.ConfigurePlatformDomain(context.Background(), "example.test", "platform", "admin_1"); err != nil {
		t.Fatal(err)
	}
	items, err := controller.ListApplicationDomains(context.Background(), "app_1")
	if err != nil || len(items) != 1 {
		t.Fatalf("placeholder items=%+v err=%v", items, err)
	}
	stableID, err := domain.StablePlatformApplicationDomainID(store.platform.ID, "app_1")
	if err != nil || items[0].ID != stableID.String() {
		t.Fatalf("placeholder ID=%q stable=%q err=%v", items[0].ID, stableID, err)
	}
	store.domains[stableID] = G3ApplicationDomainFact{ID: stableID, ApplicationID: "app_1", Hostname: items[0].Hostname, Kind: "platform", VerificationStatus: G3VerificationVerified}
	items, err = controller.ListApplicationDomains(context.Background(), "app_1")
	if err != nil || len(items) != 1 || items[0].ID != stableID.String() {
		t.Fatalf("durable items=%+v err=%v", items, err)
	}
}

func TestG3ApplicationDomainRequiresObservedServingCertificateForReady(t *testing.T) {
	now := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	store := &g3MemoryStore{apps: map[domain.ID]string{"app_1": "Demo"}, domains: map[domain.ID]G3ApplicationDomainFact{
		"custom_1":  {ID: "custom_1", ApplicationID: "app_1", Hostname: "www.customer.test", Kind: "custom", CNAME: "ingress.example.test", VerificationStatus: G3VerificationVerified, Serving: true, Certificate: &G3CertificateFact{Status: "ready", Observed: true, Subject: "www.customer.test", NotAfter: ptrG3Time(now.Add(time.Hour))}},
		"fixture_1": {ID: "fixture_1", ApplicationID: "app_1", Hostname: "fixture.customer.test", Kind: "custom", CNAME: "ingress.example.test", VerificationStatus: G3VerificationVerified, Serving: true, Certificate: &G3CertificateFact{Status: "ready", Subject: "fixture.customer.test", NotAfter: ptrG3Time(now.Add(time.Hour))}},
	}}
	controller := newG3Controller(store, &g3DNSVerifier{})
	controller.Clock = func() time.Time { return now }
	items, err := controller.ListApplicationDomains(context.Background(), "app_1")
	if err != nil || len(items) != 2 {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	var observed, fixture G3ApplicationDomain
	for _, item := range items {
		if item.ID == "custom_1" {
			observed = item
		} else {
			fixture = item
		}
	}
	if observed.Status != "ready" || !observed.Serving || observed.Certificate.Status != "ready" {
		t.Fatalf("observed=%+v", observed)
	}
	if fixture.Status != "certificate_pending" || fixture.Serving || fixture.Certificate.Status != "pending" {
		t.Fatalf("fixture=%+v", fixture)
	}
}

func TestG3ApplicationDomainKeepsCertificatePendingForIncompleteOrExpiredFacts(t *testing.T) {
	now := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	store := &g3MemoryStore{apps: map[domain.ID]string{"app_1": "Demo"}, domains: map[domain.ID]G3ApplicationDomainFact{
		"no_pointer":    {ID: "no_pointer", ApplicationID: "app_1", Hostname: "no-pointer.customer.test", Kind: "custom", CNAME: "ingress.example.test", VerificationStatus: G3VerificationVerified, Serving: false, Certificate: &G3CertificateFact{Status: "ready", Observed: true, Subject: "no-pointer.customer.test", NotAfter: ptrG3Time(now.Add(time.Hour))}},
		"wrong_subject": {ID: "wrong_subject", ApplicationID: "app_1", Hostname: "wrong-subject.customer.test", Kind: "custom", CNAME: "ingress.example.test", VerificationStatus: G3VerificationVerified, Serving: true, Certificate: &G3CertificateFact{Status: "ready", Observed: true, Subject: "other.customer.test", NotAfter: ptrG3Time(now.Add(time.Hour))}},
		"expired":       {ID: "expired", ApplicationID: "app_1", Hostname: "expired.customer.test", Kind: "custom", CNAME: "ingress.example.test", VerificationStatus: G3VerificationVerified, Serving: true, Certificate: &G3CertificateFact{Status: "ready", Observed: true, Subject: "expired.customer.test", NotAfter: ptrG3Time(now.Add(-time.Hour))}, ConvergencePhase: "recovery_required", ConvergenceStatus: "recovery_required", ConvergenceError: "serving_fact_mismatch"},
	}}
	controller := newG3Controller(store, &g3DNSVerifier{})
	controller.Clock = func() time.Time { return now }
	items, err := controller.ListApplicationDomains(context.Background(), "app_1")
	if err != nil || len(items) != 3 {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	for _, item := range items {
		if item.Status != "certificate_pending" || item.Serving || item.Certificate.Status != "pending" {
			t.Fatalf("incomplete durable fact became ready: %+v", item)
		}
		if item.ID == "expired" && (item.Failure == nil || item.Failure.Code != "serving_fact_mismatch" || item.Convergence == nil || item.Convergence.LastError != "serving_fact_mismatch") {
			t.Fatalf("recovery state was not safely projected: %+v", item)
		}
	}
}

func TestG3AccessProjectsOnlyObservedServingCertificateAsReady(t *testing.T) {
	now := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	store := &g3MemoryStore{apps: map[domain.ID]string{"app_1": "Demo"}, domains: map[domain.ID]G3ApplicationDomainFact{}, runtime: map[domain.ID]G3ApplicationAccessFacts{
		"app_1": {Runtime: G3RuntimeFact{RuntimeReady: true}, Routes: []G3RouteFact{{ID: "route_1", Hostname: "app.apps.example.test", Desired: true, Serving: true, Certificate: &G3CertificateFact{Status: "ready", Observed: true, Subject: "app.apps.example.test", NotAfter: ptrG3Time(now.Add(time.Hour))}}}},
	}}
	controller := newG3Controller(store, &g3DNSVerifier{})
	controller.Clock = func() time.Time { return now }
	access, err := controller.ApplicationAccess(context.Background(), "app_1")
	if err != nil || !access.Route.Serving || !access.Serving || access.Certificate.Status != "ready" {
		t.Fatalf("access=%+v err=%v", access, err)
	}
}

func ptrG3Time(value time.Time) *time.Time { return &value }

func TestG3ResolverFailureFailsClosed(t *testing.T) {
	store := &g3MemoryStore{apps: map[domain.ID]string{"app_1": "Demo"}, domains: map[domain.ID]G3ApplicationDomainFact{}}
	controller := newG3Controller(store, &g3DNSVerifier{err: errors.New("resolver offline")})
	if _, _, err := controller.ConfigurePlatformDomain(context.Background(), "example.test", "put", "admin_1"); !domain.IsCode(err, domain.ErrUnavailable) {
		t.Fatalf("resolver failure=%v", err)
	}
}

func TestG3DNSMismatchAndTimeoutNeverClaimReady(t *testing.T) {
	store := &g3MemoryStore{apps: map[domain.ID]string{"app_1": "Demo"}, domains: map[domain.ID]G3ApplicationDomainFact{}}
	mismatchDNS := &g3DNSVerifier{platform: map[string]contracts.PublicDNSStatus{"console.example.test": contracts.PublicDNSVerified, "ingress.example.test": contracts.PublicDNSVerified, "wildcard-probe.apps.example.test": contracts.PublicDNSMismatch}}
	controller := newG3Controller(store, mismatchDNS)
	settings, _, err := controller.ConfigurePlatformDomain(context.Background(), "example.test", "mismatch", "admin_1")
	if err != nil || settings.Status != "failed" || settings.Failure == nil {
		t.Fatalf("mismatch settings=%+v err=%v", settings, err)
	}

	store.platform = &G3PlatformDomainFact{ID: "platform_example", BaseDomain: "example.test", VerificationStatus: G3VerificationVerified}
	timeoutDNS := &g3DNSVerifier{custom: map[string]contracts.PublicDNSStatus{"www.customer.test": contracts.PublicDNSTimeout}}
	controller = newG3Controller(store, timeoutDNS)
	bound, _, err := controller.BindCustomDomain(context.Background(), "app_1", "www.customer.test", "bind", "admin_1")
	if err != nil {
		t.Fatal(err)
	}
	verified, err := controller.VerifyApplicationDomain(context.Background(), "app_1", domain.ID(bound.ID), "timeout", "admin_1")
	if err != nil || verified.Status != "pending" || verified.Verification.ObservedAt != nil {
		t.Fatalf("timeout domain=%+v err=%v", verified, err)
	}
}
