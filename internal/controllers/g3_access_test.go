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
func (s *g3MemoryStore) UnbindCustomDomain(_ context.Context, applicationID, domainID domain.ID, _ string, request G3Idempotency) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, replay, err := s.emptyReplayLocked(request); err != nil || replay {
		return replay, err
	}
	item, found := s.domains[domainID]
	if !found || item.ApplicationID != applicationID {
		return false, domain.NewError(domain.ErrNotFound, "application domain not found")
	}
	if item.Kind != "custom" || item.Serving {
		return false, ErrG3AccessConflict
	}
	delete(s.domains, domainID)
	return false, s.completeLocked(request, map[string]bool{"unbound": true})
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
	store.domains[domain.ID(bound.ID)] = G3ApplicationDomainFact{ID: domain.ID(bound.ID), ApplicationID: "app_1", Hostname: "www.customer.test", Kind: "custom", CNAME: "ingress.example.test", VerificationStatus: G3VerificationVerified, Serving: true}
	if err := controller.UnbindCustomDomain(context.Background(), "app_1", domain.ID(bound.ID), "unbind", "admin_1"); !domain.IsCode(err, domain.ErrConflict) {
		t.Fatalf("serving unbind error=%v", err)
	}
	item := store.domains[domain.ID(bound.ID)]
	item.Serving = false
	store.domains[item.ID] = item
	if err := controller.UnbindCustomDomain(context.Background(), "app_1", item.ID, "unbind-2", "admin_1"); err != nil {
		t.Fatal(err)
	}
	if err := controller.UnbindCustomDomain(context.Background(), "app_1", item.ID, "unbind-2", "admin_1"); err != nil {
		t.Fatalf("idempotent unbind replay=%v", err)
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
