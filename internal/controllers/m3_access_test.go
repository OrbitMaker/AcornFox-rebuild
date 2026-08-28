package controllers

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

type m3MemoryStore struct {
	mu       sync.Mutex
	domains  []domain.DomainBinding
	certs    []domain.CertificateReference
	routes   []domain.DesiredRoute
	pointers map[domain.ID]domain.ID
	switches []domain.TrafficSwitch
	events   []string
}

func (s *m3MemoryStore) PutDomainBinding(_ context.Context, value domain.DomainBinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.domains = append(s.domains, value)
	return nil
}
func (s *m3MemoryStore) PutCertificateReference(_ context.Context, value domain.CertificateReference) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certs = append(s.certs, value)
	return nil
}
func (s *m3MemoryStore) PutDesiredRoute(_ context.Context, value domain.Route, port int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes = append(s.routes, domain.DesiredRoute{Route: value, Port: port})
	return nil
}
func (s *m3MemoryStore) ListDesiredRoutes(context.Context) ([]domain.DesiredRoute, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]domain.DesiredRoute(nil), s.routes...), nil
}
func (s *m3MemoryStore) SetRoutePointer(_ context.Context, routeID, deploymentID domain.ID, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pointers == nil {
		s.pointers = map[domain.ID]domain.ID{}
	}
	s.pointers[routeID] = deploymentID
	return nil
}
func (s *m3MemoryStore) RecordTrafficSwitch(_ context.Context, value domain.TrafficSwitch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.switches = append(s.switches, value)
	return nil
}
func (s *m3MemoryStore) AppendAccessEvent(_ context.Context, _ domain.ID, _ string, kind, _ string, _ bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, kind)
	return nil
}

type m3DNS struct{ fail bool }

func (d m3DNS) VerifyPlatform(_ context.Context, host, _ string, _ contracts.OperationContext) (domain.DomainBinding, error) {
	if d.fail {
		return domain.DomainBinding{}, errors.New("dns failed")
	}
	now := time.Unix(1, 0).UTC()
	return domain.DomainBinding{ID: "domain_platform", Kind: domain.DomainBindingPlatform, Host: host, Status: domain.DomainVerified, CreatedAt: now, UpdatedAt: now}, nil
}
func (d m3DNS) VerifyApplication(_ context.Context, app domain.ID, host, target string, _ contracts.OperationContext) (domain.DomainBinding, error) {
	if d.fail {
		return domain.DomainBinding{}, errors.New("dns failed")
	}
	now := time.Unix(1, 0).UTC()
	return domain.DomainBinding{ID: "domain_app", Kind: domain.DomainBindingApplication, ApplicationID: app, Host: host, ExpectedCNAME: target, Status: domain.DomainVerified, CreatedAt: now, UpdatedAt: now}, nil
}

type m3Certificates struct{ fail bool }

func (c m3Certificates) Issue(_ context.Context, binding domain.DomainBinding, _ contracts.OperationContext) (domain.CertificateReference, error) {
	if c.fail {
		return domain.CertificateReference{}, errors.New("certificate failed")
	}
	now := time.Unix(1, 0).UTC()
	return domain.CertificateReference{ID: "certificate_1", DomainBindingID: binding.ID, Host: binding.Host, SecretRef: domain.SecretReference{ID: "secret_cert", Name: "tls", Provider: "test", Version: "1"}, Status: domain.CertificateReady, Fingerprint: "sha256:test", NotBefore: now, NotAfter: now.Add(time.Hour), UpdatedAt: now}, nil
}
func (c m3Certificates) Renew(ctx context.Context, previous domain.CertificateReference, op contracts.OperationContext) (domain.CertificateReference, error) {
	binding := domain.DomainBinding{Host: previous.Host}
	return c.Issue(ctx, binding, op)
}

type m3RouteProvider struct {
	mu        sync.Mutex
	routes    map[string]contracts.RouteSpec
	failApply bool
}

func (p *m3RouteProvider) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "m3-route-test", Version: "1", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilityRouteManage)}
}
func (p *m3RouteProvider) Apply(_ context.Context, request contracts.RouteRequest) (domain.Route, contracts.Evidence, error) {
	if p.failApply {
		return domain.Route{}, contracts.Evidence{}, errors.New("route failed")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.routes == nil {
		p.routes = map[string]contracts.RouteSpec{}
	}
	p.routes[request.Route.Host+request.Route.Path] = request.Route
	route := domain.Route{ID: domain.ID("route_" + strings.ReplaceAll(request.Route.Path, "/", "root")), ApplicationID: "app_test", DeploymentID: request.Route.DeploymentID, ServiceName: request.Route.ServiceName, Host: request.Route.Host, Path: request.Route.Path, CertificateRef: request.Route.CertificateRef, Verified: request.Route.Verified, Serving: true, CreatedAt: time.Unix(1, 0)}
	return route, contracts.Evidence{Refs: []domain.EvidenceRef{{ID: "ev_route", Kind: "route.actual", Digest: "sha256:" + strings.Repeat("a", 64), Locator: "route://test"}}}, nil
}
func (p *m3RouteProvider) Observe(context.Context, contracts.RouteRequest) (domain.Observation, error) {
	return domain.Observation{}, nil
}
func (p *m3RouteProvider) Remove(_ context.Context, request contracts.RouteRequest) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.routes, request.Route.Host+request.Route.Path)
	return nil
}
func (p *m3RouteProvider) Rebuild(context.Context, contracts.OperationContext) (contracts.Evidence, error) {
	return contracts.Evidence{}, nil
}
func (p *m3RouteProvider) RebuildRoutes(_ context.Context, requests []contracts.RouteRequest, _ contracts.OperationContext) (contracts.Evidence, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.routes = map[string]contracts.RouteSpec{}
	for _, request := range requests {
		p.routes[request.Route.Host+request.Route.Path] = request.Route
	}
	return contracts.Evidence{}, nil
}

func newM3Controller(routes *m3RouteProvider, store *m3MemoryStore) *M3AccessController {
	return &M3AccessController{Routes: routes, Store: store, DNS: m3DNS{}, Certificates: m3Certificates{}, Clock: func() time.Time { return time.Unix(1, 0).UTC() }, Sleep: func(context.Context, time.Duration) error { return nil }}
}

func TestM3IPFallbackDoesNotClaimDomainOrHTTPS(t *testing.T) {
	routes, store := &m3RouteProvider{}, &m3MemoryStore{}
	controller := newM3Controller(routes, store)
	state, err := controller.EnsureIPFallback(context.Background(), M3IPFallbackRequest{Target: M3RouteTarget{ApplicationID: "app_test", DeploymentID: "dep_test", ServiceName: "frontend", Port: 31001, Path: "/", Routable: true}, ServerIP: "192.0.2.10", RuntimeReady: true, IdempotencyKey: "ip-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !state.RuntimeReady || !state.IPAvailable || state.HTTPSReady || state.Domain != "" || !strings.HasPrefix(state.IPAddress, "http://192.0.2.10:31001") {
		t.Fatalf("invalid fallback state: %#v", state)
	}
}

func TestM3RoutesRejectNonRoutableAndAmbiguousPrefix(t *testing.T) {
	controller := newM3Controller(&m3RouteProvider{}, &m3MemoryStore{})
	binding, certificate, err := controller.BindApplicationDomain(context.Background(), "app_test", "app.example.test", "target.apps.example.test", "bind", "test")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = controller.ApplyDomainRoutes(context.Background(), M3DomainRouteRequest{Binding: binding, Certificate: certificate, RuntimeReady: true, IdempotencyKey: "routes", Targets: []M3RouteTarget{{ApplicationID: "app_test", DeploymentID: "dep_test", ServiceName: "worker", Port: 31002, Path: "/", Routable: false}}})
	if !domain.IsCode(err, domain.ErrForbidden) {
		t.Fatalf("non-routable service error=%v", err)
	}
	_, _, err = controller.ApplyDomainRoutes(context.Background(), M3DomainRouteRequest{Binding: binding, Certificate: certificate, RuntimeReady: true, IdempotencyKey: "routes2", Targets: []M3RouteTarget{{ApplicationID: "app_test", DeploymentID: "dep_test", ServiceName: "frontend", Port: 31001, Path: "/api", Routable: true}, {ApplicationID: "app_test", DeploymentID: "dep_test", ServiceName: "api", Port: 31002, Path: "/api/v1", Routable: true}}})
	if !domain.IsCode(err, domain.ErrConflict) {
		t.Fatalf("ambiguous path error=%v", err)
	}
}

func TestM3RootAndAPIPathApplyAndRebuild(t *testing.T) {
	routes, store := &m3RouteProvider{}, &m3MemoryStore{}
	controller := newM3Controller(routes, store)
	binding, certificate, err := controller.BindApplicationDomain(context.Background(), "app_test", "app.example.test", "target.apps.example.test", "bind", "test")
	if err != nil {
		t.Fatal(err)
	}
	applied, state, err := controller.ApplyDomainRoutes(context.Background(), M3DomainRouteRequest{Binding: binding, Certificate: certificate, RuntimeReady: true, IdempotencyKey: "routes", Targets: []M3RouteTarget{{ApplicationID: "app_test", DeploymentID: "dep_test", ServiceName: "frontend", Port: 31001, Path: "/", Routable: true}, {ApplicationID: "app_test", DeploymentID: "dep_test", ServiceName: "api", Port: 31002, Path: "/api", Routable: true}}})
	if err != nil || len(applied) != 2 || !state.HTTPSReady {
		t.Fatalf("apply=%#v state=%#v err=%v", applied, state, err)
	}
	routes.routes = map[string]contracts.RouteSpec{}
	if _, err := controller.RebuildRoutes(context.Background(), "rebuild", "test"); err != nil {
		t.Fatal(err)
	}
	if len(routes.routes) != 2 {
		t.Fatalf("rebuilt routes=%d", len(routes.routes))
	}
}

func TestM3CertificateFailureLeavesDomainFailedWithoutRoute(t *testing.T) {
	routes, store := &m3RouteProvider{}, &m3MemoryStore{}
	controller := newM3Controller(routes, store)
	controller.Certificates = m3Certificates{fail: true}
	binding, _, err := controller.BindApplicationDomain(context.Background(), "app_test", "app.example.test", "target.apps.example.test", "bind", "test")
	if err == nil || binding.Status != domain.DomainFailed || len(routes.routes) != 0 {
		t.Fatalf("binding=%#v routes=%#v err=%v", binding, routes.routes, err)
	}
}

func TestM3PlatformDomainGeneratesStableManagedApplicationHost(t *testing.T) {
	controller := newM3Controller(&m3RouteProvider{}, &m3MemoryStore{})
	platform, _, err := controller.BindPlatformDomain(context.Background(), "example.test", "gateway.fixture.test", "platform", "test")
	if err != nil {
		t.Fatal(err)
	}
	first, err := controller.CreatePlatformApplicationDomain(context.Background(), "app_test", "CRM Console", platform)
	if err != nil {
		t.Fatal(err)
	}
	second, err := controller.CreatePlatformApplicationDomain(context.Background(), "app_test", "CRM Console", platform)
	if err != nil {
		t.Fatal(err)
	}
	if first.Host != second.Host || !strings.HasSuffix(first.Host, ".apps.example.test") || first.CertificateRef != platform.CertificateRef || !first.Managed || first.VerifiedAt == nil {
		t.Fatalf("managed platform address is not stable: %#v %#v", first, second)
	}
}

func TestM3SwitchObservationFailureRestoresOldRoute(t *testing.T) {
	routes, store := &m3RouteProvider{}, &m3MemoryStore{}
	controller := newM3Controller(routes, store)
	old := domain.DesiredRoute{Route: domain.Route{ID: "route_old", ApplicationID: "app_test", DeploymentID: "dep_old", ServiceName: "frontend", Host: "app.example.test", Path: "/", CertificateRef: "certificate_1", Verified: true, Serving: true, CreatedAt: time.Unix(1, 0)}, Port: 31001}
	candidate := domain.DesiredRoute{Route: domain.Route{ID: "route_new", ApplicationID: "app_test", DeploymentID: "dep_new", ServiceName: "frontend", Host: "app.example.test", Path: "/", CertificateRef: "certificate_1", Verified: true, Serving: true, CreatedAt: time.Unix(1, 0)}, Port: 31002}
	_, _, _ = routes.Apply(context.Background(), contracts.RouteRequest{Route: routeSpecFrom(old.Route, old.Port), Operation: m3Operation("old", "test")})
	err := controller.Switch(context.Background(), M3SwitchRequest{ApplicationID: "app_test", Old: []domain.DesiredRoute{old}, Candidate: []domain.DesiredRoute{candidate}, IdempotencyKey: "switch", Healthy: func(context.Context, domain.ID) error { return nil }, Observe: func(context.Context, domain.ID) error { return errors.New("observation failed") }})
	if !domain.IsCode(err, domain.ErrUnavailable) {
		t.Fatalf("failed observation error=%v", err)
	}
	if got := routes.routes["app.example.test/"]; got.DeploymentID != "dep_old" {
		t.Fatalf("old route not restored: %#v", got)
	}
	if len(store.switches) != 1 || store.switches[0].Status != "old_serving" {
		t.Fatalf("switch evidence=%#v", store.switches)
	}
}
