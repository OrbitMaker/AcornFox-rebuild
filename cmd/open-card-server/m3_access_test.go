package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
)

type m3HTTPRouteProvider struct {
	mu      sync.Mutex
	applied []contracts.RouteRequest
}

func (p *m3HTTPRouteProvider) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "m3-http-route", Version: "1", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilityRouteManage)}
}

func (p *m3HTTPRouteProvider) Apply(_ context.Context, request contracts.RouteRequest) (domain.Route, contracts.Evidence, error) {
	p.mu.Lock()
	p.applied = append(p.applied, request)
	p.mu.Unlock()
	return domain.Route{ID: domain.ID("route_" + strings.ReplaceAll(request.Route.Path, "/", "root")), ApplicationID: "app_test", DeploymentID: request.Route.DeploymentID, ServiceName: request.Route.ServiceName, Host: request.Route.Host, Path: request.Route.Path, CertificateRef: request.Route.CertificateRef, Verified: request.Route.Verified, Serving: true, CreatedAt: time.Unix(1, 0).UTC()}, contracts.Evidence{}, nil
}

func (p *m3HTTPRouteProvider) Observe(context.Context, contracts.RouteRequest) (domain.Observation, error) {
	return domain.Observation{}, nil
}

func (p *m3HTTPRouteProvider) Remove(context.Context, contracts.RouteRequest) error { return nil }

func (p *m3HTTPRouteProvider) Rebuild(context.Context, contracts.OperationContext) (contracts.Evidence, error) {
	return contracts.Evidence{}, nil
}

type m3HTTPStore struct {
	mu     sync.Mutex
	routes []domain.DesiredRoute
}

func (s *m3HTTPStore) PutDomainBinding(context.Context, domain.DomainBinding) error { return nil }

func (s *m3HTTPStore) PutCertificateReference(context.Context, domain.CertificateReference) error {
	return nil
}

func (s *m3HTTPStore) PutDesiredRoute(_ context.Context, route domain.Route, port int) error {
	s.mu.Lock()
	s.routes = append(s.routes, domain.DesiredRoute{Route: route, Port: port})
	s.mu.Unlock()
	return nil
}

func (s *m3HTTPStore) PutPreparedDesiredRoute(_ context.Context, _ domain.DomainBinding, route domain.Route, port int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for index := range s.routes {
		if s.routes[index].Route.ID == route.ID {
			s.routes[index] = domain.DesiredRoute{Route: route, Port: port}
			return nil
		}
	}
	s.routes = append(s.routes, domain.DesiredRoute{Route: route, Port: port})
	return nil
}

func (s *m3HTTPStore) ListDesiredRoutes(context.Context) ([]domain.DesiredRoute, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]domain.DesiredRoute(nil), s.routes...), nil
}

func (s *m3HTTPStore) SetRoutePointer(context.Context, domain.ID, domain.ID, string) error {
	return nil
}

func (s *m3HTTPStore) RecordTrafficSwitch(context.Context, domain.TrafficSwitch) error {
	return nil
}

func (s *m3HTTPStore) AppendAccessEvent(context.Context, domain.ID, string, string, string, bool) error {
	return nil
}

type m3HTTPDNS struct{}

func (m3HTTPDNS) VerifyPlatform(_ context.Context, host, _ string, _ contracts.OperationContext) (domain.DomainBinding, error) {
	now := time.Unix(1, 0).UTC()
	return domain.DomainBinding{ID: "domain_platform", Kind: domain.DomainBindingPlatform, Host: host, Status: domain.DomainVerified, CreatedAt: now, UpdatedAt: now}, nil
}

func (m3HTTPDNS) VerifyApplication(_ context.Context, applicationID domain.ID, host, target string, _ contracts.OperationContext) (domain.DomainBinding, error) {
	now := time.Unix(1, 0).UTC()
	return domain.DomainBinding{ID: "domain_application", Kind: domain.DomainBindingApplication, ApplicationID: applicationID, Host: host, ExpectedCNAME: target, Status: domain.DomainVerified, CreatedAt: now, UpdatedAt: now}, nil
}

type m3HTTPCertificates struct{}

func (m3HTTPCertificates) Issue(_ context.Context, binding domain.DomainBinding, _ contracts.OperationContext) (domain.CertificateReference, error) {
	now := time.Unix(1, 0).UTC()
	return domain.CertificateReference{ID: "certificate_1", DomainBindingID: binding.ID, Host: binding.Host, SecretRef: domain.SecretReference{ID: "secret_certificate", Name: "m3-tls", Provider: "test", Version: "1"}, Status: domain.CertificateReady, Fingerprint: "sha256:test", NotBefore: now, NotAfter: now.Add(time.Hour), UpdatedAt: now}, nil
}

func (m3HTTPCertificates) Renew(ctx context.Context, certificate domain.CertificateReference, operation contracts.OperationContext) (domain.CertificateReference, error) {
	return m3HTTPCertificates{}.Issue(ctx, domain.DomainBinding{Host: certificate.Host}, operation)
}

func newM3HTTPHandler() (*M3AccessHTTPHandler, *m3HTTPRouteProvider) {
	routes := &m3HTTPRouteProvider{}
	controller := &controllers.M3AccessController{
		Routes:       routes,
		Store:        &m3HTTPStore{},
		DNS:          m3HTTPDNS{},
		Certificates: m3HTTPCertificates{},
		Clock:        func() time.Time { return time.Unix(1, 0).UTC() },
	}
	return &M3AccessHTTPHandler{Controller: controller}, routes
}

func m3HTTPRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "m3-http-test")
	return request
}

func TestM3AccessHTTPIPFallbackReturnsOnlyIPAccessState(t *testing.T) {
	handler, routes := newM3HTTPHandler()
	recorder := httptest.NewRecorder()

	handled := handler.Handle(recorder, m3HTTPRequest(http.MethodPost, "/api/v1/access/ip-fallback", `{
		"application_id":"app_test", "deployment_id":"dep_test", "service_name":"frontend",
		"port":31001, "path":"/", "routable":true, "server_ip":"192.0.2.10", "runtime_ready":true
	}`))

	if !handled || recorder.Code != http.StatusCreated {
		t.Fatalf("handled=%v status=%d body=%s", handled, recorder.Code, recorder.Body.String())
	}
	var body struct {
		AccessState domain.AccessState `json:"access_state"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.AccessState.RuntimeReady || !body.AccessState.IPAvailable || body.AccessState.HTTPSReady || body.AccessState.Domain != "" {
		t.Fatalf("fallback overclaimed readiness: %#v", body.AccessState)
	}
	if len(routes.applied) != 0 {
		t.Fatalf("IP fallback incorrectly depended on Caddy routing: %#v", routes.applied)
	}
}

func TestM3AccessHTTPDomainBindingAndRoutesRequireVerifiedDomain(t *testing.T) {
	handler, routes := newM3HTTPHandler()
	bindingRecorder := httptest.NewRecorder()
	handler.Handle(bindingRecorder, m3HTTPRequest(http.MethodPost, "/api/v1/access/application-domains", `{
		"application_id":"app_test", "host":"app.example.test", "cname_target":"target.apps.example.test"
	}`))
	if bindingRecorder.Code != http.StatusCreated || !strings.Contains(bindingRecorder.Body.String(), `"https_ready":true`) {
		t.Fatalf("binding response=%d %s", bindingRecorder.Code, bindingRecorder.Body.String())
	}

	routeRecorder := httptest.NewRecorder()
	handler.Handle(routeRecorder, m3HTTPRequest(http.MethodPost, "/api/v1/access/domain-routes", `{
		"binding":{"id":"domain_unverified","kind":"application","application_id":"app_test","host":"app.example.test","expected_cname":"target.apps.example.test","status":"verifying"},
		"certificate":{"id":"certificate_1","host":"app.example.test","status":"ready"},
		"runtime_ready":true,
		"targets":[{"application_id":"app_test","deployment_id":"dep_test","service_name":"frontend","port":31001,"path":"/","routable":true}]
	}`))
	if routeRecorder.Code != http.StatusBadRequest || !strings.Contains(routeRecorder.Body.String(), `"code":"invalid_transition"`) {
		t.Fatalf("unverified domain must fail closed: %d %s", routeRecorder.Code, routeRecorder.Body.String())
	}
	if len(routes.applied) != 0 {
		t.Fatalf("unverified domain created routes: %#v", routes.applied)
	}
}

func TestM3AccessHTTPPlatformDomainAndVerifiedRoutesReturnAccessState(t *testing.T) {
	handler, routes := newM3HTTPHandler()
	platformRecorder := httptest.NewRecorder()
	handler.Handle(platformRecorder, m3HTTPRequest(http.MethodPost, "/api/v1/access/platform-domains", `{
		"base_domain":"apps.example.test", "dns_target":"dns.apps.example.test"
	}`))
	if platformRecorder.Code != http.StatusCreated || !strings.Contains(platformRecorder.Body.String(), `"kind":"platform"`) {
		t.Fatalf("platform response=%d %s", platformRecorder.Code, platformRecorder.Body.String())
	}

	routeRecorder := httptest.NewRecorder()
	handler.Handle(routeRecorder, m3HTTPRequest(http.MethodPost, "/api/v1/access/domain-routes", `{
		"binding":{"id":"domain_1","kind":"application","application_id":"app_test","host":"app.example.test","expected_cname":"target.apps.example.test","status":"ready","certificate_ref":"certificate_1"},
		"certificate":{"id":"certificate_1","host":"app.example.test","status":"ready"},
		"runtime_ready":true,
		"targets":[
			{"application_id":"app_test","deployment_id":"dep_test","service_name":"frontend","port":31001,"path":"/","routable":true},
			{"application_id":"app_test","deployment_id":"dep_test","service_name":"api","port":31002,"path":"/api","routable":true}
		]
	}`))
	if routeRecorder.Code != http.StatusCreated || !strings.Contains(routeRecorder.Body.String(), `"https_ready":true`) {
		t.Fatalf("verified route response=%d %s", routeRecorder.Code, routeRecorder.Body.String())
	}
	if len(routes.applied) != 2 {
		t.Fatalf("verified routes applied=%#v", routes.applied)
	}
}

func TestM3AccessHTTPPrepareRoutesDoesNotCallCaddy(t *testing.T) {
	handler, routes := newM3HTTPHandler()
	recorder := httptest.NewRecorder()
	handler.Handle(recorder, m3HTTPRequest(http.MethodPost, "/api/v1/access/domain-routes/prepare", `{
		"binding":{"id":"domain_1","kind":"application","application_id":"app_test","host":"app.example.test","expected_cname":"target.apps.example.test","status":"ready"},
		"runtime_ready":true,
		"targets":[{"application_id":"app_test","deployment_id":"dep_test","service_name":"frontend","port":31001,"path":"/","routable":true}]
	}`))
	if recorder.Code != http.StatusAccepted || !strings.Contains(recorder.Body.String(), `"https_ready":false`) || len(routes.applied) != 0 {
		t.Fatalf("prepare response=%d caddy=%#v body=%s", recorder.Code, routes.applied, recorder.Body.String())
	}
}

func TestM3AccessHTTPRejectsMissingIdempotencyAndUnknownJSON(t *testing.T) {
	handler, routes := newM3HTTPHandler()
	missingKey := m3HTTPRequest(http.MethodPost, "/api/v1/access/ip-fallback", `{}`)
	missingKey.Header.Del("Idempotency-Key")
	missingRecorder := httptest.NewRecorder()
	handler.Handle(missingRecorder, missingKey)
	if missingRecorder.Code != http.StatusBadRequest || !strings.Contains(missingRecorder.Body.String(), "Idempotency-Key is required") {
		t.Fatalf("missing key response=%d %s", missingRecorder.Code, missingRecorder.Body.String())
	}

	unknownRecorder := httptest.NewRecorder()
	handler.Handle(unknownRecorder, m3HTTPRequest(http.MethodPost, "/api/v1/access/platform-domains", `{"base_domain":"example.test","dns_target":"dns.example.test","extra":true}`))
	if unknownRecorder.Code != http.StatusBadRequest || !strings.Contains(unknownRecorder.Body.String(), "unknown field") {
		t.Fatalf("unknown field response=%d %s", unknownRecorder.Code, unknownRecorder.Body.String())
	}
	if len(routes.applied) != 0 {
		t.Fatalf("invalid input applied routes: %#v", routes.applied)
	}
}

func TestM3AccessHTTPRejectsNonJSONAndNonRoutableTargets(t *testing.T) {
	handler, routes := newM3HTTPHandler()
	nonJSON := m3HTTPRequest(http.MethodPost, "/api/v1/access/platform-domains", `{}`)
	nonJSON.Header.Set("Content-Type", "text/plain")
	nonJSONRecorder := httptest.NewRecorder()
	handler.Handle(nonJSONRecorder, nonJSON)
	if nonJSONRecorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("non-json status=%d body=%s", nonJSONRecorder.Code, nonJSONRecorder.Body.String())
	}

	routeRecorder := httptest.NewRecorder()
	handler.Handle(routeRecorder, m3HTTPRequest(http.MethodPost, "/api/v1/access/domain-routes", `{
		"binding":{"id":"domain_1","kind":"application","application_id":"app_test","host":"app.example.test","expected_cname":"target.apps.example.test","status":"ready","certificate_ref":"certificate_1"},
		"certificate":{"id":"certificate_1","host":"app.example.test","status":"ready"},
		"runtime_ready":true,
		"targets":[{"application_id":"app_test","deployment_id":"dep_test","service_name":"worker","port":31002,"path":"/","routable":false}]
	}`))
	if routeRecorder.Code != http.StatusForbidden || !strings.Contains(routeRecorder.Body.String(), `"code":"forbidden"`) {
		t.Fatalf("non-routable response=%d %s", routeRecorder.Code, routeRecorder.Body.String())
	}
	if len(routes.applied) != 0 {
		t.Fatalf("worker target created routes: %#v", routes.applied)
	}
}

func TestM3AccessHTTPDoesNotClaimUnhandledPaths(t *testing.T) {
	handler, _ := newM3HTTPHandler()
	if handler.Handle(httptest.NewRecorder(), m3HTTPRequest(http.MethodPost, "/api/v1/applications", `{}`)) {
		t.Fatal("M3 handler claimed an unrelated route")
	}
}

func TestM3AccessHTTPSwitchFailureReportsOldDeploymentServing(t *testing.T) {
	handler, _ := newM3HTTPHandler()
	health := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	defer health.Close()
	recorder := httptest.NewRecorder()
	requestBody := `{
		"application_id":"app_test",
		"old":[{"route":{"id":"route_root","application_id":"app_test","deployment_id":"dep_old","service_name":"frontend","host":"app.example.test","path":"/","certificate_ref":"certificate_1","verified":true,"serving":true,"created_at":"2026-08-24T00:00:00Z"},"port":31001}],
		"candidate":[{"route":{"id":"route_root","application_id":"app_test","deployment_id":"dep_new","service_name":"frontend","host":"app.example.test","path":"/","certificate_ref":"certificate_1","verified":true,"serving":true,"created_at":"2026-08-24T00:00:00Z"},"port":31002}],
		"health_url":"` + health.URL + `",
		"observation_url":"http://127.0.0.1:1/",
		"window_ms":0
	}`
	handler.Handle(recorder, m3HTTPRequest(http.MethodPost, "/api/v1/access/traffic-switches", requestBody))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), `"code":"unavailable"`) || !strings.Contains(recorder.Body.String(), "old deployment restored and remains serving") {
		t.Fatalf("switch failure response=%d %s", recorder.Code, recorder.Body.String())
	}
}
