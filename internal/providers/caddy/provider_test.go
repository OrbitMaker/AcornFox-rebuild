package caddy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

type caddyRoundTripper func(*http.Request) (*http.Response, error)

func (fn caddyRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

type caddyReadFailureBody struct{}

func (caddyReadFailureBody) Read([]byte) (int, error) { return 0, errors.New("response stream lost") }
func (caddyReadFailureBody) Close() error             { return nil }

var _ io.ReadCloser = caddyReadFailureBody{}

type adminFixture struct {
	server  *httptest.Server
	mu      sync.Mutex
	config  []byte
	loads   int
	fail    int
	headers []http.Header
}

func newAdminFixture(t *testing.T) *adminFixture {
	t.Helper()
	fixture := &adminFixture{}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		fixture.headers = append(fixture.headers, request.Header.Clone())
		switch request.URL.Path {
		case "/load":
			if request.Method != http.MethodPost {
				writer.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if fixture.fail != 0 {
				writer.WriteHeader(fixture.fail)
				return
			}
			var document any
			if err := json.NewDecoder(request.Body).Decode(&document); err != nil {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			fixture.config, _ = json.Marshal(document)
			fixture.loads++
			writer.WriteHeader(http.StatusOK)
		case "/config/":
			if len(fixture.config) == 0 {
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write(fixture.config)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func TestCaddyAdminRequestsCarryBoundedFixtureScopeHeaders(t *testing.T) {
	fixture := newAdminFixture(t)
	provider := fixture.provider(t)
	digest := "sha256:" + strings.Repeat("a", 64)
	request := routeRequest("op_rollout:route-load:0", "fixture.example.test", "/", 18443)
	request.Operation.EvidenceID = domain.ID(digest)
	if _, _, err := provider.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Observe(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.headers) < 2 {
		t.Fatalf("headers=%d", len(fixture.headers))
	}
	for _, header := range fixture.headers {
		if header.Get("X-Open-Card-Rollout-ID") != "op_rollout" || header.Get("X-Open-Card-Route-Digest") != digest {
			t.Fatalf("scope headers=%v", header)
		}
	}
}

func (f *adminFixture) provider(t *testing.T) *Provider {
	t.Helper()
	provider, err := New(Config{AdminURL: f.server.URL, Listen: "127.0.0.1:8443", Clock: func() time.Time { return time.Unix(1, 0).UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func (f *adminFixture) snapshot() ([]byte, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.config...), f.loads
}

func (f *adminFixture) clearConfig() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.config = nil
}

func (f *adminFixture) setFailure(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = status
}

func routeRequest(key, host, path string, port int) contracts.RouteRequest {
	return contracts.RouteRequest{Route: contracts.RouteSpec{
		Host: host, Path: path, DeploymentID: "deployment_1", ServiceName: "frontend", Port: port,
		CertificateRef: "secret://test-certificate-private-key", Verified: true,
	}, Operation: contracts.OperationContext{IdempotencyKey: key}}
}

func providerErrorCode(t *testing.T, err error, want contracts.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %q", want)
	}
	var providerError *contracts.ProviderError
	if !errors.As(err, &providerError) || providerError.Code != want {
		t.Fatalf("got %T %v, want provider error %q", err, err, want)
	}
}

func TestCADDY_CT_001_RejectsNonLoopbackAdmin(t *testing.T) {
	for _, raw := range []string{
		"http://0.0.0.0:2019",
		"http://192.0.2.10:2019",
		"https://127.0.0.1:2019",
		"http://localhost:2019/other",
		"http://localhost",
		"http://localhost.evil.test:2019",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := New(Config{AdminURL: raw}); err == nil {
				t.Fatalf("accepted non-local Admin URL %q", raw)
			}
		})
	}
	for _, raw := range []string{"http://127.0.0.1:2019", "http://localhost:2019", "http://[::1]:2019"} {
		t.Run("accept "+raw, func(t *testing.T) {
			if _, err := New(Config{AdminURL: raw}); err != nil {
				t.Fatalf("rejected loopback Admin URL %q: %v", raw, err)
			}
		})
	}
	for _, listen := range []string{"not-an-address", ":0", "127.0.0.1:65536"} {
		t.Run("listener "+listen, func(t *testing.T) {
			if _, err := New(Config{Listen: listen}); err == nil {
				t.Fatalf("accepted invalid Caddy listener %q", listen)
			}
		})
	}
}

func TestCADDY_CT_001_ApplyObserveAndIdempotence(t *testing.T) {
	fixture := newAdminFixture(t)
	provider := fixture.provider(t)
	request := routeRequest("route-apply-1", "APP.EXAMPLE.test", "/api", 9001)

	first, evidence, err := provider.Apply(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Serving || !first.Verified || first.ServiceName != "frontend" || len(evidence.Refs) != 2 || !evidence.Redacted {
		t.Fatalf("unexpected apply result: %#v %#v", first, evidence)
	}
	config, loads := fixture.snapshot()
	if loads != 1 || strings.Contains(string(config), "test-certificate-private-key") {
		t.Fatalf("unexpected load/config secrecy: loads=%d config=%s", loads, config)
	}
	if !strings.Contains(string(config), `"module":"internal"`) || strings.Contains(string(config), "letsencrypt") || strings.Contains(string(config), "acme") {
		t.Fatalf("M3 Caddy config did not stay on the isolated internal issuer: %s", config)
	}
	var document map[string]any
	if err := json.Unmarshal(config, &document); err != nil {
		t.Fatal(err)
	}
	admin := document["admin"].(map[string]any)
	if admin["listen"] != strings.TrimPrefix(fixture.server.URL, "http://") {
		t.Fatalf("admin listener was not restricted to selected loopback endpoint: %#v", admin)
	}
	server := document["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["open-card"].(map[string]any)
	automaticHTTPS := server["automatic_https"].(map[string]any)
	if automaticHTTPS["disable_redirects"] != true {
		t.Fatalf("Caddy automatic HTTP redirect was not disabled: %#v", automaticHTTPS)
	}
	if !routeMatches(document, routeID(mustRouteFingerprint(t, request.Route)), request.Route) {
		t.Fatalf("Caddy configuration does not contain expected route: %s", config)
	}

	second, _, err := provider.Apply(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	_, retryLoads := fixture.snapshot()
	if second.ID != first.ID || retryLoads != 1 {
		t.Fatalf("apply was not idempotent: first=%#v second=%#v loads=%d", first, second, retryLoads)
	}
	observation, err := provider.Observe(context.Background(), routeRequest("route-observe", "app.example.test", "/api", 9001))
	serving, servingOK := observation.Value.(bool)
	if err != nil || !servingOK || !serving || observation.Kind != "route.actual" || len(observation.Evidence) != 2 {
		t.Fatalf("unexpected observation: %#v %v", observation, err)
	}
}

func TestCADDY_RejectsNonIsolatedIssuer(t *testing.T) {
	if _, err := New(Config{Issuer: "acme"}); err == nil {
		t.Fatal("public ACME issuer was accepted by the isolated M3 provider")
	}
}

func TestCADDY_PlainHTTPRequiresExplicitLoopbackWithoutIssuer(t *testing.T) {
	for _, config := range []Config{
		{PlainHTTP: true},
		{PlainHTTP: true, Listen: ":18481"},
		{PlainHTTP: true, Listen: "0.0.0.0:18481"},
		{PlainHTTP: true, Listen: "127.0.0.1:18481", Issuer: "internal"},
	} {
		if _, err := New(config); err == nil {
			t.Fatalf("accepted unsafe plain HTTP config: %#v", config)
		}
	}
	if _, err := New(Config{PlainHTTP: true, Listen: "127.0.0.1:18481"}); err != nil {
		t.Fatalf("rejected explicit loopback plain HTTP config: %v", err)
	}
}

func TestCADDY_PlainHTTPDisablesHTTPSAndOmitsTLSAutomation(t *testing.T) {
	fixture := newAdminFixture(t)
	provider, err := New(Config{AdminURL: fixture.server.URL, Listen: "127.0.0.1:18481", PlainHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := provider.Apply(context.Background(), routeRequest("plain-http-route", "app.example.test", "/", 9001)); err != nil {
		t.Fatal(err)
	}
	config, _ := fixture.snapshot()
	var document map[string]any
	if err := json.Unmarshal(config, &document); err != nil {
		t.Fatal(err)
	}
	apps := document["apps"].(map[string]any)
	if _, found := apps["tls"]; found {
		t.Fatalf("plain HTTP config retained TLS automation: %s", config)
	}
	server := apps["http"].(map[string]any)["servers"].(map[string]any)["open-card"].(map[string]any)
	if server["automatic_https"].(map[string]any)["disable"] != true || strings.Contains(string(config), `"module":"internal"`) {
		t.Fatalf("plain HTTP config did not disable HTTPS: %s", config)
	}
	listen := server["listen"].([]any)
	if len(listen) != 1 || listen[0] != "127.0.0.1:18481" {
		t.Fatalf("plain HTTP listener=%#v", listen)
	}
}

func TestCADDY_CT_001_FailedLoadKeepsPriorConfigAndDerivedCache(t *testing.T) {
	fixture := newAdminFixture(t)
	provider := fixture.provider(t)
	first := routeRequest("route-first", "app.example.test", "/", 9000)
	if _, _, err := provider.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	before, _ := fixture.snapshot()
	fixture.setFailure(http.StatusBadRequest)
	second := routeRequest("route-second", "app.example.test", "/api", 9001)
	if _, _, err := provider.Apply(context.Background(), second); err == nil {
		t.Fatal("Caddy rejected config but Apply succeeded")
	} else {
		providerErrorCode(t, err, contracts.ErrValidation)
	}
	after, _ := fixture.snapshot()
	if string(after) != string(before) {
		t.Fatalf("failed load changed active configuration:\nwant %s\n got %s", before, after)
	}
	if observation, err := provider.Observe(context.Background(), routeRequest("observe-first", "app.example.test", "/", 9000)); err != nil || observation.Value != true {
		t.Fatalf("previous route is not still observable: %#v %v", observation, err)
	}
	if _, err := provider.Observe(context.Background(), routeRequest("observe-second", "app.example.test", "/api", 9001)); err == nil {
		t.Fatal("failed route was retained in derived cache")
	}
}

func TestCADDYLoadOutcomeUnknownOnlyForUnconfirmedDelivery(t *testing.T) {
	fixture := newAdminFixture(t)
	newProvider := func(client *http.Client) *Provider {
		provider, err := New(Config{AdminURL: fixture.server.URL, Listen: "127.0.0.1:8443", HTTPClient: client})
		if err != nil {
			t.Fatal(err)
		}
		return provider
	}
	t.Run("transport result is unknown after dispatch", func(t *testing.T) {
		provider := newProvider(&http.Client{Transport: caddyRoundTripper(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("connection dropped after write")
		})})
		_, _, err := provider.Apply(context.Background(), routeRequest("route-load-unknown-transport", "app.example.test", "/", 9000))
		if !contracts.IsProviderOutcomeUnknown(err) {
			t.Fatalf("transport error is not outcome-unknown: %T %v", err, err)
		}
		providerErrorCode(t, err, contracts.ErrUnavailable)
	})
	t.Run("successful status with unreadable body is unknown", func(t *testing.T) {
		provider := newProvider(&http.Client{Transport: caddyRoundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: caddyReadFailureBody{}, Header: make(http.Header)}, nil
		})})
		_, _, err := provider.Apply(context.Background(), routeRequest("route-load-unknown-read", "app.example.test", "/", 9000))
		if !contracts.IsProviderOutcomeUnknown(err) {
			t.Fatalf("read error is not outcome-unknown: %T %v", err, err)
		}
		providerErrorCode(t, err, contracts.ErrUnavailable)
	})
	t.Run("explicit rejection remains confirmed", func(t *testing.T) {
		fixture.setFailure(http.StatusBadRequest)
		_, _, err := fixture.provider(t).Apply(context.Background(), routeRequest("route-load-rejected", "app.example.test", "/", 9000))
		if contracts.IsProviderOutcomeUnknown(err) {
			t.Fatalf("confirmed rejection became outcome-unknown: %v", err)
		}
		providerErrorCode(t, err, contracts.ErrValidation)
	})
}

func TestCADDY_RebuildRoutesUsesOpenCardFactsAfterCacheLoss(t *testing.T) {
	fixture := newAdminFixture(t)
	provider := fixture.provider(t)
	first := routeRequest("route-first", "app.example.test", "/", 9000)
	if _, _, err := provider.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	fixture.clearConfig()
	if _, err := provider.Rebuild(context.Background(), contracts.OperationContext{IdempotencyKey: "rebuild-cache"}); err != nil {
		t.Fatalf("Caddy restart rebuild failed: %v", err)
	}
	provider.ClearDerivedCache()
	if _, err := provider.Rebuild(context.Background(), contracts.OperationContext{IdempotencyKey: "rebuild-without-facts"}); err == nil {
		t.Fatal("cache-less Rebuild must not read Caddy as a source of truth")
	} else {
		providerErrorCode(t, err, contracts.ErrConflict)
	}

	second := routeRequest("route-api", "app.example.test", "/api", 9001)
	if _, err := provider.RebuildRoutes(context.Background(), []contracts.RouteRequest{first, second}, contracts.OperationContext{IdempotencyKey: "rebuild-from-facts"}); err != nil {
		t.Fatal(err)
	}
	config, _ := fixture.snapshot()
	var document any
	if err := json.Unmarshal(config, &document); err != nil {
		t.Fatal(err)
	}
	for _, request := range []contracts.RouteRequest{first, second} {
		if !routeMatches(document, routeID(mustRouteFingerprint(t, request.Route)), request.Route) {
			t.Fatalf("rebuild did not install %s", request.Route.Path)
		}
	}
}

func TestCADDY_AtomicCutoverReplacesRouteAndRejectsStaleRemove(t *testing.T) {
	fixture := newAdminFixture(t)
	provider := fixture.provider(t)
	oldRoute := routeRequest("route-old", "app.example.test", "/", 9000)
	oldFact, _, err := provider.Apply(context.Background(), oldRoute)
	if err != nil {
		t.Fatal(err)
	}
	newRoute := routeRequest("route-new", "app.example.test", "/", 9001)
	newRoute.Route.DeploymentID = "deployment_2"
	newFact, _, err := provider.Apply(context.Background(), newRoute)
	if err != nil {
		t.Fatalf("healthy replacement route was not atomically loaded: %v", err)
	}
	if oldFact.ID != newFact.ID {
		t.Fatalf("route identity changed during cutover: %s -> %s", oldFact.ID, newFact.ID)
	}
	config, loads := fixture.snapshot()
	if loads != 2 || strings.Contains(string(config), "127.0.0.1:9000") || !strings.Contains(string(config), "127.0.0.1:9001") {
		t.Fatalf("cutover left old backend active: loads=%d config=%s", loads, config)
	}
	if err := provider.Remove(context.Background(), oldRoute); err == nil {
		t.Fatal("stale remove deleted a newly cut-over route")
	} else {
		providerErrorCode(t, err, contracts.ErrConflict)
	}
	observeNew := routeRequest("observe-new", "app.example.test", "/", 9001)
	observeNew.Route.DeploymentID = "deployment_2"
	if observation, err := provider.Observe(context.Background(), observeNew); err != nil || observation.Value != true {
		t.Fatalf("cut-over route is not active: %#v %v", observation, err)
	}
}

func TestCADDY_RejectsUnverifiedAndOverlappingRoutes(t *testing.T) {
	fixture := newAdminFixture(t)
	provider := fixture.provider(t)
	unverified := routeRequest("unverified", "app.example.test", "/", 9000)
	unverified.Route.Verified = false
	if _, _, err := provider.Apply(context.Background(), unverified); err == nil {
		t.Fatal("unverified route was exposed")
	} else {
		providerErrorCode(t, err, contracts.ErrInvalidArgument)
	}
	if _, _, err := provider.Apply(context.Background(), routeRequest("api", "app.example.test", "/api", 9001)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := provider.Apply(context.Background(), routeRequest("api-v1", "app.example.test", "/api/v1", 9002)); err == nil {
		t.Fatal("overlapping non-root routes were accepted")
	} else {
		providerErrorCode(t, err, contracts.ErrConflict)
	}
	if _, _, err := provider.Apply(context.Background(), routeRequest("root", "app.example.test", "/", 9000)); err != nil {
		t.Fatalf("root fallback and /api should be allowed: %v", err)
	}
}

func mustRouteFingerprint(t *testing.T, spec contracts.RouteSpec) string {
	t.Helper()
	fingerprint, err := routeFingerprint(spec)
	if err != nil {
		t.Fatal(err)
	}
	return fingerprint
}
