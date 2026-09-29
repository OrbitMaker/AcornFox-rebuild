package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/application"
	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/auth"
	"github.com/acornfox/acornfox/internal/corehttp"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/gatewayexecution"
	"github.com/acornfox/acornfox/internal/hostmetrics"
	"github.com/acornfox/acornfox/internal/localpeer"
	"github.com/acornfox/acornfox/internal/persistence/sqlite"
	"github.com/acornfox/acornfox/internal/providers/buildkit"
)

type fakeCoreImageResolver struct{}

func TestNativeSchemaDescribesCompiledPinsWithoutStartingCore(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "unopened-core-data")
	t.Setenv("ACORNFOX_DATA_DIR", dataDir)
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previousStdout := os.Stdout
	os.Stdout = write
	defer func() { os.Stdout = previousStdout }()
	err = run([]string{"native-schema"})
	os.Stdout = previousStdout
	if closeErr := write.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	output, readErr := io.ReadAll(read)
	if closeErr := read.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil || readErr != nil {
		t.Fatalf("native-schema failed: run=%v read=%v", err, readErr)
	}
	var described struct {
		SchemaVersion      int `json:"schema_version"`
		RequiredMigrations []struct {
			Version  string `json:"version"`
			Checksum string `json:"checksum"`
		} `json:"required_migrations"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&described); err != nil {
		t.Fatalf("decode native-schema output: %v", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatalf("native-schema output has trailing data: %v", err)
	}
	pins := sqlite.CompiledNativeMigrationPins()
	if described.SchemaVersion != 1 || len(described.RequiredMigrations) != len(pins) || len(pins) == 0 {
		t.Fatalf("native-schema did not describe the exact compiled prefix: schema=%d pins=%d compiled=%d", described.SchemaVersion, len(described.RequiredMigrations), len(pins))
	}
	for i, pin := range pins {
		if described.RequiredMigrations[i].Version != pin.Version || described.RequiredMigrations[i].Checksum != pin.Checksum {
			t.Fatalf("native-schema migration %d differs from the compiled SQL", i+1)
		}
	}
	for _, args := range [][]string{
		{"native-schema", "-data-dir", dataDir},
		{"-data-dir", dataDir, "native-schema"},
		{"unknown-command"},
	} {
		if err := run(args); err == nil {
			t.Fatalf("mixed or unknown Core invocation accepted: %q", args)
		}
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("native-schema or rejected invocation touched the data directory: %v", err)
	}
}

func TestCoreGatewayHealthRequiresExactUnixPeer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.sock")
	peer := gatewayexecution.ServerConfig{SocketPath: path, ExpectedPID: int32(os.Getpid()), ExpectedUID: uint32(os.Getuid()), PeerValidator: func(int32, uint32) error { return nil }}
	server, err := gatewayexecution.NewExecutionServer(peer, &gatewayexecution.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	binding := &localpeer.RuntimePeerBinding{GatewaySocket: path, GatewayPID: peer.ExpectedPID, GatewayUID: peer.ExpectedUID}
	if err := gatewayHealth(context.Background(), binding, peer.PeerValidator); err != nil {
		t.Fatal(err)
	}
	binding.GatewayPID++
	if err := gatewayHealth(context.Background(), binding, peer.PeerValidator); err == nil {
		t.Fatal("Core accepted a Gateway socket with a different bound PID")
	}
}

func TestCoreSocketGIDRequiresBindingAndPreservesLegacyDefault(t *testing.T) {
	base := []string{"-data-dir", secureTestDir(t)}
	legacy, err := parseConfig(base)
	if err != nil || legacy.socketGID != 0 {
		t.Fatalf("legacy socket group changed: %#v %v", legacy, err)
	}
	configured, err := parseConfig(append(append([]string(nil), base...), "-container-binding", "/run/acornfox/trust/runtime-binding.json", "-socket-gid", "981"))
	if err != nil || configured.socketGID != 981 {
		t.Fatalf("explicit IPC group not retained: %#v %v", configured, err)
	}
	if _, err := parseConfig(append(append([]string(nil), base...), "-socket-gid", "981")); err == nil {
		t.Fatal("IPC group without protected binding accepted")
	}
	if _, err := parseConfig(append(append([]string(nil), base...), "-container-binding", "/run/acornfox/trust/runtime-binding.json", "-socket-gid", "4294967296")); err == nil {
		t.Fatal("overflow IPC group accepted")
	}
}

func TestUnifiedCoreRequiresLaunchTicketButFixtureDoesNot(t *testing.T) {
	if _, err := parseConfig([]string{"-data-dir", "/var/lib/acornfox/core"}); err == nil {
		t.Fatal("canonical unified Core accepted without root launch ticket")
	}
	if _, err := parseConfig([]string{"-data-dir", secureTestDir(t)}); err != nil {
		t.Fatalf("non-unified fixture rejected: %v", err)
	}
}

func (f *fakeCoreImageResolver) ResolveMetadata(ctx context.Context, repository, reference string) (appcontracts.ResolvedMetadataResult, error) {
	return appcontracts.ResolvedMetadataResult{
		Repository:  repository,
		Digest:      "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ResolvedTag: reference,
		EvidenceRef: "ev_core_test_1",
	}, nil
}

type fakeMetricsReader struct{}

func (f *fakeMetricsReader) ReadFile(path string, limit int64) ([]byte, error) {
	switch path {
	case "/proc/stat":
		return []byte("cpu  100 0 50 850 0 0 0 0 0 0\n"), nil
	case "/proc/meminfo":
		return []byte("MemTotal:        16384000 kB\nMemAvailable:     8192000 kB\n"), nil
	case "/proc/net/route":
		return []byte("Iface\tDestination\tGateway \tFlags\neth0\t00000000\t0101A8C0\t0003\n"), nil
	case "/proc/net/dev":
		return []byte("Inter-|   Receive                    |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n  eth0: 1000000     100    0    0    0     0          0         0  2000000     100    0    0    0     0       0          0\n"), nil
	default:
		return nil, os.ErrNotExist
	}
}

func (f *fakeMetricsReader) Statfs(path string) (hostmetrics.Filesystem, error) {
	return hostmetrics.Filesystem{
		Blocks:          100000,
		AvailableBlocks: 40000,
		BlockSize:       4096,
	}, nil
}

type fakeAvailabilityProvider struct {
	available bool
}

func (f *fakeAvailabilityProvider) IsAvailable() bool {
	return f.available
}

func secureTestDir(t *testing.T, sub ...string) string {
	t.Helper()
	temp := t.TempDir()
	if err := os.Chmod(temp, 0o700); err != nil {
		t.Fatal(err)
	}
	if len(sub) > 0 {
		full := filepath.Join(append([]string{temp}, sub...)...)
		if err := os.MkdirAll(full, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, 0o700); err != nil {
			t.Fatal(err)
		}
		return full
	}
	return temp
}

func TestAcornFoxCoreConfigAgreementAndRejection(t *testing.T) {
	dataDir := secureTestDir(t, "config_data")

	cases := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "valid default loopback agrees",
			args:    []string{"-data-dir", dataDir},
			wantErr: false,
		},
		{
			name:    "valid explicit loopback port agrees auto-derived origin",
			args:    []string{"-data-dir", dataDir, "-listen", "127.0.0.1:9090"},
			wantErr: false,
		},
		{
			name:    "valid explicit loopback port and matching origin",
			args:    []string{"-data-dir", dataDir, "-listen", "127.0.0.1:9090", "-origin", "http://127.0.0.1:9090"},
			wantErr: false,
		},
		{
			name:    "reject mismatched listen and origin port",
			args:    []string{"-data-dir", dataDir, "-listen", "127.0.0.1:9090", "-origin", "http://127.0.0.1:8080"},
			wantErr: true,
		},
		{
			name:    "reject origin with path",
			args:    []string{"-data-dir", dataDir, "-listen", "127.0.0.1:8080", "-origin", "http://127.0.0.1:8080/path"},
			wantErr: true,
		},
		{
			name:    "reject origin with userinfo",
			args:    []string{"-data-dir", dataDir, "-listen", "127.0.0.1:8080", "-origin", "http://user:pass@127.0.0.1:8080"},
			wantErr: true,
		},
		{
			name:    "reject localhost hostname",
			args:    []string{"-data-dir", dataDir, "-listen", "localhost:8080"},
			wantErr: true,
		},
		{
			name:    "reject public all interfaces 0.0.0.0",
			args:    []string{"-data-dir", dataDir, "-listen", "0.0.0.0:8080"},
			wantErr: true,
		},
		{
			name:    "reject public empty host bind",
			args:    []string{"-data-dir", dataDir, "-listen", ":8080"},
			wantErr: true,
		},
		{
			name:    "reject public external ip",
			args:    []string{"-data-dir", dataDir, "-listen", "192.168.1.100:8080"},
			wantErr: true,
		},
		{
			name:    "missing data directory",
			args:    []string{"-listen", "127.0.0.1:8080"},
			wantErr: true,
		},
		{
			name:    "relative data directory",
			args:    []string{"-data-dir", "relative/path", "-listen", "127.0.0.1:8080"},
			wantErr: true,
		},
		{
			name:    "in-memory data directory rejected",
			args:    []string{"-data-dir", ":memory:", "-listen", "127.0.0.1:8080"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseConfig(tc.args)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseConfig(%v) err=%v, wantErr=%v", tc.args, err, tc.wantErr)
			}
		})
	}
}

func TestAcornFoxCoreBootstrapAndReadinessFromStore(t *testing.T) {
	dataDir := secureTestDir(t, "store_readiness_data")
	credDir := secureTestDir(t, "credentials")

	// Create valid setup token
	rawToken := make([]byte, 32)
	for i := range rawToken {
		rawToken[i] = byte(i + 7)
	}
	tokenStr := base64.RawURLEncoding.EncodeToString(rawToken)
	tokenFile := filepath.Join(credDir, "acornfox-setup-token")
	if err := os.WriteFile(tokenFile, []byte(tokenStr+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	store, err := sqlite.Open(sqlite.Config{
		DataDirectory: dataDir,
		DBName:        "acornfox.db",
	})
	if err != nil {
		t.Fatalf("Open sqlite store: %v", err)
	}

	authService, err := auth.NewLocalService(auth.Config{
		Store:  store,
		Origin: "http://127.0.0.1:8080",
	})
	if err != nil {
		t.Fatal(err)
	}

	cred := corehttp.AcornFoxSetupCredential(credDir)
	if len(cred) == 0 {
		t.Fatal("failed to load setup credential from private directory")
	}

	setupHandler, err := corehttp.NewAcornFoxWebSetupHTTPHandler(store, authService, cred)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Fresh store setup state derives uninitialized from service/store
	ctx := context.Background()
	if state := setupHandler.Service.State(ctx); state != auth.WebSetupStateUninitialized {
		t.Fatalf("expected uninitialized state for fresh store, got %q", state)
	}

	server := newCoreServer(coreServerConfig{
		ExpectedHost: "127.0.0.1:8080",
		Store:        store,
		AuthService:  authService,
		AuthHandler:  &corehttp.AuthHTTPHandler{Service: authService},
		SetupHandler: setupHandler,
	})

	coreReq := func(method, path string) *http.Request {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "127.0.0.1:32145"
		req.Host = "127.0.0.1:8080"
		return req
	}

	// 2. /healthz returns 200
	hRec := httptest.NewRecorder()
	server.ServeHTTP(hRec, coreReq(http.MethodGet, "/healthz"))
	if hRec.Code != http.StatusOK {
		t.Fatalf("/healthz code=%d", hRec.Code)
	}

	// 3. /readyz returns 200 when store is open
	rRec := httptest.NewRecorder()
	server.ServeHTTP(rRec, coreReq(http.MethodGet, "/readyz"))
	if rRec.Code != http.StatusOK {
		t.Fatalf("/readyz code=%d", rRec.Code)
	}

	// 4. Non-GET on healthz/readyz returns 405
	mRec := httptest.NewRecorder()
	server.ServeHTTP(mRec, coreReq(http.MethodPost, "/readyz"))
	if mRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /readyz code=%d, want 405", mRec.Code)
	}

	// 5. When store is closed, /readyz returns 503 not_ready (derives from actual store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	rClosedRec := httptest.NewRecorder()
	server.ServeHTTP(rClosedRec, coreReq(http.MethodGet, "/readyz"))
	if rClosedRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed store /readyz code=%d, want 503", rClosedRec.Code)
	}
	var errMap map[string]string
	if err := json.Unmarshal(rClosedRec.Body.Bytes(), &errMap); err != nil || errMap["code"] != "not_ready" {
		t.Fatalf("expected not_ready code, got %s", rClosedRec.Body.String())
	}

	// 6. /healthz remains 200 even when store is closed (process liveness independent of store)
	hAliveRec := httptest.NewRecorder()
	server.ServeHTTP(hAliveRec, coreReq(http.MethodGet, "/healthz"))
	if hAliveRec.Code != http.StatusOK {
		t.Fatalf("liveness /healthz code=%d after store close", hAliveRec.Code)
	}
}

func TestAcornFoxCoreRoutingAndCapabilityUnavailable(t *testing.T) {
	dataDir := secureTestDir(t, "routing_data")
	store, err := sqlite.Open(sqlite.Config{
		DataDirectory: dataDir,
		DBName:        "acornfox.db",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	authService, err := auth.NewLocalService(auth.Config{
		Store:  store,
		Origin: "http://127.0.0.1:8080",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create test administrator and session directly in store
	now := time.Now().UTC()
	hash, err := authService.HashPassword("TestAdminPassword123")
	if err != nil {
		t.Fatal(err)
	}
	adminID := domain.ID("admin_test_1")
	if err := store.CreateAdminCredential(context.Background(), domain.AdminCredential{
		ID:                 adminID,
		PasswordHashScheme: auth.PasswordHashScheme,
		PasswordHash:       hash,
		CredentialVersion:  1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}); err != nil {
		t.Fatal(err)
	}

	loginRes, err := authService.Login(context.Background(), "http://127.0.0.1:8080", "TestAdminPassword123", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	sessionCookie := &http.Cookie{Name: corehttp.AcornFoxLocalSessionCookie, Value: loginRes.SessionToken}

	sampler := hostmetrics.NewSampler(hostmetrics.Config{
		OS:     "linux",
		Reader: &fakeMetricsReader{},
	})
	sampler.Sample(context.Background())

	imageDeliveryService := application.NewImageDeliveryService(&fakeCoreImageResolver{})
	imageDeliveryHandler := &corehttp.ImageDeliveryHandler{
		Service: imageDeliveryService,
		Store:   store,
		Auth:    authService,
		Config:  corehttp.LocalAuthRouteConfig,
	}

	server := newCoreServer(coreServerConfig{
		ExpectedHost:         "127.0.0.1:8080",
		Store:                store,
		AuthService:          authService,
		AuthHandler:          &corehttp.AuthHTTPHandler{Service: authService},
		Sampler:              sampler,
		ImageDeliveryHandler: imageDeliveryHandler,
	})

	coreReq := func(method, path string, authed bool) *http.Request {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "127.0.0.1:32145"
		req.Host = "127.0.0.1:8080"
		req.Header.Set("Origin", "http://127.0.0.1:8080")
		if authed {
			req.AddCookie(sessionCookie)
			req.AddCookie(&http.Cookie{Name: corehttp.AcornFoxLocalCSRFCookie, Value: loginRes.CSRFTok})
			req.Header.Set("X-AcornFox-CSRF", loginRes.CSRFTok)
		}
		return req
	}

	// 1. Core status: Unauthenticated -> 401
	unauthStatus := httptest.NewRecorder()
	server.ServeHTTP(unauthStatus, coreReq(http.MethodGet, "/api/v1/acornfox/core/status", false))
	if unauthStatus.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated core status code=%d, want 401", unauthStatus.Code)
	}

	// 2. Core status: Authenticated GET -> 200 with exact structure
	authStatus := httptest.NewRecorder()
	server.ServeHTTP(authStatus, coreReq(http.MethodGet, "/api/v1/acornfox/core/status", true))
	if authStatus.Code != http.StatusOK {
		t.Fatalf("authenticated core status code=%d body=%s", authStatus.Code, authStatus.Body.String())
	}
	var statusMap map[string]any
	if err := json.Unmarshal(authStatus.Body.Bytes(), &statusMap); err != nil {
		t.Fatalf("unmarshal core status: %v", err)
	}
	if statusMap["storage"] != "sqlite" || statusMap["package_management"] != "unavailable" {
		t.Fatalf("unexpected core status: %v", statusMap)
	}
	caps, ok := statusMap["capabilities"].([]any)
	if !ok || len(caps) != 1 || caps[0] != "host_metrics" {
		t.Fatalf("expected capabilities array [host_metrics], got %v", statusMap["capabilities"])
	}

	// 2b. Test dynamic availability provider reflection
	fakeProvider := &fakeAvailabilityProvider{available: true}
	serverWithProvider := newCoreServer(coreServerConfig{
		ExpectedHost:         "127.0.0.1:8080",
		Store:                store,
		AuthService:          authService,
		AuthHandler:          &corehttp.AuthHTTPHandler{Service: authService},
		Sampler:              sampler,
		PackConfig:           CorePackConfig{Enabled: true},
		AvailabilityProvider: fakeProvider,
	})
	recAvail := httptest.NewRecorder()
	serverWithProvider.ServeHTTP(recAvail, coreReq(http.MethodGet, "/api/v1/acornfox/core/status", true))
	if recAvail.Code != http.StatusOK {
		t.Fatalf("dynamic status code=%d", recAvail.Code)
	}
	var availMap map[string]any
	_ = json.Unmarshal(recAvail.Body.Bytes(), &availMap)
	if availMap["package_management"] != "available" {
		t.Fatalf("expected available when provider is available, got: %v", availMap)
	}

	fakeProvider.available = false
	recUnavail := httptest.NewRecorder()
	serverWithProvider.ServeHTTP(recUnavail, coreReq(http.MethodGet, "/api/v1/acornfox/core/status", true))
	var unavailMap map[string]any
	_ = json.Unmarshal(recUnavail.Body.Bytes(), &unavailMap)
	if unavailMap["package_management"] != "unavailable" {
		t.Fatalf("expected unavailable when provider is offline, got: %v", unavailMap)
	}

	// 3. Known business APIs without package management return 503 capability_unavailable
	capabilities := []struct {
		path string
		cap  string
	}{
		{"/api/v1/acornfox/apps", "apps"},
		{"/api/v1/acornfox/apps/app-1", "apps"},
		{"/api/v1/acornfox/source-uploads", "source_uploads"},
		{"/api/v1/acornfox/source-uploads/upload-1", "source_uploads"},
	}

	for _, tc := range capabilities {
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, coreReq(http.MethodGet, tc.path, true))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s code=%d, want 503", tc.path, rec.Code)
		}
		var errResp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
			t.Fatalf("parse 503 JSON: %v", err)
		}
		if errResp["code"] != "capability_unavailable" || errResp["capability"] != tc.cap {
			t.Fatalf("expected capability_unavailable for %s, got %v", tc.cap, errResp)
		}
	}

	// 3b. Host metrics and recent endpoints: Unauthenticated -> 401
	for _, p := range []string{"/api/v1/acornfox/host/metrics", "/api/v1/acornfox/host/metrics/recent"} {
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, coreReq(http.MethodGet, p, false))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s code=%d, want 401", p, rec.Code)
		}
	}

	// 3c. Host metrics: Authenticated GET -> 200
	recMetrics := httptest.NewRecorder()
	server.ServeHTTP(recMetrics, coreReq(http.MethodGet, "/api/v1/acornfox/host/metrics", true))
	if recMetrics.Code != http.StatusOK {
		t.Fatalf("authenticated /host/metrics code=%d, want 200 body=%s", recMetrics.Code, recMetrics.Body.String())
	}
	var metricsResp hostmetrics.Response
	if err := json.Unmarshal(recMetrics.Body.Bytes(), &metricsResp); err != nil {
		t.Fatalf("unmarshal host metrics response: %v", err)
	}
	if metricsResp.SchemaVersion != 1 {
		t.Fatalf("expected schema_version 1, got %d", metricsResp.SchemaVersion)
	}

	// 3d. Host metrics reject query params -> 400
	recMetricsBad := httptest.NewRecorder()
	server.ServeHTTP(recMetricsBad, coreReq(http.MethodGet, "/api/v1/acornfox/host/metrics?limit=10", true))
	if recMetricsBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for /host/metrics with query params, got %d", recMetricsBad.Code)
	}

	// 3e. Host metrics reject non-GET -> 405 + Allow: GET
	recMetricsPost := httptest.NewRecorder()
	server.ServeHTTP(recMetricsPost, coreReq(http.MethodPost, "/api/v1/acornfox/host/metrics", true))
	if recMetricsPost.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for POST /host/metrics, got %d", recMetricsPost.Code)
	}
	if recMetricsPost.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("expected Allow: GET, got %q", recMetricsPost.Header().Get("Allow"))
	}

	// 3f. Host metrics recent: Authenticated GET -> 200
	recRecent := httptest.NewRecorder()
	server.ServeHTTP(recRecent, coreReq(http.MethodGet, "/api/v1/acornfox/host/metrics/recent?limit=10", true))
	if recRecent.Code != http.StatusOK {
		t.Fatalf("authenticated /host/metrics/recent code=%d, want 200 body=%s", recRecent.Code, recRecent.Body.String())
	}
	var recentResp hostmetrics.RecentResponse
	if err := json.Unmarshal(recRecent.Body.Bytes(), &recentResp); err != nil {
		t.Fatalf("unmarshal recent response: %v", err)
	}
	if recentResp.SchemaVersion != 1 || recentResp.Capacity != 360 {
		t.Fatalf("unexpected recent response metadata: %+v", recentResp)
	}

	// 3g. Host metrics recent reject invalid limit -> 400
	recRecentBad := httptest.NewRecorder()
	server.ServeHTTP(recRecentBad, coreReq(http.MethodGet, "/api/v1/acornfox/host/metrics/recent?limit=999", true))
	if recRecentBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for /host/metrics/recent?limit=999, got %d", recRecentBad.Code)
	}

	// 3h. Unknown suffix under /api/v1/acornfox/host/metrics/ -> 404 JSON (no SPA fallback)
	recSuffix := httptest.NewRecorder()
	server.ServeHTTP(recSuffix, coreReq(http.MethodGet, "/api/v1/acornfox/host/metrics/nonexistent", true))
	if recSuffix.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown host metrics suffix, got %d", recSuffix.Code)
	}
	var suffixErr map[string]any
	if err := json.Unmarshal(recSuffix.Body.Bytes(), &suffixErr); err != nil || suffixErr["code"] != "not_found" {
		t.Fatalf("expected JSON 404 not_found, got body=%s", recSuffix.Body.String())
	}

	// 3i. Image delivery plan creation and confirmation flow via CoreServer
	createPlanBody := `{"app_name":"core-app","image":"nginx:latest","port":80}`
	planReq := httptest.NewRequest(http.MethodPost, "/api/v1/acornfox/image-plans", strings.NewReader(createPlanBody))
	planReq.RemoteAddr = "127.0.0.1:32145"
	planReq.Host = "127.0.0.1:8080"
	planReq.Header.Set("Origin", "http://127.0.0.1:8080")
	planReq.Header.Set("X-AcornFox-CSRF", loginRes.CSRFTok)
	planReq.AddCookie(sessionCookie)
	planReq.AddCookie(&http.Cookie{Name: corehttp.AcornFoxLocalCSRFCookie, Value: loginRes.CSRFTok})
	planRec := httptest.NewRecorder()
	server.ServeHTTP(planRec, planReq)
	if planRec.Code != http.StatusCreated {
		t.Fatalf("core image-plan creation code=%d body=%s", planRec.Code, planRec.Body.String())
	}
	var createdPlan appcontracts.ImagePlan
	_ = json.Unmarshal(planRec.Body.Bytes(), &createdPlan)

	// Confirm plan via CoreServer
	confirmBody := `{"plan_id":"` + createdPlan.ID.String() + `","plan_digest":"` + createdPlan.PlanDigest + `","idempotency_key":"core-confirm-key-1"}`
	confReq := httptest.NewRequest(http.MethodPost, "/api/v1/acornfox/image-plans/"+createdPlan.ID.String()+"/confirm", strings.NewReader(confirmBody))
	confReq.RemoteAddr = "127.0.0.1:32145"
	confReq.Host = "127.0.0.1:8080"
	confReq.Header.Set("Origin", "http://127.0.0.1:8080")
	confReq.Header.Set("X-AcornFox-CSRF", loginRes.CSRFTok)
	confReq.AddCookie(sessionCookie)
	confReq.AddCookie(&http.Cookie{Name: corehttp.AcornFoxLocalCSRFCookie, Value: loginRes.CSRFTok})
	confRec := httptest.NewRecorder()
	server.ServeHTTP(confRec, confReq)
	if confRec.Code != http.StatusOK {
		t.Fatalf("core image-plan confirmation code=%d body=%s", confRec.Code, confRec.Body.String())
	}
	var confRes appcontracts.ConfirmImagePlanResult
	_ = json.Unmarshal(confRec.Body.Bytes(), &confRes)

	// Read operation detail via CoreServer
	opReq := coreReq(http.MethodGet, "/api/v1/acornfox/operations/"+confRes.OperationID.String(), true)
	opRec := httptest.NewRecorder()
	server.ServeHTTP(opRec, opReq)
	if opRec.Code != http.StatusOK {
		t.Fatalf("core operation detail code=%d body=%s", opRec.Code, opRec.Body.String())
	}
	var opDetail appcontracts.ImageOperationDetail
	_ = json.Unmarshal(opRec.Body.Bytes(), &opDetail)
	if opDetail.State != "pending" || opDetail.PlanID != createdPlan.ID {
		t.Fatalf("unexpected operation detail: %+v", opDetail)
	}

	// 4. Retired assistant routes return 404 JSON
	for _, p := range []string{"/api/v1/acornfox/assistant", "/api/v1/acornfox/assistant/sessions"} {
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, coreReq(http.MethodGet, p, false))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("retired route %s code=%d, want 404", p, rec.Code)
		}
	}

	// 5. Unknown API route returns 404 JSON
	unknownRec := httptest.NewRecorder()
	server.ServeHTTP(unknownRec, coreReq(http.MethodGet, "/api/v1/nonexistent", true))
	if unknownRec.Code != http.StatusNotFound {
		t.Fatalf("unknown route code=%d, want 404", unknownRec.Code)
	}
}

func TestAcornFoxCoreStaticBoundary(t *testing.T) {
	dataDir := secureTestDir(t, "static_bound_data")
	webRoot := secureTestDir(t, "static_bound_web")

	// Populate core.html and asset file
	coreHTML := "<!DOCTYPE html><html><body>Core Entry</body></html>"
	if err := os.WriteFile(filepath.Join(webRoot, "core.html"), []byte(coreHTML), 0644); err != nil {
		t.Fatal(err)
	}
	assetsDir := filepath.Join(webRoot, "assets")
	if err := os.Mkdir(assetsDir, 0755); err != nil {
		t.Fatal(err)
	}
	jsFile := filepath.Join(assetsDir, "app.js")
	if err := os.WriteFile(jsFile, []byte("console.log('asset');"), 0644); err != nil {
		t.Fatal(err)
	}

	// Arbitrary ordinary file (should NOT be served)
	if err := os.WriteFile(filepath.Join(webRoot, "package.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	handler, err := newStaticCoreHandler(webRoot, dataDir)
	if err != nil {
		t.Fatalf("newStaticCoreHandler: %v", err)
	}
	defer handler.Close()

	server := newCoreServer(coreServerConfig{
		ExpectedHost:  "127.0.0.1:8080",
		StaticHandler: handler,
	})

	coreReq := func(method, path string) *http.Request {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "127.0.0.1:32145"
		req.Host = "127.0.0.1:8080"
		return req
	}

	// 1. Root / serves core.html
	rootRec := httptest.NewRecorder()
	server.ServeHTTP(rootRec, coreReq(http.MethodGet, "/"))
	if rootRec.Code != http.StatusOK || rootRec.Body.String() != coreHTML {
		t.Fatalf("/ code=%d body=%s", rootRec.Code, rootRec.Body.String())
	}

	// 2. SPA navigation route serves core.html
	spaRec := httptest.NewRecorder()
	server.ServeHTTP(spaRec, coreReq(http.MethodGet, "/login"))
	if spaRec.Code != http.StatusOK || spaRec.Body.String() != coreHTML {
		t.Fatalf("/login code=%d body=%s", spaRec.Code, spaRec.Body.String())
	}

	// 3. Static asset /assets/app.js serves file
	assetRec := httptest.NewRecorder()
	server.ServeHTTP(assetRec, coreReq(http.MethodGet, "/assets/app.js"))
	if assetRec.Code != http.StatusOK || assetRec.Body.String() != "console.log('asset');" {
		t.Fatalf("/assets/app.js code=%d body=%s", assetRec.Code, assetRec.Body.String())
	}

	// 4. Missing asset returns 404 (not HTML)
	missingRec := httptest.NewRecorder()
	server.ServeHTTP(missingRec, coreReq(http.MethodGet, "/assets/missing.js"))
	if missingRec.Code != http.StatusNotFound {
		t.Fatalf("missing asset code=%d, want 404", missingRec.Code)
	}

	// 5. Arbitrary ordinary file outside /assets/ returns 404
	ordRec := httptest.NewRecorder()
	server.ServeHTTP(ordRec, coreReq(http.MethodGet, "/package.json"))
	if ordRec.Code != http.StatusNotFound {
		t.Fatalf("arbitrary file code=%d, want 404", ordRec.Code)
	}

	// 6. Dotfile request returns 404
	dotRec := httptest.NewRecorder()
	server.ServeHTTP(dotRec, coreReq(http.MethodGet, "/.env"))
	if dotRec.Code != http.StatusNotFound {
		t.Fatalf("dotfile code=%d, want 404", dotRec.Code)
	}

	// 7. Rejection of filesystem root as web root
	if _, err := newStaticCoreHandler("/", dataDir); err == nil {
		t.Fatal("expected newStaticCoreHandler to reject root /")
	}

	// 8. Rejection of web root overlapping with data directory
	if _, err := newStaticCoreHandler(dataDir, dataDir); err == nil {
		t.Fatal("expected newStaticCoreHandler to reject overlapping webRoot and dataDir")
	}
}

func TestAcornFoxCorePackConfigAndStatus(t *testing.T) {
	dataDir := secureTestDir(t, "core_pack_data")
	store, err := sqlite.Open(sqlite.Config{DataDirectory: dataDir, DBName: "test.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	authSvc, err := auth.NewLocalService(auth.Config{Store: store, Origin: "http://127.0.0.1:8080"})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Without pack config: status is unavailable
	serverUnconfigured := newCoreServer(coreServerConfig{
		ExpectedHost: "127.0.0.1:8080",
		Store:        store,
		AuthService:  authSvc,
		PackConfig:   CorePackConfig{Enabled: false},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/core/status", nil)
	req.RemoteAddr = "127.0.0.1:45123"
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	serverUnconfigured.ServeHTTP(rec, req)

	// Since unauthenticated, check 401 or login redirect
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 unauthenticated, got %d", rec.Code)
	}

	// 2. Validate loadProtectedPackConfig guards
	// Rejection of relative path
	if _, err := loadProtectedPackConfig("relative/path.json"); err == nil {
		t.Fatal("expected relative path to be rejected")
	}

	// Empty path returns Disabled
	emptyCfg, err := loadProtectedPackConfig("")
	if err != nil || emptyCfg.Enabled {
		t.Fatalf("expected empty path to return disabled without error, got cfg=%+v, err=%v", emptyCfg, err)
	}

	// Non-root owned config file is strictly rejected
	cfgDir := secureTestDir(t, "user_cfg")
	cfgFile := filepath.Join(cfgDir, "pack-runtime.json")
	validJSON := `{
		"socket_path": "/run/acornfox-helper/helper.sock",
		"state_dir": "/var/lib/acornfox-host-helper",
		"stage_dir": "/var/lib/acornfox/core/pack-staging",
		"packs_dir": "/opt/acornfox/packs",
		"packs_state_dir": "/var/lib/acornfox/packs",
		"packs_run_dir": "/run/acornfox/packs",
		"core_uid": 1000,
		"core_gid": 1000,
		"trusted_core_executable_sha": "abc123",
		"installation_binding": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"publishers": []
	}`
	if err := os.WriteFile(cfgFile, []byte(validJSON), 0640); err != nil {
		t.Fatal(err)
	}

	if os.Getuid() != 0 {
		_, err := loadProtectedPackConfig(cfgFile)
		if err == nil || !strings.Contains(err.Error(), "strictly by root (0)") {
			t.Fatalf("expected non-root config to be rejected, got %v", err)
		}
	}
}

func TestCoreSourceRoutesPreserveLoopbackHostAndExistingRoutes(t *testing.T) {
	baseCalls := 0
	base := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { baseCalls++; w.WriteHeader(http.StatusNoContent) })
	handler := withCoreSourceRoutes(base, nil, "127.0.0.1:8080")
	r := httptest.NewRequest(http.MethodPost, corehttp.SourceBuildAPIBase+"/prepare", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Host = "127.0.0.1:8080"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || baseCalls != 0 {
		t.Fatal("unconfigured source integration fell through to existing routes")
	}
	r.Host = "attacker.invalid"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal("source route bypassed core host guard")
	}
	r = httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/image-apps", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent || baseCalls != 1 {
		t.Fatal("source composition changed existing routes")
	}
}

func TestSourceBuildPublicResourcePinsMatchInstalledBuilder(t *testing.T) {
	if appcontracts.SourceBuildPublicCPUMillis != buildkit.CPULimitMillis || appcontracts.SourceBuildPublicMemoryBytes != buildkit.MemoryLimitBytes {
		t.Fatal("public SourceBuild limits drifted from installed BuildKit worker")
	}
}
