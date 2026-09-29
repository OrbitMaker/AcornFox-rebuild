// Command acornfox-core serves the AcornFox HTTP API and web console, owns the
// SQLite store and schedules work for acornfox-executor.
//
// Core never touches Docker, BuildKit or Caddy. It reaches the executor over
// Unix sockets in layout.RunDir and serves authority sockets that the executor
// calls back to renew leases and commit results. Login, setup and read APIs
// keep working while the executor is down; execution resumes when it returns.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/acornfox/acornfox/internal/application"
	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/auth"
	"github.com/acornfox/acornfox/internal/buildnetwork"
	"github.com/acornfox/acornfox/internal/containermetrics"
	"github.com/acornfox/acornfox/internal/corehttp"
	"github.com/acornfox/acornfox/internal/gatewayexecution"
	"github.com/acornfox/acornfox/internal/hostmetrics"
	"github.com/acornfox/acornfox/internal/imageexecution"
	"github.com/acornfox/acornfox/internal/layout"
	"github.com/acornfox/acornfox/internal/peer"
	"github.com/acornfox/acornfox/internal/persistence/sqlite"
	"github.com/acornfox/acornfox/internal/providers/registryhttp"
	"github.com/acornfox/acornfox/internal/sourcebuildexecution"
)

type config struct {
	dataDir        string
	listenAddr     string
	origin         string
	credentialsDir string
	webRoot        string
	dbName         string
	noExecutor     bool
}

func parseConfig(args []string) (config, error) {
	fs := flag.NewFlagSet("acornfox-core", flag.ContinueOnError)
	var cfg config
	fs.StringVar(&cfg.dataDir, "data-dir", envOr("ACORNFOX_DATA_DIR", layout.CoreDataDir), "Private absolute SQLite data directory")
	fs.StringVar(&cfg.listenAddr, "listen", "127.0.0.1:8080", "Loopback HTTP listen address (e.g. 127.0.0.1:8080)")
	fs.StringVar(&cfg.origin, "origin", "", "Matching loopback origin (default http://<listen>)")
	fs.StringVar(&cfg.credentialsDir, "credentials-dir", os.Getenv("CREDENTIALS_DIRECTORY"), "Directory containing systemd credentials")
	fs.StringVar(&cfg.webRoot, "web-root", "", "Optional directory containing static web assets")
	fs.StringVar(&cfg.dbName, "db-name", layout.CoreDBName, "Database file name")
	fs.BoolVar(&cfg.noExecutor, "no-executor", false, "Do not connect to acornfox-executor (development only)")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if fs.NArg() != 0 {
		return config{}, fmt.Errorf("unexpected core argument %q", fs.Arg(0))
	}

	cfg.dataDir = strings.TrimSpace(cfg.dataDir)
	if cfg.dataDir == "" || cfg.dataDir == ":memory:" {
		return config{}, errors.New("data directory (-data-dir or ACORNFOX_DATA_DIR) is required")
	}
	cleanData := filepath.Clean(cfg.dataDir)
	if !filepath.IsAbs(cleanData) {
		return config{}, fmt.Errorf("data directory %q must be an absolute path", cfg.dataDir)
	}
	cfg.dataDir = cleanData

	// The listener binds an explicit loopback IP only (hostnames, including localhost, are rejected).
	cfg.listenAddr = strings.TrimSpace(cfg.listenAddr)
	if cfg.listenAddr == "" {
		cfg.listenAddr = "127.0.0.1:8080"
	}
	host, portStr, err := net.SplitHostPort(cfg.listenAddr)
	if err != nil {
		return config{}, fmt.Errorf("invalid listen address %q: %w", cfg.listenAddr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return config{}, fmt.Errorf("bind address %q is rejected; must bind to an explicit loopback IP address (e.g. 127.0.0.1)", cfg.listenAddr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return config{}, fmt.Errorf("listen port %q is invalid", portStr)
	}

	cfg.origin = strings.TrimSpace(cfg.origin)
	if cfg.origin == "" {
		cfg.origin = "http://" + cfg.listenAddr
	}
	originURL, err := url.Parse(cfg.origin)
	if err != nil || originURL.Scheme != "http" || originURL.User != nil || originURL.Path != "" || originURL.RawQuery != "" || originURL.Fragment != "" {
		return config{}, fmt.Errorf("origin %q must be an exact loopback HTTP origin without user, path, query, or fragment", cfg.origin)
	}
	originHost, originPort, err := net.SplitHostPort(originURL.Host)
	if err != nil {
		return config{}, fmt.Errorf("origin %q must have explicit host and port", cfg.origin)
	}
	if originHost != host || originPort != portStr {
		return config{}, fmt.Errorf("listen address %q and origin %q host/port must agree exactly", cfg.listenAddr, cfg.origin)
	}
	return cfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatalf("acornfox-core: %v", err)
	}
}

func run(args []string) (runErr error) {
	cfg, err := parseConfig(args)
	if err != nil {
		return err
	}
	var id layout.Identity
	if !cfg.noExecutor {
		if id, err = layout.Resolve(); err != nil {
			return err
		}
		if uint32(os.Getuid()) != id.CoreUID {
			return fmt.Errorf("must run as %s", layout.AccountCore)
		}
	}

	store, err := sqlite.Open(sqlite.Config{DataDirectory: cfg.dataDir, DBName: cfg.dbName})
	if err != nil {
		return fmt.Errorf("open sqlite store: %w", err)
	}
	// closeStore is cleared when a worker cannot be joined; the store then stays
	// locked until process exit instead of being closed under a live writer.
	closeStore := true
	defer func() {
		if closeStore {
			if closeErr := store.Close(); closeErr != nil && runErr == nil {
				runErr = fmt.Errorf("close sqlite store: %w", closeErr)
			}
		}
	}()

	authService, err := auth.NewLocalService(auth.Config{Store: store, Origin: cfg.origin})
	if err != nil {
		return fmt.Errorf("init auth service: %w", err)
	}
	authHandler := &corehttp.AuthHTTPHandler{Service: authService}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	adminExists, err := store.AdministratorExists(ctx)
	cancel()
	if err != nil {
		return fmt.Errorf("check administrator existence: %w", err)
	}
	cred := corehttp.AcornFoxSetupCredential(cfg.credentialsDir)
	setupHandler, err := corehttp.NewAcornFoxWebSetupHTTPHandler(store, authService, cred)
	if err != nil {
		return fmt.Errorf("create web setup handler: %w", err)
	}
	if !adminExists {
		if len(cred) == 0 {
			return errors.New("setup credential (acornfox-setup-token) is required when no administrator exists")
		}
		setupCtx, setupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		state := setupHandler.Service.State(setupCtx)
		setupCancel()
		if state != auth.WebSetupStateUninitialized {
			return fmt.Errorf("web setup service is not uninitialized (got state=%s); verify valid setup credential", state)
		}
	}

	staticHandler, err := newStaticCoreHandler(cfg.webRoot, cfg.dataDir)
	if err != nil {
		return fmt.Errorf("configure static core assets: %w", err)
	}
	if staticHandler != nil {
		defer staticHandler.Close()
	}

	sampler := hostmetrics.NewSampler(hostmetrics.Config{})
	registryProvider, err := registryhttp.New(registryhttp.Config{})
	if err != nil {
		return fmt.Errorf("create registry metadata provider: %w", err)
	}
	imageDeliveryService := application.NewImageDeliveryService(&application.RegistryMetadataAdapter{Provider: registryProvider})
	imageObservationHandler := &corehttp.ImageObservationHandler{Store: store, Auth: authService, Config: corehttp.LocalAuthRouteConfig}
	metricHistory := containermetrics.NewHistory(time.Now())
	metricSampler := &containermetrics.Sampler{Store: store, History: metricHistory}
	imageMetricsHandler := &corehttp.ImageMetricsHandler{Store: store, Auth: authService, Config: corehttp.LocalAuthRouteConfig, History: metricHistory, Sampler: metricSampler}

	var containerReady, sourceReady, gatewayReady atomic.Bool
	domainCommands := &application.ImagePublicAccessCommands{Store: store, Lock: application.GatewayProjectionLock{Path: layout.GatewayProjectionLock, ExpectedOwnerUID: 0, IPCGID: id.IPCGID}}
	domainHandler := &corehttp.ImagePublicAccessHandler{Commands: domainCommands, Store: store, Auth: authService, Config: corehttp.LocalAuthRouteConfig, Available: func(ctx context.Context) error {
		if !gatewayReady.Load() {
			return errors.New("gateway unavailable")
		}
		return store.ImagePublicAccessSchemaReady(ctx)
	}}
	imageDeliveryHandler := &corehttp.ImageDeliveryHandler{
		Domain:      domainHandler,
		Observation: imageObservationHandler,
		Metrics:     imageMetricsHandler,
		Service:     imageDeliveryService,
		Store:       store,
		Auth:        authService,
		Config:      corehttp.LocalAuthRouteConfig,
	}

	// The source client is shared: the image worker streams built archives from
	// it into the container runtime, and the HTTP source service reports on it.
	var sourceMu sync.RWMutex
	var sourceClient *sourcebuildexecution.Client
	currentSource := func() *sourcebuildexecution.Client {
		sourceMu.RLock()
		defer sourceMu.RUnlock()
		return sourceClient
	}
	openBuiltArchive := func(ctx context.Context, fact appcontracts.SourceBuiltArtifactFact) (io.ReadCloser, error) {
		client := currentSource()
		if client == nil {
			return nil, errors.New("source build unavailable")
		}
		return client.OpenBuiltOCI(ctx, fact)
	}
	_, sourcePolicyDigest, err := buildnetwork.ParsePolicy(buildnetwork.CanonicalPolicy())
	if err != nil {
		return errors.New("trusted source build policy unavailable")
	}
	sourceService := &application.SourceBuildService{Store: store, RunStore: store, ExportArchive: func(ctx context.Context, fact appcontracts.SourceBuiltArtifactFact) (*sourcebuildexecution.BuiltOCIReader, error) {
		reader, err := openBuiltArchive(ctx, fact)
		if err != nil {
			return nil, err
		}
		built, ok := reader.(*sourcebuildexecution.BuiltOCIReader)
		if !ok {
			_ = reader.Close()
			return nil, errors.New("source stream type unavailable")
		}
		return built, nil
	}, Policy: appcontracts.SourceBuildPolicyFact{NetworkMode: "controlled_egress_v1", WorkerPolicyDigest: sourcePolicyDigest}, Available: func(ctx context.Context) error {
		client := currentSource()
		if client == nil {
			return errors.New("source build unavailable")
		}
		return client.CheckReady(ctx)
	}}
	sourceHandler := &corehttp.SourceBuildHandler{Service: sourceService, Auth: authService, Config: corehttp.LocalAuthRouteConfig}

	server := newCoreServer(coreServerConfig{
		ExpectedHost:         cfg.listenAddr,
		Store:                store,
		AuthService:          authService,
		AuthHandler:          authHandler,
		SetupHandler:         setupHandler,
		StaticHandler:        staticHandler,
		Sampler:              sampler,
		ImageDeliveryHandler: imageDeliveryHandler,
		Executor:             executorStatus{container: &containerReady, source: &sourceReady, gateway: &gatewayReady},
	})
	listener, err := net.Listen("tcp", cfg.listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.listenAddr, err)
	}
	defer listener.Close()

	backgroundCtx, cancelBackground := context.WithCancel(context.Background())
	defer cancelBackground()
	sampler.Start(backgroundCtx)
	metricsDone := metricSampler.Start(backgroundCtx)

	var supervisors []*supervisor
	if !cfg.noExecutor {
		pid := os.Getpid()
		supervisors = []*supervisor{
			superviseContainer(backgroundCtx, store, id, pid, openBuiltArchive, imageObservationHandler, imageMetricsHandler, &containerReady),
			superviseSource(backgroundCtx, store, id, pid, func(c *sourcebuildexecution.Client) {
				sourceMu.Lock()
				sourceClient = c
				sourceMu.Unlock()
			}, &sourceReady),
			superviseGateway(backgroundCtx, store, id, pid, &gatewayReady),
		}
	}

	httpServer := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           withCoreSourceRoutes(server, sourceHandler, cfg.listenAddr),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serverErr := make(chan error, 1)
	go func() {
		if err := httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigChan)
	var triggerErr error
	select {
	case err := <-serverErr:
		triggerErr = fmt.Errorf("http server failed: %w", err)
	case sig := <-sigChan:
		log.Printf("received signal %v, shutting down", sig)
	}

	// Stop accepting requests first, then stop writers, then close the store.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v; forcing close", err)
		_ = httpServer.Close()
		if triggerErr == nil {
			triggerErr = fmt.Errorf("http shutdown: %w", err)
		}
	}
	shutdownCancel()

	cancelBackground()
	for _, s := range supervisors {
		if !s.join(5 * time.Second) {
			closeStore = false
			if triggerErr == nil {
				triggerErr = fmt.Errorf("%s worker did not stop; store remains locked until exit", s.name)
			}
		}
	}
	for name, done := range map[string]<-chan struct{}{"container metrics": metricsDone, "host metrics": sampler.Done()} {
		if done == nil {
			continue
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			closeStore = false
			if triggerErr == nil {
				triggerErr = fmt.Errorf("%s sampler did not stop; store remains locked until exit", name)
			}
		}
	}
	return triggerErr
}

func withCoreSourceRoutes(base http.Handler, source *corehttp.SourceBuildHandler, expectedHost string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == corehttp.SourceBuildAPIBase || strings.HasPrefix(r.URL.Path, corehttp.SourceBuildAPIBase+"/") {
			if !corehttp.ValidateLocalLoopbackRequestWithHost(r, expectedHost) {
				corehttp.WriteJSONError(w, http.StatusForbidden, "access_denied", "local loopback access denied")
				return
			}
			if source != nil && source.Handle(w, r) {
				return
			}
			corehttp.WriteJSONError(w, http.StatusServiceUnavailable, "unavailable", "source-build integration unavailable")
			return
		}
		base.ServeHTTP(w, r)
	})
}

// ---- executor supervision ----

// supervisor keeps one executor-facing worker running while its executor
// socket is healthy, and stops it (joining before returning) when it is not.
type supervisor struct {
	name   string
	done   chan struct{}
	joined atomic.Bool
}

// session is one running connection to an executor subsystem.
type session struct {
	stop func() bool // cancels and joins the worker; false if it did not join in time
}

const (
	superviseInterval = 2 * time.Second
	workerJoinTimeout = 3 * time.Second
)

func supervise(ctx context.Context, name string, ready *atomic.Bool, healthy func(context.Context) error, start func(context.Context) (*session, error)) *supervisor {
	s := &supervisor{name: name, done: make(chan struct{})}
	s.joined.Store(true)
	go func() {
		defer close(s.done)
		var active *session
		stop := func() {
			ready.Store(false)
			if active != nil && !active.stop() {
				s.joined.Store(false)
			}
			active = nil
		}
		defer stop()
		ticker := time.NewTicker(superviseInterval)
		defer ticker.Stop()
		for {
			probe, cancel := context.WithTimeout(ctx, 3*time.Second)
			err := healthy(probe)
			cancel()
			switch {
			case err != nil && active != nil:
				log.Printf("%s: executor unavailable, stopping worker: %v", name, err)
				stop()
				if !s.joined.Load() {
					return
				}
			case err == nil && active == nil:
				next, startErr := start(ctx)
				if startErr != nil {
					log.Printf("%s: start failed: %v", name, startErr)
					break
				}
				active = next
				ready.Store(true)
				log.Printf("%s: connected to executor", name)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return s
}

func (s *supervisor) join(timeout time.Duration) bool {
	select {
	case <-s.done:
		return s.joined.Load()
	case <-time.After(timeout):
		return false
	}
}

// joinWithin waits for done, reporting whether it closed before the timeout.
func joinWithin(done <-chan struct{}, timeout time.Duration) bool {
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func superviseContainer(ctx context.Context, store *sqlite.Store, id layout.Identity, pid int, openBuiltArchive func(context.Context, appcontracts.SourceBuiltArtifactFact) (io.ReadCloser, error), observation *corehttp.ImageObservationHandler, metrics *corehttp.ImageMetricsHandler, ready *atomic.Bool) *supervisor {
	probe, _ := imageexecution.NewClient(imageexecution.ClientConfig{SocketPath: layout.ContainerSocket, PeerUID: id.ExecutorUID, Timeout: 3 * time.Second})
	return supervise(ctx, "container", ready, probe.CheckReady, func(ctx context.Context) (*session, error) {
		authority, err := imageexecution.NewCoreAuthorityServer(imageexecution.CoreAuthorityServerConfig{
			LifecycleStore: store,
			Store:          store,
			SocketPath:     layout.ContainerAuthoritySocket,
			SocketGID:      id.IPCGID,
			ExecutorUID:    id.ExecutorUID,
		})
		if err != nil {
			return nil, err
		}
		client, err := imageexecution.NewClient(imageexecution.ClientConfig{SocketPath: layout.ContainerSocket, PeerUID: id.ExecutorUID, Timeout: 2 * time.Minute})
		if err != nil {
			_ = authority.Close()
			return nil, err
		}
		worker, err := application.NewImageExecutionWorker(application.ImageExecutionWorkerConfig{
			WorkerID:             fmt.Sprintf("core-image-worker-%d", pid),
			PollInterval:         500 * time.Millisecond,
			LeaseDuration:        2 * time.Minute,
			MaxAttempts:          3,
			Client:               client,
			BuiltContainerClient: client,
			OpenBuiltArchive:     openBuiltArchive,
			LifecycleClient:      client,
			LifecycleStore:       store,
			Store:                store,
			TaskRepo:             store,
		})
		if err != nil {
			_ = authority.Close()
			return nil, err
		}
		workerCtx, cancel := context.WithCancel(ctx)
		observation.SetClient(client)
		metrics.SetClient(client)
		worker.Start(workerCtx)
		return &session{stop: func() bool {
			observation.SetClient(nil)
			metrics.SetClient(nil)
			cancel()
			joined := joinWithin(worker.Done(), workerJoinTimeout)
			_ = authority.Close()
			return joined
		}}, nil
	})
}

func superviseSource(ctx context.Context, store *sqlite.Store, id layout.Identity, pid int, publish func(*sourcebuildexecution.Client), ready *atomic.Bool) *supervisor {
	probe, _ := sourcebuildexecution.NewClient(sourcebuildexecution.ClientConfig{SocketPath: layout.SourceSocket, PeerUID: id.ExecutorUID})
	healthy := func(ctx context.Context) error {
		if err := store.SourceBuildSchemaReady(ctx); err != nil {
			return err
		}
		return probe.CheckReady(ctx)
	}
	return supervise(ctx, "source build", ready, healthy, func(ctx context.Context) (*session, error) {
		authorityImpl, err := application.NewCoreSourceBuildAuthority(store)
		if err != nil {
			return nil, err
		}
		authority, err := sourcebuildexecution.NewAuthorityServer(sourcebuildexecution.ServerConfig{SocketPath: layout.SourceAuthoritySocket, SocketGID: id.IPCGID, PeerUID: id.ExecutorUID}, authorityImpl)
		if err != nil {
			return nil, err
		}
		client, err := sourcebuildexecution.NewClient(sourcebuildexecution.ClientConfig{SocketPath: layout.SourceSocket, PeerUID: id.ExecutorUID})
		if err != nil {
			_ = authority.Close()
			return nil, err
		}
		worker, err := application.NewSourceBuildExecutionWorker(application.SourceBuildExecutionWorkerConfig{WorkerID: fmt.Sprintf("core-source-worker-%d", pid), Store: store, TaskRepo: store, Client: client})
		if err != nil {
			_ = authority.Close()
			return nil, err
		}
		workerCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		publish(client)
		go func() {
			defer close(done)
			poll := time.NewTicker(500 * time.Millisecond)
			defer poll.Stop()
			for {
				select {
				case <-workerCtx.Done():
					return
				case <-poll.C:
					if _, err := worker.PollOnce(workerCtx); err != nil && workerCtx.Err() == nil {
						log.Printf("source build task requires reconciliation: %v", err)
					}
				}
			}
		}()
		return &session{stop: func() bool {
			publish(nil)
			cancel()
			joined := joinWithin(done, workerJoinTimeout)
			_ = authority.Close()
			return joined
		}}, nil
	})
}

func superviseGateway(ctx context.Context, store *sqlite.Store, id layout.Identity, pid int, ready *atomic.Bool) *supervisor {
	probe := peer.NewClient(layout.GatewaySocket, id.ExecutorUID, 3*time.Second)
	healthy := func(ctx context.Context) error {
		if err := store.ImagePublicAccessSchemaReady(ctx); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v1/gateway/health", nil)
		if err != nil {
			return err
		}
		response, body, err := probe.Do(req)
		if err != nil {
			return err
		}
		if response.StatusCode != http.StatusOK || string(body) != `{"interface":"gateway-execution-v1"}` {
			return errors.New("gateway execution socket is not ready")
		}
		return nil
	}
	return supervise(ctx, "gateway", ready, healthy, func(ctx context.Context) (*session, error) {
		lock := application.GatewayProjectionLock{Path: layout.GatewayProjectionLock, ExpectedOwnerUID: 0, IPCGID: id.IPCGID}
		lockCtx, cancelLock := context.WithTimeout(ctx, time.Second)
		lockErr := lock.WithLock(lockCtx, func(context.Context) error { return nil })
		cancelLock()
		if lockErr != nil {
			return nil, fmt.Errorf("gateway projection lock: %w", lockErr)
		}
		authority, err := gatewayexecution.NewAuthorityServer(gatewayexecution.ServerConfig{SocketPath: layout.GatewayAuthoritySocket, SocketGID: id.IPCGID, PeerUID: id.ExecutorUID}, store)
		if err != nil {
			return nil, err
		}
		client, err := gatewayexecution.NewClient(gatewayexecution.ClientConfig{SocketPath: layout.GatewaySocket, PeerUID: id.ExecutorUID})
		if err != nil {
			_ = authority.Close()
			return nil, err
		}
		worker := &application.ImagePublicAccessWorker{Store: store, Tasks: store, Gateway: client, WorkerID: fmt.Sprintf("core-domain-worker-%d", pid), LeaseDuration: 2 * time.Minute, PollInterval: 500 * time.Millisecond}
		workerCtx, cancel := context.WithCancel(ctx)
		done := worker.Start(workerCtx)
		return &session{stop: func() bool {
			cancel()
			joined := joinWithin(done, workerJoinTimeout)
			_ = authority.Close()
			return joined
		}}, nil
	})
}
