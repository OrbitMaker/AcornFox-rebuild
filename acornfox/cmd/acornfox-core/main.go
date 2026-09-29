package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
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
	"github.com/acornfox/acornfox/internal/corelaunch"
	"github.com/acornfox/acornfox/internal/gatewayexecution"
	"github.com/acornfox/acornfox/internal/hosthelper"
	"github.com/acornfox/acornfox/internal/hostmetrics"
	"github.com/acornfox/acornfox/internal/imageexecution"
	"github.com/acornfox/acornfox/internal/install"
	"github.com/acornfox/acornfox/internal/localpeer"
	"github.com/acornfox/acornfox/internal/packmanager"
	"github.com/acornfox/acornfox/internal/persistence/sqlite"
	"github.com/acornfox/acornfox/internal/providers/registryhttp"
	"github.com/acornfox/acornfox/internal/sourcebuildexecution"
)

type config struct {
	dataDir              string
	listenAddr           string
	origin               string
	credentialsDir       string
	webRoot              string
	dbName               string
	packConfigPath       string
	containerBindingPath string
	socketGID            uint32
	launchTicketFD       uint64
	launchSignalFD       uint64
}

func parseConfig(args []string) (config, error) {
	fs := flag.NewFlagSet("acornfox-core", flag.ContinueOnError)

	var cfg config
	fs.StringVar(&cfg.dataDir, "data-dir", os.Getenv("ACORNFOX_DATA_DIR"), "Path to private absolute SQLite data directory (required)")
	fs.StringVar(&cfg.listenAddr, "listen", "127.0.0.1:8080", "Loopback HTTP listen address (e.g. 127.0.0.1:8080)")
	fs.StringVar(&cfg.origin, "origin", "", "Matching loopback origin (default http://<listen>)")
	fs.StringVar(&cfg.credentialsDir, "credentials-dir", os.Getenv("CREDENTIALS_DIRECTORY"), "Directory containing secure systemd credentials")
	fs.StringVar(&cfg.webRoot, "web-root", "", "Optional directory containing static core web assets")
	fs.StringVar(&cfg.dbName, "db-name", "acornfox.db", "Database file name")
	fs.StringVar(&cfg.packConfigPath, "pack-config", os.Getenv("ACORNFOX_PACK_CONFIG"), "Path to protected pack runtime config JSON (/etc/acornfox/pack-runtime.json)")
	fs.StringVar(&cfg.containerBindingPath, "container-binding", os.Getenv("ACORNFOX_CONTAINER_BINDING"), "Path to root-protected container runtime peer binding JSON (/run/acornfox/runtime-binding.json)")
	socketGID := fs.Uint64("socket-gid", 0, "Optional dedicated IPC group ID for peer sockets; 0 keeps legacy mode and nonzero requires publisher-prepared parents")
	fs.Uint64Var(&cfg.launchTicketFD, "native-launch-ticket-fd", 0, "Root-provided Native launch ticket descriptor")
	fs.Uint64Var(&cfg.launchSignalFD, "native-launch-signal-fd", 0, "Root-provided Native launch readiness descriptor")

	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if fs.NArg() != 0 {
		return config{}, fmt.Errorf("unexpected core argument %q", fs.Arg(0))
	}
	if *socketGID > math.MaxUint32 {
		return config{}, errors.New("socket-gid exceeds uint32 range")
	}
	cfg.socketGID = uint32(*socketGID)

	cfg.containerBindingPath = strings.TrimSpace(cfg.containerBindingPath)
	if cfg.containerBindingPath != "" {
		cfg.containerBindingPath = filepath.Clean(cfg.containerBindingPath)
	}
	if cfg.socketGID != 0 && cfg.containerBindingPath == "" {
		return config{}, errors.New("socket-gid requires a protected runtime binding")
	}

	// 1. Validate dataDir: must be explicit, private, absolute, non-empty
	cfg.dataDir = strings.TrimSpace(cfg.dataDir)
	if cfg.dataDir == "" || cfg.dataDir == ":memory:" {
		return config{}, errors.New("data directory (-data-dir or ACORNFOX_DATA_DIR) is required")
	}
	cleanData := filepath.Clean(cfg.dataDir)
	if !filepath.IsAbs(cleanData) {
		return config{}, fmt.Errorf("data directory %q must be an absolute path", cfg.dataDir)
	}
	cfg.dataDir = cleanData
	if cfg.dataDir == install.UnifiedCoreDataDir {
		if cfg.launchTicketFD != 3 || cfg.launchSignalFD != 4 || cfg.dbName != install.UnifiedDefaultDBName {
			return config{}, errors.New("unified Native Core requires a root launch ticket")
		}
	} else if cfg.launchTicketFD != 0 || cfg.launchSignalFD != 0 {
		return config{}, errors.New("Native launch ticket is restricted to the unified Core data directory")
	}

	// 2. Validate listenAddr: must bind to an explicit loopback IP only (rejects hostnames including localhost)
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

	// 3. Validate origin and enforce exact host+port agreement with listen address
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

func run(args []string) (runErr error) {
	if len(args) > 0 {
		if args[0] == "native-schema" {
			return writeCompiledNativeSchema(os.Stdout, args[1:])
		}
		if !strings.HasPrefix(args[0], "-") {
			return fmt.Errorf("unknown core command %q", args[0])
		}
	}
	cfg, err := parseConfig(args)
	if err != nil {
		return err
	}
	var reservedGeneration int64
	if cfg.launchTicketFD != 0 {
		ticket, err := corelaunch.ReadInherited(uintptr(cfg.launchTicketFD), uintptr(cfg.launchSignalFD), cfg.dataDir)
		if err != nil {
			return fmt.Errorf("validate Native Core launch ticket: %w", err)
		}
		reservedGeneration = ticket.Generation
	}

	// Open SQLite Store with strict production semantics.
	// Store.Close is solely owned by defer at the end of run, ensuring clean lock release
	// on all return paths after all HTTP handlers and listeners have stopped.
	store, err := sqlite.Open(sqlite.Config{
		DataDirectory:    cfg.dataDir,
		DBName:           cfg.dbName,
		LaunchGeneration: reservedGeneration,
	})
	if err != nil {
		return fmt.Errorf("open sqlite store: %w", err)
	}
	closeStore := true
	defer func() {
		if closeStore {
			if closeErr := store.Close(); closeErr != nil && runErr == nil {
				runErr = fmt.Errorf("close sqlite store: %w", closeErr)
			}
		}
	}()

	// Initialize local auth service
	authService, err := auth.NewLocalService(auth.Config{
		Store:  store,
		Origin: cfg.origin,
	})
	if err != nil {
		return fmt.Errorf("init auth service: %w", err)
	}
	authHandler := &corehttp.AuthHTTPHandler{Service: authService}

	// Check bootstrap requirement from actual store
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

	// For a fresh store, verify setup service state is uninitialized; otherwise refuse startup clearly
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

	// Static core assets handler (optional)
	staticHandler, err := newStaticCoreHandler(cfg.webRoot, cfg.dataDir)
	if err != nil {
		return fmt.Errorf("configure static core assets: %w", err)
	}
	if staticHandler != nil {
		defer staticHandler.Close()
	}

	// Protected pack runtime configuration
	packCfg, err := loadProtectedPackConfig(cfg.packConfigPath)
	if err != nil {
		return fmt.Errorf("load protected pack configuration: %w", err)
	}

	var installWorker *packmanager.InstallWorker
	if packCfg.Enabled {
		gen := store.CoreGeneration()
		workerConfig := packmanager.InstallWorkerConfig{
			WorkerID:         fmt.Sprintf("core-worker-%d", os.Getpid()),
			PollInterval:     300 * time.Millisecond,
			LeaseDuration:    2 * time.Minute,
			StagingDir:       packCfg.StagingDir,
			PublishedDir:     packCfg.PublishedDir,
			StateDir:         packCfg.StateDir,
			RunDir:           packCfg.RunDir,
			CoreUID:          packCfg.CoreUID,
			CoreGID:          packCfg.CoreGID,
			CoreGeneration:   gen,
			HelperSocketPath: packCfg.HelperSocketPath,
			Policies:         packCfg.Publishers,
		}
		worker, err := packmanager.NewInstallWorker(store, workerConfig)
		if err != nil {
			return fmt.Errorf("create install worker: %w", err)
		}
		installWorker = worker
	}

	sampler := hostmetrics.NewSampler(hostmetrics.Config{})

	// Initialize Native immutable image delivery provider and handler
	registryProvider, err := registryhttp.New(registryhttp.Config{})
	if err != nil {
		return fmt.Errorf("create registry metadata provider: %w", err)
	}
	registryAdapter := &application.RegistryMetadataAdapter{Provider: registryProvider}
	imageDeliveryService := application.NewImageDeliveryService(registryAdapter)
	imageObservationHandler := &corehttp.ImageObservationHandler{Store: store, Auth: authService, Config: corehttp.LocalAuthRouteConfig}
	metricHistory := containermetrics.NewHistory(time.Now())
	metricSampler := &containermetrics.Sampler{Store: store, History: metricHistory}
	imageMetricsHandler := &corehttp.ImageMetricsHandler{Store: store, Auth: authService, Config: corehttp.LocalAuthRouteConfig, History: metricHistory, Sampler: metricSampler}
	var gatewayReady atomic.Bool
	domainCommands := &application.ImagePublicAccessCommands{Store: store, Lock: application.GatewayProjectionLock{Path: application.GatewayProjectionLockPath, ExpectedOwnerUID: 0, IPCGID: cfg.socketGID}}
	domainHandler := &corehttp.ImagePublicAccessHandler{Commands: domainCommands, Store: store, Auth: authService, Config: corehttp.LocalAuthRouteConfig, Available: func(ctx context.Context) error {
		if !gatewayReady.Load() {
			return errors.New("Gateway peer unavailable")
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

	server := newCoreServer(coreServerConfig{
		ExpectedHost:         cfg.listenAddr,
		Store:                store,
		AuthService:          authService,
		AuthHandler:          authHandler,
		SetupHandler:         setupHandler,
		StaticHandler:        staticHandler,
		Sampler:              sampler,
		ImageDeliveryHandler: imageDeliveryHandler,
		PackConfig:           packCfg,
		AvailabilityProvider: installWorker,
	})

	listener, err := net.Listen("tcp", cfg.listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.listenAddr, err)
	}
	defer listener.Close()

	imageWorkerCtx, cancelImageWorker := context.WithCancel(context.Background())
	defer cancelImageWorker()

	imageWorkerDone := make(chan struct{})
	var imageWorker *application.ImageExecutionWorker
	var authorityServer *imageexecution.CoreAuthorityServer
	var imageMu sync.Mutex
	var sourceMu sync.RWMutex
	var sourceClient *sourcebuildexecution.Client
	openBuiltArchive := func(ctx context.Context, fact appcontracts.SourceBuiltArtifactFact) (io.ReadCloser, error) {
		sourceMu.RLock()
		client := sourceClient
		sourceMu.RUnlock()
		if client == nil {
			return nil, errors.New("source peer unavailable")
		}
		return client.OpenBuiltOCI(ctx, fact)
	}

	if cfg.containerBindingPath != "" {
		go func() {
			defer close(imageWorkerDone)
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()

			myPID := int32(os.Getpid())
			myUID := uint32(os.Getuid())

			for {
				select {
				case <-imageWorkerCtx.Done():
					return
				case <-ticker.C:
					binding, err := localpeer.LoadProtectedRuntimePeerBinding(cfg.containerBindingPath)
					if err != nil || binding == nil {
						continue
					}

					// Verify self identity matches bound Core tuple
					if myUID != binding.CoreUID || myPID != binding.CorePID {
						continue
					}
					if err := localpeer.VerifyProcessIdentity(myPID, myUID, binding.CoreExeSHA, binding.CoreStartTime); err != nil {
						continue
					}

					// Verify counterpart container process via root helper attestation bridge
					helperClient := hosthelper.NewClient(hosthelper.DefaultHelperSocketPath, 5*time.Second)
					if err := imageexecution.VerifyCounterpartPeerViaHelper(imageWorkerCtx, helperClient, "container", binding.ContainerPID, binding.ContainerUID, binding); err != nil {
						continue
					}

					// Install authority server, client, and worker once
					imageMu.Lock()
					if imageWorker != nil {
						imageMu.Unlock()
						return
					}

					as, err := imageexecution.NewCoreAuthorityServer(imageexecution.CoreAuthorityServerConfig{
						LifecycleStore:       store,
						Store:                store,
						SocketPath:           binding.AuthoritySocket,
						SocketGID:            cfg.socketGID,
						ExpectedContainerUID: binding.ContainerUID,
						ExpectedContainerPID: binding.ContainerPID,
						ContainerPeerValidator: func(pid int32, uid uint32) error {
							return imageexecution.VerifyCounterpartPeerViaHelper(context.Background(), helperClient, "container", pid, uid, binding)
						},
					})
					if err != nil {
						imageMu.Unlock()
						log.Printf("start core authority server: %v", err)
						continue
					}
					authorityServer = as

					imgClient, err := imageexecution.NewClient(imageexecution.ClientConfig{
						SocketPath:  binding.ContainerSocket,
						ExpectedPID: binding.ContainerPID,
						ExpectedUID: binding.ContainerUID,
						PeerValidator: func(pid int32, uid uint32) error {
							return imageexecution.VerifyCounterpartPeerViaHelper(context.Background(), helperClient, "container", pid, uid, binding)
						},
						Timeout: 2 * time.Minute,
					})
					if err != nil {
						authorityServer.Close()
						authorityServer = nil
						imageMu.Unlock()
						log.Printf("create image execution client: %v", err)
						continue
					}

					if err := imgClient.CheckReady(imageWorkerCtx); err != nil {
						authorityServer.Close()
						authorityServer = nil
						imageMu.Unlock()
						log.Printf("container socket not yet responsive: %v; waiting", err)
						continue
					}

					imageObservationHandler.SetClient(imgClient)
					imageMetricsHandler.SetClient(imgClient)

					iw, err := application.NewImageExecutionWorker(application.ImageExecutionWorkerConfig{
						WorkerID:             fmt.Sprintf("core-image-worker-%d", myPID),
						PollInterval:         500 * time.Millisecond,
						LeaseDuration:        2 * time.Minute,
						MaxAttempts:          3,
						AuthoritySocketPath:  binding.AuthoritySocket,
						Client:               imgClient,
						BuiltContainerClient: imgClient,
						OpenBuiltArchive:     openBuiltArchive,
						LifecycleClient:      imgClient,
						LifecycleStore:       store,
						Store:                store,
						TaskRepo:             store,
					})
					if err != nil {
						authorityServer.Close()
						authorityServer = nil
						imageMu.Unlock()
						log.Printf("create image execution worker: %v", err)
						continue
					}

					imageWorker = iw
					imageWorker.Start(imageWorkerCtx)
					imageMu.Unlock()
					log.Printf("core bound to container runtime (core_pid=%d, container_pid=%d)", myPID, binding.ContainerPID)
					return
				}
			}
		}()
	} else {
		close(imageWorkerDone)
	}

	samplingCtx, samplingCancel := context.WithCancel(context.Background())
	defer samplingCancel()
	sampler.Start(samplingCtx)

	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()
	if installWorker != nil {
		installWorker.Start(workerCtx)
	}

	// Source/build has a separate scoped task consumer and attested authority
	// socket. The immutable source receipt must be committed before a user issues
	// the independent build approval POST; no automatic phase chaining exists.
	sourceCtx, cancelSource := context.WithCancel(context.Background())
	sourceDone := make(chan struct{})
	var sourceJoined atomic.Bool
	sourceJoined.Store(true)
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
		sourceMu.RLock()
		client := sourceClient
		sourceMu.RUnlock()
		if client == nil {
			return errors.New("source peer unavailable")
		}
		return client.CheckReady(ctx)
	}}
	sourceHandler := &corehttp.SourceBuildHandler{Service: sourceService, Auth: authService, Config: corehttp.LocalAuthRouteConfig}
	metricsDone := metricSampler.Start(imageWorkerCtx)
	go func() {
		defer close(sourceDone)
		sourceJoined.Store(runCoreSourceBinding(sourceCtx, store, cfg.containerBindingPath, cfg.socketGID, func(client *sourcebuildexecution.Client) { sourceMu.Lock(); sourceClient = client; sourceMu.Unlock() }))
	}()
	gatewayCtx, cancelGateway := context.WithCancel(context.Background())
	gatewayDone := make(chan struct{})
	var gatewayJoined atomic.Bool
	gatewayJoined.Store(true)
	go func() {
		defer close(gatewayDone)
		gatewayJoined.Store(runCoreGatewayBinding(gatewayCtx, store, cfg.containerBindingPath, cfg.socketGID, func(ready bool) { gatewayReady.Store(ready) }))
	}()
	defer func() {
		cancelGateway()
		select {
		case <-gatewayDone:
			if !gatewayJoined.Load() {
				closeStore = false
			}
		case <-time.After(3 * time.Second):
			closeStore = false
		}
	}()
	defer func() {
		cancelSource()
		select {
		case <-sourceDone:
			if !sourceJoined.Load() {
				closeStore = false
			}
		case <-time.After(3 * time.Second):
			closeStore = false
		}
	}()
	httpServer := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           withCoreSourceRoutes(server, sourceHandler, cfg.listenAddr),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      0,
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
		log.Printf("received signal %v, initiating graceful shutdown", sig)
	}

	// Cancel install worker and wait with bound to exit before store close
	workerCancel()
	if installWorker != nil {
		select {
		case <-installWorker.Done():
		case <-time.After(3 * time.Second):
			log.Printf("install worker shutdown timed out")
			if triggerErr == nil {
				triggerErr = errors.New("install worker shutdown timed out")
			}
		}
	}

	cancelSource()
	select {
	case <-sourceDone:
		if !sourceJoined.Load() {
			closeStore = false
			if triggerErr == nil {
				triggerErr = errors.New("source worker could not join; store remains locked")
			}
		}
	case <-time.After(3 * time.Second):
		closeStore = false
		if triggerErr == nil {
			triggerErr = errors.New("source worker shutdown timed out; store remains locked")
		}
	}
	cancelGateway()
	select {
	case <-gatewayDone:
		if !gatewayJoined.Load() {
			closeStore = false
			if triggerErr == nil {
				triggerErr = errors.New("Gateway worker could not join; store remains locked")
			}
		}
	case <-time.After(3 * time.Second):
		closeStore = false
		if triggerErr == nil {
			triggerErr = errors.New("Gateway worker shutdown timed out; store remains locked")
		}
	}
	// Cancel image worker and join late-binding watcher
	cancelImageWorker()
	<-imageWorkerDone
	select {
	case <-metricsDone:
	case <-time.After(3 * time.Second):
		closeStore = false
		if triggerErr == nil {
			triggerErr = errors.New("image metrics sampler shutdown timed out; store remains locked")
		}
	}
	imageMu.Lock()
	activeWorker := imageWorker
	activeAuthServer := authorityServer
	imageMu.Unlock()

	if activeWorker != nil {
		select {
		case <-activeWorker.Done():
		case <-time.After(3 * time.Second):
			log.Printf("image worker shutdown timed out")
			closeStore = false
			if triggerErr == nil {
				triggerErr = errors.New("image worker shutdown timed out; store kept locked until process exit")
			}
		}
	}
	if activeAuthServer != nil {
		_ = activeAuthServer.Close()
	}

	// Cancel sampling and wait with bound for sampler worker to exit before store close
	samplingCancel()
	if done := sampler.Done(); done != nil {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			log.Printf("sampler worker shutdown timed out")
			if triggerErr == nil {
				triggerErr = errors.New("sampler worker shutdown timed out")
			}
		}
	}

	// Bounded graceful shutdown of HTTP server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	shutdownErr := httpServer.Shutdown(shutdownCtx)
	shutdownCancel()

	// If shutdown times out or errors, force Close active HTTP connections before store close
	if shutdownErr != nil {
		log.Printf("graceful shutdown failed: %v; forcing close of active connections", shutdownErr)
		if closeErr := httpServer.Close(); closeErr != nil {
			log.Printf("http server force close error: %v", closeErr)
		}
		if triggerErr == nil {
			triggerErr = fmt.Errorf("http shutdown: %w", shutdownErr)
		}
	}

	return triggerErr
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatalf("acornfox-core: %v", err)
	}
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

// The binding watcher cancels the active scoped consumer before replacing its
// peer. PollOnce uses the existing Store/fences; this is not a second controller.
func runCoreSourceBinding(ctx context.Context, store *sqlite.Store, bindingPath string, socketGID uint32, publish func(*sourcebuildexecution.Client)) (joined bool) {
	joined = true
	if bindingPath == "" {
		return true
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	defer publish(nil)
	var activeDigest string
	var activeCancel context.CancelFunc
	var activeDone chan struct{}
	var authorityServer *sourcebuildexecution.Server
	stop := func() bool {
		publish(nil)
		if activeCancel != nil {
			activeCancel()
			select {
			case <-activeDone:
			case <-time.After(3 * time.Second):
				return false
			}
		}
		if authorityServer != nil {
			authorityServer.Close()
		}
		activeCancel = nil
		activeDone = nil
		authorityServer = nil
		activeDigest = ""
		return true
	}
	defer func() {
		if !stop() {
			joined = false
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return true
		case <-ticker.C:
			b, err := localpeer.LoadProtectedRuntimePeerBinding(bindingPath)
			if err != nil || b == nil || !b.HasSourceBuild() || b.CorePID != int32(os.Getpid()) || b.CoreUID != uint32(os.Getuid()) || localpeer.VerifyProcessIdentity(b.CorePID, b.CoreUID, b.CoreExeSHA, b.CoreStartTime) != nil || store.SourceBuildSchemaReady(ctx) != nil {
				if activeCancel != nil && !stop() {
					return false
				}
				continue
			}
			if activeDigest == b.Digest() {
				continue
			}
			if activeCancel != nil && !stop() {
				return false
			}
			helper := hosthelper.NewClient(hosthelper.DefaultHelperSocketPath, 3*time.Second)
			validator := func(pid int32, uid uint32) error {
				return sourcebuildexecution.VerifySourceBuildPeer(ctx, helper, b, "source-build", pid, uid)
			}
			if validator(b.SourceBuildPID, b.SourceBuildUID) != nil {
				continue
			}
			authority, err := application.NewCoreSourceBuildAuthority(store)
			if err != nil {
				continue
			}
			as, err := sourcebuildexecution.NewAuthorityServer(sourcebuildexecution.ServerConfig{SocketPath: b.SourceBuildAuthoritySocket, SocketGID: socketGID, ExpectedPID: b.SourceBuildPID, ExpectedUID: b.SourceBuildUID, PeerValidator: validator}, authority)
			if err != nil {
				continue
			}
			client, err := sourcebuildexecution.NewClient(sourcebuildexecution.ClientConfig{SocketPath: b.SourceBuildSocket, ExpectedPID: b.SourceBuildPID, ExpectedUID: b.SourceBuildUID, PeerValidator: validator})
			if err != nil {
				as.Close()
				continue
			}
			if client.CheckReady(ctx) != nil {
				as.Close()
				continue
			}
			worker, err := application.NewSourceBuildExecutionWorker(application.SourceBuildExecutionWorkerConfig{WorkerID: fmt.Sprintf("core-source-worker-%d", os.Getpid()), Store: store, TaskRepo: store, Client: client})
			if err != nil {
				as.Close()
				continue
			}
			activeCtx, cancel := context.WithCancel(ctx)
			activeCancel = cancel
			activeDone = make(chan struct{})
			authorityServer = as
			activeDigest = b.Digest()
			publish(client)
			go func(done chan struct{}) {
				defer close(done)
				poll := time.NewTicker(500 * time.Millisecond)
				defer poll.Stop()
				for {
					select {
					case <-activeCtx.Done():
						return
					case <-poll.C:
						if _, err := worker.PollOnce(activeCtx); err != nil && activeCtx.Err() == nil {
							log.Print("source-build task requires reconciliation")
						}
					}
				}
			}(activeDone)
		}
	}
}

func gatewayHealth(ctx context.Context, b *localpeer.RuntimePeerBinding, validate func(int32, uint32) error) error {
	probe, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	client := packmanager.NewUnixHTTPClient(b.GatewaySocket, b.GatewayPID, b.GatewayUID, validate, 3*time.Second)
	req, err := http.NewRequestWithContext(probe, http.MethodGet, "http://unix/v1/gateway/health", nil)
	if err != nil {
		return err
	}
	response, body, err := client.Do(req)
	if err != nil || response.StatusCode != http.StatusOK || string(body) != `{"interface":"gateway-execution-v1"}` {
		return errors.New("attested Gateway execution socket is not ready")
	}
	return nil
}

// runCoreGatewayBinding owns one attested authority socket and scoped worker
// at a time. A changed or lost binding cancels/joins the worker before closing
// authority; failure to join keeps the Store open until process exit.
func runCoreGatewayBinding(ctx context.Context, store *sqlite.Store, bindingPath string, socketGID uint32, publish func(bool)) (joined bool) {
	joined = true
	if bindingPath == "" || socketGID == 0 {
		publish(false)
		return true
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var activeDigest string
	var activeCancel context.CancelFunc
	var activeDone <-chan struct{}
	var authorityServer *gatewayexecution.Server
	stop := func() bool {
		publish(false)
		if activeCancel != nil {
			activeCancel()
			select {
			case <-activeDone:
			case <-time.After(3 * time.Second):
				return false
			}
		}
		if authorityServer != nil {
			_ = authorityServer.Close()
		}
		activeCancel, activeDone, authorityServer, activeDigest = nil, nil, nil, ""
		return true
	}
	defer func() {
		if !stop() {
			joined = false
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return true
		case <-ticker.C:
			b, err := localpeer.LoadProtectedRuntimePeerBinding(bindingPath)
			if err != nil || b == nil || !b.HasGateway() || b.CorePID != int32(os.Getpid()) || b.CoreUID != uint32(os.Getuid()) || localpeer.VerifyProcessIdentity(b.CorePID, b.CoreUID, b.CoreExeSHA, b.CoreStartTime) != nil || store.ImagePublicAccessSchemaReady(ctx) != nil {
				if activeCancel != nil && !stop() {
					return false
				}
				continue
			}
			helper := hosthelper.NewClient(hosthelper.DefaultHelperSocketPath, 3*time.Second)
			validator := func(pid int32, uid uint32) error {
				return gatewayexecution.VerifyGatewayPeer(ctx, helper, b, "gateway", pid, uid)
			}
			if validator(b.GatewayPID, b.GatewayUID) != nil {
				if activeCancel != nil && !stop() {
					return false
				}
				continue
			}
			if activeDigest == b.Digest() {
				continue
			}
			if activeCancel != nil && !stop() {
				return false
			}
			lock := application.GatewayProjectionLock{Path: application.GatewayProjectionLockPath, ExpectedOwnerUID: 0, IPCGID: socketGID}
			lockCtx, cancelLock := context.WithTimeout(ctx, time.Second)
			lockErr := lock.WithLock(lockCtx, func(context.Context) error { return nil })
			cancelLock()
			if lockErr != nil {
				continue
			}
			as, err := gatewayexecution.NewAuthorityServer(gatewayexecution.ServerConfig{SocketPath: b.GatewayAuthoritySocket, SocketGID: socketGID, ExpectedPID: b.GatewayPID, ExpectedUID: b.GatewayUID, PeerValidator: validator}, store)
			if err != nil {
				continue
			}
			client, err := gatewayexecution.NewClient(gatewayexecution.ClientConfig{SocketPath: b.GatewaySocket, ExpectedPID: b.GatewayPID, ExpectedUID: b.GatewayUID, PeerValidator: validator})
			if err != nil || gatewayHealth(ctx, b, validator) != nil {
				_ = as.Close()
				continue
			}
			worker := &application.ImagePublicAccessWorker{Store: store, Tasks: store, Gateway: client, WorkerID: fmt.Sprintf("core-domain-worker-%d", os.Getpid()), LeaseDuration: 2 * time.Minute, PollInterval: 500 * time.Millisecond}
			activeCtx, cancel := context.WithCancel(ctx)
			activeCancel, activeDone, authorityServer, activeDigest = cancel, worker.Start(activeCtx), as, b.Digest()
			publish(true)
		}
	}
}
