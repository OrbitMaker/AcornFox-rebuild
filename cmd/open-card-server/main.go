package main

import (
	"context"
	"encoding/json"
	"errors"
	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/domain"
	"log"
	"net/http"
	stdio "os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/acornfoxcandidate"
	"github.com/open-card/open-card/internal/acornfoxenv"
	aicontext "github.com/open-card/open-card/internal/ai/context"
	ailedger "github.com/open-card/open-card/internal/ai/ledger"
	"github.com/open-card/open-card/internal/ai/orchestrator"
	aiprovider "github.com/open-card/open-card/internal/ai/provider"
	airunner "github.com/open-card/open-card/internal/ai/runner"
	aitools "github.com/open-card/open-card/internal/ai/tools"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/auth"
	"github.com/open-card/open-card/internal/buildnetwork"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/hostmetrics"
	"github.com/open-card/open-card/internal/importers/dockerfile"
	"github.com/open-card/open-card/internal/observability"
	"github.com/open-card/open-card/internal/persistence/postgres"
	"github.com/open-card/open-card/internal/providers/buildkit"
	caddyprovider "github.com/open-card/open-card/internal/providers/caddy"
	"github.com/open-card/open-card/internal/providers/capacity"
	imageprovider "github.com/open-card/open-card/internal/providers/image"
	meterlocal "github.com/open-card/open-card/internal/providers/meter/local"
	registryprovider "github.com/open-card/open-card/internal/providers/registryhttp"
	secretprovider "github.com/open-card/open-card/internal/providers/secret"
	"github.com/open-card/open-card/internal/providers/source"
	"github.com/open-card/open-card/internal/rules"
)

var processIdentity = "legacy"

func main() {
	environment, environmentErr := acornfoxenv.ResolveCurrent(acornfoxenv.ProcessServer, processIdentity)
	if environmentErr != nil {
		log.Fatal(environmentErr)
	}
	lifecycleContext, lifecycleCancel := signal.NotifyContext(context.Background(), stdio.Interrupt, syscall.SIGTERM)
	defer lifecycleCancel()
	if len(stdio.Args) > 1 {
		if err := runCandidateValidation(lifecycleContext, stdio.Args[1:], environment); err != nil {
			log.Printf("%s candidate validation: %v", environment.ProductLabel(), err)
			stdio.Exit(1)
		}
		return
	}
	getenv := environment.Get
	if _, err := cleanPublicAccessEnabled(environment.Clean(), getenv(acornfoxenv.M1Enabled) == "true", getenv(acornfoxenv.M3Enabled) == "true", getenv(acornfoxenv.AuthOrigin), getenv(acornfoxenv.PublicRoot)); err != nil {
		log.Fatal("clean public access configuration conflicts")
	}
	address, addressErr := resolveServerListenerAddress(environment)
	if addressErr != nil {
		log.Fatal(addressErr)
	}
	gatewayAddress, gatewayAddressErr := resolveAgentGatewayListenerAddress(environment)
	if gatewayAddressErr != nil {
		log.Fatal(gatewayAddressErr)
	}
	compatibilityMode, compatibilityErr := acornFoxMigrationCompatibilityMode(getenv(acornfoxenv.MigrationCompatibility))
	if compatibilityErr != nil {
		log.Fatal(compatibilityErr)
	}
	server := NewAcornFoxServer()
	server.SetLegacyRoutesEnabled(compatibilityMode)
	var controllerStore *postgres.Store
	databaseURL := getenv(acornfoxenv.DatabaseURL)
	consoleAccessMode := ConsoleAccessMode(getenv(acornfoxenv.ConsoleAccess))
	if consoleAccessMode == "" {
		consoleAccessMode = ConsoleAccessPublicHTTPS
	}
	if consoleAccessMode == ConsoleAccessLocalLoopback && strings.TrimSpace(databaseURL) == "" {
		log.Fatalf("local loopback console requires persistent database: %s is unset", environment.Name(acornfoxenv.DatabaseURL))
	}
	if err := validateFeatureHierarchy(databaseURL != "", getenv(acornfoxenv.M1Enabled) == "true", getenv(acornfoxenv.M2Enabled) == "true", getenv(acornfoxenv.M3Enabled) == "true", getenv(acornfoxenv.M4Enabled) == "true", getenv(acornfoxenv.M4RolloutEnabled) == "true", getenv(acornfoxenv.M5Enabled) == "true", getenv(acornfoxenv.M6Enabled) == "true"); err != nil {
		log.Fatal(err)
	}
	if databaseURL != "" {
		connectContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		store, err := postgres.OpenStore(connectContext, databaseURL)
		cancel()
		if err != nil {
			log.Fatal(err)
		}
		defer func() {
			if err := store.Close(); err != nil {
				log.Printf("close postgres store: %v", err)
			}
		}()
		server = NewAcornFoxServerWithRepository(store)
		server.SetLegacyRoutesEnabled(compatibilityMode)
		server.SetAcornFoxDeploymentStore(store)
		server.SetAcornFoxSourceMetadata(newAcornFoxSourceMetadataHTTPHandler(store))
		server.SetAcornFoxOperation(newAcornFoxOperationHTTPHandler(store))
		server.SetAcornFoxAccessObservation(&AcornFoxAccessObservationHTTPHandler{Store: store})
		controllerStore = store
		server.SetSystemStatusStore(store)
		server.SetApplicationProjectionStore(store)
		server.SetSystemStatusNode(getenv(acornfoxenv.AgentDispatchInstanceID), getenv(acornfoxenv.AgentDispatchNodeID))
		if err := server.SetConsoleAccessMode(consoleAccessMode); err != nil {
			log.Fatalf("invalid console access mode configuration: %v", err)
		}
		origin := strings.TrimSpace(getenv(acornfoxenv.AuthOrigin))
		if origin != "" {
			var authService *auth.Service
			var authErr error
			if consoleAccessMode == ConsoleAccessLocalLoopback {
				authService, authErr = auth.NewLocalService(auth.Config{Store: store, Origin: origin})
			} else {
				authService, authErr = auth.NewService(auth.Config{Store: store, Origin: origin})
			}
			if authErr != nil {
				log.Fatal(authErr)
			}
			server.SetAuth(&AuthHTTPHandler{Service: authService})
			setupHandler, setupErr := NewAcornFoxWebSetupHTTPHandler(store, authService, acornFoxSetupCredential(stdio.Getenv("CREDENTIALS_DIRECTORY")))
			if setupErr != nil {
				log.Fatal("administrator web setup configuration is invalid")
			}
			server.SetAcornFoxWebSetup(setupHandler)
		} else {
			log.Printf("administrator HTTP authentication is not activated; %s is unset", environment.Name(acornfoxenv.AuthOrigin))
		}
		server.SetG3Access(newG3AccessHTTPHandler(store, getenv))
		server.SetG3SourceUpload(newG3SourceUploadHTTPHandler(store, getenv))
		server.AgentGateway().SetEventSink(&controllers.DurableAgentSink{Store: store})
		var acornFoxProjector controllers.AgentEvidenceProjector
		applicationWorker := &controllers.Worker{
			Store: store, Handler: applicationTaskHandler{}, Owner: "control-plane-application",
			Kinds: []string{applicationCreateTaskKind},
		}
		go func() {
			if err := applicationWorker.Run(context.Background()); err != nil {
				log.Printf("application task worker stopped: %v", err)
				server.SetReady(false)
			}
		}()
		if getenv(acornfoxenv.M1Enabled) == "true" {
			uploadRoot := getenv(acornfoxenv.SourceUploadRoot)
			workspaceRoot := getenv(acornfoxenv.SourceWorkspaceRoot)
			buildWorkRoot := getenv(acornfoxenv.BuildWorkRoot)
			for _, path := range []string{uploadRoot, workspaceRoot, buildWorkRoot} {
				if path == "" {
					log.Fatal("M1 source and build roots must be explicitly configured")
				}
				if err := stdio.MkdirAll(path, 0o700); err != nil {
					log.Fatal(err)
				}
			}
			server.SetG3SourceUpload(newG3SourceUploadHTTPHandler(store, getenv))
			logRoot := getenv(acornfoxenv.LogRoot)
			if logRoot == "" {
				logRoot = buildWorkRoot + "/m4-logs"
			}
			logConfig, configErr := m4LogStoreConfig(logRoot, getenv, environment)
			if configErr != nil {
				log.Fatal(configErr)
			}
			// Static host roots are known before any log write. Dynamic source
			// provenance is added by the build sink and Agent-event hook below.
			logConfig.Secrets = append(logConfig.Secrets, uploadRoot, workspaceRoot, buildWorkRoot, logRoot)
			acornFoxLogStore, err := observability.NewLogStore(logConfig)
			if err != nil {
				log.Fatal(err)
			}
			if err := m4ReconcileOrdinaryLogIndexes(context.Background(), store, acornFoxLogStore, time.Now().UTC()); err != nil {
				log.Fatal(err)
			}
			redactionRoots := []string{uploadRoot, workspaceRoot, buildWorkRoot, logRoot}
			buildLogSink := buildkit.BuildLogSink(&m4BuildLogSink{store: store, logs: acornFoxLogStore, redactionRoots: redactionRoots})
			acornFoxLogsHandler := newAcornFoxLogsHTTPHandler(store, acornFoxLogStore, uploadRoot, workspaceRoot, buildWorkRoot)
			server.SetAcornFoxLogs(acornFoxLogsHandler)
			acornFoxProjector = &acornFoxLogProjector{store: store, logs: acornFoxLogStore}
			server.AgentGateway().SetEventSink(&controllers.DurableAgentSink{Store: store, Projector: acornFoxProjector, RedactEnvelope: newAcornFoxAgentLogEnvelopeRedactor(store, redactionRoots...)})
			acornFoxLogCollector := &AcornFoxLogCollectionScheduler{Store: store}
			go func() {
				ticker := time.NewTicker(application.AcornFoxLogsCollectionInterval)
				defer ticker.Stop()
				for range ticker.C {
					ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
					if _, err := acornFoxLogCollector.ScheduleOnce(ctx, acornFoxLogCollectorMaximumPerTick); err != nil {
						log.Printf("AcornFox runtime log collection failed: %v", err)
					}
					cancel()
				}
			}()
			rawImageStore, err := imageprovider.New(imageprovider.Config{Root: getenv(acornfoxenv.OCIStoreRoot)})
			if err != nil {
				log.Fatal(err)
			}
			imageStore, err := newAcornFoxGatedImageStore(rawImageStore, store.DB())
			if err != nil {
				log.Fatal("image mutation gate unavailable")
			}
			capacityConfig := capacity.Config{DiskPath: buildWorkRoot, BuildReserve: contracts.ResourceLimits{CPUMillis: 250, MemoryBytes: 256 << 20, DiskBytes: 512 << 20}, RuntimeReserve: contracts.ResourceLimits{CPUMillis: 250, MemoryBytes: 256 << 20, DiskBytes: 512 << 20}}
			if value := getenv(acornfoxenv.CapacityFixedHostPort); value != "" {
				parsed, parseErr := strconv.Atoi(value)
				if parseErr != nil || parsed < 1 || parsed > 65535 {
					log.Fatal("invalid fixed capacity host port")
				}
				capacityConfig.PortAllocator = capacity.FixedPortAllocator{Port: parsed}
			}
			capacityProvider, err := capacity.New(capacityConfig)
			if err != nil {
				log.Fatal(err)
			}
			secretProvider, err := secretprovider.New(secretprovider.Config{Root: getenv(acornfoxenv.SecretRoot), MaterialRoot: getenv(acornfoxenv.SecretMaterialRoot), MasterKeyPath: getenv(acornfoxenv.SecretMasterKey), MaterialTTL: 2 * time.Minute})
			if err != nil {
				log.Fatal(err)
			}
			discoveryCursorKey, err := secretprovider.DeriveExistingContextKey(getenv(acornfoxenv.SecretMasterKey), "acornfox-discovery-cursor-v1")
			if err != nil {
				log.Fatal("AcornFox discovery cursor signing key is unavailable")
			}
			discoveryHandler := newAcornFoxDiscoveryHTTPHandler(store, discoveryCursorKey)
			server.SetAcornFoxDiscovery(discoveryHandler)
			defer discoveryHandler.Close()
			defer secretprovider.ZeroContextKey(&discoveryCursorKey)
			workspaceCapacityBytes, workspaceCapacityEntries, workspaceOperationalReserveBytes, workspaceOperationalReserveEntries, capacityErr := sourceWorkspaceCapacityConfig(getenv)
			if capacityErr != nil {
				log.Fatal("invalid source workspace capacity configuration")
			}
			sourceProvider, err := source.New(source.Config{UploadRoot: uploadRoot, WorkspaceRoot: workspaceRoot, WorkspaceCapacityBytes: workspaceCapacityBytes, WorkspaceCapacityEntries: workspaceCapacityEntries, WorkspaceOperationalReserveBytes: workspaceOperationalReserveBytes, WorkspaceOperationalReserveEntries: workspaceOperationalReserveEntries, GitResolverEndpoints: sourceGitResolverEndpoints(getenv(acornfoxenv.SourceGitResolvers))})
			if err != nil {
				log.Fatal(err)
			}
			server.controller.SetSourcePreparer(sourceProvider)
			if recoverErr := store.RecoverAcornFoxSourceUpdates(lifecycleContext, time.Now().UTC()); recoverErr != nil {
				log.Fatal("source update recovery unavailable")
			}
			server.SetAcornFoxSourceUpdate(newAcornFoxSourceUpdateHTTPHandler(&application.AcornFoxSourceUpdateService{Store: store, Preparer: sourceProvider}))
			buildConfig := buildkit.Config{Command: getenv(acornfoxenv.BuildkitCommand), Builder: getenv(acornfoxenv.BuildkitWorker), Address: getenv(acornfoxenv.BuildkitAddress), WorkspaceRoot: workspaceRoot, WorkRoot: buildWorkRoot, StaticServerBinary: getenv(acornfoxenv.StaticServerBinary), ImageStore: imageStore, Capacity: capacityProvider, SecretResolver: secretProvider, LogSink: buildLogSink, RequireLogSink: true}
			buildNetwork := contracts.NetworkPolicy{}
			if environment.Clean() {
				// The compiled policy is the requested contract. The privileged
				// attestor checks the installed file and kernel state per build;
				// a missing worker blocks builds without taking down diagnostics.
				policy := buildnetwork.CanonicalPolicy()
				_, digest, policyErr := buildnetwork.ParsePolicy(policy)
				if policyErr != nil {
					log.Fatal("invalid compiled AcornFox build policy")
				}
				buildConfig.ProductionNetworkPolicyRaw = policy
				buildConfig.WorkerPolicyAttestor = buildnetwork.Client{}
				buildNetwork = contracts.NetworkPolicy{Mode: contracts.NetworkModeControlledEgressV1, WorkerPolicyDigest: digest}
			}
			buildProvider, err := buildkit.New(buildConfig)
			if err != nil {
				log.Fatal(err)
			}
			releaseController := &controllers.ReleaseController{Store: store, Source: sourceProvider, Build: buildProvider, Capacity: capacityProvider, StaticRuntimeDigest: getenv(acornfoxenv.StaticRuntimeDigest)}
			server.SetReleaseController(releaseController)
			server.SetApplicationPublisher(store, releaseController)
			acornFoxStore := acornFoxPostgresAdapter{store: store}
			server.SetAcornFoxDockerfileImporter(dockerfile.New())
			deliveryService := &application.AcornFoxDeliveryService{
				RuntimeConfigurationGate: func(context.Context) error {
					instanceID, nodeID := getenv(acornfoxenv.AgentDispatchInstanceID), getenv(acornfoxenv.AgentDispatchNodeID)
					gateway := server.AgentGateway()
					if gateway.NodeStatus(instanceID, nodeID, time.Now()) == "online" {
						for _, capability := range gateway.NodeCapabilities(instanceID, nodeID) {
							if capability == v1.AgentCapabilityAcornFoxRuntimeConfig {
								return nil
							}
						}
					}
					return domain.NewError(domain.ErrUnsupportedCapability, "online agent with runtime configuration support is required")
				},
				Idempotency: acornFoxStore, Sources: acornFoxStore, Importer: dockerfile.New(), Builds: acornFoxStore,
				Tasks: acornFoxStore, Runtime: acornFoxStore, Observer: acornFoxStore, Builder: buildProvider, Capacity: capacityProvider,
				Config: application.AcornFoxDeliveryConfig{TargetRepository: "acornfox.local/apps", StorageKeyPrefix: "acornfox-builds", BuildNetwork: buildNetwork},
			}
			server.SetAcornFoxDeliveryCommand(acornFoxHTTPCommand{service: deliveryService})
			candidateHandler := &AcornFoxFixCandidateHTTPHandler{Store: store}
			candidateLeader, candidateErr := store.AcquireAcornFoxFixCandidateLeader(lifecycleContext)
			if errors.Is(candidateErr, postgres.ErrAcornFoxFixCandidateLeaderHeld) {
				log.Printf("fix candidate execution is owned by another server; this instance serves read-only candidate facts")
			} else if candidateErr != nil {
				log.Fatal("fix candidate execution leader unavailable")
			} else {
				candidateLeaderContext, candidateLeaderCancel := context.WithCancel(lifecycleContext)
				candidateLeaderMonitor := make(chan error, 1)
				go func() {
					err := candidateLeader.Monitor(candidateLeaderContext, acornFoxFixCandidateLeaderProbe)
					if err != nil {
						log.Printf("fix candidate execution leader lost: %v", err)
						candidateLeaderCancel()
					}
					candidateLeaderMonitor <- err
				}()
				settle := time.NewTimer(acornFoxFixCandidateLeaderSettle)
				select {
				case <-settle.C:
				case <-candidateLeaderContext.Done():
					if !settle.Stop() {
						select {
						case <-settle.C:
						default:
						}
					}
					log.Fatal("fix candidate execution leader was lost during startup")
				}
				if candidateErr := acornfoxcandidate.RetireLegacyWorkspace(workspaceRoot); candidateErr != nil {
					log.Fatal("legacy fix candidate workspace retirement failed")
				}
				candidateSourceRoot := filepath.Join(buildWorkRoot, "candidate-sources")
				candidateBuildRoot := filepath.Join(buildWorkRoot, "candidate-builds")
				for _, root := range []string{candidateSourceRoot, candidateBuildRoot} {
					if candidateErr := prepareAcornFoxCandidateWorkRoot(root); candidateErr != nil {
						log.Fatal("fix candidate work root unavailable")
					}
				}
				if candidateErr := recoverAcornFoxCandidateBuildRoot(candidateBuildRoot); candidateErr != nil {
					log.Fatal("fix candidate build recovery failed")
				}
				candidateWorkspace, candidateErr := acornfoxcandidate.NewManager(workspaceRoot, candidateSourceRoot)
				if candidateErr != nil {
					log.Fatal("fix candidate workspace unavailable")
				}
				candidateStore, candidateErr := postgres.NewAcornFoxFixCandidateFencedStore(store, candidateLeader)
				if candidateErr != nil {
					log.Fatal("fix candidate fenced store unavailable")
				}
				if candidateErr := candidateStore.RecoverAcornFoxFixCandidates(candidateLeaderContext, time.Now().UTC()); candidateErr != nil {
					log.Fatal("fix candidate recovery unavailable")
				}
				candidateLogRoot := filepath.Join(buildWorkRoot, "candidate-logs")
				if candidateErr := prepareAcornFoxCandidateWorkRoot(candidateLogRoot); candidateErr != nil {
					log.Fatal("fix candidate log root unavailable")
				}
				candidateLogStore, candidateErr := observability.NewLogStore(observability.LogStoreConfig{RootDir: candidateLogRoot, MaxFileBytes: acornFoxCandidateBuildLogMaxBytes, MaxTotalBytes: 32 << 20, MaxBuildFiles: 32, MaxFilesPerStream: 4, Secrets: append(append([]string(nil), redactionRoots...), candidateLogRoot)})
				if candidateErr != nil {
					log.Fatal("fix candidate log store unavailable")
				}
				candidateBuildConfig := buildConfig
				candidateBuildConfig.WorkspaceRoot = candidateSourceRoot
				candidateBuildConfig.WorkRoot = candidateBuildRoot
				candidateImageRoot := filepath.Join(buildWorkRoot, "candidate-images")
				candidateImageStore, candidateErr := newAcornFoxCandidateImageStore(imageStore, postgresAcornFoxCandidateImageGuard{store: store}, candidateImageRoot)
				if candidateErr != nil {
					log.Fatal("fix candidate image tracker unavailable")
				}
				candidateBuildConfig.ImageStore = candidateImageStore
				candidateBuildConfig.LogSink = &acornFoxCandidateBuildLogSink{logs: candidateLogStore, redactionRoots: append(append([]string(nil), redactionRoots...), candidateLogRoot)}
				candidateBuildProvider, candidateErr := buildkit.New(candidateBuildConfig)
				if candidateErr != nil {
					log.Fatal("fix candidate build provider unavailable")
				}
				candidateService := &application.AcornFoxFixCandidateService{
					Store: candidateStore, Workspace: candidateWorkspace,
					Builder: &application.AcornFoxFixCandidateBuilder{Builder: candidateBuildProvider, Capacity: capacityProvider, Network: buildNetwork, TargetRepository: "acornfox.local/apps", StorageKeyPrefix: "acornfox-candidate"},
					Runtime: &acornFoxFixCandidateRuntimeDispatcher{store: store, images: candidateImageStore}, Publisher: deliveryService,
				}
				candidateCoordinator, candidateErr := newAcornFoxFixCandidateCoordinator(candidateLeaderContext, candidateService)
				if candidateErr != nil {
					log.Fatal("fix candidate coordinator unavailable")
				}
				candidateHandler.Service = candidateCoordinator
				if err := candidateImageStore.Recover(candidateLeaderContext); err != nil {
					log.Printf("fix candidate image cleanup deferred")
				}
				candidateImageCleanupDone := make(chan struct{})
				go func() {
					defer close(candidateImageCleanupDone)
					ticker := time.NewTicker(time.Minute)
					defer ticker.Stop()
					for {
						select {
						case <-candidateLeaderContext.Done():
							return
						case <-ticker.C:
							cleanupContext, cleanupCancel := context.WithTimeout(candidateLeaderContext, 10*time.Second)
							if err := candidateImageStore.Recover(cleanupContext); err != nil {
								log.Printf("fix candidate image cleanup deferred")
							}
							cleanupCancel()
						}
					}
				}()
				defer func() {
					candidateLeaderCancel()
					<-candidateImageCleanupDone
					closeContext, closeCancel := context.WithTimeout(context.Background(), 30*time.Second)
					closeErr := candidateCoordinator.Close(closeContext)
					closeCancel()
					monitorErr := <-candidateLeaderMonitor
					if monitorErr != nil {
						log.Printf("fix candidate execution leader monitor: %v", monitorErr)
					}
					if closeErr != nil {
						log.Printf("fix candidate coordinator shutdown: %v", closeErr)
						return
					}
					releaseContext, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer releaseCancel()
					if err := candidateLeader.Release(releaseContext); err != nil {
						log.Printf("fix candidate execution leader release: %v", err)
					}
				}()
			}
			server.SetAcornFoxFixCandidate(candidateHandler)

			if environment.Clean() {
				stopPublic, publicErr := server.configureCleanPublicAccess(lifecycleContext, store, getenv(acornfoxenv.AuthOrigin), getenv(acornfoxenv.PublicRoot), true, getenv(acornfoxenv.M3Enabled) == "true")
				if publicErr != nil {
					log.Fatal("clean public access configuration conflicts")
				}
				defer stopPublic()
			}
			if getenv(acornfoxenv.M2Enabled) == "true" {
				registryTemp := buildWorkRoot + "/registry-config"
				if err := stdio.MkdirAll(registryTemp, 0o700); err != nil {
					log.Fatal(err)
				}
				registryProvider, err := registryprovider.New(registryprovider.Config{BaseURL: getenv(acornfoxenv.M2RegistryBaseURL), SecretResolver: secretProvider, ImageStore: imageStore, TempRoot: registryTemp})
				if err != nil {
					log.Fatal(err)
				}
				m2Controller := &controllers.M2ReleaseController{Store: store, Source: sourceProvider, Build: buildProvider, Registry: registryProvider, Capacity: capacityProvider, StaticRuntimeDigest: getenv(acornfoxenv.StaticRuntimeDigest)}
				server.SetM2(m2Controller, store, registryProvider, uploadRoot, getenv(acornfoxenv.RuntimeTaskPrefix), getenv(acornfoxenv.AgentDispatchInstanceID), getenv(acornfoxenv.AgentDispatchNodeID))
				volumeCommand := &m2AgentVolumeCommand{store: store, capabilities: server.m2AgentCapabilities}
				lifecycle, lifecycleErr := NewM2LifecycleHandler(store, volumeCommand, nil, getenv(acornfoxenv.RuntimeTaskPrefix))
				if lifecycleErr != nil {
					log.Fatal(lifecycleErr)
				}
				server.SetM2Lifecycle(lifecycle)
				var m3RouteProvider contracts.RouteProvider
				routeSetFence := newRouteSetMutationFence()
				routeMutationWorkers := newRouteMutationWorkerGroup()
				if getenv(acornfoxenv.M3Enabled) == "true" {
					production, productionErr := newM3ProductionConvergence(store, caddyprovider.Config{AdminURL: getenv(acornfoxenv.CaddyAdminURL), Listen: getenv(acornfoxenv.CaddyListen), Issuer: "internal"}, "control-plane-domain-convergence")
					composition, compositionErr := resolveM3Composition(getenv(acornfoxenv.M3Composition), getenv(acornfoxenv.RuntimeTaskPrefix), productionErr == nil, authorizeM3FixtureHost)
					if compositionErr != nil {
						server.SetReady(false)
						log.Fatal(compositionErr)
					}
					if composition == m3CompositionProduction {
						m3RouteProvider = production.Routes
						releaseLeader, startupErr := startProductionDomainConvergence(
							lifecycleContext,
							acquirePostgresDomainConvergenceLeader(store),
							func(ctx context.Context) error {
								startupContext, startupCancel := context.WithTimeout(ctx, 10*time.Second)
								defer startupCancel()
								return rebuildDomainConvergenceRoutes(startupContext, store, production.Routes, "control-plane-domain-convergence")
							},
							func() {
								server.SetTLSAllow(&TLSAllowHTTPHandler{Controller: &controllers.TLSAllowController{Store: store}})
								if server.g3Access != nil && server.g3Access.Controller != nil {
									server.g3Access.Controller.Waker = &g4b2PostgresWaker{store: store}
								}
								routeMutationWorkers.Go(lifecycleContext, func() {
									runDomainConvergenceWorker(lifecycleContext, fencedDomainConvergenceReconciler{reconciler: production, fence: routeSetFence}, &g4b2PostgresWaker{store: store}, "control-plane-domain-convergence", time.Minute)
								})
							},
						)
						if startupErr != nil {
							server.SetReady(false)
							log.Fatal(startupErr)
						}
						releaseDomainConvergenceLeaderAfterRouteWorkers(lifecycleContext, routeMutationWorkers, releaseLeader)
						// This defer is registered after Store.Close, therefore it first
						// cancels and joins every route mutator before releasing the leader.
						defer func() {
							lifecycleCancel()
							routeMutationWorkers.StopAndWait()
							releaseLeader()
						}()
					} else {
						caddyProvider, caddyErr := caddyprovider.New(caddyprovider.Config{AdminURL: getenv(acornfoxenv.CaddyAdminURL), Listen: getenv(acornfoxenv.CaddyListen), Issuer: "internal"})
						if caddyErr != nil {
							log.Fatal(caddyErr)
						}
						accessController, fixtureErr := newM3FixtureAccessController(caddyProvider, store, secretProvider, buildWorkRoot+"/m3-dns-state.json", getenv(acornfoxenv.M3DNSFail) == "true", getenv(acornfoxenv.M3CertFail) == "true")
						if fixtureErr != nil {
							log.Fatal(fixtureErr)
						}
						server.SetM3Access(&M3AccessHTTPHandler{Controller: accessController})
						m3RouteProvider = accessController.Routes
						server.SetTLSAllow(&TLSAllowHTTPHandler{Controller: &controllers.TLSAllowController{Store: store}})
						if _, rebuildErr := accessController.RebuildRoutes(context.Background(), "m3-startup-rebuild", "control-plane"); rebuildErr != nil {
							log.Printf("M3 route rebuild deferred: %v", rebuildErr)
						}
						go func() {
							ticker := time.NewTicker(5 * time.Second)
							defer ticker.Stop()
							for range ticker.C {
								ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
								_, err := accessController.RebuildRoutes(ctx, "m3-periodic-rebuild", "control-plane")
								cancel()
								if err != nil {
									log.Printf("M3 route reconciliation failed: %v", err)
								}
							}
						}()
					}
				}
				// Public access is deliberately optional and shares the one configured
				// local RouteProvider with M3. A second Caddy adapter/cache would be a
				// second route projection and could overwrite routes on restart.
				// DNS/TLS remain absent from this composition.
				if authorizedRoot := strings.TrimSpace(getenv(acornfoxenv.PublicRoot)); authorizedRoot != "" && !environment.Clean() {
					if m3RouteProvider == nil {
						log.Print("AcornFox public access is unavailable: an authorized root requires the configured M3 RouteProvider")
					} else {
						router := acornFoxPublicAccessRouteAdapter{Routes: m3RouteProvider}
						server.SetAcornFoxPublicAccess(&AcornFoxPublicAccessHTTPHandler{Service: &application.AcornFoxPublicAccessService{
							Store:  store,
							Router: router,
							Config: application.AcornFoxPublicAccessConfig{AuthorizedRoot: authorizedRoot},
						}})
						go func() {
							if err := reconcileAcornFoxPublicAccess(lifecycleContext, store, authorizedRoot, router, 10); err != nil {
								log.Printf("AcornFox public-access recovery deferred: %v", err)
							}
							ticker := time.NewTicker(30 * time.Second)
							defer ticker.Stop()
							for {
								select {
								case <-lifecycleContext.Done():
									return
								case <-ticker.C:
									if err := reconcileAcornFoxPublicAccess(lifecycleContext, store, authorizedRoot, router, 10); err != nil {
										log.Printf("AcornFox public-access recovery deferred: %v", err)
									}
								}
							}
						}()
					}
				}
				if getenv(acornfoxenv.M4Enabled) == "true" {
					rolloutEnabled := getenv(acornfoxenv.M4RolloutEnabled) == "true"
					if err := validateM4RolloutComposition(rolloutEnabled, m3RouteProvider != nil, store != nil); err != nil {
						log.Fatal(err)
					}
					logStore := acornFoxLogStore
					adapter := &m4PostgresAdapter{store: store, logs: logStore, metrics: observability.NewMetricStore(store.DB())}
					server.SetM4Logs(&M4LogsHTTPHandler{store: store, logs: logStore})
					server.AgentGateway().SetEventSink(&controllers.DurableAgentSink{Store: store, Projector: agentEvidenceProjectorChain{acornFoxProjector, adapter}, RedactEnvelope: newAcornFoxAgentLogEnvelopeRedactor(store, redactionRoots...)})
					operations := &controllers.M4OperationsController{Store: adapter, Runtime: &m4AgentRuntimeExecutor{store: store}}
					server.SetM4Operations(&M4OperationsHTTPHandler{Operations: operations, Views: adapter})
					allowM4LoopbackFixture := getenv(acornfoxenv.M4AllowLoopbackWebhookFixture) == "true" && getenv(acornfoxenv.RuntimeTaskPrefix) == "opencard-mvp-fa8f8eab"
					notifications := &controllers.M4NotificationController{
						Ledger:   &m4PostgresNotificationLedger{store: store, lease: 30 * time.Second},
						Resolver: &m4WebhookProviderResolver{Secrets: secretProvider, AllowLoopbackFixture: allowM4LoopbackFixture},
					}
					lifecycleDispatcher, dispatchErr := NewM4OperationNotificationDispatcher(notifications)
					if dispatchErr != nil {
						log.Fatal(dispatchErr)
					}
					server.SetM4Webhooks(&M4WebhookHTTPHandler{Store: adapter, Notifications: notifications, Environments: adapter})
					lifecycleWorker := &M4NotificationOutboxWorker{Store: store, Dispatcher: lifecycleDispatcher}
					if rolloutEnabled {
						rolloutInterval, intervalErr := m4RolloutInterval(getenv(acornfoxenv.M4RolloutInterval))
						if intervalErr != nil {
							log.Fatal(intervalErr)
						}
						routeAdapter := &m4StagedRouteAdapter{store: store, routes: m3RouteProvider, owner: "m4-rollout-worker", fence: routeSetFence}
						reconciler := &controllers.M4RolloutReconciler{Store: store, Routes: routeAdapter, Runtime: &m4RolloutRuntime{store: store, owner: "m4-rollout-worker"}, Retirer: &m4OldRetirer{store: store}, Owner: "m4-rollout-worker", Lease: 30 * time.Second}
						rolloutWorker := newM4RolloutWorker(reconciler, rolloutInterval)
						startM4RolloutWorker(lifecycleContext, routeMutationWorkers, rolloutWorker, routeAdapter.releaseAllRouteSets)
					} else {
						log.Print("M4 rollout coordinator is disabled; rollout mutations remain unavailable")
					}
					observationScheduler := &M4ObservationScheduler{Store: store, Interval: 5 * time.Second}
					logCollectionInterval, logCollectionErr := m4LogCollectionInterval(getenv(acornfoxenv.M4LogCollectionInterval), environment)
					if logCollectionErr != nil {
						log.Fatal(logCollectionErr)
					}
					logCollectionScheduler := &M4LogCollectionScheduler{Store: store, Interval: logCollectionInterval}
					go func() {
						ticker := time.NewTicker(time.Second)
						defer ticker.Stop()
						for range ticker.C {
							ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
							if _, err := observationScheduler.ScheduleOnce(ctx, 10); err != nil {
								log.Printf("M4 observation scheduler failed: %v", err)
							}
							cancel()
						}
					}()
					go func() {
						ticker := time.NewTicker(time.Second)
						defer ticker.Stop()
						for range ticker.C {
							ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
							if _, err := logCollectionScheduler.ScheduleOnce(ctx, 10); err != nil {
								log.Printf("M4 runtime log collection failed: %v", err)
							}
							cancel()
						}
					}()
					go func() {
						ticker := time.NewTicker(time.Second)
						defer ticker.Stop()
						for range ticker.C {
							ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
							if _, err := notifications.RunPending(ctx, "m4-notification-control-plane", 20); err != nil {
								log.Printf("M4 notification worker failed: %v", err)
							}
							cancel()
						}
					}()
					go func() {
						ticker := time.NewTicker(time.Second)
						defer ticker.Stop()
						for range ticker.C {
							ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
							if _, err := lifecycleWorker.ProcessOnce(ctx, 20); err != nil {
								log.Printf("M4 notification outbox worker failed: %v", err)
							}
							cancel()
						}
					}()
				}
				if getenv(acornfoxenv.M5Enabled) == "true" {
					usageMeter := meterlocal.New(store.DB())
					usageWorker := &M5UsageWorker{DB: store.DB(), Meter: usageMeter, Interval: time.Minute}
					if value := getenv(acornfoxenv.M5StorageCapacityBytes); value != "" {
						parsed, parseErr := strconv.ParseInt(value, 10, 64)
						if parseErr != nil || parsed <= 0 {
							log.Fatalf("%s must be a positive integer", environment.Name(acornfoxenv.M5StorageCapacityBytes))
						}
						usageWorker.StorageCapacity = parsed
					}
					if value := getenv(acornfoxenv.M5StorageHardReserveBytes); value != "" {
						parsed, parseErr := strconv.ParseInt(value, 10, 64)
						if parseErr != nil || parsed <= 0 {
							log.Fatalf("%s must be a positive integer", environment.Name(acornfoxenv.M5StorageHardReserveBytes))
						}
						usageWorker.StorageHardReserve = parsed
					}
					startupCtx, startupCancel := context.WithTimeout(context.Background(), 30*time.Second)
					if schemaErr := validateM5UsageSchema(startupCtx, store.DB()); schemaErr != nil {
						startupCancel()
						log.Fatal(schemaErr)
					}
					startupErr := usageWorker.RunOnce(startupCtx)
					startupCancel()
					if startupErr != nil {
						log.Printf("M5 initial usage aggregation deferred without blocking deployment/runtime: %v", startupErr)
					}
					server.SetM5Usage(&M5UsageHTTPHandler{DB: store.DB(), Meter: usageMeter, AllowAISummaryContext: false})
					go func() {
						ticker := time.NewTicker(usageWorker.Interval)
						defer ticker.Stop()
						for range ticker.C {
							ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
							if err := usageWorker.RunOnce(ctx); err != nil {
								log.Printf("M5 usage worker failed: %v", err)
							}
							cancel()
						}
					}()
				}
				if getenv(acornfoxenv.M6Enabled) == "true" {
					m6Context, m6Cancel := context.WithTimeout(context.Background(), 30*time.Second)
					if err := validateM6Schema(m6Context, store.DB()); err != nil {
						m6Cancel()
						log.Fatal(err)
					}
					m6Cancel()
					workspaceRoot := getenv(acornfoxenv.M6WorkspaceRoot)
					if workspaceRoot == "" {
						workspaceRoot = buildWorkRoot + "/m6-workspace"
					}
					if err := stdio.MkdirAll(workspaceRoot+"/drafts", 0o700); err != nil {
						log.Fatal(err)
					}
					contextBuilder := aicontext.New(aicontext.Config{MaxBytes: 64 << 10, MaxFileBytes: 16 << 10, MaxLogBytes: 24 << 10, MaxLogLines: 256, TemplateVersion: "context-v1"})
					catalog := aitools.DefaultCatalog()
					actionRunner, runnerErr := airunner.NewActionRunner(catalog, airunner.Options{})
					if runnerErr != nil {
						log.Fatal(runnerErr)
					}
					ledgerStore := ailedger.NewPostgres(store.DB())
					ruleRegistry := rules.NewPostgres(store.DB())
					baseOrchestrator := orchestrator.Orchestrator{Context: &m6ContextAdapter{builder: contextBuilder}, Catalog: &m6CatalogAdapter{catalog: catalog}, Runner: &m6RunnerAdapter{runner: actionRunner, last: map[string][]airunner.RunResult{}}, Ledger: ledgerStore, Candidates: &m6CandidateAdapter{registry: ruleRegistry, ledger: ledgerStore}, PolicyVersion: "m6-policy-v1"}
					providers := map[ailedger.Profile]contracts.AIProvider{}
					for ledgerProfile, providerProfile := range map[ailedger.Profile]aiprovider.Profile{ailedger.ProfileMainland: aiprovider.ProfileChina, ailedger.ProfileGlobal: aiprovider.ProfileGlobal, ailedger.ProfileLocal: aiprovider.ProfileLocal} {
						providerValue, providerErr := aiprovider.New(aiprovider.Config{Profile: providerProfile, Model: "fixture-v1", PolicyVersion: "m6-policy-v1", Available: true, MaxTokens: 4096, MaxDuration: 30 * time.Second, CacheEnabled: true, CacheTTL: 10 * time.Minute, Cooldown: time.Second})
						if providerErr != nil {
							log.Fatal(providerErr)
						}
						providers[ledgerProfile] = providerValue
					}
					if _, err := ledgerStore.CurrentSettings(context.Background()); errors.Is(err, ailedger.ErrNotFound) {
						_, _, err = ledgerStore.AppendSettings(context.Background(), ailedger.SettingsRequest{IdempotencyKey: "m6-default-disabled", RequestDigest: "sha256:m6-default-disabled", Settings: ailedger.AISettings{Version: 1, Enabled: false, Profile: ailedger.ProfileDisabled, DataScopes: []string{"operations_summary"}, MaxTokens: 128, MaxDurationMS: 5000, CooldownMS: 60000, CacheEnabled: true, Actor: "control-plane-bootstrap", ExternalCalls: false, CreatedAt: time.Now().UTC()}})
						if err != nil {
							log.Fatal(err)
						}
					} else if err != nil {
						log.Fatal(err)
					}
					server.SetM6AI(&M6AIHTTPHandler{Backend: &m6AIBackend{db: store.DB(), ledger: ledgerStore, base: baseOrchestrator, providers: providers, workspaceRoot: workspaceRoot}})
				}
			}
		}
	} else {
		log.Printf("%s is unset; using the non-persistent development repository", environment.Name(acornfoxenv.DatabaseURL))
	}
	hostSampler := hostmetrics.NewSampler(hostmetrics.Config{})
	hostSampler.Start(lifecycleContext)
	server.SetAcornFoxHostMetrics(hostmetrics.NewHTTPHandler(hostSampler))
	if getenv(acornfoxenv.AssistantEnabled) == "true" && controllerStore != nil {
		workerSocket, toolSocket := getenv(acornfoxenv.AssistantWorkerSocket), getenv(acornfoxenv.AssistantToolsSocket)
		if workerSocket == "" {
			workerSocket = "/run/acornfox-pi/worker.sock"
		}
		if toolSocket == "" {
			toolSocket = "/run/acornfox-assistant/tools.sock"
		}
		stopAssistant, assistantErr := server.configureAcornFoxAssistant(lifecycleContext, controllerStore.DB(), workerSocket, toolSocket)
		if assistantErr != nil {
			log.Print("assistant unavailable: verify its protected runtime configuration")
		} else {
			defer stopAssistant()
		}
	}

	if gatewayAddress != "" {
		var identities []struct {
			CertificateID string `json:"certificate_id"`
			InstanceID    string `json:"instance_id"`
			NodeID        string `json:"node_id"`
		}
		if err := json.Unmarshal([]byte(getenv(acornfoxenv.AgentIdentitiesJSON)), &identities); err != nil || len(identities) == 0 {
			log.Fatalf("%s must contain at least one certificate/instance/node binding", environment.Name(acornfoxenv.AgentIdentitiesJSON))
		}
		for _, identity := range identities {
			if err := server.AgentGateway().RegisterIdentity(identity.CertificateID, identity.InstanceID, identity.NodeID); err != nil {
				log.Fatal(err)
			}
		}
		gatewayTLS, err := loadAgentGatewayMTLSConfig(
			getenv(acornfoxenv.ServerAgentTLSCA),
			getenv(acornfoxenv.ServerAgentTLSCert),
			getenv(acornfoxenv.ServerAgentTLSKey),
		)
		if err != nil {
			log.Fatal(err)
		}
		gatewayServer := &http.Server{Addr: gatewayAddress, Handler: server.AgentGateway(), TLSConfig: gatewayTLS, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
		go func() {
			log.Printf("%s Agent gateway listening with mTLS on %s", environment.ProductLabel(), gatewayAddress)
			if err := gatewayServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("Agent gateway stopped: %v", err)
				server.SetReady(false)
			}
		}()
		dispatchInstance := getenv(acornfoxenv.AgentDispatchInstanceID)
		dispatchNode := getenv(acornfoxenv.AgentDispatchNodeID)
		if controllerStore != nil && dispatchInstance != "" && dispatchNode != "" {
			dispatcher := &controllers.AgentDispatcher{Store: controllerStore, Queue: server.AgentGateway(), InstanceID: dispatchInstance, NodeID: dispatchNode}
			go func() {
				for {
					worked, err := dispatcher.DispatchOne(context.Background())
					if err != nil {
						log.Printf("Agent dispatch failed: %v", err)
					}
					if !worked {
						time.Sleep(250 * time.Millisecond)
					}
				}
			}()
			go func() {
				ticker := time.NewTicker(time.Second)
				defer ticker.Stop()
				for now := range ticker.C {
					if server.AgentGateway().NodeStatus(dispatchInstance, dispatchNode, now.UTC()) != "unknown" {
						if _, err := controllerStore.RenewOwnedControllerTaskLeases(context.Background(), dispatchNode, now.UTC(), 30*time.Second); err != nil {
							log.Printf("Agent task lease renewal failed: %v", err)
						}
						continue
					}
					if _, err := controllerStore.MarkNodeDeploymentsUnknown(context.Background(), dispatchNode, now.UTC()); err != nil {
						log.Printf("Agent heartbeat unknown projection failed: %v", err)
					}
				}
			}()
		}
	}
	httpServer := server.HTTPServer(address)
	log.Printf("%s server listening on %s", environment.ProductLabel(), address)
	serveResult := make(chan error, 1)
	go func() { serveResult <- httpServer.ListenAndServe() }()
	var serveErr error
	select {
	case serveErr = <-serveResult:
		lifecycleCancel()
	case <-lifecycleContext.Done():
		shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		shutdownErr := httpServer.Shutdown(shutdownContext)
		shutdownCancel()
		if shutdownErr != nil {
			log.Printf("HTTP server shutdown: %v", shutdownErr)
		}
		serveErr = <-serveResult
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		log.Fatal(serveErr)
	}
	_ = server.Shutdown(context.Background())
}

func resolveServerListenerAddress(environment acornfoxenv.Environment) (string, error) {
	address := environment.Get(acornfoxenv.ServerAddr)
	if !environment.Clean() {
		if address == "" {
			return "127.0.0.1:8080", nil
		}
		return address, nil
	}
	if address == "" || address == "127.0.0.1:18481" {
		return "127.0.0.1:18481", nil
	}
	return "", errors.New("AcornFox clean runtime listener is invalid")
}

func resolveAgentGatewayListenerAddress(environment acornfoxenv.Environment) (string, error) {
	address := environment.Get(acornfoxenv.AgentGatewayAddr)
	if !environment.Clean() || address == "" || address == "127.0.0.1:8092" {
		return address, nil
	}
	return "", errors.New("AcornFox clean runtime listener is invalid")
}

// sourceGitResolverEndpoints has no default: an empty value leaves public Git
// disabled while preserving upload-only source creation. Resolver addresses
// themselves are validated by source.New as explicit public IP:port values.
func sourceGitResolverEndpoints(raw string) []string {
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func sourceWorkspaceCapacityConfig(getenv func(acornfoxenv.Key) string) (int64, int64, int64, int64, error) {
	if getenv == nil {
		return 0, 0, 0, 0, errors.New("source workspace environment is unavailable")
	}
	names := []acornfoxenv.Key{
		acornfoxenv.SourceWorkspaceCapacityBytes,
		acornfoxenv.SourceWorkspaceCapacityEntries,
		acornfoxenv.SourceWorkspaceOperationalReserveBytes,
		acornfoxenv.SourceWorkspaceOperationalReserveEntries,
	}
	values := [4]int64{}
	for index, name := range names {
		raw := strings.TrimSpace(getenv(name))
		if raw == "" {
			continue
		}
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			return 0, 0, 0, 0, errors.New("source workspace capacity environment is invalid")
		}
		values[index] = parsed
	}
	return values[0], values[1], values[2], values[3], nil
}
