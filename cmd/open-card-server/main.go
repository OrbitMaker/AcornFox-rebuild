package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	aicontext "github.com/open-card/open-card/internal/ai/context"
	ailedger "github.com/open-card/open-card/internal/ai/ledger"
	"github.com/open-card/open-card/internal/ai/orchestrator"
	aiprovider "github.com/open-card/open-card/internal/ai/provider"
	airunner "github.com/open-card/open-card/internal/ai/runner"
	aitools "github.com/open-card/open-card/internal/ai/tools"
	"github.com/open-card/open-card/internal/auth"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/observability"
	"github.com/open-card/open-card/internal/persistence/postgres"
	"github.com/open-card/open-card/internal/providers/buildkit"
	caddyprovider "github.com/open-card/open-card/internal/providers/caddy"
	"github.com/open-card/open-card/internal/providers/capacity"
	"github.com/open-card/open-card/internal/providers/certfixture"
	"github.com/open-card/open-card/internal/providers/dnsfixture"
	imageprovider "github.com/open-card/open-card/internal/providers/image"
	meterlocal "github.com/open-card/open-card/internal/providers/meter/local"
	registryprovider "github.com/open-card/open-card/internal/providers/registryhttp"
	secretprovider "github.com/open-card/open-card/internal/providers/secret"
	"github.com/open-card/open-card/internal/providers/source"
	"github.com/open-card/open-card/internal/rules"
)

func main() {
	address := os.Getenv("OPEN_CARD_SERVER_ADDR")
	if address == "" {
		address = "127.0.0.1:8080"
	}
	server := NewServer()
	var controllerStore *postgres.Store
	databaseURL := os.Getenv("OPEN_CARD_DATABASE_URL")
	if err := validateFeatureHierarchy(databaseURL != "", os.Getenv("OPEN_CARD_M1_ENABLED") == "true", os.Getenv("OPEN_CARD_M2_ENABLED") == "true", os.Getenv("OPEN_CARD_M3_ENABLED") == "true", os.Getenv("OPEN_CARD_M4_ENABLED") == "true", os.Getenv("OPEN_CARD_M4_ROLLOUT_ENABLED") == "true", os.Getenv("OPEN_CARD_M5_ENABLED") == "true", os.Getenv("OPEN_CARD_M6_ENABLED") == "true"); err != nil {
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
		server = NewServerWithRepository(store)
		controllerStore = store
		server.SetSystemStatusStore(store)
		server.SetApplicationProjectionStore(store)
		server.SetSystemStatusNode(os.Getenv("OPEN_CARD_AGENT_DISPATCH_INSTANCE_ID"), os.Getenv("OPEN_CARD_AGENT_DISPATCH_NODE_ID"))
		origin := strings.TrimSpace(os.Getenv("OPEN_CARD_AUTH_ORIGIN"))
		if origin != "" {
			authService, authErr := auth.NewService(auth.Config{Store: store, Origin: origin})
			if authErr != nil {
				log.Fatal(authErr)
			}
			server.SetAuth(&AuthHTTPHandler{Service: authService})
		} else {
			log.Print("administrator HTTP authentication is not activated; OPEN_CARD_AUTH_ORIGIN is unset")
		}
		server.SetG3Access(newG3AccessHTTPHandler(store))
		server.SetG3SourceUpload(&G3SourceUploadHTTPHandler{Store: store})
		server.AgentGateway().SetEventSink(&controllers.DurableAgentSink{Store: store})
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
		if os.Getenv("OPEN_CARD_M1_ENABLED") == "true" {
			uploadRoot := os.Getenv("OPEN_CARD_SOURCE_UPLOAD_ROOT")
			workspaceRoot := os.Getenv("OPEN_CARD_SOURCE_WORKSPACE_ROOT")
			buildWorkRoot := os.Getenv("OPEN_CARD_BUILD_WORK_ROOT")
			for _, path := range []string{uploadRoot, workspaceRoot, buildWorkRoot} {
				if path == "" {
					log.Fatal("M1 source and build roots must be explicitly configured")
				}
				if err := os.MkdirAll(path, 0o700); err != nil {
					log.Fatal(err)
				}
			}
			server.SetG3SourceUpload(newG3SourceUploadHTTPHandler(store))
			var m4LogStore *observability.LogStore
			var buildLogSink buildkit.BuildLogSink
			if os.Getenv("OPEN_CARD_M4_ENABLED") == "true" {
				logRoot := os.Getenv("OPEN_CARD_LOG_ROOT")
				if logRoot == "" {
					logRoot = buildWorkRoot + "/m4-logs"
				}
				logConfig, configErr := m4LogStoreConfig(logRoot, os.Getenv("OPEN_CARD_LOG_MAX_FILE_BYTES"), os.Getenv("OPEN_CARD_LOG_MAX_TOTAL_BYTES"))
				if configErr != nil {
					log.Fatal(configErr)
				}
				m4LogStore, err = observability.NewLogStore(logConfig)
				if err != nil {
					log.Fatal(err)
				}
				if err := m4ReconcileOrdinaryLogIndexes(context.Background(), store, m4LogStore, time.Now().UTC()); err != nil {
					log.Fatal(err)
				}
				buildLogSink = &m4BuildLogSink{store: store, logs: m4LogStore}
			}
			imageStore, err := imageprovider.New(imageprovider.Config{Root: os.Getenv("OPEN_CARD_OCI_STORE_ROOT")})
			if err != nil {
				log.Fatal(err)
			}
			capacityConfig := capacity.Config{DiskPath: buildWorkRoot, BuildReserve: contracts.ResourceLimits{CPUMillis: 250, MemoryBytes: 256 << 20, DiskBytes: 512 << 20}, RuntimeReserve: contracts.ResourceLimits{CPUMillis: 250, MemoryBytes: 256 << 20, DiskBytes: 512 << 20}}
			if value := os.Getenv("OPEN_CARD_CAPACITY_FIXED_HOST_PORT"); value != "" {
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
			secretProvider, err := secretprovider.New(secretprovider.Config{Root: os.Getenv("OPEN_CARD_SECRET_ROOT"), MaterialRoot: os.Getenv("OPEN_CARD_SECRET_MATERIAL_ROOT"), MasterKeyPath: os.Getenv("OPEN_CARD_SECRET_MASTER_KEY"), MaterialTTL: 2 * time.Minute})
			if err != nil {
				log.Fatal(err)
			}
			sourceProvider, err := source.New(source.Config{UploadRoot: uploadRoot, WorkspaceRoot: workspaceRoot, GitResolverEndpoints: sourceGitResolverEndpoints(os.Getenv("OPEN_CARD_SOURCE_GIT_RESOLVERS"))})
			if err != nil {
				log.Fatal(err)
			}
			server.controller.SetSourcePreparer(sourceProvider)
			buildProvider, err := buildkit.New(buildkit.Config{Command: os.Getenv("OPEN_CARD_BUILDKIT_COMMAND"), Builder: os.Getenv("OPEN_CARD_BUILDKIT_WORKER"), Address: os.Getenv("OPEN_CARD_BUILDKIT_ADDRESS"), WorkspaceRoot: workspaceRoot, WorkRoot: buildWorkRoot, StaticServerBinary: os.Getenv("OPEN_CARD_STATIC_SERVER_BINARY"), ImageStore: imageStore, Capacity: capacityProvider, SecretResolver: secretProvider, LogSink: buildLogSink})
			if err != nil {
				log.Fatal(err)
			}
			server.SetReleaseController(&controllers.ReleaseController{Store: store, Source: sourceProvider, Build: buildProvider, Capacity: capacityProvider, StaticRuntimeDigest: os.Getenv("OPEN_CARD_STATIC_RUNTIME_DIGEST")})
			if os.Getenv("OPEN_CARD_M2_ENABLED") == "true" {
				registryTemp := buildWorkRoot + "/registry-config"
				if err := os.MkdirAll(registryTemp, 0o700); err != nil {
					log.Fatal(err)
				}
				registryProvider, err := registryprovider.New(registryprovider.Config{BaseURL: os.Getenv("OPEN_CARD_M2_REGISTRY_BASE_URL"), SecretResolver: secretProvider, ImageStore: imageStore, TempRoot: registryTemp})
				if err != nil {
					log.Fatal(err)
				}
				m2Controller := &controllers.M2ReleaseController{Store: store, Source: sourceProvider, Build: buildProvider, Registry: registryProvider, Capacity: capacityProvider, StaticRuntimeDigest: os.Getenv("OPEN_CARD_STATIC_RUNTIME_DIGEST")}
				server.SetM2(m2Controller, store, registryProvider, uploadRoot, os.Getenv("OPEN_CARD_RUNTIME_TASK_PREFIX"), os.Getenv("OPEN_CARD_AGENT_DISPATCH_INSTANCE_ID"), os.Getenv("OPEN_CARD_AGENT_DISPATCH_NODE_ID"))
				volumeCommand := &m2AgentVolumeCommand{store: store, capabilities: server.m2AgentCapabilities}
				lifecycle, lifecycleErr := NewM2LifecycleHandler(store, volumeCommand, nil, os.Getenv("OPEN_CARD_RUNTIME_TASK_PREFIX"))
				if lifecycleErr != nil {
					log.Fatal(lifecycleErr)
				}
				server.SetM2Lifecycle(lifecycle)
				if os.Getenv("OPEN_CARD_M3_ENABLED") == "true" {
					caddyProvider, caddyErr := caddyprovider.New(caddyprovider.Config{AdminURL: os.Getenv("OPEN_CARD_CADDY_ADMIN_URL"), Listen: os.Getenv("OPEN_CARD_CADDY_LISTEN"), Issuer: "internal"})
					if caddyErr != nil {
						log.Fatal(caddyErr)
					}
					dnsProvider, dnsErr := dnsfixture.New(dnsfixture.Config{StatePath: buildWorkRoot + "/m3-dns-state.json"})
					if dnsErr != nil {
						log.Fatal(dnsErr)
					}
					if os.Getenv("OPEN_CARD_M3_DNS_FAIL") == "true" {
						if err := dnsProvider.SetFault(dnsfixture.Fault{Operation: "verify_cname", Code: contracts.ErrUnavailable, Message: "isolated DNS verification failure"}); err != nil {
							log.Fatal(err)
						}
					}
					dnsAuthority := certfixture.DNSAdapter{
						Present: func(ctx context.Context, name, token string, op contracts.OperationContext) (certfixture.DNS01Challenge, error) {
							challenge, err := dnsProvider.PresentDNS01(ctx, name, token, op)
							return certfixture.DNS01Challenge{Domain: challenge.Domain, Name: challenge.Name, Token: challenge.Token}, err
						},
						Verify: func(ctx context.Context, challenge certfixture.DNS01Challenge, op contracts.OperationContext) error {
							return dnsProvider.VerifyDNS01(ctx, dnsfixture.DNS01Challenge{Domain: challenge.Domain, Name: challenge.Name, Token: challenge.Token}, op)
						},
						Cleanup: func(ctx context.Context, challenge certfixture.DNS01Challenge, op contracts.OperationContext) error {
							return dnsProvider.CleanupDNS01(ctx, dnsfixture.DNS01Challenge{Domain: challenge.Domain, Name: challenge.Name, Token: challenge.Token}, op)
						},
					}
					certificateProvider, certificateErr := certfixture.New(certfixture.Config{Secrets: secretProvider, DNS: dnsAuthority, Validity: 24 * time.Hour})
					if certificateErr != nil {
						log.Fatal(certificateErr)
					}
					if os.Getenv("OPEN_CARD_M3_CERT_FAIL") == "true" {
						if err := certificateProvider.SetFault(certfixture.Fault{Operation: "issue", Code: contracts.ErrUnavailable, Message: "isolated certificate issuance failure"}); err != nil {
							log.Fatal(err)
						}
					}
					accessController := &controllers.M3AccessController{Routes: caddyProvider, Store: &m3PostgresAdapter{store: store}, DNS: &m3DNSAdapter{provider: dnsProvider}, Certificates: &m3CertificateAdapter{provider: certificateProvider}}
					server.SetM3Access(&M3AccessHTTPHandler{Controller: accessController})
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
				if os.Getenv("OPEN_CARD_M4_ENABLED") == "true" {
					rolloutEnabled := os.Getenv("OPEN_CARD_M4_ROLLOUT_ENABLED") == "true"
					if err := validateM4RolloutComposition(rolloutEnabled, server.m3Access != nil && server.m3Access.Controller != nil, store != nil); err != nil {
						log.Fatal(err)
					}
					logStore := m4LogStore
					adapter := &m4PostgresAdapter{store: store, logs: logStore, metrics: observability.NewMetricStore(store.DB())}
					server.SetM4Logs(&M4LogsHTTPHandler{store: store, logs: logStore})
					server.AgentGateway().SetEventSink(&controllers.DurableAgentSink{Store: store, Projector: adapter})
					operations := &controllers.M4OperationsController{Store: adapter, Runtime: &m4AgentRuntimeExecutor{store: store}}
					server.SetM4Operations(&M4OperationsHTTPHandler{Operations: operations, Views: adapter})
					allowM4LoopbackFixture := os.Getenv("OPEN_CARD_M4_ALLOW_LOOPBACK_WEBHOOK_FIXTURE") == "true" && os.Getenv("OPEN_CARD_RUNTIME_TASK_PREFIX") == "opencard-mvp-fa8f8eab"
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
						rolloutInterval, intervalErr := m4RolloutInterval(os.Getenv("OPEN_CARD_M4_ROLLOUT_INTERVAL"))
						if intervalErr != nil {
							log.Fatal(intervalErr)
						}
						routeAdapter := &m4StagedRouteAdapter{store: store, routes: server.m3Access.Controller.Routes, owner: "m4-rollout-worker"}
						reconciler := &controllers.M4RolloutReconciler{Store: store, Routes: routeAdapter, Runtime: &m4RolloutRuntime{store: store, owner: "m4-rollout-worker"}, Retirer: &m4OldRetirer{store: store}, Owner: "m4-rollout-worker", Lease: 30 * time.Second}
						rolloutWorker := newM4RolloutWorker(reconciler, rolloutInterval)
						go rolloutWorker.Run(context.Background())
					} else {
						log.Print("M4 rollout coordinator is disabled; rollout mutations remain unavailable")
					}
					observationScheduler := &M4ObservationScheduler{Store: store, Interval: 5 * time.Second}
					logCollectionInterval, logCollectionErr := m4LogCollectionInterval(os.Getenv("OPEN_CARD_M4_LOG_COLLECTION_INTERVAL"))
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
				if os.Getenv("OPEN_CARD_M5_ENABLED") == "true" {
					usageMeter := meterlocal.New(store.DB())
					usageWorker := &M5UsageWorker{DB: store.DB(), Meter: usageMeter, Interval: time.Minute}
					if value := os.Getenv("OPEN_CARD_M5_STORAGE_CAPACITY_BYTES"); value != "" {
						parsed, parseErr := strconv.ParseInt(value, 10, 64)
						if parseErr != nil || parsed <= 0 {
							log.Fatal("OPEN_CARD_M5_STORAGE_CAPACITY_BYTES must be a positive integer")
						}
						usageWorker.StorageCapacity = parsed
					}
					if value := os.Getenv("OPEN_CARD_M5_STORAGE_HARD_RESERVE_BYTES"); value != "" {
						parsed, parseErr := strconv.ParseInt(value, 10, 64)
						if parseErr != nil || parsed <= 0 {
							log.Fatal("OPEN_CARD_M5_STORAGE_HARD_RESERVE_BYTES must be a positive integer")
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
				if os.Getenv("OPEN_CARD_M6_ENABLED") == "true" {
					m6Context, m6Cancel := context.WithTimeout(context.Background(), 30*time.Second)
					if err := validateM6Schema(m6Context, store.DB()); err != nil {
						m6Cancel()
						log.Fatal(err)
					}
					m6Cancel()
					workspaceRoot := os.Getenv("OPEN_CARD_M6_WORKSPACE_ROOT")
					if workspaceRoot == "" {
						workspaceRoot = buildWorkRoot + "/m6-workspace"
					}
					if err := os.MkdirAll(workspaceRoot+"/drafts", 0o700); err != nil {
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
		log.Print("OPEN_CARD_DATABASE_URL is unset; using the non-persistent development repository")
	}
	if gatewayAddress := os.Getenv("OPEN_CARD_AGENT_GATEWAY_ADDR"); gatewayAddress != "" {
		var identities []struct {
			CertificateID string `json:"certificate_id"`
			InstanceID    string `json:"instance_id"`
			NodeID        string `json:"node_id"`
		}
		if err := json.Unmarshal([]byte(os.Getenv("OPEN_CARD_AGENT_IDENTITIES_JSON")), &identities); err != nil || len(identities) == 0 {
			log.Fatal("OPEN_CARD_AGENT_IDENTITIES_JSON must contain at least one certificate/instance/node binding")
		}
		for _, identity := range identities {
			if err := server.AgentGateway().RegisterIdentity(identity.CertificateID, identity.InstanceID, identity.NodeID); err != nil {
				log.Fatal(err)
			}
		}
		gatewayTLS, err := loadAgentGatewayMTLSConfig(
			os.Getenv("OPEN_CARD_SERVER_AGENT_TLS_CA"),
			os.Getenv("OPEN_CARD_SERVER_AGENT_TLS_CERT"),
			os.Getenv("OPEN_CARD_SERVER_AGENT_TLS_KEY"),
		)
		if err != nil {
			log.Fatal(err)
		}
		gatewayServer := &http.Server{Addr: gatewayAddress, Handler: server.AgentGateway(), TLSConfig: gatewayTLS, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
		go func() {
			log.Printf("open-card Agent gateway listening with mTLS on %s", gatewayAddress)
			if err := gatewayServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("Agent gateway stopped: %v", err)
				server.SetReady(false)
			}
		}()
		dispatchInstance := os.Getenv("OPEN_CARD_AGENT_DISPATCH_INSTANCE_ID")
		dispatchNode := os.Getenv("OPEN_CARD_AGENT_DISPATCH_NODE_ID")
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
	log.Printf("open-card server listening on %s", address)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	_ = server.Shutdown(context.Background())
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
