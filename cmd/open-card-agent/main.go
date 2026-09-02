package main

import (
	"context"
	"crypto/x509"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/agenttransport"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	acornfoxprobe "github.com/open-card/open-card/internal/probe"
	"github.com/open-card/open-card/internal/providers/capacity"
	imageprovider "github.com/open-card/open-card/internal/providers/image"
	"github.com/open-card/open-card/internal/providers/standalone"
	"github.com/open-card/open-card/internal/providers/standalonegroup"
	volumeprovider "github.com/open-card/open-card/internal/providers/volume"
)

func main() {
	address := os.Getenv("OPEN_CARD_AGENT_ADDR")
	if address == "" {
		address = "127.0.0.1:8091"
	}
	instanceID := os.Getenv("OPEN_CARD_INSTANCE_ID")
	if instanceID == "" {
		instanceID = "local"
	}
	nodeID := os.Getenv("OPEN_CARD_NODE_ID")
	if nodeID == "" {
		nodeID = "local-node"
	}
	version := os.Getenv("OPEN_CARD_AGENT_VERSION")
	if version == "" {
		version = "dev"
	}
	if controlPlaneURL := os.Getenv("OPEN_CARD_CONTROL_PLANE_URL"); controlPlaneURL != "" {
		runOutboundAgent(controlPlaneURL, instanceID, nodeID, version)
		return
	}
	agent := NewAgent(instanceID, nodeID, version)
	tlsConfig, err := loadMTLSConfig(
		os.Getenv("OPEN_CARD_AGENT_TLS_CA"),
		os.Getenv("OPEN_CARD_AGENT_TLS_CERT"),
		os.Getenv("OPEN_CARD_AGENT_TLS_KEY"),
	)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: address, Handler: agent.Handler(), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("open-card agent protocol %s listening on %s", "v1", address)
	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func runOutboundAgent(controlPlaneURL, instanceID, nodeID, version string) {
	tlsConfig, err := loadOutboundMTLSConfig(
		os.Getenv("OPEN_CARD_AGENT_TLS_CA"),
		os.Getenv("OPEN_CARD_AGENT_TLS_CERT"),
		os.Getenv("OPEN_CARD_AGENT_TLS_KEY"),
		os.Getenv("OPEN_CARD_CONTROL_PLANE_SERVER_NAME"),
	)
	if err != nil {
		log.Fatal(err)
	}
	socketPath := os.Getenv("OPEN_CARD_DOCKER_SOCKET")
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}
	facts, err := NewUnixDockerFactsReader(socketPath)
	if err != nil {
		log.Fatal(err)
	}
	var runtime contracts.RuntimeDriver
	var groupRuntime contracts.ServiceGroupRuntimeDriver
	var volumeRuntime contracts.VolumeProvider
	var acornFoxRuntime contracts.AcornFoxRuntimeDriver
	var acornFoxProber acornFoxRuntimeProber
	capabilities := []string{"docker.read.facts"}
	if os.Getenv("OPEN_CARD_RUNTIME_ENABLED") == "true" {
		if os.Getenv("OPEN_CARD_WORKER_NETWORK_ISOLATED") != "true" {
			log.Fatal("runtime deployment requires an externally isolated worker network")
		}
		store, storeErr := imageprovider.New(imageprovider.Config{Root: os.Getenv("OPEN_CARD_OCI_STORE_ROOT")})
		if storeErr != nil {
			log.Fatal(storeErr)
		}
		reserveMemory := int64(256 << 20)
		if value := os.Getenv("OPEN_CARD_RUNTIME_RESERVE_MEMORY_BYTES"); value != "" {
			parsed, parseErr := strconv.ParseInt(value, 10, 64)
			if parseErr != nil || parsed < 0 {
				log.Fatal("invalid runtime memory reserve")
			}
			reserveMemory = parsed
		}
		capacityConfig := capacity.Config{DiskPath: os.Getenv("OPEN_CARD_RUNTIME_WORK_ROOT"), RuntimeReserve: contracts.ResourceLimits{CPUMillis: 250, MemoryBytes: reserveMemory, DiskBytes: 512 << 20}}
		if value := os.Getenv("OPEN_CARD_RUNTIME_FIXED_HOST_PORT"); value != "" {
			parsed, parseErr := strconv.Atoi(value)
			if parseErr != nil || parsed < 1 || parsed > 65535 {
				log.Fatal("invalid fixed runtime host port")
			}
			capacityConfig.PortAllocator = capacity.FixedPortAllocator{Port: parsed}
		}
		capacityProvider, capacityErr := capacity.New(capacityConfig)
		if capacityErr != nil {
			log.Fatal(capacityErr)
		}
		standaloneRuntime, storeErr := standalone.New(standalone.Config{
			TaskPrefix:            os.Getenv("OPEN_CARD_RUNTIME_TASK_PREFIX"),
			Network:               os.Getenv("OPEN_CARD_RUNTIME_NETWORK"),
			WorkRoot:              os.Getenv("OPEN_CARD_RUNTIME_WORK_ROOT"),
			ImageStore:            store,
			Capacity:              capacityProvider,
			WorkerNetworkIsolated: true,
		})
		if storeErr != nil {
			log.Fatal(storeErr)
		}
		var runtimeCapabilities []string
		runtime, acornFoxRuntime, acornFoxProber, runtimeCapabilities, storeErr = composeAcornFoxRuntimeWithProbe(context.Background(), standaloneRuntime, func() (acornFoxRuntimeProber, error) {
			return acornfoxprobe.New(acornfoxprobe.DefaultConfig(), time.Now)
		})
		if storeErr != nil {
			log.Fatal(storeErr)
		}
		capabilities = append(capabilities, runtimeCapabilities...)
		if os.Getenv("OPEN_CARD_M2_ENABLED") == "true" {
			var metricsReader standalonegroup.RuntimeMetricsReader
			if os.Getenv("OPEN_CARD_M4_ENABLED") == "true" {
				reader, readerErr := NewUnixDockerRuntimeMetricsReader(socketPath)
				if readerErr != nil {
					log.Fatal(readerErr)
				}
				metricsReader = m4GroupRuntimeMetricsAdapter{reader: reader}
			}
			volumes, volumeErr := volumeprovider.New(volumeprovider.Config{TaskPrefix: os.Getenv("OPEN_CARD_RUNTIME_TASK_PREFIX")})
			if volumeErr != nil {
				log.Fatal(volumeErr)
			}
			volumeRuntime = volumes
			groupRuntime, storeErr = standalonegroup.New(standalonegroup.Config{
				TaskPrefix: os.Getenv("OPEN_CARD_RUNTIME_TASK_PREFIX"), Network: os.Getenv("OPEN_CARD_RUNTIME_GROUP_NETWORK"), WorkRoot: os.Getenv("OPEN_CARD_RUNTIME_WORK_ROOT"),
				ImageStore: store, Capacity: capacityProvider, Volumes: volumes, MetricsReader: metricsReader, WorkerNetworkIsolated: true,
			})
			if storeErr != nil {
				log.Fatal(storeErr)
			}
			capabilities = append(capabilities, v1.AgentCapabilityRuntimeDeployGroup, v1.AgentCapabilityRuntimeObserveGroup, v1.AgentCapabilityRuntimeLogsGroup, v1.AgentCapabilityRuntimeRollbackGroup, v1.AgentCapabilityRuntimeDestroyGroup, v1.AgentCapabilityRuntimeRestartGroupService, v1.AgentCapabilityRuntimeRestartGroup)
		}
	}
	handler := NewOutboundHandlerWithAcornFoxProbe(instanceID, nodeID, facts, runtime, groupRuntime, volumeRuntime, acornFoxRuntime, acornFoxProber)
	certificateID := ""
	if len(tlsConfig.Certificates) == 1 && len(tlsConfig.Certificates[0].Certificate) > 0 {
		certificate, parseErr := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
		if parseErr != nil {
			log.Fatal(parseErr)
		}
		certificateID = certificate.SerialNumber.String()
	}
	client := &agenttransport.Client{
		BaseURL:    controlPlaneURL,
		HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 5 * time.Second},
		Hello:      v1.Hello{InstanceID: instanceID, NodeID: nodeID, AgentVersion: version, Capabilities: capabilities, CertificateID: certificateID},
		Handler:    handler,
	}
	log.Printf("open-card agent protocol v1 actively connecting to control plane")
	if err := client.Run(context.Background()); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

type acornFoxRuntimeProvider interface {
	contracts.RuntimeDriver
	Recreate(context.Context, contracts.DeployRequest) (domain.Deployment, error)
	Reconcile(context.Context) error
}

// composeAcornFoxRuntime keeps the startup invariant testable: reconciliation
// happens before any runtime capability is returned to the caller. The legacy
// driver is deliberately returned too so existing clients remain compatible.
func composeAcornFoxRuntime(ctx context.Context, provider acornFoxRuntimeProvider) (contracts.RuntimeDriver, contracts.AcornFoxRuntimeDriver, []string, error) {
	if provider == nil {
		return nil, nil, nil, errors.New("standalone runtime is unavailable")
	}
	if err := provider.Reconcile(ctx); err != nil {
		return nil, nil, nil, err
	}
	acornFoxRuntime, err := application.NewAcornFoxRuntimeService(provider)
	if err != nil {
		return nil, nil, nil, err
	}
	return provider, acornFoxRuntime, []string{"runtime.deploy.digest", "runtime.observe", "runtime.logs", "runtime.restart", "runtime.destroy", v1.AgentCapabilityAcornFoxRuntime}, nil
}

func composeAcornFoxRuntimeWithProbe(ctx context.Context, provider acornFoxRuntimeProvider, buildProbe func() (acornFoxRuntimeProber, error)) (contracts.RuntimeDriver, contracts.AcornFoxRuntimeDriver, acornFoxRuntimeProber, []string, error) {
	if buildProbe == nil {
		return nil, nil, nil, nil, errors.New("AcornFox probe constructor is unavailable")
	}
	runtime, acornFoxRuntime, capabilities, err := composeAcornFoxRuntime(ctx, provider)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	prober, err := buildProbe()
	if err != nil || prober == nil {
		if err == nil {
			err = errors.New("AcornFox probe is unavailable")
		}
		return nil, nil, nil, nil, err
	}
	capabilities = append(capabilities, v1.AgentCapabilityAcornFoxProbe)
	if _, ok := provider.(contracts.AcornFoxBoundedLogReader); ok {
		capabilities = append(capabilities, v1.AgentCapabilityAcornFoxLogs)
	}
	return runtime, acornFoxRuntime, prober, capabilities, nil
}
