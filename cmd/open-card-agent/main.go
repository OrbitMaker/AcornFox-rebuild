package main

import (
	"context"
	"crypto/x509"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/acornfoxenv"
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

var processIdentity = "legacy"

func main() {
	environment, err := acornfoxenv.ResolveCurrent(acornfoxenv.ProcessAgent, processIdentity)
	if err != nil {
		log.Fatal(err)
	}
	run(environment)
}

func run(environment acornfoxenv.Environment) {
	getenv := environment.Get
	address, addressErr := resolveAgentListenerAddress(environment)
	if addressErr != nil {
		log.Fatal(addressErr)
	}
	instanceID := getenv(acornfoxenv.InstanceID)
	if instanceID == "" {
		instanceID = "local"
	}
	nodeID := getenv(acornfoxenv.NodeID)
	if nodeID == "" {
		nodeID = "local-node"
	}
	version := getenv(acornfoxenv.AgentVersion)
	if version == "" {
		version = "dev"
	}
	if controlPlaneURL := getenv(acornfoxenv.ControlPlaneURL); controlPlaneURL != "" {
		runOutboundAgent(controlPlaneURL, instanceID, nodeID, version, environment)
		return
	}
	agent := NewAgent(instanceID, nodeID, version)
	tlsConfig, err := loadMTLSConfig(
		getenv(acornfoxenv.AgentTLSCA),
		getenv(acornfoxenv.AgentTLSCert),
		getenv(acornfoxenv.AgentTLSKey),
	)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: address, Handler: agent.Handler(), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("%s agent protocol %s listening on %s", environment.ProductLabel(), "v1", address)
	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func resolveAgentListenerAddress(environment acornfoxenv.Environment) (string, error) {
	address := environment.Get(acornfoxenv.AgentAddr)
	if !environment.Clean() {
		if address == "" {
			return "127.0.0.1:8091", nil
		}
		return address, nil
	}
	if address == "" || address == "127.0.0.1:8091" {
		return "127.0.0.1:8091", nil
	}
	return "", errors.New("AcornFox clean runtime listener is invalid")
}

func runOutboundAgent(controlPlaneURL, instanceID, nodeID, version string, environment acornfoxenv.Environment) {
	getenv := environment.Get
	tlsConfig, err := loadOutboundMTLSConfig(
		getenv(acornfoxenv.AgentTLSCA),
		getenv(acornfoxenv.AgentTLSCert),
		getenv(acornfoxenv.AgentTLSKey),
		getenv(acornfoxenv.ControlPlaneServerName),
	)
	if err != nil {
		log.Fatal(err)
	}
	socketPath := getenv(acornfoxenv.DockerSocket)
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
	var acornFoxCandidateRuntime AcornFoxCandidateRuntime
	capabilities := []string{"docker.read.facts"}
	if getenv(acornfoxenv.RuntimeEnabled) == "true" {
		if getenv(acornfoxenv.WorkerNetworkIsolated) != "true" {
			log.Fatal("runtime deployment requires an externally isolated worker network")
		}
		store, storeErr := imageprovider.New(imageprovider.Config{Root: getenv(acornfoxenv.OCIStoreRoot)})
		if storeErr != nil {
			log.Fatal(storeErr)
		}
		reserveMemory := int64(256 << 20)
		if value := getenv(acornfoxenv.RuntimeReserveMemoryBytes); value != "" {
			parsed, parseErr := strconv.ParseInt(value, 10, 64)
			if parseErr != nil || parsed < 0 {
				log.Fatal("invalid runtime memory reserve")
			}
			reserveMemory = parsed
		}
		capacityConfig := capacity.Config{DiskPath: getenv(acornfoxenv.RuntimeWorkRoot), RuntimeReserve: contracts.ResourceLimits{CPUMillis: 250, MemoryBytes: reserveMemory, DiskBytes: 512 << 20}}
		if value := getenv(acornfoxenv.RuntimeFixedHostPort); value != "" {
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
		volumes, volumeErr := volumeprovider.New(volumeprovider.Config{TaskPrefix: getenv(acornfoxenv.RuntimeTaskPrefix)})
		if volumeErr != nil {
			log.Fatal(volumeErr)
		}
		volumeRuntime = volumes
		runtimeConfig := standalone.Config{
			Volumes:               volumes,
			TaskPrefix:            getenv(acornfoxenv.RuntimeTaskPrefix),
			Network:               getenv(acornfoxenv.RuntimeNetwork),
			WorkRoot:              getenv(acornfoxenv.RuntimeWorkRoot),
			ImageStore:            store,
			Capacity:              capacityProvider,
			WorkerNetworkIsolated: true,
		}
		bindInstalledRuntimeNetwork(&runtimeConfig, environment)
		standaloneRuntime, storeErr := standalone.New(runtimeConfig)
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
		candidateWorkRoot := filepath.Join(getenv(acornfoxenv.RuntimeWorkRoot), "candidates")
		candidateTaskPrefix := getenv(acornfoxenv.RuntimeTaskPrefix) + "-candidate"
		candidateNetwork := candidateTaskPrefix + "-network"
		if err := os.MkdirAll(candidateWorkRoot, 0o700); err != nil {
			log.Fatal("candidate runtime work root is unavailable")
		}
		candidateProvider, candidateErr := standalone.New(standalone.Config{TaskPrefix: candidateTaskPrefix, Network: candidateNetwork, WorkRoot: candidateWorkRoot, ImageStore: store, Capacity: capacityProvider, WorkerNetworkIsolated: false})
		if candidateErr != nil || candidateProvider.Reconcile(context.Background()) != nil {
			log.Fatal("candidate runtime is unavailable")
		}
		candidateProber, candidateErr := acornfoxprobe.New(acornfoxprobe.DefaultConfig(), time.Now)
		if candidateErr != nil {
			log.Fatal("candidate runtime probe is unavailable")
		}
		candidateInspector, candidateErr := newUnixAcornFoxCandidateContainerInspector(socketPath, candidateTaskPrefix, candidateNetwork)
		if candidateErr != nil {
			log.Fatal("candidate runtime inspector is unavailable")
		}
		acornFoxCandidateRuntime, candidateErr = newAcornFoxCandidateRuntimeAdapter(candidateProvider, candidateProber, candidateInspector)
		if candidateErr != nil {
			log.Fatal("candidate runtime adapter is unavailable")
		}
		capabilities = append(capabilities, v1.AgentCapabilityAcornFoxCandidateValidation)
		if getenv(acornfoxenv.M2Enabled) == "true" {
			var metricsReader standalonegroup.RuntimeMetricsReader
			if getenv(acornfoxenv.M4Enabled) == "true" {
				reader, readerErr := NewUnixDockerRuntimeMetricsReader(socketPath)
				if readerErr != nil {
					log.Fatal(readerErr)
				}
				metricsReader = m4GroupRuntimeMetricsAdapter{reader: reader}
			}
			groupRuntime, storeErr = standalonegroup.New(standalonegroup.Config{
				TaskPrefix: getenv(acornfoxenv.RuntimeTaskPrefix), Network: getenv(acornfoxenv.RuntimeGroupNetwork), WorkRoot: getenv(acornfoxenv.RuntimeWorkRoot),
				ImageStore: store, Capacity: capacityProvider, Volumes: volumes, MetricsReader: metricsReader, WorkerNetworkIsolated: true,
			})
			if storeErr != nil {
				log.Fatal(storeErr)
			}
			capabilities = append(capabilities, v1.AgentCapabilityRuntimeDeployGroup, v1.AgentCapabilityRuntimeObserveGroup, v1.AgentCapabilityRuntimeLogsGroup, v1.AgentCapabilityRuntimeRollbackGroup, v1.AgentCapabilityRuntimeDestroyGroup, v1.AgentCapabilityRuntimeRestartGroupService, v1.AgentCapabilityRuntimeRestartGroup)
		}
	}
	handler := NewOutboundHandlerWithAcornFoxProbe(instanceID, nodeID, facts, runtime, groupRuntime, volumeRuntime, acornFoxRuntime, acornFoxProber)
	handler = WithAcornFoxCandidateRuntime(handler, acornFoxCandidateRuntime)
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
	log.Printf("%s agent protocol v1 actively connecting to control plane", environment.ProductLabel())
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
	capabilities := []string{"runtime.deploy.digest", "runtime.observe", "runtime.logs", "runtime.restart", "runtime.destroy", v1.AgentCapabilityAcornFoxRuntime}
	if configured, ok := provider.(interface{ ConfiguredRuntimeSupported() bool }); ok && configured.ConfiguredRuntimeSupported() {
		capabilities = append(capabilities, v1.AgentCapabilityAcornFoxRuntimeConfig)
	}
	return provider, acornFoxRuntime, capabilities, nil
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
