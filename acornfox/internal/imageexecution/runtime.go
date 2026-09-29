package imageexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/dockermetrics"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/peer"
	capacityprovider "github.com/acornfox/acornfox/internal/providers/capacity"
	imageprovider "github.com/acornfox/acornfox/internal/providers/image"
	"github.com/acornfox/acornfox/internal/providers/registryhttp"
	"github.com/acornfox/acornfox/internal/providers/standalone"
	volumeprovider "github.com/acornfox/acornfox/internal/providers/volume"
)

type authCheckKey struct{}

func withAuthorityCheck(ctx context.Context, check func(context.Context) error) context.Context {
	return context.WithValue(ctx, authCheckKey{}, check)
}

type defaultCommandRunner struct{ dockerSocketPath string }

func (r defaultCommandRunner) Run(ctx context.Context, command string, args []string, stdout, stderr io.Writer) error {
	if command == "docker" {
		args = append([]string{"--host", "unix://" + r.dockerSocketPath}, args...)
	}
	cmd := exec.CommandContext(ctx, command, args...)
	if command == "docker" {
		// A Docker context or TLS setting must never redirect provider writes away
		// from the daemon sampled by the read-only metrics client.
		for _, entry := range os.Environ() {
			name, _, _ := strings.Cut(entry, "=")
			switch name {
			case "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION":
				continue
			}
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return cmd.Run()
}

type authorizingCommandRunner struct {
	base standalone.CommandRunner
}

func (r *authorizingCommandRunner) Run(ctx context.Context, command string, args []string, stdout, stderr io.Writer) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	isMutating := true
	if len(args) == 0 {
		return errors.New("empty docker command rejected")
	}
	switch args[0] {
	case "inspect", "logs", "version", "info":
		isMutating = false
	case "network", "volume", "container", "image":
		if len(args) < 3 {
			return errors.New("incomplete docker subcommand rejected")
		}
		if args[1] == "inspect" || boundedContainerAbsenceQuery(args) || boundedNetworkAbsenceQuery(args) {
			isMutating = false
		} else if (args[0] != "network" && args[0] != "volume") || (args[1] != "create" && args[1] != "rm") {
			return errors.New("unknown docker subcommand rejected")
		}
	case "load", "run", "rm", "create", "kill", "stop", "start", "restart":
	default:
		return errors.New("unknown docker command rejected")
	}
	if isMutating {
		checker, ok := ctx.Value(authCheckKey{}).(func(context.Context) error)
		if !ok || checker == nil {
			return errors.New("mutating docker command rejected: missing request-bound authority context")
		}
		if err := checker(ctx); err != nil {
			return fmt.Errorf("core authority rejected docker effect %s: %w", args[0], err)
		}
	}
	return r.base.Run(ctx, command, args, stdout, stderr)
}

// Only the provider's anchored name and full-ID absence probes are read-only list shapes.
func boundedContainerAbsenceQuery(args []string) bool {
	if len(args) != 7 || args[0] != "container" || args[1] != "ls" || args[2] != "--all" || args[3] != "--filter" || args[5] != "--format" {
		return false
	}
	filter := args[4]
	if args[6] == "{{.Names}}" && strings.HasPrefix(filter, "name=^/") && strings.HasSuffix(filter, "$") {
		name := strings.TrimSuffix(strings.TrimPrefix(filter, "name=^/"), "$")
		if len(name) == 0 || len(name) > 128 {
			return false
		}
		for _, c := range name {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
				return false
			}
		}
		return true
	}
	if args[6] == "{{.ID}}" && strings.HasPrefix(filter, "id=^") && strings.HasSuffix(filter, "$") {
		id := strings.TrimSuffix(strings.TrimPrefix(filter, "id=^"), "$")
		if len(id) != 64 {
			return false
		}
		for _, c := range id {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
		return true
	}
	return false
}

func boundedNetworkAbsenceQuery(args []string) bool {
	if len(args) != 6 || args[0] != "network" || args[1] != "ls" || args[2] != "--filter" || args[4] != "--format" || args[5] != "{{.ID}}" || !strings.HasPrefix(args[3], "name=^") || !strings.HasSuffix(args[3], "$") {
		return false
	}
	name := strings.TrimSuffix(strings.TrimPrefix(args[3], "name=^"), "$")
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// ContainerRuntime encapsulates host Docker execution providers guarded by Core authority.
type ContainerRuntime struct {
	taskPrefix      string
	workRoot        string
	imageStore      contracts.ImageStore
	registry        contracts.RegistryImageProvider
	capacity        contracts.CapacityProvider
	volumes         *volumeprovider.Provider
	standalone      *standalone.Provider
	metricsReader   dockermetrics.DockerRuntimeMetricsReader
	authorityClient *peer.Client
	locksMu         sync.Mutex
	locks           map[domain.ID]*sync.Mutex
}

// RuntimeConfig supplies host roots and authority parameters for container execution.
type RuntimeConfig struct {
	TaskPrefix          string
	WorkRoot            string
	ImageStoreRoot      string
	RegistryBaseURL     string
	AuthoritySocketPath string
	CoreUID             uint32 // account that must serve the Core authority socket
	DockerSocketPath    string
	Runner              standalone.CommandRunner
	Ports               standalone.PortAllocator
	Clock               func() time.Time
}

// NewContainerRuntime constructs production providers for container role execution.
func NewContainerRuntime(cfg RuntimeConfig) (*ContainerRuntime, error) {
	if cfg.AuthoritySocketPath == "" {
		return nil, errors.New("authority socket path is required for container role")
	}
	if cfg.Runner == nil && (cfg.DockerSocketPath == "" || !strings.HasPrefix(cfg.DockerSocketPath, "/") || strings.Contains(cfg.DockerSocketPath, "..")) {
		return nil, errors.New("absolute Docker socket path is required for container role")
	}
	if cfg.TaskPrefix == "" {
		cfg.TaskPrefix = "acornfox-"
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}

	authClient := peer.NewClient(cfg.AuthoritySocketPath, cfg.CoreUID, 5*time.Second)

	baseRunner := cfg.Runner
	if baseRunner == nil {
		baseRunner = defaultCommandRunner{dockerSocketPath: cfg.DockerSocketPath}
	}
	authRunner := &authorizingCommandRunner{base: baseRunner}

	imgStore, err := imageprovider.New(imageprovider.Config{
		Root: cfg.ImageStoreRoot,
	})
	if err != nil {
		return nil, fmt.Errorf("create image store: %w", err)
	}

	capProv, err := capacityprovider.New(capacityprovider.Config{})
	if err != nil {
		return nil, fmt.Errorf("create capacity provider: %w", err)
	}

	volProv, err := volumeprovider.New(volumeprovider.Config{
		TaskPrefix: cfg.TaskPrefix,
		Runner:     authRunner,
	})
	if err != nil {
		return nil, fmt.Errorf("create volume provider: %w", err)
	}

	regProv, err := registryhttp.New(registryhttp.Config{
		BaseURL:    cfg.RegistryBaseURL,
		ImageStore: imgStore,
		TempRoot:   cfg.WorkRoot,
		Timeout:    2 * time.Minute,
		Clock:      cfg.Clock,
	})
	if err != nil {
		return nil, fmt.Errorf("create registry provider: %w", err)
	}

	standProv, err := standalone.New(standalone.Config{
		NetworkProfile: standalone.ApplicationLoopbackNetworkProfile,
		TaskPrefix:     cfg.TaskPrefix,
		WorkRoot:       cfg.WorkRoot,
		ImageStore:     imgStore,
		Capacity:       capProv,
		Volumes:        volProv,
		Runner:         authRunner,
		Ports:          cfg.Ports,
		Clock:          cfg.Clock,
		Timeout:        2 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("create standalone provider: %w", err)
	}
	var metricsReader dockermetrics.DockerRuntimeMetricsReader
	if cfg.DockerSocketPath != "" {
		metricsReader, err = dockermetrics.NewUnixDockerRuntimeMetricsReader(cfg.DockerSocketPath, dockermetrics.ReadOptions{OmitChanges: true, OmitWritableLayerSize: true, AllowPartialUsage: true})
		if err != nil {
			return nil, fmt.Errorf("create Docker metrics reader: %w", err)
		}
	}

	return &ContainerRuntime{
		taskPrefix:      cfg.TaskPrefix,
		workRoot:        cfg.WorkRoot,
		imageStore:      imgStore,
		registry:        regProv,
		capacity:        capProv,
		volumes:         volProv,
		standalone:      standProv,
		metricsReader:   metricsReader,
		authorityClient: authClient,
		locks:           make(map[domain.ID]*sync.Mutex),
	}, nil
}

func (r *ContainerRuntime) lockDeployment(id domain.ID) func() {
	r.locksMu.Lock()
	l, ok := r.locks[id]
	if !ok {
		l = &sync.Mutex{}
		r.locks[id] = l
	}
	r.locksMu.Unlock()
	l.Lock()
	return l.Unlock
}

// Deploy serializes execution for deploymentID, authorizes against Core before each effect,
// pulls OCI layers, loads Docker, and observes.
func (r *ContainerRuntime) Deploy(ctx context.Context, req DeployRequest) DeployResponse {
	unlock := r.lockDeployment(req.DeploymentID)
	defer unlock()

	opContext := contracts.OperationContext{
		IdempotencyKey: fmt.Sprintf("deploy:%s", req.DeploymentID.String()),
		Deadline:       time.Now().UTC().Add(time.Duration(req.TimeoutSeconds) * time.Second),
	}

	// 1. Recompute and verify deterministic plan digest from canonical input and image digest
	computedDigest, err := appcontracts.ComputePlanDigest(req.CanonicalInput, req.ResolvedImage.Digest)
	if err != nil || computedDigest != req.PlanDigest {
		return DeployResponse{Success: false, Error: "plan digest recomputation mismatch"}
	}

	// 2. Validate mapped RuntimeSpec before any network or storage side effects
	mappedSpec, err := mappedImageRuntimeSpec(req, domain.ImageDigest{Repository: req.ResolvedImage.Repository, Digest: req.ResolvedImage.Digest})
	if err != nil {
		return DeployResponse{Error: err.Error()}
	}

	// 3. Authority check against Core: verifies live lease and binding facts
	facts, err := r.checkAuthority(ctx, req)
	if err != nil {
		return DeployResponse{Success: false, Error: "core authority rejected: " + err.Error()}
	}

	// 4. Verify authority-returned facts match execution parameters exactly
	if facts.PlanDigest != req.PlanDigest || facts.ApplicationID != req.ApplicationID ||
		facts.EnvironmentID != req.EnvironmentID || facts.ReleaseID != req.ReleaseID ||
		facts.ApprovedPort != req.CanonicalInput.Port {
		return DeployResponse{Success: false, Error: "core authority facts mismatch with request parameters"}
	}
	if facts.ImageOrigin == "source-build" {
		if req.ImageOrigin != "source-build" || facts.SourceArtifact == nil || facts.SourceArtifact.Image.Repository != req.ResolvedImage.Repository || facts.SourceArtifact.Image.Digest != req.ResolvedImage.Digest {
			return DeployResponse{Error: "Core source artifact differs from deployment"}
		}
	} else if facts.ImageOrigin != "" && facts.ImageOrigin != "registryhttp" || req.ImageOrigin == "source-build" || facts.SourceArtifact != nil {
		return DeployResponse{Error: "Core image origin differs from deployment"}
	}

	// 5. Inspect first: check if container already running and matching approved plan
	existing, obsErr := r.standalone.ObserveDeploymentSnapshot(ctx, contracts.ObserveRequest{DeploymentID: req.DeploymentID, Operation: opContext})
	if obsErr == nil && existing.Observation.Status == "running" {
		expected := mappedSpec
		expected.Image = existing.Image
		existing, err = r.standalone.ObserveExpectedDeploymentSnapshot(ctx, contracts.ObserveRequest{DeploymentID: req.DeploymentID, Operation: opContext}, expected)
		if err != nil {
			return DeployResponse{OutcomeUnknown: true, Error: err.Error()}
		}
		receipt, err := r.verifiedReceipt(ctx, req.OperationID, req.DeploymentID, opContext, existing, req)
		if err != nil {
			return DeployResponse{OutcomeUnknown: true, Error: err.Error()}
		}
		if receipt.ManifestDigest != req.ResolvedImage.Digest || receipt.ContainerPort != req.CanonicalInput.Port {
			return DeployResponse{OutcomeUnknown: true, Error: "existing receipt differs from approved request"}
		}
		if _, err := r.checkAuthority(ctx, req); err != nil {
			return DeployResponse{OutcomeUnknown: true, Error: err.Error()}
		}
		return deployReceipt(receipt)
	}

	if obsErr != nil {
		var providerError *contracts.ProviderError
		if !errors.As(obsErr, &providerError) || providerError.Code != contracts.ErrNotFound {
			return DeployResponse{OutcomeUnknown: true, Error: "existing runtime could not be verified: " + obsErr.Error()}
		}
	}

	// 6. Recheck authority before consuming or fetching the approved immutable archive.
	if _, err := r.checkAuthority(ctx, req); err != nil {
		return DeployResponse{Error: "authority check before archive failed: " + err.Error()}
	}

	manifestImage := domain.ImageDigest{Repository: req.ResolvedImage.Repository, Digest: req.ResolvedImage.Digest}
	archiveReader, storedArchive, err := r.imageStore.OpenOCI(ctx, manifestImage, opContext)
	if err != nil {
		var providerError *contracts.ProviderError
		if !errors.As(err, &providerError) || providerError.Code != contracts.ErrNotFound {
			return DeployResponse{Error: "open approved OCI archive: " + err.Error()}
		}
		if facts.ImageOrigin == "source-build" {
			return DeployResponse{OutcomeUnknown: true, Error: "source-built OCI archive is missing from Container role"}
		}
		// Preserve the store's typed missing classification, including missing recorded archive files.
		pullRes, pullErr := r.registry.ResolveAndPull(ctx, contracts.ImageResolveRequest{Repository: manifestImage.Repository, Tag: manifestImage.Digest, Operation: opContext})
		if pullErr != nil {
			return DeployResponse{Error: "pull image layers: " + pullErr.Error()}
		}
		if pullRes.Image.Repository != manifestImage.Repository || pullRes.Image.Digest != manifestImage.Digest {
			return DeployResponse{Error: "pulled image differs from approved manifest"}
		}
		archiveReader, storedArchive, err = r.imageStore.OpenOCI(ctx, manifestImage, opContext)
		if err != nil {
			return DeployResponse{Error: "open stored OCI archive: " + err.Error()}
		}
	}
	if facts.SourceArtifact != nil && (storedArchive.StorageRef != facts.SourceArtifact.StorageRef || storedArchive.Evidence.Digest != facts.SourceArtifact.ArchiveSHA256 || storedArchive.SizeBytes != facts.SourceArtifact.SizeBytes) {
		_ = archiveReader.Close()
		return DeployResponse{Error: "source-built OCI receipt differs from original Core artifact"}
	}

	archiveSeeker, ok := archiveReader.(io.ReadSeeker)
	if !ok {
		_ = archiveReader.Close()
		return DeployResponse{Error: "stored OCI archive is not seekable"}
	}
	identity, err := imageprovider.InspectOCI(ctx, archiveSeeker, manifestImage.Digest, storedArchive.SizeBytes)
	if err != nil {
		_ = archiveReader.Close()
		return DeployResponse{Error: "stored OCI archive cannot be verified: " + err.Error()}
	}
	archiveConfigDigest := identity.ConfigDigest

	imageLocator, err := r.standalone.SelectImageLocator(ctx, manifestImage, archiveConfigDigest, opContext)
	if err != nil {
		_ = archiveReader.Close()
		return DeployResponse{Error: "select expected image locator: " + err.Error()}
	}
	if imageLocator.Digest != manifestImage.Digest {
		// Classic backends require the archive keyed by their config image locator.
		storeOp := opContext
		storeOp.IdempotencyKey += ":config-id-store"
		if _, err := archiveSeeker.Seek(0, io.SeekStart); err != nil {
			_ = archiveReader.Close()
			return DeployResponse{Error: "rewind OCI archive: " + err.Error()}
		}
		if _, err := r.imageStore.StoreOCI(ctx, contracts.StoreOCIRequest{Image: imageLocator, StorageKey: "engine-id-" + strings.TrimPrefix(imageLocator.Digest, "sha256:"), Archive: archiveSeeker, Operation: storeOp}); err != nil {
			_ = archiveReader.Close()
			return DeployResponse{Error: "register OCI archive under expected image locator: " + err.Error()}
		}
	}
	if err := archiveReader.Close(); err != nil {
		return DeployResponse{Error: "close verified OCI archive: " + err.Error()}
	}

	// 9. Build mapped RuntimeSpec and Deploy to Docker
	// (Request-bound authority in reqCtx guards every mutating Docker command!)
	reqCtx := withAuthorityCheck(ctx, func(cmdCtx context.Context) error {
		_, err := r.checkAuthority(cmdCtx, req)
		return err
	})

	spec := mappedSpec
	spec.Image = imageLocator

	_, err = r.standalone.Deploy(reqCtx, contracts.DeployRequest{
		DeploymentID: req.DeploymentID,
		Spec:         spec,
		Operation:    opContext,
	})
	if err != nil {
		outcomeUnknown := contracts.IsProviderOutcomeUnknown(err) || errors.Is(err, context.DeadlineExceeded)
		return DeployResponse{Success: false, OutcomeUnknown: outcomeUnknown, Error: "standalone deploy: " + err.Error()}
	}

	snapshot, err := r.standalone.ObserveExpectedDeploymentSnapshot(ctx, contracts.ObserveRequest{DeploymentID: req.DeploymentID, Operation: opContext}, spec)
	if err != nil {
		return DeployResponse{OutcomeUnknown: true, Error: err.Error()}
	}
	if snapshot.Observation.Status != "running" {
		return DeployResponse{OutcomeUnknown: true, Error: "container deployed but not running"}
	}
	receipt, err := r.verifiedReceipt(ctx, req.OperationID, req.DeploymentID, opContext, snapshot, req)
	if err != nil {
		return DeployResponse{OutcomeUnknown: true, Error: err.Error()}
	}
	if _, err := r.checkAuthority(ctx, req); err != nil {
		return DeployResponse{OutcomeUnknown: true, Error: err.Error()}
	}
	return deployReceipt(receipt)
}

func deployReceipt(v ObserveResponse) DeployResponse {
	return DeployResponse{Success: true, ContainerID: v.ContainerID, ContainerName: v.ContainerName, ImageID: v.ImageID, ManifestDigest: v.ManifestDigest, StorageRef: v.StorageRef, ContentDigest: v.ContentDigest, SizeBytes: v.SizeBytes, HostPort: v.HostPort, ContainerPort: v.ContainerPort, HostIP: v.HostIP, Protocol: v.Protocol, ObservedAt: v.ObservedAt}
}

func (r *ContainerRuntime) Observe(ctx context.Context, req ObserveRequest) ObserveResponse {
	op := contracts.OperationContext{IdempotencyKey: "observe:" + req.DeploymentID.String(), Deadline: time.Now().UTC().Add(30 * time.Second)}
	snapshot, err := r.standalone.ObserveDeploymentSnapshot(ctx, contracts.ObserveRequest{DeploymentID: req.DeploymentID, Operation: op})
	if err != nil {
		return ObserveResponse{Error: err.Error()}
	}
	receipt, err := r.verifiedReceipt(ctx, req.OperationID, req.DeploymentID, op, snapshot)
	if err != nil {
		return ObserveResponse{Error: err.Error()}
	}
	return receipt
}

// verifiedReceipt joins Core's authenticated binding with one inspected provider snapshot and its OCI archive.
func (r *ContainerRuntime) verifiedReceipt(ctx context.Context, operationID, deploymentID domain.ID, op contracts.OperationContext, snapshot standalone.DeploymentObservationSnapshot, expected ...DeployRequest) (ObserveResponse, error) {
	payload, err := json.Marshal(ObserveBindingRequest{OperationID: operationID, DeploymentID: deploymentID})
	if err != nil {
		return ObserveResponse{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/authority/observe-binding", bytes.NewReader(payload))
	if err != nil {
		return ObserveResponse{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	if r.authorityClient == nil {
		return ObserveResponse{}, errors.New("authority client is not configured")
	}
	response, body, err := r.authorityClient.Do(request)
	if err != nil {
		return ObserveResponse{}, err
	}
	if response.StatusCode != http.StatusOK {
		return ObserveResponse{}, fmt.Errorf("observe binding status %d", response.StatusCode)
	}
	var binding ObserveBindingResponse
	if err := decodeStrictJSON(bytes.NewReader(body), &binding); err != nil {
		return ObserveResponse{}, err
	}
	if len(expected) != 0 {
		want := expected[0]
		if binding.PlanDigest != want.PlanDigest || binding.Repository != want.ResolvedImage.Repository || binding.Digest != want.ResolvedImage.Digest || binding.ApplicationID != want.ApplicationID || binding.EnvironmentID != want.EnvironmentID || binding.ReleaseID != want.ReleaseID || binding.ApprovedPort != want.CanonicalInput.Port || (want.ImageOrigin == "source-build") != (binding.ImageOrigin == "source-build") {
			return ObserveResponse{}, errors.New("Core observation binding differs from approved request")
		}
	}
	obs := snapshot.Observation
	if !binding.Valid || binding.PlanDigest == "" || snapshot.Deployment.ID != deploymentID || binding.ApplicationID != snapshot.Deployment.ApplicationID || binding.EnvironmentID != snapshot.Deployment.EnvironmentID || binding.ReleaseID != snapshot.Deployment.ReleaseID || binding.Repository != snapshot.Image.Repository || binding.ApprovedPort != snapshot.ContainerPort || snapshot.ContainerName == "" || snapshot.Image.Digest == "" || obs.ContainerID == "" || obs.ObservedAt.IsZero() {
		return ObserveResponse{}, errors.New("Core binding differs from verified runtime snapshot")
	}
	if binding.ImageOrigin == "source-build" {
		if binding.SourceArtifact == nil || binding.SourceArtifact.ApplicationID != binding.ApplicationID || binding.SourceArtifact.EnvironmentID != binding.EnvironmentID || binding.SourceArtifact.Image.Repository != binding.Repository || binding.SourceArtifact.Image.Digest != binding.Digest {
			return ObserveResponse{}, errors.New("Core source artifact differs from observation binding")
		}
		if binding.CanonicalInput == nil || binding.CanonicalInput.Repository != binding.Repository || binding.CanonicalInput.ResolvedRef != binding.Digest || binding.CanonicalInput.Port != binding.ApprovedPort {
			return ObserveResponse{}, errors.New("Core source canonical runtime facts are incomplete")
		}
		recomputed, digestErr := appcontracts.ComputePlanDigest(*binding.CanonicalInput, binding.Digest)
		if digestErr != nil || recomputed != binding.PlanDigest {
			return ObserveResponse{}, errors.New("Core source plan digest differs from canonical runtime facts")
		}
		expectedSpec, specErr := mappedImageRuntimeSpec(DeployRequest{ApplicationID: binding.ApplicationID, EnvironmentID: binding.EnvironmentID, ReleaseID: binding.ReleaseID, CanonicalInput: *binding.CanonicalInput}, snapshot.Image)
		if specErr != nil {
			return ObserveResponse{}, specErr
		}
		verifiedSnapshot, verifyErr := r.standalone.ObserveExpectedDeploymentSnapshot(ctx, contracts.ObserveRequest{DeploymentID: deploymentID, Operation: op}, expectedSpec)
		if verifyErr != nil {
			return ObserveResponse{}, verifyErr
		}
		snapshot = verifiedSnapshot
		obs = snapshot.Observation
	} else if binding.ImageOrigin != "" && binding.ImageOrigin != "registryhttp" || binding.SourceArtifact != nil {
		return ObserveResponse{}, errors.New("Core image origin is invalid")
	}
	reader, stored, err := r.imageStore.OpenOCI(ctx, domain.ImageDigest{Repository: binding.Repository, Digest: binding.Digest}, op)
	if err != nil {
		return ObserveResponse{}, fmt.Errorf("open bound OCI receipt: %w", err)
	}
	seeker, ok := reader.(io.ReadSeeker)
	if !ok {
		_ = reader.Close()
		return ObserveResponse{}, errors.New("bound OCI archive is not seekable")
	}
	identity, err := imageprovider.InspectOCI(ctx, seeker, binding.Digest, stored.SizeBytes)
	closeErr := reader.Close()
	if err != nil {
		return ObserveResponse{}, err
	}
	if closeErr != nil {
		return ObserveResponse{}, closeErr
	}
	manifest, config := identity.ManifestDigest, identity.ConfigDigest
	if binding.SourceArtifact != nil && (stored.StorageRef != binding.SourceArtifact.StorageRef || stored.Evidence.Digest != binding.SourceArtifact.ArchiveSHA256 || stored.SizeBytes != binding.SourceArtifact.SizeBytes) {
		return ObserveResponse{}, errors.New("bound source OCI receipt differs from original artifact")
	}
	if snapshot.Image.Digest != config && snapshot.Image.Digest != manifest {
		return ObserveResponse{}, errors.New("inspected engine image differs from verified OCI manifest/config")
	}
	return ObserveResponse{Success: true, Status: obs.Status, Running: obs.Status == "running", ContainerID: obs.ContainerID, ContainerName: snapshot.ContainerName, ImageID: snapshot.Image.Digest, ManifestDigest: manifest, StorageRef: stored.StorageRef, ContentDigest: stored.Evidence.Digest, SizeBytes: stored.SizeBytes, HostPort: obs.HostPort, ContainerPort: snapshot.ContainerPort, HostIP: "127.0.0.1", Protocol: "http", ObservedAt: obs.ObservedAt}, nil
}

func (r *ContainerRuntime) checkAuthority(ctx context.Context, req DeployRequest) (AuthorityCheckResponse, error) {
	if r.authorityClient == nil {
		return AuthorityCheckResponse{}, errors.New("authority client is not configured")
	}

	authReq := AuthorityCheckRequest{
		TaskID:          req.TaskID,
		OperationID:     req.OperationID,
		DeploymentID:    req.DeploymentID,
		PlanDigest:      req.PlanDigest,
		Owner:           req.TaskOwner,
		CoreGeneration:  req.CoreGeneration,
		LeaseGeneration: req.LeaseGeneration,
	}
	payload, err := json.Marshal(authReq)
	if err != nil {
		return AuthorityCheckResponse{}, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/authority/check", bytes.NewReader(payload))
	if err != nil {
		return AuthorityCheckResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, body, err := r.authorityClient.Do(httpReq)
	if err != nil {
		return AuthorityCheckResponse{}, fmt.Errorf("call core authority: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return AuthorityCheckResponse{}, fmt.Errorf("core authority returned status %d: %s", resp.StatusCode, string(body))
	}

	var authResp AuthorityCheckResponse
	if err := decodeStrictJSON(bytes.NewReader(body), &authResp); err != nil {
		return AuthorityCheckResponse{}, fmt.Errorf("decode authority response: %w", err)
	}
	if !authResp.Authorized {
		return authResp, errors.New("authority rejected: " + authResp.Error)
	}
	return authResp, nil
}

// mappedImageRuntimeSpec is the single deploy/lifecycle mapping of approved
// environment, volumes, effective resources and their canonical config digest.
func mappedImageRuntimeSpec(req DeployRequest, image domain.ImageDigest) (contracts.RuntimeSpec, error) {
	runtimeConfig := &contracts.AcornFoxRuntimeConfiguration{}
	for _, env := range req.CanonicalInput.Environment {
		kind := contracts.RuntimeEnvironmentKind(env.Kind)
		if kind == "" {
			kind = contracts.RuntimeEnvironmentLiteral
		}
		runtimeConfig.Environment = append(runtimeConfig.Environment, contracts.RuntimeEnvironmentVariable{
			Name:  env.Name,
			Value: env.Value,
			Kind:  kind,
		})
	}
	for _, vol := range req.CanonicalInput.Volumes {
		runtimeConfig.Volumes = append(runtimeConfig.Volumes, contracts.AcornFoxRuntimeVolume{
			Name:      vol.Name,
			MountPath: vol.MountPath,
			SizeBytes: vol.SizeBytes,
			ReadOnly:  vol.ReadOnly,
		})
	}
	if err := runtimeConfig.Validate(); err != nil {
		return contracts.RuntimeSpec{}, fmt.Errorf("invalid runtime configuration: %w", err)
	}

	diskBytes := req.CanonicalInput.Resources.DiskReservationBytes
	if diskBytes <= 0 {
		diskBytes = 1 << 30
	}
	pids := req.CanonicalInput.Resources.PIDs
	if pids <= 0 {
		pids = 128
	}

	runtimeResources := contracts.ResourceLimits{CPUMillis: req.CanonicalInput.Resources.CPUMillis, MemoryBytes: req.CanonicalInput.Resources.MemoryBytes, DiskBytes: diskBytes, PIDs: pids}
	runtimeConfigDigest, err := contracts.CanonicalAcornFoxRuntimeConfigDigest(*runtimeConfig, contracts.AcornFoxRuntimeRequestedResources{CPUMillis: runtimeResources.CPUMillis, MemoryBytes: runtimeResources.MemoryBytes, DiskReservationBytes: runtimeResources.DiskBytes, PIDs: runtimeResources.PIDs}, req.CanonicalInput.Port)
	if err != nil {
		return contracts.RuntimeSpec{}, fmt.Errorf("invalid mapped runtime configuration: %w", err)
	}

	return contracts.RuntimeSpec{ApplicationID: req.ApplicationID, EnvironmentID: req.EnvironmentID, ReleaseID: req.ReleaseID, ServiceName: "web", Image: image, Port: req.CanonicalInput.Port, Resources: runtimeResources, Configuration: runtimeConfig, ConfigDigest: runtimeConfigDigest}, nil
}
