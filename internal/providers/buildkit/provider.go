// Package buildkit implements the Open Card BuildProvider against a preexisting
// rootless BuildKit worker selected through a bounded buildctl Unix socket. It owns
// neither the builder process nor its host/VM isolation: those are deployment
// prerequisites which must be attested before this provider is enabled.
package buildkit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/acornfoxrelease"
	"github.com/open-card/open-card/internal/buildnetwork"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
	"github.com/open-card/open-card/internal/importers/dockerfile"
)

const (
	// MemoryLimitBytes and CPULimitMillis mirror the required worker cgroup
	// policy: MemoryMax=512M and CPUQuota=50% on one CPU period.
	MemoryLimitBytes int64 = 512 * 1024 * 1024
	CPULimitMillis   int64 = 500
	DefaultTimeout         = 5 * time.Minute
	maxCaptureBytes        = 1 << 20
)

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// CommandRunner permits unit tests to assert the exact command boundary
// without requiring Docker, buildx, or a running BuildKit daemon.
type CommandRunner interface {
	Run(ctx context.Context, command string, args []string, stdout, stderr io.Writer) error
}
type BuildLogSink interface {
	// StoreBuildLog durably persists a completed BuildKit log and returns the
	// durable reference that callers may expose in BuildResult. A sink must not
	// synthesize a reference for content it did not persist.
	StoreBuildLog(context.Context, contracts.BuildRequest, string) (string, error)
}

// WorkerPolicyAttestor is a read-only boundary to the independently
// provisioned worker. P1 verifies only a typed digest receipt; P2 must prove
// that the worker enforces the policy itself.
type WorkerPolicyAttestor interface {
	AttestWorkerPolicy(context.Context, WorkerPolicyAttestationRequest) (WorkerPolicyAttestationReceipt, error)
}

type WorkerPolicyAttestationRequest = buildnetwork.AttestationRequest
type WorkerPolicyAttestationReceipt = buildnetwork.AttestationReceipt

// controlledEgressAuthority is deliberately opaque outside this package. It
// can only be sealed from AcornFox's canonical P0 input and policy files.
type controlledEgressAuthority struct {
	policyDigest         string
	sealed               bool
	offlineBuildRequired bool
}

func sealControlledEgressAuthority(inputsRaw, policyRaw []byte) (controlledEgressAuthority, error) {
	inputs, _, err := acornfoxrelease.ParseProductBuildInputsV1(inputsRaw, policyRaw)
	if err != nil {
		return controlledEgressAuthority{}, err
	}
	return controlledEgressAuthority{policyDigest: inputs.ControlledEgressPolicySHA, sealed: true, offlineBuildRequired: true}, nil
}

func (a controlledEgressAuthority) matches(digest string) bool {
	return a.sealed && contracts.IsSHA256Digest(a.policyDigest) && a.policyDigest == digest
}

func attestationMatches(r WorkerPolicyAttestationReceipt, request WorkerPolicyAttestationRequest) bool {
	return r.SchemaVersion == 1 && request.SchemaVersion == 1 && contracts.IsSHA256Digest(r.PolicyDigest) && r.PolicyDigest == request.PolicyDigest && r.RequestFingerprint != "" && r.RequestFingerprint == request.RequestFingerprint
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, command string, args []string, stdout, stderr io.Writer) error {
	// buildctl's anonymous registry auth session still needs a writable home.
	// A fresh private directory prevents it from reading host Docker credentials.
	home, err := os.MkdirTemp("", "acornfox-buildctl-home-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(home)
	cmd := exec.CommandContext(ctx, command, args...)
	// Never inherit the controller process environment: proxy, cloud, registry,
	// database, and ambient credential variables have no place at buildctl's
	// process boundary. Commands are absolute in production configuration; the
	// fixed PATH exists only for standard helper lookup.
	// Registry challenge URLs are untrusted build input. Fetch anonymous tokens
	// inside the isolated daemon, never through the controller-side client.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=" + home, "DOCKER_CONFIG=" + filepath.Join(home, ".docker"), "BUILDKIT_NO_CLIENT_TOKEN=true"}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

// Config names an already provisioned, rootless BuildKit worker and the local
// source staging root. The provider does not create builders, reconfigure
// cgroups, or alter any host/VM resources.
type Config struct {
	Command            string
	Builder            string
	Address            string
	WorkspaceRoot      string
	WorkRoot           string
	StaticServerBinary string
	Timeout            time.Duration
	ImageStore         contracts.ImageStore
	Capacity           contracts.CapacityProvider
	SecretResolver     contracts.BuildSecretResolver
	Runner             CommandRunner
	LogSink            BuildLogSink
	// ControlledEgressInputsRaw and ControlledEgressPolicyRaw must be the two
	// canonical P0 files. New parses them into an opaque authority, then clears
	// the raw bytes; callers never provide a free-form policy digest.
	ControlledEgressInputsRaw []byte
	ControlledEgressPolicyRaw []byte
	WorkerPolicyAttestor      WorkerPolicyAttestor
	// ProductionNetworkPolicyRaw is the distinct installed build-execution
	// policy. It must not be mixed with the source-specific self-build proof.
	ProductionNetworkPolicyRaw []byte
	// RequireLogSink keeps legacy BuildKit composition optional while allowing
	// a composition root to require durable logs for every build it serves.
	// AcornFox-bound plans require a sink regardless of this switch.
	RequireLogSink bool

	controlledEgress controlledEgressAuthority
}

func (c Config) normalized() (Config, error) {
	if c.Command == "" {
		c.Command = "buildctl"
	}
	if strings.TrimSpace(c.Builder) == "" || !safeName.MatchString(c.Builder) {
		return Config{}, fmt.Errorf("buildkit builder must be a safe non-empty name")
	}
	if c.ImageStore == nil {
		return Config{}, fmt.Errorf("buildkit persistent image store is required")
	}
	if c.Capacity == nil {
		return Config{}, fmt.Errorf("buildkit capacity provider is required")
	}
	if c.Address == "" {
		c.Address = "unix:///run/open-card-buildkit/buildkitd.sock"
	}
	if (!strings.HasPrefix(c.Address, "unix:///run/open-card-buildkit/") && c.Address != "unix:///run/acornfox-buildkit/buildkitd.sock") || strings.Contains(c.Address, "..") || strings.ContainsAny(c.Address, "\r\n\x00 ") {
		return Config{}, fmt.Errorf("buildkit address must be a bounded worker unix socket")
	}
	var err error
	if c.WorkspaceRoot, err = absoluteDirectory(c.WorkspaceRoot); err != nil {
		return Config{}, fmt.Errorf("buildkit workspace root: %w", err)
	}
	if strings.TrimSpace(c.WorkRoot) == "" {
		c.WorkRoot = filepath.Join(os.TempDir(), "open-card-buildkit")
	}
	if c.WorkRoot, err = filepath.Abs(c.WorkRoot); err != nil {
		return Config{}, fmt.Errorf("buildkit work root: %w", err)
	}
	if c.StaticServerBinary != "" {
		if c.StaticServerBinary, err = filepath.Abs(c.StaticServerBinary); err != nil {
			return Config{}, fmt.Errorf("static server binary: %w", err)
		}
		info, statErr := os.Lstat(c.StaticServerBinary)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return Config{}, fmt.Errorf("static server binary must be a regular file")
		}
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	if c.Timeout <= 0 {
		return Config{}, fmt.Errorf("buildkit timeout must be positive")
	}
	if c.Runner == nil {
		c.Runner = execRunner{}
	}
	if c.RequireLogSink && c.LogSink == nil {
		return Config{}, fmt.Errorf("buildkit durable log sink is required")
	}
	hasInputs := len(c.ControlledEgressInputsRaw) != 0
	hasPolicy := len(c.ControlledEgressPolicyRaw) != 0
	hasProduction := len(c.ProductionNetworkPolicyRaw) != 0
	if hasInputs != hasPolicy || (hasInputs && hasProduction) || (hasInputs || hasProduction) != (c.WorkerPolicyAttestor != nil) {
		return Config{}, fmt.Errorf("buildkit controlled egress requires one canonical policy digest and live worker attestor")
	}
	if hasInputs {
		authority, err := sealControlledEgressAuthority(c.ControlledEgressInputsRaw, c.ControlledEgressPolicyRaw)
		if err != nil {
			return Config{}, fmt.Errorf("buildkit controlled egress policy is invalid")
		}
		c.controlledEgress = authority
		c.ControlledEgressInputsRaw = nil
		c.ControlledEgressPolicyRaw = nil
	}
	if hasProduction {
		if c.Address != "unix://"+buildnetwork.BuildkitSocketPath || c.Command != "/opt/acornfox/current/bin/buildctl" {
			return Config{}, fmt.Errorf("production buildkit must use the attested worker socket and installed buildctl")
		}
		_, digest, err := buildnetwork.ParsePolicy(c.ProductionNetworkPolicyRaw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid installed build execution policy")
		}
		c.controlledEgress = controlledEgressAuthority{policyDigest: digest, sealed: true}
		c.ProductionNetworkPolicyRaw = nil
	}
	return c, nil
}

func absoluteDirectory(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("is not a directory")
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

func safeRepository(value string) bool {
	if strings.Contains(value, "..") || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if !safeName.MatchString(part) {
			return false
		}
	}
	return true
}

// Provider is a one-build-at-a-time BuildProvider. It makes cancellation
// idempotent and keeps successful results stable for an operation key.
type Provider struct {
	config Config
	info   contracts.ProviderMetadata

	mu        sync.Mutex
	records   map[string]*record
	cancelled map[string]bool
	slot      chan struct{}
}

type record struct {
	fingerprint string
	done        chan struct{}
	result      contracts.BuildResult
	err         error
	cancel      context.CancelFunc
}

func New(config Config) (*Provider, error) {
	config, err := config.normalized()
	if err != nil {
		return nil, err
	}
	return &Provider{
		config: config,
		info: contracts.ProviderMetadata{
			Name:            "rootless-buildkit-buildctl",
			Version:         "v1",
			ContractVersion: contracts.ContractAPIVersion,
			Capabilities:    contracts.NewCapabilitySet(contracts.CapabilityBuild),
			SensitiveInputs: []string{"build secrets"},
		},
		records:   make(map[string]*record),
		cancelled: make(map[string]bool),
		slot:      make(chan struct{}, 1),
	}, nil
}

// NewProvider is an explicit alias for composition roots.
func NewProvider(config Config) (*Provider, error) { return New(config) }

func (p *Provider) Metadata(context.Context) contracts.ProviderMetadata { return p.info }

func (p *Provider) Build(ctx context.Context, request contracts.BuildRequest) (contracts.BuildResult, error) {
	if err := p.validateRequest(ctx, request); err != nil {
		return contracts.BuildResult{}, err
	}
	fingerprint := requestFingerprint(request)
	key := request.Operation.IdempotencyKey
	p.mu.Lock()
	if p.cancelled[key] {
		p.mu.Unlock()
		return contracts.BuildResult{}, p.providerError(request.Operation, contracts.ErrCancelled, "build operation was cancelled", contracts.RetryAfterReconnect, true, context.Canceled)
	}
	if prior, ok := p.records[key]; ok {
		if prior.fingerprint != fingerprint {
			p.mu.Unlock()
			return contracts.BuildResult{}, p.providerError(request.Operation, contracts.ErrConflict, "idempotency key was reused for a different build plan", contracts.RetryNever, false, nil)
		}
		p.mu.Unlock()
		select {
		case <-prior.done:
			return cloneResult(prior.result), prior.err
		case <-ctx.Done():
			return contracts.BuildResult{}, p.contextError(request.Operation, ctx.Err())
		}
	}
	record := &record{fingerprint: fingerprint, done: make(chan struct{})}
	p.records[key] = record
	p.mu.Unlock()

	result, err := p.run(ctx, request, record)
	p.mu.Lock()
	record.result, record.err = cloneResult(result), err
	record.cancel = nil
	close(record.done)
	p.mu.Unlock()
	return result, err
}

func (p *Provider) Cancel(ctx context.Context, operation contracts.OperationContext) error {
	if err := operation.Validate(); err != nil {
		return p.providerError(operation, contracts.ErrInvalidArgument, "provider idempotency key is required", contracts.RetryNever, false, err)
	}
	if err := ctx.Err(); err != nil {
		return p.contextError(operation, err)
	}
	p.mu.Lock()
	p.cancelled[operation.IdempotencyKey] = true
	if current := p.records[operation.IdempotencyKey]; current != nil && current.cancel != nil {
		current.cancel()
	}
	p.mu.Unlock()
	return nil
}

func (p *Provider) validateRequest(ctx context.Context, request contracts.BuildRequest) error {
	if err := ctx.Err(); err != nil {
		return p.contextError(request.Operation, err)
	}
	if err := request.Operation.Validate(); err != nil {
		return p.providerError(request.Operation, contracts.ErrInvalidArgument, "provider idempotency key is required", contracts.RetryNever, false, err)
	}
	if err := request.Plan.Validate(); err != nil {
		return p.providerError(request.Operation, contracts.ErrValidation, "build plan is invalid", contracts.RetryNever, false, err)
	}
	if err := validatePlanNetworkIdentity(request.Plan, request.Network); err != nil {
		return p.providerError(request.Operation, contracts.ErrForbidden, "build network policy does not match the immutable build plan", contracts.RetryNever, false, err)
	}
	if err := validateAcornFoxPlan(request.Plan); err != nil {
		return p.providerError(request.Operation, contracts.ErrValidation, "AcornFox build plan is invalid", contracts.RetryNever, false, err)
	}
	if err := p.validateNetwork(request.Plan, request.Network); err != nil {
		return p.providerError(request.Operation, contracts.ErrForbidden, "build network policy is unavailable", contracts.RetryNever, false, err)
	}
	if err := domain.RequireID(request.BuildID, "build id"); err != nil {
		return p.providerError(request.Operation, contracts.ErrValidation, "build id is invalid", contracts.RetryNever, false, err)
	}
	if err := request.Source.Validate(); err != nil || request.Source.ID != request.Plan.SourceRevisionID || request.Source.ContentDigest != request.Plan.SourceDigest {
		return p.providerError(request.Operation, contracts.ErrValidation, "source revision does not match build plan", contracts.RetryNever, false, err)
	}
	workspace, workspaceErr := filepath.EvalSymlinks(request.Source.WorkspaceRef)
	workspaceRoot, rootErr := filepath.EvalSymlinks(p.config.WorkspaceRoot)
	if workspaceErr != nil || rootErr != nil || !within(workspaceRoot, workspace) {
		return p.providerError(request.Operation, contracts.ErrForbidden, "source workspace is outside provider boundary", contracts.RetryNever, false, nil)
	}
	if len(request.Plan.SecretRefs) > 0 && p.config.SecretResolver == nil {
		return p.providerError(request.Operation, contracts.ErrUnavailable, "build secret resolver is unavailable", contracts.RetryUserAction, false, nil)
	}
	if !safeName.MatchString(request.Plan.ServiceName) {
		return p.providerError(request.Operation, contracts.ErrValidation, "build service name is invalid", contracts.RetryNever, false, nil)
	}
	if err := validateResources(request.Resources); err != nil {
		return p.providerError(request.Operation, contracts.ErrValidation, "build resources violate rootless worker policy", contracts.RetryNever, false, err)
	}
	if request.Capacity == nil || request.Capacity.Scope != contracts.CapacityBuild || !sameCapacityResources(request.Capacity.Resources, request.Resources) {
		return p.providerError(request.Operation, contracts.ErrCapacity, "build capacity lease is missing or does not match resources", contracts.RetryBackoff, true, nil)
	}
	if requiresDurableLog(request.Plan) && p.config.LogSink == nil {
		return p.providerError(request.Operation, contracts.ErrUnavailable, "build durable log sink is unavailable", contracts.RetryUserAction, false, nil)
	}
	return nil
}

func validatePlanNetworkIdentity(plan domain.BuildPlan, network contracts.NetworkPolicy) error {
	if err := network.Validate(); err != nil {
		return err
	}
	mode, workerPolicyDigest := plan.EffectiveAcornFoxNetworkPolicy()
	if string(network.EffectiveMode()) != mode || network.WorkerPolicyDigest != workerPolicyDigest {
		return errors.New("build request network policy does not match immutable build plan")
	}
	return nil
}

func requiresDurableLog(plan domain.BuildPlan) bool {
	return plan.AcornFoxDefinitionDigest != "" && plan.AcornFoxDockerfileDigest != ""
}

func validateAcornFoxPlan(plan domain.BuildPlan) error {
	if !requiresDurableLog(plan) {
		return nil
	}
	if plan.Kind != domain.BuildDockerfile || plan.ContextPath != "." || plan.DockerfilePath != "Dockerfile" {
		return errors.New("AcornFox build plan must use the root Dockerfile")
	}
	return nil
}

func validateAcornFoxDefinitionAgainstPlan(source domain.SourceRevision, plan domain.BuildPlan) error {
	if !requiresDurableLog(plan) {
		return nil
	}
	definition, err := dockerfile.Import(source)
	if err != nil {
		return err
	}
	if definition.Status != contracts.AcornFoxDockerfileReady || definition.DefinitionDigest != plan.AcornFoxDefinitionDigest || definition.DockerfileDigest != plan.AcornFoxDockerfileDigest {
		return errors.New("bound AcornFox Dockerfile definition digest changed")
	}
	return nil
}

func sameCapacityResources(left, right contracts.ResourceLimits) bool {
	return left.CPUMillis == right.CPUMillis && left.MemoryBytes == right.MemoryBytes && left.DiskBytes == right.DiskBytes && left.ConcurrencySlot == right.ConcurrencySlot && left.PIDs == right.PIDs
}

func validateResources(resources contracts.ResourceLimits) error {
	if resources.MemoryBytes != 0 && resources.MemoryBytes != MemoryLimitBytes {
		return fmt.Errorf("memory must be %d bytes", MemoryLimitBytes)
	}
	if resources.CPUMillis != 0 && resources.CPUMillis != CPULimitMillis {
		return fmt.Errorf("cpu must be %d millis", CPULimitMillis)
	}
	if resources.DiskBytes <= 0 {
		return errors.New("positive build disk capacity is required")
	}
	if resources.TimeoutSeconds < 0 {
		return errors.New("timeout must not be negative")
	}
	if resources.ConcurrencySlot != 0 && resources.ConcurrencySlot != 1 {
		return errors.New("only concurrency slot 1 is supported")
	}
	if resources.PIDs != 0 {
		return errors.New("build PID capacity is owned by the isolated worker service")
	}
	return nil
}

func (p *Provider) validateNetwork(plan domain.BuildPlan, network contracts.NetworkPolicy) error {
	if err := network.Validate(); err != nil {
		return err
	}
	if network.EffectiveMode() == contracts.NetworkModeControlledEgressV1 {
		if !requiresDurableLog(plan) || plan.Kind != domain.BuildDockerfile || plan.ContextPath != "." || plan.DockerfilePath != "Dockerfile" {
			return errors.New("controlled egress requires an AcornFox root Dockerfile plan")
		}
		if p.config.WorkerPolicyAttestor == nil || !p.config.controlledEgress.matches(network.WorkerPolicyDigest) {
			return errors.New("controlled egress worker policy is unavailable")
		}
	}
	return nil
}

func (p *Provider) run(ctx context.Context, request contracts.BuildRequest, record *record) (contracts.BuildResult, error) {
	if err := p.attestControlledEgress(ctx, request, requestFingerprint(request)); err != nil {
		return contracts.BuildResult{}, err
	}
	if err := p.acquire(ctx, request.Operation); err != nil {
		return contracts.BuildResult{}, err
	}
	defer func() { <-p.slot }()

	runCtx, cancel, err := p.buildContext(ctx, request)
	if err != nil {
		return contracts.BuildResult{}, p.providerError(request.Operation, contracts.ErrTimeout, "build timeout is invalid", contracts.RetryNever, false, err)
	}
	p.mu.Lock()
	wasCancelled := p.cancelled[request.Operation.IdempotencyKey]
	record.cancel = cancel
	p.mu.Unlock()
	if wasCancelled {
		cancel()
	}
	defer cancel()

	if err := os.MkdirAll(p.config.WorkRoot, 0o700); err != nil {
		return contracts.BuildResult{}, p.providerError(request.Operation, contracts.ErrUnavailable, "create build work root", contracts.RetryBackoff, true, err)
	}
	runRoot, err := os.MkdirTemp(p.config.WorkRoot, "build-")
	if err != nil {
		return contracts.BuildResult{}, p.providerError(request.Operation, contracts.ErrUnavailable, "create isolated build workspace", contracts.RetryBackoff, true, err)
	}
	defer os.RemoveAll(runRoot)

	contextPath, dockerfilePath, err := p.copyBuildContext(request.Source, request.Plan, runRoot)
	if err != nil {
		return contracts.BuildResult{}, p.providerError(request.Operation, contracts.ErrValidation, safePreparationFailure(err), contracts.RetryNever, false, err)
	}
	if err := validateAcornFoxDefinitionAgainstPlan(request.Source, request.Plan); err != nil {
		return contracts.BuildResult{}, p.providerError(request.Operation, contracts.ErrValidation, "AcornFox Dockerfile definition does not match build plan", contracts.RetryNever, false, err)
	}
	secretArgs, secretMaterials, err := p.mountSecrets(runCtx, request.Plan.SecretRefs, request.Operation)
	if err != nil {
		return contracts.BuildResult{}, p.providerError(request.Operation, contracts.ErrUnavailable, "prepare build secrets", contracts.RetryBackoff, true, err)
	}
	defer func() {
		for index := len(secretMaterials) - 1; index >= 0; index-- {
			revokeOperation := request.Operation
			revokeOperation.IdempotencyKey += ":secret-revoke:" + secretMaterials[index].MountID
			_ = p.config.SecretResolver.RevokeBuildSecret(context.Background(), secretMaterials[index], revokeOperation)
		}
	}()
	metadataPath := filepath.Join(runRoot, "metadata.json")
	outputPath := filepath.Join(runRoot, "image.oci.tar")
	args := p.commandArgs(request.Network, contextPath, dockerfilePath, metadataPath, outputPath, secretArgs)
	if err := p.config.Capacity.Activate(runCtx, *request.Capacity, contracts.OperationContext{IdempotencyKey: request.Operation.IdempotencyKey + ":capacity-activate", Deadline: request.Operation.Deadline, Actor: request.Operation.Actor}); err != nil {
		return contracts.BuildResult{}, err
	}
	logs := newRedactingBuffer(nil)
	logs.suppressed = len(secretMaterials) > 0
	if err := p.config.Runner.Run(runCtx, p.config.Command, args, logs, logs); err != nil {
		return contracts.BuildResult{}, p.commandError(request.Operation, err, logs.String(), len(secretMaterials) > 0)
	}
	successLogs := logs.String()
	if !logs.suppressed {
		successLogs = normalizeBuildKitRawJSONLog(successLogs)
	}
	metadata, err := os.ReadFile(metadataPath)
	if err != nil {
		return contracts.BuildResult{}, p.providerError(request.Operation, contracts.ErrValidation, "build did not produce metadata", contracts.RetryNever, false, err)
	}
	digest, err := parseOCIDigest(metadata)
	if err != nil {
		return contracts.BuildResult{}, p.providerError(request.Operation, contracts.ErrValidation, "build metadata did not contain an OCI image digest", contracts.RetryNever, false, err)
	}
	if info, err := os.Stat(outputPath); err != nil || info.Size() == 0 {
		if err == nil {
			err = errors.New("OCI output is empty")
		}
		return contracts.BuildResult{}, p.providerError(request.Operation, contracts.ErrValidation, "build did not produce OCI output", contracts.RetryNever, false, err)
	}
	image, err := domain.ParseImageDigest(request.Plan.TargetRepository, digest)
	if err != nil {
		return contracts.BuildResult{}, p.providerError(request.Operation, contracts.ErrValidation, "build image digest is invalid", contracts.RetryNever, false, err)
	}
	logRef := ""
	if p.config.LogSink != nil {
		logRef, err = p.config.LogSink.StoreBuildLog(runCtx, request, successLogs)
		if err != nil {
			return contracts.BuildResult{}, p.providerError(request.Operation, contracts.ErrUnavailable, "persist build log", contracts.RetryBackoff, true, nil)
		}
		if strings.TrimSpace(logRef) == "" {
			return contracts.BuildResult{}, p.providerError(request.Operation, contracts.ErrUnavailable, "persist build log", contracts.RetryBackoff, true, nil)
		}
	}
	archive, err := os.Open(outputPath)
	if err != nil {
		return contracts.BuildResult{}, p.providerError(request.Operation, contracts.ErrUnavailable, "open OCI output", contracts.RetryBackoff, true, err)
	}
	stored, storeErr := p.config.ImageStore.StoreOCI(runCtx, contracts.StoreOCIRequest{Image: image, StorageKey: request.Plan.Output.StorageKey, Archive: archive, Operation: request.Operation})
	closeErr := archive.Close()
	if storeErr != nil {
		return contracts.BuildResult{}, p.providerErrorWithLogRef(request.Operation, contracts.ErrUnavailable, "store OCI output", contracts.RetryBackoff, true, storeErr, logRef)
	}
	if closeErr != nil {
		return contracts.BuildResult{}, p.providerError(request.Operation, contracts.ErrUnavailable, "close OCI output", contracts.RetryBackoff, true, closeErr)
	}
	return p.success(request, stored, metadata, successLogs, logRef), nil
}

func (p *Provider) attestControlledEgress(ctx context.Context, request contracts.BuildRequest, fingerprint string) error {
	if request.Network.EffectiveMode() != contracts.NetworkModeControlledEgressV1 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return p.contextError(request.Operation, err)
	}
	attestationRequest := WorkerPolicyAttestationRequest{SchemaVersion: 1, PolicyDigest: request.Network.WorkerPolicyDigest, RequestFingerprint: fingerprint}
	receipt, err := p.config.WorkerPolicyAttestor.AttestWorkerPolicy(ctx, attestationRequest)
	if err != nil {
		return p.providerError(request.Operation, contracts.ErrUnavailable, "controlled egress worker attestation is unavailable", contracts.RetryBackoff, true, nil)
	}
	if !attestationMatches(receipt, attestationRequest) {
		return p.providerError(request.Operation, contracts.ErrForbidden, "controlled egress worker attestation does not match build request", contracts.RetryNever, false, nil)
	}
	return nil
}

func safePreparationFailure(err error) string {
	message := err.Error()
	for _, class := range []string{
		"source workspace is invalid", "source workspace digest changed", "build context escapes workspace root",
		"build context is not a directory", "symbolic links are not allowed", "non-regular build-context file",
		"dockerfile escapes build context", "dockerfile must be a regular file", "static server binary is unavailable",
		"copied Dockerfile digest does not match AcornFox build plan", "AcornFox build plan must use the root Dockerfile",
		"static server binary digest does not match build plan", "source conflicts with reserved static runtime path",
		"copy static server binary",
	} {
		if strings.Contains(message, class) {
			return "prepare isolated build workspace: " + class
		}
	}
	return "prepare isolated build workspace: copy failed"
}

func (p *Provider) acquire(ctx context.Context, operation contracts.OperationContext) error {
	select {
	case p.slot <- struct{}{}:
		return nil
	case <-ctx.Done():
		return p.contextError(operation, ctx.Err())
	}
}

func (p *Provider) buildContext(ctx context.Context, request contracts.BuildRequest) (context.Context, context.CancelFunc, error) {
	deadline := time.Now().Add(p.config.Timeout)
	if request.Resources.TimeoutSeconds > 0 {
		requested := time.Now().Add(time.Duration(request.Resources.TimeoutSeconds) * time.Second)
		if requested.Before(deadline) {
			deadline = requested
		}
	}
	if !request.Operation.Deadline.IsZero() {
		if !time.Now().Before(request.Operation.Deadline) {
			return nil, nil, context.DeadlineExceeded
		}
		if request.Operation.Deadline.Before(deadline) {
			deadline = request.Operation.Deadline
		}
	}
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	child, cancel := context.WithDeadline(ctx, deadline)
	return child, cancel, nil
}

func (p *Provider) copyBuildContext(sourceRevision domain.SourceRevision, plan domain.BuildPlan, runRoot string) (string, string, error) {
	if filepath.IsAbs(plan.ContextPath) || filepath.IsAbs(plan.DockerfilePath) {
		return "", "", errors.New("build paths must be relative")
	}
	workspace, err := filepath.EvalSymlinks(sourceRevision.WorkspaceRef)
	workspaceRoot, rootErr := filepath.EvalSymlinks(p.config.WorkspaceRoot)
	if err != nil || rootErr != nil || !within(workspaceRoot, workspace) {
		return "", "", errors.New("source workspace is invalid")
	}
	actualDigest, err := foundation.HashDirectory(workspace)
	if err != nil || "sha256:"+actualDigest != sourceRevision.ContentDigest {
		return "", "", errors.New("source workspace digest changed")
	}
	source := filepath.Join(workspace, plan.ContextPath)
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		return "", "", err
	}
	if !within(p.config.WorkspaceRoot, source) {
		return "", "", errors.New("build context escapes workspace root")
	}
	if info, err := os.Stat(source); err != nil || !info.IsDir() {
		if err == nil {
			err = errors.New("build context is not a directory")
		}
		return "", "", err
	}
	destination := filepath.Join(runRoot, "workspace")
	if err := copyTree(source, destination); err != nil {
		return "", "", err
	}
	dockerfile := ""
	if plan.Kind == domain.BuildDockerfile {
		dockerfile = filepath.Join(destination, plan.DockerfilePath)
		if !within(destination, dockerfile) {
			return "", "", errors.New("dockerfile escapes build context")
		}
		info, err := os.Lstat(dockerfile)
		if err != nil {
			return "", "", err
		}
		if !info.Mode().IsRegular() {
			return "", "", errors.New("dockerfile must be a regular file")
		}
		if plan.AcornFoxDockerfileDigest != "" {
			if plan.ContextPath != "." || plan.DockerfilePath != "Dockerfile" {
				return "", "", errors.New("AcornFox build plan must use the root Dockerfile")
			}
			copiedDigest, digestErr := digestFile(dockerfile)
			if digestErr != nil || copiedDigest != plan.AcornFoxDockerfileDigest {
				return "", "", errors.New("copied Dockerfile digest does not match AcornFox build plan")
			}
		}
	} else if plan.Kind == domain.BuildStatic {
		if p.config.StaticServerBinary == "" {
			return "", "", errors.New("static server binary is unavailable")
		}
		binaryDigest, err := digestFile(p.config.StaticServerBinary)
		if err != nil || binaryDigest != plan.StaticRuntimeDigest {
			return "", "", errors.New("static server binary digest does not match build plan")
		}
		binaryTarget := filepath.Join(destination, ".open-card-static-server")
		if _, err := os.Lstat(binaryTarget); !errors.Is(err, fs.ErrNotExist) {
			return "", "", errors.New("source conflicts with reserved static runtime path")
		}
		binary, err := os.Open(p.config.StaticServerBinary)
		if err != nil {
			return "", "", err
		}
		target, err := os.OpenFile(binaryTarget, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o500)
		if err != nil {
			binary.Close()
			return "", "", err
		}
		_, copyErr := io.Copy(target, binary)
		closeTargetErr := target.Close()
		closeBinaryErr := binary.Close()
		if copyErr != nil || closeTargetErr != nil || closeBinaryErr != nil {
			return "", "", errors.New("copy static server binary")
		}
		dockerfile = filepath.Join(runRoot, "Static.Dockerfile")
		contents := "FROM scratch\nCOPY --chown=65532:65532 --chmod=0555 .open-card-static-server /open-card-static-server\nCOPY --chown=65532:65532 . /www\nUSER 65532:65532\nEXPOSE 8080\nENTRYPOINT [\"/open-card-static-server\",\"-root\",\"/www\",\"-listen\",\":8080\"]\n"
		if err := os.WriteFile(dockerfile, []byte(contents), 0o600); err != nil {
			return "", "", err
		}
	}
	return destination, dockerfile, nil
}

func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// The random runRoot is private (0700), while the context it contains uses
// conventional Docker COPY modes so image users can traverse/read the tree.
// As in foundation.DigestTree, only the regular file's executable boolean is
// retained; uploaded write and special permission bits never propagate.
func copyTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, rel)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic links are not allowed in build context: %s", rel)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			targetInfo, err := os.Lstat(target)
			if err != nil || !targetInfo.IsDir() || targetInfo.Mode()&os.ModeSymlink != 0 {
				return errors.New("build-context directory is not regular")
			}
			return os.Chmod(target, 0o755)
		}
		if !singleLinkedContextFile(info) {
			return fmt.Errorf("non-regular or linked build-context file: %s", rel)
		}
		in, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		opened, err := in.Stat()
		if err != nil || !singleLinkedContextFile(opened) || !os.SameFile(info, opened) || info.Size() != opened.Size() || (info.Mode().Perm()&0o111 != 0) != (opened.Mode().Perm()&0o111 != 0) {
			in.Close()
			return errors.New("build-context source changed")
		}
		mode := fs.FileMode(0o644)
		if opened.Mode().Perm()&0o111 != 0 {
			mode = 0o755
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			in.Close()
			return err
		}
		copied, copyErr := io.Copy(out, io.LimitReader(in, opened.Size()+1))
		after, statErr := in.Stat()
		if copyErr == nil && (copied != opened.Size() || statErr != nil || !singleLinkedContextFile(after) || after.Size() != opened.Size() || (after.Mode().Perm()&0o111 != 0) != (opened.Mode().Perm()&0o111 != 0)) {
			copyErr = errors.New("build-context source changed")
		}
		if copyErr == nil {
			copyErr = out.Chmod(mode)
		}
		closeErr := out.Close()
		closeInputErr := in.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		return closeInputErr
	})
}
func singleLinkedContextFile(info fs.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() < 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

func (p *Provider) mountSecrets(ctx context.Context, references []domain.SecretReference, operation contracts.OperationContext) ([]string, []contracts.BuildSecretMaterial, error) {
	if len(references) == 0 {
		return nil, nil, nil
	}
	ordered := append([]domain.SecretReference(nil), references...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	mounted := make([]contracts.BuildSecretMaterial, 0, len(ordered))
	revoke := func() {
		for index := len(mounted) - 1; index >= 0; index-- {
			revokeOperation := operation
			revokeOperation.IdempotencyKey += ":secret-revoke:" + mounted[index].MountID
			_ = p.config.SecretResolver.RevokeBuildSecret(context.Background(), mounted[index], revokeOperation)
		}
	}
	for _, reference := range ordered {
		resolveOperation := operation
		resolveOperation.IdempotencyKey += ":secret-resolve:" + reference.ID.String()
		secret, err := p.config.SecretResolver.ResolveBuildSecret(ctx, reference, resolveOperation)
		if err != nil {
			revoke()
			return nil, nil, err
		}
		path, pathErr := filepath.Abs(secret.Path)
		info, statErr := os.Lstat(path)
		if secret.Reference != reference || !safeName.MatchString(reference.Name) || secret.MountID == "" || pathErr != nil || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 || !secret.ExpiresAt.After(time.Now()) {
			mounted = append(mounted, secret)
			revoke()
			return nil, nil, errors.New("resolved build secret is invalid")
		}
		secret.Path = path
		mounted = append(mounted, secret)
	}
	args := make([]string, 0, len(mounted)*2)
	for _, secret := range mounted {
		args = append(args, "--secret", "id="+secret.Reference.Name+",src="+secret.Path)
	}
	return args, mounted, nil
}

func (p *Provider) commandArgs(network contracts.NetworkPolicy, contextPath, dockerfilePath, metadataPath, outputPath string, secretArgs []string) []string {
	dockerfileDirectory := filepath.Dir(dockerfilePath)
	dockerfileName := filepath.Base(dockerfilePath)
	mode := buildKitNetworkMode(network)
	if p.config.controlledEgress.offlineBuildRequired {
		mode = "none"
	}
	args := []string{
		"--addr", p.config.Address,
		"build", "--frontend", "dockerfile.v0",
		"--local", "context=" + contextPath,
		"--local", "dockerfile=" + dockerfileDirectory,
		"--opt", "filename=" + dockerfileName,
		"--opt", "network=" + mode,
		"--progress", "rawjson",
		"--metadata-file", metadataPath,
		"--output", "type=oci,dest=" + outputPath,
	}
	args = append(args, secretArgs...)
	return args
}

func buildKitNetworkMode(network contracts.NetworkPolicy) string {
	if network.EffectiveMode() == contracts.NetworkModeControlledEgressV1 {
		return "default"
	}
	return "none"
}

func (p *Provider) success(request contracts.BuildRequest, stored contracts.StoreOCIResult, metadata []byte, logs, logRef string) contracts.BuildResult {
	fingerprint := requestFingerprint(request)
	buildID := request.BuildID
	artifactID := domain.ID("artifact_" + hashText(string(buildID), stored.Image.Digest)[:32])
	image := stored.Image
	evidenceDigest := digestBytes([]byte(logs), metadata)
	base := "buildkit://" + p.config.Builder + "/" + fingerprint
	refs := []domain.EvidenceRef{
		{ID: domain.ID("ev_" + hashText("metadata", fingerprint)[:32]), Kind: "build.metadata", Digest: digestBytes(metadata), Locator: base + "/metadata"},
		{ID: domain.ID("ev_" + hashText("oci", image.Digest)[:32]), Kind: "build.oci", Digest: image.Digest, Locator: stored.StorageRef},
	}
	if logRef != "" {
		refs = append([]domain.EvidenceRef{{ID: domain.ID("ev_" + hashText("log", fingerprint)[:32]), Kind: "build.log", Digest: digestBytes([]byte(logs)), Locator: logRef}}, refs...)
	}
	refs = append(refs, stored.Evidence.Refs...)
	now := time.Now().UTC()
	artifact := &domain.Artifact{ID: artifactID, BuildID: buildID, Image: image, OCIStorageRef: stored.StorageRef, SizeBytes: stored.SizeBytes, Evidence: append([]domain.EvidenceRef(nil), refs...), CreatedAt: now}
	return contracts.BuildResult{
		Build:    domain.Build{ID: buildID, PlanID: request.Plan.ID, Status: domain.BuildSucceeded, ArtifactID: artifactID, CreatedAt: now, UpdatedAt: now},
		Artifact: artifact,
		Evidence: contracts.Evidence{Refs: refs, Summary: "rootless BuildKit OCI output", Digest: evidenceDigest, Redacted: true},
		LogRef:   logRef,
	}
}

func (p *Provider) commandError(operation contracts.OperationContext, err error, logs string, secretMounted bool) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return p.providerError(operation, contracts.ErrTimeout, "build command timed out", contracts.RetryBackoff, true, err)
	}
	if errors.Is(err, context.Canceled) {
		return p.providerError(operation, contracts.ErrCancelled, "build command was cancelled", contracts.RetryAfterReconnect, true, err)
	}
	// The raw command error may contain paths or backend detail. Retain only a
	// redacted digest of output as evidence and expose a stable failure class.
	_, _ = logs, secretMounted
	return p.providerError(operation, contracts.ErrUnavailable, "build command failed", contracts.RetryBackoff, true, nil)
}

func (p *Provider) contextError(operation contracts.OperationContext, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return p.providerError(operation, contracts.ErrTimeout, "build operation timed out", contracts.RetryBackoff, true, err)
	}
	return p.providerError(operation, contracts.ErrCancelled, "build operation was cancelled", contracts.RetryAfterReconnect, true, err)
}

func (p *Provider) providerError(operation contracts.OperationContext, code contracts.ErrorCode, message string, retry contracts.RetryClass, retryable bool, cause error) *contracts.ProviderError {
	fingerprint := hashText(operation.IdempotencyKey)
	return &contracts.ProviderError{
		Provider: p.info.Name, Code: code, Message: message, Retry: retry, Retryable: retryable,
		Capability: contracts.CapabilityBuild, Operation: "build", Cause: cause,
		Details: map[string]string{
			"evidence_ref": "ev_" + hashText("error", fingerprint)[:32],
			// Error log references are stable correlation locators, not an
			// assertion that a durable log was written. Successful results use
			// only the durable reference returned by BuildLogSink.
			"log_ref": "buildkit://" + p.config.Builder + "/" + fingerprint + "/log",
		},
	}
}

func (p *Provider) providerErrorWithLogRef(operation contracts.OperationContext, code contracts.ErrorCode, message string, retry contracts.RetryClass, retryable bool, cause error, logRef string) *contracts.ProviderError {
	result := p.providerError(operation, code, message, retry, retryable, cause)
	if strings.TrimSpace(logRef) != "" {
		result.Details["log_ref"] = logRef
	}
	return result
}

func requestFingerprint(request contracts.BuildRequest) string {
	secretIDs := make([]string, 0, len(request.Plan.SecretRefs))
	for _, reference := range request.Plan.SecretRefs {
		secretIDs = append(secretIDs, string(reference.ID)+":"+reference.Version)
	}
	sort.Strings(secretIDs)
	return hashText(string(request.BuildID), string(request.Plan.ID), string(request.Plan.SourceRevisionID), request.Plan.SourceDigest, request.Plan.ServiceName, string(request.Plan.Kind), request.Plan.ContextPath, request.Plan.DockerfilePath, request.Plan.StaticRuntimeDigest, request.Plan.AcornFoxDefinitionDigest, request.Plan.AcornFoxDockerfileDigest, request.Plan.AcornFoxNetworkMode, request.Plan.AcornFoxWorkerPolicyDigest, request.Plan.TargetRepository, request.Plan.Output.StorageKey, string(request.Network.EffectiveMode()), request.Network.WorkerPolicyDigest, strings.Join(secretIDs, ","), request.Plan.IdempotencyKey)
}

func digestFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func hashText(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func digestBytes(parts ...[]byte) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write(part)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func parseOCIDigest(metadata []byte) (string, error) {
	var document struct {
		ContainerImageDigest string `json:"containerimage.digest"`
	}
	if err := json.Unmarshal(metadata, &document); err != nil {
		return "", err
	}
	if _, err := domain.ParseImageDigest("local/metadata", document.ContainerImageDigest); err != nil {
		return "", err
	}
	return document.ContainerImageDigest, nil
}

func cloneResult(result contracts.BuildResult) contracts.BuildResult {
	result.Evidence.Refs = append([]domain.EvidenceRef(nil), result.Evidence.Refs...)
	if result.Artifact != nil {
		artifact := *result.Artifact
		artifact.Evidence = append([]domain.EvidenceRef(nil), artifact.Evidence...)
		result.Artifact = &artifact
	}
	return result
}

type redactingBuffer struct {
	buf        bytes.Buffer
	suppressed bool
}

func newRedactingBuffer(_ [][]byte) *redactingBuffer { return &redactingBuffer{} }

func (b *redactingBuffer) Write(value []byte) (int, error) {
	originalLength := len(value)
	if b.suppressed {
		return originalLength, nil
	}
	if b.buf.Len() < maxCaptureBytes {
		remaining := maxCaptureBytes - b.buf.Len()
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = b.buf.Write(value)
	}
	return originalLength, nil
}

func (b *redactingBuffer) String() string {
	if b.suppressed {
		return "build output suppressed while secrets were mounted"
	}
	return b.buf.String()
}

// normalizeBuildKitRawJSONLog converts BuildKit rawjson progress records into
// readable stream text for successful durable logs. BuildKit encodes its data
// field as a JSON []byte (base64 on the wire). Any malformed record or absence
// of a data field falls back to the already bounded raw capture so this helper
// never invents a partial success log.
func normalizeBuildKitRawJSONLog(raw string) string {
	if raw == "" {
		return raw
	}
	var normalized bytes.Buffer
	foundData := false
	pendingCarriageReturn := false
	for _, line := range strings.SplitAfter(raw, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &fields); err != nil {
			return raw
		}
		matched, err := appendBuildKitRawJSONData(fields, &normalized, &pendingCarriageReturn)
		if err != nil {
			return raw
		}
		foundData = foundData || matched
	}
	if !foundData {
		return raw
	}
	if pendingCarriageReturn && normalized.Len() < maxCaptureBytes {
		_ = normalized.WriteByte('\n')
	}
	return normalized.String()
}

// appendBuildKitRawJSONData understands the observed BuildKit rawjson record
// shape: progress fields at the top level and log data in a top-level logs
// array. Top-level data is retained for compatibility with older fixtures.
// Any data-bearing malformed object fails the whole normalization so callers
// retain the original raw record rather than a partial readable log.
func appendBuildKitRawJSONData(fields map[string]json.RawMessage, destination *bytes.Buffer, pendingCarriageReturn *bool) (bool, error) {
	foundData := false
	if value, ok := fields["data"]; ok {
		decoded, err := decodeBuildKitRawJSONData(value)
		if err != nil {
			return false, err
		}
		appendBoundedNormalizedLog(destination, decoded, pendingCarriageReturn)
		foundData = true
	}
	logs, ok := fields["logs"]
	if !ok {
		return foundData, nil
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(logs, &entries); err != nil {
		return false, err
	}
	for _, entry := range entries {
		var logFields map[string]json.RawMessage
		if err := json.Unmarshal(entry, &logFields); err != nil {
			return false, err
		}
		value, ok := logFields["data"]
		if !ok {
			continue
		}
		decoded, err := decodeBuildKitRawJSONData(value)
		if err != nil {
			return false, err
		}
		appendBoundedNormalizedLog(destination, decoded, pendingCarriageReturn)
		foundData = true
	}
	return foundData, nil
}

func decodeBuildKitRawJSONData(value json.RawMessage) ([]byte, error) {
	if len(value) < 2 || value[0] != '"' {
		return nil, errors.New("BuildKit rawjson data is not base64 text")
	}
	var decoded []byte
	if err := json.Unmarshal(value, &decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

func appendBoundedNormalizedLog(destination *bytes.Buffer, value []byte, pendingCarriageReturn *bool) {
	for _, current := range value {
		if destination.Len() >= maxCaptureBytes {
			return
		}
		if *pendingCarriageReturn {
			_ = destination.WriteByte('\n')
			*pendingCarriageReturn = false
			if current == '\n' {
				continue
			}
			if destination.Len() >= maxCaptureBytes {
				return
			}
		}
		if current == '\r' {
			*pendingCarriageReturn = true
			continue
		}
		_ = destination.WriteByte(current)
	}
}

var _ contracts.BuildProvider = (*Provider)(nil)
