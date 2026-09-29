// Package contracts contains stable boundaries between the Open Card control
// plane and replaceable source, build, runtime, storage, route, secret,
// measurement, notification, and AI providers. Implementations report facts;
// controllers own product state and success decisions.
package contracts

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/acornfox/acornfox/internal/domain"
)

const (
	ContractAPIVersion = "v1"
)

type Capability string

const (
	CapabilitySourcePrepare   Capability = "source.prepare"
	CapabilitySourceRelease   Capability = "source.release"
	CapabilityBuild           Capability = "build.execute"
	CapabilityImageResolve    Capability = "image.resolve"
	CapabilityImagePull       Capability = "image.pull"
	CapabilityImageRetain     Capability = "image.retain"
	CapabilityImageDelete     Capability = "image.delete"
	CapabilityImageStoreOCI   Capability = "image.store_oci"
	CapabilityImageOpenOCI    Capability = "image.open_oci"
	CapabilityRuntimeDeploy   Capability = "runtime.deploy"
	CapabilityRuntimeObserve  Capability = "runtime.observe"
	CapabilityRuntimeLogs     Capability = "runtime.logs"
	CapabilityRuntimeRestart  Capability = "runtime.restart"
	CapabilityRuntimeStop     Capability = "runtime.stop"
	CapabilityRuntimeStart    Capability = "runtime.start"
	CapabilityRuntimeScale    Capability = "runtime.scale"
	CapabilityRuntimeRollback Capability = "runtime.rollback"
	CapabilityRuntimeDestroy  Capability = "runtime.destroy"
	CapabilityVolumeManage    Capability = "volume.manage"
	CapabilityObjectStorage   Capability = "object_storage"
	CapabilityRouteManage     Capability = "route.manage"
	CapabilitySecretManage    Capability = "secret.manage"
	CapabilitySecretResolve   Capability = "secret.resolve_build"
	CapabilityCapacityCheck   Capability = "capacity.check"
	CapabilityCapacityReserve Capability = "capacity.reserve"
	CapabilityMeter           Capability = "meter.ingest"
	CapabilityNotification    Capability = "notification.send"
	CapabilityAI              Capability = "ai.structured"
)

type CapabilitySet map[Capability]struct{}

func NewCapabilitySet(values ...Capability) CapabilitySet {
	set := make(CapabilitySet, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func (s CapabilitySet) Has(capability Capability) bool {
	_, ok := s[capability]
	return ok
}

func (s CapabilitySet) List() []Capability {
	values := make([]Capability, 0, len(s))
	for value := range s {
		values = append(values, value)
	}
	// Sorting here keeps generated contract reports deterministic without
	// adding an ordering requirement to provider implementations.
	sortCapabilities(values)
	return values
}

type ProviderMetadata struct {
	Name            string        `json:"name"`
	Version         string        `json:"version"`
	ContractVersion string        `json:"contract_version"`
	Capabilities    CapabilitySet `json:"capabilities"`
	Region          string        `json:"region,omitempty"`
	Healthcheck     string        `json:"healthcheck,omitempty"`
	SensitiveInputs []string      `json:"sensitive_inputs,omitempty"`
}

func (m ProviderMetadata) Validate() error {
	if m.Name == "" || m.Version == "" || m.ContractVersion == "" {
		return domain.ValidationError("provider metadata name, version, and contract version are required")
	}
	if m.ContractVersion != ContractAPIVersion {
		return domain.ValidationError("provider contract version is unsupported")
	}
	return nil
}

func (m ProviderMetadata) Supports(capability Capability) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if !m.Capabilities.Has(capability) {
		return UnsupportedCapability(capability)
	}
	return nil
}

type RetryClass = domain.RetryClass

const (
	RetryNever          = domain.RetryNever
	RetryImmediate      = domain.RetryImmediate
	RetryBackoff        = domain.RetryBackoff
	RetryAfterReconnect = domain.RetryAfterReconnect
	RetryUserAction     = domain.RetryUserAction
)

type ErrorCode = domain.ErrorCode

const (
	ErrInvalidArgument       = domain.ErrInvalidArgument
	ErrValidation            = domain.ErrValidation
	ErrInvalidTransition     = domain.ErrInvalidTransition
	ErrImmutable             = domain.ErrImmutable
	ErrConflict              = domain.ErrConflict
	ErrNotFound              = domain.ErrNotFound
	ErrUnauthorized          = domain.ErrUnauthorized
	ErrForbidden             = domain.ErrForbidden
	ErrUnsupportedCapability = domain.ErrUnsupportedCapability
	ErrUnavailable           = domain.ErrUnavailable
	ErrTimeout               = domain.ErrTimeout
	ErrCancelled             = domain.ErrCancelled
	ErrCapacity              = domain.ErrCapacity
)

type ProviderError struct {
	Provider   string            `json:"provider"`
	Code       ErrorCode         `json:"code"`
	Message    string            `json:"message"`
	Retry      RetryClass        `json:"retry"`
	Retryable  bool              `json:"retryable"`
	Capability Capability        `json:"capability,omitempty"`
	Operation  string            `json:"operation,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
	Cause      error             `json:"-"`
}

// ProviderOutcomeUnknownError means a provider request may have taken effect,
// but the caller did not receive enough of a response to prove either outcome.
// Controllers must compensate from durable facts instead of treating it as a
// confirmed provider rejection.
type ProviderOutcomeUnknownError struct{ Cause error }

func (e *ProviderOutcomeUnknownError) Error() string {
	if e == nil || e.Cause == nil {
		return "provider operation outcome is unknown"
	}
	return "provider operation outcome is unknown: " + e.Cause.Error()
}

func (e *ProviderOutcomeUnknownError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func ProviderOutcomeUnknown(cause error) error {
	if cause == nil {
		cause = errors.New("provider operation outcome is unknown")
	}
	return &ProviderOutcomeUnknownError{Cause: cause}
}

func IsProviderOutcomeUnknown(err error) bool {
	var unknown *ProviderOutcomeUnknownError
	return errors.As(err, &unknown)
}

func (e *ProviderError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Provider != "" {
		return e.Provider + ": " + e.Message + " (" + string(e.Code) + ")"
	}
	return e.Message + " (" + string(e.Code) + ")"
}

func (e *ProviderError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func UnsupportedCapability(capability Capability) *ProviderError {
	return &ProviderError{Code: ErrUnsupportedCapability, Message: "provider capability is not enabled", Retry: RetryUserAction, Capability: capability}
}

func InvalidProviderResponse(message string) *ProviderError {
	return &ProviderError{Code: ErrValidation, Message: message, Retry: RetryNever}
}

func TimeoutProviderError(operation string, cause error) *ProviderError {
	return &ProviderError{Code: ErrTimeout, Message: "provider operation timed out", Retry: RetryBackoff, Retryable: true, Operation: operation, Cause: cause}
}

func IsUnsupported(err error) bool {
	var providerErr *ProviderError
	return errors.As(err, &providerErr) && providerErr.Code == ErrUnsupportedCapability
}

type OperationContext struct {
	IdempotencyKey string    `json:"idempotency_key"`
	Deadline       time.Time `json:"deadline,omitempty"`
	EvidenceID     domain.ID `json:"evidence_id,omitempty"`
	Actor          string    `json:"actor,omitempty"`
}

func (c OperationContext) Validate() error {
	if c.IdempotencyKey == "" {
		return domain.ValidationError("provider idempotency key is required")
	}
	return nil
}

type Evidence struct {
	Refs     []domain.EvidenceRef `json:"refs"`
	Summary  string               `json:"summary,omitempty"`
	Digest   string               `json:"digest,omitempty"`
	Redacted bool                 `json:"redacted"`
}

type Provider interface {
	Metadata(ctx context.Context) ProviderMetadata
}

type PrepareSourceRequest struct {
	ApplicationID domain.ID         `json:"application_id"`
	Kind          domain.SourceKind `json:"kind"`
	Locator       string            `json:"locator"`
	Ref           string            `json:"ref,omitempty"`
	ContentDigest string            `json:"content_digest,omitempty"`
	WorkspaceRef  string            `json:"workspace_ref,omitempty"`
	Operation     OperationContext  `json:"operation"`
}

type PrepareSourceResult struct {
	Revision domain.SourceRevision `json:"revision"`
	Evidence Evidence              `json:"evidence"`
}

type ReleaseSourceRequest struct {
	Revision  domain.SourceRevision `json:"revision"`
	Operation OperationContext      `json:"operation"`
}

type SourceProvider interface {
	Provider
	Prepare(ctx context.Context, request PrepareSourceRequest) (PrepareSourceResult, error)
	Release(ctx context.Context, request ReleaseSourceRequest) error
}

type BuildRequest struct {
	BuildID   domain.ID             `json:"build_id"`
	Plan      domain.BuildPlan      `json:"plan"`
	Source    domain.SourceRevision `json:"source"`
	Resources ResourceLimits        `json:"resources"`
	Network   NetworkPolicy         `json:"network"`
	Operation OperationContext      `json:"operation"`
	Capacity  *CapacityLease        `json:"capacity_lease,omitempty"`
}

type BuildResult struct {
	Build    domain.Build     `json:"build"`
	Artifact *domain.Artifact `json:"artifact,omitempty"`
	Evidence Evidence         `json:"evidence"`
	LogRef   string           `json:"log_ref,omitempty"`
}

type BuildProvider interface {
	Provider
	Build(ctx context.Context, request BuildRequest) (BuildResult, error)
	Cancel(ctx context.Context, operationContext OperationContext) error
}

type ImageResolveRequest struct {
	Repository string                  `json:"repository"`
	Tag        string                  `json:"tag"`
	Secret     *domain.SecretReference `json:"secret,omitempty"`
	Operation  OperationContext        `json:"operation"`
}

type ImageResolveResult struct {
	Image    domain.ImageDigest `json:"image"`
	Evidence Evidence           `json:"evidence"`
}

type RegistryImageProvider interface {
	Provider
	Resolve(context.Context, ImageResolveRequest) (ImageResolveResult, error)
	ResolveAndPull(context.Context, ImageResolveRequest) (ImageResolveResult, error)
}

type ImageStore interface {
	Provider
	Resolve(ctx context.Context, request ImageResolveRequest) (ImageResolveResult, error)
	Pull(ctx context.Context, image domain.ImageDigest, operation OperationContext) (Evidence, error)
	Retain(ctx context.Context, image domain.ImageDigest, operation OperationContext) error
	Delete(ctx context.Context, image domain.ImageDigest, operation OperationContext) error
	StoreOCI(ctx context.Context, request StoreOCIRequest) (StoreOCIResult, error)
	OpenOCI(ctx context.Context, image domain.ImageDigest, operation OperationContext) (io.ReadCloser, StoreOCIResult, error)
}

type StoreOCIRequest struct {
	Image      domain.ImageDigest
	StorageKey string
	Archive    io.Reader
	Operation  OperationContext
}

type StoreOCIResult struct {
	Image      domain.ImageDigest `json:"image"`
	StorageRef string             `json:"storage_ref"`
	SizeBytes  int64              `json:"size_bytes"`
	Evidence   Evidence           `json:"evidence"`
}

type ResourceLimits struct {
	CPUMillis       int64 `json:"cpu_millis"`
	MemoryBytes     int64 `json:"memory_bytes"`
	DiskBytes       int64 `json:"disk_bytes"`
	TimeoutSeconds  int64 `json:"timeout_seconds"`
	ConcurrencySlot int   `json:"concurrency_slot"`
	PIDs            int64 `json:"pids,omitempty"`
}

type CapacityScope string

const (
	CapacityBuild   CapacityScope = "build"
	CapacityRuntime CapacityScope = "runtime"
)

type CapacityRequest struct {
	Scope     CapacityScope    `json:"scope"`
	Resources ResourceLimits   `json:"resources"`
	HostPorts int              `json:"host_ports"`
	Operation OperationContext `json:"operation"`
}

type CapacitySnapshot struct {
	Scope                CapacityScope `json:"scope"`
	TotalCPUMillis       int64         `json:"total_cpu_millis"`
	AvailableCPUMillis   int64         `json:"available_cpu_millis"`
	TotalMemoryBytes     int64         `json:"total_memory_bytes"`
	AvailableMemoryBytes int64         `json:"available_memory_bytes"`
	TotalDiskBytes       int64         `json:"total_disk_bytes"`
	AvailableDiskBytes   int64         `json:"available_disk_bytes"`
	ReservedCPUMillis    int64         `json:"reserved_cpu_millis"`
	ReservedMemoryBytes  int64         `json:"reserved_memory_bytes"`
	ReservedDiskBytes    int64         `json:"reserved_disk_bytes"`
	ObservedAt           time.Time     `json:"observed_at"`
}

type CapacityLease struct {
	ID        string         `json:"id"`
	Scope     CapacityScope  `json:"scope"`
	Resources ResourceLimits `json:"resources"`
	HostPort  int            `json:"host_port,omitempty"`
	ExpiresAt time.Time      `json:"expires_at"`
	Evidence  Evidence       `json:"evidence"`
}

type CapacityProvider interface {
	Provider
	Preflight(context.Context, CapacityRequest) (CapacitySnapshot, Evidence, error)
	Reserve(context.Context, CapacityRequest) (CapacityLease, error)
	Activate(context.Context, CapacityLease, OperationContext) error
	Release(context.Context, CapacityLease, OperationContext) error
}

type CapacityRetainedReconciler interface {
	ReconcileRetained(context.Context, CapacityLease, OperationContext) error
}

type CapacityReleasedFinalizer interface {
	FinalizeReleased(context.Context, CapacityLease, OperationContext) error
}

type NetworkMode string

const (
	// NetworkModeOffline is the default build mode. It remains the only mode
	// available to compositions that do not explicitly pin a worker policy.
	NetworkModeOffline NetworkMode = "none"
	// NetworkModeControlledEgressV1 is a request-scoped, versioned contract.
	// It does not itself configure a worker or grant any network access.
	NetworkModeControlledEgressV1 NetworkMode = "controlled_egress_v1"
)

type NetworkPolicy struct {
	Mode               NetworkMode `json:"mode"`
	WorkerPolicyDigest string      `json:"worker_policy_digest,omitempty"`
	AllowedCIDRs       []string    `json:"allowed_cidrs,omitempty"`
	AllowMetadata      bool        `json:"allow_metadata"`
}

// EffectiveMode preserves the historical empty value as the offline default.
func (p NetworkPolicy) EffectiveMode() NetworkMode {
	if p.Mode == "" {
		return NetworkModeOffline
	}
	return p.Mode
}

// Validate rejects caller-selected network exceptions. Controlled egress is
// only a digest-bound request contract; a provider must still match that
// digest to an independently provisioned worker before it can run.
func (p NetworkPolicy) Validate() error {
	if len(p.AllowedCIDRs) != 0 || p.AllowMetadata {
		return errors.New("network exceptions are not allowed")
	}
	switch p.EffectiveMode() {
	case NetworkModeOffline:
		if p.WorkerPolicyDigest != "" {
			return errors.New("offline network must not carry a worker policy digest")
		}
	case NetworkModeControlledEgressV1:
		if !IsSHA256Digest(p.WorkerPolicyDigest) {
			return errors.New("controlled egress worker policy digest is invalid")
		}
	default:
		return errors.New("build network mode is unsupported")
	}
	return nil
}

// IsSHA256Digest accepts only the immutable digest shape used to bind a
// controlled-egress request to one reviewed worker policy.
func IsSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

type RuntimeSpec struct {
	Configuration *AcornFoxRuntimeConfiguration `json:"configuration,omitempty"`
	ConfigDigest  string                        `json:"config_digest,omitempty"`
	ApplicationID domain.ID                     `json:"application_id"`
	EnvironmentID domain.ID                     `json:"environment_id"`
	ReleaseID     domain.ID                     `json:"release_id"`
	ServiceName   string                        `json:"service_name"`
	Image         domain.ImageDigest            `json:"image"`
	Resources     ResourceLimits                `json:"resources"`
	Secrets       []domain.SecretReference      `json:"secrets,omitempty"`
	Port          int                           `json:"port,omitempty"`
}

type DeployRequest struct {
	DeploymentID domain.ID        `json:"deployment_id"`
	Spec         RuntimeSpec      `json:"spec"`
	Operation    OperationContext `json:"operation"`
}
type ObserveRequest struct {
	DeploymentID domain.ID        `json:"deployment_id"`
	Operation    OperationContext `json:"operation"`
}
type LogsRequest struct {
	DeploymentID domain.ID        `json:"deployment_id"`
	ServiceName  string           `json:"service_name"`
	Since        time.Time        `json:"since,omitempty"`
	Tail         int              `json:"tail,omitempty"`
	Operation    OperationContext `json:"operation"`
}
type RestartRequest struct {
	DeploymentID domain.ID        `json:"deployment_id"`
	ServiceName  string           `json:"service_name"`
	Operation    OperationContext `json:"operation"`
}
type StopRequest struct {
	DeploymentID domain.ID        `json:"deployment_id"`
	ServiceName  string           `json:"service_name"`
	Operation    OperationContext `json:"operation"`
}
type StartRequest struct {
	DeploymentID domain.ID        `json:"deployment_id"`
	ServiceName  string           `json:"service_name"`
	Operation    OperationContext `json:"operation"`
}
type ScaleRequest struct {
	DeploymentID domain.ID        `json:"deployment_id"`
	ServiceName  string           `json:"service_name"`
	Replicas     int              `json:"replicas"`
	Operation    OperationContext `json:"operation"`
}
type RollbackRequest struct {
	DeploymentID domain.ID        `json:"deployment_id"`
	ReleaseID    domain.ID        `json:"release_id"`
	Operation    OperationContext `json:"operation"`
}
type DestroyRequest struct {
	DeploymentID      domain.ID        `json:"deployment_id"`
	PreserveVolumes   bool             `json:"preserve_volumes"`
	ConfirmationToken string           `json:"confirmation_token,omitempty"`
	Operation         OperationContext `json:"operation"`
}

type RuntimeObservation struct {
	DeploymentID domain.ID `json:"deployment_id"`
	ServiceName  string    `json:"service_name"`
	// ContainerID is the immutable Docker identity read back by the Agent. It
	// is never accepted from a user request and lets the control plane compare
	// observations with an independent docker inspect capture.
	ContainerID  string `json:"container_id,omitempty"`
	Status       string `json:"status"`
	Healthy      bool   `json:"healthy"`
	RestartCount uint64 `json:"restart_count"`
	// CPUUsageMillis is the current millicore-equivalent rate. The legacy
	// field name remains wire-compatible; consumers treat 1000 as one CPU.
	CPUUsageMillis int64          `json:"cpu_usage_millis"`
	MemoryBytes    int64          `json:"memory_bytes"`
	DiskBytes      int64          `json:"disk_bytes"`
	NetworkRxBytes int64          `json:"network_rx_bytes"`
	NetworkTxBytes int64          `json:"network_tx_bytes"`
	PIDsCurrent    int64          `json:"pids_current,omitempty"`
	ChangedPaths   int64          `json:"changed_path_count,omitempty"`
	CgroupVerified bool           `json:"cgroup_verified"`
	ExitReason     string         `json:"exit_reason,omitempty"`
	MetricsKnown   bool           `json:"metrics_known"`
	HostPort       int            `json:"host_port,omitempty"`
	Limits         ResourceLimits `json:"limits"`
	Evidence       Evidence       `json:"evidence"`
	ObservedAt     time.Time      `json:"observed_at"`
}

type RuntimeDriver interface {
	Provider
	Deploy(ctx context.Context, request DeployRequest) (domain.Deployment, error)
	Observe(ctx context.Context, request ObserveRequest) (RuntimeObservation, error)
	Logs(ctx context.Context, request LogsRequest) (<-chan string, error)
	Restart(ctx context.Context, request RestartRequest) error
	Scale(ctx context.Context, request ScaleRequest) error
	Rollback(ctx context.Context, request RollbackRequest) (domain.Deployment, error)
	Destroy(ctx context.Context, request DestroyRequest) error
}

// LifecycleRuntimeDriver is an optional narrow extension for runtime drivers supporting
// recoverable stop and start semantics without destroying containers or releasing resources.
type LifecycleRuntimeDriver interface {
	Stop(ctx context.Context, request StopRequest) error
	Start(ctx context.Context, request StartRequest) error
}

type VolumeSpec struct {
	Name      string `json:"name"`
	MountPath string `json:"mount_path"`
	SizeBytes int64  `json:"size_bytes"`
}
type VolumeRequest struct {
	Volume            VolumeSpec       `json:"volume"`
	ConfirmationToken string           `json:"confirmation_token,omitempty"`
	Operation         OperationContext `json:"operation"`
}
type VolumeProvider interface {
	Provider
	Create(context.Context, VolumeRequest) (VolumeSpec, Evidence, error)
	Attach(context.Context, VolumeRequest) error
	Detach(context.Context, VolumeRequest) error
	Retain(context.Context, VolumeRequest) error
	Destroy(context.Context, VolumeRequest) error
}

type ObjectStorageProvider interface {
	Provider
	Put(context.Context, string, []byte, OperationContext) (Evidence, error)
	Get(context.Context, string, OperationContext) ([]byte, Evidence, error)
	Delete(context.Context, string, OperationContext) error
}

type RouteSpec struct {
	Host           string    `json:"host"`
	Path           string    `json:"path"`
	DeploymentID   domain.ID `json:"deployment_id"`
	ServiceName    string    `json:"service_name,omitempty"`
	Port           int       `json:"port"`
	CertificateRef string    `json:"certificate_ref,omitempty"`
	Verified       bool      `json:"verified"`
}
type RouteRequest struct {
	Route     RouteSpec        `json:"route"`
	Operation OperationContext `json:"operation"`
}
type RouteProvider interface {
	Provider
	Apply(context.Context, RouteRequest) (domain.Route, Evidence, error)
	Observe(context.Context, RouteRequest) (domain.Observation, error)
	Remove(context.Context, RouteRequest) error
	Rebuild(context.Context, OperationContext) (Evidence, error)
}

// RouteSetRebuilder is the optional full desired-state boundary used after a
// Caddy restart. The caller obtains routes from Open Card persistence; the
// provider must not treat its generated Caddy configuration as product facts.
type RouteSetRebuilder interface {
	RebuildRoutes(context.Context, []RouteRequest, OperationContext) (Evidence, error)
}

type SecretRequest struct {
	Reference domain.SecretReference `json:"reference"`
	Value     []byte                 `json:"-"`
	Operation OperationContext       `json:"operation"`
}
type SecretMount struct {
	MountID   string                 `json:"mount_id"`
	Reference domain.SecretReference `json:"reference"`
	ExpiresAt time.Time              `json:"expires_at"`
}
type SecretProvider interface {
	Provider
	Store(context.Context, SecretRequest) (domain.SecretReference, error)
	Mount(context.Context, SecretRequest) (SecretMount, error)
	Revoke(context.Context, SecretMount, OperationContext) error
}

type BuildSecretMaterial struct {
	MountID   string                 `json:"mount_id"`
	Reference domain.SecretReference `json:"reference"`
	Path      string                 `json:"-"`
	ExpiresAt time.Time              `json:"expires_at"`
}

type BuildSecretResolver interface {
	Provider
	ResolveBuildSecret(context.Context, domain.SecretReference, OperationContext) (BuildSecretMaterial, error)
	RevokeBuildSecret(context.Context, BuildSecretMaterial, OperationContext) error
}

type MeterSample struct {
	ID                 string    `json:"id"`
	ApplicationID      domain.ID `json:"application_id"`
	EnvironmentID      domain.ID `json:"environment_id,omitempty"`
	DeploymentID       domain.ID `json:"deployment_id,omitempty"`
	ServiceName        string    `json:"service_name"`
	ReleaseID          domain.ID `json:"release_id"`
	At                 time.Time `json:"at"`
	CPUMillicores      int64     `json:"cpu_millicores"`
	CPUSeconds         float64   `json:"cpu_seconds"`
	MemoryBytes        int64     `json:"memory_bytes"`
	DiskBytes          int64     `json:"disk_bytes"`
	NetworkRxBytes     uint64    `json:"network_rx_bytes"`
	NetworkTxBytes     uint64    `json:"network_tx_bytes"`
	RuntimeSeconds     float64   `json:"runtime_seconds"`
	RestartCount       uint64    `json:"restart_count"`
	ExceptionCount     uint64    `json:"exception_count"`
	LimitCPUMillicores int64     `json:"limit_cpu_millicores"`
	LimitMemoryBytes   int64     `json:"limit_memory_bytes"`
	LimitDiskBytes     int64     `json:"limit_disk_bytes"`
	LimitPIDs          int64     `json:"limit_pids"`
}
type MeterQuery struct {
	ApplicationID domain.ID `json:"application_id"`
	EnvironmentID domain.ID `json:"environment_id,omitempty"`
	ServiceName   string    `json:"service_name,omitempty"`
	ReleaseID     domain.ID `json:"release_id,omitempty"`
	From          time.Time `json:"from"`
	To            time.Time `json:"to"`
}
type MeterProvider interface {
	Provider
	Ingest(context.Context, []MeterSample, OperationContext) error
	Query(context.Context, MeterQuery) ([]domain.UsageAggregate, error)
}

type Notification struct {
	EventID    domain.ID      `json:"event_id"`
	EventType  string         `json:"event_type"`
	Payload    map[string]any `json:"payload"`
	OccurredAt time.Time      `json:"occurred_at"`
}
type NotificationProvider interface {
	Provider
	Send(context.Context, Notification, OperationContext) error
	Test(context.Context, OperationContext) error
}

type AIRequest struct {
	TaskType  string                  `json:"task_type"`
	Context   domain.AIContextPackage `json:"context"`
	Budget    TokenBudget             `json:"budget"`
	Operation OperationContext        `json:"operation"`
}
type TokenBudget struct {
	MaxTokens   int           `json:"max_tokens"`
	MaxDuration time.Duration `json:"max_duration"`
}
type AIResult struct {
	Invocation domain.AIInvocation `json:"invocation"`
	Plan       domain.AIActionPlan `json:"plan"`
	Evidence   Evidence            `json:"evidence"`
}
type AIProvider interface {
	Provider
	StructuredCall(context.Context, AIRequest) (AIResult, error)
}

func sortCapabilities(values []Capability) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
