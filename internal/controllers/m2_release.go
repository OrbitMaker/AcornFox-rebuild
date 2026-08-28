package controllers

// m2_release.go owns the control-plane side of the M2 aggregate release
// workflow.  It deliberately keeps provider calls outside repository calls:
// providers report facts, while this controller decides when a complete,
// digest-only ServiceGroup Release is durable and when a single aggregate
// Agent task may be queued.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/importers/compose"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

var (
	ErrM2AgentCapability = errors.New("Agent does not advertise the required aggregate runtime capability")
	ErrM2ReleaseConflict = errors.New("M2 release idempotency key was reused for a different request")
)

// M2ReleaseStore is the repository boundary used by the controller.  Each
// method is implemented by a PostgreSQL transaction, but the interface keeps
// orchestration tests independent from a database and makes the provider/SQL
// boundary visible in reviews.
type M2ReleaseStore interface {
	CreateSourceRevision(context.Context, domain.SourceRevision) (domain.SourceRevision, error)
	CreateServiceGroupRevision(context.Context, postgres.ServiceGroupCreateRequest) (domain.ServiceGroup, error)
	CreateBuildPlan(context.Context, domain.BuildPlan) (domain.BuildPlan, error)
	CreateBuild(context.Context, domain.Build) (domain.Build, error)
	StartBuild(context.Context, domain.ID, time.Time) (domain.Build, error)
	CompleteBuild(context.Context, domain.Artifact, *postgres.ReleaseCreation, time.Time) (domain.Build, error)
	FailBuild(context.Context, domain.ID, string, time.Time) (domain.Build, error)
	CreateM2Release(context.Context, postgres.M2ReleaseCreation, time.Time) (domain.Release, error)
	EnqueueControllerTask(context.Context, postgres.EnqueueControllerTaskRequest) (application.Event, error)
}

var _ M2ReleaseStore = (*postgres.Store)(nil)

// M2ReleaseController is intentionally no-AI.  A caller that wants to use AI
// for a bounded exception must do so through a separate, audited contract; it
// cannot influence digest resolution or the task payload here.
type M2ReleaseController struct {
	Store    M2ReleaseStore
	Source   contracts.SourceProvider
	Build    contracts.BuildProvider
	Registry contracts.RegistryImageProvider
	Capacity contracts.CapacityProvider

	// StaticRuntimeDigest is the pinned platform runtime used by static builds.
	StaticRuntimeDigest string
	Clock               func() time.Time

	mu       sync.Mutex
	sources  map[string]sourceResult
	releases map[string]*releaseRun
	deploys  map[string]deploymentRun
	destroys map[string]destroyRun
}

type sourceResult struct {
	fingerprint string
	revision    domain.SourceRevision
}

type releaseRun struct {
	fingerprint string
	done        chan struct{}
	result      M2CompleteReleaseResult
	err         error
}

type deploymentRun struct {
	fingerprint string
	result      M2GroupDeploymentResult
}

type destroyRun struct {
	fingerprint string
	result      M2GroupDestroyResult
}

// PersistImportedGroupRequest is the normalized input to the immutable group
// repository.  The raw Compose document is intentionally absent: callers must
// pass the controlled importer result, not an executable Compose payload.
type PersistImportedGroupRequest struct {
	Result          compose.Result
	DefinitionID    domain.ID
	Version         int64
	ConfigDigest    string
	CanonicalDigest string
	VolumeClaims    []postgres.M2ServiceGroupVolumeClaim
	IdempotencyKey  string
}

// M2BuildService contains the resource and output contract for one source
// service.  Every built service gets its own durable BuildPlan and artifact;
// a complete Release is persisted only after all services have a digest.
type M2BuildService struct {
	Resources        contracts.ResourceLimits
	Network          contracts.NetworkPolicy
	TargetRepository string
	OutputStorageKey string
	SecretRefs       []domain.SecretReference
}

// M2PreviousRelease identifies a prior complete combination.  Matching source
// service fingerprints may reuse its immutable artifact binding; a changed
// source service is rebuilt.  The controller never copies only a subset into a
// new release.
type M2PreviousRelease struct {
	Release  domain.Release
	Group    domain.ServiceGroup
	Bindings []postgres.M2ReleaseServiceBinding
}

// M2CompleteReleaseRequest is the aggregate release input.  Prebuilt services
// may carry an already-resolved digest or a registry request.  A mutable tag
// is never placed in the runtime contract; ResolveAndPull is called once when
// only a reference is available.
type M2CompleteReleaseRequest struct {
	Group          domain.ServiceGroup
	Identity       postgres.M2ServiceGroupIdentity
	DefinitionID   domain.ID
	Version        int
	Source         domain.SourceRevision
	IdempotencyKey string
	Actor          string
	Deadline       time.Time
	EnvironmentID  domain.ID
	BuildServices  map[string]M2BuildService
	Registry       map[string]contracts.ImageResolveRequest
	Runtime        map[string]contracts.ResourceLimits
	VolumeClaims   []postgres.M2ServiceGroupVolumeClaim
	Rollout        postgres.M2ReleaseRollout
	Previous       *M2PreviousRelease
}

type M2CompleteReleaseResult struct {
	Release         domain.Release
	RuntimeSpec     contracts.ServiceGroupRuntimeSpec
	Builds          map[string]domain.Build
	Artifacts       map[string]domain.Artifact
	Bindings        []postgres.M2ReleaseServiceBinding
	CanonicalDigest string
}

// M2GroupDeploymentRequest queues one aggregate deploy_group task.  The
// capability set is supplied by the Agent handshake; an empty/legacy set is a
// hard failure and cannot be silently downgraded to a single-container task.
type M2GroupDeploymentRequest struct {
	ApplicationID     domain.ID
	EnvironmentID     domain.ID
	Release           domain.Release
	Spec              contracts.ServiceGroupRuntimeSpec
	AgentCapabilities contracts.CapabilitySet
	IdempotencyKey    string
	Actor             string
	Deadline          time.Time
}

type M2GroupDeploymentResult struct {
	Deployment domain.Deployment
	Operation  domain.Operation
	TaskID     domain.ID
}

type M2GroupDestroyRequest struct {
	ApplicationID     domain.ID
	EnvironmentID     domain.ID
	DeploymentID      domain.ID
	ReleaseID         domain.ID
	AgentCapabilities contracts.CapabilitySet
	PreserveVolumes   bool
	ConfirmationToken string
	IdempotencyKey    string
	Actor             string
	Deadline          time.Time
}

type M2GroupDestroyResult struct {
	Operation domain.Operation
	TaskID    domain.ID
}

type M2RolloutRequest struct {
	Current           *contracts.ServiceGroupRuntimeSpec
	Target            contracts.ServiceGroupRuntimeSpec
	Release           domain.Release
	AgentCapabilities contracts.CapabilitySet
	IdempotencyKey    string
	Actor             string
	Deadline          time.Time
}

type M2RolloutResult struct {
	Plan       RolloutPlan
	Deployment M2GroupDeploymentResult
}

// PrepareSource executes the SourceProvider first and then persists exactly
// the returned immutable revision.  A process-local replay avoids duplicate
// repository writes for concurrent retries; the provider itself remains the
// source of truth for workspace ownership.
func (c *M2ReleaseController) PrepareSource(ctx context.Context, request contracts.PrepareSourceRequest) (domain.SourceRevision, error) {
	if c.Store == nil || c.Source == nil {
		return domain.SourceRevision{}, errors.New("M2 source preparation requires store and source provider")
	}
	if request.ApplicationID.Empty() || strings.TrimSpace(request.Operation.IdempotencyKey) == "" {
		return domain.SourceRevision{}, domain.ValidationError("M2 source preparation requires application and idempotency key")
	}
	fingerprint := m2JSONDigest(request)
	c.mu.Lock()
	if c.sources == nil {
		c.sources = make(map[string]sourceResult)
	}
	if previous, ok := c.sources[request.Operation.IdempotencyKey]; ok {
		c.mu.Unlock()
		if previous.fingerprint != fingerprint {
			return domain.SourceRevision{}, ErrM2ReleaseConflict
		}
		return previous.revision, nil
	}
	c.mu.Unlock()

	prepared, err := c.Source.Prepare(ctx, request)
	if err != nil {
		return domain.SourceRevision{}, err
	}
	if err := prepared.Revision.Validate(); err != nil {
		return domain.SourceRevision{}, fmt.Errorf("source provider returned invalid revision: %w", err)
	}
	if prepared.Revision.ApplicationID != request.ApplicationID {
		return domain.SourceRevision{}, domain.ValidationError("source revision application does not match request")
	}
	persisted, err := c.Store.CreateSourceRevision(ctx, prepared.Revision)
	if err != nil {
		// The workspace was created by the provider and is not useful without a
		// durable revision.  Release is best-effort compensation only; its
		// failure is not hidden behind the repository error.
		_ = c.Source.Release(context.Background(), contracts.ReleaseSourceRequest{Revision: prepared.Revision, Operation: m2Operation(request.Operation, ":source-compensate")})
		return domain.SourceRevision{}, err
	}
	c.mu.Lock()
	c.sources[request.Operation.IdempotencyKey] = sourceResult{fingerprint: fingerprint, revision: persisted}
	c.mu.Unlock()
	return persisted, nil
}

// PersistImportedGroup writes the controlled importer result as one immutable
// definition revision.  The group ID is made deterministic for the request;
// this is important because Compose importers intentionally generate IDs for
// standalone use and a retried control-plane request must address one fact.
func (c *M2ReleaseController) PersistImportedGroup(ctx context.Context, request PersistImportedGroupRequest) (domain.ServiceGroup, error) {
	if c.Store == nil {
		return domain.ServiceGroup{}, errors.New("M2 group persistence requires store")
	}
	if request.Result.Report.Version == "" || !request.Result.Report.Accepted {
		return domain.ServiceGroup{}, domain.ValidationError("Compose import result is not accepted")
	}
	if request.Result.Canonical == nil || request.Result.ServiceGroup.ApplicationID.Empty() {
		return domain.ServiceGroup{}, domain.ValidationError("controlled Compose result is incomplete")
	}
	if request.DefinitionID.Empty() || request.Version < 1 || strings.TrimSpace(request.IdempotencyKey) == "" {
		return domain.ServiceGroup{}, domain.ValidationError("M2 group definition, version and idempotency key are required")
	}
	group := request.Result.ServiceGroup
	group.ID = m2ID("group", request.IdempotencyKey, string(group.ApplicationID), request.DefinitionID.String(), strconv.FormatInt(request.Version, 10), request.Result.Report.CanonicalDigest)
	if group.CreatedAt.IsZero() {
		group.CreatedAt = c.now()
	}
	identity := postgres.M2ServiceGroupIdentity{DefinitionID: request.DefinitionID, Version: request.Version, ConfigDigest: request.ConfigDigest, CanonicalDigest: request.CanonicalDigest}
	return c.Store.CreateServiceGroupRevision(ctx, postgres.ServiceGroupCreateRequest{
		Group: group, ImportReport: domain.ComposeImportReport{MappedFields: append([]string(nil), request.Result.Report.MappedFields...), Warnings: append([]string(nil), request.Result.Report.Warnings...)}, IdempotencyKey: request.IdempotencyKey,
		Identity: identity, VolumeClaims: cloneM2Claims(request.VolumeClaims),
	})
}

// CreateCompleteRelease resolves/builds every service, persists all successful
// artifacts, computes a complete canonical digest-only runtime contract, and
// commits one immutable M2 release.  No provider call is made after
// CreateM2Release begins, preserving the provider-outside-SQL boundary.
func (c *M2ReleaseController) CreateCompleteRelease(ctx context.Context, request M2CompleteReleaseRequest) (M2CompleteReleaseResult, error) {
	if err := c.validateController(); err != nil {
		return M2CompleteReleaseResult{}, err
	}
	if request.Identity.DefinitionID.Empty() {
		request.Identity.DefinitionID = request.DefinitionID
	}
	if request.Identity.Version == 0 {
		request.Identity.Version = int64(request.Version)
	}
	if err := validateM2CompleteRequest(request); err != nil {
		return M2CompleteReleaseResult{}, err
	}
	if !request.Source.ID.Empty() && c.Source == nil {
		return M2CompleteReleaseResult{}, errors.New("M2 complete release requires a source provider")
	}
	for _, service := range request.Group.Services {
		if service.Source.Kind == domain.ServiceStatic || service.Source.Kind == domain.ServiceDockerfile {
			if c.Build == nil {
				return M2CompleteReleaseResult{}, errors.New("M2 source release requires a build provider")
			}
		}
		if service.Source.Kind == domain.ServicePrebuilt && service.Source.Prebuilt != nil && service.Source.Prebuilt.Image.Repository == "" && c.Registry == nil {
			return M2CompleteReleaseResult{}, errors.New("M2 prebuilt release requires a registry provider")
		}
	}
	fingerprint := m2JSONDigest(request)
	c.mu.Lock()
	if c.releases == nil {
		c.releases = make(map[string]*releaseRun)
	}
	if previous, ok := c.releases[request.IdempotencyKey]; ok {
		c.mu.Unlock()
		if previous.fingerprint != fingerprint {
			return M2CompleteReleaseResult{}, ErrM2ReleaseConflict
		}
		select {
		case <-previous.done:
			return previous.result, previous.err
		case <-ctx.Done():
			return M2CompleteReleaseResult{}, ctx.Err()
		}
	}
	run := &releaseRun{fingerprint: fingerprint, done: make(chan struct{})}
	c.releases[request.IdempotencyKey] = run
	c.mu.Unlock()

	result, err := c.createCompleteRelease(ctx, request)
	c.mu.Lock()
	run.result, run.err = result, err
	close(run.done)
	c.mu.Unlock()
	return result, err
}

func (c *M2ReleaseController) createCompleteRelease(ctx context.Context, request M2CompleteReleaseRequest) (M2CompleteReleaseResult, error) {
	services := append([]domain.ServiceSpec(nil), request.Group.Services...)
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	buildNames := make([]string, 0)
	for _, service := range services {
		if service.Source.Kind == domain.ServiceStatic || service.Source.Kind == domain.ServiceDockerfile {
			if c.canReuseM2Service(request.Previous, service.Name, service) {
				continue
			}
			buildNames = append(buildNames, service.Name)
		}
	}
	buildResources, err := aggregateM2BuildResources(request, buildNames)
	if err != nil {
		return M2CompleteReleaseResult{}, err
	}
	if len(buildNames) > 0 {
		if _, _, err := c.Capacity.Preflight(ctx, contracts.CapacityRequest{Scope: contracts.CapacityBuild, Resources: buildResources, Operation: m2OperationContext(request.IdempotencyKey+":capacity-build", request.Actor, request.Deadline)}); err != nil {
			return M2CompleteReleaseResult{}, err
		}
	}
	// Runtime capacity is checked before any registry or build provider call.
	runtimeResources, err := aggregateM2RuntimeResources(request, services)
	if err != nil {
		return M2CompleteReleaseResult{}, err
	}
	if _, _, err := c.Capacity.Preflight(ctx, contracts.CapacityRequest{Scope: contracts.CapacityRuntime, Resources: runtimeResources, HostPorts: 1, Operation: m2OperationContext(request.IdempotencyKey+":capacity-runtime", request.Actor, request.Deadline)}); err != nil {
		return M2CompleteReleaseResult{}, err
	}

	images := make(map[string]domain.ImageDigest, len(services))
	bindings := make([]postgres.M2ReleaseServiceBinding, 0, len(services))
	artifacts := make(map[string]domain.Artifact)
	builds := make(map[string]domain.Build)

	// Resolve all prebuilt references before starting source builds.  A registry
	// failure therefore cannot leave a newly-created build row for this release.
	for _, service := range services {
		if service.Source.Kind != domain.ServicePrebuilt {
			continue
		}
		if reused, ok := c.reusedBinding(request.Previous, service.Name, service); ok {
			images[service.Name] = reused.Image
			bindings = append(bindings, reused)
			continue
		}
		image, resolvedFrom, err := c.resolvePrebuilt(ctx, request, service)
		if err != nil {
			return M2CompleteReleaseResult{}, err
		}
		images[service.Name] = image
		bindings = append(bindings, postgres.M2ReleaseServiceBinding{ServiceName: service.Name, Kind: postgres.M2ReleaseBindingResolvedImage, Image: image, ResolvedFrom: resolvedFrom})
	}

	for _, service := range services {
		if service.Source.Kind != domain.ServiceStatic && service.Source.Kind != domain.ServiceDockerfile {
			continue
		}
		if reused, ok := c.reusedBinding(request.Previous, service.Name, service); ok {
			images[service.Name] = reused.Image
			bindings = append(bindings, reused)
			continue
		}
		buildInput, ok := request.BuildServices[service.Name]
		if !ok {
			return M2CompleteReleaseResult{}, domain.ValidationError("M2 build service input is missing")
		}
		plan, build, artifact, err := c.buildOne(ctx, request, service, buildInput)
		if err != nil {
			if build.ID != "" {
				_, _ = c.Store.FailBuild(context.Background(), build.ID, "M2 build failed", c.now())
			}
			return M2CompleteReleaseResult{}, err
		}
		_ = plan
		builds[service.Name], artifacts[service.Name] = build, artifact
		images[service.Name] = artifact.Image
		bindings = append(bindings, postgres.M2ReleaseServiceBinding{ServiceName: service.Name, Kind: postgres.M2ReleaseBindingArtifact, ArtifactID: artifact.ID})
	}
	if !request.Source.ID.Empty() {
		if err := c.Source.Release(ctx, contracts.ReleaseSourceRequest{Revision: request.Source, Operation: m2OperationContext(request.IdempotencyKey+":source-release", request.Actor, request.Deadline)}); err != nil {
			return M2CompleteReleaseResult{}, err
		}
	}

	releaseID := m2ID("release", request.IdempotencyKey, request.Group.ID.String(), strconv.FormatInt(request.Identity.Version, 10))
	spec, err := m2RuntimeSpec(request, services, images, runtimeResources, releaseID)
	if err != nil {
		return M2CompleteReleaseResult{}, err
	}
	canonical, err := contracts.CanonicalServiceGroupReleaseDigest(request.Identity.DefinitionID, request.Identity.Version, spec)
	if err != nil {
		return M2CompleteReleaseResult{}, err
	}
	release, err := domain.NewRelease(request.Group.ApplicationID, request.Group.ID, int(request.Identity.Version), request.Identity.ConfigDigest, images, c.now())
	if err != nil {
		return M2CompleteReleaseResult{}, err
	}
	release.ID = releaseID
	creation := postgres.M2ReleaseCreation{Release: *release, DefinitionID: request.Identity.DefinitionID, Bindings: bindings, CanonicalDigest: canonical, RuntimeSpec: spec, Rollout: request.Rollout}
	persisted, err := c.Store.CreateM2Release(ctx, creation, c.now())
	if err != nil {
		return M2CompleteReleaseResult{}, err
	}
	return M2CompleteReleaseResult{Release: persisted, RuntimeSpec: spec, Builds: builds, Artifacts: artifacts, Bindings: bindings, CanonicalDigest: canonical}, nil
}

func (c *M2ReleaseController) buildOne(ctx context.Context, request M2CompleteReleaseRequest, service domain.ServiceSpec, input M2BuildService) (domain.BuildPlan, domain.Build, domain.Artifact, error) {
	if input.Resources.CPUMillis < 0 || input.Resources.MemoryBytes < 0 || input.Resources.DiskBytes < 0 || input.Resources.PIDs < 0 {
		return domain.BuildPlan{}, domain.Build{}, domain.Artifact{}, domain.ValidationError("M2 build resources must not be negative")
	}
	if input.Resources.DiskBytes <= 0 {
		return domain.BuildPlan{}, domain.Build{}, domain.Artifact{}, domain.ValidationError("M2 build disk capacity must be positive")
	}
	target := strings.TrimSpace(input.TargetRepository)
	if target == "" {
		target = "open-card/" + safeSegment(request.Group.ApplicationID.String()) + "/" + safeSegment(service.Name)
	}
	kind := domain.BuildDockerfile
	contextPath, dockerfilePath := "", ""
	staticRuntimeDigest := ""
	if service.Source.Kind == domain.ServiceStatic {
		kind, contextPath, staticRuntimeDigest = domain.BuildStatic, service.Source.Static.Directory, c.StaticRuntimeDigest
	} else {
		contextPath, dockerfilePath = service.Source.Dockerfile.Context, service.Source.Dockerfile.Dockerfile
	}
	if kind == domain.BuildStatic && !validM2Digest(staticRuntimeDigest) {
		return domain.BuildPlan{}, domain.Build{}, domain.Artifact{}, domain.ValidationError("static runtime digest is not configured")
	}
	storageKey := strings.TrimSpace(input.OutputStorageKey)
	if storageKey == "" {
		storageKey = "m2/" + safeSegment(request.Group.ID.String()) + "/" + safeSegment(service.Name)
	}
	plan := domain.BuildPlan{ID: m2ID("plan", request.IdempotencyKey, service.Name, request.Source.ID.String()), SourceRevisionID: request.Source.ID, SourceDigest: request.Source.ContentDigest, ServiceName: service.Name, Kind: kind, ContextPath: contextPath, DockerfilePath: dockerfilePath, StaticRuntimeDigest: staticRuntimeDigest, TargetRepository: target, Output: domain.BuildOutputContract{Format: domain.BuildOutputOCI, Retention: domain.BuildRetentionPersist, StorageKey: storageKey}, SecretRefs: append([]domain.SecretReference(nil), input.SecretRefs...), IdempotencyKey: request.IdempotencyKey + ":build-plan:" + service.Name, CreatedAt: c.now()}
	if err := plan.Validate(); err != nil {
		return plan, domain.Build{}, domain.Artifact{}, err
	}
	persistedPlan, err := c.Store.CreateBuildPlan(ctx, plan)
	if err != nil {
		return plan, domain.Build{}, domain.Artifact{}, err
	}
	build := domain.Build{ID: m2ID("build", request.IdempotencyKey, service.Name), PlanID: persistedPlan.ID, Status: domain.BuildPending, CreatedAt: c.now(), UpdatedAt: c.now()}
	if _, err := c.Store.CreateBuild(ctx, build); err != nil {
		return persistedPlan, build, domain.Artifact{}, err
	}
	if _, err := c.Store.StartBuild(ctx, build.ID, c.now()); err != nil {
		return persistedPlan, build, domain.Artifact{}, err
	}
	lease, err := c.Capacity.Reserve(ctx, contracts.CapacityRequest{Scope: contracts.CapacityBuild, Resources: input.Resources, Operation: m2OperationContext(request.IdempotencyKey+":capacity-reserve:"+service.Name, request.Actor, request.Deadline)})
	if err != nil {
		return persistedPlan, build, domain.Artifact{}, err
	}
	defer func() {
		_ = c.Capacity.Release(context.Background(), lease, m2OperationContext(request.IdempotencyKey+":capacity-release:"+service.Name, request.Actor, time.Time{}))
	}()
	result, err := c.Build.Build(ctx, contracts.BuildRequest{BuildID: build.ID, Plan: persistedPlan, Source: request.Source, Resources: input.Resources, Network: input.Network, Operation: m2OperationContext(request.IdempotencyKey+":build:"+service.Name, request.Actor, request.Deadline), Capacity: &lease})
	if err != nil {
		return persistedPlan, build, domain.Artifact{}, err
	}
	if result.Artifact == nil || result.Build.ID != build.ID || result.Build.PlanID != persistedPlan.ID || result.Build.Status != domain.BuildSucceeded || result.Artifact.BuildID != build.ID {
		return persistedPlan, build, domain.Artifact{}, errors.New("build provider returned an incomplete M2 artifact")
	}
	if _, err := c.Store.CompleteBuild(ctx, *result.Artifact, nil, c.now()); err != nil {
		return persistedPlan, build, domain.Artifact{}, err
	}
	return persistedPlan, result.Build, *result.Artifact, nil
}

// EnqueueGroupDeployment performs the capability and aggregate capacity gates
// before writing a single deploy_group task.  It never emits one task per
// service, which is what prevents an old Agent from running a partial group.
func (c *M2ReleaseController) EnqueueGroupDeployment(ctx context.Context, request M2GroupDeploymentRequest) (M2GroupDeploymentResult, error) {
	if err := c.validateController(); err != nil {
		return M2GroupDeploymentResult{}, err
	}
	if !request.AgentCapabilities.Has(contracts.CapabilityRuntimeDeployGroup) {
		return M2GroupDeploymentResult{}, fmt.Errorf("%w: %s", ErrM2AgentCapability, contracts.CapabilityRuntimeDeployGroup)
	}
	if request.Spec.ApplicationID != request.ApplicationID || request.Spec.EnvironmentID != request.EnvironmentID || request.Spec.ReleaseID != request.Release.ID {
		return M2GroupDeploymentResult{}, domain.ValidationError("M2 deploy group scope does not match release and environment")
	}
	if err := request.Spec.ValidateRelease(request.Release); err != nil {
		return M2GroupDeploymentResult{}, err
	}
	if strings.TrimSpace(request.IdempotencyKey) == "" {
		return M2GroupDeploymentResult{}, domain.ValidationError("M2 deployment idempotency key is required")
	}
	if err := c.preflightRuntime(ctx, request.IdempotencyKey, request.Actor, request.Deadline, request.Spec); err != nil {
		return M2GroupDeploymentResult{}, err
	}
	fingerprint := m2JSONDigest(request)
	c.mu.Lock()
	if c.deploys == nil {
		c.deploys = make(map[string]deploymentRun)
	}
	if previous, ok := c.deploys[request.IdempotencyKey]; ok {
		c.mu.Unlock()
		if previous.fingerprint != fingerprint {
			return M2GroupDeploymentResult{}, ErrM2ReleaseConflict
		}
		return previous.result, nil
	}
	c.mu.Unlock()

	now := c.now()
	deploymentID := m2ID("deployment", request.IdempotencyKey)
	deployment := domain.Deployment{ID: deploymentID, ApplicationID: request.ApplicationID, EnvironmentID: request.EnvironmentID, ReleaseID: request.Release.ID, Status: domain.DeploymentPending, CreatedAt: now, UpdatedAt: now}
	if err := deployment.Validate(); err != nil {
		return M2GroupDeploymentResult{}, err
	}
	operation, err := domain.NewOperation(request.ApplicationID, request.EnvironmentID, domain.OperationDeploy, "deployment/"+deployment.ID.String(), request.IdempotencyKey, now)
	if err != nil {
		return M2GroupDeploymentResult{}, err
	}
	operation.ID = m2ID("operation", request.IdempotencyKey)
	parameters, err := json.Marshal(contracts.DeployGroupRequest{DeploymentID: deployment.ID, Spec: request.Spec, Operation: m2OperationContext(request.IdempotencyKey, request.Actor, request.Deadline)})
	if err != nil {
		return M2GroupDeploymentResult{}, err
	}
	payload, err := json.Marshal(AgentTaskSpec{Kind: v1.TaskDeployGroup, Parameters: parameters})
	if err != nil {
		return M2GroupDeploymentResult{}, err
	}
	taskID := m2ID("task", request.IdempotencyKey)
	if _, err := c.Store.EnqueueControllerTask(ctx, postgres.EnqueueControllerTaskRequest{Operation: operation, Deployment: &deployment, TaskID: taskID, Payload: payload, MaxAttempts: 3, InitialPublishStatus: domain.PublishDeploying}); err != nil {
		return M2GroupDeploymentResult{}, err
	}
	result := M2GroupDeploymentResult{Deployment: deployment, Operation: operation, TaskID: taskID}
	c.mu.Lock()
	c.deploys[request.IdempotencyKey] = deploymentRun{fingerprint: fingerprint, result: result}
	c.mu.Unlock()
	return result, nil
}

// Rollout plans the whole group before queueing it.  The old deployment is
// kept in the runtime policy and the Agent receives the complete target
// combination; unchanged services are represented in the plan and are never
// made into independent tasks.
func (c *M2ReleaseController) Rollout(ctx context.Context, request M2RolloutRequest) (M2RolloutResult, error) {
	if err := c.validateController(); err != nil {
		return M2RolloutResult{}, err
	}
	if !request.AgentCapabilities.Has(contracts.CapabilityRuntimeDeployGroup) {
		return M2RolloutResult{}, fmt.Errorf("%w: %s", ErrM2AgentCapability, contracts.CapabilityRuntimeDeployGroup)
	}
	if strings.TrimSpace(request.IdempotencyKey) == "" {
		return M2RolloutResult{}, domain.ValidationError("M2 rollout idempotency key is required")
	}
	if err := request.Target.ValidateRelease(request.Release); err != nil {
		return M2RolloutResult{}, err
	}
	if err := c.preflightRuntime(ctx, request.IdempotencyKey+":rollout", request.Actor, request.Deadline, request.Target); err != nil {
		return M2RolloutResult{}, err
	}
	plan, err := PlanServiceGroupRollout(request.Current, request.Target, true)
	if err != nil {
		return M2RolloutResult{}, err
	}
	deployment, err := c.EnqueueGroupDeployment(ctx, M2GroupDeploymentRequest{ApplicationID: request.Target.ApplicationID, EnvironmentID: request.Target.EnvironmentID, Release: request.Release, Spec: request.Target, AgentCapabilities: request.AgentCapabilities, IdempotencyKey: request.IdempotencyKey, Actor: request.Actor, Deadline: request.Deadline})
	if err != nil {
		return M2RolloutResult{}, err
	}
	return M2RolloutResult{Plan: plan, Deployment: deployment}, nil
}

// EnqueueGroupDestroy queues the single aggregate destroy task.  The group
// capability is required even when the user requests volume preservation.
func (c *M2ReleaseController) EnqueueGroupDestroy(ctx context.Context, request M2GroupDestroyRequest) (M2GroupDestroyResult, error) {
	if c.Store == nil {
		return M2GroupDestroyResult{}, errors.New("M2 destroy requires store")
	}
	if !request.AgentCapabilities.Has(contracts.CapabilityRuntimeDestroyGroup) {
		return M2GroupDestroyResult{}, fmt.Errorf("%w: %s", ErrM2AgentCapability, contracts.CapabilityRuntimeDestroyGroup)
	}
	if request.ApplicationID.Empty() || request.EnvironmentID.Empty() || request.DeploymentID.Empty() || strings.TrimSpace(request.IdempotencyKey) == "" {
		return M2GroupDestroyResult{}, domain.ValidationError("M2 destroy scope and idempotency key are required")
	}
	fingerprint := m2JSONDigest(request)
	c.mu.Lock()
	if c.destroys == nil {
		c.destroys = make(map[string]destroyRun)
	}
	if previous, ok := c.destroys[request.IdempotencyKey]; ok {
		c.mu.Unlock()
		if previous.fingerprint != fingerprint {
			return M2GroupDestroyResult{}, ErrM2ReleaseConflict
		}
		return previous.result, nil
	}
	c.mu.Unlock()
	now := c.now()
	operation, err := domain.NewOperation(request.ApplicationID, request.EnvironmentID, domain.OperationDestroy, "destroy/"+request.DeploymentID.String(), request.IdempotencyKey, now)
	if err != nil {
		return M2GroupDestroyResult{}, err
	}
	operation.ID = m2ID("operation", request.IdempotencyKey)
	parameters, err := json.Marshal(contracts.DestroyRequest{DeploymentID: request.DeploymentID, PreserveVolumes: request.PreserveVolumes, ConfirmationToken: request.ConfirmationToken, Operation: m2OperationContext(request.IdempotencyKey, request.Actor, request.Deadline)})
	if err != nil {
		return M2GroupDestroyResult{}, err
	}
	payload, err := json.Marshal(AgentTaskSpec{Kind: v1.TaskDestroyGroup, Parameters: parameters})
	if err != nil {
		return M2GroupDestroyResult{}, err
	}
	taskID := m2ID("task", request.IdempotencyKey)
	if _, err := c.Store.EnqueueControllerTask(ctx, postgres.EnqueueControllerTaskRequest{Operation: operation, ExistingDeploymentID: request.DeploymentID, TaskID: taskID, Payload: payload, MaxAttempts: 3, InitialPublishStatus: domain.PublishDeploying}); err != nil {
		return M2GroupDestroyResult{}, err
	}
	result := M2GroupDestroyResult{Operation: operation, TaskID: taskID}
	c.mu.Lock()
	c.destroys[request.IdempotencyKey] = destroyRun{fingerprint: fingerprint, result: result}
	c.mu.Unlock()
	return result, nil
}

// Destroy is a concise compatibility alias used by API adapters.
func (c *M2ReleaseController) Destroy(ctx context.Context, request M2GroupDestroyRequest) (M2GroupDestroyResult, error) {
	return c.EnqueueGroupDestroy(ctx, request)
}

func (c *M2ReleaseController) validateController() error {
	if c.Store == nil || c.Capacity == nil {
		return errors.New("M2 release controller requires store and capacity providers")
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	return nil
}

func (c *M2ReleaseController) now() time.Time {
	if c.Clock == nil {
		c.Clock = time.Now
	}
	return c.Clock().UTC()
}

func (c *M2ReleaseController) preflightRuntime(ctx context.Context, key, actor string, deadline time.Time, spec contracts.ServiceGroupRuntimeSpec) error {
	resources, err := spec.AggregateResources()
	if err != nil {
		return err
	}
	hostPorts := 1
	if spec.Rollout.Mode == contracts.RuntimeRolloutRolling && !spec.Rollout.PreviousDeploymentID.Empty() {
		if resources.CPUMillis > (1<<62) || resources.MemoryBytes > (1<<62) || resources.DiskBytes > (1<<62) || resources.PIDs > (1<<62) {
			return domain.ValidationError("rolling runtime capacity overflows")
		}
		resources.CPUMillis *= 2
		resources.MemoryBytes *= 2
		resources.DiskBytes *= 2
		resources.PIDs *= 2
		// The active deployment already owns its loopback port in the capacity
		// snapshot. A rolling candidate requests exactly one additional port;
		// CapacityRequest intentionally forbids bulk/ad-hoc port reservations.
	}
	_, _, err = c.Capacity.Preflight(ctx, contracts.CapacityRequest{Scope: contracts.CapacityRuntime, Resources: resources, HostPorts: hostPorts, Operation: m2OperationContext(key+":capacity-runtime", actor, deadline)})
	return err
}

func aggregateM2BuildResources(request M2CompleteReleaseRequest, names []string) (contracts.ResourceLimits, error) {
	var total contracts.ResourceLimits
	for _, name := range names {
		input, ok := request.BuildServices[name]
		if !ok {
			return contracts.ResourceLimits{}, domain.ValidationError("M2 build resource input is missing")
		}
		if input.Resources.CPUMillis < 0 || input.Resources.MemoryBytes < 0 || input.Resources.DiskBytes <= 0 || input.Resources.PIDs < 0 {
			return contracts.ResourceLimits{}, domain.ValidationError("M2 build resources are invalid")
		}
		if total.CPUMillis > (1<<62)-input.Resources.CPUMillis || total.MemoryBytes > (1<<62)-input.Resources.MemoryBytes || total.DiskBytes > (1<<62)-input.Resources.DiskBytes || total.PIDs > (1<<62)-input.Resources.PIDs {
			return contracts.ResourceLimits{}, domain.ValidationError("M2 build resources overflow")
		}
		total.CPUMillis += input.Resources.CPUMillis
		total.MemoryBytes += input.Resources.MemoryBytes
		total.DiskBytes += input.Resources.DiskBytes
		total.PIDs += input.Resources.PIDs
		if input.Resources.TimeoutSeconds > total.TimeoutSeconds {
			total.TimeoutSeconds = input.Resources.TimeoutSeconds
		}
	}
	if len(names) > 0 && total.DiskBytes <= 0 {
		return contracts.ResourceLimits{}, domain.ValidationError("M2 build disk capacity is required")
	}
	return total, nil
}

func aggregateM2RuntimeResources(request M2CompleteReleaseRequest, services []domain.ServiceSpec) (contracts.ResourceLimits, error) {
	var total contracts.ResourceLimits
	for _, service := range services {
		resources, ok := request.Runtime[service.Name]
		if !ok {
			return contracts.ResourceLimits{}, domain.ValidationError("M2 runtime resource input is missing")
		}
		if resources.CPUMillis <= 0 || resources.MemoryBytes <= 0 || resources.DiskBytes <= 0 || resources.PIDs <= 0 {
			return contracts.ResourceLimits{}, domain.ValidationError("M2 runtime CPU, memory, disk and PID limits must be positive")
		}
		if total.CPUMillis > (1<<62)-resources.CPUMillis || total.MemoryBytes > (1<<62)-resources.MemoryBytes || total.DiskBytes > (1<<62)-resources.DiskBytes || total.PIDs > (1<<62)-resources.PIDs {
			return contracts.ResourceLimits{}, domain.ValidationError("M2 runtime resources overflow")
		}
		total.CPUMillis += resources.CPUMillis
		total.MemoryBytes += resources.MemoryBytes
		total.DiskBytes += resources.DiskBytes
		total.PIDs += resources.PIDs
	}
	// Writable named volumes are part of the runtime capacity contract.  Count
	// each claim once even when several services mount the same claim.
	for _, claim := range request.VolumeClaims {
		if claim.SizeBytes <= 0 || total.DiskBytes > (1<<62)-claim.SizeBytes {
			return contracts.ResourceLimits{}, domain.ValidationError("M2 runtime volume capacity is invalid")
		}
		total.DiskBytes += claim.SizeBytes
	}
	return total, nil
}

func (c *M2ReleaseController) resolvePrebuilt(ctx context.Context, request M2CompleteReleaseRequest, service domain.ServiceSpec) (domain.ImageDigest, string, error) {
	if service.Source.Prebuilt == nil {
		return domain.ImageDigest{}, "", domain.ValidationError("prebuilt source is missing")
	}
	if image := service.Source.Prebuilt.Image; image.Repository != "" || image.Digest != "" {
		if err := image.Validate(); err != nil {
			return domain.ImageDigest{}, "", err
		}
		return image, service.Source.Prebuilt.Reference, nil
	}
	resolveRequest, ok := request.Registry[service.Name]
	if !ok {
		repository, tag, err := splitM2ImageReference(service.Source.Prebuilt.Reference)
		if err != nil {
			return domain.ImageDigest{}, "", err
		}
		resolveRequest = contracts.ImageResolveRequest{Repository: repository, Tag: tag}
	}
	resolveRequest.Operation = m2OperationContext(request.IdempotencyKey+":resolve:"+service.Name, request.Actor, request.Deadline)
	result, err := c.Registry.ResolveAndPull(ctx, resolveRequest)
	if err != nil {
		return domain.ImageDigest{}, "", err
	}
	if err := result.Image.Validate(); err != nil {
		return domain.ImageDigest{}, "", fmt.Errorf("registry returned invalid digest: %w", err)
	}
	resolvedFrom := resolveRequest.Repository + ":" + resolveRequest.Tag
	return result.Image, resolvedFrom, nil
}

func m2RuntimeSpec(request M2CompleteReleaseRequest, services []domain.ServiceSpec, images map[string]domain.ImageDigest, aggregate contracts.ResourceLimits, releaseID domain.ID) (contracts.ServiceGroupRuntimeSpec, error) {
	environmentID := request.EnvironmentID
	if environmentID.Empty() {
		// A release is environment-independent. API adapters that know the
		// target environment should set it before enqueueing the task.
		environmentID = "environment-m2"
	}
	runtime := contracts.ServiceGroupRuntimeSpec{SchemaVersion: contracts.ServiceGroupRuntimeSchema, ApplicationID: request.Group.ApplicationID, EnvironmentID: environmentID, ReleaseID: releaseID, ServiceGroupID: request.Group.ID, ConfigDigest: request.Identity.ConfigDigest, EntryService: "", Services: make([]contracts.ServiceRuntimeSpec, 0, len(services)), Rollout: m2RuntimeRollout(request.Rollout)}
	for _, service := range services {
		image, ok := images[service.Name]
		if !ok {
			return contracts.ServiceGroupRuntimeSpec{}, domain.ValidationError("M2 runtime image set is incomplete")
		}
		resources := request.Runtime[service.Name]
		env := make([]contracts.RuntimeEnvironmentVariable, 0, len(service.Environment))
		for name, value := range service.Environment {
			env = append(env, contracts.RuntimeEnvironmentVariable{Name: name, Kind: contracts.RuntimeEnvironmentLiteral, Value: value})
		}
		sort.Slice(env, func(i, j int) bool { return env[i].Name < env[j].Name })
		ports := append([]int(nil), service.Ports...)
		if len(ports) == 0 && service.Port > 0 {
			ports = []int{service.Port}
		}
		dependencies := append([]domain.ServiceDependency(nil), service.Dependencies...)
		sort.Slice(dependencies, func(i, j int) bool { return dependencies[i].Service < dependencies[j].Service })
		runtime.Services = append(runtime.Services, contracts.ServiceRuntimeSpec{Name: service.Name, Role: service.Role, Required: service.Required, Image: image, Resources: resources, Volumes: append([]domain.VolumeMount(nil), service.Volumes...), Dependencies: dependencies, Entrypoint: append([]string(nil), service.Entrypoint...), Command: append([]string(nil), service.Command...), Environment: env, ContainerPorts: ports, Healthcheck: service.Healthcheck, Restart: service.Restart})
		if runtime.EntryService == "" && service.Role == domain.RoleIngress {
			runtime.EntryService = service.Name
		}
	}
	for _, claim := range request.VolumeClaims {
		runtime.VolumeClaims = append(runtime.VolumeClaims, contracts.RuntimeVolumeClaim{ID: claim.ID, Name: claim.Name, SizeBytes: claim.SizeBytes, Retain: claim.Retain})
	}
	_ = aggregate // AggregateResources rechecks the exact per-service limits.
	if runtime.EntryService == "" {
		return contracts.ServiceGroupRuntimeSpec{}, domain.ValidationError("M2 runtime group requires an ingress service")
	}
	if err := runtime.Validate(); err != nil {
		return contracts.ServiceGroupRuntimeSpec{}, err
	}
	return runtime, nil
}

func m2RuntimeRollout(policy postgres.M2ReleaseRollout) contracts.RuntimeRolloutPolicy {
	mode := contracts.RuntimeRolloutMode(policy.Mode)
	if mode == "" {
		mode = contracts.RuntimeRolloutInitial
	}
	return contracts.RuntimeRolloutPolicy{Mode: mode, PreviousDeploymentID: policy.PreviousDeploymentID, PreserveOldUntilHealthy: policy.PreserveOldUntilHealthy, DowntimeApproved: policy.DowntimeApproved}
}

func validateM2CompleteRequest(request M2CompleteReleaseRequest) error {
	if err := request.Group.Validate(); err != nil {
		return err
	}
	if !request.Source.ID.Empty() {
		if err := request.Source.Validate(); err != nil {
			return err
		}
		if request.Source.ApplicationID != request.Group.ApplicationID {
			return domain.ValidationError("M2 source and group applications do not match")
		}
	}
	if err := request.Identity.Validate(); err != nil {
		return err
	}
	if request.Identity.Version != int64(request.Version) || request.Identity.DefinitionID.Empty() || strings.TrimSpace(request.IdempotencyKey) == "" {
		return domain.ValidationError("M2 release identity and idempotency key are inconsistent")
	}
	if err := validateM2Claims(request.VolumeClaims); err != nil {
		return err
	}
	if request.Rollout.Mode == "" {
		request.Rollout.Mode = "initial"
	}
	return nil
}

func validateM2Claims(claims []postgres.M2ServiceGroupVolumeClaim) error {
	seen := map[string]struct{}{}
	for _, claim := range claims {
		if claim.ID.Empty() || strings.TrimSpace(claim.Name) == "" || strings.HasPrefix(claim.Name, "/") || strings.Contains(claim.Name, "..") || claim.SizeBytes <= 0 || !claim.Retain {
			return domain.ValidationError("M2 volume claim is invalid")
		}
		if _, ok := seen[claim.Name]; ok {
			return domain.ValidationError("M2 volume claim names must be unique")
		}
		seen[claim.Name] = struct{}{}
	}
	return nil
}

func (c *M2ReleaseController) canReuseM2Service(previous *M2PreviousRelease, name string, service domain.ServiceSpec) bool {
	_, ok := c.reusedBinding(previous, name, service)
	return ok
}

func (c *M2ReleaseController) reusedBinding(previous *M2PreviousRelease, name string, service domain.ServiceSpec) (postgres.M2ReleaseServiceBinding, bool) {
	if previous == nil || previous.Release.ServiceGroupID.Empty() || previous.Group.ID.Empty() {
		return postgres.M2ReleaseServiceBinding{}, false
	}
	old := map[string]domain.ServiceSpec{}
	for _, item := range previous.Group.Services {
		old[item.Name] = item
	}
	prior, ok := old[name]
	if !ok || m2JSONDigest(prior) != m2JSONDigest(service) {
		return postgres.M2ReleaseServiceBinding{}, false
	}
	images := previous.Release.ServiceDigests()
	image, ok := images[name]
	if !ok || image.Validate() != nil {
		return postgres.M2ReleaseServiceBinding{}, false
	}
	for _, binding := range previous.Bindings {
		if binding.ServiceName == name {
			binding.Image = image
			return binding, true
		}
	}
	return postgres.M2ReleaseServiceBinding{}, false
}

func cloneM2Claims(input []postgres.M2ServiceGroupVolumeClaim) []postgres.M2ServiceGroupVolumeClaim {
	return append([]postgres.M2ServiceGroupVolumeClaim(nil), input...)
}

func splitM2ImageReference(reference string) (string, string, error) {
	reference = strings.TrimSpace(reference)
	if reference == "" || strings.Contains(reference, "@") || strings.ContainsAny(reference, "\r\n\x00 ") {
		return "", "", domain.ValidationError("prebuilt image reference must be repository:tag")
	}
	index := strings.LastIndex(reference, ":")
	if index <= strings.LastIndex(reference, "/") || index == len(reference)-1 {
		return "", "", domain.ValidationError("prebuilt image reference must include an explicit tag")
	}
	return reference[:index], reference[index+1:], nil
}

func m2Operation(request contracts.OperationContext, suffix string) contracts.OperationContext {
	request.IdempotencyKey += suffix
	return request
}

func m2OperationContext(key, actor string, deadline time.Time) contracts.OperationContext {
	return contracts.OperationContext{IdempotencyKey: key, Actor: actor, Deadline: deadline}
}

func m2ID(prefix string, parts ...string) domain.ID {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(part))
	}
	return domain.ID(prefix + "_" + hex.EncodeToString(hash.Sum(nil))[:32])
}

func m2JSONDigest(value any) string {
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validM2Digest(value string) bool {
	value = strings.TrimPrefix(strings.TrimSpace(value), "sha256:")
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func safeSegment(value string) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "service"
	}
	return b.String()
}
