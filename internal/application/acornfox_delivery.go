package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const acornFoxDeliveryTaskAttempts = 3

// Failure facts outlive the cancelled HTTP request, but may not wait forever
// for PostgreSQL. This budget applies only to terminal failure persistence.
const acornFoxDeliveryFailureTimeout = 5 * time.Second

// AcornFoxDockerfileImporter reads the root Dockerfile projection from an
// already accepted immutable source. It deliberately accepts no client
// workspace path or Dockerfile contents.
type AcornFoxDockerfileImporter interface {
	Import(domain.SourceRevision) (contracts.AcornFoxDockerfileDefinition, error)
}

// AcornFoxDeliveryIdempotencyStore is the durable command boundary. A caller
// must reserve a command before a provider call, so a replay never builds or
// queues a second deployment.
type AcornFoxDeliveryIdempotencyStore interface {
	BeginAcornFoxDelivery(context.Context, domain.ID, string, string, time.Time) (AcornFoxDeliveryResult, bool, error)
	ReplayAcornFoxDelivery(context.Context, domain.ID, string, string) (AcornFoxDeliveryResult, bool, error)
	FailAcornFoxDelivery(context.Context, string, string, string, time.Time) error
}

// AcornFoxDeliverySourceStore is intentionally read-only. The public command
// names a revision ID, but its immutable source and application ownership come
// exclusively from this store. Reads must enforce public-Git or claimed-upload provenance.
type AcornFoxDeliverySourceStore interface {
	GetAcornFoxSourceRevision(context.Context, domain.ID, domain.ID) (domain.SourceRevision, error)
	GetAcornFoxEnvironment(context.Context, domain.ID) (domain.ID, error)
	NextAcornFoxDefinitionVersion(context.Context, domain.ID) (int, error)
	NextAcornFoxReleaseVersion(context.Context, domain.ID) (int, error)
	CreateAcornFoxDefinition(context.Context, domain.ApplicationDeliveryDefinition) (domain.ApplicationDeliveryDefinition, error)
}

// AcornFoxDeliveryBuildStore is the smallest bridge to the existing immutable
// build and release facts. The concrete PostgreSQL adapter owns its legacy
// ReleaseCreation wrapper; this application package must not import it.
type AcornFoxDeliveryBuildStore interface {
	CreateBuildPlan(context.Context, domain.BuildPlan) (domain.BuildPlan, error)
	CreateBuild(context.Context, domain.Build) (domain.Build, error)
	StartBuild(context.Context, domain.ID, time.Time) (domain.Build, error)
	CompleteAcornFoxBuild(context.Context, domain.Artifact, domain.Release, domain.ID, time.Time) (domain.Build, error)
	FailBuild(context.Context, domain.ID, string, time.Time) (domain.Build, error)
}

// AcornFoxQueuedTask carries only a marked Agent task. It has no generic
// parameters escape hatch, which prevents legacy scale/rollback/group payloads
// from entering the standalone delivery path.
type AcornFoxQueuedTask struct {
	Operation            domain.Operation
	Deployment           *domain.Deployment
	ExistingDeploymentID domain.ID
	TaskID               domain.ID
	Payload              json.RawMessage
	MaxAttempts          int
}

// AcornFoxDeliveryTaskStore persists an Agent task and its operation in one
// durable transaction. The adapter must reject an unmarked task payload.
type AcornFoxDeliveryTaskStore interface {
	CommitAcornFoxDeliveryTask(context.Context, AcornFoxQueuedTask, string, string, AcornFoxDeliveryResult, time.Time) error
}

// AcornFoxRuntimeFactStore recovers the exact accepted deploy fact for a
// deployment. It is the authority for later actions; a caller cannot submit a
// different image, port, resource request, address, or observation.
type AcornFoxRuntimeFactStore interface {
	GetAcornFoxRuntimeRequest(context.Context, domain.ID, domain.ID) (contracts.AcornFoxRuntimeDeployRequest, error)
}

// AcornFoxRuntimeObservationStore reads a previously persisted, Agent-origin
// runtime fact. It is intentionally not a live Docker/runtime driver: the
// control plane cannot manufacture or select a network target for a probe.
type AcornFoxRuntimeObservationStore interface {
	GetAcornFoxRuntimeObservation(context.Context, domain.ID, domain.ID) (contracts.AcornFoxRuntimeObservation, error)
}

type AcornFoxDeliveryConfig struct {
	TargetRepository string
	StorageKeyPrefix string
	// BuildNetwork is supplied by the trusted server composition, never by a
	// public delivery request. Its zero value preserves the offline contract.
	BuildNetwork contracts.NetworkPolicy
}

func (config AcornFoxDeliveryConfig) validate() error {
	if strings.TrimSpace(config.TargetRepository) == "" || strings.TrimSpace(config.StorageKeyPrefix) == "" {
		return errors.New("AcornFox delivery target repository and storage key prefix are required")
	}
	return config.BuildNetwork.Validate()
}

// AcornFoxDeliveryService is the narrow command service behind the standalone
// `/api/v1/acornfox` façade. It has no DNS, logs, public reachability,
// rollback, scale, rolling, group, volume, or Kubernetes behavior.
type AcornFoxDeliveryService struct {
	RuntimeConfigurationGate func(context.Context) error
	Idempotency              AcornFoxDeliveryIdempotencyStore
	Sources                  AcornFoxDeliverySourceStore
	Importer                 AcornFoxDockerfileImporter
	Builds                   AcornFoxDeliveryBuildStore
	Tasks                    AcornFoxDeliveryTaskStore
	Runtime                  AcornFoxRuntimeFactStore
	Observer                 AcornFoxRuntimeObservationStore
	Builder                  contracts.BuildProvider
	Capacity                 contracts.CapacityProvider
	Config                   AcornFoxDeliveryConfig
	Clock                    func() time.Time
}

type AcornFoxDeliveryCreateRequest struct {
	Runtime          *contracts.AcornFoxRuntimeInput
	ApplicationID    domain.ID
	SourceRevisionID domain.ID
	ContainerPort    int
	IdempotencyKey   string
	Actor            string
}

type AcornFoxDeliveryActionRequest struct {
	ApplicationID  domain.ID
	DeploymentID   domain.ID
	IdempotencyKey string
	Actor          string
}

type AcornFoxDeliveryProbeRequest struct {
	AcornFoxDeliveryActionRequest
	Protocol contracts.AcornFoxProbeProtocol
	HTTPPath string
}

// AcornFoxDeliveryResult is the durable command result shared by normal
// execution and replay. Status only describes command acceptance; it is not a
// runtime, response, health, public DNS, or TLS assertion.
type AcornFoxDeliveryResult struct {
	DeploymentID domain.ID `json:"deployment_id"`
	OperationID  domain.ID `json:"operation_id"`
	TaskID       domain.ID `json:"task_id"`
	Status       string    `json:"status"`
}

func (service *AcornFoxDeliveryService) Create(ctx context.Context, request AcornFoxDeliveryCreateRequest) (AcornFoxDeliveryResult, error) {
	if err := service.readyForCreate(); err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	if err := validateAcornFoxDeliveryCreate(request); err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	now := service.now()
	digest := acornFoxDeliveryDigest("create", request.ApplicationID.String(), request.SourceRevisionID.String(), fmt.Sprint(request.ContainerPort), strings.TrimSpace(service.Config.TargetRepository), strings.TrimSpace(service.Config.StorageKeyPrefix))
	digest = configuredAcornFoxRequestDigest(request, digest)
	if replay, found, err := service.Idempotency.BeginAcornFoxDelivery(ctx, request.ApplicationID, request.IdempotencyKey, digest, now); err != nil {
		return AcornFoxDeliveryResult{}, err
	} else if found {
		return replay, nil
	}

	result, err := service.create(ctx, request, nil, now, func(queued AcornFoxQueuedTask, result AcornFoxDeliveryResult) error {
		return service.Tasks.CommitAcornFoxDeliveryTask(ctx, queued, request.IdempotencyKey, digest, result, service.now())
	})
	if err != nil {
		return AcornFoxDeliveryResult{}, service.failDelivery(ctx, request.IdempotencyKey, digest, err)
	}
	return result, nil
}

// CreateVerifiedCandidate enters the normal release path only after W10 has
// matched a W05-imported source. The release-time BuildKit result must equal
// the OCI digest that passed isolated candidate runtime validation.
func (service *AcornFoxDeliveryService) CreateVerifiedCandidate(ctx context.Context, request AcornFoxDeliveryCreateRequest, expectedImage domain.ImageDigest) (AcornFoxDeliveryResult, error) {
	if err := service.readyForCreate(); err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	if err := validateAcornFoxDeliveryCreate(request); err != nil || expectedImage.Validate() != nil {
		return AcornFoxDeliveryResult{}, domain.ValidationError("verified candidate delivery is invalid")
	}
	now := service.now()
	digest := acornFoxDeliveryDigest("verified-candidate", request.ApplicationID.String(), request.SourceRevisionID.String(), fmt.Sprint(request.ContainerPort), expectedImage.Repository, expectedImage.Digest, strings.TrimSpace(service.Config.TargetRepository), strings.TrimSpace(service.Config.StorageKeyPrefix))
	digest = configuredAcornFoxRequestDigest(request, digest)
	if replay, found, err := service.Idempotency.BeginAcornFoxDelivery(ctx, request.ApplicationID, request.IdempotencyKey, digest, now); err != nil {
		return AcornFoxDeliveryResult{}, err
	} else if found {
		return replay, nil
	}
	result, err := service.create(ctx, request, &expectedImage, now, func(queued AcornFoxQueuedTask, result AcornFoxDeliveryResult) error {
		return service.Tasks.CommitAcornFoxDeliveryTask(ctx, queued, request.IdempotencyKey, digest, result, service.now())
	})
	if err != nil {
		return AcornFoxDeliveryResult{}, service.failDelivery(ctx, request.IdempotencyKey, digest, err)
	}
	return result, nil
}

// ReplayVerifiedCandidate is read-only. It never reserves a publish key, so an
// expired candidate can confirm a previously accepted delivery without
// opening a path to new build or runtime work.
func (service *AcornFoxDeliveryService) ReplayVerifiedCandidate(ctx context.Context, request AcornFoxDeliveryCreateRequest, expectedImage domain.ImageDigest) (AcornFoxDeliveryResult, bool, error) {
	if err := validateAcornFoxDeliveryCreate(request); err != nil || expectedImage.Validate() != nil || service == nil || service.Idempotency == nil {
		return AcornFoxDeliveryResult{}, false, domain.ValidationError("verified candidate delivery replay is invalid")
	}
	digest := acornFoxDeliveryDigest("verified-candidate", request.ApplicationID.String(), request.SourceRevisionID.String(), fmt.Sprint(request.ContainerPort), expectedImage.Repository, expectedImage.Digest, strings.TrimSpace(service.Config.TargetRepository), strings.TrimSpace(service.Config.StorageKeyPrefix))
	digest = configuredAcornFoxRequestDigest(request, digest)
	return service.Idempotency.ReplayAcornFoxDelivery(ctx, request.ApplicationID, request.IdempotencyKey, digest)
}

func (service *AcornFoxDeliveryService) create(ctx context.Context, request AcornFoxDeliveryCreateRequest, expectedImage *domain.ImageDigest, now time.Time, commit func(AcornFoxQueuedTask, AcornFoxDeliveryResult) error) (AcornFoxDeliveryResult, error) {
	configuration, resources, configDigest, err := resolveAcornFoxRuntimeInput(request.Runtime, request.ContainerPort)
	if err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	if configuration != nil {
		if service.RuntimeConfigurationGate == nil {
			return AcornFoxDeliveryResult{}, domain.NewError(domain.ErrUnsupportedCapability, "configured runtime is unavailable")
		}
		if err := service.RuntimeConfigurationGate(ctx); err != nil {
			return AcornFoxDeliveryResult{}, err
		}
	}
	source, err := service.Sources.GetAcornFoxSourceRevision(ctx, request.ApplicationID, request.SourceRevisionID)
	if err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	if err := validateAcornFoxDeliverySource(source, request.ApplicationID); err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	definition, err := service.Importer.Import(source)
	if err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	if err := definition.Validate(); err != nil || definition.Status != contracts.AcornFoxDockerfileReady || definition.SourceRevisionID != source.ID || definition.SourceContentDigest != source.ContentDigest {
		return AcornFoxDeliveryResult{}, errors.New("AcornFox root Dockerfile definition is not ready")
	}
	environmentID, err := service.Sources.GetAcornFoxEnvironment(ctx, request.ApplicationID)
	if err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	if environmentID.Empty() {
		return AcornFoxDeliveryResult{}, errors.New("AcornFox application environment is unavailable")
	}
	definitionVersion, err := service.Sources.NextAcornFoxDefinitionVersion(ctx, request.ApplicationID)
	if err != nil || definitionVersion < 1 {
		if err != nil {
			return AcornFoxDeliveryResult{}, err
		}
		return AcornFoxDeliveryResult{}, errors.New("AcornFox definition version is invalid")
	}
	acceptedDefinition := domain.ApplicationDeliveryDefinition{
		ID:               domain.ID("def_" + acornFoxDeliveryDigest("definition", request.IdempotencyKey)[:32]),
		ApplicationID:    request.ApplicationID,
		SourceRevisionID: source.ID,
		Version:          definitionVersion,
		Facts:            map[string]domain.FieldFact{},
		CreatedAt:        now,
		Immutable:        true,
	}
	if configuration != nil {
		acceptedDefinition.Facts["runtime_configuration"] = acornFoxRuntimeDefinitionFact(configuration, resources, request.ContainerPort, configDigest)
	}
	if err := acceptedDefinition.Validate(); err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	acceptedDefinition, err = service.Sources.CreateAcornFoxDefinition(ctx, acceptedDefinition)
	if err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	if acceptedDefinition.ApplicationID != request.ApplicationID || acceptedDefinition.SourceRevisionID != source.ID || !acceptedDefinition.Immutable {
		return AcornFoxDeliveryResult{}, errors.New("AcornFox delivery definition persistence returned an invalid result")
	}

	if configuration != nil {
		if err := validatePersistedAcornFoxRuntimeDefinition(acceptedDefinition, acornFoxRuntimeDefinitionFact(configuration, resources, request.ContainerPort, configDigest)); err != nil {
			return AcornFoxDeliveryResult{}, err
		}
	}
	binder := AcornFoxBuildBinder{}
	target := strings.TrimSpace(service.Config.TargetRepository)
	storageKey := acornFoxDeliveryStorageKey(service.Config.StorageKeyPrefix, request.ApplicationID, source.ID, request.IdempotencyKey)
	var buildRequest contracts.BuildRequest
	if service.Config.BuildNetwork.EffectiveMode() == contracts.NetworkModeControlledEgressV1 {
		buildRequest, err = binder.BindControlledEgress(definition, source, request.IdempotencyKey+":build", target, storageKey, service.Config.BuildNetwork.WorkerPolicyDigest, now)
	} else {
		buildRequest, err = binder.Bind(definition, source, request.IdempotencyKey+":build", target, storageKey, now)
	}
	if err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	plan, err := service.Builds.CreateBuildPlan(ctx, buildRequest.Plan)
	if err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	build := domain.Build{ID: buildRequest.BuildID, PlanID: plan.ID, Status: domain.BuildPending, CreatedAt: now, UpdatedAt: now}
	if _, err := service.Builds.CreateBuild(ctx, build); err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	if _, err := service.Builds.StartBuild(ctx, build.ID, service.now()); err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	lease, err := service.Capacity.Reserve(ctx, contracts.CapacityRequest{Scope: contracts.CapacityBuild, Resources: buildRequest.Resources, Operation: contracts.OperationContext{IdempotencyKey: request.IdempotencyKey + ":build-capacity", Actor: request.Actor}})
	if err != nil {
		return AcornFoxDeliveryResult{}, service.failBuild(ctx, build.ID, err)
	}
	defer service.Capacity.Release(context.Background(), lease, contracts.OperationContext{IdempotencyKey: request.IdempotencyKey + ":build-capacity-release", Actor: request.Actor})
	built, err := service.Builder.Build(ctx, contracts.BuildRequest{BuildID: build.ID, Plan: plan, Source: source, Resources: buildRequest.Resources, Network: buildRequest.Network, Operation: buildRequest.Operation, Capacity: &lease})
	if err != nil {
		return AcornFoxDeliveryResult{}, service.failBuild(ctx, build.ID, err)
	}
	if built.Artifact == nil || built.Build.ID != build.ID || built.Build.PlanID != plan.ID || built.Build.Status != domain.BuildSucceeded || built.Artifact.BuildID != build.ID {
		return AcornFoxDeliveryResult{}, service.failBuild(ctx, build.ID, errors.New("AcornFox build provider returned an unbound or unsuccessful result"))
	}
	if expectedImage != nil && built.Artifact.Image != *expectedImage {
		return AcornFoxDeliveryResult{}, service.failBuild(ctx, build.ID, ErrAcornFoxFixCandidateMismatch)
	}
	releaseVersion, err := service.Sources.NextAcornFoxReleaseVersion(ctx, request.ApplicationID)
	if err != nil || releaseVersion < 1 {
		if err != nil {
			return AcornFoxDeliveryResult{}, service.failBuild(ctx, build.ID, err)
		}
		return AcornFoxDeliveryResult{}, service.failBuild(ctx, build.ID, errors.New("AcornFox release version is invalid"))
	}
	// Release still has a historic mandatory service-group field. "legacy" is
	// an unexposed persistence compatibility value only; no group behavior is
	// enabled, exposed, or accepted by this service.
	releaseConfigDigest := acornFoxDeliveryDigest(plan.ID.String(), built.Artifact.Image.Digest)
	if configuration != nil {
		releaseConfigDigest = configDigest
	}
	release, err := domain.NewRelease(request.ApplicationID, "legacy", releaseVersion, releaseConfigDigest, map[string]domain.ImageDigest{"web": built.Artifact.Image}, service.now())
	if err != nil {
		return AcornFoxDeliveryResult{}, service.failBuild(ctx, build.ID, err)
	}
	release.ID = domain.ID("rel_" + acornFoxDeliveryDigest("release", plan.ID.String(), built.Artifact.Image.Digest)[:32])
	if configuration != nil {
		release.ID = domain.ID("rel_" + acornFoxDeliveryDigest("release", plan.ID.String(), built.Artifact.Image.Digest, configDigest)[:32])
	}
	if _, err := service.Builds.CompleteAcornFoxBuild(ctx, *built.Artifact, *release, acceptedDefinition.ID, service.now()); err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	fact, err := contracts.ProjectAcornFoxRuntimeReleaseFact(*release, environmentID, resources, request.ContainerPort, now)
	if configuration != nil {
		fact, err = contracts.ProjectAcornFoxConfiguredRuntimeReleaseFact(*release, environmentID, resources, request.ContainerPort, now, *configuration)
	}
	if err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	queued, result, err := service.prepareRuntimeTask(fact, request.IdempotencyKey, request.Actor, domain.OperationDeploy, false, "deploy", nil, now)
	if err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	if err := commit(queued, result); err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	return result, nil
}

func (service *AcornFoxDeliveryService) Restart(ctx context.Context, request AcornFoxDeliveryActionRequest) (AcornFoxDeliveryResult, error) {
	return service.action(ctx, request, domain.OperationRestart, "restart", false)
}

func (service *AcornFoxDeliveryService) Redeploy(ctx context.Context, request AcornFoxDeliveryActionRequest) (AcornFoxDeliveryResult, error) {
	return service.action(ctx, request, domain.OperationRedeploy, "redeploy", true)
}

func (service *AcornFoxDeliveryService) action(ctx context.Context, request AcornFoxDeliveryActionRequest, operationType domain.OperationType, action string, recreate bool) (AcornFoxDeliveryResult, error) {
	if err := service.readyForAction(false); err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	if err := validateAcornFoxDeliveryAction(request); err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	now := service.now()
	digest := acornFoxDeliveryDigest(action, request.ApplicationID.String(), request.DeploymentID.String())
	if replay, found, err := service.Idempotency.BeginAcornFoxDelivery(ctx, request.ApplicationID, request.IdempotencyKey, digest, now); err != nil {
		return AcornFoxDeliveryResult{}, err
	} else if found {
		return replay, nil
	}
	runtimeRequest, err := service.trustedRuntimeRequest(ctx, request.ApplicationID, request.DeploymentID)
	if err != nil {
		return AcornFoxDeliveryResult{}, service.failDelivery(ctx, request.IdempotencyKey, digest, err)
	}
	queued, result, err := service.prepareRuntimeTask(runtimeRequest.Fact, request.IdempotencyKey, request.Actor, operationType, recreate, action, &request.DeploymentID, now)
	if err != nil {
		return AcornFoxDeliveryResult{}, service.failDelivery(ctx, request.IdempotencyKey, digest, err)
	}
	if err := service.Tasks.CommitAcornFoxDeliveryTask(ctx, queued, request.IdempotencyKey, digest, result, service.now()); err != nil {
		return AcornFoxDeliveryResult{}, service.failDelivery(ctx, request.IdempotencyKey, digest, err)
	}
	return result, nil
}

func (service *AcornFoxDeliveryService) Probe(ctx context.Context, request AcornFoxDeliveryProbeRequest) (AcornFoxDeliveryResult, error) {
	if err := service.readyForAction(true); err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	if err := validateAcornFoxDeliveryAction(request.AcornFoxDeliveryActionRequest); err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	now := service.now()
	digest := acornFoxDeliveryDigest("probe", request.ApplicationID.String(), request.DeploymentID.String(), string(request.Protocol), request.HTTPPath)
	if replay, found, err := service.Idempotency.BeginAcornFoxDelivery(ctx, request.ApplicationID, request.IdempotencyKey, digest, now); err != nil {
		return AcornFoxDeliveryResult{}, err
	} else if found {
		return replay, nil
	}
	runtimeRequest, err := service.trustedRuntimeRequest(ctx, request.ApplicationID, request.DeploymentID)
	if err != nil {
		return AcornFoxDeliveryResult{}, service.failDelivery(ctx, request.IdempotencyKey, digest, err)
	}
	probeRequest, err := contracts.NewAcornFoxProbeRequest(contracts.AcornFoxRuntimeReference{Fact: runtimeRequest.Fact}, request.Protocol, request.HTTPPath, request.IdempotencyKey)
	if err != nil {
		return AcornFoxDeliveryResult{}, service.failDelivery(ctx, request.IdempotencyKey, digest, err)
	}
	current, err := service.Observer.GetAcornFoxRuntimeObservation(ctx, request.ApplicationID, request.DeploymentID)
	if err != nil {
		return AcornFoxDeliveryResult{}, service.failDelivery(ctx, request.IdempotencyKey, digest, err)
	}
	plan, err := BuildAcornFoxProbeTaskPlan(probeRequest, current, now)
	if err != nil {
		return AcornFoxDeliveryResult{}, service.failDelivery(ctx, request.IdempotencyKey, digest, err)
	}
	queued := AcornFoxQueuedTask{Operation: plan.Operation, ExistingDeploymentID: request.DeploymentID, TaskID: plan.TaskID, Payload: plan.Payload, MaxAttempts: acornFoxDeliveryTaskAttempts}
	result := AcornFoxDeliveryResult{DeploymentID: request.DeploymentID, OperationID: plan.Operation.ID, TaskID: plan.TaskID, Status: "accepted"}
	if err := service.Tasks.CommitAcornFoxDeliveryTask(ctx, queued, request.IdempotencyKey, digest, result, service.now()); err != nil {
		return AcornFoxDeliveryResult{}, service.failDelivery(ctx, request.IdempotencyKey, digest, err)
	}
	return result, nil
}

func (service *AcornFoxDeliveryService) prepareRuntimeTask(fact contracts.AcornFoxRuntimeReleaseFact, idempotencyKey, actor string, operationType domain.OperationType, recreate bool, action string, existing *domain.ID, now time.Time) (AcornFoxQueuedTask, AcornFoxDeliveryResult, error) {
	if err := fact.Validate(); err != nil {
		return AcornFoxQueuedTask{}, AcornFoxDeliveryResult{}, err
	}
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	if err != nil {
		return AcornFoxQueuedTask{}, AcornFoxDeliveryResult{}, err
	}
	operationID, err := contracts.AcornFoxRuntimeOperationID(fact, action, idempotencyKey)
	if err != nil {
		return AcornFoxQueuedTask{}, AcornFoxDeliveryResult{}, err
	}
	operation := domain.Operation{ID: domain.ID(operationID), ApplicationID: fact.ApplicationID, EnvironmentID: fact.EnvironmentID, TargetRef: "deployment/" + deploymentID.String() + "/" + fact.ServiceName, Type: operationType, IdempotencyKey: idempotencyKey, Status: domain.OperationPending, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	if err := operation.Validate(); err != nil {
		return AcornFoxQueuedTask{}, AcornFoxDeliveryResult{}, err
	}
	payload, taskKind, err := acornFoxRuntimeTaskPayload(fact, idempotencyKey, action, recreate)
	if err != nil {
		return AcornFoxQueuedTask{}, AcornFoxDeliveryResult{}, err
	}
	taskID := domain.ID("task_" + acornFoxDeliveryDigest("task", operationID, string(taskKind))[:32])
	queued := AcornFoxQueuedTask{Operation: operation, TaskID: taskID, Payload: payload, MaxAttempts: acornFoxDeliveryTaskAttempts}
	if existing == nil {
		deployment := domain.Deployment{ID: deploymentID, ApplicationID: fact.ApplicationID, EnvironmentID: fact.EnvironmentID, ReleaseID: fact.ReleaseID, Status: domain.DeploymentPending, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
		queued.Deployment = &deployment
	} else {
		queued.ExistingDeploymentID = *existing
		if deploymentID != *existing {
			return AcornFoxQueuedTask{}, AcornFoxDeliveryResult{}, errors.New("trusted AcornFox runtime deployment identity does not match requested deployment")
		}
	}
	return queued, AcornFoxDeliveryResult{DeploymentID: deploymentID, OperationID: operation.ID, TaskID: taskID, Status: "accepted"}, nil
}

func acornFoxRuntimeTaskPayload(fact contracts.AcornFoxRuntimeReleaseFact, idempotencyKey, action string, recreate bool) (json.RawMessage, v1.TaskKind, error) {
	switch action {
	case "deploy", "redeploy":
		request := contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: idempotencyKey, Recreate: recreate}
		if err := request.Validate(); err != nil {
			return nil, "", err
		}
		parameters, err := json.Marshal(struct {
			PayloadType string                                 `json:"acornfox_payload_type"`
			Request     contracts.AcornFoxRuntimeDeployRequest `json:"request"`
		}{PayloadType: action, Request: request})
		if err != nil {
			return nil, "", err
		}
		payload, err := json.Marshal(struct {
			Kind       v1.TaskKind     `json:"kind"`
			Parameters json.RawMessage `json:"parameters"`
		}{Kind: v1.TaskDeploy, Parameters: parameters})
		return payload, v1.TaskDeploy, err
	case "restart":
		request := contracts.AcornFoxRuntimeActionRequest{Fact: fact, IdempotencyKey: idempotencyKey}
		if err := request.Validate(); err != nil {
			return nil, "", err
		}
		parameters, err := json.Marshal(struct {
			PayloadType string                                 `json:"acornfox_payload_type"`
			Request     contracts.AcornFoxRuntimeActionRequest `json:"request"`
		}{PayloadType: "restart", Request: request})
		if err != nil {
			return nil, "", err
		}
		payload, err := json.Marshal(struct {
			Kind       v1.TaskKind     `json:"kind"`
			Parameters json.RawMessage `json:"parameters"`
		}{Kind: v1.TaskRestart, Parameters: parameters})
		return payload, v1.TaskRestart, err
	default:
		return nil, "", errors.New("AcornFox runtime action is unsupported")
	}
}

func (service *AcornFoxDeliveryService) trustedRuntimeRequest(ctx context.Context, applicationID, deploymentID domain.ID) (contracts.AcornFoxRuntimeDeployRequest, error) {
	request, err := service.Runtime.GetAcornFoxRuntimeRequest(ctx, applicationID, deploymentID)
	if err != nil {
		return contracts.AcornFoxRuntimeDeployRequest{}, err
	}
	if err := request.Validate(); err != nil {
		return contracts.AcornFoxRuntimeDeployRequest{}, errors.New("trusted AcornFox runtime request is invalid")
	}
	expected, err := contracts.AcornFoxRuntimeDeploymentID(request.Fact)
	if err != nil || expected != deploymentID || request.Fact.ApplicationID != applicationID {
		return contracts.AcornFoxRuntimeDeployRequest{}, errors.New("trusted AcornFox runtime request does not own deployment")
	}
	return request, nil
}

func (service *AcornFoxDeliveryService) failBuild(ctx context.Context, buildID domain.ID, cause error) error {
	if cause == nil {
		return nil
	}
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), acornFoxDeliveryFailureTimeout)
	defer cancel()
	if _, err := service.Builds.FailBuild(persistCtx, buildID, acornFoxDeliveryFailureReason(cause), service.now()); err != nil {
		return domain.WrapError(domain.ErrUnknownState, "AcornFox build outcome could not be recorded", err)
	}
	return cause
}

// failDelivery closes a reserved command before returning its cause. If the
// durable failure cannot be recorded, callers receive a stable unknown-state
// error instead of pretending that retrying the same key is safe.
func (service *AcornFoxDeliveryService) failDelivery(ctx context.Context, key, digest string, cause error) error {
	if cause == nil {
		return nil
	}
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), acornFoxDeliveryFailureTimeout)
	defer cancel()
	if err := service.Idempotency.FailAcornFoxDelivery(persistCtx, key, digest, acornFoxDeliveryFailureReason(cause), service.now()); err != nil {
		return domain.WrapError(domain.ErrUnknownState, "AcornFox delivery outcome could not be recorded", err)
	}
	return cause
}

// Persist stable facts, never a provider log, raw URL, or database error.
func acornFoxDeliveryFailureReason(cause error) string {
	if contracts.IsProviderOutcomeUnknown(cause) || domain.IsCode(cause, domain.ErrUnknownState) {
		return "AcornFox operation outcome is unknown"
	}
	var provider *contracts.ProviderError
	_ = errors.As(cause, &provider)
	if errors.Is(cause, context.DeadlineExceeded) || domain.IsCode(cause, domain.ErrTimeout) || provider != nil && provider.Code == contracts.ErrTimeout {
		return "AcornFox operation timed out"
	}
	if errors.Is(cause, context.Canceled) || domain.IsCode(cause, domain.ErrCancelled) || provider != nil && provider.Code == contracts.ErrCancelled {
		return "AcornFox operation was cancelled"
	}
	if provider != nil {
		switch provider.Code {
		case contracts.ErrCapacity:
			return "AcornFox capacity limit was exceeded (capacity_exceeded)"
		case contracts.ErrForbidden:
			return "AcornFox operation was forbidden (forbidden)"
		case contracts.ErrValidation:
			return "AcornFox operation failed validation (validation_failed)"
		case contracts.ErrUnsupportedCapability:
			return "AcornFox requested capability is unsupported (unsupported_capability)"
		}
	}
	return "AcornFox operation failed"
}

func (service *AcornFoxDeliveryService) readyForCreate() error {
	if service == nil || service.Idempotency == nil || service.Sources == nil || service.Importer == nil || service.Builds == nil || service.Tasks == nil || service.Builder == nil || service.Capacity == nil {
		return errors.New("AcornFox delivery service is unavailable")
	}
	return service.Config.validate()
}

func (service *AcornFoxDeliveryService) readyForAction(probe bool) error {
	if service == nil || service.Idempotency == nil || service.Tasks == nil || service.Runtime == nil {
		return errors.New("AcornFox delivery service is unavailable")
	}
	if probe && service.Observer == nil {
		return errors.New("AcornFox runtime observation is unavailable")
	}
	return nil
}

func (service *AcornFoxDeliveryService) now() time.Time {
	if service != nil && service.Clock != nil {
		return service.Clock().UTC()
	}
	return time.Now().UTC()
}

func validateAcornFoxDeliveryCreate(request AcornFoxDeliveryCreateRequest) error {
	if _, _, _, err := resolveAcornFoxRuntimeInput(request.Runtime, request.ContainerPort); err != nil {
		return err
	}
	if request.ApplicationID.Empty() || request.SourceRevisionID.Empty() || strings.TrimSpace(request.IdempotencyKey) == "" || strings.TrimSpace(request.Actor) == "" || request.ContainerPort < 0 || request.ContainerPort > 65535 {
		return domain.ValidationError("AcornFox delivery request is invalid")
	}
	return nil
}

func validateAcornFoxDeliveryAction(request AcornFoxDeliveryActionRequest) error {
	if request.ApplicationID.Empty() || request.DeploymentID.Empty() || strings.TrimSpace(request.IdempotencyKey) == "" || strings.TrimSpace(request.Actor) == "" {
		return domain.ValidationError("AcornFox delivery action is invalid")
	}
	return nil
}

func validateAcornFoxDeliverySource(source domain.SourceRevision, applicationID domain.ID) error {
	if err := source.Validate(); err != nil {
		return errors.New("AcornFox delivery requires an accepted immutable public Git or uploaded source revision")
	}
	if source.ApplicationID != applicationID {
		return domain.NewError(domain.ErrNotFound, "AcornFox source revision does not belong to application")
	}
	if !source.Immutable {
		return errors.New("AcornFox delivery requires an immutable source revision")
	}
	switch source.Kind {
	case domain.SourceGitHTTPS:
		if strings.TrimSpace(source.Commit) == "" {
			return errors.New("AcornFox Git delivery requires an accepted commit")
		}
	case domain.SourceUpload:
		// The controller owns upload claims and prepares this immutable snapshot.
	default:
		return errors.New("AcornFox delivery source kind is unsupported")
	}
	return nil
}

func acornFoxRuntimeResources() contracts.AcornFoxRuntimeRequestedResources {
	return contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 500, MemoryBytes: 512 << 20, PIDs: 128, DiskReservationBytes: 1 << 30}
}

func acornFoxDeliveryStorageKey(prefix string, applicationID, sourceID domain.ID, idempotencyKey string) string {
	return strings.TrimRight(strings.TrimSpace(prefix), "/") + "/" + applicationID.String() + "/" + sourceID.String() + "/" + acornFoxDeliveryDigest(idempotencyKey)[:24] + "/web"
}

func acornFoxDeliveryDigest(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
