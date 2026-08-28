package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// M1DeliveryStore is the transactional persistence boundary used by the
// no-AI release controller. Provider calls happen outside SQL transactions;
// every accepted fact and every state transition is committed with its audit
// and outbox record by the store method that owns it.
type M1DeliveryStore interface {
	CreateSourceRevision(context.Context, domain.SourceRevision) (domain.SourceRevision, error)
	TransitionSourceWorkspace(context.Context, domain.ID, postgres.WorkspaceLifecycle, time.Time) (postgres.WorkspaceLifecycleEvent, error)
	CreateDeliveryDefinition(context.Context, domain.ApplicationDeliveryDefinition) (domain.ApplicationDeliveryDefinition, error)
	CreateBuildPlan(context.Context, domain.BuildPlan) (domain.BuildPlan, error)
	CreateBuild(context.Context, domain.Build) (domain.Build, error)
	StartBuild(context.Context, domain.ID, time.Time) (domain.Build, error)
	CompleteBuild(context.Context, domain.Artifact, *postgres.ReleaseCreation, time.Time) (domain.Build, error)
	FailBuild(context.Context, domain.ID, string, time.Time) (domain.Build, error)
	EnqueueControllerTask(context.Context, postgres.EnqueueControllerTaskRequest) (application.Event, error)
	AppendPublishEvent(context.Context, domain.ID, domain.ID, domain.PublishStatus, string, string, []string, time.Time) (application.Event, error)
	ReservePublish(context.Context, string, string, time.Time) (json.RawMessage, bool, error)
	CompletePublish(context.Context, string, string, json.RawMessage, time.Time) error
	FailPublish(context.Context, string, string, string, time.Time) error
	ReplayPublish(context.Context, string, string) (json.RawMessage, bool, error)
}

type PublishRequest struct {
	ApplicationID    domain.ID                      `json:"application_id"`
	EnvironmentID    domain.ID                      `json:"environment_id"`
	ServiceGroupID   domain.ID                      `json:"service_group_id"`
	ServiceName      string                         `json:"service_name"`
	Source           contracts.PrepareSourceRequest `json:"source"`
	BuildKind        domain.BuildKind               `json:"build_kind"`
	ContextPath      string                         `json:"context_path"`
	DockerfilePath   string                         `json:"dockerfile_path,omitempty"`
	TargetRepository string                         `json:"target_repository"`
	OutputStorageKey string                         `json:"output_storage_key"`
	BuildSecrets     []domain.SecretReference       `json:"build_secret_refs,omitempty"`
	BuildResources   contracts.ResourceLimits       `json:"build_resources"`
	BuildNetwork     contracts.NetworkPolicy        `json:"build_network"`
	RuntimeResources contracts.ResourceLimits       `json:"runtime_resources"`
	ContainerPort    int                            `json:"container_port"`
	Version          int                            `json:"version"`
	IdempotencyKey   string                         `json:"idempotency_key"`
	Deadline         time.Time                      `json:"deadline,omitempty"`
	Actor            string                         `json:"actor,omitempty"`
}

type PublishResult struct {
	SourceRevision domain.SourceRevision                `json:"source_revision"`
	Definition     domain.ApplicationDeliveryDefinition `json:"definition"`
	BuildPlan      domain.BuildPlan                     `json:"build_plan"`
	Build          domain.Build                         `json:"build"`
	Artifact       domain.Artifact                      `json:"artifact"`
	Release        domain.Release                       `json:"release"`
	Deployment     domain.Deployment                    `json:"deployment"`
	Operation      domain.Operation                     `json:"operation"`
	TaskID         domain.ID                            `json:"task_id"`
}

type ReleaseController struct {
	Store               M1DeliveryStore
	Source              contracts.SourceProvider
	Build               contracts.BuildProvider
	Capacity            contracts.CapacityProvider
	StaticRuntimeDigest string
	Clock               func() time.Time

	mu      sync.Mutex
	running map[string]*publishRun
}

type publishRun struct {
	fingerprint string
	done        chan struct{}
	result      PublishResult
	err         error
}

func (c *ReleaseController) Publish(ctx context.Context, request PublishRequest) (PublishResult, error) {
	if c.Store == nil || c.Source == nil || c.Build == nil || c.Capacity == nil {
		return PublishResult{}, errors.New("release controller requires store, source, build and capacity providers")
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	if err := validatePublishRequest(request); err != nil {
		return PublishResult{}, err
	}
	fingerprint, err := jsonDigest(request)
	if err != nil {
		return PublishResult{}, err
	}
	if stored, replayed, replayErr := c.Store.ReplayPublish(ctx, request.IdempotencyKey, fingerprint); replayErr != nil {
		return PublishResult{}, replayErr
	} else if replayed {
		var result PublishResult
		if err := json.Unmarshal(stored, &result); err != nil {
			return PublishResult{}, err
		}
		return result, nil
	}
	if _, _, err := c.Capacity.Preflight(ctx, contracts.CapacityRequest{Scope: contracts.CapacityBuild, Resources: request.BuildResources, Operation: contracts.OperationContext{IdempotencyKey: request.IdempotencyKey + ":capacity-build", Deadline: request.Deadline, Actor: request.Actor}}); err != nil {
		return PublishResult{}, err
	}
	if _, _, err := c.Capacity.Preflight(ctx, contracts.CapacityRequest{Scope: contracts.CapacityRuntime, Resources: request.RuntimeResources, HostPorts: 1, Operation: contracts.OperationContext{IdempotencyKey: request.IdempotencyKey + ":capacity-runtime", Deadline: request.Deadline, Actor: request.Actor}}); err != nil {
		return PublishResult{}, err
	}
	c.mu.Lock()
	if c.running == nil {
		c.running = make(map[string]*publishRun)
	}
	if prior := c.running[request.IdempotencyKey]; prior != nil {
		if prior.fingerprint != fingerprint {
			c.mu.Unlock()
			return PublishResult{}, postgres.ErrIdempotencyConflict
		}
		c.mu.Unlock()
		select {
		case <-prior.done:
			return prior.result, prior.err
		case <-ctx.Done():
			return PublishResult{}, ctx.Err()
		}
	}
	run := &publishRun{fingerprint: fingerprint, done: make(chan struct{})}
	c.running[request.IdempotencyKey] = run
	c.mu.Unlock()
	stored, replayed, reserveErr := c.Store.ReservePublish(ctx, request.IdempotencyKey, fingerprint, c.Clock().UTC())
	if reserveErr != nil {
		run.err = reserveErr
	} else if replayed {
		run.err = json.Unmarshal(stored, &run.result)
	} else {
		run.result, run.err = c.publish(ctx, request)
		if run.err != nil {
			_ = c.Store.FailPublish(ctx, request.IdempotencyKey, fingerprint, run.err.Error(), c.Clock().UTC())
		} else if encoded, encodeErr := json.Marshal(run.result); encodeErr != nil {
			run.err = encodeErr
		} else {
			run.err = c.Store.CompletePublish(ctx, request.IdempotencyKey, fingerprint, encoded, c.Clock().UTC())
		}
	}
	close(run.done)
	return run.result, run.err
}

func (c *ReleaseController) publish(ctx context.Context, request PublishRequest) (PublishResult, error) {
	now := c.Clock().UTC()
	operationID := deterministicID("op", request.IdempotencyKey)
	_, err := c.Store.AppendPublishEvent(ctx, operationID, request.ApplicationID, domain.PublishPreparing, "publish.preparing", "source preparation started", nil, now)
	if err != nil {
		return PublishResult{}, err
	}
	providerContext := func(suffix string) contracts.OperationContext {
		return contracts.OperationContext{IdempotencyKey: request.IdempotencyKey + ":" + suffix, Deadline: request.Deadline, Actor: request.Actor}
	}
	sourceRequest := request.Source
	sourceRequest.ApplicationID = request.ApplicationID
	sourceRequest.Operation = providerContext("source")
	sourceResult, err := c.Source.Prepare(ctx, sourceRequest)
	if err != nil {
		_, _ = c.Store.AppendPublishEvent(ctx, operationID, request.ApplicationID, domain.PublishFailed, "publish.failed", "source preparation failed", nil, c.Clock().UTC())
		return PublishResult{}, err
	}
	revision, err := c.Store.CreateSourceRevision(ctx, sourceResult.Revision)
	if err != nil {
		return PublishResult{}, err
	}
	failWorkspace := func(cause error, buildID domain.ID) error {
		safe := foundation.RedactText(cause.Error())
		if !buildID.Empty() {
			_, _ = c.Store.FailBuild(ctx, buildID, safe, c.Clock().UTC())
		}
		_ = c.Source.Release(ctx, contracts.ReleaseSourceRequest{Revision: revision, Operation: providerContext("source-failed-release")})
		_, _ = c.Store.TransitionSourceWorkspace(ctx, revision.ID, postgres.WorkspaceFailed, c.Clock().UTC())
		_, _ = c.Store.AppendPublishEvent(ctx, operationID, request.ApplicationID, domain.PublishFailed, "publish.failed", "publish failed", nil, c.Clock().UTC())
		return cause
	}
	_, _ = c.Store.AppendPublishEvent(ctx, operationID, request.ApplicationID, domain.PublishBuilding, "publish.building", "immutable source accepted; build started", evidenceStrings(sourceResult.Evidence), c.Clock().UTC())

	definition := domain.ApplicationDeliveryDefinition{
		ID: deterministicID("def", request.IdempotencyKey, revision.ID.String()), ApplicationID: request.ApplicationID,
		SourceRevisionID: revision.ID, Version: request.Version, CreatedAt: now, Immutable: true,
		Facts: map[string]domain.FieldFact{"service": {Value: map[string]any{"name": request.ServiceName, "build_kind": request.BuildKind, "container_port": request.ContainerPort, "ai": false}, Source: domain.FactSourceRepository, Confidence: 1, Evidence: append([]domain.EvidenceRef(nil), sourceResult.Evidence.Refs...), Status: domain.FactConfirmed}},
	}
	if err := definition.Validate(); err != nil {
		return PublishResult{}, failWorkspace(err, "")
	}
	definition, err = c.Store.CreateDeliveryDefinition(ctx, definition)
	if err != nil {
		return PublishResult{}, failWorkspace(err, "")
	}
	plan := domain.BuildPlan{
		ID: deterministicID("plan", request.IdempotencyKey), SourceRevisionID: revision.ID, SourceDigest: revision.ContentDigest,
		ServiceName: request.ServiceName, Kind: request.BuildKind, ContextPath: request.ContextPath, DockerfilePath: request.DockerfilePath,
		TargetRepository: request.TargetRepository, Output: domain.BuildOutputContract{Format: domain.BuildOutputOCI, Retention: domain.BuildRetentionPersist, StorageKey: request.OutputStorageKey},
		SecretRefs: append([]domain.SecretReference(nil), request.BuildSecrets...), IdempotencyKey: request.IdempotencyKey + ":build-plan", CreatedAt: now,
	}
	if request.BuildKind == domain.BuildStatic {
		if !strings.HasPrefix(c.StaticRuntimeDigest, "sha256:") {
			return PublishResult{}, failWorkspace(errors.New("static build policy runtime is not configured"), "")
		}
		plan.StaticRuntimeDigest = c.StaticRuntimeDigest
	}
	plan, err = c.Store.CreateBuildPlan(ctx, plan)
	if err != nil {
		return PublishResult{}, failWorkspace(err, "")
	}
	buildCapacityOperation := providerContext("capacity-build-reserve")
	buildCapacity, err := c.Capacity.Reserve(ctx, contracts.CapacityRequest{Scope: contracts.CapacityBuild, Resources: request.BuildResources, Operation: buildCapacityOperation})
	if err != nil {
		return PublishResult{}, failWorkspace(err, "")
	}
	defer func() {
		_ = c.Capacity.Release(context.Background(), buildCapacity, contracts.OperationContext{IdempotencyKey: request.IdempotencyKey + ":capacity-build-release", Actor: request.Actor})
	}()
	buildID := deterministicID("build", plan.ID.String())
	build := domain.Build{ID: buildID, PlanID: plan.ID, Status: domain.BuildPending, CreatedAt: now, UpdatedAt: now}
	if _, err := c.Store.CreateBuild(ctx, build); err != nil {
		return PublishResult{}, failWorkspace(err, buildID)
	}
	if _, err := c.Store.StartBuild(ctx, buildID, c.Clock().UTC()); err != nil {
		return PublishResult{}, failWorkspace(err, buildID)
	}
	buildResult, err := c.Build.Build(ctx, contracts.BuildRequest{BuildID: buildID, Plan: plan, Source: revision, Resources: request.BuildResources, Network: request.BuildNetwork, Operation: providerContext("build"), Capacity: &buildCapacity})
	if err != nil {
		return PublishResult{}, failWorkspace(err, buildID)
	}
	if buildResult.Artifact == nil || buildResult.Build.ID != buildID || buildResult.Build.PlanID != plan.ID || buildResult.Build.Status != domain.BuildSucceeded || buildResult.Artifact.BuildID != buildID {
		return PublishResult{}, failWorkspace(errors.New("build provider returned an unbound or unsuccessful result"), buildID)
	}
	release, err := domain.NewRelease(request.ApplicationID, request.ServiceGroupID, request.Version, digestString(plan.ID.String()+":"+buildResult.Artifact.Image.Digest), map[string]domain.ImageDigest{request.ServiceName: buildResult.Artifact.Image}, c.Clock().UTC())
	if err != nil {
		return PublishResult{}, failWorkspace(err, buildID)
	}
	release.ID = deterministicID("rel", plan.ID.String(), buildResult.Artifact.Image.Digest)
	build, err = c.Store.CompleteBuild(ctx, *buildResult.Artifact, &postgres.ReleaseCreation{Release: *release, DefinitionID: definition.ID}, c.Clock().UTC())
	if err != nil {
		return PublishResult{}, failWorkspace(err, buildID)
	}
	if err := c.Source.Release(ctx, contracts.ReleaseSourceRequest{Revision: revision, Operation: providerContext("source-release")}); err != nil {
		return PublishResult{}, err
	}
	if _, err := c.Store.TransitionSourceWorkspace(ctx, revision.ID, postgres.WorkspaceReleased, c.Clock().UTC()); err != nil {
		return PublishResult{}, err
	}
	deployment := domain.Deployment{ID: deterministicID("dep", request.IdempotencyKey), ApplicationID: request.ApplicationID, EnvironmentID: request.EnvironmentID, ReleaseID: release.ID, Status: domain.DeploymentPending, CreatedAt: now, UpdatedAt: now}
	operation, err := domain.NewOperation(request.ApplicationID, request.EnvironmentID, domain.OperationDeploy, "deployment/"+deployment.ID.String(), request.IdempotencyKey+":deploy", now)
	if err != nil {
		return PublishResult{}, err
	}
	operation.ID = operationID
	taskID := deterministicID("task", request.IdempotencyKey)
	deployRequest := contracts.DeployRequest{DeploymentID: deployment.ID, Spec: contracts.RuntimeSpec{ApplicationID: request.ApplicationID, EnvironmentID: request.EnvironmentID, ReleaseID: release.ID, ServiceName: request.ServiceName, Image: buildResult.Artifact.Image, Resources: request.RuntimeResources, Port: request.ContainerPort}, Operation: providerContext("deploy")}
	deployRequest.Operation.IdempotencyKey = operation.IdempotencyKey
	parameters, err := json.Marshal(deployRequest)
	if err != nil {
		return PublishResult{}, err
	}
	payload, err := json.Marshal(AgentTaskSpec{Kind: v1.TaskDeploy, Parameters: parameters})
	if err != nil {
		return PublishResult{}, err
	}
	_, _ = c.Store.AppendPublishEvent(ctx, operationID, request.ApplicationID, domain.PublishDeploying, "publish.deploying", "persistent OCI artifact queued for Agent deployment", evidenceStrings(buildResult.Evidence), c.Clock().UTC())
	if _, err := c.Store.EnqueueControllerTask(ctx, postgres.EnqueueControllerTaskRequest{Operation: operation, Deployment: &deployment, TaskID: taskID, Payload: payload, MaxAttempts: 3, InitialPublishStatus: domain.PublishDeploying}); err != nil {
		return PublishResult{}, err
	}
	return PublishResult{SourceRevision: revision, Definition: definition, BuildPlan: plan, Build: build, Artifact: *buildResult.Artifact, Release: *release, Deployment: deployment, Operation: operation, TaskID: taskID}, nil
}

func evidenceStrings(evidence contracts.Evidence) []string {
	values := make([]string, 0, len(evidence.Refs))
	for _, ref := range evidence.Refs {
		values = append(values, ref.ID.String())
	}
	return values
}

func validatePublishRequest(request PublishRequest) error {
	if request.ApplicationID.Empty() || request.EnvironmentID.Empty() || request.ServiceGroupID.Empty() {
		return domain.ValidationError("publish application, environment and service group are required")
	}
	if strings.TrimSpace(request.ServiceName) == "" || strings.TrimSpace(request.IdempotencyKey) == "" || request.Version < 1 {
		return domain.ValidationError("publish service, version and idempotency key are required")
	}
	if request.ContainerPort < 1 || request.ContainerPort > 65535 {
		return domain.ValidationError("M1 publish requires one container port")
	}
	if request.BuildResources.DiskBytes <= 0 {
		return domain.ValidationError("M1 publish requires build disk capacity")
	}
	if request.RuntimeResources.CPUMillis <= 0 || request.RuntimeResources.MemoryBytes <= 0 || request.RuntimeResources.DiskBytes <= 0 || request.RuntimeResources.PIDs <= 0 {
		return domain.ValidationError("M1 publish requires runtime CPU, memory, disk capacity and PID limits")
	}
	if request.Source.Kind != domain.SourceGitHTTPS && request.Source.Kind != domain.SourceUpload {
		return domain.ValidationError("M1 source kind is unsupported")
	}
	return nil
}

func deterministicID(prefix string, parts ...string) domain.ID {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(part))
	}
	return domain.ID(prefix + "_" + hex.EncodeToString(h.Sum(nil))[:32])
}

func digestString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func jsonDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode publish request: %w", err)
	}
	return digestString(string(encoded)), nil
}
