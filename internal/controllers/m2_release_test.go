package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/importers/compose"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

func TestM2PersistImportedGroupUsesDeterministicImmutableIdentity(t *testing.T) {
	store := &m2ControllerStore{}
	c := newM2Controller(store)
	group := m2ControllerGroup()
	result := compose.Result{ServiceGroup: group, Report: compose.Report{Version: "m2", Accepted: true, MappedFields: []string{"services.web"}}, Canonical: []byte(`{"services":{"web":{"image":"example/web:stable"}}}`)}
	request := PersistImportedGroupRequest{Result: result, DefinitionID: "def_m2", Version: 1, IdempotencyKey: "import-m2-1"}
	first, err := c.PersistImportedGroup(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.PersistImportedGroup(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || store.groupCalls != 2 {
		t.Fatalf("group identity was not deterministic: first=%s second=%s calls=%d", first.ID, second.ID, store.groupCalls)
	}
	if first.ID == group.ID {
		t.Fatal("controller persisted importer-generated mutable identity")
	}
}

func TestM2CreateCompleteReleaseMixedSourcesBindsEveryDigest(t *testing.T) {
	store := &m2ControllerStore{}
	registry := &m2RegistryFake{image: mustImage(t, "registry.example/worker", "sha256:"+strings.Repeat("b", 64))}
	c := newM2Controller(store)
	c.Registry = registry
	c.StaticRuntimeDigest = "sha256:" + strings.Repeat("f", 64)
	group := m2ControllerGroup()
	group.Services = append(group.Services, domain.ServiceSpec{Name: "worker", Role: domain.RoleWorker, Required: true, Source: domain.ServiceSource{Kind: domain.ServicePrebuilt, Prebuilt: &domain.PrebuiltSource{Reference: "registry.example/worker:stable"}}})
	request := m2CompleteRequest(group)
	request.BuildServices = map[string]M2BuildService{"web": {Resources: m2BuildResources()}}
	request.Runtime = map[string]contracts.ResourceLimits{"web": m2RuntimeResources(), "worker": m2RuntimeResources()}
	result, err := c.CreateCompleteRelease(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Artifacts) != 1 || len(result.Builds) != 1 || len(result.Bindings) != 2 {
		t.Fatalf("mixed release did not persist complete source provenance: %+v", result)
	}
	digests := result.Release.ServiceDigests()
	if len(digests) != 2 || digests["web"].Digest == "" || digests["worker"] != registry.image {
		t.Fatalf("release digest set is incomplete: %#v", digests)
	}
	if result.CanonicalDigest == "" || len(strings.TrimPrefix(result.CanonicalDigest, "sha256:")) != 64 {
		t.Fatalf("canonical digest is not immutable sha256: %q", result.CanonicalDigest)
	}
	if store.releaseCalls != 1 || registry.calls != 1 {
		t.Fatalf("unexpected provider/repository calls: release=%d registry=%d", store.releaseCalls, registry.calls)
	}
	var seenGroup bool
	for _, binding := range result.Bindings {
		if binding.ServiceName == "web" && binding.Kind == postgres.M2ReleaseBindingArtifact && !binding.ArtifactID.Empty() {
			seenGroup = true
		}
		if binding.ServiceName == "worker" && binding.Kind == postgres.M2ReleaseBindingResolvedImage && binding.Image != registry.image {
			t.Fatalf("prebuilt binding changed digest: %+v", binding)
		}
	}
	if !seenGroup {
		t.Fatal("built service did not retain artifact provenance")
	}
}

func TestM2DockerfileBuildDoesNotCarryStaticRuntimeDigest(t *testing.T) {
	store := &m2ControllerStore{}
	c := newM2Controller(store)
	c.StaticRuntimeDigest = "sha256:" + strings.Repeat("f", 64)
	group := m2ControllerGroup()
	group.Services[0].Source = domain.ServiceSource{Kind: domain.ServiceDockerfile, Dockerfile: &domain.DockerfileSource{Context: ".", Dockerfile: "Dockerfile"}}
	request := m2CompleteRequest(group)
	request.BuildServices = map[string]M2BuildService{"web": {Resources: m2BuildResources()}}
	request.Runtime = map[string]contracts.ResourceLimits{"web": m2RuntimeResources()}
	if _, err := c.CreateCompleteRelease(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if store.lastBuildPlan.Kind != domain.BuildDockerfile || store.lastBuildPlan.StaticRuntimeDigest != "" {
		t.Fatalf("Dockerfile plan inherited platform static runtime: %+v", store.lastBuildPlan)
	}
}

func TestM2CapacityFailureHasZeroBuildRegistryAndReleaseSideEffects(t *testing.T) {
	store := &m2ControllerStore{}
	capacity := &m2CapacityFake{preflightErr: errors.New("capacity exceeded")}
	c := newM2Controller(store)
	c.Capacity = capacity
	c.Registry = &m2RegistryFake{image: mustImage(t, "registry.example/worker", "sha256:"+strings.Repeat("b", 64))}
	c.StaticRuntimeDigest = "sha256:" + strings.Repeat("f", 64)
	group := m2ControllerGroup()
	group.Services = append(group.Services, domain.ServiceSpec{Name: "worker", Role: domain.RoleWorker, Required: true, Source: domain.ServiceSource{Kind: domain.ServicePrebuilt, Prebuilt: &domain.PrebuiltSource{Reference: "registry.example/worker:stable"}}})
	request := m2CompleteRequest(group)
	request.BuildServices = map[string]M2BuildService{"web": {Resources: m2BuildResources()}}
	request.Runtime = map[string]contracts.ResourceLimits{"web": m2RuntimeResources(), "worker": m2RuntimeResources()}
	if _, err := c.CreateCompleteRelease(context.Background(), request); err == nil {
		t.Fatal("capacity failure was accepted")
	}
	if store.releaseCalls != 0 || store.buildPlanCalls != 0 || store.buildCalls != 0 || c.Registry.(*m2RegistryFake).calls != 0 {
		t.Fatalf("capacity failure caused partial side effects: store=%+v registry=%d", store, c.Registry.(*m2RegistryFake).calls)
	}
}

func TestM2EnqueueGroupDeploymentFailsClosedForLegacyAgentAndIsIdempotent(t *testing.T) {
	store := &m2ControllerStore{}
	c := newM2Controller(store)
	release, spec := m2RuntimeReleaseAndSpec(t)
	request := M2GroupDeploymentRequest{ApplicationID: spec.ApplicationID, EnvironmentID: spec.EnvironmentID, Release: release, Spec: spec, IdempotencyKey: "deploy-group-1"}
	if _, err := c.EnqueueGroupDeployment(context.Background(), request); !errors.Is(err, ErrM2AgentCapability) {
		t.Fatalf("legacy agent was not rejected: %v", err)
	}
	request.AgentCapabilities = contracts.NewCapabilitySet(contracts.CapabilityRuntimeDeployGroup)
	first, err := c.EnqueueGroupDeployment(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.EnqueueGroupDeployment(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.TaskID != second.TaskID || store.enqueueCalls != 1 {
		t.Fatalf("aggregate deploy was not idempotent: first=%s second=%s calls=%d", first.TaskID, second.TaskID, store.enqueueCalls)
	}
	var task AgentTaskSpec
	if err := json.Unmarshal(store.lastPayload, &task); err != nil || task.Kind != v1.TaskDeployGroup {
		t.Fatalf("queued task is not deploy_group: kind=%q err=%v", task.Kind, err)
	}
	var deployRequest contracts.DeployGroupRequest
	if err := json.Unmarshal(task.Parameters, &deployRequest); err != nil || deployRequest.Operation.IdempotencyKey != request.IdempotencyKey {
		t.Fatalf("nested deploy operation key drifted: %q err=%v", deployRequest.Operation.IdempotencyKey, err)
	}
}

func TestM2DestroyUsesDestroyOperationAndExactNestedIdempotencyKey(t *testing.T) {
	store := &m2ControllerStore{}
	c := newM2Controller(store)
	request := M2GroupDestroyRequest{ApplicationID: "app_runtime", EnvironmentID: "env_runtime", DeploymentID: "dep_runtime", ReleaseID: "release_runtime", AgentCapabilities: contracts.NewCapabilitySet(contracts.CapabilityRuntimeDestroyGroup), IdempotencyKey: "destroy-group-1"}
	result, err := c.EnqueueGroupDestroy(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Operation.Type != domain.OperationDestroy || store.enqueueCalls != 1 {
		t.Fatalf("destroy operation was not durable aggregate destroy: %+v calls=%d", result.Operation, store.enqueueCalls)
	}
	var task AgentTaskSpec
	if err := json.Unmarshal(store.lastPayload, &task); err != nil || task.Kind != v1.TaskDestroyGroup {
		t.Fatalf("queued task is not destroy_group: kind=%q err=%v", task.Kind, err)
	}
	var destroyRequest contracts.DestroyRequest
	if err := json.Unmarshal(task.Parameters, &destroyRequest); err != nil || destroyRequest.Operation.IdempotencyKey != request.IdempotencyKey {
		t.Fatalf("nested destroy operation key drifted: %q err=%v", destroyRequest.Operation.IdempotencyKey, err)
	}
	replayed, err := c.EnqueueGroupDestroy(context.Background(), request)
	if err != nil || replayed.TaskID != result.TaskID || store.enqueueCalls != 1 {
		t.Fatalf("destroy replay was not idempotent: replay=%+v err=%v calls=%d", replayed, err, store.enqueueCalls)
	}
}

func TestM2RolloutKeepsPreviousDeploymentAndQueuesOneAggregateTask(t *testing.T) {
	store := &m2ControllerStore{}
	c := newM2Controller(store)
	release, target := m2RuntimeReleaseAndSpec(t)
	current := target
	current.ReleaseID = "rel_old"
	current.Services[0].Image = mustImage(t, "example/web", "sha256:"+strings.Repeat("a", 64))
	target.Rollout = contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutRolling, PreviousDeploymentID: "dep_old", PreserveOldUntilHealthy: true}
	request := M2RolloutRequest{Current: &current, Target: target, Release: release, AgentCapabilities: contracts.NewCapabilitySet(contracts.CapabilityRuntimeDeployGroup), IdempotencyKey: "rollout-1"}
	result, err := c.Rollout(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Plan.Mode != contracts.RuntimeRolloutRolling || !result.Plan.PreserveOldUntilHealthy || result.Plan.RollbackWholeRelease != true {
		t.Fatalf("rolling plan did not preserve old release: %+v", result.Plan)
	}
	if result.Deployment.Deployment.ReleaseID != release.ID || store.enqueueCalls != 1 {
		t.Fatalf("rollout did not queue target aggregate: %+v calls=%d", result.Deployment, store.enqueueCalls)
	}
	if c.Capacity.(*m2CapacityFake).lastPreflight.HostPorts != 1 {
		t.Fatalf("rolling candidate reserved an invalid bulk host-port count: %+v", c.Capacity.(*m2CapacityFake).lastPreflight)
	}
}

type m2ControllerStore struct {
	mu             sync.Mutex
	groupCalls     int
	buildPlanCalls int
	buildCalls     int
	releaseCalls   int
	enqueueCalls   int
	lastPayload    []byte
	lastBuildPlan  domain.BuildPlan
}

func (s *m2ControllerStore) CreateSourceRevision(_ context.Context, revision domain.SourceRevision) (domain.SourceRevision, error) {
	return revision, nil
}
func (s *m2ControllerStore) CreateServiceGroupRevision(_ context.Context, request postgres.ServiceGroupCreateRequest) (domain.ServiceGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groupCalls++
	return request.Group, nil
}
func (s *m2ControllerStore) CreateBuildPlan(_ context.Context, plan domain.BuildPlan) (domain.BuildPlan, error) {
	s.mu.Lock()
	s.buildPlanCalls++
	s.lastBuildPlan = plan
	s.mu.Unlock()
	return plan, nil
}
func (s *m2ControllerStore) CreateBuild(_ context.Context, build domain.Build) (domain.Build, error) {
	s.mu.Lock()
	s.buildCalls++
	s.mu.Unlock()
	return build, nil
}
func (s *m2ControllerStore) StartBuild(_ context.Context, id domain.ID, now time.Time) (domain.Build, error) {
	return domain.Build{ID: id, Status: domain.BuildRunning, CreatedAt: now, UpdatedAt: now}, nil
}
func (s *m2ControllerStore) CompleteBuild(_ context.Context, artifact domain.Artifact, _ *postgres.ReleaseCreation, now time.Time) (domain.Build, error) {
	return domain.Build{ID: artifact.BuildID, Status: domain.BuildSucceeded, ArtifactID: artifact.ID, CreatedAt: now, UpdatedAt: now}, nil
}
func (s *m2ControllerStore) FailBuild(_ context.Context, id domain.ID, _ string, now time.Time) (domain.Build, error) {
	return domain.Build{ID: id, Status: domain.BuildFailed, CreatedAt: now, UpdatedAt: now}, nil
}
func (s *m2ControllerStore) CreateM2Release(_ context.Context, creation postgres.M2ReleaseCreation, _ time.Time) (domain.Release, error) {
	s.mu.Lock()
	s.releaseCalls++
	s.mu.Unlock()
	return creation.Release, nil
}
func (s *m2ControllerStore) EnqueueControllerTask(_ context.Context, request postgres.EnqueueControllerTaskRequest) (application.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enqueueCalls++
	s.lastPayload = append([]byte(nil), request.Payload...)
	return application.Event{ID: "event_m2"}, nil
}

type m2CapacityFake struct {
	preflightErr  error
	preflights    int
	lastPreflight contracts.CapacityRequest
}

func (f *m2CapacityFake) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "m2-capacity", Version: "test", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilityCapacityCheck, contracts.CapabilityCapacityReserve)}
}
func (f *m2CapacityFake) Preflight(_ context.Context, request contracts.CapacityRequest) (contracts.CapacitySnapshot, contracts.Evidence, error) {
	f.preflights++
	f.lastPreflight = request
	if f.preflightErr != nil {
		return contracts.CapacitySnapshot{}, contracts.Evidence{}, f.preflightErr
	}
	return contracts.CapacitySnapshot{}, contracts.Evidence{Redacted: true}, nil
}
func (f *m2CapacityFake) Reserve(_ context.Context, request contracts.CapacityRequest) (contracts.CapacityLease, error) {
	return contracts.CapacityLease{ID: "lease_m2", Scope: request.Scope, Resources: request.Resources, ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (f *m2CapacityFake) Activate(context.Context, contracts.CapacityLease, contracts.OperationContext) error {
	return nil
}
func (f *m2CapacityFake) Release(context.Context, contracts.CapacityLease, contracts.OperationContext) error {
	return nil
}

type m2RegistryFake struct {
	image domain.ImageDigest
	calls int
}

func (f *m2RegistryFake) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "m2-registry", Version: "test", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilityImageResolve, contracts.CapabilityImagePull)}
}
func (f *m2RegistryFake) Resolve(context.Context, contracts.ImageResolveRequest) (contracts.ImageResolveResult, error) {
	f.calls++
	return contracts.ImageResolveResult{Image: f.image}, nil
}
func (f *m2RegistryFake) ResolveAndPull(context.Context, contracts.ImageResolveRequest) (contracts.ImageResolveResult, error) {
	f.calls++
	return contracts.ImageResolveResult{Image: f.image}, nil
}

type m2BuildFake struct{}

func (m2BuildFake) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "m2-build", Version: "test", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilityBuild)}
}
func (m2BuildFake) Build(_ context.Context, request contracts.BuildRequest) (contracts.BuildResult, error) {
	image := mustImage(nil, request.Plan.TargetRepository, "sha256:"+strings.Repeat("c", 64))
	artifact := domain.Artifact{ID: "artifact_m2", BuildID: request.BuildID, Image: image, OCIStorageRef: "oci://m2", SizeBytes: 1, CreatedAt: time.Unix(1, 0)}
	return contracts.BuildResult{Build: domain.Build{ID: request.BuildID, PlanID: request.Plan.ID, Status: domain.BuildSucceeded, ArtifactID: artifact.ID}, Artifact: &artifact}, nil
}
func (m2BuildFake) Cancel(context.Context, contracts.OperationContext) error { return nil }

func newM2Controller(store *m2ControllerStore) *M2ReleaseController {
	return &M2ReleaseController{Store: store, Source: contracts.NewFakeSourceProvider(), Build: m2BuildFake{}, Registry: &m2RegistryFake{}, Capacity: &m2CapacityFake{}, Clock: func() time.Time { return time.Unix(1700000000, 0).UTC() }}
}

func m2ControllerGroup() domain.ServiceGroup {
	return domain.ServiceGroup{ID: "group_fixture", ApplicationID: "app_fixture", Name: "fixture", CreatedAt: time.Unix(1700000000, 0).UTC(), Services: []domain.ServiceSpec{{Name: "web", Role: domain.RoleIngress, Required: true, Port: 8080, Source: domain.ServiceSource{Kind: domain.ServiceStatic, Static: &domain.StaticSource{Directory: "."}}}}}
}

func m2CompleteRequest(group domain.ServiceGroup) M2CompleteReleaseRequest {
	return M2CompleteReleaseRequest{Group: group, Identity: postgres.M2ServiceGroupIdentity{DefinitionID: "def_fixture", Version: 1, ConfigDigest: "sha256:" + strings.Repeat("d", 64), CanonicalDigest: "sha256:" + strings.Repeat("e", 64)}, Version: 1, Source: domain.SourceRevision{ID: "src_fixture", ApplicationID: group.ApplicationID, Kind: domain.SourceUpload, Locator: "upload://fixture", ContentDigest: "sha256:" + strings.Repeat("a", 64), WorkspaceRef: "/var/lib/open-card/workspaces/fixture", Immutable: true, CreatedAt: time.Unix(1700000000, 0).UTC()}, IdempotencyKey: "release-m2-1"}
}

func m2BuildResources() contracts.ResourceLimits {
	return contracts.ResourceLimits{CPUMillis: 500, MemoryBytes: 64 << 20, DiskBytes: 1 << 20, TimeoutSeconds: 30, ConcurrencySlot: 1}
}
func m2RuntimeResources() contracts.ResourceLimits {
	return contracts.ResourceLimits{CPUMillis: 100, MemoryBytes: 32 << 20, DiskBytes: 1 << 20, PIDs: 64}
}

func m2RuntimeReleaseAndSpec(t *testing.T) (domain.Release, contracts.ServiceGroupRuntimeSpec) {
	groupID := domain.ID("group_runtime")
	image := mustImage(t, "example/web", "sha256:"+strings.Repeat("a", 64))
	release, err := domain.NewRelease("app_runtime", groupID, 1, "sha256:"+strings.Repeat("d", 64), map[string]domain.ImageDigest{"web": image}, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	release.ID = "release_runtime"
	spec := contracts.ServiceGroupRuntimeSpec{SchemaVersion: contracts.ServiceGroupRuntimeSchema, ApplicationID: release.ApplicationID, EnvironmentID: "env_runtime", ReleaseID: release.ID, ServiceGroupID: groupID, ConfigDigest: release.ConfigDigest, EntryService: "web", Services: []contracts.ServiceRuntimeSpec{{Name: "web", Role: domain.RoleIngress, Required: true, Image: image, Resources: m2RuntimeResources(), ContainerPorts: []int{8080}}}, Rollout: contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial}}
	return *release, spec
}

func mustImage(t *testing.T, repository, digest string) domain.ImageDigest {
	image, err := domain.ParseImageDigest(repository, digest)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	return image
}
