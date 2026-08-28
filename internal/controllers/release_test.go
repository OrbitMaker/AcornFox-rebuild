package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type releaseTestStore struct {
	mu sync.Mutex

	sources       []domain.SourceRevision
	definitions   []domain.ApplicationDeliveryDefinition
	plans         []domain.BuildPlan
	builds        map[domain.ID]domain.Build
	failedBuilds  []domain.ID
	completed     []postgres.ReleaseCreation
	transitions   []postgres.WorkspaceLifecycle
	enqueuedTasks []postgres.EnqueueControllerTaskRequest
	publishEvents []application.Event
}

func (s *releaseTestStore) AppendPublishEvent(_ context.Context, operationID, applicationID domain.ID, status domain.PublishStatus, kind, message string, evidence []string, now time.Time) (application.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	event := application.Event{ID: kind, OperationID: operationID.String(), ApplicationID: applicationID.String(), Sequence: uint64(len(s.publishEvents) + 1), OccurredAt: now, Kind: kind, Status: string(status), Message: message, EvidenceIDs: append([]string(nil), evidence...)}
	s.publishEvents = append(s.publishEvents, event)
	return event, nil
}

func (s *releaseTestStore) ReservePublish(context.Context, string, string, time.Time) (json.RawMessage, bool, error) {
	return nil, false, nil
}
func (s *releaseTestStore) ReplayPublish(context.Context, string, string) (json.RawMessage, bool, error) {
	return nil, false, nil
}
func (s *releaseTestStore) CompletePublish(context.Context, string, string, json.RawMessage, time.Time) error {
	return nil
}
func (s *releaseTestStore) FailPublish(context.Context, string, string, string, time.Time) error {
	return nil
}

func newReleaseTestStore() *releaseTestStore {
	return &releaseTestStore{builds: make(map[domain.ID]domain.Build)}
}

func (s *releaseTestStore) CreateSourceRevision(_ context.Context, revision domain.SourceRevision) (domain.SourceRevision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources = append(s.sources, revision)
	return revision, nil
}

func (s *releaseTestStore) TransitionSourceWorkspace(_ context.Context, sourceID domain.ID, state postgres.WorkspaceLifecycle, now time.Time) (postgres.WorkspaceLifecycleEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.transitions = append(s.transitions, state)
	return postgres.WorkspaceLifecycleEvent{SourceRevisionID: sourceID, State: state, Sequence: int64(len(s.transitions)), CreatedAt: now.UTC()}, nil
}

func (s *releaseTestStore) CreateDeliveryDefinition(_ context.Context, definition domain.ApplicationDeliveryDefinition) (domain.ApplicationDeliveryDefinition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.definitions = append(s.definitions, definition)
	return definition, nil
}

func (s *releaseTestStore) CreateBuildPlan(_ context.Context, plan domain.BuildPlan) (domain.BuildPlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.plans = append(s.plans, plan)
	return plan, nil
}

func (s *releaseTestStore) CreateBuild(_ context.Context, build domain.Build) (domain.Build, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.builds[build.ID] = build
	return build, nil
}

func (s *releaseTestStore) StartBuild(_ context.Context, buildID domain.ID, now time.Time) (domain.Build, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	build, ok := s.builds[buildID]
	if !ok {
		return domain.Build{}, errors.New("test build not found")
	}
	build.Status = domain.BuildRunning
	build.UpdatedAt = now.UTC()
	s.builds[buildID] = build
	return build, nil
}

func (s *releaseTestStore) CompleteBuild(_ context.Context, artifact domain.Artifact, release *postgres.ReleaseCreation, now time.Time) (domain.Build, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	build, ok := s.builds[artifact.BuildID]
	if !ok {
		return domain.Build{}, errors.New("test build not found")
	}
	if release == nil {
		return domain.Build{}, errors.New("test release is required")
	}
	build.Status = domain.BuildSucceeded
	build.ArtifactID = artifact.ID
	build.UpdatedAt = now.UTC()
	s.builds[build.ID] = build
	s.completed = append(s.completed, *release)
	return build, nil
}

func (s *releaseTestStore) FailBuild(_ context.Context, buildID domain.ID, reason string, now time.Time) (domain.Build, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	build, ok := s.builds[buildID]
	if !ok {
		return domain.Build{}, errors.New("test build not found")
	}
	build.Status = domain.BuildFailed
	build.Failure = reason
	build.UpdatedAt = now.UTC()
	s.builds[buildID] = build
	s.failedBuilds = append(s.failedBuilds, buildID)
	return build, nil
}

func (s *releaseTestStore) EnqueueControllerTask(_ context.Context, request postgres.EnqueueControllerTaskRequest) (application.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enqueuedTasks = append(s.enqueuedTasks, request)
	return application.Event{ID: request.TaskID.String(), OperationID: request.Operation.ID.String(), Kind: "operation.queued", Status: string(request.Operation.Status)}, nil
}

func (s *releaseTestStore) snapshotCounts() (sources, definitions, plans, failed, completed, tasks int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sources), len(s.definitions), len(s.plans), len(s.failedBuilds), len(s.completed), len(s.enqueuedTasks)
}

func (s *releaseTestStore) buildStatus(buildID domain.ID) domain.BuildStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.builds[buildID].Status
}

func (s *releaseTestStore) taskPayload(t *testing.T) (AgentTaskSpec, contracts.DeployRequest) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.enqueuedTasks) != 1 {
		t.Fatalf("enqueued tasks = %d, want 1", len(s.enqueuedTasks))
	}
	var spec AgentTaskSpec
	if err := json.Unmarshal(s.enqueuedTasks[0].Payload, &spec); err != nil {
		t.Fatalf("decode task spec: %v", err)
	}
	var request contracts.DeployRequest
	if err := json.Unmarshal(spec.Parameters, &request); err != nil {
		t.Fatalf("decode deploy request: %v", err)
	}
	return spec, request
}

type countingBuildProvider struct {
	inner *contracts.FakeBuildProvider
	calls atomic.Int32
}

type releaseTestCapacity struct {
	mu        sync.Mutex
	failScope contracts.CapacityScope
	preflight []contracts.CapacityRequest
	reserves  []contracts.CapacityRequest
}

func (p *releaseTestCapacity) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "test-capacity", Version: "1", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilityCapacityCheck, contracts.CapabilityCapacityReserve)}
}
func (p *releaseTestCapacity) Preflight(_ context.Context, request contracts.CapacityRequest) (contracts.CapacitySnapshot, contracts.Evidence, error) {
	p.mu.Lock()
	p.preflight = append(p.preflight, request)
	fail := p.failScope == request.Scope
	p.mu.Unlock()
	if fail {
		return contracts.CapacitySnapshot{}, contracts.Evidence{}, &contracts.ProviderError{Provider: "test-capacity", Code: contracts.ErrCapacity, Message: "capacity unavailable", Retry: contracts.RetryBackoff, Retryable: true}
	}
	return contracts.CapacitySnapshot{Scope: request.Scope, AvailableCPUMillis: 8000, AvailableMemoryBytes: 8 << 30, AvailableDiskBytes: 40 << 30}, contracts.Evidence{Redacted: true}, nil
}
func (p *releaseTestCapacity) Reserve(_ context.Context, request contracts.CapacityRequest) (contracts.CapacityLease, error) {
	p.mu.Lock()
	p.reserves = append(p.reserves, request)
	p.mu.Unlock()
	return contracts.CapacityLease{ID: "capacity-lease", Scope: request.Scope, Resources: request.Resources, HostPort: 39001, ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (*releaseTestCapacity) Activate(context.Context, contracts.CapacityLease, contracts.OperationContext) error {
	return nil
}
func (*releaseTestCapacity) Release(context.Context, contracts.CapacityLease, contracts.OperationContext) error {
	return nil
}

func (p *countingBuildProvider) Metadata(ctx context.Context) contracts.ProviderMetadata {
	return p.inner.Metadata(ctx)
}

func (p *countingBuildProvider) Build(ctx context.Context, request contracts.BuildRequest) (contracts.BuildResult, error) {
	p.calls.Add(1)
	return p.inner.Build(ctx, request)
}

func (p *countingBuildProvider) Cancel(ctx context.Context, operation contracts.OperationContext) error {
	return p.inner.Cancel(ctx, operation)
}

type blockingBuildProvider struct {
	inner   *countingBuildProvider
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *blockingBuildProvider) Metadata(ctx context.Context) contracts.ProviderMetadata {
	return p.inner.Metadata(ctx)
}

func (p *blockingBuildProvider) Build(ctx context.Context, request contracts.BuildRequest) (contracts.BuildResult, error) {
	p.once.Do(func() { close(p.started) })
	select {
	case <-p.release:
	case <-ctx.Done():
		return contracts.BuildResult{}, ctx.Err()
	}
	return p.inner.Build(ctx, request)
}

func (p *blockingBuildProvider) Cancel(ctx context.Context, operation contracts.OperationContext) error {
	return p.inner.Cancel(ctx, operation)
}

func testPublishRequest(key string) PublishRequest {
	return PublishRequest{
		ApplicationID:  domain.ID("app_1"),
		EnvironmentID:  domain.ID("env_1"),
		ServiceGroupID: domain.ID("group_1"),
		ServiceName:    "web",
		Source: contracts.PrepareSourceRequest{
			Kind:          domain.SourceGitHTTPS,
			Locator:       "https://example.com/open-card.git",
			Ref:           "main",
			ContentDigest: digestString("m1-source"),
			WorkspaceRef:  "workspace://m1/app_1/source_1",
		},
		BuildKind:        domain.BuildDockerfile,
		ContextPath:      ".",
		DockerfilePath:   "Dockerfile",
		TargetRepository: "open-card.local/apps/web",
		OutputStorageKey: "app_1/" + key + "/web",
		BuildResources:   contracts.ResourceLimits{CPUMillis: 500, MemoryBytes: 64 << 20, DiskBytes: 256 << 20, TimeoutSeconds: 60},
		BuildNetwork:     contracts.NetworkPolicy{Mode: "none"},
		RuntimeResources: contracts.ResourceLimits{CPUMillis: 250, MemoryBytes: 32 << 20, DiskBytes: 128 << 20, PIDs: 64},
		ContainerPort:    8080,
		Version:          1,
		IdempotencyKey:   key,
		Actor:            "m1-test",
	}
}

func newReleaseControllerForTest(store *releaseTestStore, build contracts.BuildProvider) *ReleaseController {
	return &ReleaseController{
		Store:    store,
		Source:   contracts.NewFakeSourceProvider(),
		Build:    build,
		Capacity: &releaseTestCapacity{},
		Clock:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
}

func TestReleaseControllerCapacityFailureHasZeroDomainOrProviderSideEffects(t *testing.T) {
	store := newReleaseTestStore()
	build := &countingBuildProvider{inner: contracts.NewFakeBuildProvider(true)}
	capacity := &releaseTestCapacity{failScope: contracts.CapacityRuntime}
	controller := newReleaseControllerForTest(store, build)
	controller.Capacity = capacity
	_, err := controller.Publish(context.Background(), testPublishRequest("m1-capacity-reject"))
	if err == nil {
		t.Fatal("capacity rejection was accepted")
	}
	sources, definitions, plans, failed, completed, tasks := store.snapshotCounts()
	if sources+definitions+plans+failed+completed+tasks != 0 || build.calls.Load() != 0 {
		t.Fatalf("capacity rejection left partial effects: %d %d %d %d %d %d builds=%d", sources, definitions, plans, failed, completed, tasks, build.calls.Load())
	}
}

func TestReleaseControllerPublishHappyNoAIChain(t *testing.T) {
	store := newReleaseTestStore()
	build := &countingBuildProvider{inner: contracts.NewFakeBuildProvider(true)}
	controller := newReleaseControllerForTest(store, build)

	result, err := controller.Publish(context.Background(), testPublishRequest("m1-happy"))
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if result.SourceRevision.ID.Empty() || result.BuildPlan.SourceRevisionID != result.SourceRevision.ID {
		t.Fatalf("source binding missing: revision=%s plan=%s", result.SourceRevision.ID, result.BuildPlan.SourceRevisionID)
	}
	if result.Build.Status != domain.BuildSucceeded || result.Artifact.BuildID != result.Build.ID {
		t.Fatalf("build result = %#v artifact build = %s", result.Build, result.Artifact.BuildID)
	}
	if result.Release.Status != domain.ReleaseReady || !result.Release.IsImmutable() {
		t.Fatalf("release = %#v, want immutable ready release", result.Release)
	}
	if result.Deployment.Status != domain.DeploymentPending || result.TaskID.Empty() {
		t.Fatalf("deployment/task = %#v/%s", result.Deployment, result.TaskID)
	}
	if result.BuildPlan.Output.Retention != domain.BuildRetentionPersist || result.Artifact.OCIStorageRef == "" {
		t.Fatalf("persistent output missing: plan=%#v artifact=%#v", result.BuildPlan.Output, result.Artifact)
	}
	if fact, ok := result.Definition.Facts["service"]; !ok || fact.Source != domain.FactSourceRepository || fact.Status != domain.FactConfirmed {
		t.Fatalf("definition fact = %#v, want repository-confirmed fact", result.Definition.Facts["service"])
	}
	if got := build.calls.Load(); got != 1 {
		t.Fatalf("build provider calls = %d, want 1", got)
	}
	sources, definitions, plans, failed, completed, tasks := store.snapshotCounts()
	if sources != 1 || definitions != 1 || plans != 1 || failed != 0 || completed != 1 || tasks != 1 {
		t.Fatalf("store counts = sources:%d definitions:%d plans:%d failed:%d completed:%d tasks:%d", sources, definitions, plans, failed, completed, tasks)
	}
	store.mu.Lock()
	if len(store.transitions) != 1 || store.transitions[0] != postgres.WorkspaceReleased {
		t.Fatalf("workspace transitions = %#v, want [released]", store.transitions)
	}
	store.mu.Unlock()
	spec, deploy := store.taskPayload(t)
	if spec.Kind != v1.TaskDeploy {
		t.Fatalf("task kind = %q, want deploy", spec.Kind)
	}
	if deploy.DeploymentID != result.Deployment.ID || deploy.Spec.ReleaseID != result.Release.ID {
		t.Fatalf("deploy binding = %#v, result deployment/release = %s/%s", deploy, result.Deployment.ID, result.Release.ID)
	}
	if deploy.Spec.Image.Digest == "" || deploy.Spec.Image.ResolvedTag != "" {
		t.Fatalf("deploy image must be digest-only: %#v", deploy.Spec.Image)
	}
}

func TestReleaseControllerBuildFailureCreatesNoReleaseOrDeployTask(t *testing.T) {
	store := newReleaseTestStore()
	build := &countingBuildProvider{inner: contracts.NewFakeBuildProvider(true)}
	build.inner.Behavior = contracts.FakeProviderBehavior{
		FailureCode:      contracts.ErrUnavailable,
		FailureMessage:   "build worker failed",
		FailureRetry:     contracts.RetryNever,
		FailureRetryable: false,
	}
	controller := newReleaseControllerForTest(store, build)

	_, err := controller.Publish(context.Background(), testPublishRequest("m1-build-failure"))
	if err == nil {
		t.Fatal("Publish() error = nil, want build failure")
	}
	sources, definitions, plans, failed, completed, tasks := store.snapshotCounts()
	if sources != 1 || definitions != 1 || plans != 1 || failed != 1 || completed != 0 || tasks != 0 {
		t.Fatalf("store counts after failure = sources:%d definitions:%d plans:%d failed:%d completed:%d tasks:%d", sources, definitions, plans, failed, completed, tasks)
	}
	sourceID := store.sources[0].ID
	buildID := deterministicID("build", store.plans[0].ID.String())
	if got := store.buildStatus(buildID); got != domain.BuildFailed {
		t.Fatalf("build status = %q, want failed", got)
	}
	if len(store.transitions) != 1 || store.transitions[0] != postgres.WorkspaceFailed {
		t.Fatalf("workspace transitions = %#v, want [failed]", store.transitions)
	}
	if sourceID.Empty() || build.calls.Load() != 1 {
		t.Fatalf("source/build facts = %s/%d", sourceID, build.calls.Load())
	}
}

func TestReleaseControllerDuplicateConcurrentPublishIsSingleChain(t *testing.T) {
	store := newReleaseTestStore()
	inner := &countingBuildProvider{inner: contracts.NewFakeBuildProvider(true)}
	build := &blockingBuildProvider{inner: inner, started: make(chan struct{}), release: make(chan struct{})}
	controller := newReleaseControllerForTest(store, build)
	request := testPublishRequest("m1-duplicate")

	type publishResult struct {
		result PublishResult
		err    error
	}
	first := make(chan publishResult, 1)
	go func() {
		result, err := controller.Publish(context.Background(), request)
		first <- publishResult{result: result, err: err}
	}()
	select {
	case <-build.started:
	case <-time.After(time.Second):
		t.Fatal("build provider did not start")
	}
	second := make(chan publishResult, 1)
	go func() {
		result, err := controller.Publish(context.Background(), request)
		second <- publishResult{result: result, err: err}
	}()
	close(build.release)
	firstResult := <-first
	secondResult := <-second
	if firstResult.err != nil || secondResult.err != nil {
		t.Fatalf("duplicate errors = %v/%v", firstResult.err, secondResult.err)
	}
	if firstResult.result.TaskID != secondResult.result.TaskID || firstResult.result.Release.ID != secondResult.result.Release.ID {
		t.Fatalf("duplicate results differ: %s/%s vs %s/%s", firstResult.result.TaskID, firstResult.result.Release.ID, secondResult.result.TaskID, secondResult.result.Release.ID)
	}
	if got := inner.calls.Load(); got != 1 {
		t.Fatalf("build provider calls = %d, want 1", got)
	}
	_, definitions, plans, failed, completed, tasks := store.snapshotCounts()
	if definitions != 1 || plans != 1 || failed != 0 || completed != 1 || tasks != 1 {
		t.Fatalf("duplicate store counts = definitions:%d plans:%d failed:%d completed:%d tasks:%d", definitions, plans, failed, completed, tasks)
	}
}

func TestReleaseControllerChangedInputConflictsAfterIdempotentPublish(t *testing.T) {
	store := newReleaseTestStore()
	build := &countingBuildProvider{inner: contracts.NewFakeBuildProvider(true)}
	controller := newReleaseControllerForTest(store, build)
	request := testPublishRequest("m1-conflict")
	if _, err := controller.Publish(context.Background(), request); err != nil {
		t.Fatalf("initial Publish() error = %v", err)
	}
	changed := request
	changed.ContainerPort = request.ContainerPort + 1
	if _, err := controller.Publish(context.Background(), changed); !errors.Is(err, postgres.ErrIdempotencyConflict) {
		t.Fatalf("changed Publish() error = %v, want idempotency conflict", err)
	}
	if got := build.calls.Load(); got != 1 {
		t.Fatalf("build provider calls after conflict = %d, want 1", got)
	}
	_, _, _, failed, completed, tasks := store.snapshotCounts()
	if failed != 0 || completed != 1 || tasks != 1 {
		t.Fatalf("store counts after conflict = failed:%d completed:%d tasks:%d", failed, completed, tasks)
	}
}
