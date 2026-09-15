package application

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func TestAcornFoxDeliveryCreateReplaysAndRejectsConflict(t *testing.T) {
	fixture := newAcornFoxDeliveryFixture(t)
	request := AcornFoxDeliveryCreateRequest{ApplicationID: fixture.source.ApplicationID, SourceRevisionID: fixture.source.ID, ContainerPort: 8080, IdempotencyKey: "delivery-create", Actor: "admin"}
	first, err := fixture.service.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "accepted" || first.DeploymentID.Empty() || len(fixture.tasks) != 1 || fixture.buildProvider.calls != 1 {
		t.Fatalf("unexpected create result=%+v tasks=%d builds=%d", first, len(fixture.tasks), fixture.buildProvider.calls)
	}
	assertAcornFoxDeployTask(t, fixture.tasks[0], "deploy", false, first.DeploymentID)
	replayed, err := fixture.service.Create(context.Background(), request)
	if err != nil || replayed != first || len(fixture.tasks) != 1 || fixture.buildProvider.calls != 1 {
		t.Fatalf("replay result=%+v err=%v tasks=%d builds=%d", replayed, err, len(fixture.tasks), fixture.buildProvider.calls)
	}
	request.ContainerPort = 9090
	if _, err := fixture.service.Create(context.Background(), request); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay error=%v", err)
	}
	if fixture.release.ServiceGroupID != "legacy" || fixture.release.ServiceDigests()["web"].Digest == "" {
		t.Fatalf("unexpected compatibility release=%+v", fixture.release)
	}
}

func TestAcornFoxDeliveryUsesOnlyTrustedCompositionNetworkPolicy(t *testing.T) {
	fixture := newAcornFoxDeliveryFixture(t)
	digest := "sha256:" + strings.Repeat("a", 64)
	fixture.service.Config.BuildNetwork = contracts.NetworkPolicy{Mode: contracts.NetworkModeControlledEgressV1, WorkerPolicyDigest: digest}
	request := AcornFoxDeliveryCreateRequest{ApplicationID: fixture.source.ApplicationID, SourceRevisionID: fixture.source.ID, ContainerPort: 8080, IdempotencyKey: "controlled-delivery", Actor: "admin"}
	if _, err := fixture.service.Create(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if got := fixture.buildProvider.lastRequest.Network; got.EffectiveMode() != contracts.NetworkModeControlledEgressV1 || got.WorkerPolicyDigest != digest {
		t.Fatalf("trusted network policy not bound: %+v", got)
	}
	fixture = newAcornFoxDeliveryFixture(t)
	fixture.service.Config.BuildNetwork = contracts.NetworkPolicy{Mode: contracts.NetworkModeControlledEgressV1, WorkerPolicyDigest: "invalid"}
	if _, err := fixture.service.Create(context.Background(), request); err == nil || fixture.buildProvider.calls != 0 || len(fixture.requests) != 0 {
		t.Fatal("invalid composition policy reached delivery effects")
	}
}

func TestAcornFoxVerifiedCandidateRequiresReleaseTimeImageIdentity(t *testing.T) {
	fixture := newAcornFoxDeliveryFixture(t)
	request := AcornFoxDeliveryCreateRequest{ApplicationID: fixture.source.ApplicationID, SourceRevisionID: fixture.source.ID, ContainerPort: 8080, IdempotencyKey: "candidate-publish", Actor: "admin"}
	actual := domain.ImageDigest{Repository: "registry.example/acornfox/web", Digest: "sha256:" + strings.Repeat("d", 64)}
	result, err := fixture.service.CreateVerifiedCandidate(context.Background(), request, actual)
	if err != nil || result.Status != "accepted" || len(fixture.tasks) != 1 || fixture.completedBuilds != 1 {
		t.Fatalf("matching result=%+v tasks=%d completed=%d err=%v", result, len(fixture.tasks), fixture.completedBuilds, err)
	}
	if replay, found, err := fixture.service.ReplayVerifiedCandidate(context.Background(), request, actual); err != nil || !found || replay != result || len(fixture.tasks) != 1 || fixture.buildProvider.calls != 1 {
		t.Fatalf("replay=%+v found=%v tasks=%d builds=%d err=%v", replay, found, len(fixture.tasks), fixture.buildProvider.calls, err)
	}
	missing := request
	missing.IdempotencyKey = "candidate-publish-missing"
	requestsBefore := len(fixture.requests)
	if replay, found, err := fixture.service.ReplayVerifiedCandidate(context.Background(), missing, actual); err != nil || found || replay != (AcornFoxDeliveryResult{}) || len(fixture.requests) != requestsBefore {
		t.Fatalf("missing replay=%+v found=%v requests=%d err=%v", replay, found, len(fixture.requests), err)
	}

	fixture = newAcornFoxDeliveryFixture(t)
	mismatch := domain.ImageDigest{Repository: actual.Repository, Digest: "sha256:" + strings.Repeat("e", 64)}
	if _, err := fixture.service.CreateVerifiedCandidate(context.Background(), request, mismatch); err == nil || len(fixture.tasks) != 0 || fixture.completedBuilds != 0 || fixture.failedBuilds != 1 {
		t.Fatalf("mismatch tasks=%d completed=%d failed=%d err=%v", len(fixture.tasks), fixture.completedBuilds, fixture.failedBuilds, err)
	}
}

func TestAcornFoxDeliveryProviderFailureDoesNotQueueRuntimeTask(t *testing.T) {
	fixture := newAcornFoxDeliveryFixture(t)
	fixture.buildProvider.err = errors.New("build failed")
	_, err := fixture.service.Create(context.Background(), AcornFoxDeliveryCreateRequest{ApplicationID: fixture.source.ApplicationID, SourceRevisionID: fixture.source.ID, ContainerPort: 8080, IdempotencyKey: "delivery-failure", Actor: "admin"})
	if err == nil || len(fixture.tasks) != 0 || fixture.completedBuilds != 0 || fixture.failedBuilds != 1 {
		t.Fatalf("err=%v tasks=%d completed=%d failed=%d", err, len(fixture.tasks), fixture.completedBuilds, fixture.failedBuilds)
	}
}

func TestAcornFoxDeliveryCreateHidesSourceOwnedByAnotherApplication(t *testing.T) {
	fixture := newAcornFoxDeliveryFixture(t)
	fixture.source.ApplicationID = "app_other"
	request := AcornFoxDeliveryCreateRequest{ApplicationID: "app_delivery", SourceRevisionID: fixture.source.ID, ContainerPort: 8080, IdempotencyKey: "delivery-wrong-source-owner", Actor: "admin"}

	if _, err := fixture.service.Create(context.Background(), request); !domain.IsCode(err, domain.ErrNotFound) {
		t.Fatalf("error=%v", err)
	}
	if fixture.buildProvider.calls != 0 || len(fixture.tasks) != 0 || fixture.completedBuilds != 0 || fixture.failedBuilds != 0 {
		t.Fatalf("builds=%d tasks=%d completed=%d failed=%d", fixture.buildProvider.calls, len(fixture.tasks), fixture.completedBuilds, fixture.failedBuilds)
	}
}

func TestAcornFoxDeliveryCommitFailureSettlesWithoutVisibleTask(t *testing.T) {
	fixture := newAcornFoxDeliveryFixture(t)
	fixture.commitErr = errors.New("injected durable commit failure")
	request := AcornFoxDeliveryCreateRequest{ApplicationID: fixture.source.ApplicationID, SourceRevisionID: fixture.source.ID, ContainerPort: 8080, IdempotencyKey: "delivery-commit-failure", Actor: "admin"}
	if _, err := fixture.service.Create(context.Background(), request); err == nil {
		t.Fatal("expected durable commit failure")
	}
	if len(fixture.tasks) != 0 || fixture.buildProvider.calls != 1 || fixture.requests[request.IdempotencyKey].status != "failed" {
		t.Fatalf("tasks=%d builds=%d record=%+v", len(fixture.tasks), fixture.buildProvider.calls, fixture.requests[request.IdempotencyKey])
	}
	if _, err := fixture.service.Create(context.Background(), request); err == nil || len(fixture.tasks) != 0 || fixture.buildProvider.calls != 1 {
		t.Fatalf("replay err=%v tasks=%d builds=%d", err, len(fixture.tasks), fixture.buildProvider.calls)
	}
}

func TestAcornFoxDeliveryActionsReuseTrustedDeploymentIdentity(t *testing.T) {
	fixture := newAcornFoxDeliveryFixture(t)
	fact := fixture.runtimeFact(8080)
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	if err != nil {
		t.Fatal(err)
	}
	fixture.runtimeRequest = contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "original"}
	restart, err := fixture.service.Restart(context.Background(), AcornFoxDeliveryActionRequest{ApplicationID: fixture.source.ApplicationID, DeploymentID: deploymentID, IdempotencyKey: "restart", Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	assertAcornFoxRestartTask(t, fixture.tasks[0], restart.DeploymentID)
	redeploy, err := fixture.service.Redeploy(context.Background(), AcornFoxDeliveryActionRequest{ApplicationID: fixture.source.ApplicationID, DeploymentID: deploymentID, IdempotencyKey: "redeploy", Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	assertAcornFoxDeployTask(t, fixture.tasks[1], "redeploy", true, redeploy.DeploymentID)
	if restart.DeploymentID != deploymentID || redeploy.DeploymentID != deploymentID {
		t.Fatalf("restart=%s redeploy=%s expected=%s", restart.DeploymentID, redeploy.DeploymentID, deploymentID)
	}
	fixture.runtimeRequest.Fact.ApplicationID = "other-app"
	if _, err := fixture.service.Restart(context.Background(), AcornFoxDeliveryActionRequest{ApplicationID: fixture.source.ApplicationID, DeploymentID: deploymentID, IdempotencyKey: "wrong-owner", Actor: "admin"}); err == nil || len(fixture.tasks) != 2 {
		t.Fatalf("wrong owner error=%v tasks=%d", err, len(fixture.tasks))
	}
}

func TestAcornFoxDeliveryProbeUsesCurrentTrustedRuntimeObservation(t *testing.T) {
	fixture := newAcornFoxDeliveryFixture(t)
	fact := fixture.runtimeFact(8080)
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	if err != nil {
		t.Fatal(err)
	}
	fixture.runtimeRequest = contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "original"}
	fixture.observer.observation = contracts.AcornFoxRuntimeObservation{DeploymentID: deploymentID, ServiceName: fact.ServiceName, InternalAddress: "127.0.0.1:39001", ObservedAt: fixture.now}
	result, err := fixture.service.Probe(context.Background(), AcornFoxDeliveryProbeRequest{AcornFoxDeliveryActionRequest: AcornFoxDeliveryActionRequest{ApplicationID: fixture.source.ApplicationID, DeploymentID: deploymentID, IdempotencyKey: "probe", Actor: "admin"}, Protocol: contracts.AcornFoxProbeProtocolHTTP, HTTPPath: "/health"})
	if err != nil {
		t.Fatal(err)
	}
	if result.DeploymentID != deploymentID || len(fixture.tasks) != 1 || fixture.observer.calls != 1 {
		t.Fatalf("result=%+v tasks=%d observe=%d", result, len(fixture.tasks), fixture.observer.calls)
	}
	var task struct {
		Kind       v1.TaskKind     `json:"kind"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if err := json.Unmarshal(fixture.tasks[0].Payload, &task); err != nil || task.Kind != v1.TaskObserve || strings.Contains(string(task.Parameters), "39001") {
		t.Fatalf("probe task=%s err=%v", fixture.tasks[0].Payload, err)
	}
}

type acornFoxDeliveryFixture struct {
	sourceProofErr  error
	importCalls     int
	service         *AcornFoxDeliveryService
	source          domain.SourceRevision
	definition      contracts.AcornFoxDockerfileDefinition
	now             time.Time
	buildProvider   *acornFoxBuildProvider
	observer        *acornFoxObserver
	requests        map[string]acornFoxDeliveryCommandRecord
	tasks           []AcornFoxQueuedTask
	runtimeRequest  contracts.AcornFoxRuntimeDeployRequest
	release         domain.Release
	completedBuilds int
	failedBuilds    int
	commitErr       error
}

type acornFoxDeliveryCommandRecord struct {
	digest string
	result AcornFoxDeliveryResult
	status string
}

func newAcornFoxDeliveryFixture(t *testing.T) *acornFoxDeliveryFixture {
	t.Helper()
	now := time.Unix(1_700_000_000, 0).UTC()
	source := domain.SourceRevision{ID: "src_delivery", ApplicationID: "app_delivery", Kind: domain.SourceGitHTTPS, Locator: "https://github.com/open-card/example.git", Ref: "main", Commit: strings.Repeat("a", 40), ContentDigest: "sha256:" + strings.Repeat("b", 64), WorkspaceRef: "/immutable/source", CreatedAt: now, Immutable: true}
	definition, err := contracts.FinalizeAcornFoxDockerfileDefinition(contracts.AcornFoxDockerfileDefinition{Status: contracts.AcornFoxDockerfileReady, SourceRevisionID: source.ID, SourceContentDigest: source.ContentDigest, DockerfileDigest: "sha256:" + strings.Repeat("c", 64), StageCount: 1, FinalStage: &contracts.AcornFoxDockerfileStage{Name: "final", Index: 0, From: "scratch"}})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &acornFoxDeliveryFixture{source: source, definition: definition, now: now, requests: make(map[string]acornFoxDeliveryCommandRecord), buildProvider: &acornFoxBuildProvider{}, observer: &acornFoxObserver{}}
	fixture.service = &AcornFoxDeliveryService{Idempotency: fixture, Sources: fixture, Importer: fixture, Builds: fixture, Tasks: fixture, Runtime: fixture, Observer: fixture.observer, Builder: fixture.buildProvider, Capacity: contracts.NewFakeCapacityProvider(true), Config: AcornFoxDeliveryConfig{TargetRepository: "registry.example/acornfox", StorageKeyPrefix: "acornfox-builds"}, Clock: func() time.Time { return fixture.now }}
	return fixture
}

func (f *acornFoxDeliveryFixture) BeginAcornFoxDelivery(_ context.Context, key, digest string, _ time.Time) (AcornFoxDeliveryResult, bool, error) {
	if prior, ok := f.requests[key]; ok {
		if prior.digest != digest {
			return AcornFoxDeliveryResult{}, false, ErrIdempotencyConflict
		}
		if prior.status == "completed" {
			return prior.result, true, nil
		}
		return AcornFoxDeliveryResult{}, false, errors.New("previous command failed")
	}
	f.requests[key] = acornFoxDeliveryCommandRecord{digest: digest, status: "pending"}
	return AcornFoxDeliveryResult{}, false, nil
}

func (f *acornFoxDeliveryFixture) ReplayAcornFoxDelivery(_ context.Context, key, digest string) (AcornFoxDeliveryResult, bool, error) {
	prior, ok := f.requests[key]
	if !ok {
		return AcornFoxDeliveryResult{}, false, nil
	}
	if prior.digest != digest {
		return AcornFoxDeliveryResult{}, false, ErrIdempotencyConflict
	}
	if prior.status != "completed" {
		return AcornFoxDeliveryResult{}, false, errors.New("previous command is not complete")
	}
	return prior.result, true, nil
}

func (f *acornFoxDeliveryFixture) FailAcornFoxDelivery(_ context.Context, key, digest, _ string, _ time.Time) error {
	f.requests[key] = acornFoxDeliveryCommandRecord{digest: digest, status: "failed"}
	return nil
}

func (f *acornFoxDeliveryFixture) GetAcornFoxSourceRevision(_ context.Context, app, id domain.ID) (domain.SourceRevision, error) {
	if f.sourceProofErr != nil {
		return domain.SourceRevision{}, f.sourceProofErr
	}
	// Deliberately permit a wrong-owner fixture result to exercise consumer validation.
	if id != f.source.ID {
		return domain.SourceRevision{}, ErrNotFound
	}
	return f.source, nil
}

func (f *acornFoxDeliveryFixture) GetAcornFoxEnvironment(_ context.Context, applicationID domain.ID) (domain.ID, error) {
	if applicationID != f.source.ApplicationID {
		return "", ErrNotFound
	}
	return "env_delivery", nil
}

func (f *acornFoxDeliveryFixture) NextAcornFoxDefinitionVersion(context.Context, domain.ID) (int, error) {
	return 1, nil
}
func (f *acornFoxDeliveryFixture) NextAcornFoxReleaseVersion(context.Context, domain.ID) (int, error) {
	return 1, nil
}
func (f *acornFoxDeliveryFixture) CreateAcornFoxDefinition(_ context.Context, definition domain.ApplicationDeliveryDefinition) (domain.ApplicationDeliveryDefinition, error) {
	return definition, nil
}
func (f *acornFoxDeliveryFixture) Import(source domain.SourceRevision) (contracts.AcornFoxDockerfileDefinition, error) {
	f.importCalls++
	if source.ID != f.source.ID {
		return contracts.AcornFoxDockerfileDefinition{}, ErrNotFound
	}
	return f.definition, nil
}
func (f *acornFoxDeliveryFixture) CreateBuildPlan(_ context.Context, plan domain.BuildPlan) (domain.BuildPlan, error) {
	return plan, nil
}
func (f *acornFoxDeliveryFixture) CreateBuild(_ context.Context, build domain.Build) (domain.Build, error) {
	return build, nil
}
func (f *acornFoxDeliveryFixture) StartBuild(_ context.Context, _ domain.ID, _ time.Time) (domain.Build, error) {
	return domain.Build{}, nil
}
func (f *acornFoxDeliveryFixture) CompleteAcornFoxBuild(_ context.Context, _ domain.Artifact, release domain.Release, _ domain.ID, _ time.Time) (domain.Build, error) {
	f.release, f.completedBuilds = release, f.completedBuilds+1
	return domain.Build{}, nil
}
func (f *acornFoxDeliveryFixture) FailBuild(_ context.Context, _ domain.ID, _ string, _ time.Time) (domain.Build, error) {
	f.failedBuilds++
	return domain.Build{}, nil
}
func (f *acornFoxDeliveryFixture) CommitAcornFoxDeliveryTask(_ context.Context, task AcornFoxQueuedTask, key, digest string, result AcornFoxDeliveryResult, _ time.Time) error {
	if f.commitErr != nil {
		return f.commitErr
	}
	f.tasks = append(f.tasks, task)
	f.requests[key] = acornFoxDeliveryCommandRecord{digest: digest, result: result, status: "completed"}
	return nil
}
func (f *acornFoxDeliveryFixture) GetAcornFoxRuntimeRequest(_ context.Context, _, _ domain.ID) (contracts.AcornFoxRuntimeDeployRequest, error) {
	return f.runtimeRequest, nil
}

type acornFoxBuildProvider struct {
	calls       int
	err         error
	lastRequest contracts.BuildRequest
}

func (p *acornFoxBuildProvider) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "test-build", Version: "1", ContractVersion: contracts.ContractAPIVersion}
}
func (p *acornFoxBuildProvider) Cancel(context.Context, contracts.OperationContext) error { return nil }
func (p *acornFoxBuildProvider) Build(_ context.Context, request contracts.BuildRequest) (contracts.BuildResult, error) {
	p.calls++
	p.lastRequest = request
	if p.err != nil {
		return contracts.BuildResult{}, p.err
	}
	artifact := domain.Artifact{ID: "art_delivery", BuildID: request.BuildID, Image: domain.ImageDigest{Repository: "registry.example/acornfox/web", Digest: "sha256:" + strings.Repeat("d", 64)}, OCIStorageRef: "oci://acornfox/web", SizeBytes: 1, CreatedAt: time.Unix(1_700_000_000, 0).UTC()}
	return contracts.BuildResult{Build: domain.Build{ID: request.BuildID, PlanID: request.Plan.ID, Status: domain.BuildSucceeded}, Artifact: &artifact}, nil
}

type acornFoxObserver struct {
	observation contracts.AcornFoxRuntimeObservation
	calls       int
}

func (o *acornFoxObserver) Deploy(context.Context, contracts.AcornFoxRuntimeDeployRequest) (contracts.AcornFoxRuntimeDeployment, error) {
	return contracts.AcornFoxRuntimeDeployment{}, errors.New("unexpected deploy")
}
func (o *acornFoxObserver) Observe(_ context.Context, _ contracts.AcornFoxRuntimeReference) (contracts.AcornFoxRuntimeObservation, error) {
	o.calls++
	return o.observation, nil
}
func (o *acornFoxObserver) GetAcornFoxRuntimeObservation(_ context.Context, _, _ domain.ID) (contracts.AcornFoxRuntimeObservation, error) {
	o.calls++
	return o.observation, nil
}
func (o *acornFoxObserver) Restart(context.Context, contracts.AcornFoxRuntimeActionRequest) error {
	return errors.New("unexpected restart")
}
func (o *acornFoxObserver) Destroy(context.Context, contracts.AcornFoxRuntimeActionRequest) error {
	return errors.New("unexpected destroy")
}

func (f *acornFoxDeliveryFixture) runtimeFact(port int) contracts.AcornFoxRuntimeReleaseFact {
	return contracts.AcornFoxRuntimeReleaseFact{ApplicationID: f.source.ApplicationID, EnvironmentID: "env_delivery", ReleaseID: "rel_delivery", ServiceName: "web", Image: domain.ImageDigest{Repository: "registry.example/acornfox/web", Digest: "sha256:" + strings.Repeat("d", 64)}, Resources: acornFoxRuntimeResources(), ContainerPort: port, AcceptedAt: f.now, Immutable: true}
}

func assertAcornFoxDeployTask(t *testing.T, task AcornFoxQueuedTask, expectedMarker string, recreate bool, deploymentID domain.ID) {
	t.Helper()
	if task.MaxAttempts != 3 || task.ExistingDeploymentID != "" && task.ExistingDeploymentID != deploymentID {
		t.Fatalf("task=%+v", task)
	}
	var envelope struct {
		Kind       v1.TaskKind     `json:"kind"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if err := json.Unmarshal(task.Payload, &envelope); err != nil || envelope.Kind != v1.TaskDeploy {
		t.Fatalf("payload=%s err=%v", task.Payload, err)
	}
	var parameters struct {
		PayloadType string                                 `json:"acornfox_payload_type"`
		Request     contracts.AcornFoxRuntimeDeployRequest `json:"request"`
	}
	if err := json.Unmarshal(envelope.Parameters, &parameters); err != nil || parameters.PayloadType != expectedMarker || parameters.Request.Recreate != recreate {
		t.Fatalf("parameters=%s decoded=%+v err=%v", envelope.Parameters, parameters, err)
	}
	actual, err := contracts.AcornFoxRuntimeDeploymentID(parameters.Request.Fact)
	if err != nil || actual != deploymentID {
		t.Fatalf("deployment=%s expected=%s err=%v", actual, deploymentID, err)
	}
}

func assertAcornFoxRestartTask(t *testing.T, task AcornFoxQueuedTask, deploymentID domain.ID) {
	t.Helper()
	var envelope struct {
		Kind       v1.TaskKind     `json:"kind"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if err := json.Unmarshal(task.Payload, &envelope); err != nil || envelope.Kind != v1.TaskRestart {
		t.Fatalf("payload=%s err=%v", task.Payload, err)
	}
	var parameters struct {
		PayloadType string                                 `json:"acornfox_payload_type"`
		Request     contracts.AcornFoxRuntimeActionRequest `json:"request"`
	}
	if err := json.Unmarshal(envelope.Parameters, &parameters); err != nil || parameters.PayloadType != "restart" {
		t.Fatalf("parameters=%s decoded=%+v err=%v", envelope.Parameters, parameters, err)
	}
	actual, err := contracts.AcornFoxRuntimeDeploymentID(parameters.Request.Fact)
	if err != nil || actual != deploymentID {
		t.Fatalf("deployment=%s expected=%s err=%v", actual, deploymentID, err)
	}
}

type acornFoxSourceProofCapacitySpy struct {
	contracts.CapacityProvider
	calls int
}

func (s *acornFoxSourceProofCapacitySpy) Reserve(ctx context.Context, request contracts.CapacityRequest) (contracts.CapacityLease, error) {
	s.calls++
	return s.CapacityProvider.Reserve(ctx, request)
}
func TestAcornFoxDeliveryRequiresSourceProofBeforeAnyBuild(t *testing.T) {
	for _, candidate := range []bool{false, true} {
		name := "normal"
		if candidate {
			name = "verified-candidate"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newAcornFoxDeliveryFixture(t)
			fixture.sourceProofErr = ErrNotFound
			capacity := &acornFoxSourceProofCapacitySpy{CapacityProvider: contracts.NewFakeCapacityProvider(true)}
			fixture.service.Capacity = capacity
			request := AcornFoxDeliveryCreateRequest{ApplicationID: fixture.source.ApplicationID, SourceRevisionID: fixture.source.ID, ContainerPort: 8080, IdempotencyKey: "proof-required", Actor: "admin"}
			var err error
			if candidate {
				_, err = fixture.service.CreateVerifiedCandidate(context.Background(), request, domain.ImageDigest{Repository: "registry.example/acornfox/web", Digest: "sha256:" + strings.Repeat("d", 64)})
			} else {
				_, err = fixture.service.Create(context.Background(), request)
			}
			if !errors.Is(err, ErrNotFound) || fixture.importCalls != 0 || fixture.buildProvider.calls != 0 || capacity.calls != 0 || len(fixture.tasks) != 0 {
				t.Fatalf("unproven source: err=%v imports=%d builds=%d capacity=%d tasks=%d", err, fixture.importCalls, fixture.buildProvider.calls, capacity.calls, len(fixture.tasks))
			}
		})
	}
}
