package application

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const acornFoxRuntimeTestDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const acornFoxRuntimeTestContainer = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"

func TestAcornFoxRuntimeLifecycleIsNarrowDeterministicAndLoopbackOnly(t *testing.T) {
	fact := acornFoxRuntimeFact(t)
	driver := &acornFoxRuntimeStub{}
	service, err := NewAcornFoxRuntimeService(driver)
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Deploy(context.Background(), contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "deploy-1"})
	if err != nil {
		t.Fatal(err)
	}
	driver.mu.Lock()
	projected := driver.states[first.DeploymentID]
	deployKey := driver.lastDeploy.Operation.IdempotencyKey
	driver.mu.Unlock()
	wantDeployKey, err := contracts.AcornFoxRuntimeOperationID(fact, "deploy", "deploy-1")
	if err != nil {
		t.Fatal(err)
	}
	if projected.Resources != (contracts.ResourceLimits{CPUMillis: fact.Resources.CPUMillis, MemoryBytes: fact.Resources.MemoryBytes, DiskBytes: fact.Resources.DiskReservationBytes, PIDs: fact.Resources.PIDs}) || deployKey != wantDeployKey || deployKey == "deploy-1" {
		t.Fatalf("AcornFox resources were not narrowly projected: spec=%#v key=%q", projected, deployKey)
	}
	second, err := service.Deploy(context.Background(), contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "deploy-1"})
	if err != nil || first != second || driver.deployMutations != 1 {
		t.Fatalf("initial deploy was not deterministic: first=%#v second=%#v mutations=%d err=%v", first, second, driver.deployMutations, err)
	}
	if err := service.Restart(context.Background(), contracts.AcornFoxRuntimeActionRequest{Fact: fact, IdempotencyKey: "restart-1"}); err != nil {
		t.Fatal(err)
	}
	if err := service.Restart(context.Background(), contracts.AcornFoxRuntimeActionRequest{Fact: fact, IdempotencyKey: "restart-1"}); err != nil || driver.restartMutations != 1 {
		t.Fatalf("restart was not idempotent: mutations=%d err=%v", driver.restartMutations, err)
	}
	if err := service.Restart(context.Background(), contracts.AcornFoxRuntimeActionRequest{Fact: fact, IdempotencyKey: "restart-2"}); err != nil || driver.restartMutations != 2 {
		t.Fatalf("new restart key did not make a new lifecycle request: mutations=%d err=%v", driver.restartMutations, err)
	}
	observation, err := service.Observe(context.Background(), contracts.AcornFoxRuntimeReference{Fact: fact})
	if err != nil || observation.InternalAddress != "127.0.0.1:39124" || observation.RequestedResources != fact.Resources || observation.AppliedLimits != (contracts.AcornFoxRuntimeAppliedLimits{CPUMillis: fact.Resources.CPUMillis, MemoryBytes: fact.Resources.MemoryBytes, PIDs: fact.Resources.PIDs}) || observation.Disk != (contracts.AcornFoxRuntimeDiskFact{ReservationBytes: fact.Resources.DiskReservationBytes}) {
		t.Fatalf("observation did not report constrained local facts: %#v %v", observation, err)
	}
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"public_address", "healthy", "rollback", "scale", "rolling", "required", "optional", "group", "timeout", "concurrency", "readback_limits"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("narrow runtime observation leaked %q: %s", forbidden, raw)
		}
	}

	recreated, err := service.Deploy(context.Background(), contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "recreate-1", Recreate: true})
	wantRecreateKey, keyErr := contracts.AcornFoxRuntimeOperationID(fact, "redeploy", "recreate-1")
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	if err != nil || recreated.DeploymentID != first.DeploymentID || driver.recreateMutations != 1 || driver.destroyMutations != 0 || driver.deployMutations != 1 || driver.lastRecreate.Operation.IdempotencyKey != wantRecreateKey || driver.lastRecreate.Operation.IdempotencyKey == "recreate-1" {
		t.Fatalf("explicit replacement was not atomically delegated: result=%#v deploy=%d recreate=%d destroy=%d request=%#v err=%v", recreated, driver.deployMutations, driver.recreateMutations, driver.destroyMutations, driver.lastRecreate, err)
	}
	if _, err := service.Deploy(context.Background(), contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "recreate-1", Recreate: true}); err != nil || driver.recreateMutations != 1 || driver.destroyMutations != 0 || driver.deployMutations != 1 {
		t.Fatalf("explicit replacement retry was not provider-idempotent: deploy=%d recreate=%d destroy=%d err=%v", driver.deployMutations, driver.recreateMutations, driver.destroyMutations, err)
	}
	if _, err := service.Deploy(context.Background(), contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "recreate-2", Recreate: true}); err != nil || driver.recreateMutations != 2 || driver.destroyMutations != 0 || driver.deployMutations != 1 {
		t.Fatalf("new replacement key did not reach provider: deploy=%d recreate=%d destroy=%d err=%v", driver.deployMutations, driver.recreateMutations, driver.destroyMutations, err)
	}
	if err := service.Destroy(context.Background(), contracts.AcornFoxRuntimeActionRequest{Fact: fact, IdempotencyKey: "destroy-1"}); err != nil {
		t.Fatal(err)
	}
	if err := service.Destroy(context.Background(), contracts.AcornFoxRuntimeActionRequest{Fact: fact, IdempotencyKey: "destroy-1"}); err == nil || !acornFoxRuntimeErrorCode(err, contracts.ErrNotFound) || driver.destroyMutations != 1 {
		t.Fatalf("destroy masked the typed not-found outcome: mutations=%d err=%v", driver.destroyMutations, err)
	}
}

func TestAcornFoxRuntimeProviderActionKeysAreIsolated(t *testing.T) {
	fact := acornFoxRuntimeFact(t)
	driver := &acornFoxRuntimeStub{}
	service, err := NewAcornFoxRuntimeService(driver)
	if err != nil {
		t.Fatal(err)
	}
	const callerKey = "same-caller-key"
	if _, err := service.Deploy(context.Background(), contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: callerKey}); err != nil {
		t.Fatal(err)
	}
	if err := service.Restart(context.Background(), contracts.AcornFoxRuntimeActionRequest{Fact: fact, IdempotencyKey: callerKey}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Observe(context.Background(), contracts.AcornFoxRuntimeReference{Fact: fact}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Deploy(context.Background(), contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: callerKey, Recreate: true}); err != nil {
		t.Fatal(err)
	}
	if err := service.Destroy(context.Background(), contracts.AcornFoxRuntimeActionRequest{Fact: fact, IdempotencyKey: callerKey}); err != nil {
		t.Fatal(err)
	}
	driver.mu.Lock()
	keys := []string{driver.lastDeploy.Operation.IdempotencyKey, driver.lastRestart.Operation.IdempotencyKey, driver.lastObserve.Operation.IdempotencyKey, driver.lastRecreate.Operation.IdempotencyKey, driver.lastDestroy.Operation.IdempotencyKey}
	driver.mu.Unlock()
	wantActions := []string{"deploy", "restart", "read", "redeploy", "destroy"}
	seen := make(map[string]struct{}, len(keys))
	for index, key := range keys {
		operationCallerKey := callerKey
		if wantActions[index] == "read" {
			operationCallerKey = "read"
		}
		want, err := contracts.AcornFoxRuntimeOperationID(fact, wantActions[index], operationCallerKey)
		if err != nil || key != want || key == callerKey {
			t.Fatalf("provider action key was not isolated: action=%q got=%q want=%q err=%v", wantActions[index], key, want, err)
		}
		if _, exists := seen[key]; exists {
			t.Fatalf("different runtime actions collided: %q", key)
		}
		seen[key] = struct{}{}
	}
	other := fact
	other.ContainerPort = 0
	if _, err := service.Deploy(context.Background(), contracts.AcornFoxRuntimeDeployRequest{Fact: other, IdempotencyKey: callerKey}); err != nil {
		t.Fatal(err)
	}
	driver.mu.Lock()
	otherKey := driver.lastDeploy.Operation.IdempotencyKey
	driver.mu.Unlock()
	if otherKey == keys[0] {
		t.Fatal("different immutable fact reused a provider operation key")
	}
}

func TestAcornFoxRuntimeRejectsUnprovenReadbackAndFailure(t *testing.T) {
	fact := acornFoxRuntimeFact(t)
	driver := &acornFoxRuntimeStub{readbackMismatch: true}
	service, err := NewAcornFoxRuntimeService(driver)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Deploy(context.Background(), contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "deploy-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Observe(context.Background(), contracts.AcornFoxRuntimeReference{Fact: fact}); err == nil {
		t.Fatal("unproven resource readback became a success")
	}

	failing, err := NewAcornFoxRuntimeService(&acornFoxRuntimeStub{deployErr: errors.New("runtime failed")})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := failing.Deploy(context.Background(), contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "deploy-1"}); err == nil || !result.DeploymentID.Empty() {
		t.Fatalf("failed lifecycle returned success: result=%#v err=%v", result, err)
	}
}

func TestAcornFoxRuntimeRejectsEmptyIdempotencyWithoutLifecycleSideEffect(t *testing.T) {
	fact := acornFoxRuntimeFact(t)
	driver := &acornFoxRuntimeStub{}
	service, err := NewAcornFoxRuntimeService(driver)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Deploy(context.Background(), contracts.AcornFoxRuntimeDeployRequest{Fact: fact}); err == nil {
		t.Fatal("empty deploy idempotency key was accepted")
	}
	if err := service.Restart(context.Background(), contracts.AcornFoxRuntimeActionRequest{Fact: fact}); err == nil {
		t.Fatal("empty restart idempotency key was accepted")
	}
	if err := service.Destroy(context.Background(), contracts.AcornFoxRuntimeActionRequest{Fact: fact}); err == nil {
		t.Fatal("empty destroy idempotency key was accepted")
	}
	if driver.deployMutations != 0 || driver.restartMutations != 0 || driver.destroyMutations != 0 {
		t.Fatalf("empty idempotency caused a lifecycle mutation: %#v", driver)
	}
}

func TestAcornFoxRuntimeRecreateDelegatesProviderFailureWithoutLocalRetry(t *testing.T) {
	fact := acornFoxRuntimeFact(t)
	driver := &acornFoxRuntimeStub{}
	service, err := NewAcornFoxRuntimeService(driver)
	if err != nil {
		t.Fatal(err)
	}
	driver.mu.Lock()
	driver.recreateErr = errors.New("provider recreate failed")
	driver.mu.Unlock()
	request := contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "recreate-failure", Recreate: true}
	if result, err := service.Deploy(context.Background(), request); err == nil || !result.DeploymentID.Empty() {
		t.Fatalf("failed recreate returned success: result=%#v err=%v", result, err)
	}
	driver.mu.Lock()
	if driver.recreateMutations != 0 || driver.destroyMutations != 0 || driver.deployMutations != 0 || len(driver.states) != 0 {
		driver.mu.Unlock()
		t.Fatalf("failed recreate had local choreography: recreate=%d destroy=%d deploy=%d states=%d", driver.recreateMutations, driver.destroyMutations, driver.deployMutations, len(driver.states))
	}
	driver.mu.Unlock()
}

func TestAcornFoxRuntimeLifecycleRejectsUnsupportedDriver(t *testing.T) {
	driver := &acornFoxRuntimeStub{} // does not implement acornFoxLifecycleDriver
	service, err := NewAcornFoxRuntimeService(driver)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := any(service).(contracts.AcornFoxLifecycleDriver); ok {
		t.Fatal("expected service wrapping unsupported driver to NOT implement AcornFoxLifecycleDriver")
	}
}

func TestAcornFoxRuntimeLifecycleStopAndStartNarrowDelegation(t *testing.T) {
	fact := acornFoxRuntimeFact(t)
	driver := &acornFoxLifecycleStub{}
	service, err := NewAcornFoxRuntimeService(driver)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, ok := any(service).(contracts.AcornFoxLifecycleDriver)
	if !ok {
		t.Fatal("expected service wrapping lifecycle driver to implement AcornFoxLifecycleDriver")
	}
	dep, err := service.Deploy(context.Background(), contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "deploy-1"})
	if err != nil {
		t.Fatal(err)
	}

	// Stop
	if err := lifecycle.Stop(context.Background(), contracts.AcornFoxRuntimeActionRequest{Fact: fact, IdempotencyKey: "stop-1"}); err != nil {
		t.Fatal(err)
	}
	wantStopKey, err := contracts.AcornFoxRuntimeOperationID(fact, "stop", "stop-1")
	if err != nil {
		t.Fatal(err)
	}
	if driver.lastStop.Operation.IdempotencyKey != wantStopKey || driver.lastStop.DeploymentID != dep.DeploymentID || driver.stopMutations != 1 {
		t.Fatalf("Stop was not correctly delegated: key=%q mutations=%d", driver.lastStop.Operation.IdempotencyKey, driver.stopMutations)
	}
	if err := lifecycle.Stop(context.Background(), contracts.AcornFoxRuntimeActionRequest{Fact: fact, IdempotencyKey: "stop-1"}); err != nil || driver.stopMutations != 1 {
		t.Fatalf("Stop replay should be idempotent: mutations=%d err=%v", driver.stopMutations, err)
	}

	// Start
	if err := lifecycle.Start(context.Background(), contracts.AcornFoxRuntimeActionRequest{Fact: fact, IdempotencyKey: "start-1"}); err != nil {
		t.Fatal(err)
	}
	wantStartKey, err := contracts.AcornFoxRuntimeOperationID(fact, "start", "start-1")
	if err != nil {
		t.Fatal(err)
	}
	if driver.lastStart.Operation.IdempotencyKey != wantStartKey || driver.lastStart.DeploymentID != dep.DeploymentID || driver.startMutations != 1 {
		t.Fatalf("Start was not correctly delegated: key=%q mutations=%d", driver.lastStart.Operation.IdempotencyKey, driver.startMutations)
	}
	if err := lifecycle.Start(context.Background(), contracts.AcornFoxRuntimeActionRequest{Fact: fact, IdempotencyKey: "start-1"}); err != nil || driver.startMutations != 1 {
		t.Fatalf("Start replay should be idempotent: mutations=%d err=%v", driver.startMutations, err)
	}

	// Empty idempotency key rejected
	if err := lifecycle.Stop(context.Background(), contracts.AcornFoxRuntimeActionRequest{Fact: fact}); err == nil {
		t.Fatal("empty stop key should be rejected")
	}
	if err := lifecycle.Start(context.Background(), contracts.AcornFoxRuntimeActionRequest{Fact: fact}); err == nil {
		t.Fatal("empty start key should be rejected")
	}
}

func acornFoxRuntimeFact(t *testing.T) contracts.AcornFoxRuntimeReleaseFact {
	t.Helper()
	release, err := domain.NewRelease("app_1", "sg_1", 1, "sha256:"+strings.Repeat("c", 64), map[string]domain.ImageDigest{"web": {Repository: "registry.open-card.test/apps/web", Digest: acornFoxRuntimeTestDigest}}, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return mustAcornFoxRuntimeFact(t, *release)
}

func mustAcornFoxRuntimeFact(t *testing.T, release domain.Release) contracts.AcornFoxRuntimeReleaseFact {
	t.Helper()
	fact, err := contracts.ProjectAcornFoxRuntimeReleaseFact(release, "env_1", contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 500, MemoryBytes: 128 << 20, DiskReservationBytes: 256 << 20, PIDs: 64}, 8080, time.Unix(2, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return fact
}

type acornFoxRuntimeStub struct {
	mu                sync.Mutex
	deployKeys        map[string]domain.Deployment
	states            map[domain.ID]contracts.RuntimeSpec
	actions           map[string]struct{}
	deployMutations   int
	restartMutations  int
	destroyMutations  int
	recreateMutations int
	readbackMismatch  bool
	deployErr         error
	deployFailures    int
	recreateErr       error
	lastDeploy        contracts.DeployRequest
	lastRecreate      contracts.DeployRequest
	lastObserve       contracts.ObserveRequest
	lastRestart       contracts.RestartRequest
	lastDestroy       contracts.DestroyRequest
}

func (driver *acornFoxRuntimeStub) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "acornfox-runtime-stub", Version: "1", ContractVersion: contracts.ContractAPIVersion}
}

func (driver *acornFoxRuntimeStub) Deploy(_ context.Context, request contracts.DeployRequest) (domain.Deployment, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if driver.deployErr != nil {
		return domain.Deployment{}, driver.deployErr
	}
	if driver.deployFailures > 0 {
		driver.deployFailures--
		return domain.Deployment{}, errors.New("temporary runtime failure")
	}
	if driver.deployKeys == nil {
		driver.deployKeys, driver.states, driver.actions = map[string]domain.Deployment{}, map[domain.ID]contracts.RuntimeSpec{}, map[string]struct{}{}
	}
	if previous, ok := driver.deployKeys[request.Operation.IdempotencyKey]; ok {
		return previous, nil
	}
	driver.lastDeploy = request
	deployment := domain.Deployment{ID: request.DeploymentID, ApplicationID: request.Spec.ApplicationID, EnvironmentID: request.Spec.EnvironmentID, ReleaseID: request.Spec.ReleaseID, Status: domain.DeploymentRuntimeReady, CreatedAt: time.Unix(1, 0).UTC(), UpdatedAt: time.Unix(1, 0).UTC()}
	driver.deployKeys[request.Operation.IdempotencyKey] = deployment
	driver.states[request.DeploymentID] = request.Spec
	driver.deployMutations++
	return deployment, nil
}

func (driver *acornFoxRuntimeStub) Recreate(_ context.Context, request contracts.DeployRequest) (domain.Deployment, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if driver.recreateErr != nil {
		return domain.Deployment{}, driver.recreateErr
	}
	if driver.deployKeys == nil {
		driver.deployKeys, driver.states, driver.actions = map[string]domain.Deployment{}, map[domain.ID]contracts.RuntimeSpec{}, map[string]struct{}{}
	}
	driver.lastRecreate = request
	key := "recreate:" + request.Operation.IdempotencyKey
	if previous, ok := driver.deployKeys[key]; ok {
		return previous, nil
	}
	deployment := domain.Deployment{ID: request.DeploymentID, ApplicationID: request.Spec.ApplicationID, EnvironmentID: request.Spec.EnvironmentID, ReleaseID: request.Spec.ReleaseID, Status: domain.DeploymentRuntimeReady, CreatedAt: time.Unix(1, 0).UTC(), UpdatedAt: time.Unix(1, 0).UTC()}
	driver.deployKeys[key] = deployment
	driver.states[request.DeploymentID] = request.Spec
	driver.recreateMutations++
	return deployment, nil
}

func (driver *acornFoxRuntimeStub) Observe(_ context.Context, request contracts.ObserveRequest) (contracts.RuntimeObservation, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.lastObserve = request
	spec, ok := driver.states[request.DeploymentID]
	if !ok {
		return contracts.RuntimeObservation{}, acornFoxRuntimeNotFound()
	}
	readback := spec.Resources
	if driver.readbackMismatch {
		readback.MemoryBytes--
	}
	return contracts.RuntimeObservation{DeploymentID: request.DeploymentID, ServiceName: spec.ServiceName, ContainerID: acornFoxRuntimeTestContainer, Status: "running", HostPort: 39124, Limits: readback, CgroupVerified: true, ObservedAt: time.Unix(3, 0).UTC()}, nil
}

func (driver *acornFoxRuntimeStub) Logs(context.Context, contracts.LogsRequest) (<-chan string, error) {
	return nil, errors.New("not used")
}

func (driver *acornFoxRuntimeStub) Restart(_ context.Context, request contracts.RestartRequest) error {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.lastRestart = request
	if _, ok := driver.states[request.DeploymentID]; !ok {
		return acornFoxRuntimeNotFound()
	}
	if _, seen := driver.actions[request.Operation.IdempotencyKey]; !seen {
		driver.actions[request.Operation.IdempotencyKey] = struct{}{}
		driver.restartMutations++
	}
	return nil
}

func (driver *acornFoxRuntimeStub) Scale(context.Context, contracts.ScaleRequest) error {
	return errors.New("not used")
}
func (driver *acornFoxRuntimeStub) Rollback(context.Context, contracts.RollbackRequest) (domain.Deployment, error) {
	return domain.Deployment{}, errors.New("not used")
}

func (driver *acornFoxRuntimeStub) Destroy(_ context.Context, request contracts.DestroyRequest) error {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.lastDestroy = request
	if driver.states == nil {
		return acornFoxRuntimeNotFound()
	}
	if _, ok := driver.states[request.DeploymentID]; !ok {
		return acornFoxRuntimeNotFound()
	}
	if _, seen := driver.actions[request.Operation.IdempotencyKey]; !seen {
		driver.actions[request.Operation.IdempotencyKey] = struct{}{}
		driver.destroyMutations++
		delete(driver.states, request.DeploymentID)
	}
	return nil
}

func acornFoxRuntimeNotFound() error { return &contracts.ProviderError{Code: contracts.ErrNotFound} }

func acornFoxRuntimeErrorCode(err error, code contracts.ErrorCode) bool {
	var providerErr *contracts.ProviderError
	return errors.As(err, &providerErr) && providerErr.Code == code
}

type acornFoxLifecycleStub struct {
	acornFoxRuntimeStub
	stopMutations  int
	startMutations int
	lastStop       contracts.StopRequest
	lastStart      contracts.StartRequest
}

func (driver *acornFoxLifecycleStub) Stop(_ context.Context, request contracts.StopRequest) error {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.lastStop = request
	if driver.states == nil {
		return acornFoxRuntimeNotFound()
	}
	if _, ok := driver.states[request.DeploymentID]; !ok {
		return acornFoxRuntimeNotFound()
	}
	if _, seen := driver.actions[request.Operation.IdempotencyKey]; !seen {
		if driver.actions == nil {
			driver.actions = map[string]struct{}{}
		}
		driver.actions[request.Operation.IdempotencyKey] = struct{}{}
		driver.stopMutations++
	}
	return nil
}

func (driver *acornFoxLifecycleStub) Start(_ context.Context, request contracts.StartRequest) error {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.lastStart = request
	if driver.states == nil {
		return acornFoxRuntimeNotFound()
	}
	if _, ok := driver.states[request.DeploymentID]; !ok {
		return acornFoxRuntimeNotFound()
	}
	if _, seen := driver.actions[request.Operation.IdempotencyKey]; !seen {
		if driver.actions == nil {
			driver.actions = map[string]struct{}{}
		}
		driver.actions[request.Operation.IdempotencyKey] = struct{}{}
		driver.startMutations++
	}
	return nil
}

type acornFoxRetainedStub struct {
	acornFoxRuntimeStub
	volumesSupported bool
	observedReceipts []contracts.AcornFoxRetainedVolumeReceipt
}

func (driver *acornFoxRetainedStub) RetainedVolumeObservationSupported() bool {
	return driver.volumesSupported
}

func (driver *acornFoxRetainedStub) ObserveRetainedVolumes(_ context.Context, _ contracts.RuntimeSpec) ([]contracts.AcornFoxRetainedVolumeReceipt, error) {
	return driver.observedReceipts, nil
}

func TestAcornFoxRuntimeRetainedVolumeObserverCapabilityAssertion(t *testing.T) {
	// 1. Driver without volume capability marker is NOT wrapped
	baseDriver := &acornFoxRuntimeStub{}
	service1, err := NewAcornFoxRuntimeService(baseDriver)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := any(service1).(contracts.AcornFoxRetainedVolumeObserver); ok {
		t.Fatal("base driver should NOT implement AcornFoxRetainedVolumeObserver")
	}

	// 2. Driver with volumesSupported=false (e.g. Volumes==nil) is NOT wrapped
	unsupportedDriver := &acornFoxRetainedStub{volumesSupported: false}
	service2, err := NewAcornFoxRuntimeService(unsupportedDriver)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := any(service2).(contracts.AcornFoxRetainedVolumeObserver); ok {
		t.Fatal("driver with volumesSupported=false should NOT implement AcornFoxRetainedVolumeObserver")
	}

	// 3. Driver with volumesSupported=true IS wrapped
	supportedDriver := &acornFoxRetainedStub{
		volumesSupported: true,
		observedReceipts: []contracts.AcornFoxRetainedVolumeReceipt{
			{ApplicationID: "app_1", LogicalName: "data", ManagedVolumeName: "vol-1", ReceiptDigest: "sha256:" + strings.Repeat("a", 64)},
		},
	}
	service3, err := NewAcornFoxRuntimeService(supportedDriver)
	if err != nil {
		t.Fatal(err)
	}
	observer, ok := any(service3).(contracts.AcornFoxRetainedVolumeObserver)
	if !ok {
		t.Fatal("driver with volumesSupported=true SHOULD implement AcornFoxRetainedVolumeObserver")
	}
	fact := acornFoxRuntimeFact(t)
	got, err := observer.ObserveRetainedVolumes(context.Background(), fact)
	if err != nil || len(got) != 0 {
		t.Fatalf("expected empty for fact with no volumes, got=%v err=%v", got, err)
	}
}
