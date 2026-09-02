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
