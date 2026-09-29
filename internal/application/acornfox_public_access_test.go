package application

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func TestAcornFoxPublicAccessEnableUsesAcceptedEndpointAndStaysPending(t *testing.T) {
	fixture := newAcornFoxPublicAccessFixture()
	result, err := fixture.service.Set(context.Background(), fixture.request(true, "enable-1"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != contracts.AcornFoxPublicPendingExternalValidation || result.ApplicationID != fixture.applicationID || result.DeploymentID != fixture.deploymentID {
		t.Fatalf("unexpected local public result: %+v", result)
	}
	if !result.DesiredPublic || result.InternalEndpoint != contracts.AcornFoxInternalEndpointAccepted || result.LocalRoute != contracts.AcornFoxLocalRouteConfigured {
		t.Fatalf("enable did not report durable component state: %+v", result)
	}
	if fixture.router.ensureCalls != 1 || fixture.router.removeCalls != 0 || fixture.router.lastEnsure.ApplicationID != fixture.applicationID || fixture.router.lastEnsure.DeploymentID != fixture.deploymentID || fixture.router.lastEnsure.ServiceName != fixture.endpoint.ServiceName || fixture.router.lastEnsure.Port != fixture.endpoint.Port {
		t.Fatalf("router was not given only the accepted local endpoint: %+v", fixture.router)
	}
	if fixture.endpointReads != 1 || fixture.runtimeMutations != 0 || fixture.dataMutations != 0 || fixture.dnsCalls != 0 {
		t.Fatalf("public enable mutated a forbidden boundary: endpoint_reads=%d runtime=%d data=%d dns=%d", fixture.endpointReads, fixture.runtimeMutations, fixture.dataMutations, fixture.dnsCalls)
	}
	if result.Hostname != fixture.router.lastEnsure.Hostname || result.Hostname == "" {
		t.Fatalf("result hostname is not the owned route hostname: result=%+v route=%+v", result, fixture.router.lastEnsure)
	}
}

func TestAcornFoxPublicAccessGetDefaultsDisabledAndNeverObservesExternalState(t *testing.T) {
	fixture := newAcornFoxPublicAccessFixture()
	serviceType := reflect.TypeOf(AcornFoxPublicAccessService{})
	for _, forbidden := range []string{"DNS", "TLS", "Runtime", "Storage"} {
		if _, exists := serviceType.FieldByName(forbidden); exists {
			t.Fatalf("public-access service unexpectedly owns %s boundary", forbidden)
		}
	}
	result, err := fixture.service.Get(context.Background(), fixture.applicationID, fixture.deploymentID)
	if err != nil || result.Status != contracts.AcornFoxPublicDisabled || result.Hostname == "" || result.DesiredPublic || result.InternalEndpoint != contracts.AcornFoxInternalEndpointNotObserved || result.LocalRoute != contracts.AcornFoxLocalRouteDisabled {
		t.Fatalf("default public status=%+v err=%v", result, err)
	}
	if fixture.endpointReads != 0 || fixture.router.ensureCalls != 0 || fixture.router.removeCalls != 0 || fixture.runtimeMutations != 0 || fixture.dataMutations != 0 || fixture.dnsCalls != 0 {
		t.Fatalf("GET crossed an external or runtime boundary: %+v", fixture)
	}
	if _, err := fixture.service.Set(context.Background(), fixture.request(true, "enable-1")); err != nil {
		t.Fatal(err)
	}
	result, err = fixture.service.Get(context.Background(), fixture.applicationID, fixture.deploymentID)
	if err != nil || result.Status != contracts.AcornFoxPublicPendingExternalValidation {
		t.Fatalf("stored public status=%+v err=%v", result, err)
	}
}

func TestAcornFoxPublicAccessEnableRejectsMissingOrUnownedEndpoint(t *testing.T) {
	for _, endpoint := range []contracts.AcornFoxRoutableEndpoint{
		{},
		{ApplicationID: "app_other", DeploymentID: "dep_public_1", ServiceName: "web", Port: 8080, Accepted: true},
		{ApplicationID: "app_public_1", DeploymentID: "dep_other", ServiceName: "web", Port: 8080, Accepted: true},
		{ApplicationID: "app_public_1", DeploymentID: "dep_public_1", ServiceName: "web", Port: 8080},
	} {
		fixture := newAcornFoxPublicAccessFixture()
		fixture.endpoint = endpoint
		_, err := fixture.service.Set(context.Background(), fixture.request(true, "missing-endpoint"))
		if code, ok := AcornFoxPublicAccessErrorCodeOf(err); !ok || code != AcornFoxInternalEndpointNotReady {
			t.Fatalf("endpoint=%+v code=%q ok=%v err=%v", endpoint, code, ok, err)
		}
		if fixture.router.ensureCalls != 0 || fixture.router.removeCalls != 0 || fixture.dnsCalls != 0 {
			t.Fatalf("unready endpoint reached an external boundary: %+v", fixture.router)
		}
	}
}

func TestAcornFoxPublicAccessDisableRemovesOnlyStoredOwnedRoute(t *testing.T) {
	fixture := newAcornFoxPublicAccessFixture()
	if _, err := fixture.service.Set(context.Background(), fixture.request(true, "enable-1")); err != nil {
		t.Fatal(err)
	}
	result, err := fixture.service.Set(context.Background(), fixture.request(false, "disable-1"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != contracts.AcornFoxPublicDisabled || fixture.router.removeCalls != 1 || fixture.router.lastRemove != fixture.router.lastEnsure {
		t.Fatalf("disable did not remove exactly the stored owned route: result=%+v router=%+v", result, fixture.router)
	}
	stored, err := fixture.service.Get(context.Background(), fixture.applicationID, fixture.deploymentID)
	if err != nil || stored.Status != contracts.AcornFoxPublicDisabled {
		t.Fatalf("disable did not become current public state: %+v err=%v", stored, err)
	}
	if fixture.endpointReads != 1 || fixture.runtimeMutations != 0 || fixture.dataMutations != 0 || fixture.dnsCalls != 0 {
		t.Fatalf("disable reread or mutated a forbidden boundary: endpoint_reads=%d runtime=%d data=%d dns=%d", fixture.endpointReads, fixture.runtimeMutations, fixture.dataMutations, fixture.dnsCalls)
	}

	fixture = newAcornFoxPublicAccessFixture()
	fixture.binding = contracts.AcornFoxPublicRouteIntent{ApplicationID: "app_other", DeploymentID: fixture.deploymentID, Hostname: "delivery-1234567890abcdef1234.apps.example.test", ServiceName: "web", Port: 8080}
	fixture.bindingFound = true
	_, err = fixture.service.Set(context.Background(), fixture.request(false, "disable-foreign"))
	if code, ok := AcornFoxPublicAccessErrorCodeOf(err); !ok || code != AcornFoxPublicAccessOwnershipConflict {
		t.Fatalf("foreign owned binding code=%q ok=%v err=%v", code, ok, err)
	}
	if fixture.router.removeCalls != 0 || fixture.dnsCalls != 0 {
		t.Fatalf("foreign route was touched: %+v", fixture.router)
	}
}

func TestAcornFoxPublicAccessReplayAndConflictArePerDeployment(t *testing.T) {
	fixture := newAcornFoxPublicAccessFixture()
	first, err := fixture.service.Set(context.Background(), fixture.request(true, "same-key"))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := fixture.service.Set(context.Background(), fixture.request(true, "same-key"))
	if err != nil || replay != first || fixture.router.ensureCalls != 1 {
		t.Fatalf("same command was not replayed: first=%+v replay=%+v calls=%d err=%v", first, replay, fixture.router.ensureCalls, err)
	}
	_, err = fixture.service.Set(context.Background(), fixture.request(false, "same-key"))
	if code, ok := AcornFoxPublicAccessErrorCodeOf(err); !ok || code != AcornFoxPublicAccessIdempotencyConflict {
		t.Fatalf("different body reuse code=%q ok=%v err=%v", code, ok, err)
	}
	if fixture.router.removeCalls != 0 {
		t.Fatalf("conflicting replay changed route: %+v", fixture.router)
	}
}

func TestAcornFoxPublicAccessDisableWithoutOwnedRouteIsLocalNoOp(t *testing.T) {
	fixture := newAcornFoxPublicAccessFixture()
	result, err := fixture.service.Set(context.Background(), fixture.request(false, "disable-empty"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != contracts.AcornFoxPublicDisabled || fixture.router.removeCalls != 0 || fixture.endpointReads != 0 || fixture.dnsCalls != 0 {
		t.Fatalf("empty disable was not a local no-op: result=%+v router=%+v endpoint_reads=%d dns=%d", result, fixture.router, fixture.endpointReads, fixture.dnsCalls)
	}
}

func TestAcornFoxPublicAccessRejectsConcurrentUnsettledCommand(t *testing.T) {
	fixture := newAcornFoxPublicAccessFixture()
	request := fixture.request(true, "unsettled")
	hostname, err := contracts.AcornFoxPublicHostname("example.test", request.ApplicationID, request.DeploymentID)
	if err != nil {
		t.Fatal(err)
	}
	fixture.records[request.IdempotencyKey] = acornFoxPublicAccessRecord{digest: acornFoxPublicAccessDigest(request, hostname)}
	_, err = fixture.service.Set(context.Background(), request)
	if code, ok := AcornFoxPublicAccessErrorCodeOf(err); !ok || code != AcornFoxPublicAccessConflict {
		t.Fatalf("unsettled command code=%q ok=%v err=%v", code, ok, err)
	}
	if fixture.router.ensureCalls != 0 || fixture.router.removeCalls != 0 || fixture.dnsCalls != 0 {
		t.Fatalf("unsettled command touched route or DNS")
	}
}

func TestAcornFoxPublicAccessMapsRouterConflictOwnershipAndUnavailable(t *testing.T) {
	for _, scenario := range []struct {
		name string
		err  error
		want AcornFoxPublicAccessErrorCode
	}{
		{name: "conflict", err: ErrAcornFoxPublicAccessConflict, want: AcornFoxPublicAccessConflict},
		{name: "ownership", err: ErrAcornFoxPublicAccessOwnershipConflict, want: AcornFoxPublicAccessOwnershipConflict},
		{name: "unavailable", err: errors.New("router down"), want: AcornFoxPublicAccessUnavailable},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			fixture := newAcornFoxPublicAccessFixture()
			fixture.router.ensureErr = scenario.err
			fact, err := fixture.service.Set(context.Background(), fixture.request(true, scenario.name))
			if code, ok := AcornFoxPublicAccessErrorCodeOf(err); !ok || code != scenario.want {
				t.Fatalf("code=%q ok=%v want=%q err=%v", code, ok, scenario.want, err)
			}
			if fixture.runtimeMutations != 0 || fixture.dataMutations != 0 || fixture.dnsCalls != 0 {
				t.Fatalf("router error mutated forbidden boundary")
			}
			if !fact.DesiredPublic || fact.InternalEndpoint != contracts.AcornFoxInternalEndpointAccepted || fact.LocalRoute != contracts.AcornFoxLocalRouteReconcileRequired {
				t.Fatalf("router error was not retained as reconcile_required: %+v", fact)
			}
		})
	}
}

func TestAcornFoxPublicAccessRejectsInvalidInputBeforeAnyBoundary(t *testing.T) {
	fixture := newAcornFoxPublicAccessFixture()
	for _, request := range []AcornFoxPublicAccessRequest{
		{ApplicationID: fixture.applicationID, DeploymentID: fixture.deploymentID},
		{ApplicationID: fixture.applicationID, IdempotencyKey: "missing-deployment"},
		{DeploymentID: fixture.deploymentID, IdempotencyKey: "missing-app"},
	} {
		if _, err := fixture.service.Set(context.Background(), request); err == nil {
			t.Fatalf("invalid request accepted: %+v", request)
		}
	}
	if fixture.beginCalls != 0 || fixture.endpointReads != 0 || fixture.router.ensureCalls != 0 || fixture.router.removeCalls != 0 || fixture.dnsCalls != 0 {
		t.Fatalf("invalid request crossed a boundary: %+v", fixture)
	}
}

type acornFoxPublicAccessFixture struct {
	mu               sync.Mutex
	service          *AcornFoxPublicAccessService
	applicationID    domain.ID
	deploymentID     domain.ID
	endpoint         contracts.AcornFoxRoutableEndpoint
	binding          contracts.AcornFoxPublicRouteIntent
	bindingFound     bool
	records          map[string]acornFoxPublicAccessRecord
	committed        map[string]contracts.AcornFoxPublicAccessFact
	current          contracts.AcornFoxPublicAccessFact
	currentFound     bool
	beginCalls       int
	endpointReads    int
	runtimeMutations int
	dataMutations    int
	dnsCalls         int
	router           acornFoxPublicAccessRouterFixture
	now              time.Time
}

type acornFoxPublicAccessRecord struct {
	digest string
	result contracts.AcornFoxPublicAccessFact
	done   bool
}

func newAcornFoxPublicAccessFixture() *acornFoxPublicAccessFixture {
	fixture := &acornFoxPublicAccessFixture{
		applicationID: "app_public_1", deploymentID: "dep_public_1",
		endpoint: contracts.AcornFoxRoutableEndpoint{ApplicationID: "app_public_1", DeploymentID: "dep_public_1", ServiceName: "web", Port: 8080, Accepted: true},
		records:  map[string]acornFoxPublicAccessRecord{}, committed: map[string]contracts.AcornFoxPublicAccessFact{}, now: time.Unix(1_700_000_000, 0).UTC(),
	}
	fixture.service = &AcornFoxPublicAccessService{Store: fixture, Router: &fixture.router, Config: AcornFoxPublicAccessConfig{AuthorizedRoot: "example.test"}, Clock: func() time.Time { return fixture.now }}
	return fixture
}

func (fixture *acornFoxPublicAccessFixture) request(enabled bool, key string) AcornFoxPublicAccessRequest {
	return AcornFoxPublicAccessRequest{ApplicationID: fixture.applicationID, DeploymentID: fixture.deploymentID, Enabled: enabled, IdempotencyKey: key}
}

func (fixture *acornFoxPublicAccessFixture) BeginAcornFoxPublicAccess(_ context.Context, fact contracts.AcornFoxPublicAccessFact, _ contracts.AcornFoxPublicRouteIntent, _ bool, key, digest string, _ domain.ID, _ time.Time) (contracts.AcornFoxPublicAccessFact, bool, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.beginCalls++
	record, ok := fixture.records[key]
	if !ok {
		fixture.records[key] = acornFoxPublicAccessRecord{digest: digest, result: fact}
		return contracts.AcornFoxPublicAccessFact{}, false, nil
	}
	if record.digest != digest {
		return contracts.AcornFoxPublicAccessFact{}, false, ErrIdempotencyConflict
	}
	if record.done {
		return record.result, true, nil
	}
	return contracts.AcornFoxPublicAccessFact{}, false, ErrAcornFoxPublicAccessConflict
}

func (fixture *acornFoxPublicAccessFixture) MarkAcornFoxPublicAccessReconcileRequired(_ context.Context, _, _ domain.ID, key, _ string, _ time.Time) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	record, ok := fixture.records[key]
	if !ok {
		return ErrAcornFoxPublicAccessConflict
	}
	record.result.LocalRoute = contracts.AcornFoxLocalRouteReconcileRequired
	fixture.records[key] = record
	fixture.current, fixture.currentFound = record.result, true
	return nil
}

func (fixture *acornFoxPublicAccessFixture) CommitAcornFoxPublicAccess(_ context.Context, fact contracts.AcornFoxPublicAccessFact, intent contracts.AcornFoxPublicRouteIntent, key, digest string, _ time.Time) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	record := fixture.records[key]
	if record.digest != digest {
		return ErrIdempotencyConflict
	}
	record.result, record.done = fact, true
	fixture.records[key] = record
	fixture.committed[key] = fact
	fixture.current, fixture.currentFound = fact, true
	if fact.Status == contracts.AcornFoxPublicPendingExternalValidation {
		fixture.binding = intent
		fixture.bindingFound = true
	} else {
		fixture.binding = contracts.AcornFoxPublicRouteIntent{}
		fixture.bindingFound = false
	}
	return nil
}

func (fixture *acornFoxPublicAccessFixture) FailAcornFoxPublicAccess(_ context.Context, _, _ domain.ID, key, digest, _ string, _ time.Time) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	record := fixture.records[key]
	if record.digest != digest {
		return ErrIdempotencyConflict
	}
	record.done = true
	fixture.records[key] = record
	return nil
}

func (fixture *acornFoxPublicAccessFixture) GetAcornFoxPublicAccess(_ context.Context, applicationID, deploymentID domain.ID) (contracts.AcornFoxPublicAccessFact, bool, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.currentFound && fixture.current.ApplicationID == applicationID && fixture.current.DeploymentID == deploymentID {
		return fixture.current, true, nil
	}
	return contracts.AcornFoxPublicAccessFact{}, false, nil
}

func (fixture *acornFoxPublicAccessFixture) GetAcornFoxRoutableEndpoint(_ context.Context, _, _ domain.ID) (contracts.AcornFoxRoutableEndpoint, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.endpointReads++
	if !fixture.endpoint.Accepted {
		return fixture.endpoint, fmt.Errorf("endpoint absent")
	}
	return fixture.endpoint, nil
}

func (fixture *acornFoxPublicAccessFixture) GetAcornFoxPublicRouteIntent(_ context.Context, _, _ domain.ID) (contracts.AcornFoxPublicRouteIntent, bool, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.binding, fixture.bindingFound, nil
}

type acornFoxPublicAccessRouterFixture struct {
	ensureCalls int
	removeCalls int
	lastEnsure  contracts.AcornFoxPublicRouteIntent
	lastRemove  contracts.AcornFoxPublicRouteIntent
	ensureErr   error
	removeErr   error
}

func (router *acornFoxPublicAccessRouterFixture) EnsureAcornFoxPublicRoute(_ context.Context, intent contracts.AcornFoxPublicRouteIntent, _ string) error {
	router.ensureCalls++
	router.lastEnsure = intent
	return router.ensureErr
}

func (router *acornFoxPublicAccessRouterFixture) RemoveAcornFoxPublicRoute(_ context.Context, intent contracts.AcornFoxPublicRouteIntent, _ string) error {
	router.removeCalls++
	router.lastRemove = intent
	return router.removeErr
}
