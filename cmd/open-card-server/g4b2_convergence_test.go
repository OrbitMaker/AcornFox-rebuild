package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type g4b2RouteStoreFake struct {
	items []postgres.DesiredRouteProjection
	err   error
}

type g4b2LeaderLeaseFake struct {
	mu       sync.Mutex
	releases int
	released chan struct{}
}

func (f *g4b2LeaderLeaseFake) Release(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releases++
	if f.releases == 1 && f.released != nil {
		close(f.released)
	}
	return nil
}

func (f *g4b2LeaderLeaseFake) Releases() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.releases
}

func TestG4B2ProductionStartupDoesNotRebuildOrStartWhenLeaderIsDenied(t *testing.T) {
	var rebuilds, starts int
	_, err := startProductionDomainConvergence(
		context.Background(),
		func(context.Context) (domainConvergenceLeaderLease, error) {
			return nil, postgres.ErrDomainConvergenceLeaderHeld
		},
		func(context.Context) error {
			rebuilds++
			return nil
		},
		func() { starts++ },
	)
	if !errors.Is(err, postgres.ErrDomainConvergenceLeaderHeld) {
		t.Fatalf("leader denial error=%v", err)
	}
	if rebuilds != 0 || starts != 0 {
		t.Fatalf("lock denial rebuilt=%d started=%d", rebuilds, starts)
	}
}

func TestG4B2ProductionStartupOrdersLeaderBeforeRebuildAndRequiresJoinedRelease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lease := &g4b2LeaderLeaseFake{released: make(chan struct{})}
	events := make([]string, 0, 3)
	release, err := startProductionDomainConvergence(
		ctx,
		func(context.Context) (domainConvergenceLeaderLease, error) {
			events = append(events, "leader")
			return lease, nil
		},
		func(context.Context) error {
			events = append(events, "rebuild")
			return nil
		},
		func() { events = append(events, "worker") },
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(events, ","); got != "leader,rebuild,worker" {
		t.Fatalf("startup order=%s", got)
	}
	cancel()
	select {
	case <-lease.released:
		t.Fatal("startup helper released leader before worker join")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case <-lease.released:
	case <-time.After(time.Second):
		t.Fatal("explicit startup cleanup did not release leader")
	}
	if lease.Releases() != 1 {
		t.Fatalf("release calls=%d", lease.Releases())
	}
}

func TestG4B2LeaderReleaseWaitsForM4WorkerAndRejectsLateWorkers(t *testing.T) {
	workers := newRouteMutationWorkerGroup()
	lease := &g4b2LeaderLeaseFake{released: make(chan struct{})}
	lifecycleContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	worker := &blockingM4LifecycleWorker{entered: make(chan struct{}), cancelled: make(chan struct{}), allowReturn: make(chan struct{}), returned: make(chan struct{})}
	if !startM4RolloutWorker(lifecycleContext, workers, worker, nil) {
		t.Fatal("M4 worker was not registered")
	}
	releaseDomainConvergenceLeaderAfterRouteWorkers(lifecycleContext, workers, func() {
		_ = lease.Release(context.Background())
	})
	select {
	case <-worker.entered:
	case <-time.After(time.Second):
		t.Fatal("M4 worker did not start")
	}
	cancel()
	select {
	case <-worker.cancelled:
	case <-time.After(time.Second):
		t.Fatal("M4 worker did not receive lifecycle cancellation")
	}
	if workers.Go(lifecycleContext, func() {}) {
		t.Fatal("route mutation worker registered after shutdown began")
	}
	select {
	case <-lease.released:
		t.Fatal("leader released before M4 returned")
	case <-time.After(20 * time.Millisecond):
	}
	close(worker.allowReturn)
	select {
	case <-worker.returned:
	case <-time.After(time.Second):
		t.Fatal("M4 worker did not return")
	}
	select {
	case <-lease.released:
	case <-time.After(time.Second):
		t.Fatal("leader was not released after M4 returned")
	}
	if lease.Releases() != 1 {
		t.Fatalf("leader releases=%d", lease.Releases())
	}
}

func TestM3ProductionCaddyConfigRequiresExactExplicitLoopbackBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		adminURL string
		listen   string
		valid    bool
	}{
		{name: "valid", adminURL: "http://127.0.0.1:2019", listen: "127.0.0.1:18481", valid: true},
		{name: "missing admin", adminURL: "", listen: "127.0.0.1:18481"},
		{name: "default listener", adminURL: "http://127.0.0.1:2019", listen: ":443"},
		{name: "missing listener", adminURL: "http://127.0.0.1:2019", listen: ""},
		{name: "public admin", adminURL: "http://192.0.2.10:2019", listen: "127.0.0.1:18481"},
		{name: "wrong admin port", adminURL: "http://127.0.0.1:2020", listen: "127.0.0.1:18481"},
		{name: "admin credentials", adminURL: "http://user:password@127.0.0.1:2019", listen: "127.0.0.1:18481"},
		{name: "admin query", adminURL: "http://127.0.0.1:2019?debug=1", listen: "127.0.0.1:18481"},
		{name: "admin fragment", adminURL: "http://127.0.0.1:2019#debug", listen: "127.0.0.1:18481"},
		{name: "admin path", adminURL: "http://127.0.0.1:2019/config", listen: "127.0.0.1:18481"},
		{name: "wrong listener port", adminURL: "http://127.0.0.1:2019", listen: "127.0.0.1:443"},
		{name: "wildcard listener", adminURL: "http://127.0.0.1:2019", listen: ":18481"},
		{name: "public listener", adminURL: "http://127.0.0.1:2019", listen: "0.0.0.0:18481"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := m3ProductionCaddyConfig(test.adminURL, test.listen)
			if test.valid {
				if err != nil {
					t.Fatal(err)
				}
				if config.AdminURL != m3ProductionCaddyAdminURL || config.Listen != m3ProductionCaddyListen || !config.PlainHTTP || config.Issuer != "" {
					t.Fatalf("unexpected production config: %#v", config)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted unsafe production config %#v", config)
			}
		})
	}
}

func TestG4B2AdapterPreservesDurableUnbindPhaseAndRestoreMarker(t *testing.T) {
	adapter := &g4b2ConvergenceAdapter{}
	for _, test := range []struct {
		phase   postgres.DomainConvergencePhase
		restore bool
	}{
		{phase: postgres.DomainConvergenceQueued},
		{phase: postgres.DomainConvergenceRecoveryRequired},
		{phase: postgres.DomainConvergenceUnbindRouteRemoved},
		{phase: postgres.DomainConvergenceUnbindRouteRemoved, restore: true},
	} {
		request := postgres.DomainConvergenceRequest{ID: "unbind_1", ApplicationID: "app_1", ApplicationDomainID: "domain_1", Hostname: "custom.example.test", Kind: postgres.DomainConvergenceUnbind, Phase: test.phase, LeaseOwner: "worker_1"}
		if test.restore {
			request.LastError = "unbind_restore_required"
		}
		work, claimed, err := adapter.work(context.Background(), request)
		if err != nil || !claimed || work.Phase != controllers.DomainConvergencePhase(test.phase) || work.Restore != test.restore {
			t.Fatalf("phase=%s restore=%v work=%+v claimed=%v err=%v", test.phase, test.restore, work, claimed, err)
		}
	}
}

func TestG4B2AdapterIdentifiesPreparedActivationRestoreWithoutLoadingCandidate(t *testing.T) {
	adapter := &g4b2ConvergenceAdapter{}
	request := postgres.DomainConvergenceRequest{ID: "converge_1", ApplicationID: "app_1", ApplicationDomainID: "domain_1", Hostname: "app.example.test", Kind: postgres.DomainConvergenceConverge, Phase: postgres.DomainConvergenceRoutePrepared, LeaseOwner: "worker_1", LastError: "route_activation_restore_required"}
	work, claimed, err := adapter.work(context.Background(), request)
	if err != nil || !claimed || !work.Restore || work.Phase != controllers.ConvergenceRoutePrepared || !work.RouteID.Empty() {
		t.Fatalf("work=%+v claimed=%v err=%v", work, claimed, err)
	}
}

func (s g4b2RouteStoreFake) ListDesiredRoutes(context.Context) ([]postgres.DesiredRouteProjection, error) {
	return s.items, s.err
}

type g4b2RouteRebuilderFake struct {
	requests []contracts.RouteRequest
	err      error
}

func (f *g4b2RouteRebuilderFake) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{}
}
func (f *g4b2RouteRebuilderFake) Apply(context.Context, contracts.RouteRequest) (domain.Route, contracts.Evidence, error) {
	return domain.Route{}, contracts.Evidence{}, nil
}
func (f *g4b2RouteRebuilderFake) Observe(context.Context, contracts.RouteRequest) (domain.Observation, error) {
	return domain.Observation{}, nil
}
func (f *g4b2RouteRebuilderFake) Remove(context.Context, contracts.RouteRequest) error { return nil }
func (f *g4b2RouteRebuilderFake) Rebuild(context.Context, contracts.OperationContext) (contracts.Evidence, error) {
	return contracts.Evidence{}, nil
}
func (f *g4b2RouteRebuilderFake) RebuildRoutes(_ context.Context, requests []contracts.RouteRequest, _ contracts.OperationContext) (contracts.Evidence, error) {
	f.requests = append([]contracts.RouteRequest(nil), requests...)
	return contracts.Evidence{}, f.err
}

type g4b2WakeStoreFake struct {
	mu           sync.Mutex
	platform     postgres.G3PlatformDomainFact
	found        bool
	bindings     []postgres.DomainConvergenceBinding
	apps         []postgres.DomainConvergenceApplication
	err          error
	ensure, wake int
	noTarget     map[domain.ID]bool
}

type g4b2CycleScannerFake struct {
	mu      sync.Mutex
	calls   int
	failFor int
	events  *[]string
}

func (f *g4b2CycleScannerFake) Scan(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.events != nil {
		*f.events = append(*f.events, "scan")
	}
	if f.calls <= f.failFor {
		return errors.New("durable binding scan unavailable")
	}
	return nil
}

func (f *g4b2CycleScannerFake) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type g4b2CycleReconcilerFake struct {
	mu     sync.Mutex
	calls  int
	events *[]string
	done   chan struct{}
}

func (f *g4b2CycleReconcilerFake) ReconcileOnce(context.Context, string) (bool, error) {
	f.mu.Lock()
	f.calls++
	if f.events != nil {
		*f.events = append(*f.events, "reconcile")
	}
	if f.done != nil && f.calls == 1 {
		close(f.done)
	}
	f.mu.Unlock()
	return false, nil
}

func (f *g4b2CycleReconcilerFake) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestG4B2ConvergenceCycleFailsClosedWhenScannerFails(t *testing.T) {
	scanner := &g4b2CycleScannerFake{failFor: 1}
	reconciler := &g4b2CycleReconcilerFake{}
	err := runDomainConvergenceCycle(context.Background(), reconciler, scanner, "owner", time.Second)
	if err == nil {
		t.Fatal("scanner failure was accepted")
	}
	if scanner.Calls() != 1 || reconciler.Calls() != 0 {
		t.Fatalf("scan=%d reconcile=%d", scanner.Calls(), reconciler.Calls())
	}
}

func TestG4B2ConvergenceWorkerRetriesAFailedScanOnTheNextTick(t *testing.T) {
	scanner := &g4b2CycleScannerFake{failFor: 1}
	reconciler := &g4b2CycleReconcilerFake{done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan struct{})
	go func() {
		runDomainConvergenceWorker(ctx, reconciler, scanner, "owner", 5*time.Millisecond)
		close(finished)
	}()
	select {
	case <-reconciler.done:
	case <-time.After(time.Second):
		t.Fatal("next worker tick did not recover scanner")
	}
	if scanner.Calls() < 2 || reconciler.Calls() != 1 {
		t.Fatalf("scan=%d reconcile=%d", scanner.Calls(), reconciler.Calls())
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("worker did not exit after cancellation")
	}
}

func TestG4B2ConvergenceWorkerFirstCycleScansBeforeReconciling(t *testing.T) {
	events := make([]string, 0, 2)
	scanner := &g4b2CycleScannerFake{events: &events}
	reconciler := &g4b2CycleReconcilerFake{events: &events, done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		runDomainConvergenceWorker(ctx, reconciler, scanner, "owner", time.Hour)
		close(finished)
	}()
	select {
	case <-reconciler.done:
	case <-time.After(time.Second):
		t.Fatal("first cycle did not reconcile")
	}
	cancel()
	<-finished
	if len(events) != 2 || events[0] != "scan" || events[1] != "reconcile" {
		t.Fatalf("events=%v", events)
	}
}

func TestG4B2ConvergenceWorkerCancellationStopsFutureCycles(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scanner := &g4b2CycleScannerFake{}
	reconciler := &g4b2CycleReconcilerFake{done: make(chan struct{})}
	finished := make(chan struct{})
	go func() {
		runDomainConvergenceWorker(ctx, reconciler, scanner, "owner", 5*time.Millisecond)
		close(finished)
	}()
	select {
	case <-reconciler.done:
	case <-time.After(time.Second):
		t.Fatal("first cycle did not complete")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after cancellation")
	}
	beforeScan, beforeReconcile := scanner.Calls(), reconciler.Calls()
	time.Sleep(20 * time.Millisecond)
	if scanner.Calls() != beforeScan || reconciler.Calls() != beforeReconcile {
		t.Fatalf("post-cancel calls scan=%d/%d reconcile=%d/%d", beforeScan, scanner.Calls(), beforeReconcile, reconciler.Calls())
	}
}

func TestG4B2ConvergenceWorkerCancelledBeforeStartDoesNoWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scanner := &g4b2CycleScannerFake{}
	reconciler := &g4b2CycleReconcilerFake{}
	runDomainConvergenceWorker(ctx, reconciler, scanner, "owner", time.Millisecond)
	if scanner.Calls() != 0 || reconciler.Calls() != 0 {
		t.Fatalf("scan=%d reconcile=%d", scanner.Calls(), reconciler.Calls())
	}
}

func (s *g4b2WakeStoreFake) PlatformDomain(context.Context) (postgres.G3PlatformDomainFact, bool, error) {
	return s.platform, s.found, s.err
}
func (s *g4b2WakeStoreFake) ListVerifiedDomainConvergenceBindings(context.Context) ([]postgres.DomainConvergenceBinding, error) {
	if s.err != nil {
		return nil, s.err
	}
	return append([]postgres.DomainConvergenceBinding(nil), s.bindings...), nil
}
func (s *g4b2WakeStoreFake) ListDomainConvergenceRuntimeApplications(context.Context) ([]postgres.DomainConvergenceApplication, error) {
	if s.err != nil {
		return nil, s.err
	}
	return append([]postgres.DomainConvergenceApplication(nil), s.apps...), nil
}
func (s *g4b2WakeStoreFake) EnsureDomainConvergencePlatformDomain(_ context.Context, platform, app domain.ID, name, base, ref string, now time.Time) (postgres.ApplicationDomainRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure++
	return postgres.ApplicationDomainRecord{ID: domain.ID("domain_" + app.String()), ApplicationID: app, PlatformDomainID: platform, Hostname: "app.apps." + base, Kind: "platform", StableSlug: "app", VerificationMethod: "dns01", VerificationStatus: postgres.DomainVerificationVerified, VerificationRef: ref, VerifiedAt: &now}, nil
}
func (s *g4b2WakeStoreFake) WakeDomainConvergence(_ context.Context, domainID, app domain.ID, host string, _ time.Time) (postgres.DomainConvergenceRequest, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.noTarget[app] {
		return postgres.DomainConvergenceRequest{}, false, postgres.ErrNotFound
	}
	s.wake++
	return postgres.DomainConvergenceRequest{ID: domain.ID("request_" + domainID.String())}, false, nil
}

func TestG4B2ScannerBackfillsPlatformAndCustomIdempotently(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	store := &g4b2WakeStoreFake{platform: postgres.G3PlatformDomainFact{ID: "platform_1", BaseDomain: "example.test", VerificationRef: "public-dns-read-only/v2-console-ingress-wildcard", VerificationStatus: postgres.G3VerificationVerified}, found: true, apps: []postgres.DomainConvergenceApplication{{ID: "app_1", Name: "Demo"}}, bindings: []postgres.DomainConvergenceBinding{{ID: "custom_1", ApplicationID: "app_2", Hostname: "www.example.test", Kind: "custom"}}, noTarget: map[domain.ID]bool{}}
	w := &g4b2PostgresWaker{store: store, clock: func() time.Time { return now }}
	if err := w.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := w.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.ensure != 2 || store.wake != 4 {
		t.Fatalf("ensure=%d wake=%d", store.ensure, store.wake)
	}
}
func TestG4B2ScannerTreatsMissingRuntimeTargetAsQueuedFutureWork(t *testing.T) {
	store := &g4b2WakeStoreFake{bindings: []postgres.DomainConvergenceBinding{{ID: "custom_1", ApplicationID: "app_1", Hostname: "www.example.test", Kind: "custom"}}, noTarget: map[domain.ID]bool{"app_1": true}}
	if err := (&g4b2PostgresWaker{store: store}).Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.wake != 0 {
		t.Fatalf("wake=%d", store.wake)
	}
}
func TestG4B2ScannerFailureDoesNotWakeOrClaim(t *testing.T) {
	store := &g4b2WakeStoreFake{err: errors.New("database unavailable"), noTarget: map[domain.ID]bool{}}
	if err := (&g4b2PostgresWaker{store: store}).Scan(context.Background()); err == nil {
		t.Fatal("scan error accepted")
	}
	if store.ensure != 0 || store.wake != 0 {
		t.Fatalf("ensure=%d wake=%d", store.ensure, store.wake)
	}
}

func TestG4B2ScannerConcurrentRunsOnlyCreateReplayableWakeFacts(t *testing.T) {
	store := &g4b2WakeStoreFake{bindings: []postgres.DomainConvergenceBinding{{ID: "custom_1", ApplicationID: "app_1", Hostname: "www.example.test", Kind: "custom"}}, noTarget: map[domain.ID]bool{}}
	waker := &g4b2PostgresWaker{store: store}
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := waker.Scan(context.Background()); err != nil {
				t.Errorf("scan: %v", err)
			}
		}()
	}
	group.Wait()
	if store.wake != 2 || store.ensure != 0 {
		t.Fatalf("wake=%d ensure=%d", store.wake, store.ensure)
	}
}

func TestG4B2StartupRebuildIncludesServingAndNonServingActiveRoutes(t *testing.T) {
	now := time.Unix(1, 0)
	lease := postgres.PortLease{ID: "lease_1", ApplicationID: "app_1", DeploymentID: "dep_1", ServiceName: "web", BindHost: "127.0.0.1", Port: 18080, AcquiredAt: now}
	pointer := postgres.RoutePointer{RouteID: "route_1", DeploymentID: "dep_1", PortLeaseID: "lease_1", Revision: 1, UpdatedAt: now}
	serving := postgres.DesiredRouteProjection{DesiredRouteRecord: postgres.DesiredRouteRecord{Route: domain.Route{ID: "route_1", ApplicationID: "app_1", DeploymentID: "dep_1", ServiceName: "web", Host: "a.example.test", Path: "/", Verified: true, Serving: true}, State: postgres.DesiredRouteActive}, Pointer: &pointer, Lease: &lease}
	nonServing := serving
	nonServing.Route.ID = "route_2"
	nonServing.Route.Host = "b.example.test"
	nonServing.Route.Serving = false
	nonServing.Pointer = &postgres.RoutePointer{RouteID: "route_2", DeploymentID: "dep_1", PortLeaseID: "lease_1", Revision: 1, UpdatedAt: now}
	routes := &g4b2RouteRebuilderFake{}
	if err := rebuildDomainConvergenceRoutes(context.Background(), g4b2RouteStoreFake{items: []postgres.DesiredRouteProjection{serving, nonServing}}, routes, "owner"); err != nil {
		t.Fatal(err)
	}
	if len(routes.requests) != 2 {
		t.Fatalf("requests=%d", len(routes.requests))
	}
}
func TestG4B2StartupRebuildRejectsIncompleteProjection(t *testing.T) {
	routes := &g4b2RouteRebuilderFake{}
	bad := postgres.DesiredRouteProjection{DesiredRouteRecord: postgres.DesiredRouteRecord{Route: domain.Route{ID: "route_1", ApplicationID: "app_1", DeploymentID: "dep_1", ServiceName: "web", Host: "a.example.test", Path: "/", Verified: true}, State: postgres.DesiredRouteActive}}
	if err := rebuildDomainConvergenceRoutes(context.Background(), g4b2RouteStoreFake{items: []postgres.DesiredRouteProjection{bad}}, routes, "owner"); err == nil {
		t.Fatal("incomplete projection accepted")
	}
}

func TestG4B2StartupRebuildHandlesEmptySetAndProviderFailure(t *testing.T) {
	empty := &g4b2RouteRebuilderFake{}
	if err := rebuildDomainConvergenceRoutes(context.Background(), g4b2RouteStoreFake{}, empty, "owner"); err != nil || len(empty.requests) != 0 {
		t.Fatalf("empty err=%v requests=%d", err, len(empty.requests))
	}
	failing := &g4b2RouteRebuilderFake{err: errors.New("caddy unavailable")}
	if err := rebuildDomainConvergenceRoutes(context.Background(), g4b2RouteStoreFake{}, failing, "owner"); err == nil {
		t.Fatal("provider failure accepted")
	}
}
