package main

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
	caddyprovider "github.com/open-card/open-card/internal/providers/caddy"
	"github.com/open-card/open-card/internal/providers/edgeprobe"
)

// g4b2ConvergenceAdapter deliberately exposes only phase-safe store methods to
// the worker. Each Store method owns a short transaction; no provider call is
// made while a transaction remains open.
type g4b2ConvergenceAdapter struct {
	store *postgres.Store
	clock func() time.Time
}

const (
	m3ProductionCaddyAdminURL = "http://127.0.0.1:2019"
	m3ProductionCaddyListen   = "127.0.0.1:18481"
)

type g4b2ConvergenceWakeStore interface {
	PlatformDomain(context.Context) (postgres.G3PlatformDomainFact, bool, error)
	ListVerifiedDomainConvergenceBindings(context.Context) ([]postgres.DomainConvergenceBinding, error)
	ListDomainConvergenceRuntimeApplications(context.Context) ([]postgres.DomainConvergenceApplication, error)
	EnsureDomainConvergencePlatformDomain(context.Context, domain.ID, domain.ID, string, string, string, time.Time) (postgres.ApplicationDomainRecord, error)
	WakeDomainConvergence(context.Context, domain.ID, domain.ID, string, time.Time) (postgres.DomainConvergenceRequest, bool, error)
}

type g4b2PostgresWaker struct {
	store g4b2ConvergenceWakeStore
	clock func() time.Time
}

func (w *g4b2PostgresWaker) Scan(ctx context.Context) error {
	if w.store == nil {
		return domain.ValidationError("domain convergence scanner store is required")
	}
	platform, found, err := w.store.PlatformDomain(ctx)
	if err != nil {
		return err
	}
	if found && platform.VerificationStatus == postgres.G3VerificationVerified {
		if err := w.WakePlatform(ctx, controllers.G3PlatformDomainFact{ID: platform.ID, BaseDomain: platform.BaseDomain, VerificationRef: platform.VerificationRef, VerificationStatus: controllers.G3VerificationStatus(platform.VerificationStatus), VerifiedAt: platform.VerifiedAt}); err != nil {
			return err
		}
	}
	bindings, err := w.store.ListVerifiedDomainConvergenceBindings(ctx)
	if err != nil {
		return err
	}
	for _, binding := range bindings {
		if binding.Kind != "custom" {
			continue
		}
		if err := w.WakeCustom(ctx, controllers.G3ApplicationDomainFact{ID: binding.ID, ApplicationID: binding.ApplicationID, Hostname: binding.Hostname, Kind: binding.Kind, VerificationStatus: controllers.G3VerificationVerified}); err != nil {
			return err
		}
	}
	return nil
}

func (w *g4b2PostgresWaker) now() time.Time {
	if w.clock != nil {
		return w.clock().UTC()
	}
	return time.Now().UTC()
}
func (w *g4b2PostgresWaker) WakePlatform(ctx context.Context, fact controllers.G3PlatformDomainFact) error {
	if w.store == nil || fact.VerificationStatus != controllers.G3VerificationVerified {
		return nil
	}
	apps, err := w.store.ListDomainConvergenceRuntimeApplications(ctx)
	if err != nil {
		return err
	}
	for _, app := range apps {
		record, err := w.store.EnsureDomainConvergencePlatformDomain(ctx, fact.ID, app.ID, app.Name, fact.BaseDomain, fact.VerificationRef, w.now())
		if err != nil {
			return err
		}
		if _, _, err := w.store.WakeDomainConvergence(ctx, record.ID, app.ID, record.Hostname, w.now()); err != nil && !errors.Is(err, postgres.ErrNotFound) {
			return err
		}
	}
	return nil
}
func (w *g4b2PostgresWaker) WakeCustom(ctx context.Context, fact controllers.G3ApplicationDomainFact) error {
	if w.store == nil || fact.VerificationStatus != controllers.G3VerificationVerified {
		return nil
	}
	_, _, err := w.store.WakeDomainConvergence(ctx, fact.ID, fact.ApplicationID, fact.Hostname, w.now())
	if errors.Is(err, postgres.ErrNotFound) {
		return nil
	}
	return err
}

func (a *g4b2ConvergenceAdapter) now() time.Time {
	if a.clock != nil {
		return a.clock().UTC()
	}
	return time.Now().UTC()
}

func (a *g4b2ConvergenceAdapter) ClaimDomainConvergence(ctx context.Context, owner string, lease time.Duration) (controllers.DomainConvergenceWork, bool, error) {
	request, claimed, err := a.store.ClaimDomainConvergenceRequest(ctx, owner, lease, a.now())
	if err != nil || !claimed {
		return controllers.DomainConvergenceWork{}, claimed, err
	}
	return a.work(ctx, request)
}

func (a *g4b2ConvergenceAdapter) work(ctx context.Context, request postgres.DomainConvergenceRequest) (controllers.DomainConvergenceWork, bool, error) {
	if request.Kind == postgres.DomainConvergenceUnbind {
		return controllers.DomainConvergenceWork{ID: request.ID, ApplicationID: request.ApplicationID, DomainID: request.ApplicationDomainID, Hostname: request.Hostname, Kind: string(request.Kind), Restore: request.LastError == "unbind_restore_required", Phase: controllers.DomainConvergencePhase(request.Phase), LeaseOwner: request.LeaseOwner, Attempt: request.Attempt}, true, nil
	}
	if request.Kind == postgres.DomainConvergenceConverge && request.Phase == postgres.DomainConvergenceRoutePrepared && request.LastError == "route_activation_restore_required" {
		return controllers.DomainConvergenceWork{ID: request.ID, ApplicationID: request.ApplicationID, DomainID: request.ApplicationDomainID, Hostname: request.Hostname, Kind: string(request.Kind), Restore: true, Phase: controllers.ConvergenceRoutePrepared, LeaseOwner: request.LeaseOwner, Attempt: request.Attempt}, true, nil
	}
	target, err := a.store.LoadDomainConvergenceFrozenTarget(ctx, request.ID, request.LeaseOwner, a.now())
	if err != nil {
		return controllers.DomainConvergenceWork{}, false, err
	}
	routeID := postgres.DomainConvergenceRouteID(request.ApplicationDomainID)
	route := contracts.RouteRequest{Route: contracts.RouteSpec{Host: request.Hostname, Path: target.Path, DeploymentID: target.DeploymentID, ServiceName: target.ServiceName, Port: target.Port, Verified: true}, Operation: contracts.OperationContext{IdempotencyKey: request.ID.String(), Actor: request.LeaseOwner}}
	return controllers.DomainConvergenceWork{ID: request.ID, ApplicationID: request.ApplicationID, DomainID: request.ApplicationDomainID, Hostname: request.Hostname, Kind: string(request.Kind), Phase: controllers.DomainConvergencePhase(request.Phase), RouteID: routeID, Route: route, LeaseOwner: request.LeaseOwner, Attempt: request.Attempt}, true, nil
}

func (a *g4b2ConvergenceAdapter) PrepareDomainConvergenceRoute(ctx context.Context, work controllers.DomainConvergenceWork) (controllers.DomainConvergenceWork, error) {
	prepared, err := a.store.PrepareDomainConvergenceRequest(ctx, work.ID, work.LeaseOwner, a.now())
	if err != nil {
		return controllers.DomainConvergenceWork{}, err
	}
	work.RouteID, work.Phase = prepared.Route.ID, controllers.ConvergenceRoutePrepared
	work.Route = contracts.RouteRequest{Route: contracts.RouteSpec{Host: prepared.Route.Host, Path: prepared.Route.Path, DeploymentID: prepared.Route.DeploymentID, ServiceName: prepared.Route.ServiceName, Port: prepared.Port, Verified: true}, Operation: contracts.OperationContext{IdempotencyKey: work.ID.String(), Actor: work.LeaseOwner}}
	return work, nil
}
func (a *g4b2ConvergenceAdapter) ActivateDomainConvergenceRoute(ctx context.Context, work controllers.DomainConvergenceWork) error {
	_, err := a.store.ActivateDomainConvergenceRoute(ctx, work.ID, work.LeaseOwner, a.now())
	return err
}
func (a *g4b2ConvergenceAdapter) AllowDomainConvergenceTLS(ctx context.Context, work controllers.DomainConvergenceWork) error {
	return a.store.AllowDomainConvergenceTLS(ctx, work.ID, work.LeaseOwner, a.now())
}
func (a *g4b2ConvergenceAdapter) RecordDomainConvergenceProbe(ctx context.Context, work controllers.DomainConvergenceWork, observation edgeprobe.Observation) error {
	value := postgres.DomainConvergenceCertificateObservation{Fingerprint: observation.Fingerprint, Issuer: observation.Issuer, NotBefore: observation.NotBefore, NotAfter: observation.NotAfter}
	if err := a.store.RecordDomainConvergenceCertificateObservation(ctx, work.ID, work.LeaseOwner, value, observation.StatusCode, a.now()); err != nil {
		return err
	}
	if err := a.store.FinalizeDomainConvergenceCertificate(ctx, work.ID, work.LeaseOwner, value, a.now()); err != nil {
		return err
	}
	return a.store.AcknowledgeDomainConvergenceCompleted(ctx, work.ID, work.LeaseOwner, a.now())
}
func (a *g4b2ConvergenceAdapter) FailDomainConvergence(ctx context.Context, work controllers.DomainConvergenceWork, code string, _ error) error {
	return a.store.FailDomainConvergenceRequest(ctx, work.ID, work.LeaseOwner, postgres.DomainConvergencePhase(work.Phase), code, a.now())
}
func (a *g4b2ConvergenceAdapter) RecoverDomainConvergenceCompleted(ctx context.Context, work controllers.DomainConvergenceWork) (bool, error) {
	return a.store.RecoverDomainConvergenceCompleted(ctx, work.ID, work.LeaseOwner, a.now())
}
func (a *g4b2ConvergenceAdapter) LoadDomainConvergenceCertificateObservation(ctx context.Context, work controllers.DomainConvergenceWork) (controllers.DomainConvergenceObservation, error) {
	value, err := a.store.LoadDomainConvergenceCertificateObservation(ctx, work.ID, work.LeaseOwner, a.now())
	return controllers.DomainConvergenceObservation{Fingerprint: value.Fingerprint, Issuer: value.Issuer, NotBefore: value.NotBefore, NotAfter: value.NotAfter, StatusCode: 200}, err
}
func (a *g4b2ConvergenceAdapter) FinalizeDomainConvergenceCertificate(ctx context.Context, work controllers.DomainConvergenceWork, observation controllers.DomainConvergenceObservation) error {
	return a.store.FinalizeDomainConvergenceCertificate(ctx, work.ID, work.LeaseOwner, postgres.DomainConvergenceCertificateObservation{Fingerprint: observation.Fingerprint, Issuer: observation.Issuer, NotBefore: observation.NotBefore, NotAfter: observation.NotAfter}, a.now())
}
func (a *g4b2ConvergenceAdapter) InspectDomainConvergenceServingFact(ctx context.Context, work controllers.DomainConvergenceWork, fingerprint string) (string, error) {
	state, err := a.store.InspectDomainConvergenceServingFact(ctx, work.ID, work.LeaseOwner, fingerprint, a.now())
	return string(state), err
}
func (a *g4b2ConvergenceAdapter) MarkDomainConvergenceRecoveryRequired(ctx context.Context, work controllers.DomainConvergenceWork, code string) error {
	return a.store.MarkDomainConvergenceRecoveryRequired(ctx, work.ID, work.LeaseOwner, postgres.DomainConvergencePhase(work.Phase), code, a.now())
}

func (a *g4b2ConvergenceAdapter) LoadDomainConvergenceActivationRestore(ctx context.Context, work controllers.DomainConvergenceWork) (controllers.DomainConvergenceActivationRestore, error) {
	loaded, err := a.store.LoadDomainConvergenceActivationRestore(ctx, work.ID, work.LeaseOwner, a.now())
	if err != nil {
		return controllers.DomainConvergenceActivationRestore{}, err
	}
	routes, err := g4b2ControllerRoutes(loaded.Routes, work)
	if err != nil {
		return controllers.DomainConvergenceActivationRestore{}, err
	}
	return controllers.DomainConvergenceActivationRestore{ID: loaded.Request.ID, Phase: controllers.DomainConvergencePhase(loaded.Request.Phase), Owner: loaded.Request.LeaseOwner, Routes: routes, Digest: loaded.Digest, Count: loaded.Count}, nil
}

func (a *g4b2ConvergenceAdapter) RestoreDomainConvergenceActivation(ctx context.Context, work controllers.DomainConvergenceWork, restore controllers.DomainConvergenceActivationRestore) error {
	return a.store.RestoreDomainConvergenceActivation(ctx, work.ID, work.LeaseOwner, restore.Digest, restore.Count, a.now())
}

func (a *g4b2ConvergenceAdapter) LoadDomainUnbindWork(ctx context.Context, work controllers.DomainConvergenceWork) (controllers.DomainUnbindWork, error) {
	loaded, err := a.store.LoadDomainUnbindWork(ctx, work.ID, work.LeaseOwner, a.now())
	if err != nil {
		return controllers.DomainUnbindWork{}, err
	}
	remaining, err := g4b2ControllerRoutes(loaded.RemainingRoutes, work)
	if err != nil {
		return controllers.DomainUnbindWork{}, err
	}
	return controllers.DomainUnbindWork{
		ID:                   loaded.Request.ID,
		Restore:              loaded.Restore,
		ApplicationID:        loaded.Request.ApplicationID,
		DomainID:             loaded.Request.ApplicationDomainID,
		Hostname:             loaded.Request.Hostname,
		Phase:                controllers.DomainConvergencePhase(loaded.Request.Phase),
		LeaseOwner:           loaded.Request.LeaseOwner,
		RemainingRoutes:      remaining,
		RemainingRouteDigest: loaded.RemainingRouteDigest,
		RemainingRouteCount:  loaded.RemainingRouteCount,
	}, nil
}

func g4b2ControllerRoutes(projections []postgres.DesiredRouteProjection, work controllers.DomainConvergenceWork) ([]controllers.DomainConvergenceRoute, error) {
	routes := make([]controllers.DomainConvergenceRoute, 0, len(projections))
	for _, projection := range projections {
		if projection.Pointer == nil || projection.Lease == nil || projection.Pointer.DeploymentID != projection.Route.DeploymentID || projection.Lease.DeploymentID != projection.Route.DeploymentID || projection.Lease.ApplicationID != projection.Route.ApplicationID || projection.Lease.ServiceName != projection.Route.ServiceName || projection.Lease.BindHost != "127.0.0.1" || projection.Lease.Port < 1 || projection.Lease.Port > 65535 || !projection.Route.Verified {
			return nil, postgres.ErrDomainConvergenceConflict
		}
		if _, err := domain.NormalizeRouteHost(projection.Route.Host); err != nil {
			return nil, err
		}
		routes = append(routes, controllers.DomainConvergenceRoute{
			ID: projection.Route.ID,
			Request: contracts.RouteRequest{
				Route:     contracts.RouteSpec{Host: projection.Route.Host, Path: projection.Route.Path, DeploymentID: projection.Route.DeploymentID, ServiceName: projection.Route.ServiceName, Port: projection.Lease.Port, CertificateRef: projection.Route.CertificateRef, Verified: true},
				Operation: contracts.OperationContext{IdempotencyKey: work.ID.String(), Actor: work.LeaseOwner},
			},
		})
	}
	return routes, nil
}

func (a *g4b2ConvergenceAdapter) MarkDomainUnbindRouteRemoved(ctx context.Context, work controllers.DomainUnbindWork) error {
	return a.store.MarkDomainUnbindRouteRemoved(ctx, work.ID, work.LeaseOwner, work.RemainingRouteDigest, work.RemainingRouteCount, a.now())
}

func (a *g4b2ConvergenceAdapter) FinalizeDomainUnbind(ctx context.Context, work controllers.DomainUnbindWork) error {
	return a.store.FinalizeDomainUnbind(ctx, work.ID, work.LeaseOwner, a.now())
}
func (a *g4b2ConvergenceAdapter) RestoreDomainUnbind(ctx context.Context, work controllers.DomainUnbindWork) error {
	return a.store.RestoreDomainUnbind(ctx, work.ID, work.LeaseOwner, work.RemainingRouteDigest, work.RemainingRouteCount, a.now())
}

var _ controllers.DomainConvergenceStore = (*g4b2ConvergenceAdapter)(nil)

func newM3ProductionConvergence(store *postgres.Store, caddyConfig caddyprovider.Config, owner string) (*controllers.DomainConvergenceController, error) {
	if store == nil || owner == "" {
		return nil, domain.ValidationError("production domain convergence store and owner are required")
	}
	productionConfig, err := m3ProductionCaddyConfig(caddyConfig.AdminURL, caddyConfig.Listen)
	if err != nil {
		return nil, err
	}
	routes, err := caddyprovider.New(productionConfig)
	if err != nil {
		return nil, err
	}
	probe, err := edgeprobe.New(edgeprobe.Config{})
	if err != nil {
		return nil, err
	}
	return &controllers.DomainConvergenceController{Store: &g4b2ConvergenceAdapter{store: store}, Routes: routes, Probe: probe, Lease: 30 * time.Second}, nil
}

// m3ProductionCaddyConfig deliberately does not reuse the provider's generic
// defaults. Production convergence must receive its privilege boundaries from
// an explicit, validated server environment; a missing value must never become
// the provider's default Admin endpoint or public listener.
func m3ProductionCaddyConfig(adminURL, listen string) (caddyprovider.Config, error) {
	if adminURL != m3ProductionCaddyAdminURL {
		return caddyprovider.Config{}, domain.ValidationError("production Caddy admin URL must be exactly http://127.0.0.1:2019")
	}
	if listen != m3ProductionCaddyListen {
		return caddyprovider.Config{}, domain.ValidationError("production Caddy listener must be exactly 127.0.0.1:18481")
	}
	return caddyprovider.Config{
		AdminURL:  m3ProductionCaddyAdminURL,
		Listen:    m3ProductionCaddyListen,
		PlainHTTP: true,
	}, nil
}

// domainConvergenceLeaderLease is intentionally small so startup sequencing
// can be tested without a PostgreSQL server. The production implementation is
// postgres.DomainConvergenceLeaderLease, which keeps a dedicated session open.
type domainConvergenceLeaderLease interface {
	Release(context.Context) error
}

type domainConvergenceLeaderAcquire func(context.Context) (domainConvergenceLeaderLease, error)

func acquirePostgresDomainConvergenceLeader(store *postgres.Store) domainConvergenceLeaderAcquire {
	return func(ctx context.Context) (domainConvergenceLeaderLease, error) {
		return store.AcquireDomainConvergenceLeader(ctx)
	}
}

// startProductionDomainConvergence acquires the single-node leader lock
// before rebuilding durable routes or starting the scanner/reconciler. The
// caller owns lifecycle release so it can wait for every route-mutating worker
// before another process is allowed to acquire the PostgreSQL leader.
func startProductionDomainConvergence(ctx context.Context, acquire domainConvergenceLeaderAcquire, rebuild func(context.Context) error, start func()) (func(), error) {
	if ctx == nil || acquire == nil || rebuild == nil || start == nil {
		return nil, domain.ValidationError("production domain convergence startup dependencies are required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lease, err := acquire(ctx)
	if err != nil {
		return nil, err
	}
	if lease == nil {
		return nil, domain.NewError(domain.ErrConflict, "production domain convergence leader was not acquired")
	}
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := lease.Release(releaseCtx); err != nil {
				log.Printf("release domain convergence leader: %v", err)
			}
		})
	}
	if err := rebuild(ctx); err != nil {
		release()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		release()
		return nil, err
	}
	start()
	return release, nil
}

// routeMutationWorkerGroup prevents shutdown from releasing the cross-process
// leader while a local B2 or M4 route mutation is still in flight. Once stop
// begins it rejects new workers, then joins all registered workers.
type routeMutationWorkerGroup struct {
	mu      sync.Mutex
	closing bool
	workers sync.WaitGroup
}

func newRouteMutationWorkerGroup() *routeMutationWorkerGroup { return &routeMutationWorkerGroup{} }

func (g *routeMutationWorkerGroup) Go(ctx context.Context, run func()) bool {
	if g == nil || run == nil {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closing || (ctx != nil && ctx.Err() != nil) {
		return false
	}
	g.workers.Add(1)
	go func() {
		defer g.workers.Done()
		run()
	}()
	return true
}

func (g *routeMutationWorkerGroup) StopAndWait() {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.closing = true
	g.mu.Unlock()
	g.workers.Wait()
}

func releaseDomainConvergenceLeaderAfterRouteWorkers(ctx context.Context, workers *routeMutationWorkerGroup, release func()) {
	if ctx == nil || release == nil {
		return
	}
	go func() {
		<-ctx.Done()
		workers.StopAndWait()
		release()
	}()
}

type g4b2RouteProjectionStore interface {
	ListDesiredRoutes(context.Context) ([]postgres.DesiredRouteProjection, error)
}

func rebuildDomainConvergenceRoutes(ctx context.Context, store g4b2RouteProjectionStore, routes contracts.RouteProvider, owner string) error {
	if store == nil || routes == nil || owner == "" {
		return domain.ValidationError("domain convergence rebuild dependencies are required")
	}
	rebuilder, ok := routes.(contracts.RouteSetRebuilder)
	if !ok {
		return domain.NewError(domain.ErrUnsupportedCapability, "production route provider cannot rebuild a full durable route set")
	}
	items, err := store.ListDesiredRoutes(ctx)
	if err != nil {
		return err
	}
	requests := make([]contracts.RouteRequest, 0, len(items))
	for _, item := range items {
		if item.State != postgres.DesiredRouteActive {
			continue
		}
		if !item.Route.Verified || item.Pointer == nil || item.Lease == nil || item.Lease.ReleasedAt != nil || item.Pointer.DeploymentID != item.Route.DeploymentID || item.Lease.DeploymentID != item.Route.DeploymentID || item.Lease.ApplicationID != item.Route.ApplicationID || item.Lease.ServiceName != item.Route.ServiceName || item.Lease.BindHost != "127.0.0.1" || item.Lease.Port < 1 || item.Lease.Port > 65535 {
			return domain.NewError(domain.ErrConflict, "durable active route projection is incomplete")
		}
		if _, err := domain.NormalizeRouteHost(item.Route.Host); err != nil {
			return err
		}
		if _, err := postgres.NormalizeM3PathPrefix(item.Route.Path); err != nil {
			return err
		}
		requests = append(requests, contracts.RouteRequest{Route: contracts.RouteSpec{Host: item.Route.Host, Path: item.Route.Path, DeploymentID: item.Route.DeploymentID, ServiceName: item.Route.ServiceName, Port: item.Lease.Port, CertificateRef: item.Route.CertificateRef, Verified: true}, Operation: contracts.OperationContext{IdempotencyKey: "m3-startup-rebuild:" + item.Route.ID.String(), Actor: owner}})
	}
	_, err = rebuilder.RebuildRoutes(ctx, requests, contracts.OperationContext{IdempotencyKey: "m3-startup-rebuild", Actor: owner})
	return err
}

type domainConvergenceReconciler interface {
	ReconcileOnce(context.Context, string) (bool, error)
}

type domainConvergenceScanner interface {
	Scan(context.Context) error
}

// runDomainConvergenceCycle deliberately scans before it claims work. A scan
// error means the durable binding view is incomplete, so claiming an intent in
// that cycle could converge a stale route. The caller records the safe error
// and retries on the next tick.
func runDomainConvergenceCycle(ctx context.Context, reconciler domainConvergenceReconciler, scanner domainConvergenceScanner, owner string, timeout time.Duration) error {
	if reconciler == nil || owner == "" {
		return domain.ValidationError("domain convergence cycle dependencies are required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if scanner != nil {
		if err := scanner.Scan(ctx); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	call, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, err := reconciler.ReconcileOnce(call, owner)
	return err
}

func runDomainConvergenceWorker(ctx context.Context, controller domainConvergenceReconciler, scanner domainConvergenceScanner, owner string, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	if controller == nil || owner == "" {
		return
	}
	run := func() {
		if err := runDomainConvergenceCycle(ctx, controller, scanner, owner, minDomainConvergenceRunTimeout(interval)); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("domain convergence cycle failed: %v", err)
		}
	}
	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func minDomainConvergenceRunTimeout(interval time.Duration) time.Duration {
	if interval < 10*time.Second {
		return interval
	}
	return 10 * time.Second
}
