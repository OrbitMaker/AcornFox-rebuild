package controllers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/providers/edgeprobe"
)

type convergenceRouteFake struct {
	apply, observe, rebuild, remove int
	err, observeErr, rebuildErr     error
	observeFailures                 int
	rebuildRequests                 []contracts.RouteRequest
}

func (f *convergenceRouteFake) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{}
}
func (f *convergenceRouteFake) Apply(context.Context, contracts.RouteRequest) (domain.Route, contracts.Evidence, error) {
	f.apply++
	return domain.Route{}, contracts.Evidence{}, f.err
}
func (f *convergenceRouteFake) Observe(context.Context, contracts.RouteRequest) (domain.Observation, error) {
	f.observe++
	if f.observeFailures > 0 {
		f.observeFailures--
		return domain.Observation{}, f.observeErr
	}
	return domain.Observation{}, nil
}
func (f *convergenceRouteFake) Remove(context.Context, contracts.RouteRequest) error {
	f.remove++
	return nil
}
func (f *convergenceRouteFake) Rebuild(context.Context, contracts.OperationContext) (contracts.Evidence, error) {
	return contracts.Evidence{}, nil
}
func (f *convergenceRouteFake) RebuildRoutes(_ context.Context, requests []contracts.RouteRequest, _ contracts.OperationContext) (contracts.Evidence, error) {
	f.rebuild++
	f.rebuildRequests = append([]contracts.RouteRequest(nil), requests...)
	return contracts.Evidence{}, f.rebuildErr
}

type convergenceProbeFake struct {
	err    error
	calls  *int
	events *[]string
}

func (f convergenceProbeFake) Probe(context.Context, string) (edgeprobe.Observation, error) {
	if f.calls != nil {
		(*f.calls)++
	}
	if f.events != nil {
		*f.events = append(*f.events, "probe")
	}
	return edgeprobe.Observation{Hostname: "app.example.test", Fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", NotBefore: time.Unix(1, 0), NotAfter: time.Unix(2, 0)}, f.err
}

type convergenceStoreFake struct {
	work                                                  DomainConvergenceWork
	failed                                                bool
	failureCode                                           string
	active                                                bool
	finalized                                             bool
	recovered                                             bool
	allowErr                                              error
	activateErr                                           error
	allowCalls                                            int
	recordPhase                                           DomainConvergencePhase
	events                                                *[]string
	loadErr, inspectErr, recoveryErr, markRecoveryErr     error
	inspectState                                          string
	recoveryCalls                                         int
	recoveryPhase                                         DomainConvergencePhase
	recoveryCode                                          string
	unbindWork                                            DomainUnbindWork
	loadUnbindErr, markUnbindErr, finalizeUnbindErr       error
	loadUnbindCalls, markUnbindCalls, finalizeUnbindCalls int
	restoreUnbindCalls                                    int
	lastLoadUnbindPhase                                   DomainConvergencePhase
	activationRestore                                     DomainConvergenceActivationRestore
	activationRestoreLoadErr, activationRestoreErr        error
	activationRestoreLoads, activationRestoreCalls        int
}

func (s *convergenceStoreFake) ClaimDomainConvergence(_ context.Context, owner string, _ time.Duration) (DomainConvergenceWork, bool, error) {
	s.work.LeaseOwner = owner
	return s.work, true, nil
}
func (s *convergenceStoreFake) PrepareDomainConvergenceRoute(_ context.Context, work DomainConvergenceWork) (DomainConvergenceWork, error) {
	work.Phase = ConvergenceRoutePrepared
	s.work = work
	return work, nil
}
func (s *convergenceStoreFake) ActivateDomainConvergenceRoute(_ context.Context, work DomainConvergenceWork) error {
	if s.activateErr != nil {
		return s.activateErr
	}
	s.active = true
	s.work.Phase = ConvergenceInternalRouteActive
	if s.events != nil {
		*s.events = append(*s.events, "activate")
	}
	return nil
}
func (s *convergenceStoreFake) AllowDomainConvergenceTLS(_ context.Context, work DomainConvergenceWork) error {
	s.allowCalls++
	if s.events != nil {
		*s.events = append(*s.events, "allow_tls")
	}
	if s.allowErr != nil {
		return s.allowErr
	}
	s.work.Phase = ConvergenceTLSAllowed
	return nil
}
func (s *convergenceStoreFake) RecordDomainConvergenceProbe(_ context.Context, work DomainConvergenceWork, _ edgeprobe.Observation) error {
	s.finalized = true
	s.recordPhase = work.Phase
	s.work.Phase = ConvergenceServing
	if s.events != nil {
		*s.events = append(*s.events, "record_probe")
	}
	return nil
}
func (s *convergenceStoreFake) FailDomainConvergence(_ context.Context, _ DomainConvergenceWork, code string, _ error) error {
	s.failed = true
	s.failureCode = code
	return nil
}

func (s *convergenceStoreFake) RecoverDomainConvergenceCompleted(_ context.Context, _ DomainConvergenceWork) (bool, error) {
	s.recovered = true
	return true, s.recoveryErr
}
func (s *convergenceStoreFake) LoadDomainConvergenceCertificateObservation(context.Context, DomainConvergenceWork) (DomainConvergenceObservation, error) {
	return DomainConvergenceObservation{Fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Issuer: "test", NotBefore: time.Unix(1, 0), NotAfter: time.Unix(2, 0), StatusCode: 200}, s.loadErr
}
func (s *convergenceStoreFake) FinalizeDomainConvergenceCertificate(_ context.Context, _ DomainConvergenceWork, _ DomainConvergenceObservation) error {
	s.finalized = true
	return nil
}
func (s *convergenceStoreFake) InspectDomainConvergenceServingFact(context.Context, DomainConvergenceWork, string) (string, error) {
	if s.inspectState == "" {
		s.inspectState = "not_serving"
	}
	return s.inspectState, s.inspectErr
}
func (s *convergenceStoreFake) MarkDomainConvergenceRecoveryRequired(_ context.Context, work DomainConvergenceWork, code string) error {
	s.failed = true
	s.recoveryCalls++
	s.recoveryPhase = work.Phase
	s.recoveryCode = code
	return s.markRecoveryErr
}
func (s *convergenceStoreFake) LoadDomainConvergenceActivationRestore(_ context.Context, _ DomainConvergenceWork) (DomainConvergenceActivationRestore, error) {
	s.activationRestoreLoads++
	return s.activationRestore, s.activationRestoreLoadErr
}
func (s *convergenceStoreFake) RestoreDomainConvergenceActivation(_ context.Context, _ DomainConvergenceWork, _ DomainConvergenceActivationRestore) error {
	s.activationRestoreCalls++
	return s.activationRestoreErr
}
func (s *convergenceStoreFake) LoadDomainUnbindWork(_ context.Context, work DomainConvergenceWork) (DomainUnbindWork, error) {
	s.loadUnbindCalls++
	s.lastLoadUnbindPhase = work.Phase
	return s.unbindWork, s.loadUnbindErr
}
func (s *convergenceStoreFake) MarkDomainUnbindRouteRemoved(_ context.Context, work DomainUnbindWork) error {
	s.markUnbindCalls++
	if s.markUnbindErr != nil {
		return s.markUnbindErr
	}
	s.work.Phase = ConvergenceUnbindRouteRemoved
	return nil
}
func (s *convergenceStoreFake) FinalizeDomainUnbind(_ context.Context, _ DomainUnbindWork) error {
	s.finalizeUnbindCalls++
	if s.finalizeUnbindErr != nil {
		return s.finalizeUnbindErr
	}
	s.work.Phase = ConvergenceCompleted
	return nil
}
func (s *convergenceStoreFake) RestoreDomainUnbind(_ context.Context, _ DomainUnbindWork) error {
	s.restoreUnbindCalls++
	return nil
}

func unbindConvergenceWork(phase DomainConvergencePhase) DomainConvergenceWork {
	return DomainConvergenceWork{ID: "unbind_request_1", ApplicationID: "app_1", DomainID: "domain_1", Hostname: "custom.example.test", Kind: "unbind", Phase: phase}
}

func unbindRoute(id, host string) DomainConvergenceRoute {
	return DomainConvergenceRoute{ID: domain.ID(id), Request: contracts.RouteRequest{Route: contracts.RouteSpec{Host: host, Path: "/", DeploymentID: "deployment_1", ServiceName: "web", Port: 18080, Verified: true}}}
}

func TestG4B2UnbindRebuildsFrozenFullSetThenMarksAndFinalizes(t *testing.T) {
	store := &convergenceStoreFake{work: unbindConvergenceWork(ConvergenceQueued)}
	store.unbindWork = DomainUnbindWork{ID: store.work.ID, ApplicationID: store.work.ApplicationID, DomainID: store.work.DomainID, Hostname: store.work.Hostname, Phase: ConvergenceQueued, LeaseOwner: "worker-1", RemainingRouteDigest: "sha256:remaining", RemainingRouteCount: 2, RemainingRoutes: []DomainConvergenceRoute{unbindRoute("route_2", "second.example.test"), unbindRoute("route_3", "third.example.test")}}
	routes := &convergenceRouteFake{}
	probes := 0
	claimed, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{calls: &probes}}).ReconcileOnce(context.Background(), "worker-1")
	if err != nil || !claimed || store.loadUnbindCalls != 1 || store.markUnbindCalls != 1 || store.finalizeUnbindCalls != 1 || routes.rebuild != 1 || len(routes.rebuildRequests) != 2 || routes.apply != 0 || routes.observe != 0 || routes.remove != 0 || probes != 0 {
		t.Fatalf("claimed=%v err=%v load=%d mark=%d finalize=%d rebuild=%d routes=%d apply=%d observe=%d remove=%d probe=%d", claimed, err, store.loadUnbindCalls, store.markUnbindCalls, store.finalizeUnbindCalls, routes.rebuild, len(routes.rebuildRequests), routes.apply, routes.observe, routes.remove, probes)
	}
}

func TestG4B2UnbindCaddyFailureLeavesDurableFactsForNormalRetry(t *testing.T) {
	store := &convergenceStoreFake{work: unbindConvergenceWork(ConvergenceQueued)}
	store.unbindWork = DomainUnbindWork{ID: store.work.ID, ApplicationID: store.work.ApplicationID, DomainID: store.work.DomainID, Hostname: store.work.Hostname, Phase: ConvergenceQueued, LeaseOwner: "worker-1", RemainingRouteDigest: "sha256:remaining", RemainingRouteCount: 1, RemainingRoutes: []DomainConvergenceRoute{unbindRoute("route_2", "second.example.test")}}
	routes := &convergenceRouteFake{rebuildErr: errors.New("caddy unavailable")}
	probes := 0
	_, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{calls: &probes}}).ReconcileOnce(context.Background(), "worker-1")
	if err == nil || !store.failed || store.markUnbindCalls != 0 || store.finalizeUnbindCalls != 0 || routes.rebuild != 1 || routes.remove != 0 || routes.apply != 0 || routes.observe != 0 || probes != 0 {
		t.Fatalf("err=%v failed=%v mark=%d finalize=%d rebuild=%d remove=%d apply=%d observe=%d probe=%d", err, store.failed, store.markUnbindCalls, store.finalizeUnbindCalls, routes.rebuild, routes.remove, routes.apply, routes.observe, probes)
	}
}

func TestG4B2UnbindOutcomeUnknownRequiresDurableRestore(t *testing.T) {
	store := &convergenceStoreFake{work: unbindConvergenceWork(ConvergenceQueued)}
	store.unbindWork = DomainUnbindWork{ID: store.work.ID, ApplicationID: store.work.ApplicationID, DomainID: store.work.DomainID, Hostname: store.work.Hostname, Phase: ConvergenceQueued, LeaseOwner: "worker-1", RemainingRouteDigest: "sha256:remaining", RemainingRouteCount: 1, RemainingRoutes: []DomainConvergenceRoute{unbindRoute("route_2", "second.example.test")}}
	routes := &convergenceRouteFake{rebuildErr: contracts.ProviderOutcomeUnknown(errors.New("Caddy /load response lost"))}
	_, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{}}).ReconcileOnce(context.Background(), "worker-1")
	if err != nil || store.recoveryCalls != 1 || store.recoveryPhase != ConvergenceQueued || store.recoveryCode != "unbind_restore_required" || store.failureCode != "" || routes.rebuild != 1 {
		t.Fatalf("err=%v recovery=%d/%s/%s failure=%q rebuild=%d", err, store.recoveryCalls, store.recoveryPhase, store.recoveryCode, store.failureCode, routes.rebuild)
	}
}

func TestG4B2UnbindReplaysFullSetAfterCrashBeforeMark(t *testing.T) {
	store := &convergenceStoreFake{work: unbindConvergenceWork(ConvergenceQueued), markUnbindErr: errors.New("lost after rebuild")}
	store.unbindWork = DomainUnbindWork{ID: store.work.ID, ApplicationID: store.work.ApplicationID, DomainID: store.work.DomainID, Hostname: store.work.Hostname, Phase: ConvergenceQueued, LeaseOwner: "worker-1", RemainingRouteDigest: "sha256:remaining", RemainingRouteCount: 1, RemainingRoutes: []DomainConvergenceRoute{unbindRoute("route_2", "second.example.test")}}
	routes := &convergenceRouteFake{}
	controller := &DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{}}
	if _, err := controller.ReconcileOnce(context.Background(), "worker-1"); err != nil || store.recoveryCalls != 1 || routes.rebuild != 1 || store.finalizeUnbindCalls != 0 {
		t.Fatalf("first err=%v recovery=%d rebuild=%d finalize=%d", err, store.recoveryCalls, routes.rebuild, store.finalizeUnbindCalls)
	}
	store.markUnbindErr = nil
	store.recoveryCalls = 0
	store.work.Phase = ConvergenceRecoveryRequired
	store.unbindWork.Phase = ConvergenceRecoveryRequired
	if _, err := controller.ReconcileOnce(context.Background(), "worker-1"); err != nil || routes.rebuild != 2 || store.markUnbindCalls != 2 || store.finalizeUnbindCalls != 1 || store.recoveryCalls != 0 {
		t.Fatalf("replay err=%v rebuild=%d mark=%d finalize=%d recovery=%d", err, routes.rebuild, store.markUnbindCalls, store.finalizeUnbindCalls, store.recoveryCalls)
	}
}

func TestG4B2UnbindRouteRemovedRebuildsFrozenSetThenFinalizes(t *testing.T) {
	store := &convergenceStoreFake{work: unbindConvergenceWork(ConvergenceUnbindRouteRemoved)}
	store.unbindWork = DomainUnbindWork{ID: store.work.ID, ApplicationID: store.work.ApplicationID, DomainID: store.work.DomainID, Hostname: store.work.Hostname, Phase: ConvergenceUnbindRouteRemoved, LeaseOwner: "worker-1", RemainingRouteDigest: "sha256:remaining", RemainingRouteCount: 1, RemainingRoutes: []DomainConvergenceRoute{unbindRoute("route_remaining", "remaining.example.test")}}
	routes := &convergenceRouteFake{}
	probes := 0
	_, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{calls: &probes}}).ReconcileOnce(context.Background(), "worker-1")
	if err != nil || store.loadUnbindCalls != 1 || store.lastLoadUnbindPhase != ConvergenceUnbindRouteRemoved || store.markUnbindCalls != 0 || store.finalizeUnbindCalls != 1 || routes.rebuild != 1 || len(routes.rebuildRequests) != 1 || routes.remove != 0 || routes.apply != 0 || routes.observe != 0 || probes != 0 {
		t.Fatalf("err=%v load=%d mark=%d final=%d rebuild=%d remove=%d apply=%d observe=%d probe=%d", err, store.loadUnbindCalls, store.markUnbindCalls, store.finalizeUnbindCalls, routes.rebuild, routes.remove, routes.apply, routes.observe, probes)
	}
}

func TestG4B2UnbindRestoreRebuildsCurrentFactsThenTerminalizesIntent(t *testing.T) {
	store := &convergenceStoreFake{work: unbindConvergenceWork(ConvergenceQueued)}
	store.unbindWork = DomainUnbindWork{ID: store.work.ID, ApplicationID: store.work.ApplicationID, DomainID: store.work.DomainID, Hostname: store.work.Hostname, Phase: ConvergenceQueued, LeaseOwner: "worker-1", Restore: true, RemainingRouteDigest: "sha256:current", RemainingRouteCount: 1, RemainingRoutes: []DomainConvergenceRoute{unbindRoute("route_current", "198.51.100.10")}}
	routes := &convergenceRouteFake{}
	_, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{}}).ReconcileOnce(context.Background(), "worker-1")
	if err != nil || routes.rebuild != 1 || store.restoreUnbindCalls != 1 || store.markUnbindCalls != 0 || store.finalizeUnbindCalls != 0 {
		t.Fatalf("err=%v rebuild=%d restore=%d mark=%d finalize=%d", err, routes.rebuild, store.restoreUnbindCalls, store.markUnbindCalls, store.finalizeUnbindCalls)
	}
}

func TestG4B2UnbindRouteRemovedRestoreKeepsPhaseAndRebuildsCurrentFacts(t *testing.T) {
	store := &convergenceStoreFake{work: DomainConvergenceWork{ID: "unbind_request_1", ApplicationID: "app_1", DomainID: "domain_1", Hostname: "custom.example.test", Kind: "unbind", Restore: true, Phase: ConvergenceUnbindRouteRemoved}}
	store.unbindWork = DomainUnbindWork{ID: store.work.ID, Restore: true, ApplicationID: store.work.ApplicationID, DomainID: store.work.DomainID, Hostname: store.work.Hostname, Phase: ConvergenceUnbindRouteRemoved, LeaseOwner: "worker-1", RemainingRouteDigest: "sha256:current", RemainingRouteCount: 1, RemainingRoutes: []DomainConvergenceRoute{unbindRoute("route_current", "current.example.test")}}
	routes := &convergenceRouteFake{}
	_, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{}}).ReconcileOnce(context.Background(), "worker-1")
	if err != nil || store.lastLoadUnbindPhase != ConvergenceUnbindRouteRemoved || routes.rebuild != 1 || store.restoreUnbindCalls != 1 || store.markUnbindCalls != 0 || store.finalizeUnbindCalls != 0 {
		t.Fatalf("err=%v phase=%s rebuild=%d restore=%d mark=%d finalize=%d", err, store.lastLoadUnbindPhase, routes.rebuild, store.restoreUnbindCalls, store.markUnbindCalls, store.finalizeUnbindCalls)
	}
}

func TestG4B2UnbindFinalizeConflictMarksRecoveryWithoutExternalCalls(t *testing.T) {
	store := &convergenceStoreFake{work: unbindConvergenceWork(ConvergenceUnbindRouteRemoved), finalizeUnbindErr: errors.New("target drift")}
	store.unbindWork = DomainUnbindWork{ID: store.work.ID, ApplicationID: store.work.ApplicationID, DomainID: store.work.DomainID, Hostname: store.work.Hostname, Phase: ConvergenceUnbindRouteRemoved, LeaseOwner: "worker-1", RemainingRouteDigest: "sha256:remaining", RemainingRouteCount: 1, RemainingRoutes: []DomainConvergenceRoute{unbindRoute("route_remaining", "remaining.example.test")}}
	routes := &convergenceRouteFake{}
	probes := 0
	_, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{calls: &probes}}).ReconcileOnce(context.Background(), "worker-1")
	if err != nil || store.recoveryCalls != 1 || store.recoveryPhase != ConvergenceUnbindRouteRemoved || store.recoveryCode != "unbind_restore_required" || routes.rebuild != 1 || routes.remove != 0 || routes.apply != 0 || routes.observe != 0 || probes != 0 {
		t.Fatalf("err=%v recovery=%d phase=%s code=%s rebuild=%d remove=%d apply=%d observe=%d probe=%d", err, store.recoveryCalls, store.recoveryPhase, store.recoveryCode, routes.rebuild, routes.remove, routes.apply, routes.observe, probes)
	}
}

func TestG4B2UnbindStaleOwnerConflictDoesNotAdvanceOrCallExternalProvider(t *testing.T) {
	store := &convergenceStoreFake{work: unbindConvergenceWork(ConvergenceUnbindRouteRemoved), finalizeUnbindErr: errors.New("stale lease"), markRecoveryErr: errors.New("lease owner changed")}
	store.unbindWork = DomainUnbindWork{ID: store.work.ID, ApplicationID: store.work.ApplicationID, DomainID: store.work.DomainID, Hostname: store.work.Hostname, Phase: ConvergenceUnbindRouteRemoved, LeaseOwner: "worker-1", RemainingRouteDigest: "sha256:remaining", RemainingRouteCount: 1, RemainingRoutes: []DomainConvergenceRoute{unbindRoute("route_remaining", "remaining.example.test")}}
	routes := &convergenceRouteFake{}
	probes := 0
	_, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{calls: &probes}}).ReconcileOnce(context.Background(), "worker-1")
	if err == nil || store.recoveryCalls != 1 || store.finalizeUnbindCalls != 1 || store.work.Phase != ConvergenceUnbindRouteRemoved || routes.rebuild != 1 || routes.remove != 0 || routes.apply != 0 || routes.observe != 0 || probes != 0 {
		t.Fatalf("err=%v recovery=%d final=%d phase=%s rebuild=%d remove=%d apply=%d observe=%d probe=%d", err, store.recoveryCalls, store.finalizeUnbindCalls, store.work.Phase, routes.rebuild, routes.remove, routes.apply, routes.observe, probes)
	}
}

func TestG4B2UnbindCompletedIsNoop(t *testing.T) {
	store := &convergenceStoreFake{work: unbindConvergenceWork(ConvergenceCompleted)}
	routes := &convergenceRouteFake{}
	probes := 0
	_, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{calls: &probes}}).ReconcileOnce(context.Background(), "worker-1")
	if err != nil || store.loadUnbindCalls != 0 || store.markUnbindCalls != 0 || store.finalizeUnbindCalls != 0 || routes.rebuild != 0 || routes.remove != 0 || routes.apply != 0 || routes.observe != 0 || probes != 0 {
		t.Fatalf("err=%v load=%d mark=%d final=%d rebuild=%d remove=%d apply=%d observe=%d probe=%d", err, store.loadUnbindCalls, store.markUnbindCalls, store.finalizeUnbindCalls, routes.rebuild, routes.remove, routes.apply, routes.observe, probes)
	}
}

func TestDomainConvergenceMovesExternalCallsOutsideDurablePhases(t *testing.T) {
	events := make([]string, 0, 4)
	store := &convergenceStoreFake{events: &events, work: DomainConvergenceWork{ID: "request_1", ApplicationID: "app_1", DomainID: "domain_1", Hostname: "app.example.test", Phase: ConvergenceQueued, RouteID: "route_1", Route: contracts.RouteRequest{Route: contracts.RouteSpec{Host: "app.example.test", Path: "/", DeploymentID: "dep_1", ServiceName: "web", Port: 18080, Verified: true}, Operation: contracts.OperationContext{IdempotencyKey: "request_1"}}}}
	routes := &convergenceRouteFake{observeErr: errors.New("route absent"), observeFailures: 1}
	controller := &DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{events: &events}}
	if claimed, err := controller.ReconcileOnce(context.Background(), "worker-1"); err != nil || !claimed || !store.active || store.allowCalls != 1 || !store.finalized || store.recordPhase != ConvergenceTLSAllowed || routes.apply != 1 || routes.observe != 2 || store.failed {
		t.Fatalf("claimed=%v err=%v active=%v allow=%d finalized=%v record_phase=%s apply=%d observe=%d failed=%v", claimed, err, store.active, store.allowCalls, store.finalized, store.recordPhase, routes.apply, routes.observe, store.failed)
	}
	want := []string{"activate", "allow_tls", "probe", "record_probe"}
	if len(events) != len(want) {
		t.Fatalf("events=%v want=%v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("events=%v want=%v", events, want)
		}
	}
}

func TestG4B2InternalRouteActiveRecoversTLSAllowBeforeProbe(t *testing.T) {
	events := make([]string, 0, 3)
	store := &convergenceStoreFake{events: &events, work: DomainConvergenceWork{ID: "request_1", ApplicationID: "app_1", DomainID: "domain_1", Hostname: "app.example.test", Phase: ConvergenceInternalRouteActive, RouteID: "route_1"}}
	routes := &convergenceRouteFake{}
	probes := 0
	claimed, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{calls: &probes, events: &events}}).ReconcileOnce(context.Background(), "worker-1")
	if err != nil || !claimed || store.allowCalls != 1 || probes != 1 || !store.finalized || store.recordPhase != ConvergenceTLSAllowed || routes.apply != 0 || routes.observe != 0 {
		t.Fatalf("claimed=%v err=%v allow=%d probe=%d finalized=%v record_phase=%s apply=%d observe=%d", claimed, err, store.allowCalls, probes, store.finalized, store.recordPhase, routes.apply, routes.observe)
	}
	want := []string{"allow_tls", "probe", "record_probe"}
	for i := range want {
		if len(events) != len(want) || events[i] != want[i] {
			t.Fatalf("events=%v want=%v", events, want)
		}
	}
}

func TestG4B2TLSAllowedRecoveryProbesWithoutReallowing(t *testing.T) {
	store := &convergenceStoreFake{work: DomainConvergenceWork{ID: "request_1", ApplicationID: "app_1", DomainID: "domain_1", Hostname: "app.example.test", Phase: ConvergenceTLSAllowed, RouteID: "route_1"}}
	routes := &convergenceRouteFake{}
	probes := 0
	claimed, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{calls: &probes}}).ReconcileOnce(context.Background(), "worker-1")
	if err != nil || !claimed || store.allowCalls != 0 || probes != 1 || !store.finalized || store.recordPhase != ConvergenceTLSAllowed || routes.apply != 0 || routes.observe != 0 {
		t.Fatalf("claimed=%v err=%v allow=%d probe=%d finalized=%v record_phase=%s apply=%d observe=%d", claimed, err, store.allowCalls, probes, store.finalized, store.recordPhase, routes.apply, routes.observe)
	}
}

func TestG4B2TLSAllowConflictStopsBeforeProbe(t *testing.T) {
	store := &convergenceStoreFake{allowErr: errors.New("stale lease"), work: DomainConvergenceWork{ID: "request_1", ApplicationID: "app_1", DomainID: "domain_1", Hostname: "app.example.test", Phase: ConvergenceInternalRouteActive, RouteID: "route_1"}}
	routes := &convergenceRouteFake{}
	probes := 0
	claimed, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{calls: &probes}}).ReconcileOnce(context.Background(), "worker-1")
	if err == nil || !claimed || store.allowCalls != 1 || probes != 0 || store.finalized || !store.failed || store.failureCode != convergenceTLSFailed || routes.apply != 0 || routes.observe != 0 {
		t.Fatalf("claimed=%v err=%v allow=%d probe=%d finalized=%v failed=%v apply=%d observe=%d", claimed, err, store.allowCalls, probes, store.finalized, store.failed, routes.apply, routes.observe)
	}
}

func TestDomainConvergenceFailureDoesNotClaimServing(t *testing.T) {
	store := &convergenceStoreFake{work: DomainConvergenceWork{ID: "request_1", ApplicationID: "app_1", DomainID: "domain_1", Hostname: "app.example.test", Phase: ConvergenceRoutePrepared, RouteID: "route_1", Route: contracts.RouteRequest{Route: contracts.RouteSpec{Host: "app.example.test", Path: "/", DeploymentID: "dep_1", ServiceName: "web", Port: 18080, Verified: true}, Operation: contracts.OperationContext{IdempotencyKey: "request_1"}}}}
	controller := &DomainConvergenceController{Store: store, Routes: &convergenceRouteFake{err: errors.New("apply failed"), observeErr: errors.New("not observed"), observeFailures: 1}, Probe: convergenceProbeFake{}}
	if _, err := controller.ReconcileOnce(context.Background(), "worker-1"); err == nil || !store.failed || store.failureCode != convergenceApplyFailed || store.finalized {
		t.Fatalf("err=%v failed=%v code=%s finalized=%v", err, store.failed, store.failureCode, store.finalized)
	}
}

func TestDomainConvergenceApplyOutcomeUnknownRequiresActivationRestore(t *testing.T) {
	store := &convergenceStoreFake{work: DomainConvergenceWork{ID: "request_unknown_apply", ApplicationID: "app_1", DomainID: "domain_1", Hostname: "app.example.test", Phase: ConvergenceRoutePrepared, RouteID: "route_1", Route: contracts.RouteRequest{Route: contracts.RouteSpec{Host: "app.example.test", Path: "/", DeploymentID: "dep_1", ServiceName: "web", Port: 18080, Verified: true}, Operation: contracts.OperationContext{IdempotencyKey: "request_unknown_apply"}}}}
	routes := &convergenceRouteFake{err: contracts.ProviderOutcomeUnknown(errors.New("Caddy /load response lost")), observeErr: errors.New("route absent"), observeFailures: 1}
	claimed, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{}}).ReconcileOnce(context.Background(), "worker-1")
	if err != nil || !claimed || store.recoveryCalls != 1 || store.recoveryCode != "route_activation_restore_required" || store.failureCode != "" || routes.apply != 1 || routes.observe != 1 {
		t.Fatalf("claimed=%v err=%v recovery=%d/%s failure=%q apply=%d observe=%d", claimed, err, store.recoveryCalls, store.recoveryCode, store.failureCode, routes.apply, routes.observe)
	}
}

func TestDomainConvergenceActivationCASFailureRequiresDurableRouteRestore(t *testing.T) {
	store := &convergenceStoreFake{activateErr: errors.New("activation CAS conflict"), work: DomainConvergenceWork{ID: "request_1", ApplicationID: "app_1", DomainID: "domain_1", Hostname: "app.example.test", Phase: ConvergenceRoutePrepared, RouteID: "route_1", Route: contracts.RouteRequest{Route: contracts.RouteSpec{Host: "app.example.test", Path: "/", DeploymentID: "dep_1", ServiceName: "web", Port: 18080, Verified: true}, Operation: contracts.OperationContext{IdempotencyKey: "request_1"}}}}
	routes := &convergenceRouteFake{}
	claimed, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{}}).ReconcileOnce(context.Background(), "worker-1")
	if err != nil || !claimed || store.recoveryCalls != 1 || store.recoveryPhase != ConvergenceRoutePrepared || store.recoveryCode != "route_activation_restore_required" || store.failed && store.failureCode != "" || routes.observe != 1 || routes.apply != 0 || routes.rebuild != 0 || store.allowCalls != 0 {
		t.Fatalf("claimed=%v err=%v recovery=%d/%s/%s failed=%v code=%s observe=%d apply=%d rebuild=%d allow=%d", claimed, err, store.recoveryCalls, store.recoveryPhase, store.recoveryCode, store.failed, store.failureCode, routes.observe, routes.apply, routes.rebuild, store.allowCalls)
	}
}

func TestDomainConvergenceActivationRestoreRebuildsBeforeAnyCandidateCall(t *testing.T) {
	work := DomainConvergenceWork{ID: "request_restore", ApplicationID: "app_1", DomainID: "domain_1", Hostname: "app.example.test", Restore: true, Phase: ConvergenceRoutePrepared}
	store := &convergenceStoreFake{work: work, activationRestore: DomainConvergenceActivationRestore{ID: work.ID, Phase: work.Phase, Owner: "worker-1", Digest: "sha256:current", Count: 1, Routes: []DomainConvergenceRoute{unbindRoute("route_current", "198.51.100.10")}}}
	routes := &convergenceRouteFake{}
	claimed, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{}}).ReconcileOnce(context.Background(), "worker-1")
	if err != nil || !claimed || store.activationRestoreLoads != 1 || store.activationRestoreCalls != 1 || routes.rebuild != 1 || routes.observe != 0 || routes.apply != 0 || store.allowCalls != 0 || store.recoveryCalls != 0 {
		t.Fatalf("claimed=%v err=%v load=%d restore=%d rebuild=%d observe=%d apply=%d allow=%d recovery=%d", claimed, err, store.activationRestoreLoads, store.activationRestoreCalls, routes.rebuild, routes.observe, routes.apply, store.allowCalls, store.recoveryCalls)
	}
}

func TestDomainConvergenceActivationRestoreFailureStaysRecoverable(t *testing.T) {
	work := DomainConvergenceWork{ID: "request_restore", ApplicationID: "app_1", DomainID: "domain_1", Hostname: "app.example.test", Restore: true, Phase: ConvergenceRoutePrepared}
	store := &convergenceStoreFake{work: work, activationRestore: DomainConvergenceActivationRestore{ID: work.ID, Phase: work.Phase, Owner: "worker-1", Digest: "sha256:current", Count: 1, Routes: []DomainConvergenceRoute{unbindRoute("route_current", "current.example.test")}}, activationRestoreErr: errors.New("restore CAS drift")}
	routes := &convergenceRouteFake{}
	claimed, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{}}).ReconcileOnce(context.Background(), "worker-1")
	if err != nil || !claimed || store.activationRestoreCalls != 1 || store.recoveryCalls != 1 || store.recoveryPhase != ConvergenceRoutePrepared || store.recoveryCode != "route_activation_restore_required" || routes.rebuild != 1 || routes.observe != 0 || routes.apply != 0 {
		t.Fatalf("claimed=%v err=%v restore=%d recovery=%d/%s/%s rebuild=%d observe=%d apply=%d", claimed, err, store.activationRestoreCalls, store.recoveryCalls, store.recoveryPhase, store.recoveryCode, routes.rebuild, routes.observe, routes.apply)
	}
}

func TestDomainConvergenceProbeFailurePersistsOnlySafeCode(t *testing.T) {
	store := &convergenceStoreFake{work: DomainConvergenceWork{ID: "request_1", ApplicationID: "app_1", DomainID: "domain_1", Hostname: "app.example.test", Phase: ConvergenceTLSAllowed, RouteID: "route_1"}}
	cause := errors.New("probe https://user:secret@example.test/path failed")
	_, err := (&DomainConvergenceController{Store: store, Routes: &convergenceRouteFake{}, Probe: convergenceProbeFake{err: cause}}).ReconcileOnce(context.Background(), "worker-1")
	if !errors.Is(err, cause) || !store.failed || store.failureCode != convergenceProbeFailed {
		t.Fatalf("err=%v failed=%v code=%q", err, store.failed, store.failureCode)
	}
}

func TestG4B2CertificateObservedBadStoredObservationMarksRecoveryRequiredWithoutProbe(t *testing.T) {
	store := &convergenceStoreFake{work: DomainConvergenceWork{ID: "request_1", ApplicationID: "app_1", DomainID: "domain_1", Hostname: "app.example.test", Phase: ConvergenceCertificateObserved, RouteID: "route_1"}, loadErr: errors.New("stored observation invalid")}
	routes := &convergenceRouteFake{}
	probes := 0
	controller := &DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{calls: &probes}}
	if _, err := controller.ReconcileOnce(context.Background(), "worker-1"); err != nil || store.recoveryCalls != 1 || store.recoveryPhase != ConvergenceCertificateObserved || store.recoveryCode != "observation_invalid" || probes != 0 || routes.apply != 0 || routes.observe != 0 || store.finalized || store.recovered {
		t.Fatalf("err=%v recovery=%d phase=%s code=%s probe=%d apply=%d observe=%d finalized=%v recovered=%v", err, store.recoveryCalls, store.recoveryPhase, store.recoveryCode, probes, routes.apply, routes.observe, store.finalized, store.recovered)
	}
}

func TestG4B2CertificateObservedMatchingServingOnlyAcksWithoutProbe(t *testing.T) {
	store := &convergenceStoreFake{work: DomainConvergenceWork{ID: "request_1", ApplicationID: "app_1", DomainID: "domain_1", Hostname: "app.example.test", Phase: ConvergenceCertificateObserved, RouteID: "route_1"}, inspectState: "matching_serving"}
	routes := &convergenceRouteFake{}
	probes := 0
	_, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{calls: &probes}}).ReconcileOnce(context.Background(), "worker-1")
	if err != nil || !store.recovered || store.recoveryCalls != 0 || store.finalized || probes != 0 || routes.apply != 0 || routes.observe != 0 {
		t.Fatalf("err=%v recovered=%v recovery=%d finalized=%v probe=%d apply=%d observe=%d", err, store.recovered, store.recoveryCalls, store.finalized, probes, routes.apply, routes.observe)
	}
}

func TestG4B2CertificateObservedPartialServingMarksRecoveryWithoutProbe(t *testing.T) {
	store := &convergenceStoreFake{work: DomainConvergenceWork{ID: "request_1", ApplicationID: "app_1", DomainID: "domain_1", Hostname: "app.example.test", Phase: ConvergenceCertificateObserved, RouteID: "route_1"}, inspectErr: errors.New("partial")}
	routes := &convergenceRouteFake{}
	probes := 0
	_, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{calls: &probes}}).ReconcileOnce(context.Background(), "worker-1")
	if err != nil || store.recoveryCalls != 1 || store.recoveryCode != "serving_fact_mismatch" || store.finalized || store.recovered || probes != 0 || routes.apply != 0 || routes.observe != 0 {
		t.Fatalf("err=%v recovery=%d code=%s final=%v recovered=%v probe=%d", err, store.recoveryCalls, store.recoveryCode, store.finalized, store.recovered, probes)
	}
}

func TestG4B2CertificateObservedNotServingFinalizesStoredObservationWithoutProbe(t *testing.T) {
	store := &convergenceStoreFake{work: DomainConvergenceWork{ID: "request_1", ApplicationID: "app_1", DomainID: "domain_1", Hostname: "app.example.test", Phase: ConvergenceCertificateObserved, RouteID: "route_1"}}
	routes := &convergenceRouteFake{}
	probes := 0
	_, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{calls: &probes}}).ReconcileOnce(context.Background(), "worker-1")
	if err != nil || !store.finalized || !store.recovered || probes != 0 || routes.apply != 0 || routes.observe != 0 {
		t.Fatalf("err=%v finalized=%v recovered=%v probe=%d apply=%d observe=%d", err, store.finalized, store.recovered, probes, routes.apply, routes.observe)
	}
}

func TestG4B2CertificateObservedRenewalPendingFinalizesWithoutCaddyReplay(t *testing.T) {
	store := &convergenceStoreFake{work: DomainConvergenceWork{ID: "request_renewal_1", ApplicationID: "app_1", DomainID: "domain_1", Hostname: "app.example.test", Phase: ConvergenceCertificateObserved, RouteID: "route_1"}, inspectState: "renewal_pending"}
	routes := &convergenceRouteFake{}
	probes := 0
	_, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{calls: &probes}}).ReconcileOnce(context.Background(), "worker-1")
	if err != nil || !store.finalized || !store.recovered || probes != 0 || routes.apply != 0 || routes.observe != 0 {
		t.Fatalf("err=%v finalized=%v recovered=%v probe=%d apply=%d observe=%d", err, store.finalized, store.recovered, probes, routes.apply, routes.observe)
	}
}

func TestG4B2CertificateObservedStaleRecoveryConflictDoesNotProbe(t *testing.T) {
	store := &convergenceStoreFake{work: DomainConvergenceWork{ID: "request_1", ApplicationID: "app_1", DomainID: "domain_1", Hostname: "app.example.test", Phase: ConvergenceCertificateObserved, RouteID: "route_1"}, inspectState: "matching_serving", recoveryErr: errors.New("stale lease")}
	routes := &convergenceRouteFake{}
	probes := 0
	_, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{calls: &probes}}).ReconcileOnce(context.Background(), "worker-1")
	if err == nil || !store.recovered || store.finalized || probes != 0 || routes.apply != 0 || routes.observe != 0 {
		t.Fatalf("err=%v recovered=%v finalized=%v probe=%d", err, store.recovered, store.finalized, probes)
	}
}

func TestDomainConvergenceRoutePreparedRecoveryObservesBeforeReapplying(t *testing.T) {
	store := &convergenceStoreFake{work: DomainConvergenceWork{ID: "request_1", ApplicationID: "app_1", DomainID: "domain_1", Hostname: "app.example.test", Phase: ConvergenceRoutePrepared, RouteID: "route_1", Route: contracts.RouteRequest{Route: contracts.RouteSpec{Host: "app.example.test", Path: "/", DeploymentID: "dep_1", ServiceName: "web", Port: 18080, Verified: true}, Operation: contracts.OperationContext{IdempotencyKey: "request_1"}}}}
	routes := &convergenceRouteFake{}
	controller := &DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{}}
	if _, err := controller.ReconcileOnce(context.Background(), "worker-1"); err != nil || routes.apply != 0 || routes.observe != 1 || !store.active || !store.finalized {
		t.Fatalf("err=%v apply=%d observe=%d active=%v final=%v", err, routes.apply, routes.observe, store.active, store.finalized)
	}
}
func TestDomainConvergenceServingRecoveryNeverReprobes(t *testing.T) {
	store := &convergenceStoreFake{work: DomainConvergenceWork{ID: "r", ApplicationID: "a", DomainID: "d", Hostname: "app.example.test", Phase: ConvergenceServing, RouteID: "route", LeaseOwner: "worker-1"}}
	routes := &convergenceRouteFake{}
	if _, err := (&DomainConvergenceController{Store: store, Routes: routes, Probe: convergenceProbeFake{}}).ReconcileOnce(context.Background(), "worker-1"); err != nil || !store.recovered || routes.apply != 0 || routes.observe != 0 {
		t.Fatalf("err=%v recovered=%v apply=%d observe=%d", err, store.recovered, routes.apply, routes.observe)
	}
}
