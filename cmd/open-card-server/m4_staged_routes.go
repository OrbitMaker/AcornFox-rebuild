package main

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// m4StagedRouteAdapter derives Caddy configuration exclusively from persisted
// current pointers plus a 0016 staged replacement snapshot. Loading the
// candidate never rewrites the pointer facts; Restore always reconstructs
// from those current facts.
type m4StagedRouteAdapter struct {
	store  *postgres.Store
	routes contracts.RouteProvider
	owner  string
	clock  func() time.Time
}

func (a *m4StagedRouteAdapter) Stage(ctx context.Context, rollout postgres.M4RolloutCoordinator) ([]domain.EvidenceRef, error) {
	if a == nil || a.store == nil || a.routes == nil {
		return nil, fmt.Errorf("M4 staged route adapter is unavailable")
	}
	staged, err := a.store.ClaimM4StagedRouteSet(ctx, rollout.OperationID, a.owner, a.now(), 30*time.Second)
	if err != nil {
		return nil, err
	}
	requests, err := a.replacementRequests(ctx, staged)
	if err != nil {
		return nil, err
	}
	if len(staged.Entries) == 0 {
		if err := a.store.MarkM4RouteSetObserved(ctx, rollout.OperationID, a.owner, []domain.EvidenceRef{}, a.now()); err != nil {
			return nil, err
		}
		return []domain.EvidenceRef{}, nil
	}
	rebuilder, ok := a.routes.(contracts.RouteSetRebuilder)
	if !ok {
		return nil, domain.NewError(domain.ErrUnsupportedCapability, "RouteProvider does not support full route-set rebuild")
	}
	evidence, err := rebuilder.RebuildRoutes(ctx, requests, contracts.OperationContext{IdempotencyKey: rollout.OperationID.String() + ":route-stage", EvidenceID: domain.ID(rollout.RouteSetDigest), Actor: "m4-rollout"})
	if err != nil {
		return nil, err
	}
	for _, request := range requests {
		if request.Route.DeploymentID != staged.CandidateDeploymentID {
			continue
		}
		observation, observeErr := a.routes.Observe(ctx, request)
		if observeErr != nil {
			return nil, observeErr
		}
		evidence.Refs = append(evidence.Refs, observation.Evidence...)
	}
	if err := a.store.MarkM4RouteSetObserved(ctx, rollout.OperationID, a.owner, evidence.Refs, a.now()); err != nil {
		return nil, err
	}
	return evidence.Refs, nil
}
func (a *m4StagedRouteAdapter) Restore(ctx context.Context, rollout postgres.M4RolloutCoordinator) error {
	if a == nil || a.store == nil || a.routes == nil {
		return fmt.Errorf("M4 staged route adapter is unavailable")
	}
	stored, err := a.store.ListDesiredRoutes(ctx)
	if err != nil {
		return err
	}
	requests := make([]contracts.RouteRequest, 0, len(stored))
	for i, item := range stored {
		if item.Pointer == nil || item.Lease == nil || item.Lease.ReleasedAt != nil {
			continue
		}
		requests = append(requests, contracts.RouteRequest{Route: contracts.RouteSpec{Host: item.Route.Host, Path: item.Route.Path, DeploymentID: item.Route.DeploymentID, ServiceName: item.Route.ServiceName, Port: item.Lease.Port, CertificateRef: item.Route.CertificateRef, Verified: item.Route.Verified}, Operation: contracts.OperationContext{IdempotencyKey: rollout.OperationID.String() + fmt.Sprintf(":route-restore:%d", i), Actor: "m4-rollout"}})
	}
	rebuilder, ok := a.routes.(contracts.RouteSetRebuilder)
	if !ok {
		return domain.NewError(domain.ErrUnsupportedCapability, "RouteProvider does not support full route-set rebuild")
	}
	_, err = rebuilder.RebuildRoutes(ctx, requests, contracts.OperationContext{IdempotencyKey: rollout.OperationID.String() + ":route-restore", Actor: "m4-rollout"})
	if err != nil {
		return err
	}
	return a.store.DiscardM4RouteSet(ctx, rollout.OperationID, a.owner, "candidate route-set failed observation; old route-set restored", a.now())
}
func (a *m4StagedRouteAdapter) Commit(ctx context.Context, rollout postgres.M4RolloutCoordinator) ([]domain.EvidenceRef, error) {
	if a == nil || a.store == nil {
		return nil, fmt.Errorf("M4 staged route adapter is unavailable")
	}
	// Stage and commit are deliberately separate crash-recoverable phases. A
	// control-plane restart can outlive the staged-set lease while the rollout
	// coordinator waits for its own lease takeover. Reclaim the exact staged
	// set before Finalize so recovery never treats an otherwise observed route
	// set as a rollout failure merely because the previous process exited.
	staged, err := a.store.ClaimM4StagedRouteSet(ctx, rollout.OperationID, a.owner, a.now(), 30*time.Second)
	if err != nil {
		return nil, err
	}
	if staged.CandidateDigest != rollout.RouteSetDigest || staged.ExpectedVersion != rollout.ExpectedRouteSetVersion {
		return nil, domain.NewError(domain.ErrConflict, "staged route-set identity changed before serving commit")
	}
	result, err := a.store.FinalizeM4Serving(ctx, postgres.FinalizeM4ServingRequest{OperationID: rollout.OperationID, Owner: a.owner, RouteSetDigest: rollout.RouteSetDigest, ExpectedVersion: rollout.ExpectedRouteSetVersion, Actor: "m4-rollout", Reason: "full staged route-set observed and committed", Evidence: rollout.Evidence, Now: a.now()})
	if err != nil {
		return nil, err
	}
	return result.Coordinator.Evidence, nil
}
func (a *m4StagedRouteAdapter) replacementRequests(ctx context.Context, staged postgres.M4StagedRouteSet) ([]contracts.RouteRequest, error) {
	stored, err := a.store.ListDesiredRoutes(ctx)
	if err != nil {
		return nil, err
	}
	entries := map[domain.ID]postgres.M4StagedRouteEntry{}
	for _, entry := range staged.Entries {
		entries[entry.RouteID] = entry
	}
	requests := make([]contracts.RouteRequest, 0, len(stored))
	seen := map[domain.ID]bool{}
	for i, item := range stored {
		if item.Pointer == nil || item.Lease == nil || item.Lease.ReleasedAt != nil {
			continue
		}
		route := item.Route
		port := item.Lease.Port
		if entry, ok := entries[route.ID]; ok {
			if route.DeploymentID != entry.OldDeploymentID || item.Lease.Port < 1 {
				return nil, domain.NewError(domain.ErrConflict, "current route-set no longer matches staged snapshot")
			}
			route.DeploymentID = entry.CandidateDeployment
			route.ServiceName = entry.ServiceName
			port = entry.CandidatePort
			if port == 0 {
				if err := a.store.DB().QueryRowContext(ctx, `SELECT host_port FROM m4_service_observations WHERE deployment_id=$1 AND service_name=$2 AND healthy=true AND host_port BETWEEN 1 AND 65535 ORDER BY observed_at DESC,id DESC LIMIT 1`, entry.CandidateDeployment.String(), entry.ServiceName).Scan(&port); err != nil {
					return nil, domain.NewError(domain.ErrConflict, "candidate route endpoint is not yet observed")
				}
			}
			seen[route.ID] = true
		}
		requests = append(requests, contracts.RouteRequest{Route: contracts.RouteSpec{Host: route.Host, Path: route.Path, DeploymentID: route.DeploymentID, ServiceName: route.ServiceName, Port: port, CertificateRef: route.CertificateRef, Verified: route.Verified}, Operation: contracts.OperationContext{IdempotencyKey: staged.OperationID.String() + fmt.Sprintf(":route-load:%d", i), EvidenceID: domain.ID(staged.CandidateDigest), Actor: "m4-rollout"}})
	}
	for id := range entries {
		if !seen[id] {
			return nil, domain.NewError(domain.ErrConflict, "staged route is absent from current route-set")
		}
	}
	sort.Slice(requests, func(i, j int) bool {
		return requests[i].Route.Host+requests[i].Route.Path < requests[j].Route.Host+requests[j].Route.Path
	})
	return requests, nil
}
func (a *m4StagedRouteAdapter) now() time.Time {
	if a.clock == nil {
		return time.Now().UTC()
	}
	return a.clock().UTC()
}
