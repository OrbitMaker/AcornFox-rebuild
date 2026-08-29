package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type blockingConvergenceReconciler struct{ entered chan struct{} }

func (r blockingConvergenceReconciler) ReconcileOnce(context.Context, string) (bool, error) {
	close(r.entered)
	return true, nil
}

type fenceRouteProvider struct{}

func (fenceRouteProvider) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{}
}
func (fenceRouteProvider) Apply(context.Context, contracts.RouteRequest) (domain.Route, contracts.Evidence, error) {
	return domain.Route{}, contracts.Evidence{}, nil
}
func (fenceRouteProvider) Observe(context.Context, contracts.RouteRequest) (domain.Observation, error) {
	return domain.Observation{}, nil
}
func (fenceRouteProvider) Remove(context.Context, contracts.RouteRequest) error { return nil }
func (fenceRouteProvider) Rebuild(context.Context, contracts.OperationContext) (contracts.Evidence, error) {
	return contracts.Evidence{}, nil
}
func (fenceRouteProvider) RebuildRoutes(context.Context, []contracts.RouteRequest, contracts.OperationContext) (contracts.Evidence, error) {
	return contracts.Evidence{}, nil
}

func TestRouteSetMutationFenceBlocksB2WhileM4HoldsRouteSet(t *testing.T) {
	fence := newRouteSetMutationFence()
	adapter := &m4StagedRouteAdapter{fence: fence}
	operationID := domain.ID("operation_m4_fence")
	if err := adapter.acquireRouteSet(context.Background(), operationID); err != nil {
		t.Fatal(err)
	}
	defer adapter.releaseAllRouteSets()
	entered := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := (fencedDomainConvergenceReconciler{reconciler: blockingConvergenceReconciler{entered: entered}, fence: fence}).ReconcileOnce(context.Background(), "b2")
		done <- err
	}()
	select {
	case <-entered:
		t.Fatal("B2 entered while M4 held the route-set fence")
	case <-time.After(20 * time.Millisecond):
	}
	adapter.releaseRouteSet(operationID)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("B2 did not enter after M4 released the route-set fence")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRouteSetMutationFenceM4ErrorsAndRecoveryDoNotLeak(t *testing.T) {
	fence := newRouteSetMutationFence()
	adapter := &m4StagedRouteAdapter{store: &postgres.Store{}, routes: fenceRouteProvider{}, owner: "m4", fence: fence}
	rollout := postgres.M4RolloutCoordinator{OperationID: "operation_m4_fence"}
	if _, err := adapter.Stage(context.Background(), rollout); err == nil {
		t.Fatal("Stage unexpectedly succeeded with an unavailable store")
	}
	assertRouteSetFenceAvailable(t, fence)
	if _, err := adapter.Commit(context.Background(), rollout); err == nil {
		t.Fatal("Commit unexpectedly succeeded with an unavailable store")
	}
	assertRouteSetFenceAvailable(t, fence)
	if err := adapter.Restore(context.Background(), rollout); err == nil {
		t.Fatal("Restore unexpectedly succeeded with an unavailable store")
	}
	assertRouteSetFenceAvailable(t, fence)
}

func TestRouteSetMutationFenceReleaseAllAndCancellationAreIdempotent(t *testing.T) {
	fence := newRouteSetMutationFence()
	adapter := &m4StagedRouteAdapter{fence: fence}
	if err := adapter.acquireRouteSet(context.Background(), "operation_lifecycle"); err != nil {
		t.Fatal(err)
	}
	adapter.releaseAllRouteSets()
	adapter.releaseAllRouteSets()
	assertRouteSetFenceAvailable(t, fence)

	release, err := fence.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fence.Acquire(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled fence acquire error=%v", err)
	}
	release()
	assertRouteSetFenceAvailable(t, fence)
}

func assertRouteSetFenceAvailable(t *testing.T, fence *routeSetMutationFence) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	release, err := fence.Acquire(ctx)
	if err != nil {
		t.Fatalf("route-set fence leaked: %v", err)
	}
	release()
}
