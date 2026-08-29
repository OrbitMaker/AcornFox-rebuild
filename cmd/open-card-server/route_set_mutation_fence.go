package main

import (
	"context"
	"sync"
)

// routeSetMutationFence serializes every full route-set provider mutation in a
// single control-plane process. PostgreSQL leader locking prevents a second
// production B2 server, so this local fence is the remaining coordination
// boundary shared by B2 convergence and M4 staged rollouts.
type routeSetMutationFence struct {
	token chan struct{}
}

func newRouteSetMutationFence() *routeSetMutationFence {
	fence := &routeSetMutationFence{token: make(chan struct{}, 1)}
	fence.token <- struct{}{}
	return fence
}

func (f *routeSetMutationFence) Acquire(ctx context.Context) (func(), error) {
	if f == nil {
		return func() {}, nil
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.token:
	}
	var once sync.Once
	return func() {
		once.Do(func() { f.token <- struct{}{} })
	}, nil
}

type fencedDomainConvergenceReconciler struct {
	reconciler domainConvergenceReconciler
	fence      *routeSetMutationFence
}

func (f fencedDomainConvergenceReconciler) ReconcileOnce(ctx context.Context, owner string) (bool, error) {
	if f.reconciler == nil {
		return false, nil
	}
	release, err := f.fence.Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	return f.reconciler.ReconcileOnce(ctx, owner)
}
