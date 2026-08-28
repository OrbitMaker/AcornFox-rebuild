package controllers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type m4RolloutRecoveryStore struct {
	rollout   postgres.M4RolloutCoordinator
	advances  []postgres.M4RolloutPhase
	failed    bool
	completed bool
}

func (s *m4RolloutRecoveryStore) ClaimM4Rollouts(_ context.Context, request postgres.ClaimM4RolloutRequest) ([]postgres.M4RolloutCoordinator, error) {
	if s.completed || s.failed {
		return nil, nil
	}
	copy := s.rollout
	copy.LeaseOwner = request.Owner
	until := request.Now.Add(request.Duration)
	copy.LeaseUntil = &until
	s.rollout = copy
	return []postgres.M4RolloutCoordinator{copy}, nil
}
func (s *m4RolloutRecoveryStore) RenewM4Rollout(context.Context, domain.ID, string, time.Time, time.Duration) error {
	return nil
}
func (s *m4RolloutRecoveryStore) AdvanceM4Rollout(_ context.Context, request postgres.AdvanceM4RolloutRequest) (postgres.M4RolloutCoordinator, error) {
	if s.rollout.Phase == request.To {
		return s.rollout, nil
	}
	if s.rollout.Phase != request.From {
		return postgres.M4RolloutCoordinator{}, errors.New("out of order")
	}
	s.rollout.Phase = request.To
	s.advances = append(s.advances, request.To)
	return s.rollout, nil
}
func (s *m4RolloutRecoveryStore) FailM4Rollout(_ context.Context, _ domain.ID, _ string, _ postgres.M4RolloutPhase, _ []domain.EvidenceRef, _ string, _ time.Time) (postgres.M4RolloutCoordinator, error) {
	s.failed = true
	s.rollout.Phase = postgres.M4RolloutFailed
	return s.rollout, nil
}
func (s *m4RolloutRecoveryStore) CompleteM4Rollout(_ context.Context, _ domain.ID, _ string, _ postgres.M4RolloutPhase, _ []domain.EvidenceRef, _ time.Time) (postgres.M4RolloutCoordinator, error) {
	s.completed = true
	s.rollout.Phase = postgres.M4RolloutCompleted
	s.advances = append(s.advances, postgres.M4RolloutCompleted)
	return s.rollout, nil
}

type m4RolloutRecoveryRoutes struct {
	stage, commit, restore int
	stageErr, commitErr    error
}

func (r *m4RolloutRecoveryRoutes) Stage(context.Context, postgres.M4RolloutCoordinator) ([]domain.EvidenceRef, error) {
	r.stage++
	return nil, r.stageErr
}
func (r *m4RolloutRecoveryRoutes) Commit(context.Context, postgres.M4RolloutCoordinator) ([]domain.EvidenceRef, error) {
	r.commit++
	return nil, r.commitErr
}
func (r *m4RolloutRecoveryRoutes) Restore(context.Context, postgres.M4RolloutCoordinator) error {
	r.restore++
	return nil
}

type m4RolloutRecoveryRuntime struct{ cleanup int }

func (*m4RolloutRecoveryRuntime) CandidateReady(context.Context, postgres.M4RolloutCoordinator) (bool, []domain.EvidenceRef, error) {
	return true, nil, nil
}
func (r *m4RolloutRecoveryRuntime) CleanupCandidate(context.Context, postgres.M4RolloutCoordinator, string) (bool, []domain.EvidenceRef, error) {
	r.cleanup++
	return true, nil, nil
}

type m4RolloutRecoveryRetirer struct{ calls int }

func (r *m4RolloutRecoveryRetirer) RetireOld(context.Context, postgres.M4RolloutCoordinator) (bool, []domain.EvidenceRef, error) {
	r.calls++
	return r.calls > 1, nil, nil
}

func m4RecoveryCoordinator(phase postgres.M4RolloutPhase) postgres.M4RolloutCoordinator {
	return postgres.M4RolloutCoordinator{OperationID: "op_recovery", ApplicationID: "app_recovery", EnvironmentID: "env_recovery", SourceDeploymentID: "dep_old", CandidateDeploymentID: "dep_candidate", Phase: phase, RouteSetDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CreatedAt: time.Unix(1, 0).UTC(), UpdatedAt: time.Unix(1, 0).UTC()}
}

func TestM4RolloutReconcilerRecoversAfterEveryDurablePhase(t *testing.T) {
	store := &m4RolloutRecoveryStore{rollout: m4RecoveryCoordinator(postgres.M4RolloutCandidateReady)}
	routes, runtime, retirer := &m4RolloutRecoveryRoutes{}, &m4RolloutRecoveryRuntime{}, &m4RolloutRecoveryRetirer{}
	now := time.Unix(1_700_000_000, 0).UTC()
	for attempt := 0; attempt < 5 && !store.completed; attempt++ {
		// A fresh reconciler instance on every iteration models a control-plane
		// restart. Durable phase is the only state carried across instances.
		reconciler := &M4RolloutReconciler{Store: store, Routes: routes, Runtime: runtime, Retirer: retirer, Owner: "worker_recovered", Lease: time.Minute, Clock: func() time.Time { return now }}
		if _, err := reconciler.ReconcileOnce(context.Background(), 1); err != nil {
			t.Fatal(err)
		}
		now = now.Add(2 * time.Minute)
	}
	want := []postgres.M4RolloutPhase{postgres.M4RolloutRouteStaged, postgres.M4RolloutRouteCommitted, postgres.M4RolloutOldRetiring, postgres.M4RolloutCompleted}
	if !store.completed || len(store.advances) != len(want) {
		t.Fatalf("rollout did not recover through all phases: completed=%v phases=%v", store.completed, store.advances)
	}
	for index := range want {
		if store.advances[index] != want[index] {
			t.Fatalf("phase %d=%s want=%s", index, store.advances[index], want[index])
		}
	}
	if routes.stage != 1 || routes.commit != 1 || retirer.calls != 2 || runtime.cleanup != 0 {
		t.Fatalf("recovery repeated external effects: routes=%#v retire=%d cleanup=%d", routes, retirer.calls, runtime.cleanup)
	}
}

func TestM4RolloutReconcilerRestoresOldAndCleansCandidateBeforeCommitFailure(t *testing.T) {
	for _, phase := range []postgres.M4RolloutPhase{postgres.M4RolloutCandidateReady, postgres.M4RolloutRouteStaged} {
		t.Run(string(phase), func(t *testing.T) {
			store := &m4RolloutRecoveryStore{rollout: m4RecoveryCoordinator(phase)}
			routes := &m4RolloutRecoveryRoutes{}
			if phase == postgres.M4RolloutCandidateReady {
				routes.stageErr = errors.New("route load failed")
			} else {
				routes.commitErr = errors.New("route observe failed")
			}
			runtime := &m4RolloutRecoveryRuntime{}
			reconciler := &M4RolloutReconciler{Store: store, Routes: routes, Runtime: runtime, Retirer: &m4RolloutRecoveryRetirer{}, Owner: "worker", Lease: time.Minute, Clock: func() time.Time { return time.Unix(2, 0).UTC() }}
			if _, err := reconciler.ReconcileOnce(context.Background(), 1); err != nil {
				t.Fatal(err)
			}
			if !store.failed || routes.restore != 1 || runtime.cleanup != 1 {
				t.Fatalf("pre-commit failure did not preserve old route and clean candidate: failed=%v routes=%#v cleanup=%d", store.failed, routes, runtime.cleanup)
			}
		})
	}
}

type m4PendingCleanupRuntime struct {
	store *m4RolloutRecoveryStore
	calls int
}

func (*m4PendingCleanupRuntime) CandidateReady(context.Context, postgres.M4RolloutCoordinator) (bool, []domain.EvidenceRef, error) {
	return true, nil, nil
}
func (r *m4PendingCleanupRuntime) CleanupCandidate(_ context.Context, rollout postgres.M4RolloutCoordinator, reason string) (bool, []domain.EvidenceRef, error) {
	r.calls++
	if r.calls == 1 {
		r.store.rollout.Phase = postgres.M4RolloutCandidateCleanup
		r.store.rollout.CandidateCleanupTaskID = "task_cleanup"
		r.store.rollout.CandidateCleanupReason = reason
		return false, nil, nil
	}
	return true, []domain.EvidenceRef{{ID: "evidence_cleanup", Kind: "agent.destroy_group"}}, nil
}

func TestM4RolloutReconcilerKeepsCleanupPendingRecoverableAcrossRestart(t *testing.T) {
	store := &m4RolloutRecoveryStore{rollout: m4RecoveryCoordinator(postgres.M4RolloutCandidateReady)}
	routes := &m4RolloutRecoveryRoutes{stageErr: errors.New("route observe failed")}
	runtime := &m4PendingCleanupRuntime{store: store}
	newReconciler := func() *M4RolloutReconciler {
		return &M4RolloutReconciler{Store: store, Routes: routes, Runtime: runtime, Retirer: &m4RolloutRecoveryRetirer{}, Owner: "worker", Lease: time.Minute, Clock: func() time.Time { return time.Unix(3, 0).UTC() }}
	}
	if _, err := newReconciler().ReconcileOnce(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if store.failed || store.rollout.Phase != postgres.M4RolloutCandidateCleanup || runtime.calls != 1 || routes.restore != 1 {
		t.Fatalf("pending cleanup was not durable: rollout=%+v failed=%v calls=%d restore=%d", store.rollout, store.failed, runtime.calls, routes.restore)
	}
	// A brand-new reconciler resumes from candidate_cleanup and does not load
	// the failed candidate route-set a second time.
	if _, err := newReconciler().ReconcileOnce(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if !store.failed || runtime.calls != 2 || routes.stage != 1 || routes.restore != 1 {
		t.Fatalf("completed cleanup did not terminalize exactly once: failed=%v calls=%d stage=%d restore=%d", store.failed, runtime.calls, routes.stage, routes.restore)
	}
}
