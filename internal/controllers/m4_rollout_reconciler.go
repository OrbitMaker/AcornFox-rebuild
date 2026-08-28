package controllers

import (
	"context"
	"errors"
	"time"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// M4RolloutReconciler advances only durably claimed coordinators. Runtime
// readiness, route staging/commit, and old retirement remain separate effects
// so a restart can resume from the committed phase without guessing from
// Caddy's derived configuration.
type M4RolloutReconciler struct {
	Store interface {
		ClaimM4Rollouts(context.Context, postgres.ClaimM4RolloutRequest) ([]postgres.M4RolloutCoordinator, error)
		RenewM4Rollout(context.Context, domain.ID, string, time.Time, time.Duration) error
		AdvanceM4Rollout(context.Context, postgres.AdvanceM4RolloutRequest) (postgres.M4RolloutCoordinator, error)
		FailM4Rollout(context.Context, domain.ID, string, postgres.M4RolloutPhase, []domain.EvidenceRef, string, time.Time) (postgres.M4RolloutCoordinator, error)
		CompleteM4Rollout(context.Context, domain.ID, string, postgres.M4RolloutPhase, []domain.EvidenceRef, time.Time) (postgres.M4RolloutCoordinator, error)
	}
	Routes interface {
		Stage(context.Context, postgres.M4RolloutCoordinator) ([]domain.EvidenceRef, error)
		Commit(context.Context, postgres.M4RolloutCoordinator) ([]domain.EvidenceRef, error)
		Restore(context.Context, postgres.M4RolloutCoordinator) error
	}
	Runtime interface {
		CandidateReady(context.Context, postgres.M4RolloutCoordinator) (bool, []domain.EvidenceRef, error)
		CleanupCandidate(context.Context, postgres.M4RolloutCoordinator, string) (bool, []domain.EvidenceRef, error)
	}
	Retirer interface {
		RetireOld(context.Context, postgres.M4RolloutCoordinator) (bool, []domain.EvidenceRef, error)
	}
	Owner string
	Lease time.Duration
	Clock func() time.Time
}

func (r *M4RolloutReconciler) ReconcileOnce(ctx context.Context, limit int) (int, error) {
	if r == nil || r.Store == nil || r.Routes == nil || r.Runtime == nil || r.Retirer == nil || r.Owner == "" || limit < 1 {
		return 0, errors.New("M4 rollout reconciler is not configured")
	}
	lease := r.Lease
	if lease <= 0 {
		lease = 30 * time.Second
	}
	items, err := r.Store.ClaimM4Rollouts(ctx, postgres.ClaimM4RolloutRequest{Owner: r.Owner, Now: r.now(), Duration: lease, Limit: limit})
	if err != nil {
		return 0, err
	}
	for _, item := range items {
		if err := r.reconcile(ctx, item, lease); err != nil {
			return len(items), err
		}
	}
	return len(items), nil
}
func (r *M4RolloutReconciler) reconcile(ctx context.Context, item postgres.M4RolloutCoordinator, lease time.Duration) error {
	if err := r.Store.RenewM4Rollout(ctx, item.OperationID, r.Owner, r.now(), lease); err != nil {
		return err
	}
	switch item.Phase {
	case postgres.M4RolloutCandidateRequested:
		ready, evidence, err := r.Runtime.CandidateReady(ctx, item)
		if err != nil {
			return r.fail(ctx, item, evidence, err)
		}
		if !ready {
			return nil
		}
		_, err = r.Store.AdvanceM4Rollout(ctx, postgres.AdvanceM4RolloutRequest{OperationID: item.OperationID, Owner: r.Owner, From: item.Phase, To: postgres.M4RolloutCandidateReady, Evidence: evidence, Reason: "candidate runtime-ready", Now: r.now()})
		return err
	case postgres.M4RolloutCandidateReady:
		evidence, err := r.Routes.Stage(ctx, item)
		if err != nil {
			return r.rollback(ctx, item, err)
		}
		_, err = r.Store.AdvanceM4Rollout(ctx, postgres.AdvanceM4RolloutRequest{OperationID: item.OperationID, Owner: r.Owner, From: item.Phase, To: postgres.M4RolloutRouteStaged, Evidence: evidence, Reason: "full route-set atomically loaded", Now: r.now()})
		return err
	case postgres.M4RolloutRouteStaged:
		evidence, err := r.Routes.Commit(ctx, item)
		if err != nil {
			return r.rollback(ctx, item, err)
		}
		_, err = r.Store.AdvanceM4Rollout(ctx, postgres.AdvanceM4RolloutRequest{OperationID: item.OperationID, Owner: r.Owner, From: item.Phase, To: postgres.M4RolloutRouteCommitted, Evidence: evidence, Reason: "route-set serving commit", Now: r.now()})
		return err
	case postgres.M4RolloutCandidateCleanup:
		done, evidence, err := r.Runtime.CleanupCandidate(ctx, item, item.CandidateCleanupReason)
		if err != nil {
			return err
		}
		if !done {
			return nil
		}
		return r.fail(ctx, item, evidence, errors.New(item.CandidateCleanupReason))
	case postgres.M4RolloutRouteCommitted:
		_, err := r.Store.AdvanceM4Rollout(ctx, postgres.AdvanceM4RolloutRequest{OperationID: item.OperationID, Owner: r.Owner, From: item.Phase, To: postgres.M4RolloutOldRetiring, Reason: "candidate serving; retire old independently", Now: r.now()})
		return err
	case postgres.M4RolloutOldRetiring:
		done, evidence, err := r.Retirer.RetireOld(ctx, item)
		if err != nil {
			return err
		}
		if !done {
			return nil
		}
		_, err = r.Store.CompleteM4Rollout(ctx, item.OperationID, r.Owner, item.Phase, evidence, r.now())
		return err
	default:
		return nil
	}
}
func (r *M4RolloutReconciler) rollback(ctx context.Context, item postgres.M4RolloutCoordinator, cause error) error {
	// Do not terminalize the coordinator until the old route-set is restored
	// and the non-serving candidate is gone. Keeping the durable phase active
	// lets a restarted worker retry either cleanup without claiming that a
	// potentially double-live or candidate-routed failure was safely handled.
	if err := r.Routes.Restore(ctx, item); err != nil {
		return errors.New("restore old route-set before rollout failure: " + foundation.RedactText(err.Error()))
	}
	done, evidence, err := r.Runtime.CleanupCandidate(ctx, item, cause.Error())
	if err != nil {
		return errors.New("clean candidate before rollout failure: " + foundation.RedactText(err.Error()))
	}
	if !done {
		return nil
	}
	return r.fail(ctx, item, evidence, cause)
}
func (r *M4RolloutReconciler) fail(ctx context.Context, item postgres.M4RolloutCoordinator, e []domain.EvidenceRef, cause error) error {
	_, err := r.Store.FailM4Rollout(ctx, item.OperationID, r.Owner, item.Phase, e, cause.Error(), r.now())
	return err
}
func (r *M4RolloutReconciler) now() time.Time {
	if r.Clock == nil {
		return time.Now().UTC()
	}
	return r.Clock().UTC()
}
