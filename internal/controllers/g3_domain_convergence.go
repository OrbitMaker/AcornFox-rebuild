package controllers

import (
	"context"
	"errors"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/providers/edgeprobe"
)

// DomainConvergencePhase is intentionally independent of provider state. The
// store is durable truth; Caddy and the edge probe are bounded observations.
type DomainConvergencePhase string

const (
	ConvergenceQueued              DomainConvergencePhase = "queued"
	ConvergenceRoutePrepared       DomainConvergencePhase = "route_prepared"
	ConvergenceInternalRouteActive DomainConvergencePhase = "internal_route_active"
	ConvergenceTLSAllowed          DomainConvergencePhase = "tls_allowed"
	ConvergenceCertificateObserved DomainConvergencePhase = "certificate_observed"
	ConvergenceServing             DomainConvergencePhase = "serving"
	ConvergenceUnbindRouteRemoved  DomainConvergencePhase = "unbind_route_removed"
	ConvergenceCompleted           DomainConvergencePhase = "completed"
	ConvergenceFailed              DomainConvergencePhase = "failed"
	ConvergenceRecoveryRequired    DomainConvergencePhase = "recovery_required"
)

type DomainConvergenceWork struct {
	ID            domain.ID
	ApplicationID domain.ID
	DomainID      domain.ID
	Hostname      string
	// Kind distinguishes a normal converge request from the durable unbind
	// workflow. An empty kind is retained for the pre-G4B2 converge adapter
	// shape; only the explicit value "unbind" may take the removal path.
	Kind       string
	Restore    bool
	Phase      DomainConvergencePhase
	Route      contracts.RouteRequest
	RouteID    domain.ID
	LeaseOwner string
	Attempt    int
}
type DomainConvergenceObservation struct {
	Fingerprint, Issuer string
	NotBefore, NotAfter time.Time
	StatusCode          int
}

type DomainConvergenceActivationRestore struct {
	ID     domain.ID
	Phase  DomainConvergencePhase
	Owner  string
	Routes []DomainConvergenceRoute
	Digest string
	Count  int
}

// DomainConvergenceRoute is a durable, provider-ready route projection.  It
// is deliberately a RouteRequest rather than a live Caddy observation so an
// unbind worker can rebuild the complete frozen route set without deriving
// facts from the edge.
type DomainConvergenceRoute struct {
	ID      domain.ID
	Request contracts.RouteRequest
}

// DomainUnbindWork is the controller-facing immutable snapshot for an unbind
// request.  Reconcile support is intentionally added separately: this type
// only carries the durable full replacement route set and its frozen digest.
type DomainUnbindWork struct {
	ID                   domain.ID
	Restore              bool
	ApplicationID        domain.ID
	DomainID             domain.ID
	Hostname             string
	Phase                DomainConvergencePhase
	LeaseOwner           string
	RemainingRoutes      []DomainConvergenceRoute
	RemainingRouteDigest string
	RemainingRouteCount  int
}

type DomainConvergenceStore interface {
	ClaimDomainConvergence(context.Context, string, time.Duration) (DomainConvergenceWork, bool, error)
	PrepareDomainConvergenceRoute(context.Context, DomainConvergenceWork) (DomainConvergenceWork, error)
	ActivateDomainConvergenceRoute(context.Context, DomainConvergenceWork) error
	AllowDomainConvergenceTLS(context.Context, DomainConvergenceWork) error
	RecordDomainConvergenceProbe(context.Context, DomainConvergenceWork, edgeprobe.Observation) error
	FailDomainConvergence(context.Context, DomainConvergenceWork, string, error) error
	RecoverDomainConvergenceCompleted(context.Context, DomainConvergenceWork) (bool, error)
	LoadDomainConvergenceCertificateObservation(context.Context, DomainConvergenceWork) (DomainConvergenceObservation, error)
	FinalizeDomainConvergenceCertificate(context.Context, DomainConvergenceWork, DomainConvergenceObservation) error
	InspectDomainConvergenceServingFact(context.Context, DomainConvergenceWork, string) (string, error)
	MarkDomainConvergenceRecoveryRequired(context.Context, DomainConvergenceWork, string) error
	LoadDomainConvergenceActivationRestore(context.Context, DomainConvergenceWork) (DomainConvergenceActivationRestore, error)
	RestoreDomainConvergenceActivation(context.Context, DomainConvergenceWork, DomainConvergenceActivationRestore) error
	LoadDomainUnbindWork(context.Context, DomainConvergenceWork) (DomainUnbindWork, error)
	MarkDomainUnbindRouteRemoved(context.Context, DomainUnbindWork) error
	FinalizeDomainUnbind(context.Context, DomainUnbindWork) error
	RestoreDomainUnbind(context.Context, DomainUnbindWork) error
}

// DomainConvergenceController performs no DNS or certificate issuance. It
// moves one leased request through durable phases, releasing the database
// transaction before every RouteProvider or HTTPS probe call.
type DomainConvergenceController struct {
	Store  DomainConvergenceStore
	Routes contracts.RouteProvider
	Probe  edgeprobe.Prober
	Lease  time.Duration
	Clock  func() time.Time
}

const (
	convergencePrepareFailed     = "prepare_failed"
	convergenceApplyFailed       = "apply_failed"
	convergenceObserveFailed     = "observe_failed"
	convergenceActivateFailed    = "activate_failed"
	convergenceTLSFailed         = "tls_allow_failed"
	convergenceProbeFailed       = "probe_failed"
	convergenceRecordFailed      = "record_failed"
	convergenceFinalizeFailed    = "finalize_failed"
	convergenceRecoverFailed     = "recover_failed"
	convergenceServingInvalid    = "serving_state_invalid"
	convergenceUnbindLoad        = "unbind_load_failed"
	convergenceUnbindUnsupported = "unbind_rebuild_unsupported"
	convergenceUnbindRebuild     = "unbind_rebuild_failed"
)

func (c *DomainConvergenceController) ReconcileOnce(ctx context.Context, owner string) (bool, error) {
	if c == nil || c.Store == nil || c.Routes == nil || c.Probe == nil {
		return false, errors.New("domain convergence dependencies are incomplete")
	}
	if owner == "" {
		return false, domain.ValidationError("domain convergence owner is required")
	}
	lease := c.Lease
	if lease == 0 {
		lease = 30 * time.Second
	}
	work, claimed, err := c.Store.ClaimDomainConvergence(ctx, owner, lease)
	if err != nil || !claimed {
		return claimed, err
	}
	// Only the RoutePrepared recovery branch needs a route request to observe
	// or re-apply Caddy. Later durable phases operate by request ID and frozen
	// facts in the Store, so requiring a transient route ID would incorrectly
	// reject a crash recovery after activation or TLS allowance.
	needsRoute := work.Phase == ConvergenceRoutePrepared && !work.Restore
	if work.LeaseOwner != owner || work.ID.Empty() || work.ApplicationID.Empty() || work.DomainID.Empty() || (needsRoute && work.RouteID.Empty()) {
		if work.Kind == "unbind" && (work.Phase == ConvergenceQueued || work.Phase == ConvergenceRecoveryRequired || work.Phase == ConvergenceUnbindRouteRemoved || work.Phase == ConvergenceCompleted) {
			// Unbind requests intentionally do not carry a target route. Their
			// immutable route-set projection is loaded below under the same lease.
		} else {
			return true, domain.ValidationError("claimed domain convergence work is malformed")
		}
	}
	if work.Kind == "unbind" {
		return true, c.reconcileUnbind(ctx, work)
	}
	if work.Kind != "" && work.Kind != "converge" {
		return true, domain.ValidationError("claimed domain convergence work is malformed")
	}
	if work.Restore && work.Phase == ConvergenceRoutePrepared {
		return true, c.restoreConvergenceActivation(ctx, work)
	}
	if work.Phase == ConvergenceQueued || work.Phase == ConvergenceRecoveryRequired {
		work, err = c.Store.PrepareDomainConvergenceRoute(ctx, work)
		if err != nil {
			return true, c.fail(ctx, work, convergencePrepareFailed, err)
		}
	}
	if work.Phase == ConvergenceRoutePrepared || work.Phase == ConvergenceRecoveryRequired {
		// A process may have died after Caddy accepted Apply but before the
		// durable CAS. Observe first so recovery never manufactures a new route
		// when the frozen route is already present.
		if _, err := c.Routes.Observe(ctx, work.Route); err != nil {
			if _, _, applyErr := c.Routes.Apply(ctx, work.Route); applyErr != nil {
				if contracts.IsProviderOutcomeUnknown(applyErr) {
					return true, c.Store.MarkDomainConvergenceRecoveryRequired(ctx, work, "route_activation_restore_required")
				}
				return true, c.fail(ctx, work, convergenceApplyFailed, applyErr)
			}
			if _, observeErr := c.Routes.Observe(ctx, work.Route); observeErr != nil {
				return true, c.fail(ctx, work, convergenceObserveFailed, observeErr)
			}
		}
		if err := c.Store.ActivateDomainConvergenceRoute(ctx, work); err != nil {
			return true, c.Store.MarkDomainConvergenceRecoveryRequired(ctx, work, "route_activation_restore_required")
		}
		work.Phase = ConvergenceInternalRouteActive
	}
	if work.Phase == ConvergenceCertificateObserved {
		observation, err := c.Store.LoadDomainConvergenceCertificateObservation(ctx, work)
		if err != nil {
			return true, c.Store.MarkDomainConvergenceRecoveryRequired(ctx, work, "observation_invalid")
		}
		state, err := c.Store.InspectDomainConvergenceServingFact(ctx, work, observation.Fingerprint)
		if err != nil {
			return true, c.Store.MarkDomainConvergenceRecoveryRequired(ctx, work, "serving_fact_mismatch")
		}
		if state == "matching_serving" {
			_, err = c.Store.RecoverDomainConvergenceCompleted(ctx, work)
			if err != nil {
				return true, c.fail(ctx, work, convergenceRecoverFailed, err)
			}
			return true, nil
		}
		if state != "not_serving" && state != "renewal_pending" {
			return true, c.fail(ctx, work, convergenceServingInvalid, domain.NewError(domain.ErrConflict, "durable serving fact is invalid"))
		}
		if err := c.Store.FinalizeDomainConvergenceCertificate(ctx, work, observation); err != nil {
			return true, c.fail(ctx, work, convergenceFinalizeFailed, err)
		}
		_, err = c.Store.RecoverDomainConvergenceCompleted(ctx, work)
		if err != nil {
			return true, c.fail(ctx, work, convergenceRecoverFailed, err)
		}
		return true, nil
	}
	if work.Phase == ConvergenceServing {
		_, err := c.Store.RecoverDomainConvergenceCompleted(ctx, work)
		if err != nil {
			return true, c.fail(ctx, work, convergenceRecoverFailed, err)
		}
		return true, nil
	}
	if work.Phase == ConvergenceInternalRouteActive {
		// Route activation and TLS allowance are distinct durable CAS steps. A
		// crash between them recovers here without probing before TLS allow has
		// been committed. A stale owner/phase conflict must likewise stop before
		// any external probe is made.
		if err := c.Store.AllowDomainConvergenceTLS(ctx, work); err != nil {
			return true, c.fail(ctx, work, convergenceTLSFailed, err)
		}
		work.Phase = ConvergenceTLSAllowed
	}
	if work.Phase == ConvergenceTLSAllowed {
		observation, err := c.Probe.Probe(ctx, work.Hostname)
		if err != nil {
			return true, c.fail(ctx, work, convergenceProbeFailed, err)
		}
		if err := c.Store.RecordDomainConvergenceProbe(ctx, work, observation); err != nil {
			return true, c.fail(ctx, work, convergenceRecordFailed, err)
		}
	}
	return true, nil
}

func (c *DomainConvergenceController) restoreConvergenceActivation(ctx context.Context, work DomainConvergenceWork) error {
	restore, err := c.Store.LoadDomainConvergenceActivationRestore(ctx, work)
	if err != nil {
		return c.Store.MarkDomainConvergenceRecoveryRequired(ctx, work, "route_activation_restore_required")
	}
	if restore.ID != work.ID || restore.Phase != work.Phase || restore.Owner != work.LeaseOwner || restore.Count != len(restore.Routes) || restore.Digest == "" {
		return c.Store.MarkDomainConvergenceRecoveryRequired(ctx, work, "route_activation_restore_required")
	}
	rebuilder, ok := c.Routes.(contracts.RouteSetRebuilder)
	if !ok {
		return c.Store.MarkDomainConvergenceRecoveryRequired(ctx, work, "route_activation_restore_required")
	}
	requests := make([]contracts.RouteRequest, 0, len(restore.Routes))
	for _, route := range restore.Routes {
		if route.ID.Empty() || route.Request.Route.Host == "" || route.Request.Route.Path == "" || route.Request.Route.DeploymentID.Empty() || route.Request.Route.Port < 1 || route.Request.Route.Port > 65535 || !route.Request.Route.Verified {
			return c.Store.MarkDomainConvergenceRecoveryRequired(ctx, work, "route_activation_restore_required")
		}
		request := route.Request
		request.Operation = contracts.OperationContext{IdempotencyKey: work.ID.String() + ":activation-restore", Actor: work.LeaseOwner}
		requests = append(requests, request)
	}
	if _, err := rebuilder.RebuildRoutes(ctx, requests, contracts.OperationContext{IdempotencyKey: work.ID.String() + ":activation-restore", Actor: work.LeaseOwner}); err != nil {
		return c.Store.MarkDomainConvergenceRecoveryRequired(ctx, work, "route_activation_restore_required")
	}
	if err := c.Store.RestoreDomainConvergenceActivation(ctx, work, restore); err != nil {
		return c.Store.MarkDomainConvergenceRecoveryRequired(ctx, work, "route_activation_restore_required")
	}
	return nil
}

// reconcileUnbind only replaces Caddy with the complete frozen route set
// stored by BeginDomainUnbind. It intentionally has no remove/best-effort
// path: an interrupted replacement can always be replayed from durable facts.
func (c *DomainConvergenceController) reconcileUnbind(ctx context.Context, work DomainConvergenceWork) error {
	switch work.Phase {
	case ConvergenceCompleted:
		return nil
	case ConvergenceQueued, ConvergenceRecoveryRequired, ConvergenceUnbindRouteRemoved:
		unbind, err := c.Store.LoadDomainUnbindWork(ctx, work)
		if err != nil {
			if work.Restore {
				return c.markUnbindRecoveryRequired(ctx, work, "unbind_restore_required")
			}
			return c.fail(ctx, work, convergenceUnbindLoad, err)
		}
		if unbind.ID != work.ID || unbind.LeaseOwner != work.LeaseOwner || unbind.Phase != work.Phase || unbind.RemainingRouteCount != len(unbind.RemainingRoutes) || unbind.RemainingRouteDigest == "" {
			return c.markUnbindRecoveryRequired(ctx, work, "unbind_frozen_set_mismatch")
		}
		rebuilder, ok := c.Routes.(contracts.RouteSetRebuilder)
		if !ok {
			return c.fail(ctx, work, convergenceUnbindUnsupported, domain.UnsupportedCapabilityError("route_set_rebuild"))
		}
		requests := make([]contracts.RouteRequest, 0, len(unbind.RemainingRoutes))
		for _, route := range unbind.RemainingRoutes {
			if route.ID.Empty() || route.Request.Route.Host == "" || route.Request.Route.Path != "/" || route.Request.Route.DeploymentID.Empty() || route.Request.Route.Port < 1 || route.Request.Route.Port > 65535 {
				return c.markUnbindRecoveryRequired(ctx, work, "unbind_frozen_route_invalid")
			}
			request := route.Request
			request.Operation = contracts.OperationContext{IdempotencyKey: work.ID.String() + ":unbind", Actor: work.LeaseOwner}
			requests = append(requests, request)
		}
		if _, err := rebuilder.RebuildRoutes(ctx, requests, contracts.OperationContext{IdempotencyKey: work.ID.String() + ":unbind", Actor: work.LeaseOwner}); err != nil {
			if contracts.IsProviderOutcomeUnknown(err) {
				return c.markUnbindRecoveryRequired(ctx, work, "unbind_restore_required")
			}
			// Caddy has not acknowledged the full replacement, so preserve all
			// business facts and leave durable retry handling to Fail.
			return c.fail(ctx, work, convergenceUnbindRebuild, err)
		}
		if unbind.Restore {
			if err := c.Store.RestoreDomainUnbind(ctx, unbind); err != nil {
				return c.markUnbindRecoveryRequired(ctx, work, "unbind_restore_required")
			}
			return nil
		}
		if work.Phase != ConvergenceUnbindRouteRemoved {
			if err := c.Store.MarkDomainUnbindRouteRemoved(ctx, unbind); err != nil {
				return c.markUnbindRecoveryRequired(ctx, work, "unbind_restore_required")
			}
		}
		if err := c.Store.FinalizeDomainUnbind(ctx, unbind); err != nil {
			return c.markUnbindRecoveryRequired(ctx, work, "unbind_restore_required")
		}
		return nil
	default:
		return c.markUnbindRecoveryRequired(ctx, work, "unbind_phase_invalid")
	}
}

func (c *DomainConvergenceController) markUnbindRecoveryRequired(ctx context.Context, work DomainConvergenceWork, code string) error {
	if err := c.Store.MarkDomainConvergenceRecoveryRequired(ctx, work, code); err != nil {
		return err
	}
	return nil
}

func (c *DomainConvergenceController) fail(ctx context.Context, work DomainConvergenceWork, code string, cause error) error {
	if work.ID.Empty() || work.LeaseOwner == "" {
		return cause
	}
	if err := c.Store.FailDomainConvergence(ctx, work, code, cause); err != nil {
		return err
	}
	return cause
}
