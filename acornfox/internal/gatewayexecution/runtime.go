package gatewayexecution

import (
	"context"
	"errors"
	"fmt"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/providers/acornfoxroute"
)

type RouteProjector interface {
	EnsureAcornFoxApprovedHostnameRoute(context.Context, contracts.AcornFoxApprovedHostnameRoute, string) error
	RemoveAcornFoxApprovedHostnameRoute(context.Context, contracts.AcornFoxApprovedHostnameRoute, string) error
	ObserveApprovedHostnameRoute(context.Context, contracts.AcornFoxApprovedHostnameRoute) (bool, error)
}

type Runtime struct {
	Authority *AuthorityClient
	Projector RouteProjector
}

func routeApproval(routes []appcontracts.ImagePublicAccessRoute, b appcontracts.ImagePublicAccessCommand) (contracts.AcornFoxApprovedHostnameRoute, error) {
	for _, r := range routes {
		if r.ApprovalID != b.ApprovalID || r.OperationID != b.OperationID {
			continue
		}
		if r.DeploymentID != b.DeploymentID || r.ApplicationID != b.ApplicationID || r.Hostname != b.Hostname || r.EndpointVersion != b.EndpointVersion || r.HostPort != b.HostPort || r.ServiceName != "web" || r.Enabled != (b.Action == appcontracts.ImagePublicAccessEnsure) {
			return contracts.AcornFoxApprovedHostnameRoute{}, errors.New("Core route inventory differs from command")
		}
		approval := contracts.AcornFoxApprovedHostnameRoute{
			Route:      contracts.AcornFoxPublicRouteIntent{ApplicationID: r.ApplicationID, DeploymentID: r.DeploymentID, Hostname: r.Hostname, ServiceName: r.ServiceName, Port: r.HostPort},
			Endpoint:   contracts.AcornFoxRoutableEndpoint{ApplicationID: r.ApplicationID, DeploymentID: r.DeploymentID, ServiceName: r.ServiceName, Port: r.HostPort, Accepted: true},
			ApprovalID: r.ApprovalID, EndpointVersion: r.EndpointVersion,
		}
		if approval.Validate() != nil || acornfoxroute.ValidateApprovedHostnameRoute("", approval) != nil {
			return contracts.AcornFoxApprovedHostnameRoute{}, errors.New("Core route approval invalid for custom-only Gateway")
		}
		return approval, nil
	}
	return contracts.AcornFoxApprovedHostnameRoute{}, errors.New("Core did not approve exact Gateway route")
}

func (r *Runtime) Execute(ctx context.Context, command Command) (appcontracts.ImagePublicAccessObservation, error) {
	var zero appcontracts.ImagePublicAccessObservation
	if r == nil || r.Authority == nil || r.Projector == nil || !commandValid(command) {
		return zero, errors.New("Gateway runtime is unavailable")
	}
	if err := r.Authority.Authorize(ctx, command); err != nil {
		return zero, err // No provider action has begun.
	}
	routes, err := r.Authority.List(ctx, command)
	if err != nil {
		return zero, err
	}
	approval, err := routeApproval(routes, command.Binding)
	if err != nil {
		return zero, err
	}
	digest, err := inventoryDigest(routes)
	if err != nil {
		return zero, err
	}
	wantPresent := command.Binding.Action == appcontracts.ImagePublicAccessEnsure
	projectCtx := withCommand(ctx, command)
	// Inspect before every possible write. In particular, a reclaimed unknown
	// or an ambiguous Store commit may already have produced the exact route.
	present, observeErr := r.Projector.ObserveApprovedHostnameRoute(projectCtx, approval)
	if observeErr != nil {
		return zero, fmt.Errorf("%w: Gateway pre-write observation failed", appcontracts.ErrOutcomeUnknown)
	}
	if present == wantPresent {
		if err := r.Authority.Check(ctx, command, digest); err != nil {
			return zero, fmt.Errorf("%w: Gateway pre-write fence changed", appcontracts.ErrOutcomeUnknown)
		}
		return appcontracts.ImagePublicAccessObservation{RouteApplied: true, ObservedAt: time.Now().UTC()}, nil
	}
	if err := r.Authority.Check(ctx, command, digest); err != nil {
		return zero, err // Still before a Caddy write.
	}
	key := "image.public_access:" + command.Binding.OperationID.String()
	if wantPresent {
		err = r.Projector.EnsureAcornFoxApprovedHostnameRoute(projectCtx, approval, key)
	} else {
		err = r.Projector.RemoveAcornFoxApprovedHostnameRoute(projectCtx, approval, key)
	}
	if err != nil {
		// The projector may have sent a successful PATCH before losing its reply.
		return zero, fmt.Errorf("%w: Gateway projection outcome unknown: %v", appcontracts.ErrOutcomeUnknown, err)
	}
	present, err = r.Projector.ObserveApprovedHostnameRoute(projectCtx, approval)
	if err != nil || present != wantPresent {
		return zero, fmt.Errorf("%w: Gateway readback did not prove the exact route", appcontracts.ErrOutcomeUnknown)
	}
	if err := r.Authority.Check(ctx, command, digest); err != nil {
		return zero, fmt.Errorf("%w: Gateway command changed after projection", appcontracts.ErrOutcomeUnknown)
	}
	return appcontracts.ImagePublicAccessObservation{RouteApplied: true, ObservedAt: time.Now().UTC()}, nil
}
