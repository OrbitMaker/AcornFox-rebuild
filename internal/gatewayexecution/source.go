package gatewayexecution

import (
	"context"
	"errors"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/providers/acornfoxroute"
)

type commandContextKey struct{}

func withCommand(ctx context.Context, command Command) context.Context {
	return context.WithValue(ctx, commandContextKey{}, command)
}

// Source implements the existing projector seam with a root-provisioned flock,
// while every Core inventory/authority request is a separate short SQL read.
type Source struct {
	Lock      application.GatewayProjectionLock
	Authority *AuthorityClient
}

func (s *Source) WithRoutes(ctx context.Context, apply func([]acornfoxroute.RouteState, func() error) error) error {
	command, ok := ctx.Value(commandContextKey{}).(Command)
	if !ok || !commandValid(command) || s == nil || s.Authority == nil || apply == nil {
		return errors.New("Gateway projection command authority unavailable")
	}
	return s.Lock.WithLock(ctx, func(locked context.Context) error {
		routes, err := s.Authority.List(locked, command)
		if err != nil {
			return err
		}
		digest, err := inventoryDigest(routes)
		if err != nil {
			return err
		}
		states := make([]acornfoxroute.RouteState, 0, len(routes))
		for _, r := range routes {
			approval := contracts.AcornFoxApprovedHostnameRoute{
				Route:      contracts.AcornFoxPublicRouteIntent{ApplicationID: r.ApplicationID, DeploymentID: r.DeploymentID, Hostname: r.Hostname, ServiceName: r.ServiceName, Port: r.HostPort},
				Endpoint:   contracts.AcornFoxRoutableEndpoint{ApplicationID: r.ApplicationID, DeploymentID: r.DeploymentID, ServiceName: r.ServiceName, Port: r.HostPort, Accepted: true},
				ApprovalID: r.ApprovalID, EndpointVersion: r.EndpointVersion,
			}
			if approval.Validate() != nil {
				return errors.New("Core inventory contains an unroutable approval")
			}
			states = append(states, acornfoxroute.RouteState{Intent: approval.Route, Approval: &approval, Enabled: r.Enabled})
		}
		return apply(states, func() error { return s.Authority.Check(locked, command, digest) })
	})
}
