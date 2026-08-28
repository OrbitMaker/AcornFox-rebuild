package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

// UpsertTLSAllowDesiredRoute persists ROUTE_DESIRED as the existing M3
// `pending` state. The route remains verified but non-serving and carries no
// certificate reference, so it cannot be replayed into Caddy.
func (s *Store) UpsertTLSAllowDesiredRoute(ctx context.Context, applicationDomainID domain.ID, route domain.Route, now time.Time) error {
	if err := domain.RequireID(applicationDomainID, "TLS allow application domain id"); err != nil {
		return err
	}
	if route.CertificateRef != "" || route.Serving || !route.Verified {
		return domain.ValidationError("TLS allow desired route must be verified, non-serving, and certificate-free")
	}
	return s.UpsertDesiredRoute(ctx, DesiredRouteRecord{Route: route, ApplicationDomainID: applicationDomainID, State: DesiredRoutePending}, now)
}

// TLSAllowState performs a single indexed facts lookup. It permits issuance
// only for a DNS-verified application domain with at least one complete
// ROUTE_DESIRED fact and no disabled, failed, certificate-bound, or unhealthy
// desired route for that domain.
func (s *Store) TLSAllowState(ctx context.Context, rawDomain string) (domain.TLSAllowState, error) {
	if err := s.requireDB(); err != nil {
		return domain.TLSAllowState{}, err
	}
	host, err := domain.NormalizeTLSAllowDomain(rawDomain)
	if err != nil {
		return domain.TLSAllowState{}, err
	}
	state := domain.TLSAllowState{Domain: host}
	err = s.db.QueryRowContext(ctx, `
		WITH verified_domain AS (
			SELECT id FROM m3_application_domains
			 WHERE hostname = $1 AND verification_status = 'verified'
		), desired_routes AS (
			SELECT r.*, d.state AS deployment_state
			  FROM m3_desired_routes r
			  JOIN verified_domain vd ON vd.id = r.application_domain_id
			  JOIN deployments d ON d.id = r.deployment_id
			 WHERE r.hostname = $1
		)
		SELECT
			EXISTS (SELECT 1 FROM verified_domain),
			EXISTS (
				SELECT 1 FROM desired_routes
				 WHERE desired_state = 'pending' AND verified AND NOT serving AND certificate_reference_id IS NULL
			),
			EXISTS (
				SELECT 1 FROM desired_routes
				 WHERE desired_state = 'pending' AND verified AND NOT serving AND certificate_reference_id IS NULL
			)
			AND NOT EXISTS (
				SELECT 1 FROM desired_routes
				 WHERE desired_state = 'pending'
				   AND (NOT verified OR serving OR certificate_reference_id IS NOT NULL OR deployment_state NOT IN ('runtime_ready', 'degraded', 'serving'))
			),
			EXISTS (SELECT 1 FROM desired_routes WHERE desired_state IN ('disabled', 'failed'))
	`, host).Scan(&state.DNSVerified, &state.RouteDesired, &state.RuntimeReady, &state.DisabledOrFailed)
	if err != nil {
		return domain.TLSAllowState{}, fmt.Errorf("lookup TLS allow state: %w", err)
	}
	return state, nil
}

var _ interface {
	UpsertTLSAllowDesiredRoute(context.Context, domain.ID, domain.Route, time.Time) error
	TLSAllowState(context.Context, string) (domain.TLSAllowState, error)
} = (*Store)(nil)
