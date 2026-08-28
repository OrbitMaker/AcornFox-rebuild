package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

type TLSAllowPreparedRoute struct {
	Route domain.Route
	Port  int
}

// UpsertTLSAllowDesiredRoute persists ROUTE_DESIRED as the existing M3
// `pending` state. The route remains verified but non-serving and carries no
// certificate reference, so it cannot be replayed into Caddy.
func (s *Store) UpsertTLSAllowDesiredRoute(ctx context.Context, applicationDomainID domain.ID, route domain.Route, now time.Time) error {
	return s.PrepareTLSAllowDesiredRoutes(ctx, applicationDomainID, []TLSAllowPreparedRoute{{Route: route, Port: 0}}, now)
}

// PrepareTLSAllowDesiredRoutes atomically creates or verifies every required
// loopback port lease and pending route. A conflict in any target rolls back
// all earlier leases and routes, leaving no partial ROUTE_DESIRED state.
func (s *Store) PrepareTLSAllowDesiredRoutes(ctx context.Context, applicationDomainID domain.ID, routes []TLSAllowPreparedRoute, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	if err := domain.RequireID(applicationDomainID, "TLS allow application domain id"); err != nil {
		return err
	}
	if len(routes) == 0 {
		return domain.ValidationError("at least one TLS allow route is required")
	}
	for _, item := range routes {
		if err := validateTLSAllowPreparedRoute(item); err != nil {
			return err
		}
	}
	now = m3Now(s, now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	rollback := func(cause error) error { return rollbackTx(tx, cause) }
	var applicationID, hostname, verification string
	if err := tx.QueryRowContext(ctx, `SELECT application_id,hostname,verification_status FROM m3_application_domains WHERE id=$1 FOR SHARE`, applicationDomainID.String()).Scan(&applicationID, &hostname, &verification); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return rollback(ErrNotFound)
		}
		return rollback(fmt.Errorf("read TLS allow application domain: %w", err))
	}
	if verification != string(DomainVerificationVerified) {
		return rollback(domain.NewError(domain.ErrInvalidTransition, "TLS allow domain is not DNS verified"))
	}
	for _, item := range routes {
		route := item.Route
		if route.ApplicationID.String() != applicationID || route.Host != hostname {
			return rollback(domain.ValidationError("TLS allow route does not match verified application domain"))
		}
		if err := m3AssertDeploymentApplicationTx(ctx, tx, route.DeploymentID, route.ApplicationID); err != nil {
			return rollback(err)
		}
		if err := prepareTLSAllowLeaseTx(ctx, tx, route, item.Port, now); err != nil {
			return rollback(err)
		}
		if err := prepareTLSAllowRouteTx(ctx, tx, applicationDomainID, route, now); err != nil {
			return rollback(err)
		}
	}
	return tx.Commit()
}

func validateTLSAllowPreparedRoute(item TLSAllowPreparedRoute) error {
	route := item.Route
	if route.CertificateRef != "" || route.Serving || !route.Verified {
		return domain.ValidationError("TLS allow desired route must be verified, non-serving, and certificate-free")
	}
	if err := route.Validate(); err != nil {
		return err
	}
	if _, err := NormalizeM3PathPrefix(route.Path); err != nil {
		return err
	}
	if item.Port < 0 || item.Port > 65535 {
		return domain.ValidationError("TLS allow route port is invalid")
	}
	return nil
}

func prepareTLSAllowLeaseTx(ctx context.Context, tx *sql.Tx, route domain.Route, port int, now time.Time) error {
	if port == 0 {
		return nil
	}
	leaseID := tlsAllowLeaseID(route.ID, route.DeploymentID, port)
	var app, deployment, service, bind string
	var existingPort int
	var released sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT application_id,deployment_id,service_name,bind_host,port,released_at FROM m3_port_leases WHERE id=$1 FOR UPDATE`, leaseID.String()).Scan(&app, &deployment, &service, &bind, &existingPort, &released)
	if err == nil {
		if released.Valid || app != route.ApplicationID.String() || deployment != route.DeploymentID.String() || service != route.ServiceName || bind != "127.0.0.1" || existingPort != port {
			return domain.NewError(domain.ErrConflict, "TLS allow route lease identity conflicts")
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read TLS allow route lease: %w", err)
	}
	var occupied string
	err = tx.QueryRowContext(ctx, `SELECT id FROM m3_port_leases WHERE bind_host='127.0.0.1' AND port=$1 AND released_at IS NULL FOR KEY SHARE`, port).Scan(&occupied)
	if err == nil {
		return domain.NewError(domain.ErrConflict, "TLS allow route port is already leased")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read TLS allow port occupancy: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO m3_port_leases(id,application_id,deployment_id,service_name,bind_host,port,acquired_at) VALUES($1,$2,$3,$4,'127.0.0.1',$5,$6)`, leaseID.String(), route.ApplicationID.String(), route.DeploymentID.String(), route.ServiceName, port, now)
	return err
}

func prepareTLSAllowRouteTx(ctx context.Context, tx *sql.Tx, applicationDomainID domain.ID, route domain.Route, now time.Time) error {
	var app, deployment, service, host, path, certificate, state string
	var verified, serving bool
	err := tx.QueryRowContext(ctx, `SELECT application_id,deployment_id,service_name,hostname,path_prefix,COALESCE(certificate_reference_id,''),desired_state,verified,serving FROM m3_desired_routes WHERE id=$1 FOR UPDATE`, route.ID.String()).Scan(&app, &deployment, &service, &host, &path, &certificate, &state, &verified, &serving)
	if err == nil {
		if app != route.ApplicationID.String() || deployment != route.DeploymentID.String() || service != route.ServiceName || host != route.Host || path != route.Path || certificate != "" {
			return domain.NewError(domain.ErrConflict, "TLS allow route identity conflicts with an existing route")
		}
		if state == string(DesiredRoutePending) && verified && !serving {
			return nil
		}
		if state == string(DesiredRouteDisabled) || state == string(DesiredRouteFailed) {
			_, err = tx.ExecContext(ctx, `UPDATE m3_desired_routes SET desired_state='pending',verified=true,serving=false,updated_at=$2 WHERE id=$1`, route.ID.String(), now)
			return err
		}
		return domain.NewError(domain.ErrConflict, "TLS allow route identity conflicts with an existing route")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read TLS allow desired route: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO m3_desired_routes(id,application_id,application_domain_id,deployment_id,service_name,hostname,path_prefix,certificate_reference_id,desired_state,verified,serving,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,NULL,'pending',true,false,$8,$8)`, route.ID.String(), route.ApplicationID.String(), applicationDomainID.String(), route.DeploymentID.String(), route.ServiceName, route.Host, route.Path, now)
	return err
}

func tlsAllowLeaseID(routeID, deploymentID domain.ID, port int) domain.ID {
	sum := sha256.Sum256([]byte("lease:" + routeID.String() + ":" + deploymentID.String() + ":" + fmt.Sprint(port)))
	return domain.ID("lease_" + hex.EncodeToString(sum[:16]))
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
