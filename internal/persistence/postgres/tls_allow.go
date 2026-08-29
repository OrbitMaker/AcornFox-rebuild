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
	leaseID := tlsAllowLeaseID(route.ApplicationID, route.DeploymentID, route.ServiceName, port)
	_, err := ensureTLSAllowLeaseTx(ctx, tx, leaseID, route.ApplicationID, route.DeploymentID, route.ServiceName, port, now)
	return err
}

// ensureTLSAllowLeaseTx owns a loopback endpoint by its stable runtime
// identity, not by an individual domain route. Multiple verified hostnames may
// therefore point to the same application/deployment/service/port lease while
// a different endpoint remains a conflict.
func ensureTLSAllowLeaseTx(ctx context.Context, tx *sql.Tx, leaseID, applicationID, deploymentID domain.ID, service string, port int, now time.Time) (domain.ID, error) {
	var app, deployment, storedService, bind string
	var existingPort int
	var released sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT application_id,deployment_id,service_name,bind_host,port,released_at FROM m3_port_leases WHERE id=$1 FOR UPDATE`, leaseID.String()).Scan(&app, &deployment, &storedService, &bind, &existingPort, &released)
	if err == nil {
		if released.Valid || app != applicationID.String() || deployment != deploymentID.String() || storedService != service || bind != "127.0.0.1" || existingPort != port {
			return "", domain.NewError(domain.ErrConflict, "TLS allow route lease identity conflicts")
		}
		return leaseID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("read TLS allow route lease: %w", err)
	}
	var occupied, occupiedApp, occupiedDeployment, occupiedService string
	err = tx.QueryRowContext(ctx, `SELECT id,application_id,deployment_id,service_name FROM m3_port_leases WHERE bind_host='127.0.0.1' AND port=$1 AND released_at IS NULL FOR KEY SHARE`, port).Scan(&occupied, &occupiedApp, &occupiedDeployment, &occupiedService)
	if err == nil {
		if occupiedApp == applicationID.String() && occupiedDeployment == deploymentID.String() && occupiedService == service {
			// A lease created before the canonical endpoint ID existed remains a
			// valid owner of this endpoint. Reuse it rather than creating a second
			// active lease or forcing a route/domain-specific identity back in.
			return domain.ID(occupied), nil
		}
		return "", domain.NewError(domain.ErrConflict, "TLS allow route port is already leased")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("read TLS allow port occupancy: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO m3_port_leases(id,application_id,deployment_id,service_name,bind_host,port,acquired_at) VALUES($1,$2,$3,$4,'127.0.0.1',$5,$6)`, leaseID.String(), applicationID.String(), deploymentID.String(), service, port, now)
	if err != nil {
		return "", err
	}
	return leaseID, nil
}

func findTLSAllowLeaseIDTx(ctx context.Context, tx *sql.Tx, applicationID, deploymentID domain.ID, service string, port int) (domain.ID, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id FROM m3_port_leases WHERE application_id=$1 AND deployment_id=$2 AND service_name=$3 AND bind_host='127.0.0.1' AND port=$4 AND released_at IS NULL FOR UPDATE`, applicationID.String(), deploymentID.String(), service, port).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrDomainConvergenceConflict
	}
	if err != nil {
		return "", err
	}
	return domain.ID(id), nil
}

func prepareTLSAllowRouteTx(ctx context.Context, tx *sql.Tx, applicationDomainID domain.ID, route domain.Route, now time.Time) error {
	var app, currentDomain, deployment, service, host, path, certificate, state string
	var verified, serving bool
	err := tx.QueryRowContext(ctx, `SELECT application_id,COALESCE(application_domain_id,''),deployment_id,service_name,hostname,path_prefix,COALESCE(certificate_reference_id,''),desired_state,verified,serving FROM m3_desired_routes WHERE id=$1 FOR UPDATE`, route.ID.String()).Scan(&app, &currentDomain, &deployment, &service, &host, &path, &certificate, &state, &verified, &serving)
	if err == nil {
		if app != route.ApplicationID.String() || host != route.Host || path != route.Path || certificate != "" || serving {
			return domain.NewError(domain.ErrConflict, "TLS allow route identity conflicts with an existing route")
		}
		if state == string(DesiredRoutePending) || state == string(DesiredRouteActive) {
			if currentDomain != applicationDomainID.String() || deployment != route.DeploymentID.String() || service != route.ServiceName || !verified {
				return domain.NewError(domain.ErrConflict, "TLS allow route identity conflicts with an existing route")
			}
			if state == string(DesiredRoutePending) {
				return nil
			}
			return domain.NewError(domain.ErrConflict, "TLS allow route identity conflicts with an existing route")
		}
		if state == string(DesiredRouteDisabled) || state == string(DesiredRouteFailed) {
			if currentDomain == applicationDomainID.String() && deployment == route.DeploymentID.String() && service == route.ServiceName {
				updated, err := tx.ExecContext(ctx, `UPDATE m3_desired_routes SET desired_state='pending',verified=true,serving=false,certificate_reference_id=NULL,updated_at=$2 WHERE id=$1 AND application_domain_id=$3 AND desired_state IN ('disabled','failed') AND serving=false AND certificate_reference_id IS NULL`, route.ID.String(), now, applicationDomainID.String())
				if err != nil {
					return err
				}
				if changed, err := updated.RowsAffected(); err != nil || changed != 1 {
					return domain.NewError(domain.ErrConflict, "TLS allow disabled route restore changed")
				}
				return nil
			}
			if currentDomain != "" && currentDomain != applicationDomainID.String() {
				return domain.NewError(domain.ErrConflict, "TLS allow disabled route belongs to a different domain")
			}
			var pointerID string
			if err := tx.QueryRowContext(ctx, `SELECT route_id FROM m3_route_pointers WHERE route_id=$1 FOR UPDATE`, route.ID.String()).Scan(&pointerID); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			} else if err == nil {
				return domain.NewError(domain.ErrConflict, "TLS allow disabled route retains a pointer")
			}
			_, err = tx.ExecContext(ctx, `UPDATE m3_desired_routes SET application_domain_id=$2,deployment_id=$3,service_name=$4,desired_state='pending',verified=true,serving=false,certificate_reference_id=NULL,updated_at=$5 WHERE id=$1 AND application_id=$6 AND hostname=$7 AND path_prefix=$8 AND desired_state IN ('disabled','failed') AND serving=false AND certificate_reference_id IS NULL`, route.ID.String(), applicationDomainID.String(), route.DeploymentID.String(), route.ServiceName, now, route.ApplicationID.String(), route.Host, route.Path)
			return err
		}
		if state == string(DesiredRoutePending) && verified && !serving {
			return nil
		}
		return domain.NewError(domain.ErrConflict, "TLS allow route identity conflicts with an existing route")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read TLS allow desired route: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO m3_desired_routes(id,application_id,application_domain_id,deployment_id,service_name,hostname,path_prefix,certificate_reference_id,desired_state,verified,serving,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,NULL,'pending',true,false,$8,$8)`, route.ID.String(), route.ApplicationID.String(), applicationDomainID.String(), route.DeploymentID.String(), route.ServiceName, route.Host, route.Path, now)
	return err
}

func tlsAllowLeaseID(applicationID, deploymentID domain.ID, service string, port int) domain.ID {
	sum := sha256.Sum256([]byte("lease:" + applicationID.String() + ":" + deploymentID.String() + ":" + service + ":" + fmt.Sprint(port)))
	return domain.ID("lease_" + hex.EncodeToString(sum[:16]))
}

// releaseTLSAllowLeaseIfUnreferencedTx releases an endpoint only after its last
// route pointer has moved away. A shared platform/custom endpoint must remain
// usable until every route has cut over or been removed.
func releaseTLSAllowLeaseIfUnreferencedTx(ctx context.Context, tx *sql.Tx, leaseID, applicationID, deploymentID domain.ID, service string, port int, now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, `
		UPDATE m3_port_leases AS lease
		   SET released_at=$1
		 WHERE lease.id=$2
		   AND lease.application_id=$3
		   AND lease.deployment_id=$4
		   AND lease.service_name=$5
		   AND lease.bind_host='127.0.0.1'
		   AND lease.port=$6
		   AND lease.released_at IS NULL
		   AND NOT EXISTS (SELECT 1 FROM m3_route_pointers pointer WHERE pointer.port_lease_id=lease.id)
	`, now, leaseID.String(), applicationID.String(), deploymentID.String(), service, port)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return changed == 1, nil
}

// TLSAllowState permits first issuance and later renewal only after the
// internal route is active. A certificate reference or serving=true is not a
// denial: both are expected during renewal. Disabled, failed, unverified, or
// unhealthy active routes fail closed.
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
		WITH domain_facts AS (
			SELECT
				COALESCE(bool_or(verification_status = 'verified'), false) AS dns_verified,
				COALESCE(bool_or(verification_status = 'failed'), false) AS dns_failed
			  FROM m3_application_domains
			 WHERE hostname = $1
		), route_facts AS (
			SELECT
				r.desired_state,
				r.verified,
				ad.verification_status,
				d.runtime_healthy,
				p.route_id IS NOT NULL
					AND p.deployment_id = r.deployment_id
					AND l.id IS NOT NULL
					AND l.application_id = r.application_id
					AND l.deployment_id = r.deployment_id
					AND l.service_name = r.service_name
					AND l.bind_host = '127.0.0.1'
					AND l.port BETWEEN 1 AND 65535
					AND l.released_at IS NULL
					AND (l.expires_at IS NULL OR l.expires_at > CURRENT_TIMESTAMP)
					AND d.runtime_healthy
					AND d.state IN ('runtime_ready', 'degraded', 'serving')
					AND (
						(NOT r.serving AND r.certificate_reference_id IS NULL)
						OR (
							r.serving
							AND c.id IS NOT NULL
							AND c.status = 'ready'
							AND c.subject_hostname = r.hostname
							AND c.secret_reference_id ~ '^edge-caddy-observation:sha256:[0-9a-f]{64}$'
							AND c.not_before <= CURRENT_TIMESTAMP
						)
					) AS route_safe
			  FROM m3_desired_routes r
			  JOIN m3_application_domains ad
			    ON ad.id = r.application_domain_id
			   AND ad.hostname = $1
			  JOIN deployments d ON d.id = r.deployment_id
			  LEFT JOIN m3_route_pointers p ON p.route_id = r.id
			  LEFT JOIN m3_port_leases l ON l.id = p.port_lease_id
			  LEFT JOIN m3_certificate_references c ON c.id = r.certificate_reference_id
			 WHERE r.hostname = $1
		)
		SELECT
			(SELECT dns_verified FROM domain_facts),
			EXISTS (
				SELECT 1 FROM route_facts
				 WHERE desired_state = 'active' AND verified AND verification_status = 'verified'
			),
			EXISTS (
				SELECT 1 FROM route_facts
				 WHERE desired_state = 'active' AND verified AND verification_status = 'verified' AND route_safe
			)
			AND NOT EXISTS (
				SELECT 1 FROM route_facts
				 WHERE desired_state = 'active'
				   AND (NOT verified OR COALESCE(verification_status, '') <> 'verified' OR NOT route_safe)
			),
			(SELECT dns_failed FROM domain_facts)
			OR EXISTS (SELECT 1 FROM route_facts WHERE desired_state IN ('disabled', 'failed'))
			OR EXISTS (
				SELECT 1 FROM route_facts
				 WHERE desired_state = 'active'
				   AND (NOT verified OR COALESCE(verification_status, '') <> 'verified' OR NOT route_safe)
			)
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
