package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"net"
	"strconv"
	"strings"
	"time"
)

type AcornFoxPublicAccessRecoveryCommand struct {
	ApplicationID, DeploymentID   domain.ID
	IdempotencyKey, RequestDigest string
	RequestedEnabled              bool
	RouteID                       domain.ID
	Phase                         string
}

// ClaimAcornFoxPublicAccessRecoveryCommands bounds restart work and changes a
// surviving applying command to reconcile_required under row locks. It never
// derives a route: callers must read the canonical M3 route fact.
func (s *Store) ClaimAcornFoxPublicAccessRecoveryCommands(ctx context.Context, limit int, now time.Time) ([]AcornFoxPublicAccessRecoveryCommand, error) {
	if limit < 1 || limit > 32 {
		return nil, domain.ValidationError("public access recovery limit invalid")
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer func() { _ = tx.Rollback() }()
	rows, e := tx.QueryContext(ctx, `SELECT application_id,deployment_id,idempotency_key,request_digest,requested_enabled,COALESCE(route_id,''),phase FROM acornfox_public_access_commands WHERE phase IN ('applying','reconcile_required') ORDER BY created_at LIMIT $1 FOR UPDATE SKIP LOCKED`, limit)
	if e != nil {
		return nil, e
	}
	out := []AcornFoxPublicAccessRecoveryCommand{}
	for rows.Next() {
		var x AcornFoxPublicAccessRecoveryCommand
		var rid string
		if e = rows.Scan(&x.ApplicationID, &x.DeploymentID, &x.IdempotencyKey, &x.RequestDigest, &x.RequestedEnabled, &rid, &x.Phase); e != nil {
			rows.Close()
			return nil, e
		}
		x.RouteID = domain.ID(rid)
		out = append(out, x)
	}
	// pgx does not permit a second statement on this transaction while the
	// candidate cursor is still active.  Closing it here also makes the lock
	// boundary explicit: the rows remain locked until commit, while all
	// ownership reads below use the same bounded snapshot safely.
	if e = rows.Close(); e != nil {
		return nil, e
	}
	for _, x := range out {
		if e = afpaAssert(ctx, tx, x.ApplicationID, x.DeploymentID); e != nil {
			return nil, e
		}
		// A surviving command is allowed to recover only the deterministic route
		// that belongs to its own deployment.  Do this check before changing an
		// applying command into reconcile_required: a corrupted command row must
		// fail closed rather than acquire recovery ownership of another route.
		if x.RequestedEnabled && x.RouteID.Empty() {
			return nil, domain.NewError(domain.ErrConflict, "public access recovery route is missing")
		}
		if !x.RouteID.Empty() {
			if x.RouteID != afpaID("route", x.ApplicationID.String(), x.DeploymentID.String()) {
				return nil, domain.NewError(domain.ErrConflict, "public access recovery route identity conflicts")
			}
			if _, _, found, err := afpaRouteIntentTx(ctx, tx, x.ApplicationID, x.DeploymentID, x.RouteID, true); err != nil || !found {
				if err != nil {
					return nil, err
				}
				return nil, domain.NewError(domain.ErrConflict, "public access recovery route is missing")
			}
		}
	}
	for _, item := range out {
		if item.Phase != "applying" {
			continue
		}
		result, err := tx.ExecContext(ctx, `UPDATE acornfox_public_access_commands SET phase='reconcile_required',updated_at=$7 WHERE application_id=$1 AND deployment_id=$2 AND idempotency_key=$3 AND request_digest=$4 AND requested_enabled=$5 AND route_id IS NOT DISTINCT FROM $6 AND phase='applying'`, item.ApplicationID.String(), item.DeploymentID.String(), item.IdempotencyKey, item.RequestDigest, item.RequestedEnabled, nullableAFPARouteID(item.RouteID), m3Now(s, now))
		if err != nil {
			return nil, err
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			if err != nil {
				return nil, err
			}
			return nil, domain.NewError(domain.ErrConflict, "public access recovery command changed")
		}
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return out, nil
}

func afpaID(kind string, parts ...string) domain.ID {
	h := sha256.Sum256([]byte(kind + "\x00" + strings.Join(parts, "\x00")))
	return domain.ID("afpa_" + kind + "_" + hex.EncodeToString(h[:12]))
}
func afpaValid(key, digest string) bool {
	return strings.TrimSpace(key) != "" && len(key) <= 512 && len(digest) == 71 && strings.HasPrefix(digest, "sha256:")
}
func afpaAssert(ctx context.Context, tx *sql.Tx, app, dep domain.ID) error {
	err := m3AssertDeploymentApplicationTx(ctx, tx, dep, app)
	if domain.IsCode(err, domain.ErrValidation) {
		return ErrNotFound
	}
	return err
}

func nullableAFPARouteID(id domain.ID) any {
	if id.Empty() {
		return nil
	}
	return id.String()
}

func afpaConflict(message string) error {
	return domain.NewError(domain.ErrConflict, message)
}

// Begin persists the M3 desired route before Caddy is asked to project it.
func (s *Store) BeginAcornFoxPublicAccess(ctx context.Context, fact contracts.AcornFoxPublicAccessFact, intent contracts.AcornFoxPublicRouteIntent, enabled bool, key, digest string, now time.Time) (contracts.AcornFoxPublicAccessFact, bool, error) {
	if s.requireDB() != nil || fact.Validate() != nil || !afpaValid(key, digest) {
		return contracts.AcornFoxPublicAccessFact{}, false, domain.ValidationError("public access command invalid")
	}
	if _, _, err := afpaPlatformRoot(fact.Hostname); err != nil {
		return contracts.AcornFoxPublicAccessFact{}, false, domain.ValidationError("public access hostname is not owned")
	}
	now = m3Now(s, now)
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return contracts.AcornFoxPublicAccessFact{}, false, e
	}
	fail := func(x error) (contracts.AcornFoxPublicAccessFact, bool, error) {
		return contracts.AcornFoxPublicAccessFact{}, false, rollbackTx(tx, x)
	}
	if e = afpaAssert(ctx, tx, fact.ApplicationID, fact.DeploymentID); e != nil {
		return fail(e)
	}
	routeID := afpaID("route", fact.ApplicationID.String(), fact.DeploymentID.String())
	var oldDigest, phase, status, host sql.NullString
	e = tx.QueryRowContext(ctx, `SELECT request_digest,phase,result_status,result_hostname FROM acornfox_public_access_commands WHERE application_id=$1 AND deployment_id=$2 AND idempotency_key=$3 FOR UPDATE`, fact.ApplicationID.String(), fact.DeploymentID.String(), key).Scan(&oldDigest, &phase, &status, &host)
	if e == nil {
		if oldDigest.String != digest {
			return fail(ErrIdempotencyConflict)
		}
		if phase.String == "completed" {
			// A replay returns the same persisted component projection as GET,
			// rather than reconstructing a stale command result from two columns.
			// The canonical M3 route/pointer/lease remains the endpoint truth.
			out, found, readErr := afpaPublicAccessFactTx(ctx, tx, fact.ApplicationID, fact.DeploymentID)
			if readErr != nil || !found || out.Validate() != nil {
				if readErr != nil {
					return fail(readErr)
				}
				return fail(domain.ValidationError("invalid replay"))
			}
			if e = tx.Commit(); e != nil {
				return contracts.AcornFoxPublicAccessFact{}, false, e
			}
			return out, true, nil
		}
		return fail(domain.NewError(domain.ErrConflict, "public access command in progress"))
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return fail(e)
	}
	if enabled {
		if intent.Validate() != nil || intent.ApplicationID != fact.ApplicationID || intent.DeploymentID != fact.DeploymentID {
			return fail(domain.ValidationError("public route intent invalid"))
		}
		if fact.Status != contracts.AcornFoxPublicPendingExternalValidation || fact.Hostname != intent.Hostname {
			return fail(domain.ValidationError("public access fact does not match enabled route"))
		}
		if e = afpaPersistEnabled(ctx, tx, intent, routeID, now); e != nil {
			return fail(e)
		}
	} else {
		if fact.Status != contracts.AcornFoxPublicDisabled {
			return fail(domain.ValidationError("public access fact does not match disabled route"))
		}
		found, err := afpaDisableRouteTx(ctx, tx, fact.ApplicationID, fact.DeploymentID, fact.Hostname, routeID, now)
		if err != nil {
			return fail(err)
		}
		if !found {
			routeID = ""
		}
	}
	routeRef := nullableAFPARouteID(routeID)
	_, e = tx.ExecContext(ctx, `INSERT INTO acornfox_public_access_commands(application_id,deployment_id,idempotency_key,request_digest,requested_enabled,route_id,phase,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'applying',$7,$7)`, fact.ApplicationID.String(), fact.DeploymentID.String(), key, digest, enabled, routeRef, now)
	if e != nil {
		return fail(domain.NewError(domain.ErrConflict, "public access command conflict"))
	}
	if e = tx.Commit(); e != nil {
		return contracts.AcornFoxPublicAccessFact{}, false, fmt.Errorf("%w: begin: %v", ErrOutcomeUnknown, e)
	}
	return contracts.AcornFoxPublicAccessFact{}, false, nil
}
func afpaPersistEnabled(ctx context.Context, tx *sql.Tx, i contracts.AcornFoxPublicRouteIntent, routeID domain.ID, now time.Time) error {
	if err := i.Validate(); err != nil || routeID.Empty() {
		return domain.ValidationError("public route intent invalid")
	}
	root, slug, err := afpaPlatformRoot(i.Hostname)
	if err != nil {
		return err
	}
	pd := afpaID("platform", root)
	ad := afpaID("domain", i.ApplicationID.String(), i.DeploymentID.String())
	lease := afpaID("lease", routeID.String())
	if err := afpaEnsurePlatformDomainTx(ctx, tx, pd, root, now); err != nil {
		return err
	}
	if err := afpaEnsureApplicationDomainTx(ctx, tx, ad, pd, i, slug, now); err != nil {
		return err
	}
	if err := afpaEnsureLeaseTx(ctx, tx, lease, i, now); err != nil {
		return err
	}
	if err := afpaEnsureRouteTx(ctx, tx, routeID, ad, i, now); err != nil {
		return err
	}
	return afpaEnsurePointerTx(ctx, tx, routeID, lease, i.DeploymentID, now)
}

// afpaPlatformRoot accepts only the generated single-node public shape.  The
// service derives this hostname from the configured authorized root; this
// defensive check keeps a direct persistence caller from turning an arbitrary
// generic hostname into a platform-domain fact.
func afpaPlatformRoot(hostname string) (root, slug string, err error) {
	labels := strings.Split(hostname, ".")
	if len(labels) < 4 || labels[1] != "apps" || !strings.HasPrefix(labels[0], "delivery-") || len(labels[0]) != len("delivery-")+20 {
		return "", "", domain.ValidationError("public hostname is not an owned delivery hostname")
	}
	for _, char := range labels[0][len("delivery-"):] {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return "", "", domain.ValidationError("public hostname is not an owned delivery hostname")
		}
	}
	return strings.Join(labels[1:], "."), labels[0], nil
}

func afpaEnsurePlatformDomainTx(ctx context.Context, tx *sql.Tx, id domain.ID, hostname string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO m3_platform_domains(id,hostname,dns_provider_ref,verification_status,wildcard_enabled,created_at,updated_at) VALUES($1,$2,'acornfox-public-access','pending',false,$3,$3) ON CONFLICT(id) DO NOTHING`, id.String(), hostname, now); err != nil {
		return err
	}
	var actualHostname, provider string
	var wildcard bool
	if err := tx.QueryRowContext(ctx, `SELECT hostname,dns_provider_ref,wildcard_enabled FROM m3_platform_domains WHERE id=$1 FOR UPDATE`, id.String()).Scan(&actualHostname, &provider, &wildcard); err != nil {
		return err
	}
	if actualHostname != hostname || provider != "acornfox-public-access" || wildcard {
		return afpaConflict("public platform domain identity conflicts")
	}
	return nil
}

func afpaEnsureApplicationDomainTx(ctx context.Context, tx *sql.Tx, id, platformID domain.ID, i contracts.AcornFoxPublicRouteIntent, slug string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO m3_application_domains(id,application_id,platform_domain_id,hostname,domain_kind,stable_slug,verification_method,verification_status,created_at,updated_at) VALUES($1,$2,$3,$4,'platform',$5,'dns01','pending',$6,$6) ON CONFLICT(id) DO NOTHING`, id.String(), i.ApplicationID.String(), platformID.String(), i.Hostname, slug, now); err != nil {
		return err
	}
	var applicationID, actualPlatformID, hostname, kind, actualSlug, method string
	if err := tx.QueryRowContext(ctx, `SELECT application_id,COALESCE(platform_domain_id,''),hostname,domain_kind,COALESCE(stable_slug,''),verification_method FROM m3_application_domains WHERE id=$1 FOR UPDATE`, id.String()).Scan(&applicationID, &actualPlatformID, &hostname, &kind, &actualSlug, &method); err != nil {
		return err
	}
	if applicationID != i.ApplicationID.String() || actualPlatformID != platformID.String() || hostname != i.Hostname || kind != "platform" || actualSlug != slug || method != "dns01" {
		return afpaConflict("public application domain identity conflicts")
	}
	return nil
}

func afpaEnsureLeaseTx(ctx context.Context, tx *sql.Tx, id domain.ID, i contracts.AcornFoxPublicRouteIntent, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO m3_port_leases(id,application_id,deployment_id,service_name,bind_host,port,acquired_at) VALUES($1,$2,$3,$4,'127.0.0.1',$5,$6) ON CONFLICT(id) DO NOTHING`, id.String(), i.ApplicationID.String(), i.DeploymentID.String(), i.ServiceName, i.Port, now); err != nil {
		return err
	}
	var app, deployment, service, bind string
	var port int
	var released sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT application_id,deployment_id,service_name,bind_host,port,released_at FROM m3_port_leases WHERE id=$1 FOR UPDATE`, id.String()).Scan(&app, &deployment, &service, &bind, &port, &released); err != nil {
		return err
	}
	if released.Valid || app != i.ApplicationID.String() || deployment != i.DeploymentID.String() || service != i.ServiceName || bind != "127.0.0.1" || port != i.Port {
		return afpaConflict("public route lease identity conflicts")
	}
	return nil
}

func afpaEnsureRouteTx(ctx context.Context, tx *sql.Tx, routeID, domainID domain.ID, i contracts.AcornFoxPublicRouteIntent, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO m3_desired_routes(id,application_id,application_domain_id,deployment_id,service_name,hostname,path_prefix,desired_state,verified,serving,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'/','active',true,false,$7,$7) ON CONFLICT(id) DO NOTHING`, routeID.String(), i.ApplicationID.String(), domainID.String(), i.DeploymentID.String(), i.ServiceName, i.Hostname, now); err != nil {
		return err
	}
	var app, storedDomain, deployment, service, hostname, path, certificate, state string
	var verified, serving bool
	if err := tx.QueryRowContext(ctx, `SELECT application_id,COALESCE(application_domain_id,''),deployment_id,service_name,hostname,path_prefix,COALESCE(certificate_reference_id,''),desired_state,verified,serving FROM m3_desired_routes WHERE id=$1 FOR UPDATE`, routeID.String()).Scan(&app, &storedDomain, &deployment, &service, &hostname, &path, &certificate, &state, &verified, &serving); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return afpaConflict("public route disappeared during enable")
		}
		return err
	}
	if app != i.ApplicationID.String() || storedDomain != domainID.String() || deployment != i.DeploymentID.String() || service != i.ServiceName || hostname != i.Hostname || path != "/" || certificate != "" || !verified || serving || (state != "active" && state != "disabled") {
		return afpaConflict("public route identity conflicts")
	}
	result, err := tx.ExecContext(ctx, `UPDATE m3_desired_routes SET desired_state='active',updated_at=$2 WHERE id=$1 AND application_id=$3 AND application_domain_id=$4 AND deployment_id=$5 AND service_name=$6 AND hostname=$7 AND path_prefix='/' AND certificate_reference_id IS NULL AND desired_state IN ('active','disabled') AND verified=true AND serving=false`, routeID.String(), now, i.ApplicationID.String(), domainID.String(), i.DeploymentID.String(), i.ServiceName, i.Hostname)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		if err != nil {
			return err
		}
		return afpaConflict("public route changed during enable")
	}
	return nil
}

func afpaEnsurePointerTx(ctx context.Context, tx *sql.Tx, routeID, leaseID, deploymentID domain.ID, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO m3_route_pointers(route_id,deployment_id,port_lease_id,revision,updated_at) VALUES($1,$2,$3,1,$4) ON CONFLICT(route_id) DO NOTHING`, routeID.String(), deploymentID.String(), leaseID.String(), now); err != nil {
		return err
	}
	var actualDeployment, actualLease string
	if err := tx.QueryRowContext(ctx, `SELECT deployment_id,port_lease_id FROM m3_route_pointers WHERE route_id=$1 FOR UPDATE`, routeID.String()).Scan(&actualDeployment, &actualLease); err != nil {
		return err
	}
	if actualDeployment != deploymentID.String() || actualLease != leaseID.String() {
		return afpaConflict("public route pointer identity conflicts")
	}
	return nil
}

// afpaRouteIntentTx is the single read-side ownership gate.  It deliberately
// walks every durable link instead of treating a route row as enough proof:
// deterministic IDs are useful names, not proof that a row is safe to reuse.
func afpaRouteIntentTx(ctx context.Context, tx *sql.Tx, applicationID, deploymentID, routeID domain.ID, lock bool) (contracts.AcornFoxPublicRouteIntent, string, bool, error) {
	lockClause := ""
	if lock {
		lockClause = " FOR UPDATE"
	}
	var app, applicationDomainID, deployment, service, hostname, path, certificate, state string
	var verified, serving bool
	err := tx.QueryRowContext(ctx, `SELECT application_id,COALESCE(application_domain_id,''),deployment_id,service_name,hostname,path_prefix,COALESCE(certificate_reference_id,''),desired_state,verified,serving FROM m3_desired_routes WHERE id=$1`+lockClause, routeID.String()).Scan(&app, &applicationDomainID, &deployment, &service, &hostname, &path, &certificate, &state, &verified, &serving)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.AcornFoxPublicRouteIntent{}, "", false, nil
	}
	if err != nil {
		return contracts.AcornFoxPublicRouteIntent{}, "", false, err
	}
	root, slug, err := afpaPlatformRoot(hostname)
	if err != nil || routeID != afpaID("route", applicationID.String(), deploymentID.String()) || app != applicationID.String() || deployment != deploymentID.String() || applicationDomainID != afpaID("domain", applicationID.String(), deploymentID.String()).String() || path != "/" || certificate != "" || !verified || serving || (state != "active" && state != "disabled") {
		return contracts.AcornFoxPublicRouteIntent{}, "", false, afpaConflict("public route identity conflicts")
	}
	platformID := afpaID("platform", root)
	var domainApp, domainPlatform, domainHost, kind, domainSlug, method string
	if err := tx.QueryRowContext(ctx, `SELECT application_id,COALESCE(platform_domain_id,''),hostname,domain_kind,COALESCE(stable_slug,''),verification_method FROM m3_application_domains WHERE id=$1`+lockClause, applicationDomainID).Scan(&domainApp, &domainPlatform, &domainHost, &kind, &domainSlug, &method); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return contracts.AcornFoxPublicRouteIntent{}, "", false, afpaConflict("public route application domain is missing")
		}
		return contracts.AcornFoxPublicRouteIntent{}, "", false, err
	}
	if domainApp != applicationID.String() || domainPlatform != platformID.String() || domainHost != hostname || kind != "platform" || domainSlug != slug || method != "dns01" {
		return contracts.AcornFoxPublicRouteIntent{}, "", false, afpaConflict("public route application domain conflicts")
	}
	var platformHost, provider string
	var wildcard bool
	if err := tx.QueryRowContext(ctx, `SELECT hostname,dns_provider_ref,wildcard_enabled FROM m3_platform_domains WHERE id=$1`+lockClause, platformID.String()).Scan(&platformHost, &provider, &wildcard); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return contracts.AcornFoxPublicRouteIntent{}, "", false, afpaConflict("public route platform domain is missing")
		}
		return contracts.AcornFoxPublicRouteIntent{}, "", false, err
	}
	if platformHost != root || provider != "acornfox-public-access" || wildcard {
		return contracts.AcornFoxPublicRouteIntent{}, "", false, afpaConflict("public route platform domain conflicts")
	}
	leaseID := afpaID("lease", routeID.String())
	var pointerDeployment, pointerLease, leaseApp, leaseDeployment, leaseService, leaseBind string
	var leasePort int
	var released sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT p.deployment_id,p.port_lease_id,l.application_id,l.deployment_id,l.service_name,l.bind_host,l.port,l.released_at FROM m3_route_pointers p JOIN m3_port_leases l ON l.id=p.port_lease_id WHERE p.route_id=$1`+lockClause, routeID.String()).Scan(&pointerDeployment, &pointerLease, &leaseApp, &leaseDeployment, &leaseService, &leaseBind, &leasePort, &released); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return contracts.AcornFoxPublicRouteIntent{}, "", false, afpaConflict("public route pointer is missing")
		}
		return contracts.AcornFoxPublicRouteIntent{}, "", false, err
	}
	intent := contracts.AcornFoxPublicRouteIntent{ApplicationID: applicationID, DeploymentID: deploymentID, Hostname: hostname, ServiceName: service, Port: leasePort}
	if pointerDeployment != deploymentID.String() || pointerLease != leaseID.String() || released.Valid || leaseApp != applicationID.String() || leaseDeployment != deploymentID.String() || leaseService != service || leaseBind != "127.0.0.1" || intent.Validate() != nil {
		return contracts.AcornFoxPublicRouteIntent{}, "", false, afpaConflict("public route pointer conflicts")
	}
	return intent, state, true, nil
}

func afpaDisableRouteTx(ctx context.Context, tx *sql.Tx, applicationID, deploymentID domain.ID, hostname string, routeID domain.ID, now time.Time) (bool, error) {
	intent, state, found, err := afpaRouteIntentTx(ctx, tx, applicationID, deploymentID, routeID, true)
	if err != nil || !found {
		return found, err
	}
	if intent.Hostname != hostname || (state != "active" && state != "disabled") {
		return false, afpaConflict("public route identity conflicts")
	}
	result, err := tx.ExecContext(ctx, `UPDATE m3_desired_routes SET desired_state='disabled',updated_at=$2 WHERE id=$1 AND application_id=$3 AND deployment_id=$4 AND desired_state IN ('active','disabled') AND verified=true AND serving=false`, routeID.String(), now, applicationID.String(), deploymentID.String())
	if err != nil {
		return false, err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		if err != nil {
			return false, err
		}
		return false, afpaConflict("public route changed during disable")
	}
	return true, nil
}
func (s *Store) CommitAcornFoxPublicAccess(ctx context.Context, f contracts.AcornFoxPublicAccessFact, _ contracts.AcornFoxPublicRouteIntent, key, digest string, now time.Time) error {
	now = m3Now(s, now)
	r, e := s.db.ExecContext(ctx, `UPDATE acornfox_public_access_commands SET phase='completed',result_status=$5,result_hostname=$6,failure_code=NULL,updated_at=$7 WHERE application_id=$1 AND deployment_id=$2 AND idempotency_key=$3 AND request_digest=$4 AND phase IN ('applying','reconcile_required')`, f.ApplicationID.String(), f.DeploymentID.String(), key, digest, f.Status, f.Hostname, now)
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}
func (s *Store) MarkAcornFoxPublicAccessReconcileRequired(ctx context.Context, a, d domain.ID, k, g string, n time.Time) error {
	_, e := s.db.ExecContext(ctx, `UPDATE acornfox_public_access_commands SET phase='reconcile_required',updated_at=$5 WHERE application_id=$1 AND deployment_id=$2 AND idempotency_key=$3 AND request_digest=$4 AND phase='applying'`, a.String(), d.String(), k, g, m3Now(s, n))
	return e
}
func (s *Store) FailAcornFoxPublicAccess(ctx context.Context, a, d domain.ID, k, g, _ string, n time.Time) error {
	_, e := s.db.ExecContext(ctx, `UPDATE acornfox_public_access_commands SET phase='failed',failure_code='failed',updated_at=$5 WHERE application_id=$1 AND deployment_id=$2 AND idempotency_key=$3 AND request_digest=$4 AND phase='applying'`, a.String(), d.String(), k, g, m3Now(s, n))
	return e
}
func (s *Store) GetAcornFoxPublicAccess(ctx context.Context, a, d domain.ID) (contracts.AcornFoxPublicAccessFact, bool, error) {
	if s.requireDB() != nil {
		return contracts.AcornFoxPublicAccessFact{}, false, s.requireDB()
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return contracts.AcornFoxPublicAccessFact{}, false, e
	}
	if e = afpaAssert(ctx, tx, a, d); e != nil {
		return contracts.AcornFoxPublicAccessFact{}, false, rollbackTx(tx, e)
	}
	fact, found, err := afpaPublicAccessFactTx(ctx, tx, a, d)
	if err != nil {
		return contracts.AcornFoxPublicAccessFact{}, false, rollbackTx(tx, err)
	}
	if err := tx.Commit(); err != nil {
		return contracts.AcornFoxPublicAccessFact{}, false, err
	}
	return fact, found, nil
}

// afpaPublicAccessFactTx projects only durable local facts. A route graph
// proves an accepted endpoint; only a completed matching enable proves the
// local provider configured it. This intentionally has no DNS/TLS/provider
// observation and never claims PUBLIC_READY.
func afpaPublicAccessFactTx(ctx context.Context, tx *sql.Tx, applicationID, deploymentID domain.ID) (contracts.AcornFoxPublicAccessFact, bool, error) {
	routeID := afpaID("route", applicationID.String(), deploymentID.String())
	intent, state, found, err := afpaRouteIntentTx(ctx, tx, applicationID, deploymentID, routeID, false)
	if err != nil {
		return contracts.AcornFoxPublicAccessFact{}, false, err
	}
	if !found {
		return contracts.AcornFoxPublicAccessFact{}, false, nil
	}
	desired := state == "active"
	status := contracts.AcornFoxPublicDisabled
	if desired {
		status = contracts.AcornFoxPublicPendingExternalValidation
	}
	fact := contracts.AcornFoxPublicAccessFact{
		ApplicationID: applicationID, DeploymentID: deploymentID, Hostname: intent.Hostname,
		Status: status, DesiredPublic: desired,
		InternalEndpoint: contracts.AcornFoxInternalEndpointAccepted,
		LocalRoute:       contracts.AcornFoxLocalRouteDisabled,
	}
	if desired {
		fact.LocalRoute = contracts.AcornFoxLocalRouteDesired
	}
	var requested bool
	var phase string
	err = tx.QueryRowContext(ctx, `SELECT requested_enabled,phase
		FROM acornfox_public_access_commands
		WHERE application_id=$1 AND deployment_id=$2
		  AND (route_id=$3 OR route_id IS NULL)
		ORDER BY created_at DESC,updated_at DESC,idempotency_key DESC
		LIMIT 1`, applicationID.String(), deploymentID.String(), routeID.String()).Scan(&requested, &phase)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return contracts.AcornFoxPublicAccessFact{}, false, err
	}
	if err == nil {
		switch phase {
		case "applying", "reconcile_required":
			fact.LocalRoute = contracts.AcornFoxLocalRouteReconcileRequired
		case "completed":
			if requested && desired {
				fact.LocalRoute = contracts.AcornFoxLocalRouteConfigured
			}
		}
	}
	if err := fact.Validate(); err != nil {
		return contracts.AcornFoxPublicAccessFact{}, false, afpaConflict("public access component fact conflicts")
	}
	return fact, true, nil
}
func (s *Store) GetAcornFoxPublicRouteIntent(ctx context.Context, a, d domain.ID) (contracts.AcornFoxPublicRouteIntent, bool, error) {
	if err := s.requireDB(); err != nil {
		return contracts.AcornFoxPublicRouteIntent{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return contracts.AcornFoxPublicRouteIntent{}, false, err
	}
	if err = afpaAssert(ctx, tx, a, d); err != nil {
		return contracts.AcornFoxPublicRouteIntent{}, false, rollbackTx(tx, err)
	}
	intent, _, found, err := afpaRouteIntentTx(ctx, tx, a, d, afpaID("route", a.String(), d.String()), false)
	if err != nil {
		return contracts.AcornFoxPublicRouteIntent{}, false, rollbackTx(tx, err)
	}
	if err = tx.Commit(); err != nil {
		return contracts.AcornFoxPublicRouteIntent{}, false, err
	}
	return intent, found, nil
}

func (s *Store) GetAcornFoxRoutableEndpoint(ctx context.Context, a, d domain.ID) (contracts.AcornFoxRoutableEndpoint, error) {
	r, e := s.GetAcornFoxRuntimeObservation(ctx, a, d)
	if e != nil {
		return contracts.AcornFoxRoutableEndpoint{}, e
	}
	p, e := s.GetLatestAcornFoxProbeObservation(ctx, a, d)
	// Runtime lookup above has already bound the application and deployment.
	// A missing or outdated response is an unmet readiness precondition, not a
	// missing resource. Preserve actual database failures and ownership errors.
	if errors.Is(e, ErrNotFound) {
		return contracts.AcornFoxRoutableEndpoint{}, application.ErrAcornFoxInternalEndpointNotReady
	}
	if e != nil {
		return contracts.AcornFoxRoutableEndpoint{}, e
	}
	if p.Outcome != contracts.AcornFoxProbeOutcomeResponded || p.ObservedAt.Before(r.ObservedAt) {
		return contracts.AcornFoxRoutableEndpoint{}, application.ErrAcornFoxInternalEndpointNotReady
	}
	h, ps, e := net.SplitHostPort(r.InternalAddress)
	if e != nil || !net.ParseIP(h).IsLoopback() {
		return contracts.AcornFoxRoutableEndpoint{}, ErrNotFound
	}
	n, e := strconv.Atoi(ps)
	if e != nil {
		return contracts.AcornFoxRoutableEndpoint{}, ErrNotFound
	}
	return contracts.AcornFoxRoutableEndpoint{ApplicationID: a, DeploymentID: d, ServiceName: r.ServiceName, Port: n, Accepted: true}, nil
}
