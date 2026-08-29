package postgres

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/domain"
)

func TestTLSAllowDesiredRouteRequiresCertificateFreePendingFact(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	record := DesiredRouteRecord{Route: domain.Route{ID: "route_tls", ApplicationID: "app_1", DeploymentID: "dep_1", ServiceName: "web", Host: "app.example.test", Path: "/", Verified: true, CreatedAt: now}, ApplicationDomainID: "domain_1", State: DesiredRoutePending}
	if err := record.Validate(); err != nil {
		t.Fatalf("valid TLS allow desired route rejected: %v", err)
	}
	record.Route.CertificateRef = "cert_1"
	if err := record.Validate(); err == nil {
		t.Fatal("certificate-bound pending route was accepted for TLS allow")
	}
}

func TestTLSAllowStateOnTaskScopedPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_TLS_ALLOW_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_TLS_ALLOW_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateTLSAllowTestDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		resetAuthTestSchema(t, context.Background(), db)
		_ = db.Close()
	}()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	resetAuthTestSchema(t, ctx, db)
	applyControlPlaneMigrations(t, ctx, db)
	store := NewStore(db)
	now := time.Unix(1_700_000_000, 0).UTC()
	app, environment, source, definition, release, deployment := domain.ID("app_tls_allow"), domain.ID("env_tls_allow"), domain.ID("src_tls_allow"), domain.ID("def_tls_allow"), domain.ID("release_tls_allow"), domain.ID("dep_tls_allow")
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO applications(id,name) VALUES($1,'tls allow')`, []any{app.String()}},
		{`INSERT INTO environments(id,application_id,name) VALUES($1,$2,'default')`, []any{environment.String(), app.String()}},
		{`INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable) VALUES($1,$2,'upload','upload','upload://tls','main',$3,'/tmp/tls','prepared',true)`, []any{source.String(), app.String(), "sha256:" + strings.Repeat("a", 64)}},
		{`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration) VALUES($1,$2,$3,1,'{}'::jsonb)`, []any{definition.String(), app.String(), source.String()}},
		{`INSERT INTO releases(id,application_id,definition_id,version,service_digests) VALUES($1,$2,$3,1,$4::jsonb)`, []any{release.String(), app.String(), definition.String(), `{"web":"sha256:` + strings.Repeat("b", 64) + `"}`}},
		{`INSERT INTO deployments(id,environment_id,release_id,state,runtime_healthy) VALUES($1,$2,$3,'runtime_ready',true)`, []any{deployment.String(), environment.String(), release.String()}},
	} {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	binding := ApplicationDomainRecord{ID: "domain_tls_allow", ApplicationID: app, Hostname: "app.tls-allow.example.test", Kind: "custom", VerificationMethod: "cname", VerificationStatus: DomainVerificationVerified, VerificationRef: "ingress.example.test", VerifiedAt: &now}
	if err := store.UpsertApplicationDomain(ctx, binding, now); err != nil {
		t.Fatal(err)
	}
	route := domain.Route{ID: "route_tls_allow", ApplicationID: app, DeploymentID: deployment, ServiceName: "web", Host: binding.Hostname, Path: "/", Verified: true, Serving: false, CreatedAt: now}
	occupied := PortLease{ID: "lease_tls_occupied", ApplicationID: app, DeploymentID: deployment, ServiceName: "occupied", BindHost: "127.0.0.1", Port: 18082, AcquiredAt: now}
	if err := store.CreatePortLease(ctx, occupied, now); err != nil {
		t.Fatal(err)
	}
	conflicting := route
	conflicting.ID, conflicting.Path, conflicting.ServiceName = "route_tls_conflict", "/api", "api"
	if err := store.PrepareTLSAllowDesiredRoutes(ctx, binding.ID, []TLSAllowPreparedRoute{{Route: route, Port: 18081}, {Route: conflicting, Port: 18082}}, now); err == nil {
		t.Fatal("second target port conflict was accepted")
	}
	var partialCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m3_desired_routes WHERE id IN ($1,$2)`, route.ID.String(), conflicting.ID.String()).Scan(&partialCount); err != nil || partialCount != 0 {
		t.Fatalf("conflicting batch left desired routes: count=%d err=%v", partialCount, err)
	}
	if err := store.PrepareTLSAllowDesiredRoutes(ctx, binding.ID, []TLSAllowPreparedRoute{{Route: route, Port: 18081}}, now); err != nil {
		t.Fatal(err)
	}
	if err := store.PrepareTLSAllowDesiredRoutes(ctx, binding.ID, []TLSAllowPreparedRoute{{Route: route, Port: 18081}}, now.Add(time.Second)); err != nil {
		t.Fatalf("repeat TLS allow preparation: %v", err)
	}
	state, err := store.TLSAllowState(ctx, binding.Hostname)
	if err != nil || state.Allowed() || state.RouteDesired {
		t.Fatalf("pending route state=%#v err=%v", state, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE m3_desired_routes SET desired_state='active' WHERE id=$1`, route.ID.String()); err != nil {
		t.Fatal(err)
	}
	leaseID := tlsAllowLeaseID(route.ApplicationID, route.DeploymentID, route.ServiceName, 18081)
	if _, err := db.ExecContext(ctx, `INSERT INTO m3_route_pointers(route_id,deployment_id,port_lease_id,revision,updated_at) VALUES($1,$2,$3,1,$4)`, route.ID.String(), deployment.String(), leaseID.String(), now); err != nil {
		t.Fatal(err)
	}
	if state, err = store.TLSAllowState(ctx, binding.Hostname); err != nil || !state.Allowed() {
		t.Fatalf("active first issuance state=%#v err=%v", state, err)
	}
	t.Run("active route requires an intact pointer and loopback lease", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, `DELETE FROM m3_route_pointers WHERE route_id=$1`, route.ID.String()); err != nil {
			t.Fatal(err)
		}
		if got, err := store.TLSAllowState(ctx, binding.Hostname); err != nil || got.Allowed() || !got.DisabledOrFailed {
			t.Fatalf("missing pointer state=%#v err=%v", got, err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO m3_route_pointers(route_id,deployment_id,port_lease_id,revision,updated_at) VALUES($1,$2,$3,2,$4)`, route.ID.String(), deployment.String(), leaseID.String(), now); err != nil {
			t.Fatal(err)
		}

		otherLease := domain.ID("lease_tls_allow_other")
		if _, err := db.ExecContext(ctx, `INSERT INTO m3_port_leases(id,application_id,deployment_id,service_name,bind_host,port,acquired_at) VALUES($1,$2,$3,'api','127.0.0.1',18083,$4)`, otherLease.String(), app.String(), deployment.String(), now); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE m3_route_pointers SET port_lease_id=$2,revision=3 WHERE route_id=$1`, route.ID.String(), otherLease.String()); err != nil {
			t.Fatal(err)
		}
		if got, err := store.TLSAllowState(ctx, binding.Hostname); err != nil || got.Allowed() || !got.DisabledOrFailed {
			t.Fatalf("conflicting lease state=%#v err=%v", got, err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE m3_route_pointers SET port_lease_id=$2,revision=4 WHERE route_id=$1`, route.ID.String(), leaseID.String()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("released expired and unhealthy targets deny", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, `UPDATE m3_port_leases SET released_at=$2 WHERE id=$1`, leaseID.String(), now); err != nil {
			t.Fatal(err)
		}
		if got, err := store.TLSAllowState(ctx, binding.Hostname); err != nil || got.Allowed() || !got.DisabledOrFailed {
			t.Fatalf("released lease state=%#v err=%v", got, err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE m3_port_leases SET released_at=NULL,expires_at=$2 WHERE id=$1`, leaseID.String(), now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if got, err := store.TLSAllowState(ctx, binding.Hostname); err != nil || got.Allowed() || !got.DisabledOrFailed {
			t.Fatalf("expired lease state=%#v err=%v", got, err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE m3_port_leases SET expires_at=NULL WHERE id=$1`, leaseID.String()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("an unsafe active route cannot be masked by a safe route", func(t *testing.T) {
		unsafeRoute := route
		unsafeRoute.ID, unsafeRoute.Path = "route_tls_allow_unsafe", "/unsafe"
		if err := store.UpsertDesiredRoute(ctx, DesiredRouteRecord{Route: unsafeRoute, ApplicationDomainID: binding.ID, State: DesiredRouteActive}, now); err != nil {
			t.Fatal(err)
		}
		if got, err := store.TLSAllowState(ctx, binding.Hostname); err != nil || got.Allowed() || !got.DisabledOrFailed {
			t.Fatalf("mixed safe and unsafe route state=%#v err=%v", got, err)
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM m3_desired_routes WHERE id=$1`, unsafeRoute.ID.String()); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := db.ExecContext(ctx, `UPDATE deployments SET state='failed', runtime_healthy=false WHERE id=$1`, deployment.String()); err != nil {
		t.Fatal(err)
	}
	if state, err = store.TLSAllowState(ctx, binding.Hostname); err != nil || state.Allowed() {
		t.Fatalf("unhealthy runtime allow state=%#v err=%v", state, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE deployments SET state='runtime_ready', runtime_healthy=true WHERE id=$1`, deployment.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE m3_desired_routes SET desired_state='disabled' WHERE id=$1`, route.ID.String()); err != nil {
		t.Fatal(err)
	}
	if state, err = store.TLSAllowState(ctx, binding.Hostname); err != nil || state.Allowed() || !state.DisabledOrFailed {
		t.Fatalf("disabled route allow state=%#v err=%v", state, err)
	}
	if err := store.UpsertTLSAllowDesiredRoute(ctx, binding.ID, route, now.Add(2*time.Second)); err != nil {
		t.Fatalf("restore TLS allow desired route: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE m3_desired_routes SET desired_state='active' WHERE id=$1`, route.ID.String()); err != nil {
		t.Fatal(err)
	}
	observationRef := domain.ID("edge-caddy-observation:sha256:" + strings.Repeat("c", 64))
	certificateID := domain.ID("cert_tls_allow")
	certificateNow := time.Now().UTC()
	if err := store.UpsertCertificateReference(ctx, CertificateReference{ID: certificateID, ApplicationDomainID: binding.ID, SecretReferenceID: observationRef, SubjectHostname: binding.Hostname, Issuer: "edge-caddy-observation", Status: CertificateReferenceReady, NotBefore: &certificateNow, NotAfter: pointerM3Time(certificateNow.Add(time.Hour))}, now); err != nil {
		t.Fatal(err)
	}
	servingRoute := route
	servingRoute.CertificateRef, servingRoute.Serving = certificateID.String(), true
	if err := store.UpsertDesiredRoute(ctx, DesiredRouteRecord{Route: servingRoute, ApplicationDomainID: binding.ID, CertificateID: certificateID, State: DesiredRouteActive}, now.Add(3*time.Second)); err != nil {
		t.Fatalf("promote prepared route after certificate readiness: %v", err)
	}
	items, err := store.ListDesiredRoutes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Route.ID != route.ID || !items[0].Route.Serving || items[0].Route.CertificateRef != certificateID.String() || items[0].State != DesiredRouteActive {
		t.Fatalf("prepared route was not promoted in place: %#v", items)
	}
	if state, err = store.TLSAllowState(ctx, binding.Hostname); err != nil || !state.Allowed() {
		t.Fatalf("serving renewal state=%#v err=%v", state, err)
	}

	t.Run("expired strict observation remains eligible for edge reissuance", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, `UPDATE m3_certificate_references SET not_before=CURRENT_TIMESTAMP - INTERVAL '2 hours',not_after=CURRENT_TIMESTAMP - INTERVAL '1 minute' WHERE id=$1`, certificateID.String()); err != nil {
			t.Fatal(err)
		}
		if got, err := store.TLSAllowState(ctx, binding.Hostname); err != nil || !got.Allowed() || got.DisabledOrFailed {
			t.Fatalf("expired strict observation TLS allow=%#v err=%v", got, err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE m3_certificate_references SET status='failed' WHERE id=$1`, certificateID.String()); err != nil {
			t.Fatal(err)
		}
		if got, err := store.TLSAllowState(ctx, binding.Hostname); err != nil || got.Allowed() || !got.DisabledOrFailed {
			t.Fatalf("failed observation TLS allow=%#v err=%v", got, err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE m3_certificate_references SET status='ready',secret_reference_id='unobserved-certificate' WHERE id=$1`, certificateID.String()); err != nil {
			t.Fatal(err)
		}
		if got, err := store.TLSAllowState(ctx, binding.Hostname); err != nil || got.Allowed() || !got.DisabledOrFailed {
			t.Fatalf("unobserved certificate TLS allow=%#v err=%v", got, err)
		}
	})

	t.Run("same owner rebind resurrects disabled stable route and stale pointer rejects", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, `DELETE FROM m3_route_pointers WHERE route_id=$1`, route.ID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE m3_desired_routes SET application_domain_id=NULL,certificate_reference_id=NULL,desired_state='disabled',serving=false WHERE id=$1`, route.ID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM m3_certificate_references WHERE id=$1`, certificateID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM m3_application_domains WHERE id=$1`, binding.ID.String()); err != nil {
			t.Fatal(err)
		}
		if err := store.UpsertApplicationDomain(ctx, binding, now.Add(4*time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := store.PrepareTLSAllowDesiredRoutes(ctx, binding.ID, []TLSAllowPreparedRoute{{Route: route, Port: 18081}}, now.Add(4*time.Second)); err != nil {
			t.Fatalf("same-owner rebind: %v", err)
		}
		var domainID, state string
		var serving bool
		if err := db.QueryRowContext(ctx, `SELECT COALESCE(application_domain_id,''),desired_state,serving FROM m3_desired_routes WHERE id=$1`, route.ID.String()).Scan(&domainID, &state, &serving); err != nil || domainID != binding.ID.String() || state != "pending" || serving {
			t.Fatalf("resurrected route domain=%s state=%s serving=%v err=%v", domainID, state, serving, err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE m3_desired_routes SET application_domain_id=NULL,desired_state='disabled',serving=false WHERE id=$1`, route.ID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM m3_application_domains WHERE id=$1`, binding.ID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO m3_route_pointers(route_id,deployment_id,port_lease_id,revision,updated_at) VALUES($1,$2,$3,1,$4)`, route.ID.String(), deployment.String(), leaseID.String(), now.Add(5*time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := store.UpsertApplicationDomain(ctx, binding, now.Add(5*time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := store.PrepareTLSAllowDesiredRoutes(ctx, binding.ID, []TLSAllowPreparedRoute{{Route: route, Port: 18081}}, now.Add(5*time.Second)); err == nil {
			t.Fatal("same-owner rebind accepted stale pointer")
		}
	})

	t.Run("detached rebind history cannot deny current same owner or cross app facts", func(t *testing.T) {
		sameHost := "same-rebind.tls-allow.example.test"
		sameBinding := ApplicationDomainRecord{ID: "domain_tls_same_rebind", ApplicationID: app, Hostname: sameHost, Kind: "custom", VerificationMethod: "cname", VerificationStatus: DomainVerificationVerified, VerificationRef: "ingress.example.test", VerifiedAt: &now}
		if err := store.UpsertApplicationDomain(ctx, sameBinding, now); err != nil {
			t.Fatal(err)
		}
		historical := domain.Route{ID: "route_tls_same_history", ApplicationID: app, DeploymentID: deployment, ServiceName: "web", Host: sameHost, Path: "/", Verified: true, CreatedAt: now}
		if err := store.UpsertDesiredRoute(ctx, DesiredRouteRecord{Route: historical, State: DesiredRouteDisabled}, now); err != nil {
			t.Fatal(err)
		}
		current := historical
		current.ID = "route_tls_same_current"
		if err := store.UpsertDesiredRoute(ctx, DesiredRouteRecord{Route: current, ApplicationDomainID: sameBinding.ID, State: DesiredRouteActive}, now); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO m3_route_pointers(route_id,deployment_id,port_lease_id,revision,updated_at) VALUES($1,$2,$3,1,$4)`, current.ID.String(), deployment.String(), leaseID.String(), now); err != nil {
			t.Fatal(err)
		}
		if got, err := store.TLSAllowState(ctx, sameHost); err != nil || !got.Allowed() || got.DisabledOrFailed {
			t.Fatalf("detached same-owner history state=%#v err=%v", got, err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE m3_desired_routes SET application_domain_id=$2 WHERE id=$1`, historical.ID.String(), sameBinding.ID.String()); err != nil {
			t.Fatal(err)
		}
		if got, err := store.TLSAllowState(ctx, sameHost); err != nil || got.Allowed() || !got.DisabledOrFailed {
			t.Fatalf("attached same-owner historical failure state=%#v err=%v", got, err)
		}

		crossApp, crossEnvironment, crossSource, crossDefinition, crossRelease, crossDeployment := domain.ID("app_tls_cross_rebind"), domain.ID("env_tls_cross_rebind"), domain.ID("src_tls_cross_rebind"), domain.ID("def_tls_cross_rebind"), domain.ID("release_tls_cross_rebind"), domain.ID("dep_tls_cross_rebind")
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO applications(id,name) VALUES($1,'tls cross rebind')`, []any{crossApp.String()}},
			{`INSERT INTO environments(id,application_id,name) VALUES($1,$2,'default')`, []any{crossEnvironment.String(), crossApp.String()}},
			{`INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable) VALUES($1,$2,'upload','upload','upload://tls-cross','main',$3,'/tmp/tls-cross','prepared',true)`, []any{crossSource.String(), crossApp.String(), "sha256:" + strings.Repeat("c", 64)}},
			{`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration) VALUES($1,$2,$3,1,'{}'::jsonb)`, []any{crossDefinition.String(), crossApp.String(), crossSource.String()}},
			{`INSERT INTO releases(id,application_id,definition_id,version,service_digests) VALUES($1,$2,$3,1,$4::jsonb)`, []any{crossRelease.String(), crossApp.String(), crossDefinition.String(), `{"web":"sha256:` + strings.Repeat("d", 64) + `"}`}},
			{`INSERT INTO deployments(id,environment_id,release_id,state,runtime_healthy) VALUES($1,$2,$3,'runtime_ready',true)`, []any{crossDeployment.String(), crossEnvironment.String(), crossRelease.String()}},
		} {
			if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
				t.Fatal(err)
			}
		}
		crossHost := "cross-rebind.tls-allow.example.test"
		crossHistorical := domain.Route{ID: "route_tls_cross_history", ApplicationID: app, DeploymentID: deployment, ServiceName: "web", Host: crossHost, Path: "/", Verified: true, CreatedAt: now}
		if err := store.UpsertDesiredRoute(ctx, DesiredRouteRecord{Route: crossHistorical, State: DesiredRouteFailed}, now); err != nil {
			t.Fatal(err)
		}
		crossBinding := ApplicationDomainRecord{ID: "domain_tls_cross_rebind", ApplicationID: crossApp, Hostname: crossHost, Kind: "custom", VerificationMethod: "cname", VerificationStatus: DomainVerificationVerified, VerificationRef: "ingress.example.test", VerifiedAt: &now}
		if err := store.UpsertApplicationDomain(ctx, crossBinding, now); err != nil {
			t.Fatal(err)
		}
		crossRoute := domain.Route{ID: "route_tls_cross_current", ApplicationID: crossApp, DeploymentID: crossDeployment, ServiceName: "web", Host: crossHost, Path: "/", Verified: true, CreatedAt: now}
		if err := store.UpsertDesiredRoute(ctx, DesiredRouteRecord{Route: crossRoute, ApplicationDomainID: crossBinding.ID, State: DesiredRouteActive}, now); err != nil {
			t.Fatal(err)
		}
		crossLease := PortLease{ID: "lease_tls_cross_rebind", ApplicationID: crossApp, DeploymentID: crossDeployment, ServiceName: "web", BindHost: "127.0.0.1", Port: 18185, AcquiredAt: now}
		if err := store.CreatePortLease(ctx, crossLease, now); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO m3_route_pointers(route_id,deployment_id,port_lease_id,revision,updated_at) VALUES($1,$2,$3,1,$4)`, crossRoute.ID.String(), crossDeployment.String(), crossLease.ID.String(), now); err != nil {
			t.Fatal(err)
		}
		if got, err := store.TLSAllowState(ctx, crossHost); err != nil || !got.Allowed() || got.DisabledOrFailed {
			t.Fatalf("detached cross-app history state=%#v err=%v", got, err)
		}
	})
}

func validateTLSAllowTestDSN(t *testing.T, dsn string) {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("task-scoped TLS allow database URL is invalid")
	}
	if host := parsed.Hostname(); host != "127.0.0.1" && host != "::1" && host != "localhost" {
		t.Fatal("task-scoped TLS allow database must be loopback-only")
	}
	if database := strings.TrimPrefix(parsed.EscapedPath(), "/"); !strings.HasPrefix(database, "open_card_g2tls_") {
		t.Fatal("task-scoped TLS allow database name must use open_card_g2tls_ prefix")
	}
}
