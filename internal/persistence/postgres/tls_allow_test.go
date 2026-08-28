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
	if err != nil || !state.Allowed() {
		t.Fatalf("first issuance state=%#v err=%v", state, err)
	}
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
	secretID := domain.ID("secret_tls_allow")
	if _, err := db.ExecContext(ctx, `INSERT INTO secret_references(id,application_id,name,ciphertext,key_version) VALUES($1,$2,'tls-allow',$3,'fixture-v1')`, secretID.String(), app.String(), []byte("encrypted-fixture")); err != nil {
		t.Fatal(err)
	}
	certificateID := domain.ID("cert_tls_allow")
	if err := store.UpsertCertificateReference(ctx, CertificateReference{ID: certificateID, ApplicationDomainID: binding.ID, SecretReferenceID: secretID, SubjectHostname: binding.Hostname, Issuer: "internal-test-ca", Status: CertificateReferenceReady, NotBefore: &now, NotAfter: pointerM3Time(now.Add(time.Hour))}, now); err != nil {
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
