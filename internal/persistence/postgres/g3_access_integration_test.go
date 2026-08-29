//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/domain"
)

func TestG3AccessStoreUsesTaskScopedPostgresAndFailsClosedOnServingUnbind(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_G3_ACCESS_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_G3_ACCESS_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateG3AccessDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	resetAuthTestSchema(t, ctx, db)
	applyControlPlaneMigrations(t, ctx, db)

	suffix := strings.ReplaceAll(domain.MustNewID("g3pg").String(), "_", "")
	appID, environmentID := domain.ID("app_"+suffix), domain.ID("env_"+suffix)
	sourceID, definitionID, releaseID, deploymentID := domain.ID("src_"+suffix), domain.ID("def_"+suffix), domain.ID("release_"+suffix), domain.ID("dep_"+suffix)
	if _, err := db.ExecContext(ctx, `INSERT INTO applications(id,name) VALUES($1,'G3 Store')`, appID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO environments(id,application_id,name) VALUES($1,$2,'default')`, environmentID.String(), appID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable) VALUES($1,$2,'upload','upload','upload://g3',$3,$4,$5,'prepared',true)`, sourceID.String(), appID.String(), "fixture-"+suffix, "sha256:"+strings.Repeat("a", 64), "/var/lib/open-card/workspaces/"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration) VALUES($1,$2,$3,1,'{}'::jsonb)`, definitionID.String(), appID.String(), sourceID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO releases(id,application_id,definition_id,version,service_digests) VALUES($1,$2,$3,1,$4::jsonb)`, releaseID.String(), appID.String(), definitionID.String(), `{"frontend":"sha256:`+strings.Repeat("b", 64)+`"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO deployments(id,environment_id,release_id,state,runtime_healthy,host_ip,host_port) VALUES($1,$2,$3,'runtime_ready',true,'198.51.100.25',18080)`, deploymentID.String(), environmentID.String(), releaseID.String()); err != nil {
		t.Fatal(err)
	}

	store := NewStore(db)
	now := time.Unix(1_700_000_000, 0).UTC()
	verifiedAt := now
	const platformVerificationRef = "public-dns-read-only/v2-console-ingress-wildcard"
	platform, _, err := store.PutPlatformDomain(ctx, G3PlatformDomainFact{ID: domain.ID("platform_" + suffix), BaseDomain: "example.test", VerificationRef: platformVerificationRef, VerificationStatus: G3VerificationVerified, VerifiedAt: &verifiedAt, CreatedAt: now, UpdatedAt: now}, g3TestIdempotency("g3.platform-domain.put.v2", "platform-"+suffix))
	if err != nil || platform.BaseDomain != "example.test" || platform.VerificationRef != platformVerificationRef {
		t.Fatalf("platform=%+v err=%v", platform, err)
	}
	storedPlatform, found, err := store.PlatformDomain(ctx)
	if err != nil || !found || storedPlatform.VerificationRef != platformVerificationRef {
		t.Fatalf("stored platform=%+v found=%v err=%v", storedPlatform, found, err)
	}
	if _, _, err := store.PutPlatformDomain(ctx, G3PlatformDomainFact{ID: domain.ID("platform_other_" + suffix), BaseDomain: "other.test", VerificationStatus: G3VerificationPending, CreatedAt: now, UpdatedAt: now}, g3TestIdempotency("g3.platform-domain.put", "platform-other-"+suffix)); !errors.Is(err, ErrG3AccessConflict) {
		t.Fatalf("singleton platform conflict=%v", err)
	}
	bindRequest := g3TestIdempotency("g3.application-domain.bind", "bind-"+suffix)
	domainFact, created, err := store.BindCustomDomain(ctx, G3ApplicationDomainFact{ID: domain.ID("domain_" + suffix), ApplicationID: appID, Hostname: "www.customer.test", Kind: "custom", CNAME: "ingress.example.test", VerificationStatus: G3VerificationPending, CreatedAt: now, UpdatedAt: now}, bindRequest)
	if err != nil || !created {
		t.Fatalf("bind domain=%+v created=%v err=%v", domainFact, created, err)
	}
	if replay, replayCreated, err := store.BindCustomDomain(ctx, domainFact, bindRequest); err != nil || replayCreated || replay.ID != domainFact.ID {
		t.Fatalf("bind replay=%+v created=%v err=%v", replay, replayCreated, err)
	}
	conflictingRequest := bindRequest
	conflictingRequest.Digest = "sha256:" + strings.Repeat("d", 64)
	if _, _, err := store.BindCustomDomain(ctx, domainFact, conflictingRequest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("bind idempotency conflict=%v", err)
	}
	domainFact, _, err = store.SetApplicationDomainVerification(ctx, appID, domainFact.ID, G3VerificationVerified, &verifiedAt, g3TestIdempotency("g3.application-domain.verify", "verify-"+suffix))
	if err != nil || domainFact.VerificationStatus != G3VerificationVerified {
		t.Fatalf("verify domain=%+v err=%v", domainFact, err)
	}
	routeID, leaseID := "route_"+suffix, "lease_"+suffix
	if _, err := db.ExecContext(ctx, `INSERT INTO m3_port_leases(id,application_id,deployment_id,service_name,bind_host,port,acquired_at) VALUES($1,$2,$3,'frontend','127.0.0.1',18080,$4)`, leaseID, appID.String(), deploymentID.String(), verifiedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO m3_desired_routes(id,application_id,application_domain_id,deployment_id,service_name,hostname,path_prefix,desired_state,verified,serving) VALUES($1,$2,$3,$4,'frontend',$5,'/','active',true,true)`, routeID, appID.String(), domainFact.ID.String(), deploymentID.String(), domainFact.Hostname); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO m3_route_pointers(route_id,deployment_id,port_lease_id,revision,updated_at) VALUES($1,$2,$3,1,$4)`, routeID, deploymentID.String(), leaseID, verifiedAt); err != nil {
		t.Fatal(err)
	}
	access, err := store.ApplicationAccessFacts(ctx, appID)
	if err != nil || !access.Runtime.RuntimeReady || access.Runtime.IPFallback == nil || *access.Runtime.IPFallback != "http://198.51.100.25:18080" || len(access.Routes) != 1 || !access.Routes[0].Serving {
		t.Fatalf("access=%+v err=%v", access, err)
	}
	if _, err := store.UnbindCustomDomain(ctx, appID, domainFact.ID, "admin_1", g3TestIdempotency("g3.application-domain.unbind", "unbind-conflict-"+suffix)); !errors.Is(err, ErrG3AccessConflict) {
		t.Fatalf("serving unbind=%v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE m3_desired_routes SET serving=false WHERE id=$1`, routeID); err != nil {
		t.Fatal(err)
	}
	unbindRequest := g3TestIdempotency("g3.application-domain.unbind", "unbind-"+suffix)
	if _, err := store.UnbindCustomDomain(ctx, appID, domainFact.ID, "admin_1", unbindRequest); err != nil {
		t.Fatal(err)
	}
	if replay, err := store.UnbindCustomDomain(ctx, appID, domainFact.ID, "admin_1", unbindRequest); err != nil || !replay {
		t.Fatalf("unbind replay=%v err=%v", replay, err)
	}
	if _, found, err := store.ApplicationDomain(ctx, appID, domainFact.ID); err != nil || found {
		t.Fatalf("unbound domain found=%v err=%v", found, err)
	}
}

func g3TestIdempotency(scope, key string) G3Idempotency {
	return G3Idempotency{Scope: scope, Key: key, Digest: "sha256:" + strings.Repeat("c", 64)}
}

func validateG3AccessDSN(t *testing.T, dsn string) {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("task-scoped G3 access database URL is invalid")
	}
	if host := parsed.Hostname(); host != "127.0.0.1" && host != "::1" && host != "localhost" {
		t.Fatal("task-scoped G3 access database must be loopback-only")
	}
	if database := strings.TrimPrefix(parsed.EscapedPath(), "/"); !strings.HasPrefix(database, "open_card_g3access_") {
		t.Fatal("task-scoped G3 access database name must use open_card_g3access_ prefix")
	}
}
