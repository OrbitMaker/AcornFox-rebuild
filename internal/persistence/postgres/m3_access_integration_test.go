//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/domain"
)

// TestM3AccessFactsPersistAndSwitchAtomically uses only task-scoped PostgreSQL.
// It requires that the normal migration runner has applied M0 through M3.
func TestM3AccessFactsPersistAndSwitchAtomically(t *testing.T) {
	dsn := os.Getenv("OPEN_CARD_TEST_DATABASE_URL")
	if strings.TrimSpace(dsn) == "" {
		t.Skip("OPEN_CARD_TEST_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	store := NewStore(db)
	suffix := strings.ToLower(domain.MustNewID("m3pg").String())
	dnsSuffix := strings.ReplaceAll(suffix[:12], "_", "-")
	appID, environmentID := domain.ID("app_"+suffix), domain.ID("env_"+suffix)
	sourceID, definitionID := domain.ID("src_"+suffix), domain.ID("def_"+suffix)
	releaseID := domain.ID("release_" + suffix)
	deploymentOne, deploymentTwo := domain.ID("dep1_"+suffix), domain.ID("dep2_"+suffix)
	if _, err := db.ExecContext(ctx, `INSERT INTO applications(id,name) VALUES($1,$2)`, appID.String(), "m3-persistence-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO environments(id,application_id,name) VALUES($1,$2,'m3')`, environmentID.String(), appID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable) VALUES($1,$2,'upload','upload','upload://m3',$3,$4,$5,'prepared',true)`, sourceID.String(), appID.String(), "upload-"+suffix, "sha256:"+strings.Repeat("a", 64), "/var/lib/open-card/workspaces/"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration) VALUES($1,$2,$3,1,'{}'::jsonb)`, definitionID.String(), appID.String(), sourceID.String()); err != nil {
		t.Fatal(err)
	}
	serviceDigests := `{"frontend":"sha256:` + strings.Repeat("d", 64) + `"}`
	if _, err := db.ExecContext(ctx, `INSERT INTO releases(id,application_id,definition_id,version,service_digests) VALUES($1,$2,$3,1,$4::jsonb)`, releaseID.String(), appID.String(), definitionID.String(), serviceDigests); err != nil {
		t.Fatal(err)
	}
	for _, deploymentID := range []domain.ID{deploymentOne, deploymentTwo} {
		if _, err := db.ExecContext(ctx, `INSERT INTO deployments(id,environment_id,release_id,state) VALUES($1,$2,$3,'runtime_ready')`, deploymentID.String(), environmentID.String(), releaseID.String()); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	platformID, appDomainID := domain.ID("platform_"+suffix), domain.ID("domain_"+suffix)
	if err := store.UpsertPlatformDomain(ctx, PlatformDomainRecord{ID: platformID, Hostname: "apps-" + dnsSuffix + ".example.test", DNSProviderRef: "fixture:dns", VerificationStatus: DomainVerificationVerified, WildcardEnabled: true, VerifiedAt: &now}, now); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertApplicationDomain(ctx, ApplicationDomainRecord{ID: appDomainID, ApplicationID: appID, PlatformDomainID: platformID, Hostname: "card-" + dnsSuffix + ".apps-" + dnsSuffix + ".example.test", Kind: "platform", StableSlug: "card-" + dnsSuffix, VerificationMethod: "dns01", VerificationStatus: DomainVerificationVerified, VerifiedAt: &now}, now); err != nil {
		t.Fatal(err)
	}
	secretID := domain.ID("secret_" + suffix)
	if _, err := db.ExecContext(ctx, `INSERT INTO secret_references(id,application_id,name,ciphertext,key_version) VALUES($1,$2,$3,$4,$5)`, secretID.String(), appID.String(), "tls-"+suffix, []byte("encrypted-fixture"), "fixture-v1"); err != nil {
		t.Fatal(err)
	}
	certificateID := domain.ID("cert_" + suffix)
	hostname := "card-" + dnsSuffix + ".apps-" + dnsSuffix + ".example.test"
	if err := store.UpsertCertificateReference(ctx, CertificateReference{ID: certificateID, ApplicationDomainID: appDomainID, SecretReferenceID: secretID, SubjectHostname: hostname, Issuer: "acme-staging", Status: CertificateReferenceReady, NotBefore: &now, NotAfter: pointerM3Time(now.Add(24 * time.Hour))}, now); err != nil {
		t.Fatal(err)
	}
	routeID := domain.ID("route_" + suffix)
	route := DesiredRouteRecord{Route: domain.Route{ID: routeID, ApplicationID: appID, DeploymentID: deploymentOne, ServiceName: "frontend", Host: hostname, Path: "/", CertificateRef: certificateID.String(), Verified: true, Serving: true, CreatedAt: now}, ApplicationDomainID: appDomainID, CertificateID: certificateID, State: DesiredRouteActive}
	if err := store.UpsertDesiredRoute(ctx, route, now); err != nil {
		t.Fatal(err)
	}
	leaseOne, leaseTwo := domain.ID("lease1_"+suffix), domain.ID("lease2_"+suffix)
	for _, lease := range []PortLease{{ID: leaseOne, ApplicationID: appID, DeploymentID: deploymentOne, ServiceName: "frontend", BindHost: "127.0.0.1", Port: 18081, AcquiredAt: now}, {ID: leaseTwo, ApplicationID: appID, DeploymentID: deploymentTwo, ServiceName: "frontend", BindHost: "127.0.0.1", Port: 18082, AcquiredAt: now}} {
		if err := store.CreatePortLease(ctx, lease, now); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.CommitTrafficSwitch(ctx, TrafficSwitchRecord{ID: domain.ID("switch1_" + suffix), ApplicationID: appID, RouteID: routeID, NextDeploymentID: deploymentOne, Status: TrafficSwitchSwitched, Reason: "initial healthy target"}, RoutePointer{PortLeaseID: leaseOne}, 0, now)
	if err != nil || first.Revision != 1 || first.DeploymentID != deploymentOne {
		t.Fatalf("initial pointer mismatch: pointer=%+v err=%v", first, err)
	}
	second, err := store.CommitTrafficSwitch(ctx, TrafficSwitchRecord{ID: domain.ID("switch2_" + suffix), ApplicationID: appID, RouteID: routeID, PreviousDeploymentID: deploymentOne, NextDeploymentID: deploymentTwo, Status: TrafficSwitchSwitched, Reason: "new target passed health"}, RoutePointer{PortLeaseID: leaseTwo}, first.Revision, now.Add(time.Second))
	if err != nil || second.Revision != 2 || second.DeploymentID != deploymentTwo {
		t.Fatalf("atomic switch mismatch: pointer=%+v err=%v", second, err)
	}
	if _, err := store.CommitTrafficSwitch(ctx, TrafficSwitchRecord{ID: domain.ID("switch3_" + suffix), ApplicationID: appID, RouteID: routeID, PreviousDeploymentID: deploymentTwo, NextDeploymentID: deploymentOne, Status: TrafficSwitchSwitched, Reason: "stale compare and swap"}, RoutePointer{PortLeaseID: leaseOne}, first.Revision, now.Add(2*time.Second)); !errors.Is(err, ErrRoutePointerConflict) {
		t.Fatalf("stale route pointer did not fail closed: %v", err)
	}
	routes, err := store.ListDesiredRoutes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var projection *DesiredRouteProjection
	for index := range routes {
		if routes[index].Route.ID == routeID {
			projection = &routes[index]
			break
		}
	}
	if projection == nil || projection.Pointer == nil || projection.Lease == nil || projection.Pointer.DeploymentID != deploymentTwo || projection.Lease.ID != leaseTwo {
		t.Fatalf("Caddy rebuild projection does not contain switched route: %+v", projection)
	}
	if _, err := db.ExecContext(ctx, `UPDATE m3_traffic_switches SET reason='mutated' WHERE id=$1`, "switch2_"+suffix); err == nil {
		t.Fatal("immutable traffic switch history update was accepted")
	}
	duplicate := route
	duplicate.Route.ID = domain.ID("route-duplicate_" + suffix)
	if err := store.UpsertDesiredRoute(ctx, duplicate, now); err == nil {
		t.Fatal("duplicate canonical hostname/path was accepted")
	}
}
