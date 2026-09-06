//go:build integration

package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// These tests are deliberately opt-in and task-scoped. Unlike the older
// integration helpers, setting the task URL never permits a silent skip.
func TestAcornFoxPublicAccessPostgresRecoveryAndM3Truth(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_DNS10_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_DNS10_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateAcornFoxDNS10DSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	applyAcornFoxDNS10Migrations(t, ctx, db)

	fixture := seedAcornFoxDNS10Fixture(t, ctx, db)
	store := postgres.NewStore(db)

	t.Run("missing and cross app reads are disabled or not found", func(t *testing.T) {
		fact, err := (&application.AcornFoxPublicAccessService{Store: store, Router: &dns10Router{}, Config: application.AcornFoxPublicAccessConfig{AuthorizedRoot: "example.test"}}).Get(ctx, fixture.app, fixture.dep)
		if err != nil || fact.Status != contracts.AcornFoxPublicDisabled {
			t.Fatalf("missing fact=%+v err=%v", fact, err)
		}
		_, err = (&application.AcornFoxPublicAccessService{Store: store, Router: &dns10Router{}, Config: application.AcornFoxPublicAccessConfig{AuthorizedRoot: "example.test"}}).Get(ctx, "other_app", fixture.dep)
		if err == nil {
			t.Fatal("cross-app read unexpectedly succeeded")
		}
	})

	endpoint, err := store.GetAcornFoxRoutableEndpoint(ctx, fixture.app, fixture.dep)
	if err != nil {
		rq, re := store.GetAcornFoxRuntimeRequest(ctx, fixture.app, fixture.dep)
		ob, oe := store.GetAcornFoxRuntimeObservation(ctx, fixture.app, fixture.dep)
		pr, pe := store.GetLatestAcornFoxProbeObservation(ctx, fixture.app, fixture.dep)
		t.Fatalf("endpoint=%v runtime_request=%+v/%v runtime_observation=%+v/%v probe=%+v/%v", err, rq, re, ob, oe, pr, pe)
	}
	host, err := contracts.AcornFoxPublicHostname("example.test", fixture.app, fixture.dep)
	if err != nil {
		t.Fatal(err)
	}
	intent := contracts.AcornFoxPublicRouteIntent{ApplicationID: fixture.app, DeploymentID: fixture.dep, Hostname: host, ServiceName: endpoint.ServiceName, Port: endpoint.Port}
	digest := dns10Digest(fixture.app, fixture.dep, true, host)
	key := "dns10-enable"
	if _, replay, err := store.BeginAcornFoxPublicAccess(ctx, dns10Fact(fixture.app, fixture.dep, host, true, contracts.AcornFoxLocalRouteDesired), intent, true, key, digest, fixture.now); err != nil || replay {
		t.Fatalf("begin enable replay=%v err=%v", replay, err)
	}
	assertDNS10RouteFacts(t, ctx, db, fixture.app, fixture.dep, "active", endpoint.Port)

	router := &dns10Router{}
	_ = db.Close()
	db, err = sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	store = postgres.NewStore(db)
	if err := reconcileAcornFoxPublicAccess(ctx, store, "example.test", acornFoxPublicAccessRouteAdapter{Routes: router, Clock: func() time.Time { return fixture.now }}, 10); err != nil {
		t.Fatal(err)
	}
	if router.ensure != 1 || router.apply != 1 {
		t.Fatalf("recovery Ensure calls=%d want 1", router.ensure)
	}
	if _, replay, err := store.BeginAcornFoxPublicAccess(ctx, dns10Fact(fixture.app, fixture.dep, host, true, contracts.AcornFoxLocalRouteDesired), intent, true, key, digest, fixture.now); err != nil || !replay {
		t.Fatalf("same-key replay=%v err=%v", replay, err)
	}
	activeRebuild := &dns10Router{}
	if err := rebuildDomainConvergenceRoutes(ctx, store, activeRebuild, "dns10"); err != nil {
		t.Fatal(err)
	}
	if len(activeRebuild.rebuildRequests) != 1 || activeRebuild.rebuildRequests[0].Route.Host != host {
		t.Fatalf("active M3 rebuild=%+v", activeRebuild.rebuildRequests)
	}

	// Disable must durably switch the canonical M3 state before the router call.
	disableKey := "dns10-disable"
	disableDigest := dns10Digest(fixture.app, fixture.dep, false, host)
	observedDisabled := false
	disableRouter := &dns10Router{beforeRemove: func() {
		var state string
		if err := db.QueryRowContext(ctx, `SELECT desired_state FROM m3_desired_routes WHERE id=$1`, dns10RouteID(fixture.app, fixture.dep)).Scan(&state); err == nil && state == "disabled" {
			observedDisabled = true
		}
	}}
	if _, replay, err := store.BeginAcornFoxPublicAccess(ctx, dns10Fact(fixture.app, fixture.dep, host, false, contracts.AcornFoxLocalRouteDisabled), intent, false, disableKey, disableDigest, fixture.now); err != nil || replay {
		t.Fatalf("begin disable replay=%v err=%v", replay, err)
	}
	_ = db.Close()
	db, err = sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	store = postgres.NewStore(db)
	if err := reconcileAcornFoxPublicAccess(ctx, store, "example.test", acornFoxPublicAccessRouteAdapter{Routes: disableRouter, Clock: func() time.Time { return fixture.now }}, 10); err != nil {
		t.Fatal(err)
	}
	if !observedDisabled || disableRouter.remove != 1 {
		t.Fatalf("disable recovery observedDisabled=%v remove=%d", observedDisabled, disableRouter.remove)
	}
	disabledRebuild := &dns10Router{}
	if err := rebuildDomainConvergenceRoutes(ctx, store, disabledRebuild, "dns10"); err != nil {
		t.Fatal(err)
	}
	if len(disabledRebuild.rebuildRequests) != 0 {
		t.Fatalf("disabled M3 rebuild=%+v", disabledRebuild.rebuildRequests)
	}
	var facts, tables int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m3_desired_routes WHERE id LIKE 'afpa_route_%'`).Scan(&facts); err != nil {
		t.Fatal(err)
	}
	if facts != 1 {
		t.Fatalf("expected one canonical route fact, got %d", facts)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='acornfox_public_access_facts'`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 0 {
		t.Fatal("created forbidden second public-access truth table")
	}
	for _, status := range []contracts.AcornFoxPublicAccessStatus{contracts.AcornFoxPublicDisabled, contracts.AcornFoxPublicPendingExternalValidation} {
		if status == "PUBLIC_READY" {
			t.Fatal("PUBLIC_READY is not a valid local state")
		}
	}
}

func TestAcornFoxPublicAccessRecoveryRequiredAndActiveConflict(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_DNS10_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_DNS10_TEST_DATABASE_URL is required")
	}
	validateAcornFoxDNS10DSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	applyAcornFoxDNS10Migrations(t, ctx, db)
	fixture := seedAcornFoxDNS10Fixture(t, ctx, db)
	store := postgres.NewStore(db)
	endpoint, err := store.GetAcornFoxRoutableEndpoint(ctx, fixture.app, fixture.dep)
	if err != nil {
		t.Fatalf("endpoint=%v", err)
	}
	host, _ := contracts.AcornFoxPublicHostname("example.test", fixture.app, fixture.dep)
	intent := contracts.AcornFoxPublicRouteIntent{ApplicationID: fixture.app, DeploymentID: fixture.dep, Hostname: host, ServiceName: endpoint.ServiceName, Port: endpoint.Port}
	req := application.AcornFoxPublicAccessRequest{ApplicationID: fixture.app, DeploymentID: fixture.dep, Enabled: true, IdempotencyKey: "active-1"}
	digest := dns10Digest(req.ApplicationID, req.DeploymentID, req.Enabled, host)
	if _, _, err := store.BeginAcornFoxPublicAccess(ctx, dns10Fact(fixture.app, fixture.dep, host, true, contracts.AcornFoxLocalRouteDesired), intent, true, req.IdempotencyKey, digest, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAcornFoxPublicAccessReconcileRequired(ctx, fixture.app, fixture.dep, req.IdempotencyKey, digest, fixture.now); err != nil {
		t.Fatal(err)
	}
	items, err := store.ClaimAcornFoxPublicAccessRecoveryCommands(ctx, 10, fixture.now)
	if err != nil || len(items) != 1 || items[0].Phase != "reconcile_required" {
		t.Fatalf("recovery claim=%+v err=%v", items, err)
	}
	if _, _, err := store.BeginAcornFoxPublicAccess(ctx, dns10Fact(fixture.app, fixture.dep, host, true, contracts.AcornFoxLocalRouteDesired), intent, true, "active-2", dns10Digest(fixture.app, fixture.dep, true, host), fixture.now); err == nil {
		t.Fatalf("different-key active command err=%v", err)
	}
}

// Provider errors are outcome-unknown, not proof that the local route was
// untouched. This task-scoped PostgreSQL proof exercises both directions over
// a close/reopen boundary so a restart performs the exact durable action once.
func TestAcornFoxPublicAccessUnknownProviderOutcomeRecoversAfterRestart(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_DNS10_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_DNS10_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateAcornFoxDNS10DSN(t, dsn)
	for _, scenario := range []struct {
		name    string
		enabled bool
	}{
		{name: "ensure", enabled: true},
		{name: "remove", enabled: false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			db, err := sql.Open("pgx", dsn)
			if err != nil {
				t.Fatal(err)
			}
			db.SetMaxOpenConns(1)
			if err := db.PingContext(ctx); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
				db.Close()
				t.Fatal(err)
			}
			applyAcornFoxDNS10Migrations(t, ctx, db)
			fixture := seedAcornFoxDNS10Fixture(t, ctx, db)
			store := postgres.NewStore(db)
			service := &application.AcornFoxPublicAccessService{Store: store, Config: application.AcornFoxPublicAccessConfig{AuthorizedRoot: "example.test"}}
			if !scenario.enabled {
				service.Router = &dns10Router{}
				if _, err := service.Set(ctx, application.AcornFoxPublicAccessRequest{ApplicationID: fixture.app, DeploymentID: fixture.dep, Enabled: true, IdempotencyKey: "initial-enable"}); err != nil {
					db.Close()
					t.Fatal(err)
				}
			}
			unknown := &dns10Router{}
			if scenario.enabled {
				unknown.ensureErr = errors.New("ensure response lost")
			} else {
				unknown.removeErr = errors.New("remove response lost")
			}
			service.Router = unknown
			fact, err := service.Set(ctx, application.AcornFoxPublicAccessRequest{ApplicationID: fixture.app, DeploymentID: fixture.dep, Enabled: scenario.enabled, IdempotencyKey: "unknown-" + scenario.name})
			if err == nil || fact.LocalRoute != contracts.AcornFoxLocalRouteReconcileRequired || fact.DesiredPublic != scenario.enabled || fact.InternalEndpoint != contracts.AcornFoxInternalEndpointAccepted {
				db.Close()
				t.Fatalf("unknown %s fact=%+v err=%v", scenario.name, fact, err)
			}
			if scenario.enabled && unknown.ensure != 1 || !scenario.enabled && unknown.remove != 1 {
				db.Close()
				t.Fatalf("unknown %s router counts=%+v", scenario.name, unknown)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = sql.Open("pgx", dsn)
			if err != nil {
				t.Fatal(err)
			}
			db.SetMaxOpenConns(1)
			defer db.Close()
			if err := db.PingContext(ctx); err != nil {
				t.Fatal(err)
			}
			store = postgres.NewStore(db)
			recovery := &dns10Router{}
			if err := reconcileAcornFoxPublicAccess(ctx, store, "example.test", acornFoxPublicAccessRouteAdapter{Routes: recovery}, 10); err != nil {
				t.Fatal(err)
			}
			if scenario.enabled && recovery.apply != 1 || !scenario.enabled && recovery.remove != 1 {
				t.Fatalf("recovery %s router counts=%+v", scenario.name, recovery)
			}
			got, err := (&application.AcornFoxPublicAccessService{Store: store, Router: recovery, Config: application.AcornFoxPublicAccessConfig{AuthorizedRoot: "example.test"}}).Get(ctx, fixture.app, fixture.dep)
			if err != nil {
				t.Fatal(err)
			}
			wantRoute := contracts.AcornFoxLocalRouteDisabled
			wantStatus := contracts.AcornFoxPublicDisabled
			if scenario.enabled {
				wantRoute, wantStatus = contracts.AcornFoxLocalRouteConfigured, contracts.AcornFoxPublicPendingExternalValidation
			}
			if got.LocalRoute != wantRoute || got.Status != wantStatus || got.DesiredPublic != scenario.enabled || got.InternalEndpoint != contracts.AcornFoxInternalEndpointAccepted {
				t.Fatalf("recovered %s fact=%+v", scenario.name, got)
			}
		})
	}
}

type dns10Fixture struct {
	app, env, release, dep, operation, task domain.ID
	now                                     time.Time
}
type dns10Router struct {
	ensure, apply, remove int
	rebuildRequests       []contracts.RouteRequest
	beforeRemove          func()
	ensureErr, removeErr  error
}

func (r *dns10Router) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "dns10-test"}
}
func (r *dns10Router) Apply(context.Context, contracts.RouteRequest) (domain.Route, contracts.Evidence, error) {
	r.ensure++
	r.apply++
	return domain.Route{}, contracts.Evidence{}, nil
}
func (r *dns10Router) Observe(context.Context, contracts.RouteRequest) (domain.Observation, error) {
	return domain.Observation{}, nil
}
func (r *dns10Router) Rebuild(context.Context, contracts.OperationContext) (contracts.Evidence, error) {
	return contracts.Evidence{}, nil
}
func (r *dns10Router) Remove(context.Context, contracts.RouteRequest) error {
	r.remove++
	if r.beforeRemove != nil {
		r.beforeRemove()
	}
	return nil
}
func (r *dns10Router) RebuildRoutes(_ context.Context, requests []contracts.RouteRequest, _ contracts.OperationContext) (contracts.Evidence, error) {
	r.rebuildRequests = append([]contracts.RouteRequest(nil), requests...)
	return contracts.Evidence{}, nil
}

func (r *dns10Router) EnsureAcornFoxPublicRoute(context.Context, contracts.AcornFoxPublicRouteIntent, string) error {
	r.ensure++
	return r.ensureErr
}
func (r *dns10Router) RemoveAcornFoxPublicRoute(context.Context, contracts.AcornFoxPublicRouteIntent, string) error {
	r.remove++
	if r.beforeRemove != nil {
		r.beforeRemove()
	}
	return r.removeErr
}

func seedAcornFoxDNS10Fixture(t *testing.T, ctx context.Context, db *sql.DB) dns10Fixture {
	return seedAcornFoxDNS10FixtureWithProbe(t, ctx, db, true, 0)
}

func seedAcornFoxDNS10FixtureWithProbe(t *testing.T, ctx context.Context, db *sql.DB, includeProbe bool, probeAge time.Duration) dns10Fixture {
	t.Helper()
	now := time.Unix(1_700_010_000, 0).UTC()
	f := dns10Fixture{app: "app_dns10", env: "env_dns10", release: "release_dns10", operation: "op_dns10", task: "task_dns10", now: now}
	fact := contracts.AcornFoxRuntimeReleaseFact{ApplicationID: f.app, EnvironmentID: f.env, ReleaseID: f.release, ServiceName: "web", Image: domain.ImageDigest{Repository: "registry.test/acornfox", Digest: "sha256:" + strings.Repeat("a", 64)}, Resources: contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 100, MemoryBytes: 1024, PIDs: 10, DiskReservationBytes: 2048}, ContainerPort: 8080, AcceptedAt: now, Immutable: true}
	dep, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	if err != nil {
		t.Fatal(err)
	}
	f.dep = dep
	params, _ := json.Marshal(map[string]any{"acornfox_payload_type": "deploy", "request": contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "dns10-deploy"}})
	payload, _ := json.Marshal(map[string]any{"kind": v1.TaskDeploy, "parameters": json.RawMessage(params)})
	details, _ := json.Marshal(contracts.AcornFoxRuntimeObservation{DeploymentID: dep, ServiceName: "web", RuntimeState: "running", InternalAddress: "127.0.0.1:18080", RequestedResources: fact.Resources, AppliedLimits: contracts.AcornFoxRuntimeAppliedLimits{CPUMillis: 100, MemoryBytes: 1024, PIDs: 10}, ObservedAt: now})
	wire, _ := json.Marshal(v1.Observation{TaskID: f.task.String(), Sequence: 1, TargetRef: "deployment/" + dep.String(), Status: "runtime_ready", Healthy: true, At: now, Details: details})
	stmts := []struct {
		q string
		a []any
	}{
		{`INSERT INTO applications(id,name,created_at,updated_at) VALUES($1,'dns10',$2,$2)`, []any{f.app, now}}, {`INSERT INTO environments(id,application_id,name,created_at) VALUES($1,$2,'default',$3)`, []any{f.env, f.app, now}},
		{`INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable,created_at) VALUES('src_dns10',$1,'upload','upload','upload://dns10','main',$2,'/tmp/dns10','prepared',true,$3)`, []any{f.app, "sha256:" + strings.Repeat("b", 64), now}},
		{`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration,created_at) VALUES('def_dns10',$1,'src_dns10',1,'{}',$2)`, []any{f.app, now}}, {`INSERT INTO releases(id,application_id,definition_id,version,service_digests,created_at) VALUES($1,$2,'def_dns10',1,$3,$4)`, []any{f.release, f.app, `{"web":"sha256:` + strings.Repeat("a", 64) + `"}`, now}},
		{`INSERT INTO deployments(id,environment_id,release_id,state,created_at,updated_at) VALUES($1,$2,$3,'runtime_ready',$4,$4)`, []any{dep, f.env, f.release, now}}, {`INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES($1,$2,$3,$4,'deploy','dns10-op','succeeded','deployment/'||$4,$5,$5)`, []any{f.operation, f.app, f.env, dep, now}},
		{`INSERT INTO task_leases(task_id,operation_id,state,payload,created_at,updated_at,last_agent_sequence) VALUES($1,$2,'completed',$3,$4,$4,1)`, []any{f.task, f.operation, payload, now}}, {`INSERT INTO task_agent_events(task_id,sequence,event_type,payload,event_digest,created_at) VALUES($1,1,'observation',$2,'sha256:` + strings.Repeat("c", 64) + `',$3)`, []any{f.task, wire, now}},
		{`INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES('op_probe_dns10',$1,$2,$3,'probe','dns10-probe','succeeded','deployment/'||$3,$4,$4)`, []any{f.app, f.env, dep, now}},
		{`INSERT INTO task_leases(task_id,operation_id,state,payload,created_at,updated_at,last_agent_sequence) VALUES('task_probe_dns10','op_probe_dns10','completed','{}',$1,$1,1)`, []any{now}},
		{`INSERT INTO task_agent_events(task_id,sequence,event_type,payload,event_digest,created_at) VALUES('task_probe_dns10',1,'observation','{}','sha256:` + strings.Repeat("d", 64) + `',$1)`, []any{now}},
		{`INSERT INTO acornfox_probe_observations(id,sample_id,task_id,agent_sequence,application_id,environment_id,release_id,deployment_id,service_name,protocol,target_class,outcome,http_status,latency_ms,observed_at,created_at,fact_digest) VALUES('probe_dns10','sample_dns10','task_probe_dns10',1,$1,$2,$3,$4,'web','http','loopback','responded',200,1,$5,$5,'sha256:` + strings.Repeat("e", 64) + `')`, []any{f.app, f.env, f.release, dep, now}},
	}
	for _, s := range stmts {
		if strings.HasPrefix(s.q, "INSERT INTO acornfox_probe_observations") {
			if !includeProbe {
				continue
			}
			s.a[len(s.a)-1] = now.Add(-probeAge)
		}
		if _, err := db.ExecContext(ctx, s.q, s.a...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	return f
}

func dns10RouteID(a, d domain.ID) string { return postgresPublicRouteID(a, d) }
func postgresPublicRouteID(a, d domain.ID) string {
	return "afpa_route_" + fmt.Sprintf("%x", sha256.Sum256([]byte("route\x00"+a.String()+"\x00"+d.String())))[:24]
}
func dns10Digest(a, d domain.ID, enabled bool, host string) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("acornfox-public-access-command\x00"+a.String()+"\x00"+d.String()+"\x00"+fmt.Sprint(enabled)+"\x00"+host)))
}

func dns10Fact(a, d domain.ID, host string, desired bool, route contracts.AcornFoxLocalRouteState) contracts.AcornFoxPublicAccessFact {
	status := contracts.AcornFoxPublicDisabled
	if desired {
		status = contracts.AcornFoxPublicPendingExternalValidation
	}
	return contracts.AcornFoxPublicAccessFact{ApplicationID: a, DeploymentID: d, Hostname: host, Status: status, DesiredPublic: desired, InternalEndpoint: contracts.AcornFoxInternalEndpointAccepted, LocalRoute: route}
}
func assertDNS10RouteFacts(t *testing.T, ctx context.Context, db *sql.DB, app, dep domain.ID, state string, port int) {
	var got string
	var p int
	if err := db.QueryRowContext(ctx, `SELECT desired_state FROM m3_desired_routes WHERE application_id=$1 AND deployment_id=$2`, app.String(), dep.String()).Scan(&got); err != nil || got != state {
		t.Fatalf("route state=%q err=%v", got, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT l.port FROM m3_route_pointers p JOIN m3_port_leases l ON l.id=p.port_lease_id WHERE p.deployment_id=$1`, dep.String()).Scan(&p); err != nil || p != port {
		t.Fatalf("lease port=%d err=%v", p, err)
	}
}

func validateAcornFoxDNS10DSN(t *testing.T, dsn string) {
	t.Helper()
	p, err := url.Parse(dsn)
	if err != nil || (p.Scheme != "postgres" && p.Scheme != "postgresql") {
		t.Fatal("invalid DNS10 DSN")
	}
	if h := p.Hostname(); h != "127.0.0.1" && h != "::1" && h != "localhost" {
		t.Fatal("DNS10 database must be loopback")
	}
	if !strings.HasPrefix(strings.TrimPrefix(p.EscapedPath(), "/"), "open_card_afbdns10_") {
		t.Fatal("DNS10 database prefix required")
	}
}
func applyAcornFoxDNS10Migrations(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join("..", "..", "migrations", "control-plane"))
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".sql" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join("..", "..", "migrations", "control-plane", n))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, string(b)); err != nil {
			t.Fatalf("migration %s: %v", n, err)
		}
	}
}

// The first installed enable attempt had an owned running runtime but no probe.
// Exercise the real SQL -> service -> HTTP chain, including foreign ownership,
// so a readiness error cannot be mistaken for an absent application.
func TestAcornFoxPublicAccessProbeReadinessClassification(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_DNS10_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_DNS10_TEST_DATABASE_URL is required")
	}
	validateAcornFoxDNS10DSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, tc := range []struct {
		name    string
		probe   bool
		age     time.Duration
		foreign bool
		status  int
		code    string
	}{
		{name: "missing probe", status: 409, code: "internal_endpoint_not_ready"},
		{name: "probe predates runtime", probe: true, age: time.Second, status: 409, code: "internal_endpoint_not_ready"},
		{name: "foreign deployment without probe", foreign: true, status: 404, code: "not_found"},
		{name: "foreign deployment with probe", foreign: true, probe: true, status: 404, code: "not_found"},
		{name: "accepted current probe", probe: true, status: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
				t.Fatal(err)
			}
			applyAcornFoxDNS10Migrations(t, ctx, db)
			f := seedAcornFoxDNS10FixtureWithProbe(t, ctx, db, tc.probe, tc.age)
			app := f.app
			if tc.foreign {
				app = "other_app"
			}
			router := &dns10Router{}
			service := &application.AcornFoxPublicAccessService{Store: postgres.NewStore(db), Router: acornFoxPublicAccessRouteAdapter{Routes: router}, Config: application.AcornFoxPublicAccessConfig{AuthorizedRoot: "example.test"}}
			handler := &AcornFoxPublicAccessHTTPHandler{Service: service}
			req := httptest.NewRequest(http.MethodPut, "/public-access", strings.NewReader(`{"enabled":true}`)).WithContext(ctx)
			req.Header.Set("Idempotency-Key", "probe-readiness-enable")
			recorder := httptest.NewRecorder()
			handler.Handle(recorder, req, app, f.dep)
			var body map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if recorder.Code != tc.status || (tc.code != "" && body["code"] != tc.code) {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if tc.status != 200 {
				var commands int
				if err := db.QueryRowContext(ctx, `SELECT count(*) FROM acornfox_public_access_commands`).Scan(&commands); err != nil {
					t.Fatal(err)
				}
				if commands != 0 || router.apply != 0 || router.remove != 0 {
					t.Fatalf("failed precondition mutated commands=%d apply=%d remove=%d", commands, router.apply, router.remove)
				}
			}
		})
	}
}
