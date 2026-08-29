//go:build integration

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type m4StagedRouteProviderCall struct {
	kind     string
	requests []contracts.RouteRequest
}

type m4StagedRouteProvider struct {
	mu          sync.Mutex
	calls       []m4StagedRouteProviderCall
	configured  []contracts.RouteRequest
	failRebuild bool
}

func (p *m4StagedRouteProvider) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{}
}
func (p *m4StagedRouteProvider) Apply(context.Context, contracts.RouteRequest) (domain.Route, contracts.Evidence, error) {
	return domain.Route{}, contracts.Evidence{}, errors.New("Apply is not used by M4 staged routes")
}
func (p *m4StagedRouteProvider) Remove(context.Context, contracts.RouteRequest) error {
	return errors.New("Remove is not used by M4 staged routes")
}
func (p *m4StagedRouteProvider) Rebuild(context.Context, contracts.OperationContext) (contracts.Evidence, error) {
	return contracts.Evidence{}, errors.New("Rebuild is not used by M4 staged routes")
}
func (p *m4StagedRouteProvider) RebuildRoutes(_ context.Context, requests []contracts.RouteRequest, _ contracts.OperationContext) (contracts.Evidence, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, m4StagedRouteProviderCall{kind: "rebuild", requests: append([]contracts.RouteRequest(nil), requests...)})
	if p.failRebuild {
		return contracts.Evidence{}, errors.New("injected full route-set load failure")
	}
	p.configured = append([]contracts.RouteRequest(nil), requests...)
	return contracts.Evidence{Refs: []domain.EvidenceRef{{ID: domain.ID(fmt.Sprintf("ev_rebuild_%d", len(p.calls))), Kind: "caddy.load"}}}, nil
}
func (p *m4StagedRouteProvider) Observe(_ context.Context, request contracts.RouteRequest) (domain.Observation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, configured := range p.configured {
		if configured.Route.Host == request.Route.Host && configured.Route.Path == request.Route.Path && configured.Route.DeploymentID == request.Route.DeploymentID && configured.Route.ServiceName == request.Route.ServiceName && configured.Route.Port == request.Route.Port {
			p.calls = append(p.calls, m4StagedRouteProviderCall{kind: "observe", requests: []contracts.RouteRequest{request}})
			sequence := len(p.calls)
			return domain.Observation{ID: domain.ID(fmt.Sprintf("obs_route_%d", sequence)), TargetRef: request.Route.Host + request.Route.Path, Kind: "route.actual", Value: true, Source: "m4-staged-route-test", ObservedAt: time.Now().UTC(), Evidence: []domain.EvidenceRef{{ID: domain.ID(fmt.Sprintf("ev_observe_%d", sequence)), Kind: "caddy.observe"}}}, nil
		}
	}
	return domain.Observation{}, errors.New("candidate route was not loaded before observe")
}
func (p *m4StagedRouteProvider) callsOf(kind string) []m4StagedRouteProviderCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make([]m4StagedRouteProviderCall, 0)
	for _, call := range p.calls {
		if call.kind == kind {
			result = append(result, call)
		}
	}
	return result
}

type m4StagedRouteSeed struct {
	app, old, candidate, operation, route domain.ID
	host                                  string
	oldPort, candidatePort                int
	rollout                               postgres.M4RolloutCoordinator
}

func TestM4StagedRouteCommitRebuildsCandidateAfterRestart(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_TEST_DATABASE_URL is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	store := postgres.NewStore(db)

	t.Run("restart rebuild is replaced by candidate before cutover", func(t *testing.T) {
		seed := seedM4StagedRoute(t, ctx, db, "restart")
		stageProvider := &m4StagedRouteProvider{}
		stageAdapter := &m4StagedRouteAdapter{store: store, routes: stageProvider, owner: "m4-staged-test", fence: newRouteSetMutationFence()}
		if _, err := stageAdapter.Stage(ctx, seed.rollout); err != nil {
			t.Fatal(err)
		}
		assertM4StagedCandidateLoaded(t, stageProvider, seed.candidate)

		// A process restart starts a fresh provider and startup derives the old
		// route-set from its still-current durable pointers.
		restartedProvider := &m4StagedRouteProvider{}
		if _, err := restartedProvider.RebuildRoutes(ctx, []contracts.RouteRequest{{Route: contracts.RouteSpec{Host: seed.host, Path: "/", DeploymentID: seed.old, ServiceName: "web", Port: seed.oldPort, Verified: true}}}, contracts.OperationContext{IdempotencyKey: "startup-old-rebuild"}); err != nil {
			t.Fatal(err)
		}
		commitFence := newRouteSetMutationFence()
		commitAdapter := &m4StagedRouteAdapter{store: store, routes: restartedProvider, owner: "m4-staged-test", fence: commitFence}
		if _, err := commitAdapter.Commit(ctx, seed.rollout); err != nil {
			t.Fatal(err)
		}
		assertM4StagedCandidateLoaded(t, restartedProvider, seed.candidate)
		assertM4StagedPointer(t, ctx, db, seed.route, seed.candidate, 2)
		var evidence string
		if err := db.QueryRowContext(ctx, `SELECT evidence_refs::text FROM audit_evidence WHERE action='operations.route_set_serving' ORDER BY sequence DESC LIMIT 1`).Scan(&evidence); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(evidence, "ev_rebuild") || !strings.Contains(evidence, "ev_observe") {
			t.Fatalf("commit did not retain fresh provider proof: %s", evidence)
		}
		before := len(restartedProvider.callsOf("rebuild"))
		if _, err := commitAdapter.Commit(ctx, seed.rollout); err != nil {
			t.Fatalf("same-process commit replay: %v", err)
		}
		if after := len(restartedProvider.callsOf("rebuild")); after != before {
			t.Fatalf("committed replay performed stale candidate rebuild: before=%d after=%d", before, after)
		}
		assertRouteSetFenceAvailable(t, commitFence)
	})

	t.Run("candidate reload failure retains old pointer and releases fence", func(t *testing.T) {
		seed := seedM4StagedRoute(t, ctx, db, "reload-failure")
		provider := &m4StagedRouteProvider{failRebuild: true}
		fence := newRouteSetMutationFence()
		adapter := &m4StagedRouteAdapter{store: store, routes: provider, owner: "m4-staged-test", fence: fence}
		if _, err := adapter.Commit(ctx, seed.rollout); err == nil {
			t.Fatal("Commit accepted a failed candidate route-set reload")
		}
		assertM4StagedPointer(t, ctx, db, seed.route, seed.old, 1)
		assertRouteSetFenceAvailable(t, fence)
		provider.failRebuild = false
		if err := adapter.Restore(ctx, seed.rollout); err != nil {
			t.Fatalf("Restore could not reclaim the released fence: %v", err)
		}
		assertM4StagedPointer(t, ctx, db, seed.route, seed.old, 1)
		assertRouteSetFenceAvailable(t, fence)
	})
}

func assertM4StagedCandidateLoaded(t *testing.T, provider *m4StagedRouteProvider, candidate domain.ID) {
	t.Helper()
	rebuilds := provider.callsOf("rebuild")
	if len(rebuilds) == 0 {
		t.Fatal("candidate full route-set was never rebuilt")
	}
	last := rebuilds[len(rebuilds)-1]
	foundCandidate := false
	for _, request := range last.requests {
		if request.Route.DeploymentID == candidate {
			foundCandidate = true
			break
		}
	}
	if !foundCandidate {
		t.Fatalf("last full route-set=%+v, missing candidate %s", last.requests, candidate)
	}
	observes := provider.callsOf("observe")
	if len(observes) == 0 || observes[len(observes)-1].requests[0].Route.DeploymentID != candidate {
		t.Fatalf("candidate was not observed after rebuild: %+v", observes)
	}
}

func assertM4StagedPointer(t *testing.T, ctx context.Context, db *sql.DB, route, deployment domain.ID, revision int64) {
	t.Helper()
	var gotDeployment string
	var gotRevision int64
	if err := db.QueryRowContext(ctx, `SELECT deployment_id,revision FROM m3_route_pointers WHERE route_id=$1`, route.String()).Scan(&gotDeployment, &gotRevision); err != nil {
		t.Fatal(err)
	}
	if gotDeployment != deployment.String() || gotRevision != revision {
		t.Fatalf("pointer deployment/revision=%s/%d want=%s/%d", gotDeployment, gotRevision, deployment, revision)
	}
}

func seedM4StagedRoute(t *testing.T, ctx context.Context, db *sql.DB, name string) m4StagedRouteSeed {
	t.Helper()
	suffix := strings.ToLower(domain.MustNewID("m4stage").String())
	now := time.Now().UTC().Truncate(time.Microsecond)
	app, env, source, definition, release := domain.ID("app_"+suffix), domain.ID("env_"+suffix), domain.ID("src_"+suffix), domain.ID("def_"+suffix), domain.ID("rel_"+suffix)
	old, candidate, operation, route, oldLease := domain.ID("old_"+suffix), domain.ID("candidate_"+suffix), domain.ID("op_"+suffix), domain.ID("route_"+suffix), domain.ID("lease_old_"+suffix)
	digest := "sha256:" + strings.Repeat("a", 64)
	host := "m4-" + strings.ReplaceAll(suffix, "_", "-") + ".example.test"
	requestDigest := m4AdapterDigest("m4-staged-route-test-request:" + suffix)
	portSeed, err := strconv.ParseInt(suffix[len("m4stage_"):len("m4stage_")+4], 16, 64)
	if err != nil {
		t.Fatal(err)
	}
	oldPort := 20000 + int(portSeed%20000)
	candidatePort := oldPort + 1
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO applications(id,name) VALUES($1,$2)`, []any{app.String(), "m4-staged-" + name + "-" + suffix}},
		{`INSERT INTO environments(id,application_id,name) VALUES($1,$2,'m4')`, []any{env.String(), app.String()}},
		{`INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable) VALUES($1,$2,'upload','upload','upload://m4',$3,$4,$5,'prepared',true)`, []any{source.String(), app.String(), "upload-" + suffix, digest, "/var/lib/open-card/workspaces/" + suffix}},
		{`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration) VALUES($1,$2,$3,1,'{}')`, []any{definition.String(), app.String(), source.String()}},
		{`INSERT INTO releases(id,application_id,definition_id,version,service_digests) VALUES($1,$2,$3,1,$4::jsonb)`, []any{release.String(), app.String(), definition.String(), `{"web":"` + digest + `"}`}},
		{`INSERT INTO deployments(id,environment_id,release_id,state,runtime_healthy,host_ip,host_port) VALUES($1,$2,$3,'serving',true,'127.0.0.1',$4),($5,$2,$3,'runtime_ready',true,'127.0.0.1',$6)`, []any{old.String(), env.String(), release.String(), oldPort, candidate.String(), candidatePort}},
		{`INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref) VALUES($1,$2,$3,$4,'redeploy',$5,'running',$6)`, []any{operation.String(), app.String(), env.String(), candidate.String(), "m4-staged-" + suffix, "environment/" + env.String()}},
		{`INSERT INTO m4_operation_requests(operation_id,request_digest,expected_fact_version,actor_id,reason) VALUES($1,$2,'facts-v1','integration','candidate observed')`, []any{operation.String(), requestDigest}},
		{`INSERT INTO m3_port_leases(id,application_id,deployment_id,service_name,bind_host,port,acquired_at) VALUES($1,$2,$3,'web','127.0.0.1',$4,$5)`, []any{oldLease.String(), app.String(), old.String(), oldPort, now}},
		{`INSERT INTO m3_desired_routes(id,application_id,deployment_id,service_name,hostname,path_prefix,desired_state,verified,serving) VALUES($1,$2,$3,'web',$4,'/','active',true,true)`, []any{route.String(), app.String(), old.String(), host}},
		{`INSERT INTO m3_route_pointers(route_id,deployment_id,port_lease_id,revision) VALUES($1,$2,$3,1)`, []any{route.String(), old.String(), oldLease.String()}},
		{`INSERT INTO m4_rollout_coordinations(operation_id,application_id,environment_id,source_deployment_id,candidate_deployment_id,phase,route_set_digest,expected_route_set_version,attempt,lease_owner,lease_until) VALUES($1,$2,$3,$4,$5,'route_staged',$6,1,1,'m4-staged-test',$7)`, []any{operation.String(), app.String(), env.String(), old.String(), candidate.String(), digest, now.Add(time.Minute)}},
		{`INSERT INTO m4_rollout_phase_events(operation_id,sequence,phase,actor) VALUES($1,1,'candidate_requested','test'),($1,2,'candidate_ready','test'),($1,3,'route_staged','test')`, []any{operation.String()}},
		{`INSERT INTO m4_rollout_route_sets(rollout_operation_id,application_id,source_deployment_id,candidate_deployment_id,old_digest,candidate_digest,expected_version,state,lease_owner,lease_until) VALUES($1,$2,$3,$4,$5,$5,1,'staged','m4-staged-test',$6)`, []any{operation.String(), app.String(), old.String(), candidate.String(), digest, now.Add(time.Minute)}},
		{`INSERT INTO m4_rollout_route_set_entries(rollout_operation_id,route_id,service_name,host,path_prefix,old_deployment_id,old_port_lease_id,old_pointer_revision,candidate_deployment_id,candidate_port) VALUES($1,$2,'web',$3,'/',$4,$5,1,$6,$7)`, []any{operation.String(), route.String(), host, old.String(), oldLease.String(), candidate.String(), candidatePort}},
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	return m4StagedRouteSeed{app: app, old: old, candidate: candidate, operation: operation, route: route, host: host, oldPort: oldPort, candidatePort: candidatePort, rollout: postgres.M4RolloutCoordinator{OperationID: operation, ApplicationID: app, EnvironmentID: env, SourceDeploymentID: old, CandidateDeploymentID: candidate, Phase: postgres.M4RolloutRouteStaged, RouteSetDigest: digest, ExpectedRouteSetVersion: 1, LeaseOwner: "m4-staged-test", CreatedAt: now, UpdatedAt: now}}
}
