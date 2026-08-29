//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func TestFinalizeM4ServingIsAtomicAndIdempotent(t *testing.T) {
	dsn := os.Getenv("OPEN_CARD_TEST_DATABASE_URL")
	if strings.TrimSpace(dsn) == "" {
		t.Skip("OPEN_CARD_TEST_DATABASE_URL is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	store := NewStore(db)
	suffix := strings.ToLower(domain.MustNewID("m4final").String())
	now := time.Now().UTC().Truncate(time.Microsecond)
	app, env, src, def, rel := domain.ID("app_"+suffix), domain.ID("env_"+suffix), domain.ID("src_"+suffix), domain.ID("def_"+suffix), domain.ID("rel_"+suffix)
	old, candidate, op, route, oldLease := domain.ID("old_"+suffix), domain.ID("candidate_"+suffix), domain.ID("op_"+suffix), domain.ID("route_"+suffix), domain.ID("lease_old_"+suffix)
	digest := "sha256:" + strings.Repeat("a", 64)
	statements := []struct {
		q    string
		args []any
	}{
		{`INSERT INTO applications(id,name) VALUES($1,$2)`, []any{app.String(), "m4-final-" + suffix}},
		{`INSERT INTO environments(id,application_id,name) VALUES($1,$2,'m4')`, []any{env.String(), app.String()}},
		{`INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable) VALUES($1,$2,'upload','upload','upload://m4',$3,$4,$5,'prepared',true)`, []any{src.String(), app.String(), "upload-" + suffix, digest, "/var/lib/open-card/workspaces/" + suffix}},
		{`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration) VALUES($1,$2,$3,1,'{}')`, []any{def.String(), app.String(), src.String()}},
		{`INSERT INTO releases(id,application_id,definition_id,version,service_digests) VALUES($1,$2,$3,1,$4::jsonb)`, []any{rel.String(), app.String(), def.String(), `{"web":"` + digest + `"}`}},
		{`INSERT INTO deployments(id,environment_id,release_id,state,runtime_healthy,host_ip,host_port) VALUES($1,$2,$3,'serving',true,'127.0.0.1',18081),($4,$2,$3,'runtime_ready',true,'127.0.0.1',18082)`, []any{old.String(), env.String(), rel.String(), candidate.String()}},
		{`INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref) VALUES($1,$2,$3,$4,'redeploy',$5,'running',$6)`, []any{op.String(), app.String(), env.String(), candidate.String(), "m4-final-" + suffix, "environment/" + env.String()}},
		{`INSERT INTO m4_operation_requests(operation_id,request_digest,expected_fact_version,actor_id,reason) VALUES($1,$2,'facts-v1','integration','candidate observed')`, []any{op.String(), "sha256:" + strings.Repeat("f", 64)}},
		{`INSERT INTO m3_port_leases(id,application_id,deployment_id,service_name,bind_host,port,acquired_at) VALUES($1,$2,$3,'web','127.0.0.1',18081,$4)`, []any{oldLease.String(), app.String(), old.String(), now}},
		{`INSERT INTO m3_desired_routes(id,application_id,deployment_id,service_name,hostname,path_prefix,desired_state,verified,serving) VALUES($1,$2,$3,'web',$4,'/','active',true,true)`, []any{route.String(), app.String(), old.String(), "m4-" + strings.ReplaceAll(suffix[:10], "_", "-") + ".example.test"}},
		{`INSERT INTO m3_route_pointers(route_id,deployment_id,port_lease_id,revision) VALUES($1,$2,$3,1)`, []any{route.String(), old.String(), oldLease.String()}},
		{`INSERT INTO m4_rollout_coordinations(operation_id,application_id,environment_id,source_deployment_id,candidate_deployment_id,phase,route_set_digest,expected_route_set_version,attempt,lease_owner,lease_until) VALUES($1,$2,$3,$4,$5,'route_staged',$6,1,1,'worker',$7)`, []any{op.String(), app.String(), env.String(), old.String(), candidate.String(), digest, now.Add(time.Minute)}},
		{`INSERT INTO m4_rollout_phase_events(operation_id,sequence,phase,actor) VALUES($1,1,'candidate_requested','test'),($1,2,'candidate_ready','test'),($1,3,'route_staged','test')`, []any{op.String()}},
		{`INSERT INTO m4_rollout_route_sets(rollout_operation_id,application_id,source_deployment_id,candidate_deployment_id,old_digest,candidate_digest,expected_version,state,lease_owner,lease_until) VALUES($1,$2,$3,$4,$5,$5,1,'observed','worker',$6)`, []any{op.String(), app.String(), old.String(), candidate.String(), digest, now.Add(time.Minute)}},
		{`INSERT INTO m4_rollout_route_set_entries(rollout_operation_id,route_id,service_name,host,path_prefix,old_deployment_id,old_port_lease_id,old_pointer_revision,candidate_deployment_id,candidate_port) SELECT $1,$2,'web',hostname,path_prefix,$3,$4,1,$5,18082 FROM m3_desired_routes WHERE id=$2`, []any{op.String(), route.String(), old.String(), oldLease.String(), candidate.String()}},
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement.q, statement.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	request := FinalizeM4ServingRequest{OperationID: op, Owner: "worker", RouteSetDigest: digest, ExpectedVersion: 1, Actor: "integration", Reason: "candidate observed", Now: now}
	badLease := request
	badLease.Owner = "stale-worker"
	if _, err := store.FinalizeM4Serving(ctx, badLease); err == nil {
		t.Fatal("stale rollout lease was accepted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE m4_rollout_route_sets SET state='staged' WHERE rollout_operation_id=$1`, op.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinalizeM4Serving(ctx, request); err == nil {
		t.Fatal("unobserved staged route-set was accepted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE m4_rollout_route_sets SET state='observed' WHERE rollout_operation_id=$1`, op.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE m3_route_pointers SET revision=2 WHERE route_id=$1`, route.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinalizeM4Serving(ctx, request); err == nil {
		t.Fatal("stale pointer revision was accepted")
	}
	var unchangedPointer, unchangedDeployment, unchangedOperation, unchangedStage string
	if err := db.QueryRowContext(ctx, `SELECT p.deployment_id,d.state,o.state,s.state FROM m3_route_pointers p JOIN deployments d ON d.id=$2 JOIN operations o ON o.id=$3 JOIN m4_rollout_route_sets s ON s.rollout_operation_id=$3 WHERE p.route_id=$1`, route.String(), candidate.String(), op.String()).Scan(&unchangedPointer, &unchangedDeployment, &unchangedOperation, &unchangedStage); err != nil {
		t.Fatal(err)
	}
	if unchangedPointer != old.String() || unchangedDeployment != "runtime_ready" || unchangedOperation != "running" || unchangedStage != "observed" {
		t.Fatalf("failed finalize left partial writes: %s %s %s %s", unchangedPointer, unchangedDeployment, unchangedOperation, unchangedStage)
	}
	if _, err := db.ExecContext(ctx, `UPDATE m3_route_pointers SET revision=1 WHERE route_id=$1`, route.String()); err != nil {
		t.Fatal(err)
	}
	result, err := store.FinalizeM4Serving(ctx, request)
	if err != nil || result.Replayed {
		t.Fatalf("finalize=%+v err=%v", result, err)
	}
	var pointer, state, operation, routeState string
	var revision int64
	if err := db.QueryRowContext(ctx, `SELECT p.deployment_id,p.revision,d.state,o.state,s.state FROM m3_route_pointers p JOIN deployments d ON d.id=$2 JOIN operations o ON o.id=$3 JOIN m4_rollout_route_sets s ON s.rollout_operation_id=$3 WHERE p.route_id=$1`, route.String(), candidate.String(), op.String()).Scan(&pointer, &revision, &state, &operation, &routeState); err != nil {
		t.Fatal(err)
	}
	if pointer != candidate.String() || revision != 2 || state != "serving" || operation != "succeeded" || routeState != "current" {
		t.Fatalf("partial finalization: %s %d %s %s %s", pointer, revision, state, operation, routeState)
	}
	var candidateLease string
	var oldReleased sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT p.port_lease_id,old_lease.released_at FROM m3_route_pointers p JOIN m3_port_leases old_lease ON old_lease.id=$2 WHERE p.route_id=$1`, route.String(), oldLease.String()).Scan(&candidateLease, &oldReleased); err != nil {
		t.Fatal(err)
	}
	if want := tlsAllowLeaseID(app, candidate, "web", 18082); candidateLease != want.String() || !oldReleased.Valid {
		t.Fatalf("M4 endpoint lease identity=%s want=%s old_released=%+v", candidateLease, want, oldReleased)
	}
	var lifecycleID, lifecycleKind, lifecycleStatus, lifecycleMessage string
	if err := db.QueryRowContext(ctx, `SELECT payload->>'id',payload->>'kind',payload->>'status',payload->>'message' FROM outbox_events WHERE aggregate_type='operation' AND aggregate_id=$1 AND event_type='operations.route_set_serving.succeeded'`, op.String()).Scan(&lifecycleID, &lifecycleKind, &lifecycleStatus, &lifecycleMessage); err != nil {
		t.Fatal(err)
	}
	if lifecycleID == "" || lifecycleKind != "operations.route_set_serving.succeeded" || lifecycleStatus != "succeeded" || lifecycleMessage == "" {
		t.Fatalf("finalize lifecycle payload is not dispatchable: id=%q kind=%q status=%q message=%q", lifecycleID, lifecycleKind, lifecycleStatus, lifecycleMessage)
	}
	replay, err := store.FinalizeM4Serving(ctx, request)
	if err != nil || !replay.Replayed {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	request.RouteSetDigest = "sha256:" + strings.Repeat("b", 64)
	if _, err := store.FinalizeM4Serving(ctx, request); err == nil {
		t.Fatal("different digest replay accepted")
	}
	request.RouteSetDigest = digest
	if _, err := store.AdvanceM4Rollout(ctx, AdvanceM4RolloutRequest{OperationID: op, Owner: "worker", From: M4RolloutRouteCommitted, To: M4RolloutOldRetiring, Reason: "retire old", Now: now.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	retireKey := "m4-retire:" + op.String() + ":" + old.String()
	retireOperation, err := domain.NewOperation(app, env, domain.OperationDestroy, "destroy/"+old.String(), retireKey, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	retireOperation.ID = domain.ID("retire_op_" + suffix)
	retireTaskID := domain.ID("retire_task_" + suffix)
	parameters, _ := json.Marshal(contracts.DestroyRequest{DeploymentID: old, PreserveVolumes: true, Operation: contracts.OperationContext{IdempotencyKey: retireKey, Actor: "test"}})
	payload, _ := json.Marshal(map[string]any{"kind": "destroy_group", "parameters": json.RawMessage(parameters)})
	task, replayed, err := store.CreateM4RetirementTask(ctx, CreateM4RetirementTaskRequest{RolloutOperationID: op, OldDeploymentID: old, Operation: retireOperation, TaskID: retireTaskID, Payload: payload, MaxAttempts: 3, Now: now.Add(time.Second)})
	if err != nil || replayed || task.Task.State != TaskReady {
		t.Fatalf("retirement task=%+v replay=%v err=%v", task, replayed, err)
	}
	var envelope struct {
		Kind       string          `json:"kind"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if json.Unmarshal(task.Task.Payload, &envelope) != nil || envelope.Kind != "destroy_group" {
		t.Fatalf("retirement payload=%s", task.Task.Payload)
	}
	var destroy contracts.DestroyRequest
	if json.Unmarshal(envelope.Parameters, &destroy) != nil || destroy.DeploymentID != old || !destroy.PreserveVolumes {
		t.Fatalf("unsafe retirement request=%+v", destroy)
	}
	if _, replayed, err := store.CreateM4RetirementTask(ctx, CreateM4RetirementTaskRequest{RolloutOperationID: op, OldDeploymentID: old, Operation: retireOperation, TaskID: retireTaskID, Payload: payload, MaxAttempts: 3, Now: now.Add(time.Second)}); err != nil || !replayed {
		t.Fatalf("retirement replay=%v err=%v", replayed, err)
	}
	if _, _, err := store.CreateM4RetirementTask(ctx, CreateM4RetirementTaskRequest{RolloutOperationID: op, OldDeploymentID: candidate, Operation: retireOperation, TaskID: retireTaskID, Payload: payload, Now: now}); err == nil {
		t.Fatal("different old target replay accepted")
	}
	var candidateState string
	if err := db.QueryRowContext(ctx, `SELECT state FROM deployments WHERE id=$1`, candidate.String()).Scan(&candidateState); err != nil || candidateState != "serving" {
		t.Fatalf("retirement enqueue rolled back candidate serving: %s %v", candidateState, err)
	}
}

func TestM4ReplacementTaskSuccessAdvancesOnlyCandidateReady(t *testing.T) {
	dsn := os.Getenv("OPEN_CARD_TEST_DATABASE_URL")
	if strings.TrimSpace(dsn) == "" {
		t.Skip("OPEN_CARD_TEST_DATABASE_URL is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	store := NewStore(db)
	suffix := strings.ToLower(domain.MustNewID("m4ready").String())
	now := time.Now().UTC().Truncate(time.Microsecond)
	app, env, src, def, rel := "app_"+suffix, "env_"+suffix, "src_"+suffix, "def_"+suffix, "rel_"+suffix
	old, candidate, op, task := "old_"+suffix, "candidate_"+suffix, "op_"+suffix, "task_"+suffix
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, statement := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO applications(id,name) VALUES($1,$2)`, []any{app, "ready-" + suffix}},
		{`INSERT INTO environments(id,application_id,name) VALUES($1,$2,'m4')`, []any{env, app}},
		{`INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable) VALUES($1,$2,'upload','upload','upload://m4',$3,$4,$5,'prepared',true)`, []any{src, app, "upload-" + suffix, digest, "/var/lib/open-card/workspaces/" + suffix}},
		{`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration) VALUES($1,$2,$3,1,'{}')`, []any{def, app, src}},
		{`INSERT INTO releases(id,application_id,definition_id,version,service_digests) VALUES($1,$2,$3,1,$4::jsonb)`, []any{rel, app, def, `{"web":"` + digest + `"}`}},
		{`INSERT INTO deployments(id,environment_id,release_id,state) VALUES($1,$2,$3,'serving'),($4,$2,$3,'deploying')`, []any{old, env, rel, candidate}},
		{`INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref) VALUES($1,$2,$3,$4,'redeploy',$5,'running',$6)`, []any{op, app, env, candidate, "ready-" + suffix, "environment/" + env}},
		{`INSERT INTO task_leases(task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload) VALUES($1,$2,'agent',$3,1,3,'leased','{"kind":"deploy","parameters":{}}')`, []any{task, op, now.Add(time.Minute)}},
		{`INSERT INTO m4_rollout_coordinations(operation_id,application_id,environment_id,source_deployment_id,candidate_deployment_id,replacement_task_id,phase,route_set_digest,expected_route_set_version) VALUES($1,$2,$3,$4,$5,$6,'candidate_requested',$7,0)`, []any{op, app, env, old, candidate, task, digest}},
		{`INSERT INTO m4_rollout_phase_events(operation_id,sequence,phase,actor) VALUES($1,1,'candidate_requested','test')`, []any{op}},
	} {
		if _, err := db.ExecContext(ctx, statement.q, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	result, err := store.FinishControllerTask(ctx, FinishControllerTaskRequest{TaskID: domain.ID(task), Owner: "agent", Now: now, Outcome: ControllerTaskSucceeded, DeferOperationTerminal: true})
	if err != nil {
		t.Fatal(err)
	}
	var operationState, deploymentState, phase, taskState string
	if err := db.QueryRowContext(ctx, `SELECT o.state,d.state,r.phase,t.state FROM operations o JOIN deployments d ON d.id=o.deployment_id JOIN m4_rollout_coordinations r ON r.operation_id=o.id JOIN task_leases t ON t.task_id=r.replacement_task_id WHERE o.id=$1`, op).Scan(&operationState, &deploymentState, &phase, &taskState); err != nil {
		t.Fatal(err)
	}
	if result.Operation.Status != domain.OperationRunning || operationState != "running" || deploymentState != "runtime_ready" || phase != "candidate_ready" || taskState != "completed" {
		t.Fatalf("deferred terminal mismatch: result=%+v states=%s/%s/%s/%s", result, operationState, deploymentState, phase, taskState)
	}
	claimed, err := store.ClaimM4Rollouts(ctx, ClaimM4RolloutRequest{Owner: "cleanup-worker", Now: now.Add(time.Second), Duration: time.Minute, Limit: 1})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim cleanup rollout=%+v err=%v", claimed, err)
	}
	cleanupKey := "m4-cleanup:" + op + ":" + candidate
	destroyBytes, _ := json.Marshal(contracts.DestroyRequest{DeploymentID: domain.ID(candidate), PreserveVolumes: true, Operation: contracts.OperationContext{IdempotencyKey: cleanupKey, Actor: "test"}})
	cleanupPayload, _ := json.Marshal(map[string]any{"kind": "destroy_group", "parameters": json.RawMessage(destroyBytes)})
	cleanupTaskID := domain.ID("cleanup_" + suffix)
	cleanup, replay, err := store.CreateM4CandidateCleanupTask(ctx, CreateM4CandidateCleanupTaskRequest{RolloutOperationID: domain.ID(op), CandidateDeployment: domain.ID(candidate), TaskID: cleanupTaskID, Payload: cleanupPayload, Owner: "cleanup-worker", Reason: "route observation failed", Now: now.Add(time.Second)})
	if err != nil || replay || cleanup.Task.State != TaskReady {
		t.Fatalf("candidate cleanup=%+v replay=%v err=%v", cleanup, replay, err)
	}
	if _, replay, err := store.CreateM4CandidateCleanupTask(ctx, CreateM4CandidateCleanupTaskRequest{RolloutOperationID: domain.ID(op), CandidateDeployment: domain.ID(candidate), TaskID: cleanupTaskID, Payload: cleanupPayload, Owner: "cleanup-worker", Reason: "route observation failed", Now: now.Add(time.Second)}); err != nil || !replay {
		t.Fatalf("cleanup replay=%v err=%v", replay, err)
	}
	if _, _, err := store.CreateM4CandidateCleanupTask(ctx, CreateM4CandidateCleanupTaskRequest{RolloutOperationID: domain.ID(op), CandidateDeployment: domain.ID(old), TaskID: cleanupTaskID, Payload: cleanupPayload, Owner: "cleanup-worker", Reason: "route observation failed", Now: now.Add(time.Second)}); err == nil {
		t.Fatal("old deployment accepted as candidate cleanup target")
	}
	leased, found, err := store.ClaimControllerTask(ctx, ClaimTaskRequest{Owner: "agent-cleanup", Now: now.Add(2 * time.Second), LeasePolicy: LeasePolicy{Duration: time.Minute, MaxAttempts: 5}})
	if err != nil || !found || leased.Task.ID != cleanupTaskID {
		t.Fatalf("cleanup lease=%+v found=%v err=%v", leased, found, err)
	}
	if _, err := store.FinishControllerTask(ctx, FinishControllerTaskRequest{TaskID: cleanupTaskID, Owner: "agent-cleanup", Now: now.Add(3 * time.Second), Outcome: ControllerTaskSucceeded, DeferOperationTerminal: true}); err != nil {
		t.Fatal(err)
	}
	var oldState, candidateState, parentState, cleanupPhase, cleanupState string
	if err := db.QueryRowContext(ctx, `SELECT old.state,candidate.state,parent.state,rollout.phase,task.state FROM m4_rollout_coordinations rollout JOIN deployments old ON old.id=rollout.source_deployment_id JOIN deployments candidate ON candidate.id=rollout.candidate_deployment_id JOIN operations parent ON parent.id=rollout.operation_id JOIN task_leases task ON task.task_id=rollout.candidate_cleanup_task_id WHERE rollout.operation_id=$1`, op).Scan(&oldState, &candidateState, &parentState, &cleanupPhase, &cleanupState); err != nil {
		t.Fatal(err)
	}
	if oldState != "serving" || candidateState != "stopped" || parentState != "running" || cleanupPhase != "candidate_cleanup" || cleanupState != "completed" {
		t.Fatalf("cleanup altered wrong identity: old=%s candidate=%s parent=%s phase=%s task=%s", oldState, candidateState, parentState, cleanupPhase, cleanupState)
	}
}
