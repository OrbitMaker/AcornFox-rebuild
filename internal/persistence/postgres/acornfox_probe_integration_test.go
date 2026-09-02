//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func TestAcornFoxProbeObservationsPersistAsImmutableTaskFacts(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_PROBE_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_PROBE_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	expectedDatabase := validateAcornFoxProbeTestDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	resetAcornFoxProbeTestSchema(t, ctx, db, expectedDatabase)
	applyControlPlaneMigrations(t, ctx, db)
	assertAcornFoxProbeMigrationsIdempotent(t, ctx, db)

	now := time.Unix(1_700_000_000, 0).UTC()
	fixture := insertAcornFoxProbeFixture(t, ctx, db, now)
	store := NewStore(db)
	status := 204
	first := AcornFoxProbeObservation{
		ID: "probe_1", SampleID: "sample_1", TaskID: fixture.taskID, AgentSequence: 1,
		ApplicationID: fixture.applicationID, EnvironmentID: fixture.environmentID, ReleaseID: fixture.releaseID, DeploymentID: fixture.deploymentID,
		ServiceName: "web", Protocol: contracts.AcornFoxProbeProtocolHTTP, TargetClass: contracts.AcornFoxProbeTargetClassLoopback,
		Outcome: contracts.AcornFoxProbeOutcomeResponded, HTTPStatus: &status, LatencyMS: 7, ObservedAt: now, FactDigest: "sha256:" + strings.Repeat("a", 64),
	}
	persisted, replayed, err := store.AppendAcornFoxProbeObservation(ctx, first)
	if err != nil || replayed || persisted.ID != first.ID {
		t.Fatalf("first probe append=%+v replayed=%v err=%v", persisted, replayed, err)
	}
	replayedFact, replayed, err := store.AppendAcornFoxProbeObservation(ctx, first)
	if err != nil || !replayed || replayedFact.ID != first.ID || replayedFact.FactDigest != first.FactDigest {
		t.Fatalf("same fact replay=%+v replayed=%v err=%v", replayedFact, replayed, err)
	}
	changedDigest := first
	changedDigest.FactDigest = "sha256:" + strings.Repeat("b", 64)
	if _, _, err := store.AppendAcornFoxProbeObservation(ctx, changedDigest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed digest replay err=%v, want idempotency conflict", err)
	}
	changedSample := first
	changedSample.ID, changedSample.SampleID, changedSample.FactDigest = "probe_changed", "sample_changed", "sha256:"+strings.Repeat("c", 64)
	if _, _, err := store.AppendAcornFoxProbeObservation(ctx, changedSample); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed task sequence replay err=%v, want idempotency conflict", err)
	}
	loaded, err := store.GetAcornFoxProbeObservation(ctx, first.SampleID)
	if err != nil || loaded.HTTPStatus == nil || *loaded.HTTPStatus != status || loaded.ErrorCode != "" {
		t.Fatalf("loaded probe=%+v err=%v", loaded, err)
	}
	listed, err := store.ListAcornFoxProbeObservations(ctx, fixture.taskID, 5)
	if err != nil || len(listed) != 1 || listed[0].ID != first.ID {
		t.Fatalf("task probe list=%+v err=%v", listed, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE acornfox_probe_observations SET latency_ms=8 WHERE id=$1`, first.ID); err == nil {
		t.Fatal("probe observation UPDATE was accepted")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM acornfox_probe_observations WHERE id=$1`, first.ID); err == nil {
		t.Fatal("probe observation DELETE was accepted")
	}

	assertAcornFoxProbeSQLMatrix(t, ctx, db, fixture, now)
	var deployments int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM deployments WHERE id=$1`, fixture.deploymentID).Scan(&deployments); err != nil || deployments != 1 {
		t.Fatalf("probe append changed deployment state: count=%d err=%v", deployments, err)
	}
}

func TestAcornFoxProbeAgentEventAndFactCommitAtomicallyWithoutDeploymentProjection(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_PROBE_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_PROBE_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	expectedDatabase := validateAcornFoxProbeTestDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	resetAcornFoxProbeTestSchema(t, ctx, db, expectedDatabase)
	applyControlPlaneMigrations(t, ctx, db)
	now := time.Unix(1_700_000_100, 0).UTC()
	fixture := insertAcornFoxProbeLifecycleFixture(t, ctx, db, now, "primary")
	store := NewStore(db)
	before := snapshotAcornFoxProbePublicFacts(t, ctx, db, fixture.deploymentID)
	if _, err := store.StartControllerTask(ctx, domain.ID(fixture.taskID), fixture.owner, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	assertAcornFoxProbePublicFactsEqual(t, before, snapshotAcornFoxProbePublicFacts(t, ctx, db, fixture.deploymentID), "start")
	for sequence, event := range []struct {
		kind    string
		payload json.RawMessage
	}{
		{string(v1.KindTaskAck), mustAcornFoxProbeJSON(t, v1.TaskAck{TaskID: fixture.taskID, Status: v1.AckAccepted})},
		{string(v1.KindLogChunk), mustAcornFoxProbeJSON(t, v1.LogChunk{TaskID: fixture.taskID, Sequence: 1, Stream: v1.LogStreamStdout, Data: "probe completed", Final: true})},
		{string(v1.KindObservation), fixture.observation},
	} {
		if _, err := store.RecordAgentEvent(ctx, AgentEventRequest{TaskID: domain.ID(fixture.taskID), Owner: fixture.owner, Now: now.Add(2 * time.Second), Sequence: uint64(sequence + 1), Kind: event.kind, Payload: event.payload, WireVersion: v1.ProtocolVersion}); err != nil {
			t.Fatalf("record sequence %d: %v", sequence+1, err)
		}
	}
	var rawEvents, cursor, facts int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM task_agent_events WHERE task_id=$1`, fixture.taskID).Scan(&rawEvents); err != nil || rawEvents != 3 {
		t.Fatalf("raw Agent events=%d err=%v", rawEvents, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT last_agent_sequence FROM task_leases WHERE task_id=$1`, fixture.taskID).Scan(&cursor); err != nil || cursor != 3 {
		t.Fatalf("Agent cursor=%d err=%v", cursor, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM acornfox_probe_observations WHERE task_id=$1 AND agent_sequence=3`, fixture.taskID).Scan(&facts); err != nil || facts != 1 {
		t.Fatalf("atomic probe fact=%d err=%v", facts, err)
	}
	assertAcornFoxProbePublicFactsEqual(t, before, snapshotAcornFoxProbePublicFacts(t, ctx, db, fixture.deploymentID), "record")
	finish := FinishControllerTaskRequest{TaskID: domain.ID(fixture.taskID), Owner: fixture.owner, Now: now.Add(3 * time.Second), Outcome: ControllerTaskSucceeded, EvidenceIDs: []string{"acornfox-probe:" + fixture.result.FactDigest}}
	if _, err := store.FinishControllerTask(ctx, finish); err != nil {
		t.Fatal(err)
	}
	assertAcornFoxProbePublicFactsEqual(t, before, snapshotAcornFoxProbePublicFacts(t, ctx, db, fixture.deploymentID), "finish")
	if replay, err := NewStore(db).FinishControllerTask(ctx, finish); err != nil || !replay.Replayed {
		t.Fatalf("finish replay=%+v err=%v", replay, err)
	}
	sampleID := "acornfox-probe:" + fixture.taskID + ":3"
	if fact, err := NewStore(db).GetAcornFoxProbeObservation(ctx, sampleID); err != nil || fact.FactDigest != fixture.result.FactDigest {
		t.Fatalf("restart fact=%+v err=%v", fact, err)
	}

	invalid := insertAcornFoxProbeLifecycleFixture(t, ctx, db, now.Add(10*time.Second), "invalid")
	beforeInvalid := snapshotAcornFoxProbePublicFacts(t, ctx, db, invalid.deploymentID)
	var bad v1.Observation
	if err := json.Unmarshal(invalid.observation, &bad); err != nil {
		t.Fatal(err)
	}
	bad.EvidenceRefs = []string{"acornfox-probe:sha256:" + strings.Repeat("b", 64)}
	if _, err := store.RecordAgentEvent(ctx, AgentEventRequest{TaskID: domain.ID(invalid.taskID), Owner: invalid.owner, Now: now.Add(11 * time.Second), Sequence: 1, Kind: string(v1.KindObservation), Payload: mustAcornFoxProbeJSON(t, bad), WireVersion: v1.ProtocolVersion}); err == nil {
		t.Fatal("invalid probe evidence committed")
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM task_agent_events WHERE task_id=$1`, invalid.taskID).Scan(&rawEvents); err != nil || rawEvents != 0 {
		t.Fatalf("invalid raw event rollback=%d err=%v", rawEvents, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT last_agent_sequence FROM task_leases WHERE task_id=$1`, invalid.taskID).Scan(&cursor); err != nil || cursor != 0 {
		t.Fatalf("invalid cursor rollback=%d err=%v", cursor, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM acornfox_probe_observations WHERE task_id=$1`, invalid.taskID).Scan(&facts); err != nil || facts != 0 {
		t.Fatalf("invalid fact rollback=%d err=%v", facts, err)
	}
	assertAcornFoxProbePublicFactsEqual(t, beforeInvalid, snapshotAcornFoxProbePublicFacts(t, ctx, db, invalid.deploymentID), "invalid record")

	failure := insertAcornFoxProbeLifecycleFixture(t, ctx, db, now.Add(20*time.Second), "failure")
	failureBefore := snapshotAcornFoxProbePublicFacts(t, ctx, db, failure.deploymentID)
	if _, err := store.StartControllerTask(ctx, domain.ID(failure.taskID), failure.owner, now.Add(21*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FailControllerTask(ctx, FailControllerTaskRequest{TaskID: domain.ID(failure.taskID), Owner: failure.owner, Now: now.Add(22 * time.Second), Retryable: true, FailureReason: "probe unavailable"}); err != nil {
		t.Fatal(err)
	}
	assertAcornFoxProbePublicFactsEqual(t, failureBefore, snapshotAcornFoxProbePublicFacts(t, ctx, db, failure.deploymentID), "retryable fail")
	if _, err := db.ExecContext(ctx, `UPDATE task_leases SET state='leased',lease_owner=$1,lease_until=$2,attempt=3 WHERE task_id=$3`, failure.owner, now.Add(time.Minute), failure.taskID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FailControllerTask(ctx, FailControllerTaskRequest{TaskID: domain.ID(failure.taskID), Owner: failure.owner, Now: now.Add(23 * time.Second), Retryable: false, FailureReason: "probe unavailable"}); err != nil {
		t.Fatal(err)
	}
	assertAcornFoxProbePublicFactsEqual(t, failureBefore, snapshotAcornFoxProbePublicFacts(t, ctx, db, failure.deploymentID), "final fail")

	cancelled := insertAcornFoxProbeLifecycleFixture(t, ctx, db, now.Add(30*time.Second), "cancelled")
	cancelledBefore := snapshotAcornFoxProbePublicFacts(t, ctx, db, cancelled.deploymentID)
	if _, err := store.StartControllerTask(ctx, domain.ID(cancelled.taskID), cancelled.owner, now.Add(31*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinishControllerTask(ctx, FinishControllerTaskRequest{TaskID: domain.ID(cancelled.taskID), Owner: cancelled.owner, Now: now.Add(32 * time.Second), Outcome: ControllerTaskCancelled}); err != nil {
		t.Fatal(err)
	}
	assertAcornFoxProbePublicFactsEqual(t, cancelledBefore, snapshotAcornFoxProbePublicFacts(t, ctx, db, cancelled.deploymentID), "cancel")
}

type acornFoxProbeLifecycleFixture struct {
	applicationID, environmentID, releaseID, deploymentID, operationID, taskID, owner string
	result                                                                            contracts.AcornFoxProbeResult
	observation                                                                       json.RawMessage
}

func insertAcornFoxProbeLifecycleFixture(t *testing.T, ctx context.Context, db *sql.DB, now time.Time, suffix string) acornFoxProbeLifecycleFixture {
	t.Helper()
	fact := contracts.AcornFoxRuntimeReleaseFact{ApplicationID: domain.ID("app_afb_probe_" + suffix), EnvironmentID: domain.ID("env_afb_probe_" + suffix), ReleaseID: domain.ID("release_afb_probe_" + suffix), ServiceName: "web", Image: domain.ImageDigest{Repository: "registry.open-card.test/apps/web", Digest: "sha256:" + strings.Repeat("a", 64)}, Resources: contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 100, MemoryBytes: 1024, PIDs: 10, DiskReservationBytes: 2048}, ContainerPort: 8080, AcceptedAt: now, Immutable: true}
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	if err != nil {
		t.Fatal(err)
	}
	request, err := contracts.NewAcornFoxProbeRequest(contracts.AcornFoxRuntimeReference{Fact: fact}, contracts.AcornFoxProbeProtocolHTTP, "/ready", "probe-lifecycle-"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	parameters := mustAcornFoxProbeJSON(t, map[string]any{"acornfox_probe_payload_type": "probe", "request": request})
	payload := mustAcornFoxProbeJSON(t, map[string]any{"kind": v1.TaskObserve, "parameters": json.RawMessage(parameters)})
	fixture := acornFoxProbeLifecycleFixture{applicationID: fact.ApplicationID.String(), environmentID: fact.EnvironmentID.String(), releaseID: fact.ReleaseID.String(), deploymentID: deploymentID.String(), operationID: "op_afb_probe_" + suffix, taskID: "task_afb_probe_" + suffix, owner: "probe-agent"}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO applications(id,name,created_at,updated_at) VALUES($1,$2,$3,$3)`, []any{fixture.applicationID, "probe " + suffix, now}},
		{`INSERT INTO environments(id,application_id,name,created_at) VALUES($1,$2,'default',$3)`, []any{fixture.environmentID, fixture.applicationID, now}},
		{`INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable,created_at) VALUES($1,$2,'upload','upload',$3,'main',$4,$5,'prepared',true,$6)`, []any{"source_afb_probe_" + suffix, fixture.applicationID, "upload://afb-probe-" + suffix, "sha256:" + strings.Repeat("d", 64), "/var/lib/open-card/afb-probe-" + suffix, now}},
		{`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration,created_at) VALUES($1,$2,$3,1,'{}'::jsonb,$4)`, []any{"definition_afb_probe_" + suffix, fixture.applicationID, "source_afb_probe_" + suffix, now}},
		{`INSERT INTO releases(id,application_id,definition_id,version,service_digests,created_at) VALUES($1,$2,$3,1,jsonb_build_object('web',$4::text),$5)`, []any{fixture.releaseID, fixture.applicationID, "definition_afb_probe_" + suffix, "sha256:" + strings.Repeat("e", 64), now}},
		{`INSERT INTO deployments(id,environment_id,release_id,state,created_at,updated_at) VALUES($1,$2,$3,'runtime_ready',$4,$4)`, []any{fixture.deploymentID, fixture.environmentID, fixture.releaseID, now}},
		{`INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES($1,$2,$3,$4,'observe',$5,'pending',$6,$7,$7)`, []any{fixture.operationID, fixture.applicationID, fixture.environmentID, fixture.deploymentID, request.IdempotencyKey, "deployment/" + fixture.deploymentID + "/probe/web", now}},
		{`INSERT INTO task_leases(task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at) VALUES($1,$2,$3,$4,1,3,'leased',$5::jsonb,$6,$6)`, []any{fixture.taskID, fixture.operationID, fixture.owner, now.Add(time.Minute), payload, now}},
	} {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	status := 503
	digest, err := contracts.AcornFoxProbeFactDigest(request, contracts.AcornFoxRuntimeObservation{DeploymentID: deploymentID, ServiceName: fact.ServiceName, InternalAddress: "127.0.0.1:39124"}, contracts.AcornFoxProbeOutcomeResponded, &status)
	if err != nil {
		t.Fatal(err)
	}
	fixture.result = contracts.AcornFoxProbeResult{ApplicationID: fact.ApplicationID, EnvironmentID: fact.EnvironmentID, ReleaseID: fact.ReleaseID, DeploymentID: deploymentID, ServiceName: fact.ServiceName, Protocol: request.Protocol, TargetClass: contracts.AcornFoxProbeTargetClassLoopback, Outcome: contracts.AcornFoxProbeOutcomeResponded, HTTPStatus: &status, ObservedAt: now, FactDigest: digest}
	fixture.observation = mustAcornFoxProbeJSON(t, v1.Observation{TaskID: fixture.taskID, Sequence: 1, TargetRef: "deployment/" + fixture.deploymentID + "/probe/web", Status: "unknown", Healthy: false, At: now, EvidenceRefs: []string{"acornfox-probe:" + digest}, Details: mustAcornFoxProbeJSON(t, fixture.result)})
	return fixture
}

type acornFoxProbePublicSnapshot struct {
	deployment           string
	m4, pointers, routes int
}

func snapshotAcornFoxProbePublicFacts(t *testing.T, ctx context.Context, db *sql.DB, deploymentID string) acornFoxProbePublicSnapshot {
	t.Helper()
	var snapshot acornFoxProbePublicSnapshot
	if err := db.QueryRowContext(ctx, `SELECT row_to_json(d)::text FROM deployments d WHERE id=$1`, deploymentID).Scan(&snapshot.deployment); err != nil {
		t.Fatal(err)
	}
	for query, target := range map[string]*int{
		`SELECT count(*) FROM m4_service_observations WHERE deployment_id=$1`: &snapshot.m4,
		`SELECT count(*) FROM m3_route_pointers WHERE deployment_id=$1`:       &snapshot.pointers,
		`SELECT count(*) FROM m3_desired_routes WHERE deployment_id=$1`:       &snapshot.routes,
	} {
		if err := db.QueryRowContext(ctx, query, deploymentID).Scan(target); err != nil {
			t.Fatal(err)
		}
	}
	return snapshot
}

func assertAcornFoxProbePublicFactsEqual(t *testing.T, want, got acornFoxProbePublicSnapshot, step string) {
	t.Helper()
	if want != got {
		t.Fatalf("probe %s changed deployment/public facts: before=%+v after=%+v", step, want, got)
	}
}

func mustAcornFoxProbeJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type acornFoxProbeFixture struct {
	applicationID, environmentID, releaseID, deploymentID, taskID string
}

func insertAcornFoxProbeFixture(t *testing.T, ctx context.Context, db *sql.DB, now time.Time) acornFoxProbeFixture {
	t.Helper()
	fixture := acornFoxProbeFixture{applicationID: "app_afb_probe", environmentID: "env_afb_probe", releaseID: "release_afb_probe", deploymentID: "deployment_afb_probe", taskID: "task_afb_probe"}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO applications(id,name,created_at,updated_at) VALUES($1,'AcornFox probe',$2,$2)`, []any{fixture.applicationID, now}},
		{`INSERT INTO environments(id,application_id,name,created_at) VALUES($1,$2,'default',$3)`, []any{fixture.environmentID, fixture.applicationID, now}},
		{`INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable,created_at) VALUES('source_afb_probe',$1,'upload','upload','upload://afb-probe','main',$2,'/var/lib/open-card/afb-probe','prepared',true,$3)`, []any{fixture.applicationID, "sha256:" + strings.Repeat("d", 64), now}},
		{`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration,created_at) VALUES('definition_afb_probe',$1,'source_afb_probe',1,'{}'::jsonb,$2)`, []any{fixture.applicationID, now}},
		{`INSERT INTO releases(id,application_id,definition_id,version,service_digests,created_at) VALUES($1,$2,'definition_afb_probe',1,jsonb_build_object('web',$3::text),$4)`, []any{fixture.releaseID, fixture.applicationID, "sha256:" + strings.Repeat("e", 64), now}},
		{`INSERT INTO deployments(id,environment_id,release_id,state,created_at,updated_at) VALUES($1,$2,$3,'runtime_ready',$4,$4)`, []any{fixture.deploymentID, fixture.environmentID, fixture.releaseID, now}},
		{`INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES('operation_afb_probe',$1,$2,$3,'observe','afb-probe-observe','succeeded',$4,$5,$5)`, []any{fixture.applicationID, fixture.environmentID, fixture.deploymentID, "deployment/" + fixture.deploymentID, now}},
		{`INSERT INTO task_leases(task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at) VALUES($1,'operation_afb_probe','probe-agent',$2,1,3,'completed','{"kind":"observe"}'::jsonb,$3,$3)`, []any{fixture.taskID, now.Add(time.Minute), now}},
		{`INSERT INTO task_agent_events(task_id,sequence,event_type,payload,event_digest,created_at) VALUES($1,1,'observation','{}'::jsonb,$2,$3)`, []any{fixture.taskID, "sha256:" + strings.Repeat("f", 64), now}},
	} {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func assertAcornFoxProbeSQLMatrix(t *testing.T, ctx context.Context, db *sql.DB, fixture acornFoxProbeFixture, now time.Time) {
	t.Helper()
	valid := []struct {
		name, protocol, outcome, errorCode string
		status                             any
		latency                            int64
	}{
		{"tcp_responded", "tcp", "responded", "", nil, 1},
		{"timeout", "http", "timeout", "timeout", nil, 60_000},
		{"refused", "tcp", "refused", "connection_refused", nil, 1},
		{"malformed", "http", "malformed_response", "malformed_response", nil, 1},
		{"cancelled", "tcp", "cancelled", "cancelled", nil, 0},
		{"not_applicable", "http", "not_applicable", "", nil, 0},
	}
	for index, item := range valid {
		appendAcornFoxProbeAgentEvent(t, ctx, db, fixture.taskID, int64(index+2), now)
		if _, err := db.ExecContext(ctx, `INSERT INTO acornfox_probe_observations(id,sample_id,task_id,agent_sequence,application_id,environment_id,release_id,deployment_id,service_name,protocol,target_class,outcome,http_status,latency_ms,error_code,observed_at,fact_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'web',$9,'loopback',$10,$11,$12,NULLIF($13,''),$14,$15)`, "matrix_"+item.name, "matrix_sample_"+item.name, fixture.taskID, index+2, fixture.applicationID, fixture.environmentID, fixture.releaseID, fixture.deploymentID, item.protocol, item.outcome, item.status, item.latency, item.errorCode, now, "sha256:"+strings.Repeat("a", 64)); err != nil {
			t.Fatalf("valid direct SQL %s rejected: %v", item.name, err)
		}
	}
	for index, item := range []struct {
		name, protocol, outcome, errorCode string
		status                             any
		latency                            int64
	}{
		{"tcp_status", "tcp", "responded", "", 200, 1},
		{"http_missing_status", "http", "responded", "", nil, 1},
		{"http_600", "http", "responded", "", 600, 1},
		{"response_error", "http", "responded", "timeout", 200, 1},
		{"timeout_missing_error", "http", "timeout", "", nil, 1},
		{"refused_missing_error", "tcp", "refused", "", nil, 1},
		{"malformed_missing_error", "http", "malformed_response", "", nil, 1},
		{"cancelled_missing_error", "tcp", "cancelled", "", nil, 1},
		{"timeout_wrong_code", "http", "timeout", "refused", nil, 1},
		{"tcp_malformed", "tcp", "malformed_response", "malformed_response", nil, 1},
		{"not_applicable_latency", "tcp", "not_applicable", "", nil, 1},
		{"not_applicable_status", "http", "not_applicable", "", 204, 0},
		{"not_applicable_error", "http", "not_applicable", "timeout", nil, 0},
	} {
		sequence := 100 + index
		appendAcornFoxProbeAgentEvent(t, ctx, db, fixture.taskID, int64(sequence), now)
		if _, err := db.ExecContext(ctx, `INSERT INTO acornfox_probe_observations(id,sample_id,task_id,agent_sequence,application_id,environment_id,release_id,deployment_id,service_name,protocol,target_class,outcome,http_status,latency_ms,error_code,observed_at,fact_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'web',$9,'loopback',$10,$11,$12,NULLIF($13,''),$14,$15)`, "invalid_"+item.name, "invalid_sample_"+item.name, fixture.taskID, sequence, fixture.applicationID, fixture.environmentID, fixture.releaseID, fixture.deploymentID, item.protocol, item.outcome, item.status, item.latency, item.errorCode, now, "sha256:"+strings.Repeat("f", 64)); err == nil {
			t.Fatalf("invalid direct SQL %s was accepted", item.name)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO environments(id,application_id,name) VALUES('env_afb_probe_other',$1,'other')`, fixture.applicationID); err != nil {
		t.Fatal(err)
	}
	appendAcornFoxProbeAgentEvent(t, ctx, db, fixture.taskID, 999, now)
	if _, err := db.ExecContext(ctx, `INSERT INTO acornfox_probe_observations(id,sample_id,task_id,agent_sequence,application_id,environment_id,release_id,deployment_id,service_name,protocol,target_class,outcome,http_status,latency_ms,error_code,observed_at,fact_digest) VALUES('cross_scope','cross_scope_sample',$1,999,$2,'env_afb_probe_other',$3,$4,'web','http','loopback','responded',204,1,NULL,$5,$6)`, fixture.taskID, fixture.applicationID, fixture.releaseID, fixture.deploymentID, now, "sha256:"+strings.Repeat("e", 64)); err == nil {
		t.Fatal("direct SQL cross-scope probe fact was accepted")
	}
}

func appendAcornFoxProbeAgentEvent(t *testing.T, ctx context.Context, db *sql.DB, taskID string, sequence int64, now time.Time) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `INSERT INTO task_agent_events(task_id,sequence,event_type,payload,event_digest,created_at) VALUES($1,$2,'observation','{}'::jsonb,$3,$4)`, taskID, sequence, "sha256:"+strings.Repeat("f", 64), now); err != nil {
		t.Fatal(err)
	}
}

func assertAcornFoxProbeMigrationsIdempotent(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "..", "..", "migrations", "control-plane", "0027_acornfox_probe_observations.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for run := 1; run <= 2; run++ {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, string(payload)); err != nil {
			_ = tx.Rollback()
			t.Fatalf("rerun probe migration %d: %v", run, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit probe migration %d: %v", run, err)
		}
	}
}

func validateAcornFoxProbeTestDSN(t *testing.T, dsn string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("task-scoped AcornFox probe database URL is invalid")
	}
	if host := parsed.Hostname(); host != "127.0.0.1" && host != "::1" && host != "localhost" {
		t.Fatal("task-scoped AcornFox probe database must be loopback-only")
	}
	database := strings.TrimPrefix(parsed.EscapedPath(), "/")
	if database == "" || strings.Contains(database, "/") || !strings.HasPrefix(database, "open_card_afbprobe_") {
		t.Fatal("task-scoped AcornFox probe database name must use open_card_afbprobe_ prefix")
	}
	return database
}

func resetAcornFoxProbeTestSchema(t *testing.T, ctx context.Context, db *sql.DB, expectedDatabase string) {
	t.Helper()
	var currentDatabase string
	if err := db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&currentDatabase); err != nil || currentDatabase != expectedDatabase {
		t.Fatal("connected database does not match validated dedicated AcornFox probe test database")
	}
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset validated dedicated AcornFox probe test schema: %v", err)
	}
}
