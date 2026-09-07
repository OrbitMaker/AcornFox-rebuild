//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func TestAcornFoxOperationResultUsesOnlyThisTaskEvidence(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_SOURCE_METADATA_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_SOURCE_METADATA_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	expected := validateAcornFoxSourceMetadataDSN(t, dsn)
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
	resetAcornFoxSourceMetadataSchema(t, ctx, db, expected)
	applyControlPlaneMigrations(t, ctx, db)
	now := time.Unix(1_700_500_000, 0).UTC()
	fact, deploymentID := seedAcornFoxOperationFixture(t, ctx, db, now)
	store := NewStore(db)

	probeRequest, err := contracts.NewAcornFoxProbeRequest(contracts.AcornFoxRuntimeReference{Fact: fact}, contracts.AcornFoxProbeProtocolHTTP, "/ready", "operation-probe")
	if err != nil {
		t.Fatal(err)
	}
	probePayload := acornFoxOperationProbePayload(t, probeRequest)
	seedAcornFoxOperationAndTask(t, ctx, db, "op_operation_probe", "task_operation_probe", deploymentID, "observe", "succeeded", "completed", probePayload, now)
	if _, err := db.ExecContext(ctx, `INSERT INTO task_agent_events(task_id,sequence,event_type,payload,event_digest,created_at) VALUES('task_operation_probe',1,'observation','{}'::jsonb,$1,$2)`, "sha256:"+strings.Repeat("a", 64), now); err != nil {
		t.Fatal(err)
	}
	status := 500
	if _, err := db.ExecContext(ctx, `INSERT INTO acornfox_probe_observations(id,sample_id,task_id,agent_sequence,application_id,environment_id,release_id,deployment_id,service_name,protocol,target_class,outcome,http_status,latency_ms,observed_at,fact_digest) VALUES('probe_operation_500','sample_operation_500','task_operation_probe',1,'app_operation','env_operation','rel_operation',$1,'web','http','loopback','responded',$2,8,$3,$4)`, deploymentID.String(), status, now.Add(time.Second), "sha256:"+strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	verified, err := store.GetAcornFoxOperationResult(ctx, "app_operation", "op_operation_probe")
	if err != nil || verified.Status != contracts.AcornFoxOperationVerified || verified.Evidence == nil || verified.Evidence.Kind != contracts.AcornFoxOperationResponseObservation || verified.Evidence.Verdict != contracts.AcornFoxOperationEvidenceUnhealthy || verified.Evidence.HTTPStatus == nil || *verified.Evidence.HTTPStatus != 500 {
		t.Fatalf("500 response operation result=%+v err=%v", verified, err)
	}

	runtimePayload := acornFoxOperationRuntimePayload(t, fact)
	seedAcornFoxOperationAndTask(t, ctx, db, "op_operation_old", "task_operation_old", deploymentID, "deploy", "succeeded", "completed", runtimePayload, now.Add(2*time.Second))
	seedAcornFoxOperationAndTask(t, ctx, db, "op_operation_old_evidence", "task_operation_old_evidence", deploymentID, "deploy", "succeeded", "completed", runtimePayload, now.Add(3*time.Second))
	if _, err := db.ExecContext(ctx, `INSERT INTO task_agent_events(task_id,sequence,event_type,payload,event_digest,created_at) VALUES('task_operation_old_evidence',1,'observation','{}'::jsonb,$1,$2)`, "sha256:"+strings.Repeat("c", 64), now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	old, err := store.GetAcornFoxOperationResult(ctx, "app_operation", "op_operation_old")
	if err != nil || old.Status != contracts.AcornFoxOperationUnknown || old.Evidence != nil {
		t.Fatalf("old task evidence was reused result=%+v err=%v", old, err)
	}
	seedAcornFoxOperationAndTask(t, ctx, db, "op_operation_runtime", "task_operation_runtime", deploymentID, "deploy", "succeeded", "completed", runtimePayload, now.Add(5*time.Second))
	runtimeObserved := contracts.AcornFoxRuntimeObservation{DeploymentID: deploymentID, ServiceName: fact.ServiceName, RuntimeState: "running", InternalAddress: "127.0.0.1:18080", RequestedResources: fact.Resources, AppliedLimits: contracts.AcornFoxRuntimeAppliedLimits{CPUMillis: fact.Resources.CPUMillis, MemoryBytes: fact.Resources.MemoryBytes, PIDs: fact.Resources.PIDs}, ObservedAt: now.Add(6 * time.Second)}
	runtimeDetails, err := json.Marshal(runtimeObserved)
	if err != nil {
		t.Fatal(err)
	}
	runtimeWire, err := json.Marshal(v1.Observation{TaskID: "task_operation_runtime", Sequence: 1, TargetRef: "deployment/" + deploymentID.String(), Status: "runtime_ready", Healthy: true, At: now.Add(6 * time.Second), Details: runtimeDetails})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO task_agent_events(task_id,sequence,event_type,payload,event_digest,created_at) VALUES('task_operation_runtime',1,'observation',$1,$2,$3)`, runtimeWire, "sha256:"+strings.Repeat("d", 64), now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	runtimeVerified, err := store.GetAcornFoxOperationResult(ctx, "app_operation", "op_operation_runtime")
	if err != nil || runtimeVerified.Status != contracts.AcornFoxOperationVerified || runtimeVerified.Evidence == nil || runtimeVerified.Evidence.Kind != contracts.AcornFoxOperationRuntimeObservation || runtimeVerified.Evidence.Verdict != contracts.AcornFoxOperationEvidenceObserved || runtimeVerified.Evidence.HTTPStatus != nil {
		t.Fatalf("runtime operation result=%+v err=%v", runtimeVerified, err)
	}

	seedAcornFoxOperationAndTask(t, ctx, db, "op_operation_accepted", "task_operation_accepted", deploymentID, "deploy", "pending", "ready", runtimePayload, now.Add(7*time.Second))
	accepted, err := store.GetAcornFoxOperationResult(ctx, "app_operation", "op_operation_accepted")
	if err != nil || accepted.Status != contracts.AcornFoxOperationAccepted {
		t.Fatalf("accepted result=%+v err=%v", accepted, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE operations SET state='succeeded' WHERE id='op_operation_accepted'; UPDATE task_leases SET state='completed' WHERE task_id='task_operation_accepted'`); err != nil {
		t.Fatal(err)
	}
	seedAcornFoxOperationAndTask(t, ctx, db, "op_operation_running", "task_operation_running", deploymentID, "deploy", "running", "leased", runtimePayload, now.Add(8*time.Second))
	running, err := store.GetAcornFoxOperationResult(ctx, "app_operation", "op_operation_running")
	if err != nil || running.Status != contracts.AcornFoxOperationRunning {
		t.Fatalf("running result=%+v err=%v", running, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE operations SET state='failed' WHERE id='op_operation_running'; UPDATE task_leases SET state='failed' WHERE task_id='task_operation_running'`); err != nil {
		t.Fatal(err)
	}
	seedAcornFoxOperationAndTask(t, ctx, db, "op_operation_failed", "task_operation_failed", deploymentID, "deploy", "failed", "failed", runtimePayload, now.Add(9*time.Second))
	failed, err := store.GetAcornFoxOperationResult(ctx, "app_operation", "op_operation_failed")
	if err != nil || failed.Status != contracts.AcornFoxOperationFailed || failed.Evidence != nil {
		t.Fatalf("failed result=%+v err=%v", failed, err)
	}
	if _, err := store.GetAcornFoxOperationResult(ctx, "app_operation_other", "op_operation_probe"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign operation err=%v", err)
	}
}

func seedAcornFoxOperationFixture(t *testing.T, ctx context.Context, db *sql.DB, now time.Time) (contracts.AcornFoxRuntimeReleaseFact, domain.ID) {
	t.Helper()
	fact := contracts.AcornFoxRuntimeReleaseFact{ApplicationID: "app_operation", EnvironmentID: "env_operation", ReleaseID: "rel_operation", ServiceName: "web", Image: domain.ImageDigest{Repository: "registry.example/operation", Digest: "sha256:" + strings.Repeat("d", 64)}, Resources: contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 100, MemoryBytes: 1024, PIDs: 10, DiskReservationBytes: 2048}, ContainerPort: 8080, AcceptedAt: now, Immutable: true}
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO applications(id,name,created_at,updated_at) VALUES('app_operation','operation',$1,$1),('app_operation_other','other',$1,$1)`, []any{now}},
		{`INSERT INTO environments(id,application_id,name,created_at) VALUES('env_operation','app_operation','default',$1)`, []any{now}},
		{`INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable,created_at) VALUES('src_operation','app_operation','upload','upload','upload://operation','main',$1,'/private/operation','prepared',true,$2)`, []any{"sha256:" + strings.Repeat("e", 64), now}},
		{`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration,created_at) VALUES('def_operation','app_operation','src_operation',1,'{}'::jsonb,$1)`, []any{now}},
		{`INSERT INTO releases(id,application_id,definition_id,version,service_digests,created_at) VALUES('rel_operation','app_operation','def_operation',1,jsonb_build_object('web',$1::text),$2)`, []any{fact.Image.Digest, now}},
		{`INSERT INTO deployments(id,environment_id,release_id,state,created_at,updated_at) VALUES($1,'env_operation','rel_operation','runtime_ready',$2,$2)`, []any{deploymentID.String(), now}},
	} {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return fact, deploymentID
}

func seedAcornFoxOperationAndTask(t *testing.T, ctx context.Context, db *sql.DB, operationID, taskID string, deploymentID domain.ID, operationType, operationState, taskState string, payload json.RawMessage, now time.Time) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES($1,'app_operation','env_operation',$2,$3,$4,$5,$1,$6,$6)`, operationID, deploymentID.String(), operationType, operationID+"-key", operationState, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO task_leases(task_id,operation_id,attempt,max_attempts,state,payload,created_at,updated_at) VALUES($1,$2,1,3,$3,$4::jsonb,$5,$5)`, taskID, operationID, taskState, payload, now); err != nil {
		t.Fatal(err)
	}
}

func acornFoxOperationProbePayload(t *testing.T, request contracts.AcornFoxProbeRequest) json.RawMessage {
	t.Helper()
	parameters, err := json.Marshal(struct {
		PayloadType string                         `json:"acornfox_probe_payload_type"`
		Request     contracts.AcornFoxProbeRequest `json:"request"`
	}{PayloadType: "probe", Request: request})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(struct {
		Kind       v1.TaskKind     `json:"kind"`
		Parameters json.RawMessage `json:"parameters"`
	}{Kind: v1.TaskObserve, Parameters: parameters})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func acornFoxOperationRuntimePayload(t *testing.T, fact contracts.AcornFoxRuntimeReleaseFact) json.RawMessage {
	t.Helper()
	request := contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "operation-runtime"}
	parameters, err := json.Marshal(struct {
		PayloadType string                                 `json:"acornfox_payload_type"`
		Request     contracts.AcornFoxRuntimeDeployRequest `json:"request"`
	}{PayloadType: "deploy", Request: request})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(struct {
		Kind       v1.TaskKind     `json:"kind"`
		Parameters json.RawMessage `json:"parameters"`
	}{Kind: v1.TaskDeploy, Parameters: parameters})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
