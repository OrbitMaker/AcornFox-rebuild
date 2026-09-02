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

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/domain"
)

// TestAcornFoxDeliveryTaskCommitPersistsTheTaskAndReplayTogether exercises the
// PostgreSQL boundary that closes delivery's former enqueue/finalize gap. It
// deliberately reopens Store after every accepted command rather than relying
// on in-memory process state.
func TestAcornFoxDeliveryTaskCommitPersistsTheTaskAndReplayTogether(t *testing.T) {
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

	now := time.Unix(1_700_000_000, 0).UTC()
	for _, action := range []struct {
		name       string
		digestChar string
		type_      domain.OperationType
	}{
		{name: "create", digestChar: "a", type_: domain.OperationDeploy},
		{name: "restart", digestChar: "b", type_: domain.OperationRestart},
		{name: "redeploy", digestChar: "c", type_: domain.OperationRedeploy},
		{name: "probe", digestChar: "d", type_: domain.OperationObserve},
	} {
		fixture := insertAcornFoxDeliveryCommitFixture(t, ctx, db, now, action.name)
		key := "acornfox:" + action.name + ":durable-replay"
		digest := "sha256:" + strings.Repeat(action.digestChar, 64)
		if _, err := db.ExecContext(ctx, `INSERT INTO m1_publish_requests(idempotency_key,request_digest,status,created_at,updated_at) VALUES($1,$2,'in_progress',$3,$3)`, key, digest, now); err != nil {
			t.Fatal(err)
		}
		operation := domain.Operation{ID: domain.ID("op_afb_api06_" + action.name), ApplicationID: fixture.applicationID, EnvironmentID: fixture.environmentID, TargetRef: "deployment/" + fixture.deploymentID.String() + "/web", Type: action.type_, IdempotencyKey: key, Status: domain.OperationPending, CreatedAt: now, UpdatedAt: now}
		taskID := domain.ID("task_afb_api06_" + action.name)
		response, err := json.Marshal(map[string]string{"deployment_id": fixture.deploymentID.String(), "operation_id": operation.ID.String(), "task_id": taskID.String(), "status": "accepted"})
		if err != nil {
			t.Fatal(err)
		}
		request := EnqueueControllerTaskRequest{Operation: operation, ExistingDeploymentID: fixture.deploymentID, TaskID: taskID, Payload: json.RawMessage(`{"kind":"acornfox-test"}`), MaxAttempts: 3, InitialPublishStatus: domain.PublishDeploying}
		if _, err := NewStore(db).EnqueueControllerTaskAndCompletePublish(ctx, request, key, digest, response, now); err != nil {
			t.Fatalf("%s commit: %v", action.name, err)
		}
		reopened := NewStore(db)
		replayed, found, err := reopened.ReplayPublish(ctx, key, digest)
		if err != nil || !found || !acornFoxDeliveryCommitJSONEqual(t, replayed, response) {
			t.Fatalf("%s replay=%s found=%v err=%v", action.name, replayed, found, err)
		}
		if _, err := reopened.GetControllerTask(ctx, taskID); err != nil {
			t.Fatalf("%s durable task unavailable after reopen: %v", action.name, err)
		}
		if _, _, err := reopened.ReservePublish(ctx, key, "sha256:"+strings.Repeat("f", 64), now.Add(time.Second)); !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatalf("%s changed replay err=%v", action.name, err)
		}
	}

	fixture := insertAcornFoxDeliveryCommitFixture(t, ctx, db, now, "rollback")
	operation := domain.Operation{ID: "op_afb_api06_rollback", ApplicationID: fixture.applicationID, EnvironmentID: fixture.environmentID, TargetRef: "deployment/" + fixture.deploymentID.String() + "/web", Type: domain.OperationRestart, IdempotencyKey: "missing-publish-row", Status: domain.OperationPending, CreatedAt: now, UpdatedAt: now}
	request := EnqueueControllerTaskRequest{Operation: operation, ExistingDeploymentID: fixture.deploymentID, TaskID: "task_afb_api06_rollback", Payload: json.RawMessage(`{"kind":"acornfox-test"}`), MaxAttempts: 3}
	if _, err := NewStore(db).EnqueueControllerTaskAndCompletePublish(ctx, request, operation.IdempotencyKey, "sha256:"+strings.Repeat("e", 64), json.RawMessage(`{"status":"accepted"}`), now); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("missing publish reservation err=%v", err)
	}
	var operations, tasks int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM operations WHERE id=$1`, operation.ID.String()).Scan(&operations); err != nil || operations != 0 {
		t.Fatalf("rolled-back operation count=%d err=%v", operations, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM task_leases WHERE task_id=$1`, "task_afb_api06_rollback").Scan(&tasks); err != nil || tasks != 0 {
		t.Fatalf("rolled-back task count=%d err=%v", tasks, err)
	}

	// Simulate process death after a provider/build has returned but before the
	// service reaches its atomic task commit. A later process must terminally
	// settle the same AcornFox key; it may not start another build or task.
	abandonedKey, abandonedDigest := "acornfox:create:abandoned-after-provider", "sha256:"+strings.Repeat("e", 64)
	if _, err := db.ExecContext(ctx, `INSERT INTO build_plans(id,source_revision_id,source_digest,service_name,build_kind,context_path,dockerfile_path,target_repository,output_contract,secret_refs,idempotency_key,created_at) VALUES('plan_afb_api06_abandoned','src_afb_api06_rollback',$1,'web','dockerfile','.','Dockerfile','registry.example/acornfox','{"format":"oci","retention":"persistent","storage_key":"afb-api06/abandoned"}'::jsonb,'[]'::jsonb,$2,$3)`, "sha256:"+strings.Repeat("a", 64), abandonedKey+":build", now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO builds(id,plan_id,state,created_at,updated_at) VALUES('build_afb_api06_abandoned','plan_afb_api06_abandoned','running',$1,$1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO m1_publish_requests(idempotency_key,request_digest,status,created_at,updated_at) VALUES($1,$2,'in_progress',$3,$3)`, abandonedKey, abandonedDigest, now); err != nil {
		t.Fatal(err)
	}
	if err := NewStore(db).AbandonExpiredAcornFoxPublish(ctx, abandonedKey, abandonedDigest, now.Add(7*time.Minute), 6*time.Minute); !errors.Is(err, ErrAcornFoxPublishAbandoned) {
		t.Fatalf("abandoned recovery err=%v", err)
	}
	if _, _, err := NewStore(db).ReservePublish(ctx, abandonedKey, abandonedDigest, now.Add(8*time.Minute)); !errors.Is(err, ErrAcornFoxPublishAbandoned) {
		t.Fatalf("abandoned replay err=%v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM task_leases WHERE task_id LIKE 'task_afb_api06_abandoned%'`).Scan(&tasks); err != nil || tasks != 0 {
		t.Fatalf("abandoned recovery created task count=%d err=%v", tasks, err)
	}
	var buildState, buildReason string
	if err := db.QueryRowContext(ctx, `SELECT state,failure_reason FROM builds WHERE id='build_afb_api06_abandoned'`).Scan(&buildState, &buildReason); err != nil || buildState != "failed" || buildReason == "" {
		t.Fatalf("abandoned build state=%q reason=%q err=%v", buildState, buildReason, err)
	}
	legacyKey, legacyDigest := "legacy:publish:in-progress", "sha256:"+strings.Repeat("f", 64)
	if _, err := db.ExecContext(ctx, `INSERT INTO m1_publish_requests(idempotency_key,request_digest,status,created_at,updated_at) VALUES($1,$2,'in_progress',$3,$3)`, legacyKey, legacyDigest, now); err != nil {
		t.Fatal(err)
	}
	if err := NewStore(db).AbandonExpiredAcornFoxPublish(ctx, legacyKey, legacyDigest, now.Add(7*time.Minute), 6*time.Minute); err == nil || !domain.IsCode(err, domain.ErrValidation) {
		t.Fatalf("legacy recovery err=%v", err)
	}
	if _, _, err := NewStore(db).ReservePublish(ctx, legacyKey, legacyDigest, now.Add(8*time.Minute)); !errors.Is(err, ErrIdempotencyInProgress) {
		t.Fatalf("legacy row semantics changed: %v", err)
	}
}

func acornFoxDeliveryCommitJSONEqual(t *testing.T, left, right json.RawMessage) bool {
	t.Helper()
	var a, b map[string]string
	if err := json.Unmarshal(left, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(right, &b); err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

type acornFoxDeliveryCommitFixture struct {
	applicationID, environmentID, deploymentID domain.ID
}

func insertAcornFoxDeliveryCommitFixture(t *testing.T, ctx context.Context, db *sql.DB, now time.Time, suffix string) acornFoxDeliveryCommitFixture {
	t.Helper()
	fixture := acornFoxDeliveryCommitFixture{applicationID: domain.ID("app_afb_api06_" + suffix), environmentID: domain.ID("env_afb_api06_" + suffix), deploymentID: domain.ID("dep_afb_api06_" + suffix)}
	sourceID, definitionID, releaseID := "src_afb_api06_"+suffix, "def_afb_api06_"+suffix, "rel_afb_api06_"+suffix
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO applications(id,name,created_at,updated_at) VALUES($1,$2,$3,$3)`, []any{fixture.applicationID.String(), "AFB API06 " + suffix, now}},
		{`INSERT INTO environments(id,application_id,name,created_at) VALUES($1,$2,'default',$3)`, []any{fixture.environmentID.String(), fixture.applicationID.String(), now}},
		{`INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable,created_at) VALUES($1,$2,'upload','upload',$3,'main',$4,$5,'prepared',true,$6)`, []any{sourceID, fixture.applicationID.String(), "upload://afb-api06-" + suffix, "sha256:" + strings.Repeat("a", 64), "/var/lib/open-card/afb-api06-" + suffix, now}},
		{`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration,created_at) VALUES($1,$2,$3,1,'{}'::jsonb,$4)`, []any{definitionID, fixture.applicationID.String(), sourceID, now}},
		{`INSERT INTO releases(id,application_id,definition_id,version,service_digests,created_at) VALUES($1,$2,$3,1,jsonb_build_object('web',$4::text),$5)`, []any{releaseID, fixture.applicationID.String(), definitionID, "sha256:" + strings.Repeat("b", 64), now}},
		{`INSERT INTO deployments(id,environment_id,release_id,state,created_at,updated_at) VALUES($1,$2,$3,'runtime_ready',$4,$4)`, []any{fixture.deploymentID.String(), fixture.environmentID.String(), releaseID, now}},
	} {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}
