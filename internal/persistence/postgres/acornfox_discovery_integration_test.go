//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func TestAcornFoxDiscoveryPersistsOnlyPublicGitAndStrictRuntimeDeployments(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_ENTRY07_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_ENTRY07_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	expected := validateAcornFoxEntryDiscoveryDSN(t, dsn)
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
	resetAcornFoxEntryDiscoverySchema(t, ctx, db, expected)
	applyControlPlaneMigrations(t, ctx, db)
	now := time.Unix(1_700_100_000, 0).UTC()
	fixture := insertAcornFoxProbeFixture(t, ctx, db, now)
	if _, err := db.ExecContext(ctx, `INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,git_commit,content_digest,workspace_ref,workspace_lifecycle,immutable,created_at) VALUES('source_discovery_git',$1,'git','git_https','https://github.com/acme/discovery.git','main',$2,$3,'/private/discovery','prepared',true,$4)`, fixture.applicationID, strings.Repeat("a", 40), "sha256:"+strings.Repeat("b", 64), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	insertAcornFoxDiscoverySourceProof(t, ctx, db, fixture, "source_discovery_git", now.Add(time.Second))
	if _, err := db.ExecContext(ctx, `INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,git_commit,content_digest,workspace_ref,workspace_lifecycle,immutable,created_at) VALUES('source_discovery_unproven',$1,'git','git_https','https://github.com/acme/unproven.git','main',$2,$3,'/private/unproven','prepared',true,$4)`, fixture.applicationID, strings.Repeat("d", 40), "sha256:"+strings.Repeat("e", 64), now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	insertAcornFoxDiscoveryWrongOperationSourceTask(t, ctx, db, fixture, "source_discovery_unproven", now.Add(3*time.Second))
	strictDeployment := insertAcornFoxDiscoveryStrictDeployment(t, ctx, db, fixture, now.Add(2*time.Second))
	insertAcornFoxDiscoveryNonMarkerPrefix(t, ctx, db, fixture, strictDeployment, now.Add(2*time.Second))
	assertAcornFoxDiscoveryTaskLookupPlan(t, ctx, db, fixture, strictDeployment, now)
	store := NewStore(db)
	sources, err := store.ListAcornFoxSourceRevisions(ctx, domain.ID(fixture.applicationID), nil, 50)
	if err != nil || len(sources.Items) != 1 || sources.Items[0].ID != "source_discovery_git" || sources.Items[0].Locator != "https://github.com/acme/discovery.git" {
		t.Fatalf("sources=%+v err=%v", sources, err)
	}
	deliveries, err := store.ListAcornFoxDeployments(ctx, domain.ID(fixture.applicationID), nil, 50)
	if err != nil || len(deliveries.Items) != 1 || deliveries.Items[0].ID != strictDeployment {
		t.Fatalf("deliveries=%+v err=%v", deliveries, err)
	}
	if _, err := store.ListAcornFoxDeployments(ctx, "app_other", nil, 50); err != ErrNotFound {
		t.Fatalf("cross app err=%v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := restarted.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	page, err := NewStore(restarted).ListAcornFoxSourceRevisions(ctx, domain.ID(fixture.applicationID), &AcornFoxDiscoveryCursor{CreatedAt: sources.Items[0].CreatedAt, ID: sources.Items[0].ID}, 50)
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("restart source cursor page=%+v err=%v", page, err)
	}
	insertAcornFoxDiscoveryMarkedMalformedPrefix(t, ctx, restarted, fixture, now.Add(4*time.Second))
	if _, err := NewStore(restarted).ListAcornFoxDeployments(ctx, domain.ID(fixture.applicationID), nil, 50); err == nil || !strings.Contains(err.Error(), "task bound exhausted") {
		t.Fatalf("malformed marked task overflow err=%v", err)
	}
}

func assertAcornFoxDiscoveryTaskLookupPlan(t *testing.T, ctx context.Context, db *sql.DB, fixture acornFoxProbeFixture, deploymentID domain.ID, now time.Time) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `INSERT INTO deployments(id,environment_id,release_id,state,created_at,updated_at) VALUES('dep_entry_noise',$1,$2,'stopped',$3,$3)`, fixture.environmentID, fixture.releaseID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) SELECT 'op_entry_noise_'||value::text,$1,$2,'dep_entry_noise','observe','noise-'||value::text,'succeeded','deployment/dep_entry_noise',$3,$3 FROM generate_series(1,2000) AS value`, fixture.applicationID, fixture.environmentID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO task_leases(task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at) SELECT 'task_entry_noise_'||value::text,'op_entry_noise_'||value::text,'agent',$1,1,3,'completed','{"kind":"observe"}'::jsonb,$2,$2 FROM generate_series(1,2000) AS value`, now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `ANALYZE operations; ANALYZE task_leases`); err != nil {
		t.Fatal(err)
	}
	var plan []byte
	err := db.QueryRowContext(ctx, `EXPLAIN (FORMAT JSON, COSTS FALSE) SELECT lease.payload FROM task_leases lease JOIN operations operation ON operation.id=lease.operation_id WHERE operation.deployment_id=$1 AND operation.operation_type IN ('deploy','redeploy') AND lease.payload->>'kind'='deploy' AND lease.payload->'parameters'->>'acornfox_payload_type' IN ('deploy','redeploy') ORDER BY lease.created_at,lease.task_id LIMIT 17`, deploymentID).Scan(&plan)
	if err != nil {
		t.Fatal(err)
	}
	text := string(plan)
	if strings.Contains(text, `"Seq Scan"`) || !strings.Contains(text, "operations_acornfox_discovery_deployment_type_idx") || !strings.Contains(text, "task_leases_acornfox_discovery_operation_order_idx") {
		t.Fatalf("discovery task lookup plan did not use bounded indexes: %s", text)
	}
}

func insertAcornFoxDiscoveryNonMarkerPrefix(t *testing.T, ctx context.Context, db *sql.DB, fixture acornFoxProbeFixture, deploymentID domain.ID, now time.Time) {
	t.Helper()
	for index := 0; index < acornFoxDiscoveryTaskRowsPerDeployment+1; index++ {
		id := fmt.Sprintf("entry_prefix_%02d", index)
		if _, err := db.ExecContext(ctx, `INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES($1,$2,$3,$4,'observe',$5,'succeeded',$6,$7,$7)`, "op_"+id, fixture.applicationID, fixture.environmentID, deploymentID, id, "deployment/"+deploymentID.String(), now.Add(-time.Duration(index+1)*time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO task_leases(task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at) VALUES($1,$2,'agent',$3,1,3,'completed','{"kind":"observe"}'::jsonb,$4,$4)`, "task_"+id, "op_"+id, now.Add(time.Minute), now.Add(-time.Duration(index+1)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
}

func insertAcornFoxDiscoveryMarkedMalformedPrefix(t *testing.T, ctx context.Context, db *sql.DB, fixture acornFoxProbeFixture, now time.Time) {
	t.Helper()
	deploymentID := domain.ID("dep_entry_marked_malformed")
	if _, err := db.ExecContext(ctx, `INSERT INTO deployments(id,environment_id,release_id,state,created_at,updated_at) VALUES($1,$2,$3,'deploying',$4,$4)`, deploymentID, fixture.environmentID, fixture.releaseID, now); err != nil {
		t.Fatal(err)
	}
	payload := `{"kind":"deploy","parameters":{"acornfox_payload_type":"deploy","request":{}}}`
	for index := 0; index < acornFoxDiscoveryTaskRowsPerDeployment+1; index++ {
		id := fmt.Sprintf("entry_malformed_%02d", index)
		if _, err := db.ExecContext(ctx, `INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES($1,$2,$3,$4,'deploy',$5,'succeeded',$6,$7,$7)`, "op_"+id, fixture.applicationID, fixture.environmentID, deploymentID, id, "deployment/"+deploymentID.String(), now.Add(time.Duration(index+1)*time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO task_leases(task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at) VALUES($1,$2,'agent',$3,1,3,'completed',$4::jsonb,$5,$5)`, "task_"+id, "op_"+id, now.Add(time.Minute), payload, now.Add(time.Duration(index+1)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
}

func insertAcornFoxDiscoveryWrongOperationSourceTask(t *testing.T, ctx context.Context, db *sql.DB, fixture acornFoxProbeFixture, sourceID string, now time.Time) {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"kind": createApplicationTaskTag, "application_id": fixture.applicationID, "operation_id": "operation_entry_source_wrong", "source_revision_id": sourceID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO operations(id,application_id,environment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES('operation_entry_source_wrong',$1,$2,'deploy','entry-source-wrong','succeeded',$3,$4,$4)`, fixture.applicationID, fixture.environmentID, fixture.applicationID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO task_leases(task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at) VALUES('task_entry_source_wrong','operation_entry_source_wrong','control',$1,1,3,'completed',$2::jsonb,$3,$3)`, now.Add(time.Minute), payload, now); err != nil {
		t.Fatal(err)
	}
}

func insertAcornFoxDiscoverySourceProof(t *testing.T, ctx context.Context, db *sql.DB, fixture acornFoxProbeFixture, sourceID string, now time.Time) {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"kind": createApplicationTaskTag, "application_id": fixture.applicationID, "operation_id": "operation_entry_source", "source_revision_id": sourceID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO operations(id,application_id,environment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES('operation_entry_source',$1,$2,'create_application','entry-source','succeeded',$3,$4,$4)`, fixture.applicationID, fixture.environmentID, fixture.applicationID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO task_leases(task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at) VALUES('task_entry_source','operation_entry_source','control',$1,1,3,'completed',$2::jsonb,$3,$3)`, now.Add(time.Minute), payload, now); err != nil {
		t.Fatal(err)
	}
}

func insertAcornFoxDiscoveryStrictDeployment(t *testing.T, ctx context.Context, db *sql.DB, fixture acornFoxProbeFixture, now time.Time) domain.ID {
	t.Helper()
	fact := contracts.AcornFoxRuntimeReleaseFact{ApplicationID: domain.ID(fixture.applicationID), EnvironmentID: domain.ID(fixture.environmentID), ReleaseID: domain.ID(fixture.releaseID), ServiceName: "web", Image: domain.ImageDigest{Repository: "registry.example.test/acornfox/web", Digest: "sha256:" + strings.Repeat("c", 64)}, Resources: contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 100, MemoryBytes: 1024, PIDs: 10, DiskReservationBytes: 2048}, ContainerPort: 8080, AcceptedAt: now, Immutable: true}
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := json.Marshal(map[string]any{"acornfox_payload_type": "deploy", "request": contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "entry-discovery"}})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"kind": v1.TaskDeploy, "parameters": json.RawMessage(parameters)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO deployments(id,environment_id,release_id,state,created_at,updated_at) VALUES($1,$2,$3,'deploying',$4,$4)`, deploymentID, fixture.environmentID, fixture.releaseID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES('operation_entry_discovery',$1,$2,$3,'deploy','entry-discovery','succeeded',$4,$5,$5)`, fixture.applicationID, fixture.environmentID, deploymentID, "deployment/"+deploymentID.String(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO task_leases(task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at) VALUES('task_entry_discovery','operation_entry_discovery','agent',$1,1,3,'completed',$2::jsonb,$3,$3)`, now.Add(time.Minute), payload, now); err != nil {
		t.Fatal(err)
	}
	return deploymentID
}

func validateAcornFoxEntryDiscoveryDSN(t *testing.T, dsn string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || (parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1" && parsed.Hostname() != "localhost") {
		t.Fatal("task-scoped AcornFox discovery database URL is invalid")
	}
	database := strings.TrimPrefix(parsed.EscapedPath(), "/")
	if database == "" || strings.Contains(database, "/") || !strings.HasPrefix(database, "open_card_afbentry07_") {
		t.Fatal("task-scoped AcornFox discovery database name is invalid")
	}
	return database
}

func resetAcornFoxEntryDiscoverySchema(t *testing.T, ctx context.Context, db *sql.DB, expected string) {
	t.Helper()
	var current string
	if err := db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&current); err != nil || current != expected {
		t.Fatal("connected database does not match validated discovery database")
	}
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
}
