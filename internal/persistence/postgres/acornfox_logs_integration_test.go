//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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

func acornFoxLogDigest(seed string) string {
	return "sha256:" + strings.Repeat(seed, 64)
}

func TestAcornFoxDeliveryLogIndexesUseImmutableDeliveryIdentity(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_LOGS_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_LOGS_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	expectedDatabase := validateAcornFoxLogsTestDSN(t, dsn)
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
	resetAcornFoxLogsTestSchema(t, ctx, db, expectedDatabase)
	applyControlPlaneMigrations(t, ctx, db)
	assertAcornFoxLogsMigrationIdempotent(t, ctx, db)

	now := time.Unix(1_700_000_000, 0).UTC()
	fixture := insertAcornFoxProbeFixture(t, ctx, db, now)
	insertAcornFoxLogsArtifactFixture(t, ctx, db, fixture, now)
	logsTask := insertAcornFoxStrictLogsTask(t, ctx, db, fixture, now)
	store := NewStore(db)
	appID := domain.ID(fixture.applicationID)
	deploymentID := domain.ID(logsTask.deploymentID)
	redactionValues, err := store.GetAcornFoxDeliveryLogRedactionValues(ctx, appID, deploymentID)
	if err != nil || len(redactionValues) != 2 || redactionValues[0] != "upload://afb-probe" || redactionValues[1] != "/var/lib/open-card/afb-probe" {
		t.Fatalf("private delivery redaction values=%q err=%v", redactionValues, err)
	}
	if _, err := store.GetAcornFoxDeliveryLogRedactionValues(ctx, "app_other", deploymentID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-application redaction values err=%v, want not found", err)
	}
	if _, err := store.GetAcornFoxDeliveryLogRedactionValues(ctx, appID, "deployment_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing deployment redaction values err=%v, want not found", err)
	}

	for _, index := range []LogIndex{
		{ID: "log_runtime_b", ApplicationID: appID, ServiceName: "web", DeploymentID: deploymentID, OperationID: domain.ID(logsTask.operationID), LogTaskID: domain.ID(logsTask.taskID), Category: LogIndexRuntime, LogStream: LogStreamStdout, Truncation: LogTruncationComplete, Path: "/safe/runtime/b.log", Segment: 1, ByteSize: 1, ContentDigest: acornFoxLogDigest("1"), CreatedAt: now},
		{ID: "log_runtime_b_2", ApplicationID: appID, ServiceName: "web", DeploymentID: deploymentID, OperationID: domain.ID(logsTask.operationID), LogTaskID: domain.ID(logsTask.taskID), Category: LogIndexRuntime, LogStream: LogStreamStdout, Truncation: LogTruncationSourceLimited, Path: "/safe/runtime/b-2.log", Segment: 2, ByteSize: 1, ContentDigest: acornFoxLogDigest("2"), CreatedAt: now},
		{ID: "log_runtime_a", ApplicationID: appID, ServiceName: "web", DeploymentID: deploymentID, OperationID: domain.ID(logsTask.operationID), LogTaskID: domain.ID(logsTask.taskID), Category: LogIndexRuntime, LogStream: LogStreamStderr, Truncation: LogTruncationComplete, Path: "/safe/runtime/a.log", Segment: 3, ByteSize: 1, ContentDigest: acornFoxLogDigest("3"), CreatedAt: now},
		{ID: "log_build_good", ApplicationID: appID, ServiceName: "web", BuildID: "build_afb_logs_good", Category: LogIndexBuild, LogStream: LogStreamCombined, Truncation: LogTruncationComplete, Path: "/safe/build/good.log", Segment: 1, ByteSize: 1, ContentDigest: acornFoxLogDigest("4"), CreatedAt: now},
		{ID: "log_build_good_2", ApplicationID: appID, ServiceName: "web", BuildID: "build_afb_logs_good", Category: LogIndexBuild, LogStream: LogStreamCombined, Truncation: LogTruncationSourceLimited, Path: "/safe/build/good-2.log", Segment: 2, ByteSize: 1, ContentDigest: acornFoxLogDigest("5"), CreatedAt: now},
		{ID: "log_build_worker", ApplicationID: appID, ServiceName: "worker", BuildID: "build_afb_logs_worker", Category: LogIndexBuild, LogStream: LogStreamStdout, Truncation: LogTruncationComplete, Path: "/safe/build/worker.log", Segment: 1, ByteSize: 1, ContentDigest: acornFoxLogDigest("6"), CreatedAt: now.Add(-time.Second)},
		{ID: "log_build_other", ApplicationID: appID, ServiceName: "web", BuildID: "build_afb_logs_other", Category: LogIndexBuild, LogStream: LogStreamCombined, Truncation: LogTruncationComplete, Path: "/safe/build/other.log", Segment: 2, ByteSize: 1, ContentDigest: acornFoxLogDigest("7"), CreatedAt: now},
		{ID: "log_runtime_retired", ApplicationID: appID, ServiceName: "web", DeploymentID: deploymentID, OperationID: domain.ID(logsTask.operationID), LogTaskID: domain.ID(logsTask.taskID), Category: LogIndexRuntime, LogStream: LogStreamUnknown, Truncation: LogTruncationUnknown, Path: "/safe/runtime/retired.log", Segment: 4, ByteSize: 1, ContentDigest: acornFoxLogDigest("8"), CreatedAt: now},
	} {
		if err := store.AppendLogIndex(ctx, index, now); err != nil {
			t.Fatalf("append index %s: %v", index.ID, err)
		}
	}
	// This pointer has all of the ordinary M4 identity metadata, including a
	// task foreign key, but its task is a lifecycle control task. Public log
	// reads must not reinterpret it as Docker output.
	synthetic := insertAcornFoxSyntheticControlTask(t, ctx, db, fixture, logsTask, now)
	if err := store.AppendLogIndex(ctx, LogIndex{ID: "log_runtime_lifecycle", ApplicationID: appID, ServiceName: "web", DeploymentID: deploymentID, OperationID: domain.ID(synthetic.operationID), LogTaskID: domain.ID(synthetic.taskID), Category: LogIndexRuntime, LogStream: LogStreamStdout, Truncation: LogTruncationComplete, Path: "/safe/runtime/lifecycle.log", Segment: 9, ByteSize: 1, ContentDigest: acornFoxLogDigest("9"), CreatedAt: now}, now); err != nil {
		t.Fatalf("append synthetic lifecycle index: %v", err)
	}
	if err := store.RetireOrdinaryLogIndex(ctx, "log_runtime_retired", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// A row written before 0028 has no build/stream/truncation facts. It must
	// remain readable and become explicit unknown metadata in Go, not a guessed
	// stdout/complete value.
	if _, err := db.ExecContext(ctx, `INSERT INTO m4_log_indexes(id,application_id,service_name,category,path,segment,byte_size,created_at) VALUES('log_legacy_unknown',$1,'audit','audit','/safe/audit/legacy.log',1,1,$2)`, fixture.applicationID, now); err != nil {
		t.Fatal(err)
	}
	all, err := store.ListLogIndexes(ctx, appID, true, 20)
	if err != nil {
		t.Fatal(err)
	}
	legacyFound := false
	logTaskFound := false
	for _, index := range all {
		if index.ID == "log_legacy_unknown" {
			legacyFound = index.BuildID.Empty() && index.LogStream == LogStreamUnknown && index.Truncation == LogTruncationUnknown
		}
		if index.ID == "log_runtime_b" {
			logTaskFound = index.LogTaskID == domain.ID(logsTask.taskID)
		}
	}
	if !legacyFound {
		t.Fatalf("legacy null metadata was not preserved as unknown: %+v", all)
	}
	if !logTaskFound {
		t.Fatalf("strict runtime log task provenance was not preserved: %+v", all)
	}
	// A pre-0028 runtime pointer can remain in the internal ledger, but cannot
	// enter the AcornFox response model because it has no content proof.
	if _, err := db.ExecContext(ctx, `INSERT INTO m4_log_indexes(id,application_id,service_name,deployment_id,operation_id,category,log_stream,truncation,path,segment,byte_size,created_at) VALUES('log_runtime_legacy',$1,'web',$2,$3,'runtime','stdout','complete','/safe/runtime/legacy.log',5,1,$4)`, fixture.applicationID, logsTask.deploymentID, logsTask.operationID, now); err != nil {
		t.Fatal(err)
	}

	runtime, err := store.ListAcornFoxDeliveryLogIndexes(ctx, appID, deploymentID, LogIndexRuntime, nil, 1)
	if err != nil || len(runtime.Records) != 1 || runtime.Records[0].OperationID != domain.ID(logsTask.operationID) || runtime.Records[0].LogStream != LogStreamStdout || runtime.Records[0].Truncation != LogTruncationSourceLimited || len(runtime.Records[0].Segments) != 2 || runtime.Records[0].Segments[0].ID != "log_runtime_b" || runtime.Records[0].Segments[0].ContentDigest != acornFoxLogDigest("1") || runtime.Records[0].Segments[1].ID != "log_runtime_b_2" || runtime.Records[0].Segments[1].ContentDigest != acornFoxLogDigest("2") || runtime.NextCursor == nil || !runtime.HasRetiredIndexes {
		t.Fatalf("runtime page=%+v err=%v", runtime, err)
	}
	runtimeNext, err := store.ListAcornFoxDeliveryLogIndexes(ctx, appID, deploymentID, LogIndexRuntime, runtime.NextCursor, 1)
	if err != nil || len(runtimeNext.Records) != 1 || runtimeNext.Records[0].LogStream != LogStreamStderr || len(runtimeNext.Records[0].Segments) != 1 || runtimeNext.Records[0].Segments[0].ID != "log_runtime_a" || runtimeNext.NextCursor != nil || !runtimeNext.HasRetiredIndexes {
		t.Fatalf("runtime next page=%+v err=%v", runtimeNext, err)
	}
	build, err := store.ListAcornFoxDeliveryLogIndexes(ctx, appID, deploymentID, LogIndexBuild, nil, 1)
	if err != nil || len(build.Records) != 1 || build.Records[0].BuildID != "build_afb_logs_good" || build.Records[0].Truncation != LogTruncationSourceLimited || len(build.Records[0].Segments) != 2 || build.Records[0].Segments[0].ID != "log_build_good" || build.Records[0].Segments[1].ID != "log_build_good_2" || build.NextCursor == nil || build.HasRetiredIndexes {
		t.Fatalf("build page=%+v err=%v", build, err)
	}
	buildNext, err := store.ListAcornFoxDeliveryLogIndexes(ctx, appID, deploymentID, LogIndexBuild, build.NextCursor, 1)
	if err != nil || len(buildNext.Records) != 1 || buildNext.Records[0].BuildID != "build_afb_logs_worker" || len(buildNext.Records[0].Segments) != 1 || buildNext.Records[0].Segments[0].ID != "log_build_worker" || buildNext.NextCursor != nil {
		t.Fatalf("build next page=%+v err=%v", buildNext, err)
	}
	if _, err := store.ListAcornFoxDeliveryLogIndexes(ctx, appID, deploymentID, LogIndexAudit, nil, 1); err == nil {
		t.Fatal("audit source was accepted for AcornFox delivery logs")
	}
	if _, err := store.ListAcornFoxDeliveryLogIndexes(ctx, "app_other", deploymentID, LogIndexRuntime, nil, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-application deployment lookup err=%v, want not found", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO m4_log_indexes(id,application_id,service_name,category,build_id,log_stream,truncation,path,segment,byte_size,created_at) VALUES('invalid_log_metadata',$1,'web','runtime','build_afb_logs_good','stdout','complete','/safe/invalid.log',1,1,$2)`, fixture.applicationID, now); err == nil {
		t.Fatal("database accepted a build ID on a runtime log index")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO m4_log_indexes(id,application_id,service_name,category,log_stream,truncation,path,segment,byte_size,created_at) VALUES('invalid_log_stream',$1,'web','runtime','file','complete','/safe/invalid-stream.log',1,1,$2)`, fixture.applicationID, now); err == nil {
		t.Fatal("database accepted an invalid log stream")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO m4_log_indexes(id,application_id,service_name,category,log_stream,truncation,path,segment,byte_size,content_digest,created_at) VALUES('invalid_log_digest',$1,'web','runtime','stdout','complete','/safe/invalid-digest.log',1,1,'sha256:`+strings.Repeat("A", 64)+`',$2)`, fixture.applicationID, now); err == nil {
		t.Fatal("database accepted an invalid log content digest")
	}
	if err := insertAcornFoxUnboundBuildLogFixture(ctx, db, fixture, now); err != nil {
		t.Fatalf("insert unbound build log fixture: %v", err)
	}
	unbound, err := store.ListAcornFoxDeliveryLogIndexes(ctx, appID, deploymentID, LogIndexBuild, nil, 10)
	if err != nil || len(unbound.Records) != 2 {
		t.Fatalf("unbound build plan entered public delivery logs: records=%+v err=%v", unbound.Records, err)
	}
}

func TestAcornFoxLogCollectionCandidatesRequireStrictRuntimeTaskAndStaleLogs(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_LOGS_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_LOGS_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	expectedDatabase := validateAcornFoxLogsTestDSN(t, dsn)
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
	resetAcornFoxLogsTestSchema(t, ctx, db, expectedDatabase)
	applyControlPlaneMigrations(t, ctx, db)

	now := time.Unix(1_700_000_100, 0).UTC()
	strict := insertAcornFoxProbeLifecycleFixture(t, ctx, db, now, "logs_candidate")
	legacy := insertAcornFoxProbeLifecycleFixture(t, ctx, db, now, "logs_legacy")
	malformed := insertAcornFoxProbeLifecycleFixture(t, ctx, db, now, "logs_malformed")
	for _, fixture := range []acornFoxProbeLifecycleFixture{strict, legacy, malformed} {
		settleAcornFoxCandidateFixture(t, ctx, db, fixture, now)
	}
	insertAcornFoxCandidateTask(t, ctx, db, strict, acornFoxCandidatePayload(t, strict, now, false), "deploy")
	insertAcornFoxCandidateTask(t, ctx, db, malformed, acornFoxMismatchedCandidatePayload(t, malformed, now), "malformed")
	store := NewStore(db)
	if _, err := store.GetAcornFoxRuntimeRequest(ctx, domain.ID(malformed.applicationID), domain.ID(malformed.deploymentID)); err == nil {
		t.Fatal("runtime reader accepted a task whose fact did not derive the persisted deployment")
	}
	candidates, err := store.ListAcornFoxLogCollectionCandidates(ctx, now.Add(time.Second), 10)
	if err != nil || len(candidates) != 1 || candidates[0].ApplicationID.String() != strict.applicationID || candidates[0].EnvironmentID.String() != strict.environmentID || candidates[0].DeploymentID.String() != strict.deploymentID {
		t.Fatalf("strict candidate list=%+v err=%v; legacy=%+v malformed=%+v", candidates, err, legacy, malformed)
	}
	insertAcornFoxCompletedLogsTask(t, ctx, db, strict, now.Add(2*time.Second))
	candidates, err = store.ListAcornFoxLogCollectionCandidates(ctx, now.Add(time.Second), 10)
	if err != nil || len(candidates) != 0 {
		t.Fatalf("empty completed AcornFox logs task did not watermark candidate: %+v err=%v", candidates, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE task_leases SET state='failed',updated_at=$1 WHERE task_id='task_afb_logs_candidate_empty'`, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE operations SET state='failed',updated_at=$1 WHERE id='op_afb_logs_candidate_empty'`, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	candidates, err = store.ListAcornFoxLogCollectionCandidates(ctx, now.Add(time.Second), 10)
	if err != nil || len(candidates) != 1 || candidates[0].DeploymentID.String() != strict.deploymentID {
		t.Fatalf("failed AcornFox logs task suppressed retry: %+v err=%v", candidates, err)
	}
	if err := store.AppendLogIndex(ctx, LogIndex{ID: "log_candidate_fresh", ApplicationID: domain.ID(strict.applicationID), ServiceName: "web", DeploymentID: domain.ID(strict.deploymentID), OperationID: "op_afb_logs_candidate_deploy", Category: LogIndexRuntime, LogStream: LogStreamCombined, Truncation: LogTruncationComplete, Path: "/safe/runtime/fresh.log", Segment: 1, ByteSize: 1, ContentDigest: acornFoxLogDigest("9"), CreatedAt: now.Add(2 * time.Second)}, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	candidates, err = store.ListAcornFoxLogCollectionCandidates(ctx, now.Add(time.Second), 10)
	if err != nil || len(candidates) != 0 {
		t.Fatalf("fresh runtime log did not suppress candidate: %+v err=%v", candidates, err)
	}
	if err := store.RetireOrdinaryLogIndex(ctx, "log_candidate_fresh", now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES('op_afb_logs_candidate_active',$1,$2,$3,'observe','afb-logs-active','pending','deployment/active',$4,$4)`, strict.applicationID, strict.environmentID, strict.deploymentID, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	candidates, err = store.ListAcornFoxLogCollectionCandidates(ctx, now.Add(time.Second), 10)
	if err != nil || len(candidates) != 0 {
		t.Fatalf("active environment operation did not suppress candidate: %+v err=%v", candidates, err)
	}
	for _, call := range []struct {
		olderThan time.Time
		limit     int
	}{{time.Time{}, 1}, {now, 0}, {now, 101}} {
		if _, err := store.ListAcornFoxLogCollectionCandidates(ctx, call.olderThan, call.limit); err == nil {
			t.Fatalf("invalid candidate query accepted: %+v", call)
		}
	}
}

func TestAcornFoxLogCollectionCandidateValidationDoesNotStarveAfterMalformedPrefix(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_LOGS_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_LOGS_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	expectedDatabase := validateAcornFoxLogsTestDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	resetAcornFoxLogsTestSchema(t, ctx, db, expectedDatabase)
	applyControlPlaneMigrations(t, ctx, db)

	now := time.Unix(1_700_000_300, 0).UTC()
	fixtures := make([]acornFoxProbeLifecycleFixture, 0, 33)
	for index := 0; index < 33; index++ {
		fixture := insertAcornFoxProbeLifecycleFixture(t, ctx, db, now, fmt.Sprintf("fair_malformed_%02d", index))
		settleAcornFoxCandidateFixture(t, ctx, db, fixture, now)
		fixtures = append(fixtures, fixture)
	}
	validIndex := 0
	for index := 1; index < len(fixtures); index++ {
		if fixtures[index].deploymentID > fixtures[validIndex].deploymentID {
			validIndex = index
		}
	}
	valid := fixtures[validIndex]
	for index, fixture := range fixtures {
		payload := acornFoxMismatchedCandidatePayload(t, fixture, now)
		if index == validIndex {
			payload = acornFoxCandidatePayload(t, fixture, now, false)
		}
		insertAcornFoxCandidateTask(t, ctx, db, fixture, payload, fmt.Sprintf("fair_%02d", index))
	}
	candidates, err := NewStore(db).ListAcornFoxLogCollectionCandidates(ctx, now.Add(time.Second), 1)
	if err != nil || len(candidates) != 1 || candidates[0].DeploymentID.String() != valid.deploymentID {
		t.Fatalf("malformed prefix starved valid candidate: candidates=%+v err=%v", candidates, err)
	}
}

func insertAcornFoxCompletedLogsTask(t *testing.T, ctx context.Context, db *sql.DB, fixture acornFoxProbeLifecycleFixture, now time.Time) {
	t.Helper()
	payload := acornFoxLogsCandidatePayload(t, fixture, now)
	if _, err := db.ExecContext(ctx, `INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES('op_afb_logs_candidate_empty',$1,$2,$3,'observe','afb-logs-empty','succeeded',$4,$5,$5)`, fixture.applicationID, fixture.environmentID, fixture.deploymentID, "deployment/"+fixture.deploymentID+"/logs/web", now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO task_leases(task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at) VALUES('task_afb_logs_candidate_empty','op_afb_logs_candidate_empty','logs-agent',$1,1,3,'completed',$2::jsonb,$3,$3)`, now.Add(time.Minute), payload, now); err != nil {
		t.Fatal(err)
	}
}

func acornFoxLogsCandidatePayload(t *testing.T, fixture acornFoxProbeLifecycleFixture, now time.Time) json.RawMessage {
	t.Helper()
	fact := contracts.AcornFoxRuntimeReleaseFact{ApplicationID: domain.ID(fixture.applicationID), EnvironmentID: domain.ID(fixture.environmentID), ReleaseID: domain.ID(fixture.releaseID), ServiceName: "web", Image: domain.ImageDigest{Repository: "registry.open-card.test/apps/web", Digest: "sha256:" + strings.Repeat("a", 64)}, Resources: contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 100, MemoryBytes: 1024, PIDs: 10, DiskReservationBytes: 2048}, ContainerPort: 8080, AcceptedAt: time.Unix(1_700_000_100, 0).UTC(), Immutable: true}
	reference := contracts.AcornFoxRuntimeReference{Fact: fact}
	request, err := contracts.NewAcornFoxLogsRequest(reference, now.Add(-time.Second), 1, "afb-logs-empty")
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := json.Marshal(map[string]any{"acornfox_log_payload_type": "logs", "request": request})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"kind": v1.TaskLogs, "parameters": json.RawMessage(parameters)})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func settleAcornFoxCandidateFixture(t *testing.T, ctx context.Context, db *sql.DB, fixture acornFoxProbeLifecycleFixture, now time.Time) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `UPDATE operations SET state='succeeded',updated_at=$1 WHERE id=$2`, now, fixture.operationID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE task_leases SET state='completed',updated_at=$1 WHERE task_id=$2`, now, fixture.taskID); err != nil {
		t.Fatal(err)
	}
}

func insertAcornFoxCandidateTask(t *testing.T, ctx context.Context, db *sql.DB, fixture acornFoxProbeLifecycleFixture, payload json.RawMessage, suffix string) {
	t.Helper()
	operationID := "op_afb_logs_candidate_" + suffix
	taskID := "task_afb_logs_candidate_" + suffix
	if _, err := db.ExecContext(ctx, `INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES($1,$2,$3,$4,'deploy',$5,'succeeded',$6,$7,$7)`, operationID, fixture.applicationID, fixture.environmentID, fixture.deploymentID, "afb-logs-"+suffix, "deployment/"+fixture.deploymentID, time.Unix(1_700_000_100, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO task_leases(task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at) VALUES($1,$2,'logs-agent',$3,1,3,'completed',$4::jsonb,$5,$5)`, taskID, operationID, time.Unix(1_700_000_200, 0).UTC(), payload, time.Unix(1_700_000_100, 0).UTC()); err != nil {
		t.Fatal(err)
	}
}

func acornFoxCandidatePayload(t *testing.T, fixture acornFoxProbeLifecycleFixture, now time.Time, recreate bool) json.RawMessage {
	t.Helper()
	fact := contracts.AcornFoxRuntimeReleaseFact{ApplicationID: domain.ID(fixture.applicationID), EnvironmentID: domain.ID(fixture.environmentID), ReleaseID: domain.ID(fixture.releaseID), ServiceName: "web", Image: domain.ImageDigest{Repository: "registry.open-card.test/apps/web", Digest: "sha256:" + strings.Repeat("a", 64)}, Resources: contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 100, MemoryBytes: 1024, PIDs: 10, DiskReservationBytes: 2048}, ContainerPort: 8080, AcceptedAt: now, Immutable: true}
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	if err != nil || deploymentID.String() != fixture.deploymentID {
		t.Fatalf("candidate runtime fact deployment=%q fixture=%q err=%v", deploymentID, fixture.deploymentID, err)
	}
	parameters, err := json.Marshal(map[string]any{"acornfox_payload_type": "deploy", "request": contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "afb-logs-candidate", Recreate: recreate}})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"kind": v1.TaskDeploy, "parameters": json.RawMessage(parameters)})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func acornFoxMismatchedCandidatePayload(t *testing.T, fixture acornFoxProbeLifecycleFixture, now time.Time) json.RawMessage {
	t.Helper()
	fact := contracts.AcornFoxRuntimeReleaseFact{ApplicationID: domain.ID(fixture.applicationID), EnvironmentID: domain.ID(fixture.environmentID), ReleaseID: "release_afb_probe_mismatched", ServiceName: "web", Image: domain.ImageDigest{Repository: "registry.open-card.test/apps/web", Digest: "sha256:" + strings.Repeat("a", 64)}, Resources: contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 100, MemoryBytes: 1024, PIDs: 10, DiskReservationBytes: 2048}, ContainerPort: 8080, AcceptedAt: now, Immutable: true}
	parameters, err := json.Marshal(map[string]any{"acornfox_payload_type": "deploy", "request": contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "afb-logs-mismatched"}})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"kind": v1.TaskDeploy, "parameters": json.RawMessage(parameters)})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func insertAcornFoxLogsArtifactFixture(t *testing.T, ctx context.Context, db *sql.DB, fixture acornFoxProbeFixture, now time.Time) {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO build_plans(id,source_revision_id,source_digest,service_name,build_kind,context_path,dockerfile_path,acornfox_definition_digest,acornfox_dockerfile_digest,target_repository,output_contract,secret_refs,idempotency_key,created_at) VALUES('plan_afb_logs','source_afb_probe',$1,'web','dockerfile','.','Dockerfile',$2,$3,'registry.open-card.test/apps/web','{"format":"oci","retention":"persistent","storage_key":"afb-logs"}'::jsonb,'[]'::jsonb,'afb-logs-build',$4)`, []any{"sha256:" + strings.Repeat("d", 64), "sha256:" + strings.Repeat("e", 64), "sha256:" + strings.Repeat("f", 64), now}},
		{`INSERT INTO builds(id,plan_id,state,artifact_id,created_at,updated_at) VALUES('build_afb_logs_good','plan_afb_logs','succeeded','artifact_afb_logs_good',$1,$1)`, []any{now}},
		{`INSERT INTO artifacts(id,build_id,image_repository,image_digest,oci_storage_ref,size_bytes,created_at) VALUES('artifact_afb_logs_good','build_afb_logs_good','registry.open-card.test/apps/web','sha256:` + strings.Repeat("a", 64) + `','oci://afb-logs/good',1,$1)`, []any{now}},
		{`INSERT INTO release_artifacts(release_id,service_name,artifact_id) VALUES($1,'web','artifact_afb_logs_good')`, []any{fixture.releaseID}},
		{`INSERT INTO build_plans(id,source_revision_id,source_digest,service_name,build_kind,context_path,dockerfile_path,acornfox_definition_digest,acornfox_dockerfile_digest,target_repository,output_contract,secret_refs,idempotency_key,created_at) VALUES('plan_afb_logs_worker','source_afb_probe',$1,'worker','dockerfile','.','Dockerfile',$2,$3,'registry.open-card.test/apps/worker','{"format":"oci","retention":"persistent","storage_key":"afb-logs-worker"}'::jsonb,'[]'::jsonb,'afb-logs-worker',$4)`, []any{"sha256:" + strings.Repeat("d", 64), "sha256:" + strings.Repeat("e", 64), "sha256:" + strings.Repeat("f", 64), now}},
		{`INSERT INTO builds(id,plan_id,state,artifact_id,created_at,updated_at) VALUES('build_afb_logs_worker','plan_afb_logs_worker','succeeded','artifact_afb_logs_worker',$1,$1)`, []any{now}},
		{`INSERT INTO artifacts(id,build_id,image_repository,image_digest,oci_storage_ref,size_bytes,created_at) VALUES('artifact_afb_logs_worker','build_afb_logs_worker','registry.open-card.test/apps/worker','sha256:` + strings.Repeat("b", 64) + `','oci://afb-logs/worker',1,$1)`, []any{now}},
		{`INSERT INTO release_artifacts(release_id,service_name,artifact_id) VALUES($1,'worker','artifact_afb_logs_worker')`, []any{fixture.releaseID}},
		{`INSERT INTO builds(id,plan_id,state,failure_reason,created_at,updated_at) VALUES('build_afb_logs_other','plan_afb_logs','failed','unrelated',$1,$1)`, []any{now}},
	} {
		if _, err := tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

type acornFoxStrictLogsTask struct {
	deploymentID string
	operationID  string
	taskID       string
}

func insertAcornFoxStrictLogsTask(t *testing.T, ctx context.Context, db *sql.DB, fixture acornFoxProbeFixture, now time.Time) acornFoxStrictLogsTask {
	t.Helper()
	fact := contracts.AcornFoxRuntimeReleaseFact{
		ApplicationID: domain.ID(fixture.applicationID), EnvironmentID: domain.ID(fixture.environmentID), ReleaseID: domain.ID(fixture.releaseID),
		ServiceName: "web", Image: domain.ImageDigest{Repository: "registry.open-card.test/apps/web", Digest: "sha256:" + strings.Repeat("a", 64)},
		Resources: contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 100, MemoryBytes: 1024, PIDs: 10, DiskReservationBytes: 2048}, ContainerPort: 8080, AcceptedAt: now, Immutable: true,
	}
	request, err := contracts.NewAcornFoxLogsRequest(contracts.AcornFoxRuntimeReference{Fact: fact}, now.Add(-time.Second), 1, "afb-logs-public")
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := json.Marshal(map[string]any{"acornfox_log_payload_type": "logs", "request": request})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"kind": v1.TaskLogs, "parameters": json.RawMessage(parameters)})
	if err != nil {
		t.Fatal(err)
	}
	result := acornFoxStrictLogsTask{deploymentID: request.DeploymentID.String(), operationID: "operation_afb_logs_public", taskID: "task_afb_logs_public"}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO deployments(id,environment_id,release_id,state,created_at,updated_at) VALUES($1,$2,$3,'runtime_ready',$4,$4)`, []any{result.deploymentID, fixture.environmentID, fixture.releaseID, now}},
		{`INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES($1,$2,$3,$4,'observe','afb-logs-public','succeeded',$5,$6,$6)`, []any{result.operationID, fixture.applicationID, fixture.environmentID, result.deploymentID, "deployment/" + result.deploymentID + "/logs/web", now}},
		{`INSERT INTO task_leases(task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at) VALUES($1,$2,'logs-agent',$3,1,3,'completed',$4::jsonb,$5,$5)`, []any{result.taskID, result.operationID, now.Add(time.Minute), payload, now}},
	} {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func insertAcornFoxSyntheticControlTask(t *testing.T, ctx context.Context, db *sql.DB, fixture acornFoxProbeFixture, logs acornFoxStrictLogsTask, now time.Time) acornFoxStrictLogsTask {
	t.Helper()
	result := acornFoxStrictLogsTask{deploymentID: logs.deploymentID, operationID: "operation_afb_logs_lifecycle", taskID: "task_afb_logs_lifecycle"}
	payload := `{"kind":"deploy","parameters":{"acornfox_payload_type":"deploy"}}`
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES($1,$2,$3,$4,'deploy','afb-logs-lifecycle','succeeded',$5,$6,$6)`, []any{result.operationID, fixture.applicationID, fixture.environmentID, result.deploymentID, "deployment/" + result.deploymentID, now}},
		{`INSERT INTO task_leases(task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at) VALUES($1,$2,'control-agent',$3,1,3,'completed',$4::jsonb,$5,$5)`, []any{result.taskID, result.operationID, now.Add(time.Minute), payload, now}},
	} {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func insertAcornFoxUnboundBuildLogFixture(ctx context.Context, db *sql.DB, fixture acornFoxProbeFixture, now time.Time) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO build_plans(id,source_revision_id,source_digest,service_name,build_kind,context_path,dockerfile_path,target_repository,output_contract,secret_refs,idempotency_key,created_at) VALUES('plan_afb_logs_unbound','source_afb_probe',$1,'legacy','dockerfile','.','Dockerfile','registry.open-card.test/apps/legacy','{"format":"oci","retention":"persistent","storage_key":"afb-logs-unbound"}'::jsonb,'[]'::jsonb,'afb-logs-unbound',$2)`, []any{"sha256:" + strings.Repeat("d", 64), now}},
		{`INSERT INTO builds(id,plan_id,state,artifact_id,created_at,updated_at) VALUES('build_afb_logs_unbound','plan_afb_logs_unbound','succeeded','artifact_afb_logs_unbound',$1,$1)`, []any{now}},
		{`INSERT INTO artifacts(id,build_id,image_repository,image_digest,oci_storage_ref,size_bytes,created_at) VALUES('artifact_afb_logs_unbound','build_afb_logs_unbound','registry.open-card.test/apps/legacy','sha256:` + strings.Repeat("c", 64) + `','oci://afb-logs/unbound',1,$1)`, []any{now}},
		{`INSERT INTO release_artifacts(release_id,service_name,artifact_id) VALUES($1,'legacy','artifact_afb_logs_unbound')`, []any{fixture.releaseID}},
		{`INSERT INTO m4_log_indexes(id,application_id,service_name,build_id,category,log_stream,truncation,path,segment,byte_size,content_digest,created_at) VALUES('log_build_unbound',$1,'legacy','build_afb_logs_unbound','build','combined','complete','/safe/build/unbound.log',1,1,$2,$3)`, []any{fixture.applicationID, acornFoxLogDigest("b"), now}},
	} {
		if _, err := tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func assertAcornFoxLogsMigrationIdempotent(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	for _, migration := range []string{"0028_acornfox_log_metadata.sql", "0029_acornfox_log_provenance.sql"} {
		payload, err := os.ReadFile(filepath.Join("..", "..", "..", "migrations", "control-plane", migration))
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
				t.Fatalf("rerun %s migration %d: %v", migration[:4], run, err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatalf("commit rerun %s migration %d: %v", migration[:4], run, err)
			}
		}
	}
}

func validateAcornFoxLogsTestDSN(t *testing.T, dsn string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("task-scoped AcornFox logs database URL is invalid")
	}
	if host := parsed.Hostname(); host != "127.0.0.1" && host != "::1" && host != "localhost" {
		t.Fatal("task-scoped AcornFox logs database must be loopback-only")
	}
	database := strings.TrimPrefix(parsed.EscapedPath(), "/")
	if database == "" || strings.Contains(database, "/") || !strings.HasPrefix(database, "open_card_afblogs_") {
		t.Fatal("task-scoped AcornFox logs database name must use open_card_afblogs_ prefix")
	}
	return database
}

func resetAcornFoxLogsTestSchema(t *testing.T, ctx context.Context, db *sql.DB, expectedDatabase string) {
	t.Helper()
	var currentDatabase string
	if err := db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&currentDatabase); err != nil || currentDatabase != expectedDatabase {
		t.Fatal("connected database does not match validated dedicated AcornFox logs test database")
	}
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset validated dedicated AcornFox logs test schema: %v", err)
	}
}
