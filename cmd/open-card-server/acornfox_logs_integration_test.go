//go:build integration

package main

import (
	"context"
	"database/sql"
	"encoding/json"
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
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/observability"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// This is intentionally an opt-in, task-scoped PostgreSQL test. A run with
// OPEN_CARD_AFB_LOGS_TEST_DATABASE_URL set must not skip; its database name
// and loopback host are constrained before its public schema is reset.
func TestAcornFoxLogsHTTPRestartReconstructsPageAndCursor(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_LOGS_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_LOGS_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	acornFoxLogsIntegrationValidateDSN(t, dsn)
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
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	acornFoxLogsIntegrationMigrations(t, ctx, db)
	now := time.Unix(1_700_000_000, 0).UTC()
	fixture := acornFoxLogsIntegrationFixture(t, ctx, db, now)
	store := postgres.NewStore(db)
	root := t.TempDir()
	logs, err := observability.NewLogStore(observability.LogStoreConfig{RootDir: root, MaxFileBytes: 128 << 10, MaxTotalBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	build, err := logs.AppendRecord(observability.LogCategoryBuild, "build_build_1", []byte("build token=server-secret locator=https://private.example/repo.git workspace=/private/acornfox/work"))
	if err != nil {
		t.Fatal(err)
	}
	runtimeOne, err := logs.AppendRecord(observability.LogCategoryRuntime, "runtime_operation_1", []byte("runtime one token=server-secret"))
	if err != nil {
		t.Fatal(err)
	}
	runtimeTwo, err := logs.AppendRecord(observability.LogCategoryRuntime, "runtime_operation_2", []byte("runtime two workspace=/private/acornfox/work"))
	if err != nil {
		t.Fatal(err)
	}
	buildDigest, _, err := acornFoxLogSegmentDigest(filepath.Join(logs.RootDir(), string(observability.LogCategoryBuild)), build.Path)
	if err != nil {
		t.Fatal(err)
	}
	runtimeOneDigest, _, err := acornFoxLogSegmentDigest(filepath.Join(logs.RootDir(), string(observability.LogCategoryRuntime)), runtimeOne.Path)
	if err != nil {
		t.Fatal(err)
	}
	runtimeTwoDigest, _, err := acornFoxLogSegmentDigest(filepath.Join(logs.RootDir(), string(observability.LogCategoryRuntime)), runtimeTwo.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []postgres.LogIndex{
		{ID: "log_build_1", ApplicationID: "app_logs_http", ServiceName: "web", BuildID: "build_logs_http", Category: postgres.LogIndexBuild, LogStream: postgres.LogStreamCombined, Truncation: postgres.LogTruncationSourceLimited, Path: build.Path, Segment: build.Sequence, ByteSize: build.Bytes, ContentDigest: buildDigest, CreatedAt: now},
		{ID: "log_runtime_1", ApplicationID: "app_logs_http", ServiceName: "web", DeploymentID: fixture.deploymentID, OperationID: fixture.operationOne, LogTaskID: fixture.taskOne, Category: postgres.LogIndexRuntime, LogStream: postgres.LogStreamCombined, Truncation: postgres.LogTruncationComplete, Path: runtimeOne.Path, Segment: runtimeOne.Sequence, ByteSize: runtimeOne.Bytes, ContentDigest: runtimeOneDigest, CreatedAt: now.Add(time.Second)},
		{ID: "log_runtime_2", ApplicationID: "app_logs_http", ServiceName: "web", DeploymentID: fixture.deploymentID, OperationID: fixture.operationTwo, LogTaskID: fixture.taskTwo, Category: postgres.LogIndexRuntime, LogStream: postgres.LogStreamStdout, Truncation: postgres.LogTruncationComplete, Path: runtimeTwo.Path, Segment: runtimeTwo.Sequence, ByteSize: runtimeTwo.Bytes, ContentDigest: runtimeTwoDigest, CreatedAt: now.Add(2 * time.Second)},
	} {
		if err := store.AppendLogIndex(ctx, index, now); err != nil {
			t.Fatalf("append %s: %v", index.ID, err)
		}
	}

	handler := newAcornFoxLogsHTTPHandler(store, logs)
	first := acornFoxLogsIntegrationGET(t, handler, fixture.deploymentID, "/?source=runtime&limit=1")
	if first.Availability != "available" {
		t.Fatalf("first availability got %q, want %q", first.Availability, "available")
	}
	if len(first.Items) != 1 {
		t.Fatalf("first item count got %d, want 1: %#v", len(first.Items), first.Items)
	}
	if first.NextCursor == nil {
		t.Fatalf("first next cursor is nil")
	}
	firstCursor, ok := first.NextCursor.(string)
	if !ok || strings.TrimSpace(firstCursor) == "" {
		t.Fatalf("first next cursor type/value=%T/%#v, want non-empty string", first.NextCursor, first.NextCursor)
	}
	if strings.Contains(first.Items[0].Content, "server-secret") {
		t.Fatalf("first runtime content leaked secret: %q", first.Items[0].Content)
	}
	buildResponse := acornFoxLogsIntegrationGET(t, handler, fixture.deploymentID, "/?source=build")
	if len(buildResponse.Items) != 1 || strings.Contains(buildResponse.Items[0].Content, "private.example") || strings.Contains(buildResponse.Items[0].Content, "/private/acornfox/work") {
		t.Fatalf("build response did not isolate/redact source facts: %+v", buildResponse)
	}

	// Reopen both durable components to prove the page can be reconstructed
	// without retained in-memory cursor or content state.
	if err := logs.Close(); err != nil {
		t.Fatal(err)
	}
	restartedLogs, err := observability.NewLogStore(observability.LogStoreConfig{RootDir: root, MaxFileBytes: 128 << 10, MaxTotalBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	restartedStore := postgres.NewStore(db)
	restarted := newAcornFoxLogsHTTPHandler(restartedStore, restartedLogs)
	next := acornFoxLogsIntegrationGET(t, restarted, fixture.deploymentID, "/?source=runtime&limit=1&cursor="+url.QueryEscape(firstCursor))
	if len(next.Items) != 1 {
		t.Fatalf("restart item count got %d, want 1: %#v", len(next.Items), next.Items)
	}
	if got, want := next.Items[0].Content, "runtime one token=[REDACTED]"; got != want {
		t.Fatalf("restart content got %q (%d bytes), want %q (%d bytes)", got, len(got), want, len(want))
	}
	if next.NextCursor != nil {
		t.Fatalf("restart next cursor got %T/%#v, want nil", next.NextCursor, next.NextCursor)
	}
}

func TestM4BuildLogSinkReplaysCrashGapAndRetiresMissingSegments(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_LOGS_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_LOGS_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	acornFoxLogsIntegrationValidateDSN(t, dsn)
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
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	acornFoxLogsIntegrationMigrations(t, ctx, db)
	now := time.Unix(1_700_000_000, 0).UTC()
	acornFoxLogsIntegrationFixture(t, ctx, db, now)

	logs, err := observability.NewLogStore(observability.LogStoreConfig{RootDir: t.TempDir(), MaxFileBytes: 4, MaxTotalBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	request := contracts.BuildRequest{BuildID: "build_logs_http", Plan: domain.BuildPlan{ServiceName: "web"}, Source: domain.SourceRevision{ApplicationID: "app_logs_http"}}
	stream := "build-" + request.BuildID.String()
	if err := logs.Append(observability.LogCategoryBuild, stream, []byte("crash-gap")); err != nil {
		t.Fatal(err)
	}
	// Simulate a process crash after the file write but before the metadata
	// transaction. The replay must index this immutable stream, not append it.
	sink := &m4BuildLogSink{store: postgres.NewStore(db), logs: logs, clock: func() time.Time { return now }}
	path, err := sink.StoreBuildLog(ctx, request, "crash-gap")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := logs.Read(observability.LogCategoryBuild, stream); err != nil || string(got) != "crash-gap" {
		t.Fatalf("crash replay duplicated or lost bytes: %q err=%v", got, err)
	}
	files, err := logs.List(observability.LogCategoryBuild, stream)
	if err != nil || len(files) < 2 || path != files[len(files)-1].Path {
		t.Fatalf("crash replay files=%#v path=%q err=%v", files, path, err)
	}
	var active int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m4_log_indexes WHERE build_id='build_logs_http' AND retired_at IS NULL`).Scan(&active); err != nil || active != len(files) {
		t.Fatalf("crash replay active indexes=%d files=%d err=%v", active, len(files), err)
	}
	if _, err := sink.StoreBuildLog(ctx, request, "crash-gap"); err != nil {
		t.Fatal(err)
	}
	if got, err := logs.Read(observability.LogCategoryBuild, stream); err != nil || string(got) != "crash-gap" {
		t.Fatalf("indexed replay duplicated or lost bytes: %q err=%v", got, err)
	}

	acornFoxRemoveLogFiles(t, files)
	path, err = sink.StoreBuildLog(ctx, request, "recovered")
	if err != nil {
		t.Fatal(err)
	}
	firstRecoveryStream := stream + "-recovery-1"
	if got, err := logs.Read(observability.LogCategoryBuild, firstRecoveryStream); err != nil || string(got) != "recovered" {
		t.Fatalf("missing-file replay did not replace unavailable bytes: %q err=%v", got, err)
	}
	if !strings.Contains(path, firstRecoveryStream) {
		t.Fatalf("missing-file replay did not select first recovery generation: %q", path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("missing-file replay returned stale path %q: %v", path, err)
	}
	firstRecoveryFiles, err := logs.List(observability.LogCategoryBuild, firstRecoveryStream)
	if err != nil {
		t.Fatal(err)
	}
	var retired int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m4_log_indexes WHERE build_id='build_logs_http' AND retired_at IS NOT NULL`).Scan(&retired); err != nil || retired != len(files) {
		t.Fatalf("missing-file replay retired=%d files=%d err=%v", retired, len(files), err)
	}

	acornFoxRemoveLogFiles(t, firstRecoveryFiles)
	path, err = sink.StoreBuildLog(ctx, request, "recovered-again")
	if err != nil {
		t.Fatal(err)
	}
	secondRecoveryStream := stream + "-recovery-2"
	if got, err := logs.Read(observability.LogCategoryBuild, secondRecoveryStream); err != nil || string(got) != "recovered-again" || !strings.Contains(path, secondRecoveryStream) {
		t.Fatalf("second recovery stream/content/path=%q/%q/%q err=%v", secondRecoveryStream, got, path, err)
	}
	secondRecoveryFiles, err := logs.List(observability.LogCategoryBuild, secondRecoveryStream)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m4_log_indexes WHERE build_id='build_logs_http' AND retired_at IS NOT NULL`).Scan(&retired); err != nil || retired != len(files)+len(firstRecoveryFiles) {
		t.Fatalf("second recovery retired=%d err=%v", retired, err)
	}

	acornFoxRemoveLogFiles(t, secondRecoveryFiles)
	thirdRecoveryStream := stream + "-recovery-3"
	if err := logs.Append(observability.LogCategoryBuild, thirdRecoveryStream, []byte("crash-recovery")); err != nil {
		t.Fatal(err)
	}
	path, err = sink.StoreBuildLog(ctx, request, "crash-recovery")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := logs.Read(observability.LogCategoryBuild, thirdRecoveryStream); err != nil || string(got) != "crash-recovery" || !strings.Contains(path, thirdRecoveryStream) {
		t.Fatalf("recovery crash replay duplicated stream/content/path=%q/%q/%q err=%v", thirdRecoveryStream, got, path, err)
	}
	thirdRecoveryFiles, err := logs.List(observability.LogCategoryBuild, thirdRecoveryStream)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m4_log_indexes WHERE build_id='build_logs_http' AND retired_at IS NULL`).Scan(&active); err != nil || active != len(thirdRecoveryFiles) {
		t.Fatalf("recovery crash active=%d files=%d err=%v", active, len(thirdRecoveryFiles), err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m4_log_indexes WHERE build_id='build_logs_http' AND retired_at IS NOT NULL`).Scan(&retired); err != nil || retired != len(files)+len(firstRecoveryFiles)+len(secondRecoveryFiles) {
		t.Fatalf("recovery crash retired=%d err=%v", retired, err)
	}
}

func acornFoxRemoveLogFiles(t *testing.T, files []observability.LogFile) {
	t.Helper()
	for _, file := range files {
		if err := os.Remove(file.Path); err != nil {
			t.Fatal(err)
		}
	}
}

func acornFoxLogsIntegrationGET(t *testing.T, handler *AcornFoxLogsHTTPHandler, deploymentID domain.ID, path string) acornFoxLogsResponse {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.Handle(recorder, httptest.NewRequest(http.MethodGet, path, nil), "app_logs_http", deploymentID)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET %s status=%d body=%s", path, recorder.Code, recorder.Body.String())
	}
	var response acornFoxLogsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func acornFoxLogsIntegrationValidateDSN(t *testing.T, dsn string) {
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
}

func acornFoxLogsIntegrationMigrations(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join("..", "..", "migrations", "control-plane"))
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".sql" {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		payload, err := os.ReadFile(filepath.Join("..", "..", "migrations", "control-plane", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, string(payload)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
}

type acornFoxLogsIntegrationDelivery struct {
	deploymentID domain.ID
	operationOne domain.ID
	operationTwo domain.ID
	taskOne      domain.ID
	taskTwo      domain.ID
}

func acornFoxLogsIntegrationFixture(t *testing.T, ctx context.Context, db *sql.DB, now time.Time) acornFoxLogsIntegrationDelivery {
	t.Helper()
	fact := contracts.AcornFoxRuntimeReleaseFact{
		ApplicationID: "app_logs_http", EnvironmentID: "env_logs_http", ReleaseID: "release_logs_http", ServiceName: "web",
		Image:         domain.ImageDigest{Repository: "registry.open-card.test/apps/web", Digest: "sha256:" + strings.Repeat("b", 64)},
		Resources:     contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 100, MemoryBytes: 1024, PIDs: 10, DiskReservationBytes: 2048},
		ContainerPort: 8080, AcceptedAt: now, Immutable: true,
	}
	firstRequest, err := contracts.NewAcornFoxLogsRequest(contracts.AcornFoxRuntimeReference{Fact: fact}, now.Add(-time.Second), 1, "logs-http-1")
	if err != nil {
		t.Fatal(err)
	}
	secondRequest, err := contracts.NewAcornFoxLogsRequest(contracts.AcornFoxRuntimeReference{Fact: fact}, now.Add(-2*time.Second), 1, "logs-http-2")
	if err != nil {
		t.Fatal(err)
	}
	if firstRequest.DeploymentID != secondRequest.DeploymentID {
		t.Fatal("AcornFox logs task derivation drifted deployment identity")
	}
	firstPayload := acornFoxLogsIntegrationTaskPayload(t, firstRequest)
	secondPayload := acornFoxLogsIntegrationTaskPayload(t, secondRequest)
	result := acornFoxLogsIntegrationDelivery{deploymentID: firstRequest.DeploymentID, operationOne: "operation_logs_http_1", operationTwo: "operation_logs_http_2", taskOne: "task_logs_http_1", taskTwo: "task_logs_http_2"}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO applications(id,name,created_at,updated_at) VALUES('app_logs_http','AcornFox logs',$1,$1)`, []any{now}},
		{`INSERT INTO environments(id,application_id,name,created_at) VALUES('env_logs_http','app_logs_http','default',$1)`, []any{now}},
		{`INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable,created_at) VALUES('source_logs_http','app_logs_http','upload','upload','https://private.example/repo.git','main',$1,'/private/acornfox/work','prepared',true,$2)`, []any{"sha256:" + strings.Repeat("a", 64), now}},
		{`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration,created_at) VALUES('definition_logs_http','app_logs_http','source_logs_http',1,'{}'::jsonb,$1)`, []any{now}},
		{`INSERT INTO releases(id,application_id,definition_id,version,service_digests,created_at) VALUES('release_logs_http','app_logs_http','definition_logs_http',1,jsonb_build_object('web',$1::text),$2)`, []any{"sha256:" + strings.Repeat("b", 64), now}},
		{`INSERT INTO deployments(id,environment_id,release_id,state,created_at,updated_at) VALUES($1,'env_logs_http','release_logs_http','runtime_ready',$2,$2)`, []any{result.deploymentID, now}},
		{`INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES($1,'app_logs_http','env_logs_http',$2,'observe','logs-1','succeeded',$3,$4,$4)`, []any{result.operationOne, result.deploymentID, "deployment/" + result.deploymentID.String() + "/logs/web", now}},
		{`INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES($1,'app_logs_http','env_logs_http',$2,'observe','logs-2','succeeded',$3,$4,$4)`, []any{result.operationTwo, result.deploymentID, "deployment/" + result.deploymentID.String() + "/logs/web", now}},
		{`INSERT INTO task_leases(task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at) VALUES($1,$2,'logs-agent',$3,1,3,'completed',$4::jsonb,$5,$5)`, []any{result.taskOne, result.operationOne, now.Add(time.Minute), firstPayload, now}},
		{`INSERT INTO task_leases(task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at) VALUES($1,$2,'logs-agent',$3,1,3,'completed',$4::jsonb,$5,$5)`, []any{result.taskTwo, result.operationTwo, now.Add(time.Minute), secondPayload, now}},
		{`INSERT INTO build_plans(id,source_revision_id,source_digest,service_name,build_kind,context_path,dockerfile_path,acornfox_definition_digest,acornfox_dockerfile_digest,target_repository,output_contract,secret_refs,idempotency_key,created_at) VALUES('plan_logs_http','source_logs_http',$1,'web','dockerfile','.','Dockerfile',$2,$3,'registry.open-card.test/apps/web','{"format":"oci","retention":"persistent","storage_key":"logs-http"}'::jsonb,'[]'::jsonb,'logs-http',$4)`, []any{"sha256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("d", 64), "sha256:" + strings.Repeat("e", 64), now}},
		// The production state machine creates a build before its artifact. Keep
		// that order so the fixture proves both the build-state check and the
		// deferred build→artifact foreign key without weakening either.
		{`INSERT INTO builds(id,plan_id,state,created_at,updated_at) VALUES('build_logs_http','plan_logs_http','running',$1,$1)`, []any{now}},
		{`INSERT INTO artifacts(id,build_id,image_repository,image_digest,oci_storage_ref,size_bytes,created_at) VALUES('artifact_logs_http','build_logs_http','registry.open-card.test/apps/web',$1,'oci://logs-http',1,$2)`, []any{"sha256:" + strings.Repeat("b", 64), now}},
		{`UPDATE builds SET state='succeeded',artifact_id='artifact_logs_http',updated_at=$1 WHERE id='build_logs_http'`, []any{now}},
		{`INSERT INTO release_artifacts(release_id,service_name,artifact_id) VALUES('release_logs_http','web','artifact_logs_http')`, nil},
	} {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func acornFoxLogsIntegrationTaskPayload(t *testing.T, request contracts.AcornFoxLogsRequest) json.RawMessage {
	t.Helper()
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
