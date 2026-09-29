package migrationpreview

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/auth"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/persistence/postgres"
	"github.com/open-card/open-card/internal/persistence/sqlite"
)

func fixtureSQL(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		if state, ok := err.(interface{ SQLState() string }); ok {
			t.Fatalf("task_fixture_sql_failed SQLSTATE=%s", state.SQLState())
		}
		t.Fatal("task_fixture_sql_failed")
	}
}
func rawTarget(t *testing.T, dir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "projection", "acornfox.db"))
	if err != nil {
		t.Fatal("diagnostic_read_failed")
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}
func assertCoreGate(t *testing.T, result Result) {
	t.Helper()
	ctx := context.Background()
	dir := filepath.Join(result.PrivateDirectory, "projection")
	db := rawTarget(t, result.PrivateDirectory)
	var generation, beforeFacts int64
	if db.QueryRow(`SELECT generation FROM core_generation`).Scan(&generation) != nil || db.QueryRow(`SELECT count(*) FROM applications`).Scan(&beforeFacts) != nil {
		t.Fatal("gate_baseline_failed")
	}
	fd, err := syscall.Open(filepath.Join(dir, "acornfox.lock"), syscall.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal("gate_lock_failed")
	}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		syscall.Close(fd)
		t.Fatal("gate_lock_failed")
	}
	if opened, err := sqlite.Open(sqlite.Config{DataDirectory: dir}); !errors.Is(err, sqlite.ErrStoreLocked) {
		if opened != nil {
			opened.Close()
		}
		t.Fatal("held_preview_lock_not_enforced")
	}
	syscall.Flock(fd, syscall.LOCK_UN)
	syscall.Close(fd)
	if opened, err := sqlite.Open(sqlite.Config{DataDirectory: dir}); !errors.Is(err, sqlite.ErrIncompatibleSchema) {
		if opened != nil {
			opened.Close()
		}
		t.Fatal("diagnostic_marker_not_enforced")
	}
	var afterGeneration, afterFacts int64
	if db.QueryRowContext(ctx, `SELECT generation FROM core_generation`).Scan(&afterGeneration) != nil || db.QueryRowContext(ctx, `SELECT count(*) FROM applications`).Scan(&afterFacts) != nil || generation != afterGeneration || beforeFacts != afterFacts {
		t.Fatal("core_refusal_mutated_diagnostic")
	}
}

func TestTaskScopedPG16MigrationPreview(t *testing.T) {
	file := os.Getenv("TC1G_TEST_DSN_FILE")
	parent := os.Getenv("TC1G_TEST_PRIVATE_PARENT")
	container := os.Getenv("TC1G_TEST_CONTAINER")
	if file == "" || parent == "" || container == "" {
		t.Skip("explicit task-owned PG16 fixture files required")
	}
	raw, err := privateFile(file)
	if err != nil {
		t.Fatal("private_fixture_file_rejected")
	}
	db, err := sql.Open("pgx", strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal("task_fixture_open_failed")
	}
	defer db.Close()
	var name string
	if db.QueryRow(`SELECT current_database()`).Scan(&name) != nil || name != "open_card_tc1g_0040" {
		t.Fatal("wrong_task_fixture_identity")
	}
	ctx := context.Background()
	store := postgres.NewStore(db)
	now := time.Date(2026, 9, 26, 1, 2, 3, 123456000, time.UTC)
	store.SetClock(func() time.Time { return now })
	hashing, err := auth.NewLocalService(auth.Config{Store: store, Origin: "http://127.0.0.1:19999"})
	if err != nil {
		t.Fatal("fixture_hash_service_failed")
	}
	hash, err := hashing.HashPassword("TaskFixturePassword_Only2026!")
	if err != nil {
		t.Fatal("fixture_hash_failed")
	}
	cred := domain.AdminCredential{ID: "admin_tc1g", PasswordHashScheme: auth.PasswordHashScheme, PasswordHash: hash, CredentialVersion: 1, CreatedAt: now, UpdatedAt: now}
	if store.CreateAdminCredential(ctx, cred) != nil {
		t.Fatal("fixture_auth_failed")
	}
	disabled := now.Add(time.Hour)
	old := cred
	old.ID = "admin_tc1g_history"
	old.DisabledAt = &disabled
	if store.CreateAdminCredential(ctx, old) != nil {
		t.Fatal("fixture_auth_history_failed")
	}
	session := domain.AdminSession{ID: "session_tc1g", AdminID: cred.ID, SessionDigest: domain.AuthDigest(strings.Repeat("a", 64)), CSRFDigest: domain.AuthDigest(strings.Repeat("b", 64)), CredentialVersion: 1, CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(8 * time.Hour), AbsoluteExpiresAt: now.Add(24 * time.Hour)}
	if store.CreateAdminSession(ctx, session) != nil {
		t.Fatal("fixture_session_failed")
	}
	if store.RevokeAdminSession(ctx, session.ID, now.Add(time.Minute)) != nil {
		t.Fatal("fixture_session_revoke_failed")
	}
	for i := 0; i < 5; i++ {
		if _, err := store.RecordAdminLoginFailure(ctx, cred.ID, domain.AuthDigest(strings.Repeat("c", 64)), now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal("fixture_rate_history_failed")
		}
	}
	app, _ := domain.NewApplication("tc1g genuine application", now)
	envID, _ := domain.NewID("env")
	opID, _ := domain.NewID("op")
	taskID, _ := domain.NewID("task")
	created, err := store.CreateApplication(ctx, application.CreateApplicationRecord{Application: app, EnvironmentID: envID, OperationID: opID, TaskID: taskID, IdempotencyKey: "tc1g-create", Event: application.Event{SchemaVersion: "1.1", OccurredAt: now, Kind: "operation.created", Status: "preparing"}})
	if err != nil {
		t.Fatal("fixture_application_failed")
	}
	claim, found, err := store.ClaimTask(ctx, postgres.ClaimTaskRequest{Owner: "legacy-worker", Now: now.Add(time.Minute), Kinds: []string{"application.create"}, LeasePolicy: postgres.LeasePolicy{Duration: time.Hour, MaxAttempts: 3}})
	if err != nil || !found {
		t.Fatal("fixture_old_lease_failed")
	}
	fixtureSQL(t, db, `SELECT setval('outbox_events_stream_sequence',10,true)`)
	event := application.Event{SchemaVersion: "1.1", ID: "evt-tc1g-history", OperationID: created.OperationID.String(), ApplicationID: created.Application.ID.String(), Sequence: 11, OccurredAt: now.Add(time.Second), Kind: "operation.created", Status: "preparing"}
	payload, _ := json.Marshal(event)
	second, err := store.AppendOutboxEvent(ctx, postgres.OutboxEvent{ID: event.ID, AggregateType: "operation", AggregateID: created.OperationID.String(), AggregateVersion: 1, EventType: event.Kind, Payload: payload, CreatedAt: event.OccurredAt, PayloadVersion: "1.1"})
	if err != nil || second.StreamSequence != 11 || second.Sequence != 2 {
		t.Fatal("fixture_outbox_gap_failed")
	}
	if _, err := store.MarkOutboxPublished(ctx, created.Event.ID, now.Add(time.Second)); err != nil {
		t.Fatal("fixture_published_history_failed")
	}
	fixtureSQL(t, db, `SELECT setval('outbox_events_stream_sequence',15,true)`)
	fixtureSQL(t, db, `INSERT INTO audit_evidence(id,actor_type,actor_id,action,reason,input_digest,result,evidence_refs,previous_hash,record_hash,created_at) VALUES('audit_tc1g_history','system','release-controller','historical.serving','preserved source reason',$1,'recorded','[{"id":"evidence_legacy","kind":"probe"}]',NULL,$2,$3)`, "sha256:"+strings.Repeat("d", 64), "sha256:"+strings.Repeat("e", 64), now)
	// The exported snapshot is a real READ ONLY transaction, not a query sandbox.
	selected, err := install.NewSelectedPostgresDatabase([]byte("OPEN_CARD_DATABASE_URL=" + strings.TrimSpace(string(raw)) + "\n"))
	if err != nil {
		t.Fatal("snapshot_open_failed")
	}
	snap, err := selected.BeginPlatformBackupSnapshot(ctx)
	if err != nil {
		t.Fatal("snapshot_begin_failed")
	}
	if rows, err := snap.ReadRows(ctx, `INSERT INTO applications(id,name) VALUES('tc1g_readonly_reject','x') RETURNING id`); err == nil {
		rows.Close()
		t.Fatal("snapshot_write_allowed")
	}
	if snap.Rollback() != nil {
		t.Fatal("snapshot_probe_rollback_failed")
	}
	selected.Close()
	cfg := Config{SourceDSNFile: file, OutputParent: parent, DumpTool: filepath.Join(parent, "pg-dump")}
	t.Run("untrusted-tool-rejected-before-credentials", func(t *testing.T) {
		unsafe := t.TempDir()
		sentinel := filepath.Join(parent, "untrusted-executed")
		tool := filepath.Join(unsafe, "pg-dump")
		if os.WriteFile(tool, []byte("#!/bin/sh\ntouch "+sentinel+"\n"), 0700) != nil || os.Chmod(unsafe, 0777) != nil {
			t.Fatal("unsafe_fixture_prepare_failed")
		}
		defer os.Chmod(unsafe, 0700)
		bad := cfg
		bad.DumpTool = tool
		res, err := Run(ctx, bad)
		if err == nil || res.PrivateDirectory != "" {
			t.Fatal("untrusted_tool_not_preflight_rejected")
		}
		if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
			t.Fatal("credentials_reached_untrusted_tool")
		}
	})
	result, err := Run(ctx, cfg)
	if err != nil {
		t.Fatal("preview_run_failed:" + err.Error())
	}
	if !result.Report.ProjectionVerified || result.Report.ActivationEligible || result.Report.SchemaVersion != 40 || result.Report.Status != "projection_verified_snapshot_import_incomplete" {
		t.Fatal("preview_boundary_or_projection_failed")
	}
	t.Log("0040 projection and full snapshot protected at", result.PrivateDirectory)
	target := rawTarget(t, result.PrivateDirectory)
	// Exact PostgreSQL-persisted JSONB export bytes, not pre-insert HTTP formatting.
	for _, fact := range []struct {
		source, target string
		args           []any
	}{{`SELECT response::text FROM idempotency_records WHERE scope='application.create' AND idempotency_key=$1`, `SELECT response FROM idempotency_records WHERE scope='application.create' AND idempotency_key=?`, []any{"tc1g-create"}}, {`SELECT payload::text FROM task_leases WHERE task_id=$1`, `SELECT payload FROM task_leases WHERE task_id=?`, []any{claim.ID.String()}}, {`SELECT evidence_refs::text FROM audit_evidence WHERE id=$1`, `SELECT evidence_refs FROM audit_evidence WHERE id=?`, []any{"audit_tc1g_history"}}} {
		var a, b string
		if db.QueryRow(fact.source, fact.args...).Scan(&a) != nil || target.QueryRow(fact.target, fact.args...).Scan(&b) != nil || a != b {
			t.Fatal("persisted_json_export_bytes_changed")
		}
	}
	var cg, lg, attempt int64
	var owner, state string
	if target.QueryRow(`SELECT core_generation,lease_generation,attempt,lease_owner,state FROM task_leases WHERE task_id=?`, claim.ID.String()).Scan(&cg, &lg, &attempt, &owner, &state) != nil || cg != 0 || lg != 0 || attempt != int64(claim.Attempt) || owner != claim.LeaseOwner || state != "leased" {
		t.Fatal("lease_facts_reauthorized_or_changed")
	}
	var global, local int64
	if target.QueryRow(`SELECT sequence,stream_sequence FROM outbox_events WHERE id=?`, second.ID).Scan(&local, &global) != nil || local != 2 || global != 11 {
		t.Fatal("sequence_dimensions_changed")
	}
	var published int
	if target.QueryRow(`SELECT count(*) FROM outbox_events WHERE published_at IS NOT NULL`).Scan(&published) != nil || published != 1 {
		t.Fatal("published_history_lost")
	}
	var protocolCount int
	for _, c := range result.Report.Coverage {
		if c.Name == "protocol_contracts" {
			protocolCount = int(c.Rows)
		}
	}
	if protocolCount == 0 {
		t.Fatal("protocol_seed_disappeared")
	}
	assertCoreGate(t, result)
	// Restore the FULL same-snapshot custom dump into a separate owned database.
	command := exec.Command("docker", "exec", container, "createdb", "-U", "postgres", "open_card_tc1g_restore")
	if command.Run() != nil {
		t.Fatal("restore_fixture_create_failed")
	}
	command = exec.Command("docker", "exec", container, "pg_restore", "-U", "postgres", "--exit-on-error", "--no-owner", "--no-acl", "-d", "open_card_tc1g_restore", filepath.Join(result.PrivateDirectory, "control-plane.dump"))
	if command.Run() != nil {
		t.Fatal("full_dump_restore_failed")
	}
	restoreDSN := strings.Replace(strings.TrimSpace(string(raw)), "/open_card_tc1g_0040?", "/open_card_tc1g_restore?", 1)
	restored, err := sql.Open("pgx", restoreDSN)
	if err != nil {
		t.Fatal("restore_open_failed")
	}
	defer restored.Close()
	for _, c := range result.Report.Coverage {
		if c.Kind != "r" && c.Kind != "p" {
			continue
		}
		var count int64
		if restored.QueryRow(`SELECT count(*) FROM ONLY public.`+identifier(c.Name)).Scan(&count) != nil || count != c.Rows {
			t.Fatal("full_dump_table_count_mismatch")
		}
	}
	var high int64
	if restored.QueryRow(`SELECT last_value FROM outbox_events_stream_sequence`).Scan(&high) != nil || high != 15 {
		t.Fatal("full_dump_sequence_metadata_lost")
	}
	interrupted, err := run(ctx, cfg, true)
	if err != nil || interrupted.Report.ProjectionVerified || interrupted.Report.ActivationEligible {
		t.Fatal("interruption_false_success")
	}
	interruptedDB := rawTarget(t, interrupted.PrivateDirectory)
	var count int
	if interruptedDB.QueryRow(`SELECT count(*) FROM applications`).Scan(&count) != nil || count != 0 {
		t.Fatal("interruption_partial_projection")
	}
	assertCoreGate(t, interrupted)
	retry, err := Run(ctx, cfg)
	if err != nil || !retry.Report.ProjectionVerified || !reflect.DeepEqual(retry.Report.ProjectionCounts, result.Report.ProjectionCounts) {
		t.Fatal("retry_projection_mismatch")
	}
	if !reflect.DeepEqual(retry.Report.Coverage, result.Report.Coverage) {
		t.Fatal("readonly_source_changed")
	}
	t.Run("unknown-column-and-bad-ledger", func(t *testing.T) {
		fixtureSQL(t, db, `ALTER TABLE task_leases ADD COLUMN tc1g_unmapped text`)
		unknown, err := Run(ctx, cfg)
		if err != nil || unknown.Report.ProjectionVerified || unknown.Report.ActivationEligible || len(unknown.Report.SchemaDifferences) == 0 {
			t.Fatal("unknown_column_not_rejected")
		}
		fixtureSQL(t, db, `ALTER TABLE task_leases DROP COLUMN tc1g_unmapped`)
		fixtureSQL(t, db, `CREATE TABLE tc1g_unknown_relation(id text)`)
		unknownRelation, err := Run(ctx, cfg)
		if err != nil || unknownRelation.Report.ProjectionVerified || len(unknownRelation.Report.SchemaDifferences) == 0 {
			t.Fatal("unknown_relation_not_rejected")
		}
		fixtureSQL(t, db, `DROP TABLE tc1g_unknown_relation`)
		data, _ := schemas.ReadFile("schemas/pg0040.json")
		var expected Matrix
		if json.Unmarshal(data, &expected) != nil {
			t.Fatal("compiled_fixture_matrix_invalid")
		}
		viewSQL := ""
		for _, r := range expected.Relations {
			if r.Name == "m6_ai_settings_current" {
				viewSQL = r.ViewDefinition
			}
		}
		if viewSQL == "" {
			t.Fatal("frozen_view_missing")
		}
		fixtureSQL(t, db, `CREATE OR REPLACE VIEW m6_ai_settings_current AS SELECT * FROM (`+strings.TrimSuffix(strings.TrimSpace(viewSQL), ";")+`) original WHERE false`)
		unknownView, err := Run(ctx, cfg)
		if err != nil || unknownView.Report.ProjectionVerified || len(unknownView.Report.SchemaDifferences) == 0 {
			t.Fatal("unknown_view_definition_not_rejected")
		}
		fixtureSQL(t, db, `CREATE OR REPLACE VIEW m6_ai_settings_current AS `+viewSQL)
		var checksum string
		if db.QueryRow(`SELECT checksum FROM schema_migrations WHERE version='0040'`).Scan(&checksum) != nil {
			t.Fatal("fixture_ledger_failed")
		}
		fixtureSQL(t, db, `UPDATE schema_migrations SET checksum=$1 WHERE version='0040'`, strings.Repeat("0", 64))
		bad, err := Run(ctx, cfg)
		if err != nil || bad.Report.ProjectionVerified || bad.Report.ActivationEligible {
			t.Fatal("bad_ledger_not_rejected")
		}
		fixtureSQL(t, db, `UPDATE schema_migrations SET checksum=$1 WHERE version='0040'`, checksum)
	})
	// Exact outbox protocol failures in the existing rejection phase, not a new matrix.
	badVersion := event
	badVersion.ID = "evt-tc1g-version9"
	badVersion.SchemaVersion = "9.9"
	badVersion.Sequence = 16
	badPayload, _ := json.Marshal(badVersion)
	fixtureSQL(t, db, `INSERT INTO outbox_events(id,aggregate_type,aggregate_id,aggregate_version,sequence,stream_sequence,event_type,payload,payload_version) VALUES('evt-tc1g-version9','operation',$1,1,3,16,'operation.created',$2,'9.9')`, created.OperationID.String(), string(badPayload))
	unknownPayload := event
	unknownPayload.ID = "evt-tc1g-source-ref"
	unknownPayload.Sequence = 17
	unknownBytes, _ := json.Marshal(unknownPayload)
	unknownBytes = append(unknownBytes[:len(unknownBytes)-1], []byte(`,"source_revision_id":"source_not_projected"}`)...)
	fixtureSQL(t, db, `INSERT INTO outbox_events(id,aggregate_type,aggregate_id,aggregate_version,sequence,stream_sequence,event_type,payload,payload_version) VALUES('evt-tc1g-source-ref','operation',$1,1,4,17,'operation.created',$2,'1.1')`, created.OperationID.String(), string(unknownBytes))
	outboxRejected, err := Run(ctx, cfg)
	if err != nil || outboxRejected.Report.ProjectionVerified || outboxRejected.Report.ActivationEligible {
		t.Fatal("outbox_protocol_or_extra_reference_accepted")
	}
	codes := strings.Join(outboxRejected.Report.FailureCodes, " ")
	if !strings.Contains(codes, "outbox_events.unsupported_event_version") || !strings.Contains(codes, "outbox_events.unsupported_event_payload") {
		t.Fatal("outbox_failure_codes_missing")
	}
	fixtureSQL(t, db, `UPDATE operations SET operation_type='source.unsupported',target_ref='unprojected_source' WHERE id=$1`, created.OperationID.String())
	fixtureSQL(t, db, `UPDATE task_leases SET negotiated_capabilities='{}' WHERE task_id=$1`, claim.ID.String())
	scopeRejected, err := Run(ctx, cfg)
	if err != nil || scopeRejected.Report.ProjectionVerified {
		t.Fatal("operation_or_nonarray_capability_accepted")
	}
	scopeCodes := strings.Join(scopeRejected.Report.FailureCodes, " ")
	if !strings.Contains(scopeCodes, "operations.unsupported_operation_target") || !strings.Contains(scopeCodes, "task_leases.unsupported_wire_capability") {
		t.Fatal("operation_capability_failure_codes_missing")
	}
	fixtureSQL(t, db, `UPDATE operations SET operation_type='create_application',target_ref=$1 WHERE id=$2`, created.Application.ID.String(), created.OperationID.String())
	fixtureSQL(t, db, `UPDATE task_leases SET negotiated_capabilities='[]' WHERE task_id=$1`, claim.ID.String())
	// Advance the SAME source fixture to0041, retaining all seeds and history.
	migration, err := os.ReadFile("../../migrations/control-plane/0041_acornfox_lifecycle_and_retention.sql")
	if err != nil {
		t.Fatal("fixture_migration_missing")
	}
	fixtureSQL(t, db, string(migration))
	fixtureSQL(t, db, `INSERT INTO schema_migrations(version,checksum) VALUES('0041',$1)`, digest(migration))
	fixtureSQL(t, db, `INSERT INTO source_revisions(id,application_id,provider,git_commit,source_kind,locator,content_digest,workspace_ref,workspace_lifecycle) VALUES('source_tc1g',$1,'git',$2,'git_https','https://example.invalid/repository',$3,'fixture://workspace','prepared')`, created.Application.ID.String(), strings.Repeat("a", 40), "sha256:"+strings.Repeat("a", 64))
	fixtureSQL(t, db, `INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration) VALUES('definition_tc1g',$1,'source_tc1g',1,'{}')`, created.Application.ID.String())
	fixtureSQL(t, db, `INSERT INTO releases(id,application_id,definition_id,version,service_digests,service_group_id) VALUES('release_tc1g',$1,'definition_tc1g',1,jsonb_build_object('frontend',$2::text),'legacy')`, created.Application.ID.String(), "sha256:"+strings.Repeat("b", 64))
	fixtureSQL(t, db, `INSERT INTO deployments(id,environment_id,release_id,state) VALUES('deployment_tc1g',$1,'release_tc1g','paused')`, created.EnvironmentID.String())
	fixtureSQL(t, db, `UPDATE applications SET management_state='archived',archived_at=$1 WHERE id=$2`, now.Add(time.Hour), created.Application.ID.String())
	fixtureSQL(t, db, `INSERT INTO acornfox_retained_volumes(id,application_id,logical_name,managed_volume_name,receipt_digest,verified_at,last_verified_deployment_id) VALUES('volume_tc1g',$1,'data','task-owned-volume',$2,$3,'deployment_tc1g')`, created.Application.ID.String(), "sha256:"+strings.Repeat("f", 64), now)
	fixtureSQL(t, db, `UPDATE task_leases SET result='{"recorded":true}',result_digest=$1,completed_at=$2 WHERE task_id=$3`, "sha256:"+strings.Repeat("f", 64), now.Add(time.Hour), claim.ID.String())
	fixtureSQL(t, db, `INSERT INTO outbox_events(id,aggregate_type,aggregate_id,aggregate_version,sequence,stream_sequence,event_type,payload,payload_version,compatibility) VALUES('evt-tc1g-incompatible','operation',$1,1,5,18,'operation.created',$2,'1.1','{"wire":"unsupported"}')`, created.OperationID.String(), string(payload))
	fixtureSQL(t, db, `INSERT INTO idempotency_records(scope,idempotency_key,request_digest,status,created_at,updated_at) VALUES('runtime.unsupported','tc1g-unknown',$1,'in_progress',$2,$2)`, "sha256:"+strings.Repeat("a", 64), now)
	fixtureSQL(t, db, `SELECT setval('outbox_events_stream_sequence',18,true)`)
	unsupported, err := Run(ctx, cfg)
	if err != nil || unsupported.Report.ProjectionVerified || unsupported.Report.ActivationEligible || unsupported.Report.SchemaVersion != 41 {
		t.Fatal("0041_unsupported_projection_not_rejected")
	}
	assertCoreGate(t, unsupported)
	if err := writePrivate(filepath.Join(parent, "fixture-validation-"+time.Now().UTC().Format("20060102T150405.000000000")+".json"), struct {
		Supported40, Interrupted, Retry, Unsupported41 Report
		FullDumpRestore, SnapshotWriteRejected         bool
	}{result.Report, interrupted.Report, retry.Report, unsupported.Report, true, true}); err != nil {
		t.Fatal("fixture_receipt_failed")
	}
}
