package install_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/install"
)

// TestG7PlatformBackupExportedSnapshot proves that B3's dump and facts use
// the same exported PostgreSQL snapshot. The second plan is committed by a
// separate connection while the capture transaction is still open, so it can
// only appear in the later source capture.
func TestG7PlatformBackupExportedSnapshot(t *testing.T) {
	if os.Getenv("OPEN_CARD_G5B_REQUIRE_PG") != "1" {
		t.Skip("set OPEN_CARD_G5B_REQUIRE_PG=1 for the real PostgreSQL acceptance")
	}
	for key, value := range map[string]string{
		"OPEN_CARD_G7_COOKIE": "g7-cookie-canary",
		"OPEN_CARD_G7_PEM":    "-----BEGIN G7 PRIVATE KEY-----",
	} {
		t.Setenv(key, value)
	}
	bin := gate5BBinaries(t)
	assertG7Postgres16(t, bin)
	h := startGate5BPostgres(t, bin)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	name := fmt.Sprintf("open_card_g7_%d", time.Now().UnixNano())
	h.exec(t, ctx, "postgres", "CREATE DATABASE "+name+" OWNER "+h.runtimeRole)
	root := filepath.Join(h.root, "g7-"+name)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	migrations := copyAllG7Migrations(t, root)
	runMigration(t, ctx, h, name, migrations, "0024")
	insertPlan(t, ctx, h, name, "plan-baseline-g7", "idem-baseline-g7")
	seedG7Facts(t, ctx, h, name)

	rawEnv, err := install.FormatDatabaseEnv(h.url(name))
	if err != nil {
		t.Fatal(err)
	}
	env, err := install.PostgresEnvironment(rawEnv)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := install.NewSelectedPostgresDatabase(rawEnv)
	if err != nil {
		t.Fatal(err)
	}
	defer selected.Close()

	dump, err := filepath.EvalSymlinks(bin.pgdump)
	if err != nil {
		t.Fatal(err)
	}
	restore, err := filepath.EvalSymlinks(bin.pgrestore)
	if err != nil {
		t.Fatal(err)
	}
	artifactRoot := filepath.Join(root, "artifact")
	if err := os.MkdirAll(artifactRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(artifactRoot, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	writer, err := install.TaskDurableWriter(artifactRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	runner := &g7BackupRunner{h: h, database: name, inject: true}
	snapshotter, err := install.TaskPostgresSnapshotterWithRestore(dump, restore, runner)
	if err != nil {
		t.Fatal(err)
	}
	request := install.PlatformBackupDatabaseCaptureRequest{
		TransactionID: "g7-platform-backup-transaction",
		Writer:        writer,
		Environment:   env,
		LocalBackupKey: install.PlatformBackupKeyReferenceV1{
			Provider: "local-backup-key", KeyID: "backup-encryption", KeyVersion: "key-v1",
		},
	}
	result, err := install.CapturePlatformBackupDatabase(ctx, selected, snapshotter, request)
	if err != nil {
		assertG7NoCanary(t, err.Error())
		t.Fatal(err)
	}
	if got := h.queryRow(t, ctx, name, "SELECT count(*) FROM dns_change_plans"); got != "2" {
		t.Fatalf("source plan count after injection = %s, want 2", got)
	}
	if got := g7RouteCount(result.Facts.Routes, "dns_change_plans"); got != 1 {
		t.Fatalf("captured plan count = %d, want 1", got)
	}
	if result.Facts.Audit.Table.RowCount != 1 || result.Facts.Audit.ChainHead == nil || *result.Facts.Audit.ChainHead != "sha256:"+strings.Repeat("c", 64) || !result.Facts.Audit.LinkContinuity {
		t.Fatalf("audit fact missing seeded chain row: %+v", result.Facts.Audit)
	}
	if len(result.Facts.KeyReferences.References) != 2 || result.Facts.KeyReferences.References[0].Provider != "control-plane-secret" || result.Facts.KeyReferences.References[1].Provider != "local-backup-key" {
		t.Fatalf("key references = %+v", result.Facts.KeyReferences.References)
	}
	if result.Facts.TasksOutbox.Tables[0].RowCount != 1 || result.Facts.TasksOutbox.PendingOutbox.RowCount != 1 {
		t.Fatalf("outbox fact missing seeded pending row: %+v", result.Facts.TasksOutbox)
	}
	assertG7NoCanary(t, fmt.Sprintf("%+v", result.Facts))
	if result.DumpEvidence.Size <= 0 || len(result.DumpEvidence.SHA256) != 64 || result.DatabaseSnapshotSHA256 == "" || result.DatabaseSnapshotSHA256 != result.Facts.DatabaseSnapshotSHA256 {
		t.Fatalf("invalid dump/snapshot evidence: %+v", result)
	}
	info, err := os.Stat(filepath.Join(artifactRoot, "control-plane.dump"))
	if err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() || info.Size() != result.DumpEvidence.Size {
		t.Fatalf("dump permissions/evidence invalid: info=%v evidence=%+v", info, result.DumpEvidence)
	}
	if got := g7FileSHA256(t, filepath.Join(artifactRoot, "control-plane.dump")); got != result.DumpEvidence.SHA256 {
		t.Fatalf("dump hash = %s, evidence = %s", got, result.DumpEvidence.SHA256)
	}
	assertG7RunnerSafe(t, runner)

	restoreDB, err := install.CandidateDatabaseName("g7-restore-database")
	if err != nil {
		t.Fatal(err)
	}
	h.exec(t, ctx, "postgres", "CREATE DATABASE "+restoreDB+" OWNER "+h.runtimeRole)
	restoreRaw, err := install.FormatDatabaseEnv(h.url(restoreDB))
	if err != nil {
		t.Fatal(err)
	}
	restoreEnv, err := install.PostgresEnvironment(restoreRaw)
	if err != nil {
		t.Fatal(err)
	}
	restoredRunner := &g7BackupRunner{h: h, database: restoreDB}
	restoredSnapshotter, err := install.TaskPostgresSnapshotterWithRestore(dump, restore, restoredRunner)
	if err != nil {
		t.Fatal(err)
	}
	if err := restoredSnapshotter.Restore(ctx, restoreDB, filepath.Join(artifactRoot, "control-plane.dump"), result.DumpEvidence, restoreEnv); err != nil {
		t.Fatal(err)
	}
	wantRestoreArgv := []string{restore, "--exit-on-error", "--single-transaction", "--no-owner", "--no-acl", "--dbname", restoreDB, filepath.Join(artifactRoot, "control-plane.dump")}
	if !reflect.DeepEqual(restoredRunner.argv, [][]string{wantRestoreArgv}) {
		t.Fatalf("restore argv = %v, want %v", restoredRunner.argv, wantRestoreArgv)
	}
	if !restoredRunner.sawRestore {
		t.Fatal("restore runner did not execute pg_restore")
	}
	assertG7NoCanary(t, fmt.Sprint(restoredRunner.env))
	if got := h.queryRow(t, ctx, restoreDB, "SELECT count(*) FROM dns_change_plans"); got != "1" {
		t.Fatalf("restored plan count = %s, want 1", got)
	}
	if got := h.queryRow(t, ctx, restoreDB, "SELECT count(*) FROM schema_migrations"); got != "24" {
		t.Fatalf("restored migration count = %s, want 24", got)
	}
	restored, err := install.NewSelectedPostgresDatabase(restoreRaw)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	restoredRoot := filepath.Join(root, "restored-artifact")
	if err := os.MkdirAll(restoredRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(restoredRoot, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	restoredWriter, err := install.TaskDurableWriter(restoredRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer restoredWriter.Close()
	// This independent capture also verifies the restored selected database can
	// begin/capture/rollback facts, while its dump is not used for comparison.
	restoredResult, err := install.CapturePlatformBackupDatabase(ctx, restored, restoredSnapshotter, install.PlatformBackupDatabaseCaptureRequest{TransactionID: "g7-restored-facts", Writer: restoredWriter, Environment: restoreEnv, LocalBackupKey: request.LocalBackupKey})
	if err != nil {
		t.Fatal(err)
	}
	assertG7FactsEqual(t, result.Facts, restoredResult.Facts)
	if restoredResult.Facts.Audit.Table.RowCount != 1 || restoredResult.Facts.TasksOutbox.PendingOutbox.RowCount != 1 {
		t.Fatalf("restored seeded facts missing")
	}
	assertG7NoCanary(t, fmt.Sprintf("%+v", restoredResult.Facts))
	assertG7DumpArgv(t, restoredRunner.argv[1:])
	assertG7NoCanary(t, fmt.Sprint(restoredRunner.argv, restoredRunner.env))

	sourceRoot := filepath.Join(root, "source-later-artifact")
	if err := os.MkdirAll(sourceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(sourceRoot, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	sourceWriter, err := install.TaskDurableWriter(sourceRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer sourceWriter.Close()
	later, err := install.CapturePlatformBackupDatabase(ctx, selected, snapshotter, install.PlatformBackupDatabaseCaptureRequest{TransactionID: "g7-source-later", Writer: sourceWriter, Environment: env, LocalBackupKey: request.LocalBackupKey})
	if err != nil {
		t.Fatal(err)
	}
	if got := g7RouteCount(later.Facts.Routes, "dns_change_plans"); got != 2 || later.Facts.Routes.Tables[1].RowsSHA256 == result.Facts.Routes.Tables[1].RowsSHA256 {
		t.Fatalf("later source capture did not observe second plan: count=%d before=%s after=%s", got, result.Facts.Routes.Tables[1].RowsSHA256, later.Facts.Routes.Tables[1].RowsSHA256)
	}
	assertG7NoCanary(t, fmt.Sprint(runner.env))
	assertG7DumpArgv(t, runner.argv)
	assertG7NoCanary(t, fmt.Sprint(runner.argv, runner.env, later.Facts))
}

type g7BackupRunner struct {
	h          *gate5BPostgres
	database   string
	env        [][]string
	argv       [][]string
	injected   bool
	sawDump    bool
	sawRestore bool
	inject     bool
	events     []string
}

func (r *g7BackupRunner) Run(ctx context.Context, argv, env []string) install.PostgresRunResult {
	name := filepath.Base(argv[0])
	if name == "pg_dump" {
		if len(argv) != 7 || argv[1] != "--format=custom" || argv[2] != "--file" || argv[4] != "--no-owner" || argv[5] != "--no-acl" || !regexp.MustCompile(`^--snapshot=[0-9A-F]{8}-[0-9A-F]{8}-[1-9][0-9]{0,9}$`).MatchString(argv[6]) {
			return install.PostgresRunResult{ExitCode: -1, Err: fmt.Errorf("invalid pg_dump invocation")}
		}
	}
	if name == "pg_restore" {
		for _, required := range []string{"--exit-on-error", "--single-transaction", "--no-owner", "--no-acl", "--dbname"} {
			found := false
			for _, arg := range argv {
				if arg == required {
					found = true
				}
			}
			if !found {
				return install.PostgresRunResult{ExitCode: -1, Err: fmt.Errorf("invalid pg_restore invocation")}
			}
		}
		r.sawRestore = true
	}
	redactedArgv := append([]string(nil), argv...)
	for i, arg := range redactedArgv {
		if strings.HasPrefix(arg, "--snapshot=") {
			redactedArgv[i] = "--snapshot=<redacted>"
		}
	}
	r.argv = append(r.argv, redactedArgv)
	redacted := make([]string, 0, len(env))
	for _, value := range env {
		key, _, _ := strings.Cut(value, "=")
		if key == "PGPASSWORD" {
			redacted = append(redacted, "PGPASSWORD=<redacted>")
		} else {
			redacted = append(redacted, value)
		}
	}
	r.env = append(r.env, redacted)
	if name == "pg_dump" && r.inject && !r.injected {
		r.injected = true
		r.sawDump = true
		sql := "INSERT INTO dns_change_plans(id,idempotency_key,input_digest,changes,created_at) VALUES ('plan-injected-g7','idem-injected-g7','sha256:" + strings.Repeat("b", 64) + "','[]'::jsonb,now())"
		if err := runGate5B(ctx, r.h.bin.psql, []string{"-X", "-v", "ON_ERROR_STOP=1", "-d", r.database, "-c", sql}, r.h.env(r.database)); err != nil {
			return install.PostgresRunResult{ExitCode: -1, Err: err}
		}
		r.events = append(r.events, "insert_committed")
	}
	if name == "pg_dump" {
		r.events = append(r.events, "pg_dump_start")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = append([]string(nil), env...)
	if err := cmd.Run(); err != nil {
		if x, ok := err.(*exec.ExitError); ok {
			return install.PostgresRunResult{ExitCode: x.ExitCode(), Err: err}
		}
		return install.PostgresRunResult{ExitCode: -1, Err: err}
	}
	return install.PostgresRunResult{}
}

func copyAllG7Migrations(t *testing.T, root string) string {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	sourceDir := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "..", "migrations", "control-plane"))
	target := filepath.Join(root, "migrations")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 24; version++ {
		matches, err := filepath.Glob(filepath.Join(sourceDir, fmt.Sprintf("%04d_*.sql", version)))
		if err != nil || len(matches) != 1 {
			t.Fatalf("expected canonical migration %04d", version)
		}
		raw, err := os.ReadFile(matches[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, filepath.Base(matches[0])), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return target
}

func insertPlan(t *testing.T, ctx context.Context, h *gate5BPostgres, db, id, idem string) {
	t.Helper()
	sql := "INSERT INTO dns_change_plans(id,idempotency_key,input_digest,changes,created_at) VALUES ('" + id + "','" + idem + "','sha256:" + strings.Repeat("a", 64) + "','[]'::jsonb,now())"
	command := exec.CommandContext(ctx, h.bin.psql, "-X", "-v", "ON_ERROR_STOP=1", "-d", db, "-c", sql)
	command.Env = append(os.Environ(), h.env(db)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("baseline plan insert failed: %v: %s", err, output)
	}
}

func seedG7Facts(t *testing.T, ctx context.Context, h *gate5BPostgres, db string) {
	t.Helper()
	statements := []string{
		"INSERT INTO applications(id,name) VALUES ('g7-app','G7 seeded application')",
		"INSERT INTO secret_references(id,application_id,name,ciphertext,key_version) VALUES ('g7-secret','g7-app','g7-secret','\\xdeadbeef','key-v1')",
		"INSERT INTO audit_evidence(id,actor_type,actor_id,action,reason,input_digest,result,record_hash,created_at) VALUES ('g7-audit','system','g7','g7.seed','integration','sha256:" + strings.Repeat("d", 64) + "','recorded','sha256:" + strings.Repeat("c", 64) + "',now())",
		"INSERT INTO outbox_events(id,aggregate_type,aggregate_id,aggregate_version,sequence,event_type,payload,created_at,payload_version) VALUES ('g7-event','application','g7-app',1,1,'g7.seed','{}'::jsonb,now(),'1.1')",
	}
	for _, sql := range statements {
		h.exec(t, ctx, db, sql)
	}
}

func assertG7Postgres16(t *testing.T, bin gate5BBinarySet) {
	t.Helper()
	for _, path := range []string{bin.initdb, bin.pgctl, bin.pgdump, bin.pgrestore, bin.psql} {
		output, err := exec.Command(path, "--version").CombinedOutput()
		if err != nil || !regexp.MustCompile(`PostgreSQL\) 16\.`).Match(output) {
			t.Fatalf("binary %s is not PostgreSQL 16.x: %s (%v)", path, output, err)
		}
	}
}

func g7RouteCount(routes install.PlatformBackupRoutesV1, name string) int64 {
	for _, table := range routes.Tables {
		if table.Name == name {
			return table.RowCount
		}
	}
	return -1
}

func assertG7FactsEqual(t *testing.T, a, b install.PlatformBackupCapturedFactsV1) {
	t.Helper()
	a.DatabaseSnapshotSHA256, b.DatabaseSnapshotSHA256, a.CurrentDatabase, b.CurrentDatabase = "", "", "", ""
	a.Routes.DatabaseSnapshotSHA256, b.Routes.DatabaseSnapshotSHA256 = "", ""
	a.Audit.DatabaseSnapshotSHA256, b.Audit.DatabaseSnapshotSHA256 = "", ""
	a.KeyReferences.DatabaseSnapshotSHA256, b.KeyReferences.DatabaseSnapshotSHA256 = "", ""
	a.TasksOutbox.DatabaseSnapshotSHA256, b.TasksOutbox.DatabaseSnapshotSHA256 = "", ""
	a.TLS.DatabaseSnapshotSHA256, b.TLS.DatabaseSnapshotSHA256 = "", ""
	if !reflect.DeepEqual(a.Routes, b.Routes) || !reflect.DeepEqual(a.Audit, b.Audit) || !reflect.DeepEqual(a.KeyReferences, b.KeyReferences) || !reflect.DeepEqual(a.TasksOutbox, b.TasksOutbox) || !reflect.DeepEqual(a.TLS, b.TLS) || !reflect.DeepEqual(a.SchemaMigrations, b.SchemaMigrations) {
		t.Fatalf("restored facts differ: source=%+v restored=%+v", a, b)
	}
}

func assertG7RunnerSafe(t *testing.T, r *g7BackupRunner) {
	t.Helper()
	if !r.sawDump {
		t.Fatal("runner did not execute pg_dump")
	}
	if !reflect.DeepEqual(r.events, []string{"insert_committed", "pg_dump_start"}) {
		t.Fatalf("runner order = %v", r.events)
	}
	joined := fmt.Sprint(r.env)
	assertG7NoCanary(t, joined)
}

func assertG7DumpArgv(t *testing.T, argv [][]string) {
	t.Helper()
	for _, args := range argv {
		if len(args) != 7 || filepath.Base(args[0]) != "pg_dump" || args[1] != "--format=custom" || args[2] != "--file" || args[4] != "--no-owner" || args[5] != "--no-acl" || args[6] != "--snapshot=<redacted>" {
			t.Fatalf("redacted pg_dump argv invalid: %v", args)
		}
	}
}

func assertG7NoCanary(t *testing.T, value string) {
	t.Helper()
	for _, canary := range []string{"g7-cookie-canary", "-----BEGIN G7 PRIVATE KEY-----", "g5b-runtime-password-sentinel", "g5b-control-password-sentinel"} {
		if strings.Contains(value, canary) {
			t.Fatalf("credential canary leaked: %q", canary)
		}
	}
}

func g7FileSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
