//go:build integration

package install_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/install"
)

func TestGate6NativeBootstrapCreatesAndReplaysRealCandidateDatabase(t *testing.T) {
	bin := os.Getenv("OPEN_CARD_G6_BOOTSTRAP_PG_BIN_DIR")
	if bin == "" {
		t.Skip("OPEN_CARD_G6_BOOTSTRAP_PG_BIN_DIR is required for the explicit task PostgreSQL gate")
	}
	for _, name := range []string{"initdb", "pg_ctl", "psql"} {
		path := filepath.Join(bin, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			t.Fatalf("unsafe PostgreSQL tool %s: %v", path, err)
		}
	}
	root := t.TempDir()
	data := filepath.Join(root, "pgdata")
	socket, err := os.MkdirTemp("/tmp", "open-card-g6-pg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socket) })
	port := taskLoopbackPort(t)
	runTaskPGCommand(t, filepath.Join(bin, "initdb"), "--pgdata", data, "--username", "postgres", "--auth", "trust", "--no-locale", "--encoding", "UTF8")
	logPath := filepath.Join(root, "postgres.log")
	runTaskPGCommand(t, filepath.Join(bin, "pg_ctl"), "--pgdata", data, "--log", logPath, "--options", fmt.Sprintf("-F -h 127.0.0.1 -p %d -k %s", port, socket), "--wait", "start")
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			command := exec.Command(filepath.Join(bin, "pg_ctl"), "--pgdata", data, "--wait", "--mode", "fast", "stop")
			command.Env = taskPGEnvironment()
			_ = command.Run()
		}
	})
	psql := filepath.Join(bin, "psql")
	adminURL := fmt.Sprintf("postgresql://postgres@127.0.0.1:%d/postgres?sslmode=disable", port)
	roleSQL := `CREATE ROLE opencard LOGIN PASSWORD 'runtime-secret' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT;
CREATE ROLE open_card_upgrade_control LOGIN PASSWORD 'control-secret' CREATEDB NOSUPERUSER NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT;
GRANT opencard TO open_card_upgrade_control;
GRANT pg_read_all_stats TO open_card_upgrade_control;`
	runTaskPGCommand(t, psql, "--no-psqlrc", "--set", "ON_ERROR_STOP=1", "--dbname", adminURL, "--command", roleSQL)

	runtimeEnv, err := install.FormatDatabaseEnv(fmt.Sprintf("postgresql://opencard:runtime-secret@127.0.0.1:%d/postgres?sslmode=disable", port))
	if err != nil {
		t.Fatal(err)
	}
	controlEnv, err := install.FormatDatabaseEnv(fmt.Sprintf("postgresql://open_card_upgrade_control:control-secret@127.0.0.1:%d/postgres?sslmode=disable", port))
	if err != nil {
		t.Fatal(err)
	}
	control, err := install.TaskPostgresControl(runtimeEnv, controlEnv)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	migrations := taskBootstrapMigrations(t)
	release := install.ReleaseV1{ID: "task-rc2", Version: install.Gate6CandidateVersion, SourceCommit: strings.Repeat("a", 40), Architecture: runtime.GOARCH, ManifestSHA256: strings.Repeat("b", 64)}
	input := install.BootstrapDatabaseInput{TransactionID: "bootstrap-task-pg", InstallationIDSHA256: strings.Repeat("c", 64), CandidateActivationID: "activation-task-pg", Release: release}
	database, err := install.TaskBootstrapDatabase(input, runtimeEnv, control.ControlIdentitySHA256(), control, "opencard", func(name string) (install.BootstrapMigrationControl, error) {
		return control.ForCandidate(name)
	}, func() (install.BootstrapMigrations, error) { return migrations, nil })
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := database.Create(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Name == "postgres" || candidate.Name == "opencard" || !strings.HasPrefix(candidate.Name, "open_card_act_") {
		t.Fatal(taskCandidateSummary(candidate, nil))
	}
	result, err := database.Migrate(context.Background(), candidate)
	if err != nil || result.Database.Migration != "0024" || result.Database.SchemaMigrationsSHA256 == "" {
		t.Fatal(taskDatabaseResultSummary(result, err))
	}
	if raw, err := json.Marshal(result); err != nil || strings.Contains(string(raw), "runtime-secret") || strings.Contains(string(raw), "postgresql://") {
		t.Fatalf("result leaked secret: %s %v", raw, err)
	}
	candidateURL, err := install.ParseDatabaseEnv(result.DatabaseEnv)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := sql.Open("pgx", candidateURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var count int
	var latest string
	if err := conn.QueryRow(`SELECT count(*), max(version) FROM schema_migrations`).Scan(&count, &latest); err != nil || count != 24 || !strings.HasPrefix(latest, "0024_") {
		t.Fatalf("rows=%d latest=%q err=%v", count, latest, err)
	}
	for _, table := range []string{"applications", "admin_credentials", "m3_domain_convergence_requests"} {
		var exists bool
		if err := conn.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, "public."+table).Scan(&exists); err != nil || !exists {
			t.Fatalf("table=%s exists=%v err=%v", table, exists, err)
		}
	}
	second, err := database.Create(context.Background())
	if err != nil || second.RecoveryEvidenceSHA256 != candidate.RecoveryEvidenceSHA256 {
		t.Fatal(taskCandidateSummary(second, err))
	}
	replayed, err := database.Migrate(context.Background(), second)
	if err != nil || replayed.Database != result.Database {
		t.Fatal(taskDatabaseResultSummary(replayed, err))
	}
	runTaskPGCommand(t, filepath.Join(bin, "pg_ctl"), "--pgdata", data, "--wait", "--mode", "fast", "stop")
	stopped = true
}

func taskBootstrapMigrations(t *testing.T) install.BootstrapMigrations {
	t.Helper()
	_, sourceFile, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	paths, err := filepath.Glob(filepath.Join(repo, "migrations", "control-plane", "[0-9][0-9][0-9][0-9]_*.sql"))
	if err != nil || len(paths) != 24 {
		t.Fatalf("migration files=%d err=%v", len(paths), err)
	}
	sort.Strings(paths)
	result := install.BootstrapMigrations{Rows: make([]install.MigrationRow, 0, len(paths)), SQL: make([]string, 0, len(paths))}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := install.SHA256File(path)
		if err != nil {
			t.Fatal(err)
		}
		result.Rows = append(result.Rows, install.MigrationRow{Version: strings.TrimSuffix(filepath.Base(path), ".sql"), Checksum: digest})
		result.SQL = append(result.SQL, string(raw))
	}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	return result
}

func taskLoopbackPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func taskPGEnvironment() []string {
	return []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=/tmp"}
}

func runTaskPGCommand(t *testing.T, name string, args ...string) {
	t.Helper()
	if err := executeTaskPGCommand(name, args...); err != nil {
		t.Fatal(err)
	}
}

func executeTaskPGCommand(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.Env = taskPGEnvironment()
	if _, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("task PostgreSQL command failed: %s", filepath.Base(name))
	}
	return nil
}

func TestGate6TaskPostgresCommandFailureIsRedacted(t *testing.T) {
	script := filepath.Join(t.TempDir(), "psql-failure")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho runtime-secret control-secret >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := executeTaskPGCommand(script, "--command", "SELECT 'runtime-secret control-secret'")
	if err == nil || strings.Contains(err.Error(), "runtime-secret") || strings.Contains(err.Error(), "control-secret") || strings.Contains(err.Error(), "SELECT") {
		t.Fatalf("secret-bearing command failure was not redacted: %v", err)
	}
}

func taskCandidateSummary(candidate install.BootstrapCandidateDatabase, err error) string {
	return fmt.Sprintf("candidate_name=%q runtime_sha=%q control_sha=%q recovery_sha=%q failed=%t", candidate.Name, candidate.RuntimeDatabaseEnvSHA256, candidate.ControlDatabaseIdentitySHA256, candidate.RecoveryEvidenceSHA256, err != nil)
}

func taskDatabaseResultSummary(result install.BootstrapDatabaseResult, err error) string {
	return fmt.Sprintf("database_name=%q migration=%q schema_sha=%q runtime_sha=%q control_sha=%q recovery_sha=%q failed=%t", result.Database.Name, result.Database.Migration, result.Database.SchemaMigrationsSHA256, result.RuntimeDatabaseEnvSHA256, result.ControlDatabaseIdentitySHA256, result.RecoveryEvidenceSHA256, err != nil)
}

func TestGate6TaskPostgresAssertionSummariesAreRedacted(t *testing.T) {
	secretEnv := []byte("OPEN_CARD_DATABASE_URL=postgresql://user:runtime-secret@127.0.0.1:5432/db\n")
	candidate := install.BootstrapCandidateDatabase{Name: "open_card_act_0123456789abcdef", DatabaseEnv: secretEnv, RuntimeDatabaseEnvSHA256: strings.Repeat("a", 64), ControlDatabaseIdentitySHA256: strings.Repeat("b", 64), RecoveryEvidenceSHA256: strings.Repeat("c", 64)}
	result := install.BootstrapDatabaseResult{Database: install.DatabaseV1{Name: candidate.Name, Migration: "0024", SchemaMigrationsSHA256: strings.Repeat("d", 64)}, DatabaseEnv: secretEnv, CandidateDatabaseName: candidate.Name, RuntimeDatabaseEnvSHA256: candidate.RuntimeDatabaseEnvSHA256, ControlDatabaseIdentitySHA256: candidate.ControlDatabaseIdentitySHA256, RecoveryEvidenceSHA256: candidate.RecoveryEvidenceSHA256}
	for _, summary := range []string{taskCandidateSummary(candidate, fmt.Errorf("control-secret")), taskDatabaseResultSummary(result, fmt.Errorf("control-secret"))} {
		if strings.Contains(summary, "runtime-secret") || strings.Contains(summary, "control-secret") || strings.Contains(summary, "postgresql://") || strings.Contains(summary, "OPEN_CARD_DATABASE_URL") {
			t.Fatalf("assertion summary leaked: %s", summary)
		}
	}
}
