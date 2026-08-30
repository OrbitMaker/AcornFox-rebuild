package install_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-card/open-card/internal/install"
)

// This is deliberately a real PostgreSQL boundary test.  Its task-local
// server is started from initdb under one short mktemp root; it never discovers or uses a
// host PostgreSQL socket, port, data directory, database, or credential.
func TestGate5BTaskPostgresRC0ToRC1Matrix(t *testing.T) {
	for key, value := range map[string]string{
		"OPEN_CARD_G5B_COOKIE":    "g5b-cookie-sentinel",
		"OPEN_CARD_G5B_PEM":       "-----BEGIN G5B PRIVATE KEY-----",
		"TENCENT_SECRET_ID":       "g5b-tencent-sentinel",
		"AWS_SECRET_ACCESS_KEY":   "g5b-aws-sentinel",
		"OPEN_CARD_G5B_API_TOKEN": "g5b-token-sentinel",
	} {
		t.Setenv(key, value)
	}
	binaries := gate5BBinaries(t)
	h := startGate5BPostgres(t, binaries)
	defer h.close(t)
	if err := runGate5B(context.Background(), h.bin.psql, []string{"-X", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c", "CREATE DATABASE open_card_runtime_must_not_create"}, h.runtimeEnv("postgres")); err == nil {
		t.Fatal("runtime role unexpectedly has CREATEDB")
	}
	if os.Getenv("OPEN_CARD_G5B_REQUIRE_PG") == "1" {
		if _, err := os.Stat(filepath.Join(h.root, "executed")); err != nil {
			t.Fatal("required task PostgreSQL execution sentinel is missing")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	t.Run("success_real_snapshot_restore_migrate", func(t *testing.T) {
		fixture := h.fixture(t, ctx, "success")
		engine, store, session, services, request := fixture.engine("")
		if err := engine.RunNew(ctx, request); err != nil {
			t.Fatalf("real upgrade failed: %v (journal=%s failure=%#v)", err, store.journal.State, store.journal.Failure)
		}
		if store.activeID != request.CandidateActivationID || store.previousID != fixture.old.ActivationID || store.marker {
			t.Fatalf("pointer outcome active=%q previous=%q marker=%v", store.activeID, store.previousID, store.marker)
		}
		if !fixture.applicationExists(ctx, fixture.activeDB) || !fixture.applicationExists(ctx, session.candidateDB) {
			t.Fatal("seed application was not retained in old and candidate databases")
		}
		if count := fixture.rowCount(ctx, fixture.activeDB); count != 23 {
			t.Fatalf("old migration rows = %d, want 23", count)
		}
		if count := fixture.rowCount(ctx, session.candidateDB); count != 24 {
			t.Fatalf("candidate migration rows = %d, want 24", count)
		}
		if store.candidate.Database.Name != session.candidateDB || string(store.candidateEnv) != string(session.CandidateDatabaseEnv()) {
			t.Fatal("candidate activation did not retain the candidate database environment")
		}
		if owner := h.queryRow(t, ctx, "postgres", "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = '"+session.candidateDB+"'"); owner != h.runtimeRole {
			t.Fatalf("candidate database owner = %q, want runtime role %q", owner, h.runtimeRole)
		}
		controlDigest, ok := session.adapter.(interface{ ControlIdentitySHA256() string })
		controlEnv, err := install.FormatDatabaseEnv(h.controlURL())
		if !ok || err != nil || controlDigest.ControlIdentitySHA256() != hashGate5B(controlEnv) {
			t.Fatal("database session did not retain the exact task control identity digest")
		}
		if store.journal.CandidateDatabase == nil || store.journal.Migration == nil || store.journal.CandidateDatabase.SchemaMigrationsSHA256 == store.journal.Migration.ManifestSHA256 {
			t.Fatal("schema-row evidence was not kept distinct from release-manifest evidence")
		}
		info, err := os.Stat(session.snapshotPath())
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("snapshot is not a retained 0600 regular artifact: %v", err)
		}
		if !services.guarded { // Edge was intentionally inactive in the captured policy.
			t.Fatal("inactive edge policy was not preserved")
		}
		assertNoGate5BSecretLeak(t, nil, store, session)
	})

	for _, tc := range []struct {
		name       string
		failAt     string
		postSwitch bool
	}{
		{name: "snapshot", failAt: "snapshot"},
		{name: "restore_create", failAt: "restore"},
		{name: "migration", failAt: "migrate"},
		{name: "validation", failAt: "validate"},
		{name: "active_switch", failAt: "switch"},
		{name: "post_switch_health", failAt: "health", postSwitch: true},
	} {
		t.Run("known_failure_"+tc.name, func(t *testing.T) {
			fixture := h.fixture(t, ctx, tc.name)
			engine, store, session, services, request := fixture.engine(tc.failAt)
			outcome := engine.RunNew(ctx, request)
			if outcome == nil {
				t.Fatal("injected failure unexpectedly succeeded")
			}
			assertNoGate5BSecretLeak(t, outcome, store, session)
			driverUnknown := tc.failAt == "snapshot" || tc.failAt == "restore" || tc.failAt == "migrate" || tc.failAt == "validate"
			if store.activeID != fixture.old.ActivationID || driverUnknown != store.marker {
				t.Fatalf("known failure did not retain/restore old active pointer: active=%q marker=%v state=%s failure=%#v", store.activeID, store.marker, store.journal.State, store.journal.Failure)
			}
			if driverUnknown && (!services.guarded || store.journal.State != install.JournalRecoveryRequired) {
				t.Fatal("actual driver uncertainty did not become recovery-required with edge guarded")
			}
			if !fixture.applicationExists(ctx, fixture.activeDB) {
				t.Fatal("known failure changed old active database data")
			}
			if tc.postSwitch {
				if !services.restored || !store.rolledBack {
					t.Fatal("post-switch health failure did not execute rollback")
				}
				if !fixture.applicationExists(ctx, session.candidateDB) {
					t.Fatal("rollback auto-dropped candidate data")
				}
			}
		})
	}

	t.Run("unknown_outcome_is_recovery_required_and_repeatable", func(t *testing.T) {
		fixture := h.fixture(t, ctx, "unknown")
		engine, store, session, services, request := fixture.engine("snapshot")
		outcome := engine.RunNew(ctx, request)
		if outcome == nil {
			t.Fatal("unknown snapshot result unexpectedly succeeded")
		}
		assertNoGate5BSecretLeak(t, outcome, store, session)
		if !store.marker || !services.guarded || store.journal.State != install.JournalRecoveryRequired {
			t.Fatalf("unknown outcome was not fail-closed: marker=%v guarded=%v state=%s", store.marker, services.guarded, store.journal.State)
		}
		for i := 0; i < 2; i++ {
			if err := engine.Recover(ctx, request.TransactionID); err == nil {
				t.Fatal("recovery-required terminal state unexpectedly reported success")
			}
			if !store.marker || !services.guarded || store.activeID != fixture.old.ActivationID {
				t.Fatal("repeated recovery lost fail-closed old-active state")
			}
		}
	})

	t.Run("lock_candidate_evidence_and_rejections", func(t *testing.T) {
		fixture := h.fixture(t, ctx, "guards")
		engine, store, session, _, request := fixture.engine("")
		lock, err := store.Acquire(ctx, "other-txn")
		if err != nil {
			t.Fatal(err)
		}
		if err := engine.RunNew(ctx, request); !errors.Is(err, install.ErrUpgradeLocked) {
			t.Fatalf("concurrent lock result = %v", err)
		}
		if err := lock.Release(); err != nil {
			t.Fatal(err)
		}
		if _, _, err := session.Snapshot(ctx); err != nil {
			t.Fatal(err)
		}
		if err := session.CreateRestore(ctx, session.candidateDB); err != nil {
			t.Fatal(err)
		}
		if comment := h.queryRow(t, ctx, "postgres", "SELECT coalesce(shobj_description(oid, 'pg_database'), '') FROM pg_database WHERE datname = '"+session.candidateDB+"'"); comment != "open-card-upgrade:"+strings.Repeat("e", 64) {
			t.Fatalf("candidate recovery evidence = %q", comment)
		}
		bad := install.ActiveDatabaseInspectionRequest{DatabaseEnv: fixture.activeEnv, ExpectedMigration: "0023", ExpectedRowsSHA256: strings.Repeat("0", 64), ExpectedRowCount: 23}
		if _, err := session.InspectActive(ctx, bad); err == nil {
			t.Fatal("wrong active schema digest was accepted")
		}
		bad.DatabaseEnv = []byte("OPEN_CARD_DATABASE_URL=postgresql://opencard:wrong@127.0.0.1:1/not_the_active?sslmode=disable\n")
		if _, err := session.InspectActive(ctx, bad); err == nil {
			t.Fatal("wrong active environment was accepted")
		}
		badRequest := request
		badRequest.CandidateRelease.SourceCommit = "not-a-git-commit"
		if err := engine.RunNew(ctx, badRequest); err == nil {
			t.Fatal("wrong candidate source commit was accepted")
		}
	})

	assertNoDropDatabaseAPI(t)

	if err := h.closeNow(); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(h.bin.pgctl, "-D", filepath.Join(h.root, "pgdata"), "status").Run(); err == nil {
		t.Fatal("task PostgreSQL still reports running after pg_ctl stop")
	}
	if err := syscall.Kill(h.pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("task PostgreSQL pid %d remains after cleanup: %v", h.pid, err)
	}
	if err := os.RemoveAll(h.root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(h.root); !os.IsNotExist(err) {
		t.Fatal("task PostgreSQL root remains after cleanup")
	}
}

type gate5BBinarySet struct{ initdb, pgctl, pgdump, pgrestore, psql string }

func gate5BBinaries(t *testing.T) gate5BBinarySet {
	t.Helper()
	required := os.Getenv("OPEN_CARD_G5B_REQUIRE_PG") == "1"
	values := gate5BBinarySet{}
	for _, item := range []struct {
		name string
		out  *string
	}{{"initdb", &values.initdb}, {"pg_ctl", &values.pgctl}, {"pg_dump", &values.pgdump}, {"pg_restore", &values.pgrestore}, {"psql", &values.psql}} {
		path, err := exec.LookPath(item.name)
		if err != nil {
			if required {
				t.Fatalf("required task PostgreSQL binary %s is unavailable", item.name)
			}
			t.Skipf("task PostgreSQL acceptance requires %s", item.name)
		}
		*item.out = path
	}
	return values
}

type gate5BPostgres struct {
	root        string
	port        int
	pid         int
	bin         gate5BBinarySet
	runtimeRole string
	controlRole string
	mu          sync.Mutex
	dead        bool
}

func startGate5BPostgres(t *testing.T, bin gate5BBinarySet) *gate5BPostgres {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "ocg5b-")
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "pgdata")
	socket := filepath.Join(root, "socket")
	if err := os.Mkdir(socket, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := runGate5B(context.Background(), bin.initdb, []string{"-D", data, "--auth=trust", "--no-locale", "--encoding=UTF8", "-U", "g5badmin"}, nil); err != nil {
		_ = os.RemoveAll(root)
		t.Fatalf("task initdb failed: %v", err)
	}
	log := filepath.Join(root, "postgres.log")
	port := 0
	var startErr error
	for attempt := 0; attempt < 5; attempt++ {
		candidate := reserveGate5BPort(t)
		startErr = runGate5B(context.Background(), bin.pgctl, []string{"-D", data, "-l", log, "-o", fmt.Sprintf("-h 127.0.0.1 -k %s -p %d", socket, candidate), "-w", "-t", "30", "start"}, nil)
		if startErr == nil {
			port = candidate
			break
		}
	}
	if startErr != nil || port == 0 {
		_ = os.RemoveAll(root)
		t.Fatal("task PostgreSQL start failed")
	}
	h := &gate5BPostgres{root: root, port: port, bin: bin, runtimeRole: "opencard", controlRole: "open_card_upgrade_control"}
	h.exec(t, context.Background(), "postgres", "CREATE ROLE opencard LOGIN PASSWORD 'g5b-runtime-password-sentinel' NOCREATEDB NOSUPERUSER NOREPLICATION NOBYPASSRLS")
	h.exec(t, context.Background(), "postgres", "CREATE ROLE open_card_upgrade_control LOGIN PASSWORD 'g5b-control-password-sentinel' CREATEDB NOSUPERUSER NOREPLICATION NOBYPASSRLS")
	// PostgreSQL requires a CREATEDB role to be a member of the requested
	// OWNER role. Membership is deliberately one-way: runtime cannot inherit
	// the control role or acquire CREATEDB through it.
	h.exec(t, context.Background(), "postgres", "GRANT opencard TO open_card_upgrade_control")
	// Session draining must see runtime sessions after the service quiesce;
	// grant that observability only to the root-secret control role.
	h.exec(t, context.Background(), "postgres", "GRANT pg_read_all_stats TO open_card_upgrade_control")
	if h.queryRow(t, context.Background(), "postgres", "SELECT pg_has_role('opencard', 'open_card_upgrade_control', 'member') || ',' || pg_has_role('open_card_upgrade_control', 'opencard', 'member')") != "false,true" {
		h.close(t)
		t.Fatal("PostgreSQL control membership is not one-way")
	}
	if visibility := h.queryRow(t, context.Background(), "postgres", "SELECT pg_has_role('open_card_upgrade_control', 'pg_read_all_stats', 'member')"); visibility != "t" {
		h.close(t)
		t.Fatalf("control role lacks the required runtime-session visibility: %q", visibility)
	}
	row := h.queryRow(t, context.Background(), "postgres", "SELECT pg_backend_pid()")
	if _, err := fmt.Sscan(row, &h.pid); err != nil || h.pid <= 1 {
		h.close(t)
		t.Fatal("task PostgreSQL did not expose a valid pid")
	}
	if os.Getenv("OPEN_CARD_G5B_REQUIRE_PG") == "1" {
		if err := os.WriteFile(filepath.Join(root, "executed"), []byte("task-postgres-executed\n"), 0o600); err != nil {
			h.close(t)
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { h.close(t) })
	return h
}

func reserveGate5BPort(t *testing.T) int {
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

func (h *gate5BPostgres) close(t *testing.T) {
	t.Helper()
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		err = h.closeNow()
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Errorf("task PostgreSQL cleanup failed: %v", err)
	}
	if err := os.RemoveAll(h.root); err != nil {
		t.Errorf("task PostgreSQL root cleanup failed: %v", err)
	}
}

func (h *gate5BPostgres) closeNow() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.dead {
		return nil
	}
	if err := runGate5B(context.Background(), h.bin.pgctl, []string{"-D", filepath.Join(h.root, "pgdata"), "-m", "fast", "-w", "-t", "30", "stop"}, nil); err != nil {
		return err
	}
	h.dead = true
	return nil
}

func (h *gate5BPostgres) url(database string) string {
	// The isolated cluster uses trust authentication, but the production parser
	// requires an encoded password component. This task-only value is never
	// journaled, logged, or passed on argv.
	return fmt.Sprintf("postgresql://%s:g5b-runtime-password-sentinel@127.0.0.1:%d/%s?sslmode=disable", h.runtimeRole, h.port, database)
}

func (h *gate5BPostgres) controlURL() string {
	return fmt.Sprintf("postgresql://%s:g5b-control-password-sentinel@127.0.0.1:%d/postgres?sslmode=disable", h.controlRole, h.port)
}

func (h *gate5BPostgres) env(database string) []string {
	return []string{"PGHOST=127.0.0.1", fmt.Sprintf("PGPORT=%d", h.port), "PGUSER=g5badmin", "PGDATABASE=" + database, "PGSSLMODE=disable"}
}

func (h *gate5BPostgres) runtimeEnv(database string) []string {
	return []string{"PGHOST=127.0.0.1", fmt.Sprintf("PGPORT=%d", h.port), "PGUSER=" + h.runtimeRole, "PGDATABASE=" + database, "PGSSLMODE=disable"}
}

func (h *gate5BPostgres) exec(t *testing.T, ctx context.Context, database, sql string) {
	t.Helper()
	if err := runGate5B(ctx, h.bin.psql, []string{"-X", "-v", "ON_ERROR_STOP=1", "-d", database, "-c", sql}, h.env(database)); err != nil {
		t.Fatal("task SQL command failed")
	}
}

func (h *gate5BPostgres) queryRow(t *testing.T, ctx context.Context, database, sql string) string {
	t.Helper()
	command := exec.CommandContext(ctx, h.bin.psql, "-X", "-A", "-q", "-t", "-d", database, "-c", sql)
	command.Env = append(os.Environ(), h.env(database)...)
	output, err := command.Output()
	if err != nil {
		t.Fatal("task SQL query failed")
	}
	return strings.TrimSpace(string(output))
}

func runGate5B(ctx context.Context, path string, args, env []string) error {
	command := exec.CommandContext(ctx, path, args...)
	command.Env = append(os.Environ(), env...)
	return command.Run()
}

type gate5BFixture struct {
	t         *testing.T
	h         *gate5BPostgres
	activeDB  string
	activeEnv []byte
	old       install.ActivationV1
	oldDigest string
	rows23    string
	seedID    string
	root      string
}

func (h *gate5BPostgres) fixture(t *testing.T, ctx context.Context, suffix string) *gate5BFixture {
	t.Helper()
	safe := strings.ReplaceAll(suffix, "_", "")
	active := "open_card_active_" + safe
	h.exec(t, ctx, "postgres", "CREATE DATABASE "+active+" OWNER "+h.runtimeRole)
	root := filepath.Join(h.root, "fixture-"+safe)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	first23 := copyFirst23Migrations(t, root)
	runMigration(t, ctx, h, active, first23, "0023")
	seed := "app_gate5b_" + safe
	h.exec(t, ctx, active, "INSERT INTO applications(id, name) VALUES ('"+seed+"', 'Gate5B task acceptance')")
	env, err := install.FormatDatabaseEnv(h.url(active))
	if err != nil {
		t.Fatal(err)
	}
	rows := migrationRowsDigest(t, ctx, h, active)
	release := install.ReleaseV1{ID: "release-old-" + safe, Version: "0.8.0-rc.0", SourceCommit: strings.Repeat("1", 40), Architecture: "amd64", ManifestSHA256: strings.Repeat("a", 64)}
	old := install.ActivationV1{SchemaVersion: 1, ActivationID: "activation-old-" + safe, Origin: "native", Release: release, Database: install.DatabaseV1{Name: active, Migration: "0023", SchemaMigrationsSHA256: rows}, DatabaseEnvSHA256: hashGate5B(env), CreatedAt: time.Now().UTC(), CreatedByTransactionID: "txn-" + safe}
	if err := old.Validate(); err != nil {
		t.Fatalf("fixture activation invalid: %v", err)
	}
	digest, err := install.CanonicalActivationJSONSHA256(old)
	if err != nil {
		t.Fatal(err)
	}
	return &gate5BFixture{t: t, h: h, activeDB: active, activeEnv: env, old: old, oldDigest: digest, rows23: rows, seedID: seed, root: root}
}

func (f *gate5BFixture) engine(failAt string) (*install.UpgradeEngine, *gate5BStore, *gate5BSession, *gate5BServices, install.UpgradeRequest) {
	activationID := "activation-new-" + strings.TrimPrefix(f.old.ActivationID, "activation-old-")
	candidate, err := install.CandidateDatabaseName(activationID)
	if err != nil {
		f.t.Fatal(err)
	}
	tx := "txn-" + strings.TrimPrefix(f.old.ActivationID, "activation-old-")
	release, releaseRoot := f.release(takeBadMigration(failAt))
	store := &gate5BStore{fixture: f, old: f.old, oldDigest: f.oldDigest, activeID: f.old.ActivationID, activeDigest: f.oldDigest, failAt: failAt}
	session := f.databaseSession(tx, activationID, candidate, release, releaseRoot, failAt)
	services := &gate5BServices{failAt: failAt}
	factory := install.UpgradeDatabaseOpenFunc(func(_ context.Context, request install.UpgradeDatabaseOpenRequest) (install.UpgradeDatabaseSession, error) {
		if string(request.ActiveDatabaseEnv) != string(f.activeEnv) || request.CandidateDatabaseName != candidate {
			return nil, install.ErrPostgresOutcomeUnknown
		}
		return session, nil
	})
	request := install.UpgradeRequest{TransactionID: tx, CandidateRelease: release, CandidateActivationID: activationID, CandidateDatabaseName: candidate, RecoveryEvidenceSHA256: strings.Repeat("e", 64), RequestedManifestSHA256: release.ManifestSHA256}
	return &install.UpgradeEngine{Store: store, DatabaseFactory: factory, Services: services, Now: func() time.Time { return time.Now().UTC() }}, store, session, services, request
}

func takeBadMigration(failAt string) bool { return failAt == "migrate" }

func (f *gate5BFixture) databaseSession(tx, activationID, candidate string, release install.ReleaseV1, releaseRoot, failAt string) *gate5BSession {
	f.t.Helper()
	artifactRoot := filepath.Join(f.root, "artifacts")
	artifactDir := filepath.Join(artifactRoot, tx)
	if err := os.MkdirAll(artifactDir, 0o711); err != nil {
		f.t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{artifactRoot: 0o700, artifactDir: 0o711} {
		if err := os.Chmod(path, mode); err != nil {
			f.t.Fatal(err)
		}
		if err := os.Chown(path, os.Getuid(), os.Getgid()); err != nil {
			f.t.Fatal(err)
		}
	}
	writer, err := install.TaskDurableWriter(artifactRoot, os.Getuid(), os.Getgid())
	if err != nil {
		f.t.Fatal(err)
	}
	controlEnv, err := install.FormatDatabaseEnv(f.h.controlURL())
	if err != nil {
		f.t.Fatal(err)
	}
	control, err := install.TaskPostgresControl(f.activeEnv, controlEnv)
	if err != nil {
		f.t.Fatal(err)
	}
	dump, err := filepath.EvalSymlinks(f.h.bin.pgdump)
	if err != nil {
		f.t.Fatal(err)
	}
	restore, err := filepath.EvalSymlinks(f.h.bin.pgrestore)
	if err != nil {
		f.t.Fatal(err)
	}
	runner := &gate5BRunner{failAt: failAt}
	snapshotter, err := install.TaskPostgresSnapshotterWithRestore(dump, restore, runner)
	if err != nil {
		f.t.Fatal(err)
	}
	candidateEnv, err := install.CandidateDatabaseEnv(f.activeEnv, candidate)
	if err != nil {
		f.t.Fatal(err)
	}
	validator := &gate5BValidator{fixture: f, candidate: candidate, fail: failAt == "validate"}
	adapter, err := install.TaskUpgradeDatabaseAdapter(install.UpgradeDatabasePlan{
		TransactionID:             tx,
		ArtifactRoot:              artifactRoot,
		ArtifactDir:               artifactDir,
		ActiveDatabaseEnv:         f.activeEnv,
		CandidateDatabaseName:     candidate,
		CandidateActivationID:     activationID,
		CandidateDatabaseEnv:      candidateEnv,
		CandidateRelease:          release,
		CandidateReleaseRoot:      releaseRoot,
		CandidateRecoveryEvidence: strings.Repeat("e", 64),
		DrainInterval:             time.Millisecond,
		Validator:                 validator,
		ArtifactWriter:            writer,
	}, control, snapshotter)
	if err != nil {
		_ = control.Close()
		_ = writer.Close()
		f.t.Fatal(err)
	}
	return &gate5BSession{fixture: f, tx: tx, candidateDB: candidate, artifactDir: artifactDir, adapter: adapter, runner: runner, validator: validator}
}

func (f *gate5BFixture) applicationExists(ctx context.Context, database string) bool {
	return f.h.queryRow(f.t, ctx, database, "SELECT count(*) FROM applications WHERE id = '"+f.seedID+"'") == "1"
}

func (f *gate5BFixture) rowCount(ctx context.Context, database string) int {
	value := f.h.queryRow(f.t, ctx, database, "SELECT count(*) FROM schema_migrations")
	var count int
	if _, err := fmt.Sscan(value, &count); err != nil {
		f.t.Fatal(err)
	}
	return count
}

func copyFirst23Migrations(t *testing.T, root string) string {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", ".."))
	sourceDir := filepath.Join(repo, "migrations", "control-plane")
	target := filepath.Join(root, "migrations")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 23; version++ {
		matches, err := filepath.Glob(filepath.Join(sourceDir, fmt.Sprintf("%04d_*.sql", version)))
		if err != nil || len(matches) != 1 {
			t.Fatalf("expected exactly one canonical migration %04d", version)
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

func runMigration(t *testing.T, ctx context.Context, h *gate5BPostgres, database, migrations, required string) {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	script := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "..", "scripts", "mvp", "control-plane-migrate.sh"))
	if err := runGate5B(ctx, "bash", []string{script, migrations}, []string{"DATABASE_URL=" + h.url(database), "OPEN_CARD_REQUIRED_MIGRATION_VERSION=" + required}); err != nil {
		t.Fatal("canonical task migration failed")
	}
}

func migrationRowsDigest(t *testing.T, ctx context.Context, h *gate5BPostgres, database string) string {
	t.Helper()
	conn, err := pgx.Connect(ctx, h.url(database))
	if err != nil {
		t.Fatal("task migration evidence connection failed")
	}
	defer conn.Close(ctx)
	rows, err := conn.Query(ctx, "SELECT version, checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		t.Fatal("task migration evidence query failed")
	}
	defer rows.Close()
	var evidence []string
	for rows.Next() {
		var version, checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			t.Fatal(err)
		}
		evidence = append(evidence, version+"\t"+checksum+"\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(evidence)
	return hashGate5B([]byte(strings.Join(evidence, "")))
}

func hashGate5B(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

type gate5BLock struct{ store *gate5BStore }

func (l *gate5BLock) Release() error {
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	l.store.locked = false
	return nil
}

type gate5BStore struct {
	mu                         sync.Mutex
	fixture                    *gate5BFixture
	old                        install.ActivationV1
	oldDigest                  string
	activeID, activeDigest     string
	previousID, previousDigest string
	candidate                  install.ActivationV1
	candidateDigest            string
	candidateEnv               []byte
	journal                    install.UpgradeJournalV1
	marker, locked, rolledBack bool
	failAt                     string
}

func (s *gate5BStore) Acquire(_ context.Context, _ string) (install.UpgradeLock, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return nil, install.ErrUpgradeLocked
	}
	s.locked = true
	return &gate5BLock{store: s}, nil
}
func (s *gate5BStore) LoadJournal(_ context.Context, _ string) (install.UpgradeJournalV1, error) {
	return s.journal, nil
}
func (s *gate5BStore) ReadActualState(_ context.Context, _, _ string) (install.UpgradeActualState, error) {
	return install.UpgradeActualState{ActiveID: s.activeID, PreviousID: s.previousID, MarkerTransactionID: markerID(s.marker, s.journal.TransactionID), OldActivationJSONSHA256: s.oldDigest, CandidateActivationJSONSHA256: s.candidateDigest, PreviousActivationJSONSHA256: s.previousDigest, OldActivationExists: true, CandidateActivationExists: s.candidateDigest != ""}, nil
}
func markerID(marker bool, id string) string {
	if marker {
		return id
	}
	return ""
}
func (s *gate5BStore) EnsureMarker(_ context.Context, _ string) error { s.marker = true; return nil }
func (s *gate5BStore) PreflightPlan(_ context.Context, _ install.UpgradePreflightRequest) (install.UpgradePreflight, error) {
	return install.UpgradePreflight{Existing: &install.ExistingActivationPreflight{Activation: s.old, JSONSHA256: s.oldDigest, DatabaseEnv: s.fixture.activeEnv}}, nil
}
func (s *gate5BStore) PrepareLegacyProjection(context.Context, install.LegacyProjectionPlan, install.ActivationV1) (install.LegacyProjectionObservation, error) {
	return install.LegacyProjectionObservation{}, install.ErrUpgradeLocked
}
func (s *gate5BStore) FinalizeLegacyProjection(context.Context, install.LegacyProjectionPlan, install.ActivationV1) (install.LegacyProjectionObservation, error) {
	return install.LegacyProjectionObservation{}, install.ErrUpgradeLocked
}
func (s *gate5BStore) ReadLegacyProjection(context.Context, install.LegacyProjectionPlan, install.ActivationV1) (install.LegacyProjectionObservation, error) {
	return install.LegacyProjectionObservation{}, install.ErrUpgradeLocked
}
func (s *gate5BStore) RecoverLegacyPlan(context.Context, install.ActivationV1, string) (install.LegacyProjectionPlan, error) {
	return install.LegacyProjectionPlan{}, install.ErrUpgradeLocked
}
func (s *gate5BStore) PrepareEdgeConfig(context.Context, install.EdgeConfigTransitionPlan) (install.EdgeConfigObservationV1, error) {
	return install.EdgeConfigObservationV1{}, install.ErrUpgradeLocked
}
func (s *gate5BStore) FinalizeEdgeConfig(context.Context, install.EdgeConfigTransitionPlan) (install.EdgeConfigObservationV1, error) {
	return install.EdgeConfigObservationV1{}, install.ErrUpgradeLocked
}
func (s *gate5BStore) ReadEdgeConfig(context.Context, install.EdgeConfigTransitionPlan) (install.EdgeConfigObservationV1, error) {
	return install.EdgeConfigObservationV1{}, install.ErrUpgradeLocked
}
func (s *gate5BStore) ReadActivationState(context.Context) (install.UpgradeActivationState, error) {
	return install.UpgradeActivationState{ActiveID: s.activeID, PreviousID: s.previousID, ActiveActivationJSONSHA256: s.activeDigest, PreviousJSONSHA256: s.previousDigest, Marker: s.marker}, nil
}
func (s *gate5BStore) ReadActiveForRestore(context.Context) (install.ExistingActivationPreflight, error) {
	if s.marker || s.activeID != s.old.ActivationID || s.activeDigest != s.oldDigest {
		return install.ExistingActivationPreflight{}, errors.New("active restore identity is unavailable")
	}
	return install.ExistingActivationPreflight{Activation: s.old, JSONSHA256: s.oldDigest, DatabaseEnv: append([]byte(nil), s.fixture.activeEnv...)}, nil
}
func (s *gate5BStore) CreateJournal(_ context.Context, j install.UpgradeJournalV1) error {
	s.journal = j
	return nil
}
func (s *gate5BStore) SaveJournal(_ context.Context, j install.UpgradeJournalV1) error {
	s.journal = j
	return nil
}
func (s *gate5BStore) Marker(_ context.Context, set bool) error { s.marker = set; return nil }
func (s *gate5BStore) WriteCandidateActivation(_ context.Context, a install.ActivationV1, env []byte) (string, error) {
	digest, err := install.CanonicalActivationJSONSHA256(a)
	if err != nil {
		return "", err
	}
	s.candidate, s.candidateDigest, s.candidateEnv = a, digest, append([]byte(nil), env...)
	return digest, nil
}
func (s *gate5BStore) WriteRestoreActivation(ctx context.Context, a install.ActivationV1, env []byte) (string, error) {
	if a.Origin != "restore" || a.RestoreSource == nil {
		return "", errors.New("invalid restore activation")
	}
	return s.WriteCandidateActivation(ctx, a, env)
}
func (s *gate5BStore) SetPrevious(_ context.Context, id string) error {
	s.previousID, s.previousDigest = id, s.oldDigest
	return nil
}
func (s *gate5BStore) RestorePrevious(_ context.Context, _, id, digest string) error {
	s.previousID, s.previousDigest = id, digest
	return nil
}
func (s *gate5BStore) SwapActive(_ context.Context, id string) error {
	if s.failAt == "switch" {
		return errors.New("switch")
	}
	if id != s.candidate.ActivationID {
		return errors.New("invalid")
	}
	s.activeID, s.activeDigest = id, s.candidateDigest
	return nil
}
func (s *gate5BStore) RestoreActive(_ context.Context, active, previous string) error {
	if active != s.old.ActivationID || previous != s.candidate.ActivationID {
		return errors.New("invalid")
	}
	s.activeID, s.activeDigest = s.old.ActivationID, s.oldDigest
	s.previousID, s.previousDigest, s.rolledBack = s.candidate.ActivationID, s.candidateDigest, true
	return nil
}

type gate5BSession struct {
	fixture                      *gate5BFixture
	tx, candidateDB, artifactDir string
	adapter                      install.UpgradeDatabaseSession
	runner                       *gate5BRunner
	validator                    *gate5BValidator
}

func (s *gate5BSession) InspectActive(ctx context.Context, r install.ActiveDatabaseInspectionRequest) (install.DatabaseV1, error) {
	return s.adapter.InspectActive(ctx, r)
}
func (s *gate5BSession) Drain(ctx context.Context) error { return s.adapter.Drain(ctx) }
func (s *gate5BSession) Snapshot(ctx context.Context) (install.SnapshotEvidence, string, error) {
	return s.adapter.Snapshot(ctx)
}
func (s *gate5BSession) CreateRestore(ctx context.Context, candidate string) error {
	return s.adapter.CreateRestore(ctx, candidate)
}
func (s *gate5BSession) Migrate(ctx context.Context) (install.UpgradeMigrationEvidence, error) {
	return s.adapter.Migrate(ctx)
}
func (s *gate5BSession) Validate(ctx context.Context, id string) (install.ArtifactV1, error) {
	return s.adapter.Validate(ctx, id)
}
func (s *gate5BSession) CandidateDatabaseEnv() []byte  { return s.adapter.CandidateDatabaseEnv() }
func (s *gate5BSession) ControlIdentitySHA256() string { return s.adapter.ControlIdentitySHA256() }
func (s *gate5BSession) Close() error                  { return s.adapter.Close() }
func (s *gate5BSession) snapshotPath() string {
	return filepath.Join(s.artifactDir, "control-plane.dump")
}

type gate5BRunner struct {
	failAt    string
	argv, env [][]string
	errors    []string
}

func (r *gate5BRunner) Run(ctx context.Context, argv, env []string) install.PostgresRunResult {
	copyArgv := append([]string(nil), argv...)
	r.argv = append(r.argv, copyArgv)
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
	name := filepath.Base(argv[0])
	if (r.failAt == "snapshot" && name == "pg_dump") || (r.failAt == "restore" && name == "pg_restore") {
		r.errors = append(r.errors, "runner_failed")
		return install.PostgresRunResult{ExitCode: 1, Err: errors.New("g5b-pg-password-sentinel g5b-cookie-sentinel g5b-token-sentinel")}
	}
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	command.Env = append([]string(nil), env...)
	if err := command.Run(); err != nil {
		r.errors = append(r.errors, "runner_failed")
		if exited, ok := err.(*exec.ExitError); ok {
			return install.PostgresRunResult{ExitCode: exited.ExitCode(), Err: err}
		}
		return install.PostgresRunResult{ExitCode: -1, Err: err}
	}
	return install.PostgresRunResult{}
}

type gate5BValidator struct {
	fixture   *gate5BFixture
	candidate string
	fail      bool
	errors    []string
}

func (v *gate5BValidator) ValidateCandidate(ctx context.Context, id string) error {
	if v.fail {
		v.errors = append(v.errors, "validator_failed")
		return errors.New("-----BEGIN G5B PRIVATE KEY----- g5b-tencent-sentinel g5b-aws-sentinel")
	}
	if id == "" || v.fixture.rowCount(ctx, v.candidate) != 24 || !v.fixture.applicationExists(ctx, v.candidate) {
		v.errors = append(v.errors, "validator_failed")
		return install.ErrPostgresOutcomeUnknown
	}
	return nil
}

func (f *gate5BFixture) release(badMigration bool) (install.ReleaseV1, string) {
	f.t.Helper()
	root := filepath.Join(f.root, "releases", "release-new-"+strings.TrimPrefix(f.old.ActivationID, "activation-old-"))
	files := make([]install.FileDigest, 0, 40)
	write := func(path string, raw []byte, mode os.FileMode) {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			f.t.Fatal(err)
		}
		if err := os.WriteFile(full, raw, mode); err != nil {
			f.t.Fatal(err)
		}
		digest, err := install.SHA256File(full)
		if err != nil {
			f.t.Fatal(err)
		}
		files = append(files, install.FileDigest{Path: path, SHA256: digest, Mode: uint32(mode)})
	}
	_, source, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", ".."))
	for version := 1; version <= 24; version++ {
		matches, err := filepath.Glob(filepath.Join(repo, "migrations", "control-plane", fmt.Sprintf("%04d_*.sql", version)))
		if err != nil || len(matches) != 1 {
			f.t.Fatalf("expected one migration %04d", version)
		}
		raw, err := os.ReadFile(matches[0])
		if err != nil {
			f.t.Fatal(err)
		}
		if badMigration && version == 24 {
			raw = []byte("THIS IS NOT VALID SQL;\n")
		}
		write("migrations/control-plane/"+filepath.Base(matches[0]), raw, 0o640)
	}
	for path, raw := range map[string][]byte{
		"bin/open-card-admin":                                     []byte("#!/bin/sh\nexit 0\n"),
		"bin/open-card-upgrade":                                   []byte("#!/bin/sh\nexit 0\n"),
		"systemd/open-card-edge.service":                          []byte("[Service]\n"),
		"systemd/open-card-upgrade-recover.service":               install.ProductionUpgradeRecoveryUnitBytes(),
		"systemd/open-card-upgrade-safe.target":                   []byte("[Unit]\n"),
		"systemd/open-card-upgrade-finalize.service":              install.ProductionUpgradeFinalizeUnitBytes(),
		"systemd/open-card-edge.service.d/10-upgrade-marker.conf": install.ProductionUpgradeEdgeMarkerDropInBytes(),
		"caddy/open-card-edge.Caddyfile.example":                  []byte("edge\n"),
		"web/dist/index.html":                                     []byte("web\n"),
		"docs/licenses/licenses-manifest.json":                    []byte("{}\n"),
		"sbom.spdx.json":                                          []byte("{}\n"),
		"source-manifest.sha256":                                  []byte("source\n"),
	} {
		mode := os.FileMode(0o644)
		if strings.HasPrefix(path, "bin/") {
			mode = 0o755
		}
		write(path, raw, mode)
	}
	manifest := install.Manifest{SchemaVersion: install.ManifestSchemaVersion, Product: install.ManifestProduct, Version: install.ProductionCandidateVersion, ReleaseID: filepath.Base(root), Architecture: "amd64", MigrationVersion: install.CurrentMigrationVersion, SourceCommit: strings.Repeat("2", 40), NMinusOne: &install.NMinusOne{Version: install.ProductionNMinusOneVersion, MigrationVersion: "0023", SourceCommit: install.RC0SourceCommit, ReleaseManifestSHA256: install.RC0ReleaseManifestSHA256, ArchiveSHA256: install.RC0ArchiveSHA256, BundleManifestSHA256: install.RC0BundleManifestSHA256}, Protocol: install.AgentProtocolVersion, ConfigDir: install.DefaultConfigDir, DataDir: install.DefaultDataDir, Compatibility: install.Compatibility{MinDataVersion: 23, MaxDataVersion: 24, MinAgentProtocol: install.PreviousAgentProtocol, MaxAgentProtocol: install.AgentProtocolVersion}, Files: files}
	if err := install.SaveManifest(filepath.Join(root, "manifest.json"), manifest); err != nil {
		f.t.Fatal(err)
	}
	digest, err := install.SHA256File(filepath.Join(root, "manifest.json"))
	if err != nil {
		f.t.Fatal(err)
	}
	return install.ReleaseV1{ID: manifest.ReleaseID, Version: manifest.Version, SourceCommit: manifest.SourceCommit, Architecture: manifest.Architecture, ManifestSHA256: digest}, root
}

type gate5BServices struct {
	failAt            string
	guarded, restored bool
}

func (*gate5BServices) Capture(context.Context) (install.ServiceSnapshotV1, error) {
	return install.ServiceSnapshotV1{Server: install.UnitSnapshotV1{Active: true, Enabled: true}}, nil
}
func (*gate5BServices) Quiesce(context.Context) error       { return nil }
func (*gate5BServices) StartInternal(context.Context) error { return nil }
func (s *gate5BServices) HealthInternal(context.Context) error {
	if s.failAt == "health" {
		return errors.New("health")
	}
	return nil
}
func (*gate5BServices) StartEdge(context.Context) error                { return nil }
func (*gate5BServices) HealthEdge(context.Context) error               { return nil }
func (s *gate5BServices) GuardEdge(context.Context) error              { s.guarded = true; return nil }
func (*gate5BServices) ReloadServerUnit(context.Context, string) error { return nil }
func (*gate5BServices) ValidateEdgeConfig(_ context.Context, transition install.EdgeConfigTransitionV1, artifact install.ArtifactV1) (install.EdgeConfigValidationV1, error) {
	if transition.InstalledAfterSHA256 == "" || transition.CandidateCaddySHA256 == "" || artifact.SHA256 != transition.InstalledAfterSHA256 {
		return install.EdgeConfigValidationV1{}, errors.New("invalid edge validation")
	}
	return install.EdgeConfigValidationV1{ConfigSHA256: transition.InstalledAfterSHA256, CaddySHA256: transition.CandidateCaddySHA256, EvidenceSHA256: strings.Repeat("f", 64)}, nil
}
func (s *gate5BServices) RestoreSnapshot(context.Context, install.ServiceSnapshotV1) error {
	s.restored = true
	return nil
}
func (*gate5BServices) HealthRestoredInternal(context.Context) error { return nil }
func (s *gate5BServices) RestoreEdge(context.Context, install.ServiceSnapshotV1) error {
	s.restored = true
	return nil
}

func assertNoGate5BSecretLeak(t *testing.T, outcome error, store *gate5BStore, session *gate5BSession) {
	t.Helper()
	raw, err := install.MarshalUpgradeJournalV1(store.journal)
	if err != nil {
		t.Fatal(err)
	}
	values := []string{
		"postgresql://",
		"g5b-pg-password-sentinel",
		"g5b-cookie-sentinel",
		"-----BEGIN G5B PRIVATE KEY-----",
		"g5b-tencent-sentinel",
		"g5b-aws-sentinel",
		"g5b-token-sentinel",
		string(session.fixture.activeEnv),
	}
	assertSecretFree(t, "journal", raw, values)
	if outcome != nil {
		assertSecretFree(t, "returned upgrade error", []byte(outcome.Error()), values)
	}
	for _, argv := range session.runner.argv {
		assertSecretFree(t, "runner argv", []byte(strings.Join(argv, "\n")), values)
	}
	for _, env := range session.runner.env {
		assertSecretFree(t, "runner env", []byte(strings.Join(env, "\n")), values)
		if strings.Contains(strings.Join(env, "\n"), "PGPASSWORD=<redacted>") {
			continue
		}
		t.Fatal("runner capture did not redact the required child password")
	}
	assertSecretFree(t, "runner errors", []byte(strings.Join(session.runner.errors, "\n")), values)
	assertSecretFree(t, "validator errors", []byte(strings.Join(session.validator.errors, "\n")), values)
	for _, path := range []string{filepath.Join(session.fixture.h.root, "postgres.log"), session.artifactDir} {
		assertTreeSecretFree(t, path, values)
	}
	if strings.Contains(strings.Join(os.Args, " "), "postgresql://") {
		t.Fatal("test process argv contains a database URL")
	}
}

func assertSecretFree(t *testing.T, location string, raw []byte, values []string) {
	t.Helper()
	for _, value := range values {
		if value != "" && strings.Contains(string(raw), value) {
			t.Fatalf("%s leaked a secret sentinel", location)
		}
	}
}

func assertTreeSecretFree(t *testing.T, path string, values []string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		assertSecretFree(t, filepath.Base(path), raw, values)
		return
	}
	err = filepath.WalkDir(path, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		raw, readErr := os.ReadFile(name)
		if readErr != nil {
			return readErr
		}
		for _, value := range values {
			if value != "" && strings.Contains(string(raw), value) {
				return fmt.Errorf("secret sentinel in %s", filepath.Base(name))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal("retained artifact or log secret scan failed")
	}
}

func assertNoDropDatabaseAPI(t *testing.T) {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", ".."))
	for _, name := range []string{"internal/install/postgres_candidate.go", "internal/install/upgrade_database_adapter.go", "internal/install/upgrade_engine.go"} {
		raw, err := os.ReadFile(filepath.Join(repo, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToUpper(string(raw)), "DROP DATABASE") {
			t.Fatalf("forbidden database-drop API in %s", name)
		}
	}
}
