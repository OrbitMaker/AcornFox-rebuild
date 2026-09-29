//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/application"
)

func validateManagementTestDSN(t *testing.T, dsn string) {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("task-scoped database URL is invalid")
	}
	host := parsed.Hostname()
	if host != "127.0.0.1" && host != "::1" && host != "localhost" {
		t.Fatal("task-scoped database must be loopback-only")
	}
	database := strings.TrimPrefix(parsed.EscapedPath(), "/")
	if !strings.HasPrefix(database, "open_card_management_") {
		t.Fatal("task-scoped database name must use open_card_management_ prefix")
	}
}

func redactDSN(dsn string, cause error) error {
	parsed, err := url.Parse(dsn)
	if err != nil {
		return cause
	}
	if parsed.User != nil {
		parsed.User = url.UserPassword(parsed.User.Username(), "REDACTED")
	}
	return fmt.Errorf("%w (dsn=%s)", cause, parsed.String())
}

func setupManagementTestDB(t *testing.T, ctx context.Context) (*sql.DB, *Store) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_MANAGEMENT_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Fatal("OPEN_CARD_MANAGEMENT_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateManagementTestDSN(t, dsn)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open database: %v", redactDSN(dsn, err))
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping database: %v", redactDSN(dsn, err))
	}

	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset test schema: %v", err)
	}

	migrationsDir := "../../../migrations/control-plane"
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var allFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			allFiles = append(allFiles, entry.Name())
		}
	}
	sort.Strings(allFiles)

	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version text PRIMARY KEY,
			checksum text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		)
	`); err != nil {
		t.Fatal(err)
	}

	for _, name := range allFiles {
		filePath := filepath.Join(migrationsDir, name)
		payload, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(payload)
		checksum := hex.EncodeToString(h[:])
		version := strings.TrimSuffix(name, ".sql")

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, string(payload)); err != nil {
			_ = tx.Rollback()
			t.Fatalf("apply migration %s: %v", name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)`, version, checksum); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}

	return db, NewStore(db)
}

func seedAppAndDeployment(t *testing.T, ctx context.Context, db *sql.DB, appID, depID, state string, now time.Time) {
	t.Helper()
	envID := "env_" + strings.TrimPrefix(appID, "app_")
	srcID := "src_" + strings.TrimPrefix(appID, "app_")
	defID := "def_" + strings.TrimPrefix(appID, "app_")
	relID := "rel_" + strings.TrimPrefix(appID, "app_")

	if _, err := db.ExecContext(ctx, `INSERT INTO applications (id, name, version, created_at, updated_at) VALUES ($1, $2, 1, $3, $3)`, appID, "Test App "+appID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO environments (id, application_id, name, created_at) VALUES ($1, $2, 'production', $3)`, envID, appID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO source_revisions (id, application_id, provider, git_commit, created_at) VALUES ($1, $2, 'git', '0123456789abcdef0123456789abcdef01234567', $3)`, srcID, appID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO delivery_definitions (id, application_id, source_revision_id, version, configuration, created_at) VALUES ($1, $2, $3, 1, '{"dockerfile":"scratch"}'::jsonb, $4)`, defID, appID, srcID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO releases (id, application_id, definition_id, version, service_digests, config_digest, created_at) VALUES ($1, $2, $3, 1, '{"web":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}'::jsonb, 'cfg_identity_1', $4)`, relID, appID, defID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO deployments (id, environment_id, release_id, state, version, created_at, updated_at) VALUES ($1, $2, $3, $4, 1, $5, $5)`, depID, envID, relID, state, now); err != nil {
		t.Fatal(err)
	}
}

func TestAcornFoxManagement0040To0041RealMigrationAndDataPreservation(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_MANAGEMENT_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Fatal("OPEN_CARD_MANAGEMENT_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateManagementTestDSN(t, dsn)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open database: %v", redactDSN(dsn, err))
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping database: %v", redactDSN(dsn, err))
	}

	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset test schema: %v", err)
	}

	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version text PRIMARY KEY,
			checksum text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		)
	`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}

	migrationsDir := "../../../migrations/control-plane"
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}

	var allFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			allFiles = append(allFiles, entry.Name())
		}
	}
	sort.Strings(allFiles)

	if len(allFiles) < 41 {
		t.Fatalf("expected at least 41 migration files, found %d", len(allFiles))
	}

	var pre0041Files []string
	var file0041 string
	for _, name := range allFiles {
		prefix := name[:4]
		if prefix <= "0040" {
			pre0041Files = append(pre0041Files, name)
		} else if prefix == "0041" {
			file0041 = name
		}
	}

	if len(pre0041Files) != 40 {
		t.Fatalf("expected exactly 40 pre-0041 migrations, found %d", len(pre0041Files))
	}
	if file0041 == "" {
		t.Fatal("0041 migration file not found")
	}

	pre0041Checksums := make(map[string]string)
	for _, name := range pre0041Files {
		filePath := filepath.Join(migrationsDir, name)
		payload, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}
		h := sha256.Sum256(payload)
		checksum := hex.EncodeToString(h[:])
		version := strings.TrimSuffix(name, ".sql")
		pre0041Checksums[version] = checksum

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin tx for %s: %v", name, err)
		}
		if _, err := tx.ExecContext(ctx, string(payload)); err != nil {
			_ = tx.Rollback()
			t.Fatalf("apply migration %s: %v", name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)`, version, checksum); err != nil {
			_ = tx.Rollback()
			t.Fatalf("record migration %s: %v", name, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit migration %s: %v", name, err)
		}
	}

	var countPre int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&countPre); err != nil || countPre != 40 {
		t.Fatalf("expected 40 applied migrations, got %d (err: %v)", countPre, err)
	}

	seedTime := time.Unix(1_700_000_000, 0).UTC()
	seedAppAndDeployment(t, ctx, db, "app_smoke_1", "dep_smoke_1", "runtime_ready", seedTime)

	publishKey := "acornfox:create:app_smoke_1:smoke1"
	publishDigest := "sha256:" + strings.Repeat("1", 64)
	if _, err := db.ExecContext(ctx, `
		INSERT INTO m1_publish_requests (idempotency_key, request_digest, status, response, created_at, updated_at)
		VALUES ($1, $2, 'completed', '{"deployment_id":"dep_smoke_1"}'::jsonb, $3, $3)
	`, publishKey, publishDigest, seedTime); err != nil {
		t.Fatalf("seed m1_publish_requests: %v", err)
	}

	pubCmdKey := "dns-smoke-1"
	pubCmdDigest := "sha256:" + strings.Repeat("2", 64)
	if _, err := db.ExecContext(ctx, `
		INSERT INTO acornfox_public_access_commands (application_id, deployment_id, idempotency_key, request_digest, requested_enabled, phase, result_status, result_hostname, created_at, updated_at)
		VALUES ('app_smoke_1', 'dep_smoke_1', $1, $2, false, 'completed', 'PUBLIC_DISABLED', 'delivery-0123456789abcdef.apps.example.test', $3, $3)
	`, pubCmdKey, pubCmdDigest, seedTime); err != nil {
		t.Fatalf("seed acornfox_public_access_commands: %v", err)
	}

	filePath0041 := filepath.Join(migrationsDir, file0041)
	payload0041, err := os.ReadFile(filePath0041)
	if err != nil {
		t.Fatalf("read 0041 migration file: %v", err)
	}
	h0041 := sha256.Sum256(payload0041)
	checksum0041 := hex.EncodeToString(h0041[:])
	version0041 := strings.TrimSuffix(file0041, ".sql")

	tx0041, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx for 0041: %v", err)
	}
	if _, err := tx0041.ExecContext(ctx, string(payload0041)); err != nil {
		_ = tx0041.Rollback()
		t.Fatalf("apply migration 0041: %v", err)
	}
	if _, err := tx0041.ExecContext(ctx, `INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)`, version0041, checksum0041); err != nil {
		_ = tx0041.Rollback()
		t.Fatalf("record migration 0041: %v", err)
	}
	if err := tx0041.Commit(); err != nil {
		t.Fatalf("commit migration 0041: %v", err)
	}

	// 7.1 Ledger verification
	var countPost int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&countPost); err != nil || countPost != 41 {
		t.Fatalf("expected 41 applied migrations, got %d (err: %v)", countPost, err)
	}

	rows, err := db.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	defer rows.Close()

	appliedMap := make(map[string]string)
	for rows.Next() {
		var v, c string
		if err := rows.Scan(&v, &c); err != nil {
			t.Fatalf("scan schema_migrations: %v", err)
		}
		appliedMap[v] = c
	}
	rows.Close()

	for v, expectedChecksum := range pre0041Checksums {
		gotChecksum, ok := appliedMap[v]
		if !ok {
			t.Fatalf("migration %s missing after 0041", v)
		}
		if gotChecksum != expectedChecksum {
			t.Fatalf("checksum mismatch for %s: before=%s, after=%s", v, expectedChecksum, gotChecksum)
		}
	}
	if appliedMap[version0041] != checksum0041 {
		t.Fatalf("checksum mismatch for 0041: want=%s got=%s", checksum0041, appliedMap[version0041])
	}

	// 7.2 Data preservation
	var appName, mgmtState string
	var archivedAt sql.NullTime
	err = db.QueryRowContext(ctx, `SELECT name, management_state, archived_at FROM applications WHERE id = 'app_smoke_1'`).Scan(&appName, &mgmtState, &archivedAt)
	if err != nil {
		t.Fatalf("query application after 0041: %v", err)
	}
	if appName != "Test App app_smoke_1" || mgmtState != "active" || archivedAt.Valid {
		t.Fatalf("application data corrupted: name=%s mgmtState=%s archivedAt=%v", appName, mgmtState, archivedAt)
	}

	var depState string
	err = db.QueryRowContext(ctx, `SELECT state FROM deployments WHERE id = 'dep_smoke_1'`).Scan(&depState)
	if err != nil || depState != "runtime_ready" {
		t.Fatalf("deployment data corrupted: state=%s err=%v", depState, err)
	}

	// Permitting paused
	if _, err := db.ExecContext(ctx, `INSERT INTO deployments (id, environment_id, release_id, state, version, created_at, updated_at) VALUES ('dep_smoke_paused', 'env_smoke_1', 'rel_smoke_1', 'paused', 1, $1, $1)`, seedTime); err != nil {
		t.Fatalf("insert paused deployment after 0041 failed: %v", err)
	}

	// m1_publish_requests application_id NULL vs explicit
	var pubAppID sql.NullString
	err = db.QueryRowContext(ctx, `SELECT application_id FROM m1_publish_requests WHERE idempotency_key = $1`, publishKey).Scan(&pubAppID)
	if err != nil {
		t.Fatalf("query m1_publish_requests: %v", err)
	}
	if pubAppID.Valid {
		t.Fatalf("expected legacy publish application_id to be NULL, got %s", pubAppID.String)
	}
	publishKey2 := "acornfox:create:app_smoke_1:smoke2"
	publishDigest2 := "sha256:" + strings.Repeat("3", 64)
	if _, err := db.ExecContext(ctx, `INSERT INTO m1_publish_requests (idempotency_key, request_digest, status, application_id, created_at, updated_at) VALUES ($1, $2, 'in_progress', 'app_smoke_1', $3, $3)`, publishKey2, publishDigest2, seedTime); err != nil {
		t.Fatalf("insert m1_publish_requests with application_id failed: %v", err)
	}

	// acornfox_public_access_commands management_command_id NULL
	var mgmtCmdID sql.NullString
	err = db.QueryRowContext(ctx, `SELECT management_command_id FROM acornfox_public_access_commands WHERE idempotency_key = $1`, pubCmdKey).Scan(&mgmtCmdID)
	if err != nil {
		t.Fatalf("query acornfox_public_access_commands: %v", err)
	}
	if mgmtCmdID.Valid {
		t.Fatalf("expected legacy public access command management_command_id to be NULL, got %s", mgmtCmdID.String)
	}

	// 7.6 New tables & constraints
	cmdID := "mgmt_cmd_smoke_1"
	cmdKey := "mgmt-smoke-key-1"
	cmdDigest := "sha256:" + strings.Repeat("4", 64)

	if _, err := db.ExecContext(ctx, `
		INSERT INTO acornfox_management_commands
			(id, application_id, idempotency_key, request_digest, target_set_digest, action, phase, phase_version, lease_token, lease_owner, lease_expires_at, created_at, updated_at)
		VALUES ($1, 'app_smoke_1', $2, $3, '', 'stop', 'accepted', 1, 'tok_1', 'worker_1', $4, $5, $5)
	`, cmdID, cmdKey, cmdDigest, seedTime.Add(time.Hour), seedTime); err != nil {
		t.Fatalf("insert acornfox_management_commands: %v", err)
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO acornfox_management_commands
			(id, application_id, idempotency_key, request_digest, target_set_digest, action, phase, phase_version, created_at, updated_at)
		VALUES ('mgmt_cmd_smoke_dup', 'app_smoke_1', 'other-key', $1, '', 'stop', 'accepted', 1, $2, $2)
	`, "sha256:"+strings.Repeat("5", 64), seedTime); err == nil {
		t.Fatal("expected duplicate active command on same app to violate partial unique index")
	}

	tgtID := "mgmt_tgt_smoke_1"
	if _, err := db.ExecContext(ctx, `
		INSERT INTO acornfox_management_targets
			(id, command_id, deployment_id, release_id, snapshot_deployment_version, revision, route_phase, original_desired_public, status, created_at, updated_at)
		VALUES ($1, $2, 'dep_smoke_1', 'rel_smoke_1', 1, 1, 'initial', true, 'pending', $3, $3)
	`, tgtID, cmdID, seedTime); err != nil {
		t.Fatalf("insert acornfox_management_targets: %v", err)
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO acornfox_pause_receipts
			(deployment_id, application_id, stop_command_id, config_identity, release_id, original_desired_public, pause_epoch, consumed, created_at, updated_at)
		VALUES ('dep_smoke_1', 'app_smoke_1', $1, 'cfg_smoke_1', 'rel_smoke_1', true, 1, false, $2, $2)
	`, cmdID, seedTime); err != nil {
		t.Fatalf("insert acornfox_pause_receipts: %v", err)
	}

	volID := "vol_smoke_1"
	volDigest := "sha256:" + strings.Repeat("6", 64)
	if _, err := db.ExecContext(ctx, `
		INSERT INTO acornfox_retained_volumes
			(id, application_id, logical_name, managed_volume_name, volume_driver, receipt_digest, verified_at, last_verified_deployment_id, created_at, updated_at)
		VALUES ($1, 'app_smoke_1', 'data', 'smoke-managed-vol-data', 'local', $2, $3, 'dep_smoke_1', $3, $3)
	`, volID, volDigest, seedTime); err != nil {
		t.Fatalf("insert acornfox_retained_volumes: %v", err)
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO acornfox_retained_volumes
			(id, application_id, logical_name, managed_volume_name, volume_driver, receipt_digest, verified_at, last_verified_deployment_id, created_at, updated_at)
		VALUES ('vol_smoke_dup', 'app_smoke_1', 'data', 'other-managed-name', 'local', $1, $2, 'dep_smoke_1', $2, $2)
	`, volDigest, seedTime); err == nil {
		t.Fatal("expected duplicate (application_id, logical_name) in acornfox_retained_volumes to fail")
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO acornfox_public_access_commands
			(application_id, deployment_id, idempotency_key, request_digest, requested_enabled, phase, management_command_id, created_at, updated_at)
		VALUES ('app_smoke_1', 'dep_smoke_1', 'mgmt-pub-key-1', $1, false, 'applying', $2, $3, $3)
	`, "sha256:"+strings.Repeat("7", 64), cmdID, seedTime); err != nil {
		t.Fatalf("insert acornfox_public_access_commands with management_command_id: %v", err)
	}
}

func TestAcornFoxManagementStoreD1LeaseFencing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, store := setupManagementTestDB(t, ctx)
	defer db.Close()

	now := time.Unix(1_700_000_000, 0).UTC()
	seedAppAndDeployment(t, ctx, db, "app_fence", "dep_fence", "runtime_ready", now)

	// 1. Begin stop command
	req := application.AcornFoxManagementRequest{
		ApplicationID:  "app_fence",
		DeploymentID:   "dep_fence",
		Action:         "stop",
		IdempotencyKey: "stop-fence-1",
		Actor:          "admin",
	}
	res, replay, err := store.BeginManagementCommand(ctx, req, "", now)
	if err != nil || replay {
		t.Fatalf("begin stop command: replay=%v err=%v", replay, err)
	}
	if len(res.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(res.Targets))
	}
	target := res.Targets[0]
	if target.ReleaseID != "rel_fence" || target.SnapshotDeploymentVersion != 1 || target.Revision != 1 {
		t.Fatalf("target snapshot fields invalid: %+v", target)
	}

	// 2. Claim lease
	leases, err := store.ClaimManagementCommandLeases(ctx, "worker-1", 10*time.Second, 1, now)
	if err != nil || len(leases) != 1 {
		t.Fatalf("claim lease: len=%d err=%v", len(leases), err)
	}
	lease := leases[0]
	if lease.Token == "" || lease.PhaseVersion != 1 || lease.Owner != "worker-1" {
		t.Fatalf("lease fields invalid: %+v", lease)
	}

	// 3. Stale token rejected
	badTokenLease := lease
	badTokenLease.Token = "stale-token-123"
	err = store.UpdateManagementCommandPhase(ctx, badTokenLease, "accepted", "runtime_stopping", "")
	if !errors.Is(err, application.ErrManagementLeaseLost) {
		t.Fatalf("expected ErrManagementLeaseLost for bad token, got: %v", err)
	}

	// 4. Stale phase_version rejected
	badVersionLease := lease
	badVersionLease.PhaseVersion = 99
	err = store.UpdateManagementCommandPhase(ctx, badVersionLease, "accepted", "runtime_stopping", "")
	if !errors.Is(err, application.ErrManagementLeaseLost) {
		t.Fatalf("expected ErrManagementLeaseLost for bad phaseVersion, got: %v", err)
	}

	// 5. Wrong expected phase rejected
	err = store.UpdateManagementCommandPhase(ctx, lease, "runtime_stopping", "completed", "")
	if !errors.Is(err, application.ErrManagementLeaseLost) {
		t.Fatalf("expected ErrManagementLeaseLost for wrong expectedPhase, got: %v", err)
	}

	// 6. Wrong target revision rejected
	err = store.UpdateManagementTarget(ctx, lease, target, 99)
	if !errors.Is(err, application.ErrManagementTargetConflict) {
		t.Fatalf("expected ErrManagementTargetConflict for wrong revision, got: %v", err)
	}

	// 7. Expired lease rejected (set lease_expires_at in past)
	if _, err := db.ExecContext(ctx, `UPDATE acornfox_management_commands SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1`, lease.CommandID.String()); err != nil {
		t.Fatal(err)
	}
	err = store.UpdateManagementCommandPhase(ctx, lease, "accepted", "runtime_stopping", "")
	if !errors.Is(err, application.ErrManagementLeaseLost) {
		t.Fatalf("expected ErrManagementLeaseLost for expired lease, got: %v", err)
	}

	// 8. Lease takeover by worker-2 after expiration
	leases2, err := store.ClaimManagementCommandLeases(ctx, "worker-2", 10*time.Second, 1, time.Now())
	if err != nil || len(leases2) != 1 {
		t.Fatalf("worker-2 takeover failed: len=%d err=%v", len(leases2), err)
	}
	lease2 := leases2[0]
	if lease2.Owner != "worker-2" || lease2.Token == lease.Token {
		t.Fatalf("expected new owner and distinct token on takeover: %+v", lease2)
	}

	// 9. Valid phase transition releases lease immediately and increments phase_version
	err = store.UpdateManagementCommandPhase(ctx, lease2, "accepted", "runtime_stopping", "")
	if err != nil {
		t.Fatalf("valid phase update failed: %v", err)
	}

	// Verify in DB that lease is released and phase_version incremented
	var dbOwner, dbToken sql.NullString
	var dbExpires sql.NullTime
	var dbPhase string
	var dbVersion int64
	err = db.QueryRowContext(ctx, `SELECT lease_owner, lease_token, lease_expires_at, phase, phase_version FROM acornfox_management_commands WHERE id = $1`, lease.CommandID.String()).Scan(&dbOwner, &dbToken, &dbExpires, &dbPhase, &dbVersion)
	if err != nil {
		t.Fatal(err)
	}
	if dbOwner.Valid || dbToken.Valid || dbExpires.Valid || dbPhase != "runtime_stopping" || dbVersion != 2 {
		t.Fatalf("expected lease released and version 2 in DB, got owner=%v token=%v expires=%v phase=%s ver=%d", dbOwner, dbToken, dbExpires, dbPhase, dbVersion)
	}

	// 10. Next worker can claim immediately without waiting for lease expiry
	leases3, err := store.ClaimManagementCommandLeases(ctx, "worker-3", 10*time.Second, 1, time.Now())
	if err != nil || len(leases3) != 1 {
		t.Fatalf("worker-3 claim failed: len=%d err=%v", len(leases3), err)
	}
	if leases3[0].Phase != "runtime_stopping" || leases3[0].PhaseVersion != 2 {
		t.Fatalf("unexpected lease3: %+v", leases3[0])
	}
}

func TestAcornFoxManagementStoreD1PauseReceiptBinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, store := setupManagementTestDB(t, ctx)
	defer db.Close()

	now := time.Unix(1_700_000_000, 0).UTC()
	seedAppAndDeployment(t, ctx, db, "app_pause", "dep_pause", "runtime_ready", now)

	// 1. Begin stop
	stopKey := "stop-key-p1"
	req := application.AcornFoxManagementRequest{
		ApplicationID:  "app_pause",
		DeploymentID:   "dep_pause",
		Action:         "stop",
		IdempotencyKey: stopKey,
		Actor:          "admin",
	}
	res, replay, err := store.BeginManagementCommand(ctx, req, "", now)
	if err != nil || replay {
		t.Fatalf("begin stop: %v", err)
	}
	leases, err := store.ClaimManagementCommandLeases(ctx, "worker-1", 10*time.Second, 1, now)
	if err != nil || len(leases) != 1 {
		t.Fatalf("claim: %v", err)
	}
	lease := leases[0]
	target := lease.Targets[0]

	// 2. SavePauseReceipt under valid lease
	receipt := application.AcornFoxPauseReceipt{
		DeploymentID:          target.DeploymentID,
		ApplicationID:         lease.ApplicationID,
		StopCommandID:         lease.CommandID,
		ConfigIdentity:        "cfg_identity_1",
		OriginalDesiredPublic: true,
		IntentDigest:          "sha256:" + strings.Repeat("a", 64),
	}
	err = store.SavePauseReceipt(ctx, lease, target, receipt)
	if err != nil {
		t.Fatalf("SavePauseReceipt failed: %v", err)
	}

	// Verify in DB that release_id was populated correctly and FK passed
	loaded, found, err := store.GetPauseReceipt(ctx, "app_pause", "dep_pause")
	if err != nil || !found {
		t.Fatalf("GetPauseReceipt failed: found=%v err=%v", found, err)
	}
	if loaded.ReleaseID != "rel_pause" || loaded.PauseEpoch != 1 || !loaded.OriginalDesiredPublic || loaded.StopCommandID != lease.CommandID {
		t.Fatalf("saved pause receipt attributes mismatch: %+v", loaded)
	}

	// 3. Idempotent retry of SavePauseReceipt with same stop command: no-op, epoch unchanged
	err = store.SavePauseReceipt(ctx, lease, target, receipt)
	if err != nil {
		t.Fatalf("idempotent SavePauseReceipt retry failed: %v", err)
	}
	loaded2, _, _ := store.GetPauseReceipt(ctx, "app_pause", "dep_pause")
	if loaded2.PauseEpoch != 1 {
		t.Fatalf("epoch incremented on idempotent retry: %d", loaded2.PauseEpoch)
	}

	// 4. If intent changes on same command retry -> conflict
	mutatedReceipt := receipt
	mutatedReceipt.IntentDigest = "sha256:" + strings.Repeat("b", 64)
	err = store.SavePauseReceipt(ctx, lease, target, mutatedReceipt)
	if err == nil {
		t.Fatal("expected conflict when intent changes on same command retry")
	}

	// 5. Complete stop command and set deployment to paused
	if _, err := db.ExecContext(ctx, `UPDATE deployments SET state = 'paused', version = version + 1 WHERE id = 'dep_pause'`); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateManagementCommandPhase(ctx, lease, "accepted", "completed", ""); err != nil {
		t.Fatal(err)
	}

	// 6. Fresh Stop key on already paused deployment must be rejected with conflict
	newStopReq := application.AcornFoxManagementRequest{
		ApplicationID:  "app_pause",
		DeploymentID:   "dep_pause",
		Action:         "stop",
		IdempotencyKey: "stop-key-fresh-on-paused",
		Actor:          "admin",
	}
	_, _, err = store.BeginManagementCommand(ctx, newStopReq, "", now)
	if err == nil {
		t.Fatal("expected conflict for fresh stop key on already paused deployment")
	}

	// 7. Original completed stop key replays cleanly via front-loaded replay
	replayedRes, isReplay, err := store.BeginManagementCommand(ctx, req, "", now)
	if err != nil || !isReplay {
		t.Fatalf("expected front-loaded replay of completed stop command, got replay=%v err=%v", isReplay, err)
	}
	if replayedRes.CommandID != res.CommandID || replayedRes.Phase != "completed" {
		t.Fatalf("replayed result mismatch: %+v", replayedRes)
	}
}

func TestAcornFoxManagementStoreD1IdempotencyReplayAndSnapshotStability(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, store := setupManagementTestDB(t, ctx)
	defer db.Close()

	now := time.Unix(1_700_000_000, 0).UTC()
	seedAppAndDeployment(t, ctx, db, "app_replay", "dep_replay_1", "runtime_ready", now)

	// 1. Begin Stop
	key := "stop-replay-key"
	req := application.AcornFoxManagementRequest{
		ApplicationID:  "app_replay",
		DeploymentID:   "dep_replay_1",
		Action:         "stop",
		IdempotencyKey: key,
		Actor:          "admin",
	}
	res, replay, err := store.BeginManagementCommand(ctx, req, "", now)
	if err != nil || replay {
		t.Fatalf("begin stop: %v", err)
	}

	// Claim lease and complete command
	leases, _ := store.ClaimManagementCommandLeases(ctx, "w1", 10*time.Second, 1, now)
	_ = store.UpdateManagementCommandPhase(ctx, leases[0], "accepted", "completed", "")

	// 2. Mutate current deployment.version in DB (simulating multiple runtime changes)
	if _, err := db.ExecContext(ctx, `UPDATE deployments SET version = version + 10 WHERE id = 'dep_replay_1'`); err != nil {
		t.Fatal(err)
	}

	// 3. Replay with original key: must succeed and return stored snapshot version without error
	replayed, isReplay, err := store.BeginManagementCommand(ctx, req, "", now)
	if err != nil || !isReplay {
		t.Fatalf("front-loaded replay failed after deployment version mutation: %v", err)
	}
	if replayed.CommandID != res.CommandID || len(replayed.Targets) != 1 || replayed.Targets[0].SnapshotDeploymentVersion != 1 {
		t.Fatalf("snapshot deployment version corrupted: %+v", replayed.Targets[0])
	}

	// 4. Same key with changed DeploymentID must return conflict
	changedReq := req
	changedReq.DeploymentID = "dep_replay_2"
	_, _, err = store.BeginManagementCommand(ctx, changedReq, "", now)
	if err == nil {
		t.Fatal("expected conflict for same key with different DeploymentID")
	}
}
