package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/auth"
	"github.com/open-card/open-card/internal/domain"
)

func secureTestDir(t *testing.T, sub ...string) string {
	t.Helper()
	temp := t.TempDir()
	if err := os.Chmod(temp, 0o700); err != nil {
		t.Fatal(err)
	}
	if len(sub) > 0 {
		full := filepath.Join(append([]string{temp}, sub...)...)
		if err := os.MkdirAll(full, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, 0o700); err != nil {
			t.Fatal(err)
		}
		return full
	}
	return temp
}

func newTestSQLiteStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := secureTestDir(t, "acornfox_test")
	store, err := Open(Config{
		DataDirectory: dir,
		DBName:        "acornfox.db",
		BusyTimeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Open sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store, dir
}

func TestReservedLaunchGenerationSurvivesFailedStartAndOldBackup(t *testing.T) {
	ctx := context.Background()
	data := secureTestDir(t, "launch-source")
	// A genuinely absent DB may consume the first root reservation R=1;
	// this cannot require a prior Store.Open merely to create the database.
	first, err := Open(Config{DataDirectory: data, LaunchGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	if first.CoreGeneration() != 1 {
		t.Fatalf("first generation = %d", first.CoreGeneration())
	}
	backup := filepath.Join(secureTestDir(t, "launch-backup"), "old.db")
	if err := first.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	// R=2 was durably reserved before the child opened the store; losing
	// the child after commit must not erase that reservation.
	failedChild, err := Open(Config{DataDirectory: data, LaunchGeneration: 2})
	if err != nil {
		t.Fatal(err)
	}
	if failedChild.CoreGeneration() != 2 {
		t.Fatalf("reserved generation = %d", failedChild.CoreGeneration())
	}
	if err := failedChild.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Config{DataDirectory: data, LaunchGeneration: 2}); err == nil {
		t.Fatal("replayed reservation reopened an already advanced store")
	}
	readOnly, err := sql.Open("sqlite", "file:"+filepath.Join(data, "acornfox.db")+"?mode=ro&_pragma=query_only(ON)")
	if err != nil {
		t.Fatal(err)
	}
	var unchanged int64
	if err := readOnly.QueryRow("SELECT generation FROM core_generation WHERE singleton=1").Scan(&unchanged); err != nil {
		t.Fatal(err)
	}
	if err := readOnly.Close(); err != nil {
		t.Fatal(err)
	}
	if unchanged != 2 {
		t.Fatalf("rejected replay changed DB generation to %d", unchanged)
	}
	// Make 0011 genuinely pending. The stale ticket must reject before the
	// migration runner recreates its tables or ledger row.
	raw, err := sql.Open("sqlite", filepath.Join(data, "acornfox.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`DROP TABLE image_lifecycle_results; DROP TABLE image_lifecycle_commands; DELETE FROM _schema_migrations WHERE version='0011_image_lifecycle'`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Config{DataDirectory: data, LaunchGeneration: 2}); err == nil {
		t.Fatal("stale reservation migrated pending schema before rejection")
	}
	check, err := sql.Open("sqlite", "file:"+filepath.Join(data, "acornfox.db")+"?mode=ro&_pragma=query_only(ON)")
	if err != nil {
		t.Fatal(err)
	}
	var migrated int
	if err := check.QueryRow(`SELECT count(*) FROM _schema_migrations WHERE version='0011_image_lifecycle'`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if migrated != 0 {
		t.Fatal("rejected launch wrote pending migration ledger")
	}
	if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='image_lifecycle_commands'`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if migrated != 0 {
		t.Fatal("rejected launch created pending migration table")
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}
	// A physical restore has only generation 1; the next root reservation
	// must be R=3, not the old database's apparent next generation 2.
	restored := secureTestDir(t, "launch-restored")
	content, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(restored, "acornfox.db"), content, 0600); err != nil {
		t.Fatal(err)
	}
	next, err := Open(Config{DataDirectory: restored, LaunchGeneration: 3})
	if err != nil {
		t.Fatal(err)
	}
	if next.CoreGeneration() != 3 {
		t.Fatalf("restored launch reused old generation: %d", next.CoreGeneration())
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	legacy, err := Open(Config{DataDirectory: restored})
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	if legacy.CoreGeneration() != 4 {
		t.Fatalf("non-unified increment changed: %d", legacy.CoreGeneration())
	}
}

func TestStoreOpenCloseAndPragmas(t *testing.T) {
	// Rejection of relative path
	if _, err := Open(Config{DataDirectory: "relative/path"}); err == nil {
		t.Fatal("expected relative data directory to be rejected")
	}

	// Rejection of reserved db name
	tempAbs := secureTestDir(t)
	if _, err := Open(Config{DataDirectory: tempAbs, DBName: "acornfox.lock"}); err == nil {
		t.Fatal("expected reserved db name to be rejected")
	}
	if _, err := Open(Config{DataDirectory: tempAbs, DBName: "sub/dir.db"}); err == nil {
		t.Fatal("expected slash in db name to be rejected")
	}

	store, dir := newTestSQLiteStore(t)

	// Check directory permissions (0700)
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("data directory perm = %o, want 0700", dirInfo.Mode().Perm())
	}

	// Check db and lock file permissions (0600)
	dbInfo, err := os.Stat(store.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	if dbInfo.Mode().Perm() != 0o600 {
		t.Fatalf("db file perm = %o, want 0600", dbInfo.Mode().Perm())
	}

	lockInfo, err := os.Stat(filepath.Join(dir, "acornfox.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if lockInfo.Mode().Perm() != 0o600 {
		t.Fatalf("lock file perm = %o, want 0600", lockInfo.Mode().Perm())
	}

	// Verify PRAGMA values on live store
	var version string
	if err := store.db.QueryRow("SELECT sqlite_version();").Scan(&version); err != nil {
		t.Fatalf("sqlite_version: %v", err)
	}
	t.Logf("sqlite_version = %s", version)
	var fk int
	var journalMode string
	var synchronous int
	var busyTimeout int
	if err := store.db.QueryRow("PRAGMA foreign_keys;").Scan(&fk); err != nil || fk != 1 {
		t.Fatalf("foreign_keys = %d, want 1", fk)
	}
	if err := store.db.QueryRow("PRAGMA journal_mode;").Scan(&journalMode); err != nil || strings.ToLower(journalMode) != "wal" {
		t.Fatalf("journal_mode = %s, want wal", journalMode)
	}
	if err := store.db.QueryRow("PRAGMA synchronous;").Scan(&synchronous); err != nil || synchronous < 2 {
		t.Fatalf("synchronous = %d, want >= 2", synchronous)
	}
	if err := store.db.QueryRow("PRAGMA busy_timeout;").Scan(&busyTimeout); err != nil {
		t.Fatalf("busy_timeout: %v", err)
	}
	t.Logf("PRAGMA foreign_keys = %d, journal_mode = %s, synchronous = %d, busy_timeout = %d", fk, journalMode, synchronous, busyTimeout)

	// Attempting to open second store on same directory must be rejected by writer lock
	_, err = Open(Config{DataDirectory: dir})
	if err == nil || !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("expected ErrStoreLocked for competing Open, got %v", err)
	}

	// Close releases lock
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Second store can now open
	store2, err := Open(Config{DataDirectory: dir})
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	_ = store2.Close()
}

func TestStoreUnsafeSidecarAndSymlinkRejection(t *testing.T) {
	tempParent := secureTestDir(t)
	dataDir := filepath.Join(tempParent, "acornfox_sidecar_test")
	_ = os.MkdirAll(dataDir, 0o700)

	// 1. Unsafe sidecar symlink
	walPath := filepath.Join(dataDir, "acornfox.db-wal")
	targetFile := filepath.Join(tempParent, "dummy_target")
	_ = os.WriteFile(targetFile, []byte("unsafe"), 0o600)
	if err := os.Symlink(targetFile, walPath); err != nil {
		t.Fatal(err)
	}

	_, err := Open(Config{DataDirectory: dataDir})
	if err == nil || !strings.Contains(err.Error(), "must be a regular non-symlink file") {
		t.Fatalf("expected symlink sidecar rejection, got: %v", err)
	}
	_ = os.Remove(walPath)

	// 2. Data directory symlink rejection
	symlinkDataDir := filepath.Join(tempParent, "data_dir_symlink")
	if err := os.Symlink(dataDir, symlinkDataDir); err != nil {
		t.Fatal(err)
	}
	_, err = Open(Config{DataDirectory: symlinkDataDir})
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("expected data directory symlink rejection, got: %v", err)
	}

	// 3. Unsafe group/world-writable non-sticky ancestor rejection
	unsafeParent := filepath.Join(tempParent, "unsafe_group_dir")
	if err := os.MkdirAll(unsafeParent, 0o777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(unsafeParent, 0o777)
	unsafeDataDir := filepath.Join(unsafeParent, "sub_data_dir")
	if err := os.MkdirAll(unsafeDataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err = Open(Config{DataDirectory: unsafeDataDir})
	if err == nil || !strings.Contains(err.Error(), "writable by group or others without sticky bit") {
		t.Fatalf("expected unsafe group writable ancestor rejection, got: %v", err)
	}
}

func TestStoreTimestampCanonicalEncodingAndExpiryBounds(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestSQLiteStore(t)

	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	encoded := FormatTime(now)
	if len(encoded) != 30 || !strings.HasSuffix(encoded, ".000000000Z") {
		t.Fatalf("FormatTime produced non-fixed-width string: %q", encoded)
	}

	// Microsecond roundtrip precision
	microTime := time.Date(2026, 9, 26, 12, 0, 0, 123456000, time.UTC)
	microEncoded := FormatTime(microTime)
	parsed, err := ParseTime(microEncoded)
	if err != nil || !parsed.Equal(microTime) {
		t.Fatalf("microsecond roundtrip failed: parsed=%v want=%v err=%v", parsed, microTime, err)
	}

	// Lexicographical ordering in SQL for whole second vs fractional second
	adminID := domain.ID("admin_time")
	if err := store.CreateAdminCredential(ctx, domain.AdminCredential{
		ID:                 adminID,
		PasswordHashScheme: auth.PasswordHashScheme,
		PasswordHash:       "$pbkdf2-sha256$i=600000,l=32$c2FsdHNhbHQ$a2V5",
		CredentialVersion:  1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}); err != nil {
		t.Fatal(err)
	}

	// Session expiring at exact whole second 12:00:00.000000000Z
	wholeSecondExpiry := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	createdAt := wholeSecondExpiry.Add(-8 * time.Hour)
	lastSeenAt := createdAt
	absoluteExpiresAt := createdAt.Add(24 * time.Hour)
	sessID := domain.ID("sess_time_test")
	sessDigest := domain.AuthDigest("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	csrfDigest := domain.AuthDigest("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")

	_, err = store.db.ExecContext(ctx, `
		INSERT INTO admin_sessions
			(id, admin_id, session_digest, csrf_digest, credential_version, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL);
	`, sessID.String(), adminID.String(), sessDigest.String(), csrfDigest.String(), 1, FormatTime(createdAt), FormatTime(lastSeenAt), FormatTime(wholeSecondExpiry), FormatTime(absoluteExpiresAt))
	if err != nil {
		t.Fatal(err)
	}

	// Query at same second + 500ms (12:00:00.500000000Z): must be observed as expired
	halfSecondLater := wholeSecondExpiry.Add(500 * time.Millisecond)
	_, err = store.ActiveAdminSessionByDigest(ctx, sessDigest, halfSecondLater)
	if !errors.Is(err, domain.ErrObjectNotFound) {
		t.Fatalf("whole second expiry was not expired at +500ms: %v", err)
	}

	// Query at 1 nanosecond before whole second: must be active
	nanoBefore := wholeSecondExpiry.Add(-time.Nanosecond)
	active, err := store.ActiveAdminSessionByDigest(ctx, sessDigest, nanoBefore)
	if err != nil || active.ID != sessID {
		t.Fatalf("expected active at -1ns, got err=%v", err)
	}

	// Non-canonical decode rejection
	if _, err := ParseTime("2026-09-26T12:00:00Z"); err == nil {
		t.Fatal("expected short RFC3339 without fractional digits to be rejected by strict canonical decoder")
	}
}

func TestStoreTableConstraintsRejectDirectBadWrites(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestSQLiteStore(t)
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	nowStr := FormatTime(now)

	// 1. Credentials table constraints
	// Empty ID rejected
	_, err := store.db.ExecContext(ctx, `INSERT INTO admin_credentials (id, password_hash_scheme, password_hash, credential_version, created_at, updated_at) VALUES ('', 'pbkdf2-sha256-v1', '$pbkdf2$hash', 1, ?, ?);`, nowStr, nowStr)
	if err == nil {
		t.Fatal("empty id was accepted")
	}
	// Zero version rejected
	_, err = store.db.ExecContext(ctx, `INSERT INTO admin_credentials (id, password_hash_scheme, password_hash, credential_version, created_at, updated_at) VALUES ('adm', 'pbkdf2-sha256-v1', '$pbkdf2$hash', 0, ?, ?);`, nowStr, nowStr)
	if err == nil {
		t.Fatal("zero version was accepted")
	}
	// Invalid scheme (unversioned) rejected
	_, err = store.db.ExecContext(ctx, `INSERT INTO admin_credentials (id, password_hash_scheme, password_hash, credential_version, created_at, updated_at) VALUES ('adm', 'unversioned_scheme', '$pbkdf2$hash', 1, ?, ?);`, nowStr, nowStr)
	if err == nil {
		t.Fatal("unversioned scheme was accepted")
	}
	// Invalid hash (missing initial $) rejected
	_, err = store.db.ExecContext(ctx, `INSERT INTO admin_credentials (id, password_hash_scheme, password_hash, credential_version, created_at, updated_at) VALUES ('adm', 'pbkdf2-sha256-v1', 'no_dollar_hash', 1, ?, ?);`, nowStr, nowStr)
	if err == nil {
		t.Fatal("hash without initial dollar was accepted")
	}
	// updated_at < created_at rejected
	_, err = store.db.ExecContext(ctx, `INSERT INTO admin_credentials (id, password_hash_scheme, password_hash, credential_version, created_at, updated_at) VALUES ('adm', 'pbkdf2-sha256-v1', '$pbkdf2$hash', 1, ?, ?);`, nowStr, FormatTime(now.Add(-time.Second)))
	if err == nil {
		t.Fatal("updated_at < created_at was accepted")
	}

	// 2. Insert valid active admin (including normal hash with f and v)
	adminID := "admin_valid"
	hashWithFV := "$pbkdf2-sha256$i=600000,l=32$c2FsdF9mX3Y$a2V5X2Zfdg"
	_, err = store.db.ExecContext(ctx, `INSERT INTO admin_credentials (id, password_hash_scheme, password_hash, credential_version, created_at, updated_at) VALUES (?, 'pbkdf2-sha256-v1', ?, 1, ?, ?);`, adminID, hashWithFV, nowStr, nowStr)
	if err != nil {
		t.Fatalf("valid hash containing f and v rejected: %v", err)
	}

	// Password hash with space or tab rejected
	_, err = store.db.ExecContext(ctx, `INSERT INTO admin_credentials (id, password_hash_scheme, password_hash, credential_version, created_at, updated_at) VALUES ('adm_space', 'pbkdf2-sha256-v1', '$hdr$body with space', 1, ?, ?);`, nowStr, nowStr)
	if err == nil {
		t.Fatal("password hash with space was accepted")
	}
	_, err = store.db.ExecContext(ctx, `INSERT INTO admin_credentials (id, password_hash_scheme, password_hash, credential_version, created_at, updated_at) VALUES ('adm_tab', 'pbkdf2-sha256-v1', "$hdr$body\twith_tab", 1, ?, ?);`, nowStr, nowStr)
	if err == nil {
		t.Fatal("password hash with tab was accepted")
	}

	// 3. Second active admin rejected by partial unique index
	_, err = store.db.ExecContext(ctx, `INSERT INTO admin_credentials (id, password_hash_scheme, password_hash, credential_version, created_at, updated_at) VALUES ('admin_second', 'pbkdf2-sha256-v1', '$pbkdf2-sha256$i=600000,l=32$c2FsdA$a2V5', 1, ?, ?);`, nowStr, nowStr)
	if err == nil {
		t.Fatal("second active admin accepted")
	}

	// 4. Multiple disabled admins permitted
	_, err = store.db.ExecContext(ctx, `INSERT INTO admin_credentials (id, password_hash_scheme, password_hash, credential_version, disabled_at, created_at, updated_at) VALUES ('admin_dis1', 'pbkdf2-sha256-v1', '$pbkdf2-sha256$i=600000,l=32$c2FsdA$a2V5', 1, ?, ?, ?);`, nowStr, nowStr, nowStr)
	if err != nil {
		t.Fatalf("first disabled admin rejected: %v", err)
	}
	_, err = store.db.ExecContext(ctx, `INSERT INTO admin_credentials (id, password_hash_scheme, password_hash, credential_version, disabled_at, created_at, updated_at) VALUES ('admin_dis2', 'pbkdf2-sha256-v1', '$pbkdf2-sha256$i=600000,l=32$c2FsdA$a2V5', 1, ?, ?, ?);`, nowStr, nowStr, nowStr)
	if err != nil {
		t.Fatalf("second disabled admin rejected: %v", err)
	}

	// 5. Session table constraints: uppercase hex rejected, non-hex rejected, duration violation rejected
	digest64Lower := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digest64Upper := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	digest64NonHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdg"
	csrf64Lower := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	// Uppercase session_digest rejected
	_, err = store.db.ExecContext(ctx, `INSERT INTO admin_sessions (id, admin_id, session_digest, csrf_digest, credential_version, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES ('s_up', ?, ?, ?, 1, ?, ?, ?, ?);`, adminID, digest64Upper, csrf64Lower, nowStr, nowStr, FormatTime(now.Add(8*time.Hour)), FormatTime(now.Add(24*time.Hour)))
	if err == nil {
		t.Fatal("uppercase session_digest was accepted")
	}

	// Non-hex session_digest rejected
	_, err = store.db.ExecContext(ctx, `INSERT INTO admin_sessions (id, admin_id, session_digest, csrf_digest, credential_version, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES ('s_nonhex', ?, ?, ?, 1, ?, ?, ?, ?);`, adminID, digest64NonHex, csrf64Lower, nowStr, nowStr, FormatTime(now.Add(8*time.Hour)), FormatTime(now.Add(24*time.Hour)))
	if err == nil {
		t.Fatal("non-hex session_digest was accepted")
	}

	// Session absolute_expires_at != created_at + 24 hours rejected
	_, err = store.db.ExecContext(ctx, `INSERT INTO admin_sessions (id, admin_id, session_digest, csrf_digest, credential_version, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES ('s_dur', ?, ?, ?, 1, ?, ?, ?, ?);`, adminID, digest64Lower, csrf64Lower, nowStr, nowStr, FormatTime(now.Add(8*time.Hour)), FormatTime(now.Add(25*time.Hour)))
	if err == nil {
		t.Fatal("session duration != 24h was accepted")
	}

	// Invalid date where strftime yields NULL rejected
	invalidDateStr := "2026-99-99T99:99:99.000000000Z"
	_, err = store.db.ExecContext(ctx, `INSERT INTO admin_sessions (id, admin_id, session_digest, csrf_digest, credential_version, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES ('s_invdate', ?, ?, ?, 1, ?, ?, ?, ?);`, adminID, digest64Lower, csrf64Lower, invalidDateStr, invalidDateStr, invalidDateStr, invalidDateStr)
	if err == nil {
		t.Fatal("invalid date string where strftime returns NULL was accepted")
	}

	// Valid fractional duration preserving 9 nanosecond digits accepted
	fracCreated := "2026-09-26T12:34:56.789123456Z"
	fracLastSeen := "2026-09-26T12:34:56.789123456Z"
	fracIdleExp := "2026-09-26T20:34:56.789123456Z"
	fracAbsExp := "2026-09-27T12:34:56.789123456Z"
	_, err = store.db.ExecContext(ctx, `INSERT INTO admin_sessions (id, admin_id, session_digest, csrf_digest, credential_version, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES ('s_frac', ?, ?, ?, 1, ?, ?, ?, ?);`, adminID, digest64Lower, csrf64Lower, fracCreated, fracLastSeen, fracIdleExp, fracAbsExp)
	if err != nil {
		t.Fatalf("valid fractional session timestamps rejected: %v", err)
	}

	// 6. Rate limit table constraints: uppercase source_digest rejected, window mismatch rejected
	// Uppercase source_digest rejected
	_, err = store.db.ExecContext(ctx, `INSERT INTO admin_login_rate_limits (admin_id, source_digest, window_started_at, window_expires_at, failure_count, last_failure_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?);`, adminID, digest64Upper, nowStr, FormatTime(now.Add(15*time.Minute)), nowStr, nowStr)
	if err == nil {
		t.Fatal("uppercase source_digest was accepted")
	}

	// window_expires_at != window_started_at + 15 minutes rejected
	_, err = store.db.ExecContext(ctx, `INSERT INTO admin_login_rate_limits (admin_id, source_digest, window_started_at, window_expires_at, failure_count, last_failure_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?);`, adminID, digest64Lower, nowStr, FormatTime(now.Add(20*time.Minute)), nowStr, nowStr)
	if err == nil {
		t.Fatal("window duration != 15m was accepted")
	}

	// failure_count = 5 without lock timestamps rejected
	_, err = store.db.ExecContext(ctx, `INSERT INTO admin_login_rate_limits (admin_id, source_digest, window_started_at, window_expires_at, failure_count, last_failure_at, updated_at) VALUES (?, ?, ?, ?, 5, ?, ?);`, adminID, digest64Lower, nowStr, FormatTime(now.Add(15*time.Minute)), nowStr, nowStr)
	if err == nil {
		t.Fatal("failure_count=5 without lock timestamps was accepted")
	}

	// failure_count < 5 with locked_at rejected
	_, err = store.db.ExecContext(ctx, `INSERT INTO admin_login_rate_limits (admin_id, source_digest, window_started_at, window_expires_at, failure_count, last_failure_at, locked_at, locked_until, updated_at) VALUES (?, ?, ?, ?, 3, ?, ?, ?, ?);`, adminID, digest64Lower, nowStr, FormatTime(now.Add(15*time.Minute)), nowStr, nowStr, FormatTime(now.Add(15*time.Minute)), nowStr)
	if err == nil {
		t.Fatal("failure_count=3 with lock timestamps was accepted")
	}
}

func TestStoreAdminCredentialLifecycleAndDisabledHistory(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestSQLiteStore(t)

	// 1. Initial state: no administrator
	exists, err := store.AdministratorExists(ctx)
	if err != nil || exists {
		t.Fatalf("expected exists=false initially, got %v (err=%v)", exists, err)
	}

	_, err = store.ActiveAdminCredential(ctx)
	if !errors.Is(err, domain.ErrObjectNotFound) {
		t.Fatalf("want ErrObjectNotFound, got %v", err)
	}

	// 2. Create first active administrator
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	adminID := domain.ID("admin_1")
	cred1 := domain.AdminCredential{
		ID:                 adminID,
		PasswordHashScheme: auth.PasswordHashScheme,
		PasswordHash:       "$pbkdf2-sha256$i=600000,l=32$c2FsdHNhbHQ$a2V5a2V5a2V5",
		CredentialVersion:  1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := store.CreateAdminCredential(ctx, cred1); err != nil {
		t.Fatalf("CreateAdminCredential: %v", err)
	}

	exists, err = store.AdministratorExists(ctx)
	if err != nil || !exists {
		t.Fatalf("expected exists=true, got %v", exists)
	}

	active, err := store.ActiveAdminCredential(ctx)
	if err != nil || active.ID != adminID || active.CredentialVersion != 1 {
		t.Fatalf("active = %+v, err = %v", active, err)
	}

	// 3. Second active administrator MUST be rejected by partial unique index
	cred2 := domain.AdminCredential{
		ID:                 domain.ID("admin_2"),
		PasswordHashScheme: auth.PasswordHashScheme,
		PasswordHash:       "$pbkdf2-sha256$i=600000,l=32$c2FsdHNhbHQ$bmV3a2V5",
		CredentialVersion:  1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := store.CreateAdminCredential(ctx, cred2); err == nil {
		t.Fatal("second active administrator was accepted, expected constraint violation")
	}

	// 4. Rotate credential
	rotated, err := store.RotateAdminCredential(ctx, adminID, 1, auth.PasswordHashScheme, "$pbkdf2-sha256$i=600000,l=32$c2FsdHNhbHQ$cm90YXRlZA", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("RotateAdminCredential: %v", err)
	}
	if rotated.CredentialVersion != 2 {
		t.Fatalf("rotated version = %d, want 2", rotated.CredentialVersion)
	}

	// Stale rotation attempt rejected
	_, err = store.RotateAdminCredential(ctx, adminID, 1, auth.PasswordHashScheme, "$pbkdf2-sha256$i=600000,l=32$c2FsdHNhbHQ$c3RhbGU", now.Add(2*time.Minute))
	if !errors.Is(err, domain.ErrCredentialVersionConflict) {
		t.Fatalf("want ErrCredentialVersionConflict, got %v", err)
	}

	// 5. Disable active administrator directly
	disabledTime := now.Add(3 * time.Minute)
	_, err = store.db.ExecContext(ctx, "UPDATE admin_credentials SET disabled_at = ? WHERE id = ?;", FormatTime(disabledTime), adminID.String())
	if err != nil {
		t.Fatal(err)
	}

	// Now active is missing
	_, err = store.ActiveAdminCredential(ctx)
	if !errors.Is(err, domain.ErrObjectNotFound) {
		t.Fatalf("want ErrObjectNotFound after disable, got %v", err)
	}

	// But AdministratorExists remains true (historical record counted!)
	exists, err = store.AdministratorExists(ctx)
	if err != nil || !exists {
		t.Fatalf("AdministratorExists must remain true with only disabled records, got exists=%v err=%v", exists, err)
	}

	// Second disabled historical record CAN be inserted (multiple disabled rows permitted)
	disabledTime2 := now.Add(4 * time.Minute)
	cred3 := domain.AdminCredential{
		ID:                 domain.ID("admin_history_3"),
		PasswordHashScheme: auth.PasswordHashScheme,
		PasswordHash:       "$pbkdf2-sha256$i=600000,l=32$c2FsdHNhbHQ$aGlzdG9yeQ",
		CredentialVersion:  1,
		DisabledAt:         &disabledTime2,
		CreatedAt:          now,
		UpdatedAt:          disabledTime2,
	}
	if err := store.CreateAdminCredential(ctx, cred3); err != nil {
		t.Fatalf("multiple disabled historical rows must be allowed: %v", err)
	}
}

func TestStoreSessionLifecycleTouchAndMonotonicity(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestSQLiteStore(t)
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

	adminID := domain.ID("admin_sess")
	if err := store.CreateAdminCredential(ctx, domain.AdminCredential{
		ID:                 adminID,
		PasswordHashScheme: auth.PasswordHashScheme,
		PasswordHash:       "$pbkdf2-sha256$i=600000,l=32$c2FsdHNhbHQ$a2V5",
		CredentialVersion:  1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}); err != nil {
		t.Fatal(err)
	}

	sessID := domain.ID("sess_1")
	sessDigest := domain.AuthDigest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	csrfDigest := domain.AuthDigest("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	sess := domain.AdminSession{
		ID:                sessID,
		AdminID:           adminID,
		SessionDigest:     sessDigest,
		CSRFDigest:        csrfDigest,
		CredentialVersion: 1,
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(domain.AdminSessionIdleTimeout),
		AbsoluteExpiresAt: now.Add(domain.AdminSessionAbsoluteTimeout),
	}
	if err := store.CreateAdminSession(ctx, sess); err != nil {
		t.Fatalf("CreateAdminSession: %v", err)
	}

	// Lookup active
	active, err := store.ActiveAdminSessionByDigest(ctx, sessDigest, now.Add(time.Minute))
	if err != nil || active.ID != sessID {
		t.Fatalf("active session = %+v, err = %v", active, err)
	}

	// Touch advances last_seen_at
	touched, err := store.TouchAdminSession(ctx, sessID, 1, now.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("TouchAdminSession: %v", err)
	}
	if !touched.LastSeenAt.Equal(now.Add(10 * time.Minute)) {
		t.Fatalf("last_seen_at = %v, want %v", touched.LastSeenAt, now.Add(10*time.Minute))
	}

	// Monotonic touch: out-of-order request with older timestamp must NOT move last_seen backward
	touchedReorder, err := store.TouchAdminSession(ctx, sessID, 1, now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("reordered touch: %v", err)
	}
	if touchedReorder.LastSeenAt.Before(touched.LastSeenAt) {
		t.Fatalf("last_seen_at moved backward: %v < %v", touchedReorder.LastSeenAt, touched.LastSeenAt)
	}

	// Revoke
	if err := store.RevokeAdminSession(ctx, sessID, now.Add(15*time.Minute)); err != nil {
		t.Fatalf("RevokeAdminSession: %v", err)
	}

	// Lookup after revocation -> not found
	_, err = store.ActiveAdminSessionByDigest(ctx, sessDigest, now.Add(16*time.Minute))
	if !errors.Is(err, domain.ErrObjectNotFound) {
		t.Fatalf("expected ErrObjectNotFound after revocation, got %v", err)
	}

	// Revoke is idempotent
	if err := store.RevokeAdminSession(ctx, sessID, now.Add(20*time.Minute)); err != nil {
		t.Fatalf("idempotent RevokeAdminSession: %v", err)
	}
}

func TestStoreAtomicRateLimitAndLockout(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestSQLiteStore(t)
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	adminID := domain.ID("admin_rl")
	sourceDigest := domain.AuthDigest("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")

	if err := store.CreateAdminCredential(ctx, domain.AdminCredential{
		ID:                 adminID,
		PasswordHashScheme: auth.PasswordHashScheme,
		PasswordHash:       "$pbkdf2-sha256$i=600000,l=32$c2FsdHNhbHQ$a2V5",
		CredentialVersion:  1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}); err != nil {
		t.Fatal(err)
	}

	// 1-4 failures
	for i := 1; i <= 4; i++ {
		rec, err := store.RecordAdminLoginFailure(ctx, adminID, sourceDigest, now.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatalf("failure %d: %v", i, err)
		}
		if rec.FailureCount != i || rec.IsLocked(now.Add(time.Duration(i)*time.Minute)) {
			t.Fatalf("rec %d unexpected: %+v", i, rec)
		}
	}

	// 5th failure triggers lock
	lockedNow := now.Add(5 * time.Minute)
	rec5, err := store.RecordAdminLoginFailure(ctx, adminID, sourceDigest, lockedNow)
	if err != nil {
		t.Fatalf("failure 5: %v", err)
	}
	if rec5.FailureCount != 5 || !rec5.IsLocked(lockedNow) {
		t.Fatalf("expected locked rec5: %+v", rec5)
	}

	// Subsequent failure while locked preserves lock without shortening
	rec6, err := store.RecordAdminLoginFailure(ctx, adminID, sourceDigest, now.Add(6*time.Minute))
	if err != nil {
		t.Fatalf("failure 6: %v", err)
	}
	if !rec6.LockedUntil.Equal(*rec5.LockedUntil) {
		t.Fatalf("lock was shortened or altered: before=%v after=%v", rec5.LockedUntil, rec6.LockedUntil)
	}

	// Window reset after lockout expires
	afterLock := rec5.LockedUntil.Add(time.Second)
	recReset, err := store.RecordAdminLoginFailure(ctx, adminID, sourceDigest, afterLock)
	if err != nil {
		t.Fatalf("reset failure: %v", err)
	}
	if recReset.FailureCount != 1 || recReset.IsLocked(afterLock) {
		t.Fatalf("expected reset: %+v", recReset)
	}
}

func TestStoreAtomicSessionCreationGating(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestSQLiteStore(t)
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	adminID := domain.ID("admin_gate")
	sourceDigest := domain.AuthDigest("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")

	if err := store.CreateAdminCredential(ctx, domain.AdminCredential{
		ID:                 adminID,
		PasswordHashScheme: auth.PasswordHashScheme,
		PasswordHash:       "$pbkdf2-sha256$i=600000,l=32$c2FsdHNhbHQ$a2V5",
		CredentialVersion:  1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}); err != nil {
		t.Fatal(err)
	}

	sess := domain.AdminSession{
		ID:                domain.ID("sess_gated"),
		AdminID:           adminID,
		SessionDigest:     domain.AuthDigest("1111111111111111111111111111111111111111111111111111111111111111"),
		CSRFDigest:        domain.AuthDigest("2222222222222222222222222222222222222222222222222222222222222222"),
		CredentialVersion: 1,
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(domain.AdminSessionIdleTimeout),
		AbsoluteExpiresAt: now.Add(domain.AdminSessionAbsoluteTimeout),
	}

	// 1. Lock the source by recording 5 failures
	for i := 1; i <= 5; i++ {
		_, _ = store.RecordAdminLoginFailure(ctx, adminID, sourceDigest, now.Add(time.Duration(i)*time.Second))
	}

	// Creation while source locked must return auth.ErrRateLimited
	err := store.CreateAdminSessionIfLoginAllowed(ctx, sess, sourceDigest, now.Add(10*time.Second))
	if !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("want ErrRateLimited when locked, got %v", err)
	}

	// 2. Different unlocked source with rotated credential version
	otherSource := domain.AuthDigest("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	staleSess := sess
	staleSess.CredentialVersion = 99 // version mismatch
	err = store.CreateAdminSessionIfLoginAllowed(ctx, staleSess, otherSource, now.Add(10*time.Second))
	if !errors.Is(err, domain.ErrCredentialVersionConflict) {
		t.Fatalf("want ErrCredentialVersionConflict for stale version, got %v", err)
	}

	// 3. Corrupted locked_until timestamp in storage must fail closed with ErrCorruptData
	if _, err := store.db.ExecContext(ctx, "PRAGMA ignore_check_constraints = ON;"); err != nil {
		t.Fatal(err)
	}
	_, err = store.db.ExecContext(ctx, "UPDATE admin_login_rate_limits SET locked_until = '2026-99-99T99:99:99.000000000Z' WHERE admin_id = ?;", adminID.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "PRAGMA ignore_check_constraints = OFF;"); err != nil {
		t.Fatal(err)
	}
	err = store.CreateAdminSessionIfLoginAllowed(ctx, sess, sourceDigest, now.Add(10*time.Second))
	if err == nil || !errors.Is(err, ErrCorruptData) {
		t.Fatalf("expected ErrCorruptData on corrupt locked_until timestamp, got: %v", err)
	}

	// 4. Valid creation with correct version on unlocked source
	validSess := sess
	validSess.SessionDigest = domain.AuthDigest("3333333333333333333333333333333333333333333333333333333333333333")
	validSess.CSRFDigest = domain.AuthDigest("4444444444444444444444444444444444444444444444444444444444444444")
	err = store.CreateAdminSessionIfLoginAllowed(ctx, validSess, otherSource, now.Add(10*time.Second))
	if err != nil {
		t.Fatalf("valid CreateAdminSessionIfLoginAllowed: %v", err)
	}
}

func TestStoreBackupAndRestoreValidation(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestSQLiteStore(t)
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	adminID := domain.ID("admin_bkp")

	if err := store.CreateAdminCredential(ctx, domain.AdminCredential{
		ID:                 adminID,
		PasswordHashScheme: auth.PasswordHashScheme,
		PasswordHash:       "$pbkdf2-sha256$i=600000,l=32$c2FsdHNhbHQ$a2V5",
		CredentialVersion:  1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}); err != nil {
		t.Fatal(err)
	}

	sessDigest := domain.AuthDigest("5555555555555555555555555555555555555555555555555555555555555555")
	if err := store.CreateAdminSession(ctx, domain.AdminSession{
		ID:                domain.ID("sess_bkp"),
		AdminID:           adminID,
		SessionDigest:     sessDigest,
		CSRFDigest:        domain.AuthDigest("6666666666666666666666666666666666666666666666666666666666666666"),
		CredentialVersion: 1,
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(domain.AdminSessionIdleTimeout),
		AbsoluteExpiresAt: now.Add(domain.AdminSessionAbsoluteTimeout),
	}); err != nil {
		t.Fatal(err)
	}

	backupDir := secureTestDir(t, "backup")
	backupPath := filepath.Join(backupDir, "backup_acornfox.db")

	if err := store.Backup(ctx, backupPath); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// Verify backup file exists and has 0600 permissions
	fi, err := os.Stat(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup file perm = %o, want 0600", fi.Mode().Perm())
	}

	// Attempting backup onto existing file must fail (no overwrite)
	if err := store.Backup(ctx, backupPath); err == nil {
		t.Fatal("expected backup to fail when destination already exists")
	}

	// Reopen backup in a clean independent directory to validate restore
	restoreDir := secureTestDir(t, "restore_dest")
	restorePath := filepath.Join(restoreDir, "acornfox.db")
	content, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(restorePath, content, 0o600); err != nil {
		t.Fatal(err)
	}

	restoredStore, err := Open(Config{
		DataDirectory: restoreDir,
		DBName:        "acornfox.db",
	})
	if err != nil {
		t.Fatalf("Open restored store: %v", err)
	}
	defer restoredStore.Close()

	// Verify restored state
	active, err := restoredStore.ActiveAdminCredential(ctx)
	if err != nil || active.ID != adminID {
		t.Fatalf("restored credential = %+v, err = %v", active, err)
	}
	activeSess, err := restoredStore.ActiveAdminSessionByDigest(ctx, sessDigest, now.Add(time.Minute))
	if err != nil || activeSess.AdminID != adminID {
		t.Fatalf("restored session = %+v, err = %v", activeSess, err)
	}
}

func TestStoreSchemaIdentityAndStructuralValidation(t *testing.T) {
	ctx := context.Background()
	dir := secureTestDir(t, "acornfox_corrupt")
	store, err := Open(Config{DataDirectory: dir})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Checksum mismatch in _schema_migrations
	_, err = store.db.ExecContext(ctx, "UPDATE _schema_migrations SET checksum = '0000000000000000000000000000000000000000000000000000000000000000' WHERE version = '0001_admin_auth';")
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()

	_, err = Open(Config{DataDirectory: dir})
	if err == nil || !errors.Is(err, ErrIncompatibleSchema) {
		t.Fatalf("expected ErrIncompatibleSchema on checksum mismatch, got %v", err)
	}

	// 2. Unexpected tables without versioning
	dirUnversioned := secureTestDir(t, "acornfox_unexpected_table")
	rawStore, err := Open(Config{DataDirectory: dirUnversioned})
	if err != nil {
		t.Fatal(err)
	}
	// Inject unexpected table
	_, err = rawStore.db.ExecContext(ctx, "CREATE TABLE unexpected_external_table (id INT PRIMARY KEY);")
	if err != nil {
		t.Fatal(err)
	}
	_ = rawStore.Close()

	// Reopen must reject unexpected table in owned schema
	_, err = Open(Config{DataDirectory: dirUnversioned})
	if err == nil || !errors.Is(err, ErrIncompatibleSchema) {
		t.Fatalf("expected ErrIncompatibleSchema on unexpected table, got %v", err)
	}

	// 3. Structural alteration: drop expected partial index
	dirIndexCorrupt := secureTestDir(t, "acornfox_index_corrupt")
	idxStore, err := Open(Config{DataDirectory: dirIndexCorrupt})
	if err != nil {
		t.Fatal(err)
	}
	_, err = idxStore.db.ExecContext(ctx, "DROP INDEX admin_credentials_one_enabled_idx;")
	if err != nil {
		t.Fatal(err)
	}
	_ = idxStore.Close()

	_, err = Open(Config{DataDirectory: dirIndexCorrupt})
	if err == nil || !errors.Is(err, ErrIncompatibleSchema) {
		t.Fatalf("expected ErrIncompatibleSchema on missing index, got %v", err)
	}

	// 4. Same-name index structurally altered to non-partial index
	dirIndexAltered := secureTestDir(t, "acornfox_index_altered")
	altStore, err := Open(Config{DataDirectory: dirIndexAltered})
	if err != nil {
		t.Fatal(err)
	}
	_, err = altStore.db.ExecContext(ctx, "DROP INDEX admin_credentials_one_enabled_idx; CREATE INDEX admin_credentials_one_enabled_idx ON admin_credentials (id);")
	if err != nil {
		t.Fatal(err)
	}
	_ = altStore.Close()

	_, err = Open(Config{DataDirectory: dirIndexAltered})
	if err == nil || !errors.Is(err, ErrIncompatibleSchema) {
		t.Fatalf("expected ErrIncompatibleSchema on structurally altered same-name index, got %v", err)
	}
}
