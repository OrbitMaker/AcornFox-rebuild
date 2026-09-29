package postgres

import (
	"context"
	"database/sql"
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
	"github.com/open-card/open-card/internal/domain"
)

func TestAdminAuthMigrationIsAdditiveAndExcludesRawCredentialFields(t *testing.T) {
	payload, err := os.ReadFile("../../../migrations/control-plane/0022_admin_auth.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS admin_credentials",
		"admin_credentials_one_enabled_idx",
		"CREATE TABLE IF NOT EXISTS admin_sessions",
		"absolute_expires_at = created_at + INTERVAL '24 hours'",
		"idle_expires_at = LEAST(last_seen_at + INTERVAL '8 hours', absolute_expires_at)",
		"CREATE TABLE IF NOT EXISTS admin_login_rate_limits",
		"window_expires_at = window_started_at + INTERVAL '15 minutes'",
		"failure_count = 5",
		"locked_until = locked_at + INTERVAL '15 minutes'",
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("0022 migration is missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"session_token", "csrf_token", "source_ip", "remote_addr", "plaintext_password"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Errorf("0022 migration must not persist %q", forbidden)
		}
	}
}

func TestControlPlaneMigrationSequenceIsContinuousTo0040(t *testing.T) {
	entries, err := os.ReadDir("../../../migrations/control-plane")
	if err != nil {
		t.Fatal(err)
	}
	versions := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		versions = append(versions, entry.Name()[:4])
	}
	sort.Strings(versions)
	if len(versions) != 40 || versions[0] != "0001" || versions[len(versions)-1] != "0040" {
		t.Fatalf("migration range = %v, want 0001 through 0040", versions)
	}
	for index, version := range versions {
		want := fmt.Sprintf("%04d", index+1)
		if version != want {
			t.Fatalf("migration %d = %s, want %s", index, version, want)
		}
	}
}

// TestAdminAuthSchemaOnTaskScopedPostgres applies every migration twice to an
// explicitly named loopback-only temporary database. It skips without that
// opt-in environment variable, so ordinary unit tests cannot reach a shared,
// cloud, or production PostgreSQL instance.
func TestAdminAuthSchemaOnTaskScopedPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AUTH_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AUTH_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateAuthTestDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		resetAuthTestSchema(t, context.Background(), db)
		_ = db.Close()
	}()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	resetAuthTestSchema(t, ctx, db)
	applyControlPlaneMigrations(t, ctx, db)
	applyControlPlaneMigrations(t, ctx, db)

	now := time.Unix(1_700_000_000, 0).UTC()
	if _, err := db.ExecContext(ctx, `INSERT INTO admin_credentials (id, password_hash_scheme, password_hash, credential_version, created_at, updated_at) VALUES ('admin_plaintext', 'argon2id-v1', 'plaintext', 1, $1, $1)`, now); err == nil {
		t.Fatal("plaintext-shaped password value was accepted")
	}
	store := NewStore(db)
	credential := authTestCredential(now)
	if err := store.CreateAdminCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ActiveAdminCredential(ctx); err != nil {
		t.Fatal(err)
	}
	second := credential
	second.ID = "admin_2"
	if err := store.CreateAdminCredential(ctx, second); err == nil {
		t.Fatal("second enabled administrator was accepted")
	}

	session := authTestSession(now)
	if err := store.CreateAdminSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ActiveAdminSessionByDigest(ctx, session.SessionDigest, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO admin_sessions (id, admin_id, session_digest, csrf_digest, credential_version, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES ('session_bad_digest', 'admin_1', 'short', $1, 1, $2, $2, $2 + INTERVAL '8 hours', $2 + INTERVAL '24 hours')`, strings.Repeat("d", 64), now); err == nil {
		t.Fatal("non-digest session value was accepted")
	}

	rotated, err := store.RotateAdminCredential(ctx, credential.ID, credential.CredentialVersion, "bcrypt-v1", "$bcrypt$v1$fixture", now.Add(2*time.Minute))
	if err != nil || rotated.CredentialVersion != 2 {
		t.Fatalf("credential rotation = %+v, %v", rotated, err)
	}
	if _, err := store.ActiveAdminSessionByDigest(ctx, session.SessionDigest, now.Add(3*time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session from prior credential version remained active: %v", err)
	}

	lockedAt := now.Add(5 * time.Minute)
	rate := domain.AdminLoginRateLimit{
		AdminID:         credential.ID,
		SourceDigest:    domain.AuthDigest(strings.Repeat("e", domain.AuthDigestHexLength)),
		WindowStartedAt: now,
		WindowExpiresAt: now.Add(domain.AdminLoginFailureWindow),
		FailureCount:    domain.AdminLoginMaxFailureAttempts,
		LastFailureAt:   lockedAt,
		LockedAt:        &lockedAt,
		LockedUntil:     pointerAuthTime(lockedAt.Add(domain.AdminLoginLockoutDuration)),
		UpdatedAt:       lockedAt,
	}
	if err := store.UpsertAdminLoginRateLimit(ctx, rate); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdminLoginRateLimit(ctx, credential.ID, rate.SourceDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO admin_login_rate_limits (admin_id, source_digest, window_started_at, window_expires_at, failure_count, last_failure_at, locked_at, locked_until, updated_at) VALUES ('admin_1', 'not-a-digest', $1, $1 + INTERVAL '15 minutes', 5, $1, $1, $1 + INTERVAL '15 minutes', $1)`, now); err == nil {
		t.Fatal("non-digest login source was accepted")
	}
}

func validateAuthTestDSN(t *testing.T, dsn string) {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("task-scoped database URL is invalid")
	}
	if host := parsed.Hostname(); host != "127.0.0.1" && host != "::1" && host != "localhost" {
		t.Fatal("task-scoped database must be loopback-only")
	}
	if database := strings.TrimPrefix(parsed.EscapedPath(), "/"); !strings.HasPrefix(database, "open_card_g2auth_") {
		t.Fatal("task-scoped database name must use open_card_g2auth_ prefix")
	}
}

func resetAuthTestSchema(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset task-scoped schema: %v", err)
	}
}

func applyControlPlaneMigrations(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS g2auth_test_migrations (version text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir("../../../migrations/control-plane")
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
		payload, readErr := os.ReadFile(filepath.Join("../../../migrations/control-plane", name))
		if readErr != nil {
			t.Fatal(readErr)
		}
		tx, beginErr := db.BeginTx(ctx, nil)
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		reservation, reserveErr := tx.ExecContext(ctx, `INSERT INTO g2auth_test_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, name[:4])
		if reserveErr != nil {
			_ = tx.Rollback()
			t.Fatalf("reserve %s: %v", name, reserveErr)
		}
		applied, rowsErr := reservation.RowsAffected()
		if rowsErr != nil {
			_ = tx.Rollback()
			t.Fatalf("inspect %s reservation: %v", name, rowsErr)
		}
		if applied == 1 {
			if _, execErr := tx.ExecContext(ctx, string(payload)); execErr != nil {
				_ = tx.Rollback()
				t.Fatalf("apply %s: %v", name, execErr)
			}
		}
		if commitErr := tx.Commit(); commitErr != nil {
			t.Fatalf("commit %s: %v", name, commitErr)
		}
	}
}

func authTestCredential(now time.Time) domain.AdminCredential {
	return domain.AdminCredential{ID: "admin_1", PasswordHashScheme: "argon2id-v1", PasswordHash: "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$ZGlnaWVzdA", CredentialVersion: 1, CreatedAt: now, UpdatedAt: now}
}

func authTestSession(now time.Time) domain.AdminSession {
	return domain.AdminSession{ID: "session_1", AdminID: "admin_1", SessionDigest: domain.AuthDigest(strings.Repeat("a", domain.AuthDigestHexLength)), CSRFDigest: domain.AuthDigest(strings.Repeat("b", domain.AuthDigestHexLength)), CredentialVersion: 1, CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(domain.AdminSessionIdleTimeout), AbsoluteExpiresAt: now.Add(domain.AdminSessionAbsoluteTimeout)}
}

func pointerAuthTime(value time.Time) *time.Time { return &value }

func TestPostgresAtomicRateLimitAndSessionGatingParity(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AUTH_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AUTH_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateAuthTestDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	resetAuthTestSchema(t, ctx, db)
	applyControlPlaneMigrations(t, ctx, db)

	store := NewStore(db)
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	adminID := domain.ID("admin_pg_parity")
	sourceDigest := domain.AuthDigest(strings.Repeat("c", 64))

	// 1. Create admin credential
	if err := store.CreateAdminCredential(ctx, domain.AdminCredential{
		ID:                 adminID,
		PasswordHashScheme: "argon2id-v1",
		PasswordHash:       "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$ZGlnaWVzdA",
		CredentialVersion:  1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}); err != nil {
		t.Fatal(err)
	}

	// 2. Test concurrent RecordAdminLoginFailure absent-row race and atomic increments
	results := make(chan error, 5)
	for i := 0; i < 5; i++ {
		stepTime := now.Add(time.Duration(i) * time.Minute)
		go func(tStep time.Time) {
			_, err := store.RecordAdminLoginFailure(ctx, adminID, sourceDigest, tStep)
			results <- err
		}(stepTime)
	}
	for i := 0; i < 5; i++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent RecordAdminLoginFailure failed: %v", err)
		}
	}

	// Read back authoritative state: must be locked after 5 failures
	rec, err := store.AdminLoginRateLimit(ctx, adminID, sourceDigest)
	if err != nil {
		t.Fatalf("read back rate limit: %v", err)
	}
	if rec.FailureCount != 5 || !rec.IsLocked(now.Add(5*time.Minute)) {
		t.Fatalf("expected locked rate limit after 5 failures: %+v", rec)
	}

	// 3. Test CreateAdminSessionIfLoginAllowed when source is locked
	sess := domain.AdminSession{
		ID:                domain.ID("sess_pg_parity"),
		AdminID:           adminID,
		SessionDigest:     domain.AuthDigest(strings.Repeat("d", 64)),
		CSRFDigest:        domain.AuthDigest(strings.Repeat("e", 64)),
		CredentialVersion: 1,
		CreatedAt:         now.Add(6 * time.Minute),
		LastSeenAt:        now.Add(6 * time.Minute),
		IdleExpiresAt:     now.Add(6 * time.Minute).Add(domain.AdminSessionIdleTimeout),
		AbsoluteExpiresAt: now.Add(6 * time.Minute).Add(domain.AdminSessionAbsoluteTimeout),
	}
	err = store.CreateAdminSessionIfLoginAllowed(ctx, sess, sourceDigest, now.Add(6*time.Minute))
	if !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("want ErrRateLimited when source locked, got: %v", err)
	}

	// 4. Test CreateAdminSessionIfLoginAllowed with mismatched credential version on unlocked source
	otherSource := domain.AuthDigest(strings.Repeat("f", 64))
	staleSess := sess
	staleSess.CredentialVersion = 2
	err = store.CreateAdminSessionIfLoginAllowed(ctx, staleSess, otherSource, now.Add(6*time.Minute))
	if !errors.Is(err, domain.ErrCredentialVersionConflict) {
		t.Fatalf("want ErrCredentialVersionConflict for stale version, got: %v", err)
	}

	// 5. Successful session creation on unlocked source with valid version
	validSess := sess
	err = store.CreateAdminSessionIfLoginAllowed(ctx, validSess, otherSource, now.Add(6*time.Minute))
	if err != nil {
		t.Fatalf("expected session creation success, got: %v", err)
	}
}

func TestPostgresCreateSessionSharesAdvisoryLockWithFailureRecording(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AUTH_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AUTH_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateAuthTestDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	resetAuthTestSchema(t, ctx, db)
	applyControlPlaneMigrations(t, ctx, db)

	store := NewStore(db)
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	adminID := domain.ID("admin_lock_share")
	sourceDigest := domain.AuthDigest(strings.Repeat("7", 64))

	if err := store.CreateAdminCredential(ctx, domain.AdminCredential{
		ID:                 adminID,
		PasswordHashScheme: "argon2id-v1",
		PasswordHash:       "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$ZGlnaWVzdA",
		CredentialVersion:  1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}); err != nil {
		t.Fatal(err)
	}

	// Begin external transaction and acquire the advisory xact lock explicitly
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1::text), hashtext($2::text))`, adminID.String(), sourceDigest.String()); err != nil {
		t.Fatal(err)
	}

	sessionResult := make(chan error, 1)
	sess := domain.AdminSession{
		ID:                domain.ID("sess_shared_lock"),
		AdminID:           adminID,
		SessionDigest:     domain.AuthDigest(strings.Repeat("8", 64)),
		CSRFDigest:        domain.AuthDigest(strings.Repeat("9", 64)),
		CredentialVersion: 1,
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(domain.AdminSessionIdleTimeout),
		AbsoluteExpiresAt: now.Add(domain.AdminSessionAbsoluteTimeout),
	}

	go func() {
		sessionResult <- store.CreateAdminSessionIfLoginAllowed(ctx, sess, sourceDigest, now)
	}()

	// Verify CreateAdminSessionIfLoginAllowed blocks while the lock is held
	select {
	case err := <-sessionResult:
		t.Fatalf("session creation did not block on held advisory lock: %v", err)
	case <-time.After(150 * time.Millisecond):
		// Expected: blocked waiting for advisory lock
	}

	// Inside the transaction holding the lock, commit a rate-limit lockout
	lockedAt := now
	lockedUntil := now.Add(domain.AdminLoginLockoutDuration)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO admin_login_rate_limits
			(admin_id, source_digest, window_started_at, window_expires_at, failure_count, last_failure_at, locked_at, locked_until, updated_at)
		VALUES ($1, $2, $3, $4, 5, $5, $6, $7, $8)
	`, adminID.String(), sourceDigest.String(), now, now.Add(domain.AdminLoginFailureWindow), now, lockedAt, lockedUntil, now); err != nil {
		t.Fatal(err)
	}

	// Commit transaction, releasing advisory lock
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// Now CreateAdminSessionIfLoginAllowed unblocks, observes the committed lock, and must return ErrRateLimited
	select {
	case err := <-sessionResult:
		if !errors.Is(err, domain.ErrRateLimited) {
			t.Fatalf("expected ErrRateLimited after lock committed, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session creation timed out after advisory lock released")
	}
}
