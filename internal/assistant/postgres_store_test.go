package assistant

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/domain"
)

func TestAssistantMigrationContainsBoundedProjectedFactsOnly(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "migrations", "control-plane", "0037_acornfox_assistant.sql"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(raw))
	for _, required := range []string{"acornfox_assistant_sessions", "acornfox_assistant_runs", "acornfox_assistant_events", "acornfox_assistant_one_running_per_session_idx", "request_digest", "message_bytes", "event_bytes"} {
		if !strings.Contains(text, required) {
			t.Errorf("migration missing %q", required)
		}
	}
	for _, forbidden := range []string{"provider_error text", "tool_args json", "tool_arguments json", "raw_event json", "credential text", "environment_json"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("migration contains forbidden field %q", forbidden)
		}
	}
}

func TestPostgresStoreDurabilityLeaseRecoveryAndRetention(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_ASSISTANT_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_ASSISTANT_TEST_DATABASE_URL is required")
	}
	validateAssistantDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(8)
	resetAssistantSchema(t, ctx, db)
	applyAssistantMigration(t, ctx, db, "0022_admin_auth.sql")
	applyAssistantMigration(t, ctx, db, "0037_acornfox_assistant.sql")
	applyAssistantMigration(t, ctx, db, "0037_acornfox_assistant.sql")
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	if _, err = db.ExecContext(ctx, `INSERT INTO admin_credentials(id,password_hash_scheme,password_hash,credential_version,created_at,updated_at) VALUES('admin_pg','pbkdf2-sha256-v1','$pbkdf2-sha256$i=600000,l=32$c2FsdA$ZGlnaWVzdA',1,$1,$1)`, now); err != nil {
		t.Fatal(err)
	}
	store, err := newPostgresStore(ctx, db, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := newPostgresStore(ctx, db, 50*time.Millisecond); !errors.Is(err, ErrWriterLeaseHeld) {
		t.Fatalf("second writer=%v", err)
	}
	actor := Actor{AdminID: "admin_pg"}
	session := Session{ID: "asst_session_pg", Scope: Scope{Kind: ScopeApp, AppID: "app_pg"}, CreatedAt: now, UpdatedAt: now, ownerID: actor.AdminID}
	if err = store.CreateSession(ctx, actor, session); err != nil {
		t.Fatal(err)
	}
	if empty, err := store.EventsAfter(ctx, actor, session.ID, 0, DefaultEventPageSize); err != nil || empty.Status != CursorOK || empty.OldestCursor != 1 || empty.LatestCursor != 0 || len(empty.Events) != 0 {
		t.Fatalf("empty=%+v err=%v", empty, err)
	}
	run := Run{ID: "asst_run_pg", SessionID: session.ID, Status: RunAccepted, CreatedAt: now, UpdatedAt: now, message: "durable user message"}
	created, replay, err := store.CreateOrReplayRun(ctx, actor, session.ID, "idem-pg", messageDigest(run.message), run, now)
	if err != nil || replay || created.ID != run.ID {
		t.Fatalf("create=%+v replay=%v err=%v", created, replay, err)
	}
	replayed, replay, err := store.CreateOrReplayRun(ctx, actor, session.ID, "idem-pg", messageDigest(run.message), Run{ID: "asst_run_other", message: run.message}, now)
	if err != nil || !replay || replayed.ID != run.ID {
		t.Fatalf("replay=%+v replay=%v err=%v", replayed, replay, err)
	}
	if _, _, err = store.CreateOrReplayRun(ctx, actor, session.ID, "idem-pg", messageDigest("different"), Run{ID: "asst_run_conflict", message: "different"}, now); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflict=%v", err)
	}
	claimed, found, err := store.ClaimNextRun(ctx, session.ID, now.Add(time.Second))
	if err != nil || !found || claimed.ownerID != actor.AdminID || claimed.message != run.message {
		t.Fatalf("claim=%+v found=%v err=%v", claimed, found, err)
	}
	if _, found, err = store.ClaimNextRun(ctx, session.ID, now.Add(time.Second)); err != nil || found {
		t.Fatalf("double claim found=%v err=%v", found, err)
	}
	for index := 0; index < 316; index++ {
		if _, err = store.AppendEvent(ctx, session.ID, run.ID, EventAssistantDelta, "chunk", now.Add(2*time.Second)); err != nil {
			t.Fatalf("delta %d: %v", index, err)
		}
	}
	if _, err = store.AppendEvent(ctx, session.ID, run.ID, EventAssistantMessage, "durable assistant answer", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = store.FinishRun(ctx, session.ID, run.ID, RunCompleted, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.EventsAfter(ctx, actor, session.ID, 0, DefaultEventPageSize)
	if err != nil || len(snapshot.Events) != 4 || snapshot.Events[0].Text != run.message || snapshot.Events[3].Type != EventRunCompleted {
		t.Fatalf("events=%+v err=%v", snapshot, err)
	}
	if snapshot.Events[2].Type != EventAssistantMessage || snapshot.Events[2].Cursor <= 2 || snapshot.LatestCursor != 320 {
		t.Fatalf("compaction cursor=%+v", snapshot)
	}

	// An accepted run survives one store instance, then the next exclusive
	// writer marks it unknown without invoking a Runner.
	pending := Run{ID: "asst_run_pending_pg", SessionID: session.ID, Status: RunAccepted, CreatedAt: now.Add(4 * time.Second), UpdatedAt: now.Add(4 * time.Second), message: "never automatically resend"}
	if _, _, err = store.CreateOrReplayRun(ctx, actor, session.ID, "pending-pg", messageDigest(pending.message), pending, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-store.Done():
	default:
		t.Fatal("closed writer did not signal Done")
	}
	restarted, err := newPostgresStore(ctx, db, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	runner := newFakeRunner()
	service, err := NewService(Config{Store: restarted, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if count, err := service.Recover(ctx); err != nil || count != 1 {
		t.Fatalf("recover=%d err=%v", count, err)
	}
	if calls, _ := runner.counts(); calls != 0 {
		t.Fatalf("recovery resent runner=%d", calls)
	}
	recovered, err := restarted.EventsAfter(ctx, actor, session.ID, 4, DefaultEventPageSize)
	if err != nil {
		t.Fatal(err)
	}
	foundUnknown := false
	for _, event := range recovered.Events {
		if event.RunID == pending.ID && event.Type == EventRunUnknown {
			foundUnknown = true
		}
	}
	if !foundUnknown {
		t.Fatalf("recovered events=%+v", recovered)
	}

	// Retention advances the oldest cursor monotonically and reports an expired
	// browser cursor instead of silently skipping history.
	retentionSession := Session{ID: "asst_session_retention", Scope: Scope{Kind: ScopeHost}, CreatedAt: now, UpdatedAt: now, ownerID: actor.AdminID}
	if err = restarted.CreateSession(ctx, actor, retentionSession); err != nil {
		t.Fatal(err)
	}
	retentionRun := Run{ID: "asst_run_retention", SessionID: retentionSession.ID, Status: RunAccepted, CreatedAt: now, UpdatedAt: now, message: "retention"}
	if _, _, err = restarted.CreateOrReplayRun(ctx, actor, retentionSession.ID, "retention", messageDigest(retentionRun.message), retentionRun, now); err != nil {
		t.Fatal(err)
	}
	if _, found, err = restarted.ClaimNextRun(ctx, retentionSession.ID, now); err != nil || !found {
		t.Fatalf("retention claim=%v err=%v", found, err)
	}
	for index := 0; index < defaultMaxEventsPerSession+2; index++ {
		if _, err = restarted.AppendEvent(ctx, retentionSession.ID, retentionRun.ID, EventAssistantDelta, "x", now); err != nil {
			t.Fatalf("append %d: %v", index, err)
		}
	}
	expired, err := restarted.EventsAfter(ctx, actor, retentionSession.ID, 0, DefaultEventPageSize)
	if !errors.Is(err, ErrCursorExpired) || expired.Status != CursorExpired || expired.OldestCursor <= 1 {
		t.Fatalf("expired=%+v err=%v", expired, err)
	}
}

func TestPostgresStoreSignalsWriterConnectionLoss(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_ASSISTANT_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_ASSISTANT_TEST_DATABASE_URL is required")
	}
	validateAssistantDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(4)
	store, err := newPostgresStore(ctx, db, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.mu.Lock()
	var pid int
	err = store.writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid)
	store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRowContext(ctx, `SELECT pg_terminate_backend($1)`, pid).Scan(new(bool)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-store.Done():
	case <-ctx.Done():
		t.Fatal("writer loss did not signal Done")
	}
	if err = store.CreateSession(ctx, Actor{AdminID: "admin_pg"}, Session{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid precedence=%v", err)
	}
}

func validateAssistantDSN(t *testing.T, dsn string) {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || (parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "localhost" && parsed.Hostname() != "::1") || !strings.HasPrefix(strings.TrimPrefix(parsed.EscapedPath(), "/"), "open_card_assistant_") {
		t.Fatal("assistant test database URL is invalid")
	}
}
func resetAssistantSchema(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
}
func applyAssistantMigration(t *testing.T, ctx context.Context, db *sql.DB, name string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "migrations", "control-plane", name))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, string(raw)); err != nil {
		t.Fatalf("apply %s: %v", name, err)
	}
}

var _ = domain.ID("")
