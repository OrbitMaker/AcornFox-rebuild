package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/application"
	applicationcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/auth"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

// accepted0001Checksum is captured from the frozen accepted TC1B source.
// The migration regression is anchored to this immutable accepted checksum.
const accepted0001Checksum = "4fc6cfec1b1d70a6ad5fd02806708e7ec22e6b0b78238567aae250bc1910eebf"

func assertApplicationFactCounts(t *testing.T, db *sql.DB, want int) {
	t.Helper()
	tables := []string{
		"applications",
		"environments",
		"operations",
		"task_leases",
		"outbox_events",
		"idempotency_records",
		"audit_evidence",
	}
	for _, tbl := range tables {
		var count int
		if err := db.QueryRow(fmt.Sprintf("SELECT count(*) FROM %s;", tbl)).Scan(&count); err != nil {
			t.Fatalf("count table %s: %v", tbl, err)
		}
		if count != want {
			t.Fatalf("table %s count = %d, want %d", tbl, count, want)
		}
	}
}

func TestMigration0001ChecksumPreserved(t *testing.T) {
	currentChecksum := sha256Hex(authMigrationSQL())
	if currentChecksum != accepted0001Checksum {
		t.Fatalf("0001_admin_auth checksum was altered! got %s, want %s", currentChecksum, accepted0001Checksum)
	}
}

func TestMigrationUpgradeFrom0001AuthFixture(t *testing.T) {
	ctx := context.Background()
	dir := secureTestDir(t, "acornfox_upgrade_fixture")
	dbPath := filepath.Join(dir, "acornfox.db")

	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	nowStr := FormatTime(now)

	// 1. Prepare raw SQLite database with ONLY 0001_admin_auth schema applied
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw sqlite db: %v", err)
	}

	if _, err := rawDB.Exec(ownedSchemaDefinitions[0].sql); err != nil {
		t.Fatalf("create _schema_migrations: %v", err)
	}
	if _, err := rawDB.Exec(authMigrationSQL()); err != nil {
		t.Fatalf("apply authMigrationSQL: %v", err)
	}
	if _, err := rawDB.Exec(`
		INSERT INTO _schema_migrations (version, checksum, applied_at)
		VALUES (?, ?, ?);
	`, version0001_admin_auth, accepted0001Checksum, nowStr); err != nil {
		t.Fatalf("record 0001_admin_auth migration: %v", err)
	}

	// 2. Insert valid admin credential and session into 0001 auth tables
	adminID := domain.ID("admin_fixture_1")
	sessID := domain.ID("sess_fixture_1")
	sessDigest := domain.AuthDigest("1111111111111111111111111111111111111111111111111111111111111111")
	csrfDigest := domain.AuthDigest("2222222222222222222222222222222222222222222222222222222222222222")

	if _, err := rawDB.Exec(`
		INSERT INTO admin_credentials
			(id, password_hash_scheme, password_hash, credential_version, disabled_at, created_at, updated_at)
		VALUES (?, ?, ?, 1, NULL, ?, ?);
	`, adminID.String(), auth.PasswordHashScheme, "$pbkdf2-sha256$i=600000,l=32$c2FsdHNhbHQ$a2V5", nowStr, nowStr); err != nil {
		t.Fatalf("insert fixture admin credential: %v", err)
	}

	if _, err := rawDB.Exec(`
		INSERT INTO admin_sessions
			(id, admin_id, session_digest, csrf_digest, credential_version, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at)
		VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, NULL);
	`, sessID.String(), adminID.String(), sessDigest.String(), csrfDigest.String(), nowStr, nowStr, FormatTime(now.Add(8*time.Hour)), FormatTime(now.Add(24*time.Hour))); err != nil {
		t.Fatalf("insert fixture admin session: %v", err)
	}

	if err := rawDB.Close(); err != nil {
		t.Fatalf("close raw fixture db: %v", err)
	}

	if err := os.Chmod(dbPath, 0600); err != nil {
		t.Fatalf("secure fixture database: %v", err)
	}

	// 3. Open store on existing 0001 auth database: must upgrade to 0002 cleanly
	store, err := Open(Config{DataDirectory: dir})
	if err != nil {
		t.Fatalf("Open store on 0001 fixture failed: %v", err)
	}
	defer store.Close()

	// 4. Verify original auth credential and session remain intact and active
	cred, err := store.ActiveAdminCredential(ctx)
	if err != nil || cred.ID != adminID {
		t.Fatalf("failed to retrieve active admin credential after upgrade: cred=%+v err=%v", cred, err)
	}
	sess, err := store.ActiveAdminSessionByDigest(ctx, sessDigest, now.Add(time.Minute))
	if err != nil || sess.ID != sessID {
		t.Fatalf("failed to retrieve active admin session after upgrade: sess=%+v err=%v", sess, err)
	}

	// 5. Verify _schema_migrations contains both migrations with valid checksums
	rows, err := store.db.QueryContext(ctx, "SELECT version, checksum FROM _schema_migrations ORDER BY version;")
	if err != nil {
		t.Fatalf("query migrations: %v", err)
	}
	defer rows.Close()

	migrationMap := map[string]string{}
	for rows.Next() {
		var v, c string
		if err := rows.Scan(&v, &c); err != nil {
			t.Fatal(err)
		}
		migrationMap[v] = c
	}
	if migrationMap[version0001_admin_auth] != accepted0001Checksum {
		t.Fatalf("0001 checksum mismatch: got %q, want %q", migrationMap[version0001_admin_auth], accepted0001Checksum)
	}
	if migrationMap[version0002_application_repository] != sha256Hex(applicationMigrationSQL()) {
		t.Fatalf("0002 checksum mismatch: got %q, want %q", migrationMap[version0002_application_repository], sha256Hex(applicationMigrationSQL()))
	}

	// 6. Verify application repository functions work on upgraded DB
	controller := application.NewController(store)
	res, err := controller.CreateApplication(ctx, "upgraded-app", "key-upgraded-1")
	if err != nil {
		t.Fatalf("CreateApplication on upgraded DB: %v", err)
	}
	app, err := store.GetApplication(ctx, res.Application.ID)
	if err != nil || app.Name != "upgraded-app" {
		t.Fatalf("GetApplication on upgraded DB: app=%+v err=%v", app, err)
	}

	// 7. Tampered 0001 checksum: use a DIFFERENT valid 64-lowerhex string so the CHECK constraint
	// in _schema_migrations passes, but the migration runner detects the mismatch and returns ErrIncompatibleSchema.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	rawDB2, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	differentValidHexChecksum := "1111111111111111111111111111111111111111111111111111111111111111"
	_, err = rawDB2.Exec("UPDATE _schema_migrations SET checksum = ? WHERE version = ?;", differentValidHexChecksum, version0001_admin_auth)
	_ = rawDB2.Close()
	if err != nil {
		t.Fatal(err)
	}

	_, err = Open(Config{DataDirectory: dir})
	if err == nil || !errors.Is(err, ErrIncompatibleSchema) {
		t.Fatalf("expected ErrIncompatibleSchema on tampered 0001 checksum, got: %v", err)
	}
}

func TestApplicationRepositoryCloseReopenPreservesData(t *testing.T) {
	ctx := context.Background()
	store, dir := newTestSQLiteStore(t)
	controller := application.NewController(store)

	key := "key-reopen-test"
	createRes, err := controller.CreateApplication(ctx, "app-reopen", key)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}

	appID := createRes.Application.ID
	opID := createRes.OperationID
	evtID := createRes.Event.ID
	evtSeq := createRes.Event.Sequence

	// Close store
	if err := store.Close(); err != nil {
		t.Fatalf("store.Close: %v", err)
	}

	// Reopen store from same directory
	reopened, err := Open(Config{DataDirectory: dir})
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()

	// GetApplication
	app, err := reopened.GetApplication(ctx, appID)
	if err != nil {
		t.Fatalf("GetApplication after reopen: %v", err)
	}
	if app.ID != appID || app.Name != "app-reopen" || app.ManagementState != domain.ApplicationManagementActive {
		t.Fatalf("application mismatch: %+v", app)
	}

	// ListApplications
	apps, err := reopened.ListApplications(ctx)
	if err != nil || len(apps) != 1 {
		t.Fatalf("ListApplications after reopen: apps=%+v err=%v", apps, err)
	}
	if apps[0].ID != appID {
		t.Fatalf("ListApplications ID mismatch: %s != %s", apps[0].ID, appID)
	}

	// ListEvents
	events, err := reopened.ListEvents(ctx, application.EventFilter{OperationID: opID.String()})
	if err != nil || len(events) != 1 {
		t.Fatalf("ListEvents after reopen: events=%+v err=%v", events, err)
	}
	if events[0].ID != evtID || events[0].Sequence != evtSeq || events[0].OperationID != opID.String() || events[0].SchemaVersion != "1.1" {
		t.Fatalf("ListEvents mismatch: %+v", events[0])
	}

	// Preflight replay returns identical full result
	digest := applicationNameDigest("app-reopen")
	preflightRes, found, err := reopened.PreflightCreateApplication(ctx, application.CreateApplicationPreflight{
		IdempotencyKey: key,
		RequestDigest:  digest,
	})
	if err != nil || !found {
		t.Fatalf("PreflightCreateApplication replay: found=%v err=%v", found, err)
	}
	if preflightRes.Application.ID != appID ||
		preflightRes.Application.Name != createRes.Application.Name ||
		!preflightRes.Application.CreatedAt.Equal(createRes.Application.CreatedAt) ||
		preflightRes.OperationID != opID ||
		preflightRes.EnvironmentID != createRes.EnvironmentID ||
		preflightRes.Event.ID != evtID ||
		preflightRes.Event.Sequence != evtSeq ||
		preflightRes.Event.Kind != createRes.Event.Kind ||
		preflightRes.Event.Status != createRes.Event.Status ||
		preflightRes.Event.SchemaVersion != createRes.Event.SchemaVersion {
		t.Fatalf("PreflightCreateApplication result mismatch: got %+v, want %+v", preflightRes, createRes)
	}
}

func TestApplicationRepositoryConcurrent20SubmissionsSameKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	store, _ := newTestSQLiteStore(t)
	controller := application.NewController(store)

	key := fmt.Sprintf("concurrent-test-%d", time.Now().UnixNano())

	const clients = 20
	results := make([]application.CreateApplicationResult, clients)
	errorsByClient := make([]error, clients)

	var wg sync.WaitGroup
	wg.Add(clients)
	for i := 0; i < clients; i++ {
		go func(index int) {
			defer wg.Done()
			results[index], errorsByClient[index] = controller.CreateApplication(ctx, "concurrent-app", key)
		}(i)
	}
	wg.Wait()

	for i, err := range errorsByClient {
		if err != nil {
			t.Fatalf("client %d failed: %v", i, err)
		}
		if results[i].Application.ID != results[0].Application.ID ||
			results[i].Application.Name != results[0].Application.Name ||
			results[i].OperationID != results[0].OperationID ||
			results[i].EnvironmentID != results[0].EnvironmentID ||
			results[i].Event.ID != results[0].Event.ID ||
			results[i].Event.Sequence != results[0].Event.Sequence ||
			results[i].Event.SchemaVersion != results[0].Event.SchemaVersion {
			t.Fatalf("client %d got different idempotent replay result: %+v vs %+v", i, results[i], results[0])
		}
	}

	assertApplicationFactCounts(t, store.db, 1)
}

func TestApplicationRepositoryIdempotencyConflict(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestSQLiteStore(t)
	controller := application.NewController(store)

	key := "conflict-key-test"
	_, err := controller.CreateApplication(ctx, "first-app-name", key)
	if err != nil {
		t.Fatalf("first CreateApplication: %v", err)
	}

	// 1. Create with same key but different name -> ErrIdempotencyConflict
	_, err = controller.CreateApplication(ctx, "different-app-name", key)
	if !errors.Is(err, application.ErrIdempotencyConflict) {
		t.Fatalf("expected ErrIdempotencyConflict on create, got: %v", err)
	}

	// 2. Preflight with same key but mismatched digest -> ErrIdempotencyConflict
	_, _, err = store.PreflightCreateApplication(ctx, application.CreateApplicationPreflight{
		IdempotencyKey: key,
		RequestDigest:  "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected ErrIdempotencyConflict on preflight mismatch, got: %v", err)
	}
}

func TestApplicationRepositoryRollbackOnPartialWriteFailure(t *testing.T) {
	for _, table := range []string{"task_leases", "audit_evidence"} {
		t.Run(table, func(t *testing.T) {
			ctx := context.Background()
			store, _ := newTestSQLiteStore(t)
			controller := application.NewController(store)
			if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_insert BEFORE INSERT ON `+table+` BEGIN SELECT RAISE(ABORT,'injected fact insertion failure'); END;`); err != nil {
				t.Fatal(err)
			}
			if _, err := controller.CreateApplication(ctx, "rollback-app", "rollback-key"); err == nil {
				t.Fatal("injected insertion accepted")
			}
			assertApplicationFactCounts(t, store.db, 0)
			if _, err := store.db.ExecContext(ctx, `DROP TRIGGER reject_insert`); err != nil {
				t.Fatal(err)
			}
			result, err := controller.CreateApplication(ctx, "rollback-app", "rollback-key")
			if err != nil {
				t.Fatal(err)
			}
			replay, err := controller.CreateApplication(ctx, "rollback-app", "rollback-key")
			if err != nil || replay.Application.ID != result.Application.ID || replay.Event.ID != result.Event.ID {
				t.Fatalf("retry/replay %+v %v", replay, err)
			}
			assertApplicationFactCounts(t, store.db, 1)
		})
	}
}

func TestApplicationRepositoryExistingInProgressRejection(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestSQLiteStore(t)

	key := "key-existing-in-progress"
	digest := applicationNameDigest("app-in-progress")
	nowStr := FormatTime(time.Now().UTC())

	// Preseed an in_progress idempotency record
	_, err := store.db.ExecContext(ctx, `
		INSERT INTO idempotency_records
			(scope, idempotency_key, request_digest, status, created_at, updated_at)
		VALUES (?, ?, ?, 'in_progress', ?, ?);
	`, createApplicationScope, key, digest, nowStr, nowStr)
	if err != nil {
		t.Fatalf("preseed in_progress row: %v", err)
	}

	// 1. PreflightCreateApplication must return ErrIdempotencyInProgress
	_, found, err := store.PreflightCreateApplication(ctx, application.CreateApplicationPreflight{
		IdempotencyKey: key,
		RequestDigest:  digest,
	})
	if !errors.Is(err, ErrIdempotencyInProgress) || found {
		t.Fatalf("preflight want ErrIdempotencyInProgress, got found=%v err=%v", found, err)
	}

	// 2. CreateApplication must return ErrIdempotencyInProgress and leave no other facts
	app, err := domain.NewApplication("app-in-progress", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	envID, _ := domain.NewID("env")
	opID, _ := domain.NewID("op")
	taskID, _ := domain.NewID("task")

	_, err = store.CreateApplication(ctx, application.CreateApplicationRecord{
		Audit:          applicationcontracts.AuditContext{ActorType: "system", ActorID: "application-controller", Reason: "trusted test command"},
		Application:    app,
		EnvironmentID:  envID,
		OperationID:    opID,
		TaskID:         taskID,
		IdempotencyKey: key,
		RequestDigest:  digest,
		Event: application.Event{
			Kind:   "operation.created",
			Status: "preparing",
		},
	})
	if !errors.Is(err, ErrIdempotencyInProgress) {
		t.Fatalf("create want ErrIdempotencyInProgress, got %v", err)
	}

	// Verify no other facts were written (only the 1 preseeded idempotency record)
	for _, tbl := range []string{"applications", "environments", "operations", "task_leases", "outbox_events"} {
		var count int
		if err := store.db.QueryRow(fmt.Sprintf("SELECT count(*) FROM %s;", tbl)).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("table %s leaked rows: %d", tbl, count)
		}
	}

	// 3. Independent creation with a new key still succeeds
	controller := application.NewController(store)
	freshRes, err := controller.CreateApplication(ctx, "fresh-app", "key-fresh-1")
	if err != nil {
		t.Fatalf("fresh creation failed: %v", err)
	}
	if freshRes.Application.Name != "fresh-app" {
		t.Fatalf("unexpected fresh app name: %s", freshRes.Application.Name)
	}
}

func TestApplicationRepositoryTwoOperationsSequencesAndFilterIsolation(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestSQLiteStore(t)

	// Future input timestamps must still satisfy durable update ordering.
	t1 := time.Now().UTC().Add(time.Hour)
	t2 := t1.Add(10 * time.Minute)

	app1, _ := domain.NewApplication("app-one", t1)
	envID1, _ := domain.NewID("env")
	opID1, _ := domain.NewID("op")
	taskID1, _ := domain.NewID("task")

	res1, err := store.CreateApplication(ctx, application.CreateApplicationRecord{
		Audit:          applicationcontracts.AuditContext{ActorType: "system", ActorID: "application-controller", Reason: "trusted test command"},
		Application:    app1,
		EnvironmentID:  envID1,
		OperationID:    opID1,
		TaskID:         taskID1,
		IdempotencyKey: "key-op-1",
		Event: application.Event{
			SchemaVersion: "1.1",
			OccurredAt:    t1,
			Kind:          "operation.created",
			Status:        "preparing",
		},
	})
	if err != nil {
		t.Fatalf("create app 1: %v", err)
	}
	if res1.Event.Sequence != 1 {
		t.Fatalf("op1 sequence = %d, want 1", res1.Event.Sequence)
	}

	app2, _ := domain.NewApplication("app-two", t2)
	envID2, _ := domain.NewID("env")
	opID2, _ := domain.NewID("op")
	taskID2, _ := domain.NewID("task")

	res2, err := store.CreateApplication(ctx, application.CreateApplicationRecord{
		Audit:          applicationcontracts.AuditContext{ActorType: "system", ActorID: "application-controller", Reason: "trusted test command"},
		Application:    app2,
		EnvironmentID:  envID2,
		OperationID:    opID2,
		TaskID:         taskID2,
		IdempotencyKey: "key-op-2",
		Event: application.Event{
			SchemaVersion: "1.1",
			OccurredAt:    t2,
			Kind:          "operation.created",
			Status:        "preparing",
		},
	})
	if err != nil {
		t.Fatalf("create app 2: %v", err)
	}
	if res2.Event.Sequence != 2 {
		t.Fatalf("op2 sequence = %d, want 2", res2.Event.Sequence)
	}

	// 1. OperationID filter isolation
	evtsOp1, err := store.ListEvents(ctx, application.EventFilter{OperationID: opID1.String()})
	if err != nil || len(evtsOp1) != 1 || evtsOp1[0].ID != res1.Event.ID {
		t.Fatalf("op1 events isolation failed: %+v", evtsOp1)
	}
	evtsOp2, err := store.ListEvents(ctx, application.EventFilter{OperationID: opID2.String()})
	if err != nil || len(evtsOp2) != 1 || evtsOp2[0].ID != res2.Event.ID {
		t.Fatalf("op2 events isolation failed: %+v", evtsOp2)
	}

	// 2. AfterSequence cursor excludes prior events
	evtsAfter1, err := store.ListEvents(ctx, application.EventFilter{AfterSequence: 1})
	if err != nil || len(evtsAfter1) != 1 || evtsAfter1[0].Sequence != 2 {
		t.Fatalf("AfterSequence 1 failed: %+v", evtsAfter1)
	}

	// 3. Since boundary filters
	evtsSinceT1, err := store.ListEvents(ctx, application.EventFilter{Since: t1})
	if err != nil || len(evtsSinceT1) != 2 {
		t.Fatalf("Since t1 want 2 events, got %d", len(evtsSinceT1))
	}
	evtsSinceT2, err := store.ListEvents(ctx, application.EventFilter{Since: t2})
	if err != nil || len(evtsSinceT2) != 1 || evtsSinceT2[0].ID != res2.Event.ID {
		t.Fatalf("Since t2 want 1 event (res2), got %+v", evtsSinceT2)
	}
	evtsSinceFuture, err := store.ListEvents(ctx, application.EventFilter{Since: t2.Add(time.Hour)})
	if err != nil || len(evtsSinceFuture) != 0 {
		t.Fatalf("Since future want 0 events, got %d", len(evtsSinceFuture))
	}

	// 4. Over-limit rejected
	_, err = store.ListEvents(ctx, application.EventFilter{Limit: 10001})
	if err == nil {
		t.Fatal("expected over-limit to be rejected")
	}
}

func TestApplicationRepositoryTableDrivenUnsupportedSourceInputs(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestSQLiteStore(t)

	app, _ := domain.NewApplication("unsupported-app", time.Now().UTC())
	envID, _ := domain.NewID("env")
	opID, _ := domain.NewID("op")
	taskID, _ := domain.NewID("task")

	cases := []struct {
		name                   string
		source                 *application.CreateApplicationSource
		preparedSource         *domain.SourceRevision
		publicSourceProvenance *contracts.AcornFoxPublicSourceProvenance
	}{
		{
			name:   "non_nil_source",
			source: &application.CreateApplicationSource{Kind: application.CreateApplicationSourceUpload, UploadID: domain.ID("upload_1")},
		},
		{
			name:           "non_nil_prepared_source",
			preparedSource: &domain.SourceRevision{ID: domain.ID("rev_1")},
		},
		{
			name:                   "non_nil_public_source_provenance",
			publicSourceProvenance: &contracts.AcornFoxPublicSourceProvenance{SourceRevisionID: domain.ID("rev_1")},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record := application.CreateApplicationRecord{
				Audit:                  applicationcontracts.AuditContext{ActorType: "system", ActorID: "application-controller", Reason: "trusted test command"},
				Application:            app,
				EnvironmentID:          envID,
				OperationID:            opID,
				TaskID:                 taskID,
				IdempotencyKey:         "key-" + tc.name,
				Source:                 tc.source,
				PreparedSource:         tc.preparedSource,
				PublicSourceProvenance: tc.publicSourceProvenance,
				Event: application.Event{
					Kind:   "operation.created",
					Status: "preparing",
				},
			}

			_, err := store.CreateApplication(ctx, record)
			if err == nil {
				t.Fatalf("%s: expected error on unsupported source input", tc.name)
			}
			var domainErr *domain.DomainError
			if !errors.As(err, &domainErr) || domainErr.Code != domain.ErrUnsupportedCapability {
				t.Fatalf("%s: expected ErrUnsupportedCapability, got: %v", tc.name, err)
			}

			assertApplicationFactCounts(t, store.db, 0)
		})
	}

	// Preflight with non-nil source
	_, found, err := store.PreflightCreateApplication(ctx, application.CreateApplicationPreflight{
		IdempotencyKey: "key-preflight-unsupported",
		RequestDigest:  "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		Source:         &application.CreateApplicationSource{Kind: application.CreateApplicationSourceUpload, UploadID: domain.ID("upload_1")},
	})
	if err == nil || found {
		t.Fatal("expected preflight with source to be rejected")
	}
	var preflightDomainErr *domain.DomainError
	if !errors.As(err, &preflightDomainErr) || preflightDomainErr.Code != domain.ErrUnsupportedCapability {
		t.Fatalf("preflight expected ErrUnsupportedCapability, got: %v", err)
	}
}

func TestApplicationRepositoryOutboxRowDecoderCorruptionFailsClosed(t *testing.T) {
	validNow := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	validTimeStr := FormatTime(validNow)
	validPayload := `{"schema_version":"1.0","id":"evt-1","operation_id":"op-1","application_id":"app-1","sequence":1,"kind":"operation.created","status":"preparing"}`

	cases := []struct {
		name string
		row  outboxEventRow
	}{
		{
			name: "invalid_stream_sequence_zero",
			row:  outboxEventRow{id: "evt-1", operationID: "op-1", streamSequence: 0, eventType: "operation.created", payload: validPayload, createdAt: validTimeStr, payloadVersion: "1.0"},
		},
		{
			name: "invalid_stream_sequence_negative",
			row:  outboxEventRow{id: "evt-1", operationID: "op-1", streamSequence: -1, eventType: "operation.created", payload: validPayload, createdAt: validTimeStr, payloadVersion: "1.0"},
		},
		{
			name: "corrupt_timestamp",
			row:  outboxEventRow{id: "evt-1", operationID: "op-1", streamSequence: 1, eventType: "operation.created", payload: validPayload, createdAt: "2026-99-99T99:99:99.000000000Z", payloadVersion: "1.0"},
		},
		{
			name: "corrupt_json_payload",
			row:  outboxEventRow{id: "evt-1", operationID: "op-1", streamSequence: 1, eventType: "operation.created", payload: "not-json-payload", createdAt: validTimeStr, payloadVersion: "1.0"},
		},
		{
			name: "incompatible_payload_version",
			row:  outboxEventRow{id: "evt-1", operationID: "op-1", streamSequence: 1, eventType: "operation.created", payload: validPayload, createdAt: validTimeStr, payloadVersion: "2.0"},
		},
		{
			name: "schema_version_mismatch",
			row:  outboxEventRow{id: "evt-1", operationID: "op-1", streamSequence: 1, eventType: "operation.created", payload: `{"schema_version":"1.1","id":"evt-1","operation_id":"op-1","application_id":"app-1","sequence":1,"kind":"operation.created","status":"preparing"}`, createdAt: validTimeStr, payloadVersion: "1.0"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeOutboxEventRow(tc.row)
			if err == nil || !errors.Is(err, ErrIdempotencyCorrupt) {
				t.Fatalf("%s: expected ErrIdempotencyCorrupt, got: %v", tc.name, err)
			}
		})
	}
}

func TestApplicationRepositoryOutboxTriggerProtectedImmutability(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestSQLiteStore(t)
	controller := application.NewController(store)

	res, err := controller.CreateApplication(ctx, "immutability-app", "key-immutability")
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}

	// 1. Direct UPDATE of payload must be rejected by outbox_events_no_update trigger
	_, err = store.db.ExecContext(ctx, "UPDATE outbox_events SET payload = '{}' WHERE id = ?;", res.Event.ID)
	if err == nil {
		t.Fatal("expected trigger outbox_events_no_update to reject payload modification")
	}

	// 2. Direct DELETE of outbox event must be rejected by outbox_events_no_delete trigger
	_, err = store.db.ExecContext(ctx, "DELETE FROM outbox_events WHERE id = ?;", res.Event.ID)
	if err == nil {
		t.Fatal("expected trigger outbox_events_no_delete to reject delete")
	}

	// 3. Monotonic published_at update succeeds once
	pubTime := FormatTime(time.Now().UTC())
	pubRes, err := store.db.ExecContext(ctx, "UPDATE outbox_events SET published_at = ? WHERE id = ? AND published_at IS NULL;", pubTime, res.Event.ID)
	if err != nil {
		t.Fatalf("monotonic publication update failed: %v", err)
	}
	rowsAff, _ := pubRes.RowsAffected()
	if rowsAff != 1 {
		t.Fatalf("rows affected = %d, want 1", rowsAff)
	}

	// 4. Modifying published_at after it was set must be rejected
	_, err = store.db.ExecContext(ctx, "UPDATE outbox_events SET published_at = ? WHERE id = ?;", FormatTime(time.Now().UTC().Add(time.Hour)), res.Event.ID)
	if err == nil {
		t.Fatal("expected trigger to reject altering already-published marker")
	}
}

func TestApplicationRepositoryDecodeCreateApplicationResultValidation(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	validResult := application.CreateApplicationResult{
		Application: domain.Application{
			ID:              domain.ID("app_valid_1"),
			Name:            "valid-app",
			ManagementState: domain.ApplicationManagementActive,
			CreatedAt:       now,
			UpdatedAt:       now,
		},
		EnvironmentID:    domain.ID("env_valid_1"),
		OperationID:      domain.ID("op_valid_1"),
		SourceRevisionID: "",
		Event: application.Event{
			SchemaVersion: "1.1",
			ID:            "evt-1",
			OperationID:   "op_valid_1",
			ApplicationID: "app_valid_1",
			Sequence:      1,
			OccurredAt:    now,
			Kind:          "operation.created",
			Status:        "preparing",
		},
	}
	validBytes, err := json.Marshal(validResult)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Valid roundtrip decoding and equality
	decoded, err := decodeCreateApplicationResult(validBytes)
	if err != nil {
		t.Fatalf("decode valid result failed: %v", err)
	}
	if decoded.Application.ID != validResult.Application.ID ||
		decoded.Application.Name != validResult.Application.Name ||
		decoded.Application.ManagementState != validResult.Application.ManagementState ||
		!decoded.Application.CreatedAt.Equal(validResult.Application.CreatedAt) ||
		!decoded.Application.UpdatedAt.Equal(validResult.Application.UpdatedAt) ||
		decoded.EnvironmentID != validResult.EnvironmentID ||
		decoded.OperationID != validResult.OperationID ||
		decoded.SourceRevisionID != "" ||
		decoded.Event.ID != validResult.Event.ID ||
		decoded.Event.OperationID != validResult.Event.OperationID ||
		decoded.Event.ApplicationID != validResult.Event.ApplicationID ||
		decoded.Event.Sequence != validResult.Event.Sequence ||
		decoded.Event.Kind != validResult.Event.Kind ||
		decoded.Event.Status != validResult.Event.Status ||
		decoded.Event.SchemaVersion != validResult.Event.SchemaVersion ||
		!decoded.Event.OccurredAt.Equal(validResult.Event.OccurredAt) {
		t.Fatalf("decoded result does not match original: got %+v, want %+v", decoded, validResult)
	}

	// 2. Compact table of durable response validation cases
	corruptCases := []struct {
		valid    bool
		name     string
		mutateFn func(r application.CreateApplicationResult) []byte
	}{
		{
			name: "empty_bytes",
			mutateFn: func(r application.CreateApplicationResult) []byte {
				return []byte("")
			},
		},
		{
			name: "invalid_json",
			mutateFn: func(r application.CreateApplicationResult) []byte {
				return []byte("{not-json}")
			},
		},
		{
			name: "unknown_fields_disallowed",
			mutateFn: func(r application.CreateApplicationResult) []byte {
				return []byte(fmt.Sprintf(`{"unknown_extra_field":"danger",%s`, string(validBytes)[1:]))
			},
		},
		{
			name: "trailing_json_data",
			mutateFn: func(r application.CreateApplicationResult) []byte {
				return append(validBytes, []byte(`{"trailing":true}`)...)
			},
		},
		{
			name:  "trailing_array_close",
			valid: false,
			mutateFn: func(r application.CreateApplicationResult) []byte {
				return append(append([]byte(nil), validBytes...), []byte("]")...)
			},
		},
		{
			name:  "trailing_object_close",
			valid: false,
			mutateFn: func(r application.CreateApplicationResult) []byte {
				return append(append([]byte(nil), validBytes...), []byte("}")...)
			},
		},
		{
			name:  "trailing_invalid_junk",
			valid: false,
			mutateFn: func(r application.CreateApplicationResult) []byte {
				return append(append([]byte(nil), validBytes...), []byte("junk")...)
			},
		},
		{
			name:  "legal_trailing_whitespace",
			valid: true,
			mutateFn: func(r application.CreateApplicationResult) []byte {
				return append(append([]byte(nil), validBytes...), []byte(" \n\t\r")...)
			},
		},
		{
			name: "missing_application_id",
			mutateFn: func(r application.CreateApplicationResult) []byte {
				r.Application.ID = ""
				b, _ := json.Marshal(r)
				return b
			},
		},
		{
			name: "missing_application_name",
			mutateFn: func(r application.CreateApplicationResult) []byte {
				r.Application.Name = ""
				b, _ := json.Marshal(r)
				return b
			},
		},
		{
			name: "missing_environment_id",
			mutateFn: func(r application.CreateApplicationResult) []byte {
				r.EnvironmentID = ""
				b, _ := json.Marshal(r)
				return b
			},
		},
		{
			name: "missing_operation_id",
			mutateFn: func(r application.CreateApplicationResult) []byte {
				r.OperationID = ""
				b, _ := json.Marshal(r)
				return b
			},
		},
		{
			name: "non_empty_source_revision_in_sqlite",
			mutateFn: func(r application.CreateApplicationResult) []byte {
				r.SourceRevisionID = domain.ID("rev_not_allowed_in_sqlite")
				b, _ := json.Marshal(r)
				return b
			},
		},
		{
			name: "empty_event_id",
			mutateFn: func(r application.CreateApplicationResult) []byte {
				r.Event.ID = ""
				b, _ := json.Marshal(r)
				return b
			},
		},
		{
			name: "zero_event_sequence",
			mutateFn: func(r application.CreateApplicationResult) []byte {
				r.Event.Sequence = 0
				b, _ := json.Marshal(r)
				return b
			},
		},
		{
			name: "mismatched_event_application_id",
			mutateFn: func(r application.CreateApplicationResult) []byte {
				r.Event.ApplicationID = "different_app_id"
				b, _ := json.Marshal(r)
				return b
			},
		},
		{
			name: "mismatched_event_operation_id",
			mutateFn: func(r application.CreateApplicationResult) []byte {
				r.Event.OperationID = "different_op_id"
				b, _ := json.Marshal(r)
				return b
			},
		},
		{
			name: "empty_event_kind",
			mutateFn: func(r application.CreateApplicationResult) []byte {
				r.Event.Kind = ""
				b, _ := json.Marshal(r)
				return b
			},
		},
		{
			name: "empty_event_status",
			mutateFn: func(r application.CreateApplicationResult) []byte {
				r.Event.Status = ""
				b, _ := json.Marshal(r)
				return b
			},
		},
		{
			name: "incompatible_schema_version",
			mutateFn: func(r application.CreateApplicationResult) []byte {
				r.Event.SchemaVersion = "2.0"
				b, _ := json.Marshal(r)
				return b
			},
		},
	}

	for _, tc := range corruptCases {
		t.Run(tc.name, func(t *testing.T) {
			corrupted := tc.mutateFn(validResult)
			_, err := decodeCreateApplicationResult(corrupted)
			if tc.valid {
				if err != nil {
					t.Fatalf("%s: expected valid response, got: %v", tc.name, err)
				}
				return
			}
			if err == nil || !errors.Is(err, ErrIdempotencyCorrupt) {
				t.Fatalf("%s: expected ErrIdempotencyCorrupt, got: %v", tc.name, err)
			}
		})
	}
}
