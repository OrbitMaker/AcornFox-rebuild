package install

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type captureRow struct {
	values []any
	err    error
}

func (r captureRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return errors.New("scan shape")
	}
	for i, value := range r.values {
		switch p := dest[i].(type) {
		case *string:
			*p = value.(string)
		case *int64:
			*p = value.(int64)
		case *bool:
			*p = value.(bool)
		case *sql.NullString:
			if value != nil {
				*p = sql.NullString{String: value.(string), Valid: true}
			}
		}
	}
	return nil
}

type captureRows struct {
	values        [][]any
	at            int
	closeErr, err error
	closed        bool
}

func (r *captureRows) Next() bool { return r.at < len(r.values) }
func (r *captureRows) Scan(dest ...any) error {
	err := captureRow{values: r.values[r.at]}.Scan(dest...)
	r.at++
	return err
}
func (r *captureRows) Err() error   { return r.err }
func (r *captureRows) Close() error { r.closed = true; return r.closeErr }

type captureTx struct {
	execs, queries, rowQueries []string
	rows                       func(string) postgresRows
	row                        func(string) postgresRow
	queryErr                   func(string) error
	rollbackErr                error
	rolledBack, committed      bool
	order                      *[]string
}

func (t *captureTx) ExecContext(_ context.Context, query string, _ ...any) (postgresResult, error) {
	t.execs = append(t.execs, query)
	if t.order != nil {
		*t.order = append(*t.order, "exec:"+query)
	}
	return nil, nil
}
func (t *captureTx) QueryContext(_ context.Context, query string, _ ...any) (postgresRows, error) {
	t.queries = append(t.queries, query)
	if t.order != nil {
		*t.order = append(*t.order, "query:"+query)
	}
	if t.queryErr != nil {
		if err := t.queryErr(query); err != nil {
			return nil, err
		}
	}
	return t.rows(query), nil
}
func (t *captureTx) QueryRowContext(_ context.Context, query string, _ ...any) postgresRow {
	t.rowQueries = append(t.rowQueries, query)
	if t.order != nil {
		*t.order = append(*t.order, "row:"+query)
	}
	return t.row(query)
}
func (t *captureTx) Commit() error { t.committed = true; return nil }
func (t *captureTx) Rollback() error {
	t.rolledBack = true
	if t.order != nil {
		*t.order = append(*t.order, "rollback")
	}
	return t.rollbackErr
}

type captureDB struct {
	tx      *captureTx
	options *sql.TxOptions
}

func (d *captureDB) QueryRowContext(context.Context, string, ...any) postgresRow {
	return captureRow{err: errors.New("outside tx")}
}
func (d *captureDB) QueryContext(context.Context, string, ...any) (postgresRows, error) {
	return nil, errors.New("outside tx")
}
func (d *captureDB) ExecContext(context.Context, string, ...any) (postgresResult, error) {
	return nil, errors.New("outside tx")
}
func (d *captureDB) BeginTx(_ context.Context, options *sql.TxOptions) (postgresTx, error) {
	d.options = options
	return d.tx, nil
}
func (d *captureDB) Close() error { return nil }

type orderedPG struct {
	order       *[]string
	result      PostgresRunResult
	write       bool
	sawPrepared bool
	writer      *DurableWriter
}

type removeFaultOps struct{ durableOps }

func (r removeFaultOps) Remove(name string) error {
	if name == platformBackupDumpFile {
		return errors.New("injected remove failure")
	}
	return r.durableOps.Remove(name)
}

func (r *orderedPG) Run(_ context.Context, argv, _ []string) PostgresRunResult {
	if r.order != nil {
		*r.order = append(*r.order, "dump")
	}
	if r.writer != nil {
		r.sawPrepared = preparedPlatformBackupDump(r.writer)
	}
	if r.write {
		_ = os.WriteFile(argv[3], []byte("dump"), 0o600)
	}
	return r.result
}

func compositeFixture(t *testing.T, order *[]string, rollbackErr error, queryErr func(string) error) (*SelectedPostgresDatabase, *PostgresSnapshotter, *captureTx, PlatformBackupDatabaseCaptureRequest) {
	t.Helper()
	chain := "sha256:" + strings.Repeat("a", 64)
	tx := &captureTx{order: order, rollbackErr: rollbackErr, queryErr: queryErr}
	tx.rows = func(query string) postgresRows {
		switch {
		case strings.Contains(query, "FROM (SELECT * FROM public.audit_evidence"):
			return &captureRows{values: [][]any{{`{"sequence":1}`, int64(1), nil, chain}}}
		case query == "SELECT id, key_version, revoked_at IS NOT NULL FROM public.secret_references ORDER BY id", strings.HasPrefix(query, "SELECT id, CASE WHEN platform_domain_id"):
			return &captureRows{}
		case query == "SELECT version, checksum FROM public.schema_migrations ORDER BY version":
			rows := make([][]any, 24)
			for i := range rows {
				rows[i] = []any{fmt.Sprintf("%04d", i+1), fmt.Sprintf("%064x", i+1)}
			}
			return &captureRows{values: rows}
		default:
			return &captureRows{}
		}
	}
	tx.row = func(query string) postgresRow {
		switch query {
		case "SELECT pg_export_snapshot()":
			return captureRow{values: []any{"00000003-0000001B-1"}}
		case "SELECT last_value, is_called FROM public.audit_evidence_sequence_seq":
			return captureRow{values: []any{int64(1), true}}
		case "SELECT last_value, is_called FROM public.outbox_events_stream_sequence":
			return captureRow{values: []any{int64(0), false}}
		case "SELECT current_database()":
			return captureRow{values: []any{"open_card"}}
		default:
			return captureRow{err: errors.New("unexpected row query")}
		}
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, durableDirMode); err != nil {
		t.Fatal(err)
	}
	writer, err := TaskDurableWriter(dir, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	tool := filepath.Join(t.TempDir(), "pg_dump")
	if err := os.WriteFile(tool, []byte("dump"), 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &orderedPG{order: order, write: true, writer: writer}
	snapshotter, err := TaskPostgresSnapshotter(tool, runner)
	if err != nil {
		t.Fatal(err)
	}
	return &SelectedPostgresDatabase{database: &captureDB{tx: tx}}, snapshotter, tx, PlatformBackupDatabaseCaptureRequest{TransactionID: "transaction-1", Writer: writer, Environment: env(t), LocalBackupKey: PlatformBackupKeyReferenceV1{Provider: "local-backup-key", KeyID: "backup-encryption", KeyVersion: "key-v1"}}
}

func TestPlatformBackupSnapshotCapturesFixedReadOnlyFactsAndRollsBack(t *testing.T) {
	chain := "sha256:" + strings.Repeat("a", 64)
	tx := &captureTx{}
	tx.rows = func(query string) postgresRows {
		switch {
		case strings.Contains(query, "FROM (SELECT * FROM public.audit_evidence"):
			return &captureRows{values: [][]any{{`{"sequence":1}`, int64(1), nil, chain}}}
		case query == "SELECT id, key_version, revoked_at IS NOT NULL FROM public.secret_references ORDER BY id", strings.HasPrefix(query, "SELECT id, CASE WHEN platform_domain_id"):
			return &captureRows{}
		case query == "SELECT version, checksum FROM public.schema_migrations ORDER BY version":
			rows := make([][]any, 24)
			for i := range rows {
				rows[i] = []any{fmt.Sprintf("%04d", i+1), fmt.Sprintf("%064x", i+1)}
			}
			return &captureRows{values: rows}
		default:
			return &captureRows{}
		}
	}
	tx.row = func(query string) postgresRow {
		switch query {
		case "SELECT pg_export_snapshot()":
			return captureRow{values: []any{"00000003-0000001B-1"}}
		case "SELECT last_value, is_called FROM public.audit_evidence_sequence_seq":
			return captureRow{values: []any{int64(1), true}}
		case "SELECT last_value, is_called FROM public.outbox_events_stream_sequence":
			return captureRow{values: []any{int64(0), false}}
		case "SELECT current_database()":
			return captureRow{values: []any{"open_card"}}
		default:
			return captureRow{err: errors.New("unexpected row query")}
		}
	}
	db := &captureDB{tx: tx}
	snapshot, err := (&SelectedPostgresDatabase{database: db}).BeginPlatformBackupSnapshot(context.Background())
	if err != nil || db.options == nil || db.options.Isolation != sql.LevelRepeatableRead || !db.options.ReadOnly {
		t.Fatalf("begin: %#v %v", db.options, err)
	}
	wantExec := []string{"SET LOCAL TimeZone TO 'UTC'", "SET LOCAL DateStyle TO 'ISO, YMD'", "SET LOCAL IntervalStyle TO 'iso_8601'", "SET LOCAL bytea_output TO 'hex'", "SET LOCAL extra_float_digits TO '3'", "SET LOCAL search_path TO pg_catalog, public"}
	if !equalStrings(tx.execs, wantExec) {
		t.Fatalf("session=%q", tx.execs)
	}
	facts, err := snapshot.CaptureFacts(context.Background(), PlatformBackupKeyReferenceV1{Provider: "local-backup-key", KeyID: "backup-encryption", KeyVersion: "key-v1"})
	if err != nil {
		t.Fatal(err)
	}
	if facts.DatabaseSnapshotSHA256 != sha256TextFrom("00000003-0000001B-1") || facts.Audit.Table.RowsSHA256 != sha256TextFrom("{\"sequence\":1}\n") || facts.Audit.ChainHead == nil || *facts.Audit.ChainHead != chain || len(facts.Routes.Tables) != len(platformBackupRouteTables) {
		t.Fatalf("facts=%+v", facts)
	}
	if _, err := facts.ReleaseDatabase(); err != nil {
		t.Fatalf("release database: %v", err)
	}
	if len(tx.queries) != len(platformBackupRouteTables)+1+1+3+1+1+1+1 {
		t.Fatalf("query count=%d queries=%q", len(tx.queries), tx.queries)
	}
	if err := snapshot.Commit(); !errors.Is(err, ErrPostgresOutcomeUnknown) || tx.committed {
		t.Fatalf("commit=%v committed=%v", err, tx.committed)
	}
	if err := snapshot.Rollback(); err != nil || !tx.rolledBack {
		t.Fatalf("rollback=%v", err)
	}
}

func TestPlatformBackupSnapshotCapturesPublicAccessAndDNSRecoveryFacts(t *testing.T) {
	database, _, tx, _ := compositeFixture(t, nil, nil, nil)
	baseRows := tx.rows
	const publicCommand = `{"application_id":"app-a","deployment_id":"deployment-a","idempotency_key":"public-enable","phase":"applying"}`
	const dnsExecution = `{"plan_id":"plan-a","change_index":0,"phase":"reconcile_required"}`
	const dnsScope = `{"installation_id":"install-a","provider":"aliyun-dns","zone_id":"zone-a","plan_id":"plan-a","change_index":0,"request_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	tx.rows = func(query string) postgresRows {
		switch {
		case strings.Contains(query, "public.acornfox_public_access_commands"):
			if !strings.Contains(query, "ORDER BY application_id, deployment_id, idempotency_key") {
				return &captureRows{err: errors.New("public-access route facts use an unstable order")}
			}
			return &captureRows{values: [][]any{{publicCommand}}}
		case strings.Contains(query, "public.dns_change_execution_steps"):
			if !strings.Contains(query, "ORDER BY plan_id, change_index") {
				return &captureRows{err: errors.New("DNS execution route facts use an unstable order")}
			}
			return &captureRows{values: [][]any{{dnsExecution}}}
		case strings.Contains(query, "public.dns_change_execution_scopes"):
			if !strings.Contains(query, "ORDER BY installation_id, provider, zone_id") {
				return &captureRows{err: errors.New("DNS execution scope facts use an unstable order")}
			}
			return &captureRows{values: [][]any{{dnsScope}}}
		case strings.Contains(query, "public.dns_change_owned_records"):
			if !strings.Contains(query, "ORDER BY installation_id, owner_key") {
				return &captureRows{err: errors.New("DNS ownership route facts use an unstable order")}
			}
			return baseRows(query)
		default:
			return baseRows(query)
		}
	}
	snapshot, err := database.BeginPlatformBackupSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = snapshot.Rollback() }()
	facts, err := snapshot.CaptureFacts(context.Background(), PlatformBackupKeyReferenceV1{Provider: "local-backup-key", KeyID: "backup-encryption", KeyVersion: "key-v1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(facts.Routes.Tables) != len(platformBackupRouteTables) || !facts.Routes.Tables[0].valid("acornfox_public_access_commands", []string{"application_id", "deployment_id", "idempotency_key"}) || facts.Routes.Tables[0].RowCount != 1 || facts.Routes.Tables[0].RowsSHA256 != sha256TextFrom(publicCommand+"\n") || !facts.Routes.Tables[1].valid("dns_change_execution_steps", []string{"plan_id", "change_index"}) || facts.Routes.Tables[1].RowCount != 1 || facts.Routes.Tables[1].RowsSHA256 != sha256TextFrom(dnsExecution+"\n") || !facts.Routes.Tables[2].valid("dns_change_execution_scopes", []string{"installation_id", "provider", "zone_id"}) || facts.Routes.Tables[2].RowCount != 1 || facts.Routes.Tables[2].RowsSHA256 != sha256TextFrom(dnsScope+"\n") || facts.Routes.Tables[3].Name != "dns_change_owned_records" || !equalStrings(facts.Routes.Tables[3].OrderBy, []string{"installation_id", "owner_key"}) {
		t.Fatalf("route facts = %#v", facts.Routes.Tables)
	}
}

func TestPlatformBackupSnapshotRollbackAndRowsAmbiguityFailClosed(t *testing.T) {
	tx := &captureTx{rollbackErr: errors.New("private failure")}
	tx.row = func(query string) postgresRow {
		if query == "SELECT pg_export_snapshot()" {
			return captureRow{values: []any{"00000003-0000001B-1"}}
		}
		return captureRow{err: errors.New("private")}
	}
	tx.rows = func(string) postgresRows { return &captureRows{closeErr: errors.New("private")} }
	snapshot, err := (&SelectedPostgresDatabase{database: &captureDB{tx: tx}}).BeginPlatformBackupSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Rollback(); !errors.Is(err, ErrPostgresOutcomeUnknown) || strings.Contains(err.Error(), "private") {
		t.Fatalf("rollback=%v", err)
	}
	if snapshot.tx != nil || !snapshot.closed || snapshot.exportedSnapshotID != "" {
		t.Fatalf("rollback ambiguity retained capability: %#v", snapshot)
	}

	tx = &captureTx{}
	tx.row = func(query string) postgresRow {
		if query == "SELECT pg_export_snapshot()" {
			return captureRow{values: []any{"00000003-0000001B-1"}}
		}
		return captureRow{err: errors.New("private")}
	}
	tx.rows = func(string) postgresRows { return &captureRows{closeErr: errors.New("private")} }
	snapshot, err = (&SelectedPostgresDatabase{database: &captureDB{tx: tx}}).BeginPlatformBackupSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = snapshot.CaptureFacts(context.Background(), PlatformBackupKeyReferenceV1{Provider: "local-backup-key", KeyID: "backup-encryption", KeyVersion: "key-v1"})
	if !errors.Is(err, ErrPostgresOutcomeUnknown) || strings.Contains(err.Error(), "private") {
		t.Fatalf("capture=%v", err)
	}
}

func TestSnapshotWithExportedSnapshotRejectsRawIDBeforeRunner(t *testing.T) {
	runner := &fakePG{}
	snapshotter := snap(t, runner)
	_, err := snapshotter.SnapshotWithExportedSnapshot(context.Background(), "transaction-1", t.TempDir(), env(t), "bad raw snapshot", nil)
	if !errors.Is(err, ErrPostgresOutcomeUnknown) || len(runner.argv) != 0 || strings.Contains(err.Error(), "bad raw") {
		t.Fatalf("err=%v argv=%q", err, runner.argv)
	}
}

func TestSnapshotWithExportedSnapshotUsesOnlyFixedArgument(t *testing.T) {
	runner := &fakePG{}
	snapshotter := snap(t, runner)
	dir := t.TempDir()
	runner.write = func(argv []string) { _ = os.WriteFile(argv[3], []byte("dump"), 0o600) }
	_, err := snapshotter.SnapshotWithExportedSnapshot(context.Background(), "transaction-1", dir, env(t), "00000003-0000001B-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{snapshotter.tool, "--format=custom", "--file", filepath.Join(dir, "control-plane.dump"), "--no-owner", "--no-acl", "--snapshot=00000003-0000001B-1"}
	if !equalStrings(runner.argv, want) || strings.Contains(strings.Join(runner.env, "\n"), "00000003-0000001B-1") {
		t.Fatalf("argv=%q env=%q", runner.argv, runner.env)
	}
}

func TestPlatformBackupSnapshotUsesPG16IDAndRedactsFormatting(t *testing.T) {
	if !validPostgresExportedSnapshotID("00000003-0000001B-1") || validPostgresExportedSnapshotID("00000003-0000001b-1") || validPostgresExportedSnapshotID("3:27:1") || validPostgresExportedSnapshotID("00000003-0000001B-0") {
		t.Fatal("exported snapshot validation is not strict")
	}
	snapshot := PlatformBackupSnapshot{exportedSnapshotID: "00000003-0000001B-1", DatabaseSnapshotSHA256: strings.Repeat("a", 64)}
	raw, err := json.Marshal(&snapshot)
	if err != nil || strings.Contains(string(raw), snapshot.exportedSnapshotID) || strings.Contains(fmt.Sprintf("%+v %#v", snapshot, &snapshot), snapshot.exportedSnapshotID) {
		t.Fatalf("snapshot leaked: json=%s format=%+v", raw, snapshot)
	}
}

func TestPlatformBackupSnapshotRejectsRevokedLocalKey(t *testing.T) {
	snapshot := &PlatformBackupSnapshot{tx: &captureTx{}, exportedSnapshotID: "00000003-0000001B-1", DatabaseSnapshotSHA256: strings.Repeat("a", 64)}
	_, err := snapshot.CaptureFacts(context.Background(), PlatformBackupKeyReferenceV1{Provider: "local-backup-key", KeyID: "backup-encryption", KeyVersion: "key-v1", Revoked: true})
	if !errors.Is(err, ErrPostgresOutcomeUnknown) {
		t.Fatalf("err=%v", err)
	}
}

func TestPlatformBackupSnapshotRequiresExactLocalKeyReference(t *testing.T) {
	for _, key := range []PlatformBackupKeyReferenceV1{
		{Provider: "control-plane-secret", KeyID: "backup-encryption", KeyVersion: "key-v1"},
		{Provider: "local-backup-key", KeyID: "backup-key", KeyVersion: "key-v1"},
		{Provider: "local-backup-key", KeyID: "backup-encryption", KeyVersion: "v1"},
	} {
		if validLocalBackupKeyReference(key) {
			t.Fatalf("accepted %#v", key)
		}
	}
	if !validLocalBackupKeyReference(PlatformBackupKeyReferenceV1{Provider: "local-backup-key", KeyID: "backup-encryption", KeyVersion: "key-current"}) {
		t.Fatal("rejected exact local key")
	}
}

func TestPlatformBackupAuditAcceptsSequenceGapsButRejectsBrokenLinks(t *testing.T) {
	firstHash := "sha256:" + strings.Repeat("a", 64)
	lastHash := "sha256:" + strings.Repeat("b", 64)
	makeSnapshot := func(previous any) *PlatformBackupSnapshot {
		tx := &captureTx{}
		tx.rows = func(string) postgresRows {
			return &captureRows{values: [][]any{{`{"sequence":1}`, int64(1), nil, firstHash}, {`{"sequence":3}`, int64(3), previous, lastHash}}}
		}
		tx.row = func(string) postgresRow { return captureRow{values: []any{int64(3), true}} }
		return &PlatformBackupSnapshot{tx: tx, exportedSnapshotID: "00000003-0000001B-1", DatabaseSnapshotSHA256: strings.Repeat("c", 64)}
	}
	if fact, err := makeSnapshot(firstHash).captureAudit(context.Background()); err != nil || fact.LastSequence == nil || *fact.LastSequence != 3 {
		t.Fatalf("gap fact=%+v err=%v", fact, err)
	}
	if _, err := makeSnapshot("sha256:" + strings.Repeat("d", 64)).captureAudit(context.Background()); !errors.Is(err, ErrPostgresOutcomeUnknown) {
		t.Fatalf("broken link err=%v", err)
	}
}

func TestPlatformBackupCaptureRejectsInvalidTLSReferenceAndLegacyMigrations(t *testing.T) {
	tx := &captureTx{}
	tx.rows = func(query string) postgresRows {
		if strings.HasPrefix(query, "SELECT id, CASE WHEN platform_domain_id") {
			return &captureRows{values: [][]any{{"cert-1", "application_domain", "domain-1", "opaque:bad", "example.test", "issuer", "ready", nil, nil, nil}}}
		}
		rows := make([][]any, 23)
		for i := range rows {
			rows[i] = []any{fmt.Sprintf("%04d", i+1), fmt.Sprintf("%064x", i+1)}
		}
		return &captureRows{values: rows}
	}
	snapshot := &PlatformBackupSnapshot{tx: tx, exportedSnapshotID: "00000003-0000001B-1", DatabaseSnapshotSHA256: strings.Repeat("a", 64)}
	if _, err := snapshot.captureTLS(context.Background()); !errors.Is(err, ErrPostgresOutcomeUnknown) {
		t.Fatalf("tls err=%v", err)
	}
	if _, err := snapshot.captureMigrationRows(context.Background()); !errors.Is(err, ErrPostgresOutcomeUnknown) {
		t.Fatalf("legacy migrations err=%v", err)
	}
}

func TestCapturePlatformBackupDatabaseCompositeOrderSuccessAndFailureCleanup(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		order := []string{}
		database, snapshotter, tx, request := compositeFixture(t, &order, nil, nil)
		result, err := CapturePlatformBackupDatabase(context.Background(), database, snapshotter, request)
		if err != nil || !tx.rolledBack || result.DatabaseSnapshotSHA256 == "" || result.DatabaseSnapshotSHA256 != result.Facts.DatabaseSnapshotSHA256 || result.DumpEvidence.Size != 4 {
			t.Fatalf("result=%+v err=%v order=%q", result, err, order)
		}
		if order[0] != "exec:SET LOCAL TimeZone TO 'UTC'" || order[5] != "exec:SET LOCAL search_path TO pg_catalog, public" || order[6] != "row:SELECT pg_export_snapshot()" || order[7] != "dump" || order[len(order)-1] != "rollback" {
			t.Fatalf("order=%q", order)
		}
		if !snapshotter.runner.(*orderedPG).sawPrepared {
			t.Fatal("runner did not receive prepared durable dump")
		}
		if _, err := os.Stat(filepath.Join(request.Writer.rootPath, platformBackupDumpFile)); err != nil {
			t.Fatal(err)
		}
	})
	for _, test := range []struct {
		name        string
		rollbackErr error
		factsFail   bool
		dumpFail    bool
	}{
		{"dump-fail", nil, false, true}, {"facts-fail", nil, true, false}, {"rollback-fail", errors.New("private rollback"), false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			order := []string{}
			queryErr := func(query string) error {
				if test.factsFail && strings.Contains(query, "public.dns_change_owned_records") {
					return errors.New("private facts")
				}
				return nil
			}
			database, snapshotter, tx, request := compositeFixture(t, &order, test.rollbackErr, queryErr)
			runner := snapshotter.runner.(*orderedPG)
			if test.dumpFail {
				runner.result = PostgresRunResult{ExitCode: 1, Err: errors.New("private dump")}
			}
			result, err := CapturePlatformBackupDatabase(context.Background(), database, snapshotter, request)
			if !errors.Is(err, ErrPostgresOutcomeUnknown) || result.DumpEvidence != (SnapshotEvidence{}) || result.DatabaseSnapshotSHA256 != "" || result.Facts.DatabaseSnapshotSHA256 != "" || !tx.rolledBack || strings.Contains(err.Error(), "private") {
				t.Fatalf("result=%+v err=%v order=%q", result, err, order)
			}
			if _, statErr := os.Lstat(filepath.Join(request.Writer.rootPath, platformBackupDumpFile)); !os.IsNotExist(statErr) {
				t.Fatalf("incomplete dump survived: %v", statErr)
			}
		})
	}
}

func TestExportedSnapshotDumpRejectsExistingArtifactBeforeRunner(t *testing.T) {
	runner := &fakePG{}
	snapshotter := snap(t, runner)
	dir := t.TempDir()
	path := filepath.Join(dir, "control-plane.dump")
	if err := os.WriteFile(path, []byte("dump"), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence, err := snapshotEvidence(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotter.SnapshotWithExportedSnapshot(context.Background(), "transaction-1", dir, env(t), "00000003-0000001B-1", &evidence); !errors.Is(err, ErrSnapshotConflict) || len(runner.argv) != 0 {
		t.Fatalf("err=%v argv=%q", err, runner.argv)
	}
}

func TestPlatformBackupCompositeRequiresPinnedWriterAndFreshLeaf(t *testing.T) {
	database, snapshotter, tx, request := compositeFixture(t, nil, nil, nil)
	if err := os.Chmod(request.Writer.rootPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := CapturePlatformBackupDatabase(context.Background(), database, snapshotter, request); !errors.Is(err, ErrPostgresOutcomeUnknown) || tx.rolledBack {
		t.Fatalf("0755 err=%v rollback=%v", err, tx.rolledBack)
	}
	if err := os.Chmod(request.Writer.rootPath, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := request.Writer.CreateMetadata(platformBackupDumpFile, []byte("old")); err != nil {
		t.Fatal(err)
	}
	if _, err := CapturePlatformBackupDatabase(context.Background(), database, snapshotter, request); !errors.Is(err, ErrSnapshotConflict) || tx.rolledBack {
		t.Fatalf("existing err=%v rollback=%v", err, tx.rolledBack)
	}
	if _, err := TaskDurableWriter("relative", os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("relative writer accepted")
	}
	if _, err := TaskDurableWriter(request.Writer.rootPath, os.Getuid()+1, os.Getgid()); err == nil {
		t.Fatal("wrong owner writer accepted")
	}
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(request.Writer.rootPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := TaskDurableWriter(link, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("symlink writer accepted")
	}
}

func TestPlatformBackupCompositeCleanupFaultIsDistinct(t *testing.T) {
	database, snapshotter, _, request := compositeFixture(t, nil, nil, nil)
	request.Writer = &DurableWriter{ops: removeFaultOps{request.Writer.ops}, uid: request.Writer.uid, gid: request.Writer.gid, rootPath: request.Writer.rootPath, rootInfo: request.Writer.rootInfo}
	snapshotter.runner.(*orderedPG).result = PostgresRunResult{ExitCode: 1, Err: errors.New("private dump")}
	_, err := CapturePlatformBackupDatabase(context.Background(), database, snapshotter, request)
	if !errors.Is(err, ErrPlatformBackupCleanupUnknown) || strings.Contains(err.Error(), "private") {
		t.Fatalf("err=%v", err)
	}
}
