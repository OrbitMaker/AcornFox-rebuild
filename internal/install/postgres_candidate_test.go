package install

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type candidateFake struct {
	exists             bool
	evidence           string
	err, execErr       error
	name, sql, comment string
}

func (f *candidateFake) CandidateEvidence(_ context.Context, name string) (bool, string, error) {
	f.name = name
	return f.exists, f.evidence, f.err
}
func (f *candidateFake) CreateCandidate(_ context.Context, name, evidence string) error {
	f.sql = "CREATE DATABASE " + name
	f.comment = candidateDatabaseEvidence(evidence)
	return f.execErr
}

type migrationFake struct {
	rows             []MigrationRow
	rowsErr, execErr error
	sql              string
}

func (f *migrationFake) MigrationRows(context.Context) ([]MigrationRow, error) {
	return f.rows, f.rowsErr
}

type migrationTxFake struct{ parent *migrationFake }

func (t *migrationTxFake) ExecMigration(_ context.Context, sql string) error {
	t.parent.sql = sql
	return t.parent.execErr
}
func (t *migrationTxFake) RecordMigration(_ context.Context, row MigrationRow) error {
	t.parent.rows = append(t.parent.rows, row)
	return nil
}
func (t *migrationTxFake) Commit() error   { return nil }
func (t *migrationTxFake) Rollback() error { return nil }
func (f *migrationFake) BeginMigration(context.Context) (MigrationTx, error) {
	return &migrationTxFake{f}, nil
}
func candidateRequest(id string) CreateCandidateRequest {
	return CreateCandidateRequest{ActivationID: id, RecoveryEvidence: strings.Repeat("a", 64)}
}
func recoveryRequest(id string) CreateCandidateRequest {
	name, _ := CandidateDatabaseName(id)
	return CreateCandidateRequest{ActivationID: id, ExpectedExistingName: name, RecoveryEvidence: strings.Repeat("a", 64)}
}

type validatorFake struct {
	id  string
	err error
}

type adapterRow struct {
	values []any
	err    error
}

func (r adapterRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i := range dest {
		switch p := dest[i].(type) {
		case *bool:
			*p = r.values[i].(bool)
		case *int:
			*p = r.values[i].(int)
		case *string:
			*p = r.values[i].(string)
		}
	}
	return nil
}

type adapterRows struct {
	rows             [][]any
	at               int
	scanErr, rowsErr error
}

func (r *adapterRows) Next() bool { return r.at < len(r.rows) }
func (r *adapterRows) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	err := adapterRow{values: r.rows[r.at]}.Scan(dest...)
	r.at++
	return err
}
func (r *adapterRows) Err() error   { return r.rowsErr }
func (r *adapterRows) Close() error { return nil }

type adapterTx struct {
	execSQL                         string
	args                            []any
	execErr, commitErr, rollbackErr error
	committed, rolledBack           bool
}

func (t *adapterTx) ExecContext(_ context.Context, q string, a ...any) (postgresResult, error) {
	t.execSQL = q
	t.args = a
	return nil, t.execErr
}
func (t *adapterTx) Commit() error   { t.committed = true; return t.commitErr }
func (t *adapterTx) Rollback() error { t.rolledBack = true; return t.rollbackErr }

type adapterDB struct {
	row      postgresRow
	rows     postgresRows
	query    string
	args     []any
	exec     string
	execArgs []any
	execs    []string
	tx       *adapterTx
	closeErr error
}

func (d *adapterDB) QueryRowContext(_ context.Context, q string, a ...any) postgresRow {
	d.query = q
	d.args = a
	return d.row
}
func (d *adapterDB) QueryContext(_ context.Context, q string, a ...any) (postgresRows, error) {
	d.query = q
	d.args = a
	return d.rows, nil
}
func (d *adapterDB) ExecContext(_ context.Context, q string, a ...any) (postgresResult, error) {
	d.exec = q
	d.execArgs = a
	d.execs = append(d.execs, q)
	return nil, nil
}
func (d *adapterDB) BeginTx(context.Context, *sql.TxOptions) (postgresTx, error) { return d.tx, nil }
func (d *adapterDB) Close() error                                                { return d.closeErr }

func (f *validatorFake) ValidateCandidate(_ context.Context, id string) error {
	f.id = id
	return f.err
}

func migrationRows(n int) []MigrationRow {
	rows := make([]MigrationRow, n)
	for i := range rows {
		rows[i] = MigrationRow{Version: fmt.Sprintf("%04d", i+1), Checksum: fmt.Sprintf("%064x", i+1)}
	}
	return rows
}
func migrationDigest(rows []MigrationRow) string {
	h := sha256.New()
	for _, row := range rows {
		_, _ = fmt.Fprintf(h, "%s\t%s\n", row.Version, row.Checksum)
	}
	return hex.EncodeToString(h.Sum(nil))
}

type fakePG struct {
	argv, env []string
	result    PostgresRunResult
	write     func([]string)
}

func (f *fakePG) Run(_ context.Context, a, e []string) PostgresRunResult {
	f.argv, f.env = a, e
	if f.write != nil {
		f.write(a)
	}
	return f.result
}

type sessions struct {
	n   []int
	err error
}

func (s *sessions) CountOpenCardSessions(context.Context) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	v := s.n[0]
	if len(s.n) > 1 {
		s.n = s.n[1:]
	}
	return v, nil
}
func env(t *testing.T) PostgresProcessEnvironment {
	v, e := PostgresEnvironment([]byte("OPEN_CARD_DATABASE_URL=postgresql://us%40er:p%2Fass@127.0.0.1:5432/open_card?sslmode=require\n"))
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func snap(t *testing.T, r *fakePG) *PostgresSnapshotter {
	p := filepath.Join(t.TempDir(), "pg_dump")
	if e := os.WriteFile(p, []byte("x"), 0700); e != nil {
		t.Fatal(e)
	}
	s, e := TaskPostgresSnapshotter(p, r)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestPGEnvAndSessions(t *testing.T) {
	v := env(t)
	if v.Descriptor.Database != "open_card" || strings.Contains(v.Descriptor.Host, "pass") || !strings.Contains(strings.Join(v.ChildEnv, "\n"), "PGPASSWORD=p/ass") {
		t.Fatal(v)
	}
	ctx, c := context.WithTimeout(context.Background(), time.Second)
	defer c()
	x, e := WaitForNoOpenCardSessions(ctx, &sessions{n: []int{1, 0}}, time.Millisecond)
	if e != nil || x.Code != "drained" {
		t.Fatal(e)
	}
	_, e = WaitForNoOpenCardSessions(ctx, &sessions{err: errors.New("secret")}, time.Millisecond)
	if e == nil || strings.Contains(e.Error(), "secret") {
		t.Fatal(e)
	}
}

func TestProductionControlReadsParameterizedCandidateEvidence(t *testing.T) {
	db := &adapterDB{row: adapterRow{values: []any{true, "open-card-upgrade:" + strings.Repeat("a", 64)}}}
	p := &ProductionPostgresControl{admin: db}
	ok, evidence, err := p.CandidateEvidence(context.Background(), "open_card_act_0123456789abcdef")
	if err != nil || !ok || evidence != "open-card-upgrade:"+strings.Repeat("a", 64) || db.query != "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1), COALESCE((SELECT obj_description(oid, 'pg_database') FROM pg_database WHERE datname = $1), '')" || len(db.args) != 1 {
		t.Fatalf("ok=%v evidence=%q err=%v query=%q args=%v", ok, evidence, err, db.query, db.args)
	}
}

func TestProductionControlCreateStoresFixedCandidateEvidence(t *testing.T) {
	db := &adapterDB{}
	p := &ProductionPostgresControl{admin: db}
	evidence := strings.Repeat("a", 64)
	if err := p.CreateCandidate(context.Background(), "open_card_act_0123456789abcdef", evidence); err != nil || len(db.execs) != 2 || db.execs[0] != "CREATE DATABASE open_card_act_0123456789abcdef" || db.execs[1] != "COMMENT ON DATABASE open_card_act_0123456789abcdef IS 'open-card-upgrade:"+evidence+"'" {
		t.Fatalf("err=%v sql=%q all=%q", err, db.exec, db.execs)
	}
	if err := p.CreateCandidate(context.Background(), "bad; DROP DATABASE x", evidence); !errors.Is(err, ErrPostgresOutcomeUnknown) {
		t.Fatalf("err=%v sql=%q", err, db.exec)
	}
}

func TestProductionControlUsesFixedSessionQuery(t *testing.T) {
	db := &adapterDB{row: adapterRow{values: []any{3}}}
	p := &ProductionPostgresControl{admin: db}
	n, err := p.CountOpenCardSessions(context.Background())
	if err != nil || n != 3 || db.query != WaitForNoOpenCardSessionsSQL {
		t.Fatalf("n=%d err=%v query=%q", n, err, db.query)
	}
}

func TestSQLMigrationControlReadsRowsAndUsesParameterizedRecord(t *testing.T) {
	db := &adapterDB{rows: &adapterRows{rows: [][]any{{"0001", "abc"}, {"0002", "def"}}}}
	s := &SQLMigrationControl{database: db}
	rows, err := s.MigrationRows(context.Background())
	if err != nil || len(rows) != 2 || rows[1].Version != "0002" {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	tx := &adapterTx{}
	s.database = &adapterDB{tx: tx}
	mt, err := s.BeginMigration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := mt.RecordMigration(context.Background(), MigrationRow{"0024", "checksum"}); err != nil {
		t.Fatal(err)
	}
	if tx.execSQL != "INSERT INTO schema_migrations(version, checksum) VALUES ($1, $2)" || fmt.Sprint(tx.args) != "[0024 checksum]" {
		t.Fatalf("sql=%q args=%v", tx.execSQL, tx.args)
	}
}

func TestSQLMigrationTransactionPropagatesCommitAndRollback(t *testing.T) {
	tx := &adapterTx{commitErr: errors.New("commit-secret"), rollbackErr: errors.New("rollback-secret")}
	s := &SQLMigrationControl{database: &adapterDB{tx: tx}}
	mt, err := s.BeginMigration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := mt.Commit(); !errors.Is(err, ErrPostgresOutcomeUnknown) || strings.Contains(err.Error(), "secret") || !tx.committed {
		t.Fatalf("err=%v committed=%v", err, tx.committed)
	}
	if err := mt.Rollback(); err == nil || !tx.rolledBack || !strings.Contains(err.Error(), "rollback-secret") {
		t.Fatalf("rollback err=%v rolledBack=%v", err, tx.rolledBack)
	}
}

func TestCreateCandidateUsesDerivedSafeNameAndExactSQL(t *testing.T) {
	f := &candidateFake{}
	name, err := CreateCandidate(context.Background(), f, candidateRequest("activation-1"))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := CandidateDatabaseName("activation-1")
	if name != want || f.name != want || f.sql != "CREATE DATABASE "+want || f.comment != "open-card-upgrade:"+strings.Repeat("a", 64) {
		t.Fatalf("name=%q exists=%q sql=%q comment=%q", name, f.name, f.sql, f.comment)
	}
}

func TestCreateCandidateAllowsExistingOnlyWithExactPersistentEvidence(t *testing.T) {
	f := &candidateFake{exists: true, evidence: candidateDatabaseEvidence(strings.Repeat("a", 64))}
	name, err := CreateCandidate(context.Background(), f, recoveryRequest("activation-1"))
	if err != nil || name == "" || f.sql != "" {
		t.Fatalf("name=%q err=%v sql=%q", name, err, f.sql)
	}
}

func TestCreateCandidateRejectsExistingConflict(t *testing.T) {
	for _, evidence := range []string{"", "open-card-upgrade:" + strings.Repeat("b", 64)} {
		_, err := CreateCandidate(context.Background(), &candidateFake{exists: true, evidence: evidence}, recoveryRequest("activation-1"))
		if !errors.Is(err, ErrCandidateConflict) {
			t.Fatalf("evidence=%q err=%v", evidence, err)
		}
	}
}

func TestCreateCandidateRedactsControlErrors(t *testing.T) {
	_, err := CreateCandidate(context.Background(), &candidateFake{err: errors.New("password-secret")}, candidateRequest("activation-1"))
	if !errors.Is(err, ErrPostgresOutcomeUnknown) || strings.Contains(err.Error(), "password-secret") {
		t.Fatalf("err=%v", err)
	}
	_, err = CreateCandidate(context.Background(), &candidateFake{execErr: errors.New("password-secret")}, candidateRequest("activation-1"))
	if !errors.Is(err, ErrPostgresOutcomeUnknown) || strings.Contains(err.Error(), "password-secret") {
		t.Fatalf("err=%v", err)
	}
}

func TestCreateCandidateRejectsMaliciousActivationBeforeSQL(t *testing.T) {
	f := &candidateFake{}
	if _, err := CreateCandidate(context.Background(), f, candidateRequest("x; DROP DATABASE open_card")); err == nil || f.sql != "" || f.name != "" {
		t.Fatalf("err=%v name=%q sql=%q", err, f.name, f.sql)
	}
}

func TestApplyCandidateMigrationRequiresExactHistory(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows []MigrationRow
	}{
		{"gap", append(migrationRows(1), MigrationRow{Version: "0003", Checksum: "x"})},
		{"duplicate", func() []MigrationRow { r := migrationRows(23); r[1].Version = r[0].Version; return r }()},
		{"checksum drift", func() []MigrationRow { r := migrationRows(23); r[4].Checksum = "drift"; return r }()},
		{"future", append(migrationRows(23), MigrationRow{Version: "0025", Checksum: "x"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ApplyCandidateMigration(context.Background(), &migrationFake{rows: tc.rows}, migrationRows(24), "sql")
			if !errors.Is(err, ErrCandidateConflict) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestApplyCandidateMigrationExecutes0024AndRecordsExactDigest(t *testing.T) {
	rows := migrationRows(23)
	f := &migrationFake{rows: rows}
	expected := migrationRows(24)
	expected[23].Checksum = sha256TextFrom("ALTER TABLE x")
	ev, err := ApplyCandidateMigration(context.Background(), f, expected, "ALTER TABLE x")
	if err != nil || f.sql != "ALTER TABLE x" || ev.From != "0023" || ev.To != "0024" {
		t.Fatalf("ev=%+v sql=%q err=%v", ev, f.sql, err)
	}
	rows = append(rows, MigrationRow{Version: "0024", Checksum: sha256TextFrom("ALTER TABLE x")})
	if ev.RowsSHA256 != migrationDigest(rows) {
		t.Fatalf("digest=%s", ev.RowsSHA256)
	}
}

func TestApplyCandidateMigrationIsIdempotentForExact0024(t *testing.T) {
	rows := migrationRows(24)
	f := &migrationFake{rows: rows}
	_, err := ApplyCandidateMigration(context.Background(), f, migrationRows(24), "sql")
	if err != nil || f.sql != "" {
		t.Fatalf("err=%v sql=%q", err, f.sql)
	}
}

func TestApplyCandidateMigrationRedactsExecutionErrors(t *testing.T) {
	expected := migrationRows(24)
	expected[23].Checksum = sha256TextFrom("sql")
	_, err := ApplyCandidateMigration(context.Background(), &migrationFake{rows: migrationRows(23), execErr: errors.New("password-secret")}, expected, "sql")
	if !errors.Is(err, ErrPostgresOutcomeUnknown) || strings.Contains(err.Error(), "password-secret") {
		t.Fatalf("err=%v", err)
	}
}

func TestValidateCandidatePassesActivationID(t *testing.T) {
	f := &validatorFake{}
	if err := ValidateCandidate(context.Background(), f, "activation-1"); err != nil || f.id != "activation-1" {
		t.Fatalf("id=%q err=%v", f.id, err)
	}
}

func TestValidateCandidateRedactsValidationErrors(t *testing.T) {
	err := ValidateCandidate(context.Background(), &validatorFake{err: errors.New("password-secret")}, "activation-1")
	if err == nil || strings.Contains(err.Error(), "password-secret") {
		t.Fatalf("err=%v", err)
	}
}

func TestRestoreRedactsRunnerFailure(t *testing.T) {
	r := &fakePG{result: PostgresRunResult{ExitCode: 1, Err: errors.New("password-secret")}}
	dir := t.TempDir()
	dump, restore := filepath.Join(dir, "dump-tool"), filepath.Join(dir, "restore-tool")
	_ = os.WriteFile(dump, []byte("dump"), 0700)
	_ = os.WriteFile(restore, []byte("restore"), 0700)
	s, err := TaskPostgresSnapshotterWithRestore(dump, restore, r)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "control-plane.dump")
	_ = os.WriteFile(p, []byte("dump"), 0600)
	ev, _ := snapshotEvidence(p)
	err = s.Restore(context.Background(), "open_card_act_0123456789abcdef", p, ev, env(t))
	if !errors.Is(err, ErrPostgresOutcomeUnknown) || strings.Contains(err.Error(), "password-secret") {
		t.Fatalf("err=%v", err)
	}
}

func TestRestoreReturnsUnknownForNonzeroRunnerOutcome(t *testing.T) {
	r := &fakePG{result: PostgresRunResult{ExitCode: 2}}
	dir := t.TempDir()
	dump, restore := filepath.Join(dir, "dump-tool"), filepath.Join(dir, "restore-tool")
	_ = os.WriteFile(dump, []byte("dump"), 0700)
	_ = os.WriteFile(restore, []byte("restore"), 0700)
	s, err := TaskPostgresSnapshotterWithRestore(dump, restore, r)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "control-plane.dump")
	_ = os.WriteFile(p, []byte("dump"), 0600)
	ev, _ := snapshotEvidence(p)
	if err := s.Restore(context.Background(), "open_card_act_0123456789abcdef", p, ev, env(t)); !errors.Is(err, ErrPostgresOutcomeUnknown) {
		t.Fatalf("err=%v", err)
	}
}

func TestRestoreRejectsSnapshotDigestMismatch(t *testing.T) {
	r := &fakePG{}
	dir := t.TempDir()
	dump, restore := filepath.Join(dir, "dump-tool"), filepath.Join(dir, "restore-tool")
	_ = os.WriteFile(dump, []byte("dump"), 0700)
	_ = os.WriteFile(restore, []byte("restore"), 0700)
	s, _ := TaskPostgresSnapshotterWithRestore(dump, restore, r)
	p := filepath.Join(dir, "control-plane.dump")
	_ = os.WriteFile(p, []byte("dump"), 0600)
	ev, _ := snapshotEvidence(p)
	ev.SHA256 = strings.Repeat("0", 64)
	if err := s.Restore(context.Background(), "open_card_act_0123456789abcdef", p, ev, env(t)); !errors.Is(err, ErrSnapshotConflict) {
		t.Fatalf("err=%v", err)
	}
}

func TestRestoreRejectsSnapshotSymlink(t *testing.T) {
	r := &fakePG{}
	dir := t.TempDir()
	dump, restore := filepath.Join(dir, "dump-tool"), filepath.Join(dir, "restore-tool")
	_ = os.WriteFile(dump, []byte("dump"), 0700)
	_ = os.WriteFile(restore, []byte("restore"), 0700)
	s, _ := TaskPostgresSnapshotterWithRestore(dump, restore, r)
	target := filepath.Join(dir, "target")
	_ = os.WriteFile(target, []byte("dump"), 0600)
	p := filepath.Join(dir, "control-plane.dump")
	_ = os.Symlink(target, p)
	if err := s.Restore(context.Background(), "open_card_act_0123456789abcdef", p, SnapshotEvidence{}, env(t)); !errors.Is(err, ErrSnapshotConflict) {
		t.Fatalf("err=%v", err)
	}
}

func TestPostgresCandidateSourceHasNoDropDatabaseOrDeletionAPI(t *testing.T) {
	b, err := os.ReadFile("postgres_candidate.go")
	if err != nil {
		t.Fatal(err)
	}
	src := strings.ToUpper(string(b))
	if strings.Contains(src, "DROP DATABASE") || strings.Contains(src, "DELETECANDIDATE") || strings.Contains(src, "DROPCANDIDATE") {
		t.Fatal("candidate source exposes deletion")
	}
}
func TestSnapshot(t *testing.T) {
	r := &fakePG{}
	s := snap(t, r)
	d := t.TempDir()
	_ = os.Chmod(d, 0700)
	r.write = func(a []string) { _ = os.WriteFile(a[3], []byte("dump"), 0600) }
	x, e := s.Snapshot(context.Background(), "txn-1", d, env(t), nil)
	if e != nil || x.Size != 4 || r.argv[0] == "postgresql" || strings.Contains(strings.Join(r.argv, " "), "p/ass") {
		t.Fatal(e)
	}
	if _, e = s.Snapshot(context.Background(), "txn-1", d, env(t), nil); !errors.Is(e, ErrSnapshotConflict) {
		t.Fatal(e)
	}
	if _, e = s.Snapshot(context.Background(), "txn-1", d, env(t), &x); e != nil {
		t.Fatal(e)
	}
	r.result = PostgresRunResult{ExitCode: 1, Err: errors.New("secret")}
	d2 := t.TempDir()
	_ = os.Chmod(d2, 0700)
	if _, e = s.Snapshot(context.Background(), "txn-2", d2, env(t), nil); !errors.Is(e, ErrPostgresOutcomeUnknown) || strings.Contains(e.Error(), "secret") {
		t.Fatal(e)
	}
}

func TestRestoreUsesOnlyIndependentlyTrustedPGRestore(t *testing.T) {
	runner := &fakePG{}
	dir := t.TempDir()
	dump, restore := filepath.Join(dir, "pg_dump"), filepath.Join(dir, "pg_restore")
	if err := os.WriteFile(dump, []byte("dump"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(restore, []byte("restore"), 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := TaskPostgresSnapshotterWithRestore(dump, restore, runner)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(dir, "control-plane.dump")
	if err := os.WriteFile(snapshot, []byte("dump"), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence, err := snapshotEvidence(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(context.Background(), "open_card_act_0123456789abcdef", snapshot, evidence, env(t)); err != nil {
		t.Fatal(err)
	}
	if runner.argv[0] != restore || strings.Contains(strings.Join(runner.argv, " "), "postgresql") || !strings.Contains(strings.Join(runner.env, "\n"), "PGPASSWORD=p/ass") {
		t.Fatal("restore argv/env unsafe")
	}
	if err := os.Chmod(snapshot, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(context.Background(), "open_card_act_0123456789abcdef", snapshot, evidence, env(t)); !errors.Is(err, ErrSnapshotConflict) {
		t.Fatal(err)
	}
}
