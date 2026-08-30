package install

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

var candidateDatabaseName = regexp.MustCompile(`^open_card_act_[a-f0-9]{16}$`)
var postgresRoleName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
var ErrPostgresOutcomeUnknown = errors.New("postgres operation outcome is unknown")
var ErrSnapshotConflict = errors.New("snapshot artifact already exists with unknown identity")
var ErrCandidateConflict = errors.New("candidate database conflicts with existing evidence")

const WaitForNoOpenCardSessionsSQL = `SELECT count(*) FROM pg_stat_activity WHERE datname LIKE 'open_card%' AND pid <> pg_backend_pid() AND application_name <> 'open-card-admin'`

type PostgresDescriptor struct{ Host, Port, Database, SSLMode string }
type PostgresProcessEnvironment struct {
	ChildEnv   []string
	Descriptor PostgresDescriptor
}
type SessionDrainResult struct{ Code string }
type SnapshotEvidence struct {
	SHA256 string
	Size   int64
}
type PostgresRunResult struct {
	ExitCode int
	Output   string
	Err      error
}
type PostgresRunner interface {
	Run(context.Context, []string, []string) PostgresRunResult
}
type PostgresSnapshotter struct {
	tool, restoreTool string
	runner            PostgresRunner
}
type SessionCounter interface {
	CountOpenCardSessions(context.Context) (int, error)
}
type CandidateControl interface {
	CandidateEvidence(context.Context, string) (CandidateDatabaseIdentity, error)
	CreateCandidate(context.Context, string, string) error
}
type CandidateDatabaseIdentity struct {
	Exists          bool
	Evidence, Owner string
}
type CreateCandidateRequest struct{ ActivationID, ExpectedExistingName, ExpectedExistingOwner, RecoveryEvidence string }
type CandidateValidator interface {
	ValidateCandidate(context.Context, string) error
}
type MigrationControl interface {
	MigrationRows(context.Context) ([]MigrationRow, error)
	BeginMigration(context.Context) (MigrationTx, error)
}
type MigrationTx interface {
	ExecMigration(context.Context, string) error
	RecordMigration(context.Context, MigrationRow) error
	Commit() error
	Rollback() error
}
type MigrationRow struct{ Version, Checksum string }
type MigrationEvidence struct{ From, To, RowsSHA256 string }

func CreateCandidate(ctx context.Context, control CandidateControl, request CreateCandidateRequest) (string, error) {
	if control == nil || !validSHA(request.RecoveryEvidence) {
		return "", ErrPostgresOutcomeUnknown
	}
	name, err := CandidateDatabaseName(request.ActivationID)
	if err != nil {
		return "", err
	}
	identity, err := control.CandidateEvidence(ctx, name)
	if err != nil {
		return "", ErrPostgresOutcomeUnknown
	}
	if identity.Exists {
		if request.ExpectedExistingName == name && request.ExpectedExistingOwner != "" && identity.Owner == request.ExpectedExistingOwner && identity.Evidence == candidateDatabaseEvidence(request.RecoveryEvidence) {
			return name, nil
		}
		return "", ErrCandidateConflict
	}
	if err := control.CreateCandidate(ctx, name, request.RecoveryEvidence); err != nil {
		return "", ErrPostgresOutcomeUnknown
	}
	return name, nil
}

func candidateDatabaseEvidence(recoveryEvidence string) string {
	return "open-card-upgrade:" + recoveryEvidence
}

// ProductionPostgresControl keeps decoded DSNs private and exposes only safe
// fixed/parameterized candidate operations.
type ProductionPostgresControl struct {
	admin              postgresDB
	runtimeEnv         PostgresProcessEnvironment
	runtimeRole        string
	runtimeBase        *pgx.ConnConfig
	controlRole        string
	controlIdentitySHA string
}

const productionUpgradeDatabaseEnvPath = "/etc/open-card/upgrade-database.env"

// readProductionUpgradeDatabaseEnv is private test indirection only. The
// exported production constructor always reads the fixed root-owned control
// identity and never accepts a caller supplied control path or bytes.
var readProductionUpgradeDatabaseEnv = func() ([]byte, error) {
	return readRootOnlyDatabaseEnv(productionUpgradeDatabaseEnvPath)
}

// SelectedPostgresDatabase is a short-lived connection to exactly the
// database named by database.env. It is deliberately separate from
// ProductionPostgresControl, whose administrative connection is rewritten to
// /postgres for cluster-level candidate operations.
type SelectedPostgresDatabase struct {
	database    postgresDB
	environment PostgresProcessEnvironment
}

// Small database seams keep adapter behavior unit-testable without requiring a
// live PostgreSQL server or a third-party SQL mock package.
type postgresDB interface {
	QueryRowContext(context.Context, string, ...any) postgresRow
	QueryContext(context.Context, string, ...any) (postgresRows, error)
	ExecContext(context.Context, string, ...any) (postgresResult, error)
	BeginTx(context.Context, *sql.TxOptions) (postgresTx, error)
	Close() error
}
type postgresRow interface{ Scan(...any) error }
type postgresRows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close() error
}
type postgresResult interface{}
type postgresTx interface {
	ExecContext(context.Context, string, ...any) (postgresResult, error)
	Commit() error
	Rollback() error
}
type databaseSQL struct{ db *sql.DB }

func (d databaseSQL) QueryRowContext(c context.Context, q string, a ...any) postgresRow {
	return d.db.QueryRowContext(c, q, a...)
}
func (d databaseSQL) QueryContext(c context.Context, q string, a ...any) (postgresRows, error) {
	return d.db.QueryContext(c, q, a...)
}
func (d databaseSQL) ExecContext(c context.Context, q string, a ...any) (postgresResult, error) {
	r, err := d.db.ExecContext(c, q, a...)
	return r, err
}
func (d databaseSQL) BeginTx(c context.Context, o *sql.TxOptions) (postgresTx, error) {
	t, err := d.db.BeginTx(c, o)
	if err != nil {
		return nil, err
	}
	return databaseTx{t}, nil
}
func (d databaseSQL) Close() error { return d.db.Close() }

type databaseTx struct{ tx *sql.Tx }

func (t databaseTx) ExecContext(c context.Context, q string, a ...any) (postgresResult, error) {
	return t.tx.ExecContext(c, q, a...)
}
func (t databaseTx) Commit() error   { return t.tx.Commit() }
func (t databaseTx) Rollback() error { return t.tx.Rollback() }

func NewProductionPostgresControl(runtimeDatabaseEnv []byte) (*ProductionPostgresControl, error) {
	controlDatabaseEnv, err := readProductionUpgradeDatabaseEnv()
	if err != nil {
		return nil, errors.New("invalid upgrade control environment")
	}
	return newPostgresControl(runtimeDatabaseEnv, controlDatabaseEnv)
}

// TaskPostgresControl is an explicit task-only seam. It permits isolated
// PostgreSQL acceptance tests to supply a dedicated control role without
// weakening the fixed production control-env source.
func TaskPostgresControl(runtimeDatabaseEnv, controlDatabaseEnv []byte) (*ProductionPostgresControl, error) {
	return newPostgresControl(runtimeDatabaseEnv, controlDatabaseEnv)
}

func newPostgresControl(runtimeDatabaseEnv, controlDatabaseEnv []byte) (*ProductionPostgresControl, error) {
	runtimeEnv, runtimeBase, err := productionPostgresConfig(runtimeDatabaseEnv)
	if err != nil {
		return nil, errors.New("invalid runtime database environment")
	}
	controlEnv, controlBase, err := productionPostgresConfig(controlDatabaseEnv)
	if err != nil {
		return nil, errors.New("invalid upgrade control environment")
	}
	runtimeRole, err := postgresRole(runtimeDatabaseEnv)
	if err != nil {
		return nil, errors.New("invalid runtime database environment")
	}
	controlRole, err := postgresRole(controlDatabaseEnv)
	if err != nil || controlRole == runtimeRole || controlBase.Database != "postgres" || controlEnv.Descriptor.Host != runtimeEnv.Descriptor.Host || controlEnv.Descriptor.Port != runtimeEnv.Descriptor.Port || controlEnv.Descriptor.SSLMode != runtimeEnv.Descriptor.SSLMode {
		return nil, errors.New("invalid upgrade control environment")
	}
	// PostgreSQL forbids CREATE DATABASE inside the extended-protocol implicit
	// transaction used by database/sql. The fixed cluster-control connection
	// therefore uses pgx simple protocol only for its vetted statements.
	controlBase.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	db := stdlib.OpenDB(*controlBase)
	if db == nil {
		return nil, errors.New("open postgres control failed")
	}
	digest := sha256.Sum256(controlDatabaseEnv)
	return &ProductionPostgresControl{admin: databaseSQL{db}, runtimeEnv: runtimeEnv, runtimeRole: runtimeRole, runtimeBase: runtimeBase, controlRole: controlRole, controlIdentitySHA: hex.EncodeToString(digest[:])}, nil
}

func NewSelectedPostgresDatabase(databaseEnv []byte) (*SelectedPostgresDatabase, error) {
	environment, config, err := productionPostgresConfig(databaseEnv)
	if err != nil || config.Database != environment.Descriptor.Database {
		return nil, errors.New("invalid database environment")
	}
	database := stdlib.OpenDB(*config)
	if database == nil {
		return nil, errors.New("open selected database failed")
	}
	return &SelectedPostgresDatabase{database: databaseSQL{database}, environment: environment}, nil
}

// productionPostgresConfig makes the validated database.env the sole source
// of connection identity. libpq-style PG* environment defaults are rejected
// rather than inherited, so a process-level credential or service profile
// cannot silently redirect an upgrade connection.
func productionPostgresConfig(databaseEnv []byte) (PostgresProcessEnvironment, *pgx.ConnConfig, error) {
	if hasAmbientPostgresEnvironment() {
		return PostgresProcessEnvironment{}, nil, errors.New("ambient postgres environment is forbidden")
	}
	environment, err := PostgresEnvironment(databaseEnv)
	if err != nil {
		return PostgresProcessEnvironment{}, nil, errors.New("invalid database environment")
	}
	dsn, err := ParseDatabaseEnv(databaseEnv)
	if err != nil {
		return PostgresProcessEnvironment{}, nil, errors.New("invalid database environment")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil || config.Database != environment.Descriptor.Database || config.Host != environment.Descriptor.Host {
		return PostgresProcessEnvironment{}, nil, errors.New("invalid database environment")
	}
	return environment, config, nil
}

func hasAmbientPostgresEnvironment() bool {
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if ok && strings.HasPrefix(key, "PG") && value != "" {
			return true
		}
	}
	return false
}

func (s *SelectedPostgresDatabase) Close() error {
	if s == nil || s.database == nil {
		return nil
	}
	database := s.database
	s.database = nil
	return database.Close()
}

func (s *SelectedPostgresDatabase) MigrationRows(ctx context.Context) ([]MigrationRow, error) {
	if s == nil || s.database == nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	return (&SQLMigrationControl{database: s.database}).MigrationRows(ctx)
}
func (p *ProductionPostgresControl) Close() error {
	if p == nil || p.admin == nil {
		return nil
	}
	admin := p.admin
	p.admin = nil
	return admin.Close()
}

// ControlIdentitySHA256 exposes only the digest of the exact control-env
// bytes. It is suitable for a journal/audit binding and never exposes the
// control DSN or password.
func (p *ProductionPostgresControl) ControlIdentitySHA256() string {
	if p == nil || !validSHA(p.controlIdentitySHA) {
		return ""
	}
	return p.controlIdentitySHA
}
func (p *ProductionPostgresControl) CandidateEvidence(ctx context.Context, name string) (CandidateDatabaseIdentity, error) {
	if p == nil || !candidateDatabaseName.MatchString(name) {
		return CandidateDatabaseIdentity{}, ErrPostgresOutcomeUnknown
	}
	var identity CandidateDatabaseIdentity
	err := p.admin.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1), COALESCE((SELECT shobj_description(oid, 'pg_database') FROM pg_database WHERE datname = $1), ''), COALESCE((SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = $1), '')", name).Scan(&identity.Exists, &identity.Evidence, &identity.Owner)
	if err != nil {
		return CandidateDatabaseIdentity{}, ErrPostgresOutcomeUnknown
	}
	return identity, nil
}
func (p *ProductionPostgresControl) CreateCandidate(ctx context.Context, name, recoveryEvidence string) error {
	if p == nil || !candidateDatabaseName.MatchString(name) || !validSHA(recoveryEvidence) || !postgresRoleName.MatchString(p.runtimeRole) {
		return ErrPostgresOutcomeUnknown
	}
	if _, err := p.admin.ExecContext(ctx, "CREATE DATABASE "+name+" OWNER "+p.runtimeRole); err != nil {
		return ErrPostgresOutcomeUnknown
	}
	if _, err := p.admin.ExecContext(ctx, "COMMENT ON DATABASE "+name+" IS '"+candidateDatabaseEvidence(recoveryEvidence)+"'"); err != nil {
		return ErrPostgresOutcomeUnknown
	}
	identity, err := p.CandidateEvidence(ctx, name)
	if err != nil {
		return ErrPostgresOutcomeUnknown
	}
	if !identity.Exists || identity.Owner != p.runtimeRole || identity.Evidence != candidateDatabaseEvidence(recoveryEvidence) {
		return ErrPostgresOutcomeUnknown
	}
	return nil
}
func (p *ProductionPostgresControl) CountOpenCardSessions(ctx context.Context) (int, error) {
	var count int
	err := p.admin.QueryRowContext(ctx, WaitForNoOpenCardSessionsSQL).Scan(&count)
	if err != nil {
		return 0, ErrPostgresOutcomeUnknown
	}
	return count, nil
}
func (p *ProductionPostgresControl) ForCandidate(name string) (*SQLMigrationControl, error) {
	if p == nil || p.runtimeBase == nil || !candidateDatabaseName.MatchString(name) || hasAmbientPostgresEnvironment() {
		return nil, ErrPostgresOutcomeUnknown
	}
	config := *p.runtimeBase
	config.Database = name
	db := stdlib.OpenDB(config)
	if db == nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	return &SQLMigrationControl{databaseSQL{db}}, nil
}

func postgresRole(raw []byte) (string, error) {
	dsn, err := ParseDatabaseEnv(raw)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(dsn)
	if err != nil || u.User == nil || !postgresRoleName.MatchString(u.User.Username()) {
		return "", errors.New("invalid postgres role")
	}
	return u.User.Username(), nil
}

func readRootOnlyDatabaseEnv(path string) ([]byte, error) {
	if path != productionUpgradeDatabaseEnvPath {
		return nil, errors.New("invalid upgrade control environment")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("invalid upgrade control environment")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("invalid upgrade control environment")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("invalid upgrade control environment")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 {
		return nil, errors.New("invalid upgrade control environment")
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, errors.New("invalid upgrade control environment")
	}
	if _, err := ParseDatabaseEnv(raw); err != nil {
		return nil, errors.New("invalid upgrade control environment")
	}
	return raw, nil
}

type SQLMigrationControl struct{ database postgresDB }

func (s *SQLMigrationControl) Close() error {
	if s == nil || s.database == nil {
		return nil
	}
	database := s.database
	s.database = nil
	return database.Close()
}
func (s *SQLMigrationControl) MigrationRows(ctx context.Context) ([]MigrationRow, error) {
	rows, err := s.database.QueryContext(ctx, "SELECT version, checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	defer rows.Close()
	out := []MigrationRow{}
	for rows.Next() {
		var r MigrationRow
		if err := rows.Scan(&r.Version, &r.Checksum); err != nil {
			return nil, ErrPostgresOutcomeUnknown
		}
		out = append(out, r)
	}
	if rows.Err() != nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	return out, nil
}
func (s *SQLMigrationControl) BeginMigration(ctx context.Context) (MigrationTx, error) {
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	return &sqlMigrationTx{tx}, nil
}

type sqlMigrationTx struct{ tx postgresTx }

func (t *sqlMigrationTx) ExecMigration(ctx context.Context, sqlText string) error {
	_, err := t.tx.ExecContext(ctx, sqlText)
	if err != nil {
		return ErrPostgresOutcomeUnknown
	}
	return nil
}
func (t *sqlMigrationTx) RecordMigration(ctx context.Context, row MigrationRow) error {
	_, err := t.tx.ExecContext(ctx, "INSERT INTO schema_migrations(version, checksum) VALUES ($1, $2)", row.Version, row.Checksum)
	if err != nil {
		return ErrPostgresOutcomeUnknown
	}
	return nil
}
func (t *sqlMigrationTx) Commit() error {
	if err := t.tx.Commit(); err != nil {
		return ErrPostgresOutcomeUnknown
	}
	return nil
}
func (t *sqlMigrationTx) Rollback() error { return t.tx.Rollback() }

func (s *PostgresSnapshotter) Restore(ctx context.Context, candidate string, snapshot string, expected SnapshotEvidence, env PostgresProcessEnvironment) error {
	if s == nil || s.runner == nil || !candidateDatabaseName.MatchString(candidate) || !validProcessEnv(env) {
		return ErrPostgresOutcomeUnknown
	}
	actual, err := snapshotEvidence(snapshot)
	if err != nil || actual != expected {
		return ErrSnapshotConflict
	}
	if s.restoreTool == "" {
		return ErrPostgresOutcomeUnknown
	}
	result := s.runner.Run(ctx, []string{s.restoreTool, "--exit-on-error", "--single-transaction", "--no-owner", "--no-acl", "--dbname", candidate, snapshot}, append([]string(nil), env.ChildEnv...))
	if result.Err != nil || result.ExitCode != 0 {
		return fmt.Errorf("%w: pg_restore", ErrPostgresOutcomeUnknown)
	}
	return nil
}

func ApplyCandidateMigration(ctx context.Context, typed MigrationControl, expected []MigrationRow, migrationSQL string) (MigrationEvidence, error) {
	if typed == nil || migrationSQL == "" || !validMigrationRows(expected, 24) {
		return MigrationEvidence{}, ErrPostgresOutcomeUnknown
	}
	rows, err := typed.MigrationRows(ctx)
	if err != nil {
		return MigrationEvidence{}, ErrPostgresOutcomeUnknown
	}
	if len(rows) != 23 && len(rows) != 24 || !matchesExpected(rows, expected[:len(rows)]) {
		return MigrationEvidence{}, ErrCandidateConflict
	}
	if len(rows) == 23 {
		tx, err := typed.BeginMigration(ctx)
		if err != nil {
			return MigrationEvidence{}, ErrPostgresOutcomeUnknown
		}
		defer tx.Rollback()
		if err := tx.ExecMigration(ctx, migrationSQL); err != nil {
			return MigrationEvidence{}, ErrPostgresOutcomeUnknown
		}
		if err := tx.RecordMigration(ctx, expected[23]); err != nil {
			return MigrationEvidence{}, ErrPostgresOutcomeUnknown
		}
		if err := tx.Commit(); err != nil {
			return MigrationEvidence{}, ErrPostgresOutcomeUnknown
		}
		rows, err = typed.MigrationRows(ctx)
		if err != nil || !matchesExpected(rows, expected) {
			return MigrationEvidence{}, ErrPostgresOutcomeUnknown
		}
	}
	return migrationEvidence(rows)
}
func migrationEvidence(rows []MigrationRow) (MigrationEvidence, error) {
	hash := sha256.New()
	for _, row := range rows {
		_, _ = fmt.Fprintf(hash, "%s\t%s\n", row.Version, row.Checksum)
	}
	return MigrationEvidence{From: "0023", To: "0024", RowsSHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}
func validMigrationRows(rows []MigrationRow, length int) bool {
	if len(rows) != length {
		return false
	}
	seen := map[string]bool{}
	for i, row := range rows {
		if len(row.Version) < 4 || row.Version[:4] != fmt.Sprintf("%04d", i+1) || !lowercaseHex(row.Checksum, 64) || seen[row.Version] {
			return false
		}
		seen[row.Version] = true
	}
	return true
}
func matchesExpected(actual, expected []MigrationRow) bool {
	if len(actual) != len(expected) {
		return false
	}
	for i := range actual {
		if actual[i] != expected[i] {
			return false
		}
	}
	return true
}
func lowercaseHex(value string, length int) bool {
	return len(value) == length && regexp.MustCompile(`^[a-f0-9]+$`).MatchString(value)
}
func ValidateCandidate(ctx context.Context, validator CandidateValidator, activationID string) error {
	if validator == nil || !validID(activationID) {
		return ErrPostgresOutcomeUnknown
	}
	if err := validator.ValidateCandidate(ctx, activationID); err != nil {
		return errors.New("candidate validation failed")
	}
	return nil
}
func validProcessEnv(value PostgresProcessEnvironment) bool {
	return value.Descriptor.Host != "" && value.Descriptor.Database != "" && len(value.ChildEnv) >= 5 && strings.HasPrefix(value.ChildEnv[3], "PGPASSWORD=")
}
func sha256TextFrom(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func CandidateDatabaseName(id string) (string, error) {
	if !validID(id) {
		return "", errors.New("invalid activation id")
	}
	d := sha256.Sum256([]byte(id))
	n := "open_card_act_" + hex.EncodeToString(d[:8])
	if !candidateDatabaseName.MatchString(n) {
		return "", errors.New("invalid candidate database name")
	}
	return n, nil
}
func PostgresEnvironment(raw []byte) (PostgresProcessEnvironment, error) {
	dsn, err := ParseDatabaseEnv(raw)
	if err != nil {
		return PostgresProcessEnvironment{}, errors.New("invalid database environment")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.User == nil || u.Hostname() == "" {
		return PostgresProcessEnvironment{}, errors.New("invalid database environment")
	}
	pass, ok := u.User.Password()
	if !ok {
		return PostgresProcessEnvironment{}, errors.New("invalid database environment")
	}
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	db := strings.Trim(u.EscapedPath(), "/")
	mode := u.Query().Get("sslmode")
	if db == "" || mode != "" && mode != "disable" && mode != "require" && mode != "verify-ca" && mode != "verify-full" {
		return PostgresProcessEnvironment{}, errors.New("invalid database environment")
	}
	env := []string{"PGHOST=" + u.Hostname(), "PGPORT=" + port, "PGUSER=" + u.User.Username(), "PGPASSWORD=" + pass, "PGDATABASE=" + db}
	if mode != "" {
		env = append(env, "PGSSLMODE="+mode)
	}
	return PostgresProcessEnvironment{env, PostgresDescriptor{u.Hostname(), port, db, mode}}, nil
}
func WaitForNoOpenCardSessions(ctx context.Context, c SessionCounter, interval time.Duration) (SessionDrainResult, error) {
	if c == nil || interval <= 0 {
		return SessionDrainResult{"invalid"}, errors.New("session drain dependencies are invalid")
	}
	for {
		n, e := c.CountOpenCardSessions(ctx)
		if e != nil {
			return SessionDrainResult{"query_failed"}, errors.New("session drain query failed")
		}
		if n == 0 {
			return SessionDrainResult{"drained"}, nil
		}
		select {
		case <-ctx.Done():
			return SessionDrainResult{"timeout"}, errors.New("session drain timed out")
		case <-time.After(interval):
		}
	}
}
func ProductionPostgresSnapshotter() (*PostgresSnapshotter, error) {
	return newSnapshotter("/usr/bin/pg_dump", "/usr/bin/pg_restore", nil, true)
}
func TaskPostgresSnapshotter(tool string, r PostgresRunner) (*PostgresSnapshotter, error) {
	return newSnapshotter(tool, "", r, false)
}
func TaskPostgresSnapshotterWithRestore(dumpTool, restoreTool string, r PostgresRunner) (*PostgresSnapshotter, error) {
	return newSnapshotter(dumpTool, restoreTool, r, false)
}
func newSnapshotter(tool, restoreTool string, r PostgresRunner, prod bool) (*PostgresSnapshotter, error) {
	i, e := os.Lstat(tool)
	if e != nil || !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("pg_dump tool is unsafe")
	}
	if prod {
		st, ok := i.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return nil, errors.New("pg_dump tool is unsafe")
		}
	}
	if restoreTool != "" {
		ri, re := os.Lstat(restoreTool)
		if re != nil || !ri.Mode().IsRegular() || ri.Mode()&os.ModeSymlink != 0 || ri.Mode().Perm()&0o022 != 0 {
			return nil, errors.New("pg_restore tool is unsafe")
		}
		if prod {
			st, ok := ri.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != 0 {
				return nil, errors.New("pg_restore tool is unsafe")
			}
		}
	}
	if !prod && r == nil {
		return nil, errors.New("task pg_dump runner is required")
	}
	return &PostgresSnapshotter{tool, restoreTool, r}, nil
}
func (s *PostgresSnapshotter) Snapshot(ctx context.Context, tx, dir string, env PostgresProcessEnvironment, expect *SnapshotEvidence) (SnapshotEvidence, error) {
	i, e := os.Lstat(dir)
	if s == nil || s.runner == nil || !validID(tx) || e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm()&0o022 != 0 || len(env.ChildEnv) < 5 {
		return SnapshotEvidence{}, ErrPostgresOutcomeUnknown
	}
	p := filepath.Join(dir, "control-plane.dump")
	if _, e = os.Lstat(p); e == nil {
		x, e := snapshotEvidence(p)
		if e != nil || expect == nil || x != *expect {
			return SnapshotEvidence{}, ErrSnapshotConflict
		}
		return x, nil
	}
	// pg_dump has no --exit-on-error option (unlike pg_restore).  A non-zero
	// process result is already a fail-closed snapshot outcome.
	res := s.runner.Run(ctx, []string{s.tool, "--format=custom", "--file", p, "--no-owner", "--no-acl"}, append([]string(nil), env.ChildEnv...))
	if res.Err != nil || res.ExitCode != 0 {
		return SnapshotEvidence{}, fmt.Errorf("%w: pg_dump", ErrPostgresOutcomeUnknown)
	}
	if e = os.Chmod(p, 0o600); e != nil {
		return SnapshotEvidence{}, fmt.Errorf("%w: snapshot permissions", ErrPostgresOutcomeUnknown)
	}
	x, e := snapshotEvidence(p)
	if e != nil {
		return SnapshotEvidence{}, fmt.Errorf("%w: snapshot verification", ErrPostgresOutcomeUnknown)
	}
	return x, nil
}
func snapshotEvidence(p string) (SnapshotEvidence, error) {
	i, e := os.Lstat(p)
	if e != nil || !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm() != 0o600 || i.Size() < 1 {
		return SnapshotEvidence{}, errors.New("snapshot unsafe")
	}
	b, e := os.ReadFile(p)
	if e != nil {
		return SnapshotEvidence{}, e
	}
	d := sha256.Sum256(b)
	return SnapshotEvidence{hex.EncodeToString(d[:]), i.Size()}, nil
}
