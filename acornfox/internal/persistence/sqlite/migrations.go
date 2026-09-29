package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	version0001_admin_auth = "0001_admin_auth"
)

var (
	ErrIncompatibleSchema = errors.New("incompatible sqlite schema")
	ErrCorruptData        = errors.New("corrupt sqlite data")
)

const TimeLayout = "2006-01-02T15:04:05.000000000Z"
const timePattern = "[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z"

func FormatTime(t time.Time) string {
	return t.UTC().Format(TimeLayout)
}

func ParseTime(s string) (time.Time, error) {
	if len(s) != 30 || s[29] != 'Z' || s[10] != 'T' || s[19] != '.' {
		return time.Time{}, fmt.Errorf("invalid non-canonical sqlite timestamp %q: must match %s", s, TimeLayout)
	}
	t, err := time.Parse(TimeLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse canonical sqlite timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}

type schemaObjectDef struct {
	name string
	sql  string
}

// Single authoritative definition for each owned table and index.
// Used both for migration execution and structural schema fingerprinting.
var ownedSchemaDefinitions = []schemaObjectDef{
	{
		name: "_schema_migrations",
		sql: `CREATE TABLE IF NOT EXISTS _schema_migrations (
    version TEXT PRIMARY KEY NOT NULL,
    checksum TEXT NOT NULL,
    applied_at TEXT NOT NULL,
    CHECK (length(version) > 0),
    CHECK (length(checksum) = 64 AND checksum NOT GLOB '*[^0-9a-f]*'),
    CHECK (applied_at GLOB '` + timePattern + `')
);`,
	},
	{
		name: "admin_credentials",
		sql: `CREATE TABLE IF NOT EXISTS admin_credentials (
    id TEXT PRIMARY KEY NOT NULL,
    password_hash_scheme TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    credential_version INTEGER NOT NULL DEFAULT 1,
    disabled_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (length(trim(id)) > 0),
    CHECK (password_hash_scheme NOT GLOB '*[^a-z0-9._-]*' AND password_hash_scheme GLOB '[a-z0-9]*' AND rtrim(password_hash_scheme, '0123456789') GLOB '*-v' AND (length(rtrim(password_hash_scheme, '0123456789')) - 2) BETWEEN 1 AND 56 AND substr(password_hash_scheme, length(rtrim(password_hash_scheme, '0123456789')) + 1, 1) GLOB '[1-9]'),
    CHECK (length(password_hash) <= 4096 AND substr(password_hash, 1, 1) = '$' AND instr(substr(password_hash, 2), '$') BETWEEN 2 AND 129 AND substr(password_hash, 2, 1) GLOB '[A-Za-z0-9]' AND substr(password_hash, 2, instr(substr(password_hash, 2), '$') - 1) NOT GLOB '*[^A-Za-z0-9._=-]*' AND length(substr(password_hash, 2 + instr(substr(password_hash, 2), '$'))) > 0 AND instr(password_hash, char(9)) = 0 AND instr(password_hash, char(10)) = 0 AND instr(password_hash, char(11)) = 0 AND instr(password_hash, char(12)) = 0 AND instr(password_hash, char(13)) = 0 AND instr(password_hash, char(32)) = 0),
    CHECK (credential_version > 0),
    CHECK (updated_at >= created_at),
    CHECK (disabled_at IS NULL OR disabled_at >= created_at),
    CHECK (created_at GLOB '` + timePattern + `'),
    CHECK (updated_at GLOB '` + timePattern + `'),
    CHECK (disabled_at IS NULL OR disabled_at GLOB '` + timePattern + `')
);`,
	},
	{
		name: "admin_credentials_one_enabled_idx",
		sql: `CREATE UNIQUE INDEX IF NOT EXISTS admin_credentials_one_enabled_idx
    ON admin_credentials ((1))
    WHERE disabled_at IS NULL;`,
	},
	{
		name: "admin_sessions",
		sql: `CREATE TABLE IF NOT EXISTS admin_sessions (
    id TEXT PRIMARY KEY NOT NULL,
    admin_id TEXT NOT NULL REFERENCES admin_credentials(id) ON DELETE RESTRICT,
    session_digest TEXT NOT NULL UNIQUE,
    csrf_digest TEXT NOT NULL UNIQUE,
    credential_version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    idle_expires_at TEXT NOT NULL,
    absolute_expires_at TEXT NOT NULL,
    revoked_at TEXT,
    CHECK (length(session_digest) = 64 AND session_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(csrf_digest) = 64 AND csrf_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (session_digest <> csrf_digest),
    CHECK (credential_version > 0),
    CHECK (last_seen_at >= created_at AND last_seen_at <= absolute_expires_at),
    CHECK (created_at GLOB '` + timePattern + `'),
    CHECK (last_seen_at GLOB '` + timePattern + `'),
    CHECK (idle_expires_at GLOB '` + timePattern + `'),
    CHECK (absolute_expires_at GLOB '` + timePattern + `'),
    CHECK (revoked_at IS NULL OR (revoked_at GLOB '` + timePattern + `' AND revoked_at >= created_at)),
    CHECK (strftime('%Y-%m-%dT%H:%M:%S', substr(created_at, 1, 19) || 'Z', '+24 hours') IS NOT NULL AND absolute_expires_at = strftime('%Y-%m-%dT%H:%M:%S', substr(created_at, 1, 19) || 'Z', '+24 hours') || substr(created_at, 20)),
    CHECK (strftime('%Y-%m-%dT%H:%M:%S', substr(last_seen_at, 1, 19) || 'Z', '+8 hours') IS NOT NULL AND idle_expires_at <= absolute_expires_at AND idle_expires_at = min(strftime('%Y-%m-%dT%H:%M:%S', substr(last_seen_at, 1, 19) || 'Z', '+8 hours') || substr(last_seen_at, 20), absolute_expires_at))
);`,
	},
	{
		name: "admin_sessions_active_lookup_idx",
		sql: `CREATE INDEX IF NOT EXISTS admin_sessions_active_lookup_idx
    ON admin_sessions (session_digest, idle_expires_at, absolute_expires_at)
    WHERE revoked_at IS NULL;`,
	},
	{
		name: "admin_login_rate_limits",
		sql: `CREATE TABLE IF NOT EXISTS admin_login_rate_limits (
    admin_id TEXT NOT NULL REFERENCES admin_credentials(id) ON DELETE RESTRICT,
    source_digest TEXT NOT NULL,
    window_started_at TEXT NOT NULL,
    window_expires_at TEXT NOT NULL,
    failure_count INTEGER NOT NULL,
    last_failure_at TEXT NOT NULL,
    locked_at TEXT,
    locked_until TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (admin_id, source_digest),
    CHECK (length(source_digest) = 64 AND source_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (window_started_at GLOB '` + timePattern + `'),
    CHECK (window_expires_at GLOB '` + timePattern + `'),
    CHECK (last_failure_at GLOB '` + timePattern + `'),
    CHECK (updated_at GLOB '` + timePattern + `'),
    CHECK (strftime('%Y-%m-%dT%H:%M:%S', substr(window_started_at, 1, 19) || 'Z', '+15 minutes') IS NOT NULL AND window_expires_at = strftime('%Y-%m-%dT%H:%M:%S', substr(window_started_at, 1, 19) || 'Z', '+15 minutes') || substr(window_started_at, 20)),
    CHECK (last_failure_at >= window_started_at AND last_failure_at <= window_expires_at),
    CHECK (updated_at >= window_started_at),
    CHECK (
        (failure_count BETWEEN 1 AND 4 AND locked_at IS NULL AND locked_until IS NULL)
        OR
        (failure_count = 5 AND locked_at IS NOT NULL AND locked_until IS NOT NULL AND locked_at = last_failure_at AND locked_at GLOB '` + timePattern + `' AND locked_until GLOB '` + timePattern + `' AND strftime('%Y-%m-%dT%H:%M:%S', substr(locked_at, 1, 19) || 'Z', '+15 minutes') IS NOT NULL AND locked_until = strftime('%Y-%m-%dT%H:%M:%S', substr(locked_at, 1, 19) || 'Z', '+15 minutes') || substr(locked_at, 20))
    )
);`,
	},
	{
		name: "admin_login_rate_limits_lock_idx",
		sql: `CREATE INDEX IF NOT EXISTS admin_login_rate_limits_lock_idx
    ON admin_login_rate_limits (locked_until)
    WHERE locked_until IS NOT NULL;`,
	},
}

func authMigrationSQL() string {
	var sb strings.Builder
	for _, obj := range ownedSchemaDefinitions {
		if obj.name == "_schema_migrations" {
			continue
		}
		sb.WriteString(obj.sql)
		sb.WriteString("\n\n")
	}
	return sb.String()
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(s)))
	return hex.EncodeToString(sum[:])
}

func normalizeSQL(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ";")
	s = strings.ReplaceAll(s, "IF NOT EXISTS ", "")
	s = strings.ReplaceAll(s, "if not exists ", "")
	return strings.Join(strings.Fields(s), " ")
}

// These two finite, already reviewed migrations consist of top-level CREATE
// statements separated by a newline. Keep their compiled SQL as the sole
// structural fingerprint source instead of copying 24 object definitions.
func addNativeSchemaObjects(expected map[string]string, sqlText string, want int) error {
	statements := strings.Split(strings.TrimSpace(sqlText), "\nCREATE ")
	if len(statements) != want {
		return fmt.Errorf("native migration object count differs: %w", ErrIncompatibleSchema)
	}
	for i, statement := range statements {
		if i != 0 {
			statement = "CREATE " + statement
		}
		fields := strings.Fields(statement)
		if len(fields) < 3 || fields[0] != "CREATE" {
			return fmt.Errorf("native migration object definition invalid: %w", ErrIncompatibleSchema)
		}
		nameIndex := 2
		if fields[1] == "UNIQUE" && len(fields) >= 4 && fields[2] == "INDEX" {
			nameIndex = 3
		} else if fields[1] != "TABLE" && fields[1] != "INDEX" && fields[1] != "TRIGGER" {
			return fmt.Errorf("native migration object kind invalid: %w", ErrIncompatibleSchema)
		}
		name := fields[nameIndex]
		if name == "" || strings.ContainsAny(name, "();,\"' ") {
			return fmt.Errorf("native migration object name invalid: %w", ErrIncompatibleSchema)
		}
		if _, exists := expected[name]; exists {
			return fmt.Errorf("native migration object duplicate: %w", ErrIncompatibleSchema)
		}
		expected[name] = strings.TrimSpace(statement)
	}
	return nil
}

// migration is one immutable schema step. Applied steps are verified by checksum.
type migration struct {
	version string
	body    string
}

// migrations is the complete, ordered schema history of a fresh installation.
// Never edit an entry that has shipped; append a new one instead.
func migrations() []migration {
	return []migration{
		{version0001_admin_auth, authMigrationSQL()},
		{version0002_application_repository, applicationMigrationSQL()},
		{version0003_task_fencing, taskMigrationSQL()},
		{version0004_audit_evidence, auditMigrationSQL()},
		{version0005_image_delivery, imageDeliveryMigrationSQL()},
		{version0006_image_execution, imageExecutionMigrationSQL()},
		{version0007_image_lifecycle, imageLifecycleMigrationSQL()},
		{version0008_source_build, sourceBuildSchemaSQL},
		{version0009_image_public_access, imagePublicAccessSchemaSQL},
	}
}

// expectedSchema returns the exact final definition of every owned object.
func expectedSchema() (map[string]string, error) {
	expected := map[string]string{}
	for _, group := range [][]schemaObjectDef{
		ownedSchemaDefinitions, applicationSchemaDefinitions, auditSchemaDefinitions,
		imageDeliverySchemaDefinitions, imageDeliveryTriggers,
		imageExecutionSchemaDefinitions, imageExecutionTriggers,
		imageLifecycleSchemaDefinitions, imageLifecycleTriggers,
	} {
		for _, o := range group {
			expected[o.name] = o.sql
		}
	}
	expected["task_leases"] = finalTaskSchemaSQL(expected["task_leases"])
	expected[coreGenerationSchema.name] = coreGenerationSchema.sql
	if err := addNativeSchemaObjects(expected, sourceBuildSchemaSQL, 12); err != nil {
		return nil, err
	}
	if err := addNativeSchemaObjects(expected, imagePublicAccessSchemaSQL, 12); err != nil {
		return nil, err
	}
	return expected, nil
}

// runMigrationsAndVerifySchema applies pending migrations in one transaction and
// then requires the database to contain exactly the expected owned schema.
func runMigrationsAndVerifySchema(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}
	defer tx.Rollback()

	var hasLedger bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='_schema_migrations');`).Scan(&hasLedger); err != nil {
		return fmt.Errorf("check _schema_migrations existence: %w", err)
	}
	if !hasLedger {
		var tables int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';`).Scan(&tables); err != nil {
			return fmt.Errorf("inspect pre-migration tables: %w", err)
		}
		if tables > 0 {
			return fmt.Errorf("unexpected nonempty unversioned sqlite database (%d tables): %w", tables, ErrIncompatibleSchema)
		}
		if _, err := tx.ExecContext(ctx, ownedSchemaDefinitions[0].sql); err != nil {
			return fmt.Errorf("create _schema_migrations: %w", err)
		}
	}

	applied := map[string]string{}
	rows, err := tx.QueryContext(ctx, `SELECT version, checksum FROM _schema_migrations ORDER BY version;`)
	if err != nil {
		return fmt.Errorf("query applied migrations: %w", err)
	}
	for rows.Next() {
		var v, c string
		if err := rows.Scan(&v, &c); err != nil {
			rows.Close()
			return fmt.Errorf("scan migration row: %w", err)
		}
		applied[v] = c
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("iterate migration rows: %w", err)
	}

	steps := migrations()
	known := make(map[string]bool, len(steps))
	gap := false
	for _, m := range steps {
		known[m.version] = true
		if _, ok := applied[m.version]; !ok {
			gap = true
		} else if gap {
			return fmt.Errorf("applied migrations are not a contiguous prefix: %w", ErrIncompatibleSchema)
		}
	}
	for v := range applied {
		if !known[v] {
			return fmt.Errorf("unknown applied migration %q: %w", v, ErrIncompatibleSchema)
		}
	}

	now := FormatTime(time.Now().UTC())
	for _, m := range steps {
		checksum := sha256Hex(m.body)
		if actual, ok := applied[m.version]; ok {
			if actual != checksum {
				return fmt.Errorf("checksum mismatch for migration %s: %w", m.version, ErrIncompatibleSchema)
			}
			continue
		}
		if _, err := tx.ExecContext(ctx, m.body); err != nil {
			return fmt.Errorf("apply migration %s: %w", m.version, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO _schema_migrations(version,checksum,applied_at) VALUES(?,?,?)`, m.version, checksum, now); err != nil {
			return fmt.Errorf("record migration %s: %w", m.version, err)
		}
	}

	fkRows, err := tx.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return err
	}
	violations, iterationErr := foreignKeyCheckResult(fkRows)
	if iterationErr != nil {
		return iterationErr
	}
	if violations {
		return fmt.Errorf("foreign key check failed: %w", ErrIncompatibleSchema)
	}

	expected, err := expectedSchema()
	if err != nil {
		return err
	}
	schemaRows, err := tx.QueryContext(ctx, `
		SELECT type, name, sql
		  FROM sqlite_master
		 WHERE type IN ('table', 'index', 'trigger', 'view')
		   AND name NOT LIKE 'sqlite_%'
		   AND sql IS NOT NULL
		 ORDER BY type, name;
	`)
	if err != nil {
		return fmt.Errorf("query sqlite schema objects: %w", err)
	}
	defer schemaRows.Close()
	found := map[string]bool{}
	for schemaRows.Next() {
		var objType, objName, actualSQL string
		if err := schemaRows.Scan(&objType, &objName, &actualSQL); err != nil {
			return fmt.Errorf("scan sqlite schema object: %w", err)
		}
		want, ok := expected[objName]
		if !ok {
			return fmt.Errorf("unexpected %s %q in owned schema: %w", objType, objName, ErrIncompatibleSchema)
		}
		if normalizeSQL(actualSQL) != normalizeSQL(want) {
			return fmt.Errorf("altered structural definition for %s %q: %w", objType, objName, ErrIncompatibleSchema)
		}
		found[objName] = true
	}
	if err := schemaRows.Err(); err != nil {
		return err
	}
	for name := range expected {
		if !found[name] {
			return fmt.Errorf("missing expected object %q in owned schema: %w", name, ErrIncompatibleSchema)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit schema migration: %v", ErrOutcomeUnknown, err)
	}
	return nil
}

// An iterator error cannot certify an empty foreign-key violation result.
func foreignKeyCheckResult(rows interface {
	Next() bool
	Err() error
	Close() error
}) (bool, error) {
	violation := rows.Next()
	err := rows.Err()
	closeErr := rows.Close()
	return violation, errors.Join(err, closeErr)
}
