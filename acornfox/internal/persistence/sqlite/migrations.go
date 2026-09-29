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

func runMigrationsAndVerifySchema(ctx context.Context, db *sql.DB) (retErr error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var ledgerExists int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_schema_migrations'`).Scan(&ledgerExists); err != nil {
		return err
	}
	pending := true
	if ledgerExists == 1 {
		var applied int
		if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM _schema_migrations WHERE version=?`, version0010_image_execution).Scan(&applied); err != nil {
			return err
		}
		pending = applied == 0
	}
	defer func() {
		restoreCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		fail := func(e error) { retErr = errors.Join(retErr, e) }
		if _, err := conn.ExecContext(restoreCtx, `PRAGMA foreign_keys=ON`); err != nil {
			fail(fmt.Errorf("restore FK ON failed: %w", err))
			return
		}
		var fk int
		if err := conn.QueryRowContext(restoreCtx, `PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
			fail(fmt.Errorf("restore FK ON verification failed"))
			return
		}
		rows, err := conn.QueryContext(restoreCtx, `PRAGMA foreign_key_check`)
		if err != nil {
			fail(err)
			return
		}
		violation, iterationErr := foreignKeyCheckResult(rows)
		if iterationErr != nil {
			fail(iterationErr)
			return
		}
		if violation {
			fail(fmt.Errorf("foreign key consistency failed: %w", ErrIncompatibleSchema))
		}
	}()
	if pending {
		if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
			return err
		}
		var fk int
		if err := conn.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 0 {
			return fmt.Errorf("maintenance FK OFF failed")
		}
	}

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}
	defer tx.Rollback()

	// 1. Detect arbitrary existing tables before migrations exist
	var hasMigrationsTable bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='_schema_migrations');`).Scan(&hasMigrationsTable); err != nil {
		return fmt.Errorf("check _schema_migrations existence: %w", err)
	}

	migrationsTableSQL := ownedSchemaDefinitions[0].sql
	if !hasMigrationsTable {
		var userTableCount int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';`).Scan(&userTableCount); err != nil {
			return fmt.Errorf("inspect pre-migration tables: %w", err)
		}
		if userTableCount > 0 {
			return fmt.Errorf("unexpected nonempty unversioned sqlite database (%d tables): %w", userTableCount, ErrIncompatibleSchema)
		}

		if _, err := tx.ExecContext(ctx, migrationsTableSQL); err != nil {
			return fmt.Errorf("create _schema_migrations: %w", err)
		}
	}

	// 2. Read applied migrations
	rows, err := tx.QueryContext(ctx, `SELECT version, checksum FROM _schema_migrations ORDER BY version;`)
	if err != nil {
		return fmt.Errorf("query applied migrations: %w", err)
	}
	defer rows.Close()

	applied := map[string]string{}
	for rows.Next() {
		var v, c string
		if err := rows.Scan(&v, &c); err != nil {
			return fmt.Errorf("scan migration row: %w", err)
		}
		applied[v] = c
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate migration rows: %w", err)
	}

	knownVersions := []string{
		version0001_admin_auth, version0002_application_repository, version0003_task_fencing,
		version0004_audit_evidence, version0005_pack_intents, version0006_pack_protocol_execution,
		version0007_pack_artifact_staging, version0008_pack_activation, version0009_image_delivery,
		version0010_image_execution, version0011_image_lifecycle, version0012_source_build,
		version0013_image_public_access,
	}
	known := make(map[string]bool, len(knownVersions))
	gap := false
	for _, version := range knownVersions {
		known[version] = true
		if _, ok := applied[version]; !ok {
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
	migration001SQL := authMigrationSQL()
	expected001Checksum := sha256Hex(migration001SQL)

	if actualChecksum, ok := applied[version0001_admin_auth]; ok {
		if actualChecksum != expected001Checksum {
			return fmt.Errorf("checksum mismatch for migration %s (applied %s, expected %s): %w", version0001_admin_auth, actualChecksum, expected001Checksum, ErrIncompatibleSchema)
		}
	} else {
		if _, err := tx.ExecContext(ctx, migration001SQL); err != nil {
			return fmt.Errorf("apply migration %s: %w", version0001_admin_auth, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO _schema_migrations (version, checksum, applied_at)
			VALUES (?, ?, ?);
		`, version0001_admin_auth, expected001Checksum, now); err != nil {
			return fmt.Errorf("record migration %s: %w", version0001_admin_auth, err)
		}
	}

	migration002SQL := applicationMigrationSQL()
	expected002Checksum := sha256Hex(migration002SQL)

	if actualChecksum, ok := applied[version0002_application_repository]; ok {
		if actualChecksum != expected002Checksum {
			return fmt.Errorf("checksum mismatch for migration %s (applied %s, expected %s): %w", version0002_application_repository, actualChecksum, expected002Checksum, ErrIncompatibleSchema)
		}
	} else {
		if _, err := tx.ExecContext(ctx, migration002SQL); err != nil {
			return fmt.Errorf("apply migration %s: %w", version0002_application_repository, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO _schema_migrations (version, checksum, applied_at)
			VALUES (?, ?, ?);
		`, version0002_application_repository, expected002Checksum, now); err != nil {
			return fmt.Errorf("record migration %s: %w", version0002_application_repository, err)
		}
	}

	migration003SQL := taskMigrationSQL()
	expected003Checksum := sha256Hex(migration003SQL)
	if actual, ok := applied[version0003_task_fencing]; ok {
		if actual != expected003Checksum {
			return fmt.Errorf("checksum mismatch for migration %s: %w", version0003_task_fencing, ErrIncompatibleSchema)
		}
	} else {
		if _, err := tx.ExecContext(ctx, migration003SQL); err != nil {
			return fmt.Errorf("apply task migration: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO _schema_migrations(version,checksum,applied_at) VALUES (?,?,?)`, version0003_task_fencing, expected003Checksum, now); err != nil {
			return err
		}
	}

	migration004SQL := auditMigrationSQL()
	expected004Checksum := sha256Hex(migration004SQL)
	if actual, ok := applied[version0004_audit_evidence]; ok {
		if actual != expected004Checksum {
			return fmt.Errorf("checksum mismatch for audit migration: %w", ErrIncompatibleSchema)
		}
	} else {
		if _, err := tx.ExecContext(ctx, migration004SQL); err != nil {
			return fmt.Errorf("apply audit migration: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO _schema_migrations(version,checksum,applied_at) VALUES(?,?,?)`, version0004_audit_evidence, expected004Checksum, now); err != nil {
			return err
		}
	}

	expected005Checksum := sha256Hex(packMigrationSQL())
	if actual, ok := applied[version0005_pack_intents]; ok {
		if actual != expected005Checksum {
			return fmt.Errorf("pack migration checksum mismatch: %w", ErrIncompatibleSchema)
		}
	} else {
		if err := applyPackMigration(ctx, tx, nil); err != nil {
			return fmt.Errorf("pack migration failed: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO _schema_migrations(version,checksum,applied_at) VALUES(?,?,?)`, version0005_pack_intents, expected005Checksum, now); err != nil {
			return err
		}
	}
	if _, err := readInstallationBinding(ctx, tx); err != nil {
		return fmt.Errorf("%w: %v", ErrCorruptData, err)
	}

	expected006Checksum := sha256Hex(packExecutionMigrationSQL())
	if actual, ok := applied[version0006_pack_protocol_execution]; ok {
		if actual != expected006Checksum {
			return fmt.Errorf("checksum mismatch for migration %s: %w", version0006_pack_protocol_execution, ErrIncompatibleSchema)
		}
	} else {
		if _, err := tx.ExecContext(ctx, packExecutionMigrationSQL()); err != nil {
			return fmt.Errorf("apply pack execution migration: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO _schema_migrations(version,checksum,applied_at) VALUES(?,?,?)`, version0006_pack_protocol_execution, expected006Checksum, now); err != nil {
			return err
		}
	}

	expected007Checksum := sha256Hex(packLifecycleMigrationSQL())
	if actual, ok := applied[version0007_pack_artifact_staging]; ok {
		if actual != expected007Checksum {
			return fmt.Errorf("checksum mismatch for migration %s: %w", version0007_pack_artifact_staging, ErrIncompatibleSchema)
		}
	} else {
		if _, err := tx.ExecContext(ctx, packLifecycleMigrationSQL()); err != nil {
			return fmt.Errorf("apply pack lifecycle migration: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO _schema_migrations(version,checksum,applied_at) VALUES(?,?,?)`, version0007_pack_artifact_staging, expected007Checksum, now); err != nil {
			return err
		}
	}

	expected008Checksum := sha256Hex(packActivationMigrationSQL())
	if actual, ok := applied[version0008_pack_activation]; ok {
		if actual != expected008Checksum {
			return fmt.Errorf("checksum mismatch for migration %s: %w", version0008_pack_activation, ErrIncompatibleSchema)
		}
	} else {
		if _, err := tx.ExecContext(ctx, packActivationMigrationSQL()); err != nil {
			return fmt.Errorf("apply pack activation migration: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO _schema_migrations(version,checksum,applied_at) VALUES(?,?,?)`, version0008_pack_activation, expected008Checksum, now); err != nil {
			return err
		}
	}

	expected009Checksum := sha256Hex(imageDeliveryMigrationSQL())
	if actual, ok := applied[version0009_image_delivery]; ok {
		if actual != expected009Checksum {
			return fmt.Errorf("checksum mismatch for migration %s: %w", version0009_image_delivery, ErrIncompatibleSchema)
		}
	} else {
		if _, err := tx.ExecContext(ctx, imageDeliveryMigrationSQL()); err != nil {
			return fmt.Errorf("apply image delivery migration: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO _schema_migrations(version,checksum,applied_at) VALUES(?,?,?)`, version0009_image_delivery, expected009Checksum, now); err != nil {
			return err
		}
	}

	expected010Checksum := sha256Hex(imageExecutionMigrationSQL())
	if actual, ok := applied[version0010_image_execution]; ok {
		if actual != expected010Checksum {
			return fmt.Errorf("checksum mismatch for migration %s: %w", version0010_image_execution, ErrIncompatibleSchema)
		}
	} else {
		if _, err := tx.ExecContext(ctx, imageExecutionMigrationSQL()); err != nil {
			return fmt.Errorf("apply image execution migration: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO _schema_migrations(version,checksum,applied_at) VALUES(?,?,?)`, version0010_image_execution, expected010Checksum, now); err != nil {
			return err
		}
	}

	expected011Checksum := sha256Hex(imageLifecycleMigrationSQL())
	if actual, ok := applied[version0011_image_lifecycle]; ok {
		if actual != expected011Checksum {
			return fmt.Errorf("lifecycle migration checksum mismatch: %w", ErrIncompatibleSchema)
		}
	} else {
		if _, err := tx.ExecContext(ctx, imageLifecycleMigrationSQL()); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO _schema_migrations(version,checksum,applied_at) VALUES(?,?,?)`, version0011_image_lifecycle, expected011Checksum, now); err != nil {
			return err
		}
	}

	for _, migration := range []struct{ version, body string }{
		{version0012_source_build, sourceBuildSchemaSQL},
		{version0013_image_public_access, imagePublicAccessSchemaSQL},
	} {
		checksum := sha256Hex(migration.body)
		if actual, ok := applied[migration.version]; ok {
			if actual != checksum {
				return fmt.Errorf("checksum mismatch for migration %s: %w", migration.version, ErrIncompatibleSchema)
			}
			continue
		}
		if _, err := tx.ExecContext(ctx, migration.body); err != nil {
			return fmt.Errorf("apply migration %s: %w", migration.version, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO _schema_migrations(version,checksum,applied_at) VALUES(?,?,?)`, migration.version, checksum, now); err != nil {
			return fmt.Errorf("record migration %s: %w", migration.version, err)
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
		return fmt.Errorf("pack migration FK check failed: %w", ErrIncompatibleSchema)
	}

	// 3. Structural verification of owned schema: compare actual SQL of all objects
	expectedSQLMap := map[string]string{}
	for _, obj := range ownedSchemaDefinitions {
		expectedSQLMap[obj.name] = obj.sql
	}
	for _, obj := range applicationSchemaDefinitions {
		expectedSQLMap[obj.name] = obj.sql
	}

	for _, obj := range auditSchemaDefinitions {
		expectedSQLMap[obj.name] = obj.sql
	}
	expectedSQLMap["task_leases"] = finalTaskSchemaSQL(expectedSQLMap["task_leases"])
	expectedSQLMap[coreGenerationSchema.name] = coreGenerationSchema.sql

	expectedSQLMap["operations"] = packOperationsSQL(`"operations"`)
	delete(expectedSQLMap, "operations_application_idx")
	delete(expectedSQLMap, "operations_one_active_per_environment")
	for _, o := range packOperationIndices {
		expectedSQLMap[o.name] = o.sql
	}
	for _, o := range packSchemaDefinitions {
		expectedSQLMap[o.name] = o.sql
	}
	for _, o := range packIntentTriggers {
		expectedSQLMap[o.name] = o.sql
	}
	for _, o := range packExecutionSchemaDefinitions {
		expectedSQLMap[o.name] = o.sql
	}
	for _, o := range packExecutionTriggers {
		expectedSQLMap[o.name] = o.sql
	}
	for _, o := range packLifecycleSchemaDefinitions {
		expectedSQLMap[o.name] = o.sql
	}
	for _, o := range packLifecycleTriggers {
		expectedSQLMap[o.name] = o.sql
	}
	for _, o := range packActivationSchemaDefinitions {
		expectedSQLMap[o.name] = o.sql
	}
	for _, o := range packActivationTriggers {
		expectedSQLMap[o.name] = o.sql
	}
	for _, o := range imageDeliverySchemaDefinitions {
		expectedSQLMap[o.name] = o.sql
	}
	for _, o := range imageDeliveryTriggers {
		expectedSQLMap[o.name] = o.sql
	}
	for _, o := range imageExecutionSchemaDefinitions {
		expectedSQLMap[o.name] = o.sql
	}
	for _, o := range imageExecutionTriggers {
		expectedSQLMap[o.name] = o.sql
	}

	for _, objects := range [][]schemaObjectDef{imageLifecycleSchemaDefinitions, imageLifecycleTriggers} {
		for _, o := range objects {
			expectedSQLMap[o.name] = o.sql
		}
	}
	if err := addNativeSchemaObjects(expectedSQLMap, sourceBuildSchemaSQL, 12); err != nil {
		return err
	}
	if err := addNativeSchemaObjects(expectedSQLMap, imagePublicAccessSchemaSQL, 12); err != nil {
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

	foundObjects := map[string]bool{}
	for schemaRows.Next() {
		var objType, objName, actualSQL string
		if err := schemaRows.Scan(&objType, &objName, &actualSQL); err != nil {
			return fmt.Errorf("scan sqlite schema object: %w", err)
		}
		expectedSQL, ok := expectedSQLMap[objName]
		if !ok {
			return fmt.Errorf("unexpected %s in owned auth schema %q: %w", objType, objName, ErrIncompatibleSchema)
		}
		if normalizeSQL(actualSQL) != normalizeSQL(expectedSQL) {
			return fmt.Errorf("altered structural definition for %s %q: %w", objType, objName, ErrIncompatibleSchema)
		}
		foundObjects[objName] = true
	}
	if err := schemaRows.Err(); err != nil {
		return err
	}

	for exp := range expectedSQLMap {
		if !foundObjects[exp] {
			return fmt.Errorf("missing expected object in owned auth schema %q: %w", exp, ErrIncompatibleSchema)
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
