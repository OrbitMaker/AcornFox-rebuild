package state

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

// timeLayout is the canonical UTC text format used for every timestamp column.
// Fixed-width so lexical order equals chronological order.
const timeLayout = "2006-01-02T15:04:05.000000000Z"

// timePattern is the GLOB expression that CHECK constraints use to reject any
// non-canonical timestamp text.
const timePattern = "[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z"

// formatTime renders t as canonical UTC text.
func formatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

// parseTime parses canonical UTC text back into a time.Time.
func parseTime(s string) (time.Time, error) {
	if len(s) != 30 || s[29] != 'Z' || s[10] != 'T' || s[19] != '.' {
		return time.Time{}, fmt.Errorf("invalid non-canonical timestamp %q", s)
	}
	t, err := time.Parse(timeLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse canonical timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}

// migration is one immutable schema step. Applied steps are verified by their
// sha256 checksum; a mismatch means the shipped schema was edited in place,
// which is reported as ErrBadSchema.
type migration struct {
	version string
	body    string
}

// migration0001 creates the AcornFox desired-state tables.
const migration0001 = `
CREATE TABLE apps (
    name               TEXT PRIMARY KEY NOT NULL,
    desired            TEXT NOT NULL,
    port               INTEGER NOT NULL DEFAULT 0,
    health_path        TEXT NOT NULL,
    public_port        INTEGER NOT NULL UNIQUE,
    current_deployment TEXT NOT NULL DEFAULT '',
    memory_mb          INTEGER NOT NULL,
    cpu_milli          INTEGER NOT NULL,
    volume_seq         INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    CHECK (desired IN ('running','stopped')),
    CHECK (port >= 0),
    CHECK (public_port > 0),
    CHECK (memory_mb > 0),
    CHECK (cpu_milli > 0),
    CHECK (volume_seq >= 0),
    CHECK (created_at GLOB '` + timePattern + `'),
    CHECK (updated_at GLOB '` + timePattern + `')
);

CREATE TABLE deployments (
    id            TEXT PRIMARY KEY NOT NULL,
    app           TEXT NOT NULL REFERENCES apps(name) ON DELETE CASCADE,
    seq           INTEGER NOT NULL,
    source_kind   TEXT NOT NULL,
    source_ref    TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    request_key   TEXT NOT NULL DEFAULT '',
    image_id      TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL,
    attempts      INTEGER NOT NULL DEFAULT 0,
    diagnosis     TEXT NOT NULL DEFAULT '',
    warnings      TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    finished_at   TEXT,
    CHECK (source_kind IN ('upload','image')),
    CHECK (seq > 0),
    CHECK (attempts >= 0),
    CHECK (created_at GLOB '` + timePattern + `'),
    CHECK (updated_at GLOB '` + timePattern + `'),
    CHECK (finished_at IS NULL OR finished_at GLOB '` + timePattern + `')
);

CREATE UNIQUE INDEX deployments_app_seq_idx ON deployments (app, seq);

CREATE UNIQUE INDEX deployments_app_request_key_idx ON deployments (app, request_key) WHERE request_key <> '';

CREATE INDEX deployments_app_created_idx ON deployments (app, created_at);

CREATE TABLE app_env (
    app    TEXT NOT NULL REFERENCES apps(name) ON DELETE CASCADE,
    key    TEXT NOT NULL,
    value  TEXT NOT NULL,
    secret INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (app, key),
    CHECK (secret IN (0,1))
);

CREATE TABLE app_volumes (
    app         TEXT NOT NULL REFERENCES apps(name) ON DELETE CASCADE,
    path        TEXT NOT NULL,
    volume_name TEXT NOT NULL UNIQUE,
    auto        INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (app, path),
    CHECK (auto IN (0,1)),
    CHECK (created_at GLOB '` + timePattern + `')
);

CREATE TABLE addons (
    app         TEXT NOT NULL REFERENCES apps(name) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    image       TEXT NOT NULL,
    volume_name TEXT NOT NULL,
    credentials TEXT NOT NULL DEFAULT '',
    env_var     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (app, kind),
    CHECK (created_at GLOB '` + timePattern + `')
);

CREATE TABLE events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    app           TEXT NOT NULL,
    deployment_id TEXT NOT NULL DEFAULT '',
    at            TEXT NOT NULL,
    stage         TEXT NOT NULL,
    message       TEXT NOT NULL,
    CHECK (at GLOB '` + timePattern + `')
);

CREATE INDEX events_app_idx ON events (app, id);

CREATE INDEX events_deployment_idx ON events (deployment_id, id);
`

// migration0002 copies the admin authentication DDL verbatim from
// internal/persistence/sqlite/migrations.go so both databases share the same
// reviewed schema. AcornFox N1 does not use these tables, but they are created
// so that the N2/N3 auth layer can attach without another migration.
const migration0002 = `CREATE TABLE IF NOT EXISTS admin_credentials (
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
);

CREATE UNIQUE INDEX IF NOT EXISTS admin_credentials_one_enabled_idx
    ON admin_credentials ((1))
    WHERE disabled_at IS NULL;

CREATE TABLE IF NOT EXISTS admin_sessions (
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
);

CREATE INDEX IF NOT EXISTS admin_sessions_active_lookup_idx
    ON admin_sessions (session_digest, idle_expires_at, absolute_expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS admin_login_rate_limits (
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
);

CREATE INDEX IF NOT EXISTS admin_login_rate_limits_lock_idx
    ON admin_login_rate_limits (locked_until)
    WHERE locked_until IS NOT NULL;
`

// migration0003 widens the deployments.source_kind CHECK to also allow 'git'
// (N2). SQLite cannot alter a CHECK constraint in place, so the table is
// rebuilt: a new table with the widened constraint is created, existing rows
// are copied verbatim, the old table is dropped and the new one renamed, then
// every index is recreated. The 12-step rename preserves all data and the
// unique/idempotency indexes byte-for-byte.
const migration0003 = `
CREATE TABLE deployments_new (
    id            TEXT PRIMARY KEY NOT NULL,
    app           TEXT NOT NULL REFERENCES apps(name) ON DELETE CASCADE,
    seq           INTEGER NOT NULL,
    source_kind   TEXT NOT NULL,
    source_ref    TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    request_key   TEXT NOT NULL DEFAULT '',
    image_id      TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL,
    attempts      INTEGER NOT NULL DEFAULT 0,
    diagnosis     TEXT NOT NULL DEFAULT '',
    warnings      TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    finished_at   TEXT,
    CHECK (source_kind IN ('upload','image','git')),
    CHECK (seq > 0),
    CHECK (attempts >= 0),
    CHECK (created_at GLOB '` + timePattern + `'),
    CHECK (updated_at GLOB '` + timePattern + `'),
    CHECK (finished_at IS NULL OR finished_at GLOB '` + timePattern + `')
);

INSERT INTO deployments_new
    (id, app, seq, source_kind, source_ref, source_digest, request_key, image_id, status, attempts, diagnosis, warnings, created_at, updated_at, finished_at)
SELECT
    id, app, seq, source_kind, source_ref, source_digest, request_key, image_id, status, attempts, diagnosis, warnings, created_at, updated_at, finished_at
FROM deployments;

DROP TABLE deployments;

ALTER TABLE deployments_new RENAME TO deployments;

CREATE UNIQUE INDEX deployments_app_seq_idx ON deployments (app, seq);

CREATE UNIQUE INDEX deployments_app_request_key_idx ON deployments (app, request_key) WHERE request_key <> '';

CREATE INDEX deployments_app_created_idx ON deployments (app, created_at);
`

// migration0004 adds the N3 console and domain tables: one-time console login
// tokens, browser sessions (only SHA-256 digests of secrets are stored) and
// per-app custom domains. Timestamps use the same canonical UTC text as every
// other table so lexical order equals chronological order.
const migration0004 = `
CREATE TABLE console_tokens (
    token_digest TEXT PRIMARY KEY NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    CHECK (length(token_digest) = 64 AND token_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (created_at GLOB '` + timePattern + `'),
    CHECK (expires_at GLOB '` + timePattern + `'),
    CHECK (expires_at >= created_at)
);

CREATE TABLE console_sessions (
    id                  TEXT PRIMARY KEY NOT NULL,
    session_digest      TEXT NOT NULL UNIQUE,
    csrf_digest         TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    last_seen_at        TEXT NOT NULL,
    idle_expires_at     TEXT NOT NULL,
    absolute_expires_at TEXT NOT NULL,
    revoked_at          TEXT,
    CHECK (length(id) = 16 AND id NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(session_digest) = 64 AND session_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(csrf_digest) = 64 AND csrf_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (created_at GLOB '` + timePattern + `'),
    CHECK (last_seen_at GLOB '` + timePattern + `'),
    CHECK (idle_expires_at GLOB '` + timePattern + `'),
    CHECK (absolute_expires_at GLOB '` + timePattern + `'),
    CHECK (revoked_at IS NULL OR revoked_at GLOB '` + timePattern + `'),
    CHECK (last_seen_at >= created_at),
    CHECK (absolute_expires_at >= created_at),
    CHECK (idle_expires_at <= absolute_expires_at)
);

CREATE INDEX console_sessions_digest_idx ON console_sessions (session_digest) WHERE revoked_at IS NULL;

CREATE TABLE app_domains (
    app        TEXT NOT NULL REFERENCES apps(name) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    status     TEXT NOT NULL,
    diagnosis  TEXT NOT NULL DEFAULT '',
    checked_at TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (name),
    CHECK (status IN ('pending','ready','failed')),
    CHECK (created_at GLOB '` + timePattern + `'),
    CHECK (checked_at IS NULL OR checked_at GLOB '` + timePattern + `')
);

CREATE INDEX app_domains_app_idx ON app_domains (app, name);
`

// migrationList is the complete, ordered schema history. Never edit a shipped
// entry; append a new one instead.
func migrationList() []migration {
	return []migration{
		{"0001_apps", migration0001},
		{"0002_admin_auth", migration0002},
		{"0003_source_git", migration0003},
		{"0004_console_domains", migration0004},
	}
}

// schemaMigrationsDDL creates the ledger table that records applied migrations
// and their checksums.
const schemaMigrationsDDL = `CREATE TABLE IF NOT EXISTS _schema_migrations (
    version    TEXT PRIMARY KEY NOT NULL,
    checksum   TEXT NOT NULL,
    applied_at TEXT NOT NULL,
    CHECK (length(version) > 0),
    CHECK (length(checksum) = 64 AND checksum NOT GLOB '*[^0-9a-f]*'),
    CHECK (applied_at GLOB '` + timePattern + `')
);`

// checksum computes the sha256 hex of a migration body, ignoring surrounding
// whitespace so cosmetic reformatting of the constant does not trip the guard.
func checksum(body string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(body)))
	return hex.EncodeToString(sum[:])
}

// runMigrations applies every pending migration in one transaction and verifies
// that already-applied migrations still match their recorded checksum. A
// mismatch or an unknown/out-of-order applied migration returns ErrBadSchema.
func runMigrations(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, schemaMigrationsDDL); err != nil {
		return fmt.Errorf("create _schema_migrations: %w", err)
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

	steps := migrationList()
	known := make(map[string]bool, len(steps))
	gap := false
	for _, m := range steps {
		known[m.version] = true
		if _, ok := applied[m.version]; !ok {
			gap = true
		} else if gap {
			return fmt.Errorf("applied migrations are not a contiguous prefix: %w", ErrBadSchema)
		}
	}
	for v := range applied {
		if !known[v] {
			return fmt.Errorf("unknown applied migration %q: %w", v, ErrBadSchema)
		}
	}

	now := formatTime(time.Now().UTC())
	for _, m := range steps {
		sum := checksum(m.body)
		if actual, ok := applied[m.version]; ok {
			if actual != sum {
				return fmt.Errorf("checksum mismatch for migration %s: %w", m.version, ErrBadSchema)
			}
			continue
		}
		if _, err := tx.ExecContext(ctx, m.body); err != nil {
			return fmt.Errorf("apply migration %s: %w", m.version, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO _schema_migrations(version,checksum,applied_at) VALUES(?,?,?)`, m.version, sum, now); err != nil {
			return fmt.Errorf("record migration %s: %w", m.version, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}
	return nil
}
