-- G2-01 single-administrator authentication facts. This migration stores only
-- password hashes and fixed-length digests; raw passwords, session/CSRF
-- tokens, and source addresses are intentionally absent.

CREATE TABLE IF NOT EXISTS admin_credentials (
    id text PRIMARY KEY,
    password_hash_scheme text NOT NULL,
    password_hash text NOT NULL,
    credential_version bigint NOT NULL DEFAULT 1,
    disabled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (length(trim(id)) > 0),
    CHECK (password_hash_scheme ~ '^[a-z0-9][a-z0-9._-]{0,55}-v[1-9][0-9]*$'),
    CHECK (password_hash ~ '^\$[A-Za-z0-9][A-Za-z0-9._=-]{0,127}\$[^[:space:]]+$'),
    CHECK (length(password_hash) <= 4096),
    CHECK (credential_version > 0),
    CHECK (updated_at >= created_at),
    CHECK (disabled_at IS NULL OR disabled_at >= created_at)
);

-- A partial unique index is the database authority for this single-instance
-- product: disabled historical credentials do not prevent a replacement, but
-- two enabled administrators can never coexist.
CREATE UNIQUE INDEX IF NOT EXISTS admin_credentials_one_enabled_idx
    ON admin_credentials ((true))
    WHERE disabled_at IS NULL;

CREATE TABLE IF NOT EXISTS admin_sessions (
    id text PRIMARY KEY,
    admin_id text NOT NULL REFERENCES admin_credentials(id) ON DELETE RESTRICT,
    session_digest char(64) NOT NULL UNIQUE,
    csrf_digest char(64) NOT NULL UNIQUE,
    credential_version bigint NOT NULL,
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CHECK (session_digest ~ '^[0-9a-f]{64}$'),
    CHECK (csrf_digest ~ '^[0-9a-f]{64}$'),
    CHECK (session_digest <> csrf_digest),
    CHECK (credential_version > 0),
    CHECK (last_seen_at >= created_at AND last_seen_at <= absolute_expires_at),
    CHECK (absolute_expires_at = created_at + INTERVAL '24 hours'),
    CHECK (idle_expires_at = LEAST(last_seen_at + INTERVAL '8 hours', absolute_expires_at)),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
CREATE INDEX IF NOT EXISTS admin_sessions_active_lookup_idx
    ON admin_sessions (session_digest, idle_expires_at, absolute_expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS admin_login_rate_limits (
    admin_id text NOT NULL REFERENCES admin_credentials(id) ON DELETE RESTRICT,
    source_digest char(64) NOT NULL,
    window_started_at timestamptz NOT NULL,
    window_expires_at timestamptz NOT NULL,
    failure_count smallint NOT NULL,
    last_failure_at timestamptz NOT NULL,
    locked_at timestamptz,
    locked_until timestamptz,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (admin_id, source_digest),
    CHECK (source_digest ~ '^[0-9a-f]{64}$'),
    CHECK (window_expires_at = window_started_at + INTERVAL '15 minutes'),
    CHECK (last_failure_at >= window_started_at AND last_failure_at <= window_expires_at),
    CHECK (updated_at >= window_started_at),
    CHECK (
        (failure_count BETWEEN 1 AND 4 AND locked_at IS NULL AND locked_until IS NULL)
        OR
        (failure_count = 5 AND locked_at = last_failure_at AND locked_until = locked_at + INTERVAL '15 minutes')
    )
);
CREATE INDEX IF NOT EXISTS admin_login_rate_limits_lock_idx
    ON admin_login_rate_limits (locked_until)
    WHERE locked_until IS NOT NULL;
