-- AcornFox assistant conversation durability. Browser-visible events contain
-- only bounded user/assistant text projections; provider events, tool
-- arguments, credentials, and raw provider errors have no column.

CREATE TABLE IF NOT EXISTS acornfox_assistant_sessions (
    id text PRIMARY KEY,
    owner_admin_id text NOT NULL REFERENCES admin_credentials(id) ON DELETE RESTRICT,
    scope_kind text NOT NULL CHECK (scope_kind IN ('host', 'app')),
    app_id text,
    next_cursor bigint NOT NULL DEFAULT 0 CHECK (next_cursor >= 0),
    event_bytes bigint NOT NULL DEFAULT 0 CHECK (event_bytes >= 0),
    run_count integer NOT NULL DEFAULT 0 CHECK (run_count >= 0 AND run_count <= 256),
    message_bytes bigint NOT NULL DEFAULT 0 CHECK (message_bytes >= 0 AND message_bytes <= 2097152),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((scope_kind = 'host' AND app_id IS NULL) OR (scope_kind = 'app' AND length(trim(app_id)) > 0)),
    CHECK (updated_at >= created_at)
);
CREATE INDEX IF NOT EXISTS acornfox_assistant_sessions_owner_idx
    ON acornfox_assistant_sessions (owner_admin_id, created_at, id);

CREATE TABLE IF NOT EXISTS acornfox_assistant_runs (
    id text PRIMARY KEY,
    session_id text NOT NULL REFERENCES acornfox_assistant_sessions(id) ON DELETE CASCADE,
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    message text NOT NULL CHECK (octet_length(message) BETWEEN 1 AND 65536),
    status text NOT NULL CHECK (status IN ('accepted', 'running', 'completed', 'failed', 'aborted', 'unknown')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (session_id, idempotency_key),
    CHECK (updated_at >= created_at)
);
CREATE UNIQUE INDEX IF NOT EXISTS acornfox_assistant_one_running_per_session_idx
    ON acornfox_assistant_runs (session_id)
    WHERE status = 'running';
CREATE INDEX IF NOT EXISTS acornfox_assistant_runs_queue_idx
    ON acornfox_assistant_runs (session_id, created_at, id)
    WHERE status = 'accepted';

CREATE TABLE IF NOT EXISTS acornfox_assistant_events (
    session_id text NOT NULL REFERENCES acornfox_assistant_sessions(id) ON DELETE CASCADE,
    cursor bigint NOT NULL CHECK (cursor > 0),
    run_id text NOT NULL REFERENCES acornfox_assistant_runs(id) ON DELETE CASCADE,
    event_type text NOT NULL CHECK (event_type IN ('run.accepted', 'run.started', 'assistant.delta', 'assistant.message', 'run.completed', 'run.failed', 'run.aborted', 'run.unknown')),
    text text NOT NULL DEFAULT '' CHECK (octet_length(text) <= 65536),
    byte_size integer NOT NULL CHECK (byte_size >= 128 AND byte_size <= 65664),
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY (session_id, cursor)
);
CREATE INDEX IF NOT EXISTS acornfox_assistant_events_run_idx
    ON acornfox_assistant_events (run_id, cursor);
