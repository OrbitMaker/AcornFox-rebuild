-- G3 source uploads are immutable metadata plus a private storage reference.
-- File bytes and client-selected host paths remain outside PostgreSQL.

CREATE TABLE IF NOT EXISTS source_uploads (
    id text PRIMARY KEY,
    upload_kind text NOT NULL,
    status text NOT NULL,
    content_digest text NOT NULL,
    total_bytes bigint NOT NULL,
    file_count integer NOT NULL,
    storage_ref text NOT NULL,
    idempotency_key text NOT NULL UNIQUE,
    request_digest text NOT NULL,
    expires_at timestamptz NOT NULL,
    claimed_application_id text REFERENCES applications(id),
    claimed_source_revision_id text REFERENCES source_revisions(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (length(trim(id)) > 0),
    CHECK (upload_kind IN ('archive','directory')),
    CHECK (status IN ('ready','claimed','expired','failed')),
    CHECK (content_digest ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (total_bytes >= 0 AND file_count > 0),
    CHECK (storage_ref = 'upload://' || id),
    CHECK (expires_at > created_at),
    CHECK (updated_at >= created_at),
    CHECK ((status = 'claimed') = (claimed_application_id IS NOT NULL AND claimed_source_revision_id IS NOT NULL)),
    CHECK ((status <> 'claimed') = (claimed_application_id IS NULL AND claimed_source_revision_id IS NULL))
);

CREATE INDEX IF NOT EXISTS source_uploads_cleanup_idx
    ON source_uploads(status, expires_at, created_at)
    WHERE status IN ('ready','expired','failed');

CREATE TABLE IF NOT EXISTS source_upload_files (
    upload_id text NOT NULL REFERENCES source_uploads(id) ON DELETE CASCADE,
    relative_path text NOT NULL,
    byte_count bigint NOT NULL,
    content_digest text NOT NULL,
    PRIMARY KEY (upload_id, relative_path),
    CHECK (length(relative_path) BETWEEN 1 AND 512),
    CHECK (relative_path ~ '^[ -~]+$'),
    CHECK (relative_path !~ '[\\:]' AND relative_path !~ '(^|/)\.?\.?($|/)' AND relative_path !~ '(^/|//|/$)'),
    CHECK (byte_count >= 0),
    CHECK (content_digest ~ '^sha256:[0-9a-f]{64}$')
);
