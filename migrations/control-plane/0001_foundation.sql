CREATE TABLE applications (
    id text PRIMARY KEY,
    name text NOT NULL,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE environments (
    id text PRIMARY KEY,
    application_id text NOT NULL REFERENCES applications(id),
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, name)
);

CREATE TABLE source_revisions (
    id text PRIMARY KEY,
    application_id text NOT NULL REFERENCES applications(id),
    provider text NOT NULL CHECK (provider IN ('git', 'upload')),
    git_commit text,
    content_digest text,
    workspace_manifest jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (provider = 'git' AND git_commit IS NOT NULL AND content_digest IS NULL)
        OR
        (provider = 'upload' AND content_digest IS NOT NULL AND git_commit IS NULL)
    )
);

CREATE TABLE delivery_definitions (
    id text PRIMARY KEY,
    application_id text NOT NULL REFERENCES applications(id),
    source_revision_id text NOT NULL REFERENCES source_revisions(id),
    version bigint NOT NULL CHECK (version > 0),
    configuration jsonb NOT NULL,
    observations jsonb NOT NULL DEFAULT '[]'::jsonb,
    recommendations jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, version)
);

CREATE TABLE releases (
    id text PRIMARY KEY,
    application_id text NOT NULL REFERENCES applications(id),
    definition_id text NOT NULL REFERENCES delivery_definitions(id),
    version bigint NOT NULL CHECK (version > 0),
    service_digests jsonb NOT NULL CHECK (jsonb_typeof(service_digests) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, version)
);

CREATE TABLE deployments (
    id text PRIMARY KEY,
    environment_id text NOT NULL REFERENCES environments(id),
    release_id text NOT NULL REFERENCES releases(id),
    state text NOT NULL CHECK (state IN (
        'pending', 'deploying', 'runtime_ready', 'serving', 'degraded',
        'failed', 'rolling_back', 'rolled_back', 'unknown', 'stopped'
    )),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE operations (
    id text PRIMARY KEY,
    environment_id text NOT NULL REFERENCES environments(id),
    deployment_id text REFERENCES deployments(id),
    operation_type text NOT NULL,
    idempotency_key text NOT NULL,
    state text NOT NULL CHECK (state IN (
        'pending', 'leased', 'running', 'waiting', 'cancelling',
        'succeeded', 'failed', 'cancelled', 'rolled_back'
    )),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (environment_id, idempotency_key)
);

CREATE UNIQUE INDEX operations_one_active_per_environment
    ON operations (environment_id)
    WHERE state IN ('pending', 'leased', 'running', 'waiting', 'cancelling');

CREATE TABLE outbox_events (
    id text PRIMARY KEY,
    aggregate_type text NOT NULL,
    aggregate_id text NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    sequence bigint NOT NULL CHECK (sequence > 0),
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz,
    UNIQUE (aggregate_type, aggregate_id, sequence)
);

CREATE INDEX outbox_events_pending_idx
    ON outbox_events (created_at, id)
    WHERE published_at IS NULL;

CREATE TABLE task_leases (
    task_id text PRIMARY KEY,
    operation_id text NOT NULL REFERENCES operations(id),
    lease_owner text,
    lease_until timestamptz,
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    state text NOT NULL CHECK (state IN ('ready', 'leased', 'completed', 'failed', 'cancelled')),
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX task_leases_claimable_idx
    ON task_leases (state, lease_until, created_at);

CREATE TABLE secret_references (
    id text PRIMARY KEY,
    application_id text NOT NULL REFERENCES applications(id),
    name text NOT NULL,
    ciphertext bytea NOT NULL,
    key_version text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    UNIQUE (application_id, name)
);

CREATE TABLE audit_evidence (
    id text PRIMARY KEY,
    sequence bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    actor_type text NOT NULL,
    actor_id text NOT NULL,
    action text NOT NULL,
    reason text NOT NULL,
    input_digest text NOT NULL,
    result text NOT NULL,
    evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    previous_hash text,
    record_hash text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);
