-- M1 delivery persistence extends the M0 control-plane without rewriting
-- historical rows.  A source revision, definition, plan, artifact and ready
-- release are immutable facts; only build and deployment execution state is
-- mutable.  This lets a controller retry execution without rewriting what it
-- was asked to build or deploy.

-- 0001 represented source provenance as either a Git commit or upload digest.
-- M1 records both the resolved source digest and the retained workspace for
-- every new revision.  Legacy rows intentionally retain NULL source_kind.
ALTER TABLE source_revisions
    ADD COLUMN IF NOT EXISTS source_kind text,
    ADD COLUMN IF NOT EXISTS locator text,
    ADD COLUMN IF NOT EXISTS source_ref text,
    ADD COLUMN IF NOT EXISTS workspace_ref text,
    ADD COLUMN IF NOT EXISTS workspace_lifecycle text,
    ADD COLUMN IF NOT EXISTS immutable boolean NOT NULL DEFAULT true;

ALTER TABLE source_revisions
    DROP CONSTRAINT IF EXISTS source_revisions_check;

ALTER TABLE source_revisions
    ADD CONSTRAINT source_revisions_m1_shape_check CHECK (
        source_kind IS NULL
        OR (
            source_kind IN ('git_https', 'git_ssh', 'upload')
            AND locator IS NOT NULL AND length(trim(locator)) > 0
            AND content_digest ~ '^sha256:[0-9a-f]{64}$'
            AND workspace_ref IS NOT NULL AND length(trim(workspace_ref)) > 0
            AND workspace_lifecycle IN ('prepared', 'released', 'failed')
            AND immutable
            AND (
                (source_kind IN ('git_https', 'git_ssh') AND provider = 'git' AND git_commit IS NOT NULL)
                OR (source_kind = 'upload' AND provider = 'upload')
            )
        )
    );

CREATE UNIQUE INDEX IF NOT EXISTS source_revisions_m1_content_uidx
    ON source_revisions (application_id, source_kind, content_digest)
    WHERE source_kind IS NOT NULL;

-- Workspace cleanup is an execution lifecycle, so it is a separate
-- append-only stream rather than an update to the immutable source revision.
CREATE TABLE source_workspace_events (
    source_revision_id text NOT NULL REFERENCES source_revisions(id),
    sequence bigint NOT NULL CHECK (sequence > 0),
    workspace_ref text NOT NULL CHECK (length(trim(workspace_ref)) > 0),
    state text NOT NULL CHECK (state IN ('prepared', 'released', 'failed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source_revision_id, sequence)
);

CREATE TRIGGER source_workspace_events_are_append_only
    BEFORE UPDATE OR DELETE ON source_workspace_events
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();

CREATE TABLE build_plans (
    id text PRIMARY KEY,
    source_revision_id text NOT NULL REFERENCES source_revisions(id),
    source_digest text NOT NULL CHECK (source_digest ~ '^sha256:[0-9a-f]{64}$'),
    service_name text NOT NULL CHECK (length(trim(service_name)) > 0),
    build_kind text NOT NULL CHECK (build_kind IN ('static', 'dockerfile')),
    context_path text NOT NULL CHECK (length(trim(context_path)) > 0),
    dockerfile_path text,
    target_repository text NOT NULL CHECK (length(trim(target_repository)) > 0),
    output_contract jsonb NOT NULL CHECK (jsonb_typeof(output_contract) = 'object'),
    secret_refs jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(secret_refs) = 'array'),
    idempotency_key text NOT NULL CHECK (length(trim(idempotency_key)) > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((build_kind = 'dockerfile') = (dockerfile_path IS NOT NULL))
);

CREATE UNIQUE INDEX build_plans_idempotency_uidx
    ON build_plans (source_revision_id, service_name, idempotency_key);

CREATE TABLE builds (
    id text PRIMARY KEY,
    plan_id text NOT NULL REFERENCES build_plans(id),
    state text NOT NULL CHECK (state IN ('pending', 'running', 'succeeded', 'failed', 'cancelled')),
    artifact_id text,
    failure_reason text,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((state = 'succeeded') = (artifact_id IS NOT NULL)),
    CHECK ((state <> 'failed') OR failure_reason IS NOT NULL)
);

CREATE INDEX builds_plan_created_idx ON builds (plan_id, created_at, id);

CREATE TABLE artifacts (
    id text PRIMARY KEY,
    build_id text NOT NULL UNIQUE REFERENCES builds(id),
    image_repository text NOT NULL CHECK (length(trim(image_repository)) > 0),
    image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    resolved_tag text,
    oci_storage_ref text NOT NULL CHECK (length(trim(oci_storage_ref)) > 0),
    size_bytes bigint NOT NULL CHECK (size_bytes > 0),
    evidence jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(evidence) = 'array'),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (image_repository, image_digest)
);

ALTER TABLE builds
    ADD CONSTRAINT builds_artifact_id_fkey
    FOREIGN KEY (artifact_id) REFERENCES artifacts(id) DEFERRABLE INITIALLY DEFERRED;

CREATE TRIGGER build_plans_are_immutable
    BEFORE UPDATE OR DELETE ON build_plans
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();

CREATE TRIGGER artifacts_are_immutable
    BEFORE UPDATE OR DELETE ON artifacts
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();

-- releases was intentionally immutable in M0.  M1 makes that explicit: a
-- release is written only after every referenced artifact has succeeded.  The
-- execution state remains on deployments and operations, never on the release.
ALTER TABLE releases
    ADD COLUMN IF NOT EXISTS service_group_id text NOT NULL DEFAULT 'legacy',
    ADD COLUMN IF NOT EXISTS config_digest text NOT NULL DEFAULT 'legacy',
    ADD COLUMN IF NOT EXISTS release_status text NOT NULL DEFAULT 'ready';

ALTER TABLE releases
    ADD CONSTRAINT releases_m1_ready_check CHECK (release_status = 'ready');

ALTER TABLE deployments
    ADD COLUMN IF NOT EXISTS failure_reason text;

CREATE TABLE release_artifacts (
    release_id text NOT NULL REFERENCES releases(id),
    service_name text NOT NULL CHECK (length(trim(service_name)) > 0),
    artifact_id text NOT NULL REFERENCES artifacts(id),
    PRIMARY KEY (release_id, service_name),
    UNIQUE (release_id, artifact_id)
);

CREATE TRIGGER release_artifacts_are_immutable
    BEFORE UPDATE OR DELETE ON release_artifacts
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();

CREATE INDEX deployments_release_state_idx
    ON deployments (release_id, state, updated_at DESC);

COMMENT ON TABLE build_plans IS
    'Immutable, redacted build intent. secret_refs are references only, never secret values.';
COMMENT ON TABLE artifacts IS
    'Persistent OCI artifacts. A build may reference exactly one immutable artifact.';
COMMENT ON TABLE release_artifacts IS
    'Immutable release-to-artifact proof used to prevent releases from failed builds.';
