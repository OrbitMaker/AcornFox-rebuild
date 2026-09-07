CREATE TABLE IF NOT EXISTS acornfox_source_updates (
    application_id text NOT NULL REFERENCES applications(id),
    idempotency_key text NOT NULL,
    request_digest text NOT NULL,
    base_source_revision_id text NOT NULL REFERENCES source_revisions(id),
    requested_ref text NOT NULL,
    state text NOT NULL,
    source_revision_id text REFERENCES source_revisions(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (application_id,idempotency_key),
    CHECK (length(trim(idempotency_key)) > 0 AND request_digest ~ '^sha256:[0-9a-f]{64}$' AND length(trim(requested_ref)) > 0),
    CHECK (state IN ('preparing','imported','failed','unknown')),
    CHECK ((state = 'imported') = (source_revision_id IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS acornfox_source_updates_one_preparing_per_app
    ON acornfox_source_updates(application_id) WHERE state='preparing';
