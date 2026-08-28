-- M2 service groups are additive immutable facts.  The old M0/M1 tables and
-- readers remain valid; a release with service_group_id = 'legacy' is the
-- compatibility escape hatch for rows written before M2.

CREATE TABLE IF NOT EXISTS service_groups (
    id text PRIMARY KEY,
    application_id text NOT NULL REFERENCES applications(id),
    name text NOT NULL,
    -- M2 identity is a definition revision, not a mutable logical-name row.
    -- These columns are nullable only for rows created by an older pre-M2
    -- checkout; all post-migration inserts are fail-closed by the identity
    -- trigger below.
    definition_id text REFERENCES delivery_definitions(id),
    version bigint,
    config_digest text,
    canonical_digest text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT service_groups_name_not_blank CHECK (length(trim(name)) > 0),
    CONSTRAINT service_groups_id_not_blank CHECK (length(trim(id)) > 0)
);

ALTER TABLE service_groups
    ADD COLUMN IF NOT EXISTS definition_id text REFERENCES delivery_definitions(id),
    ADD COLUMN IF NOT EXISTS version bigint,
    ADD COLUMN IF NOT EXISTS config_digest text,
    ADD COLUMN IF NOT EXISTS canonical_digest text;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'service_groups'::regclass
           AND conname = 'service_groups_identity_shape'
    ) THEN
        ALTER TABLE service_groups
            ADD CONSTRAINT service_groups_identity_shape CHECK (
                (
                    definition_id IS NULL
                    AND version IS NULL
                    AND config_digest IS NULL
                    AND canonical_digest IS NULL
                )
                OR (
                    definition_id IS NOT NULL
                    AND version > 0
                    AND config_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND canonical_digest ~ '^sha256:[0-9a-f]{64}$'
                )
            ) NOT VALID;
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS service_groups_application_name_version_uidx
    ON service_groups(application_id, name, version)
    WHERE definition_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS service_groups_definition_uidx
    ON service_groups(definition_id)
    WHERE definition_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS service_group_specs (
    service_group_id text NOT NULL REFERENCES service_groups(id),
    service_name text NOT NULL,
    sort_order integer NOT NULL,
    role text NOT NULL,
    source_kind text NOT NULL,
    spec jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (service_group_id, service_name),
    UNIQUE (service_group_id, sort_order),
    CONSTRAINT service_group_specs_name_not_blank CHECK (length(trim(service_name)) > 0),
    CONSTRAINT service_group_specs_sort_order_nonnegative CHECK (sort_order >= 0),
    CONSTRAINT service_group_specs_role_allowed CHECK (role IN ('ingress', 'worker', 'stateful', 'one_shot')),
    CONSTRAINT service_group_specs_source_kind_allowed CHECK (source_kind IN ('static', 'dockerfile', 'prebuilt')),
    CONSTRAINT service_group_specs_shape CHECK (
        jsonb_typeof(spec) = 'object'
        AND spec ? 'name'
        AND jsonb_typeof(spec->'name') = 'string'
        AND spec->>'name' = service_name
        AND spec ? 'role'
        AND jsonb_typeof(spec->'role') = 'string'
        AND spec->>'role' = role
        AND spec ? 'source'
        AND jsonb_typeof(spec->'source') = 'object'
        AND spec->'source' ? 'kind'
        AND spec->'source'->>'kind' = source_kind
        AND (
            (
                source_kind = 'static'
                AND spec->'source' ? 'static'
                AND jsonb_typeof(spec->'source'->'static') = 'object'
                AND spec->'source'->'static' ? 'directory'
                AND jsonb_typeof(spec->'source'->'static'->'directory') = 'string'
                AND length(trim(spec->'source'->'static'->>'directory')) > 0
                AND NOT (spec->'source' ? 'dockerfile')
                AND NOT (spec->'source' ? 'prebuilt')
            )
            OR
            (
                source_kind = 'dockerfile'
                AND spec->'source' ? 'dockerfile'
                AND jsonb_typeof(spec->'source'->'dockerfile') = 'object'
                AND spec->'source'->'dockerfile' ? 'context'
                AND jsonb_typeof(spec->'source'->'dockerfile'->'context') = 'string'
                AND length(trim(spec->'source'->'dockerfile'->>'context')) > 0
                AND spec->'source'->'dockerfile' ? 'dockerfile'
                AND jsonb_typeof(spec->'source'->'dockerfile'->'dockerfile') = 'string'
                AND length(trim(spec->'source'->'dockerfile'->>'dockerfile')) > 0
                AND NOT (spec->'source' ? 'static')
                AND NOT (spec->'source' ? 'prebuilt')
            )
            OR
            (
                source_kind = 'prebuilt'
                AND spec->'source' ? 'prebuilt'
                AND jsonb_typeof(spec->'source'->'prebuilt') = 'object'
                AND NOT (spec->'source' ? 'static')
                AND NOT (spec->'source' ? 'dockerfile')
                AND (
                    (
                        spec->'source'->'prebuilt' ? 'reference'
                        AND jsonb_typeof(spec->'source'->'prebuilt'->'reference') = 'string'
                        AND length(trim(spec->'source'->'prebuilt'->>'reference')) > 0
                        AND (
                            NOT (spec->'source'->'prebuilt' ? 'image')
                            OR (
                                coalesce(spec->'source'->'prebuilt'->'image'->>'repository','') = ''
                                AND coalesce(spec->'source'->'prebuilt'->'image'->>'digest','') = ''
                            )
                        )
                    )
                    OR
                    (
                        spec->'source'->'prebuilt' ? 'image'
                        AND jsonb_typeof(spec->'source'->'prebuilt'->'image') = 'object'
                        AND (spec->'source'->'prebuilt'->'image'->>'repository') IS NOT NULL
                        AND (spec->'source'->'prebuilt'->'image'->>'digest') ~ '^sha256:[0-9a-f]{64}$'
                        AND NOT (spec->'source'->'prebuilt' ? 'reference')
                    )
                )
            )
        )
    )
);

CREATE TABLE IF NOT EXISTS service_group_import_reports (
    id text PRIMARY KEY,
    service_group_id text NOT NULL UNIQUE REFERENCES service_groups(id),
    mapped_fields jsonb NOT NULL DEFAULT '[]'::jsonb,
    warnings jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT service_group_import_reports_id_not_blank CHECK (length(trim(id)) > 0),
    CONSTRAINT service_group_import_reports_mapped_array CHECK (jsonb_typeof(mapped_fields) = 'array'),
    CONSTRAINT service_group_import_reports_warnings_array CHECK (jsonb_typeof(warnings) = 'array')
);

-- Named volume claims are immutable group facts.  A release copies the
-- references into m2_release_volume_claims, so a later group revision cannot
-- silently change the data attached to an already-created release.
CREATE TABLE IF NOT EXISTS service_group_volume_claims (
    service_group_id text NOT NULL REFERENCES service_groups(id),
    claim_id text NOT NULL,
    name text NOT NULL,
    size_bytes bigint NOT NULL,
    retain boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (service_group_id, claim_id),
    UNIQUE (service_group_id, name),
    CONSTRAINT service_group_volume_claims_id_not_blank CHECK (length(trim(claim_id)) > 0),
    CONSTRAINT service_group_volume_claims_name_not_blank CHECK (length(trim(name)) > 0),
    CONSTRAINT service_group_volume_claims_name_safe CHECK (name NOT LIKE '/%' AND name NOT LIKE '%..%'),
    CONSTRAINT service_group_volume_claims_size_positive CHECK (size_bytes > 0),
    CONSTRAINT service_group_volume_claims_retained CHECK (retain)
);

CREATE INDEX IF NOT EXISTS service_group_volume_claims_group_idx
    ON service_group_volume_claims(service_group_id, name);

-- A separate request table keeps M2's idempotency contract independent from
-- the generic M0 records.  It is mutable only while a request is completed;
-- the group, specs, report, audit row and outbox event remain immutable facts.
CREATE TABLE IF NOT EXISTS m2_service_group_requests (
    idempotency_key text PRIMARY KEY,
    request_digest text NOT NULL,
    status text NOT NULL,
    service_group_id text REFERENCES service_groups(id),
    import_report_id text REFERENCES service_group_import_reports(id),
    response jsonb,
    failure_reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT m2_service_group_requests_key_not_blank CHECK (length(trim(idempotency_key)) > 0),
    CONSTRAINT m2_service_group_requests_digest_format CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT m2_service_group_requests_status_allowed CHECK (status IN ('in_progress', 'completed', 'failed')),
    CONSTRAINT m2_service_group_requests_state_shape CHECK (
        (status = 'in_progress' AND service_group_id IS NULL AND import_report_id IS NULL AND response IS NULL AND failure_reason IS NULL)
        OR
        (status = 'completed' AND service_group_id IS NOT NULL AND import_report_id IS NOT NULL AND response IS NOT NULL AND failure_reason IS NULL)
        OR
        (status = 'failed' AND service_group_id IS NULL AND import_report_id IS NULL AND response IS NULL AND failure_reason IS NOT NULL AND length(trim(failure_reason)) > 0)
    )
);

CREATE INDEX IF NOT EXISTS service_groups_application_created_idx
    ON service_groups (application_id, created_at DESC, id);

-- A group is an immutable definition revision.  Reusing a display name for
-- a later revision is valid; idempotency is keyed by the caller's request,
-- not by (application_id, name).
ALTER TABLE service_groups
    DROP CONSTRAINT IF EXISTS service_groups_application_id_name_key;

CREATE TABLE IF NOT EXISTS m2_release_service_bindings (
    release_id text NOT NULL REFERENCES releases(id),
    service_name text NOT NULL,
    binding_kind text NOT NULL,
    artifact_id text REFERENCES artifacts(id),
    image_repository text,
    image_digest text,
    resolved_tag text,
    resolved_from text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (release_id, service_name),
    CONSTRAINT m2_release_bindings_service_name_not_blank CHECK (length(trim(service_name)) > 0),
    CONSTRAINT m2_release_bindings_kind_allowed CHECK (binding_kind IN ('artifact', 'resolved_image')),
    CONSTRAINT m2_release_bindings_digest_shape CHECK (
        (binding_kind = 'artifact'
            AND artifact_id IS NOT NULL
            AND image_repository IS NULL
            AND image_digest IS NULL
            AND resolved_tag IS NULL
            AND resolved_from IS NULL)
        OR
        (binding_kind = 'resolved_image'
            AND artifact_id IS NULL
            AND image_repository IS NOT NULL
            AND length(trim(image_repository)) > 0
            AND image_digest ~ '^sha256:[0-9a-f]{64}$'
            AND resolved_from IS NOT NULL
            AND length(trim(resolved_from)) > 0)
    )
);

ALTER TABLE releases
    ADD COLUMN IF NOT EXISTS canonical_digest text NOT NULL DEFAULT 'legacy';

CREATE TABLE IF NOT EXISTS m2_release_runtime_specs (
    release_id text PRIMARY KEY REFERENCES releases(id),
    schema_version text NOT NULL,
    spec jsonb NOT NULL,
    canonical_digest text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT m2_release_runtime_schema_supported CHECK (schema_version = '1'),
    CONSTRAINT m2_release_runtime_spec_object CHECK (jsonb_typeof(spec) = 'object'),
    CONSTRAINT m2_release_runtime_digest_shape CHECK (canonical_digest ~ '^sha256:[0-9a-f]{64}$')
);

CREATE OR REPLACE FUNCTION validate_m2_release_runtime_spec_complete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_release text;
    release_row releases%ROWTYPE;
    runtime_row m2_release_runtime_specs%ROWTYPE;
    expected_count integer;
BEGIN
    target_release := coalesce(to_jsonb(NEW)->>'release_id', to_jsonb(NEW)->>'id');
    SELECT * INTO release_row FROM releases WHERE id = target_release;
    IF release_row.id IS NULL OR release_row.service_group_id = 'legacy' THEN
        RETURN NEW;
    END IF;
    SELECT * INTO runtime_row FROM m2_release_runtime_specs WHERE release_id = target_release;
    IF runtime_row.release_id IS NULL THEN
        RAISE EXCEPTION 'M2 release runtime specification is missing' USING ERRCODE = '23514';
    END IF;
    IF runtime_row.schema_version <> '1'
       OR runtime_row.canonical_digest <> release_row.canonical_digest
       OR runtime_row.spec->>'release_id' <> release_row.id
       OR runtime_row.spec->>'service_group_id' <> release_row.service_group_id
       OR runtime_row.spec->>'application_id' <> release_row.application_id
       OR runtime_row.spec->>'config_digest' <> release_row.config_digest
       OR jsonb_typeof(runtime_row.spec->'services') <> 'array' THEN
        RAISE EXCEPTION 'M2 release runtime identity does not match immutable release' USING ERRCODE = '23514';
    END IF;
    SELECT count(*) INTO expected_count FROM jsonb_object_keys(release_row.service_digests);
    IF jsonb_array_length(runtime_row.spec->'services') <> expected_count OR EXISTS (
        SELECT 1
          FROM jsonb_each_text(release_row.service_digests) digest(service_name,image_digest)
         WHERE NOT EXISTS (
             SELECT 1
               FROM jsonb_array_elements(runtime_row.spec->'services') service
              WHERE service->>'name' = digest.service_name
                AND service->'image'->>'digest' = digest.image_digest
         )
    ) THEN
        RAISE EXCEPTION 'M2 release runtime service digest set is incomplete' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'releases'::regclass
           AND tgname = 'releases_require_m2_runtime_spec'
    ) THEN
        CREATE CONSTRAINT TRIGGER releases_require_m2_runtime_spec
            AFTER INSERT ON releases
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW EXECUTE FUNCTION validate_m2_release_runtime_spec_complete();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'm2_release_runtime_specs'::regclass
           AND tgname = 'm2_release_runtime_specs_require_release'
    ) THEN
        CREATE CONSTRAINT TRIGGER m2_release_runtime_specs_require_release
            AFTER INSERT ON m2_release_runtime_specs
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW EXECUTE FUNCTION validate_m2_release_runtime_spec_complete();
    END IF;
END
$$;

-- These are immutable release references used by restart/recovery and GC.
-- They intentionally point to the release/group facts rather than to mutable
-- deployment state.  Data claims are retained by default; image protections
-- remain until their owning release is explicitly eligible for collection.
CREATE TABLE IF NOT EXISTS m2_release_volume_claims (
    release_id text NOT NULL REFERENCES releases(id),
    claim_id text NOT NULL,
    name text NOT NULL,
    size_bytes bigint NOT NULL,
    retain boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (release_id, claim_id),
    UNIQUE (release_id, name),
    CONSTRAINT m2_release_volume_claims_id_not_blank CHECK (length(trim(claim_id)) > 0),
    CONSTRAINT m2_release_volume_claims_name_not_blank CHECK (length(trim(name)) > 0),
    CONSTRAINT m2_release_volume_claims_size_positive CHECK (size_bytes > 0),
    CONSTRAINT m2_release_volume_claims_retained CHECK (retain)
);

CREATE TABLE IF NOT EXISTS m2_release_rollouts (
    release_id text PRIMARY KEY REFERENCES releases(id),
    mode text NOT NULL,
    previous_release_id text REFERENCES releases(id),
    previous_deployment_id text,
    preserve_old_until_healthy boolean NOT NULL DEFAULT false,
    downtime_approved boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT m2_release_rollouts_mode_allowed CHECK (mode IN ('initial', 'rolling', 'recreate')),
    CONSTRAINT m2_release_rollouts_shape CHECK (
        (mode = 'initial' AND previous_release_id IS NULL AND previous_deployment_id IS NULL AND NOT preserve_old_until_healthy AND NOT downtime_approved)
        OR
        (mode = 'rolling' AND previous_release_id IS NOT NULL AND previous_deployment_id IS NOT NULL AND preserve_old_until_healthy AND NOT downtime_approved)
        OR
        (mode = 'recreate' AND previous_release_id IS NOT NULL AND previous_deployment_id IS NOT NULL AND NOT preserve_old_until_healthy AND downtime_approved)
    )
);

CREATE TABLE IF NOT EXISTS m2_release_image_protections (
    release_id text NOT NULL REFERENCES releases(id),
    image_repository text NOT NULL,
    image_digest text NOT NULL,
    reason text NOT NULL,
    protected_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (release_id, image_repository, image_digest),
    CONSTRAINT m2_release_image_protections_repository_not_blank CHECK (length(trim(image_repository)) > 0),
    CONSTRAINT m2_release_image_protections_digest_shape CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT m2_release_image_protections_reason_not_blank CHECK (length(trim(reason)) > 0)
);

CREATE INDEX IF NOT EXISTS m2_release_image_protections_gc_idx
    ON m2_release_image_protections(image_repository, image_digest, protected_until);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'releases'::regclass
           AND conname = 'releases_m2_canonical_digest_shape'
    ) THEN
        ALTER TABLE releases
            ADD CONSTRAINT releases_m2_canonical_digest_shape CHECK (
                canonical_digest = 'legacy'
                OR canonical_digest ~ '^sha256:[0-9a-f]{64}$'
            );
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS m2_release_service_bindings_release_kind_idx
    ON m2_release_service_bindings (release_id, binding_kind, service_name);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'm2_release_service_bindings'::regclass
           AND conname = 'm2_release_bindings_service_name_not_blank'
    ) THEN
        ALTER TABLE m2_release_service_bindings
            ADD CONSTRAINT m2_release_bindings_service_name_not_blank
            CHECK (length(trim(service_name)) > 0);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'm2_release_service_bindings'::regclass
           AND conname = 'm2_release_bindings_kind_allowed'
    ) THEN
        ALTER TABLE m2_release_service_bindings
            ADD CONSTRAINT m2_release_bindings_kind_allowed
            CHECK (binding_kind IN ('artifact', 'resolved_image'));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'm2_release_service_bindings'::regclass
           AND conname = 'm2_release_bindings_digest_shape'
    ) THEN
        ALTER TABLE m2_release_service_bindings
            ADD CONSTRAINT m2_release_bindings_digest_shape
            CHECK (
                (binding_kind = 'artifact' AND artifact_id IS NOT NULL AND image_repository IS NULL AND image_digest IS NULL AND resolved_tag IS NULL AND resolved_from IS NULL)
                OR
                (binding_kind = 'resolved_image' AND artifact_id IS NULL AND image_repository IS NOT NULL AND length(trim(image_repository)) > 0 AND image_digest ~ '^sha256:[0-9a-f]{64}$' AND resolved_from IS NOT NULL AND length(trim(resolved_from)) > 0)
            );
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION reject_m2_release_binding_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'm2_release_service_bindings'::regclass
           AND tgname = 'm2_release_service_bindings_are_immutable'
    ) THEN
        CREATE TRIGGER m2_release_service_bindings_are_immutable
            BEFORE UPDATE OR DELETE ON m2_release_service_bindings
            FOR EACH ROW EXECUTE FUNCTION reject_m2_release_binding_mutation();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'm2_release_runtime_specs'::regclass
           AND tgname = 'm2_release_runtime_specs_are_immutable'
    ) THEN
        CREATE TRIGGER m2_release_runtime_specs_are_immutable
            BEFORE UPDATE OR DELETE ON m2_release_runtime_specs
            FOR EACH ROW EXECUTE FUNCTION reject_m2_release_binding_mutation();
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS service_group_specs_group_order_idx
    ON service_group_specs (service_group_id, sort_order, service_name);

CREATE INDEX IF NOT EXISTS m2_service_group_requests_updated_idx
    ON m2_service_group_requests (updated_at, idempotency_key);

-- The SQL files are normally applied once by the checksum migrator, but the
-- guards below make a direct re-run safe as well and fail closed if an older
-- database has an incomplete shape.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'service_groups'::regclass
           AND conname = 'service_groups_name_not_blank'
    ) THEN
        ALTER TABLE service_groups
            ADD CONSTRAINT service_groups_name_not_blank
            CHECK (length(trim(name)) > 0);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'service_groups'::regclass
           AND conname = 'service_groups_id_not_blank'
    ) THEN
        ALTER TABLE service_groups
            ADD CONSTRAINT service_groups_id_not_blank
            CHECK (length(trim(id)) > 0);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'service_group_specs'::regclass
           AND conname = 'service_group_specs_name_not_blank'
    ) THEN
        ALTER TABLE service_group_specs
            ADD CONSTRAINT service_group_specs_name_not_blank
            CHECK (length(trim(service_name)) > 0);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'service_group_specs'::regclass
           AND conname = 'service_group_specs_sort_order_nonnegative'
    ) THEN
        ALTER TABLE service_group_specs
            ADD CONSTRAINT service_group_specs_sort_order_nonnegative
            CHECK (sort_order >= 0);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'service_group_specs'::regclass
           AND conname = 'service_group_specs_role_allowed'
    ) THEN
        ALTER TABLE service_group_specs
            ADD CONSTRAINT service_group_specs_role_allowed
            CHECK (role IN ('ingress', 'worker', 'stateful', 'one_shot'));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'service_group_specs'::regclass
           AND conname = 'service_group_specs_source_kind_allowed'
    ) THEN
        ALTER TABLE service_group_specs
            ADD CONSTRAINT service_group_specs_source_kind_allowed
            CHECK (source_kind IN ('static', 'dockerfile', 'prebuilt'));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'service_group_specs'::regclass
           AND conname = 'service_group_specs_shape'
    ) THEN
        ALTER TABLE service_group_specs
            ADD CONSTRAINT service_group_specs_shape
            CHECK (
                jsonb_typeof(spec) = 'object'
                AND spec ? 'name'
                AND jsonb_typeof(spec->'name') = 'string'
                AND spec->>'name' = service_name
                AND spec ? 'role'
                AND jsonb_typeof(spec->'role') = 'string'
                AND spec->>'role' = role
                AND spec ? 'source'
                AND jsonb_typeof(spec->'source') = 'object'
                AND spec->'source' ? 'kind'
                AND spec->'source'->>'kind' = source_kind
            );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'service_group_import_reports'::regclass
           AND conname = 'service_group_import_reports_mapped_array'
    ) THEN
        ALTER TABLE service_group_import_reports
            ADD CONSTRAINT service_group_import_reports_mapped_array
            CHECK (jsonb_typeof(mapped_fields) = 'array');
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'service_group_import_reports'::regclass
           AND conname = 'service_group_import_reports_warnings_array'
    ) THEN
        ALTER TABLE service_group_import_reports
            ADD CONSTRAINT service_group_import_reports_warnings_array
            CHECK (jsonb_typeof(warnings) = 'array');
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'm2_service_group_requests'::regclass
           AND conname = 'm2_service_group_requests_digest_format'
    ) THEN
        ALTER TABLE m2_service_group_requests
            ADD CONSTRAINT m2_service_group_requests_digest_format
            CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$');
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'm2_service_group_requests'::regclass
           AND conname = 'm2_service_group_requests_status_allowed'
    ) THEN
        ALTER TABLE m2_service_group_requests
            ADD CONSTRAINT m2_service_group_requests_status_allowed
            CHECK (status IN ('in_progress', 'completed', 'failed'));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'm2_service_group_requests'::regclass
           AND conname = 'm2_service_group_requests_state_shape'
    ) THEN
        ALTER TABLE m2_service_group_requests
            ADD CONSTRAINT m2_service_group_requests_state_shape
            CHECK (
                (status = 'in_progress' AND service_group_id IS NULL AND import_report_id IS NULL AND response IS NULL AND failure_reason IS NULL)
                OR
                (status = 'completed' AND service_group_id IS NOT NULL AND import_report_id IS NOT NULL AND response IS NOT NULL AND failure_reason IS NULL)
                OR
                (status = 'failed' AND service_group_id IS NULL AND import_report_id IS NULL AND response IS NULL AND failure_reason IS NOT NULL AND length(trim(failure_reason)) > 0)
            );
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION reject_m2_service_group_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$$;

CREATE OR REPLACE FUNCTION validate_m2_service_group_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    definition_application text;
    definition_version bigint;
BEGIN
    -- Existing rows from an older checkout are intentionally readable, but a
    -- new row must carry the complete immutable M2 identity.  This prevents a
    -- direct SQL writer from bypassing the Go repository contract.
    IF NEW.definition_id IS NULL
       OR NEW.version IS NULL
       OR NEW.config_digest IS NULL
       OR NEW.canonical_digest IS NULL THEN
        RAISE EXCEPTION 'M2 service group identity is required'
            USING ERRCODE = '23514';
    END IF;
    SELECT application_id, version
      INTO definition_application, definition_version
      FROM delivery_definitions
     WHERE id = NEW.definition_id;
    IF definition_application IS NULL THEN
        RAISE EXCEPTION 'M2 service group definition does not exist'
            USING ERRCODE = '23503';
    END IF;
    IF definition_application <> NEW.application_id THEN
        RAISE EXCEPTION 'service group application does not match definition application'
            USING ERRCODE = '23514';
    END IF;
    IF definition_version <> NEW.version THEN
        RAISE EXCEPTION 'service group version does not match definition version'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION reject_m2_release_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF COALESCE(OLD.service_group_id, 'legacy') <> 'legacy' THEN
        RAISE EXCEPTION 'M2 release rows are immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN OLD;
END;
$$;

CREATE OR REPLACE FUNCTION reject_m2_release_reference_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$$;

CREATE OR REPLACE FUNCTION validate_m2_release_reference()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    release_group text;
    release_app text;
    expected_digest text;
    expected_repository text;
    previous_app text;
    claim_exists boolean;
BEGIN
    SELECT service_group_id, application_id
      INTO release_group, release_app
      FROM releases
     WHERE id = NEW.release_id;
    IF release_group IS NULL OR release_group = 'legacy' THEN
        RETURN NEW;
    END IF;

    IF TG_TABLE_NAME = 'm2_release_volume_claims' THEN
        SELECT EXISTS (
            SELECT 1 FROM service_group_volume_claims claim
             WHERE claim.service_group_id = release_group
               AND claim.claim_id = NEW.claim_id
               AND claim.name = NEW.name
               AND claim.size_bytes = NEW.size_bytes
               AND claim.retain = NEW.retain
        ) INTO claim_exists;
        IF NOT claim_exists THEN
            RAISE EXCEPTION 'release volume claim is not declared by its service group'
                USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'm2_release_rollouts' THEN
        IF NEW.previous_release_id IS NOT NULL THEN
            SELECT application_id INTO previous_app FROM releases WHERE id = NEW.previous_release_id;
            IF previous_app IS NULL OR previous_app <> release_app THEN
                RAISE EXCEPTION 'rollout previous release belongs to another application'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
    ELSIF TG_TABLE_NAME = 'm2_release_image_protections' THEN
        SELECT binding.image_digest, binding.image_repository
          INTO expected_digest, expected_repository
          FROM m2_release_service_bindings binding
         WHERE binding.release_id = NEW.release_id
           AND binding.binding_kind = 'resolved_image'
           AND binding.image_repository = NEW.image_repository
           AND binding.image_digest = NEW.image_digest
         LIMIT 1;
        IF expected_digest IS NULL THEN
            SELECT artifact.image_digest, artifact.image_repository
              INTO expected_digest, expected_repository
              FROM m2_release_service_bindings binding
              JOIN artifacts artifact ON artifact.id = binding.artifact_id
             WHERE binding.release_id = NEW.release_id
               AND artifact.image_repository = NEW.image_repository
               AND artifact.image_digest = NEW.image_digest
             LIMIT 1;
        END IF;
        IF expected_digest IS NULL OR expected_repository IS DISTINCT FROM NEW.image_repository THEN
            RAISE EXCEPTION 'image protection reference is not part of the immutable release'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'service_groups'::regclass
           AND tgname = 'service_groups_are_immutable'
    ) THEN
        CREATE TRIGGER service_groups_are_immutable
            BEFORE UPDATE OR DELETE ON service_groups
            FOR EACH ROW EXECUTE FUNCTION reject_m2_service_group_mutation();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'service_group_specs'::regclass
           AND tgname = 'service_group_specs_are_immutable'
    ) THEN
        CREATE TRIGGER service_group_specs_are_immutable
            BEFORE UPDATE OR DELETE ON service_group_specs
            FOR EACH ROW EXECUTE FUNCTION reject_m2_service_group_mutation();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'service_group_import_reports'::regclass
           AND tgname = 'service_group_import_reports_are_immutable'
    ) THEN
        CREATE TRIGGER service_group_import_reports_are_immutable
            BEFORE UPDATE OR DELETE ON service_group_import_reports
            FOR EACH ROW EXECUTE FUNCTION reject_m2_service_group_mutation();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'service_groups'::regclass
           AND tgname = 'service_groups_require_m2_identity'
    ) THEN
        CREATE TRIGGER service_groups_require_m2_identity
            BEFORE INSERT ON service_groups
            FOR EACH ROW EXECUTE FUNCTION validate_m2_service_group_identity();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'releases'::regclass
           AND tgname = 'm2_releases_are_immutable'
    ) THEN
        CREATE TRIGGER m2_releases_are_immutable
            BEFORE UPDATE OR DELETE ON releases
            FOR EACH ROW EXECUTE FUNCTION reject_m2_release_mutation();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'service_group_volume_claims'::regclass
           AND tgname = 'service_group_volume_claims_are_immutable'
    ) THEN
        CREATE TRIGGER service_group_volume_claims_are_immutable
            BEFORE UPDATE OR DELETE ON service_group_volume_claims
            FOR EACH ROW EXECUTE FUNCTION reject_m2_release_reference_mutation();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'm2_release_volume_claims'::regclass
           AND tgname = 'm2_release_volume_claims_are_immutable'
    ) THEN
        CREATE TRIGGER m2_release_volume_claims_are_immutable
            BEFORE UPDATE OR DELETE ON m2_release_volume_claims
            FOR EACH ROW EXECUTE FUNCTION reject_m2_release_reference_mutation();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'm2_release_rollouts'::regclass
           AND tgname = 'm2_release_rollouts_are_immutable'
    ) THEN
        CREATE TRIGGER m2_release_rollouts_are_immutable
            BEFORE UPDATE OR DELETE ON m2_release_rollouts
            FOR EACH ROW EXECUTE FUNCTION reject_m2_release_reference_mutation();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'm2_release_image_protections'::regclass
           AND tgname = 'm2_release_image_protections_are_immutable'
    ) THEN
        CREATE TRIGGER m2_release_image_protections_are_immutable
            BEFORE UPDATE OR DELETE ON m2_release_image_protections
            FOR EACH ROW EXECUTE FUNCTION reject_m2_release_reference_mutation();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'm2_release_volume_claims'::regclass
           AND tgname = 'm2_release_volume_claims_require_declared_claim'
    ) THEN
        CREATE TRIGGER m2_release_volume_claims_require_declared_claim
            BEFORE INSERT ON m2_release_volume_claims
            FOR EACH ROW EXECUTE FUNCTION validate_m2_release_reference();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'm2_release_rollouts'::regclass
           AND tgname = 'm2_release_rollouts_require_same_application'
    ) THEN
        CREATE TRIGGER m2_release_rollouts_require_same_application
            BEFORE INSERT ON m2_release_rollouts
            FOR EACH ROW EXECUTE FUNCTION validate_m2_release_reference();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'm2_release_image_protections'::regclass
           AND tgname = 'm2_release_image_protections_require_release_image'
    ) THEN
        CREATE TRIGGER m2_release_image_protections_require_release_image
            BEFORE INSERT ON m2_release_image_protections
            FOR EACH ROW EXECUTE FUNCTION validate_m2_release_reference();
    END IF;
END
$$;

-- A release's JSON digest map is a complete, immutable service-group set.
-- Legacy M1 rows retain their old semantics; every M2 release is checked
-- against the persisted group before the insert is allowed.
CREATE OR REPLACE FUNCTION validate_m2_release_digest_set()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_count integer;
    actual_count integer;
    group_application text;
    definition_application text;
    group_definition text;
    group_version bigint;
    group_config_digest text;
    group_canonical_digest text;
BEGIN
    IF NEW.service_group_id IS NULL OR NEW.service_group_id = 'legacy' THEN
        RETURN NEW;
    END IF;

    SELECT application_id, definition_id, version, config_digest, canonical_digest
      INTO group_application, group_definition, group_version, group_config_digest, group_canonical_digest
      FROM service_groups
     WHERE id = NEW.service_group_id;
    IF group_application IS NULL OR group_application <> NEW.application_id THEN
        RAISE EXCEPTION 'release application does not match service group application'
            USING ERRCODE = '23514';
    END IF;
    IF group_definition IS NULL
       OR group_definition <> NEW.definition_id
       OR group_version <> NEW.version
       OR group_config_digest <> NEW.config_digest THEN
        RAISE EXCEPTION 'release identity does not match service group definition revision'
            USING ERRCODE = '23514';
    END IF;
    SELECT application_id INTO definition_application
      FROM delivery_definitions
     WHERE id = NEW.definition_id;
    IF definition_application IS NULL OR definition_application <> NEW.application_id THEN
        RAISE EXCEPTION 'release application does not match definition application'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*) INTO expected_count
      FROM service_group_specs
     WHERE service_group_id = NEW.service_group_id;
    IF expected_count = 0 THEN
        RAISE EXCEPTION 'release service group has no persisted services'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*) INTO actual_count FROM jsonb_object_keys(NEW.service_digests);
    IF actual_count <> expected_count THEN
        RAISE EXCEPTION 'release digest set must contain exactly one digest per service'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM service_group_specs spec
         WHERE spec.service_group_id = NEW.service_group_id
           AND NOT (NEW.service_digests ? spec.service_name)
    ) OR EXISTS (
        SELECT 1
          FROM jsonb_object_keys(NEW.service_digests) AS digest(service_name)
         WHERE NOT EXISTS (
             SELECT 1 FROM service_group_specs spec
              WHERE spec.service_group_id = NEW.service_group_id
                AND spec.service_name = digest.service_name
         )
    ) THEN
        RAISE EXCEPTION 'release digest set does not match service group services'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION validate_m2_release_artifacts_complete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_release text;
    release_group text;
    expected_count integer;
    actual_count integer;
    binding_count integer;
BEGIN
    target_release := coalesce(to_jsonb(NEW)->>'release_id', to_jsonb(NEW)->>'id');
    SELECT service_group_id INTO release_group
      FROM releases
     WHERE id = target_release;
    IF release_group IS NULL OR release_group = 'legacy' THEN
        RETURN NEW;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM release_artifacts release_artifact
          JOIN artifacts artifact ON artifact.id = release_artifact.artifact_id
          JOIN builds build ON build.id = artifact.build_id
          JOIN build_plans build_plan ON build_plan.id = build.plan_id
          JOIN source_revisions source ON source.id = build_plan.source_revision_id
          JOIN releases rel ON rel.id = release_artifact.release_id
         WHERE release_artifact.release_id = target_release
           AND source.application_id <> rel.application_id
    ) THEN
        RAISE EXCEPTION 'release artifact provenance application does not match release'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM release_artifacts release_artifact
          JOIN artifacts artifact ON artifact.id = release_artifact.artifact_id
          JOIN builds build ON build.id = artifact.build_id
          JOIN build_plans build_plan ON build_plan.id = build.plan_id
         WHERE release_artifact.release_id = target_release
           AND build_plan.service_name <> release_artifact.service_name
    ) THEN
        RAISE EXCEPTION 'release artifact provenance service does not match release binding'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*) INTO expected_count
      FROM service_group_specs
     WHERE service_group_id = release_group;
    SELECT count(*) INTO actual_count
      FROM release_artifacts
     WHERE release_id = target_release;
    SELECT count(*) INTO binding_count
      FROM m2_release_service_bindings
     WHERE release_id = target_release;

    -- M2 writes one explicit binding for every service.  M1 artifact rows are
    -- accepted as a compatibility fallback for all-artifact groups and are
    -- mirrored by the binding table when a new M2 release is created.
    IF binding_count = 0 THEN
        IF actual_count <> expected_count OR EXISTS (
            SELECT 1 FROM service_group_specs spec
             WHERE spec.service_group_id = release_group
               AND spec.source_kind = 'prebuilt'
        ) THEN
            RAISE EXCEPTION 'release service binding set is incomplete'
                USING ERRCODE = '23514';
        END IF;
    ELSIF binding_count <> expected_count THEN
        RAISE EXCEPTION 'release service binding set is incomplete'
            USING ERRCODE = '23514';
    END IF;

    IF binding_count > 0 AND (EXISTS (
        SELECT 1
          FROM service_group_specs spec
         WHERE spec.service_group_id = release_group
           AND NOT EXISTS (
               SELECT 1 FROM m2_release_service_bindings binding
                WHERE binding.release_id = target_release
                  AND binding.service_name = spec.service_name
           )
    ) OR EXISTS (
        SELECT 1
          FROM m2_release_service_bindings binding
         WHERE binding.release_id = target_release
           AND NOT EXISTS (
               SELECT 1 FROM service_group_specs spec
                WHERE spec.service_group_id = release_group
                  AND spec.service_name = binding.service_name
           )
    )) THEN
        RAISE EXCEPTION 'release service binding set does not match service group services'
            USING ERRCODE = '23514';
    END IF;

    IF binding_count > 0 AND EXISTS (
        SELECT 1
          FROM service_group_specs spec
          JOIN m2_release_service_bindings binding
            ON binding.release_id = target_release
           AND binding.service_name = spec.service_name
         WHERE spec.service_group_id = release_group
           AND ((spec.source_kind = 'prebuilt' AND binding.binding_kind <> 'resolved_image')
             OR (spec.source_kind <> 'prebuilt' AND binding.binding_kind <> 'artifact'))
    ) THEN
        RAISE EXCEPTION 'release service binding provenance does not match service source'
            USING ERRCODE = '23514';
    END IF;

    IF binding_count > 0 AND EXISTS (
        SELECT 1
          FROM m2_release_service_bindings binding
         WHERE binding.release_id = target_release
           AND binding.binding_kind = 'artifact'
           AND NOT EXISTS (
               SELECT 1 FROM release_artifacts artifact
                WHERE artifact.release_id = target_release
                  AND artifact.service_name = binding.service_name
                  AND artifact.artifact_id = binding.artifact_id
           )
    ) THEN
        RAISE EXCEPTION 'artifact service binding is missing its compatibility artifact row'
            USING ERRCODE = '23514';
    END IF;

    IF binding_count > 0 AND EXISTS (
        SELECT 1
          FROM release_artifacts artifact
         WHERE artifact.release_id = target_release
           AND NOT EXISTS (
               SELECT 1 FROM m2_release_service_bindings binding
                WHERE binding.release_id = target_release
                  AND binding.service_name = artifact.service_name
           )
    ) THEN
        RAISE EXCEPTION 'release artifact row is missing its service binding'
            USING ERRCODE = '23514';
    END IF;

    IF binding_count > 0 AND EXISTS (
        SELECT 1
          FROM m2_release_service_bindings binding
          JOIN releases rel ON rel.id = binding.release_id
         WHERE binding.release_id = target_release
           AND binding.binding_kind = 'resolved_image'
           AND (rel.service_digests->>binding.service_name) <> binding.image_digest
    ) THEN
        RAISE EXCEPTION 'resolved image binding digest does not match release digest set'
            USING ERRCODE = '23514';
    END IF;

    IF binding_count = 0 AND EXISTS (
        SELECT 1
          FROM release_artifacts artifact
         WHERE artifact.release_id = target_release
           AND NOT EXISTS (
               SELECT 1 FROM service_group_specs spec
                WHERE spec.service_group_id = release_group
                  AND spec.service_name = artifact.service_name
           )
    ) THEN
        RAISE EXCEPTION 'release artifact set does not match service group services'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM release_artifacts artifact
          JOIN artifacts image ON image.id = artifact.artifact_id
          JOIN releases rel ON rel.id = artifact.release_id
         WHERE artifact.release_id = target_release
           AND image.image_digest <> rel.service_digests->>artifact.service_name
    ) THEN
        RAISE EXCEPTION 'release artifact digest does not match release digest set'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'releases'::regclass
           AND tgname = 'releases_require_m2_digest_set'
    ) THEN
        CREATE TRIGGER releases_require_m2_digest_set
            BEFORE INSERT ON releases
            FOR EACH ROW EXECUTE FUNCTION validate_m2_release_digest_set();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'releases'::regclass
           AND tgname = 'releases_require_m2_artifacts'
    ) THEN
        CREATE CONSTRAINT TRIGGER releases_require_m2_artifacts
            AFTER INSERT ON releases
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW EXECUTE FUNCTION validate_m2_release_artifacts_complete();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'release_artifacts'::regclass
           AND tgname = 'release_artifacts_require_m2_complete_set'
    ) THEN
        CREATE CONSTRAINT TRIGGER release_artifacts_require_m2_complete_set
            AFTER INSERT ON release_artifacts
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW EXECUTE FUNCTION validate_m2_release_artifacts_complete();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'm2_release_service_bindings'::regclass
           AND tgname = 'm2_release_bindings_require_complete_set'
    ) THEN
        CREATE CONSTRAINT TRIGGER m2_release_bindings_require_complete_set
            AFTER INSERT ON m2_release_service_bindings
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW EXECUTE FUNCTION validate_m2_release_artifacts_complete();
    END IF;
END
$$;

COMMENT ON TABLE service_groups IS
    'M2 immutable normalized service-group definitions; legacy M1 rows are not rewritten.';
COMMENT ON TABLE service_group_specs IS
    'M2 immutable ServiceSpec rows. spec is the validated controlled union, never raw Compose input.';
COMMENT ON TABLE service_group_import_reports IS
    'Immutable Compose/source import mapping and warning report for one ServiceGroup.';
COMMENT ON TABLE m2_service_group_requests IS
    'M2 durable idempotency records. A completed request points to one immutable group and import report.';
