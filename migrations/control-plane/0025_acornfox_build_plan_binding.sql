-- AcornFox Dockerfile definitions are immutable source facts. A build plan may
-- optionally bind to one definition and its exact root Dockerfile digest. The
-- pair stays nullable so historical plans remain readable without backfill.
ALTER TABLE build_plans
    ADD COLUMN IF NOT EXISTS acornfox_definition_digest text,
    ADD COLUMN IF NOT EXISTS acornfox_dockerfile_digest text;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'build_plans'::regclass
          AND conname = 'build_plans_acornfox_binding_check'
    ) THEN
        ALTER TABLE build_plans
            ADD CONSTRAINT build_plans_acornfox_binding_check CHECK (
                (acornfox_definition_digest IS NULL AND acornfox_dockerfile_digest IS NULL)
                OR (
                    acornfox_definition_digest IS NOT NULL
                    AND acornfox_dockerfile_digest IS NOT NULL
                    AND acornfox_definition_digest ~ '^sha256:[0-9A-Fa-f]{64}$'
                    AND acornfox_dockerfile_digest ~ '^sha256:[0-9A-Fa-f]{64}$'
                    AND build_kind = 'dockerfile'
                    AND context_path = '.'
                    AND dockerfile_path = 'Dockerfile'
                    AND static_runtime_digest IS NULL
                    AND output_contract @> '{"format":"oci","retention":"persistent"}'::jsonb
                )
            );
    END IF;
END $$;
