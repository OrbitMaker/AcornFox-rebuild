-- Nullable fields preserve historical build plans as effective offline plans.
-- A controlled-egress identity is meaningful only for a 0025-bound root
-- Dockerfile plan with persistent OCI output; this migration grants no egress.
ALTER TABLE build_plans
    ADD COLUMN IF NOT EXISTS acornfox_network_mode text,
    ADD COLUMN IF NOT EXISTS acornfox_worker_policy_digest text;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'build_plans'::regclass
          AND conname = 'build_plans_acornfox_network_policy_check'
    ) THEN
        ALTER TABLE build_plans
            ADD CONSTRAINT build_plans_acornfox_network_policy_check CHECK (
                (acornfox_network_mode IS NULL AND acornfox_worker_policy_digest IS NULL)
                OR (acornfox_network_mode = 'none' AND acornfox_worker_policy_digest IS NULL)
                OR (
                    acornfox_network_mode IS NOT NULL
                    AND acornfox_network_mode = 'controlled_egress_v1'
                    AND acornfox_worker_policy_digest IS NOT NULL
                    AND acornfox_worker_policy_digest ~ '^sha256:[a-f0-9]{64}$'
                    AND acornfox_definition_digest IS NOT NULL
                    AND acornfox_dockerfile_digest IS NOT NULL
                    AND build_kind = 'dockerfile'
                    AND context_path = '.'
                    AND dockerfile_path = 'Dockerfile'
                    AND static_runtime_digest IS NULL
                    AND output_contract @> '{"format":"oci","retention":"persistent"}'::jsonb
                )
            );
    END IF;
END $$;
