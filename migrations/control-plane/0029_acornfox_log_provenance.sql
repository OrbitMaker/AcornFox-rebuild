-- A public AcornFox runtime log must name the exact durable TaskLogs request
-- that produced it. Generic M4 lifecycle, probe, and control-plane chunks
-- deliberately keep this field NULL and remain internal-only metadata.
ALTER TABLE m4_log_indexes
    ADD COLUMN IF NOT EXISTS log_task_id text REFERENCES task_leases(task_id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'm4_log_indexes'::regclass
           AND conname = 'm4_log_indexes_log_task_runtime_only'
    ) THEN
        ALTER TABLE m4_log_indexes
            ADD CONSTRAINT m4_log_indexes_log_task_runtime_only CHECK (
                log_task_id IS NULL OR category = 'runtime'
            );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS m4_log_indexes_active_runtime_task_idx
    ON m4_log_indexes(log_task_id, deployment_id, created_at DESC, id DESC)
    WHERE category = 'runtime' AND log_task_id IS NOT NULL AND retired_at IS NULL;
