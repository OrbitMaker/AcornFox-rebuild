-- OBS-002 independent Docker/cgroup facts. Existing 0014 observations remain
-- readable with empty/zero defaults; newly projected Agent samples populate
-- the immutable container identity, actual limits and process facts.

ALTER TABLE m4_service_observations
    ADD COLUMN IF NOT EXISTS container_id text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS host_port integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS pids_current bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS applied_cpu_millicores bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS applied_memory_bytes bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS applied_pids bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS changed_path_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS cgroup_verified boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS metrics_known boolean NOT NULL DEFAULT false;

ALTER TABLE m4_service_observations
    DROP CONSTRAINT IF EXISTS m4_service_observations_runtime_fact_shape;
ALTER TABLE m4_service_observations
    ADD CONSTRAINT m4_service_observations_runtime_fact_shape CHECK (
        host_port BETWEEN 0 AND 65535
        AND pids_current >= 0
        AND applied_cpu_millicores >= 0
        AND applied_memory_bytes >= 0
        AND applied_pids >= 0
        AND changed_path_count >= 0
        AND (container_id = '' OR container_id ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')
        AND (NOT cgroup_verified OR (metrics_known AND container_id <> '' AND applied_cpu_millicores > 0 AND applied_memory_bytes > 0 AND applied_pids > 0))
    );

CREATE INDEX IF NOT EXISTS m4_service_observations_container_idx
    ON m4_service_observations(container_id, observed_at DESC)
    WHERE container_id <> '';
