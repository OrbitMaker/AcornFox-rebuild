-- M5 local usage facts. This migration is additive and intentionally excludes
-- commercial, regional, billing, and AI concepts. Actual observations and
-- configured limits are stored in separate columns.
CREATE TABLE IF NOT EXISTS m5_usage_raw_facts (
    source_id text PRIMARY KEY,
    source_fingerprint text NOT NULL,
    application_id text NOT NULL REFERENCES applications(id),
    environment_id text NOT NULL DEFAULT '',
    deployment_id text NOT NULL DEFAULT '',
    release_id text NOT NULL DEFAULT '',
    service_name text NOT NULL,
    observed_at timestamptz NOT NULL,
    cpu_seconds double precision NOT NULL DEFAULT 0 CHECK (cpu_seconds >= 0),
    memory_byte_seconds double precision NOT NULL DEFAULT 0 CHECK (memory_byte_seconds >= 0),
    runtime_seconds double precision NOT NULL DEFAULT 0 CHECK (runtime_seconds >= 0),
    cpu_millicores bigint NOT NULL DEFAULT 0 CHECK (cpu_millicores >= 0),
    memory_bytes bigint NOT NULL DEFAULT 0 CHECK (memory_bytes >= 0),
    disk_bytes bigint NOT NULL DEFAULT 0 CHECK (disk_bytes >= 0),
    network_rx_bytes bigint NOT NULL DEFAULT 0 CHECK (network_rx_bytes >= 0),
    network_tx_bytes bigint NOT NULL DEFAULT 0 CHECK (network_tx_bytes >= 0),
    restart_count bigint NOT NULL DEFAULT 0 CHECK (restart_count >= 0),
    exception_count bigint NOT NULL DEFAULT 0 CHECK (exception_count >= 0),
    limit_cpu_millicores bigint NOT NULL DEFAULT 0 CHECK (limit_cpu_millicores >= 0),
    limit_memory_bytes bigint NOT NULL DEFAULT 0 CHECK (limit_memory_bytes >= 0),
    limit_disk_bytes bigint NOT NULL DEFAULT 0 CHECK (limit_disk_bytes >= 0),
    limit_pids bigint NOT NULL DEFAULT 0 CHECK (limit_pids >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (length(trim(source_id)) > 0 AND length(trim(application_id)) > 0 AND length(trim(service_name)) > 0)
);
CREATE INDEX IF NOT EXISTS m5_usage_raw_scope_time_idx ON m5_usage_raw_facts(application_id, service_name, release_id, observed_at DESC);
CREATE FUNCTION m5_reject_usage_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('open_card.m5_retention', true) = 'approved' THEN RETURN OLD; END IF;
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME USING ERRCODE = '55000';
END; $$;
CREATE TRIGGER m5_usage_raw_facts_immutable BEFORE UPDATE OR DELETE ON m5_usage_raw_facts FOR EACH ROW EXECUTE FUNCTION m5_reject_usage_mutation();

-- Revisions make late arrivals safe: compaction appends a new materialized
-- fact instead of mutating a previously recorded bucket.
CREATE TABLE IF NOT EXISTS m5_usage_bucket_facts (
    application_id text NOT NULL REFERENCES applications(id), environment_id text NOT NULL DEFAULT '', deployment_id text NOT NULL DEFAULT '', release_id text NOT NULL DEFAULT '', service_name text NOT NULL,
    window_start timestamptz NOT NULL, window_end timestamptz NOT NULL, revision integer NOT NULL,
    source_digest text NOT NULL, sample_count bigint NOT NULL CHECK (sample_count > 0), cpu_seconds double precision NOT NULL CHECK (cpu_seconds >= 0), memory_byte_seconds double precision NOT NULL CHECK (memory_byte_seconds >= 0), disk_byte_seconds double precision NOT NULL CHECK (disk_byte_seconds >= 0), runtime_seconds double precision NOT NULL CHECK (runtime_seconds >= 0), average_cpu_millicores double precision NOT NULL CHECK (average_cpu_millicores >= 0), average_memory_bytes double precision NOT NULL CHECK (average_memory_bytes >= 0), average_disk_bytes double precision NOT NULL CHECK (average_disk_bytes >= 0), trend_cpu_millicores_per_second double precision NOT NULL, trend_memory_bytes_per_second double precision NOT NULL, trend_disk_bytes_per_second double precision NOT NULL, network_rx_bytes bigint NOT NULL CHECK (network_rx_bytes >= 0), network_tx_bytes bigint NOT NULL CHECK (network_tx_bytes >= 0), restart_count bigint NOT NULL CHECK (restart_count >= 0), exception_count bigint NOT NULL CHECK (exception_count >= 0), peak_cpu_millicores bigint NOT NULL CHECK (peak_cpu_millicores >= 0), peak_memory_bytes bigint NOT NULL CHECK (peak_memory_bytes >= 0), peak_disk_bytes bigint NOT NULL CHECK (peak_disk_bytes >= 0), limit_cpu_millicores bigint NOT NULL CHECK (limit_cpu_millicores >= 0), limit_memory_bytes bigint NOT NULL CHECK (limit_memory_bytes >= 0), limit_disk_bytes bigint NOT NULL CHECK (limit_disk_bytes >= 0), limit_pids bigint NOT NULL CHECK (limit_pids >= 0), created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(application_id, environment_id, deployment_id, release_id, service_name, window_start, revision), CHECK (window_end > window_start)
);
CREATE INDEX IF NOT EXISTS m5_usage_bucket_query_idx ON m5_usage_bucket_facts(application_id, service_name, release_id, window_start DESC, revision DESC);
CREATE TRIGGER m5_usage_bucket_facts_immutable BEFORE UPDATE OR DELETE ON m5_usage_bucket_facts FOR EACH ROW EXECUTE FUNCTION m5_reject_usage_mutation();
CREATE OR REPLACE VIEW m5_usage_bucket_current AS SELECT * FROM (SELECT b.*, row_number() OVER (PARTITION BY application_id,environment_id,deployment_id,release_id,service_name,window_start ORDER BY revision DESC) AS current_rank FROM m5_usage_bucket_facts b) ranked WHERE current_rank=1;

CREATE TABLE IF NOT EXISTS m5_usage_anomalies (id text PRIMARY KEY, source_id text NOT NULL REFERENCES m5_usage_raw_facts(source_id), application_id text NOT NULL REFERENCES applications(id), kind text NOT NULL, observed_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(source_id, kind));
CREATE INDEX IF NOT EXISTS m5_usage_anomalies_app_time_idx ON m5_usage_anomalies(application_id, observed_at DESC);
CREATE TRIGGER m5_usage_anomalies_immutable BEFORE UPDATE OR DELETE ON m5_usage_anomalies FOR EACH ROW EXECUTE FUNCTION m5_reject_usage_mutation();

CREATE TABLE IF NOT EXISTS m5_usage_storage_state (singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), total_bytes bigint NOT NULL CHECK(total_bytes > 0), used_bytes bigint NOT NULL CHECK(used_bytes >= 0 AND used_bytes <= total_bytes), hard_watermark_bytes bigint NOT NULL CHECK(hard_watermark_bytes >= 0), observed_at timestamptz NOT NULL);
