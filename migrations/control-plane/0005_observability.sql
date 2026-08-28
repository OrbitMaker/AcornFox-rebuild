-- G6 observability storage: raw samples are append-only and range
-- partitioned by observation time.  The default partitions keep the schema
-- usable immediately; operations can create/drop daily partitions for the
-- seven-day retention window without rewriting application code.

CREATE TABLE metric_samples (
    observed_at timestamptz NOT NULL,
    sample_identity text NOT NULL,
    sample_fingerprint text NOT NULL,
    sample_id text NOT NULL DEFAULT '',
    application_id text NOT NULL REFERENCES applications(id),
    service_name text NOT NULL,
    release_id text NOT NULL DEFAULT '',
    cpu double precision NOT NULL DEFAULT 0,
    cpu_seconds double precision NOT NULL DEFAULT 0,
    memory_bytes double precision NOT NULL DEFAULT 0,
    disk_bytes double precision NOT NULL DEFAULT 0,
    network_rx_bytes bigint NOT NULL DEFAULT 0 CHECK (network_rx_bytes >= 0),
    network_tx_bytes bigint NOT NULL DEFAULT 0 CHECK (network_tx_bytes >= 0),
    restart_count bigint NOT NULL DEFAULT 0 CHECK (restart_count >= 0),
    exception_count bigint NOT NULL DEFAULT 0 CHECK (exception_count >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (observed_at, sample_identity),
    CHECK (length(trim(application_id)) > 0),
    CHECK (length(trim(service_name)) > 0),
    CHECK (cpu >= 0 AND cpu < 'Infinity'::double precision AND cpu <> 'NaN'::double precision),
    CHECK (cpu_seconds >= 0 AND cpu_seconds < 'Infinity'::double precision AND cpu_seconds <> 'NaN'::double precision),
    CHECK (memory_bytes >= 0 AND memory_bytes < 'Infinity'::double precision AND memory_bytes <> 'NaN'::double precision),
    CHECK (disk_bytes >= 0 AND disk_bytes < 'Infinity'::double precision AND disk_bytes <> 'NaN'::double precision)
) PARTITION BY RANGE (observed_at);

CREATE TABLE metric_samples_default
    PARTITION OF metric_samples DEFAULT;

CREATE INDEX metric_samples_application_service_time_idx
    ON metric_samples (application_id, service_name, observed_at DESC);

CREATE INDEX metric_samples_application_release_time_idx
    ON metric_samples (application_id, release_id, observed_at DESC);

CREATE INDEX metric_samples_service_time_idx
    ON metric_samples (service_name, observed_at DESC);

CREATE INDEX metric_samples_producer_id_idx
    ON metric_samples (sample_id, observed_at)
    WHERE sample_id <> '';

-- Five-minute materialized facts are kept separate from raw observations so
-- query paths can use a compact table while late raw samples remain available
-- for recomputation.  It is range partitioned on the same lifecycle key.
CREATE TABLE usage_aggregates (
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL,
    application_id text NOT NULL REFERENCES applications(id),
    service_name text NOT NULL,
    release_id text NOT NULL DEFAULT '',
    sample_count bigint NOT NULL CHECK (sample_count > 0),
    average_cpu double precision NOT NULL DEFAULT 0,
    peak_cpu double precision NOT NULL DEFAULT 0,
    trend_cpu double precision NOT NULL DEFAULT 0,
    cpu_seconds double precision NOT NULL DEFAULT 0,
    average_memory_bytes double precision NOT NULL DEFAULT 0,
    peak_memory_bytes double precision NOT NULL DEFAULT 0,
    trend_memory_bytes double precision NOT NULL DEFAULT 0,
    memory_byte_seconds double precision NOT NULL DEFAULT 0,
    average_disk_bytes double precision NOT NULL DEFAULT 0,
    peak_disk_bytes double precision NOT NULL DEFAULT 0,
    trend_disk_bytes double precision NOT NULL DEFAULT 0,
    network_rx_bytes bigint NOT NULL DEFAULT 0 CHECK (network_rx_bytes >= 0),
    network_tx_bytes bigint NOT NULL DEFAULT 0 CHECK (network_tx_bytes >= 0),
    restart_count bigint NOT NULL DEFAULT 0 CHECK (restart_count >= 0),
    exception_count bigint NOT NULL DEFAULT 0 CHECK (exception_count >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (window_start, application_id, service_name, release_id),
    CHECK (window_end > window_start),
    CHECK (length(trim(application_id)) > 0),
    CHECK (length(trim(service_name)) > 0),
    CHECK (average_cpu >= 0 AND average_cpu < 'Infinity'::double precision AND average_cpu <> 'NaN'::double precision),
    CHECK (peak_cpu >= 0 AND peak_cpu < 'Infinity'::double precision AND peak_cpu <> 'NaN'::double precision),
    CHECK (average_memory_bytes >= 0 AND average_memory_bytes < 'Infinity'::double precision AND average_memory_bytes <> 'NaN'::double precision),
    CHECK (peak_memory_bytes >= 0 AND peak_memory_bytes < 'Infinity'::double precision AND peak_memory_bytes <> 'NaN'::double precision)
) PARTITION BY RANGE (window_start);

CREATE TABLE usage_aggregates_default
    PARTITION OF usage_aggregates DEFAULT;

CREATE INDEX usage_aggregates_application_service_window_idx
    ON usage_aggregates (application_id, service_name, window_start DESC);

CREATE INDEX usage_aggregates_application_release_window_idx
    ON usage_aggregates (application_id, release_id, window_start DESC);

CREATE FUNCTION reject_observability_row_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER metric_samples_are_immutable
    BEFORE UPDATE OR DELETE ON metric_samples
    FOR EACH ROW EXECUTE FUNCTION reject_observability_row_mutation();

CREATE TRIGGER usage_aggregates_are_immutable
    BEFORE UPDATE OR DELETE ON usage_aggregates
    FOR EACH ROW EXECUTE FUNCTION reject_observability_row_mutation();

COMMENT ON TABLE metric_samples IS
    'Append-only raw observations; create daily range partitions and drop partitions older than seven days.';
COMMENT ON TABLE usage_aggregates IS
    'Append-only time-bucket usage facts; five-minute buckets are the initial query contract.';
COMMENT ON INDEX metric_samples_application_service_time_idx IS
    'Supports application/service/window scans for 100 services over seven days of one-minute samples.';
