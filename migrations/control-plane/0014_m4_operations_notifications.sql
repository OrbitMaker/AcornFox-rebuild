-- M4 operations facts. Notification credentials remain opaque
-- SecretProvider references; payloads and response bodies are intentionally
-- absent from this control-plane ledger.

CREATE TABLE IF NOT EXISTS m4_webhook_endpoints (
    id text PRIMARY KEY,
    application_id text NOT NULL REFERENCES applications(id),
    endpoint_url text NOT NULL,
    secret_reference_id text NOT NULL,
	-- Opaque SecretProvider identity; no ciphertext or material is stored.
	secret_name text NOT NULL,
	secret_provider text NOT NULL,
	secret_version text NOT NULL DEFAULT '',
    event_types jsonb NOT NULL DEFAULT '[]'::jsonb,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT m4_webhook_endpoints_id_not_blank CHECK (length(trim(id)) > 0),
    CONSTRAINT m4_webhook_endpoints_url_https CHECK (endpoint_url ~ '^https://'),
    CONSTRAINT m4_webhook_endpoints_secret_reference_not_blank CHECK (length(trim(secret_reference_id)) > 0),
	CONSTRAINT m4_webhook_endpoints_secret_name_not_blank CHECK (length(trim(secret_name)) > 0),
	CONSTRAINT m4_webhook_endpoints_secret_provider_not_blank CHECK (length(trim(secret_provider)) > 0),
    CONSTRAINT m4_webhook_endpoints_event_types_array CHECK (jsonb_typeof(event_types) = 'array')
);

CREATE UNIQUE INDEX IF NOT EXISTS m4_webhook_endpoints_application_url_uidx
    ON m4_webhook_endpoints(application_id, endpoint_url);

-- One row is the durable logical notification. Duplicate input with the same
-- payload digest raises received_count only; a different digest is rejected by
-- the repository before an attempt can be appended.
CREATE TABLE IF NOT EXISTS m4_webhook_events (
    endpoint_id text NOT NULL REFERENCES m4_webhook_endpoints(id),
    delivery_id text NOT NULL UNIQUE,
    event_id text NOT NULL,
    event_type text NOT NULL,
    payload_digest text NOT NULL,
    -- Strictly canonical, already-redacted lifecycle notification JSON only.
    -- Never raw logs, headers, request/response bodies, PEM, or secrets.
    payload jsonb NOT NULL,
    idempotency_key text NOT NULL,
    request_digest text NOT NULL,
    occurred_at timestamptz NOT NULL,
    delivery_status text NOT NULL DEFAULT 'pending',
    received_count bigint NOT NULL DEFAULT 1,
    attempt_count integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz DEFAULT now(),
    lease_owner text,
    lease_until timestamptz,
    last_attempt_at timestamptz,
    delivered_at timestamptz,
    failure_reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(endpoint_id, event_id),
    CONSTRAINT m4_webhook_events_delivery_id_not_blank CHECK (length(trim(delivery_id)) > 0),
    CONSTRAINT m4_webhook_events_event_id_not_blank CHECK (length(trim(event_id)) > 0),
    CONSTRAINT m4_webhook_events_type_not_blank CHECK (length(trim(event_type)) > 0),
    CONSTRAINT m4_webhook_events_digest_shape CHECK (payload_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT m4_webhook_events_payload_shape CHECK (
        jsonb_typeof(payload) = 'object'
        AND payload ?& ARRAY['schema_version','application_id','environment_id','incident_id','kind','severity','message','occurred_at']
        AND (payload - ARRAY['schema_version','application_id','environment_id','incident_id','kind','severity','message','occurred_at']) = '{}'::jsonb
        AND jsonb_typeof(payload->'schema_version') = 'string'
        AND jsonb_typeof(payload->'application_id') = 'string'
        AND jsonb_typeof(payload->'environment_id') = 'string'
        AND jsonb_typeof(payload->'incident_id') = 'string'
        AND jsonb_typeof(payload->'kind') = 'string'
        AND jsonb_typeof(payload->'severity') = 'string'
        AND jsonb_typeof(payload->'message') = 'string'
        AND jsonb_typeof(payload->'occurred_at') = 'string'
    ),
    CONSTRAINT m4_webhook_events_idempotency_not_blank CHECK (length(trim(idempotency_key)) > 0),
    CONSTRAINT m4_webhook_events_request_digest_shape CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT m4_webhook_events_status_allowed CHECK (delivery_status IN ('pending', 'retry_wait', 'delivered', 'failed')),
    CONSTRAINT m4_webhook_events_count_nonnegative CHECK (received_count > 0 AND attempt_count >= 0),
    CONSTRAINT m4_webhook_events_lease_shape CHECK ((lease_owner IS NULL AND lease_until IS NULL) OR (lease_owner IS NOT NULL AND length(trim(lease_owner)) > 0 AND lease_until IS NOT NULL)),
    CONSTRAINT m4_webhook_events_delivery_shape CHECK (
        (delivery_status = 'delivered' AND delivered_at IS NOT NULL AND failure_reason IS NULL AND next_attempt_at IS NULL)
        OR (delivery_status IN ('pending', 'retry_wait') AND delivered_at IS NULL AND next_attempt_at IS NOT NULL)
        OR (delivery_status = 'failed' AND delivered_at IS NULL AND failure_reason IS NOT NULL AND length(trim(failure_reason)) > 0 AND next_attempt_at IS NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS m4_webhook_events_endpoint_idempotency_uidx
    ON m4_webhook_events(endpoint_id, idempotency_key);

CREATE INDEX IF NOT EXISTS m4_webhook_events_pending_idx
    ON m4_webhook_events(next_attempt_at, endpoint_id, event_id)
    WHERE delivery_status IN ('pending', 'retry_wait');

CREATE TABLE IF NOT EXISTS m4_webhook_attempts (
    id text PRIMARY KEY,
    endpoint_id text NOT NULL,
    event_id text NOT NULL,
    attempt_number integer NOT NULL,
    request_digest text NOT NULL,
    status text NOT NULL,
    http_status integer,
    error_code text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT m4_webhook_attempts_id_not_blank CHECK (length(trim(id)) > 0),
    CONSTRAINT m4_webhook_attempts_number_positive CHECK (attempt_number > 0),
    CONSTRAINT m4_webhook_attempts_request_digest_shape CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT m4_webhook_attempts_status_allowed CHECK (status IN ('delivered', 'retryable_failure', 'failed')),
    CONSTRAINT m4_webhook_attempts_http_status_range CHECK (http_status IS NULL OR http_status BETWEEN 100 AND 599),
    CONSTRAINT m4_webhook_attempts_result_shape CHECK (
        (status = 'delivered' AND http_status BETWEEN 200 AND 299 AND error_code IS NULL)
        OR (status IN ('retryable_failure', 'failed') AND (http_status IS NULL OR http_status NOT BETWEEN 200 AND 299))
    ),
    FOREIGN KEY(endpoint_id, event_id) REFERENCES m4_webhook_events(endpoint_id, event_id),
    UNIQUE(endpoint_id, event_id, attempt_number)
);

CREATE INDEX IF NOT EXISTS m4_webhook_attempts_event_idx
    ON m4_webhook_attempts(endpoint_id, event_id, attempt_number DESC);

CREATE OR REPLACE FUNCTION m4_webhook_attempts_are_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'M4 webhook attempts are immutable' USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS m4_webhook_attempts_no_mutation ON m4_webhook_attempts;
CREATE TRIGGER m4_webhook_attempts_no_mutation
BEFORE UPDATE OR DELETE ON m4_webhook_attempts
FOR EACH ROW EXECUTE FUNCTION m4_webhook_attempts_are_immutable();

-- Indexing never copies log content. A path/segment is metadata only, tied to
-- the facts required to render ordinary and operations views from one source.
CREATE TABLE IF NOT EXISTS m4_log_indexes (
    id text PRIMARY KEY,
    application_id text NOT NULL REFERENCES applications(id),
    service_name text NOT NULL,
    release_id text REFERENCES releases(id),
    deployment_id text REFERENCES deployments(id),
    operation_id text REFERENCES operations(id),
    category text NOT NULL,
    path text NOT NULL,
    segment integer NOT NULL,
    byte_size bigint NOT NULL DEFAULT 0,
    retired_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT m4_log_indexes_id_not_blank CHECK (length(trim(id)) > 0),
    CONSTRAINT m4_log_indexes_service_not_blank CHECK (length(trim(service_name)) > 0),
    CONSTRAINT m4_log_indexes_category_allowed CHECK (category IN ('build', 'runtime', 'audit')),
    -- PostgreSQL text itself rejects NUL. Keep the schema check portable and
    -- leave path traversal/ownership validation to the local LogStore layer.
    CONSTRAINT m4_log_indexes_path_not_blank CHECK (length(trim(path)) > 0),
    CONSTRAINT m4_log_indexes_segment_nonnegative CHECK (segment >= 0),
    CONSTRAINT m4_log_indexes_bytes_nonnegative CHECK (byte_size >= 0),
    -- Audit evidence/segments can never be retired by an ordinary log GC.
    CONSTRAINT m4_log_indexes_audit_not_retired CHECK (category <> 'audit' OR retired_at IS NULL),
    UNIQUE(category, path, segment)
);

CREATE INDEX IF NOT EXISTS m4_log_indexes_application_query_idx
    ON m4_log_indexes(application_id, service_name, created_at DESC, id)
    WHERE retired_at IS NULL;
CREATE INDEX IF NOT EXISTS m4_log_indexes_operation_query_idx
    ON m4_log_indexes(operation_id, created_at DESC, id)
    WHERE operation_id IS NOT NULL AND retired_at IS NULL;

CREATE OR REPLACE FUNCTION m4_protect_log_index()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' OR OLD.category = 'audit' OR OLD.retired_at IS NOT NULL OR NEW.retired_at IS NULL THEN
        RAISE EXCEPTION 'M4 log indexes are append-only; audit indexes cannot be retired' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS m4_log_indexes_protect ON m4_log_indexes;
CREATE TRIGGER m4_log_indexes_protect
BEFORE UPDATE OR DELETE ON m4_log_indexes
FOR EACH ROW EXECUTE FUNCTION m4_protect_log_index();

-- M0 already owns the active-operation partial unique index. This additional
-- reader index is not a second lock; it supports a shared ordinary/operator
-- projection without weakening that existing invariant.
CREATE INDEX IF NOT EXISTS operations_m4_application_state_updated_idx
    ON operations(application_id, state, updated_at DESC, id);

-- The operation row remains the source of lifecycle state. This companion
-- record freezes the operator input and terminal result required for an
-- idempotent M4 replay without putting log content or secrets into operations.
CREATE TABLE IF NOT EXISTS m4_operation_requests (
    operation_id text PRIMARY KEY REFERENCES operations(id),
    request_digest text NOT NULL,
    expected_fact_version text NOT NULL,
    actor_id text NOT NULL,
    reason text NOT NULL,
    result jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    CONSTRAINT m4_operation_requests_digest_shape CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT m4_operation_requests_fact_version_not_blank CHECK (length(trim(expected_fact_version)) > 0),
    CONSTRAINT m4_operation_requests_actor_not_blank CHECK (length(trim(actor_id)) > 0),
    CONSTRAINT m4_operation_requests_reason_not_blank CHECK (length(trim(reason)) > 0),
    CONSTRAINT m4_operation_requests_completion_shape CHECK ((result IS NULL AND completed_at IS NULL) OR (result IS NOT NULL AND completed_at IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS m4_operation_requests_digest_uidx
    ON m4_operation_requests(request_digest);

-- Typed service facts are append-only observations produced by the Agent
-- bridge. They are intentionally separate from usage aggregation and carry
-- both health/exit reason and the independent runtime counters needed by M4.
CREATE TABLE IF NOT EXISTS m4_service_observations (
    id text PRIMARY KEY,
    sample_id text NOT NULL UNIQUE,
    application_id text NOT NULL REFERENCES applications(id),
    environment_id text NOT NULL REFERENCES environments(id),
    deployment_id text NOT NULL REFERENCES deployments(id),
    release_id text NOT NULL REFERENCES releases(id),
    service_name text NOT NULL,
    service_role text NOT NULL,
    runtime_status text NOT NULL,
    healthy boolean NOT NULL,
    required boolean NOT NULL,
    exit_reason text,
    cpu_millicores bigint NOT NULL DEFAULT 0,
    memory_bytes bigint NOT NULL DEFAULT 0,
    disk_bytes bigint NOT NULL DEFAULT 0,
    network_rx_bytes bigint NOT NULL DEFAULT 0,
    network_tx_bytes bigint NOT NULL DEFAULT 0,
    restart_count bigint NOT NULL DEFAULT 0,
    observed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT m4_service_observations_service_not_blank CHECK (length(trim(service_name)) > 0),
    CONSTRAINT m4_service_observations_role_allowed CHECK (service_role IN ('ingress', 'worker', 'stateful', 'one_shot')),
    CONSTRAINT m4_service_observations_status_not_blank CHECK (length(trim(runtime_status)) > 0),
    CONSTRAINT m4_service_observations_counters_nonnegative CHECK (cpu_millicores >= 0 AND memory_bytes >= 0 AND disk_bytes >= 0 AND network_rx_bytes >= 0 AND network_tx_bytes >= 0 AND restart_count >= 0)
);

CREATE INDEX IF NOT EXISTS m4_service_observations_view_idx
    ON m4_service_observations(application_id, environment_id, deployment_id, service_name, observed_at DESC, id DESC);

CREATE TRIGGER m4_service_observations_are_immutable
    BEFORE UPDATE OR DELETE ON m4_service_observations
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();

-- A lifecycle outbox record may fan out to several webhook endpoints.  This
-- receipt is deliberately separate from `outbox_events.published_at`: SSE and
-- other consumers retain their own cursors, while a crash between durable
-- notification reservation and receipt insertion is harmless because the
-- ledger has an endpoint+event idempotency key.
CREATE TABLE IF NOT EXISTS m4_webhook_outbox_receipts (
    outbox_event_id text NOT NULL REFERENCES outbox_events(id),
    endpoint_id text NOT NULL REFERENCES m4_webhook_endpoints(id),
    dispatched_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(outbox_event_id, endpoint_id)
);

CREATE INDEX IF NOT EXISTS m4_webhook_outbox_receipts_endpoint_idx
    ON m4_webhook_outbox_receipts(endpoint_id, dispatched_at DESC);
