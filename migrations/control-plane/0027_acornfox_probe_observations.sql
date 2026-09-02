-- AcornFox probe observations are append-only facts. They describe only a
-- loopback HTTP/TCP transport attempt; they do not establish application
-- health, public reachability, DNS, TLS, or serving state.
CREATE TABLE IF NOT EXISTS acornfox_probe_observations (
    id text PRIMARY KEY,
    sample_id text NOT NULL UNIQUE,
    task_id text NOT NULL REFERENCES task_leases(task_id),
    agent_sequence bigint NOT NULL CHECK (agent_sequence > 0),
    application_id text NOT NULL REFERENCES applications(id),
    environment_id text NOT NULL REFERENCES environments(id),
    release_id text NOT NULL REFERENCES releases(id),
    deployment_id text NOT NULL REFERENCES deployments(id),
    service_name text NOT NULL,
    protocol text NOT NULL CHECK (protocol IN ('http', 'tcp')),
    target_class text NOT NULL CHECK (target_class = 'loopback'),
    outcome text NOT NULL CHECK (outcome IN ('responded', 'timeout', 'refused', 'malformed_response', 'cancelled', 'not_applicable')),
    http_status integer,
    latency_ms bigint NOT NULL CHECK (latency_ms BETWEEN 0 AND 60000),
    error_code text,
    observed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    fact_digest text NOT NULL CHECK (fact_digest ~ '^sha256:[a-f0-9]{64}$'),
    CONSTRAINT acornfox_probe_observations_identity_unique UNIQUE (task_id, agent_sequence),
    CONSTRAINT acornfox_probe_observations_agent_event_fk
        FOREIGN KEY (task_id, agent_sequence) REFERENCES task_agent_events(task_id, sequence),
    CONSTRAINT acornfox_probe_observations_ids_not_blank CHECK (
        length(trim(id)) > 0
        AND length(trim(sample_id)) > 0
        AND length(trim(task_id)) > 0
        AND length(trim(application_id)) > 0
        AND length(trim(environment_id)) > 0
        AND length(trim(release_id)) > 0
        AND length(trim(deployment_id)) > 0
        AND length(trim(service_name)) > 0
    ),
    CONSTRAINT acornfox_probe_observations_status_shape CHECK (
        (protocol = 'http' AND outcome = 'responded' AND http_status IS NOT NULL AND http_status BETWEEN 100 AND 599)
        OR ((protocol <> 'http' OR outcome <> 'responded') AND http_status IS NULL)
    ),
    CONSTRAINT acornfox_probe_observations_protocol_outcome_shape CHECK (
        protocol = 'http' OR outcome <> 'malformed_response'
    ),
    CONSTRAINT acornfox_probe_observations_outcome_shape CHECK (
        (outcome = 'responded' AND error_code IS NULL)
        OR (outcome = 'not_applicable' AND error_code IS NULL)
        OR (outcome = 'timeout' AND error_code IS NOT NULL AND error_code = 'timeout')
        OR (outcome = 'refused' AND error_code IS NOT NULL AND error_code = 'connection_refused')
        OR (outcome = 'malformed_response' AND error_code IS NOT NULL AND error_code = 'malformed_response')
        OR (outcome = 'cancelled' AND error_code IS NOT NULL AND error_code = 'cancelled')
    ),
    CONSTRAINT acornfox_probe_observations_not_applicable_shape CHECK (
        outcome <> 'not_applicable' OR (http_status IS NULL AND error_code IS NULL AND latency_ms = 0)
    )
);

CREATE INDEX IF NOT EXISTS acornfox_probe_observations_task_sequence_idx
    ON acornfox_probe_observations(task_id, agent_sequence);

CREATE INDEX IF NOT EXISTS acornfox_probe_observations_scope_time_idx
    ON acornfox_probe_observations(application_id, environment_id, deployment_id, service_name, observed_at DESC, id DESC);

-- A projector may only append a fact for the deployment already owned by the
-- durable task. Individual foreign keys alone would permit cross-application
-- rows assembled from otherwise valid identifiers.
CREATE OR REPLACE FUNCTION acornfox_probe_observations_validate_task_scope()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    expected_application_id text;
    expected_environment_id text;
    expected_release_id text;
    expected_deployment_id text;
BEGIN
    SELECT operation.application_id, operation.environment_id, deployment.release_id, operation.deployment_id
      INTO expected_application_id, expected_environment_id, expected_release_id, expected_deployment_id
      FROM task_leases AS task
      JOIN operations AS operation ON operation.id = task.operation_id
      JOIN deployments AS deployment ON deployment.id = operation.deployment_id
     WHERE task.task_id = NEW.task_id;

    IF NOT FOUND
       OR NEW.application_id IS DISTINCT FROM expected_application_id
       OR NEW.environment_id IS DISTINCT FROM expected_environment_id
       OR NEW.release_id IS DISTINCT FROM expected_release_id
       OR NEW.deployment_id IS DISTINCT FROM expected_deployment_id THEN
        RAISE EXCEPTION 'acornfox probe observation does not match task scope' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION acornfox_probe_observations_reject_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'acornfox probe observations are append-only' USING ERRCODE = '55000';
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = 'acornfox_probe_observations'::regclass
          AND tgname = 'acornfox_probe_observations_task_scope'
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER acornfox_probe_observations_task_scope
            BEFORE INSERT ON acornfox_probe_observations
            FOR EACH ROW EXECUTE FUNCTION acornfox_probe_observations_validate_task_scope();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = 'acornfox_probe_observations'::regclass
          AND tgname = 'acornfox_probe_observations_are_immutable'
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER acornfox_probe_observations_are_immutable
            BEFORE UPDATE OR DELETE ON acornfox_probe_observations
            FOR EACH ROW EXECUTE FUNCTION acornfox_probe_observations_reject_mutation();
    END IF;
END $$;
