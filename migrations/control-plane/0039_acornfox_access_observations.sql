-- Administrator-client public access observations are short-lived,
-- append-only facts. They report what the authenticated administrator's
-- client observed; they do not prove the client's geographic position.

CREATE TABLE IF NOT EXISTS acornfox_access_observations (
    application_id text NOT NULL REFERENCES applications(id) ON DELETE RESTRICT,
    deployment_id text NOT NULL REFERENCES deployments(id) ON DELETE RESTRICT,
    report_id text NOT NULL,
    report_digest text NOT NULL,
    owner_admin_id text NOT NULL REFERENCES admin_credentials(id) ON DELETE RESTRICT,
    hostname text NOT NULL,
    observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    dns jsonb NOT NULL,
    tls jsonb NOT NULL,
    https jsonb NOT NULL,
    PRIMARY KEY (application_id, deployment_id, report_id),
    CONSTRAINT acornfox_access_observations_identity_check CHECK (
        report_id ~ '^[A-Za-z0-9_-]{1,128}$'
        AND report_digest ~ '^sha256:[0-9a-f]{64}$'
        AND length(trim(owner_admin_id)) > 0
        AND hostname = lower(trim(hostname))
        AND length(hostname) BETWEEN 1 AND 253
    ),
    CONSTRAINT acornfox_access_observations_time_check CHECK (
        expires_at = received_at + interval '5 minutes'
        AND observed_at BETWEEN received_at - interval '15 minutes' AND received_at + interval '1 minute'
    ),
    CONSTRAINT acornfox_access_observations_dns_check CHECK (
        jsonb_typeof(dns) = 'object'
        AND dns ? 'state'
        AND (dns - ARRAY['state','addresses','failure_code']) = '{}'::jsonb
        AND (
            (dns->>'state' = 'observed'
             AND NOT dns ? 'failure_code'
             AND jsonb_typeof(dns->'addresses') = 'array'
             AND jsonb_array_length(dns->'addresses') BETWEEN 1 AND 8)
            OR
            (dns->>'state' = 'failed'
             AND NOT dns ? 'addresses'
             AND dns->>'failure_code' IN ('dns_no_answer','dns_timeout','dns_lookup_failed'))
        )
    ),
    CONSTRAINT acornfox_access_observations_tls_check CHECK (
        jsonb_typeof(tls) = 'object'
        AND tls ? 'state'
        AND (tls - ARRAY['state','certificate_sha256','failure_code']) = '{}'::jsonb
        AND (
            (tls->>'state' = 'not_attempted' AND NOT tls ? 'certificate_sha256' AND NOT tls ? 'failure_code')
            OR
            (tls->>'state' = 'observed' AND tls->>'certificate_sha256' ~ '^sha256:[0-9a-f]{64}$' AND NOT tls ? 'failure_code')
            OR
            (tls->>'state' = 'failed' AND NOT tls ? 'certificate_sha256' AND tls->>'failure_code' IN ('tls_connect_failed','tls_name_mismatch','tls_certificate_invalid','tls_timeout'))
        )
    ),
    CONSTRAINT acornfox_access_observations_https_check CHECK (
        jsonb_typeof(https) = 'object'
        AND https ? 'state'
        AND (https - ARRAY['state','http_status','response_sample_sha256','response_sample_bytes','response_truncated','failure_code']) = '{}'::jsonb
        AND (
            (https->>'state' = 'not_attempted'
             AND NOT https ? 'http_status'
             AND NOT https ? 'response_sample_sha256'
             AND NOT https ? 'response_sample_bytes'
             AND NOT https ? 'response_truncated'
             AND NOT https ? 'failure_code')
            OR
            (https->>'state' = 'observed'
             AND jsonb_typeof(https->'http_status') = 'number'
             AND (https->>'http_status')::integer BETWEEN 100 AND 599
             AND https->>'response_sample_sha256' ~ '^sha256:[0-9a-f]{64}$'
             AND https ? 'response_sample_bytes'
             AND jsonb_typeof(https->'response_sample_bytes') = 'number'
             AND (https->>'response_sample_bytes')::integer BETWEEN 0 AND 65536
             AND https ? 'response_truncated'
             AND jsonb_typeof(https->'response_truncated') = 'boolean'
             AND NOT https ? 'failure_code')
            OR
            (https->>'state' = 'failed'
             AND NOT https ? 'http_status'
             AND NOT https ? 'response_sample_sha256'
             AND NOT https ? 'response_sample_bytes'
             AND NOT https ? 'response_truncated'
             AND https->>'failure_code' IN ('https_timeout','https_transport_failed'))
        )
    ),
    CONSTRAINT acornfox_access_observations_layer_check CHECK (
        (dns->>'state' <> 'failed' OR (tls->>'state' = 'not_attempted' AND https->>'state' = 'not_attempted'))
        AND (tls->>'state' NOT IN ('failed','not_attempted') OR https->>'state' = 'not_attempted')
    )
);

CREATE INDEX IF NOT EXISTS acornfox_access_observations_latest_idx
    ON acornfox_access_observations(application_id, deployment_id, hostname, received_at DESC, report_id DESC);

CREATE OR REPLACE FUNCTION acornfox_access_observations_validate_scope()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    target_valid boolean;
BEGIN
    SELECT EXISTS (
        SELECT 1
          FROM deployments AS deployment
          JOIN environments AS environment ON environment.id = deployment.environment_id
          JOIN m3_desired_routes AS route
            ON route.application_id = environment.application_id
           AND route.deployment_id = deployment.id
           AND route.hostname = NEW.hostname
           AND route.desired_state = 'active'
           AND route.verified = true
           AND route.serving = false
          JOIN LATERAL (
              SELECT command.requested_enabled, command.phase, command.result_hostname
                FROM acornfox_public_access_commands AS command
               WHERE command.application_id = environment.application_id
                 AND command.deployment_id = deployment.id
                 AND command.route_id = route.id
               ORDER BY command.created_at DESC, command.updated_at DESC, command.idempotency_key DESC
               LIMIT 1
          ) AS current_command ON true
         WHERE deployment.id = NEW.deployment_id
           AND environment.application_id = NEW.application_id
           AND current_command.requested_enabled = true
           AND current_command.phase = 'completed'
           AND current_command.result_hostname = NEW.hostname
    ) INTO target_valid;
    IF NOT target_valid THEN
        RAISE EXCEPTION 'access observation target is not the current desired public route' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS acornfox_access_observations_validate_scope_trigger ON acornfox_access_observations;
CREATE TRIGGER acornfox_access_observations_validate_scope_trigger
    BEFORE INSERT ON acornfox_access_observations
    FOR EACH ROW EXECUTE FUNCTION acornfox_access_observations_validate_scope();

DROP TRIGGER IF EXISTS acornfox_access_observations_immutable ON acornfox_access_observations;
CREATE TRIGGER acornfox_access_observations_immutable
    BEFORE UPDATE OR DELETE ON acornfox_access_observations
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
