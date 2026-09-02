-- AcornFox public-access command ledger. M3 application-domain, desired-route,
-- port-lease and route-pointer rows remain the sole route-intent authority.
-- This table records only a command phase, exact route reference and replay.

CREATE TABLE IF NOT EXISTS acornfox_public_access_commands (
    application_id text NOT NULL REFERENCES applications(id),
    deployment_id text NOT NULL REFERENCES deployments(id),
    idempotency_key text NOT NULL,
    request_digest text NOT NULL,
    requested_enabled boolean NOT NULL,
    route_id text REFERENCES m3_desired_routes(id),
    phase text NOT NULL,
    result_status text,
    result_hostname text,
    failure_code text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (application_id, deployment_id, idempotency_key),
    CONSTRAINT acornfox_public_access_commands_key_check CHECK (length(trim(idempotency_key)) BETWEEN 1 AND 512),
    CONSTRAINT acornfox_public_access_commands_digest_check CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT acornfox_public_access_commands_phase_check CHECK (phase IN ('prepared', 'applying', 'reconcile_required', 'completed', 'failed')),
    CONSTRAINT acornfox_public_access_commands_result_check CHECK (
        (phase = 'completed' AND result_status IN ('PUBLIC_DISABLED', 'PENDING_EXTERNAL_VALIDATION') AND result_hostname = lower(trim(result_hostname)) AND failure_code IS NULL)
        OR
        (phase <> 'completed' AND result_status IS NULL AND result_hostname IS NULL)
    )
);

-- Only one nonterminal mutation may own a deployment. A completed command is
-- replayable by its exact key; a restart reconciles a surviving nonterminal.
CREATE UNIQUE INDEX IF NOT EXISTS acornfox_public_access_commands_active_uidx
    ON acornfox_public_access_commands(application_id, deployment_id)
    WHERE phase IN ('prepared', 'applying', 'reconcile_required');

CREATE INDEX IF NOT EXISTS acornfox_public_access_commands_reconcile_idx
    ON acornfox_public_access_commands(phase, created_at, application_id, deployment_id)
    WHERE phase IN ('applying', 'reconcile_required');
