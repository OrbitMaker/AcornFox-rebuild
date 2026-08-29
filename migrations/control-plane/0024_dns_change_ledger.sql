-- G4 local-only DNS ownership, dry-run, and reconciliation ledger.
-- This migration never contains Tencent credentials or a provider write path.

CREATE TABLE IF NOT EXISTS dns_change_owned_records (
    owner_key text PRIMARY KEY CHECK (owner_key ~ '^[a-z][a-z0-9:_-]{2,127}$'),
    provider text NOT NULL CHECK (provider = 'dnspod'),
    domain_id bigint NOT NULL CHECK (domain_id > 0),
    domain text NOT NULL CHECK (length(trim(domain)) > 0),
    record_id bigint NOT NULL CHECK (record_id > 0),
    host text NOT NULL CHECK (length(trim(host)) > 0),
    record_type text NOT NULL CHECK (record_type IN ('A','CNAME')),
    value text NOT NULL CHECK (length(trim(value)) > 0),
    ttl integer NOT NULL CHECK (ttl BETWEEN 1 AND 604800),
    last_request_id text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    last_plan_id text,
    UNIQUE (provider, domain_id, record_id)
);

CREATE TABLE IF NOT EXISTS dns_change_plans (
    id text PRIMARY KEY,
    idempotency_key text NOT NULL UNIQUE,
    input_digest text NOT NULL CHECK (input_digest ~ '^sha256:[0-9a-f]{64}$'),
    changes jsonb NOT NULL CHECK (jsonb_typeof(changes) = 'array'),
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_change_reconcile_state (
    scope text PRIMARY KEY,
    last_run_at timestamptz NOT NULL
);

-- Gate4B-2 durable domain convergence intent. DNS provider ownership remains
-- outside the runtime; this table only records bounded route/TLS convergence
-- work and never stores certificate material or provider credentials.
CREATE TABLE IF NOT EXISTS m3_domain_convergence_requests (
    id text PRIMARY KEY,
    application_domain_id text NOT NULL,
    application_id text NOT NULL REFERENCES applications(id),
    hostname text NOT NULL,
    request_kind text NOT NULL,
    target_deployment_id text REFERENCES deployments(id),
    request_digest text NOT NULL,
    idempotency_key text NOT NULL,
    actor_type text NOT NULL CHECK (actor_type IN ('system','administrator')),
    actor_id text NOT NULL CHECK (length(trim(actor_id)) > 0),
    phase text NOT NULL,
    status text NOT NULL,
    resume_phase text,
    lease_owner text,
    lease_until timestamptz,
    attempt integer NOT NULL DEFAULT 0,
    recovery_attempt integer NOT NULL DEFAULT 0 CHECK (recovery_attempt >= 0),
    max_attempts integer NOT NULL DEFAULT 20,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    result jsonb,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    CONSTRAINT m3_domain_convergence_requests_id_not_blank CHECK (length(trim(id)) > 0),
    CONSTRAINT m3_domain_convergence_requests_domain_not_blank CHECK (length(trim(application_domain_id)) > 0),
    CONSTRAINT m3_domain_convergence_requests_hostname_normalized CHECK (hostname = lower(trim(hostname)) AND hostname ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'),
    CONSTRAINT m3_domain_convergence_requests_kind_allowed CHECK (request_kind IN ('converge','unbind')),
    CONSTRAINT m3_domain_convergence_requests_digest_shape CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT m3_domain_convergence_requests_phase_allowed CHECK (phase IN ('queued','route_prepared','internal_route_active','tls_allowed','certificate_observed','serving','unbind_route_removed','completed','failed','recovery_required')),
    CONSTRAINT m3_domain_convergence_requests_resume_phase_allowed CHECK (resume_phase IS NULL OR resume_phase IN ('queued','route_prepared','internal_route_active','tls_allowed','certificate_observed','serving','unbind_route_removed')),
    CONSTRAINT m3_domain_convergence_requests_status_allowed CHECK (status IN ('queued','leased','completed','failed','recovery_required')),
    CONSTRAINT m3_domain_convergence_requests_lease_shape CHECK ((lease_owner IS NULL) = (lease_until IS NULL)),
    CONSTRAINT m3_domain_convergence_requests_attempt_shape CHECK (attempt >= 0 AND max_attempts BETWEEN 1 AND 100 AND attempt <= max_attempts),
    CONSTRAINT m3_domain_convergence_requests_payload_object CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT m3_domain_convergence_requests_result_object CHECK (result IS NULL OR jsonb_typeof(result) = 'object'),
    CONSTRAINT m3_domain_convergence_requests_state_shape CHECK (
        (status = 'queued' AND phase IN ('queued','route_prepared','internal_route_active','tls_allowed','certificate_observed','serving','unbind_route_removed') AND lease_owner IS NULL AND lease_until IS NULL AND resume_phase IS NULL AND completed_at IS NULL)
        OR (status = 'leased' AND phase IN ('queued','route_prepared','internal_route_active','tls_allowed','certificate_observed','serving','unbind_route_removed') AND lease_owner IS NOT NULL AND lease_until IS NOT NULL AND resume_phase IS NULL AND completed_at IS NULL)
        OR (status = 'recovery_required' AND phase = 'recovery_required' AND lease_owner IS NULL AND lease_until IS NULL AND resume_phase IN ('queued','route_prepared','internal_route_active','tls_allowed','certificate_observed','serving','unbind_route_removed') AND completed_at IS NULL)
        OR (status = 'completed' AND phase = 'completed' AND lease_owner IS NULL AND lease_until IS NULL AND resume_phase IS NULL AND completed_at IS NOT NULL)
        OR (status = 'failed' AND phase = 'failed' AND lease_owner IS NULL AND lease_until IS NULL AND resume_phase IS NULL AND completed_at IS NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS m3_domain_convergence_requests_idempotency_uidx
    ON m3_domain_convergence_requests(request_kind, idempotency_key);
CREATE INDEX IF NOT EXISTS m3_domain_convergence_requests_claim_idx
    ON m3_domain_convergence_requests(status, lease_until, created_at, id);
CREATE INDEX IF NOT EXISTS m3_domain_convergence_requests_domain_idx
    ON m3_domain_convergence_requests(application_domain_id, created_at DESC, id);

-- Historical disabled/failed routes are retained as audit facts after an
-- unbind. They must not reserve a hostname/path for a new verified binding.
-- Pending and active facts remain exclusive so two live convergence attempts
-- cannot publish the same route.
DROP INDEX IF EXISTS m3_desired_routes_host_path_uidx;
CREATE UNIQUE INDEX IF NOT EXISTS m3_desired_routes_host_path_live_uidx
    ON m3_desired_routes(hostname, path_prefix)
    WHERE desired_state IN ('pending','active');
