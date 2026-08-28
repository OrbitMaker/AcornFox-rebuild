-- M3 access facts.  Caddy's live/admin configuration is deliberately absent:
-- the control-plane facts below are the sole durable reconstruction input.
-- Certificate material is held by secret_references/SecretProvider; this
-- migration stores opaque reference IDs only and has no private-key column.

CREATE TABLE IF NOT EXISTS m3_platform_domains (
    id text PRIMARY KEY,
    hostname text NOT NULL,
    dns_provider_ref text NOT NULL,
    verification_status text NOT NULL DEFAULT 'pending',
    wildcard_enabled boolean NOT NULL DEFAULT false,
    verification_ref text,
    verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT m3_platform_domains_id_not_blank CHECK (length(trim(id)) > 0),
    CONSTRAINT m3_platform_domains_hostname_normalized CHECK (hostname = lower(trim(hostname)) AND hostname ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'),
    CONSTRAINT m3_platform_domains_provider_not_blank CHECK (length(trim(dns_provider_ref)) > 0),
    CONSTRAINT m3_platform_domains_status_allowed CHECK (verification_status IN ('pending', 'verified', 'failed')),
    CONSTRAINT m3_platform_domains_verified_shape CHECK ((verification_status = 'verified') = (verified_at IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS m3_platform_domains_hostname_uidx
    ON m3_platform_domains(hostname);

CREATE TABLE IF NOT EXISTS m3_application_domains (
    id text PRIMARY KEY,
    application_id text NOT NULL REFERENCES applications(id),
    platform_domain_id text REFERENCES m3_platform_domains(id),
    hostname text NOT NULL,
    domain_kind text NOT NULL,
    stable_slug text,
    verification_method text NOT NULL,
    verification_status text NOT NULL DEFAULT 'pending',
    verification_ref text,
    verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT m3_application_domains_id_not_blank CHECK (length(trim(id)) > 0),
    CONSTRAINT m3_application_domains_hostname_normalized CHECK (hostname = lower(trim(hostname)) AND hostname ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'),
    CONSTRAINT m3_application_domains_kind_allowed CHECK (domain_kind IN ('platform', 'custom')),
    CONSTRAINT m3_application_domains_verification_allowed CHECK (verification_method IN ('dns01', 'cname')),
    CONSTRAINT m3_application_domains_status_allowed CHECK (verification_status IN ('pending', 'verified', 'failed')),
    CONSTRAINT m3_application_domains_verified_shape CHECK ((verification_status = 'verified') = (verified_at IS NOT NULL)),
    -- Platform names are generated from a stable slug; user supplied custom
    -- names are CNAME-only and cannot be treated as platform DNS ownership.
    CONSTRAINT m3_application_domains_kind_shape CHECK (
        (domain_kind = 'platform' AND platform_domain_id IS NOT NULL AND verification_method = 'dns01' AND stable_slug IS NOT NULL AND stable_slug = lower(trim(stable_slug)) AND stable_slug ~ '^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$')
        OR
        (domain_kind = 'custom' AND platform_domain_id IS NULL AND verification_method = 'cname' AND stable_slug IS NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS m3_application_domains_hostname_uidx
    ON m3_application_domains(hostname);
CREATE UNIQUE INDEX IF NOT EXISTS m3_application_domains_platform_slug_uidx
    ON m3_application_domains(platform_domain_id, stable_slug)
    WHERE domain_kind = 'platform';
CREATE INDEX IF NOT EXISTS m3_application_domains_application_idx
    ON m3_application_domains(application_id, created_at DESC, id);

CREATE TABLE IF NOT EXISTS m3_certificate_references (
    id text PRIMARY KEY,
    platform_domain_id text REFERENCES m3_platform_domains(id),
    application_domain_id text REFERENCES m3_application_domains(id),
    -- Opaque SecretProvider reference. It may be backed by the local encrypted
    -- file provider rather than the control-plane secret_references table.
    secret_reference_id text NOT NULL,
    subject_hostname text NOT NULL,
    issuer text NOT NULL,
    status text NOT NULL,
    not_before timestamptz,
    not_after timestamptz,
    renewal_due_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT m3_certificate_references_id_not_blank CHECK (length(trim(id)) > 0),
    CONSTRAINT m3_certificate_references_subject_normalized CHECK (subject_hostname = lower(trim(subject_hostname)) AND subject_hostname ~ '^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'),
    CONSTRAINT m3_certificate_references_issuer_not_blank CHECK (length(trim(issuer)) > 0),
    CONSTRAINT m3_certificate_references_status_allowed CHECK (status IN ('pending', 'ready', 'renewal_due', 'failed', 'revoked')),
    CONSTRAINT m3_certificate_references_owner_shape CHECK (num_nonnulls(platform_domain_id, application_domain_id) = 1),
    CONSTRAINT m3_certificate_references_validity_shape CHECK ((not_before IS NULL AND not_after IS NULL) OR (not_before IS NOT NULL AND not_after IS NOT NULL AND not_after > not_before))
);

CREATE UNIQUE INDEX IF NOT EXISTS m3_certificate_references_platform_subject_uidx
    ON m3_certificate_references(platform_domain_id, subject_hostname)
    WHERE platform_domain_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS m3_certificate_references_application_subject_uidx
    ON m3_certificate_references(application_domain_id, subject_hostname)
    WHERE application_domain_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS m3_port_leases (
    id text PRIMARY KEY,
    application_id text NOT NULL REFERENCES applications(id),
    deployment_id text NOT NULL REFERENCES deployments(id),
    service_name text NOT NULL,
    bind_host text NOT NULL,
    port integer NOT NULL,
    acquired_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    released_at timestamptz,
    CONSTRAINT m3_port_leases_id_not_blank CHECK (length(trim(id)) > 0),
    CONSTRAINT m3_port_leases_service_not_blank CHECK (length(trim(service_name)) > 0),
    CONSTRAINT m3_port_leases_bind_host_not_blank CHECK (length(trim(bind_host)) > 0),
    CONSTRAINT m3_port_leases_port_range CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT m3_port_leases_expiry_shape CHECK (expires_at IS NULL OR expires_at > acquired_at),
    CONSTRAINT m3_port_leases_release_shape CHECK (released_at IS NULL OR released_at >= acquired_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS m3_port_leases_active_endpoint_uidx
    ON m3_port_leases(bind_host, port) WHERE released_at IS NULL;
CREATE INDEX IF NOT EXISTS m3_port_leases_deployment_idx
    ON m3_port_leases(deployment_id, released_at, acquired_at DESC);

CREATE TABLE IF NOT EXISTS m3_desired_routes (
    id text PRIMARY KEY,
    application_id text NOT NULL REFERENCES applications(id),
    application_domain_id text REFERENCES m3_application_domains(id),
    deployment_id text NOT NULL REFERENCES deployments(id),
    service_name text NOT NULL,
    hostname text NOT NULL,
    path_prefix text NOT NULL,
    certificate_reference_id text REFERENCES m3_certificate_references(id),
    desired_state text NOT NULL DEFAULT 'pending',
    verified boolean NOT NULL DEFAULT false,
    serving boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT m3_desired_routes_id_not_blank CHECK (length(trim(id)) > 0),
    -- Desired routes also retain the literal IP+system-port fallback. Go
    -- validates exact IP syntax before writing; the SQL branch prevents a
    -- DNS-only constraint from silently dropping that fallback fact.
    CONSTRAINT m3_desired_routes_hostname_normalized CHECK (hostname = lower(trim(hostname)) AND (hostname ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$' OR hostname ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' OR hostname ~ '^[0-9a-f:]+$')),
    CONSTRAINT m3_desired_routes_path_normalized CHECK (path_prefix ~ '^/([^/?#]+/)*[^/?#]*$' AND (path_prefix = '/' OR right(path_prefix, 1) <> '/')),
    CONSTRAINT m3_desired_routes_service_not_blank CHECK (length(trim(service_name)) > 0),
    CONSTRAINT m3_desired_routes_state_allowed CHECK (desired_state IN ('pending', 'active', 'disabled', 'failed')),
    CONSTRAINT m3_desired_routes_serving_shape CHECK (NOT serving OR (verified AND desired_state = 'active'))
);

CREATE UNIQUE INDEX IF NOT EXISTS m3_desired_routes_host_path_uidx
    ON m3_desired_routes(hostname, path_prefix);
CREATE INDEX IF NOT EXISTS m3_desired_routes_rebuild_idx
    ON m3_desired_routes(desired_state, hostname, path_prefix, id);

CREATE TABLE IF NOT EXISTS m3_route_pointers (
    route_id text PRIMARY KEY REFERENCES m3_desired_routes(id),
    deployment_id text NOT NULL REFERENCES deployments(id),
    port_lease_id text NOT NULL REFERENCES m3_port_leases(id),
    revision bigint NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT m3_route_pointers_revision_positive CHECK (revision > 0)
);

CREATE INDEX IF NOT EXISTS m3_route_pointers_deployment_idx
    ON m3_route_pointers(deployment_id, route_id);

-- Switching is history, never a mutable Caddy configuration snapshot. The
-- pointer transaction below is the durable atomic cutover point.
CREATE TABLE IF NOT EXISTS m3_traffic_switches (
    id text PRIMARY KEY,
    application_id text NOT NULL REFERENCES applications(id),
    route_id text NOT NULL REFERENCES m3_desired_routes(id),
    previous_deployment_id text REFERENCES deployments(id),
    next_deployment_id text NOT NULL REFERENCES deployments(id),
    status text NOT NULL,
    reason text NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT m3_traffic_switches_id_not_blank CHECK (length(trim(id)) > 0),
    CONSTRAINT m3_traffic_switches_status_allowed CHECK (status IN ('started', 'healthy', 'switched', 'failed', 'old_serving', 'stable')),
    CONSTRAINT m3_traffic_switches_reason_not_blank CHECK (length(trim(reason)) > 0),
    CONSTRAINT m3_traffic_switches_distinct_targets CHECK (previous_deployment_id IS NULL OR previous_deployment_id <> next_deployment_id)
);

CREATE INDEX IF NOT EXISTS m3_traffic_switches_route_idx
    ON m3_traffic_switches(route_id, observed_at DESC, id);

CREATE OR REPLACE FUNCTION m3_traffic_switches_are_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'm3 traffic switch history is immutable';
END;
$$;

DROP TRIGGER IF EXISTS m3_traffic_switches_no_update ON m3_traffic_switches;
CREATE TRIGGER m3_traffic_switches_no_update
BEFORE UPDATE OR DELETE ON m3_traffic_switches
FOR EACH ROW EXECUTE FUNCTION m3_traffic_switches_are_immutable();
