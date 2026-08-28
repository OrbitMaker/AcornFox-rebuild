-- Candidate route sets are not current route facts. They are an immutable
-- staging snapshot that a controller may load and observe before one later
-- transaction moves the live pointers.

CREATE TABLE IF NOT EXISTS m4_rollout_route_sets (
    rollout_operation_id text PRIMARY KEY REFERENCES m4_rollout_coordinations(operation_id),
    application_id text NOT NULL REFERENCES applications(id),
    source_deployment_id text NOT NULL REFERENCES deployments(id),
    candidate_deployment_id text NOT NULL REFERENCES deployments(id),
    old_digest text NOT NULL CHECK (old_digest ~ '^sha256:[0-9a-f]{64}$'),
    candidate_digest text NOT NULL CHECK (candidate_digest ~ '^sha256:[0-9a-f]{64}$'),
    expected_version bigint NOT NULL CHECK (expected_version >= 0),
    state text NOT NULL DEFAULT 'staged' CHECK (state IN ('staged','loaded','observed','current','discarded')),
    lease_owner text,
    lease_until timestamptz,
    stage_evidence jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(stage_evidence)='array'),
    observe_evidence jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(observe_evidence)='array'),
    failure_reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT m4_staged_route_sets_distinct_deployments CHECK (source_deployment_id <> candidate_deployment_id),
    CONSTRAINT m4_staged_route_sets_lease_shape CHECK ((lease_owner IS NULL AND lease_until IS NULL) OR (lease_owner IS NOT NULL AND length(trim(lease_owner))>0 AND lease_until IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS m4_rollout_route_set_entries (
    rollout_operation_id text NOT NULL REFERENCES m4_rollout_route_sets(rollout_operation_id),
    route_id text NOT NULL REFERENCES m3_desired_routes(id),
    service_name text NOT NULL CHECK (length(trim(service_name)) > 0),
    host text NOT NULL CHECK (length(trim(host)) > 0),
    path_prefix text NOT NULL CHECK (path_prefix ~ '^/'),
    certificate_reference_id text,
    old_deployment_id text NOT NULL REFERENCES deployments(id),
    old_port_lease_id text NOT NULL REFERENCES m3_port_leases(id),
    old_pointer_revision bigint NOT NULL CHECK (old_pointer_revision > 0),
    candidate_deployment_id text NOT NULL REFERENCES deployments(id),
    candidate_port integer NOT NULL CHECK (candidate_port BETWEEN 1 AND 65535),
    PRIMARY KEY(rollout_operation_id, route_id),
    CONSTRAINT m4_staged_route_entries_deployments_differ CHECK (old_deployment_id <> candidate_deployment_id)
);

CREATE INDEX IF NOT EXISTS m4_staged_route_sets_recovery_idx
    ON m4_rollout_route_sets(state,lease_until,updated_at,rollout_operation_id)
    WHERE state NOT IN ('current','discarded');

CREATE OR REPLACE FUNCTION m4_reject_staged_route_entry_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'M4 staged route entries are immutable' USING ERRCODE='55000'; END;
$$;
DROP TRIGGER IF EXISTS m4_staged_route_entries_no_mutation ON m4_rollout_route_set_entries;
CREATE TRIGGER m4_staged_route_entries_no_mutation BEFORE UPDATE OR DELETE ON m4_rollout_route_set_entries FOR EACH ROW EXECUTE FUNCTION m4_reject_staged_route_entry_mutation();
