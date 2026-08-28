-- M4 two-phase rollout coordination. Runtime readiness and external serving
-- are deliberately distinct: only a later route-set commit may make a
-- candidate the durable serving target.

CREATE TABLE IF NOT EXISTS m4_rollout_coordinations (
    operation_id text PRIMARY KEY REFERENCES operations(id),
    application_id text NOT NULL REFERENCES applications(id),
    environment_id text NOT NULL REFERENCES environments(id),
    source_deployment_id text NOT NULL REFERENCES deployments(id),
    candidate_deployment_id text NOT NULL UNIQUE REFERENCES deployments(id),
    replacement_task_id text UNIQUE REFERENCES task_leases(task_id),
    old_retirement_task_id text UNIQUE REFERENCES task_leases(task_id),
    phase text NOT NULL,
    route_set_digest text NOT NULL,
    expected_route_set_version bigint NOT NULL DEFAULT 0,
    attempt integer NOT NULL DEFAULT 0,
    lease_owner text,
    lease_until timestamptz,
    observation_deadline timestamptz,
    failure_reason text,
    evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    CONSTRAINT m4_rollout_coordinations_phase_allowed CHECK (phase IN ('candidate_requested', 'candidate_ready', 'route_staged', 'route_committed', 'old_retiring', 'completed', 'failed', 'rolled_back')),
    CONSTRAINT m4_rollout_coordinations_distinct_deployments CHECK (source_deployment_id <> candidate_deployment_id),
    CONSTRAINT m4_rollout_coordinations_digest_shape CHECK (route_set_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT m4_rollout_coordinations_version_nonnegative CHECK (expected_route_set_version >= 0),
    CONSTRAINT m4_rollout_coordinations_attempt_nonnegative CHECK (attempt >= 0),
    CONSTRAINT m4_rollout_coordinations_lease_shape CHECK ((lease_owner IS NULL AND lease_until IS NULL) OR (lease_owner IS NOT NULL AND length(trim(lease_owner)) > 0 AND lease_until IS NOT NULL)),
    CONSTRAINT m4_rollout_coordinations_evidence_array CHECK (jsonb_typeof(evidence) = 'array'),
    CONSTRAINT m4_rollout_coordinations_terminal_shape CHECK (
        (phase IN ('completed', 'failed', 'rolled_back') AND completed_at IS NOT NULL)
        OR (phase NOT IN ('completed', 'failed', 'rolled_back') AND completed_at IS NULL)
    ),
    CONSTRAINT m4_rollout_coordinations_failure_shape CHECK (
        (phase = 'failed' AND failure_reason IS NOT NULL AND length(trim(failure_reason)) > 0)
        OR phase <> 'failed'
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS m4_rollout_coordinations_active_environment_uidx
    ON m4_rollout_coordinations(environment_id)
    WHERE phase NOT IN ('completed', 'failed', 'rolled_back');
CREATE INDEX IF NOT EXISTS m4_rollout_coordinations_claim_idx
    ON m4_rollout_coordinations(phase, lease_until, updated_at, operation_id)
    WHERE phase NOT IN ('completed', 'failed', 'rolled_back');
CREATE INDEX IF NOT EXISTS m4_rollout_coordinations_application_idx
    ON m4_rollout_coordinations(application_id, environment_id, created_at DESC);

CREATE TABLE IF NOT EXISTS m4_rollout_phase_events (
    operation_id text NOT NULL REFERENCES m4_rollout_coordinations(operation_id),
    sequence bigint NOT NULL CHECK (sequence > 0),
    phase text NOT NULL CHECK (phase IN ('candidate_requested', 'candidate_ready', 'route_staged', 'route_committed', 'old_retiring', 'completed', 'failed', 'rolled_back')),
    actor text NOT NULL CHECK (length(trim(actor)) > 0),
    evidence jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(evidence) = 'array'),
    reason text NOT NULL DEFAULT '' CHECK (length(reason) <= 1024),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (operation_id, sequence)
);

CREATE OR REPLACE FUNCTION m4_rollout_phase_events_are_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'M4 rollout phase events are immutable' USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS m4_rollout_phase_events_no_mutation ON m4_rollout_phase_events;
CREATE TRIGGER m4_rollout_phase_events_no_mutation
BEFORE UPDATE OR DELETE ON m4_rollout_phase_events
FOR EACH ROW EXECUTE FUNCTION m4_rollout_phase_events_are_immutable();

CREATE OR REPLACE FUNCTION m4_validate_rollout_coordinator_scope()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    operation_application text;
    operation_environment text;
    source_application text;
    source_environment text;
    candidate_application text;
    candidate_environment text;
BEGIN
    SELECT application_id, environment_id INTO operation_application, operation_environment
      FROM operations WHERE id = NEW.operation_id;
    SELECT e.application_id, d.environment_id INTO source_application, source_environment
      FROM deployments d JOIN environments e ON e.id = d.environment_id WHERE d.id = NEW.source_deployment_id;
    SELECT e.application_id, d.environment_id INTO candidate_application, candidate_environment
      FROM deployments d JOIN environments e ON e.id = d.environment_id WHERE d.id = NEW.candidate_deployment_id;
    IF operation_application IS NULL OR source_application IS NULL OR candidate_application IS NULL
       OR operation_application <> NEW.application_id OR operation_environment <> NEW.environment_id
       OR source_application <> NEW.application_id OR source_environment <> NEW.environment_id
       OR candidate_application <> NEW.application_id OR candidate_environment <> NEW.environment_id THEN
        RAISE EXCEPTION 'M4 rollout coordinator scope does not match operation and deployments' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS m4_rollout_coordinators_validate_scope ON m4_rollout_coordinations;
CREATE TRIGGER m4_rollout_coordinators_validate_scope
BEFORE INSERT OR UPDATE OF application_id, environment_id, source_deployment_id, candidate_deployment_id ON m4_rollout_coordinations
FOR EACH ROW EXECUTE FUNCTION m4_validate_rollout_coordinator_scope();
