-- M6 controlled-AI evidence and rule evolution.
--
-- Every table is append-only.  A phase is represented by a new row rather
-- than an UPDATE to a previous phase, which makes provider retries and
-- process-restart replay inspectable.  The payload columns contain only
-- redacted metadata; the trigger rejects common plaintext-secret shapes.

CREATE OR REPLACE FUNCTION m6_json_contains_plaintext_secret(value jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    item jsonb;
    key text;
    text_value text;
    normalized text;
BEGIN
    IF value IS NULL THEN RETURN false; END IF;
    IF jsonb_typeof(value) = 'object' THEN
        FOR key, item IN SELECT object_key, object_value FROM jsonb_each(value) AS fields(object_key, object_value) LOOP
            normalized := lower(regexp_replace(key, '[^a-zA-Z0-9]', '', 'g'));
            IF normalized IN ('password','passwd','passphrase','token','accesstoken','refreshtoken','apikey','secret','clientsecret','privatekey','signingkey','authorization','cookie','credential') THEN
                IF jsonb_typeof(item) <> 'string' THEN RETURN true; END IF;
                text_value := item #>> '{}';
                IF btrim(text_value) <> ''
                   AND lower(text_value) NOT LIKE '[redacted]'
                   AND lower(text_value) NOT LIKE 'secret://%'
                   AND lower(text_value) NOT LIKE 'ref:%'
                   AND lower(text_value) NOT LIKE 'reference:%'
                   AND lower(text_value) NOT LIKE 'sha256:%'
                   AND lower(text_value) NOT LIKE 'digest:%' THEN RETURN true; END IF;
            ELSIF m6_json_contains_plaintext_secret(item) THEN
                RETURN true;
            END IF;
        END LOOP;
        RETURN false;
    ELSIF jsonb_typeof(value) = 'array' THEN
        FOR item IN SELECT array_item FROM jsonb_array_elements(value) AS elements(array_item) LOOP
            IF m6_json_contains_plaintext_secret(item) THEN RETURN true; END IF;
        END LOOP;
        RETURN false;
    ELSIF jsonb_typeof(value) = 'string' THEN
        text_value := value #>> '{}';
        IF lower(btrim(text_value)) LIKE 'secret://%'
           OR lower(btrim(text_value)) LIKE 'ref:%'
           OR lower(btrim(text_value)) LIKE 'reference:%'
           OR lower(btrim(text_value)) LIKE 'sha256:%'
           OR lower(btrim(text_value)) LIKE 'digest:%'
           OR lower(btrim(text_value)) = '[redacted]' THEN RETURN false; END IF;
        IF text_value ~* '-----BEGIN[^-]*(PRIVATE KEY|CERTIFICATE)-----' THEN RETURN true; END IF;
        IF text_value ~* '(^|[[:space:],;{])(password|passwd|passphrase|token|access[_-]?token|refresh[_-]?token|api[_-]?key|secret|client[_-]?secret|private[_-]?key|authorization|cookie|credential)[[:space:]]*[:=][[:space:]]*[^[:space:],;}[]+' THEN RETURN true; END IF;
        IF text_value ~* 'bearer[[:space:]]+[A-Za-z0-9._~+/=-]{8,}' THEN RETURN true; END IF;
    END IF;
    RETURN false;
END;
$$;

CREATE OR REPLACE FUNCTION m6_reject_plaintext_payload()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF m6_json_contains_plaintext_secret(NEW.payload) THEN
        RAISE EXCEPTION 'M6 AI payload contains sensitive plaintext' USING ERRCODE = '22023';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION m6_reject_ai_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME USING ERRCODE = '55000';
END;
$$;

CREATE TABLE IF NOT EXISTS m6_ai_invocations (
    id text PRIMARY KEY,
    idempotency_key text NOT NULL UNIQUE,
    request_digest text NOT NULL,
    task_type text NOT NULL,
    application_id text NOT NULL DEFAULT '',
    problem_fingerprint text NOT NULL,
    version_key text NOT NULL,
    cache_key text NOT NULL DEFAULT '',
    provider text NOT NULL,
    model text NOT NULL,
    policy_version text NOT NULL,
    profile text NOT NULL DEFAULT '',
    context_id text NOT NULL DEFAULT '',
    status text NOT NULL,
    outcome text NOT NULL DEFAULT '',
    tokens bigint NOT NULL CHECK (tokens >= 0),
    duration_ms bigint NOT NULL CHECK (duration_ms >= 0),
    cpu_seconds double precision NOT NULL DEFAULT 0 CHECK (cpu_seconds >= 0),
    memory_bytes bigint NOT NULL DEFAULT 0 CHECK (memory_bytes >= 0),
    disk_bytes bigint NOT NULL DEFAULT 0 CHECK (disk_bytes >= 0),
    network_rx_bytes bigint NOT NULL DEFAULT 0 CHECK (network_rx_bytes >= 0),
    network_tx_bytes bigint NOT NULL DEFAULT 0 CHECK (network_tx_bytes >= 0),
    peak_memory_bytes bigint NOT NULL DEFAULT 0 CHECK (peak_memory_bytes >= 0),
    candidate_id text NOT NULL DEFAULT '',
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (length(trim(id)) > 0 AND length(trim(idempotency_key)) > 0 AND length(trim(request_digest)) > 0),
    CHECK (length(trim(task_type)) > 0 AND length(trim(problem_fingerprint)) > 0 AND length(trim(version_key)) > 0),
    CHECK (length(trim(provider)) > 0 AND length(trim(model)) > 0 AND length(trim(policy_version)) > 0)
);
CREATE INDEX IF NOT EXISTS m6_ai_invocations_scope_idx ON m6_ai_invocations(application_id, task_type, created_at DESC);
CREATE INDEX IF NOT EXISTS m6_ai_invocations_outcome_idx ON m6_ai_invocations(outcome, created_at DESC);

CREATE TABLE IF NOT EXISTS m6_ai_context_packages (
    id text PRIMARY KEY, idempotency_key text NOT NULL UNIQUE, request_digest text NOT NULL,
    invocation_id text NOT NULL DEFAULT '', scope jsonb NOT NULL, source_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    authorized boolean NOT NULL, redacted boolean NOT NULL, template_version text NOT NULL,
    profile text NOT NULL DEFAULT '', retention text NOT NULL DEFAULT '', payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(), CHECK (authorized AND redacted AND jsonb_typeof(scope) = 'array')
);
CREATE INDEX IF NOT EXISTS m6_ai_context_invocation_idx ON m6_ai_context_packages(invocation_id, created_at DESC);

CREATE TABLE IF NOT EXISTS m6_ai_action_plans (
    id text PRIMARY KEY, idempotency_key text NOT NULL UNIQUE, request_digest text NOT NULL,
    invocation_id text NOT NULL DEFAULT '', task_type text NOT NULL, target_refs jsonb NOT NULL,
    assumptions jsonb NOT NULL DEFAULT '[]'::jsonb, evidence_refs jsonb NOT NULL,
    actions jsonb NOT NULL, rollback_id text NOT NULL DEFAULT '', confidence double precision NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    requires_user_confirmation boolean NOT NULL, schema_version text NOT NULL, payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS m6_ai_plans_invocation_idx ON m6_ai_action_plans(invocation_id, created_at DESC);

CREATE TABLE IF NOT EXISTS m6_ai_tool_actions (
    id text PRIMARY KEY, idempotency_key text NOT NULL UNIQUE, request_digest text NOT NULL,
    invocation_id text NOT NULL DEFAULT '', plan_id text NOT NULL DEFAULT '', sequence integer NOT NULL CHECK (sequence >= 0),
    tool_id text NOT NULL, tool_version text NOT NULL, parameters jsonb NOT NULL DEFAULT '{}'::jsonb,
    workspace_ref text NOT NULL DEFAULT '', risk_class text NOT NULL, validation_id text NOT NULL,
    bounds jsonb NOT NULL DEFAULT '{}'::jsonb, network text NOT NULL DEFAULT '', timeout_ms bigint NOT NULL CHECK (timeout_ms >= 0),
    status text NOT NULL, output_digest text NOT NULL DEFAULT '', diff_digest text NOT NULL DEFAULT '', payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS m6_ai_actions_invocation_idx ON m6_ai_tool_actions(invocation_id, sequence, id);

CREATE TABLE IF NOT EXISTS m6_ai_verifications (
    id text PRIMARY KEY, idempotency_key text NOT NULL UNIQUE, request_digest text NOT NULL,
    invocation_id text NOT NULL DEFAULT '', plan_id text NOT NULL DEFAULT '', action_id text NOT NULL DEFAULT '',
    validator_id text NOT NULL, passed boolean NOT NULL, evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    summary text NOT NULL DEFAULT '', payload jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS m6_ai_verifications_invocation_idx ON m6_ai_verifications(invocation_id, created_at DESC);

CREATE TABLE IF NOT EXISTS m6_ai_rollbacks (
    id text PRIMARY KEY, idempotency_key text NOT NULL UNIQUE, request_digest text NOT NULL,
    invocation_id text NOT NULL DEFAULT '', plan_id text NOT NULL DEFAULT '', rollback_id text NOT NULL,
    status text NOT NULL, reason text NOT NULL, evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    payload jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS m6_ai_rollbacks_invocation_idx ON m6_ai_rollbacks(invocation_id, created_at DESC);

CREATE TABLE IF NOT EXISTS m6_ai_outcomes (
    id text PRIMARY KEY, idempotency_key text NOT NULL UNIQUE, request_digest text NOT NULL,
    invocation_id text NOT NULL, status text NOT NULL, exit_code integer NOT NULL DEFAULT 0,
    summary text NOT NULL DEFAULT '', user_confirmed boolean NOT NULL, rolled_back boolean NOT NULL,
    failure_code text NOT NULL DEFAULT '', resource jsonb NOT NULL DEFAULT '{}'::jsonb,
    tokens bigint NOT NULL CHECK (tokens >= 0), duration_ms bigint NOT NULL CHECK (duration_ms >= 0),
    candidate_id text NOT NULL DEFAULT '', payload jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS m6_ai_outcomes_invocation_idx ON m6_ai_outcomes(invocation_id, created_at DESC);

CREATE TABLE IF NOT EXISTS m6_ai_candidate_refs (
    id text PRIMARY KEY, idempotency_key text NOT NULL UNIQUE, request_digest text NOT NULL,
    invocation_id text NOT NULL, candidate_id text NOT NULL, fingerprint text NOT NULL,
    aggregation text NOT NULL, status text NOT NULL DEFAULT '', payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS m6_ai_candidate_refs_invocation_idx ON m6_ai_candidate_refs(invocation_id, created_at DESC);
CREATE INDEX IF NOT EXISTS m6_ai_candidate_refs_candidate_idx ON m6_ai_candidate_refs(candidate_id, created_at DESC);

CREATE TABLE IF NOT EXISTS m6_ai_interventions (
    id text PRIMARY KEY, idempotency_key text NOT NULL UNIQUE, request_digest text NOT NULL,
    invocation_id text NOT NULL, payload jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS m6_ai_interventions_invocation_idx ON m6_ai_interventions(invocation_id);

DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['m6_ai_invocations','m6_ai_context_packages','m6_ai_action_plans','m6_ai_tool_actions','m6_ai_verifications','m6_ai_rollbacks','m6_ai_outcomes','m6_ai_candidate_refs','m6_ai_interventions'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS %I_plaintext_guard ON %I', table_name, table_name);
        EXECUTE format('CREATE TRIGGER %I_plaintext_guard BEFORE INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION m6_reject_plaintext_payload()', table_name, table_name);
        EXECUTE format('DROP TRIGGER IF EXISTS %I_immutable ON %I', table_name, table_name);
        EXECUTE format('CREATE TRIGGER %I_immutable BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m6_reject_ai_mutation()', table_name, table_name);
    END LOOP;
END;
$$;

CREATE OR REPLACE VIEW m6_ai_intervention_metrics AS
SELECT
    count(*) AS interventions,
    count(*) FILTER (WHERE COALESCE(NULLIF(o.status, ''), NULLIF(i.outcome, ''), i.status) = 'succeeded') AS succeeded,
    count(*) FILTER (WHERE COALESCE(NULLIF(o.status, ''), NULLIF(i.outcome, ''), i.status) = 'failed') AS failed,
    count(*) FILTER (WHERE COALESCE(NULLIF(o.status, ''), NULLIF(i.outcome, ''), i.status) = 'rolled_back') AS rolled_back,
    COALESCE(sum(COALESCE(o.tokens, i.tokens)), 0) AS tokens,
    COALESCE(sum(COALESCE(o.duration_ms, i.duration_ms)), 0) AS duration_ms,
    count(DISTINCT cr.candidate_id) AS distinct_candidates
FROM m6_ai_invocations i
LEFT JOIN LATERAL (
    SELECT status, tokens, duration_ms FROM m6_ai_outcomes
    WHERE invocation_id = i.id ORDER BY created_at DESC, id DESC LIMIT 1
) o ON true
LEFT JOIN m6_ai_candidate_refs cr ON cr.invocation_id = i.id;

-- AI service configuration is also versioned evidence.  It contains no
-- credentials; secrets remain owned by SecretProvider and are represented by
-- references outside this table.  The disabled profile is the only valid
-- disabled state and external network calls are explicitly false.
CREATE TABLE IF NOT EXISTS m6_ai_settings_events (
    id text PRIMARY KEY,
    idempotency_key text NOT NULL UNIQUE,
    request_digest text NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    enabled boolean NOT NULL,
    profile text NOT NULL CHECK (profile IN ('mainland','global','local','disabled')),
    provider text NOT NULL DEFAULT '',
    model text NOT NULL DEFAULT '',
    data_scopes jsonb NOT NULL,
    max_tokens bigint NOT NULL DEFAULT 0 CHECK (max_tokens >= 0),
    max_duration_ms bigint NOT NULL DEFAULT 0 CHECK (max_duration_ms >= 0),
    cooldown_ms bigint NOT NULL DEFAULT 0 CHECK (cooldown_ms >= 0),
    cache_enabled boolean NOT NULL DEFAULT true,
    actor text NOT NULL,
    external_calls boolean NOT NULL DEFAULT false CHECK (external_calls = false),
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((profile = 'disabled' AND enabled = false AND provider = '' AND model = '') OR profile <> 'disabled'),
    CHECK ((NOT enabled) OR (profile <> 'disabled' AND length(trim(provider)) > 0 AND length(trim(model)) > 0)),
    CHECK (jsonb_typeof(data_scopes) = 'array')
);
CREATE INDEX IF NOT EXISTS m6_ai_settings_version_idx ON m6_ai_settings_events(version DESC, created_at DESC);
DROP TRIGGER IF EXISTS m6_ai_settings_events_plaintext_guard ON m6_ai_settings_events;
CREATE TRIGGER m6_ai_settings_events_plaintext_guard BEFORE INSERT OR UPDATE ON m6_ai_settings_events FOR EACH ROW EXECUTE FUNCTION m6_reject_plaintext_payload();
DROP TRIGGER IF EXISTS m6_ai_settings_events_immutable ON m6_ai_settings_events;
CREATE TRIGGER m6_ai_settings_events_immutable BEFORE UPDATE OR DELETE ON m6_ai_settings_events FOR EACH ROW EXECUTE FUNCTION m6_reject_ai_mutation();
CREATE OR REPLACE VIEW m6_ai_settings_current AS
SELECT * FROM m6_ai_settings_events ORDER BY version DESC, created_at DESC, id DESC LIMIT 1;

-- Rule candidates are immutable snapshots plus append-only observation,
-- evaluation, and lifecycle events.  The current candidate is the latest
-- lifecycle event folded by the rules repository; no row is promoted by SQL.
CREATE TABLE IF NOT EXISTS m6_rule_candidates (
    id text PRIMARY KEY, fingerprint text NOT NULL, name text NOT NULL DEFAULT '',
    status text NOT NULL CHECK (status IN ('draft','testing','reviewed','shadow','approved','promoted')),
    success_count bigint NOT NULL DEFAULT 0 CHECK (success_count >= 0),
    application_count bigint NOT NULL DEFAULT 0 CHECK (application_count >= 0),
    regression_passed boolean NOT NULL DEFAULT false, shadow_passed boolean NOT NULL DEFAULT false,
    review_decision text NOT NULL DEFAULT '', reviewed_by text NOT NULL DEFAULT '', proposed_version text NOT NULL DEFAULT '',
    test_evidence jsonb NOT NULL DEFAULT '[]'::jsonb, payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS m6_rule_candidates_fingerprint_idx ON m6_rule_candidates(fingerprint, created_at DESC);
CREATE INDEX IF NOT EXISTS m6_rule_candidates_status_idx ON m6_rule_candidates(status, updated_at DESC);

CREATE TABLE IF NOT EXISTS m6_rule_candidate_observations (
    id text PRIMARY KEY, idempotency_key text NOT NULL UNIQUE, request_digest text NOT NULL,
    candidate_id text NOT NULL, fingerprint text NOT NULL, invocation_id text NOT NULL DEFAULT '',
    application_id text NOT NULL DEFAULT '', success boolean NOT NULL, evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
    payload jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS m6_rule_observations_candidate_idx ON m6_rule_candidate_observations(candidate_id, created_at DESC);

CREATE TABLE IF NOT EXISTS m6_rule_candidate_events (
    id text PRIMARY KEY, idempotency_key text NOT NULL UNIQUE, request_digest text NOT NULL,
    sequence bigserial NOT NULL UNIQUE,
    candidate_id text NOT NULL, fingerprint text NOT NULL, from_status text NOT NULL, to_status text NOT NULL,
    actor text NOT NULL DEFAULT '', reason text NOT NULL DEFAULT '', payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (from_status <> to_status),
    CHECK (to_status IN ('draft','testing','reviewed','shadow','approved','promoted'))
);
CREATE INDEX IF NOT EXISTS m6_rule_candidate_events_candidate_idx ON m6_rule_candidate_events(candidate_id, created_at DESC);

CREATE TABLE IF NOT EXISTS m6_rule_evaluations (
    id text PRIMARY KEY, idempotency_key text NOT NULL UNIQUE, request_digest text NOT NULL,
    candidate_id text NOT NULL, test_name text NOT NULL, kind text NOT NULL DEFAULT '', passed boolean NOT NULL,
    evidence jsonb NOT NULL DEFAULT '[]'::jsonb, payload jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS m6_rule_evaluations_candidate_idx ON m6_rule_evaluations(candidate_id, created_at DESC);

CREATE TABLE IF NOT EXISTS m6_rule_versions (
    id text PRIMARY KEY, candidate_id text NOT NULL, fingerprint text NOT NULL, version text NOT NULL,
    code_digest text NOT NULL, definition jsonb NOT NULL DEFAULT '{}'::jsonb, payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(candidate_id, version)
);
CREATE INDEX IF NOT EXISTS m6_rule_versions_fingerprint_idx ON m6_rule_versions(fingerprint, created_at DESC);

CREATE TABLE IF NOT EXISTS m6_rule_registry_events (
    id text PRIMARY KEY, idempotency_key text NOT NULL UNIQUE, request_digest text NOT NULL,
    sequence bigserial NOT NULL UNIQUE,
    rule_version_id text NOT NULL, candidate_id text NOT NULL, fingerprint text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('promoted','enabled','disabled','rollback')),
    previous_id text NOT NULL DEFAULT '', actor text NOT NULL DEFAULT '', reason text NOT NULL DEFAULT '',
    payload jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS m6_rule_registry_events_fingerprint_idx ON m6_rule_registry_events(fingerprint, created_at DESC);

CREATE OR REPLACE FUNCTION m6_reject_rule_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME USING ERRCODE = '55000';
END;
$$;

DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['m6_rule_candidates','m6_rule_candidate_observations','m6_rule_candidate_events','m6_rule_evaluations','m6_rule_versions','m6_rule_registry_events'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS %I_plaintext_guard ON %I', table_name, table_name);
        EXECUTE format('CREATE TRIGGER %I_plaintext_guard BEFORE INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION m6_reject_plaintext_payload()', table_name, table_name);
        EXECUTE format('DROP TRIGGER IF EXISTS %I_immutable ON %I', table_name, table_name);
        EXECUTE format('CREATE TRIGGER %I_immutable BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m6_reject_rule_mutation()', table_name, table_name);
    END LOOP;
END;
$$;
