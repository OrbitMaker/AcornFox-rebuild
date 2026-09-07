-- Administrator-confirmed assistant restart/redeploy proposals. PI/tool calls
-- can only insert pending rows; approval and execution remain Go HTTP actions.

CREATE TABLE IF NOT EXISTS acornfox_assistant_actions (
    id text PRIMARY KEY,
    owner_admin_id text NOT NULL REFERENCES admin_credentials(id) ON DELETE RESTRICT,
    assistant_session_id text NOT NULL REFERENCES acornfox_assistant_sessions(id) ON DELETE CASCADE,
    assistant_run_id text NOT NULL REFERENCES acornfox_assistant_runs(id) ON DELETE CASCADE,
    proposal_key char(64) NOT NULL UNIQUE CHECK (proposal_key ~ '^[0-9a-f]{64}$'),
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    execution_key text NOT NULL UNIQUE CHECK (length(execution_key) BETWEEN 1 AND 128),
    action text NOT NULL CHECK (action IN ('restart', 'redeploy')),
    application_id text NOT NULL REFERENCES applications(id) ON DELETE RESTRICT,
    deployment_id text NOT NULL REFERENCES deployments(id) ON DELETE RESTRICT,
    target_release_id text NOT NULL REFERENCES releases(id) ON DELETE RESTRICT,
    target_release_version bigint NOT NULL CHECK (target_release_version > 0),
    safe_application_name text NOT NULL CHECK (length(safe_application_name) BETWEEN 1 AND 128),
    state text NOT NULL CHECK (state IN ('pending','rejected','expired','executing','accepted','unknown','verified','failed')),
    operation_id text REFERENCES operations(id) ON DELETE RESTRICT,
    verification_state text NOT NULL DEFAULT 'pending' CHECK (verification_state IN ('pending','verified','failed')),
    verification_verdict text NOT NULL DEFAULT '' CHECK (length(verification_verdict) <= 256),
    verification_observed_at timestamptz,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (expires_at > created_at AND updated_at >= created_at)
);
CREATE INDEX IF NOT EXISTS acornfox_assistant_actions_session_idx
    ON acornfox_assistant_actions (owner_admin_id, assistant_session_id, created_at, id);
CREATE UNIQUE INDEX IF NOT EXISTS acornfox_assistant_one_active_action_per_app_idx
    ON acornfox_assistant_actions (application_id)
    WHERE state IN ('executing','accepted','unknown');
