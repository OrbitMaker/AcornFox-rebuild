-- AcornFox lifecycle and retention management.
-- Preserves existing 40 migrations intact.

-- 1. applications table: add management_state and archived_at
ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS management_state text NOT NULL DEFAULT 'active'
        CHECK (management_state IN ('active', 'archiving', 'archived')),
    ADD COLUMN IF NOT EXISTS archived_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_applications_management_state
    ON applications (management_state);

-- 2. deployments table: add 'paused' to state check constraint
ALTER TABLE deployments
    DROP CONSTRAINT IF EXISTS deployments_state_check;

ALTER TABLE deployments
    ADD CONSTRAINT deployments_state_check CHECK (state IN (
        'pending', 'preparing', 'deploying', 'runtime_ready', 'serving',
        'degraded', 'failed', 'rolling_back', 'rolled_back', 'unknown', 'stopped', 'paused'
    ));

-- 3. m1_publish_requests table: add application_id
ALTER TABLE m1_publish_requests
    ADD COLUMN IF NOT EXISTS application_id text REFERENCES applications(id);

CREATE INDEX IF NOT EXISTS idx_m1_publish_requests_app_status
    ON m1_publish_requests (application_id, status);

-- 4. acornfox_management_commands table
CREATE TABLE IF NOT EXISTS acornfox_management_commands (
    id text PRIMARY KEY,
    application_id text NOT NULL REFERENCES applications(id),
    idempotency_key text NOT NULL,
    request_digest text NOT NULL,
    target_set_digest text NOT NULL DEFAULT '',
    action text NOT NULL CHECK (action IN ('stop', 'start', 'archive')),
    phase text NOT NULL CHECK (phase IN (
        'accepted',
        'route_closing',
        'runtime_stopping',
        'runtime_starting',
        'probing',
        'route_restoring',
        'runtime_destroying',
        'verifying_retention',
        'archived',
        'completed',
        'failed'
    )),
    phase_version bigint NOT NULL DEFAULT 1 CHECK (phase_version > 0),
    lease_owner text,
    lease_token text,
    lease_expires_at timestamptz,
    failure_reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT acornfox_management_commands_key_check CHECK (length(trim(idempotency_key)) BETWEEN 1 AND 512),
    CONSTRAINT acornfox_management_commands_digest_check CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT acornfox_management_commands_failure_check CHECK ((phase = 'failed') = (failure_reason IS NOT NULL))
);

-- Only one nonterminal management command per application
CREATE UNIQUE INDEX IF NOT EXISTS acornfox_management_commands_active_app_uidx
    ON acornfox_management_commands (application_id)
    WHERE phase NOT IN ('completed', 'failed');

-- Unique idempotency key per application
CREATE UNIQUE INDEX IF NOT EXISTS acornfox_management_commands_idempotency_uidx
    ON acornfox_management_commands (application_id, idempotency_key);

-- 5. acornfox_management_targets table
CREATE TABLE IF NOT EXISTS acornfox_management_targets (
    id text PRIMARY KEY,
    command_id text NOT NULL REFERENCES acornfox_management_commands(id),
    deployment_id text NOT NULL REFERENCES deployments(id),
    release_id text NOT NULL REFERENCES releases(id),
    snapshot_deployment_version bigint NOT NULL CHECK (snapshot_deployment_version > 0),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    route_phase text NOT NULL DEFAULT 'initial' CHECK (route_phase IN ('initial', 'closed', 'restored', 'conflict', 'skipped')),
    runtime_task_id text REFERENCES task_leases(task_id),
    probe_task_id text REFERENCES task_leases(task_id),
    original_desired_public boolean NOT NULL DEFAULT false,
    original_route_intent jsonb,
    config_identity text,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'conflict')),
    failure_reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (command_id, deployment_id)
);

CREATE INDEX IF NOT EXISTS idx_acornfox_management_targets_cmd
    ON acornfox_management_targets (command_id);

CREATE INDEX IF NOT EXISTS idx_acornfox_management_targets_dep
    ON acornfox_management_targets (deployment_id);

-- 6. acornfox_pause_receipts table
CREATE TABLE IF NOT EXISTS acornfox_pause_receipts (
    deployment_id text PRIMARY KEY REFERENCES deployments(id),
    application_id text NOT NULL REFERENCES applications(id),
    stop_command_id text NOT NULL REFERENCES acornfox_management_commands(id),
    config_identity text NOT NULL,
    release_id text NOT NULL REFERENCES releases(id),
    original_desired_public boolean NOT NULL DEFAULT false,
    canonical_intent jsonb,
    intent_digest text,
    pause_epoch bigint NOT NULL DEFAULT 1 CHECK (pause_epoch > 0),
    consumed boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_acornfox_pause_receipts_app
    ON acornfox_pause_receipts (application_id);

-- 7. acornfox_management_retention_evidence table
CREATE TABLE IF NOT EXISTS acornfox_management_retention_evidence (
    command_id text NOT NULL REFERENCES acornfox_management_commands(id),
    target_id text NOT NULL REFERENCES acornfox_management_targets(id),
    task_id text NOT NULL REFERENCES task_leases(task_id),
    deployment_id text NOT NULL REFERENCES deployments(id),
    sequence bigint NOT NULL CHECK (sequence > 0),
    event_digest text NOT NULL,
    verified_retained_volumes jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (target_id, task_id)
);

CREATE INDEX IF NOT EXISTS idx_acornfox_retention_evidence_cmd
    ON acornfox_management_retention_evidence (command_id);

-- 8. acornfox_retained_volumes table
CREATE TABLE IF NOT EXISTS acornfox_retained_volumes (
    id text PRIMARY KEY,
    application_id text NOT NULL REFERENCES applications(id),
    logical_name text NOT NULL,
    managed_volume_name text NOT NULL,
    volume_driver text NOT NULL DEFAULT 'local',
    receipt_digest text NOT NULL,
    verified_at timestamptz NOT NULL,
    last_verified_deployment_id text NOT NULL REFERENCES deployments(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT acornfox_retained_volumes_logical_name_check CHECK (length(trim(logical_name)) > 0),
    CONSTRAINT acornfox_retained_volumes_managed_name_check CHECK (length(trim(managed_volume_name)) > 0),
    CONSTRAINT acornfox_retained_volumes_receipt_digest_check CHECK (receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
    UNIQUE (application_id, logical_name)
);

CREATE INDEX IF NOT EXISTS idx_acornfox_retained_volumes_app
    ON acornfox_retained_volumes (application_id);

-- 9. acornfox_public_access_commands table: add management_command_id
ALTER TABLE acornfox_public_access_commands
    ADD COLUMN IF NOT EXISTS management_command_id text REFERENCES acornfox_management_commands(id);

CREATE INDEX IF NOT EXISTS idx_afpa_commands_mgmt_id
    ON acornfox_public_access_commands (management_command_id);
