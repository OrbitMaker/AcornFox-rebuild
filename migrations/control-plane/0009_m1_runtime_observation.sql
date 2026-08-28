-- A deployment becomes publicly usable in M1 only after the Agent has
-- reported a healthy immutable-digest runtime and the system-assigned
-- loopback endpoint has been persisted. Raw Docker inspection output is not
-- stored; the redacted wire observation and its evidence references remain in
-- task_agent_events.
ALTER TABLE deployments
    ADD COLUMN IF NOT EXISTS host_ip inet,
    ADD COLUMN IF NOT EXISTS host_port integer,
    ADD COLUMN IF NOT EXISTS last_observed_at timestamptz,
    ADD COLUMN IF NOT EXISTS runtime_healthy boolean NOT NULL DEFAULT false;

ALTER TABLE deployments
    ADD CONSTRAINT deployments_m1_endpoint_check CHECK (
        (host_ip IS NULL AND host_port IS NULL)
        OR (host_ip IS NOT NULL AND host_port BETWEEN 1 AND 65535)
    );

CREATE INDEX IF NOT EXISTS deployments_m1_endpoint_idx
    ON deployments (host_ip, host_port)
    WHERE host_port IS NOT NULL;

ALTER TABLE build_plans
    ADD COLUMN IF NOT EXISTS static_runtime_digest text;

ALTER TABLE build_plans
    ADD CONSTRAINT build_plans_m1_base_image_check CHECK (
        (build_kind = 'static' AND static_runtime_digest ~ '^sha256:[0-9a-f]{64}$')
        OR (build_kind = 'dockerfile' AND static_runtime_digest IS NULL)
    );
