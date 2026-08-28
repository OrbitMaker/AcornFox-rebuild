-- Align durable controller states with the domain state machines. Migration
-- files are wrapped in a transaction by control-plane-migrate.sh.
ALTER TABLE operations
    DROP CONSTRAINT IF EXISTS operations_state_check;

ALTER TABLE operations
    ADD CONSTRAINT operations_state_check CHECK (state IN (
        'pending', 'leased', 'running', 'waiting', 'cancelling',
        'succeeded', 'failed', 'cancelled', 'rolling_back', 'rolled_back'
    ));

ALTER TABLE deployments
    DROP CONSTRAINT IF EXISTS deployments_state_check;

ALTER TABLE deployments
    ADD CONSTRAINT deployments_state_check CHECK (state IN (
        'pending', 'preparing', 'deploying', 'runtime_ready', 'serving',
        'degraded', 'failed', 'rolling_back', 'rolled_back', 'unknown', 'stopped'
    ));

ALTER TABLE task_leases
    ADD COLUMN IF NOT EXISTS last_agent_sequence bigint NOT NULL DEFAULT 0
        CHECK (last_agent_sequence >= 0),
    ADD COLUMN IF NOT EXISTS result_digest text,
    ADD COLUMN IF NOT EXISTS result jsonb,
    ADD COLUMN IF NOT EXISTS completed_at timestamptz;

CREATE TABLE task_agent_events (
    task_id text NOT NULL REFERENCES task_leases(task_id),
    sequence bigint NOT NULL CHECK (sequence > 0),
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    event_digest text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (task_id, sequence)
);

CREATE INDEX task_agent_events_created_idx
    ON task_agent_events (created_at, task_id, sequence);

CREATE TRIGGER task_agent_events_are_append_only
    BEFORE UPDATE OR DELETE ON task_agent_events
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
