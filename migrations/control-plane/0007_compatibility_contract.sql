-- Additive N-1/N compatibility metadata. Existing readers continue selecting
-- their original columns; new readers receive explicit 1.0 defaults for rows
-- written before version negotiation existed.
ALTER TABLE outbox_events
    ADD COLUMN IF NOT EXISTS payload_version text NOT NULL DEFAULT '1.0',
    ADD COLUMN IF NOT EXISTS compatibility jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE task_leases
    ADD COLUMN IF NOT EXISTS wire_version text NOT NULL DEFAULT '1.0',
    ADD COLUMN IF NOT EXISTS negotiated_capabilities jsonb NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE task_agent_events
    ADD COLUMN IF NOT EXISTS wire_version text NOT NULL DEFAULT '1.0',
    ADD COLUMN IF NOT EXISTS compatibility_report jsonb NOT NULL DEFAULT '{}'::jsonb;

UPDATE outbox_events
   SET payload_version = payload->>'schema_version'
 WHERE payload ? 'schema_version'
   AND payload->>'schema_version' ~ '^[0-9]+\.[0-9]+$';

ALTER TABLE outbox_events
    ADD CONSTRAINT outbox_events_payload_version_format
    CHECK (payload_version ~ '^[0-9]+\.[0-9]+$');

ALTER TABLE task_leases
    ADD CONSTRAINT task_leases_wire_version_format
    CHECK (wire_version ~ '^[0-9]+\.[0-9]+$');

ALTER TABLE task_agent_events
    ADD CONSTRAINT task_agent_events_wire_version_format
    CHECK (wire_version ~ '^[0-9]+\.[0-9]+$');

CREATE TABLE protocol_contracts (
    component text NOT NULL,
    version text NOT NULL,
    minimum_peer_version text NOT NULL,
    capabilities jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (component, version),
    CHECK (version ~ '^[0-9]+\.[0-9]+$'),
    CHECK (minimum_peer_version ~ '^[0-9]+\.[0-9]+$'),
    CHECK (jsonb_typeof(capabilities) = 'array')
);

INSERT INTO protocol_contracts(component,version,minimum_peer_version,capabilities)
VALUES
    ('rest-sse','1.0','1.0','["rest","sse"]'::jsonb),
    ('rest-sse','1.1','1.0','["rest","sse","persistent_sse_schema"]'::jsonb),
    ('agent','1.0','1.0','["mtls","typed_tasks","heartbeat"]'::jsonb),
    ('agent','1.1','1.0','["mtls","typed_tasks","heartbeat","agent_sequence","observation_details"]'::jsonb);

CREATE TRIGGER protocol_contracts_are_append_only
    BEFORE UPDATE OR DELETE ON protocol_contracts
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
