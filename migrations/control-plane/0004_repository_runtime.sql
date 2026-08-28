-- The first three migrations predate the persistent repository. Keep their
-- aggregate-local outbox sequence for compatibility and add a separate,
-- database-owned global cursor for replay and SSE Last-Event-ID.
CREATE SEQUENCE IF NOT EXISTS outbox_events_stream_sequence AS bigint;

ALTER TABLE outbox_events
    ADD COLUMN IF NOT EXISTS stream_sequence bigint;

WITH pending AS (
    SELECT id
      FROM outbox_events
     WHERE stream_sequence IS NULL
     ORDER BY created_at, id
)
UPDATE outbox_events AS event
   SET stream_sequence = nextval('outbox_events_stream_sequence'::regclass)
  FROM pending
 WHERE event.id = pending.id;

SELECT setval(
    'outbox_events_stream_sequence'::regclass,
    COALESCE(MAX(stream_sequence), 1),
    MAX(stream_sequence) IS NOT NULL
)
FROM outbox_events;

ALTER TABLE outbox_events
    ALTER COLUMN stream_sequence SET DEFAULT nextval('outbox_events_stream_sequence'::regclass),
    ALTER COLUMN stream_sequence SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'outbox_events'::regclass
           AND conname = 'outbox_events_stream_sequence_positive'
    ) THEN
        ALTER TABLE outbox_events
            ADD CONSTRAINT outbox_events_stream_sequence_positive
            CHECK (stream_sequence > 0);
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS outbox_events_stream_sequence_uidx
    ON outbox_events (stream_sequence);

CREATE INDEX IF NOT EXISTS outbox_events_stream_replay_idx
    ON outbox_events (stream_sequence, aggregate_type, aggregate_id);

CREATE INDEX IF NOT EXISTS outbox_events_operation_replay_idx
    ON outbox_events (aggregate_id, stream_sequence)
    WHERE aggregate_type = 'operation';

-- Operations can now be reconstructed without joining through a mutable
-- environment projection. Existing rows derive application_id from their
-- environment before the new NOT NULL/FK invariant is installed.
ALTER TABLE operations
    ADD COLUMN IF NOT EXISTS application_id text;

UPDATE operations AS operation
   SET application_id = environment.application_id
  FROM environments AS environment
 WHERE operation.environment_id = environment.id
   AND operation.application_id IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'operations'::regclass
           AND conname = 'operations_application_id_fkey'
    ) THEN
        ALTER TABLE operations
            ADD CONSTRAINT operations_application_id_fkey
            FOREIGN KEY (application_id) REFERENCES applications(id);
    END IF;
END
$$;

ALTER TABLE operations
    ALTER COLUMN application_id SET NOT NULL,
    ADD COLUMN IF NOT EXISTS target_ref text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS failure_reason text;

CREATE INDEX IF NOT EXISTS operations_application_idx
    ON operations (application_id, created_at, id);

-- Task retry policy and a redacted failure reason are durable task facts. A
-- positive default keeps rows created by 0001 claimable after upgrading.
ALTER TABLE task_leases
    ADD COLUMN IF NOT EXISTS max_attempts integer;

UPDATE task_leases
     SET max_attempts = 3
 WHERE max_attempts IS NULL;

ALTER TABLE task_leases
    ALTER COLUMN max_attempts SET DEFAULT 3,
    ALTER COLUMN max_attempts SET NOT NULL,
    ADD COLUMN IF NOT EXISTS last_error text;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'task_leases'::regclass
           AND conname = 'task_leases_max_attempts_positive'
    ) THEN
        ALTER TABLE task_leases
            ADD CONSTRAINT task_leases_max_attempts_positive
            CHECK (max_attempts > 0);
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS task_leases_claimable_runtime_idx
    ON task_leases (state, lease_until, created_at, task_id);

-- Idempotency is scoped so the same key can safely be used by distinct
-- use-cases. A completed row must carry its exact persisted response; an
-- in-progress row is intentionally not stealable by a retry.
CREATE TABLE IF NOT EXISTS idempotency_records (
    scope text NOT NULL,
    idempotency_key text NOT NULL,
    request_digest text NOT NULL,
    status text NOT NULL CHECK (status IN ('in_progress', 'completed', 'failed')),
    response jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope, idempotency_key),
    CHECK ((status = 'completed') = (response IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idempotency_records_updated_idx
    ON idempotency_records (updated_at, scope);

-- Event identity, aggregate, versions, type, payload, and creation time are
-- append-only. Publishing is the sole permitted update so a crash-safe
-- publisher can retry a delivery without changing event history.
CREATE OR REPLACE FUNCTION reject_outbox_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'outbox_events rows are append-only'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.aggregate_type IS DISTINCT FROM OLD.aggregate_type
       OR NEW.aggregate_id IS DISTINCT FROM OLD.aggregate_id
       OR NEW.aggregate_version IS DISTINCT FROM OLD.aggregate_version
       OR NEW.sequence IS DISTINCT FROM OLD.sequence
       OR NEW.stream_sequence IS DISTINCT FROM OLD.stream_sequence
       OR NEW.event_type IS DISTINCT FROM OLD.event_type
       OR NEW.payload IS DISTINCT FROM OLD.payload
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'outbox_events history is append-only'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.published_at IS NOT NULL
       AND NEW.published_at IS DISTINCT FROM OLD.published_at THEN
        RAISE EXCEPTION 'outbox_events publication marker is monotonic'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'outbox_events'::regclass
           AND tgname = 'outbox_events_are_append_only'
    ) THEN
        CREATE TRIGGER outbox_events_are_append_only
            BEFORE UPDATE OR DELETE ON outbox_events
            FOR EACH ROW EXECUTE FUNCTION reject_outbox_event_mutation();
    END IF;
END
$$;
