package sqlite

import (
	"strings"
)

const version0002_application_repository = "0002_application_repository"

var applicationSchemaDefinitions = []schemaObjectDef{
	{
		name: "idempotency_records",
		sql: `CREATE TABLE IF NOT EXISTS idempotency_records (
    scope TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('in_progress', 'completed', 'failed')),
    response TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (scope, idempotency_key),
    CHECK (length(trim(scope)) > 0),
    CHECK (length(trim(idempotency_key)) > 0),
    CHECK (length(trim(request_digest)) > 0),
    CHECK (created_at GLOB '` + timePattern + `'),
    CHECK (updated_at GLOB '` + timePattern + `'),
    CHECK (updated_at >= created_at),
    CHECK (
        (status = 'completed' AND response IS NOT NULL AND json_valid(response) = 1)
        OR
        (status IN ('in_progress', 'failed') AND response IS NULL)
    )
);`,
	},
	{
		name: "idempotency_records_updated_idx",
		sql: `CREATE INDEX IF NOT EXISTS idempotency_records_updated_idx
    ON idempotency_records (updated_at, scope);`,
	},
	{
		name: "applications",
		sql: `CREATE TABLE IF NOT EXISTS applications (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (length(trim(id)) > 0),
    CHECK (length(trim(name)) > 0),
    CHECK (version > 0),
    CHECK (created_at GLOB '` + timePattern + `'),
    CHECK (updated_at GLOB '` + timePattern + `'),
    CHECK (updated_at >= created_at)
);`,
	},
	{
		name: "applications_created_idx",
		sql: `CREATE INDEX IF NOT EXISTS applications_created_idx
    ON applications (created_at, id);`,
	},
	{
		name: "environments",
		sql: `CREATE TABLE IF NOT EXISTS environments (
    id TEXT PRIMARY KEY NOT NULL,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (application_id, name),
    CHECK (length(trim(id)) > 0),
    CHECK (length(trim(application_id)) > 0),
    CHECK (length(trim(name)) > 0),
    CHECK (created_at GLOB '` + timePattern + `')
);`,
	},
	{
		name: "operations",
		sql: `CREATE TABLE IF NOT EXISTS operations (
    id TEXT PRIMARY KEY NOT NULL,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE RESTRICT,
    environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
    operation_type TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'pending', 'leased', 'running', 'waiting', 'cancelling',
        'succeeded', 'failed', 'cancelled', 'rolling_back', 'rolled_back'
    )),
    version INTEGER NOT NULL DEFAULT 1,
    target_ref TEXT NOT NULL DEFAULT '',
    failure_reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    target_kind TEXT NOT NULL DEFAULT 'application' CHECK (target_kind = 'application'),
    UNIQUE (environment_id, idempotency_key),
    CHECK (length(trim(id)) > 0),
    CHECK (length(trim(application_id)) > 0),
    CHECK (length(trim(environment_id)) > 0),
    CHECK (length(trim(operation_type)) > 0),
    CHECK (length(trim(idempotency_key)) > 0),
    CHECK (version > 0),
    CHECK (created_at GLOB '` + timePattern + `'),
    CHECK (updated_at GLOB '` + timePattern + `'),
    CHECK (updated_at >= created_at)
);`,
	},
	{
		name: "operations_application_idx",
		sql: `CREATE INDEX IF NOT EXISTS operations_application_idx
    ON operations (application_id, created_at, id);`,
	},
	{
		name: "operations_one_active_per_environment",
		sql: `CREATE UNIQUE INDEX IF NOT EXISTS operations_one_active_per_environment
    ON operations (environment_id)
    WHERE state IN ('pending', 'leased', 'running', 'waiting', 'cancelling');`,
	},
	{
		name: "task_leases",
		sql: `CREATE TABLE IF NOT EXISTS task_leases (
    task_id TEXT PRIMARY KEY NOT NULL,
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
    lease_owner TEXT,
    lease_until TEXT,
    attempt INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    state TEXT NOT NULL CHECK (state IN ('ready', 'leased', 'completed', 'failed', 'cancelled')),
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (length(trim(task_id)) > 0),
    CHECK (length(trim(operation_id)) > 0),
    CHECK (attempt >= 0),
    CHECK (max_attempts > 0),
    CHECK (json_valid(payload) = 1),
    CHECK (created_at GLOB '` + timePattern + `'),
    CHECK (updated_at GLOB '` + timePattern + `'),
    CHECK (updated_at >= created_at),
    CHECK (lease_until IS NULL OR lease_until GLOB '` + timePattern + `')
);`,
	},
	{
		name: "task_leases_claimable_runtime_idx",
		sql: `CREATE INDEX IF NOT EXISTS task_leases_claimable_runtime_idx
    ON task_leases (state, lease_until, created_at, task_id);`,
	},
	{
		name: "outbox_events",
		sql: `CREATE TABLE IF NOT EXISTS outbox_events (
    id TEXT PRIMARY KEY NOT NULL,
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    aggregate_version INTEGER NOT NULL,
    sequence INTEGER NOT NULL,
    stream_sequence INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL,
    published_at TEXT,
    payload_version TEXT NOT NULL DEFAULT '1.0',
    CHECK (length(trim(id)) > 0),
    CHECK (length(trim(aggregate_type)) > 0),
    CHECK (length(trim(aggregate_id)) > 0),
    CHECK (aggregate_version > 0),
    CHECK (sequence > 0),
    CHECK (stream_sequence > 0),
    CHECK (length(trim(event_type)) > 0),
    CHECK (json_valid(payload) = 1),
    CHECK (created_at GLOB '` + timePattern + `'),
    CHECK (published_at IS NULL OR published_at GLOB '` + timePattern + `'),
    CHECK (length(trim(payload_version)) > 0),
    UNIQUE (aggregate_type, aggregate_id, sequence)
);`,
	},
	{
		name: "outbox_events_stream_sequence_uidx",
		sql: `CREATE UNIQUE INDEX IF NOT EXISTS outbox_events_stream_sequence_uidx
    ON outbox_events (stream_sequence);`,
	},
	{
		name: "outbox_events_stream_replay_idx",
		sql: `CREATE INDEX IF NOT EXISTS outbox_events_stream_replay_idx
    ON outbox_events (stream_sequence, aggregate_type, aggregate_id);`,
	},
	{
		name: "outbox_events_operation_replay_idx",
		sql: `CREATE INDEX IF NOT EXISTS outbox_events_operation_replay_idx
    ON outbox_events (aggregate_id, stream_sequence)
    WHERE aggregate_type = 'operation';`,
	},
	{
		name: "outbox_events_pending_idx",
		sql: `CREATE INDEX IF NOT EXISTS outbox_events_pending_idx
    ON outbox_events (created_at, id)
    WHERE published_at IS NULL;`,
	},
	{
		name: "outbox_events_no_delete",
		sql: `CREATE TRIGGER IF NOT EXISTS outbox_events_no_delete
BEFORE DELETE ON outbox_events
BEGIN
    SELECT RAISE(ABORT, 'outbox_events rows are append-only');
END;`,
	},
	{
		name: "outbox_events_no_update",
		sql: `CREATE TRIGGER IF NOT EXISTS outbox_events_no_update
BEFORE UPDATE ON outbox_events
BEGIN
    SELECT CASE
        WHEN NEW.id <> OLD.id
          OR NEW.aggregate_type <> OLD.aggregate_type
          OR NEW.aggregate_id <> OLD.aggregate_id
          OR NEW.aggregate_version <> OLD.aggregate_version
          OR NEW.sequence <> OLD.sequence
          OR NEW.stream_sequence <> OLD.stream_sequence
          OR NEW.event_type <> OLD.event_type
          OR NEW.payload <> OLD.payload
          OR NEW.created_at <> OLD.created_at
          OR NEW.payload_version <> OLD.payload_version
        THEN RAISE(ABORT, 'outbox_events history is append-only')
        WHEN OLD.published_at IS NOT NULL AND (NEW.published_at IS NULL OR NEW.published_at <> OLD.published_at)
        THEN RAISE(ABORT, 'outbox_events publication marker is monotonic')
    END;
END;`,
	},
}

func applicationMigrationSQL() string {
	var sb strings.Builder
	for _, obj := range applicationSchemaDefinitions {
		sb.WriteString(obj.sql)
		sb.WriteString("\n\n")
	}
	return sb.String()
}
