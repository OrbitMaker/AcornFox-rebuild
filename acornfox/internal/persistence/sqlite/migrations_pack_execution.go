package sqlite

import (
	"strings"
)

const version0006_pack_protocol_execution = "0006_pack_protocol_execution"

var packExecutionSchemaDefinitions = []schemaObjectDef{
	{
		name: "pack_protocol_instances",
		sql: `CREATE TABLE pack_protocol_instances (
    pack_id TEXT NOT NULL REFERENCES pack_records(pack_id) ON DELETE RESTRICT,
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
    instance_id TEXT PRIMARY KEY NOT NULL,
    instance_generation INTEGER NOT NULL CHECK(instance_generation > 0),
    installation_binding TEXT NOT NULL CHECK(length(installation_binding)=64 AND installation_binding NOT GLOB '*[^0-9a-f]*'),
    manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'),
    executable_sha256 TEXT NOT NULL CHECK(length(executable_sha256)=64 AND executable_sha256 NOT GLOB '*[^0-9a-f]*'),
    executable_path TEXT NOT NULL CHECK(length(trim(executable_path)) > 0),
    protocol_version TEXT NOT NULL CHECK(protocol_version = '1.0'),
    capabilities TEXT NOT NULL CHECK(json_valid(capabilities)=1),
    expected_uid INTEGER NOT NULL,
    expected_pid INTEGER NOT NULL CHECK(expected_pid > 0),
    process_start_identity TEXT NOT NULL CHECK(length(trim(process_start_identity)) > 0),
    socket_path TEXT NOT NULL CHECK(length(trim(socket_path)) > 0),
    core_generation INTEGER NOT NULL CHECK(core_generation > 0),
    retired_at TEXT CHECK(retired_at IS NULL OR retired_at GLOB '` + timePattern + `'),
    created_at TEXT NOT NULL CHECK(created_at GLOB '` + timePattern + `'),
    updated_at TEXT NOT NULL CHECK(updated_at GLOB '` + timePattern + `' AND updated_at >= created_at),
    CHECK(length(trim(instance_id)) > 0)
);`,
	},
	{
		name: "pack_protocol_instances_active_idx",
		sql: `CREATE UNIQUE INDEX pack_protocol_instances_active_idx
    ON pack_protocol_instances (pack_id)
    WHERE retired_at IS NULL;`,
	},
	{
		name: "pack_protocol_instances_gen_idx",
		sql: `CREATE UNIQUE INDEX pack_protocol_instances_gen_idx
    ON pack_protocol_instances (pack_id, instance_generation);`,
	},
	{
		name: "pack_protocol_checks",
		sql: `CREATE TABLE pack_protocol_checks (
    task_id TEXT PRIMARY KEY NOT NULL REFERENCES task_leases(task_id) ON DELETE RESTRICT,
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
    pack_id TEXT NOT NULL REFERENCES pack_records(pack_id) ON DELETE RESTRICT,
    instance_id TEXT NOT NULL REFERENCES pack_protocol_instances(instance_id) ON DELETE RESTRICT,
    instance_generation INTEGER NOT NULL CHECK(instance_generation > 0),
    kind TEXT NOT NULL CHECK(kind = 'pack.protocol.observe'),
    capability TEXT NOT NULL CHECK(capability = 'diagnostic.observe'),
    scope TEXT NOT NULL CHECK(length(trim(scope)) > 0),
    idempotency_key TEXT NOT NULL CHECK(length(trim(idempotency_key)) > 0),
    input_digest TEXT NOT NULL CHECK(length(input_digest)=64 AND input_digest NOT GLOB '*[^0-9a-f]*'),
    input_context TEXT NOT NULL CHECK(json_valid(input_context)=1),
    cancellation_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancellation_requested IN (0,1)),
    cancellation_reason TEXT,
    cancellation_requested_at TEXT CHECK(cancellation_requested_at IS NULL OR cancellation_requested_at GLOB '` + timePattern + `'),
    created_at TEXT NOT NULL CHECK(created_at GLOB '` + timePattern + `'),
    updated_at TEXT NOT NULL CHECK(updated_at GLOB '` + timePattern + `' AND updated_at >= created_at)
);`,
	},
	{
		name: "pack_protocol_checks_key",
		sql: `CREATE UNIQUE INDEX pack_protocol_checks_key
    ON pack_protocol_checks (pack_id, idempotency_key);`,
	},
	{
		name: "pack_protocol_checks_op_idx",
		sql: `CREATE INDEX pack_protocol_checks_op_idx
    ON pack_protocol_checks (operation_id);`,
	},
	{
		name: "pack_protocol_events",
		sql: `CREATE TABLE pack_protocol_events (
    receipt_id TEXT PRIMARY KEY NOT NULL,
    task_id TEXT NOT NULL REFERENCES pack_protocol_checks(task_id) ON DELETE RESTRICT,
    instance_id TEXT NOT NULL REFERENCES pack_protocol_instances(instance_id) ON DELETE RESTRICT,
    core_generation INTEGER NOT NULL CHECK(core_generation > 0),
    lease_generation INTEGER NOT NULL CHECK(lease_generation > 0),
    instance_generation INTEGER NOT NULL CHECK(instance_generation > 0),
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    input_digest TEXT NOT NULL CHECK(length(input_digest)=64 AND input_digest NOT GLOB '*[^0-9a-f]*'),
    event_digest TEXT NOT NULL CHECK(length(event_digest)=64 AND event_digest NOT GLOB '*[^0-9a-f]*'),
    kind TEXT NOT NULL CHECK(length(trim(kind)) > 0),
    terminal INTEGER NOT NULL CHECK(terminal IN (0,1)),
    terminal_status TEXT CHECK(terminal_status IS NULL OR terminal_status IN ('succeeded','failed')),
    payload TEXT NOT NULL CHECK(json_valid(payload)=1),
    committed_at TEXT NOT NULL CHECK(committed_at GLOB '` + timePattern + `'),
    created_at TEXT NOT NULL CHECK(created_at GLOB '` + timePattern + `'),
    CHECK(length(trim(receipt_id)) > 0)
);`,
	},
	{
		name: "pack_protocol_events_task_seq",
		sql: `CREATE UNIQUE INDEX pack_protocol_events_task_seq
    ON pack_protocol_events (task_id, sequence);`,
	},
	{
		name: "pack_protocol_events_task_digest",
		sql: `CREATE UNIQUE INDEX pack_protocol_events_task_digest
    ON pack_protocol_events (task_id, event_digest);`,
	},
}

var packExecutionTriggers = []schemaObjectDef{
	{
		name: "pack_protocol_instances_frozen_fields",
		sql: `CREATE TRIGGER pack_protocol_instances_frozen_fields BEFORE UPDATE ON pack_protocol_instances BEGIN
 SELECT CASE WHEN NEW.pack_id<>OLD.pack_id OR NEW.operation_id<>OLD.operation_id OR NEW.instance_id<>OLD.instance_id OR NEW.instance_generation<>OLD.instance_generation OR NEW.installation_binding<>OLD.installation_binding OR NEW.manifest_sha256<>OLD.manifest_sha256 OR NEW.executable_sha256<>OLD.executable_sha256 OR NEW.executable_path<>OLD.executable_path OR NEW.protocol_version<>OLD.protocol_version OR NEW.capabilities<>OLD.capabilities OR NEW.expected_uid<>OLD.expected_uid OR NEW.expected_pid<>OLD.expected_pid OR NEW.process_start_identity<>OLD.process_start_identity OR NEW.socket_path<>OLD.socket_path OR NEW.core_generation<>OLD.core_generation OR NEW.created_at<>OLD.created_at OR (OLD.retired_at IS NOT NULL AND (NEW.retired_at IS NULL OR NEW.retired_at<>OLD.retired_at)) THEN RAISE(ABORT,'pack protocol instance identity is immutable') END;
 END;`,
	},
	{
		name: "pack_protocol_instances_no_delete",
		sql: `CREATE TRIGGER pack_protocol_instances_no_delete BEFORE DELETE ON pack_protocol_instances BEGIN
 SELECT RAISE(ABORT,'pack protocol instance history is immutable');
 END;`,
	},
	{
		name: "pack_protocol_checks_frozen_fields",
		sql: `CREATE TRIGGER pack_protocol_checks_frozen_fields BEFORE UPDATE ON pack_protocol_checks BEGIN
 SELECT CASE WHEN NEW.task_id<>OLD.task_id OR NEW.operation_id<>OLD.operation_id OR NEW.pack_id<>OLD.pack_id OR NEW.instance_id<>OLD.instance_id OR NEW.instance_generation<>OLD.instance_generation OR NEW.kind<>OLD.kind OR NEW.capability<>OLD.capability OR NEW.scope<>OLD.scope OR NEW.idempotency_key<>OLD.idempotency_key OR NEW.input_digest<>OLD.input_digest OR NEW.input_context<>OLD.input_context OR NEW.created_at<>OLD.created_at THEN RAISE(ABORT,'pack protocol check identity is immutable') END;
 END;`,
	},
	{
		name: "pack_protocol_checks_no_delete",
		sql: `CREATE TRIGGER pack_protocol_checks_no_delete BEFORE DELETE ON pack_protocol_checks BEGIN
 SELECT RAISE(ABORT,'pack protocol check history is immutable');
 END;`,
	},
	{
		name: "pack_protocol_events_frozen",
		sql: `CREATE TRIGGER pack_protocol_events_frozen BEFORE UPDATE ON pack_protocol_events BEGIN
 SELECT RAISE(ABORT,'pack protocol event history is immutable');
 END;`,
	},
	{
		name: "pack_protocol_events_no_delete",
		sql: `CREATE TRIGGER pack_protocol_events_no_delete BEFORE DELETE ON pack_protocol_events BEGIN
 SELECT RAISE(ABORT,'pack protocol event history is immutable');
 END;`,
	},
}

func packExecutionMigrationSQL() string {
	var b strings.Builder
	for _, o := range packExecutionSchemaDefinitions {
		b.WriteString(o.sql)
		b.WriteString("\n\n")
	}
	for _, o := range packExecutionTriggers {
		b.WriteString(o.sql)
		b.WriteString("\n\n")
	}
	return b.String()
}
