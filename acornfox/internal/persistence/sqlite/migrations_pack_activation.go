package sqlite

import (
	"strings"
)

const version0008_pack_activation = "0008_pack_activation"

var packActivationSchemaDefinitions = []schemaObjectDef{
	{
		name: "pack_activation_journal",
		sql: `CREATE TABLE pack_activation_journal (
    journal_id TEXT PRIMARY KEY NOT NULL,
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
    pack_id TEXT NOT NULL REFERENCES pack_records(pack_id) ON DELETE RESTRICT,
    version TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256)=64 AND plan_sha256 NOT GLOB '*[^0-9a-f]*'),
    artifact_receipt_id TEXT NOT NULL REFERENCES pack_artifact_receipts(receipt_id) ON DELETE RESTRICT,
    phase TEXT NOT NULL CHECK(phase IN ('publishing','published','starting','started','ready','active','cancelled','failed')),
    revision INTEGER NOT NULL CHECK(revision > 0),
    core_generation INTEGER NOT NULL CHECK(core_generation > 0),
    lease_generation INTEGER NOT NULL CHECK(lease_generation > 0),
    owner_id TEXT NOT NULL CHECK(length(trim(owner_id)) > 0),
    publish_id TEXT NOT NULL CHECK(length(trim(publish_id)) > 0),
    installed_root TEXT NOT NULL CHECK(length(trim(installed_root)) > 0),
    unit_name TEXT NOT NULL CHECK(length(trim(unit_name)) > 0),
    instance_id TEXT,
    main_pid INTEGER,
    socket_path TEXT,
    process_start_identity TEXT,
    candidate_capabilities TEXT CHECK(candidate_capabilities IS NULL OR json_valid(candidate_capabilities)=1),
    current_pointer_effect TEXT,
    activation_generation INTEGER,
    failure_reason TEXT,
    created_at TEXT NOT NULL CHECK(created_at GLOB '` + timePattern + `'),
    updated_at TEXT NOT NULL CHECK(updated_at GLOB '` + timePattern + `' AND updated_at >= created_at),
    CHECK(length(trim(journal_id)) > 0)
);`,
	},
	{
		name: "pack_activation_journal_op",
		sql: `CREATE UNIQUE INDEX pack_activation_journal_op
    ON pack_activation_journal (operation_id);`,
	},
	{
		name: "pack_activation_journal_pack",
		sql: `CREATE INDEX pack_activation_journal_pack
    ON pack_activation_journal (pack_id, version);`,
	},
	{
		name: "pack_activation_receipts",
		sql: `CREATE TABLE pack_activation_receipts (
    receipt_id TEXT PRIMARY KEY NOT NULL,
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
    pack_id TEXT NOT NULL REFERENCES pack_records(pack_id) ON DELETE RESTRICT,
    version TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256)=64 AND plan_sha256 NOT GLOB '*[^0-9a-f]*'),
    artifact_receipt_id TEXT NOT NULL REFERENCES pack_artifact_receipts(receipt_id) ON DELETE RESTRICT,
    installed_root TEXT NOT NULL CHECK(length(trim(installed_root)) > 0),
    relative_current_target TEXT NOT NULL CHECK(length(trim(relative_current_target)) > 0),
    unit_name TEXT NOT NULL CHECK(length(trim(unit_name)) > 0),
    service_identity TEXT NOT NULL CHECK(length(trim(service_identity)) > 0),
    instance_id TEXT NOT NULL CHECK(length(trim(instance_id)) > 0),
    main_pid INTEGER NOT NULL CHECK(main_pid > 0),
    process_start_identity TEXT NOT NULL CHECK(length(trim(process_start_identity)) > 0),
    socket_path TEXT NOT NULL CHECK(length(trim(socket_path)) > 0),
    capabilities TEXT NOT NULL CHECK(length(capabilities) <= 262144 AND json_valid(capabilities)=1),
    activation_generation INTEGER NOT NULL CHECK(activation_generation > 0),
    activated_at TEXT NOT NULL CHECK(activated_at GLOB '` + timePattern + `'),
    created_at TEXT NOT NULL CHECK(created_at GLOB '` + timePattern + `'),
    CHECK(length(trim(receipt_id)) > 0)
);`,
	},
	{
		name: "pack_activation_receipts_op",
		sql: `CREATE UNIQUE INDEX pack_activation_receipts_op
    ON pack_activation_receipts (operation_id);`,
	},
	{
		name: "pack_activation_receipts_pack_ver",
		sql: `CREATE UNIQUE INDEX pack_activation_receipts_pack_ver
    ON pack_activation_receipts (pack_id, version);`,
	},
	{
		name: "pack_active_runtimes",
		sql: `CREATE TABLE pack_active_runtimes (
    pack_id TEXT PRIMARY KEY NOT NULL REFERENCES pack_records(pack_id) ON DELETE RESTRICT,
    active_version TEXT NOT NULL,
    activation_receipt_id TEXT NOT NULL REFERENCES pack_activation_receipts(receipt_id) ON DELETE RESTRICT,
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
    instance_id TEXT NOT NULL CHECK(length(trim(instance_id)) > 0),
    unit_name TEXT NOT NULL CHECK(length(trim(unit_name)) > 0),
    socket_path TEXT NOT NULL CHECK(length(trim(socket_path)) > 0),
    capabilities TEXT NOT NULL CHECK(length(capabilities) <= 262144 AND json_valid(capabilities)=1),
    runtime_status TEXT NOT NULL CHECK(runtime_status IN ('ready','unknown','stopped','failed')),
    core_generation INTEGER NOT NULL CHECK(core_generation > 0),
    last_observed_at TEXT NOT NULL CHECK(last_observed_at GLOB '` + timePattern + `'),
    updated_at TEXT NOT NULL CHECK(updated_at GLOB '` + timePattern + `'),
    CHECK(length(trim(pack_id)) > 0)
);`,
	},
	{
		name: "pack_active_runtimes_op",
		sql: `CREATE INDEX pack_active_runtimes_op
    ON pack_active_runtimes (operation_id);`,
	},
}

var packActivationTriggers = []schemaObjectDef{
	{
		name: "pack_activation_receipts_frozen",
		sql: `CREATE TRIGGER pack_activation_receipts_frozen BEFORE UPDATE ON pack_activation_receipts BEGIN
 SELECT RAISE(ABORT,'pack activation receipt is immutable');
 END;`,
	},
	{
		name: "pack_activation_receipts_no_delete",
		sql: `CREATE TRIGGER pack_activation_receipts_no_delete BEFORE DELETE ON pack_activation_receipts BEGIN
 SELECT RAISE(ABORT,'pack activation receipt history is immutable');
 END;`,
	},
	{
		name: "pack_activation_journal_frozen_fields",
		sql: `CREATE TRIGGER pack_activation_journal_frozen_fields BEFORE UPDATE ON pack_activation_journal BEGIN
 SELECT CASE WHEN NEW.journal_id<>OLD.journal_id OR NEW.operation_id<>OLD.operation_id OR NEW.pack_id<>OLD.pack_id OR NEW.version<>OLD.version OR NEW.plan_sha256<>OLD.plan_sha256 OR NEW.artifact_receipt_id<>OLD.artifact_receipt_id OR NEW.created_at<>OLD.created_at OR NEW.revision<=OLD.revision THEN RAISE(ABORT,'pack activation journal identity is immutable and revision must strictly increase') END;
 END;`,
	},
	{
		name: "pack_activation_journal_no_delete",
		sql: `CREATE TRIGGER pack_activation_journal_no_delete BEFORE DELETE ON pack_activation_journal BEGIN
 SELECT RAISE(ABORT,'pack activation journal history is immutable');
 END;`,
	},
}

func packActivationMigrationSQL() string {
	var b strings.Builder
	for _, o := range packActivationSchemaDefinitions {
		b.WriteString(o.sql)
		b.WriteString("\n")
	}
	for _, o := range packActivationTriggers {
		b.WriteString(o.sql)
		b.WriteString("\n")
	}
	return b.String()
}
