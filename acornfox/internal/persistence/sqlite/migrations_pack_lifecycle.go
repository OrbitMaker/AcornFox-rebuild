package sqlite

import (
	"strings"
)

const version0007_pack_artifact_staging = "0007_pack_artifact_staging"

var packLifecycleSchemaDefinitions = []schemaObjectDef{
	{
		name: "pack_trust_materials",
		sql: `CREATE TABLE pack_trust_materials (
    material_id TEXT PRIMARY KEY NOT NULL,
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
    pack_id TEXT NOT NULL REFERENCES pack_records(pack_id) ON DELETE RESTRICT,
    version TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256)=64 AND plan_sha256 NOT GLOB '*[^0-9a-f]*'),
    catalog_sha256 TEXT NOT NULL CHECK(length(catalog_sha256)=64 AND catalog_sha256 NOT GLOB '*[^0-9a-f]*'),
    catalog_sequence INTEGER NOT NULL CHECK(catalog_sequence > 0),
    manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'),
    artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256)=64 AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'),
    catalog_envelope TEXT NOT NULL CHECK(length(catalog_envelope) <= 262144 AND json_valid(catalog_envelope)=1),
    manifest_bytes TEXT NOT NULL CHECK(length(manifest_bytes) <= 2097152 AND json_valid(manifest_bytes)=1),
    authority_kind TEXT NOT NULL CHECK(authority_kind IN ('original_plan','renewed_catalog')),
    authority_sequence INTEGER NOT NULL DEFAULT 1 CHECK(authority_sequence > 0),
    created_at TEXT NOT NULL CHECK(created_at GLOB '` + timePattern + `'),
    CHECK(length(trim(material_id)) > 0)
);`,
	},
	{
		name: "pack_trust_materials_op_seq",
		sql: `CREATE UNIQUE INDEX pack_trust_materials_op_seq
    ON pack_trust_materials (operation_id, authority_sequence);`,
	},
	{
		name: "pack_trust_materials_pack_ver",
		sql: `CREATE INDEX pack_trust_materials_pack_ver
    ON pack_trust_materials (pack_id, version);`,
	},
	{
		name: "pack_lifecycle_journal",
		sql: `CREATE TABLE pack_lifecycle_journal (
    journal_id TEXT PRIMARY KEY NOT NULL,
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
    pack_id TEXT NOT NULL REFERENCES pack_records(pack_id) ON DELETE RESTRICT,
    version TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256)=64 AND plan_sha256 NOT GLOB '*[^0-9a-f]*'),
    phase TEXT NOT NULL CHECK(phase IN ('staging','verified','authorization_required','failed')),
    revision INTEGER NOT NULL CHECK(revision > 0),
    core_generation INTEGER NOT NULL CHECK(core_generation > 0),
    lease_generation INTEGER NOT NULL CHECK(lease_generation > 0),
    owner_id TEXT NOT NULL CHECK(length(trim(owner_id)) > 0),
    stage_directory TEXT NOT NULL CHECK(length(trim(stage_directory)) > 0),
    authority_catalog_sha256 TEXT NOT NULL CHECK(length(authority_catalog_sha256)=64 AND authority_catalog_sha256 NOT GLOB '*[^0-9a-f]*'),
    authority_sequence INTEGER NOT NULL CHECK(authority_sequence > 0),
    authority_expires_at TEXT NOT NULL CHECK(authority_expires_at GLOB '` + timePattern + `'),
    failure_reason TEXT,
    created_at TEXT NOT NULL CHECK(created_at GLOB '` + timePattern + `'),
    updated_at TEXT NOT NULL CHECK(updated_at GLOB '` + timePattern + `' AND updated_at >= created_at),
    CHECK(length(trim(journal_id)) > 0)
);`,
	},
	{
		name: "pack_lifecycle_journal_op",
		sql: `CREATE UNIQUE INDEX pack_lifecycle_journal_op
    ON pack_lifecycle_journal (operation_id);`,
	},
	{
		name: "pack_lifecycle_journal_pack",
		sql: `CREATE INDEX pack_lifecycle_journal_pack
    ON pack_lifecycle_journal (pack_id, version);`,
	},
	{
		name: "pack_artifact_receipts",
		sql: `CREATE TABLE pack_artifact_receipts (
    receipt_id TEXT PRIMARY KEY NOT NULL,
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
    pack_id TEXT NOT NULL REFERENCES pack_records(pack_id) ON DELETE RESTRICT,
    version TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256)=64 AND plan_sha256 NOT GLOB '*[^0-9a-f]*'),
    archive_sha256 TEXT NOT NULL CHECK(length(archive_sha256)=64 AND archive_sha256 NOT GLOB '*[^0-9a-f]*'),
    manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'),
    executable_sha256 TEXT NOT NULL CHECK(length(executable_sha256)=64 AND executable_sha256 NOT GLOB '*[^0-9a-f]*'),
    executable_path TEXT NOT NULL CHECK(length(trim(executable_path)) > 0),
    catalog_sha256 TEXT NOT NULL CHECK(length(catalog_sha256)=64 AND catalog_sha256 NOT GLOB '*[^0-9a-f]*'),
    catalog_sequence INTEGER NOT NULL CHECK(catalog_sequence > 0),
    archive_size INTEGER NOT NULL CHECK(archive_size > 0),
    unpacked_total_bytes INTEGER NOT NULL CHECK(unpacked_total_bytes > 0),
    relative_stage_path TEXT NOT NULL CHECK(length(trim(relative_stage_path)) > 0),
    stage_identity TEXT NOT NULL CHECK(length(trim(stage_identity)) > 0),
    member_count INTEGER NOT NULL CHECK(member_count > 0),
    verified_at TEXT NOT NULL CHECK(verified_at GLOB '` + timePattern + `'),
    created_at TEXT NOT NULL CHECK(created_at GLOB '` + timePattern + `'),
    CHECK(length(trim(receipt_id)) > 0)
);`,
	},
	{
		name: "pack_artifact_receipts_op",
		sql: `CREATE UNIQUE INDEX pack_artifact_receipts_op
    ON pack_artifact_receipts (operation_id);`,
	},
	{
		name: "pack_artifact_receipts_pack_ver_plan",
		sql: `CREATE UNIQUE INDEX pack_artifact_receipts_pack_ver_plan
    ON pack_artifact_receipts (pack_id, version, plan_sha256);`,
	},
}

var packLifecycleTriggers = []schemaObjectDef{
	{
		name: "pack_trust_materials_frozen",
		sql: `CREATE TRIGGER pack_trust_materials_frozen BEFORE UPDATE ON pack_trust_materials BEGIN
 SELECT RAISE(ABORT,'pack trust material is immutable');
 END;`,
	},
	{
		name: "pack_trust_materials_no_delete",
		sql: `CREATE TRIGGER pack_trust_materials_no_delete BEFORE DELETE ON pack_trust_materials BEGIN
 SELECT RAISE(ABORT,'pack trust material history is immutable');
 END;`,
	},
	{
		name: "pack_lifecycle_journal_frozen_fields",
		sql: `CREATE TRIGGER pack_lifecycle_journal_frozen_fields BEFORE UPDATE ON pack_lifecycle_journal BEGIN
 SELECT CASE WHEN NEW.journal_id<>OLD.journal_id OR NEW.operation_id<>OLD.operation_id OR NEW.pack_id<>OLD.pack_id OR NEW.version<>OLD.version OR NEW.plan_sha256<>OLD.plan_sha256 OR NEW.created_at<>OLD.created_at OR NEW.revision<=OLD.revision THEN RAISE(ABORT,'pack lifecycle journal identity is immutable and revision must strictly increase') END;
 END;`,
	},
	{
		name: "pack_lifecycle_journal_no_delete",
		sql: `CREATE TRIGGER pack_lifecycle_journal_no_delete BEFORE DELETE ON pack_lifecycle_journal BEGIN
 SELECT RAISE(ABORT,'pack lifecycle journal history is immutable');
 END;`,
	},
	{
		name: "pack_artifact_receipts_frozen",
		sql: `CREATE TRIGGER pack_artifact_receipts_frozen BEFORE UPDATE ON pack_artifact_receipts BEGIN
 SELECT RAISE(ABORT,'pack artifact receipt is immutable');
 END;`,
	},
	{
		name: "pack_artifact_receipts_no_delete",
		sql: `CREATE TRIGGER pack_artifact_receipts_no_delete BEFORE DELETE ON pack_artifact_receipts BEGIN
 SELECT RAISE(ABORT,'pack artifact receipt history is immutable');
 END;`,
	},
}

func packLifecycleMigrationSQL() string {
	var b strings.Builder
	for _, o := range packLifecycleSchemaDefinitions {
		b.WriteString(o.sql)
		b.WriteString("\n\n")
	}
	for _, o := range packLifecycleTriggers {
		b.WriteString(o.sql)
		b.WriteString("\n\n")
	}
	return b.String()
}
