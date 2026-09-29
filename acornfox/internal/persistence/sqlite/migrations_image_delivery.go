package sqlite

import (
	"strings"
)

const version0005_image_delivery = "0005_image_delivery"

var imageDeliverySchemaDefinitions = []schemaObjectDef{
	{
		name: "image_plans",
		sql: `CREATE TABLE IF NOT EXISTS image_plans (
    id TEXT PRIMARY KEY NOT NULL,
    admin_id TEXT NOT NULL REFERENCES admin_credentials(id) ON DELETE RESTRICT,
    app_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('planned', 'needs_input')),
    plan_digest TEXT NOT NULL CHECK (length(plan_digest) = 71 AND plan_digest GLOB 'sha256:[0-9a-f]*'),
    canonical_input TEXT NOT NULL CHECK (json_valid(canonical_input) = 1),
    resolved_image TEXT NOT NULL CHECK (json_valid(resolved_image) = 1),
    resolver_provenance TEXT NOT NULL CHECK (json_valid(resolver_provenance) = 1),
    missing_inputs TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(missing_inputs) = 1),
    created_at TEXT NOT NULL CHECK (created_at GLOB '` + timePattern + `'),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '` + timePattern + `' AND updated_at >= created_at),
    CHECK (length(trim(id)) > 0),
    CHECK (length(trim(admin_id)) > 0),
    CHECK (length(trim(app_name)) > 0)
);`,
	},
	{
		name: "image_plans_admin_idx",
		sql: `CREATE INDEX IF NOT EXISTS image_plans_admin_idx
    ON image_plans (admin_id, created_at, id);`,
	},
	{
		name: "image_plans_digest_idx",
		sql: `CREATE INDEX IF NOT EXISTS image_plans_digest_idx
    ON image_plans (plan_digest);`,
	},
	{
		name: "image_deploy_intents",
		sql: `CREATE TABLE IF NOT EXISTS image_deploy_intents (
    operation_id TEXT PRIMARY KEY NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
    plan_id TEXT NOT NULL REFERENCES image_plans(id) ON DELETE RESTRICT,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE RESTRICT,
    environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
    plan_digest TEXT NOT NULL CHECK (length(plan_digest) = 71 AND plan_digest GLOB 'sha256:[0-9a-f]*'),
    created_at TEXT NOT NULL CHECK (created_at GLOB '` + timePattern + `'),
    CHECK (length(trim(operation_id)) > 0),
    CHECK (length(trim(plan_id)) > 0),
    CHECK (length(trim(application_id)) > 0),
    CHECK (length(trim(environment_id)) > 0)
);`,
	},
	{
		name: "image_deploy_intents_plan_idx",
		sql: `CREATE INDEX IF NOT EXISTS image_deploy_intents_plan_idx
    ON image_deploy_intents (plan_id);`,
	},
	{
		name: "image_deploy_intents_app_idx",
		sql: `CREATE INDEX IF NOT EXISTS image_deploy_intents_app_idx
    ON image_deploy_intents (application_id);`,
	},
}

var imageDeliveryTriggers = []schemaObjectDef{
	{
		name: "image_plans_frozen_fields",
		sql: `CREATE TRIGGER IF NOT EXISTS image_plans_frozen_fields BEFORE UPDATE ON image_plans BEGIN
    SELECT CASE WHEN NEW.id <> OLD.id OR NEW.admin_id <> OLD.admin_id OR NEW.app_name <> OLD.app_name OR NEW.status <> OLD.status OR NEW.missing_inputs <> OLD.missing_inputs OR NEW.plan_digest <> OLD.plan_digest OR NEW.canonical_input <> OLD.canonical_input OR NEW.resolved_image <> OLD.resolved_image OR NEW.resolver_provenance <> OLD.resolver_provenance OR NEW.created_at <> OLD.created_at THEN RAISE(ABORT, 'image plan identity is immutable') END;
END;`,
	},
	{
		name: "image_plans_no_delete",
		sql: `CREATE TRIGGER IF NOT EXISTS image_plans_no_delete BEFORE DELETE ON image_plans BEGIN
    SELECT RAISE(ABORT, 'image plans are immutable');
END;`,
	},
	{
		name: "image_deploy_intents_frozen",
		sql: `CREATE TRIGGER IF NOT EXISTS image_deploy_intents_frozen BEFORE UPDATE ON image_deploy_intents BEGIN
    SELECT RAISE(ABORT, 'image deploy intent is immutable');
END;`,
	},
	{
		name: "image_deploy_intents_no_delete",
		sql: `CREATE TRIGGER IF NOT EXISTS image_deploy_intents_no_delete BEFORE DELETE ON image_deploy_intents BEGIN
    SELECT RAISE(ABORT, 'image deploy intent history is immutable');
END;`,
	},
}

func imageDeliveryMigrationSQL() string {
	var sb strings.Builder
	for _, obj := range imageDeliverySchemaDefinitions {
		sb.WriteString(obj.sql)
		sb.WriteString("\n\n")
	}
	for _, obj := range imageDeliveryTriggers {
		sb.WriteString(obj.sql)
		sb.WriteString("\n\n")
	}
	return sb.String()
}
