package sqlite

import (
	"strings"
)

const version0006_image_execution = "0006_image_execution"

var imageExecutionSchemaDefinitions = []schemaObjectDef{
	{
		name: "image_releases",
		sql: `CREATE TABLE IF NOT EXISTS image_releases (
    id TEXT PRIMARY KEY NOT NULL,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE RESTRICT,
    plan_id TEXT NOT NULL REFERENCES image_plans(id) ON DELETE RESTRICT,
    plan_digest TEXT NOT NULL CHECK (length(plan_digest) = 71 AND plan_digest GLOB 'sha256:[0-9a-f]*'),
    repository TEXT NOT NULL,
    digest TEXT NOT NULL CHECK (length(digest) = 71 AND digest GLOB 'sha256:[0-9a-f]*'),
    platform TEXT NOT NULL CHECK (platform = 'linux/amd64'),
    created_at TEXT NOT NULL CHECK (created_at GLOB '` + timePattern + `'),
    CHECK (length(trim(id)) > 0),
    CHECK (length(trim(application_id)) > 0),
    CHECK (length(trim(plan_id)) > 0),
    CHECK (length(trim(repository)) > 0)
);`,
	},
	{
		name: "image_releases_app_idx",
		sql: `CREATE INDEX IF NOT EXISTS image_releases_app_idx
    ON image_releases (application_id);`,
	},
	{
		name: "image_releases_plan_idx",
		sql: `CREATE INDEX IF NOT EXISTS image_releases_plan_idx
    ON image_releases (plan_id);`,
	},
	{
		name: "image_deployments",
		sql: `CREATE TABLE IF NOT EXISTS image_deployments (
    id TEXT PRIMARY KEY NOT NULL,
    release_id TEXT NOT NULL REFERENCES image_releases(id) ON DELETE RESTRICT,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE RESTRICT,
    environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES task_leases(task_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('deploying', 'running', 'failed', 'stopped')),
    container_id TEXT,
    container_name TEXT,
    image_id TEXT,
    created_at TEXT NOT NULL CHECK (created_at GLOB '` + timePattern + `'),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '` + timePattern + `' AND updated_at >= created_at),
    CHECK (length(trim(id)) > 0),
    CHECK (length(trim(release_id)) > 0),
    CHECK (length(trim(application_id)) > 0),
    CHECK (length(trim(environment_id)) > 0),
    CHECK (length(trim(operation_id)) > 0),
    CHECK (length(trim(task_id)) > 0)
);`,
	},
	{
		name: "image_deployments_op_idx",
		sql: `CREATE UNIQUE INDEX IF NOT EXISTS image_deployments_op_idx
    ON image_deployments (operation_id);`,
	},
	{
		name: "image_deployments_app_env_idx",
		sql: `CREATE INDEX IF NOT EXISTS image_deployments_app_env_idx
    ON image_deployments (application_id, environment_id);`,
	},
	{
		name: "image_artifacts",
		sql: `CREATE TABLE IF NOT EXISTS image_artifacts (
    id TEXT PRIMARY KEY NOT NULL,
    release_id TEXT NOT NULL REFERENCES image_releases(id) ON DELETE RESTRICT,
    repository TEXT NOT NULL,
    digest TEXT NOT NULL CHECK (length(digest) = 71 AND digest GLOB 'sha256:[0-9a-f]*'),
    image_id TEXT NOT NULL CHECK (length(image_id) = 71 AND image_id GLOB 'sha256:[0-9a-f]*'),
    content_digest TEXT NOT NULL CHECK (length(content_digest) = 71 AND content_digest GLOB 'sha256:[0-9a-f]*'),
    size_bytes INTEGER NOT NULL CHECK (size_bytes > 0),
    storage_ref TEXT NOT NULL CHECK (length(trim(storage_ref)) > 0),
    created_at TEXT NOT NULL CHECK (created_at GLOB '` + timePattern + `'),
    CHECK (length(trim(id)) > 0),
    CHECK (length(trim(release_id)) > 0),
    CHECK (length(trim(repository)) > 0)
);`,
	},
	{
		name: "image_artifacts_release_idx",
		sql: `CREATE INDEX IF NOT EXISTS image_artifacts_release_idx
    ON image_artifacts (release_id);`,
	},
	{
		name: "image_artifacts_digest_idx",
		sql: `CREATE INDEX IF NOT EXISTS image_artifacts_digest_idx
    ON image_artifacts (digest);`,
	},
	{
		name: "image_endpoints",
		sql: `CREATE TABLE IF NOT EXISTS image_endpoints (
    id TEXT PRIMARY KEY NOT NULL,
    deployment_id TEXT NOT NULL REFERENCES image_deployments(id) ON DELETE RESTRICT,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE RESTRICT,
    environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
    protocol TEXT NOT NULL CHECK (protocol IN ('http', 'https')),
    host_ip TEXT NOT NULL CHECK (host_ip = '127.0.0.1'),
    host_port INTEGER NOT NULL CHECK (host_port > 0 AND host_port <= 65535),
    container_port INTEGER NOT NULL CHECK (container_port > 0 AND container_port <= 65535),
    observed_at TEXT NOT NULL CHECK (observed_at GLOB '` + timePattern + `'),
    created_at TEXT NOT NULL CHECK (created_at GLOB '` + timePattern + `'),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '` + timePattern + `' AND updated_at >= created_at),
    CHECK (length(trim(id)) > 0),
    CHECK (length(trim(deployment_id)) > 0),
    CHECK (length(trim(application_id)) > 0),
    CHECK (length(trim(environment_id)) > 0)
);`,
	},
	{
		name: "image_endpoints_deployment_idx",
		sql: `CREATE UNIQUE INDEX IF NOT EXISTS image_endpoints_deployment_idx
    ON image_endpoints (deployment_id);`,
	},
}

var imageExecutionTriggers = []schemaObjectDef{
	{
		name: "image_releases_no_delete",
		sql: `CREATE TRIGGER IF NOT EXISTS image_releases_no_delete BEFORE DELETE ON image_releases BEGIN
    SELECT RAISE(ABORT, 'image releases are immutable');
END;`,
	},
	{
		name: "image_releases_frozen",
		sql: `CREATE TRIGGER IF NOT EXISTS image_releases_frozen BEFORE UPDATE ON image_releases BEGIN
    SELECT RAISE(ABORT, 'image releases are immutable');
END;`,
	},
	{
		name: "image_artifacts_no_delete",
		sql: `CREATE TRIGGER IF NOT EXISTS image_artifacts_no_delete BEFORE DELETE ON image_artifacts BEGIN
    SELECT RAISE(ABORT, 'image artifacts are immutable');
END;`,
	},
	{
		name: "image_artifacts_frozen",
		sql: `CREATE TRIGGER IF NOT EXISTS image_artifacts_frozen BEFORE UPDATE ON image_artifacts BEGIN
    SELECT RAISE(ABORT, 'image artifacts are immutable');
END;`,
	},
	{
		name: "image_deployments_no_delete",
		sql: `CREATE TRIGGER IF NOT EXISTS image_deployments_no_delete BEFORE DELETE ON image_deployments BEGIN
    SELECT RAISE(ABORT, 'image deployments cannot be deleted');
END;`,
	},
	{
		name: "image_deployments_frozen_fields",
		sql: `CREATE TRIGGER IF NOT EXISTS image_deployments_frozen_fields BEFORE UPDATE ON image_deployments BEGIN
    SELECT CASE WHEN NEW.id <> OLD.id OR NEW.release_id <> OLD.release_id OR NEW.application_id <> OLD.application_id OR NEW.environment_id <> OLD.environment_id OR NEW.operation_id <> OLD.operation_id OR NEW.task_id <> OLD.task_id OR NEW.created_at <> OLD.created_at THEN RAISE(ABORT, 'image deployment identity is immutable') END;
END;`,
	},
}

func imageExecutionMigrationSQL() string {
	var sb strings.Builder
	for _, obj := range imageExecutionSchemaDefinitions {
		sb.WriteString(obj.sql)
		sb.WriteString("\n\n")
	}
	for _, obj := range imageExecutionTriggers {
		sb.WriteString(obj.sql)
		sb.WriteString("\n\n")
	}
	return sb.String()
}
