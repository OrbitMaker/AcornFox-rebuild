package sqlite

import "strings"

const version0007_image_lifecycle = "0007_image_lifecycle"

var imageLifecycleSchemaDefinitions = []schemaObjectDef{
	{name: "image_lifecycle_commands", sql: `CREATE TABLE IF NOT EXISTS image_lifecycle_commands (
 operation_id TEXT PRIMARY KEY NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
 task_id TEXT NOT NULL UNIQUE REFERENCES task_leases(task_id) ON DELETE RESTRICT,
 deployment_id TEXT NOT NULL REFERENCES image_deployments(id) ON DELETE RESTRICT,
 admin_id TEXT NOT NULL REFERENCES admin_credentials(id) ON DELETE RESTRICT,
 action TEXT NOT NULL CHECK(action IN ('stop','start','restart')),
 binding TEXT NOT NULL CHECK(json_valid(binding)),
 created_at TEXT NOT NULL CHECK(created_at GLOB '` + timePattern + `')
);`},
	{name: "image_lifecycle_commands_deployment_idx", sql: `CREATE INDEX IF NOT EXISTS image_lifecycle_commands_deployment_idx ON image_lifecycle_commands(deployment_id);`},
	{name: "image_lifecycle_results", sql: `CREATE TABLE IF NOT EXISTS image_lifecycle_results (
 operation_id TEXT PRIMARY KEY NOT NULL REFERENCES image_lifecycle_commands(operation_id) ON DELETE RESTRICT,
 result TEXT NOT NULL CHECK(json_valid(result)),
 created_at TEXT NOT NULL CHECK(created_at GLOB '` + timePattern + `')
);`},
}
var imageLifecycleTriggers = []schemaObjectDef{
	{name: "image_lifecycle_commands_frozen", sql: `CREATE TRIGGER IF NOT EXISTS image_lifecycle_commands_frozen BEFORE UPDATE ON image_lifecycle_commands BEGIN SELECT RAISE(ABORT, 'lifecycle command immutable'); END;`},
	{name: "image_lifecycle_commands_no_delete", sql: `CREATE TRIGGER IF NOT EXISTS image_lifecycle_commands_no_delete BEFORE DELETE ON image_lifecycle_commands BEGIN SELECT RAISE(ABORT, 'lifecycle command immutable'); END;`},
	{name: "image_lifecycle_results_frozen", sql: `CREATE TRIGGER IF NOT EXISTS image_lifecycle_results_frozen BEFORE UPDATE ON image_lifecycle_results BEGIN SELECT RAISE(ABORT, 'lifecycle result immutable'); END;`},
	{name: "image_lifecycle_results_no_delete", sql: `CREATE TRIGGER IF NOT EXISTS image_lifecycle_results_no_delete BEFORE DELETE ON image_lifecycle_results BEGIN SELECT RAISE(ABORT, 'lifecycle result immutable'); END;`},
}

func imageLifecycleMigrationSQL() string {
	var b strings.Builder
	for _, objects := range [][]schemaObjectDef{imageLifecycleSchemaDefinitions, imageLifecycleTriggers} {
		for _, o := range objects {
			b.WriteString(o.sql)
			b.WriteString("\n\n")
		}
	}
	return b.String()
}
