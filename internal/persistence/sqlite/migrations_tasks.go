package sqlite

import "strings"

const version0003_task_fencing = "0003_task_fencing"

var taskAddedColumns = []string{
	"last_error TEXT NOT NULL DEFAULT '' CHECK (length(last_error) <= 1024)",
	"last_agent_sequence INTEGER NOT NULL DEFAULT 0 CHECK (last_agent_sequence >= 0)",
	"core_generation INTEGER NOT NULL DEFAULT 0 CHECK (core_generation >= 0)",
	"lease_generation INTEGER NOT NULL DEFAULT 0 CHECK (lease_generation >= 0)",
}

var coreGenerationSchema = schemaObjectDef{name: "core_generation", sql: `CREATE TABLE core_generation (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    generation INTEGER NOT NULL CHECK (generation >= 0)
);`}

func taskMigrationSQL() string {
	var b strings.Builder
	for _, col := range taskAddedColumns {
		b.WriteString("ALTER TABLE task_leases ADD COLUMN " + col + ";\n")
	}
	b.WriteString(coreGenerationSchema.sql)
	b.WriteString("\nINSERT INTO core_generation (singleton, generation) VALUES (1, 0);\n")
	return b.String()
}

// SQLite places added columns immediately before the frozen table constraints.
// Keep the 0002 migration text immutable and verify the final altered shape.
func finalTaskSchemaSQL(frozen string) string {
	columns := strings.Join(taskAddedColumns, ", ")
	return strings.Replace(frozen, "    CHECK (length(trim(task_id))", "    "+columns+",\n    CHECK (length(trim(task_id))", 1)
}
