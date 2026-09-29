package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
)

const version0005_pack_intents = "0005_pack_intents"

var packSchemaDefinitions = []schemaObjectDef{
	{name: "core_installation", sql: `CREATE TABLE core_installation (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 public_binding TEXT NOT NULL CHECK(length(public_binding)=64 AND public_binding NOT GLOB '*[^0-9a-f]*')
);`},
	{name: "pack_records", sql: `CREATE TABLE pack_records (
 pack_id TEXT PRIMARY KEY NOT NULL,
 desired_version TEXT NOT NULL,
 manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'),
 artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256)=64 AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'),
 catalog_sha256 TEXT NOT NULL CHECK(length(catalog_sha256)=64 AND catalog_sha256 NOT GLOB '*[^0-9a-f]*'),
 catalog_sequence INTEGER NOT NULL CHECK(catalog_sequence>0),
 state TEXT NOT NULL CHECK(state='planned'),
 installation_binding TEXT NOT NULL CHECK(length(installation_binding)=64 AND installation_binding NOT GLOB '*[^0-9a-f]*'),
 revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 CHECK(length(trim(pack_id))>0),
 CHECK(created_at GLOB '` + timePattern + `'),
 CHECK(updated_at GLOB '` + timePattern + `' AND updated_at>=created_at)
);`},
	{name: "pack_install_intents", sql: `CREATE TABLE pack_install_intents (
 operation_id TEXT PRIMARY KEY NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
 pack_id TEXT NOT NULL REFERENCES pack_records(pack_id) ON DELETE RESTRICT,
 version TEXT NOT NULL,
 plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256)=64 AND plan_sha256 NOT GLOB '*[^0-9a-f]*'),
 phase TEXT NOT NULL CHECK(phase='planned'),
 selected_identity TEXT NOT NULL CHECK(json_valid(selected_identity)=1),
 created_at TEXT NOT NULL CHECK(created_at GLOB '` + timePattern + `')
);`},
}
var packIntentTriggers = []schemaObjectDef{
	{name: "pack_intents_frozen_fields", sql: `CREATE TRIGGER pack_intents_frozen_fields BEFORE UPDATE ON pack_install_intents BEGIN
 SELECT CASE WHEN NEW.operation_id<>OLD.operation_id OR NEW.pack_id<>OLD.pack_id OR NEW.version<>OLD.version OR NEW.plan_sha256<>OLD.plan_sha256 OR NEW.selected_identity<>OLD.selected_identity OR NEW.created_at<>OLD.created_at THEN RAISE(ABORT,'package intent identity is immutable') END;
 END;`},
	{name: "pack_intents_no_delete", sql: `CREATE TRIGGER pack_intents_no_delete BEFORE DELETE ON pack_install_intents BEGIN SELECT RAISE(ABORT,'package intent history is immutable'); END;`},
}

func packOperationsSQL(name string) string {
	return `CREATE TABLE ` + name + ` (
 id TEXT PRIMARY KEY NOT NULL,
 application_id TEXT REFERENCES applications(id) ON DELETE RESTRICT,
 environment_id TEXT REFERENCES environments(id) ON DELETE RESTRICT,
 operation_type TEXT NOT NULL,
 idempotency_key TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','leased','running','waiting','cancelling','succeeded','failed','cancelled','rolling_back','rolled_back')),
 version INTEGER NOT NULL DEFAULT 1 CHECK(version>0),
 target_ref TEXT NOT NULL DEFAULT '',
 failure_reason TEXT,
 created_at TEXT NOT NULL CHECK(created_at GLOB '` + timePattern + `'),
 updated_at TEXT NOT NULL CHECK(updated_at GLOB '` + timePattern + `' AND updated_at>=created_at),
 target_kind TEXT NOT NULL DEFAULT 'application' CHECK(target_kind IN ('application','pack')),
 pack_id TEXT REFERENCES pack_records(pack_id) ON DELETE RESTRICT,
 CHECK(length(trim(id))>0 AND length(trim(operation_type))>0 AND length(trim(idempotency_key))>0),
 CHECK((target_kind='application' AND application_id IS NOT NULL AND environment_id IS NOT NULL AND pack_id IS NULL)
 OR (target_kind='pack' AND pack_id IS NOT NULL AND application_id IS NULL AND environment_id IS NULL))
);`
}

var packOperationIndices = []schemaObjectDef{
	{name: "operations_application_idx", sql: `CREATE INDEX operations_application_idx ON operations(application_id,created_at,id);`},
	{name: "operations_application_key", sql: `CREATE UNIQUE INDEX operations_application_key ON operations(environment_id,idempotency_key) WHERE target_kind='application';`},
	{name: "operations_one_active_per_environment", sql: `CREATE UNIQUE INDEX operations_one_active_per_environment ON operations(environment_id) WHERE target_kind='application' AND state IN ('pending','leased','running','waiting','cancelling');`},
	{name: "operations_pack_key", sql: `CREATE UNIQUE INDEX operations_pack_key ON operations(pack_id,idempotency_key) WHERE target_kind='pack';`},
	{name: "operations_one_active_per_pack", sql: `CREATE UNIQUE INDEX operations_one_active_per_pack ON operations(pack_id) WHERE target_kind='pack' AND state IN ('pending','leased','running','waiting','cancelling');`},
}

const copyOldOperations = `INSERT INTO new_operations(id,application_id,environment_id,operation_type,idempotency_key,state,version,target_ref,failure_reason,created_at,updated_at,target_kind,pack_id) SELECT id,application_id,environment_id,operation_type,idempotency_key,state,version,target_ref,failure_reason,created_at,updated_at,'application',NULL FROM operations;`

func packMigrationSQL() string {
	var b strings.Builder
	for _, o := range packSchemaDefinitions[:2] {
		b.WriteString(o.sql)
		b.WriteString("\n")
	}
	b.WriteString(packOperationsSQL("new_operations"))
	b.WriteString(copyOldOperations)
	b.WriteString("\nDROP TABLE operations;\nALTER TABLE new_operations RENAME TO operations;\n")
	for _, o := range packOperationIndices {
		b.WriteString(o.sql)
		b.WriteString("\n")
	}
	b.WriteString(packSchemaDefinitions[2].sql)
	for _, o := range packIntentTriggers {
		b.WriteString(o.sql)
		b.WriteString("\n")
	}
	return b.String()
}

// Test may fail this private maintenance step after copy, without a global flag
// or production fault injection endpoint. All DDL/data remains one transaction.
func applyPackMigration(ctx context.Context, tx *sql.Tx, afterCopy func() error) error {
	for _, o := range packSchemaDefinitions[:2] {
		if _, err := tx.ExecContext(ctx, o.sql); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, packOperationsSQL("new_operations")); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, copyOldOperations); err != nil {
		return err
	}
	if afterCopy != nil {
		if err := afterCopy(); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE operations;ALTER TABLE new_operations RENAME TO operations;`); err != nil {
		return err
	}
	for _, o := range packOperationIndices {
		if _, err := tx.ExecContext(ctx, o.sql); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, packSchemaDefinitions[2].sql); err != nil {
		return err
	}
	for _, o := range packIntentTriggers {
		if _, err := tx.ExecContext(ctx, o.sql); err != nil {
			return err
		}
	}
	var binding [32]byte
	if _, err := rand.Read(binding[:]); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO core_installation VALUES(1,?)`, hex.EncodeToString(binding[:]))
	return err
}
func readInstallationBinding(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (string, error) {
	var binding string
	if err := q.QueryRowContext(ctx, `SELECT public_binding FROM core_installation WHERE singleton=1`).Scan(&binding); err != nil || len(binding) != 64 || strings.Trim(binding, "0123456789abcdef") != "" {
		return "", errors.New("corrupt public installation binding")
	}
	return binding, nil
}
