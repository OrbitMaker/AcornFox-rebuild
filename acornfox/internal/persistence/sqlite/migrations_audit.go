package sqlite

import "strings"

const version0004_audit_evidence = "0004_audit_evidence"

var auditSchemaDefinitions = []schemaObjectDef{
	{name: "audit_evidence", sql: `CREATE TABLE audit_evidence (
    id TEXT PRIMARY KEY NOT NULL,
    sequence INTEGER NOT NULL UNIQUE CHECK (sequence > 0),
    actor_type TEXT NOT NULL CHECK (length(trim(actor_type)) > 0),
    actor_id TEXT NOT NULL CHECK (length(trim(actor_id)) > 0),
    action TEXT NOT NULL CHECK (length(trim(action)) > 0),
    reason TEXT NOT NULL,
    input_digest TEXT NOT NULL,
    result TEXT NOT NULL,
    evidence_refs TEXT NOT NULL CHECK (json_valid(evidence_refs) = 1 AND json_type(evidence_refs) = 'array'),
    previous_hash TEXT,
    record_hash TEXT NOT NULL UNIQUE CHECK (length(record_hash) > 0),
    hash_scheme TEXT NOT NULL CHECK (hash_scheme IN ('acornfox-audit-v1', 'legacy-pg-m1', 'legacy-pg-domain-convergence', 'legacy-pg-serving', 'legacy-pg-unclassified')),
    created_at TEXT NOT NULL,
    CHECK (length(trim(id)) > 0)
);`},
	{name: "audit_evidence_chain_head", sql: `CREATE TRIGGER audit_evidence_chain_head
BEFORE INSERT ON audit_evidence
BEGIN
    SELECT CASE
        WHEN NEW.previous_hash IS NOT (SELECT record_hash FROM audit_evidence ORDER BY sequence DESC LIMIT 1)
          OR NEW.sequence <= COALESCE((SELECT MAX(sequence) FROM audit_evidence), 0)
        THEN RAISE(ABORT, 'audit chain head or sequence mismatch')
    END;
END;`},
	{name: "audit_evidence_no_update", sql: `CREATE TRIGGER audit_evidence_no_update
BEFORE UPDATE ON audit_evidence
BEGIN
    SELECT RAISE(ABORT, 'audit history is immutable');
END;`},
	{name: "audit_evidence_no_delete", sql: `CREATE TRIGGER audit_evidence_no_delete
BEFORE DELETE ON audit_evidence
BEGIN
    SELECT RAISE(ABORT, 'audit history is immutable');
END;`},
}

func auditMigrationSQL() string {
	var b strings.Builder
	for _, o := range auditSchemaDefinitions {
		b.WriteString(o.sql)
		b.WriteString("\n\n")
	}
	return b.String()
}
