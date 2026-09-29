package migrationpreview

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	contracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/compatibility"
	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/persistence/sqlite"
)

type row map[string]json.RawMessage
type mapping struct {
	table   string
	columns []string
	key     string
}

// Only these fixed target columns are copied. Missing source facts do not get
// synthesized through business Create/Append methods or placeholder records.
var projection = []mapping{
	{"admin_credentials", []string{"id", "password_hash_scheme", "password_hash", "credential_version", "disabled_at", "created_at", "updated_at"}, "id"},
	{"admin_sessions", []string{"id", "admin_id", "session_digest", "csrf_digest", "credential_version", "created_at", "last_seen_at", "idle_expires_at", "absolute_expires_at", "revoked_at"}, "id"},
	{"admin_login_rate_limits", []string{"admin_id", "source_digest", "window_started_at", "window_expires_at", "failure_count", "last_failure_at", "locked_at", "locked_until", "updated_at"}, "admin_id,source_digest"},
	{"applications", []string{"id", "name", "version", "created_at", "updated_at"}, "id"},
	{"environments", []string{"id", "application_id", "name", "created_at"}, "id"},
	{"operations", []string{"id", "application_id", "environment_id", "operation_type", "idempotency_key", "state", "version", "target_ref", "failure_reason", "created_at", "updated_at"}, "id"},
	{"idempotency_records", []string{"scope", "idempotency_key", "request_digest", "status", "response", "created_at", "updated_at"}, "scope,idempotency_key"},
	{"task_leases", []string{"task_id", "operation_id", "lease_owner", "lease_until", "attempt", "max_attempts", "state", "payload", "created_at", "updated_at", "last_error", "last_agent_sequence", "core_generation", "lease_generation"}, "task_id"},
	{"outbox_events", []string{"id", "aggregate_type", "aggregate_id", "aggregate_version", "sequence", "stream_sequence", "event_type", "payload", "created_at", "published_at", "payload_version"}, "stream_sequence"},
	{"audit_evidence", []string{"id", "sequence", "actor_type", "actor_id", "action", "reason", "input_digest", "result", "evidence_refs", "previous_hash", "record_hash", "created_at", "hash_scheme"}, "sequence"},
}

func stringValue(v json.RawMessage) (string, error) {
	var s string
	if json.Unmarshal(v, &s) != nil {
		return "", errors.New("unsupported_scalar")
	}
	return s, nil
}
func isNull(v json.RawMessage) bool   { return len(v) == 0 || string(v) == "null" }
func rawEmpty(v json.RawMessage) bool { return isNull(v) || string(v) == "{}" || string(v) == "[]" }

// A row action alone cannot identify its historic PG hash producer. The
// snapshot-backed manifest records unknown provenance honestly for this slice.
func auditLegacyScheme(_ string) string { return "legacy-pg-unclassified" }

func supportedRow(table string, r row) error {
	bad := func(code string) error { return fmt.Errorf("%s.%s", table, code) }
	switch table {
	case "applications":
		if state, ok := r["management_state"]; ok {
			v, _ := stringValue(state)
			if v != "active" || !isNull(r["archived_at"]) {
				return bad("unsupported_management_history")
			}
		}
	case "operations":
		if !isNull(r["deployment_id"]) {
			return bad("unsupported_deployment_link")
		}
		operationType, _ := stringValue(r["operation_type"])
		target, _ := stringValue(r["target_ref"])
		app, _ := stringValue(r["application_id"])
		if operationType != "create_application" || target != app {
			return bad("unsupported_operation_target")
		}
	case "idempotency_records":
		scope, _ := stringValue(r["scope"])
		if scope != "application.create" {
			return bad("unsupported_command_scope")
		}
		if !isNull(r["response"]) {
			v, err := contracts.DecodeCreateApplicationResult(r["response"])
			if err != nil || !v.SourceRevisionID.Empty() {
				return bad("unsupported_response_fact")
			}
		}
	case "task_leases":
		wire, _ := stringValue(r["wire_version"])
		if wire != "1.0" || string(r["negotiated_capabilities"]) != "[]" {
			return bad("unsupported_wire_capability")
		}
		if !isNull(r["result"]) || !isNull(r["result_digest"]) || !isNull(r["completed_at"]) {
			return bad("unsupported_task_result")
		}
		var p map[string]json.RawMessage
		if json.Unmarshal(r["payload"], &p) != nil {
			return bad("unsupported_payload")
		}
		for k := range p {
			if k != "kind" && k != "application_id" && k != "operation_id" && k != "source_revision_id" {
				return bad("unsupported_payload_field")
			}
		}
		kind, e1 := stringValue(p["kind"])
		app, e2 := stringValue(p["application_id"])
		op, e3 := stringValue(p["operation_id"])
		source, e4 := stringValue(p["source_revision_id"])
		actualOp, _ := stringValue(r["operation_id"])
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || kind != "application.create" || source != "" || app == "" || op != actualOp {
			return bad("unsupported_payload")
		}
	case "outbox_events":
		if string(r["compatibility"]) != "{}" {
			return bad("unsupported_compatibility")
		}
		aggregate, _ := stringValue(r["aggregate_type"])
		if aggregate != "operation" {
			return bad("unsupported_aggregate")
		}
		versionText, _ := stringValue(r["payload_version"])
		version, err := compatibility.Parse(versionText)
		if err != nil || version.Major != 1 || version.Minor > 1 {
			return bad("unsupported_event_version")
		}
		var event contracts.Event
		decoder := json.NewDecoder(bytes.NewReader(r["payload"]))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil {
			return bad("unsupported_event_payload")
		}
		var trailing any
		if decoder.Decode(&trailing) != io.EOF {
			return bad("unsupported_event_payload")
		}
		id, _ := stringValue(r["id"])
		aggregateID, _ := stringValue(r["aggregate_id"])
		eventType, _ := stringValue(r["event_type"])
		var cursor int64
		if json.Unmarshal(r["stream_sequence"], &cursor) != nil || cursor <= 0 || event.SchemaVersion != versionText || event.Kind != eventType || eventType != "operation.created" || event.Status != "preparing" || event.ID != id || event.OperationID != aggregateID || event.ApplicationID == "" || event.Sequence != uint64(cursor) || len(event.EvidenceIDs) > 0 {
			return bad("unsupported_event_metadata_or_reference")
		}

	}
	return nil
}
func field(table, col string, r row) (any, error) {
	if col == "core_generation" || col == "lease_generation" {
		return int64(0), nil
	}
	if col == "hash_scheme" {
		action, err := stringValue(r["action"])
		if err != nil {
			return nil, err
		}
		return auditLegacyScheme(action), nil
	}
	v, ok := r[col]
	if !ok {
		return nil, errors.New("missing_projection_column")
	}
	if isNull(v) {
		if table == "task_leases" && col == "last_error" {
			return "", nil
		}
		return nil, nil
	}
	if col == "response" || col == "payload" || col == "evidence_refs" {
		if !json.Valid(v) {
			return nil, errors.New("invalid_json")
		}
		return string(v), nil
	}
	// All timestamps arrive as PostgreSQL's JSON timestamptz export. Audit keeps
	// that raw export string; other target timestamps preserve the same instant.
	if strings.HasSuffix(col, "_at") || (col == "lease_until" || col == "locked_until") {
		s, err := stringValue(v)
		if err != nil {
			return nil, err
		}
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil || t.Year() < 1 || t.Year() > 9999 {
			return nil, errors.New("timestamp_not_equivalent")
		}
		if table == "audit_evidence" {
			return s, nil
		}
		return sqlite.FormatTime(t), nil
	}
	if len(v) > 0 && v[0] == '"' {
		return stringValue(v)
	}
	var i int64
	if json.Unmarshal(v, &i) != nil {
		return nil, errors.New("unsupported_numeric_type")
	}
	return i, nil
}
func project(ctx context.Context, s *install.PlatformBackupSnapshot, t *target, interrupt bool) (map[string]int64, []string, error) {
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, errors.New("projection_begin_failed")
	}
	defer tx.Rollback()
	counts := map[string]int64{}
	issues := []string{}
	checks := []referenceCheck{}
	for _, m := range projection {
		order := []string{}
		for _, k := range strings.Split(m.key, ",") {
			order = append(order, identifier(k))
		}
		rows, err := s.ReadRows(ctx, `SELECT row_to_json(t)::text FROM public.`+identifier(m.table)+` t ORDER BY `+strings.Join(order, ","))
		if err != nil {
			return nil, nil, errors.New("projection_read_failed")
		}
		for rows.Next() {
			var raw string
			if rows.Scan(&raw) != nil {
				rows.Close()
				return nil, nil, errors.New("projection_read_failed")
			}
			var r row
			if json.Unmarshal([]byte(raw), &r) != nil {
				rows.Close()
				return nil, nil, errors.New("projection_read_failed")
			}
			if err := supportedRow(m.table, r); err != nil {
				issues = append(issues, err.Error())
				continue
			}
			checks = append(checks, rowReferences(m.table, r)...)
			args := []any{}
			valid := true
			for _, col := range m.columns {
				value, err := field(m.table, col, r)
				if err != nil {
					issues = append(issues, m.table+".unsupported_column_value")
					valid = false
					break
				}
				args = append(args, value)
			}
			if !valid {
				continue
			}
			cols := []string{}
			for _, col := range m.columns {
				cols = append(cols, identifier(col))
			}
			query := `INSERT INTO ` + identifier(m.table) + ` (` + strings.Join(cols, ",") + `) VALUES (` + strings.TrimSuffix(strings.Repeat("?,", len(args)), ",") + `)`
			if _, err := tx.ExecContext(ctx, query, args...); err != nil {
				issues = append(issues, m.table+".constraint_or_reference_rejected")
				continue
			}
			counts[m.table]++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, nil, errors.New("projection_read_failed")
		}
	}
	for _, check := range checks {
		var n int
		if tx.QueryRowContext(ctx, check.query, check.args...).Scan(&n) != nil || n != 1 {
			issues = append(issues, check.code)
		}
	}
	if len(issues) > 0 {
		return nil, issues, nil
	}
	if interrupt {
		return nil, []string{"projection_interrupted_before_commit"}, nil
	}
	var check string
	if err := tx.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&check); err != nil || check != "ok" {
		return nil, []string{"projection_integrity_failed"}, nil
	}
	fk, err := tx.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return nil, []string{"projection_foreign_keys_failed"}, nil
	}
	violated, iterationErr := previewForeignKeyResult(fk)
	if iterationErr != nil {
		return nil, nil, errors.New("projection_foreign_keys_query_failed")
	}

	if violated {
		return nil, []string{"projection_foreign_keys_failed"}, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE diagnostic_migration_preview SET projection_status='verified' WHERE singleton=1`); err != nil {
		return nil, nil, errors.New("projection_checkpoint_failed")
	}
	if tx.Commit() != nil {
		return nil, nil, errors.New("projection_commit_unknown")
	}
	return counts, nil, nil
}

type referenceCheck struct {
	query string
	args  []any
	code  string
}

func rowReferences(table string, r row) []referenceCheck {
	switch table {
	case "operations":
		env, _ := stringValue(r["environment_id"])
		app, _ := stringValue(r["application_id"])
		return []referenceCheck{{`SELECT count(*) FROM environments WHERE id=? AND application_id=?`, []any{env, app}, "operations.missing_environment_reference"}}
	case "idempotency_records":
		if !isNull(r["response"]) {
			v, err := contracts.DecodeCreateApplicationResult(r["response"])
			if err == nil {
				return []referenceCheck{{`SELECT count(*) FROM operations o JOIN environments e ON e.id=o.environment_id JOIN applications a ON a.id=o.application_id JOIN outbox_events b ON b.aggregate_id=o.id WHERE e.application_id=a.id AND a.id=? AND e.id=? AND o.id=? AND b.id=?`, []any{v.Application.ID.String(), v.EnvironmentID.String(), v.OperationID.String(), v.Event.ID}, "idempotency_records.missing_response_reference"}}
			}
		}
	case "task_leases":
		var p map[string]string
		if json.Unmarshal(r["payload"], &p) == nil {
			return []referenceCheck{{`SELECT count(*) FROM operations WHERE id=? AND application_id=?`, []any{p["operation_id"], p["application_id"]}, "task_leases.missing_payload_reference"}}
		}
	case "outbox_events":
		var e contracts.Event
		if json.Unmarshal(r["payload"], &e) == nil {
			return []referenceCheck{{`SELECT count(*) FROM operations WHERE id=? AND application_id=?`, []any{e.OperationID, e.ApplicationID}, "outbox_events.missing_event_reference"}}
		}
	}
	return nil
}

func previewForeignKeyResult(rows interface {
	Next() bool
	Err() error
	Close() error
}) (bool, error) {
	violation := rows.Next()
	err := rows.Err()
	closeErr := rows.Close()
	return violation, errors.Join(err, closeErr)
}
