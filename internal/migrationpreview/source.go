package migrationpreview

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/open-card/open-card/internal/install"
)

// These complete catalog matrices were generated from the frozen repository's
// exact migration bytes on PG16, then checked in as explicit0040/0041 coverage.
//
//go:embed schemas/*.json
var schemas embed.FS

const catalogSQL = `SELECT json_build_object('name',c.relname,'kind',c.relkind,'partition',c.relispartition,'parent',(SELECT p.relname FROM pg_inherits i JOIN pg_class p ON p.oid=i.inhparent WHERE i.inhrelid=c.oid LIMIT 1),'view_definition',CASE WHEN c.relkind IN ('v','m') THEN pg_get_viewdef(c.oid,true) ELSE NULL END,'columns',COALESCE((SELECT json_agg(json_build_object('name',a.attname,'type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull) ORDER BY a.attnum) FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),'[]'::json),'constraints',COALESCE((SELECT json_agg(pg_get_constraintdef(x.oid,true) ORDER BY x.conname) FROM pg_constraint x WHERE x.conrelid=c.oid),'[]'::json))::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f','S') ORDER BY c.relname`

func sourceMatrix(ctx context.Context, s *install.PlatformBackupSnapshot) (Matrix, []string, error) {
	namespace, err := s.ReadRows(ctx, `SELECT count(*) FROM pg_namespace WHERE nspname NOT IN ('public','pg_catalog','information_schema') AND nspname NOT LIKE 'pg_toast%' AND nspname NOT LIKE 'pg_temp_%'`)
	if err != nil {
		return Matrix{}, nil, fmt.Errorf("catalog_unreadable")
	}
	var unknown int
	if !namespace.Next() || namespace.Scan(&unknown) != nil {
		namespace.Close()
		return Matrix{}, nil, fmt.Errorf("catalog_unreadable")
	}
	namespace.Close()
	if unknown != 0 {
		return Matrix{}, []string{"unknown_schema_namespace"}, nil
	}
	rows, err := s.ReadRows(ctx, `SELECT version,checksum FROM public.schema_migrations ORDER BY version`)
	if err != nil {
		return Matrix{}, nil, fmt.Errorf("source_ledger_unreadable")
	}
	ledger := []install.MigrationRow{}
	for rows.Next() {
		var row install.MigrationRow
		if err := rows.Scan(&row.Version, &row.Checksum); err != nil {
			rows.Close()
			return Matrix{}, nil, fmt.Errorf("source_ledger_unreadable")
		}
		ledger = append(ledger, row)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return Matrix{}, nil, fmt.Errorf("source_ledger_unreadable")
	}
	if len(ledger) != 40 && len(ledger) != 41 {
		return Matrix{}, []string{"unknown_schema_version"}, nil
	}
	data, _ := schemas.ReadFile(fmt.Sprintf("schemas/pg%04d.json", len(ledger)))
	var expected Matrix
	if err := json.Unmarshal(data, &expected); err != nil {
		return Matrix{}, nil, fmt.Errorf("compiled_matrix_invalid")
	}
	if !reflect.DeepEqual(ledger, expected.Migrations) {
		return expected, []string{"migration_manifest_mismatch"}, nil
	}
	rows, err = s.ReadRows(ctx, catalogSQL)
	if err != nil {
		return expected, nil, fmt.Errorf("catalog_unreadable")
	}
	actual := []Relation{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return expected, nil, fmt.Errorf("catalog_unreadable")
		}
		var rel Relation
		if json.Unmarshal([]byte(raw), &rel) != nil {
			rows.Close()
			return expected, nil, fmt.Errorf("catalog_unreadable")
		}
		actual = append(actual, rel)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return expected, nil, fmt.Errorf("catalog_unreadable")
	}
	expected.Differences = schemaDifferences(expected.Relations, actual)
	if !reflect.DeepEqual(actual, expected.Relations) {
		return expected, []string{"unknown_relation_column_type_or_constraint"}, nil
	}
	return expected, nil, nil
}

// identifier is used only for names from the embedded, positively matched
// schema matrix. Source values and CLI text never supply projection SQL.
func identifier(v string) string { return `"` + strings.ReplaceAll(v, `"`, `""`) + `"` }

var mappedTables = map[string]bool{"admin_credentials": true, "admin_sessions": true, "admin_login_rate_limits": true, "applications": true, "environments": true, "operations": true, "idempotency_records": true, "task_leases": true, "outbox_events": true, "audit_evidence": true}

func disposition(table, col string) string {
	if table == "schema_migrations" {
		return "non-authoritative-source-metadata"
	}
	if !mappedTables[table] {
		return "unsupported"
	}
	switch table + "." + col {
	case "applications.management_state", "applications.archived_at", "operations.deployment_id", "task_leases.result", "task_leases.result_digest", "task_leases.completed_at", "task_leases.wire_version", "task_leases.negotiated_capabilities", "outbox_events.compatibility":
		return "unsupported"
	case "task_leases.last_error":
		return "explicit-transform-null-to-empty"
	}
	found := false
	for _, m := range projection {
		if m.table == table {
			for _, c := range m.columns {
				if c == col {
					found = true
				}
			}
		}
	}
	if !found {
		return "unsupported"
	}
	if strings.HasSuffix(col, "_at") || (col == "lease_until" || col == "locked_until") || strings.Contains(col, "expires_at") {
		if table != "audit_evidence" {
			return "explicit-transform-same-instant-utc"
		}
	}
	return "mapped"
}
func coverage(ctx context.Context, s *install.PlatformBackupSnapshot, m Matrix) ([]RelationCoverage, []SequenceObservation, error) {
	result := []RelationCoverage{}
	sequences := []SequenceObservation{}
	for _, rel := range m.Relations {
		if rel.Kind == "S" {
			rows, err := s.ReadRows(ctx, `SELECT last_value,is_called FROM public.`+identifier(rel.Name))
			if err != nil {
				return nil, nil, fmt.Errorf("sequence_observation_failed")
			}
			var obs SequenceObservation
			obs.Name = rel.Name
			if !rows.Next() || rows.Scan(&obs.LastValue, &obs.IsCalled) != nil {
				rows.Close()
				return nil, nil, fmt.Errorf("sequence_observation_failed")
			}
			rows.Close()
			sequences = append(sequences, obs)
			continue
		}
		if rel.Kind != "r" && rel.Kind != "p" && rel.Kind != "v" && rel.Kind != "m" {
			return nil, nil, fmt.Errorf("relation_kind_unsupported")
		}
		c := RelationCoverage{Name: rel.Name, Kind: rel.Kind, Partition: rel.Partition, Parent: rel.Parent, Disposition: "unsupported"}
		if mappedTables[rel.Name] {
			c.Disposition = "mapped-projection-only"
		}
		if rel.Name == "schema_migrations" {
			c.Disposition = "non-authoritative-source-metadata"
		}
		only := "ONLY "
		if rel.Kind == "v" || rel.Kind == "m" {
			only = ""
		}
		if rel.Kind == "v" {
			c.Disposition = "non-authoritative-derived-view"
		}
		rows, err := s.ReadRows(ctx, `SELECT row_to_json(t)::text FROM `+only+`public.`+identifier(rel.Name)+` t ORDER BY row_to_json(t)::text COLLATE "C"`)
		if err != nil {
			return nil, nil, fmt.Errorf("coverage_read_failed")
		}
		rowHash := sha256.New()
		nonNull := map[string]int64{}
		for rows.Next() {
			var raw string
			if rows.Scan(&raw) != nil {
				rows.Close()
				return nil, nil, fmt.Errorf("coverage_read_failed")
			}
			var values map[string]json.RawMessage
			if json.Unmarshal([]byte(raw), &values) != nil {
				rows.Close()
				return nil, nil, fmt.Errorf("coverage_read_failed")
			}
			for k, v := range values {
				if string(v) != "null" {
					nonNull[k]++
				}
			}
			rowHash.Write([]byte(raw))
			rowHash.Write([]byte("\n"))
			c.Rows++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("coverage_read_failed")
		}
		c.SHA256 = hex.EncodeToString(rowHash.Sum(nil))
		for _, col := range rel.Columns {
			c.Columns = append(c.Columns, ColumnCoverage{Name: col.Name, Type: col.Type, Disposition: func() string {
				if rel.Kind == "v" {
					return "non-authoritative-derived-view"
				}
				return disposition(rel.Name, col.Name)
			}(), NonNullRows: nonNull[col.Name]})
		}
		result = append(result, c)
	}
	sort.Slice(sequences, func(i, j int) bool { return sequences[i].Name < sequences[j].Name })
	return result, sequences, nil
}

func safeMetadata(s string) string {
	if len(s) > 128 {
		return "<untrusted-metadata>"
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_ .(),[]", r)) {
			return "<untrusted-metadata>"
		}
	}
	return s
}
func schemaDifferences(expected, actual []Relation) []SchemaDifference {
	result := []SchemaDifference{}
	wanted := map[string]Relation{}
	for _, r := range expected {
		wanted[r.Name] = r
	}
	for _, a := range actual {
		e, ok := wanted[a.Name]
		if !ok {
			result = append(result, SchemaDifference{Relation: safeMetadata(a.Name), Code: "unknown_relation"})
			continue
		}
		delete(wanted, a.Name)
		columns := map[string]Column{}
		for _, c := range e.Columns {
			columns[c.Name] = c
		}
		for _, c := range a.Columns {
			old, ok := columns[c.Name]
			if !ok {
				result = append(result, SchemaDifference{Relation: safeMetadata(a.Name), Column: safeMetadata(c.Name), ObservedType: safeMetadata(c.Type), Code: "unknown_column"})
				continue
			}
			delete(columns, c.Name)
			if old != c {
				result = append(result, SchemaDifference{Relation: safeMetadata(a.Name), Column: safeMetadata(c.Name), ExpectedType: safeMetadata(old.Type), ObservedType: safeMetadata(c.Type), Code: "column_type_or_nullability_mismatch"})
			}
		}
		for _, c := range e.Columns {
			if _, ok := columns[c.Name]; ok {
				result = append(result, SchemaDifference{Relation: safeMetadata(a.Name), Column: safeMetadata(c.Name), Code: "missing_column"})
			}
		}
		if e.ViewDefinition != a.ViewDefinition {
			result = append(result, SchemaDifference{Relation: safeMetadata(a.Name), Code: "unknown_view_definition"})
		}
		if !reflect.DeepEqual(e.Constraints, a.Constraints) || e.Kind != a.Kind || e.Partition != a.Partition || !reflect.DeepEqual(e.Parent, a.Parent) {
			result = append(result, SchemaDifference{Relation: safeMetadata(a.Name), Code: "relation_or_constraint_mismatch"})
		}
	}
	for _, r := range expected {
		if _, ok := wanted[r.Name]; ok {
			result = append(result, SchemaDifference{Relation: safeMetadata(r.Name), Code: "missing_relation"})
		}
	}
	return result
}
