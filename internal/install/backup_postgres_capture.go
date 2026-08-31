package install

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

const platformBackupDumpFile = "control-plane.dump"

var ErrPlatformBackupCleanupUnknown = errors.New("platform backup cleanup outcome is unknown")

// PostgreSQL 16 emits exported snapshot identifiers such as
// 00000003-0000001B-1. Keep this validation deliberately narrower than a
// generic token so a value can only reach pg_dump through --snapshot.
var postgresExportedSnapshotID = regexp.MustCompile(`^[0-9A-F]{8}-[0-9A-F]{8}-[1-9][0-9]{0,9}$`)

const (
	postgresCaptureMaxSnapshotID = 27
	postgresCaptureMaxRowBytes   = 8 << 20
)

func validPostgresExportedSnapshotID(value string) bool {
	return len(value) > 0 && len(value) <= postgresCaptureMaxSnapshotID && postgresExportedSnapshotID.MatchString(value)
}

// PlatformBackupSnapshot is the short-lived read-only transaction that pins
// B3 facts and pg_dump to one PostgreSQL exported snapshot. Its raw snapshot
// ID deliberately remains private to this package and is never marshalled.
type PlatformBackupSnapshot struct {
	tx                     postgresTx
	exportedSnapshotID     string
	DatabaseSnapshotSHA256 string
	closed                 bool
}

// These redactions cover both value and pointer formatting/JSON paths. The raw
// exported ID is an in-process capability and must never appear in telemetry.
func (PlatformBackupSnapshot) String() string   { return "platform-backup-snapshot(redacted)" }
func (PlatformBackupSnapshot) GoString() string { return "install.PlatformBackupSnapshot(redacted)" }
func (PlatformBackupSnapshot) MarshalJSON() ([]byte, error) {
	return json.Marshal("platform-backup-snapshot(redacted)")
}

// PlatformBackupCapturedFactsV1 contains only public-safe B2 receipts. The
// release fact's activation/release/pointer fields are composed by the backup
// manager; Database is the transaction-pinned database evidence it needs.
type PlatformBackupCapturedFactsV1 struct {
	DatabaseSnapshotSHA256 string
	Routes                 PlatformBackupRoutesV1
	Audit                  PlatformBackupAuditV1
	KeyReferences          PlatformBackupKeyReferencesV1
	TasksOutbox            PlatformBackupTasksOutboxV1
	TLS                    PlatformBackupTLSV1
	CurrentDatabase        string
	SchemaMigrations       []MigrationRow
}

// PlatformBackupDatabaseCaptureRequest has no expected dump evidence: an
// exported-snapshot dump must always be fresh, never reused from disk.
type PlatformBackupDatabaseCaptureRequest struct {
	TransactionID  string
	Writer         *DurableWriter
	Environment    PostgresProcessEnvironment
	LocalBackupKey PlatformBackupKeyReferenceV1
}

// PlatformBackupDatabaseCaptureResult is returned only after the export
// transaction has rolled back successfully, so its dump and facts are known to
// originate from the same now-closed PostgreSQL snapshot.
type PlatformBackupDatabaseCaptureResult struct {
	DumpEvidence           SnapshotEvidence
	Facts                  PlatformBackupCapturedFactsV1
	DatabaseSnapshotSHA256 string
}

// BeginPlatformBackupSnapshot starts the only transaction allowed for B3
// capture. It must remain open until pg_dump and CaptureFacts complete.
func (s *SelectedPostgresDatabase) BeginPlatformBackupSnapshot(ctx context.Context) (*PlatformBackupSnapshot, error) {
	if s == nil || s.database == nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	tx, err := s.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	fail := func() (*PlatformBackupSnapshot, error) {
		if tx.Rollback() != nil {
			return nil, ErrPostgresOutcomeUnknown
		}
		return nil, ErrPostgresOutcomeUnknown
	}
	for _, query := range []string{
		"SET LOCAL TimeZone TO 'UTC'",
		"SET LOCAL DateStyle TO 'ISO, YMD'",
		"SET LOCAL IntervalStyle TO 'iso_8601'",
		"SET LOCAL bytea_output TO 'hex'",
		"SET LOCAL extra_float_digits TO '3'",
		"SET LOCAL search_path TO pg_catalog, public",
	} {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return fail()
		}
	}
	var rawSnapshotID string
	if err := tx.QueryRowContext(ctx, "SELECT pg_export_snapshot()").Scan(&rawSnapshotID); err != nil || !validPostgresExportedSnapshotID(rawSnapshotID) {
		return fail()
	}
	digest := sha256.Sum256([]byte(rawSnapshotID))
	return &PlatformBackupSnapshot{tx: tx, exportedSnapshotID: rawSnapshotID, DatabaseSnapshotSHA256: hex.EncodeToString(digest[:])}, nil
}

// SnapshotWithExportedSnapshot is the only safe bridge from the private
// exported identifier to pg_dump. It never places the identifier in an error,
// process environment, or fact payload.
func (s *PlatformBackupSnapshot) SnapshotWithExportedSnapshot(ctx context.Context, snapshotter *PostgresSnapshotter, transactionID, dir string, env PostgresProcessEnvironment, expect *SnapshotEvidence) (SnapshotEvidence, error) {
	if s == nil || s.tx == nil || s.closed || snapshotter == nil {
		return SnapshotEvidence{}, ErrPostgresOutcomeUnknown
	}
	return snapshotter.SnapshotWithExportedSnapshot(ctx, transactionID, dir, env, s.exportedSnapshotID, expect)
}

func (s *PlatformBackupSnapshot) snapshotPreparedExportedSnapshot(ctx context.Context, snapshotter *PostgresSnapshotter, transactionID string, writer *DurableWriter, env PostgresProcessEnvironment) (SnapshotEvidence, error) {
	if s == nil || s.tx == nil || s.closed || snapshotter == nil {
		return SnapshotEvidence{}, ErrPostgresOutcomeUnknown
	}
	return snapshotter.snapshotPreparedExportedSnapshot(ctx, transactionID, writer, env, s.exportedSnapshotID)
}

// Commit is forbidden: B3's export transaction is a read-only consistency
// anchor, not a mutation boundary. Call Rollback exactly once after capture.
func (s *PlatformBackupSnapshot) Commit() error { return ErrPostgresOutcomeUnknown }

func (s *PlatformBackupSnapshot) Rollback() error {
	if s == nil || s.tx == nil || s.closed {
		return ErrPostgresOutcomeUnknown
	}
	// Detach before the driver call. A failed/ambiguous rollback must never
	// leave a reusable exported snapshot capability in memory.
	tx := s.tx
	s.tx = nil
	s.closed = true
	s.exportedSnapshotID = ""
	if err := tx.Rollback(); err != nil {
		return ErrPostgresOutcomeUnknown
	}
	return nil
}

// CaptureFacts records every B2 database fact using the still-open exported
// snapshot. It intentionally returns no raw database rows or secret material.
func (s *PlatformBackupSnapshot) CaptureFacts(ctx context.Context, localBackupKey PlatformBackupKeyReferenceV1) (PlatformBackupCapturedFactsV1, error) {
	if s == nil || s.tx == nil || s.closed || !validPostgresExportedSnapshotID(s.exportedSnapshotID) || !validLocalBackupKeyReference(localBackupKey) {
		return PlatformBackupCapturedFactsV1{}, ErrPostgresOutcomeUnknown
	}
	result := PlatformBackupCapturedFactsV1{DatabaseSnapshotSHA256: s.DatabaseSnapshotSHA256}
	routes := make([]TableDigest, 0, len(platformBackupRouteTables))
	for _, table := range platformBackupRouteTables {
		digest, err := s.tableDigest(ctx, table.name, table.order, "")
		if err != nil {
			return PlatformBackupCapturedFactsV1{}, err
		}
		routes = append(routes, digest)
	}
	result.Routes = PlatformBackupRoutesV1{SchemaVersion: 1, DatabaseSnapshotSHA256: s.DatabaseSnapshotSHA256, Canonicalization: PlatformBackupFactCanonicalization, Tables: routes}
	if result.Routes.Validate() != nil {
		return PlatformBackupCapturedFactsV1{}, ErrPostgresOutcomeUnknown
	}

	audit, err := s.captureAudit(ctx)
	if err != nil {
		return PlatformBackupCapturedFactsV1{}, err
	}
	result.Audit = audit
	keys, err := s.captureKeyReferences(ctx, localBackupKey)
	if err != nil {
		return PlatformBackupCapturedFactsV1{}, err
	}
	result.KeyReferences = keys
	tasks, err := s.captureTasksOutbox(ctx)
	if err != nil {
		return PlatformBackupCapturedFactsV1{}, err
	}
	result.TasksOutbox = tasks
	tls, err := s.captureTLS(ctx)
	if err != nil {
		return PlatformBackupCapturedFactsV1{}, err
	}
	result.TLS = tls
	migrations, err := s.captureMigrationRows(ctx)
	if err != nil {
		return PlatformBackupCapturedFactsV1{}, err
	}
	result.SchemaMigrations = migrations
	if err := s.tx.QueryRowContext(ctx, "SELECT current_database()").Scan(&result.CurrentDatabase); err != nil || result.CurrentDatabase == "" {
		return PlatformBackupCapturedFactsV1{}, ErrPostgresOutcomeUnknown
	}
	return result, nil
}

func validLocalBackupKeyReference(value PlatformBackupKeyReferenceV1) bool {
	return value.Provider == "local-backup-key" && value.KeyID == "backup-encryption" && backupKeyVersion.MatchString(value.KeyVersion) && !value.Revoked && value.valid()
}

// CapturePlatformBackupDatabase is the sole production-safe B3 operation. It
// owns Begin -> pg_dump(--snapshot) -> facts -> Rollback as one all-or-nothing
// capture. Legacy BackupManager remains the V2 path; a Platform V3 manager
// must use this composite rather than compose the low-level primitives.
func CapturePlatformBackupDatabase(ctx context.Context, selectedDB *SelectedPostgresDatabase, snapshotter *PostgresSnapshotter, request PlatformBackupDatabaseCaptureRequest) (PlatformBackupDatabaseCaptureResult, error) {
	if selectedDB == nil || snapshotter == nil || !validID(request.TransactionID) || !validLocalBackupKeyReference(request.LocalBackupKey) || !validPlatformBackupCaptureWriter(request.Writer) {
		return PlatformBackupDatabaseCaptureResult{}, ErrPostgresOutcomeUnknown
	}
	if err := createPreparedPlatformBackupDump(request.Writer); err != nil {
		return PlatformBackupDatabaseCaptureResult{}, err
	}
	snapshot, err := selectedDB.BeginPlatformBackupSnapshot(ctx)
	if err != nil {
		if cleanupErr := removeNewPlatformBackupDump(request.Writer); cleanupErr != nil {
			return PlatformBackupDatabaseCaptureResult{}, cleanupErr
		}
		return PlatformBackupDatabaseCaptureResult{}, ErrPostgresOutcomeUnknown
	}
	fail := func() (PlatformBackupDatabaseCaptureResult, error) {
		rollbackErr := snapshot.Rollback()
		cleanupErr := removeNewPlatformBackupDump(request.Writer)
		if cleanupErr != nil {
			return PlatformBackupDatabaseCaptureResult{}, cleanupErr
		}
		if rollbackErr != nil {
			return PlatformBackupDatabaseCaptureResult{}, ErrPostgresOutcomeUnknown
		}
		return PlatformBackupDatabaseCaptureResult{}, ErrPostgresOutcomeUnknown
	}
	dump, err := snapshot.snapshotPreparedExportedSnapshot(ctx, snapshotter, request.TransactionID, request.Writer, request.Environment)
	if err != nil {
		return fail()
	}
	facts, err := snapshot.CaptureFacts(ctx, request.LocalBackupKey)
	if err != nil || facts.DatabaseSnapshotSHA256 != snapshot.DatabaseSnapshotSHA256 {
		return fail()
	}
	if err := snapshot.Rollback(); err != nil {
		if cleanupErr := removeNewPlatformBackupDump(request.Writer); cleanupErr != nil {
			return PlatformBackupDatabaseCaptureResult{}, cleanupErr
		}
		return PlatformBackupDatabaseCaptureResult{}, ErrPostgresOutcomeUnknown
	}
	return PlatformBackupDatabaseCaptureResult{DumpEvidence: dump, Facts: facts, DatabaseSnapshotSHA256: facts.DatabaseSnapshotSHA256}, nil
}

func validPlatformBackupCaptureWriter(writer *DurableWriter) bool {
	if writer == nil || writer.VerifyLiveRoot() != nil || writer.rootInfo == nil {
		return false
	}
	root, err := writer.ops.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	defer writer.ops.CloseFile(root)
	info, err := writer.ops.Stat(root)
	return err == nil && info.IsDir() && info.Mode().Perm() == durableDirMode && verifyOwner(info, writer.uid, writer.gid) == nil
}

func createPreparedPlatformBackupDump(writer *DurableWriter) error {
	err := writer.CreateMetadata(platformBackupDumpFile, nil)
	if err == nil {
		if preparedPlatformBackupDump(writer) {
			return nil
		}
		return ErrPostgresOutcomeUnknown
	}
	if errors.Is(err, os.ErrExist) {
		return ErrSnapshotConflict
	}
	if errors.Is(err, ErrDurableCommitUnknown) {
		raw, readErr := writer.ReadMetadata(platformBackupDumpFile)
		if readErr == nil && len(raw) == 0 && preparedPlatformBackupDump(writer) {
			return nil
		}
	}
	return ErrPostgresOutcomeUnknown
}

func removeNewPlatformBackupDump(writer *DurableWriter) error {
	if writer == nil || writer.RemoveMetadata(platformBackupDumpFile) != nil {
		return ErrPlatformBackupCleanupUnknown
	}
	return nil
}

func (s *PlatformBackupSnapshot) tableDigest(ctx context.Context, table string, order []string, where string) (TableDigest, error) {
	query, ok := postgresTableDigestSQL(table, order, where)
	if !ok {
		return TableDigest{}, ErrPostgresOutcomeUnknown
	}
	rows, err := s.tx.QueryContext(ctx, query)
	if err != nil {
		return TableDigest{}, ErrPostgresOutcomeUnknown
	}
	digest, count, err := postgresRowsDigest(rows)
	if err != nil {
		return TableDigest{}, err
	}
	return TableDigest{Name: table, RowCount: count, RowsSHA256: digest, OrderBy: append([]string(nil), order...)}, nil
}

func postgresTableDigestSQL(table string, order []string, where string) (string, bool) {
	if table == "" || len(order) == 0 || where != "" && where != "WHERE published_at IS NULL" && where != "WHERE state IN ('ready','leased')" {
		return "", false
	}
	allowed := false
	for _, expected := range platformBackupRouteTables {
		if expected.name == table && equalStrings(expected.order, order) {
			allowed = true
		}
	}
	for _, expected := range []struct {
		name  string
		order []string
	}{
		{"audit_evidence", []string{"sequence"}}, {"outbox_events", []string{"stream_sequence"}}, {"task_agent_events", []string{"task_id", "sequence"}}, {"task_leases", []string{"created_at", "task_id"}},
	} {
		if expected.name == table && equalStrings(expected.order, order) {
			allowed = true
		}
	}
	if !allowed {
		return "", false
	}
	return "SELECT to_jsonb(t)::text FROM (SELECT * FROM public." + table + " " + where + " ORDER BY " + strings.Join(order, ", ") + ") t", true
}

func postgresRowsDigest(rows postgresRows) (string, int64, error) {
	if rows == nil {
		return "", 0, ErrPostgresOutcomeUnknown
	}
	hash := sha256.New()
	var count int64
	for rows.Next() {
		var row string
		if err := rows.Scan(&row); err != nil || len(row) > postgresCaptureMaxRowBytes {
			_ = rows.Close()
			return "", 0, ErrPostgresOutcomeUnknown
		}
		if _, err := hash.Write([]byte(row)); err != nil {
			_ = rows.Close()
			return "", 0, ErrPostgresOutcomeUnknown
		}
		if _, err := hash.Write([]byte{'\n'}); err != nil {
			_ = rows.Close()
			return "", 0, ErrPostgresOutcomeUnknown
		}
		count++
	}
	if rows.Err() != nil || rows.Close() != nil {
		return "", 0, ErrPostgresOutcomeUnknown
	}
	return hex.EncodeToString(hash.Sum(nil)), count, nil
}

func (s *PlatformBackupSnapshot) captureAudit(ctx context.Context) (PlatformBackupAuditV1, error) {
	const query = "SELECT to_jsonb(t)::text, t.sequence, t.previous_hash, t.record_hash FROM (SELECT * FROM public.audit_evidence ORDER BY sequence) t"
	rows, err := s.tx.QueryContext(ctx, query)
	if err != nil {
		return PlatformBackupAuditV1{}, ErrPostgresOutcomeUnknown
	}
	hash := sha256.New()
	var count, first, last int64
	var chain string
	for rows.Next() {
		var row, recordHash string
		var sequence int64
		var previous sql.NullString
		if err := rows.Scan(&row, &sequence, &previous, &recordHash); err != nil || len(row) > postgresCaptureMaxRowBytes || sequence <= 0 || (count > 0 && sequence <= last) || previous.String != chain || previous.Valid != (chain != "") || !strings.HasPrefix(recordHash, "sha256:") || !validSHA(strings.TrimPrefix(recordHash, "sha256:")) {
			_ = rows.Close()
			return PlatformBackupAuditV1{}, ErrPostgresOutcomeUnknown
		}
		if _, err := fmt.Fprintf(hash, "%s\n", row); err != nil {
			_ = rows.Close()
			return PlatformBackupAuditV1{}, ErrPostgresOutcomeUnknown
		}
		if count == 0 {
			first = sequence
		}
		last, chain, count = sequence, recordHash, count+1
	}
	if rows.Err() != nil || rows.Close() != nil {
		return PlatformBackupAuditV1{}, ErrPostgresOutcomeUnknown
	}
	var sequence PlatformBackupSequenceV1
	if err := s.tx.QueryRowContext(ctx, "SELECT last_value, is_called FROM public.audit_evidence_sequence_seq").Scan(&sequence.LastValue, &sequence.IsCalled); err != nil || sequence.LastValue < 0 {
		return PlatformBackupAuditV1{}, ErrPostgresOutcomeUnknown
	}
	sequence.Relation = "public.audit_evidence_sequence_seq"
	fact := PlatformBackupAuditV1{SchemaVersion: 1, DatabaseSnapshotSHA256: s.DatabaseSnapshotSHA256, Canonicalization: PlatformBackupFactCanonicalization, Table: TableDigest{Name: "audit_evidence", RowCount: count, RowsSHA256: hex.EncodeToString(hash.Sum(nil)), OrderBy: []string{"sequence"}}, Sequence: sequence, LinkContinuity: true}
	if count > 0 {
		fact.FirstSequence, fact.LastSequence, fact.ChainHead = &first, &last, &chain
	}
	if fact.Validate() != nil {
		return PlatformBackupAuditV1{}, ErrPostgresOutcomeUnknown
	}
	return fact, nil
}

func (s *PlatformBackupSnapshot) captureKeyReferences(ctx context.Context, local PlatformBackupKeyReferenceV1) (PlatformBackupKeyReferencesV1, error) {
	rows, err := s.tx.QueryContext(ctx, "SELECT id, key_version, revoked_at IS NOT NULL FROM public.secret_references ORDER BY id")
	if err != nil {
		return PlatformBackupKeyReferencesV1{}, ErrPostgresOutcomeUnknown
	}
	refs := []PlatformBackupKeyReferenceV1{}
	for rows.Next() {
		var id, version string
		var revoked bool
		if err := rows.Scan(&id, &version, &revoked); err != nil {
			_ = rows.Close()
			return PlatformBackupKeyReferencesV1{}, ErrPostgresOutcomeUnknown
		}
		ref := PlatformBackupKeyReferenceV1{Provider: "control-plane-secret", KeyID: id, KeyVersion: version, Revoked: revoked}
		if !ref.valid() {
			_ = rows.Close()
			return PlatformBackupKeyReferencesV1{}, ErrPostgresOutcomeUnknown
		}
		refs = append(refs, ref)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return PlatformBackupKeyReferencesV1{}, ErrPostgresOutcomeUnknown
	}
	refs = append(refs, local)
	sort.Slice(refs, func(i, j int) bool { return keyRefLess(refs[i], refs[j]) })
	fact := PlatformBackupKeyReferencesV1{SchemaVersion: 1, DatabaseSnapshotSHA256: s.DatabaseSnapshotSHA256, References: refs}
	if fact.Validate() != nil {
		return PlatformBackupKeyReferencesV1{}, ErrPostgresOutcomeUnknown
	}
	return fact, nil
}

func (s *PlatformBackupSnapshot) captureTasksOutbox(ctx context.Context) (PlatformBackupTasksOutboxV1, error) {
	full := []struct {
		name  string
		order []string
	}{{"outbox_events", []string{"stream_sequence"}}, {"task_agent_events", []string{"task_id", "sequence"}}, {"task_leases", []string{"created_at", "task_id"}}}
	tables := make([]TableDigest, 0, len(full))
	for _, item := range full {
		digest, err := s.tableDigest(ctx, item.name, item.order, "")
		if err != nil {
			return PlatformBackupTasksOutboxV1{}, err
		}
		tables = append(tables, digest)
	}
	pending, err := s.captureSubset(ctx, "outbox_events", []string{"stream_sequence"}, "WHERE published_at IS NULL")
	if err != nil {
		return PlatformBackupTasksOutboxV1{}, err
	}
	recoverable, err := s.captureRecoverableTasks(ctx)
	if err != nil {
		return PlatformBackupTasksOutboxV1{}, err
	}
	var sequence PlatformBackupSequenceV1
	if err := s.tx.QueryRowContext(ctx, "SELECT last_value, is_called FROM public.outbox_events_stream_sequence").Scan(&sequence.LastValue, &sequence.IsCalled); err != nil || sequence.LastValue < 0 {
		return PlatformBackupTasksOutboxV1{}, ErrPostgresOutcomeUnknown
	}
	sequence.Relation = "public.outbox_events_stream_sequence"
	fact := PlatformBackupTasksOutboxV1{SchemaVersion: 1, DatabaseSnapshotSHA256: s.DatabaseSnapshotSHA256, Canonicalization: PlatformBackupFactCanonicalization, Tables: tables, OutboxSequence: sequence, PendingOutbox: pending, RecoverableTasks: recoverable}
	if fact.Validate() != nil {
		return PlatformBackupTasksOutboxV1{}, ErrPostgresOutcomeUnknown
	}
	return fact, nil
}

func (s *PlatformBackupSnapshot) captureSubset(ctx context.Context, table string, order []string, where string) (PlatformBackupPendingOutboxV1, error) {
	digest, err := s.tableDigest(ctx, table, order, where)
	if err != nil {
		return PlatformBackupPendingOutboxV1{}, err
	}
	result := PlatformBackupPendingOutboxV1{PlatformBackupRowsDigestV1: PlatformBackupRowsDigestV1{RowCount: digest.RowCount, RowsSHA256: digest.RowsSHA256, OrderBy: digest.OrderBy}}
	if result.RowCount == 0 {
		return result, nil
	}
	var first, last int64
	if err := s.tx.QueryRowContext(ctx, "SELECT min(stream_sequence), max(stream_sequence) FROM public.outbox_events WHERE published_at IS NULL").Scan(&first, &last); err != nil || first <= 0 || last < first {
		return PlatformBackupPendingOutboxV1{}, ErrPostgresOutcomeUnknown
	}
	result.FirstStreamSequence, result.LastStreamSequence = &first, &last
	return result, nil
}

func (s *PlatformBackupSnapshot) captureRecoverableTasks(ctx context.Context) (PlatformBackupRecoverableTasksV1, error) {
	digest, err := s.tableDigest(ctx, "task_leases", []string{"created_at", "task_id"}, "WHERE state IN ('ready','leased')")
	if err != nil {
		return PlatformBackupRecoverableTasksV1{}, err
	}
	result := PlatformBackupRecoverableTasksV1{PlatformBackupRowsDigestV1: PlatformBackupRowsDigestV1{RowCount: digest.RowCount, RowsSHA256: digest.RowsSHA256, OrderBy: digest.OrderBy}}
	if result.RowCount == 0 {
		return result, nil
	}
	var first, last time.Time
	if err := s.tx.QueryRowContext(ctx, "SELECT min(created_at), max(created_at) FROM public.task_leases WHERE state IN ('ready','leased')").Scan(&first, &last); err != nil || first.IsZero() || last.IsZero() {
		return PlatformBackupRecoverableTasksV1{}, ErrPostgresOutcomeUnknown
	}
	first, last = first.UTC(), last.UTC()
	result.FirstCreatedAt, result.LastCreatedAt = &first, &last
	return result, nil
}

func (s *PlatformBackupSnapshot) captureTLS(ctx context.Context) (PlatformBackupTLSV1, error) {
	const query = "SELECT id, CASE WHEN platform_domain_id IS NOT NULL THEN 'platform_domain' ELSE 'application_domain' END, COALESCE(platform_domain_id, application_domain_id), secret_reference_id, subject_hostname, issuer, status, not_before, not_after, renewal_due_at FROM public.m3_certificate_references ORDER BY id"
	rows, err := s.tx.QueryContext(ctx, query)
	if err != nil {
		return PlatformBackupTLSV1{}, ErrPostgresOutcomeUnknown
	}
	refs := []PlatformBackupTLSReferenceV1{}
	for rows.Next() {
		var ref PlatformBackupTLSReferenceV1
		var secret sql.NullString
		var before, after, renewal sql.NullTime
		if err := rows.Scan(&ref.CertificateReferenceID, &ref.OwnerKind, &ref.OwnerID, &secret, &ref.SubjectHostname, &ref.Issuer, &ref.Status, &before, &after, &renewal); err != nil {
			_ = rows.Close()
			return PlatformBackupTLSV1{}, ErrPostgresOutcomeUnknown
		}
		if secret.Valid {
			if !validID(secret.String) {
				_ = rows.Close()
				return PlatformBackupTLSV1{}, ErrPostgresOutcomeUnknown
			}
			value := secret.String
			ref.SecretReferenceID = &value
		}
		ref.NotBefore, ref.NotAfter, ref.RenewalDueAt = nullableTime(before), nullableTime(after), nullableTime(renewal)
		if !ref.valid() {
			_ = rows.Close()
			return PlatformBackupTLSV1{}, ErrPostgresOutcomeUnknown
		}
		refs = append(refs, ref)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return PlatformBackupTLSV1{}, ErrPostgresOutcomeUnknown
	}
	fact := PlatformBackupTLSV1{SchemaVersion: 1, DatabaseSnapshotSHA256: s.DatabaseSnapshotSHA256, MaterialIncluded: false, RestorePolicy: "resolve-or-reissue", References: refs}
	if fact.Validate() != nil {
		return PlatformBackupTLSV1{}, ErrPostgresOutcomeUnknown
	}
	return fact, nil
}

func (s *PlatformBackupSnapshot) captureMigrationRows(ctx context.Context) ([]MigrationRow, error) {
	rows, err := s.tx.QueryContext(ctx, "SELECT version, checksum FROM public.schema_migrations ORDER BY version")
	if err != nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	result := []MigrationRow{}
	for rows.Next() {
		var row MigrationRow
		if err := rows.Scan(&row.Version, &row.Checksum); err != nil {
			_ = rows.Close()
			return nil, ErrPostgresOutcomeUnknown
		}
		result = append(result, row)
	}
	if rows.Err() != nil || rows.Close() != nil || len(result) != 24 || !validMigrationRows(result, 24) || result[23].Version[:4] != CurrentMigrationVersion {
		return nil, ErrPostgresOutcomeUnknown
	}
	return result, nil
}

// ReleaseDatabase returns the database component used by the B2 release fact
// after the caller verifies its activation metadata and filesystem pointers.
func (f PlatformBackupCapturedFactsV1) ReleaseDatabase() (PlatformBackupReleaseDatabaseV1, error) {
	if !validSHA(f.DatabaseSnapshotSHA256) || f.CurrentDatabase == "" || len(f.SchemaMigrations) != 24 || !validMigrationRows(f.SchemaMigrations, 24) || f.SchemaMigrations[23].Version[:4] != CurrentMigrationVersion {
		return PlatformBackupReleaseDatabaseV1{}, ErrPostgresOutcomeUnknown
	}
	digest, err := CanonicalMigrationRowsSHA256(f.SchemaMigrations)
	if err != nil {
		return PlatformBackupReleaseDatabaseV1{}, ErrPostgresOutcomeUnknown
	}
	return PlatformBackupReleaseDatabaseV1{DatabaseV1: DatabaseV1{Name: f.CurrentDatabase, Migration: f.SchemaMigrations[len(f.SchemaMigrations)-1].Version[:4], SchemaMigrationsSHA256: digest}, CurrentDatabase: f.CurrentDatabase, SchemaMigrationsCount: int64(len(f.SchemaMigrations)), SchemaMigrationsRowsSHA256: digest}, nil
}
