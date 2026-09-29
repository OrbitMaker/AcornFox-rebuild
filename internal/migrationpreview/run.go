package migrationpreview

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/open-card/open-card/internal/install"
)

func privateParent(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return errors.New("private_output_parent_required")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Getuid()) {
		return errors.New("private_output_parent_required")
	}
	return nil
}
func Run(ctx context.Context, cfg Config) (Result, error) { return run(ctx, cfg, false) }
func run(ctx context.Context, cfg Config, interrupt bool) (res Result, retErr error) {
	if err := trustedAncestors(cfg.SourceDSNFile); err != nil {
		return res, err
	}
	if err := trustedAncestors(filepath.Join(cfg.OutputParent, "new-output")); err != nil {
		return res, err
	}
	trustedTool, err := trustedDumpTool(cfg.DumpTool)
	if err != nil {
		return res, err
	}
	cfg.DumpTool = trustedTool
	if err := privateParent(cfg.OutputParent); err != nil {
		return res, err
	}
	dsn, err := privateFile(cfg.SourceDSNFile)
	if err != nil {
		return res, err
	}
	value := strings.TrimSpace(string(dsn))
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return res, errors.New("source_file_rejected")
	}
	environmentBytes := []byte("OPEN_CARD_DATABASE_URL=" + value + "\n")
	selected, err := install.NewSelectedPostgresDatabase(environmentBytes)
	if err != nil {
		return res, errors.New("source_identity_rejected")
	}
	defer selected.Close()
	environment, err := install.PostgresEnvironment(environmentBytes)
	if err != nil {
		return res, errors.New("source_identity_rejected")
	}
	snapshot, err := selected.BeginPlatformBackupSnapshot(ctx)
	if err != nil {
		return res, errors.New("source_snapshot_failed")
	}
	snapshotClosed := false
	defer func() {
		if !snapshotClosed {
			snapshotClosed = true
			if snapshot.Rollback() != nil && retErr == nil {
				retErr = errors.New("source_snapshot_close_unknown")
			}
		}
		if res.PrivateDirectory != "" {
			if retErr != nil {
				res.Report.Status = "capture_or_projection_failed"
				res.Report.FailureCodes = append(res.Report.FailureCodes, retErr.Error())
			}
			if writePrivate(filepath.Join(res.PrivateDirectory, "report.json"), res.Report) != nil && retErr == nil {
				retErr = errors.New("report_write_failed")
			}
		}
	}()
	res.PrivateDirectory, err = os.MkdirTemp(cfg.OutputParent, "preview-")
	if err != nil {
		return res, errors.New("private_output_failed")
	}
	res.Report = Report{Status: "snapshot_import_incomplete", ActivationEligible: false, SnapshotIdentitySHA256: snapshot.DatabaseSnapshotSHA256, SequenceContinuation: "sequence_read_is_not_mvcc;allocation_floor_not_implemented;formal_cutover_requires_write_freeze"}

	snapshotter, err := install.TaskPostgresSnapshotter(cfg.DumpTool, dumpRunner{})
	if err != nil {
		return res, errors.New("dump_tool_rejected")
	}
	res.Report.Dump, err = snapshot.SnapshotWithExportedSnapshot(ctx, snapshotter, "tc1g-preview", res.PrivateDirectory, environment, nil)
	if err != nil {
		return res, errors.New("source_dump_failed")
	}
	matrix, issues, err := sourceMatrix(ctx, snapshot)
	if err != nil {
		return res, err
	}
	res.Report.SchemaVersion = matrix.Version
	res.Report.SchemaDifferences = matrix.Differences
	if len(issues) > 0 {
		res.Report.FailureCodes = append([]string{"snapshot_import_incomplete"}, issues...)
		return res, nil
	}
	res.Report.Coverage, res.Report.SequenceObservations, err = coverage(ctx, snapshot, matrix)
	if err != nil {
		return res, err
	}
	manifest := struct {
		Schema    Matrix
		Coverage  []RelationCoverage
		Sequences []SequenceObservation
		Dump      install.SnapshotEvidence
	}{matrix, res.Report.Coverage, res.Report.SequenceObservations, res.Report.Dump}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return res, errors.New("manifest_failed")
	}
	res.Report.ManifestSHA256 = digest(manifestBytes)
	if err := writePrivate(filepath.Join(res.PrivateDirectory, "manifest.json"), manifest); err != nil {
		return res, errors.New("manifest_write_failed")
	}
	diagnostic, err := openTarget(ctx, res.PrivateDirectory, res.Report.SnapshotIdentitySHA256, res.Report.ManifestSHA256)
	if err != nil {
		return res, err
	}
	defer func() {
		if diagnostic.Close() != nil && retErr == nil {
			retErr = errors.New("diagnostic_close_unknown")
		}
	}()
	res.Report.ProjectionCounts, issues, err = project(ctx, snapshot, diagnostic, interrupt)
	if err != nil {
		return res, err
	}
	if len(issues) > 0 {
		res.Report.FailureCodes = append([]string{"snapshot_import_incomplete"}, issues...)
		_, _ = diagnostic.db.ExecContext(ctx, `UPDATE diagnostic_migration_preview SET projection_status='rejected' WHERE singleton=1`)
		return res, nil
	}
	res.Report.ProjectionVerified = true
	res.Report.Status = "projection_verified_snapshot_import_incomplete"
	res.Report.FailureCodes = []string{"snapshot_import_incomplete", "nonempty_protocol_seed_unmapped", "full_history_tables_unmapped", "allocation_floor_not_implemented", "external_key_file_assets_not_captured"}
	// Close the shared exported snapshot only after dump, coverage and projection.
	snapshotClosed = true
	if err := snapshot.Rollback(); err != nil {
		return res, errors.New("source_snapshot_close_unknown")
	}
	return res, nil
}
