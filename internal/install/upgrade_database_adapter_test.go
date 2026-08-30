package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

type adapterValidationFake struct {
	got string
	err error
}

func TestInspectionOnlySessionHasNoControlIdentityDigest(t *testing.T) {
	session := newActiveInspectionSession(
		[]byte("OPEN_CARD_DATABASE_URL=postgresql://user:password@127.0.0.1:5432/open_card?sslmode=require\n"),
		[]byte("OPEN_CARD_DATABASE_URL=postgresql://user:password@127.0.0.1:5432/open_card_candidate?sslmode=require\n"),
	)
	if session.ControlIdentitySHA256() != "" {
		t.Fatal("inspection-only session exposed a control identity digest")
	}
}

func TestProductionPostgresRunnerUsesOnlyValidatedChildEnvironment(t *testing.T) {
	for key, value := range map[string]string{
		"OPEN_CARD_DATABASE_URL": "postgresql://ambient:secret@example.invalid/open_card",
		"DATABASE_URL":           "postgresql://ambient:secret@example.invalid/open_card",
		"PGPASSWORD":             "ambient-secret",
		"TENCENT_SECRET_ID":      "cloud-secret",
		"AWS_SECRET_ACCESS_KEY":  "cloud-secret",
		"HTTP_PROXY":             "http://proxy.invalid",
		"ACCESS_TOKEN":           "token-secret",
	} {
		t.Setenv(key, value)
	}
	var captured *exec.Cmd
	runner := productionPostgresRunner{command: func(ctx context.Context, path string, args ...string) *exec.Cmd {
		if path != "/usr/bin/true" || len(args) != 0 {
			t.Fatalf("argv = %q %q", path, args)
		}
		captured = exec.CommandContext(ctx, path)
		return captured
	}}
	environment, err := PostgresEnvironment([]byte("OPEN_CARD_DATABASE_URL=postgresql://user:password@127.0.0.1:5432/open_card?sslmode=require\n"))
	if err != nil {
		t.Fatal(err)
	}
	if result := runner.Run(context.Background(), []string{"/usr/bin/true"}, environment.ChildEnv); result.Err != nil || result.ExitCode != 0 {
		t.Fatalf("result = %#v", result)
	}
	if captured == nil {
		t.Fatal("command factory was not called")
	}
	want := append(append([]string(nil), productionSubprocessBaseEnv...), environment.ChildEnv...)
	if !reflect.DeepEqual(captured.Env, want) {
		t.Fatalf("child env = %q, want %q", captured.Env, want)
	}
	for _, entry := range captured.Env {
		if strings.Contains(entry, "ambient") || strings.Contains(entry, "cloud-secret") || strings.Contains(entry, "proxy.invalid") || strings.Contains(entry, "token-secret") {
			t.Fatalf("ambient value leaked into child env: %q", entry)
		}
	}
	for _, invalid := range [][]string{
		append(append([]string(nil), environment.ChildEnv...), "HTTP_PROXY=http://proxy.invalid"),
		append(append([]string(nil), environment.ChildEnv...), "PGHOST=duplicate"),
		append(append([]string(nil), environment.ChildEnv...), "PGPORT=not-a-port"),
		append(append([]string(nil), environment.ChildEnv...), "PGSSLMODE=unsafe"),
		append(append([]string(nil), environment.ChildEnv...), "malformed"),
	} {
		if result := runner.Run(context.Background(), []string{"/usr/bin/true"}, invalid); !errors.Is(result.Err, ErrPostgresOutcomeUnknown) {
			t.Fatalf("unsafe env result = %#v", result)
		}
	}
}

func TestUpgradeDatabaseAdapterCloseAttemptsAllResourcesOnce(t *testing.T) {
	writerOps := &adapterCloseOps{err: errors.New("writer close")}
	adapter := &UpgradeDatabaseAdapter{
		control: &ProductionPostgresControl{admin: &adapterDB{closeErr: errors.New("control close")}},
		plan:    UpgradeDatabasePlan{ArtifactWriter: &DurableWriter{ops: writerOps}},
	}
	if err := adapter.Close(); !errors.Is(err, ErrPostgresOutcomeUnknown) {
		t.Fatalf("close error = %v", err)
	}
	if writerOps.calls != 1 {
		t.Fatalf("writer close calls = %d", writerOps.calls)
	}
	if err := adapter.Close(); err != nil || writerOps.calls != 1 {
		t.Fatalf("second close = %v calls=%d", err, writerOps.calls)
	}
}

type adapterCloseOps struct {
	durableOps
	calls int
	err   error
}

func (o *adapterCloseOps) Close() error { o.calls++; return o.err }

type migrationLifecycleDB struct {
	adapterDB
	rowsCall int
	first    []MigrationRow
	second   []MigrationRow
}

func (d *migrationLifecycleDB) QueryContext(_ context.Context, _ string, _ ...any) (postgresRows, error) {
	d.rowsCall++
	if d.rowsCall == 1 {
		return inspectionRows(d.first), nil
	}
	return inspectionRows(d.second), nil
}

func TestUpgradeDatabaseAdapterMigrateObservesCandidateClose(t *testing.T) {
	plan, _, pg := adapterPlan(t)
	active, err := PostgresEnvironment(plan.ActiveDatabaseEnv)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := verifiedUpgradeRelease(plan)
	if err != nil {
		t.Fatal(err)
	}
	expected, _, err := migrationInput(plan.CandidateReleaseRoot, manifest)
	if err != nil {
		t.Fatal(err)
	}
	database := &migrationLifecycleDB{adapterDB: adapterDB{tx: &adapterTx{}, closeErr: errors.New("candidate close")}, first: expected[:23], second: expected}
	adapter, err := TaskUpgradeDatabaseAdapter(plan, adapterControl(active), adapterSnapshotter(t, pg))
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	adapter.candidateOpen = func(string) (*SQLMigrationControl, error) { return &SQLMigrationControl{database: database}, nil }
	if _, err := adapter.Migrate(context.Background()); !errors.Is(err, ErrPostgresOutcomeUnknown) {
		t.Fatalf("close failure was ignored: %v", err)
	}
	if database.rowsCall != 2 {
		t.Fatalf("migration did not complete before close: rows=%d", database.rowsCall)
	}

	drift := &migrationLifecycleDB{adapterDB: adapterDB{closeErr: errors.New("candidate close")}}
	adapter.candidateOpen = func(string) (*SQLMigrationControl, error) { return &SQLMigrationControl{database: drift}, nil }
	// The query returns no valid rows, so the migration error is primary and
	// must not be replaced by the close error.
	if _, err := adapter.Migrate(context.Background()); !errors.Is(err, ErrCandidateConflict) {
		t.Fatalf("primary migration failure was replaced: %v", err)
	}
}

type upgradeAdapterDB struct {
	*adapterDB
	exists   bool
	evidence string
	owner    string
}

func (d *upgradeAdapterDB) QueryRowContext(_ context.Context, query string, _ ...any) postgresRow {
	if query == WaitForNoOpenCardSessionsSQL {
		return adapterRow{values: []any{0}}
	}
	return adapterRow{values: []any{d.exists, d.evidence, d.owner}}
}

func (f *adapterValidationFake) ValidateCandidate(_ context.Context, id string) error {
	f.got = id
	return f.err
}

func adapterDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func adapterRelease(t *testing.T) (ReleaseV1, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "release-rc1")
	if err := os.MkdirAll(filepath.Join(root, "migrations/control-plane"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := make([]FileDigest, 0, 24)
	for version := 1; version <= 24; version++ {
		name := formatMigrationVersion(version) + "_upgrade.sql"
		if version == 24 {
			name = "0024_dns_change_ledger.sql"
		}
		path := filepath.Join(root, "migrations/control-plane", name)
		raw := []byte("-- migration " + formatMigrationVersion(version) + "\nSELECT " + formatMigrationVersion(version) + ";\n")
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, FileDigest{Path: "migrations/control-plane/" + name, SHA256: adapterDigest(raw), Mode: 0o644})
	}
	for path, raw := range map[string][]byte{
		"bin/open-card-admin":                                     []byte("admin\n"),
		"bin/open-card-server":                                    []byte("server\n"),
		"bin/open-card-upgrade":                                   []byte("upgrade\n"),
		"systemd/open-card-edge.service":                          []byte("edge\n"),
		"systemd/open-card-upgrade-recover.service":               ProductionUpgradeRecoveryUnitBytes(),
		"systemd/open-card-upgrade-safe.target":                   ProductionUpgradeSafeBootTargetBytes(),
		"systemd/open-card-upgrade-finalize.service":              ProductionUpgradeFinalizeUnitBytes(),
		"systemd/open-card-edge.service.d/10-upgrade-marker.conf": ProductionUpgradeEdgeMarkerDropInBytes(),
		"caddy/open-card-edge.Caddyfile.example":                  []byte("edge\n"),
		"web/dist/index.html":                                     []byte("web\n"),
		"docs/licenses/licenses-manifest.json":                    []byte("{}\n"),
		"sbom.spdx.json":                                          []byte("{}\n"),
		"source-manifest.sha256":                                  []byte("source\n"),
	} {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if path == "bin/open-card-admin" || path == "bin/open-card-server" || path == "bin/open-card-upgrade" {
			mode = 0o755
		}
		if err := os.WriteFile(full, raw, mode); err != nil {
			t.Fatal(err)
		}
		files = append(files, FileDigest{Path: path, SHA256: adapterDigest(raw), Mode: uint32(mode)})
	}
	manifest := Manifest{
		SchemaVersion:    ManifestSchemaVersion,
		Product:          ManifestProduct,
		Version:          ProductionCandidateVersion,
		ReleaseID:        "release-rc1",
		Architecture:     "amd64",
		MigrationVersion: CurrentMigrationVersion,
		SourceCommit:     strings.Repeat("a", 40),
		NMinusOne:        &NMinusOne{Version: ProductionNMinusOneVersion, MigrationVersion: "0023", SourceCommit: RC0SourceCommit, ReleaseManifestSHA256: RC0ReleaseManifestSHA256, ArchiveSHA256: RC0ArchiveSHA256, BundleManifestSHA256: RC0BundleManifestSHA256},
		Protocol:         AgentProtocolVersion,
		ConfigDir:        DefaultConfigDir,
		DataDir:          DefaultDataDir,
		Compatibility:    Compatibility{MinDataVersion: 23, MaxDataVersion: 24, MinAgentProtocol: PreviousAgentProtocol, MaxAgentProtocol: AgentProtocolVersion},
		Files:            files,
	}
	if err := SaveManifest(filepath.Join(root, "manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	digest, err := SHA256File(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	return ReleaseV1{ID: manifest.ReleaseID, Version: manifest.Version, SourceCommit: manifest.SourceCommit, Architecture: manifest.Architecture, ManifestSHA256: digest}, root
}

func adapterPlan(t *testing.T) (UpgradeDatabasePlan, *adapterValidationFake, *fakePG) {
	t.Helper()
	release, releaseRoot := adapterRelease(t)
	artifactRoot := filepath.Join(t.TempDir(), "artifacts")
	tx := "transaction-1"
	artifactDir := filepath.Join(artifactRoot, tx)
	if err := os.MkdirAll(artifactDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writer, err := TaskDurableWriter(artifactRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	backupRoot := filepath.Join(t.TempDir(), "backups")
	if err := os.MkdirAll(backupRoot, durableDirMode); err != nil {
		t.Fatal(err)
	}
	backupWriter, err := TaskDurableWriter(backupRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	activationID := "activation-new"
	candidate, err := CandidateDatabaseName(activationID)
	if err != nil {
		t.Fatal(err)
	}
	candidateEnv := []byte("OPEN_CARD_DATABASE_URL=postgresql://user:password@127.0.0.1:5432/" + candidate + "?sslmode=require\n")
	validator := &adapterValidationFake{}
	pg := &fakePG{write: func(argv []string) {
		if len(argv) > 3 && !strings.HasSuffix(argv[0], "pg_restore") {
			if err := os.WriteFile(argv[3], []byte("snapshot"), 0o600); err != nil {
				t.Fatalf("write snapshot: %v", err)
			}
		}
	}}
	return UpgradeDatabasePlan{
		TransactionID:             tx,
		ArtifactRoot:              artifactRoot,
		ArtifactDir:               artifactDir,
		BackupRoot:                backupRoot,
		BackupWriter:              backupWriter,
		ActiveDatabaseEnv:         []byte("OPEN_CARD_DATABASE_URL=postgresql://user:password@127.0.0.1:5432/open_card?sslmode=require\n"),
		CandidateDatabaseName:     candidate,
		CandidateActivationID:     activationID,
		CandidateDatabaseEnv:      candidateEnv,
		CandidateRelease:          release,
		CandidateReleaseRoot:      releaseRoot,
		CandidateRecoveryEvidence: strings.Repeat("a", 64),
		DrainInterval:             time.Millisecond,
		Validator:                 validator,
		ArtifactWriter:            writer,
	}, validator, pg
}

func adapterBackup(t *testing.T, plan UpgradeDatabasePlan, payload string) ActiveDatabaseBackupV2 {
	t.Helper()
	if plan.BackupWriter == nil {
		t.Fatal("missing task backup writer")
	}
	backupID := "backup-restore-1"
	created, err := plan.BackupWriter.CreateChildDirectory(backupID, durableDirMode)
	if err != nil || !created {
		t.Fatalf("create backup directory created=%v err=%v", created, err)
	}
	child, err := plan.BackupWriter.OpenChildWriter(backupID, durableDirMode)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	if err := child.CreateMetadata(ActiveDatabaseBackupDumpFile, []byte(payload)); err != nil {
		t.Fatal(err)
	}
	manifest, err := verifiedUpgradeRelease(plan)
	if err != nil {
		t.Fatal(err)
	}
	rows, _, err := migrationInput(plan.CandidateReleaseRoot, manifest)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := migrationEvidence(rows)
	if err != nil {
		t.Fatal(err)
	}
	metadata := ActiveDatabaseBackupV2{
		SchemaVersion:              ActiveDatabaseBackupSchemaVersion,
		BackupID:                   backupID,
		CreatedAt:                  time.Unix(1, 0).UTC(),
		Reason:                     "manual",
		SourceActivationID:         "activation-source",
		SourceActivationJSONSHA256: strings.Repeat("c", 64),
		SourceRelease:              plan.CandidateRelease,
		SourceDatabase:             DatabaseV1{Name: "open_card_source", Migration: "0024", SchemaMigrationsSHA256: evidence.RowsSHA256},
		DatabaseEnvSHA256:          strings.Repeat("d", 64),
		DumpFile:                   ActiveDatabaseBackupDumpFile,
		DumpSHA256:                 sha256Bytes([]byte(payload)),
		DumpSize:                   int64(len(payload)),
		DumpFormat:                 ActiveDatabaseBackupDumpFormat,
	}
	raw, err := MarshalActiveDatabaseBackupV2(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := child.CreateMetadata(activeDatabaseBackupMetadataName, raw); err != nil {
		t.Fatal(err)
	}
	return metadata
}

func adapterSnapshotter(t *testing.T, pg *fakePG) *PostgresSnapshotter {
	t.Helper()
	dump := filepath.Join(t.TempDir(), "pg_dump")
	restore := filepath.Join(t.TempDir(), "pg_restore")
	for _, path := range []string{dump, restore} {
		if err := os.WriteFile(path, []byte("tool"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	snapshotter, err := TaskPostgresSnapshotterWithRestore(dump, restore, pg)
	if err != nil {
		t.Fatal(err)
	}
	return snapshotter
}

func adapterControl(env PostgresProcessEnvironment) *ProductionPostgresControl {
	return &ProductionPostgresControl{admin: &upgradeAdapterDB{adapterDB: &adapterDB{}, exists: true, evidence: candidateDatabaseEvidence(strings.Repeat("a", 64)), owner: "user"}, runtimeEnv: env, runtimeRole: "user", controlIdentitySHA: strings.Repeat("b", 64)}
}

func existingAdapterControl(env PostgresProcessEnvironment) *ProductionPostgresControl {
	return &ProductionPostgresControl{admin: &upgradeAdapterDB{adapterDB: &adapterDB{}, exists: true, evidence: candidateDatabaseEvidence(strings.Repeat("a", 64)), owner: "user"}, runtimeEnv: env, runtimeRole: "user", controlIdentitySHA: strings.Repeat("b", 64)}
}

func TestUpgradeDatabaseAdapterSnapshotRestoreAndValidationAreBound(t *testing.T) {
	plan, validator, pg := adapterPlan(t)
	active, err := PostgresEnvironment(plan.ActiveDatabaseEnv)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := TaskUpgradeDatabaseAdapter(plan, adapterControl(active), adapterSnapshotter(t, pg))
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if adapter.ControlIdentitySHA256() != strings.Repeat("b", 64) {
		t.Fatal("adapter did not retain control identity digest")
	}
	if err := adapter.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot, source, err := adapter.Snapshot(context.Background())
	if err != nil || source != "open_card" || snapshot.Size == 0 || !validSHA(snapshot.SHA256) {
		t.Fatalf("snapshot=%+v source=%q err=%v", snapshot, source, err)
	}
	if err := adapter.CreateRestore(context.Background(), plan.CandidateDatabaseName); err != nil {
		t.Fatal(err)
	}
	if len(pg.argv) == 0 || !strings.Contains(strings.Join(pg.argv, "\n"), "--dbname\n"+plan.CandidateDatabaseName) || strings.Contains(strings.Join(pg.env, "\n"), "open_card\n") {
		t.Fatalf("restore argv=%v env=%v", pg.argv, pg.env)
	}
	artifact, err := adapter.Validate(context.Background(), plan.CandidateActivationID)
	if err != nil || validator.got != plan.CandidateActivationID || artifact.Path != artifactPath(plan.TransactionID, "validation.json") || !validSHA(artifact.SHA256) {
		t.Fatalf("artifact=%+v validator=%q err=%v", artifact, validator.got, err)
	}
	again, err := adapter.Validate(context.Background(), plan.CandidateActivationID)
	if err != nil || again != artifact {
		t.Fatalf("again=%+v err=%v", again, err)
	}
}

func TestUpgradeDatabaseAdapterRejectsReleaseDriftAndUnsafeArtifacts(t *testing.T) {
	plan, _, pg := adapterPlan(t)
	active, err := PostgresEnvironment(plan.ActiveDatabaseEnv)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := TaskUpgradeDatabaseAdapter(plan, adapterControl(active), adapterSnapshotter(t, pg))
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if err := os.Chmod(filepath.Join(plan.CandidateReleaseRoot, "migrations/control-plane/0024_dns_change_ledger.sql"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Migrate(context.Background()); !errors.Is(err, ErrPostgresOutcomeUnknown) {
		t.Fatalf("migration error=%v", err)
	}
	if err := os.Chmod(plan.ArtifactDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, _, err := adapter.Snapshot(context.Background()); !errors.Is(err, ErrPostgresOutcomeUnknown) {
		t.Fatalf("snapshot error=%v", err)
	}
}

func TestUpgradeDatabaseAdapterRejectsIncompleteProductionPayloadBeforeMutableWork(t *testing.T) {
	plan, _, pg := adapterPlan(t)
	if err := os.Remove(filepath.Join(plan.CandidateReleaseRoot, "web/dist/index.html")); err != nil {
		t.Fatal(err)
	}
	active, err := PostgresEnvironment(plan.ActiveDatabaseEnv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TaskUpgradeDatabaseAdapter(plan, adapterControl(active), adapterSnapshotter(t, pg)); !errors.Is(err, ErrPostgresOutcomeUnknown) {
		t.Fatalf("incomplete production release accepted: %v", err)
	}
	if len(pg.argv) != 0 {
		t.Fatalf("mutable postgres tool invoked before release validation: %v", pg.argv)
	}
	plan, _, pg = adapterPlan(t)
	plan.CandidateRelease.Version = ProductionNMinusOneVersion
	active, err = PostgresEnvironment(plan.ActiveDatabaseEnv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TaskUpgradeDatabaseAdapter(plan, adapterControl(active), adapterSnapshotter(t, pg)); !errors.Is(err, ErrPostgresOutcomeUnknown) {
		t.Fatalf("wrong production tuple accepted: %v", err)
	}
	if len(pg.argv) != 0 {
		t.Fatalf("mutable postgres tool invoked for wrong tuple: %v", pg.argv)
	}
}

func TestUpgradeDatabaseAdapterRejectsBadPlanAndDoesNotExposeSecrets(t *testing.T) {
	plan, _, pg := adapterPlan(t)
	active, err := PostgresEnvironment(plan.ActiveDatabaseEnv)
	if err != nil {
		t.Fatal(err)
	}
	plan.CandidateDatabaseEnv = append([]byte(nil), plan.ActiveDatabaseEnv...)
	if _, err := TaskUpgradeDatabaseAdapter(plan, adapterControl(active), adapterSnapshotter(t, pg)); !errors.Is(err, ErrPostgresOutcomeUnknown) {
		t.Fatalf("err=%v", err)
	}
	if strings.Contains(string(plan.CandidateDatabaseEnv), "password") && strings.Contains(ErrPostgresOutcomeUnknown.Error(), "password") {
		t.Fatal("secret leaked through adapter error")
	}
}

func TestUpgradeDatabaseAdapterRestoresKnownExistingCandidateAndRejectsReleaseSymlink(t *testing.T) {
	plan, _, pg := adapterPlan(t)
	active, err := PostgresEnvironment(plan.ActiveDatabaseEnv)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := TaskUpgradeDatabaseAdapter(plan, existingAdapterControl(active), adapterSnapshotter(t, pg))
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if _, _, err := adapter.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := adapter.CreateRestore(context.Background(), plan.CandidateDatabaseName); err != nil {
		t.Fatalf("known candidate recovery: %v", err)
	}
	if len(pg.argv) == 0 || !strings.Contains(strings.Join(pg.argv, " "), "--exit-on-error") {
		t.Fatalf("restore not invoked: %v", pg.argv)
	}
	if err := os.Remove(filepath.Join(plan.CandidateReleaseRoot, "migrations/control-plane/0001_upgrade.sql")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("0024_upgrade.sql", filepath.Join(plan.CandidateReleaseRoot, "migrations/control-plane/0001_upgrade.sql")); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Migrate(context.Background()); !errors.Is(err, ErrPostgresOutcomeUnknown) {
		t.Fatalf("symlink migration error=%v", err)
	}
	if source, err := os.ReadFile("upgrade_database_adapter.go"); err == nil && strings.Contains(strings.ToLower(string(source)), "drop database") {
		t.Fatal("adapter must not add a candidate-drop path")
	}
}

func TestUpgradeDatabaseAdapterRestoresVerifiedBackupIntoCandidateArtifact(t *testing.T) {
	plan, _, pg := adapterPlan(t)
	backup := adapterBackup(t, plan, "custom-backup")
	sourceDump, err := ActiveDatabaseBackupDumpPath(plan.BackupRoot, backup.BackupID)
	if err != nil {
		t.Fatal(err)
	}
	// The source can change after the no-follow read/copy. pg_restore must use
	// the transaction artifact, not re-open the backup path.
	pg.write = func(argv []string) {
		if strings.HasSuffix(argv[0], "pg_restore") {
			if err := os.WriteFile(sourceDump, []byte("mutated-after-copy"), durableFileMode); err != nil {
				t.Fatal(err)
			}
		}
	}
	active, err := PostgresEnvironment(plan.ActiveDatabaseEnv)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := TaskUpgradeDatabaseAdapter(plan, adapterControl(active), adapterSnapshotter(t, pg))
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	snapshot, err := adapter.PrepareBackupSnapshot(context.Background(), backup)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot != (SnapshotEvidence{SHA256: backup.DumpSHA256, Size: backup.DumpSize}) || len(pg.argv) != 0 {
		t.Fatalf("snapshot=%+v candidate argv=%q", snapshot, pg.argv)
	}
	if err := adapter.CreateRestore(context.Background(), plan.CandidateDatabaseName); err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(plan.ArtifactDir, ActiveDatabaseBackupDumpFile)
	artifact, err := os.ReadFile(artifactPath)
	if err != nil || string(artifact) != "custom-backup" {
		t.Fatalf("artifact=%q err=%v", artifact, err)
	}
	info, err := os.Lstat(artifactPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != durableFileMode {
		t.Fatalf("artifact mode=%v err=%v", info.Mode(), err)
	}
	if strings.Contains(strings.Join(pg.argv, "\n"), "password") || strings.Contains(strings.Join(pg.argv, "\n"), "open_card\n") || !strings.Contains(strings.Join(pg.argv, "\n"), "--dbname\n"+plan.CandidateDatabaseName) {
		t.Fatalf("unsafe restore argv=%q", pg.argv)
	}
	if strings.Contains(strings.Join(pg.env, "\n"), "OPEN_CARD_DATABASE_URL") || strings.Contains(strings.Join(pg.env, "\n"), "PGDATABASE=open_card\n") {
		t.Fatalf("unsafe restore env=%q", pg.env)
	}
	rowsManifest, _, err := migrationInput(plan.CandidateReleaseRoot, mustVerifiedUpgradeRelease(t, plan))
	if err != nil {
		t.Fatal(err)
	}
	inspectDB := &adapterDB{rows: inspectionRows(rowsManifest)}
	adapter.candidateOpen = func(name string) (*SQLMigrationControl, error) {
		if name != plan.CandidateDatabaseName {
			t.Fatalf("candidate=%q", name)
		}
		return &SQLMigrationControl{database: inspectDB}, nil
	}
	evidence, err := adapter.InspectBackupRestoredCandidate(context.Background(), backup)
	if err != nil || evidence.From != "0024" || evidence.To != "0024" || evidence.RowsSHA256 != backup.SourceDatabase.SchemaMigrationsSHA256 || evidence.ReleaseManifestSHA256 != plan.CandidateRelease.ManifestSHA256 || inspectDB.exec != "" {
		t.Fatalf("evidence=%+v exec=%q err=%v", evidence, inspectDB.exec, err)
	}
}

func TestUpgradeDatabaseAdapterBackupRestoreReplayAndRejectsBackupIdentityDrift(t *testing.T) {
	t.Run("exact-replay", func(t *testing.T) {
		plan, _, pg := adapterPlan(t)
		backup := adapterBackup(t, plan, "custom-backup")
		active, err := PostgresEnvironment(plan.ActiveDatabaseEnv)
		if err != nil {
			t.Fatal(err)
		}
		adapter, err := TaskUpgradeDatabaseAdapter(plan, adapterControl(active), adapterSnapshotter(t, pg))
		if err != nil {
			t.Fatal(err)
		}
		defer adapter.Close()
		first, err := adapter.PrepareBackupSnapshot(context.Background(), backup)
		if err != nil {
			t.Fatal(err)
		}
		second, err := adapter.PrepareBackupSnapshot(context.Background(), backup)
		if err != nil || second != first {
			t.Fatalf("second=%+v first=%+v err=%v", second, first, err)
		}
	})
	for name, mutate := range map[string]func(*ActiveDatabaseBackupV2){
		"release":     func(b *ActiveDatabaseBackupV2) { b.SourceRelease.SourceCommit = strings.Repeat("f", 40) },
		"database":    func(b *ActiveDatabaseBackupV2) { b.SourceDatabase.Name = "open_card_other" },
		"dump-digest": func(b *ActiveDatabaseBackupV2) { b.DumpSHA256 = strings.Repeat("e", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			plan, _, pg := adapterPlan(t)
			backup := adapterBackup(t, plan, "custom-backup")
			mutate(&backup)
			active, err := PostgresEnvironment(plan.ActiveDatabaseEnv)
			if err != nil {
				t.Fatal(err)
			}
			adapter, err := TaskUpgradeDatabaseAdapter(plan, adapterControl(active), adapterSnapshotter(t, pg))
			if err != nil {
				t.Fatal(err)
			}
			defer adapter.Close()
			if _, err := adapter.PrepareBackupSnapshot(context.Background(), backup); !errors.Is(err, ErrCandidateConflict) {
				t.Fatalf("restore error=%v", err)
			}
			if len(pg.argv) != 0 {
				t.Fatalf("restore tool ran for mismatched backup identity: %v", pg.argv)
			}
		})
	}
	t.Run("dump-mutated", func(t *testing.T) {
		plan, _, pg := adapterPlan(t)
		backup := adapterBackup(t, plan, "custom-backup")
		dump, err := ActiveDatabaseBackupDumpPath(plan.BackupRoot, backup.BackupID)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dump, []byte("tampered"), durableFileMode); err != nil {
			t.Fatal(err)
		}
		active, err := PostgresEnvironment(plan.ActiveDatabaseEnv)
		if err != nil {
			t.Fatal(err)
		}
		adapter, err := TaskUpgradeDatabaseAdapter(plan, adapterControl(active), adapterSnapshotter(t, pg))
		if err != nil {
			t.Fatal(err)
		}
		defer adapter.Close()
		if _, err := adapter.PrepareBackupSnapshot(context.Background(), backup); !errors.Is(err, ErrCandidateConflict) {
			t.Fatalf("restore error=%v", err)
		}
	})
	for name, corrupt := range map[string]func(t *testing.T, dump string){
		"mode": func(t *testing.T, dump string) {
			if err := os.Chmod(dump, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, dump string) {
			if err := os.Remove(dump); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("elsewhere", dump); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run("unsafe-"+name, func(t *testing.T) {
			plan, _, pg := adapterPlan(t)
			backup := adapterBackup(t, plan, "custom-backup")
			dump, err := ActiveDatabaseBackupDumpPath(plan.BackupRoot, backup.BackupID)
			if err != nil {
				t.Fatal(err)
			}
			corrupt(t, dump)
			active, err := PostgresEnvironment(plan.ActiveDatabaseEnv)
			if err != nil {
				t.Fatal(err)
			}
			adapter, err := TaskUpgradeDatabaseAdapter(plan, adapterControl(active), adapterSnapshotter(t, pg))
			if err != nil {
				t.Fatal(err)
			}
			defer adapter.Close()
			if _, err := adapter.PrepareBackupSnapshot(context.Background(), backup); !errors.Is(err, ErrPostgresOutcomeUnknown) {
				t.Fatalf("restore error=%v", err)
			}
			if len(pg.argv) != 0 {
				t.Fatalf("restore tool ran for unsafe dump: %v", pg.argv)
			}
		})
	}
}

func TestUpgradeDatabaseAdapterBackupRestoreFailsClosed(t *testing.T) {
	t.Run("restore-unknown", func(t *testing.T) {
		plan, _, pg := adapterPlan(t)
		backup := adapterBackup(t, plan, "custom-backup")
		pg.result = PostgresRunResult{ExitCode: 1, Err: errors.New("restore failed: password=never-log")}
		active, err := PostgresEnvironment(plan.ActiveDatabaseEnv)
		if err != nil {
			t.Fatal(err)
		}
		adapter, err := TaskUpgradeDatabaseAdapter(plan, adapterControl(active), adapterSnapshotter(t, pg))
		if err != nil {
			t.Fatal(err)
		}
		defer adapter.Close()
		if _, err = adapter.PrepareBackupSnapshot(context.Background(), backup); err != nil {
			t.Fatalf("prepare error=%v", err)
		}
		err = adapter.CreateRestore(context.Background(), plan.CandidateDatabaseName)
		if !errors.Is(err, ErrPostgresOutcomeUnknown) || strings.Contains(err.Error(), "password") {
			t.Fatalf("restore error=%v", err)
		}
		if _, err := os.Stat(filepath.Join(plan.ArtifactDir, ActiveDatabaseBackupDumpFile)); err != nil {
			t.Fatalf("copied artifact missing after restore uncertainty: %v", err)
		}
	})
	t.Run("schema-drift", func(t *testing.T) {
		plan, _, pg := adapterPlan(t)
		backup := adapterBackup(t, plan, "custom-backup")
		active, err := PostgresEnvironment(plan.ActiveDatabaseEnv)
		if err != nil {
			t.Fatal(err)
		}
		adapter, err := TaskUpgradeDatabaseAdapter(plan, adapterControl(active), adapterSnapshotter(t, pg))
		if err != nil {
			t.Fatal(err)
		}
		defer adapter.Close()
		adapter.candidateOpen = func(string) (*SQLMigrationControl, error) {
			return &SQLMigrationControl{database: &adapterDB{rows: inspectionRows(migrationRows(23))}}, nil
		}
		if _, err := adapter.InspectBackupRestoredCandidate(context.Background(), backup); !errors.Is(err, ErrCandidateConflict) {
			t.Fatalf("schema drift error=%v", err)
		}
	})
}

func mustVerifiedUpgradeRelease(t *testing.T, plan UpgradeDatabasePlan) Manifest {
	t.Helper()
	manifest, err := verifiedUpgradeRelease(plan)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

type candidateProcessFake struct {
	wait    chan error
	signals []os.Signal
}

func (p *candidateProcessFake) Signal(signal os.Signal) error {
	p.signals = append(p.signals, signal)
	select {
	case p.wait <- nil:
	default:
	}
	return nil
}
func (p *candidateProcessFake) Wait() error { return <-p.wait }

func candidatePrivilegeSeams() (func(string) (*user.User, error), func(string) error, func() int) {
	return func(name string) (*user.User, error) {
			if name != productionCandidateRuntimeUser {
				return nil, errors.New("unexpected user")
			}
			return &user.User{Uid: "123", Gid: "456", Username: productionCandidateRuntimeUser}, nil
		}, func(path string) error {
			if path != productionCandidatePrivilegeDropPath {
				return errors.New("unexpected setpriv")
			}
			return nil
		}, func() int { return 0 }
}

func TestProductionCandidateValidatorUsesFD3AndSafeInvocation(t *testing.T) {
	process := &candidateProcessFake{wait: make(chan error, 1)}
	var serverPath string
	var serverArgs, serverEnv, probeTargets, adminArgs, adminEnv []string
	var adminPath string
	lookup, verify, euid := candidatePrivilegeSeams()
	validator := productionCandidateValidator{
		adminPath:        "/opt/open-card/releases/release-rc1/bin/open-card-admin",
		serverPath:       "/opt/open-card/releases/release-rc1/bin/open-card-server",
		releaseID:        "release-rc1",
		setprivPath:      productionCandidatePrivilegeDropPath,
		lookupUser:       lookup,
		verifyExecutable: verify,
		effectiveUID:     euid,
		resolve: func(id string) (ActiveDatabase, error) {
			return ActiveDatabase{Activation: ActivationV1{ActivationID: id, Release: ReleaseV1{ID: "release-rc1"}}, DatabaseURL: "postgresql://candidate:never-log-this@127.0.0.1:5432/open_card_candidate?sslmode=require"}, nil
		},
		start: func(_ context.Context, path string, args, env []string, fd *os.File) (candidateServerProcess, error) {
			if fd == nil || fd.Fd() < 3 {
				t.Fatal("candidate listener FD was not inherited")
			}
			serverPath, serverArgs, serverEnv = path, append([]string(nil), args...), append([]string(nil), env...)
			return process, nil
		},
		probe: func(_ context.Context, target string) error {
			probeTargets = append(probeTargets, target)
			return nil
		},
		runAdmin: func(_ context.Context, path string, args, env []string) error {
			adminPath, adminArgs, adminEnv = path, append([]string(nil), args...), append([]string(nil), env...)
			return nil
		},
		probeTimeout:       time.Second,
		terminationTimeout: time.Second,
	}
	if err := validator.ValidateCandidate(context.Background(), "activation-new"); err != nil {
		t.Fatal(err)
	}
	if serverPath != productionCandidatePrivilegeDropPath || !reflect.DeepEqual(serverArgs, []string{"--reuid=123", "--regid=456", "--clear-groups", "--", validator.serverPath, "--candidate-validate"}) || adminPath != validator.adminPath || !reflect.DeepEqual(adminArgs, []string{"candidate", "validate", "--activation-id", "activation-new"}) || !reflect.DeepEqual(adminEnv, productionSubprocessBaseEnv) || len(probeTargets) != 2 || !strings.HasSuffix(probeTargets[0], "/healthz") || !strings.HasSuffix(probeTargets[1], "/readyz") || !reflect.DeepEqual(process.signals, []os.Signal{syscall.SIGTERM}) {
		t.Fatalf("server=%q %v admin=%q %v probes=%v signals=%v", serverPath, serverArgs, adminPath, adminArgs, probeTargets, process.signals)
	}
	joined := strings.Join(append(append([]string(nil), serverArgs...), serverEnv...), "\n")
	for _, forbidden := range []string{"PGPASSWORD=", "PGHOST=", "OPEN_CARD_AGENT_GATEWAY_ADDR", "OPEN_CARD_AUTH_ORIGIN", "HTTP_PROXY", "TENCENT", "AWS_"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("candidate server leaked forbidden environment %q: %v", forbidden, serverEnv)
		}
	}
	if !strings.Contains(strings.Join(serverEnv, "\n"), "OPEN_CARD_DATABASE_URL=postgresql://candidate:never-log-this") || !strings.Contains(strings.Join(serverEnv, "\n"), "OPEN_CARD_CANDIDATE_LISTEN_FD=3") || !strings.Contains(strings.Join(serverEnv, "\n"), "OPEN_CARD_M6_ENABLED=false") {
		t.Fatalf("candidate environment is incomplete: %v", serverEnv)
	}
}

func candidateValidatorForFailure(process *candidateProcessFake) productionCandidateValidator {
	lookup, verify, euid := candidatePrivilegeSeams()
	return productionCandidateValidator{
		adminPath:        "/opt/open-card/releases/release-rc1/bin/open-card-admin",
		serverPath:       "/opt/open-card/releases/release-rc1/bin/open-card-server",
		releaseID:        "release-rc1",
		setprivPath:      productionCandidatePrivilegeDropPath,
		lookupUser:       lookup,
		verifyExecutable: verify,
		effectiveUID:     euid,
		resolve: func(id string) (ActiveDatabase, error) {
			return ActiveDatabase{Activation: ActivationV1{ActivationID: id, Release: ReleaseV1{ID: "release-rc1"}}, DatabaseURL: "postgresql://candidate:never-log-this@127.0.0.1:5432/open_card_candidate?sslmode=require"}, nil
		},
		start: func(_ context.Context, _ string, _ []string, _ []string, _ *os.File) (candidateServerProcess, error) {
			return process, nil
		},
		probeTimeout:       100 * time.Millisecond,
		terminationTimeout: time.Second,
	}
}

func TestProductionCandidateValidatorFailsClosedAndCleansProcess(t *testing.T) {
	t.Run("nonroot cannot launch candidate server", func(t *testing.T) {
		process := &candidateProcessFake{wait: make(chan error, 1)}
		validator := candidateValidatorForFailure(process)
		started := false
		validator.effectiveUID = func() int { return 501 }
		validator.start = func(context.Context, string, []string, []string, *os.File) (candidateServerProcess, error) {
			started = true
			return process, nil
		}
		if err := validator.ValidateCandidate(context.Background(), "activation-new"); !errors.Is(err, ErrPostgresOutcomeUnknown) || started {
			t.Fatalf("nonroot launch result=%v started=%v", err, started)
		}
	})
	t.Run("server exits before health", func(t *testing.T) {
		process := &candidateProcessFake{wait: make(chan error, 1)}
		process.wait <- errors.New("candidate exited")
		validator := candidateValidatorForFailure(process)
		validator.probe = func(context.Context, string) error { return ErrPostgresOutcomeUnknown }
		if err := validator.ValidateCandidate(context.Background(), "activation-new"); !errors.Is(err, ErrPostgresOutcomeUnknown) || len(process.signals) != 0 {
			t.Fatalf("early exit result=%v signals=%v", err, process.signals)
		}
	})
	t.Run("admin failure terminates candidate", func(t *testing.T) {
		process := &candidateProcessFake{wait: make(chan error, 1)}
		validator := candidateValidatorForFailure(process)
		validator.probe = func(context.Context, string) error { return nil }
		validator.runAdmin = func(context.Context, string, []string, []string) error {
			return errors.New("postgresql://candidate:never-log-this")
		}
		if err := validator.ValidateCandidate(context.Background(), "activation-new"); !errors.Is(err, ErrPostgresOutcomeUnknown) || !reflect.DeepEqual(process.signals, []os.Signal{syscall.SIGTERM}) || strings.Contains(err.Error(), "never-log-this") {
			t.Fatalf("admin failure result=%v signals=%v", err, process.signals)
		}
	})
	t.Run("cancelled probe terminates candidate", func(t *testing.T) {
		process := &candidateProcessFake{wait: make(chan error, 1)}
		validator := candidateValidatorForFailure(process)
		validator.probe = func(context.Context, string) error { return ErrPostgresOutcomeUnknown }
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := validator.ValidateCandidate(ctx, "activation-new"); !errors.Is(err, ErrPostgresOutcomeUnknown) || !reflect.DeepEqual(process.signals, []os.Signal{syscall.SIGTERM}) {
			t.Fatalf("cancel result=%v signals=%v", err, process.signals)
		}
	})
}

func TestProductionCandidateValidatorRequiresManifestBoundServerAndAdmin(t *testing.T) {
	release, root := adapterRelease(t)
	manifest, err := LoadManifest(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	validator := productionCandidateValidator{
		adminPath:  filepath.Join(root, "bin/open-card-admin"),
		serverPath: filepath.Join(root, "bin/open-card-server"),
		releaseID:  release.ID,
	}
	if !verifiedProductionValidator(root, manifest, validator) {
		t.Fatal("manifest-bound candidate executables were rejected")
	}
	if err := os.WriteFile(validator.serverPath, []byte("tampered\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if verifiedProductionValidator(root, manifest, validator) {
		t.Fatal("tampered candidate server was accepted")
	}
}

type inspectionDB struct {
	*adapterDB
	closes int
}

func (d *inspectionDB) Close() error {
	d.closes++
	return d.closeErr
}

func inspectionRows(rows []MigrationRow) *adapterRows {
	values := make([][]any, len(rows))
	for index, row := range rows {
		values[index] = []any{row.Version, row.Checksum}
	}
	return &adapterRows{rows: values}
}

func inspectionAdapter(t *testing.T, database postgresDB, factoryErr error) (*UpgradeDatabaseAdapter, UpgradeDatabasePlan, *int) {
	t.Helper()
	plan, _, pg := adapterPlan(t)
	active, err := PostgresEnvironment(plan.ActiveDatabaseEnv)
	if err != nil {
		t.Fatal(err)
	}
	opens := 0
	factory := ActiveDatabaseInspectionFactory(func([]byte) (*SelectedPostgresDatabase, error) {
		opens++
		if factoryErr != nil {
			return nil, factoryErr
		}
		return &SelectedPostgresDatabase{database: database}, nil
	})
	adapter, err := TaskUpgradeDatabaseAdapter(plan, adapterControl(active), adapterSnapshotter(t, pg), factory)
	if err != nil {
		t.Fatal(err)
	}
	return adapter, plan, &opens
}

func inspectionRequest(env []byte, expected string) ActiveDatabaseInspectionRequest {
	return ActiveDatabaseInspectionRequest{DatabaseEnv: env, ExpectedMigration: "0023", ExpectedRowsSHA256: expected, ExpectedRowCount: 23}
}

func TestUpgradeDatabaseAdapterInspectActiveExactRowsAndStableInvocation(t *testing.T) {
	rows := migrationRows(23)
	database := &inspectionDB{adapterDB: &adapterDB{rows: inspectionRows(rows)}}
	adapter, plan, opens := inspectionAdapter(t, database, nil)
	defer adapter.Close()
	expected := migrationDigest(rows)
	request := inspectionRequest(plan.ActiveDatabaseEnv, expected)
	first, err := adapter.InspectActive(context.Background(), request)
	if err != nil || first != (DatabaseV1{Name: "open_card", Migration: "0023", SchemaMigrationsSHA256: expected}) || database.query != "SELECT version, checksum FROM schema_migrations ORDER BY version" || database.closes != 1 {
		t.Fatalf("database=%+v err=%v query=%q closes=%d", first, err, database.query, database.closes)
	}
	database.rows = inspectionRows(rows)
	second, err := adapter.InspectActive(context.Background(), request)
	if err != nil || second != first || *opens != 2 || database.closes != 2 {
		t.Fatalf("second=%+v err=%v opens=%d closes=%d", second, err, *opens, database.closes)
	}
	_ = plan
}

func TestUpgradeDatabaseAdapterInspectActiveSupportsRC1Rows(t *testing.T) {
	rows := migrationRows(24)
	database := &inspectionDB{adapterDB: &adapterDB{rows: inspectionRows(rows)}}
	adapter, plan, _ := inspectionAdapter(t, database, nil)
	defer adapter.Close()
	request := ActiveDatabaseInspectionRequest{DatabaseEnv: plan.ActiveDatabaseEnv, ExpectedMigration: "0024", ExpectedRowsSHA256: migrationDigest(rows), ExpectedRowCount: 24}
	got, err := adapter.InspectActive(context.Background(), request)
	if err != nil || got != (DatabaseV1{Name: "open_card", Migration: "0024", SchemaMigrationsSHA256: migrationDigest(rows)}) {
		t.Fatalf("database=%+v err=%v", got, err)
	}
}

func TestCandidateDatabaseEnvPreservesEncodedAuthorityAndTLS(t *testing.T) {
	active := []byte("OPEN_CARD_DATABASE_URL=postgresql://us%40er:p%2Fass@db.example:5544/open_card?sslmode=verify-full&application_name=open-card\n")
	candidate, err := CandidateDatabaseName("activation-new")
	if err != nil {
		t.Fatal(err)
	}
	got, err := CandidateDatabaseEnv(active, candidate)
	if err != nil {
		t.Fatal(err)
	}
	dsn, err := ParseDatabaseEnv(got)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dsn, "us%40er:p%2Fass@db.example:5544/") || !strings.Contains(dsn, "sslmode=verify-full") || !strings.Contains(dsn, "application_name=open-card") || !strings.Contains(dsn, "/"+candidate) {
		t.Fatalf("candidate DSN lost authority/query semantics: %q", dsn)
	}
}

func TestUpgradeDatabaseAdapterInspectActiveBindsExactPlanEnvironment(t *testing.T) {
	rows := migrationRows(23)
	database := &inspectionDB{adapterDB: &adapterDB{rows: inspectionRows(rows)}}
	adapter, plan, opens := inspectionAdapter(t, database, nil)
	defer adapter.Close()
	foreign := []byte("OPEN_CARD_DATABASE_URL=postgresql://user:password@127.0.0.1:5432/open_card_active?sslmode=require\n")
	if _, err := adapter.InspectActive(context.Background(), inspectionRequest(foreign, migrationDigest(rows))); !errors.Is(err, ErrPostgresOutcomeUnknown) || *opens != 0 {
		t.Fatalf("foreign request err=%v opens=%d", err, *opens)
	}
	encoded := []byte("OPEN_CARD_DATABASE_URL=postgresql://us%40er:p%2Fass@127.0.0.1:5432/open_card?sslmode=require\n")
	plan.ActiveDatabaseEnv = encoded
	active, err := PostgresEnvironment(encoded)
	if err != nil {
		t.Fatal(err)
	}
	opens = new(int)
	factory := ActiveDatabaseInspectionFactory(func(raw []byte) (*SelectedPostgresDatabase, error) {
		*opens = *opens + 1
		if string(raw) != string(encoded) {
			t.Fatal("inspection opener received a different environment")
		}
		return &SelectedPostgresDatabase{database: database}, nil
	})
	bound, err := TaskUpgradeDatabaseAdapter(plan, adapterControl(active), adapterSnapshotter(t, &fakePG{}), factory)
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	got, err := bound.InspectActive(context.Background(), inspectionRequest(encoded, migrationDigest(rows)))
	if err != nil || got.Name != "open_card" || *opens != 1 {
		t.Fatalf("inspection=%+v err=%v opens=%d", got, err, *opens)
	}
}

func TestUpgradeDatabaseAdapterInspectActiveRejectsDrift(t *testing.T) {
	base := migrationRows(23)
	cases := []struct {
		name string
		rows []MigrationRow
	}{
		{name: "missing", rows: base[:22]},
		{name: "extra", rows: append(append([]MigrationRow(nil), base...), MigrationRow{Version: "0024", Checksum: strings.Repeat("a", 64)})},
		{name: "reordered", rows: func() []MigrationRow {
			rows := append([]MigrationRow(nil), base...)
			rows[0], rows[1] = rows[1], rows[0]
			return rows
		}()},
		{name: "duplicate", rows: func() []MigrationRow {
			rows := append([]MigrationRow(nil), base...)
			rows[1].Version = rows[0].Version
			return rows
		}()},
		{name: "checksum", rows: func() []MigrationRow {
			rows := append([]MigrationRow(nil), base...)
			rows[4].Checksum = strings.Repeat("b", 64)
			return rows
		}()},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			database := &inspectionDB{adapterDB: &adapterDB{rows: inspectionRows(test.rows)}}
			adapter, plan, _ := inspectionAdapter(t, database, nil)
			defer adapter.Close()
			if _, err := adapter.InspectActive(context.Background(), inspectionRequest(plan.ActiveDatabaseEnv, migrationDigest(base))); err == nil || strings.Contains(err.Error(), "password") {
				t.Fatalf("err=%v", err)
			}
		})
	}
	database := &inspectionDB{adapterDB: &adapterDB{rows: inspectionRows(base)}}
	adapter, plan, _ := inspectionAdapter(t, database, nil)
	defer adapter.Close()
	if _, err := adapter.InspectActive(context.Background(), inspectionRequest(plan.ActiveDatabaseEnv, strings.Repeat("f", 64))); !errors.Is(err, ErrCandidateConflict) {
		t.Fatalf("wrong expected err=%v", err)
	}
	if _, err := adapter.InspectActive(context.Background(), ActiveDatabaseInspectionRequest{DatabaseEnv: plan.ActiveDatabaseEnv, ExpectedMigration: "0024", ExpectedRowsSHA256: migrationDigest(base), ExpectedRowCount: 24}); !errors.Is(err, ErrPostgresOutcomeUnknown) {
		t.Fatalf("wrong migration err=%v", err)
	}
}

func TestUpgradeDatabaseAdapterInspectActiveRedactsFailuresAndRequestJSON(t *testing.T) {
	secretEnv := []byte("OPEN_CARD_DATABASE_URL=postgresql://user:password@127.0.0.1:5432/open_card?sslmode=require\n")
	request := inspectionRequest(secretEnv, migrationDigest(migrationRows(23)))
	raw, err := json.Marshal(request)
	if err != nil || strings.Contains(string(raw), "postgresql") || strings.Contains(string(raw), "database_env") {
		t.Fatalf("request JSON=%s err=%v", raw, err)
	}
	for _, test := range []struct {
		name       string
		database   postgresDB
		factoryErr error
	}{
		{name: "open", factoryErr: errors.New("postgresql://password-secret")},
		{name: "query", database: &inspectionDB{adapterDB: &adapterDB{queryErr: errors.New("password-secret")}}},
		{name: "close", database: &inspectionDB{adapterDB: &adapterDB{rows: inspectionRows(migrationRows(23)), closeErr: errors.New("password-secret")}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter, plan, _ := inspectionAdapter(t, test.database, test.factoryErr)
			defer adapter.Close()
			_, err := adapter.InspectActive(context.Background(), inspectionRequest(plan.ActiveDatabaseEnv, migrationDigest(migrationRows(23))))
			if !errors.Is(err, ErrPostgresOutcomeUnknown) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
