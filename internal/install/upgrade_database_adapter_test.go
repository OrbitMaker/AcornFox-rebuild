package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type adapterValidationFake struct {
	got string
	err error
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
}

func (d *upgradeAdapterDB) QueryRowContext(_ context.Context, query string, _ ...any) postgresRow {
	if query == WaitForNoOpenCardSessionsSQL {
		return adapterRow{values: []any{0}}
	}
	return adapterRow{values: []any{d.exists, d.evidence}}
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
		if path == "bin/open-card-admin" || path == "bin/open-card-upgrade" {
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
	return &ProductionPostgresControl{admin: &upgradeAdapterDB{adapterDB: &adapterDB{}}, environment: env}
}

func existingAdapterControl(env PostgresProcessEnvironment) *ProductionPostgresControl {
	return &ProductionPostgresControl{admin: &upgradeAdapterDB{adapterDB: &adapterDB{}, exists: true, evidence: candidateDatabaseEvidence(strings.Repeat("a", 64))}, environment: env}
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

func TestProductionCandidateValidatorUsesFixedSafeInvocation(t *testing.T) {
	var path string
	var args, env []string
	validator := productionCandidateValidator{path: "/opt/open-card/releases/release-rc1/bin/open-card-admin", run: func(_ context.Context, gotPath string, gotArgs, gotEnv []string) error {
		path, args, env = gotPath, append([]string(nil), gotArgs...), append([]string(nil), gotEnv...)
		return nil
	}}
	if err := validator.ValidateCandidate(context.Background(), "activation-new"); err != nil {
		t.Fatal(err)
	}
	if path != "/opt/open-card/releases/release-rc1/bin/open-card-admin" || strings.Join(args, " ") != "candidate validate --activation-id activation-new" || !reflect.DeepEqual(env, productionSubprocessBaseEnv) || strings.Contains(strings.Join(args, "\n")+strings.Join(env, "\n"), "postgres") {
		t.Fatalf("path=%q args=%v env=%v", path, args, env)
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
