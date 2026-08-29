package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type adapterValidationFake struct {
	got string
	err error
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
		path := filepath.Join(root, "migrations/control-plane", name)
		raw := []byte("-- migration " + formatMigrationVersion(version) + "\nSELECT " + formatMigrationVersion(version) + ";\n")
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, FileDigest{Path: "migrations/control-plane/" + name, SHA256: adapterDigest(raw), Mode: 0o644})
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
	if err := os.Chmod(filepath.Join(plan.CandidateReleaseRoot, "migrations/control-plane/0024_upgrade.sql"), 0o600); err != nil {
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
	if path != "/opt/open-card/releases/release-rc1/bin/open-card-admin" || strings.Join(args, " ") != "candidate validate --activation-id activation-new" || strings.Join(env, "\n") != "PATH=/usr/bin:/bin" || strings.Contains(strings.Join(args, "\n")+strings.Join(env, "\n"), "postgres") {
		t.Fatalf("path=%q args=%v env=%v", path, args, env)
	}
}
