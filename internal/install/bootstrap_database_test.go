package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type bootstrapCandidateFake struct {
	exists          bool
	evidence, owner string
	created         string
	createCalls     int
	createErr       error
}

func (f *bootstrapCandidateFake) CandidateEvidence(_ context.Context, _ string) (CandidateDatabaseIdentity, error) {
	return CandidateDatabaseIdentity{Exists: f.exists, Evidence: f.evidence, Owner: f.owner}, nil
}
func (f *bootstrapCandidateFake) CreateCandidate(_ context.Context, name, evidence string) error {
	f.createCalls++
	if f.createErr != nil {
		return f.createErr
	}
	f.created, f.exists, f.owner, f.evidence = name, true, "opencard", candidateDatabaseEvidence(evidence)
	return nil
}

func TestBootstrapDatabasePersistsCreateBeforeMigration(t *testing.T) {
	release, root := bootstrapRC2Release(t)
	migrations, err := LoadTaskBootstrapMigrations(root, os.Getuid(), os.Getgid(), release)
	if err != nil {
		t.Fatal(err)
	}
	candidateControl := &bootstrapCandidateFake{}
	ledger := &bootstrapLedgerFake{}
	service, err := TaskBootstrapDatabase(bootstrapInput(release), bootstrapRuntimeEnv(t), strings.Repeat("c", 64), candidateControl, "opencard", func(string) (BootstrapMigrationControl, error) { return ledger, nil }, func() (BootstrapMigrations, error) { return migrations, nil })
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := service.Create(context.Background())
	if err != nil || candidateControl.createCalls != 1 || !candidateControl.exists || len(ledger.rows) != 0 || len(ledger.lastSQL) != 0 {
		t.Fatalf("create boundary candidate=%+v control=%+v rows=%d sql=%d err=%v", candidate, candidateControl, len(ledger.rows), len(ledger.lastSQL), err)
	}
	encoded, err := json.Marshal(candidate)
	if err != nil || strings.Contains(string(encoded), "postgresql://") || strings.Contains(string(encoded), "bootstrap-password-sentinel") {
		t.Fatalf("candidate identity leaked environment: %s %v", encoded, err)
	}
	result, err := service.Migrate(context.Background(), candidate)
	if err != nil || len(ledger.rows) != 24 || result.Database.Name != candidate.Name {
		t.Fatalf("migrate result=%+v rows=%d err=%v", result, len(ledger.rows), err)
	}
	candidateControl.exists = false
	beforeCalls := candidateControl.createCalls
	if _, err := service.Migrate(context.Background(), candidate); !errors.Is(err, ErrCandidateConflict) || candidateControl.createCalls != beforeCalls {
		t.Fatalf("missing journaled candidate was recreated: calls=%d err=%v", candidateControl.createCalls, err)
	}
}

type bootstrapLedgerFake struct {
	rows              []MigrationRow
	ledger            bool
	beginErr, execErr error
	commitUnknownAt   int
	dropCommitAt      int
	commits           int
	lastSQL           []string
}

func (f *bootstrapLedgerFake) EnsureMigrationLedger(context.Context) error {
	f.ledger = true
	return nil
}
func (f *bootstrapLedgerFake) MigrationRows(context.Context) ([]MigrationRow, error) {
	if !f.ledger {
		return nil, errors.New("ledger not created")
	}
	return append([]MigrationRow(nil), f.rows...), nil
}
func (f *bootstrapLedgerFake) BeginMigration(context.Context) (MigrationTx, error) {
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	return &bootstrapLedgerTx{parent: f}, nil
}

type bootstrapLedgerTx struct {
	parent *bootstrapLedgerFake
	row    MigrationRow
}

func (t *bootstrapLedgerTx) ExecMigration(_ context.Context, sql string) error {
	t.parent.lastSQL = append(t.parent.lastSQL, sql)
	return t.parent.execErr
}
func (t *bootstrapLedgerTx) RecordMigration(_ context.Context, row MigrationRow) error {
	t.row = row
	return nil
}
func (t *bootstrapLedgerTx) Commit() error {
	t.parent.commits++
	if t.parent.dropCommitAt == t.parent.commits {
		return ErrPostgresOutcomeUnknown
	}
	t.parent.rows = append(t.parent.rows, t.row)
	if t.parent.commitUnknownAt == t.parent.commits {
		return ErrPostgresOutcomeUnknown
	}
	return nil
}
func (*bootstrapLedgerTx) Rollback() error { return nil }

func bootstrapRuntimeEnv(t *testing.T) []byte {
	t.Helper()
	env, err := FormatDatabaseEnv("postgresql://opencard:bootstrap-password-sentinel@127.0.0.1:5432/bootstrap_template?sslmode=require")
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func bootstrapInput(release ReleaseV1) BootstrapDatabaseInput {
	return BootstrapDatabaseInput{TransactionID: "bootstrap-txn-1", InstallationIDSHA256: strings.Repeat("a", 64), CandidateActivationID: "activation-bootstrap-1", Release: release}
}

func TestBootstrapDatabaseProvisionsEmptyAndReplaysExactCandidate(t *testing.T) {
	release, root := bootstrapRC2Release(t)
	migrations, err := LoadTaskBootstrapMigrations(root, os.Getuid(), os.Getgid(), release)
	if err != nil {
		t.Fatal(err)
	}
	if encoded, err := json.Marshal(migrations); err != nil || strings.Contains(string(encoded), "SELECT 1") || strings.Contains(string(encoded), "sql") {
		t.Fatalf("migration payload serialization exposed SQL: %s %v", encoded, err)
	}
	candidate := &bootstrapCandidateFake{}
	ledger := &bootstrapLedgerFake{}
	input := bootstrapInput(release)
	service, err := TaskBootstrapDatabase(input, bootstrapRuntimeEnv(t), strings.Repeat("c", 64), candidate, "opencard", func(name string) (BootstrapMigrationControl, error) {
		want, _ := CandidateDatabaseName(input.CandidateActivationID)
		if name != want {
			t.Fatalf("candidate name = %q", name)
		}
		return ledger, nil
	}, func() (BootstrapMigrations, error) { return migrations, nil })
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Provision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !ledger.ledger || len(ledger.rows) != 24 || len(ledger.lastSQL) != 24 || candidate.created != result.Database.Name || result.Database.Migration != "0024" {
		t.Fatalf("provision result=%#v rows=%d sql=%d candidate=%#v", result, len(ledger.rows), len(ledger.lastSQL), candidate)
	}
	if env, err := PostgresEnvironment(result.DatabaseEnv); err != nil || env.Descriptor.Database != result.Database.Name || result.Database.SchemaMigrationsSHA256 != migrationDigest(migrations.Rows) || result.RuntimeDatabaseEnvSHA256 != sha256Bytes(bootstrapRuntimeEnv(t)) || result.ControlDatabaseIdentitySHA256 != strings.Repeat("c", 64) {
		t.Fatalf("database result is not exact: %#v %v", result, err)
	}
	encoded, err := json.Marshal(result)
	if err != nil || strings.Contains(string(encoded), "bootstrap-password-sentinel") || strings.Contains(string(encoded), "postgresql://") {
		t.Fatalf("result serialization leaked database environment: %s %v", encoded, err)
	}
	// The second invocation must accept only the owner/comment replay created
	// by the first one and perform no additional CREATE DATABASE operation.
	created := candidate.created
	again, err := service.Provision(context.Background())
	if err != nil || again.Database != result.Database || again.CandidateDatabaseName != result.CandidateDatabaseName || again.RecoveryEvidenceSHA256 != result.RecoveryEvidenceSHA256 || string(again.DatabaseEnv) != string(result.DatabaseEnv) || candidate.created != created || len(ledger.rows) != 24 {
		t.Fatalf("replay=%#v err=%v candidate=%#v rows=%d", again, err, candidate, len(ledger.rows))
	}
}

func TestBootstrapDatabaseRejectsIdentityAndLedgerFailures(t *testing.T) {
	release, root := bootstrapRC2Release(t)
	migrations, err := LoadTaskBootstrapMigrations(root, os.Getuid(), os.Getgid(), release)
	if err != nil {
		t.Fatal(err)
	}
	for name, configure := range map[string]func(*bootstrapCandidateFake, *bootstrapLedgerFake){
		"existing_wrong_owner": func(c *bootstrapCandidateFake, _ *bootstrapLedgerFake) {
			c.exists, c.owner, c.evidence = true, "other", candidateDatabaseEvidence(strings.Repeat("b", 64))
		},
		"existing_wrong_evidence": func(c *bootstrapCandidateFake, _ *bootstrapLedgerFake) {
			c.exists, c.owner, c.evidence = true, "opencard", candidateDatabaseEvidence(strings.Repeat("b", 64))
		},
		"ledger_gap": func(_ *bootstrapCandidateFake, l *bootstrapLedgerFake) {
			l.rows = append([]MigrationRow{migrations.Rows[0]}, migrations.Rows[2])
		},
		"migration_exec": func(_ *bootstrapCandidateFake, l *bootstrapLedgerFake) {
			l.execErr = errors.New("sql secret must not escape")
		},
		"commit_unknown": func(_ *bootstrapCandidateFake, l *bootstrapLedgerFake) { l.dropCommitAt = 1 },
		"ledger_extra": func(_ *bootstrapCandidateFake, l *bootstrapLedgerFake) {
			l.rows = append(append([]MigrationRow(nil), migrations.Rows...), MigrationRow{Version: "0025_foreign", Checksum: strings.Repeat("f", 64)})
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate, ledger := &bootstrapCandidateFake{}, &bootstrapLedgerFake{}
			configure(candidate, ledger)
			service, err := TaskBootstrapDatabase(bootstrapInput(release), bootstrapRuntimeEnv(t), strings.Repeat("c", 64), candidate, "opencard", func(string) (BootstrapMigrationControl, error) { return ledger, nil }, func() (BootstrapMigrations, error) { return migrations, nil })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Provision(context.Background()); err == nil || !errors.Is(err, ErrCandidateConflict) && !errors.Is(err, ErrPostgresOutcomeUnknown) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("failure=%v", err)
			}
		})
	}
}

func TestBootstrapDatabaseResumesExactMigrationPrefix(t *testing.T) {
	release, root := bootstrapRC2Release(t)
	migrations, err := LoadTaskBootstrapMigrations(root, os.Getuid(), os.Getgid(), release)
	if err != nil {
		t.Fatal(err)
	}
	ledger := &bootstrapLedgerFake{ledger: true, rows: append([]MigrationRow(nil), migrations.Rows[:7]...)}
	service, err := TaskBootstrapDatabase(bootstrapInput(release), bootstrapRuntimeEnv(t), strings.Repeat("c", 64), &bootstrapCandidateFake{}, "opencard", func(string) (BootstrapMigrationControl, error) { return ledger, nil }, func() (BootstrapMigrations, error) { return migrations, nil })
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Provision(context.Background())
	if err != nil || len(ledger.rows) != 24 || len(ledger.lastSQL) != 17 || result.Database.SchemaMigrationsSHA256 != migrationDigest(migrations.Rows) {
		t.Fatalf("prefix replay result=%+v rows=%d sql=%d err=%v", result, len(ledger.rows), len(ledger.lastSQL), err)
	}
}

func TestBootstrapDatabaseRecoveryEvidenceBindsControlIdentity(t *testing.T) {
	release, root := bootstrapRC2Release(t)
	migrations, err := LoadTaskBootstrapMigrations(root, os.Getuid(), os.Getgid(), release)
	if err != nil {
		t.Fatal(err)
	}
	candidate := &bootstrapCandidateFake{}
	ledger := &bootstrapLedgerFake{}
	open := func(string) (BootstrapMigrationControl, error) { return ledger, nil }
	load := func() (BootstrapMigrations, error) { return migrations, nil }
	first, err := TaskBootstrapDatabase(bootstrapInput(release), bootstrapRuntimeEnv(t), strings.Repeat("c", 64), candidate, "opencard", open, load)
	if err != nil {
		t.Fatal(err)
	}
	result, err := first.Provision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := TaskBootstrapDatabase(bootstrapInput(release), bootstrapRuntimeEnv(t), strings.Repeat("d", 64), candidate, "opencard", open, load)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Provision(context.Background()); !errors.Is(err, ErrCandidateConflict) || result.ControlDatabaseIdentitySHA256 == strings.Repeat("d", 64) {
		t.Fatalf("control identity drift accepted: %v", err)
	}
}

func TestBootstrapDatabaseReconcilesCommitUnknownAndLoaderRejectsDrift(t *testing.T) {
	release, root := bootstrapRC2Release(t)
	migrations, err := LoadTaskBootstrapMigrations(root, os.Getuid(), os.Getgid(), release)
	if err != nil {
		t.Fatal(err)
	}
	ledger := &bootstrapLedgerFake{commitUnknownAt: 1}
	service, err := TaskBootstrapDatabase(bootstrapInput(release), bootstrapRuntimeEnv(t), strings.Repeat("c", 64), &bootstrapCandidateFake{}, "opencard", func(string) (BootstrapMigrationControl, error) { return ledger, nil }, func() (BootstrapMigrations, error) { return migrations, nil })
	if err != nil {
		t.Fatal(err)
	}
	if result, err := service.Provision(context.Background()); err != nil || len(ledger.rows) != 24 || result.Database.SchemaMigrationsSHA256 != migrationDigest(migrations.Rows) {
		t.Fatalf("commit-unknown reconciliation result=%#v rows=%d err=%v", result, len(ledger.rows), err)
	}
	if err := os.Chmod(filepath.Join(root, "releases", release.ID, "migrations", "control-plane", "0001_bootstrap.sql"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTaskBootstrapMigrations(root, os.Getuid(), os.Getgid(), release); !errors.Is(err, ErrPostgresOutcomeUnknown) {
		t.Fatalf("mode drift accepted: %v", err)
	}
}

func TestBootstrapDatabaseVerifiesReleaseBeforeCandidateSideEffect(t *testing.T) {
	release, _ := bootstrapRC2Release(t)
	candidate := &bootstrapCandidateFake{}
	service, err := TaskBootstrapDatabase(bootstrapInput(release), bootstrapRuntimeEnv(t), strings.Repeat("c", 64), candidate, "opencard", func(string) (BootstrapMigrationControl, error) {
		return &bootstrapLedgerFake{}, nil
	}, func() (BootstrapMigrations, error) { return BootstrapMigrations{}, ErrPostgresOutcomeUnknown })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Provision(context.Background()); !errors.Is(err, ErrPostgresOutcomeUnknown) || candidate.created != "" || candidate.exists {
		t.Fatalf("unverified release caused candidate side effect: candidate=%+v err=%v", candidate, err)
	}
}

func TestBootstrapMigrationLoaderRejectsReleaseAndPathDrift(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, string, *ReleaseV1){
		"missing": func(t *testing.T, activeRoot string, release *ReleaseV1) {
			t.Helper()
			if err := os.Remove(filepath.Join(activeRoot, "releases", release.ID, "migrations/control-plane/0001_bootstrap.sql")); err != nil {
				t.Fatal(err)
			}
		},
		"extra": func(t *testing.T, activeRoot string, release *ReleaseV1) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(activeRoot, "releases", release.ID, "migrations/control-plane/foreign.txt"), []byte("foreign\n"), 0o640); err != nil {
				t.Fatal(err)
			}
		},
		"hash": func(t *testing.T, activeRoot string, release *ReleaseV1) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(activeRoot, "releases", release.ID, "migrations/control-plane/0001_bootstrap.sql"), []byte("tampered\n"), 0o640); err != nil {
				t.Fatal(err)
			}
		},
		"version": func(t *testing.T, activeRoot string, release *ReleaseV1) {
			t.Helper()
			manifestPath := filepath.Join(activeRoot, "releases", release.ID, "manifest.json")
			manifest, err := LoadManifest(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			manifest.Version = ProductionCandidateVersion
			raw, _ := json.Marshal(manifest)
			if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			release.ManifestSHA256, _ = SHA256File(manifestPath)
		},
		"lineage": func(t *testing.T, activeRoot string, release *ReleaseV1) {
			t.Helper()
			manifestPath := filepath.Join(activeRoot, "releases", release.ID, "manifest.json")
			manifest, err := LoadManifest(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			manifest.NMinusOne.BundleManifestSHA256 = strings.Repeat("0", 64)
			raw, _ := json.Marshal(manifest)
			if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			release.ManifestSHA256, _ = SHA256File(manifestPath)
		},
		"releases-symlink": func(t *testing.T, activeRoot string, _ *ReleaseV1) {
			t.Helper()
			releases := filepath.Join(activeRoot, "releases")
			moved := filepath.Join(activeRoot, "moved-releases")
			if err := os.Rename(releases, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("moved-releases", releases); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			release, activeRoot := bootstrapRC2Release(t)
			mutate(t, activeRoot, &release)
			if _, err := LoadTaskBootstrapMigrations(activeRoot, os.Getuid(), os.Getgid(), release); !errors.Is(err, ErrPostgresOutcomeUnknown) {
				t.Fatalf("%s drift accepted: %v", name, err)
			}
		})
	}
}

func TestBootstrapDatabaseEnvUsesPinnedNoFollowRoot(t *testing.T) {
	root := t.TempDir()
	writer, err := TaskDurableWriter(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	runtimeEnv := bootstrapRuntimeEnv(t)
	if err := writer.CreateMetadata(filepath.Base(productionBootstrapDatabaseEnvPath), runtimeEnv); err != nil {
		t.Fatal(err)
	}
	if got, err := readBootstrapDatabaseEnv(writer); err != nil || string(got) != string(runtimeEnv) {
		t.Fatalf("read=%q err=%v", got, err)
	}
	if err := os.Chmod(filepath.Join(root, filepath.Base(productionBootstrapDatabaseEnvPath)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readBootstrapDatabaseEnv(writer); err == nil {
		t.Fatal("writable bootstrap database environment accepted")
	}
	if _, err := TaskDurableWriter(root, os.Getuid()+1, os.Getgid()); err == nil {
		t.Fatal("foreign-owned bootstrap environment root accepted")
	}
	symlinkRoot := filepath.Join(t.TempDir(), "bootstrap-env-link")
	if err := os.Symlink(root, symlinkRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := TaskDurableWriter(symlinkRoot, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("symlink bootstrap environment root accepted")
	}
}

func TestBootstrapDatabaseProductionBoundariesAndNoDestructiveSurface(t *testing.T) {
	release, _ := bootstrapRC2Release(t)
	runtimeEnv := bootstrapRuntimeEnv(t)
	controlEnv, err := FormatDatabaseEnv("postgresql://open_card_upgrade_control:control-password-sentinel@127.0.0.1:5432/postgres?sslmode=require")
	if err != nil {
		t.Fatal(err)
	}
	oldRuntime, oldControl := readProductionBootstrapDatabaseEnv, readProductionUpgradeDatabaseEnv
	readProductionBootstrapDatabaseEnv = func() ([]byte, error) { return runtimeEnv, nil }
	readProductionUpgradeDatabaseEnv = func() ([]byte, error) { return controlEnv, nil }
	t.Cleanup(func() { readProductionBootstrapDatabaseEnv, readProductionUpgradeDatabaseEnv = oldRuntime, oldControl })
	service, err := ProductionBootstrapDatabase(bootstrapInput(release))
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if string(service.runtimeEnv) != string(runtimeEnv) || service.runtimeRole != "opencard" || service.load == nil {
		t.Fatal("production bootstrap constructor did not bind fixed data-only dependencies")
	}
	for _, name := range []string{"bootstrap_database.go"} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		source := strings.ToUpper(string(raw))
		if strings.Contains(source, "DROP DATABASE") || strings.Contains(source, "DELETE DATABASE") || strings.Contains(source, "OPEN_CARD_DATABASE_URL=") && name == "bootstrap_database.go" {
			t.Fatalf("unsafe bootstrap source surface in %s", name)
		}
	}
}

func bootstrapRC2Release(t *testing.T) (ReleaseV1, string) {
	t.Helper()
	activeRoot := filepath.Join(t.TempDir(), "open-card")
	root := filepath.Join(activeRoot, "releases", "release-rc2")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]struct {
		raw  []byte
		mode os.FileMode
	}{}
	for version := 1; version <= 24; version++ {
		name := fmt.Sprintf("migrations/control-plane/%04d_bootstrap.sql", version)
		if version == 24 {
			name = "migrations/control-plane/0024_dns_change_ledger.sql"
		}
		files[name] = struct {
			raw  []byte
			mode os.FileMode
		}{[]byte(fmt.Sprintf("SELECT %d;\n", version)), 0o640}
	}
	for _, path := range []string{
		"bin/open-card-admin", "bin/open-card-upgrade", "scripts/mvp/host-preflight.sh", "scripts/mvp/buildkit-production-capacity.sh", "scripts/mvp/g6-staging-evidence.sh", "tools/evidence/g6_validate.py", "tools/evidence/g6_target_receipt.py",
	} {
		files[path] = struct {
			raw  []byte
			mode os.FileMode
		}{[]byte("#!/bin/sh\nexit 0\n"), 0o755}
	}
	for _, path := range []string{
		"systemd/open-card-edge.service", "systemd/open-card-upgrade-recover.service", "systemd/open-card-upgrade-safe.target", "systemd/open-card-upgrade-finalize.service", "systemd/open-card-edge.service.d/10-upgrade-marker.conf", "caddy/open-card-edge.Caddyfile.example", "web/dist/index.html", "docs/licenses/licenses-manifest.json", "sbom.spdx.json", "source-manifest.sha256",
	} {
		files[path] = struct {
			raw  []byte
			mode os.FileMode
		}{[]byte("bootstrap\n"), 0o644}
	}
	manifestFiles := make([]FileDigest, 0, len(files))
	for path, file := range files {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, file.raw, file.mode); err != nil {
			t.Fatal(err)
		}
		digest, err := SHA256File(full)
		if err != nil {
			t.Fatal(err)
		}
		manifestFiles = append(manifestFiles, FileDigest{Path: path, SHA256: digest, Mode: uint32(file.mode)})
	}
	architecture := RuntimeArchitecture()
	lineage, err := RC1LineageForArchitecture(architecture)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{SchemaVersion: ManifestSchemaVersion, Product: ManifestProduct, Version: Gate6CandidateVersion, ReleaseID: filepath.Base(root), Architecture: architecture, MigrationVersion: CurrentMigrationVersion, SourceCommit: strings.Repeat("b", 40), NMinusOne: &NMinusOne{Version: Gate6NMinusOneVersion, MigrationVersion: "0024", SourceCommit: lineage.SourceCommit, ReleaseManifestSHA256: lineage.ReleaseManifestSHA256, ArchiveSHA256: lineage.ArchiveSHA256, BundleManifestSHA256: lineage.BundleManifestSHA256}, Protocol: AgentProtocolVersion, ConfigDir: DefaultConfigDir, DataDir: DefaultDataDir, Compatibility: Compatibility{MinDataVersion: 23, MaxDataVersion: 24, MinAgentProtocol: PreviousAgentProtocol, MaxAgentProtocol: AgentProtocolVersion}, Files: manifestFiles}
	if err := SaveManifest(filepath.Join(root, "manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	digest, err := SHA256File(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	return ReleaseV1{ID: manifest.ReleaseID, Version: manifest.Version, SourceCommit: manifest.SourceCommit, Architecture: manifest.Architecture, ManifestSHA256: digest}, activeRoot
}
