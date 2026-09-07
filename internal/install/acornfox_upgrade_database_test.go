package install

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type acornFoxUpgradeDatabaseLedgerFake struct {
	rows      []MigrationRow
	available bool
	executed  []string
	commits   int
}

func (*acornFoxUpgradeDatabaseLedgerFake) EnsureMigrationLedger(context.Context) error { return nil }
func (f *acornFoxUpgradeDatabaseLedgerFake) MigrationRows(context.Context) ([]MigrationRow, error) {
	if !f.available {
		return nil, errors.New("ledger unavailable")
	}
	return append([]MigrationRow(nil), f.rows...), nil
}
func (f *acornFoxUpgradeDatabaseLedgerFake) BeginMigration(context.Context) (MigrationTx, error) {
	if !f.available {
		return nil, errors.New("ledger unavailable")
	}
	return &acornFoxUpgradeDatabaseTxFake{ledger: f}, nil
}

type acornFoxUpgradeDatabaseTxFake struct {
	ledger *acornFoxUpgradeDatabaseLedgerFake
	sql    string
	row    MigrationRow
}

func (t *acornFoxUpgradeDatabaseTxFake) ExecMigration(_ context.Context, sql string) error {
	t.sql = sql
	return nil
}
func (t *acornFoxUpgradeDatabaseTxFake) RecordMigration(_ context.Context, row MigrationRow) error {
	t.row = row
	return nil
}
func (t *acornFoxUpgradeDatabaseTxFake) Commit() error {
	t.ledger.executed = append(t.ledger.executed, t.sql)
	t.ledger.rows = append(t.ledger.rows, t.row)
	t.ledger.commits++
	return nil
}
func (*acornFoxUpgradeDatabaseTxFake) Rollback() error { return nil }

type acornFoxUpgradeDatabaseRunnerFake struct {
	ledger                 *acornFoxUpgradeDatabaseLedgerFake
	sourceRows             []MigrationRow
	calls                  [][]string
	environments           [][]string
	restoreErrAfterEffect  bool
	restoreFailedOnce      bool
	dumpErrAfterEffect     bool
	dumpFailedOnce         bool
	listFail               bool
	forbidUnexpectedBinary bool
}

func (f *acornFoxUpgradeDatabaseRunnerFake) Run(_ context.Context, argv, environment []string) PostgresRunResult {
	f.calls = append(f.calls, append([]string(nil), argv...))
	f.environments = append(f.environments, append([]string(nil), environment...))
	if len(argv) == 0 {
		return PostgresRunResult{ExitCode: -1, Err: errors.New("empty argv")}
	}
	switch argv[0] {
	case productionPostgresDumpTool:
		var path string
		for index := range argv {
			if argv[index] == "--file" && index+1 < len(argv) {
				path = argv[index+1]
			}
		}
		if path == "" {
			return PostgresRunResult{ExitCode: -1, Err: errors.New("missing dump path")}
		}
		if err := os.WriteFile(path, []byte("private custom-format snapshot"), 0o600); err != nil {
			return PostgresRunResult{ExitCode: -1, Err: err}
		}
		if f.dumpErrAfterEffect && !f.dumpFailedOnce {
			f.dumpFailedOnce = true
			return PostgresRunResult{ExitCode: 1, Err: errors.New("lost dump outcome")}
		}
	case productionPostgresRestoreTool:
		if len(argv) == 3 && argv[1] == "--list" {
			if f.listFail {
				return PostgresRunResult{ExitCode: 1, Err: errors.New("invalid custom archive")}
			}
			return PostgresRunResult{}
		}
		f.ledger.available = true
		f.ledger.rows = append([]MigrationRow(nil), f.sourceRows...)
		if f.restoreErrAfterEffect && !f.restoreFailedOnce {
			f.restoreFailedOnce = true
			return PostgresRunResult{ExitCode: 1, Err: errors.New("lost restore outcome")}
		}
	default:
		if f.forbidUnexpectedBinary {
			return PostgresRunResult{ExitCode: -1, Err: errors.New("unexpected binary")}
		}
	}
	return PostgresRunResult{}
}

type acornFoxUpgradeDatabaseAdminFake struct {
	identity acornFoxUpgradeShadowIdentity
	creates  int
	comments []string
}

func (f *acornFoxUpgradeDatabaseAdminFake) Inspect(context.Context, string) (acornFoxUpgradeShadowIdentity, error) {
	return f.identity, nil
}
func (f *acornFoxUpgradeDatabaseAdminFake) Create(context.Context, string) error {
	f.creates++
	if f.identity.Exists {
		return errors.New("already exists")
	}
	f.identity = acornFoxUpgradeShadowIdentity{Exists: true, Owner: acornFoxControlPlaneRole}
	return nil
}
func (f *acornFoxUpgradeDatabaseAdminFake) SetEvidence(_ context.Context, _ string, evidence string) error {
	if !f.identity.Exists {
		return errors.New("missing database")
	}
	f.identity.Evidence = evidence
	f.comments = append(f.comments, evidence)
	return nil
}

type acornFoxUpgradeDatabaseHealthFake struct {
	calls int
	fail  bool
}

func (f *acornFoxUpgradeDatabaseHealthFake) Check(_ context.Context, environment []byte, database, rowsSHA string) error {
	f.calls++
	if !bytes.HasPrefix(environment, []byte("ACORNFOX_DATABASE_URL=postgresql://acornfox:")) || !acornFoxUpgradeShadowName.MatchString(database) || !validSHA(rowsSHA) {
		return errors.New("invalid health input")
	}
	if f.fail {
		return errors.New("candidate unhealthy")
	}
	return nil
}

type acornFoxUpgradeDatabaseFixture struct {
	database   *acornFoxUpgradeDatabase
	migrations acornFoxControlPlaneMigrations
	source     *acornFoxUpgradeDatabaseLedgerFake
	candidate  *acornFoxUpgradeDatabaseLedgerFake
	runner     *acornFoxUpgradeDatabaseRunnerFake
	admin      *acornFoxUpgradeDatabaseAdminFake
	health     *acornFoxUpgradeDatabaseHealthFake
	state      string
	password   string
}

func newAcornFoxUpgradeDatabaseFixture(t *testing.T) acornFoxUpgradeDatabaseFixture {
	return newAcornFoxUpgradeDatabaseFixtureWithSource(t, 34)
}

func newAcornFoxUpgradeDatabaseFixtureWithSource(t *testing.T, sourceDataVersion int) acornFoxUpgradeDatabaseFixture {
	t.Helper()
	parent := t.TempDir()
	host := filepath.Join(parent, "host")
	state := filepath.Join(host, "var", "lib", "acornfox", "install")
	if err := os.Mkdir(host, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	layout, err := newTestProductionAcornFoxLayout(state, host, os.Getuid(), os.Getgid(), acornFoxTestLayoutPrincipals())
	if err != nil {
		t.Fatal(err)
	}
	migrations := acornFoxControlPlaneMigrations{rows: make([]MigrationRow, 0, len(acornFoxV1Migrations)), sql: make([]string, 0, len(acornFoxV1Migrations))}
	for _, name := range acornFoxV1Migrations {
		sqlText := "SELECT '" + name + "'"
		migrations.rows = append(migrations.rows, MigrationRow{Version: strings.TrimSuffix(name, ".sql"), Checksum: sha256Bytes([]byte(sqlText))})
		migrations.sql = append(migrations.sql, sqlText)
	}
	if !migrations.valid() {
		t.Fatal("invalid migration fixture")
	}
	password := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	activeEnvironment := []byte("ACORNFOX_DATABASE_URL=postgresql://acornfox:" + password + "@127.0.0.1:5432/acornfox?sslmode=disable\n")
	source := &acornFoxUpgradeDatabaseLedgerFake{rows: append([]MigrationRow(nil), migrations.rows[:sourceDataVersion]...), available: true}
	candidate := &acornFoxUpgradeDatabaseLedgerFake{}
	runner := &acornFoxUpgradeDatabaseRunnerFake{ledger: candidate, sourceRows: source.rows, forbidUnexpectedBinary: true}
	admin := &acornFoxUpgradeDatabaseAdminFake{}
	health := &acornFoxUpgradeDatabaseHealthFake{}
	open := func(environment []byte) (BootstrapMigrationControl, error) {
		name, err := acornFoxControlPlaneDatabaseName(environment)
		if err != nil {
			return nil, err
		}
		if name == acornFoxControlPlaneDatabase {
			return source, nil
		}
		return candidate, nil
	}
	database, err := newTaskAcornFoxUpgradeDatabase(layout, "upgrade-transaction-1", strings.Repeat("a", 64), strings.Repeat("b", 64), activeEnvironment, migrations, sourceDataVersion, runner, admin, open, health)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return acornFoxUpgradeDatabaseFixture{database: database, migrations: migrations, source: source, candidate: candidate, runner: runner, admin: admin, health: health, state: state, password: password}
}

func TestAcornFoxUpgradeDatabaseMigratesExact0039PrefixTo0040(t *testing.T) {
	fixture := newAcornFoxUpgradeDatabaseFixtureWithSource(t, 39)
	private, err := fixture.database.Prepare(context.Background(), nil)
	if err != nil || private.Evidence.State != acornFoxUpgradeDatabaseHealthValidated {
		t.Fatalf("private=%#v err=%v", private.Evidence, err)
	}
	if len(fixture.source.rows) != 39 || !matchesExpected(fixture.source.rows, fixture.migrations.rows[:39]) || len(fixture.candidate.rows) != 40 || fixture.candidate.commits != 1 || !matchesExpectedSQL(fixture.candidate.executed, fixture.migrations.sql[39:]) {
		t.Fatalf("source=%d candidate=%d commits=%d sql=%q", len(fixture.source.rows), len(fixture.candidate.rows), fixture.candidate.commits, fixture.candidate.executed)
	}
}

func TestAcornFoxUpgradePrivateStoreBindsAndRemovesDatabaseArtifacts(t *testing.T) {
	fixture := newAcornFoxUpgradeDatabaseFixture(t)
	private, err := fixture.database.Prepare(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	store, err := newAcornFoxRepoStoreForLayout(fixture.database.layout)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	upgrade := newAcornFoxUpgrade(fixture.database.layout)
	cross := acornFoxCrossSchemaUpgradeV1{Database: private.Evidence}
	if err := upgrade.verifyCrossSchemaDatabaseArtifacts(store, cross); err != nil {
		t.Fatalf("verify err=%v", err)
	}
	artifact := filepath.Join(fixture.state, acornFoxUpgradeDirectory, acornFoxUpgradeDatabaseRoot, fixture.database.artifactID)
	if err := os.Link(filepath.Join(artifact, acornFoxUpgradeDatabaseSnapshot), filepath.Join(artifact, ".open-card-file-0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	journal := acornFoxUpgradeJournal{CrossSchema: &cross}
	if err := upgrade.removeCrossSchemaDatabaseArtifacts(store, journal); err != nil {
		t.Fatalf("remove err=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(fixture.state, acornFoxUpgradeDirectory, acornFoxUpgradeDatabaseRoot)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("database artifact remained: %v", err)
	}
}

func TestAcornFoxUpgradePrivateStoreRejectsForeignDatabaseArtifact(t *testing.T) {
	fixture := newAcornFoxUpgradeDatabaseFixture(t)
	private, err := fixture.database.Prepare(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	store, err := newAcornFoxRepoStoreForLayout(fixture.database.layout)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	artifact := filepath.Join(fixture.state, acornFoxUpgradeDirectory, acornFoxUpgradeDatabaseRoot, fixture.database.artifactID)
	if err := os.WriteFile(filepath.Join(artifact, "foreign"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	upgrade := newAcornFoxUpgrade(fixture.database.layout)
	cross := acornFoxCrossSchemaUpgradeV1{Database: private.Evidence}
	if err := upgrade.verifyCrossSchemaDatabaseArtifacts(store, cross); !errors.Is(err, ErrAcornFoxUpgradeConflict) {
		t.Fatalf("verify err=%v", err)
	}
	if err := upgrade.removeCrossSchemaDatabaseArtifacts(store, acornFoxUpgradeJournal{CrossSchema: &cross}); !errors.Is(err, ErrAcornFoxUpgradeConflict) {
		t.Fatalf("remove err=%v", err)
	}
}

func TestAcornFoxUpgradeDatabasePreparesShadowAndPreservesSource(t *testing.T) {
	fixture := newAcornFoxUpgradeDatabaseFixture(t)
	plan, err := fixture.database.Plan()
	if err != nil || plan.Evidence.State != acornFoxUpgradeDatabasePlanned {
		t.Fatalf("plan=%#v err=%v", plan.Evidence, err)
	}
	serialized, err := json.Marshal(plan)
	if err != nil || bytes.Contains(serialized, []byte(fixture.password)) || bytes.Contains(serialized, []byte("postgresql://")) || fmt.Sprintf("%v", plan) != "AcornFox upgrade database [redacted]" {
		t.Fatalf("private result leaked: %s err=%v format=%v", serialized, err, plan)
	}
	private, err := fixture.database.Prepare(context.Background(), &plan.Evidence)
	if err != nil || private.Evidence.State != acornFoxUpgradeDatabaseHealthValidated || private.Evidence.validate() != nil {
		t.Fatalf("prepare=%#v err=%v", private.Evidence, err)
	}
	if !matchesExpected(fixture.source.rows, fixture.migrations.rows[:34]) {
		t.Fatal("source database changed")
	}
	if !matchesExpected(fixture.candidate.rows, fixture.migrations.rows) || fixture.candidate.commits != AcornFoxV1DataVersion-34 || !matchesExpectedSQL(fixture.candidate.executed, fixture.migrations.sql[34:]) {
		t.Fatalf("candidate rows=%d commits=%d sql=%q", len(fixture.candidate.rows), fixture.candidate.commits, fixture.candidate.executed)
	}
	if fixture.admin.creates != 1 || fixture.health.calls != 1 || fixture.admin.identity.Evidence != fixture.database.shadowEvidence("validated") {
		t.Fatalf("admin=%#v health=%d", fixture.admin, fixture.health.calls)
	}
	if got := private.candidateEnvironmentBytes(); !bytes.Contains(got, []byte("/"+fixture.database.shadowDatabase+"?sslmode=disable")) || bytes.Contains(got, []byte("/acornfox?")) {
		t.Fatalf("candidate environment has wrong database: %q", got)
	}
	if len(fixture.runner.calls) != 3 || fixture.runner.calls[0][0] != productionPostgresDumpTool || fixture.runner.calls[1][0] != productionPostgresRestoreTool || fixture.runner.calls[1][1] != "--list" || fixture.runner.calls[2][0] != productionPostgresRestoreTool {
		t.Fatalf("tools=%q", fixture.runner.calls)
	}
	artifact := filepath.Join(fixture.state, acornFoxUpgradeDirectory, acornFoxUpgradeDatabaseRoot, fixture.database.artifactID)
	for _, path := range []string{filepath.Join(fixture.state, acornFoxUpgradeDirectory), filepath.Join(fixture.state, acornFoxUpgradeDirectory, acornFoxUpgradeDatabaseRoot), artifact} {
		if info, err := os.Lstat(path); err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("private directory %s info=%v err=%v", path, info, err)
		}
	}
	if info, err := os.Lstat(filepath.Join(artifact, acornFoxUpgradeDatabaseDump)); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("dump info=%v err=%v", info, err)
	}
}

func TestAcornFoxUpgradeDatabaseRecoversLostRestoreOutcomeWithoutSecondRestore(t *testing.T) {
	fixture := newAcornFoxUpgradeDatabaseFixture(t)
	fixture.runner.restoreErrAfterEffect = true
	if _, err := fixture.database.Prepare(context.Background(), nil); !errors.Is(err, ErrAcornFoxUpgradeUnknown) {
		t.Fatalf("lost restore outcome err=%v", err)
	}
	if len(fixture.candidate.rows) != 34 || fixture.admin.identity.Evidence != fixture.database.shadowEvidence("created") {
		t.Fatalf("crash state rows=%d evidence=%q", len(fixture.candidate.rows), fixture.admin.identity.Evidence)
	}
	private, err := fixture.database.Prepare(context.Background(), nil)
	if err != nil || private.Evidence.State != acornFoxUpgradeDatabaseHealthValidated {
		t.Fatalf("recovery=%#v err=%v", private.Evidence, err)
	}
	restores := 0
	for _, argv := range fixture.runner.calls {
		if len(argv) > 1 && argv[0] == productionPostgresRestoreTool && argv[1] != "--list" {
			restores++
		}
	}
	if restores != 1 || fixture.candidate.commits != AcornFoxV1DataVersion-34 || fixture.admin.creates != 1 {
		t.Fatalf("restores=%d commits=%d creates=%d", restores, fixture.candidate.commits, fixture.admin.creates)
	}
}

func TestAcornFoxUpgradeDatabaseRecoversDumpBeforeWitnessWithoutSecondDump(t *testing.T) {
	fixture := newAcornFoxUpgradeDatabaseFixture(t)
	fixture.runner.dumpErrAfterEffect = true
	if _, err := fixture.database.Prepare(context.Background(), nil); !errors.Is(err, ErrAcornFoxUpgradeUnknown) {
		t.Fatalf("lost dump outcome err=%v", err)
	}
	artifact := filepath.Join(fixture.state, acornFoxUpgradeDirectory, acornFoxUpgradeDatabaseRoot, fixture.database.artifactID)
	if _, err := os.Lstat(filepath.Join(artifact, acornFoxUpgradeDatabaseDump)); err != nil {
		t.Fatalf("dump was not published before lost outcome: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(artifact, acornFoxUpgradeDatabaseSnapshot)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot witness unexpectedly exists: %v", err)
	}
	private, err := fixture.database.Prepare(context.Background(), nil)
	if err != nil || private.Evidence.State != acornFoxUpgradeDatabaseHealthValidated {
		t.Fatalf("recovery=%#v err=%v", private.Evidence, err)
	}
	dumps := 0
	for _, argv := range fixture.runner.calls {
		if len(argv) != 0 && argv[0] == productionPostgresDumpTool {
			dumps++
		}
	}
	if dumps != 1 {
		t.Fatalf("dump executions=%d", dumps)
	}
}

func TestAcornFoxUpgradeDatabaseRejectsInvalidCustomDumpBeforeShadow(t *testing.T) {
	fixture := newAcornFoxUpgradeDatabaseFixture(t)
	fixture.runner.listFail = true
	if _, err := fixture.database.Prepare(context.Background(), nil); !errors.Is(err, ErrAcornFoxUpgradeUnknown) {
		t.Fatalf("invalid custom dump err=%v", err)
	}
	if fixture.admin.creates != 0 || fixture.candidate.available || fixture.candidate.commits != 0 {
		t.Fatalf("invalid dump reached shadow creates=%d available=%t commits=%d", fixture.admin.creates, fixture.candidate.available, fixture.candidate.commits)
	}
}

func TestAcornFoxUpgradeDatabaseRejectsNonExact0034BeforeEffects(t *testing.T) {
	fixture := newAcornFoxUpgradeDatabaseFixture(t)
	fixture.source.rows[12].Checksum = strings.Repeat("f", 64)
	if _, err := fixture.database.Prepare(context.Background(), nil); !errors.Is(err, ErrAcornFoxUpgradeConflict) {
		t.Fatalf("drift err=%v", err)
	}
	if len(fixture.runner.calls) != 0 || fixture.admin.creates != 0 || fixture.candidate.commits != 0 {
		t.Fatalf("prefix rejection had effects calls=%q creates=%d commits=%d", fixture.runner.calls, fixture.admin.creates, fixture.candidate.commits)
	}
	if _, err := os.Lstat(filepath.Join(fixture.state, acornFoxUpgradeDirectory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("prefix rejection wrote artifacts: %v", err)
	}
}

func TestAcornFoxUpgradeDatabaseReplaysHealthWithoutRestoringOrMigrating(t *testing.T) {
	fixture := newAcornFoxUpgradeDatabaseFixture(t)
	fixture.health.fail = true
	if _, err := fixture.database.Prepare(context.Background(), nil); !errors.Is(err, ErrAcornFoxUpgradeUnknown) {
		t.Fatalf("health failure err=%v", err)
	}
	if fixture.candidate.commits != AcornFoxV1DataVersion-34 || fixture.admin.identity.Evidence != fixture.database.shadowEvidence("migrated") {
		t.Fatalf("migration was not durable commits=%d evidence=%q", fixture.candidate.commits, fixture.admin.identity.Evidence)
	}
	fixture.health.fail = false
	private, err := fixture.database.Prepare(context.Background(), nil)
	if err != nil || private.Evidence.State != acornFoxUpgradeDatabaseHealthValidated {
		t.Fatalf("health replay=%#v err=%v", private.Evidence, err)
	}
	restores := 0
	for _, argv := range fixture.runner.calls {
		if len(argv) > 1 && argv[0] == productionPostgresRestoreTool && argv[1] != "--list" {
			restores++
		}
	}
	if restores != 1 || fixture.candidate.commits != AcornFoxV1DataVersion-34 || fixture.health.calls != 2 {
		t.Fatalf("restores=%d commits=%d health=%d", restores, fixture.candidate.commits, fixture.health.calls)
	}
}

func TestAcornFoxUpgradeDatabaseRejectsUnboundExistingShadow(t *testing.T) {
	fixture := newAcornFoxUpgradeDatabaseFixture(t)
	fixture.admin.identity = acornFoxUpgradeShadowIdentity{Exists: true, Owner: acornFoxControlPlaneRole}
	snapshot, err := fixture.database.Snapshot(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.RestoreMigrate(context.Background(), snapshot); !errors.Is(err, ErrAcornFoxUpgradeConflict) {
		t.Fatalf("unbound shadow err=%v", err)
	}
	if fixture.admin.creates != 0 || len(fixture.admin.comments) != 0 {
		t.Fatalf("unbound shadow was claimed: %#v", fixture.admin)
	}
}

func TestLoadAcornFoxUpgradeMigrationsUsesVerifiedInactiveSubstrate(t *testing.T) {
	prepared := newAcornFoxProductionPreparedFixture(t)
	migrations, err := loadAcornFoxUpgradeMigrations(prepared.published, prepared.binding)
	if err != nil || !migrations.valid() || len(migrations.rows) != AcornFoxV1DataVersion || migrations.rows[33].Version != "0034_artifacts_per_build" || migrations.rows[34].Version != "0035_acornfox_source_metadata" || migrations.rows[38].Version != "0039_acornfox_access_observations" || migrations.rows[39].Version != "0040_acornfox_fix_candidates" {
		t.Fatalf("migrations=%d valid=%t err=%v", len(migrations.rows), migrations.valid(), err)
	}
	if _, err := loadAcornFoxUpgradeMigrations(prepared.published, strings.Repeat("f", 64)); !errors.Is(err, ErrAcornFoxUpgradeConflict) {
		t.Fatalf("wrong binding err=%v", err)
	}
}

func TestAcornFoxExpectedCurrentDatabaseRequiresTerminalBoundJournal(t *testing.T) {
	runtimeConfig, prepared, identity := runtimeConfigFixture(t)
	if _, err := runtimeRun(runtimeConfig, identity); err != nil {
		t.Fatal(err)
	}
	repository, err := prepared.store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	shadow := "acornfox_upg_0123456789abcdef0123"
	evidence := acornFoxUpgradeDatabaseEvidence{
		SchemaVersion:              acornFoxUpgradeDatabaseSchema,
		State:                      acornFoxUpgradeDatabaseHealthValidated,
		TransactionID:              "upgrade-transaction-1",
		OldBindingSHA256:           strings.Repeat("7", 64),
		NextBindingSHA256:          repository.BindingSHA256,
		ShadowDatabase:             shadow,
		RecoveryEvidenceSHA256:     strings.Repeat("b", 64),
		SourceRowsSHA256:           strings.Repeat("c", 64),
		CandidateRowsSHA256:        strings.Repeat("d", 64),
		CandidateDatabaseEnvSHA256: strings.Repeat("e", 64),
		SnapshotSHA256:             strings.Repeat("f", 64),
		SnapshotSize:               1,
	}
	journal := acornFoxUpgradeJournal{Phase: "UPGRADED", Next: acornFoxUpgradeImage{Repo: repository}, CrossSchema: &acornFoxCrossSchemaUpgradeV1{Database: evidence}}
	if got, err := acornFoxExpectedCurrentDatabaseFromJournal(repository, journal, repository.BindingSHA256); err != nil || got != shadow {
		t.Fatalf("database=%q err=%v repo=%#v evidenceErr=%v", got, err, repository, evidence.validate())
	}
	for _, mutate := range []func(*acornFoxUpgradeJournal, *AcornFoxRepoJournalV1){
		func(j *acornFoxUpgradeJournal, _ *AcornFoxRepoJournalV1) {
			j.CrossSchema.Database.ShadowDatabase = "acornfox_upg_forged"
		},
		func(j *acornFoxUpgradeJournal, _ *AcornFoxRepoJournalV1) {
			j.CrossSchema.Database.NextBindingSHA256 = strings.Repeat("9", 64)
		},
		func(j *acornFoxUpgradeJournal, _ *AcornFoxRepoJournalV1) { j.Phase = "SWITCHED" },
		func(_ *acornFoxUpgradeJournal, r *AcornFoxRepoJournalV1) { r.BindingSHA256 = strings.Repeat("8", 64) },
	} {
		forgedJournal := journal
		cross := *journal.CrossSchema
		forgedJournal.CrossSchema = &cross
		forgedRepository := repository
		mutate(&forgedJournal, &forgedRepository)
		if got, err := acornFoxExpectedCurrentDatabaseFromJournal(forgedRepository, forgedJournal, repository.BindingSHA256); !errors.Is(err, ErrAcornFoxUpgradeConflict) || got != "" {
			t.Fatalf("forged authority database=%q err=%v", got, err)
		}
	}
}

func matchesExpectedSQL(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}
