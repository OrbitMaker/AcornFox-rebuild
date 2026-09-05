package install

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type acornFoxControlPlaneLedgerFake struct {
	rows       []MigrationRow
	failCommit bool
}

func (f *acornFoxControlPlaneLedgerFake) EnsureMigrationLedger(context.Context) error { return nil }
func (f *acornFoxControlPlaneLedgerFake) MigrationRows(context.Context) ([]MigrationRow, error) {
	return append([]MigrationRow(nil), f.rows...), nil
}
func (f *acornFoxControlPlaneLedgerFake) BeginMigration(context.Context) (MigrationTx, error) {
	return &acornFoxControlPlaneTxFake{ledger: f}, nil
}

type acornFoxControlPlaneTxFake struct {
	ledger *acornFoxControlPlaneLedgerFake
	row    MigrationRow
}

func (*acornFoxControlPlaneTxFake) ExecMigration(context.Context, string) error { return nil }
func (f *acornFoxControlPlaneTxFake) RecordMigration(_ context.Context, row MigrationRow) error {
	f.row = row
	return nil
}
func (f *acornFoxControlPlaneTxFake) Commit() error {
	f.ledger.rows = append(f.ledger.rows, f.row)
	if f.ledger.failCommit {
		return errors.New("ambiguous")
	}
	return nil
}
func (*acornFoxControlPlaneTxFake) Rollback() error { return nil }

type acornFoxControlPlaneProvisionerFake struct {
	argv  []string
	stdin []byte
	err   error
}

func (f *acornFoxControlPlaneProvisionerFake) Run(_ context.Context, argv []string, stdin []byte) error {
	f.argv, f.stdin = append([]string(nil), argv...), append([]byte(nil), stdin...)
	return f.err
}

func newAcornFoxControlPlanePrepared(t *testing.T, ledger *acornFoxControlPlaneLedgerFake, runner *acornFoxControlPlaneProvisionerFake) (*acornFoxControlPlane, acornFoxProductionPreparedFixture) {
	t.Helper()
	prepared := newAcornFoxProductionPreparedFixture(t)
	if err := prepareAcornFoxRepository(context.Background(), prepared.store, prepared.published, prepared.binding); err != nil {
		t.Fatal(err)
	}
	service, err := newTaskAcornFoxControlPlane(prepared.layout, bytes.NewReader(bytes.Repeat([]byte{7}, 32)), runner, func([]byte) (BootstrapMigrationControl, error) { return ledger, nil })
	if err != nil {
		t.Fatal(err)
	}
	service.bridge.ownership = prepared.owners.edge()
	return service, prepared
}

func TestAcornFoxControlPlaneMigratesClosed33PrefixAndReplays(t *testing.T) {
	ledger, runner := &acornFoxControlPlaneLedgerFake{}, &acornFoxControlPlaneProvisionerFake{}
	service, prepared := newAcornFoxControlPlanePrepared(t, ledger, runner)
	if _, err := service.bridge.verifyPrepared(context.Background()); err != nil {
		t.Fatalf("precondition=%v", err)
	}
	if _, _, err := service.authority(context.Background()); err != nil {
		t.Fatalf("authority=%v", err)
	}
	first, err := service.migrate(context.Background())
	if err != nil || first.Validate() != nil || first.BindingSHA256 != prepared.binding || len(ledger.rows) != 33 {
		t.Fatalf("receipt=%#v rows=%d err=%v", first, len(ledger.rows), err)
	}
	if !validAcornFoxControlPlaneProvisionArgv(runner.argv) || !bytes.Contains(runner.stdin, []byte("CREATE ROLE acornfox")) || strings.Contains(strings.Join(runner.argv, " "), "Bw") {
		t.Fatalf("provision boundary argv=%q", runner.argv)
	}
	activation, _ := AcornFoxRepoActivationID(prepared.binding)
	for _, name := range []string{"database.env"} {
		info, statErr := os.Lstat(filepath.Join(prepared.host, "opt", "acornfox", "activations", activation, name))
		if statErr != nil {
			t.Fatal(statErr)
		}
		prepared.owners.set(info, acornFoxInstallPrincipal{})
	}
	if _, err := service.bridge.verifyPrepared(context.Background()); err != nil {
		t.Fatalf("replay precondition=%v", err)
	}
	second, err := service.migrate(context.Background())
	if err != nil || second != first || len(ledger.rows) != 33 {
		t.Fatalf("replay=%#v rows=%d err=%v", second, len(ledger.rows), err)
	}
	for _, path := range []string{
		filepath.Join(prepared.state, acornFoxControlPlaneStateEnv),
		filepath.Join(prepared.state, acornFoxControlPlaneReceipt),
		filepath.Join(prepared.host, "opt", "acornfox", "activations", activation, "database.env"),
	} {
		info, statErr := os.Lstat(path)
		if statErr != nil || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("durable artifact %s info=%#v err=%v", path, info, statErr)
		}
	}
	for _, path := range []string{filepath.Join(prepared.state, acornFoxControlPlaneStateEnv), filepath.Join(prepared.host, "opt", "acornfox", "activations", activation, "database.env")} {
		raw, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.HasPrefix(raw, []byte("ACORNFOX_DATABASE_URL=")) || bytes.Contains(raw, []byte("OPEN_CARD_")) {
			t.Fatalf("persisted env path=%s raw=%q err=%v", path, raw, readErr)
		}
	}
	prepared.assertExternalSentinel(t)
}

func TestAcornFoxControlPlaneRejectsLedgerGapAndPreservesExternalSentinel(t *testing.T) {
	ledger, runner := &acornFoxControlPlaneLedgerFake{rows: []MigrationRow{{Version: "0001_foundation", Checksum: acornFoxFixtureDigest("a")}, {Version: "0003_audit_chain_serialization", Checksum: acornFoxFixtureDigest("a")}}}, &acornFoxControlPlaneProvisionerFake{}
	service, prepared := newAcornFoxControlPlanePrepared(t, ledger, runner)
	if _, err := service.migrate(context.Background()); !errors.Is(err, ErrAcornFoxControlPlaneConflict) {
		t.Fatalf("gap err=%v", err)
	}
	prepared.assertExternalSentinel(t)
}

func TestEnsureAcornFoxControlPlaneLedgerAcceptsAmbiguousExactCommit(t *testing.T) {
	migrations := acornFoxControlPlaneMigrations{rows: []MigrationRow{{Version: "0001_foundation", Checksum: acornFoxFixtureDigest("a")}}, sql: []string{"SELECT 1"}}
	// The shared validator intentionally requires the closed 33-member table;
	// use the manifest fixture to exercise the real ambiguous-commit path.
	ledger, runner := &acornFoxControlPlaneLedgerFake{failCommit: true}, &acornFoxControlPlaneProvisionerFake{}
	service, _ := newAcornFoxControlPlanePrepared(t, ledger, runner)
	_, err := service.migrate(context.Background())
	if err != nil || len(ledger.rows) != 33 || migrations.valid() {
		t.Fatalf("ambiguous err=%v rows=%d", err, len(ledger.rows))
	}
}

func TestEnsureAcornFoxControlPlaneLedgerAcceptsOnlyExactPrefixes(t *testing.T) {
	seed, runner := &acornFoxControlPlaneLedgerFake{}, &acornFoxControlPlaneProvisionerFake{}
	service, _ := newAcornFoxControlPlanePrepared(t, seed, runner)
	_, migrations, err := service.authority(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []int{0, 1, 32, 33} {
		t.Run("prefix", func(t *testing.T) {
			ledger := &acornFoxControlPlaneLedgerFake{rows: append([]MigrationRow(nil), migrations.rows[:prefix]...)}
			if err := ensureAcornFoxControlPlaneLedger(context.Background(), ledger, migrations); err != nil || !matchesExpected(ledger.rows, migrations.rows) {
				t.Fatalf("prefix=%d err=%v rows=%d", prefix, err, len(ledger.rows))
			}
		})
	}
	for _, rows := range [][]MigrationRow{
		append([]MigrationRow{migrations.rows[0], migrations.rows[2]}, migrations.rows[3:]...),
		append(append([]MigrationRow(nil), migrations.rows...), migrations.rows[0]),
		append([]MigrationRow{{Version: migrations.rows[0].Version, Checksum: acornFoxFixtureDigest("f")}}, migrations.rows[1:]...),
	} {
		if err := ensureAcornFoxControlPlaneLedger(context.Background(), &acornFoxControlPlaneLedgerFake{rows: rows}, migrations); !errors.Is(err, ErrAcornFoxControlPlaneConflict) {
			t.Fatalf("non-prefix err=%v", err)
		}
	}
}
