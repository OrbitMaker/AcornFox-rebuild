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
	argv    []string
	stdin   []byte
	err     error
	started chan struct{}
	resume  <-chan struct{}
}

func (f *acornFoxControlPlaneProvisionerFake) Run(_ context.Context, argv []string, stdin []byte) error {
	f.argv, f.stdin = append([]string(nil), argv...), append([]byte(nil), stdin...)
	if f.started != nil {
		close(f.started)
	}
	if f.resume != nil {
		<-f.resume
	}
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
	service.expectedIdentity = AcornFoxBuildIdentityV1{SchemaVersion: AcornFoxHelperContractV1Schema, Product: AcornFoxV1Product, LayoutVersion: AcornFoxSubstrateLayoutV1, Role: "upgrade", Version: prepared.published.receipt.CandidateReceipt.Version, ReleaseID: prepared.published.receipt.CandidateReceipt.ReleaseID, SourceCommit: prepared.published.receipt.CandidateReceipt.SourceCommit}
	service.bridge.ownership = prepared.owners.edge()
	return service, prepared
}

func writeAcornFoxControlPlaneStateEnv(t *testing.T, prepared acornFoxProductionPreparedFixture, raw []byte) {
	t.Helper()
	writer, err := TaskDurableWriter(prepared.state, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.CreateMetadata(acornFoxControlPlaneStateEnv, raw); err != nil {
		t.Fatal(err)
	}
}

func writeAcornFoxControlPlaneStateReceipt(t *testing.T, prepared acornFoxProductionPreparedFixture, raw []byte) {
	t.Helper()
	writer, err := TaskDurableWriter(prepared.state, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.CreateMetadata(acornFoxControlPlaneReceipt, raw); err != nil {
		t.Fatal(err)
	}
}

func writeAcornFoxControlPlaneActivationEnv(t *testing.T, prepared acornFoxProductionPreparedFixture, raw []byte) {
	t.Helper()
	activation, err := AcornFoxRepoActivationID(prepared.binding)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(prepared.host, "opt", "acornfox", "activations", activation)
	writer, err := TaskDurableWriter(path, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.CreateMetadata(acornFoxControlPlaneActivationEnv, raw); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(path, acornFoxControlPlaneActivationEnv))
	if err != nil {
		t.Fatal(err)
	}
	prepared.owners.set(info, acornFoxInstallPrincipal{})
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

func TestAcornFoxControlPlaneMigrationSerializesFixedRepositoryLock(t *testing.T) {
	ledger := &acornFoxControlPlaneLedgerFake{}
	resume := make(chan struct{})
	runner := &acornFoxControlPlaneProvisionerFake{started: make(chan struct{}), resume: resume}
	service, prepared := newAcornFoxControlPlanePrepared(t, ledger, runner)
	firstDone := make(chan error, 1)
	go func() {
		_, err := service.migrate(context.Background())
		firstDone <- err
	}()
	<-runner.started // provision is a C1 effect; the fixed repo lock is held now.

	otherRunner := &acornFoxControlPlaneProvisionerFake{}
	other, err := newTaskAcornFoxControlPlane(prepared.layout, bytes.NewReader(bytes.Repeat([]byte{9}, 32)), otherRunner, func([]byte) (BootstrapMigrationControl, error) { return ledger, nil })
	if err != nil {
		t.Fatal(err)
	}
	other.expectedIdentity = service.expectedIdentity
	other.bridge.ownership = prepared.owners.edge()
	if _, err := other.migrate(context.Background()); !errors.Is(err, ErrAcornFoxRepoLocked) {
		t.Fatalf("concurrent migration err=%v", err)
	}
	close(resume)
	if err := <-firstDone; err != nil {
		t.Fatalf("first migration err=%v", err)
	}
	activation, err := AcornFoxRepoActivationID(prepared.binding)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(prepared.host, "opt", "acornfox", "activations", activation, acornFoxControlPlaneActivationEnv))
	if err != nil {
		t.Fatal(err)
	}
	prepared.owners.set(info, acornFoxInstallPrincipal{})
	if _, err := other.migrate(context.Background()); err != nil {
		t.Fatalf("migration after lock release err=%v", err)
	}
	prepared.assertExternalSentinel(t)
}

func TestAcornFoxControlPlaneMigrationReleasesLockAfterFailure(t *testing.T) {
	ledger, runner := &acornFoxControlPlaneLedgerFake{}, &acornFoxControlPlaneProvisionerFake{err: errors.New("provision failed")}
	service, prepared := newAcornFoxControlPlanePrepared(t, ledger, runner)
	if _, err := service.migrate(context.Background()); !errors.Is(err, ErrAcornFoxControlPlaneUnknown) {
		t.Fatalf("migration err=%v", err)
	}
	other, err := newAcornFoxRepoStoreForLayout(prepared.layout)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	other.ownership = prepared.owners.edge()
	lock, err := other.Acquire(context.Background())
	if err != nil {
		t.Fatalf("fixed lock remained held after failure: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	prepared.assertExternalSentinel(t)
}

func TestAcornFoxControlPlaneRejectsHelperIdentityBeforeEffectsAndAllowsCurrentBinding(t *testing.T) {
	ledger, runner := &acornFoxControlPlaneLedgerFake{}, &acornFoxControlPlaneProvisionerFake{}
	service, prepared := newAcornFoxControlPlanePrepared(t, ledger, runner)
	openCalls := 0
	service.open = func([]byte) (BootstrapMigrationControl, error) {
		openCalls++
		return ledger, nil
	}
	wrong := service.expectedIdentity
	wrong.Version = "1.2.4-test.1"
	wrong.ReleaseID = "release-1.2.4-test.1"
	if _, err := service.migrateWithIdentity(context.Background(), wrong); !errors.Is(err, ErrAcornFoxControlPlaneConflict) {
		t.Fatalf("mismatched helper identity err=%v", err)
	}
	activation, err := AcornFoxRepoActivationID(prepared.binding)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(prepared.state, acornFoxControlPlaneStateEnv),
		filepath.Join(prepared.state, acornFoxControlPlaneReceipt),
		filepath.Join(prepared.host, "opt", "acornfox", "activations", activation, acornFoxControlPlaneActivationEnv),
	} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("identity mismatch wrote %s: %v", path, err)
		}
	}
	if len(runner.argv) != 0 || openCalls != 0 || len(ledger.rows) != 0 {
		t.Fatalf("identity mismatch effects argv=%q open=%d rows=%d", runner.argv, openCalls, len(ledger.rows))
	}
	if _, err := service.migrate(context.Background()); err != nil {
		t.Fatalf("current locked binding should migrate: %v", err)
	}
	prepared.assertExternalSentinel(t)
}

func TestAcornFoxControlPlaneRejectsInvalidHelperIdentityBeforePreparedVerification(t *testing.T) {
	ledger, runner := &acornFoxControlPlaneLedgerFake{}, &acornFoxControlPlaneProvisionerFake{}
	service, prepared := newAcornFoxControlPlanePrepared(t, ledger, runner)
	openCalls := 0
	service.open = func([]byte) (BootstrapMigrationControl, error) {
		openCalls++
		return ledger, nil
	}
	invalid := service.expectedIdentity
	invalid.Role = "healthcheck"
	if _, err := service.migrateWithIdentity(context.Background(), invalid); !errors.Is(err, ErrAcornFoxControlPlaneUnknown) {
		t.Fatalf("invalid helper identity err=%v", err)
	}
	if len(runner.argv) != 0 || openCalls != 0 || len(ledger.rows) != 0 {
		t.Fatalf("invalid helper identity effects argv=%q open=%d rows=%d", runner.argv, openCalls, len(ledger.rows))
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

func TestAcornFoxControlPlaneResumesStateOnlyEnvironmentWithoutNewSecret(t *testing.T) {
	ledger, runner := &acornFoxControlPlaneLedgerFake{}, &acornFoxControlPlaneProvisionerFake{}
	service, prepared := newAcornFoxControlPlanePrepared(t, ledger, runner)
	env, err := service.newEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	writeAcornFoxControlPlaneStateEnv(t, prepared, env)
	receipt, err := service.migrate(context.Background())
	if err != nil || receipt.Validate() != nil || len(ledger.rows) != 33 {
		t.Fatalf("receipt=%#v rows=%d err=%v", receipt, len(ledger.rows), err)
	}
	activation, _ := AcornFoxRepoActivationID(prepared.binding)
	got, err := os.ReadFile(filepath.Join(prepared.host, "opt", "acornfox", "activations", activation, acornFoxControlPlaneActivationEnv))
	if err != nil || !bytes.Equal(got, env) || len(runner.stdin) == 0 || bytes.Contains(runner.stdin, []byte("ACORNFOX_DATABASE_URL")) {
		t.Fatalf("activation=%q env=%q runner=%q err=%v", got, env, runner.stdin, err)
	}
	prepared.assertExternalSentinel(t)
}

func TestAcornFoxControlPlaneStateOnlyRetriesAfterActivationFailure(t *testing.T) {
	ledger, runner := &acornFoxControlPlaneLedgerFake{}, &acornFoxControlPlaneProvisionerFake{}
	service, prepared := newAcornFoxControlPlanePrepared(t, ledger, runner)
	env, err := service.newEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	writeAcornFoxControlPlaneStateEnv(t, prepared, env)
	activation, _ := AcornFoxRepoActivationID(prepared.binding)
	directory := filepath.Join(prepared.host, "opt", "acornfox", "activations", activation)
	write := service.writeActivation
	service.writeActivation = func(*DurableWriter, []byte) error { return errors.New("injected activation publish failure") }
	if _, err := service.migrate(context.Background()); !errors.Is(err, ErrAcornFoxControlPlaneUnknown) || len(ledger.rows) != 0 || len(runner.argv) != 0 {
		t.Fatalf("failed create err=%v rows=%d argv=%q", err, len(ledger.rows), runner.argv)
	}
	service.writeActivation = func(writer *DurableWriter, raw []byte) error {
		if err := writer.CreateMetadata(acornFoxControlPlaneActivationEnv, raw); err != nil {
			return err
		}
		return errors.New("injected uncertain activation publish")
	}
	if _, err := service.migrate(context.Background()); !errors.Is(err, ErrAcornFoxControlPlaneUnknown) || len(ledger.rows) != 0 || len(runner.argv) != 0 {
		t.Fatalf("uncertain create err=%v rows=%d argv=%q", err, len(ledger.rows), runner.argv)
	}
	// This models an uncertain publish result: the exact activation bytes are
	// now visible before retry. The retry must reread and converge, not mint a
	// different secret or try to replace the durable file.
	service.writeActivation = write
	got, err := os.ReadFile(filepath.Join(directory, acornFoxControlPlaneActivationEnv))
	if err != nil || !bytes.Equal(got, env) {
		t.Fatalf("uncertain artifact=%q env=%q err=%v", got, env, err)
	}
	info, err := os.Lstat(filepath.Join(directory, acornFoxControlPlaneActivationEnv))
	if err != nil {
		t.Fatal(err)
	}
	prepared.owners.set(info, acornFoxInstallPrincipal{})
	if _, err := service.migrate(context.Background()); err != nil || len(ledger.rows) != 33 {
		t.Fatalf("exact retry err=%v rows=%d", err, len(ledger.rows))
	}
	prepared.assertExternalSentinel(t)
}

func TestAcornFoxControlPlaneRejectsActivationOnlyAndUnequalCopies(t *testing.T) {
	for _, test := range []struct {
		name  string
		state bool
		other bool
	}{
		{name: "activation only"},
		{name: "unequal", state: true, other: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ledger, runner := &acornFoxControlPlaneLedgerFake{}, &acornFoxControlPlaneProvisionerFake{}
			service, prepared := newAcornFoxControlPlanePrepared(t, ledger, runner)
			first, err := service.newEnvironment()
			if err != nil {
				t.Fatal(err)
			}
			second := append([]byte(nil), first...)
			second[len(second)-2] = 'A'
			if test.state {
				writeAcornFoxControlPlaneStateEnv(t, prepared, first)
			}
			writeAcornFoxControlPlaneActivationEnv(t, prepared, func() []byte {
				if test.other {
					return second
				}
				return first
			}())
			if _, err := service.migrate(context.Background()); !errors.Is(err, ErrAcornFoxControlPlaneConflict) || len(ledger.rows) != 0 || len(runner.argv) != 0 {
				t.Fatalf("err=%v rows=%d argv=%q", err, len(ledger.rows), runner.argv)
			}
			prepared.assertExternalSentinel(t)
		})
	}
}

func TestAcornFoxControlPlaneEnvironmentRejectsKeyAndQueryDrift(t *testing.T) {
	service, _ := newAcornFoxControlPlanePrepared(t, &acornFoxControlPlaneLedgerFake{}, &acornFoxControlPlaneProvisionerFake{})
	valid, err := service.newEnvironment()
	if err != nil || !validAcornFoxControlPlaneEnvironment(valid) {
		t.Fatalf("valid env=%q err=%v", valid, err)
	}
	for _, raw := range [][]byte{
		bytes.Replace(valid, []byte("ACORNFOX_DATABASE_URL="), []byte("OPEN_CARD_DATABASE_URL="), 1),
		bytes.Replace(valid, []byte("sslmode=disable"), []byte("sslmode=disable&x=1"), 1),
		bytes.Replace(valid, []byte("sslmode=disable"), []byte("sslmode=require"), 1),
		append(append([]byte(nil), valid[:len(valid)-1]...), []byte("\nextra\n")...),
	} {
		if validAcornFoxControlPlaneEnvironment(raw) {
			t.Fatalf("drift accepted: %q", raw)
		}
	}
}

func TestAcornFoxControlPlaneReceiptFailureAndExactRetry(t *testing.T) {
	for _, test := range []struct {
		name      string
		write     func(*DurableWriter, []byte) error
		wasStored bool
	}{
		{name: "hard failure", write: func(*DurableWriter, []byte) error { return errors.New("injected receipt failure") }},
		{name: "uncertain exact", wasStored: true, write: func(writer *DurableWriter, raw []byte) error {
			if err := writer.CreateMetadata(acornFoxControlPlaneReceipt, raw); err != nil {
				return err
			}
			return errors.New("injected receipt uncertainty")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ledger, runner := &acornFoxControlPlaneLedgerFake{}, &acornFoxControlPlaneProvisionerFake{}
			service, prepared := newAcornFoxControlPlanePrepared(t, ledger, runner)
			write := service.writeReceipt
			service.writeReceipt = test.write
			if _, err := service.migrate(context.Background()); !errors.Is(err, ErrAcornFoxControlPlaneUnknown) || len(ledger.rows) != 33 {
				t.Fatalf("first err=%v rows=%d", err, len(ledger.rows))
			}
			activation, _ := AcornFoxRepoActivationID(prepared.binding)
			info, err := os.Lstat(filepath.Join(prepared.host, "opt", "acornfox", "activations", activation, acornFoxControlPlaneActivationEnv))
			if err != nil {
				t.Fatal(err)
			}
			prepared.owners.set(info, acornFoxInstallPrincipal{})
			service.writeReceipt = write
			receipt, err := service.migrate(context.Background())
			if err != nil || receipt.Validate() != nil || len(ledger.rows) != 33 {
				t.Fatalf("retry receipt=%#v err=%v rows=%d stored=%t", receipt, err, len(ledger.rows), test.wasStored)
			}
			prepared.assertExternalSentinel(t)
		})
	}
}

func TestAcornFoxControlPlaneRejectsStaleReceiptIdentity(t *testing.T) {
	for _, field := range []string{"binding", "release", "source", "rows", "env", "identity"} {
		t.Run(field, func(t *testing.T) {
			ledger, runner := &acornFoxControlPlaneLedgerFake{}, &acornFoxControlPlaneProvisionerFake{}
			service, prepared := newAcornFoxControlPlanePrepared(t, ledger, runner)
			env, err := service.newEnvironment()
			if err != nil {
				t.Fatal(err)
			}
			writeAcornFoxControlPlaneStateEnv(t, prepared, env)
			authority, migrations, err := service.authority(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			receipt := AcornFoxControlPlaneMigrationReceiptV1{SchemaVersion: 1, State: "CONTROL_PLANE_MIGRATED", BindingSHA256: authority.binding, ReleaseID: authority.releaseID, SourceCommit: authority.sourceCommit, MigrationVersion: AcornFoxV1MigrationVersion, MigrationRowsSHA256: acornFoxMigrationRowsSHA256(migrations.rows), DatabaseEnvSHA256: sha256Bytes(env), DatabaseIdentitySHA256: acornFoxControlPlaneIdentitySHA256()}
			switch field {
			case "binding":
				receipt.BindingSHA256 = acornFoxFixtureDigest("f")
			case "release":
				receipt.ReleaseID = "release-wrong"
			case "source":
				receipt.SourceCommit = strings.Repeat("f", 40)
			case "rows":
				receipt.MigrationRowsSHA256 = acornFoxFixtureDigest("f")
			case "env":
				receipt.DatabaseEnvSHA256 = acornFoxFixtureDigest("f")
			case "identity":
				receipt.DatabaseIdentitySHA256 = acornFoxFixtureDigest("f")
			}
			raw, err := MarshalAcornFoxControlPlaneMigrationReceiptV1(receipt)
			if err != nil {
				t.Fatal(err)
			}
			writeAcornFoxControlPlaneStateReceipt(t, prepared, raw)
			if _, err := service.migrate(context.Background()); !errors.Is(err, ErrAcornFoxControlPlaneConflict) || len(ledger.rows) != 0 || len(runner.argv) != 0 {
				t.Fatalf("field=%s err=%v rows=%d argv=%q", field, err, len(ledger.rows), runner.argv)
			}
			prepared.assertExternalSentinel(t)
		})
	}
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
