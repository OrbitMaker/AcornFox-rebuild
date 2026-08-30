package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/install"
)

const testTransaction = "upgrade-cli-test"
const testRelease = "release-cli-test"
const testManifest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func cliIdentity(t *testing.T) install.UpgradeCLIIdentity {
	t.Helper()
	identity, err := testIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func testIdentity() (install.UpgradeCLIIdentity, error) {
	return install.DeriveUpgradeCLIIdentity(testTransaction, install.VerifiedUpgradeReleaseV1{Release: install.ReleaseV1{ID: testRelease, Version: install.ProductionCandidateVersion, SourceCommit: "0123456789abcdef0123456789abcdef01234567", Architecture: "amd64", ManifestSHA256: testManifest}, UpgradeExecutableSHA256: testManifest})
}

func cliArgs(command string) []string {
	return []string{command, "--transaction-id", testTransaction, "--release-id", testRelease, "--manifest-sha256", testManifest, "--expect-layout", "native"}
}

func testDependencies(runtime upgradeRuntime) upgradeDependencies {
	constructor := func(context.Context) (upgradeRuntime, error) { return runtime, nil }
	return upgradeDependencies{
		euid:             func() int { return 0 },
		derive:           func(upgradeCommandConfig) (install.UpgradeCLIIdentity, error) { return testIdentity() },
		newRuntime:       constructor,
		newStatusRuntime: constructor,
	}
}

func TestParseUpgradeArgsIsExactAndForbidsDangerousInputs(t *testing.T) {
	valid := cliArgs("run")
	config, err := parseUpgradeArgs(valid)
	if err != nil || config.command != "run" || config.expectLegacy || config.transactionID != testTransaction {
		t.Fatalf("valid parse failed: %#v %v", config, err)
	}
	for _, args := range [][]string{
		{"run"},
		append(append([]string{}, valid...), "--task-root", "/tmp/x"),
		append(append([]string{}, valid...), "--manifest-sha256", testManifest),
		{"preflight", "--transaction-id", "../bad", "--release-id", testRelease, "--manifest-sha256", testManifest, "--expect-layout", "native"},
		{"recover", "--pending", "--transaction-id", testTransaction},
		{"status", "--release-id", testRelease},
		{"recover", "--transaction-id", "bad/tx"},
	} {
		if _, err := parseUpgradeArgs(args); err == nil {
			t.Fatalf("accepted forbidden args %#v", args)
		}
	}
	if config, err := parseUpgradeArgs([]string{"recover", "--pending"}); err != nil || !config.pending {
		t.Fatalf("pending parse failed: %#v %v", config, err)
	}
	if config, err := parseUpgradeArgs([]string{"prepare-control"}); err != nil || config.command != "prepare-control" {
		t.Fatalf("prepare-control parse failed: %#v %v", config, err)
	}
	for _, args := range [][]string{{"prepare-control", "--task-root", "/tmp/x"}, {"prepare-control", "--transaction-id", testTransaction}} {
		if _, err := parseUpgradeArgs(args); err == nil {
			t.Fatalf("prepare-control accepted flags %#v", args)
		}
	}
	for _, command := range []string{"recover-prepare", "recover-finalize"} {
		config, err := parseUpgradeArgs([]string{command, "--pending"})
		if err != nil || !config.pending || config.transactionID != "" {
			t.Fatalf("boot parse failed for %s: %#v %v", command, config, err)
		}
		for _, invalid := range [][]string{{command}, {command, "--transaction-id", testTransaction}, {command, "--pending", "--pending"}, {command, "--pending", "--task-root", "/tmp/x"}} {
			if _, err := parseUpgradeArgs(invalid); err == nil {
				t.Fatalf("accepted unsafe boot args %#v", invalid)
			}
		}
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"backup-create", "--backup-id", "backup-cli-1", "--reason", "manual"}, "backup-create"},
		{[]string{"backup-status", "--backup-id", "backup-cli-1"}, "backup-status"},
		{[]string{"restore-preflight", "--transaction-id", "restore-cli-1", "--backup-id", "backup-cli-1"}, "restore-preflight"},
		{[]string{"restore-run", "--transaction-id", "restore-cli-1", "--backup-id", "backup-cli-1"}, "restore-run"},
	} {
		config, err := parseUpgradeArgs(tc.args)
		if err != nil || config.command != tc.want || config.backupID != "backup-cli-1" {
			t.Fatalf("backup/restore parse failed: args=%#v config=%#v err=%v", tc.args, config, err)
		}
	}
	for _, args := range [][]string{
		{"backup-create", "--backup-id", "backup-cli-1", "--reason", "manual", "--path", "/tmp/x"},
		{"backup-create", "--backup-id", "not-a-backup", "--reason", "manual"},
		{"backup-status", "--backup-id", "../backup"},
		{"restore-preflight", "--transaction-id", "restore-cli-1", "--backup-id", "backup-cli-1", "--database-url", "postgres://secret@db/x"},
		{"restore-run", "--transaction-id", "restore-cli-1", "--backup-id", "backup-cli-1", "--backup-id", "backup-cli-1"},
	} {
		if _, err := parseUpgradeArgs(args); err == nil {
			t.Fatalf("accepted unsafe backup/restore args %#v", args)
		}
	}
}

func TestBackupAndRestoreCommandsStayTypedAndRedacted(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var backupRequest install.BackupCreateRequest
	var restoreRequest install.RestoreRequest
	runtime := upgradeRuntime{
		backupCreate: func(_ context.Context, request install.BackupCreateRequest) (install.ActiveDatabaseBackupV2, error) {
			backupRequest = request
			return install.ActiveDatabaseBackupV2{BackupID: request.BackupID}, nil
		},
		backupStatus: func(_ context.Context, backupID string) (install.ActiveDatabaseBackupV2, error) {
			return install.ActiveDatabaseBackupV2{BackupID: backupID}, nil
		},
		restorePreflight: func(_ context.Context, request install.RestoreRequest) (install.RestoreEligibilityV1, error) {
			restoreRequest = request
			return install.RestoreEligibilityV1{SchemaVersion: 1, TransactionID: request.TransactionID, BackupID: request.BackupID}, nil
		},
		restoreRun: func(_ context.Context, request install.RestoreRequest) error { restoreRequest = request; return nil },
		close:      func() error { return nil },
	}
	deps := testDependencies(runtime)
	deps.newBackupRuntime = func(context.Context) (upgradeRuntime, error) { return runtime, nil }
	for _, tc := range []struct{ args []string }{
		{[]string{"backup-create", "--backup-id", "backup-cli-1", "--reason", "manual"}},
		{[]string{"backup-status", "--backup-id", "backup-cli-1"}},
		{[]string{"restore-preflight", "--transaction-id", "restore-cli-1", "--backup-id", "backup-cli-1"}},
		{[]string{"restore-run", "--transaction-id", "restore-cli-1", "--backup-id", "backup-cli-1"}},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := runWithDependencies(context.Background(), tc.args, &stdout, &stderr, deps); code != exitOK || stderr.Len() != 0 || strings.Contains(stdout.String(), "postgres") {
			t.Fatalf("command failed: args=%#v code=%d out=%q err=%q", tc.args, code, stdout.String(), stderr.String())
		}
		if tc.args[0] == "restore-run" && (!strings.Contains(stdout.String(), "\"request_kind\":\"restore\"") || !strings.Contains(stdout.String(), "COMMITTED")) {
			t.Fatalf("restore run did not expose typed journal result: %q", stdout.String())
		}
	}
	if backupRequest.BackupID != "backup-cli-1" || backupRequest.Reason != "manual" || restoreRequest.TransactionID != "restore-cli-1" || restoreRequest.BackupID != "backup-cli-1" {
		t.Fatalf("typed requests were not preserved: backup=%+v restore=%+v", backupRequest, restoreRequest)
	}
	stdout.Reset()
	stderr.Reset()
	runtime.backupCreate = func(context.Context, install.BackupCreateRequest) (install.ActiveDatabaseBackupV2, error) {
		return install.ActiveDatabaseBackupV2{}, errors.New("postgres://secret@db/x")
	}
	deps.newBackupRuntime = func(context.Context) (upgradeRuntime, error) { return runtime, nil }
	if code := runWithDependencies(context.Background(), []string{"backup-create", "--backup-id", "backup-cli-1", "--reason", "manual"}, &stdout, &stderr, deps); code != exitInternal || strings.Contains(stdout.String()+stderr.String(), "secret") || !strings.Contains(stderr.String(), "backup_unavailable") {
		t.Fatalf("backup error leaked or had wrong code: code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
}

func TestBackupRestoreCommandsRequireRootBeforeRuntimeConstruction(t *testing.T) {
	for _, args := range [][]string{
		{"backup-create", "--backup-id", "backup-cli-1", "--reason", "manual"},
		{"backup-status", "--backup-id", "backup-cli-1"},
		{"restore-preflight", "--transaction-id", "restore-cli-1", "--backup-id", "backup-cli-1"},
		{"restore-run", "--transaction-id", "restore-cli-1", "--backup-id", "backup-cli-1"},
	} {
		var stdout, stderr bytes.Buffer
		called := false
		deps := upgradeDependencies{euid: func() int { return 99 }, newRuntime: func(context.Context) (upgradeRuntime, error) { called = true; return upgradeRuntime{}, nil }, newBackupRuntime: func(context.Context) (upgradeRuntime, error) { called = true; return upgradeRuntime{}, nil }}
		if code := runWithDependencies(context.Background(), args, &stdout, &stderr, deps); code != exitPrivilege || called || !strings.Contains(stderr.String(), "root_required") {
			t.Fatalf("command escaped root gate: args=%#v code=%d called=%v out=%q err=%q", args, code, called, stdout.String(), stderr.String())
		}
	}
}

func TestPrepareControlIsRootOnlyAndDoesNotConstructRuntime(t *testing.T) {
	var stdout, stderr bytes.Buffer
	constructed, prepared := false, false
	deps := upgradeDependencies{
		euid:             func() int { return 0 },
		verifyExecutable: func() error { return nil },
		prepareControl: func(context.Context) (string, error) {
			prepared = true
			return testManifest, nil
		},
		newRuntime: func(context.Context) (upgradeRuntime, error) {
			constructed = true
			return upgradeRuntime{}, nil
		},
	}
	if code := runWithDependencies(context.Background(), []string{"prepare-control"}, &stdout, &stderr, deps); code != exitOK || !prepared || constructed || stderr.Len() != 0 || !strings.Contains(stdout.String(), "control_identity_sha256") || strings.Contains(stdout.String(), "postgres") {
		t.Fatalf("prepare-control escaped its narrow boundary: code=%d prepared=%v constructed=%v out=%q err=%q", code, prepared, constructed, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	prepared = false
	deps.euid = func() int { return 99 }
	if code := runWithDependencies(context.Background(), []string{"prepare-control"}, &stdout, &stderr, deps); code != exitPrivilege || prepared || strings.Contains(stderr.String(), "postgres") {
		t.Fatalf("non-root prepare-control was accepted/leaked: code=%d prepared=%v out=%q err=%q", code, prepared, stdout.String(), stderr.String())
	}
}

func TestBootCommandsUseOnlyAtomicPendingPrepareAndRedactErrors(t *testing.T) {
	for _, tc := range []struct{ command string }{{"recover-prepare"}, {"recover-finalize"}} {
		t.Run(tc.command, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			prepareCalled, finalizeCalled := false, ""
			runtime := upgradeRuntime{pending: func(context.Context) (install.PendingTransaction, error) {
				return install.PendingTransaction{TransactionID: testTransaction, Marker: install.UpgradeMarkerSame}, nil
			}, close: func() error { return nil }}
			result := install.BootRecoveryResultV1{SchemaVersion: 1, TransactionID: testTransaction, State: install.JournalCommitted, MarkerRetained: true, FinalizeRequired: true}
			runtime.prepare = func(context.Context) (install.BootRecoveryResultV1, error) { prepareCalled = true; return result, nil }
			runtime.finalize = func(_ context.Context, tx string) (install.BootRecoveryResultV1, error) {
				finalizeCalled = tx
				return result, nil
			}
			deps := testDependencies(upgradeRuntime{})
			deps.newPrepareRuntime = func(context.Context) (upgradeRuntime, error) { return runtime, nil }
			deps.newFinalizeRuntime = func(context.Context) (upgradeRuntime, error) { return runtime, nil }
			if code := runWithDependencies(context.Background(), []string{tc.command, "--pending"}, &stdout, &stderr, deps); code != exitOK || stderr.Len() != 0 || !strings.Contains(stdout.String(), "COMMITTED") {
				t.Fatalf("boot command failed: code=%d out=%q err=%q", code, stdout.String(), stderr.String())
			}
			if tc.command == "recover-prepare" && (!prepareCalled || finalizeCalled != "") {
				t.Fatalf("prepare was not atomic-only: prepare=%v finalize=%q", prepareCalled, finalizeCalled)
			}
			if tc.command == "recover-finalize" && (prepareCalled || finalizeCalled != testTransaction) {
				t.Fatalf("finalize did not use pending marker: prepare=%v finalize=%q", prepareCalled, finalizeCalled)
			}
		})
	}
}

func TestRecoverPrepareWithoutMarkerIsReadOnlyNoOp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	prepareConstructor := false
	prepareCalls := false
	deps := testDependencies(upgradeRuntime{})
	deps.newPrepareRuntime = func(context.Context) (upgradeRuntime, error) {
		prepareConstructor = true
		return upgradeRuntime{prepare: func(context.Context) (install.BootRecoveryResultV1, error) {
			prepareCalls = true
			return install.BootRecoveryResultV1{SchemaVersion: 1, Skipped: true}, nil
		}, close: func() error { return nil }}, nil
	}
	if code := runWithDependencies(context.Background(), []string{"recover-prepare", "--pending"}, &stdout, &stderr, deps); code != exitOK || !prepareConstructor || !prepareCalls || stderr.Len() != 0 || !strings.Contains(stdout.String(), "\"skipped\":true") || !strings.Contains(stdout.String(), "\"marker_retained\":false") {
		t.Fatalf("no-marker prepare was not typed atomic no-op: code=%d constructed=%v called=%v out=%q err=%q", code, prepareConstructor, prepareCalls, stdout.String(), stderr.String())
	}
}

func TestBootCommandsRejectForeignOrUnknownPendingMarkerAndFinalizeAbsent(t *testing.T) {
	for _, tc := range []struct {
		command string
		pending install.PendingTransaction
	}{
		{"recover-finalize", install.PendingTransaction{Marker: install.UpgradeMarkerAbsent}},
		{"recover-finalize", install.PendingTransaction{Marker: install.UpgradeMarkerForeign}},
		{"recover-finalize", install.PendingTransaction{Marker: install.UpgradeMarkerUnknown}},
	} {
		t.Run(tc.command+"-"+string(tc.pending.Marker), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			called := false
			runtime := upgradeRuntime{pending: func(context.Context) (install.PendingTransaction, error) { return tc.pending, nil }, finalize: func(context.Context, string) (install.BootRecoveryResultV1, error) {
				called = true
				return install.BootRecoveryResultV1{}, nil
			}, close: func() error { return nil }}
			deps := testDependencies(upgradeRuntime{})
			deps.newFinalizeRuntime = func(context.Context) (upgradeRuntime, error) { return runtime, nil }
			if code := runWithDependencies(context.Background(), []string{tc.command, "--pending"}, &stdout, &stderr, deps); code != exitConflict || called || strings.Contains(stderr.String(), "foreign") {
				t.Fatalf("pending=%+v code=%d called=%v out=%q err=%q", tc.pending, code, called, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunParsesBeforePrivilegeAndRedactsErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false
	deps := upgradeDependencies{euid: func() int { return 99 }, newRuntime: func(context.Context) (upgradeRuntime, error) { called = true; return upgradeRuntime{}, nil }}
	if code := runWithDependencies(context.Background(), []string{"run", "--database-url", "postgres://password@host/db"}, &stdout, &stderr, deps); code != exitArgs || called || strings.Contains(stdout.String()+stderr.String(), "password") {
		t.Fatalf("invalid arguments leaked or constructed runtime: code=%d out=%q err=%q called=%v", code, stdout.String(), stderr.String(), called)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runWithDependencies(context.Background(), cliArgs("run"), &stdout, &stderr, deps); code != exitPrivilege || called || !strings.Contains(stderr.String(), "root_required") {
		t.Fatalf("privilege result incorrect: code=%d out=%q err=%q called=%v", code, stdout.String(), stderr.String(), called)
	}
}

func TestRunPreflightAndRunUseDerivedIdentity(t *testing.T) {
	identity := cliIdentity(t)
	var seen install.UpgradeRequest
	for _, command := range []string{"preflight", "run"} {
		var stdout, stderr bytes.Buffer
		seen = install.UpgradeRequest{}
		runtime := upgradeRuntime{
			preflight: func(_ context.Context, request install.UpgradeRequest) (install.UpgradeEligibilityV1, error) {
				seen = request
				return install.UpgradeEligibilityV1{SchemaVersion: 1, TransactionID: request.TransactionID, Layout: "native"}, nil
			},
			run:   func(_ context.Context, request install.UpgradeRequest) error { seen = request; return nil },
			close: func() error { return nil },
		}
		deps := testDependencies(runtime)
		deps.derive = func(config upgradeCommandConfig) (install.UpgradeCLIIdentity, error) {
			if config.releaseID != testRelease || config.manifestSHA256 != testManifest {
				t.Fatal("unexpected selector")
			}
			return identity, nil
		}
		if code := runWithDependencies(context.Background(), cliArgs(command), &stdout, &stderr, deps); code != exitOK || stderr.Len() != 0 || seen.CandidateActivationID != identity.Request.CandidateActivationID || seen.CandidateDatabaseName != identity.Request.CandidateDatabaseName || seen.RecoveryEvidenceSHA256 != identity.RecoveryEvidenceSHA256 || seen.RequestedManifestSHA256 != testManifest {
			t.Fatalf("%s failed: code=%d out=%q err=%q request=%#v", command, code, stdout.String(), stderr.String(), seen)
		}
		if !strings.Contains(stdout.String(), "\n") || strings.Count(stdout.String(), "\n") != 1 {
			t.Fatalf("%s output not one JSON line: %q", command, stdout.String())
		}
	}
}

func TestPreflightRejectsCandidateBinaryDigestBeforeEngine(t *testing.T) {
	identity := cliIdentity(t)
	called := false
	var stdout, stderr bytes.Buffer
	runtime := upgradeRuntime{preflight: func(context.Context, install.UpgradeRequest) (install.UpgradeEligibilityV1, error) {
		called = true
		return install.UpgradeEligibilityV1{}, nil
	}, close: func() error { return nil }}
	deps := testDependencies(runtime)
	deps.derive = func(upgradeCommandConfig) (install.UpgradeCLIIdentity, error) { return identity, nil }
	deps.verifyCandidateExecutable = func(digest string) error {
		if digest != identity.UpgradeExecutableSHA256 {
			t.Fatalf("unexpected binary digest %q", digest)
		}
		return errors.New("digest mismatch")
	}
	if code := runWithDependencies(context.Background(), cliArgs("preflight"), &stdout, &stderr, deps); code != exitIneligible || called || strings.Contains(stderr.String(), "digest mismatch") {
		t.Fatalf("candidate binary mismatch reached engine/leaked: code=%d called=%v out=%q err=%q", code, called, stdout.String(), stderr.String())
	}
}

func TestRunBuffersSuccessUntilCloseAndEmitsExactlyOneObject(t *testing.T) {
	identity := cliIdentity(t)
	var stdout, stderr bytes.Buffer
	runtime := upgradeRuntime{
		preflight: func(context.Context, install.UpgradeRequest) (install.UpgradeEligibilityV1, error) {
			return install.UpgradeEligibilityV1{SchemaVersion: 1, TransactionID: testTransaction, Layout: "native"}, nil
		},
		close: func() error { return errors.New("postgres://password@host") },
	}
	deps := testDependencies(runtime)
	deps.derive = func(upgradeCommandConfig) (install.UpgradeCLIIdentity, error) { return identity, nil }
	if code := runWithDependencies(context.Background(), cliArgs("preflight"), &stdout, &stderr, deps); code != exitInternal || stdout.Len() != 0 || strings.Count(stderr.String(), "\n") != 1 || !strings.Contains(stderr.String(), "runtime_close_failed") || strings.Contains(stderr.String(), "password") {
		t.Fatalf("close output was not singular/redacted: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRecoveryServiceStateParserIsClosed(t *testing.T) {
	valid := []byte("FragmentPath=/etc/systemd/system/open-card-upgrade-recover.service\nDropInPaths=\nNeedDaemonReload=no\nUnitFileState=static\n")
	if err := parseRecoveryServiceState(valid); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{
		[]byte("FragmentPath=/etc/systemd/system/open-card-upgrade-recover.service\nDropInPaths=/etc/systemd/system/x.conf\nNeedDaemonReload=no\nUnitFileState=static\n"),
		[]byte("FragmentPath=/etc/systemd/system/open-card-upgrade-recover.service\nDropInPaths=\nNeedDaemonReload=yes\nUnitFileState=static\n"),
		[]byte("FragmentPath=/etc/systemd/system/open-card-upgrade-recover.service\nDropInPaths=\nNeedDaemonReload=no\nUnitFileState=enabled\n"),
		[]byte("FragmentPath=/tmp/other\nDropInPaths=\nNeedDaemonReload=no\nUnitFileState=static\n"),
		[]byte("FragmentPath=/etc/systemd/system/open-card-upgrade-recover.service\nDropInPaths=\nNeedDaemonReload=no\nUnitFileState=static\nExecStart=/bin/sh -c unsafe\n"),
		[]byte("FragmentPath=/etc/systemd/system/open-card-upgrade-recover.service\nFragmentPath=/etc/systemd/system/open-card-upgrade-recover.service\nDropInPaths=\nNeedDaemonReload=no\nUnitFileState=static\n"),
	} {
		if err := parseRecoveryServiceState(raw); err == nil {
			t.Fatalf("accepted unsafe unit state %q", raw)
		}
	}
}

func TestSafeBootTargetActiveFence(t *testing.T) {
	commandFor := func(raw string) systemctlCommandFactory {
		return func(context.Context, string, ...string) *exec.Cmd {
			return exec.Command("/bin/sh", "-c", "printf '%b' \"$1\"", "sh", raw)
		}
	}
	for _, tc := range []struct {
		name          string
		raw           string
		requireActive bool
		want          bool
	}{
		{"normal-active", "UnitFileState=enabled\\nActiveState=active\\n", true, true},
		{"normal-inactive", "UnitFileState=enabled\\nActiveState=inactive\\n", true, false},
		{"normal-activating", "UnitFileState=enabled\\nActiveState=activating\\n", true, false},
		{"prepare-inactive", "UnitFileState=enabled\\nActiveState=inactive\\n", false, true},
		{"prepare-activating", "UnitFileState=enabled\\nActiveState=activating\\n", false, true},
		{"disabled", "UnitFileState=disabled\\nActiveState=active\\n", false, false},
		{"failed", "UnitFileState=enabled\\nActiveState=failed\\n", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifySafeBootTargetStateWithDependencies(context.Background(), commandFor(tc.raw), tc.requireActive)
			if (err == nil) != tc.want {
				t.Fatalf("raw=%q requireActive=%v err=%v", tc.raw, tc.requireActive, err)
			}
		})
	}
}

func TestBootGraphAcceptsSystemdDerivedDependenciesButRejectsOpenCardDrift(t *testing.T) {
	if !containsRequiredBootUnits("shutdown.target sysinit.target open-card-edge.service default.target open-card-upgrade-finalize.service basic.target open-card-server.service open-card-agent.service open-card-caddy.service open-card-buildkit.service", "open-card-buildkit.service", "open-card-caddy.service", "open-card-server.service", "open-card-agent.service", "open-card-edge.service", "open-card-upgrade-finalize.service") {
		t.Fatal("reordered systemd-derived target graph was rejected")
	}
	if !containsRequiredBootUnits("sysinit.target open-card-upgrade-safe.target shutdown.target", "open-card-upgrade-safe.target") {
		t.Fatal("derived business requirement was rejected")
	}
	for _, value := range []string{
		"sysinit.target open-card-edge.service",                               // missing required members
		"open-card-upgrade-recover.service open-card-foreign.service",         // foreign Open Card edge
		"open-card-upgrade-recover.service open-card-upgrade-recover.service", // duplicate
		"open-card-upgrade-recover.service ../unsafe.service",                 // malformed
	} {
		if containsRequiredBootUnits(value, "open-card-upgrade-recover.service") {
			t.Fatalf("accepted unsafe graph property %q", value)
		}
	}
	if _, err := parseSystemctlProperties([]byte("Requires=open-card-upgrade-recover.service\nRequires=open-card-upgrade-recover.service\n"), []string{"Requires"}); err == nil {
		t.Fatal("duplicate systemctl property was accepted")
	}
}

func TestSystemctlTrustRejectsUnsafeLeafBeforeAnyExec(t *testing.T) {
	for name, info := range map[string]os.FileInfo{
		"wrong-mode":  cliFileInfo{mode: 0o777, uid: 0, gid: 0},
		"wrong-owner": cliFileInfo{mode: 0o755, uid: 1, gid: 0},
		"symlink":     cliFileInfo{mode: os.ModeSymlink | 0o777, uid: 0, gid: 0},
	} {
		if trustedSystemctlInfo(info) {
			t.Fatalf("accepted %s", name)
		}
	}
	called := false
	err := verifyRecoveryServiceStateWithDependencies(context.Background(), func() error { return errors.New("unsafe systemctl") }, func(context.Context, string, ...string) *exec.Cmd {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatalf("unsafe systemctl reached exec: err=%v called=%v", err, called)
	}
}

type cliFileInfo struct {
	mode     os.FileMode
	uid, gid uint32
}

func (i cliFileInfo) Name() string       { return "systemctl" }
func (i cliFileInfo) Size() int64        { return 0 }
func (i cliFileInfo) Mode() os.FileMode  { return i.mode }
func (i cliFileInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (i cliFileInfo) IsDir() bool        { return false }
func (i cliFileInfo) Sys() any           { return &syscall.Stat_t{Uid: i.uid, Gid: i.gid} }

func TestRecoverPendingAndTerminalDisposition(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := ""
	runtime := upgradeRuntime{
		pending: func(context.Context) (install.PendingTransaction, error) {
			return install.PendingTransaction{TransactionID: testTransaction, Marker: install.UpgradeMarkerSame}, nil
		},
		recover: func(_ context.Context, tx string) error {
			called = tx
			return install.UpgradePhaseError{Phase: install.JournalAbortedPreSwitch, Code: "recovered"}
		},
		status: func(context.Context, string) (install.UpgradeStatusV1, error) {
			return install.UpgradeStatusV1{TransactionID: testTransaction, State: install.JournalAbortedPreSwitch, Disposition: install.UpgradeStatusTerminal}, nil
		},
		close: func() error { return nil },
	}
	deps := testDependencies(runtime)
	if code := runWithDependencies(context.Background(), []string{"recover", "--pending"}, &stdout, &stderr, deps); code != exitOK || called != testTransaction || stderr.Len() != 0 || !strings.Contains(stdout.String(), "ABORTED_PRE_SWITCH") {
		t.Fatalf("recover did not accept terminal rollback: code=%d called=%q out=%q err=%q", code, called, stdout.String(), stderr.String())
	}
}

func TestStatusIsReadOnlyAndPendingDoesNotConstructIdentity(t *testing.T) {
	var stdout, stderr bytes.Buffer
	derived := false
	statusCalls := 0
	runtime := upgradeRuntime{
		pending: func(context.Context) (install.PendingTransaction, error) {
			return install.PendingTransaction{Marker: install.UpgradeMarkerAbsent}, nil
		},
		status: func(context.Context, string) (install.UpgradeStatusV1, error) {
			statusCalls++
			return install.UpgradeStatusV1{}, nil
		},
		close: func() error { return nil },
	}
	deps := testDependencies(runtime)
	deps.derive = func(upgradeCommandConfig) (install.UpgradeCLIIdentity, error) {
		derived = true
		return install.UpgradeCLIIdentity{}, nil
	}
	if code := runWithDependencies(context.Background(), []string{"status", "--pending"}, &stdout, &stderr, deps); code != exitOK || derived || statusCalls != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "absent") {
		t.Fatalf("pending status used mutable path: code=%d derived=%v calls=%d out=%q err=%q", code, derived, statusCalls, stdout.String(), stderr.String())
	}
}

func TestStatusUsesDedicatedStoreOnlyConstructor(t *testing.T) {
	var stdout, stderr bytes.Buffer
	serviceConstructor := false
	storeConstructor := false
	deps := upgradeDependencies{
		euid: func() int { return 0 },
		newRuntime: func(context.Context) (upgradeRuntime, error) {
			serviceConstructor = true
			return upgradeRuntime{}, errors.New("must not construct services")
		},
		newStatusRuntime: func(context.Context) (upgradeRuntime, error) {
			storeConstructor = true
			return upgradeRuntime{
				pending: func(context.Context) (install.PendingTransaction, error) {
					return install.PendingTransaction{Marker: install.UpgradeMarkerAbsent}, nil
				},
				status: func(context.Context, string) (install.UpgradeStatusV1, error) { return install.UpgradeStatusV1{}, nil },
				close:  func() error { return nil },
			}, nil
		},
	}
	if code := runWithDependencies(context.Background(), []string{"status", "--pending"}, &stdout, &stderr, deps); code != exitOK || !storeConstructor || serviceConstructor || stderr.Len() != 0 {
		t.Fatalf("status constructor boundary failed: code=%d store=%v service=%v out=%q err=%q", code, storeConstructor, serviceConstructor, stdout.String(), stderr.String())
	}
}

func TestRunPassesSignalCancellationToEngine(t *testing.T) {
	identity := cliIdentity(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	var stdout, stderr bytes.Buffer
	runtime := upgradeRuntime{
		preflight: func(got context.Context, _ install.UpgradeRequest) (install.UpgradeEligibilityV1, error) {
			called = true
			if got.Err() == nil {
				t.Fatal("cancellation was not propagated")
			}
			return install.UpgradeEligibilityV1{}, install.UpgradePhaseError{Phase: install.JournalPreflighted, Code: "cancelled"}
		},
		close: func() error { return nil },
	}
	deps := testDependencies(runtime)
	deps.derive = func(upgradeCommandConfig) (install.UpgradeCLIIdentity, error) { return identity, nil }
	if code := runWithDependencies(ctx, cliArgs("preflight"), &stdout, &stderr, deps); code != exitIneligible || !called || strings.Contains(stderr.String(), "cancelled") {
		t.Fatalf("cancelled preflight leaked or did not run: code=%d called=%v out=%q err=%q", code, called, stdout.String(), stderr.String())
	}
}

func TestErrorMappingAndClosePrecedence(t *testing.T) {
	identity := cliIdentity(t)
	var stdout, stderr bytes.Buffer
	closed := 0
	runtime := upgradeRuntime{
		run:   func(context.Context, install.UpgradeRequest) error { return install.ErrUpgradeLocked },
		close: func() error { closed++; return errors.New("postgres://secret") },
	}
	deps := testDependencies(runtime)
	deps.derive = func(upgradeCommandConfig) (install.UpgradeCLIIdentity, error) { return identity, nil }
	if code := runWithDependencies(context.Background(), cliArgs("run"), &stdout, &stderr, deps); code != exitLocked || closed != 1 || !strings.Contains(stderr.String(), "upgrade_locked") || strings.Contains(stderr.String(), "secret") {
		t.Fatalf("primary error was replaced/leaked: code=%d closed=%d out=%q err=%q", code, closed, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	runtime.preflight = func(context.Context, install.UpgradeRequest) (install.UpgradeEligibilityV1, error) {
		return install.UpgradeEligibilityV1{SchemaVersion: 1}, nil
	}
	runtime.run = nil
	deps = testDependencies(runtime)
	deps.derive = func(upgradeCommandConfig) (install.UpgradeCLIIdentity, error) { return identity, nil }
	if code := runWithDependencies(context.Background(), cliArgs("preflight"), &stdout, &stderr, deps); code != exitInternal || !strings.Contains(stderr.String(), "runtime_close_failed") || strings.Contains(stderr.String(), "secret") {
		t.Fatalf("close failure not surfaced safely: code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	runtime = upgradeRuntime{run: func(context.Context, install.UpgradeRequest) error {
		return install.UpgradePhaseError{Phase: install.JournalCommitted, Code: "edge_failed"}
	}, close: func() error { return nil }}
	deps = testDependencies(runtime)
	deps.derive = func(upgradeCommandConfig) (install.UpgradeCLIIdentity, error) { return identity, nil }
	if code := runWithDependencies(context.Background(), cliArgs("run"), &stdout, &stderr, deps); code != exitRecovery || !strings.Contains(stderr.String(), "upgrade_incomplete") {
		t.Fatalf("incomplete upgrade had wrong disposition: code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
}

func TestProductionRuntimeConstructsAndClosesInFixedOrder(t *testing.T) {
	events := []string{}
	store := &cliStoreFake{}
	deps := productionRuntimeDependencies{
		verifyExecutable:   func() error { events = append(events, "executable"); return nil },
		verifyRecoveryUnit: func() error { events = append(events, "unit"); return nil },
		openStore: func() (upgradeRuntimeStore, error) {
			events = append(events, "store")
			return upgradeRuntimeStore{store: store, status: func(context.Context, string) (install.UpgradeStatusV1, error) { return install.UpgradeStatusV1{}, nil }, pending: func(context.Context) (install.PendingTransaction, error) { return install.PendingTransaction{}, nil }, close: func() error { events = append(events, "store-close"); return nil }}, nil
		},
		openService: func() (install.UpgradeServiceDriver, func() error, error) {
			events = append(events, "service")
			return &cliServiceFake{}, func() error { events = append(events, "service-close"); return errors.New("service close") }, nil
		},
		openBackupInspector: func() (install.UpgradeBackupInspector, func() error, error) {
			events = append(events, "backup")
			return cliBackupInspectorFake{}, func() error { events = append(events, "backup-close"); return nil }, nil
		},
		databaseFactory: install.UpgradeDatabaseOpenFunc(func(context.Context, install.UpgradeDatabaseOpenRequest) (install.UpgradeDatabaseSession, error) {
			return nil, errors.New("not used")
		}),
		now: func() time.Time { return time.Unix(1, 0) },
	}
	deps.verifyRecoveryServiceState = func(context.Context) error { events = append(events, "unit-state"); return nil }
	runtime, err := newProductionRuntimeWithDependencies(context.Background(), deps)
	if err != nil || strings.Join(events, ",") != "executable,unit,unit-state,store,service,backup" {
		t.Fatalf("constructor order failed: %v %v", events, err)
	}
	if err := runtime.close(); err == nil || strings.Join(events, ",") != "executable,unit,unit-state,store,service,backup,backup-close,service-close,store-close" {
		t.Fatalf("close order/precedence failed: %v %v", events, err)
	}
}

func TestProductionRuntimeRejectsRecoveryUnitServiceStateBeforeStore(t *testing.T) {
	calledStore := false
	deps := productionRuntimeDependencies{
		verifyExecutable:           func() error { return nil },
		verifyRecoveryUnit:         func() error { return nil },
		verifyRecoveryServiceState: func(context.Context) error { return errors.New("drop-in") },
		openStore: func() (upgradeRuntimeStore, error) {
			calledStore = true
			return upgradeRuntimeStore{}, nil
		},
		openService:     func() (install.UpgradeServiceDriver, func() error, error) { return nil, nil, errors.New("not used") },
		databaseFactory: install.NewProductionUpgradeDatabaseFactory(),
		now:             func() time.Time { return time.Unix(1, 0) },
	}
	if _, err := newProductionRuntimeWithDependencies(context.Background(), deps); err == nil || calledStore {
		t.Fatalf("unsafe recovery unit state reached store: err=%v called=%v", err, calledStore)
	}
}

func TestMutableRuntimeRequiresActiveSafeTargetBeforeOpeningStore(t *testing.T) {
	for _, tc := range []struct {
		name       string
		fenceError error
		wantStore  bool
	}{
		{"inactive-target", errors.New("safe target inactive"), false},
		{"active-target", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			openedStore := false
			deps := productionRuntimeDependencies{
				verifyExecutable:   func() error { return nil },
				verifyRecoveryUnit: func() error { return nil },
				verifyRecoveryServiceState: func(context.Context) error {
					return tc.fenceError
				},
				openStore: func() (upgradeRuntimeStore, error) {
					openedStore = true
					return upgradeRuntimeStore{store: &cliStoreFake{}, status: func(context.Context, string) (install.UpgradeStatusV1, error) { return install.UpgradeStatusV1{}, nil }, pending: func(context.Context) (install.PendingTransaction, error) { return install.PendingTransaction{}, nil }, close: func() error { return nil }}, nil
				},
				openService: func() (install.UpgradeServiceDriver, func() error, error) {
					return &cliServiceFake{}, func() error { return nil }, nil
				},
				openBackupInspector: func() (install.UpgradeBackupInspector, func() error, error) {
					return cliBackupInspectorFake{}, func() error { return nil }, nil
				},
				databaseFactory: install.NewProductionUpgradeDatabaseFactory(),
				now:             func() time.Time { return time.Unix(1, 0).UTC() },
			}
			runtime, err := newProductionRuntimeWithDependencies(context.Background(), deps)
			if (err == nil) != tc.wantStore || openedStore != tc.wantStore {
				t.Fatalf("err=%v openedStore=%v", err, openedStore)
			}
			if runtime.close != nil {
				_ = runtime.close()
			}
		})
	}
}

type cliStoreFake struct{}

type cliBackupInspectorFake struct{}

func (cliBackupInspectorFake) Inspect(context.Context, string) (install.ActiveDatabaseBackupV2, error) {
	return install.ActiveDatabaseBackupV2{}, errors.New("not used")
}

func (*cliStoreFake) Acquire(context.Context, string) (install.UpgradeLock, error) {
	return nil, errors.New("not used")
}
func (*cliStoreFake) LoadJournal(context.Context, string) (install.UpgradeJournalV1, error) {
	return install.UpgradeJournalV1{}, errors.New("not used")
}
func (*cliStoreFake) ReadActualState(context.Context, string, string) (install.UpgradeActualState, error) {
	return install.UpgradeActualState{}, errors.New("not used")
}
func (*cliStoreFake) EnsureMarker(context.Context, string) error { return errors.New("not used") }
func (*cliStoreFake) PreflightPlan(context.Context, install.UpgradePreflightRequest) (install.UpgradePreflight, error) {
	return install.UpgradePreflight{}, errors.New("not used")
}
func (*cliStoreFake) PrepareLegacyProjection(context.Context, install.LegacyProjectionPlan, install.ActivationV1) (install.LegacyProjectionObservation, error) {
	return install.LegacyProjectionObservation{}, errors.New("not used")
}
func (*cliStoreFake) FinalizeLegacyProjection(context.Context, install.LegacyProjectionPlan, install.ActivationV1) (install.LegacyProjectionObservation, error) {
	return install.LegacyProjectionObservation{}, errors.New("not used")
}
func (*cliStoreFake) ReadLegacyProjection(context.Context, install.LegacyProjectionPlan, install.ActivationV1) (install.LegacyProjectionObservation, error) {
	return install.LegacyProjectionObservation{}, errors.New("not used")
}
func (*cliStoreFake) RecoverLegacyPlan(context.Context, install.ActivationV1, string) (install.LegacyProjectionPlan, error) {
	return install.LegacyProjectionPlan{}, errors.New("not used")
}
func (*cliStoreFake) PrepareEdgeConfig(context.Context, install.EdgeConfigTransitionPlan) (install.EdgeConfigObservationV1, error) {
	return install.EdgeConfigObservationV1{}, errors.New("not used")
}
func (*cliStoreFake) FinalizeEdgeConfig(context.Context, install.EdgeConfigTransitionPlan) (install.EdgeConfigObservationV1, error) {
	return install.EdgeConfigObservationV1{}, errors.New("not used")
}
func (*cliStoreFake) ReadEdgeConfig(context.Context, install.EdgeConfigTransitionPlan) (install.EdgeConfigObservationV1, error) {
	return install.EdgeConfigObservationV1{}, errors.New("not used")
}
func (*cliStoreFake) ReadActivationState(context.Context) (install.UpgradeActivationState, error) {
	return install.UpgradeActivationState{}, errors.New("not used")
}
func (*cliStoreFake) ReadActiveForRestore(context.Context) (install.ExistingActivationPreflight, error) {
	return install.ExistingActivationPreflight{}, errors.New("not used")
}
func (*cliStoreFake) CreateJournal(context.Context, install.UpgradeJournalV1) error {
	return errors.New("not used")
}
func (*cliStoreFake) SaveJournal(context.Context, install.UpgradeJournalV1) error {
	return errors.New("not used")
}
func (*cliStoreFake) Marker(context.Context, bool) error { return errors.New("not used") }
func (*cliStoreFake) WriteCandidateActivation(context.Context, install.ActivationV1, []byte) (string, error) {
	return "", errors.New("not used")
}
func (*cliStoreFake) WriteRestoreActivation(context.Context, install.ActivationV1, []byte) (string, error) {
	return "", errors.New("not used")
}
func (*cliStoreFake) SetPrevious(context.Context, string) error { return errors.New("not used") }
func (*cliStoreFake) RestorePrevious(context.Context, string, string, string) error {
	return errors.New("not used")
}
func (*cliStoreFake) SwapActive(context.Context, string) error { return errors.New("not used") }
func (*cliStoreFake) RestoreActive(context.Context, string, string) error {
	return errors.New("not used")
}

type cliServiceFake struct{}

func (*cliServiceFake) Capture(context.Context) (install.ServiceSnapshotV1, error) {
	return install.ServiceSnapshotV1{}, errors.New("not used")
}
func (*cliServiceFake) Quiesce(context.Context) error        { return errors.New("not used") }
func (*cliServiceFake) StartInternal(context.Context) error  { return errors.New("not used") }
func (*cliServiceFake) HealthInternal(context.Context) error { return errors.New("not used") }
func (*cliServiceFake) StartEdge(context.Context) error      { return errors.New("not used") }
func (*cliServiceFake) HealthEdge(context.Context) error     { return errors.New("not used") }
func (*cliServiceFake) GuardEdge(context.Context) error      { return errors.New("not used") }
func (*cliServiceFake) ValidateEdgeConfig(context.Context, install.EdgeConfigTransitionV1, install.ArtifactV1) (install.EdgeConfigValidationV1, error) {
	return install.EdgeConfigValidationV1{}, errors.New("not used")
}
func (*cliServiceFake) ReloadServerUnit(context.Context, string) error { return errors.New("not used") }
func (*cliServiceFake) RestoreSnapshot(context.Context, install.ServiceSnapshotV1) error {
	return errors.New("not used")
}
func (*cliServiceFake) HealthRestoredInternal(context.Context) error { return errors.New("not used") }
func (*cliServiceFake) RestoreEdge(context.Context, install.ServiceSnapshotV1) error {
	return errors.New("not used")
}
