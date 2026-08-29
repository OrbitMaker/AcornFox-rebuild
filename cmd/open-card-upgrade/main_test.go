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
	valid := []byte("FragmentPath=/etc/systemd/system/open-card-upgrade-recover.service\nDropInPaths=\nNeedDaemonReload=no\nUnitFileState=enabled\n")
	if err := parseRecoveryServiceState(valid); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{
		[]byte("FragmentPath=/etc/systemd/system/open-card-upgrade-recover.service\nDropInPaths=/etc/systemd/system/x.conf\nNeedDaemonReload=no\nUnitFileState=enabled\n"),
		[]byte("FragmentPath=/etc/systemd/system/open-card-upgrade-recover.service\nDropInPaths=\nNeedDaemonReload=yes\nUnitFileState=enabled\n"),
		[]byte("FragmentPath=/etc/systemd/system/open-card-upgrade-recover.service\nDropInPaths=\nNeedDaemonReload=no\nUnitFileState=disabled\n"),
		[]byte("FragmentPath=/tmp/other\nDropInPaths=\nNeedDaemonReload=no\nUnitFileState=enabled\n"),
		[]byte("FragmentPath=/etc/systemd/system/open-card-upgrade-recover.service\nDropInPaths=\nNeedDaemonReload=no\nUnitFileState=enabled\nExecStart=/bin/sh -c unsafe\n"),
		[]byte("FragmentPath=/etc/systemd/system/open-card-upgrade-recover.service\nFragmentPath=/etc/systemd/system/open-card-upgrade-recover.service\nDropInPaths=\nNeedDaemonReload=no\nUnitFileState=enabled\n"),
	} {
		if err := parseRecoveryServiceState(raw); err == nil {
			t.Fatalf("accepted unsafe unit state %q", raw)
		}
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
		databaseFactory: install.UpgradeDatabaseOpenFunc(func(context.Context, install.UpgradeDatabaseOpenRequest) (install.UpgradeDatabaseSession, error) {
			return nil, errors.New("not used")
		}),
		now: func() time.Time { return time.Unix(1, 0) },
	}
	deps.verifyRecoveryServiceState = func(context.Context) error { events = append(events, "unit-state"); return nil }
	runtime, err := newProductionRuntimeWithDependencies(context.Background(), deps)
	if err != nil || strings.Join(events, ",") != "executable,unit,unit-state,store,service" {
		t.Fatalf("constructor order failed: %v %v", events, err)
	}
	if err := runtime.close(); err == nil || strings.Join(events, ",") != "executable,unit,unit-state,store,service,service-close,store-close" {
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

type cliStoreFake struct{}

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
func (*cliStoreFake) ReadActivationState(context.Context) (install.UpgradeActivationState, error) {
	return install.UpgradeActivationState{}, errors.New("not used")
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
func (*cliServiceFake) Quiesce(context.Context) error                  { return errors.New("not used") }
func (*cliServiceFake) StartInternal(context.Context) error            { return errors.New("not used") }
func (*cliServiceFake) HealthInternal(context.Context) error           { return errors.New("not used") }
func (*cliServiceFake) StartEdge(context.Context) error                { return errors.New("not used") }
func (*cliServiceFake) HealthEdge(context.Context) error               { return errors.New("not used") }
func (*cliServiceFake) GuardEdge(context.Context) error                { return errors.New("not used") }
func (*cliServiceFake) ReloadServerUnit(context.Context, string) error { return errors.New("not used") }
func (*cliServiceFake) RestoreSnapshot(context.Context, install.ServiceSnapshotV1) error {
	return errors.New("not used")
}
func (*cliServiceFake) HealthRestoredInternal(context.Context) error { return errors.New("not used") }
func (*cliServiceFake) RestoreEdge(context.Context, install.ServiceSnapshotV1) error {
	return errors.New("not used")
}
