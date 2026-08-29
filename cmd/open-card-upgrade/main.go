// Command open-card-upgrade is the only privileged entry point for the
// Gate5B activation engine. It accepts immutable release and transaction
// identities, never paths, database URLs, service names, or fault controls.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/install"
)

const (
	exitOK         = 0
	exitInternal   = 1
	exitArgs       = 2
	exitPrivilege  = 3
	exitLocked     = 20
	exitConflict   = 21
	exitRecovery   = 22
	exitIneligible = 23
)

const productionUpgradeExecutable = "/opt/open-card/upgrade-tools/open-card-upgrade"
const productionUpgradeRecoveryUnit = install.ProductionUpgradeRecoveryUnitPath

type upgradeCommandConfig struct {
	command        string
	transactionID  string
	releaseID      string
	manifestSHA256 string
	expectLegacy   bool
	pending        bool
}

type upgradeRuntime struct {
	preflight func(context.Context, install.UpgradeRequest) (install.UpgradeEligibilityV1, error)
	run       func(context.Context, install.UpgradeRequest) error
	recover   func(context.Context, string) error
	status    func(context.Context, string) (install.UpgradeStatusV1, error)
	pending   func(context.Context) (install.PendingTransaction, error)
	close     func() error
}

type upgradeDependencies struct {
	euid                      func() int
	derive                    func(upgradeCommandConfig) (install.UpgradeCLIIdentity, error)
	verifyCandidateExecutable func(string) error
	newRuntime                func(context.Context) (upgradeRuntime, error)
	newStatusRuntime          func(context.Context) (upgradeRuntime, error)
}

// productionRuntimeDependencies is a private construction seam. It proves the
// fixed executable/unit/store/service order without exposing a task-root or
// alternate production path in the shipped parser.
type productionRuntimeDependencies struct {
	verifyExecutable           func() error
	verifyRecoveryUnit         func() error
	verifyRecoveryServiceState func(context.Context) error
	openStore                  func() (upgradeRuntimeStore, error)
	openService                func() (install.UpgradeServiceDriver, func() error, error)
	databaseFactory            install.UpgradeDatabaseFactory
	now                        func() time.Time
}

type upgradeRuntimeStore struct {
	store   install.UpgradeJournalStore
	status  func(context.Context, string) (install.UpgradeStatusV1, error)
	pending func(context.Context) (install.PendingTransaction, error)
	close   func() error
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := runWithDependencies(ctx, os.Args[1:], os.Stdout, os.Stderr, productionUpgradeDependencies())
	os.Exit(code)
}

func productionUpgradeDependencies() upgradeDependencies {
	return upgradeDependencies{
		euid:                      os.Geteuid,
		derive:                    deriveProductionIdentity,
		verifyCandidateExecutable: verifyProductionUpgradeExecutableDigest,
		newRuntime:                newProductionRuntime,
		newStatusRuntime:          newProductionStatusRuntime,
	}
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithDependencies(context.Background(), args, stdout, stderr, productionUpgradeDependencies())
}

func runWithDependencies(ctx context.Context, args []string, stdout, stderr io.Writer, deps upgradeDependencies) (code int) {
	var bufferedStdout, bufferedStderr bytes.Buffer
	defer func() {
		if code == exitOK {
			_, _ = stdout.Write(bufferedStdout.Bytes())
			return
		}
		_, _ = stderr.Write(bufferedStderr.Bytes())
	}()
	return runWithDependenciesCore(ctx, args, &bufferedStdout, &bufferedStderr, deps)
}

func runWithDependenciesCore(ctx context.Context, args []string, stdout, stderr io.Writer, deps upgradeDependencies) (code int) {
	config, err := parseUpgradeArgs(args)
	if err != nil {
		return writeUpgradeError(stderr, exitArgs, "invalid_arguments")
	}
	if deps.euid == nil || deps.euid() != 0 {
		return writeUpgradeError(stderr, exitPrivilege, "root_required")
	}
	constructor := deps.newRuntime
	if config.command == "status" {
		constructor = deps.newStatusRuntime
	}
	if constructor == nil || ((config.command == "preflight" || config.command == "run") && deps.derive == nil) {
		return writeUpgradeError(stderr, exitInternal, "internal_error")
	}
	runtime, err := constructor(ctx)
	if err != nil {
		return writeUpgradeError(stderr, exitInternal, "runtime_unavailable")
	}
	if runtime.close != nil {
		defer func() {
			if err := runtime.close(); err != nil && code == exitOK {
				code = writeUpgradeError(stderr, exitInternal, "runtime_close_failed")
			}
		}()
	}

	if config.command == "status" {
		return runUpgradeStatus(ctx, stdout, stderr, runtime, config)
	}
	switch config.command {
	case "preflight":
		identity, err := deps.derive(config)
		if err != nil {
			return writeUpgradeError(stderr, exitIneligible, "release_ineligible")
		}
		identity.Request.ExpectedLegacy = config.expectLegacy
		if deps.verifyCandidateExecutable != nil && deps.verifyCandidateExecutable(identity.UpgradeExecutableSHA256) != nil {
			return writeUpgradeError(stderr, exitIneligible, "release_ineligible")
		}
		if runtime.preflight == nil {
			return writeUpgradeError(stderr, exitInternal, "runtime_unavailable")
		}
		eligibility, err := runtime.preflight(ctx, identity.Request)
		if err != nil {
			return writeUpgradeEngineError(stderr, err)
		}
		return writeUpgradeJSON(stdout, exitOK, map[string]any{"ok": true, "command": "preflight", "eligibility": eligibility})
	case "run":
		identity, err := deps.derive(config)
		if err != nil {
			return writeUpgradeError(stderr, exitIneligible, "release_ineligible")
		}
		identity.Request.ExpectedLegacy = config.expectLegacy
		if deps.verifyCandidateExecutable != nil && deps.verifyCandidateExecutable(identity.UpgradeExecutableSHA256) != nil {
			return writeUpgradeError(stderr, exitIneligible, "release_ineligible")
		}
		if runtime.run == nil {
			return writeUpgradeError(stderr, exitInternal, "runtime_unavailable")
		}
		if err := runtime.run(ctx, identity.Request); err != nil {
			return writeUpgradeEngineError(stderr, err)
		}
		return writeUpgradeJSON(stdout, exitOK, map[string]any{"ok": true, "transaction_id": config.transactionID, "state": install.JournalCommitted})
	case "recover":
		if runtime.recover == nil || runtime.status == nil {
			return writeUpgradeError(stderr, exitInternal, "runtime_unavailable")
		}
		if config.pending {
			if runtime.pending == nil {
				return writeUpgradeError(stderr, exitInternal, "runtime_unavailable")
			}
			pending, pendingErr := runtime.pending(ctx)
			if pendingErr != nil || pending.Marker != install.UpgradeMarkerSame || pending.TransactionID == "" {
				return writeUpgradeError(stderr, exitConflict, "status_unreadable")
			}
			config.transactionID = pending.TransactionID
		}
		err := runtime.recover(ctx, config.transactionID)
		status, statusErr := runtime.status(ctx, config.transactionID)
		if statusErr == nil && status.Disposition == install.UpgradeStatusTerminal && (status.State == install.JournalAbortedPreSwitch || status.State == install.JournalRolledBack || status.State == install.JournalCommitted) {
			return writeUpgradeJSON(stdout, exitOK, map[string]any{"ok": true, "command": "recover", "status": status})
		}
		if err != nil {
			return writeUpgradeEngineError(stderr, err)
		}
		if statusErr != nil {
			return writeUpgradeError(stderr, exitConflict, "status_unreadable")
		}
		if status.Disposition != install.UpgradeStatusTerminal {
			return writeUpgradeError(stderr, exitRecovery, "recovery_required")
		}
		return writeUpgradeJSON(stdout, exitOK, map[string]any{"ok": true, "command": "recover", "status": status})
	default:
		return writeUpgradeError(stderr, exitArgs, "invalid_arguments")
	}
}

func runUpgradeStatus(ctx context.Context, stdout, stderr io.Writer, runtime upgradeRuntime, config upgradeCommandConfig) int {
	if runtime.status == nil || runtime.pending == nil {
		return writeUpgradeError(stderr, exitInternal, "runtime_unavailable")
	}
	transactionID := config.transactionID
	if config.pending {
		pending, err := runtime.pending(ctx)
		if err != nil {
			return writeUpgradeError(stderr, exitConflict, "status_unreadable")
		}
		if pending.Marker != install.UpgradeMarkerSame || pending.TransactionID == "" {
			return writeUpgradeJSON(stdout, exitOK, map[string]any{"ok": true, "pending": pending})
		}
		transactionID = pending.TransactionID
	}
	status, err := runtime.status(ctx, transactionID)
	if err != nil {
		return writeUpgradeError(stderr, exitConflict, "status_unreadable")
	}
	return writeUpgradeJSON(stdout, exitOK, map[string]any{"ok": true, "status": status})
}

func writeUpgradeEngineError(stdout io.Writer, err error) int {
	if errors.Is(err, install.ErrUpgradeLocked) {
		return writeUpgradeError(stdout, exitLocked, "upgrade_locked")
	}
	if errors.Is(err, install.ErrUpgradeConflict) || errors.Is(err, install.ErrUpgradeJournalConflict) {
		return writeUpgradeError(stdout, exitConflict, "upgrade_conflict")
	}
	var phase install.UpgradePhaseError
	if errors.As(err, &phase) {
		switch phase.Phase {
		case install.JournalRecoveryRequired, install.JournalAbortedPreSwitch, install.JournalRollbackSwitched, install.JournalRolledBack:
			return writeUpgradeError(stdout, exitRecovery, "recovery_required")
		case install.JournalPreflighted:
			return writeUpgradeError(stdout, exitIneligible, "release_ineligible")
		default:
			return writeUpgradeError(stdout, exitRecovery, "upgrade_incomplete")
		}
	}
	return writeUpgradeError(stdout, exitInternal, "internal_error")
}

func writeUpgradeError(stdout io.Writer, code int, message string) int {
	return writeUpgradeJSON(stdout, code, map[string]any{"ok": false, "code": message})
}

func writeUpgradeJSON(stdout io.Writer, code int, value any) int {
	if stdout == nil {
		return exitInternal
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(value) != nil {
		return exitInternal
	}
	return code
}

func parseUpgradeArgs(args []string) (upgradeCommandConfig, error) {
	if len(args) == 0 {
		return upgradeCommandConfig{}, errors.New("command required")
	}
	config := upgradeCommandConfig{command: args[0]}
	switch config.command {
	case "preflight", "run":
		for index := 1; index < len(args); index++ {
			flag := args[index]
			if index+1 >= len(args) {
				return upgradeCommandConfig{}, errors.New("flag value required")
			}
			index++
			switch flag {
			case "--transaction-id":
				config.transactionID = args[index]
			case "--release-id":
				config.releaseID = args[index]
			case "--manifest-sha256":
				config.manifestSHA256 = args[index]
			case "--expect-layout":
				if args[index] == "native" {
					config.expectLegacy = false
				} else if args[index] == "rc0-legacy" {
					config.expectLegacy = true
				} else {
					return upgradeCommandConfig{}, errors.New("invalid layout")
				}
			default:
				return upgradeCommandConfig{}, errors.New("unsupported flag")
			}
		}
		if !validCLIIdentifier(config.transactionID) || !validCLIIdentifier(config.releaseID) || !validCLISHA(config.manifestSHA256) || !containsExactly(args[1:], "--transaction-id", "--release-id", "--manifest-sha256", "--expect-layout") {
			return upgradeCommandConfig{}, errors.New("invalid command")
		}
	case "recover", "status":
		for index := 1; index < len(args); index++ {
			switch args[index] {
			case "--transaction-id":
				index++
				if index >= len(args) {
					return upgradeCommandConfig{}, errors.New("flag value required")
				}
				config.transactionID = args[index]
			case "--pending":
				config.pending = true
			default:
				return upgradeCommandConfig{}, errors.New("unsupported flag")
			}
		}
		if (config.transactionID == "" && !config.pending) || (config.transactionID != "" && config.pending) || !containsOnlyRecoveryFlags(args[1:]) || (config.transactionID != "" && !validCLIIdentifier(config.transactionID)) {
			return upgradeCommandConfig{}, errors.New("invalid recovery command")
		}
	default:
		return upgradeCommandConfig{}, errors.New("unsupported command")
	}
	return config, nil
}

func containsExactly(args []string, wanted ...string) bool {
	if len(args) != len(wanted)*2 {
		return false
	}
	seen := make(map[string]bool, len(wanted))
	for index := 0; index < len(args); index += 2 {
		flag := args[index]
		if seen[flag] {
			return false
		}
		seen[flag] = true
	}
	for _, flag := range wanted {
		if !seen[flag] {
			return false
		}
	}
	return true
}

func containsOnlyRecoveryFlags(args []string) bool {
	if len(args) == 1 {
		return args[0] == "--pending"
	}
	return len(args) == 2 && args[0] == "--transaction-id"
}

func validCLIIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if !((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-') || (index == 0 && (character == '.' || character == '_' || character == '-')) {
			return false
		}
	}
	return true
}

func validCLISHA(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func deriveProductionIdentity(config upgradeCommandConfig) (install.UpgradeCLIIdentity, error) {
	release, err := install.LoadVerifiedProductionUpgradeRelease(config.releaseID, config.manifestSHA256)
	if err != nil {
		return install.UpgradeCLIIdentity{}, err
	}
	return install.DeriveUpgradeCLIIdentity(config.transactionID, release)
}

func newProductionRuntime(ctx context.Context) (upgradeRuntime, error) {
	return newProductionRuntimeWithDependencies(ctx, productionRuntimeDeps())
}

func productionRuntimeDeps() productionRuntimeDependencies {
	return productionRuntimeDependencies{
		verifyExecutable:           func() error { return verifyProductionUpgradeExecutable(productionUpgradeExecutable) },
		verifyRecoveryUnit:         func() error { return verifyProductionRecoveryUnit(productionUpgradeRecoveryUnit) },
		verifyRecoveryServiceState: verifyProductionRecoveryServiceState,
		openStore: func() (upgradeRuntimeStore, error) {
			store, err := install.ProductionUpgradeStore()
			if err != nil {
				return upgradeRuntimeStore{}, err
			}
			return upgradeRuntimeStore{store: store, status: store.ReadUpgradeStatus, pending: store.PendingTransaction, close: store.Close}, nil
		},
		openService: func() (install.UpgradeServiceDriver, func() error, error) {
			service, err := install.ProductionUpgradeServiceAdapter()
			if err != nil {
				return nil, nil, err
			}
			return service, service.Close, nil
		},
		databaseFactory: install.NewProductionUpgradeDatabaseFactory(),
		now:             func() time.Time { return time.Now().UTC() },
	}
}

func newProductionRuntimeWithDependencies(ctx context.Context, deps productionRuntimeDependencies) (upgradeRuntime, error) {
	if deps.verifyExecutable == nil || deps.verifyRecoveryUnit == nil || deps.verifyRecoveryServiceState == nil || deps.openStore == nil || deps.openService == nil || deps.databaseFactory == nil || deps.now == nil {
		return upgradeRuntime{}, errors.New("invalid production runtime dependencies")
	}
	if err := deps.verifyExecutable(); err != nil {
		return upgradeRuntime{}, err
	}
	if err := deps.verifyRecoveryUnit(); err != nil {
		return upgradeRuntime{}, err
	}
	if err := deps.verifyRecoveryServiceState(ctx); err != nil {
		return upgradeRuntime{}, err
	}
	store, err := deps.openStore()
	if err != nil || store.store == nil || store.close == nil || store.status == nil || store.pending == nil {
		return upgradeRuntime{}, errors.New("open upgrade store failed")
	}
	service, closeService, err := deps.openService()
	if err != nil || service == nil || closeService == nil {
		_ = store.close()
		return upgradeRuntime{}, errors.New("open upgrade service failed")
	}
	engine := &install.UpgradeEngine{Store: store.store, DatabaseFactory: deps.databaseFactory, Services: service, Now: deps.now}
	return upgradeRuntime{
		preflight: engine.Preflight,
		run:       engine.RunNew,
		recover:   engine.Recover,
		status:    store.status,
		pending:   store.pending,
		close: func() error {
			first := closeService()
			if err := store.close(); first == nil {
				first = err
			}
			return first
		},
	}, nil
}

// newProductionStatusRuntime deliberately opens only the durable store. A
// status query must remain readable when PostgreSQL, systemd, or a candidate
// release is unhealthy, and it must not create any mutable service/database
// dependency.
func newProductionStatusRuntime(_ context.Context) (upgradeRuntime, error) {
	deps := productionRuntimeDeps()
	if deps.verifyExecutable == nil || deps.verifyRecoveryUnit == nil || deps.openStore == nil {
		return upgradeRuntime{}, errors.New("invalid production status dependencies")
	}
	if err := deps.verifyExecutable(); err != nil {
		return upgradeRuntime{}, err
	}
	if err := deps.verifyRecoveryUnit(); err != nil {
		return upgradeRuntime{}, err
	}
	store, err := deps.openStore()
	if err != nil || store.status == nil || store.pending == nil || store.close == nil {
		return upgradeRuntime{}, errors.New("open upgrade store failed")
	}
	return upgradeRuntime{status: store.status, pending: store.pending, close: store.close}, nil
}

func verifyProductionUpgradeExecutable(path string) error {
	if path != productionUpgradeExecutable {
		return errors.New("invalid executable path")
	}
	if err := verifyRootOwnedDirectoryChain("/opt", "/opt/open-card", "/opt/open-card/upgrade-tools"); err != nil {
		return errors.New("invalid executable")
	}
	_, err := readRootOwnedNoFollowFile("/opt/open-card/upgrade-tools", "open-card-upgrade", 0o755)
	if err != nil {
		return errors.New("invalid executable")
	}
	resolved, err := os.Executable()
	if err != nil || resolved != path {
		return errors.New("invalid executable")
	}
	return nil
}

func verifyProductionUpgradeExecutableDigest(expectedSHA256 string) error {
	if !validCLISHA(expectedSHA256) || verifyProductionUpgradeExecutable(productionUpgradeExecutable) != nil {
		return errors.New("invalid executable")
	}
	raw, err := readRootOwnedNoFollowFile("/opt/open-card/upgrade-tools", "open-card-upgrade", 0o755)
	if err != nil {
		return errors.New("invalid executable")
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != expectedSHA256 {
		return errors.New("invalid executable")
	}
	return nil
}

func verifyProductionRecoveryUnit(path string) error {
	if path != productionUpgradeRecoveryUnit {
		return errors.New("invalid recovery unit")
	}
	if err := verifyRootOwnedDirectoryChain("/etc", "/etc/systemd", "/etc/systemd/system"); err != nil {
		return errors.New("invalid recovery unit")
	}
	raw, err := readRootOwnedNoFollowFile("/etc/systemd/system", "open-card-upgrade-recover.service", 0o644)
	if err != nil || !bytes.Equal(raw, install.ProductionUpgradeRecoveryUnitBytes()) {
		return errors.New("invalid recovery unit")
	}
	post, err := readRootOwnedNoFollowFile("/etc/systemd/system", "open-card-upgrade-recover.service", 0o644)
	if err != nil || !bytes.Equal(post, raw) {
		return errors.New("invalid recovery unit")
	}
	return nil
}

func verifyProductionRecoveryServiceState(ctx context.Context) error {
	return verifyRecoveryServiceStateWithDependencies(ctx, verifyProductionSystemctl, exec.CommandContext)
}

type systemctlCommandFactory func(context.Context, string, ...string) *exec.Cmd

func verifyRecoveryServiceStateWithDependencies(ctx context.Context, verifySystemctl func() error, commandFactory systemctlCommandFactory) error {
	if verifySystemctl == nil || commandFactory == nil || verifySystemctl() != nil {
		return errors.New("invalid recovery unit state")
	}
	command := commandFactory(ctx, "/usr/bin/systemctl", "show", "open-card-upgrade-recover.service", "--property=FragmentPath", "--property=DropInPaths", "--property=NeedDaemonReload", "--property=UnitFileState", "--no-pager")
	if command == nil {
		return errors.New("invalid recovery unit state")
	}
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	raw, err := command.Output()
	if err != nil {
		return errors.New("invalid recovery unit state")
	}
	return parseRecoveryServiceState(raw)
}

func verifyProductionSystemctl() error {
	if err := verifyRootOwnedDirectoryChain("/usr", "/usr/bin"); err != nil {
		return errors.New("invalid systemctl")
	}
	root, err := os.OpenRoot("/usr/bin")
	if err != nil {
		return errors.New("invalid systemctl")
	}
	defer root.Close()
	file, err := root.OpenFile("systemctl", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("invalid systemctl")
	}
	info, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil || closeErr != nil || !trustedSystemctlInfo(info) {
		return errors.New("invalid systemctl")
	}
	return nil
}

func trustedSystemctlInfo(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 == 0 && rootOwned(info)
}

func parseRecoveryServiceState(raw []byte) error {
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return errors.New("invalid recovery unit state")
		}
		if _, exists := values[key]; exists {
			return errors.New("invalid recovery unit state")
		}
		values[key] = value
	}
	if len(values) != 4 || values["FragmentPath"] != productionUpgradeRecoveryUnit || values["DropInPaths"] != "" || values["NeedDaemonReload"] != "no" || values["UnitFileState"] != "enabled" {
		return errors.New("invalid recovery unit state")
	}
	return nil
}

func verifyRootOwnedDirectoryChain(paths ...string) error {
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || !rootOwned(info) {
			return errors.New("unsafe directory")
		}
	}
	return nil
}

func readRootOwnedNoFollowFile(rootPath, name string, mode os.FileMode) ([]byte, error) {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(file)
	info, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || !rootOwned(info) {
		return nil, errors.New("unsafe file")
	}
	return raw, nil
}

func rootOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Gid == 0
}
