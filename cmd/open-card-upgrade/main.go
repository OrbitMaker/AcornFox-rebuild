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
	"path/filepath"
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
const helperRole = "upgrade"

var (
	processIdentity   = "legacy"
	buildVersion      string
	buildSourceCommit string
	buildLayoutSchema string
)

var productionBootUnitFiles = []struct {
	path string
	name string
	raw  func() []byte
}{
	{install.ProductionUpgradeRecoveryUnitPath, "open-card-upgrade-recover.service", install.ProductionUpgradeRecoveryUnitBytes},
	{install.ProductionUpgradeSafeBootTargetPath, "open-card-upgrade-safe.target", install.ProductionUpgradeSafeBootTargetBytes},
	{install.ProductionUpgradeFinalizeUnitPath, "open-card-upgrade-finalize.service", install.ProductionUpgradeFinalizeUnitBytes},
	{install.ProductionUpgradeEdgeMarkerDropInPath, "10-upgrade-marker.conf", install.ProductionUpgradeEdgeMarkerDropInBytes},
}

type upgradeCommandConfig struct {
	command        string
	transactionID  string
	releaseID      string
	manifestSHA256 string
	backupID       string
	reason         string
	expectLegacy   bool
	pending        bool
	confirmation   string
	candidateDir   string
	bindingSHA256  string
	selfSHA256     string
}

type upgradeRuntime struct {
	bootstrap        func(context.Context, install.BootstrapRequest) error
	preflight        func(context.Context, install.UpgradeRequest) (install.UpgradeEligibilityV1, error)
	run              func(context.Context, install.UpgradeRequest) error
	recover          func(context.Context, string) error
	prepare          func(context.Context) (install.BootRecoveryResultV1, error)
	finalize         func(context.Context, string) (install.BootRecoveryResultV1, error)
	status           func(context.Context, string) (install.UpgradeStatusV1, error)
	backupCreate     func(context.Context, install.BackupCreateRequest) (install.ActiveDatabaseBackupV2, error)
	backupStatus     func(context.Context, string) (install.ActiveDatabaseBackupV2, error)
	restorePreflight func(context.Context, install.RestoreRequest) (install.RestoreEligibilityV1, error)
	restoreRun       func(context.Context, install.RestoreRequest) error
	pending          func(context.Context) (install.PendingTransaction, error)
	close            func() error
}

// installationIdentityMigrationStore keeps the privileged migration command
// limited to its two required operations and makes its construction testable
// without accepting roots or identity values from CLI arguments.
type installationIdentityMigrationStore interface {
	Migrate(context.Context) (install.InstallationIdentity, error)
	Close() error
}

type upgradeDependencies struct {
	euid                         func() int
	derive                       func(upgradeCommandConfig) (install.UpgradeCLIIdentity, error)
	verifyExecutable             func() error
	prepareControl               func(context.Context) (string, error)
	prepareBootstrap             func(context.Context, string) (install.BootstrapRuntimeReceipt, error)
	verifyCandidateExecutable    func(string) error
	newRuntime                   func(context.Context) (upgradeRuntime, error)
	newStatusRuntime             func(context.Context) (upgradeRuntime, error)
	newPrepareRuntime            func(context.Context) (upgradeRuntime, error)
	newFinalizeRuntime           func(context.Context) (upgradeRuntime, error)
	newBackupRuntime             func(context.Context) (upgradeRuntime, error)
	deriveBootstrap              func(upgradeCommandConfig) (install.BootstrapRequest, error)
	newBootstrapRuntime          func(context.Context) (upgradeRuntime, error)
	verifyCommittedBootstrap     func(context.Context, install.BootstrapRequest) error
	finalizeBootstrap            func(context.Context, install.BootstrapRequest) (install.BootstrapFinalizationReceipt, error)
	newInstallationIdentityStore func() (installationIdentityMigrationStore, error)
	acornFoxClean                acornFoxCleanDependencies
}

// acornFoxCleanDependencies is intentionally separate from the legacy
// runtime providers. Its four functions are the complete clean-mode effect
// surface and are injected directly by focused command tests.
type acornFoxCleanDependencies struct {
	euid           func() int
	bootstrap      func(context.Context, install.AcornFoxCandidateSetRequestV1) (install.AcornFoxHostBootstrapReceiptV1, error)
	recover        func(context.Context) (install.AcornFoxHostBootstrapReceiptV1, error)
	verifyPrepared func(context.Context) (install.AcornFoxHostBootstrapReceiptV1, error)
}

type productionBootstrapRuntimeDependencies struct {
	verifyExecutable    func() error
	verifyBootArtifacts func(context.Context, bool) error
	openStore           func() (install.BootstrapEngineStore, func() error, error)
	openService         func() (install.BootstrapServiceDriver, func() error, error)
	openDatabase        func(install.BootstrapDatabaseInput) (install.BootstrapDatabaseDriver, func() error, error)
	now                 func() time.Time
}

type unavailableBootstrapDatabase struct{}

func (unavailableBootstrapDatabase) Create(context.Context) (install.BootstrapCandidateDatabase, error) {
	return install.BootstrapCandidateDatabase{}, install.ErrPostgresOutcomeUnknown
}
func (unavailableBootstrapDatabase) Migrate(context.Context, install.BootstrapCandidateDatabase) (install.BootstrapDatabaseResult, error) {
	return install.BootstrapDatabaseResult{}, install.ErrPostgresOutcomeUnknown
}

// productionRuntimeDependencies is a private construction seam. It proves the
// fixed executable/unit/store/service order without exposing a task-root or
// alternate production path in the shipped parser.
type productionRuntimeDependencies struct {
	verifyExecutable           func() error
	verifyBootArtifacts        func(context.Context, bool) error
	verifyRecoveryUnit         func() error
	verifyRecoveryServiceState func(context.Context) error
	openStore                  func() (upgradeRuntimeStore, error)
	openService                func() (install.UpgradeServiceDriver, func() error, error)
	openBackupInspector        func() (install.UpgradeBackupInspector, func() error, error)
	databaseFactory            install.UpgradeDatabaseFactory
	now                        func() time.Time
}

var (
	errBootRuntimeConfiguration     = errors.New("boot runtime configuration unavailable")
	errBootArtifactsUnavailable     = errors.New("boot artifacts unavailable")
	errBootUnitFilesUnavailable     = errors.New("boot unit files unavailable")
	errBootSystemctlUnavailable     = errors.New("boot systemctl unavailable")
	errBootUnitStateUnavailable     = errors.New("boot unit state unavailable")
	errBootTargetGraphUnavailable   = errors.New("boot target graph unavailable")
	errBootFenceStateUnavailable    = errors.New("boot fence state unavailable")
	errBootBusinessGraphUnavailable = errors.New("boot business graph unavailable")
	errBootExecutableUnavailable    = errors.New("boot executable unavailable")
	errBootStoreUnavailable         = errors.New("boot store unavailable")
	errBootServiceUnavailable       = errors.New("boot service unavailable")
)

func runtimeConstructionErrorCode(err error) string {
	switch {
	case errors.Is(err, errBootRuntimeConfiguration):
		return "boot_runtime_configuration_unavailable"
	case errors.Is(err, errBootArtifactsUnavailable):
		return "boot_artifacts_unavailable"
	case errors.Is(err, errBootUnitFilesUnavailable):
		return "boot_unit_files_unavailable"
	case errors.Is(err, errBootSystemctlUnavailable):
		return "boot_systemctl_unavailable"
	case errors.Is(err, errBootUnitStateUnavailable):
		return "boot_unit_state_unavailable"
	case errors.Is(err, errBootTargetGraphUnavailable):
		return "boot_target_graph_unavailable"
	case errors.Is(err, errBootFenceStateUnavailable):
		return "boot_fence_state_unavailable"
	case errors.Is(err, errBootBusinessGraphUnavailable):
		return "boot_business_graph_unavailable"
	case errors.Is(err, errBootExecutableUnavailable):
		return "boot_executable_unavailable"
	case errors.Is(err, errBootStoreUnavailable):
		return "boot_store_unavailable"
	case errors.Is(err, errBootServiceUnavailable):
		return "boot_service_unavailable"
	default:
		return "runtime_unavailable"
	}
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
		verifyExecutable:          func() error { return verifyProductionUpgradeExecutable(productionUpgradeExecutable) },
		prepareControl:            install.PrepareProductionUpgradeControl,
		prepareBootstrap:          install.PrepareProductionBootstrapRuntime,
		verifyCandidateExecutable: verifyProductionUpgradeExecutableDigest,
		newRuntime:                newProductionRuntime,
		newStatusRuntime:          newProductionStatusRuntime,
		newPrepareRuntime:         newProductionPrepareRuntime,
		newFinalizeRuntime:        newProductionFinalizeRuntime,
		newBackupRuntime:          newProductionBackupRuntime,
		deriveBootstrap: func(config upgradeCommandConfig) (install.BootstrapRequest, error) {
			return install.DeriveProductionBootstrapRequest(config.manifestSHA256, config.confirmation)
		},
		newBootstrapRuntime:      newProductionBootstrapRuntime,
		verifyCommittedBootstrap: install.VerifyProductionCommittedBootstrap,
		finalizeBootstrap:        install.FinalizeProductionBootstrapEnvironment,
		newInstallationIdentityStore: func() (installationIdentityMigrationStore, error) {
			return install.NewProductionInstallationIdentityStore()
		},
		acornFoxClean: acornFoxCleanDependencies{
			euid:           os.Geteuid,
			bootstrap:      install.BootstrapAcornFoxHostV1,
			recover:        install.RecoverAcornFoxHostV1,
			verifyPrepared: install.VerifyPreparedAcornFoxHostV1,
		},
	}
}

// newProductionPrepareRuntime intentionally exposes only the DB factory and
// narrow unit reloader to ReconcileBoot. The engine's prepare method has no
// UpgradeServiceDriver parameter, so this constructor cannot accidentally
// start, stop, probe, or restore a business service.
func newProductionPrepareRuntime(ctx context.Context) (upgradeRuntime, error) {
	return newProductionBootRuntime(ctx, false)
}

func newProductionFinalizeRuntime(ctx context.Context) (upgradeRuntime, error) {
	return newProductionBootRuntime(ctx, true)
}

func newProductionBootRuntime(ctx context.Context, finalize bool) (upgradeRuntime, error) {
	return newProductionBootRuntimeWithDependencies(ctx, finalize, productionRuntimeDeps())
}

func newProductionBootRuntimeWithDependencies(ctx context.Context, finalize bool, deps productionRuntimeDependencies) (upgradeRuntime, error) {
	if deps.verifyExecutable == nil || deps.verifyBootArtifacts == nil || deps.openStore == nil || deps.openService == nil || deps.databaseFactory == nil || deps.now == nil {
		return upgradeRuntime{}, errBootRuntimeConfiguration
	}
	if err := deps.verifyBootArtifacts(ctx, finalize); err != nil {
		if runtimeConstructionErrorCode(err) != "runtime_unavailable" {
			return upgradeRuntime{}, err
		}
		return upgradeRuntime{}, errBootArtifactsUnavailable
	}
	if deps.verifyExecutable() != nil {
		return upgradeRuntime{}, errBootExecutableUnavailable
	}
	store, err := deps.openStore()
	if err != nil || store.store == nil || store.close == nil || store.pending == nil {
		return upgradeRuntime{}, errBootStoreUnavailable
	}
	services, closeServices, err := deps.openService()
	if err != nil || services == nil || closeServices == nil {
		_ = store.close()
		return upgradeRuntime{}, errBootServiceUnavailable
	}
	engine := &install.UpgradeEngine{Store: store.store, DatabaseFactory: deps.databaseFactory, Now: deps.now}
	runtime := upgradeRuntime{pending: store.pending, close: func() error {
		first := closeServices()
		if closeErr := store.close(); first == nil {
			first = closeErr
		}
		return first
	}}
	if finalize {
		engine.Services = services
		runtime.finalize = engine.FinalizeBoot
	} else {
		runtime.prepare = func(callCtx context.Context) (install.BootRecoveryResultV1, error) {
			return engine.ReconcilePendingBoot(callCtx, services)
		}
	}
	return runtime, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithDependencies(context.Background(), args, stdout, stderr, productionUpgradeDependencies())
}

func runWithDependencies(ctx context.Context, args []string, stdout, stderr io.Writer, deps upgradeDependencies) (code int) {
	if processIdentity == "acornfox" {
		return runAcornFoxClean(ctx, args, stdout, helperRole, deps.acornFoxClean)
	}
	if processIdentity != "legacy" {
		return writeAcornFoxContractFailure(stdout, install.AcornFoxHelperCodeIdentityMismatch)
	}
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

// runAcornFoxClean is a closed dispatch table for the standalone AcornFox
// helper.  It intentionally shares no parser or runtime constructor with the
// legacy Open Card upgrade engine.
func runAcornFoxClean(ctx context.Context, args []string, stdout io.Writer, role string, deps acornFoxCleanDependencies) int {
	if len(args) > 0 && args[0] == "contract-check" {
		return runAcornFoxContractCheck(args, stdout, role)
	}
	config, err := parseAcornFoxCleanArgs(args)
	if err != nil {
		return writeAcornFoxCleanError(stdout, exitArgs, "invalid_arguments")
	}
	identity, ok := acornFoxCleanBuildIdentity(role)
	if !ok {
		return writeAcornFoxCleanError(stdout, exitIneligible, "helper_identity_ineligible")
	}
	if deps.euid == nil || deps.euid() != 0 {
		return writeAcornFoxCleanError(stdout, exitIneligible, "root_ineligible")
	}
	var receipt install.AcornFoxHostBootstrapReceiptV1
	switch config.command {
	case "repository-bootstrap":
		if deps.bootstrap == nil {
			return writeAcornFoxCleanError(stdout, exitIneligible, "candidate_ineligible")
		}
		receipt, err = deps.bootstrap(ctx, install.AcornFoxCandidateSetRequestV1{Directory: config.candidateDir, BindingSHA256: config.bindingSHA256, SelfSHA256: config.selfSHA256})
	case "recover-prepare":
		if deps.recover == nil {
			return writeAcornFoxCleanError(stdout, exitRecovery, "recovery_unknown")
		}
		receipt, err = deps.recover(ctx)
	case "recover-finalize":
		if deps.verifyPrepared == nil {
			return writeAcornFoxCleanError(stdout, exitRecovery, "recovery_unknown")
		}
		receipt, err = deps.verifyPrepared(ctx)
	default:
		return writeAcornFoxCleanError(stdout, exitArgs, "invalid_arguments")
	}
	if err != nil || receipt.Validate() != nil {
		return writeAcornFoxCleanBridgeError(stdout, err)
	}
	if receipt.ReleaseID != identity.ReleaseID || receipt.SourceCommit != identity.SourceCommit {
		return writeAcornFoxCleanError(stdout, exitIneligible, "helper_identity_ineligible")
	}
	return writeUpgradeJSON(stdout, exitOK, map[string]any{"ok": true, "command": config.command, "receipt": receipt})
}

// acornFoxCleanBuildIdentity is intentionally local: the clean bootstrap
// command may run before a candidate is installed, so it cannot call the
// installed-helper contract verifier to learn its identity.
func acornFoxCleanBuildIdentity(role string) (install.AcornFoxBuildIdentityV1, bool) {
	identity := install.AcornFoxBuildIdentityV1{
		SchemaVersion: install.AcornFoxHelperContractV1Schema,
		Product:       install.AcornFoxV1Product,
		LayoutVersion: install.AcornFoxSubstrateLayoutV1,
		Role:          role,
		Version:       buildVersion,
		ReleaseID:     "release-" + buildVersion,
		SourceCommit:  buildSourceCommit,
	}
	return identity, processIdentity == "acornfox" && buildLayoutSchema == "1" && role == "upgrade" && identity.Validate() == nil
}

func parseAcornFoxCleanArgs(args []string) (upgradeCommandConfig, error) {
	if len(args) == 0 {
		return upgradeCommandConfig{}, errors.New("command required")
	}
	config := upgradeCommandConfig{command: args[0]}
	switch config.command {
	case "repository-bootstrap":
		if len(args) != 7 {
			return upgradeCommandConfig{}, errors.New("invalid repository bootstrap")
		}
		for index := 1; index < len(args); index += 2 {
			flag, value := args[index], args[index+1]
			switch flag {
			case "--candidate-dir":
				config.candidateDir = value
			case "--binding-sha256":
				config.bindingSHA256 = value
			case "--self-sha256":
				config.selfSHA256 = value
			default:
				return upgradeCommandConfig{}, errors.New("unsupported flag")
			}
		}
		if !filepath.IsAbs(config.candidateDir) || filepath.Clean(config.candidateDir) == string(filepath.Separator) || !validCLISHA(config.bindingSHA256) || !validCLISHA(config.selfSHA256) || !containsExactly(args[1:], "--candidate-dir", "--binding-sha256", "--self-sha256") {
			return upgradeCommandConfig{}, errors.New("invalid repository bootstrap")
		}
	case "recover-prepare", "recover-finalize":
		if len(args) != 2 || args[1] != "--pending" {
			return upgradeCommandConfig{}, errors.New("invalid recovery")
		}
		config.pending = true
	default:
		return upgradeCommandConfig{}, errors.New("unsupported clean command")
	}
	return config, nil
}

func writeAcornFoxCleanBridgeError(stdout io.Writer, err error) int {
	switch {
	case err == nil:
		return writeAcornFoxCleanError(stdout, exitIneligible, "candidate_ineligible")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), errors.Is(err, install.ErrAcornFoxRepoRecoveryUnknown), errors.Is(err, install.ErrAcornFoxLiveRecoveryUnknown), errors.Is(err, install.ErrAcornFoxLiveReleaseUnknown):
		return writeAcornFoxCleanError(stdout, exitRecovery, "recovery_unknown")
	case errors.Is(err, install.ErrAcornFoxRepoLocked):
		return writeAcornFoxCleanError(stdout, exitLocked, "repository_locked")
	case errors.Is(err, install.ErrAcornFoxSubstrateRecoveryRequired), errors.Is(err, install.ErrAcornFoxStageCleanupUnknown):
		return writeAcornFoxCleanError(stdout, exitRecovery, "recovery_unknown")
	case errors.Is(err, install.ErrAcornFoxRepoBootstrapConflict), errors.Is(err, install.ErrAcornFoxRepoConflict), errors.Is(err, install.ErrAcornFoxLiveConflict), errors.Is(err, install.ErrAcornFoxSubstrateConflict):
		return writeAcornFoxCleanError(stdout, exitConflict, "repository_conflict")
	default:
		return writeAcornFoxCleanError(stdout, exitIneligible, "candidate_ineligible")
	}
}

func writeAcornFoxCleanError(stdout io.Writer, code int, message string) int {
	return writeUpgradeError(stdout, code, message)
}

func runAcornFoxContractCheck(args []string, stdout io.Writer, role string) int {
	if len(args) != 5 || args[0] != "contract-check" || args[1] != "--product" || args[2] != "acornfox" || args[3] != "--layout-schema" || args[4] != "1" {
		return writeAcornFoxContractFailure(stdout, install.AcornFoxHelperCodeInvalidArguments)
	}
	identity := install.AcornFoxBuildIdentityV1{SchemaVersion: install.AcornFoxHelperContractV1Schema, Product: install.AcornFoxV1Product, LayoutVersion: install.AcornFoxSubstrateLayoutV1, Role: role, Version: buildVersion, ReleaseID: "release-" + buildVersion, SourceCommit: buildSourceCommit}
	if buildLayoutSchema != "1" || identity.Validate() != nil {
		return writeAcornFoxContractFailure(stdout, install.AcornFoxHelperCodeIdentityMismatch)
	}
	return writeAcornFoxContractResult(stdout, install.VerifyProductionAcornFoxHelperContract(identity))
}

func writeAcornFoxContractFailure(stdout io.Writer, code string) int {
	return writeAcornFoxContractResult(stdout, install.AcornFoxHelperContractResultV1{SchemaVersion: install.AcornFoxHelperContractV1Schema, Code: code})
}

func writeAcornFoxContractResult(stdout io.Writer, result install.AcornFoxHelperContractResultV1) int {
	raw, err := install.MarshalAcornFoxHelperContractResultV1(result)
	if err != nil || stdout == nil {
		return exitInternal
	}
	_, err = stdout.Write(append(raw, '\n'))
	if err != nil {
		return exitInternal
	}
	if result.OK {
		return exitOK
	}
	return exitInternal
}

func runWithDependenciesCore(ctx context.Context, args []string, stdout, stderr io.Writer, deps upgradeDependencies) (code int) {
	config, err := parseUpgradeArgs(args)
	if err != nil {
		return writeUpgradeError(stderr, exitArgs, "invalid_arguments")
	}
	if deps.euid == nil || deps.euid() != 0 {
		return writeUpgradeError(stderr, exitPrivilege, "root_required")
	}
	if config.command == "installation-identity-migrate" {
		if deps.newInstallationIdentityStore == nil {
			return writeUpgradeError(stderr, exitInternal, "installation_identity_migration_failed")
		}
		store, openErr := deps.newInstallationIdentityStore()
		if openErr != nil || store == nil {
			if store != nil {
				_ = store.Close()
			}
			return writeUpgradeError(stderr, exitInternal, "installation_identity_migration_failed")
		}
		identity, migrateErr := store.Migrate(ctx)
		closeErr := store.Close()
		identitySHA256 := identity.SHA256()
		if migrateErr != nil || closeErr != nil || !validCLISHA(identitySHA256) {
			return writeUpgradeError(stderr, exitInternal, "installation_identity_migration_failed")
		}
		return writeUpgradeJSON(stdout, exitOK, map[string]any{"installation_id_sha256": identitySHA256})
	}
	// prepare-control deliberately precedes all runtime construction and the
	// safe-target fence. It provisions only the root-owned control identity;
	// it must stay usable before any activation slot or systemd barrier exists.
	if config.command == "prepare-control" {
		if deps.verifyExecutable == nil || deps.prepareControl == nil || deps.verifyExecutable() != nil {
			return writeUpgradeError(stderr, exitInternal, "runtime_unavailable")
		}
		identity, prepareErr := deps.prepareControl(ctx)
		if prepareErr != nil || !validCLISHA(identity) {
			return writeUpgradeError(stderr, exitInternal, "control_prepare_failed")
		}
		return writeUpgradeJSON(stdout, exitOK, map[string]any{"ok": true, "command": "prepare-control", "control_identity_sha256": identity})
	}
	if config.command == "prepare-bootstrap" {
		if deps.verifyExecutable == nil || deps.prepareBootstrap == nil || deps.verifyExecutable() != nil {
			return writeUpgradeError(stderr, exitInternal, "runtime_unavailable")
		}
		receipt, prepareErr := deps.prepareBootstrap(ctx, config.manifestSHA256)
		if prepareErr != nil || receipt.Validate() != nil || receipt.ManifestSHA256 != config.manifestSHA256 {
			return writeUpgradeError(stderr, exitInternal, "bootstrap_prepare_failed")
		}
		return writeUpgradeJSON(stdout, exitOK, map[string]any{"ok": true, "command": config.command, "receipt": receipt})
	}
	if config.command == "bootstrap-verify" || config.command == "bootstrap-finalize" {
		if deps.deriveBootstrap == nil {
			return writeUpgradeError(stderr, exitInternal, "internal_error")
		}
		request, deriveErr := deps.deriveBootstrap(config)
		if deriveErr != nil {
			return writeUpgradeError(stderr, exitIneligible, "bootstrap_identity_ineligible")
		}
		if config.command == "bootstrap-verify" {
			if deps.verifyCommittedBootstrap == nil || deps.verifyCommittedBootstrap(ctx, request) != nil {
				return writeUpgradeError(stderr, exitConflict, "bootstrap_not_committed")
			}
			return writeUpgradeJSON(stdout, exitOK, map[string]any{"ok": true, "command": config.command, "state": install.BootstrapCommitted})
		}
		if deps.finalizeBootstrap == nil {
			return writeUpgradeError(stderr, exitInternal, "internal_error")
		}
		receipt, finalizeErr := deps.finalizeBootstrap(ctx, request)
		if finalizeErr != nil || receipt.Validate() != nil {
			return writeUpgradeError(stderr, exitConflict, "bootstrap_finalize_failed")
		}
		return writeUpgradeJSON(stdout, exitOK, map[string]any{"ok": true, "command": config.command, "receipt": receipt})
	}
	constructor := deps.newRuntime
	switch config.command {
	case "bootstrap-native", "bootstrap-verify", "bootstrap-finalize":
		constructor = deps.newBootstrapRuntime
	case "status":
		constructor = deps.newStatusRuntime
	case "backup-create", "backup-status":
		constructor = deps.newBackupRuntime
	case "recover-prepare":
		constructor = deps.newPrepareRuntime
	case "recover-finalize":
		constructor = deps.newFinalizeRuntime
	}
	if constructor == nil || ((config.command == "preflight" || config.command == "run") && deps.derive == nil) || (config.command == "bootstrap-native" && deps.deriveBootstrap == nil) {
		return writeUpgradeError(stderr, exitInternal, "internal_error")
	}
	runtime, err := constructor(ctx)
	if err != nil {
		return writeUpgradeError(stderr, exitInternal, runtimeConstructionErrorCode(err))
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
	case "bootstrap-native", "bootstrap-verify", "bootstrap-finalize":
		request, err := deps.deriveBootstrap(config)
		if err != nil {
			return writeUpgradeError(stderr, exitIneligible, "bootstrap_identity_ineligible")
		}
		if runtime.bootstrap == nil {
			return writeUpgradeError(stderr, exitInternal, "runtime_unavailable")
		}
		if err := runtime.bootstrap(ctx, request); err != nil {
			return writeBootstrapError(stderr, err)
		}
		return writeUpgradeJSON(stdout, exitOK, map[string]any{"ok": true, "command": config.command, "state": install.BootstrapCommitted})
	case "backup-create":
		if runtime.backupCreate == nil {
			return writeUpgradeError(stderr, exitInternal, "runtime_unavailable")
		}
		backup, err := runtime.backupCreate(ctx, install.BackupCreateRequest{BackupID: config.backupID, Reason: config.reason})
		if err != nil {
			return writeBackupError(stderr, err)
		}
		return writeUpgradeJSON(stdout, exitOK, map[string]any{"ok": true, "command": config.command, "backup": backup})
	case "backup-status":
		if runtime.backupStatus == nil {
			return writeUpgradeError(stderr, exitInternal, "runtime_unavailable")
		}
		backup, err := runtime.backupStatus(ctx, config.backupID)
		if err != nil {
			return writeBackupError(stderr, err)
		}
		return writeUpgradeJSON(stdout, exitOK, map[string]any{"ok": true, "command": config.command, "backup": backup})
	case "restore-preflight":
		if runtime.restorePreflight == nil {
			return writeUpgradeError(stderr, exitInternal, "runtime_unavailable")
		}
		eligibility, err := runtime.restorePreflight(ctx, install.RestoreRequest{TransactionID: config.transactionID, BackupID: config.backupID})
		if err != nil {
			return writeUpgradeEngineError(stderr, err)
		}
		return writeUpgradeJSON(stdout, exitOK, map[string]any{"ok": true, "command": config.command, "eligibility": eligibility})
	case "restore-run":
		if runtime.restoreRun == nil {
			return writeUpgradeError(stderr, exitInternal, "runtime_unavailable")
		}
		if err := runtime.restoreRun(ctx, install.RestoreRequest{TransactionID: config.transactionID, BackupID: config.backupID}); err != nil {
			return writeUpgradeEngineError(stderr, err)
		}
		return writeUpgradeJSON(stdout, exitOK, map[string]any{"ok": true, "command": config.command, "transaction_id": config.transactionID, "request_kind": install.RequestKindRestore, "state": install.JournalCommitted})
	case "preflight":
		identity, err := deps.derive(config)
		if err != nil {
			return writeUpgradeError(stderr, exitIneligible, "release_identity_ineligible")
		}
		identity.Request.ExpectedLegacy = config.expectLegacy
		if deps.verifyCandidateExecutable != nil && deps.verifyCandidateExecutable(identity.UpgradeExecutableSHA256) != nil {
			return writeUpgradeError(stderr, exitIneligible, "upgrade_executable_ineligible")
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
			return writeUpgradeError(stderr, exitIneligible, "release_identity_ineligible")
		}
		identity.Request.ExpectedLegacy = config.expectLegacy
		if deps.verifyCandidateExecutable != nil && deps.verifyCandidateExecutable(identity.UpgradeExecutableSHA256) != nil {
			return writeUpgradeError(stderr, exitIneligible, "upgrade_executable_ineligible")
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
	case "recover-prepare":
		if runtime.prepare == nil {
			return writeUpgradeError(stderr, exitInternal, "runtime_unavailable")
		}
		result, err := runtime.prepare(ctx)
		if err != nil {
			return writeUpgradeEngineError(stderr, err)
		}
		return writeUpgradeJSON(stdout, exitOK, map[string]any{"ok": true, "command": config.command, "recovery": result})
	case "recover-finalize":
		if runtime.pending == nil {
			return writeUpgradeError(stderr, exitInternal, "runtime_unavailable")
		}
		pending, pendingErr := runtime.pending(ctx)
		if pendingErr != nil || pending.Marker != install.UpgradeMarkerSame || pending.TransactionID == "" {
			return writeUpgradeError(stderr, exitConflict, "status_unreadable")
		}
		if runtime.finalize == nil {
			return writeUpgradeError(stderr, exitInternal, "runtime_unavailable")
		}
		result, err := runtime.finalize(ctx, pending.TransactionID)
		if err != nil {
			return writeUpgradeEngineError(stderr, err)
		}
		return writeUpgradeJSON(stdout, exitOK, map[string]any{"ok": true, "command": config.command, "recovery": result})
	default:
		return writeUpgradeError(stderr, exitArgs, "invalid_arguments")
	}
}

func writeBackupError(stdout io.Writer, err error) int {
	if errors.Is(err, install.ErrBackupConflict) {
		return writeUpgradeError(stdout, exitConflict, "backup_conflict")
	}
	return writeUpgradeError(stdout, exitInternal, "backup_unavailable")
}

func writeBootstrapError(stdout io.Writer, err error) int {
	if errors.Is(err, install.ErrUpgradeLocked) {
		return writeUpgradeError(stdout, exitLocked, "bootstrap_locked")
	}
	if errors.Is(err, install.ErrBootstrapConflict) || errors.Is(err, install.ErrUpgradeJournalConflict) || errors.Is(err, install.ErrCandidateConflict) {
		return writeUpgradeError(stdout, exitConflict, "bootstrap_conflict")
	}
	if errors.Is(err, install.ErrBootstrapRecoveryRequired) {
		return writeUpgradeError(stdout, exitRecovery, "bootstrap_recovery_required")
	}
	return writeUpgradeError(stdout, exitInternal, "bootstrap_unavailable")
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
	case "installation-identity-migrate":
		if len(args) != 1 {
			return upgradeCommandConfig{}, errors.New("installation identity migration takes no flags")
		}
	case "prepare-control":
		if len(args) != 1 {
			return upgradeCommandConfig{}, errors.New("prepare-control takes no flags")
		}
	case "prepare-bootstrap":
		if len(args) != 3 || args[1] != "--expected-manifest-sha256" || !validCLISHA(args[2]) {
			return upgradeCommandConfig{}, errors.New("invalid prepare-bootstrap command")
		}
		config.manifestSHA256 = args[2]
	case "bootstrap-native", "bootstrap-verify", "bootstrap-finalize":
		for index := 1; index < len(args); index++ {
			if index+1 >= len(args) {
				return upgradeCommandConfig{}, errors.New("flag value required")
			}
			flag, value := args[index], args[index+1]
			index++
			switch flag {
			case "--expected-manifest-sha256":
				config.manifestSHA256 = value
			case "--confirm-installation-id":
				config.confirmation = value
			default:
				return upgradeCommandConfig{}, errors.New("unsupported flag")
			}
		}
		if !validCLISHA(config.manifestSHA256) || !validBootstrapConfirmation(config.confirmation) || !containsExactly(args[1:], "--expected-manifest-sha256", "--confirm-installation-id") {
			return upgradeCommandConfig{}, errors.New("invalid bootstrap command")
		}
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
	case "restore-preflight", "restore-run":
		for index := 1; index < len(args); index++ {
			flag := args[index]
			if index+1 >= len(args) {
				return upgradeCommandConfig{}, errors.New("flag value required")
			}
			index++
			switch flag {
			case "--transaction-id":
				config.transactionID = args[index]
			case "--backup-id":
				config.backupID = args[index]
			default:
				return upgradeCommandConfig{}, errors.New("unsupported flag")
			}
		}
		if !validCLIIdentifier(config.transactionID) || !validCLIBackupID(config.backupID) || !containsExactly(args[1:], "--transaction-id", "--backup-id") {
			return upgradeCommandConfig{}, errors.New("invalid restore command")
		}
	case "backup-create":
		for index := 1; index < len(args); index++ {
			flag := args[index]
			if index+1 >= len(args) {
				return upgradeCommandConfig{}, errors.New("flag value required")
			}
			index++
			switch flag {
			case "--backup-id":
				config.backupID = args[index]
			case "--reason":
				config.reason = args[index]
			default:
				return upgradeCommandConfig{}, errors.New("unsupported flag")
			}
		}
		if !validCLIBackupID(config.backupID) || !validCLIIdentifier(config.reason) || !containsExactly(args[1:], "--backup-id", "--reason") {
			return upgradeCommandConfig{}, errors.New("invalid backup create command")
		}
	case "backup-status":
		if len(args) != 3 || args[1] != "--backup-id" || !validCLIBackupID(args[2]) {
			return upgradeCommandConfig{}, errors.New("invalid backup status command")
		}
		config.backupID = args[2]
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
	case "recover-prepare", "recover-finalize":
		if len(args) != 2 || args[1] != "--pending" {
			return upgradeCommandConfig{}, errors.New("invalid boot recovery command")
		}
		config.pending = true
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

func validCLIBackupID(value string) bool {
	return strings.HasPrefix(value, "backup-") && validCLIIdentifier(value)
}

func validBootstrapConfirmation(value string) bool {
	const prefix = "BOOTSTRAP:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+48 {
		return false
	}
	for _, character := range value[len(prefix):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
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

func newProductionBootstrapRuntime(ctx context.Context) (upgradeRuntime, error) {
	return newProductionBootstrapRuntimeWithDependencies(ctx, productionBootstrapRuntimeDeps())
}

func productionBootstrapRuntimeDeps() productionBootstrapRuntimeDependencies {
	return productionBootstrapRuntimeDependencies{
		verifyExecutable:    func() error { return verifyProductionUpgradeExecutable(productionUpgradeExecutable) },
		verifyBootArtifacts: verifyProductionBootArtifacts,
		openStore: func() (install.BootstrapEngineStore, func() error, error) {
			store, err := install.ProductionBootstrapStore()
			if err != nil {
				return nil, nil, err
			}
			return store, store.Close, nil
		},
		openService: func() (install.BootstrapServiceDriver, func() error, error) {
			service, err := install.ProductionBootstrapServiceAdapter()
			if err != nil {
				return nil, nil, err
			}
			return service, service.Close, nil
		},
		openDatabase: func(input install.BootstrapDatabaseInput) (install.BootstrapDatabaseDriver, func() error, error) {
			database, err := install.ProductionBootstrapDatabase(input)
			if err != nil {
				return nil, nil, err
			}
			return database, database.Close, nil
		},
		now: func() time.Time { return time.Now().UTC() },
	}
}

func newProductionBootstrapRuntimeWithDependencies(ctx context.Context, deps productionBootstrapRuntimeDependencies) (upgradeRuntime, error) {
	if deps.verifyExecutable == nil || deps.verifyBootArtifacts == nil || deps.openStore == nil || deps.openService == nil || deps.openDatabase == nil || deps.now == nil {
		return upgradeRuntime{}, errors.New("invalid bootstrap runtime dependencies")
	}
	if deps.verifyExecutable() != nil {
		return upgradeRuntime{}, errBootExecutableUnavailable
	}
	if err := deps.verifyBootArtifacts(ctx, false); err != nil {
		if runtimeConstructionErrorCode(err) != "runtime_unavailable" {
			return upgradeRuntime{}, err
		}
		return upgradeRuntime{}, errBootArtifactsUnavailable
	}
	store, closeStore, err := deps.openStore()
	if err != nil || store == nil || closeStore == nil {
		return upgradeRuntime{}, errBootStoreUnavailable
	}
	services, closeServices, err := deps.openService()
	if err != nil || services == nil || closeServices == nil {
		_ = closeStore()
		return upgradeRuntime{}, errBootServiceUnavailable
	}
	runtime := upgradeRuntime{close: func() error {
		first := closeServices()
		if closeErr := closeStore(); first == nil {
			first = closeErr
		}
		return first
	}}
	runtime.bootstrap = func(callCtx context.Context, request install.BootstrapRequest) error {
		database, closeDatabase, err := deps.openDatabase(install.BootstrapDatabaseInput{TransactionID: request.TransactionID, InstallationIDSHA256: request.InstallationIDSHA256, CandidateActivationID: request.CandidateActivationID, Release: request.Release})
		if err != nil || database == nil || closeDatabase == nil {
			// COMMITTED replay needs no database credential and must remain
			// possible after the fixed bootstrap environment is finalized. Any
			// nonterminal journal reaches Create/Migrate and fails closed.
			database, closeDatabase = unavailableBootstrapDatabase{}, func() error { return nil }
		}
		engine := &install.BootstrapEngine{Store: store, Database: database, Services: services, Now: deps.now}
		runErr := engine.Run(callCtx, request)
		closeErr := closeDatabase()
		if runErr != nil {
			return runErr
		}
		if closeErr != nil {
			return install.ErrBootstrapRecoveryRequired
		}
		return nil
	}
	return runtime, nil
}

func newProductionRuntime(ctx context.Context) (upgradeRuntime, error) {
	return newProductionRuntimeWithDependencies(ctx, productionRuntimeDeps())
}

func productionRuntimeDeps() productionRuntimeDependencies {
	return productionRuntimeDependencies{
		verifyExecutable:           func() error { return verifyProductionUpgradeExecutable(productionUpgradeExecutable) },
		verifyBootArtifacts:        verifyProductionBootArtifacts,
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
		openBackupInspector: func() (install.UpgradeBackupInspector, func() error, error) {
			manager, err := install.ProductionBackupManager()
			if err != nil {
				return nil, nil, err
			}
			return manager, manager.Close, nil
		},
		databaseFactory: install.NewProductionUpgradeDatabaseFactory(),
		now:             func() time.Time { return time.Now().UTC() },
	}
}

func newProductionRuntimeWithDependencies(ctx context.Context, deps productionRuntimeDependencies) (upgradeRuntime, error) {
	if deps.verifyExecutable == nil || deps.verifyRecoveryUnit == nil || deps.verifyRecoveryServiceState == nil || deps.openStore == nil || deps.openService == nil || deps.openBackupInspector == nil || deps.databaseFactory == nil || deps.now == nil {
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
	backupInspector, closeBackups, err := deps.openBackupInspector()
	if err != nil || backupInspector == nil || closeBackups == nil {
		_ = closeService()
		_ = store.close()
		return upgradeRuntime{}, errors.New("open backup manager failed")
	}
	engine := &install.UpgradeEngine{Store: store.store, DatabaseFactory: deps.databaseFactory, Services: service, BackupInspector: backupInspector, Now: deps.now}
	return upgradeRuntime{
		preflight:        engine.Preflight,
		run:              engine.RunNew,
		recover:          engine.Recover,
		status:           store.status,
		pending:          store.pending,
		restorePreflight: engine.PreflightRestore,
		restoreRun:       engine.RunRestore,
		close: func() error {
			first := closeBackups()
			if err := closeService(); first == nil {
				first = err
			}
			if err := store.close(); first == nil {
				first = err
			}
			return first
		},
	}, nil
}

// newProductionBackupRuntime owns only the V2 backup receipt boundary. It
// neither opens a release, database migration adapter, nor a service driver.
func newProductionBackupRuntime(_ context.Context) (upgradeRuntime, error) {
	if verifyProductionUpgradeExecutable(productionUpgradeExecutable) != nil {
		return upgradeRuntime{}, errors.New("invalid production backup runtime")
	}
	backups, err := install.ProductionBackupManager()
	if err != nil {
		return upgradeRuntime{}, errors.New("open backup manager failed")
	}
	return upgradeRuntime{backupCreate: backups.Create, backupStatus: backups.Inspect, close: backups.Close}, nil
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

// verifyProductionBootArtifacts binds the privileged boot commands to all
// four exact fragments. It checks files before querying systemd so an unsafe
// fragment or drop-in can never influence an argv passed to systemctl.
// verifyProductionBootArtifacts validates the exact installed graph and its
// safe-target runtime state. Normal mutable commands and boot finalization
// require an active barrier; boot prepare may run while systemd is still
// activating the target, but it still requires the target to be enabled.
func verifyProductionBootArtifacts(ctx context.Context, requireActive bool) error {
	for _, file := range productionBootUnitFiles {
		root, name := filepath.Dir(file.path), filepath.Base(file.path)
		if err := verifyRootOwnedDirectoryChain("/etc", "/etc/systemd", "/etc/systemd/system", root); err != nil {
			return errBootUnitFilesUnavailable
		}
		raw, err := readRootOwnedNoFollowFile(root, name, 0o644)
		if err != nil || !bytes.Equal(raw, file.raw()) {
			return errBootUnitFilesUnavailable
		}
	}
	if err := verifyProductionSystemctl(); err != nil {
		return errBootSystemctlUnavailable
	}
	for _, check := range []struct {
		unit, path, state, dropins string
	}{
		{"open-card-upgrade-recover.service", install.ProductionUpgradeRecoveryUnitPath, "static", ""},
		{"open-card-upgrade-safe.target", install.ProductionUpgradeSafeBootTargetPath, "enabled", ""},
		{"open-card-upgrade-finalize.service", install.ProductionUpgradeFinalizeUnitPath, "static", ""},
		{"open-card-edge.service", "/etc/systemd/system/open-card-edge.service", "enabled", install.ProductionUpgradeEdgeMarkerDropInPath},
	} {
		values, err := productionSystemctlProperties(ctx, check.unit, "FragmentPath", "DropInPaths", "NeedDaemonReload", "UnitFileState")
		if err != nil || values["FragmentPath"] != check.path || values["DropInPaths"] != check.dropins || values["NeedDaemonReload"] != "no" || values["UnitFileState"] != check.state {
			return errBootUnitStateUnavailable
		}
	}
	target, err := productionSystemctlProperties(ctx, "open-card-upgrade-safe.target", "Requires", "Wants", "Before")
	if err != nil || !containsRequiredBootUnits(target["Requires"], "open-card-upgrade-recover.service") || !containsRequiredBootUnits(target["Wants"], "open-card-upgrade-finalize.service") || !containsRequiredBootUnits(target["Before"], "open-card-buildkit.service", "open-card-caddy.service", "open-card-server.service", "open-card-agent.service", "open-card-edge.service", "open-card-upgrade-finalize.service") {
		return errBootTargetGraphUnavailable
	}
	if err := verifyProductionSafeBootTargetState(ctx, requireActive); err != nil {
		return errBootFenceStateUnavailable
	}
	for _, check := range []struct {
		unit     string
		requires []string
	}{
		{"open-card-buildkit.service", []string{"open-card-upgrade-safe.target"}},
		{"open-card-caddy.service", []string{"open-card-upgrade-safe.target"}},
		{"open-card-server.service", []string{"open-card-buildkit.service", "open-card-upgrade-safe.target"}},
		{"open-card-agent.service", []string{"open-card-upgrade-safe.target"}},
		{"open-card-edge.service", []string{"open-card-upgrade-safe.target"}},
	} {
		values, err := productionSystemctlProperties(ctx, check.unit, "Requires")
		if err != nil || !containsRequiredBootUnits(values["Requires"], check.requires...) {
			return errBootBusinessGraphUnavailable
		}
	}
	return nil
}

func validSafeBootTargetState(unitFileState, activeState string, requireActive bool) bool {
	if unitFileState != "enabled" {
		return false
	}
	if requireActive {
		return activeState == "active"
	}
	return activeState == "active" || activeState == "activating" || activeState == "inactive"
}

func verifyProductionSafeBootTargetState(ctx context.Context, requireActive bool) error {
	values, err := productionSystemctlProperties(ctx, "open-card-upgrade-safe.target", "UnitFileState", "ActiveState")
	if err != nil || !validSafeBootTargetState(values["UnitFileState"], values["ActiveState"], requireActive) {
		return errors.New("invalid safe boot target state")
	}
	return nil
}

func productionSystemctlProperties(ctx context.Context, unit string, properties ...string) (map[string]string, error) {
	if !validSystemdUnitName(unit) || len(properties) == 0 {
		return nil, errors.New("invalid systemctl property request")
	}
	args := []string{"show", unit}
	for _, property := range properties {
		if property == "" || strings.ContainsAny(property, "= \t\n") {
			return nil, errors.New("invalid systemctl property")
		}
		args = append(args, "--property="+property)
	}
	args = append(args, "--no-pager")
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	raw, err := command.Output()
	if err != nil {
		return nil, errors.New("systemctl show failed")
	}
	return parseSystemctlProperties(raw, properties)
}

func validSystemdUnitName(value string) bool {
	if !strings.HasPrefix(value, "open-card-") || !(strings.HasSuffix(value, ".service") || strings.HasSuffix(value, ".target")) {
		return false
	}
	return !strings.ContainsAny(value, "/\\\x00 \t\n")
}

func parseSystemctlProperties(raw []byte, required []string) (map[string]string, error) {
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if _, exists := values[key]; !ok || key == "" || exists {
			return nil, errors.New("invalid systemctl properties")
		}
		values[key] = value
	}
	if len(values) != len(required) {
		return nil, errors.New("invalid systemctl properties")
	}
	for _, property := range required {
		if _, ok := values[property]; !ok {
			return nil, errors.New("invalid systemctl properties")
		}
	}
	return values, nil
}

// containsRequiredBootUnits validates only the declarative Open Card part of
// a systemd graph. systemd appends ordering/default dependencies such as
// sysinit.target and shutdown.target at runtime and may reorder all entries,
// so byte-for-byte equality would reject a correct host. It still rejects a
// duplicate, malformed, or unapproved Open Card unit.
func containsRequiredBootUnits(value string, expected ...string) bool {
	fields := strings.Fields(value)
	wanted := make(map[string]struct{}, len(expected))
	for _, unit := range expected {
		if !validSystemdUnitName(unit) {
			return false
		}
		wanted[unit] = struct{}{}
	}
	seen := make(map[string]struct{}, len(fields))
	for _, unit := range fields {
		if unit == "" || strings.ContainsAny(unit, "/\\\x00") {
			return false
		}
		if _, exists := seen[unit]; exists {
			return false
		}
		seen[unit] = struct{}{}
		if strings.HasPrefix(unit, "open-card-") {
			if _, approved := wanted[unit]; !approved {
				return false
			}
		}
	}
	for unit := range wanted {
		if _, found := seen[unit]; !found {
			return false
		}
	}
	return true
}

func verifyProductionRecoveryServiceState(ctx context.Context) error {
	return verifyProductionBootArtifacts(ctx, true)
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

// verifySafeBootTargetStateWithDependencies is the narrow injected seam for
// the mutable-runtime fence. Its caller has already pinned /usr/bin/systemctl
// and the canonical unit fragments; this helper proves that ordinary mutable
// commands cannot run in the gap before the safe target becomes active.
func verifySafeBootTargetStateWithDependencies(ctx context.Context, commandFactory systemctlCommandFactory, requireActive bool) error {
	if commandFactory == nil {
		return errors.New("invalid safe boot target state")
	}
	command := commandFactory(ctx, "/usr/bin/systemctl", "show", "open-card-upgrade-safe.target", "--property=UnitFileState", "--property=ActiveState", "--no-pager")
	if command == nil {
		return errors.New("invalid safe boot target state")
	}
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	raw, err := command.Output()
	if err != nil {
		return errors.New("invalid safe boot target state")
	}
	values, err := parseSystemctlProperties(raw, []string{"UnitFileState", "ActiveState"})
	if err != nil || !validSafeBootTargetState(values["UnitFileState"], values["ActiveState"], requireActive) {
		return errors.New("invalid safe boot target state")
	}
	return nil
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
	if len(values) != 4 || values["FragmentPath"] != productionUpgradeRecoveryUnit || values["DropInPaths"] != "" || values["NeedDaemonReload"] != "no" || values["UnitFileState"] != "static" {
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
