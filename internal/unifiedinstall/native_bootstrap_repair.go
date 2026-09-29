package unifiedinstall

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/acornfoxrelease"
	"github.com/open-card/open-card/internal/artifactio"
	"github.com/open-card/open-card/internal/corelaunch"
	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/localpeer"
	"github.com/open-card/open-card/internal/persistence/sqlite"
	"golang.org/x/sys/unix"
)

const (
	bootstrapRepairRoot           = UnifiedPrivateStageRoot + "/bootstrap-repair"
	bootstrapRepairOldPin         = "/etc/acornfox/trust/bootstrap-repair-old-pin.json"
	bootstrapRepairNewPin         = "/etc/acornfox/trust/bootstrap-repair-new-pin.json"
	bootstrapRepairIntentPath     = bootstrapRepairRoot + "/intent.json"
	bootstrapRepairAuthorizedPath = bootstrapRepairRoot + "/start-authorized"
	bootstrapRepairDropInDir      = "/etc/systemd/system/acornfox-core.service.d"
	bootstrapRepairDropInPath     = bootstrapRepairDropInDir + "/50-acornfox-bootstrap-repair.conf"
)

var ErrBootstrapRepairUnknown = errors.New("owned bootstrap repair outcome unknown; preserve gate, intent, database and releases")

type NativeBootstrapRepairStageResult struct {
	StagePath              string `json:"stage_path"`
	ReleaseID              string `json:"release_id"`
	ManifestSHA256         string `json:"manifest_sha256"`
	Status                 string `json:"status"`
	RuntimeEvidencePending bool   `json:"runtime_evidence_pending"`
}

// StageNativeBootstrapRepair is the only dependency-unresolved byte-stage.
// It never supplies absent/managed dependency facts and never starts a role.
func StageNativeBootstrapRepair(ctx context.Context, bundleID string) (result NativeBootstrapRepairStageResult, returnedErr error) {
	var zero NativeBootstrapRepairStageResult
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || os.Getegid() != 0 || !ValidNativeBundleID(bundleID) {
		return zero, ErrIncomplete
	}
	intent, err := repairReadIntent()
	if err != nil {
		return zero, err
	}
	if err := repairStageIntentMatches(intent, bundleID, intent.NewManifestSHA256, intent.NewReleaseID); err != nil {
		return zero, err
	}
	lock, err := repairLaunchLock()
	if err != nil {
		return zero, err
	}
	defer func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN); _ = lock.Close() }()
	if err := repairRequireAbsent(bootstrapRepairAuthorizedPath, repairPhasePath("release-install-planned")); err != nil {
		return zero, err
	}
	if err := repairDropInEffective(ctx); err != nil {
		return zero, err
	}
	var oldPin, newPin acornfoxrelease.TrustedReleasePinV1
	if err := readProtectedPublisherJSON(bootstrapRepairOldPin, 4096, &oldPin); err != nil {
		return zero, err
	}
	if err := readProtectedPublisherJSON(bootstrapRepairNewPin, 4096, &newPin); err != nil {
		return zero, err
	}
	for _, item := range []struct{ path, want string }{{bootstrapRepairOldPin, intent.OldPinSHA256}, {bootstrapRepairNewPin, intent.NewPinSHA256}, {UnifiedTrustedPinPath, intent.NewPinSHA256}} {
		actual, e := repairProtectedFileSHA(item.path, 0o600, 0)
		if e != nil || actual != item.want {
			return zero, ErrIncomplete
		}
	}
	oldComplete := filepath.Join(UnifiedPrivateStageRoot, nativeHostPrepareRecords, "prepare-"+intent.OldManifestSHA256+"-complete.json")
	var oldReceipt nativeHostReceipt
	if err := readHostJSON(oldComplete, 0, 0, &oldReceipt); err != nil || oldReceipt.Result.InstallationID != intent.InstallationID || oldReceipt.Result.StagePath != intent.OldStagePath {
		return zero, ErrIncomplete
	}
	oldStage, err := verifyStagedRelease(ctx, intent.OldStagePath, UnifiedPrivateStageRoot, oldPin, 0, 0)
	if err != nil || oldStage.sha256 != intent.OldManifestSHA256 || oldStage.manifest.ReleaseID != intent.OldReleaseID {
		return zero, ErrIncomplete
	}
	if _, err := readCompletedHostPreparation(ctx, intent.OldStagePath, oldStage, productionNativeHostDeps(), oldComplete); err != nil {
		return zero, err
	}
	firstPath := filepath.Join(UnifiedPrivateStageRoot, nativeHostPrepareRecords, "first-core-"+intent.OldManifestSHA256+"-intent.json")
	var first nativeFirstCoreIntent
	if err := readHostJSON(firstPath, 0, 0, &first); err != nil || first.InstallationID != intent.InstallationID || first.StagePath != intent.OldStagePath || first.ReleaseID != intent.OldReleaseID || first.ManifestSHA256 != intent.OldManifestSHA256 || first.TokenSHA256 != intent.TokenSHA256 {
		return zero, ErrIncomplete
	}
	oldCompleteSHA, e1 := repairProtectedFileSHA(oldComplete, 0o600, 0)
	firstSHA, e2 := repairProtectedFileSHA(firstPath, 0o600, 0)
	installationSHA, e3 := repairProtectedFileSHA(UnifiedInstallationIDPath, 0o600, 0)
	if e1 != nil || e2 != nil || e3 != nil {
		return zero, ErrIncomplete
	}
	if err := repairFreshAdmissionWithPin(ctx, intent, oldComplete, oldCompleteSHA, firstPath, firstSHA, installationSHA, intent.NewPinSHA256); err != nil {
		return zero, err
	}
	if err := repairStoppedUnit(ctx, intent.OldUnitSHA256); err != nil {
		return zero, err
	}
	if err := repairNoBusinessRoles(ctx, oldStage.manifest); err != nil {
		return zero, err
	}
	if err := repairOwnedRuntimeInactive(ctx, oldStage.manifest); err != nil {
		return zero, err
	}
	account := oldReceipt.Accounts
	generation, inode, err := readCoreGenerationOnly(ctx, sqlite.CompiledNativeMigrationPins(), uint32(account.CoreUID), uint32(account.CoreGID))
	if err != nil || generation != intent.DatabaseGeneration || inode != intent.DatabaseInode {
		return zero, ErrIncomplete
	}
	if err := repairEmptyUserFacts(ctx, inode, generation, account.CoreUID, account.CoreGID); err != nil {
		return zero, err
	}
	if err := repairStageReadyAbsent(intent.OldStagePath); err != nil {
		return zero, err
	}
	incoming, err := verifyBootstrapRepairIncoming(ctx, bundleID, newPin)
	if err != nil || incoming.SHA256 != intent.NewManifestSHA256 || incoming.Manifest.ReleaseID != intent.NewReleaseID {
		return zero, ErrIncomplete
	}
	loaded, err := loadProductionNativeStageInputWithCollector(ctx, bundleID, collectNativeArtifactHostFacts)
	if err != nil {
		return zero, err
	}
	defer func() {
		if e := loaded.Close(); e != nil {
			returnedErr = errors.Join(returnedErr, ErrBootstrapRepairUnknown, e)
		}
	}()
	manifest, err := loaded.Intake.Witness.Snapshot()
	if err != nil {
		return zero, err
	}
	newSHA, err := loaded.Intake.Witness.ManifestSHA256()
	if err != nil {
		return zero, err
	}
	if err := repairStageIntentMatches(intent, bundleID, newSHA, manifest.ReleaseID); err != nil {
		return zero, err
	}
	if err := repairSameNativeSQLitePins(oldStage.manifest.SQLiteCompatibility, manifest.SQLiteCompatibility); err != nil {
		return zero, err
	}
	if err := repairSameDependencyRuntime(oldStage.manifest, manifest); err != nil {
		return zero, err
	}
	if _, err := inspectRepairArtifactCandidate(ctx, loaded.Intake); err != nil {
		return zero, err
	}
	staged, err := stageProductionRepairBytes(ctx, loaded.Intake)
	if err != nil {
		return zero, errors.Join(ErrBootstrapRepairUnknown, err)
	}
	result = NativeBootstrapRepairStageResult{StagePath: staged.Path, ReleaseID: staged.ReleaseID, ManifestSHA256: staged.ManifestSHA256, Status: "inactive_staged", RuntimeEvidencePending: true}
	if staged.ReleaseID != intent.NewReleaseID || staged.ManifestSHA256 != intent.NewManifestSHA256 {
		return zero, ErrBootstrapRepairUnknown
	}
	if observed, err := verifyStagedRelease(ctx, staged.Path, UnifiedPrivateStageRoot, newPin, 0, 0); err != nil || observed.sha256 != intent.NewManifestSHA256 {
		return zero, ErrBootstrapRepairUnknown
	}
	if err := repairRequireAbsent(bootstrapRepairAuthorizedPath); err != nil {
		return zero, ErrBootstrapRepairUnknown
	}
	if err := repairDropInEffective(ctx); err != nil {
		return zero, errors.Join(ErrBootstrapRepairUnknown, err)
	}
	if err := repairFreshAdmissionWithPin(ctx, intent, oldComplete, oldCompleteSHA, firstPath, firstSHA, installationSHA, intent.NewPinSHA256); err != nil {
		return zero, errors.Join(ErrBootstrapRepairUnknown, err)
	}
	if err := repairStoppedUnit(ctx, intent.OldUnitSHA256); err != nil {
		return zero, errors.Join(ErrBootstrapRepairUnknown, err)
	}
	if err := repairNoBusinessRoles(ctx, oldStage.manifest); err != nil {
		return zero, errors.Join(ErrBootstrapRepairUnknown, err)
	}
	if err := repairOwnedRuntimeInactive(ctx, oldStage.manifest); err != nil {
		return zero, errors.Join(ErrBootstrapRepairUnknown, err)
	}
	if err := repairEmptyUserFacts(ctx, inode, generation, account.CoreUID, account.CoreGID); err != nil {
		return zero, errors.Join(ErrBootstrapRepairUnknown, err)
	}
	return result, nil
}

func repairStageReadyAbsent(oldStagePath string) error {
	return repairStageReadyAbsentAt(UnifiedPrivateStageRoot, oldStagePath)
}

func repairStageReadyAbsentAt(root, oldStagePath string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return ErrIncomplete
	}
	for _, entry := range entries {
		name := entry.Name()
		if nativeReadyName.MatchString(name) {
			if filepath.Join(root, name) != oldStagePath {
				return ErrBootstrapRepairUnknown
			}
			continue
		}
		if strings.HasPrefix(name, ".partial-") {
			return ErrBootstrapRepairUnknown
		}
	}
	return nil
}

type NativeBootstrapRepairBeginResult struct {
	InstallationID    string `json:"installation_id"`
	BundleID          string `json:"bundle_id"`
	OldReleaseID      string `json:"old_release_id"`
	NewReleaseID      string `json:"new_release_id"`
	OldManifestSHA256 string `json:"old_manifest_sha256"`
	NewManifestSHA256 string `json:"new_manifest_sha256"`
	OldPinSHA256      string `json:"old_pin_sha256"`
	NewPinSHA256      string `json:"new_pin_sha256"`
	IntentSHA256      string `json:"intent_sha256"`
	Status            string `json:"status"`
}

type bootstrapRepairIntent struct {
	InstallationID     string `json:"installation_id"`
	Nonce              string `json:"nonce"`
	BundleID           string `json:"bundle_id"`
	OldStagePath       string `json:"old_stage_path"`
	OldReleaseID       string `json:"old_release_id"`
	NewReleaseID       string `json:"new_release_id"`
	OldManifestSHA256  string `json:"old_manifest_sha256"`
	NewManifestSHA256  string `json:"new_manifest_sha256"`
	OldPinSHA256       string `json:"old_pin_sha256"`
	NewPinSHA256       string `json:"new_pin_sha256"`
	OldCurrentSHA256   string `json:"old_current_sha256"`
	OldUnitSHA256      string `json:"old_unit_sha256"`
	TokenSHA256        string `json:"token_sha256"`
	DatabaseInode      uint64 `json:"database_inode"`
	DatabaseGeneration int64  `json:"database_generation"`
	LaunchHighWater    int64  `json:"launch_high_water"`
}

type bootstrapRepairIncoming struct {
	Path     string
	Manifest acornfoxrelease.UnifiedReleaseManifestV1
	SHA256   string
}

// BeginNativeBootstrapRepair is the sole root-owned admission for the failed
// first-Core installation. A new active pin, stage, backup or Core start is
// forbidden until this returns a durable, read-back closed start gate.
func BeginNativeBootstrapRepair(ctx context.Context, bundleID string) (NativeBootstrapRepairBeginResult, error) {
	var zero NativeBootstrapRepairBeginResult
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || os.Getegid() != 0 || !ValidNativeBundleID(bundleID) {
		return zero, ErrIncomplete
	}
	var oldPin, newPin acornfoxrelease.TrustedReleasePinV1
	if err := readProtectedPublisherJSON(bootstrapRepairOldPin, 4096, &oldPin); err != nil {
		return zero, err
	}
	if err := readProtectedPublisherJSON(bootstrapRepairNewPin, 4096, &newPin); err != nil {
		return zero, err
	}
	if oldPin.ExpectedReleaseID == newPin.ExpectedReleaseID || oldPin.ExpectedManifestSHA256 == newPin.ExpectedManifestSHA256 || oldPin.ExpectedSourceCommit == newPin.ExpectedSourceCommit {
		return zero, ErrIncomplete
	}
	active, err := repairProtectedFileSHA(UnifiedTrustedPinPath, 0o600, 0)
	if err != nil {
		return zero, err
	}
	oldPinSHA, err := repairProtectedFileSHA(bootstrapRepairOldPin, 0o600, 0)
	if err != nil || active != oldPinSHA {
		return zero, ErrIncomplete
	}
	newPinSHA, err := repairProtectedFileSHA(bootstrapRepairNewPin, 0o600, 0)
	if err != nil {
		return zero, err
	}
	if err := repairRootBeforeIntent(); err != nil {
		return zero, err
	}
	if err := repairRequireAbsent(bootstrapRepairAuthorizedPath); err != nil {
		return zero, err
	}
	dropInExists, err := repairOwnedDropInState()
	if err != nil {
		return zero, err
	}
	incoming, err := verifyBootstrapRepairIncoming(ctx, bundleID, newPin)
	if err != nil {
		return zero, err
	}
	if incoming.SHA256 != newPin.ExpectedManifestSHA256 {
		return zero, ErrIncomplete
	}
	newRelease, err := install.ReleaseDirectory(install.UnifiedReleasesDir, incoming.Manifest.ReleaseID)
	if err != nil {
		return zero, err
	}
	if err := repairRequireAbsent(newRelease); err != nil {
		return zero, err
	}
	var hostReceipt nativeHostReceipt
	oldComplete := filepath.Join(UnifiedPrivateStageRoot, nativeHostPrepareRecords, "prepare-"+oldPin.ExpectedManifestSHA256+"-complete.json")
	if err := readHostJSON(oldComplete, 0, 0, &hostReceipt); err != nil {
		return zero, err
	}
	oldCompleteSHA, err := repairProtectedFileSHA(oldComplete, 0o600, 0)
	if err != nil {
		return zero, err
	}
	oldStage, err := verifyStagedRelease(ctx, hostReceipt.Result.StagePath, UnifiedPrivateStageRoot, oldPin, 0, 0)
	if err != nil {
		return zero, err
	}
	if _, err := readCompletedHostPreparation(ctx, hostReceipt.Result.StagePath, oldStage, productionNativeHostDeps(), oldComplete); err != nil {
		return zero, err
	}
	if oldStage.sha256 != oldPin.ExpectedManifestSHA256 || oldStage.manifest.ReleaseID != oldPin.ExpectedReleaseID || hostReceipt.Result.InstallationID == "" {
		return zero, ErrIncomplete
	}
	if err := repairSameNativeSQLitePins(oldStage.manifest.SQLiteCompatibility, incoming.Manifest.SQLiteCompatibility); err != nil {
		return zero, err
	}
	if err := repairSameDependencyRuntime(oldStage.manifest, incoming.Manifest); err != nil {
		return zero, err
	}
	var first nativeFirstCoreIntent
	firstPath := filepath.Join(UnifiedPrivateStageRoot, nativeHostPrepareRecords, "first-core-"+oldStage.sha256+"-intent.json")
	if err := readHostJSON(firstPath, 0, 0, &first); err != nil {
		return zero, err
	}
	firstSHA, err := repairProtectedFileSHA(firstPath, 0o600, 0)
	if err != nil {
		return zero, err
	}
	installationSHA, err := repairProtectedFileSHA(UnifiedInstallationIDPath, 0o600, 0)
	if err != nil {
		return zero, err
	}
	if first.InstallationID != hostReceipt.Result.InstallationID || first.StagePath != hostReceipt.Result.StagePath || first.ReleaseID != oldStage.manifest.ReleaseID || first.ManifestSHA256 != oldStage.sha256 || len(first.TokenSHA256) != 64 {
		return zero, ErrIncomplete
	}
	currentPath := install.UnifiedCurrentSymlink
	current, err := os.Lstat(currentPath)
	if err != nil || current.Mode()&os.ModeSymlink == 0 || artifactio.CheckFileOwner(current, 0, 0) != nil {
		return zero, ErrIncomplete
	}
	oldRelease, err := install.ReleaseDirectory(install.UnifiedReleasesDir, oldStage.manifest.ReleaseID)
	if err != nil {
		return zero, err
	}
	link, err := os.Readlink(currentPath)
	if err != nil || link != oldRelease {
		return zero, ErrIncomplete
	}
	currentSHA := sha256.Sum256([]byte(link))
	tokenSHA, err := repairProtectedFileSHA(nativeCoreSetupTokenSource, 0o600, 0)
	if err != nil || tokenSHA != first.TokenSHA256 {
		return zero, ErrIncomplete
	}
	unitPath := "/etc/systemd/system/" + NativeCoreUnit
	unitSHA, err := repairProtectedFileSHA(unitPath, 0o644, 0)
	if err != nil || hostReceipt.Files[unitPath] != unitSHA {
		return zero, ErrIncomplete
	}
	state, err := readNativeCoreUnitState(ctx)
	if err != nil || !state.Loaded || state.Active || state.MainPID != 0 || !nativeNoUnitJob(state.Job) {
		return zero, ErrIncomplete
	}
	lock, err := repairLaunchLock()
	if err != nil {
		return zero, err
	}
	defer lock.Close()
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	if err := repairStoppedUnit(ctx, unitSHA); err != nil {
		return zero, err
	}
	if err := repairNoBusinessRoles(ctx, oldStage.manifest); err != nil {
		return zero, err
	}
	account := hostReceipt.Accounts
	generation, inode, err := readCoreGenerationOnly(ctx, sqlite.CompiledNativeMigrationPins(), uint32(account.CoreUID), uint32(account.CoreGID))
	if err != nil || inode == 0 || generation < 1 {
		return zero, ErrIncomplete
	}
	highWater, err := readCoreLaunchHighWater(nativeCoreJournal, hostReceipt.Result.InstallationID)
	if err != nil || highWater < generation {
		return zero, ErrIncomplete
	}
	if err := repairEmptyUserFacts(ctx, inode, generation, account.CoreUID, account.CoreGID); err != nil {
		return zero, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return zero, err
	}
	intent := bootstrapRepairIntent{InstallationID: hostReceipt.Result.InstallationID, Nonce: hex.EncodeToString(nonce[:]), BundleID: bundleID,
		OldStagePath: hostReceipt.Result.StagePath, OldReleaseID: oldStage.manifest.ReleaseID, NewReleaseID: incoming.Manifest.ReleaseID,
		OldManifestSHA256: oldStage.sha256, NewManifestSHA256: incoming.SHA256, OldPinSHA256: oldPinSHA, NewPinSHA256: newPinSHA,
		OldCurrentSHA256: hex.EncodeToString(currentSHA[:]), OldUnitSHA256: unitSHA, TokenSHA256: tokenSHA,
		DatabaseInode: inode, DatabaseGeneration: generation, LaunchHighWater: highWater}
	unknown := func(err error) (NativeBootstrapRepairBeginResult, error) {
		return zero, errors.Join(ErrBootstrapRepairUnknown, err)
	}
	const dropIn = "[Unit]\nConditionPathExists=" + bootstrapRepairAuthorizedPath + "\n"
	if !dropInExists {
		if err := ensureNativeDirectory(bootstrapRepairDropInDir, 0, 0, 0o755, true); err != nil {
			return unknown(err)
		}
		if err := publishHostFile(bootstrapRepairDropInPath, []byte(dropIn), 0o644, 0, 0); err != nil {
			return unknown(err)
		}
	}
	if err := nativeFirstCoreSystemctl(ctx, "daemon-reload"); err != nil {
		return unknown(err)
	}
	if err := repairRequireAbsent(bootstrapRepairAuthorizedPath); err != nil {
		return unknown(err)
	}
	if err := repairDropInEffective(ctx); err != nil {
		return unknown(err)
	}
	if err := repairStoppedUnit(ctx, unitSHA); err != nil {
		return unknown(err)
	}
	if err := repairNoBusinessRoles(ctx, oldStage.manifest); err != nil {
		return unknown(err)
	}
	if err := repairFreshAdmission(ctx, intent, oldComplete, oldCompleteSHA, firstPath, firstSHA, installationSHA); err != nil {
		return unknown(err)
	}
	// The durable gate is now effective. Recheck mutable DB facts under the
	// launch lock before freezing an intent; a crash before this point leaves
	// only an exact owned stop gate and no active pin/current repair effect.
	againGeneration, againInode, err := readCoreGenerationOnly(ctx, sqlite.CompiledNativeMigrationPins(), uint32(account.CoreUID), uint32(account.CoreGID))
	if err != nil || againGeneration != generation || againInode != inode {
		return unknown(ErrIncomplete)
	}
	if err := repairEmptyUserFacts(ctx, inode, generation, account.CoreUID, account.CoreGID); err != nil {
		return unknown(err)
	}
	if err := ensureNativeDirectory(bootstrapRepairRoot, 0, 0, 0o700, true); err != nil {
		return unknown(err)
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		return unknown(err)
	}
	if err := publishHostFile(bootstrapRepairIntentPath, raw, 0o600, 0, 0); err != nil {
		return unknown(err)
	}
	intentDigest := sha256.Sum256(raw)
	intentSHA, err := repairProtectedFileSHA(bootstrapRepairIntentPath, 0o600, 0)
	if err != nil || intentSHA != hex.EncodeToString(intentDigest[:]) {
		return unknown(ErrIncomplete)
	}
	var readback bootstrapRepairIntent
	if err := readHostJSON(bootstrapRepairIntentPath, 0, 0, &readback); err != nil || readback != intent {
		return unknown(ErrIncomplete)
	}
	return NativeBootstrapRepairBeginResult{InstallationID: intent.InstallationID, BundleID: intent.BundleID, OldReleaseID: intent.OldReleaseID, NewReleaseID: intent.NewReleaseID,
		OldManifestSHA256: intent.OldManifestSHA256, NewManifestSHA256: intent.NewManifestSHA256,
		OldPinSHA256: intent.OldPinSHA256, NewPinSHA256: intent.NewPinSHA256, IntentSHA256: intentSHA, Status: "gate_closed"}, nil
}

func repairRequireAbsent(paths ...string) error {
	for _, path := range paths {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return ErrIncomplete
		}
	}
	return nil
}

func repairSameNativeSQLitePins(old, next acornfoxrelease.SQLiteCompatibilityV1) error {
	compiled := sqlite.CompiledNativeMigrationPins()
	if old.ReadWriteMode != "exclusive_writer" || next.ReadWriteMode != old.ReadWriteMode ||
		old.RollbackPolicy != acornfoxrelease.RollbackRequiresDataRestore || next.RollbackPolicy != old.RollbackPolicy ||
		len(old.RequiredMigrations) != len(compiled) || len(next.RequiredMigrations) != len(compiled) {
		return ErrIncompatible
	}
	for i, pin := range compiled {
		if old.RequiredMigrations[i].Version != pin.Version || old.RequiredMigrations[i].Checksum != pin.Checksum ||
			next.RequiredMigrations[i] != old.RequiredMigrations[i] {
			return ErrIncompatible
		}
	}
	return nil
}

func repairSameDependencyRuntime(old, next acornfoxrelease.UnifiedReleaseManifestV1) error {
	if !reflect.DeepEqual(old.Dependencies, next.Dependencies) || len(old.Dependencies) != 4 {
		return ErrIncompatible
	}
	oldArtifacts := make(map[string]acornfoxrelease.UnifiedArtifactV1, len(old.Artifacts))
	nextArtifacts := make(map[string]acornfoxrelease.UnifiedArtifactV1, len(next.Artifacts))
	for _, artifact := range old.Artifacts {
		oldArtifacts[artifact.ID] = artifact
	}
	for _, artifact := range next.Artifacts {
		nextArtifacts[artifact.ID] = artifact
	}
	for _, policy := range old.Dependencies {
		for _, id := range policy.RuntimeArtifactIDs {
			before, oldOK := oldArtifacts[id]
			after, newOK := nextArtifacts[id]
			if !oldOK || !newOK || before.RelativePath != after.RelativePath || before.SizeBytes != after.SizeBytes || before.SHA256 != after.SHA256 || before.Executable != after.Executable {
				return ErrIncompatible
			}
		}
	}
	return nil
}

func repairStageIntentMatches(intent bootstrapRepairIntent, bundleID, manifestSHA, releaseID string) error {
	if !ValidNativeBundleID(bundleID) || intent.BundleID != bundleID || len(intent.NewManifestSHA256) != 64 || intent.NewManifestSHA256 != manifestSHA || intent.NewReleaseID != releaseID {
		return ErrIncomplete
	}
	return nil
}

func repairFreshAdmission(ctx context.Context, intent bootstrapRepairIntent, oldComplete, oldCompleteSHA, firstPath, firstSHA, installationSHA string) error {
	return repairFreshAdmissionWithPin(ctx, intent, oldComplete, oldCompleteSHA, firstPath, firstSHA, installationSHA, intent.OldPinSHA256)
}

func repairFreshAdmissionWithPin(ctx context.Context, intent bootstrapRepairIntent, oldComplete, oldCompleteSHA, firstPath, firstSHA, installationSHA, activePinSHA string) error {
	for _, item := range []struct{ path, want string }{
		{bootstrapRepairOldPin, intent.OldPinSHA256},
		{bootstrapRepairNewPin, intent.NewPinSHA256},
		{UnifiedTrustedPinPath, activePinSHA},
		{oldComplete, oldCompleteSHA},
		{firstPath, firstSHA},
		{UnifiedInstallationIDPath, installationSHA},
		{nativeCoreSetupTokenSource, intent.TokenSHA256},
	} {
		got, err := repairProtectedFileSHA(item.path, 0o600, 0)
		if err != nil || got != item.want {
			return ErrIncomplete
		}
	}
	installation, err := readNativeInstallationID(productionNativeHostDeps())
	if err != nil || installation != intent.InstallationID {
		return ErrIncomplete
	}
	current, err := os.Lstat(install.UnifiedCurrentSymlink)
	if err != nil || current.Mode()&os.ModeSymlink == 0 || artifactio.CheckFileOwner(current, 0, 0) != nil {
		return ErrIncomplete
	}
	link, err := os.Readlink(install.UnifiedCurrentSymlink)
	if err != nil || link != filepath.Join(install.UnifiedReleasesDir, intent.OldReleaseID) {
		return ErrIncomplete
	}
	sum := sha256.Sum256([]byte(link))
	if hex.EncodeToString(sum[:]) != intent.OldCurrentSHA256 {
		return ErrIncomplete
	}
	actualHigh, err := readCoreLaunchHighWater(nativeCoreJournal, intent.InstallationID)
	if err != nil || actualHigh != intent.LaunchHighWater {
		return ErrIncomplete
	}
	if err := repairRequireAbsent(bootstrapRepairAuthorizedPath); err != nil {
		return err
	}
	return ctx.Err()
}

func repairRootBeforeIntent() error {
	info, err := os.Lstat(bootstrapRepairRoot)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || artifactio.CheckFileOwner(info, 0, 0) != nil {
		return ErrIncomplete
	}
	entries, err := os.ReadDir(bootstrapRepairRoot)
	if err != nil || len(entries) != 0 {
		return ErrIncomplete
	}
	return nil
}

func repairOwnedDropInState() (bool, error) {
	dir, err := os.Lstat(bootstrapRepairDropInDir)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || !dir.IsDir() || dir.Mode().Perm() != 0o755 || artifactio.CheckFileOwner(dir, 0, 0) != nil {
		return false, ErrIncomplete
	}
	entries, err := os.ReadDir(bootstrapRepairDropInDir)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(bootstrapRepairDropInPath) {
		return false, ErrIncomplete
	}
	const dropIn = "[Unit]\nConditionPathExists=" + bootstrapRepairAuthorizedPath + "\n"
	info, err := os.Lstat(bootstrapRepairDropInPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 || info.Size() != int64(len(dropIn)) || artifactio.CheckFileOwner(info, 0, 0) != nil {
		return false, ErrIncomplete
	}
	data, err := os.ReadFile(bootstrapRepairDropInPath)
	if err != nil || string(data) != dropIn {
		return false, ErrIncomplete
	}
	return true, nil
}

func repairProtectedFileSHA(path string, mode os.FileMode, uid int) (string, error) {
	return repairFileSHAAt(path, mode, uid, 0)
}

func repairFileSHAAt(path string, mode os.FileMode, uid, gid int) (string, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != mode || artifactio.CheckFileOwner(before, uid, gid) != nil || before.Size() < 1 || before.Size() > 1<<20 {
		return "", ErrIncomplete
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return "", ErrIncomplete
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(file, 1<<20+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func verifyBootstrapRepairIncoming(ctx context.Context, bundleID string, pin acornfoxrelease.TrustedReleasePinV1) (bootstrapRepairIncoming, error) {
	var zero bootstrapRepairIncoming
	bundle := filepath.Join(UnifiedPrivateStageRoot, "incoming", bundleID)
	for _, dir := range []string{UnifiedPrivateStageRoot, filepath.Join(UnifiedPrivateStageRoot, "incoming"), bundle} {
		if err := verifyNativeBundleDir(dir, 0, 0); err != nil {
			return zero, err
		}
	}
	root, err := os.OpenRoot(bundle)
	if err != nil {
		return zero, err
	}
	defer root.Close()
	items, err := bundleEntries(root, ".", 0, 0)
	if err != nil || len(items) != 2 {
		return zero, ErrIncomplete
	}
	names := map[string]bool{}
	for _, item := range items {
		names[item.Name()] = true
	}
	if !names["manifest.json"] || !names["payload"] {
		return zero, ErrIncomplete
	}
	info, err := root.Lstat("manifest.json")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > 64<<10 || artifactio.CheckFileOwner(info, 0, 0) != nil {
		return zero, ErrIncomplete
	}
	file, err := root.OpenFile("manifest.json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return zero, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, 64<<10+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(raw)) != info.Size() {
		return zero, ErrIncomplete
	}
	witness, err := acornfoxrelease.ParseUnifiedManifestV1(raw)
	if err != nil || acornfoxrelease.VerifyUnifiedManifestTrust(witness, pin) != nil {
		return zero, ErrIncomplete
	}
	manifest, err := witness.Snapshot()
	if err != nil {
		return zero, err
	}
	wanted := make(map[string]acornfoxrelease.UnifiedArtifactV1, len(manifest.Artifacts))
	for _, a := range manifest.Artifacts {
		wanted[a.RelativePath] = a
	}
	seen := make(map[string]bool, len(wanted))
	if err := inspectNativeBundleTree(ctx, root, "payload", wanted, seen, 0, 0, 0); err != nil || len(seen) != len(wanted) {
		return zero, ErrIncomplete
	}
	for _, a := range manifest.Artifacts {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		name := "payload/" + a.RelativePath
		before, err := root.Lstat(name)
		if err != nil || !before.Mode().IsRegular() || before.Size() != a.SizeBytes || artifactio.CheckFileOwner(before, 0, 0) != nil {
			return zero, ErrIncomplete
		}
		f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return zero, err
		}
		h := sha256.New()
		_, hashErr := io.Copy(h, io.LimitReader(f, a.SizeBytes+1))
		closeErr := f.Close()
		if hashErr != nil || closeErr != nil || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
			return zero, ErrIncomplete
		}
	}
	self, err := localpeer.AttestLinuxProcess(int32(os.Getpid()))
	if err != nil || self.UID != 0 {
		return zero, ErrIncomplete
	}
	updater, err := componentArtifact(manifest, manifest.Components.HostUpdate.ArtifactID)
	if err != nil || updater.RelativePath != "bin/acornfox-host-update" || self.ExecutablePath != filepath.Join(bundle, "payload", updater.RelativePath) || self.ExecutableSHA256 != updater.SHA256 {
		return zero, ErrIncomplete
	}
	sha, err := witness.ManifestSHA256()
	if err != nil {
		return zero, err
	}
	return bootstrapRepairIncoming{Path: bundle, Manifest: manifest, SHA256: sha}, nil
}

func repairLaunchLock() (*os.File, error) {
	journal, err := os.Lstat(nativeCoreJournal)
	if err != nil || !journal.IsDir() || journal.Mode().Perm() != 0o700 || artifactio.CheckFileOwner(journal, 0, 0) != nil {
		return nil, ErrIncomplete
	}
	path := filepath.Join(nativeCoreJournal, "launch.lock")
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 || artifactio.CheckFileOwner(before, 0, 0) != nil {
		return nil, ErrIncomplete
	}
	file, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		file.Close()
		return nil, ErrIncomplete
	}
	return file, nil
}

func repairStoppedUnit(ctx context.Context, unitSHA string) error {
	actual, err := repairProtectedFileSHA("/etc/systemd/system/"+NativeCoreUnit, 0o644, 0)
	if err != nil || actual != unitSHA {
		return ErrIncomplete
	}
	state, err := readNativeCoreUnitState(ctx)
	if err != nil || !state.Loaded || state.Active || state.MainPID != 0 || !nativeNoUnitJob(state.Job) {
		return ErrIncomplete
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, "/usr/bin/systemctl", "show", NativeCoreUnit, "--property=ActiveState,ControlPID")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	raw, err := cmd.Output()
	if err != nil || len(raw) > 256 {
		return ErrIncomplete
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return ErrIncomplete
		}
		if _, duplicate := values[key]; duplicate {
			return ErrIncomplete
		}
		values[key] = value
	}
	if len(values) != 2 || values["ActiveState"] != "inactive" && values["ActiveState"] != "failed" || values["ControlPID"] != "0" {
		return ErrIncomplete
	}
	return nil
}

func repairNoBusinessRoles(ctx context.Context, manifest acornfoxrelease.UnifiedReleaseManifestV1) error {
	if err := repairRequireAbsent(UnifiedRuntimeBindingPath); err != nil {
		return err
	}
	roles := []struct{ name, unit, relative string }{
		{acornfoxrelease.RoleContainerRuntime, "acornfox-container.service", "bin/acornfox-container"},
		{acornfoxrelease.RoleSourceBuild, "acornfox-source-build.service", "bin/acornfox-source-build"},
		{acornfoxrelease.RoleApplicationGateway, "acornfox-gateway.service", "bin/acornfox-gateway"},
	}
	executables := map[string]bool{}
	oldRelease, err := install.ReleaseDirectory(install.UnifiedReleasesDir, manifest.ReleaseID)
	if err != nil {
		return err
	}
	for _, expected := range roles {
		found := false
		for _, role := range manifest.Roles {
			if role.Name != expected.name {
				continue
			}
			if found {
				return ErrIncomplete
			}
			found = true
			artifact, e := componentArtifact(manifest, role.RunnerArtifactID)
			if e != nil || artifact.RelativePath != expected.relative || !artifact.Executable {
				return ErrIncomplete
			}
			executables[filepath.Join(oldRelease, artifact.RelativePath)] = true
		}
		if !found {
			return ErrIncomplete
		}
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		cmd := exec.CommandContext(bounded, "/usr/bin/systemctl", "show", expected.unit, "--property=Id,LoadState,ActiveState,MainPID,ControlPID,Job")
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
		raw, e := cmd.Output()
		cancel()
		if e != nil || len(raw) > 1024 {
			return ErrIncomplete
		}
		values := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok || key == "" {
				return ErrIncomplete
			}
			if _, duplicate := values[key]; duplicate {
				return ErrIncomplete
			}
			values[key] = value
		}
		if len(values) != 6 || values["Id"] != expected.unit || values["LoadState"] != "loaded" ||
			(values["ActiveState"] != "inactive" && values["ActiveState"] != "failed") ||
			values["MainPID"] != "0" || values["ControlPID"] != "0" || !nativeNoUnitJob(values["Job"]) {
			return ErrIncomplete
		}
	}
	for _, relative := range []string{"bin/acornfox-core", "bin/acornfox-host-update"} {
		executables[filepath.Join(oldRelease, relative)] = true
	}
	processes, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, process := range processes {
		if _, err := strconv.Atoi(process.Name()); err != nil {
			continue
		}
		path, e := os.Readlink(filepath.Join("/proc", process.Name(), "exe"))
		if os.IsNotExist(e) || errors.Is(e, syscall.ESRCH) {
			continue
		}
		if e != nil {
			return e
		}
		if executables[path] || executables[strings.TrimSuffix(path, " (deleted)")] {
			return ErrIncomplete
		}
	}
	return nil
}

// HostPrep owns these exact unit files and old immutable bytes. The repair
// byte-stage cannot infer a usable managed dependency from that ownership; it
// only proves no fixed service/socket/process is presently active or foreign.
func repairOwnedRuntimeInactive(ctx context.Context, manifest acornfoxrelease.UnifiedReleaseManifestV1) error {
	for _, path := range []string{
		"/run/acornfox-buildkit/buildkitd.sock", "/run/acornfox/edge-admin/admin.sock",
		"/usr/bin/buildkitd", "/usr/local/bin/buildkitd", "/usr/bin/caddy", "/usr/local/bin/caddy",
	} {
		if err := repairRequireAbsent(path); err != nil {
			return err
		}
	}
	oldRelease, err := install.ReleaseDirectory(install.UnifiedReleasesDir, manifest.ReleaseID)
	if err != nil {
		return err
	}
	artifacts := map[string]acornfoxrelease.UnifiedArtifactV1{}
	for _, artifact := range manifest.Artifacts {
		artifacts[artifact.ID] = artifact
	}
	wanted := map[string]bool{}
	for _, dependency := range manifest.Dependencies {
		if dependency.Name != acornfoxrelease.DependencyBuildKit && dependency.Name != acornfoxrelease.DependencyCaddy {
			continue
		}
		for _, id := range dependency.RuntimeArtifactIDs {
			artifact, ok := artifacts[id]
			if !ok || !strings.HasPrefix(artifact.RelativePath, "embedded/bin/") {
				return ErrIncomplete
			}
			wanted[filepath.Join(oldRelease, artifact.RelativePath)] = true
		}
	}
	if len(wanted) != 4 {
		return ErrIncomplete
	}
	for _, unit := range []string{"acornfox-buildkit.service", "acornfox-caddy.service"} {
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		cmd := exec.CommandContext(bounded, "/usr/bin/systemctl", "show", unit, "--property=Id,LoadState,ActiveState,MainPID,ControlPID,Job,FragmentPath,DropInPaths")
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
		raw, runErr := cmd.Output()
		cancel()
		if runErr != nil || len(raw) > 2048 {
			return ErrIncomplete
		}
		values := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok || key == "" {
				return ErrIncomplete
			}
			if _, duplicate := values[key]; duplicate {
				return ErrIncomplete
			}
			values[key] = value
		}
		if len(values) != 8 || values["Id"] != unit || values["LoadState"] != "loaded" || values["ActiveState"] != "inactive" && values["ActiveState"] != "failed" || values["MainPID"] != "0" || values["ControlPID"] != "0" || !nativeNoUnitJob(values["Job"]) || values["FragmentPath"] != "/etc/systemd/system/"+unit || values["DropInPaths"] != "" {
			return ErrIncomplete
		}
	}
	processes, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, process := range processes {
		if _, err := strconv.Atoi(process.Name()); err != nil {
			continue
		}
		path, e := os.Readlink(filepath.Join("/proc", process.Name(), "exe"))
		if os.IsNotExist(e) || errors.Is(e, syscall.ESRCH) {
			continue
		}
		if e != nil {
			return e
		}
		if wanted[path] || wanted[strings.TrimSuffix(path, " (deleted)")] {
			return ErrIncomplete
		}
	}
	return nil
}

const repairCoreUnitObject = "/org/freedesktop/systemd1/unit/acornfox_2dcore_2eservice"

func repairBusctlRead(ctx context.Context, args ...string) ([]byte, error) {
	out := &boundedCommandOutput{limit: 4096}
	cmd := exec.CommandContext(ctx, "/usr/bin/busctl", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil || out.data.Len() < 1 {
		return nil, ErrIncomplete
	}
	return out.data.Bytes(), nil
}

func repairJSONExactlyOne(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrIncomplete
	}
	return nil
}

func repairBusctlCoreConditions(ctx context.Context) error {
	objectRaw, err := repairBusctlRead(ctx, "--system", "--json=short", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "GetUnit", "s", NativeCoreUnit)
	if err != nil {
		return err
	}
	if err := repairValidateCoreUnitObject(objectRaw); err != nil {
		return err
	}
	conditionRaw, err := repairBusctlRead(ctx, "--system", "--json=short", "get-property", "org.freedesktop.systemd1", repairCoreUnitObject, "org.freedesktop.systemd1.Unit", "Conditions")
	if err != nil {
		return err
	}
	return repairValidateCoreConditions(conditionRaw)
}

func repairValidateCoreUnitObject(raw []byte) error {
	var object struct {
		Type string   `json:"type"`
		Data []string `json:"data"`
	}
	if repairJSONExactlyOne(raw, &object) != nil || object.Type != "o" || len(object.Data) != 1 || object.Data[0] != repairCoreUnitObject {
		return ErrIncomplete
	}
	return nil
}

func repairValidateCoreConditions(raw []byte) error {
	var envelope struct {
		Type string              `json:"type"`
		Data [][]json.RawMessage `json:"data"`
	}
	if repairJSONExactlyOne(raw, &envelope) != nil || envelope.Type != "a(sbbsi)" || len(envelope.Data) != 1 || len(envelope.Data[0]) != 5 {
		return ErrIncomplete
	}
	row := envelope.Data[0]
	var conditionType, parameter string
	if json.Unmarshal(row[0], &conditionType) != nil || json.Unmarshal(row[3], &parameter) != nil {
		return ErrIncomplete
	}
	if conditionType != "ConditionPathExists" || string(bytes.TrimSpace(row[1])) != "false" || string(bytes.TrimSpace(row[2])) != "false" || parameter != bootstrapRepairAuthorizedPath {
		return ErrIncomplete
	}
	switch string(bytes.TrimSpace(row[4])) {
	case "-1", "0", "1":
	default:
		return ErrIncomplete
	}
	// PreviousResult is historical; only the exact currently loaded condition,
	// absent marker, effective drop-in and stopped unit establish this gate.
	return nil
}

func repairDropInEffective(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, "/usr/bin/systemctl", "show", NativeCoreUnit, "--property=Id,LoadState,ActiveState,MainPID,ControlPID,Job,DropInPaths,NeedDaemonReload")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	raw, err := cmd.Output()
	if err != nil || len(raw) > 4096 {
		return ErrIncomplete
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok || name == "" {
			return ErrIncomplete
		}
		if _, duplicate := values[name]; duplicate {
			return ErrIncomplete
		}
		values[name] = value
	}
	if len(values) != 8 || values["Id"] != NativeCoreUnit || values["LoadState"] != "loaded" || values["ActiveState"] != "inactive" && values["ActiveState"] != "failed" || values["MainPID"] != "0" || values["ControlPID"] != "0" || !nativeNoUnitJob(values["Job"]) || values["DropInPaths"] != bootstrapRepairDropInPath || values["NeedDaemonReload"] != "no" {
		return ErrIncomplete
	}
	// Callers that require a closed gate also check the marker is absent.
	// Continue checks this same loaded condition after publishing its tightly
	// bound authorization file, immediately before its one Core start.
	return repairBusctlCoreConditions(bounded)
}

func repairEmptyUserFacts(ctx context.Context, inode uint64, generation int64, uid, gid int) error {
	return repairEmptyUserFactsAt(ctx, install.UnifiedCoreDataDir, inode, generation, uid, gid)
}

// The production entrypoint above fixes the Core directory. Tests use a
// private directory so they never open the host's installed database.
func repairEmptyUserFactsAt(ctx context.Context, dataDirectory string, inode uint64, generation int64, uid, gid int) error {
	path := filepath.Join(dataDirectory, install.UnifiedDefaultDBName)
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 || artifactio.CheckFileOwner(before, uid, gid) != nil {
		return ErrIncomplete
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino != inode {
		return ErrIncomplete
	}
	db, err := sql.Open("sqlite", "file:"+url.PathEscape(path)+"?mode=ro&_pragma=query_only(ON)")
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var current int64
	if err := db.QueryRowContext(ctx, "SELECT generation FROM core_generation WHERE singleton=1").Scan(&current); err != nil || current != generation {
		return ErrIncomplete
	}
	for _, table := range []string{"admin_credentials", "applications", "environments", "operations", "task_leases"} {
		var count int64
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			return ErrIncomplete
		}
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		return ErrIncomplete
	}
	return nil
}

// repairChildTicket is never taken from argv, an environment variable or an
// untrusted JSON request. The parent writes one bounded inherited descriptor.
type repairChildTicket struct {
	Operation          string `json:"operation"`
	InstallationID     string `json:"installation_id"`
	Nonce              string `json:"nonce"`
	NewReleaseID       string `json:"new_release_id"`
	NewManifestSHA256  string `json:"new_manifest_sha256"`
	ExpectedUnitSHA256 string `json:"expected_unit_sha256"`
	DatabaseInode      uint64 `json:"database_inode"`
	DatabaseGeneration int64  `json:"database_generation"`
	ParentPID          int32  `json:"parent_pid"`
	ChildSHA256        string `json:"child_sha256"`
	ChildPID           int32  `json:"child_pid"`
	CoreUID            int    `json:"core_uid"`
	BackupName         string `json:"backup_name"`
	BackupSHA256       string `json:"backup_sha256,omitempty"`
	BackupSizeBytes    int64  `json:"backup_size_bytes,omitempty"`
	BackupGeneration   int64  `json:"backup_generation,omitempty"`
	LaunchHighWater    int64  `json:"launch_high_water,omitempty"`
}

type repairChallenge struct {
	Kind     string                               `json:"kind"`
	Nonce    string                               `json:"nonce"`
	Sequence int                                  `json:"sequence"`
	Prepared *sqlite.NativeOfflineRestorePrepared `json:"prepared,omitempty"`
}
type repairChallengeReply struct {
	Digest string `json:"digest"`
	Commit bool   `json:"commit,omitempty"`
}

func repairChallengeDigest(ticketNonce, challengeNonce string, sequence int) string {
	sum := sha256.Sum256([]byte(ticketNonce + "|" + challengeNonce + "|" + strconv.Itoa(sequence)))
	return hex.EncodeToString(sum[:])
}

func repairRootChallengeRecheck(ctx context.Context, intent bootstrapRepairIntent, parent localpeer.ProcessAttestation, lock *os.File, unitSHA string) error {
	if lock == nil {
		return ErrBootstrapRepairUnknown
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return ErrBootstrapRepairUnknown
	}
	again, err := localpeer.AttestLinuxProcess(int32(os.Getpid()))
	if err != nil || again.StartTime != parent.StartTime || again.ExecutableSHA256 != parent.ExecutableSHA256 {
		return ErrBootstrapRepairUnknown
	}
	if err := repairRequireAbsent(bootstrapRepairAuthorizedPath); err != nil {
		return err
	}
	if err := repairDropInEffective(ctx); err != nil {
		return err
	}
	if err := repairStoppedUnit(ctx, unitSHA); err != nil {
		return err
	}
	pin, err := repairProtectedFileSHA(UnifiedTrustedPinPath, 0o600, 0)
	if err != nil || pin != intent.NewPinSHA256 {
		return ErrIncomplete
	}
	return nil
}

// RunNativeBootstrapRepairChild is the only demoted Core-UID maintenance
// entrypoint. Descriptor 3 carries the root-issued ticket; 4 and 5 are the
// fixed child-to-parent challenge and parent-to-child reply pipes.
func RunNativeBootstrapRepairChild(ctx context.Context, operation string, output io.Writer) error {
	account, err := user.Lookup(install.AccountCore)
	if err != nil {
		return err
	}
	uid, e1 := strconv.ParseUint(account.Uid, 10, 32)
	gid, e2 := strconv.ParseUint(account.Gid, 10, 32)
	if e1 != nil || e2 != nil {
		return ErrIncomplete
	}
	return runNativeBootstrapRepairChildAt(ctx, operation, output, repairChildEnvironment{
		coreUID: int(uid), coreGID: int(gid), dataDirectory: install.UnifiedCoreDataDir, backupDirectory: install.UnifiedBackupDir,
		verifyStopped: func(checkCtx context.Context, unitSHA string) error {
			if err := repairStoppedUnit(checkCtx, unitSHA); err != nil {
				return err
			}
			return repairDropInEffective(checkCtx)
		},
	})
}

type repairChildEnvironment struct {
	coreUID, coreGID               int
	dataDirectory, backupDirectory string
	verifyStopped                  func(context.Context, string) error
}

// Only same-package fixtures provide private paths. The exported child entry
// above always binds the installed Core account and the fixed Native paths.
func runNativeBootstrapRepairChildAt(ctx context.Context, operation string, output io.Writer, environment repairChildEnvironment) error {
	if ctx == nil || output == nil || operation != "backup" && operation != "restore" || environment.verifyStopped == nil || !filepath.IsAbs(environment.dataDirectory) || !filepath.IsAbs(environment.backupDirectory) {
		return ErrIncomplete
	}
	uid, gid := environment.coreUID, environment.coreGID
	if uid <= 0 || gid <= 0 || os.Getuid() != uid || os.Geteuid() != uid || os.Getgid() != gid || os.Getegid() != gid {
		return ErrIncomplete
	}
	if flags, err := unix.FcntlInt(uintptr(3), unix.F_GETFL, 0); err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return ErrIncomplete
	}
	base, err := corelaunch.ReadInherited(3, 4, environment.dataDirectory)
	if err != nil {
		return err
	}
	metadata := os.NewFile(5, "root-owned-repair-metadata")
	challengeWrite := os.NewFile(6, "repair-challenge-write")
	replyRead := os.NewFile(7, "repair-reply-read")
	if metadata == nil || challengeWrite == nil || replyRead == nil {
		return ErrIncomplete
	}
	defer metadata.Close()
	defer challengeWrite.Close()
	defer replyRead.Close()
	if flags, err := unix.FcntlInt(uintptr(5), unix.F_GETFL, 0); err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return ErrIncomplete
	}
	info, err := metadata.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > 4096 {
		return ErrIncomplete
	}
	identity, ok := info.Sys().(*syscall.Stat_t)
	if !ok || identity.Uid != 0 || identity.Gid != 0 || identity.Nlink != 1 {
		return ErrIncomplete
	}
	raw := make([]byte, info.Size())
	if n, err := metadata.ReadAt(raw, 0); err != nil || n != len(raw) {
		return ErrIncomplete
	}
	var ticket repairChildTicket
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&ticket) != nil || decoder.Decode(&struct{}{}) != io.EOF || ticket.Operation != operation || len(ticket.Nonce) != 32 || ticket.BackupName != "backup-"+ticket.Nonce+".db" {
		return ErrIncomplete
	}
	if operation == "restore" && (len(ticket.BackupSHA256) != 64 || ticket.BackupSizeBytes <= 0 || ticket.BackupGeneration < 0 || ticket.LaunchHighWater < ticket.BackupGeneration) {
		return ErrIncomplete
	}
	if base.InstallationID != ticket.InstallationID || base.ReleaseID != ticket.NewReleaseID || base.ManifestSHA256 != ticket.NewManifestSHA256 || base.ExecutableSHA256 != ticket.ChildSHA256 || base.DataDirectory != environment.dataDirectory || base.DatabaseInode != ticket.DatabaseInode || base.Generation != ticket.DatabaseGeneration || base.ChildPID != os.Getpid() || base.ParentPID != os.Getppid() || base.CoreUID != uid || ticket.ChildPID != int32(os.Getpid()) || ticket.ParentPID != int32(os.Getppid()) || ticket.CoreUID != uid {
		return ErrIncomplete
	}
	if err := environment.verifyStopped(ctx, ticket.ExpectedUnitSHA256); err != nil {
		return err
	}
	sequence := 0
	challengeEncoder := json.NewEncoder(challengeWrite)
	replyDecoder := json.NewDecoder(io.LimitReader(replyRead, 4096))
	replyDecoder.DisallowUnknownFields()
	maintenance := func(checkCtx context.Context) error {
		if err := checkCtx.Err(); err != nil {
			return err
		}
		// Private gate/pin and launch-flock authority remain with the root parent.
		if err := environment.verifyStopped(checkCtx, ticket.ExpectedUnitSHA256); err != nil {
			return err
		}
		if operation == "backup" {
			if err := repairEmptyUserFactsAt(checkCtx, environment.dataDirectory, ticket.DatabaseInode, ticket.DatabaseGeneration, uid, gid); err != nil {
				return err
			}
		}
		var challengeNonce [16]byte
		if _, err := rand.Read(challengeNonce[:]); err != nil {
			return err
		}
		sequence++
		challenge := repairChallenge{Kind: "maintenance", Nonce: hex.EncodeToString(challengeNonce[:]), Sequence: sequence}
		if err := challengeEncoder.Encode(challenge); err != nil {
			return err
		}
		var reply repairChallengeReply
		if err := replyDecoder.Decode(&reply); err != nil || reply.Digest != repairChallengeDigest(ticket.Nonce, challenge.Nonce, sequence) {
			return ErrIncomplete
		}
		return nil
	}
	if operation == "backup" {
		req := sqlite.NativeOfflineBackupRequest{DataDirectory: environment.dataDirectory, BackupDirectory: environment.backupDirectory, BackupName: ticket.BackupName, ExpectedPins: sqlite.CompiledNativeMigrationPins()}
		receipt, err := sqlite.BackupNativeOffline(ctx, req, maintenance)
		if err != nil {
			return err
		}
		if sequence != 2 || receipt.SourceDBInode != ticket.DatabaseInode || receipt.Generation != ticket.DatabaseGeneration {
			return sqlite.ErrNativeBackupOutcomeUnknown
		}
		return json.NewEncoder(output).Encode(receipt)
	}
	req := sqlite.NativeOfflineRestoreRequest{DataDirectory: environment.dataDirectory, BackupDirectory: environment.backupDirectory, BackupName: ticket.BackupName, AttemptID: ticket.Nonce,
		BackupSHA256: ticket.BackupSHA256, BackupSizeBytes: ticket.BackupSizeBytes, BackupGeneration: ticket.BackupGeneration, LaunchHighWater: ticket.LaunchHighWater,
		ExpectedPins: sqlite.CompiledNativeMigrationPins()}
	restore, err := sqlite.RestoreNativeOffline(ctx, req, maintenance, func(prepared sqlite.NativeOfflineRestorePrepared) error {
		if prepared.BackupSHA256 != ticket.BackupSHA256 || prepared.SourceDBInode != ticket.DatabaseInode || prepared.SeedGeneration < ticket.LaunchHighWater {
			return ErrIncomplete
		}
		var challengeNonce [16]byte
		if _, err := rand.Read(challengeNonce[:]); err != nil {
			return err
		}
		sequence++
		challenge := repairChallenge{Kind: "approve_restore", Nonce: hex.EncodeToString(challengeNonce[:]), Sequence: sequence, Prepared: &prepared}
		if err := challengeEncoder.Encode(challenge); err != nil {
			return err
		}
		var reply repairChallengeReply
		if err := replyDecoder.Decode(&reply); err != nil || !reply.Commit || reply.Digest != repairChallengeDigest(ticket.Nonce, challenge.Nonce, sequence) {
			return ErrIncomplete
		}
		return nil
	})
	if err != nil {
		return err
	}
	if sequence != 4 || restore.OriginalDBInode != ticket.DatabaseInode || restore.SeedGeneration < ticket.LaunchHighWater {
		return sqlite.ErrNativeRestoreOutcomeUnknown
	}
	return json.NewEncoder(output).Encode(restore)
}

func repairTicketFiles(prefix string) (writer, reader *os.File, cleanup func(), err error) {
	writer, err = os.CreateTemp(bootstrapRepairRoot, prefix)
	if err != nil {
		return nil, nil, nil, err
	}
	path := writer.Name()
	initial, statErr := writer.Stat()
	if statErr != nil {
		_ = writer.Close()
		return nil, nil, nil, statErr
	}
	cleanup = func() {
		if reader != nil {
			_ = reader.Close()
		}
		if writer != nil {
			_ = writer.Close()
		}
		if current, e := os.Lstat(path); e == nil {
			if os.SameFile(current, initial) {
				_ = os.Remove(path)
			}
		}
	}
	if err = writer.Chmod(0o600); err != nil {
		cleanup()
		return nil, nil, nil, err
	}
	info, e := writer.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || artifactio.CheckFileOwner(info, 0, 0) != nil {
		cleanup()
		return nil, nil, nil, ErrIncomplete
	}
	reader, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		cleanup()
		return nil, nil, nil, err
	}
	opened, e := reader.Stat()
	if e != nil || !os.SameFile(info, opened) {
		cleanup()
		return nil, nil, nil, ErrIncomplete
	}
	return writer, reader, cleanup, nil
}

// Both maintenance operations use this one fixed Core-UID FD3..7 launch. It
// creates no service and owns only its inherited ticket files and pipes.
type repairChildSession struct {
	child                     *exec.Cmd
	output                    bytes.Buffer
	parent                    localpeer.ProcessAttestation
	challengeRead, replyWrite *os.File
	closeFiles                []func()
	joined                    bool
}

func (s *repairChildSession) close() {
	if s == nil {
		return
	}
	if s.child != nil && s.child.Process != nil && !s.joined {
		_ = s.child.Process.Kill()
		_ = s.child.Wait()
		s.joined = true
	}
	for _, closeFile := range s.closeFiles {
		closeFile()
	}
}

func (s *repairChildSession) wait() error {
	if s == nil || s.child == nil || s.joined {
		return ErrIncomplete
	}
	err := s.child.Wait()
	s.joined = true
	return err
}

func repairStartCoreChild(ctx context.Context, intent bootstrapRepairIntent, stagePath string, newStage verifiedStage, accounts nativeHostIDs,
	operation, unitSHA string, inode uint64, generation int64, backup *NativeBackupProtectedReceipt, highWater int64) (session *repairChildSession, returnedErr error) {
	if ctx == nil || accounts.CoreUID <= 0 || accounts.CoreGID <= 0 || inode == 0 || generation < 1 || operation != "backup" && operation != "restore" || operation == "restore" && (backup == nil || highWater < generation) {
		return nil, ErrIncomplete
	}
	updater, err := componentArtifact(newStage.manifest, newStage.manifest.Components.HostUpdate.ArtifactID)
	if err != nil || updater.RelativePath != "bin/acornfox-host-update" {
		return nil, ErrIncomplete
	}
	childPath := filepath.Join(install.UnifiedReleasesDir, newStage.manifest.ReleaseID, updater.RelativePath)
	if err := verifyNativeCoreBinary(childPath, updater.SHA256); err != nil {
		return nil, err
	}
	parent, err := localpeer.AttestLinuxProcess(int32(os.Getpid()))
	if err != nil || parent.UID != 0 || parent.ExecutablePath != filepath.Join(stagePath, "payload", updater.RelativePath) || parent.ExecutableSHA256 != updater.SHA256 {
		return nil, ErrIncomplete
	}
	s := &repairChildSession{parent: parent}
	defer func() {
		if returnedErr != nil {
			s.close()
		}
	}()
	baseWrite, baseRead, baseCleanup, err := repairTicketFiles(operation + "-base-")
	if err != nil {
		return nil, err
	}
	s.closeFiles = append(s.closeFiles, baseCleanup)
	metaWrite, metaRead, metaCleanup, err := repairTicketFiles(operation + "-metadata-")
	if err != nil {
		return nil, err
	}
	s.closeFiles = append(s.closeFiles, metaCleanup)
	signalRead, signalWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	s.closeFiles = append(s.closeFiles, func() { _ = signalRead.Close(); _ = signalWrite.Close() })
	challengeRead, challengeWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	s.closeFiles = append(s.closeFiles, func() { _ = challengeRead.Close(); _ = challengeWrite.Close() })
	replyRead, replyWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	s.closeFiles = append(s.closeFiles, func() { _ = replyRead.Close(); _ = replyWrite.Close() })
	s.challengeRead = challengeRead
	s.replyWrite = replyWrite
	child := exec.CommandContext(ctx, childPath, "native-bootstrap-repair-child", operation)
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(accounts.CoreUID), Gid: uint32(accounts.CoreGID), Groups: []uint32{uint32(accounts.CoreGID)}}}
	child.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	child.Dir = "/"
	child.Stderr = io.Discard
	child.ExtraFiles = []*os.File{baseRead, signalRead, metaRead, challengeWrite, replyRead}
	child.Stdout = &s.output
	if err := child.Start(); err != nil {
		return nil, err
	}
	s.child = child
	_ = baseRead.Close()
	_ = signalRead.Close()
	_ = metaRead.Close()
	_ = challengeWrite.Close()
	_ = replyRead.Close()
	base := corelaunch.Ticket{InstallationID: intent.InstallationID, ReleaseID: intent.NewReleaseID, ManifestSHA256: intent.NewManifestSHA256,
		ExecutableSHA256: updater.SHA256, DataDirectory: install.UnifiedCoreDataDir, DatabaseInode: inode,
		ChildPID: child.Process.Pid, ParentPID: os.Getpid(), CoreUID: accounts.CoreUID, Generation: generation}
	metadata := repairChildTicket{Operation: operation, InstallationID: intent.InstallationID, Nonce: intent.Nonce, NewReleaseID: intent.NewReleaseID,
		NewManifestSHA256: intent.NewManifestSHA256, ExpectedUnitSHA256: unitSHA, DatabaseInode: inode, DatabaseGeneration: generation,
		ParentPID: parent.PID, ChildSHA256: updater.SHA256, ChildPID: int32(child.Process.Pid), CoreUID: accounts.CoreUID, BackupName: "backup-" + intent.Nonce + ".db"}
	if backup != nil {
		metadata.BackupSHA256 = backup.Backup.SHA256
		metadata.BackupSizeBytes = backup.Backup.SizeBytes
		metadata.BackupGeneration = backup.Backup.Generation
		metadata.LaunchHighWater = highWater
	}
	baseRaw, e1 := json.Marshal(base)
	metaRaw, e2 := json.Marshal(metadata)
	if e1 != nil || e2 != nil || len(baseRaw) < 1 || len(baseRaw) > 4096 || len(metaRaw) < 1 || len(metaRaw) > 4096 {
		return nil, ErrIncomplete
	}
	for _, item := range []struct {
		file *os.File
		raw  []byte
	}{{baseWrite, baseRaw}, {metaWrite, metaRaw}} {
		if n, err := item.file.WriteAt(item.raw, 0); err != nil || n != len(item.raw) {
			return nil, ErrBootstrapRepairUnknown
		}
		if err := item.file.Sync(); err != nil {
			return nil, ErrBootstrapRepairUnknown
		}
	}
	if n, err := signalWrite.Write([]byte{1}); err != nil || n != 1 {
		return nil, ErrBootstrapRepairUnknown
	}
	_ = signalWrite.Close()
	return s, nil
}

func repairBackupWithCoreChild(ctx context.Context, intent bootstrapRepairIntent, stagePath string, oldStage verifiedStage, newStage verifiedStage, accounts nativeHostIDs, launchLock *os.File) (NativeBackupProtectedReceipt, error) {
	var zero NativeBackupProtectedReceipt
	if ctx == nil || launchLock == nil || intent.DatabaseGeneration < 1 || accounts.CoreUID <= 0 || accounts.CoreGID <= 0 {
		return zero, ErrIncomplete
	}
	session, err := repairStartCoreChild(ctx, intent, stagePath, newStage, accounts, "backup", intent.OldUnitSHA256, intent.DatabaseInode, intent.DatabaseGeneration, nil, 0)
	if err != nil {
		return zero, err
	}
	defer session.close()
	backupName := "backup-" + intent.Nonce + ".db"
	challengeDecoder := json.NewDecoder(io.LimitReader(session.challengeRead, 4096))
	challengeDecoder.DisallowUnknownFields()
	replyEncoder := json.NewEncoder(session.replyWrite)
	for sequence := 1; sequence <= 2; sequence++ {
		var challenge repairChallenge
		if err := challengeDecoder.Decode(&challenge); err != nil || challenge.Kind != "maintenance" || len(challenge.Nonce) != 32 || challenge.Sequence != sequence {
			return zero, ErrBootstrapRepairUnknown
		}
		if err := repairRootChallengeRecheck(ctx, intent, session.parent, launchLock, intent.OldUnitSHA256); err != nil {
			return zero, err
		}
		if err := replyEncoder.Encode(repairChallengeReply{Digest: repairChallengeDigest(intent.Nonce, challenge.Nonce, sequence)}); err != nil {
			return zero, err
		}
	}
	_ = session.replyWrite.Close()
	if err := session.wait(); err != nil {
		return zero, errors.Join(sqlite.ErrNativeBackupOutcomeUnknown, err)
	}
	if session.output.Len() < 1 || session.output.Len() > 8192 {
		return zero, sqlite.ErrNativeBackupOutcomeUnknown
	}
	var backup sqlite.NativeOfflineBackupReceipt
	dec := json.NewDecoder(bytes.NewReader(session.output.Bytes()))
	dec.DisallowUnknownFields()
	if dec.Decode(&backup) != nil || dec.Decode(&struct{}{}) != io.EOF || backup.BackupPath != filepath.Join(install.UnifiedBackupDir, backupName) || backup.SourceDBInode != intent.DatabaseInode || backup.Generation != intent.DatabaseGeneration {
		return zero, sqlite.ErrNativeBackupOutcomeUnknown
	}
	plan := NativeSQLiteBackupPlan{CoreUID: uint32(accounts.CoreUID), CoreGID: uint32(accounts.CoreGID), ReleaseID: oldStage.manifest.ReleaseID, SourceCommit: oldStage.manifest.Provenance.SourceCommit,
		ManifestSHA256: oldStage.sha256, InstallationID: intent.InstallationID, Request: sqlite.NativeOfflineBackupRequest{DataDirectory: install.UnifiedCoreDataDir, BackupDirectory: install.UnifiedBackupDir, BackupName: backupName, ExpectedPins: sqlite.CompiledNativeMigrationPins()}}
	protected, err := SaveNativeBackupReceipt(ctx, plan, backup)
	if err != nil {
		return zero, errors.Join(ErrBootstrapRepairUnknown, err)
	}
	return protected, nil
}

type NativeBootstrapRepairContinueResult struct {
	InstallationID string `json:"installation_id"`
	ReleaseID      string `json:"release_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	CorePID        int32  `json:"core_pid"`
	CoreStartTime  string `json:"core_start_time"`
	BackupID       string `json:"backup_id"`
	Status         string `json:"status"`
}

type bootstrapRepairPhase struct {
	InstallationID     string `json:"installation_id"`
	NewManifestSHA256  string `json:"new_manifest_sha256"`
	Name               string `json:"name"`
	ActualSHA256       string `json:"actual_sha256,omitempty"`
	DatabaseInode      uint64 `json:"database_inode,omitempty"`
	DatabaseGeneration int64  `json:"database_generation,omitempty"`
}

var ErrBootstrapRepairRestoreUnapproved = errors.New("restore not approved; original database identity retained; keep repair gate closed")
var ErrBootstrapRepairRestoreUncertain = errors.New("restore approval or replacement outcome unknown; keep repair gate closed")

func repairWriteRestoreStarted(intent bootstrapRepairIntent, backupSHA string, inode uint64, generation int64) error {
	if inode == 0 || generation < 1 || len(backupSHA) != 64 {
		return ErrIncomplete
	}
	record := bootstrapRepairPhase{InstallationID: intent.InstallationID, NewManifestSHA256: intent.NewManifestSHA256,
		Name: "restore-started", ActualSHA256: backupSHA, DatabaseInode: inode, DatabaseGeneration: generation}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return publishHostFile(repairPhasePath("restore-started"), raw, 0o600, 0, 0)
}

func repairReadRestoreStarted(intent bootstrapRepairIntent, backupSHA string) (bootstrapRepairPhase, bool, error) {
	var phase bootstrapRepairPhase
	path := repairPhasePath("restore-started")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return phase, false, nil
	} else if err != nil {
		return phase, false, err
	}
	if err := readHostJSON(path, 0, 0, &phase); err != nil {
		return phase, false, err
	}
	if phase.InstallationID != intent.InstallationID || phase.NewManifestSHA256 != intent.NewManifestSHA256 || phase.Name != "restore-started" || phase.ActualSHA256 != backupSHA || phase.DatabaseInode == 0 || phase.DatabaseGeneration < intent.DatabaseGeneration {
		return phase, false, ErrIncomplete
	}
	return phase, true, nil
}

type bootstrapRepairCompletion struct {
	Phase  bootstrapRepairPhase                `json:"phase"`
	Result NativeBootstrapRepairContinueResult `json:"result"`
}

func repairReadCompletion(intent bootstrapRepairIntent) (bootstrapRepairCompletion, bool, error) {
	var completion bootstrapRepairCompletion
	if _, err := os.Lstat(repairPhasePath("complete")); os.IsNotExist(err) {
		return completion, false, nil
	} else if err != nil {
		return completion, false, err
	}
	if err := readHostJSON(repairPhasePath("complete"), 0, 0, &completion); err != nil {
		return completion, false, err
	}
	want := bootstrapRepairPhase{InstallationID: intent.InstallationID, NewManifestSHA256: intent.NewManifestSHA256, Name: "complete", ActualSHA256: intent.NewManifestSHA256}
	if completion.Phase != want || completion.Result.InstallationID != intent.InstallationID || completion.Result.ReleaseID != intent.NewReleaseID || completion.Result.ManifestSHA256 != intent.NewManifestSHA256 || completion.Result.CorePID <= 0 || completion.Result.CoreStartTime == "" || completion.Result.BackupID != "backup-"+intent.Nonce || completion.Result.Status != "core_started_setup_required" {
		return completion, false, ErrIncomplete
	}
	return completion, true, nil
}

func repairWriteCompletion(intent bootstrapRepairIntent, result NativeBootstrapRepairContinueResult) error {
	completion := bootstrapRepairCompletion{Phase: bootstrapRepairPhase{InstallationID: intent.InstallationID, NewManifestSHA256: intent.NewManifestSHA256, Name: "complete", ActualSHA256: intent.NewManifestSHA256}, Result: result}
	raw, err := json.Marshal(completion)
	if err != nil {
		return err
	}
	return publishHostFile(repairPhasePath("complete"), raw, 0o600, 0, 0)
}

func repairPhasePath(name string) string {
	return filepath.Join(bootstrapRepairRoot, "phase-"+name+".json")
}
func repairWritePhase(intent bootstrapRepairIntent, name, actualSHA string) error {
	return repairWritePhaseAt(bootstrapRepairRoot, intent, name, actualSHA)
}

func repairWritePhaseAt(root string, intent bootstrapRepairIntent, name, actualSHA string) error {
	record := bootstrapRepairPhase{InstallationID: intent.InstallationID, NewManifestSHA256: intent.NewManifestSHA256, Name: name, ActualSHA256: actualSHA}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return publishHostFile(filepath.Join(root, "phase-"+name+".json"), raw, 0o600, os.Getuid(), os.Getgid())
}

func repairEnsurePhaseAt(root string, intent bootstrapRepairIntent, name, actualSHA string) error {
	present, err := repairReadPhaseAt(root, intent, name, actualSHA)
	if err != nil || present {
		return err
	}
	return repairWritePhaseAt(root, intent, name, actualSHA)
}

func repairReadPhaseAt(root string, intent bootstrapRepairIntent, name, actualSHA string) (bool, error) {
	path := filepath.Join(root, "phase-"+name+".json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	var record bootstrapRepairPhase
	if err := readHostJSON(path, os.Getuid(), os.Getgid(), &record); err != nil {
		return false, err
	}
	if record != (bootstrapRepairPhase{InstallationID: intent.InstallationID, NewManifestSHA256: intent.NewManifestSHA256, Name: name, ActualSHA256: actualSHA}) {
		return false, ErrIncomplete
	}
	return true, nil
}

// A complete, inactive copy is safe to resume only when this intent recorded
// its planned installation and every installed byte still matches the stage.
func repairInstallInactiveRelease(ctx context.Context, intent bootstrapRepairIntent, stagePath string, stage verifiedStage, release string, d nativeHostDeps, phaseRoot string) error {
	if intent.NewReleaseID != stage.manifest.ReleaseID || intent.NewManifestSHA256 != stage.sha256 {
		return ErrIncomplete
	}
	planned, err := repairReadPhaseAt(phaseRoot, intent, "release-install-planned", intent.NewManifestSHA256)
	if err != nil {
		return err
	}
	installed, err := repairReadPhaseAt(phaseRoot, intent, "release-installed", intent.NewManifestSHA256)
	if err != nil || installed && !planned {
		return ErrIncomplete
	}
	_, statErr := os.Lstat(d.path(release))
	if os.IsNotExist(statErr) {
		if installed {
			return ErrIncomplete
		}
		// A missing release after a previous plan may hide a retained partial
		// copy. Its byte identity cannot be inferred from the phase alone.
		if planned {
			return ErrBootstrapRepairUnknown
		}
		if err := repairWritePhaseAt(phaseRoot, intent, "release-install-planned", intent.NewManifestSHA256); err != nil {
			return err
		}
		if err := installNativeRelease(ctx, d, stagePath, stage, release); err != nil {
			return errors.Join(ErrBootstrapRepairUnknown, err)
		}
	} else if statErr != nil || !planned {
		return ErrBootstrapRepairUnknown
	}
	if err := verifyInstalledRelease(ctx, d.path(release), stage, d.ownerUID, d.ownerGID); err != nil {
		return errors.Join(ErrBootstrapRepairUnknown, err)
	}
	if !installed {
		if err := repairWritePhaseAt(phaseRoot, intent, "release-installed", intent.NewManifestSHA256); err != nil {
			return errors.Join(ErrBootstrapRepairUnknown, err)
		}
	}
	return nil
}

func repairReadIntent() (bootstrapRepairIntent, error) {
	var intent bootstrapRepairIntent
	if err := readHostJSON(bootstrapRepairIntentPath, 0, 0, &intent); err != nil {
		return intent, err
	}
	if intent.InstallationID == "" || len(intent.Nonce) != 32 || !ValidNativeBundleID(intent.BundleID) || len(intent.NewManifestSHA256) != 64 || len(intent.OldManifestSHA256) != 64 || intent.DatabaseInode == 0 || intent.DatabaseGeneration < 1 || intent.LaunchHighWater < intent.DatabaseGeneration {
		return intent, ErrIncomplete
	}
	return intent, nil
}

// ContinueNativeBootstrapRepair accepts only the new trusted ready stage for a
// durable begin intent. It does not repeat fresh HostPrep or mint a new token.
func ContinueNativeBootstrapRepair(ctx context.Context, stagePath string) (result NativeBootstrapRepairContinueResult, returnedErr error) {
	var zero NativeBootstrapRepairContinueResult
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || os.Getegid() != 0 || filepath.Dir(stagePath) != UnifiedPrivateStageRoot || !nativeReadyName.MatchString(filepath.Base(stagePath)) {
		return zero, ErrIncomplete
	}
	intent, err := repairReadIntent()
	if err != nil {
		return zero, err
	}
	var oldPin, newPin acornfoxrelease.TrustedReleasePinV1
	if err := readProtectedPublisherJSON(bootstrapRepairOldPin, 4096, &oldPin); err != nil {
		return zero, err
	}
	if err := readProtectedPublisherJSON(bootstrapRepairNewPin, 4096, &newPin); err != nil {
		return zero, err
	}
	for _, item := range []struct{ path, want string }{{bootstrapRepairOldPin, intent.OldPinSHA256}, {bootstrapRepairNewPin, intent.NewPinSHA256}, {UnifiedTrustedPinPath, intent.NewPinSHA256}} {
		got, e := repairProtectedFileSHA(item.path, 0o600, 0)
		if e != nil || got != item.want {
			return zero, ErrIncomplete
		}
	}
	oldStage, err := verifyStagedRelease(ctx, intent.OldStagePath, UnifiedPrivateStageRoot, oldPin, 0, 0)
	if err != nil || oldStage.sha256 != intent.OldManifestSHA256 || oldStage.manifest.ReleaseID != intent.OldReleaseID {
		return zero, ErrIncomplete
	}
	newStage, err := verifyStagedRelease(ctx, stagePath, UnifiedPrivateStageRoot, newPin, 0, 0)
	if err != nil || newStage.sha256 != intent.NewManifestSHA256 || newStage.manifest.ReleaseID != intent.NewReleaseID {
		return zero, ErrIncomplete
	}
	if err := repairSameNativeSQLitePins(oldStage.manifest.SQLiteCompatibility, newStage.manifest.SQLiteCompatibility); err != nil {
		return zero, err
	}
	if completion, present, err := repairReadCompletion(intent); err != nil {
		return zero, err
	} else if present {
		return repairReadCompletedRepair(ctx, intent, stagePath, newStage, completion.Result)
	}
	if err := repairRequireAbsent(bootstrapRepairAuthorizedPath); err != nil {
		return zero, ErrBootstrapRepairUnknown
	}
	if err := repairDropInEffective(ctx); err != nil {
		return zero, err
	}
	var oldReceipt nativeHostReceipt
	oldComplete := filepath.Join(UnifiedPrivateStageRoot, nativeHostPrepareRecords, "prepare-"+intent.OldManifestSHA256+"-complete.json")
	if err := readHostJSON(oldComplete, 0, 0, &oldReceipt); err != nil || oldReceipt.Result.InstallationID != intent.InstallationID {
		return zero, ErrIncomplete
	}
	if oldReceipt.Result.StagePath != intent.OldStagePath || oldReceipt.Result.ReleaseID != intent.OldReleaseID || oldReceipt.Result.ManifestSHA256 != intent.OldManifestSHA256 || oldReceipt.Result.Status != "prepared_not_started" {
		return zero, ErrIncomplete
	}
	if err := verifyCompletedHostAccounts(productionNativeHostDeps(), oldReceipt.Accounts); err != nil {
		return zero, err
	}
	oldRelease, err := install.ReleaseDirectory(install.UnifiedReleasesDir, intent.OldReleaseID)
	if err != nil || verifyInstalledRelease(ctx, oldRelease, oldStage, 0, 0) != nil {
		return zero, ErrIncomplete
	}
	files, coreUnit, newUnitSHA, err := repairExpectedHostFiles(stagePath, newStage, oldReceipt)
	if err != nil {
		return zero, err
	}
	actualUnitSHA, err := repairProtectedFileSHA("/etc/systemd/system/"+NativeCoreUnit, 0o644, 0)
	if err != nil || actualUnitSHA != intent.OldUnitSHA256 && actualUnitSHA != newUnitSHA {
		return zero, ErrBootstrapRepairUnknown
	}
	if err := repairStoppedUnit(ctx, actualUnitSHA); err != nil {
		return zero, err
	}
	if err := repairNoBusinessRoles(ctx, oldStage.manifest); err != nil {
		return zero, err
	}
	lock, err := repairLaunchLock()
	if err != nil {
		return zero, err
	}
	defer func() {
		if lock != nil {
			_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
			_ = lock.Close()
		}
	}()
	generation, inode, err := readCoreGenerationOnly(ctx, sqlite.CompiledNativeMigrationPins(), uint32(oldReceipt.Accounts.CoreUID), uint32(oldReceipt.Accounts.CoreGID))
	if err != nil || inode != intent.DatabaseInode || generation != intent.DatabaseGeneration {
		return zero, ErrIncomplete
	}
	if err := repairEmptyUserFacts(ctx, inode, generation, oldReceipt.Accounts.CoreUID, oldReceipt.Accounts.CoreGID); err != nil {
		return zero, err
	}
	high, err := readCoreLaunchHighWater(nativeCoreJournal, intent.InstallationID)
	if err != nil || high != intent.LaunchHighWater {
		return zero, ErrIncomplete
	}
	newRelease, err := install.ReleaseDirectory(install.UnifiedReleasesDir, newStage.manifest.ReleaseID)
	if err != nil {
		return zero, err
	}
	unknown := func(err error) (NativeBootstrapRepairContinueResult, error) {
		return zero, errors.Join(ErrBootstrapRepairUnknown, err)
	}
	if err := repairInstallInactiveRelease(ctx, intent, stagePath, newStage, newRelease, productionNativeHostDeps(), bootstrapRepairRoot); err != nil {
		return unknown(err)
	}
	backupStarted, err := repairReadPhaseAt(bootstrapRepairRoot, intent, "backup-started", "")
	if err != nil {
		return unknown(err)
	}
	var backup NativeBackupProtectedReceipt
	if backupStarted {
		backup, err = ReadNativeBackupReceipt(ctx, "backup-"+intent.Nonce)
		if err != nil {
			return unknown(err)
		}
	} else {
		if actualUnitSHA != intent.OldUnitSHA256 {
			return unknown(ErrIncomplete)
		}
		if err := repairWritePhase(intent, "backup-started", ""); err != nil {
			return unknown(err)
		}
		backup, err = repairBackupWithCoreChild(ctx, intent, stagePath, oldStage, newStage, oldReceipt.Accounts, lock)
		if err != nil {
			return unknown(err)
		}
	}
	if backup.InstallationID != intent.InstallationID || backup.ReleaseID != intent.OldReleaseID || backup.ManifestSHA256 != intent.OldManifestSHA256 || backup.Backup.SourceDBInode != intent.DatabaseInode || backup.Backup.Generation != intent.DatabaseGeneration {
		return unknown(ErrIncomplete)
	}
	if err := repairEnsurePhaseAt(bootstrapRepairRoot, intent, "backup-complete", backup.Backup.SHA256); err != nil {
		return unknown(err)
	}
	if err := repairSwitchCoreUnitAndCurrentAt(intent, bootstrapRepairRoot,
		"/etc/systemd/system/"+NativeCoreUnit, "/etc/systemd/system/.acornfox-bootstrap-core-unit.tmp",
		install.UnifiedCurrentSymlink, "/opt/acornfox/.bootstrap-repair-current.tmp",
		intent.OldUnitSHA256, coreUnit, newUnitSHA, oldRelease, newRelease, 0); err != nil {
		return unknown(err)
	}
	if err := nativeFirstCoreSystemctl(ctx, "daemon-reload"); err != nil {
		return unknown(err)
	}
	if err := repairDropInEffective(ctx); err != nil {
		return unknown(err)
	}
	if err := repairStoppedUnit(ctx, newUnitSHA); err != nil {
		return unknown(err)
	}
	newReceipt, err := repairInstallSuccessorReceipt(ctx, intent, stagePath, newStage, oldReceipt, files)
	if err != nil {
		return unknown(err)
	}
	if err := repairWritePhase(intent, "successor-host-receipt", intent.NewManifestSHA256); err != nil {
		return unknown(err)
	}
	if err := repairInstallSuccessorFirstIntent(intent, stagePath, newStage); err != nil {
		return unknown(err)
	}
	if err := repairWritePhase(intent, "successor-first-core-intent", intent.TokenSHA256); err != nil {
		return unknown(err)
	}
	if err := repairWritePhase(intent, "start-authorization-planned", intent.NewManifestSHA256); err != nil {
		return unknown(err)
	}
	authorization := []byte(intent.InstallationID + "\n" + intent.NewManifestSHA256 + "\n")
	if err := publishHostFile(bootstrapRepairAuthorizedPath, authorization, 0o600, 0, 0); err != nil {
		return unknown(err)
	}
	gateAuthorized := true
	defer func() {
		if returnedErr != nil && gateAuthorized {
			if closeErr := repairCloseAuthorizedGate(ctx); closeErr != nil {
				returnedErr = errors.Join(returnedErr, ErrBootstrapRepairUnknown, closeErr)
			}
		}
	}()
	if err := repairVerifyAuthorizationBeforeStart(ctx, intent, newStage, newUnitSHA, newReceipt); err != nil {
		return unknown(err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
		return unknown(err)
	}
	if err := lock.Close(); err != nil {
		return unknown(err)
	}
	lock = nil
	if err := nativeFirstCoreSystemctl(ctx, "start", NativeCoreUnit); err != nil {
		return unknown(err)
	}
	coreArtifact, err := componentArtifact(newStage.manifest, newStage.manifest.Components.Core.ArtifactID)
	if err != nil || coreArtifact.RelativePath != "bin/acornfox-core" {
		return unknown(ErrIncomplete)
	}
	hostArtifact, err := componentArtifact(newStage.manifest, newStage.manifest.Components.HostUpdate.ArtifactID)
	if err != nil || hostArtifact.RelativePath != "bin/acornfox-host-update" {
		return unknown(ErrIncomplete)
	}
	deps := productionFirstCoreDeps()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var core NativeFirstCoreResult
	for {
		core, err = readExistingNativeFirstCore(ctx, deps, newStage, newReceipt, coreArtifact.SHA256, hostArtifact.SHA256, intent.TokenSHA256, true)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return unknown(ctx.Err())
		case <-deadline.C:
			return unknown(err)
		case <-ticker.C:
		}
	}
	if core.Status != "core_started_setup_required" || core.CorePID <= 0 {
		return unknown(ErrIncomplete)
	}
	if err := repairReadRunningGeneration(ctx, intent.InstallationID, intent.LaunchHighWater); err != nil {
		return unknown(err)
	}
	completed := NativeBootstrapRepairContinueResult{InstallationID: intent.InstallationID, ReleaseID: newStage.manifest.ReleaseID,
		ManifestSHA256: newStage.sha256, CorePID: core.CorePID, CoreStartTime: core.CoreStartTime,
		BackupID: backup.BackupID, Status: "core_started_setup_required"}
	if err := repairWriteCompletion(intent, completed); err != nil {
		return unknown(err)
	}
	gateAuthorized = false
	return completed, nil
}

// A completed retry is read-only. It returns the original response only when
// the protected receipt and the actual running Core still identify that same
// child; a later restart or a changed database is an unknown outcome here.
func repairReadCompletedRepair(ctx context.Context, intent bootstrapRepairIntent, stagePath string, stage verifiedStage, original NativeBootstrapRepairContinueResult) (NativeBootstrapRepairContinueResult, error) {
	var zero NativeBootstrapRepairContinueResult
	const dropIn = "[Unit]\nConditionPathExists=" + bootstrapRepairAuthorizedPath + "\n"
	dropSHA := sha256.Sum256([]byte(dropIn))
	if actual, err := repairProtectedFileSHA(bootstrapRepairDropInPath, 0o644, 0); err != nil || actual != hex.EncodeToString(dropSHA[:]) {
		return zero, ErrBootstrapRepairUnknown
	}
	marker := []byte(intent.InstallationID + "\n" + intent.NewManifestSHA256 + "\n")
	markerSHA := sha256.Sum256(marker)
	actual, err := repairProtectedFileSHA(bootstrapRepairAuthorizedPath, 0o600, 0)
	if err != nil || actual != hex.EncodeToString(markerSHA[:]) {
		return zero, ErrBootstrapRepairUnknown
	}
	newRelease, err := install.ReleaseDirectory(install.UnifiedReleasesDir, intent.NewReleaseID)
	if err != nil || verifyInstalledRelease(ctx, newRelease, stage, 0, 0) != nil {
		return zero, ErrBootstrapRepairUnknown
	}
	current, err := os.Readlink(install.UnifiedCurrentSymlink)
	if err != nil || current != newRelease {
		return zero, ErrBootstrapRepairUnknown
	}
	var receipt nativeHostReceipt
	complete := filepath.Join(UnifiedPrivateStageRoot, nativeHostPrepareRecords, "prepare-"+intent.NewManifestSHA256+"-complete.json")
	if err := readHostJSON(complete, 0, 0, &receipt); err != nil || receipt.Result.InstallationID != intent.InstallationID {
		return zero, ErrBootstrapRepairUnknown
	}
	if _, err := readCompletedHostPreparation(ctx, stagePath, stage, productionNativeHostDeps(), complete); err != nil {
		return zero, ErrBootstrapRepairUnknown
	}
	var first nativeFirstCoreIntent
	firstPath := filepath.Join(UnifiedPrivateStageRoot, nativeHostPrepareRecords, "first-core-"+intent.NewManifestSHA256+"-intent.json")
	if err := readHostJSON(firstPath, 0, 0, &first); err != nil || first.InstallationID != intent.InstallationID || first.StagePath != stagePath || first.TokenSHA256 != intent.TokenSHA256 || first.ReleaseID != intent.NewReleaseID || first.ManifestSHA256 != intent.NewManifestSHA256 {
		return zero, ErrBootstrapRepairUnknown
	}
	backup, err := ReadNativeBackupReceipt(ctx, original.BackupID)
	if err != nil || backup.InstallationID != intent.InstallationID || backup.ReleaseID != intent.OldReleaseID || backup.ManifestSHA256 != intent.OldManifestSHA256 || backup.Backup.SourceDBInode != intent.DatabaseInode || backup.Backup.Generation != intent.DatabaseGeneration {
		return zero, ErrBootstrapRepairUnknown
	}
	coreArtifact, err := componentArtifact(stage.manifest, stage.manifest.Components.Core.ArtifactID)
	if err != nil {
		return zero, ErrBootstrapRepairUnknown
	}
	hostArtifact, err := componentArtifact(stage.manifest, stage.manifest.Components.HostUpdate.ArtifactID)
	if err != nil {
		return zero, ErrBootstrapRepairUnknown
	}
	core, err := readExistingNativeFirstCore(ctx, productionFirstCoreDeps(), stage, receipt, coreArtifact.SHA256, hostArtifact.SHA256, intent.TokenSHA256, true)
	if err != nil || core.CorePID != original.CorePID || core.CoreStartTime != original.CoreStartTime || core.Status != original.Status {
		return zero, ErrBootstrapRepairUnknown
	}
	if err := repairReadRunningGeneration(ctx, intent.InstallationID, intent.LaunchHighWater); err != nil {
		return zero, ErrBootstrapRepairUnknown
	}
	return original, nil
}

func repairExpectedHostFiles(stagePath string, stage verifiedStage, old nativeHostReceipt) ([]hostFile, []byte, string, error) {
	files, err := nativeHostFiles(stagePath, stage.manifest.ReleaseID, old.Accounts)
	if err != nil || len(files) != len(old.Files) {
		return nil, nil, "", ErrIncomplete
	}
	var coreUnit []byte
	var coreSHA string
	for _, file := range files {
		sum := sha256.Sum256(file.data)
		want := hex.EncodeToString(sum[:])
		if file.path == "/etc/systemd/system/"+NativeCoreUnit {
			coreUnit = file.data
			coreSHA = want
			if old.Files[file.path] == "" || old.Files[file.path] == want {
				return nil, nil, "", ErrIncomplete
			}
			continue
		}
		if old.Files[file.path] != want {
			return nil, nil, "", ErrIncomplete
		}
		actual, e := repairProtectedFileSHA(file.path, file.mode, 0)
		if e != nil || actual != want {
			return nil, nil, "", ErrIncomplete
		}
	}
	if len(coreUnit) == 0 || len(coreSHA) != 64 {
		return nil, nil, "", ErrIncomplete
	}
	return files, coreUnit, coreSHA, nil
}

func repairReplaceCoreUnit(oldSHA string, next []byte, nextSHA string) error {
	return repairReplaceCoreUnitAt("/etc/systemd/system/"+NativeCoreUnit, "/etc/systemd/system/.acornfox-bootstrap-core-unit.tmp", oldSHA, next, nextSHA, 0)
}

func repairReplaceCoreUnitAt(path, temp, oldSHA string, next []byte, nextSHA string, ownerUID int) error {
	if err := repairRequireAbsent(temp); err != nil {
		return err
	}
	actual, err := repairFileSHAAt(path, 0o644, ownerUID, os.Getgid())
	if err != nil || actual != oldSHA {
		return ErrIncomplete
	}
	if err := publishHostFile(temp, next, 0o644, ownerUID, os.Getgid()); err != nil {
		return err
	}
	actual, err = repairFileSHAAt(path, 0o644, ownerUID, os.Getgid())
	if err != nil || actual != oldSHA {
		return ErrBootstrapRepairUnknown
	}
	if err := os.Rename(temp, path); err != nil {
		return errors.Join(ErrBootstrapRepairUnknown, err)
	}
	if err := artifactio.SyncDirectory(filepath.Dir(path)); err != nil {
		return errors.Join(ErrBootstrapRepairUnknown, err)
	}
	actual, err = repairFileSHAAt(path, 0o644, ownerUID, os.Getgid())
	if err != nil || actual != nextSHA {
		return ErrBootstrapRepairUnknown
	}
	return nil
}

func repairReplaceCurrent(oldRelease, newRelease string) error {
	return repairReplaceCurrentAt(install.UnifiedCurrentSymlink, "/opt/acornfox/.bootstrap-repair-current.tmp", oldRelease, newRelease, 0)
}

func repairReplaceCurrentAt(path, temp, oldRelease, newRelease string, ownerUID int) error {
	if err := repairRequireAbsent(temp); err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink == 0 || artifactio.CheckFileOwner(current, ownerUID, os.Getgid()) != nil {
		return ErrIncomplete
	}
	link, err := os.Readlink(path)
	if err != nil || link != oldRelease {
		return ErrIncomplete
	}
	if err := os.Symlink(newRelease, temp); err != nil {
		return err
	}
	if link, err := os.Readlink(temp); err != nil || link != newRelease {
		return ErrBootstrapRepairUnknown
	}
	current, err = os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink == 0 || artifactio.CheckFileOwner(current, ownerUID, os.Getgid()) != nil {
		return ErrBootstrapRepairUnknown
	}
	if link, err := os.Readlink(path); err != nil || link != oldRelease {
		return ErrBootstrapRepairUnknown
	}
	if err := os.Rename(temp, path); err != nil {
		return errors.Join(ErrBootstrapRepairUnknown, err)
	}
	if err := artifactio.SyncDirectory(filepath.Dir(path)); err != nil {
		return errors.Join(ErrBootstrapRepairUnknown, err)
	}
	if link, err := os.Readlink(path); err != nil || link != newRelease {
		return ErrBootstrapRepairUnknown
	}
	return nil
}

// Only the two switch gaps with durable backup evidence are resumable. The
// actual unit/current bytes decide the position; phase rows never override a
// conflicting filesystem observation.
func repairSwitchCoreUnitAndCurrentAt(intent bootstrapRepairIntent, phaseRoot, unitPath, unitTemp, currentPath, currentTemp string, oldUnitSHA string, newUnit []byte, newUnitSHA, oldRelease, newRelease string, ownerUID int) error {
	unitSHA, err := repairFileSHAAt(unitPath, 0o644, ownerUID, os.Getgid())
	if err != nil || unitSHA != oldUnitSHA && unitSHA != newUnitSHA {
		return ErrBootstrapRepairUnknown
	}
	currentInfo, err := os.Lstat(currentPath)
	if err != nil || currentInfo.Mode()&os.ModeSymlink == 0 || artifactio.CheckFileOwner(currentInfo, ownerUID, os.Getgid()) != nil {
		return ErrBootstrapRepairUnknown
	}
	current, err := os.Readlink(currentPath)
	if err != nil || current != oldRelease && current != newRelease || unitSHA == oldUnitSHA && current == newRelease {
		return ErrBootstrapRepairUnknown
	}
	unitPlanned, err := repairReadPhaseAt(phaseRoot, intent, "unit-switch-planned", newUnitSHA)
	if err != nil {
		return err
	}
	unitSwitched, err := repairReadPhaseAt(phaseRoot, intent, "unit-switched", newUnitSHA)
	if err != nil {
		return err
	}
	currentPlanned, err := repairReadPhaseAt(phaseRoot, intent, "current-switch-planned", intent.NewManifestSHA256)
	if err != nil {
		return err
	}
	currentSwitched, err := repairReadPhaseAt(phaseRoot, intent, "current-switched", intent.NewManifestSHA256)
	if err != nil {
		return err
	}
	if unitSHA == oldUnitSHA {
		if unitSwitched || currentPlanned || currentSwitched {
			return ErrBootstrapRepairUnknown
		}
		if err := repairEnsurePhaseAt(phaseRoot, intent, "unit-switch-planned", newUnitSHA); err != nil {
			return err
		}
		if err := repairReplaceCoreUnitAt(unitPath, unitTemp, oldUnitSHA, newUnit, newUnitSHA, ownerUID); err != nil {
			return err
		}
	} else if !unitPlanned {
		return ErrBootstrapRepairUnknown
	}
	if err := repairEnsurePhaseAt(phaseRoot, intent, "unit-switched", newUnitSHA); err != nil {
		return err
	}
	if current == oldRelease {
		if currentSwitched {
			return ErrBootstrapRepairUnknown
		}
		if err := repairEnsurePhaseAt(phaseRoot, intent, "current-switch-planned", intent.NewManifestSHA256); err != nil {
			return err
		}
		if err := repairReplaceCurrentAt(currentPath, currentTemp, oldRelease, newRelease, ownerUID); err != nil {
			return err
		}
	} else if !currentPlanned {
		return ErrBootstrapRepairUnknown
	}
	return repairEnsurePhaseAt(phaseRoot, intent, "current-switched", intent.NewManifestSHA256)
}

func repairInstallSuccessorReceipt(ctx context.Context, intent bootstrapRepairIntent, stagePath string, stage verifiedStage, old nativeHostReceipt, files []hostFile) (nativeHostReceipt, error) {
	var zero nativeHostReceipt
	result := NativeHostPrepareResult{InstallationID: intent.InstallationID, ReleaseID: stage.manifest.ReleaseID, ManifestSHA256: stage.sha256, StagePath: stagePath,
		Status: "prepared_not_started", DependencyEvidencePending: append([]string(nil), old.Result.DependencyEvidencePending...), RuntimeParentsRequireReprepare: old.Result.RuntimeParentsRequireReprepare}
	hashes := make(map[string]string, len(files))
	for _, file := range files {
		sum := sha256.Sum256(file.data)
		hash := hex.EncodeToString(sum[:])
		actual, err := repairProtectedFileSHA(file.path, file.mode, 0)
		if err != nil || actual != hash {
			return zero, ErrIncomplete
		}
		hashes[file.path] = hash
	}
	receipt := nativeHostReceipt{Result: result, Accounts: old.Accounts, Files: hashes}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return zero, err
	}
	path := filepath.Join(UnifiedPrivateStageRoot, nativeHostPrepareRecords, "prepare-"+stage.sha256+"-complete.json")
	wantSHA := sha256.Sum256(raw)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		if err := publishHostFile(path, raw, 0o600, 0, 0); err != nil {
			return zero, err
		}
	} else if err != nil {
		return zero, err
	}
	actualSHA, err := repairProtectedFileSHA(path, 0o600, 0)
	if err != nil || actualSHA != hex.EncodeToString(wantSHA[:]) {
		return zero, ErrBootstrapRepairUnknown
	}
	var actual nativeHostReceipt
	if err := readHostJSON(path, 0, 0, &actual); err != nil {
		return zero, ErrBootstrapRepairUnknown
	}
	if actual.Result.InstallationID != receipt.Result.InstallationID || actual.Result.ReleaseID != receipt.Result.ReleaseID || actual.Result.ManifestSHA256 != receipt.Result.ManifestSHA256 {
		return zero, ErrBootstrapRepairUnknown
	}
	if len(actual.Files) != len(receipt.Files) {
		return zero, ErrBootstrapRepairUnknown
	}
	for path, want := range receipt.Files {
		if actual.Files[path] != want {
			return zero, ErrBootstrapRepairUnknown
		}
	}
	if actual.Accounts != receipt.Accounts {
		return zero, ErrBootstrapRepairUnknown
	}
	if actual.Result.StagePath != receipt.Result.StagePath || actual.Result.Status != receipt.Result.Status {
		return zero, ErrBootstrapRepairUnknown
	}
	if _, err := readCompletedHostPreparation(ctx, stagePath, stage, productionNativeHostDeps(), path); err != nil {
		return zero, errors.Join(ErrBootstrapRepairUnknown, err)
	}
	return receipt, nil
}

func repairInstallSuccessorFirstIntent(intent bootstrapRepairIntent, stagePath string, stage verifiedStage) error {
	newIntent := nativeFirstCoreIntent{InstallationID: intent.InstallationID, StagePath: stagePath, ReleaseID: stage.manifest.ReleaseID, ManifestSHA256: stage.sha256, TokenSHA256: intent.TokenSHA256}
	raw, err := json.Marshal(newIntent)
	if err != nil {
		return err
	}
	path := filepath.Join(UnifiedPrivateStageRoot, nativeHostPrepareRecords, "first-core-"+stage.sha256+"-intent.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		if err := publishHostFile(path, raw, 0o600, 0, 0); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	wantSHA := sha256.Sum256(raw)
	if actual, err := repairProtectedFileSHA(path, 0o600, 0); err != nil || actual != hex.EncodeToString(wantSHA[:]) {
		return ErrBootstrapRepairUnknown
	}
	var again nativeFirstCoreIntent
	if err := readHostJSON(path, 0, 0, &again); err != nil || again != newIntent {
		return ErrBootstrapRepairUnknown
	}
	return nil
}

func repairReadRunningGeneration(ctx context.Context, installationID string, oldHigh int64) error {
	high, err := readCoreLaunchHighWater(nativeCoreJournal, installationID)
	if err != nil || high != oldHigh+1 {
		return ErrIncomplete
	}
	path := filepath.Join(install.UnifiedCoreDataDir, install.UnifiedDefaultDBName)
	db, err := sql.Open("sqlite", "file:"+url.PathEscape(path)+"?mode=ro&_pragma=query_only(ON)")
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var generation int64
	if err := db.QueryRowContext(ctx, "SELECT generation FROM core_generation WHERE singleton=1").Scan(&generation); err != nil || generation != high {
		return ErrIncomplete
	}
	return nil
}

func repairVerifyAuthorizationBeforeStart(ctx context.Context, intent bootstrapRepairIntent, stage verifiedStage, unitSHA string, receipt nativeHostReceipt) error {
	data := []byte(intent.InstallationID + "\n" + intent.NewManifestSHA256 + "\n")
	info, err := os.Lstat(bootstrapRepairAuthorizedPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != int64(len(data)) || artifactio.CheckFileOwner(info, 0, 0) != nil {
		return ErrIncomplete
	}
	actual, err := os.ReadFile(bootstrapRepairAuthorizedPath)
	if err != nil || !bytes.Equal(actual, data) {
		return ErrIncomplete
	}
	pinSHA, err := repairProtectedFileSHA(UnifiedTrustedPinPath, 0o600, 0)
	if err != nil || pinSHA != intent.NewPinSHA256 {
		return ErrIncomplete
	}
	current, err := os.Readlink(install.UnifiedCurrentSymlink)
	if err != nil || current != filepath.Join(install.UnifiedReleasesDir, intent.NewReleaseID) {
		return ErrIncomplete
	}
	if err := repairDropInEffective(ctx); err != nil {
		return err
	}
	if err := repairStoppedUnit(ctx, unitSHA); err != nil {
		return err
	}
	if err := repairNoBusinessRoles(ctx, stage.manifest); err != nil {
		return err
	}
	path := filepath.Join(UnifiedPrivateStageRoot, nativeHostPrepareRecords, "prepare-"+stage.sha256+"-complete.json")
	if _, err := readCompletedHostPreparation(ctx, receipt.Result.StagePath, stage, productionNativeHostDeps(), path); err != nil {
		return err
	}
	firstPath := filepath.Join(UnifiedPrivateStageRoot, nativeHostPrepareRecords, "first-core-"+stage.sha256+"-intent.json")
	var first nativeFirstCoreIntent
	if err := readHostJSON(firstPath, 0, 0, &first); err != nil || first.InstallationID != intent.InstallationID || first.StagePath != receipt.Result.StagePath || first.ReleaseID != stage.manifest.ReleaseID || first.ManifestSHA256 != stage.sha256 || first.TokenSHA256 != intent.TokenSHA256 {
		return ErrIncomplete
	}
	tokenSHA, err := repairProtectedFileSHA(nativeCoreSetupTokenSource, 0o600, 0)
	if err != nil || tokenSHA != intent.TokenSHA256 {
		return ErrIncomplete
	}
	return repairEmptyUserFacts(ctx, intent.DatabaseInode, intent.DatabaseGeneration, receipt.Accounts.CoreUID, receipt.Accounts.CoreGID)
}

func repairCloseAuthorizedGate(ctx context.Context) error {
	intent, err := repairReadIntent()
	if err != nil {
		return err
	}
	path := bootstrapRepairAuthorizedPath
	info, err := os.Lstat(path)
	if err == nil {
		want := []byte(intent.InstallationID + "\n" + intent.NewManifestSHA256 + "\n")
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != int64(len(want)) || artifactio.CheckFileOwner(info, 0, 0) != nil {
			return ErrBootstrapRepairUnknown
		}
		actual, e := os.ReadFile(path)
		if e != nil || !bytes.Equal(actual, want) {
			return ErrBootstrapRepairUnknown
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		if err := artifactio.SyncDirectory(filepath.Dir(path)); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := nativeFirstCoreSystemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	state, err := readNativeCoreUnitState(ctx)
	if err != nil {
		return err
	}
	if state.Active || state.MainPID > 0 {
		if err := nativeFirstCoreSystemctl(ctx, "stop", NativeCoreUnit); err != nil {
			return err
		}
	}
	if err := repairRequireAbsent(path); err != nil {
		return err
	}
	if err := repairDropInEffective(ctx); err != nil {
		return err
	}
	state, err = readNativeCoreUnitState(ctx)
	if err != nil || state.Active || state.MainPID != 0 || !nativeNoUnitJob(state.Job) {
		return ErrBootstrapRepairUnknown
	}
	return nil
}

func repairRestoreWithCoreChild(ctx context.Context, intent bootstrapRepairIntent, stagePath string, newStage verifiedStage, accounts nativeHostIDs, unitSHA string, currentInode uint64, currentGeneration, highWater int64, backup NativeBackupProtectedReceipt, launchLock *os.File) (sqlite.NativeOfflineRestoreReceipt, error) {
	var zero sqlite.NativeOfflineRestoreReceipt
	if ctx == nil || launchLock == nil || currentInode == 0 || currentGeneration < 1 || highWater < intent.LaunchHighWater || backup.Backup.SHA256 == "" {
		return zero, ErrIncomplete
	}
	session, err := repairStartCoreChild(ctx, intent, stagePath, newStage, accounts, "restore", unitSHA, currentInode, currentGeneration, &backup, highWater)
	if err != nil {
		return zero, err
	}
	defer session.close()
	decoder := json.NewDecoder(io.LimitReader(session.challengeRead, 8192))
	decoder.DisallowUnknownFields()
	encoder := json.NewEncoder(session.replyWrite)
	approved := false
	for sequence := 1; sequence <= 5; sequence++ {
		var challenge repairChallenge
		if err := decoder.Decode(&challenge); err == io.EOF {
			break
		} else if err != nil || challenge.Sequence != sequence || len(challenge.Nonce) != 32 {
			return zero, ErrBootstrapRepairUnknown
		}
		if err := repairRootChallengeRecheck(ctx, intent, session.parent, launchLock, unitSHA); err != nil {
			return zero, err
		}
		reply := repairChallengeReply{Digest: repairChallengeDigest(intent.Nonce, challenge.Nonce, sequence)}
		switch challenge.Kind {
		case "maintenance":
			if challenge.Prepared != nil {
				return zero, ErrIncomplete
			}
		case "approve_restore":
			if approved || challenge.Prepared == nil || challenge.Prepared.BackupSHA256 != backup.Backup.SHA256 || challenge.Prepared.SourceDBInode != currentInode || challenge.Prepared.SeedGeneration < highWater || challenge.Prepared.QuarantineDirectory != filepath.Join(install.UnifiedBackupDir, "quarantine-"+intent.Nonce) {
				return zero, ErrIncomplete
			}
			raw, err := json.Marshal(challenge.Prepared)
			if err != nil || len(raw) > 4096 {
				return zero, ErrIncomplete
			}
			if err := publishHostFile(filepath.Join(bootstrapRepairRoot, "restore-quarantined.json"), raw, 0o600, 0, 0); err != nil {
				return zero, err
			}
			approved = true
			reply.Commit = true
		default:
			return zero, ErrIncomplete
		}
		if err := encoder.Encode(reply); err != nil {
			return zero, err
		}
	}
	_ = session.replyWrite.Close()
	if err := session.wait(); err != nil {
		return zero, errors.Join(sqlite.ErrNativeRestoreOutcomeUnknown, err)
	}
	if !approved || session.output.Len() < 1 || session.output.Len() > 8192 {
		return zero, sqlite.ErrNativeRestoreOutcomeUnknown
	}
	var restored sqlite.NativeOfflineRestoreReceipt
	out := json.NewDecoder(bytes.NewReader(session.output.Bytes()))
	out.DisallowUnknownFields()
	if out.Decode(&restored) != nil || out.Decode(&struct{}{}) != io.EOF || restored.OriginalDBInode != currentInode || restored.SeedGeneration < highWater || restored.QuarantineDirectory != filepath.Join(install.UnifiedBackupDir, "quarantine-"+intent.Nonce) {
		return zero, sqlite.ErrNativeRestoreOutcomeUnknown
	}
	if err := repairWritePhase(intent, "restore-complete", restored.RestoredDBSHA256); err != nil {
		return zero, errors.Join(ErrBootstrapRepairUnknown, err)
	}
	return restored, nil
}

type NativeBootstrapRepairRecoveryResult struct {
	InstallationID    string `json:"installation_id"`
	RestoredReleaseID string `json:"restored_release_id"`
	BackupID          string `json:"backup_id"`
	SeedGeneration    int64  `json:"seed_generation"`
	Status            string `json:"status"`
}

// An interrupted restore is never restarted merely because restore-started
// exists. Only the protected approval, completed phase, unchanged quarantine
// and exact replacement DB prove that the SQLite replacement already finished.
func repairReadCompletedRestoreAt(ctx context.Context, root, dataDirectory, backupDirectory string, intent bootstrapRepairIntent, uid, gid int, backup NativeBackupProtectedReceipt) (sqlite.NativeOfflineRestoreReceipt, bool, error) {
	var zero sqlite.NativeOfflineRestoreReceipt
	path := filepath.Join(root, "phase-restore-complete.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return zero, false, nil
	} else if err != nil {
		return zero, false, err
	}
	var phase bootstrapRepairPhase
	if err := readHostJSON(path, os.Getuid(), os.Getgid(), &phase); err != nil || phase.InstallationID != intent.InstallationID || phase.NewManifestSHA256 != intent.NewManifestSHA256 || phase.Name != "restore-complete" || len(phase.ActualSHA256) != 64 {
		return zero, false, ErrBootstrapRepairUnknown
	}
	var prepared sqlite.NativeOfflineRestorePrepared
	if err := readHostJSON(filepath.Join(root, "restore-quarantined.json"), os.Getuid(), os.Getgid(), &prepared); err != nil || prepared.BackupSHA256 != backup.Backup.SHA256 || prepared.SourceDBInode == 0 || prepared.SeedGeneration < intent.LaunchHighWater || prepared.QuarantineDirectory != filepath.Join(backupDirectory, "quarantine-"+intent.Nonce) {
		return zero, false, ErrBootstrapRepairUnknown
	}
	quarantine, err := os.Lstat(prepared.QuarantineDirectory)
	if err != nil || !quarantine.IsDir() || quarantine.Mode().Perm() != 0o700 || artifactio.CheckFileOwner(quarantine, uid, gid) != nil {
		return zero, false, ErrBootstrapRepairUnknown
	}
	if source, err := os.Lstat(filepath.Join(prepared.QuarantineDirectory, install.UnifiedDefaultDBName)); err != nil || !source.Mode().IsRegular() || source.Mode().Perm() != 0o600 || artifactio.CheckFileOwner(source, uid, gid) != nil {
		return zero, false, ErrBootstrapRepairUnknown
	}
	currentPath := filepath.Join(dataDirectory, install.UnifiedDefaultDBName)
	before, err := os.Lstat(currentPath)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 || artifactio.CheckFileOwner(before, uid, gid) != nil {
		return zero, false, ErrBootstrapRepairUnknown
	}
	file, err := os.OpenFile(currentPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return zero, false, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		_ = file.Close()
		return zero, false, ErrBootstrapRepairUnknown
	}
	hash := sha256.New()
	_, readErr := io.Copy(hash, contextReader{context: ctx, reader: file})
	closeErr := file.Close()
	after, statErr := os.Lstat(currentPath)
	if readErr != nil || closeErr != nil || statErr != nil || !os.SameFile(before, after) || hex.EncodeToString(hash.Sum(nil)) != phase.ActualSHA256 {
		return zero, false, ErrBootstrapRepairUnknown
	}
	return sqlite.NativeOfflineRestoreReceipt{QuarantineDirectory: prepared.QuarantineDirectory, RestoredDBSHA256: phase.ActualSHA256, SeedGeneration: prepared.SeedGeneration, OriginalDBInode: prepared.SourceDBInode}, true, nil
}

func repairClassifyUnfinishedRestoreAt(root, dataDirectory, backupDirectory string, intent bootstrapRepairIntent, started bootstrapRepairPhase, currentInode uint64, currentGeneration int64) error {
	if started.DatabaseInode != currentInode || started.DatabaseGeneration != currentGeneration {
		return ErrBootstrapRepairRestoreUncertain
	}
	for _, path := range []string{
		filepath.Join(root, "restore-quarantined.json"), filepath.Join(backupDirectory, "quarantine-"+intent.Nonce),
		filepath.Join(dataDirectory, ".native-restore-"+intent.Nonce+".db"),
		filepath.Join(dataDirectory, ".native-retired-"+intent.Nonce+"-acornfox.db"),
		filepath.Join(dataDirectory, ".native-retired-"+intent.Nonce+"-acornfox.db-wal"),
		filepath.Join(dataDirectory, ".native-retired-"+intent.Nonce+"-acornfox.db-shm"),
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return ErrBootstrapRepairRestoreUncertain
		}
	}
	return ErrBootstrapRepairRestoreUnapproved
}

func repairReplaceActivePin(currentSHA string, oldPin acornfoxrelease.TrustedReleasePinV1, oldSHA string) error {
	return repairReplaceActivePinAt(UnifiedTrustedPinPath, "/etc/acornfox/trust/.bootstrap-repair-old-pin.tmp", bootstrapRepairOldPin, currentSHA, oldPin, oldSHA, 0)
}

func repairReplaceActivePinAt(path, temp, oldPinPath, currentSHA string, oldPin acornfoxrelease.TrustedReleasePinV1, oldSHA string, ownerUID int) error {
	if err := repairRequireAbsent(temp); err != nil {
		return err
	}
	actual, err := repairFileSHAAt(path, 0o600, ownerUID, os.Getgid())
	if err != nil || actual != currentSHA {
		return ErrIncomplete
	}
	data, err := os.ReadFile(oldPinPath)
	if err != nil || len(data) > 4096 || len(data) < 1 {
		return ErrIncomplete
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != oldSHA {
		return ErrIncomplete
	}
	var parsed acornfoxrelease.TrustedReleasePinV1
	if err := json.Unmarshal(data, &parsed); err != nil || parsed != oldPin {
		return ErrIncomplete
	}
	if err := publishHostFile(temp, data, 0o600, ownerUID, os.Getgid()); err != nil {
		return err
	}
	actual, err = repairFileSHAAt(path, 0o600, ownerUID, os.Getgid())
	if err != nil || actual != currentSHA {
		return ErrBootstrapRepairUnknown
	}
	if err := os.Rename(temp, path); err != nil {
		return errors.Join(ErrBootstrapRepairUnknown, err)
	}
	if err := artifactio.SyncDirectory(filepath.Dir(path)); err != nil {
		return errors.Join(ErrBootstrapRepairUnknown, err)
	}
	actual, err = repairFileSHAAt(path, 0o600, ownerUID, os.Getgid())
	if err != nil || actual != oldSHA {
		return ErrBootstrapRepairUnknown
	}
	return nil
}

type repairRollbackPaths struct {
	phaseRoot, unit, unitTemp, current, currentTemp, pin, pinTemp, oldPin string
}

// Called only after the completed SQLite replacement has been proven from
// protected phase, quarantine and DB SHA. Every resumable mixed state is the
// prefix of unit -> current -> pin; all other combinations are foreign drift.
func repairRollbackOwnedStateAt(intent bootstrapRepairIntent, paths repairRollbackPaths, oldUnit []byte, newUnitSHA, oldRelease, newRelease string, oldPin acornfoxrelease.TrustedReleasePinV1, ownerUID int) error {
	unitSHA, err := repairFileSHAAt(paths.unit, 0o644, ownerUID, os.Getgid())
	if err != nil || unitSHA != newUnitSHA && unitSHA != intent.OldUnitSHA256 {
		return ErrBootstrapRepairUnknown
	}
	info, err := os.Lstat(paths.current)
	if err != nil || info.Mode()&os.ModeSymlink == 0 || artifactio.CheckFileOwner(info, ownerUID, os.Getgid()) != nil {
		return ErrBootstrapRepairUnknown
	}
	current, err := os.Readlink(paths.current)
	if err != nil || current != newRelease && current != oldRelease {
		return ErrBootstrapRepairUnknown
	}
	pinSHA, err := repairFileSHAAt(paths.pin, 0o600, ownerUID, os.Getgid())
	if err != nil || pinSHA != intent.NewPinSHA256 && pinSHA != intent.OldPinSHA256 {
		return ErrBootstrapRepairUnknown
	}
	if unitSHA == newUnitSHA && current == oldRelease || current == newRelease && pinSHA == intent.OldPinSHA256 || unitSHA == newUnitSHA && pinSHA == intent.OldPinSHA256 {
		return ErrBootstrapRepairUnknown
	}
	unitPlanned, err := repairReadPhaseAt(paths.phaseRoot, intent, "rollback-unit-planned", intent.OldUnitSHA256)
	if err != nil {
		return err
	}
	unitDone, err := repairReadPhaseAt(paths.phaseRoot, intent, "rollback-unit", intent.OldUnitSHA256)
	if err != nil {
		return err
	}
	currentPlanned, err := repairReadPhaseAt(paths.phaseRoot, intent, "rollback-current-planned", intent.OldManifestSHA256)
	if err != nil {
		return err
	}
	currentDone, err := repairReadPhaseAt(paths.phaseRoot, intent, "rollback-current", intent.OldManifestSHA256)
	if err != nil {
		return err
	}
	pinPlanned, err := repairReadPhaseAt(paths.phaseRoot, intent, "rollback-pin-planned", intent.OldPinSHA256)
	if err != nil {
		return err
	}
	pinDone, err := repairReadPhaseAt(paths.phaseRoot, intent, "rollback-pin", intent.OldPinSHA256)
	if err != nil {
		return err
	}
	if unitSHA == newUnitSHA {
		if unitDone || currentPlanned || currentDone || pinPlanned || pinDone {
			return ErrBootstrapRepairUnknown
		}
		if err := repairEnsurePhaseAt(paths.phaseRoot, intent, "rollback-unit-planned", intent.OldUnitSHA256); err != nil {
			return err
		}
		if err := repairReplaceCoreUnitAt(paths.unit, paths.unitTemp, newUnitSHA, oldUnit, intent.OldUnitSHA256, ownerUID); err != nil {
			return err
		}
	} else if !unitPlanned {
		return ErrBootstrapRepairUnknown
	}
	if err := repairEnsurePhaseAt(paths.phaseRoot, intent, "rollback-unit", intent.OldUnitSHA256); err != nil {
		return err
	}
	if current == newRelease {
		if currentDone || pinPlanned || pinDone {
			return ErrBootstrapRepairUnknown
		}
		if err := repairEnsurePhaseAt(paths.phaseRoot, intent, "rollback-current-planned", intent.OldManifestSHA256); err != nil {
			return err
		}
		if err := repairReplaceCurrentAt(paths.current, paths.currentTemp, newRelease, oldRelease, ownerUID); err != nil {
			return err
		}
	} else if !currentPlanned {
		return ErrBootstrapRepairUnknown
	}
	if err := repairEnsurePhaseAt(paths.phaseRoot, intent, "rollback-current", intent.OldManifestSHA256); err != nil {
		return err
	}
	if pinSHA == intent.NewPinSHA256 {
		if pinDone {
			return ErrBootstrapRepairUnknown
		}
		if err := repairEnsurePhaseAt(paths.phaseRoot, intent, "rollback-pin-planned", intent.OldPinSHA256); err != nil {
			return err
		}
		if err := repairReplaceActivePinAt(paths.pin, paths.pinTemp, paths.oldPin, intent.NewPinSHA256, oldPin, intent.OldPinSHA256, ownerUID); err != nil {
			return err
		}
	} else if !pinPlanned {
		return ErrBootstrapRepairUnknown
	}
	return repairEnsurePhaseAt(paths.phaseRoot, intent, "rollback-pin", intent.OldPinSHA256)
}

// RecoverNativeBootstrapRepair is a separate, explicitly invoked stop-and-
// restore action. It never starts the known-bad Source15 Core release.
func RecoverNativeBootstrapRepair(ctx context.Context, stagePath string) (NativeBootstrapRepairRecoveryResult, error) {
	var zero NativeBootstrapRepairRecoveryResult
	if ctx == nil || os.Geteuid() != 0 || os.Getegid() != 0 || filepath.Dir(stagePath) != UnifiedPrivateStageRoot || !nativeReadyName.MatchString(filepath.Base(stagePath)) {
		return zero, ErrIncomplete
	}
	intent, err := repairReadIntent()
	if err != nil {
		return zero, err
	}
	if _, completed, err := repairReadCompletion(intent); err != nil || completed {
		return zero, ErrIncomplete
	}
	var oldPin, newPin acornfoxrelease.TrustedReleasePinV1
	if err := readProtectedPublisherJSON(bootstrapRepairOldPin, 4096, &oldPin); err != nil {
		return zero, err
	}
	if err := readProtectedPublisherJSON(bootstrapRepairNewPin, 4096, &newPin); err != nil {
		return zero, err
	}
	if pinSHA, err := repairProtectedFileSHA(UnifiedTrustedPinPath, 0o600, 0); err != nil || pinSHA != intent.NewPinSHA256 && pinSHA != intent.OldPinSHA256 {
		return zero, ErrIncomplete
	}
	oldStage, err := verifyStagedRelease(ctx, intent.OldStagePath, UnifiedPrivateStageRoot, oldPin, 0, 0)
	if err != nil || oldStage.sha256 != intent.OldManifestSHA256 {
		return zero, ErrIncomplete
	}
	newStage, err := verifyStagedRelease(ctx, stagePath, UnifiedPrivateStageRoot, newPin, 0, 0)
	if err != nil || newStage.sha256 != intent.NewManifestSHA256 {
		return zero, ErrIncomplete
	}
	var oldReceipt nativeHostReceipt
	oldComplete := filepath.Join(UnifiedPrivateStageRoot, nativeHostPrepareRecords, "prepare-"+intent.OldManifestSHA256+"-complete.json")
	if err := readHostJSON(oldComplete, 0, 0, &oldReceipt); err != nil || oldReceipt.Result.InstallationID != intent.InstallationID {
		return zero, ErrIncomplete
	}
	newRelease, err := install.ReleaseDirectory(install.UnifiedReleasesDir, intent.NewReleaseID)
	if err != nil {
		return zero, err
	}
	if err := verifyInstalledRelease(ctx, newRelease, newStage, 0, 0); err != nil {
		return zero, err
	}
	files, _, newUnitSHA, err := repairExpectedHostFiles(stagePath, newStage, oldReceipt)
	if err == nil {
		_ = files
	} // Other twelve original owned files remain exact.
	if err != nil {
		return zero, err
	}
	if err := repairCloseAuthorizedGate(ctx); err != nil {
		return zero, errors.Join(ErrBootstrapRepairUnknown, err)
	}
	actualUnitSHA, err := repairProtectedFileSHA("/etc/systemd/system/"+NativeCoreUnit, 0o644, 0)
	if err != nil || actualUnitSHA != newUnitSHA && actualUnitSHA != intent.OldUnitSHA256 {
		return zero, ErrBootstrapRepairUnknown
	}
	if err := repairStoppedUnit(ctx, actualUnitSHA); err != nil {
		return zero, err
	}
	oldRelease, err := install.ReleaseDirectory(install.UnifiedReleasesDir, intent.OldReleaseID)
	if err != nil || verifyInstalledRelease(ctx, oldRelease, oldStage, 0, 0) != nil {
		return zero, ErrBootstrapRepairUnknown
	}
	current, err := os.Readlink(install.UnifiedCurrentSymlink)
	if err != nil || current != newRelease && current != oldRelease {
		return zero, ErrIncomplete
	}
	lock, err := repairLaunchLock()
	if err != nil {
		return zero, err
	}
	defer lock.Close()
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	core := oldReceipt.Accounts
	generation, inode, err := readCoreGenerationOnly(ctx, sqlite.CompiledNativeMigrationPins(), uint32(core.CoreUID), uint32(core.CoreGID))
	if err != nil || inode == 0 || generation < intent.DatabaseGeneration {
		return zero, ErrIncomplete
	}
	if err := repairEmptyUserFacts(ctx, inode, generation, core.CoreUID, core.CoreGID); err != nil {
		return zero, err
	}
	high, err := readCoreLaunchHighWater(nativeCoreJournal, intent.InstallationID)
	if err != nil || high < intent.LaunchHighWater {
		return zero, ErrIncomplete
	}
	backupID := "backup-" + intent.Nonce
	backup, err := ReadNativeBackupReceipt(ctx, backupID)
	if err != nil || backup.InstallationID != intent.InstallationID || backup.ManifestSHA256 != intent.OldManifestSHA256 || backup.ReleaseID != intent.OldReleaseID || backup.Backup.Generation != intent.DatabaseGeneration {
		return zero, ErrIncomplete
	}
	restoreStart, started, err := repairReadRestoreStarted(intent, backup.Backup.SHA256)
	if err != nil {
		return zero, ErrBootstrapRepairUnknown
	}
	var restored sqlite.NativeOfflineRestoreReceipt
	if started {
		var completed bool
		restored, completed, err = repairReadCompletedRestoreAt(ctx, bootstrapRepairRoot, install.UnifiedCoreDataDir, install.UnifiedBackupDir, intent, core.CoreUID, core.CoreGID, backup)
		if err != nil {
			return zero, errors.Join(ErrBootstrapRepairUnknown, err)
		}
		if !completed {
			return zero, errors.Join(ErrBootstrapRepairUnknown, repairClassifyUnfinishedRestoreAt(bootstrapRepairRoot, install.UnifiedCoreDataDir, install.UnifiedBackupDir, intent, restoreStart, inode, generation))
		}
	} else {
		if err := repairRequireAbsent(repairPhasePath("restore-complete"), filepath.Join(bootstrapRepairRoot, "restore-quarantined.json")); err != nil {
			return zero, ErrBootstrapRepairUnknown
		}
		if err := repairWriteRestoreStarted(intent, backup.Backup.SHA256, inode, generation); err != nil {
			return zero, errors.Join(ErrBootstrapRepairUnknown, err)
		}
		restored, err = repairRestoreWithCoreChild(ctx, intent, stagePath, newStage, core, newUnitSHA, inode, generation, high, backup, lock)
		if err != nil {
			return zero, errors.Join(ErrBootstrapRepairUnknown, err)
		}
	}
	if restored.SeedGeneration < high {
		return zero, ErrBootstrapRepairUnknown
	}
	oldFiles, err := nativeHostFiles(intent.OldStagePath, oldStage.manifest.ReleaseID, core)
	if err != nil {
		return zero, err
	}
	var oldUnit []byte
	for _, file := range oldFiles {
		if file.path == "/etc/systemd/system/"+NativeCoreUnit {
			oldUnit = file.data
		}
	}
	if len(oldUnit) == 0 {
		return zero, ErrIncomplete
	}
	paths := repairRollbackPaths{phaseRoot: bootstrapRepairRoot, unit: "/etc/systemd/system/" + NativeCoreUnit,
		unitTemp: "/etc/systemd/system/.acornfox-bootstrap-core-unit.tmp", current: install.UnifiedCurrentSymlink,
		currentTemp: "/opt/acornfox/.bootstrap-repair-current.tmp", pin: UnifiedTrustedPinPath,
		pinTemp: "/etc/acornfox/trust/.bootstrap-repair-old-pin.tmp", oldPin: bootstrapRepairOldPin}
	if err := repairRollbackOwnedStateAt(intent, paths, oldUnit, newUnitSHA, oldRelease, newRelease, oldPin, 0); err != nil {
		return zero, errors.Join(ErrBootstrapRepairUnknown, err)
	}
	if err := nativeFirstCoreSystemctl(ctx, "daemon-reload"); err != nil {
		return zero, ErrBootstrapRepairUnknown
	}
	if err := repairRequireAbsent(bootstrapRepairAuthorizedPath); err != nil {
		return zero, ErrBootstrapRepairUnknown
	}
	if err := repairDropInEffective(ctx); err != nil {
		return zero, ErrBootstrapRepairUnknown
	}
	if err := repairStoppedUnit(ctx, intent.OldUnitSHA256); err != nil {
		return zero, ErrBootstrapRepairUnknown
	}
	if err := repairEnsurePhaseAt(bootstrapRepairRoot, intent, "rolled-back-stopped", intent.OldManifestSHA256); err != nil {
		return zero, ErrBootstrapRepairUnknown
	}
	return NativeBootstrapRepairRecoveryResult{InstallationID: intent.InstallationID, RestoredReleaseID: intent.OldReleaseID, BackupID: backupID, SeedGeneration: restored.SeedGeneration, Status: "rolled_back_stopped"}, nil
}
