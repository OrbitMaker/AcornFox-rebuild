package unifiedinstall

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/open-card/open-card/internal/acornfoxrelease"
	"github.com/open-card/open-card/internal/artifactio"
	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/localpeer"
	"github.com/open-card/open-card/internal/persistence/sqlite"
	"golang.org/x/sys/unix"
)

const nativeRestoreJournalDirectory = "restore-journal"

var ErrNativeRestoreUnknown = errors.New("Native SQLite restore outcome unknown; keep Core masked and preserve quarantine")

type NativeRestorePlan struct {
	BackupID, InstallationID, ReleaseID, ManifestSHA256, AttemptID string
	CoreUID, CoreGID                                               uint32
	Request                                                        sqlite.NativeOfflineRestoreRequest
}

type nativeRestorePhase struct {
	BackupID       string                               `json:"backup_id"`
	InstallationID string                               `json:"installation_id"`
	ReleaseID      string                               `json:"release_id"`
	ManifestSHA256 string                               `json:"manifest_sha256"`
	AttemptID      string                               `json:"attempt_id"`
	Phase          string                               `json:"phase"`
	Prepared       *sqlite.NativeOfflineRestorePrepared `json:"prepared,omitempty"`
	Receipt        *sqlite.NativeOfflineRestoreReceipt  `json:"receipt,omitempty"`
}

// WithNativeRestorePlan holds the same root launch flock throughout restore.
// It never calls Store.Open, unmasks a unit, or starts a service.
func WithNativeRestorePlan(ctx context.Context, backupID, stagePath string, execute func(NativeRestorePlan) error) error {
	if ctx == nil || execute == nil || os.Geteuid() != 0 || os.Getegid() != 0 || !nativeBackupID.MatchString(backupID) || filepath.Dir(stagePath) != UnifiedPrivateStageRoot || filepath.Clean(stagePath) != stagePath {
		return ErrIncomplete
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := CheckNativeCoreMaintenance(ctx); err != nil {
		return err
	}
	if err := verifyRootRunAncestor(nativeCoreJournal); err != nil {
		return err
	}
	journal, err := os.Lstat(nativeCoreJournal)
	if err != nil || !journal.IsDir() || journal.Mode().Perm() != 0700 || artifactio.CheckFileOwner(journal, 0, 0) != nil {
		return ErrIncomplete
	}
	lock, err := os.OpenFile(filepath.Join(nativeCoreJournal, "launch.lock"), os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || artifactio.CheckFileOwner(info, 0, 0) != nil {
		return ErrIncomplete
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return ErrIncomplete
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	receipt, err := ReadNativeBackupReceipt(ctx, backupID)
	if err != nil {
		return err
	}
	pin := acornfoxrelease.TrustedReleasePinV1{ExpectedReleaseID: receipt.ReleaseID, ExpectedManifestSHA256: receipt.ManifestSHA256, ExpectedSourceCommit: receipt.SourceCommit}
	stage, err := reopenProductionStage(ctx, stagePath, pin)
	if err != nil || stage.sha256 != receipt.ManifestSHA256 {
		return ErrIncomplete
	}
	updater, err := componentArtifact(stage.manifest, stage.manifest.Components.HostUpdate.ArtifactID)
	if err != nil || updater.RelativePath != "bin/acornfox-host-update" {
		return ErrIncomplete
	}
	self, err := localpeer.AttestLinuxProcess(int32(os.Getpid()))
	if err != nil {
		return err
	}
	expectedExe := filepath.Join(install.UnifiedReleasesDir, receipt.ReleaseID, updater.RelativePath)
	if self.UID != 0 || self.ExecutablePath != expectedExe || self.ExecutableSHA256 != updater.SHA256 {
		return ErrIncomplete
	}
	oldPins := receipt.Backup.Migrations
	if len(oldPins) < 1 || len(oldPins) > 64 || len(stage.manifest.SQLiteCompatibility.RequiredMigrations) != len(oldPins) {
		return ErrIncompatible
	}
	for i, p := range oldPins {
		if stage.manifest.SQLiteCompatibility.RequiredMigrations[i].Version != p.Version || stage.manifest.SQLiteCompatibility.RequiredMigrations[i].Checksum != p.Checksum {
			return ErrIncompatible
		}
	}
	coreUID, coreGID, err := resolvedRoleOwner(install.AccountCore)
	if err != nil {
		return err
	}
	old, err := localpeer.LoadProtectedRuntimePeerBinding(UnifiedRuntimeBindingPath)
	if err != nil || old == nil {
		return ErrIncomplete
	}
	if _, statErr := os.Lstat("/proc/" + strconvPID(old.CorePID)); !os.IsNotExist(statErr) {
		return ErrIncomplete
	}
	high, err := readCoreLaunchHighWater(nativeCoreJournal, receipt.InstallationID)
	if err != nil || high < 1 {
		return ErrIncomplete
	}
	if err := rejectExistingRestoreAttempt(backupID); err != nil {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	attempt := hex.EncodeToString(nonce[:])
	plan := NativeRestorePlan{BackupID: backupID, InstallationID: receipt.InstallationID, ReleaseID: receipt.ReleaseID, ManifestSHA256: receipt.ManifestSHA256, AttemptID: attempt, CoreUID: coreUID, CoreGID: coreGID, Request: sqlite.NativeOfflineRestoreRequest{
		DataDirectory: install.UnifiedCoreDataDir, BackupDirectory: install.UnifiedBackupDir, BackupName: backupID + ".db", AttemptID: attempt, BackupSHA256: receipt.Backup.SHA256, BackupSizeBytes: receipt.Backup.SizeBytes, BackupGeneration: receipt.Backup.Generation, LaunchHighWater: high, ExpectedPins: append([]sqlite.NativeMigrationPin(nil), oldPins...),
	}}
	if err := PersistNativeRestorePhase(ctx, plan, "intent", nil, nil); err != nil {
		return errors.Join(ErrNativeRestoreUnknown, err)
	}
	if err := execute(plan); err != nil {
		return errors.Join(ErrNativeRestoreUnknown, err)
	}
	return nil
}

func strconvPID(pid int32) string {
	if pid <= 0 {
		return "0"
	}
	return strconv.FormatInt(int64(pid), 10)
}

func rejectExistingRestoreAttempt(id string) error {
	path := filepath.Join(UnifiedPrivateStageRoot, nativeRestoreJournalDirectory)
	info, statErr := os.Lstat(path)
	if os.IsNotExist(statErr) {
		return nil
	}
	if statErr != nil || !info.IsDir() || info.Mode().Perm() != 0700 || artifactio.CheckFileOwner(info, 0, 0) != nil {
		return ErrIncomplete
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	prefix := id + "-"
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			return ErrIncomplete
		}
	}
	return nil
}

// PersistNativeRestorePhase uses the already accepted root private durable
// writer. Metadata names are exclusive; errors after an intent are unknown.
func PersistNativeRestorePhase(ctx context.Context, plan NativeRestorePlan, phase string, prepared *sqlite.NativeOfflineRestorePrepared, receipt *sqlite.NativeOfflineRestoreReceipt) (err error) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return ErrIncomplete
	}
	return persistNativeRestorePhaseAt(ctx, plan, phase, prepared, receipt, UnifiedPrivateStageRoot, 0, 0)
}

func persistNativeRestorePhaseAt(ctx context.Context, plan NativeRestorePlan, phase string, prepared *sqlite.NativeOfflineRestorePrepared, receipt *sqlite.NativeOfflineRestoreReceipt, privateRoot string, uid, gid int) (err error) {
	if ctx == nil || !nativeBackupID.MatchString(plan.BackupID) || !validRestoreAttemptID(plan.AttemptID) || (phase != "intent" && phase != "quarantined" && phase != "committed") {
		return ErrIncomplete
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if phase == "quarantined" && (prepared == nil || prepared.QuarantineDirectory != filepath.Join(install.UnifiedBackupDir, "quarantine-"+plan.AttemptID) || prepared.BackupSHA256 != plan.Request.BackupSHA256) {
		return ErrIncomplete
	}
	if phase == "committed" && (receipt == nil || receipt.SeedGeneration < plan.Request.LaunchHighWater || receipt.QuarantineDirectory != filepath.Join(install.UnifiedBackupDir, "quarantine-"+plan.AttemptID)) {
		return ErrIncomplete
	}
	writer, err := artifactio.NewDurableWriter(privateRoot, uid, gid)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := writer.Close(); closeErr != nil {
			err = errors.Join(err, ErrNativeRestoreUnknown, closeErr)
		}
	}()
	if writer.RootInfo().Mode().Perm() != 0700 {
		return ErrIncomplete
	}
	if _, err := writer.CreateChildDirectory(nativeRestoreJournalDirectory, 0700); err != nil {
		return err
	}
	child, err := writer.OpenChildWriter(nativeRestoreJournalDirectory, 0700)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := child.Close(); closeErr != nil {
			err = errors.Join(err, ErrNativeRestoreUnknown, closeErr)
		}
	}()
	value := nativeRestorePhase{BackupID: plan.BackupID, InstallationID: plan.InstallationID, ReleaseID: plan.ReleaseID, ManifestSHA256: plan.ManifestSHA256, AttemptID: plan.AttemptID, Phase: phase, Prepared: prepared, Receipt: receipt}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 8192 {
		return ErrIncomplete
	}
	name := plan.BackupID + "-" + plan.AttemptID + "-" + phase + ".json"
	if err := child.CreateMetadata(name, raw); err != nil {
		return err
	}
	got, err := child.ReadMetadata(name)
	if err != nil || !bytes.Equal(got, raw) {
		return errors.Join(ErrNativeRestoreUnknown, err)
	}
	return nil
}

func validRestoreAttemptID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil && strings.ToLower(id) == id
}
