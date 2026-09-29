package unifiedinstall

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/acornfoxrelease"
	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/localpeer"
	"github.com/open-card/open-card/internal/persistence/sqlite"
)

const NativeCoreUnit = "acornfox-core.service"

type NativeSQLiteBackupPlan struct {
	CoreUID, CoreGID                                        uint32
	ReleaseID, SourceCommit, ManifestSHA256, InstallationID string
	Request                                                 sqlite.NativeOfflineBackupRequest
}

// CheckNativeCoreMaintenance enforces a real fixed systemd stop/inhibit gate.
// A missing unit or merely inactive but startable unit is not accepted.
func CheckNativeCoreMaintenance(ctx context.Context) error {
	if ctx == nil {
		return ErrIncomplete
	}
	deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(deadline, "/usr/bin/systemctl", "show", NativeCoreUnit, "--property=LoadState,ActiveState,SubState,MainPID,Job")
	output, err := cmd.Output()
	if err != nil || len(output) > 2048 {
		return errors.New("Native Core service maintenance state is unavailable")
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		name, value, found := strings.Cut(line, "=")
		if !found || name == "" || len(values) >= 5 {
			return ErrIncomplete
		}
		values[name] = value
	}
	if len(values) != 5 || values["LoadState"] != "masked" || values["ActiveState"] != "inactive" || values["SubState"] != "dead" || values["MainPID"] != "0" || (values["Job"] != "" && values["Job"] != "0") {
		return errors.New("Native Core unit must be masked and stopped without a pending job")
	}
	return nil
}

// PreflightNativeSQLiteBackup is the actual root composition gate for the
// non-migrating Core-UID child. It does not call sqlite.Open or stop a service.
func PreflightNativeSQLiteBackup(ctx context.Context, stagePath string) (NativeSQLiteBackupPlan, error) {
	var zero NativeSQLiteBackupPlan
	if ctx == nil || os.Geteuid() != 0 || os.Getegid() != 0 {
		return zero, ErrIncomplete
	}
	if err := CheckNativeCoreMaintenance(ctx); err != nil {
		return zero, err
	}
	var pin acornfoxrelease.TrustedReleasePinV1
	if err := readProtectedPublisherJSON(UnifiedTrustedPinPath, 4096, &pin); err != nil {
		return zero, err
	}
	var installation struct {
		ID string `json:"installation_id"`
	}
	if err := readProtectedPublisherJSON(UnifiedInstallationIDPath, 1024, &installation); err != nil {
		return zero, err
	}
	if len(installation.ID) < 8 || len(installation.ID) > 128 || strings.ContainsAny(installation.ID, "/\\\x00 \t\r\n") {
		return zero, ErrIncomplete
	}
	stage, err := reopenProductionStage(ctx, stagePath, pin)
	if err != nil {
		return zero, err
	}
	component, err := componentArtifact(stage.manifest, stage.manifest.Components.HostUpdate.ArtifactID)
	if err != nil || component.RelativePath != "bin/acornfox-host-update" {
		return zero, ErrIncomplete
	}
	att, err := localpeer.AttestLinuxProcess(int32(os.Getpid()))
	if err != nil {
		return zero, err
	}
	installed := filepath.Join(install.UnifiedReleasesDir, stage.manifest.ReleaseID, component.RelativePath)
	if att.UID != 0 || att.ExecutablePath != installed || att.ExecutableSHA256 != component.SHA256 {
		return zero, ErrIncomplete
	}
	oldBinding, err := localpeer.LoadProtectedRuntimePeerBinding(UnifiedRuntimeBindingPath)
	if err != nil || oldBinding == nil {
		return zero, ErrIncomplete
	}
	if _, err := os.Lstat(fmt.Sprintf("/proc/%d", oldBinding.CorePID)); !os.IsNotExist(err) {
		return zero, errors.New("previous Core process is still present or cannot be ruled out")
	}
	account, err := user.Lookup(install.AccountCore)
	if err != nil {
		return zero, err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return zero, ErrIncomplete
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || gid == 0 {
		return zero, ErrIncomplete
	}
	compiled := sqlite.CompiledNativeMigrationPins()
	actualPins := stage.manifest.SQLiteCompatibility.RequiredMigrations
	if len(actualPins) != len(compiled) || stage.manifest.SQLiteCompatibility.ReadWriteMode != "exclusive_writer" || stage.manifest.SQLiteCompatibility.RollbackPolicy != acornfoxrelease.RollbackRequiresDataRestore {
		return zero, ErrIncompatible
	}
	for i, pin := range actualPins {
		if pin.Version != compiled[i].Version || pin.Checksum != compiled[i].Checksum {
			return zero, ErrIncompatible
		}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return zero, err
	}
	return NativeSQLiteBackupPlan{CoreUID: uint32(uid), CoreGID: uint32(gid), ReleaseID: stage.manifest.ReleaseID, SourceCommit: stage.manifest.Provenance.SourceCommit, ManifestSHA256: stage.sha256, InstallationID: installation.ID, Request: sqlite.NativeOfflineBackupRequest{DataDirectory: install.UnifiedCoreDataDir, BackupDirectory: install.UnifiedBackupDir, BackupName: "backup-" + hex.EncodeToString(nonce[:]) + ".db", ExpectedPins: compiled}}, nil
}
