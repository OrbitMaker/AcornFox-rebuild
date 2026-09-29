package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/localpeer"
	"github.com/open-card/open-card/internal/persistence/sqlite"
	"github.com/open-card/open-card/internal/unifiedinstall"
)

func nativeSQLiteFailureMessage(err error) string {
	if errors.Is(err, sqlite.ErrNativeBackupOutcomeUnknown) {
		return "acornfox-host-update: Native SQLite backup outcome unknown; preserve evidence and reconcile before retry"
	}
	return "acornfox-host-update: Native SQLite backup failed before a verified receipt"
}

func nativeSQLiteRestoreFailureMessage(err error) string {
	if errors.Is(err, unifiedinstall.ErrNativeRestoreUnknown) || errors.Is(err, sqlite.ErrNativeRestoreOutcomeUnknown) {
		return "acornfox-host-update: Native SQLite restore outcome unknown; keep Core masked and preserve backup/quarantine/journal"
	}
	return "acornfox-host-update: Native SQLite restore preflight refused before a verified intent"
}

func runNativeSQLiteBackup(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("native-sqlite-backup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var stage string
	fs.StringVar(&stage, "stage", "", "fixed complete trusted Native ready stage")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || filepath.Dir(stage) != unifiedinstall.UnifiedPrivateStageRoot || filepath.Clean(stage) != stage {
		return errors.New("fixed ready stage is required")
	}
	plan, err := unifiedinstall.PreflightNativeSQLiteBackup(ctx, stage)
	if err != nil {
		return err
	}
	input, err := json.Marshal(plan.Request)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	child := exec.CommandContext(ctx, executable, "native-sqlite-backup-child")
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: plan.CoreUID, Gid: plan.CoreGID, Groups: []uint32{plan.CoreGID}}}
	child.Env = []string{"PATH=/usr/bin:/bin"}
	child.Dir = "/"
	child.Stdin = bytes.NewReader(input)
	var output bytes.Buffer
	child.Stdout = &output
	child.Stderr = io.Discard
	if err := child.Run(); err != nil {
		if _, statErr := os.Lstat(filepath.Join(plan.Request.BackupDirectory, plan.Request.BackupName)); !os.IsNotExist(statErr) {
			return errors.Join(sqlite.ErrNativeBackupOutcomeUnknown, err, statErr)
		}
		return fmt.Errorf("Native SQLite backup child failed before publication: %w", err)
	}
	if output.Len() < 1 || output.Len() > 8192 {
		return sqlite.ErrNativeBackupOutcomeUnknown
	}
	var receipt sqlite.NativeOfflineBackupReceipt
	dec := json.NewDecoder(bytes.NewReader(output.Bytes()))
	dec.DisallowUnknownFields()
	if dec.Decode(&receipt) != nil || dec.Decode(&struct{}{}) != io.EOF || receipt.BackupPath != filepath.Join(plan.Request.BackupDirectory, plan.Request.BackupName) || receipt.SizeBytes <= 0 || receipt.SourceDBInode == 0 || len(receipt.Migrations) != len(plan.Request.ExpectedPins) {
		return sqlite.ErrNativeBackupOutcomeUnknown
	}
	for i, pin := range receipt.Migrations {
		if pin != plan.Request.ExpectedPins[i] {
			return sqlite.ErrNativeBackupOutcomeUnknown
		}
	}
	if err := unifiedinstall.CheckNativeCoreMaintenance(ctx); err != nil {
		return errors.Join(sqlite.ErrNativeBackupOutcomeUnknown, err)
	}
	protected, err := unifiedinstall.SaveNativeBackupReceipt(ctx, plan, receipt)
	if err != nil {
		return errors.Join(sqlite.ErrNativeBackupOutcomeUnknown, err)
	}
	result := struct {
		ReleaseID      string                            `json:"release_id"`
		SourceCommit   string                            `json:"source_commit"`
		ManifestSHA256 string                            `json:"manifest_sha256"`
		BackupID       string                            `json:"backup_id"`
		Backup         sqlite.NativeOfflineBackupReceipt `json:"backup"`
	}{plan.ReleaseID, plan.SourceCommit, plan.ManifestSHA256, protected.BackupID, receipt}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		return errors.Join(sqlite.ErrNativeBackupOutcomeUnknown, err)
	}
	return nil
}

func runNativeSQLiteBackupChild(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return errors.New("Native SQLite child accepts no arguments")
	}
	account, err := user.Lookup(install.AccountCore)
	if err != nil {
		return err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 || os.Getuid() != int(uid) || os.Geteuid() != int(uid) {
		return errors.New("Native SQLite child is not the fixed Core identity")
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || gid == 0 || os.Getgid() != int(gid) || os.Getegid() != int(gid) {
		return errors.New("Native SQLite child has the wrong Core group")
	}
	input, err := io.ReadAll(io.LimitReader(os.Stdin, 8193))
	if err != nil || len(input) > 8192 {
		return errors.New("Native SQLite child input is invalid")
	}
	var request sqlite.NativeOfflineBackupRequest
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.DisallowUnknownFields()
	if dec.Decode(&request) != nil || dec.Decode(&struct{}{}) != io.EOF || request.DataDirectory != install.UnifiedCoreDataDir || request.BackupDirectory != install.UnifiedBackupDir {
		return errors.New("Native SQLite child request is not fixed")
	}
	if err := unifiedinstall.CheckNativeCoreMaintenance(ctx); err != nil {
		return err
	}
	receipt, err := sqlite.BackupNativeOffline(ctx, request, unifiedinstall.CheckNativeCoreMaintenance)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stdout).Encode(receipt); err != nil {
		return errors.Join(sqlite.ErrNativeBackupOutcomeUnknown, err)
	}
	return nil
}

func runNativeSQLiteRestore(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("native-sqlite-restore", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var backupID, stage string
	fs.StringVar(&backupID, "backup-id", "", "root-protected Native backup receipt ID")
	fs.StringVar(&stage, "stage", "", "retained trusted old-release ready stage")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || filepath.Dir(stage) != unifiedinstall.UnifiedPrivateStageRoot || filepath.Clean(stage) != stage {
		return errors.New("fixed old-release stage required")
	}
	deadline, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	return unifiedinstall.WithNativeRestorePlan(deadline, backupID, stage, func(plan unifiedinstall.NativeRestorePlan) error {
		if err := unifiedinstall.CheckNativeCoreMaintenance(deadline); err != nil {
			return err
		}
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		child := exec.CommandContext(deadline, executable, "native-sqlite-restore-child")
		child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: plan.CoreUID, Gid: plan.CoreGID, Groups: []uint32{plan.CoreGID}}}
		child.Env = []string{"PATH=/usr/bin:/bin"}
		child.Dir = "/"
		child.Stderr = io.Discard
		input, err := child.StdinPipe()
		if err != nil {
			return err
		}
		output, err := child.StdoutPipe()
		if err != nil {
			return err
		}
		if err := child.Start(); err != nil {
			return err
		}
		joined := false
		defer func() {
			if !joined {
				_ = input.Close()
				_ = child.Process.Kill()
				_ = child.Wait()
			}
		}()
		encoder := json.NewEncoder(input)
		decoder := json.NewDecoder(io.LimitReader(output, 16<<10))
		decoder.DisallowUnknownFields()
		if err := encoder.Encode(plan.Request); err != nil {
			return err
		}
		var prepared sqlite.NativeOfflineRestorePrepared
		if err := decoder.Decode(&prepared); err != nil {
			return err
		}
		if prepared.QuarantineDirectory != filepath.Join(install.UnifiedBackupDir, "quarantine-"+plan.AttemptID) || prepared.SourceDBInode == 0 || prepared.CurrentGeneration < 0 || prepared.SeedGeneration < prepared.CurrentGeneration || prepared.SeedGeneration < plan.Request.BackupGeneration || prepared.SeedGeneration < plan.Request.LaunchHighWater || prepared.BackupSHA256 != plan.Request.BackupSHA256 {
			return unifiedinstall.ErrIncomplete
		}
		if err := unifiedinstall.PersistNativeRestorePhase(deadline, plan, "quarantined", &prepared, nil); err != nil {
			return err
		}
		if err := encoder.Encode(struct {
			Commit bool `json:"commit"`
		}{true}); err != nil {
			return err
		}
		var restored sqlite.NativeOfflineRestoreReceipt
		if err := decoder.Decode(&restored); err != nil {
			return err
		}
		if err := input.Close(); err != nil {
			return err
		}
		waitErr := child.Wait()
		joined = true
		if waitErr != nil || restored.QuarantineDirectory != prepared.QuarantineDirectory || restored.SeedGeneration != prepared.SeedGeneration || restored.OriginalDBInode != prepared.SourceDBInode {
			return errors.Join(sqlite.ErrNativeRestoreOutcomeUnknown, waitErr)
		}
		if err := unifiedinstall.CheckNativeCoreMaintenance(deadline); err != nil {
			return err
		}
		if err := unifiedinstall.PersistNativeRestorePhase(deadline, plan, "committed", nil, &restored); err != nil {
			return err
		}
		if err := json.NewEncoder(stdout).Encode(struct {
			BackupID       string `json:"backup_id"`
			AttemptID      string `json:"attempt_id"`
			SeedGeneration int64  `json:"seed_generation"`
		}{plan.BackupID, plan.AttemptID, restored.SeedGeneration}); err != nil {
			return err
		}
		return nil
	})
}

func runNativeSQLiteRestoreChild(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return errors.New("Native restore child accepts no arguments")
	}
	account, err := user.Lookup(install.AccountCore)
	if err != nil {
		return err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 || os.Getuid() != int(uid) || os.Geteuid() != int(uid) {
		return errors.New("Native restore child has wrong Core identity")
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || gid == 0 || os.Getgid() != int(gid) || os.Getegid() != int(gid) {
		return errors.New("Native restore child has wrong Core group")
	}
	parent, err := localpeer.AttestLinuxProcess(int32(os.Getppid()))
	if err != nil {
		return err
	}
	self, err := localpeer.AttestLinuxProcess(int32(os.Getpid()))
	if err != nil || parent.UID != 0 || parent.ExecutablePath != self.ExecutablePath || parent.ExecutableSHA256 != self.ExecutableSHA256 {
		return errors.New("Native restore child lacks fixed root parent")
	}
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 16<<10))
	decoder.DisallowUnknownFields()
	var request sqlite.NativeOfflineRestoreRequest
	if err := decoder.Decode(&request); err != nil || request.DataDirectory != install.UnifiedCoreDataDir || request.BackupDirectory != install.UnifiedBackupDir {
		return errors.New("Native restore child request is not fixed")
	}
	if err := unifiedinstall.CheckNativeCoreMaintenance(ctx); err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	receipt, err := sqlite.RestoreNativeOffline(ctx, request, unifiedinstall.CheckNativeCoreMaintenance, func(prepared sqlite.NativeOfflineRestorePrepared) error {
		if err := encoder.Encode(prepared); err != nil {
			return err
		}
		var approval struct {
			Commit bool `json:"commit"`
		}
		if err := decoder.Decode(&approval); err != nil || !approval.Commit {
			return errors.New("root quarantine phase approval absent")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := encoder.Encode(receipt); err != nil {
		return errors.Join(sqlite.ErrNativeRestoreOutcomeUnknown, err)
	}
	return nil
}
