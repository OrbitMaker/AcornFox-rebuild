package unifiedinstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/open-card/open-card/internal/artifactio"
	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/persistence/sqlite"
)

const nativeBackupReceiptDir = "backup-receipts"

var nativeBackupID = regexp.MustCompile(`^backup-[0-9a-f]{32}$`)
var nativeHexSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)
var nativeSourceCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)
var nativeMigrationVersion = regexp.MustCompile(`^[0-9]{4}_[a-z0-9_]{1,64}$`)
var ErrNativeBackupReceiptUnknown = errors.New("protected Native backup receipt outcome is unknown")

// NativeBackupProtectedReceipt is durable root-owned restore input, never a
// caller-supplied arbitrary path or a copied CLI stdout document.
type NativeBackupProtectedReceipt struct {
	SchemaVersion  int                               `json:"schema_version"`
	BackupID       string                            `json:"backup_id"`
	InstallationID string                            `json:"installation_id"`
	ReleaseID      string                            `json:"release_id"`
	SourceCommit   string                            `json:"source_commit"`
	ManifestSHA256 string                            `json:"manifest_sha256"`
	Backup         sqlite.NativeOfflineBackupReceipt `json:"backup"`
}

func (r NativeBackupProtectedReceipt) validate(backupDirectory string) error {
	if r.SchemaVersion != 1 || !nativeBackupID.MatchString(r.BackupID) || len(r.InstallationID) < 8 || len(r.InstallationID) > 128 || strings.ContainsAny(r.InstallationID, "/\\\x00 \t\r\n") || r.ReleaseID == "" || !nativeSourceCommit.MatchString(r.SourceCommit) || !nativeHexSHA.MatchString(r.ManifestSHA256) || !nativeHexSHA.MatchString(r.Backup.SHA256) || r.Backup.SizeBytes <= 0 || r.Backup.SourceDBInode == 0 || r.Backup.Generation < 0 || len(r.Backup.Migrations) < 1 || len(r.Backup.Migrations) > 64 || r.Backup.BackupPath != filepath.Join(backupDirectory, r.BackupID+".db") {
		return ErrIncomplete
	}
	if _, err := install.ReleaseDirectory(install.UnifiedReleasesDir, r.ReleaseID); err != nil {
		return ErrIncomplete
	}
	previous := ""
	for _, pin := range r.Backup.Migrations {
		if !nativeMigrationVersion.MatchString(pin.Version) || pin.Version <= previous || !nativeHexSHA.MatchString(pin.Checksum) {
			return ErrIncomplete
		}
		previous = pin.Version
	}
	return nil
}

// SaveNativeBackupReceipt is called only after the Core-UID child has returned
// a verified backup. Any failure is unknown for the *already existing backup*;
// neither backup nor a possibly published receipt is removed automatically.
func SaveNativeBackupReceipt(ctx context.Context, plan NativeSQLiteBackupPlan, backup sqlite.NativeOfflineBackupReceipt) (NativeBackupProtectedReceipt, error) {
	var zero NativeBackupProtectedReceipt
	if ctx == nil || os.Geteuid() != 0 || os.Getegid() != 0 || plan.InstallationID == "" || plan.Request.BackupDirectory != install.UnifiedBackupDir || plan.Request.DataDirectory != install.UnifiedCoreDataDir || backup.BackupPath != filepath.Join(plan.Request.BackupDirectory, plan.Request.BackupName) {
		return zero, ErrIncomplete
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	var currentInstallation struct {
		ID string `json:"installation_id"`
	}
	if err := readProtectedPublisherJSON(UnifiedInstallationIDPath, 1024, &currentInstallation); err != nil || currentInstallation.ID != plan.InstallationID {
		return zero, errors.Join(ErrNativeBackupReceiptUnknown, err)
	}
	id, err := nativeBackupReceiptID(plan.Request.BackupName)
	if err != nil {
		return zero, err
	}
	receipt := NativeBackupProtectedReceipt{SchemaVersion: 1, BackupID: id, InstallationID: plan.InstallationID, ReleaseID: plan.ReleaseID, SourceCommit: plan.SourceCommit, ManifestSHA256: plan.ManifestSHA256, Backup: backup}
	if err := receipt.validate(install.UnifiedBackupDir); err != nil {
		return zero, err
	}
	if !matchesNativeBackupPins(plan.Request.ExpectedPins, backup.Migrations) {
		return zero, ErrIncomplete
	}
	if err := verifyRootRunAncestor(install.UnifiedBackupDir); err != nil {
		return zero, errors.Join(ErrNativeBackupReceiptUnknown, err)
	}
	if err := verifyNativeBackupFile(ctx, backup.BackupPath, int(plan.CoreUID), int(plan.CoreGID), backup); err != nil {
		return zero, errors.Join(ErrNativeBackupReceiptUnknown, err)
	}
	if err := verifyRootRunAncestor(UnifiedPrivateStageRoot); err != nil {
		return zero, errors.Join(ErrNativeBackupReceiptUnknown, err)
	}
	if err := saveNativeBackupReceiptAt(ctx, UnifiedPrivateStageRoot, 0, 0, receipt, nil); err != nil {
		return zero, errors.Join(ErrNativeBackupReceiptUnknown, err)
	}
	return receipt, nil
}

// ReadNativeBackupReceipt resolves only a fixed safe ID in the private root.
// The backup bytes are rehashed before returning this authority to restore.
func ReadNativeBackupReceipt(ctx context.Context, id string) (NativeBackupProtectedReceipt, error) {
	var zero NativeBackupProtectedReceipt
	if ctx == nil || os.Geteuid() != 0 || os.Getegid() != 0 || !nativeBackupID.MatchString(id) {
		return zero, ErrIncomplete
	}
	account, err := user.Lookup(install.AccountCore)
	if err != nil {
		return zero, err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid <= 0 {
		return zero, ErrIncomplete
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil || gid <= 0 {
		return zero, ErrIncomplete
	}
	if err := verifyRootRunAncestor(UnifiedPrivateStageRoot); err != nil {
		return zero, err
	}
	receipt, err := readNativeBackupReceiptAt(ctx, UnifiedPrivateStageRoot, 0, 0, install.UnifiedBackupDir, id)
	if err != nil {
		return zero, err
	}
	if err := verifyRootRunAncestor(install.UnifiedBackupDir); err != nil {
		return zero, err
	}
	if err := verifyNativeBackupFile(ctx, receipt.Backup.BackupPath, uid, gid, receipt.Backup); err != nil {
		return zero, err
	}
	var currentInstallation struct {
		ID string `json:"installation_id"`
	}
	if err := readProtectedPublisherJSON(UnifiedInstallationIDPath, 1024, &currentInstallation); err != nil || currentInstallation.ID != receipt.InstallationID {
		return zero, ErrIncomplete
	}
	return receipt, nil
}

// afterPublish is a narrow test seam for a failure after no-replace commit.
func saveNativeBackupReceiptAt(ctx context.Context, privateRoot string, uid, gid int, receipt NativeBackupProtectedReceipt, afterPublish func() error) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	writer, err := artifactio.NewDurableWriter(privateRoot, uid, gid)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := writer.Close(); closeErr != nil {
			err = errors.Join(err, ErrNativeBackupReceiptUnknown, closeErr)
		}
	}()
	if writer.RootInfo().Mode().Perm() != 0700 {
		return ErrIncomplete
	}
	if _, err := writer.CreateChildDirectory(nativeBackupReceiptDir, 0700); err != nil {
		return err
	}
	child, err := writer.OpenChildWriter(nativeBackupReceiptDir, 0700)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := child.Close(); closeErr != nil {
			err = errors.Join(err, ErrNativeBackupReceiptUnknown, closeErr)
		}
	}()
	raw, err := json.Marshal(receipt)
	if err != nil || len(raw) > 16<<10 {
		return ErrIncomplete
	}
	name := receipt.BackupID + ".json"
	if err := child.CreateMetadata(name, raw); err != nil {
		return err
	}
	if afterPublish != nil {
		if err := afterPublish(); err != nil {
			return errors.Join(ErrNativeBackupReceiptUnknown, err)
		}
	}
	readback, err := child.ReadMetadata(name)
	if err != nil || !bytes.Equal(readback, raw) {
		return errors.Join(ErrNativeBackupReceiptUnknown, err)
	}
	return nil
}

func readNativeBackupReceiptAt(ctx context.Context, privateRoot string, uid, gid int, backupDirectory, id string) (NativeBackupProtectedReceipt, error) {
	var zero NativeBackupProtectedReceipt
	if ctx == nil || !nativeBackupID.MatchString(id) {
		return zero, ErrIncomplete
	}
	writer, err := artifactio.NewDurableWriter(privateRoot, uid, gid)
	if err != nil {
		return zero, err
	}
	defer writer.Close()
	if writer.RootInfo().Mode().Perm() != 0700 {
		return zero, ErrIncomplete
	}
	child, err := writer.OpenChildWriter(nativeBackupReceiptDir, 0700)
	if err != nil {
		return zero, err
	}
	defer child.Close()
	raw, err := child.ReadMetadata(id + ".json")
	if err != nil || len(raw) < 1 || len(raw) > 16<<10 {
		return zero, ErrIncomplete
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt NativeBackupProtectedReceipt
	if decoder.Decode(&receipt) != nil || decoder.Decode(&struct{}{}) != io.EOF || receipt.BackupID != id || receipt.validate(backupDirectory) != nil {
		return zero, ErrIncomplete
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	return receipt, nil
}

func verifyNativeBackupFile(ctx context.Context, path string, uid, gid int, expected sqlite.NativeOfflineBackupReceipt) error {
	if ctx == nil || path != expected.BackupPath {
		return ErrIncomplete
	}
	directory, err := os.Lstat(filepath.Dir(path))
	if err != nil || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 || directory.Mode().Perm() != 0700 || artifactio.CheckFileOwner(directory, uid, gid) != nil {
		return ErrIncomplete
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() != expected.SizeBytes || artifactio.CheckFileOwner(before, uid, gid) != nil {
		return ErrIncomplete
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return ErrIncomplete
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	hash := sha256.New()
	n, readErr := io.Copy(hash, contextReader{ctx, io.LimitReader(file, expected.SizeBytes+1)})
	closeErr := file.Close()
	after, statErr := os.Lstat(path)
	if readErr != nil || closeErr != nil || statErr != nil || !os.SameFile(before, after) || artifactio.CheckFileOwner(after, uid, gid) != nil || n != expected.SizeBytes || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
		return ErrIncomplete
	}
	return nil
}

func nativeBackupReceiptID(backupName string) (string, error) {
	if !filepath.IsAbs(backupName) && filepath.Base(backupName) == backupName && len(backupName) > len(".db") {
		id := backupName[:len(backupName)-len(".db")]
		if nativeBackupID.MatchString(id) && backupName == id+".db" {
			return id, nil
		}
	}
	return "", fmt.Errorf("%w: invalid Native backup ID", ErrIncomplete)
}

func matchesNativeBackupPins(expected, actual []sqlite.NativeMigrationPin) bool {
	if len(expected) == 0 || len(expected) != len(actual) {
		return false
	}
	for index := range actual {
		if expected[index] != actual[index] {
			return false
		}
	}
	return true
}
