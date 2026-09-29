package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"golang.org/x/sys/unix"
)

var ErrNativeRestoreOutcomeUnknown = errors.New("Native SQLite restore outcome is unknown; preserve quarantine and keep Core stopped")
var nativeRestoreAttempt = regexp.MustCompile(`^[0-9a-f]{32}$`)
var nativeRestoreMigrationVersion = regexp.MustCompile(`^[0-9]{4}_[a-z0-9_]{1,64}$`)
var nativeRestoreHexSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)

type NativeOfflineRestoreRequest struct {
	DataDirectory, BackupDirectory, BackupName, AttemptID string
	BackupSHA256                                          string
	BackupSizeBytes, BackupGeneration, LaunchHighWater    int64
	ExpectedPins                                          []NativeMigrationPin
}

type NativeOfflineRestorePrepared struct {
	QuarantineDirectory string `json:"quarantine_directory"`
	CurrentGeneration   int64  `json:"current_generation"`
	SeedGeneration      int64  `json:"seed_generation"`
	SourceDBInode       uint64 `json:"source_db_inode"`
	BackupSHA256        string `json:"backup_sha256"`
}

type NativeOfflineRestoreReceipt struct {
	QuarantineDirectory string `json:"quarantine_directory"`
	RestoredDBSHA256    string `json:"restored_db_sha256"`
	SeedGeneration      int64  `json:"seed_generation"`
	OriginalDBInode     uint64 `json:"original_db_inode"`
}

// RestoreNativeOffline runs only as the fixed Core UID under the existing
// writer flock. approveReplacement must persist a root-owned quarantine phase
// before it sends approval; an error leaves the original names untouched.
func RestoreNativeOffline(ctx context.Context, req NativeOfflineRestoreRequest, maintenanceCheck func(context.Context) error, approveReplacement func(NativeOfflineRestorePrepared) error) (NativeOfflineRestoreReceipt, error) {
	var zero NativeOfflineRestoreReceipt
	if ctx == nil || maintenanceCheck == nil || approveReplacement == nil || !filepath.IsAbs(req.DataDirectory) || !filepath.IsAbs(req.BackupDirectory) || filepath.Clean(req.DataDirectory) != req.DataDirectory || filepath.Clean(req.BackupDirectory) != req.BackupDirectory || !nativeBackupName.MatchString(req.BackupName) || !nativeRestoreAttempt.MatchString(req.AttemptID) || len(req.BackupSHA256) != 64 || req.BackupSizeBytes <= 0 || req.BackupGeneration < 0 || req.LaunchHighWater < 0 {
		return zero, ErrIncompatibleSchema
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	// Restore the schema certified by the protected old-release receipt. A
	// newer updater may register additional migrations, but must not apply them
	// to a physical rollback image.
	if len(req.ExpectedPins) < 1 || len(req.ExpectedPins) > 64 {
		return zero, ErrIncompatibleSchema
	}
	previousVersion := ""
	for _, pin := range req.ExpectedPins {
		if !nativeRestoreMigrationVersion.MatchString(pin.Version) || pin.Version <= previousVersion || !nativeRestoreHexSHA.MatchString(pin.Checksum) {
			return zero, ErrIncompatibleSchema
		}
		previousVersion = pin.Version
	}
	pins := req.ExpectedPins
	if err := verifyTrustedDirectory(req.DataDirectory); err != nil {
		return zero, err
	}
	if err := verifyTrustedDirectory(req.BackupDirectory); err != nil {
		return zero, err
	}
	dbPath := filepath.Join(req.DataDirectory, "acornfox.db")
	backupPath := filepath.Join(req.BackupDirectory, req.BackupName)
	original, err := nativeOwnerFile(dbPath)
	if err != nil {
		return zero, err
	}
	lockPath := filepath.Join(req.DataDirectory, "acornfox.lock")
	if _, err := nativeOwnerFile(lockPath); err != nil {
		return zero, err
	}
	lockFD, err := unix.Open(lockPath, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return zero, err
	}
	defer unix.Close(lockFD)
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return zero, fmt.Errorf("%w: Core writer lock is not quiescent", ErrStoreLocked)
	}
	defer unix.Flock(lockFD, unix.LOCK_UN)
	if err := maintenanceCheck(ctx); err != nil {
		return zero, err
	}
	current, err := inspectCurrentRestoreGeneration(ctx, dbPath)
	if err != nil {
		return zero, err
	}
	lockedOriginal, err := nativeOwnerFile(dbPath)
	if err != nil || !os.SameFile(original, lockedOriginal) {
		return zero, ErrCorruptData
	}
	sourceFiles := map[string]os.FileInfo{"acornfox.db": lockedOriginal}
	for _, suffix := range []string{"-wal", "-shm"} {
		info, sidecarErr := nativeOwnerFile(dbPath + suffix)
		if sidecarErr == nil {
			sourceFiles["acornfox.db"+suffix] = info
		} else if !os.IsNotExist(sidecarErr) {
			return zero, sidecarErr
		}
	}
	seed := current
	if req.BackupGeneration > seed {
		seed = req.BackupGeneration
	}
	if req.LaunchHighWater > seed {
		seed = req.LaunchHighWater
	}
	if seed < 0 || seed >= 9223372036854775806 {
		return zero, ErrIncompatibleSchema
	}
	backupSHA, backupSize, err := nativeBackupDigest(backupPath)
	if err != nil || backupSHA != req.BackupSHA256 || backupSize != req.BackupSizeBytes {
		return zero, errors.Join(ErrIncompatibleSchema, err)
	}
	backupInfo, err := nativeOwnerFile(backupPath)
	if err != nil {
		return zero, err
	}
	backupDB, err := sql.Open("sqlite", "file:"+url.PathEscape(backupPath)+"?mode=ro&_pragma=query_only(ON)")
	if err != nil {
		return zero, err
	}
	backupDB.SetMaxOpenConns(1)
	backupGeneration, inspectErr := inspectNativeDatabase(ctx, backupDB, pins)
	closeErr := backupDB.Close()
	if inspectErr != nil || closeErr != nil || backupGeneration != req.BackupGeneration {
		return zero, errors.Join(ErrIncompatibleSchema, inspectErr, closeErr)
	}
	quarantine := filepath.Join(req.BackupDirectory, "quarantine-"+req.AttemptID)
	if err := os.Mkdir(quarantine, 0700); err != nil {
		return zero, err
	}
	// From here, preserve the new quarantine and report uncertain completion.
	unknown := func(err error) (NativeOfflineRestoreReceipt, error) {
		return zero, errors.Join(ErrNativeRestoreOutcomeUnknown, err)
	}
	if err := syncRestoreDirectory(req.BackupDirectory); err != nil {
		return unknown(err)
	}
	copiedSHA := make(map[string]string, len(sourceFiles))
	for name, info := range sourceFiles {
		copySHA, err := copyNativeRestoreFile(ctx, filepath.Join(req.DataDirectory, name), filepath.Join(quarantine, name), info)
		if err != nil {
			return unknown(err)
		}
		copiedSHA[name] = copySHA
	}
	if _, err := copyNativeRestoreFile(ctx, backupPath, filepath.Join(quarantine, "work.db"), backupInfo); err != nil {
		return unknown(err)
	}
	if err := syncRestoreDirectory(quarantine); err != nil {
		return unknown(err)
	}
	workPath := filepath.Join(quarantine, "work.db")
	if workSHA, workSize, err := nativeBackupDigest(workPath); err != nil || workSHA != req.BackupSHA256 || workSize != req.BackupSizeBytes {
		return unknown(errors.Join(ErrIncompatibleSchema, err))
	}
	work, err := sql.Open("sqlite", "file:"+url.PathEscape(workPath)+"?_pragma=foreign_keys(ON)")
	if err != nil {
		return unknown(err)
	}
	work.SetMaxOpenConns(1)
	if previous, err := inspectNativeDatabase(ctx, work, pins); err != nil || previous != req.BackupGeneration {
		work.Close()
		return unknown(errors.Join(ErrIncompatibleSchema, err))
	}
	tx, err := work.BeginTx(ctx, nil)
	if err != nil {
		work.Close()
		return unknown(err)
	}
	var seeded int64
	err = tx.QueryRowContext(ctx, `UPDATE core_generation SET generation=? WHERE singleton=1 AND generation<=? RETURNING generation`, seed, seed).Scan(&seeded)
	if err != nil || seeded != seed {
		tx.Rollback()
		work.Close()
		return unknown(errors.Join(ErrIncompatibleSchema, err))
	}
	if err := tx.Commit(); err != nil {
		work.Close()
		return unknown(err)
	}
	candidate := filepath.Join(req.DataDirectory, ".native-restore-"+req.AttemptID+".db")
	if err := backupSQLiteConnection(ctx, work, workPath, candidate); err != nil {
		work.Close()
		return unknown(err)
	}
	if err := work.Close(); err != nil {
		return unknown(err)
	}
	candidateDB, err := sql.Open("sqlite", "file:"+url.PathEscape(candidate)+"?mode=ro&_pragma=query_only(ON)")
	if err != nil {
		return unknown(err)
	}
	candidateDB.SetMaxOpenConns(1)
	gotSeed, verifyErr := inspectNativeDatabase(ctx, candidateDB, pins)
	closeErr = candidateDB.Close()
	if verifyErr != nil || closeErr != nil || gotSeed != seed {
		return unknown(errors.Join(ErrIncompatibleSchema, verifyErr, closeErr))
	}
	candidateSHA, _, err := nativeBackupDigest(candidate)
	if err != nil {
		return unknown(err)
	}
	prepared := NativeOfflineRestorePrepared{quarantine, current, seed, original.Sys().(*syscall.Stat_t).Ino, req.BackupSHA256}
	if err := approveReplacement(prepared); err != nil {
		return unknown(err)
	}
	if err := ctx.Err(); err != nil {
		return unknown(err)
	}
	if err := maintenanceCheck(ctx); err != nil {
		return unknown(err)
	}
	if again, err := inspectCurrentRestoreGeneration(ctx, dbPath); err != nil || again != current {
		return unknown(errors.Join(ErrIncompatibleSchema, err))
	}
	for name, info := range sourceFiles {
		again, err := nativeOwnerFile(filepath.Join(req.DataDirectory, name))
		if err != nil || !os.SameFile(info, again) {
			return unknown(ErrCorruptData)
		}
		actualSHA, _, err := nativeBackupDigest(filepath.Join(req.DataDirectory, name))
		if err != nil || actualSHA != copiedSHA[name] {
			return unknown(errors.Join(ErrCorruptData, err))
		}
	}
	for _, name := range []string{"acornfox.db-wal", "acornfox.db-shm"} {
		if _, known := sourceFiles[name]; !known {
			if _, statErr := os.Lstat(filepath.Join(req.DataDirectory, name)); !os.IsNotExist(statErr) {
				return unknown(ErrCorruptData)
			}
		}
	}
	if actualSHA, _, err := nativeBackupDigest(candidate); err != nil || actualSHA != candidateSHA {
		return unknown(errors.Join(ErrCorruptData, err))
	}
	// All destinations are same-directory and no-replace. On any interruption
	// originals survive as retired names and as fsynced quarantine copies.
	for _, name := range []string{"acornfox.db-wal", "acornfox.db-shm", "acornfox.db"} {
		if _, exists := sourceFiles[name]; !exists {
			continue
		}
		src := filepath.Join(req.DataDirectory, name)
		retired := filepath.Join(req.DataDirectory, ".native-retired-"+req.AttemptID+"-"+name)
		if err := moveNativeRestoreNoReplace(src, retired); err != nil {
			return unknown(err)
		}
		if err := syncRestoreDirectory(req.DataDirectory); err != nil {
			return unknown(err)
		}
	}
	if err := moveNativeRestoreNoReplace(candidate, dbPath); err != nil {
		return unknown(err)
	}
	if err := syncRestoreDirectory(req.DataDirectory); err != nil {
		return unknown(err)
	}
	final, err := sql.Open("sqlite", "file:"+url.PathEscape(dbPath)+"?mode=ro&_pragma=query_only(ON)")
	if err != nil {
		return unknown(err)
	}
	final.SetMaxOpenConns(1)
	actual, verifyErr := inspectNativeDatabase(ctx, final, pins)
	closeErr = final.Close()
	if verifyErr != nil || closeErr != nil || actual != seed {
		return unknown(errors.Join(ErrIncompatibleSchema, verifyErr, closeErr))
	}
	if finalSHA, _, err := nativeBackupDigest(dbPath); err != nil || finalSHA != candidateSHA {
		return unknown(errors.Join(ErrCorruptData, err))
	}
	if err := maintenanceCheck(ctx); err != nil {
		return unknown(err)
	}
	if err := ctx.Err(); err != nil {
		return unknown(err)
	}
	return NativeOfflineRestoreReceipt{quarantine, candidateSHA, seed, prepared.SourceDBInode}, nil
}

func inspectCurrentRestoreGeneration(ctx context.Context, path string) (int64, error) {
	db, err := sql.Open("sqlite", "file:"+url.PathEscape(path)+"?mode=ro&_pragma=query_only(ON)")
	if err != nil {
		return 0, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var generation int64
	if err := db.QueryRowContext(ctx, `SELECT generation FROM core_generation WHERE singleton=1`).Scan(&generation); err != nil || generation < 0 {
		return 0, ErrIncompatibleSchema
	}
	var integrity string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		return 0, ErrCorruptData
	}
	return generation, nil
}

func copyNativeRestoreFile(ctx context.Context, source, target string, before os.FileInfo) (string, error) {
	if before == nil {
		return "", ErrCorruptData
	}
	input, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer input.Close()
	opened, err := input.Stat()
	if err != nil || !os.SameFile(before, opened) || before.Size() != opened.Size() || !before.ModTime().Equal(opened.ModTime()) {
		return "", ErrCorruptData
	}
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(output, hash), contextRestoreReader{ctx, input})
	syncErr := output.Sync()
	closeErr := output.Close()
	closeInputErr := input.Close()
	after, statErr := os.Lstat(source)
	if copyErr != nil || syncErr != nil || closeErr != nil || closeInputErr != nil || statErr != nil || !os.SameFile(before, after) || n != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return "", errors.Join(ErrCorruptData, copyErr, syncErr, closeErr, closeInputErr, statErr)
	}
	streamSHA := hex.EncodeToString(hash.Sum(nil))
	sourceSHA, sourceSize, err := nativeBackupDigest(source)
	if err != nil || sourceSHA != streamSHA || sourceSize != n {
		return "", errors.Join(ErrCorruptData, err)
	}
	targetSHA, targetSize, err := nativeBackupDigest(target)
	if err != nil || targetSHA != streamSHA || targetSize != n {
		return "", errors.Join(ErrCorruptData, err)
	}
	return streamSHA, nil
}

type contextRestoreReader struct {
	ctx   context.Context
	input io.Reader
}

func (r contextRestoreReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.input.Read(p)
}

func syncRestoreDirectory(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	syncErr := unix.Fsync(fd)
	closeErr := unix.Close(fd)
	return errors.Join(syncErr, closeErr)
}

// The destination link is exclusive; after unlinking the old name the inode
// stays preserved at its retired name. Quarantine itself is an independent
// fsynced byte copy, never a hardlink.
func moveNativeRestoreNoReplace(source, target string) error {
	if filepath.Dir(source) != filepath.Dir(target) {
		return ErrIncompatibleSchema
	}
	if err := os.Link(source, target); err != nil {
		return err
	}
	if err := os.Remove(source); err != nil {
		return err
	}
	return nil
}
