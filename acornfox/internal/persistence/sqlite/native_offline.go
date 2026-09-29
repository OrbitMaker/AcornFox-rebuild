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

type NativeMigrationPin struct{ Version, Checksum string }

// CompiledNativeMigrationPins derives checksums from the exact registered
// migrations, including the finite Source and domain additions.
func CompiledNativeMigrationPins() []NativeMigrationPin {
	return []NativeMigrationPin{
		{version0001_admin_auth, sha256Hex(authMigrationSQL())},
		{version0002_application_repository, sha256Hex(applicationMigrationSQL())},
		{version0003_task_fencing, sha256Hex(taskMigrationSQL())},
		{version0004_audit_evidence, sha256Hex(auditMigrationSQL())},
		{version0005_pack_intents, sha256Hex(packMigrationSQL())},
		{version0006_pack_protocol_execution, sha256Hex(packExecutionMigrationSQL())},
		{version0007_pack_artifact_staging, sha256Hex(packLifecycleMigrationSQL())},
		{version0008_pack_activation, sha256Hex(packActivationMigrationSQL())},
		{version0009_image_delivery, sha256Hex(imageDeliveryMigrationSQL())},
		{version0010_image_execution, sha256Hex(imageExecutionMigrationSQL())},
		{version0011_image_lifecycle, sha256Hex(imageLifecycleMigrationSQL())},
		{version0012_source_build, sha256Hex(sourceBuildSchemaSQL)},
		{version0013_image_public_access, sha256Hex(imagePublicAccessSchemaSQL)},
	}
}

type NativeOfflineBackupRequest struct {
	DataDirectory, BackupDirectory, BackupName string
	ExpectedPins                               []NativeMigrationPin
}

type NativeOfflineBackupReceipt struct {
	BackupPath    string               `json:"backup_path"`
	SHA256        string               `json:"sha256"`
	SizeBytes     int64                `json:"size_bytes"`
	SourceDBInode uint64               `json:"source_db_inode"`
	Generation    int64                `json:"generation"`
	Migrations    []NativeMigrationPin `json:"migrations"`
}

var nativeBackupName = regexp.MustCompile(`^backup-[a-z0-9-]{8,80}\.db$`)
var ErrNativeBackupOutcomeUnknown = errors.New("Native SQLite backup outcome is unknown")

// BackupNativeOffline is called by the fixed Core-UID child only. It never
// calls Store.Open, executes migrations, or advances core_generation.
func BackupNativeOffline(ctx context.Context, req NativeOfflineBackupRequest, maintenanceCheck func(context.Context) error) (NativeOfflineBackupReceipt, error) {
	var zero NativeOfflineBackupReceipt
	if ctx == nil || maintenanceCheck == nil || !filepath.IsAbs(req.DataDirectory) || !filepath.IsAbs(req.BackupDirectory) || filepath.Clean(req.DataDirectory) != req.DataDirectory || filepath.Clean(req.BackupDirectory) != req.BackupDirectory || !nativeBackupName.MatchString(req.BackupName) {
		return zero, ErrIncompatibleSchema
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	compiled := CompiledNativeMigrationPins()
	if len(req.ExpectedPins) != len(compiled) {
		return zero, ErrIncompatibleSchema
	}
	for index := range compiled {
		if req.ExpectedPins[index] != compiled[index] {
			return zero, ErrIncompatibleSchema
		}
	}
	if err := verifyTrustedDirectory(req.DataDirectory); err != nil {
		return zero, err
	}
	if err := verifyTrustedDirectory(req.BackupDirectory); err != nil {
		return zero, err
	}
	dbPath := filepath.Join(req.DataDirectory, "acornfox.db")
	before, err := nativeOwnerFile(dbPath)
	if err != nil {
		return zero, err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		path := dbPath + suffix
		if _, err := nativeOwnerFile(path); err != nil && !os.IsNotExist(err) {
			return zero, err
		}
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
		return zero, fmt.Errorf("%w: writer lock is not quiescent: %v", ErrStoreLocked, err)
	}
	defer unix.Flock(lockFD, unix.LOCK_UN)
	if err := maintenanceCheck(ctx); err != nil {
		return zero, err
	}
	db, err := sql.Open("sqlite", "file:"+url.PathEscape(dbPath)+"?_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)")
	if err != nil {
		return zero, err
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	generation, err := inspectNativeDatabase(ctx, db, compiled)
	if err != nil {
		return zero, err
	}
	dest := filepath.Join(req.BackupDirectory, req.BackupName)
	if _, statErr := os.Lstat(dest); statErr == nil {
		return zero, ErrIncompatibleSchema
	} else if !os.IsNotExist(statErr) {
		return zero, statErr
	}
	if err := backupSQLiteConnection(ctx, db, dbPath, dest); err != nil {
		if _, statErr := os.Lstat(dest); !os.IsNotExist(statErr) {
			return zero, errors.Join(ErrNativeBackupOutcomeUnknown, err, statErr)
		}
		return zero, err
	}
	backup, err := sql.Open("sqlite", "file:"+url.PathEscape(dest)+"?mode=ro&_pragma=foreign_keys(ON)")
	if err != nil {
		return zero, errors.Join(ErrNativeBackupOutcomeUnknown, err)
	}
	backup.SetMaxOpenConns(1)
	verifiedGeneration, verifyErr := inspectNativeDatabase(ctx, backup, compiled)
	closeErr := backup.Close()
	if verifyErr != nil || closeErr != nil || verifiedGeneration != generation {
		return zero, errors.Join(ErrNativeBackupOutcomeUnknown, verifyErr, closeErr, ErrCorruptData)
	}
	sha, size, err := nativeBackupDigest(dest)
	if err != nil {
		return zero, errors.Join(ErrNativeBackupOutcomeUnknown, err)
	}
	after, err := nativeOwnerFile(dbPath)
	if err != nil || !os.SameFile(before, after) {
		return zero, errors.Join(ErrNativeBackupOutcomeUnknown, ErrCorruptData, err)
	}
	if again, err := inspectNativeDatabase(ctx, db, compiled); err != nil || again != generation {
		return zero, errors.Join(ErrNativeBackupOutcomeUnknown, ErrCorruptData, err)
	}
	if err := maintenanceCheck(ctx); err != nil {
		return zero, errors.Join(ErrNativeBackupOutcomeUnknown, err)
	}
	if err := ctx.Err(); err != nil {
		return zero, errors.Join(ErrNativeBackupOutcomeUnknown, err)
	}
	stat := before.Sys().(*syscall.Stat_t)
	return NativeOfflineBackupReceipt{BackupPath: dest, SHA256: sha, SizeBytes: size, SourceDBInode: stat.Ino, Generation: generation, Migrations: append([]NativeMigrationPin(nil), compiled...)}, nil
}

func nativeOwnerFile(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, ErrCorruptData
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() || stat.Nlink != 1 {
		return nil, ErrCorruptData
	}
	return info, nil
}

func inspectNativeDatabase(ctx context.Context, db *sql.DB, pins []NativeMigrationPin) (int64, error) {
	rows, err := db.QueryContext(ctx, `SELECT version,checksum FROM _schema_migrations ORDER BY version`)
	if err != nil {
		return 0, err
	}
	index := 0
	for rows.Next() {
		var version, checksum string
		if rows.Scan(&version, &checksum) != nil || index >= len(pins) || pins[index] != (NativeMigrationPin{version, checksum}) {
			_ = rows.Close()
			return 0, ErrIncompatibleSchema
		}
		index++
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil || closeErr != nil || index != len(pins) {
		return 0, errors.Join(err, closeErr, ErrIncompatibleSchema)
	}
	var generation int64
	if err := db.QueryRowContext(ctx, `SELECT generation FROM core_generation WHERE singleton=1`).Scan(&generation); err != nil || generation < 0 {
		return 0, ErrIncompatibleSchema
	}
	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return 0, ErrCorruptData
	}
	fk, err := db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return 0, err
	}
	violation := fk.Next()
	err = fk.Err()
	closeErr = fk.Close()
	if violation || err != nil || closeErr != nil {
		return 0, errors.Join(err, closeErr, ErrCorruptData)
	}
	return generation, nil
}

func nativeBackupDigest(path string) (string, int64, error) {
	info, err := nativeOwnerFile(path)
	if err != nil {
		return "", 0, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", 0, err
	}
	hash := sha256.New()
	n, readErr := io.Copy(hash, file)
	closeErr := file.Close()
	after, statErr := os.Lstat(path)
	if readErr != nil || closeErr != nil || statErr != nil || !os.SameFile(info, after) || n != info.Size() {
		return "", 0, ErrCorruptData
	}
	return hex.EncodeToString(hash.Sum(nil)), n, nil
}
