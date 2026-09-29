package unifiedinstall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/persistence/sqlite"
)

func TestNativeBackupReceiptNoReplaceAndPostCommitUncertainty(t *testing.T) {
	ctx := context.Background()
	root, backups := t.TempDir(), t.TempDir()
	for _, path := range []string{root, backups} {
		if err := os.Chmod(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	id := "backup-" + strings.Repeat("a", 32)
	receipt := NativeBackupProtectedReceipt{SchemaVersion: 1, BackupID: id, InstallationID: "fixture-installation", ReleaseID: "release-1.0.0", SourceCommit: strings.Repeat("b", 40), ManifestSHA256: strings.Repeat("c", 64), Backup: sqlite.NativeOfflineBackupReceipt{BackupPath: filepath.Join(backups, id+".db"), SHA256: strings.Repeat("d", 64), SizeBytes: 123, SourceDBInode: 42, Generation: 5, Migrations: sqlite.CompiledNativeMigrationPins()}}
	uid, gid := os.Getuid(), os.Getgid()
	if err := saveNativeBackupReceiptAt(ctx, root, uid, gid, receipt, nil); err != nil {
		t.Fatal(err)
	}
	read, err := readNativeBackupReceiptAt(ctx, root, uid, gid, backups, id)
	if err != nil || !reflect.DeepEqual(read, receipt) {
		t.Fatal("fixed-ID protected receipt did not reread", err)
	}
	changed := receipt
	changed.SourceCommit = strings.Repeat("e", 40)
	if err := saveNativeBackupReceiptAt(ctx, root, uid, gid, changed, nil); err == nil {
		t.Fatal("duplicate receipt replaced committed bytes")
	}
	read, err = readNativeBackupReceiptAt(ctx, root, uid, gid, backups, id)
	if err != nil || !reflect.DeepEqual(read, receipt) {
		t.Fatal("duplicate changed the protected receipt", err)
	}
	other := receipt
	other.BackupID = "backup-" + strings.Repeat("f", 32)
	other.Backup.BackupPath = filepath.Join(backups, other.BackupID+".db")
	fault := errors.New("post-publication readback unavailable")
	if err := saveNativeBackupReceiptAt(ctx, root, uid, gid, other, func() error { return fault }); !errors.Is(err, ErrNativeBackupReceiptUnknown) || !errors.Is(err, fault) {
		t.Fatal("post-effect receipt failure was not marked unknown", err)
	}
	read, err = readNativeBackupReceiptAt(ctx, root, uid, gid, backups, other.BackupID)
	if err != nil || !reflect.DeepEqual(read, other) {
		t.Fatal("unknown publication deleted the committed receipt", err)
	}
	future := receipt
	future.BackupID = "backup-" + strings.Repeat("2", 32)
	future.Backup.BackupPath = filepath.Join(backups, future.BackupID+".db")
	future.Backup.Migrations = append(append([]sqlite.NativeMigrationPin(nil), receipt.Backup.Migrations...), sqlite.NativeMigrationPin{Version: "0014_unknown", Checksum: strings.Repeat("3", 64)})
	if matchesNativeBackupPins(receipt.Backup.Migrations, future.Backup.Migrations) {
		t.Fatal("backup with pins beyond the approved plan could be published")
	}
	if err := saveNativeBackupReceiptAt(ctx, root, uid, gid, future, nil); err != nil {
		t.Fatal(err)
	}
	read, err = readNativeBackupReceiptAt(ctx, root, uid, gid, backups, future.BackupID)
	if err != nil || !reflect.DeepEqual(read, future) {
		t.Fatal("structurally valid older/future pin count could not be read", err)
	}
	invalid := future
	invalid.Backup.Migrations = append([]sqlite.NativeMigrationPin(nil), future.Backup.Migrations...)
	invalid.Backup.Migrations[len(invalid.Backup.Migrations)-1].Version = invalid.Backup.Migrations[len(invalid.Backup.Migrations)-2].Version
	if invalid.validate(backups) == nil {
		t.Fatal("duplicate unordered migration version accepted")
	}
}
