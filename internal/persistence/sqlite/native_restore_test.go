package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeOfflineRestorePreservesFailureAndSeedsAboveLaunchFloor(t *testing.T) {
	ctx := context.Background()
	data := secureTestDir(t, "restore-data")
	backups := secureTestDir(t, "restore-backups")
	backupName := "backup-" + strings.Repeat("a", 32) + ".db"
	first, err := Open(Config{DataDirectory: data})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Backup(ctx, filepath.Join(backups, backupName)); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := Open(Config{DataDirectory: data})
	if err != nil {
		t.Fatal(err)
	}
	if next.CoreGeneration() != 2 {
		t.Fatalf("current generation=%d", next.CoreGeneration())
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	backupSHA, backupSize, err := nativeBackupDigest(filepath.Join(backups, backupName))
	if err != nil {
		t.Fatal(err)
	}
	oldDB := filepath.Join(data, "acornfox.db")
	before, err := nativeOwnerFile(oldDB)
	if err != nil {
		t.Fatal(err)
	}
	// Keep one idle SQLite connection open after a committed WAL write so
	// the failure phase must physically preserve all three original files.
	raw, err := sql.Open("sqlite", "file:"+url.PathEscape(oldDB)+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	raw.SetMaxOpenConns(1)
	if _, err := raw.Exec("PRAGMA wal_autocheckpoint=0"); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec("UPDATE core_generation SET generation=generation WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	originalDigests := map[string]string{}
	for _, name := range []string{"acornfox.db", "acornfox.db-wal", "acornfox.db-shm"} {
		sha, _, err := nativeBackupDigest(filepath.Join(data, name))
		if err != nil {
			t.Fatalf("missing real SQLite sidecar %s: %v", name, err)
		}
		originalDigests[name] = sha
	}
	request := NativeOfflineRestoreRequest{
		DataDirectory: data, BackupDirectory: backups, BackupName: backupName,
		AttemptID: strings.Repeat("b", 32), BackupSHA256: backupSHA, BackupSizeBytes: backupSize,
		BackupGeneration: 1, LaunchHighWater: 5, ExpectedPins: CompiledNativeMigrationPins(),
	}
	failure := errors.New("root phase journal unavailable")
	var prepared NativeOfflineRestorePrepared
	_, err = RestoreNativeOffline(ctx, request, func(context.Context) error { return nil }, func(p NativeOfflineRestorePrepared) error { prepared = p; return failure })
	if !errors.Is(err, ErrNativeRestoreOutcomeUnknown) || !errors.Is(err, failure) {
		t.Fatalf("pre-replace failure=%v", err)
	}
	after, err := nativeOwnerFile(oldDB)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("failed phase changed original DB identity", err)
	}
	if current, err := inspectCurrentRestoreGeneration(ctx, oldDB); err != nil || current != 2 {
		t.Fatalf("failed phase changed generation: %d %v", current, err)
	}
	if prepared.SeedGeneration != 5 || prepared.QuarantineDirectory != filepath.Join(backups, "quarantine-"+request.AttemptID) {
		t.Fatalf("missing quarantine proof: %+v", prepared)
	}
	for name, expected := range originalDigests {
		got, _, err := nativeBackupDigest(filepath.Join(data, name))
		if err != nil || got != expected {
			t.Fatalf("original %s changed before approval: %s %v", name, got, err)
		}
		copied, _, err := nativeBackupDigest(filepath.Join(prepared.QuarantineDirectory, name))
		if err != nil || copied != expected {
			t.Fatalf("quarantine %s digest differs: %s %v", name, copied, err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	request.AttemptID = strings.Repeat("c", 32)
	receipt, err := RestoreNativeOffline(ctx, request, func(context.Context) error { return nil }, func(p NativeOfflineRestorePrepared) error {
		if p.CurrentGeneration != 2 || p.SeedGeneration != 5 || p.SourceDBInode == 0 {
			t.Fatalf("bad approved phase: %+v", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.SeedGeneration != 5 || receipt.OriginalDBInode == 0 {
		t.Fatalf("restore receipt=%+v", receipt)
	}
	if current, err := inspectCurrentRestoreGeneration(ctx, oldDB); err != nil || current != 5 {
		t.Fatalf("restored seed=%d %v", current, err)
	}
	if _, err := nativeOwnerFile(filepath.Join(data, ".native-retired-"+request.AttemptID+"-acornfox.db")); err != nil {
		t.Fatal("retired original missing", err)
	}
	if _, err := nativeOwnerFile(filepath.Join(receipt.QuarantineDirectory, "acornfox.db")); err != nil {
		t.Fatal("quarantine original copy missing", err)
	}
	launched, err := Open(Config{DataDirectory: data, LaunchGeneration: 6})
	if err != nil {
		t.Fatal(err)
	}
	defer launched.Close()
	if launched.CoreGeneration() != 6 {
		t.Fatalf("restored launch reused high-water: %d", launched.CoreGeneration())
	}
}
