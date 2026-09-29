package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeOfflineBackupIncludesCommittedWALWithoutOpeningStore(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	data, backups := filepath.Join(root, "core"), filepath.Join(root, "backups")
	for _, path := range []string{data, backups} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	store, err := Open(Config{DataDirectory: data, DBName: "acornfox.db"})
	if err != nil {
		t.Fatal(err)
	}
	request := NativeOfflineBackupRequest{DataDirectory: data, BackupDirectory: backups, BackupName: "backup-wal-committed.db", ExpectedPins: CompiledNativeMigrationPins()}
	checkCount := 0
	check := func(context.Context) error { checkCount++; return nil }
	if _, err := BackupNativeOffline(ctx, request, check); !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("active Store writer lock was accepted: %v", err)
	}
	before := store.CoreGeneration()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(data, "acornfox.db")
	db, err := sql.Open("sqlite", "file:"+url.PathEscape(dbPath)+"?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	now := FormatTime(time.Now().UTC())
	if _, err := db.ExecContext(ctx, `INSERT INTO idempotency_records(scope,idempotency_key,request_digest,status,created_at,updated_at) VALUES('native-fixture','wal-committed','digest','in_progress',?,?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(dbPath + "-wal"); err != nil || info.Size() == 0 {
		t.Fatal("fixture did not retain committed WAL", err)
	}
	receipt, err := BackupNativeOffline(ctx, request, check)
	if err != nil {
		t.Fatal(err)
	}
	if checkCount != 2 || receipt.Generation != before || receipt.SizeBytes <= 0 || len(receipt.SHA256) != 64 {
		t.Fatal("backup changed generation or skipped maintenance fences")
	}
	var after int64
	if err := db.QueryRowContext(ctx, `SELECT generation FROM core_generation WHERE singleton=1`).Scan(&after); err != nil || after != before {
		t.Fatal("offline backup changed source generation", err)
	}
	backup, err := sql.Open("sqlite", "file:"+url.PathEscape(receipt.BackupPath)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	var count int
	if err := backup.QueryRowContext(ctx, `SELECT count(*) FROM idempotency_records WHERE scope='native-fixture' AND idempotency_key='wal-committed'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("committed WAL row absent from consistent backup", err)
	}
	if _, err := BackupNativeOffline(ctx, request, check); err == nil {
		t.Fatal("existing backup destination was overwritten")
	}
	sha, _, err := nativeBackupDigest(receipt.BackupPath)
	if err != nil || sha != receipt.SHA256 {
		t.Fatal("no-replace failure altered backup", err)
	}
}
