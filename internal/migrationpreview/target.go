package migrationpreview

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/persistence/sqlite"
)

const diagnosticDDL = `CREATE TABLE diagnostic_migration_preview (
 singleton INTEGER PRIMARY KEY CHECK (singleton=1),
 source_identity_sha256 TEXT NOT NULL,
 manifest_sha256 TEXT NOT NULL,
 projection_status TEXT NOT NULL CHECK (projection_status IN ('pending','verified','rejected','interrupted'))
)`

type target struct {
	db   *sql.DB
	lock *os.File
	path string
}

func fileIdentity(path string) (syscall.Stat_t, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return syscall.Stat_t{}, errors.New("target_identity_rejected")
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != uint32(os.Getuid()) || st.Mode&0777 != 0600 || st.Nlink != 1 {
		return st, errors.New("target_identity_rejected")
	}
	return st, nil
}
func sameIdentity(a, b syscall.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }
func openTarget(ctx context.Context, runDir, sourceIdentity, manifest string) (*target, error) {
	dir := filepath.Join(runDir, "projection")
	if err := os.Mkdir(dir, 0700); err != nil {
		return nil, errors.New("new_target_required")
	}
	var directoryID syscall.Stat_t
	if syscall.Lstat(dir, &directoryID) != nil {
		return nil, errors.New("target_directory_rejected")
	}
	core, err := sqlite.Open(sqlite.Config{DataDirectory: dir})
	if err != nil {
		return nil, errors.New("target_initialize_failed")
	}
	dbPath := core.DBPath()
	dbID, err := fileIdentity(dbPath)
	if err != nil {
		core.Close()
		return nil, err
	}
	lockPath := filepath.Join(dir, "acornfox.lock")
	lockID, err := fileIdentity(lockPath)
	if err != nil {
		core.Close()
		return nil, err
	}
	if core.Close() != nil {
		return nil, errors.New("target_initialize_close_failed")
	}
	// Reacquire the EXISTING lock without O_CREAT. A competing owner is a failure.
	fd, err := syscall.Open(lockPath, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("target_lock_rejected")
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	var opened syscall.Stat_t
	if syscall.Fstat(fd, &opened) != nil || !sameIdentity(opened, lockID) || opened.Mode&syscall.S_IFMT != syscall.S_IFREG || opened.Mode&0777 != 0600 || opened.Nlink != 1 || opened.Uid != uint32(os.Getuid()) {
		lock.Close()
		return nil, errors.New("target_lock_rejected")
	}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		lock.Close()
		return nil, errors.New("target_lock_busy")
	}
	fail := func(err error) (*target, error) { syscall.Flock(fd, syscall.LOCK_UN); lock.Close(); return nil, err }
	actual, err := fileIdentity(dbPath)
	if err != nil || !sameIdentity(actual, dbID) {
		return fail(errors.New("target_identity_changed"))
	}
	var directoryNow syscall.Stat_t
	if syscall.Lstat(dir, &directoryNow) != nil || !sameIdentity(directoryID, directoryNow) || directoryNow.Uid != uint32(os.Getuid()) || directoryNow.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return fail(errors.New("target_directory_changed"))
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return fail(errors.New("target_directory_rejected"))
	}
	db, err := sql.Open("sqlite", "file:"+url.PathEscape(dbPath)+"?_pragma=foreign_keys(ON)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout=5000")
	if err != nil {
		return fail(errors.New("target_open_failed"))
	}
	db.SetMaxOpenConns(1)
	t := &target{db: db, lock: lock, path: dir}
	if err := db.PingContext(ctx); err != nil {
		t.Close()
		return nil, errors.New("target_open_failed")
	}
	actual, err = fileIdentity(dbPath)
	if err != nil || !sameIdentity(actual, dbID) {
		t.Close()
		return nil, errors.New("target_identity_changed")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Close()
		return nil, errors.New("diagnostic_gate_failed")
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, diagnosticDDL); err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO diagnostic_migration_preview VALUES(1,?,?,'pending')`, sourceIdentity, manifest)
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO _schema_migrations(version,checksum,applied_at) VALUES('diagnostic_tc1g_v1',?,?)`, digest([]byte(diagnosticDDL)), sqlite.FormatTime(time.Now().UTC()))
	}
	if err != nil {
		tx.Rollback()
		t.Close()
		return nil, errors.New("diagnostic_gate_failed")
	}
	if tx.Commit() != nil {
		tx.Rollback()
		t.Close()
		return nil, errors.New("diagnostic_gate_commit_unknown")
	}
	return t, nil
}
func (t *target) Close() error {
	err := t.db.Close()
	syscall.Flock(int(t.lock.Fd()), syscall.LOCK_UN)
	t.lock.Close()
	return err
}
