package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/acornfox/acornfox/internal/auth"
	"github.com/acornfox/acornfox/internal/domain"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

var (
	ErrStoreLocked = errors.New("sqlite store data directory is already locked by another process")
	ErrStoreClosed = errors.New("sqlite store is closed")
)

type Config struct {
	DataDirectory string
	DBName        string
	BusyTimeout   time.Duration
}

type Store struct {
	db             *sql.DB
	dir            string
	dbPath         string
	lockFile       *os.File
	coreGeneration int64
	closeOnce      sync.Once
	closed         bool
	mu             sync.RWMutex
}

var _ auth.Store = (*Store)(nil)
var _ auth.WebSetupStore = (*Store)(nil)

// verifyTrustedDirectory walks from cleanDir up to the filesystem root.
// It verifies that all ancestor directories are real directories, not symlinks,
// owned by either root (uid 0) or current process UID, and not group/world-writable
// unless root-owned with the sticky bit set (such as standard /tmp: 01777).
// The target directory itself must be owned by the current process UID and have mode 0700.
func verifyTrustedDirectory(cleanDir string) error {
	if !filepath.IsAbs(cleanDir) {
		return errors.New("directory path must be absolute")
	}

	// 1. Walk and verify all ancestors
	parent := filepath.Dir(cleanDir)
	for p := parent; p != "/" && p != "."; p = filepath.Dir(p) {
		pFi, err := os.Lstat(p)
		if err != nil {
			return fmt.Errorf("stat ancestor directory %s: %w", p, err)
		}
		if pFi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("ancestor directory %s must not be a symlink", p)
		}
		if !pFi.IsDir() {
			return fmt.Errorf("ancestor path %s is not a directory", p)
		}
		stat, ok := pFi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("inspect ancestor directory %s stat failed", p)
		}
		// Ancestor must be owned by current UID or root
		if int(stat.Uid) != os.Getuid() && int(stat.Uid) != 0 {
			return fmt.Errorf("ancestor directory %s owned by untrusted uid %d", p, stat.Uid)
		}
		// Reject group- or world-writable ancestors (mode & 0022 != 0) unless root-owned sticky directory
		if pFi.Mode()&0022 != 0 {
			if int(stat.Uid) != 0 || pFi.Mode()&os.ModeSticky == 0 {
				return fmt.Errorf("ancestor directory %s is writable by group or others without sticky bit: mode=%o", p, pFi.Mode().Perm())
			}
		}
	}

	// 2. Target directory verification: must exist, be real directory, owned by current UID, and mode 0700
	fi, err := os.Lstat(cleanDir)
	if err != nil {
		return fmt.Errorf("stat directory %s: %w", cleanDir, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("directory %s must not be a symlink", cleanDir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("path %s is not a directory", cleanDir)
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("directory %s owner %d does not match process uid %d", cleanDir, stat.Uid, os.Getuid())
	}
	if fi.Mode().Perm() != 0o700 {
		return fmt.Errorf("directory %s permissions %o must be 0700", cleanDir, fi.Mode().Perm())
	}

	return nil
}

func Open(cfg Config) (*Store, error) {
	dir := strings.TrimSpace(cfg.DataDirectory)
	if dir == "" || strings.Contains(dir, "\x00") || dir == ":memory:" {
		return nil, errors.New("valid local sqlite data directory is required")
	}
	cleanDir := filepath.Clean(dir)
	if !filepath.IsAbs(cleanDir) {
		return nil, errors.New("sqlite data directory must be an absolute path")
	}

	// Ensure cleanDir exists with 0700 if not exist
	if _, err := os.Lstat(cleanDir); os.IsNotExist(err) {
		if err := os.MkdirAll(cleanDir, 0o700); err != nil {
			return nil, fmt.Errorf("create data directory: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("inspect data directory: %w", err)
	}

	if err := verifyTrustedDirectory(cleanDir); err != nil {
		return nil, err
	}

	// Validate DBName
	dbName := strings.TrimSpace(cfg.DBName)
	if dbName == "" {
		dbName = "acornfox.db"
	}
	if filepath.Base(dbName) != dbName || strings.ContainsAny(dbName, "/\\:\x00") || strings.Contains(dbName, "..") {
		return nil, errors.New("sqlite db name must be a clean single file basename")
	}
	if dbName == "acornfox.lock" || strings.HasSuffix(dbName, "-wal") || strings.HasSuffix(dbName, "-shm") {
		return nil, errors.New("sqlite db name is reserved")
	}

	// Check existing sidecars (WAL, SHM)
	for _, sidecar := range []string{dbName + "-wal", dbName + "-shm"} {
		scPath := filepath.Join(cleanDir, sidecar)
		if scFi, err := os.Lstat(scPath); err == nil {
			if scFi.Mode()&os.ModeSymlink != 0 || !scFi.Mode().IsRegular() {
				return nil, fmt.Errorf("sidecar %s must be a regular non-symlink file", sidecar)
			}
			if stat, ok := scFi.Sys().(*syscall.Stat_t); ok {
				if int(stat.Uid) != os.Getuid() {
					return nil, fmt.Errorf("sidecar %s owner %d does not match process uid %d", sidecar, stat.Uid, os.Getuid())
				}
			}
			if scFi.Mode().Perm()&0077 != 0 {
				return nil, fmt.Errorf("sidecar %s permissions %o must not be accessible to group/others", sidecar, scFi.Mode().Perm())
			}
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("inspect sidecar %s: %w", sidecar, err)
		}
	}

	// Open writer lock file with Linux O_NOFOLLOW
	lockPath := filepath.Join(cleanDir, "acornfox.lock")
	lockFd, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file (no-follow): %w", err)
	}
	lockFile := os.NewFile(uintptr(lockFd), lockPath)

	var success bool
	var db *sql.DB
	defer func() {
		if !success {
			if db != nil {
				_ = db.Close()
			}
			if lockFile != nil {
				_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
				_ = lockFile.Close()
			}
		}
	}()

	var lockStat unix.Stat_t
	if err := unix.Fstat(lockFd, &lockStat); err != nil {
		return nil, fmt.Errorf("fstat lock file: %w", err)
	}
	if lockStat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("lock file must be a regular file")
	}
	if int(lockStat.Uid) != os.Getuid() {
		return nil, fmt.Errorf("lock file owner %d does not match process uid %d", lockStat.Uid, os.Getuid())
	}
	if lockStat.Mode&0777 != 0600 {
		return nil, fmt.Errorf("lock file permissions %o must be 0600", lockStat.Mode&0777)
	}
	if lockStat.Nlink != 1 {
		return nil, fmt.Errorf("lock file has %d links, must be 1", lockStat.Nlink)
	}

	if err := syscall.Flock(lockFd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("obtain store writer lock on %s: %w", lockPath, ErrStoreLocked)
		}
		return nil, fmt.Errorf("flock %s: %w", lockPath, err)
	}

	// Precreate and validate DB file with Linux O_NOFOLLOW
	dbPath := filepath.Join(cleanDir, dbName)
	dbFd, err := unix.Open(dbPath, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open db file (no-follow): %w", err)
	}
	var dbStat unix.Stat_t
	if err := unix.Fstat(dbFd, &dbStat); err != nil {
		_ = unix.Close(dbFd)
		return nil, fmt.Errorf("fstat db file: %w", err)
	}
	_ = unix.Close(dbFd)

	if dbStat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("db file must be a regular file")
	}
	if int(dbStat.Uid) != os.Getuid() {
		return nil, fmt.Errorf("db file owner %d does not match process uid %d", dbStat.Uid, os.Getuid())
	}
	if dbStat.Mode&0777 != 0600 {
		return nil, fmt.Errorf("db file permissions %o must be 0600", dbStat.Mode&0777)
	}
	if dbStat.Nlink != 1 {
		return nil, fmt.Errorf("db file has %d links, must be 1", dbStat.Nlink)
	}

	busyTimeoutMS := 5000
	if cfg.BusyTimeout > 0 {
		busyTimeoutMS = int(cfg.BusyTimeout.Milliseconds())
	}

	escapedPath := url.PathEscape(dbPath)
	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(ON)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout=%d", escapedPath, busyTimeoutMS)

	db, err = sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1)

	if _, err := db.Exec(fmt.Sprintf(`
		PRAGMA foreign_keys = ON;
		PRAGMA journal_mode = WAL;
		PRAGMA synchronous = FULL;
		PRAGMA busy_timeout = %d;
	`, busyTimeoutMS)); err != nil {
		return nil, fmt.Errorf("configure sqlite pragmas: %w", err)
	}

	var fk int
	var journalMode string
	var synchronous int
	if err := db.QueryRow("PRAGMA foreign_keys;").Scan(&fk); err != nil || fk != 1 {
		return nil, fmt.Errorf("verify PRAGMA foreign_keys failed (got %d): %w", fk, err)
	}
	if err := db.QueryRow("PRAGMA journal_mode;").Scan(&journalMode); err != nil || strings.ToLower(journalMode) != "wal" {
		return nil, fmt.Errorf("verify PRAGMA journal_mode failed (got %s): %w", journalMode, err)
	}
	if err := db.QueryRow("PRAGMA synchronous;").Scan(&synchronous); err != nil || synchronous < 2 {
		return nil, fmt.Errorf("verify PRAGMA synchronous failed (got %d): %w", synchronous, err)
	}

	// Startup foreign key consistency check
	var fkViolationTable, fkViolationRowID, fkViolationParent string
	var fkViolationFkID int
	fkCheckRow := db.QueryRow("PRAGMA foreign_key_check;")
	if err := fkCheckRow.Scan(&fkViolationTable, &fkViolationRowID, &fkViolationParent, &fkViolationFkID); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("foreign_key_check query failed: %w", err)
	} else if err == nil {
		return nil, fmt.Errorf("foreign_key_check failed on table %s (row %s): %w", fkViolationTable, fkViolationRowID, ErrIncompatibleSchema)
	}

	// Run migrations and schema structural checks
	if err := runMigrationsAndVerifySchema(context.Background(), db); err != nil {
		return nil, err
	}

	generationTx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin core generation: %w", err)
	}
	defer generationTx.Rollback()
	// Every open advances the generation so tasks leased by a previous process
	// can be fenced off.
	var generation int64
	if generationErr := generationTx.QueryRow(`UPDATE core_generation SET generation = generation + 1 WHERE singleton = 1 AND generation < 9223372036854775807 RETURNING generation`).Scan(&generation); generationErr != nil {
		return nil, fmt.Errorf("advance persistent core generation (exhaustion or stale reservation refuses open): %w", generationErr)
	}
	if err := generationTx.Commit(); err != nil {
		return nil, fmt.Errorf("%w: commit core generation: %v", ErrOutcomeUnknown, err)
	}

	success = true
	return &Store{
		coreGeneration: generation,
		db:             db,
		dir:            cleanDir,
		dbPath:         dbPath,
		lockFile:       lockFile,
	}, nil
}

func (s *Store) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.closed = true
		if s.db != nil {
			closeErr = s.db.Close()
		}
		if s.lockFile != nil {
			_ = syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_UN)
			_ = s.lockFile.Close()
		}
	})
	return closeErr
}

func (s *Store) DBPath() string { return s.dbPath }

func (s *Store) CoreGeneration() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.coreGeneration
}

func (s *Store) checkOpen() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || s.db == nil {
		return ErrStoreClosed
	}
	return nil
}

func (s *Store) Backup(ctx context.Context, destPath string) (err error) {
	if checkErr := s.checkOpen(); checkErr != nil {
		return checkErr
	}
	return backupSQLiteConnection(ctx, s.db, s.dbPath, destPath)
}

// backupSQLiteConnection is the existing durable VACUUM INTO sink shared with
// the quiescent Core-UID backup leaf. It does not open a Store or run migrations.
func backupSQLiteConnection(ctx context.Context, db *sql.DB, sourcePath, destPath string) (err error) {
	destPath = strings.TrimSpace(destPath)
	if destPath == "" || strings.Contains(destPath, "\x00") {
		return errors.New("invalid backup destination path")
	}
	cleanDest := filepath.Clean(destPath)
	if !filepath.IsAbs(cleanDest) {
		return errors.New("backup destination must be an absolute path")
	}
	if cleanDest == sourcePath {
		return errors.New("cannot backup database onto itself")
	}

	// Reject if destination already exists or is a symlink
	if dfi, statErr := os.Lstat(cleanDest); statErr == nil {
		if dfi.Mode()&os.ModeSymlink != 0 {
			return errors.New("backup destination must not be a symlink")
		}
		return errors.New("backup destination already exists")
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect backup destination: %w", statErr)
	}

	destDir := filepath.Dir(cleanDest)
	if dirErr := verifyTrustedDirectory(destDir); dirErr != nil {
		return fmt.Errorf("verify backup destination directory: %w", dirErr)
	}

	// Create private temp file with Linux no-follow
	tempPath := filepath.Join(destDir, fmt.Sprintf(".acornfox_backup_tmp_%d.db", time.Now().UnixNano()))
	tempFd, openTempErr := unix.Open(tempPath, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if openTempErr != nil {
		return fmt.Errorf("create temp backup file: %w", openTempErr)
	}
	_ = unix.Close(tempFd)

	defer func() {
		if tempPath != "" {
			if rmErr := os.Remove(tempPath); rmErr != nil && !os.IsNotExist(rmErr) {
				err = errors.Join(err, fmt.Errorf("cleanup temp backup file %s: %w", tempPath, rmErr))
			}
		}
	}()

	// VACUUM INTO performs a live, consistent, non-WAL checkpointed single-file snapshot
	_, execErr := db.ExecContext(ctx, "VACUUM INTO ?", tempPath)
	if execErr != nil {
		return fmt.Errorf("sqlite backup (VACUUM INTO): %w", execErr)
	}

	// Verify temp file with fstat
	verifyFd, openVerifyErr := unix.Open(tempPath, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if openVerifyErr != nil {
		return fmt.Errorf("open backup verification: %w", openVerifyErr)
	}
	var vStat unix.Stat_t
	if fstatErr := unix.Fstat(verifyFd, &vStat); fstatErr != nil {
		_ = unix.Close(verifyFd)
		return fmt.Errorf("fstat backup temp file: %w", fstatErr)
	}
	if vStat.Mode&unix.S_IFMT != unix.S_IFREG || vStat.Mode&0777 != 0600 || int(vStat.Uid) != os.Getuid() || vStat.Nlink != 1 {
		_ = unix.Close(verifyFd)
		return fmt.Errorf("backup temp file invalid (mode=%o, uid=%d, nlink=%d)", vStat.Mode&0777, vStat.Uid, vStat.Nlink)
	}
	if fsyncFileErr := unix.Fsync(verifyFd); fsyncFileErr != nil {
		_ = unix.Close(verifyFd)
		return fmt.Errorf("fsync backup file: %w", fsyncFileErr)
	}
	if closeFileErr := unix.Close(verifyFd); closeFileErr != nil {
		return fmt.Errorf("close backup verification descriptor: %w", closeFileErr)
	}

	// Atomically publish WITHOUT overwriting an existing target (os.Link fails if destination exists)
	if linkErr := os.Link(tempPath, cleanDest); linkErr != nil {
		return fmt.Errorf("publish backup file without overwrite: %w", linkErr)
	}

	// Do not clear tempPath until removal succeeds; report failure if temporary copy remains
	if rmErr := os.Remove(tempPath); rmErr != nil && !os.IsNotExist(rmErr) {
		return fmt.Errorf("backup published to %s but removing temporary link %s failed: %w", cleanDest, tempPath, rmErr)
	}
	tempPath = "" // successfully removed

	// Fsync parent directory to ensure durable directory entry
	dirFd, openDirErr := unix.Open(destDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if openDirErr != nil {
		return fmt.Errorf("backup published to %s but opening parent directory for fsync failed; durability not confirmed: %w", cleanDest, openDirErr)
	}
	defer func() {
		if closeDirErr := unix.Close(dirFd); closeDirErr != nil && err == nil {
			err = fmt.Errorf("backup published to %s but closing parent directory failed: %w", cleanDest, closeDirErr)
		}
	}()
	if fsyncDirErr := unix.Fsync(dirFd); fsyncDirErr != nil {
		return fmt.Errorf("backup published to %s but parent directory fsync failed; durability not confirmed: %w", cleanDest, fsyncDirErr)
	}

	return nil
}

func (s *Store) AdministratorExists(ctx context.Context) (bool, error) {
	if err := s.checkOpen(); err != nil {
		return false, err
	}
	var exists bool
	if err := s.db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM admin_credentials);").Scan(&exists); err != nil {
		return false, fmt.Errorf("sqlite inspect administrator records: %w", err)
	}
	return exists, nil
}

func (s *Store) CreateAdminCredential(ctx context.Context, credential domain.AdminCredential) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if err := credential.Validate(); err != nil {
		return err
	}

	var disabledAt sql.NullString
	if credential.DisabledAt != nil {
		disabledAt = sql.NullString{String: FormatTime(*credential.DisabledAt), Valid: true}
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO admin_credentials
			(id, password_hash_scheme, password_hash, credential_version, disabled_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?);
	`, credential.ID.String(), credential.PasswordHashScheme, credential.PasswordHash, credential.CredentialVersion, disabledAt, FormatTime(credential.CreatedAt), FormatTime(credential.UpdatedAt))
	if err != nil {
		return fmt.Errorf("sqlite create administrator credential: %w", err)
	}
	return nil
}

func (s *Store) ActiveAdminCredential(ctx context.Context) (domain.AdminCredential, error) {
	if err := s.checkOpen(); err != nil {
		return domain.AdminCredential{}, err
	}
	credential, err := scanAdminCredentialRow(s.db.QueryRowContext(ctx, `
		SELECT id, password_hash_scheme, password_hash, credential_version, disabled_at, created_at, updated_at
		  FROM admin_credentials
		 WHERE disabled_at IS NULL;
	`))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AdminCredential{}, domain.ErrObjectNotFound
	}
	if err != nil {
		return domain.AdminCredential{}, fmt.Errorf("sqlite read active administrator credential: %w", err)
	}
	return credential, nil
}

func (s *Store) RotateAdminCredential(ctx context.Context, adminID domain.ID, expectedVersion int64, passwordHashScheme, passwordHash string, now time.Time) (domain.AdminCredential, error) {
	if err := s.checkOpen(); err != nil {
		return domain.AdminCredential{}, err
	}
	if err := domain.RequireID(adminID, "administrator id"); err != nil {
		return domain.AdminCredential{}, err
	}
	if expectedVersion < 1 {
		return domain.AdminCredential{}, domain.ValidationError("expected credential version must be positive")
	}
	passwordHashScheme, err := domain.NormalizePasswordHashScheme(passwordHashScheme)
	if err != nil {
		return domain.AdminCredential{}, err
	}
	if now.IsZero() {
		return domain.AdminCredential{}, domain.ValidationError("credential rotation time is required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.AdminCredential{}, fmt.Errorf("begin rotate admin credential tx: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `
		UPDATE admin_credentials
		   SET password_hash_scheme = ?,
		       password_hash = ?,
		       credential_version = credential_version + 1,
		       updated_at = ?
		 WHERE id = ?
		   AND credential_version = ?
		   AND disabled_at IS NULL;
	`, passwordHashScheme, passwordHash, FormatTime(now), adminID.String(), expectedVersion)
	if err != nil {
		return domain.AdminCredential{}, fmt.Errorf("sqlite update rotate credential: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return domain.AdminCredential{}, fmt.Errorf("sqlite inspect rotate credential rows affected: %w", err)
	}
	if affected == 0 {
		return domain.AdminCredential{}, domain.ErrCredentialVersionConflict
	}

	credential, err := scanAdminCredentialRow(tx.QueryRowContext(ctx, `
		SELECT id, password_hash_scheme, password_hash, credential_version, disabled_at, created_at, updated_at
		  FROM admin_credentials
		 WHERE id = ?;
	`, adminID.String()))
	if err != nil {
		return domain.AdminCredential{}, fmt.Errorf("sqlite read rotated credential: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return domain.AdminCredential{}, fmt.Errorf("commit rotate credential tx: %w", err)
	}
	return credential, nil
}

func (s *Store) CreateAdminSession(ctx context.Context, session domain.AdminSession) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if err := session.Validate(); err != nil {
		return err
	}
	var revokedAt sql.NullString
	if session.RevokedAt != nil {
		revokedAt = sql.NullString{String: FormatTime(*session.RevokedAt), Valid: true}
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO admin_sessions
			(id, admin_id, session_digest, csrf_digest, credential_version, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`, session.ID.String(), session.AdminID.String(), session.SessionDigest.String(), session.CSRFDigest.String(), session.CredentialVersion, FormatTime(session.CreatedAt), FormatTime(session.LastSeenAt), FormatTime(session.IdleExpiresAt), FormatTime(session.AbsoluteExpiresAt), revokedAt)
	if err != nil {
		return fmt.Errorf("sqlite create administrator session: %w", err)
	}
	return nil
}

func (s *Store) ActiveAdminSessionByDigest(ctx context.Context, digest domain.AuthDigest, now time.Time) (domain.AdminSession, error) {
	if err := s.checkOpen(); err != nil {
		return domain.AdminSession{}, err
	}
	if err := digest.Validate("session digest"); err != nil {
		return domain.AdminSession{}, err
	}
	if now.IsZero() {
		return domain.AdminSession{}, domain.ValidationError("session lookup time is required")
	}

	nowStr := FormatTime(now)
	session, err := scanAdminSessionRow(s.db.QueryRowContext(ctx, `
		SELECT s.id, s.admin_id, s.session_digest, s.csrf_digest, s.credential_version,
		       s.created_at, s.last_seen_at, s.idle_expires_at, s.absolute_expires_at, s.revoked_at
		  FROM admin_sessions s
		  JOIN admin_credentials a ON a.id = s.admin_id
		 WHERE s.session_digest = ?
		   AND s.revoked_at IS NULL
		   AND a.disabled_at IS NULL
		   AND a.credential_version = s.credential_version
		   AND s.idle_expires_at > ?
		   AND s.absolute_expires_at > ?;
	`, digest.String(), nowStr, nowStr))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AdminSession{}, domain.ErrObjectNotFound
	}
	if err != nil {
		return domain.AdminSession{}, fmt.Errorf("sqlite read active admin session: %w", err)
	}
	return session, nil
}

func (s *Store) TouchAdminSession(ctx context.Context, sessionID domain.ID, credentialVersion int64, now time.Time) (domain.AdminSession, error) {
	if err := s.checkOpen(); err != nil {
		return domain.AdminSession{}, err
	}
	if err := domain.RequireID(sessionID, "administrator session id"); err != nil {
		return domain.AdminSession{}, err
	}
	if credentialVersion < 1 || now.IsZero() {
		return domain.AdminSession{}, domain.ValidationError("session touch identity or time is invalid")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.AdminSession{}, fmt.Errorf("begin touch session tx: %w", err)
	}
	defer tx.Rollback()

	nowStr := FormatTime(now)
	session, err := scanAdminSessionRow(tx.QueryRowContext(ctx, `
		SELECT s.id, s.admin_id, s.session_digest, s.csrf_digest, s.credential_version,
		       s.created_at, s.last_seen_at, s.idle_expires_at, s.absolute_expires_at, s.revoked_at
		  FROM admin_sessions s
		  JOIN admin_credentials a ON a.id = s.admin_id
		 WHERE s.id = ?
		   AND s.credential_version = ?
		   AND a.disabled_at IS NULL
		   AND a.credential_version = s.credential_version
		   AND s.revoked_at IS NULL
		   AND s.idle_expires_at > ?
		   AND s.absolute_expires_at > ?;
	`, sessionID.String(), credentialVersion, nowStr, nowStr))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AdminSession{}, domain.ErrObjectNotFound
	}
	if err != nil {
		return domain.AdminSession{}, fmt.Errorf("sqlite query session before touch: %w", err)
	}

	// Guarantee last_seen_at does not move backward under reordered requests
	newLastSeen := now.UTC()
	if newLastSeen.Before(session.LastSeenAt) {
		newLastSeen = session.LastSeenAt
	}

	newIdle := newLastSeen.Add(domain.AdminSessionIdleTimeout)
	if newIdle.After(session.AbsoluteExpiresAt) {
		newIdle = session.AbsoluteExpiresAt
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE admin_sessions
		   SET last_seen_at = ?,
		       idle_expires_at = ?
		 WHERE id = ?;
	`, FormatTime(newLastSeen), FormatTime(newIdle), sessionID.String())
	if err != nil {
		return domain.AdminSession{}, fmt.Errorf("sqlite update touched session: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return domain.AdminSession{}, fmt.Errorf("commit touch session tx: %w", err)
	}

	session.LastSeenAt = newLastSeen
	session.IdleExpiresAt = newIdle
	return session, nil
}

func (s *Store) RevokeAdminSession(ctx context.Context, sessionID domain.ID, revokedAt time.Time) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if err := domain.RequireID(sessionID, "administrator session id"); err != nil {
		return err
	}
	if revokedAt.IsZero() {
		return domain.ValidationError("session revocation time is required")
	}

	res, err := s.db.ExecContext(ctx, `
		UPDATE admin_sessions
		   SET revoked_at = COALESCE(revoked_at, ?)
		 WHERE id = ?;
	`, FormatTime(revokedAt), sessionID.String())
	if err != nil {
		return fmt.Errorf("sqlite revoke admin session: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite inspect session revocation rows affected: %w", err)
	}
	if affected == 0 {
		return domain.ErrObjectNotFound
	}
	return nil
}

func (s *Store) UpsertAdminLoginRateLimit(ctx context.Context, record domain.AdminLoginRateLimit) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if err := record.Validate(); err != nil {
		return err
	}

	var lockedAt, lockedUntil sql.NullString
	if record.LockedAt != nil {
		lockedAt = sql.NullString{String: FormatTime(*record.LockedAt), Valid: true}
	}
	if record.LockedUntil != nil {
		lockedUntil = sql.NullString{String: FormatTime(*record.LockedUntil), Valid: true}
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO admin_login_rate_limits
			(admin_id, source_digest, window_started_at, window_expires_at, failure_count, last_failure_at, locked_at, locked_until, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (admin_id, source_digest) DO UPDATE
		   SET window_started_at = excluded.window_started_at,
		       window_expires_at = excluded.window_expires_at,
		       failure_count = excluded.failure_count,
		       last_failure_at = excluded.last_failure_at,
		       locked_at = excluded.locked_at,
		       locked_until = excluded.locked_until,
		       updated_at = excluded.updated_at;
	`, record.AdminID.String(), record.SourceDigest.String(), FormatTime(record.WindowStartedAt), FormatTime(record.WindowExpiresAt), record.FailureCount, FormatTime(record.LastFailureAt), lockedAt, lockedUntil, FormatTime(record.UpdatedAt))
	if err != nil {
		return fmt.Errorf("sqlite upsert admin login rate limit: %w", err)
	}
	return nil
}

func (s *Store) AdminLoginRateLimit(ctx context.Context, adminID domain.ID, sourceDigest domain.AuthDigest) (domain.AdminLoginRateLimit, error) {
	if err := s.checkOpen(); err != nil {
		return domain.AdminLoginRateLimit{}, err
	}
	if err := domain.RequireID(adminID, "login rate limit admin id"); err != nil {
		return domain.AdminLoginRateLimit{}, err
	}
	if err := sourceDigest.Validate("login rate limit source digest"); err != nil {
		return domain.AdminLoginRateLimit{}, err
	}

	record, err := scanAdminLoginRateLimitRow(s.db.QueryRowContext(ctx, `
		SELECT admin_id, source_digest, window_started_at, window_expires_at, failure_count, last_failure_at, locked_at, locked_until, updated_at
		  FROM admin_login_rate_limits
		 WHERE admin_id = ? AND source_digest = ?;
	`, adminID.String(), sourceDigest.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AdminLoginRateLimit{}, domain.ErrObjectNotFound
	}
	if err != nil {
		return domain.AdminLoginRateLimit{}, fmt.Errorf("sqlite read admin login rate limit: %w", err)
	}
	return record, nil
}

func (s *Store) RecordAdminLoginFailure(ctx context.Context, adminID domain.ID, sourceDigest domain.AuthDigest, now time.Time) (domain.AdminLoginRateLimit, error) {
	if err := s.checkOpen(); err != nil {
		return domain.AdminLoginRateLimit{}, err
	}
	if err := domain.RequireID(adminID, "login rate limit admin id"); err != nil {
		return domain.AdminLoginRateLimit{}, err
	}
	if err := sourceDigest.Validate("login rate limit source digest"); err != nil {
		return domain.AdminLoginRateLimit{}, err
	}
	if now.IsZero() {
		return domain.AdminLoginRateLimit{}, domain.ValidationError("login failure record time is required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.AdminLoginRateLimit{}, fmt.Errorf("sqlite begin record login failure tx: %w", err)
	}
	defer tx.Rollback()

	var existing *domain.AdminLoginRateLimit
	record, err := scanAdminLoginRateLimitRow(tx.QueryRowContext(ctx, `
		SELECT admin_id, source_digest, window_started_at, window_expires_at, failure_count, last_failure_at, locked_at, locked_until, updated_at
		  FROM admin_login_rate_limits
		 WHERE admin_id = ? AND source_digest = ?;
	`, adminID.String(), sourceDigest.String()))
	if err == nil {
		existing = &record
	} else if !errors.Is(err, sql.ErrNoRows) {
		return domain.AdminLoginRateLimit{}, fmt.Errorf("sqlite query existing rate limit: %w", err)
	}

	next := domain.TransitionAdminLoginRateLimit(existing, adminID, sourceDigest, now)
	if err := next.Validate(); err != nil {
		return domain.AdminLoginRateLimit{}, fmt.Errorf("validate transitioned rate limit: %w", err)
	}

	var lockedAt, lockedUntil sql.NullString
	if next.LockedAt != nil {
		lockedAt = sql.NullString{String: FormatTime(*next.LockedAt), Valid: true}
	}
	if next.LockedUntil != nil {
		lockedUntil = sql.NullString{String: FormatTime(*next.LockedUntil), Valid: true}
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO admin_login_rate_limits
			(admin_id, source_digest, window_started_at, window_expires_at, failure_count, last_failure_at, locked_at, locked_until, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (admin_id, source_digest) DO UPDATE
		   SET window_started_at = excluded.window_started_at,
		       window_expires_at = excluded.window_expires_at,
		       failure_count = excluded.failure_count,
		       last_failure_at = excluded.last_failure_at,
		       locked_at = excluded.locked_at,
		       locked_until = excluded.locked_until,
		       updated_at = excluded.updated_at;
	`, next.AdminID.String(), next.SourceDigest.String(), FormatTime(next.WindowStartedAt), FormatTime(next.WindowExpiresAt), next.FailureCount, FormatTime(next.LastFailureAt), lockedAt, lockedUntil, FormatTime(next.UpdatedAt))
	if err != nil {
		return domain.AdminLoginRateLimit{}, fmt.Errorf("sqlite upsert transitioned rate limit: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return domain.AdminLoginRateLimit{}, fmt.Errorf("commit record login failure tx: %w", err)
	}
	return next, nil
}

func (s *Store) CreateAdminSessionIfLoginAllowed(ctx context.Context, session domain.AdminSession, sourceDigest domain.AuthDigest, now time.Time) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if err := session.Validate(); err != nil {
		return err
	}
	if err := sourceDigest.Validate("session creation source digest"); err != nil {
		return err
	}
	if now.IsZero() {
		return domain.ValidationError("session authorization time is required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite begin create admin session tx: %w", err)
	}
	defer tx.Rollback()

	// 1. Re-check credential state
	var credVersion int64
	var disabledAt sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT credential_version, disabled_at
		  FROM admin_credentials
		 WHERE id = ?;
	`, session.AdminID.String()).Scan(&credVersion, &disabledAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrObjectNotFound
	}
	if err != nil {
		return fmt.Errorf("sqlite check admin credential state: %w", err)
	}
	if disabledAt.Valid || credVersion != session.CredentialVersion {
		return domain.ErrCredentialVersionConflict
	}

	// 2. Re-check rate limit lock by scanning and validating the FULL record (fail-closed on corrupt timestamp/state)
	record, err := scanAdminLoginRateLimitRow(tx.QueryRowContext(ctx, `
		SELECT admin_id, source_digest, window_started_at, window_expires_at, failure_count, last_failure_at, locked_at, locked_until, updated_at
		  FROM admin_login_rate_limits
		 WHERE admin_id = ? AND source_digest = ?;
	`, session.AdminID.String(), sourceDigest.String()))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("sqlite check rate limit record: %w", ErrCorruptData)
	}
	if err == nil {
		if valErr := record.Validate(); valErr != nil {
			return fmt.Errorf("sqlite validate persisted rate limit: %w", ErrCorruptData)
		}
		if record.IsLocked(now) {
			return auth.ErrRateLimited
		}
	}

	// 3. Persist session
	var revokedAt sql.NullString
	if session.RevokedAt != nil {
		revokedAt = sql.NullString{String: FormatTime(*session.RevokedAt), Valid: true}
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO admin_sessions
			(id, admin_id, session_digest, csrf_digest, credential_version, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`, session.ID.String(), session.AdminID.String(), session.SessionDigest.String(), session.CSRFDigest.String(), session.CredentialVersion, FormatTime(session.CreatedAt), FormatTime(session.LastSeenAt), FormatTime(session.IdleExpiresAt), FormatTime(session.AbsoluteExpiresAt), revokedAt)
	if err != nil {
		return fmt.Errorf("sqlite create administrator session: %w", err)
	}

	return tx.Commit()
}

type rowScanner interface{ Scan(...any) error }

func scanAdminCredentialRow(row rowScanner) (domain.AdminCredential, error) {
	var credential domain.AdminCredential
	var disabledAt sql.NullString
	var createdAtStr, updatedAtStr string

	if err := row.Scan(&credential.ID, &credential.PasswordHashScheme, &credential.PasswordHash, &credential.CredentialVersion, &disabledAt, &createdAtStr, &updatedAtStr); err != nil {
		return domain.AdminCredential{}, err
	}

	var err error
	credential.CreatedAt, err = ParseTime(createdAtStr)
	if err != nil {
		return domain.AdminCredential{}, fmt.Errorf("parse credential created_at: %w", ErrCorruptData)
	}
	credential.UpdatedAt, err = ParseTime(updatedAtStr)
	if err != nil {
		return domain.AdminCredential{}, fmt.Errorf("parse credential updated_at: %w", ErrCorruptData)
	}
	if disabledAt.Valid {
		t, err := ParseTime(disabledAt.String)
		if err != nil {
			return domain.AdminCredential{}, fmt.Errorf("parse credential disabled_at: %w", ErrCorruptData)
		}
		credential.DisabledAt = &t
	}
	if err := credential.Validate(); err != nil {
		return domain.AdminCredential{}, fmt.Errorf("validate scanned credential: %w", ErrCorruptData)
	}
	return credential, nil
}

func scanAdminSessionRow(row rowScanner) (domain.AdminSession, error) {
	var session domain.AdminSession
	var createdAtStr, lastSeenAtStr, idleExpiresAtStr, absoluteExpiresAtStr string
	var revokedAt sql.NullString

	if err := row.Scan(&session.ID, &session.AdminID, &session.SessionDigest, &session.CSRFDigest, &session.CredentialVersion, &createdAtStr, &lastSeenAtStr, &idleExpiresAtStr, &absoluteExpiresAtStr, &revokedAt); err != nil {
		return domain.AdminSession{}, err
	}

	var err error
	session.CreatedAt, err = ParseTime(createdAtStr)
	if err != nil {
		return domain.AdminSession{}, fmt.Errorf("parse session created_at: %w", ErrCorruptData)
	}
	session.LastSeenAt, err = ParseTime(lastSeenAtStr)
	if err != nil {
		return domain.AdminSession{}, fmt.Errorf("parse session last_seen_at: %w", ErrCorruptData)
	}
	session.IdleExpiresAt, err = ParseTime(idleExpiresAtStr)
	if err != nil {
		return domain.AdminSession{}, fmt.Errorf("parse session idle_expires_at: %w", ErrCorruptData)
	}
	session.AbsoluteExpiresAt, err = ParseTime(absoluteExpiresAtStr)
	if err != nil {
		return domain.AdminSession{}, fmt.Errorf("parse session absolute_expires_at: %w", ErrCorruptData)
	}
	if revokedAt.Valid {
		t, err := ParseTime(revokedAt.String)
		if err != nil {
			return domain.AdminSession{}, fmt.Errorf("parse session revoked_at: %w", ErrCorruptData)
		}
		session.RevokedAt = &t
	}
	if err := session.Validate(); err != nil {
		return domain.AdminSession{}, fmt.Errorf("validate scanned session: %w", ErrCorruptData)
	}
	return session, nil
}

func scanAdminLoginRateLimitRow(row rowScanner) (domain.AdminLoginRateLimit, error) {
	var record domain.AdminLoginRateLimit
	var winStartStr, winExpStr, lastFailStr, upStr string
	var lockedAt, lockedUntil sql.NullString

	if err := row.Scan(&record.AdminID, &record.SourceDigest, &winStartStr, &winExpStr, &record.FailureCount, &lastFailStr, &lockedAt, &lockedUntil, &upStr); err != nil {
		return domain.AdminLoginRateLimit{}, err
	}

	var err error
	record.WindowStartedAt, err = ParseTime(winStartStr)
	if err != nil {
		return domain.AdminLoginRateLimit{}, fmt.Errorf("parse rate limit window_started_at: %w", ErrCorruptData)
	}
	record.WindowExpiresAt, err = ParseTime(winExpStr)
	if err != nil {
		return domain.AdminLoginRateLimit{}, fmt.Errorf("parse rate limit window_expires_at: %w", ErrCorruptData)
	}
	record.LastFailureAt, err = ParseTime(lastFailStr)
	if err != nil {
		return domain.AdminLoginRateLimit{}, fmt.Errorf("parse rate limit last_failure_at: %w", ErrCorruptData)
	}
	record.UpdatedAt, err = ParseTime(upStr)
	if err != nil {
		return domain.AdminLoginRateLimit{}, fmt.Errorf("parse rate limit updated_at: %w", ErrCorruptData)
	}
	if lockedAt.Valid {
		t, err := ParseTime(lockedAt.String)
		if err != nil {
			return domain.AdminLoginRateLimit{}, fmt.Errorf("parse rate limit locked_at: %w", ErrCorruptData)
		}
		record.LockedAt = &t
	}
	if lockedUntil.Valid {
		t, err := ParseTime(lockedUntil.String)
		if err != nil {
			return domain.AdminLoginRateLimit{}, fmt.Errorf("parse rate limit locked_until: %w", ErrCorruptData)
		}
		record.LockedUntil = &t
	}
	if err := record.Validate(); err != nil {
		return domain.AdminLoginRateLimit{}, fmt.Errorf("validate scanned rate limit: %w", ErrCorruptData)
	}
	return record, nil
}
