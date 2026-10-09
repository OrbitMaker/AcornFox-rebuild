package state

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

// envKeyPattern is the accepted environment variable key form.
var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// deploymentIDPattern is the accepted deployment ID form (12 lowercase hex).
var deploymentIDPattern = regexp.MustCompile(`^[0-9a-f]{12}$`)

// terminalStatuses are the statuses a deployment can never leave.
var terminalStatuses = map[string]bool{
	StatusLive:       true,
	StatusRetired:    true,
	StatusFailed:     true,
	StatusSuperseded: true,
}

// Store is the SQLite-backed desired-state store. All methods are safe for
// concurrent use: the underlying *sql.DB is configured with a single writer
// connection, so writes serialise and SQLite's own locking is never contended
// across goroutines of this process.
type Store struct {
	db       *sql.DB
	lockFile *os.File // held for the process lifetime; released on Close
	minPort  int
	maxPort  int
	now      func() time.Time // injectable clock; nil means time.Now (used by tests)
}

// nowUTC returns the current time in UTC, honoring an injected clock.
func (s *Store) nowUTC() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

// setClock replaces the store clock; used by tests to exercise expiry.
func (s *Store) setClock(fn func() time.Time) { s.now = fn }

// Open creates the parent directory (0700) and database file (0600), takes an
// exclusive, non-blocking flock on Path+".lock" (ErrLocked if another process
// holds it), enables foreign keys + WAL + synchronous=FULL + a busy timeout,
// and runs migrations. It uses a single writer connection.
func Open(cfg Config) (*Store, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("%w: empty database path", ErrInvalid)
	}
	minPort := cfg.PublicPortMin
	if minPort == 0 {
		minPort = 18810
	}
	maxPort := cfg.PublicPortMax
	if maxPort == 0 {
		maxPort = 18899
	}
	if minPort < 1 || maxPort < minPort || maxPort > 65535 {
		return nil, fmt.Errorf("%w: invalid public port range [%d,%d]", ErrInvalid, minPort, maxPort)
	}

	dir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	// Acquire the cross-process exclusive lock before opening the database so
	// two servers never share one file.
	lockPath := cfg.Path + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lockFile.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("flock lock file: %w", err)
	}

	// Ensure the database file exists with 0600 before the driver opens it.
	dbFile, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		releaseLock(lockFile)
		return nil, fmt.Errorf("create db file: %w", err)
	}
	dbFile.Close()
	if err := os.Chmod(cfg.Path, 0o600); err != nil {
		releaseLock(lockFile)
		return nil, fmt.Errorf("chmod db file: %w", err)
	}

	dsn := "file:" + cfg.Path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		releaseLock(lockFile)
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// Single writer connection keeps SQLite writes serialised and avoids
	// "database is locked" from concurrent write transactions in one process.
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		releaseLock(lockFile)
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	if err := runMigrations(ctx, db); err != nil {
		db.Close()
		releaseLock(lockFile)
		return nil, err
	}

	return &Store{db: db, lockFile: lockFile, minPort: minPort, maxPort: maxPort}, nil
}

// releaseLock unlocks and closes the flock file.
func releaseLock(f *os.File) {
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	_ = f.Close()
}

// Close closes the database and releases the process lock.
func (s *Store) Close() error {
	err := s.db.Close()
	releaseLock(s.lockFile)
	return err
}

// -------- Apps --------

// EnsureApp returns the app, creating it with defaults and the next free public
// port when it does not exist. The bool is true when the app was created.
func (s *Store) EnsureApp(ctx context.Context, name string) (App, bool, error) {
	if !ValidAppName(name) {
		return App{}, false, fmt.Errorf("%w: app name %q", ErrInvalid, name)
	}
	var (
		app     App
		created bool
	)
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		existing, err := scanAppTx(ctx, tx, name)
		if err == nil {
			app = existing
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		port, err := allocatePortTx(ctx, tx, s.minPort, s.maxPort)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		nowText := formatTime(now)
		_, err = tx.ExecContext(ctx, `INSERT INTO apps
			(name, desired, port, health_path, public_port, current_deployment, memory_mb, cpu_milli, volume_seq, created_at, updated_at)
			VALUES (?, ?, 0, ?, ?, '', ?, ?, 0, ?, ?)`,
			name, DesiredRunning, DefaultHealthPath, port, DefaultMemoryMB, DefaultCPUMilli, nowText, nowText)
		if err != nil {
			return fmt.Errorf("insert app: %w", err)
		}
		created = true
		app, err = scanAppTx(ctx, tx, name)
		return err
	})
	if err != nil {
		return App{}, false, err
	}
	return app, created, nil
}

// GetApp returns the app or ErrNotFound.
func (s *Store) GetApp(ctx context.Context, name string) (App, error) {
	var app App
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		a, err := scanAppTx(ctx, tx, name)
		app = a
		return err
	})
	return app, err
}

// ListApps returns every app ordered by name.
func (s *Store) ListApps(ctx context.Context) ([]App, error) {
	rows, err := s.db.QueryContext(ctx, appSelect+` FROM apps ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list apps: %w", err)
	}
	defer rows.Close()
	var out []App
	for rows.Next() {
		a, err := scanAppRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpdateApp reads, applies fn, and writes the app in one transaction. Name,
// CreatedAt and PublicPort are immutable: any change fn makes to them is
// ignored (the stored values are preserved).
func (s *Store) UpdateApp(ctx context.Context, name string, fn func(*App) error) (App, error) {
	var app App
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		current, err := scanAppTx(ctx, tx, name)
		if err != nil {
			return err
		}
		draft := current
		if err := fn(&draft); err != nil {
			return err
		}
		// Enforce immutable columns.
		draft.Name = current.Name
		draft.CreatedAt = current.CreatedAt
		draft.PublicPort = current.PublicPort
		if draft.Desired != DesiredRunning && draft.Desired != DesiredStopped {
			return fmt.Errorf("%w: desired %q", ErrInvalid, draft.Desired)
		}
		if draft.Port < 0 || draft.MemoryMB <= 0 || draft.CPUMilli <= 0 {
			return fmt.Errorf("%w: invalid app fields", ErrInvalid)
		}
		if draft.HealthPath == "" {
			draft.HealthPath = DefaultHealthPath
		}
		draft.UpdatedAt = time.Now().UTC()
		_, err = tx.ExecContext(ctx, `UPDATE apps SET
			desired=?, port=?, health_path=?, current_deployment=?, memory_mb=?, cpu_milli=?, updated_at=?
			WHERE name=?`,
			draft.Desired, draft.Port, draft.HealthPath, draft.CurrentDeployment,
			draft.MemoryMB, draft.CPUMilli, formatTime(draft.UpdatedAt), name)
		if err != nil {
			return fmt.Errorf("update app: %w", err)
		}
		app, err = scanAppTx(ctx, tx, name)
		return err
	})
	return app, err
}

// DeleteApp removes an app and its related SQL records, including volume
// records (ON DELETE CASCADE). keepVolumes is retained for caller compatibility;
// this store never deletes Docker volumes. The caller handles Docker cleanup
// and must delete requested volumes before removing the app record.
func (s *Store) DeleteApp(ctx context.Context, name string, keepVolumes bool) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		// Ensure the app exists.
		if _, err := scanAppTx(ctx, tx, name); err != nil {
			return err
		}

		// Delete related data in dependency order (foreign keys are ON DELETE CASCADE
		// from the schema, but we make it explicit here for clarity).
		if _, err := tx.ExecContext(ctx, `DELETE FROM events WHERE app=?`, name); err != nil {
			return fmt.Errorf("delete events: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM app_domains WHERE app=?`, name); err != nil {
			return fmt.Errorf("delete domains: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM app_env WHERE app=?`, name); err != nil {
			return fmt.Errorf("delete env: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM addons WHERE app=?`, name); err != nil {
			return fmt.Errorf("delete addons: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM deployments WHERE app=?`, name); err != nil {
			return fmt.Errorf("delete deployments: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM apps WHERE name=?`, name); err != nil {
			return fmt.Errorf("delete app: %w", err)
		}
		return nil
	})
}

// SetCurrentDeployment atomically retires the previous live deployment (keeping
// its FinishedAt), marks deploymentID live, and points apps.current_deployment
// at it.
func (s *Store) SetCurrentDeployment(ctx context.Context, app, deploymentID string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		a, err := scanAppTx(ctx, tx, app)
		if err != nil {
			return err
		}
		d, err := scanDeploymentTx(ctx, tx, deploymentID)
		if err != nil {
			return err
		}
		if d.App != app {
			return fmt.Errorf("%w: deployment %s is not in app %s", ErrInvalid, deploymentID, app)
		}
		now := time.Now().UTC()
		nowText := formatTime(now)
		// Retire the previous live deployment, if any and different.
		if a.CurrentDeployment != "" && a.CurrentDeployment != deploymentID {
			if _, err := tx.ExecContext(ctx, `UPDATE deployments
				SET status=?, updated_at=?, finished_at=COALESCE(finished_at, ?)
				WHERE id=? AND status=?`,
				StatusRetired, nowText, nowText, a.CurrentDeployment, StatusLive); err != nil {
				return fmt.Errorf("retire previous: %w", err)
			}
		}
		// Promote the new deployment to live.
		if _, err := tx.ExecContext(ctx, `UPDATE deployments
			SET status=?, updated_at=?
			WHERE id=?`, StatusLive, nowText, deploymentID); err != nil {
			return fmt.Errorf("promote deployment: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE apps SET current_deployment=?, updated_at=? WHERE name=?`,
			deploymentID, nowText, app); err != nil {
			return fmt.Errorf("set current deployment: %w", err)
		}
		return nil
	})
}

// -------- Deployments --------

// CreateDeployment inserts a queued deployment, or returns the existing one
// (bool=false) when the request is idempotent:
//   - RequestKey matches an existing deployment of the app, or
//   - the newest pending-or-live deployment of the app has the same SourceDigest.
func (s *Store) CreateDeployment(ctx context.Context, in NewDeployment) (Deployment, bool, error) {
	if !ValidAppName(in.App) {
		return Deployment{}, false, fmt.Errorf("%w: app name %q", ErrInvalid, in.App)
	}
	if in.SourceKind != SourceUpload && in.SourceKind != SourceImage && in.SourceKind != SourceGit {
		return Deployment{}, false, fmt.Errorf("%w: source kind %q", ErrInvalid, in.SourceKind)
	}
	var (
		dep     Deployment
		created bool
	)
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := scanAppTx(ctx, tx, in.App); err != nil {
			return err
		}
		// Idempotency by request key. Only a pending or live deployment is
		// returned as-is; once the earlier one has ended (failed, retired,
		// superseded) the same request means "deploy this again", so its key is
		// released and a new deployment is created below. Otherwise fixing the
		// server and re-running `deploy` on unchanged code would keep returning
		// the old failure.
		if in.RequestKey != "" {
			existing, err := scanDeploymentByRequestKeyTx(ctx, tx, in.App, in.RequestKey)
			switch {
			case err == nil && !deploymentEnded(existing.Status):
				dep = existing
				return nil
			case err == nil:
				if _, err := tx.ExecContext(ctx, `UPDATE deployments SET request_key='' WHERE id=?`, existing.ID); err != nil {
					return fmt.Errorf("release request key: %w", err)
				}
			case !errors.Is(err, ErrNotFound):
				return err
			}
		}
		// Idempotency by digest of the newest pending-or-live deployment.
		// Skip this check when BypassDedup is true (used by redeploy).
		if in.SourceDigest != "" && !in.BypassDedup {
			newest, err := scanNewestPendingOrLiveTx(ctx, tx, in.App)
			if err == nil && newest.SourceDigest == in.SourceDigest {
				dep = newest
				return nil
			}
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
		}

		var maxSeq sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT MAX(seq) FROM deployments WHERE app=?`, in.App).Scan(&maxSeq); err != nil {
			return fmt.Errorf("query max seq: %w", err)
		}
		seq := int(maxSeq.Int64) + 1

		id, err := newDeploymentID(ctx, tx)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		nowText := formatTime(now)
		_, err = tx.ExecContext(ctx, `INSERT INTO deployments
			(id, app, seq, source_kind, source_ref, source_digest, request_key, image_id, status, attempts, diagnosis, warnings, created_at, updated_at, finished_at, based_on_seq, origin_kind, reason)
			VALUES (?, ?, ?, ?, ?, ?, ?, '', ?, 0, '', '', ?, ?, NULL, ?, ?, ?)`,
			id, in.App, seq, in.SourceKind, in.SourceRef, in.SourceDigest, in.RequestKey, StatusQueued, nowText, nowText,
			in.BasedOnSeq, in.OriginKind, in.Reason)
		if err != nil {
			return fmt.Errorf("insert deployment: %w", err)
		}
		created = true
		dep, err = scanDeploymentTx(ctx, tx, id)
		return err
	})
	if err != nil {
		return Deployment{}, false, err
	}
	return dep, created, nil
}

// GetDeployment returns one deployment or ErrNotFound.
func (s *Store) GetDeployment(ctx context.Context, id string) (Deployment, error) {
	var d Deployment
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		got, err := scanDeploymentTx(ctx, tx, id)
		d = got
		return err
	})
	return d, err
}

// ListDeployments returns deployments of an app, newest first, up to limit
// (limit <= 0 means no limit).
func (s *Store) ListDeployments(ctx context.Context, app string, limit int) ([]Deployment, error) {
	q := deploymentSelect + ` FROM deployments WHERE app=? ORDER BY seq DESC`
	args := []any{app}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	defer rows.Close()
	return scanDeploymentRows(rows)
}

// PendingDeployments returns the pending deployments of an app, oldest first.
func (s *Store) PendingDeployments(ctx context.Context, app string) ([]Deployment, error) {
	rows, err := s.db.QueryContext(ctx, deploymentSelect+`
		FROM deployments
		WHERE app=? AND status IN (?,?,?,?,?)
		ORDER BY seq ASC`,
		app, StatusQueued, StatusBuilding, StatusStarting, StatusChecking, StatusRouting)
	if err != nil {
		return nil, fmt.Errorf("pending deployments: %w", err)
	}
	defer rows.Close()
	return scanDeploymentRows(rows)
}

// UpdateDeployment reads, applies fn, and writes one deployment. It sets
// UpdatedAt, sets FinishedAt when the status becomes terminal, and rejects any
// attempt to leave a terminal status with ErrConflict.
func (s *Store) UpdateDeployment(ctx context.Context, id string, fn func(*Deployment) error) (Deployment, error) {
	var dep Deployment
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		current, err := scanDeploymentTx(ctx, tx, id)
		if err != nil {
			return err
		}
		if terminalStatuses[current.Status] {
			return fmt.Errorf("%w: deployment %s is already terminal (%s)", ErrConflict, id, current.Status)
		}
		draft := current
		if err := fn(&draft); err != nil {
			return err
		}
		// Immutable identity columns.
		draft.ID = current.ID
		draft.App = current.App
		draft.Seq = current.Seq
		draft.CreatedAt = current.CreatedAt
		draft.RequestKey = current.RequestKey

		now := time.Now().UTC()
		draft.UpdatedAt = now
		if terminalStatuses[draft.Status] {
			if draft.FinishedAt == nil {
				t := now
				draft.FinishedAt = &t
			}
		} else {
			// Non-terminal statuses never carry a finish time.
			draft.FinishedAt = nil
		}

		diagText, err := marshalDiagnosis(draft.Diagnosis)
		if err != nil {
			return err
		}
		warnText, err := marshalWarnings(draft.Warnings)
		if err != nil {
			return err
		}
		var finishedText any
		if draft.FinishedAt != nil {
			finishedText = formatTime(*draft.FinishedAt)
		}
		_, err = tx.ExecContext(ctx, `UPDATE deployments SET
			source_ref=?, source_digest=?, image_id=?, status=?, attempts=?, diagnosis=?, warnings=?, updated_at=?, finished_at=?
			WHERE id=?`,
			draft.SourceRef, draft.SourceDigest, draft.ImageID, draft.Status, draft.Attempts,
			diagText, warnText, formatTime(draft.UpdatedAt), finishedText, id)
		if err != nil {
			return fmt.Errorf("update deployment: %w", err)
		}
		dep, err = scanDeploymentTx(ctx, tx, id)
		return err
	})
	return dep, err
}

// KeptImageDeployments returns the deployments whose images must be kept: the
// current live deployment plus the newest KeepVersions retired deployments that
// have an ImageID. Everything else may be garbage collected.
func (s *Store) KeptImageDeployments(ctx context.Context, app string) ([]Deployment, error) {
	var out []Deployment
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		a, err := scanAppTx(ctx, tx, app)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		if a.CurrentDeployment != "" {
			live, err := scanDeploymentTx(ctx, tx, a.CurrentDeployment)
			if err == nil {
				out = append(out, live)
				seen[live.ID] = true
			} else if !errors.Is(err, ErrNotFound) {
				return err
			}
		}
		rows, err := tx.QueryContext(ctx, deploymentSelect+`
			FROM deployments
			WHERE app=? AND status=? AND image_id<>''
			ORDER BY seq DESC
			LIMIT ?`, app, StatusRetired, KeepVersions)
		if err != nil {
			return fmt.Errorf("kept image deployments: %w", err)
		}
		defer rows.Close()
		kept, err := scanDeploymentRows(rows)
		if err != nil {
			return err
		}
		for _, d := range kept {
			if !seen[d.ID] {
				out = append(out, d)
				seen[d.ID] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// -------- Env, volumes, add-ons --------

// SetEnv inserts or replaces one environment variable. The key must match
// ^[A-Za-z_][A-Za-z0-9_]{0,127}$.
func (s *Store) SetEnv(ctx context.Context, v EnvVar) error {
	if !envKeyPattern.MatchString(v.Key) {
		return fmt.Errorf("%w: env key %q", ErrInvalid, v.Key)
	}
	secret := 0
	if v.Secret {
		secret = 1
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := scanAppTx(ctx, tx, v.App); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO app_env (app, key, value, secret)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(app, key) DO UPDATE SET value=excluded.value, secret=excluded.secret`,
			v.App, v.Key, v.Value, secret)
		if err != nil {
			return fmt.Errorf("set env: %w", err)
		}
		return nil
	})
}

// DeleteEnv removes one environment variable. Deleting a missing key is a no-op.
func (s *Store) DeleteEnv(ctx context.Context, app, key string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := scanAppTx(ctx, tx, app); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM app_env WHERE app=? AND key=?`, app, key); err != nil {
			return fmt.Errorf("delete env: %w", err)
		}
		return nil
	})
}

// ListEnv returns all environment variables of an app, including secret values,
// ordered by key.
func (s *Store) ListEnv(ctx context.Context, app string) ([]EnvVar, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT app, key, value, secret FROM app_env WHERE app=? ORDER BY key`, app)
	if err != nil {
		return nil, fmt.Errorf("list env: %w", err)
	}
	defer rows.Close()
	var out []EnvVar
	for rows.Next() {
		var e EnvVar
		var secret int
		if err := rows.Scan(&e.App, &e.Key, &e.Value, &secret); err != nil {
			return nil, fmt.Errorf("scan env: %w", err)
		}
		e.Secret = secret != 0
		out = append(out, e)
	}
	return out, rows.Err()
}

// AddVolume records a persisted directory for an app. It is idempotent per
// (app, path): a second call with the same path returns the existing volume
// (bool=false) without allocating a new name. Names af-<app>-<n> use a
// per-app counter that never reuses a value.
func (s *Store) AddVolume(ctx context.Context, app, path string, auto bool) (Volume, bool, error) {
	if !filepath.IsAbs(path) || path != filepath.Clean(path) {
		return Volume{}, false, fmt.Errorf("%w: volume path %q must be absolute and clean", ErrInvalid, path)
	}
	var (
		vol     Volume
		created bool
	)
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := scanAppTx(ctx, tx, app); err != nil {
			return err
		}
		existing, err := scanVolumeTx(ctx, tx, app, path)
		if err == nil {
			vol = existing
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		// Allocate the next per-app counter value; never reuse.
		var seq int
		if err := tx.QueryRowContext(ctx, `UPDATE apps SET volume_seq = volume_seq + 1 WHERE name=? RETURNING volume_seq`, app).Scan(&seq); err != nil {
			return fmt.Errorf("increment volume_seq: %w", err)
		}
		name := fmt.Sprintf("af-%s-%d", app, seq)
		autoInt := 0
		if auto {
			autoInt = 1
		}
		nowText := formatTime(time.Now().UTC())
		if _, err := tx.ExecContext(ctx, `INSERT INTO app_volumes (app, path, volume_name, auto, created_at)
			VALUES (?, ?, ?, ?, ?)`, app, path, name, autoInt, nowText); err != nil {
			return fmt.Errorf("insert volume: %w", err)
		}
		created = true
		vol, err = scanVolumeTx(ctx, tx, app, path)
		return err
	})
	if err != nil {
		return Volume{}, false, err
	}
	return vol, created, nil
}

// ListVolumes returns all volumes of an app, ordered by path.
func (s *Store) ListVolumes(ctx context.Context, app string) ([]Volume, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT app, path, volume_name, auto, created_at FROM app_volumes WHERE app=? ORDER BY path`, app)
	if err != nil {
		return nil, fmt.Errorf("list volumes: %w", err)
	}
	defer rows.Close()
	var out []Volume
	for rows.Next() {
		var v Volume
		var auto int
		var createdText string
		if err := rows.Scan(&v.App, &v.Path, &v.VolumeName, &auto, &createdText); err != nil {
			return nil, fmt.Errorf("scan volume: %w", err)
		}
		v.Auto = auto != 0
		if v.CreatedAt, err = parseTime(createdText); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ListAddons returns all add-ons of an app that are not soft-deleted, ordered by kind.
func (s *Store) ListAddons(ctx context.Context, app string) ([]Addon, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT app, kind, image, volume_name, credentials, env_var, created_at FROM addons WHERE app=? AND removed_at IS NULL ORDER BY kind`, app)
	if err != nil {
		return nil, fmt.Errorf("list addons: %w", err)
	}
	defer rows.Close()
	var out []Addon
	for rows.Next() {
		var a Addon
		var creds, createdText string
		if err := rows.Scan(&a.App, &a.Kind, &a.Image, &a.VolumeName, &creds, &a.EnvVar, &createdText); err != nil {
			return nil, fmt.Errorf("scan addon: %w", err)
		}
		if creds != "" {
			a.Credentials = json.RawMessage(creds)
		}
		if a.CreatedAt, err = parseTime(createdText); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListRemovedAddons returns all soft-deleted add-ons of an app, ordered by kind.
func (s *Store) ListRemovedAddons(ctx context.Context, app string) ([]Addon, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT app, kind, image, volume_name, credentials, env_var, created_at FROM addons WHERE app=? AND removed_at IS NOT NULL ORDER BY kind`, app)
	if err != nil {
		return nil, fmt.Errorf("list removed addons: %w", err)
	}
	defer rows.Close()
	var out []Addon
	for rows.Next() {
		var a Addon
		var creds, createdText string
		if err := rows.Scan(&a.App, &a.Kind, &a.Image, &a.VolumeName, &creds, &a.EnvVar, &createdText); err != nil {
			return nil, fmt.Errorf("scan addon: %w", err)
		}
		if creds != "" {
			a.Credentials = json.RawMessage(creds)
		}
		if a.CreatedAt, err = parseTime(createdText); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AddAddon records an add-on for an app. If a soft-deleted add-on of the same
// kind exists, it is restored with its existing credentials (returned via reused=true).
// It returns ErrNotFound when the app is missing, ErrInvalid for malformed input,
// and ErrConflict when the app already has an active add-on of that kind or another
// add-on providing the same env var.
func (s *Store) AddAddon(ctx context.Context, addon Addon) (reused bool, err error) {
	if !ValidAddonKind(addon.Kind) || addon.Image == "" || addon.VolumeName == "" ||
		!envKeyPattern.MatchString(addon.EnvVar) || !json.Valid(addon.Credentials) {
		return false, fmt.Errorf("%w: addon %s/%s", ErrInvalid, addon.App, addon.Kind)
	}
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := scanAppTx(ctx, tx, addon.App); err != nil {
			return err
		}

		// Restoring an add-on keeps its pinned image, volume, env var and credentials.
		var existingKind, existingEnvVar string
		var removedAt sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT kind, env_var, removed_at FROM addons WHERE app=? AND kind=? LIMIT 1`,
			addon.App, addon.Kind).Scan(&existingKind, &existingEnvVar, &removedAt)
		restore := err == nil && removedAt.Valid
		if err == nil && !restore {
			return fmt.Errorf("%w: app %s already has addon %s", ErrConflict, addon.App, existingKind)
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("check addon conflict: %w", err)
		}

		envVar := addon.EnvVar
		if restore {
			envVar = existingEnvVar
		}
		var conflictKind string
		err = tx.QueryRowContext(ctx, `SELECT kind FROM addons WHERE app=? AND env_var=? AND removed_at IS NULL LIMIT 1`,
			addon.App, envVar).Scan(&conflictKind)
		if err == nil {
			return fmt.Errorf("%w: app %s already has addon %s providing %s", ErrConflict, addon.App, conflictKind, envVar)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("check env var conflict: %w", err)
		}
		if restore {
			if _, err := tx.ExecContext(ctx, `UPDATE addons SET removed_at=NULL WHERE app=? AND kind=?`, addon.App, addon.Kind); err != nil {
				return fmt.Errorf("restore addon: %w", err)
			}
			reused = true
			return nil
		}

		createdAt := addon.CreatedAt
		if createdAt.IsZero() {
			createdAt = s.nowUTC()
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO addons (app, kind, image, volume_name, credentials, env_var, created_at, removed_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
			addon.App, addon.Kind, addon.Image, addon.VolumeName, string(addon.Credentials), addon.EnvVar, formatTime(createdAt)); err != nil {
			return fmt.Errorf("insert addon: %w", err)
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return reused, nil
}

// RemoveAddon soft-deletes or hard-deletes the add-on record of kind from app.
// When deleteVolume is false, it soft-deletes (sets removed_at); when true, it
// hard-deletes. It returns ErrNotFound when no such add-on exists.
func (s *Store) RemoveAddon(ctx context.Context, app, kind string, deleteVolume bool) error {
	if deleteVolume {
		res, err := s.db.ExecContext(ctx, `DELETE FROM addons WHERE app=? AND kind=?`, app, kind)
		if err != nil {
			return fmt.Errorf("delete addon: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("delete addon: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("%w: addon %s/%s", ErrNotFound, app, kind)
		}
	} else {
		now := formatTime(s.nowUTC())
		res, err := s.db.ExecContext(ctx, `UPDATE addons SET removed_at=? WHERE app=? AND kind=? AND removed_at IS NULL`, now, app, kind)
		if err != nil {
			return fmt.Errorf("soft delete addon: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("soft delete addon: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("%w: addon %s/%s", ErrNotFound, app, kind)
		}
	}
	return nil
}

// -------- Events --------

// AddEvent appends one history line. The id column is autoincrement.
func (s *Store) AddEvent(ctx context.Context, e Event) error {
	at := e.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO events (app, deployment_id, at, stage, message)
		VALUES (?, ?, ?, ?, ?)`, e.App, e.DeploymentID, formatTime(at), e.Stage, e.Message)
	if err != nil {
		return fmt.Errorf("add event: %w", err)
	}
	return nil
}

// ListEvents returns events for an app (and optionally a deployment) with id
// greater than afterID, oldest first, up to limit (limit <= 0 means no limit).
func (s *Store) ListEvents(ctx context.Context, app, deploymentID string, afterID int64, limit int) ([]Event, error) {
	q := `SELECT id, app, deployment_id, at, stage, message FROM events WHERE app=? AND id>?`
	args := []any{app, afterID}
	if deploymentID != "" {
		q += ` AND deployment_id=?`
		args = append(args, deploymentID)
	}
	q += ` ORDER BY id ASC`
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var atText string
		if err := rows.Scan(&e.ID, &e.App, &e.DeploymentID, &atText, &e.Stage, &e.Message); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		if e.At, err = parseTime(atText); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// -------- helpers --------

// inTx runs fn in an immediate write transaction and commits on success.
func (s *Store) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

const appSelect = `SELECT name, desired, port, health_path, public_port, current_deployment, memory_mb, cpu_milli, created_at, updated_at`

// rowScanner abstracts *sql.Row and *sql.Rows for shared scanning.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanAppFrom(sc rowScanner) (App, error) {
	var a App
	var createdText, updatedText string
	if err := sc.Scan(&a.Name, &a.Desired, &a.Port, &a.HealthPath, &a.PublicPort,
		&a.CurrentDeployment, &a.MemoryMB, &a.CPUMilli, &createdText, &updatedText); err != nil {
		return App{}, err
	}
	var err error
	if a.CreatedAt, err = parseTime(createdText); err != nil {
		return App{}, err
	}
	if a.UpdatedAt, err = parseTime(updatedText); err != nil {
		return App{}, err
	}
	return a, nil
}

func scanAppRow(rows *sql.Rows) (App, error) { return scanAppFrom(rows) }

func scanAppTx(ctx context.Context, tx *sql.Tx, name string) (App, error) {
	row := tx.QueryRowContext(ctx, appSelect+` FROM apps WHERE name=?`, name)
	a, err := scanAppFrom(row)
	if errors.Is(err, sql.ErrNoRows) {
		return App{}, ErrNotFound
	}
	if err != nil {
		return App{}, fmt.Errorf("scan app: %w", err)
	}
	return a, nil
}

func allocatePortTx(ctx context.Context, tx *sql.Tx, minPort, maxPort int) (int, error) {
	used := map[int]bool{}
	rows, err := tx.QueryContext(ctx, `SELECT public_port FROM apps`)
	if err != nil {
		return 0, fmt.Errorf("query used ports: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			return 0, fmt.Errorf("scan port: %w", err)
		}
		used[p] = true
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for p := minPort; p <= maxPort; p++ {
		if !used[p] {
			return p, nil
		}
	}
	return 0, fmt.Errorf("%w: public port range [%d,%d] exhausted", ErrConflict, minPort, maxPort)
}

const deploymentSelect = `SELECT id, app, seq, source_kind, source_ref, source_digest, request_key, image_id, status, attempts, diagnosis, warnings, created_at, updated_at, finished_at, based_on_seq, origin_kind, reason`

func scanDeploymentFrom(sc rowScanner) (Deployment, error) {
	var d Deployment
	var diagText, warnText, createdText, updatedText string
	var finishedText sql.NullString
	if err := sc.Scan(&d.ID, &d.App, &d.Seq, &d.SourceKind, &d.SourceRef, &d.SourceDigest,
		&d.RequestKey, &d.ImageID, &d.Status, &d.Attempts, &diagText, &warnText,
		&createdText, &updatedText, &finishedText, &d.BasedOnSeq, &d.OriginKind, &d.Reason); err != nil {
		return Deployment{}, err
	}
	var err error
	if d.Diagnosis, err = unmarshalDiagnosis(diagText); err != nil {
		return Deployment{}, err
	}
	if d.Warnings, err = unmarshalWarnings(warnText); err != nil {
		return Deployment{}, err
	}
	if d.CreatedAt, err = parseTime(createdText); err != nil {
		return Deployment{}, err
	}
	if d.UpdatedAt, err = parseTime(updatedText); err != nil {
		return Deployment{}, err
	}
	if finishedText.Valid {
		t, err := parseTime(finishedText.String)
		if err != nil {
			return Deployment{}, err
		}
		d.FinishedAt = &t
	}
	return d, nil
}

func scanDeploymentTx(ctx context.Context, tx *sql.Tx, id string) (Deployment, error) {
	row := tx.QueryRowContext(ctx, deploymentSelect+` FROM deployments WHERE id=?`, id)
	d, err := scanDeploymentFrom(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Deployment{}, ErrNotFound
	}
	if err != nil {
		return Deployment{}, fmt.Errorf("scan deployment: %w", err)
	}
	return d, nil
}

func scanDeploymentByRequestKeyTx(ctx context.Context, tx *sql.Tx, app, key string) (Deployment, error) {
	row := tx.QueryRowContext(ctx, deploymentSelect+` FROM deployments WHERE app=? AND request_key=?`, app, key)
	d, err := scanDeploymentFrom(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Deployment{}, ErrNotFound
	}
	if err != nil {
		return Deployment{}, fmt.Errorf("scan deployment by request key: %w", err)
	}
	return d, nil
}

// deploymentEnded reports whether a deployment is finished and not serving:
// the complement of the pending-or-live set used for digest dedup.
func deploymentEnded(status string) bool {
	return status == StatusFailed || status == StatusRetired || status == StatusSuperseded
}

func scanNewestPendingOrLiveTx(ctx context.Context, tx *sql.Tx, app string) (Deployment, error) {
	row := tx.QueryRowContext(ctx, deploymentSelect+`
		FROM deployments
		WHERE app=? AND status IN (?,?,?,?,?,?)
		ORDER BY seq DESC
		LIMIT 1`,
		app, StatusQueued, StatusBuilding, StatusStarting, StatusChecking, StatusRouting, StatusLive)
	d, err := scanDeploymentFrom(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Deployment{}, ErrNotFound
	}
	if err != nil {
		return Deployment{}, fmt.Errorf("scan newest deployment: %w", err)
	}
	return d, nil
}

func scanDeploymentRows(rows *sql.Rows) ([]Deployment, error) {
	var out []Deployment
	for rows.Next() {
		d, err := scanDeploymentFrom(rows)
		if err != nil {
			return nil, fmt.Errorf("scan deployment row: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func scanVolumeTx(ctx context.Context, tx *sql.Tx, app, path string) (Volume, error) {
	row := tx.QueryRowContext(ctx, `SELECT app, path, volume_name, auto, created_at FROM app_volumes WHERE app=? AND path=?`, app, path)
	var v Volume
	var auto int
	var createdText string
	if err := row.Scan(&v.App, &v.Path, &v.VolumeName, &auto, &createdText); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Volume{}, ErrNotFound
		}
		return Volume{}, fmt.Errorf("scan volume: %w", err)
	}
	v.Auto = auto != 0
	var err error
	if v.CreatedAt, err = parseTime(createdText); err != nil {
		return Volume{}, err
	}
	return v, nil
}

// newDeploymentID returns a 12-hex-char ID that is unique in the deployments
// table.
func newDeploymentID(ctx context.Context, tx *sql.Tx) (string, error) {
	for attempt := 0; attempt < 16; attempt++ {
		var buf [6]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return "", fmt.Errorf("random id: %w", err)
		}
		id := hex.EncodeToString(buf[:])
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM deployments WHERE id=?)`, id).Scan(&exists); err != nil {
			return "", fmt.Errorf("check id uniqueness: %w", err)
		}
		if !exists {
			return id, nil
		}
	}
	return "", fmt.Errorf("%w: could not allocate unique deployment id", ErrConflict)
}

// marshalDiagnosis encodes a diagnosis to JSON text ("" when nil).
func marshalDiagnosis(d *Diagnosis) (string, error) {
	if d == nil {
		return "", nil
	}
	b, err := json.Marshal(d)
	if err != nil {
		return "", fmt.Errorf("marshal diagnosis: %w", err)
	}
	return string(b), nil
}

func unmarshalDiagnosis(s string) (*Diagnosis, error) {
	if s == "" {
		return nil, nil
	}
	var d Diagnosis
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		return nil, fmt.Errorf("unmarshal diagnosis: %w", err)
	}
	return &d, nil
}

// marshalWarnings encodes warnings to JSON text ("" when empty).
func marshalWarnings(w []Diagnosis) (string, error) {
	if len(w) == 0 {
		return "", nil
	}
	b, err := json.Marshal(w)
	if err != nil {
		return "", fmt.Errorf("marshal warnings: %w", err)
	}
	return string(b), nil
}

func unmarshalWarnings(s string) ([]Diagnosis, error) {
	if s == "" {
		return nil, nil
	}
	var w []Diagnosis
	if err := json.Unmarshal([]byte(s), &w); err != nil {
		return nil, fmt.Errorf("unmarshal warnings: %w", err)
	}
	return w, nil
}

// deploymentIDValid reports whether id is 12 lowercase hex characters. Kept for
// callers (server/reconciler) that validate IDs before lookups.
func deploymentIDValid(id string) bool { return deploymentIDPattern.MatchString(id) }

var _ = deploymentIDValid
