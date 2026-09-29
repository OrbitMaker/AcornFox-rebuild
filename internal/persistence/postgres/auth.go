package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

var ErrCredentialVersionConflict = domain.ErrCredentialVersionConflict

func (s *Store) AdministratorExists(ctx context.Context) (bool, error) {
	if err := s.requireDB(); err != nil {
		return false, err
	}
	var exists bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM admin_credentials)`).Scan(&exists); err != nil {
		return false, fmt.Errorf("inspect administrator records: %w", err)
	}
	return exists, nil
}

func (s *Store) CreateAdminCredential(ctx context.Context, credential domain.AdminCredential) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	if err := credential.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO admin_credentials
			(id, password_hash_scheme, password_hash, credential_version, disabled_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, credential.ID.String(), credential.PasswordHashScheme, credential.PasswordHash, credential.CredentialVersion, credential.DisabledAt, credential.CreatedAt.UTC(), credential.UpdatedAt.UTC())
	if err != nil {
		return fmt.Errorf("create administrator credential: %w", err)
	}
	return nil
}

func (s *Store) ActiveAdminCredential(ctx context.Context) (domain.AdminCredential, error) {
	if err := s.requireDB(); err != nil {
		return domain.AdminCredential{}, err
	}
	credential, err := scanAdminCredential(s.db.QueryRowContext(ctx, `
		SELECT id, password_hash_scheme, password_hash, credential_version, disabled_at, created_at, updated_at
		  FROM admin_credentials
		 WHERE disabled_at IS NULL
	`))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AdminCredential{}, ErrNotFound
	}
	if err != nil {
		return domain.AdminCredential{}, fmt.Errorf("read active administrator credential: %w", err)
	}
	return credential, nil
}

func (s *Store) RotateAdminCredential(ctx context.Context, adminID domain.ID, expectedVersion int64, passwordHashScheme, passwordHash string, now time.Time) (domain.AdminCredential, error) {
	if err := s.requireDB(); err != nil {
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
	credential, err := scanAdminCredential(s.db.QueryRowContext(ctx, `
		UPDATE admin_credentials
		   SET password_hash_scheme = $3,
		       password_hash = $4,
		       credential_version = credential_version + 1,
		       updated_at = $5
		 WHERE id = $1
		   AND credential_version = $2
		   AND disabled_at IS NULL
		 RETURNING id, password_hash_scheme, password_hash, credential_version, disabled_at, created_at, updated_at
	`, adminID.String(), expectedVersion, passwordHashScheme, passwordHash, now.UTC()))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AdminCredential{}, ErrCredentialVersionConflict
	}
	if err != nil {
		return domain.AdminCredential{}, fmt.Errorf("rotate administrator credential: %w", err)
	}
	if err := credential.Validate(); err != nil {
		return domain.AdminCredential{}, fmt.Errorf("rotated administrator credential: %w", err)
	}
	return credential, nil
}

func (s *Store) CreateAdminSession(ctx context.Context, session domain.AdminSession) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	if err := session.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO admin_sessions
			(id, admin_id, session_digest, csrf_digest, credential_version, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, session.ID.String(), session.AdminID.String(), session.SessionDigest.String(), session.CSRFDigest.String(), session.CredentialVersion, session.CreatedAt.UTC(), session.LastSeenAt.UTC(), session.IdleExpiresAt.UTC(), session.AbsoluteExpiresAt.UTC(), session.RevokedAt)
	if err != nil {
		return fmt.Errorf("create administrator session: %w", err)
	}
	return nil
}

func (s *Store) ActiveAdminSessionByDigest(ctx context.Context, digest domain.AuthDigest, now time.Time) (domain.AdminSession, error) {
	if err := s.requireDB(); err != nil {
		return domain.AdminSession{}, err
	}
	if err := digest.Validate("session digest"); err != nil {
		return domain.AdminSession{}, err
	}
	if now.IsZero() {
		return domain.AdminSession{}, domain.ValidationError("session lookup time is required")
	}
	session, err := scanAdminSession(s.db.QueryRowContext(ctx, `
		SELECT s.id, s.admin_id, s.session_digest, s.csrf_digest, s.credential_version,
		       s.created_at, s.last_seen_at, s.idle_expires_at, s.absolute_expires_at, s.revoked_at
		  FROM admin_sessions s
		  JOIN admin_credentials a ON a.id = s.admin_id
		 WHERE s.session_digest = $1
		   AND s.revoked_at IS NULL
		   AND a.disabled_at IS NULL
		   AND a.credential_version = s.credential_version
		   AND s.idle_expires_at > $2
		   AND s.absolute_expires_at > $2
	`, digest.String(), now.UTC()))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AdminSession{}, ErrNotFound
	}
	if err != nil {
		return domain.AdminSession{}, fmt.Errorf("read active administrator session: %w", err)
	}
	return session, nil
}

// TouchAdminSession advances the idle deadline only while the same credential
// version remains active. The absolute expiry stays fixed at session creation.
func (s *Store) TouchAdminSession(ctx context.Context, sessionID domain.ID, credentialVersion int64, now time.Time) (domain.AdminSession, error) {
	if err := s.requireDB(); err != nil {
		return domain.AdminSession{}, err
	}
	if err := domain.RequireID(sessionID, "administrator session id"); err != nil {
		return domain.AdminSession{}, err
	}
	if credentialVersion < 1 || now.IsZero() {
		return domain.AdminSession{}, domain.ValidationError("session touch identity or time is invalid")
	}
	session, err := scanAdminSession(s.db.QueryRowContext(ctx, `
		UPDATE admin_sessions s
		   SET last_seen_at = $3,
		       idle_expires_at = LEAST($3 + INTERVAL '8 hours', s.absolute_expires_at)
		  FROM admin_credentials a
		 WHERE s.id = $1
		   AND s.credential_version = $2
		   AND a.id = s.admin_id
		   AND a.disabled_at IS NULL
		   AND a.credential_version = s.credential_version
		   AND s.revoked_at IS NULL
		   AND s.idle_expires_at > $3
		   AND s.absolute_expires_at > $3
		 RETURNING s.id, s.admin_id, s.session_digest, s.csrf_digest, s.credential_version,
		           s.created_at, s.last_seen_at, s.idle_expires_at, s.absolute_expires_at, s.revoked_at
	`, sessionID.String(), credentialVersion, now.UTC()))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AdminSession{}, ErrNotFound
	}
	if err != nil {
		return domain.AdminSession{}, fmt.Errorf("touch administrator session: %w", err)
	}
	return session, nil
}

func (s *Store) RevokeAdminSession(ctx context.Context, sessionID domain.ID, revokedAt time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	if err := domain.RequireID(sessionID, "administrator session id"); err != nil {
		return err
	}
	if revokedAt.IsZero() {
		return domain.ValidationError("session revocation time is required")
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE admin_sessions
		   SET revoked_at = COALESCE(revoked_at, $2)
		 WHERE id = $1
	`, sessionID.String(), revokedAt.UTC())
	if err != nil {
		return fmt.Errorf("revoke administrator session: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect administrator session revocation: %w", err)
	}
	if count != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) UpsertAdminLoginRateLimit(ctx context.Context, record domain.AdminLoginRateLimit) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	if err := record.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO admin_login_rate_limits
			(admin_id, source_digest, window_started_at, window_expires_at, failure_count, last_failure_at, locked_at, locked_until, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (admin_id, source_digest) DO UPDATE
		   SET window_started_at = EXCLUDED.window_started_at,
		       window_expires_at = EXCLUDED.window_expires_at,
		       failure_count = EXCLUDED.failure_count,
		       last_failure_at = EXCLUDED.last_failure_at,
		       locked_at = EXCLUDED.locked_at,
		       locked_until = EXCLUDED.locked_until,
		       updated_at = EXCLUDED.updated_at
	`, record.AdminID.String(), record.SourceDigest.String(), record.WindowStartedAt.UTC(), record.WindowExpiresAt.UTC(), record.FailureCount, record.LastFailureAt.UTC(), record.LockedAt, record.LockedUntil, record.UpdatedAt.UTC())
	if err != nil {
		return fmt.Errorf("upsert administrator login rate limit: %w", err)
	}
	return nil
}

func (s *Store) AdminLoginRateLimit(ctx context.Context, adminID domain.ID, sourceDigest domain.AuthDigest) (domain.AdminLoginRateLimit, error) {
	if err := s.requireDB(); err != nil {
		return domain.AdminLoginRateLimit{}, err
	}
	if err := domain.RequireID(adminID, "login rate limit admin id"); err != nil {
		return domain.AdminLoginRateLimit{}, err
	}
	if err := sourceDigest.Validate("login rate limit source digest"); err != nil {
		return domain.AdminLoginRateLimit{}, err
	}
	record, err := scanAdminLoginRateLimit(s.db.QueryRowContext(ctx, `
		SELECT admin_id, source_digest, window_started_at, window_expires_at, failure_count, last_failure_at, locked_at, locked_until, updated_at
		  FROM admin_login_rate_limits
		 WHERE admin_id = $1 AND source_digest = $2
	`, adminID.String(), sourceDigest.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AdminLoginRateLimit{}, ErrNotFound
	}
	if err != nil {
		return domain.AdminLoginRateLimit{}, fmt.Errorf("read administrator login rate limit: %w", err)
	}
	return record, nil
}

func (s *Store) RecordAdminLoginFailure(ctx context.Context, adminID domain.ID, sourceDigest domain.AuthDigest, now time.Time) (domain.AdminLoginRateLimit, error) {
	if err := s.requireDB(); err != nil {
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
		return domain.AdminLoginRateLimit{}, fmt.Errorf("begin record login failure tx: %w", err)
	}
	defer tx.Rollback()

	// Acquire an advisory transaction lock to serialize concurrent attempts for this (admin, source)
	// even before an initial row exists, preventing the absent-row insert race.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1::text), hashtext($2::text))`, adminID.String(), sourceDigest.String()); err != nil {
		return domain.AdminLoginRateLimit{}, fmt.Errorf("lock login rate limit key: %w", err)
	}

	var existing *domain.AdminLoginRateLimit
	record, err := scanAdminLoginRateLimit(tx.QueryRowContext(ctx, `
		SELECT admin_id, source_digest, window_started_at, window_expires_at, failure_count, last_failure_at, locked_at, locked_until, updated_at
		  FROM admin_login_rate_limits
		 WHERE admin_id = $1 AND source_digest = $2
	`, adminID.String(), sourceDigest.String()))
	if err == nil {
		existing = &record
	} else if !errors.Is(err, sql.ErrNoRows) {
		return domain.AdminLoginRateLimit{}, fmt.Errorf("query existing rate limit: %w", err)
	}

	next := domain.TransitionAdminLoginRateLimit(existing, adminID, sourceDigest, now)
	if err := next.Validate(); err != nil {
		return domain.AdminLoginRateLimit{}, fmt.Errorf("validate transitioned rate limit: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO admin_login_rate_limits
			(admin_id, source_digest, window_started_at, window_expires_at, failure_count, last_failure_at, locked_at, locked_until, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (admin_id, source_digest) DO UPDATE
		   SET window_started_at = EXCLUDED.window_started_at,
		       window_expires_at = EXCLUDED.window_expires_at,
		       failure_count = EXCLUDED.failure_count,
		       last_failure_at = EXCLUDED.last_failure_at,
		       locked_at = EXCLUDED.locked_at,
		       locked_until = EXCLUDED.locked_until,
		       updated_at = EXCLUDED.updated_at
	`, next.AdminID.String(), next.SourceDigest.String(), next.WindowStartedAt.UTC(), next.WindowExpiresAt.UTC(), next.FailureCount, next.LastFailureAt.UTC(), next.LockedAt, next.LockedUntil, next.UpdatedAt.UTC())
	if err != nil {
		return domain.AdminLoginRateLimit{}, fmt.Errorf("upsert transitioned rate limit: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return domain.AdminLoginRateLimit{}, fmt.Errorf("commit record login failure: %w", err)
	}
	return next, nil
}

func (s *Store) CreateAdminSessionIfLoginAllowed(ctx context.Context, session domain.AdminSession, sourceDigest domain.AuthDigest, now time.Time) error {
	if err := s.requireDB(); err != nil {
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
		return fmt.Errorf("begin create admin session tx: %w", err)
	}
	defer tx.Rollback()

	// Acquire exact same advisory xact lock as RecordAdminLoginFailure on (adminID, sourceDigest)
	// to prevent concurrent failure recording from committing a lock between our rate check and session insert.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1::text), hashtext($2::text))`, session.AdminID.String(), sourceDigest.String()); err != nil {
		return fmt.Errorf("lock admin login session key: %w", err)
	}

	// 1. Re-check credential state under FOR SHARE lock
	var credVersion int64
	var disabledAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT credential_version, disabled_at
		  FROM admin_credentials
		 WHERE id = $1
		   FOR SHARE
	`, session.AdminID.String()).Scan(&credVersion, &disabledAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("check admin credential state: %w", err)
	}
	if disabledAt.Valid || credVersion != session.CredentialVersion {
		return ErrCredentialVersionConflict
	}

	// 2. Re-check full rate limit state and validate record
	var existingRate *domain.AdminLoginRateLimit
	rec, err := scanAdminLoginRateLimit(tx.QueryRowContext(ctx, `
		SELECT admin_id, source_digest, window_started_at, window_expires_at, failure_count, last_failure_at, locked_at, locked_until, updated_at
		  FROM admin_login_rate_limits
		 WHERE admin_id = $1 AND source_digest = $2
	`, session.AdminID.String(), sourceDigest.String()))
	if err == nil {
		existingRate = &rec
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check rate limit state: %w", err)
	}
	if existingRate != nil {
		if err := existingRate.Validate(); err != nil {
			return fmt.Errorf("validate persisted rate limit: %w", err)
		}
		if existingRate.IsLocked(now) {
			return domain.ErrRateLimited
		}
	}

	// 3. Persist session
	_, err = tx.ExecContext(ctx, `
		INSERT INTO admin_sessions
			(id, admin_id, session_digest, csrf_digest, credential_version, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, session.ID.String(), session.AdminID.String(), session.SessionDigest.String(), session.CSRFDigest.String(), session.CredentialVersion, session.CreatedAt.UTC(), session.LastSeenAt.UTC(), session.IdleExpiresAt.UTC(), session.AbsoluteExpiresAt.UTC(), session.RevokedAt)
	if err != nil {
		return fmt.Errorf("create administrator session: %w", err)
	}

	return tx.Commit()
}

type rowScanner interface{ Scan(...any) error }

func scanAdminCredential(row rowScanner) (domain.AdminCredential, error) {
	var credential domain.AdminCredential
	if err := row.Scan(&credential.ID, &credential.PasswordHashScheme, &credential.PasswordHash, &credential.CredentialVersion, &credential.DisabledAt, &credential.CreatedAt, &credential.UpdatedAt); err != nil {
		return domain.AdminCredential{}, err
	}
	credential.CreatedAt = credential.CreatedAt.UTC()
	credential.UpdatedAt = credential.UpdatedAt.UTC()
	if credential.DisabledAt != nil {
		value := credential.DisabledAt.UTC()
		credential.DisabledAt = &value
	}
	return credential, nil
}

func scanAdminSession(row rowScanner) (domain.AdminSession, error) {
	var session domain.AdminSession
	var sessionDigest, csrfDigest string
	if err := row.Scan(&session.ID, &session.AdminID, &sessionDigest, &csrfDigest, &session.CredentialVersion, &session.CreatedAt, &session.LastSeenAt, &session.IdleExpiresAt, &session.AbsoluteExpiresAt, &session.RevokedAt); err != nil {
		return domain.AdminSession{}, err
	}
	session.SessionDigest = domain.AuthDigest(sessionDigest)
	session.CSRFDigest = domain.AuthDigest(csrfDigest)
	session.CreatedAt = session.CreatedAt.UTC()
	session.LastSeenAt = session.LastSeenAt.UTC()
	session.IdleExpiresAt = session.IdleExpiresAt.UTC()
	session.AbsoluteExpiresAt = session.AbsoluteExpiresAt.UTC()
	if session.RevokedAt != nil {
		value := session.RevokedAt.UTC()
		session.RevokedAt = &value
	}
	return session, nil
}

func scanAdminLoginRateLimit(row rowScanner) (domain.AdminLoginRateLimit, error) {
	var record domain.AdminLoginRateLimit
	var sourceDigest string
	if err := row.Scan(&record.AdminID, &sourceDigest, &record.WindowStartedAt, &record.WindowExpiresAt, &record.FailureCount, &record.LastFailureAt, &record.LockedAt, &record.LockedUntil, &record.UpdatedAt); err != nil {
		return domain.AdminLoginRateLimit{}, err
	}
	record.SourceDigest = domain.AuthDigest(sourceDigest)
	record.WindowStartedAt = record.WindowStartedAt.UTC()
	record.WindowExpiresAt = record.WindowExpiresAt.UTC()
	record.LastFailureAt = record.LastFailureAt.UTC()
	record.UpdatedAt = record.UpdatedAt.UTC()
	if record.LockedAt != nil {
		value := record.LockedAt.UTC()
		record.LockedAt = &value
	}
	if record.LockedUntil != nil {
		value := record.LockedUntil.UTC()
		record.LockedUntil = &value
	}
	return record, nil
}
