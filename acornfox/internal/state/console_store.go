package state

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// domainNamePattern accepts a lowercase DNS hostname with at least one dot and
// no trailing dot. Each label is 1..63 chars of [a-z0-9-] not starting or
// ending with '-'; total length is bounded to <= 253 by AddDomain.
var domainNamePattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// sha256Hex returns the lowercase hex SHA-256 digest of s.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ConsoleCSRFToken derives the CSRF token from a session secret. It is stable
// for the life of the session and recoverable by the server from the (HttpOnly)
// session cookie, so GET /v1/console/session can return it without persisting
// the plaintext. It is unguessable without the session secret.
func ConsoleCSRFToken(sessionSecret string) string {
	return sha256Hex("acornfox-csrf:" + sessionSecret)
}

// CSRFDigest returns the digest stored for a CSRF token, so a presented token
// can be compared without keeping the token itself.
func CSRFDigest(csrfToken string) string { return sha256Hex(csrfToken) }

// randomHex returns n random bytes hex-encoded (2n hex chars).
func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("random bytes: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// -------- Console tokens & sessions --------

// CreateConsoleToken mints a one-time login token: 32 random bytes hex. Only
// the SHA-256 digest and expiry (ConsoleTokenTTL) are stored; the plaintext
// token is returned to the caller and never persisted.
func (s *Store) CreateConsoleToken(ctx context.Context) (string, error) {
	token, err := randomHex(32)
	if err != nil {
		return "", err
	}
	now := s.nowUTC()
	digest := sha256Hex(token)
	_, err = s.db.ExecContext(ctx, `INSERT INTO console_tokens (token_digest, created_at, expires_at)
		VALUES (?, ?, ?)`, digest, formatTime(now), formatTime(now.Add(ConsoleTokenTTL)))
	if err != nil {
		return "", fmt.Errorf("insert console token: %w", err)
	}
	return token, nil
}

// RedeemConsoleToken exchanges a one-time token for a new session. It is single
// use: the token row is deleted whether or not it was still valid. It returns
// ErrNotFound when the token is unknown, expired or already used. On success it
// creates a session and returns the session record, the session secret (to set
// as the cookie) and the CSRF token; only digests of both secrets are stored.
func (s *Store) RedeemConsoleToken(ctx context.Context, token string) (ConsoleSession, string, string, error) {
	var (
		sess          ConsoleSession
		sessionSecret string
		csrfToken     string
	)
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		digest := sha256Hex(token)
		var expiresText string
		row := tx.QueryRowContext(ctx, `SELECT expires_at FROM console_tokens WHERE token_digest=?`, digest)
		if err := row.Scan(&expiresText); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("scan console token: %w", err)
		}
		// Single use: delete the token regardless of validity.
		if _, err := tx.ExecContext(ctx, `DELETE FROM console_tokens WHERE token_digest=?`, digest); err != nil {
			return fmt.Errorf("delete console token: %w", err)
		}
		expires, err := parseTime(expiresText)
		if err != nil {
			return err
		}
		now := s.nowUTC()
		if !now.Before(expires) {
			return ErrNotFound
		}

		// Create the session.
		id, err := randomHex(8) // 16 hex chars
		if err != nil {
			return err
		}
		sessionSecret, err = randomHex(32)
		if err != nil {
			return err
		}
		// Derive the CSRF token from the session secret so it is recoverable by
		// the server on later requests without persisting the plaintext.
		csrfToken = ConsoleCSRFToken(sessionSecret)
		sess = ConsoleSession{
			ID:              id,
			CSRFDigest:      sha256Hex(csrfToken),
			CreatedAt:       now,
			LastSeenAt:      now,
			IdleExpiresAt:   now.Add(ConsoleSessionIdle),
			AbsoluteExpires: now.Add(ConsoleSessionAbsolute),
		}
		if sess.IdleExpiresAt.After(sess.AbsoluteExpires) {
			sess.IdleExpiresAt = sess.AbsoluteExpires
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO console_sessions
			(id, session_digest, csrf_digest, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
			sess.ID, sha256Hex(sessionSecret), sess.CSRFDigest,
			formatTime(sess.CreatedAt), formatTime(sess.LastSeenAt),
			formatTime(sess.IdleExpiresAt), formatTime(sess.AbsoluteExpires))
		if err != nil {
			return fmt.Errorf("insert console session: %w", err)
		}
		return nil
	})
	if err != nil {
		return ConsoleSession{}, "", "", err
	}
	return sess, sessionSecret, csrfToken, nil
}

// TouchConsoleSession validates a session by its secret and slides its idle
// expiry forward (capped at the absolute expiry). It returns ErrNotFound when
// the session is unknown, revoked, or past either expiry.
func (s *Store) TouchConsoleSession(ctx context.Context, sessionSecret string) (ConsoleSession, error) {
	var sess ConsoleSession
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		digest := sha256Hex(sessionSecret)
		got, err := scanConsoleSessionTx(ctx, tx, digest)
		if err != nil {
			return err
		}
		now := s.nowUTC()
		if got.RevokedAt != nil || !now.Before(got.IdleExpiresAt) || !now.Before(got.AbsoluteExpires) {
			return ErrNotFound
		}
		got.LastSeenAt = now
		got.IdleExpiresAt = now.Add(ConsoleSessionIdle)
		if got.IdleExpiresAt.After(got.AbsoluteExpires) {
			got.IdleExpiresAt = got.AbsoluteExpires
		}
		if _, err := tx.ExecContext(ctx, `UPDATE console_sessions
			SET last_seen_at=?, idle_expires_at=? WHERE session_digest=?`,
			formatTime(got.LastSeenAt), formatTime(got.IdleExpiresAt), digest); err != nil {
			return fmt.Errorf("touch console session: %w", err)
		}
		sess = got
		return nil
	})
	if err != nil {
		return ConsoleSession{}, err
	}
	return sess, nil
}

// RevokeConsoleSession marks the session identified by its secret revoked.
// Revoking an unknown or already revoked session is a no-op.
func (s *Store) RevokeConsoleSession(ctx context.Context, sessionSecret string) error {
	digest := sha256Hex(sessionSecret)
	_, err := s.db.ExecContext(ctx, `UPDATE console_sessions SET revoked_at=?
		WHERE session_digest=? AND revoked_at IS NULL`, formatTime(s.nowUTC()), digest)
	if err != nil {
		return fmt.Errorf("revoke console session: %w", err)
	}
	return nil
}

// PruneConsole deletes expired tokens and sessions (revoked or past their
// absolute expiry). It is safe to call periodically.
func (s *Store) PruneConsole(ctx context.Context) error {
	nowText := formatTime(s.nowUTC())
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM console_tokens WHERE expires_at < ?`, nowText); err != nil {
			return fmt.Errorf("prune console tokens: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM console_sessions
			WHERE revoked_at IS NOT NULL OR absolute_expires_at < ?`, nowText); err != nil {
			return fmt.Errorf("prune console sessions: %w", err)
		}
		return nil
	})
}

func scanConsoleSessionTx(ctx context.Context, tx *sql.Tx, digest string) (ConsoleSession, error) {
	row := tx.QueryRowContext(ctx, `SELECT id, csrf_digest, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at
		FROM console_sessions WHERE session_digest=?`, digest)
	var (
		sess         ConsoleSession
		createdText  string
		lastSeenText string
		idleText     string
		absoluteText string
		revokedText  sql.NullString
	)
	if err := row.Scan(&sess.ID, &sess.CSRFDigest, &createdText, &lastSeenText, &idleText, &absoluteText, &revokedText); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ConsoleSession{}, ErrNotFound
		}
		return ConsoleSession{}, fmt.Errorf("scan console session: %w", err)
	}
	var err error
	if sess.CreatedAt, err = parseTime(createdText); err != nil {
		return ConsoleSession{}, err
	}
	if sess.LastSeenAt, err = parseTime(lastSeenText); err != nil {
		return ConsoleSession{}, err
	}
	if sess.IdleExpiresAt, err = parseTime(idleText); err != nil {
		return ConsoleSession{}, err
	}
	if sess.AbsoluteExpires, err = parseTime(absoluteText); err != nil {
		return ConsoleSession{}, err
	}
	if revokedText.Valid {
		t, err := parseTime(revokedText.String)
		if err != nil {
			return ConsoleSession{}, err
		}
		sess.RevokedAt = &t
	}
	return sess, nil
}

// -------- Domains --------

// ValidDomainName reports whether name is an acceptable custom domain: lowercase,
// a valid hostname with at least one dot, not a trailing dot, not an IP literal,
// and at most 253 characters.
func ValidDomainName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	if name != strings.ToLower(name) {
		return false
	}
	if !domainNamePattern.MatchString(name) {
		return false
	}
	// Reject dotted-decimal IPv4 literals (all-numeric labels).
	labels := strings.Split(name, ".")
	allNumeric := true
	for _, l := range labels {
		if strings.TrimFunc(l, func(r rune) bool { return r >= '0' && r <= '9' }) != "" {
			allNumeric = false
			break
		}
	}
	return !allNumeric
}

// AddDomain records a custom domain for an app. It is idempotent for the same
// app (returns the existing row with bool=false). If another app already owns
// the name it returns ErrConflict. New domains start in DomainPending.
func (s *Store) AddDomain(ctx context.Context, app, name string) (Domain, bool, error) {
	if !ValidAppName(app) {
		return Domain{}, false, fmt.Errorf("%w: app name %q", ErrInvalid, app)
	}
	if !ValidDomainName(name) {
		return Domain{}, false, fmt.Errorf("%w: domain name %q", ErrInvalid, name)
	}
	var (
		dom     Domain
		created bool
	)
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := scanAppTx(ctx, tx, app); err != nil {
			return err
		}
		existing, err := scanDomainTx(ctx, tx, name)
		if err == nil {
			if existing.App != app {
				return ErrConflict
			}
			dom = existing
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		now := s.nowUTC()
		if _, err := tx.ExecContext(ctx, `INSERT INTO app_domains (app, name, status, diagnosis, checked_at, created_at)
			VALUES (?, ?, ?, '', NULL, ?)`, app, name, DomainPending, formatTime(now)); err != nil {
			return fmt.Errorf("insert domain: %w", err)
		}
		created = true
		dom, err = scanDomainTx(ctx, tx, name)
		return err
	})
	if err != nil {
		return Domain{}, false, err
	}
	return dom, created, nil
}

// RemoveDomain deletes a domain from an app. Removing a domain that does not
// exist (for that app) is a no-op; ErrNotFound is only returned when another
// app owns the name.
func (s *Store) RemoveDomain(ctx context.Context, app, name string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		existing, err := scanDomainTx(ctx, tx, name)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			return err
		}
		if existing.App != app {
			return ErrNotFound
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM app_domains WHERE name=?`, name); err != nil {
			return fmt.Errorf("delete domain: %w", err)
		}
		return nil
	})
}

// ListDomains returns domains for an app ordered by name; app "" returns every
// app's domains.
func (s *Store) ListDomains(ctx context.Context, app string) ([]Domain, error) {
	q := `SELECT app, name, status, diagnosis, checked_at, created_at FROM app_domains`
	var args []any
	if app != "" {
		q += ` WHERE app=?`
		args = append(args, app)
	}
	q += ` ORDER BY name`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list domains: %w", err)
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		d, err := scanDomainRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetDomainStatus updates a domain's status and diagnosis and sets CheckedAt to
// now. It returns ErrNotFound when the (app, name) pair does not exist.
func (s *Store) SetDomainStatus(ctx context.Context, app, name, status string, diag *Diagnosis) error {
	if status != DomainPending && status != DomainReady && status != DomainFailed {
		return fmt.Errorf("%w: domain status %q", ErrInvalid, status)
	}
	diagText, err := marshalDiagnosis(diag)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		existing, err := scanDomainTx(ctx, tx, name)
		if err != nil {
			return err
		}
		if existing.App != app {
			return ErrNotFound
		}
		res, err := tx.ExecContext(ctx, `UPDATE app_domains SET status=?, diagnosis=?, checked_at=? WHERE name=?`,
			status, diagText, formatTime(s.nowUTC()), name)
		if err != nil {
			return fmt.Errorf("set domain status: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func scanDomainFrom(sc rowScanner) (Domain, error) {
	var (
		d           Domain
		diagText    string
		checkedText sql.NullString
		createdText string
	)
	if err := sc.Scan(&d.App, &d.Name, &d.Status, &diagText, &checkedText, &createdText); err != nil {
		return Domain{}, err
	}
	var err error
	if d.Diagnosis, err = unmarshalDiagnosis(diagText); err != nil {
		return Domain{}, err
	}
	if checkedText.Valid {
		t, err := parseTime(checkedText.String)
		if err != nil {
			return Domain{}, err
		}
		d.CheckedAt = &t
	}
	if d.CreatedAt, err = parseTime(createdText); err != nil {
		return Domain{}, err
	}
	return d, nil
}

func scanDomainRow(rows *sql.Rows) (Domain, error) { return scanDomainFrom(rows) }

func scanDomainTx(ctx context.Context, tx *sql.Tx, name string) (Domain, error) {
	row := tx.QueryRowContext(ctx, `SELECT app, name, status, diagnosis, checked_at, created_at
		FROM app_domains WHERE name=?`, name)
	d, err := scanDomainFrom(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Domain{}, ErrNotFound
	}
	if err != nil {
		return Domain{}, fmt.Errorf("scan domain: %w", err)
	}
	return d, nil
}
