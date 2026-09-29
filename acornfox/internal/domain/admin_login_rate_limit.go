package domain

import (
	"time"
)

// TransitionAdminLoginRateLimit computes the next atomic rate limit state for
// an administrator authentication failure. It preserves the 5-failure / 15-minute
// lockout policy and guarantees that an existing committed lockout cannot be shortened.
func TransitionAdminLoginRateLimit(existing *AdminLoginRateLimit, adminID ID, sourceDigest AuthDigest, now time.Time) AdminLoginRateLimit {
	now = now.UTC()

	// 1. An existing active lockout takes precedence over window expiration.
	// If a source was locked (e.g. at minute 14 until minute 29), an attempt
	// at minute 16 falls outside the original 15-minute window but MUST NOT clear the lock.
	if existing != nil && existing.LockedUntil != nil && now.Before(*existing.LockedUntil) {
		record := *existing
		if now.After(record.UpdatedAt) {
			record.UpdatedAt = now
		}
		return record
	}

	// 2. If no record exists or the previous failure window has expired without an active lock,
	// start a fresh 15-minute failure window.
	if existing == nil || now.After(existing.WindowExpiresAt) {
		return AdminLoginRateLimit{
			AdminID:         adminID,
			SourceDigest:    sourceDigest,
			WindowStartedAt: now,
			WindowExpiresAt: now.Add(AdminLoginFailureWindow),
			FailureCount:    1,
			LastFailureAt:   now,
			UpdatedAt:       now,
		}
	}

	// 3. Increment failures within the active window.
	record := *existing

	// Monotonicity: reordered clocks must not move timestamps backward
	lastFailure := now
	if record.LastFailureAt.After(lastFailure) {
		lastFailure = record.LastFailureAt
	}
	record.LastFailureAt = lastFailure

	updatedAt := now
	if record.UpdatedAt.After(updatedAt) {
		updatedAt = record.UpdatedAt
	}
	record.UpdatedAt = updatedAt

	record.FailureCount++
	if record.FailureCount > AdminLoginMaxFailureAttempts {
		record.FailureCount = AdminLoginMaxFailureAttempts
	}

	if record.FailureCount == AdminLoginMaxFailureAttempts {
		lockedAt := record.LastFailureAt
		lockedUntil := lockedAt.Add(AdminLoginLockoutDuration)
		record.LockedAt = &lockedAt
		record.LockedUntil = &lockedUntil
	} else {
		record.LockedAt = nil
		record.LockedUntil = nil
	}
	return record
}

// IsLocked reports whether the rate limit is actively locked at the given time.
func (r AdminLoginRateLimit) IsLocked(now time.Time) bool {
	return r.LockedUntil != nil && now.UTC().Before(*r.LockedUntil)
}
