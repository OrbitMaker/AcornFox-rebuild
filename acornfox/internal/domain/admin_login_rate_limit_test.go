package domain

import (
	"testing"
	"time"
)

func TestTransitionAdminLoginRateLimit(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	adminID := ID("admin_1")
	sourceDigest := AuthDigest("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	// 1. Initial failure starts window with count 1
	r1 := TransitionAdminLoginRateLimit(nil, adminID, sourceDigest, now)
	if err := r1.Validate(); err != nil {
		t.Fatalf("r1 validate: %v", err)
	}
	if r1.FailureCount != 1 || r1.IsLocked(now) {
		t.Fatalf("unexpected r1: %+v", r1)
	}

	// 2. Increments within window
	r2 := TransitionAdminLoginRateLimit(&r1, adminID, sourceDigest, now.Add(time.Minute))
	if err := r2.Validate(); err != nil {
		t.Fatalf("r2 validate: %v", err)
	}
	if r2.FailureCount != 2 || r2.IsLocked(now.Add(time.Minute)) {
		t.Fatalf("unexpected r2: %+v", r2)
	}

	r3 := TransitionAdminLoginRateLimit(&r2, adminID, sourceDigest, now.Add(2*time.Minute))
	r4 := TransitionAdminLoginRateLimit(&r3, adminID, sourceDigest, now.Add(3*time.Minute))
	if r4.FailureCount != 4 {
		t.Fatalf("unexpected r4 failure count: %d", r4.FailureCount)
	}

	// 3. 5th failure triggers 15 minute lock
	r5 := TransitionAdminLoginRateLimit(&r4, adminID, sourceDigest, now.Add(4*time.Minute))
	if err := r5.Validate(); err != nil {
		t.Fatalf("r5 validate: %v", err)
	}
	if r5.FailureCount != 5 || !r5.IsLocked(now.Add(4*time.Minute)) {
		t.Fatalf("expected r5 to be locked: %+v", r5)
	}
	if !r5.LockedUntil.Equal(now.Add(4 * time.Minute).Add(AdminLoginLockoutDuration)) {
		t.Fatalf("unexpected locked_until: %v", r5.LockedUntil)
	}

	// 4. Failure while already locked preserves locked_until and does not shorten it
	r6 := TransitionAdminLoginRateLimit(&r5, adminID, sourceDigest, now.Add(5*time.Minute))
	if err := r6.Validate(); err != nil {
		t.Fatalf("r6 validate: %v", err)
	}
	if !r6.LockedUntil.Equal(*r5.LockedUntil) {
		t.Fatalf("lock was shortened or altered: before=%v after=%v", r5.LockedUntil, r6.LockedUntil)
	}

	// 5. Failure after window expiry resets window and restarts count at 1
	afterExpiry := r1.WindowExpiresAt.Add(time.Second)
	rReset := TransitionAdminLoginRateLimit(&r1, adminID, sourceDigest, afterExpiry)
	if err := rReset.Validate(); err != nil {
		t.Fatalf("rReset validate: %v", err)
	}
	if rReset.FailureCount != 1 || !rReset.WindowStartedAt.Equal(afterExpiry) {
		t.Fatalf("expected reset window: %+v", rReset)
	}
}

func TestTransitionAdminLoginRateLimitLockPreservedAcrossWindowExpiry(t *testing.T) {
	// Boundary scenario: failure at min 0, 5th failure at min 14 -> lock until min 29.
	// Failure at min 16 (after original 15-min window has elapsed) MUST NOT clear the lock.
	t0 := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	adminID := ID("admin_boundary")
	sourceDigest := AuthDigest("1111111111111111111111111111111111111111111111111111111111111111")

	rec := TransitionAdminLoginRateLimit(nil, adminID, sourceDigest, t0) // min 0: fail 1
	for m := 1; m <= 4; m++ {
		rec = TransitionAdminLoginRateLimit(&rec, adminID, sourceDigest, t0.Add(time.Duration(m*3+2)*time.Minute))
	}
	// At minute 14 (14m < 15m), this was 5th failure
	t14 := t0.Add(14 * time.Minute)
	rec = TransitionAdminLoginRateLimit(&rec, adminID, sourceDigest, t14)
	if rec.FailureCount != 5 || !rec.IsLocked(t14) {
		t.Fatalf("expected locked at minute 14, got %+v", rec)
	}
	lockUntil := *rec.LockedUntil
	if !lockUntil.Equal(t14.Add(15 * time.Minute)) {
		t.Fatalf("expected lock until minute 29, got %v", lockUntil)
	}

	// At minute 16, original failure window (0..15m) has passed, but lock is active until min 29.
	t16 := t0.Add(16 * time.Minute)
	rec16 := TransitionAdminLoginRateLimit(&rec, adminID, sourceDigest, t16)
	if !rec16.IsLocked(t16) {
		t.Fatalf("expected lock to be preserved at minute 16, got %+v", rec16)
	}
	if !rec16.LockedUntil.Equal(lockUntil) {
		t.Fatalf("lock was shortened or altered at minute 16: want %v, got %v", lockUntil, rec16.LockedUntil)
	}
	if err := rec16.Validate(); err != nil {
		t.Fatalf("rec16 validate: %v", err)
	}

	// Reordered clock: an attempt with earlier timestamp must not move last_failure_at backward
	tEarlier := t14.Add(-time.Minute)
	recReordered := TransitionAdminLoginRateLimit(&rec, adminID, sourceDigest, tEarlier)
	if recReordered.LastFailureAt.Before(rec.LastFailureAt) {
		t.Fatalf("last failure moved backward on reordered clock: before=%v, reordered=%v", rec.LastFailureAt, recReordered.LastFailureAt)
	}
	if !recReordered.IsLocked(t14) {
		t.Fatal("reordered attempt cleared lock")
	}
}
