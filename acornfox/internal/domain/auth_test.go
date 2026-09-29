package domain

import (
	"strings"
	"testing"
	"time"
)

func authDigest(char string) AuthDigest { return AuthDigest(strings.Repeat(char, AuthDigestHexLength)) }

func validAdminCredential(now time.Time) AdminCredential {
	return AdminCredential{
		ID:                 "admin_1",
		PasswordHashScheme: "argon2id-v1",
		PasswordHash:       "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$ZGlnaWVzdA",
		CredentialVersion:  1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
}

func validAdminSession(now time.Time) AdminSession {
	return AdminSession{
		ID:                "session_1",
		AdminID:           "admin_1",
		SessionDigest:     authDigest("a"),
		CSRFDigest:        authDigest("b"),
		CredentialVersion: 1,
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(AdminSessionIdleTimeout),
		AbsoluteExpiresAt: now.Add(AdminSessionAbsoluteTimeout),
	}
}

func TestAdminCredentialRejectsPlaintextAndUnversionedHashes(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	if err := validAdminCredential(now).Validate(); err != nil {
		t.Fatalf("valid administrator credential rejected: %v", err)
	}
	for _, candidate := range []AdminCredential{
		func() AdminCredential {
			value := validAdminCredential(now)
			value.PasswordHash = "plaintext"
			return value
		}(),
		func() AdminCredential {
			value := validAdminCredential(now)
			value.PasswordHashScheme = "ARGON2ID"
			return value
		}(),
		func() AdminCredential { value := validAdminCredential(now); value.CredentialVersion = 0; return value }(),
	} {
		if err := candidate.Validate(); err == nil {
			t.Fatalf("invalid administrator credential accepted: %+v", candidate)
		}
	}
}

func TestAdminSessionEnforcesFixedLifetimeAndDigestBoundary(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	if err := validAdminSession(now).Validate(); err != nil {
		t.Fatalf("valid administrator session rejected: %v", err)
	}
	for _, candidate := range []AdminSession{
		func() AdminSession { value := validAdminSession(now); value.SessionDigest = "short"; return value }(),
		func() AdminSession {
			value := validAdminSession(now)
			value.CSRFDigest = value.SessionDigest
			return value
		}(),
		func() AdminSession {
			value := validAdminSession(now)
			value.IdleExpiresAt = now.Add(7 * time.Hour)
			return value
		}(),
		func() AdminSession {
			value := validAdminSession(now)
			value.AbsoluteExpiresAt = now.Add(23 * time.Hour)
			return value
		}(),
	} {
		if err := candidate.Validate(); err == nil {
			t.Fatalf("invalid administrator session accepted: %+v", candidate)
		}
	}
}

func TestAdminLoginRateLimitEnforcesFiveFailuresAndFifteenMinuteLock(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	lockedAt := now.Add(5 * time.Minute)
	limit := AdminLoginRateLimit{
		AdminID:         "admin_1",
		SourceDigest:    authDigest("c"),
		WindowStartedAt: now,
		WindowExpiresAt: now.Add(AdminLoginFailureWindow),
		FailureCount:    AdminLoginMaxFailureAttempts,
		LastFailureAt:   lockedAt,
		LockedAt:        &lockedAt,
		LockedUntil:     pointerTime(lockedAt.Add(AdminLoginLockoutDuration)),
		UpdatedAt:       lockedAt,
	}
	if err := limit.Validate(); err != nil {
		t.Fatalf("valid lockout record rejected: %v", err)
	}
	limit.LockedUntil = pointerTime(lockedAt.Add(14 * time.Minute))
	if err := limit.Validate(); err == nil {
		t.Fatal("short login lockout accepted")
	}
}

func pointerTime(value time.Time) *time.Time { return &value }
