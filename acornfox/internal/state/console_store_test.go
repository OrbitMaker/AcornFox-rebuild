package state

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fixedClock returns a controllable clock for a store.
func fixedClock(t *time.Time) func() time.Time {
	return func() time.Time { return *t }
}

func TestConsoleTokenSingleUse(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	token, err := s.CreateConsoleToken(ctx)
	if err != nil {
		t.Fatalf("CreateConsoleToken: %v", err)
	}
	if len(token) != 64 {
		t.Fatalf("token length = %d, want 64 hex", len(token))
	}

	sess, secret, csrf, err := s.RedeemConsoleToken(ctx, token)
	if err != nil {
		t.Fatalf("RedeemConsoleToken: %v", err)
	}
	if len(sess.ID) != 16 || secret == "" || csrf == "" {
		t.Fatalf("bad session: id=%q secret=%q csrf=%q", sess.ID, secret, csrf)
	}
	if sess.CSRFDigest != sha256Hex(csrf) {
		t.Fatalf("csrf digest mismatch")
	}

	// Second redemption of the same token must fail (single use).
	if _, _, _, err := s.RedeemConsoleToken(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second redeem err = %v, want ErrNotFound", err)
	}
}

func TestConsoleTokenExpiry(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s.setClock(fixedClock(&now))

	token, err := s.CreateConsoleToken(ctx)
	if err != nil {
		t.Fatalf("CreateConsoleToken: %v", err)
	}
	// Advance past the TTL.
	now = now.Add(ConsoleTokenTTL + time.Second)
	if _, _, _, err := s.RedeemConsoleToken(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired redeem err = %v, want ErrNotFound", err)
	}
}

func TestConsoleTokenUnknown(t *testing.T) {
	s := openTest(t)
	if _, _, _, err := s.RedeemConsoleToken(context.Background(), "deadbeef"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown redeem err = %v, want ErrNotFound", err)
	}
}

func TestConsoleSessionSlidingIdleAndAbsolute(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s.setClock(fixedClock(&now))

	token, _ := s.CreateConsoleToken(ctx)
	_, secret, _, err := s.RedeemConsoleToken(ctx, token)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}

	// Touch within idle window slides idle expiry forward.
	now = now.Add(7 * time.Hour)
	sess, err := s.TouchConsoleSession(ctx, secret)
	if err != nil {
		t.Fatalf("touch: %v", err)
	}
	if !sess.IdleExpiresAt.Equal(now.Add(ConsoleSessionIdle)) {
		t.Fatalf("idle not slid: got %v", sess.IdleExpiresAt)
	}

	// After sliding, another 7h keeps it alive (idle would have expired without slide).
	now = now.Add(7 * time.Hour)
	if _, err := s.TouchConsoleSession(ctx, secret); err != nil {
		t.Fatalf("touch after slide: %v", err)
	}

	// Absolute cap: 24h from creation. Creation was at 12:00; now is 12:00+14h.
	// Jump beyond 24h absolute -> expired even though recently touched.
	now = time.Date(2026, 1, 2, 12, 0, 1, 0, time.UTC)
	if _, err := s.TouchConsoleSession(ctx, secret); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absolute cap err = %v, want ErrNotFound", err)
	}
}

func TestConsoleSessionIdleExpiry(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s.setClock(fixedClock(&now))
	token, _ := s.CreateConsoleToken(ctx)
	_, secret, _, _ := s.RedeemConsoleToken(ctx, token)

	// Idle for more than 8h without a touch -> expired.
	now = now.Add(ConsoleSessionIdle + time.Minute)
	if _, err := s.TouchConsoleSession(ctx, secret); !errors.Is(err, ErrNotFound) {
		t.Fatalf("idle expiry err = %v, want ErrNotFound", err)
	}
}

func TestConsoleSessionRevoke(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	token, _ := s.CreateConsoleToken(ctx)
	_, secret, _, _ := s.RedeemConsoleToken(ctx, token)

	if err := s.RevokeConsoleSession(ctx, secret); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := s.TouchConsoleSession(ctx, secret); !errors.Is(err, ErrNotFound) {
		t.Fatalf("touch after revoke err = %v, want ErrNotFound", err)
	}
	// Revoking again is a no-op.
	if err := s.RevokeConsoleSession(ctx, secret); err != nil {
		t.Fatalf("revoke again: %v", err)
	}
	// Revoking unknown is a no-op.
	if err := s.RevokeConsoleSession(ctx, "unknownsecret"); err != nil {
		t.Fatalf("revoke unknown: %v", err)
	}
}

func TestPruneConsole(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s.setClock(fixedClock(&now))

	// An expired token and a revoked session should be pruned.
	if _, err := s.CreateConsoleToken(ctx); err != nil {
		t.Fatalf("token: %v", err)
	}
	token, _ := s.CreateConsoleToken(ctx)
	_, secret, _, _ := s.RedeemConsoleToken(ctx, token)
	if err := s.RevokeConsoleSession(ctx, secret); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	now = now.Add(2 * time.Hour)
	if err := s.PruneConsole(ctx); err != nil {
		t.Fatalf("prune: %v", err)
	}

	var tokenCount, sessionCount int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM console_tokens`).Scan(&tokenCount); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM console_sessions`).Scan(&sessionCount); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if tokenCount != 0 {
		t.Fatalf("expired tokens not pruned: %d", tokenCount)
	}
	if sessionCount != 0 {
		t.Fatalf("revoked sessions not pruned: %d", sessionCount)
	}
}

func TestDomainAddListRemove(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if _, _, err := s.EnsureApp(ctx, "web"); err != nil {
		t.Fatalf("EnsureApp: %v", err)
	}

	dom, created, err := s.AddDomain(ctx, "web", "notes.acornfox.test")
	if err != nil || !created {
		t.Fatalf("AddDomain: created=%v err=%v", created, err)
	}
	if dom.Status != DomainPending {
		t.Fatalf("new domain status = %q, want pending", dom.Status)
	}

	// Idempotent for same app.
	_, created2, err := s.AddDomain(ctx, "web", "notes.acornfox.test")
	if err != nil || created2 {
		t.Fatalf("AddDomain idempotent: created=%v err=%v", created2, err)
	}

	list, err := s.ListDomains(ctx, "web")
	if err != nil || len(list) != 1 {
		t.Fatalf("ListDomains: %v len=%d", err, len(list))
	}

	if err := s.RemoveDomain(ctx, "web", "notes.acornfox.test"); err != nil {
		t.Fatalf("RemoveDomain: %v", err)
	}
	list, _ = s.ListDomains(ctx, "web")
	if len(list) != 0 {
		t.Fatalf("domain not removed: %d", len(list))
	}
	// Removing a missing domain is a no-op.
	if err := s.RemoveDomain(ctx, "web", "notes.acornfox.test"); err != nil {
		t.Fatalf("RemoveDomain missing: %v", err)
	}
}

func TestDomainUniqueAcrossApps(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if _, _, err := s.EnsureApp(ctx, "web"); err != nil {
		t.Fatalf("EnsureApp web: %v", err)
	}
	if _, _, err := s.EnsureApp(ctx, "api"); err != nil {
		t.Fatalf("EnsureApp api: %v", err)
	}
	if _, _, err := s.AddDomain(ctx, "web", "shared.acornfox.test"); err != nil {
		t.Fatalf("AddDomain web: %v", err)
	}
	if _, _, err := s.AddDomain(ctx, "api", "shared.acornfox.test"); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-app add err = %v, want ErrConflict", err)
	}
	// Removing from the wrong app returns ErrNotFound.
	if err := s.RemoveDomain(ctx, "api", "shared.acornfox.test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong-app remove err = %v, want ErrNotFound", err)
	}
}

func TestSetDomainStatus(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if _, _, err := s.EnsureApp(ctx, "web"); err != nil {
		t.Fatalf("EnsureApp: %v", err)
	}
	if _, _, err := s.AddDomain(ctx, "web", "notes.acornfox.test"); err != nil {
		t.Fatalf("AddDomain: %v", err)
	}
	diag := &Diagnosis{Stage: "domain", Code: "cert_pending", Message: "证书尚未签发"}
	if err := s.SetDomainStatus(ctx, "web", "notes.acornfox.test", DomainFailed, diag); err != nil {
		t.Fatalf("SetDomainStatus: %v", err)
	}
	list, _ := s.ListDomains(ctx, "web")
	if len(list) != 1 || list[0].Status != DomainFailed {
		t.Fatalf("status not set: %+v", list)
	}
	if list[0].Diagnosis == nil || list[0].Diagnosis.Code != "cert_pending" {
		t.Fatalf("diagnosis not set: %+v", list[0].Diagnosis)
	}
	if list[0].CheckedAt == nil {
		t.Fatalf("CheckedAt not set")
	}
	// Unknown domain -> ErrNotFound.
	if err := s.SetDomainStatus(ctx, "web", "missing.acornfox.test", DomainReady, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown set err = %v, want ErrNotFound", err)
	}
}

func TestValidDomainName(t *testing.T) {
	valid := []string{"notes.acornfox.test", "a.b.c", "x-y.example.com"}
	invalid := []string{
		"", "nodot", "UPPER.example.com", "trailing.dot.",
		"1.2.3.4", "-bad.example.com", "bad-.example.com",
	}
	for _, v := range valid {
		if !ValidDomainName(v) {
			t.Errorf("ValidDomainName(%q) = false, want true", v)
		}
	}
	for _, v := range invalid {
		if ValidDomainName(v) {
			t.Errorf("ValidDomainName(%q) = true, want false", v)
		}
	}
}
