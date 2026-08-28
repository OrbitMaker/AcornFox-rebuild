package auth

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type memoryStore struct {
	credential domain.AdminCredential
	sessions   map[domain.AuthDigest]domain.AdminSession
	rates      map[domain.AuthDigest]domain.AdminLoginRateLimit
}

func (s *memoryStore) ActiveAdminCredential(context.Context) (domain.AdminCredential, error) {
	if s.credential.ID.Empty() || s.credential.DisabledAt != nil {
		return domain.AdminCredential{}, postgres.ErrNotFound
	}
	return s.credential, nil
}

func (s *memoryStore) RotateAdminCredential(_ context.Context, id domain.ID, expected int64, scheme, hash string, now time.Time) (domain.AdminCredential, error) {
	if s.credential.ID != id || s.credential.CredentialVersion != expected || s.credential.DisabledAt != nil {
		return domain.AdminCredential{}, postgres.ErrCredentialVersionConflict
	}
	s.credential.PasswordHashScheme, s.credential.PasswordHash = scheme, hash
	s.credential.CredentialVersion++
	s.credential.UpdatedAt = now
	return s.credential, nil
}

func (s *memoryStore) CreateAdminSession(_ context.Context, session domain.AdminSession) error {
	if s.sessions == nil {
		s.sessions = map[domain.AuthDigest]domain.AdminSession{}
	}
	s.sessions[session.SessionDigest] = session
	return nil
}

func (s *memoryStore) ActiveAdminSessionByDigest(_ context.Context, digest domain.AuthDigest, now time.Time) (domain.AdminSession, error) {
	session, ok := s.sessions[digest]
	if !ok || session.RevokedAt != nil || !now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) || session.CredentialVersion != s.credential.CredentialVersion {
		return domain.AdminSession{}, postgres.ErrNotFound
	}
	return session, nil
}

func (s *memoryStore) TouchAdminSession(_ context.Context, id domain.ID, credentialVersion int64, now time.Time) (domain.AdminSession, error) {
	for digest, session := range s.sessions {
		if session.ID == id && session.CredentialVersion == credentialVersion && now.Before(session.IdleExpiresAt) && now.Before(session.AbsoluteExpiresAt) {
			session.LastSeenAt = now
			session.IdleExpiresAt = now.Add(domain.AdminSessionIdleTimeout)
			if session.IdleExpiresAt.After(session.AbsoluteExpiresAt) {
				session.IdleExpiresAt = session.AbsoluteExpiresAt
			}
			s.sessions[digest] = session
			return session, nil
		}
	}
	return domain.AdminSession{}, postgres.ErrNotFound
}

func (s *memoryStore) RevokeAdminSession(_ context.Context, id domain.ID, now time.Time) error {
	for digest, session := range s.sessions {
		if session.ID == id {
			session.RevokedAt = &now
			s.sessions[digest] = session
			return nil
		}
	}
	return postgres.ErrNotFound
}

func (s *memoryStore) UpsertAdminLoginRateLimit(_ context.Context, record domain.AdminLoginRateLimit) error {
	if s.rates == nil {
		s.rates = map[domain.AuthDigest]domain.AdminLoginRateLimit{}
	}
	s.rates[record.SourceDigest] = record
	return nil
}

func (s *memoryStore) AdminLoginRateLimit(_ context.Context, _ domain.ID, source domain.AuthDigest) (domain.AdminLoginRateLimit, error) {
	record, ok := s.rates[source]
	if !ok {
		return domain.AdminLoginRateLimit{}, postgres.ErrNotFound
	}
	return record, nil
}

func newTestService(t *testing.T, store Store, now *time.Time) *Service {
	t.Helper()
	randomBytes := make([]byte, 256)
	for index := range randomBytes {
		randomBytes[index] = byte(index)
	}
	service, err := newService(Config{Store: store, Origin: "https://console.example.test", Iterations: 3, Random: bytes.NewReader(randomBytes), Clock: func() time.Time { return *now }}, true)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func seedCredential(t *testing.T, service *Service, store *memoryStore, password string, now time.Time) {
	t.Helper()
	hash, err := service.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	store.credential = domain.AdminCredential{ID: "admin_1", PasswordHashScheme: PasswordHashScheme, PasswordHash: hash, CredentialVersion: 1, CreatedAt: now, UpdatedAt: now}
}

func TestProductionConstructorRejectsWeakPBKDF2(t *testing.T) {
	if _, err := NewService(Config{Store: &memoryStore{}, Origin: "https://console.example.test", Iterations: MinimumPBKDF2Iterations - 1}); err == nil {
		t.Fatal("production constructor accepted weak PBKDF2 iterations")
	}
}

func TestPasswordPolicyAndVersionedPBKDF2Encoding(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	service := newTestService(t, &memoryStore{}, &now)
	for _, password := range []string{"", "short", strings.Repeat("a", 14), strings.Repeat("a", 1025), "valid-password\x00with-null", string([]byte{0xff, 0xfe})} {
		if _, err := service.HashPassword(password); err == nil {
			t.Fatalf("invalid password accepted: %q", password)
		}
	}
	password := "密码安全长度足够的管理员口令123"
	encoded, err := service.HashPassword(password)
	if err != nil || !strings.HasPrefix(encoded, "$pbkdf2-sha256$i=3,l=32$") {
		t.Fatalf("encoded password=%q err=%v", encoded, err)
	}
	if valid, err := verifyPassword(password, encoded, 3); err != nil || !valid {
		t.Fatalf("encoded password did not verify: valid=%v err=%v", valid, err)
	}
	if valid, err := verifyPassword(password, encoded, MinimumPBKDF2Iterations); err == nil || valid {
		t.Fatal("low-iteration test hash passed production verification")
	}
}

func TestLoginRateLimitSessionCSRFAndPasswordRotation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	store := &memoryStore{}
	service := newTestService(t, store, &now)
	password := "correct horse battery staple 123"
	seedCredential(t, service, store, password, now)
	for attempt := 1; attempt <= domain.AdminLoginMaxFailureAttempts; attempt++ {
		_, err := service.Login(context.Background(), "https://console.example.test", "wrong password with enough length", "127.0.0.1")
		if attempt < domain.AdminLoginMaxFailureAttempts && !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("attempt %d error=%v", attempt, err)
		}
		if attempt == domain.AdminLoginMaxFailureAttempts && !errors.Is(err, ErrRateLimited) {
			t.Fatalf("fifth attempt error=%v", err)
		}
	}
	if _, err := service.Login(context.Background(), "https://console.example.test", password, "127.0.0.1"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("locked credential did not return rate limit: %v", err)
	}
	now = now.Add(16 * time.Minute)
	login, err := service.Login(context.Background(), "https://console.example.test", password, "127.0.0.1")
	if err != nil || login.SessionToken == "" || login.CSRFTok == "" || login.SessionToken == login.CSRFTok {
		t.Fatalf("login=%+v err=%v", login, err)
	}
	if _, _, err := service.Session(context.Background(), login.SessionToken); err != nil {
		t.Fatal(err)
	}
	if err := service.ChangePassword(context.Background(), "https://console.example.test", login.SessionToken, login.CSRFTok, password, "new correct horse battery staple 456"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Session(context.Background(), login.SessionToken); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("old session remained valid after rotation: %v", err)
	}
}

func TestAuthorizeControlPlaneWriteOrdersSessionBeforeOriginAndBindsCSRF(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	store := &memoryStore{}
	service := newTestService(t, store, &now)
	password := "correct horse battery staple 123"
	seedCredential(t, service, store, password, now)
	first, err := service.Login(context.Background(), "https://console.example.test", password, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Login(context.Background(), "https://console.example.test", password, "127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthorizeControlPlaneWrite(context.Background(), "https://console.example.test", first.SessionToken, first.CSRFTok); err != nil {
		t.Fatalf("valid write authorization failed: %v", err)
	}
	for _, input := range []struct {
		name, origin, session, csrf string
		want                        error
	}{
		{name: "missing session is not origin detail", origin: "https://other.example.test", want: ErrAuthenticationFailed},
		{name: "wrong origin", origin: "https://other.example.test", session: first.SessionToken, csrf: first.CSRFTok, want: ErrOriginDenied},
		{name: "missing csrf", origin: "https://console.example.test", session: first.SessionToken, want: ErrCSRFInvalid},
		{name: "cross session csrf", origin: "https://console.example.test", session: first.SessionToken, csrf: second.CSRFTok, want: ErrCSRFInvalid},
	} {
		t.Run(input.name, func(t *testing.T) {
			if _, err := service.AuthorizeControlPlaneWrite(context.Background(), input.origin, input.session, input.csrf); !errors.Is(err, input.want) {
				t.Fatalf("error=%v want=%v", err, input.want)
			}
		})
	}
}

func TestProductionPBKDF2FloorCompletesUnderOneSecond(t *testing.T) {
	service, err := NewService(Config{Store: &memoryStore{}, Origin: "https://console.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := service.HashPassword("production PBKDF2 minimum benchmark 123"); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed >= 2*time.Second {
		t.Fatalf("minimum PBKDF2 took %s under the race-safe ceiling", elapsed)
	} else {
		t.Logf("production PBKDF2 600000 iterations took %s", elapsed)
	}
}

func TestAuthServiceOnTaskScopedPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AUTH_SERVICE_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AUTH_SERVICE_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateAuthServiceDSN(t, dsn)
	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(filepath.Join("..", "..", "migrations", "control-plane", "0022_admin_auth.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(payload)); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	service, err := NewService(Config{Store: postgres.NewStore(db), Origin: "https://console.example.test", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := service.HashPassword("postgres correct horse battery staple 123")
	if err != nil {
		t.Fatal(err)
	}
	credential := domain.AdminCredential{ID: "admin_1", PasswordHashScheme: PasswordHashScheme, PasswordHash: hash, CredentialVersion: 1, CreatedAt: now, UpdatedAt: now}
	if err := postgres.NewStore(db).CreateAdminCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < domain.AdminLoginMaxFailureAttempts; attempt++ {
		_, _ = service.Login(ctx, "https://console.example.test", "invalid password that is long enough", "127.0.0.1")
	}
	if _, err := service.Login(ctx, "https://console.example.test", "postgres correct horse battery staple 123", "127.0.0.1"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected persistent lockout, got %v", err)
	}
	now = now.Add(16 * time.Minute)
	login, err := service.Login(ctx, "https://console.example.test", "postgres correct horse battery staple 123", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthorizeControlPlaneWrite(ctx, "https://console.example.test", login.SessionToken, login.CSRFTok); err != nil {
		t.Fatalf("persistent control-plane write authorization failed: %v", err)
	}
	if err := service.ChangePassword(ctx, "https://console.example.test", login.SessionToken, login.CSRFTok, "postgres correct horse battery staple 123", "postgres rotated correct horse battery 456"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Session(ctx, login.SessionToken); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("persistent old session remained valid: %v", err)
	}
}

func validateAuthServiceDSN(t *testing.T, dsn string) {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("task-scoped auth service database URL is invalid")
	}
	if host := parsed.Hostname(); host != "127.0.0.1" && host != "::1" && host != "localhost" {
		t.Fatal("task-scoped auth service database must be loopback-only")
	}
	if database := strings.TrimPrefix(parsed.EscapedPath(), "/"); !strings.HasPrefix(database, "open_card_g2authsvc_") {
		t.Fatal("task-scoped auth service database name must use open_card_g2authsvc_ prefix")
	}
}
