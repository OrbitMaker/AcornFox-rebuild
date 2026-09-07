package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

type webSetupMemoryStore struct {
	mu             sync.Mutex
	exists         bool
	credential     domain.AdminCredential
	createCalls    int
	inspectErr     error
	createErr      error
	commitThenFail bool
	beforeCreate   func()
}

func (s *webSetupMemoryStore) AdministratorExists(context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inspectErr != nil {
		return false, s.inspectErr
	}
	return s.exists, nil
}

func (s *webSetupMemoryStore) CreateAdminCredential(_ context.Context, credential domain.AdminCredential) error {
	if s.beforeCreate != nil {
		s.beforeCreate()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.createCalls++
	if s.exists {
		return errors.New("administrator singleton conflict")
	}
	if s.createErr != nil && !s.commitThenFail {
		return s.createErr
	}
	s.exists = true
	s.credential = credential
	if s.commitThenFail {
		return errors.New("commit outcome was not returned")
	}
	return nil
}

func webSetupFixture(t *testing.T, store WebSetupStore, now *time.Time, token string) *WebSetupService {
	t.Helper()
	authService, err := newService(Config{Store: &memoryStore{}, Origin: "https://console.example.test", Iterations: 1, Random: rand.Reader, Clock: func() time.Time { return *now }}, true)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewWebSetupService(WebSetupConfig{Store: store, Auth: authService, SetupTokenCredential: []byte(token + "\n"), Clock: func() time.Time { return *now }})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func fixedWebSetupToken(seed byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{seed}, tokenBytes))
}

func TestWebSetupStateFailsClosedAndNeverReopens(t *testing.T) {
	now := time.Date(2026, 9, 7, 8, 0, 0, 0, time.UTC)
	store := &webSetupMemoryStore{}
	authService := newTestService(t, &memoryStore{}, &now)
	missing, err := NewWebSetupService(WebSetupConfig{Store: store, Auth: authService, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if got := missing.State(context.Background()); got != WebSetupStateUnavailable {
		t.Fatalf("missing credential state=%q", got)
	}
	validToken := fixedWebSetupToken(6)
	for _, malformed := range [][]byte{[]byte(validToken + "\r\n"), []byte(validToken + "\n\n"), []byte(" " + validToken)} {
		service, err := NewWebSetupService(WebSetupConfig{Store: store, Auth: authService, SetupTokenCredential: malformed, Clock: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		if got := service.State(context.Background()); got != WebSetupStateUnavailable {
			t.Fatalf("malformed credential state=%q", got)
		}
	}
	store.exists = true
	if got := missing.State(context.Background()); got != WebSetupStateInitialized {
		t.Fatalf("historical administrator state=%q", got)
	}
	store.inspectErr = errors.New("database sentinel")
	if got := missing.State(context.Background()); got != WebSetupStateUnavailable {
		t.Fatalf("database failure state=%q", got)
	}
}

func TestWebSetupRejectsBadTokenThenConsumesTokenThroughAdministratorState(t *testing.T) {
	now := time.Date(2026, 9, 7, 8, 0, 0, 0, time.UTC)
	store := &webSetupMemoryStore{}
	token := fixedWebSetupToken(7)
	service := webSetupFixture(t, store, &now, token)
	password := "correct horse battery staple"
	bad := fixedWebSetupToken(8)
	if err := service.Setup(context.Background(), "https://console.example.test", bad, password); !errors.Is(err, ErrWebSetupToken) || strings.Contains(err.Error(), bad) {
		t.Fatalf("bad token error=%v", err)
	}
	if err := service.Setup(context.Background(), "https://console.example.test", token, password); err != nil {
		t.Fatal(err)
	}
	if store.createCalls != 1 || service.State(context.Background()) != WebSetupStateInitialized {
		t.Fatalf("calls=%d state=%q", store.createCalls, service.State(context.Background()))
	}
	matches, err := service.auth.VerifyPasswordHash(password, store.credential.PasswordHash)
	if err != nil || !matches {
		t.Fatalf("stored password hash did not verify: matches=%v err=%v", matches, err)
	}
	if err := service.Setup(context.Background(), "https://console.example.test", token, "another correct horse battery staple"); !errors.Is(err, ErrWebSetupInitialized) {
		t.Fatalf("replay error=%v", err)
	}
	if store.createCalls != 1 {
		t.Fatalf("replay made %d creates", store.createCalls)
	}
}

func TestWebSetupConcurrentBootstrapCreatesOneAdministrator(t *testing.T) {
	now := time.Date(2026, 9, 7, 8, 0, 0, 0, time.UTC)
	store := &webSetupMemoryStore{}
	token := fixedWebSetupToken(9)
	service := webSetupFixture(t, store, &now, token)
	const callers = 12
	start := make(chan struct{})
	store.beforeCreate = func() { <-start }
	errorsByCaller := make(chan error, callers)
	for index := 0; index < callers; index++ {
		go func() {
			errorsByCaller <- service.Setup(context.Background(), "https://console.example.test", token, "concurrent correct password")
		}()
	}
	close(start)
	successes := 0
	initialized := 0
	for index := 0; index < callers; index++ {
		err := <-errorsByCaller
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrWebSetupInitialized):
			initialized++
		case errors.Is(err, ErrRateLimited):
			// The bounded unauthenticated lane rejects excess concurrent work
			// before hashing; it does not weaken singleton behavior.
		default:
			t.Fatalf("unexpected concurrent error=%v", err)
		}
	}
	if successes != 1 || initialized < 1 || store.createCalls < 1 || !store.exists {
		t.Fatalf("successes=%d initialized=%d createCalls=%d exists=%v", successes, initialized, store.createCalls, store.exists)
	}
}

func TestWebSetupLateCreateFailureObservesCommitAndRefusesSecondAccount(t *testing.T) {
	now := time.Date(2026, 9, 7, 8, 0, 0, 0, time.UTC)
	store := &webSetupMemoryStore{commitThenFail: true}
	token := fixedWebSetupToken(10)
	service := webSetupFixture(t, store, &now, token)
	err := service.Setup(context.Background(), "https://console.example.test", token, "late failure correct password")
	if !errors.Is(err, ErrWebSetupInitialized) || service.State(context.Background()) != WebSetupStateInitialized {
		t.Fatalf("late failure=%v state=%q", err, service.State(context.Background()))
	}
	if err := service.Setup(context.Background(), "https://console.example.test", token, "second account password"); !errors.Is(err, ErrWebSetupInitialized) {
		t.Fatalf("second attempt error=%v", err)
	}
	if store.createCalls != 1 {
		t.Fatalf("late failure made %d creates", store.createCalls)
	}
}

func TestWebSetupRequiresExactOriginAndBoundsAttempts(t *testing.T) {
	now := time.Date(2026, 9, 7, 8, 0, 0, 0, time.UTC)
	store := &webSetupMemoryStore{}
	token := fixedWebSetupToken(11)
	service := webSetupFixture(t, store, &now, token)
	for _, origin := range []string{"", "http://console.example.test", "https://console.example.test/", "https://other.example.test"} {
		if err := service.Setup(context.Background(), origin, token, "origin protected password"); !errors.Is(err, ErrOriginDenied) {
			t.Fatalf("origin=%q error=%v", origin, err)
		}
	}
	bad := fixedWebSetupToken(12)
	for attempt := 0; attempt < domain.AdminLoginMaxFailureAttempts; attempt++ {
		if err := service.Setup(context.Background(), "https://console.example.test", bad, "rate limited password"); !errors.Is(err, ErrWebSetupToken) {
			t.Fatalf("attempt=%d error=%v", attempt, err)
		}
	}
	if err := service.Setup(context.Background(), "https://console.example.test", token, "rate limited password"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("rate limit error=%v", err)
	}
	now = now.Add(domain.AdminLoginFailureWindow)
	if err := service.Setup(context.Background(), "https://console.example.test", token, "rate limited password"); err != nil {
		t.Fatalf("post-window setup error=%v", err)
	}
}
