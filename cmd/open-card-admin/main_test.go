package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/auth"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

func TestParseArgsRejectsPasswordArgumentsAndEnvironment(t *testing.T) {
	for _, args := range [][]string{{"bootstrap"}, {"bootstrap", "--password", "secret"}, {"reset-password", "--password-file", "relative"}, {"bootstrap", "--password-file", "/tmp/password", "--server-env", "relative"}} {
		if _, err := parseArgs(args); err == nil {
			t.Fatalf("expected rejected arguments: %#v", args)
		}
	}
	config, err := parseArgs([]string{"bootstrap", "--password-file", "/etc/open-card/bootstrap-password"})
	if err != nil || config.serverEnv != defaultServerEnv {
		t.Fatalf("config=%#v err=%v", config, err)
	}
}

func TestAdminBootstrapAndResetOnTaskScopedPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_ADMIN_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_ADMIN_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	database, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	if _, err := database.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", "control-plane", "0022_admin_auth.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	store := postgres.NewStore(database)
	now := time.Unix(1_700_000_000, 0).UTC()
	if err := applyCredential(ctx, store, "bootstrap", []byte("bootstrap correct horse battery staple 123"), now); err != nil {
		t.Fatal(err)
	}
	if err := applyCredential(ctx, store, "bootstrap", []byte("another correct horse battery staple 456"), now); err == nil {
		t.Fatal("second bootstrap was accepted")
	}
	credential, err := store.ActiveAdminCredential(ctx)
	if err != nil || credential.CredentialVersion != 1 {
		t.Fatalf("credential=%+v err=%v", credential, err)
	}
	service, err := auth.NewService(auth.Config{Store: store, Origin: "https://console.example.test", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	login, err := service.Login(ctx, "https://console.example.test", "bootstrap correct horse battery staple 123", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := applyCredential(ctx, store, "reset-password", []byte("rotated correct horse battery staple 789"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Session(ctx, login.SessionToken); !errors.Is(err, auth.ErrAuthenticationFailed) {
		t.Fatalf("old session remained valid after reset: %v", err)
	}
	credential, err = store.ActiveAdminCredential(ctx)
	if err != nil || credential.CredentialVersion != 2 {
		t.Fatalf("rotated credential=%+v err=%v", credential, err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE admin_credentials SET disabled_at = now()`); err != nil {
		t.Fatal(err)
	}
	if err := applyCredential(ctx, store, "bootstrap", []byte("disabled record still blocks bootstrap 999"), now.Add(2*time.Minute)); err == nil {
		t.Fatal("bootstrap accepted a disabled historical administrator")
	}
}

func TestReadRootOnlyPasswordRejectsSymlinkAndOpenPermissions(t *testing.T) {
	directory := t.TempDir()
	plain := filepath.Join(directory, "password")
	if err := os.WriteFile(plain, []byte("correct horse battery staple\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readRootOnlyPassword(plain); err == nil {
		t.Fatal("world-readable password file was accepted")
	}
	link := filepath.Join(directory, "password-link")
	if err := os.Symlink(plain, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRootOnlyPassword(link); err == nil {
		t.Fatal("password symlink was accepted")
	}
}
