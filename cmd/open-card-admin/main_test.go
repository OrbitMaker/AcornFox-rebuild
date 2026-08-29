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
	for _, args := range [][]string{{"bootstrap"}, {"bootstrap", "--password", "secret"}, {"reset-password", "--password-file", "relative"}, {"bootstrap", "--password-file", "/tmp/password", "--server-env", "/etc/open-card/server.env"}, {"activation", "validate"}, {"candidate", "validate", "--activation-id", "../../escape"}} {
		if _, err := parseArgs(args); err == nil {
			t.Fatalf("expected rejected arguments: %#v", args)
		}
	}
	config, err := parseArgs([]string{"bootstrap", "--password-file", "/etc/open-card/bootstrap-password"})
	if err != nil || config.command != "bootstrap" || config.taskRoot != "" {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	candidate, err := parseArgs([]string{"candidate", "validate", "--activation-id", "activation-1", "--task-root", "/tmp/open-card-task-root"})
	if err != nil || candidate.command != "candidate-validate" || candidate.activationID != "activation-1" || candidate.taskRoot != "/tmp/open-card-task-root" {
		t.Fatalf("candidate=%#v err=%v", candidate, err)
	}
}

func TestRuntimeUnitsPutActiveDatabaseAfterGlobalConfigAndGateEdge(t *testing.T) {
	server, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "open-card-server.service"))
	if err != nil {
		t.Fatal(err)
	}
	global := strings.Index(string(server), "EnvironmentFile=-/etc/open-card/server.env")
	active := strings.Index(string(server), "EnvironmentFile=/opt/open-card/active/database.env")
	if global < 0 || active < 0 || global >= active {
		t.Fatal("server unit does not load mandatory active database.env after global config")
	}
	edge, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "open-card-edge.service"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(edge), "ConditionPathExists=!/var/lib/open-card/upgrade-in-progress") {
		t.Fatal("edge is not gated by the fixed upgrade marker")
	}
}

func TestAdminRejectsLegacyServerEnvAndRedactsActiveResolutionErrors(t *testing.T) {
	t.Setenv("OPEN_CARD_DATABASE_URL", "postgresql://admin:secret@db.example/open_card")
	if _, err := parseArgs([]string{"bootstrap", "--password-file", "/tmp/password", "--server-env", "/etc/open-card/server.env"}); err == nil {
		t.Fatal("legacy server.env fallback flag was accepted")
	}
	_, err := resolveActiveDatabase(commandConfig{command: "activation-validate", activationID: "activation-1", taskRoot: "/definitely/missing/open-card"})
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "postgres") {
		t.Fatalf("active resolution error leaked a DSN: %v", err)
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
