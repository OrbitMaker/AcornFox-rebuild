// Command open-card-admin performs root-only, local administrator credential
// bootstrap and password rotation. It intentionally has no HTTP surface and
// never accepts a password through flags, standard input pipes, or environment
// variables.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/auth"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

const defaultServerEnv = "/etc/open-card/server.env"

type commandConfig struct {
	command      string
	passwordFile string
	serverEnv    string
}

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "open-card-admin: root is required")
		os.Exit(1)
	}
	if err := run(os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "open-card-admin:", err)
		os.Exit(1)
	}
}

func run(args []string, stderr io.Writer) error {
	config, err := parseArgs(args)
	if err != nil {
		return err
	}
	password, err := readRootOnlyPassword(config.passwordFile)
	if err != nil {
		return err
	}
	defer zero(password)
	databaseURL, err := databaseURLFromEnvFile(config.serverEnv)
	if err != nil {
		return err
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("open administrator database: %w", err)
	}
	defer database.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := database.PingContext(ctx); err != nil {
		return fmt.Errorf("ping administrator database: %w", err)
	}
	return applyCredential(ctx, postgres.NewStore(database), config.command, password, time.Now().UTC())
}

func applyCredential(ctx context.Context, store *postgres.Store, command string, password []byte, now time.Time) error {
	service, err := auth.NewService(auth.Config{Store: store})
	if err != nil {
		return err
	}
	hash, err := service.HashPassword(string(password))
	if err != nil {
		return err
	}
	switch command {
	case "bootstrap":
		var exists bool
		if err := store.DB().QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM admin_credentials)`).Scan(&exists); err != nil {
			return fmt.Errorf("inspect administrator records: %w", err)
		}
		if exists {
			return errors.New("administrator already exists; bootstrap is refused")
		}
		id, err := domain.NewID("admin")
		if err != nil {
			return err
		}
		if err := store.CreateAdminCredential(ctx, domain.AdminCredential{ID: id, PasswordHashScheme: auth.PasswordHashScheme, PasswordHash: hash, CredentialVersion: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
	case "reset-password":
		credential, err := store.ActiveAdminCredential(ctx)
		if err != nil {
			if errors.Is(err, postgres.ErrNotFound) {
				return errors.New("administrator does not exist; bootstrap first")
			}
			return err
		}
		if _, err := store.RotateAdminCredential(ctx, credential.ID, credential.CredentialVersion, auth.PasswordHashScheme, hash, now); err != nil {
			return err
		}
	default:
		return errors.New("unsupported command")
	}
	return nil
}

func parseArgs(args []string) (commandConfig, error) {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		return commandConfig{}, errors.New("usage: open-card-admin <bootstrap|reset-password> --password-file ABSOLUTE_PATH [--server-env ABSOLUTE_PATH]")
	}
	if len(args) == 0 || (args[0] != "bootstrap" && args[0] != "reset-password") {
		return commandConfig{}, errors.New("command must be bootstrap or reset-password")
	}
	config := commandConfig{command: args[0], serverEnv: defaultServerEnv}
	for index := 1; index < len(args); index++ {
		switch args[index] {
		case "--password-file":
			index++
			if index >= len(args) {
				return commandConfig{}, errors.New("--password-file requires a value")
			}
			config.passwordFile = args[index]
		case "--server-env":
			index++
			if index >= len(args) {
				return commandConfig{}, errors.New("--server-env requires a value")
			}
			config.serverEnv = args[index]
		default:
			return commandConfig{}, fmt.Errorf("unsupported argument %q; passwords are accepted only through --password-file", args[index])
		}
	}
	if config.passwordFile == "" || !filepath.IsAbs(config.passwordFile) {
		return commandConfig{}, errors.New("--password-file must be an absolute path")
	}
	if !filepath.IsAbs(config.serverEnv) {
		return commandConfig{}, errors.New("--server-env must be an absolute path")
	}
	return config, nil
}

func readRootOnlyPassword(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect password file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return nil, errors.New("password file must be a non-symlink root-only regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return nil, errors.New("password file must be owned by root")
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read password file: %w", err)
	}
	value = []byte(strings.TrimSuffix(strings.TrimSuffix(string(value), "\n"), "\r"))
	if len(value) == 0 {
		return nil, errors.New("password file is empty")
	}
	return value, nil
}

func databaseURLFromEnvFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect server environment: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("server environment must be a non-symlink root-only regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return "", errors.New("server environment must be owned by root")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read server environment: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "OPEN_CARD_DATABASE_URL="); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value), nil
		}
	}
	return "", errors.New("OPEN_CARD_DATABASE_URL is missing from server environment")
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
