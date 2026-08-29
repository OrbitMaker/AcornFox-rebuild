// Command open-card-admin performs root-only, local administrator credential
// bootstrap and password rotation. It intentionally has no HTTP surface and
// never accepts a password through flags, standard input pipes, or environment
// variables.
package main

import (
	"context"
	"crypto/sha256"
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
	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type commandConfig struct {
	command      string
	passwordFile string
	activationID string
	taskRoot     string
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
	resolved, err := resolveActiveDatabase(config)
	if err != nil {
		return err
	}
	database, err := sql.Open("pgx", resolved.DatabaseURL)
	if err != nil {
		return errors.New("open active administrator database failed")
	}
	defer database.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := database.PingContext(ctx); err != nil {
		return errors.New("ping active administrator database failed")
	}
	if config.command == "activation-validate" || config.command == "candidate-validate" {
		return validateActivationDatabase(ctx, database, resolved.Activation)
	}
	password, err := readRootOnlyPassword(config.passwordFile)
	if err != nil {
		return err
	}
	defer zero(password)
	return applyCredential(ctx, postgres.NewStore(database), config.command, password, time.Now().UTC())
}

func resolveActiveDatabase(config commandConfig) (install.ActiveDatabase, error) {
	var resolver *install.ActiveDatabaseResolver
	var err error
	if config.taskRoot != "" {
		resolver, err = install.TaskActiveDatabaseResolver(config.taskRoot, os.Getuid(), os.Getgid())
	} else {
		resolver, err = install.ProductionActiveDatabaseResolver()
	}
	if err != nil {
		return install.ActiveDatabase{}, errors.New("resolve active database identity failed")
	}
	if config.command == "candidate-validate" {
		resolved, resolveErr := resolver.ResolveActivation(config.activationID)
		if resolveErr != nil {
			return install.ActiveDatabase{}, errors.New("resolve candidate database identity failed")
		}
		return resolved, nil
	}
	resolved, resolveErr := resolver.Resolve()
	if resolveErr != nil {
		return install.ActiveDatabase{}, errors.New("resolve active database identity failed")
	}
	if config.command == "activation-validate" && resolved.Activation.ActivationID != config.activationID {
		return install.ActiveDatabase{}, errors.New("active activation identity mismatch")
	}
	return resolved, nil
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
		return commandConfig{}, errors.New("usage: open-card-admin <bootstrap|reset-password> --password-file ABSOLUTE_PATH [--task-root ABSOLUTE_PATH] | activation validate --activation-id ID [--task-root ABSOLUTE_PATH] | candidate validate --activation-id ID [--task-root ABSOLUTE_PATH]")
	}
	if len(args) == 0 {
		return commandConfig{}, errors.New("command is required")
	}
	config := commandConfig{}
	index := 0
	switch args[0] {
	case "bootstrap", "reset-password":
		config.command = args[0]
		index = 1
	case "activation", "candidate":
		if len(args) < 2 || args[1] != "validate" {
			return commandConfig{}, errors.New("activation and candidate support only validate")
		}
		config.command = args[0] + "-validate"
		index = 2
	default:
		return commandConfig{}, errors.New("unsupported command")
	}
	for ; index < len(args); index++ {
		switch args[index] {
		case "--password-file":
			index++
			if index >= len(args) {
				return commandConfig{}, errors.New("--password-file requires a value")
			}
			config.passwordFile = args[index]
		case "--activation-id":
			index++
			if index >= len(args) {
				return commandConfig{}, errors.New("--activation-id requires a value")
			}
			config.activationID = args[index]
		case "--task-root":
			index++
			if index >= len(args) {
				return commandConfig{}, errors.New("--task-root requires a value")
			}
			config.taskRoot = args[index]
		default:
			return commandConfig{}, fmt.Errorf("unsupported argument %q; passwords are accepted only through --password-file", args[index])
		}
	}
	if (config.command == "bootstrap" || config.command == "reset-password") && (config.passwordFile == "" || !filepath.IsAbs(config.passwordFile)) {
		return commandConfig{}, errors.New("--password-file must be an absolute path")
	}
	if config.taskRoot != "" && !filepath.IsAbs(config.taskRoot) {
		return commandConfig{}, errors.New("--task-root must be an absolute path")
	}
	if (config.command == "activation-validate" || config.command == "candidate-validate") && !validActivationID(config.activationID) {
		return commandConfig{}, errors.New("--activation-id must be valid")
	}
	if (config.command == "activation-validate" || config.command == "candidate-validate") && config.passwordFile != "" {
		return commandConfig{}, errors.New("validation commands do not accept --password-file")
	}
	if (config.command == "bootstrap" || config.command == "reset-password") && config.activationID != "" {
		return commandConfig{}, errors.New("credential commands do not accept --activation-id")
	}
	return config, nil
}

func validActivationID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, c := range value {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') || (index == 0 && (c == '.' || c == '_' || c == '-')) {
			return false
		}
	}
	return true
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

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func validateActivationDatabase(ctx context.Context, database *sql.DB, activation install.ActivationV1) error {
	tx, err := database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return errors.New("begin activation validation failed")
	}
	defer tx.Rollback()
	if err := validateSchemaFacts(ctx, tx, activation.Database.Migration, activation.Database.SchemaMigrationsSHA256); err != nil {
		return err
	}
	return nil
}

func validateSchemaFacts(ctx context.Context, tx *sql.Tx, expectedMigration, expectedDigest string) error {
	var migrationsTable, adminTable, applicationsTable bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass('public.schema_migrations') IS NOT NULL, to_regclass('public.admin_credentials') IS NOT NULL, to_regclass('public.applications') IS NOT NULL`).Scan(&migrationsTable, &adminTable, &applicationsTable); err != nil || !migrationsTable || !adminTable || !applicationsTable {
		return errors.New("activation database schema validation failed")
	}
	rows, err := tx.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return errors.New("activation migration validation failed")
	}
	defer rows.Close()
	hash := sha256.New()
	last := ""
	count := 0
	for rows.Next() {
		var version, checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			return errors.New("activation migration validation failed")
		}
		if len(version) < 4 || checksum == "" {
			return errors.New("activation migration validation failed")
		}
		if _, err := fmt.Fprintf(hash, "%s\t%s\n", version, checksum); err != nil {
			return errors.New("activation migration validation failed")
		}
		last = version[:4]
		count++
	}
	if err := rows.Err(); err != nil || count == 0 || last != expectedMigration || fmt.Sprintf("%x", hash.Sum(nil)) != expectedDigest {
		return errors.New("activation migration validation failed")
	}
	var enabledAdmins int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM admin_credentials WHERE disabled_at IS NULL`).Scan(&enabledAdmins); err != nil || enabledAdmins > 1 {
		return errors.New("activation authentication validation failed")
	}
	return nil
}
