//go:build g4b2e2e

package postgres

// This file is intentionally compiled only by the task-local G4B2 E2E test.
// It is not a production schema-management API.

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const g4b2E2EDatabasePrefix = "open_card_g4b2_e2e_"

// ResetG4B2E2ESchema clears and reapplies the control-plane schema only after
// proving that db is a loopback PostgreSQL connection to a task-named
// database. The caller owns the PostgreSQL process and supplies the repository
// root so canonical migrations, rather than ad-hoc fixture SQL, are used.
func ResetG4B2E2ESchema(ctx context.Context, db *sql.DB, repositoryRoot string) error {
	if db == nil {
		return fmt.Errorf("G4B2 E2E database is required")
	}
	if err := validateG4B2E2EDatabase(ctx, db); err != nil {
		return err
	}
	migrations, err := g4b2E2EMigrationFiles(repositoryRoot)
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		return fmt.Errorf("reset G4B2 E2E schema: %w", err)
	}
	for _, migration := range migrations {
		payload, err := os.ReadFile(migration)
		if err != nil {
			return fmt.Errorf("read G4B2 E2E migration %s: %w", filepath.Base(migration), err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin G4B2 E2E migration %s: %w", filepath.Base(migration), err)
		}
		if _, err := tx.ExecContext(ctx, string(payload)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply G4B2 E2E migration %s: %w", filepath.Base(migration), err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit G4B2 E2E migration %s: %w", filepath.Base(migration), err)
		}
	}
	return nil
}

func validateG4B2E2EDatabase(ctx context.Context, db *sql.DB) error {
	var database, serverAddress string
	if err := db.QueryRowContext(ctx, `SELECT current_database(), COALESCE(host(inet_server_addr()), '')`).Scan(&database, &serverAddress); err != nil {
		return fmt.Errorf("inspect G4B2 E2E database: %w", err)
	}
	if !strings.HasPrefix(database, g4b2E2EDatabasePrefix) {
		return fmt.Errorf("G4B2 E2E database must use %q prefix", g4b2E2EDatabasePrefix)
	}
	ip := net.ParseIP(serverAddress)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("G4B2 E2E PostgreSQL server must be loopback-only")
	}
	return nil
}

func g4b2E2EMigrationFiles(repositoryRoot string) ([]string, error) {
	repositoryRoot = strings.TrimSpace(repositoryRoot)
	if repositoryRoot == "" {
		return nil, fmt.Errorf("G4B2 E2E repository root is required")
	}
	directory := filepath.Join(repositoryRoot, "migrations", "control-plane")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read G4B2 E2E migrations: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		files = append(files, filepath.Join(directory, entry.Name()))
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("G4B2 E2E migrations are empty")
	}
	sort.Strings(files)
	return files, nil
}
