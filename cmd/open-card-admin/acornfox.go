package main

import (
	"context"
	"database/sql"
	"errors"
	"github.com/open-card/open-card/internal/install"
	"io"
	"os"
	"time"
)

var (
	processIdentity   = "legacy"
	buildVersion      string
	buildSourceCommit string
	buildLayoutSchema string
)

func runAcornFoxAdmin(args []string, stderr io.Writer, euid func() int) error {
	c, err := parseArgs(args)
	if err != nil {
		return err
	}
	if euid() != 0 {
		return errors.New("root is required")
	}
	if (c.command != "bootstrap" && c.command != "reset-password") || c.taskRoot != "" || buildLayoutSchema != "1" {
		return errors.New("unsupported AcornFox administrator command or build identity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	database, err := install.OpenAcornFoxAdminDatabase(ctx, buildVersion, buildSourceCommit)
	if err != nil {
		return err
	}
	defer database.Close()
	return runWithDatabaseValidation(args, stderr, euid, os.Lstat, func(commandConfig) (install.ActiveDatabase, error) {
		// Credential writes need only the DSN. No AcornFox activation is
		// represented as a legacy activation or passed to legacy validation.
		return install.ActiveDatabase{DatabaseURL: database.DatabaseURL}, nil
	}, nil, func(ctx context.Context, db *sql.DB) error {
		tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return errors.New("validate AcornFox administrator database failed")
		}
		defer tx.Rollback()
		var name, role string
		if err := tx.QueryRowContext(ctx, "SELECT current_database(), current_user").Scan(&name, &role); err != nil || name != "acornfox" || role != "acornfox" {
			return errors.New("AcornFox administrator database identity mismatch")
		}
		if err := validateSchemaFacts(ctx, tx, install.AcornFoxV1MigrationVersion, database.MigrationRowsSHA256); err != nil {
			return errors.New("AcornFox administrator schema identity mismatch")
		}
		return tx.Commit()
	})
}
