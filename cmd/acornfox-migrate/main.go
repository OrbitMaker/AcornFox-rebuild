package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/open-card/open-card/internal/migrationpreview"
)

func main() {
	fs := flag.NewFlagSet("acornfox-migrate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dry := fs.Bool("dry-run", false, "required; diagnostic projection only, never activation")
	dsn := fs.String("source-dsn-file", "", "explicit0600 source DSN file; no ambient DATABASE_URL")
	output := fs.String("output-parent", "", "existing private0700 parent; each run creates a new private diagnostic directory")
	dump := fs.String("pg-dump", "/usr/lib/postgresql/16/bin/pg_dump", "trusted PG16 dump executable")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			fs.SetOutput(os.Stdout)
			fmt.Println("PG→SQLite diagnostic dry-run. activation_eligible is always false.")
			fs.PrintDefaults()
			return
		}
		fmt.Fprintln(os.Stderr, "invalid_arguments")
		os.Exit(2)
	}
	if !*dry || fs.NArg() != 0 || *dsn == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "explicit_dry_run_source_file_and_private_output_required")
		os.Exit(2)
	}
	result, err := migrationpreview.Run(context.Background(), migrationpreview.Config{SourceDSNFile: *dsn, OutputParent: *output, DumpTool: *dump})
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	// Only a sanitized report and private artifact path are emitted, never source rows.
	_ = json.NewEncoder(os.Stdout).Encode(struct {
		Report           migrationpreview.Report `json:"report"`
		PrivateDirectory string                  `json:"private_directory"`
	}{result.Report, result.PrivateDirectory})
}
