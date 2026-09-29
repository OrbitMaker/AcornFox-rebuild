package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/open-card/open-card/internal/persistence/sqlite"
)

// writeCompiledNativeSchema describes this binary's registered migrations.
// It does not inspect a database or initialize the Core runtime.
func writeCompiledNativeSchema(out io.Writer, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("native-schema accepts no arguments: %q", args[0])
	}
	pins := sqlite.CompiledNativeMigrationPins()
	type migration struct {
		Version  string `json:"version"`
		Checksum string `json:"checksum"`
	}
	response := struct {
		SchemaVersion      int         `json:"schema_version"`
		RequiredMigrations []migration `json:"required_migrations"`
	}{SchemaVersion: 1, RequiredMigrations: make([]migration, 0, len(pins))}
	for _, pin := range pins {
		response.RequiredMigrations = append(response.RequiredMigrations, migration{pin.Version, pin.Checksum})
	}
	raw, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("marshal native schema: %w", err)
	}
	raw = append(raw, '\n')
	n, err := out.Write(raw)
	if err != nil {
		return fmt.Errorf("write native schema: %w", err)
	}
	if n != len(raw) {
		return errors.New("write native schema: short write")
	}
	return nil
}
