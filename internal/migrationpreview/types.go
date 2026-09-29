// Package migrationpreview implements a standalone, never-activatable diagnostic
// projection. It does not expose database access through the core repository.
package migrationpreview

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"syscall"

	"github.com/open-card/open-card/internal/install"
)

type Config struct{ SourceDSNFile, OutputParent, DumpTool string }
type Column struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	NotNull bool   `json:"not_null"`
}
type Relation struct {
	Name           string   `json:"name"`
	Kind           string   `json:"kind"`
	Partition      bool     `json:"partition"`
	Parent         *string  `json:"parent"`
	Columns        []Column `json:"columns"`
	Constraints    []string `json:"constraints"`
	ViewDefinition string   `json:"view_definition"`
}
type SchemaDifference struct{ Relation, Column, ExpectedType, ObservedType, Code string }
type Matrix struct {
	Differences []SchemaDifference     `json:"-"`
	Version     int                    `json:"version"`
	Migrations  []install.MigrationRow `json:"migrations"`
	Relations   []Relation             `json:"relations"`
}
type ColumnCoverage struct {
	Name, Type, Disposition string
	NonNullRows             int64
}
type RelationCoverage struct {
	Name, Kind, Disposition, SHA256 string
	Partition                       bool
	Parent                          *string
	Rows                            int64
	Columns                         []ColumnCoverage
}
type SequenceObservation struct {
	Name      string
	LastValue int64
	IsCalled  bool
}
type Report struct {
	Status                 string                   `json:"status"`
	ActivationEligible     bool                     `json:"activation_eligible"`
	ProjectionVerified     bool                     `json:"projection_verified"`
	SchemaVersion          int                      `json:"schema_version"`
	FailureCodes           []string                 `json:"failure_codes"`
	SchemaDifferences      []SchemaDifference       `json:"schema_differences,omitempty"`
	Dump                   install.SnapshotEvidence `json:"dump"`
	SnapshotIdentitySHA256 string                   `json:"snapshot_identity_sha256"`
	ManifestSHA256         string                   `json:"manifest_sha256"`
	Coverage               []RelationCoverage       `json:"coverage"`
	SequenceObservations   []SequenceObservation    `json:"sequence_observations"`
	SequenceContinuation   string                   `json:"sequence_continuation"`
	ProjectionCounts       map[string]int64         `json:"projection_counts,omitempty"`
}
type Result struct {
	Report           Report
	PrivateDirectory string
}

// Process output is intentionally discarded: PG errors may contain source values.
type dumpRunner struct{}

func (dumpRunner) Run(ctx context.Context, argv, env []string) install.PostgresRunResult {
	// The existing snapshotter supplies this fixed --file argument. Precreating
	// only this new private output keeps partial dumps0600 if pg_dump fails.
	if len(argv) < 4 || argv[2] != "--file" {
		return install.PostgresRunResult{ExitCode: 1, Err: errors.New("dump_arguments_rejected")}
	}
	f, err := os.OpenFile(argv[3], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return install.PostgresRunResult{ExitCode: 1, Err: errors.New("dump_output_rejected")}
	}
	if f.Close() != nil {
		return install.PostgresRunResult{ExitCode: 1, Err: errors.New("dump_output_rejected")}
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = env
	err = cmd.Run()
	if err != nil {
		return install.PostgresRunResult{ExitCode: 1, Err: errors.New("dump_process_failed")}
	}
	return install.PostgresRunResult{}
}
func digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func privateFile(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("source_file_rejected")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, errors.New("source_file_rejected")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != uint32(os.Getuid()) || st.Nlink != 1 || info.Size() <= 0 || info.Size() > 4096 {
		return nil, errors.New("source_file_rejected")
	}
	b := make([]byte, info.Size())
	n, err := f.Read(b)
	if err != nil || n != len(b) {
		return nil, errors.New("source_file_rejected")
	}
	return b, nil
}
func writePrivate(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}
