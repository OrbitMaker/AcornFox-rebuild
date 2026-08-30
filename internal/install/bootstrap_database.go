package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
)

// The bootstrap runtime template is the only production source for the
// runtime role/host/TLS identity.  Its database component is replaced only
// after the candidate name has been derived from the bootstrap identity.
const (
	productionBootstrapDatabaseEnvPath = "/etc/open-card/bootstrap-database.env"
	productionBootstrapActiveRoot      = "/opt/open-card"
)

var readProductionBootstrapDatabaseEnv = func() ([]byte, error) {
	return readBootstrapRootOnlyDatabaseEnv(productionBootstrapDatabaseEnvPath)
}

// BootstrapDatabaseInput is data-only.  In particular, it has no DSN, path,
// role, tool, SQL, or caller-supplied database name/evidence field.
type BootstrapDatabaseInput struct {
	TransactionID         string
	InstallationIDSHA256  string
	CandidateActivationID string
	Release               ReleaseV1
}

func (i BootstrapDatabaseInput) Validate() error {
	if !validID(i.TransactionID) || !validSHA(i.InstallationIDSHA256) || !validID(i.CandidateActivationID) || !i.Release.valid() || i.Release.Version != Gate6CandidateVersion {
		return errors.New("invalid bootstrap database input")
	}
	if _, err := CandidateDatabaseName(i.CandidateActivationID); err != nil {
		return errors.New("invalid bootstrap database input")
	}
	return nil
}

// BootstrapDatabaseResult carries the published database truth. DatabaseEnv
// remains an in-memory byte binding: it must never be marshalled, logged, or
// included in a journal/error.
type BootstrapDatabaseResult struct {
	Database                      DatabaseV1 `json:"database"`
	DatabaseEnv                   []byte     `json:"-"`
	CandidateDatabaseName         string     `json:"candidate_database_name"`
	RuntimeDatabaseEnvSHA256      string     `json:"runtime_database_env_sha256"`
	ControlDatabaseIdentitySHA256 string     `json:"control_database_identity_sha256"`
	RecoveryEvidenceSHA256        string     `json:"recovery_evidence_sha256"`
}

func (r BootstrapDatabaseResult) Validate() error {
	if !r.Database.valid() || r.Database.Migration != CurrentMigrationVersion || r.CandidateDatabaseName != r.Database.Name || !candidateDatabaseName.MatchString(r.CandidateDatabaseName) || !validSHA(r.RuntimeDatabaseEnvSHA256) || !validSHA(r.ControlDatabaseIdentitySHA256) || !validSHA(r.RecoveryEvidenceSHA256) {
		return errors.New("invalid bootstrap database result")
	}
	env, err := PostgresEnvironment(r.DatabaseEnv)
	if err != nil || env.Descriptor.Database != r.Database.Name {
		return errors.New("invalid bootstrap database result")
	}
	return nil
}

// BootstrapMigrationControl adds ledger creation to the existing typed
// migration transaction seam. It is deliberately not a generic SQL executor.
type BootstrapMigrationControl interface {
	MigrationControl
	EnsureMigrationLedger(context.Context) error
}

// BootstrapMigrations is a verified, ordered RC2 migration payload. SQL is
// retained only in memory for the per-migration transaction that consumes it.
type BootstrapMigrations struct {
	Rows []MigrationRow `json:"rows"`
	SQL  []string       `json:"-"`
}

func (m BootstrapMigrations) Validate() error {
	if len(m.Rows) != 24 || len(m.SQL) != 24 || !validMigrationRows(m.Rows, 24) {
		return errors.New("invalid bootstrap migrations")
	}
	for _, sqlText := range m.SQL {
		if strings.TrimSpace(sqlText) == "" {
			return errors.New("invalid bootstrap migrations")
		}
	}
	return nil
}

type bootstrapCandidateMigrationOpen func(string) (BootstrapMigrationControl, error)
type bootstrapMigrationLoad func() (BootstrapMigrations, error)

// BootstrapDatabase composes the existing candidate identity primitive with
// the bootstrap-specific all-migration ledger contract.
type BootstrapDatabase struct {
	input       BootstrapDatabaseInput
	runtimeEnv  []byte
	runtimeSHA  string
	controlSHA  string
	control     CandidateControl
	runtimeRole string
	open        bootstrapCandidateMigrationOpen
	load        bootstrapMigrationLoad
	close       func() error
}

// ProductionBootstrapDatabase fixes both environment files and the release
// root. The caller supplies only immutable bootstrap identity data.
func ProductionBootstrapDatabase(input BootstrapDatabaseInput) (*BootstrapDatabase, error) {
	if input.Validate() != nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	runtimeEnv, err := readProductionBootstrapDatabaseEnv()
	if err != nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	control, err := NewProductionPostgresControl(runtimeEnv)
	if err != nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	database, err := newBootstrapDatabase(input, runtimeEnv, control.ControlIdentitySHA256(), control, control.runtimeRole, func(name string) (BootstrapMigrationControl, error) {
		return control.ForCandidate(name)
	}, func() (BootstrapMigrations, error) {
		return LoadProductionBootstrapMigrations(input.Release)
	}, control.Close)
	if err != nil {
		_ = control.Close()
		return nil, ErrPostgresOutcomeUnknown
	}
	return database, nil
}

// TaskBootstrapDatabase is the explicit test-only constructor. The release
// directory and database dependencies must be supplied by the test; production
// callers cannot override either fixed root/environment boundary.
func TaskBootstrapDatabase(input BootstrapDatabaseInput, runtimeEnv []byte, controlIdentitySHA256 string, control CandidateControl, runtimeRole string, open func(string) (BootstrapMigrationControl, error), load func() (BootstrapMigrations, error)) (*BootstrapDatabase, error) {
	return newBootstrapDatabase(input, runtimeEnv, controlIdentitySHA256, control, runtimeRole, open, load, nil)
}

func newBootstrapDatabase(input BootstrapDatabaseInput, runtimeEnv []byte, controlIdentitySHA256 string, control CandidateControl, runtimeRole string, open bootstrapCandidateMigrationOpen, load bootstrapMigrationLoad, closeFn func() error) (*BootstrapDatabase, error) {
	if input.Validate() != nil || !validSHA(controlIdentitySHA256) || control == nil || !postgresRoleName.MatchString(runtimeRole) || open == nil || load == nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	env, err := PostgresEnvironment(runtimeEnv)
	if err != nil || env.Descriptor.Database == "" {
		return nil, ErrPostgresOutcomeUnknown
	}
	return &BootstrapDatabase{input: input, runtimeEnv: append([]byte(nil), runtimeEnv...), runtimeSHA: sha256Bytes(runtimeEnv), controlSHA: controlIdentitySHA256, control: control, runtimeRole: runtimeRole, open: open, load: load, close: closeFn}, nil
}

func (b *BootstrapDatabase) Close() error {
	if b == nil || b.close == nil {
		return nil
	}
	closeFn := b.close
	b.close = nil
	return closeFn()
}

// Provision creates/replays the exact candidate database and proves its
// complete 0001..0024 ledger. It never exposes a destructive/drop operation.
func (b *BootstrapDatabase) Provision(ctx context.Context) (BootstrapDatabaseResult, error) {
	if b == nil || b.input.Validate() != nil || ctx.Err() != nil {
		return BootstrapDatabaseResult{}, ErrPostgresOutcomeUnknown
	}
	name, err := CandidateDatabaseName(b.input.CandidateActivationID)
	if err != nil {
		return BootstrapDatabaseResult{}, ErrPostgresOutcomeUnknown
	}
	candidateEnv, err := CandidateDatabaseEnv(b.runtimeEnv, name)
	if err != nil {
		return BootstrapDatabaseResult{}, ErrPostgresOutcomeUnknown
	}
	evidence := bootstrapRecoveryEvidence(b.input, name, b.runtimeSHA, b.controlSHA)
	migrations, err := b.load()
	if err != nil || migrations.Validate() != nil {
		return BootstrapDatabaseResult{}, ErrPostgresOutcomeUnknown
	}
	if _, err := CreateCandidate(ctx, b.control, CreateCandidateRequest{ActivationID: b.input.CandidateActivationID, ExpectedExistingName: name, ExpectedExistingOwner: b.runtimeRole, RecoveryEvidence: evidence}); err != nil {
		return BootstrapDatabaseResult{}, bootstrapDatabaseError(err)
	}
	ledger, err := b.open(name)
	if err != nil || ledger == nil {
		return BootstrapDatabaseResult{}, ErrPostgresOutcomeUnknown
	}
	defer ledgerClose(ledger)
	if err := EnsureMigrationLedger(ctx, ledger, migrations); err != nil {
		return BootstrapDatabaseResult{}, bootstrapDatabaseError(err)
	}
	rows, err := ledger.MigrationRows(ctx)
	if err != nil || !matchesExpected(rows, migrations.Rows) {
		return BootstrapDatabaseResult{}, ErrPostgresOutcomeUnknown
	}
	proof, err := migrationEvidence(rows)
	if err != nil || proof.To != CurrentMigrationVersion || !validSHA(proof.RowsSHA256) {
		return BootstrapDatabaseResult{}, ErrPostgresOutcomeUnknown
	}
	result := BootstrapDatabaseResult{Database: DatabaseV1{Name: name, Migration: CurrentMigrationVersion, SchemaMigrationsSHA256: proof.RowsSHA256}, DatabaseEnv: candidateEnv, CandidateDatabaseName: name, RuntimeDatabaseEnvSHA256: b.runtimeSHA, ControlDatabaseIdentitySHA256: b.controlSHA, RecoveryEvidenceSHA256: evidence}
	if result.Validate() != nil {
		return BootstrapDatabaseResult{}, ErrPostgresOutcomeUnknown
	}
	return result, nil
}

func ledgerClose(value BootstrapMigrationControl) {
	if closer, ok := value.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}

// EnsureMigrationLedger accepts only an empty ledger or one exact contiguous
// prefix. Each missing migration has its own transaction. A commit error is
// deliberately reread: if the exact row became durable it is a successful
// ambiguous commit; any other result remains fail-closed.
func EnsureMigrationLedger(ctx context.Context, control BootstrapMigrationControl, migrations BootstrapMigrations) error {
	if control == nil || migrations.Validate() != nil {
		return ErrPostgresOutcomeUnknown
	}
	if err := control.EnsureMigrationLedger(ctx); err != nil {
		return ErrPostgresOutcomeUnknown
	}
	rows, err := control.MigrationRows(ctx)
	if err != nil || len(rows) > len(migrations.Rows) || !matchesExpected(rows, migrations.Rows[:len(rows)]) {
		return ErrCandidateConflict
	}
	for index := len(rows); index < len(migrations.Rows); index++ {
		tx, err := control.BeginMigration(ctx)
		if err != nil {
			return ErrPostgresOutcomeUnknown
		}
		committed := false
		if err := tx.ExecMigration(ctx, migrations.SQL[index]); err != nil {
			_ = tx.Rollback()
			return ErrPostgresOutcomeUnknown
		}
		if err := tx.RecordMigration(ctx, migrations.Rows[index]); err != nil {
			_ = tx.Rollback()
			return ErrPostgresOutcomeUnknown
		}
		if err := tx.Commit(); err != nil {
			observed, readErr := control.MigrationRows(ctx)
			if readErr != nil || len(observed) != index+1 || !matchesExpected(observed, migrations.Rows[:index+1]) {
				return ErrPostgresOutcomeUnknown
			}
			committed = true
		} else {
			committed = true
		}
		if !committed {
			return ErrPostgresOutcomeUnknown
		}
		rows, err = control.MigrationRows(ctx)
		if err != nil || len(rows) != index+1 || !matchesExpected(rows, migrations.Rows[:index+1]) {
			return ErrPostgresOutcomeUnknown
		}
	}
	return nil
}

// EnsureMigrationLedger on the existing SQL implementation creates only the
// fixed ledger table. It intentionally provides no arbitrary SQL surface.
func (s *SQLMigrationControl) EnsureMigrationLedger(ctx context.Context) error {
	if s == nil || s.database == nil {
		return ErrPostgresOutcomeUnknown
	}
	_, err := s.database.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`)
	if err != nil {
		return ErrPostgresOutcomeUnknown
	}
	return nil
}

// LoadProductionBootstrapMigrations is pinned beneath the production release
// root. It does not accept caller-controlled release directories.
func LoadProductionBootstrapMigrations(release ReleaseV1) (BootstrapMigrations, error) {
	if release.Version != Gate6CandidateVersion || !release.valid() {
		return BootstrapMigrations{}, ErrPostgresOutcomeUnknown
	}
	writer, err := ProductionDurableWriter(productionBootstrapActiveRoot)
	if err != nil {
		return BootstrapMigrations{}, ErrPostgresOutcomeUnknown
	}
	defer writer.Close()
	return loadBootstrapMigrations(writer, release)
}

// LoadTaskBootstrapMigrations is test-only. It preserves the exact same
// manifest/digest/mode checks through an explicit task-owned active root.
func LoadTaskBootstrapMigrations(activeRoot string, uid, gid int, release ReleaseV1) (BootstrapMigrations, error) {
	if !safeAbsPath(activeRoot) || uid < 0 || gid < 0 {
		return BootstrapMigrations{}, ErrPostgresOutcomeUnknown
	}
	writer, err := TaskDurableWriter(activeRoot, uid, gid)
	if err != nil {
		return BootstrapMigrations{}, ErrPostgresOutcomeUnknown
	}
	defer writer.Close()
	return loadBootstrapMigrations(writer, release)
}

func loadBootstrapMigrations(writer *DurableWriter, release ReleaseV1) (BootstrapMigrations, error) {
	if writer == nil || release.Version != Gate6CandidateVersion || !release.valid() {
		return BootstrapMigrations{}, ErrPostgresOutcomeUnknown
	}
	manifestRaw, err := secureReleaseFile(writer, release.ID, "manifest.json", 0o644)
	if err != nil || sha256Bytes(manifestRaw) != release.ManifestSHA256 {
		return BootstrapMigrations{}, ErrPostgresOutcomeUnknown
	}
	manifest, err := parseReleaseManifest(manifestRaw)
	if err != nil || manifest.ReleaseID != release.ID || manifest.Version != Gate6CandidateVersion || manifest.MigrationVersion != CurrentMigrationVersion || manifest.SourceCommit != release.SourceCommit || manifest.Architecture != release.Architecture || ValidateProductionCandidate(manifest) != nil || verifySecureRelease(writer, release.ID, manifest) != nil {
		return BootstrapMigrations{}, ErrPostgresOutcomeUnknown
	}
	byPath := make(map[string]FileDigest, len(manifest.Files))
	for _, file := range manifest.Files {
		byPath[file.Path] = file
	}
	result := BootstrapMigrations{Rows: make([]MigrationRow, 0, 24), SQL: make([]string, 0, 24)}
	for version := 1; version <= 24; version++ {
		prefix := "migrations/control-plane/" + formatMigrationVersion(version) + "_"
		var selected FileDigest
		count := 0
		for path, digest := range byPath {
			if strings.HasPrefix(path, prefix) && strings.HasSuffix(path, ".sql") {
				selected, count = digest, count+1
			}
		}
		if count != 1 || selected.Mode != 0o640 {
			return BootstrapMigrations{}, ErrPostgresOutcomeUnknown
		}
		raw, err := secureReleaseFile(writer, release.ID, selected.Path, 0o640)
		if err != nil || sha256Bytes(raw) != selected.SHA256 || len(raw) == 0 {
			return BootstrapMigrations{}, ErrPostgresOutcomeUnknown
		}
		result.Rows = append(result.Rows, MigrationRow{Version: strings.TrimSuffix(filepath.Base(selected.Path), ".sql"), Checksum: selected.SHA256})
		result.SQL = append(result.SQL, string(raw))
	}
	if result.Validate() != nil {
		return BootstrapMigrations{}, ErrPostgresOutcomeUnknown
	}
	return result, nil
}

func bootstrapRecoveryEvidence(input BootstrapDatabaseInput, name, runtimeDatabaseEnvSHA256, controlDatabaseIdentitySHA256 string) string {
	payload := struct {
		Transaction      string    `json:"transaction"`
		Installation     string    `json:"installation"`
		Activation       string    `json:"activation"`
		Database         string    `json:"database"`
		RuntimeEnvSHA256 string    `json:"runtime_env_sha256"`
		ControlSHA256    string    `json:"control_sha256"`
		Release          ReleaseV1 `json:"release"`
	}{input.TransactionID, input.InstallationIDSHA256, input.CandidateActivationID, name, runtimeDatabaseEnvSHA256, controlDatabaseIdentitySHA256, input.Release}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func bootstrapDatabaseError(err error) error {
	if errors.Is(err, ErrCandidateConflict) {
		return ErrCandidateConflict
	}
	return ErrPostgresOutcomeUnknown
}

func readBootstrapRootOnlyDatabaseEnv(path string) ([]byte, error) {
	if path != productionBootstrapDatabaseEnvPath {
		return nil, errors.New("invalid bootstrap environment")
	}
	writer, err := ProductionDurableWriter(filepath.Dir(path))
	if err != nil {
		return nil, errors.New("invalid bootstrap environment")
	}
	defer writer.Close()
	return readBootstrapDatabaseEnv(writer)
}

func readBootstrapDatabaseEnv(writer *DurableWriter) ([]byte, error) {
	if writer == nil {
		return nil, errors.New("invalid bootstrap environment")
	}
	raw, err := writer.ReadMetadata(filepath.Base(productionBootstrapDatabaseEnvPath))
	if err != nil || len(raw) == 0 {
		return nil, errors.New("invalid bootstrap environment")
	}
	if _, err := ParseDatabaseEnv(raw); err != nil {
		return nil, errors.New("invalid bootstrap environment")
	}
	return raw, nil
}
