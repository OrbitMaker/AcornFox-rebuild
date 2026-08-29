package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// UpgradeDatabasePlan contains the immutable identities the database half of
// an upgrade is allowed to use. In particular, it keeps the physical task
// artifact directory separate from the journal's fixed artifact path.
type UpgradeDatabasePlan struct {
	TransactionID             string
	ArtifactRoot              string
	ArtifactDir               string
	ActiveDatabaseEnv         []byte
	CandidateDatabaseName     string
	CandidateActivationID     string
	CandidateDatabaseEnv      []byte
	CandidateRelease          ReleaseV1
	CandidateReleaseRoot      string
	CandidateRecoveryEvidence string
	DrainInterval             time.Duration
	Validator                 CandidateValidator
	ArtifactWriter            *DurableWriter
}

// ProductionUpgradeDatabaseInput is deliberately data-only. Production paths,
// durable writers, database tools, and candidate validation are fixed by the
// constructor and cannot be substituted by a caller.
type ProductionUpgradeDatabaseInput struct {
	TransactionID          string
	ActiveDatabaseEnv      []byte
	CandidateDatabaseName  string
	CandidateActivationID  string
	CandidateDatabaseEnv   []byte
	CandidateRelease       ReleaseV1
	VerifiedSnapshot       *SnapshotEvidence
	RecoveryEvidenceSHA256 string
}

// ActiveDatabaseInspectionFactory is task-only injection for the temporary
// connection that remains bound to the selected active database.
type ActiveDatabaseInspectionFactory func([]byte) (*SelectedPostgresDatabase, error)

// ActiveDatabaseControlFactory is retained as a compatibility spelling for
// task callers; it has the selected-database return type, never the /postgres
// cluster control type.
type ActiveDatabaseControlFactory = ActiveDatabaseInspectionFactory

// UpgradeDatabaseAdapter composes the fixed Postgres candidate primitives
// into the UpgradeDatabaseDriver boundary. It intentionally has no delete or
// candidate-drop operation: a failed upgrade is recovered through its journal.
type UpgradeDatabaseAdapter struct {
	plan          UpgradeDatabasePlan
	control       *ProductionPostgresControl
	snapshotter   *PostgresSnapshotter
	activeEnv     PostgresProcessEnvironment
	activeEnvSHA  string
	snapshot      *SnapshotEvidence
	activeFactory ActiveDatabaseInspectionFactory
}

// UpgradeDatabaseOpenFunc is a task-only seam for locked engine tests.  It
// receives a defensive copy of the active environment.
type UpgradeDatabaseOpenFunc func(context.Context, UpgradeDatabaseOpenRequest) (UpgradeDatabaseSession, error)

func (f UpgradeDatabaseOpenFunc) Open(ctx context.Context, request UpgradeDatabaseOpenRequest) (UpgradeDatabaseSession, error) {
	if f == nil || request.Validate() != nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	copyRequest := request
	copyRequest.ActiveDatabaseEnv = append([]byte(nil), request.ActiveDatabaseEnv...)
	return f(ctx, copyRequest)
}

// ProductionUpgradeDatabaseFactory is intentionally parameterless: the
// privileged caller may choose an upgrade identity, never paths, tools, or a
// database environment other than the pinned active activation value.
type ProductionUpgradeDatabaseFactory struct{}

func NewProductionUpgradeDatabaseFactory() ProductionUpgradeDatabaseFactory {
	return ProductionUpgradeDatabaseFactory{}
}

func (ProductionUpgradeDatabaseFactory) Open(_ context.Context, request UpgradeDatabaseOpenRequest) (UpgradeDatabaseSession, error) {
	if request.Validate() != nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	candidateEnv, err := CandidateDatabaseEnv(request.ActiveDatabaseEnv, request.CandidateDatabaseName)
	if err != nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	if request.CandidateRelease.ID == "" {
		return newActiveInspectionSession(request.ActiveDatabaseEnv, candidateEnv), nil
	}
	adapter, err := ProductionUpgradeDatabaseAdapter(ProductionUpgradeDatabaseInput{
		TransactionID:          request.TransactionID,
		ActiveDatabaseEnv:      append([]byte(nil), request.ActiveDatabaseEnv...),
		CandidateDatabaseName:  request.CandidateDatabaseName,
		CandidateActivationID:  request.CandidateActivationID,
		CandidateDatabaseEnv:   candidateEnv,
		CandidateRelease:       request.CandidateRelease,
		RecoveryEvidenceSHA256: sha256TextFrom(request.TransactionID + "\n" + request.CandidateActivationID + "\n" + request.CandidateRelease.ManifestSHA256),
	})
	if err != nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	return adapter, nil
}

// activeInspectionSession is used only by legacy PREFLIGHTED recovery, where
// the candidate release tuple is not serialized in the journal.  It can
// inspect the pinned old database but deliberately refuses every mutable
// candidate operation.
type activeInspectionSession struct {
	activeEnv    []byte
	activeEnvSHA string
	candidateEnv []byte
}

func newActiveInspectionSession(activeEnv, candidateEnv []byte) *activeInspectionSession {
	digest := sha256.Sum256(activeEnv)
	return &activeInspectionSession{activeEnv: append([]byte(nil), activeEnv...), activeEnvSHA: hex.EncodeToString(digest[:]), candidateEnv: append([]byte(nil), candidateEnv...)}
}

func (s *activeInspectionSession) InspectActive(ctx context.Context, request ActiveDatabaseInspectionRequest) (DatabaseV1, error) {
	if s == nil || request.Validate() != nil || !bytes.Equal(request.DatabaseEnv, s.activeEnv) || sha256Bytes(request.DatabaseEnv) != s.activeEnvSHA {
		return DatabaseV1{}, ErrPostgresOutcomeUnknown
	}
	return inspectSelectedActiveDatabase(ctx, request, NewSelectedPostgresDatabase)
}
func (s *activeInspectionSession) CandidateDatabaseEnv() []byte {
	return append([]byte(nil), s.candidateEnv...)
}
func (*activeInspectionSession) Close() error                { return nil }
func (*activeInspectionSession) Drain(context.Context) error { return ErrPostgresOutcomeUnknown }
func (*activeInspectionSession) Snapshot(context.Context) (SnapshotEvidence, string, error) {
	return SnapshotEvidence{}, "", ErrPostgresOutcomeUnknown
}
func (*activeInspectionSession) CreateRestore(context.Context, string) error {
	return ErrPostgresOutcomeUnknown
}
func (*activeInspectionSession) Migrate(context.Context) (UpgradeMigrationEvidence, error) {
	return UpgradeMigrationEvidence{}, ErrPostgresOutcomeUnknown
}
func (*activeInspectionSession) Validate(context.Context, string) (ArtifactV1, error) {
	return ArtifactV1{}, ErrPostgresOutcomeUnknown
}

// CandidateDatabaseEnv changes only the selected database path. Credentials,
// host, port, query parameters and TLS mode are preserved by url.URL.
func CandidateDatabaseEnv(active []byte, candidate string) ([]byte, error) {
	if !candidateDatabaseName.MatchString(candidate) {
		return nil, ErrPostgresOutcomeUnknown
	}
	dsn, err := ParseDatabaseEnv(active)
	if err != nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	u, err := url.Parse(dsn)
	if err != nil || strings.Trim(u.EscapedPath(), "/") == "" {
		return nil, ErrPostgresOutcomeUnknown
	}
	u.Path = "/" + candidate
	u.RawPath = ""
	return FormatDatabaseEnv(u.String())
}

// ProductionUpgradeDatabaseAdapter binds only fixed production dependencies.
func ProductionUpgradeDatabaseAdapter(input ProductionUpgradeDatabaseInput) (*UpgradeDatabaseAdapter, error) {
	if !validID(input.TransactionID) || !input.CandidateRelease.valid() || !validSHA(input.RecoveryEvidenceSHA256) || input.VerifiedSnapshot != nil && (!validSHA(input.VerifiedSnapshot.SHA256) || input.VerifiedSnapshot.Size < 1) {
		return nil, ErrPostgresOutcomeUnknown
	}
	writer, err := ProductionDurableWriter(upgradeArtifactsRoot)
	if err != nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	plan := UpgradeDatabasePlan{
		TransactionID:             input.TransactionID,
		ArtifactRoot:              upgradeArtifactsRoot,
		ArtifactDir:               filepath.Join(upgradeArtifactsRoot, input.TransactionID),
		ActiveDatabaseEnv:         input.ActiveDatabaseEnv,
		CandidateDatabaseName:     input.CandidateDatabaseName,
		CandidateActivationID:     input.CandidateActivationID,
		CandidateDatabaseEnv:      input.CandidateDatabaseEnv,
		CandidateRelease:          input.CandidateRelease,
		CandidateReleaseRoot:      filepath.Join(productionActiveRoot, "releases", input.CandidateRelease.ID),
		CandidateRecoveryEvidence: input.RecoveryEvidenceSHA256,
		DrainInterval:             time.Second,
		Validator:                 productionCandidateValidator{path: filepath.Join(productionActiveRoot, "releases", input.CandidateRelease.ID, "bin/open-card-admin")},
		ArtifactWriter:            writer,
	}
	control, err := NewProductionPostgresControl(plan.ActiveDatabaseEnv)
	if err != nil {
		_ = plan.ArtifactWriter.Close()
		return nil, ErrPostgresOutcomeUnknown
	}
	snapshotter, err := ProductionPostgresSnapshotter()
	if err != nil {
		_ = control.Close()
		_ = plan.ArtifactWriter.Close()
		return nil, ErrPostgresOutcomeUnknown
	}
	// The candidate primitive owns fixed-tool validation; the adapter supplies
	// the process boundary used only by production. Task constructors continue
	// to require an injected runner.
	snapshotter.runner = productionPostgresRunner{}
	adapter, err := newUpgradeDatabaseAdapter(plan, control, snapshotter)
	if err != nil {
		_ = control.Close()
		_ = plan.ArtifactWriter.Close()
		return nil, err
	}
	if input.VerifiedSnapshot != nil {
		evidence := *input.VerifiedSnapshot
		adapter.snapshot = &evidence
	}
	return adapter, nil
}

type productionCandidateValidator struct {
	path string
	run  func(context.Context, string, []string, []string) error
}

func (v productionCandidateValidator) ValidateCandidate(ctx context.Context, activationID string) error {
	if !validID(activationID) || !safeAbsPath(v.path) {
		return ErrPostgresOutcomeUnknown
	}
	run := v.run
	if run == nil {
		run = runProductionCandidateValidation
	}
	return run(ctx, v.path, []string{"candidate", "validate", "--activation-id", activationID}, []string{"PATH=/usr/bin:/bin"})
}

func runProductionCandidateValidation(ctx context.Context, path string, args, env []string) error {
	command := exec.CommandContext(ctx, path, args...)
	// Candidate validation resolves its database.env from the candidate
	// activation; its argv and environment never carry a DSN.
	command.Env = append([]string(nil), env...)
	return command.Run()
}

type productionPostgresRunner struct{}

func (productionPostgresRunner) Run(ctx context.Context, argv, env []string) PostgresRunResult {
	if len(argv) == 0 {
		return PostgresRunResult{ExitCode: -1, Err: ErrPostgresOutcomeUnknown}
	}
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	command.Env = append(os.Environ(), env...)
	if err := command.Run(); err != nil {
		if exited, ok := err.(*exec.ExitError); ok {
			return PostgresRunResult{ExitCode: exited.ExitCode(), Err: err}
		}
		return PostgresRunResult{ExitCode: -1, Err: err}
	}
	return PostgresRunResult{}
}

// TaskUpgradeDatabaseAdapter accepts the existing task seams without
// introducing parallel Postgres contracts. The optional dependencies are, in
// order, *ProductionPostgresControl, *PostgresSnapshotter, CandidateValidator,
// and *DurableWriter; plan fields take precedence for the latter two.
//
// The variadic form preserves a compact task constructor while keeping the
// production constructor unable to accept test-only dependencies.
func TaskUpgradeDatabaseAdapter(plan UpgradeDatabasePlan, dependencies ...any) (*UpgradeDatabaseAdapter, error) {
	var control *ProductionPostgresControl
	var snapshotter *PostgresSnapshotter
	var activeFactory ActiveDatabaseInspectionFactory
	for _, dependency := range dependencies {
		switch value := dependency.(type) {
		case *ProductionPostgresControl:
			if control != nil {
				return nil, ErrPostgresOutcomeUnknown
			}
			control = value
		case *PostgresSnapshotter:
			if snapshotter != nil {
				return nil, ErrPostgresOutcomeUnknown
			}
			snapshotter = value
		case CandidateValidator:
			if plan.Validator != nil {
				return nil, ErrPostgresOutcomeUnknown
			}
			plan.Validator = value
		case *DurableWriter:
			if plan.ArtifactWriter != nil {
				return nil, ErrPostgresOutcomeUnknown
			}
			plan.ArtifactWriter = value
		case ActiveDatabaseInspectionFactory:
			if activeFactory != nil {
				return nil, ErrPostgresOutcomeUnknown
			}
			activeFactory = value
		case func([]byte) (*SelectedPostgresDatabase, error):
			if activeFactory != nil {
				return nil, ErrPostgresOutcomeUnknown
			}
			activeFactory = ActiveDatabaseInspectionFactory(value)
		default:
			return nil, ErrPostgresOutcomeUnknown
		}
	}
	adapter, err := newUpgradeDatabaseAdapter(plan, control, snapshotter)
	if err != nil {
		return nil, err
	}
	adapter.activeFactory = activeFactory
	return adapter, nil
}

func newUpgradeDatabaseAdapter(plan UpgradeDatabasePlan, control *ProductionPostgresControl, snapshotter *PostgresSnapshotter) (*UpgradeDatabaseAdapter, error) {
	if control == nil || snapshotter == nil || !validUpgradeDatabasePlan(plan) {
		return nil, ErrPostgresOutcomeUnknown
	}
	activeEnv, err := PostgresEnvironment(plan.ActiveDatabaseEnv)
	if err != nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	manifest, err := verifiedUpgradeRelease(plan)
	if err != nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	if validator, ok := plan.Validator.(productionCandidateValidator); ok && !verifiedProductionValidator(plan.CandidateReleaseRoot, manifest, validator.path) {
		return nil, ErrPostgresOutcomeUnknown
	}
	digest := sha256.Sum256(plan.ActiveDatabaseEnv)
	return &UpgradeDatabaseAdapter{plan: cloneUpgradeDatabasePlan(plan), control: control, snapshotter: snapshotter, activeEnv: activeEnv, activeEnvSHA: hex.EncodeToString(digest[:])}, nil
}

func verifiedProductionValidator(releaseRoot string, manifest Manifest, path string) bool {
	want := filepath.Join(releaseRoot, "bin/open-card-admin")
	if path != want {
		return false
	}
	for _, file := range manifest.Files {
		if file.Path == "bin/open-card-admin" {
			return file.Mode == 0o755
		}
	}
	return false
}

func cloneUpgradeDatabasePlan(plan UpgradeDatabasePlan) UpgradeDatabasePlan {
	plan.ActiveDatabaseEnv = append([]byte(nil), plan.ActiveDatabaseEnv...)
	plan.CandidateDatabaseEnv = append([]byte(nil), plan.CandidateDatabaseEnv...)
	return plan
}

func validUpgradeDatabasePlan(plan UpgradeDatabasePlan) bool {
	if !validID(plan.TransactionID) || !safeAbsPath(plan.ArtifactRoot) || !safeAbsPath(plan.ArtifactDir) || plan.ArtifactDir != filepath.Join(plan.ArtifactRoot, plan.TransactionID) || !plan.CandidateRelease.valid() || !safeAbsPath(plan.CandidateReleaseRoot) || !validID(plan.CandidateActivationID) || plan.Validator == nil || plan.ArtifactWriter == nil {
		return false
	}
	if plan.DrainInterval <= 0 {
		return false
	}
	name, err := CandidateDatabaseName(plan.CandidateActivationID)
	if err != nil || name != plan.CandidateDatabaseName {
		return false
	}
	active, err := PostgresEnvironment(plan.ActiveDatabaseEnv)
	if err != nil || !validID(active.Descriptor.Database) {
		return false
	}
	candidate, err := PostgresEnvironment(plan.CandidateDatabaseEnv)
	if err != nil || candidate.Descriptor.Database != plan.CandidateDatabaseName {
		return false
	}
	if plan.CandidateRecoveryEvidence != "" && !validSHA(plan.CandidateRecoveryEvidence) {
		return false
	}
	return true
}

func (a *UpgradeDatabaseAdapter) Drain(ctx context.Context) error {
	if a == nil || a.control == nil {
		return ErrPostgresOutcomeUnknown
	}
	_, err := WaitForNoOpenCardSessions(ctx, a.control, a.plan.DrainInterval)
	if err != nil {
		return ErrPostgresOutcomeUnknown
	}
	return nil
}

// InspectActive verifies the pre-upgrade active database strictly from the
// selected database.env. It never serializes the request environment or the
// decoded DSN, and its temporary control is always closed before return.
func (a *UpgradeDatabaseAdapter) InspectActive(ctx context.Context, request ActiveDatabaseInspectionRequest) (database DatabaseV1, err error) {
	if a == nil || request.Validate() != nil {
		return DatabaseV1{}, ErrPostgresOutcomeUnknown
	}
	environment, parseErr := PostgresEnvironment(request.DatabaseEnv)
	digest := sha256.Sum256(request.DatabaseEnv)
	if parseErr != nil || !validID(environment.Descriptor.Database) || hex.EncodeToString(digest[:]) != a.activeEnvSHA || environment.Descriptor != a.activeEnv.Descriptor {
		return DatabaseV1{}, ErrPostgresOutcomeUnknown
	}
	factory := a.activeFactory
	if factory == nil {
		factory = NewSelectedPostgresDatabase
	}
	return inspectSelectedActiveDatabase(ctx, request, factory)
}

func inspectSelectedActiveDatabase(ctx context.Context, request ActiveDatabaseInspectionRequest, factory ActiveDatabaseInspectionFactory) (database DatabaseV1, err error) {
	if request.Validate() != nil || factory == nil {
		return DatabaseV1{}, ErrPostgresOutcomeUnknown
	}
	environment, parseErr := PostgresEnvironment(request.DatabaseEnv)
	if parseErr != nil || !validID(environment.Descriptor.Database) {
		return DatabaseV1{}, ErrPostgresOutcomeUnknown
	}
	selected, openErr := factory(append([]byte(nil), request.DatabaseEnv...))
	if openErr != nil || selected == nil || selected.database == nil {
		return DatabaseV1{}, ErrPostgresOutcomeUnknown
	}
	defer func() {
		if closeErr := selected.Close(); closeErr != nil && err == nil {
			database, err = DatabaseV1{}, ErrPostgresOutcomeUnknown
		}
	}()
	rows, queryErr := selected.MigrationRows(ctx)
	if queryErr != nil || !validMigrationRows(rows, request.ExpectedRowCount) {
		return DatabaseV1{}, ErrPostgresOutcomeUnknown
	}
	evidence, evidenceErr := migrationEvidence(rows)
	if evidenceErr != nil || evidence.RowsSHA256 != request.ExpectedRowsSHA256 {
		return DatabaseV1{}, ErrCandidateConflict
	}
	return DatabaseV1{Name: environment.Descriptor.Database, Migration: request.ExpectedMigration, SchemaMigrationsSHA256: evidence.RowsSHA256}, nil
}

func (a *UpgradeDatabaseAdapter) Snapshot(ctx context.Context) (SnapshotEvidence, string, error) {
	if a == nil || !secureArtifactDirectory(a.plan.ArtifactDir) {
		return SnapshotEvidence{}, "", ErrPostgresOutcomeUnknown
	}
	evidence, err := a.snapshotter.Snapshot(ctx, a.plan.TransactionID, a.plan.ArtifactDir, a.activeEnv, a.snapshot)
	if err != nil {
		return SnapshotEvidence{}, "", upgradeDatabaseError(err)
	}
	a.snapshot = &evidence
	return evidence, a.activeEnv.Descriptor.Database, nil
}

func (a *UpgradeDatabaseAdapter) CreateRestore(ctx context.Context, candidate string) error {
	if a == nil || candidate != a.plan.CandidateDatabaseName || a.snapshot == nil {
		return ErrPostgresOutcomeUnknown
	}
	if _, err := CreateCandidate(ctx, a.control, CreateCandidateRequest{
		ActivationID:         a.plan.CandidateActivationID,
		ExpectedExistingName: a.plan.CandidateDatabaseName,
		RecoveryEvidence:     a.recoveryEvidence(),
	}); err != nil {
		return upgradeDatabaseError(err)
	}
	if err := a.snapshotter.Restore(ctx, candidate, filepath.Join(a.plan.ArtifactDir, "control-plane.dump"), *a.snapshot, mustPostgresEnvironment(a.plan.CandidateDatabaseEnv)); err != nil {
		return upgradeDatabaseError(err)
	}
	return nil
}

func (a *UpgradeDatabaseAdapter) recoveryEvidence() string {
	if a.plan.CandidateRecoveryEvidence != "" {
		return a.plan.CandidateRecoveryEvidence
	}
	digest := sha256.Sum256([]byte(a.plan.TransactionID + "\n" + a.plan.CandidateActivationID + "\n" + a.plan.CandidateRelease.ManifestSHA256))
	return hex.EncodeToString(digest[:])
}

func mustPostgresEnvironment(raw []byte) PostgresProcessEnvironment {
	env, _ := PostgresEnvironment(raw)
	return env
}

func (a *UpgradeDatabaseAdapter) Migrate(ctx context.Context) (UpgradeMigrationEvidence, error) {
	if a == nil || a.control == nil {
		return UpgradeMigrationEvidence{}, ErrPostgresOutcomeUnknown
	}
	manifest, err := verifiedUpgradeRelease(a.plan)
	if err != nil {
		return UpgradeMigrationEvidence{}, ErrPostgresOutcomeUnknown
	}
	rows, migrationSQL, err := migrationInput(a.plan.CandidateReleaseRoot, manifest)
	if err != nil {
		return UpgradeMigrationEvidence{}, ErrPostgresOutcomeUnknown
	}
	control, err := a.control.ForCandidate(a.plan.CandidateDatabaseName)
	if err != nil || control == nil {
		return UpgradeMigrationEvidence{}, ErrPostgresOutcomeUnknown
	}
	defer control.Close()
	evidence, err := ApplyCandidateMigration(ctx, control, rows, migrationSQL)
	if err != nil {
		return UpgradeMigrationEvidence{}, upgradeDatabaseError(err)
	}
	return UpgradeMigrationEvidence{From: evidence.From, To: evidence.To, RowsSHA256: evidence.RowsSHA256, ReleaseManifestSHA256: a.plan.CandidateRelease.ManifestSHA256}, nil
}

func (a *UpgradeDatabaseAdapter) Validate(ctx context.Context, activationID string) (ArtifactV1, error) {
	if a == nil || activationID != a.plan.CandidateActivationID {
		return ArtifactV1{}, ErrPostgresOutcomeUnknown
	}
	if err := ValidateCandidate(ctx, a.plan.Validator, activationID); err != nil {
		return ArtifactV1{}, upgradeDatabaseError(err)
	}
	raw, err := validationEvidence(a.plan)
	if err != nil {
		return ArtifactV1{}, ErrPostgresOutcomeUnknown
	}
	name := filepath.ToSlash(filepath.Join(a.plan.TransactionID, "validation.json"))
	if err := createExactValidation(a.plan.ArtifactWriter, name, raw); err != nil {
		return ArtifactV1{}, upgradeDatabaseError(err)
	}
	digest := sha256.Sum256(raw)
	return ArtifactV1{Path: artifactPath(a.plan.TransactionID, "validation.json"), SHA256: hex.EncodeToString(digest[:]), Size: int64(len(raw))}, nil
}

func (a *UpgradeDatabaseAdapter) Close() error {
	if a == nil || a.control == nil {
		return nil
	}
	controlErr := a.control.Close()
	if a.plan.ArtifactWriter != nil {
		if err := a.plan.ArtifactWriter.Close(); controlErr == nil {
			return err
		}
	}
	return controlErr
}

func (a *UpgradeDatabaseAdapter) CandidateDatabaseEnv() []byte {
	if a == nil {
		return nil
	}
	return append([]byte(nil), a.plan.CandidateDatabaseEnv...)
}

func secureArtifactDirectory(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 == 0
}

func verifiedUpgradeRelease(plan UpgradeDatabasePlan) (Manifest, error) {
	if !safeAbsPath(plan.CandidateReleaseRoot) || filepath.Base(plan.CandidateReleaseRoot) != plan.CandidateRelease.ID {
		return Manifest{}, ErrPostgresOutcomeUnknown
	}
	if err := ensureNoSymlinkBetween(filepath.Dir(plan.CandidateReleaseRoot), plan.CandidateReleaseRoot); err != nil {
		return Manifest{}, ErrPostgresOutcomeUnknown
	}
	manifestPath := filepath.Join(plan.CandidateReleaseRoot, "manifest.json")
	info, err := os.Lstat(manifestPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return Manifest{}, ErrPostgresOutcomeUnknown
	}
	digest, err := SHA256File(manifestPath)
	if err != nil || digest != plan.CandidateRelease.ManifestSHA256 {
		return Manifest{}, ErrPostgresOutcomeUnknown
	}
	manifest, err := LoadManifest(manifestPath)
	if err != nil || manifest.ReleaseID != plan.CandidateRelease.ID || manifest.Version != plan.CandidateRelease.Version || manifest.SourceCommit != plan.CandidateRelease.SourceCommit || manifest.Architecture != plan.CandidateRelease.Architecture || manifest.MigrationVersion != CurrentMigrationVersion {
		return Manifest{}, ErrPostgresOutcomeUnknown
	}
	if ValidateProductionCandidate(manifest) != nil || VerifyRelease(plan.CandidateReleaseRoot, manifest) != nil {
		return Manifest{}, ErrPostgresOutcomeUnknown
	}
	return manifest, nil
}

func migrationInput(releaseRoot string, manifest Manifest) ([]MigrationRow, string, error) {
	byPath := make(map[string]FileDigest, len(manifest.Files))
	for _, file := range manifest.Files {
		byPath[file.Path] = file
	}
	rows := make([]MigrationRow, 0, 24)
	var migrationSQL string
	for version := 1; version <= 24; version++ {
		prefix := "migrations/control-plane/" + formatMigrationVersion(version) + "_"
		var match FileDigest
		matches := 0
		for path, file := range byPath {
			if strings.HasPrefix(path, prefix) && strings.HasSuffix(path, ".sql") {
				match, matches = file, matches+1
			}
		}
		if matches != 1 || match.Mode != 0o644 {
			return nil, "", ErrPostgresOutcomeUnknown
		}
		rows = append(rows, MigrationRow{Version: formatMigrationVersion(version), Checksum: match.SHA256})
		if version == 24 {
			raw, err := os.ReadFile(filepath.Join(releaseRoot, filepath.FromSlash(match.Path)))
			if err != nil || sha256TextFrom(string(raw)) != match.SHA256 {
				return nil, "", ErrPostgresOutcomeUnknown
			}
			migrationSQL = string(raw)
		}
	}
	if !validMigrationRows(rows, 24) || migrationSQL == "" {
		return nil, "", ErrPostgresOutcomeUnknown
	}
	return rows, migrationSQL, nil
}

func formatMigrationVersion(version int) string { return fmt.Sprintf("%04d", version) }

func validationEvidence(plan UpgradeDatabasePlan) ([]byte, error) {
	payload := struct {
		Code           string `json:"code"`
		CandidateID    string `json:"candidate_activation_id"`
		ManifestSHA256 string `json:"manifest_sha256"`
		SchemaVersion  int    `json:"schema_version"`
	}{Code: "candidate_validated", CandidateID: plan.CandidateActivationID, ManifestSHA256: plan.CandidateRelease.ManifestSHA256, SchemaVersion: 1}
	return json.Marshal(payload)
}

func createExactValidation(writer *DurableWriter, name string, raw []byte) error {
	if writer == nil {
		return ErrPostgresOutcomeUnknown
	}
	if err := writer.CreateMetadata(name, raw); err == nil {
		return nil
	}
	existing, err := writer.ReadMetadata(name)
	if err != nil || !bytes.Equal(existing, raw) {
		return ErrCandidateConflict
	}
	return nil
}

func upgradeDatabaseError(err error) error {
	if errors.Is(err, ErrCandidateConflict) || errors.Is(err, ErrSnapshotConflict) || errors.Is(err, ErrPostgresOutcomeUnknown) {
		return err
	}
	return ErrPostgresOutcomeUnknown
}

var _ UpgradeDatabaseSession = (*UpgradeDatabaseAdapter)(nil)
var _ UpgradeDatabaseFactory = ProductionUpgradeDatabaseFactory{}
