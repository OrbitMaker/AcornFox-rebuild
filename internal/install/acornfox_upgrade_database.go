package install

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	acornFoxUpgradeDatabaseSchema       = 1
	acornFoxUpgradeDatabaseRoot         = "database"
	acornFoxUpgradeDatabaseDump         = "control-plane.dump"
	acornFoxUpgradeDatabaseSnapshot     = "snapshot.json"
	acornFoxUpgradeDatabaseShadowIntent = "shadow-intent.json"
	acornFoxUpgradeDatabaseMigrated     = "migrated.json"
	acornFoxUpgradeDatabaseValidated    = "validated.json"

	acornFoxUpgradeDatabasePlanned         = "PLANNED"
	acornFoxUpgradeDatabasePrefixVerified  = "PREFIX_VERIFIED"
	acornFoxUpgradeDatabaseSnapshotCreated = "SNAPSHOT_CREATED"
	acornFoxUpgradeDatabaseShadowReady     = "SHADOW_READY"
	acornFoxUpgradeDatabaseMigrationsDone  = "MIGRATED"
	acornFoxUpgradeDatabaseHealthValidated = "VALIDATED"
)

// acornFoxCrossSchemaDatabaseName is shared by the environment and receipt
// validators. A matching name is only a syntactic prerequisite; the terminal
// upgrade journal remains the authority for selecting it as current.
var acornFoxUpgradeShadowName = regexp.MustCompile(`^acornfox_upg_[a-f0-9]{20}$`)

var acornFoxCrossSchemaDatabaseName = acornFoxUpgradeShadowName

// acornFoxUpgradeDatabaseEvidence is safe to embed in the private upgrade
// journal. It deliberately contains only hashes, deterministic identifiers,
// and the dump size. Database environment bytes and decoded connection data
// never cross this type.
type acornFoxUpgradeDatabaseEvidence struct {
	SchemaVersion              int    `json:"schema_version"`
	State                      string `json:"state"`
	TransactionID              string `json:"transaction_id"`
	OldBindingSHA256           string `json:"old_binding_sha256"`
	NextBindingSHA256          string `json:"next_binding_sha256"`
	ShadowDatabase             string `json:"shadow_database"`
	RecoveryEvidenceSHA256     string `json:"recovery_evidence_sha256"`
	SourceRowsSHA256           string `json:"source_rows_sha256"`
	CandidateRowsSHA256        string `json:"candidate_rows_sha256,omitempty"`
	CandidateDatabaseEnvSHA256 string `json:"candidate_database_env_sha256"`
	SnapshotSHA256             string `json:"snapshot_sha256,omitempty"`
	SnapshotSize               int64  `json:"snapshot_size,omitempty"`
}

func (e acornFoxUpgradeDatabaseEvidence) validate() error {
	rank := acornFoxUpgradeDatabaseStateRank(e.State)
	if e.SchemaVersion != acornFoxUpgradeDatabaseSchema || rank == 0 || !validID(e.TransactionID) || !validSHA(e.OldBindingSHA256) || !validSHA(e.NextBindingSHA256) || e.OldBindingSHA256 == e.NextBindingSHA256 || !acornFoxCrossSchemaDatabaseName.MatchString(e.ShadowDatabase) || !validSHA(e.RecoveryEvidenceSHA256) || !validSHA(e.SourceRowsSHA256) || !validSHA(e.CandidateDatabaseEnvSHA256) {
		return ErrAcornFoxUpgradeConflict
	}
	if rank < acornFoxUpgradeDatabaseStateRank(acornFoxUpgradeDatabaseSnapshotCreated) {
		if e.SnapshotSHA256 != "" || e.SnapshotSize != 0 || e.CandidateRowsSHA256 != "" {
			return ErrAcornFoxUpgradeConflict
		}
		return nil
	}
	if !validSHA(e.SnapshotSHA256) || e.SnapshotSize < 1 {
		return ErrAcornFoxUpgradeConflict
	}
	if rank < acornFoxUpgradeDatabaseStateRank(acornFoxUpgradeDatabaseShadowReady) {
		if e.CandidateRowsSHA256 != "" {
			return ErrAcornFoxUpgradeConflict
		}
		return nil
	}
	if !validSHA(e.CandidateRowsSHA256) {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}

func acornFoxUpgradeDatabaseStateRank(state string) int {
	switch state {
	case acornFoxUpgradeDatabasePlanned:
		return 1
	case acornFoxUpgradeDatabasePrefixVerified:
		return 2
	case acornFoxUpgradeDatabaseSnapshotCreated:
		return 3
	case acornFoxUpgradeDatabaseShadowReady:
		return 4
	case acornFoxUpgradeDatabaseMigrationsDone:
		return 5
	case acornFoxUpgradeDatabaseHealthValidated:
		return 6
	default:
		return 0
	}
}

// acornFoxUpgradeDatabasePrivate is the only result that carries candidate
// database environment bytes. It is intentionally package-private and always
// formats as redacted text; its JSON form contains evidence only.
type acornFoxUpgradeDatabasePrivate struct {
	Evidence             acornFoxUpgradeDatabaseEvidence `json:"evidence"`
	candidateEnvironment []byte
}

func (p acornFoxUpgradeDatabasePrivate) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "AcornFox upgrade database [redacted]")
}

func (p acornFoxUpgradeDatabasePrivate) candidateEnvironmentBytes() []byte {
	return bytes.Clone(p.candidateEnvironment)
}

type acornFoxUpgradeShadowIdentity struct {
	Exists   bool
	Owner    string
	Evidence string
}

type acornFoxUpgradeDatabaseAdmin interface {
	Inspect(context.Context, string) (acornFoxUpgradeShadowIdentity, error)
	Create(context.Context, string) error
	SetEvidence(context.Context, string, string) error
}

type acornFoxUpgradeMigrationOpen func([]byte) (BootstrapMigrationControl, error)

type acornFoxUpgradeDatabaseHealth interface {
	Check(context.Context, []byte, string, string) error
}

type acornFoxUpgradeDatabase struct {
	layout               acornFoxInstallLayout
	transactionID        string
	oldBindingSHA256     string
	nextBindingSHA256    string
	shadowDatabase       string
	recoveryEvidence     string
	artifactID           string
	activeEnvironment    []byte
	candidateEnvironment []byte
	activeProcessEnv     PostgresProcessEnvironment
	candidateProcessEnv  PostgresProcessEnvironment
	migrations           acornFoxControlPlaneMigrations
	sourceDataVersion    int
	rootWriter           *DurableWriter
	snapshotter          *PostgresSnapshotter
	runner               PostgresRunner
	admin                acornFoxUpgradeDatabaseAdmin
	open                 acornFoxUpgradeMigrationOpen
	health               acornFoxUpgradeDatabaseHealth
}

func newProductionAcornFoxUpgradeDatabase(layout acornFoxInstallLayout, transactionID, oldBindingSHA256, nextBindingSHA256 string, activeEnvironment []byte, migrations acornFoxControlPlaneMigrations, sourceDataVersion int) (*acornFoxUpgradeDatabase, error) {
	if layout.validate() != nil || layout.mode != acornFoxInstallLayoutProduction || layout.hostRootPath != "/" || layout.stateRootPath != "/var/lib/acornfox/install" {
		return nil, ErrAcornFoxUpgradeConflict
	}
	rootWriter, err := ProductionDurableWriter(layout.stateRootPath)
	if err != nil {
		return nil, ErrAcornFoxUpgradeUnknown
	}
	snapshotter, err := ProductionPostgresSnapshotter()
	if err != nil {
		_ = rootWriter.Close()
		return nil, ErrAcornFoxUpgradeUnknown
	}
	runner := productionPostgresRunner{}
	snapshotter.runner = runner
	admin, err := newAcornFoxProductionUpgradeDatabaseAdmin()
	if err != nil {
		_ = rootWriter.Close()
		return nil, ErrAcornFoxUpgradeUnknown
	}
	database, err := newAcornFoxUpgradeDatabase(layout, transactionID, oldBindingSHA256, nextBindingSHA256, activeEnvironment, migrations, sourceDataVersion, rootWriter, snapshotter, runner, admin, openAcornFoxUpgradeMigrationControl, acornFoxUpgradeDefaultDatabaseHealth{})
	if err != nil {
		_ = rootWriter.Close()
		return nil, err
	}
	return database, nil
}

// loadAcornFoxUpgradeMigrations reads the already verified inactive substrate.
// It is safe before copyNextSubstrate because the descriptor-pinned substrate,
// rather than a future /opt/acornfox release path, is the source of every SQL
// byte and checksum.
func loadAcornFoxUpgradeMigrations(substrate *PublishedAcornFoxSubstrateV1, nextBindingSHA256 string) (acornFoxControlPlaneMigrations, error) {
	if substrate == nil || !validSHA(nextBindingSHA256) || substrate.Verify() != nil {
		return acornFoxControlPlaneMigrations{}, ErrAcornFoxUpgradeConflict
	}
	candidate := substrate.receipt.CandidateReceipt
	if candidate.BindingSHA256 != nextBindingSHA256 || candidate.MigrationVersion != AcornFoxV1MigrationVersion || candidate.ReleaseID == "" {
		return acornFoxControlPlaneMigrations{}, ErrAcornFoxUpgradeConflict
	}
	prefix := "opt/acornfox/releases/" + candidate.ReleaseID + "/migrations/control-plane/"
	entries := make(map[string]SubstrateEntry, len(acornFoxV1Migrations))
	for _, entry := range substrate.receipt.Entries {
		if strings.HasPrefix(entry.Path, prefix) {
			entries[entry.Path] = entry
		}
	}
	result := acornFoxControlPlaneMigrations{rows: make([]MigrationRow, 0, len(acornFoxV1Migrations)), sql: make([]string, 0, len(acornFoxV1Migrations))}
	for _, name := range acornFoxV1Migrations {
		path := prefix + name
		entry, ok := entries[path]
		if !ok || entry.Kind != SubstrateEntryFile || entry.Mode != 0o640 || !validSHA(entry.SHA256) || entry.Size < 1 {
			return acornFoxControlPlaneMigrations{}, ErrAcornFoxUpgradeConflict
		}
		raw, err := acornFoxLiveReadSource(substrate.root, substrate, entry)
		if err != nil || sha256Bytes(raw) != entry.SHA256 || len(raw) == 0 {
			return acornFoxControlPlaneMigrations{}, ErrAcornFoxUpgradeConflict
		}
		result.rows = append(result.rows, MigrationRow{Version: strings.TrimSuffix(name, ".sql"), Checksum: entry.SHA256})
		result.sql = append(result.sql, string(raw))
	}
	if len(entries) != len(acornFoxV1Migrations) || !result.valid() {
		return acornFoxControlPlaneMigrations{}, ErrAcornFoxUpgradeConflict
	}
	return result, nil
}

// newTaskAcornFoxUpgradeDatabase is the only dependency-injection boundary.
// It retains the production layout model and fixed PostgreSQL 16 argv while
// allowing task-local process, SQL, and health behavior.
func newTaskAcornFoxUpgradeDatabase(layout acornFoxInstallLayout, transactionID, oldBindingSHA256, nextBindingSHA256 string, activeEnvironment []byte, migrations acornFoxControlPlaneMigrations, sourceDataVersion int, runner PostgresRunner, admin acornFoxUpgradeDatabaseAdmin, open acornFoxUpgradeMigrationOpen, health acornFoxUpgradeDatabaseHealth) (*acornFoxUpgradeDatabase, error) {
	if layout.validate() != nil || layout.mode != acornFoxInstallLayoutProduction || runner == nil || admin == nil || open == nil || health == nil {
		return nil, ErrAcornFoxUpgradeConflict
	}
	rootWriter, err := TaskDurableWriter(layout.stateRootPath, layout.stateOwner.uid, layout.stateOwner.gid)
	if err != nil {
		return nil, ErrAcornFoxUpgradeUnknown
	}
	snapshotter := &PostgresSnapshotter{tool: productionPostgresDumpTool, restoreTool: productionPostgresRestoreTool, runner: runner}
	database, err := newAcornFoxUpgradeDatabase(layout, transactionID, oldBindingSHA256, nextBindingSHA256, activeEnvironment, migrations, sourceDataVersion, rootWriter, snapshotter, runner, admin, open, health)
	if err != nil {
		_ = rootWriter.Close()
		return nil, err
	}
	return database, nil
}

func newAcornFoxUpgradeDatabase(layout acornFoxInstallLayout, transactionID, oldBindingSHA256, nextBindingSHA256 string, activeEnvironment []byte, migrations acornFoxControlPlaneMigrations, sourceDataVersion int, rootWriter *DurableWriter, snapshotter *PostgresSnapshotter, runner PostgresRunner, admin acornFoxUpgradeDatabaseAdmin, open acornFoxUpgradeMigrationOpen, health acornFoxUpgradeDatabaseHealth) (*acornFoxUpgradeDatabase, error) {
	if !validID(transactionID) || !validSHA(oldBindingSHA256) || !validSHA(nextBindingSHA256) || oldBindingSHA256 == nextBindingSHA256 || !validAcornFoxControlPlaneEnvironment(activeEnvironment) || !migrations.valid() || (sourceDataVersion != 34 && sourceDataVersion != 39) || sourceDataVersion >= len(migrations.rows) || rootWriter == nil || rootWriter.VerifyLiveRoot() != nil || snapshotter == nil || snapshotter.tool != productionPostgresDumpTool || snapshotter.restoreTool != productionPostgresRestoreTool || runner == nil || admin == nil || open == nil || health == nil {
		return nil, ErrAcornFoxUpgradeConflict
	}
	activeProcessEnv, err := acornFoxUpgradePostgresEnvironment(activeEnvironment, acornFoxControlPlaneDatabase)
	if err != nil {
		return nil, ErrAcornFoxUpgradeConflict
	}
	recovery := sha256Bytes([]byte("acornfox-cross-schema-database-v1\x00" + transactionID + "\x00" + oldBindingSHA256 + "\x00" + nextBindingSHA256))
	shadow := "acornfox_upg_" + recovery[:20]
	candidateEnvironment, candidateProcessEnv, err := acornFoxUpgradeCandidateEnvironment(activeEnvironment, shadow)
	if err != nil || !acornFoxCrossSchemaDatabaseName.MatchString(shadow) {
		return nil, ErrAcornFoxUpgradeConflict
	}
	return &acornFoxUpgradeDatabase{
		layout: layout, transactionID: transactionID, oldBindingSHA256: oldBindingSHA256, nextBindingSHA256: nextBindingSHA256,
		shadowDatabase: shadow, recoveryEvidence: recovery, artifactID: "cross-schema-" + recovery[:20],
		activeEnvironment: bytes.Clone(activeEnvironment), candidateEnvironment: candidateEnvironment,
		activeProcessEnv: activeProcessEnv, candidateProcessEnv: candidateProcessEnv, migrations: migrations, sourceDataVersion: sourceDataVersion,
		rootWriter: rootWriter, snapshotter: snapshotter, runner: runner, admin: admin, open: open, health: health,
	}, nil
}

func (d *acornFoxUpgradeDatabase) Close() error {
	if d == nil || d.rootWriter == nil {
		return nil
	}
	writer := d.rootWriter
	d.rootWriter = nil
	d.activeEnvironment = nil
	d.candidateEnvironment = nil
	return writer.Close()
}

// acornFoxExpectedCurrentDatabase is the sole bridge that permits ordinary
// runtime/admin validation to accept a non-default AcornFox database. A name
// matching the shadow regex is insufficient: the locked current repository
// and the canonical terminal cross-schema journal must bind the same next
// image and VALIDATED database evidence.
func acornFoxExpectedCurrentDatabase(store *TaskAcornFoxRepoStore, bindingSHA256 string) (string, error) {
	if store == nil || !store.ownsLock() || store.layout.validate() != nil || store.layout.mode != acornFoxInstallLayoutProduction || !validSHA(bindingSHA256) {
		return "", ErrAcornFoxUpgradeConflict
	}
	repository, err := store.Load(context.Background())
	if err != nil || repository.Phase != AcornFoxRepoPreparedFinal || repository.NeedsRecovery || repository.BindingSHA256 != bindingSHA256 {
		return "", ErrAcornFoxUpgradeConflict
	}
	reader := &acornFoxUpgrade{layout: store.layout, ownership: store.ownership}
	journal, err := reader.load(store)
	if err != nil || journal.Phase != "UPGRADED" || journal.CrossSchema == nil || journal.CrossSchema.validate(journal) != nil {
		return "", ErrAcornFoxUpgradeConflict
	}
	return acornFoxExpectedCurrentDatabaseFromJournal(repository, journal, bindingSHA256)
}

func acornFoxExpectedCurrentDatabaseFromJournal(repository AcornFoxRepoJournalV1, journal acornFoxUpgradeJournal, bindingSHA256 string) (string, error) {
	if !validSHA(bindingSHA256) || repository.Validate() != nil || repository.Phase != AcornFoxRepoPreparedFinal || repository.NeedsRecovery || repository.BindingSHA256 != bindingSHA256 || journal.Phase != "UPGRADED" || journal.CrossSchema == nil {
		return "", ErrAcornFoxUpgradeConflict
	}
	evidence := journal.CrossSchema.Database
	if evidence.validate() != nil || evidence.State != acornFoxUpgradeDatabaseHealthValidated || evidence.NextBindingSHA256 != bindingSHA256 || journal.Next.Repo.BindingSHA256 != bindingSHA256 || !sameAcornFoxRepoJournal(repository, journal.Next.Repo) || !acornFoxUpgradeShadowName.MatchString(evidence.ShadowDatabase) {
		return "", ErrAcornFoxUpgradeConflict
	}
	return evidence.ShadowDatabase, nil
}

func (d *acornFoxUpgradeDatabase) baseEvidence(state string) acornFoxUpgradeDatabaseEvidence {
	return acornFoxUpgradeDatabaseEvidence{
		SchemaVersion: acornFoxUpgradeDatabaseSchema, State: state, TransactionID: d.transactionID,
		OldBindingSHA256: d.oldBindingSHA256, NextBindingSHA256: d.nextBindingSHA256,
		ShadowDatabase: d.shadowDatabase, RecoveryEvidenceSHA256: d.recoveryEvidence,
		SourceRowsSHA256:           acornFoxMigrationRowsSHA256(d.migrations.rows[:d.sourceDataVersion]),
		CandidateDatabaseEnvSHA256: sha256Bytes(d.candidateEnvironment),
	}
}

// Plan exposes the deterministic candidate database identity and the private
// candidate environment before PostgreSQL effects. Orchestration can use this
// to build the next private image and its environment digest before creating
// the upgrade journal.
func (d *acornFoxUpgradeDatabase) Plan() (acornFoxUpgradeDatabasePrivate, error) {
	if d == nil || d.rootWriter == nil || d.rootWriter.VerifyLiveRoot() != nil || len(d.candidateEnvironment) == 0 {
		return acornFoxUpgradeDatabasePrivate{}, ErrAcornFoxUpgradeUnknown
	}
	evidence := d.baseEvidence(acornFoxUpgradeDatabasePlanned)
	if err := evidence.validate(); err != nil {
		return acornFoxUpgradeDatabasePrivate{}, err
	}
	return acornFoxUpgradeDatabasePrivate{Evidence: evidence, candidateEnvironment: bytes.Clone(d.candidateEnvironment)}, nil
}

func (d *acornFoxUpgradeDatabase) InspectPrefix(ctx context.Context) (acornFoxUpgradeDatabaseEvidence, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || d.open == nil || len(d.migrations.rows) != AcornFoxV1DataVersion {
		return acornFoxUpgradeDatabaseEvidence{}, ErrAcornFoxUpgradeUnknown
	}
	control, err := d.open(bytes.Clone(d.activeEnvironment))
	if err != nil || control == nil {
		return acornFoxUpgradeDatabaseEvidence{}, ErrAcornFoxUpgradeUnknown
	}
	defer ledgerClose(control)
	rows, err := control.MigrationRows(ctx)
	if err != nil {
		return acornFoxUpgradeDatabaseEvidence{}, ErrAcornFoxUpgradeUnknown
	}
	if len(rows) != d.sourceDataVersion || !matchesExpected(rows, d.migrations.rows[:d.sourceDataVersion]) {
		return acornFoxUpgradeDatabaseEvidence{}, ErrAcornFoxUpgradeConflict
	}
	evidence := d.baseEvidence(acornFoxUpgradeDatabasePrefixVerified)
	return evidence, evidence.validate()
}

func (d *acornFoxUpgradeDatabase) Snapshot(ctx context.Context, prior *acornFoxUpgradeDatabaseEvidence) (acornFoxUpgradeDatabaseEvidence, error) {
	prefix, err := d.InspectPrefix(ctx)
	if err != nil {
		return acornFoxUpgradeDatabaseEvidence{}, err
	}
	if prior != nil && (prior.validate() != nil || !d.sameIdentity(*prior) || acornFoxUpgradeDatabaseStateRank(prior.State) < acornFoxUpgradeDatabaseStateRank(acornFoxUpgradeDatabasePlanned)) {
		return acornFoxUpgradeDatabaseEvidence{}, ErrAcornFoxUpgradeConflict
	}
	writer, err := d.artifactWriter()
	if err != nil {
		return acornFoxUpgradeDatabaseEvidence{}, err
	}
	defer writer.Close()
	dumpPath := filepath.Join(writer.rootPath, acornFoxUpgradeDatabaseDump)
	actual, statErr := snapshotEvidence(dumpPath)
	if statErr != nil {
		if !errors.Is(statErr, os.ErrNotExist) {
			if _, lstatErr := os.Lstat(dumpPath); !errors.Is(lstatErr, os.ErrNotExist) {
				return acornFoxUpgradeDatabaseEvidence{}, ErrAcornFoxUpgradeConflict
			}
		}
		actual, err = d.snapshotter.Snapshot(ctx, d.transactionID, writer.rootPath, d.activeProcessEnv, nil)
		if err != nil {
			return acornFoxUpgradeDatabaseEvidence{}, ErrAcornFoxUpgradeUnknown
		}
	}
	evidence := prefix
	evidence.State = acornFoxUpgradeDatabaseSnapshotCreated
	evidence.SnapshotSHA256, evidence.SnapshotSize = actual.SHA256, actual.Size
	if prior != nil && acornFoxUpgradeDatabaseStateRank(prior.State) >= acornFoxUpgradeDatabaseStateRank(acornFoxUpgradeDatabaseSnapshotCreated) && (prior.SnapshotSHA256 != evidence.SnapshotSHA256 || prior.SnapshotSize != evidence.SnapshotSize) {
		return acornFoxUpgradeDatabaseEvidence{}, ErrAcornFoxUpgradeConflict
	}
	if err := d.verifyCustomDump(ctx, dumpPath, d.activeProcessEnv); err != nil {
		return acornFoxUpgradeDatabaseEvidence{}, err
	}
	if _, err := d.ensureWitness(writer, acornFoxUpgradeDatabaseSnapshot, evidence); err != nil {
		return acornFoxUpgradeDatabaseEvidence{}, err
	}
	return evidence, nil
}

func (d *acornFoxUpgradeDatabase) RestoreMigrate(ctx context.Context, prior acornFoxUpgradeDatabaseEvidence) (acornFoxUpgradeDatabasePrivate, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || prior.validate() != nil || !d.sameIdentity(prior) || acornFoxUpgradeDatabaseStateRank(prior.State) < acornFoxUpgradeDatabaseStateRank(acornFoxUpgradeDatabaseSnapshotCreated) {
		return acornFoxUpgradeDatabasePrivate{}, ErrAcornFoxUpgradeConflict
	}
	writer, err := d.artifactWriter()
	if err != nil {
		return acornFoxUpgradeDatabasePrivate{}, err
	}
	defer writer.Close()
	if err := d.verifySnapshot(writer, prior); err != nil {
		return acornFoxUpgradeDatabasePrivate{}, err
	}
	intentExisted, err := d.ensureShadowIntent(ctx, writer, prior)
	if err != nil {
		return acornFoxUpgradeDatabasePrivate{}, err
	}
	identity, err := d.ensureShadow(ctx, intentExisted)
	if err != nil {
		return acornFoxUpgradeDatabasePrivate{}, err
	}
	control, rows, err := d.inspectCandidate(ctx)
	if err != nil && identity.Evidence != d.shadowEvidence("created") {
		return acornFoxUpgradeDatabasePrivate{}, ErrAcornFoxUpgradeUnknown
	}
	if err == nil {
		defer ledgerClose(control)
	}
	if err != nil {
		if restoreErr := d.restore(ctx, writer, prior); restoreErr != nil {
			return acornFoxUpgradeDatabasePrivate{}, restoreErr
		}
		control, rows, err = d.inspectCandidate(ctx)
		if err != nil || len(rows) != d.sourceDataVersion || !matchesExpected(rows, d.migrations.rows[:d.sourceDataVersion]) {
			ledgerClose(control)
			return acornFoxUpgradeDatabasePrivate{}, ErrAcornFoxUpgradeConflict
		}
		defer ledgerClose(control)
	} else if len(rows) < d.sourceDataVersion || len(rows) > AcornFoxV1DataVersion || !matchesExpected(rows, d.migrations.rows[:len(rows)]) {
		return acornFoxUpgradeDatabasePrivate{}, ErrAcornFoxUpgradeConflict
	}
	if identity.Evidence == d.shadowEvidence("migrated") && len(rows) != AcornFoxV1DataVersion {
		return acornFoxUpgradeDatabasePrivate{}, ErrAcornFoxUpgradeConflict
	}
	if len(rows) == d.sourceDataVersion {
		if err := d.setShadowEvidence(ctx, "restored"); err != nil {
			return acornFoxUpgradeDatabasePrivate{}, err
		}
	}
	rows, err = d.migrateTail(ctx, control, rows)
	if err != nil {
		return acornFoxUpgradeDatabasePrivate{}, err
	}
	if err := d.setShadowEvidence(ctx, "migrated"); err != nil {
		return acornFoxUpgradeDatabasePrivate{}, err
	}
	evidence := prior
	evidence.State = acornFoxUpgradeDatabaseMigrationsDone
	evidence.CandidateRowsSHA256 = acornFoxMigrationRowsSHA256(rows)
	if evidence.CandidateRowsSHA256 != acornFoxMigrationRowsSHA256(d.migrations.rows) || evidence.validate() != nil {
		return acornFoxUpgradeDatabasePrivate{}, ErrAcornFoxUpgradeConflict
	}
	if _, err := d.ensureWitness(writer, acornFoxUpgradeDatabaseMigrated, evidence); err != nil {
		return acornFoxUpgradeDatabasePrivate{}, err
	}
	return acornFoxUpgradeDatabasePrivate{Evidence: evidence, candidateEnvironment: bytes.Clone(d.candidateEnvironment)}, nil
}

func (d *acornFoxUpgradeDatabase) Validate(ctx context.Context, prepared acornFoxUpgradeDatabasePrivate) (acornFoxUpgradeDatabasePrivate, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || prepared.Evidence.validate() != nil || !d.sameIdentity(prepared.Evidence) || prepared.Evidence.State != acornFoxUpgradeDatabaseMigrationsDone || !bytes.Equal(prepared.candidateEnvironment, d.candidateEnvironment) || sha256Bytes(prepared.candidateEnvironment) != prepared.Evidence.CandidateDatabaseEnvSHA256 {
		return acornFoxUpgradeDatabasePrivate{}, ErrAcornFoxUpgradeConflict
	}
	control, rows, err := d.inspectCandidate(ctx)
	if err != nil {
		return acornFoxUpgradeDatabasePrivate{}, ErrAcornFoxUpgradeUnknown
	}
	defer ledgerClose(control)
	if !matchesExpected(rows, d.migrations.rows) || acornFoxMigrationRowsSHA256(rows) != prepared.Evidence.CandidateRowsSHA256 {
		return acornFoxUpgradeDatabasePrivate{}, ErrAcornFoxUpgradeConflict
	}
	if err := d.health.Check(ctx, bytes.Clone(d.candidateEnvironment), d.shadowDatabase, prepared.Evidence.CandidateRowsSHA256); err != nil {
		return acornFoxUpgradeDatabasePrivate{}, ErrAcornFoxUpgradeUnknown
	}
	if err := d.setShadowEvidence(ctx, "validated"); err != nil {
		return acornFoxUpgradeDatabasePrivate{}, err
	}
	evidence := prepared.Evidence
	evidence.State = acornFoxUpgradeDatabaseHealthValidated
	writer, err := d.artifactWriter()
	if err != nil {
		return acornFoxUpgradeDatabasePrivate{}, err
	}
	defer writer.Close()
	if _, err := d.ensureWitness(writer, acornFoxUpgradeDatabaseValidated, evidence); err != nil {
		return acornFoxUpgradeDatabasePrivate{}, err
	}
	return acornFoxUpgradeDatabasePrivate{Evidence: evidence, candidateEnvironment: bytes.Clone(d.candidateEnvironment)}, nil
}

func (d *acornFoxUpgradeDatabase) Prepare(ctx context.Context, prior *acornFoxUpgradeDatabaseEvidence) (acornFoxUpgradeDatabasePrivate, error) {
	snapshot, err := d.Snapshot(ctx, prior)
	if err != nil {
		return acornFoxUpgradeDatabasePrivate{}, err
	}
	prepared, err := d.RestoreMigrate(ctx, snapshot)
	if err != nil {
		return acornFoxUpgradeDatabasePrivate{}, err
	}
	return d.Validate(ctx, prepared)
}

func (d *acornFoxUpgradeDatabase) sameIdentity(e acornFoxUpgradeDatabaseEvidence) bool {
	base := d.baseEvidence(acornFoxUpgradeDatabasePrefixVerified)
	return e.TransactionID == base.TransactionID && e.OldBindingSHA256 == base.OldBindingSHA256 && e.NextBindingSHA256 == base.NextBindingSHA256 && e.ShadowDatabase == base.ShadowDatabase && e.RecoveryEvidenceSHA256 == base.RecoveryEvidenceSHA256 && e.SourceRowsSHA256 == base.SourceRowsSHA256 && e.CandidateDatabaseEnvSHA256 == base.CandidateDatabaseEnvSHA256
}

func (d *acornFoxUpgradeDatabase) artifactWriter() (*DurableWriter, error) {
	if d == nil || d.rootWriter == nil || d.rootWriter.VerifyLiveRoot() != nil {
		return nil, ErrAcornFoxUpgradeUnknown
	}
	upgrade, err := ensureAcornFoxUpgradeDatabaseChild(d.rootWriter, acornFoxUpgradeDirectory)
	if err != nil {
		return nil, err
	}
	defer upgrade.Close()
	database, err := ensureAcornFoxUpgradeDatabaseChild(upgrade, acornFoxUpgradeDatabaseRoot)
	if err != nil {
		return nil, err
	}
	defer database.Close()
	return ensureAcornFoxUpgradeDatabaseChild(database, d.artifactID)
}

func ensureAcornFoxUpgradeDatabaseChild(parent *DurableWriter, name string) (*DurableWriter, error) {
	if parent == nil || parent.VerifyLiveRoot() != nil {
		return nil, ErrAcornFoxUpgradeUnknown
	}
	if _, err := parent.CreateChildDirectory(name, durableDirMode); err != nil {
		return nil, ErrAcornFoxUpgradeUnknown
	}
	child, err := parent.OpenChildWriter(name, durableDirMode)
	if err != nil {
		return nil, ErrAcornFoxUpgradeConflict
	}
	return child, nil
}

func (d *acornFoxUpgradeDatabase) ensureWitness(writer *DurableWriter, name string, evidence acornFoxUpgradeDatabaseEvidence) (bool, error) {
	if writer == nil || evidence.validate() != nil || !d.sameIdentity(evidence) {
		return false, ErrAcornFoxUpgradeConflict
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return false, ErrAcornFoxUpgradeUnknown
	}
	createErr := writer.CreateMetadata(name, raw)
	if createErr == nil {
		return false, nil
	}
	existing, readErr := writer.ReadMetadata(name)
	if readErr != nil {
		return false, ErrAcornFoxUpgradeUnknown
	}
	var observed acornFoxUpgradeDatabaseEvidence
	if strictCanonicalJSON(existing, &observed, "AcornFox upgrade database evidence") != nil || observed != evidence || !bytes.Equal(existing, raw) {
		return true, ErrAcornFoxUpgradeConflict
	}
	return true, nil
}

func (d *acornFoxUpgradeDatabase) verifySnapshot(writer *DurableWriter, evidence acornFoxUpgradeDatabaseEvidence) error {
	actual, err := snapshotEvidence(filepath.Join(writer.rootPath, acornFoxUpgradeDatabaseDump))
	if err != nil || actual.SHA256 != evidence.SnapshotSHA256 || actual.Size != evidence.SnapshotSize {
		return ErrAcornFoxUpgradeConflict
	}
	var witness acornFoxUpgradeDatabaseEvidence
	raw, err := writer.ReadMetadata(acornFoxUpgradeDatabaseSnapshot)
	if err != nil || strictCanonicalJSON(raw, &witness, "AcornFox upgrade database snapshot") != nil || witness != evidence {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}

func (d *acornFoxUpgradeDatabase) ensureShadowIntent(ctx context.Context, writer *DurableWriter, evidence acornFoxUpgradeDatabaseEvidence) (bool, error) {
	raw, readErr := writer.ReadMetadata(acornFoxUpgradeDatabaseShadowIntent)
	if readErr == nil {
		var observed acornFoxUpgradeDatabaseEvidence
		if strictCanonicalJSON(raw, &observed, "AcornFox upgrade shadow intent") != nil || observed != evidence {
			return true, ErrAcornFoxUpgradeConflict
		}
		return true, nil
	}
	if !errors.Is(readErr, os.ErrNotExist) {
		return false, ErrAcornFoxUpgradeUnknown
	}
	identity, err := d.admin.Inspect(ctx, d.shadowDatabase)
	if err != nil {
		return false, ErrAcornFoxUpgradeUnknown
	}
	if identity.Exists {
		return false, ErrAcornFoxUpgradeConflict
	}
	return d.ensureWitness(writer, acornFoxUpgradeDatabaseShadowIntent, evidence)
}

func (d *acornFoxUpgradeDatabase) ensureShadow(ctx context.Context, intentExisted bool) (acornFoxUpgradeShadowIdentity, error) {
	identity, err := d.admin.Inspect(ctx, d.shadowDatabase)
	if err != nil {
		return identity, ErrAcornFoxUpgradeUnknown
	}
	if !identity.Exists {
		if err := d.admin.Create(ctx, d.shadowDatabase); err != nil {
			return identity, ErrAcornFoxUpgradeUnknown
		}
		identity, err = d.admin.Inspect(ctx, d.shadowDatabase)
		if err != nil || !identity.Exists || identity.Owner != acornFoxControlPlaneRole || identity.Evidence != "" {
			return identity, ErrAcornFoxUpgradeUnknown
		}
		if err := d.setShadowEvidence(ctx, "created"); err != nil {
			return identity, err
		}
		identity.Evidence = d.shadowEvidence("created")
		return identity, nil
	}
	if identity.Owner != acornFoxControlPlaneRole {
		return identity, ErrAcornFoxUpgradeConflict
	}
	if identity.Evidence == "" {
		if !intentExisted {
			return identity, ErrAcornFoxUpgradeConflict
		}
		if err := d.setShadowEvidence(ctx, "created"); err != nil {
			return identity, err
		}
		identity.Evidence = d.shadowEvidence("created")
	}
	for _, state := range []string{"created", "restored", "migrated", "validated"} {
		if identity.Evidence == d.shadowEvidence(state) {
			return identity, nil
		}
	}
	return identity, ErrAcornFoxUpgradeConflict
}

func (d *acornFoxUpgradeDatabase) inspectCandidate(ctx context.Context) (BootstrapMigrationControl, []MigrationRow, error) {
	control, err := d.open(bytes.Clone(d.candidateEnvironment))
	if err != nil || control == nil {
		return nil, nil, ErrAcornFoxUpgradeUnknown
	}
	rows, err := control.MigrationRows(ctx)
	if err != nil {
		ledgerClose(control)
		return nil, nil, ErrAcornFoxUpgradeUnknown
	}
	return control, rows, nil
}

func (d *acornFoxUpgradeDatabase) restore(ctx context.Context, writer *DurableWriter, evidence acornFoxUpgradeDatabaseEvidence) error {
	if err := d.verifySnapshot(writer, evidence); err != nil {
		return err
	}
	if !acornFoxCrossSchemaDatabaseName.MatchString(d.shadowDatabase) || !validProcessEnv(d.candidateProcessEnv) || d.candidateProcessEnv.Descriptor.Database != d.shadowDatabase {
		return ErrAcornFoxUpgradeConflict
	}
	argv := []string{productionPostgresRestoreTool, "--exit-on-error", "--single-transaction", "--no-owner", "--no-acl", "--dbname", d.shadowDatabase, filepath.Join(writer.rootPath, acornFoxUpgradeDatabaseDump)}
	result := d.runner.Run(ctx, argv, append([]string(nil), d.candidateProcessEnv.ChildEnv...))
	if result.Err != nil || result.ExitCode != 0 {
		return ErrAcornFoxUpgradeUnknown
	}
	return nil
}

func (d *acornFoxUpgradeDatabase) verifyCustomDump(ctx context.Context, path string, environment PostgresProcessEnvironment) error {
	if d == nil || ctx == nil || ctx.Err() != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || !validProcessEnv(environment) {
		return ErrAcornFoxUpgradeConflict
	}
	result := d.runner.Run(ctx, []string{productionPostgresRestoreTool, "--list", path}, append([]string(nil), environment.ChildEnv...))
	if result.Err != nil || result.ExitCode != 0 {
		return ErrAcornFoxUpgradeUnknown
	}
	return nil
}

func (d *acornFoxUpgradeDatabase) migrateTail(ctx context.Context, control BootstrapMigrationControl, rows []MigrationRow) ([]MigrationRow, error) {
	if control == nil || len(rows) < 34 || len(rows) > len(d.migrations.rows) || !matchesExpected(rows, d.migrations.rows[:len(rows)]) {
		return nil, ErrAcornFoxUpgradeConflict
	}
	for index := len(rows); index < len(d.migrations.rows); index++ {
		if index < 34 {
			return nil, ErrAcornFoxUpgradeConflict
		}
		tx, err := control.BeginMigration(ctx)
		if err != nil {
			return nil, ErrAcornFoxUpgradeUnknown
		}
		if err := tx.ExecMigration(ctx, d.migrations.sql[index]); err != nil {
			_ = tx.Rollback()
			return nil, ErrAcornFoxUpgradeUnknown
		}
		if err := tx.RecordMigration(ctx, d.migrations.rows[index]); err != nil {
			_ = tx.Rollback()
			return nil, ErrAcornFoxUpgradeUnknown
		}
		if err := tx.Commit(); err != nil {
			observed, readErr := control.MigrationRows(ctx)
			if readErr != nil || len(observed) != index+1 || !matchesExpected(observed, d.migrations.rows[:index+1]) {
				return nil, ErrAcornFoxUpgradeUnknown
			}
		}
		rows, err = control.MigrationRows(ctx)
		if err != nil || len(rows) != index+1 || !matchesExpected(rows, d.migrations.rows[:index+1]) {
			return nil, ErrAcornFoxUpgradeUnknown
		}
	}
	return rows, nil
}

func (d *acornFoxUpgradeDatabase) shadowEvidence(state string) string {
	return "acornfox-cross-schema-v1:" + d.recoveryEvidence + ":" + state
}

func (d *acornFoxUpgradeDatabase) setShadowEvidence(ctx context.Context, state string) error {
	want := d.shadowEvidence(state)
	if !validAcornFoxUpgradeShadowEvidence(want) || d.admin.SetEvidence(ctx, d.shadowDatabase, want) != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	identity, err := d.admin.Inspect(ctx, d.shadowDatabase)
	if err != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	if !identity.Exists || identity.Owner != acornFoxControlPlaneRole || identity.Evidence != want {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}

func acornFoxUpgradePostgresEnvironment(raw []byte, expectedDatabase string) (PostgresProcessEnvironment, error) {
	value, err := parseAcornFoxControlPlaneEnvironment(raw)
	if err != nil {
		return PostgresProcessEnvironment{}, err
	}
	u, err := url.Parse(value)
	if err != nil || u.User == nil || strings.TrimPrefix(u.Path, "/") != expectedDatabase || u.RawPath != "" || u.RawQuery != "sslmode=disable" || u.Fragment != "" {
		return PostgresProcessEnvironment{}, ErrAcornFoxUpgradeConflict
	}
	compatible, err := FormatDatabaseEnv(u.String())
	if err != nil {
		return PostgresProcessEnvironment{}, ErrAcornFoxUpgradeConflict
	}
	environment, err := PostgresEnvironment(compatible)
	if err != nil || environment.Descriptor.Database != expectedDatabase || environment.Descriptor.Host != "127.0.0.1" || environment.Descriptor.Port != "5432" || environment.Descriptor.SSLMode != "disable" {
		return PostgresProcessEnvironment{}, ErrAcornFoxUpgradeConflict
	}
	return environment, nil
}

func acornFoxUpgradeCandidateEnvironment(active []byte, candidate string) ([]byte, PostgresProcessEnvironment, error) {
	if !validAcornFoxControlPlaneEnvironment(active) || !acornFoxCrossSchemaDatabaseName.MatchString(candidate) {
		return nil, PostgresProcessEnvironment{}, ErrAcornFoxUpgradeConflict
	}
	value, err := parseAcornFoxControlPlaneEnvironment(active)
	if err != nil {
		return nil, PostgresProcessEnvironment{}, ErrAcornFoxUpgradeConflict
	}
	u, err := url.Parse(value)
	if err != nil {
		return nil, PostgresProcessEnvironment{}, ErrAcornFoxUpgradeConflict
	}
	u.Path, u.RawPath = "/"+candidate, ""
	raw := []byte("ACORNFOX_DATABASE_URL=" + u.String() + "\n")
	environment, err := acornFoxUpgradePostgresEnvironment(raw, candidate)
	if err != nil {
		return nil, PostgresProcessEnvironment{}, err
	}
	return raw, environment, nil
}

func openAcornFoxUpgradeMigrationControl(environment []byte) (BootstrapMigrationControl, error) {
	value, err := parseAcornFoxControlPlaneEnvironment(environment)
	if err != nil {
		return nil, ErrAcornFoxUpgradeUnknown
	}
	compatible, err := FormatDatabaseEnv(value)
	if err != nil {
		return nil, ErrAcornFoxUpgradeUnknown
	}
	selected, err := NewSelectedPostgresDatabase(compatible)
	if err != nil {
		return nil, ErrAcornFoxUpgradeUnknown
	}
	return &acornFoxSelectedMigrationControl{SelectedPostgresDatabase: selected}, nil
}

type acornFoxUpgradeDefaultDatabaseHealth struct{}

func (acornFoxUpgradeDefaultDatabaseHealth) Check(ctx context.Context, environment []byte, expectedDatabase, expectedRowsSHA256 string) error {
	value, err := parseAcornFoxControlPlaneEnvironment(environment)
	if err != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	compatible, err := FormatDatabaseEnv(value)
	if err != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	selected, err := NewSelectedPostgresDatabase(compatible)
	if err != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	defer selected.Close()
	name, err := selected.CurrentDatabase(ctx)
	if err != nil || name != expectedDatabase {
		return ErrAcornFoxUpgradeUnknown
	}
	rows, err := selected.MigrationRows(ctx)
	if err != nil || len(rows) != AcornFoxV1DataVersion || acornFoxMigrationRowsSHA256(rows) != expectedRowsSHA256 {
		return ErrAcornFoxUpgradeUnknown
	}
	return nil
}

type acornFoxProductionUpgradeDatabaseAdmin struct{}

func newAcornFoxProductionUpgradeDatabaseAdmin() (acornFoxUpgradeDatabaseAdmin, error) {
	for _, tool := range []string{acornFoxControlPlaneRunuser, acornFoxControlPlanePSQL} {
		if _, err := safeProductionExecutable(tool); err != nil {
			return nil, ErrAcornFoxUpgradeUnknown
		}
	}
	return acornFoxProductionUpgradeDatabaseAdmin{}, nil
}

func (acornFoxProductionUpgradeDatabaseAdmin) Inspect(ctx context.Context, name string) (acornFoxUpgradeShadowIdentity, error) {
	if !acornFoxCrossSchemaDatabaseName.MatchString(name) {
		return acornFoxUpgradeShadowIdentity{}, ErrAcornFoxUpgradeConflict
	}
	sqlText := "SELECT CASE WHEN d.datname IS NULL THEN '0' ELSE '1' END, COALESCE(pg_get_userbyid(d.datdba), ''), COALESCE(encode(convert_to(shobj_description(d.oid, 'pg_database'), 'UTF8'), 'hex'), '') FROM (VALUES (1)) AS one(n) LEFT JOIN pg_database d ON d.datname = '" + name + "';\n"
	out, err := acornFoxRunUpgradeDatabaseAdmin(ctx, []byte(sqlText))
	if err != nil {
		return acornFoxUpgradeShadowIdentity{}, err
	}
	fields := strings.Split(strings.TrimSuffix(string(out), "\n"), "\t")
	if len(fields) != 3 || (fields[0] != "0" && fields[0] != "1") || len(out) > 1024 {
		return acornFoxUpgradeShadowIdentity{}, ErrAcornFoxUpgradeUnknown
	}
	identity := acornFoxUpgradeShadowIdentity{Exists: fields[0] == "1", Owner: fields[1]}
	if fields[2] != "" {
		raw, decodeErr := hex.DecodeString(fields[2])
		if decodeErr != nil || len(raw) > 256 {
			return acornFoxUpgradeShadowIdentity{}, ErrAcornFoxUpgradeUnknown
		}
		identity.Evidence = string(raw)
	}
	if !identity.Exists && (identity.Owner != "" || identity.Evidence != "") {
		return acornFoxUpgradeShadowIdentity{}, ErrAcornFoxUpgradeUnknown
	}
	return identity, nil
}

func (acornFoxProductionUpgradeDatabaseAdmin) Create(ctx context.Context, name string) error {
	if !acornFoxCrossSchemaDatabaseName.MatchString(name) {
		return ErrAcornFoxUpgradeConflict
	}
	_, err := acornFoxRunUpgradeDatabaseAdmin(ctx, []byte("CREATE DATABASE "+name+" OWNER "+acornFoxControlPlaneRole+";\n"))
	return err
}

func (acornFoxProductionUpgradeDatabaseAdmin) SetEvidence(ctx context.Context, name, evidence string) error {
	if !acornFoxCrossSchemaDatabaseName.MatchString(name) || !validAcornFoxUpgradeShadowEvidence(evidence) {
		return ErrAcornFoxUpgradeConflict
	}
	_, err := acornFoxRunUpgradeDatabaseAdmin(ctx, []byte("COMMENT ON DATABASE "+name+" IS '"+evidence+"';\n"))
	return err
}

func validAcornFoxUpgradeShadowEvidence(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 3 || parts[0] != "acornfox-cross-schema-v1" || !validSHA(parts[1]) {
		return false
	}
	return parts[2] == "created" || parts[2] == "restored" || parts[2] == "migrated" || parts[2] == "validated"
}

func acornFoxRunUpgradeDatabaseAdmin(ctx context.Context, stdin []byte) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || len(stdin) == 0 || len(stdin) > 4096 {
		return nil, ErrAcornFoxUpgradeUnknown
	}
	argv := []string{acornFoxControlPlaneRunuser, "-u", "postgres", "--", acornFoxControlPlanePSQL, "-X", "-w", "-v", "ON_ERROR_STOP=1", "-h", "/var/run/postgresql", "-p", "5432", "-U", "postgres", "-d", "postgres", "-At", "-F", "\t", "-f", "-"}
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	command.Env = append([]string(nil), productionSubprocessBaseEnv...)
	command.Stdin = bytes.NewReader(stdin)
	var stdout bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = io.Discard
	if err := command.Run(); err != nil || stdout.Len() > 1024 {
		return nil, ErrAcornFoxUpgradeUnknown
	}
	return stdout.Bytes(), nil
}
