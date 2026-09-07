package install

// This file owns the AcornFox V1 control-plane database transition.  It is
// intentionally separate from the retained Open Card bootstrap database
// implementation: AcornFox has a closed release migration inventory and a
// fixed single-node PostgreSQL identity.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

var (
	ErrAcornFoxControlPlaneConflict = errors.New("AcornFox control plane conflicts with prepared state")
	ErrAcornFoxControlPlaneUnknown  = errors.New("AcornFox control plane outcome is unknown")
)

const (
	acornFoxControlPlaneStateEnv      = "control-plane-database.env"
	acornFoxControlPlaneReceipt       = "control-plane-migration.json"
	acornFoxControlPlaneActivationEnv = "database.env"
	acornFoxControlPlaneDatabase      = "acornfox"
	acornFoxControlPlaneRole          = "acornfox"
	acornFoxControlPlanePSQL          = "/usr/lib/postgresql/16/bin/psql"
	acornFoxControlPlaneRunuser       = "/usr/sbin/runuser"
)

// AcornFoxControlPlaneMigrationReceiptV1 deliberately contains only durable
// public identities.  The database environment and password never leave the
// writer boundary as serializable data.
type AcornFoxControlPlaneMigrationReceiptV1 struct {
	SchemaVersion          int    `json:"schema_version"`
	State                  string `json:"state"`
	BindingSHA256          string `json:"binding_sha256"`
	ReleaseID              string `json:"release_id"`
	SourceCommit           string `json:"source_commit"`
	MigrationVersion       string `json:"migration_version"`
	MigrationRowsSHA256    string `json:"migration_rows_sha256"`
	DatabaseEnvSHA256      string `json:"database_env_sha256"`
	DatabaseIdentitySHA256 string `json:"database_identity_sha256"`
}

func (r AcornFoxControlPlaneMigrationReceiptV1) Validate() error {
	return r.validateMigration(AcornFoxV1MigrationVersion)
}

func (r AcornFoxControlPlaneMigrationReceiptV1) validateMigration(migration string) error {
	if r.SchemaVersion != 1 || r.State != "CONTROL_PLANE_MIGRATED" || !validSHA(r.BindingSHA256) || !validID(r.ReleaseID) || !acornFoxHostSourceCommit.MatchString(r.SourceCommit) || r.MigrationVersion != migration || (migration != AcornFoxV1MigrationVersion && migration != acornFoxRecentPredecessorMigration && migration != AcornFoxLegacyPredecessorMigration) || !validSHA(r.MigrationRowsSHA256) || !validSHA(r.DatabaseEnvSHA256) || !validSHA(r.DatabaseIdentitySHA256) {
		return ErrAcornFoxControlPlaneConflict
	}
	return nil
}

func MarshalAcornFoxControlPlaneMigrationReceiptV1(r AcornFoxControlPlaneMigrationReceiptV1) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

func ParseAcornFoxControlPlaneMigrationReceiptV1(raw []byte) (AcornFoxControlPlaneMigrationReceiptV1, error) {
	var result AcornFoxControlPlaneMigrationReceiptV1
	if err := strictCanonicalJSON(raw, &result, "AcornFox control plane migration receipt"); err != nil {
		return result, ErrAcornFoxControlPlaneConflict
	}
	return result, result.Validate()
}

func parseAcornFoxControlPlaneMigrationReceiptForUpgrade(raw []byte, migration string) (AcornFoxControlPlaneMigrationReceiptV1, error) {
	var result AcornFoxControlPlaneMigrationReceiptV1
	if strictCanonicalJSON(raw, &result, "AcornFox control plane migration receipt") != nil || result.validateMigration(migration) != nil {
		return result, ErrAcornFoxControlPlaneConflict
	}
	return result, nil
}

// acornFoxControlPlaneProvisioner is deliberately smaller than PostgresRunner:
// the only command it can receive is the package-fixed runuser/psql sequence,
// and stdin is the sole channel permitted to contain the generated password.
type acornFoxControlPlaneProvisioner interface {
	Run(context.Context, []string, []byte) error
}

type acornFoxControlPlaneMigrations struct {
	rows []MigrationRow
	sql  []string
}

func (m acornFoxControlPlaneMigrations) valid() bool {
	if len(m.rows) != len(acornFoxV1Migrations) || len(m.sql) != len(acornFoxV1Migrations) || !validMigrationRows(m.rows, len(acornFoxV1Migrations)) {
		return false
	}
	for index, sqlText := range m.sql {
		if strings.TrimSpace(sqlText) == "" || m.rows[index].Version != strings.TrimSuffix(acornFoxV1Migrations[index], ".sql") {
			return false
		}
	}
	return true
}

// acornFoxControlPlane is package-private so tests can model the exact
// production layout while production has no configurable root/DSN/tool seam.
type acornFoxControlPlane struct {
	layout           acornFoxInstallLayout
	bridge           acornFoxHostBridge
	random           io.Reader
	provisioner      acornFoxControlPlaneProvisioner
	open             func([]byte) (BootstrapMigrationControl, error)
	writeActivation  func(*DurableWriter, []byte) error
	writeReceipt     func(*DurableWriter, []byte) error
	expectedIdentity AcornFoxBuildIdentityV1
}

// MigrateAcornFoxControlPlaneV1 is the sole production entrypoint.  It has no
// caller-controlled root, database, role, DSN, migration directory or command.
// expected is the already-validated identity compiled into the detached helper,
// never a CLI-provided deployment authority.
func MigrateAcornFoxControlPlaneV1(ctx context.Context, expected AcornFoxBuildIdentityV1) (AcornFoxControlPlaneMigrationReceiptV1, error) {
	layout, err := newProductionAcornFoxLayout()
	if err != nil {
		return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneUnknown
	}
	service, err := newAcornFoxControlPlane(layout, newAcornFoxHostBridge(layout, newAcornFoxProductionSelfVerifier()), rand.Reader, acornFoxProductionControlPlaneProvisioner{}, openProductionAcornFoxControlPlane)
	if err != nil {
		return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneUnknown
	}
	return service.migrateWithIdentity(ctx, expected)
}

// newTaskAcornFoxControlPlane is the only test constructor.  Its layout is an
// already pinned 0700 temporary production model; the remaining seams are
// deterministic entropy, a fixed-argv provision runner and a typed ledger.
func newTaskAcornFoxControlPlane(layout acornFoxInstallLayout, random io.Reader, provisioner acornFoxControlPlaneProvisioner, open func([]byte) (BootstrapMigrationControl, error)) (*acornFoxControlPlane, error) {
	return newAcornFoxControlPlane(layout, newAcornFoxHostBridge(layout, acornFoxSelfVerifier{}), random, provisioner, open)
}

func newAcornFoxControlPlane(layout acornFoxInstallLayout, bridge acornFoxHostBridge, random io.Reader, provisioner acornFoxControlPlaneProvisioner, open func([]byte) (BootstrapMigrationControl, error)) (*acornFoxControlPlane, error) {
	if layout.validate() != nil || layout.mode != acornFoxInstallLayoutProduction || random == nil || provisioner == nil || open == nil {
		return nil, ErrAcornFoxControlPlaneUnknown
	}
	return &acornFoxControlPlane{layout: layout, bridge: bridge, random: random, provisioner: provisioner, open: open, writeActivation: func(writer *DurableWriter, raw []byte) error {
		return writer.CreateMetadata(acornFoxControlPlaneActivationEnv, raw)
	}, writeReceipt: func(writer *DurableWriter, raw []byte) error {
		return writer.CreateMetadata(acornFoxControlPlaneReceipt, raw)
	}}, nil
}

// migrate is package-private task-only compatibility for the fixed temporary
// fixture. Production enters only through MigrateAcornFoxControlPlaneV1,
// which receives the helper identity from the closed CLI dispatcher.
func (s *acornFoxControlPlane) migrate(ctx context.Context) (AcornFoxControlPlaneMigrationReceiptV1, error) {
	if s == nil {
		return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneUnknown
	}
	return s.migrateWithIdentity(ctx, s.expectedIdentity)
}

func (s *acornFoxControlPlane) migrateWithIdentity(ctx context.Context, expected AcornFoxBuildIdentityV1) (AcornFoxControlPlaneMigrationReceiptV1, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.writeActivation == nil || s.writeReceipt == nil || !validAcornFoxControlPlaneHelperIdentity(expected) {
		return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneUnknown
	}
	// The prepared-state verifier is deliberately retained ahead of the
	// migration lock: it may repair only an already-prepared repository and
	// owns its own repository lease.  Once it has returned, every C1 effect is
	// serialized by exactly one fixed repository-install lock below.
	if _, err := s.bridge.verifyPrepared(ctx); err != nil {
		if errors.Is(err, ErrAcornFoxRepoLocked) {
			return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxRepoLocked
		}
		return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneConflict
	}
	store, err := newAcornFoxRepoStoreForLayout(s.layout)
	if err != nil {
		return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneUnknown
	}
	store.ownership = s.bridge.ownership
	defer store.Close()
	lock, err := store.Acquire(ctx)
	if err != nil {
		if errors.Is(err, ErrAcornFoxRepoLocked) {
			return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxRepoLocked
		}
		return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneConflict
	}
	defer lock.Release()
	authority, migrations, err := s.authorityForStore(ctx, store, expected)
	if err != nil {
		return AcornFoxControlPlaneMigrationReceiptV1{}, err
	}
	state, host, err := s.writers(authority.activationID)
	if err != nil {
		return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneUnknown
	}
	defer state.Close()
	defer host.Close()
	activationEnv := acornFoxControlPlaneActivationEnv

	// The secret is generated only when neither durable env witness exists.
	// Every replay first proves the two byte-identical locations agree.
	stateEnv, stateErr := state.ReadMetadata(acornFoxControlPlaneStateEnv)
	activation, activationErr := host.ReadMetadata(activationEnv)
	var env []byte
	switch {
	case errors.Is(stateErr, os.ErrNotExist) && errors.Is(activationErr, os.ErrNotExist):
		env, err = s.newEnvironment()
		if err == nil {
			err = state.CreateMetadata(acornFoxControlPlaneStateEnv, env)
		}
		if err == nil {
			err = s.writeActivation(host, env)
		}
		if err != nil {
			return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneUnknown
		}
	case stateErr == nil && errors.Is(activationErr, os.ErrNotExist):
		// A durable state environment preceding the activation copy is the one
		// recoverable prefix this leaf owns. Reuse its exact bytes; a failed or
		// uncertain no-replace publish remains unknown so the next replay can
		// re-read the activation slot and converge only on byte equality.
		env = stateEnv
		if !validAcornFoxControlPlaneEnvironment(env) {
			return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneConflict
		}
		if err := s.writeActivation(host, env); err != nil {
			return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneUnknown
		}
	case stateErr == nil && activationErr == nil && bytes.Equal(stateEnv, activation):
		env = stateEnv
	default:
		return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneConflict
	}
	if !validAcornFoxControlPlaneEnvironment(env) {
		return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneConflict
	}
	if existing, readErr := state.ReadMetadata(acornFoxControlPlaneReceipt); readErr == nil {
		receipt, parseErr := ParseAcornFoxControlPlaneMigrationReceiptV1(existing)
		if parseErr != nil || receipt.BindingSHA256 != authority.binding || receipt.ReleaseID != authority.releaseID || receipt.SourceCommit != authority.sourceCommit || receipt.MigrationRowsSHA256 != acornFoxMigrationRowsSHA256(migrations.rows) || receipt.DatabaseEnvSHA256 != sha256Bytes(env) || receipt.DatabaseIdentitySHA256 != acornFoxControlPlaneIdentitySHA256() {
			return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneConflict
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneConflict
	}
	if err := s.provision(ctx, env); err != nil {
		return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneUnknown
	}

	control, err := s.open(env)
	if err != nil || control == nil {
		return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneUnknown
	}
	defer ledgerClose(control)
	if err := ensureAcornFoxControlPlaneLedger(ctx, control, migrations); err != nil {
		return AcornFoxControlPlaneMigrationReceiptV1{}, err
	}
	rows, err := control.MigrationRows(ctx)
	if err != nil || !matchesExpected(rows, migrations.rows) {
		return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneUnknown
	}
	rowsDigest := acornFoxMigrationRowsSHA256(rows)
	receipt := AcornFoxControlPlaneMigrationReceiptV1{SchemaVersion: 1, State: "CONTROL_PLANE_MIGRATED", BindingSHA256: authority.binding, ReleaseID: authority.releaseID, SourceCommit: authority.sourceCommit, MigrationVersion: AcornFoxV1MigrationVersion, MigrationRowsSHA256: rowsDigest, DatabaseEnvSHA256: sha256Bytes(env), DatabaseIdentitySHA256: acornFoxControlPlaneIdentitySHA256()}
	raw, err := MarshalAcornFoxControlPlaneMigrationReceiptV1(receipt)
	if err != nil {
		return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneUnknown
	}
	if existing, readErr := state.ReadMetadata(acornFoxControlPlaneReceipt); readErr == nil {
		if !bytes.Equal(existing, raw) {
			return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneConflict
		}
	} else if errors.Is(readErr, os.ErrNotExist) {
		if err := s.writeReceipt(state, raw); err != nil {
			return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneUnknown
		}
	} else {
		return AcornFoxControlPlaneMigrationReceiptV1{}, ErrAcornFoxControlPlaneConflict
	}
	return receipt, nil
}

type acornFoxControlPlaneAuthority struct {
	binding, releaseID, sourceCommit, activationID string
}

func (s *acornFoxControlPlane) authority(ctx context.Context) (acornFoxControlPlaneAuthority, acornFoxControlPlaneMigrations, error) {
	if s == nil || !validAcornFoxControlPlaneHelperIdentity(s.expectedIdentity) {
		return acornFoxControlPlaneAuthority{}, acornFoxControlPlaneMigrations{}, ErrAcornFoxControlPlaneUnknown
	}
	if _, err := s.bridge.verifyPrepared(ctx); err != nil {
		if errors.Is(err, ErrAcornFoxRepoLocked) {
			return acornFoxControlPlaneAuthority{}, acornFoxControlPlaneMigrations{}, ErrAcornFoxRepoLocked
		}
		return acornFoxControlPlaneAuthority{}, acornFoxControlPlaneMigrations{}, ErrAcornFoxControlPlaneConflict
	}
	store, err := newAcornFoxRepoStoreForLayout(s.layout)
	if err != nil {
		return acornFoxControlPlaneAuthority{}, acornFoxControlPlaneMigrations{}, ErrAcornFoxControlPlaneUnknown
	}
	defer store.Close()
	store.ownership = s.bridge.ownership
	lock, err := store.Acquire(ctx)
	if err != nil {
		if errors.Is(err, ErrAcornFoxRepoLocked) {
			return acornFoxControlPlaneAuthority{}, acornFoxControlPlaneMigrations{}, ErrAcornFoxRepoLocked
		}
		return acornFoxControlPlaneAuthority{}, acornFoxControlPlaneMigrations{}, ErrAcornFoxControlPlaneConflict
	}
	defer lock.Release()
	return s.authorityForStore(ctx, store, s.expectedIdentity)
}

// authorityForStore consumes the store descriptor that migrate has already
// locked. It must not acquire a second lock: the migration's authority,
// environment, provisioning, SQL ledger and receipt are one serialized C1
// transition.
func (s *acornFoxControlPlane) authorityForStore(ctx context.Context, store *TaskAcornFoxRepoStore, expected AcornFoxBuildIdentityV1) (acornFoxControlPlaneAuthority, acornFoxControlPlaneMigrations, error) {
	if s == nil || store == nil || !store.ownsLock() || !validAcornFoxControlPlaneHelperIdentity(expected) {
		return acornFoxControlPlaneAuthority{}, acornFoxControlPlaneMigrations{}, ErrAcornFoxControlPlaneConflict
	}
	journal, err := store.Resume(ctx)
	if err != nil || journal.Phase != AcornFoxRepoPreparedFinal || journal.NeedsRecovery || journal.LayoutSHA256 != s.layout.evidence() {
		return acornFoxControlPlaneAuthority{}, acornFoxControlPlaneMigrations{}, ErrAcornFoxControlPlaneConflict
	}
	rawBinding, err := newAcornFoxBindingStore(store).Read(journal.BindingSHA256)
	if err != nil {
		return acornFoxControlPlaneAuthority{}, acornFoxControlPlaneMigrations{}, ErrAcornFoxControlPlaneConflict
	}
	binding, err := ParseAcornFoxCandidateBindingV1(rawBinding, journal.BindingSHA256)
	if err != nil || binding.binding.ReleaseID == "" || binding.binding.SourceCommit == "" || binding.binding.ReleaseID != expected.ReleaseID || binding.binding.SourceCommit != expected.SourceCommit {
		return acornFoxControlPlaneAuthority{}, acornFoxControlPlaneMigrations{}, ErrAcornFoxControlPlaneConflict
	}
	activationID, err := AcornFoxRepoActivationID(journal.BindingSHA256)
	if err != nil {
		return acornFoxControlPlaneAuthority{}, acornFoxControlPlaneMigrations{}, ErrAcornFoxControlPlaneConflict
	}
	migrations, err := loadAcornFoxControlPlaneMigrations(s.layout, binding.binding)
	if err != nil {
		return acornFoxControlPlaneAuthority{}, acornFoxControlPlaneMigrations{}, ErrAcornFoxControlPlaneConflict
	}
	return acornFoxControlPlaneAuthority{binding: journal.BindingSHA256, releaseID: binding.binding.ReleaseID, sourceCommit: binding.binding.SourceCommit, activationID: activationID}, migrations, nil
}

func validAcornFoxControlPlaneHelperIdentity(expected AcornFoxBuildIdentityV1) bool {
	return expected.Validate() == nil && expected.Product == AcornFoxV1Product && expected.LayoutVersion == AcornFoxSubstrateLayoutV1 && expected.Role == "upgrade"
}

func (s *acornFoxControlPlane) writers(activationID string) (*DurableWriter, *DurableWriter, error) {
	if s.layout.mode != acornFoxInstallLayoutProduction {
		return nil, nil, ErrAcornFoxControlPlaneUnknown
	}
	if s.layout.hostRootPath == "/" {
		state, err := ProductionDurableWriter(s.layout.stateRootPath)
		if err != nil {
			return nil, nil, err
		}
		host, err := ProductionDurableWriter(filepath.Join("/opt/acornfox/activations", activationID))
		if err != nil {
			_ = state.Close()
			return nil, nil, err
		}
		return state, host, nil
	}
	state, err := TaskDurableWriter(s.layout.stateRootPath, s.layout.stateOwner.uid, s.layout.stateOwner.gid)
	if err != nil {
		return nil, nil, err
	}
	host, err := TaskDurableWriter(filepath.Join(s.layout.hostRootPath, "opt", "acornfox", "activations", activationID), s.layout.stateOwner.uid, s.layout.stateOwner.gid)
	if err != nil {
		_ = state.Close()
		return nil, nil, err
	}
	return state, host, nil
}

func (s *acornFoxControlPlane) newEnvironment() ([]byte, error) {
	secret := make([]byte, 32)
	if _, err := io.ReadFull(s.random, secret); err != nil {
		return nil, err
	}
	password := base64.RawURLEncoding.EncodeToString(secret)
	return []byte("ACORNFOX_DATABASE_URL=postgresql://" + acornFoxControlPlaneRole + ":" + password + "@127.0.0.1:5432/" + acornFoxControlPlaneDatabase + "?sslmode=disable\n"), nil
}

func validAcornFoxControlPlaneEnvironment(raw []byte) bool {
	return validAcornFoxControlPlaneEnvironmentForDatabase(raw, acornFoxControlPlaneDatabase)
}

func validAcornFoxControlPlaneEnvironmentForDatabase(raw []byte, database string) bool {
	value, err := parseAcornFoxControlPlaneEnvironment(raw)
	if err != nil {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || u.User == nil {
		return false
	}
	password, ok := u.User.Password()
	if !ok || !postgresRoleName.MatchString(database) || len(password) != base64.RawURLEncoding.EncodedLen(32) || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.User.Username() != acornFoxControlPlaneRole || u.Hostname() != "127.0.0.1" || u.Port() != "5432" || u.Path != "/"+database || u.RawPath != "" || u.RawQuery != "sslmode=disable" || u.Fragment != "" || u.User.String() != acornFoxControlPlaneRole+":"+password {
		return false
	}
	_, err = base64.RawURLEncoding.DecodeString(password)
	return err == nil
}

func acornFoxControlPlaneDatabaseName(raw []byte) (string, error) {
	value, err := parseAcornFoxControlPlaneEnvironment(raw)
	if err != nil {
		return "", ErrAcornFoxControlPlaneConflict
	}
	u, err := url.Parse(value)
	if err != nil || u.Path == "" || strings.Count(u.Path, "/") != 1 {
		return "", ErrAcornFoxControlPlaneConflict
	}
	return strings.TrimPrefix(u.Path, "/"), nil
}

func validAcornFoxBoundControlPlaneEnvironment(raw []byte, receipt AcornFoxControlPlaneMigrationReceiptV1, expectedDatabase string) bool {
	if receipt.validateMigration(receipt.MigrationVersion) != nil || sha256Bytes(raw) != receipt.DatabaseEnvSHA256 || receipt.DatabaseIdentitySHA256 != acornFoxControlPlaneIdentitySHA256ForDatabase(expectedDatabase) {
		return false
	}
	database, err := acornFoxControlPlaneDatabaseName(raw)
	if err != nil || database != expectedDatabase || (database != acornFoxControlPlaneDatabase && !acornFoxUpgradeShadowName.MatchString(database)) {
		return false
	}
	return validAcornFoxControlPlaneEnvironmentForDatabase(raw, database)
}

func acornFoxControlPlaneEnvironmentForDatabase(raw []byte, database string) ([]byte, error) {
	if !validAcornFoxControlPlaneEnvironment(raw) || !acornFoxUpgradeShadowName.MatchString(database) {
		return nil, ErrAcornFoxControlPlaneConflict
	}
	value, err := parseAcornFoxControlPlaneEnvironment(raw)
	if err != nil {
		return nil, ErrAcornFoxControlPlaneConflict
	}
	u, err := url.Parse(value)
	if err != nil {
		return nil, ErrAcornFoxControlPlaneConflict
	}
	u.Path = "/" + database
	u.RawPath = ""
	result := []byte("ACORNFOX_DATABASE_URL=" + u.String() + "\n")
	if !validAcornFoxControlPlaneEnvironmentForDatabase(result, database) {
		return nil, ErrAcornFoxControlPlaneConflict
	}
	return result, nil
}

func parseAcornFoxControlPlaneEnvironment(raw []byte) (string, error) {
	const prefix = "ACORNFOX_DATABASE_URL="
	if !bytes.HasPrefix(raw, []byte(prefix)) || !bytes.HasSuffix(raw, []byte("\n")) || bytes.Count(raw, []byte("\n")) != 1 || bytes.ContainsAny(raw, "\x00\r") {
		return "", ErrAcornFoxControlPlaneConflict
	}
	value := strings.TrimSuffix(strings.TrimPrefix(string(raw), prefix), "\n")
	if value == "" || strings.ContainsAny(value, " \t#$\\\"'") {
		return "", ErrAcornFoxControlPlaneConflict
	}
	return value, nil
}

func (s *acornFoxControlPlane) provision(ctx context.Context, env []byte) error {
	if s == nil || !validAcornFoxControlPlaneEnvironment(env) {
		return ErrAcornFoxControlPlaneUnknown
	}
	value, err := parseAcornFoxControlPlaneEnvironment(env)
	if err != nil {
		return ErrAcornFoxControlPlaneUnknown
	}
	u, err := url.Parse(value)
	if err != nil || u.User == nil {
		return ErrAcornFoxControlPlaneUnknown
	}
	password, ok := u.User.Password()
	if !ok || strings.ContainsAny(password, "'\\\x00") {
		return ErrAcornFoxControlPlaneUnknown
	}
	// The password occurs only in psql stdin. The role and database clauses are
	// idempotent so a crash after their server-side commit is safe to replay.
	stdin := []byte("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'acornfox') THEN CREATE ROLE acornfox LOGIN PASSWORD '" + password + "'; END IF; END $$;\n" +
		"SELECT 'CREATE DATABASE acornfox OWNER acornfox' WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'acornfox')\\gexec\n")
	argv := []string{acornFoxControlPlaneRunuser, "-u", "postgres", "--", acornFoxControlPlanePSQL, "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-f", "-"}
	if !validAcornFoxControlPlaneProvisionArgv(argv) || s.provisioner.Run(ctx, argv, stdin) != nil {
		return ErrAcornFoxControlPlaneUnknown
	}
	return nil
}

func acornFoxControlPlaneIdentitySHA256() string {
	return acornFoxControlPlaneIdentitySHA256ForDatabase(acornFoxControlPlaneDatabase)
}

func acornFoxControlPlaneIdentitySHA256ForDatabase(database string) string {
	if database != acornFoxControlPlaneDatabase && !acornFoxUpgradeShadowName.MatchString(database) {
		return ""
	}
	return sha256Bytes([]byte("acornfox-control-plane-postgres-v1\x00" + database + "\x00127.0.0.1\x005432\x00disable"))
}

func ensureAcornFoxControlPlaneLedger(ctx context.Context, control BootstrapMigrationControl, migrations acornFoxControlPlaneMigrations) error {
	if ctx == nil || control == nil || !migrations.valid() {
		return ErrAcornFoxControlPlaneUnknown
	}
	if err := control.EnsureMigrationLedger(ctx); err != nil {
		return ErrAcornFoxControlPlaneUnknown
	}
	rows, err := control.MigrationRows(ctx)
	if err != nil || len(rows) > len(migrations.rows) || !matchesExpected(rows, migrations.rows[:len(rows)]) {
		return ErrAcornFoxControlPlaneConflict
	}
	for index := len(rows); index < len(migrations.rows); index++ {
		tx, err := control.BeginMigration(ctx)
		if err != nil {
			return ErrAcornFoxControlPlaneUnknown
		}
		if err := tx.ExecMigration(ctx, migrations.sql[index]); err != nil {
			_ = tx.Rollback()
			return ErrAcornFoxControlPlaneUnknown
		}
		if err := tx.RecordMigration(ctx, migrations.rows[index]); err != nil {
			_ = tx.Rollback()
			return ErrAcornFoxControlPlaneUnknown
		}
		if err := tx.Commit(); err != nil {
			observed, readErr := control.MigrationRows(ctx)
			if readErr != nil || len(observed) != index+1 || !matchesExpected(observed, migrations.rows[:index+1]) {
				return ErrAcornFoxControlPlaneUnknown
			}
		}
		rows, err = control.MigrationRows(ctx)
		if err != nil || len(rows) != index+1 || !matchesExpected(rows, migrations.rows[:index+1]) {
			return ErrAcornFoxControlPlaneUnknown
		}
	}
	return nil
}

func acornFoxMigrationRowsSHA256(rows []MigrationRow) string {
	hash := sha256.New()
	for _, row := range rows {
		_, _ = hash.Write([]byte(row.Version + "\t" + row.Checksum + "\n"))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// loadAcornFoxControlPlaneMigrations performs the minimum descriptor-bound
// release validation needed here.  It is independent of the legacy 0024
// manifest verifier, whose accepted product contract must not be widened.
func loadAcornFoxControlPlaneMigrations(layout acornFoxInstallLayout, binding AcornFoxCandidateBindingV1) (acornFoxControlPlaneMigrations, error) {
	if layout.validate() != nil || layout.mode != acornFoxInstallLayoutProduction || validateAcornFoxBinding(binding) != nil {
		return acornFoxControlPlaneMigrations{}, ErrAcornFoxControlPlaneConflict
	}
	root, err := os.OpenRoot(layout.hostRootPath)
	if err != nil {
		return acornFoxControlPlaneMigrations{}, ErrAcornFoxControlPlaneConflict
	}
	defer root.Close()
	uid, gid := layout.stateOwner.uid, layout.stateOwner.gid
	for _, parent := range []string{"opt", "opt/acornfox", "opt/acornfox/releases", "opt/acornfox/releases/" + binding.ReleaseID, "opt/acornfox/releases/" + binding.ReleaseID + "/migrations", "opt/acornfox/releases/" + binding.ReleaseID + "/migrations/control-plane"} {
		info, err := root.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || verifyOwner(info, uid, gid) != nil {
			return acornFoxControlPlaneMigrations{}, ErrAcornFoxControlPlaneConflict
		}
	}
	read := func(name string, mode os.FileMode) ([]byte, error) {
		path := "opt/acornfox/releases/" + binding.ReleaseID + "/" + name
		file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, ErrAcornFoxControlPlaneConflict
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || acornFoxRepoNlink(info) != 1 || verifyOwner(info, uid, gid) != nil {
			return nil, ErrAcornFoxControlPlaneConflict
		}
		raw, err := io.ReadAll(file)
		if err != nil {
			return nil, ErrAcornFoxControlPlaneConflict
		}
		return raw, nil
	}
	manifestRaw, err := read("manifest.json", 0o644)
	if err != nil || sha256Bytes(manifestRaw) != binding.ManifestSHA256 {
		return acornFoxControlPlaneMigrations{}, ErrAcornFoxControlPlaneConflict
	}
	var manifest Manifest
	if err := strictCanonicalJSON(manifestRaw, &manifest, "AcornFox manifest"); err != nil || validateAcornFoxCandidateManifest(manifest, binding) != nil {
		return acornFoxControlPlaneMigrations{}, ErrAcornFoxControlPlaneConflict
	}
	byPath := make(map[string]FileDigest, len(manifest.Files))
	for _, file := range manifest.Files {
		byPath[file.Path] = file
	}
	result := acornFoxControlPlaneMigrations{rows: make([]MigrationRow, 0, len(acornFoxV1Migrations)), sql: make([]string, 0, len(acornFoxV1Migrations))}
	for _, name := range acornFoxV1Migrations {
		path := "migrations/control-plane/" + name
		digest, ok := byPath[path]
		if !ok || digest.Mode != 0o640 {
			return acornFoxControlPlaneMigrations{}, ErrAcornFoxControlPlaneConflict
		}
		raw, err := read(path, 0o640)
		if err != nil || sha256Bytes(raw) != digest.SHA256 || len(raw) == 0 {
			return acornFoxControlPlaneMigrations{}, ErrAcornFoxControlPlaneConflict
		}
		result.rows = append(result.rows, MigrationRow{Version: strings.TrimSuffix(name, ".sql"), Checksum: digest.SHA256})
		result.sql = append(result.sql, string(raw))
	}
	if !result.valid() {
		return acornFoxControlPlaneMigrations{}, ErrAcornFoxControlPlaneConflict
	}
	return result, nil
}

type acornFoxProductionControlPlaneProvisioner struct{}

func (acornFoxProductionControlPlaneProvisioner) Run(ctx context.Context, argv []string, stdin []byte) error {
	if !validAcornFoxControlPlaneProvisionArgv(argv) || len(stdin) == 0 || ctx == nil || ctx.Err() != nil {
		return ErrAcornFoxControlPlaneUnknown
	}
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	command.Stdin = bytes.NewReader(stdin)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return ErrAcornFoxControlPlaneUnknown
	}
	return nil
}

func validAcornFoxControlPlaneProvisionArgv(argv []string) bool {
	want := []string{acornFoxControlPlaneRunuser, "-u", "postgres", "--", acornFoxControlPlanePSQL, "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-f", "-"}
	return len(argv) == len(want) && func() bool {
		for i := range want {
			if argv[i] != want[i] {
				return false
			}
		}
		return true
	}()
}

func openProductionAcornFoxControlPlane(env []byte) (BootstrapMigrationControl, error) {
	if !validAcornFoxControlPlaneEnvironment(env) {
		return nil, ErrAcornFoxControlPlaneUnknown
	}
	value, err := parseAcornFoxControlPlaneEnvironment(env)
	if err != nil {
		return nil, ErrAcornFoxControlPlaneUnknown
	}
	// The retained PostgreSQL adapter understands its historic variable key.
	// This compatibility byte slice is in-memory only: every AcornFox durable
	// artifact uses ACORNFOX_DATABASE_URL exclusively.
	database, err := NewSelectedPostgresDatabase([]byte("OPEN_CARD_DATABASE_URL=" + value + "\n"))
	if err != nil {
		return nil, ErrAcornFoxControlPlaneUnknown
	}
	return &acornFoxSelectedMigrationControl{SelectedPostgresDatabase: database}, nil
}

type acornFoxSelectedMigrationControl struct{ *SelectedPostgresDatabase }

func (c *acornFoxSelectedMigrationControl) BeginMigration(ctx context.Context) (MigrationTx, error) {
	if c == nil || c.SelectedPostgresDatabase == nil {
		return nil, ErrPostgresOutcomeUnknown
	}
	return (&SQLMigrationControl{database: c.database}).BeginMigration(ctx)
}
func (c *acornFoxSelectedMigrationControl) EnsureMigrationLedger(ctx context.Context) error {
	if c == nil || c.SelectedPostgresDatabase == nil {
		return ErrPostgresOutcomeUnknown
	}
	return (&SQLMigrationControl{database: c.database}).EnsureMigrationLedger(ctx)
}
