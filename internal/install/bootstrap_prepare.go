package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/url"
	"os"
	"os/user"
	"strconv"
)

const (
	bootstrapRuntimeDatabaseEnvName = "bootstrap-database.env"
	bootstrapSafeEdgeConfigName     = "open-card-edge.Caddyfile"
	bootstrapSafeEdgeEnvName        = "open-card-edge.env"
)

var ErrBootstrapRuntimePreparation = errors.New("bootstrap runtime preparation failed")

// BootstrapRuntimeReceipt binds only immutable release identity and file
// digests. It deliberately contains neither paths nor runtime credentials.
type BootstrapRuntimeReceipt struct {
	ReleaseID                  string `json:"release_id"`
	ManifestSHA256             string `json:"manifest_sha256"`
	BootstrapDatabaseEnvSHA256 string `json:"bootstrap_database_env_sha256"`
	SafeEdgeConfigSHA256       string `json:"safe_edge_config_sha256"`
	SafeEdgeEnvSHA256          string `json:"safe_edge_env_sha256"`
}

func (r BootstrapRuntimeReceipt) Validate() error {
	if !validID(r.ReleaseID) || !validSHA(r.ManifestSHA256) || !validSHA(r.BootstrapDatabaseEnvSHA256) || !validSHA(r.SafeEdgeConfigSHA256) || !validSHA(r.SafeEdgeEnvSHA256) {
		return ErrBootstrapRuntimePreparation
	}
	return nil
}

type bootstrapReleaseSelector func(*DurableWriter, string) (ReleaseV1, error)

// BootstrapRuntimePreparer owns only the fixed initial runtime templates and
// the local runtime-role normalization command. It deliberately has no
// caller-selected filesystem path, database target, SQL, or process argv.
type BootstrapRuntimePreparer struct {
	config, active    *DurableWriter
	uid, gid, edgeGID int
	random            io.Reader
	runner            UpgradeControlRunner
	selectRelease     bootstrapReleaseSelector
	production        bool
}

// PrepareProductionBootstrapRuntime is the production-only entrypoint.
// expectedManifestSHA256 selects exactly one verified RC3 release beneath the
// fixed active root; callers cannot name a release or provide an environment.
func PrepareProductionBootstrapRuntime(ctx context.Context, expectedManifestSHA256 string) (BootstrapRuntimeReceipt, error) {
	if os.Geteuid() != 0 || !validSHA(expectedManifestSHA256) {
		return BootstrapRuntimeReceipt{}, ErrBootstrapRuntimePreparation
	}
	config, err := ProductionDurableWriter("/etc/open-card")
	if err != nil {
		return BootstrapRuntimeReceipt{}, ErrBootstrapRuntimePreparation
	}
	defer config.Close()
	active, err := ProductionDurableWriter(productionBootstrapActiveRoot)
	if err != nil {
		return BootstrapRuntimeReceipt{}, ErrBootstrapRuntimePreparation
	}
	defer active.Close()
	edge, err := user.Lookup(productionCaddyUser)
	if err != nil || edge == nil {
		return BootstrapRuntimeReceipt{}, ErrBootstrapRuntimePreparation
	}
	edgeGID, err := strconv.Atoi(edge.Gid)
	if err != nil || edgeGID < 0 || verifyUpgradeControlProductionPrerequisites() != nil {
		return BootstrapRuntimeReceipt{}, ErrBootstrapRuntimePreparation
	}
	p, err := newBootstrapRuntimePreparer(config, active, 0, 0, edgeGID, rand.Reader, productionUpgradeControlRunner{}, selectBootstrapRC3Release, true)
	if err != nil {
		return BootstrapRuntimeReceipt{}, ErrBootstrapRuntimePreparation
	}
	return p.Prepare(ctx, expectedManifestSHA256)
}

// NewTaskBootstrapRuntimePreparer is the explicit task-only seam. All roots,
// ownership, entropy, process result and RC2 selector are supplied by a test.
func NewTaskBootstrapRuntimePreparer(config, active *DurableWriter, uid, gid, edgeGID int, random io.Reader, runner UpgradeControlRunner, selector func(*DurableWriter, string) (ReleaseV1, error)) (*BootstrapRuntimePreparer, error) {
	return newBootstrapRuntimePreparer(config, active, uid, gid, edgeGID, random, runner, selector, false)
}

func newBootstrapRuntimePreparer(config, active *DurableWriter, uid, gid, edgeGID int, random io.Reader, runner UpgradeControlRunner, selector bootstrapReleaseSelector, production bool) (*BootstrapRuntimePreparer, error) {
	if config == nil || active == nil || config.uid != uid || config.gid != gid || active.uid != uid || active.gid != gid || edgeGID < 0 || random == nil || runner == nil || selector == nil || config.VerifyLiveRoot() != nil || active.VerifyLiveRoot() != nil {
		return nil, ErrBootstrapRuntimePreparation
	}
	return &BootstrapRuntimePreparer{config: config, active: active, uid: uid, gid: gid, edgeGID: edgeGID, random: random, runner: runner, selectRelease: selector, production: production}, nil
}

func (p *BootstrapRuntimePreparer) Prepare(ctx context.Context, expectedManifestSHA256 string) (BootstrapRuntimeReceipt, error) {
	if p == nil || ctx == nil || !validSHA(expectedManifestSHA256) || p.config.VerifyLiveRoot() != nil || p.active.VerifyLiveRoot() != nil {
		return BootstrapRuntimeReceipt{}, ErrBootstrapRuntimePreparation
	}
	release, err := p.selectRelease(p.active, expectedManifestSHA256)
	if err != nil || !release.valid() || release.Version != Gate7CandidateVersion || release.ManifestSHA256 != expectedManifestSHA256 {
		return BootstrapRuntimeReceipt{}, ErrBootstrapRuntimePreparation
	}
	databaseEnv, err := p.prepareRuntimeDatabaseEnv()
	if err != nil {
		return BootstrapRuntimeReceipt{}, ErrBootstrapRuntimePreparation
	}
	secret, err := validateBootstrapRuntimeDatabaseEnv(databaseEnv)
	if err != nil {
		return BootstrapRuntimeReceipt{}, ErrBootstrapRuntimePreparation
	}
	result := p.runner.Run(ctx, bootstrapRuntimePSQLCommand(), bootstrapRuntimeSQL(secret))
	if ctx.Err() != nil || result.Err != nil || result.ExitCode != 0 {
		return BootstrapRuntimeReceipt{}, ErrBootstrapRuntimePreparation
	}
	config, env := bootstrapSafeEdgeConfig(), bootstrapSafeEdgeEnv()
	if err := p.ensureFixed(bootstrapSafeEdgeConfigName, config, 0o640, p.uid, p.edgeGID); err != nil {
		return BootstrapRuntimeReceipt{}, ErrBootstrapRuntimePreparation
	}
	if err := p.ensureFixed(bootstrapSafeEdgeEnvName, env, 0o640, p.uid, p.edgeGID); err != nil {
		return BootstrapRuntimeReceipt{}, ErrBootstrapRuntimePreparation
	}
	receipt := BootstrapRuntimeReceipt{ReleaseID: release.ID, ManifestSHA256: release.ManifestSHA256, BootstrapDatabaseEnvSHA256: sha256Bytes(databaseEnv), SafeEdgeConfigSHA256: sha256Bytes(config), SafeEdgeEnvSHA256: sha256Bytes(env)}
	if receipt.Validate() != nil {
		return BootstrapRuntimeReceipt{}, ErrBootstrapRuntimePreparation
	}
	return receipt, nil
}

func (p *BootstrapRuntimePreparer) prepareRuntimeDatabaseEnv() ([]byte, error) {
	raw, err := p.readBootstrapDatabaseEnv()
	if err == nil {
		return raw, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrBootstrapRuntimePreparation
	}
	secret, err := upgradeControlSecret(p.random)
	if err != nil {
		return nil, ErrBootstrapRuntimePreparation
	}
	want, err := bootstrapRuntimeDatabaseEnv(secret)
	if err != nil {
		return nil, ErrBootstrapRuntimePreparation
	}
	createErr := p.config.CreateMetadata(bootstrapRuntimeDatabaseEnvName, want)
	if createErr != nil {
		if !errors.Is(createErr, os.ErrExist) && !errors.Is(createErr, ErrDurableCommitUnknown) {
			return nil, ErrBootstrapRuntimePreparation
		}
	}
	got, readErr := p.readBootstrapDatabaseEnv()
	if readErr != nil || !bytes.Equal(got, want) && !errors.Is(createErr, os.ErrExist) {
		return nil, ErrBootstrapRuntimePreparation
	}
	// A concurrent winner may have chosen the secret. It is safe only when its
	// own strict template validates; unlike mutable configuration, it is never
	// overwritten by this preparer.
	if _, validErr := validateBootstrapRuntimeDatabaseEnv(got); validErr != nil {
		return nil, ErrBootstrapRuntimePreparation
	}
	return got, nil
}

func (p *BootstrapRuntimePreparer) readBootstrapDatabaseEnv() ([]byte, error) {
	if p == nil || p.config == nil || p.config.ops == nil {
		return nil, ErrBootstrapRuntimePreparation
	}
	info, err := p.config.ops.Lstat(bootstrapRuntimeDatabaseEnvName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, ErrBootstrapRuntimePreparation
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != durableFileMode || verifyOwner(info, p.uid, p.gid) != nil {
		return nil, ErrBootstrapRuntimePreparation
	}
	raw, err := p.config.ReadMetadata(bootstrapRuntimeDatabaseEnvName)
	if err != nil || validateBootstrapRuntimeDatabaseEnvOnly(raw) != nil {
		return nil, ErrBootstrapRuntimePreparation
	}
	return raw, nil
}

func (p *BootstrapRuntimePreparer) ensureFixed(name string, want []byte, mode os.FileMode, uid, gid int) error {
	info, err := p.config.ops.Lstat(name)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != mode || verifyOwner(info, uid, gid) != nil {
			return ErrBootstrapRuntimePreparation
		}
		got, readErr := readFixedOwnedFile(p.config, name, mode, uid, gid)
		if readErr != nil || !bytes.Equal(got, want) {
			return ErrBootstrapRuntimePreparation
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ErrBootstrapRuntimePreparation
	}
	if writeErr := writeFixedOwnedFile(p.config, name, want, mode, uid, gid); writeErr != nil {
		if !errors.Is(writeErr, ErrDurableCommitUnknown) {
			return ErrBootstrapRuntimePreparation
		}
	}
	got, readErr := readFixedOwnedFile(p.config, name, mode, uid, gid)
	if readErr != nil || !bytes.Equal(got, want) {
		return ErrBootstrapRuntimePreparation
	}
	return nil
}

func bootstrapRuntimeDatabaseEnv(secret string) ([]byte, error) {
	if !validUpgradeControlSecret(secret) {
		return nil, ErrBootstrapRuntimePreparation
	}
	return FormatDatabaseEnv("postgresql://" + upgradeControlRuntimeRole + ":" + secret + "@127.0.0.1:5432/postgres?sslmode=disable")
}

func validateBootstrapRuntimeDatabaseEnv(raw []byte) (string, error) {
	dsn, err := ParseDatabaseEnv(raw)
	if err != nil {
		return "", ErrBootstrapRuntimePreparation
	}
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Scheme != "postgresql" || parsed.Host != "127.0.0.1:5432" || parsed.EscapedPath() != "/postgres" || parsed.RawQuery != "sslmode=disable" || parsed.User == nil || parsed.User.Username() != upgradeControlRuntimeRole {
		return "", ErrBootstrapRuntimePreparation
	}
	password, ok := parsed.User.Password()
	if !ok || !validUpgradeControlSecret(password) {
		return "", ErrBootstrapRuntimePreparation
	}
	return password, nil
}

func validateBootstrapRuntimeDatabaseEnvOnly(raw []byte) error {
	_, err := validateBootstrapRuntimeDatabaseEnv(raw)
	return err
}

func bootstrapRuntimePSQLCommand() []string { return upgradeControlPSQLCommand() }
func bootstrapRuntimeSQL(secret string) []byte {
	return []byte("DO $$\nBEGIN\n" +
		"  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opencard') THEN\n" +
		"    CREATE ROLE opencard LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT;\n" +
		"  ELSE\n" +
		"    ALTER ROLE opencard LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT;\n" +
		"  END IF;\n" +
		"  ALTER ROLE opencard PASSWORD '" + secret + "';\nEND\n$$;\n")
}

func bootstrapSafeEdgeConfig() []byte {
	return []byte("{\n\tadmin 127.0.0.1:2020\n}\n\nhttp://127.0.0.1:18482 {\n\t@edge_health path /healthz\n\trespond @edge_health 200\n\trespond 404\n}\n")
}
func bootstrapSafeEdgeEnv() []byte {
	return []byte(edgeEnvCanonicalComment + "\nHOME=" + productionEdgeRuntimePaths.home + "\nXDG_DATA_HOME=" + productionEdgeRuntimePaths.data + "\nXDG_CONFIG_HOME=" + productionEdgeRuntimePaths.config + "\nOPEN_CARD_EDGE_LOG_DIR=" + productionEdgeRuntimePaths.log + "\n")
}
