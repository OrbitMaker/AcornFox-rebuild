package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	upgradeControlEnvironmentName = "upgrade-database.env"
	upgradeControlRuntimeRole     = "opencard"
	upgradeControlRole            = "open_card_upgrade_control"
	upgradeControlRunuser         = "/usr/sbin/runuser"
	upgradeControlPSQL            = "/usr/bin/psql"
)

// ErrUpgradeControlProvisioning is deliberately generic.  Provisioning must
// not reveal a control credential, a database error, or subprocess output.
var ErrUpgradeControlProvisioning = errors.New("upgrade control provisioning failed")

// UpgradeControlRunResult intentionally exposes no process output. Production
// execution discards stdout/stderr; the seam exists only to prove ordering and
// fixed argv/stdin handling in task-scoped tests.
type UpgradeControlRunResult struct {
	ExitCode int
	Err      error
}

type UpgradeControlRunner interface {
	Run(context.Context, []string, []byte) UpgradeControlRunResult
}

// UpgradeControlProvisioner owns the one root-only control identity file and
// the fixed local PostgreSQL role normalization operation. It has no caller
// supplied paths, role names, SQL, or subprocess environment.
type UpgradeControlProvisioner struct {
	writer     *DurableWriter
	runner     UpgradeControlRunner
	random     io.Reader
	production bool
}

// PrepareProductionUpgradeControl is the narrow entry point intended for the
// later root-only `open-card-upgrade prepare-control` command.
func PrepareProductionUpgradeControl(ctx context.Context) (string, error) {
	if os.Geteuid() != 0 {
		return "", ErrUpgradeControlProvisioning
	}
	writer, err := ProductionDurableWriter("/etc/open-card")
	if err != nil {
		return "", ErrUpgradeControlProvisioning
	}
	defer writer.Close()
	provisioner := &UpgradeControlProvisioner{writer: writer, runner: productionUpgradeControlRunner{}, random: rand.Reader, production: true}
	return provisioner.Provision(ctx)
}

// NewTaskUpgradeControlProvisioner supplies the only test seam. Its root is
// explicit and task-owned; production code cannot use this constructor.
func NewTaskUpgradeControlProvisioner(root string, uid, gid int, random io.Reader, runner UpgradeControlRunner) (*UpgradeControlProvisioner, error) {
	writer, err := TaskDurableWriter(root, uid, gid)
	if err != nil {
		return nil, err
	}
	if random == nil || runner == nil {
		_ = writer.Close()
		return nil, ErrUpgradeControlProvisioning
	}
	return &UpgradeControlProvisioner{writer: writer, runner: runner, random: random}, nil
}

func (p *UpgradeControlProvisioner) Close() error {
	if p == nil || p.writer == nil {
		return nil
	}
	return p.writer.Close()
}

// Provision durably establishes the exact database.env before invoking psql.
// A retry always uses the stored secret and repeats the idempotent SQL.
func (p *UpgradeControlProvisioner) Provision(ctx context.Context) (string, error) {
	if p == nil || p.writer == nil || p.writer.ops == nil || p.runner == nil || p.random == nil || ctx == nil {
		return "", ErrUpgradeControlProvisioning
	}
	if p.production && verifyUpgradeControlProductionPrerequisites() != nil {
		return "", ErrUpgradeControlProvisioning
	}

	_, lstatErr := p.writer.ops.Lstat(upgradeControlEnvironmentName)
	if lstatErr != nil && !errors.Is(lstatErr, os.ErrNotExist) {
		return "", ErrUpgradeControlProvisioning
	}
	raw, err := p.writer.ReadMetadata(upgradeControlEnvironmentName)
	if err != nil {
		// O_NOFOLLOW can report a symlink as not found on some platforms.
		// Lstat above distinguishes that unsafe existing leaf from true absence.
		if !errors.Is(err, os.ErrNotExist) || lstatErr == nil {
			return "", ErrUpgradeControlProvisioning
		}
		secret, generateErr := upgradeControlSecret(p.random)
		if generateErr != nil {
			return "", ErrUpgradeControlProvisioning
		}
		raw, err = upgradeControlDatabaseEnv(secret)
		if err != nil {
			return "", ErrUpgradeControlProvisioning
		}
		if createErr := p.writer.CreateMetadata(upgradeControlEnvironmentName, raw); createErr != nil {
			// CreateMetadata never replaces an existing leaf.  EEXIST means a
			// concurrent provisioner won; a post-link fsync ambiguity may also
			// have published this exact value.  In both cases the only safe action
			// is to reread the durable winner and use its password for SQL.
			if !errors.Is(createErr, os.ErrExist) && !errors.Is(createErr, ErrDurableCommitUnknown) {
				return "", ErrUpgradeControlProvisioning
			}
			published, readErr := p.writer.ReadMetadata(upgradeControlEnvironmentName)
			if readErr != nil {
				return "", ErrUpgradeControlProvisioning
			}
			raw = published
		} else {
			published, readErr := p.writer.ReadMetadata(upgradeControlEnvironmentName)
			if readErr != nil || !bytes.Equal(published, raw) {
				return "", ErrUpgradeControlProvisioning
			}
		}
	}

	secret, err := validateUpgradeControlDatabaseEnv(raw)
	if err != nil {
		return "", ErrUpgradeControlProvisioning
	}
	// SQL contains the password only in stdin, never command argv or env.
	result := p.runner.Run(ctx, upgradeControlPSQLCommand(), upgradeControlSQL(secret))
	if result.Err != nil || result.ExitCode != 0 {
		return "", ErrUpgradeControlProvisioning
	}
	return sha256Bytes(raw), nil
}

func upgradeControlSecret(random io.Reader) (string, error) {
	var value [32]byte
	if _, err := io.ReadFull(random, value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func upgradeControlDatabaseEnv(secret string) ([]byte, error) {
	if !validUpgradeControlSecret(secret) {
		return nil, ErrUpgradeControlProvisioning
	}
	return FormatDatabaseEnv("postgresql://" + upgradeControlRole + ":" + secret + "@127.0.0.1:5432/postgres?sslmode=disable")
}

func validateUpgradeControlDatabaseEnv(raw []byte) (string, error) {
	dsn, err := ParseDatabaseEnv(raw)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme != "postgresql" || u.Hostname() != "127.0.0.1" || u.Port() != "5432" || u.EscapedPath() != "/postgres" || u.User == nil || u.User.Username() != upgradeControlRole || u.RawQuery != "sslmode=disable" {
		return "", ErrUpgradeControlProvisioning
	}
	secret, ok := u.User.Password()
	if !ok || !validUpgradeControlSecret(secret) {
		return "", ErrUpgradeControlProvisioning
	}
	canonical, err := upgradeControlDatabaseEnv(secret)
	if err != nil || !bytes.Equal(canonical, raw) {
		return "", ErrUpgradeControlProvisioning
	}
	return secret, nil
}

func validUpgradeControlSecret(secret string) bool {
	if len(secret) != base64.RawURLEncoding.EncodedLen(32) {
		return false
	}
	for _, c := range secret {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func upgradeControlPSQLCommand() []string {
	return []string{upgradeControlRunuser, "--user", "postgres", "--", upgradeControlPSQL, "--no-psqlrc", "--set", "ON_ERROR_STOP=1", "--dbname", "postgres"}
}

func upgradeControlSQL(secret string) []byte {
	// secret is base64url-only, so interpolation cannot alter this fixed SQL.
	return []byte("DO $$\n" +
		"BEGIN\n" +
		"  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opencard' AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls) THEN\n" +
		"    RAISE EXCEPTION 'runtime role invariant failed';\n" +
		"  END IF;\n" +
		"  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'open_card_upgrade_control') THEN\n" +
		"    CREATE ROLE open_card_upgrade_control LOGIN CREATEDB NOSUPERUSER NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT;\n" +
		"  ELSE\n" +
		"    ALTER ROLE open_card_upgrade_control LOGIN CREATEDB NOSUPERUSER NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT;\n" +
		"  END IF;\n" +
		"  IF EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles granted ON granted.oid = m.roleid JOIN pg_roles member ON member.oid = m.member WHERE member.rolname = 'open_card_upgrade_control' AND granted.rolname NOT IN ('opencard', 'pg_read_all_stats')) THEN\n" +
		"    RAISE EXCEPTION 'control membership invariant failed';\n" +
		"  END IF;\n" +
		"  ALTER ROLE open_card_upgrade_control PASSWORD '" + secret + "';\n" +
		"  REVOKE open_card_upgrade_control FROM opencard;\n" +
		"  GRANT opencard TO open_card_upgrade_control;\n" +
		"  GRANT pg_read_all_stats TO open_card_upgrade_control;\n" +
		"  IF EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles granted ON granted.oid = m.roleid JOIN pg_roles member ON member.oid = m.member WHERE member.rolname = 'opencard' AND granted.rolname IN ('open_card_upgrade_control', 'pg_read_all_stats')) THEN\n" +
		"    RAISE EXCEPTION 'runtime membership invariant failed';\n" +
		"  END IF;\n" +
		"END\n$$;\n")
}

type productionUpgradeControlRunner struct{}

func (productionUpgradeControlRunner) Run(ctx context.Context, argv []string, stdin []byte) UpgradeControlRunResult {
	if !equalStringSlice(argv, upgradeControlPSQLCommand()) {
		return UpgradeControlRunResult{ExitCode: -1, Err: ErrUpgradeControlProvisioning}
	}
	cmd := exec.CommandContext(ctx, upgradeControlRunuser, argv[1:]...)
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Env = append([]string(nil), productionSubprocessBaseEnv...)
	if err := cmd.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return UpgradeControlRunResult{ExitCode: exit.ExitCode(), Err: err}
		}
		return UpgradeControlRunResult{ExitCode: -1, Err: err}
	}
	return UpgradeControlRunResult{}
}

func verifyUpgradeControlProductionPrerequisites() error {
	for _, path := range []string{"/etc", "/etc/open-card", "/usr", "/usr/sbin", "/usr/bin"} {
		if err := verifyUpgradeControlSecureDirectory(path); err != nil {
			return err
		}
	}
	for _, path := range []string{upgradeControlRunuser, upgradeControlPSQL} {
		if err := verifyUpgradeControlTool(path); err != nil {
			return err
		}
	}
	return nil
}

func verifyUpgradeControlSecureDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || verifyOwner(info, 0, 0) != nil {
		return ErrUpgradeControlProvisioning
	}
	return nil
}

func verifyUpgradeControlTool(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrUpgradeControlProvisioning
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || verifyOwner(info, 0, 0) != nil {
		return ErrUpgradeControlProvisioning
	}
	return nil
}

func equalStringSlice(left, right []string) bool {
	return len(left) == len(right) && strings.Join(left, "\x00") == strings.Join(right, "\x00")
}
