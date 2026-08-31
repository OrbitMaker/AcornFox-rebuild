package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const (
	backupConfigSchemaVersion = 1
	backupConfigMaxSize       = 4 << 10
	backupRoleProfileMaxSize  = 1 << 10

	productionBackupConfigRoot = "/etc/open-card"
	backupConfigFileName       = "backup.json"
	backupRoleProfileFileName  = "backup-cos.credentials"
)

var (
	// Errors from this boundary are deliberately content-free: bucket names,
	// endpoints, and role topology are operational data, not diagnostics.
	ErrBackupConfigUnavailable      = errors.New("backup configuration unavailable")
	ErrBackupRoleProfileUnavailable = errors.New("backup role profile unavailable")

	backupCOSBucket = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,50}[a-z0-9])?-[0-9]{10}$`)
	backupCOSRegion = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	backupRoleName  = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,128}$`)
)

// BackupConfigV1 is the frozen, credential-free COS publication contract.
// Credentials must be acquired solely through the named instance role.
type BackupConfigV1 struct {
	SchemaVersion        int    `json:"schema_version"`
	InstallationIDSHA256 string `json:"installation_id_sha256"`
	Provider             string `json:"provider"`
	Bucket               string `json:"bucket"`
	Region               string `json:"region"`
	Endpoint             string `json:"endpoint"`
	Prefix               string `json:"prefix"`
	CredentialProvider   string `json:"credential_provider"`
}

func (c BackupConfigV1) Validate() error {
	if c.SchemaVersion != backupConfigSchemaVersion || !validSHA(c.InstallationIDSHA256) ||
		c.Provider != "tencent-cos" || !backupCOSBucket.MatchString(c.Bucket) || strings.ToLower(c.Bucket) != c.Bucket ||
		!backupCOSRegion.MatchString(c.Region) || strings.ToLower(c.Region) != c.Region ||
		c.Endpoint != "https://"+c.Bucket+".cos."+c.Region+".tencentcos.cn" ||
		c.Prefix != "open-card/backups" || c.CredentialProvider != "cvm-instance-role" {
		return ErrBackupConfigUnavailable
	}
	return nil
}

// BindInstallation makes the public config digest useful only to the one
// installation it was provisioned for.
func (c BackupConfigV1) BindInstallation(expectedInstallationSHA256 string) error {
	if c.Validate() != nil || !validSHA(expectedInstallationSHA256) || c.InstallationIDSHA256 != expectedInstallationSHA256 {
		return ErrBackupConfigUnavailable
	}
	return nil
}

// ObjectKey is the only object-name constructor for this config namespace.
func (c BackupConfigV1) ObjectKey(backupID string) (string, error) {
	if c.Validate() != nil || !validBackupID(backupID) {
		return "", ErrBackupConfigUnavailable
	}
	return c.Prefix + "/" + c.InstallationIDSHA256 + "/" + backupID + ".ocbkp", nil
}

// String and GoString prevent ordinary formatting from disclosing storage
// topology. MarshalBackupConfigV1 is intentionally canonical and not redacted.
func (BackupConfigV1) String() string   { return "backup-config(redacted)" }
func (BackupConfigV1) GoString() string { return "install.BackupConfigV1(redacted)" }

func MarshalBackupConfigV1(config BackupConfigV1) ([]byte, error) {
	if config.Validate() != nil {
		return nil, ErrBackupConfigUnavailable
	}
	raw, err := json.Marshal(config)
	if err != nil {
		return nil, ErrBackupConfigUnavailable
	}
	return append(raw, '\n'), nil
}

func ParseBackupConfigV1(raw []byte) (BackupConfigV1, error) {
	var config BackupConfigV1
	if len(raw) == 0 || len(raw) > backupConfigMaxSize || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) ||
		len(raw) == 0 || raw[len(raw)-1] != '\n' || (len(raw) > 1 && raw[len(raw)-2] == '\n') ||
		decodeStrict(raw, &config) != nil || requireStrictFields(raw, []string{"schema_version", "installation_id_sha256", "provider", "bucket", "region", "endpoint", "prefix", "credential_provider"}) != nil || config.Validate() != nil {
		return BackupConfigV1{}, ErrBackupConfigUnavailable
	}
	canonical, err := MarshalBackupConfigV1(config)
	if err != nil || !bytes.Equal(raw, canonical) {
		return BackupConfigV1{}, ErrBackupConfigUnavailable
	}
	return config, nil
}

func ParseBoundBackupConfigV1(raw []byte, expectedInstallationSHA256 string) (BackupConfigV1, error) {
	config, err := ParseBackupConfigV1(raw)
	if err != nil || config.BindInstallation(expectedInstallationSHA256) != nil {
		return BackupConfigV1{}, ErrBackupConfigUnavailable
	}
	return config, nil
}

// BackupRoleProfileV1 is separate from BackupConfigV1 so permissions can be
// audited without ever introducing a credential field into either contract.
type BackupRoleProfileV1 struct {
	SchemaVersion int
	RoleName      string
}

func (p BackupRoleProfileV1) Validate() error {
	if p.SchemaVersion != 1 || !backupRoleName.MatchString(p.RoleName) {
		return ErrBackupRoleProfileUnavailable
	}
	return nil
}

func (BackupRoleProfileV1) String() string   { return "backup-role-profile(redacted)" }
func (BackupRoleProfileV1) GoString() string { return "install.BackupRoleProfileV1(redacted)" }

func MarshalBackupRoleProfileV1(profile BackupRoleProfileV1) ([]byte, error) {
	if profile.Validate() != nil {
		return nil, ErrBackupRoleProfileUnavailable
	}
	return []byte("schema_version=1\nrole_name=" + profile.RoleName + "\n"), nil
}

func ParseBackupRoleProfileV1(raw []byte) (BackupRoleProfileV1, error) {
	if len(raw) == 0 || len(raw) > backupRoleProfileMaxSize || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return BackupRoleProfileV1{}, ErrBackupRoleProfileUnavailable
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) != 3 || lines[2] != "" || lines[0] != "schema_version=1" || !strings.HasPrefix(lines[1], "role_name=") || strings.Count(lines[1], "=") != 1 {
		return BackupRoleProfileV1{}, ErrBackupRoleProfileUnavailable
	}
	profile := BackupRoleProfileV1{SchemaVersion: 1, RoleName: strings.TrimPrefix(lines[1], "role_name=")}
	if profile.Validate() != nil {
		return BackupRoleProfileV1{}, ErrBackupRoleProfileUnavailable
	}
	return profile, nil
}

// BackupConfigReader has exactly one root. Production callers cannot replace
// it; task callers must supply both a prepared root and expected ownership.
type BackupConfigReader struct {
	root string
	uid  int
	gid  int
}

func ProductionBackupConfigReader() (*BackupConfigReader, error) {
	return newBackupConfigReader(productionBackupConfigRoot, 0, 0)
}

func TaskBackupConfigReader(root string, uid, gid int) (*BackupConfigReader, error) {
	if uid < 0 || gid < 0 {
		return nil, ErrBackupConfigUnavailable
	}
	return newBackupConfigReader(root, uid, gid)
}

func newBackupConfigReader(root string, uid, gid int) (*BackupConfigReader, error) {
	if !safeAbsPath(root) {
		return nil, ErrBackupConfigUnavailable
	}
	if _, err := secureReadRoot(root, uid, gid, false); err != nil {
		return nil, ErrBackupConfigUnavailable
	}
	return &BackupConfigReader{root: root, uid: uid, gid: gid}, nil
}

func (r *BackupConfigReader) ReadConfig(expectedInstallationSHA256 string) (BackupConfigV1, error) {
	if r == nil {
		return BackupConfigV1{}, ErrBackupConfigUnavailable
	}
	raw, err := secureReadPinnedFile(r.root, backupConfigFileName, r.uid, r.gid, 0o600, backupConfigMaxSize, false)
	if err != nil {
		return BackupConfigV1{}, ErrBackupConfigUnavailable
	}
	return ParseBoundBackupConfigV1(raw, expectedInstallationSHA256)
}

func (r *BackupConfigReader) ReadRoleProfile() (BackupRoleProfileV1, error) {
	if r == nil {
		return BackupRoleProfileV1{}, ErrBackupRoleProfileUnavailable
	}
	raw, err := secureReadPinnedFile(r.root, backupRoleProfileFileName, r.uid, r.gid, 0o400, backupRoleProfileMaxSize, false)
	if err != nil {
		return BackupRoleProfileV1{}, ErrBackupRoleProfileUnavailable
	}
	return ParseBackupRoleProfileV1(raw)
}

// secureReadPinnedFile validates the configured root before and after opening
// a no-follow leaf, and compares the live root inode. This closes ordinary
// root/leaf replacement races without accepting an arbitrary production path.
func secureReadPinnedFile(root, name string, uid, gid int, mode os.FileMode, max int, exactRootMode bool) ([]byte, error) {
	before, err := secureReadRoot(root, uid, gid, exactRootMode)
	if err != nil {
		return nil, err
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer opened.Close()
	live, err := opened.Stat(".")
	if err != nil || !sameFileIdentity(before, live) || !secureReadDirectory(live, uid, gid, exactRootMode) {
		return nil, errors.New("unsafe read root")
	}
	// O_NONBLOCK prevents a hostile FIFO from turning a read-only verifier
	// into a blocking service. The fstat below still rejects every non-regular
	// leaf before any bytes are accepted.
	file, err := opened.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || !ownedBy(info, uid, gid) || fileNlink(info) != 1 {
		return nil, errors.New("unsafe read leaf")
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(max)+1))
	if err != nil || len(raw) > max {
		return nil, errors.New("unsafe read data")
	}
	after, err := secureReadRoot(root, uid, gid, exactRootMode)
	if err != nil || !sameFileIdentity(before, after) {
		return nil, errors.New("unsafe replaced root")
	}
	return raw, nil
}

func secureReadRoot(root string, uid, gid int, exactMode bool) (os.FileInfo, error) {
	if !safeAbsPath(root) || secureReadAncestors(root, uid, gid) != nil {
		return nil, errors.New("unsafe root ancestors")
	}
	info, err := os.Lstat(root)
	if err != nil || !secureReadDirectory(info, uid, gid, exactMode) {
		return nil, errors.New("unsafe root")
	}
	return info, nil
}

func secureReadAncestors(root string, uid, gid int) error {
	if !safeAbsPath(root) {
		return errors.New("unsafe root ancestors")
	}
	parts := strings.Split(strings.TrimPrefix(root, "/"), "/")
	parent := "/"
	for _, part := range parts[:len(parts)-1] {
		parent = filepath.Join(parent, part)
		info, err := os.Lstat(parent)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || !secureAncestorOwner(info, uid, gid) {
			return errors.New("unsafe root ancestor")
		}
	}
	return nil
}

// Ancestors may be platform-owned (for example /private on macOS) or owned
// by the explicitly selected task owner. Both cases are fixed identities;
// group/other-writable components and every symlink remain forbidden.
func secureAncestorOwner(info os.FileInfo, uid, gid int) bool {
	return ownedBy(info, uid, gid) || ownedBy(info, 0, 0)
}

func secureReadDirectory(info os.FileInfo, uid, gid int, exactMode bool) bool {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !ownedBy(info, uid, gid) {
		return false
	}
	if exactMode {
		return info.Mode().Perm() == 0o700
	}
	return info.Mode().Perm()&0o022 == 0
}

func sameFileIdentity(a, b os.FileInfo) bool {
	as, aok := a.Sys().(*syscall.Stat_t)
	bs, bok := b.Sys().(*syscall.Stat_t)
	return aok && bok && as.Dev == bs.Dev && as.Ino == bs.Ino
}

func fileNlink(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(stat.Nlink)
}
