package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
)

const (
	productionBackupKeyRoot = "/etc/open-card/backup-keys"
	backupKeyActiveFile     = "active"
	backupKeyFileSuffix     = ".key"
	backupKeySize           = 32
	backupKeyActiveMaxSize  = 256
)

var (
	ErrBackupKeyUnavailable = errors.New("backup key unavailable")
	ErrBackupKeyDestroyed   = errors.New("backup key destroyed")
	backupKeyVersion        = regexp.MustCompile(`^key-[A-Za-z0-9][A-Za-z0-9._-]{0,119}$`)
)

// BackupKeyMaterial keeps raw material unprintable and only lends a transient
// copy to the caller. The resolver never returns its stored bytes directly.
type BackupKeyMaterial struct {
	state *backupKeyMaterialState
}

// The mutable state is intentionally one pointer behind the public value.
// A copied BackupKeyMaterial therefore shares synchronization and erasure
// state, while value formatting cannot recursively print the raw bytes.
type backupKeyMaterialState struct {
	mu        sync.Mutex
	version   string
	material  []byte
	destroyed bool
}

func (m *BackupKeyMaterial) Version() (string, error) {
	if m == nil || m.state == nil {
		return "", ErrBackupKeyUnavailable
	}
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	if m.state.destroyed {
		return "", ErrBackupKeyDestroyed
	}
	return m.state.version, nil
}

func (m *BackupKeyMaterial) WithBytes(callback func([]byte) error) error {
	if m == nil || m.state == nil || callback == nil {
		return ErrBackupKeyUnavailable
	}
	m.state.mu.Lock()
	if m.state.destroyed {
		m.state.mu.Unlock()
		return ErrBackupKeyDestroyed
	}
	transient := append([]byte(nil), m.state.material...)
	m.state.mu.Unlock()
	defer zeroBackupBytes(transient)
	return callback(transient)
}

func (m *BackupKeyMaterial) Destroy() {
	if m == nil || m.state == nil {
		return
	}
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	zeroBackupBytes(m.state.material)
	m.state.material = nil
	m.state.destroyed = true
}

func (BackupKeyMaterial) String() string   { return "backup-key-material(redacted)" }
func (BackupKeyMaterial) GoString() string { return "install.BackupKeyMaterial(redacted)" }
func (BackupKeyMaterial) MarshalJSON() ([]byte, error) {
	return json.Marshal("backup_key_material_redacted")
}

// BackupKeyResolver resolves explicit versioned key files below one secure,
// read-only directory. It does not enumerate, create, rotate, or fall back.
type BackupKeyResolver struct {
	mu     sync.Mutex
	root   string
	uid    int
	gid    int
	closed bool
}

func ProductionBackupKeyResolver() (*BackupKeyResolver, error) {
	return newBackupKeyResolver(productionBackupKeyRoot, 0, 0)
}

func TaskBackupKeyResolver(root string, uid, gid int) (*BackupKeyResolver, error) {
	if uid < 0 || gid < 0 {
		return nil, ErrBackupKeyUnavailable
	}
	return newBackupKeyResolver(root, uid, gid)
}

func newBackupKeyResolver(root string, uid, gid int) (*BackupKeyResolver, error) {
	if !safeAbsPath(root) {
		return nil, ErrBackupKeyUnavailable
	}
	if _, err := secureReadRoot(root, uid, gid, true); err != nil {
		return nil, ErrBackupKeyUnavailable
	}
	return &BackupKeyResolver{root: root, uid: uid, gid: gid}, nil
}

// ResolveActive reads the pinned active selector once then resolves precisely
// that version. It never scans the directory or substitutes another key.
func (r *BackupKeyResolver) ResolveActive() (*BackupKeyMaterial, error) {
	if r == nil {
		return nil, ErrBackupKeyUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrBackupKeyUnavailable
	}
	raw, err := secureReadPinnedFile(r.root, backupKeyActiveFile, r.uid, r.gid, 0o400, backupKeyActiveMaxSize, true)
	if err != nil {
		return nil, ErrBackupKeyUnavailable
	}
	version, err := parseBackupKeyActive(raw)
	if err != nil {
		return nil, ErrBackupKeyUnavailable
	}
	return r.resolveLocked(version)
}

func (r *BackupKeyResolver) Resolve(version string) (*BackupKeyMaterial, error) {
	if r == nil {
		return nil, ErrBackupKeyUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrBackupKeyUnavailable
	}
	return r.resolveLocked(version)
}

func (r *BackupKeyResolver) resolveLocked(version string) (*BackupKeyMaterial, error) {
	if !backupKeyVersion.MatchString(version) {
		return nil, ErrBackupKeyUnavailable
	}
	raw, err := secureReadPinnedFile(r.root, version+backupKeyFileSuffix, r.uid, r.gid, 0o400, backupKeySize, true)
	if err != nil || len(raw) != backupKeySize {
		zeroBackupBytes(raw)
		return nil, ErrBackupKeyUnavailable
	}
	material := &BackupKeyMaterial{state: &backupKeyMaterialState{version: version, material: raw}}
	return material, nil
}

// Close is fail-closed. Existing material remains independently destroyable,
// while all future resolver reads are rejected.
func (r *BackupKeyResolver) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

func parseBackupKeyActive(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > backupKeyActiveMaxSize || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return "", ErrBackupKeyUnavailable
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) != 3 || lines[2] != "" || lines[0] != "schema_version=1" || !strings.HasPrefix(lines[1], "active_key_version=") || strings.Count(lines[1], "=") != 1 {
		return "", ErrBackupKeyUnavailable
	}
	version := strings.TrimPrefix(lines[1], "active_key_version=")
	if !backupKeyVersion.MatchString(version) {
		return "", ErrBackupKeyUnavailable
	}
	return version, nil
}

func zeroBackupBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
