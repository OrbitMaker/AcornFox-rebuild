package hostconfig

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
)

const (
	DefaultBootstrapExecutablePath = "/usr/local/libexec/acornfox-host-bootstrap"
	DefaultHostRuntimeConfigPath   = "/etc/acornfox-host/host-runtime.json"
	DefaultBootstrapRoot           = "/usr/local/lib/acornfox-host/bootstrap"
	DefaultSlotsRoot               = "/var/lib/acornfox-host/slots"
	DefaultControllerRoot          = "/var/lib/acornfox-host/controller"
	DefaultInvocationLockPath      = "/run/acornfox-host/invocation.lock"
	MaxConfigSize                  = 256 * 1024
)

var (
	ErrConfigInsecure     = errors.New("hostconfig: insecure config file permissions or ownership")
	ErrConfigInvalid      = errors.New("hostconfig: invalid configuration content")
	ErrConfigRootMismatch = errors.New("hostconfig: config roots mismatch compile-time constants")
	ErrInvocationBusy     = errors.New("hostconfig: invocation lock currently held")
	ErrLockInsecure       = errors.New("hostconfig: insecure invocation lock path or ownership")
)

var semverRegex = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-(beta|rc)\.([0-9]+))?$`)

type HostBundleFileConfig struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   int64  `json:"mode"`
}

type HostBootstrapSpecConfig struct {
	Root               string                 `json:"root"`
	OS                 string                 `json:"os"`
	Architecture       string                 `json:"arch"`
	Version            string                 `json:"version"`
	Launcher           string                 `json:"launcher"`
	Controller         string                 `json:"controller"`
	ControllerProtocol int                    `json:"controller_protocol"`
	InstanceProtocol   int                    `json:"instance_protocol"`
	BackendAPIProtocol int                    `json:"backend_api_protocol"`
	Files              []HostBundleFileConfig `json:"files"`
}

type ConfigPolicyFile struct {
	PublicKeyHex    string   `json:"public_key"`
	IndexURL        string   `json:"index_url"`
	OS              string   `json:"os"`
	Arch            string   `json:"arch"`
	Channel         string   `json:"channel"`
	AllowedHosts    []string `json:"allowed_hosts"`
	MaxArtifactSize int64    `json:"max_artifact_size"`
}

type HostConfigFile struct {
	SchemaVersion           int                     `json:"schema_version"`
	InstanceID              string                  `json:"instance_id"`
	BootstrapBackendBinding string                  `json:"bootstrap_backend_binding"`
	BootstrapSpec           HostBootstrapSpecConfig `json:"bootstrap_spec"`
	Policy                  ConfigPolicyFile        `json:"policy"`
	pins                    []*os.File              `json:"-"`
}

// Close closes all pinned ancestor directory descriptors.
func (c *HostConfigFile) Close() error {
	if c == nil {
		return nil
	}
	var errs []error
	for _, f := range c.pins {
		if err := f.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	c.pins = nil
	return errors.Join(errs...)
}

func isValidHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func pinDirectoryChain(p string, allowNonRoot bool) ([]*os.File, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid path %q", ErrConfigInsecure, p)
	}

	var dirs []string
	for cur := abs; ; cur = filepath.Dir(cur) {
		dirs = append(dirs, cur)
		if cur == filepath.Dir(cur) {
			break
		}
	}

	var pins []*os.File
	closePins := func() {
		for _, f := range pins {
			_ = f.Close()
		}
	}

	// Pin and verify from root downward
	for i := len(dirs) - 1; i >= 0; i-- {
		dir := dirs[i]
		f, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			closePins()
			return nil, fmt.Errorf("%w: failed to open ancestor %q: %v", ErrConfigInsecure, dir, err)
		}
		pins = append(pins, f)

		info, err := f.Stat()
		if err != nil {
			closePins()
			return nil, fmt.Errorf("%w: failed to stat ancestor %q: %v", ErrConfigInsecure, dir, err)
		}
		if !info.IsDir() {
			closePins()
			return nil, fmt.Errorf("%w: ancestor %q is not a directory", ErrConfigInsecure, dir)
		}

		if !allowNonRoot {
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				closePins()
				return nil, ErrConfigInsecure
			}
			if st.Uid != 0 {
				closePins()
				return nil, fmt.Errorf("%w: ancestor directory %q not owned by root", ErrConfigInsecure, dir)
			}
			if info.Mode().Perm()&0022 != 0 && !(st.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
				closePins()
				return nil, fmt.Errorf("%w: ancestor directory %q is group/world writable", ErrConfigInsecure, dir)
			}
		}
	}
	return pins, nil
}

func revalidatePins(pins []*os.File) error {
	for _, f := range pins {
		infoFromFD, err := f.Stat()
		if err != nil {
			return fmt.Errorf("%w: failed to stat pinned fd: %v", ErrConfigInsecure, err)
		}
		actual, err := os.Lstat(f.Name())
		if err != nil || !os.SameFile(infoFromFD, actual) || actual.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: pinned directory %q modified or replaced", ErrConfigInsecure, f.Name())
		}
	}
	return nil
}

// ReadAndValidateConfigFile loads host-runtime.json fail-closed with full permission checks,
// pinned ancestor verification, and exact canonical JSON byte equality.
// Pins are guaranteed closed on any error; caller holds pins via cfg.Close() on success.
func ReadAndValidateConfigFile(path string, expectedBootstrapRoot string, allowNonRoot bool) (*HostConfigFile, error) {
	if path == "" {
		path = DefaultHostRuntimeConfigPath
	}
	if expectedBootstrapRoot == "" {
		expectedBootstrapRoot = DefaultBootstrapRoot
	}

	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("%w: config path must be absolute and clean", ErrConfigInsecure)
	}

	// 1. Pin entire directory chain down to parent
	pins, err := pinDirectoryChain(filepath.Dir(path), allowNonRoot)
	if err != nil {
		return nil, err
	}
	var success bool
	defer func() {
		if !success {
			for _, f := range pins {
				_ = f.Close()
			}
		}
	}()

	// 2. Open file with O_NOFOLLOW
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to open config: %v", ErrConfigInsecure, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: config must be a regular file", ErrConfigInsecure)
	}
	if info.Size() == 0 || info.Size() > MaxConfigSize {
		return nil, fmt.Errorf("%w: invalid config file size", ErrConfigInvalid)
	}

	actual, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, actual) || actual.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: config file identity mismatch or symlink", ErrConfigInsecure)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, ErrConfigInsecure
	}
	if stat.Nlink != 1 {
		return nil, fmt.Errorf("%w: config file must have exactly 1 link", ErrConfigInsecure)
	}

	if !allowNonRoot {
		if stat.Uid != 0 || stat.Gid != 0 {
			return nil, fmt.Errorf("%w: config file must be owned by root:root", ErrConfigInsecure)
		}
		if info.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("%w: config file must not have group or other permissions", ErrConfigInsecure)
		}
	}

	// 3. Read content
	raw, err := io.ReadAll(io.LimitReader(f, MaxConfigSize+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxConfigSize {
		return nil, fmt.Errorf("%w: config file exceeds size limit", ErrConfigInvalid)
	}

	// 4. Strict JSON parsing with DisallowUnknownFields
	var cfg HostConfigFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%w: JSON decode failed: %v", ErrConfigInvalid, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: unexpected trailing data", ErrConfigInvalid)
	}

	// 5. Canonical byte equality check (strictly rejects duplicate, case-conflicting, or out-of-order keys)
	canonical, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		return nil, fmt.Errorf("%w: config JSON must be strictly canonical (rejects duplicates, case conflicts, and key reordering)", ErrConfigInvalid)
	}

	// 6. Semantic invariant validation
	if cfg.SchemaVersion != 1 {
		return nil, fmt.Errorf("%w: unsupported schema version %d", ErrConfigInvalid, cfg.SchemaVersion)
	}
	if !isValidHexSHA256(cfg.InstanceID) {
		return nil, fmt.Errorf("%w: invalid instance_id", ErrConfigInvalid)
	}
	if !isValidHexSHA256(cfg.BootstrapBackendBinding) {
		return nil, fmt.Errorf("%w: invalid bootstrap_backend_binding", ErrConfigInvalid)
	}

	bs := cfg.BootstrapSpec
	if bs.Root != expectedBootstrapRoot {
		return nil, fmt.Errorf("%w: bootstrap root %q mismatch expected %q", ErrConfigRootMismatch, bs.Root, expectedBootstrapRoot)
	}
	expectedOS := "linux"
	if allowNonRoot {
		expectedOS = runtime.GOOS
	}
	if bs.OS != expectedOS {
		return nil, fmt.Errorf("%w: unsupported OS %q", ErrConfigInvalid, bs.OS)
	}
	if bs.Architecture != runtime.GOARCH {
		return nil, fmt.Errorf("%w: architecture mismatch: config %q vs host %q", ErrConfigInvalid, bs.Architecture, runtime.GOARCH)
	}
	if !semverRegex.MatchString(bs.Version) {
		return nil, fmt.Errorf("%w: invalid bootstrap semver version %q", ErrConfigInvalid, bs.Version)
	}
	if bs.Launcher != "launcher/acornfox-host-launcher" {
		return nil, fmt.Errorf("%w: launcher path %q mismatch", ErrConfigInvalid, bs.Launcher)
	}
	if bs.Controller != "controller/acornfox-host-update" {
		return nil, fmt.Errorf("%w: controller path %q mismatch", ErrConfigInvalid, bs.Controller)
	}
	if bs.ControllerProtocol != 1 || bs.InstanceProtocol != 1 || bs.BackendAPIProtocol != 1 {
		return nil, fmt.Errorf("%w: protocol version mismatch in bootstrap spec", ErrConfigInvalid)
	}
	if len(bs.Files) == 0 {
		return nil, fmt.Errorf("%w: bootstrap spec files cannot be empty", ErrConfigInvalid)
	}

	pol := cfg.Policy
	if pol.OS != expectedOS || pol.Arch != runtime.GOARCH {
		return nil, fmt.Errorf("%w: policy OS/Arch mismatch", ErrConfigInvalid)
	}
	if pol.Channel != "stable" && pol.Channel != "beta" {
		return nil, fmt.Errorf("%w: invalid policy channel %q", ErrConfigInvalid, pol.Channel)
	}
	if len(pol.PublicKeyHex) != 64 {
		return nil, fmt.Errorf("%w: invalid policy public key length", ErrConfigInvalid)
	}
	if _, err := hex.DecodeString(pol.PublicKeyHex); err != nil {
		return nil, fmt.Errorf("%w: invalid policy public key hex: %v", ErrConfigInvalid, err)
	}
	if !strings.HasPrefix(pol.IndexURL, "https://") {
		return nil, fmt.Errorf("%w: policy index URL must use https", ErrConfigInvalid)
	}

	// 7. Post-open revalidation: verify all pinned ancestors against pathnames
	if err := revalidatePins(pins); err != nil {
		return nil, err
	}

	success = true
	cfg.pins = pins
	return &cfg, nil
}

// AcquireInvocationLock securely opens and locks the invocation lockfile,
// verifying the ancestor directory chain, O_NOFOLLOW, nlink==1, and non-blocking flock.
func AcquireInvocationLock(lockPath string, allowNonRoot bool) (*os.File, error) {
	if lockPath == "" {
		lockPath = DefaultInvocationLockPath
	}
	if !filepath.IsAbs(lockPath) || filepath.Clean(lockPath) != lockPath {
		return nil, fmt.Errorf("%w: lock path must be absolute and clean", ErrLockInsecure)
	}

	parentDir := filepath.Dir(lockPath)
	pins, err := pinDirectoryChain(parentDir, allowNonRoot)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, f := range pins {
			_ = f.Close()
		}
	}()

	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to open lockfile: %v", ErrLockInsecure, err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%w: lockfile must be regular", ErrLockInsecure)
	}

	actual, err := os.Lstat(lockPath)
	if err != nil || !os.SameFile(info, actual) || actual.Mode()&os.ModeSymlink != 0 {
		f.Close()
		return nil, fmt.Errorf("%w: lockfile identity mismatch or symlink", ErrLockInsecure)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		f.Close()
		return nil, fmt.Errorf("%w: lockfile must have single link", ErrLockInsecure)
	}

	if !allowNonRoot {
		if stat.Uid != 0 {
			f.Close()
			return nil, fmt.Errorf("%w: lockfile must be owned by root", ErrLockInsecure)
		}
		if info.Mode().Perm()&0077 != 0 {
			f.Close()
			return nil, fmt.Errorf("%w: lockfile must be 0600", ErrLockInsecure)
		}
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrInvocationBusy
		}
		return nil, fmt.Errorf("failed to acquire flock: %w", err)
	}

	// Post-lock revalidation of pinned parent chain
	if err := revalidatePins(pins); err != nil {
		f.Close()
		return nil, err
	}

	return f, nil
}
