//go:build linux

package desktopupdateguest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/open-card/open-card/internal/desktopupdate"
)

var (
	ErrPrivilegeRequired = errors.New("guest provision: root privileges required")
	ErrInvalidRequest    = errors.New("guest provision: invalid request")
)

type ProvisionRequest struct {
	Kind                 string // "linux-local" or "mac-managed"
	BootstrapHostVersion string // semver string, e.g. "1.0.0"
	WorkerSourcePath     string // path to worker binary file
	ExpectedWorkerSHA256 string // expected SHA-256 hex
	PolicySourcePath     string // path to policy JSON file
	ExpectedPolicySHA256 string // expected SHA-256 hex
}

type ProvisionReceipt struct {
	Kind                 string `json:"kind"`
	InstanceID           string `json:"instance_id"`
	NativeID             string `json:"native_id"`
	WorkerSHA256         string `json:"worker_sha256"`
	PolicySHA256         string `json:"policy_sha256"`
	InstanceSHA256       string `json:"instance_sha256"`
	MarkerSHA256         string `json:"marker_sha256"`
	BootstrapHostVersion string `json:"bootstrap_host_version"`
}

type provisionPaths struct {
	anchor      string
	executable  string
	policy      string
	instance    string
	state       string
	macMarker   string
	linuxMarker string
	lock        string
}

func defaultProductionPaths() provisionPaths {
	return provisionPaths{
		anchor:      "/",
		executable:  ExecutablePath,
		policy:      PolicyPath,
		instance:    InstancePath,
		state:       StatePath,
		macMarker:   "/var/lib/acornfox-desktop/owner-marker",
		linuxMarker: filepath.Join(filepath.Dir(InstancePath), "linux-owner-marker"),
		lock:        filepath.Join(filepath.Dir(InstancePath), "provision.lock"),
	}
}

// Provision is the public root-only provisioning entry point for native outer installers.
// It publishes the fixed worker, instance, state, and policy atomically to their fixed
// production paths. It accepts no destination root, shell fragments, or runtime authority overrides.
func Provision(ctx context.Context, req ProvisionRequest) (*ProvisionReceipt, error) {
	if os.Geteuid() != 0 {
		return nil, ErrPrivilegeRequired
	}
	return provisionWithPaths(ctx, defaultProductionPaths(), req)
}

// provisionWithPaths is package-private for deterministic testing under a private root anchor.
func provisionWithPaths(ctx context.Context, paths provisionPaths, req ProvisionRequest) (*ProvisionReceipt, error) {
	if os.Geteuid() != 0 {
		return nil, ErrPrivilegeRequired
	}
	if ctx == nil {
		return nil, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 1. Validate request parameters
	if req.Kind != "linux-local" && req.Kind != "mac-managed" {
		return nil, ErrConflict
	}
	if _, err := desktopupdate.ParseSemver(req.BootstrapHostVersion); err != nil {
		return nil, ErrConflict
	}
	expectedWorkerSHA := strings.ToLower(strings.TrimSpace(req.ExpectedWorkerSHA256))
	if !hexID.MatchString(expectedWorkerSHA) {
		return nil, ErrConflict
	}
	expectedPolicySHA := strings.ToLower(strings.TrimSpace(req.ExpectedPolicySHA256))
	if !hexID.MatchString(expectedPolicySHA) {
		return nil, ErrConflict
	}

	// 2. Read and pin worker source via opened FD
	workerBytes, err := readSourceFile(paths.anchor, req.WorkerSourcePath, 64<<20)
	if err != nil {
		return nil, ErrConflict
	}
	if digest(workerBytes) != expectedWorkerSHA {
		return nil, ErrConflict
	}

	// 3. Read and pin policy source via opened FD
	policyBytes, err := readSourceFile(paths.anchor, req.PolicySourcePath, 64<<10)
	if err != nil {
		return nil, ErrConflict
	}
	if digest(policyBytes) != expectedPolicySHA {
		return nil, ErrConflict
	}

	var policy Policy
	if decode(policyBytes, &policy) != nil || policy.Schema != 1 || len(policy.PublicKey) != ed25519.PublicKeySize || policy.MaxArtifactSize < 1 || policy.MaxArtifactSize > desktopupdate.MaxArtifactSizeBytes || len(policy.AllowedHosts) == 0 {
		return nil, ErrConflict
	}
	if policy.HostArch != runtime.GOARCH || (policy.Channel != "stable" && policy.Channel != "beta") {
		return nil, ErrConflict
	}
	if req.Kind == "linux-local" && policy.HostOS != "linux" {
		return nil, ErrConflict
	}
	if req.Kind == "mac-managed" && policy.HostOS != "darwin" {
		return nil, ErrConflict
	}

	// 4. Strict ELF validation: 64-bit, little-endian, executable/PIE, non-zero entry, matching machine
	if err := verifyWorkerELF(workerBytes, policy.HostArch); err != nil {
		return nil, ErrConflict
	}

	// 5. Acquire root-owned provisioning lock around the entire operation
	lockFile, err := acquireProvisionLock(paths.anchor, paths.lock)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = lockFile.Close()
	}()

	// 6. Branch: configured re-entry vs fresh/resume provisioning
	if _, err := os.Lstat(paths.policy); err == nil {
		// P1-1: Target policy already exists: exact re-entry only.
		// All files and valid state must exist. Do not recreate missing state or reset history.
		return validateConfiguredReentry(paths, req, workerBytes, policyBytes)
	}

	// P1-2: Target policy absent: fresh/resume provisioning.
	// State directory must be absent or completely empty. Policy published last.
	return freshOrResumeProvisioning(paths, req, workerBytes, policyBytes)
}

func validateConfiguredReentry(paths provisionPaths, req ProvisionRequest, workerBytes, policyBytes []byte) (*ProvisionReceipt, error) {
	// 1. Policy must exist and match expected bytes exactly
	polRaw, err := readSafe(paths.anchor, paths.policy, 0600, 65536)
	if err != nil || !bytes.Equal(polRaw, policyBytes) {
		return nil, ErrConflict
	}

	// 2. Worker executable must exist, regular, perm 0755, root:root, nlink 1, exact bytes
	wInfo, err := os.Lstat(paths.executable)
	if err != nil {
		return nil, ErrConflict
	}
	wStat, ok := wInfo.Sys().(*syscall.Stat_t)
	if !ok || !wInfo.Mode().IsRegular() || wStat.Uid != 0 || wStat.Gid != 0 || wStat.Nlink != 1 || wInfo.Mode().Perm() != 0755 {
		return nil, ErrConflict
	}
	wRaw, err := readSafe(paths.anchor, paths.executable, 0755, int64(len(workerBytes)+1024))
	if err != nil || !bytes.Equal(wRaw, workerBytes) {
		return nil, ErrConflict
	}

	// 3. Instance file must exist and match expected schema/kind
	instRaw, err := readSafe(paths.anchor, paths.instance, 0600, 65536)
	if err != nil {
		return nil, ErrConflict
	}
	var inst Instance
	if decode(instRaw, &inst) != nil || inst.Schema != 1 || inst.Kind != req.Kind || inst.BootstrapHostVersion != req.BootstrapHostVersion {
		return nil, ErrConflict
	}

	// 4. Marker must exist and match instance.MarkerSHA256
	markerPath := paths.macMarker
	if req.Kind == "linux-local" {
		markerPath = paths.linuxMarker
	}
	mRaw, err := readSafe(paths.anchor, markerPath, 0600, 65536)
	if err != nil || digest(mRaw) != inst.MarkerSHA256 {
		return nil, ErrConflict
	}

	// 5. State directory must exist, perm 0700, root:root, non-symlink
	sInfo, err := os.Lstat(paths.state)
	if err != nil {
		return nil, ErrConflict
	}
	sStat, ok := sInfo.Sys().(*syscall.Stat_t)
	if !ok || !sInfo.IsDir() || sInfo.Mode()&os.ModeSymlink != 0 || sStat.Uid != 0 || sStat.Gid != 0 || sInfo.Mode().Perm() != 0700 {
		return nil, ErrConflict
	}

	// 6. Validate configuration and snapshot with Executor
	sp := systemPaths{
		anchor:     paths.anchor,
		policy:     paths.policy,
		instance:   paths.instance,
		state:      paths.state,
		executable: paths.executable,
		marker:     paths.macMarker,
	}
	exec, err := open(sp)
	if err != nil {
		return nil, err
	}

	// Acquire executor lock and verify state.json exists and validates
	execLock, err := exec.lock()
	if err != nil {
		return nil, err
	}
	defer execLock.Close()

	snap, err := exec.readSnapshot()
	if err != nil {
		return nil, ErrConflict
	}
	if snap.Schema != 1 {
		return nil, ErrConflict
	}

	return &ProvisionReceipt{
		Kind:                 req.Kind,
		InstanceID:           inst.InstanceID,
		NativeID:             inst.NativeID,
		WorkerSHA256:         digest(workerBytes),
		PolicySHA256:         digest(policyBytes),
		InstanceSHA256:       digest(instRaw),
		MarkerSHA256:         inst.MarkerSHA256,
		BootstrapHostVersion: req.BootstrapHostVersion,
	}, nil
}

func freshOrResumeProvisioning(paths provisionPaths, req ProvisionRequest, workerBytes, policyBytes []byte) (*ProvisionReceipt, error) {
	// Policy must NOT exist
	if _, err := os.Lstat(paths.policy); err == nil {
		return nil, ErrConflict
	}

	// P1-2: State directory must be absent OR completely empty!
	sInfo, err := os.Lstat(paths.state)
	if err == nil {
		sStat, ok := sInfo.Sys().(*syscall.Stat_t)
		if !ok || !sInfo.IsDir() || sInfo.Mode()&os.ModeSymlink != 0 || sStat.Uid != 0 || sStat.Gid != 0 || sInfo.Mode().Perm() != 0700 {
			return nil, ErrConflict
		}
		entries, readErr := os.ReadDir(paths.state)
		if readErr != nil || len(entries) > 0 {
			return nil, ErrConflict // Reject non-empty state directory!
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := ensureDirSafe(paths.anchor, paths.state, 0700); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}

	// Marker
	var nativeID string
	var markerSHA string

	switch req.Kind {
	case "mac-managed":
		raw, err := readSafe(paths.anchor, paths.macMarker, 0600, 65536)
		if err != nil {
			return nil, ErrConflict
		}
		var m struct {
			Product  string `json:"product"`
			Instance string `json:"instance"`
		}
		if jsonMarker(raw, &m) != nil || m.Product != "acornfox" || !macID.MatchString(m.Instance) {
			return nil, ErrConflict
		}
		nativeID = m.Instance
		markerSHA = digest(raw)

	case "linux-local":
		raw, err := readSafe(paths.anchor, paths.linuxMarker, 0600, 65536)
		if err == nil {
			var m struct {
				Product  string `json:"product"`
				Instance string `json:"instance"`
			}
			if jsonMarker(raw, &m) != nil || m.Product != "acornfox" || !hexID.MatchString(m.Instance) {
				return nil, ErrConflict
			}
			nativeID = m.Instance
			markerSHA = digest(raw)
		} else if errors.Is(err, os.ErrNotExist) {
			if err := ensureDirSafe(paths.anchor, filepath.Dir(paths.linuxMarker), 0755); err != nil {
				return nil, err
			}
			var randBytes [32]byte
			if _, err := io.ReadFull(crand.Reader, randBytes[:]); err != nil {
				return nil, err
			}
			nativeID = hex.EncodeToString(randBytes[:])
			markerRaw := []byte(fmt.Sprintf(`{"product":"acornfox","instance":"%s"}`+"\n", nativeID))
			if err := writeNew(paths.linuxMarker, markerRaw, 0600); err != nil {
				return nil, err
			}
			_ = os.Chown(paths.linuxMarker, 0, 0)
			if err := syncDir(filepath.Dir(paths.linuxMarker)); err != nil {
				return nil, err
			}
			markerSHA = digest(markerRaw)
		} else {
			return nil, ErrConflict
		}
	}

	// Instance
	instanceID := digest([]byte(req.Kind + ":" + nativeID))
	instance := Instance{
		Schema:               1,
		Kind:                 req.Kind,
		NativeID:             nativeID,
		InstanceID:           instanceID,
		MarkerSHA256:         markerSHA,
		BootstrapHostVersion: req.BootstrapHostVersion,
	}
	instanceBytes := encoded(instance)

	// Ensure worker executable: 0755 root:root
	if err := ensureFileSafe(paths.anchor, paths.executable, workerBytes, 0755); err != nil {
		return nil, err
	}

	// Ensure instance file: 0600 root:root
	if err := ensureFileSafe(paths.anchor, paths.instance, instanceBytes, 0600); err != nil {
		return nil, err
	}

	// Verify state directory is still empty before publishing policy
	entries, err := os.ReadDir(paths.state)
	if err != nil || len(entries) > 0 {
		return nil, ErrConflict
	}

	// PUBLISH POLICY LAST
	if err := ensureFileSafe(paths.anchor, paths.policy, policyBytes, 0600); err != nil {
		return nil, err
	}

	// Post-validation with open(sp)
	sp := systemPaths{
		anchor:     paths.anchor,
		policy:     paths.policy,
		instance:   paths.instance,
		state:      paths.state,
		executable: paths.executable,
		marker:     paths.macMarker,
	}
	if _, err := open(sp); err != nil {
		return nil, err
	}

	return &ProvisionReceipt{
		Kind:                 req.Kind,
		InstanceID:           instanceID,
		NativeID:             nativeID,
		WorkerSHA256:         digest(workerBytes),
		PolicySHA256:         digest(policyBytes),
		InstanceSHA256:       digest(instanceBytes),
		MarkerSHA256:         markerSHA,
		BootstrapHostVersion: req.BootstrapHostVersion,
	}, nil
}

func readSourceFile(anchor, path string, maxLimit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrConflict
	}
	parentDir := filepath.Dir(path)
	checkAnchor := "/"
	if anchor != "/" && strings.HasPrefix(parentDir, anchor) {
		checkAnchor = anchor
	}
	if err := checkParents(checkAnchor, parentDir); err != nil {
		return nil, ErrConflict
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrConflict
	}
	defer f.Close()

	info1, err := f.Stat()
	if err != nil {
		return nil, ErrConflict
	}
	s1, ok := info1.Sys().(*syscall.Stat_t)
	if !ok || !info1.Mode().IsRegular() || info1.Mode()&os.ModeSymlink != 0 || s1.Uid != 0 || s1.Gid != 0 || s1.Nlink != 1 || info1.Mode().Perm()&0022 != 0 {
		return nil, ErrConflict
	}

	data, err := io.ReadAll(io.LimitReader(f, maxLimit+1))
	if err != nil || int64(len(data)) > maxLimit {
		return nil, ErrConflict
	}

	info2, err := f.Stat()
	if err != nil {
		return nil, ErrConflict
	}
	s2, ok := info2.Sys().(*syscall.Stat_t)
	if !ok || !os.SameFile(info1, info2) || s2.Ino != s1.Ino || s2.Dev != s1.Dev || info2.Size() != int64(len(data)) {
		return nil, ErrConflict
	}

	return data, nil
}

func acquireProvisionLock(anchor, lockPath string) (*os.File, error) {
	if err := ensureDirSafe(anchor, filepath.Dir(lockPath), 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || s.Uid != 0 || s.Gid != 0 || s.Nlink != 1 || info.Mode().Perm() != 0600 {
		f.Close()
		return nil, ErrConflict
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	_ = os.Chown(lockPath, 0, 0)
	return f, nil
}

func ensureDirSafe(anchor, targetDir string, mode os.FileMode) error {
	rel, err := filepath.Rel(anchor, targetDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return ErrConflict
	}
	current := anchor
	parts := strings.Split(rel, string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				if err := os.Mkdir(current, mode); err != nil {
					return err
				}
				_ = os.Chmod(current, mode)
				_ = os.Chown(current, 0, 0)
				continue
			}
			return err
		}
		s, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || s.Uid != 0 || s.Gid != 0 {
			return ErrConflict
		}
	}
	return nil
}

func ensureFileSafe(anchor, targetPath string, expectedBytes []byte, mode os.FileMode) error {
	if err := ensureDirSafe(anchor, filepath.Dir(targetPath), 0755); err != nil {
		return err
	}
	info, err := os.Lstat(targetPath)
	if err == nil {
		// File exists: verify idempotency
		s, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || s.Uid != 0 || s.Gid != 0 || s.Nlink != 1 || info.Mode().Perm() != mode {
			return ErrConflict
		}
		existing, err := readSafe(anchor, targetPath, mode, int64(len(expectedBytes)+1024))
		if err != nil || !bytes.Equal(existing, expectedBytes) {
			return ErrConflict // Mismatch fails preserving existing files
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// File does not exist: create with writeNew
	if err := writeNew(targetPath, expectedBytes, mode); err != nil {
		return err
	}
	_ = os.Chown(targetPath, 0, 0)
	return syncDir(filepath.Dir(targetPath))
}

func verifyWorkerELF(raw []byte, expectedArch string) error {
	f, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return ErrConflict
	}
	defer f.Close()

	if f.Class != elf.ELFCLASS64 {
		return ErrConflict
	}
	if f.Data != elf.ELFDATA2LSB {
		return ErrConflict
	}
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return ErrConflict
	}
	if f.Entry == 0 {
		return ErrConflict
	}
	switch expectedArch {
	case "amd64":
		if f.Machine != elf.EM_X86_64 {
			return ErrConflict
		}
	case "arm64":
		if f.Machine != elf.EM_AARCH64 {
			return ErrConflict
		}
	default:
		return ErrConflict
	}
	return nil
}
