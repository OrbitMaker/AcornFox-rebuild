package localpeer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	MaxBindingFileBytes = 16 << 10 // 16 KiB
	BindingVersion1     = "1.0"
)

// RuntimePeerBinding is the immutable, root-published mutual attestation profile.
type RuntimePeerBinding struct {
	Version                    string `json:"version"`
	InstallationID             string `json:"installation_id"`
	ContainerSocket            string `json:"container_socket"`
	AuthoritySocket            string `json:"authority_socket"`
	CoreUID                    uint32 `json:"core_uid"`
	CorePID                    int32  `json:"core_pid"`
	CoreExeSHA                 string `json:"core_exe_sha"`
	CoreStartTime              string `json:"core_start_time"`
	ContainerUID               uint32 `json:"container_uid"`
	ContainerPID               int32  `json:"container_pid"`
	ContainerExeSHA            string `json:"container_exe_sha"`
	ContainerStartTime         string `json:"container_start_time"`
	SourceBuildUID             uint32 `json:"source_build_uid,omitempty"`
	SourceBuildPID             int32  `json:"source_build_pid,omitempty"`
	SourceBuildExeSHA          string `json:"source_build_exe_sha,omitempty"`
	SourceBuildStartTime       string `json:"source_build_start_time,omitempty"`
	SourceBuildSocket          string `json:"source_build_socket,omitempty"`
	SourceBuildAuthoritySocket string `json:"source_build_authority_socket,omitempty"`
	GatewayUID                 uint32 `json:"gateway_uid,omitempty"`
	GatewayPID                 int32  `json:"gateway_pid,omitempty"`
	GatewayExeSHA              string `json:"gateway_exe_sha,omitempty"`
	GatewayStartTime           string `json:"gateway_start_time,omitempty"`
	GatewaySocket              string `json:"gateway_socket,omitempty"`
	GatewayAuthoritySocket     string `json:"gateway_authority_socket,omitempty"`
}

// Validate ensures every required field is present with strict positive PID, non-empty start, and 64-hex SHA.
func (b *RuntimePeerBinding) Validate() error {
	if b == nil {
		return errors.New("runtime peer binding is nil")
	}
	if b.Version != BindingVersion1 {
		return fmt.Errorf("unsupported binding version %q", b.Version)
	}
	if b.ContainerSocket == "" || !filepath.IsAbs(b.ContainerSocket) {
		return errors.New("container_socket must be an absolute path")
	}
	if b.AuthoritySocket == "" || !filepath.IsAbs(b.AuthoritySocket) {
		return errors.New("authority_socket must be an absolute path")
	}
	if b.CorePID <= 0 {
		return errors.New("core_pid must be a positive PID")
	}
	if strings.TrimSpace(b.CoreStartTime) == "" {
		return errors.New("core_start_time is required")
	}
	if !validBindingHexSHA(b.CoreExeSHA) {
		return errors.New("core_exe_sha must be 64 lowercase hex characters")
	}
	if b.ContainerPID <= 0 {
		return errors.New("container_pid must be a positive PID")
	}
	if strings.TrimSpace(b.ContainerStartTime) == "" {
		return errors.New("container_start_time is required")
	}
	if !validBindingHexSHA(b.ContainerExeSHA) {
		return errors.New("container_exe_sha must be 64 lowercase hex characters")
	}
	if b.HasSourceBuild() {
		if b.SourceBuildUID == 0 || b.SourceBuildPID <= 0 || !validBindingHexSHA(b.SourceBuildExeSHA) || strings.TrimSpace(b.SourceBuildStartTime) == "" || !filepath.IsAbs(b.SourceBuildSocket) || !filepath.IsAbs(b.SourceBuildAuthoritySocket) {
			return errors.New("source-build binding must contain the complete nonroot identity and socket tuple")
		}
		if filepath.Clean(b.SourceBuildSocket) != b.SourceBuildSocket || filepath.Clean(b.SourceBuildAuthoritySocket) != b.SourceBuildAuthoritySocket {
			return errors.New("source-build socket paths must be canonical")
		}
		if b.SourceBuildPID == b.CorePID || b.SourceBuildPID == b.ContainerPID || b.SourceBuildSocket == b.SourceBuildAuthoritySocket || b.SourceBuildSocket == filepath.Clean(b.ContainerSocket) || b.SourceBuildSocket == filepath.Clean(b.AuthoritySocket) || b.SourceBuildAuthoritySocket == filepath.Clean(b.ContainerSocket) || b.SourceBuildAuthoritySocket == filepath.Clean(b.AuthoritySocket) {
			return errors.New("source-build identity and sockets must be distinct")
		}
	}
	if b.HasGateway() {
		if b.GatewayUID == 0 || b.GatewayPID <= 0 || !validBindingHexSHA(b.GatewayExeSHA) || strings.TrimSpace(b.GatewayStartTime) == "" || !filepath.IsAbs(b.GatewaySocket) || !filepath.IsAbs(b.GatewayAuthoritySocket) {
			return errors.New("gateway binding must contain the complete nonroot identity and socket tuple")
		}
		if filepath.Clean(b.GatewaySocket) != b.GatewaySocket || filepath.Clean(b.GatewayAuthoritySocket) != b.GatewayAuthoritySocket || b.GatewaySocket == b.GatewayAuthoritySocket {
			return errors.New("gateway socket paths must be canonical and distinct")
		}
		if b.GatewayPID == b.CorePID || b.GatewayPID == b.ContainerPID || b.GatewayUID == b.CoreUID || b.GatewayUID == b.ContainerUID || b.HasSourceBuild() && (b.GatewayPID == b.SourceBuildPID || b.GatewayUID == b.SourceBuildUID) {
			return errors.New("gateway identity must be distinct from other roles")
		}
		for _, other := range []string{b.ContainerSocket, b.AuthoritySocket, b.SourceBuildSocket, b.SourceBuildAuthoritySocket} {
			if other != "" && (b.GatewaySocket == filepath.Clean(other) || b.GatewayAuthoritySocket == filepath.Clean(other)) {
				return errors.New("gateway socket aliases another role")
			}
		}
	}
	return nil
}

// Digest computes the deterministic sha256 hex digest of the canonical binding identity.
func (b *RuntimePeerBinding) Digest() string {
	raw, _ := json.Marshal(b)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validBindingHexSHA(s string) bool {
	if len(s) != 64 {
		return false
	}
	h, err := hex.DecodeString(s)
	return err == nil && len(h) == 32 && s == strings.ToLower(s)
}

// ParseRuntimePeerBinding decodes bounded JSON into a validated RuntimePeerBinding.
func ParseRuntimePeerBinding(raw []byte) (*RuntimePeerBinding, error) {
	if len(raw) > MaxBindingFileBytes {
		return nil, errors.New("runtime peer binding exceeds maximum bound (16KB)")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	var b RuntimePeerBinding
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("decode runtime peer binding: %w", err)
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("extraneous content in runtime peer binding")
	}
	if err := b.Validate(); err != nil {
		return nil, fmt.Errorf("invalid runtime peer binding: %w", err)
	}
	return &b, nil
}

// LoadProtectedRuntimePeerBinding reads and verifies the descriptor of a root-owned, non-writable protected binding file.
func LoadProtectedRuntimePeerBinding(path string) (*RuntimePeerBinding, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return nil, nil // Unconfigured
	}
	cleanPath = filepath.Clean(cleanPath)
	if !filepath.IsAbs(cleanPath) {
		return nil, fmt.Errorf("binding path %q must be absolute", cleanPath)
	}

	// Open descriptor directly with O_NOFOLLOW to bind descriptor identity and prevent TOCTOU symlinks
	f, err := os.OpenFile(cleanPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Absent
		}
		return nil, fmt.Errorf("open runtime peer binding %q: %w", cleanPath, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat runtime peer binding descriptor %q: %w", cleanPath, err)
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("runtime peer binding %q must be a regular file", cleanPath)
	}

	// Reject group-writable (0020) and other-writable (0002)
	perm := info.Mode().Perm()
	if perm&0022 != 0 {
		return nil, fmt.Errorf("runtime peer binding %q has insecure write permissions (mode %o)", cleanPath, perm)
	}

	// Verify owner: strictly root (UID 0)
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("cannot determine file owner stat; rejected")
	}
	if stat.Uid != 0 {
		return nil, fmt.Errorf("runtime peer binding %q owner UID %d is untrusted; must be owned strictly by root (0)", cleanPath, stat.Uid)
	}

	// Validate ancestor directories are not symlinks, not group/world-writable, and strictly root-owned
	dir := filepath.Dir(cleanPath)
	for dir != "/" && dir != "." {
		dInfo, err := os.Lstat(dir)
		if err != nil {
			return nil, fmt.Errorf("stat ancestor dir %q: %w", dir, err)
		}
		if dInfo.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("ancestor dir %q is a symlink", dir)
		}
		if dInfo.Mode().Perm()&0022 != 0 {
			return nil, fmt.Errorf("ancestor dir %q has insecure write permissions (mode %o)", dir, dInfo.Mode().Perm())
		}
		dStat, dOk := dInfo.Sys().(*syscall.Stat_t)
		if !dOk {
			return nil, errors.New("cannot determine ancestor directory stat; rejected")
		}
		if dStat.Uid != 0 {
			return nil, fmt.Errorf("ancestor dir %q owner UID %d is untrusted; must be owned strictly by root (0)", dir, dStat.Uid)
		}
		dir = filepath.Dir(dir)
	}

	raw, err := io.ReadAll(io.LimitReader(f, MaxBindingFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read runtime peer binding %q: %w", cleanPath, err)
	}

	return ParseRuntimePeerBinding(raw)
}

func (b *RuntimePeerBinding) HasSourceBuild() bool {
	return b != nil && (b.SourceBuildUID != 0 || b.SourceBuildPID != 0 || b.SourceBuildExeSHA != "" || b.SourceBuildStartTime != "" || b.SourceBuildSocket != "" || b.SourceBuildAuthoritySocket != "")
}

func (b *RuntimePeerBinding) HasGateway() bool {
	return b != nil && (b.GatewayUID != 0 || b.GatewayPID != 0 || b.GatewayExeSHA != "" || b.GatewayStartTime != "" || b.GatewaySocket != "" || b.GatewayAuthoritySocket != "")
}
