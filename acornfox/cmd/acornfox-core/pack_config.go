package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/acornfox/acornfox/internal/packprotocol"
)

type ProtectedPublisherConfig struct {
	Publisher    string   `json:"publisher"`
	PublicKey    string   `json:"public_key"`
	AllowedHosts []string `json:"allowed_hosts"`
}

type ProtectedRuntimeConfigFile struct {
	SocketPath               string                     `json:"socket_path"`
	StateDir                 string                     `json:"state_dir"`
	PacksDir                 string                     `json:"packs_dir"`
	PacksStateDir            string                     `json:"packs_state_dir"`
	PacksRunDir              string                     `json:"packs_run_dir"`
	StageDir                 string                     `json:"stage_dir"`
	CoreUID                  uint32                     `json:"core_uid"`
	CoreGID                  uint32                     `json:"core_gid"`
	TrustedCoreExecutableSHA string                     `json:"trusted_core_executable_sha"`
	InstallationBinding      string                     `json:"installation_binding"`
	Publishers               []ProtectedPublisherConfig `json:"publishers"`
}

type CorePackConfig struct {
	Enabled             bool
	Registered          bool
	ConfigPath          string
	HelperSocketPath    string
	StagingDir          string
	PublishedDir        string
	StateDir            string
	RunDir              string
	CoreUID             uint32
	CoreGID             uint32
	InstallationBinding string
	Publishers          map[string]packprotocol.VerificationPolicy
}

func loadProtectedPackConfig(path string) (CorePackConfig, error) {
	if path == "" {
		return CorePackConfig{Enabled: false}, nil
	}
	cleanPath := filepath.Clean(path)
	if !filepath.IsAbs(cleanPath) {
		return CorePackConfig{}, fmt.Errorf("pack config path %q must be absolute", path)
	}

	// Open file descriptor directly with O_NOFOLLOW to bind descriptor identity and prevent TOCTOU
	f, err := os.OpenFile(cleanPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return CorePackConfig{Enabled: false}, nil
		}
		return CorePackConfig{}, fmt.Errorf("open pack config %q: %w", cleanPath, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return CorePackConfig{}, fmt.Errorf("stat pack config descriptor %q: %w", cleanPath, err)
	}

	if !info.Mode().IsRegular() {
		return CorePackConfig{}, fmt.Errorf("pack config %q must be a regular file", cleanPath)
	}

	// Strictly reject group-writable (0020) and other-writable (0002)
	perm := info.Mode().Perm()
	if perm&0022 != 0 {
		return CorePackConfig{}, fmt.Errorf("pack config %q has insecure write permissions (mode %o): must not be group- or other-writable", cleanPath, perm)
	}

	// Verify owner: strictly root (UID 0) only; no current-UID or test exceptions permitted
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return CorePackConfig{}, errors.New("cannot determine file owner stat; rejected")
	}
	if stat.Uid != 0 {
		return CorePackConfig{}, fmt.Errorf("pack config %q owner UID %d is untrusted; must be owned strictly by root (0)", cleanPath, stat.Uid)
	}

	// Validate ancestor directories are not symlinks and not group/world-writable, and strictly root-owned
	dir := filepath.Dir(cleanPath)
	for dir != "/" && dir != "." {
		dInfo, err := os.Lstat(dir)
		if err != nil {
			return CorePackConfig{}, fmt.Errorf("stat ancestor dir %q: %w", dir, err)
		}
		if dInfo.Mode()&os.ModeSymlink != 0 {
			return CorePackConfig{}, fmt.Errorf("ancestor dir %q is a symlink", dir)
		}
		if dInfo.Mode().Perm()&0022 != 0 {
			return CorePackConfig{}, fmt.Errorf("ancestor dir %q has insecure write permissions (mode %o)", dir, dInfo.Mode().Perm())
		}
		dStat, dOk := dInfo.Sys().(*syscall.Stat_t)
		if !dOk {
			return CorePackConfig{}, errors.New("cannot determine ancestor directory stat; rejected")
		}
		if dStat.Uid != 0 {
			return CorePackConfig{}, fmt.Errorf("ancestor dir %q owner UID %d is untrusted; must be owned strictly by root (0)", dir, dStat.Uid)
		}
		dir = filepath.Dir(dir)
	}

	// Read content directly from verified descriptor
	raw, err := io.ReadAll(f)
	if err != nil {
		return CorePackConfig{}, fmt.Errorf("read pack config %q: %w", cleanPath, err)
	}

	var parsed ProtectedRuntimeConfigFile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return CorePackConfig{}, fmt.Errorf("parse pack config %q: %w", cleanPath, err)
	}

	// Honest capability degradation: if no publishers or helper socket or installation binding, fail-closed to unavailable
	if len(parsed.Publishers) == 0 || parsed.SocketPath == "" || parsed.InstallationBinding == "" {
		return CorePackConfig{
			Enabled:          false,
			ConfigPath:       cleanPath,
			HelperSocketPath: parsed.SocketPath,
		}, nil
	}

	if parsed.StageDir == "" {
		parsed.StageDir = "/var/lib/acornfox/core/pack-staging"
	}
	if parsed.PacksDir == "" {
		parsed.PacksDir = "/opt/acornfox/packs"
	}
	if parsed.PacksStateDir == "" {
		parsed.PacksStateDir = "/var/lib/acornfox/packs"
	}
	if parsed.PacksRunDir == "" {
		parsed.PacksRunDir = "/run/acornfox/packs"
	}

	publishers := make(map[string]packprotocol.VerificationPolicy, len(parsed.Publishers))
	for _, p := range parsed.Publishers {
		keyBytes, err := base64.StdEncoding.DecodeString(p.PublicKey)
		if err != nil || len(keyBytes) != ed25519.PublicKeySize {
			return CorePackConfig{}, fmt.Errorf("invalid public key for publisher %q", p.Publisher)
		}
		publishers[p.Publisher] = packprotocol.VerificationPolicy{
			Publisher:           p.Publisher,
			PublicKey:           ed25519.PublicKey(keyBytes),
			AllowedHosts:        p.AllowedHosts,
			CoreVersion:         "1.0.0",
			ProtocolVersion:     "1.0",
			OS:                  "linux",
			Arch:                "amd64",
			InstallationBinding: parsed.InstallationBinding,
		}
	}

	return CorePackConfig{
		Enabled:             true,
		ConfigPath:          cleanPath,
		HelperSocketPath:    parsed.SocketPath,
		StagingDir:          parsed.StageDir,
		PublishedDir:        parsed.PacksDir,
		StateDir:            parsed.PacksStateDir,
		RunDir:              parsed.PacksRunDir,
		CoreUID:             parsed.CoreUID,
		CoreGID:             parsed.CoreGID,
		InstallationBinding: parsed.InstallationBinding,
		Publishers:          publishers,
	}, nil
}

var errPackConfigUnavailable = errors.New("package management configuration unavailable")

func checkHelperSocketAvailable(socketPath string) bool {
	if socketPath == "" {
		return false
	}
	conn, err := net.DialTimeout("unix", socketPath, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
