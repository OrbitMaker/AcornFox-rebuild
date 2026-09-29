package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"log"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/open-card/open-card/internal/hosthelper"
	"github.com/open-card/open-card/internal/localpeer"
	"github.com/open-card/open-card/internal/packmanager"
	"github.com/open-card/open-card/internal/packprotocol"
)

type ProtectedPublisherConfig struct {
	Publisher    string   `json:"publisher"`
	PublicKey    string   `json:"public_key"`
	AllowedHosts []string `json:"allowed_hosts"`
}

type runtimeConfig struct {
	SocketPath               string                     `json:"socket_path"`
	StateDir                 string                     `json:"state_dir"`
	StageDir                 string                     `json:"stage_dir"`
	PacksDir                 string                     `json:"packs_dir"`
	PacksStateDir            string                     `json:"packs_state_dir"`
	PacksRunDir              string                     `json:"packs_run_dir"`
	ServiceTemplatePath      string                     `json:"service_template_path"`
	CoreUID                  uint32                     `json:"core_uid"`
	CoreGID                  uint32                     `json:"core_gid"`
	TrustedCoreExecutableSHA string                     `json:"trusted_core_executable_sha"`
	InstallationBinding      string                     `json:"installation_binding"`
	Publishers               []ProtectedPublisherConfig `json:"publishers"`
}

func main() {
	configPath := flag.String("config", "/etc/acornfox/pack-runtime.json", "Path to protected pack-runtime.json configuration")
	runtimeBindingPath := flag.String("runtime-binding", "", "Optional path to root-protected runtime-binding.json for peer attestation")
	readonlyPeer := flag.Bool("readonly-peer", false, "Start host-helper in readonly peer attestation mode")
	coreGIDFlag := flag.Uint("core-gid", 0, "Actual Core primary group ID (legacy helper socket group when --socket-gid is absent)")
	socketGIDFlag := flag.Uint("socket-gid", 0, "Optional separately allocated IPC group ID for the helper socket")
	socketPathFlag := flag.String("socket", hosthelper.DefaultHelperSocketPath, "Unix domain socket path for host-helper")
	flag.Parse()

	if *readonlyPeer {
		if *runtimeBindingPath == "" {
			log.Fatalf("runtime-binding is required in readonly-peer mode")
		}
		cleanBinding := filepath.Clean(*runtimeBindingPath)
		binding, err := localpeer.LoadProtectedRuntimePeerBinding(cleanBinding)
		if err != nil {
			log.Fatalf("load runtime binding failed: %v", err)
		}
		if binding == nil {
			log.Fatalf("runtime binding is empty or missing")
		}

		if *coreGIDFlag == 0 || *coreGIDFlag > math.MaxUint32 {
			log.Fatalf("--core-gid must be configured (> 0 and <= MaxUint32) in readonly-peer mode")
		}
		gid := uint32(*coreGIDFlag)
		if *socketGIDFlag > math.MaxUint32 {
			log.Fatalf("--socket-gid exceeds MaxUint32")
		}

		sockPath := hosthelper.DefaultHelperSocketPath
		if *socketPathFlag != "" {
			sockPath = filepath.Clean(*socketPathFlag)
		}

		cfg := hosthelper.ServerConfig{
			SocketPath:         sockPath,
			RuntimeBindingPath: cleanBinding,
			ReadOnlyPeerOnly:   true,
			CoreGID:            gid,
			SocketGID:          uint32(*socketGIDFlag),
		}
		server, err := hosthelper.NewServer(cfg)
		if err != nil {
			log.Fatalf("initialize readonly helper server: %v", err)
		}
		if err := server.Start(); err != nil {
			log.Fatalf("start readonly helper server: %v", err)
		}
		defer server.Close()
		log.Printf("acornfox-host-helper started in readonly-peer mode on %s", cfg.SocketPath)
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigChan
		log.Printf("received signal %v, shutting down helper", sig)
		return
	}

	cleanConfig := filepath.Clean(*configPath)
	if !filepath.IsAbs(cleanConfig) {
		log.Fatalf("config path %q must be absolute", *configPath)
	}

	// Strictly open with O_NOFOLLOW to bind descriptor and prevent TOCTOU
	f, err := os.OpenFile(cleanConfig, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		log.Fatalf("open protected config %s failed: %v; helper requires valid protected configuration", cleanConfig, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		log.Fatalf("stat config descriptor %s: %v", cleanConfig, err)
	}
	if !info.Mode().IsRegular() {
		log.Fatalf("config %s must be a regular file", cleanConfig)
	}
	perm := info.Mode().Perm()
	if perm&0022 != 0 {
		log.Fatalf("config %s has insecure write permissions (mode %o); must not be group- or other-writable", cleanConfig, perm)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		log.Fatalf("config %s must be owned strictly by root (0)", cleanConfig)
	}

	// Validate ancestor directories are not symlinks and strictly root-owned
	dir := filepath.Dir(cleanConfig)
	for dir != "/" && dir != "." {
		dInfo, err := os.Lstat(dir)
		if err != nil {
			log.Fatalf("stat ancestor dir %s: %v", dir, err)
		}
		if dInfo.Mode()&os.ModeSymlink != 0 {
			log.Fatalf("ancestor dir %s is a symlink", dir)
		}
		if dInfo.Mode().Perm()&0022 != 0 {
			log.Fatalf("ancestor dir %s has insecure write permissions (mode %o)", dir, dInfo.Mode().Perm())
		}
		dStat, dOk := dInfo.Sys().(*syscall.Stat_t)
		if !dOk || dStat.Uid != 0 {
			log.Fatalf("ancestor dir %s must be owned strictly by root (0)", dir)
		}
		dir = filepath.Dir(dir)
	}

	raw, err := io.ReadAll(f)
	if err != nil {
		log.Fatalf("read config %s: %v", cleanConfig, err)
	}

	var rtCfg runtimeConfig
	if err := json.Unmarshal(raw, &rtCfg); err != nil {
		log.Fatalf("parse config %s: %v", cleanConfig, err)
	}

	if rtCfg.CoreUID == 0 {
		log.Fatalf("core_uid must be configured (> 0) in %s; helper fail-closed", cleanConfig)
	}
	if rtCfg.TrustedCoreExecutableSHA == "" {
		log.Fatalf("trusted_core_executable_sha must be configured in %s; helper fail-closed", cleanConfig)
	}
	if rtCfg.InstallationBinding == "" {
		log.Fatalf("installation_binding must be configured in %s; helper fail-closed", cleanConfig)
	}
	if len(rtCfg.Publishers) == 0 {
		log.Fatalf("at least one trusted publisher must be configured in %s; helper fail-closed", cleanConfig)
	}

	policies := make(map[string]packprotocol.VerificationPolicy, len(rtCfg.Publishers))
	for _, p := range rtCfg.Publishers {
		keyBytes, err := base64.StdEncoding.DecodeString(p.PublicKey)
		if err != nil || len(keyBytes) != ed25519.PublicKeySize {
			log.Fatalf("invalid public key for publisher %q in %s", p.Publisher, cleanConfig)
		}
		policies[p.Publisher] = packprotocol.VerificationPolicy{
			Publisher:           p.Publisher,
			PublicKey:           ed25519.PublicKey(keyBytes),
			AllowedHosts:        p.AllowedHosts,
			CoreVersion:         "1.0.0",
			ProtocolVersion:     "1.0",
			OS:                  "linux",
			Arch:                "amd64",
			InstallationBinding: rtCfg.InstallationBinding,
		}
	}

	cfg := hosthelper.ServerConfig{
		SocketPath:               rtCfg.SocketPath,
		StateDir:                 rtCfg.StateDir,
		StageDir:                 rtCfg.StageDir,
		PacksDir:                 rtCfg.PacksDir,
		PacksStateDir:            rtCfg.PacksStateDir,
		PacksRunDir:              rtCfg.PacksRunDir,
		ServiceTemplatePath:      rtCfg.ServiceTemplatePath,
		TrustedCoreUID:           rtCfg.CoreUID,
		CoreGID:                  rtCfg.CoreGID,
		TrustedCoreExecutableSHA: rtCfg.TrustedCoreExecutableSHA,
		InstallationBinding:      rtCfg.InstallationBinding,
		Policies:                 policies,
		VerifyStagedInventory:    packmanager.ReadAndVerifyStagedInventory,
		RuntimeBindingPath:       strings.TrimSpace(*runtimeBindingPath),
	}

	server, err := hosthelper.NewServer(cfg)
	if err != nil {
		log.Fatalf("initialize helper server: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("start helper server: %v", err)
	}
	defer server.Close()

	log.Printf("acornfox-host-helper started on %s (core_uid=%d)", cfg.SocketPath, cfg.TrustedCoreUID)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan
	log.Printf("received signal %v, shutting down helper", sig)
}
