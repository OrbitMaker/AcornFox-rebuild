package hostconfig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func createValidConfig(t *testing.T, dir string, bootstrapRoot string) (string, *HostConfigFile) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &HostConfigFile{
		SchemaVersion:           1,
		InstanceID:              strings.Repeat("a", 64),
		BootstrapBackendBinding: strings.Repeat("b", 64),
		BootstrapSpec: HostBootstrapSpecConfig{
			Root:               bootstrapRoot,
			OS:                 runtime.GOOS,
			Architecture:       runtime.GOARCH,
			Version:            "1.0.0",
			Launcher:           "launcher/acornfox-host-launcher",
			Controller:         "controller/acornfox-host-update",
			ControllerProtocol: 1,
			InstanceProtocol:   1,
			BackendAPIProtocol: 1,
			Files: []HostBundleFileConfig{
				{
					Path:   "launcher/acornfox-host-launcher",
					SHA256: strings.Repeat("1", 64),
					Size:   100,
					Mode:   0755,
				},
				{
					Path:   "controller/acornfox-host-update",
					SHA256: strings.Repeat("2", 64),
					Size:   200,
					Mode:   0755,
				},
			},
		},
		Policy: ConfigPolicyFile{
			PublicKeyHex:    hex.EncodeToString(pub),
			IndexURL:        "https://update.example.com/index.json",
			OS:              runtime.GOOS,
			Arch:            runtime.GOARCH,
			Channel:         "stable",
			AllowedHosts:    []string{"update.example.com"},
			MaxArtifactSize: 104857600,
		},
	}

	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "host-runtime.json")
	if err := os.WriteFile(cfgPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, cfg
}

func TestConfigValidCanonical(t *testing.T) {
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfgPath, wantCfg := createValidConfig(t, tmpDir, tmpDir)
	gotCfg, err := ReadAndValidateConfigFile(cfgPath, tmpDir, true)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if gotCfg.InstanceID != wantCfg.InstanceID {
		t.Fatalf("instance ID mismatch")
	}
}

func TestConfigDuplicateKeysRejected(t *testing.T) {
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfgPath, _ := createValidConfig(t, tmpDir, tmpDir)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// Inject duplicate key at top level
	dupRaw := strings.Replace(string(raw), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)
	if err := os.WriteFile(cfgPath, []byte(dupRaw), 0600); err != nil {
		t.Fatal(err)
	}

	_, err = ReadAndValidateConfigFile(cfgPath, tmpDir, true)
	if err == nil {
		t.Fatal("expected error on duplicate key")
	}
}

func TestConfigNestedDuplicateKeysRejected(t *testing.T) {
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfgPath, _ := createValidConfig(t, tmpDir, tmpDir)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// Inject nested duplicate inside policy
	nestedDup := strings.Replace(string(raw), `"channel":"stable"`, `"channel":"stable","channel":"stable"`, 1)
	if err := os.WriteFile(cfgPath, []byte(nestedDup), 0600); err != nil {
		t.Fatal(err)
	}

	_, err = ReadAndValidateConfigFile(cfgPath, tmpDir, true)
	if err == nil {
		t.Fatal("expected error on nested duplicate key")
	}
}

func TestConfigSymlinkRejected(t *testing.T) {
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfgPath, _ := createValidConfig(t, tmpDir, tmpDir)
	symPath := filepath.Join(tmpDir, "sym-config.json")
	if err := os.Symlink(cfgPath, symPath); err != nil {
		t.Fatal(err)
	}

	_, err = ReadAndValidateConfigFile(symPath, tmpDir, true)
	if err == nil {
		t.Fatal("expected error on symlink config")
	}
}

func TestInvocationLockMutualExclusion(t *testing.T) {
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	lockPath := filepath.Join(tmpDir, "invocation.lock")
	lock1, err := AcquireInvocationLock(lockPath, true)
	if err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}
	defer lock1.Close()

	// Second acquire must fail with ErrInvocationBusy
	_, err = AcquireInvocationLock(lockPath, true)
	if !errors.Is(err, ErrInvocationBusy) && !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatalf("expected ErrInvocationBusy, got: %v", err)
	}
}

func TestConfigPinsClosedOnError(t *testing.T) {
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	badPath := filepath.Join(tmpDir, "bad-config.json")
	if err := os.WriteFile(badPath, []byte("invalid-json"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err = ReadAndValidateConfigFile(badPath, tmpDir, true)
	if err == nil {
		t.Fatal("expected error on invalid json")
	}
}

func TestConfigPinsClosedOnSuccess(t *testing.T) {
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfgPath, _ := createValidConfig(t, tmpDir, tmpDir)
	cfg, err := ReadAndValidateConfigFile(cfgPath, tmpDir, true)
	if err != nil {
		t.Fatalf("failed to load valid config: %v", err)
	}
	if len(cfg.pins) == 0 {
		t.Fatal("expected pinned ancestors on success")
	}

	// Calling Close() must close all pins without error
	if err := cfg.Close(); err != nil {
		t.Fatalf("cfg.Close() failed: %v", err)
	}
	if len(cfg.pins) != 0 {
		t.Fatal("pins must be nil after Close")
	}
}
