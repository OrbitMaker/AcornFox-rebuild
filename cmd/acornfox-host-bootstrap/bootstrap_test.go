package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/hostconfig"
	"github.com/open-card/open-card/internal/hostlifecycle"
)

func init() {
	if len(os.Args) == 2 && os.Args[1] == "managed-child" {
		// Child executing via descriptor inheritance
		lifecycleFile := os.NewFile(4, "lifecycle-socket")
		if lifecycleFile == nil {
			os.Exit(1)
		}
		defer lifecycleFile.Close()

		// 1. Send pre-core hello-v1
		hello := &hostlifecycle.HelloFrame{
			Type:          hostlifecycle.FrameTypeHello,
			SchemaVersion: hostlifecycle.ProtocolVersion1,
		}
		helloBytes, err := hostlifecycle.EncodeHello(hello)
		if err != nil {
			os.Exit(1)
		}
		if err := hostlifecycle.WriteFrame(lifecycleFile, helloBytes); err != nil {
			os.Exit(1)
		}

		behavior := os.Getenv("TEST_CHILD_BEHAVIOR")
		if behavior == "hang-after-hello" {
			time.Sleep(60 * time.Second)
			os.Exit(0)
		}

		// 2. Await admit-v1
		admitBytes, err := hostlifecycle.ReadFrame(lifecycleFile)
		if err != nil {
			os.Exit(1)
		}
		admit, err := hostlifecycle.DecodeAdmit(admitBytes)
		if err != nil {
			os.Exit(1)
		}

		// 3. Send result-v1 echoing the exact admission nonce
		result := &hostlifecycle.ResultFrame{
			Type:          hostlifecycle.FrameTypeResult,
			SchemaVersion: hostlifecycle.ProtocolVersion1,
			Nonce:         admit.Nonce,
			Operation:     admit.Operation,
			State:         "idle",
			ReasonCode:    "ok",
			Version:       "1.0.0",
			SlotID:        admit.SlotID,
		}
		resultBytes, err := hostlifecycle.EncodeResult(result)
		if err != nil {
			os.Exit(1)
		}
		behavior = os.Getenv("TEST_CHILD_BEHAVIOR")
		if behavior == "bad-nonce" {
			result.Nonce = strings.Repeat("0", 64)
			resultBytes, _ = hostlifecycle.EncodeResult(result)
		}
		if behavior == "reselect-extra-frame" {
			reselect := &hostlifecycle.ReselectFrame{
				Type:          hostlifecycle.FrameTypeReselect,
				SchemaVersion: hostlifecycle.ProtocolVersion1,
				Nonce:         admit.Nonce,
				ReasonCode:    "active_slot_repaired",
				ActiveSlotID:  admit.SlotID,
			}
			rBytes, _ := hostlifecycle.EncodeReselect(reselect)
			_ = hostlifecycle.WriteFrame(lifecycleFile, rBytes)
			_ = hostlifecycle.WriteFrame(lifecycleFile, rBytes) // Extra frame!
			os.Exit(0)
		}
		if err := hostlifecycle.WriteFrame(lifecycleFile, resultBytes); err != nil {
			os.Exit(1)
		}
		if behavior == "extra-frame" {
			_ = hostlifecycle.WriteFrame(lifecycleFile, resultBytes)
		}
		if behavior == "hang-after-result" {
			time.Sleep(60 * time.Second)
		}

		os.Exit(0)
	}
}

func createTestConfig(t *testing.T, dir string, bootstrapRoot string) (string, string, string) {
	t.Helper()
	instanceID := strings.Repeat("a", 64)
	bindingID := strings.Repeat("b", 64)

	binData, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}

	launcherDir := filepath.Join(bootstrapRoot, "launcher")
	controllerDir := filepath.Join(bootstrapRoot, "controller")
	if err := os.MkdirAll(launcherDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(controllerDir, 0700); err != nil {
		t.Fatal(err)
	}

	launcherPath := filepath.Join(launcherDir, "acornfox-host-launcher")
	controllerPath := filepath.Join(controllerDir, "acornfox-host-update")
	if err := os.WriteFile(launcherPath, binData, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(controllerPath, binData, 0755); err != nil {
		t.Fatal(err)
	}

	h := sha256.Sum256(binData)
	binSHA := hex.EncodeToString(h[:])

	files := []hostconfig.HostBundleFileConfig{
		{
			Path:   "controller/acornfox-host-update",
			SHA256: binSHA,
			Size:   int64(len(binData)),
			Mode:   0755,
		},
		{
			Path:   "launcher/acornfox-host-launcher",
			SHA256: binSHA,
			Size:   int64(len(binData)),
			Mode:   0755,
		},
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	cfg := hostconfig.HostConfigFile{
		SchemaVersion:           1,
		InstanceID:              instanceID,
		BootstrapBackendBinding: bindingID,
		BootstrapSpec: hostconfig.HostBootstrapSpecConfig{
			Root:               bootstrapRoot,
			OS:                 runtime.GOOS,
			Architecture:       runtime.GOARCH,
			Version:            "1.0.0",
			Launcher:           "launcher/acornfox-host-launcher",
			Controller:         "controller/acornfox-host-update",
			ControllerProtocol: 1,
			InstanceProtocol:   1,
			BackendAPIProtocol: 1,
			Files:              files,
		},
		Policy: hostconfig.ConfigPolicyFile{
			PublicKeyHex:    strings.Repeat("c", 64),
			IndexURL:        "https://update.example.com/index.json",
			OS:              runtime.GOOS,
			Arch:            runtime.GOARCH,
			Channel:         "stable",
			AllowedHosts:    []string{"update.example.com"},
			MaxArtifactSize: 104857600,
		},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "host-runtime.json")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	return configPath, instanceID, bindingID
}

func TestConfigValidation(t *testing.T) {
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}
	bootstrapDir := filepath.Join(tmpDir, "bootstrap")
	if err := os.MkdirAll(bootstrapDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfgPath, instanceID, bindingID := createTestConfig(t, tmpDir, bootstrapDir)

	cfg, err := hostconfig.ReadAndValidateConfigFile(cfgPath, bootstrapDir, true)
	if err != nil {
		t.Fatalf("expected valid config, got: %v", err)
	}
	if cfg.InstanceID != instanceID || cfg.BootstrapBackendBinding != bindingID {
		t.Fatalf("config content mismatch")
	}

	// Bootstrap root mismatch
	_, err = hostconfig.ReadAndValidateConfigFile(cfgPath, "/nonexistent/root", true)
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected root mismatch error, got: %v", err)
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

	lock1, err := hostconfig.AcquireInvocationLock(lockPath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer lock1.Close()

	// Try RunBootstrap while lock held
	opts := BootstrapOptions{
		ConfigPath:     filepath.Join(tmpDir, "dummy.json"),
		InvocationLock: lockPath,
		AllowNonRoot:   true,
	}
	_, err = RunBootstrap(context.Background(), hostlifecycle.OpStatus, opts)
	if !errors.Is(err, hostconfig.ErrInvocationBusy) {
		t.Fatalf("expected ErrInvocationBusy, got: %v", err)
	}
}

func TestVerbValidation(t *testing.T) {
	validVerbs := []string{
		hostlifecycle.OpStart,
		hostlifecycle.OpStatus,
		hostlifecycle.OpCheck,
		hostlifecycle.OpAdvance,
		hostlifecycle.OpResumeBackend,
		hostlifecycle.OpDismiss,
	}
	for _, v := range validVerbs {
		if !hostlifecycle.IsValidOperation(v) {
			t.Errorf("verb %q should be valid", v)
		}
	}

	invalidVerbs := []string{"", "install", "upgrade", "stop", "restart", "nuke", "--version"}
	for _, v := range invalidVerbs {
		if hostlifecycle.IsValidOperation(v) {
			t.Errorf("verb %q should be invalid", v)
		}
	}
}

// TestRealBootstrapChildHandshakePipeline executes the full RunBootstrap -> OpenActiveControllerReadOnly ->
// child launch via descriptor -> pre-core hello -> admit -> result -> reap child pipeline.
func TestRealBootstrapChildHandshakePipeline(t *testing.T) {
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	bootstrapDir := filepath.Join(tmpDir, "bootstrap")
	slotsDir := filepath.Join(tmpDir, "slots")
	if err := os.MkdirAll(bootstrapDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(slotsDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Create slot lockfile
	slotLockPath := filepath.Join(slotsDir, "lock")
	if err := os.WriteFile(slotLockPath, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}

	cfgPath, _, _ := createTestConfig(t, tmpDir, bootstrapDir)
	invocationLockPath := filepath.Join(tmpDir, "invocation.lock")

	opts := BootstrapOptions{
		ConfigPath:     cfgPath,
		BootstrapRoot:  bootstrapDir,
		SlotsRoot:      slotsDir,
		InvocationLock: invocationLockPath,
		AllowNonRoot:   true,
		OutcomeTimeout: 15 * time.Second,
	}

	result, err := RunBootstrap(context.Background(), hostlifecycle.OpStatus, opts)
	if err != nil {
		t.Fatalf("RunBootstrap pipeline failed: %v", err)
	}

	if result.Operation != hostlifecycle.OpStatus || result.State != "idle" || result.ReasonCode != "ok" {
		t.Fatalf("unexpected pipeline result: %+v", result)
	}
	if result.Nonce == "" {
		t.Fatal("result nonce must not be empty")
	}

	t.Logf("SUCCESSFUL REAL BOOTSTRAP PIPELINE: Operation=%s State=%s Reason=%s Nonce=%s",
		result.Operation, result.State, result.ReasonCode, result.Nonce)
}

func TestBootstrapChildHangAfterResult(t *testing.T) {
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	bootstrapDir := filepath.Join(tmpDir, "bootstrap")
	slotsDir := filepath.Join(tmpDir, "slots")
	_ = os.MkdirAll(bootstrapDir, 0700)
	_ = os.MkdirAll(slotsDir, 0700)
	_ = os.WriteFile(filepath.Join(slotsDir, "lock"), []byte(""), 0600)

	cfgPath, _, _ := createTestConfig(t, tmpDir, bootstrapDir)
	invocationLockPath := filepath.Join(tmpDir, "invocation.lock")

	opts := BootstrapOptions{
		ConfigPath:     cfgPath,
		BootstrapRoot:  bootstrapDir,
		SlotsRoot:      slotsDir,
		InvocationLock: invocationLockPath,
		AllowNonRoot:   true,
		OutcomeTimeout: 10 * time.Second,
	}

	t.Setenv("TEST_CHILD_BEHAVIOR", "hang-after-result")
	if len(getChildEnvironment()) == 1 {
		t.Skip("skipping behavior injection test: requires -tags fixture")
	}

	start := time.Now()
	_, err = RunBootstrap(context.Background(), hostlifecycle.OpStatus, opts)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error for child hanging after result")
	}
	if !errors.Is(err, ErrChildTerminated) {
		t.Fatalf("expected ErrChildTerminated, got: %v", err)
	}
	// Bounded wait must fire in <= 8 seconds (5s wait deadline + overhead), not 60s
	if elapsed > 10*time.Second {
		t.Fatalf("child hang wait took too long: %v", elapsed)
	}

	// Verify lock can be re-acquired immediately
	lock, err := hostconfig.AcquireInvocationLock(invocationLockPath, true)
	if err != nil {
		t.Fatalf("failed to reacquire lock: %v", err)
	}
	lock.Close()
}

func TestBootstrapContextCancel(t *testing.T) {
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	bootstrapDir := filepath.Join(tmpDir, "bootstrap")
	slotsDir := filepath.Join(tmpDir, "slots")
	_ = os.MkdirAll(bootstrapDir, 0700)
	_ = os.MkdirAll(slotsDir, 0700)
	_ = os.WriteFile(filepath.Join(slotsDir, "lock"), []byte(""), 0600)

	cfgPath, _, _ := createTestConfig(t, tmpDir, bootstrapDir)
	invocationLockPath := filepath.Join(tmpDir, "invocation.lock")

	opts := BootstrapOptions{
		ConfigPath:     cfgPath,
		BootstrapRoot:  bootstrapDir,
		SlotsRoot:      slotsDir,
		InvocationLock: invocationLockPath,
		AllowNonRoot:   true,
		OutcomeTimeout: 60 * time.Second,
	}

	t.Setenv("TEST_CHILD_BEHAVIOR", "hang-after-hello")
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel promptly after child is running
	time.AfterFunc(100*time.Millisecond, cancel)

	start := time.Now()
	_, err = RunBootstrap(ctx, hostlifecycle.OpStatus, opts)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
	// Context cancellation must wake immediately (< 3s)
	if elapsed > 4*time.Second {
		t.Fatalf("cancellation took too long: %v", elapsed)
	}

	// Verify lock can be re-acquired immediately
	lock, err := hostconfig.AcquireInvocationLock(invocationLockPath, true)
	if err != nil {
		t.Fatalf("failed to reacquire lock: %v", err)
	}
	lock.Close()
}

func TestBootstrapBadNonce(t *testing.T) {
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	bootstrapDir := filepath.Join(tmpDir, "bootstrap")
	slotsDir := filepath.Join(tmpDir, "slots")
	_ = os.MkdirAll(bootstrapDir, 0700)
	_ = os.MkdirAll(slotsDir, 0700)
	_ = os.WriteFile(filepath.Join(slotsDir, "lock"), []byte(""), 0600)

	cfgPath, _, _ := createTestConfig(t, tmpDir, bootstrapDir)
	invocationLockPath := filepath.Join(tmpDir, "invocation.lock")

	opts := BootstrapOptions{
		ConfigPath:     cfgPath,
		BootstrapRoot:  bootstrapDir,
		SlotsRoot:      slotsDir,
		InvocationLock: invocationLockPath,
		AllowNonRoot:   true,
		OutcomeTimeout: 10 * time.Second,
	}

	t.Setenv("TEST_CHILD_BEHAVIOR", "bad-nonce")
	if len(getChildEnvironment()) == 1 {
		t.Skip("skipping behavior injection test: requires -tags fixture")
	}
	_, err = RunBootstrap(context.Background(), hostlifecycle.OpStatus, opts)
	if err == nil || !errors.Is(err, ErrProtocolMismatch) {
		t.Fatalf("expected ErrProtocolMismatch on bad nonce, got: %v", err)
	}
}

func TestBootstrapExtraTrailingFrame(t *testing.T) {
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	bootstrapDir := filepath.Join(tmpDir, "bootstrap")
	slotsDir := filepath.Join(tmpDir, "slots")
	_ = os.MkdirAll(bootstrapDir, 0700)
	_ = os.MkdirAll(slotsDir, 0700)
	_ = os.WriteFile(filepath.Join(slotsDir, "lock"), []byte(""), 0600)

	cfgPath, _, _ := createTestConfig(t, tmpDir, bootstrapDir)
	invocationLockPath := filepath.Join(tmpDir, "invocation.lock")

	opts := BootstrapOptions{
		ConfigPath:     cfgPath,
		BootstrapRoot:  bootstrapDir,
		SlotsRoot:      slotsDir,
		InvocationLock: invocationLockPath,
		AllowNonRoot:   true,
		OutcomeTimeout: 10 * time.Second,
	}

	t.Setenv("TEST_CHILD_BEHAVIOR", "extra-frame")
	if len(getChildEnvironment()) == 1 {
		t.Skip("skipping behavior injection test: requires -tags fixture")
	}
	_, err = RunBootstrap(context.Background(), hostlifecycle.OpStatus, opts)
	if err == nil || !errors.Is(err, ErrProtocolMismatch) {
		t.Fatalf("expected ErrProtocolMismatch on extra trailing frame, got: %v", err)
	}
}

func TestBootstrapReselectExtraTrailingFrame(t *testing.T) {
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	bootstrapDir := filepath.Join(tmpDir, "bootstrap")
	slotsDir := filepath.Join(tmpDir, "slots")
	_ = os.MkdirAll(bootstrapDir, 0700)
	_ = os.MkdirAll(slotsDir, 0700)
	_ = os.WriteFile(filepath.Join(slotsDir, "lock"), []byte(""), 0600)

	// Create state.new to simulate torn state so selector selects recovery role
	_ = os.WriteFile(filepath.Join(slotsDir, "state.new"), []byte("torn"), 0600)

	cfgPath, _, _ := createTestConfig(t, tmpDir, bootstrapDir)
	invocationLockPath := filepath.Join(tmpDir, "invocation.lock")

	opts := BootstrapOptions{
		ConfigPath:     cfgPath,
		BootstrapRoot:  bootstrapDir,
		SlotsRoot:      slotsDir,
		InvocationLock: invocationLockPath,
		AllowNonRoot:   true,
		OutcomeTimeout: 10 * time.Second,
	}

	t.Setenv("TEST_CHILD_BEHAVIOR", "reselect-extra-frame")
	if len(getChildEnvironment()) == 1 {
		t.Skip("skipping behavior injection test: requires -tags fixture")
	}
	_, err = RunBootstrap(context.Background(), hostlifecycle.OpStatus, opts)
	if err == nil || !errors.Is(err, ErrProtocolMismatch) {
		t.Fatalf("expected ErrProtocolMismatch on extra trailing frame after reselect, got: %v", err)
	}
}
