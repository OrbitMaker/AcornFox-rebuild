package hostprovision

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/open-card/open-card/internal/desktopupdate"
	"github.com/open-card/open-card/internal/hostconfig"
)

var (
	testBinaryBytes []byte
	testBinaryOnce  sync.Once
)

func getTestExecutableBytes(t *testing.T) []byte {
	t.Helper()
	testBinaryOnce.Do(func() {
		if self, err := os.Executable(); err == nil {
			realPath, err := filepath.EvalSymlinks(self)
			if err == nil {
				if raw, err := os.ReadFile(realPath); err == nil && len(raw) > 0 {
					testBinaryBytes = raw
					return
				}
			}
		}

		tmpDir, err := os.MkdirTemp("", "acornfox-test-bin-")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		binPath := filepath.Join(tmpDir, "helper")
		srcPath := filepath.Join(tmpDir, "main.go")
		if err := os.WriteFile(srcPath, []byte("package main\nfunc main() {}\n"), 0600); err != nil {
			t.Fatalf("failed to write source: %v", err)
		}
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", binPath, srcPath)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("failed to build test helper: %v: %s", err, string(out))
		}
		raw, err := os.ReadFile(binPath)
		if err != nil {
			t.Fatalf("failed to read built helper: %v", err)
		}
		testBinaryBytes = raw
	})

	if len(testBinaryBytes) == 0 {
		t.Fatal("empty test binary bytes")
	}
	return testBinaryBytes
}

func createTestPolicyFile(t *testing.T, dir, hostOS, arch string) (string, []byte, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	policy := hostconfig.ConfigPolicyFile{
		PublicKeyHex:    hex.EncodeToString(pub),
		IndexURL:        "https://updates.acornfox.test/index.json",
		OS:              hostOS,
		Arch:            arch,
		Channel:         "stable",
		AllowedHosts:    []string{"updates.acornfox.test"},
		MaxArtifactSize: 100 << 20,
	}

	// Strictly canonical JSON bytes (json.Marshal without trailing newline)
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("failed to marshal policy: %v", err)
	}

	p := filepath.Join(dir, "host-update-policy.json")
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}
	return p, raw, sha256Hex(raw)
}

func createTestInstanceFile(t *testing.T, targetPath, version string) (string, string) {
	t.Helper()
	var randBytes [32]byte
	_, _ = io.ReadFull(rand.Reader, randBytes[:])
	nativeID := hex.EncodeToString(randBytes[:])
	instanceID := sha256Hex([]byte("linux-local:" + nativeID))
	markerSHA := sha256Hex([]byte(fmt.Sprintf(`{"product":"acornfox","instance":"%s"}`, nativeID)))

	inst := guestInstanceFile{
		SchemaVersion:        1,
		Kind:                 "linux-local",
		NativeID:             nativeID,
		InstanceID:           instanceID,
		MarkerSHA256:         markerSHA,
		BootstrapHostVersion: version,
	}

	raw, err := json.Marshal(inst)
	if err != nil {
		t.Fatalf("failed to marshal instance: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		t.Fatalf("failed to mkdir for instance: %v", err)
	}
	if err := os.WriteFile(targetPath, raw, 0600); err != nil {
		t.Fatalf("failed to write instance: %v", err)
	}
	return targetPath, instanceID
}

func createMockGuestTransport(
	expectedInstanceID string,
	expectedBinding string,
	mutateObs func(*desktopupdate.BackendObservation),
) desktopupdate.GuestTransport {
	return func(ctx context.Context, cmd desktopupdate.GuestCommand, stdin io.Reader, stdout io.Writer) (int, error) {
		if ctx != nil && ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if cmd.Arguments()[0] != "observe" {
			return 1, fmt.Errorf("unexpected command %v", cmd)
		}

		obs := desktopupdate.BackendObservation{
			LocalLoopback:    true,
			MigrationVersion: "0040",
			Architecture:     runtime.GOARCH,
			InstanceID:       expectedInstanceID,
			Binding:          expectedBinding,
			Ready:            true,
			Finalized:        true,
			AttemptState:     "absent",
		}
		if mutateObs != nil {
			mutateObs(&obs)
		}

		resRaw, err := json.Marshal(obs)
		if err != nil {
			return 1, err
		}

		reply := struct {
			OK     bool            `json:"ok"`
			Code   string          `json:"code"`
			Result json.RawMessage `json:"result,omitempty"`
		}{
			OK:     true,
			Code:   "ok",
			Result: resRaw,
		}

		outBytes, err := json.Marshal(reply)
		if err != nil {
			return 1, err
		}
		_, err = stdout.Write(outBytes)
		return 0, err
	}
}

func setupIsolatedTestEnv(t *testing.T) (string, ProvisionPaths, string, string) {
	t.Helper()
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("failed to resolve tempdir: %v", err)
	}
	if err := os.Chmod(tmpDir, 0755); err != nil {
		t.Fatalf("failed to chmod tempdir: %v", err)
	}

	stagingDir := filepath.Join(tmpDir, "staging")
	targetDir := filepath.Join(tmpDir, "target")
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		t.Fatal(err)
	}

	paths := ProvisionPaths{
		BootstrapExecutable: filepath.Join(targetDir, "libexec", "acornfox-host-bootstrap"),
		BootstrapRoot:       filepath.Join(targetDir, "bootstrap"),
		LauncherPath:        filepath.Join(targetDir, "bootstrap", "launcher", "acornfox-host-launcher"),
		ControllerPath:      filepath.Join(targetDir, "bootstrap", "controller", "acornfox-host-update"),
		ConfigPath:          filepath.Join(targetDir, "host-runtime.json"),
		GuestInstancePath:   filepath.Join(targetDir, "guest-instance.json"),
		SlotsRoot:           filepath.Join(targetDir, "slots"),
		SlotsLock:           filepath.Join(targetDir, "slots", "lock"),
		ControllerRoot:      filepath.Join(targetDir, "controller"),
	}

	return tmpDir, paths, stagingDir, targetDir
}

func setupValidSources(t *testing.T, stagingDir, guestInstPath, version, binding string) (ProvisionRequest, string) {
	t.Helper()
	binBytes := getTestExecutableBytes(t)
	binSHA := sha256Hex(binBytes)

	stablePath := filepath.Join(stagingDir, "acornfox-host-bootstrap")
	if err := os.WriteFile(stablePath, binBytes, 0755); err != nil {
		t.Fatal(err)
	}

	c0Path := filepath.Join(stagingDir, "acornfox-host-update")
	if err := os.WriteFile(c0Path, binBytes, 0755); err != nil {
		t.Fatal(err)
	}

	polTargetOS := "linux"
	if runtime.GOOS != "linux" {
		polTargetOS = runtime.GOOS
	}
	polPath, _, polSHA := createTestPolicyFile(t, stagingDir, polTargetOS, runtime.GOARCH)

	_, instanceID := createTestInstanceFile(t, guestInstPath, version)

	req := ProvisionRequest{
		BootstrapVersion:        version,
		BootstrapBackendBinding: binding,
		StableBootstrapSource:   stablePath,
		ExpectedBootstrapSHA256: binSHA,
		ManagedC0Source:         c0Path,
		ExpectedC0SHA256:        binSHA,
		PolicySourcePath:        polPath,
		ExpectedPolicySHA256:    polSHA,
	}
	return req, instanceID
}

// 1. TestProvisionProductionAPIIsFixedAndRootOnly: proves production Provision(ctx, req) has
// no test bypass options parameter and enforces root privileges.
func TestProvisionProductionAPIIsFixedAndRootOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipping non-root check when running as root")
	}

	req := ProvisionRequest{
		BootstrapVersion:        "1.0.0",
		BootstrapBackendBinding: strings.Repeat("a", 64),
		StableBootstrapSource:   "/tmp/bootstrap",
		ExpectedBootstrapSHA256: strings.Repeat("b", 64),
		ManagedC0Source:         "/tmp/c0",
		ExpectedC0SHA256:        strings.Repeat("c", 64),
		PolicySourcePath:        "/tmp/policy",
		ExpectedPolicySHA256:    strings.Repeat("d", 64),
	}

	// Production entry signature accepts ONLY (ctx, req)
	_, err := Provision(context.Background(), req)
	if !errors.Is(err, ErrPrivilegeRequired) {
		t.Fatalf("expected ErrPrivilegeRequired for non-root caller of production API, got: %v", err)
	}
}

// 2. TestProvisionFreshSuccess: validates clean fresh provisioning with exact permission invariants.
func TestProvisionFreshSuccess(t *testing.T) {
	_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
	version := "1.0.0"
	binding := strings.Repeat("b", 64)

	req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, version, binding)
	opts := provisionOptions{
		allowNonRoot:   true,
		paths:          paths,
		guestTransport: createMockGuestTransport(instanceID, binding, nil),
	}

	receipt, err := provisionWithOptions(context.Background(), req, opts)
	if err != nil {
		t.Fatalf("provisionWithOptions failed: %v", err)
	}

	if receipt.InstanceID != instanceID {
		t.Errorf("receipt instance ID mismatch: got %q, want %q", receipt.InstanceID, instanceID)
	}
	if receipt.BootstrapVersion != version {
		t.Errorf("receipt version mismatch: got %q, want %q", receipt.BootstrapVersion, version)
	}
	if receipt.BootstrapBackendBinding != binding {
		t.Errorf("receipt binding mismatch: got %q, want %q", receipt.BootstrapBackendBinding, binding)
	}
	if receipt.StableBootstrapSHA256 != req.ExpectedBootstrapSHA256 {
		t.Errorf("receipt stable bootstrap SHA mismatch")
	}
	if receipt.LauncherSHA256 != req.ExpectedC0SHA256 || receipt.ControllerSHA256 != req.ExpectedC0SHA256 {
		t.Errorf("receipt C0 SHA mismatch")
	}
	if receipt.BootstrapID == "" {
		t.Errorf("receipt bootstrap ID should not be empty")
	}

	// Verify exact file permissions and regular status
	for _, p := range []string{paths.BootstrapExecutable, paths.LauncherPath, paths.ControllerPath} {
		info, err := os.Lstat(p)
		if err != nil {
			t.Fatalf("expected file %q to exist: %v", p, err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0755 {
			t.Errorf("file %q unexpected mode %o", p, info.Mode().Perm())
		}
	}

	// Distinct inodes check
	st1, _ := os.Lstat(paths.LauncherPath)
	st2, _ := os.Lstat(paths.ControllerPath)
	sys1 := st1.Sys().(*syscall.Stat_t)
	sys2 := st2.Sys().(*syscall.Stat_t)
	if sys1.Dev == sys2.Dev && sys1.Ino == sys2.Ino {
		t.Fatalf("launcher and controller must have distinct inodes")
	}

	// Verify exact directory permissions
	for _, d := range []string{paths.BootstrapRoot, filepath.Dir(paths.LauncherPath), filepath.Dir(paths.ControllerPath)} {
		info, err := os.Lstat(d)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0755 {
			t.Errorf("bootstrap dir %q mode mismatch: %o", d, info.Mode().Perm())
		}
	}
	for _, d := range []string{paths.SlotsRoot, paths.ControllerRoot} {
		info, err := os.Lstat(d)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Errorf("state root %q mode mismatch: %o", d, info.Mode().Perm())
		}
	}

	// Lockfile exists, mode 0600
	lockInfo, err := os.Lstat(paths.SlotsLock)
	if err != nil || !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0600 {
		t.Errorf("slots lock invalid: %v, info: %+v", err, lockInfo)
	}

	// Config exists, mode 0600
	cfgInfo, err := os.Lstat(paths.ConfigPath)
	if err != nil || !cfgInfo.Mode().IsRegular() || cfgInfo.Mode().Perm() != 0600 {
		t.Errorf("config invalid: %v, info: %+v", err, cfgInfo)
	}

	// Read and validate using production loaders
	cfg, err := hostconfig.ReadAndValidateConfigFile(paths.ConfigPath, paths.BootstrapRoot, true)
	if err != nil {
		t.Fatalf("ReadAndValidateConfigFile failed: %v", err)
	}
	defer cfg.Close()

	pinned, err := desktopupdate.PinHostBootstrap(context.Background(), convertBootstrapSpec(cfg.BootstrapSpec))
	if err != nil {
		t.Fatalf("PinHostBootstrap failed: %v", err)
	}
	defer pinned.Close()

	if pinned.ID() != receipt.BootstrapID {
		t.Errorf("pinned ID mismatch: got %q, want %q", pinned.ID(), receipt.BootstrapID)
	}
}

// 3. TestProvisionExactReentry: re-running with identical inputs returns same receipt and does not clobber.
func TestProvisionExactReentry(t *testing.T) {
	_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
	version := "1.0.0"
	binding := strings.Repeat("c", 64)

	req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, version, binding)
	opts := provisionOptions{
		allowNonRoot:   true,
		paths:          paths,
		guestTransport: createMockGuestTransport(instanceID, binding, nil),
	}

	receipt1, err := provisionWithOptions(context.Background(), req, opts)
	if err != nil {
		t.Fatalf("first provisionWithOptions failed: %v", err)
	}

	// Second run (exact reentry)
	receipt2, err := provisionWithOptions(context.Background(), req, opts)
	if err != nil {
		t.Fatalf("reentry provisionWithOptions failed: %v", err)
	}

	if receipt1.BootstrapID != receipt2.BootstrapID {
		t.Errorf("reentry bootstrap ID mismatch: %q vs %q", receipt1.BootstrapID, receipt2.BootstrapID)
	}
	if receipt1.ConfigSHA256 != receipt2.ConfigSHA256 {
		t.Errorf("reentry config SHA mismatch: %q vs %q", receipt1.ConfigSHA256, receipt2.ConfigSHA256)
	}
	if receipt1.PolicySHA256 != receipt2.PolicySHA256 {
		t.Errorf("reentry policy SHA mismatch: %q vs %q", receipt1.PolicySHA256, receipt2.PolicySHA256)
	}
}

// 4. TestProvisionInterruptionResume: resumes from partial outputs when config is absent.
func TestProvisionInterruptionResume(t *testing.T) {
	_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
	version := "1.0.0"
	binding := strings.Repeat("d", 64)

	req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, version, binding)

	injectedErr := errors.New("simulated crash before publish")
	optsWithFault := provisionOptions{
		allowNonRoot:      true,
		paths:             paths,
		guestTransport:    createMockGuestTransport(instanceID, binding, nil),
		beforePublishHook: func() error { return injectedErr },
	}

	_, err := provisionWithOptions(context.Background(), req, optsWithFault)
	if !errors.Is(err, injectedErr) {
		t.Fatalf("expected injected error, got: %v", err)
	}

	// Verify host-runtime.json does NOT exist yet (policy-last invariant)
	if _, err := os.Lstat(paths.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("host-runtime.json should not exist after interrupted run")
	}

	// Resume run without fault: must succeed
	optsResume := provisionOptions{
		allowNonRoot:   true,
		paths:          paths,
		guestTransport: createMockGuestTransport(instanceID, binding, nil),
	}

	receipt, err := provisionWithOptions(context.Background(), req, optsResume)
	if err != nil {
		t.Fatalf("resumed provisionWithOptions failed: %v", err)
	}
	if receipt.InstanceID != instanceID {
		t.Errorf("instance ID mismatch on resume")
	}

	cfg, err := hostconfig.ReadAndValidateConfigFile(paths.ConfigPath, paths.BootstrapRoot, true)
	if err != nil {
		t.Fatalf("config readback failed after resume: %v", err)
	}
	defer cfg.Close()
}

// 5. TestProvisionMismatchNoMutation: asserts failure on input mismatches without mutating existing state.
func TestProvisionMismatchNoMutation(t *testing.T) {
	_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
	version := "1.0.0"
	binding := strings.Repeat("e", 64)

	req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, version, binding)
	opts := provisionOptions{
		allowNonRoot:   true,
		paths:          paths,
		guestTransport: createMockGuestTransport(instanceID, binding, nil),
	}

	receipt, err := provisionWithOptions(context.Background(), req, opts)
	if err != nil {
		t.Fatalf("initial provisionWithOptions failed: %v", err)
	}

	origConfigRaw, _ := os.ReadFile(paths.ConfigPath)

	t.Run("BindingMismatch", func(t *testing.T) {
		badReq := req
		badReq.BootstrapBackendBinding = strings.Repeat("f", 64)
		_, err := provisionWithOptions(context.Background(), badReq, opts)
		if !errors.Is(err, ErrProvisionConflict) {
			t.Fatalf("expected ErrProvisionConflict, got %v", err)
		}
		afterRaw, _ := os.ReadFile(paths.ConfigPath)
		if !bytes.Equal(origConfigRaw, afterRaw) {
			t.Errorf("config was mutated on binding mismatch")
		}
	})

	t.Run("VersionMismatch", func(t *testing.T) {
		badReq := req
		badReq.BootstrapVersion = "1.0.1"
		_, err := provisionWithOptions(context.Background(), badReq, opts)
		if !errors.Is(err, ErrProvisionConflict) {
			t.Fatalf("expected ErrProvisionConflict, got %v", err)
		}
		afterRaw, _ := os.ReadFile(paths.ConfigPath)
		if !bytes.Equal(origConfigRaw, afterRaw) {
			t.Errorf("config was mutated on version mismatch")
		}
	})

	t.Run("C0HashMismatch", func(t *testing.T) {
		badReq := req
		badReq.ExpectedC0SHA256 = strings.Repeat("1", 64)
		_, err := provisionWithOptions(context.Background(), badReq, opts)
		if !errors.Is(err, ErrInvalidRequest) && !errors.Is(err, ErrProvisionConflict) {
			t.Fatalf("expected error on C0 mismatch, got %v", err)
		}
		afterRaw, _ := os.ReadFile(paths.ConfigPath)
		if !bytes.Equal(origConfigRaw, afterRaw) {
			t.Errorf("config was mutated on C0 mismatch")
		}
	})

	cfg, err := hostconfig.ReadAndValidateConfigFile(paths.ConfigPath, paths.BootstrapRoot, true)
	if err != nil {
		t.Fatalf("original config corrupted: %v", err)
	}
	defer cfg.Close()
	if cfg.BootstrapSpec.Version != receipt.BootstrapVersion {
		t.Errorf("version changed")
	}
}

// 6. TestProvisionConfigAbsentForeignOrTorn: fails closed when config is absent and unmanaged files exist,
// proving zero mutations (no slots/lock created).
func TestProvisionConfigAbsentForeignOrTorn(t *testing.T) {
	t.Run("NonEmptyControllerRootZeroMutation", func(t *testing.T) {
		_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
		req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("1", 64))

		// Pre-create controller root with state.json (torn unmanaged state)
		_ = os.MkdirAll(paths.ControllerRoot, 0700)
		_ = os.WriteFile(filepath.Join(paths.ControllerRoot, "state.json"), []byte(`{"schema_version":1}`), 0600)

		opts := provisionOptions{
			allowNonRoot:   true,
			paths:          paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
		}

		_, err := provisionWithOptions(context.Background(), req, opts)
		if !errors.Is(err, ErrProvisionConflict) {
			t.Fatalf("expected ErrProvisionConflict for non-empty controller root, got %v", err)
		}

		// Verify zero mutations: slots root and slots lock must NOT have been created!
		if _, err := os.Lstat(paths.SlotsLock); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("slots lock should not be created when controller is foreign")
		}
		if _, err := os.Lstat(paths.SlotsRoot); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("slots root should not be created when controller is foreign")
		}
	})

	t.Run("UnexpectedFilesInSlotsRootZeroMutation", func(t *testing.T) {
		_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
		req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("1", 64))

		_ = os.MkdirAll(paths.SlotsRoot, 0700)
		_ = os.WriteFile(filepath.Join(paths.SlotsRoot, "ledger.json"), []byte(`{}`), 0600)

		opts := provisionOptions{
			allowNonRoot:   true,
			paths:          paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
		}

		_, err := provisionWithOptions(context.Background(), req, opts)
		if !errors.Is(err, ErrProvisionConflict) {
			t.Fatalf("expected ErrProvisionConflict for unexpected files in slots root, got %v", err)
		}

		// Verify zero mutations: slots lock was NOT created
		if _, err := os.Lstat(paths.SlotsLock); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("slots lock should not be created when slots contains foreign file")
		}
	})
}

// 7. TestProvisionConfigPresentMissingDependenciesNoRepair: when host-runtime.json exists but
// dependencies are missing, provision must fail closed without repairing or creating missing dependencies.
func TestProvisionConfigPresentMissingDependenciesNoRepair(t *testing.T) {
	t.Run("MissingSlotsLockNoRepair", func(t *testing.T) {
		_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
		req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("2", 64))

		opts := provisionOptions{
			allowNonRoot:   true,
			paths:          paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
		}

		// First, do a complete provision
		_, err := provisionWithOptions(context.Background(), req, opts)
		if err != nil {
			t.Fatalf("setup provision failed: %v", err)
		}

		// Delete slots lockfile to create a torn dependency state
		_ = os.Remove(paths.SlotsLock)

		// Call provision again: must fail closed without re-creating slots lock
		_, err = provisionWithOptions(context.Background(), req, opts)
		if !errors.Is(err, ErrProvisionConflict) {
			t.Fatalf("expected ErrProvisionConflict on missing dependency during reentry, got %v", err)
		}

		// Verify slots lock was NOT repaired/created
		if _, err := os.Lstat(paths.SlotsLock); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("slots lock must not be repaired during reentry")
		}
	})

	t.Run("MissingSlotsRootNoRepair", func(t *testing.T) {
		_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
		req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("3", 64))

		opts := provisionOptions{
			allowNonRoot:   true,
			paths:          paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
		}

		_, err := provisionWithOptions(context.Background(), req, opts)
		if err != nil {
			t.Fatalf("setup provision failed: %v", err)
		}

		// Delete entire slots root
		_ = os.RemoveAll(paths.SlotsRoot)

		_, err = provisionWithOptions(context.Background(), req, opts)
		if !errors.Is(err, ErrProvisionConflict) {
			t.Fatalf("expected ErrProvisionConflict on missing slots root during reentry, got %v", err)
		}

		// Verify slots root was NOT repaired/created
		if _, err := os.Lstat(paths.SlotsRoot); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("slots root must not be repaired during reentry")
		}
	})
}

// 8. TestProvisionActiveAncestorReplacementTOCTOU: asserts that replacing an ancestor directory
// after open/check before write causes immediate failure without foreign write.
func TestProvisionActiveAncestorReplacementTOCTOU(t *testing.T) {
	t.Run("ReplaceParentAfterCheckBeforeWrite", func(t *testing.T) {
		tmpDir, paths, stagingDir, _ := setupIsolatedTestEnv(t)
		req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("4", 64))

		foreignDir := filepath.Join(tmpDir, "foreign-directory")
		_ = os.MkdirAll(foreignDir, 0755)

		// Injected hook: when about to write launcher, swap launcher's parent directory with foreignDir
		var hookTriggered bool
		opts := provisionOptions{
			allowNonRoot:   true,
			paths:          paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
			ancestorHook: func(phase string, targetPath string) error {
				if phase == "after-check-before-write" && targetPath == paths.LauncherPath {
					hookTriggered = true
					// Replace launcher directory with a symlink to foreignDir
					origDir := filepath.Dir(paths.LauncherPath)
					backupDir := origDir + ".bak"
					if err := os.Rename(origDir, backupDir); err != nil {
						return err
					}
					if err := os.Symlink(foreignDir, origDir); err != nil {
						return err
					}
				}
				return nil
			},
		}

		_, err := provisionWithOptions(context.Background(), req, opts)
		if err == nil {
			t.Fatal("expected failure on active ancestor replacement")
		}
		if !hookTriggered {
			t.Fatal("expected hook to trigger")
		}

		// Assert zero foreign writes: foreignDir must be completely empty!
		entries, err := os.ReadDir(foreignDir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) > 0 {
			t.Fatalf("foreign directory was written to: %v", entries)
		}

		// host-runtime.json must not exist
		if _, err := os.Lstat(paths.ConfigPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("host-runtime.json should not exist after ancestor replacement failure")
		}
	})

	t.Run("ReplaceParentBeforeLink", func(t *testing.T) {
		tmpDir, paths, stagingDir, _ := setupIsolatedTestEnv(t)
		req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("5", 64))

		foreignDir := filepath.Join(tmpDir, "foreign-before-link")
		_ = os.MkdirAll(foreignDir, 0755)

		var hookTriggered bool
		opts := provisionOptions{
			allowNonRoot:   true,
			paths:          paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
			ancestorHook: func(phase string, targetPath string) error {
				if phase == "before-link" && targetPath == paths.LauncherPath {
					hookTriggered = true
					origDir := filepath.Dir(paths.LauncherPath)
					backupDir := origDir + ".bak"
					if err := os.Rename(origDir, backupDir); err != nil {
						return err
					}
					if err := os.Symlink(foreignDir, origDir); err != nil {
						return err
					}
				}
				return nil
			},
		}

		_, err := provisionWithOptions(context.Background(), req, opts)
		if err == nil {
			t.Fatal("expected failure on active ancestor replacement before link")
		}
		if !hookTriggered {
			t.Fatal("expected before-link hook to trigger")
		}

		entries, err := os.ReadDir(foreignDir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) > 0 {
			t.Fatalf("foreign directory was written to: %v", entries)
		}
	})

	t.Run("ReplaceParentAfterLockReturn", func(t *testing.T) {
		tmpDir, paths, stagingDir, _ := setupIsolatedTestEnv(t)
		req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("5", 64))

		foreignDir := filepath.Join(tmpDir, "foreign-slots")
		_ = os.MkdirAll(foreignDir, 0700)

		var hookTriggered bool
		opts := provisionOptions{
			allowNonRoot:   true,
			paths:          paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
			ancestorHook: func(phase string, targetPath string) error {
				if phase == "after-lock-return" && targetPath == paths.SlotsLock {
					hookTriggered = true
					// Swap slots directory with foreignDir
					backupDir := paths.SlotsRoot + ".bak"
					if err := os.Rename(paths.SlotsRoot, backupDir); err != nil {
						return err
					}
					if err := os.Symlink(foreignDir, paths.SlotsRoot); err != nil {
						return err
					}
				}
				return nil
			},
		}

		_, err := provisionWithOptions(context.Background(), req, opts)
		if err == nil {
			t.Fatal("expected failure on active slots ancestor replacement after lock return")
		}
		if !hookTriggered {
			t.Fatal("expected after-lock-return hook to trigger")
		}

		// Foreign directory must have zero writes
		entries, err := os.ReadDir(foreignDir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) > 0 {
			t.Fatalf("foreign directory was written to: %v", entries)
		}

		// host-runtime.json must not exist
		if _, err := os.Lstat(paths.ConfigPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("host-runtime.json should not exist after ancestor replacement failure")
		}
	})

	t.Run("ReplaceParentAfterLockReturnReentry", func(t *testing.T) {
		tmpDir, paths, stagingDir, _ := setupIsolatedTestEnv(t)
		req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("5", 64))

		// First, do a complete provision
		baseOpts := provisionOptions{
			allowNonRoot:   true,
			paths:          paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
		}
		_, err := provisionWithOptions(context.Background(), req, baseOpts)
		if err != nil {
			t.Fatalf("setup provision failed: %v", err)
		}

		foreignDir := filepath.Join(tmpDir, "foreign-slots-reentry")
		_ = os.MkdirAll(foreignDir, 0700)

		var hookTriggered bool
		reentryOpts := provisionOptions{
			allowNonRoot:   true,
			paths:          paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
			ancestorHook: func(phase string, targetPath string) error {
				if phase == "after-lock-return" && targetPath == paths.SlotsLock {
					hookTriggered = true
					backupDir := paths.SlotsRoot + ".bak"
					if err := os.Rename(paths.SlotsRoot, backupDir); err != nil {
						return err
					}
					if err := os.Symlink(foreignDir, paths.SlotsRoot); err != nil {
						return err
					}
				}
				return nil
			},
		}

		_, err = provisionWithOptions(context.Background(), req, reentryOpts)
		if err == nil {
			t.Fatal("expected failure on active slots ancestor replacement after lock return during reentry")
		}
		if !hookTriggered {
			t.Fatal("expected reentry after-lock-return hook to trigger")
		}

		entries, err := os.ReadDir(foreignDir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) > 0 {
			t.Fatalf("foreign directory was written to during reentry: %v", entries)
		}
	})
}

// 9. TestProvisionPolicyCanonicalByteEquality: verifies rejection of non-canonical policy JSON
// and asserts zero policy hash drift across re-entry.
func TestProvisionPolicyCanonicalByteEquality(t *testing.T) {
	_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
	req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("6", 64))

	t.Run("RejectNonCanonicalWhitespaceOrReorderedKeys", func(t *testing.T) {
		origRaw, _ := os.ReadFile(req.PolicySourcePath)
		var obj map[string]any
		_ = json.Unmarshal(origRaw, &obj)

		// Formatted with indent (not compact canonical)
		nonCanonical, _ := json.MarshalIndent(obj, "", "    ")
		badPolicyPath := filepath.Join(stagingDir, "non-canonical-policy.json")
		_ = os.WriteFile(badPolicyPath, nonCanonical, 0600)

		badReq := req
		badReq.PolicySourcePath = badPolicyPath
		badReq.ExpectedPolicySHA256 = sha256Hex(nonCanonical)

		opts := provisionOptions{
			allowNonRoot:   true,
			paths:          paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
		}

		_, err := provisionWithOptions(context.Background(), badReq, opts)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("expected ErrInvalidRequest for non-canonical policy JSON, got %v", err)
		}
	})

	t.Run("RejectLeadingNewline", func(t *testing.T) {
		origRaw, _ := os.ReadFile(req.PolicySourcePath)
		badBytes := append([]byte("\n"), origRaw...)
		badPolicyPath := filepath.Join(stagingDir, "leading-nl-policy.json")
		_ = os.WriteFile(badPolicyPath, badBytes, 0600)

		badReq := req
		badReq.PolicySourcePath = badPolicyPath
		badReq.ExpectedPolicySHA256 = sha256Hex(badBytes)

		opts := provisionOptions{
			allowNonRoot:   true,
			paths:          paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
		}

		_, err := provisionWithOptions(context.Background(), badReq, opts)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("expected ErrInvalidRequest for leading newline in policy, got %v", err)
		}
	})

	t.Run("RejectTrailingNewline", func(t *testing.T) {
		origRaw, _ := os.ReadFile(req.PolicySourcePath)
		badBytes := append(origRaw, '\n')
		badPolicyPath := filepath.Join(stagingDir, "trailing-nl-policy.json")
		_ = os.WriteFile(badPolicyPath, badBytes, 0600)

		badReq := req
		badReq.PolicySourcePath = badPolicyPath
		badReq.ExpectedPolicySHA256 = sha256Hex(badBytes)

		opts := provisionOptions{
			allowNonRoot:   true,
			paths:          paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
		}

		_, err := provisionWithOptions(context.Background(), badReq, opts)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("expected ErrInvalidRequest for trailing newline in policy, got %v", err)
		}
	})

	t.Run("RejectTrailingSpace", func(t *testing.T) {
		origRaw, _ := os.ReadFile(req.PolicySourcePath)
		badBytes := append(origRaw, ' ')
		badPolicyPath := filepath.Join(stagingDir, "trailing-space-policy.json")
		_ = os.WriteFile(badPolicyPath, badBytes, 0600)

		badReq := req
		badReq.PolicySourcePath = badPolicyPath
		badReq.ExpectedPolicySHA256 = sha256Hex(badBytes)

		opts := provisionOptions{
			allowNonRoot:   true,
			paths:          paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
		}

		_, err := provisionWithOptions(context.Background(), badReq, opts)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("expected ErrInvalidRequest for trailing space in policy, got %v", err)
		}
	})

	t.Run("ExactReentryZeroPolicyHashDrift", func(t *testing.T) {
		opts := provisionOptions{
			allowNonRoot:   true,
			paths:          paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
		}

		receipt1, err := provisionWithOptions(context.Background(), req, opts)
		if err != nil {
			t.Fatalf("initial provision failed: %v", err)
		}

		receipt2, err := provisionWithOptions(context.Background(), req, opts)
		if err != nil {
			t.Fatalf("reentry provision failed: %v", err)
		}

		if receipt1.PolicySHA256 != req.ExpectedPolicySHA256 {
			t.Errorf("receipt policy SHA %q != expected %q", receipt1.PolicySHA256, req.ExpectedPolicySHA256)
		}
		if receipt1.PolicySHA256 != receipt2.PolicySHA256 {
			t.Errorf("policy SHA drifted on reentry: %q vs %q", receipt1.PolicySHA256, receipt2.PolicySHA256)
		}
	})
}

// 10. TestProvisionPolicyLastFailureInjection: verifies failure before publish leaves no host-runtime.json.
func TestProvisionPolicyLastFailureInjection(t *testing.T) {
	_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
	req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("7", 64))

	opts := provisionOptions{
		allowNonRoot:   true,
		paths:          paths,
		guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
		beforePublishHook: func() error {
			return errors.New("fail before publish")
		},
	}

	_, err := provisionWithOptions(context.Background(), req, opts)
	if err == nil {
		t.Fatal("expected failure from beforePublishHook")
	}

	if _, err := os.Lstat(paths.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("host-runtime.json must not exist if publish hook failed")
	}
}

// 11. TestProvisionStatePreservation: verifies that existing state.json and ledger.json are preserved across reentry.
func TestProvisionStatePreservation(t *testing.T) {
	_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
	req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("8", 64))

	opts := provisionOptions{
		allowNonRoot:   true,
		paths:          paths,
		guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
	}

	_, err := provisionWithOptions(context.Background(), req, opts)
	if err != nil {
		t.Fatalf("initial provision failed: %v", err)
	}

	stateContent := []byte(`{"applied_sequence":1,"active_slot":"slot-001"}`)
	ledgerContent := []byte(`{"active":"slot-001","history":[]}`)

	statePath := filepath.Join(paths.ControllerRoot, "state.json")
	ledgerPath := filepath.Join(paths.SlotsRoot, "ledger.json")

	if err := os.WriteFile(statePath, stateContent, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ledgerPath, ledgerContent, 0600); err != nil {
		t.Fatal(err)
	}

	receipt, err := provisionWithOptions(context.Background(), req, opts)
	if err != nil {
		t.Fatalf("reentry failed: %v", err)
	}
	if receipt.InstanceID != instanceID {
		t.Errorf("instance ID mismatch")
	}

	curState, err := os.ReadFile(statePath)
	if err != nil || !bytes.Equal(curState, stateContent) {
		t.Errorf("state.json was modified or deleted: %v", err)
	}
	curLedger, err := os.ReadFile(ledgerPath)
	if err != nil || !bytes.Equal(curLedger, ledgerContent) {
		t.Errorf("ledger.json was modified or deleted: %v", err)
	}
}

// 12. TestProvisionConfigSchemaAndProductionReadback: verifies canonical JSON byte equality and production loader success.
func TestProvisionConfigSchemaAndProductionReadback(t *testing.T) {
	_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
	req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("9", 64))

	opts := provisionOptions{
		allowNonRoot:   true,
		paths:          paths,
		guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
	}

	_, err := provisionWithOptions(context.Background(), req, opts)
	if err != nil {
		t.Fatalf("provision failed: %v", err)
	}

	raw, err := os.ReadFile(paths.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}

	var cfg hostconfig.HostConfigFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		t.Fatalf("config decode failed: %v", err)
	}
	canonical, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		t.Errorf("config is not canonical JSON byte-for-byte")
	}

	loaded, err := hostconfig.ReadAndValidateConfigFile(paths.ConfigPath, paths.BootstrapRoot, true)
	if err != nil {
		t.Fatalf("production ReadAndValidateConfigFile failed: %v", err)
	}
	defer loaded.Close()
}

// 13. TestProvisionWrongArchitecture: verifies rejection of mismatched arch in policy.
func TestProvisionWrongArchitecture(t *testing.T) {
	_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
	req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("a", 64))

	wrongArch := "mips"
	if runtime.GOARCH == "amd64" {
		wrongArch = "arm64"
	}
	targetOS := "linux"
	if runtime.GOOS != "linux" {
		targetOS = runtime.GOOS
	}
	polPath, _, polSHA := createTestPolicyFile(t, stagingDir, targetOS, wrongArch)
	req.PolicySourcePath = polPath
	req.ExpectedPolicySHA256 = polSHA

	opts := provisionOptions{
		allowNonRoot:   true,
		paths:          paths,
		guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
	}

	_, err := provisionWithOptions(context.Background(), req, opts)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for wrong arch, got %v", err)
	}
}

// 14. TestProvisionWrongInstanceOrBinding: verifies all backend observation and guest instance contract checks.
func TestProvisionWrongInstanceOrBinding(t *testing.T) {
	t.Run("WrongKindInInstance", func(t *testing.T) {
		_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
		req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("b", 64))

		badInst := guestInstanceFile{
			SchemaVersion:        1,
			Kind:                 "mac-managed",
			NativeID:             "xyz",
			InstanceID:           instanceID,
			MarkerSHA256:         strings.Repeat("0", 64),
			BootstrapHostVersion: "1.0.0",
		}
		raw, _ := json.Marshal(badInst)
		_ = os.WriteFile(paths.GuestInstancePath, raw, 0600)

		opts := provisionOptions{
			allowNonRoot:   true,
			paths:          paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
		}

		_, err := provisionWithOptions(context.Background(), req, opts)
		if !errors.Is(err, ErrProvisionConflict) {
			t.Fatalf("expected ErrProvisionConflict for non-linux-local kind, got %v", err)
		}
	})

	t.Run("WrongBindingInObservation", func(t *testing.T) {
		_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
		req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("b", 64))

		opts := provisionOptions{
			allowNonRoot: true,
			paths:        paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, func(obs *desktopupdate.BackendObservation) {
				obs.Binding = strings.Repeat("9", 64)
			}),
		}

		_, err := provisionWithOptions(context.Background(), req, opts)
		if !errors.Is(err, ErrObserveFailed) {
			t.Fatalf("expected ErrObserveFailed for wrong binding, got %v", err)
		}
	})

	t.Run("ReadyFalseInObservation", func(t *testing.T) {
		_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
		req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("b", 64))

		opts := provisionOptions{
			allowNonRoot: true,
			paths:        paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, func(obs *desktopupdate.BackendObservation) {
				obs.Ready = false
			}),
		}

		_, err := provisionWithOptions(context.Background(), req, opts)
		if !errors.Is(err, ErrObserveFailed) {
			t.Fatalf("expected ErrObserveFailed when ready=false, got %v", err)
		}
	})

	t.Run("FinalizedFalseInObservation", func(t *testing.T) {
		_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
		req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("b", 64))

		opts := provisionOptions{
			allowNonRoot: true,
			paths:        paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, func(obs *desktopupdate.BackendObservation) {
				obs.Finalized = false
			}),
		}

		_, err := provisionWithOptions(context.Background(), req, opts)
		if !errors.Is(err, ErrObserveFailed) {
			t.Fatalf("expected ErrObserveFailed when finalized=false, got %v", err)
		}
	})

	t.Run("LocalLoopbackFalseInObservation", func(t *testing.T) {
		_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
		req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("b", 64))

		opts := provisionOptions{
			allowNonRoot: true,
			paths:        paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, func(obs *desktopupdate.BackendObservation) {
				obs.LocalLoopback = false
			}),
		}

		_, err := provisionWithOptions(context.Background(), req, opts)
		if !errors.Is(err, ErrObserveFailed) {
			t.Fatalf("expected ErrObserveFailed when local_loopback=false, got %v", err)
		}
	})

	t.Run("MigrationNot0040", func(t *testing.T) {
		_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
		req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("b", 64))

		opts := provisionOptions{
			allowNonRoot: true,
			paths:        paths,
			guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, func(obs *desktopupdate.BackendObservation) {
				obs.MigrationVersion = "0039"
			}),
		}

		_, err := provisionWithOptions(context.Background(), req, opts)
		if !errors.Is(err, ErrObserveFailed) {
			t.Fatalf("expected ErrObserveFailed when migration != 0040, got %v", err)
		}
	})
}

// 15. TestProvisionCanceledObserve: verifies prompt cancellation handling without publishing.
func TestProvisionCanceledObserve(t *testing.T) {
	_, paths, stagingDir, _ := setupIsolatedTestEnv(t)
	req, instanceID := setupValidSources(t, stagingDir, paths.GuestInstancePath, "1.0.0", strings.Repeat("c", 64))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	opts := provisionOptions{
		allowNonRoot:   true,
		paths:          paths,
		guestTransport: createMockGuestTransport(instanceID, req.BootstrapBackendBinding, nil),
	}

	_, err := provisionWithOptions(ctx, req, opts)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	if _, err := os.Lstat(paths.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("host-runtime.json should not exist when context canceled")
	}
}
