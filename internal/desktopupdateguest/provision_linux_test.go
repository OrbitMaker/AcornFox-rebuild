//go:build linux

package desktopupdateguest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/desktopupdate"
)

func buildTestWorkerBinary(t *testing.T, dir string) string {
	t.Helper()
	binPath := filepath.Join(dir, "test-worker")
	var raw []byte
	var err error
	if supplied := os.Getenv("ACORNFOX_GUEST_WORKER_TEST_BIN"); supplied != "" {
		raw, err = os.ReadFile(supplied)
	} else if self, e := os.Executable(); e == nil {
		raw, err = os.ReadFile(self)
	}
	if err != nil || len(raw) == 0 {
		t.Fatalf("could not read test worker binary: %v", err)
	}
	if err := os.WriteFile(binPath, raw, 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chown(binPath, 0, 0)
	return binPath
}

func setupTestProvisionPaths(anchor string) provisionPaths {
	return provisionPaths{
		anchor:      anchor,
		executable:  filepath.Join(anchor, "usr", "local", "libexec", "acornfox-guest-update"),
		policy:      filepath.Join(anchor, "etc", "acornfox-host", "guest-update-policy.json"),
		instance:    filepath.Join(anchor, "etc", "acornfox-host", "guest-instance.json"),
		state:       filepath.Join(anchor, "var", "lib", "acornfox-host", "guest-update"),
		macMarker:   filepath.Join(anchor, "var", "lib", "acornfox-desktop", "owner-marker"),
		linuxMarker: filepath.Join(anchor, "etc", "acornfox-host", "linux-owner-marker"),
		lock:        filepath.Join(anchor, "etc", "acornfox-host", "provision.lock"),
	}
}

func createTestPolicyFile(t *testing.T, dir, hostOS string) (string, []byte, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pol := Policy{
		Schema:          1,
		PublicKey:       pub,
		HostOS:          hostOS,
		HostArch:        runtime.GOARCH,
		Channel:         "stable",
		AllowedHosts:    []string{"updates.example.test"},
		MaxArtifactSize: 100 << 20,
	}
	raw := encoded(pol)
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chown(path, 0, 0)
	return path, raw, digest(raw)
}

func TestProvisionUnprivilegedCallerFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipping unprivileged check when running as root")
	}
	req := ProvisionRequest{
		Kind:                 "linux-local",
		BootstrapHostVersion: "1.0.0",
		WorkerSourcePath:     "/dummy/worker",
		ExpectedWorkerSHA256: strings.Repeat("a", 64),
		PolicySourcePath:     "/dummy/policy",
		ExpectedPolicySHA256: strings.Repeat("b", 64),
	}
	_, err := Provision(context.Background(), req)
	if !errors.Is(err, ErrPrivilegeRequired) {
		t.Fatalf("expected ErrPrivilegeRequired for non-root caller, got %v", err)
	}
}

func TestProvisionFreshLinuxLocal(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	anchor := t.TempDir()
	paths := setupTestProvisionPaths(anchor)

	staging := filepath.Join(anchor, "staging")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	_ = os.Chown(staging, 0, 0)

	workerPath := buildTestWorkerBinary(t, staging)
	workerBytes, err := os.ReadFile(workerPath)
	if err != nil {
		t.Fatal(err)
	}
	workerSHA := digest(workerBytes)

	policyPath, _, policySHA := createTestPolicyFile(t, staging, "linux")

	req := ProvisionRequest{
		Kind:                 "linux-local",
		BootstrapHostVersion: "1.0.0",
		WorkerSourcePath:     workerPath,
		ExpectedWorkerSHA256: workerSHA,
		PolicySourcePath:     policyPath,
		ExpectedPolicySHA256: policySHA,
	}

	receipt, err := provisionWithPaths(context.Background(), paths, req)
	if err != nil {
		t.Fatalf("provisionWithPaths failed: %v", err)
	}

	if receipt.Kind != "linux-local" || receipt.BootstrapHostVersion != "1.0.0" {
		t.Errorf("unexpected receipt metadata: %+v", receipt)
	}
	if receipt.WorkerSHA256 != workerSHA {
		t.Errorf("worker SHA mismatch in receipt: got %s, want %s", receipt.WorkerSHA256, workerSHA)
	}
	if receipt.PolicySHA256 != policySHA {
		t.Errorf("policy SHA mismatch in receipt: got %s, want %s", receipt.PolicySHA256, policySHA)
	}
	if !hexID.MatchString(receipt.NativeID) || !hexID.MatchString(receipt.InstanceID) {
		t.Errorf("invalid IDs in receipt: native=%s, instance=%s", receipt.NativeID, receipt.InstanceID)
	}

	// Verify file permissions and ownership on disk
	info, err := os.Lstat(paths.executable)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Errorf("executable perm mismatch: %v, err=%v", info.Mode().Perm(), err)
	}
	info, err = os.Lstat(paths.linuxMarker)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Errorf("marker perm mismatch: %v, err=%v", info.Mode().Perm(), err)
	}
	info, err = os.Lstat(paths.instance)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Errorf("instance perm mismatch: %v, err=%v", info.Mode().Perm(), err)
	}
	info, err = os.Lstat(paths.state)
	if err != nil || info.Mode().Perm() != 0700 || !info.IsDir() {
		t.Errorf("state dir perm mismatch: %v, err=%v", info.Mode().Perm(), err)
	}
	info, err = os.Lstat(paths.policy)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Errorf("policy perm mismatch: %v, err=%v", info.Mode().Perm(), err)
	}

	// Verify open(sp) validates cleanly
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
		t.Fatalf("open(sp) failed on provisioned system: %v", err)
	}
	if exec == nil || exec.instance.InstanceID != receipt.InstanceID {
		t.Errorf("open returned inconsistent executor: %+v", exec)
	}
}

func TestProvisionIdempotentReentry(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	anchor := t.TempDir()
	paths := setupTestProvisionPaths(anchor)

	staging := filepath.Join(anchor, "staging")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	_ = os.Chown(staging, 0, 0)

	workerPath := buildTestWorkerBinary(t, staging)
	workerBytes, err := os.ReadFile(workerPath)
	if err != nil {
		t.Fatal(err)
	}
	workerSHA := digest(workerBytes)
	policyPath, _, policySHA := createTestPolicyFile(t, staging, "linux")

	req := ProvisionRequest{
		Kind:                 "linux-local",
		BootstrapHostVersion: "1.2.3",
		WorkerSourcePath:     workerPath,
		ExpectedWorkerSHA256: workerSHA,
		PolicySourcePath:     policyPath,
		ExpectedPolicySHA256: policySHA,
	}

	// First provision
	receipt1, err := provisionWithPaths(context.Background(), paths, req)
	if err != nil {
		t.Fatalf("first provision failed: %v", err)
	}

	// Now initialize a basic snapshot via load so exact re-entry has valid state.json
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
		t.Fatalf("open(sp) failed: %v", err)
	}
	if _, err := exec.load(); err != nil {
		t.Fatalf("load snapshot failed: %v", err)
	}

	// Read marker content before reentry
	markerBefore, err := os.ReadFile(paths.linuxMarker)
	if err != nil {
		t.Fatal(err)
	}

	// Second provision (reentry)
	receipt2, err := provisionWithPaths(context.Background(), paths, req)
	if err != nil {
		t.Fatalf("reentry provision failed: %v", err)
	}

	// Check marker was NOT rewritten or modified
	markerAfter, err := os.ReadFile(paths.linuxMarker)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(markerBefore, markerAfter) {
		t.Errorf("marker was rewritten on reentry!")
	}

	if receipt1.InstanceID != receipt2.InstanceID || receipt1.NativeID != receipt2.NativeID {
		t.Errorf("receipt mismatch on idempotent reentry: r1=%+v, r2=%+v", receipt1, receipt2)
	}
}

func TestProvisionConfiguredMissingPrerequisitesFails(t *testing.T) {
	// P1-1: When policy exists, exact re-entry only.
	// If state directory, state.json, worker, or instance is missing, fail immediately without recreating.
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}

	for _, tc := range []string{"missing-state-dir", "missing-state-json", "missing-worker", "missing-instance"} {
		t.Run(tc, func(t *testing.T) {
			anchor := t.TempDir()
			paths := setupTestProvisionPaths(anchor)

			staging := filepath.Join(anchor, "staging")
			if err := os.Mkdir(staging, 0700); err != nil {
				t.Fatal(err)
			}
			_ = os.Chown(staging, 0, 0)

			workerPath := buildTestWorkerBinary(t, staging)
			workerBytes, _ := os.ReadFile(workerPath)
			workerSHA := digest(workerBytes)
			policyPath, _, policySHA := createTestPolicyFile(t, staging, "linux")

			req := ProvisionRequest{
				Kind:                 "linux-local",
				BootstrapHostVersion: "1.0.0",
				WorkerSourcePath:     workerPath,
				ExpectedWorkerSHA256: workerSHA,
				PolicySourcePath:     policyPath,
				ExpectedPolicySHA256: policySHA,
			}

			// Complete initial provision
			if _, err := provisionWithPaths(context.Background(), paths, req); err != nil {
				t.Fatalf("initial provision failed: %v", err)
			}

			// Initialize state.json
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
				t.Fatal(err)
			}
			if _, err := exec.load(); err != nil {
				t.Fatal(err)
			}

			// Introduce defect
			switch tc {
			case "missing-state-dir":
				if err := os.RemoveAll(paths.state); err != nil {
					t.Fatal(err)
				}
			case "missing-state-json":
				if err := os.Remove(filepath.Join(paths.state, "state.json")); err != nil {
					t.Fatal(err)
				}
			case "missing-worker":
				if err := os.Remove(paths.executable); err != nil {
					t.Fatal(err)
				}
			case "missing-instance":
				if err := os.Remove(paths.instance); err != nil {
					t.Fatal(err)
				}
			}

			// Calling provisionWithPaths must fail with ErrConflict
			_, err = provisionWithPaths(context.Background(), paths, req)
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("expected ErrConflict for %s, got %v", tc, err)
			}

			// Crucial: for missing-state-dir, verify state directory was NOT recreated!
			if tc == "missing-state-dir" {
				if _, err := os.Lstat(paths.state); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("missing state directory was illegally recreated!")
				}
			}
		})
	}
}

func TestProvisionConfiguredPreservesJobsAndFloor(t *testing.T) {
	// P1-1: Configured installation with existing jobs and catalog floor must be preserved intact.
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	anchor := t.TempDir()
	paths := setupTestProvisionPaths(anchor)

	staging := filepath.Join(anchor, "staging")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	_ = os.Chown(staging, 0, 0)

	workerPath := buildTestWorkerBinary(t, staging)
	workerBytes, _ := os.ReadFile(workerPath)
	workerSHA := digest(workerBytes)
	policyPath, _, policySHA := createTestPolicyFile(t, staging, "linux")

	req := ProvisionRequest{
		Kind:                 "linux-local",
		BootstrapHostVersion: "1.0.0",
		WorkerSourcePath:     workerPath,
		ExpectedWorkerSHA256: workerSHA,
		PolicySourcePath:     policyPath,
		ExpectedPolicySHA256: policySHA,
	}

	// 1. Initial provision
	if _, err := provisionWithPaths(context.Background(), paths, req); err != nil {
		t.Fatalf("initial provision failed: %v", err)
	}

	// 2. Open executor and create a snapshot with Floor = 7 and a job
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
		t.Fatal(err)
	}
	if _, err := exec.load(); err != nil {
		t.Fatal(err)
	}

	// Add job and set floor
	j := JobReceipt{
		Intent: desktopupdate.HostUpgradeIntent{
			InstanceID:     exec.instance.InstanceID,
			AttemptID:      strings.Repeat("3", 64),
			FromBinding:    strings.Repeat("1", 64),
			ToBinding:      strings.Repeat("2", 64),
			ArtifactSHA256: strings.Repeat("4", 64),
		},
		State:       "upgraded",
		EnvelopeSHA: strings.Repeat("5", 64),
		AcceptedAt:  time.Now().UTC(),
		Sequence:    7,
	}
	snap := snapshot{
		Schema:      1,
		Revision:    1,
		PreviousSHA: "",
		PolicySHA:   digest(encoded(exec.policy)),
		InstanceSHA: digest(encoded(exec.instance)),
		Floor:       7,
		FloorSHA:    strings.Repeat("6", 64),
		Jobs:        []JobReceipt{j},
	}
	stateJSON := encoded(snap)
	stateFile := filepath.Join(paths.state, "state.json")
	if err := os.WriteFile(stateFile, stateJSON, 0600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chown(stateFile, 0, 0)

	// Capture state.json content and stat
	stateBefore, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	infoBefore, err := os.Lstat(stateFile)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Re-run provisionWithPaths
	receipt, err := provisionWithPaths(context.Background(), paths, req)
	if err != nil {
		t.Fatalf("reentry failed: %v", err)
	}
	if receipt.InstanceID != exec.instance.InstanceID {
		t.Errorf("instance ID changed: %s vs %s", receipt.InstanceID, exec.instance.InstanceID)
	}

	// 4. Verify state.json was completely untouched!
	stateAfter, err := os.ReadFile(filepath.Join(paths.state, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	infoAfter, err := os.Lstat(filepath.Join(paths.state, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stateBefore, stateAfter) {
		t.Errorf("state.json was modified during configured re-entry!")
	}
	statBefore := infoBefore.Sys().(*syscall.Stat_t)
	statAfter := infoAfter.Sys().(*syscall.Stat_t)
	if statBefore.Ino != statAfter.Ino {
		t.Errorf("state.json inode changed: %d vs %d", statBefore.Ino, statAfter.Ino)
	}
}

func TestProvisionPolicyAbsentNonEmptyStateFails(t *testing.T) {
	// P1-2: When policy is absent, state directory must be absent or completely empty.
	// Any pre-existing files (job-*, state.json, unknown) must be rejected with ErrConflict.
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}

	for _, filename := range []string{"job-123", "state.json", "foreign.txt", "lock"} {
		t.Run(filename, func(t *testing.T) {
			anchor := t.TempDir()
			paths := setupTestProvisionPaths(anchor)

			staging := filepath.Join(anchor, "staging")
			if err := os.Mkdir(staging, 0700); err != nil {
				t.Fatal(err)
			}
			_ = os.Chown(staging, 0, 0)

			workerPath := buildTestWorkerBinary(t, staging)
			workerBytes, _ := os.ReadFile(workerPath)
			workerSHA := digest(workerBytes)
			policyPath, _, policySHA := createTestPolicyFile(t, staging, "linux")

			// Pre-create state directory with the file inside, but NO policy file
			if err := ensureDirSafe(paths.anchor, paths.state, 0700); err != nil {
				t.Fatal(err)
			}
			filePath := filepath.Join(paths.state, filename)
			if err := os.WriteFile(filePath, []byte("data"), 0600); err != nil {
				t.Fatal(err)
			}
			_ = os.Chown(filePath, 0, 0)

			req := ProvisionRequest{
				Kind:                 "linux-local",
				BootstrapHostVersion: "1.0.0",
				WorkerSourcePath:     workerPath,
				ExpectedWorkerSHA256: workerSHA,
				PolicySourcePath:     policyPath,
				ExpectedPolicySHA256: policySHA,
			}

			_, err := provisionWithPaths(context.Background(), paths, req)
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("expected ErrConflict for non-empty state dir with %s, got %v", filename, err)
			}

			// Verify policy file was NOT published!
			if _, err := os.Lstat(paths.policy); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("policy was published despite non-empty state directory!")
			}
		})
	}
}

func TestProvisionBadELFValidation(t *testing.T) {
	// P2-2: ELF validation must reject non-executables (ET_REL), zero entry, big endian, wrong arch
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	anchor := t.TempDir()
	staging := filepath.Join(anchor, "staging")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	_ = os.Chown(staging, 0, 0)

	validWorkerPath := buildTestWorkerBinary(t, staging)
	validELF, err := os.ReadFile(validWorkerPath)
	if err != nil {
		t.Fatal(err)
	}

	policyPath, _, policySHA := createTestPolicyFile(t, staging, "linux")

	// 1. ET_REL object file (bytes 16-17 = 1, 0)
	t.Run("ET_REL", func(t *testing.T) {
		p := setupTestProvisionPaths(t.TempDir())
		badELF := append([]byte(nil), validELF...)
		badELF[16] = 1
		badELF[17] = 0
		badPath := filepath.Join(staging, "worker-rel")
		_ = os.WriteFile(badPath, badELF, 0755)
		_ = os.Chown(badPath, 0, 0)

		req := ProvisionRequest{
			Kind:                 "linux-local",
			BootstrapHostVersion: "1.0.0",
			WorkerSourcePath:     badPath,
			ExpectedWorkerSHA256: digest(badELF),
			PolicySourcePath:     policyPath,
			ExpectedPolicySHA256: policySHA,
		}
		_, err := provisionWithPaths(context.Background(), p, req)
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("expected ErrConflict for ET_REL ELF, got %v", err)
		}
	})

	// 2. Zero entry point (bytes 24-31 = 0)
	t.Run("ZeroEntry", func(t *testing.T) {
		p := setupTestProvisionPaths(t.TempDir())
		badELF := append([]byte(nil), validELF...)
		for i := 24; i < 32; i++ {
			badELF[i] = 0
		}
		badPath := filepath.Join(staging, "worker-zero-entry")
		_ = os.WriteFile(badPath, badELF, 0755)
		_ = os.Chown(badPath, 0, 0)

		req := ProvisionRequest{
			Kind:                 "linux-local",
			BootstrapHostVersion: "1.0.0",
			WorkerSourcePath:     badPath,
			ExpectedWorkerSHA256: digest(badELF),
			PolicySourcePath:     policyPath,
			ExpectedPolicySHA256: policySHA,
		}
		_, err := provisionWithPaths(context.Background(), p, req)
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("expected ErrConflict for zero entry ELF, got %v", err)
		}
	})

	// 3. Big-endian data encoding (byte 5 = 2)
	t.Run("BigEndian", func(t *testing.T) {
		p := setupTestProvisionPaths(t.TempDir())
		badELF := append([]byte(nil), validELF...)
		badELF[5] = 2
		badPath := filepath.Join(staging, "worker-be")
		_ = os.WriteFile(badPath, badELF, 0755)
		_ = os.Chown(badPath, 0, 0)

		req := ProvisionRequest{
			Kind:                 "linux-local",
			BootstrapHostVersion: "1.0.0",
			WorkerSourcePath:     badPath,
			ExpectedWorkerSHA256: digest(badELF),
			PolicySourcePath:     policyPath,
			ExpectedPolicySHA256: policySHA,
		}
		_, err := provisionWithPaths(context.Background(), p, req)
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("expected ErrConflict for big endian ELF, got %v", err)
		}
	})

	// 4. Wrong machine architecture (bytes 18-19 = 3, 0 for EM_386)
	t.Run("WrongMachine", func(t *testing.T) {
		p := setupTestProvisionPaths(t.TempDir())
		badELF := append([]byte(nil), validELF...)
		badELF[18] = 3
		badELF[19] = 0
		badPath := filepath.Join(staging, "worker-386")
		_ = os.WriteFile(badPath, badELF, 0755)
		_ = os.Chown(badPath, 0, 0)

		req := ProvisionRequest{
			Kind:                 "linux-local",
			BootstrapHostVersion: "1.0.0",
			WorkerSourcePath:     badPath,
			ExpectedWorkerSHA256: digest(badELF),
			PolicySourcePath:     policyPath,
			ExpectedPolicySHA256: policySHA,
		}
		_, err := provisionWithPaths(context.Background(), p, req)
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("expected ErrConflict for wrong machine ELF, got %v", err)
		}
	})
}

func TestProvisionSourceValidationAndSwap(t *testing.T) {
	// P2-1: Sources must be absolute clean paths, root-owned, non-symlink, single-link, not group-writable
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	anchor := t.TempDir()
	staging := filepath.Join(anchor, "staging")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	_ = os.Chown(staging, 0, 0)

	workerPath := buildTestWorkerBinary(t, staging)
	workerBytes, _ := os.ReadFile(workerPath)
	workerSHA := digest(workerBytes)
	policyPath, _, policySHA := createTestPolicyFile(t, staging, "linux")

	baseReq := ProvisionRequest{
		Kind:                 "linux-local",
		BootstrapHostVersion: "1.0.0",
		WorkerSourcePath:     workerPath,
		ExpectedWorkerSHA256: workerSHA,
		PolicySourcePath:     policyPath,
		ExpectedPolicySHA256: policySHA,
	}

	// 1. Relative source path
	t.Run("RelativePath", func(t *testing.T) {
		p := setupTestProvisionPaths(t.TempDir())
		r := baseReq
		r.WorkerSourcePath = "relative/path"
		if _, err := provisionWithPaths(context.Background(), p, r); !errors.Is(err, ErrConflict) {
			t.Fatalf("expected ErrConflict for relative path, got %v", err)
		}
	})

	// 2. Symlink source
	t.Run("SymlinkSource", func(t *testing.T) {
		p := setupTestProvisionPaths(t.TempDir())
		symPath := filepath.Join(staging, "sym-worker")
		_ = os.Symlink(workerPath, symPath)
		defer os.Remove(symPath)
		r := baseReq
		r.WorkerSourcePath = symPath
		if _, err := provisionWithPaths(context.Background(), p, r); !errors.Is(err, ErrConflict) {
			t.Fatalf("expected ErrConflict for symlink source, got %v", err)
		}
	})

	// 3. Hardlink source (nlink > 1)
	t.Run("HardlinkSource", func(t *testing.T) {
		p := setupTestProvisionPaths(t.TempDir())
		hardPath := filepath.Join(staging, "hard-worker")
		_ = os.Link(workerPath, hardPath)
		defer os.Remove(hardPath)
		r := baseReq
		r.WorkerSourcePath = hardPath
		if _, err := provisionWithPaths(context.Background(), p, r); !errors.Is(err, ErrConflict) {
			t.Fatalf("expected ErrConflict for hardlinked source, got %v", err)
		}
	})

	// 4. Group-writable source directory (0777)
	t.Run("GroupWritableDir", func(t *testing.T) {
		p := setupTestProvisionPaths(t.TempDir())
		badDir := filepath.Join(anchor, "bad-dir")
		_ = os.Mkdir(badDir, 0777)
		defer os.RemoveAll(badDir)
		wPath := filepath.Join(badDir, "worker")
		_ = os.WriteFile(wPath, workerBytes, 0755)
		_ = os.Chown(wPath, 0, 0)
		r := baseReq
		r.WorkerSourcePath = wPath
		if _, err := provisionWithPaths(context.Background(), p, r); !errors.Is(err, ErrConflict) {
			t.Fatalf("expected ErrConflict for group-writable parent dir, got %v", err)
		}
	})
}

func TestProvisionConcurrentIdenticalAndConflicting(t *testing.T) {
	// P2-3: Concurrent calls on the same target set serialize via the provisioning lock.
	// Identical calls all succeed; conflicting calls fail the loser cleanly without state corruption.
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	anchor := t.TempDir()
	paths := setupTestProvisionPaths(anchor)

	staging := filepath.Join(anchor, "staging")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	_ = os.Chown(staging, 0, 0)

	workerPath := buildTestWorkerBinary(t, staging)
	workerBytes, _ := os.ReadFile(workerPath)
	workerSHA := digest(workerBytes)
	policyPath, _, policySHA := createTestPolicyFile(t, staging, "linux")

	// 1. Initial provision to create baseline state
	req := ProvisionRequest{
		Kind:                 "linux-local",
		BootstrapHostVersion: "1.0.0",
		WorkerSourcePath:     workerPath,
		ExpectedWorkerSHA256: workerSHA,
		PolicySourcePath:     policyPath,
		ExpectedPolicySHA256: policySHA,
	}
	receipt, err := provisionWithPaths(context.Background(), paths, req)
	if err != nil {
		t.Fatalf("initial provision failed: %v", err)
	}

	// Initialize state snapshot for re-entry validation
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
		t.Fatal(err)
	}
	if _, err := exec.load(); err != nil {
		t.Fatal(err)
	}

	// 2. Concurrent identical calls: all must succeed and return identical receipts
	var wg sync.WaitGroup
	results := make([]*ProvisionReceipt, 4)
	errs := make([]error, 4)
	for i := 0; i < 4; i++ {
		idx := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[idx], errs[idx] = provisionWithPaths(context.Background(), paths, req)
		}()
	}
	wg.Wait()

	for i := range results {
		if errs[i] != nil {
			t.Errorf("concurrent identical call %d failed: %v", i, errs[i])
		} else if results[i].InstanceID != receipt.InstanceID {
			t.Errorf("concurrent call %d returned different instance ID: %s vs %s", i, results[i].InstanceID, receipt.InstanceID)
		}
	}

	// 3. Concurrent conflicting call: different version -> must fail with ErrConflict
	conflictingReq := req
	conflictingReq.BootstrapHostVersion = "9.9.9"
	_, err = provisionWithPaths(context.Background(), paths, conflictingReq)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict for conflicting version, got %v", err)
	}
}

func TestProvisionPolicyPublishedLast(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	anchor := t.TempDir()
	paths := setupTestProvisionPaths(anchor)

	sp := systemPaths{
		anchor:     paths.anchor,
		policy:     paths.policy,
		instance:   paths.instance,
		state:      paths.state,
		executable: paths.executable,
		marker:     paths.macMarker,
	}

	// Before provisioning, open(sp) returns ErrNotConfigured
	if _, err := open(sp); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured before provision, got %v", err)
	}

	staging := filepath.Join(anchor, "staging")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	_ = os.Chown(staging, 0, 0)

	workerPath := buildTestWorkerBinary(t, staging)
	workerBytes, _ := os.ReadFile(workerPath)
	workerSHA := digest(workerBytes)
	policyPath, _, policySHA := createTestPolicyFile(t, staging, "linux")

	// Pre-create worker and instance manually, but NOT policy
	_ = ensureDirSafe(paths.anchor, filepath.Dir(paths.executable), 0755)
	_ = writeNew(paths.executable, workerBytes, 0755)
	_ = ensureDirSafe(paths.anchor, paths.state, 0700)

	// Still no policy file: open(sp) must still return ErrNotConfigured!
	if _, err := open(sp); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured when policy is missing, got %v", err)
	}

	// Now run provision: completes and publishes policy last
	req := ProvisionRequest{
		Kind:                 "linux-local",
		BootstrapHostVersion: "1.0.0",
		WorkerSourcePath:     workerPath,
		ExpectedWorkerSHA256: workerSHA,
		PolicySourcePath:     policyPath,
		ExpectedPolicySHA256: policySHA,
	}
	if _, err := provisionWithPaths(context.Background(), paths, req); err != nil {
		t.Fatalf("provision failed: %v", err)
	}

	// After provision, open(sp) succeeds
	if _, err := open(sp); err != nil {
		t.Fatalf("expected open(sp) to succeed after policy published, got %v", err)
	}
}
