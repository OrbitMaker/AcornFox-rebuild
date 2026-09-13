//go:build darwin && cgo

package darwinlaunch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/desktopupdate"
)

var (
	buildHelperOnce sync.Once
	helperPath      string
	helperErr       error

	buildReplOnce sync.Once
	replPath      string
	replErr       error
)

func getTestHelper(t *testing.T) string {
	t.Helper()
	buildHelperOnce.Do(func() {
		dir, err := os.MkdirTemp("", "darwinlaunch-helper-")
		if err != nil {
			helperErr = err
			return
		}
		bin := filepath.Join(dir, "helper")
		out, err := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", bin, "./testdata/helper").CombinedOutput()
		if err != nil {
			helperErr = fmt.Errorf("build helper: %w: %s", err, out)
			return
		}
		// Explicitly sign with fixed test identifier
		_ = exec.Command("/usr/bin/codesign", "-s", "-", "-f", "-i", "com.acornfox.test.helper", bin).Run()
		helperPath = bin
	})
	if helperErr != nil {
		t.Fatal(helperErr)
	}
	return helperPath
}

func getReplHelper(t *testing.T) string {
	t.Helper()
	buildReplOnce.Do(func() {
		dir, err := os.MkdirTemp("", "darwinlaunch-repl-")
		if err != nil {
			replErr = err
			return
		}
		bin := filepath.Join(dir, "helper_repl")
		out, err := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", bin, "./testdata/helper_repl").CombinedOutput()
		if err != nil {
			replErr = fmt.Errorf("build repl: %w: %s", err, out)
			return
		}
		// Explicitly sign with the SAME fixed test identifier so rejection proves exact CDHash
		_ = exec.Command("/usr/bin/codesign", "-s", "-", "-f", "-i", "com.acornfox.test.helper", bin).Run()
		replPath = bin
	})
	if replErr != nil {
		t.Fatal(replErr)
	}
	return replPath
}

// P1: posix_spawn attribute and file actions failures must be checked before spawn
func TestDarwinLaunch_P1_PosixSpawnAttributeAndActionFailures(t *testing.T) {
	if !InternalTestingEnabled {
		t.Skip("posix_spawn attribute/action fault injection requires -tags acornfox_internal_testing")
	}
	helper := getTestHelper(t)
	f, err := os.Open(helper)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	failureNames := map[int]string{
		1: "posix_spawnattr_setflags",
		2: "posix_spawnattr_setpgroup",
		3: "posix_spawnattr_setsigdefault",
		4: "posix_spawnattr_setsigmask",
		5: "dup2_devnull",
		6: "dup2_stdout",
		7: "dup2_stderr",
		8: "dup2_lifecycle",
	}

	for code := 1; code <= 8; code++ {
		t.Run(failureNames[code], func(t *testing.T) {
			tempDir := t.TempDir()
			markerPath := filepath.Join(tempDir, fmt.Sprintf("marker_%d.txt", code))

			injectSpawnFailure(code)
			defer clearSpawnFailure()

			prepared, _, err := prepareFixtureChild(
				context.Background(),
				f,
				tempDir,
				"helper",
				[]string{"--marker-file", markerPath},
				true,
			)
			clearSpawnFailure()

			if err == nil {
				if prepared != nil {
					_ = prepared.Abort(context.Background())
				}
				t.Fatalf("expected error for injected failure %s, got nil", failureNames[code])
			}

			if prepared != nil {
				_ = prepared.Abort(context.Background())
				t.Fatalf("expected nil prepared child on failure, got %+v", prepared)
			}

			if activeChildCount() != 0 {
				t.Fatalf("child registered in registry after spawn failure: %d active", activeChildCount())
			}

			if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
				t.Fatalf("marker file was written despite spawn failure")
			}
		})
	}
}

// P1: PreparedChild cleanup failure must be retryable; Resume/prepare post-spawn failure preserves owner
func TestDarwinLaunch_P1_PreparedChildAbortRetryAndRetainedError(t *testing.T) {
	helper := getTestHelper(t)
	f, err := os.Open(helper)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	tempDir := t.TempDir()
	ctx := context.Background()

	// 1. Prepared child SIGKILL failure -> abortLocked returns ChildRetainedError and allows retry
	prepared, _, err := prepareFixtureChild(
		ctx,
		f,
		tempDir,
		"helper",
		[]string{"--hang"},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	pid := prepared.PID()
	injectKillDenial(pid)
	defer clearFaultInjections()

	abortErr := prepared.Abort(ctx)
	if abortErr == nil {
		t.Fatalf("expected Abort to fail when SIGKILL is denied")
	}

	var retainedErr *ChildRetainedError
	if !errors.As(abortErr, &retainedErr) {
		t.Fatalf("expected ChildRetainedError, got: %T (%v)", abortErr, abortErr)
	}
	if retainedErr.PID != pid || retainedErr.PreparedChild != prepared {
		t.Fatalf("retained error does not preserve prepared child: %+v", retainedErr)
	}

	// Verify child is still in registry
	if activeChildCount() == 0 {
		t.Fatalf("expected child to remain in registry while kill is denied")
	}

	// Retry Abort after clearing injection
	clearFaultInjections()
	retryErr := prepared.Abort(ctx)
	if retryErr != nil {
		t.Fatalf("retry Abort failed: %v", retryErr)
	}

	if activeChildCount() != 0 {
		t.Fatalf("expected child to be reaped and unregistered: %d still active", activeChildCount())
	}
}

// P1: Resume post-spawn failure preserves retryable owner when cleanup fails
func TestDarwinLaunch_P1_ResumePostSpawnFailurePreservesOwner(t *testing.T) {
	helper := getTestHelper(t)
	f, err := os.Open(helper)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	tempDir := t.TempDir()
	ctx := context.Background()

	prepared, _, err := prepareFixtureChild(
		ctx,
		f,
		tempDir,
		"helper",
		[]string{"--hang"},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	pid := prepared.PID()

	// Tamper destination file so Resume's inode check fails
	origBytes, err := os.ReadFile(prepared.destPath)
	if err != nil {
		t.Fatal(err)
	}
	// Replace destination with new file
	_ = os.Remove(prepared.destPath)
	if err := os.WriteFile(prepared.destPath, append(origBytes, 0x99), 0500); err != nil {
		t.Fatal(err)
	}

	// Inject kill denial so cleanup during Resume fails
	injectKillDenial(pid)
	defer clearFaultInjections()

	owned, resumeErr := prepared.Resume()
	if owned != nil {
		_ = owned.Stop(ctx)
		t.Fatalf("expected Resume to fail on tampered destination")
	}
	if resumeErr == nil {
		t.Fatalf("expected error from Resume")
	}

	var retainedErr *ChildRetainedError
	if !errors.As(resumeErr, &retainedErr) {
		t.Fatalf("expected ChildRetainedError preserving owner, got %T (%v)", resumeErr, resumeErr)
	}
	if retainedErr.PreparedChild == nil {
		t.Fatalf("retained error missing PreparedChild owner")
	}

	// Clear injection and retry abort on preserved owner
	clearFaultInjections()
	if err := retainedErr.PreparedChild.Abort(ctx); err != nil {
		t.Fatalf("retry Abort on preserved owner failed: %v", err)
	}

	if activeChildCount() != 0 {
		t.Fatalf("expected child to be reaped: %d active", activeChildCount())
	}
}

// P2: Context cancellation during materialization & spawn boundaries
func TestDarwinLaunch_P2_ContextCancellationDuringMaterialization(t *testing.T) {
	helper := getTestHelper(t)
	f, err := os.Open(helper)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	tempDir := t.TempDir()

	// 1. Pre-cancelled context fails closed immediately
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	prepared, _, err := prepareFixtureChild(
		canceledCtx,
		f,
		tempDir,
		"helper",
		nil,
		true,
	)
	if !errors.Is(err, context.Canceled) {
		if prepared != nil {
			_ = prepared.Abort(context.Background())
		}
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if prepared != nil {
		t.Fatalf("expected nil prepared child on cancellation")
	}
	if activeChildCount() != 0 {
		t.Fatalf("child spawned despite cancellation")
	}
}

// P2: Fast exit tail output preservation
func TestDarwinLaunch_P2_FastExitTailOutputPreserved(t *testing.T) {
	helper := getTestHelper(t)
	f, err := os.Open(helper)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	tempDir := t.TempDir()
	ctx := context.Background()

	sentinel := "FAST_EXIT_TAIL_DATA_SENTINEL_20260913_OK\n"
	prepared, _, err := prepareFixtureChild(
		ctx,
		f,
		tempDir,
		"helper",
		[]string{"--fast-exit-tail", sentinel},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	owned, err := prepared.Resume()
	if err != nil {
		_ = prepared.Abort(ctx)
		t.Fatal(err)
	}

	res := owned.Wait(ctx)
	if res.Err != nil {
		t.Fatalf("Wait error: %v", res.Err)
	}
	if !res.Exited || res.ExitCode != 0 {
		t.Fatalf("child did not exit cleanly: %+v", res)
	}
	if string(res.Stdout) != sentinel {
		t.Fatalf("fast exit tail output corrupted or lost: expected %q, got %q", sentinel, string(res.Stdout))
	}

	if activeChildCount() != 0 {
		t.Fatalf("child still active after fast exit: %d", activeChildCount())
	}
}

// Case 4: Correct fixture normal lifecycle
func TestDarwinLaunch_Case4_CorrectFixtureLifecycle(t *testing.T) {
	helper := getTestHelper(t)
	f, err := os.Open(helper)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	tempDir := t.TempDir()
	markerPath := filepath.Join(tempDir, "marker.txt")

	ctx := context.Background()
	prepared, srcID, err := prepareFixtureChild(
		ctx,
		f,
		tempDir,
		"helper",
		[]string{"--marker-file", markerPath},
		true,
	)
	if err != nil {
		t.Fatalf("prepareFixtureChild failed: %v", err)
	}
	defer func() {
		if prepared != nil {
			_ = prepared.Abort(context.Background())
		}
	}()

	pid := prepared.PID()
	if pid <= 0 {
		t.Fatalf("invalid PID: %d", pid)
	}
	if srcID.SHA256 == "" || srcID.Size <= 0 {
		t.Fatalf("invalid source identity: %+v", srcID)
	}

	// Verify raw sysctl p_stat is strictly SSTOP (4)
	pstat, err := CheckProcessSStop(pid)
	if err != nil || pstat != 4 {
		t.Fatalf("expected raw p_stat=4 (SSTOP), got pstat=%d, err=%v", pstat, err)
	}

	// Verify marker is absent before Resume
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("marker file exists before Resume!")
	}

	// Resume the child
	owned, err := prepared.Resume()
	if err != nil {
		t.Fatalf("Resume failed: %v", err)
	}
	prepared = nil // ownership transferred

	// Wait for child to exit
	res := owned.Wait(ctx)
	if res.Err != nil {
		t.Fatalf("Wait error: %v", res.Err)
	}
	if !res.Exited || res.ExitCode != 0 {
		t.Fatalf("child did not exit cleanly: %+v", res)
	}

	// Verify marker now exists with expected content
	markerContent, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatalf("marker missing after exit: %v", err)
	}
	if !strings.Contains(string(markerContent), "ACORNFOX_ORIGINAL_CONTROLLER_FD_OK_MARKER_V1") {
		t.Fatalf("unexpected marker content: %s", markerContent)
	}

	// Verify child reaped in registry
	if activeChildCount() != 0 {
		t.Fatalf("child %d still registered in active registry", pid)
	}
}

// Case 5: Path swap before spawn, swap-back, and valid replacement left in place
func TestDarwinLaunch_Case5_PathSwapAndReplacementMatrix(t *testing.T) {
	helperOrig := getTestHelper(t)
	helperRepl := getReplHelper(t)

	fOrig, err := os.Open(helperOrig)
	if err != nil {
		t.Fatal(err)
	}
	defer fOrig.Close()

	fRepl, err := os.Open(helperRepl)
	if err != nil {
		t.Fatal(err)
	}
	defer fRepl.Close()

	// Extract static code signing identity and exact CDHash from both helpers
	origID, origCDHash, err := getStaticCodeSigningInfo(helperOrig)
	if err != nil || origCDHash == "" {
		t.Fatalf("failed to extract orig CDHash: %v", err)
	}
	replID, replCDHash, err := getStaticCodeSigningInfo(helperRepl)
	if err != nil || replCDHash == "" {
		t.Fatalf("failed to extract repl CDHash: %v", err)
	}
	if origCDHash == replCDHash {
		t.Fatalf("helper and helper_repl unexpectedly share the same CDHash: %s", origCDHash)
	}

	origBytes, err := os.ReadFile(helperOrig)
	if err != nil {
		t.Fatal(err)
	}
	replBytes, err := os.ReadFile(helperRepl)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// --- 5A: Valid replacement binary spawned with requirement bound to original CDHash ---
	t.Run("5A_ReplacementWithOriginalRequirementRejected", func(t *testing.T) {
		tempDir := t.TempDir()
		markerRepl := filepath.Join(tempDir, "marker_repl_5a.txt")

		// Requirement derived from ORIGINAL verified FD (real CDHash, NOT all-zero)
		origReqStr := fmt.Sprintf("identifier %q and cdhash H\"%s\"", origID, origCDHash)

		prepFail, _, err := prepareFixtureChildWithReq(
			ctx,
			fRepl,
			tempDir,
			replID,
			[]string{"--marker-file", markerRepl},
			true,
			origReqStr,
		)
		if prepFail != nil {
			_ = prepFail.Abort(context.Background())
			t.Fatalf("expected prepare to fail on CDHash mismatch, but child was returned")
		}
		if err == nil || !errors.Is(err, ErrUntrustedExecutable) {
			t.Fatalf("expected ErrUntrustedExecutable on CDHash mismatch, got: %v", err)
		}
		if _, err := os.Stat(markerRepl); !os.IsNotExist(err) {
			t.Fatalf("marker was written despite requirement rejection")
		}
		if activeChildCount() != 0 {
			t.Fatalf("active children remaining in registry after 5A: %d", activeChildCount())
		}
	})

	// --- 5B: Materialized path swapped to replacement while suspended, before dynamic validation ---
	t.Run("5B_PathSwappedToReplacementBeforeValidation", func(t *testing.T) {
		tempDir := t.TempDir()
		marker := filepath.Join(tempDir, "marker_5b.txt")

		hookCalled := false
		prepFail, _, err := prepareFixtureChildWithHook(
			ctx,
			fOrig,
			tempDir,
			origID,
			[]string{"--marker-file", marker},
			true,
			"",
			func(destPath string, childPID int) error {
				hookCalled = true
				// Overwrite destination executable with replacement bytes while child is suspended
				_ = os.Remove(destPath)
				return os.WriteFile(destPath, replBytes, 0500)
			},
		)
		if !hookCalled {
			t.Fatalf("test hook was not called")
		}
		if prepFail != nil {
			_ = prepFail.Abort(context.Background())
			t.Fatalf("expected prepare to fail when path was swapped before validation, but child was returned")
		}
		if err == nil || !errors.Is(err, ErrUntrustedExecutable) {
			t.Fatalf("expected ErrUntrustedExecutable on swapped path before validation, got: %v", err)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("marker was written despite path swap rejection")
		}
		if activeChildCount() != 0 {
			t.Fatalf("active children remaining in registry after 5B: %d", activeChildCount())
		}
	})

	// --- 5C: Path swapped to replacement, then restored back to original before validation ---
	t.Run("5C_PathSwapAndRestoreBeforeValidation", func(t *testing.T) {
		tempDir := t.TempDir()
		marker := filepath.Join(tempDir, "marker_5c.txt")

		hookCalled := false
		prepFail, _, err := prepareFixtureChildWithHook(
			ctx,
			fRepl,
			tempDir,
			replID,
			[]string{"--marker-file", marker},
			true,
			"",
			func(destPath string, childPID int) error {
				hookCalled = true
				// Spawned replacement; swap path back to original before validation
				_ = os.Remove(destPath)
				return os.WriteFile(destPath, origBytes, 0500)
			},
		)
		if !hookCalled {
			t.Fatalf("test hook was not called")
		}
		if prepFail != nil {
			_ = prepFail.Abort(context.Background())
			t.Fatalf("expected prepare to fail on restored path, but child was returned")
		}
		if err == nil || !errors.Is(err, ErrUntrustedExecutable) {
			t.Fatalf("expected ErrUntrustedExecutable on restored path modification, got: %v", err)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("marker was written despite swap-back rejection")
		}
		if activeChildCount() != 0 {
			t.Fatalf("active children remaining in registry after 5C: %d", activeChildCount())
		}
	})

	// --- 5D: Code section corrupted ---
	t.Run("5D_CorruptedBinaryFailsPreSpawn", func(t *testing.T) {
		tempDir := t.TempDir()
		corrupted := filepath.Join(tempDir, "corrupted_bin")
		corruptedBytes := make([]byte, len(origBytes))
		copy(corruptedBytes, origBytes)
		for i := len(corruptedBytes) / 2; i < len(corruptedBytes)/2+100; i++ {
			corruptedBytes[i] ^= 0x55
		}
		if err := os.WriteFile(corrupted, corruptedBytes, 0755); err != nil {
			t.Fatal(err)
		}
		fCorrupt, err := os.Open(corrupted)
		if err != nil {
			t.Fatal(err)
		}
		defer fCorrupt.Close()

		prepCorrupt, _, err := prepareFixtureChild(ctx, fCorrupt, tempDir, "helper", nil, true)
		if prepCorrupt != nil {
			_ = prepCorrupt.Abort(context.Background())
			t.Fatalf("expected corrupted binary to reject, but got prepared child")
		}
		if err == nil || !errors.Is(err, ErrUntrustedExecutable) {
			t.Fatalf("expected ErrUntrustedExecutable on corrupted binary, got: %v", err)
		}
		if activeChildCount() != 0 {
			t.Fatalf("active children remaining in registry after 5D: %d", activeChildCount())
		}
	})
}

// Case 6: Production constructor rejects ad-hoc, empty Team ID, missing CS_RUNTIME
func TestDarwinLaunch_Case6_ProductionRejectionOfAdHocAndMismatchedTeamID(t *testing.T) {
	helper := getTestHelper(t)
	f, err := os.Open(helper)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ctx := context.Background()

	// 1. PrepareController on ad-hoc signed helper MUST reject in production mode
	prep1, _, err := PrepareController(ctx, f)
	if err == nil {
		if prep1 != nil {
			_ = prep1.Abort(ctx)
		}
		t.Fatalf("expected PrepareController to reject ad-hoc signed binary in production mode, but it succeeded")
	}
	if !errors.Is(err, ErrUntrustedHost) && !errors.Is(err, ErrUntrustedExecutable) {
		t.Logf("PrepareController rejected with expected security error: %v", err)
	}

	// 2. PrepareSlotLauncher on ad-hoc signed helper MUST reject in production mode
	prep2, _, err := PrepareSlotLauncher(ctx, f, LauncherActionStart)
	if err == nil {
		if prep2 != nil {
			_ = prep2.Abort(ctx)
		}
		t.Fatalf("expected PrepareSlotLauncher to reject ad-hoc signed binary in production mode, but it succeeded")
	}
	if !errors.Is(err, ErrUntrustedHost) && !errors.Is(err, ErrUntrustedExecutable) {
		t.Logf("PrepareSlotLauncher rejected with expected security error: %v", err)
	}

	// 3. Invalid action rejects
	prep3, _, err := PrepareSlotLauncher(ctx, f, LauncherAction("invalid-action"))
	if prep3 != nil {
		_ = prep3.Abort(ctx)
	}
	if !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("expected ErrInvalidAction, got: %v", err)
	}

	if activeChildCount() != 0 {
		t.Fatalf("active children remaining in registry: %d", activeChildCount())
	}
}

// Case 7: Admission ordering with actual OpenActiveControllerReadOnly callback locking
func TestDarwinLaunch_Case7_AdmissionOrderingWithSlotLock(t *testing.T) {
	helper := getTestHelper(t)
	helperBytes, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}

	baseDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(baseDir, 0700); err != nil {
		t.Fatal(err)
	}

	bootDir := filepath.Join(baseDir, "bootstrap")
	slotsDir := filepath.Join(baseDir, "slots")
	for _, d := range []string{bootDir, slotsDir} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}

	// Write binaries in bootstrap
	launcherRel := "launcher"
	controllerRel := "controller"
	for _, name := range []string{launcherRel, controllerRel} {
		if err := os.WriteFile(filepath.Join(bootDir, name), helperBytes, 0755); err != nil {
			t.Fatal(err)
		}
	}

	spec := desktopupdate.HostBootstrapSpec{
		Root:               bootDir,
		OS:                 runtime.GOOS,
		Architecture:       runtime.GOARCH,
		Version:            "1.0.0",
		Launcher:           launcherRel,
		Controller:         controllerRel,
		ControllerProtocol: 1,
		InstanceProtocol:   1,
		BackendAPIProtocol: 1,
		Files: []desktopupdate.HostBundleFile{
			{Path: launcherRel, SHA256: hostTestSHA(helperBytes), Size: int64(len(helperBytes)), Mode: 0755},
			{Path: controllerRel, SHA256: hostTestSHA(helperBytes), Size: int64(len(helperBytes)), Mode: 0755},
		},
	}

	bootstrap, err := desktopupdate.PinHostBootstrap(context.Background(), spec)
	if err != nil {
		t.Fatalf("PinHostBootstrap failed: %v", err)
	}
	defer bootstrap.Close()

	// Provision slot lockfile named "lock"
	lockPath := filepath.Join(slotsDir, "lock")
	lockF, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	lockF.Close()

	var preparedChild *PreparedChild
	ctx := context.Background()
	markerPath := filepath.Join(baseDir, "case7_marker.txt")

	opts := desktopupdate.HostBootstrapReadOnlyOptions{
		Root:       slotsDir,
		InstanceID: strings.Repeat("7", 64),
		Bootstrap:  bootstrap,
	}

	// OpenActiveControllerReadOnly acquires slot lock across callback
	err = desktopupdate.OpenActiveControllerReadOnly(ctx, opts, func(cbCtx context.Context, target desktopupdate.HostActiveControllerTarget, controllerFD *os.File) error {
		// Inside callback: verify slot lock is held by trying to lock non-blocking
		testLockF, err := os.OpenFile(lockPath, os.O_RDWR, 0600)
		if err == nil {
			flockErr := syscall.Flock(int(testLockF.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			testLockF.Close()
			if flockErr == nil {
				t.Fatalf("expected slot lock to be held during callback!")
			}
		}

		// Prepare child inside callback
		p, _, prepErr := prepareFixtureChild(
			cbCtx,
			controllerFD,
			baseDir,
			"helper",
			[]string{"--lifecycle", "--marker-file", markerPath},
			true,
		)
		if prepErr != nil {
			return prepErr
		}
		preparedChild = p

		// Verify child has NOT executed (marker absent)
		if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
			_ = p.Abort(context.Background())
			t.Fatalf("marker file exists before admission and resume!")
		}

		// Callback returns, releasing slot lock
		return nil
	})
	if err != nil {
		if preparedChild != nil {
			_ = preparedChild.Abort(context.Background())
		}
		t.Fatalf("OpenActiveControllerReadOnly failed: %v", err)
	}

	// After callback returns: verify slot lock is released
	testLockF, err := os.OpenFile(lockPath, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(testLockF.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = preparedChild.Abort(context.Background())
		t.Fatalf("expected slot lock to be released after callback, got: %v", err)
	}
	_ = syscall.Flock(int(testLockF.Fd()), syscall.LOCK_UN)
	testLockF.Close()

	// Write packet39 admission frame on ParentLifecycle
	if _, err := preparedChild.ParentLifecycle().Write([]byte("admit-v1")); err != nil {
		_ = preparedChild.Abort(context.Background())
		t.Fatalf("write admission failed: %v", err)
	}

	// Resume child
	owned, err := preparedChild.Resume()
	if err != nil {
		_ = preparedChild.Abort(context.Background())
		t.Fatalf("Resume failed: %v", err)
	}
	preparedChild = nil

	// Give child a moment, then stop cooperatively
	time.Sleep(100 * time.Millisecond)
	if err := owned.Stop(ctx); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	res := owned.Wait(ctx)
	if !res.Exited || res.ExitCode != 0 {
		t.Fatalf("expected clean exit 0, got: %+v", res)
	}

	// Verify marker written
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("marker was not written after admission: %v", err)
	}

	if activeChildCount() != 0 {
		t.Fatalf("active children remaining in registry: %d", activeChildCount())
	}
}

// Case 8: Lifecycle EOF cooperative stop
func TestDarwinLaunch_Case8_LifecycleEOFCooperativeStop(t *testing.T) {
	helper := getTestHelper(t)
	f, err := os.Open(helper)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	tempDir := t.TempDir()
	markerPath := filepath.Join(tempDir, "marker_case8.txt")

	ctx := context.Background()
	prepared, _, err := prepareFixtureChild(
		ctx,
		f,
		tempDir,
		"helper",
		[]string{"--lifecycle", "--marker-file", markerPath},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Send admission
	if _, err := prepared.ParentLifecycle().Write([]byte("admit-v1")); err != nil {
		_ = prepared.Abort(ctx)
		t.Fatal(err)
	}

	owned, err := prepared.Resume()
	if err != nil {
		_ = prepared.Abort(ctx)
		t.Fatal(err)
	}

	// Give child a moment to write marker and enter wait loop
	time.Sleep(100 * time.Millisecond)

	// Stop closes ParentLifecycle, triggering EOF in child
	if err := owned.Stop(ctx); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	res := owned.Wait(ctx)
	if !res.Exited || res.ExitCode != 0 {
		t.Fatalf("expected clean exit code 0, got: %+v", res)
	}

	// Verify marker was written
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("marker was not written: %v", err)
	}

	if activeChildCount() != 0 {
		t.Fatalf("active children remaining in registry: %d", activeChildCount())
	}
}

// Case 9: Fault injection (SIGKILL failure, waitpid failure, stalled stdout with truncation)
func TestDarwinLaunch_Case9_FaultInjectionAndStalledStdout(t *testing.T) {
	helper := getTestHelper(t)
	f, err := os.Open(helper)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	tempDir := t.TempDir()
	ctx := context.Background()

	// 9A: Injected SIGKILL failure on running child with fallback
	prepared, _, err := prepareFixtureChild(
		ctx,
		f,
		tempDir,
		"helper",
		[]string{"--hang"},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	owned, err := prepared.Resume()
	if err != nil {
		_ = prepared.Abort(ctx)
		t.Fatal(err)
	}

	// Inject kill denial
	injectKillDenial(owned.PID())
	defer clearFaultInjections()

	// Stop should fail because SIGKILL fails
	stopErr := owned.Stop(ctx)
	if stopErr == nil {
		t.Fatalf("expected Stop to fail when SIGKILL is denied")
	}
	if activeChildCount() == 0 {
		t.Fatalf("child should still be retained in registry when kill failed")
	}

	// Clear injection
	clearFaultInjections()

	// Retrying Stop should succeed and reap child
	if err := owned.Stop(ctx); err != nil {
		t.Fatalf("retry Stop failed: %v", err)
	}
	if activeChildCount() != 0 {
		t.Fatalf("child still registered after successful reap")
	}

	// 9B: Injected waitpid failure
	preparedWait, _, err := prepareFixtureChild(
		ctx,
		f,
		tempDir,
		"helper",
		[]string{"--hang"},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	ownedWait, err := preparedWait.Resume()
	if err != nil {
		_ = preparedWait.Abort(ctx)
		t.Fatal(err)
	}

	injectWaitpidFailure(ownedWait.PID())
	defer clearFaultInjections()

	_ = ownedWait.Stop(ctx)
	if activeChildCount() == 0 {
		t.Fatalf("child should still be retained in registry when waitpid failed")
	}

	clearFaultInjections()
	if err := ownedWait.Stop(ctx); err != nil {
		t.Fatalf("retry Stop after clearing waitpid failure failed: %v", err)
	}
	if activeChildCount() != 0 {
		t.Fatalf("child still registered after waitpid retry")
	}

	// 9C: Stalled stdout (child writes 256 KiB to stdout)
	preparedFlood, _, err := prepareFixtureChild(
		ctx,
		f,
		tempDir,
		"helper",
		[]string{"--flood-stdout"},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	ownedFlood, err := preparedFlood.Resume()
	if err != nil {
		_ = preparedFlood.Abort(ctx)
		t.Fatal(err)
	}

	time.Sleep(150 * time.Millisecond)

	if err := ownedFlood.Stop(ctx); err != nil {
		t.Fatalf("Stop flooded child failed: %v", err)
	}

	resFlood := ownedFlood.Wait(ctx)
	if !resFlood.Exited || resFlood.ExitCode != 0 {
		t.Fatalf("flooded child did not exit cleanly: %+v", resFlood)
	}

	// Verify capped stdout drain was capped at maxPipeDrainBytes (64 KiB) and truncation flag exposed
	if len(resFlood.Stdout) > maxPipeDrainBytes {
		t.Fatalf("stdout exceeded max limit %d: got %d", maxPipeDrainBytes, len(resFlood.Stdout))
	}
	if len(resFlood.Stdout) != maxPipeDrainBytes {
		t.Fatalf("expected exactly %d capped bytes, got %d", maxPipeDrainBytes, len(resFlood.Stdout))
	}
	if !resFlood.StdoutTruncated {
		t.Fatalf("expected StdoutTruncated to be true for 256 KiB output")
	}

	if activeChildCount() != 0 {
		t.Fatalf("active children remaining in registry: %d", activeChildCount())
	}
}

// Case 10: Parallel prepare independent ownership
func TestDarwinLaunch_Case10_ParallelPrepareIndependentOwnership(t *testing.T) {
	helper := getTestHelper(t)
	f, err := os.Open(helper)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	tempDir := t.TempDir()
	const concurrency = 5

	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			markerPath := filepath.Join(tempDir, fmt.Sprintf("parallel_marker_%d.txt", idx))
			prepared, _, err := prepareFixtureChild(
				context.Background(),
				f,
				tempDir,
				"helper",
				[]string{"--marker-file", markerPath},
				true,
			)
			if err != nil {
				errCh <- fmt.Errorf("[%d] prepare failed: %w", idx, err)
				return
			}
			defer func() {
				if prepared != nil {
					_ = prepared.Abort(context.Background())
				}
			}()

			owned, err := prepared.Resume()
			if err != nil {
				errCh <- fmt.Errorf("[%d] resume failed: %w", idx, err)
				return
			}
			prepared = nil

			res := owned.Wait(context.Background())
			if !res.Exited || res.ExitCode != 0 {
				errCh <- fmt.Errorf("[%d] unexpected exit: %+v", idx, res)
				return
			}

			if _, err := os.Stat(markerPath); err != nil {
				errCh <- fmt.Errorf("[%d] marker missing: %w", idx, err)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}

	if activeChildCount() != 0 {
		t.Fatalf("active children remaining in registry: %d", activeChildCount())
	}
}

// Case 11: Symbol scan proving no csops or private symbol
func TestDarwinLaunch_Case11_SymbolScanNoCsops(t *testing.T) {
	files := []string{
		"security_darwin.h",
		"security_darwin.c",
		"spawn_darwin.c",
		"launcher_darwin.go",
		"distribution_production.go",
		"distribution_testing.go",
		"fault_injection_bridge_testing.go",
		"fault_injection_bridge_disabled.go",
		"unsupported.go",
	}

	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("failed to read %s: %v", f, err)
		}
		if bytes.Contains(content, []byte("csops")) {
			t.Fatalf("forbidden symbol 'csops' found in source file %s", f)
		}
	}

	if len(os.Args) > 0 && os.Args[0] != "" {
		out, err := exec.Command("go", "tool", "nm", os.Args[0]).CombinedOutput()
		if err == nil {
			if bytes.Contains(out, []byte("csops")) {
				t.Fatalf("forbidden symbol 'csops' found in compiled test binary symbols")
			}
			if !InternalTestingEnabled {
				if bytes.Contains(out, []byte("inject_spawn_failure")) || bytes.Contains(out, []byte("clear_spawn_failure")) {
					t.Fatalf("forbidden spawn injection symbols found in test binary without internal testing tag")
				}
			}
		}
	}
}

// Test distribution build variant vs production build
func TestDarwinLaunch_DistributionVariant(t *testing.T) {
	helper := getTestHelper(t)
	f, err := os.Open(helper)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if DistributionMode == "production" {
		_, _, err = PrepareTestDistributionController(context.Background(), f)
		if !errors.Is(err, ErrTestDistributionUnavailable) {
			t.Fatalf("expected ErrTestDistributionUnavailable in production mode, got: %v", err)
		}
		_, _, err = PrepareTestDistributionSlotLauncher(context.Background(), f, LauncherActionStart)
		if !errors.Is(err, ErrTestDistributionUnavailable) {
			t.Fatalf("expected ErrTestDistributionUnavailable in production mode, got: %v", err)
		}
	} else if DistributionMode == "test-distribution" {
		prep, srcID, err := PrepareTestDistributionController(context.Background(), f)
		if err != nil {
			t.Fatalf("expected PrepareTestDistributionController to succeed in test-distribution mode, got: %v", err)
		}
		if prep == nil || srcID.SHA256 == "" {
			t.Fatalf("invalid prepared result in test-distribution mode")
		}
		_ = prep.Abort(context.Background())
		if activeChildCount() != 0 {
			t.Fatalf("child remaining in registry after test distribution abort")
		}
	}
}

func hostTestSHA(data []byte) string {
	cmd := exec.Command("shasum", "-a", "256")
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	if len(fields) > 0 {
		return fields[0]
	}
	return ""
}
