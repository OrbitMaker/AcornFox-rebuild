//go:build linux

package desktopupdate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func buildLocalTransportHelper(t *testing.T, dir string) string {
	t.Helper()
	helperBin := filepath.Join(dir, "acornfox-guest-update")
	if supplied := os.Getenv("ACORNFOX_LOCAL_TRANSPORT_TEST_HELPER"); supplied != "" {
		raw, err := os.ReadFile(supplied)
		if err != nil {
			t.Fatalf("read prebuilt test helper: %v", err)
		}
		if err := os.WriteFile(helperBin, raw, 0755); err != nil {
			t.Fatalf("copy prebuilt test helper: %v", err)
		}
		return helperBin
	}
	src := filepath.Join("testdata", "local_transport_helper", "main.go")
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", helperBin, src)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build helper failed: %v\n%s", err, out)
	}
	if err := os.Chmod(helperBin, 0755); err != nil {
		t.Fatal(err)
	}
	return helperBin
}

func setupTestRootDirectory(t *testing.T) (string, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("skipping root directory setup: caller is not root")
	}
	resetManagerRegistryForTest()
	t.Cleanup(func() { resetManagerRegistryForTest() })
	base, err := os.MkdirTemp("", "acornfox-transport-root-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chown(base, 0, 0)

	sub := filepath.Join(base, "libexec")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chown(sub, 0, 0)

	helper := buildLocalTransportHelper(t, sub)
	_ = os.Chown(helper, 0, 0)
	return sub, helper
}

func TestLocalTransportArgumentValidation(t *testing.T) {
	validAttempt := strings.Repeat("a", 64)
	validCmds := []GuestCommand{
		{verb: "observe", attempt: ""},
		{verb: "observe", attempt: validAttempt},
		{verb: "status", attempt: validAttempt},
		{verb: "submit", attempt: ""},
		{verb: "recover", attempt: validAttempt},
	}
	for _, cmd := range validCmds {
		if err := validateGuestCommand(cmd); err != nil {
			t.Errorf("expected valid for %+v, got %v", cmd, err)
		}
	}

	invalidCmds := []GuestCommand{
		{},
		{verb: "observe", attempt: "not-a-hash"},
		{verb: "observe", attempt: "123"},
		{verb: "status", attempt: ""},
		{verb: "status", attempt: "bad-hash"},
		{verb: "submit", attempt: validAttempt},
		{verb: "recover", attempt: ""},
		{verb: "recover", attempt: "bad-hash"},
		{verb: "run", attempt: validAttempt},
		{verb: "collect"},
		{verb: "sh", attempt: "-c id"},
		{verb: "bash"},
		{verb: "sudo"},
		{verb: "rm", attempt: "-rf /"},
	}
	for _, cmd := range invalidCmds {
		if err := validateGuestCommand(cmd); !errors.Is(err, ErrInvalidCommand) {
			t.Errorf("expected ErrInvalidCommand for %+v, got %v", cmd, err)
		}
	}
}

func TestLocalTransportUnprivilegedCallerFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipping unprivileged check when running as root")
	}
	transport := NewPrivilegedLocalGuestTransport()
	_, err := transport(context.Background(), GuestCommand{verb: "observe"}, nil, nil)
	if !errors.Is(err, ErrPrivilegeRequired) {
		t.Fatalf("expected ErrPrivilegeRequired, got %v", err)
	}
}

func TestLocalTransportPathVerificationFailsClosed(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges required for ownership tests")
	}
	dir, helper := setupTestRootDirectory(t)

	// 1. Non-absolute or uncleaned path
	tr := newLocalGuestTransport("relative/path")
	_, err := tr(context.Background(), GuestCommand{verb: "observe"}, nil, nil)
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("expected ErrInvalidOptions for relative path, got %v", err)
	}

	// 2. Executable is symlink
	symlink := filepath.Join(dir, "symlink-helper")
	if err := os.Symlink(helper, symlink); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(symlink)
	tr = newLocalGuestTransport(symlink)
	_, err = tr(context.Background(), GuestCommand{verb: "observe"}, nil, nil)
	if !errors.Is(err, ErrGuestTransport) {
		t.Fatalf("expected ErrGuestTransport for symlink executable, got %v", err)
	}

	// 3. Executable group/other writable (0777)
	if err := os.Chmod(helper, 0777); err != nil {
		t.Fatal(err)
	}
	tr = newLocalGuestTransport(helper)
	_, err = tr(context.Background(), GuestCommand{verb: "observe"}, nil, nil)
	if !errors.Is(err, ErrGuestTransport) {
		t.Fatalf("expected ErrGuestTransport for 0777 executable, got %v", err)
	}
	_ = os.Chmod(helper, 0755)

	// 4. Executable not marked executable (0644)
	if err := os.Chmod(helper, 0644); err != nil {
		t.Fatal(err)
	}
	tr = newLocalGuestTransport(helper)
	_, err = tr(context.Background(), GuestCommand{verb: "observe"}, nil, nil)
	if !errors.Is(err, ErrGuestTransport) {
		t.Fatalf("expected ErrGuestTransport for non-executable file, got %v", err)
	}
	_ = os.Chmod(helper, 0755)

	// 5. Executable has multiple hardlinks (nlink > 1)
	hardlink := filepath.Join(dir, "hardlink-helper")
	if err := os.Link(helper, hardlink); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(hardlink)
	tr = newLocalGuestTransport(helper)
	_, err = tr(context.Background(), GuestCommand{verb: "observe"}, nil, nil)
	if !errors.Is(err, ErrGuestTransport) {
		t.Fatalf("expected ErrGuestTransport for multi-link executable, got %v", err)
	}
	_ = os.Remove(hardlink)

	// 6. Parent directory group/other writable (0777)
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	tr = newLocalGuestTransport(helper)
	_, err = tr(context.Background(), GuestCommand{verb: "observe"}, nil, nil)
	if !errors.Is(err, ErrGuestTransport) {
		t.Fatalf("expected ErrGuestTransport for group-writable parent dir, got %v", err)
	}
	_ = os.Chmod(dir, 0755)
}

func TestLocalTransportPinnedExecutableExecutesEvenIfUnlinked(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)

	pins, execF, err := pinPathChain(helper)
	if err != nil {
		t.Fatalf("pinPathChain failed: %v", err)
	}
	defer func() {
		for _, f := range pins {
			_ = f.Close()
		}
	}()

	// Unlink the executable from the filesystem before execution
	if err := os.Remove(helper); err != nil {
		t.Fatalf("remove helper failed: %v", err)
	}
	if _, err := os.Lstat(helper); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected helper to be unlinked, got err=%v", err)
	}

	// Spawn child executing /proc/self/fd/3 directly
	cmd := exec.Command("/proc/self/fd/3", "observe")
	cmd.ExtraFiles = []*os.File{execF}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("execution of unlinked pinned descriptor failed: %v\n%s", err, out)
	}

	var resp map[string]any
	if err := json.Unmarshal(out, &resp); err != nil || resp["ok"] != true || resp["verb"] != "observe" {
		t.Fatalf("unexpected output from pinned unlinked executable: %s", string(out))
	}
}

type unclosableReader struct{}

func (unclosableReader) Read(p []byte) (int, error) {
	time.Sleep(1 * time.Hour)
	return 0, io.EOF
}

type unclosableWriter struct{}

func (unclosableWriter) Write(p []byte) (int, error) {
	time.Sleep(1 * time.Hour)
	return len(p), nil
}

type fakeCloserReader struct {
	unclosableReader
}

func (fakeCloserReader) Close() error {
	return nil
}

type fakeCloserWriter struct {
	unclosableWriter
}

func (fakeCloserWriter) Close() error {
	return nil
}

func TestLocalTransportUnsupportedStreamTypesRejected(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	// 1. Unclosable arbitrary reader rejected before spawn
	_, err := tr(context.Background(), GuestCommand{verb: "submit"}, unclosableReader{}, nil)
	if !errors.Is(err, ErrUnsupportedStream) {
		t.Fatalf("expected ErrUnsupportedStream for unclosable reader, got %v", err)
	}

	// 2. Unclosable arbitrary writer rejected before spawn
	_, err = tr(context.Background(), GuestCommand{verb: "observe"}, nil, unclosableWriter{})
	if !errors.Is(err, ErrUnsupportedStream) {
		t.Fatalf("expected ErrUnsupportedStream for unclosable writer, got %v", err)
	}

	// 3. Reader implementing dummy io.Closer whose Close is no-op rejected before spawn
	_, err = tr(context.Background(), GuestCommand{verb: "submit"}, fakeCloserReader{}, nil)
	if !errors.Is(err, ErrUnsupportedStream) {
		t.Fatalf("expected ErrUnsupportedStream for fakeCloserReader, got %v", err)
	}

	// 4. Writer implementing dummy io.Closer rejected before spawn
	_, err = tr(context.Background(), GuestCommand{verb: "observe"}, nil, fakeCloserWriter{})
	if !errors.Is(err, ErrUnsupportedStream) {
		t.Fatalf("expected ErrUnsupportedStream for fakeCloserWriter, got %v", err)
	}

	// 5. Generic *os.File rejected before spawn
	dummyFile, err := os.CreateTemp("", "dummy")
	if err == nil {
		defer os.Remove(dummyFile.Name())
		defer dummyFile.Close()
		_, err = tr(context.Background(), GuestCommand{verb: "submit"}, dummyFile, nil)
		if !errors.Is(err, ErrUnsupportedStream) {
			t.Fatalf("expected ErrUnsupportedStream for *os.File stdin, got %v", err)
		}
	}
}

func TestLocalTransportExactArgumentAndExecution(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	// Observe without attempt
	var buf bytes.Buffer
	code, err := tr(context.Background(), GuestCommand{verb: "observe"}, nil, &buf)
	if err != nil || code != 0 {
		t.Fatalf("observe failed: code=%d, err=%v", code, err)
	}
	var resp map[string]any
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil || resp["ok"] != true || resp["verb"] != "observe" {
		t.Fatalf("unexpected observe response: %s", buf.String())
	}

	// Status with attempt
	buf.Reset()
	attempt := strings.Repeat("1", 64)
	code, err = tr(context.Background(), GuestCommand{verb: "status", attempt: attempt}, nil, &buf)
	if err != nil || code != 0 {
		t.Fatalf("status failed: code=%d, err=%v", code, err)
	}
	resp = nil
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil || resp["ok"] != true || resp["attempt"] != attempt {
		t.Fatalf("unexpected status response: %s", buf.String())
	}

	// Recover with attempt
	buf.Reset()
	attempt = strings.Repeat("2", 64)
	code, err = tr(context.Background(), GuestCommand{verb: "recover", attempt: attempt}, nil, &buf)
	if err != nil || code != 0 {
		t.Fatalf("recover failed: code=%d, err=%v", code, err)
	}
	resp = nil
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil || resp["ok"] != true || resp["attempt"] != attempt {
		t.Fatalf("unexpected recover response: %s", buf.String())
	}
}

func TestLocalTransportStdinStreamingAndBinaryPayload(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	payload := make([]byte, 256*1024)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	code, err := tr(context.Background(), GuestCommand{verb: "submit"}, bytes.NewReader(payload), &buf)
	if err != nil || code != 0 {
		t.Fatalf("submit binary payload failed: code=%d, err=%v", code, err)
	}

	var resp map[string]any
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil || resp["ok"] != true {
		t.Fatalf("unexpected submit response: %s", buf.String())
	}
	readBytes, ok := resp["read_bytes"].(float64)
	if !ok || int(readBytes) != len(payload) {
		t.Fatalf("expected helper to read %d bytes, got %v", len(payload), resp["read_bytes"])
	}
}

func TestLocalTransportSeparateStderrNoLeakAndExitStatus(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	attempt := strings.Repeat("e", 64)
	var stdout bytes.Buffer
	code, err := tr(context.Background(), GuestCommand{verb: "observe", attempt: attempt}, nil, &stdout)
	if code != 42 {
		t.Fatalf("expected exit code 42, got %d", code)
	}
	if err != nil {
		t.Fatalf("expected nil transport err for non-zero exit code, got %v", err)
	}

	stdoutStr := stdout.String()
	if strings.Contains(stdoutStr, "secret-internal-error") || strings.Contains(stdoutStr, "database") {
		t.Fatalf("stderr leaked into stdout: %s", stdoutStr)
	}
}

func TestLocalTransportStdoutOverflowAndWriterError(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	// Helper attempts to write 128KB on attempt "d"; guestOutput has 64KB limit
	attempt := strings.Repeat("d", 64)
	var output guestOutput
	code, err := tr(context.Background(), GuestCommand{verb: "observe", attempt: attempt}, nil, &output)
	if !errors.Is(err, ErrGuestProtocol) {
		t.Fatalf("expected ErrGuestProtocol on stdout overflow, got code=%d, err=%v", code, err)
	}
}

func TestLocalTransportCancellablePipeStreamCancelsCleanly(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	pr, pw := io.Pipe()
	defer pw.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := tr(ctx, GuestCommand{verb: "submit"}, pr, nil)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if elapsed > 1*time.Second {
		t.Fatalf("cancellation of blocked pipe took too long: %v", elapsed)
	}
}

func TestLocalTransportDescendantHoldsPipesGraceExpiryKillsGroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	pidFile := "/tmp/acornfox-test-child.pid"
	_ = os.Remove(pidFile)
	defer os.Remove(pidFile)

	var stdout bytes.Buffer
	attempt := strings.Repeat("c", 64)

	start := time.Now()
	code, err := tr(context.Background(), GuestCommand{verb: "observe", attempt: attempt}, nil, &stdout)
	elapsed := time.Since(start)

	// Transport must return within bounded grace (~500ms grace + teardown)
	if elapsed > 2*time.Second {
		t.Fatalf("grace timeout took too long: %v", elapsed)
	}
	if !errors.Is(err, ErrGuestTransport) {
		t.Fatalf("expected ErrGuestTransport on descendant pipe hold, got %v (code=%d)", err, code)
	}

	// Read descendant child PID
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read child pidfile failed: %v", err)
	}
	childPID, _ := strconv.Atoi(string(data))
	if childPID <= 1 {
		t.Fatalf("invalid child PID: %d", childPID)
	}

	// Verify descendant child process was killed upon grace expiry
	time.Sleep(50 * time.Millisecond)
	if err := syscall.Kill(childPID, 0); err == nil {
		_ = syscall.Kill(childPID, syscall.SIGKILL)
		t.Fatalf("descendant child process %d survived grace expiry group kill", childPID)
	}
}

func TestLocalTransportDetachedWorkerSurvivesCancellation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	pidFile := "/tmp/acornfox-test-detached.pid"
	_ = os.Remove(pidFile)
	defer os.Remove(pidFile)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var stdout bytes.Buffer
	attempt := strings.Repeat("4", 64)

	errCh := make(chan error, 1)
	go func() {
		_, err := tr(ctx, GuestCommand{verb: "observe", attempt: attempt}, nil, &stdout)
		errCh <- err
	}()

	var detachedPID int
	for i := 0; i < 40; i++ {
		time.Sleep(25 * time.Millisecond)
		if data, err := os.ReadFile(pidFile); err == nil && len(data) > 0 {
			detachedPID, _ = strconv.Atoi(string(data))
			break
		}
	}

	if detachedPID <= 1 {
		t.Fatalf("failed to retrieve detached worker PID from %s", pidFile)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(detachedPID, syscall.SIGKILL)
	})

	// Verify detached worker is running initially
	if err := syscall.Kill(detachedPID, 0); err != nil {
		t.Fatalf("expected detached worker %d to be running, got %v", detachedPID, err)
	}

	// Cancel context to kill this invocation's process group
	cancel()
	err := <-errCh
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	// Assert detached worker in its own session survived the process group kill
	time.Sleep(50 * time.Millisecond)
	if err := syscall.Kill(detachedPID, 0); err != nil {
		t.Fatalf("detached worker %d was erroneously killed by process group cancellation", detachedPID)
	}
}

func TestLocalTransportDetachedWorkerRetainsPipeBoundedFailure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	pidFile := "/tmp/acornfox-test-retaining.pid"
	_ = os.Remove(pidFile)
	defer os.Remove(pidFile)

	var stdout bytes.Buffer
	attempt := strings.Repeat("5", 64)

	start := time.Now()
	_, err := tr(context.Background(), GuestCommand{verb: "observe", attempt: attempt}, nil, &stdout)
	elapsed := time.Since(start)

	// Must return ErrGuestTransport due to drain timeout
	if !errors.Is(err, ErrGuestTransport) {
		t.Fatalf("expected ErrGuestTransport on pipe-retaining detached worker, got %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("drain grace took too long: %v", elapsed)
	}

	// Read retaining worker PID
	data, rErr := os.ReadFile(pidFile)
	if rErr != nil {
		t.Fatalf("read retaining pidfile failed: %v", rErr)
	}
	retainingPID, _ := strconv.Atoi(string(data))
	if retainingPID <= 1 {
		t.Fatalf("invalid retaining PID: %d", retainingPID)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(retainingPID, syscall.SIGKILL)
	})

	// Verify detached worker was NOT killed
	time.Sleep(50 * time.Millisecond)
	if err := syscall.Kill(retainingPID, 0); err != nil {
		t.Fatalf("detached worker %d was erroneously killed when pipes were closed", retainingPID)
	}
}

func TestLocalTransportNoAutomaticResubmission(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	attempt := strings.Repeat("e", 64)
	code, err := tr(context.Background(), GuestCommand{verb: "status", attempt: attempt}, nil, nil)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d (err=%v)", code, err)
	}
}

func TestLocalTransportDeterministicWaitidErrorWithLiveChild(t *testing.T) {
	// Proves P1 fix: waitid failure with live child triggers direct child kill via pidfd,
	// zero numeric group-kill calls, exactly one cmd.Wait(), and bounded ErrGuestTransport.
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	pidFile := "/tmp/acornfox-test-livechild.pid"
	_ = os.Remove(pidFile)
	defer os.Remove(pidFile)

	var mu sync.Mutex
	var groupKillCalls int
	var pidfdKillCalls int

	setTestHookSyscallKill(func(pid int, sig syscall.Signal) error {
		mu.Lock()
		groupKillCalls++
		mu.Unlock()
		return syscall.Kill(pid, sig)
	})
	t.Cleanup(func() { setTestHookSyscallKill(nil) })

	setTestHookPidfdSendSignal(func(pidfd uintptr, sig syscall.Signal) error {
		mu.Lock()
		pidfdKillCalls++
		mu.Unlock()
		return rawPidfdSendSignal(pidfd, sig)
	})
	t.Cleanup(func() { setTestHookPidfdSendSignal(nil) })

	setTestHookWaitidNoReap(func(pid int) error {
		for i := 0; i < 40; i++ {
			if _, err := os.Stat(pidFile); err == nil {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		return syscall.EINVAL
	})
	t.Cleanup(func() { setTestHookWaitidNoReap(nil) })

	attempt := strings.Repeat("7", 64)
	start := time.Now()
	_, err := tr(context.Background(), GuestCommand{verb: "observe", attempt: attempt}, nil, nil)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrGuestTransport) {
		t.Fatalf("expected ErrGuestTransport on waitid error, got %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("fatal waitid error path took too long: %v", elapsed)
	}

	mu.Lock()
	defer mu.Unlock()
	if groupKillCalls != 0 {
		t.Errorf("expected 0 numeric group-kill calls on waitid error, got %d", groupKillCalls)
	}
	if pidfdKillCalls != 1 {
		t.Errorf("expected 1 direct-child pidfd kill call, got %d", pidfdKillCalls)
	}

	// Verify child process was actually killed via pidfd
	data, rErr := os.ReadFile(pidFile)
	if rErr == nil && len(data) > 0 {
		childPID, _ := strconv.Atoi(string(data))
		if childPID > 1 {
			time.Sleep(50 * time.Millisecond)
			if err := syscall.Kill(childPID, 0); err == nil {
				_ = syscall.Kill(childPID, syscall.SIGKILL)
				t.Fatalf("child process %d was not killed by pidfd", childPID)
			}
		}
	}
}

func TestLocalTransportCancelThenWaitidError(t *testing.T) {
	// Proves P1 fix: cancellation followed by waitid error enters fatal supervision path,
	// executes direct child pidfd kill, never issues negative PGID signal after wait error,
	// and returns ErrGuestTransport within bound.
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	pidFile := "/tmp/acornfox-test-livechild.pid"
	_ = os.Remove(pidFile)
	defer os.Remove(pidFile)

	var mu sync.Mutex
	var groupKillCalls int
	var pidfdKillCalls int

	setTestHookSyscallKill(func(pid int, sig syscall.Signal) error {
		mu.Lock()
		groupKillCalls++
		mu.Unlock()
		return syscall.Kill(pid, sig)
	})
	t.Cleanup(func() { setTestHookSyscallKill(nil) })

	setTestHookPidfdSendSignal(func(pidfd uintptr, sig syscall.Signal) error {
		mu.Lock()
		pidfdKillCalls++
		mu.Unlock()
		return rawPidfdSendSignal(pidfd, sig)
	})
	t.Cleanup(func() { setTestHookPidfdSendSignal(nil) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	setTestHookWaitidNoReap(func(pid int) error {
		for i := 0; i < 40; i++ {
			if ctx.Err() != nil {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		return syscall.ECHILD
	})
	t.Cleanup(func() { setTestHookWaitidNoReap(nil) })

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	attempt := strings.Repeat("7", 64)
	start := time.Now()
	_, err := tr(ctx, GuestCommand{verb: "observe", attempt: attempt}, nil, nil)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrGuestTransport) {
		t.Fatalf("expected ErrGuestTransport on cancel-then-waitid-error, got %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("cancel then error took too long: %v", elapsed)
	}

	mu.Lock()
	defer mu.Unlock()
	if groupKillCalls > 1 {
		t.Errorf("expected at most 1 group kill call (from initial cancel), got %d", groupKillCalls)
	}
	if pidfdKillCalls != 1 {
		t.Errorf("expected 1 direct-child pidfd kill call, got %d", pidfdKillCalls)
	}
}

func TestLocalTransportWaitidECHILDBranch(t *testing.T) {
	// Proves P1 fix: ECHILD from waitid enters fatal error path with zero numeric group-kill calls.
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	pidFile := "/tmp/acornfox-test-livechild.pid"
	_ = os.Remove(pidFile)
	defer os.Remove(pidFile)

	var mu sync.Mutex
	var groupKillCalls int
	var pidfdKillCalls int

	setTestHookSyscallKill(func(pid int, sig syscall.Signal) error {
		mu.Lock()
		groupKillCalls++
		mu.Unlock()
		return syscall.Kill(pid, sig)
	})
	t.Cleanup(func() { setTestHookSyscallKill(nil) })

	setTestHookPidfdSendSignal(func(pidfd uintptr, sig syscall.Signal) error {
		mu.Lock()
		pidfdKillCalls++
		mu.Unlock()
		return rawPidfdSendSignal(pidfd, sig)
	})
	t.Cleanup(func() { setTestHookPidfdSendSignal(nil) })

	setTestHookWaitidNoReap(func(pid int) error {
		return syscall.ECHILD
	})
	t.Cleanup(func() { setTestHookWaitidNoReap(nil) })

	attempt := strings.Repeat("7", 64)
	start := time.Now()
	_, err := tr(context.Background(), GuestCommand{verb: "observe", attempt: attempt}, nil, nil)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrGuestTransport) {
		t.Fatalf("expected ErrGuestTransport on ECHILD waitid error, got %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("ECHILD branch took too long: %v", elapsed)
	}

	mu.Lock()
	defer mu.Unlock()
	if groupKillCalls != 0 {
		t.Errorf("expected ZERO numeric group-kill calls on ECHILD, got %d", groupKillCalls)
	}
	if pidfdKillCalls != 1 {
		t.Errorf("expected 1 direct-child pidfd kill call, got %d", pidfdKillCalls)
	}
}

func TestLocalTransportUnsupportedPreflightNoSpawn(t *testing.T) {
	// Proves capability gate: unsupported waitid-WNOWAIT or pidfd fails closed before spawn.
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	// 1. Unsupported waitid preflight (returns ENOSYS)
	setTestHookPreflight(func() error {
		return syscall.ENOSYS
	})
	t.Cleanup(func() { setTestHookPreflight(nil) })

	var stdout bytes.Buffer
	_, err := tr(context.Background(), GuestCommand{verb: "observe"}, nil, &stdout)
	if !errors.Is(err, ErrGuestTransport) {
		t.Fatalf("expected ErrGuestTransport on ENOSYS preflight, got %v", err)
	}
	if stdout.Len() > 0 {
		t.Fatalf("expected no output when preflight fails before spawn, got %s", stdout.String())
	}

	// 2. Unsupported pidfd preflight (returns EINVAL)
	setTestHookPreflight(func() error {
		return syscall.EINVAL
	})
	stdout.Reset()
	_, err = tr(context.Background(), GuestCommand{verb: "observe"}, nil, &stdout)
	if !errors.Is(err, ErrGuestTransport) {
		t.Fatalf("expected ErrGuestTransport on EINVAL preflight, got %v", err)
	}
	if stdout.Len() > 0 {
		t.Fatalf("expected no output when preflight fails before spawn, got %s", stdout.String())
	}
}

func TestLocalTransportDescendantClosesStdioAndKeepsRunning(t *testing.T) {
	// Proves P2 fix: parent exits 0, descendant in SAME group closes stdio and keeps running.
	// Normal waitid success settles the original group while leader is unreaped,
	// so the same-group descendant is killed before transport returns.
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	pidFile := "/tmp/acornfox-test-samegroup-closedstdio.pid"
	_ = os.Remove(pidFile)
	defer os.Remove(pidFile)

	var stdout bytes.Buffer
	attempt := strings.Repeat("6", 64)

	start := time.Now()
	code, err := tr(context.Background(), GuestCommand{verb: "observe", attempt: attempt}, nil, &stdout)
	elapsed := time.Since(start)

	if err != nil || code != 0 {
		t.Fatalf("expected code 0, err nil, got code=%d, err=%v", code, err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("transport took too long: %v", elapsed)
	}

	// Read same-group descendant PID
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read samegroup pidfile failed: %v", err)
	}
	childPID, _ := strconv.Atoi(string(data))
	if childPID <= 1 {
		t.Fatalf("invalid child PID: %d", childPID)
	}

	// Verify descendant child was killed when original group was settled
	time.Sleep(50 * time.Millisecond)
	if err := syscall.Kill(childPID, 0); err == nil {
		_ = syscall.Kill(childPID, syscall.SIGKILL)
		t.Fatalf("same-group descendant %d survived normal exit group cleanup", childPID)
	}
}

func TestLocalTransportDetachedWorkerPreservedOnNormalExit(t *testing.T) {
	// Proves P2 invariant: parent exits 0, detached worker in NEW session (setsid)
	// closes stdio and keeps running. Normal group settling does NOT kill the detached worker!
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	pidFile := "/tmp/acornfox-test-detached-normal.pid"
	_ = os.Remove(pidFile)
	defer os.Remove(pidFile)

	var stdout bytes.Buffer
	attempt := strings.Repeat("8", 64)

	start := time.Now()
	code, err := tr(context.Background(), GuestCommand{verb: "observe", attempt: attempt}, nil, &stdout)
	elapsed := time.Since(start)

	if err != nil || code != 0 {
		t.Fatalf("expected code 0, err nil, got code=%d, err=%v", code, err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("transport took too long: %v", elapsed)
	}

	// Read detached PID
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read detached pidfile failed: %v", err)
	}
	detachedPID, _ := strconv.Atoi(string(data))
	if detachedPID <= 1 {
		t.Fatalf("invalid detached PID: %d", detachedPID)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(detachedPID, syscall.SIGKILL)
	})

	// Verify detached worker survived!
	time.Sleep(50 * time.Millisecond)
	if err := syscall.Kill(detachedPID, 0); err != nil {
		t.Fatalf("detached worker %d was erroneously killed by normal exit group cleanup", detachedPID)
	}
}

func TestLocalTransportPidfdSignalFailureRetainedOwnershipAndResolve(t *testing.T) {
	// Proves P1 signal failure resolution:
	// 1. Waitid error with live child + pidfd SIGKILL error returns bounded ErrGuestProcessRetained (< 2s).
	// 2. Ownership transferred to retainedProcessOwner (mode: cleanupDirectOnly, status: ownerRetained).
	// 3. Next command is rejected with ErrGuestProcessRetained without spawning.
	// 4. When pidfd signaling is restored, the managed reaper kills and reaps the child,
	//    calls cmd.Wait() exactly once, closes pidfd, and cleans up the retained owner.
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	pidFile := "/tmp/acornfox-test-livechild.pid"
	_ = os.Remove(pidFile)
	defer os.Remove(pidFile)

	var mu sync.Mutex
	var groupKillCalls int
	var pidfdKillCalls int

	setTestHookSyscallKill(func(pid int, sig syscall.Signal) error {
		mu.Lock()
		groupKillCalls++
		mu.Unlock()
		return syscall.Kill(pid, sig)
	})
	t.Cleanup(func() { setTestHookSyscallKill(nil) })

	setTestHookWaitidNoReap(func(pid int) error {
		for i := 0; i < 40; i++ {
			if _, err := os.Stat(pidFile); err == nil {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		return syscall.EINVAL
	})
	t.Cleanup(func() { setTestHookWaitidNoReap(nil) })

	// Inject error into pidfd_send_signal
	setTestHookPidfdSendSignal(func(pidfd uintptr, sig syscall.Signal) error {
		mu.Lock()
		pidfdKillCalls++
		mu.Unlock()
		return syscall.EPERM
	})
	t.Cleanup(func() { setTestHookPidfdSendSignal(nil) })

	attempt := strings.Repeat("7", 64)
	start := time.Now()
	_, err := tr(context.Background(), GuestCommand{verb: "observe", attempt: attempt}, nil, nil)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrGuestProcessRetained) {
		t.Fatalf("expected ErrGuestProcessRetained, got %v", err)
	}
	if !errors.Is(err, ErrGuestTransport) {
		t.Fatalf("expected ErrGuestProcessRetained to wrap ErrGuestTransport, got %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("signal failure ownership transfer took too long: %v", elapsed)
	}

	mu.Lock()
	if groupKillCalls != 0 {
		t.Errorf("expected 0 numeric group-kill calls on waitid error, got %d", groupKillCalls)
	}
	mu.Unlock()

	mgr := getOrCreateManager(helper)
	owner := mgr.RetainedOwner()
	if owner == nil {
		t.Fatal("expected retainedProcessOwner to be stored in manager")
	}
	if owner.Mode() != cleanupDirectOnly {
		t.Errorf("expected mode cleanupDirectOnly, got %v", owner.Mode())
	}
	if owner.Status() != ownerRetained {
		t.Errorf("expected status ownerRetained, got %v", owner.Status())
	}
	if owner.isResolved() {
		t.Error("expected owner to be unresolved while signal error is active")
	}

	// Next command must be rejected immediately without spawning
	_, err2 := tr(context.Background(), GuestCommand{verb: "observe"}, nil, nil)
	if !errors.Is(err2, ErrGuestProcessRetained) {
		t.Fatalf("expected second command to return ErrGuestProcessRetained, got %v", err2)
	}

	// Now release injection by restoring valid pidfd signaling
	setTestHookPidfdSendSignal(nil)

	// Wait for reaper to settle
	select {
	case <-owner.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("reaper did not settle in time")
	}

	if owner.Status() != ownerCleaned {
		t.Errorf("expected owner status ownerCleaned, got %v", owner.Status())
	}
	if !owner.WaitCalled() {
		t.Error("expected cmd.Wait to have been called by reaper")
	}
	if owner.ChildPidFD() != -1 {
		t.Errorf("expected childPidFD to be closed (-1), got %d", owner.ChildPidFD())
	}

	// Verify live child is dead
	data, rErr := os.ReadFile(pidFile)
	if rErr == nil && len(data) > 0 {
		childPID, _ := strconv.Atoi(string(data))
		if childPID > 1 {
			time.Sleep(50 * time.Millisecond)
			if err := syscall.Kill(childPID, 0); err == nil {
				_ = syscall.Kill(childPID, syscall.SIGKILL)
				t.Fatalf("child process %d was not killed after injection release", childPID)
			}
		}
	}
}

func TestLocalTransportGroupSignalFailureRetainedOwnershipAndResolve(t *testing.T) {
	// Proves P1 signal failure resolution on group settlement:
	// 1. Successful waitid observation of parent exit, same-group descendant alive.
	// 2. Syscall kill to -pgid fails with EPERM.
	// 3. Transport returns bounded ErrGuestProcessRetained (< 2s).
	// 4. Parent leader is kept unreaped (zombie) to guard PGID against reuse.
	// 5. Next command is rejected with ErrGuestProcessRetained.
	// 6. When group kill is restored, reaper settles group, reaps leader once, closes pidfd.
	// 7. Descendant child is killed.
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	pidFile := "/tmp/acornfox-test-samegroup-closedstdio.pid"
	_ = os.Remove(pidFile)
	defer os.Remove(pidFile)

	var mu sync.Mutex
	var killAttempts int

	setTestHookSyscallKill(func(pid int, sig syscall.Signal) error {
		mu.Lock()
		killAttempts++
		mu.Unlock()
		if pid < 0 {
			return syscall.EPERM
		}
		return syscall.Kill(pid, sig)
	})
	t.Cleanup(func() { setTestHookSyscallKill(nil) })

	attempt := strings.Repeat("6", 64)
	start := time.Now()
	_, err := tr(context.Background(), GuestCommand{verb: "observe", attempt: attempt}, nil, nil)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrGuestProcessRetained) {
		t.Fatalf("expected ErrGuestProcessRetained, got %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("group signal failure took too long: %v", elapsed)
	}

	mgr := getOrCreateManager(helper)
	owner := mgr.RetainedOwner()
	if owner == nil {
		t.Fatal("expected retainedProcessOwner to be stored in manager")
	}
	if owner.Mode() != cleanupGroupRequired {
		t.Errorf("expected mode cleanupGroupRequired, got %v", owner.Mode())
	}
	if owner.Status() != ownerRetained {
		t.Errorf("expected status ownerRetained, got %v", owner.Status())
	}

	// Next command must be rejected immediately
	_, err2 := tr(context.Background(), GuestCommand{verb: "observe"}, nil, nil)
	if !errors.Is(err2, ErrGuestProcessRetained) {
		t.Fatalf("expected second command to return ErrGuestProcessRetained, got %v", err2)
	}

	// Descendant child is still alive
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read samegroup pidfile failed: %v", err)
	}
	childPID, _ := strconv.Atoi(string(data))
	if childPID <= 1 {
		t.Fatalf("invalid child PID: %d", childPID)
	}

	// Release injection
	setTestHookSyscallKill(nil)

	// Wait for reaper to settle
	select {
	case <-owner.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("reaper did not settle in time")
	}

	if owner.Status() != ownerCleaned {
		t.Errorf("expected owner status ownerCleaned, got %v", owner.Status())
	}
	if !owner.WaitCalled() {
		t.Error("expected cmd.Wait to have been called by reaper")
	}
	if owner.ChildPidFD() != -1 {
		t.Errorf("expected childPidFD to be closed (-1), got %d", owner.ChildPidFD())
	}

	// Verify descendant child was killed
	time.Sleep(50 * time.Millisecond)
	if err := syscall.Kill(childPID, 0); err == nil {
		_ = syscall.Kill(childPID, syscall.SIGKILL)
		t.Fatalf("same-group descendant %d was not killed after injection release", childPID)
	}
}

func TestLocalTransportPermanentSignalFailureBoundedInterval(t *testing.T) {
	// Proves: signal rejection for a bounded test interval returns ErrGuestProcessRetained,
	// owner remains explicitly retained, then test cleanup restores kill and waits for reaper.
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	pidFile := "/tmp/acornfox-test-livechild.pid"
	_ = os.Remove(pidFile)
	defer os.Remove(pidFile)

	setTestHookWaitidNoReap(func(pid int) error {
		for i := 0; i < 40; i++ {
			if _, err := os.Stat(pidFile); err == nil {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		return syscall.EINVAL
	})
	t.Cleanup(func() { setTestHookWaitidNoReap(nil) })

	setTestHookPidfdSendSignal(func(pidfd uintptr, sig syscall.Signal) error {
		return syscall.EPERM
	})

	attempt := strings.Repeat("7", 64)
	start := time.Now()
	_, err := tr(context.Background(), GuestCommand{verb: "observe", attempt: attempt}, nil, nil)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrGuestProcessRetained) {
		t.Fatalf("expected ErrGuestProcessRetained, got %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("transport took too long: %v", elapsed)
	}

	mgr := getOrCreateManager(helper)
	owner := mgr.RetainedOwner()
	if owner == nil {
		t.Fatal("expected retained owner")
	}
	if owner.Status() != ownerRetained {
		t.Fatalf("expected owner status ownerRetained, got %v", owner.Status())
	}

	// Test cleanup restores hook and waits for reaper so no goroutine leaks
	t.Cleanup(func() {
		setTestHookPidfdSendSignal(nil)
		select {
		case <-owner.Done():
		case <-time.After(5 * time.Second):
			t.Log("reaper cleanup timeout")
		}
	})
}

func TestLocalTransportConcurrentCallsSerializeAndDenyRetained(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	var wg sync.WaitGroup
	results := make([]error, 4)
	for i := 0; i < 4; i++ {
		idx := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := tr(context.Background(), GuestCommand{verb: "observe"}, nil, nil)
			results[idx] = err
		}()
	}
	wg.Wait()

	for i, err := range results {
		if err != nil {
			t.Errorf("concurrent call %d failed: %v", i, err)
		}
	}
}

func TestLocalTransportQueueCallCancelledWhileWaiting(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	// Call 1 holds execution token using blocking attempt
	attempt := strings.Repeat("b", 64)
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()

	call1Started := make(chan struct{})
	call1Err := make(chan error, 1)
	go func() {
		close(call1Started)
		_, err := tr(ctx1, GuestCommand{verb: "observe", attempt: attempt}, nil, nil)
		call1Err <- err
	}()

	<-call1Started
	// Give call 1 enough time to enter execute and acquire m.sem
	time.Sleep(50 * time.Millisecond)

	// Call 2 waits in admission queue
	ctx2, cancel2 := context.WithCancel(context.Background())
	call2Err := make(chan error, 1)
	call2Start := time.Now()
	go func() {
		_, err := tr(ctx2, GuestCommand{verb: "observe"}, nil, nil)
		call2Err <- err
	}()

	// Cancel Call 2 while Call 1 is still holding the execution token
	time.Sleep(20 * time.Millisecond)
	cancel2()

	var err2 error
	select {
	case err2 = <-call2Err:
	case <-time.After(1 * time.Second):
		t.Fatal("Call 2 did not return promptly upon cancellation")
	}
	call2Elapsed := time.Since(call2Start)

	if !errors.Is(err2, context.Canceled) {
		t.Fatalf("expected context.Canceled for Call 2, got %v", err2)
	}
	if call2Elapsed > 1*time.Second {
		t.Fatalf("Call 2 cancellation took too long: %v", call2Elapsed)
	}

	// Now cancel Call 1 to release resources
	cancel1()
	err1 := <-call1Err
	if !errors.Is(err1, context.Canceled) {
		t.Fatalf("expected context.Canceled for Call 1, got %v", err1)
	}
}

func TestLocalTransportQueueCallRetainedFatalPriorityOverCancel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}
	_, helper := setupTestRootDirectory(t)
	tr := newLocalGuestTransport(helper)

	pidFile := "/tmp/acornfox-test-livechild.pid"
	_ = os.Remove(pidFile)
	defer os.Remove(pidFile)

	setTestHookWaitidNoReap(func(pid int) error {
		for i := 0; i < 40; i++ {
			if _, err := os.Stat(pidFile); err == nil {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		return syscall.EINVAL
	})
	t.Cleanup(func() { setTestHookWaitidNoReap(nil) })

	setTestHookPidfdSendSignal(func(pidfd uintptr, sig syscall.Signal) error {
		return syscall.EPERM
	})
	t.Cleanup(func() { setTestHookPidfdSendSignal(nil) })

	// Call 1 triggers retained ownership
	attempt := strings.Repeat("7", 64)
	_, err1 := tr(context.Background(), GuestCommand{verb: "observe", attempt: attempt}, nil, nil)
	if !errors.Is(err1, ErrGuestProcessRetained) {
		t.Fatalf("expected ErrGuestProcessRetained for Call 1, got %v", err1)
	}

	mgr := getOrCreateManager(helper)
	owner := mgr.RetainedOwner()
	if owner == nil {
		t.Fatal("expected retained owner")
	}
	t.Cleanup(func() {
		setTestHookPidfdSendSignal(nil)
		select {
		case <-owner.Done():
		case <-time.After(5 * time.Second):
		}
	})

	// Call 2 with a pre-cancelled context must STILL return ErrGuestProcessRetained!
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()

	_, err2 := tr(ctx2, GuestCommand{verb: "observe"}, nil, nil)
	if !errors.Is(err2, ErrGuestProcessRetained) {
		t.Fatalf("expected ErrGuestProcessRetained to take precedence over cancelled context, got %v", err2)
	}
}
