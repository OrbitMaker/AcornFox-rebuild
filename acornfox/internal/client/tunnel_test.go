package client

import (
	"context"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The tunnel tests reuse the re-exec fake-ssh pattern from client_test.go.
// FAKE_SSH_MODE=listen makes the fake ssh parse the -L argument and itself
// listen on 127.0.0.1:<local>, so OpenTunnel's TCP probe succeeds without a
// real forward. FAKE_SSH_MODE=stderr (defined in client_test.go) is reused for
// the failure cases.
//
// fakeSSHListen is dispatched from TestMain in client_test.go.

func fakeSSHListen() {
	bumpCounter()
	local := parseDashLLocal(os.Args)
	if local == "" {
		return
	}
	ln, err := net.Listen("tcp", local)
	if err != nil {
		return
	}
	defer ln.Close()
	// Accept connections until killed so the probe (and any later dial)
	// succeeds; each accepted conn is closed immediately.
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
	}
}

// parseDashLLocal extracts "127.0.0.1:<local>" from a "-L a:b:c:d" spec in the
// argv: the forward is "127.0.0.1:<local>:127.0.0.1:<remote>".
func parseDashLLocal(args []string) string {
	for i, a := range args {
		if a == "-L" && i+1 < len(args) {
			parts := strings.Split(args[i+1], ":")
			if len(parts) == 4 {
				return parts[0] + ":" + parts[1]
			}
		}
	}
	return ""
}

func TestTunnelArgs(t *testing.T) {
	got := tunnelArgs(Target{SSH: "ubuntu@1.2.3.4", Port: 2222, Identity: "/k/id"}, 54321)
	want := []string{
		"-N", "-T",
		"-o", "BatchMode=yes",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "ServerAliveInterval=15",
		"-L", "127.0.0.1:54321:127.0.0.1:18800",
		"-p", "2222", "-i", "/k/id", "ubuntu@1.2.3.4",
	}
	if !equalStrings(got, want) {
		t.Errorf("argv = %v\nwant %v", got, want)
	}
}

func TestOpenTunnelSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-ssh via re-exec assumes unix-style process control")
	}
	withFakeSSH(t)
	t.Setenv("FAKE_SSH_MODE", "listen")

	port := freeTCPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tun, err := OpenTunnel(ctx, Target{SSH: "devbox"}, port)
	if err != nil {
		t.Fatalf("OpenTunnel: %v", err)
	}
	defer tun.Close()

	if tun.LocalURL == "" || !strings.Contains(tun.LocalURL, "127.0.0.1") {
		t.Errorf("LocalURL = %q", tun.LocalURL)
	}
	// The forwarded port must be reachable (the fake ssh is listening).
	c, err := net.DialTimeout("tcp", strings.TrimPrefix(tun.LocalURL, "http://"), 2*time.Second)
	if err != nil {
		t.Fatalf("dial forwarded port: %v", err)
	}
	_ = c.Close()

	// Closing ends the tunnel; Done must fire.
	if err := tun.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	select {
	case <-tun.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("Done not closed after Close")
	}
}

func TestOpenTunnelForwardingDisabled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-ssh via re-exec assumes unix-style process control")
	}
	withFakeSSH(t)
	t.Setenv("FAKE_SSH_MODE", "stderr")
	t.Setenv("FAKE_SSH_STDERR", "channel 0: open failed: administratively prohibited: open failed")
	t.Setenv("FAKE_SSH_EXIT", "255")

	port := freeTCPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := OpenTunnel(ctx, Target{SSH: "devbox"}, port)
	var e *Error
	if !asError(err, &e) {
		t.Fatalf("want *Error, got %v", err)
	}
	if e.Diag.Stage != stageConnect || e.Diag.Code != codeForwardingOff {
		t.Errorf("want connect/forwarding_disabled, got %s/%s", e.Diag.Stage, e.Diag.Code)
	}
}

func TestOpenTunnelProcessExits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-ssh via re-exec assumes unix-style process control")
	}
	withFakeSSH(t)
	t.Setenv("FAKE_SSH_MODE", "stderr")
	t.Setenv("FAKE_SSH_STDERR", "ssh: connect to host x port 22: Connection refused")
	t.Setenv("FAKE_SSH_EXIT", "255")

	port := freeTCPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := OpenTunnel(ctx, Target{SSH: "devbox"}, port)
	var e *Error
	if !asError(err, &e) {
		t.Fatalf("want *Error, got %v", err)
	}
	if e.Diag.Code != codeHostUnreachable {
		t.Errorf("code = %q, want host_unreachable", e.Diag.Code)
	}
}

func TestOpenTunnelSSHMissing(t *testing.T) {
	old := sshPath
	sshPath = "ssh"
	t.Cleanup(func() { sshPath = old })
	t.Setenv("PATH", t.TempDir())

	_, err := OpenTunnel(context.Background(), Target{SSH: "devbox"}, freeTCPPort(t))
	var e *Error
	if !asError(err, &e) {
		t.Fatalf("want *Error, got %v", err)
	}
	if e.Diag.Code != codeSSHMissing {
		t.Errorf("code = %q, want ssh_missing", e.Diag.Code)
	}
}

// freeTCPPort reserves an ephemeral port and returns it (closed immediately so
// the fake ssh can bind it). Small races are acceptable in tests.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// ensure http is referenced (kept for parity with client_test helpers).
var _ = http.MethodGet
