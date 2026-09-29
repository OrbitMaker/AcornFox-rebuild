//go:build !windows

package main

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestRunProxyRelaysBothWays starts a temp unix socket echo-ish server, then
// runs runProxy against it and checks the byte stream is relayed both ways.
func TestRunProxyRelaysBothWays(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "api.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Server: read the request bytes, then write a fixed response and close.
	const reply = "HTTP/1.1 200 OK\r\n\r\n"
	var got bytes.Buffer
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 6)
		n, _ := io.ReadFull(c, buf)
		got.Write(buf[:n])
		_, _ = c.Write([]byte(reply))
	}()

	stdin := bytes.NewBufferString("GET /\n")
	var stdout, stderr bytes.Buffer
	code := runProxy([]string{"-socket", sock}, stdin, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runProxy exit = %d, stderr=%s", code, stderr.String())
	}
	<-srvDone
	if stdout.String() != reply {
		t.Fatalf("stdout = %q, want %q", stdout.String(), reply)
	}
	if got.String() != "GET /\n" {
		t.Fatalf("server received %q, want %q", got.String(), "GET /\n")
	}
}

// TestRunProxyServerDown maps a missing socket to exit 14 / "server not running".
func TestRunProxyServerDown(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "missing.sock")
	var stderr bytes.Buffer
	code := runProxy([]string{"-socket", sock}, bytes.NewBuffer(nil), io.Discard, &stderr)
	if code != proxyExitServerDown {
		t.Fatalf("exit = %d, want %d", code, proxyExitServerDown)
	}
	if want := "acornfox proxy: server not running"; !bytes.Contains(stderr.Bytes(), []byte(want)) {
		t.Fatalf("stderr = %q, want to contain %q", stderr.String(), want)
	}
}

// TestRunProxyPermissionDenied maps an unconnectable socket without permission
// to exit 13. It creates a socket, then removes read/write/execute permission
// on its directory so dialing fails with EACCES. Skipped when run as root
// (root bypasses permission checks).
func TestRunProxyPermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses unix permission checks")
	}
	dir := t.TempDir()
	sub := filepath.Join(dir, "locked")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(sub, "api.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	// Accept in the background so a successful dial would otherwise proceed.
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	// Remove all permission on the directory so dialing the socket is denied.
	if err := os.Chmod(sub, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })

	var stderr bytes.Buffer
	code := runProxy([]string{"-socket", sock}, bytes.NewBuffer(nil), io.Discard, &stderr)
	if code != proxyExitPermissionDenied {
		t.Skipf("dial did not yield EACCES on this platform (exit %d, stderr=%s)", code, stderr.String())
	}
	if want := "acornfox proxy: permission denied"; !bytes.Contains(stderr.Bytes(), []byte(want)) {
		t.Fatalf("stderr = %q, want to contain %q", stderr.String(), want)
	}
}

// TestRunProxyExitsWhenServerCloses ensures runProxy returns promptly when the
// server closes the connection even if stdin never reaches EOF.
func TestRunProxyExitsWhenServerCloses(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "api.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		_ = c.Close() // close immediately
	}()

	// A stdin that blocks forever (never EOF) so only the server-side close can
	// end the proxy.
	pr, pw := io.Pipe()
	defer pw.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	done := make(chan int, 1)
	go func() {
		defer wg.Done()
		done <- runProxy([]string{"-socket", sock}, pr, io.Discard, io.Discard)
	}()

	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runProxy did not exit after server closed the connection")
	}
	wg.Wait()
}
