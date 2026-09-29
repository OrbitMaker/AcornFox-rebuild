//go:build !windows

// This file implements the "acornfox proxy" subcommand (N2). On the server the
// CLI reaches the API over SSH: `ssh ... acornfox proxy` connects to the local
// API unix socket and relays a single byte stream between the SSH session's
// stdin/stdout and the socket. See docs/n2-contract.md section 1.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
)

// Exit codes the client relies on to classify a proxy dial failure (contract
// section 1: connect/permission_denied and connect/server_down).
const (
	proxyExitPermissionDenied = 13
	proxyExitServerDown       = 14
)

// runProxy dials the server's API unix socket and relays stdin/stdout to it.
// It exits when either direction closes. Dial errors map to a stderr message
// and a distinct exit code so the client can classify them.
func runProxy(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", "/run/acornfox/api.sock", "server API unix socket to relay to")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	conn, err := net.Dial("unix", *socket)
	if err != nil {
		return proxyDialError(stderr, err)
	}
	defer conn.Close()

	// Relay both directions. stdin->conn runs in the background; the call
	// returns once conn->stdout finishes (the server closed its side or the
	// stream ended), which guarantees all bytes have been written to stdout
	// before returning. Closing conn unblocks the background copy on return.
	go func() {
		_, _ = io.Copy(conn, stdin)
		// Signal EOF to the server so it can flush its response.
		if uc, ok := conn.(*net.UnixConn); ok {
			_ = uc.CloseWrite()
		}
	}()
	_, _ = io.Copy(stdout, conn)
	return 0
}

// proxyDialError writes the classified message for a failed dial and returns
// the matching exit code.
func proxyDialError(stderr io.Writer, err error) int {
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		fmt.Fprintln(stderr, "acornfox proxy: permission denied")
		return proxyExitPermissionDenied
	}
	// Missing socket file or refused connection => the server is not running.
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) || os.IsNotExist(err) {
		fmt.Fprintln(stderr, "acornfox proxy: server not running")
		return proxyExitServerDown
	}
	// Any other dial failure is treated as the server being down.
	fmt.Fprintln(stderr, "acornfox proxy: server not running")
	return proxyExitServerDown
}
