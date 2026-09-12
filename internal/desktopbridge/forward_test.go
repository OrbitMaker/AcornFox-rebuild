package desktopbridge

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func forwardTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

func forwardHarness(t *testing.T, idle time.Duration) (client, backend *net.TCPConn, cancel context.CancelFunc, done <-chan struct{}) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, inbound := forwardTCPPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Error("proxy did not finish both copy goroutines after cancellation")
		}
	})
	target := Target{Host: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port)}
	go func() {
		proxyWithIdleTimeout(ctx, target, inbound, idle)
		close(finished)
	}()
	_ = listener.SetDeadline(time.Now().Add(3 * time.Second))
	backend, err = listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = backend.SetDeadline(time.Now().Add(5 * time.Second))
	return client, backend, cancel, finished
}

func waitForwardDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("proxy did not finish")
	}
}

func TestProxyDrainsResponseAfterRequestHalfClose(t *testing.T) {
	client, backend, _, done := forwardHarness(t, time.Second)
	request := bytes.Repeat([]byte("request"), 1<<16)
	response := bytes.Repeat([]byte("response"), 1<<18)
	serverDone := make(chan error, 1)
	go func() {
		got, err := io.ReadAll(backend)
		if err == nil && !bytes.Equal(got, request) {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			_, err = backend.Write(response)
		}
		if err == nil {
			err = backend.CloseWrite()
		}
		serverDone <- err
	}()
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(client)
	if err != nil || !bytes.Equal(got, response) {
		t.Fatalf("response truncated after request EOF: bytes=%d, want=%d, err=%v", len(got), len(response), err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	waitForwardDone(t, done)
}

func TestProxyActivityExtendsIdleDeadline(t *testing.T) {
	const idle = 150 * time.Millisecond
	client, backend, _, done := forwardHarness(t, idle)
	serverDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(backend, backend)
		_ = backend.CloseWrite()
		serverDone <- err
	}()
	start := time.Now()
	for range 12 {
		time.Sleep(30 * time.Millisecond)
		if _, err := client.Write([]byte("alive")); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 5)
		if _, err := io.ReadFull(client, got); err != nil || string(got) != "alive" {
			t.Fatalf("active connection expired: %q, %v", got, err)
		}
	}
	if time.Since(start) <= 2*idle {
		t.Fatal("test did not exceed the original absolute deadline")
	}
	_ = client.CloseWrite()
	if _, err := io.ReadAll(client); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	waitForwardDone(t, done)
}

func TestProxyIdleTimeoutClosesBothDirections(t *testing.T) {
	client, backend, _, done := forwardHarness(t, 40*time.Millisecond)
	waitForwardDone(t, done)
	for _, conn := range []net.Conn{client, backend} {
		if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("idle connection not closed: %v", err)
		}
	}
}

func TestProxyCancellationWakesBothCopies(t *testing.T) {
	client, backend, cancel, done := forwardHarness(t, time.Minute)
	cancel()
	waitForwardDone(t, done)
	for _, conn := range []net.Conn{client, backend} {
		if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("cancelled connection not closed: %v", err)
		}
	}
}

func TestProxyReadErrorWakesOtherCopy(t *testing.T) {
	client, backend, _, done := forwardHarness(t, time.Minute)
	// Abort the request stream so the proxy cannot wait a minute for a reply.
	if err := client.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	waitForwardDone(t, done)
	if _, err := backend.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("backend not closed after inbound reset: %v", err)
	}
}
