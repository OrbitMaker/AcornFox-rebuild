//go:build linux

package desktopbridge

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// AF_UNIX and AF_INET exercise the same Linux fd/runtime-poll transport without
// requiring /dev/vsock. The AF_VSOCK bind itself still needs a real guest test.
func vsockPair(t *testing.T) (*vsockConn, *vsockConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	first, err := newVsockConn(fds[0], vsockAddr{}, vsockAddr{})
	if err != nil {
		_ = syscall.Close(fds[1])
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := newVsockConn(fds[1], vsockAddr{}, vsockAddr{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	for _, conn := range []*vsockConn{first, second} {
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	return first, second
}

func vsockTCPListener(t *testing.T) (*vsockListener, *net.TCPAddr) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		_ = syscall.Close(fd)
		t.Fatal(err)
	}
	if err := syscall.Listen(fd, 8); err != nil {
		_ = syscall.Close(fd)
		t.Fatal(err)
	}
	address, err := syscall.Getsockname(fd)
	if err != nil {
		_ = syscall.Close(fd)
		t.Fatal(err)
	}
	listener, err := newVsockListener(fd, vsockAddr{port: GuestHTTPPort})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: address.(*syscall.SockaddrInet4).Port}
}

func awaitVsockResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("socket operation failed to wake")
		return nil
	}
}

func assertVsockTimeout(t *testing.T, err error) {
	t.Helper()
	var timeout net.Error
	if !errors.Is(err, os.ErrDeadlineExceeded) || !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("expected deadline net.Error, got %v", err)
	}
}

func assertVsockFDFlags(t *testing.T, raw syscall.RawConn) {
	t.Helper()
	var flags, descriptorFlags uintptr
	var flagErr syscall.Errno
	if err := raw.Control(func(fd uintptr) {
		flags, _, flagErr = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
		if flagErr == 0 {
			descriptorFlags, _, flagErr = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if flagErr != 0 || flags&syscall.O_NONBLOCK == 0 || descriptorFlags&syscall.FD_CLOEXEC == 0 {
		t.Fatalf("fd flags = %x/%x, error = %v", flags, descriptorFlags, flagErr)
	}
}

func TestVsockAcceptPollsAndSetsFDFlags(t *testing.T) {
	listener, address := vsockTCPListener(t)
	assertVsockFDFlags(t, listener.raw)
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			_, err = conn.Write([]byte("accepted"))
		}
		done <- err
	}()
	// With no pending connection, Accept must wait instead of returning EAGAIN.
	select {
	case err := <-done:
		t.Fatalf("Accept returned before a connection: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	peer, err := net.DialTimeout("tcp", address.String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	_ = peer.SetDeadline(time.Now().Add(time.Second))
	got, err := io.ReadAll(peer)
	if err != nil || string(got) != "accepted" {
		t.Fatalf("accepted stream = %q, %v", got, err)
	}
	if err := awaitVsockResult(t, done); err != nil {
		t.Fatal(err)
	}
	// Inspect an accepted descriptor directly as well.
	peer2, err := net.DialTimeout("tcp", address.String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer peer2.Close()
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	assertVsockFDFlags(t, conn.(*vsockConn).raw)
}

func TestVsockCloseWakesConcurrentAccept(t *testing.T) {
	listener, _ := vsockTCPListener(t)
	done := make(chan error, 3)
	for range 3 {
		go func() { _, err := listener.Accept(); done <- err }()
	}
	time.Sleep(20 * time.Millisecond)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := awaitVsockResult(t, done); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close = %v", err)
		}
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed Accept = %v", err)
	}
}

func TestVsockReadDeadlineAndRecovery(t *testing.T) {
	conn, peer := vsockPair(t)
	done := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); done <- err }()
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	assertVsockTimeout(t, awaitVsockResult(t, done))
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte("r")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := io.ReadFull(conn, buffer); err != nil || string(buffer) != "r" {
		t.Fatalf("read after clearing deadline = %q, %v", buffer, err)
	}
}

func TestVsockWriteDeadlineAndRecovery(t *testing.T) {
	conn, peer := vsockPair(t)
	if err := conn.raw.Control(func(fd uintptr) { _ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4096) }); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 2<<20)
	n, err := conn.Write(payload)
	assertVsockTimeout(t, err)
	if n <= 0 || n >= len(payload) {
		t.Fatalf("write did not exercise a partially filled buffer: %d", n)
	}
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := io.Copy(io.Discard, peer); done <- err }()
	if _, err := conn.Write([]byte("recovered")); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := awaitVsockResult(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestVsockSetDeadlineAppliesToBothDirections(t *testing.T) {
	conn, _ := vsockPair(t)
	if err := conn.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := conn.Read(make([]byte, 1))
	assertVsockTimeout(t, err)
	_, err = conn.Write([]byte("x"))
	assertVsockTimeout(t, err)
}

func TestVsockCloseWakesReadAndWrite(t *testing.T) {
	conn, _ := vsockPair(t)
	done := make(chan error, 2)
	go func() { _, err := conn.Read(make([]byte, 1)); done <- err }()
	go func() { _, err := conn.Write(make([]byte, 2<<20)); done <- err }()
	time.Sleep(20 * time.Millisecond)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := awaitVsockResult(t, done); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked I/O after Close = %v", err)
		}
	}
	if err := conn.CloseWrite(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("CloseWrite after Close = %v", err)
	}
}

func TestVsockFullDuplexAndHalfClose(t *testing.T) {
	first, second := vsockPair(t)
	left := bytes.Repeat([]byte("left"), 1<<18)
	right := bytes.Repeat([]byte("right"), 1<<18)
	done := make(chan error, 4)
	for _, item := range []struct {
		conn *vsockConn
		want []byte
		send []byte
	}{{first, right, left}, {second, left, right}} {
		go func() {
			_, err := item.conn.Write(item.send)
			if err == nil {
				err = item.conn.CloseWrite()
			}
			done <- err
		}()
		go func() {
			got, err := io.ReadAll(item.conn)
			if err == nil && !bytes.Equal(got, item.want) {
				err = errors.New("full duplex payload mismatch")
			}
			done <- err
		}()
	}
	for range 4 {
		if err := awaitVsockResult(t, done); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVsockHalfCloseAllowsResponseAfterRequestEOF(t *testing.T) {
	conn, peer := vsockPair(t)
	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(peer)
	if err != nil || string(request) != "request" {
		t.Fatalf("half-closed request = %q, %v", request, err)
	}
	if _, err := peer.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(conn)
	if err != nil || string(response) != "response" {
		t.Fatalf("response after request EOF = %q, %v", response, err)
	}
}

func TestVsockCloseReadWakesRead(t *testing.T) {
	conn, _ := vsockPair(t)
	done := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); done <- err }()
	if err := conn.CloseRead(); err != nil {
		t.Fatal(err)
	}
	if err := awaitVsockResult(t, done); err != io.EOF {
		t.Fatalf("read after CloseRead = %v", err)
	}
}

func TestVsockConstructionFailureClosesFD(t *testing.T) {
	fd, err := syscall.Open("/dev/null", syscall.O_RDWR|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file, _, err := newVsockFile(fd)
	if err == nil {
		_ = file.Close()
		t.Fatal("non-pollable descriptor accepted")
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != syscall.EBADF {
		t.Fatalf("constructor leaked fd: Fstat = %v", err)
	}
}

func TestListenVsockRejectsArbitraryPortBeforeSocketCreation(t *testing.T) {
	if _, err := ListenVsock(12345); err == nil {
		t.Fatal("unexpected arbitrary destination listener")
	}
}
