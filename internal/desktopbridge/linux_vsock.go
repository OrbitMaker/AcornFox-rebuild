//go:build linux

package desktopbridge

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const afVSock = 40

type sockaddrVM struct {
	Family    uint16
	Reserved1 uint16
	Port      uint32
	CID       uint32
	Zero      [4]byte
}

type vsockListener struct {
	file   *os.File
	raw    syscall.RawConn
	addr   vsockAddr
	closed atomic.Bool
}

// ListenVsock binds a guest-side virtio socket listener. The standard library's
// Sockaddr and net.FileConn do not support AF_VSOCK. Use raw bind/accept and let
// os.File register the nonblocking descriptors with Go's runtime poller.
func ListenVsock(port uint32) (net.Listener, error) {
	if _, err := TargetForPort(port); err != nil {
		return nil, err
	}
	fd, err := syscall.Socket(afVSock, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	addr := sockaddrVM{Family: afVSock, Port: port, CID: 0xffffffff}
	if _, _, errno := syscall.Syscall(syscall.SYS_BIND, uintptr(fd), uintptr(unsafe.Pointer(&addr)), unsafe.Sizeof(addr)); errno != 0 {
		_ = syscall.Close(fd)
		return nil, errno
	}
	if err := syscall.Listen(fd, maxConnections); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return newVsockListener(fd, vsockAddr{cid: addr.CID, port: port})
}

// newVsockFile takes ownership of fd, including on failure. fd must already be
// nonblocking and close-on-exec; NewFile detects O_NONBLOCK to enable polling.
func newVsockFile(fd int) (*os.File, syscall.RawConn, error) {
	file := os.NewFile(uintptr(fd), "acornfox-vsock")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, nil, syscall.EBADF
	}
	raw, err := file.SyscallConn()
	if err == nil {
		// Fail during construction if this descriptor cannot support deadlines.
		err = file.SetDeadline(time.Time{})
	}
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return file, raw, nil
}

func newVsockListener(fd int, addr vsockAddr) (*vsockListener, error) {
	file, raw, err := newVsockFile(fd)
	if err != nil {
		return nil, err
	}
	return &vsockListener{file: file, raw: raw, addr: addr}, nil
}

func (l *vsockListener) Accept() (net.Conn, error) {
	var accepted int
	var acceptErr error
	var peer sockaddrVM
	err := l.raw.Read(func(fd uintptr) bool {
		for {
			length := uint32(unsafe.Sizeof(peer))
			// syscall.Accept4 converts the returned sockaddr and rejects AF_VSOCK.
			n, _, errno := syscall.Syscall6(syscall.SYS_ACCEPT4, fd, uintptr(unsafe.Pointer(&peer)), uintptr(unsafe.Pointer(&length)), syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0, 0)
			switch errno {
			case 0:
				accepted = int(n)
				return true
			case syscall.EINTR, syscall.ECONNABORTED:
				continue
			case syscall.EAGAIN:
				return false // Runtime poll: Close wakes this wait.
			default:
				acceptErr = errno
				return true
			}
		}
	})
	if err != nil {
		if l.closed.Load() {
			err = net.ErrClosed
		}
		return nil, vsockError("accept", l.addr, nil, err)
	}
	if acceptErr != nil {
		return nil, vsockError("accept", l.addr, nil, acceptErr)
	}
	remote := vsockAddr{cid: peer.CID, port: peer.Port}
	conn, err := newVsockConn(accepted, l.addr, remote)
	if err != nil {
		return nil, vsockError("accept", l.addr, remote, err)
	}
	return conn, nil
}

func (l *vsockListener) Close() error {
	l.closed.Store(true)
	return vsockError("close", l.addr, nil, l.file.Close())
}
func (l *vsockListener) Addr() net.Addr { return l.addr }

type vsockConn struct {
	file   *os.File
	raw    syscall.RawConn
	local  vsockAddr
	remote vsockAddr
	closed atomic.Bool
}

func newVsockConn(fd int, local, remote vsockAddr) (*vsockConn, error) {
	file, raw, err := newVsockFile(fd)
	if err != nil {
		return nil, err
	}
	return &vsockConn{file: file, raw: raw, local: local, remote: remote}, nil
}

func (c *vsockConn) Read(p []byte) (int, error) {
	n, err := c.file.Read(p)
	if err == io.EOF {
		return n, err
	}
	return n, c.opError("read", err)
}

func (c *vsockConn) Write(p []byte) (int, error) {
	n, err := c.file.Write(p)
	return n, c.opError("write", err)
}

func (c *vsockConn) Close() error {
	c.closed.Store(true)
	return c.opError("close", c.file.Close())
}
func (c *vsockConn) LocalAddr() net.Addr  { return c.local }
func (c *vsockConn) RemoteAddr() net.Addr { return c.remote }
func (c *vsockConn) SetDeadline(t time.Time) error {
	return c.opError("set", c.file.SetDeadline(t))
}
func (c *vsockConn) SetReadDeadline(t time.Time) error {
	return c.opError("set", c.file.SetReadDeadline(t))
}
func (c *vsockConn) SetWriteDeadline(t time.Time) error {
	return c.opError("set", c.file.SetWriteDeadline(t))
}

func (c *vsockConn) CloseRead() error  { return c.shutdown(syscall.SHUT_RD) }
func (c *vsockConn) CloseWrite() error { return c.shutdown(syscall.SHUT_WR) }

func (c *vsockConn) shutdown(how int) error {
	var shutdownErr error
	err := c.raw.Control(func(fd uintptr) { shutdownErr = syscall.Shutdown(int(fd), how) })
	if err == nil {
		err = shutdownErr
	}
	return c.opError("shutdown", err)
}

func (c *vsockConn) opError(op string, err error) error {
	if err != nil && c.closed.Load() {
		err = net.ErrClosed
	}
	return vsockError(op, c.local, c.remote, err)
}

func vsockError(op string, local, remote net.Addr, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrClosed) {
		err = net.ErrClosed
	}
	return &net.OpError{Op: op, Net: "vsock", Source: local, Addr: remote, Err: err}
}

type vsockAddr struct {
	cid  uint32
	port uint32
}

func (vsockAddr) Network() string  { return "vsock" }
func (a vsockAddr) String() string { return fmt.Sprintf("%d:%d", a.cid, a.port) }

var _ net.Listener = (*vsockListener)(nil)
var _ net.Conn = (*vsockConn)(nil)
