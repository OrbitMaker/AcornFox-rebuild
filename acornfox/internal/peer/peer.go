// Package peer provides the local Unix-socket boundary between acornfox-core
// and acornfox-executor.
//
// Trust model: the two processes run as distinct system accounts. A socket is
// created 0660 in a directory prepared by systemd, owned by a shared group, and
// every accepted or dialed connection must present the expected peer UID as
// reported by the kernel (SO_PEERCRED). Process IDs are not pinned: services
// restart independently and the UID is the identity that matters.
package peer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// MaxMessageBytes bounds every JSON request or response exchanged over a peer socket.
const MaxMessageBytes = 64 << 10

var (
	ErrUnsupportedPlatform  = errors.New("peer credentials are unsupported on this platform")
	ErrPeerMismatch         = errors.New("peer uid mismatch")
	ErrResponseBodyExceeded = errors.New("response body exceeds protocol limit")
)

// Identity is the kernel-reported credential of a Unix socket peer.
type Identity struct {
	UID uint32
	PID int32
	GID uint32
}

// Of returns the kernel-reported credential of a local Unix connection.
func Of(conn net.Conn) (Identity, error) { return peerIdentity(conn) }

// Listen creates a Unix socket that only accepts connections from allowUID.
// A stale socket file at path is replaced; any other file type is refused.
// When gid is nonzero the socket group is set to gid so the peer can connect.
func Listen(path string, gid, allowUID uint32) (net.Listener, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("peer socket path must be absolute and clean")
	}
	if allowUID == 0 {
		return nil, errors.New("peer socket must name a non-root peer uid")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("peer socket path %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	raw, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Listener, error) {
		_ = raw.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if gid != 0 {
		if err := os.Chown(path, -1, int(gid)); err != nil {
			return fail(err)
		}
	}
	if err := os.Chmod(path, 0o660); err != nil {
		return fail(err)
	}
	return &listener{Listener: raw, allowUID: allowUID}, nil
}

type listener struct {
	net.Listener
	allowUID uint32
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		id, err := Of(conn)
		if err != nil || id.UID != l.allowUID {
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}

// Client is an HTTP client over a Unix socket that verifies the server's UID.
type Client struct {
	client *http.Client
}

// NewClient returns a client for the socket at path whose server must run as peerUID.
func NewClient(path string, peerUID uint32, timeout time.Duration) *Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: timeout,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, "unix", path)
			if err != nil {
				return nil, err
			}
			id, err := Of(conn)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			if id.UID != peerUID {
				_ = conn.Close()
				return nil, ErrPeerMismatch
			}
			return conn, nil
		},
	}
	return &Client{client: &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// DoStream sends req and returns a response whose body is bounded by maxBytes.
// The caller must close the body.
func (c *Client) DoStream(req *http.Request, maxBytes int64) (*http.Response, error) {
	if c == nil || req == nil || maxBytes <= 0 {
		return nil, ErrResponseBodyExceeded
	}
	req.URL.Scheme = "http"
	req.URL.Host = "unix"
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &boundedBody{ReadCloser: resp.Body, remaining: maxBytes}
	return resp, nil
}

// Do sends req and reads a response body of at most MaxMessageBytes.
func (c *Client) Do(req *http.Request) (*http.Response, []byte, error) {
	resp, err := c.DoStream(req, MaxMessageBytes)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxMessageBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(body) > MaxMessageBytes {
		return nil, nil, ErrResponseBodyExceeded
	}
	return resp, body, nil
}

type boundedBody struct {
	io.ReadCloser
	remaining int64
}

func (b *boundedBody) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	if b.remaining == 0 {
		var probe [1]byte
		n, err := b.ReadCloser.Read(probe[:])
		if n > 0 {
			return 0, ErrResponseBodyExceeded
		}
		return 0, err
	}
	if int64(len(dst)) > b.remaining {
		dst = dst[:b.remaining]
	}
	n, err := b.ReadCloser.Read(dst)
	b.remaining -= int64(n)
	return n, err
}
