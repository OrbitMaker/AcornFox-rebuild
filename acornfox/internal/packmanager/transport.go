package packmanager

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/acornfox/acornfox/internal/localpeer"
	"github.com/acornfox/acornfox/internal/packprotocol"
)

var (
	ErrPeerCredentialMismatch = errors.New("peer uid or pid mismatch")
	ErrResponseBodyExceeded   = errors.New("response body exceeds protocol limit")
)

type UnixHTTPClient struct {
	client      *http.Client
	socketPath  string
	expectedPID int32
	expectedUID uint32
	validator   func(pid int32, uid uint32) error
}

func NewUnixHTTPClient(socketPath string, expectedPID int32, expectedUID uint32, validator func(pid int32, uid uint32) error, timeout time.Duration) *UnixHTTPClient {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	transport := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: timeout,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, "unix", socketPath)
			if err != nil {
				return nil, err
			}
			peerID, err := localpeer.PeerIdentity(conn)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			if expectedPID > 0 && peerID.PID != expectedPID {
				_ = conn.Close()
				return nil, ErrPeerCredentialMismatch
			}
			if peerID.UID != expectedUID {
				_ = conn.Close()
				return nil, ErrPeerCredentialMismatch
			}
			if validator != nil {
				if err := validator(peerID.PID, peerID.UID); err != nil {
					_ = conn.Close()
					return nil, err
				}
			}
			return conn, nil
		},
	}

	return &UnixHTTPClient{
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		socketPath:  socketPath,
		expectedPID: expectedPID,
		expectedUID: expectedUID,
		validator:   validator,
	}
}

// DoStream keeps the same kernel-credential/validator transport as Do, but
// leaves a bounded response body to the caller. The caller must Close it.
func (c *UnixHTTPClient) DoStream(req *http.Request, maxBytes int64) (*http.Response, error) {
	if c == nil || req == nil || maxBytes <= 0 {
		return nil, ErrResponseBodyExceeded
	}
	req.URL.Scheme = "http"
	req.URL.Host = "unix"
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &boundedUnixBody{ReadCloser: resp.Body, remaining: maxBytes}
	return resp, nil
}

type boundedUnixBody struct {
	io.ReadCloser
	remaining int64
}

func (b *boundedUnixBody) Read(dst []byte) (int, error) {
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

func (c *UnixHTTPClient) Do(req *http.Request) (*http.Response, []byte, error) {
	resp, err := c.DoStream(req, packprotocol.MaxProtocolMessageBytes)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, packprotocol.MaxProtocolMessageBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(body) > packprotocol.MaxProtocolMessageBytes {
		return nil, nil, ErrResponseBodyExceeded
	}
	return resp, body, nil
}
