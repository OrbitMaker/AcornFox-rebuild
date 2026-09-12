package desktopbridge

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	maxConnections = 32
	dialTimeout    = 10 * time.Second
	idleTimeout    = 2 * time.Minute
)

// Serve accepts a bounded number of connections and proxies each one only to
// the fixed guest-loopback target attached to listenerPort.
func Serve(ctx context.Context, listener net.Listener, listenerPort uint32) error {
	target, err := TargetForPort(listenerPort)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	var connections sync.WaitGroup
	defer func() {
		cancel()
		_ = listener.Close()
		stop()
		connections.Wait()
	}()
	sem := make(chan struct{}, maxConnections)
	for {
		inbound, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer func() { <-sem }()
				proxyWithIdleTimeout(ctx, target, inbound, idleTimeout)
			}()
		default:
			_ = inbound.Close()
		}
	}
}

func proxyWithIdleTimeout(ctx context.Context, target Target, inbound net.Conn, idle time.Duration) {
	defer inbound.Close()
	stopInbound := context.AfterFunc(ctx, func() { _ = inbound.Close() })
	defer stopInbound()
	dialer := net.Dialer{Timeout: dialTimeout}
	outbound, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.Host, fmtPort(target.Port)))
	if err != nil {
		return
	}
	defer outbound.Close()
	stopOutbound := context.AfterFunc(ctx, func() { _ = outbound.Close() })
	defer stopOutbound()

	// Activity in either direction keeps the entire connection alive, including
	// a long SSH install whose output or keepalives continue beyond two minutes.
	var activity sync.Mutex
	touch := func() {
		activity.Lock()
		defer activity.Unlock()
		deadline := time.Now().Add(idle)
		_ = inbound.SetDeadline(deadline)
		_ = outbound.SetDeadline(deadline)
	}
	touch()
	done := make(chan error, 2)
	copyTo := func(dst, src net.Conn) {
		_, err := io.Copy(activityConn{Conn: dst, touch: touch}, activityConn{Conn: src, touch: touch})
		if err == nil {
			if writer, ok := dst.(interface{ CloseWrite() error }); ok {
				err = writer.CloseWrite()
			}
		}
		done <- err
	}
	go copyTo(outbound, inbound)
	go copyTo(inbound, outbound)
	if err := <-done; err != nil {
		_ = inbound.Close()
		_ = outbound.Close()
	}
	// A clean request EOF only closes the destination's write half. Drain the
	// response before closing both sockets; errors/cancellation wake both copies.
	<-done
}

type activityConn struct {
	net.Conn
	touch func()
}

func (c activityConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c activityConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func fmtPort(port uint16) string {
	return fmt.Sprintf("%d", port)
}

// ForwardStdioHTTP is the Windows-facing bridge mode. It does not parse a
// request or accept a destination: its byte stream always reaches guest
// loopback HTTP on port 8080. Callers keep diagnostics on stderr.
func ForwardStdioHTTP(ctx context.Context, input io.Reader, output io.Writer, dial func(string, string, time.Duration) (net.Conn, error)) error {
	target, err := TargetForPort(GuestHTTPPort)
	if err != nil {
		return err
	}
	conn, err := dial("tcp", net.JoinHostPort(target.Host, fmtPort(target.Port)), dialTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	responseDone := make(chan struct{}, 1)
	go func() { _, _ = io.Copy(conn, input) }()
	go func() { _, _ = io.Copy(output, conn); responseDone <- struct{}{} }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-responseDone:
		return nil
	}
}
