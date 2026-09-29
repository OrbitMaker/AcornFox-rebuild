package client

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

// consoleRemotePort is the loopback port the console listener binds to on the
// server. The N3 contract fixes it at 18800; `open` forwards a free local port
// to it. It is not configurable via Target (URL-mode targets bypass the tunnel
// entirely and use their own host:port).
const consoleRemotePort = 18800

// tunnelConnectTimeout bounds how long OpenTunnel waits for the forwarded local
// port to start accepting connections before giving up.
const tunnelConnectTimeout = 15 * time.Second

// tunnelPollInterval is how often OpenTunnel probes the local port.
const tunnelPollInterval = 100 * time.Millisecond

// Tunnel is a live `ssh -L` port forward from a local loopback port to the
// server's console listener. The caller opens LocalURL in a browser and keeps
// the tunnel alive until Ctrl+C (context cancel) or the ssh process exits.
type Tunnel struct {
	// LocalURL is the console base URL reachable through the forward, e.g.
	// "http://127.0.0.1:54321". It never contains a token.
	LocalURL string

	cmd      *exec.Cmd
	done     chan struct{}
	closeOne sync.Once
	closeErr error

	mu  sync.Mutex
	err error
}

// Done is closed when the tunnel ends (the ssh process exits or Close is
// called).
func (t *Tunnel) Done() <-chan struct{} { return t.done }

// Err returns the classified error that ended the tunnel, or nil if it ended
// cleanly (Close). It is only meaningful after Done is closed.
func (t *Tunnel) Err() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.err
}

// Close terminates the ssh process. It is safe to call multiple times.
func (t *Tunnel) Close() error {
	t.closeOne.Do(func() {
		if t.cmd != nil && t.cmd.Process != nil {
			_ = t.cmd.Process.Kill()
			<-t.done // the reaper closes done once Wait returns
			return
		}
		// No process (test tunnels): end the tunnel by closing done unless it
		// is already closed.
		select {
		case <-t.done:
		default:
			close(t.done)
		}
	})
	return t.closeErr
}

// NewClosedTunnel builds a *Tunnel that has already ended, carrying localURL
// and the given end error. It exists so other packages (e.g. internal/cli) can
// exercise the "tunnel died" path with a fake tunnel function; it starts no
// process. err may be nil (clean exit).
func NewClosedTunnel(localURL string, err error) *Tunnel {
	done := make(chan struct{})
	close(done)
	return &Tunnel{LocalURL: localURL, done: done, err: err}
}

// NewLiveTunnelForTest builds a *Tunnel whose Done channel never fires on its
// own (no process). It lets other packages exercise the "block until Ctrl+C"
// path. Close closes Done so the caller's defer does not block.
func NewLiveTunnelForTest(localURL string) *Tunnel {
	return &Tunnel{LocalURL: localURL, done: make(chan struct{})}
}

// tunnelArgs builds the ssh argv (excluding the program name) for a `-L`
// forward from 127.0.0.1:local to 127.0.0.1:consoleRemotePort on t. It mirrors
// sshArgs' -p/-i handling but uses -N -T and ExitOnForwardFailure so a refused
// forward makes ssh exit instead of hanging.
func tunnelArgs(t Target, localPort int) []string {
	args := []string{
		"-N", "-T",
		"-o", "BatchMode=yes",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "ServerAliveInterval=15",
		"-L", fmt.Sprintf("127.0.0.1:%d:127.0.0.1:%d", localPort, consoleRemotePort),
	}
	if t.Port != 0 {
		args = append(args, "-p", strconv.Itoa(t.Port))
	}
	if t.Identity != "" {
		args = append(args, "-i", t.Identity)
	}
	args = append(args, t.SSH)
	return args
}

// OpenTunnel starts `ssh -N -T ... -L 127.0.0.1:localPort:127.0.0.1:18800 ...`
// against t and waits until the local port accepts a TCP connection (up to
// tunnelConnectTimeout) or the process exits. On success it returns a live
// *Tunnel; on failure a classified connect *Error (including
// connect/forwarding_disabled when the server refuses the forward).
func OpenTunnel(ctx context.Context, t Target, localPort int) (*Tunnel, error) {
	if t.SSH == "" {
		return nil, connectError(codeConnectFailed, "target 缺少 ssh")
	}

	prog := sshPath
	if prog == "ssh" {
		resolved, err := exec.LookPath("ssh")
		if err != nil {
			return nil, connectError(codeSSHMissing, "")
		}
		prog = resolved
	}

	cmd := exec.Command(prog, tunnelArgs(t, localPort)...)
	stderr := newBoundedBuffer(stderrCap)
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, connectError(codeConnectFailed, err.Error())
	}

	tun := &Tunnel{
		LocalURL: "http://127.0.0.1:" + strconv.Itoa(localPort),
		cmd:      cmd,
		done:     make(chan struct{}),
	}

	// A single reaper owns cmd.Wait. It classifies the exit for Err() and
	// closes done so waiters observe the end.
	exited := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		code := -1
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		tun.mu.Lock()
		if err != nil {
			tun.err = connectError(classifySSH(code, stderr.String()), stderr.String())
		}
		tun.mu.Unlock()
		exited <- err
		close(tun.done)
	}()

	local := "127.0.0.1:" + strconv.Itoa(localPort)
	deadline := time.Now().Add(tunnelConnectTimeout)
	ticker := time.NewTicker(tunnelPollInterval)
	defer ticker.Stop()

	for {
		// The forward is up once the local port accepts a connection.
		if c, err := net.DialTimeout("tcp", local, tunnelPollInterval); err == nil {
			_ = c.Close()
			return tun, nil
		}

		select {
		case <-tun.done:
			// Process exited before the forward came up: surface its cause.
			if e := tun.Err(); e != nil {
				return nil, e
			}
			return nil, connectError(codeConnectFailed, stderr.String())
		case <-ctx.Done():
			_ = tun.Close()
			return nil, connectError(codeConnectFailed, ctx.Err().Error())
		case <-ticker.C:
		}

		if time.Now().After(deadline) {
			_ = tun.Close()
			return nil, connectError(codeConnectFailed, "隧道端口在 15 秒内未就绪")
		}
	}
}
