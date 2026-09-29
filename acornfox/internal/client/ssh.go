package client

import (
	"context"
	"errors"
	"io"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

// sshPath is the ssh executable the client launches. It is a package variable
// so tests can point it at a fake ssh. Empty means "resolve via PATH".
var sshPath = "ssh"

// defaultRemoteCommand is used when Target.RemoteCommand is empty.
const defaultRemoteCommand = "acornfox proxy"

// stderrCap bounds how much ssh stderr we retain for diagnosis (64 KB).
const stderrCap = 64 << 10

// sshArgs builds the exact argv (excluding the program name) for launching ssh
// against t. The contract fixes: -T, -o BatchMode=yes, -o ServerAliveInterval=15,
// optional -p and -i, then user@host, then the remote command.
func sshArgs(t Target) []string {
	args := []string{
		"-T",
		"-o", "BatchMode=yes",
		"-o", "ServerAliveInterval=15",
	}
	if t.Port != 0 {
		args = append(args, "-p", strconv.Itoa(t.Port))
	}
	if t.Identity != "" {
		args = append(args, "-i", t.Identity)
	}
	args = append(args, t.SSH)
	remote := t.RemoteCommand
	if remote == "" {
		remote = defaultRemoteCommand
	}
	args = append(args, remote)
	return args
}

// sshConn wraps an ssh child process as a single net.Conn: reads come from the
// process stdout, writes go to its stdin, Close kills the process and waits.
// One CLI command uses exactly one sshConn (MaxConnsPerHost=1, keep-alive).
//
// A single reaper goroutine owns cmd.Wait(); its result is published through
// waitCh (closed when the process exits) so Close, exited() and waitExit() can
// observe the exit state without racing on Wait.
type sshConn struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser

	stderr *boundedBuffer

	waitCh    chan struct{} // closed once the process has been reaped
	waitErr   error         // set before waitCh is closed
	exitCode_ int           // set before waitCh is closed; -1 if unknown

	closeOnce sync.Once
	closeErr  error
}

// startReaper launches the single goroutine that reaps the process.
func (c *sshConn) startReaper() {
	go func() {
		err := c.cmd.Wait()
		c.waitErr = err
		if c.cmd.ProcessState != nil {
			c.exitCode_ = c.cmd.ProcessState.ExitCode()
		} else {
			c.exitCode_ = -1
		}
		close(c.waitCh)
	}()
}

func (c *sshConn) Read(p []byte) (int, error)  { return c.stdout.Read(p) }
func (c *sshConn) Write(p []byte) (int, error) { return c.stdin.Write(p) }

func (c *sshConn) Close() error {
	c.closeOnce.Do(func() {
		// Closing stdin lets a well-behaved proxy exit; then kill to be sure.
		_ = c.stdin.Close()
		if c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
		}
		<-c.waitCh // reaper completes cmd.Wait exactly once
		c.closeErr = c.waitErr
	})
	return c.closeErr
}

// dummyAddr is a placeholder for LocalAddr/RemoteAddr; the transport never
// inspects it.
type dummyAddr struct{}

func (dummyAddr) Network() string { return "ssh" }
func (dummyAddr) String() string  { return "ssh" }

func (c *sshConn) LocalAddr() net.Addr  { return dummyAddr{} }
func (c *sshConn) RemoteAddr() net.Addr { return dummyAddr{} }

// Deadlines are best-effort no-ops: a pipe over a process has no OS-level
// deadline support, and request cancellation is handled via context on the
// HTTP layer instead.
func (c *sshConn) SetDeadline(time.Time) error      { return nil }
func (c *sshConn) SetReadDeadline(time.Time) error  { return nil }
func (c *sshConn) SetWriteDeadline(time.Time) error { return nil }

// boundedBuffer keeps at most cap bytes, dropping the overflow. Safe for the
// single writer goroutine that exec wires to the process stderr.
type boundedBuffer struct {
	mu  sync.Mutex
	buf []byte
	cap int
}

func newBoundedBuffer(capBytes int) *boundedBuffer {
	return &boundedBuffer{cap: capBytes}
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buf) >= b.cap {
		return len(p), nil // already full; discard but report progress
	}
	room := b.cap - len(b.buf)
	if room > len(p) {
		room = len(p)
	}
	b.buf = append(b.buf, p[:room]...)
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

// sshDialer starts the ssh child process on demand and returns a single
// sshConn. It launches at most one process; a second dial after the process has
// exited returns the classified connect error.
type sshDialer struct {
	target Target

	mu       sync.Mutex
	conn     *sshConn
	started  bool
	startErr error
}

// dial starts ssh (once) and returns the connection. On any startup failure it
// returns a classified *Error. If the process was already started and has since
// exited, it re-classifies from the captured stderr/exit code.
func (d *sshDialer) dial(ctx context.Context) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.started {
		if d.startErr != nil {
			return nil, d.startErr
		}
		// Already have a live conn; the transport keeps a single connection, so
		// a re-dial only happens after the previous conn broke. Classify from
		// what the process left behind.
		if d.conn != nil && d.conn.exited() {
			return nil, connectError(classifySSH(d.conn.exitCode(), d.conn.stderr.String()), d.conn.stderr.String())
		}
		if d.conn != nil {
			return d.conn, nil
		}
	}
	d.started = true

	prog := sshPath
	if prog == "ssh" {
		resolved, err := exec.LookPath("ssh")
		if err != nil {
			d.startErr = connectError(codeSSHMissing, "")
			return nil, d.startErr
		}
		prog = resolved
	}

	cmd := exec.CommandContext(ctx, prog, sshArgs(d.target)...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		d.startErr = connectError(codeConnectFailed, err.Error())
		return nil, d.startErr
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		d.startErr = connectError(codeConnectFailed, err.Error())
		return nil, d.startErr
	}
	stderr := newBoundedBuffer(stderrCap)
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		// LookPath already ran, so a start failure here is unusual; treat a
		// missing binary as ssh_missing, anything else as generic.
		if errors.Is(err, exec.ErrNotFound) {
			d.startErr = connectError(codeSSHMissing, err.Error())
		} else {
			d.startErr = connectError(codeConnectFailed, err.Error())
		}
		return nil, d.startErr
	}

	d.conn = &sshConn{
		cmd:       cmd,
		stdin:     stdin,
		stdout:    stdout,
		stderr:    stderr,
		waitCh:    make(chan struct{}),
		exitCode_: -1,
	}
	d.conn.startReaper()
	return d.conn, nil
}

// classifyStartupFailure re-reads the process state and returns the connect
// error to surface when an HTTP request fails before any response bytes.
func (d *sshDialer) classifyStartupFailure() *Error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if e, ok := d.startErr.(*Error); ok {
		return e
	}
	if d.conn == nil {
		return connectError(codeConnectFailed, "")
	}
	// Give the process a moment to flush stderr / exit for accurate diagnosis.
	d.conn.waitExit(500 * time.Millisecond)
	return connectError(classifySSH(d.conn.exitCode(), d.conn.stderr.String()), d.conn.stderr.String())
}

// close terminates the ssh process if one was started.
func (d *sshDialer) close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}

// exited reports whether the ssh process has terminated.
func (c *sshConn) exited() bool {
	select {
	case <-c.waitCh:
		return true
	default:
		return false
	}
}

// exitCode returns the process exit code, or -1 if unknown/still running.
func (c *sshConn) exitCode() int {
	select {
	case <-c.waitCh:
		return c.exitCode_
	default:
		return -1
	}
}

// waitExit waits up to d for the process to exit, then returns. It never blocks
// forever so a hung ssh cannot stall diagnosis.
func (c *sshConn) waitExit(d time.Duration) {
	select {
	case <-c.waitCh:
	case <-time.After(d):
	}
}
