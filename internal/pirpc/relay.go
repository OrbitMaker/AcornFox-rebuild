package pirpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
)

// RelayProcess owns a validated Pi subprocess while leaving its stdin/stdout
// available to a trusted local relay. The command line and environment retain
// all ProcessConfig restrictions; only the already-framed stream is exposed.
type RelayProcess struct {
	stdin     io.WriteCloser
	stdout    io.ReadCloser
	cmd       *exec.Cmd
	done      chan struct{}
	waitMu    sync.Mutex
	waitErr   error
	closeOnce sync.Once
}

// StartRelay launches Pi for a trusted Unix-socket relay. It does not parse or
// log stdin/stdout and never exposes stderr.
func StartRelay(ctx context.Context, config ProcessConfig) (*RelayProcess, error) {
	cmd, err := prepareCommand(ctx, config)
	if err != nil {
		return nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, errors.New("pirpc: create relay stdin failed")
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, errors.New("pirpc: create relay stdout failed")
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, errors.New("pirpc: start relay process failed")
	}
	process := &RelayProcess{stdin: stdin, stdout: stdout, cmd: cmd, done: make(chan struct{})}
	go process.wait()
	return process, nil
}

func (p *RelayProcess) wait() {
	err := p.cmd.Wait()
	p.waitMu.Lock()
	if err != nil {
		p.waitErr = ErrProcessExited
	}
	p.waitMu.Unlock()
	close(p.done)
}

func (p *RelayProcess) Stdin() io.WriteCloser { return p.stdin }
func (p *RelayProcess) Stdout() io.ReadCloser { return p.stdout }
func (p *RelayProcess) Done() <-chan struct{} { return p.done }

func (p *RelayProcess) PID() int {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

func (p *RelayProcess) Wait(ctx context.Context) error {
	select {
	case <-p.done:
		p.waitMu.Lock()
		defer p.waitMu.Unlock()
		return p.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close closes both sides of the relay, then kills only this owned process if
// it does not exit before ctx. Returned errors contain no process output.
func (p *RelayProcess) Close(ctx context.Context) error {
	p.closeOnce.Do(func() {
		_ = p.stdin.Close()
		_ = p.stdout.Close()
	})
	select {
	case <-p.done:
		return p.Wait(context.Background())
	case <-ctx.Done():
		_ = p.cmd.Process.Kill()
		<-p.done
		return fmt.Errorf("pirpc: relay shutdown: %w", ctx.Err())
	}
}
