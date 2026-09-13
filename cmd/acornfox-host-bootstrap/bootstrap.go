package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/desktopupdate"
	"github.com/open-card/open-card/internal/hostconfig"
	"github.com/open-card/open-card/internal/hostlifecycle"
)

var (
	ErrSelectionLimit   = errors.New("hostbootstrap: exceeded maximum reselect attempts")
	ErrChildTerminated  = errors.New("hostbootstrap: child process terminated unexpectedly")
	ErrChildRetained    = errors.New("hostbootstrap: child process cleanup retained")
	ErrProtocolMismatch = errors.New("hostbootstrap: lifecycle protocol violation")
)

type BootstrapOptions struct {
	ConfigPath     string
	BootstrapRoot  string
	SlotsRoot      string
	InvocationLock string
	AllowNonRoot   bool
	OutcomeTimeout time.Duration
}

type boundedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remain := b.max - b.buf.Len()
	if remain > 0 {
		toWrite := len(p)
		if toWrite > remain {
			toWrite = remain
		}
		b.buf.Write(p[:toWrite])
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type childSession struct {
	cmd        *exec.Cmd
	parentConn net.Conn
	target     desktopupdate.HostActiveControllerTarget
	waitCh     chan error
	reaped     bool
	mu         sync.Mutex
}

func (s *childSession) terminateAndReap(timeout time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reaped {
		return nil
	}
	if s.parentConn != nil {
		_ = s.parentConn.Close()
	}
	if s.cmd != nil && s.cmd.Process != nil {
		pid := s.cmd.Process.Pid
		_ = killProcessGroup(pid)

		select {
		case waitErr := <-s.waitCh:
			s.reaped = true
			return waitErr
		case <-time.After(timeout):
			// Second kill attempt
			_ = killProcessGroup(pid)
			// Do NOT set s.reaped = true since process has not been confirmed reaped
			return fmt.Errorf("%w: process group %d failed to exit within %v", ErrChildRetained, pid, timeout)
		}
	}
	return nil
}

func (s *childSession) waitCleanExitAndRequireEOF(timeout time.Duration) error {
	var childExitErr error
	select {
	case waitErr := <-s.waitCh:
		s.mu.Lock()
		s.reaped = true
		childExitErr = waitErr
		s.mu.Unlock()
	case <-time.After(timeout):
		cleanupErr := s.terminateAndReap(5 * time.Second)
		err := fmt.Errorf("%w: child hung after sending outcome", ErrChildTerminated)
		return errors.Join(err, cleanupErr)
	}

	if childExitErr != nil {
		_ = s.parentConn.Close()
		return fmt.Errorf("%w: child exit error: %v", ErrChildTerminated, childExitErr)
	}

	// Reject extra trailing frames: verify connection has reached EOF
	var extra [1]byte
	_ = s.parentConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, rErr := s.parentConn.Read(extra[:])
	_ = s.parentConn.Close()
	if n > 0 || (rErr != nil && !errors.Is(rErr, io.EOF)) {
		return fmt.Errorf("%w: unexpected extra frame data after outcome", ErrProtocolMismatch)
	}

	return nil
}

func RunBootstrap(ctx context.Context, verb string, opts BootstrapOptions) (*hostlifecycle.ResultFrame, error) {
	if !hostlifecycle.IsValidOperation(verb) {
		return nil, hostlifecycle.ErrInvalidOperation
	}

	lockPath := opts.InvocationLock
	if lockPath == "" {
		lockPath = hostconfig.DefaultInvocationLockPath
	}
	lockFile, err := hostconfig.AcquireInvocationLock(lockPath, opts.AllowNonRoot)
	if err != nil {
		return nil, err
	}
	defer lockFile.Close()

	cfg, err := hostconfig.ReadAndValidateConfigFile(opts.ConfigPath, opts.BootstrapRoot, opts.AllowNonRoot)
	if err != nil {
		return nil, err
	}
	defer cfg.Close()

	bootstrapSpec := convertBootstrapSpec(cfg.BootstrapSpec)
	pinned, err := desktopupdate.PinHostBootstrap(ctx, bootstrapSpec)
	if err != nil {
		return nil, err
	}
	defer pinned.Close()

	slotsRoot := opts.SlotsRoot
	if slotsRoot == "" {
		slotsRoot = hostconfig.DefaultSlotsRoot
	}

	outcomeTimeout := opts.OutcomeTimeout
	if outcomeTimeout == 0 {
		outcomeTimeout = 120 * time.Second
	}

	for selection := 0; selection < 2; selection++ {
		var session childSession
		var stderrBuf boundedBuffer
		stderrBuf.max = 16 * 1024

		err = desktopupdate.OpenActiveControllerReadOnly(
			ctx,
			desktopupdate.HostBootstrapReadOnlyOptions{
				Root:       slotsRoot,
				InstanceID: cfg.InstanceID,
				Bootstrap:  pinned,
			},
			func(cbCtx context.Context, target desktopupdate.HostActiveControllerTarget, controllerFD *os.File) error {
				parentSock, childSock, err := createLifecycleSocketpair()
				if err != nil {
					return err
				}

				conn, err := net.FileConn(parentSock)
				parentSock.Close()
				if err != nil {
					childSock.Close()
					return err
				}

				cmd := prepareChildCommand(controllerFD, childSock)
				cmd.Stdin = nil
				cmd.Stdout = nil
				cmd.Stderr = &stderrBuf

				if err := cmd.Start(); err != nil {
					childSock.Close()
					conn.Close()
					return err
				}

				// Parent closes child end of socket immediately after start
				childSock.Close()

				waitCh := make(chan error, 1)
				go func() {
					waitCh <- cmd.Wait()
				}()

				session = childSession{
					cmd:        cmd,
					parentConn: conn,
					target:     target,
					waitCh:     waitCh,
				}

				// Wake blocking reads promptly if context is canceled
				stopCancel := context.AfterFunc(cbCtx, func() {
					_ = conn.Close()
				})
				defer stopCancel()

				// Await pre-core hello-v1 with bounded deadline
				if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
					_ = session.terminateAndReap(5 * time.Second)
					return err
				}

				raw, err := hostlifecycle.ReadFrame(conn)
				if err != nil {
					_ = session.terminateAndReap(5 * time.Second)
					return fmt.Errorf("%w: failed reading pre-core hello: %v", ErrProtocolMismatch, err)
				}

				hello, err := hostlifecycle.DecodeHello(raw)
				if err != nil || hello.Type != hostlifecycle.FrameTypeHello || hello.SchemaVersion != hostlifecycle.ProtocolVersion1 {
					_ = session.terminateAndReap(5 * time.Second)
					return ErrProtocolMismatch
				}

				// Pre-core hello received; callback returns to unlock slot root
				return nil
			},
		)

		if err != nil {
			cleanupErr := session.terminateAndReap(5 * time.Second)
			if cleanupErr != nil {
				return nil, errors.Join(err, cleanupErr)
			}
			return nil, err
		}

		// Prompt context cancellation wakes socket I/O
		stopCtxCancel := context.AfterFunc(ctx, func() {
			if session.parentConn != nil {
				_ = session.parentConn.Close()
			}
		})
		defer stopCtxCancel()

		// Generate 32-byte crypto random nonce
		nonceBytes := make([]byte, 32)
		if _, err := rand.Read(nonceBytes); err != nil {
			cleanupErr := session.terminateAndReap(5 * time.Second)
			if cleanupErr != nil {
				return nil, errors.Join(err, cleanupErr)
			}
			return nil, err
		}
		nonceHex := hex.EncodeToString(nonceBytes)

		roleStr := hostlifecycle.RoleNormal
		if session.target.IsRecovery() {
			roleStr = hostlifecycle.RoleRecovery
		}

		admit := &hostlifecycle.AdmitFrame{
			Type:          hostlifecycle.FrameTypeAdmit,
			SchemaVersion: hostlifecycle.ProtocolVersion1,
			Operation:     verb,
			Role:          roleStr,
			SlotID:        session.target.SlotID,
			InstanceID:    cfg.InstanceID,
			Nonce:         nonceHex,
		}

		admitBytes, err := hostlifecycle.EncodeAdmit(admit)
		if err != nil {
			cleanupErr := session.terminateAndReap(5 * time.Second)
			if cleanupErr != nil {
				return nil, errors.Join(err, cleanupErr)
			}
			return nil, err
		}

		// Write admit frame with deadline
		if err := session.parentConn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			cleanupErr := session.terminateAndReap(5 * time.Second)
			if cleanupErr != nil {
				return nil, errors.Join(err, cleanupErr)
			}
			return nil, err
		}
		if err := hostlifecycle.WriteFrame(session.parentConn, admitBytes); err != nil {
			cleanupErr := session.terminateAndReap(5 * time.Second)
			if cleanupErr != nil {
				return nil, errors.Join(err, cleanupErr)
			}
			return nil, err
		}

		// Read outcome frame with bounded deadline
		if err := session.parentConn.SetReadDeadline(time.Now().Add(outcomeTimeout)); err != nil {
			cleanupErr := session.terminateAndReap(5 * time.Second)
			if cleanupErr != nil {
				return nil, errors.Join(err, cleanupErr)
			}
			return nil, err
		}

		respBytes, err := hostlifecycle.ReadFrame(session.parentConn)
		if err != nil {
			if ctx.Err() != nil {
				cleanupErr := session.terminateAndReap(5 * time.Second)
				return nil, errors.Join(ctx.Err(), cleanupErr)
			}
			cleanupErr := session.terminateAndReap(5 * time.Second)
			readErr := fmt.Errorf("%w: failed reading child outcome: %v", ErrChildTerminated, err)
			if cleanupErr != nil {
				return nil, errors.Join(readErr, cleanupErr)
			}
			return nil, readErr
		}

		frameType, err := hostlifecycle.DetectFrameType(respBytes)
		if err != nil {
			cleanupErr := session.terminateAndReap(5 * time.Second)
			if cleanupErr != nil {
				return nil, errors.Join(err, cleanupErr)
			}
			return nil, err
		}

		switch frameType {
		case hostlifecycle.FrameTypeReselect:
			if !session.target.IsRecovery() {
				cleanupErr := session.terminateAndReap(5 * time.Second)
				err := fmt.Errorf("%w: reselect returned under normal role", ErrProtocolMismatch)
				if cleanupErr != nil {
					return nil, errors.Join(err, cleanupErr)
				}
				return nil, err
			}
			reselect, err := hostlifecycle.DecodeReselect(respBytes)
			if err != nil {
				cleanupErr := session.terminateAndReap(5 * time.Second)
				if cleanupErr != nil {
					return nil, errors.Join(err, cleanupErr)
				}
				return nil, err
			}
			if reselect.Nonce != nonceHex {
				cleanupErr := session.terminateAndReap(5 * time.Second)
				err := fmt.Errorf("%w: reselect nonce mismatch", ErrProtocolMismatch)
				if cleanupErr != nil {
					return nil, errors.Join(err, cleanupErr)
				}
				return nil, err
			}

			// Bounded wait for recovery child to exit and verify socket reached EOF
			if err := session.waitCleanExitAndRequireEOF(5 * time.Second); err != nil {
				return nil, err
			}
			continue

		case hostlifecycle.FrameTypeResult:
			result, err := hostlifecycle.DecodeResult(respBytes)
			if err != nil {
				cleanupErr := session.terminateAndReap(5 * time.Second)
				if cleanupErr != nil {
					return nil, errors.Join(err, cleanupErr)
				}
				return nil, err
			}
			if result.Nonce != nonceHex {
				cleanupErr := session.terminateAndReap(5 * time.Second)
				err := fmt.Errorf("%w: result nonce mismatch", ErrProtocolMismatch)
				if cleanupErr != nil {
					return nil, errors.Join(err, cleanupErr)
				}
				return nil, err
			}
			if result.Operation != verb {
				cleanupErr := session.terminateAndReap(5 * time.Second)
				err := fmt.Errorf("%w: result operation %q does not match requested %q", ErrProtocolMismatch, result.Operation, verb)
				if cleanupErr != nil {
					return nil, errors.Join(err, cleanupErr)
				}
				return nil, err
			}

			// Bounded wait for child to exit and verify socket reached EOF
			if err := session.waitCleanExitAndRequireEOF(5 * time.Second); err != nil {
				return nil, err
			}
			return result, nil

		default:
			cleanupErr := session.terminateAndReap(5 * time.Second)
			err := ErrProtocolMismatch
			if cleanupErr != nil {
				return nil, errors.Join(err, cleanupErr)
			}
			return nil, err
		}
	}

	return nil, ErrSelectionLimit
}
