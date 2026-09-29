//go:build !darwin || !cgo

package darwinlaunch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
)

const (
	ControllerIdentifier = "com.acornfox.host-update"
	LauncherIdentifier   = "com.acornfox.host-launcher"
	DistributionMode     = "unsupported"
)

var (
	ErrUnsupportedPlatform         = errors.New("darwinlaunch: verified native launch layer is supported only on Darwin with cgo")
	ErrChildRetained               = errors.New("darwinlaunch: child process remains retained in registry")
	ErrUntrustedHost               = errors.New("darwinlaunch: running host process does not satisfy security requirements")
	ErrUntrustedExecutable         = errors.New("darwinlaunch: executable does not satisfy security requirements")
	ErrInvalidAction               = errors.New("darwinlaunch: invalid launcher action")
	ErrExecutionFailed             = errors.New("darwinlaunch: native execution failed")
	ErrAlreadyResumed              = errors.New("darwinlaunch: child already resumed")
	ErrAlreadyAborted              = errors.New("darwinlaunch: child already aborted")
	ErrTestDistributionUnavailable = errors.New("darwinlaunch: test distribution constructors are not available in production builds")
)

type LauncherAction string

const (
	LauncherActionStart       LauncherAction = "start"
	LauncherActionMaintenance LauncherAction = "maintenance"
	LauncherActionProbeHelper LauncherAction = "probe-helper"
)

type SourceIdentity struct {
	SHA256 string
	Size   int64
}

type ExitResult struct {
	ExitCode        int
	Signal          syscall.Signal
	Exited          bool
	Signaled        bool
	Stdout          []byte
	Stderr          []byte
	StdoutTruncated bool
	StderrTruncated bool
	Err             error
}

type ChildRetainedError struct {
	Err           error
	PreparedChild *PreparedChild
	OwnedChild    *OwnedChild
	PID           int
}

func (e *ChildRetainedError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("darwinlaunch: child process %d retained: %v", e.PID, e.Err)
}

func (e *ChildRetainedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type PreparedChild struct{}

func (p *PreparedChild) PID() int                        { return 0 }
func (p *PreparedChild) ParentLifecycle() *os.File       { return nil }
func (p *PreparedChild) Resume() (*OwnedChild, error)    { return nil, ErrUnsupportedPlatform }
func (p *PreparedChild) Abort(ctx context.Context) error { return ErrUnsupportedPlatform }

type OwnedChild struct{}

func (c *OwnedChild) PID() int { return 0 }
func (c *OwnedChild) Wait(ctx context.Context) ExitResult {
	return ExitResult{Err: ErrUnsupportedPlatform}
}
func (c *OwnedChild) Stop(ctx context.Context) error { return ErrUnsupportedPlatform }

func PrepareController(ctx context.Context, verifiedFD *os.File) (*PreparedChild, SourceIdentity, error) {
	return nil, SourceIdentity{}, ErrUnsupportedPlatform
}

func PrepareSlotLauncher(ctx context.Context, verifiedFD *os.File, action LauncherAction) (*PreparedChild, SourceIdentity, error) {
	return nil, SourceIdentity{}, ErrUnsupportedPlatform
}

func PrepareTestDistributionController(ctx context.Context, verifiedFD *os.File) (*PreparedChild, SourceIdentity, error) {
	return nil, SourceIdentity{}, ErrUnsupportedPlatform
}

func PrepareTestDistributionSlotLauncher(ctx context.Context, verifiedFD *os.File, action LauncherAction) (*PreparedChild, SourceIdentity, error) {
	return nil, SourceIdentity{}, ErrUnsupportedPlatform
}

func CheckProcessSStop(pid int) (int, error) {
	return 0, ErrUnsupportedPlatform
}

func injectKillDenial(pid int)     {}
func injectWaitpidFailure(pid int) {}
func clearFaultInjections()        {}
func activeChildCount() int        { return 0 }
func getStaticCodeSigningInfo(path string) (string, string, error) {
	return "", "", ErrUnsupportedPlatform
}
