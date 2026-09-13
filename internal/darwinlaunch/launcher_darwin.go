//go:build darwin && cgo

package darwinlaunch

/*
#cgo CFLAGS: -Wall -Werror -Wno-unused-variable
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include "security_darwin.h"
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"debug/macho"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	ControllerIdentifier = "com.acornfox.host-update"
	LauncherIdentifier   = "com.acornfox.host-launcher"

	maxHostExecutableSize = 512 << 20 // 512 MiB
	maxPipeDrainBytes     = 64 * 1024 // 64 KiB
)

var (
	ErrChildRetained                = errors.New("darwinlaunch: child process remains retained in registry")
	ErrUntrustedHost                = errors.New("darwinlaunch: running host process does not satisfy security requirements")
	ErrUntrustedExecutable          = errors.New("darwinlaunch: executable does not satisfy security requirements")
	ErrInvalidAction                = errors.New("darwinlaunch: invalid launcher action")
	ErrExecutionFailed              = errors.New("darwinlaunch: native execution failed")
	ErrAlreadyResumed               = errors.New("darwinlaunch: child already resumed")
	ErrAlreadyAborted               = errors.New("darwinlaunch: child already aborted")
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

// ChildRetainedError preserves the live child owner when a post-spawn operation,
// cancellation, or termination fails, ensuring the caller can inspect and retry.
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

// cappedBuffer provides bounded concurrent capture up to limit bytes.
type cappedBuffer struct {
	mu        sync.Mutex
	buf       []byte
	limit     int
	truncated bool
}

func newCappedBuffer(limit int) *cappedBuffer {
	return &cappedBuffer{limit: limit}
}

func (b *cappedBuffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n = len(p)
	if len(b.buf) < b.limit {
		space := b.limit - len(b.buf)
		if len(p) <= space {
			b.buf = append(b.buf, p...)
		} else {
			b.buf = append(b.buf, p[:space]...)
			b.truncated = true
		}
	} else {
		b.truncated = true
	}
	return n, nil
}

func (b *cappedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]byte, len(b.buf))
	copy(out, b.buf)
	return out
}

func (b *cappedBuffer) IsTruncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

func (b *cappedBuffer) SetTruncated() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.truncated = true
}

type childState struct {
	pid             int
	exitDone        chan struct{}
	mu              sync.Mutex
	exited          bool
	exitCode        int
	signaled        bool
	signal          syscall.Signal
	reaped          bool
	waitErr         error
	waiterRunning   bool
	drainWG         sync.WaitGroup
	stdoutDrain     *cappedBuffer
	stderrDrain     *cappedBuffer
	prOut           *os.File
	prErr           *os.File
	destPath        string
	destFD          *os.File
	sessionDir      string
	reqRef          C.SecRequirementRef
	parentLifecycle *os.File
}

func (cs *childState) isReaped() bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.reaped
}

func (cs *childState) ensureWaiter() {
	cs.mu.Lock()
	if cs.reaped || cs.waiterRunning {
		cs.mu.Unlock()
		return
	}
	cs.waiterRunning = true
	cs.waitErr = nil
	cs.mu.Unlock()
	go cs.runWaiter()
}

func (cs *childState) runWaiter() {
	for {
		var status syscall.WaitStatus
		var rusage syscall.Rusage
		wpid, err := syscall.Wait4(cs.pid, &status, 0, &rusage)
		if err == syscall.EINTR {
			continue
		}

		defaultRegistry.mu.Lock()
		injectWait := defaultRegistry.injectWaitpidFailurePID == cs.pid
		defaultRegistry.mu.Unlock()

		if injectWait {
			cs.mu.Lock()
			cs.waitErr = syscall.EINVAL
			cs.waiterRunning = false
			cs.mu.Unlock()
			return
		}

		cs.mu.Lock()
		if err == nil && wpid == cs.pid {
			cs.exited = status.Exited()
			if cs.exited {
				cs.exitCode = status.ExitStatus()
			}
			cs.signaled = status.Signaled()
			if cs.signaled {
				cs.signal = status.Signal()
			}
			cs.waiterRunning = false
			cs.mu.Unlock()

			// Wait for pipe drains to naturally reach EOF before closing descriptors
			drainDone := make(chan struct{})
			go func() {
				cs.drainWG.Wait()
				close(drainDone)
			}()

			select {
			case <-drainDone:
			case <-time.After(1 * time.Second):
				cs.stdoutDrain.SetTruncated()
				cs.stderrDrain.SetTruncated()
				if cs.prOut != nil {
					_ = cs.prOut.Close()
				}
				if cs.prErr != nil {
					_ = cs.prErr.Close()
				}
				<-drainDone
			}

			cs.mu.Lock()
			cs.reaped = true
			close(cs.exitDone)
			cs.mu.Unlock()

			defaultRegistry.unregister(cs.pid)
			cs.cleanupFiles()
			return
		}

		if errors.Is(err, syscall.ECHILD) {
			cs.waiterRunning = false
			cs.mu.Unlock()

			drainDone := make(chan struct{})
			go func() {
				cs.drainWG.Wait()
				close(drainDone)
			}()

			select {
			case <-drainDone:
			case <-time.After(1 * time.Second):
				cs.stdoutDrain.SetTruncated()
				cs.stderrDrain.SetTruncated()
				if cs.prOut != nil {
					_ = cs.prOut.Close()
				}
				if cs.prErr != nil {
					_ = cs.prErr.Close()
				}
				<-drainDone
			}

			cs.mu.Lock()
			cs.reaped = true
			close(cs.exitDone)
			cs.mu.Unlock()

			defaultRegistry.unregister(cs.pid)
			cs.cleanupFiles()
			return
		}

		// Non-ECHILD error: record and leave waiter retryable via ensureWaiter
		cs.waitErr = err
		cs.waiterRunning = false
		cs.mu.Unlock()
		return
	}
}

func (cs *childState) cleanupFiles() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.destFD != nil {
		_ = cs.destFD.Close()
		cs.destFD = nil
	}
	if cs.destPath != "" {
		_ = os.Remove(cs.destPath)
		cs.destPath = ""
	}
	if cs.sessionDir != "" {
		_ = os.Remove(cs.sessionDir)
		cs.sessionDir = ""
	}
	if C.is_null_requirement(cs.reqRef) == 0 {
		C.release_requirement(cs.reqRef)
		cs.reqRef = C.null_requirement()
	}
	if cs.parentLifecycle != nil {
		_ = cs.parentLifecycle.Close()
		cs.parentLifecycle = nil
	}
	if cs.prOut != nil {
		_ = cs.prOut.Close()
		cs.prOut = nil
	}
	if cs.prErr != nil {
		_ = cs.prErr.Close()
		cs.prErr = nil
	}
}

type childRegistry struct {
	mu                      sync.Mutex
	children                map[int]*childState
	injectKillDenialPID     int
	injectWaitpidFailurePID int
}

var defaultRegistry = &childRegistry{
	children: make(map[int]*childState),
}

func (r *childRegistry) register(cs *childState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.children[cs.pid] = cs
	cs.ensureWaiter()
}

func (r *childRegistry) unregister(pid int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.children, pid)
}

func (r *childRegistry) get(pid int) *childState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.children[pid]
}

func (r *childRegistry) signal(pid int, sig syscall.Signal) error {
	r.mu.Lock()
	if r.injectKillDenialPID == pid && sig == syscall.SIGKILL {
		r.mu.Unlock()
		return syscall.EPERM
	}
	r.mu.Unlock()
	return syscall.Kill(pid, sig)
}

func (r *childRegistry) injectKillDenial(pid int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.injectKillDenialPID = pid
}

func (r *childRegistry) injectWaitpidFailure(pid int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.injectWaitpidFailurePID = pid
}

func (r *childRegistry) clearInjections() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.injectKillDenialPID = 0
	r.injectWaitpidFailurePID = 0
}

func (r *childRegistry) activeCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.children)
}

// PreparedChild represents a child process that has been spawned in POSIX_SPAWN_START_SUSPENDED
// state, verified against raw p_stat == SSTOP and dynamic exact SecRequirement, and is owned
// exclusively by the ChildRegistry awaiting admission and Resume.
type PreparedChild struct {
	pid             int
	destPath        string
	destFD          *os.File
	sessionDir      string
	parentLifecycle *os.File
	reqRef          C.SecRequirementRef
	state           *childState
	mu              sync.Mutex
	resumed         bool
	aborted         bool
}

func (p *PreparedChild) PID() int {
	return p.pid
}

func (p *PreparedChild) ParentLifecycle() *os.File {
	return p.parentLifecycle
}

func (p *PreparedChild) Resume() (*OwnedChild, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.resumed {
		return nil, ErrAlreadyResumed
	}
	if p.aborted {
		return nil, ErrAlreadyAborted
	}

	failWithAbort := func(cause error) error {
		abortErr := p.abortLocked(context.Background())
		if abortErr != nil {
			return &ChildRetainedError{
				Err:           fmt.Errorf("%w (abort cleanup failed: %v)", cause, abortErr),
				PreparedChild: p,
				PID:           p.pid,
			}
		}
		return cause
	}

	// 1. Recheck registry ownership
	state := defaultRegistry.get(p.pid)
	if state == nil || state.isReaped() {
		return nil, failWithAbort(errors.New("darwinlaunch: child is no longer owned by registry"))
	}

	// 2. Recheck raw sysctl p_stat == 4 (SSTOP)
	var pstat C.int
	if C.check_process_sstop(C.pid_t(p.pid), &pstat) != 0 || pstat != 4 {
		return nil, failWithAbort(fmt.Errorf("darwinlaunch: child is not suspended (raw p_stat=%d)", pstat))
	}

	// 3. Recheck destination file inode, UID, nlink and permissions
	destInfo, err := os.Lstat(p.destPath)
	if err != nil {
		return nil, failWithAbort(fmt.Errorf("darwinlaunch: destination missing before resume: %w", err))
	}
	fdInfo, err := p.destFD.Stat()
	if err != nil || !os.SameFile(destInfo, fdInfo) {
		return nil, failWithAbort(errors.New("darwinlaunch: destination inode changed before resume"))
	}
	destSys, ok := destInfo.Sys().(*syscall.Stat_t)
	if !ok || destSys.Uid != uint32(os.Geteuid()) || destSys.Nlink != 1 {
		return nil, failWithAbort(errors.New("darwinlaunch: destination ownership or link count drift before resume"))
	}
	if destInfo.Mode().Perm() != 0500 || destInfo.Mode()&os.ModeSymlink != 0 {
		return nil, failWithAbort(errors.New("darwinlaunch: destination mode changed before resume"))
	}

	// 4. Recheck dynamic exact validity
	if ret := C.validate_dynamic_guest(C.pid_t(p.pid), p.reqRef); ret != 0 {
		return nil, failWithAbort(fmt.Errorf("%w: dynamic guest recheck failed: %d", ErrUntrustedExecutable, int(ret)))
	}

	// Send SIGCONT
	if err := defaultRegistry.signal(p.pid, syscall.SIGCONT); err != nil {
		return nil, failWithAbort(fmt.Errorf("darwinlaunch: failed to send SIGCONT: %w", err))
	}

	p.resumed = true
	return &OwnedChild{
		pid:             p.pid,
		destPath:        p.destPath,
		destFD:          p.destFD,
		sessionDir:      p.sessionDir,
		parentLifecycle: p.parentLifecycle,
		reqRef:          p.reqRef,
		state:           p.state,
	}, nil
}

func (p *PreparedChild) Abort(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.abortLocked(ctx)
}

func (p *PreparedChild) abortLocked(ctx context.Context) error {
	if p.resumed {
		return ErrAlreadyResumed
	}
	if p.aborted {
		return nil
	}

	if p.parentLifecycle != nil {
		_ = p.parentLifecycle.Close()
		p.parentLifecycle = nil
	}

	sigErr := defaultRegistry.signal(p.pid, syscall.SIGKILL)
	if sigErr != nil && !errors.Is(sigErr, syscall.ESRCH) {
		return &ChildRetainedError{
			Err:           fmt.Errorf("darwinlaunch: abort sigkill failed: %w", sigErr),
			PreparedChild: p,
			PID:           p.pid,
		}
	}

	select {
	case <-p.state.exitDone:
		p.aborted = true
		return nil
	case <-time.After(2 * time.Second):
		if p.state.isReaped() {
			p.aborted = true
			return nil
		}
		return &ChildRetainedError{
			Err:           ErrChildRetained,
			PreparedChild: p,
			PID:           p.pid,
		}
	case <-ctx.Done():
		if p.state.isReaped() {
			p.aborted = true
			return nil
		}
		return &ChildRetainedError{
			Err:           ctx.Err(),
			PreparedChild: p,
			PID:           p.pid,
		}
	}
}

// OwnedChild represents a running or exited child process whose lifetime is
// tracked exclusively by internal/darwinlaunch.
type OwnedChild struct {
	pid             int
	destPath        string
	destFD          *os.File
	sessionDir      string
	parentLifecycle *os.File
	reqRef          C.SecRequirementRef
	state           *childState
	mu              sync.Mutex
}

func (c *OwnedChild) PID() int {
	return c.pid
}

func (c *OwnedChild) Wait(ctx context.Context) ExitResult {
	select {
	case <-c.state.exitDone:
		// Wait for concurrent pipe drains to reach EOF before releasing outputs
		c.state.drainWG.Wait()

		c.state.mu.Lock()
		defer c.state.mu.Unlock()
		return ExitResult{
			ExitCode:        c.state.exitCode,
			Signal:          c.state.signal,
			Exited:          c.state.exited,
			Signaled:        c.state.signaled,
			Stdout:          c.state.stdoutDrain.Bytes(),
			Stderr:          c.state.stderrDrain.Bytes(),
			StdoutTruncated: c.state.stdoutDrain.IsTruncated(),
			StderrTruncated: c.state.stderrDrain.IsTruncated(),
			Err:             c.state.waitErr,
		}
	case <-ctx.Done():
		return ExitResult{
			Stdout:          c.state.stdoutDrain.Bytes(),
			Stderr:          c.state.stderrDrain.Bytes(),
			StdoutTruncated: c.state.stdoutDrain.IsTruncated(),
			StderrTruncated: c.state.stderrDrain.IsTruncated(),
			Err:             ctx.Err(),
		}
	}
}

func (c *OwnedChild) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Exact already-stopped is success
	if c.state.isReaped() {
		return nil
	}

	c.state.ensureWaiter()

	// Step 1: Close sole parent lifecycle socket endpoint (EOF cooperative signal)
	if c.parentLifecycle != nil {
		_ = c.parentLifecycle.Close()
		c.parentLifecycle = nil
	}

	// Step 2: Bounded wait for cooperative child exit
	select {
	case <-c.state.exitDone:
		return nil
	case <-time.After(1 * time.Second):
	case <-ctx.Done():
		return ctx.Err()
	}

	// Step 3: Direct-child SIGTERM fallback (never kill process group)
	if err := defaultRegistry.signal(c.pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return &ChildRetainedError{
			Err:        fmt.Errorf("darwinlaunch: sigterm failed: %w", err),
			OwnedChild: c,
			PID:        c.pid,
		}
	}

	select {
	case <-c.state.exitDone:
		return nil
	case <-time.After(500 * time.Millisecond):
	case <-ctx.Done():
		return ctx.Err()
	}

	// Step 4: Direct-child SIGKILL fallback
	if err := defaultRegistry.signal(c.pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return &ChildRetainedError{
			Err:        fmt.Errorf("darwinlaunch: sigkill failed: %w", err),
			OwnedChild: c,
			PID:        c.pid,
		}
	}

	select {
	case <-c.state.exitDone:
		return nil
	case <-time.After(2 * time.Second):
		if c.state.isReaped() {
			return nil
		}
		return &ChildRetainedError{
			Err:        ErrChildRetained,
			OwnedChild: c,
			PID:        c.pid,
		}
	case <-ctx.Done():
		return ctx.Err()
	}
}

func defaultNativeLaunchBaseDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("user home dir: %w", err)
	}
	return filepath.Join(home, "Library", "Application Support", "AcornFox", "native-launch"), nil
}

type launchConfig struct {
	identifier                 string
	args                       []string
	allowAdHoc                 bool
	baseDir                    string
	customReq                  string
	afterSpawnBeforeValidation func(destPath string, childPID int) error
}

func PrepareController(ctx context.Context, verifiedFD *os.File) (*PreparedChild, SourceIdentity, error) {
	if ctx == nil || ctx.Err() != nil || verifiedFD == nil {
		return nil, SourceIdentity{}, os.ErrInvalid
	}

	baseDir, err := defaultNativeLaunchBaseDir()
	if err != nil {
		return nil, SourceIdentity{}, err
	}

	cfg := launchConfig{
		identifier: ControllerIdentifier,
		args:       []string{"--controller"},
		allowAdHoc: false,
		baseDir:    baseDir,
	}

	return prepareChild(ctx, verifiedFD, cfg)
}

func PrepareSlotLauncher(ctx context.Context, verifiedFD *os.File, action LauncherAction) (*PreparedChild, SourceIdentity, error) {
	if ctx == nil || ctx.Err() != nil || verifiedFD == nil {
		return nil, SourceIdentity{}, os.ErrInvalid
	}

	var actionArg string
	switch action {
	case LauncherActionStart:
		actionArg = "start"
	case LauncherActionMaintenance:
		actionArg = "maintenance"
	case LauncherActionProbeHelper:
		actionArg = "probe-helper"
	default:
		return nil, SourceIdentity{}, ErrInvalidAction
	}

	baseDir, err := defaultNativeLaunchBaseDir()
	if err != nil {
		return nil, SourceIdentity{}, err
	}

	cfg := launchConfig{
		identifier: LauncherIdentifier,
		args:       []string{actionArg},
		allowAdHoc: false,
		baseDir:    baseDir,
	}

	return prepareChild(ctx, verifiedFD, cfg)
}

// prepareFixtureChild is an internal test helper only, unavailable in production commands.
func prepareFixtureChild(ctx context.Context, verifiedFD *os.File, baseDir, identifier string, args []string, allowAdHoc bool) (*PreparedChild, SourceIdentity, error) {
	cfg := launchConfig{
		identifier: identifier,
		args:       args,
		allowAdHoc: allowAdHoc,
		baseDir:    baseDir,
	}
	return prepareChild(ctx, verifiedFD, cfg)
}

// prepareFixtureChildWithReq compiles a custom requirement string for testing exact requirement mismatches.
func prepareFixtureChildWithReq(ctx context.Context, verifiedFD *os.File, baseDir, identifier string, args []string, allowAdHoc bool, customReq string) (*PreparedChild, SourceIdentity, error) {
	cfg := launchConfig{
		identifier: identifier,
		args:       args,
		allowAdHoc: allowAdHoc,
		baseDir:    baseDir,
		customReq:  customReq,
	}
	return prepareChild(ctx, verifiedFD, cfg)
}

// prepareFixtureChildWithHook allows injecting a pathname swap/restore hook between spawn and dynamic validation.
func prepareFixtureChildWithHook(
	ctx context.Context,
	verifiedFD *os.File,
	baseDir, identifier string,
	args []string,
	allowAdHoc bool,
	customReq string,
	afterSpawnBeforeValidation func(destPath string, childPID int) error,
) (*PreparedChild, SourceIdentity, error) {
	cfg := launchConfig{
		identifier:                 identifier,
		args:                       args,
		allowAdHoc:                 allowAdHoc,
		baseDir:                    baseDir,
		customReq:                  customReq,
		afterSpawnBeforeValidation: afterSpawnBeforeValidation,
	}
	return prepareChild(ctx, verifiedFD, cfg)
}

func prepareChild(ctx context.Context, verifiedFD *os.File, cfg launchConfig) (*PreparedChild, SourceIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, SourceIdentity{}, err
	}

	// 1. Verify source FD stat and Mach-O ARM64 exec headers
	srcStatBefore, err := verifiedFD.Stat()
	if err != nil {
		return nil, SourceIdentity{}, fmt.Errorf("source fstat failed: %w", err)
	}
	if !srcStatBefore.Mode().IsRegular() || srcStatBefore.Size() <= 0 || srcStatBefore.Size() > maxHostExecutableSize {
		return nil, SourceIdentity{}, ErrUntrustedExecutable
	}

	if err := verifyMachoArm64(verifiedFD); err != nil {
		return nil, SourceIdentity{}, fmt.Errorf("%w: %v", ErrUntrustedExecutable, err)
	}

	// 2. Validate running host identity if not allowAdHoc
	var hostTeamID string
	if !cfg.allowAdHoc {
		var teamBuf [64]C.char
		var hostFlags C.uint32_t
		ret := C.validate_host_self(&teamBuf[0], C.size_t(len(teamBuf)), &hostFlags)
		if ret != 0 {
			return nil, SourceIdentity{}, fmt.Errorf("%w: host self check returned %d", ErrUntrustedHost, int(ret))
		}
		hostTeamID = C.GoString(&teamBuf[0])
		if hostTeamID == "" || (uint32(hostFlags)&C.CS_RUNTIME == 0) || (uint32(hostFlags)&C.CS_ADHOC != 0) {
			return nil, SourceIdentity{}, fmt.Errorf("%w: host missing team ID or CS_RUNTIME", ErrUntrustedHost)
		}
	}

	// 3. Prepare private unpredictable runtime directory (0700 current user)
	if err := ctx.Err(); err != nil {
		return nil, SourceIdentity{}, err
	}
	if err := os.MkdirAll(cfg.baseDir, 0700); err != nil {
		return nil, SourceIdentity{}, fmt.Errorf("base dir mkdir: %w", err)
	}
	if err := os.Chmod(cfg.baseDir, 0700); err != nil {
		return nil, SourceIdentity{}, fmt.Errorf("base dir chmod: %w", err)
	}
	baseInfo, err := os.Stat(cfg.baseDir)
	if err != nil || baseInfo.Mode().Perm() != 0700 {
		return nil, SourceIdentity{}, fmt.Errorf("base dir permissions invalid: %w", err)
	}

	var sessionRand [16]byte
	if _, err := rand.Read(sessionRand[:]); err != nil {
		return nil, SourceIdentity{}, err
	}
	sessionDir := filepath.Join(cfg.baseDir, "session-"+hex.EncodeToString(sessionRand[:]))
	if err := os.Mkdir(sessionDir, 0700); err != nil {
		return nil, SourceIdentity{}, fmt.Errorf("session dir mkdir: %w", err)
	}
	cleanupSessionDir := true
	defer func() {
		if cleanupSessionDir {
			_ = os.RemoveAll(sessionDir)
		}
	}()

	destPath := filepath.Join(sessionDir, "acornfox-guest")
	destFD, err := os.OpenFile(destPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, SourceIdentity{}, fmt.Errorf("dest open: %w", err)
	}
	cleanupDestFD := true
	defer func() {
		if cleanupDestFD {
			_ = destFD.Close()
		}
	}()

	// 4. Materialization: read from source FD with pread from 0, stream to dest FD, compute SHA256 & size
	hasher := sha256.New()
	var totalWritten int64
	buf := make([]byte, 64*1024)
	var offset int64
	for {
		if err := ctx.Err(); err != nil {
			return nil, SourceIdentity{}, err
		}
		n, rerr := verifiedFD.ReadAt(buf, offset)
		if n > 0 {
			w, werr := destFD.Write(buf[:n])
			if werr != nil || w != n {
				return nil, SourceIdentity{}, fmt.Errorf("dest write failed: %w", werr)
			}
			hasher.Write(buf[:n])
			totalWritten += int64(n)
			offset += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, SourceIdentity{}, fmt.Errorf("source readat failed: %w", rerr)
		}
	}

	srcIdentity := SourceIdentity{
		SHA256: hex.EncodeToString(hasher.Sum(nil)),
		Size:   totalWritten,
	}

	// Verify source stat after copy
	srcStatAfter, err := verifiedFD.Stat()
	if err != nil || !os.SameFile(srcStatBefore, srcStatAfter) || srcStatAfter.Size() != totalWritten {
		return nil, SourceIdentity{}, errors.New("darwinlaunch: source file changed during materialization")
	}

	// fsync dest, chmod 0500, fsync session dir (strict error propagation)
	if err := destFD.Sync(); err != nil {
		return nil, SourceIdentity{}, fmt.Errorf("sync dest file: %w", err)
	}
	if err := destFD.Chmod(0500); err != nil {
		return nil, SourceIdentity{}, fmt.Errorf("chmod dest file: %w", err)
	}
	sessionDirF, err := os.Open(sessionDir)
	if err != nil {
		return nil, SourceIdentity{}, fmt.Errorf("open session dir for sync: %w", err)
	}
	if err := sessionDirF.Sync(); err != nil {
		_ = sessionDirF.Close()
		return nil, SourceIdentity{}, fmt.Errorf("sync session dir: %w", err)
	}
	if err := sessionDirF.Close(); err != nil {
		return nil, SourceIdentity{}, fmt.Errorf("close session dir: %w", err)
	}

	// Destination stat checks: regular, current owner, mode 0500, nlink 1, size == totalWritten
	destStat, err := destFD.Stat()
	if err != nil || !destStat.Mode().IsRegular() || destStat.Mode().Perm() != 0500 || destStat.Size() != totalWritten {
		return nil, SourceIdentity{}, errors.New("darwinlaunch: destination stat invalid after write")
	}
	destSys, ok := destStat.Sys().(*syscall.Stat_t)
	if !ok || destSys.Uid != uint32(os.Geteuid()) || destSys.Nlink != 1 {
		return nil, SourceIdentity{}, errors.New("darwinlaunch: destination ownership or link count invalid")
	}
	lstatDest, err := os.Lstat(destPath)
	if err != nil || !os.SameFile(destStat, lstatDest) || lstatDest.Mode()&os.ModeSymlink != 0 {
		return nil, SourceIdentity{}, errors.New("darwinlaunch: destination path-to-FD mismatch")
	}

	// Rehash from pinned destination FD from offset 0
	rehasher := sha256.New()
	var rehashOffset int64
	for {
		if err := ctx.Err(); err != nil {
			return nil, SourceIdentity{}, err
		}
		n, rerr := destFD.ReadAt(buf, rehashOffset)
		if n > 0 {
			rehasher.Write(buf[:n])
			rehashOffset += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, SourceIdentity{}, fmt.Errorf("dest rehash readat failed: %w", rerr)
		}
	}
	if rehashOffset != totalWritten || hex.EncodeToString(rehasher.Sum(nil)) != srcIdentity.SHA256 {
		return nil, SourceIdentity{}, errors.New("darwinlaunch: destination rehash mismatch")
	}

	if err := ctx.Err(); err != nil {
		return nil, SourceIdentity{}, err
	}

	// 5. Static code inspection and requirement compilation
	cDestPath := C.CString(destPath)
	defer C.free(unsafe.Pointer(cDestPath))

	var idBuf [256]C.char
	var teamBuf [64]C.char
	var cdhashBuf [128]C.char
	var staticFlags C.uint32_t
	var isValid C.int

	inspectRet := C.inspect_static_code(
		cDestPath,
		&idBuf[0], C.size_t(len(idBuf)),
		&teamBuf[0], C.size_t(len(teamBuf)),
		&cdhashBuf[0], C.size_t(len(cdhashBuf)),
		&staticFlags,
		&isValid,
	)
	if inspectRet != 0 {
		return nil, SourceIdentity{}, fmt.Errorf("%w: inspect_static_code error: %d", ErrUntrustedExecutable, int(inspectRet))
	}

	staticIdentifier := C.GoString(&idBuf[0])
	staticTeamID := C.GoString(&teamBuf[0])
	staticCDHash := C.GoString(&cdhashBuf[0])

	if staticCDHash == "" {
		return nil, SourceIdentity{}, fmt.Errorf("%w: missing CDHash", ErrUntrustedExecutable)
	}

	if !cfg.allowAdHoc {
		if isValid != 1 {
			return nil, SourceIdentity{}, fmt.Errorf("%w: static validity check failed", ErrUntrustedExecutable)
		}
		if staticIdentifier != cfg.identifier {
			return nil, SourceIdentity{}, fmt.Errorf("%w: identifier mismatch (%q != %q)", ErrUntrustedExecutable, staticIdentifier, cfg.identifier)
		}
		if staticTeamID != hostTeamID {
			return nil, SourceIdentity{}, fmt.Errorf("%w: team ID mismatch (%q != %q)", ErrUntrustedExecutable, staticTeamID, hostTeamID)
		}
		if (uint32(staticFlags)&C.CS_RUNTIME == 0) || (uint32(staticFlags)&C.CS_ADHOC != 0) {
			return nil, SourceIdentity{}, fmt.Errorf("%w: executable lacks CS_RUNTIME or is ad-hoc", ErrUntrustedExecutable)
		}
	}

	reqIdentifier := cfg.identifier
	if cfg.allowAdHoc && staticIdentifier != "" {
		reqIdentifier = staticIdentifier
	}

	var reqRef C.SecRequirementRef
	cTeamID := C.CString(staticTeamID)
	defer C.free(unsafe.Pointer(cTeamID))
	cIdentifier := C.CString(reqIdentifier)
	defer C.free(unsafe.Pointer(cIdentifier))
	cCDHash := C.CString(staticCDHash)
	defer C.free(unsafe.Pointer(cCDHash))

	var reqStrBuf [1024]C.char
	var compileRet C.int
	if cfg.customReq != "" {
		cCustomReq := C.CString(cfg.customReq)
		defer C.free(unsafe.Pointer(cCustomReq))
		cfCustomStr := C.CFStringCreateWithCString(C.kCFAllocatorDefault, cCustomReq, C.kCFStringEncodingUTF8)
		if cfCustomStr != 0 {
			compileRet = C.int(C.SecRequirementCreateWithString(C.CFStringRef(cfCustomStr), C.kSecCSDefaultFlags, &reqRef))
			C.CFRelease(C.CFTypeRef(cfCustomStr))
		} else {
			compileRet = -1
		}
	} else {
		compileRet = C.compile_exact_requirement(
			cTeamID,
			cIdentifier,
			cCDHash,
			C.int(boolToInt(cfg.allowAdHoc)),
			&reqRef,
			&reqStrBuf[0],
			C.size_t(len(reqStrBuf)),
		)
	}
	if compileRet != 0 || C.is_null_requirement(reqRef) != 0 {
		return nil, SourceIdentity{}, fmt.Errorf("%w: compile requirement failed: %d", ErrUntrustedExecutable, int(compileRet))
	}

	// 6. Immediate pre-spawn path-to-FD verification
	preSpawnStat, err := os.Lstat(destPath)
	if err != nil || !os.SameFile(destStat, preSpawnStat) || preSpawnStat.Mode()&os.ModeSymlink != 0 {
		C.release_requirement(reqRef)
		return nil, SourceIdentity{}, errors.New("darwinlaunch: destination tampered immediately before spawn")
	}

	if err := ctx.Err(); err != nil {
		C.release_requirement(reqRef)
		return nil, SourceIdentity{}, err
	}

	// 7. Setup spawn FDs: lifecycle socketpair, stdout pipe, stderr pipe, /dev/null
	lifecycleFds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		C.release_requirement(reqRef)
		return nil, SourceIdentity{}, fmt.Errorf("lifecycle socketpair: %w", err)
	}
	syscall.CloseOnExec(lifecycleFds[0])
	parentLifecycle := os.NewFile(uintptr(lifecycleFds[0]), "parent-lifecycle")
	childLifecycleFD := lifecycleFds[1]

	prOut, pwOut, err := os.Pipe()
	if err != nil {
		_ = parentLifecycle.Close()
		_ = syscall.Close(childLifecycleFD)
		C.release_requirement(reqRef)
		return nil, SourceIdentity{}, err
	}
	prErr, pwErr, err := os.Pipe()
	if err != nil {
		_ = parentLifecycle.Close()
		_ = syscall.Close(childLifecycleFD)
		_ = prOut.Close()
		_ = pwOut.Close()
		C.release_requirement(reqRef)
		return nil, SourceIdentity{}, err
	}

	devnull, err := os.OpenFile("/dev/null", os.O_RDONLY, 0)
	if err != nil {
		_ = parentLifecycle.Close()
		_ = syscall.Close(childLifecycleFD)
		_ = prOut.Close()
		_ = pwOut.Close()
		_ = prErr.Close()
		_ = pwErr.Close()
		C.release_requirement(reqRef)
		return nil, SourceIdentity{}, err
	}

	if err := ctx.Err(); err != nil {
		_ = parentLifecycle.Close()
		_ = syscall.Close(childLifecycleFD)
		_ = prOut.Close()
		_ = pwOut.Close()
		_ = prErr.Close()
		_ = pwErr.Close()
		_ = devnull.Close()
		C.release_requirement(reqRef)
		return nil, SourceIdentity{}, err
	}

	argv := append([]string{destPath}, cfg.args...)
	envp := []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}

	cArgv, cleanupArgv := cStringArray(argv)
	defer cleanupArgv()
	cEnvp, cleanupEnvp := cStringArray(envp)
	defer cleanupEnvp()

	var childPID C.pid_t
	spawnRet := C.spawn_suspended_child(
		cDestPath,
		cArgv,
		cEnvp,
		C.int(devnull.Fd()),
		C.int(pwOut.Fd()),
		C.int(pwErr.Fd()),
		C.int(childLifecycleFD),
		&childPID,
	)

	_ = devnull.Close()
	_ = syscall.Close(childLifecycleFD)
	_ = pwOut.Close()
	_ = pwErr.Close()

	if spawnRet != 0 {
		_ = parentLifecycle.Close()
		_ = prOut.Close()
		_ = prErr.Close()
		C.release_requirement(reqRef)
		return nil, SourceIdentity{}, fmt.Errorf("%w: posix_spawn failed: %d", ErrExecutionFailed, int(spawnRet))
	}

	pid := int(childPID)
	stdoutDrain := newCappedBuffer(maxPipeDrainBytes)
	stderrDrain := newCappedBuffer(maxPipeDrainBytes)

	state := &childState{
		pid:             pid,
		exitDone:        make(chan struct{}),
		stdoutDrain:     stdoutDrain,
		stderrDrain:     stderrDrain,
		prOut:           prOut,
		prErr:           prErr,
		destPath:        destPath,
		destFD:          destFD,
		sessionDir:      sessionDir,
		reqRef:          reqRef,
		parentLifecycle: parentLifecycle,
	}

	// Concurrently drain stdout and stderr without blocking
	state.drainWG.Add(2)
	go func() {
		defer state.drainWG.Done()
		_, _ = io.Copy(stdoutDrain, prOut)
	}()
	go func() {
		defer state.drainWG.Done()
		_, _ = io.Copy(stderrDrain, prErr)
	}()

	// Register in registry immediately
	defaultRegistry.register(state)

	prepared := &PreparedChild{
		pid:             pid,
		destPath:        destPath,
		destFD:          destFD,
		sessionDir:      sessionDir,
		parentLifecycle: parentLifecycle,
		reqRef:          reqRef,
		state:           state,
	}

	cleanupSessionDir = false
	cleanupDestFD = false

	failPostSpawn := func(cause error) (*PreparedChild, SourceIdentity, error) {
		abortErr := prepared.Abort(context.Background())
		if abortErr != nil {
			return prepared, srcIdentity, &ChildRetainedError{
				Err:           fmt.Errorf("%w (abort cleanup failed: %v)", cause, abortErr),
				PreparedChild: prepared,
				PID:           prepared.PID(),
			}
		}
		return nil, SourceIdentity{}, cause
	}

	// Check cancellation immediately after spawn
	if err := ctx.Err(); err != nil {
		return failPostSpawn(err)
	}

	// 8. Verify raw p_stat == SSTOP (4)
	var pstat C.int
	if C.check_process_sstop(childPID, &pstat) != 0 || pstat != 4 {
		return failPostSpawn(fmt.Errorf("darwinlaunch: child not in SSTOP state: p_stat=%d", int(pstat)))
	}

	// Execute test hook if provided (e.g. pathname swap/restore while child remains suspended)
	if cfg.afterSpawnBeforeValidation != nil {
		if err := cfg.afterSpawnBeforeValidation(destPath, pid); err != nil {
			return failPostSpawn(err)
		}
	}

	// Verify child has not written anything before admission
	if len(stdoutDrain.Bytes()) > 0 || len(stderrDrain.Bytes()) > 0 {
		return failPostSpawn(errors.New("darwinlaunch: child executed code before resume"))
	}

	// 9. Dynamic guest validation
	guestRet := C.validate_dynamic_guest(childPID, reqRef)
	if guestRet != 0 {
		return failPostSpawn(fmt.Errorf("%w: dynamic validation failed: %d", ErrUntrustedExecutable, int(guestRet)))
	}

	return prepared, srcIdentity, nil
}

func verifyMachoArm64(f *os.File) error {
	m, err := macho.NewFile(f)
	if err != nil {
		return err
	}
	defer m.Close()
	if m.Magic != macho.Magic64 || m.Type != macho.TypeExec || m.Cpu != macho.CpuArm64 {
		return fmt.Errorf("magic=%x type=%x cpu=%x", m.Magic, m.Type, m.Cpu)
	}
	return nil
}

func cStringArray(strs []string) (**C.char, func()) {
	cArray := C.malloc(C.size_t(len(strs)+1) * C.size_t(unsafe.Sizeof(uintptr(0))))
	slice := (*[1 << 20]*C.char)(cArray)[: len(strs)+1 : len(strs)+1]
	for i, s := range strs {
		slice[i] = C.CString(s)
	}
	slice[len(strs)] = nil
	cleanup := func() {
		for i := 0; i < len(strs); i++ {
			C.free(unsafe.Pointer(slice[i]))
		}
		C.free(cArray)
	}
	return (**C.char)(cArray), cleanup
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CheckProcessSStop inspects the raw p_stat of a process via sysctl.
// Returns raw p_stat (SSTOP is 4).
func CheckProcessSStop(pid int) (int, error) {
	var pstat C.int
	if ret := C.check_process_sstop(C.pid_t(pid), &pstat); ret != 0 {
		return 0, fmt.Errorf("sysctl check_process_sstop error: %d", int(ret))
	}
	return int(pstat), nil
}

// Fault injection and inspection helpers (unexported, test use only)
func injectKillDenial(pid int) {
	defaultRegistry.injectKillDenial(pid)
}

func injectWaitpidFailure(pid int) {
	defaultRegistry.injectWaitpidFailure(pid)
}

func clearFaultInjections() {
	defaultRegistry.clearInjections()
	clearSpawnFailure()
}

func activeChildCount() int {
	return defaultRegistry.activeCount()
}

func getStaticCodeSigningInfo(path string) (identifier string, cdhash string, err error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var idBuf [256]C.char
	var teamBuf [64]C.char
	var cdhashBuf [128]C.char
	var staticFlags C.uint32_t
	var isValid C.int

	ret := C.inspect_static_code(
		cPath,
		&idBuf[0], C.size_t(len(idBuf)),
		&teamBuf[0], C.size_t(len(teamBuf)),
		&cdhashBuf[0], C.size_t(len(cdhashBuf)),
		&staticFlags,
		&isValid,
	)
	if ret != 0 {
		return "", "", fmt.Errorf("inspect_static_code failed: %d", int(ret))
	}
	return C.GoString(&idBuf[0]), C.GoString(&cdhashBuf[0]), nil
}
