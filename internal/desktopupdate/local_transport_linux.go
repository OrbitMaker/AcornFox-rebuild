//go:build linux

package desktopupdate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const DefaultGuestUpdateExecutablePath = "/usr/local/libexec/acornfox-guest-update"

const (
	pPID               = 1          // P_PID in Linux sys/wait.h
	wNOHANG            = 1          // WNOHANG
	wEXITED            = 4          // WEXITED
	wNOWAIT            = 0x01000000 // WNOWAIT
	sysPidfdSendSignal = 424
	sysPidfdOpen       = 434
)

var (
	ErrPrivilegeRequired = errors.New("desktopupdate: privileged supervisor required")
	ErrInvalidCommand    = errors.New("desktopupdate: invalid guest command")
	ErrUnsupportedStream = errors.New("desktopupdate: unsupported or non-cancellable stream type")
)

type cleanupMode int

const (
	cleanupGroupRequired cleanupMode = iota
	cleanupDirectOnly
)

type ownerStatus int

const (
	ownerRetained ownerStatus = iota
	ownerCleaned
)

type retainedProcessOwner struct {
	mu         sync.Mutex
	cmd        *exec.Cmd
	childPidFD int
	pgid       int
	mode       cleanupMode
	status     ownerStatus
	done       chan struct{}
	stopReaper chan struct{}
	waitCalled bool
	waitErr    error
}

func (o *retainedProcessOwner) isResolved() bool {
	select {
	case <-o.done:
		return true
	default:
		return false
	}
}

func (o *retainedProcessOwner) Mode() cleanupMode {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.mode
}

func (o *retainedProcessOwner) Status() ownerStatus {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.status
}

func (o *retainedProcessOwner) WaitCalled() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.waitCalled
}

func (o *retainedProcessOwner) ChildPidFD() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.childPidFD
}

func (o *retainedProcessOwner) PGID() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.pgid
}

func (o *retainedProcessOwner) Done() <-chan struct{} {
	return o.done
}

func (o *retainedProcessOwner) runReaper() {
	defer close(o.done)
	defer func() {
		o.mu.Lock()
		if o.childPidFD >= 0 {
			_ = syscall.Close(o.childPidFD)
			o.childPidFD = -1
		}
		o.mu.Unlock()
	}()

	backoff := 10 * time.Millisecond
	maxBackoff := 100 * time.Millisecond

	for {
		select {
		case <-o.stopReaper:
			return
		default:
		}

		if o.mode == cleanupGroupRequired {
			err := doSyscallKill(-o.pgid, syscall.SIGKILL)
			if err == nil || errors.Is(err, syscall.ESRCH) {
				o.mu.Lock()
				o.waitErr = o.cmd.Wait()
				o.waitCalled = true
				o.status = ownerCleaned
				o.mu.Unlock()
				return
			}
		} else if o.mode == cleanupDirectOnly {
			o.mu.Lock()
			fd := o.childPidFD
			o.mu.Unlock()
			if fd >= 0 {
				err := doPidfdSendSignal(uintptr(fd), syscall.SIGKILL)
				if err == nil || errors.Is(err, syscall.ESRCH) {
					o.mu.Lock()
					o.waitErr = o.cmd.Wait()
					o.waitCalled = true
					o.status = ownerCleaned
					o.mu.Unlock()
					return
				}
			}
		}

		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

type localGuestTransportManager struct {
	mu             sync.Mutex
	sem            chan struct{}
	executablePath string
	retained       *retainedProcessOwner
}

func (m *localGuestTransportManager) RetainedOwner() *retainedProcessOwner {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.retained
}

var (
	registryMu      sync.Mutex
	managerRegistry = make(map[string]*localGuestTransportManager)
)

func getOrCreateManager(execPath string) *localGuestTransportManager {
	registryMu.Lock()
	defer registryMu.Unlock()
	cleanPath := filepath.Clean(execPath)
	mgr, exists := managerRegistry[cleanPath]
	if !exists {
		mgr = &localGuestTransportManager{
			executablePath: cleanPath,
			sem:            make(chan struct{}, 1),
		}
		managerRegistry[cleanPath] = mgr
	}
	return mgr
}

func resetManagerRegistryForTest() {
	registryMu.Lock()
	defer registryMu.Unlock()
	managerRegistry = make(map[string]*localGuestTransportManager)
}

// Private test hooks protected by RWMutex for race-safety.
var (
	hookMu                  sync.RWMutex
	testPreflightHook       func() error
	testHookWaitidNoReap    func(pid int) error
	testHookSyscallKill     func(pid int, sig syscall.Signal) error
	testHookPidfdSendSignal func(pidfd uintptr, sig syscall.Signal) error
)

func setTestHookPreflight(h func() error) {
	hookMu.Lock()
	testPreflightHook = h
	hookMu.Unlock()
}

func setTestHookWaitidNoReap(h func(pid int) error) {
	hookMu.Lock()
	testHookWaitidNoReap = h
	hookMu.Unlock()
}

func setTestHookSyscallKill(h func(pid int, sig syscall.Signal) error) {
	hookMu.Lock()
	testHookSyscallKill = h
	hookMu.Unlock()
}

func setTestHookPidfdSendSignal(h func(pidfd uintptr, sig syscall.Signal) error) {
	hookMu.Lock()
	testHookPidfdSendSignal = h
	hookMu.Unlock()
}

func doSyscallKill(pid int, sig syscall.Signal) error {
	hookMu.RLock()
	h := testHookSyscallKill
	hookMu.RUnlock()
	if h != nil {
		return h(pid, sig)
	}
	return syscall.Kill(pid, sig)
}

func rawPidfdOpen(pid int, flags int) (int, error) {
	fd, _, errno := syscall.Syscall(sysPidfdOpen, uintptr(pid), uintptr(flags), 0)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

func rawPidfdSendSignal(pidfd uintptr, sig syscall.Signal) error {
	_, _, errno := syscall.Syscall(sysPidfdSendSignal, pidfd, uintptr(sig), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func doPidfdSendSignal(pidfd uintptr, sig syscall.Signal) error {
	hookMu.RLock()
	h := testHookPidfdSendSignal
	hookMu.RUnlock()
	if h != nil {
		return h(pidfd, sig)
	}
	return rawPidfdSendSignal(pidfd, sig)
}

func doWaitidNoReap(pid int) error {
	hookMu.RLock()
	h := testHookWaitidNoReap
	hookMu.RUnlock()
	if h != nil {
		return h(pid)
	}
	return waitidNoReap(pid)
}

// preflightCapabilities verifies the required kernel capabilities fail-closed before spawn.
func preflightCapabilities() error {
	hookMu.RLock()
	h := testPreflightHook
	hookMu.RUnlock()
	if h != nil {
		if err := h(); err != nil {
			return ErrGuestTransport
		}
		return nil
	}

	// 1. Preflight waitid with WNOHANG|WEXITED|WNOWAIT against current PID.
	// ECHILD is the expected proof that the syscall and option set are accepted.
	var siginfo [128]byte
	for {
		_, _, errno := syscall.Syscall6(
			syscall.SYS_WAITID,
			uintptr(pPID),
			uintptr(syscall.Getpid()),
			uintptr(unsafe.Pointer(&siginfo[0])),
			uintptr(wEXITED|wNOWAIT|wNOHANG),
			0,
			0,
		)
		if errno == syscall.EINTR {
			continue
		}
		if errno != syscall.ECHILD {
			return ErrGuestTransport
		}
		break
	}

	// 2. Open a pidfd for the current process with raw pidfd_open, send signal 0, then close it.
	fd, err := rawPidfdOpen(syscall.Getpid(), 0)
	if err != nil {
		return ErrGuestTransport
	}
	defer syscall.Close(fd)

	if err := rawPidfdSendSignal(uintptr(fd), 0); err != nil {
		return ErrGuestTransport
	}

	return nil
}

// NewPrivilegedLocalGuestTransport returns a GuestTransport for an already privileged
// Linux supervisor that executes the fixed, root-owned updater at
// /usr/local/libexec/acornfox-guest-update.
// It accepts no path, environment, shell, privilege elevation or destination overrides.
// Callers without root privileges fail closed.
func NewPrivilegedLocalGuestTransport() GuestTransport {
	return newLocalGuestTransport(DefaultGuestUpdateExecutablePath)
}

// newLocalGuestTransport is package-private to desktopupdate for test injection only.
func newLocalGuestTransport(execPath string) GuestTransport {
	mgr := getOrCreateManager(execPath)
	return func(ctx context.Context, command GuestCommand, stdin io.Reader, stdout io.Writer) (int, error) {
		return mgr.execute(ctx, command, stdin, stdout)
	}
}

func validateGuestCommand(cmd GuestCommand) error {
	switch cmd.verb {
	case "observe":
		if cmd.attempt != "" && validateSHA256(cmd.attempt) != nil {
			return ErrInvalidCommand
		}
	case "status":
		if cmd.attempt == "" || validateSHA256(cmd.attempt) != nil {
			return ErrInvalidCommand
		}
	case "submit":
		if cmd.attempt != "" {
			return ErrInvalidCommand
		}
	case "recover":
		if cmd.attempt == "" || validateSHA256(cmd.attempt) != nil {
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	return nil
}

// validateStreamTypes restricts input and output streams strictly to the concrete
// types used by GuestBackend. Generic io.Closer or arbitrary unclosable blocking
// streams are rejected before process spawn.
func validateStreamTypes(stdin io.Reader, stdout io.Writer) error {
	if stdin != nil {
		switch stdin.(type) {
		case *bytes.Reader, *strings.Reader, *bytes.Buffer, *io.PipeReader:
			// Approved concrete input streams
		default:
			return ErrUnsupportedStream
		}
	}
	if stdout != nil {
		switch stdout.(type) {
		case *bytes.Buffer, *guestOutput:
			// Approved in-memory output streams
		default:
			if stdout != io.Discard {
				return ErrUnsupportedStream
			}
		}
	}
	return nil
}

// waitidNoReap observes direct-child termination without reaping it,
// keeping the child PID unreaped while cancellation and pipe cleanup settle.
func waitidNoReap(pid int) error {
	var siginfo [128]byte
	for {
		_, _, errno := syscall.Syscall6(
			syscall.SYS_WAITID,
			uintptr(pPID),
			uintptr(pid),
			uintptr(unsafe.Pointer(&siginfo[0])),
			uintptr(wEXITED|wNOWAIT),
			0,
			0,
		)
		if errno == 0 {
			return nil
		}
		if errno == syscall.EINTR {
			continue
		}
		return errno
	}
}

// pinPathChain performs descriptor-relative traversal starting from root "/"
// using openat with O_NOFOLLOW on each component. It verifies that every parent
// directory and the target executable are owned by root, not group- or other-writable,
// and not symlinks. The final executable descriptor is returned for execution.
func pinPathChain(execPath string) ([]*os.File, *os.File, error) {
	if !filepath.IsAbs(execPath) || filepath.Clean(execPath) != execPath || execPath == "/" {
		return nil, nil, ErrInvalidOptions
	}

	var pins []*os.File
	closePins := func() {
		for _, f := range pins {
			_ = f.Close()
		}
	}

	// 1. Open root "/"
	rootFD, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, ErrGuestTransport
	}
	rootF := os.NewFile(uintptr(rootFD), "/")
	pins = append(pins, rootF)

	var st syscall.Stat_t
	if err := syscall.Fstat(rootFD, &st); err != nil || st.Uid != 0 || (st.Mode&0022 != 0 && !(st.Uid == 0 && st.Mode&syscall.S_ISVTX != 0)) {
		closePins()
		return nil, nil, ErrGuestTransport
	}

	// 2. Traversal relative to rootFD using Openat with O_NOFOLLOW
	clean := filepath.Clean(execPath)
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	if len(parts) == 0 {
		closePins()
		return nil, nil, ErrInvalidOptions
	}

	curFD := rootFD
	for i := 0; i < len(parts)-1; i++ {
		part := parts[i]
		if part == "" || part == "." || part == ".." {
			closePins()
			return nil, nil, ErrInvalidOptions
		}
		nextFD, err := syscall.Openat(curFD, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			closePins()
			return nil, nil, ErrGuestTransport
		}
		nextF := os.NewFile(uintptr(nextFD), part)
		pins = append(pins, nextF)

		if err := syscall.Fstat(nextFD, &st); err != nil {
			closePins()
			return nil, nil, ErrGuestTransport
		}
		if st.Uid != 0 || st.Mode&syscall.S_IFDIR == 0 || (st.Mode&0022 != 0 && !(st.Uid == 0 && st.Mode&syscall.S_ISVTX != 0)) {
			closePins()
			return nil, nil, ErrGuestTransport
		}
		curFD = nextFD
	}

	// 3. Open final executable relative to last parent directory
	execName := parts[len(parts)-1]
	execFD, err := syscall.Openat(curFD, execName, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		closePins()
		return nil, nil, ErrGuestTransport
	}
	execF := os.NewFile(uintptr(execFD), execName)
	pins = append(pins, execF)

	if err := syscall.Fstat(execFD, &st); err != nil {
		closePins()
		return nil, nil, ErrGuestTransport
	}
	if st.Uid != 0 || st.Mode&syscall.S_IFREG == 0 || st.Mode&0022 != 0 || st.Mode&0111 == 0 || st.Nlink != 1 {
		closePins()
		return nil, nil, ErrGuestTransport
	}

	return pins, execF, nil
}

type processPhase int

const (
	phaseRunning processPhase = iota
	phaseObservedUnreaped
	phaseFailed
	phaseReaped
)

type waitResult struct {
	err error
}

func (m *localGuestTransportManager) execute(ctx context.Context, command GuestCommand, stdin io.Reader, stdout io.Writer) (int, error) {
	if os.Geteuid() != 0 {
		return 0, ErrPrivilegeRequired
	}
	if ctx == nil {
		return 0, ErrInvalidOptions
	}

	// 1. Unresolved retained owner has highest priority: shared helper is unavailable
	m.mu.Lock()
	if m.retained != nil {
		if m.retained.isResolved() {
			m.retained = nil
		} else {
			m.mu.Unlock()
			return 0, ErrGuestProcessRetained
		}
	}
	m.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := validateGuestCommand(command); err != nil {
		return 0, err
	}
	if err := validateStreamTypes(stdin, stdout); err != nil {
		return 0, err
	}

	// Context-aware admission: acquire execution token or fail-closed on cancellation
	select {
	case <-ctx.Done():
		m.mu.Lock()
		if m.retained != nil && !m.retained.isResolved() {
			m.mu.Unlock()
			return 0, ErrGuestProcessRetained
		}
		m.mu.Unlock()
		return 0, ctx.Err()
	case m.sem <- struct{}{}:
	}
	defer func() { <-m.sem }()

	m.mu.Lock()
	if m.retained != nil {
		if m.retained.isResolved() {
			m.retained = nil
		} else {
			m.mu.Unlock()
			return 0, ErrGuestProcessRetained
		}
	}
	m.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	if err := preflightCapabilities(); err != nil {
		return 0, err
	}

	pins, execF, err := pinPathChain(m.executablePath)
	if err != nil {
		return 0, err
	}
	defer func() {
		for _, f := range pins {
			_ = f.Close()
		}
	}()

	args := command.Arguments()

	// Use managed os.Pipe for standard streams
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return 0, ErrGuestTransport
	}
	defer stdinW.Close()

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		_ = stdinR.Close()
		return 0, ErrGuestTransport
	}
	defer stdoutR.Close()

	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		_ = stdinR.Close()
		_ = stdoutR.Close()
		return 0, ErrGuestTransport
	}
	defer stderrR.Close()

	// Execute exclusively via /proc/self/fd/3 with the verified descriptor in ExtraFiles[0]
	cmd := exec.Command("/proc/self/fd/3", args...)
	cmd.Args = append([]string{m.executablePath}, args...)
	cmd.ExtraFiles = []*os.File{execF}
	cmd.Env = []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
	}

	var childPidFD int = -1
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		PidFD:   &childPidFD,
	}

	cmd.Stdin = stdinR
	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW

	if err := cmd.Start(); err != nil {
		_ = stdinR.Close()
		_ = stdoutW.Close()
		_ = stderrR.Close()
		return 0, ErrGuestTransport
	}

	// Parent closes child ends immediately
	_ = stdinR.Close()
	_ = stdoutW.Close()
	_ = stderrW.Close()

	pid := cmd.Process.Pid
	pgid := pid

	if childPidFD < 0 {
		fd, err := rawPidfdOpen(pid, 0)
		if err != nil {
			_ = doSyscallKill(-pid, syscall.SIGKILL)
			_ = cmd.Wait()
			return 0, ErrGuestTransport
		}
		childPidFD = fd
	}

	transferred := false
	closeChildPidFD := func() {
		if !transferred && childPidFD >= 0 {
			_ = syscall.Close(childPidFD)
			childPidFD = -1
		}
	}
	defer closeChildPidFD()

	var processMu sync.Mutex
	phase := phaseRunning
	var killSent bool
	var observerFailed bool

	killGroupLocked := func() error {
		if !observerFailed && (phase == phaseRunning || phase == phaseObservedUnreaped) && !killSent && pgid > 1 {
			err := doSyscallKill(-pgid, syscall.SIGKILL)
			if err == nil || errors.Is(err, syscall.ESRCH) {
				killSent = true
				return nil
			}
			return err
		}
		return nil
	}

	killDirectChildPidFD := func() error {
		if childPidFD >= 0 {
			err := doPidfdSendSignal(uintptr(childPidFD), syscall.SIGKILL)
			if err == nil || errors.Is(err, syscall.ESRCH) {
				return nil
			}
			return err
		}
		return nil
	}

	// 1. waitid worker: observes child termination without reaping
	waitResultCh := make(chan waitResult, 1)
	go func() {
		err := doWaitidNoReap(pid)
		waitResultCh <- waitResult{err: err}
	}()

	// 2. Stdin worker
	stdinDone := make(chan struct{})
	go func() {
		defer close(stdinDone)
		defer stdinW.Close()
		if stdin != nil {
			buf := make([]byte, 32*1024)
			for {
				n, rErr := stdin.Read(buf)
				if n > 0 {
					if _, wErr := stdinW.Write(buf[:n]); wErr != nil {
						return
					}
				}
				if rErr != nil {
					return
				}
			}
		}
	}()

	// 3. Stdout worker
	var stdoutErr error
	stdoutDone := make(chan struct{})
	stdoutFailed := make(chan error, 1)
	go func() {
		defer close(stdoutDone)
		defer stdoutR.Close()
		buf := make([]byte, 4096)
		for {
			n, rErr := stdoutR.Read(buf)
			if n > 0 && stdout != nil {
				if _, wErr := stdout.Write(buf[:n]); wErr != nil {
					stdoutErr = wErr
					select {
					case stdoutFailed <- wErr:
					default:
					}
					return
				}
			}
			if rErr != nil {
				return
			}
		}
	}()

	// 4. Stderr worker (discard with bounded memory)
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		defer stderrR.Close()
		lim := io.LimitReader(stderrR, 64*1024)
		_, _ = io.Copy(io.Discard, lim)
		_, _ = io.Copy(io.Discard, stderrR)
	}()

	transferOwnership := func(mode cleanupMode) (int, error) {
		transferred = true

		_ = stdinW.Close()
		_ = stdoutR.Close()
		_ = stderrR.Close()
		if pr, ok := stdin.(*io.PipeReader); ok {
			_ = pr.CloseWithError(ErrGuestProcessRetained)
		}

		const joinGrace = 500 * time.Millisecond
		joinTimer := time.NewTimer(joinGrace)
		select {
		case <-stdinDone:
		case <-joinTimer.C:
		}
		select {
		case <-stdoutDone:
		case <-joinTimer.C:
		}
		select {
		case <-stderrDone:
		case <-joinTimer.C:
		}
		joinTimer.Stop()

		_ = stdoutR.Close()
		_ = stderrR.Close()

		<-stdinDone
		<-stdoutDone
		<-stderrDone

		owner := &retainedProcessOwner{
			cmd:        cmd,
			childPidFD: childPidFD,
			pgid:       pgid,
			mode:       mode,
			status:     ownerRetained,
			done:       make(chan struct{}),
			stopReaper: make(chan struct{}),
		}

		m.mu.Lock()
		m.retained = owner
		m.mu.Unlock()

		go owner.runReaper()

		return 0, ErrGuestProcessRetained
	}

	var fatalObserverError bool

	// Calling goroutine is the sole supervisor
	select {
	case <-ctx.Done():
		processMu.Lock()
		kErr := killGroupLocked()
		processMu.Unlock()
		_ = stdinW.Close()
		_ = stdoutR.Close()
		if pr, ok := stdin.(*io.PipeReader); ok {
			_ = pr.CloseWithError(ctx.Err())
		}
		res := <-waitResultCh
		if res.err != nil {
			processMu.Lock()
			observerFailed = true
			phase = phaseFailed
			processMu.Unlock()
			fatalObserverError = true
			if pErr := killDirectChildPidFD(); pErr != nil {
				return transferOwnership(cleanupDirectOnly)
			}
		} else {
			processMu.Lock()
			phase = phaseObservedUnreaped
			processMu.Unlock()
			if kErr != nil {
				return transferOwnership(cleanupGroupRequired)
			}
		}

	case err := <-stdoutFailed:
		stdoutErr = err
		processMu.Lock()
		kErr := killGroupLocked()
		processMu.Unlock()
		_ = stdinW.Close()
		_ = stdoutR.Close()
		if pr, ok := stdin.(*io.PipeReader); ok {
			_ = pr.CloseWithError(err)
		}
		res := <-waitResultCh
		if res.err != nil {
			processMu.Lock()
			observerFailed = true
			phase = phaseFailed
			processMu.Unlock()
			fatalObserverError = true
			if pErr := killDirectChildPidFD(); pErr != nil {
				return transferOwnership(cleanupDirectOnly)
			}
		} else {
			processMu.Lock()
			phase = phaseObservedUnreaped
			processMu.Unlock()
			if kErr != nil {
				return transferOwnership(cleanupGroupRequired)
			}
		}

	case res := <-waitResultCh:
		if res.err != nil {
			processMu.Lock()
			observerFailed = true
			phase = phaseFailed
			processMu.Unlock()
			fatalObserverError = true
			if pErr := killDirectChildPidFD(); pErr != nil {
				return transferOwnership(cleanupDirectOnly)
			}
		} else {
			processMu.Lock()
			phase = phaseObservedUnreaped
			processMu.Unlock()
		}
	}

	if fatalObserverError {
		_ = stdinW.Close()
		_ = stdoutR.Close()
		_ = stderrR.Close()
		if pr, ok := stdin.(*io.PipeReader); ok {
			_ = pr.CloseWithError(ErrGuestTransport)
		}

		const drainGrace = 500 * time.Millisecond
		graceTimer := time.NewTimer(drainGrace)
		select {
		case <-stdoutDone:
			select {
			case <-stderrDone:
			case <-graceTimer.C:
			}
		case <-graceTimer.C:
		}
		graceTimer.Stop()

		_ = stdoutR.Close()
		_ = stderrR.Close()

		<-stdinDone
		<-stdoutDone
		<-stderrDone

		_ = cmd.Wait()
		processMu.Lock()
		phase = phaseReaped
		processMu.Unlock()

		return 0, ErrGuestTransport
	}

	// Exit observed: close child stdin and known PipeReader
	_ = stdinW.Close()
	if pr, ok := stdin.(*io.PipeReader); ok {
		_ = pr.CloseWithError(io.EOF)
	}

	// Fixed drain grace period for stdout/stderr
	const drainGrace = 500 * time.Millisecond
	graceTimer := time.NewTimer(drainGrace)
	defer graceTimer.Stop()

	var drainTimedOut bool
	select {
	case <-stdoutDone:
		select {
		case <-stderrDone:
		case <-graceTimer.C:
			drainTimedOut = true
		}
	case <-graceTimer.C:
		drainTimedOut = true
	}

	if drainTimedOut {
		processMu.Lock()
		kErr := killGroupLocked()
		processMu.Unlock()
		_ = stdoutR.Close()
		_ = stderrR.Close()
		if kErr != nil {
			return transferOwnership(cleanupGroupRequired)
		}
	}

	// Join all workers before final reap
	<-stdinDone
	<-stdoutDone
	<-stderrDone

	// Before final reap: explicitly settle the original process group while the leader remains unreaped.
	// This removes any same-group descendants (even if they closed stdio).
	// Detached workers (in a separate setsid session) are outside this PGID and remain untouched.
	processMu.Lock()
	kErr := killGroupLocked()
	processMu.Unlock()
	if kErr != nil {
		return transferOwnership(cleanupGroupRequired)
	}

	// Reap child process exactly once with all kill-capable goroutines joined
	waitErr := cmd.Wait()
	processMu.Lock()
	phase = phaseReaped
	processMu.Unlock()

	// Return precedence
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if stdoutErr != nil {
		return 0, stdoutErr
	}
	if drainTimedOut {
		return 0, ErrGuestTransport
	}

	exitCode := 0
	if waitErr != nil {
		if exitError, ok := waitErr.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			return 0, ErrGuestTransport
		}
	}
	return exitCode, nil
}
