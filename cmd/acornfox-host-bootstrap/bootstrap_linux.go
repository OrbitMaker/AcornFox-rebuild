//go:build linux

package main

import (
	"os"
	"os/exec"
	"syscall"
)

const defaultChildExecPath = "/proc/self/fd/3"

func createLifecycleSocketpair() (parent *os.File, child *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	parent = os.NewFile(uintptr(fds[0]), "parent-lifecycle")
	child = os.NewFile(uintptr(fds[1]), "child-lifecycle")
	return parent, child, nil
}

func prepareChildCommand(controllerFD *os.File, childSock *os.File) *exec.Cmd {
	cmd := exec.Command(defaultChildExecPath, "managed-child")
	cmd.Args = []string{"acornfox-host-update", "managed-child"}
	cmd.ExtraFiles = []*os.File{controllerFD, childSock}
	cmd.Env = getChildEnvironment()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
	}
	return cmd
}

func killProcessGroup(pid int) error {
	if pid <= 0 {
		return nil
	}
	return syscall.Kill(-pid, syscall.SIGKILL)
}
