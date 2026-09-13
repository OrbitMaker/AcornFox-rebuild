//go:build !linux

package main

import (
	"os"
	"os/exec"
	"syscall"
)

func createLifecycleSocketpair() (parent *os.File, child *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}
	syscall.CloseOnExec(fds[0])
	syscall.CloseOnExec(fds[1])
	parent = os.NewFile(uintptr(fds[0]), "parent-lifecycle")
	child = os.NewFile(uintptr(fds[1]), "child-lifecycle")
	return parent, child, nil
}

func prepareChildCommand(controllerFD *os.File, childSock *os.File) *exec.Cmd {
	// On non-Linux (e.g. macOS dev test), use /dev/fd/3 if present or the file name
	path := controllerFD.Name()
	cmd := exec.Command(path, "managed-child")
	cmd.Args = []string{"acornfox-host-update", "managed-child"}
	cmd.ExtraFiles = []*os.File{controllerFD, childSock}
	cmd.Env = getChildEnvironment()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	return cmd
}

func killProcessGroup(pid int) error {
	if pid <= 0 {
		return nil
	}
	return syscall.Kill(-pid, syscall.SIGKILL)
}
