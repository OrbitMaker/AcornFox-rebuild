//go:build darwin || linux

package source

import (
	"os/exec"
	"syscall"
)

// startGitProcessGroup prevents a timed-out git parent from leaving a
// git-remote-https helper alive with access to the transient object directory.
func startGitProcessGroup(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func stopGitProcessGroup(command *exec.Cmd) {
	if command != nil && command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
}
