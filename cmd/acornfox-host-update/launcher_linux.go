//go:build linux

package main

import (
	"context"
	"os"
	"os/exec"
	"syscall"
)

func executeLauncherSubcommand(ctx context.Context, launcherFile *os.File, subcmd string) error {
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", subcmd)
	cmd.Args = []string{"acornfox-host-launcher", subcmd}
	cmd.ExtraFiles = []*os.File{launcherFile}
	cmd.Env = getLauncherEnvironment()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
