//go:build !linux

package main

import (
	"context"
	"os"
	"os/exec"
	"syscall"
)

func executeLauncherSubcommand(ctx context.Context, launcherFile *os.File, subcmd string) error {
	path := launcherFile.Name()
	cmd := exec.CommandContext(ctx, path, subcmd)
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
