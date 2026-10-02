//go:build windows

package main

import (
	"fmt"
	"io"
	"os"
)

// The server, runner and proxy subcommands run only on the Linux server.
// Windows builds are CLI-only.

const serverOnly = "acornfox: 该命令只在服务器（Linux）上运行；本机请使用 deploy、status 等命令"

func runServer(_ []string, _ io.Writer, stderr io.Writer) int {
	fmt.Fprintln(stderr, serverOnly)
	return 2
}

func runRunner(_ ...string) int {
	fmt.Fprintln(os.Stderr, serverOnly)
	return 2
}

func runProxy(_ []string, _ io.Reader, _ io.Writer, stderr io.Writer) int {
	fmt.Fprintln(stderr, serverOnly)
	return 2
}

func runInit(_ []string, _ io.Writer, stderr io.Writer) int {
	fmt.Fprintln(stderr, serverOnly)
	return 2
}

func runMigrate(_ []string, _ io.Writer, stderr io.Writer) int {
	fmt.Fprintln(stderr, serverOnly)
	return 2
}

func runAdminToken(_ []string, _ io.Writer, stderr io.Writer) int {
	fmt.Fprintln(stderr, serverOnly)
	return 2
}
