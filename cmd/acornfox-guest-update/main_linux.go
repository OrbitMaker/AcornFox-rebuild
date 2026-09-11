//go:build linux

package main

import (
	"context"
	"os"

	"github.com/open-card/open-card/internal/desktopupdateguest"
)

func main() {
	os.Exit(desktopupdateguest.RunCommand(context.Background(), os.Args[1:], os.Stdin, os.Stdout))
}
