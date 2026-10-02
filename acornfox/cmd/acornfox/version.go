package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/acornfox/acornfox/internal/cli"
)

// runVersion implements `acornfox version`: print version information. The
// version string is cli.Version, set at build time via
// -ldflags "-X github.com/acornfox/acornfox/internal/cli.Version=x.y.z".
// `acornfox --json version` is handled by internal/cli instead.
func runVersion(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fmt.Fprintf(stdout, "acornfox %s\n", cli.Version)
	return 0
}
