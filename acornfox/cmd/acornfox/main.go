// Command acornfox is the AcornFox client and server binary. Client commands
// (deploy, status, env, ...) run in the internal/cli package; server-side
// subcommands (server, runner, proxy) are handled here in package main.
package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/acornfox/acornfox/internal/cli"
	"github.com/acornfox/acornfox/internal/client"
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

// run dispatches the server-side subcommands to their handlers and everything
// else to the CLI command layer.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "server":
			return runServer(args[1:], stdout, stderr)
		case "runner":
			return runRunner(args[1:]...)
		case "proxy":
			return runProxy(args[1:], stdin, stdout, stderr)
		}
	}
	// The default connector wraps client.Connect so internal/cli stays
	// decoupled from the transport implementation.
	connect := func(ctx context.Context, t client.Target) (client.API, error) {
		return client.Connect(ctx, t)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return cli.MainWithConnector(ctx, args, stdin, stdout, stderr, os.Getenv, connect, "", mustGetwd())
}

func mustGetwd() string {
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}
