// acornfox-build-network is the Native root-owned build policy executor.
// The Source adapter and rootless BuildKit worker never receive its network privileges.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/open-card/open-card/internal/buildnetwork"
)

func parseCommand(args []string) (string, error) {
	if len(args) != 1 || (args[0] != "serve" && args[0] != "cleanup") {
		return "", errors.New("expected serve or cleanup")
	}
	return args[0], nil
}

func run(ctx context.Context, args []string) error {
	command, err := parseCommand(args)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("host root is required")
	}
	manager, err := buildnetwork.NewNativeProductionManager()
	if err != nil {
		return err
	}
	defer manager.Close()
	if command == "cleanup" {
		return manager.Cleanup(ctx)
	}
	return manager.Serve(ctx)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		// Manager errors may describe host paths or command output. Keep the
		// service-facing message fixed; detailed diagnostics stay with the owner.
		fmt.Fprintln(os.Stderr, "acornfox-build-network: policy executor unavailable")
		os.Exit(1)
	}
}
