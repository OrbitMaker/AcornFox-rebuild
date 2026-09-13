package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/open-card/open-card/internal/hostlifecycle"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: acornfox-host-bootstrap <start|status|check|advance|resume-backend|dismiss>\n")
		os.Exit(2)
	}

	verb := os.Args[1]
	if !hostlifecycle.IsValidOperation(verb) {
		fmt.Fprintf(os.Stderr, "acornfox-host-bootstrap: invalid verb %q\n", verb)
		os.Exit(2)
	}

	opts := getProductionBootstrapOptions()
	if !opts.AllowNonRoot && os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "acornfox-host-bootstrap: root privileges required\n")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	result, err := RunBootstrap(ctx, verb, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "acornfox-host-bootstrap: error: %v\n", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "acornfox-host-bootstrap: failed to encode output: %v\n", err)
		os.Exit(1)
	}
}
