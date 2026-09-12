//go:build linux

package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/open-card/open-card/internal/desktopbridge"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--stdio-http" {
		if err := desktopbridge.ForwardStdioHTTP(context.Background(), os.Stdin, os.Stdout, net.DialTimeout); err != nil {
			log.Printf("guest bridge stdio-http unavailable: %v", err)
			os.Exit(23)
		}
		return
	}
	if len(os.Args) != 1 {
		log.Print("guest bridge: unsupported mode")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ports := []uint32{desktopbridge.GuestSSHPort, desktopbridge.GuestHTTPPort, desktopbridge.GuestHealthPort}
	var wg sync.WaitGroup
	errCh := make(chan error, len(ports))
	for _, port := range ports {
		listener, err := desktopbridge.ListenVsock(port)
		if err != nil {
			log.Printf("guest bridge unavailable on fixed port %d: %v", port, err)
			stop()
			break
		}
		wg.Add(1)
		go func(port uint32) {
			defer wg.Done()
			if err := desktopbridge.Serve(ctx, listener, port); err != nil {
				errCh <- err
				stop()
			}
		}(port)
	}
	<-ctx.Done()
	wg.Wait()
	select {
	case err := <-errCh:
		log.Printf("guest bridge stopped: %v", err)
	default:
	}
}
