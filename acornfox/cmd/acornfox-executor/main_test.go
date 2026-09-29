package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestParseFlagsDefaultsAndValidation(t *testing.T) {
	cfg, err := parseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.dockerSocket != "/var/run/docker.sock" || len(cfg.gitResolvers) != 2 || cfg.caddyAccount != "caddy" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	for _, args := range [][]string{
		{"-docker-socket", "relative.sock"},
		{"-docker-socket", "/run/../docker.sock"},
		{"-git-resolvers", " , "},
		{"-retry-interval", "0s"},
		{"extra"},
	} {
		if _, err := parseFlags(args); err == nil {
			t.Fatalf("accepted invalid flags %v", args)
		}
	}
}

func TestKeepStartingRetriesThenHoldsUntilShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts, stopped := 0, make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		keepStarting(ctx, "test", 10*time.Millisecond, func() (func(), error) {
			attempts++
			if attempts < 3 {
				return nil, errors.New("dependency missing")
			}
			return func() { close(stopped) }, nil
		})
	}()
	time.Sleep(100 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("subsystem returned before shutdown")
	default:
	}
	cancel()
	<-done
	select {
	case <-stopped:
	default:
		t.Fatal("started subsystem was not stopped on shutdown")
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}
