//go:build fixture

package main

import (
	"context"
	"runtime"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/desktopupdate"
)

func TestFixtureTransportMissingBackendStateFailsClosed(t *testing.T) {
	tmpDir := t.TempDir()
	tr := getFixtureGuestTransport(tmpDir)

	backend, err := desktopupdate.NewGuestBackend(desktopupdate.GuestBackendOptions{
		InstanceID:   strings.Repeat("a", 64),
		Architecture: runtime.GOARCH,
		Transport:    tr,
	})
	if err != nil {
		t.Fatalf("failed to construct guest backend: %v", err)
	}

	// backend-state.json does not exist in tmpDir; observe must fail closed without fallback
	_, err = backend.Observe(context.Background(), "")
	if err == nil {
		t.Fatal("expected Observe to fail when backend-state.json is missing in fixture mode")
	}
}
