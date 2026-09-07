package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRefusesRootBeforeReadingConfiguration(t *testing.T) {
	err := run(context.Background(), []string{"--config", "/untrusted/file"}, io.Discard, func() int { return 0 }, func(string) string { return "/run/credentials/test" })
	if err == nil || err.Error() != "refusing to run as root" {
		t.Fatalf("run() error = %v", err)
	}
}

func TestParseConfigArgumentRequiresSystemdCredentialPath(t *testing.T) {
	directory := systemCredentialDirectory
	want := filepath.Join(directory, configCredentialName)
	got, err := parseConfigArgument([]string{"--config", want}, directory)
	if err != nil || got != want {
		t.Fatalf("parseConfigArgument() = %q, %v", got, err)
	}
	for _, args := range [][]string{
		{}, {"--config", "/tmp/pi-config"}, {"--config", want, "extra"}, {"--other", want},
	} {
		_, err := parseConfigArgument(args, directory)
		if err == nil {
			t.Fatalf("parseConfigArgument(%q) unexpectedly succeeded", args)
		}
		if strings.Contains(err.Error(), "/tmp/pi-config") {
			t.Fatalf("error exposed rejected path: %v", err)
		}
	}
}

func TestConfigCredentialMustBeReadOnlyRegularFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, configCredentialName)
	if err := os.WriteFile(path, []byte("{}"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := validateConfigCredential(path, os.Lstat); err != nil {
		t.Fatalf("read-only credential error = %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateConfigCredential(path, os.Lstat); err == nil {
		t.Fatal("writable config credential was accepted")
	}
}

func TestRunRequiresCredentialDirectoryForNonRoot(t *testing.T) {
	err := run(context.Background(), nil, io.Discard, func() int { return 1001 }, func(string) string { return "" })
	if err == nil || err.Error() != "systemd credential directory is unavailable" {
		t.Fatalf("run() error = %v", err)
	}
}
