package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalConfigCommandSuccess(t *testing.T) {
	parent := t.TempDir()
	outDir := filepath.Join(parent, "fresh-local-config")

	var stdout, stderr bytes.Buffer
	code := run([]string{"--output-dir", outDir, "--version", "v1.2.3", "--now", "2026-09-12T10:00:00Z"}, &stdout, &stderr, rand.Reader)
	if code != 0 {
		t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr.String())
	}

	// Verify stdout contains valid JSON receipt
	var receipt LocalConfigReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatalf("failed to parse receipt JSON: %v, raw: %s", err, stdout.String())
	}
	if receipt.Origin != "http://127.0.0.1:8080" {
		t.Errorf("expected origin http://127.0.0.1:8080, got %s", receipt.Origin)
	}
	if receipt.Version != "v1.2.3" {
		t.Errorf("expected version v1.2.3, got %s", receipt.Version)
	}
	if len(receipt.Files) != 7 {
		t.Fatalf("expected 7 files in receipt, got %d", len(receipt.Files))
	}

	// Verify stdout does NOT contain private keys or PEM headers
	stdoutStr := stdout.String()
	if strings.Contains(stdoutStr, "BEGIN PRIVATE KEY") || strings.Contains(stdoutStr, "BEGIN CERTIFICATE") {
		t.Errorf("stdout must not leak PEM data or keys: %s", stdoutStr)
	}

	// Check files on disk
	dirInfo, err := os.Stat(outDir)
	if err != nil {
		t.Fatalf("failed to stat outDir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0700 {
		t.Errorf("expected dir mode 0700, got %o", dirInfo.Mode().Perm())
	}

	for _, fileSummary := range receipt.Files {
		filePath := filepath.Join(outDir, fileSummary.RelativePath)
		info, err := os.Stat(filePath)
		if err != nil {
			t.Fatalf("failed to stat generated file %s: %v", filePath, err)
		}
		if fileSummary.IntendedOwner != "root" || fileSummary.IntendedGroup != "root" {
			t.Errorf("file %s unexpected intended owner: %s:%s", fileSummary.RelativePath, fileSummary.IntendedOwner, fileSummary.IntendedGroup)
		}
		if strings.HasSuffix(fileSummary.RelativePath, ".key") {
			if info.Mode().Perm() != 0600 {
				t.Errorf("key file %s expected 0600, got %o", fileSummary.RelativePath, info.Mode().Perm())
			}
		} else {
			if info.Mode().Perm() != 0644 {
				t.Errorf("non-key file %s expected 0644, got %o", fileSummary.RelativePath, info.Mode().Perm())
			}
		}
	}
}

func TestLocalConfigCommandRejectsExistingDirectory(t *testing.T) {
	parent := t.TempDir()
	existingDir := filepath.Join(parent, "already-exists")
	if err := os.Mkdir(existingDir, 0700); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"--output-dir", existingDir}, &stdout, &stderr, rand.Reader)
	if code == 0 {
		t.Fatalf("expected nonzero exit code when target dir already exists, got 0")
	}
	if !strings.Contains(stderr.String(), "error:") {
		t.Errorf("expected error in stderr, got: %s", stderr.String())
	}
}

func TestLocalConfigCommandRejectsExistingFileOrSymlink(t *testing.T) {
	parent := t.TempDir()

	// 1. Existing regular file
	fileTarget := filepath.Join(parent, "a-regular-file")
	if err := os.WriteFile(fileTarget, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"--output-dir", fileTarget}, &stdout, &stderr, rand.Reader)
	if code == 0 {
		t.Fatalf("expected nonzero code for existing file, got 0")
	}

	// 2. Existing symlink to a directory
	otherDir := filepath.Join(parent, "other-dir")
	if err := os.Mkdir(otherDir, 0700); err != nil {
		t.Fatal(err)
	}
	symlinkTarget := filepath.Join(parent, "symlink-dir")
	if err := os.Symlink(otherDir, symlinkTarget); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"--output-dir", symlinkTarget}, &stdout, &stderr, rand.Reader)
	if code == 0 {
		t.Fatalf("expected nonzero code for existing symlink, got 0")
	}
}

func TestLocalConfigCommandRejectsMissingParentDirectory(t *testing.T) {
	parent := t.TempDir()
	nonExistentParent := filepath.Join(parent, "does", "not", "exist")
	target := filepath.Join(nonExistentParent, "config")

	var stdout, stderr bytes.Buffer
	code := run([]string{"--output-dir", target}, &stdout, &stderr, rand.Reader)
	if code == 0 {
		t.Fatalf("expected nonzero code when parent directory does not exist, got 0")
	}
}

func TestLocalConfigCommandRejectsInvalidArgsAndExtraPositional(t *testing.T) {
	parent := t.TempDir()
	outDir := filepath.Join(parent, "config")

	// Missing --output-dir
	var stdout, stderr bytes.Buffer
	code := run([]string{}, &stdout, &stderr, rand.Reader)
	if code != 2 {
		t.Errorf("expected code 2 for missing --output-dir, got %d", code)
	}

	// Extra positional arguments
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"--output-dir", outDir, "extra-arg"}, &stdout, &stderr, rand.Reader)
	if code != 2 {
		t.Errorf("expected code 2 for extra positional args, got %d", code)
	}

	// Invalid flag
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"--unknown-flag"}, &stdout, &stderr, rand.Reader)
	if code != 2 {
		t.Errorf("expected code 2 for invalid flag, got %d", code)
	}

	// Invalid --now format
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"--output-dir", outDir, "--now", "invalid-date"}, &stdout, &stderr, rand.Reader)
	if code != 2 {
		t.Errorf("expected code 2 for invalid --now, got %d", code)
	}
}

func TestLocalConfigCommandFailureDoesNotWriteFiles(t *testing.T) {
	parent := t.TempDir()
	outDir := filepath.Join(parent, "failure-target")

	// Pass an invalid resolver that causes GenerateLocal to fail
	var stdout, stderr bytes.Buffer
	code := run([]string{"--output-dir", outDir, "--resolvers", "127.0.0.1:53"}, &stdout, &stderr, rand.Reader)
	if code == 0 {
		t.Fatalf("expected nonzero code for invalid resolver, got 0")
	}

	// Ensure outDir was never created or left behind
	if _, err := os.Stat(outDir); !os.IsNotExist(err) {
		t.Fatalf("target directory %s should not exist after generation failure, err: %v", outDir, err)
	}
}
