package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIPositionalArgumentsRejected(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "acornfox-host-provision")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v: %s", err, out)
	}

	cmd := exec.Command(binPath,
		"-bootstrap-version", "1.0.0",
		"-binding-sha", strings.Repeat("a", 64),
		"-bootstrap-source", "/tmp/boot",
		"-bootstrap-sha", strings.Repeat("b", 64),
		"-c0-source", "/tmp/c0",
		"-c0-sha", strings.Repeat("c", 64),
		"-policy-source", "/tmp/pol",
		"-policy-sha", strings.Repeat("d", 64),
		"unexpected-positional-arg",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure on unexpected positional arg, got exit code 0: %s", out)
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 2 {
			t.Fatalf("expected exit code 2, got %d: %s", exitErr.ExitCode(), out)
		}
	} else {
		t.Fatalf("expected ExitError, got %v: %s", err, out)
	}
	if !strings.Contains(string(out), "unexpected positional argument") {
		t.Errorf("expected error message to mention unexpected positional argument: %s", out)
	}
}

func TestCLIMissingRequiredArguments(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "acornfox-host-provision")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v: %s", err, out)
	}

	cmd := exec.Command(binPath)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure on missing flags, got exit code 0")
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 2 {
			t.Fatalf("expected exit code 2, got %d: %s", exitErr.ExitCode(), out)
		}
	}
}
