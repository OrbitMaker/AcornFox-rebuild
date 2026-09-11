package acornfoxrelease

import (
	"context"
	"debug/elf"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectOneBinaryRejectsWrongArchitecture(t *testing.T) {
	root, cacheRoot, witness, policy, toolchain := syntheticGoReleaseRepository(t)
	plan, err := PrepareGoBuildPlanV1(context.Background(), witness, policy, toolchain, root, cacheRoot, localNPMCLIPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()

	taskRoot := buildTaskRoot(t)
	stage, err := BuildGoBinariesV1(context.Background(), plan, taskRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()

	upgrade := plan.Targets()[8]
	upgradePath := filepath.Join(stage.root, filepath.FromSlash(upgrade.Output))

	// Read built binary
	raw, err := os.ReadFile(upgradePath)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Verify that the successfully built binary matches current Architecture
	if _, err := inspectOneBinary(upgradePath, upgrade, plan); err != nil {
		t.Fatalf("legitimate binary rejected: %v", err)
	}

	// 2. Tamper ELF Machine header to the wrong architecture
	// e_machine is at offset 18 (2 bytes, little endian)
	tampered := filepath.Join(taskRoot, "tampered-arch-binary")
	tamperedBytes := append([]byte(nil), raw...)
	if Architecture == "amd64" {
		// Replace EM_X86_64 (62 / 0x003e) with EM_AARCH64 (183 / 0x00b7)
		tamperedBytes[18] = 0xb7
		tamperedBytes[19] = 0x00
	} else {
		// Replace EM_AARCH64 (183 / 0x00b7) with EM_X86_64 (62 / 0x003e)
		tamperedBytes[18] = 0x3e
		tamperedBytes[19] = 0x00
	}

	if err := os.WriteFile(tampered, tamperedBytes, 0o755); err != nil {
		t.Fatal(err)
	}

	// Inspect tampered machine binary: must be rejected with ErrGoStage
	if _, err := inspectOneBinary(tampered, upgrade, plan); err == nil {
		t.Fatal("binary with mismatched ELF machine was accepted")
	}

	// Double check with debug/elf that tamperedBytes has the mismatched machine
	f, err := elf.Open(tampered)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if Architecture == "amd64" && f.Machine != elf.EM_AARCH64 {
		t.Fatalf("expected tampered machine EM_AARCH64, got %v", f.Machine)
	} else if Architecture == "arm64" && f.Machine != elf.EM_X86_64 {
		t.Fatalf("expected tampered machine EM_X86_64, got %v", f.Machine)
	}
}

func TestDecisionV1RejectsWrongArchitecture(t *testing.T) {
	d := decisionFixture()
	if Architecture == "amd64" {
		d.Architecture = "arm64"
	} else {
		d.Architecture = "amd64"
	}
	if _, err := CanonicalDecisionV1(d); err == nil {
		t.Fatal("decision with mismatched architecture was accepted")
	}
}
