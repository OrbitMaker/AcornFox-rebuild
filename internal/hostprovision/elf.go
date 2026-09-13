package hostprovision

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"fmt"
)

// verifyExecutableBinary verifies that raw contains a valid executable for the target OS and architecture.
// In production Linux, it strictly verifies 64-bit ELF executables.
// In test environments on macOS, it verifies 64-bit Mach-O executables.
func verifyExecutableBinary(raw []byte, targetOS, targetArch string) error {
	switch targetOS {
	case "linux":
		return verifyELF(raw, targetArch)
	case "darwin":
		return verifyMachO(raw, targetArch)
	default:
		return fmt.Errorf("%w: unsupported target OS %q", ErrInvalidRequest, targetOS)
	}
}

// verifyELF validates that raw contains a valid 64-bit little-endian ELF executable or PIE
// with non-zero entry point and machine architecture matching expectedArch.
func verifyELF(raw []byte, expectedArch string) error {
	f, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("%w: invalid ELF format: %v", ErrInvalidRequest, err)
	}
	defer f.Close()

	if f.Class != elf.ELFCLASS64 {
		return fmt.Errorf("%w: ELF class must be 64-bit", ErrInvalidRequest)
	}
	if f.Data != elf.ELFDATA2LSB {
		return fmt.Errorf("%w: ELF data encoding must be little-endian (LSB)", ErrInvalidRequest)
	}
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return fmt.Errorf("%w: ELF type must be ET_EXEC or ET_DYN", ErrInvalidRequest)
	}
	if f.Entry == 0 {
		return fmt.Errorf("%w: ELF entry point cannot be zero", ErrInvalidRequest)
	}

	switch expectedArch {
	case "amd64":
		if f.Machine != elf.EM_X86_64 {
			return fmt.Errorf("%w: ELF machine mismatch: expected amd64 (EM_X86_64), got %v", ErrInvalidRequest, f.Machine)
		}
	case "arm64":
		if f.Machine != elf.EM_AARCH64 {
			return fmt.Errorf("%w: ELF machine mismatch: expected arm64 (EM_AARCH64), got %v", ErrInvalidRequest, f.Machine)
		}
	default:
		return fmt.Errorf("%w: unsupported target architecture %q", ErrInvalidRequest, expectedArch)
	}

	return nil
}

// verifyMachO validates 64-bit Mach-O executables for macOS test environments.
func verifyMachO(raw []byte, expectedArch string) error {
	f, err := macho.NewFile(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("%w: invalid Mach-O format: %v", ErrInvalidRequest, err)
	}
	defer f.Close()

	if f.Magic != macho.Magic64 || f.Type != macho.TypeExec {
		return fmt.Errorf("%w: Mach-O must be 64-bit executable", ErrInvalidRequest)
	}

	switch expectedArch {
	case "amd64":
		if f.Cpu != macho.CpuAmd64 {
			return fmt.Errorf("%w: Mach-O cpu mismatch: expected amd64", ErrInvalidRequest)
		}
	case "arm64":
		if f.Cpu != macho.CpuArm64 {
			return fmt.Errorf("%w: Mach-O cpu mismatch: expected arm64", ErrInvalidRequest)
		}
	default:
		return fmt.Errorf("%w: unsupported target architecture %q", ErrInvalidRequest, expectedArch)
	}

	return nil
}
