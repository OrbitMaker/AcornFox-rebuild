package corehttp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupRuntimeCredentialRejectsUnsafeFiles(t *testing.T) {
	temp := t.TempDir()
	if err := os.Chmod(temp, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(temp, "cred")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "acornfox-setup-token")
	value := strings.Repeat("A", 43) + "\n"
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	if got := AcornFoxSetupCredential(directory); string(got) != value {
		t.Fatal("protected credential was not loaded")
	}
	if err := os.Chmod(path, 0440); err != nil {
		t.Fatal(err)
	}
	if got := AcornFoxSetupCredential(directory); string(got) != value {
		t.Fatal("systemd group-read credential was rejected")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if got := AcornFoxSetupCredential(directory); got != nil {
		t.Fatal("public credential was loaded")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}

	// Test unsafe directory permissions
	if err := os.Chmod(directory, 0777); err != nil {
		t.Fatal(err)
	}
	if got := AcornFoxSetupCredential(directory); got != nil {
		t.Fatal("credential in world-writable directory was loaded")
	}
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if got := AcornFoxSetupCredential(directory); got != nil {
		t.Fatal("credential in world-readable directory was loaded")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	outTemp := t.TempDir()
	if err := os.Chmod(outTemp, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(outTemp, "outside")
	if err := os.WriteFile(outside, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if got := AcornFoxSetupCredential(directory); got != nil {
		t.Fatal("symlink credential was loaded")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value+"extra"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := AcornFoxSetupCredential(directory); got != nil {
		t.Fatal("oversized credential was loaded")
	}

	symTemp := t.TempDir()
	if err := os.Chmod(symTemp, 0700); err != nil {
		t.Fatal(err)
	}
	symlinkDir := filepath.Join(symTemp, "symlink_dir")
	if err := os.Symlink(directory, symlinkDir); err != nil {
		t.Fatal(err)
	}
	if got := AcornFoxSetupCredential(symlinkDir); got != nil {
		t.Fatal("symlink directory accepted")
	}

	for _, invalid := range []string{"", ".", directory + "/..", filepath.Join(directory, "missing")} {
		if got := AcornFoxSetupCredential(invalid); got != nil {
			t.Fatal("invalid credential directory accepted")
		}
	}
}
