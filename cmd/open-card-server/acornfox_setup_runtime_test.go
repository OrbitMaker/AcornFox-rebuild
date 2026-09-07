package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupRuntimeCredentialRejectsUnsafeFiles(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "acornfox-setup-token")
	value := strings.Repeat("A", 43) + "\n"
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	if got := acornFoxSetupCredential(directory); string(got) != value {
		t.Fatal("protected credential was not loaded")
	}
	if err := os.Chmod(path, 0440); err != nil {
		t.Fatal(err)
	}
	if got := acornFoxSetupCredential(directory); string(got) != value {
		t.Fatal("systemd group-read credential was rejected")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if got := acornFoxSetupCredential(directory); got != nil {
		t.Fatal("public credential was loaded")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if got := acornFoxSetupCredential(directory); got != nil {
		t.Fatal("symlink credential was loaded")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value+"extra"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := acornFoxSetupCredential(directory); got != nil {
		t.Fatal("oversized credential was loaded")
	}
	for _, invalid := range []string{"", ".", directory + "/..", filepath.Join(directory, "missing")} {
		if got := acornFoxSetupCredential(invalid); got != nil {
			t.Fatal("invalid credential directory accepted")
		}
	}
}
