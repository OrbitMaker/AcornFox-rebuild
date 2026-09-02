package secret

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDeriveExistingContextKeyIsStableSeparatedAndDoesNotCreateMasterKey(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "master.key")
	if err := os.WriteFile(keyPath, []byte("01234567890123456789012345678901"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := DeriveExistingContextKey(keyPath, "acornfox-discovery-cursor-v1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := DeriveExistingContextKey(keyPath, "acornfox-discovery-cursor-v1")
	if err != nil || first != second {
		t.Fatalf("same label stable=%v err=%v", first == second, err)
	}
	different, err := DeriveExistingContextKey(keyPath, "another-domain")
	if err != nil || first == different {
		t.Fatalf("domain separation stable=%v err=%v", first == different, err)
	}
	missing := filepath.Join(directory, "missing.key")
	if _, err := DeriveExistingContextKey(missing, "acornfox-discovery-cursor-v1"); err == nil {
		t.Fatal("missing existing key was accepted")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("derivation created master key err=%v", err)
	}
	ZeroContextKey(&first)
	if first != [32]byte{} {
		t.Fatal("derived key was not cleared")
	}
}
