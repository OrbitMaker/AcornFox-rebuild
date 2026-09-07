package install

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-card/open-card/internal/acornfoxsetup"
)

func TestAcornFoxRuntimeConfigIncludesRequiredHTTPSConfiguration(t *testing.T) {
	s, prepared, id := runtimeConfigFixture(t)
	if receipt, err := runtimeRun(s, id); err != nil || receipt.Validate() != nil {
		t.Fatalf("HTTPS configuration was not published: %v", err)
	}
	if _, err := runtimeScopeForTest(t, prepared); err != nil {
		t.Fatal("complete HTTPS configuration rejected", err)
	}
	edge := filepath.Join(prepared.host, acornfoxsetup.EdgeConfiguration)
	if info, err := os.Stat(edge); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0644 {
		t.Fatal("required HTTPS configuration is absent or has wrong permissions")
	}
	if err := os.Remove(edge); err != nil {
		t.Fatal(err)
	}
	if _, err := runtimeScopeForTest(t, prepared); err == nil {
		t.Fatal("missing HTTPS configuration was accepted as a complete installation")
	}
}

func TestAcornFoxRuntimeConfigPublishesManagedSetupCredential(t *testing.T) {
	s, prepared, id := runtimeConfigFixture(t)
	if _, err := runtimeRun(s, id); err != nil {
		t.Fatal(err)
	}
	intent, _ := runtimeIntentForTest(t, prepared)
	path := filepath.Join(prepared.host, acornFoxSetupCredentialPath)
	if raw, err := os.ReadFile(path); err != nil || string(raw) != string(intent.SetupToken) {
		t.Fatal("setup credential bytes are not the persisted intent")
	}
	if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("setup credential permissions are unsafe")
	}
	if err := prepareAcornFoxRepository(context.Background(), prepared.store, prepared.published, prepared.binding); err != nil {
		t.Fatalf("managed setup credential rejected: %v", err)
	}
	if err := os.WriteFile(path, []byte("tampered\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := prepareAcornFoxRepository(context.Background(), prepared.store, prepared.published, prepared.binding); err == nil {
		t.Fatal("tampered setup credential accepted")
	}
}
