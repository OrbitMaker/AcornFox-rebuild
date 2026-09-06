package install

import (
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
