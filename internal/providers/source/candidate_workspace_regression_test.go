package source

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/open-card/open-card/internal/acornfoxcandidate"
)

func TestLegacyCandidateNamespaceIsRetiredBeforeSourcePoolAdmission(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, ".acornfox-candidates")
	if err := os.Mkdir(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := measureWorkspacePool(root); err == nil {
		t.Fatal("source pool admitted the obsolete candidate namespace")
	}
	if err := acornfoxcandidate.RetireLegacyWorkspace(root); err != nil {
		t.Fatal(err)
	}
	if usage, err := measureWorkspacePool(root); err != nil || usage != (workspaceUsage{}) {
		t.Fatalf("usage=%+v err=%v", usage, err)
	}
}
