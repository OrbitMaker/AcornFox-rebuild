package install

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// This integration path intentionally observes only repository task-root
// bytes. It does not invoke a runtime, volume, host, network, or data mutator.
func TestAcornFox04CRepositoryPreparationLeavesExternalSentinelUntouched(t *testing.T) {
	root, store, published, receipt := acornFoxRepoBootstrapFixture(t)
	sentinel := filepath.Join(t.TempDir(), "external-sentinel")
	if err := os.WriteFile(sentinel, []byte("outside-task-root"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	beforeRaw, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareAcornFoxRepository(context.Background(), store, published, receipt.CandidateReceipt.BindingSHA256); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	afterRaw, err := os.ReadFile(sentinel)
	if err != nil || string(beforeRaw) != string(afterRaw) || !os.SameFile(before, after) {
		t.Fatalf("sentinel changed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, acornFoxLiveDir, "opt", "acornfox", "current")); err != nil {
		t.Fatal(err)
	}
}
