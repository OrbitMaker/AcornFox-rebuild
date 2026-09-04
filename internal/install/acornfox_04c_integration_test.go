package install

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-card/open-card/internal/contracts"
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

// Repository preparation receives no provider capability. These pre-existing
// fake observations model retained runtime/volume facts and a network ledger;
// their canonical snapshots prove that this repository-only engine made no
// provider call observable through its input surface.
func TestAcornFox04CRepositoryOnlyLeavesProviderFactsAndDataSentinelUntouched(t *testing.T) {
	runtime := contracts.NewFakeRuntimeDriver(true)
	volume := contracts.NewFakeVolumeProvider(true)
	ledger := struct {
		Runtime contracts.ProviderMetadata `json:"runtime"`
		Volume  contracts.ProviderMetadata `json:"volume"`
		Network []string                   `json:"network_ledger"`
	}{runtime.Metadata(context.Background()), volume.Metadata(context.Background()), []string{"retained-volume:application-data", "network:existing-app-net"}}
	beforeFacts, err := json.Marshal(ledger)
	if err != nil {
		t.Fatal(err)
	}
	root, store, published, receipt := acornFoxRepoBootstrapFixture(t)
	sentinel := filepath.Join(t.TempDir(), "application-data")
	if err = os.WriteFile(sentinel, []byte("retained application data"), 0o600); err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	beforeRaw, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	old := acornFoxRepoBootstrapFaultStep
	acornFoxRepoBootstrapFaultStep = func(step string) error {
		if step == "journal-active" {
			return errors.New("fault")
		}
		return nil
	}
	err = prepareAcornFoxRepository(context.Background(), store, published, receipt.CandidateReceipt.BindingSHA256)
	acornFoxRepoBootstrapFaultStep = old
	if !errors.Is(err, ErrAcornFoxRepoBootstrapConflict) {
		t.Fatalf("fault=%v", err)
	}
	fresh, err := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err = prepareAcornFoxRepository(context.Background(), fresh, published, receipt.CandidateReceipt.BindingSHA256); err != nil {
		t.Fatalf("recovery=%v", err)
	}
	afterFacts, err := json.Marshal(ledger)
	if err != nil || string(beforeFacts) != string(afterFacts) {
		t.Fatalf("provider facts changed: %v", err)
	}
	afterInfo, err := os.Stat(sentinel)
	afterRaw, readErr := os.ReadFile(sentinel)
	if err != nil || readErr != nil || !os.SameFile(beforeInfo, afterInfo) || string(beforeRaw) != string(afterRaw) {
		t.Fatalf("application-data sentinel changed: %v %v", err, readErr)
	}
}
