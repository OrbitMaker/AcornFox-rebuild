package install

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
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
	image, err := domain.ParseImageDigest("example/acornfox", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := runtime.Deploy(context.Background(), contracts.DeployRequest{DeploymentID: domain.ID("dep_04c_seed"), Spec: contracts.RuntimeSpec{ApplicationID: domain.ID("app_04c"), EnvironmentID: domain.ID("env_04c"), ReleaseID: domain.ID("release_04c"), ServiceName: "web", Image: image, Port: 8080}, Operation: contracts.OperationContext{IdempotencyKey: "runtime-seed"}})
	if err != nil {
		t.Fatal(err)
	}
	observe := func() contracts.RuntimeObservation {
		got, err := runtime.Observe(context.Background(), contracts.ObserveRequest{DeploymentID: deployment.ID, Operation: contracts.OperationContext{IdempotencyKey: "runtime-observe"}})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	beforeObservation := observe()
	volumeSpec := contracts.VolumeSpec{Name: "retained-data", MountPath: "/var/lib/app", SizeBytes: 1024}
	if _, _, err = volume.Create(context.Background(), contracts.VolumeRequest{Volume: volumeSpec, Operation: contracts.OperationContext{IdempotencyKey: "volume-create"}}); err != nil {
		t.Fatal(err)
	}
	if err = volume.Attach(context.Background(), contracts.VolumeRequest{Volume: volumeSpec, Operation: contracts.OperationContext{IdempotencyKey: "volume-attach"}}); err != nil {
		t.Fatal(err)
	}
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
	beforeObservationRaw, marshalErr := json.Marshal(beforeObservation)
	afterObservationRaw, afterMarshalErr := json.Marshal(observe())
	if marshalErr != nil || afterMarshalErr != nil || string(beforeObservationRaw) != string(afterObservationRaw) {
		t.Fatalf("runtime observation changed: %v %v", marshalErr, afterMarshalErr)
	}
}
