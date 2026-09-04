package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
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

// Repository preparation receives no provider capability. The recording
// wrappers call the real contract fakes while seeding retained state, then
// prove that preparation and clean-journal recovery make no mutating provider
// call. Their state is deliberately test-local: production has no provider
// seam here.
func TestAcornFox04CRepositoryOnlyLeavesProviderFactsAndDataSentinelUntouched(t *testing.T) {
	for _, tc := range []struct{ name, fault string }{
		{"success", ""},
		{"activation-recovery", "journal-active"},
		{"current-recovery", "journal-current"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acornFox04CRepositoryProviderIsolationCase(t, tc.fault)
		})
	}
}

func acornFox04CRepositoryProviderIsolationCase(t *testing.T, fault string) {
	t.Helper()
	runtime := &acornFox04CRuntimeRecorder{driver: contracts.NewFakeRuntimeDriver(true)}
	volume := &acornFox04CVolumeRecorder{provider: contracts.NewFakeVolumeProvider(true)}
	image, err := domain.ParseImageDigest("example/acornfox", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := runtime.Deploy(context.Background(), contracts.DeployRequest{DeploymentID: domain.ID("dep_04c_seed"), Spec: contracts.RuntimeSpec{ApplicationID: domain.ID("app_04c"), EnvironmentID: domain.ID("env_04c"), ReleaseID: domain.ID("release_04c"), ServiceName: "web", Image: image, Port: 8080}, Operation: contracts.OperationContext{IdempotencyKey: "runtime-seed"}})
	if err != nil {
		t.Fatal(err)
	}
	volumeSpec := contracts.VolumeSpec{Name: "retained-data", MountPath: "/var/lib/app", SizeBytes: 1024}
	if _, _, err = volume.Create(context.Background(), contracts.VolumeRequest{Volume: volumeSpec, Operation: contracts.OperationContext{IdempotencyKey: "volume-create"}}); err != nil {
		t.Fatal(err)
	}
	if err = volume.Attach(context.Background(), contracts.VolumeRequest{Volume: volumeSpec, Operation: contracts.OperationContext{IdempotencyKey: "volume-attach"}}); err != nil {
		t.Fatal(err)
	}
	if err = volume.Retain(context.Background(), contracts.VolumeRequest{Volume: volumeSpec, Operation: contracts.OperationContext{IdempotencyKey: "volume-retain"}}); err != nil {
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
	before := acornFox04CProviderSnapshot(t, runtime, volume, deployment.ID, sentinel, []string{"retained-volume:application-data", "network:existing-app-net"})
	if fault == "" {
		err = prepareAcornFoxRepository(context.Background(), store, published, receipt.CandidateReceipt.BindingSHA256)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		old := acornFoxRepoBootstrapFaultStep
		acornFoxRepoBootstrapFaultStep = func(step string) error {
			if step == fault {
				return errors.New("fault")
			}
			return nil
		}
		err = prepareAcornFoxRepository(context.Background(), store, published, receipt.CandidateReceipt.BindingSHA256)
		acornFoxRepoBootstrapFaultStep = old
		if !errors.Is(err, ErrAcornFoxRepoBootstrapConflict) {
			t.Fatalf("fault=%v", err)
		}
		if err = store.Close(); err != nil {
			t.Fatal(err)
		}
		fresh, openErr := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
		if openErr != nil {
			t.Fatal(openErr)
		}
		defer fresh.Close()
		if err = prepareAcornFoxRepository(context.Background(), fresh, published, receipt.CandidateReceipt.BindingSHA256); err != nil {
			t.Fatalf("recovery=%v", err)
		}
	}
	after := acornFox04CProviderSnapshot(t, runtime, volume, deployment.ID, sentinel, []string{"retained-volume:application-data", "network:existing-app-net"})
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("provider or sentinel state changed:\n before=%#v\n after=%#v", before, after)
	}
	if before.RuntimeMutations != after.RuntimeMutations || before.VolumeMutations != after.VolumeMutations {
		t.Fatalf("provider mutation count changed: runtime %d->%d volume %d->%d", before.RuntimeMutations, after.RuntimeMutations, before.VolumeMutations, after.VolumeMutations)
	}
	if after.Sentinel.Inode == 0 || after.Sentinel.SHA256 == "" || beforeInfo == nil || len(beforeRaw) == 0 {
		t.Fatal("sentinel snapshot is incomplete")
	}
}

type acornFox04CRuntimeRecorder struct {
	driver    *contracts.FakeRuntimeDriver
	mutations int
}

func (r *acornFox04CRuntimeRecorder) Deploy(ctx context.Context, request contracts.DeployRequest) (domain.Deployment, error) {
	deployment, err := r.driver.Deploy(ctx, request)
	if err == nil {
		r.mutations++
	}
	return deployment, err
}
func (r *acornFox04CRuntimeRecorder) Observe(ctx context.Context, request contracts.ObserveRequest) (contracts.RuntimeObservation, error) {
	return r.driver.Observe(ctx, request)
}

type acornFox04CVolumeRecorder struct {
	provider  *contracts.FakeVolumeProvider
	state     acornFox04CVolumeState
	mutations int
}
type acornFox04CVolumeState struct {
	Spec     contracts.VolumeSpec
	Created  bool
	Attached bool
	Retained bool
}

func (r *acornFox04CVolumeRecorder) Create(ctx context.Context, request contracts.VolumeRequest) (contracts.VolumeSpec, contracts.Evidence, error) {
	spec, evidence, err := r.provider.Create(ctx, request)
	if err == nil {
		r.state.Spec, r.state.Created, r.mutations = spec, true, r.mutations+1
	}
	return spec, evidence, err
}
func (r *acornFox04CVolumeRecorder) Attach(ctx context.Context, request contracts.VolumeRequest) error {
	err := r.provider.Attach(ctx, request)
	if err == nil {
		r.state.Attached, r.mutations = true, r.mutations+1
	}
	return err
}
func (r *acornFox04CVolumeRecorder) Retain(ctx context.Context, request contracts.VolumeRequest) error {
	err := r.provider.Retain(ctx, request)
	if err == nil {
		r.state.Retained, r.mutations = true, r.mutations+1
	}
	return err
}

type acornFox04CSentinelSnapshot struct {
	Inode  uint64
	SHA256 string
}
type acornFox04CProviderStateSnapshot struct {
	RuntimeProvider  contracts.ProviderMetadata
	VolumeProvider   contracts.ProviderMetadata
	Observation      contracts.RuntimeObservation
	Volume           acornFox04CVolumeState
	Network          string
	Sentinel         acornFox04CSentinelSnapshot
	RuntimeMutations int
	VolumeMutations  int
}

func acornFox04CProviderSnapshot(t *testing.T, runtime *acornFox04CRuntimeRecorder, volume *acornFox04CVolumeRecorder, deploymentID domain.ID, sentinel string, network []string) acornFox04CProviderStateSnapshot {
	t.Helper()
	observation, err := runtime.Observe(context.Background(), contracts.ObserveRequest{DeploymentID: deploymentID, Operation: contracts.OperationContext{IdempotencyKey: "runtime-observe"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("sentinel inode unavailable")
	}
	sum := sha256.Sum256(raw)
	return acornFox04CProviderStateSnapshot{RuntimeProvider: runtime.driver.Metadata(context.Background()), VolumeProvider: volume.provider.Metadata(context.Background()), Observation: observation, Volume: volume.state, Network: strings.Join(network, "\x00"), Sentinel: acornFox04CSentinelSnapshot{Inode: uint64(stat.Ino), SHA256: hex.EncodeToString(sum[:])}, RuntimeMutations: runtime.mutations, VolumeMutations: volume.mutations}
}

func TestAcornFox04CRepositoryEngineHasNoProviderCapability(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("test source unavailable")
	}
	path := filepath.Join(filepath.Dir(source), "acornfox_repo_bootstrap.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for _, imported := range file.Imports {
		value := strings.Trim(imported.Path.Value, "\"")
		if strings.Contains(value, "/contracts") || strings.Contains(value, "/domain") {
			t.Fatalf("repository engine imports provider package %q", value)
		}
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "prepareAcornFoxRepository" {
			continue
		}
		if function.Type.Params == nil || len(function.Type.Params.List) != 4 {
			t.Fatalf("repository engine provider boundary changed: %#v", function.Type.Params)
		}
		return
	}
	t.Fatal("repository engine entrypoint missing")
}
