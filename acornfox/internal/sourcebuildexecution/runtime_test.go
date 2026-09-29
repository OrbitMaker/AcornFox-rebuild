package sourcebuildexecution

import (
	"context"
	"errors"
	"github.com/acornfox/acornfox/internal/foundation"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	capacityprovider "github.com/acornfox/acornfox/internal/providers/capacity"
)

type authorityFixture struct {
	check       func(SourceBuildCommand) error
	wrongDigest bool
}

func (a *authorityFixture) AuthorizeSourceBuild(_ context.Context, c SourceBuildCommand) (appcontracts.SourceBuildPermit, error) {
	if err := a.check(c); err != nil {
		return appcontracts.SourceBuildPermit{}, err
	}
	d, err := SourceBuildCommandDigest(c)
	if a.wrongDigest {
		d = "sha256:" + strings.Repeat("0", 64)
	}
	return appcontracts.SourceBuildPermit{CommandSHA256: d}, err
}

type sourceFixture struct {
	result   contracts.PrepareSourceResult
	prepared int
	released int
}

func (s *sourceFixture) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Capabilities: contracts.NewCapabilitySet(contracts.CapabilitySourcePrepare, contracts.CapabilitySourceRelease)}
}
func (s *sourceFixture) Prepare(context.Context, contracts.PrepareSourceRequest) (contracts.PrepareSourceResult, error) {
	s.prepared++
	return s.result, nil
}
func (s *sourceFixture) Release(context.Context, contracts.ReleaseSourceRequest) error {
	s.released++
	return nil
}

type buildFixture struct {
	result    contracts.BuildResult
	built     int
	cancelled int
	failure   error
	key       string
	capacity  contracts.CapacityProvider
}

func (b *buildFixture) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Capabilities: contracts.NewCapabilitySet(contracts.CapabilityBuild)}
}
func (b *buildFixture) Build(ctx context.Context, r contracts.BuildRequest) (contracts.BuildResult, error) {
	if r.Capacity == nil {
		return contracts.BuildResult{}, ErrBinding
	}
	if err := b.capacity.Activate(ctx, *r.Capacity, contracts.OperationContext{IdempotencyKey: r.Operation.IdempotencyKey + ":capacity-activate"}); err != nil {
		return contracts.BuildResult{}, err
	}
	b.built++
	b.key = r.Operation.IdempotencyKey
	return b.result, b.failure
}
func (b *buildFixture) Cancel(_ context.Context, o contracts.OperationContext) error {
	b.cancelled++
	b.key = o.IdempotencyKey
	return nil
}

func TestRuntimeMapsOnlyCoreApprovedStagesAndRejectsIdentityDrift(t *testing.T) {
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	commit := strings.Repeat("a", 40)
	workspace := filepath.Join(t.TempDir(), "source")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte("FROM scratch\nCMD [\"/app\"]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	digestHex, err := foundation.HashDirectory(workspace)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + digestHex
	binding := appcontracts.SourceBuildBinding{TaskID: "task_fixture", OperationID: "op_fixture", ApplicationID: "app_fixture", Owner: "worker", CoreGeneration: 3, LeaseGeneration: 2}
	prepare := contracts.PrepareSourceRequest{ApplicationID: binding.ApplicationID, Kind: domain.SourceGitHTTPS, Locator: "https://github.com/acme/app", Ref: commit, ContentDigest: digest, Operation: contracts.OperationContext{IdempotencyKey: "prepare-key"}}
	revision := domain.SourceRevision{ID: "src_fixture", ApplicationID: binding.ApplicationID, Kind: domain.SourceGitHTTPS, Locator: prepare.Locator, Ref: commit, Commit: commit, ContentDigest: digest, WorkspaceRef: workspace, CreatedAt: now, Immutable: true}
	request := contracts.BuildRequest{BuildID: "build_fixture", Source: revision, Resources: contracts.ResourceLimits{CPUMillis: 100, MemoryBytes: 1024, DiskBytes: 1024, TimeoutSeconds: 120, ConcurrencySlot: 1, PIDs: 64}, Operation: contracts.OperationContext{IdempotencyKey: "build-key"}, Plan: domain.BuildPlan{ID: "plan_fixture", SourceRevisionID: revision.ID, SourceDigest: digest, ServiceName: "web", Kind: domain.BuildDockerfile, ContextPath: ".", DockerfilePath: "Dockerfile", TargetRepository: "ghcr.io/acme/app", Output: domain.BuildOutputContract{Format: domain.BuildOutputOCI, Retention: domain.BuildRetentionPersist, StorageKey: "artifact-fixture"}, IdempotencyKey: "build-key", CreatedAt: now}}
	artifact := domain.Artifact{ID: "artifact_fixture", BuildID: request.BuildID, Image: domain.ImageDigest{Repository: request.Plan.TargetRepository, Digest: "sha256:" + strings.Repeat("c", 64)}, OCIStorageRef: "opaque-stored-oci", SizeBytes: 123, CreatedAt: now}
	src := &sourceFixture{result: contracts.PrepareSourceResult{Revision: revision}}
	builder := &buildFixture{result: contracts.BuildResult{Build: domain.Build{ID: request.BuildID, PlanID: request.Plan.ID, Status: domain.BuildSucceeded, ArtifactID: artifact.ID}, Artifact: &artifact, LogRef: "durable-log-ref"}}
	expected := map[appcontracts.SourceBuildStage]SourceBuildCommand{}
	expected[appcontracts.SourceBuildPrepare] = SourceBuildCommand{Stage: appcontracts.SourceBuildPrepare, Binding: binding, Prepare: &prepare}
	expected[appcontracts.SourceBuildBuild] = SourceBuildCommand{Stage: appcontracts.SourceBuildBuild, Binding: binding, Build: &request}
	cancel := CancelSourceBuildRequest{BuildID: request.BuildID, PlanID: request.Plan.ID, SourceRevisionID: revision.ID, Operation: request.Operation}
	expected[appcontracts.SourceBuildCancel] = SourceBuildCommand{Stage: appcontracts.SourceBuildCancel, Binding: binding, Cancel: &cancel}
	release := contracts.ReleaseSourceRequest{Revision: revision, Operation: contracts.OperationContext{IdempotencyKey: "release-key"}}
	expected[appcontracts.SourceBuildRelease] = SourceBuildCommand{Stage: appcontracts.SourceBuildRelease, Binding: binding, Release: &release}
	// This in-memory authority stands in for the missing durable Core consumer.
	// Matching the entire approved object is essential, not just an action label.
	authority := &authorityFixture{check: func(c SourceBuildCommand) error {
		want, ok := expected[c.Stage]
		if !ok {
			return ErrBinding
		}
		got, _ := SourceBuildCommandDigest(c)
		target, _ := SourceBuildCommandDigest(want)
		if got != target {
			return ErrBinding
		}
		return nil
	}}
	capacity, err := capacityprovider.New(capacityprovider.Config{Reader: capacityprovider.ReaderFunc(func(context.Context, string) (capacityprovider.HostCapacity, error) {
		return capacityprovider.HostCapacity{TotalCPUMillis: 10000, AvailableCPUMillis: 10000, TotalMemoryBytes: 1 << 30, AvailableMemoryBytes: 1 << 30, TotalDiskBytes: 1 << 30, AvailableDiskBytes: 1 << 30}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	factory := func(c contracts.CapacityProvider) (contracts.BuildProvider, error) {
		builder.capacity = c
		return builder, nil
	}
	runtime, err := NewRuntime(Config{Source: src, BuilderFactory: factory, Authority: authority, Capacity: capacity})
	if err != nil {
		t.Fatal(err)
	}
	cancelledCtx, cancelCtx := context.WithCancel(context.Background())
	cancelCtx()
	if _, err := runtime.Prepare(cancelledCtx, binding, prepare); !errors.Is(err, context.Canceled) || src.prepared != 0 {
		t.Fatal("pre-cancelled command lost cause or produced effects")
	}
	prepared, err := runtime.Prepare(context.Background(), binding, prepare)
	if err != nil || prepared.Result.Revision.ID != revision.ID || builder.built != 0 {
		t.Fatalf("prepare err=%v", err)
	}
	src.result.Revision.ContentDigest = "sha256:" + strings.Repeat("d", 64)
	if _, err := runtime.Prepare(context.Background(), binding, prepare); !contracts.IsProviderOutcomeUnknown(err) {
		t.Fatal("wrong successful source digest accepted")
	}
	src.result.Revision.ContentDigest = digest
	injected := request
	injected.Capacity = &contracts.CapacityLease{ID: "caller-lease"}
	if _, err := runtime.Build(context.Background(), binding, injected); err == nil || builder.built != 0 {
		t.Fatal("external capacity was accepted")
	}
	built, err := runtime.Build(context.Background(), binding, request)
	if err != nil || built.Result.Artifact.ID != artifact.ID || built.SourceRevisionID != revision.ID || built.SourceDigest != digest {
		t.Fatalf("build err=%v", err)
	}
	snapshot, _, err := capacity.Preflight(context.Background(), contracts.CapacityRequest{Scope: contracts.CapacityBuild, Resources: request.Resources, Operation: contracts.OperationContext{IdempotencyKey: "inspect-after-success"}})
	if err != nil || snapshot.ReservedCPUMillis != 0 {
		t.Fatal("known success did not release real reservation")
	}
	if err := runtime.Cancel(context.Background(), binding, cancel); err != nil || builder.key != "build-key" {
		t.Fatalf("cancel err=%v", err)
	}
	changed := release
	changed.Revision.WorkspaceRef = "/owned/source/other-task"
	if err := runtime.Release(context.Background(), binding, changed); err == nil || src.released != 0 {
		t.Fatal("caller-selected workspace released")
	}
	stale := binding
	stale.LeaseGeneration++
	if _, err := runtime.Build(context.Background(), stale, request); err == nil || builder.built != 1 {
		t.Fatal("stale binding dispatched")
	}
	altered := request
	altered.Plan.DockerfilePath = "other.Dockerfile"
	if _, err := runtime.Build(context.Background(), binding, altered); err == nil || builder.built != 1 {
		t.Fatal("unapproved build plan dispatched")
	}
	wrongCancel := cancel
	wrongCancel.Operation.IdempotencyKey = "other-build"
	if err := runtime.Cancel(context.Background(), binding, wrongCancel); err == nil || builder.cancelled != 1 {
		t.Fatal("wrong build cancelled")
	}
	authority.wrongDigest = true
	if _, err := runtime.Build(context.Background(), binding, request); err == nil || builder.built != 1 {
		t.Fatal("unbound permit dispatched")
	}
	authority.wrongDigest = false
	request.Operation.IdempotencyKey = "build-wrong-result"
	builder.result.Build.ID = "build_other"
	if _, err := runtime.Build(context.Background(), binding, request); !contracts.IsProviderOutcomeUnknown(err) || !errors.Is(err, ErrBinding) {
		t.Fatal("invalid success not preserved as unknown")
	}
	builder.result.Build.ID = request.BuildID
	request.Operation.IdempotencyKey = "build-cancelled"
	builder.failure = context.DeadlineExceeded
	before := src.released
	if _, err := runtime.Build(context.Background(), binding, request); !errors.Is(err, context.DeadlineExceeded) || src.released != before {
		t.Fatal("build failure dropped cause or automatically released source")
	}
	snapshot, _, err = capacity.Preflight(context.Background(), contracts.CapacityRequest{Scope: contracts.CapacityBuild, Resources: request.Resources, Operation: contracts.OperationContext{IdempotencyKey: "inspect-after-unknown"}})
	if err != nil || snapshot.ReservedCPUMillis != 2*request.Resources.CPUMillis {
		t.Fatal("unknown remote outcome blindly released reservation")
	}
	if err := runtime.Release(context.Background(), binding, release); err != nil || src.released != 1 {
		t.Fatalf("approved release err=%v", err)
	}
	if _, err := NewRuntime(Config{Source: src, BuilderFactory: factory, Capacity: capacity}); err == nil {
		t.Fatal("authority missing accepted")
	}
}
