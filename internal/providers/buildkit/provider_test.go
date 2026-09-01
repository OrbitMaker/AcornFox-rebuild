package buildkit

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
	"github.com/open-card/open-card/internal/importers/dockerfile"
	secretprovider "github.com/open-card/open-card/internal/providers/secret"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type fakeRunner struct {
	mu    sync.Mutex
	calls [][]string
	run   func(context.Context, []string, io.Writer, io.Writer) error
}

type fakeBuildLogSink struct {
	mu      sync.Mutex
	calls   int
	ref     string
	err     error
	events  *[]string
	content string
}

func (s *fakeBuildLogSink) StoreBuildLog(_ context.Context, _ contracts.BuildRequest, content string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.content = content
	if s.events != nil {
		*s.events = append(*s.events, "log")
	}
	if s.err != nil {
		return "", s.err
	}
	return s.ref, nil
}

func (s *fakeBuildLogSink) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

type countingImageStore struct {
	contracts.ImageStore
	mu     sync.Mutex
	calls  int
	err    error
	events *[]string
}

func (s *countingImageStore) StoreOCI(ctx context.Context, request contracts.StoreOCIRequest) (contracts.StoreOCIResult, error) {
	s.mu.Lock()
	s.calls++
	if s.events != nil {
		*s.events = append(*s.events, "oci")
	}
	err := s.err
	s.mu.Unlock()
	if err != nil {
		return contracts.StoreOCIResult{}, err
	}
	return s.ImageStore.StoreOCI(ctx, request)
}

func (s *countingImageStore) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (r *fakeRunner) Run(ctx context.Context, command string, args []string, stdout, stderr io.Writer) error {
	if command != "buildctl" {
		return fmt.Errorf("unexpected command %q", command)
	}
	r.mu.Lock()
	r.calls = append(r.calls, append([]string(nil), args...))
	r.mu.Unlock()
	return r.run(ctx, args, stdout, stderr)
}

func (r *fakeRunner) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func writingRunner(t *testing.T, output string) *fakeRunner {
	t.Helper()
	return &fakeRunner{run: func(_ context.Context, args []string, stdout, _ io.Writer) error {
		if _, err := io.WriteString(stdout, output); err != nil {
			return err
		}
		metadata := valueAfter(t, args, "--metadata-file")
		oci := strings.TrimPrefix(valueAfter(t, args, "--output"), "type=oci,dest=")
		if err := os.WriteFile(metadata, []byte(`{"containerimage.digest":"`+testDigest+`"}`), 0o600); err != nil {
			return err
		}
		return os.WriteFile(oci, []byte("oci-layout"), 0o600)
	}}
}

type fakeSecretResolver struct{ root string }

func (f fakeSecretResolver) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "fake-secret-resolver", Version: "1", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilitySecretResolve)}
}
func (f fakeSecretResolver) ResolveBuildSecret(_ context.Context, reference domain.SecretReference, operation contracts.OperationContext) (contracts.BuildSecretMaterial, error) {
	path := filepath.Join(f.root, reference.ID.String()+"-"+hashText(operation.IdempotencyKey)[:8])
	if err := os.WriteFile(path, []byte("super-secret"), 0o400); err != nil {
		return contracts.BuildSecretMaterial{}, err
	}
	return contracts.BuildSecretMaterial{MountID: "mount-" + hashText(operation.IdempotencyKey)[:12], Reference: reference, Path: path, ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (f fakeSecretResolver) RevokeBuildSecret(_ context.Context, material contracts.BuildSecretMaterial, _ contracts.OperationContext) error {
	_ = os.Chmod(material.Path, 0o600)
	return os.Remove(material.Path)
}

type fakeCapacity struct{}

func (fakeCapacity) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "fake-capacity", Version: "1", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilityCapacityCheck, contracts.CapabilityCapacityReserve)}
}
func (fakeCapacity) Preflight(_ context.Context, request contracts.CapacityRequest) (contracts.CapacitySnapshot, contracts.Evidence, error) {
	return contracts.CapacitySnapshot{Scope: request.Scope}, contracts.Evidence{Redacted: true}, nil
}
func (fakeCapacity) Reserve(_ context.Context, request contracts.CapacityRequest) (contracts.CapacityLease, error) {
	return contracts.CapacityLease{ID: "lease-1", Scope: request.Scope, Resources: request.Resources, ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (fakeCapacity) Activate(context.Context, contracts.CapacityLease, contracts.OperationContext) error {
	return nil
}
func (fakeCapacity) Release(context.Context, contracts.CapacityLease, contracts.OperationContext) error {
	return nil
}

func testProvider(t *testing.T, runner CommandRunner) (*Provider, string, domain.SourceRevision) {
	t.Helper()
	root := t.TempDir()
	workspaceRoot := filepath.Join(root, "sources")
	project := filepath.Join(workspaceRoot, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "Dockerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(project, "Dockerfile"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(project, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(workspaceRoot, func(path string, entry os.DirEntry, err error) error {
			if err == nil {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	digest, err := foundation.HashDirectory(project)
	if err != nil {
		t.Fatal(err)
	}
	source := domain.SourceRevision{ID: "src_1", ApplicationID: "app_1", Kind: domain.SourceUpload, Locator: "upload://fixture", ContentDigest: "sha256:" + digest, WorkspaceRef: project, CreatedAt: time.Unix(1, 0).UTC(), Immutable: true}
	staticServer := filepath.Join(root, "open-card-static-server")
	if err := os.WriteFile(staticServer, []byte("static-server-binary"), 0o500); err != nil {
		t.Fatal(err)
	}
	secretRoot := filepath.Join(root, "secret-materials")
	if err := os.Mkdir(secretRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	provider, err := New(Config{
		Builder:            "rootless-worker",
		WorkspaceRoot:      workspaceRoot,
		WorkRoot:           filepath.Join(root, "work"),
		StaticServerBinary: staticServer,
		Runner:             runner,
		ImageStore:         contracts.NewFakeImageStore(true),
		Capacity:           fakeCapacity{},
		SecretResolver:     fakeSecretResolver{root: secretRoot},
		LogSink:            &fakeBuildLogSink{ref: "memory://build-log/default"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider, root, source
}

func bindAcornFoxDigests(t *testing.T, request *contracts.BuildRequest) {
	t.Helper()
	definition, err := dockerfile.Import(request.Source)
	if err != nil {
		t.Fatal(err)
	}
	if definition.Status != contracts.AcornFoxDockerfileReady {
		t.Fatalf("test Dockerfile definition is not ready: %#v", definition)
	}
	request.Plan.AcornFoxDefinitionDigest = definition.DefinitionDigest
	request.Plan.AcornFoxDockerfileDigest = definition.DockerfileDigest
}

func testRequest(key string, source domain.SourceRevision) contracts.BuildRequest {
	request := contracts.BuildRequest{
		BuildID: "build_1",
		Plan: domain.BuildPlan{
			ID: "plan_1", SourceRevisionID: "src_1", ServiceName: "web", Kind: domain.BuildDockerfile,
			SourceDigest: source.ContentDigest, ContextPath: ".", DockerfilePath: "Dockerfile", TargetRepository: "registry.open-card.local/apps/web",
			Output:     domain.BuildOutputContract{Format: domain.BuildOutputOCI, Retention: domain.BuildRetentionPersist, StorageKey: "app_1/src_1/web"},
			SecretRefs: []domain.SecretReference{{ID: "secret_1", Name: "registry_token", Provider: "fake", Version: "v1"}}, IdempotencyKey: key,
		},
		Source:    source,
		Resources: contracts.ResourceLimits{MemoryBytes: MemoryLimitBytes, CPUMillis: CPULimitMillis, DiskBytes: 256 << 20, ConcurrencySlot: 1},
		Operation: contracts.OperationContext{IdempotencyKey: key},
	}
	request.Capacity = &contracts.CapacityLease{ID: "lease-" + key, Scope: contracts.CapacityBuild, Resources: request.Resources, ExpiresAt: time.Now().Add(time.Minute)}
	return request
}

func valueAfter(t *testing.T, args []string, flag string) string {
	t.Helper()
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	t.Fatalf("missing %s in %#v", flag, args)
	return ""
}

func TestBuildUsesAllowlistedRootlessBuildxBoundaryAndCleansWorkspace(t *testing.T) {
	runner := writingRunner(t, "using super-secret\n")
	provider, root, source := testProvider(t, runner)
	result, err := provider.Build(context.Background(), testRequest("build-1", source))
	if err != nil {
		t.Fatal(err)
	}
	if result.Artifact == nil || result.Artifact.Image.Digest != testDigest || result.Artifact.Image.Repository != "registry.open-card.local/apps/web" {
		t.Fatalf("unexpected immutable artifact: %#v", result.Artifact)
	}
	if !result.Evidence.Redacted || len(result.Evidence.Refs) < 4 || result.LogRef == "" || result.Artifact.OCIStorageRef == "" || strings.Contains(fmt.Sprintf("%#v", result), "super-secret") {
		t.Fatalf("result leaked a secret or lacks redacted evidence: %#v", result)
	}
	if runner.callCount() != 1 {
		t.Fatalf("want one endpoint command, got %d", runner.callCount())
	}
	args := runner.calls[0]
	wantPrefix := []string{"--addr", "unix:///run/open-card-buildkit/buildkitd.sock", "build", "--frontend", "dockerfile.v0", "--local"}
	for i, want := range wantPrefix {
		if args[i] != want {
			t.Fatalf("command flag %d: got %q want %q; args=%#v", i, args[i], want, args)
		}
	}
	for _, forbidden := range []string{"--allow", "--ssh", "--push", "--load", "--build-arg", "--add-host", "--network=host"} {
		for _, got := range args {
			if got == forbidden {
				t.Fatalf("unsafe flag %q in %#v", forbidden, args)
			}
		}
	}
	if !strings.Contains(strings.Join(args, " "), "--opt network=none") {
		t.Fatalf("offline BuildKit network option is missing: %#v", args)
	}
	if !strings.Contains(strings.Join(args, " "), "--secret id=registry_token,src=") {
		t.Fatalf("secret was not materialized as a temp file: %#v", args)
	}
	entries, err := os.ReadDir(filepath.Join(root, "work"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("per-build workspace/output/secret cleanup failed: %#v", entries)
	}
	secretEntries, err := os.ReadDir(filepath.Join(root, "secret-materials"))
	if err != nil || len(secretEntries) != 0 {
		t.Fatalf("secret resolver material was not revoked: %#v err=%v", secretEntries, err)
	}

	again, err := provider.Build(context.Background(), testRequest("build-1", source))
	if err != nil || again.Build.ID != result.Build.ID || runner.callCount() != 1 {
		t.Fatalf("successful retry was not idempotent: result=%#v err=%v calls=%d", again, err, runner.callCount())
	}
}

func TestStaticBuildGeneratesPinnedPlatformDockerfile(t *testing.T) {
	var generated string
	runner := writingRunner(t, "")
	original := runner.run
	runner.run = func(ctx context.Context, args []string, stdout, stderr io.Writer) error {
		directory := valueWithPrefix(t, args, "dockerfile=")
		filename := valueWithPrefix(t, args, "filename=")
		path := filepath.Join(directory, filename)
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		generated = string(contents)
		return original(ctx, args, stdout, stderr)
	}
	provider, _, source := testProvider(t, runner)
	request := testRequest("static", source)
	request.Plan.Kind = domain.BuildStatic
	request.Plan.DockerfilePath = ""
	request.Plan.SecretRefs = nil
	digest, err := digestFile(provider.config.StaticServerBinary)
	if err != nil {
		t.Fatal(err)
	}
	request.Plan.StaticRuntimeDigest = digest
	if _, err := provider.Build(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(generated, "FROM scratch") || !strings.Contains(generated, "COPY --chown=65532:65532 --chmod=0555 .open-card-static-server") || !strings.Contains(generated, "COPY --chown=65532:65532 . /www") || !strings.Contains(generated, "USER 65532:65532") {
		t.Fatalf("static Dockerfile was not pinned and deterministic: %q", generated)
	}
}

func valueWithPrefix(t *testing.T, args []string, prefix string) string {
	t.Helper()
	for _, value := range args {
		if strings.HasPrefix(value, prefix) {
			return strings.TrimPrefix(value, prefix)
		}
	}
	t.Fatalf("missing value prefix %s in %#v", prefix, args)
	return ""
}

func TestBuildRejectsPolicyEscapesBeforeCallingEndpoint(t *testing.T) {
	runner := writingRunner(t, "")
	provider, _, source := testProvider(t, runner)
	request := testRequest("policy", source)
	request.Network = contracts.NetworkPolicy{Mode: "default"}
	assertProviderCode(t, mustBuild(provider, request), contracts.ErrForbidden)
	request = testRequest("memory", source)
	request.Resources.MemoryBytes = MemoryLimitBytes - 1
	assertProviderCode(t, mustBuild(provider, request), contracts.ErrValidation)
	request = testRequest("slots", source)
	request.Resources.ConcurrencySlot = 2
	assertProviderCode(t, mustBuild(provider, request), contracts.ErrValidation)
	request = testRequest("metadata", source)
	request.Network = contracts.NetworkPolicy{Mode: "none", AllowMetadata: true}
	assertProviderCode(t, mustBuild(provider, request), contracts.ErrForbidden)
	request = testRequest("cidr", source)
	request.Network = contracts.NetworkPolicy{Mode: "none", AllowedCIDRs: []string{"169.254.169.254/32"}}
	assertProviderCode(t, mustBuild(provider, request), contracts.ErrForbidden)
	request = testRequest("host-context", source)
	request.Plan.ContextPath = "/var/run/docker.sock"
	assertProviderCode(t, mustBuild(provider, request), contracts.ErrValidation)
	request = testRequest("host-dockerfile", source)
	request.Plan.DockerfilePath = "/etc/passwd"
	assertProviderCode(t, mustBuild(provider, request), contracts.ErrValidation)
	request = testRequest("no-disk-capacity", source)
	request.Resources.DiskBytes = 0
	assertProviderCode(t, mustBuild(provider, request), contracts.ErrValidation)
	request = testRequest("build-pids", source)
	request.Resources.PIDs = 1
	assertProviderCode(t, mustBuild(provider, request), contracts.ErrValidation)
	if runner.callCount() != 0 {
		t.Fatalf("policy rejection invoked endpoint %d times", runner.callCount())
	}
}

func TestBuildTimeoutAndCancelAreClassified(t *testing.T) {
	blocking := &fakeRunner{run: func(ctx context.Context, _ []string, _ io.Writer, _ io.Writer) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	provider, _, source := testProvider(t, blocking)
	timeoutRequest := testRequest("timeout", source)
	timeoutRequest.Resources.TimeoutSeconds = 1
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	assertProviderCode(t, mustBuild(provider, timeoutRequest, ctx), contracts.ErrTimeout)

	started := make(chan struct{})
	cancelRunner := &fakeRunner{run: func(ctx context.Context, _ []string, _ io.Writer, _ io.Writer) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}}
	provider, _, source = testProvider(t, cancelRunner)
	request := testRequest("cancel", source)
	finished := make(chan error, 1)
	go func() { finished <- mustBuild(provider, request) }()
	<-started
	if err := provider.Cancel(context.Background(), request.Operation); err != nil {
		t.Fatal(err)
	}
	assertProviderCode(t, <-finished, contracts.ErrCancelled)
	assertProviderCode(t, mustBuild(provider, request), contracts.ErrCancelled)
}

func TestBuildSerializesDistinctOperations(t *testing.T) {
	started := make(chan string, 2)
	release := make(chan struct{})
	runner := &fakeRunner{run: func(_ context.Context, args []string, _ io.Writer, _ io.Writer) error {
		started <- filepath.Base(args[len(args)-1])
		<-release
		metadata := valueAfter(t, args, "--metadata-file")
		oci := strings.TrimPrefix(valueAfter(t, args, "--output"), "type=oci,dest=")
		_ = os.WriteFile(metadata, []byte(`{"containerimage.digest":"`+testDigest+`"}`), 0o600)
		return os.WriteFile(oci, []byte("oci-layout"), 0o600)
	}}
	provider, _, source := testProvider(t, runner)
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { first <- mustBuild(provider, testRequest("first", source)) }()
	<-started
	go func() { second <- mustBuild(provider, testRequest("second", source)) }()
	select {
	case <-started:
		t.Fatal("second build entered endpoint before first released")
	case <-time.After(25 * time.Millisecond):
	}
	release <- struct{}{}
	assertNoError(t, <-first)
	<-started
	release <- struct{}{}
	assertNoError(t, <-second)
}

func TestBuildCommandFailureDoesNotLeakSecret(t *testing.T) {
	runner := &fakeRunner{run: func(_ context.Context, _ []string, _ io.Writer, _ io.Writer) error {
		return errors.New("endpoint rejected super-secret")
	}}
	provider, _, source := testProvider(t, runner)
	err := mustBuild(provider, testRequest("redact", source))
	assertProviderCode(t, err, contracts.ErrUnavailable)
	if strings.Contains(fmt.Sprintf("%v %#v", err, err), "super-secret") {
		t.Fatalf("provider error leaked secret: %#v", err)
	}
}

func TestBuildPersistsReadableBuildKitRawJSONLog(t *testing.T) {
	marker := "AFB_NETWORK_PROBE all_attempted_all_denied\n"
	runner := writingRunner(t, rawJSONLogsProgress("vertex one\r\n", marker))
	provider, _, source := testProvider(t, runner)
	request := testRequest("readable-rawjson", source)
	request.Plan.SecretRefs = nil
	result, err := provider.Build(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	sink, ok := provider.config.LogSink.(*fakeBuildLogSink)
	if !ok || sink.content != "vertex one\n"+marker || !strings.Contains(result.Evidence.Digest, "sha256:") {
		t.Fatalf("successful rawjson log was not normalized before persistence: sink=%#v result=%#v", sink, result)
	}
}

func TestNormalizeBuildKitRawJSONLogFallbackAndBound(t *testing.T) {
	raw := `{"vertex":"progress-only"}` + "\n" + rawJSONLogsProgress("first \r", "\nsecond\n")
	if got := normalizeBuildKitRawJSONLog(raw); got != "first \nsecond\n" {
		t.Fatalf("rawjson event ordering changed: %q", got)
	}
	if got := normalizeBuildKitRawJSONLog(rawJSONProgress("compatibility\n")); got != "compatibility\n" {
		t.Fatalf("top-level rawjson data compatibility changed: %q", got)
	}
	malformed := rawJSONLogsProgress("recognized\n") + `{"logs":[{"data":123}]}` + "\n"
	if got := normalizeBuildKitRawJSONLog(malformed); got != malformed {
		t.Fatalf("malformed rawjson did not retain raw fallback: %q", got)
	}
	noData := `{"vertex":"only","logs":[{"vertex":"also-progress-only"}]}` + "\n"
	if got := normalizeBuildKitRawJSONLog(noData); got != noData {
		t.Fatalf("data-free rawjson did not retain raw fallback: %q", got)
	}
	tooLarge := rawJSONLogsProgress(strings.Repeat("x", maxCaptureBytes+1))
	if got := normalizeBuildKitRawJSONLog(tooLarge); len(got) != maxCaptureBytes {
		t.Fatalf("normalized log was not bounded: %d", len(got))
	}
}

func rawJSONProgress(value string) string {
	return `{"data":"` + base64.StdEncoding.EncodeToString([]byte(value)) + `"}` + "\n"
}

func rawJSONLogsProgress(values ...string) string {
	entries := make([]string, 0, len(values))
	for _, value := range values {
		entries = append(entries, `{"vertex":"sha256:fixture","stream":1,"data":"`+base64.StdEncoding.EncodeToString([]byte(value))+`","timestamp":"2026-09-01T00:00:00Z"}`)
	}
	return `{"logs":[` + strings.Join(entries, ",") + `]}` + "\n"
}

func TestAcornFoxBuildRejectsCopiedDockerfileMismatchBeforeEffects(t *testing.T) {
	runner := writingRunner(t, "")
	provider, _, source := testProvider(t, runner)
	request := testRequest("acornfox-digest-mismatch", source)
	bindAcornFoxDigests(t, &request)
	request.Plan.AcornFoxDockerfileDigest = "sha256:" + strings.Repeat("0", 64)
	logs := &fakeBuildLogSink{ref: "memory://build-log/mismatch"}
	store := &countingImageStore{ImageStore: contracts.NewFakeImageStore(true)}
	provider.config.LogSink = logs
	provider.config.ImageStore = store
	err := mustBuild(provider, request)
	assertProviderCode(t, err, contracts.ErrValidation)
	if runner.callCount() != 0 || logs.callCount() != 0 || store.callCount() != 0 {
		t.Fatalf("mismatched copied Dockerfile caused effects: runner=%d logs=%d oci=%d", runner.callCount(), logs.callCount(), store.callCount())
	}
}

func TestAcornFoxBuildRejectsDefinitionSemanticMismatchBeforeEffects(t *testing.T) {
	runner := writingRunner(t, "")
	provider, _, source := testProvider(t, runner)
	request := testRequest("acornfox-definition-mismatch", source)
	bindAcornFoxDigests(t, &request)
	if err := os.Chmod(source.WorkspaceRef, 0o700); err != nil {
		t.Fatal(err)
	}
	dockerfilePath := filepath.Join(source.WorkspaceRef, "Dockerfile")
	if err := os.Chmod(dockerfilePath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dockerfilePath, []byte("FROM scratch\nCMD [\"/changed\"]\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	updatedSourceDigest, err := foundation.HashDirectory(source.WorkspaceRef)
	if err != nil {
		t.Fatal(err)
	}
	updatedDockerfileDigest, err := digestFile(dockerfilePath)
	if err != nil {
		t.Fatal(err)
	}
	request.Source.ContentDigest = "sha256:" + updatedSourceDigest
	request.Plan.SourceDigest = request.Source.ContentDigest
	request.Plan.AcornFoxDockerfileDigest = updatedDockerfileDigest
	logs := &fakeBuildLogSink{ref: "memory://build-log/mismatch"}
	store := &countingImageStore{ImageStore: contracts.NewFakeImageStore(true)}
	provider.config.LogSink = logs
	provider.config.ImageStore = store
	err = mustBuild(provider, request)
	assertProviderCode(t, err, contracts.ErrValidation)
	if runner.callCount() != 0 || logs.callCount() != 0 || store.callCount() != 0 {
		t.Fatalf("definition mismatch caused effects: runner=%d logs=%d oci=%d", runner.callCount(), logs.callCount(), store.callCount())
	}
}

func TestAcornFoxBuildRequiresDurableLogBeforeOCI(t *testing.T) {
	runner := writingRunner(t, "normal build output\n")
	provider, _, source := testProvider(t, runner)
	request := testRequest("acornfox-log-order", source)
	bindAcornFoxDigests(t, &request)
	events := []string{}
	logs := &fakeBuildLogSink{ref: "memory://build-log/durable", events: &events}
	store := &countingImageStore{ImageStore: contracts.NewFakeImageStore(true), events: &events}
	provider.config.LogSink = logs
	provider.config.ImageStore = store
	result, err := provider.Build(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.LogRef != logs.ref || len(events) != 2 || events[0] != "log" || events[1] != "oci" {
		t.Fatalf("durable log was not persisted before OCI with its actual reference: result=%#v events=%#v", result, events)
	}
	if len(result.Evidence.Refs) == 0 || result.Evidence.Refs[0].Locator != logs.ref {
		t.Fatalf("build log evidence does not use durable log reference: %#v", result.Evidence.Refs)
	}
}

func TestAcornFoxBuildLogFailurePreventsOCIAndOCIErrorRetainsTruthfulLog(t *testing.T) {
	t.Run("log failure", func(t *testing.T) {
		runner := writingRunner(t, "")
		provider, _, source := testProvider(t, runner)
		request := testRequest("acornfox-log-failure", source)
		bindAcornFoxDigests(t, &request)
		logs := &fakeBuildLogSink{err: errors.New("durable log unavailable")}
		store := &countingImageStore{ImageStore: contracts.NewFakeImageStore(true)}
		provider.config.LogSink = logs
		provider.config.ImageStore = store
		assertProviderCode(t, mustBuild(provider, request), contracts.ErrUnavailable)
		if logs.callCount() != 1 || store.callCount() != 0 {
			t.Fatalf("log failure must prevent OCI storage: logs=%d oci=%d", logs.callCount(), store.callCount())
		}
	})
	t.Run("OCI failure", func(t *testing.T) {
		runner := writingRunner(t, "")
		provider, _, source := testProvider(t, runner)
		request := testRequest("acornfox-oci-failure", source)
		bindAcornFoxDigests(t, &request)
		logs := &fakeBuildLogSink{ref: "memory://build-log/retained"}
		store := &countingImageStore{ImageStore: contracts.NewFakeImageStore(true), err: errors.New("OCI store unavailable")}
		provider.config.LogSink = logs
		provider.config.ImageStore = store
		result, err := provider.Build(context.Background(), request)
		assertProviderCode(t, err, contracts.ErrUnavailable)
		var providerErr *contracts.ProviderError
		if !errors.As(err, &providerErr) || providerErr.Details["log_ref"] != logs.ref {
			t.Fatalf("OCI failure did not expose the actual retained durable log reference: %#v", err)
		}
		if result.Artifact != nil || logs.callCount() != 1 || store.callCount() != 1 {
			t.Fatalf("OCI failure did not leave only truthful durable log evidence: result=%#v logs=%d oci=%d", result, logs.callCount(), store.callCount())
		}
	})
}

func TestAcornFoxBuildWithoutLogSinkFailsBeforeRunner(t *testing.T) {
	runner := writingRunner(t, "")
	provider, _, source := testProvider(t, runner)
	request := testRequest("acornfox-no-log-sink", source)
	bindAcornFoxDigests(t, &request)
	provider.config.LogSink = nil
	assertProviderCode(t, mustBuild(provider, request), contracts.ErrUnavailable)
	if runner.callCount() != 0 {
		t.Fatal("AcornFox build ran without a durable log sink")
	}
}

func TestAcornFoxBuildSameKeyTargetDriftConflictsWithoutSecondRunner(t *testing.T) {
	runner := writingRunner(t, "")
	provider, _, source := testProvider(t, runner)
	request := testRequest("acornfox-target-drift", source)
	bindAcornFoxDigests(t, &request)
	if _, err := provider.Build(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	drift := request
	drift.Plan.TargetRepository = "registry.open-card.local/apps/other"
	assertProviderCode(t, mustBuild(provider, drift), contracts.ErrConflict)
	if runner.callCount() != 1 {
		t.Fatalf("same-key target drift invoked a second runner: %d", runner.callCount())
	}
}

func TestAcornFoxBuildRejectsNonRootPlanBeforeRunner(t *testing.T) {
	runner := writingRunner(t, "")
	provider, _, source := testProvider(t, runner)
	request := testRequest("acornfox-non-root", source)
	bindAcornFoxDigests(t, &request)
	request.Plan.DockerfilePath = "container/Dockerfile"
	assertProviderCode(t, mustBuild(provider, request), contracts.ErrValidation)
	if runner.callCount() != 0 {
		t.Fatal("non-root AcornFox plan invoked BuildKit")
	}
}

func TestLogSinkRequirementDoesNotBreakLegacyOptionalBuilds(t *testing.T) {
	runner := writingRunner(t, "")
	provider, _, source := testProvider(t, runner)
	provider.config.LogSink = nil
	result, err := provider.Build(context.Background(), testRequest("legacy-no-log", source))
	if err != nil {
		t.Fatal(err)
	}
	if result.LogRef != "" {
		t.Fatalf("legacy build fabricated a durable log reference: %#v", result)
	}
	config := provider.config
	config.RequireLogSink = true
	if _, err := New(config); err == nil {
		t.Fatal("required durable log sink was accepted when absent")
	}
}

func TestRealSecretResolverSuppressesCanaryAndRevokesMaterial(t *testing.T) {
	canary := []byte("OPENCARD_M1_CANARY_7f53d923")
	root := t.TempDir()
	vault := filepath.Join(root, "vault")
	materials := filepath.Join(root, "materials")
	key := filepath.Join(root, "master.key")
	resolver, err := secretprovider.New(secretprovider.Config{Root: vault, MaterialRoot: materials, MasterKeyPath: key, MaterialTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	reference := domain.SecretReference{ID: "secret_canary", Name: "canary", Provider: "filesystem-secret", Version: "v1"}
	if _, err := resolver.Store(context.Background(), contracts.SecretRequest{Reference: reference, Value: canary, Operation: contracts.OperationContext{IdempotencyKey: "store-canary"}}); err != nil {
		t.Fatal(err)
	}
	baseRunner := writingRunner(t, "")
	original := baseRunner.run
	baseRunner.run = func(ctx context.Context, args []string, stdout, stderr io.Writer) error {
		var source string
		for index, value := range args {
			if value == "--secret" && index+1 < len(args) {
				for _, part := range strings.Split(args[index+1], ",") {
					if strings.HasPrefix(part, "src=") {
						source = strings.TrimPrefix(part, "src=")
					}
				}
			}
		}
		value, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		_, _ = stdout.Write(value)
		return original(ctx, args, stdout, stderr)
	}
	provider, _, source := testProvider(t, baseRunner)
	provider.config.SecretResolver = resolver
	request := testRequest("real-secret", source)
	request.Plan.SecretRefs = []domain.SecretReference{reference}
	result, err := provider.Build(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%#v", result), string(canary)) {
		t.Fatal("build result leaked canary")
	}
	sink, ok := provider.config.LogSink.(*fakeBuildLogSink)
	if !ok || sink.content != "build output suppressed while secrets were mounted" || strings.Contains(sink.content, string(canary)) {
		t.Fatalf("secret-mounted build log was not suppressed: %#v", sink)
	}
	entries, err := os.ReadDir(materials)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("secret materials survived build: %#v", entries)
	}
	for _, scanRoot := range []string{vault, materials} {
		_ = filepath.WalkDir(scanRoot, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type().IsRegular() {
				value, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				if bytes.Contains(value, canary) {
					t.Fatalf("canary leaked to %s", path)
				}
			}
			return nil
		})
	}
	joined := strings.Join(baseRunner.calls[0], " ")
	if strings.Contains(joined, string(canary)) || !strings.Contains(joined, "id=canary,src=") {
		t.Fatalf("secret command boundary is unsafe: %s", joined)
	}
}

func mustBuild(provider *Provider, request contracts.BuildRequest, contexts ...context.Context) error {
	ctx := context.Background()
	if len(contexts) > 0 {
		ctx = contexts[0]
	}
	_, err := provider.Build(ctx, request)
	return err
}

func assertProviderCode(t *testing.T, err error, want contracts.ErrorCode) {
	t.Helper()
	var providerErr *contracts.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Code != want || providerErr.Details["evidence_ref"] == "" || providerErr.Details["log_ref"] == "" {
		t.Fatalf("want provider code %q with evidence refs, got %#v", want, err)
	}
}

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
