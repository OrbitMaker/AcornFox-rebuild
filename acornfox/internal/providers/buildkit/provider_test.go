package buildkit

import (
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

	"github.com/acornfox/acornfox/internal/acornfoxrelease"
	"github.com/acornfox/acornfox/internal/buildnetwork"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/foundation"
	"github.com/acornfox/acornfox/internal/importers/dockerfile"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type fakeRunner struct {
	mu    sync.Mutex
	calls [][]string
	run   func(context.Context, []string, io.Writer, io.Writer) error
}

type fakeWorkerPolicyAttestor struct {
	mu      sync.Mutex
	calls   []WorkerPolicyAttestationRequest
	receipt func(WorkerPolicyAttestationRequest) WorkerPolicyAttestationReceipt
	err     error
	events  *[]string
}

func (a *fakeWorkerPolicyAttestor) AttestWorkerPolicy(_ context.Context, request WorkerPolicyAttestationRequest) (WorkerPolicyAttestationReceipt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, request)
	if a.events != nil {
		*a.events = append(*a.events, "attest")
	}
	if a.err != nil {
		return WorkerPolicyAttestationReceipt{}, a.err
	}
	if a.receipt != nil {
		return a.receipt(request), nil
	}
	return WorkerPolicyAttestationReceipt{SchemaVersion: request.SchemaVersion, PolicyDigest: request.PolicyDigest, RequestFingerprint: request.RequestFingerprint}, nil
}

func (a *fakeWorkerPolicyAttestor) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.calls)
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
	if command != "buildctl" && command != "/opt/acornfox/current/bin/buildctl" {
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

func TestExecRunnerUsesMinimalChildEnvironment(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	command := filepath.Join(t.TempDir(), "buildctl-probe")
	if err := os.WriteFile(command, body, 0o700); err != nil {
		t.Fatal(err)
	}
	capture := filepath.Join(t.TempDir(), "environment")
	for key, value := range map[string]string{
		"HTTP_PROXY": "http://proxy.invalid", "HTTPS_PROXY": "https://proxy.invalid", "ALL_PROXY": "socks5://proxy.invalid", "NO_PROXY": "localhost",
		"REGISTRY_TOKEN": "registry-secret", "ALIBABA_CLOUD_ACCESS_KEY_ID": "aliyun-secret", "TENCENTCLOUD_SECRET_KEY": "tencent-secret", "VOLCENGINE_ACCESS_KEY": "volc-secret", "DATABASE_URL": "postgres://secret",
	} {
		t.Setenv(key, value)
	}
	if err := (execRunner{}).Run(context.Background(), command, []string{"-test.run=^TestExecRunnerEnvironmentHelper$", "--", "--acornfox-capture-env", capture}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	entries := strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
	if len(entries) != 6 || strings.Join(entries[:3], "\x00") != "PATH=/usr/bin:/bin\x00LANG=C\x00LC_ALL=C" || entries[5] != "BUILDKIT_NO_CLIENT_TOKEN=true" {
		t.Fatalf("buildctl child inherited ambient environment: %q", raw)
	}
	home := strings.TrimPrefix(entries[3], "HOME=")
	if !filepath.IsAbs(home) || !strings.HasPrefix(filepath.Base(home), "acornfox-buildctl-home-") || entries[4] != "DOCKER_CONFIG="+filepath.Join(home, ".docker") {
		t.Fatalf("buildctl home is not isolated: %q", entries)
	}
	if _, err := os.Stat(home); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temporary buildctl home was not removed")
	}
}

func TestExecRunnerEnvironmentHelper(t *testing.T) {
	for index, arg := range os.Args {
		if arg == "--acornfox-capture-env" && index+1 < len(os.Args) {
			home, err := os.Stat(os.Getenv("HOME"))
			if err != nil || !home.IsDir() || home.Mode().Perm() != 0700 {
				t.Fatal("child home is not a private directory")
			}
			if err := os.WriteFile(os.Args[index+1], []byte(strings.Join(os.Environ(), "\x00")+"\x00"), 0o600); err != nil {
				t.Fatal(err)
			}
			os.Exit(0)
		}
	}
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

type countingCapacity struct {
	fakeCapacity
	activations int
	events      *[]string
}

func (c *countingCapacity) Activate(context.Context, contracts.CapacityLease, contracts.OperationContext) error {
	c.activations++
	if c.events != nil {
		*c.events = append(*c.events, "capacity")
	}
	return nil
}

type countingSecretResolver struct {
	fakeSecretResolver
	calls int
}

func (c *countingSecretResolver) ResolveBuildSecret(ctx context.Context, reference domain.SecretReference, operation contracts.OperationContext) (contracts.BuildSecretMaterial, error) {
	c.calls++
	return c.fakeSecretResolver.ResolveBuildSecret(ctx, reference, operation)
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

func controlledRequest(t *testing.T, key string, source domain.SourceRevision, policyDigest string) contracts.BuildRequest {
	t.Helper()
	request := testRequest(key, source)
	bindAcornFoxDigests(t, &request)
	request.Network = contracts.NetworkPolicy{Mode: contracts.NetworkModeControlledEgressV1, WorkerPolicyDigest: policyDigest}
	request.Plan.AcornFoxNetworkMode = string(request.Network.Mode)
	request.Plan.AcornFoxWorkerPolicyDigest = request.Network.WorkerPolicyDigest
	return request
}

func controlledEgressRaw(t *testing.T) ([]byte, []byte) {
	t.Helper()
	inputs, err := os.ReadFile(filepath.Join("..", "..", "..", "release", "acornfox-product-build-inputs-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := os.ReadFile(filepath.Join("..", "..", "..", "release", "acornfox-controlled-egress-policy-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	return inputs, policy
}

func controlledEgressDigest(t *testing.T) string {
	t.Helper()
	inputsRaw, policyRaw := controlledEgressRaw(t)
	inputs, _, err := acornfoxrelease.ParseProductBuildInputsV1(inputsRaw, policyRaw)
	if err != nil {
		t.Fatal(err)
	}
	return inputs.ControlledEgressPolicySHA
}

func configuredControlledProvider(t *testing.T, provider *Provider, attestor WorkerPolicyAttestor) *Provider {
	t.Helper()
	inputs, policy := controlledEgressRaw(t)
	config := provider.config
	config.ControlledEgressInputsRaw = inputs
	config.ControlledEgressPolicyRaw = policy
	config.WorkerPolicyAttestor = attestor
	configured, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return configured
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

func TestControlledEgressIsUnavailableBeforeAnyDownstreamEffect(t *testing.T) {
	const policyDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	runner := writingRunner(t, "")
	provider, root, source := testProvider(t, runner)
	logs := &fakeBuildLogSink{ref: "memory://build-log/controlled"}
	store := &countingImageStore{ImageStore: contracts.NewFakeImageStore(true)}
	capacity := &countingCapacity{}
	secrets := &countingSecretResolver{fakeSecretResolver: fakeSecretResolver{root: filepath.Join(root, "counted-secrets")}}
	if err := os.Mkdir(secrets.root, 0o700); err != nil {
		t.Fatal(err)
	}
	provider.config.LogSink = logs
	provider.config.ImageStore = store
	provider.config.Capacity = capacity
	provider.config.SecretResolver = secrets

	request := testRequest("controlled-unavailable", source)
	bindAcornFoxDigests(t, &request)
	request.Network = contracts.NetworkPolicy{Mode: contracts.NetworkModeControlledEgressV1, WorkerPolicyDigest: policyDigest}
	request.Plan.AcornFoxNetworkMode = string(request.Network.Mode)
	request.Plan.AcornFoxWorkerPolicyDigest = request.Network.WorkerPolicyDigest
	request.Source.WorkspaceRef = filepath.Join(root, "must-not-evaluate")
	assertProviderCode(t, mustBuild(provider, request), contracts.ErrForbidden)
	if runner.callCount() != 0 || logs.callCount() != 0 || store.callCount() != 0 || capacity.activations != 0 || secrets.calls != 0 {
		t.Fatalf("controlled-egress rejection had downstream effects: runner=%d logs=%d store=%d capacity=%d secrets=%d", runner.callCount(), logs.callCount(), store.callCount(), capacity.activations, secrets.calls)
	}

	nested := testRequest("controlled-nested-exceptions", source)
	nested.Network = contracts.NetworkPolicy{Mode: contracts.NetworkModeControlledEgressV1, WorkerPolicyDigest: policyDigest, AllowedCIDRs: []string{"10.0.0.0/8"}, AllowMetadata: true}
	assertProviderCode(t, mustBuild(provider, nested), contracts.ErrForbidden)

	bound := testRequest("controlled-acornfox-bound", source)
	bindAcornFoxDigests(t, &bound)
	bound.Network = contracts.NetworkPolicy{Mode: contracts.NetworkModeControlledEgressV1, WorkerPolicyDigest: policyDigest}
	bound.Plan.AcornFoxNetworkMode = string(bound.Network.Mode)
	bound.Plan.AcornFoxWorkerPolicyDigest = bound.Network.WorkerPolicyDigest
	assertProviderCode(t, mustBuild(provider, bound), contracts.ErrForbidden)

	mismatchedMode := bound
	mismatchedMode.Operation.IdempotencyKey = "controlled-plan-offline-request"
	mismatchedMode.Network = contracts.NetworkPolicy{Mode: contracts.NetworkModeOffline}
	assertProviderCode(t, mustBuild(provider, mismatchedMode), contracts.ErrForbidden)
	mismatchedDigest := bound
	mismatchedDigest.Operation.IdempotencyKey = "controlled-plan-other-digest"
	mismatchedDigest.Network.WorkerPolicyDigest = "sha256:" + strings.Repeat("e", 64)
	assertProviderCode(t, mustBuild(provider, mismatchedDigest), contracts.ErrForbidden)

	static := testRequest("controlled-static", source)
	static.Plan.Kind = domain.BuildStatic
	static.Plan.DockerfilePath = ""
	static.Plan.StaticRuntimeDigest = testDigest
	static.Network = contracts.NetworkPolicy{Mode: contracts.NetworkModeControlledEgressV1, WorkerPolicyDigest: policyDigest}
	assertProviderCode(t, mustBuild(provider, static), contracts.ErrForbidden)
	if runner.callCount() != 0 || logs.callCount() != 0 || store.callCount() != 0 || capacity.activations != 0 || secrets.calls != 0 {
		t.Fatal("legacy, AcornFox-bound, static, or nested controlled requests had downstream effects")
	}
}

func TestControlledEgressChangesFingerprintWithoutExecuting(t *testing.T) {
	const policyDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	runner := writingRunner(t, "")
	provider, _, source := testProvider(t, runner)
	offline := testRequest("network-fingerprint", source)
	controlled := offline
	controlled.Network = contracts.NetworkPolicy{Mode: contracts.NetworkModeControlledEgressV1, WorkerPolicyDigest: policyDigest}
	bindAcornFoxDigests(t, &controlled)
	controlled.Plan.AcornFoxNetworkMode = string(controlled.Network.Mode)
	controlled.Plan.AcornFoxWorkerPolicyDigest = controlled.Network.WorkerPolicyDigest
	differentPolicy := controlled
	differentPolicy.Network.WorkerPolicyDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if requestFingerprint(offline) == requestFingerprint(controlled) || requestFingerprint(controlled) == requestFingerprint(differentPolicy) {
		t.Fatal("network mode or worker policy digest was omitted from idempotency fingerprint")
	}
	assertProviderCode(t, mustBuild(provider, controlled), contracts.ErrForbidden)
	assertProviderCode(t, mustBuild(provider, differentPolicy), contracts.ErrForbidden)
	if runner.callCount() != 0 {
		t.Fatalf("controlled egress executed despite dormant contract: %d", runner.callCount())
	}
}

func TestControlledEgressAdmitsOnlyExactAttestedAcornFoxBuild(t *testing.T) {
	policyDigest := controlledEgressDigest(t)
	runner := writingRunner(t, "controlled build output\n")
	provider, root, source := testProvider(t, runner)
	events := []string{}
	attestor := &fakeWorkerPolicyAttestor{events: &events}
	capacity := &countingCapacity{events: &events}
	provider.config.Capacity = capacity
	provider = configuredControlledProvider(t, provider, attestor)
	request := controlledRequest(t, "controlled-success", source, policyDigest)
	result, err := provider.Build(context.Background(), request)
	if err != nil || result.Artifact == nil || attestor.callCount() != 1 || runner.callCount() != 1 || capacity.activations != 1 {
		t.Fatalf("controlled build was not admitted exactly once: result=%#v err=%v attests=%d runs=%d capacity=%d", result, err, attestor.callCount(), runner.callCount(), capacity.activations)
	}
	if len(events) < 2 || events[0] != "attest" || events[1] != "capacity" {
		t.Fatalf("attestation was not before build effects: %#v", events)
	}
	args := strings.Join(runner.calls[0], " ")
	if !strings.Contains(args, "--opt network=none") || strings.Contains(args, "network=default") {
		t.Fatalf("source-specific download policy allowed networked RUN steps: %s", args)
	}
	for _, forbidden := range []string{"--allow", "network.host", "security.insecure", "--ssh", "--add-host", "proxy"} {
		if strings.Contains(args, forbidden) {
			t.Fatalf("controlled build expanded authority with %q: %s", forbidden, args)
		}
	}
	again, err := provider.Build(context.Background(), request)
	if err != nil || again.Build.ID != result.Build.ID || attestor.callCount() != 1 || runner.callCount() != 1 {
		t.Fatalf("successful controlled replay did not use cached result: result=%#v err=%v attests=%d runs=%d", again, err, attestor.callCount(), runner.callCount())
	}

	differentDigest := request
	differentDigest.Network.WorkerPolicyDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	differentDigest.Plan.AcornFoxWorkerPolicyDigest = differentDigest.Network.WorkerPolicyDigest
	assertProviderCode(t, mustBuild(provider, differentDigest), contracts.ErrForbidden)
	if attestor.callCount() != 1 || runner.callCount() != 1 {
		t.Fatalf("different controlled policy digest repeated an admitted build: attests=%d runs=%d", attestor.callCount(), runner.callCount())
	}
	if entries, err := os.ReadDir(filepath.Join(root, "work")); err != nil || len(entries) != 0 {
		t.Fatalf("controlled build did not clean its workspace: entries=%#v err=%v", entries, err)
	}
}

func TestProductionExecutionPolicyAllowsNetworkedRUNThroughAttestedWorker(t *testing.T) {
	runner := writingRunner(t, "production controlled output\n")
	provider, _, source := testProvider(t, runner)
	config := provider.config
	config.ProductionNetworkPolicyRaw = buildnetwork.CanonicalPolicy()
	attestor := &fakeWorkerPolicyAttestor{}
	config.WorkerPolicyAttestor = attestor
	config.Address = "unix:///run/acornfox-buildkit/buildkitd.sock"
	config.Command = "/opt/acornfox/current/bin/buildctl"
	for name, change := range map[string]func(*Config){
		"legacy socket":     func(c *Config) { c.Address = "unix:///run/open-card-buildkit/buildkitd.sock" },
		"default socket":    func(c *Config) { c.Address = "" },
		"different command": func(c *Config) { c.Command = "/tmp/buildctl" },
		"path command":      func(c *Config) { c.Command = "" },
	} {
		t.Run(name, func(t *testing.T) {
			mismatch := config
			change(&mismatch)
			if _, err := New(mismatch); err == nil {
				t.Fatal("production builder differing from attested identity accepted")
			}
		})
	}
	native := config
	native.Command = "/opt/acornfox/current/embedded/bin/buildctl"
	if _, err := New(native); err != nil {
		t.Fatalf("fixed Native embedded buildctl rejected: %v", err)
	}
	provider, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := buildnetwork.ParsePolicy(buildnetwork.CanonicalPolicy())
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Build(context.Background(), controlledRequest(t, "installed-network", source, digest))
	if err != nil || result.Artifact == nil || attestor.callCount() != 1 {
		t.Fatal(result, err)
	}
	if !strings.Contains(strings.Join(runner.calls[0], " "), "--opt network=default") {
		t.Fatal("installed build-execution policy was not selected")
	}
	config.ControlledEgressInputsRaw = []byte("{}")
	config.ControlledEgressPolicyRaw = []byte("{}")
	if _, err := New(config); err == nil {
		t.Fatal("mixed self-build and production authority accepted")
	}
}

func TestControlledEgressConfigAndOfflineBuildStayBounded(t *testing.T) {
	runner := writingRunner(t, "")
	provider, _, source := testProvider(t, runner)
	base := provider.config
	inputs, policy := controlledEgressRaw(t)
	for name, configure := range map[string]func(*Config){
		"inputs without attestor": func(c *Config) { c.ControlledEgressInputsRaw, c.ControlledEgressPolicyRaw = inputs, policy },
		"attestor without digest": func(c *Config) { c.WorkerPolicyAttestor = &fakeWorkerPolicyAttestor{} },
		"malformed P0 inputs": func(c *Config) {
			c.ControlledEgressInputsRaw, c.ControlledEgressPolicyRaw, c.WorkerPolicyAttestor = []byte("{}\n"), policy, &fakeWorkerPolicyAttestor{}
		},
		"drifted P0 policy": func(c *Config) {
			c.ControlledEgressInputsRaw, c.ControlledEgressPolicyRaw, c.WorkerPolicyAttestor = inputs, append(append([]byte(nil), policy[:len(policy)-1]...), ' '), &fakeWorkerPolicyAttestor{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			configure(&config)
			if _, err := New(config); err == nil {
				t.Fatal("invalid controlled-egress configuration was accepted")
			}
		})
	}
	attestor := &fakeWorkerPolicyAttestor{}
	provider = configuredControlledProvider(t, provider, attestor)
	if _, err := provider.Build(context.Background(), testRequest("offline-with-attestor", source)); err != nil {
		t.Fatal(err)
	}
	if attestor.callCount() != 0 || runner.callCount() != 1 || !strings.Contains(strings.Join(runner.calls[0], " "), "--opt network=none") {
		t.Fatalf("offline build changed under configured controlled authority: attests=%d calls=%d args=%#v", attestor.callCount(), runner.callCount(), runner.calls)
	}
}

func TestControlledEgressFailsClosedBeforeBuildPreparation(t *testing.T) {
	policyDigest := controlledEgressDigest(t)
	tests := []struct {
		name      string
		configure func(*testing.T, *Provider, *fakeWorkerPolicyAttestor) *Provider
		mutate    func(*contracts.BuildRequest)
		want      contracts.ErrorCode
	}{
		{"missing authority", func(_ *testing.T, p *Provider, _ *fakeWorkerPolicyAttestor) *Provider { return p }, func(_ *contracts.BuildRequest) {}, contracts.ErrForbidden},
		{"configured digest mismatch", func(t *testing.T, p *Provider, a *fakeWorkerPolicyAttestor) *Provider {
			return configuredControlledProvider(t, p, a)
		}, func(r *contracts.BuildRequest) {
			r.Network.WorkerPolicyDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			r.Plan.AcornFoxWorkerPolicyDigest = r.Network.WorkerPolicyDigest
		}, contracts.ErrForbidden},
		{"plan digest mismatch", func(t *testing.T, p *Provider, a *fakeWorkerPolicyAttestor) *Provider {
			return configuredControlledProvider(t, p, a)
		}, func(r *contracts.BuildRequest) {
			r.Plan.AcornFoxWorkerPolicyDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}, contracts.ErrForbidden},
		{"attestor error", func(t *testing.T, p *Provider, a *fakeWorkerPolicyAttestor) *Provider {
			a.err = errors.New("private attestor failure")
			return configuredControlledProvider(t, p, a)
		}, func(_ *contracts.BuildRequest) {}, contracts.ErrUnavailable},
		{"malformed receipt", func(t *testing.T, p *Provider, a *fakeWorkerPolicyAttestor) *Provider {
			a.receipt = func(WorkerPolicyAttestationRequest) WorkerPolicyAttestationReceipt {
				return WorkerPolicyAttestationReceipt{}
			}
			return configuredControlledProvider(t, p, a)
		}, func(_ *contracts.BuildRequest) {}, contracts.ErrForbidden},
		{"receipt digest drift", func(t *testing.T, p *Provider, a *fakeWorkerPolicyAttestor) *Provider {
			a.receipt = func(r WorkerPolicyAttestationRequest) WorkerPolicyAttestationReceipt {
				return WorkerPolicyAttestationReceipt{SchemaVersion: 1, PolicyDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", RequestFingerprint: r.RequestFingerprint}
			}
			return configuredControlledProvider(t, p, a)
		}, func(_ *contracts.BuildRequest) {}, contracts.ErrForbidden},
		{"receipt fingerprint drift", func(t *testing.T, p *Provider, a *fakeWorkerPolicyAttestor) *Provider {
			a.receipt = func(r WorkerPolicyAttestationRequest) WorkerPolicyAttestationReceipt {
				return WorkerPolicyAttestationReceipt{SchemaVersion: 1, PolicyDigest: r.PolicyDigest, RequestFingerprint: "other"}
			}
			return configuredControlledProvider(t, p, a)
		}, func(_ *contracts.BuildRequest) {}, contracts.ErrForbidden},
		{"static plan", func(t *testing.T, p *Provider, a *fakeWorkerPolicyAttestor) *Provider {
			return configuredControlledProvider(t, p, a)
		}, func(r *contracts.BuildRequest) {
			r.Plan.Kind = domain.BuildStatic
			r.Plan.DockerfilePath = ""
			r.Plan.StaticRuntimeDigest = testDigest
			r.Plan.AcornFoxDefinitionDigest = ""
			r.Plan.AcornFoxDockerfileDigest = ""
			r.Plan.AcornFoxNetworkMode = ""
			r.Plan.AcornFoxWorkerPolicyDigest = ""
		}, contracts.ErrForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := writingRunner(t, "")
			provider, root, source := testProvider(t, runner)
			logs := &fakeBuildLogSink{ref: "memory://build-log/controlled"}
			store := &countingImageStore{ImageStore: contracts.NewFakeImageStore(true)}
			capacity := &countingCapacity{}
			secrets := &countingSecretResolver{fakeSecretResolver: fakeSecretResolver{root: filepath.Join(root, "counted-secrets")}}
			if err := os.Mkdir(secrets.root, 0o700); err != nil {
				t.Fatal(err)
			}
			provider.config.LogSink, provider.config.ImageStore, provider.config.Capacity, provider.config.SecretResolver = logs, store, capacity, secrets
			attestor := &fakeWorkerPolicyAttestor{}
			provider = tc.configure(t, provider, attestor)
			request := controlledRequest(t, "controlled-reject-"+strings.ReplaceAll(tc.name, " ", "-"), source, policyDigest)
			tc.mutate(&request)
			err := mustBuild(provider, request)
			assertProviderCode(t, err, tc.want)
			if strings.Contains(fmt.Sprint(err), "private attestor failure") {
				t.Fatal("attestor details leaked")
			}
			if runner.callCount() != 0 || logs.callCount() != 0 || store.callCount() != 0 || capacity.activations != 0 || secrets.calls != 0 {
				t.Fatalf("controlled rejection had downstream effects: runner=%d logs=%d store=%d capacity=%d secrets=%d", runner.callCount(), logs.callCount(), store.callCount(), capacity.activations, secrets.calls)
			}
		})
	}
}

func TestControlledEgressAttestsBeforeSourcePreparationAndPreservesFailures(t *testing.T) {
	policyDigest := controlledEgressDigest(t)
	t.Run("attests before source preparation", func(t *testing.T) {
		runner := writingRunner(t, "")
		provider, _, source := testProvider(t, runner)
		attestor := &fakeWorkerPolicyAttestor{}
		provider = configuredControlledProvider(t, provider, attestor)
		request := controlledRequest(t, "controlled-source-drift", source, policyDigest)
		request.Source.ContentDigest = "sha256:" + strings.Repeat("b", 64)
		request.Plan.SourceDigest = request.Source.ContentDigest
		assertProviderCode(t, mustBuild(provider, request), contracts.ErrValidation)
		if attestor.callCount() != 1 || runner.callCount() != 0 {
			t.Fatalf("source preparation ran before attestation or invoked runner: attests=%d runs=%d", attestor.callCount(), runner.callCount())
		}
	})
	t.Run("durable log failure prevents OCI", func(t *testing.T) {
		runner := writingRunner(t, "")
		provider, _, source := testProvider(t, runner)
		attestor := &fakeWorkerPolicyAttestor{}
		provider = configuredControlledProvider(t, provider, attestor)
		logs := &fakeBuildLogSink{err: errors.New("durable log unavailable")}
		store := &countingImageStore{ImageStore: contracts.NewFakeImageStore(true)}
		provider.config.LogSink, provider.config.ImageStore = logs, store
		assertProviderCode(t, mustBuild(provider, controlledRequest(t, "controlled-log-failure", source, policyDigest)), contracts.ErrUnavailable)
		if attestor.callCount() != 1 || logs.callCount() != 1 || store.callCount() != 0 {
			t.Fatalf("controlled log failure changed OCI semantics: attests=%d logs=%d oci=%d", attestor.callCount(), logs.callCount(), store.callCount())
		}
	})
	t.Run("OCI failure retains durable log", func(t *testing.T) {
		runner := writingRunner(t, "")
		provider, _, source := testProvider(t, runner)
		attestor := &fakeWorkerPolicyAttestor{}
		provider = configuredControlledProvider(t, provider, attestor)
		logs := &fakeBuildLogSink{ref: "memory://build-log/controlled-retained"}
		store := &countingImageStore{ImageStore: contracts.NewFakeImageStore(true), err: errors.New("OCI store unavailable")}
		provider.config.LogSink, provider.config.ImageStore = logs, store
		result, err := provider.Build(context.Background(), controlledRequest(t, "controlled-oci-failure", source, policyDigest))
		assertProviderCode(t, err, contracts.ErrUnavailable)
		var providerErr *contracts.ProviderError
		if result.Artifact != nil || attestor.callCount() != 1 || logs.callCount() != 1 || store.callCount() != 1 || !errors.As(err, &providerErr) || providerErr.Details["log_ref"] != logs.ref {
			t.Fatalf("controlled OCI failure lost durable log truth: result=%#v err=%#v attests=%d logs=%d oci=%d", result, err, attestor.callCount(), logs.callCount(), store.callCount())
		}
	})
	t.Run("cancelled request does not attest", func(t *testing.T) {
		runner := writingRunner(t, "")
		provider, _, source := testProvider(t, runner)
		attestor := &fakeWorkerPolicyAttestor{}
		provider = configuredControlledProvider(t, provider, attestor)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		assertProviderCode(t, mustBuild(provider, controlledRequest(t, "controlled-cancelled", source, policyDigest), ctx), contracts.ErrCancelled)
		if attestor.callCount() != 0 || runner.callCount() != 0 {
			t.Fatalf("cancelled controlled request had effects: attests=%d runs=%d", attestor.callCount(), runner.callCount())
		}
	})
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
