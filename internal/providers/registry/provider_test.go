package registry

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type runnerCall struct {
	command string
	args    []string
	env     []string
}

type fakeRunner struct {
	mu       sync.Mutex
	calls    []runnerCall
	output   string
	err      error
	readAuth bool
	auth     string
	config   string
}

type sequenceRunner struct {
	mu      sync.Mutex
	calls   []runnerCall
	outputs []string
	errors  []error
}

func (r *sequenceRunner) Run(_ context.Context, command string, args []string, _ io.Reader, env []string, stdout, _ io.Writer) error {
	r.mu.Lock()
	index := len(r.calls)
	r.calls = append(r.calls, runnerCall{command: command, args: append([]string(nil), args...), env: append([]string(nil), env...)})
	var output string
	var runErr error
	if index < len(r.outputs) {
		output = r.outputs[index]
	}
	if index < len(r.errors) {
		runErr = r.errors[index]
	}
	r.mu.Unlock()
	if output != "" {
		_, _ = io.WriteString(stdout, output)
	}
	return runErr
}

func (r *fakeRunner) Run(_ context.Context, command string, args []string, _ io.Reader, env []string, stdout, _ io.Writer) error {
	r.mu.Lock()
	r.calls = append(r.calls, runnerCall{command: command, args: append([]string(nil), args...), env: append([]string(nil), env...)})
	if len(args) >= 2 && args[0] == "--config" {
		r.config = args[1]
		if raw, err := os.ReadFile(filepath.Join(args[1], "config.json")); err == nil {
			r.auth = string(raw)
		}
	}
	r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	_, _ = io.WriteString(stdout, r.output)
	return nil
}

type fakeSecretResolver struct {
	contracts.ProviderMetadata
	material contracts.BuildSecretMaterial
	mu       sync.Mutex
	resolves int
	revokes  int
}

func (r *fakeSecretResolver) Metadata(context.Context) contracts.ProviderMetadata {
	return r.ProviderMetadata
}

func (r *fakeSecretResolver) ResolveBuildSecret(context.Context, domain.SecretReference, contracts.OperationContext) (contracts.BuildSecretMaterial, error) {
	r.mu.Lock()
	r.resolves++
	r.mu.Unlock()
	return r.material, nil
}

func (r *fakeSecretResolver) RevokeBuildSecret(context.Context, contracts.BuildSecretMaterial, contracts.OperationContext) error {
	r.mu.Lock()
	r.revokes++
	r.mu.Unlock()
	return nil
}

func newResolverTestProvider(t *testing.T, runner CommandRunner) *Provider {
	t.Helper()
	provider, err := New(Config{Runner: runner, OS: "linux", Architecture: "amd64", TempRoot: t.TempDir(), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func resolveRequest(key string) contracts.ImageResolveRequest {
	return contracts.ImageResolveRequest{Repository: "registry.example.test/open-card/web", Tag: "stable", Operation: contracts.OperationContext{IdempotencyKey: key}}
}

func TestResolvePublicManifestListPinsRequestedPlatform(t *testing.T) {
	t.Setenv("DOCKER_AUTH_CONFIG", `{"auths":{"registry.example.test":{"auth":"ambient-secret"}}}`)
	runner := &fakeRunner{output: `{"manifests":[{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":{"os":"linux","architecture":"arm64"}},{"digest":"` + testDigest + `","platform":{"os":"linux","architecture":"amd64"}}]}`}
	provider := newResolverTestProvider(t, runner)
	result, err := provider.Resolve(context.Background(), resolveRequest("public-platform"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Image.Digest != testDigest || result.Image.ResolvedTag != "stable" {
		t.Fatalf("unexpected immutable result: %#v", result.Image)
	}
	if result.Evidence.Digest == "" || !result.Evidence.Redacted || len(result.Evidence.Refs) != 1 {
		t.Fatalf("incomplete redacted evidence: %#v", result.Evidence)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.calls) != 1 || runner.calls[0].command != "docker" {
		t.Fatalf("unexpected Docker invocation: %#v", runner.calls)
	}
	if strings.Contains(strings.Join(runner.calls[0].args, " "), "stable-password") {
		t.Fatal("credential appeared in Docker arguments")
	}
	if strings.Contains(strings.Join(runner.calls[0].env, " "), "ambient-secret") || strings.Contains(strings.Join(runner.calls[0].env, " "), "DOCKER_AUTH_CONFIG") {
		t.Fatal("ambient Docker credential appeared in child environment")
	}
}

func TestResolvePrivateMaterialUsesEphemeralConfigAndRevokes(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "material")
	if err := os.WriteFile(secretPath, []byte("registry-user:canary-password"), 0o400); err != nil {
		t.Fatal(err)
	}
	secret := domain.SecretReference{ID: "secret_registry", Name: "registry", Provider: "filesystem-secret", Version: "v1"}
	resolver := &fakeSecretResolver{
		ProviderMetadata: contracts.ProviderMetadata{Name: "fake-secret", Version: "test", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilitySecretResolve)},
		material:         contracts.BuildSecretMaterial{MountID: "mount_test", Reference: secret, Path: secretPath, ExpiresAt: time.Now().Add(time.Minute)},
	}
	runner := &fakeRunner{output: `{"Descriptor":{"digest":"` + testDigest + `","platform":{"os":"linux","architecture":"amd64"}}}`}
	provider := newResolverTestProvider(t, runner)
	provider.config.SecretResolver = resolver
	request := resolveRequest("private-config")
	request.Secret = &secret
	result, err := provider.Resolve(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Image.Digest != testDigest {
		t.Fatalf("unexpected private result: %#v", result.Image)
	}
	resolver.mu.Lock()
	if resolver.resolves != 1 || resolver.revokes != 1 {
		t.Fatalf("secret material lifecycle mismatch: resolves=%d revokes=%d", resolver.resolves, resolver.revokes)
	}
	resolver.mu.Unlock()
	runner.mu.Lock()
	configDir := runner.config
	for _, call := range runner.calls {
		joined := strings.Join(call.args, " ") + "\x00" + strings.Join(call.env, " ")
		if strings.Contains(joined, "registry-user") || strings.Contains(joined, "canary-password") {
			t.Fatal("credential appeared in command arguments or environment")
		}
	}
	if !strings.Contains(runner.auth, base64.StdEncoding.EncodeToString([]byte("registry-user:canary-password"))) {
		t.Fatalf("temporary Docker config did not contain expected auth: %q", runner.auth)
	}
	runner.mu.Unlock()
	if _, err := os.Stat(configDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary Docker config was not removed: %q err=%v", configDir, err)
	}
}

func TestResolvePrivateMaterialSupportsDockerConfigAndNeverCopiesFullConfig(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "docker-config")
	secretJSON := `{"auths":{"private.example.test":{"username":"user","password":"pass"},"other.example.test":{"auth":"should-not-copy"}}}`
	if err := os.WriteFile(secretPath, []byte(secretJSON), 0o400); err != nil {
		t.Fatal(err)
	}
	secret := domain.SecretReference{ID: "secret_registry", Name: "registry", Provider: "filesystem-secret"}
	resolver := &fakeSecretResolver{
		ProviderMetadata: contracts.ProviderMetadata{Name: "fake-secret", Version: "test", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilitySecretResolve)},
		material:         contracts.BuildSecretMaterial{MountID: "mount_config", Reference: secret, Path: secretPath, ExpiresAt: time.Now().Add(time.Minute)},
	}
	runner := &fakeRunner{output: `{"Descriptor":{"digest":"` + testDigest + `","platform":{"os":"linux","architecture":"amd64"}}}`}
	provider := newResolverTestProvider(t, runner)
	provider.config.SecretResolver = resolver
	request := resolveRequest("private-docker-config")
	request.Repository = "private.example.test/open-card/web"
	request.Secret = &secret
	if _, err := provider.Resolve(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	if strings.Contains(runner.auth, "should-not-copy") || strings.Contains(runner.auth, "other.example.test") {
		t.Fatalf("full Docker config was copied into temp config: %q", runner.auth)
	}
	runner.mu.Unlock()
}

func TestResolveRejectsPlatformMismatchWithoutMutableResult(t *testing.T) {
	runner := &fakeRunner{output: `{"manifests":[{"digest":"` + testDigest + `","platform":{"os":"linux","architecture":"arm64"}}]}`}
	provider := newResolverTestProvider(t, runner)
	_, err := provider.Resolve(context.Background(), resolveRequest("platform-mismatch"))
	var providerErr *contracts.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Code != contracts.ErrConflict {
		t.Fatalf("expected platform conflict, got %v", err)
	}
}

func TestResolveIdempotencyAndConflict(t *testing.T) {
	runner := &fakeRunner{output: `{"Descriptor":{"digest":"` + testDigest + `","platform":{"os":"linux","architecture":"amd64"}}}`}
	provider := newResolverTestProvider(t, runner)
	first, err := provider.Resolve(context.Background(), resolveRequest("same-key"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.Resolve(context.Background(), resolveRequest("same-key"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Image != second.Image {
		t.Fatalf("idempotent retry changed result: %#v %#v", first.Image, second.Image)
	}
	conflict := resolveRequest("same-key")
	conflict.Tag = "other"
	_, err = provider.Resolve(context.Background(), conflict)
	var providerErr *contracts.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Code != contracts.ErrConflict {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
	runner.mu.Lock()
	if len(runner.calls) != 1 {
		t.Fatalf("idempotent retry executed Docker %d times", len(runner.calls))
	}
	runner.mu.Unlock()
}

func TestResolveFailureDoesNotLeakManifestOrCredential(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "material")
	if err := os.WriteFile(secretPath, []byte("user:super-secret-canary"), 0o400); err != nil {
		t.Fatal(err)
	}
	secret := domain.SecretReference{ID: "secret_registry", Name: "registry", Provider: "filesystem-secret"}
	resolver := &fakeSecretResolver{
		ProviderMetadata: contracts.ProviderMetadata{Name: "fake-secret", Version: "test", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilitySecretResolve)},
		material:         contracts.BuildSecretMaterial{MountID: "mount_fail", Reference: secret, Path: secretPath, ExpiresAt: time.Now().Add(time.Minute)},
	}
	runner := &fakeRunner{output: "not-json", err: errors.New("docker output included super-secret-canary")}
	provider := newResolverTestProvider(t, runner)
	provider.config.SecretResolver = resolver
	request := resolveRequest("failure-redaction")
	request.Secret = &secret
	_, err := provider.Resolve(context.Background(), request)
	if err == nil || strings.Contains(err.Error(), "super-secret-canary") || strings.Contains(err.Error(), "docker output") {
		t.Fatalf("provider error leaked sensitive command details: %v", err)
	}
	resolver.mu.Lock()
	if resolver.revokes != 1 {
		t.Fatalf("secret was not revoked on Docker failure: %d", resolver.revokes)
	}
	resolver.mu.Unlock()
}

func TestParseManifestDigestAcceptsSingleDescriptorWithoutPlatform(t *testing.T) {
	digest, err := parseManifestDigest([]byte(`{"Descriptor":{"digest":"`+testDigest+`"}}`), "linux", "amd64", "")
	if err != nil || digest != testDigest {
		t.Fatalf("single descriptor parsing failed: %q %v", digest, err)
	}
}

func TestParseManifestDigestAcceptsDockerVerboseArray(t *testing.T) {
	raw := `[{"Ref":"registry.example.test/open-card/web:stable","Descriptor":{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":{"os":"linux","architecture":"arm64"}}},{"Ref":"registry.example.test/open-card/web:stable","Descriptor":{"digest":"` + testDigest + `","platform":{"os":"linux","architecture":"amd64"}}}]`
	digest, err := parseManifestDigest([]byte(raw), "linux", "amd64", "")
	if err != nil || digest != testDigest {
		t.Fatalf("Docker verbose array parsing failed: %q %v", digest, err)
	}
}

func TestResolveAndPullUsesOnlyResolvedDigestAndVerifiesFacts(t *testing.T) {
	inspect := `{"RepoDigests":["registry.example.test/open-card/web@` + testDigest + `"],"Os":"linux","Architecture":"amd64"}`
	runner := &sequenceRunner{outputs: []string{
		`{"Descriptor":{"digest":"` + testDigest + `","platform":{"os":"linux","architecture":"amd64"}}}`,
		"pulled\n",
		inspect,
	}}
	provider := newResolverTestProvider(t, runner)
	result, err := provider.ResolveAndPull(context.Background(), resolveRequest("resolve-pull"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Image.Digest != testDigest || result.Image.ResolvedTag != "stable" {
		t.Fatalf("unexpected pulled image result: %#v", result.Image)
	}
	if result.Evidence.Refs[0].Kind != "registry.image.resolve_and_pull" || !strings.Contains(result.Evidence.Summary, "pulled") {
		t.Fatalf("pull evidence did not identify immutable pull: %#v", result.Evidence)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.calls) != 3 {
		t.Fatalf("resolve+pull made %d Docker calls, want 3", len(runner.calls))
	}
	manifestArgs := strings.Join(runner.calls[0].args, " ")
	pullArgs := strings.Join(runner.calls[1].args, " ")
	inspectArgs := strings.Join(runner.calls[2].args, " ")
	if !strings.Contains(manifestArgs, "registry.example.test/open-card/web:stable") {
		t.Fatalf("manifest resolve did not use requested tag: %q", manifestArgs)
	}
	if strings.Contains(pullArgs, ":stable") || !strings.Contains(pullArgs, "registry.example.test/open-card/web@"+testDigest) {
		t.Fatalf("pull was not digest-only: %q", pullArgs)
	}
	if strings.Contains(inspectArgs, ":stable") || !strings.Contains(inspectArgs, "registry.example.test/open-card/web@"+testDigest) {
		t.Fatalf("inspect was not digest-only: %q", inspectArgs)
	}
}

func TestResolveAndPullIdempotencyNamespaceDiffersFromResolve(t *testing.T) {
	inspect := `{"RepoDigests":["registry.example.test/open-card/web@` + testDigest + `"],"Os":"linux","Architecture":"amd64"}`
	runner := &sequenceRunner{outputs: []string{
		`{"Descriptor":{"digest":"` + testDigest + `","platform":{"os":"linux","architecture":"amd64"}}}`,
		`{"Descriptor":{"digest":"` + testDigest + `","platform":{"os":"linux","architecture":"amd64"}}}`,
		"pulled\n",
		inspect,
	}}
	provider := newResolverTestProvider(t, runner)
	request := resolveRequest("shared-operation-key")
	if _, err := provider.Resolve(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.ResolveAndPull(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.calls) != 4 {
		t.Fatalf("resolve and resolve+pull unexpectedly shared idempotency result: %d calls", len(runner.calls))
	}
}

func TestResolveAndPullRejectsRepoDigestMismatch(t *testing.T) {
	runner := &sequenceRunner{outputs: []string{
		`{"Descriptor":{"digest":"` + testDigest + `","platform":{"os":"linux","architecture":"amd64"}}}`,
		"pulled\n",
		`{"RepoDigests":["registry.example.test/open-card/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"Os":"linux","Architecture":"amd64"}`,
	}}
	provider := newResolverTestProvider(t, runner)
	_, err := provider.ResolveAndPull(context.Background(), resolveRequest("repo-digest-mismatch"))
	var providerErr *contracts.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Code != contracts.ErrConflict {
		t.Fatalf("expected RepoDigest conflict, got %v", err)
	}
}

func TestResolveAndPullPrivateCredentialsRevokeOnPullFailure(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "material")
	if err := os.WriteFile(secretPath, []byte("registry-user:canary-password"), 0o400); err != nil {
		t.Fatal(err)
	}
	secret := domain.SecretReference{ID: "secret_registry", Name: "registry", Provider: "filesystem-secret", Version: "v1"}
	resolver := &fakeSecretResolver{
		ProviderMetadata: contracts.ProviderMetadata{Name: "fake-secret", Version: "test", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilitySecretResolve)},
		material:         contracts.BuildSecretMaterial{MountID: "mount_pull_failure", Reference: secret, Path: secretPath, ExpiresAt: time.Now().Add(time.Minute)},
	}
	runner := &sequenceRunner{
		outputs: []string{`{"Descriptor":{"digest":"` + testDigest + `","platform":{"os":"linux","architecture":"amd64"}}}`},
		errors:  []error{nil, errors.New("pull failed with secret-like text")},
	}
	provider := newResolverTestProvider(t, runner)
	provider.config.SecretResolver = resolver
	request := resolveRequest("pull-secret-failure")
	request.Secret = &secret
	_, err := provider.ResolveAndPull(context.Background(), request)
	if err == nil || strings.Contains(err.Error(), "secret-like") || strings.Contains(err.Error(), "canary-password") {
		t.Fatalf("pull failure leaked sensitive details: %v", err)
	}
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if resolver.resolves != 1 || resolver.revokes != 1 {
		t.Fatalf("private pull material lifecycle mismatch: resolves=%d revokes=%d", resolver.resolves, resolver.revokes)
	}
}
