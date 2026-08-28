// Package registry resolves registry tags to immutable OCI manifest digests.
//
// The provider owns registry resolution and an optional digest-pinned Docker
// pull, but is not an ImageStore: callers still persist the returned digest
// through the ImageStore boundary before they can deploy it.  Registry
// credentials are materialized only for one operation and are never passed as
// command arguments or environment variables.
package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const (
	providerName    = "docker-registry-resolver"
	providerVersion = "m2"
	defaultCommand  = "docker"
	defaultTimeout  = 2 * time.Minute
	maxManifestSize = 16 << 20
	maxSecretSize   = 1 << 20
)

var (
	errInvalidRegistry = errors.New("registry input is invalid")
	errPlatformMissing = errors.New("registry manifest has no compatible platform")
	errCredential      = errors.New("registry credential material is invalid")
)

// CommandRunner is the only external command boundary.  stdin is included so
// future login implementations can use a pipe without putting credentials in
// argv or the environment.  Resolve currently writes a temporary Docker
// config and therefore passes a nil stdin to manifest inspect.
type CommandRunner interface {
	Run(ctx context.Context, command string, args []string, stdin io.Reader, env []string, stdout, stderr io.Writer) error
}

// Runner is a concise compatibility alias for callers that name the
// dependency simply as a runner.
type Runner = CommandRunner

type execRunner struct{}

func (execRunner) Run(ctx context.Context, command string, args []string, stdin io.Reader, env []string, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	// A nil env means inherit the process environment.  We never use that
	// path for credentials; callers can inject an explicit sanitized env.
	if env != nil {
		cmd.Env = append([]string(nil), env...)
	}
	return cmd.Run()
}

// Config configures the provider-owned Docker command boundary.  OS and
// Architecture default to the current Go target so a manifest list cannot be
// silently resolved to an incompatible image.
type Config struct {
	Command        string
	Runner         CommandRunner
	SecretResolver contracts.BuildSecretResolver
	TempRoot       string
	Timeout        time.Duration
	Clock          func() time.Time
	OS             string
	Architecture   string
	Variant        string
	// PlatformOS and PlatformArchitecture are accepted as explicit aliases
	// for composition roots that use platform-prefixed configuration names.
	PlatformOS           string
	PlatformArchitecture string
}

func (c Config) normalized() (Config, error) {
	if strings.TrimSpace(c.Command) == "" {
		c.Command = defaultCommand
	}
	if c.Runner == nil {
		c.Runner = execRunner{}
	}
	if c.Timeout == 0 {
		c.Timeout = defaultTimeout
	}
	if c.Timeout <= 0 {
		return Config{}, errors.New("registry timeout must be positive")
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	if c.OS == "" {
		c.OS = c.PlatformOS
	}
	if c.Architecture == "" {
		c.Architecture = c.PlatformArchitecture
	}
	if c.OS == "" {
		c.OS = runtime.GOOS
	}
	if c.Architecture == "" {
		c.Architecture = runtime.GOARCH
	}
	c.OS = normalizeOS(c.OS)
	c.Architecture = normalizeArch(c.Architecture)
	if !safePlatformPart(c.OS) || !safePlatformPart(c.Architecture) || (c.Variant != "" && !safePlatformPart(c.Variant)) {
		return Config{}, errors.New("registry platform is invalid")
	}
	if c.TempRoot != "" {
		root, err := filepath.Abs(c.TempRoot)
		if err != nil {
			return Config{}, errors.New("registry temp root is invalid")
		}
		if info, err := os.Lstat(root); err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return Config{}, errors.New("registry temp root must be a directory")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return Config{}, errors.New("registry temp root is unavailable")
		}
		c.TempRoot = root
	}
	return c, nil
}

// Provider implements immutable tag resolution and digest-pinned Docker pull
// verification.  It does not own persistent image retention or deletion.
type Provider struct {
	config   Config
	metadata contracts.ProviderMetadata

	mu         sync.Mutex
	operations map[string]*operationRecord
}

type operationRecord struct {
	fingerprint string
	done        chan struct{}
	result      contracts.ImageResolveResult
	err         error
}

// New constructs a fail-closed resolver.  No command or filesystem mutation
// happens until Resolve is called.
func New(config Config) (*Provider, error) {
	config, err := config.normalized()
	if err != nil {
		return nil, err
	}
	return &Provider{
		config: config,
		metadata: contracts.ProviderMetadata{
			Name:            providerName,
			Version:         providerVersion,
			ContractVersion: contracts.ContractAPIVersion,
			Capabilities:    contracts.NewCapabilitySet(contracts.CapabilityImageResolve, contracts.CapabilityImagePull),
			SensitiveInputs: []string{"registry secret reference", "registry credential material"},
		},
		operations: make(map[string]*operationRecord),
	}, nil
}

var _ contracts.RegistryImageProvider = (*Provider)(nil)

// NewProvider is an explicit composition-root alias.
func NewProvider(config Config) (*Provider, error) { return New(config) }

func (p *Provider) Metadata(context.Context) contracts.ProviderMetadata { return p.metadata }

// Resolve inspects repository:tag with Docker's verbose manifest output and
// returns a platform-compatible manifest digest.  The returned ImageDigest
// retains the requested tag only as provenance; downstream runtime/build
// boundaries must use Image.Digest and never reconstruct repository:tag.
func (p *Provider) Resolve(ctx context.Context, request contracts.ImageResolveRequest) (contracts.ImageResolveResult, error) {
	fingerprint, err := requestFingerprint(request, p.config)
	if err != nil {
		return contracts.ImageResolveResult{}, p.failure(request.Operation, contracts.ErrValidation, "resolve", err.Error(), err)
	}
	if err := p.check(ctx, request.Operation); err != nil {
		return contracts.ImageResolveResult{}, err
	}
	key := request.Operation.IdempotencyKey
	record, leader, err := p.begin(key, fingerprint)
	if err != nil {
		return contracts.ImageResolveResult{}, p.failure(request.Operation, contracts.ErrConflict, "resolve", err.Error(), nil)
	}
	if !leader {
		if err := waitRecord(ctx, request.Operation, record); err != nil {
			return contracts.ImageResolveResult{}, p.classify(request.Operation, err)
		}
		return cloneResult(record.result), record.err
	}

	result, opErr := p.resolve(ctx, request)
	p.finish(record, result, opErr)
	return cloneResult(result), opErr
}

func (p *Provider) resolve(ctx context.Context, request contracts.ImageResolveRequest) (contracts.ImageResolveResult, error) {
	ctx, cancel := operationContext(ctx, request.Operation, p.config.Timeout)
	defer cancel()
	session, err := p.prepareSession(ctx, request, "resolve")
	if err != nil {
		return contracts.ImageResolveResult{}, err
	}
	defer session.Close()
	image, err := p.resolveManifest(ctx, request, session.Directory, "resolve")
	if err != nil {
		return contracts.ImageResolveResult{}, err
	}
	return p.resultFor(request, image, "resolve", "registry tag resolved to an immutable platform digest"), nil
}

// ResolveAndPull resolves a mutable tag once, then pulls and verifies only
// repository@sha256:digest.  The operation is idempotent in a separate
// namespace from Resolve, so reusing a key cannot replay a resolve-only
// result as a successful pull.
func (p *Provider) ResolveAndPull(ctx context.Context, request contracts.ImageResolveRequest) (contracts.ImageResolveResult, error) {
	fingerprint, err := requestFingerprint(request, p.config)
	if err != nil {
		return contracts.ImageResolveResult{}, p.failure(request.Operation, contracts.ErrValidation, "resolve_and_pull", err.Error(), err)
	}
	if err := p.check(ctx, request.Operation); err != nil {
		return contracts.ImageResolveResult{}, err
	}
	key := "resolve_and_pull\x00" + request.Operation.IdempotencyKey
	record, leader, err := p.begin(key, digestString("resolve_and_pull", fingerprint))
	if err != nil {
		return contracts.ImageResolveResult{}, p.failure(request.Operation, contracts.ErrConflict, "resolve_and_pull", err.Error(), nil)
	}
	if !leader {
		if err := waitRecord(ctx, request.Operation, record); err != nil {
			return contracts.ImageResolveResult{}, p.classifyAction(request.Operation, "resolve_and_pull", err)
		}
		return cloneResult(record.result), record.err
	}

	result, opErr := p.resolveAndPull(ctx, request)
	p.finish(record, result, opErr)
	return cloneResult(result), opErr
}

func (p *Provider) resolveAndPull(ctx context.Context, request contracts.ImageResolveRequest) (contracts.ImageResolveResult, error) {
	ctx, cancel := operationContext(ctx, request.Operation, p.config.Timeout)
	defer cancel()
	session, err := p.prepareSession(ctx, request, "resolve_and_pull")
	if err != nil {
		return contracts.ImageResolveResult{}, err
	}
	defer session.Close()
	image, err := p.resolveManifest(ctx, request, session.Directory, "resolve_and_pull")
	if err != nil {
		return contracts.ImageResolveResult{}, err
	}
	if err := p.pullDigest(ctx, session.Directory, image, request.Operation); err != nil {
		return contracts.ImageResolveResult{}, err
	}
	if err := p.verifyPulledImage(ctx, session.Directory, image, request.Operation); err != nil {
		return contracts.ImageResolveResult{}, err
	}
	return p.resultFor(request, image, "resolve_and_pull", "registry tag resolved and pulled by immutable platform digest"), nil
}

type resolveSession struct {
	Directory string
	resolver  contracts.BuildSecretResolver
	material  *contracts.BuildSecretMaterial
	operation contracts.OperationContext
}

func (s *resolveSession) Close() {
	if s == nil {
		return
	}
	if s.material != nil && s.resolver != nil {
		revokeOperation := s.operation
		// Cleanup must not inherit an expired request deadline.  Preserve the
		// idempotency key so a filesystem SecretProvider can drop its resolve
		// record, but make revocation itself unconditional on cancellation.
		revokeOperation.Deadline = time.Time{}
		_ = s.resolver.RevokeBuildSecret(context.Background(), *s.material, revokeOperation)
	}
	if s.Directory != "" {
		_ = os.RemoveAll(s.Directory)
	}
}

func (p *Provider) prepareSession(ctx context.Context, request contracts.ImageResolveRequest, action string) (resolveSession, error) {
	tempDir, err := os.MkdirTemp(p.config.TempRoot, "open-card-registry-")
	if err != nil {
		return resolveSession{}, p.failure(request.Operation, contracts.ErrUnavailable, action, "registry temporary config could not be created", nil)
	}
	secretOperation := request.Operation
	secretOperation.IdempotencyKey = action + "\x00" + request.Operation.IdempotencyKey
	session := resolveSession{Directory: tempDir, operation: secretOperation}
	fail := func(providerErr error) (resolveSession, error) {
		session.Close()
		return resolveSession{}, providerErr
	}
	if err := os.Chmod(tempDir, 0o700); err != nil {
		return fail(p.failure(request.Operation, contracts.ErrUnavailable, action, "registry temporary config could not be secured", nil))
	}
	if request.Secret == nil {
		return session, nil
	}
	if p.config.SecretResolver == nil {
		return fail(p.failure(request.Operation, contracts.ErrUnauthorized, action, "registry credentials require a secret resolver", nil))
	}
	if err := request.Secret.Validate(); err != nil {
		return fail(p.failure(request.Operation, contracts.ErrValidation, action, "registry secret reference is invalid", nil))
	}
	resolverMetadata := p.config.SecretResolver.Metadata(ctx)
	if resolverMetadata.Validate() != nil || !resolverMetadata.Capabilities.Has(contracts.CapabilitySecretResolve) {
		return fail(p.failure(request.Operation, contracts.ErrUnauthorized, action, "registry secret resolver capability is unavailable", nil))
	}
	material, err := p.config.SecretResolver.ResolveBuildSecret(ctx, *request.Secret, secretOperation)
	if err != nil {
		return fail(p.failure(request.Operation, contracts.ErrUnauthorized, action, "registry credentials could not be materialized", nil))
	}
	session.resolver = p.config.SecretResolver
	session.material = &material
	if material.Reference != *request.Secret || material.ExpiresAt.IsZero() || !material.ExpiresAt.After(p.config.Clock().UTC()) {
		return fail(p.failure(request.Operation, contracts.ErrUnauthorized, action, "registry credential material is expired or mismatched", nil))
	}
	if err := writeCredentialConfig(tempDir, registryHost(request.Repository), material); err != nil {
		return fail(p.failure(request.Operation, contracts.ErrUnauthorized, action, "registry credentials could not be prepared", nil))
	}
	return session, nil
}

func (p *Provider) resolveManifest(ctx context.Context, request contracts.ImageResolveRequest, configDir, action string) (domain.ImageDigest, error) {
	ref := request.Repository + ":" + request.Tag
	args := []string{"--config", configDir, "manifest", "inspect", "--verbose", ref}
	var stdout cappedBuffer
	stdout.limit = maxManifestSize
	if err := p.config.Runner.Run(ctx, p.config.Command, args, nil, sanitizedEnvironment(), &stdout, io.Discard); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return domain.ImageDigest{}, p.classifyAction(request.Operation, action, ctxErr)
		}
		return domain.ImageDigest{}, p.classifyAction(request.Operation, action, err)
	}
	if stdout.Len() == 0 || stdout.overflow {
		return domain.ImageDigest{}, p.failure(request.Operation, contracts.ErrValidation, action, "registry returned an invalid manifest response", nil)
	}
	digest, err := parseManifestDigest(stdout.Bytes(), p.config.OS, p.config.Architecture, p.config.Variant)
	if err != nil {
		code := contracts.ErrValidation
		if errors.Is(err, errPlatformMissing) {
			code = contracts.ErrConflict
		}
		return domain.ImageDigest{}, p.failure(request.Operation, code, action, err.Error(), nil)
	}
	image, err := domain.ParseImageDigest(request.Repository, digest)
	if err != nil {
		return domain.ImageDigest{}, p.failure(request.Operation, contracts.ErrValidation, action, "registry returned an invalid image digest", nil)
	}
	image.ResolvedTag = request.Tag
	return image, nil
}

func (p *Provider) resultFor(request contracts.ImageResolveRequest, image domain.ImageDigest, mode, summary string) contracts.ImageResolveResult {
	resultDigest := evidenceDigest(mode, request.Repository, request.Tag, image.Digest, p.config.OS, p.config.Architecture, p.config.Variant)
	return contracts.ImageResolveResult{
		Image: image,
		Evidence: contracts.Evidence{
			Refs: []domain.EvidenceRef{{
				ID:      domain.ID("ev_" + resultDigest[7:39]),
				Kind:    "registry.image." + mode,
				Digest:  resultDigest,
				Locator: "registry://" + request.Repository + "@" + image.Digest,
			}},
			Summary:  summary,
			Digest:   resultDigest,
			Redacted: true,
		},
	}
}

func (p *Provider) pullDigest(ctx context.Context, configDir string, image domain.ImageDigest, operation contracts.OperationContext) error {
	ref := image.Repository + "@" + image.Digest
	args := []string{"--config", configDir, "pull", ref}
	if err := p.config.Runner.Run(ctx, p.config.Command, args, nil, sanitizedEnvironment(), io.Discard, io.Discard); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return p.classifyAction(operation, "pull", ctxErr)
		}
		return p.classifyAction(operation, "pull", err)
	}
	return nil
}

type pulledImageFacts struct {
	RepoDigests  []string `json:"RepoDigests"`
	OS           string   `json:"Os"`
	Architecture string   `json:"Architecture"`
	Variant      string   `json:"Variant"`
}

func (p *Provider) verifyPulledImage(ctx context.Context, configDir string, image domain.ImageDigest, operation contracts.OperationContext) error {
	ref := image.Repository + "@" + image.Digest
	args := []string{"--config", configDir, "image", "inspect", "--format", "{{json .}}", ref}
	var stdout cappedBuffer
	stdout.limit = maxManifestSize
	if err := p.config.Runner.Run(ctx, p.config.Command, args, nil, sanitizedEnvironment(), &stdout, io.Discard); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return p.classifyAction(operation, "inspect", ctxErr)
		}
		return p.classifyAction(operation, "inspect", err)
	}
	if stdout.Len() == 0 || stdout.overflow {
		return p.failure(operation, contracts.ErrValidation, "inspect", "Docker image inspect returned an invalid response", nil)
	}
	facts, err := parsePulledImageFacts(stdout.Bytes())
	if err != nil {
		return p.failure(operation, contracts.ErrValidation, "inspect", "Docker image inspect facts are invalid", nil)
	}
	if normalizeOS(facts.OS) != p.config.OS || normalizeArch(facts.Architecture) != p.config.Architecture || (p.config.Variant != "" && facts.Variant != p.config.Variant) {
		return p.failure(operation, contracts.ErrConflict, "inspect", "pulled image platform does not match the requested Agent platform", nil)
	}
	for _, repoDigest := range facts.RepoDigests {
		repository, digest, ok := strings.Cut(repoDigest, "@")
		if ok && digest == image.Digest && equivalentRepository(repository, image.Repository) {
			return nil
		}
	}
	return p.failure(operation, contracts.ErrConflict, "inspect", "pulled image RepoDigest does not match the resolved immutable digest", nil)
}

func parsePulledImageFacts(raw []byte) (pulledImageFacts, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return pulledImageFacts{}, errInvalidRegistry
	}
	if trimmed[0] == '[' {
		var values []pulledImageFacts
		if err := json.Unmarshal(trimmed, &values); err != nil || len(values) != 1 {
			return pulledImageFacts{}, errInvalidRegistry
		}
		return values[0], nil
	}
	var value pulledImageFacts
	if err := json.Unmarshal(trimmed, &value); err != nil {
		return pulledImageFacts{}, errInvalidRegistry
	}
	return value, nil
}

func equivalentRepository(left, right string) bool {
	normalize := func(value string) string {
		value = strings.TrimSuffix(strings.TrimSpace(value), "/")
		value = strings.TrimPrefix(value, "https://")
		value = strings.TrimPrefix(value, "http://")
		if !strings.ContainsAny(value, ".:") && value != "localhost" {
			if strings.Contains(value, "/") {
				value = "docker.io/" + value
			} else {
				value = "docker.io/library/" + value
			}
		}
		return value
	}
	return normalize(left) == normalize(right)
}

// cappedBuffer prevents a malicious or broken registry command from forcing
// unbounded memory growth before the response-size validation runs.
type cappedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (b *cappedBuffer) Write(value []byte) (int, error) {
	if b.limit <= 0 {
		return len(value), nil
	}
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		b.overflow = true
		return len(value), nil
	}
	if len(value) > remaining {
		_, _ = b.Buffer.Write(value[:remaining])
		b.overflow = true
		return len(value), nil
	}
	_, _ = b.Buffer.Write(value)
	return len(value), nil
}

// sanitizedEnvironment prevents ambient credentials such as
// DOCKER_AUTH_CONFIG, registry passwords, and cloud tokens from crossing the
// command boundary.  Docker receives authentication only through the
// operation-scoped --config directory.
func sanitizedEnvironment() []string {
	allowed := []string{"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "XDG_RUNTIME_DIR"}
	env := make([]string, 0, len(allowed))
	for _, name := range allowed {
		if value, ok := os.LookupEnv(name); ok && value != "" {
			env = append(env, name+"="+value)
		}
	}
	if !hasEnvironmentKey(env, "PATH") {
		env = append(env, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}
	return env
}

func hasEnvironmentKey(env []string, key string) bool {
	prefix := key + "="
	for _, value := range env {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func (p *Provider) begin(key, fingerprint string) (*operationRecord, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if previous, ok := p.operations[key]; ok {
		if previous.fingerprint != fingerprint {
			return nil, false, errors.New("idempotency key was reused for a different registry resolve")
		}
		return previous, false, nil
	}
	record := &operationRecord{fingerprint: fingerprint, done: make(chan struct{})}
	p.operations[key] = record
	return record, true, nil
}

func (p *Provider) finish(record *operationRecord, result contracts.ImageResolveResult, err error) {
	p.mu.Lock()
	record.result = cloneResult(result)
	record.err = err
	close(record.done)
	p.mu.Unlock()
}

func waitRecord(ctx context.Context, operation contracts.OperationContext, record *operationRecord) error {
	if operation.Deadline.IsZero() {
		select {
		case <-record.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	timer := time.NewTimer(time.Until(operation.Deadline))
	defer timer.Stop()
	select {
	case <-record.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return context.DeadlineExceeded
	}
}

func cloneResult(result contracts.ImageResolveResult) contracts.ImageResolveResult {
	result.Evidence.Refs = append([]domain.EvidenceRef(nil), result.Evidence.Refs...)
	return result
}

func (p *Provider) check(ctx context.Context, operation contracts.OperationContext) error {
	if err := p.metadata.Supports(contracts.CapabilityImageResolve); err != nil {
		return p.failure(operation, contracts.ErrUnsupportedCapability, "resolve", "provider capability is not enabled", err)
	}
	if err := operation.Validate(); err != nil {
		return p.failure(operation, contracts.ErrInvalidArgument, "resolve", "provider idempotency key is required", nil)
	}
	if err := operationError(ctx, operation); err != nil {
		return p.classify(operation, err)
	}
	return nil
}

func (p *Provider) classify(operation contracts.OperationContext, err error) error {
	return p.classifyAction(operation, "resolve", err)
}

func (p *Provider) classifyAction(operation contracts.OperationContext, action string, err error) error {
	if errors.Is(err, context.Canceled) {
		return p.failure(operation, contracts.ErrCancelled, action, "registry operation was cancelled", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return p.failure(operation, contracts.ErrTimeout, action, "registry operation timed out", err)
	}
	return p.failure(operation, contracts.ErrUnavailable, action, "registry operation failed", nil)
}

func (p *Provider) failure(operation contracts.OperationContext, code contracts.ErrorCode, action, message string, cause error) *contracts.ProviderError {
	retry, retryable := contracts.RetryNever, false
	if code == contracts.ErrUnavailable || code == contracts.ErrTimeout {
		retry, retryable = contracts.RetryBackoff, true
	}
	if code == contracts.ErrCancelled {
		retry, retryable = contracts.RetryAfterReconnect, true
	}
	if code == contracts.ErrUnauthorized || code == contracts.ErrConflict {
		retry = contracts.RetryUserAction
	}
	digest := sha256.Sum256([]byte(operation.IdempotencyKey))
	return &contracts.ProviderError{Provider: providerName, Code: code, Message: message, Retry: retry, Retryable: retryable, Capability: contracts.CapabilityImageResolve, Operation: action, Cause: cause,
		Details: map[string]string{"evidence_ref": "ev_" + hex.EncodeToString(digest[:])[:32]}}
}

func requestFingerprint(request contracts.ImageResolveRequest, config Config) (string, error) {
	if err := validateRepository(request.Repository); err != nil {
		return "", err
	}
	if !validTag(request.Tag) {
		return "", errInvalidRegistry
	}
	secret := ""
	if request.Secret != nil {
		if err := request.Secret.Validate(); err != nil {
			return "", errInvalidRegistry
		}
		secret = string(request.Secret.ID) + "\x00" + request.Secret.Name + "\x00" + request.Secret.Provider + "\x00" + request.Secret.Version
	}
	return digestString(request.Repository, request.Tag, secret, config.OS, config.Architecture, config.Variant), nil
}

func operationContext(ctx context.Context, operation contracts.OperationContext, timeout time.Duration) (context.Context, context.CancelFunc) {
	if !operation.Deadline.IsZero() {
		return context.WithDeadline(ctx, operation.Deadline)
	}
	return context.WithTimeout(ctx, timeout)
}

func operationError(ctx context.Context, operation contracts.OperationContext) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !operation.Deadline.IsZero() && !time.Now().Before(operation.Deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func validateRepository(repository string) error {
	if strings.TrimSpace(repository) != repository || repository == "" || strings.ContainsAny(repository, "\\@?#\r\n\x00 \t") || strings.HasPrefix(repository, "/") || strings.HasSuffix(repository, "/") || strings.Contains(repository, "..") {
		return errInvalidRegistry
	}
	parts := strings.Split(repository, "/")
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			return errInvalidRegistry
		}
		if strings.Contains(part, ":") {
			if index != 0 {
				return errInvalidRegistry
			}
			host, port, ok := strings.Cut(part, ":")
			if !ok || host == "" || port == "" || strings.Trim(port, "0123456789") != "" {
				return errInvalidRegistry
			}
			part = host
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
				return errInvalidRegistry
			}
		}
	}
	return nil
}

func validTag(tag string) bool {
	if strings.TrimSpace(tag) != tag || tag == "" || len(tag) > 128 || strings.ContainsAny(tag, "/:@\\\r\n\x00 \t") {
		return false
	}
	for _, r := range tag {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.-", r)) {
			return false
		}
	}
	return true
}

func safePlatformPart(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func normalizeOS(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "darwin" {
		return "linux" // Docker registry images target Linux on the Agent.
	}
	return value
}

func normalizeArch(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "x86_64":
		return "amd64"
	case "aarch64":
		return "arm64"
	case "armhf":
		return "arm"
	default:
		return value
	}
}

// manifestDescriptor is the subset emitted by docker manifest inspect
// --verbose.  Both list and single-platform responses are accepted.
type manifestDescriptor struct {
	Digest   string `json:"digest"`
	Platform *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant"`
	} `json:"platform,omitempty"`
}

type verboseManifest struct {
	Descriptor *manifestDescriptor  `json:"Descriptor"`
	Manifests  []manifestDescriptor `json:"manifests"`
}

func parseManifestDigest(raw []byte, targetOS, targetArch, targetVariant string) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", errInvalidRegistry
	}
	descriptors := make([]manifestDescriptor, 0, 4)
	if trimmed[0] == '[' {
		// Docker CLI emits a JSON array of {Ref, Descriptor, ...} objects
		// for some manifest-list responses, while newer versions emit an
		// OCI index object.  Accept only descriptor digests from either
		// shape; never infer a platform from a mutable tag.
		var entries []verboseManifest
		if err := json.Unmarshal(trimmed, &entries); err != nil {
			return "", errInvalidRegistry
		}
		for _, entry := range entries {
			if entry.Descriptor != nil {
				descriptors = append(descriptors, *entry.Descriptor)
			}
			descriptors = append(descriptors, entry.Manifests...)
		}
	} else {
		var payload verboseManifest
		if err := json.Unmarshal(trimmed, &payload); err != nil {
			return "", errInvalidRegistry
		}
		descriptors = append(descriptors, payload.Manifests...)
		if payload.Descriptor != nil {
			descriptors = append(descriptors, *payload.Descriptor)
		}
	}
	if len(descriptors) == 0 {
		return "", errInvalidRegistry
	}
	targetOS = normalizeOS(targetOS)
	targetArch = normalizeArch(targetArch)
	for _, item := range descriptors {
		if !validDigest(item.Digest) {
			continue
		}
		if item.Platform == nil {
			// A single-platform response may omit platform metadata.  The
			// Docker daemon has already selected it, but a manifest list may
			// not silently do so.
			if len(descriptors) == 1 {
				return item.Digest, nil
			}
			continue
		}
		if normalizeOS(item.Platform.OS) != targetOS || normalizeArch(item.Platform.Architecture) != targetArch {
			continue
		}
		if targetVariant != "" && item.Platform.Variant != targetVariant {
			continue
		}
		return item.Digest, nil
	}
	return "", errPlatformMissing
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func registryHost(repository string) string {
	host := strings.Split(repository, "/")[0]
	if !strings.ContainsAny(host, ".:") && host != "localhost" {
		return "https://index.docker.io/v1/"
	}
	return host
}

type dockerAuthEntry struct {
	Auth     string `json:"auth,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type dockerConfig struct {
	Auths map[string]dockerAuthEntry `json:"auths"`
}

type credentialPayload struct {
	Username string                     `json:"username"`
	Password string                     `json:"password"`
	Token    string                     `json:"token"`
	Auth     string                     `json:"auth"`
	Registry string                     `json:"registry"`
	Auths    map[string]dockerAuthEntry `json:"auths"`
}

func writeCredentialConfig(directory, host string, material contracts.BuildSecretMaterial) error {
	info, err := os.Lstat(material.Path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errCredential
	}
	file, err := os.Open(material.Path)
	if err != nil {
		return errCredential
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maxSecretSize+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(content) == 0 || len(content) > maxSecretSize {
		zeroBytes(content)
		return errCredential
	}
	auth, parseErr := parseCredential(content, host)
	zeroBytes(content)
	if parseErr != nil {
		return parseErr
	}
	config := dockerConfig{Auths: map[string]dockerAuthEntry{host: {Auth: string(auth)}}}
	encoded, err := json.Marshal(config)
	config.Auths[host] = dockerAuthEntry{}
	zeroBytes(auth)
	if err != nil {
		return errCredential
	}
	path := filepath.Join(directory, "config.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return errCredential
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return errCredential
	}
	return nil
}

func parseCredential(content []byte, host string) ([]byte, error) {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 {
		return nil, errCredential
	}
	if trimmed[0] == '{' {
		var payload credentialPayload
		if err := json.Unmarshal(trimmed, &payload); err != nil {
			return nil, errCredential
		}
		if len(payload.Auths) > 0 {
			for key, entry := range payload.Auths {
				if registryKeyMatches(key, host) {
					if entry.Auth != "" {
						return []byte(entry.Auth), nil
					}
					return basicAuth(entry.Username, entry.Password)
				}
			}
		}
		if payload.Auth != "" {
			return []byte(payload.Auth), nil
		}
		if payload.Token != "" {
			return basicAuth("", payload.Token)
		}
		if payload.Username != "" || payload.Password != "" {
			return basicAuth(payload.Username, payload.Password)
		}
		return nil, errCredential
	}
	// The narrow text form is username:password, username newline password,
	// or a bearer token.  It is read only from the secret material file.
	text := strings.TrimSpace(string(trimmed))
	if strings.Contains(text, "\n") {
		parts := strings.SplitN(text, "\n", 2)
		return basicAuth(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}
	if index := strings.IndexByte(text, ':'); index > 0 {
		return basicAuth(text[:index], text[index+1:])
	}
	return basicAuth("", text)
}

func registryKeyMatches(key, host string) bool {
	normalize := func(value string) string {
		value = strings.TrimSuffix(strings.TrimSpace(value), "/")
		value = strings.TrimPrefix(value, "https://")
		value = strings.TrimPrefix(value, "http://")
		return value
	}
	return normalize(key) == normalize(host)
}

func basicAuth(username, password string) ([]byte, error) {
	if username == "" && password == "" {
		return nil, errCredential
	}
	return []byte(base64.StdEncoding.EncodeToString([]byte(username + ":" + password))), nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func digestString(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = io.WriteString(hash, value)
		_, _ = hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func evidenceDigest(values ...string) string { return digestString(values...) }

var _ interface {
	contracts.Provider
	Resolve(context.Context, contracts.ImageResolveRequest) (contracts.ImageResolveResult, error)
} = (*Provider)(nil)
