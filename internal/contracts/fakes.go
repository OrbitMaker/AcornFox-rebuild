package contracts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

// FakeProviderBehavior is deliberately small and deterministic. It lets
// contract tests exercise cancellation, timeout, and classified provider
// errors without a network, Docker daemon, or model service.
//
// FailureAttempts is the number of attempts that fail. A zero value with a
// FailureCode makes the failure permanent. This behavior is test-only and is
// never part of a provider's serialized metadata.
type FakeProviderBehavior struct {
	Delay            time.Duration
	FailureCode      ErrorCode
	FailureMessage   string
	FailureRetry     RetryClass
	FailureRetryable bool
	FailureAttempts  int
}

// FakeBehavior is a short compatibility alias for callers configuring fakes.
type FakeBehavior = FakeProviderBehavior

func (b FakeProviderBehavior) failure(attempt int) (ErrorCode, string, RetryClass, bool, bool) {
	if b.FailureCode == "" || (b.FailureAttempts > 0 && attempt > b.FailureAttempts) {
		return "", "", "", false, false
	}
	retry := b.FailureRetry
	if retry == "" {
		retry = RetryBackoff
	}
	message := b.FailureMessage
	if message == "" {
		message = "fake provider failure"
	}
	return b.FailureCode, message, retry, b.FailureRetryable, true
}

// FakeCapabilityProvider is useful for contract tests that only need to
// negotiate a provider's declared capabilities.
type FakeCapabilityProvider struct {
	Info ProviderMetadata
}

func (f FakeCapabilityProvider) Metadata(context.Context) ProviderMetadata { return f.Info }

func fakeMetadata(name string, capabilities CapabilitySet, sensitive ...string) ProviderMetadata {
	return ProviderMetadata{
		Name:            name,
		Version:         "test",
		ContractVersion: ContractAPIVersion,
		Capabilities:    capabilities,
		SensitiveInputs: append([]string(nil), sensitive...),
	}
}

func fakeHash(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func fakeDigest(parts ...string) string { return "sha256:" + fakeHash(parts...) }

func fakeID(prefix string, parts ...string) domain.ID {
	return domain.ID(prefix + "_" + fakeHash(parts...)[:32])
}

func fakeOperationHash(operation OperationContext) string {
	return fakeHash(operation.IdempotencyKey)
}

func fakeEvidence(provider string, operation OperationContext, kind string) Evidence {
	digest := fakeDigest(provider, kind, operation.IdempotencyKey)
	ref := domain.EvidenceRef{
		ID:      fakeID("ev", provider, kind, operation.IdempotencyKey),
		Kind:    kind,
		Digest:  digest,
		Locator: "fake://" + provider + "/" + kind + "/" + fakeOperationHash(operation),
	}
	return Evidence{
		Refs:     []domain.EvidenceRef{ref},
		Summary:  "fake " + kind + " evidence",
		Digest:   digest,
		Redacted: true,
	}
}

func fakeEvidenceRefs(provider string, operation OperationContext, kinds ...string) []domain.EvidenceRef {
	refs := make([]domain.EvidenceRef, 0, len(kinds))
	for _, kind := range kinds {
		refs = append(refs, fakeEvidence(provider, operation, kind).Refs[0])
	}
	return refs
}

func fakeProviderError(metadata ProviderMetadata, operation OperationContext, capability Capability, action string, code ErrorCode, message string, retry RetryClass, retryable bool, cause error) *ProviderError {
	if retry == "" {
		retry = RetryNever
	}
	return &ProviderError{
		Provider:   metadata.Name,
		Code:       code,
		Message:    message,
		Retry:      retry,
		Retryable:  retryable,
		Capability: capability,
		Operation:  action,
		Cause:      cause,
		Details: map[string]string{
			"evidence_ref": string(fakeID("ev", metadata.Name, action, operation.IdempotencyKey)),
			"log_ref":      "fake://" + metadata.Name + "/logs/" + fakeOperationHash(operation),
		},
	}
}

func fakeContextError(ctx context.Context, metadata ProviderMetadata, operation OperationContext, capability Capability, action string) error {
	if err := ctx.Err(); err != nil {
		if err == context.DeadlineExceeded {
			return fakeProviderError(metadata, operation, capability, action, ErrTimeout, "provider operation timed out", RetryBackoff, true, err)
		}
		return fakeProviderError(metadata, operation, capability, action, ErrCancelled, "provider operation cancelled", RetryAfterReconnect, true, err)
	}
	if !operation.Deadline.IsZero() && !time.Now().Before(operation.Deadline) {
		return fakeProviderError(metadata, operation, capability, action, ErrTimeout, "provider operation timed out", RetryBackoff, true, context.DeadlineExceeded)
	}
	return nil
}

func fakeWait(ctx context.Context, metadata ProviderMetadata, operation OperationContext, capability Capability, action string, delay time.Duration) error {
	if err := fakeContextError(ctx, metadata, operation, capability, action); err != nil {
		return err
	}
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	var deadline <-chan time.Time
	var deadlineTimer *time.Timer
	if !operation.Deadline.IsZero() {
		remaining := time.Until(operation.Deadline)
		if remaining <= 0 {
			return fakeContextError(ctx, metadata, operation, capability, action)
		}
		deadlineTimer = time.NewTimer(remaining)
		defer deadlineTimer.Stop()
		deadline = deadlineTimer.C
	}
	select {
	case <-timer.C:
		return fakeContextError(ctx, metadata, operation, capability, action)
	case <-ctx.Done():
		return fakeContextError(ctx, metadata, operation, capability, action)
	case <-deadline:
		return fakeProviderError(metadata, operation, capability, action, ErrTimeout, "provider operation timed out", RetryBackoff, true, context.DeadlineExceeded)
	}
}

func fakeCheck(ctx context.Context, metadata ProviderMetadata, capability Capability, operation OperationContext, behavior FakeProviderBehavior, action string, attempt int) error {
	if err := fakeContextError(ctx, metadata, operation, capability, action); err != nil {
		return err
	}
	if err := operation.Validate(); err != nil {
		return fakeProviderError(metadata, operation, capability, action, ErrInvalidArgument, "provider idempotency key is required", RetryNever, false, err)
	}
	if err := metadata.Validate(); err != nil {
		return err
	}
	if !metadata.Capabilities.Has(capability) {
		return fakeProviderError(metadata, operation, capability, action, ErrUnsupportedCapability, "provider capability is not enabled", RetryUserAction, false, nil)
	}
	if err := fakeWait(ctx, metadata, operation, capability, action, behavior.Delay); err != nil {
		return err
	}
	if code, message, retry, retryable, ok := behavior.failure(attempt); ok {
		return fakeProviderError(metadata, operation, capability, action, code, message, retry, retryable, nil)
	}
	return nil
}

func fakeArgument(metadata ProviderMetadata, operation OperationContext, capability Capability, action, message string) error {
	return fakeProviderError(metadata, operation, capability, action, ErrInvalidArgument, message, RetryNever, false, nil)
}

func fakeConflict(metadata ProviderMetadata, operation OperationContext, capability Capability, action, message string) error {
	return fakeProviderError(metadata, operation, capability, action, ErrConflict, message, RetryNever, false, nil)
}

func fakeNotFound(metadata ProviderMetadata, operation OperationContext, capability Capability, action, message string) error {
	return fakeProviderError(metadata, operation, capability, action, ErrNotFound, message, RetryNever, false, nil)
}

func fakeValidation(metadata ProviderMetadata, operation OperationContext, capability Capability, action, message string, cause error) error {
	return fakeProviderError(metadata, operation, capability, action, ErrValidation, message, RetryNever, false, cause)
}

func cloneEvidence(evidence Evidence) Evidence {
	evidence.Refs = append([]domain.EvidenceRef(nil), evidence.Refs...)
	return evidence
}

func cloneBuildResult(result BuildResult) BuildResult {
	result.Evidence = cloneEvidence(result.Evidence)
	if result.Artifact != nil {
		artifact := *result.Artifact
		artifact.Evidence = append([]domain.EvidenceRef(nil), artifact.Evidence...)
		result.Artifact = &artifact
	}
	return result
}

func cloneImageResult(result ImageResolveResult) ImageResolveResult {
	result.Evidence = cloneEvidence(result.Evidence)
	return result
}

func sameDigest(parts ...string) string { return fakeDigest(parts...) }

// FakeObjectStorageProvider deliberately starts with no capabilities. It is a
// small fail-closed fake for CT-OBJECT-001 and also provides a deterministic
// in-memory implementation when object storage is explicitly enabled.
type FakeObjectStorageProvider struct {
	Info     ProviderMetadata
	Behavior FakeProviderBehavior
	mu       sync.RWMutex
	objects  map[string][]byte
	byKey    map[string]string
}

func NewFakeObjectStorageProvider(enabled bool) *FakeObjectStorageProvider {
	capabilities := CapabilitySet{}
	if enabled {
		capabilities[CapabilityObjectStorage] = struct{}{}
	}
	return &FakeObjectStorageProvider{
		Info:    fakeMetadata("fake-object-storage", capabilities),
		objects: make(map[string][]byte),
		byKey:   make(map[string]string),
	}
}

func (f *FakeObjectStorageProvider) Metadata(context.Context) ProviderMetadata { return f.Info }

func (f *FakeObjectStorageProvider) check(ctx context.Context, operation OperationContext, action string) error {
	return fakeCheck(ctx, f.Info, CapabilityObjectStorage, operation, f.Behavior, action, 1)
}

func (f *FakeObjectStorageProvider) Put(ctx context.Context, key string, value []byte, operation OperationContext) (Evidence, error) {
	if err := f.check(ctx, operation, "put"); err != nil {
		return Evidence{}, err
	}
	if strings.TrimSpace(key) == "" {
		return Evidence{}, fakeArgument(f.Info, operation, CapabilityObjectStorage, "put", "object key is required")
	}
	digest := sameDigest("object", key, string(value))
	f.mu.Lock()
	defer f.mu.Unlock()
	if previous, ok := f.byKey[operation.IdempotencyKey]; ok && previous != digest {
		return Evidence{}, fakeConflict(f.Info, operation, CapabilityObjectStorage, "put", "idempotency key was reused for a different object")
	}
	f.byKey[operation.IdempotencyKey] = digest
	f.objects[key] = append([]byte(nil), value...)
	return fakeEvidence(f.Info.Name, operation, "object.put"), nil
}

func (f *FakeObjectStorageProvider) Get(ctx context.Context, key string, operation OperationContext) ([]byte, Evidence, error) {
	if err := f.check(ctx, operation, "get"); err != nil {
		return nil, Evidence{}, err
	}
	if strings.TrimSpace(key) == "" {
		return nil, Evidence{}, fakeArgument(f.Info, operation, CapabilityObjectStorage, "get", "object key is required")
	}
	f.mu.RLock()
	value, ok := f.objects[key]
	f.mu.RUnlock()
	if !ok {
		return nil, Evidence{}, fakeNotFound(f.Info, operation, CapabilityObjectStorage, "get", "object not found")
	}
	return append([]byte(nil), value...), fakeEvidence(f.Info.Name, operation, "object.get"), nil
}

func (f *FakeObjectStorageProvider) Delete(ctx context.Context, key string, operation OperationContext) error {
	if err := f.check(ctx, operation, "delete"); err != nil {
		return err
	}
	if strings.TrimSpace(key) == "" {
		return fakeArgument(f.Info, operation, CapabilityObjectStorage, "delete", "object key is required")
	}
	f.mu.Lock()
	delete(f.objects, key)
	f.mu.Unlock()
	return nil
}

// FakeSourceProvider proves that a provider can be called idempotently without
// touching Git, a filesystem, or a network. The returned revision is immutable
// and content-addressed by the request's input.
type FakeSourceProvider struct {
	Info     ProviderMetadata
	Behavior FakeProviderBehavior
	mu       sync.Mutex
	byKey    map[string]PrepareSourceResult
	request  map[string]string
	released map[domain.ID]bool
}

func NewFakeSourceProvider() *FakeSourceProvider {
	return &FakeSourceProvider{
		Info:     fakeMetadata("fake-source", NewCapabilitySet(CapabilitySourcePrepare, CapabilitySourceRelease)),
		byKey:    make(map[string]PrepareSourceResult),
		request:  make(map[string]string),
		released: make(map[domain.ID]bool),
	}
}

func (f *FakeSourceProvider) Release(ctx context.Context, request ReleaseSourceRequest) error {
	if err := fakeCheck(ctx, f.Info, CapabilitySourceRelease, request.Operation, f.Behavior, "release", 1); err != nil {
		return err
	}
	if err := request.Revision.Validate(); err != nil {
		return fakeValidation(f.Info, request.Operation, CapabilitySourceRelease, "release", "source revision is invalid", err)
	}
	f.mu.Lock()
	f.released[request.Revision.ID] = true
	f.mu.Unlock()
	return nil
}

func (f *FakeSourceProvider) Metadata(context.Context) ProviderMetadata { return f.Info }

func (f *FakeSourceProvider) Prepare(ctx context.Context, request PrepareSourceRequest) (PrepareSourceResult, error) {
	if err := fakeCheck(ctx, f.Info, CapabilitySourcePrepare, request.Operation, f.Behavior, "prepare", 1); err != nil {
		return PrepareSourceResult{}, err
	}
	if request.ApplicationID.Empty() || strings.TrimSpace(request.Locator) == "" || strings.TrimSpace(request.ContentDigest) == "" || strings.TrimSpace(request.WorkspaceRef) == "" {
		return PrepareSourceResult{}, fakeArgument(f.Info, request.Operation, CapabilitySourcePrepare, "prepare", "source request is incomplete")
	}
	fingerprint := fakeHash(string(request.ApplicationID), string(request.Kind), request.Locator, request.Ref, request.ContentDigest, request.WorkspaceRef)
	f.mu.Lock()
	defer f.mu.Unlock()
	if previous, ok := f.request[request.Operation.IdempotencyKey]; ok {
		if previous != fingerprint {
			return PrepareSourceResult{}, fakeConflict(f.Info, request.Operation, CapabilitySourcePrepare, "prepare", "idempotency key was reused for a different source")
		}
		return cloneSourceResult(f.byKey[request.Operation.IdempotencyKey]), nil
	}
	commit := strings.TrimSpace(request.Ref)
	if request.Kind == domain.SourceGitHTTPS || request.Kind == domain.SourceGitSSH {
		commit = "fake-commit-" + fingerprint[:16]
	}
	revision, err := domain.NewSourceRevision(request.ApplicationID, request.Kind, request.Locator, request.Ref, commit, request.ContentDigest, request.WorkspaceRef, time.Unix(0, 0).UTC())
	if err != nil {
		return PrepareSourceResult{}, fakeValidation(f.Info, request.Operation, CapabilitySourcePrepare, "prepare", "source revision is invalid", err)
	}
	revision.ID = fakeID("src", fingerprint)
	result := PrepareSourceResult{Revision: revision, Evidence: fakeEvidence(f.Info.Name, request.Operation, "source.prepare")}
	f.request[request.Operation.IdempotencyKey] = fingerprint
	f.byKey[request.Operation.IdempotencyKey] = result
	return cloneSourceResult(result), nil
}

func cloneSourceResult(result PrepareSourceResult) PrepareSourceResult {
	result.Evidence = cloneEvidence(result.Evidence)
	return result
}

// FakeBuildProvider returns a deterministic OCI digest and evidence. Its
// in-memory operation table also proves that retries do not create a second
// build or artifact.
type FakeBuildProvider struct {
	Info      ProviderMetadata
	Behavior  FakeProviderBehavior
	mu        sync.Mutex
	results   map[string]BuildResult
	request   map[string]string
	attempts  map[string]int
	cancelled map[string]bool
}

func NewFakeBuildProvider(enabled bool) *FakeBuildProvider {
	capabilities := CapabilitySet{}
	if enabled {
		capabilities[CapabilityBuild] = struct{}{}
	}
	return &FakeBuildProvider{
		Info:      fakeMetadata("fake-build", capabilities),
		results:   make(map[string]BuildResult),
		request:   make(map[string]string),
		attempts:  make(map[string]int),
		cancelled: make(map[string]bool),
	}
}

func (f *FakeBuildProvider) Metadata(context.Context) ProviderMetadata { return f.Info }

func (f *FakeBuildProvider) Build(ctx context.Context, request BuildRequest) (BuildResult, error) {
	if err := request.Plan.Validate(); err != nil {
		return BuildResult{}, fakeValidation(f.Info, request.Operation, CapabilityBuild, "build", "build plan is invalid", err)
	}
	if err := request.Network.Validate(); err != nil {
		return BuildResult{}, fakeValidation(f.Info, request.Operation, CapabilityBuild, "build", "build network policy is invalid", err)
	}
	planMode, planWorkerPolicyDigest := request.Plan.EffectiveAcornFoxNetworkPolicy()
	if string(request.Network.EffectiveMode()) != planMode || request.Network.WorkerPolicyDigest != planWorkerPolicyDigest {
		return BuildResult{}, fakeProviderError(f.Info, request.Operation, CapabilityBuild, "build", ErrForbidden, "build network policy does not match the immutable build plan", RetryNever, false, nil)
	}
	if request.Network.EffectiveMode() == NetworkModeControlledEgressV1 {
		return BuildResult{}, fakeProviderError(f.Info, request.Operation, CapabilityBuild, "build", ErrForbidden, "controlled egress worker policy is unavailable", RetryNever, false, nil)
	}
	f.mu.Lock()
	f.attempts[request.Operation.IdempotencyKey]++
	attempt := f.attempts[request.Operation.IdempotencyKey]
	f.mu.Unlock()
	if err := fakeCheck(ctx, f.Info, CapabilityBuild, request.Operation, f.Behavior, "build", attempt); err != nil {
		return BuildResult{}, err
	}
	if err := domain.RequireID(request.BuildID, "build id"); err != nil {
		return BuildResult{}, fakeValidation(f.Info, request.Operation, CapabilityBuild, "build", "build id is invalid", err)
	}
	if err := request.Source.Validate(); err != nil || request.Source.ID != request.Plan.SourceRevisionID || request.Source.ContentDigest != request.Plan.SourceDigest {
		return BuildResult{}, fakeValidation(f.Info, request.Operation, CapabilityBuild, "build", "source revision binding is invalid", err)
	}
	fingerprint := fakeHash(string(request.BuildID), string(request.Plan.ID), string(request.Plan.SourceRevisionID), request.Plan.SourceDigest, request.Plan.ServiceName, string(request.Plan.Kind), request.Plan.ContextPath, request.Plan.DockerfilePath, request.Plan.StaticRuntimeDigest, request.Plan.AcornFoxDefinitionDigest, request.Plan.AcornFoxDockerfileDigest, request.Plan.AcornFoxNetworkMode, request.Plan.AcornFoxWorkerPolicyDigest, request.Plan.TargetRepository, request.Plan.Output.StorageKey, string(request.Network.EffectiveMode()), request.Network.WorkerPolicyDigest, request.Plan.IdempotencyKey)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cancelled[request.Operation.IdempotencyKey] {
		return BuildResult{}, fakeProviderError(f.Info, request.Operation, CapabilityBuild, "build", ErrCancelled, "build operation was cancelled", RetryAfterReconnect, true, context.Canceled)
	}
	if previous, ok := f.request[request.Operation.IdempotencyKey]; ok {
		if previous != fingerprint {
			return BuildResult{}, fakeConflict(f.Info, request.Operation, CapabilityBuild, "build", "idempotency key was reused for a different build plan")
		}
		return cloneBuildResult(f.results[request.Operation.IdempotencyKey]), nil
	}
	image, _ := domain.ParseImageDigest(request.Plan.TargetRepository, fakeDigest("build-image", fingerprint))
	evidence := fakeEvidence(f.Info.Name, request.Operation, "build.result")
	evidence.Refs = append(evidence.Refs, fakeEvidenceRefs(f.Info.Name, request.Operation, "build.log", "build.artifact")...)
	buildID := request.BuildID
	artifactID := fakeID("artifact", fingerprint)
	artifact := &domain.Artifact{ID: artifactID, BuildID: buildID, Image: image, OCIStorageRef: "fake://oci/" + request.Plan.Output.StorageKey, SizeBytes: 1024, Evidence: append([]domain.EvidenceRef(nil), evidence.Refs...), CreatedAt: time.Unix(0, 0).UTC()}
	result := BuildResult{
		Build:    domain.Build{ID: buildID, PlanID: request.Plan.ID, Status: domain.BuildSucceeded, ArtifactID: artifactID, CreatedAt: time.Unix(0, 0).UTC(), UpdatedAt: time.Unix(0, 0).UTC()},
		Artifact: artifact,
		Evidence: evidence,
		LogRef:   "fake://" + f.Info.Name + "/logs/" + fingerprint,
	}
	f.request[request.Operation.IdempotencyKey] = fingerprint
	f.results[request.Operation.IdempotencyKey] = cloneBuildResult(result)
	return cloneBuildResult(result), nil
}

func (f *FakeBuildProvider) Cancel(ctx context.Context, operation OperationContext) error {
	if err := fakeCheck(ctx, f.Info, CapabilityBuild, operation, f.Behavior, "cancel", 1); err != nil {
		return err
	}
	f.mu.Lock()
	if _, done := f.results[operation.IdempotencyKey]; !done {
		f.cancelled[operation.IdempotencyKey] = true
	}
	f.mu.Unlock()
	return nil
}

// FakeImageStore resolves tags to immutable digests and keeps protected and
// retained image state so a garbage-collection test cannot delete a live
// release accidentally.
type FakeImageStore struct {
	Info           ProviderMetadata
	Behavior       FakeProviderBehavior
	mu             sync.Mutex
	resolved       map[string]ImageResolveResult
	request        map[string]string
	retained       map[string]bool
	protected      map[string]bool
	protectedRepos map[string]bool
	deleted        map[string]bool
	pulled         map[string]bool
	oci            map[string][]byte
	ociResult      map[string]StoreOCIResult
}

func NewFakeImageStore(enabled bool) *FakeImageStore {
	capabilities := CapabilitySet{}
	if enabled {
		capabilities = NewCapabilitySet(CapabilityImageResolve, CapabilityImagePull, CapabilityImageRetain, CapabilityImageDelete, CapabilityImageStoreOCI, CapabilityImageOpenOCI)
	}
	return &FakeImageStore{
		Info:           fakeMetadata("fake-image", capabilities, "registry_secret_ref"),
		resolved:       make(map[string]ImageResolveResult),
		request:        make(map[string]string),
		retained:       make(map[string]bool),
		protected:      make(map[string]bool),
		protectedRepos: make(map[string]bool),
		deleted:        make(map[string]bool),
		pulled:         make(map[string]bool),
		oci:            make(map[string][]byte),
		ociResult:      make(map[string]StoreOCIResult),
	}
}

func (f *FakeImageStore) StoreOCI(ctx context.Context, request StoreOCIRequest) (StoreOCIResult, error) {
	if err := fakeCheck(ctx, f.Info, CapabilityImageStoreOCI, request.Operation, f.Behavior, "store_oci", 1); err != nil {
		return StoreOCIResult{}, err
	}
	if err := request.Image.Validate(); err != nil || strings.TrimSpace(request.StorageKey) == "" || request.Archive == nil {
		return StoreOCIResult{}, fakeValidation(f.Info, request.Operation, CapabilityImageStoreOCI, "store_oci", "persistent OCI input is invalid", err)
	}
	content, err := io.ReadAll(request.Archive)
	if err != nil || len(content) == 0 {
		return StoreOCIResult{}, fakeValidation(f.Info, request.Operation, CapabilityImageStoreOCI, "store_oci", "OCI archive is empty", err)
	}
	key := imageKey(request.Image)
	f.mu.Lock()
	defer f.mu.Unlock()
	if previous, ok := f.oci[key]; ok && !bytes.Equal(previous, content) {
		return StoreOCIResult{}, fakeConflict(f.Info, request.Operation, CapabilityImageStoreOCI, "store_oci", "digest already stores different OCI content")
	}
	result := StoreOCIResult{Image: request.Image, StorageRef: "fake://oci/" + fakeHash(request.StorageKey, key), SizeBytes: int64(len(content)), Evidence: fakeEvidence(f.Info.Name, request.Operation, "image.store_oci")}
	f.oci[key] = append([]byte(nil), content...)
	f.ociResult[key] = result
	return result, nil
}

func (f *FakeImageStore) OpenOCI(ctx context.Context, image domain.ImageDigest, operation OperationContext) (io.ReadCloser, StoreOCIResult, error) {
	if err := fakeCheck(ctx, f.Info, CapabilityImageOpenOCI, operation, f.Behavior, "open_oci", 1); err != nil {
		return nil, StoreOCIResult{}, err
	}
	if err := image.Validate(); err != nil {
		return nil, StoreOCIResult{}, fakeValidation(f.Info, operation, CapabilityImageOpenOCI, "open_oci", "image digest is invalid", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key := imageKey(image)
	content, ok := f.oci[key]
	if !ok {
		return nil, StoreOCIResult{}, fakeNotFound(f.Info, operation, CapabilityImageOpenOCI, "open_oci", "stored OCI archive not found")
	}
	return io.NopCloser(bytes.NewReader(append([]byte(nil), content...))), f.ociResult[key], nil
}

func (f *FakeImageStore) Metadata(context.Context) ProviderMetadata { return f.Info }

func imageKey(image domain.ImageDigest) string { return image.Repository + "@" + image.Digest }

func (f *FakeImageStore) Protect(image domain.ImageDigest) error {
	if err := image.Validate(); err != nil {
		return err
	}
	f.mu.Lock()
	f.protected[imageKey(image)] = true
	f.mu.Unlock()
	return nil
}

func (f *FakeImageStore) SetProtectedRepository(repository string, protected bool) {
	f.mu.Lock()
	if protected {
		f.protectedRepos[repository] = true
	} else {
		delete(f.protectedRepos, repository)
	}
	for key := range f.protected {
		if strings.HasPrefix(key, repository+"@") {
			if protected {
				f.protected[key] = true
			} else {
				delete(f.protected, key)
			}
		}
	}
	f.mu.Unlock()
}

func (f *FakeImageStore) Resolve(ctx context.Context, request ImageResolveRequest) (ImageResolveResult, error) {
	if err := fakeCheck(ctx, f.Info, CapabilityImageResolve, request.Operation, f.Behavior, "resolve", 1); err != nil {
		return ImageResolveResult{}, err
	}
	if strings.TrimSpace(request.Repository) == "" || strings.TrimSpace(request.Tag) == "" {
		return ImageResolveResult{}, fakeArgument(f.Info, request.Operation, CapabilityImageResolve, "resolve", "image repository and tag are required")
	}
	fingerprint := fakeHash(request.Repository, request.Tag)
	f.mu.Lock()
	defer f.mu.Unlock()
	if previous, ok := f.request[request.Operation.IdempotencyKey]; ok {
		if previous != fingerprint {
			return ImageResolveResult{}, fakeConflict(f.Info, request.Operation, CapabilityImageResolve, "resolve", "idempotency key was reused for a different image")
		}
		return cloneImageResult(f.resolved[request.Operation.IdempotencyKey]), nil
	}
	image, err := domain.ParseImageDigest(request.Repository, fakeDigest("resolved-image", request.Repository, request.Tag))
	if err != nil {
		return ImageResolveResult{}, fakeValidation(f.Info, request.Operation, CapabilityImageResolve, "resolve", "resolved image is invalid", err)
	}
	image.ResolvedTag = request.Tag
	result := ImageResolveResult{Image: image, Evidence: fakeEvidence(f.Info.Name, request.Operation, "image.resolve")}
	f.request[request.Operation.IdempotencyKey] = fingerprint
	f.resolved[request.Operation.IdempotencyKey] = result
	return cloneImageResult(result), nil
}

func (f *FakeImageStore) Pull(ctx context.Context, image domain.ImageDigest, operation OperationContext) (Evidence, error) {
	if err := fakeCheck(ctx, f.Info, CapabilityImagePull, operation, f.Behavior, "pull", 1); err != nil {
		return Evidence{}, err
	}
	if err := image.Validate(); err != nil {
		return Evidence{}, fakeValidation(f.Info, operation, CapabilityImagePull, "pull", "image digest is invalid", err)
	}
	f.mu.Lock()
	f.pulled[imageKey(image)] = true
	f.mu.Unlock()
	return fakeEvidence(f.Info.Name, operation, "image.pull"), nil
}

func (f *FakeImageStore) Retain(ctx context.Context, image domain.ImageDigest, operation OperationContext) error {
	if err := fakeCheck(ctx, f.Info, CapabilityImageRetain, operation, f.Behavior, "retain", 1); err != nil {
		return err
	}
	if err := image.Validate(); err != nil {
		return fakeValidation(f.Info, operation, CapabilityImageRetain, "retain", "image digest is invalid", err)
	}
	f.mu.Lock()
	f.retained[imageKey(image)] = true
	f.mu.Unlock()
	return nil
}

func (f *FakeImageStore) Delete(ctx context.Context, image domain.ImageDigest, operation OperationContext) error {
	if err := fakeCheck(ctx, f.Info, CapabilityImageDelete, operation, f.Behavior, "delete", 1); err != nil {
		return err
	}
	if err := image.Validate(); err != nil {
		return fakeValidation(f.Info, operation, CapabilityImageDelete, "delete", "image digest is invalid", err)
	}
	key := imageKey(image)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.protected[key] || f.protectedRepos[image.Repository] {
		return fakeConflict(f.Info, operation, CapabilityImageDelete, "delete", "protected image cannot be deleted")
	}
	if f.retained[key] {
		return fakeConflict(f.Info, operation, CapabilityImageDelete, "delete", "retained image cannot be deleted")
	}
	f.deleted[key] = true
	return nil
}

type fakeRuntimeState struct {
	Deployment domain.Deployment
	SpecDigest string
	Restarts   uint64
	Replicas   int
	Destroyed  bool
	HostPort   int
	Resources  ResourceLimits
}

type FakeCapacityProvider struct {
	Info     ProviderMetadata
	Behavior FakeProviderBehavior
	Snapshot CapacitySnapshot
	mu       sync.Mutex
	leases   map[string]CapacityLease
}

func NewFakeCapacityProvider(enabled bool) *FakeCapacityProvider {
	caps := CapabilitySet{}
	if enabled {
		caps = NewCapabilitySet(CapabilityCapacityCheck, CapabilityCapacityReserve)
	}
	return &FakeCapacityProvider{Info: fakeMetadata("fake-capacity", caps), Snapshot: CapacitySnapshot{TotalCPUMillis: 8000, AvailableCPUMillis: 8000, TotalMemoryBytes: 8 << 30, AvailableMemoryBytes: 8 << 30, TotalDiskBytes: 40 << 30, AvailableDiskBytes: 40 << 30, ObservedAt: time.Unix(1, 0).UTC()}, leases: make(map[string]CapacityLease)}
}
func (f *FakeCapacityProvider) Metadata(context.Context) ProviderMetadata { return f.Info }
func (f *FakeCapacityProvider) Preflight(ctx context.Context, request CapacityRequest) (CapacitySnapshot, Evidence, error) {
	if err := fakeCheck(ctx, f.Info, CapabilityCapacityCheck, request.Operation, f.Behavior, "preflight", 1); err != nil {
		return CapacitySnapshot{}, Evidence{}, err
	}
	s := f.Snapshot
	s.Scope = request.Scope
	if request.Resources.CPUMillis > s.AvailableCPUMillis || request.Resources.MemoryBytes > s.AvailableMemoryBytes || request.Resources.DiskBytes > s.AvailableDiskBytes {
		return CapacitySnapshot{}, Evidence{}, fakeProviderError(f.Info, request.Operation, CapabilityCapacityCheck, "preflight", ErrCapacity, "capacity unavailable", RetryBackoff, true, nil)
	}
	return s, fakeEvidence(f.Info.Name, request.Operation, "capacity.preflight"), nil
}
func (f *FakeCapacityProvider) Reserve(ctx context.Context, request CapacityRequest) (CapacityLease, error) {
	_, e, err := f.Preflight(ctx, request)
	if err != nil {
		return CapacityLease{}, err
	}
	lease := CapacityLease{ID: "capacity_" + fakeHash(request.Operation.IdempotencyKey)[:24], Scope: request.Scope, Resources: request.Resources, ExpiresAt: time.Now().Add(time.Minute), Evidence: e}
	if request.HostPorts > 0 {
		lease.HostPort = 39001
	}
	f.mu.Lock()
	f.leases[lease.ID] = lease
	f.mu.Unlock()
	return lease, nil
}
func (f *FakeCapacityProvider) Activate(_ context.Context, lease CapacityLease, _ OperationContext) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.leases[lease.ID]; !ok {
		return errors.New("capacity lease not found")
	}
	return nil
}
func (f *FakeCapacityProvider) Release(_ context.Context, lease CapacityLease, _ OperationContext) error {
	f.mu.Lock()
	delete(f.leases, lease.ID)
	f.mu.Unlock()
	return nil
}

// FakeRuntimeDriver models the lifecycle surface without creating containers.
// Operation keys map to one deployment, and all observations carry a redacted
// evidence reference instead of raw daemon output.
type FakeRuntimeDriver struct {
	Info       ProviderMetadata
	Behavior   FakeProviderBehavior
	mu         sync.Mutex
	byKey      map[string]domain.Deployment
	requests   map[string]string
	states     map[domain.ID]*fakeRuntimeState
	operations map[string]struct{}
}

func NewFakeRuntimeDriver(enabled bool) *FakeRuntimeDriver {
	capabilities := CapabilitySet{}
	if enabled {
		capabilities = NewCapabilitySet(CapabilityRuntimeDeploy, CapabilityRuntimeObserve, CapabilityRuntimeLogs, CapabilityRuntimeRestart, CapabilityRuntimeScale, CapabilityRuntimeRollback, CapabilityRuntimeDestroy)
	}
	return &FakeRuntimeDriver{
		Info:       fakeMetadata("fake-runtime", capabilities),
		byKey:      make(map[string]domain.Deployment),
		requests:   make(map[string]string),
		states:     make(map[domain.ID]*fakeRuntimeState),
		operations: make(map[string]struct{}),
	}
}

func (f *FakeRuntimeDriver) Metadata(context.Context) ProviderMetadata { return f.Info }

func validateRuntimeSpec(spec RuntimeSpec) error {
	if spec.ApplicationID.Empty() || spec.EnvironmentID.Empty() || spec.ReleaseID.Empty() || strings.TrimSpace(spec.ServiceName) == "" {
		return fmt.Errorf("runtime application, environment, release, and service are required")
	}
	if err := spec.Image.Validate(); err != nil {
		return err
	}
	return nil
}

func (f *FakeRuntimeDriver) Deploy(ctx context.Context, request DeployRequest) (domain.Deployment, error) {
	if err := fakeCheck(ctx, f.Info, CapabilityRuntimeDeploy, request.Operation, f.Behavior, "deploy", 1); err != nil {
		return domain.Deployment{}, err
	}
	if err := validateRuntimeSpec(request.Spec); err != nil {
		return domain.Deployment{}, fakeValidation(f.Info, request.Operation, CapabilityRuntimeDeploy, "deploy", "runtime specification is invalid", err)
	}
	if err := domain.RequireID(request.DeploymentID, "deployment id"); err != nil {
		return domain.Deployment{}, fakeValidation(f.Info, request.Operation, CapabilityRuntimeDeploy, "deploy", "deployment id is invalid", err)
	}
	secretRefs := make([]string, 0, len(request.Spec.Secrets))
	for _, secret := range request.Spec.Secrets {
		secretRefs = append(secretRefs, string(secret.ID)+":"+secret.Name+":"+secret.Provider+":"+secret.Version)
	}
	sort.Strings(secretRefs)
	fingerprint := fakeHash(string(request.DeploymentID), string(request.Spec.ApplicationID), string(request.Spec.EnvironmentID), string(request.Spec.ReleaseID), request.Spec.ServiceName, request.Spec.Image.Repository, request.Spec.Image.Digest, fmt.Sprint(request.Spec.Resources), strings.Join(secretRefs, ":"), fmt.Sprint(request.Spec.Port))
	f.mu.Lock()
	defer f.mu.Unlock()
	if previous, ok := f.requests[request.Operation.IdempotencyKey]; ok {
		if previous != fingerprint {
			return domain.Deployment{}, fakeConflict(f.Info, request.Operation, CapabilityRuntimeDeploy, "deploy", "idempotency key was reused for a different runtime specification")
		}
		return f.byKey[request.Operation.IdempotencyKey], nil
	}
	deployment := domain.Deployment{ID: request.DeploymentID, ApplicationID: request.Spec.ApplicationID, EnvironmentID: request.Spec.EnvironmentID, ReleaseID: request.Spec.ReleaseID, Status: domain.DeploymentPending, CreatedAt: time.Unix(0, 0).UTC(), UpdatedAt: time.Unix(0, 0).UTC()}
	if err := deployment.Validate(); err != nil {
		return domain.Deployment{}, fakeValidation(f.Info, request.Operation, CapabilityRuntimeDeploy, "deploy", "deployment is invalid", err)
	}
	f.requests[request.Operation.IdempotencyKey] = fingerprint
	f.byKey[request.Operation.IdempotencyKey] = deployment
	f.states[deployment.ID] = &fakeRuntimeState{Deployment: deployment, SpecDigest: fingerprint, Replicas: 1, HostPort: request.Spec.Port, Resources: request.Spec.Resources}
	return deployment, nil
}

func (f *FakeRuntimeDriver) Observe(ctx context.Context, request ObserveRequest) (RuntimeObservation, error) {
	if err := fakeCheck(ctx, f.Info, CapabilityRuntimeObserve, request.Operation, f.Behavior, "observe", 1); err != nil {
		return RuntimeObservation{}, err
	}
	if request.DeploymentID.Empty() {
		return RuntimeObservation{}, fakeArgument(f.Info, request.Operation, CapabilityRuntimeObserve, "observe", "deployment id is required")
	}
	f.mu.Lock()
	state, ok := f.states[request.DeploymentID]
	if ok {
		stateCopy := *state
		f.mu.Unlock()
		healthy := !stateCopy.Destroyed && stateCopy.Deployment.Status != domain.DeploymentStopped && stateCopy.Deployment.Status != domain.DeploymentRolledBack
		status := string(domain.DeploymentRuntimeReady)
		if stateCopy.Destroyed {
			status = string(domain.DeploymentStopped)
		} else if stateCopy.Deployment.Status == domain.DeploymentRolledBack {
			status = string(domain.DeploymentRolledBack)
		}
		return RuntimeObservation{DeploymentID: request.DeploymentID, ServiceName: "fake-service", Status: status, Healthy: healthy, RestartCount: stateCopy.Restarts, HostPort: stateCopy.HostPort, Limits: stateCopy.Resources, Evidence: fakeEvidence(f.Info.Name, request.Operation, "runtime.observe"), ObservedAt: time.Unix(0, 0).UTC()}, nil
	}
	f.mu.Unlock()
	return RuntimeObservation{}, fakeNotFound(f.Info, request.Operation, CapabilityRuntimeObserve, "observe", "deployment not found")
}

func (f *FakeRuntimeDriver) Logs(ctx context.Context, request LogsRequest) (<-chan string, error) {
	if err := fakeCheck(ctx, f.Info, CapabilityRuntimeLogs, request.Operation, f.Behavior, "logs", 1); err != nil {
		return nil, err
	}
	if request.DeploymentID.Empty() {
		return nil, fakeArgument(f.Info, request.Operation, CapabilityRuntimeLogs, "logs", "deployment id is required")
	}
	f.mu.Lock()
	_, ok := f.states[request.DeploymentID]
	f.mu.Unlock()
	if !ok {
		return nil, fakeNotFound(f.Info, request.Operation, CapabilityRuntimeLogs, "logs", "deployment not found")
	}
	output := make(chan string, 1)
	output <- "fake runtime log: deployment=" + fakeHash(string(request.DeploymentID))[:16]
	close(output)
	return output, nil
}

func (f *FakeRuntimeDriver) Restart(ctx context.Context, request RestartRequest) error {
	if err := fakeCheck(ctx, f.Info, CapabilityRuntimeRestart, request.Operation, f.Behavior, "restart", 1); err != nil {
		return err
	}
	if request.DeploymentID.Empty() {
		return fakeArgument(f.Info, request.Operation, CapabilityRuntimeRestart, "restart", "deployment id is required")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.states[request.DeploymentID]
	if !ok || state.Destroyed {
		return fakeNotFound(f.Info, request.Operation, CapabilityRuntimeRestart, "restart", "deployment not found")
	}
	if _, seen := f.operations[request.Operation.IdempotencyKey]; !seen {
		state.Restarts++
		f.operations[request.Operation.IdempotencyKey] = struct{}{}
	}
	return nil
}

func (f *FakeRuntimeDriver) Scale(ctx context.Context, request ScaleRequest) error {
	if err := fakeCheck(ctx, f.Info, CapabilityRuntimeScale, request.Operation, f.Behavior, "scale", 1); err != nil {
		return err
	}
	if request.DeploymentID.Empty() || request.Replicas < 0 {
		return fakeArgument(f.Info, request.Operation, CapabilityRuntimeScale, "scale", "deployment id and non-negative replicas are required")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.states[request.DeploymentID]
	if !ok || state.Destroyed {
		return fakeNotFound(f.Info, request.Operation, CapabilityRuntimeScale, "scale", "deployment not found")
	}
	if _, seen := f.operations[request.Operation.IdempotencyKey]; !seen {
		state.Replicas = request.Replicas
		f.operations[request.Operation.IdempotencyKey] = struct{}{}
	}
	return nil
}

func (f *FakeRuntimeDriver) Rollback(ctx context.Context, request RollbackRequest) (domain.Deployment, error) {
	if err := fakeCheck(ctx, f.Info, CapabilityRuntimeRollback, request.Operation, f.Behavior, "rollback", 1); err != nil {
		return domain.Deployment{}, err
	}
	if request.DeploymentID.Empty() || request.ReleaseID.Empty() {
		return domain.Deployment{}, fakeArgument(f.Info, request.Operation, CapabilityRuntimeRollback, "rollback", "deployment and release ids are required")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.states[request.DeploymentID]
	if !ok {
		return domain.Deployment{}, fakeNotFound(f.Info, request.Operation, CapabilityRuntimeRollback, "rollback", "deployment not found")
	}
	if previous, seen := f.byKey[request.Operation.IdempotencyKey]; seen {
		return previous, nil
	}
	state.Deployment.ReleaseID = request.ReleaseID
	state.Deployment.Status = domain.DeploymentRolledBack
	state.Deployment.UpdatedAt = time.Unix(0, 0).UTC()
	f.byKey[request.Operation.IdempotencyKey] = state.Deployment
	return state.Deployment, nil
}

func (f *FakeRuntimeDriver) Destroy(ctx context.Context, request DestroyRequest) error {
	if err := fakeCheck(ctx, f.Info, CapabilityRuntimeDestroy, request.Operation, f.Behavior, "destroy", 1); err != nil {
		return err
	}
	if request.DeploymentID.Empty() {
		return fakeArgument(f.Info, request.Operation, CapabilityRuntimeDestroy, "destroy", "deployment id is required")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.states[request.DeploymentID]
	if !ok {
		return fakeNotFound(f.Info, request.Operation, CapabilityRuntimeDestroy, "destroy", "deployment not found")
	}
	if _, seen := f.operations[request.Operation.IdempotencyKey]; !seen {
		state.Destroyed = true
		state.Deployment.Status = domain.DeploymentStopped
		state.Deployment.UpdatedAt = time.Unix(0, 0).UTC()
		f.operations[request.Operation.IdempotencyKey] = struct{}{}
	}
	return nil
}

// FakeVolumeProvider defaults every created volume to retained. Destruction is
// intentionally a separate, explicitly confirmed operation.
type fakeVolumeState struct {
	Spec      VolumeSpec
	Retained  bool
	Attached  bool
	Destroyed bool
}

type FakeVolumeProvider struct {
	Info     ProviderMetadata
	Behavior FakeProviderBehavior
	mu       sync.Mutex
	volumes  map[string]*fakeVolumeState
	byKey    map[string]VolumeSpec
}

func NewFakeVolumeProvider(enabled bool) *FakeVolumeProvider {
	caps := CapabilitySet{}
	if enabled {
		caps[CapabilityVolumeManage] = struct{}{}
	}
	return &FakeVolumeProvider{Info: fakeMetadata("fake-volume", caps), volumes: make(map[string]*fakeVolumeState), byKey: make(map[string]VolumeSpec)}
}

func (f *FakeVolumeProvider) Metadata(context.Context) ProviderMetadata { return f.Info }

func (f *FakeVolumeProvider) Create(ctx context.Context, request VolumeRequest) (VolumeSpec, Evidence, error) {
	if err := fakeCheck(ctx, f.Info, CapabilityVolumeManage, request.Operation, f.Behavior, "create", 1); err != nil {
		return VolumeSpec{}, Evidence{}, err
	}
	if strings.TrimSpace(request.Volume.Name) == "" {
		return VolumeSpec{}, Evidence{}, fakeArgument(f.Info, request.Operation, CapabilityVolumeManage, "create", "volume name is required")
	}
	if request.Volume.SizeBytes < 0 {
		return VolumeSpec{}, Evidence{}, fakeArgument(f.Info, request.Operation, CapabilityVolumeManage, "create", "volume size cannot be negative")
	}
	fingerprint := fakeHash(request.Volume.Name, request.Volume.MountPath, fmt.Sprint(request.Volume.SizeBytes))
	f.mu.Lock()
	defer f.mu.Unlock()
	if previous, ok := f.byKey[request.Operation.IdempotencyKey]; ok {
		if fakeHash(previous.Name, previous.MountPath, fmt.Sprint(previous.SizeBytes)) != fingerprint {
			return VolumeSpec{}, Evidence{}, fakeConflict(f.Info, request.Operation, CapabilityVolumeManage, "create", "idempotency key was reused for a different volume")
		}
		return previous, fakeEvidence(f.Info.Name, request.Operation, "volume.create"), nil
	}
	if existing, ok := f.volumes[request.Volume.Name]; ok && !existing.Destroyed {
		if existing.Spec.MountPath != request.Volume.MountPath || existing.Spec.SizeBytes != request.Volume.SizeBytes {
			return VolumeSpec{}, Evidence{}, fakeConflict(f.Info, request.Operation, CapabilityVolumeManage, "create", "volume name already exists with different specification")
		}
		f.byKey[request.Operation.IdempotencyKey] = existing.Spec
		return existing.Spec, fakeEvidence(f.Info.Name, request.Operation, "volume.create"), nil
	}
	f.byKey[request.Operation.IdempotencyKey] = request.Volume
	f.volumes[request.Volume.Name] = &fakeVolumeState{Spec: request.Volume, Retained: true}
	return request.Volume, fakeEvidence(f.Info.Name, request.Operation, "volume.create"), nil
}

func (f *FakeVolumeProvider) stateOperation(ctx context.Context, request VolumeRequest, action string) error {
	return fakeCheck(ctx, f.Info, CapabilityVolumeManage, request.Operation, f.Behavior, action, 1)
}

func (f *FakeVolumeProvider) Attach(ctx context.Context, request VolumeRequest) error {
	if err := f.stateOperation(ctx, request, "attach"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.volumes[request.Volume.Name]
	if !ok || state.Destroyed {
		return fakeNotFound(f.Info, request.Operation, CapabilityVolumeManage, "attach", "volume not found")
	}
	state.Attached = true
	return nil
}

func (f *FakeVolumeProvider) Detach(ctx context.Context, request VolumeRequest) error {
	if err := f.stateOperation(ctx, request, "detach"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.volumes[request.Volume.Name]
	if !ok || state.Destroyed {
		return fakeNotFound(f.Info, request.Operation, CapabilityVolumeManage, "detach", "volume not found")
	}
	state.Attached = false
	return nil
}

func (f *FakeVolumeProvider) Retain(ctx context.Context, request VolumeRequest) error {
	if err := f.stateOperation(ctx, request, "retain"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.volumes[request.Volume.Name]
	if !ok || state.Destroyed {
		return fakeNotFound(f.Info, request.Operation, CapabilityVolumeManage, "retain", "volume not found")
	}
	state.Retained = true
	return nil
}

func (f *FakeVolumeProvider) Destroy(ctx context.Context, request VolumeRequest) error {
	if err := f.stateOperation(ctx, request, "destroy"); err != nil {
		return err
	}
	if strings.TrimSpace(request.ConfirmationToken) == "" {
		return fakeProviderError(f.Info, request.Operation, CapabilityVolumeManage, "destroy", ErrUnauthorized, "dangerous confirmation token is required", RetryUserAction, false, nil)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.volumes[request.Volume.Name]
	if !ok {
		return fakeNotFound(f.Info, request.Operation, CapabilityVolumeManage, "destroy", "volume not found")
	}
	state.Destroyed = true
	return nil
}

type fakeRouteState struct {
	Route domain.Route
	Spec  string
}

// FakeRouteProvider returns both desired and actual evidence for each route.
type FakeRouteProvider struct {
	Info     ProviderMetadata
	Behavior FakeProviderBehavior
	mu       sync.Mutex
	byKey    map[string]fakeRouteState
	byRoute  map[string]fakeRouteState
}

func NewFakeRouteProvider(enabled bool) *FakeRouteProvider {
	caps := CapabilitySet{}
	if enabled {
		caps[CapabilityRouteManage] = struct{}{}
	}
	return &FakeRouteProvider{Info: fakeMetadata("fake-route", caps), byKey: make(map[string]fakeRouteState), byRoute: make(map[string]fakeRouteState)}
}

func routeFingerprint(route RouteSpec) string {
	return fakeHash(route.Host, route.Path, string(route.DeploymentID), route.ServiceName, fmt.Sprint(route.Port), route.CertificateRef, fmt.Sprint(route.Verified))
}

func (f *FakeRouteProvider) Metadata(context.Context) ProviderMetadata { return f.Info }

func (f *FakeRouteProvider) Apply(ctx context.Context, request RouteRequest) (domain.Route, Evidence, error) {
	if err := fakeCheck(ctx, f.Info, CapabilityRouteManage, request.Operation, f.Behavior, "apply", 1); err != nil {
		return domain.Route{}, Evidence{}, err
	}
	if strings.TrimSpace(request.Route.Host) == "" || !strings.HasPrefix(request.Route.Path, "/") || request.Route.DeploymentID.Empty() || request.Route.Port < 1 || request.Route.Port > 65535 || !request.Route.Verified {
		return domain.Route{}, Evidence{}, fakeArgument(f.Info, request.Operation, CapabilityRouteManage, "apply", "route host, absolute path, and deployment are required")
	}
	spec := routeFingerprint(request.Route)
	f.mu.Lock()
	defer f.mu.Unlock()
	if previous, ok := f.byKey[request.Operation.IdempotencyKey]; ok {
		if previous.Spec != spec {
			return domain.Route{}, Evidence{}, fakeConflict(f.Info, request.Operation, CapabilityRouteManage, "apply", "idempotency key was reused for a different route")
		}
		evidence := fakeEvidence(f.Info.Name, request.Operation, "route.desired")
		evidence.Refs = append(evidence.Refs, fakeEvidenceRefs(f.Info.Name, request.Operation, "route.actual")...)
		return previous.Route, evidence, nil
	}
	if previous, ok := f.byRoute[spec]; ok {
		f.byKey[request.Operation.IdempotencyKey] = previous
		evidence := fakeEvidence(f.Info.Name, request.Operation, "route.desired")
		evidence.Refs = append(evidence.Refs, fakeEvidenceRefs(f.Info.Name, request.Operation, "route.actual")...)
		return previous.Route, evidence, nil
	}
	route := domain.Route{ID: fakeID("route", spec), ApplicationID: domain.ID("app_fake"), DeploymentID: request.Route.DeploymentID, ServiceName: request.Route.ServiceName, Host: request.Route.Host, Path: request.Route.Path, CertificateRef: request.Route.CertificateRef, Verified: request.Route.Verified, Serving: true, CreatedAt: time.Unix(0, 0).UTC()}
	if err := route.Validate(); err != nil {
		return domain.Route{}, Evidence{}, fakeValidation(f.Info, request.Operation, CapabilityRouteManage, "apply", "route is invalid", err)
	}
	state := fakeRouteState{Route: route, Spec: spec}
	f.byKey[request.Operation.IdempotencyKey] = state
	f.byRoute[spec] = state
	evidence := fakeEvidence(f.Info.Name, request.Operation, "route.desired")
	evidence.Refs = append(evidence.Refs, fakeEvidenceRefs(f.Info.Name, request.Operation, "route.actual")...)
	return route, evidence, nil
}

func (f *FakeRouteProvider) Observe(ctx context.Context, request RouteRequest) (domain.Observation, error) {
	if err := fakeCheck(ctx, f.Info, CapabilityRouteManage, request.Operation, f.Behavior, "observe", 1); err != nil {
		return domain.Observation{}, err
	}
	spec := routeFingerprint(request.Route)
	f.mu.Lock()
	state, ok := f.byRoute[spec]
	f.mu.Unlock()
	if !ok {
		return domain.Observation{}, fakeNotFound(f.Info, request.Operation, CapabilityRouteManage, "observe", "route not found")
	}
	observation := domain.Observation{ID: fakeID("obs", spec), TargetRef: state.Route.Host + state.Route.Path, Kind: "route.actual", Value: state.Route.Serving, Source: f.Info.Name, ObservedAt: time.Unix(0, 0).UTC(), Evidence: fakeEvidenceRefs(f.Info.Name, request.Operation, "route.desired", "route.actual")}
	if err := observation.Validate(); err != nil {
		return domain.Observation{}, fakeValidation(f.Info, request.Operation, CapabilityRouteManage, "observe", "route observation is invalid", err)
	}
	return observation, nil
}

func (f *FakeRouteProvider) Remove(ctx context.Context, request RouteRequest) error {
	if err := fakeCheck(ctx, f.Info, CapabilityRouteManage, request.Operation, f.Behavior, "remove", 1); err != nil {
		return err
	}
	spec := routeFingerprint(request.Route)
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.byRoute, spec)
	for key, state := range f.byKey {
		if state.Spec == spec {
			delete(f.byKey, key)
		}
	}
	return nil
}

func (f *FakeRouteProvider) Rebuild(ctx context.Context, operation OperationContext) (Evidence, error) {
	if err := fakeCheck(ctx, f.Info, CapabilityRouteManage, operation, f.Behavior, "rebuild", 1); err != nil {
		return Evidence{}, err
	}
	evidence := fakeEvidence(f.Info.Name, operation, "route.desired")
	evidence.Refs = append(evidence.Refs, fakeEvidenceRefs(f.Info.Name, operation, "route.actual")...)
	return evidence, nil
}

type fakeSecretState struct {
	Digest  string
	Revoked bool
}

// FakeSecretProvider never stores a caller-visible plaintext value. Store and
// Mount return only a reference/mount handle, and JSON tags on SecretRequest
// keep Value out of serialized inputs.
type FakeSecretProvider struct {
	Info     ProviderMetadata
	Behavior FakeProviderBehavior
	mu       sync.Mutex
	secrets  map[domain.ID]fakeSecretState
	mounts   map[string]SecretMount
	revoked  map[string]bool
	byKey    map[string]domain.SecretReference
}

func NewFakeSecretProvider(enabled bool) *FakeSecretProvider {
	caps := CapabilitySet{}
	if enabled {
		caps[CapabilitySecretManage] = struct{}{}
	}
	return &FakeSecretProvider{Info: fakeMetadata("fake-secret", caps, "value", "secret_value"), secrets: make(map[domain.ID]fakeSecretState), mounts: make(map[string]SecretMount), revoked: make(map[string]bool), byKey: make(map[string]domain.SecretReference)}
}

func (f *FakeSecretProvider) Metadata(context.Context) ProviderMetadata { return f.Info }

func (f *FakeSecretProvider) Store(ctx context.Context, request SecretRequest) (domain.SecretReference, error) {
	if err := fakeCheck(ctx, f.Info, CapabilitySecretManage, request.Operation, f.Behavior, "store", 1); err != nil {
		return domain.SecretReference{}, err
	}
	if err := request.Reference.Validate(); err != nil {
		return domain.SecretReference{}, fakeValidation(f.Info, request.Operation, CapabilitySecretManage, "store", "secret reference is invalid", err)
	}
	fingerprint := fakeHash(string(request.Reference.ID), request.Reference.Name, request.Reference.Provider, request.Reference.Version, string(request.Value))
	f.mu.Lock()
	defer f.mu.Unlock()
	if previous, ok := f.byKey[request.Operation.IdempotencyKey]; ok {
		if previous.ID != request.Reference.ID {
			return domain.SecretReference{}, fakeConflict(f.Info, request.Operation, CapabilitySecretManage, "store", "idempotency key was reused for a different secret")
		}
		return previous, nil
	}
	f.secrets[request.Reference.ID] = fakeSecretState{Digest: fakeDigest("secret", fingerprint)}
	f.byKey[request.Operation.IdempotencyKey] = request.Reference
	return request.Reference, nil
}

func (f *FakeSecretProvider) Mount(ctx context.Context, request SecretRequest) (SecretMount, error) {
	if err := fakeCheck(ctx, f.Info, CapabilitySecretManage, request.Operation, f.Behavior, "mount", 1); err != nil {
		return SecretMount{}, err
	}
	if err := request.Reference.Validate(); err != nil {
		return SecretMount{}, fakeValidation(f.Info, request.Operation, CapabilitySecretManage, "mount", "secret reference is invalid", err)
	}
	mountKey := request.Operation.IdempotencyKey + ":" + string(request.Reference.ID)
	f.mu.Lock()
	defer f.mu.Unlock()
	if previous, ok := f.mounts[mountKey]; ok {
		if f.revoked[mountKey] {
			return SecretMount{}, fakeConflict(f.Info, request.Operation, CapabilitySecretManage, "mount", "secret mount has been revoked")
		}
		return previous, nil
	}
	mount := SecretMount{MountID: "mount_" + fakeHash(string(request.Reference.ID), request.Operation.IdempotencyKey)[:24], Reference: request.Reference, ExpiresAt: time.Unix(0, 0).UTC().Add(time.Minute)}
	f.mounts[mountKey] = mount
	f.revoked[mountKey] = false
	return mount, nil
}

func (f *FakeSecretProvider) Revoke(ctx context.Context, mount SecretMount, operation OperationContext) error {
	if err := fakeCheck(ctx, f.Info, CapabilitySecretManage, operation, f.Behavior, "revoke", 1); err != nil {
		return err
	}
	if strings.TrimSpace(mount.MountID) == "" {
		return fakeArgument(f.Info, operation, CapabilitySecretManage, "revoke", "mount id is required")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for key, existing := range f.mounts {
		if existing.MountID == mount.MountID {
			f.revoked[key] = true
			return nil
		}
	}
	return fakeNotFound(f.Info, operation, CapabilitySecretManage, "revoke", "secret mount not found")
}

// FakeMeterProvider de-duplicates samples by stable sample ID and aggregates
// every sample in the half-open query window [From, To).
type FakeMeterProvider struct {
	Info     ProviderMetadata
	Behavior FakeProviderBehavior
	mu       sync.Mutex
	Samples  []MeterSample
	byID     map[string]MeterSample
	byOp     map[string]string
}

func NewFakeMeterProvider(enabled bool) *FakeMeterProvider {
	caps := CapabilitySet{}
	if enabled {
		caps[CapabilityMeter] = struct{}{}
	}
	return &FakeMeterProvider{Info: fakeMetadata("fake-meter", caps), byID: make(map[string]MeterSample), byOp: make(map[string]string)}
}

func (f *FakeMeterProvider) Metadata(context.Context) ProviderMetadata { return f.Info }

func meterSampleFingerprint(sample MeterSample) string {
	return fakeHash(sample.ID, string(sample.ApplicationID), string(sample.EnvironmentID), string(sample.DeploymentID), sample.ServiceName, string(sample.ReleaseID), sample.At.UTC().Format(time.RFC3339Nano), fmt.Sprint(sample.CPUMillicores), fmt.Sprint(sample.CPUSeconds), fmt.Sprint(sample.MemoryBytes), fmt.Sprint(sample.DiskBytes), fmt.Sprint(sample.NetworkRxBytes), fmt.Sprint(sample.NetworkTxBytes), fmt.Sprint(sample.RuntimeSeconds), fmt.Sprint(sample.RestartCount), fmt.Sprint(sample.ExceptionCount), fmt.Sprint(sample.LimitCPUMillicores), fmt.Sprint(sample.LimitMemoryBytes), fmt.Sprint(sample.LimitDiskBytes), fmt.Sprint(sample.LimitPIDs))
}

func (f *FakeMeterProvider) Ingest(ctx context.Context, samples []MeterSample, operation OperationContext) error {
	if err := fakeCheck(ctx, f.Info, CapabilityMeter, operation, f.Behavior, "ingest", 1); err != nil {
		return err
	}
	batchFingerprint := fakeHash(func() string {
		parts := make([]string, 0, len(samples))
		for _, sample := range samples {
			parts = append(parts, meterSampleFingerprint(sample))
		}
		sort.Strings(parts)
		return strings.Join(parts, ":")
	}())
	f.mu.Lock()
	defer f.mu.Unlock()
	if previous, ok := f.byOp[operation.IdempotencyKey]; ok {
		if previous != batchFingerprint {
			return fakeConflict(f.Info, operation, CapabilityMeter, "ingest", "idempotency key was reused for a different sample batch")
		}
		return nil
	}
	pending := make(map[string]MeterSample, len(samples))
	newSamples := make([]MeterSample, 0, len(samples))
	for _, sample := range samples {
		if strings.TrimSpace(sample.ID) == "" || sample.ApplicationID.Empty() || strings.TrimSpace(sample.ServiceName) == "" || sample.At.IsZero() || sample.CPUMillicores < 0 || sample.CPUSeconds < 0 || sample.MemoryBytes < 0 || sample.DiskBytes < 0 || sample.RuntimeSeconds < 0 || sample.LimitCPUMillicores < 0 || sample.LimitMemoryBytes < 0 || sample.LimitDiskBytes < 0 || sample.LimitPIDs < 0 {
			return fakeArgument(f.Info, operation, CapabilityMeter, "ingest", "meter sample is invalid")
		}
		previous, ok := f.byID[sample.ID]
		if pendingSample, pendingOK := pending[sample.ID]; pendingOK {
			previous, ok = pendingSample, true
		}
		if ok {
			if meterSampleFingerprint(previous) != meterSampleFingerprint(sample) {
				return fakeConflict(f.Info, operation, CapabilityMeter, "ingest", "sample id was reused for different measurements")
			}
			continue
		}
		pending[sample.ID] = sample
		newSamples = append(newSamples, sample)
	}
	for _, sample := range newSamples {
		if _, ok := f.byID[sample.ID]; ok {
			continue
		}
		copy := sample
		f.byID[sample.ID] = copy
		f.Samples = append(f.Samples, copy)
	}
	f.byOp[operation.IdempotencyKey] = batchFingerprint
	return nil
}

func (f *FakeMeterProvider) Query(ctx context.Context, query MeterQuery) ([]domain.UsageAggregate, error) {
	operation := OperationContext{IdempotencyKey: "query:" + string(query.ApplicationID) + ":" + query.From.UTC().Format(time.RFC3339Nano) + ":" + query.To.UTC().Format(time.RFC3339Nano)}
	if err := fakeCheck(ctx, f.Info, CapabilityMeter, operation, f.Behavior, "query", 1); err != nil {
		return nil, err
	}
	if query.ApplicationID.Empty() || query.From.IsZero() || query.To.IsZero() || !query.From.Before(query.To) {
		return nil, fakeArgument(f.Info, operation, CapabilityMeter, "query", "meter query application and window are required")
	}
	type aggregateKey struct {
		environment, deployment domain.ID
		service                 string
		release                 domain.ID
	}
	f.mu.Lock()
	groups := make(map[aggregateKey]domain.UsageAggregate)
	bounds := make(map[aggregateKey][]MeterSample)
	for _, sample := range f.Samples {
		if sample.ApplicationID != query.ApplicationID || sample.At.Before(query.From) || !sample.At.Before(query.To) {
			continue
		}
		if query.ServiceName != "" && sample.ServiceName != query.ServiceName {
			continue
		}
		if !query.ReleaseID.Empty() && sample.ReleaseID != query.ReleaseID {
			continue
		}
		if !query.EnvironmentID.Empty() && sample.EnvironmentID != query.EnvironmentID {
			continue
		}
		key := aggregateKey{environment: sample.EnvironmentID, deployment: sample.DeploymentID, service: sample.ServiceName, release: sample.ReleaseID}
		bounds[key] = append(bounds[key], sample)
		aggregate := groups[key]
		if aggregate.ID.Empty() {
			aggregate = domain.UsageAggregate{ID: fakeID("usage", string(query.ApplicationID), string(sample.EnvironmentID), string(sample.DeploymentID), sample.ServiceName, string(sample.ReleaseID), query.From.UTC().Format(time.RFC3339Nano), query.To.UTC().Format(time.RFC3339Nano)), ApplicationID: query.ApplicationID, EnvironmentID: sample.EnvironmentID, DeploymentID: sample.DeploymentID, ServiceName: sample.ServiceName, ReleaseID: sample.ReleaseID, WindowStart: query.From.UTC(), WindowEnd: query.To.UTC()}
		}
		aggregate.SampleCount++
		aggregate.AverageCPUMillicores += float64(sample.CPUMillicores)
		aggregate.AverageMemoryBytes += float64(sample.MemoryBytes)
		aggregate.AverageDiskBytes += float64(sample.DiskBytes)
		aggregate.CPUSeconds += sample.CPUSeconds
		aggregate.MemoryByteSeconds += float64(sample.MemoryBytes)
		aggregate.DiskByteSeconds += float64(sample.DiskBytes)
		aggregate.NetworkRxBytes += sample.NetworkRxBytes
		aggregate.NetworkTxBytes += sample.NetworkTxBytes
		aggregate.RuntimeSeconds += sample.RuntimeSeconds
		aggregate.RestartCount += sample.RestartCount
		aggregate.ExceptionCount += sample.ExceptionCount
		aggregate.PeakCPUMillicores = maxInt64(aggregate.PeakCPUMillicores, sample.CPUMillicores)
		aggregate.PeakMemoryBytes = maxInt64(aggregate.PeakMemoryBytes, sample.MemoryBytes)
		aggregate.PeakDiskBytes = maxInt64(aggregate.PeakDiskBytes, sample.DiskBytes)
		aggregate.LimitCPUMillicores = maxInt64(aggregate.LimitCPUMillicores, sample.LimitCPUMillicores)
		aggregate.LimitMemoryBytes = maxInt64(aggregate.LimitMemoryBytes, sample.LimitMemoryBytes)
		aggregate.LimitDiskBytes = maxInt64(aggregate.LimitDiskBytes, sample.LimitDiskBytes)
		aggregate.LimitPIDs = maxInt64(aggregate.LimitPIDs, sample.LimitPIDs)
		groups[key] = aggregate
	}
	f.mu.Unlock()
	keys := make([]aggregateKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].environment != keys[j].environment {
			return keys[i].environment < keys[j].environment
		}
		if keys[i].deployment != keys[j].deployment {
			return keys[i].deployment < keys[j].deployment
		}
		if keys[i].service == keys[j].service {
			return keys[i].release < keys[j].release
		}
		return keys[i].service < keys[j].service
	})
	result := make([]domain.UsageAggregate, 0, len(keys))
	for _, key := range keys {
		aggregate := groups[key]
		if aggregate.SampleCount > 0 {
			count := float64(aggregate.SampleCount)
			aggregate.AverageCPUMillicores /= count
			aggregate.AverageMemoryBytes /= count
			aggregate.AverageDiskBytes /= count
		}
		ordered := append([]MeterSample(nil), bounds[key]...)
		sort.Slice(ordered, func(i, j int) bool { return ordered[i].At.Before(ordered[j].At) })
		if len(ordered) > 1 {
			duration := ordered[len(ordered)-1].At.Sub(ordered[0].At).Seconds()
			if duration > 0 {
				aggregate.TrendCPUMillicoresPerSecond = float64(ordered[len(ordered)-1].CPUMillicores-ordered[0].CPUMillicores) / duration
				aggregate.TrendMemoryBytesPerSecond = float64(ordered[len(ordered)-1].MemoryBytes-ordered[0].MemoryBytes) / duration
				aggregate.TrendDiskBytesPerSecond = float64(ordered[len(ordered)-1].DiskBytes-ordered[0].DiskBytes) / duration
			}
		}
		result = append(result, aggregate)
	}
	return result, nil
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}

// FakeNotificationProvider records one successful delivery per EventID. A
// configured failure can be limited to N attempts, which makes retry/dedupe
// behavior directly testable without an HTTP receiver.
type FakeNotificationProvider struct {
	Info         ProviderMetadata
	Behavior     FakeProviderBehavior
	mu           sync.Mutex
	Sent         []Notification
	Attempts     map[domain.ID]int
	delivered    map[domain.ID]Notification
	fingerprints map[domain.ID]string
	byKey        map[string]domain.ID
}

func NewFakeNotificationProvider(enabled bool) *FakeNotificationProvider {
	caps := CapabilitySet{}
	if enabled {
		caps[CapabilityNotification] = struct{}{}
	}
	return &FakeNotificationProvider{Info: fakeMetadata("fake-notification", caps), Attempts: make(map[domain.ID]int), delivered: make(map[domain.ID]Notification), fingerprints: make(map[domain.ID]string), byKey: make(map[string]domain.ID)}
}

func (f *FakeNotificationProvider) Metadata(context.Context) ProviderMetadata { return f.Info }

func (f *FakeNotificationProvider) Send(ctx context.Context, notification Notification, operation OperationContext) error {
	f.mu.Lock()
	f.Attempts[notification.EventID]++
	attempt := f.Attempts[notification.EventID]
	f.mu.Unlock()
	if err := fakeCheck(ctx, f.Info, CapabilityNotification, operation, f.Behavior, "send", attempt); err != nil {
		return err
	}
	if notification.EventID.Empty() || strings.TrimSpace(notification.EventType) == "" {
		return fakeArgument(f.Info, operation, CapabilityNotification, "send", "notification event id and type are required")
	}
	payloadFingerprint := fakeHash(notification.EventType, notification.OccurredAt.UTC().Format(time.RFC3339Nano), fmt.Sprint(notification.Payload))
	f.mu.Lock()
	defer f.mu.Unlock()
	if previous, ok := f.byKey[operation.IdempotencyKey]; ok && previous != notification.EventID {
		return fakeConflict(f.Info, operation, CapabilityNotification, "send", "idempotency key was reused for a different event")
	}
	f.byKey[operation.IdempotencyKey] = notification.EventID
	if _, ok := f.delivered[notification.EventID]; ok {
		if f.fingerprints[notification.EventID] != payloadFingerprint {
			return fakeConflict(f.Info, operation, CapabilityNotification, "send", "event id was reused for different notification content")
		}
		return nil
	}
	copy := notification
	if copy.Payload != nil {
		copy.Payload = map[string]any{"redacted": true}
	}
	f.delivered[notification.EventID] = copy
	f.fingerprints[notification.EventID] = payloadFingerprint
	f.Sent = append(f.Sent, copy)
	return nil
}

func (f *FakeNotificationProvider) Test(ctx context.Context, operation OperationContext) error {
	return fakeCheck(ctx, f.Info, CapabilityNotification, operation, f.Behavior, "test", 1)
}

// FakeAIProvider returns a bounded, structured, redacted plan and never
// exposes the context package's contents. Disabling the capability fails closed
// so the controller can choose its normal non-AI degradation path.
type FakeAIProvider struct {
	Info     ProviderMetadata
	Behavior FakeProviderBehavior
	mu       sync.Mutex
	results  map[string]AIResult
	request  map[string]string
}

func NewFakeAIProvider(enabled bool) *FakeAIProvider {
	caps := CapabilitySet{}
	if enabled {
		caps[CapabilityAI] = struct{}{}
	}
	return &FakeAIProvider{Info: fakeMetadata("fake-ai", caps, "context.secret", "prompt"), results: make(map[string]AIResult), request: make(map[string]string)}
}

func (f *FakeAIProvider) Metadata(context.Context) ProviderMetadata { return f.Info }

func (f *FakeAIProvider) StructuredCall(ctx context.Context, request AIRequest) (AIResult, error) {
	if err := fakeCheck(ctx, f.Info, CapabilityAI, request.Operation, f.Behavior, "structured_call", 1); err != nil {
		return AIResult{}, err
	}
	if strings.TrimSpace(request.TaskType) == "" {
		return AIResult{}, fakeArgument(f.Info, request.Operation, CapabilityAI, "structured_call", "AI task type is required")
	}
	if request.Budget.MaxDuration > 0 && f.Behavior.Delay > request.Budget.MaxDuration {
		return AIResult{}, fakeProviderError(f.Info, request.Operation, CapabilityAI, "structured_call", ErrTimeout, "AI token budget duration exceeded", RetryBackoff, true, context.DeadlineExceeded)
	}
	fingerprint := fakeHash(request.TaskType, string(request.Context.ID), request.Context.TemplateVersion, strings.Join(request.Context.Scope, ":"))
	f.mu.Lock()
	defer f.mu.Unlock()
	if previous, ok := f.request[request.Operation.IdempotencyKey]; ok {
		if previous != fingerprint {
			return AIResult{}, fakeConflict(f.Info, request.Operation, CapabilityAI, "structured_call", "idempotency key was reused for a different AI request")
		}
		return cloneAIResult(f.results[request.Operation.IdempotencyKey]), nil
	}
	invocationID := fakeID("aiinv", fingerprint)
	planID := fakeID("aiplan", fingerprint)
	refs := fakeEvidenceRefs(f.Info.Name, request.Operation, "ai.context", "ai.response")
	result := AIResult{
		Invocation: domain.AIInvocation{ID: invocationID, Provider: f.Info.Name, Model: "fake-model-v1", Profile: request.Context.Profile, PolicyVersion: "fake-policy-v1", PromptVersion: "fake-prompt-v1", ProblemFingerprint: fingerprint, ContextID: request.Context.ID, ContextDigest: request.Context.ManifestDigest, Tokens: uint64(maxInt(request.Budget.MaxTokens, 1)), DurationMS: f.Behavior.Delay.Milliseconds(), Status: "succeeded"},
		Plan:       domain.AIActionPlan{ID: planID, SchemaVersion: "1.0", PolicyVersion: "fake-policy-v1", TaskType: request.TaskType, TargetRefs: map[string]string{"scope": "controller"}, Sources: []string{"context:" + request.Context.ManifestDigest}, EvidenceRefs: append([]domain.EvidenceRef(nil), refs...), Actions: []domain.AIAction{{ToolID: "fake.readonly", ToolVersion: "v1", Risk: domain.AIRiskReadOnly, ExpectedResult: "bounded redacted findings", ValidationID: "fake-validation-v1"}}, Budget: domain.AIPlanBudget{MaxTokens: maxInt(request.Budget.MaxTokens, 1), MaxDurationMS: maxInt64Value(request.Budget.MaxDuration.Milliseconds(), 1000), MaxActions: 1}, Confidence: 0.5, RequiresUserConfirmation: false},
		Evidence:   Evidence{Refs: refs, Summary: "fake structured AI response", Digest: fakeDigest("ai", fingerprint), Redacted: true},
	}
	f.request[request.Operation.IdempotencyKey] = fingerprint
	f.results[request.Operation.IdempotencyKey] = cloneAIResult(result)
	return cloneAIResult(result), nil
}

func maxInt64Value(value, fallback int64) int64 {
	if value > 0 {
		return value
	}
	return fallback
}

func maxInt(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func cloneAIResult(result AIResult) AIResult {
	result.Evidence = cloneEvidence(result.Evidence)
	result.Plan.EvidenceRefs = append([]domain.EvidenceRef(nil), result.Plan.EvidenceRefs...)
	result.Plan.Actions = append([]domain.AIAction(nil), result.Plan.Actions...)
	if result.Plan.TargetRefs != nil {
		refs := make(map[string]string, len(result.Plan.TargetRefs))
		for key, value := range result.Plan.TargetRefs {
			refs[key] = value
		}
		result.Plan.TargetRefs = refs
	}
	return result
}

func safeName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "service"
	}
	var builder strings.Builder
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.' {
			builder.WriteRune(char)
		} else {
			builder.WriteByte('-')
		}
	}
	return builder.String()
}

var (
	_ SourceProvider        = (*FakeSourceProvider)(nil)
	_ BuildProvider         = (*FakeBuildProvider)(nil)
	_ ImageStore            = (*FakeImageStore)(nil)
	_ RuntimeDriver         = (*FakeRuntimeDriver)(nil)
	_ CapacityProvider      = (*FakeCapacityProvider)(nil)
	_ VolumeProvider        = (*FakeVolumeProvider)(nil)
	_ ObjectStorageProvider = (*FakeObjectStorageProvider)(nil)
	_ RouteProvider         = (*FakeRouteProvider)(nil)
	_ SecretProvider        = (*FakeSecretProvider)(nil)
	_ MeterProvider         = (*FakeMeterProvider)(nil)
	_ NotificationProvider  = (*FakeNotificationProvider)(nil)
	_ AIProvider            = (*FakeAIProvider)(nil)
)
