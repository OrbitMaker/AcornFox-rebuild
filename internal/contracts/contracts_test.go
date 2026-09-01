package contracts

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

func providerErrorCode(t *testing.T, err error, want ErrorCode) *ProviderError {
	t.Helper()
	if err == nil {
		t.Fatalf("expected provider error %q", want)
	}
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) {
		t.Fatalf("expected ProviderError, got %T: %v", err, err)
	}
	if providerErr.Code != want {
		t.Fatalf("expected provider error %q, got %q (%v)", want, providerErr.Code, err)
	}
	if providerErr.Details["evidence_ref"] == "" || providerErr.Details["log_ref"] == "" {
		t.Fatalf("provider error did not carry evidence/log references: %#v", providerErr)
	}
	return providerErr
}

func assertEvidence(t *testing.T, evidence Evidence, minRefs int) {
	t.Helper()
	if !evidence.Redacted || evidence.Digest == "" || len(evidence.Refs) < minRefs {
		t.Fatalf("incomplete redacted evidence: %#v", evidence)
	}
	for _, ref := range evidence.Refs {
		if err := ref.Validate(); err != nil {
			t.Fatalf("invalid evidence ref: %v", err)
		}
	}
}

func validBuildRequest(key string) BuildRequest {
	source := domain.SourceRevision{ID: "src_1", ApplicationID: "app_1", Kind: domain.SourceUpload, Locator: "upload://fixture", ContentDigest: "sha256:" + strings.Repeat("1", 64), WorkspaceRef: "/immutable/src_1", CreatedAt: time.Unix(1, 0).UTC(), Immutable: true}
	return BuildRequest{
		BuildID:   domain.ID("build_1"),
		Plan:      domain.BuildPlan{ID: domain.ID("plan_1"), SourceRevisionID: domain.ID("src_1"), SourceDigest: source.ContentDigest, ServiceName: "web", Kind: domain.BuildDockerfile, ContextPath: ".", DockerfilePath: "Dockerfile", TargetRepository: "open-card.local/apps/web", Output: domain.BuildOutputContract{Format: domain.BuildOutputOCI, Retention: domain.BuildRetentionPersist, StorageKey: "app_1/src_1/web"}, IdempotencyKey: key},
		Source:    source,
		Operation: OperationContext{IdempotencyKey: key},
	}
}

func validImage() domain.ImageDigest {
	return domain.ImageDigest{Repository: "example/web", Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", ResolvedTag: "stable"}
}

func TestCT_BUILD_003_NetworkPolicyIsOfflineByDefaultAndDigestBoundForControlledEgress(t *testing.T) {
	validDigest := "sha256:" + strings.Repeat("a", 64)
	for name, policy := range map[string]NetworkPolicy{
		"empty_defaults_offline": {},
		"explicit_offline":       {Mode: NetworkModeOffline},
		"controlled":             {Mode: NetworkModeControlledEgressV1, WorkerPolicyDigest: validDigest},
	} {
		t.Run(name, func(t *testing.T) {
			if err := policy.Validate(); err != nil {
				t.Fatalf("valid policy rejected: %v", err)
			}
		})
	}
	for name, policy := range map[string]NetworkPolicy{
		"unknown_mode":          {Mode: "default"},
		"offline_policy_digest": {Mode: NetworkModeOffline, WorkerPolicyDigest: validDigest},
		"controlled_empty":      {Mode: NetworkModeControlledEgressV1},
		"controlled_malformed":  {Mode: NetworkModeControlledEgressV1, WorkerPolicyDigest: "sha256:ABC"},
		"cidr_exception":        {Mode: NetworkModeControlledEgressV1, WorkerPolicyDigest: validDigest, AllowedCIDRs: []string{"10.0.0.0/8"}},
		"metadata_exception":    {Mode: NetworkModeControlledEgressV1, WorkerPolicyDigest: validDigest, AllowMetadata: true},
	} {
		t.Run(name, func(t *testing.T) {
			if err := policy.Validate(); err == nil {
				t.Fatal("unsafe network policy was accepted")
			}
		})
	}
}

func TestCT_OBJECT_001_ObjectStorageCapabilityFailsClosed(t *testing.T) {
	provider := NewFakeObjectStorageProvider(false)
	operation := OperationContext{IdempotencyKey: "object-1"}
	if _, err := provider.Put(context.Background(), "evidence/one", []byte("not-sensitive"), operation); err == nil {
		t.Fatal("expected unsupported object storage capability")
	} else if !IsUnsupported(err) {
		t.Fatalf("expected unsupported_capability, got %T %v", err, err)
	}
}

func TestCT_OBJECT_001_EnabledObjectStorageFakeWorks(t *testing.T) {
	provider := NewFakeObjectStorageProvider(true)
	operation := OperationContext{IdempotencyKey: "object-1"}
	if _, err := provider.Put(context.Background(), "evidence/one", []byte("value"), operation); err != nil {
		t.Fatal(err)
	}
	value, evidence, err := provider.Get(context.Background(), "evidence/one", OperationContext{IdempotencyKey: "object-2"})
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "value" || !evidence.Redacted {
		t.Fatalf("unexpected object result: %q %#v", value, evidence)
	}
}

func TestCT_SOURCE_001_FakeSourceProviderIsIdempotent(t *testing.T) {
	provider := NewFakeSourceProvider()
	request := PrepareSourceRequest{ApplicationID: "app-1", Kind: "upload", Locator: "upload.tar.gz", ContentDigest: "sha256:source", WorkspaceRef: "workspace-1", Operation: OperationContext{IdempotencyKey: "source-1"}}
	first, err := provider.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision.ID != second.Revision.ID || first.Revision.ContentDigest != second.Revision.ContentDigest {
		t.Fatalf("source provider was not idempotent: %#v %#v", first, second)
	}
}

func TestCT_PROVIDER_001_MetadataAndCapabilityListAreDeterministic(t *testing.T) {
	metadata := ProviderMetadata{Name: "fake", Version: "1", ContractVersion: ContractAPIVersion, Capabilities: NewCapabilitySet(CapabilityRuntimeObserve, CapabilityBuild, CapabilitySourcePrepare)}
	if err := metadata.Validate(); err != nil {
		t.Fatal(err)
	}
	list := metadata.Capabilities.List()
	for i := 1; i < len(list); i++ {
		if list[i] < list[i-1] {
			t.Fatalf("capability list is not sorted: %#v", list)
		}
	}
	if err := metadata.Supports(CapabilityRouteManage); err == nil || !IsUnsupported(err) {
		t.Fatalf("expected unsupported route capability, got %v", err)
	}
}

func TestCT_BUILD_001_FakeBuildIsIdempotentAndEvidenceBacked(t *testing.T) {
	provider := NewFakeBuildProvider(true)
	request := validBuildRequest("build-1")
	first, err := provider.Build(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.Build(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Build.ID != second.Build.ID || first.Artifact == nil || second.Artifact == nil || first.Artifact.Image.Digest != second.Artifact.Image.Digest {
		t.Fatalf("build retry created a different result: %#v %#v", first, second)
	}
	if first.Build.Status != domain.BuildSucceeded || first.LogRef == "" {
		t.Fatalf("build result is not a successful immutable artifact: %#v", first)
	}
	assertEvidence(t, first.Evidence, 3)
	if len(first.Artifact.Evidence) < 3 {
		t.Fatalf("artifact evidence refs missing: %#v", first.Artifact)
	}

	failing := NewFakeBuildProvider(true)
	failing.Behavior = FakeProviderBehavior{FailureCode: ErrCapacity, FailureMessage: "capacity unavailable", FailureRetry: RetryBackoff, FailureRetryable: true}
	providerErrorCode(t, mustBuildError(failing, request), ErrCapacity)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	providerErrorCode(t, mustBuildError(provider, BuildRequest{BuildID: request.BuildID, Plan: request.Plan, Source: request.Source, Operation: OperationContext{IdempotencyKey: "build-cancel"}}, ctx), ErrCancelled)

	timeoutProvider := NewFakeBuildProvider(true)
	timeoutProvider.Behavior.Delay = 50 * time.Millisecond
	deadlineCtx, deadlineCancel := context.WithTimeout(context.Background(), 2*time.Millisecond)
	defer deadlineCancel()
	providerErrorCode(t, mustBuildError(timeoutProvider, request, deadlineCtx), ErrTimeout)

	cancelProvider := NewFakeBuildProvider(true)
	if err := cancelProvider.Cancel(context.Background(), OperationContext{IdempotencyKey: "build-cleanup"}); err != nil {
		t.Fatal(err)
	}
	providerErrorCode(t, mustBuildError(cancelProvider, BuildRequest{BuildID: request.BuildID, Plan: request.Plan, Source: request.Source, Operation: OperationContext{IdempotencyKey: "build-cleanup"}}), ErrCancelled)
}

func TestCT_BUILD_004_FakeBuildRejectsControlledEgressAndKeepsItsOperationTableEmpty(t *testing.T) {
	provider := NewFakeBuildProvider(true)
	request := validBuildRequest("controlled-fake")
	request.Network = NetworkPolicy{Mode: NetworkModeControlledEgressV1, WorkerPolicyDigest: "sha256:" + strings.Repeat("a", 64)}
	providerErrorCode(t, mustBuildError(provider, request), ErrForbidden)
	provider.mu.Lock()
	attempts := provider.attempts[request.Operation.IdempotencyKey]
	_, recorded := provider.request[request.Operation.IdempotencyKey]
	provider.mu.Unlock()
	if attempts != 0 || recorded {
		t.Fatalf("controlled egress changed fake operation state: attempts=%d recorded=%t", attempts, recorded)
	}

	request.Network.AllowedCIDRs = []string{"10.0.0.0/8"}
	providerErrorCode(t, mustBuildError(provider, request), ErrValidation)
}

func mustBuildError(provider *FakeBuildProvider, request BuildRequest, contexts ...context.Context) error {
	ctx := context.Background()
	if len(contexts) > 0 {
		ctx = contexts[0]
	}
	_, err := provider.Build(ctx, request)
	return err
}

func TestCT_IMAGE_001_FakeImagePinsDigestAndProtectsDeletion(t *testing.T) {
	provider := NewFakeImageStore(true)
	request := ImageResolveRequest{Repository: "example/web", Tag: "stable", Operation: OperationContext{IdempotencyKey: "image-resolve"}}
	first, err := provider.Resolve(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.Resolve(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Image != second.Image || first.Image.ResolvedTag != "stable" || first.Image.Digest == "" {
		t.Fatalf("tag was not resolved to one immutable digest: %#v %#v", first, second)
	}
	assertEvidence(t, first.Evidence, 1)
	if _, err := provider.Pull(context.Background(), first.Image, OperationContext{IdempotencyKey: "image-pull"}); err != nil {
		t.Fatal(err)
	}
	if err := provider.Protect(first.Image); err != nil {
		t.Fatal(err)
	}
	providerErrorCode(t, provider.Delete(context.Background(), first.Image, OperationContext{IdempotencyKey: "image-delete"}), ErrConflict)

	provider.SetProtectedRepository("example/other", true)
	other := validImage()
	other.Repository = "example/other"
	providerErrorCode(t, provider.Delete(context.Background(), other, OperationContext{IdempotencyKey: "image-delete-other"}), ErrConflict)
	providerErrorCode(t, NewFakeImageStore(false).Delete(context.Background(), first.Image, OperationContext{IdempotencyKey: "image-disabled"}), ErrUnsupportedCapability)
}

func TestCT_RUNTIME_001_FakeRuntimeLifecycleIsIdempotent(t *testing.T) {
	provider := NewFakeRuntimeDriver(true)
	spec := RuntimeSpec{ApplicationID: domain.ID("app_1"), EnvironmentID: domain.ID("env_1"), ReleaseID: domain.ID("rel_1"), ServiceName: "web", Image: validImage(), Port: 8080}
	deployRequest := DeployRequest{DeploymentID: domain.ID("dep_1234567890abcdef"), Spec: spec, Operation: OperationContext{IdempotencyKey: "runtime-deploy"}}
	first, err := provider.Deploy(context.Background(), deployRequest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.Deploy(context.Background(), deployRequest)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("deploy retry created a second deployment: %#v %#v", first, second)
	}
	observation, err := provider.Observe(context.Background(), ObserveRequest{DeploymentID: first.ID, Operation: OperationContext{IdempotencyKey: "runtime-observe"}})
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Healthy || observation.Status != string(domain.DeploymentRuntimeReady) {
		t.Fatalf("unexpected runtime observation: %#v", observation)
	}
	assertEvidence(t, observation.Evidence, 1)
	logs, err := provider.Logs(context.Background(), LogsRequest{DeploymentID: first.ID, Operation: OperationContext{IdempotencyKey: "runtime-logs"}})
	if err != nil {
		t.Fatal(err)
	}
	if line, ok := <-logs; !ok || !strings.Contains(line, "fake runtime log") {
		t.Fatalf("missing runtime log line: %q %v", line, ok)
	}
	if err := provider.Restart(context.Background(), RestartRequest{DeploymentID: first.ID, Operation: OperationContext{IdempotencyKey: "runtime-restart"}}); err != nil {
		t.Fatal(err)
	}
	if err := provider.Restart(context.Background(), RestartRequest{DeploymentID: first.ID, Operation: OperationContext{IdempotencyKey: "runtime-restart"}}); err != nil {
		t.Fatal(err)
	}
	if err := provider.Scale(context.Background(), ScaleRequest{DeploymentID: first.ID, Replicas: 2, Operation: OperationContext{IdempotencyKey: "runtime-scale"}}); err != nil {
		t.Fatal(err)
	}
	rolledBack, err := provider.Rollback(context.Background(), RollbackRequest{DeploymentID: first.ID, ReleaseID: domain.ID("rel_0"), Operation: OperationContext{IdempotencyKey: "runtime-rollback"}})
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.Status != domain.DeploymentRolledBack {
		t.Fatalf("rollback did not produce rolled_back state: %#v", rolledBack)
	}
	if err := provider.Destroy(context.Background(), DestroyRequest{DeploymentID: first.ID, Operation: OperationContext{IdempotencyKey: "runtime-destroy"}}); err != nil {
		t.Fatal(err)
	}
	stopped, err := provider.Observe(context.Background(), ObserveRequest{DeploymentID: first.ID, Operation: OperationContext{IdempotencyKey: "runtime-observe-stopped"}})
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Healthy || stopped.Status != string(domain.DeploymentStopped) {
		t.Fatalf("destroy did not make runtime unhealthy/stopped: %#v", stopped)
	}
	providerErrorCode(t, NewFakeRuntimeDriver(false).Restart(context.Background(), RestartRequest{DeploymentID: first.ID, Operation: OperationContext{IdempotencyKey: "runtime-disabled"}}), ErrUnsupportedCapability)
}

func TestCT_VOLUME_001_FakeVolumeRetainsByDefaultAndRequiresConfirmation(t *testing.T) {
	provider := NewFakeVolumeProvider(true)
	volume := VolumeSpec{Name: "data", MountPath: "/var/lib/app", SizeBytes: 1024}
	created, evidence, err := provider.Create(context.Background(), VolumeRequest{Volume: volume, Operation: OperationContext{IdempotencyKey: "volume-create"}})
	if err != nil {
		t.Fatal(err)
	}
	if created != volume {
		t.Fatalf("volume spec changed: %#v", created)
	}
	assertEvidence(t, evidence, 1)
	if err := provider.Attach(context.Background(), VolumeRequest{Volume: volume, Operation: OperationContext{IdempotencyKey: "volume-attach"}}); err != nil {
		t.Fatal(err)
	}
	if err := provider.Detach(context.Background(), VolumeRequest{Volume: volume, Operation: OperationContext{IdempotencyKey: "volume-detach"}}); err != nil {
		t.Fatal(err)
	}
	if err := provider.Retain(context.Background(), VolumeRequest{Volume: volume, Operation: OperationContext{IdempotencyKey: "volume-retain"}}); err != nil {
		t.Fatal(err)
	}
	destroy := VolumeRequest{Volume: volume, Operation: OperationContext{IdempotencyKey: "volume-destroy"}}
	providerErrorCode(t, provider.Destroy(context.Background(), destroy), ErrUnauthorized)
	destroy.ConfirmationToken = "confirm-volume-destroy"
	if err := provider.Destroy(context.Background(), destroy); err != nil {
		t.Fatal(err)
	}
	providerErrorCode(t, NewFakeVolumeProvider(false).Attach(context.Background(), VolumeRequest{Volume: volume, Operation: OperationContext{IdempotencyKey: "volume-disabled"}}), ErrUnsupportedCapability)
}

func TestCT_ROUTE_001_FakeRouteHasDesiredActualEvidenceAndIdempotency(t *testing.T) {
	provider := NewFakeRouteProvider(true)
	route := RouteSpec{Host: "app.example.test", Path: "/", DeploymentID: domain.ID("dep_1"), ServiceName: "web", Port: 8080, CertificateRef: "cert_1", Verified: true}
	request := RouteRequest{Route: route, Operation: OperationContext{IdempotencyKey: "route-apply"}}
	first, evidence, err := provider.Apply(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, retryEvidence, err := provider.Apply(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || !first.Serving || !first.Verified {
		t.Fatalf("route apply is not stable/serving: %#v %#v", first, second)
	}
	assertEvidence(t, evidence, 2)
	assertEvidence(t, retryEvidence, 2)
	observation, err := provider.Observe(context.Background(), RouteRequest{Route: route, Operation: OperationContext{IdempotencyKey: "route-observe"}})
	if err != nil {
		t.Fatal(err)
	}
	if observation.Kind != "route.actual" || len(observation.Evidence) < 2 {
		t.Fatalf("route observation lacks actual/desired evidence: %#v", observation)
	}
	if _, err := provider.Rebuild(context.Background(), OperationContext{IdempotencyKey: "route-rebuild"}); err != nil {
		t.Fatal(err)
	}
	if err := provider.Remove(context.Background(), RouteRequest{Route: route, Operation: OperationContext{IdempotencyKey: "route-remove"}}); err != nil {
		t.Fatal(err)
	}
	providerErrorCode(t, mustObserveRoute(provider, route), ErrNotFound)
}

func mustObserveRoute(provider *FakeRouteProvider, route RouteSpec) error {
	_, err := provider.Observe(context.Background(), RouteRequest{Route: route, Operation: OperationContext{IdempotencyKey: "route-after-remove"}})
	return err
}

func TestCT_SECRET_001_FakeSecretNeverReturnsPlaintextAndMountsAreRevocable(t *testing.T) {
	provider := NewFakeSecretProvider(true)
	secretValue := []byte("super-secret-canary")
	reference := domain.SecretReference{ID: domain.ID("secret_1"), Name: "registry", Provider: "fake"}
	request := SecretRequest{Reference: reference, Value: secretValue, Operation: OperationContext{IdempotencyKey: "secret-store"}}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), string(secretValue)) || strings.Contains(string(encoded), "value") {
		t.Fatalf("secret value leaked into serialized request: %s", encoded)
	}
	stored, err := provider.Store(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if stored != reference {
		t.Fatalf("store returned a different reference: %#v", stored)
	}
	mountRequest := SecretRequest{Reference: stored, Operation: OperationContext{IdempotencyKey: "secret-mount"}}
	mount, err := provider.Mount(context.Background(), mountRequest)
	if err != nil {
		t.Fatal(err)
	}
	retryMount, err := provider.Mount(context.Background(), mountRequest)
	if err != nil {
		t.Fatal(err)
	}
	if mount.MountID == "" || mount.MountID != retryMount.MountID || mount.Reference != reference {
		t.Fatalf("mount is not idempotent/reference-only: %#v %#v", mount, retryMount)
	}
	if err := provider.Revoke(context.Background(), mount, OperationContext{IdempotencyKey: "secret-revoke"}); err != nil {
		t.Fatal(err)
	}
	providerErrorCode(t, mustMount(provider, mountRequest), ErrConflict)
}

func mustMount(provider *FakeSecretProvider, request SecretRequest) error {
	_, err := provider.Mount(context.Background(), request)
	return err
}

func TestCT_METER_001_FakeMeterDeduplicatesAndQueriesWindow(t *testing.T) {
	provider := NewFakeMeterProvider(true)
	start := time.Unix(100, 0).UTC()
	samples := []MeterSample{
		{ID: "sample-1", ApplicationID: domain.ID("app_1"), EnvironmentID: "env_1", DeploymentID: "dep_1", ServiceName: "web", ReleaseID: domain.ID("rel_1"), At: start.Add(time.Minute), CPUMillicores: 250, CPUSeconds: 1.5, MemoryBytes: 10, DiskBytes: 4, NetworkRxBytes: 100, NetworkTxBytes: 50, RuntimeSeconds: 60, LimitCPUMillicores: 500, LimitMemoryBytes: 100},
		{ID: "sample-1", ApplicationID: domain.ID("app_1"), EnvironmentID: "env_1", DeploymentID: "dep_1", ServiceName: "web", ReleaseID: domain.ID("rel_1"), At: start.Add(time.Minute), CPUMillicores: 250, CPUSeconds: 1.5, MemoryBytes: 10, DiskBytes: 4, NetworkRxBytes: 100, NetworkTxBytes: 50, RuntimeSeconds: 60, LimitCPUMillicores: 500, LimitMemoryBytes: 100},
		{ID: "sample-late", ApplicationID: domain.ID("app_1"), EnvironmentID: "env_1", DeploymentID: "dep_1", ServiceName: "web", ReleaseID: domain.ID("rel_1"), At: start.Add(2 * time.Minute), CPUMillicores: 300, CPUSeconds: 2, MemoryBytes: 20, DiskBytes: 8, NetworkRxBytes: 200, NetworkTxBytes: 75, RuntimeSeconds: 60, LimitCPUMillicores: 500, LimitMemoryBytes: 100},
		{ID: "sample-outside", ApplicationID: domain.ID("app_1"), ServiceName: "web", ReleaseID: domain.ID("rel_1"), At: start.Add(2 * time.Hour), CPUSeconds: 99, MemoryBytes: 99},
	}
	if err := provider.Ingest(context.Background(), samples, OperationContext{IdempotencyKey: "meter-ingest"}); err != nil {
		t.Fatal(err)
	}
	if err := provider.Ingest(context.Background(), samples, OperationContext{IdempotencyKey: "meter-ingest"}); err != nil {
		t.Fatal(err)
	}
	if len(provider.Samples) != 3 {
		t.Fatalf("duplicate sample was not removed: %d samples", len(provider.Samples))
	}
	query, err := provider.Query(context.Background(), MeterQuery{ApplicationID: domain.ID("app_1"), ServiceName: "web", From: start, To: start.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(query) != 1 || query[0].SampleCount != 2 || query[0].AverageCPUMillicores != 275 || query[0].AverageMemoryBytes != 15 || query[0].AverageDiskBytes != 6 || query[0].TrendCPUMillicoresPerSecond != float64(50)/60 || query[0].CPUSeconds != 3.5 || query[0].MemoryByteSeconds != 30 || query[0].DiskByteSeconds != 12 || query[0].NetworkRxBytes != 300 || query[0].NetworkTxBytes != 125 || query[0].RuntimeSeconds != 120 || query[0].PeakCPUMillicores != 300 || query[0].LimitCPUMillicores != 500 {
		t.Fatalf("unexpected usage aggregate: %#v", query)
	}
	changed := samples[0]
	changed.CPUSeconds = 9
	providerErrorCode(t, provider.Ingest(context.Background(), []MeterSample{changed}, OperationContext{IdempotencyKey: "meter-conflict"}), ErrConflict)
	providerErrorCode(t, mustMeterQuery(provider, MeterQuery{ApplicationID: domain.ID("app_1"), From: start.Add(time.Hour), To: start}), ErrInvalidArgument)
}

func mustMeterQuery(provider *FakeMeterProvider, query MeterQuery) error {
	_, err := provider.Query(context.Background(), query)
	return err
}

func TestCT_NOTIFY_001_FakeNotificationRetriesOnceAndDeduplicatesEvent(t *testing.T) {
	provider := NewFakeNotificationProvider(true)
	provider.Behavior = FakeProviderBehavior{FailureCode: ErrUnavailable, FailureMessage: "receiver unavailable", FailureRetry: RetryBackoff, FailureRetryable: true, FailureAttempts: 1}
	notification := Notification{EventID: domain.ID("event_1"), EventType: "deployment.succeeded", Payload: map[string]any{"secret": "must-not-be-retained"}, OccurredAt: time.Unix(100, 0).UTC()}
	operation := OperationContext{IdempotencyKey: "notify-1"}
	providerErrorCode(t, provider.Send(context.Background(), notification, operation), ErrUnavailable)
	if err := provider.Send(context.Background(), notification, operation); err != nil {
		t.Fatal(err)
	}
	if err := provider.Send(context.Background(), notification, OperationContext{IdempotencyKey: "notify-retry"}); err != nil {
		t.Fatal(err)
	}
	if len(provider.Sent) != 1 || provider.Attempts[notification.EventID] != 3 {
		t.Fatalf("notification retry/dedupe state is wrong: sent=%d attempts=%d", len(provider.Sent), provider.Attempts[notification.EventID])
	}
	if _, leaked := provider.Sent[0].Payload["secret"]; leaked {
		t.Fatalf("notification payload was retained instead of redacted: %#v", provider.Sent[0].Payload)
	}
	providerErrorCode(t, provider.Send(context.Background(), Notification{EventID: notification.EventID, EventType: "different", OccurredAt: notification.OccurredAt}, OperationContext{IdempotencyKey: "notify-different"}), ErrConflict)
	provider.Behavior = FakeProviderBehavior{}
	if err := provider.Test(context.Background(), OperationContext{IdempotencyKey: "notify-test"}); err != nil {
		t.Fatal(err)
	}
}

func TestCT_AI_001_FakeAIIsStructuredBoundedAndDisableable(t *testing.T) {
	provider := NewFakeAIProvider(true)
	request := AIRequest{TaskType: "diagnose_build", Context: domain.AIContextPackage{ID: domain.ID("ctx_1"), ApplicationID: domain.ID("app_1"), TaskType: "diagnose_build", Profile: "local", Scope: []string{"build/log-window"}, ObjectVersions: map[string]string{"build": "v1"}, SourceRefs: []domain.EvidenceRef{{ID: "ev_ctx_1", Kind: "build_log", Digest: "sha256:context"}}, ManifestDigest: "sha256:context-manifest", Bytes: 128, Authorized: true, Redacted: true, UntrustedData: true, TemplateVersion: "v1"}, Budget: TokenBudget{MaxTokens: 64}, Operation: OperationContext{IdempotencyKey: "ai-1"}}
	first, err := provider.StructuredCall(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.StructuredCall(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Invocation.ID != second.Invocation.ID || first.Plan.ID != second.Plan.ID || first.Invocation.Status != "succeeded" || len(first.Plan.Actions) != 1 {
		t.Fatalf("structured AI result is not stable/complete: %#v %#v", first, second)
	}
	assertEvidence(t, first.Evidence, 2)
	if !first.Evidence.Redacted || first.Invocation.Provider != "fake-ai" || first.Invocation.Model == "" || first.Plan.Actions[0].ValidationID == "" {
		t.Fatalf("AI result missing bounded metadata: %#v", first)
	}
	provider.Behavior.Delay = 20 * time.Millisecond
	deadlineCtx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	providerErrorCode(t, mustAIError(provider, request, deadlineCtx, "ai-timeout"), ErrTimeout)
	providerErrorCode(t, mustAIError(NewFakeAIProvider(false), request, context.Background(), "ai-disabled"), ErrUnsupportedCapability)
}

func mustAIError(provider *FakeAIProvider, request AIRequest, ctx context.Context, key string) error {
	request.Operation.IdempotencyKey = key
	_, err := provider.StructuredCall(ctx, request)
	return err
}
