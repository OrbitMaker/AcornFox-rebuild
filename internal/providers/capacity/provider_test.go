package capacity

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
)

func fixedReader(value HostCapacity) ReaderFunc {
	return func(context.Context, string) (HostCapacity, error) { return value, nil }
}

func hostCapacity() HostCapacity {
	return HostCapacity{
		TotalCPUMillis:       2_000,
		AvailableCPUMillis:   2_000,
		TotalMemoryBytes:     2_000,
		AvailableMemoryBytes: 2_000,
		TotalDiskBytes:       2_000,
		AvailableDiskBytes:   2_000,
	}
}

func capacityProvider(t *testing.T, reader Reader, configure func(*Config)) *Provider {
	t.Helper()
	config := Config{Reader: reader, DiskPath: "/private/test-disk", LeaseTTL: time.Minute}
	if configure != nil {
		configure(&config)
	}
	provider, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func capacityRequest(scope contracts.CapacityScope, key string, cpu, memory, disk int64, ports int) contracts.CapacityRequest {
	return contracts.CapacityRequest{
		Scope:     scope,
		Resources: contracts.ResourceLimits{CPUMillis: cpu, MemoryBytes: memory, DiskBytes: disk},
		HostPorts: ports,
		Operation: contracts.OperationContext{IdempotencyKey: key},
	}
}

func providerErrorCode(t *testing.T, err error, code contracts.ErrorCode) *contracts.ProviderError {
	t.Helper()
	if err == nil {
		t.Fatalf("expected provider error %s", code)
	}
	var providerErr *contracts.ProviderError
	if !errors.As(err, &providerErr) {
		t.Fatalf("expected ProviderError, got %T: %v", err, err)
	}
	if providerErr.Code != code {
		t.Fatalf("expected code %s, got %s (%v)", code, providerErr.Code, err)
	}
	return providerErr
}

func TestPreflightScopeReserveAndRedactedEvidence(t *testing.T) {
	provider := capacityProvider(t, fixedReader(hostCapacity()), func(config *Config) {
		config.BuildReserve = contracts.ResourceLimits{CPUMillis: 250, MemoryBytes: 250, DiskBytes: 250}
		config.RuntimeReserve = contracts.ResourceLimits{CPUMillis: 100, MemoryBytes: 100, DiskBytes: 100}
	})

	buildRequest := capacityRequest(contracts.CapacityBuild, "preflight-build", 1_700, 1_700, 1_700, 0)
	snapshot, evidence, err := provider.Preflight(context.Background(), buildRequest)
	if err != nil {
		t.Fatalf("build preflight: %v", err)
	}
	if snapshot.AvailableCPUMillis != 1_750 || snapshot.AvailableMemoryBytes != 1_750 || snapshot.AvailableDiskBytes != 1_750 {
		t.Fatalf("scope reserve was not applied: %#v", snapshot)
	}
	if snapshot.ReservedCPUMillis != 250 || snapshot.ReservedMemoryBytes != 250 || snapshot.ReservedDiskBytes != 250 {
		t.Fatalf("scope reserve was not reported: %#v", snapshot)
	}
	if !evidence.Redacted || len(evidence.Refs) != 1 || !strings.HasPrefix(evidence.Digest, "sha256:") {
		t.Fatalf("evidence is not redacted and digest-backed: %#v", evidence)
	}
	if strings.Contains(evidence.Summary, "/private/test-disk") || strings.Contains(evidence.Summary, "preflight-build") {
		t.Fatalf("evidence exposed host/request data: %#v", evidence)
	}

	runtimeRequest := capacityRequest(contracts.CapacityRuntime, "preflight-runtime", 1_900, 1_900, 1_900, 0)
	runtimeSnapshot, _, err := provider.Preflight(context.Background(), runtimeRequest)
	if err != nil {
		t.Fatalf("runtime preflight: %v", err)
	}
	if runtimeSnapshot.AvailableCPUMillis != 1_900 || runtimeSnapshot.ReservedCPUMillis != 100 {
		t.Fatalf("runtime reserve was not scoped: %#v", runtimeSnapshot)
	}
}

func TestPreflightClassifiesCPUAndMemoryAndDiskShortage(t *testing.T) {
	provider := capacityProvider(t, fixedReader(hostCapacity()), nil)
	tests := []struct {
		name     string
		request  contracts.CapacityRequest
		resource string
	}{
		{name: "cpu", request: capacityRequest(contracts.CapacityRuntime, "short-cpu", 2_001, 0, 0, 0), resource: "cpu"},
		{name: "memory", request: capacityRequest(contracts.CapacityRuntime, "short-memory", 0, 2_001, 0, 0), resource: "memory"},
		{name: "disk", request: capacityRequest(contracts.CapacityRuntime, "short-disk", 0, 0, 2_001, 0), resource: "disk"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, evidence, err := provider.Preflight(context.Background(), test.request)
			providerErr := providerErrorCode(t, err, contracts.ErrCapacity)
			if providerErr.Details["resource"] != test.resource {
				t.Fatalf("unexpected shortage classification: %#v", providerErr.Details)
			}
			if providerErr.Details["evidence_ref"] == "" || !evidence.Redacted {
				t.Fatalf("capacity failure lost redacted evidence: %#v %#v", providerErr, evidence)
			}
			if strings.Contains(err.Error(), "/private/test-disk") || strings.Contains(err.Error(), test.request.Operation.IdempotencyKey) {
				t.Fatalf("capacity error exposed sensitive request/host data: %v", err)
			}
		})
	}
}

func TestPortShortageIsCapacityErrorWithoutLeaseLeak(t *testing.T) {
	provider := capacityProvider(t, fixedReader(hostCapacity()), func(config *Config) {
		config.PortAllocator = PortAllocatorFunc(func(context.Context) (net.Listener, error) {
			return nil, errors.New("bind: address already in use")
		})
	})
	request := capacityRequest(contracts.CapacityRuntime, "short-port-preflight", 0, 0, 0, 1)
	_, _, err := provider.Preflight(context.Background(), request)
	providerErrorCode(t, err, contracts.ErrCapacity)
	if provider.ActiveLeaseCount() != 0 {
		t.Fatalf("port preflight failure created a lease: %d", provider.ActiveLeaseCount())
	}

	reserveRequest := capacityRequest(contracts.CapacityRuntime, "short-port-reserve", 0, 0, 0, 1)
	_, err = provider.Reserve(context.Background(), reserveRequest)
	providerErrorCode(t, err, contracts.ErrCapacity)
	if provider.ActiveLeaseCount() != 0 {
		t.Fatalf("port reserve failure leaked a lease: %d", provider.ActiveLeaseCount())
	}
}

func TestReserveIsAtomicAcrossConcurrentRequests(t *testing.T) {
	provider := capacityProvider(t, fixedReader(hostCapacity()), nil)
	request := func(index int) contracts.CapacityRequest {
		return capacityRequest(contracts.CapacityRuntime, "concurrent-"+string(rune('a'+index)), 1_100, 1_100, 1_100, 0)
	}
	var wait sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	capacityFailures := 0
	var unexpected []error
	for index := 0; index < 16; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, err := provider.Reserve(context.Background(), request(index))
			if err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
				return
			}
			var providerErr *contracts.ProviderError
			if !errors.As(err, &providerErr) || providerErr.Code != contracts.ErrCapacity {
				mu.Lock()
				unexpected = append(unexpected, err)
				mu.Unlock()
				return
			}
			mu.Lock()
			capacityFailures++
			mu.Unlock()
		}(index)
	}
	wait.Wait()
	if successes != 1 || capacityFailures != 15 || len(unexpected) != 0 || provider.ActiveLeaseCount() != 1 {
		t.Fatalf("reservation overcommit or leak: successes=%d failures=%d unexpected=%v active=%d", successes, capacityFailures, unexpected, provider.ActiveLeaseCount())
	}
}

func TestPortActivationRetainsResourcesAndReleaseIsIdempotent(t *testing.T) {
	provider := capacityProvider(t, fixedReader(hostCapacity()), nil)
	request := capacityRequest(contracts.CapacityRuntime, "port-reserve", 500, 500, 500, 1)
	lease, err := provider.Reserve(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if lease.HostPort == 0 || provider.ActiveLeaseCount() != 1 {
		t.Fatalf("port lease was not retained: %#v", lease)
	}
	blocked, err := net.Listen("tcp4", "127.0.0.1:"+itoa(lease.HostPort))
	if err == nil {
		_ = blocked.Close()
		t.Fatalf("reserved port could be rebound before activation")
	}

	if err := provider.Activate(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "port-activate"}); err != nil {
		t.Fatal(err)
	}
	available, err := net.Listen("tcp4", "127.0.0.1:"+itoa(lease.HostPort))
	if err != nil {
		t.Fatalf("activated port was not released for Docker bind: %v", err)
	}
	_ = available.Close()
	if provider.ActiveLeaseCount() != 1 {
		t.Fatalf("activation released resource accounting: %d", provider.ActiveLeaseCount())
	}
	if err := provider.Activate(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "port-activate"}); err != nil {
		t.Fatalf("activate was not idempotent: %v", err)
	}

	release := contracts.OperationContext{IdempotencyKey: "port-release"}
	if err := provider.Release(context.Background(), lease, release); err != nil {
		t.Fatal(err)
	}
	if err := provider.Release(context.Background(), lease, release); err != nil {
		t.Fatalf("release was not idempotent: %v", err)
	}
	if provider.ActiveLeaseCount() != 0 {
		t.Fatalf("release leaked resource accounting: %d", provider.ActiveLeaseCount())
	}
	otherLease := lease
	otherLease.ID = "cap_other"
	providerErrorCode(t, provider.Release(context.Background(), otherLease, release), contracts.ErrConflict)
}

func TestLeaseExpiryClosesPortAndReturnsCapacity(t *testing.T) {
	clock := time.Unix(100, 0).UTC()
	var clockMu sync.Mutex
	now := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return clock
	}
	provider := capacityProvider(t, fixedReader(hostCapacity()), func(config *Config) {
		config.LeaseTTL = time.Minute
		config.Clock = now
	})
	lease, err := provider.Reserve(context.Background(), capacityRequest(contracts.CapacityRuntime, "ttl", 1_900, 1_900, 1_900, 1))
	if err != nil {
		t.Fatal(err)
	}
	clockMu.Lock()
	clock = clock.Add(2 * time.Minute)
	clockMu.Unlock()
	if provider.ActiveLeaseCount() != 0 {
		t.Fatalf("expired lease still counted: %d", provider.ActiveLeaseCount())
	}
	available, err := net.Listen("tcp4", "127.0.0.1:"+itoa(lease.HostPort))
	if err != nil {
		t.Fatalf("expired lease leaked port: %v", err)
	}
	_ = available.Close()
	providerErrorCode(t, provider.Activate(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "ttl-activate"}), contracts.ErrTimeout)
	if err := provider.Release(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "ttl-release"}); err != nil {
		t.Fatalf("expired release should be idempotent cleanup: %v", err)
	}
}

func TestActivatedRuntimeLeaseDoesNotExpireBeforeExplicitRelease(t *testing.T) {
	clock := time.Unix(100, 0).UTC()
	provider := capacityProvider(t, fixedReader(hostCapacity()), func(config *Config) { config.LeaseTTL = time.Minute; config.Clock = func() time.Time { return clock } })
	lease, err := provider.Reserve(context.Background(), capacityRequest(contracts.CapacityRuntime, "active-ttl", 500, 500, 500, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Activate(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "active-ttl-activate"}); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(10 * time.Minute)
	if provider.ActiveLeaseCount() != 1 {
		t.Fatal("activated runtime accounting expired while workload was still running")
	}
	if err := provider.Release(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "active-ttl-release"}); err != nil {
		t.Fatal(err)
	}
	if provider.ActiveLeaseCount() != 0 {
		t.Fatal("explicit release did not return activated capacity")
	}
}

func TestOperationKeyConflictAndPreflightIdempotency(t *testing.T) {
	provider := capacityProvider(t, fixedReader(hostCapacity()), nil)
	first := capacityRequest(contracts.CapacityRuntime, "same-preflight", 100, 100, 100, 0)
	one, evidence, err := provider.Preflight(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	two, sameEvidence, err := provider.Preflight(context.Background(), first)
	if err != nil || two != one || sameEvidence.Digest != evidence.Digest {
		t.Fatalf("preflight was not idempotent: %#v %#v %v", two, sameEvidence, err)
	}
	conflict := first
	conflict.Resources.CPUMillis = 101
	_, _, err = provider.Preflight(context.Background(), conflict)
	providerErrorCode(t, err, contracts.ErrConflict)

	lease, err := provider.Reserve(context.Background(), capacityRequest(contracts.CapacityRuntime, "same-reserve", 100, 100, 100, 0))
	if err != nil {
		t.Fatal(err)
	}
	again, err := provider.Reserve(context.Background(), capacityRequest(contracts.CapacityRuntime, "same-reserve", 100, 100, 100, 0))
	if err != nil || again.ID != lease.ID {
		t.Fatalf("reserve was not idempotent: %#v %v", again, err)
	}
	conflict = capacityRequest(contracts.CapacityRuntime, "same-reserve", 101, 100, 100, 0)
	_, err = provider.Reserve(context.Background(), conflict)
	providerErrorCode(t, err, contracts.ErrConflict)
}

func TestMetadataAndValidation(t *testing.T) {
	provider := capacityProvider(t, fixedReader(hostCapacity()), nil)
	metadata := provider.Metadata(context.Background())
	if err := metadata.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := metadata.Supports(contracts.CapabilityCapacityCheck); err != nil {
		t.Fatal(err)
	}
	_, _, err := provider.Preflight(context.Background(), contracts.CapacityRequest{Scope: contracts.CapacityRuntime, Operation: contracts.OperationContext{IdempotencyKey: "invalid"}, HostPorts: 2})
	providerErrorCode(t, err, contracts.ErrInvalidArgument)
	_, err = provider.Reserve(context.Background(), capacityRequest(contracts.CapacityRuntime, "negative", -1, 0, 0, 0))
	providerErrorCode(t, err, contracts.ErrInvalidArgument)
}

func TestSystemReaderReadsLinuxCPUAndMemoryAndStatfs(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SystemReader is a Linux host boundary")
	}
	observation, err := (SystemReader{}).Read(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if observation.TotalCPUMillis <= 0 || observation.AvailableCPUMillis < 0 || observation.TotalMemoryBytes <= 0 || observation.AvailableMemoryBytes < 0 || observation.TotalDiskBytes <= 0 || observation.AvailableDiskBytes < 0 {
		t.Fatalf("system reader returned unusable host capacity: %#v", observation)
	}
	if observation.AvailableCPUMillis > observation.TotalCPUMillis || observation.AvailableMemoryBytes > observation.TotalMemoryBytes || observation.AvailableDiskBytes > observation.TotalDiskBytes {
		t.Fatalf("system reader returned availability above totals: %#v", observation)
	}
}

func itoa(value int) string {
	return strconv.Itoa(value)
}
