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

	"github.com/acornfox/acornfox/internal/contracts"
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

func TestReconcileActiveRestoresAccountingWithoutPortAllocation(t *testing.T) {
	var allocatorCalls int
	provider := capacityProvider(t, fixedReader(hostCapacity()), func(config *Config) {
		config.PortAllocator = PortAllocatorFunc(func(context.Context) (net.Listener, error) {
			allocatorCalls++
			return nil, errors.New("reconcile must not allocate a port")
		})
	})
	lease := activeRuntimeLease("cap_restored", 1_200, 1_200, 1_200, 49152)
	if err := provider.ReconcileActive(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "restore-one"}); err != nil {
		t.Fatal(err)
	}
	if allocatorCalls != 0 || provider.ActiveLeaseCount() != 1 {
		t.Fatalf("reconcile allocated a port or failed to retain accounting: calls=%d active=%d", allocatorCalls, provider.ActiveLeaseCount())
	}

	snapshot, _, err := provider.Preflight(context.Background(), capacityRequest(contracts.CapacityRuntime, "restored-snapshot", 0, 0, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.AvailableCPUMillis != 800 || snapshot.AvailableMemoryBytes != 800 || snapshot.AvailableDiskBytes != 800 {
		t.Fatalf("restored lease was not reflected in capacity snapshot: %#v", snapshot)
	}
	_, err = provider.Reserve(context.Background(), capacityRequest(contracts.CapacityRuntime, "restored-overcommit", 801, 801, 801, 0))
	providerErrorCode(t, err, contracts.ErrCapacity)

	if err := provider.Release(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "restore-release"}); err != nil {
		t.Fatal(err)
	}
	if provider.ActiveLeaseCount() != 0 {
		t.Fatalf("released restored lease remained active: %d", provider.ActiveLeaseCount())
	}
	if _, err := provider.Reserve(context.Background(), capacityRequest(contracts.CapacityRuntime, "restored-after-release", 2_000, 2_000, 2_000, 0)); err != nil {
		t.Fatalf("release did not return restored capacity: %v", err)
	}
}

func TestReconcileActiveIsLeaseIdempotentAndConflictsOnDifferentContent(t *testing.T) {
	provider := capacityProvider(t, fixedReader(hostCapacity()), nil)
	lease := activeRuntimeLease("cap_reconcile_idempotent", 500, 500, 500, 0)
	if err := provider.ReconcileActive(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "reconcile-first"}); err != nil {
		t.Fatal(err)
	}
	if err := provider.ReconcileActive(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "reconcile-replay"}); err != nil {
		t.Fatalf("same recovered lease was not idempotent: %v", err)
	}
	if provider.ActiveLeaseCount() != 1 {
		t.Fatalf("same recovered lease was double counted: %d", provider.ActiveLeaseCount())
	}

	different := lease
	different.Resources.CPUMillis++
	providerErrorCode(t, provider.ReconcileActive(context.Background(), different, contracts.OperationContext{IdempotencyKey: "reconcile-different"}), contracts.ErrConflict)
	providerErrorCode(t, provider.ReconcileActive(context.Background(), activeRuntimeLease("cap_different", 500, 500, 500, 0), contracts.OperationContext{IdempotencyKey: "reconcile-first"}), contracts.ErrConflict)
}

func TestReconcileActiveRetainsExistingOccupancyAndPreventsThirdLease(t *testing.T) {
	provider := capacityProvider(t, fixedReader(hostCapacity()), nil)
	first := activeRuntimeLease("cap_reconcile_first", 1_200, 1_200, 1_200, 0)
	second := activeRuntimeLease("cap_reconcile_second", 800, 800, 800, 0)
	if err := provider.ReconcileActive(context.Background(), first, contracts.OperationContext{IdempotencyKey: "reconcile-capacity-one"}); err != nil {
		t.Fatal(err)
	}
	if err := provider.ReconcileActive(context.Background(), second, contracts.OperationContext{IdempotencyKey: "reconcile-capacity-two"}); err != nil {
		t.Fatal(err)
	}
	_, err := provider.Reserve(context.Background(), capacityRequest(contracts.CapacityRuntime, "reconcile-capacity-third", 1, 1, 1, 0))
	providerErrorCode(t, err, contracts.ErrCapacity)
	if provider.ActiveLeaseCount() != 2 {
		t.Fatalf("restored leases were not retained: %d", provider.ActiveLeaseCount())
	}
}

func TestReconcileActiveAcceptsExistingOccupancyWhenHostAvailabilityIsLower(t *testing.T) {
	provider := capacityProvider(t, fixedReader(HostCapacity{
		TotalCPUMillis:       2_000,
		AvailableCPUMillis:   500,
		TotalMemoryBytes:     2_000,
		AvailableMemoryBytes: 500,
		TotalDiskBytes:       2_000,
		AvailableDiskBytes:   500,
	}), nil)
	lease := activeRuntimeLease("cap_reconcile_low", 1_000, 1_000, 1_000, 0)
	if err := provider.ReconcileActive(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "reconcile-low-host"}); err != nil {
		t.Fatalf("existing workload must remain accounted even after host availability drops: %v", err)
	}
	snapshot, _, err := provider.Preflight(context.Background(), capacityRequest(contracts.CapacityRuntime, "reconcile-low-host-snapshot", 0, 0, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.AvailableCPUMillis != 0 || snapshot.AvailableMemoryBytes != 0 || snapshot.AvailableDiskBytes != 0 {
		t.Fatalf("restored occupancy did not floor future availability: %#v", snapshot)
	}
}

func TestReconcileActiveRejectsInvalidLeaseAndOperation(t *testing.T) {
	provider := capacityProvider(t, fixedReader(hostCapacity()), nil)
	valid := activeRuntimeLease("cap_reconcile_valid", 100, 100, 100, 0)
	tests := []struct {
		name      string
		lease     contracts.CapacityLease
		operation contracts.OperationContext
	}{
		{name: "missing lease id", lease: contracts.CapacityLease{Scope: contracts.CapacityRuntime, Resources: valid.Resources}, operation: contracts.OperationContext{IdempotencyKey: "invalid-id"}},
		{name: "build scope", lease: func() contracts.CapacityLease { item := valid; item.Scope = contracts.CapacityBuild; return item }(), operation: contracts.OperationContext{IdempotencyKey: "invalid-scope"}},
		{name: "zero accounting resource", lease: func() contracts.CapacityLease { item := valid; item.Resources.DiskBytes = 0; return item }(), operation: contracts.OperationContext{IdempotencyKey: "invalid-resource"}},
		{name: "negative resource", lease: func() contracts.CapacityLease { item := valid; item.Resources.MemoryBytes = -1; return item }(), operation: contracts.OperationContext{IdempotencyKey: "negative-resource"}},
		{name: "invalid host port", lease: func() contracts.CapacityLease { item := valid; item.HostPort = 65536; return item }(), operation: contracts.OperationContext{IdempotencyKey: "invalid-port"}},
		{name: "missing operation", lease: valid, operation: contracts.OperationContext{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			providerErrorCode(t, provider.ReconcileActive(context.Background(), test.lease, test.operation), contracts.ErrInvalidArgument)
		})
	}
	if provider.ActiveLeaseCount() != 0 {
		t.Fatalf("invalid reconcile created an active lease: %d", provider.ActiveLeaseCount())
	}
}

func TestReconcileActiveIsRaceSafe(t *testing.T) {
	provider := capacityProvider(t, fixedReader(hostCapacity()), nil)
	lease := activeRuntimeLease("cap_reconcile_race", 500, 500, 500, 0)
	var wait sync.WaitGroup
	var failures []error
	var mu sync.Mutex
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			err := provider.ReconcileActive(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "reconcile-race-" + itoa(index)})
			if err == nil {
				return
			}
			mu.Lock()
			failures = append(failures, err)
			mu.Unlock()
		}(index)
	}
	wait.Wait()
	if len(failures) != 0 || provider.ActiveLeaseCount() != 1 {
		t.Fatalf("concurrent reconcile was not safe: failures=%v active=%d", failures, provider.ActiveLeaseCount())
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

func activeRuntimeLease(id string, cpu, memory, disk int64, hostPort int) contracts.CapacityLease {
	return contracts.CapacityLease{
		ID:        id,
		Scope:     contracts.CapacityRuntime,
		Resources: contracts.ResourceLimits{CPUMillis: cpu, MemoryBytes: memory, DiskBytes: disk},
		HostPort:  hostPort,
		ExpiresAt: time.Unix(1, 0).UTC(),
	}
}

func TestReconcileRetainedRestoresAccountingWithoutPortAllocation(t *testing.T) {
	var allocatorCalls int
	provider := capacityProvider(t, fixedReader(hostCapacity()), func(config *Config) {
		config.PortAllocator = PortAllocatorFunc(func(context.Context) (net.Listener, error) {
			allocatorCalls++
			return nil, errors.New("reconcile retained must not allocate a port")
		})
	})
	lease := activeRuntimeLease("cap_retained_test", 1_200, 1_200, 1_200, 49152)
	if err := provider.ReconcileRetained(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "retained-one"}); err != nil {
		t.Fatal(err)
	}
	if allocatorCalls != 0 || provider.ActiveLeaseCount() != 1 {
		t.Fatalf("reconcile retained allocated a port or failed to retain accounting: calls=%d active=%d", allocatorCalls, provider.ActiveLeaseCount())
	}

	snapshot, _, err := provider.Preflight(context.Background(), capacityRequest(contracts.CapacityRuntime, "retained-snapshot", 0, 0, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.AvailableCPUMillis != 800 || snapshot.AvailableMemoryBytes != 800 || snapshot.AvailableDiskBytes != 800 {
		t.Fatalf("retained lease was not reflected in capacity snapshot: %#v", snapshot)
	}
	_, err = provider.Reserve(context.Background(), capacityRequest(contracts.CapacityRuntime, "retained-overcommit", 801, 801, 801, 0))
	providerErrorCode(t, err, contracts.ErrCapacity)

	// Idempotent retry with same key and different key
	if err := provider.ReconcileRetained(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "retained-one"}); err != nil {
		t.Fatalf("same retained lease replay should succeed: %v", err)
	}
	if err := provider.ReconcileRetained(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "retained-replay"}); err != nil {
		t.Fatalf("same retained lease with new key should succeed: %v", err)
	}

	// Release returns capacity
	if err := provider.Release(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "retained-release"}); err != nil {
		t.Fatal(err)
	}
	if provider.ActiveLeaseCount() != 0 {
		t.Fatalf("released retained lease remained active: %d", provider.ActiveLeaseCount())
	}
}

func TestReconcileRetainedRejectsDuplicatePortAcrossDifferentLeases(t *testing.T) {
	provider := capacityProvider(t, fixedReader(hostCapacity()), nil)
	first := activeRuntimeLease("cap_retained_port_1", 500, 500, 500, 49200)
	second := activeRuntimeLease("cap_retained_port_2", 500, 500, 500, 49200) // duplicate port!

	if err := provider.ReconcileRetained(context.Background(), first, contracts.OperationContext{IdempotencyKey: "retained-port-1"}); err != nil {
		t.Fatal(err)
	}
	err := provider.ReconcileRetained(context.Background(), second, contracts.OperationContext{IdempotencyKey: "retained-port-2"})
	providerErrorCode(t, err, contracts.ErrConflict)
}

func TestReconcileRetainedRestoresWhenHostAvailabilityLowerAndFloorsAvailable(t *testing.T) {
	provider := capacityProvider(t, fixedReader(HostCapacity{
		TotalCPUMillis:       2_000,
		AvailableCPUMillis:   500, // lower than retained lease requirement of 1,000!
		TotalMemoryBytes:     2_000,
		AvailableMemoryBytes: 500,
		TotalDiskBytes:       2_000,
		AvailableDiskBytes:   500,
	}), nil)
	lease := activeRuntimeLease("cap_retained_low_host", 1_000, 1_000, 1_000, 49200)

	// Available is lower than lease, but retained restore must still succeed!
	if err := provider.ReconcileRetained(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "reconcile-low"}); err != nil {
		t.Fatalf("reconcile retained must succeed even when host availability dropped: %v", err)
	}
	if provider.ActiveLeaseCount() != 1 {
		t.Fatalf("expected count 1, got %d", provider.ActiveLeaseCount())
	}

	// Snapshot floors available at 0
	snapshot, _, err := provider.Preflight(context.Background(), capacityRequest(contracts.CapacityRuntime, "preflight-floored", 0, 0, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.AvailableCPUMillis != 0 || snapshot.AvailableMemoryBytes != 0 || snapshot.AvailableDiskBytes != 0 {
		t.Fatalf("expected floored available at 0: %#v", snapshot)
	}

	// New Reserve must be rejected due to zero remaining capacity
	_, err = provider.Reserve(context.Background(), capacityRequest(contracts.CapacityRuntime, "reserve-over", 1, 1, 1, 0))
	providerErrorCode(t, err, contracts.ErrCapacity)

	// Same key replay is stable
	if err := provider.ReconcileRetained(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "reconcile-low"}); err != nil {
		t.Fatalf("same key replay failed: %v", err)
	}

	// Different lease same port conflicts
	diffLease := activeRuntimeLease("cap_diff_lease", 100, 100, 100, 49200)
	err = provider.ReconcileRetained(context.Background(), diffLease, contracts.OperationContext{IdempotencyKey: "diff-port-conflict"})
	providerErrorCode(t, err, contracts.ErrConflict)
}

func TestReconcileRetainedRejectsInvalidLeases(t *testing.T) {
	provider := capacityProvider(t, fixedReader(hostCapacity()), nil)

	invalidScope := activeRuntimeLease("cap_retained_build", 500, 500, 500, 0)
	invalidScope.Scope = contracts.CapacityBuild
	providerErrorCode(t, provider.ReconcileRetained(context.Background(), invalidScope, contracts.OperationContext{IdempotencyKey: "retained-scope"}), contracts.ErrInvalidArgument)

	zeroCPU := activeRuntimeLease("cap_retained_zero", 0, 500, 500, 0)
	providerErrorCode(t, provider.ReconcileRetained(context.Background(), zeroCPU, contracts.OperationContext{IdempotencyKey: "retained-zero"}), contracts.ErrInvalidArgument)

	negMem := activeRuntimeLease("cap_retained_neg", 500, -10, 500, 0)
	providerErrorCode(t, provider.ReconcileRetained(context.Background(), negMem, contracts.OperationContext{IdempotencyKey: "retained-neg"}), contracts.ErrInvalidArgument)

	invalidPort := activeRuntimeLease("cap_retained_badport", 500, 500, 500, 70000)
	providerErrorCode(t, provider.ReconcileRetained(context.Background(), invalidPort, contracts.OperationContext{IdempotencyKey: "retained-badport"}), contracts.ErrInvalidArgument)
}

func TestReconcileRetainedPromotesToActiveUponReconcileActive(t *testing.T) {
	provider := capacityProvider(t, fixedReader(hostCapacity()), nil)
	lease := activeRuntimeLease("cap_retained_promote", 600, 600, 600, 49201)

	if err := provider.ReconcileRetained(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "retained-op"}); err != nil {
		t.Fatal(err)
	}
	if provider.ActiveLeaseCount() != 1 {
		t.Fatalf("expected 1 active lease: %d", provider.ActiveLeaseCount())
	}

	// Workload resumes and calls ReconcileActive
	if err := provider.ReconcileActive(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "resume-op"}); err != nil {
		t.Fatalf("promoting retained lease to active failed: %v", err)
	}
	if provider.ActiveLeaseCount() != 1 {
		t.Fatalf("promoted lease double counted: %d", provider.ActiveLeaseCount())
	}
}

func TestReconcileBidirectionalPortConflictBetweenActiveAndRetained(t *testing.T) {
	provider := capacityProvider(t, fixedReader(hostCapacity()), nil)
	activeLease := activeRuntimeLease("cap_active_first", 500, 500, 500, 49205)
	retainedLease := activeRuntimeLease("cap_retained_second", 500, 500, 500, 49205) // duplicate port

	// Case 1: active first, then retained conflicts
	if err := provider.ReconcileActive(context.Background(), activeLease, contracts.OperationContext{IdempotencyKey: "active-first"}); err != nil {
		t.Fatal(err)
	}
	err := provider.ReconcileRetained(context.Background(), retainedLease, contracts.OperationContext{IdempotencyKey: "retained-conflict"})
	providerErrorCode(t, err, contracts.ErrConflict)

	// Case 2: fresh provider with retained first, then active conflicts
	provider2 := capacityProvider(t, fixedReader(hostCapacity()), nil)
	if err := provider2.ReconcileRetained(context.Background(), retainedLease, contracts.OperationContext{IdempotencyKey: "retained-first"}); err != nil {
		t.Fatal(err)
	}
	err2 := provider2.ReconcileActive(context.Background(), activeLease, contracts.OperationContext{IdempotencyKey: "active-conflict"})
	providerErrorCode(t, err2, contracts.ErrConflict)
}

func TestReconcileRetainedRejectsUnactivatedOrFingerprintMismatch(t *testing.T) {
	provider := capacityProvider(t, fixedReader(hostCapacity()), nil)
	// Reserve a lease (unactivated)
	reserved, err := provider.Reserve(context.Background(), capacityRequest(contracts.CapacityRuntime, "unactivated-reserve", 500, 500, 500, 1))
	if err != nil {
		t.Fatal(err)
	}
	// Calling ReconcileRetained with same ID must fail because it's not activated
	err = provider.ReconcileRetained(context.Background(), reserved, contracts.OperationContext{IdempotencyKey: "reconcile-unactivated"})
	providerErrorCode(t, err, contracts.ErrConflict)

	// Now activate a lease and test fingerprint mismatch
	activated := activeRuntimeLease("cap_activated_mismatch", 500, 500, 500, 49210)
	if err := provider.ReconcileRetained(context.Background(), activated, contracts.OperationContext{IdempotencyKey: "reconcile-ok"}); err != nil {
		t.Fatal(err)
	}
	mismatch := activated
	mismatch.Resources.CPUMillis = 501
	err = provider.ReconcileRetained(context.Background(), mismatch, contracts.OperationContext{IdempotencyKey: "reconcile-mismatch"})
	providerErrorCode(t, err, contracts.ErrConflict)
}

type sequencePortAllocator struct {
	mu     sync.Mutex
	ports  []int
	index  int
	closed []int
}

type trackClosedListener struct {
	net.Listener
	port    int
	onClose func(int)
}

func (l *trackClosedListener) Close() error {
	if l.onClose != nil {
		l.onClose(l.port)
	}
	return l.Listener.Close()
}

func (a *sequencePortAllocator) Listen(ctx context.Context) (net.Listener, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.index >= len(a.ports) {
		return nil, errors.New("sequence port allocator exhausted")
	}
	port := a.ports[a.index]
	a.index++
	rawListener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	// Wrap with custom port for deterministic testing
	return &trackClosedListener{
		Listener: rawListener,
		port:     port,
		onClose: func(p int) {
			a.mu.Lock()
			a.closed = append(a.closed, p)
			a.mu.Unlock()
		},
	}, nil
}

func (a *sequencePortAllocator) loopbackPort(l net.Listener) (int, error) {
	if tl, ok := l.(*trackClosedListener); ok {
		return tl.port, nil
	}
	return loopbackPort(l)
}

func TestReserveAvoidsRetainedHostPortUsingBoundedRetry(t *testing.T) {
	const retainedPort = 49250
	const freshPort = 49251

	allocatorCalls := 0
	closedPorts := make([]int, 0)
	var mu sync.Mutex

	provider := capacityProvider(t, fixedReader(hostCapacity()), func(config *Config) {
		config.PortAllocator = PortAllocatorFunc(func(ctx context.Context) (net.Listener, error) {
			mu.Lock()
			allocatorCalls++
			port := freshPort
			if allocatorCalls == 1 {
				port = retainedPort // First attempt collides with retained port
			}
			mu.Unlock()
			raw, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			// Use fixed loopback port for deterministic test
			fake := FixedPortAllocator{Port: port}
			l, err := fake.Listen(ctx)
			_ = raw.Close()
			if err != nil {
				return nil, err
			}
			return &trackClosedListener{
				Listener: l,
				port:     port,
				onClose: func(p int) {
					mu.Lock()
					closedPorts = append(closedPorts, p)
					mu.Unlock()
				},
			}, nil
		})
	})

	// 1. Reconcile a retained lease holding retainedPort (e.g. paused container)
	retained := activeRuntimeLease("cap_retained_busy", 500, 500, 500, retainedPort)
	if err := provider.ReconcileRetained(context.Background(), retained, contracts.OperationContext{IdempotencyKey: "reconcile-busy"}); err != nil {
		t.Fatal(err)
	}

	// 2. Reserve a new port: allocator first yields retainedPort, then freshPort
	lease, err := provider.Reserve(context.Background(), capacityRequest(contracts.CapacityRuntime, "reserve-fresh", 100, 100, 100, 1))
	if err != nil {
		t.Fatalf("Reserve failed: %v", err)
	}

	// Must get freshPort, not retainedPort
	if lease.HostPort != freshPort {
		t.Fatalf("Reserve took retained port: got=%d want=%d", lease.HostPort, freshPort)
	}
	// The colliding listener for retainedPort must have been closed immediately
	mu.Lock()
	defer mu.Unlock()
	if len(closedPorts) == 0 || closedPorts[0] != retainedPort {
		t.Fatalf("colliding port listener was not closed: %v", closedPorts)
	}
}

func TestReserveExceedsRetryAttemptsFailsBoundedWithoutLeak(t *testing.T) {
	const busyPort = 49260
	closedCount := 0
	var mu sync.Mutex

	provider := capacityProvider(t, fixedReader(hostCapacity()), func(config *Config) {
		config.PortAllocator = PortAllocatorFunc(func(ctx context.Context) (net.Listener, error) {
			fake := FixedPortAllocator{Port: busyPort}
			l, err := fake.Listen(ctx)
			if err != nil {
				return nil, err
			}
			return &trackClosedListener{
				Listener: l,
				port:     busyPort,
				onClose: func(int) {
					mu.Lock()
					closedCount++
					mu.Unlock()
				},
			}, nil
		})
	})

	// Occupy busyPort with active lease
	active := activeRuntimeLease("cap_active_busy", 500, 500, 500, busyPort)
	if err := provider.ReconcileActive(context.Background(), active, contracts.OperationContext{IdempotencyKey: "reconcile-active"}); err != nil {
		t.Fatal(err)
	}

	// Attempt Reserve: allocator always yields busyPort, must fail bounded
	_, err := provider.Reserve(context.Background(), capacityRequest(contracts.CapacityRuntime, "reserve-fail", 100, 100, 100, 1))
	providerErrorCode(t, err, contracts.ErrCapacity)

	mu.Lock()
	defer mu.Unlock()
	// All retried listeners must have been closed (no leak)
	if closedCount != maxPortAllocationAttempts {
		t.Fatalf("expected %d closed attempts, got %d", maxPortAllocationAttempts, closedCount)
	}
}

func TestFinalizeReleasedIdempotentWithoutReactivatingOrClaimingPort(t *testing.T) {
	provider := capacityProvider(t, fixedReader(hostCapacity()), nil)
	lease := activeRuntimeLease("cap_missing_lease", 500, 500, 500, 49270)

	// 1. Finalize non-existent lease -> idempotent success, does NOT insert active lease or claim port
	if err := provider.FinalizeReleased(context.Background(), lease, contracts.OperationContext{IdempotencyKey: "finalize-missing"}); err != nil {
		t.Fatalf("finalize missing lease should succeed: %v", err)
	}
	if provider.ActiveLeaseCount() != 0 {
		t.Fatalf("finalize missing lease created an active lease: count=%d", provider.ActiveLeaseCount())
	}

	// 2. Now add a real retained lease
	retained := activeRuntimeLease("cap_real_retained", 500, 500, 500, 49270)
	if err := provider.ReconcileRetained(context.Background(), retained, contracts.OperationContext{IdempotencyKey: "reconcile-real"}); err != nil {
		t.Fatal(err)
	}
	if provider.ActiveLeaseCount() != 1 {
		t.Fatalf("expected 1 active lease: %d", provider.ActiveLeaseCount())
	}

	// 3. Finalize the real retained lease -> transitions to released
	if err := provider.FinalizeReleased(context.Background(), retained, contracts.OperationContext{IdempotencyKey: "finalize-real"}); err != nil {
		t.Fatalf("finalize real retained lease failed: %v", err)
	}
	if provider.ActiveLeaseCount() != 0 {
		t.Fatalf("finalized lease remained active: count=%d", provider.ActiveLeaseCount())
	}

	// 4. Mismatched fingerprint on existing lease is rejected
	activeAgain := activeRuntimeLease("cap_fingerprint_test", 500, 500, 500, 49271)
	if err := provider.ReconcileActive(context.Background(), activeAgain, contracts.OperationContext{IdempotencyKey: "reconcile-fp"}); err != nil {
		t.Fatal(err)
	}
	mismatch := activeAgain
	mismatch.Resources.CPUMillis = 501
	err := provider.FinalizeReleased(context.Background(), mismatch, contracts.OperationContext{IdempotencyKey: "finalize-mismatch"})
	providerErrorCode(t, err, contracts.ErrConflict)
}
