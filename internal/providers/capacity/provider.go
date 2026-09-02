// Package capacity provides the local Linux capacity boundary used by the
// build and standalone runtime providers.
//
// A lease is a reservation in the provider's process, not a claim that a
// container has already been created.  Reserve keeps a loopback listener open
// when a host port is requested.  Activate closes that listener so Docker can
// bind the same port, while CPU, memory, and disk reservations remain held
// until Release (or lease expiry).
package capacity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const (
	providerName    = "linux-capacity"
	providerVersion = "m1"
	defaultDiskPath = "/"
	defaultLeaseTTL = 5 * time.Minute
)

// HostCapacity is the raw host observation returned by a Reader.  Available
// values describe what the host reports before this provider's reservations
// and scope-specific safety reserve are subtracted.
type HostCapacity struct {
	TotalCPUMillis       int64
	AvailableCPUMillis   int64
	TotalMemoryBytes     int64
	AvailableMemoryBytes int64
	TotalDiskBytes       int64
	AvailableDiskBytes   int64
}

// HostSnapshot is kept as a readable alias for integrations that use the
// word snapshot for a point-in-time host observation.
type HostSnapshot = HostCapacity

// Reader supplies a point-in-time host observation.  Implementations should
// avoid returning paths, mount names, or other host topology in errors; the
// provider deliberately redacts those details before returning them to a
// controller.
type Reader interface {
	Read(context.Context, string) (HostCapacity, error)
}

// CapacityReader is a compatibility alias for callers that name the
// dependency by its responsibility.
type CapacityReader = Reader

// ReaderFunc adapts a function into a Reader.  It is useful for deterministic
// tests without requiring a real /proc, cgroup, or filesystem.
type ReaderFunc func(context.Context, string) (HostCapacity, error)

func (f ReaderFunc) Read(ctx context.Context, path string) (HostCapacity, error) {
	return f(ctx, path)
}

// PortAllocator owns the short-lived loopback listener used to reserve one
// host port.  The default implementation asks the OS for a TCP4 ephemeral
// port.  Tests can inject an allocator with deterministic listeners.
type PortAllocator interface {
	Listen(context.Context) (net.Listener, error)
}

// PortAllocatorFunc adapts a function into a PortAllocator.
type PortAllocatorFunc func(context.Context) (net.Listener, error)

func (f PortAllocatorFunc) Listen(ctx context.Context) (net.Listener, error) {
	return f(ctx)
}

type systemPortAllocator struct{}

func (systemPortAllocator) Listen(ctx context.Context) (net.Listener, error) {
	return (&net.ListenConfig{}).Listen(ctx, "tcp4", "127.0.0.1:0")
}

type FixedPortAllocator struct{ Port int }

func (a FixedPortAllocator) Listen(ctx context.Context) (net.Listener, error) {
	if a.Port < 1 || a.Port > 65535 {
		return nil, errors.New("fixed capacity port is invalid")
	}
	return (&net.ListenConfig{}).Listen(ctx, "tcp4", fmt.Sprintf("127.0.0.1:%d", a.Port))
}

// Config contains the provider-owned capacity boundary.  BuildReserve and
// RuntimeReserve are scope-specific safety floors.  Active leases from either
// scope are always counted; the selected scope's floor is additionally
// subtracted from the available host observation.
type Config struct {
	Reader         Reader
	DiskPath       string
	BuildReserve   contracts.ResourceLimits
	RuntimeReserve contracts.ResourceLimits
	LeaseTTL       time.Duration
	PortAllocator  PortAllocator
	Clock          func() time.Time
}

func (c Config) normalized() (Config, error) {
	if c.Reader == nil {
		c.Reader = SystemReader{}
	}
	if strings.TrimSpace(c.DiskPath) == "" {
		c.DiskPath = defaultDiskPath
	}
	if c.LeaseTTL == 0 {
		c.LeaseTTL = defaultLeaseTTL
	}
	if c.LeaseTTL <= 0 {
		return Config{}, errors.New("capacity lease TTL must be positive and finite")
	}
	if c.PortAllocator == nil {
		c.PortAllocator = systemPortAllocator{}
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	if err := validateResources(c.BuildReserve); err != nil {
		return Config{}, fmt.Errorf("build capacity reserve: %w", err)
	}
	if err := validateResources(c.RuntimeReserve); err != nil {
		return Config{}, fmt.Errorf("runtime capacity reserve: %w", err)
	}
	return c, nil
}

// Provider implements contracts.CapacityProvider using local host facts and
// in-process atomic reservations.
type Provider struct {
	config   Config
	metadata contracts.ProviderMetadata

	mu         sync.Mutex
	leases     map[string]*leaseRecord
	operations map[string]operationRecord
}

type leaseRecord struct {
	lease     contracts.CapacityLease
	listener  net.Listener
	activated bool
	released  bool
	expired   bool
	timer     *time.Timer
}

type operationRecord struct {
	fingerprint string
	snapshot    contracts.CapacitySnapshot
	evidence    contracts.Evidence
	lease       contracts.CapacityLease
	err         error
}

var _ contracts.CapacityProvider = (*Provider)(nil)

// New constructs a local capacity provider.  The zero Reader uses real Linux
// host observations; tests should inject ReaderFunc or another Reader.
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
			Capabilities: contracts.NewCapabilitySet(
				contracts.CapabilityCapacityCheck,
				contracts.CapabilityCapacityReserve,
			),
			Healthcheck: "local host resources",
		},
		leases:     make(map[string]*leaseRecord),
		operations: make(map[string]operationRecord),
	}, nil
}

// NewProvider is an explicit constructor alias used by provider registries.
func NewProvider(config Config) (*Provider, error) { return New(config) }

// NewWithReader is a small convenience for tests and local integrations.
func NewWithReader(reader Reader, config Config) (*Provider, error) {
	config.Reader = reader
	return New(config)
}

func (p *Provider) Metadata(context.Context) contracts.ProviderMetadata { return p.metadata }

// Preflight returns a redacted snapshot after subtracting active leases and
// the reserve for request.Scope.  A requested port is probed and immediately
// released; Reserve is the operation that holds the listener.
func (p *Provider) Preflight(ctx context.Context, request contracts.CapacityRequest) (contracts.CapacitySnapshot, contracts.Evidence, error) {
	if err := p.validateRequest(ctx, request, contracts.CapabilityCapacityCheck, "preflight"); err != nil {
		return contracts.CapacitySnapshot{}, contracts.Evidence{}, err
	}
	fingerprint := requestFingerprint(request)
	opKey := operationKey("preflight", request.Operation.IdempotencyKey)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.reapLocked()
	if previous, ok := p.operations[opKey]; ok {
		if previous.fingerprint != fingerprint {
			return contracts.CapacitySnapshot{}, contracts.Evidence{}, p.conflict(request.Operation, contracts.CapabilityCapacityCheck, "preflight")
		}
		return previous.snapshot, previous.evidence, previous.err
	}

	observed, err := p.read(ctx)
	if err != nil {
		if operationErr := contextError(ctx, request.Operation, p.config.Clock); operationErr != nil {
			return contracts.CapacitySnapshot{}, contracts.Evidence{}, operationErr
		}
		return contracts.CapacitySnapshot{}, contracts.Evidence{}, p.readError(request.Operation, contracts.CapabilityCapacityCheck, "preflight", err)
	}
	snapshot := p.snapshotLocked(request.Scope, observed)
	evidence := capacityEvidence("preflight", request, snapshot, 0, time.Time{})
	if err := contextError(ctx, request.Operation, p.config.Clock); err != nil {
		return contracts.CapacitySnapshot{}, contracts.Evidence{}, err
	}
	if resources := shortfalls(request.Resources, snapshot); len(resources) != 0 {
		err := p.capacityError(request.Operation, contracts.CapabilityCapacityCheck, "preflight", resources, evidence)
		p.operations[opKey] = operationRecord{fingerprint: fingerprint, snapshot: snapshot, evidence: evidence, err: err}
		return snapshot, evidence, err
	}
	if request.HostPorts == 1 {
		listener, listenErr := p.listen(ctx)
		if listenErr != nil {
			if operationErr := contextError(ctx, request.Operation, p.config.Clock); operationErr != nil {
				return contracts.CapacitySnapshot{}, contracts.Evidence{}, operationErr
			}
			err := p.capacityError(request.Operation, contracts.CapabilityCapacityCheck, "preflight", []string{"port"}, evidence)
			p.operations[opKey] = operationRecord{fingerprint: fingerprint, snapshot: snapshot, evidence: evidence, err: err}
			return snapshot, evidence, err
		}
		if closeErr := listener.Close(); closeErr != nil {
			err := p.unavailableError(request.Operation, contracts.CapabilityCapacityCheck, "preflight", "loopback port probe failed", closeErr)
			p.operations[opKey] = operationRecord{fingerprint: fingerprint, snapshot: snapshot, evidence: evidence, err: err}
			return snapshot, evidence, err
		}
	}
	p.operations[opKey] = operationRecord{fingerprint: fingerprint, snapshot: snapshot, evidence: evidence}
	return snapshot, evidence, nil
}

// Reserve atomically checks the latest host observation and records a lease.
// For HostPorts == 1 it retains a loopback listener until Activate, Release,
// or expiry, preventing an intervening local process from taking the port.
func (p *Provider) Reserve(ctx context.Context, request contracts.CapacityRequest) (contracts.CapacityLease, error) {
	if err := p.validateRequest(ctx, request, contracts.CapabilityCapacityReserve, "reserve"); err != nil {
		return contracts.CapacityLease{}, err
	}
	fingerprint := requestFingerprint(request)
	opKey := operationKey("reserve", request.Operation.IdempotencyKey)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.reapLocked()
	if previous, ok := p.operations[opKey]; ok {
		if previous.fingerprint != fingerprint {
			return contracts.CapacityLease{}, p.conflict(request.Operation, contracts.CapabilityCapacityReserve, "reserve")
		}
		return previous.lease, previous.err
	}

	observed, err := p.read(ctx)
	if err != nil {
		if operationErr := contextError(ctx, request.Operation, p.config.Clock); operationErr != nil {
			return contracts.CapacityLease{}, operationErr
		}
		return contracts.CapacityLease{}, p.readError(request.Operation, contracts.CapabilityCapacityReserve, "reserve", err)
	}
	snapshot := p.snapshotLocked(request.Scope, observed)
	evidence := capacityEvidence("reserve", request, snapshot, 0, time.Time{})
	if err := contextError(ctx, request.Operation, p.config.Clock); err != nil {
		return contracts.CapacityLease{}, err
	}
	if resources := shortfalls(request.Resources, snapshot); len(resources) != 0 {
		err := p.capacityError(request.Operation, contracts.CapabilityCapacityReserve, "reserve", resources, evidence)
		p.operations[opKey] = operationRecord{fingerprint: fingerprint, evidence: evidence, err: err}
		return contracts.CapacityLease{}, err
	}

	var listener net.Listener
	var hostPort int
	if request.HostPorts == 1 {
		listener, err = p.listen(ctx)
		if err != nil {
			if operationErr := contextError(ctx, request.Operation, p.config.Clock); operationErr != nil {
				return contracts.CapacityLease{}, operationErr
			}
			err = p.capacityError(request.Operation, contracts.CapabilityCapacityReserve, "reserve", []string{"port"}, evidence)
			p.operations[opKey] = operationRecord{fingerprint: fingerprint, evidence: evidence, err: err}
			return contracts.CapacityLease{}, err
		}
		hostPort, err = loopbackPort(listener)
		if err != nil {
			_ = listener.Close()
			err = p.unavailableError(request.Operation, contracts.CapabilityCapacityReserve, "reserve", "loopback listener was invalid", err)
			p.operations[opKey] = operationRecord{fingerprint: fingerprint, evidence: evidence, err: err}
			return contracts.CapacityLease{}, err
		}
	}
	if err := contextError(ctx, request.Operation, p.config.Clock); err != nil {
		if listener != nil {
			_ = listener.Close()
		}
		return contracts.CapacityLease{}, err
	}

	now := p.config.Clock().UTC()
	lease := contracts.CapacityLease{
		ID:        "cap_" + hashParts(request.Operation.IdempotencyKey, request.Scope, request.Resources, hostPort, now.UnixNano())[:32],
		Scope:     request.Scope,
		Resources: request.Resources,
		HostPort:  hostPort,
		ExpiresAt: now.Add(p.config.LeaseTTL),
	}
	lease.Evidence = capacityEvidence("lease", request, snapshot, hostPort, lease.ExpiresAt)
	record := &leaseRecord{lease: lease, listener: listener}
	record.timer = time.AfterFunc(p.config.LeaseTTL, func() { p.expire(lease.ID) })
	p.leases[lease.ID] = record
	p.operations[opKey] = operationRecord{fingerprint: fingerprint, lease: lease, evidence: lease.Evidence}
	return lease, nil
}

// Activate releases only the temporary port listener.  The resource lease
// remains active until Release, so a Docker create/bind race cannot make the
// provider overcommit CPU, memory, or disk.
func (p *Provider) Activate(ctx context.Context, lease contracts.CapacityLease, operation contracts.OperationContext) error {
	if err := p.validateOperation(ctx, operation, contracts.CapabilityCapacityReserve, "activate"); err != nil {
		return err
	}
	if lease.ID == "" {
		return p.argumentError(operation, contracts.CapabilityCapacityReserve, "activate", "capacity lease id is required")
	}
	fingerprint := leaseOperationFingerprint(lease)
	opKey := operationKey("activate", operation.IdempotencyKey)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.reapLocked()
	if previous, ok := p.operations[opKey]; ok {
		if previous.fingerprint != fingerprint {
			return p.conflict(operation, contracts.CapabilityCapacityReserve, "activate")
		}
		return previous.err
	}
	record, ok := p.leases[lease.ID]
	if !ok {
		err := p.notFoundError(operation, contracts.CapabilityCapacityReserve, "activate", "capacity lease was not found")
		p.operations[opKey] = operationRecord{fingerprint: fingerprint, err: err}
		return err
	}
	if record.expired {
		err := p.expiredError(operation, contracts.CapabilityCapacityReserve, "activate")
		p.operations[opKey] = operationRecord{fingerprint: fingerprint, err: err}
		return err
	}
	if record.released {
		err := p.conflict(operation, contracts.CapabilityCapacityReserve, "activate")
		p.operations[opKey] = operationRecord{fingerprint: fingerprint, err: err}
		return err
	}
	if record.listener != nil {
		if err := record.listener.Close(); err != nil {
			safe := p.unavailableError(operation, contracts.CapabilityCapacityReserve, "activate", "loopback listener could not be released", err)
			p.operations[opKey] = operationRecord{fingerprint: fingerprint, err: safe}
			return safe
		}
		record.listener = nil
	}
	record.activated = true
	if record.timer != nil {
		record.timer.Stop()
		record.timer = nil
	}
	p.operations[opKey] = operationRecord{fingerprint: fingerprint}
	return nil
}

// ReconcileActive restores an already-running standalone runtime lease after
// this provider process restarts. The standalone provider must first prove the
// runtime and any published port still exist; this method only restores local
// accounting and deliberately neither binds nor probes a port.
//
// A restored lease is activated from the outset, so it does not carry an
// expiry timer. The running workload, rather than the pre-activation lease
// timeout, owns its lifetime until Release is called.
func (p *Provider) ReconcileActive(ctx context.Context, lease contracts.CapacityLease, operation contracts.OperationContext) error {
	const action = "reconcile_active"
	if err := p.validateOperation(ctx, operation, contracts.CapabilityCapacityReserve, action); err != nil {
		return err
	}
	if err := p.validateActiveLease(lease); err != nil {
		return p.argumentError(operation, contracts.CapabilityCapacityReserve, action, err.Error())
	}
	fingerprint := activeLeaseFingerprint(lease)
	opKey := operationKey(action, operation.IdempotencyKey)

	p.mu.Lock()
	defer p.mu.Unlock()
	if previous, ok := p.operations[opKey]; ok {
		if previous.fingerprint != fingerprint {
			return p.conflict(operation, contracts.CapabilityCapacityReserve, action)
		}
		return previous.err
	}
	if record, ok := p.leases[lease.ID]; ok {
		if record.released || !record.activated || activeLeaseFingerprint(record.lease) != fingerprint {
			return p.conflict(operation, contracts.CapabilityCapacityReserve, action)
		}
		p.operations[opKey] = operationRecord{fingerprint: fingerprint}
		return nil
	}

	// Reconciliation is intentionally independent of the current host snapshot.
	// A live container remains an actual reservation even if host availability
	// has fallen since it was first started; subsequent snapshots floor the
	// remaining availability at zero.
	p.leases[lease.ID] = &leaseRecord{lease: lease, activated: true}
	p.operations[opKey] = operationRecord{fingerprint: fingerprint}
	return nil
}

// Release is idempotent.  An already-expired lease is considered released
// because the expiry path has already closed its listener and returned its
// accounting capacity.
func (p *Provider) Release(ctx context.Context, lease contracts.CapacityLease, operation contracts.OperationContext) error {
	if err := p.validateOperation(ctx, operation, contracts.CapabilityCapacityReserve, "release"); err != nil {
		return err
	}
	if lease.ID == "" {
		return p.argumentError(operation, contracts.CapabilityCapacityReserve, "release", "capacity lease id is required")
	}
	fingerprint := leaseOperationFingerprint(lease)
	opKey := operationKey("release", operation.IdempotencyKey)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.reapLocked()
	if previous, ok := p.operations[opKey]; ok {
		if previous.fingerprint != fingerprint {
			return p.conflict(operation, contracts.CapabilityCapacityReserve, "release")
		}
		return previous.err
	}
	record, ok := p.leases[lease.ID]
	if !ok {
		err := p.notFoundError(operation, contracts.CapabilityCapacityReserve, "release", "capacity lease was not found")
		p.operations[opKey] = operationRecord{fingerprint: fingerprint, err: err}
		return err
	}
	if !record.released {
		if record.timer != nil {
			record.timer.Stop()
		}
		if record.listener != nil {
			// net.Listener.Close is idempotent for the system listener.  Mark the
			// lease released even if a custom listener reports a close error so
			// accounting cannot remain indefinitely reserved.
			_ = record.listener.Close()
			record.listener = nil
		}
		record.released = true
	}
	p.operations[opKey] = operationRecord{fingerprint: fingerprint}
	return nil
}

// ActiveLeaseCount is intentionally small diagnostic surface for tests and
// local acceptance checks.  It reports accounting leases, not completed
// idempotency records.
func (p *Provider) ActiveLeaseCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reapLocked()
	count := 0
	for _, record := range p.leases {
		if !record.released {
			count++
		}
	}
	return count
}

func (p *Provider) read(ctx context.Context) (HostCapacity, error) {
	observed, err := p.config.Reader.Read(ctx, p.config.DiskPath)
	if err != nil {
		return HostCapacity{}, err
	}
	if err := observed.validate(); err != nil {
		return HostCapacity{}, err
	}
	return observed, nil
}

func (p *Provider) snapshotLocked(scope contracts.CapacityScope, observed HostCapacity) contracts.CapacitySnapshot {
	reserve := p.reserveFor(scope)
	var active contracts.ResourceLimits
	for _, record := range p.leases {
		if record.released {
			continue
		}
		active.CPUMillis = saturatingAdd(active.CPUMillis, record.lease.Resources.CPUMillis)
		active.MemoryBytes = saturatingAdd(active.MemoryBytes, record.lease.Resources.MemoryBytes)
		active.DiskBytes = saturatingAdd(active.DiskBytes, record.lease.Resources.DiskBytes)
	}
	reservedCPU := saturatingAdd(active.CPUMillis, reserve.CPUMillis)
	reservedMemory := saturatingAdd(active.MemoryBytes, reserve.MemoryBytes)
	reservedDisk := saturatingAdd(active.DiskBytes, reserve.DiskBytes)
	return contracts.CapacitySnapshot{
		Scope:                scope,
		TotalCPUMillis:       observed.TotalCPUMillis,
		AvailableCPUMillis:   subtractFloor(observed.AvailableCPUMillis, reservedCPU),
		TotalMemoryBytes:     observed.TotalMemoryBytes,
		AvailableMemoryBytes: subtractFloor(observed.AvailableMemoryBytes, reservedMemory),
		TotalDiskBytes:       observed.TotalDiskBytes,
		AvailableDiskBytes:   subtractFloor(observed.AvailableDiskBytes, reservedDisk),
		ReservedCPUMillis:    reservedCPU,
		ReservedMemoryBytes:  reservedMemory,
		ReservedDiskBytes:    reservedDisk,
		ObservedAt:           p.config.Clock().UTC(),
	}
}

func (p *Provider) reserveFor(scope contracts.CapacityScope) contracts.ResourceLimits {
	if scope == contracts.CapacityBuild {
		return p.config.BuildReserve
	}
	return p.config.RuntimeReserve
}

func (p *Provider) listen(ctx context.Context) (net.Listener, error) {
	listener, err := p.config.PortAllocator.Listen(ctx)
	if err != nil {
		return nil, err
	}
	if listener == nil {
		return nil, errors.New("port allocator returned a nil listener")
	}
	if _, err := loopbackPort(listener); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func loopbackPort(listener net.Listener) (int, error) {
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address == nil || address.IP == nil || !address.IP.IsLoopback() || address.Port < 1 || address.Port > 65535 {
		return 0, errors.New("listener is not a valid loopback TCP listener")
	}
	return address.Port, nil
}

func (p *Provider) expire(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	record, ok := p.leases[id]
	if !ok || record.released || record.activated {
		return
	}
	// The injected clock is authoritative.  A fake clock may be advanced by a
	// test independently of wall time, so the ordinary public operations also
	// call reapLocked and this callback intentionally remains conservative.
	if p.config.Clock().Before(record.lease.ExpiresAt) {
		return
	}
	p.expireLocked(record)
}

func (p *Provider) reapLocked() {
	now := p.config.Clock()
	for _, record := range p.leases {
		if record.released || record.activated || now.Before(record.lease.ExpiresAt) {
			continue
		}
		p.expireLocked(record)
	}
}

func (p *Provider) expireLocked(record *leaseRecord) {
	if record.released {
		return
	}
	if record.timer != nil {
		record.timer.Stop()
	}
	if record.listener != nil {
		_ = record.listener.Close()
		record.listener = nil
	}
	record.expired = true
	record.released = true
}

func (p *Provider) validateRequest(ctx context.Context, request contracts.CapacityRequest, capability contracts.Capability, action string) error {
	if err := p.validateOperation(ctx, request.Operation, capability, action); err != nil {
		return err
	}
	if request.Scope != contracts.CapacityBuild && request.Scope != contracts.CapacityRuntime {
		return p.argumentError(request.Operation, capability, action, "capacity scope is unsupported")
	}
	if err := validateResources(request.Resources); err != nil {
		return p.argumentError(request.Operation, capability, action, "capacity resources must not be negative")
	}
	if request.HostPorts < 0 || request.HostPorts > 1 {
		return p.argumentError(request.Operation, capability, action, "at most one loopback host port may be reserved")
	}
	return nil
}

func (p *Provider) validateActiveLease(lease contracts.CapacityLease) error {
	if strings.TrimSpace(lease.ID) == "" {
		return errors.New("capacity lease id is required")
	}
	if lease.Scope != contracts.CapacityRuntime {
		return errors.New("only runtime capacity leases can be reconciled")
	}
	if err := validateResources(lease.Resources); err != nil {
		return errors.New("capacity resources must not be negative")
	}
	if lease.Resources.CPUMillis <= 0 || lease.Resources.MemoryBytes <= 0 || lease.Resources.DiskBytes <= 0 {
		return errors.New("active runtime capacity resources must be positive")
	}
	if lease.HostPort < 0 || lease.HostPort > 65535 {
		return errors.New("capacity host port is invalid")
	}
	return nil
}

func (p *Provider) validateOperation(ctx context.Context, operation contracts.OperationContext, capability contracts.Capability, action string) error {
	if err := contextError(ctx, operation, p.config.Clock); err != nil {
		return err
	}
	if err := operation.Validate(); err != nil {
		return p.argumentError(operation, capability, action, "provider idempotency key is required")
	}
	return nil
}

func contextError(ctx context.Context, operation contracts.OperationContext, clock func() time.Time) error {
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return &contracts.ProviderError{Provider: providerName, Code: contracts.ErrTimeout, Message: "capacity operation timed out", Retry: contracts.RetryBackoff, Retryable: true, Operation: "capacity", Cause: err}
		}
		return &contracts.ProviderError{Provider: providerName, Code: contracts.ErrCancelled, Message: "capacity operation cancelled", Retry: contracts.RetryAfterReconnect, Retryable: true, Operation: "capacity", Cause: err}
	}
	if !operation.Deadline.IsZero() && !clock().Before(operation.Deadline) {
		return &contracts.ProviderError{Provider: providerName, Code: contracts.ErrTimeout, Message: "capacity operation timed out", Retry: contracts.RetryBackoff, Retryable: true, Operation: "capacity", Cause: context.DeadlineExceeded}
	}
	return nil
}

func (p *Provider) argumentError(operation contracts.OperationContext, capability contracts.Capability, action, message string) error {
	return p.providerError(operation, capability, action, contracts.ErrInvalidArgument, message, contracts.RetryNever, false, nil, nil)
}

func (p *Provider) conflict(operation contracts.OperationContext, capability contracts.Capability, action string) error {
	return p.providerError(operation, capability, action, contracts.ErrConflict, "idempotency key was reused for a different capacity operation", contracts.RetryNever, false, nil, nil)
}

func (p *Provider) notFoundError(operation contracts.OperationContext, capability contracts.Capability, action, message string) error {
	return p.providerError(operation, capability, action, contracts.ErrNotFound, message, contracts.RetryNever, false, nil, nil)
}

func (p *Provider) expiredError(operation contracts.OperationContext, capability contracts.Capability, action string) error {
	return p.providerError(operation, capability, action, contracts.ErrTimeout, "capacity lease expired", contracts.RetryUserAction, false, nil, nil)
}

func (p *Provider) unavailableError(operation contracts.OperationContext, capability contracts.Capability, action, message string, cause error) error {
	return p.providerError(operation, capability, action, contracts.ErrUnavailable, message, contracts.RetryBackoff, true, cause, nil)
}

func (p *Provider) readError(operation contracts.OperationContext, capability contracts.Capability, action string, cause error) error {
	return p.providerError(operation, capability, action, contracts.ErrUnavailable, "host capacity observation unavailable", contracts.RetryBackoff, true, cause, nil)
}

func (p *Provider) capacityError(operation contracts.OperationContext, capability contracts.Capability, action string, resources []string, evidence contracts.Evidence) error {
	details := map[string]string{"evidence_ref": evidenceReference(evidence)}
	if len(resources) > 0 {
		details["resource"] = strings.Join(resources, ",")
	}
	return p.providerError(operation, capability, action, contracts.ErrCapacity, "requested capacity exceeds the available host budget", contracts.RetryBackoff, true, nil, details)
}

func (p *Provider) providerError(operation contracts.OperationContext, capability contracts.Capability, action string, code contracts.ErrorCode, message string, retry contracts.RetryClass, retryable bool, cause error, details map[string]string) *contracts.ProviderError {
	if details == nil {
		details = map[string]string{}
	}
	return &contracts.ProviderError{Provider: providerName, Code: code, Message: message, Retry: retry, Retryable: retryable, Capability: capability, Operation: action, Details: details, Cause: cause}
}

func capacityEvidence(kind string, request contracts.CapacityRequest, snapshot contracts.CapacitySnapshot, hostPort int, expiresAt time.Time) contracts.Evidence {
	digest := hashParts(kind, request.Scope, request.Resources, request.HostPorts, snapshot, hostPort, expiresAt.UTC().UnixNano())
	return contracts.Evidence{
		Refs: []domain.EvidenceRef{{
			ID:      domain.ID("cap_ev_" + digest[:32]),
			Kind:    "capacity." + kind,
			Digest:  "sha256:" + digest,
			Locator: "capacity://evidence/" + digest[:32],
		}},
		Summary:  "redacted local capacity evidence",
		Digest:   "sha256:" + digest,
		Redacted: true,
	}
}

func evidenceReference(evidence contracts.Evidence) string {
	if len(evidence.Refs) == 0 {
		return ""
	}
	return string(evidence.Refs[0].ID)
}

func requestFingerprint(request contracts.CapacityRequest) string {
	return hashParts(request.Scope, request.Resources, request.HostPorts)
}

func leaseOperationFingerprint(lease contracts.CapacityLease) string {
	// The ID is the stable opaque handle.  Callers may deserialize a lease and
	// omit its evidence without making a valid idempotent operation conflict.
	return hashParts(lease.ID)
}

func activeLeaseFingerprint(lease contracts.CapacityLease) string {
	// Evidence is intentionally excluded because callers may deserialize the
	// durable lease from a compact record. Its identity, scope, accounting
	// values, and assigned host port are the restored facts.
	return hashParts(lease.ID, lease.Scope, lease.Resources, lease.HostPort)
}

func operationKey(action, idempotencyKey string) string { return action + "\x00" + idempotencyKey }

func hashParts(parts ...any) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(fmt.Sprintf("%T:%v", part, part)))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func validateResources(resources contracts.ResourceLimits) error {
	if resources.CPUMillis < 0 || resources.MemoryBytes < 0 || resources.DiskBytes < 0 || resources.TimeoutSeconds < 0 || resources.ConcurrencySlot < 0 || resources.PIDs < 0 {
		return errors.New("resource limits must not be negative")
	}
	return nil
}

func shortfalls(resources contracts.ResourceLimits, snapshot contracts.CapacitySnapshot) []string {
	var result []string
	if resources.CPUMillis > snapshot.AvailableCPUMillis {
		result = append(result, "cpu")
	}
	if resources.MemoryBytes > snapshot.AvailableMemoryBytes {
		result = append(result, "memory")
	}
	if resources.DiskBytes > snapshot.AvailableDiskBytes {
		result = append(result, "disk")
	}
	return result
}

func saturatingAdd(left, right int64) int64 {
	if right > 0 && left > int64(^uint64(0)>>1)-right {
		return int64(^uint64(0) >> 1)
	}
	return left + right
}

func subtractFloor(value, reserved int64) int64 {
	if reserved >= value {
		return 0
	}
	return value - reserved
}

func (h HostCapacity) validate() error {
	if h.TotalCPUMillis <= 0 || h.TotalMemoryBytes <= 0 || h.TotalDiskBytes <= 0 {
		return errors.New("host capacity totals must be positive")
	}
	if h.AvailableCPUMillis < 0 || h.AvailableCPUMillis > h.TotalCPUMillis {
		return errors.New("host CPU availability is invalid")
	}
	if h.AvailableMemoryBytes < 0 || h.AvailableMemoryBytes > h.TotalMemoryBytes {
		return errors.New("host memory availability is invalid")
	}
	if h.AvailableDiskBytes < 0 || h.AvailableDiskBytes > h.TotalDiskBytes {
		return errors.New("host disk availability is invalid")
	}
	return nil
}
