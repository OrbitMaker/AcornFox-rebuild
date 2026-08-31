package healthcheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/install"
)

const (
	incidentStateFile = "incident-state.json"
	incidentLockFile  = "incident-state.lock"
	maxProbeSubject   = 1024
)

// HostFact is the narrow probe boundary. Subject may be a runtime identity or
// other sensitive-looking input, but the collector emits only its SHA-256.
// Probe-controlled text can therefore never become a result code, snapshot,
// incident state, or delivery payload.
type HostFact struct {
	Subject  string
	Severity Severity
}

// HostProbe is one injected, secret-free host-health fact source. The result
// must describe the declared Kind exactly; commands and their output stay
// outside this package.
type HostProbe struct {
	Kind  CheckKind
	Check func(context.Context) (HostFact, error)
}

// TaskStateStore persists the single Gate7 incident state below a caller-owned
// task root. It intentionally has no production constructor.
type TaskStateStore struct {
	mu     sync.Mutex
	writer *install.DurableWriter
	lock   *install.DurableLock
}

// NewTaskStateStore opens a task-owned, root-contained state root. The root
// must already satisfy the durable writer's non-symlink ownership and mode
// checks; incident state is always stored at the fixed relative filename.
func NewTaskStateStore(root string) (*TaskStateStore, error) {
	writer, err := install.TaskDurableWriter(root, os.Getuid(), os.Getgid())
	if err != nil {
		return nil, errors.New("invalid health state root")
	}
	lock, err := writer.AcquireMetadataLock(incidentLockFile)
	if err != nil {
		_ = writer.Close()
		return nil, errors.New("health state is already in use")
	}
	return &TaskStateStore{writer: writer, lock: lock}, nil
}

// NewProductionStateStore opens the one fixed, root-owned incident-state
// store used by the production runner. It deliberately exposes neither a
// caller-selected root nor ownership parameters.
func NewProductionStateStore() (*TaskStateStore, error) {
	writer, err := install.ProductionDurableWriter(productionHealthStateRoot)
	if err != nil {
		return nil, errors.New("health state root is unavailable")
	}
	lock, err := writer.AcquireMetadataLock(incidentLockFile)
	if err != nil {
		_ = writer.Close()
		return nil, errors.New("health state is already in use")
	}
	return &TaskStateStore{writer: writer, lock: lock}, nil
}

// Close releases the pinned task-root descriptor. A closed store cannot be
// reused, which prevents later writes through an unverified root.
func (s *TaskStateStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writer == nil {
		return nil
	}
	first := s.writer.Close()
	s.writer = nil
	if s.lock != nil {
		if err := s.lock.Release(); err != nil && first == nil {
			first = err
		}
		s.lock = nil
	}
	return first
}

func (s *TaskStateStore) available() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writer != nil && s.lock != nil
}

func (s *TaskStateStore) loadLocked() (*IncidentState, error) {
	if s == nil || s.writer == nil {
		return nil, errors.New("health state store is unavailable")
	}
	raw, err := s.writer.ReadMetadata(incidentStateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("health state is unavailable")
	}
	state, err := ParseIncident(raw)
	if err != nil {
		return nil, errors.New("health state is invalid")
	}
	return &state, nil
}

func (s *TaskStateStore) saveLocked(state IncidentState) error {
	if s == nil || s.writer == nil {
		return errors.New("health state store is unavailable")
	}
	raw, err := MarshalIncident(state)
	if err != nil {
		return errors.New("invalid health state")
	}
	// ReadMetadata verifies an existing leaf is a root-contained 0600 regular
	// file and refuses a symlink instead of silently replacing it.
	if _, err := s.writer.ReadMetadata(incidentStateFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("health state is unavailable")
	}
	if err := s.writer.WriteMetadata(incidentStateFile, raw); err != nil {
		return errors.New("health state persistence failed")
	}
	return nil
}

// TaskHostCollector evaluates exactly the fixed Gate7 checks and uses a task
// state store for durable notification replay. It has no production wiring.
type TaskHostCollector struct {
	probes map[CheckKind]HostProbe
	store  *TaskStateStore
	clock  func() time.Time
}

// Evaluation is returned only after the new incident state has been made
// durable. Callers may therefore expose Decision.Notify or Decision.Recovery
// without losing the notification across a restart.
type Evaluation struct {
	Snapshot Snapshot
	Decision Decision
}

// NewTaskHostCollector validates the complete fixed probe set before any probe
// can run. The caller supplies the clock so collection always stamps one UTC
// instant and tests can exercise escalation boundaries exactly.
func NewTaskHostCollector(probes []HostProbe, store *TaskStateStore, clock func() time.Time) (*TaskHostCollector, error) {
	if !store.available() || clock == nil || len(probes) != len(fixedKinds) {
		return nil, errors.New("invalid task health collector")
	}
	byKind := make(map[CheckKind]HostProbe, len(probes))
	for _, probe := range probes {
		if !validKind(probe.Kind) || probe.Check == nil {
			return nil, errors.New("invalid task health collector")
		}
		if _, exists := byKind[probe.Kind]; exists {
			return nil, errors.New("invalid task health collector")
		}
		byKind[probe.Kind] = probe
	}
	for _, kind := range fixedKinds {
		if _, exists := byKind[kind]; !exists {
			return nil, errors.New("invalid task health collector")
		}
	}
	return &TaskHostCollector{probes: byKind, store: store, clock: clock}, nil
}

// Collect obtains every fixed check in canonical order at one injected UTC
// instant. Probe failures and invalid facts are deliberately reduced to fixed
// errors so arbitrary command output cannot enter persisted incident state.
func (c *TaskHostCollector) Collect(ctx context.Context) (Snapshot, error) {
	if c == nil || c.clock == nil || len(c.probes) != len(fixedKinds) {
		return Snapshot{}, errors.New("health collector is unavailable")
	}
	now := c.clock()
	if !utc(now) {
		return Snapshot{}, errors.New("health collector clock is invalid")
	}
	results := make([]CheckResult, 0, len(fixedKinds))
	overall := SeverityOK
	for _, kind := range fixedKinds {
		probe, exists := c.probes[kind]
		if !exists || probe.Check == nil {
			return Snapshot{}, errors.New("health collector configuration is invalid")
		}
		fact, err := probe.Check(ctx)
		if err != nil || !validSeverity(fact.Severity) || len(fact.Subject) == 0 || len(fact.Subject) > maxProbeSubject {
			return Snapshot{}, errors.New("health probe failed")
		}
		subject := sha256.Sum256([]byte(fact.Subject))
		code := "healthy"
		if fact.Severity != SeverityOK {
			code = string(kind) + "_failed"
		}
		result := CheckResult{Kind: kind, SubjectSHA256: hex.EncodeToString(subject[:]), Severity: fact.Severity, Code: code}
		if result.Validate() != nil {
			return Snapshot{}, errors.New("health probe failed")
		}
		results = append(results, result)
		overall = maxSeverity(overall, result.Severity)
	}
	snapshot := Snapshot{SchemaVersion: SchemaVersion, ObservedAt: now, Results: results, Overall: overall}
	if snapshot.Validate() != nil {
		return Snapshot{}, errors.New("health snapshot is invalid")
	}
	return snapshot, nil
}

// Evaluate persists the transition before returning it. If an earlier delivery
// was not acknowledged, Decide preserves its pending notification and this
// method returns it again after a process restart.
func (c *TaskHostCollector) Evaluate(ctx context.Context) (Evaluation, error) {
	if c == nil || c.store == nil {
		return Evaluation{}, errors.New("health collector is unavailable")
	}
	snapshot, err := c.Collect(ctx)
	if err != nil {
		return Evaluation{}, err
	}
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	previous, err := c.store.loadLocked()
	if err != nil {
		return Evaluation{}, err
	}
	decision, err := Decide(previous, snapshot)
	if err != nil {
		return Evaluation{}, errors.New("health decision failed")
	}
	if err := c.store.saveLocked(decision.State); err != nil {
		return Evaluation{}, err
	}
	return Evaluation{Snapshot: snapshot, Decision: decision}, nil
}

// Acknowledge persists successful delivery using the contract's sole
// acknowledgement transition. It cannot clear a pending notification by any
// other state mutation.
func (c *TaskHostCollector) Acknowledge() (IncidentState, error) {
	if c == nil || c.store == nil {
		return IncidentState{}, errors.New("health collector is unavailable")
	}
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	previous, err := c.store.loadLocked()
	if err != nil || previous == nil {
		return IncidentState{}, errors.New("health state is unavailable")
	}
	next, err := acknowledgeIncidentLocked(*previous, nil)
	if err != nil {
		return IncidentState{}, err
	}
	if err := c.store.saveLocked(next); err != nil {
		return IncidentState{}, err
	}
	return next, nil
}

// AcknowledgeEvent clears a pending notification only when the caller proves
// it delivered the exact durable event it was given. A newer incident or a
// changed pending notification therefore cannot be acknowledged by a stale
// dispatcher result.
func (c *TaskHostCollector) AcknowledgeEvent(event WebhookDeliveryEventV1) (IncidentState, error) {
	if c == nil || c.store == nil || event.Validate() != nil {
		return IncidentState{}, errors.New("health collector is unavailable")
	}
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	previous, err := c.store.loadLocked()
	if err != nil || previous == nil {
		return IncidentState{}, errors.New("health state is unavailable")
	}
	next, err := acknowledgeIncidentLocked(*previous, &event)
	if err != nil {
		return IncidentState{}, err
	}
	if err := c.store.saveLocked(next); err != nil {
		return IncidentState{}, err
	}
	return next, nil
}

// CurrentIncident returns the exact durable incident state under the store
// transaction lock. Production composition uses it to prove a dispatcher
// acknowledgement reached storage before reporting delivery success.
func (c *TaskHostCollector) CurrentIncident() (IncidentState, error) {
	if c == nil || c.store == nil {
		return IncidentState{}, errors.New("health collector is unavailable")
	}
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	current, err := c.store.loadLocked()
	if err != nil || current == nil {
		return IncidentState{}, errors.New("health state is unavailable")
	}
	return *current, nil
}

func acknowledgeIncidentLocked(previous IncidentState, expected *WebhookDeliveryEventV1) (IncidentState, error) {
	if expected != nil {
		actual, err := WebhookDeliveryEventFromIncident(previous)
		if err != nil || !sameWebhookDeliveryEvent(actual, *expected) {
			return IncidentState{}, errors.New("health delivery event is stale")
		}
	}
	return AcknowledgeDelivery(previous)
}
