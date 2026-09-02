package dnschange

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrExecutionConflict means the provider facts no longer match the plan.
// The caller must present the conflict to an operator rather than overwrite a
// foreign or manually changed record.
var ErrExecutionConflict = errors.New("DNS change execution ownership conflict")

// ErrReconcileRequired means a provider write may have completed but its
// result could not be proven.  It is intentionally not retried by this layer.
var ErrReconcileRequired = errors.New("DNS change execution requires reconciliation")

// ErrProviderUnavailable is intentionally generic: callers must not surface
// provider response bodies, endpoints, or credential-adjacent diagnostics.
var ErrProviderUnavailable = errors.New("DNS change provider operation unavailable")

// WriteReceipt is the small, credential-free provider acknowledgement which
// becomes an ownership fact after a confirmed write.
type WriteReceipt struct {
	RecordID  string
	RequestID string
}

// ExecutorProvider is the provider-neutral mutation port. Implementations are
// expected to list a complete, bounded zone and preserve provider IDs as
// opaque strings.
type ExecutorProvider interface {
	ListRecords(context.Context, ManagedZone) ([]Record, error)
	CreateRecord(context.Context, DesiredRecord) (WriteReceipt, error)
	UpdateRecord(context.Context, Record) (WriteReceipt, error)
	DeleteRecord(context.Context, Record) (WriteReceipt, error)
}

// ExecutionLedger is the durable, single source of ownership and
// idempotency. It intentionally excludes provider credentials and payloads.
type ExecutionLedger interface {
	ListOwned(context.Context, string, string, string) ([]OwnedRecord, error)
	SavePlan(context.Context, Plan) (Plan, bool, error)
	FindPlan(context.Context, string) (Plan, bool, error)
	UpsertOwned(context.Context, OwnedRecord) error
	DeleteOwnedExact(context.Context, OwnedRecord) error
	EnsureExecutionSteps(context.Context, Plan) ([]ExecutionStep, error)
	ClaimProviderWrite(context.Context, ManagedZone, ExecutionStep) (ExecutionPhase, bool, error)
	SetExecutionPhase(context.Context, ExecutionStep, ExecutionPhase) error
}

type ExecutionPhase string

const (
	ExecutionPlanned           ExecutionPhase = "planned"
	ExecutionWriteStarted      ExecutionPhase = "write_started"
	ExecutionReconcileRequired ExecutionPhase = "reconcile_required"
	ExecutionApplied           ExecutionPhase = "applied"
)

// ExecutionStep is the durable mutation boundary. Fingerprint binds the plan
// input and one exact change, so a resumed process cannot repurpose a phase
// row for a different provider call.
type ExecutionStep struct {
	PlanID             string
	ChangeIndex        int
	RequestFingerprint string
	Phase              ExecutionPhase
}

// ExecutionStepsForPlan produces the immutable write intent rows for one
// persisted plan. It is exported for provider-bridge fixtures and does not
// expose any provider credential or transport data.
func ExecutionStepsForPlan(plan Plan) []ExecutionStep {
	steps := make([]ExecutionStep, 0, len(plan.Changes))
	for index, change := range plan.Changes {
		steps = append(steps, ExecutionStep{PlanID: plan.ID, ChangeIndex: index, RequestFingerprint: changeFingerprint(plan, index, change), Phase: ExecutionPlanned})
	}
	return steps
}

type ExecuteRequest struct {
	IdempotencyKey string
	Desired        []DesiredRecord
	ManagedZone    ManagedZone
}

type ExecuteResult struct {
	Plan     Plan
	Replayed bool
}

// Executor uses process-local serialization around the exact
// installation/provider/zone tuple to avoid duplicate local work. The durable
// ClaimProviderWrite CAS grants cross-process permission for every mutation.
type Executor struct {
	Store    ExecutionLedger
	Provider ExecutorProvider
	Clock    func() time.Time

	mu    sync.Mutex
	locks map[string]*executionLock
}

// executionLock exists only while one local execution is using its zone.
// Durable scope claims, rather than this in-memory object, guard mutations
// across control-plane processes.
type executionLock struct {
	mu    sync.Mutex
	users int
}

func (e *Executor) Execute(ctx context.Context, request ExecuteRequest) (ExecuteResult, error) {
	if e == nil || e.Store == nil || e.Provider == nil || strings.TrimSpace(request.IdempotencyKey) == "" {
		return ExecuteResult{}, errors.New("DNS change executor is not configured")
	}
	zone, err := executionZone(request)
	if err != nil {
		return ExecuteResult{}, err
	}
	unlock := e.lock(zoneKey(Record{InstallationID: zone.InstallationID, Provider: zone.Provider, ZoneID: zone.ZoneID}))
	defer unlock()

	if stored, found, err := e.Store.FindPlan(ctx, request.IdempotencyKey); err != nil {
		return ExecuteResult{}, err
	} else if found {
		if !sameExecutionIntent(stored, request.Desired, zone) {
			return ExecuteResult{}, ErrIdempotencyConflict
		}
		if err := e.apply(ctx, stored, zone); err != nil {
			return ExecuteResult{}, err
		}
		return ExecuteResult{Plan: stored, Replayed: true}, nil
	}

	observed, err := e.list(ctx, zone)
	if err != nil {
		return ExecuteResult{}, err
	}
	owned, err := e.Store.ListOwned(ctx, zone.InstallationID, zone.Provider, zone.ZoneID)
	if err != nil {
		return ExecuteResult{}, err
	}
	plan, err := BuildDryRun(request.IdempotencyKey, request.Desired, observed, owned, e.now())
	if err != nil {
		return ExecuteResult{}, err
	}
	stored, replayed, err := e.Store.SavePlan(ctx, plan)
	if err != nil {
		return ExecuteResult{}, err
	}
	if replayed && !sameExecutionIntent(stored, request.Desired, zone) {
		return ExecuteResult{}, ErrIdempotencyConflict
	}
	if err := e.apply(ctx, stored, zone); err != nil {
		return ExecuteResult{}, err
	}
	return ExecuteResult{Plan: stored, Replayed: replayed}, nil
}

func executionZone(request ExecuteRequest) (ManagedZone, error) {
	zone := request.ManagedZone
	if zone.Validate() != nil {
		return ManagedZone{}, errors.New("DNS execution managed zone is invalid")
	}
	for _, record := range request.Desired {
		if record.Validate() != nil || record.InstallationID != zone.InstallationID || record.Provider != zone.Provider || record.ZoneID != zone.ZoneID || !strings.EqualFold(record.Domain, zone.Domain) {
			return ManagedZone{}, errors.New("DNS execution desired records do not match the managed zone")
		}
	}
	return zone, nil
}

func (e *Executor) apply(ctx context.Context, plan Plan, zone ManagedZone) error {
	steps, err := e.Store.EnsureExecutionSteps(ctx, plan)
	if err != nil {
		return err
	}
	if len(steps) != len(plan.Changes) {
		return ErrExecutionConflict
	}
	for index, change := range plan.Changes {
		step := steps[index]
		if step.PlanID != plan.ID || step.ChangeIndex != index || step.RequestFingerprint != changeFingerprint(plan, index, change) {
			return ErrExecutionConflict
		}
		if step.Phase == ExecutionApplied {
			continue
		}
		if step.Phase == ExecutionWriteStarted || step.Phase == ExecutionReconcileRequired {
			if err := e.reconcileStep(ctx, plan, step, change, zone); err != nil {
				return err
			}
			continue
		}
		if step.Phase != ExecutionPlanned {
			return ErrExecutionConflict
		}
		switch change.Kind {
		case ChangeNoop:
			if err := e.Store.SetExecutionPhase(ctx, step, ExecutionApplied); err != nil {
				return err
			}
			continue
		case ChangeCreate:
			if change.After == nil {
				return ErrExecutionConflict
			}
			observed, err := e.list(ctx, zone)
			if err != nil {
				return err
			}
			alreadyApplied := false
			for _, record := range observed {
				if recordKey(record) != recordKey(change.After.Record) {
					continue
				}
				if e.ownedMatches(ctx, zone, change.OwnerKey, record) {
					// The provider write and ownership insert both completed during
					// an earlier attempt. Never send a duplicate AddDomainRecord.
					alreadyApplied = true
					break
				}
				// A replay which made it past a prior provider write but not the
				// ownership insert must be reconciled manually; adoption would
				// silently claim a foreign record.
				return ErrReconcileRequired
			}
			if alreadyApplied {
				return ErrExecutionConflict
			}
			claimed, won, err := e.Store.ClaimProviderWrite(ctx, zone, step)
			if err != nil {
				return err
			}
			if !won {
				return e.resolveLostWriteClaim(ctx, plan, step, claimed, change, zone)
			}
			if err := e.revalidateClaimedCreate(ctx, zone, change); err != nil {
				return e.reconcileRequired(ctx, step)
			}
			receipt, err := e.Provider.CreateRecord(ctx, *change.After)
			if err != nil {
				return e.reconcileRequired(ctx, step)
			}
			if !validOpaqueID(receipt.RecordID) || strings.TrimSpace(receipt.RequestID) == "" {
				return e.reconcileRequired(ctx, step)
			}
			record := change.After.Record
			record.RecordID, record.RequestID, record.CreatedAt = receipt.RecordID, receipt.RequestID, e.now()
			if err := e.Store.UpsertOwned(ctx, OwnedRecord{OwnerKey: change.OwnerKey, Record: record, UpdatedAt: e.now(), LastPlanID: plan.ID}); err != nil {
				return e.reconcileRequired(ctx, step)
			}
			if err := e.Store.SetExecutionPhase(ctx, step, ExecutionApplied); err != nil {
				return e.reconcileRequired(ctx, step)
			}
		case ChangeUpdate, ChangeDelete:
			if change.Before == nil {
				return ErrExecutionConflict
			}
			owned, current, err := e.currentOwned(ctx, zone, change.OwnerKey, *change.Before)
			if err != nil {
				return err
			}
			claimed, won, err := e.Store.ClaimProviderWrite(ctx, zone, step)
			if err != nil {
				return err
			}
			if !won {
				return e.resolveLostWriteClaim(ctx, plan, step, claimed, change, zone)
			}
			// The plan could have waited behind another zone mutation after its
			// first read. Recheck exact provider and ownership facts after the
			// durable scope claim; never write from a stale plan.
			owned, current, err = e.currentOwned(ctx, zone, change.OwnerKey, *change.Before)
			if err != nil {
				return e.reconcileRequired(ctx, step)
			}
			if change.Kind == ChangeUpdate {
				if change.After == nil {
					return ErrExecutionConflict
				}
				receipt, err := e.Provider.UpdateRecord(ctx, Record{InstallationID: current.InstallationID, Provider: current.Provider, ZoneID: current.ZoneID, Domain: current.Domain, RecordID: current.RecordID, Name: change.After.Name, Type: change.After.Type, Value: change.After.Value, TTL: change.After.TTL})
				if err != nil {
					return e.reconcileRequired(ctx, step)
				}
				if strings.TrimSpace(receipt.RequestID) == "" || (receipt.RecordID != "" && receipt.RecordID != current.RecordID) {
					return e.reconcileRequired(ctx, step)
				}
				updated := owned
				updated.Record.Value, updated.Record.TTL, updated.Record.RequestID = change.After.Value, change.After.TTL, receipt.RequestID
				updated.UpdatedAt, updated.LastPlanID = e.now(), plan.ID
				if err := e.Store.UpsertOwned(ctx, updated); err != nil {
					return e.reconcileRequired(ctx, step)
				}
				if err := e.Store.SetExecutionPhase(ctx, step, ExecutionApplied); err != nil {
					return e.reconcileRequired(ctx, step)
				}
			} else {
				receipt, err := e.Provider.DeleteRecord(ctx, current)
				if err != nil {
					return e.reconcileRequired(ctx, step)
				}
				if strings.TrimSpace(receipt.RequestID) == "" || (receipt.RecordID != "" && receipt.RecordID != current.RecordID) {
					return e.reconcileRequired(ctx, step)
				}
				if err := e.Store.DeleteOwnedExact(ctx, owned); err != nil {
					return e.reconcileRequired(ctx, step)
				}
				if err := e.Store.SetExecutionPhase(ctx, step, ExecutionApplied); err != nil {
					return e.reconcileRequired(ctx, step)
				}
			}
		default:
			return ErrExecutionConflict
		}
	}
	return nil
}

func (e *Executor) resolveLostWriteClaim(ctx context.Context, plan Plan, step ExecutionStep, phase ExecutionPhase, change Change, zone ManagedZone) error {
	step.Phase = phase
	switch phase {
	case ExecutionApplied:
		return nil
	case ExecutionWriteStarted, ExecutionReconcileRequired:
		return e.reconcileStep(ctx, plan, step, change, zone)
	default:
		return ErrExecutionConflict
	}
}

// revalidateClaimedCreate makes the pre-write create condition explicit after
// the durable zone scope was acquired. A plan can be built before another plan
// mutates the zone; it must not use a later lease to overwrite that new fact.
func (e *Executor) revalidateClaimedCreate(ctx context.Context, zone ManagedZone, change Change) error {
	if change.After == nil {
		return ErrExecutionConflict
	}
	observed, err := e.list(ctx, zone)
	if err != nil {
		return err
	}
	for _, record := range observed {
		if recordKey(record) == recordKey(change.After.Record) {
			return ErrExecutionConflict
		}
	}
	owned, err := e.Store.ListOwned(ctx, zone.InstallationID, zone.Provider, zone.ZoneID)
	if err != nil {
		return err
	}
	for _, item := range owned {
		if item.OwnerKey == change.OwnerKey {
			return ErrExecutionConflict
		}
	}
	return nil
}

func (e *Executor) currentOwned(ctx context.Context, zone ManagedZone, ownerKey string, expected Record) (OwnedRecord, Record, error) {
	owned, err := e.Store.ListOwned(ctx, zone.InstallationID, zone.Provider, zone.ZoneID)
	if err != nil {
		return OwnedRecord{}, Record{}, err
	}
	var exact *OwnedRecord
	for index := range owned {
		if owned[index].OwnerKey == ownerKey {
			exact = &owned[index]
			break
		}
	}
	if exact == nil || !recordEqual(exact.Record, expected) || exact.Record.RecordID != expected.RecordID {
		return OwnedRecord{}, Record{}, ErrExecutionConflict
	}
	observed, err := e.list(ctx, zone)
	if err != nil {
		return OwnedRecord{}, Record{}, err
	}
	var found *Record
	for index := range observed {
		if observed[index].RecordID != expected.RecordID {
			continue
		}
		if found != nil {
			return OwnedRecord{}, Record{}, ErrExecutionConflict
		}
		found = &observed[index]
	}
	if found == nil || !recordEqual(*found, expected) {
		return OwnedRecord{}, Record{}, ErrExecutionConflict
	}
	return *exact, *found, nil
}

// reconcileStep is read-only with respect to the DNS provider. A process can
// crash after a request has crossed the network boundary; even a stale read is
// not permission to send that request again. We either prove the durable
// ownership fact reached the intended state or leave the step recoverable.
func (e *Executor) reconcileStep(ctx context.Context, plan Plan, step ExecutionStep, change Change, zone ManagedZone) error {
	observed, err := e.list(ctx, zone)
	if err != nil {
		return e.reconcileRequired(ctx, step)
	}
	owned, err := e.Store.ListOwned(ctx, zone.InstallationID, zone.Provider, zone.ZoneID)
	if err != nil {
		return e.reconcileRequired(ctx, step)
	}
	ownedFor := func(ownerKey string) *OwnedRecord {
		for index := range owned {
			if owned[index].OwnerKey == ownerKey {
				return &owned[index]
			}
		}
		return nil
	}
	findByID := func(id string) *Record {
		for index := range observed {
			if observed[index].RecordID == id {
				return &observed[index]
			}
		}
		return nil
	}
	markApplied := func() error {
		if err := e.Store.SetExecutionPhase(ctx, step, ExecutionApplied); err != nil {
			return e.reconcileRequired(ctx, step)
		}
		return nil
	}
	switch change.Kind {
	case ChangeNoop:
		return markApplied()
	case ChangeCreate:
		if change.After == nil {
			return ErrExecutionConflict
		}
		for _, current := range observed {
			if recordKey(current) != recordKey(change.After.Record) || !recordEqual(current, change.After.Record) {
				continue
			}
			item := ownedFor(change.OwnerKey)
			if item != nil && item.Record.RecordID == current.RecordID && recordEqual(item.Record, current) {
				return markApplied()
			}
			// A matching record without our exact durable ownership receipt is
			// not proof of ownership. Do not adopt it and do not call Create.
			return e.reconcileRequired(ctx, step)
		}
		return e.reconcileRequired(ctx, step)
	case ChangeUpdate:
		if change.Before == nil || change.After == nil {
			return ErrExecutionConflict
		}
		item := ownedFor(change.OwnerKey)
		current := findByID(change.Before.RecordID)
		if item == nil || current == nil || current.RecordID != item.Record.RecordID {
			return e.reconcileRequired(ctx, step)
		}
		if recordEqual(*current, change.After.Record) {
			// The record ID remains stable. The old request receipt is the only
			// durable ownership proof available after an indeterminate response;
			// retain it while reconciling the observed desired value.
			updated := *item
			updated.Record.Value, updated.Record.TTL = change.After.Value, change.After.TTL
			updated.UpdatedAt, updated.LastPlanID = e.now(), plan.ID
			if err := e.Store.UpsertOwned(ctx, updated); err != nil {
				return e.reconcileRequired(ctx, step)
			}
			return markApplied()
		}
		return e.reconcileRequired(ctx, step)
	case ChangeDelete:
		if change.Before == nil {
			return ErrExecutionConflict
		}
		item := ownedFor(change.OwnerKey)
		if findByID(change.Before.RecordID) != nil {
			return e.reconcileRequired(ctx, step)
		}
		if item != nil {
			if item.Record.RecordID != change.Before.RecordID || !recordEqual(item.Record, *change.Before) {
				return e.reconcileRequired(ctx, step)
			}
			if err := e.Store.DeleteOwnedExact(ctx, *item); err != nil {
				return e.reconcileRequired(ctx, step)
			}
		}
		return markApplied()
	default:
		return ErrExecutionConflict
	}
}

func (e *Executor) reconcileRequired(ctx context.Context, step ExecutionStep) error {
	_ = e.Store.SetExecutionPhase(ctx, step, ExecutionReconcileRequired)
	return ErrReconcileRequired
}

func (e *Executor) ownedMatches(ctx context.Context, zone ManagedZone, ownerKey string, observed Record) bool {
	owned, err := e.Store.ListOwned(ctx, zone.InstallationID, zone.Provider, zone.ZoneID)
	if err != nil {
		return false
	}
	for _, item := range owned {
		if item.OwnerKey == ownerKey && item.Record.RecordID == observed.RecordID && recordEqual(item.Record, observed) {
			return true
		}
	}
	return false
}

func (e *Executor) list(ctx context.Context, zone ManagedZone) ([]Record, error) {
	items, err := e.Provider.ListRecords(ctx, zone)
	if err != nil {
		return nil, executionProviderError(err)
	}
	ids := make(map[string]struct{}, len(items))
	for _, item := range items {
		if item.Validate(true) != nil || item.InstallationID != zone.InstallationID || item.Provider != zone.Provider || item.ZoneID != zone.ZoneID || !strings.EqualFold(item.Domain, zone.Domain) {
			return nil, ErrExecutionConflict
		}
		key := providerRecordKey(item)
		if _, duplicate := ids[key]; duplicate {
			return nil, ErrExecutionConflict
		}
		ids[key] = struct{}{}
	}
	return items, nil
}

func sameExecutionIntent(plan Plan, desired []DesiredRecord, zone ManagedZone) bool {
	expected := make([]DesiredRecord, 0, len(plan.Changes))
	for _, change := range plan.Changes {
		if change.After != nil {
			expected = append(expected, *change.After)
		}
	}
	if len(expected) != len(desired) {
		return false
	}
	canonical := func(items []DesiredRecord) []byte {
		items = append([]DesiredRecord(nil), items...)
		sort.Slice(items, func(i, j int) bool { return items[i].OwnerKey < items[j].OwnerKey })
		payload, _ := json.Marshal(struct {
			Zone    ManagedZone     `json:"zone"`
			Desired []DesiredRecord `json:"desired"`
		}{zone, items})
		return payload
	}
	return string(canonical(expected)) == string(canonical(desired))
}

func changeFingerprint(plan Plan, index int, change Change) string {
	payload, err := json.Marshal(struct {
		PlanID      string `json:"plan_id"`
		InputDigest string `json:"input_digest"`
		Index       int    `json:"index"`
		Change      Change `json:"change"`
	}{plan.ID, plan.InputDigest, index, change})
	if err != nil {
		panic("DNS change fingerprint serialization failed")
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func executionProviderError(err error) error {
	if err == nil {
		return nil
	}
	var indeterminate interface{ RequiresReconcile() bool }
	if errors.As(err, &indeterminate) && indeterminate.RequiresReconcile() {
		return ErrReconcileRequired
	}
	return ErrProviderUnavailable
}

func (e *Executor) lock(key string) func() {
	e.mu.Lock()
	if e.locks == nil {
		e.locks = make(map[string]*executionLock)
	}
	lock := e.locks[key]
	if lock == nil {
		lock = &executionLock{}
		e.locks[key] = lock
	}
	lock.users++
	e.mu.Unlock()
	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		e.mu.Lock()
		lock.users--
		if lock.users == 0 && e.locks[key] == lock {
			delete(e.locks, key)
		}
		e.mu.Unlock()
	}
}

func (e *Executor) now() time.Time {
	if e.Clock != nil {
		return e.Clock().UTC()
	}
	return time.Now().UTC()
}
