package aliyundns

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/dnschange"
)

type bridgeDNS struct {
	records []Record
	created CreateRecord
	updated UpdateRecord
	deleted string
}

type bridgeLedger struct {
	plans map[string]dnschange.Plan
	owned map[string]dnschange.OwnedRecord
	steps map[string]dnschange.ExecutionStep
}

func newBridgeLedger() *bridgeLedger {
	return &bridgeLedger{plans: map[string]dnschange.Plan{}, owned: map[string]dnschange.OwnedRecord{}, steps: map[string]dnschange.ExecutionStep{}}
}
func (s *bridgeLedger) ListOwned(_ context.Context, installationID, provider, zoneID string) ([]dnschange.OwnedRecord, error) {
	result := []dnschange.OwnedRecord{}
	for _, item := range s.owned {
		if item.Record.InstallationID == installationID && item.Record.Provider == provider && item.Record.ZoneID == zoneID {
			result = append(result, item)
		}
	}
	return result, nil
}
func (s *bridgeLedger) SavePlan(_ context.Context, plan dnschange.Plan) (dnschange.Plan, bool, error) {
	if old, ok := s.plans[plan.IdempotencyKey]; ok {
		if old.InputDigest != plan.InputDigest {
			return dnschange.Plan{}, false, dnschange.ErrIdempotencyConflict
		}
		return old, true, nil
	}
	s.plans[plan.IdempotencyKey] = plan
	return plan, false, nil
}
func (s *bridgeLedger) FindPlan(_ context.Context, key string) (dnschange.Plan, bool, error) {
	item, ok := s.plans[key]
	return item, ok, nil
}
func (s *bridgeLedger) UpsertOwned(_ context.Context, item dnschange.OwnedRecord) error {
	key := item.Record.InstallationID + ":" + item.OwnerKey
	if existing, ok := s.owned[key]; ok && (existing.Record.RecordID != item.Record.RecordID || existing.Record.ZoneID != item.Record.ZoneID) {
		return dnschange.ErrOwnershipConflict
	}
	s.owned[key] = item
	return nil
}
func (s *bridgeLedger) DeleteOwnedExact(_ context.Context, item dnschange.OwnedRecord) error {
	key := item.Record.InstallationID + ":" + item.OwnerKey
	existing, ok := s.owned[key]
	if !ok || existing.Record.RecordID != item.Record.RecordID || existing.Record.RequestID != item.Record.RequestID {
		return dnschange.ErrNotFound
	}
	delete(s.owned, key)
	return nil
}
func (s *bridgeLedger) EnsureExecutionSteps(_ context.Context, plan dnschange.Plan) ([]dnschange.ExecutionStep, error) {
	result := make([]dnschange.ExecutionStep, 0, len(plan.Changes))
	for index, expected := range dnschange.ExecutionStepsForPlan(plan) {
		key := plan.ID + ":" + string(rune(index))
		step, ok := s.steps[key]
		if !ok {
			step = expected
			s.steps[key] = step
		}
		result = append(result, step)
	}
	return result, nil
}
func (s *bridgeLedger) ClaimProviderWrite(_ context.Context, _ dnschange.ManagedZone, step dnschange.ExecutionStep) (dnschange.ExecutionPhase, bool, error) {
	key := step.PlanID + ":" + string(rune(step.ChangeIndex))
	current, ok := s.steps[key]
	if !ok || current.RequestFingerprint != step.RequestFingerprint {
		return "", false, dnschange.ErrExecutionConflict
	}
	if current.Phase != dnschange.ExecutionPlanned {
		return current.Phase, false, nil
	}
	current.Phase = dnschange.ExecutionWriteStarted
	s.steps[key] = current
	return dnschange.ExecutionWriteStarted, true, nil
}
func (s *bridgeLedger) SetExecutionPhase(_ context.Context, step dnschange.ExecutionStep, phase dnschange.ExecutionPhase) error {
	key := step.PlanID + ":" + string(rune(step.ChangeIndex))
	current, ok := s.steps[key]
	if !ok || current.RequestFingerprint != step.RequestFingerprint {
		return dnschange.ErrExecutionConflict
	}
	current.Phase = phase
	s.steps[key] = current
	return nil
}

type executorBridgeDNS struct {
	mu                     sync.Mutex
	records                []Record
	creates, updates, dels int
}

func (f *executorBridgeDNS) ListRecords(context.Context, string) ([]Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Record(nil), f.records...), nil
}
func (f *executorBridgeDNS) CreateRecord(_ context.Context, item CreateRecord) (WriteReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates++
	id := "opaque/create:1"
	f.records = append(f.records, Record{ID: id, DomainName: item.DomainName, RR: item.RR, Type: item.Type, Value: item.Value, TTL: item.TTL, Line: "default"})
	return WriteReceipt{RecordID: id, RequestID: "req-create"}, nil
}
func (f *executorBridgeDNS) UpdateRecord(_ context.Context, item UpdateRecord) (WriteReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates++
	for index := range f.records {
		if f.records[index].ID == item.ID {
			f.records[index].RR, f.records[index].Type, f.records[index].Value, f.records[index].TTL = item.RR, item.Type, item.Value, item.TTL
			return WriteReceipt{RecordID: item.ID, RequestID: "req-update"}, nil
		}
	}
	return WriteReceipt{}, errors.New("fixture record missing")
}
func (f *executorBridgeDNS) DeleteRecord(_ context.Context, id string) (WriteReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dels++
	for index := range f.records {
		if f.records[index].ID == id {
			f.records = append(f.records[:index], f.records[index+1:]...)
			return WriteReceipt{RecordID: id, RequestID: "req-delete"}, nil
		}
	}
	return WriteReceipt{}, errors.New("fixture record missing")
}

func (f *bridgeDNS) ListRecords(context.Context, string) ([]Record, error) {
	return append([]Record(nil), f.records...), nil
}
func (f *bridgeDNS) CreateRecord(_ context.Context, record CreateRecord) (WriteReceipt, error) {
	f.created = record
	return WriteReceipt{RecordID: "opaque/created:17", RequestID: "request-created"}, nil
}
func (f *bridgeDNS) UpdateRecord(_ context.Context, record UpdateRecord) (WriteReceipt, error) {
	f.updated = record
	return WriteReceipt{RecordID: record.ID, RequestID: "request-updated"}, nil
}
func (f *bridgeDNS) DeleteRecord(_ context.Context, id string) (WriteReceipt, error) {
	f.deleted = id
	return WriteReceipt{RecordID: id, RequestID: "request-deleted"}, nil
}

func TestDNSChangeBridgePreservesOpaqueIDsAndRejectsScopeEscape(t *testing.T) {
	provider := &bridgeDNS{records: []Record{{ID: "opaque/id:1", DomainName: "example.com", RR: "*.apps", Type: "A", Value: "8.8.8.8", TTL: 600, Line: "default"}}}
	bridge := DNSChangeBridge{DNS: provider, InstallationID: "install-bridge", ZoneID: "zone/opaque:17", Domain: "example.com"}
	zone := dnschange.ManagedZone{InstallationID: "install-bridge", Provider: dnschange.ProviderAlibabaCloudDNS, ZoneID: "zone/opaque:17", Domain: "example.com"}
	items, err := bridge.ListRecords(context.Background(), zone)
	if err != nil || len(items) != 1 || items[0].RecordID != "opaque/id:1" || items[0].Provider != dnschange.ProviderAlibabaCloudDNS {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	desired := dnschange.DesiredRecord{OwnerKey: "acornfox:wildcard-a", Record: dnschange.Record{InstallationID: "install-bridge", Provider: dnschange.ProviderAlibabaCloudDNS, ZoneID: "zone/opaque:17", Domain: "example.com", Name: "*.apps", Type: "A", Value: "8.8.8.8", TTL: 600}}
	receipt, err := bridge.CreateRecord(context.Background(), desired)
	if err != nil || receipt.RecordID != "opaque/created:17" || provider.created.RR != "*.apps" || provider.created.DomainName != "example.com" {
		t.Fatalf("receipt=%+v err=%v create=%+v", receipt, err, provider.created)
	}
	if _, err := bridge.ListRecords(context.Background(), dnschange.ManagedZone{InstallationID: "other", Provider: dnschange.ProviderAlibabaCloudDNS, ZoneID: zone.ZoneID, Domain: zone.Domain}); err == nil {
		t.Fatal("scope escape was accepted")
	}
	unsafe := desired
	unsafe.Name = "console"
	if _, err := bridge.CreateRecord(context.Background(), unsafe); err == nil || provider.created.RR == "console" {
		t.Fatalf("unsafe desired write err=%v create=%+v", err, provider.created)
	}
}

func TestDNSChangeExecutorUsesAlibabaBridgeForCreateReplayAndCleanup(t *testing.T) {
	provider := &executorBridgeDNS{}
	bridge := DNSChangeBridge{DNS: provider, InstallationID: "install-execute", ZoneID: "zone/opaque:execute", Domain: "example.com"}
	desired := dnschange.DesiredRecord{OwnerKey: "acornfox:wildcard-a", Record: dnschange.Record{InstallationID: "install-execute", Provider: dnschange.ProviderAlibabaCloudDNS, ZoneID: "zone/opaque:execute", Domain: "example.com", Name: "*.apps", Type: "A", Value: "8.8.8.8", TTL: 600}}
	zone := dnschange.ManagedZone{InstallationID: desired.InstallationID, Provider: desired.Provider, ZoneID: desired.ZoneID, Domain: desired.Domain}
	executor := &dnschange.Executor{Store: newBridgeLedger(), Provider: bridge, Clock: func() time.Time { return time.Unix(5, 0).UTC() }}
	if result, err := executor.Execute(context.Background(), dnschange.ExecuteRequest{IdempotencyKey: "bridge-create", Desired: []dnschange.DesiredRecord{desired}, ManagedZone: zone}); err != nil || result.Replayed || provider.creates != 1 {
		t.Fatalf("create result=%+v err=%v writes=%d", result, err, provider.creates)
	}
	if result, err := executor.Execute(context.Background(), dnschange.ExecuteRequest{IdempotencyKey: "bridge-create", Desired: []dnschange.DesiredRecord{desired}, ManagedZone: zone}); err != nil || !result.Replayed || provider.creates != 1 {
		t.Fatalf("replay result=%+v err=%v writes=%d", result, err, provider.creates)
	}
	if _, err := executor.Execute(context.Background(), dnschange.ExecuteRequest{IdempotencyKey: "bridge-cleanup", ManagedZone: zone}); err != nil || provider.dels != 1 || len(provider.records) != 0 {
		t.Fatalf("cleanup err=%v deletes=%d records=%+v", err, provider.dels, provider.records)
	}
}
