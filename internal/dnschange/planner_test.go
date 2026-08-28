package dnschange

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBuildDryRunProducesExactCreateUpdateDeleteAndRollback(t *testing.T) {
	desired, err := PlatformARecords(7, "example.com", "8.8.8.8", 600)
	if err != nil {
		t.Fatal(err)
	}
	owned := OwnedRecord{OwnerKey: "platform:console", Record: Record{Provider: ProviderDNSPod, DomainID: 7, Domain: "example.com", RecordID: 42, Host: "console", Type: "A", Value: "1.1.1.1", TTL: 600, RequestID: "req-old", CreatedAt: time.Unix(1, 0)}, UpdatedAt: time.Unix(2, 0)}
	obsolete := OwnedRecord{OwnerKey: "customer:obsolete", Record: Record{Provider: ProviderDNSPod, DomainID: 7, Domain: "example.com", RecordID: 43, Host: "old", Type: "CNAME", Value: "ingress.example.com", TTL: 600, RequestID: "req-43", CreatedAt: time.Unix(1, 0)}, UpdatedAt: time.Unix(2, 0)}
	observed := []Record{owned.Record, obsolete.Record}
	plan, err := BuildDryRun("dry-1", desired, observed, []OwnedRecord{owned, obsolete}, time.Unix(3, 0))
	if err != nil || len(plan.Changes) != 4 {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	changes := map[string]Change{}
	for _, change := range plan.Changes {
		changes[change.OwnerKey] = change
	}
	if change := changes["platform:console"]; change.Kind != ChangeUpdate || change.Before.RecordID != 42 || change.Rollback.RecordID != 42 || change.Rollback.Record.Value != "1.1.1.1" {
		t.Fatalf("console update=%+v", change)
	}
	if change := changes["customer:obsolete"]; change.Kind != ChangeDelete || change.Before.RecordID != 43 || change.Rollback.Kind != ChangeCreate {
		t.Fatalf("delete=%+v", change)
	}
	if change := changes["platform:ingress"]; change.Kind != ChangeCreate || !change.Rollback.Deferred {
		t.Fatalf("create=%+v", change)
	}
}

func TestBuildDryRunFailsClosedForUnownedRecordAndManualDrift(t *testing.T) {
	desired, err := PlatformARecords(7, "example.com", "8.8.8.8", 600)
	if err != nil {
		t.Fatal(err)
	}
	unowned := Record{Provider: ProviderDNSPod, DomainID: 7, Domain: "example.com", RecordID: 11, Host: "console", Type: "A", Value: "8.8.8.8", TTL: 600, RequestID: "req-11", CreatedAt: time.Unix(1, 0)}
	if _, err := BuildDryRun("unowned", desired, []Record{unowned}, nil, time.Now()); err == nil {
		t.Fatal("unowned record was adopted")
	}
	owned := OwnedRecord{OwnerKey: "platform:console", Record: unowned, UpdatedAt: time.Now()}
	owned.Record.Value = "1.1.1.1"
	if _, err := BuildDryRun("drift", desired, []Record{unowned}, []OwnedRecord{owned}, time.Now()); err == nil {
		t.Fatal("manual drift was overwritten")
	}
}

func TestDesiredRecordsRejectPrivateAddressAndOutOfBoundaryHosts(t *testing.T) {
	if _, err := PlatformARecords(7, "example.com", "10.0.0.1", 600); err == nil {
		t.Fatal("private platform address accepted")
	}
	bad := DesiredRecord{OwnerKey: "platform:other", Record: Record{Provider: ProviderDNSPod, DomainID: 7, Domain: "example.com", Host: "other", Type: "A", Value: "8.8.8.8", TTL: 600}}
	if err := bad.Validate(); err == nil {
		t.Fatal("out-of-boundary platform A host accepted")
	}
	bad = DesiredRecord{OwnerKey: "customer:wildcard", Record: Record{Provider: ProviderDNSPod, DomainID: 7, Domain: "example.com", Host: "*.customer", Type: "CNAME", Value: "ingress.example.com", TTL: 600}}
	if err := bad.Validate(); err == nil {
		t.Fatal("wildcard customer CNAME accepted")
	}
	bad = DesiredRecord{OwnerKey: "platform:ipv6", Record: Record{Provider: ProviderDNSPod, DomainID: 7, Domain: "example.com", Host: "console", Type: "A", Value: "2606:4700:4700::1111", TTL: 600}}
	if err := bad.Validate(); err == nil {
		t.Fatal("IPv6 A value accepted")
	}
}

func TestBuildDryRunRejectsAmbiguousRecordSetsAndInvalidOwner(t *testing.T) {
	desired, err := PlatformARecords(7, "example.com", "8.8.8.8", 600)
	if err != nil {
		t.Fatal(err)
	}
	duplicateID := Record{Provider: ProviderDNSPod, DomainID: 7, Domain: "example.com", RecordID: 42, Host: "console", Type: "A", Value: "8.8.8.8", TTL: 600, RequestID: "req-42", CreatedAt: time.Unix(1, 0)}
	duplicateIDSecond := duplicateID
	duplicateIDSecond.Host = "ingress"
	if _, err := BuildDryRun("duplicate-id", desired, []Record{duplicateID, duplicateIDSecond}, nil, time.Now()); err == nil {
		t.Fatal("duplicate observed RecordId accepted")
	}
	first, err := CustomerCNAME("customer:first", 7, "example.com", "www", "ingress.example.com", 600)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CustomerCNAME("customer:second", 7, "example.com", "www", "ingress.example.com", 600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildDryRun("duplicate-identity", []DesiredRecord{first, second}, nil, nil, time.Now()); err == nil {
		t.Fatal("duplicate desired identity accepted")
	}
	differentDomain, err := CustomerCNAME("customer:other", 7, "other.example", "www", "ingress.other.example", 600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildDryRun("domain-id", append(desired, differentDomain), nil, nil, time.Now()); err == nil {
		t.Fatal("one DomainId mapped to multiple names")
	}
	owned := OwnedRecord{OwnerKey: "x", Record: duplicateID, UpdatedAt: time.Unix(2, 0)}
	if err := owned.Validate(); err == nil {
		t.Fatal("invalid ownership key accepted")
	}
}

func TestBuildDryRunRejectsOwnershipIdentityRewrite(t *testing.T) {
	owned := OwnedRecord{OwnerKey: "platform:console", Record: Record{Provider: ProviderDNSPod, DomainID: 7, Domain: "example.com", RecordID: 42, Host: "console", Type: "A", Value: "8.8.8.8", TTL: 600, RequestID: "req-42", CreatedAt: time.Unix(1, 0)}, UpdatedAt: time.Unix(2, 0)}
	desired := DesiredRecord{OwnerKey: "platform:console", Record: Record{Provider: ProviderDNSPod, DomainID: 8, Domain: "other.example", Host: "console", Type: "A", Value: "8.8.8.8", TTL: 600}}
	if _, err := BuildDryRun("identity", []DesiredRecord{desired}, []Record{owned.Record}, []OwnedRecord{owned}, time.Now()); err == nil {
		t.Fatal("ownership identity rewrite was accepted")
	}
}

type memoryLedger struct {
	owned map[int64][]OwnedRecord
	plans map[string]Plan
	last  map[string]time.Time
}

func newMemoryLedger() *memoryLedger {
	return &memoryLedger{owned: map[int64][]OwnedRecord{}, plans: map[string]Plan{}, last: map[string]time.Time{}}
}
func (s *memoryLedger) ListOwned(_ context.Context, id int64) ([]OwnedRecord, error) {
	return append([]OwnedRecord(nil), s.owned[id]...), nil
}
func (s *memoryLedger) SavePlan(_ context.Context, plan Plan) (Plan, bool, error) {
	if old, ok := s.plans[plan.IdempotencyKey]; ok {
		if old.InputDigest != plan.InputDigest {
			return Plan{}, false, ErrIdempotencyConflict
		}
		return old, true, nil
	}
	s.plans[plan.IdempotencyKey] = plan
	return plan, false, nil
}
func (s *memoryLedger) LastReconcile(_ context.Context, scope string) (time.Time, error) {
	return s.last[scope], nil
}
func (s *memoryLedger) SetLastReconcile(_ context.Context, scope string, now time.Time) error {
	s.last[scope] = now
	return nil
}

type fixtureReader struct {
	records []Record
	calls   int
}

func (r *fixtureReader) ListRecords(context.Context, int64, string) ([]Record, error) {
	r.calls++
	return append([]Record(nil), r.records...), nil
}

type domainFixtureReader struct{ records map[int64][]Record }

func (r *domainFixtureReader) ListRecords(_ context.Context, domainID int64, _ string) ([]Record, error) {
	return append([]Record(nil), r.records[domainID]...), nil
}

func TestReconcilerRunsOnlyOnInjectedSixtySecondCadence(t *testing.T) {
	desired, err := PlatformARecords(7, "example.com", "8.8.8.8", 600)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(600, 0).UTC()
	store := newMemoryLedger()
	reader := &fixtureReader{}
	reconciler := &Reconciler{Store: store, Reader: reader, Desired: desired, Scope: "dns-g4", Clock: func() time.Time { return now }, Interval: time.Minute}
	first, err := reconciler.ReconcileOnce(context.Background())
	if err != nil || !first.Due || reader.calls != 1 {
		t.Fatalf("first=%+v err=%v calls=%d", first, err, reader.calls)
	}
	now = now.Add(59 * time.Second)
	second, err := reconciler.ReconcileOnce(context.Background())
	if err != nil || second.Due || reader.calls != 1 {
		t.Fatalf("second=%+v err=%v calls=%d", second, err, reader.calls)
	}
	now = now.Add(time.Second)
	third, err := reconciler.ReconcileOnce(context.Background())
	if err != nil || !third.Due || reader.calls != 2 || third.Plan.ID == first.Plan.ID {
		t.Fatalf("third=%+v err=%v calls=%d", third, err, reader.calls)
	}
	if _, _, err := store.SavePlan(context.Background(), Plan{ID: "different", IdempotencyKey: first.Plan.IdempotencyKey, InputDigest: "sha256:" + string(make([]byte, 64)), CreatedAt: now}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict=%v", err)
	}
}

func TestReconcilerIncludesManagedEmptyCustomerZoneForDeletePlan(t *testing.T) {
	now := time.Unix(600, 0).UTC()
	store := newMemoryLedger()
	owned := OwnedRecord{OwnerKey: "customer:deleted", Record: Record{Provider: ProviderDNSPod, DomainID: 8, Domain: "customer.example", RecordID: 88, Host: "www", Type: "CNAME", Value: "ingress.example.com", TTL: 600, RequestID: "req-88", CreatedAt: now}, UpdatedAt: now}
	store.owned[8] = []OwnedRecord{owned}
	reader := &domainFixtureReader{records: map[int64][]Record{8: {owned.Record}}}
	reconciler := &Reconciler{Store: store, Reader: reader, ManagedDomainIDs: map[int64]string{8: "customer.example"}, Scope: "customer-delete", Clock: func() time.Time { return now }, Interval: time.Minute}
	result, err := reconciler.ReconcileOnce(context.Background())
	if err != nil || !result.Due || len(result.Plan.Changes) != 1 || result.Plan.Changes[0].Kind != ChangeDelete || result.Plan.Changes[0].Before.RecordID != 88 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
