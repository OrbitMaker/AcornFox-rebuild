package dnschange

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func legacyRecord(id, name, value string) Record {
	return Record{InstallationID: legacyDNSPodInstallationID, Provider: ProviderDNSPod, ZoneID: "7", Domain: "example.com", RecordID: id, Name: name, Type: "A", Value: value, TTL: 600, RequestID: "req-" + id, CreatedAt: time.Unix(1, 0).UTC()}
}

func alibabaRecord(id, name, recordType, value string) Record {
	return Record{InstallationID: "install-alpha", Provider: ProviderAlibabaCloudDNS, ZoneID: "zone-opaque/A:17", Domain: "example.com", RecordID: id, Name: name, Type: recordType, Value: value, TTL: 600, RequestID: "request-" + id, CreatedAt: time.Unix(1, 0).UTC()}
}

func owned(owner string, record Record) OwnedRecord {
	return OwnedRecord{OwnerKey: owner, Record: record, UpdatedAt: time.Unix(2, 0).UTC()}
}

func TestBuildDryRunPreservesLegacyDNSPodCreateUpdateDeleteAndRollback(t *testing.T) {
	desired, err := PlatformARecords("7", "example.com", "8.8.8.8", 600)
	if err != nil {
		t.Fatal(err)
	}
	current := legacyRecord("42", "console", "1.1.1.1")
	obsolete := Record{InstallationID: legacyDNSPodInstallationID, Provider: ProviderDNSPod, ZoneID: "7", Domain: "example.com", RecordID: "43", Name: "old", Type: "CNAME", Value: "ingress.example.com", TTL: 600, RequestID: "req-43", CreatedAt: time.Unix(1, 0).UTC()}
	plan, err := BuildDryRun("dry-legacy", desired, []Record{current, obsolete}, []OwnedRecord{owned("platform:console", current), owned("customer:obsolete", obsolete)}, time.Unix(3, 0))
	if err != nil || len(plan.Changes) != 4 {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	changes := map[string]Change{}
	for _, change := range plan.Changes {
		changes[change.OwnerKey] = change
	}
	if change := changes["platform:console"]; change.Kind != ChangeUpdate || change.Before.RecordID != "42" || change.Rollback.RecordID != "42" || change.Rollback.Record.Value != "1.1.1.1" {
		t.Fatalf("console update=%+v", change)
	}
	if change := changes["customer:obsolete"]; change.Kind != ChangeDelete || change.Before.RecordID != "43" || change.Rollback.Kind != ChangeCreate {
		t.Fatalf("delete=%+v", change)
	}
	if change := changes["platform:ingress"]; change.Kind != ChangeCreate || !change.Rollback.Deferred {
		t.Fatalf("create=%+v", change)
	}
}

func TestRecordDecodesHistoricalNumericDNSPodPlanIdentity(t *testing.T) {
	var record Record
	if err := json.Unmarshal([]byte(`{"provider":"dnspod","domain_id":7,"domain":"example.com","record_id":42,"host":"console","type":"A","value":"8.8.8.8","ttl":600,"request_id":"req-42","created_at":"1970-01-01T00:00:01Z"}`), &record); err != nil {
		t.Fatal(err)
	}
	if record.InstallationID != legacyDNSPodInstallationID || record.ZoneID != "7" || record.RecordID != "42" || record.Name != "console" || record.Validate(true) != nil {
		t.Fatalf("legacy record=%+v", record)
	}
}

func TestChangesDecodeHistoricalNumericDNSPodRollbackIdentity(t *testing.T) {
	var changes []Change
	if err := json.Unmarshal([]byte(`[{"kind":"update","owner_key":"platform:console","before":{"provider":"dnspod","domain_id":7,"domain":"example.com","record_id":42,"host":"console","type":"A","value":"1.1.1.1","ttl":600,"request_id":"req-42","created_at":"1970-01-01T00:00:01Z"},"rollback":{"kind":"update","record_id":42}}]`), &changes); err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Before == nil || changes[0].Before.RecordID != "42" || changes[0].Rollback == nil || changes[0].Rollback.RecordID != "42" {
		t.Fatalf("legacy changes=%+v", changes)
	}
}

func TestAlibabaWildcardRecordsPermitOnlyExactWildcardAndDNS01TXT(t *testing.T) {
	desired, err := AlibabaWildcardRecords("install-alpha", "zone-opaque/A:17", "example.com", "8.8.8.8", "challenge-value", 600)
	if err != nil || len(desired) != 2 {
		t.Fatalf("desired=%+v err=%v", desired, err)
	}
	if desired[0].Name != "*.apps" || desired[0].Type != "A" || desired[1].Name != "_acme-challenge.apps" || desired[1].Type != "TXT" {
		t.Fatalf("unexpected exact records: %+v", desired)
	}
	for _, bad := range []DesiredRecord{
		{OwnerKey: "acornfox:root", Record: Record{InstallationID: "install-alpha", Provider: ProviderAlibabaCloudDNS, ZoneID: "zone", Domain: "example.com", Name: "@", Type: "A", Value: "8.8.8.8", TTL: 600}},
		{OwnerKey: "acornfox:console", Record: Record{InstallationID: "install-alpha", Provider: ProviderAlibabaCloudDNS, ZoneID: "zone", Domain: "example.com", Name: "console", Type: "A", Value: "8.8.8.8", TTL: 600}},
		{OwnerKey: "acornfox:app", Record: Record{InstallationID: "install-alpha", Provider: ProviderAlibabaCloudDNS, ZoneID: "zone", Domain: "example.com", Name: "my-app.apps", Type: "A", Value: "8.8.8.8", TTL: 600}},
		{OwnerKey: "acornfox:cname", Record: Record{InstallationID: "install-alpha", Provider: ProviderAlibabaCloudDNS, ZoneID: "zone", Domain: "example.com", Name: "*.apps", Type: "CNAME", Value: "ingress.example.com", TTL: 600}},
		{OwnerKey: "acornfox:private", Record: Record{InstallationID: "install-alpha", Provider: ProviderAlibabaCloudDNS, ZoneID: "zone", Domain: "example.com", Name: "*.apps", Type: "A", Value: "10.0.0.1", TTL: 600}},
	} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("unsafe Alibaba desired record accepted: %+v", bad)
		}
	}
}

func TestBuildDryRunUsesOpaqueIDsAndRejectsOwnershipTupleDrift(t *testing.T) {
	desired, err := AlibabaWildcardRecords("install-alpha", "zone-opaque/A:17", "example.com", "8.8.8.8", "challenge-value", 600)
	if err != nil {
		t.Fatal(err)
	}
	currentA := alibabaRecord("record/opaque:42", "*.apps", "A", "1.1.1.1")
	currentTXT := alibabaRecord("record/opaque:99", "_acme-challenge.apps", "TXT", "old-challenge")
	plan, err := BuildDryRun("opaque-update", desired, []Record{currentA, currentTXT}, []OwnedRecord{owned("acornfox:wildcard-a", currentA), owned("acornfox:wildcard-dns01", currentTXT)}, time.Unix(3, 0))
	if err != nil || len(plan.Changes) != 2 {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	for _, mutate := range []func(*OwnedRecord){
		func(item *OwnedRecord) { item.Record.InstallationID = "install-other" },
		func(item *OwnedRecord) { item.Record.Provider = ProviderDNSPod },
		func(item *OwnedRecord) { item.Record.ZoneID = "zone-other" },
		func(item *OwnedRecord) { item.Record.Name = "other.apps" },
		func(item *OwnedRecord) { item.Record.Type = "TXT" },
	} {
		drifted := owned("acornfox:wildcard-a", currentA)
		mutate(&drifted)
		if _, err := BuildDryRun("tuple-drift", desired, []Record{currentA, currentTXT}, []OwnedRecord{drifted, owned("acornfox:wildcard-dns01", currentTXT)}, time.Now()); err == nil {
			t.Fatal("ownership tuple drift was accepted")
		}
	}
}

func TestBuildDryRunFailsClosedForForeignRecordsAndManualDrift(t *testing.T) {
	desired, err := AlibabaWildcardRecords("install-alpha", "zone-opaque/A:17", "example.com", "8.8.8.8", "challenge-value", 600)
	if err != nil {
		t.Fatal(err)
	}
	foreign := alibabaRecord("foreign-record", "*.apps", "A", "8.8.8.8")
	if _, err := BuildDryRun("foreign", desired, []Record{foreign}, nil, time.Now()); err == nil {
		t.Fatal("foreign record was adopted")
	}
	ownedA := owned("acornfox:wildcard-a", foreign)
	ownedA.Record.Value = "1.1.1.1"
	if _, err := BuildDryRun("drift", desired, []Record{foreign}, []OwnedRecord{ownedA}, time.Now()); err == nil {
		t.Fatal("manual drift was overwritten")
	}
}

func TestBuildDryRunRejectsDuplicateOpaqueProviderRecordID(t *testing.T) {
	desired, err := AlibabaWildcardRecords("install-alpha", "zone-opaque/A:17", "example.com", "8.8.8.8", "challenge-value", 600)
	if err != nil {
		t.Fatal(err)
	}
	first := alibabaRecord("same/opaque-id", "*.apps", "A", "8.8.8.8")
	second := first
	second.Name = "other.apps"
	if _, err := BuildDryRun("duplicate-provider-id", desired, []Record{first, second}, nil, time.Now()); err == nil {
		t.Fatal("duplicate provider record id was accepted")
	}
}

type memoryLedger struct {
	owned map[string][]OwnedRecord
	plans map[string]Plan
	last  map[string]time.Time
}

func newMemoryLedger() *memoryLedger {
	return &memoryLedger{owned: map[string][]OwnedRecord{}, plans: map[string]Plan{}, last: map[string]time.Time{}}
}
func (s *memoryLedger) ListOwned(_ context.Context, installationID, provider, zoneID string) ([]OwnedRecord, error) {
	return append([]OwnedRecord(nil), s.owned[zoneKey(Record{InstallationID: installationID, Provider: provider, ZoneID: zoneID})]...), nil
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
	records map[string][]Record
	calls   int
}

func (r *fixtureReader) ListRecords(_ context.Context, installationID, zoneID, domain string) ([]Record, error) {
	r.calls++
	return append([]Record(nil), r.records[opaqueTuple(installationID, zoneID, domain)]...), nil
}

func TestReconcilerRunsOnInjectedCadenceWithManagedProviderZone(t *testing.T) {
	desired, err := AlibabaWildcardRecords("install-alpha", "zone-opaque/A:17", "example.com", "8.8.8.8", "challenge-value", 600)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(600, 0).UTC()
	store := newMemoryLedger()
	reader := &fixtureReader{records: map[string][]Record{opaqueTuple("install-alpha", "zone-opaque/A:17", "example.com"): {}}}
	reconciler := &Reconciler{Store: store, Reader: reader, Desired: desired, Scope: "dns-acornfox", Clock: func() time.Time { return now }, Interval: time.Minute}
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

func TestReconcilerIncludesManagedEmptyZoneForDeletePlan(t *testing.T) {
	now := time.Unix(600, 0).UTC()
	store := newMemoryLedger()
	record := alibabaRecord("record-88", "*.apps", "A", "8.8.8.8")
	store.owned[zoneKey(record)] = []OwnedRecord{owned("acornfox:wildcard-a", record)}
	reader := &fixtureReader{records: map[string][]Record{opaqueTuple("install-alpha", "zone-opaque/A:17", "example.com"): {record}}}
	reconciler := &Reconciler{Store: store, Reader: reader, ManagedZones: []ManagedZone{{InstallationID: "install-alpha", Provider: ProviderAlibabaCloudDNS, ZoneID: "zone-opaque/A:17", Domain: "example.com"}}, Scope: "delete", Clock: func() time.Time { return now }, Interval: time.Minute}
	result, err := reconciler.ReconcileOnce(context.Background())
	if err != nil || !result.Due || len(result.Plan.Changes) != 1 || result.Plan.Changes[0].Kind != ChangeDelete || result.Plan.Changes[0].Before.RecordID != "record-88" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
