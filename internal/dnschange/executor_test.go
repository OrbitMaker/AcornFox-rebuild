package dnschange

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestExecutionIntentSurvivesPlanJSONRoundTrip(t *testing.T) {
	desired, zone := executionFixture("1.1.1.1")
	plan, err := BuildDryRun("round-trip", []DesiredRecord{desired}, nil, nil, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(plan.Changes)
	if err != nil {
		t.Fatal(err)
	}
	var changes []Change
	if err := json.Unmarshal(payload, &changes); err != nil {
		t.Fatal(err)
	}
	plan.Changes = changes
	if !sameExecutionIntent(plan, []DesiredRecord{desired}, zone) {
		t.Fatalf("intent changed payload=%s decoded=%#v desired=%#v", payload, *changes[0].After, desired)
	}
}

type executorLedger struct {
	mu      sync.Mutex
	owned   map[string]OwnedRecord
	plans   map[string]Plan
	steps   map[string]ExecutionStep
	deletes int
}

func newExecutorLedger() *executorLedger {
	return &executorLedger{owned: map[string]OwnedRecord{}, plans: map[string]Plan{}, steps: map[string]ExecutionStep{}}
}

func (s *executorLedger) ListOwned(_ context.Context, installationID, provider, zoneID string) ([]OwnedRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := []OwnedRecord{}
	for _, item := range s.owned {
		if item.Record.InstallationID == installationID && item.Record.Provider == provider && item.Record.ZoneID == zoneID {
			result = append(result, item)
		}
	}
	return result, nil
}
func (s *executorLedger) SavePlan(_ context.Context, plan Plan) (Plan, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.plans[plan.IdempotencyKey]; ok {
		if old.InputDigest != plan.InputDigest {
			return Plan{}, false, ErrIdempotencyConflict
		}
		return old, true, nil
	}
	s.plans[plan.IdempotencyKey] = plan
	return plan, false, nil
}
func (s *executorLedger) FindPlan(_ context.Context, key string) (Plan, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	plan, ok := s.plans[key]
	return plan, ok, nil
}
func (s *executorLedger) UpsertOwned(_ context.Context, owned OwnedRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := owned.Record.InstallationID + ":" + owned.OwnerKey
	if old, ok := s.owned[key]; ok && !sameOwnershipIdentity(old, owned) {
		return ErrOwnershipConflict
	}
	s.owned[key] = owned
	return nil
}
func (s *executorLedger) DeleteOwnedExact(_ context.Context, owned OwnedRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := owned.Record.InstallationID + ":" + owned.OwnerKey
	old, ok := s.owned[key]
	if !ok || !recordEqual(old.Record, owned.Record) || old.Record.RecordID != owned.Record.RecordID || old.Record.RequestID != owned.Record.RequestID {
		return ErrNotFound
	}
	delete(s.owned, key)
	s.deletes++
	return nil
}
func (s *executorLedger) EnsureExecutionSteps(_ context.Context, plan Plan) ([]ExecutionStep, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]ExecutionStep, 0, len(plan.Changes))
	for index, change := range plan.Changes {
		key := plan.ID + ":" + string(rune(index))
		step, ok := s.steps[key]
		if !ok {
			step = ExecutionStep{PlanID: plan.ID, ChangeIndex: index, RequestFingerprint: changeFingerprint(plan, index, change), Phase: ExecutionPlanned}
			s.steps[key] = step
		}
		if step.RequestFingerprint != changeFingerprint(plan, index, change) {
			return nil, ErrExecutionConflict
		}
		result = append(result, step)
	}
	return result, nil
}
func (s *executorLedger) ClaimProviderWrite(_ context.Context, _ ManagedZone, step ExecutionStep) (ExecutionPhase, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := step.PlanID + ":" + string(rune(step.ChangeIndex))
	current, ok := s.steps[key]
	if !ok || current.RequestFingerprint != step.RequestFingerprint {
		return "", false, ErrExecutionConflict
	}
	if current.Phase != ExecutionPlanned {
		return current.Phase, false, nil
	}
	current.Phase = ExecutionWriteStarted
	s.steps[key] = current
	return ExecutionWriteStarted, true, nil
}
func (s *executorLedger) SetExecutionPhase(_ context.Context, step ExecutionStep, phase ExecutionPhase) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := step.PlanID + ":" + string(rune(step.ChangeIndex))
	current, ok := s.steps[key]
	if !ok || current.RequestFingerprint != step.RequestFingerprint || !validExecutionTransition(current.Phase, phase) {
		return ErrExecutionConflict
	}
	current.Phase = phase
	s.steps[key] = current
	return nil
}

type executorProvider struct {
	mu       sync.Mutex
	records  []Record
	creates  int
	updates  int
	deletes  int
	writeErr error
	// applyThenErr simulates the provider accepting a write while the client
	// loses the definitive receipt. listResponses can then model eventual
	// consistency on subsequent reconciliation reads.
	applyThenErr  bool
	listResponses [][]Record
}

func (p *executorProvider) ListRecords(_ context.Context, _ ManagedZone) ([]Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.listResponses) > 0 {
		response := p.listResponses[0]
		p.listResponses = p.listResponses[1:]
		return append([]Record(nil), response...), nil
	}
	return append([]Record(nil), p.records...), nil
}
func (p *executorProvider) CreateRecord(_ context.Context, desired DesiredRecord) (WriteReceipt, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.creates++
	if p.writeErr != nil && !p.applyThenErr {
		return WriteReceipt{}, p.writeErr
	}
	record := desired.Record
	record.RecordID, record.RequestID, record.CreatedAt = "opaque-created-"+string(rune('0'+p.creates)), "request-create", time.Unix(100, 0).UTC()
	p.records = append(p.records, record)
	if p.writeErr != nil {
		return WriteReceipt{}, p.writeErr
	}
	return WriteReceipt{RecordID: record.RecordID, RequestID: record.RequestID}, nil
}
func (p *executorProvider) UpdateRecord(_ context.Context, update Record) (WriteReceipt, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.updates++
	if p.writeErr != nil && !p.applyThenErr {
		return WriteReceipt{}, p.writeErr
	}
	for index := range p.records {
		if p.records[index].RecordID == update.RecordID {
			p.records[index].Name, p.records[index].Type, p.records[index].Value, p.records[index].TTL, p.records[index].RequestID = update.Name, update.Type, update.Value, update.TTL, "request-update"
			if p.writeErr != nil {
				return WriteReceipt{}, p.writeErr
			}
			return WriteReceipt{RecordID: update.RecordID, RequestID: "request-update"}, nil
		}
	}
	return WriteReceipt{}, errors.New("missing fixture record")
}
func (p *executorProvider) DeleteRecord(_ context.Context, record Record) (WriteReceipt, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deletes++
	if p.writeErr != nil && !p.applyThenErr {
		return WriteReceipt{}, p.writeErr
	}
	for index := range p.records {
		if p.records[index].RecordID == record.RecordID {
			p.records = append(p.records[:index], p.records[index+1:]...)
			if p.writeErr != nil {
				return WriteReceipt{}, p.writeErr
			}
			return WriteReceipt{RecordID: record.RecordID, RequestID: "request-delete"}, nil
		}
	}
	return WriteReceipt{}, errors.New("missing fixture record")
}

type fixtureIndeterminate struct{}

func (fixtureIndeterminate) Error() string           { return "fixture write result unknown" }
func (fixtureIndeterminate) RequiresReconcile() bool { return true }

func executionFixture(value string) (DesiredRecord, ManagedZone) {
	record := DesiredRecord{OwnerKey: "acornfox:wildcard-a", Record: Record{InstallationID: "install-executor", Provider: ProviderAlibabaCloudDNS, ZoneID: "opaque-zone/17", Domain: "example.com", Name: "*.apps", Type: "A", Value: value, TTL: 600}}
	return record, ManagedZone{InstallationID: record.InstallationID, Provider: record.Provider, ZoneID: record.ZoneID, Domain: record.Domain}
}

func TestExecutorCreateReplayUpdateDeleteAndCleanup(t *testing.T) {
	first, zone := executionFixture("8.8.8.8")
	ledger, provider := newExecutorLedger(), &executorProvider{}
	executor := &Executor{Store: ledger, Provider: provider, Clock: func() time.Time { return time.Unix(200, 0).UTC() }}
	created, err := executor.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "create-key", Desired: []DesiredRecord{first}, ManagedZone: zone})
	if err != nil || created.Replayed || provider.creates != 1 || len(provider.records) != 1 {
		t.Fatalf("create=%+v err=%v creates=%d records=%+v", created, err, provider.creates, provider.records)
	}
	replay, err := executor.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "create-key", Desired: []DesiredRecord{first}, ManagedZone: zone})
	if err != nil || !replay.Replayed || provider.creates != 1 {
		t.Fatalf("replay=%+v err=%v creates=%d", replay, err, provider.creates)
	}
	second, _ := executionFixture("1.1.1.1")
	if _, err := executor.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "update-key", Desired: []DesiredRecord{second}, ManagedZone: zone}); err != nil || provider.updates != 1 || provider.records[0].Value != "1.1.1.1" {
		t.Fatalf("update err=%v updates=%d records=%+v", err, provider.updates, provider.records)
	}
	if replay, err := executor.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "update-key", Desired: []DesiredRecord{second}, ManagedZone: zone}); err != nil || !replay.Replayed || provider.updates != 1 {
		t.Fatalf("update replay=%+v err=%v updates=%d", replay, err, provider.updates)
	}
	if _, err := executor.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "cleanup-key", ManagedZone: zone}); err != nil || provider.deletes != 1 || len(provider.records) != 0 || ledger.deletes != 1 {
		t.Fatalf("cleanup err=%v deletes=%d records=%+v ledger_deletes=%d", err, provider.deletes, provider.records, ledger.deletes)
	}
	if replay, err := executor.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "cleanup-key", ManagedZone: zone}); err != nil || !replay.Replayed || provider.deletes != 1 {
		t.Fatalf("cleanup replay=%+v err=%v deletes=%d", replay, err, provider.deletes)
	}
}

func TestExecutorRefusesForeignDriftAndIndeterminateWrites(t *testing.T) {
	desired, zone := executionFixture("8.8.8.8")
	foreign := desired.Record
	foreign.RecordID, foreign.RequestID, foreign.CreatedAt = "foreign-opaque", "foreign-request", time.Unix(1, 0)
	for _, test := range []struct {
		name    string
		prepare func(*executorLedger, *executorProvider)
		want    error
	}{
		{"foreign", func(_ *executorLedger, provider *executorProvider) { provider.records = []Record{foreign} }, nil},
		{"indeterminate", func(_ *executorLedger, provider *executorProvider) { provider.writeErr = fixtureIndeterminate{} }, ErrReconcileRequired},
	} {
		t.Run(test.name, func(t *testing.T) {
			ledger, provider := newExecutorLedger(), &executorProvider{}
			test.prepare(ledger, provider)
			executor := &Executor{Store: ledger, Provider: provider}
			_, err := executor.Execute(context.Background(), ExecuteRequest{IdempotencyKey: test.name + "-key", Desired: []DesiredRecord{desired}, ManagedZone: zone})
			if test.want == nil {
				if err == nil || provider.creates != 0 || provider.updates != 0 || provider.deletes != 0 {
					t.Fatalf("foreign err=%v writes=%d/%d/%d", err, provider.creates, provider.updates, provider.deletes)
				}
				return
			}
			if !errors.Is(err, test.want) || provider.creates != 1 || provider.updates != 0 || provider.deletes != 0 {
				t.Fatalf("err=%v writes=%d/%d/%d", err, provider.creates, provider.updates, provider.deletes)
			}
		})
	}
}

func TestExecutorNeverRetriesIndeterminateProviderWritesAfterStaleReads(t *testing.T) {
	t.Run("create remains reconcile-required without ownership receipt", func(t *testing.T) {
		desired, zone := executionFixture("8.8.8.8")
		ledger := newExecutorLedger()
		provider := &executorProvider{writeErr: fixtureIndeterminate{}, applyThenErr: true}
		executor := &Executor{Store: ledger, Provider: provider}
		if _, err := executor.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "stale-create", Desired: []DesiredRecord{desired}, ManagedZone: zone}); !errors.Is(err, ErrReconcileRequired) || provider.creates != 1 {
			t.Fatalf("first create err=%v writes=%d", err, provider.creates)
		}
		provider.mu.Lock()
		actual := append([]Record(nil), provider.records...)
		provider.listResponses = [][]Record{{}, actual}
		provider.mu.Unlock()
		for range 2 {
			if _, err := executor.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "stale-create", Desired: []DesiredRecord{desired}, ManagedZone: zone}); !errors.Is(err, ErrReconcileRequired) {
				t.Fatalf("create replay err=%v", err)
			}
		}
		if provider.creates != 1 {
			t.Fatalf("create was retried %d times", provider.creates)
		}
	})
	for _, test := range []struct {
		name       string
		cleanup    bool
		wantWrites func(*executorProvider) int
	}{
		{"update", false, func(p *executorProvider) int { return p.updates }},
		{"delete", true, func(p *executorProvider) int { return p.deletes }},
	} {
		t.Run(test.name, func(t *testing.T) {
			before, zone := executionFixture("8.8.8.8")
			current := before.Record
			current.RecordID, current.RequestID, current.CreatedAt = "opaque-existing", "request-existing", time.Unix(1, 0)
			ledger := newExecutorLedger()
			if err := ledger.UpsertOwned(context.Background(), OwnedRecord{OwnerKey: before.OwnerKey, Record: current, UpdatedAt: time.Unix(1, 0)}); err != nil {
				t.Fatal(err)
			}
			provider := &executorProvider{records: []Record{current}, writeErr: fixtureIndeterminate{}, applyThenErr: true}
			executor := &Executor{Store: ledger, Provider: provider}
			desired := []DesiredRecord{}
			if !test.cleanup {
				next, _ := executionFixture("1.1.1.1")
				desired = []DesiredRecord{next}
			}
			key := "stale-" + test.name
			if _, err := executor.Execute(context.Background(), ExecuteRequest{IdempotencyKey: key, Desired: desired, ManagedZone: zone}); !errors.Is(err, ErrReconcileRequired) || test.wantWrites(provider) != 1 {
				t.Fatalf("first %s err=%v writes=%d", test.name, err, test.wantWrites(provider))
			}
			provider.mu.Lock()
			actual := append([]Record(nil), provider.records...)
			provider.listResponses = [][]Record{{current}, actual}
			provider.mu.Unlock()
			if _, err := executor.Execute(context.Background(), ExecuteRequest{IdempotencyKey: key, Desired: desired, ManagedZone: zone}); !errors.Is(err, ErrReconcileRequired) || test.wantWrites(provider) != 1 {
				t.Fatalf("stale replay %s err=%v writes=%d", test.name, err, test.wantWrites(provider))
			}
			if result, err := executor.Execute(context.Background(), ExecuteRequest{IdempotencyKey: key, Desired: desired, ManagedZone: zone}); err != nil || !result.Replayed || test.wantWrites(provider) != 1 {
				t.Fatalf("conclusive replay %s result=%+v err=%v writes=%d", test.name, result, err, test.wantWrites(provider))
			}
		})
	}
}

func TestExecutorSerializesConcurrentSameKey(t *testing.T) {
	desired, zone := executionFixture("8.8.8.8")
	ledger, provider := newExecutorLedger(), &executorProvider{}
	executor := &Executor{Store: ledger, Provider: provider}
	var group sync.WaitGroup
	errors := make(chan error, 2)
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := executor.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "concurrent-key", Desired: []DesiredRecord{desired}, ManagedZone: zone})
			errors <- err
		}()
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if provider.creates != 1 || len(provider.records) != 1 {
		t.Fatalf("duplicate write creates=%d records=%+v", provider.creates, provider.records)
	}
}

func TestExecutorReleasesIdleZoneLock(t *testing.T) {
	desired, zone := executionFixture("8.8.8.8")
	ledger, provider := newExecutorLedger(), &executorProvider{}
	executor := &Executor{Store: ledger, Provider: provider}
	if _, err := executor.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "lock-release", Desired: []DesiredRecord{desired}, ManagedZone: zone}); err != nil {
		t.Fatal(err)
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if len(executor.locks) != 0 {
		t.Fatalf("idle zone locks = %d", len(executor.locks))
	}
}

func TestExecutorRejectsDifferentReplayIntentBeforeProviderWrite(t *testing.T) {
	first, zone := executionFixture("8.8.8.8")
	ledger, provider := newExecutorLedger(), &executorProvider{}
	executor := &Executor{Store: ledger, Provider: provider}
	if _, err := executor.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "reused-key", Desired: []DesiredRecord{first}, ManagedZone: zone}); err != nil {
		t.Fatal(err)
	}
	second, _ := executionFixture("1.1.1.1")
	if _, err := executor.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "reused-key", Desired: []DesiredRecord{second}, ManagedZone: zone}); !errors.Is(err, ErrIdempotencyConflict) || provider.updates != 0 || provider.creates != 1 {
		t.Fatalf("err=%v creates=%d updates=%d", err, provider.creates, provider.updates)
	}
}
