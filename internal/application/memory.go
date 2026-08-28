package application

import (
	"context"
	"sort"
	"sync"

	"github.com/open-card/open-card/internal/domain"
)

type memoryIdempotency struct {
	digest string
	result CreateApplicationResult
}

// MemoryRepository is the deterministic development/test implementation. It
// has the same idempotency and replay semantics as the PostgreSQL repository.
type MemoryRepository struct {
	mu           sync.RWMutex
	applications map[domain.ID]domain.Application
	idempotency  map[string]memoryIdempotency
	events       []Event
	nextSequence uint64
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		applications: make(map[domain.ID]domain.Application),
		idempotency:  make(map[string]memoryIdempotency),
	}
}

func (r *MemoryRepository) CreateApplication(_ context.Context, record CreateApplicationRecord) (CreateApplicationResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if previous, ok := r.idempotency[record.IdempotencyKey]; ok {
		if previous.digest != record.RequestDigest {
			return CreateApplicationResult{}, ErrIdempotencyConflict
		}
		return cloneCreateResult(previous.result), nil
	}
	r.nextSequence++
	record.Event.Sequence = r.nextSequence
	record.Event.ID = eventID(record.Event.Sequence)
	r.applications[record.Application.ID] = record.Application
	result := CreateApplicationResult{Application: record.Application, EnvironmentID: record.EnvironmentID, OperationID: record.OperationID, Event: cloneEvent(record.Event)}
	r.events = append(r.events, cloneEvent(record.Event))
	r.idempotency[record.IdempotencyKey] = memoryIdempotency{digest: record.RequestDigest, result: cloneCreateResult(result)}
	return result, nil
}

func (r *MemoryRepository) ListApplications(context.Context) ([]domain.Application, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	items := make([]domain.Application, 0, len(r.applications))
	for _, item := range r.applications {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].ID < items[j].ID
		}
		return items[i].CreatedAt.Before(items[j].CreatedAt)
	})
	return items, nil
}

func (r *MemoryRepository) GetApplication(_ context.Context, id domain.ID) (domain.Application, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	item, ok := r.applications[id]
	if !ok {
		return domain.Application{}, ErrNotFound
	}
	return item, nil
}

func (r *MemoryRepository) ListEvents(_ context.Context, filter EventFilter) ([]Event, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	limit := filter.Limit
	if limit <= 0 {
		limit = 1000
	}
	items := make([]Event, 0)
	for _, item := range r.events {
		if item.Sequence <= filter.AfterSequence || (filter.OperationID != "" && item.OperationID != filter.OperationID) {
			continue
		}
		if !filter.Since.IsZero() && item.OccurredAt.Before(filter.Since) {
			continue
		}
		items = append(items, cloneEvent(item))
		if len(items) == limit {
			break
		}
	}
	return items, nil
}

func cloneEvent(value Event) Event {
	value.EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	return value
}

func cloneCreateResult(value CreateApplicationResult) CreateApplicationResult {
	value.Event = cloneEvent(value.Event)
	return value
}

func eventID(sequence uint64) string {
	return "evt-" + formatSequence(sequence)
}

func formatSequence(sequence uint64) string {
	if sequence == 0 {
		return "0"
	}
	var digits [20]byte
	position := len(digits)
	for sequence > 0 {
		position--
		digits[position] = byte('0' + sequence%10)
		sequence /= 10
	}
	return string(digits[position:])
}
