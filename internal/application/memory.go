package application

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

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
	uploads      map[domain.ID]domain.SourceUploadRecord
	workspaces   map[string]domain.ID
	events       []Event
	nextSequence uint64
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		applications: make(map[domain.ID]domain.Application),
		idempotency:  make(map[string]memoryIdempotency),
		uploads:      make(map[domain.ID]domain.SourceUploadRecord),
		workspaces:   make(map[string]domain.ID),
	}
}

func (r *MemoryRepository) PreflightCreateApplication(_ context.Context, input CreateApplicationPreflight) (CreateApplicationResult, bool, error) {
	if strings.TrimSpace(input.IdempotencyKey) == "" || strings.TrimSpace(input.RequestDigest) == "" {
		return CreateApplicationResult{}, false, domain.ValidationError("application idempotency preflight is incomplete")
	}
	if input.Source != nil {
		if err := input.Source.Validate(); err != nil {
			return CreateApplicationResult{}, false, err
		}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if previous, ok := r.idempotency[input.IdempotencyKey]; ok {
		if previous.digest != input.RequestDigest {
			return CreateApplicationResult{}, false, ErrIdempotencyConflict
		}
		return cloneCreateResult(previous.result), true, nil
	}
	if input.Source != nil && input.Source.Kind == CreateApplicationSourceUpload {
		upload, found := r.uploads[input.Source.UploadID]
		if !found {
			return CreateApplicationResult{}, false, ErrNotFound
		}
		if upload.Status == domain.SourceUploadClaimed {
			return CreateApplicationResult{}, false, domain.WrapError(domain.ErrConflict, "source upload is already claimed", domain.ErrSourceUploadClaimed)
		}
		now := input.Now
		if now.IsZero() {
			now = time.Now().UTC()
		}
		if upload.Status != domain.SourceUploadReady || !now.Before(upload.ExpiresAt) {
			return CreateApplicationResult{}, false, domain.NewError(domain.ErrConflict, "source upload is not ready")
		}
	}
	return CreateApplicationResult{}, false, nil
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
	if record.Source != nil {
		switch record.Source.Kind {
		case CreateApplicationSourceUpload:
			if record.PreparedSource == nil || record.PreparedSource.ID.Empty() || record.PreparedSource.ApplicationID != record.Application.ID || record.PreparedSource.Kind != domain.SourceUpload || record.PreparedSource.Locator != "upload://"+record.Source.UploadID.String() {
				return CreateApplicationResult{}, domain.ValidationError("upload source requires a prepared immutable source revision")
			}
			if err := record.PreparedSource.Validate(); err != nil {
				return CreateApplicationResult{}, err
			}
			upload, found := r.uploads[record.Source.UploadID]
			if !found {
				return CreateApplicationResult{}, ErrNotFound
			}
			if upload.Status == domain.SourceUploadClaimed {
				return CreateApplicationResult{}, domain.WrapError(domain.ErrConflict, "source upload is already claimed", domain.ErrSourceUploadClaimed)
			}
			if upload.Status != domain.SourceUploadReady || !record.Application.CreatedAt.Before(upload.ExpiresAt) {
				return CreateApplicationResult{}, domain.NewError(domain.ErrConflict, "source upload is not ready")
			}
			upload.Status, upload.ClaimedApplicationID, upload.ClaimedSourceID, upload.UpdatedAt = domain.SourceUploadClaimed, record.Application.ID, record.PreparedSource.ID, record.Application.CreatedAt
			r.uploads[upload.ID] = upload
		case CreateApplicationSourceGit:
			if record.PreparedSource == nil || !PreparedSourceMatches(*record.Source, *record.PreparedSource) {
				return CreateApplicationResult{}, domain.ValidationError("git source requires a prepared immutable source revision")
			}
			if err := record.PreparedSource.Validate(); err != nil {
				return CreateApplicationResult{}, err
			}
		default:
			return CreateApplicationResult{}, domain.ValidationError("application source kind is unsupported")
		}
	}
	r.nextSequence++
	record.Event.Sequence = r.nextSequence
	record.Event.ID = eventID(record.Event.Sequence)
	r.applications[record.Application.ID] = record.Application
	if record.PreparedSource != nil {
		r.workspaces[record.PreparedSource.WorkspaceRef] = record.PreparedSource.ID
	}
	result := CreateApplicationResult{Application: record.Application, EnvironmentID: record.EnvironmentID, OperationID: record.OperationID, SourceRevisionID: preparedSourceID(record.PreparedSource), Event: cloneEvent(record.Event)}
	r.events = append(r.events, cloneEvent(record.Event))
	r.idempotency[record.IdempotencyKey] = memoryIdempotency{digest: record.RequestDigest, result: cloneCreateResult(result)}
	return result, nil
}

func (r *MemoryRepository) HasSourceWorkspaceReference(_ context.Context, workspace string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, found := r.workspaces[workspace]
	return found, nil
}

func preparedSourceID(source *domain.SourceRevision) domain.ID {
	if source == nil {
		return ""
	}
	return source.ID
}

// RegisterSourceUpload is a deterministic test/development helper. Production
// upload facts are written by the PostgreSQL upload store instead.
func (r *MemoryRepository) RegisterSourceUpload(upload domain.SourceUploadRecord) error {
	if err := upload.Validate(); err != nil {
		return err
	}
	if upload.Status != domain.SourceUploadReady {
		return domain.ValidationError("memory source upload must start ready")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.uploads[upload.ID]; exists {
		return ErrIdempotencyConflict
	}
	r.uploads[upload.ID] = upload
	return nil
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
