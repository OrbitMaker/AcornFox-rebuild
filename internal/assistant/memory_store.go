package assistant

import (
	"context"
	"crypto/subtle"
	"sort"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

const (
	defaultMaxEventsPerSession     = 4096
	defaultMaxEventBytesPerSession = 1 << 20
)

type MemoryStoreConfig struct {
	MaxEventsPerSession     int
	MaxEventBytesPerSession int
}

type memorySession struct {
	session      Session
	runs         map[domain.ID]Run
	runOrder     []domain.ID
	idempotency  map[string]domain.ID
	events       []Event
	nextCursor   uint64
	eventBytes   int
	messageBytes int
}

// MemoryStore is a stateful, concurrency-safe contract implementation for
// tests and local composition. It is not a production durability claim.
type MemoryStore struct {
	mu            sync.Mutex
	sessions      map[domain.ID]*memorySession
	maxEvents     int
	maxEventBytes int
}

func NewMemoryStore(config MemoryStoreConfig) *MemoryStore {
	maxEvents := config.MaxEventsPerSession
	if maxEvents <= 0 {
		maxEvents = defaultMaxEventsPerSession
	}
	maxBytes := config.MaxEventBytesPerSession
	if maxBytes <= 0 {
		maxBytes = defaultMaxEventBytesPerSession
	}
	return &MemoryStore{sessions: make(map[domain.ID]*memorySession), maxEvents: maxEvents, maxEventBytes: maxBytes}
}

func (s *MemoryStore) CreateSession(_ context.Context, actor Actor, session Session) error {
	if actor.AdminID.Empty() || session.ID.Empty() || session.ownerID != actor.AdminID || session.Scope.Validate() != nil {
		return ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, existing := range s.sessions {
		if existing.session.ownerID == actor.AdminID {
			count++
		}
	}
	if count >= MaxSessionsPerOwner {
		return ErrSessionLimit
	}
	if _, exists := s.sessions[session.ID]; exists {
		return ErrUnavailable
	}
	s.sessions[session.ID] = &memorySession{session: session, runs: make(map[domain.ID]Run), idempotency: make(map[string]domain.ID)}
	return nil
}

func (s *MemoryStore) ListSessions(_ context.Context, actor Actor) ([]Session, error) {
	if actor.AdminID.Empty() {
		return nil, ErrUnauthorized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]Session, 0)
	for _, item := range s.sessions {
		if item.session.ownerID == actor.AdminID {
			result = append(result, item.session)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.Before(result[j].CreatedAt) })
	return result, nil
}

func (s *MemoryStore) GetSession(_ context.Context, actor Actor, id domain.ID) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.sessionForActorLocked(actor, id)
	if !ok {
		return Session{}, ErrNotFound
	}
	return item.session, nil
}

func (s *MemoryStore) CreateOrReplayRun(_ context.Context, actor Actor, sessionID domain.ID, key, digest string, run Run, at time.Time) (Run, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.sessionForActorLocked(actor, sessionID)
	if !ok {
		return Run{}, false, ErrNotFound
	}
	if existingID, exists := item.idempotency[key]; exists {
		existing := item.runs[existingID]
		if subtle.ConstantTimeCompare([]byte(existing.requestDigest), []byte(digest)) != 1 {
			return Run{}, false, ErrIdempotencyConflict
		}
		return existing, true, nil
	}
	if len(item.runOrder) >= MaxRunsPerSession {
		return Run{}, false, ErrRunLimit
	}
	queued := 0
	for _, id := range item.runOrder {
		if status := item.runs[id].Status; status == RunAccepted || status == RunRunning {
			queued++
		}
	}
	if queued >= MaxQueuedRunsPerSession || item.messageBytes+len(run.message) > MaxRunMessageBytesPerSession {
		return Run{}, false, ErrRunLimit
	}
	run.ownerID, run.SessionID, run.requestDigest, run.idempotencyKey = actor.AdminID, sessionID, digest, key
	item.runs[run.ID] = run
	item.runOrder = append(item.runOrder, run.ID)
	item.idempotency[key] = run.ID
	item.messageBytes += len(run.message)
	item.session.UpdatedAt = at
	if _, err := s.appendEventLocked(item, run.ID, EventRunAccepted, run.message, at); err != nil {
		delete(item.runs, run.ID)
		delete(item.idempotency, key)
		item.messageBytes -= len(run.message)
		item.runOrder = item.runOrder[:len(item.runOrder)-1]
		return Run{}, false, err
	}
	return run, false, nil
}

func (s *MemoryStore) ClaimNextRun(_ context.Context, sessionID domain.ID, at time.Time) (Run, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.sessions[sessionID]
	if !ok {
		return Run{}, false, ErrNotFound
	}
	for _, id := range item.runOrder {
		if item.runs[id].Status == RunRunning {
			return Run{}, false, nil
		}
	}
	for _, id := range item.runOrder {
		run := item.runs[id]
		if run.Status != RunAccepted {
			continue
		}
		run.Status, run.UpdatedAt = RunRunning, at
		item.runs[id] = run
		item.session.UpdatedAt = at
		if _, err := s.appendEventLocked(item, id, EventRunStarted, "", at); err != nil {
			return Run{}, false, err
		}
		return run, true, nil
	}
	return Run{}, false, nil
}

func (s *MemoryStore) AppendEvent(_ context.Context, sessionID, runID domain.ID, kind EventType, text string, at time.Time) (Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.sessions[sessionID]
	if !ok {
		return Event{}, ErrNotFound
	}
	run, ok := item.runs[runID]
	if !ok || run.Status != RunRunning {
		return Event{}, ErrNotFound
	}
	if !validEventText(text) {
		return Event{}, ErrEventLimit
	}
	if kind == EventAssistantMessage {
		s.compactRunDeltasLocked(item, runID)
	}
	return s.appendEventLocked(item, runID, kind, text, at)
}

func (s *MemoryStore) compactRunDeltasLocked(item *memorySession, runID domain.ID) {
	originalLength := len(item.events)
	kept := item.events[:0]
	for _, event := range item.events {
		if event.RunID == runID && event.Type == EventAssistantDelta {
			item.eventBytes -= len(event.Text) + 128
			continue
		}
		kept = append(kept, event)
	}
	for index := len(kept); index < originalLength; index++ {
		item.events[index] = Event{}
	}
	item.events = kept
}

func (s *MemoryStore) FinishRun(_ context.Context, sessionID, runID domain.ID, status RunStatus, at time.Time) (Run, error) {
	if !terminalRunStatus(status) {
		return Run{}, ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.sessions[sessionID]
	if !ok {
		return Run{}, ErrNotFound
	}
	run, ok := item.runs[runID]
	if !ok {
		return Run{}, ErrNotFound
	}
	if terminalRunStatus(run.Status) {
		return run, nil
	}
	if run.Status != RunRunning {
		return Run{}, ErrInvalidInput
	}
	run.Status, run.UpdatedAt = status, at
	item.runs[runID], item.session.UpdatedAt = run, at
	kind := map[RunStatus]EventType{RunCompleted: EventRunCompleted, RunFailed: EventRunFailed, RunAborted: EventRunAborted, RunUnknown: EventRunUnknown}[status]
	if _, err := s.appendEventLocked(item, runID, kind, "", at); err != nil {
		return Run{}, err
	}
	return run, nil
}

func (s *MemoryStore) AbortSessionRuns(_ context.Context, actor Actor, sessionID domain.ID, at time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.sessionForActorLocked(actor, sessionID)
	if !ok {
		return 0, ErrNotFound
	}
	count := 0
	for _, id := range item.runOrder {
		run := item.runs[id]
		if run.Status != RunAccepted && run.Status != RunRunning {
			continue
		}
		run.Status, run.UpdatedAt = RunAborted, at
		item.runs[id] = run
		if _, err := s.appendEventLocked(item, id, EventRunAborted, "", at); err != nil {
			return count, err
		}
		count++
	}
	item.session.UpdatedAt = at
	return count, nil
}

func (s *MemoryStore) EventsAfter(_ context.Context, actor Actor, sessionID domain.ID, after uint64, limit int) (EventSnapshot, error) {
	if limit <= 0 || limit > DefaultEventPageSize {
		limit = DefaultEventPageSize
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.sessionForActorLocked(actor, sessionID)
	if !ok {
		return EventSnapshot{}, ErrNotFound
	}
	oldest, latest := item.nextCursor+1, item.nextCursor
	if len(item.events) > 0 {
		oldest = item.events[0].Cursor
	}
	if after > latest {
		return EventSnapshot{}, ErrInvalidInput
	}
	if len(item.events) > 0 && after+1 < oldest {
		return EventSnapshot{Status: CursorExpired, OldestCursor: oldest, LatestCursor: latest, Events: []Event{}}, ErrCursorExpired
	}
	result := make([]Event, 0, limit)
	remaining := 0
	for _, event := range item.events {
		if event.Cursor <= after {
			continue
		}
		if len(result) < limit {
			result = append(result, event)
		} else {
			remaining++
		}
	}
	status := CursorOK
	if remaining > 0 {
		status = CursorSlowConsumer
	}
	return EventSnapshot{Status: status, OldestCursor: oldest, LatestCursor: latest, Events: result}, nil
}

func (s *MemoryStore) RecoverInterrupted(_ context.Context, at time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, item := range s.sessions {
		for _, id := range item.runOrder {
			run := item.runs[id]
			if run.Status != RunAccepted && run.Status != RunRunning {
				continue
			}
			run.Status, run.UpdatedAt = RunUnknown, at
			item.runs[id] = run
			if _, err := s.appendEventLocked(item, id, EventRunUnknown, "", at); err != nil {
				return count, err
			}
			count++
		}
	}
	return count, nil
}

func (s *MemoryStore) sessionForActorLocked(actor Actor, id domain.ID) (*memorySession, bool) {
	if actor.AdminID.Empty() {
		return nil, false
	}
	item, ok := s.sessions[id]
	return item, ok && item.session.ownerID == actor.AdminID
}

func (s *MemoryStore) appendEventLocked(item *memorySession, runID domain.ID, kind EventType, text string, at time.Time) (Event, error) {
	if len(text) > MaxEventTextBytes || len(text) > s.maxEventBytes {
		return Event{}, ErrEventLimit
	}
	item.nextCursor++
	event := Event{Cursor: item.nextCursor, RunID: runID, Type: kind, OccurredAt: at, Text: text}
	item.events = append(item.events, event)
	item.eventBytes += len(text) + 128
	for len(item.events) > s.maxEvents || item.eventBytes > s.maxEventBytes {
		item.eventBytes -= len(item.events[0].Text) + 128
		item.events = item.events[1:]
	}
	return event, nil
}

var _ Store = (*MemoryStore)(nil)
