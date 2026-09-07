package assistantactions

import (
	"context"
	"crypto/subtle"
	"github.com/open-card/open-card/internal/assistant"
	"github.com/open-card/open-card/internal/domain"
	"sort"
	"sync"
	"time"
)

type MemoryStore struct {
	mu    sync.Mutex
	items map[domain.ID]Proposal
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{items: map[domain.ID]Proposal{}} }
func (s *MemoryStore) GetPrepared(_ context.Context, actor assistant.Actor, key, requestDigest string) (Proposal, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.items {
		if item.proposalKey == key {
			if item.owner.AdminID != actor.AdminID || subtle.ConstantTimeCompare([]byte(item.requestDigest), []byte(requestDigest)) != 1 {
				return Proposal{}, false, ErrConflict
			}
			return item, true, nil
		}
	}
	return Proposal{}, false, nil
}
func (s *MemoryStore) PrepareOrReplay(_ context.Context, actor assistant.Actor, p Proposal) (Proposal, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.items {
		if item.proposalKey == p.proposalKey {
			if item.owner.AdminID != actor.AdminID || subtle.ConstantTimeCompare([]byte(item.requestDigest), []byte(p.requestDigest)) != 1 {
				return Proposal{}, false, ErrConflict
			}
			return item, true, nil
		}
	}
	s.items[p.ID] = p
	return p, false, nil
}
func (s *MemoryStore) List(_ context.Context, actor assistant.Actor, sid domain.ID, now time.Time) ([]Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := []Proposal{}
	for id, item := range s.items {
		if item.owner.AdminID != actor.AdminID || item.SessionID != sid {
			continue
		}
		if item.State == StatePending && !now.Before(item.ExpiresAt) {
			item.State = StateExpired
			item.UpdatedAt = now
			s.items[id] = item
		}
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.Before(result[j].CreatedAt) })
	return result, nil
}
func (s *MemoryStore) Reject(_ context.Context, actor assistant.Actor, sid, id domain.ID, now time.Time) (Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.items[id]
	if !ok || p.owner.AdminID != actor.AdminID || p.SessionID != sid {
		return Proposal{}, ErrNotFound
	}
	if p.State == StateRejected {
		return p, nil
	}
	if p.State != StatePending {
		return Proposal{}, ErrConflict
	}
	if !now.Before(p.ExpiresAt) {
		p.State = StateExpired
		p.UpdatedAt = now
		s.items[id] = p
		return p, ErrExpired
	}
	p.State = StateRejected
	p.UpdatedAt = now
	s.items[id] = p
	return p, nil
}
func (s *MemoryStore) BeginExecution(_ context.Context, actor assistant.Actor, sid, id domain.ID, current Target, now time.Time) (Proposal, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.items[id]
	if !ok || p.owner.AdminID != actor.AdminID || p.SessionID != sid {
		return Proposal{}, false, ErrNotFound
	}
	if p.State == StateExecuting || p.State == StateUnknown {
		return p, true, nil
	}
	if p.State != StatePending {
		return p, false, nil
	}
	if !now.Before(p.ExpiresAt) {
		p.State = StateExpired
		p.UpdatedAt = now
		s.items[id] = p
		return p, false, ErrExpired
	}
	if !p.Target.Equal(current) {
		p.State = StateExpired
		p.Verification = Verification{State: VerificationFailed, Verdict: "target_changed"}
		p.UpdatedAt = now
		s.items[id] = p
		return p, false, ErrTargetChanged
	}
	for otherID, other := range s.items {
		if otherID != id && other.Target.ApplicationID == p.Target.ApplicationID && activeState(other.State) {
			return Proposal{}, false, ErrConflict
		}
	}
	p.State = StateExecuting
	p.UpdatedAt = now
	s.items[id] = p
	return p, true, nil
}
func (s *MemoryStore) FinishExecution(_ context.Context, id, operationID domain.ID, state State, now time.Time) (Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.items[id]
	if !ok {
		return Proposal{}, ErrNotFound
	}
	if p.State == StateAccepted || p.State == StateFailed {
		return p, nil
	}
	if p.State != StateExecuting && p.State != StateUnknown {
		return Proposal{}, ErrConflict
	}
	if state != StateAccepted && state != StateFailed && state != StateUnknown {
		return Proposal{}, ErrInvalid
	}
	p.State = state
	if !operationID.Empty() {
		p.OperationID = operationID
	}
	p.UpdatedAt = now
	s.items[id] = p
	return p, nil
}
func (s *MemoryStore) FinishVerification(_ context.Context, id, operationID domain.ID, v Verification, now time.Time) (Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.items[id]
	if !ok || p.OperationID != operationID {
		return Proposal{}, ErrNotFound
	}
	if p.State == StateVerified || p.State == StateFailed {
		return p, nil
	}
	if p.State != StateAccepted && p.State != StateUnknown {
		return Proposal{}, ErrConflict
	}
	if v.State == VerificationVerified {
		p.State = StateVerified
	} else if v.State == VerificationFailed {
		p.State = StateFailed
	} else {
		return Proposal{}, ErrInvalid
	}
	p.Verification = v
	p.UpdatedAt = now
	s.items[id] = p
	return p, nil
}

var _ Store = (*MemoryStore)(nil)
