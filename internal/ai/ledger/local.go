package ledger

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

func (s *LocalStore) AppendInvocation(ctx context.Context, request AppendInvocationRequest) (Invocation, bool, error) {
	if err := checkContext(ctx); err != nil {
		return Invocation{}, false, err
	}
	if s == nil {
		return Invocation{}, false, ErrInvalid
	}
	record := cloneInvocation(request.Record)
	key, digest, err := normalizeRequest(firstNonEmpty(request.IdempotencyKey, record.IdempotencyKey), firstNonEmpty(request.RequestDigest, record.RequestDigest), record, record.ID)
	if err != nil {
		return Invocation{}, false, err
	}
	record.ID = ensureID("aiinv", record.ID, key, digest)
	record.IdempotencyKey, record.RequestDigest = key, digest
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if err := validateInvocation(record); err != nil {
		return Invocation{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendInvocationLocked(record, key, digest)
}

func (s *LocalStore) AppendContext(ctx context.Context, request AppendContextRequest) (ContextPackage, bool, error) {
	if err := checkContext(ctx); err != nil {
		return ContextPackage{}, false, err
	}
	if s == nil {
		return ContextPackage{}, false, ErrInvalid
	}
	record := cloneContext(request.Record)
	key, digest, err := normalizeRequest(firstNonEmpty(request.IdempotencyKey, record.IdempotencyKey), firstNonEmpty(request.RequestDigest, record.RequestDigest), record, record.ID)
	if err != nil {
		return ContextPackage{}, false, err
	}
	record.ID = ensureID("aictx", record.ID, key, digest)
	record.IdempotencyKey, record.RequestDigest = key, digest
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if err := validateContext(record); err != nil {
		return ContextPackage{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendContextLocked(record, key, digest)
}

func (s *LocalStore) AppendPlan(ctx context.Context, request AppendPlanRequest) (ActionPlan, bool, error) {
	if err := checkContext(ctx); err != nil {
		return ActionPlan{}, false, err
	}
	if s == nil {
		return ActionPlan{}, false, ErrInvalid
	}
	record := clonePlan(request.Record)
	key, digest, err := normalizeRequest(firstNonEmpty(request.IdempotencyKey, record.IdempotencyKey), firstNonEmpty(request.RequestDigest, record.RequestDigest), record, record.ID)
	if err != nil {
		return ActionPlan{}, false, err
	}
	record.ID = ensureID("aiplan", record.ID, key, digest)
	record.IdempotencyKey, record.RequestDigest = key, digest
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if err := validatePlan(record); err != nil {
		return ActionPlan{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendPlanLocked(record, key, digest)
}

func (s *LocalStore) AppendToolAction(ctx context.Context, request AppendToolActionRequest) (ToolAction, bool, error) {
	if err := checkContext(ctx); err != nil {
		return ToolAction{}, false, err
	}
	if s == nil {
		return ToolAction{}, false, ErrInvalid
	}
	record := cloneAction(request.Record)
	key, digest, err := normalizeRequest(firstNonEmpty(request.IdempotencyKey, record.IdempotencyKey), firstNonEmpty(request.RequestDigest, record.RequestDigest), record, record.ID)
	if err != nil {
		return ToolAction{}, false, err
	}
	record.ID = ensureID("aiaction", record.ID, key, digest)
	record.IdempotencyKey, record.RequestDigest = key, digest
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if err := validateAction(record); err != nil {
		return ToolAction{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendActionLocked(record, key, digest)
}

func (s *LocalStore) AppendVerification(ctx context.Context, request AppendVerificationRequest) (Verification, bool, error) {
	if err := checkContext(ctx); err != nil {
		return Verification{}, false, err
	}
	if s == nil {
		return Verification{}, false, ErrInvalid
	}
	record := cloneVerification(request.Record)
	key, digest, err := normalizeRequest(firstNonEmpty(request.IdempotencyKey, record.IdempotencyKey), firstNonEmpty(request.RequestDigest, record.RequestDigest), record, record.ID)
	if err != nil {
		return Verification{}, false, err
	}
	record.ID = ensureID("aiver", record.ID, key, digest)
	record.IdempotencyKey, record.RequestDigest = key, digest
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if err := validateVerification(record); err != nil {
		return Verification{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendVerificationLocked(record, key, digest)
}

func (s *LocalStore) AppendRollback(ctx context.Context, request AppendRollbackRequest) (Rollback, bool, error) {
	if err := checkContext(ctx); err != nil {
		return Rollback{}, false, err
	}
	if s == nil {
		return Rollback{}, false, ErrInvalid
	}
	record := cloneRollback(request.Record)
	key, digest, err := normalizeRequest(firstNonEmpty(request.IdempotencyKey, record.IdempotencyKey), firstNonEmpty(request.RequestDigest, record.RequestDigest), record, record.ID)
	if err != nil {
		return Rollback{}, false, err
	}
	record.ID = ensureID("airollback", record.ID, key, digest)
	record.IdempotencyKey, record.RequestDigest = key, digest
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if err := validateRollback(record); err != nil {
		return Rollback{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendRollbackLocked(record, key, digest)
}

func (s *LocalStore) AppendOutcome(ctx context.Context, request AppendOutcomeRequest) (Outcome, bool, error) {
	if err := checkContext(ctx); err != nil {
		return Outcome{}, false, err
	}
	if s == nil {
		return Outcome{}, false, ErrInvalid
	}
	record := request.Record
	key, digest, err := normalizeRequest(firstNonEmpty(request.IdempotencyKey, record.IdempotencyKey), firstNonEmpty(request.RequestDigest, record.RequestDigest), record, record.ID)
	if err != nil {
		return Outcome{}, false, err
	}
	record.ID = ensureID("aioutcome", record.ID, key, digest)
	record.IdempotencyKey, record.RequestDigest = key, digest
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if err := validateOutcome(record); err != nil {
		return Outcome{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendOutcomeLocked(record, key, digest)
}

func (s *LocalStore) AppendCandidateRef(ctx context.Context, request AppendCandidateRefRequest) (CandidateRef, bool, error) {
	if err := checkContext(ctx); err != nil {
		return CandidateRef{}, false, err
	}
	if s == nil {
		return CandidateRef{}, false, ErrInvalid
	}
	record := request.Record
	key, digest, err := normalizeRequest(firstNonEmpty(request.IdempotencyKey, record.IdempotencyKey), firstNonEmpty(request.RequestDigest, record.RequestDigest), record, record.ID)
	if err != nil {
		return CandidateRef{}, false, err
	}
	record.ID = ensureID("aicandidate", record.ID, key, digest)
	record.IdempotencyKey, record.RequestDigest = key, digest
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if err := validateCandidateRef(record); err != nil {
		return CandidateRef{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record.InvocationID = s.resolveInvocationIDLocked(record.InvocationID)
	return s.appendCandidateLocked(record, key, digest)
}

func (s *LocalStore) resolveInvocationIDLocked(id string) string {
	if _, ok := s.invocations[id]; ok {
		return id
	}
	for candidateID := range s.invocations {
		if strings.HasSuffix(candidateID, "_"+id) {
			return candidateID
		}
	}
	return id
}

func (s *LocalStore) AppendIntervention(ctx context.Context, request AppendInterventionRequest) (Intervention, bool, error) {
	if err := checkContext(ctx); err != nil {
		return Intervention{}, false, err
	}
	if s == nil {
		return Intervention{}, false, ErrInvalid
	}
	record := cloneIntervention(request.Record)
	key, digest, err := normalizeRequest(firstNonEmpty(request.IdempotencyKey, record.Invocation.IdempotencyKey), firstNonEmpty(request.RequestDigest, record.Invocation.RequestDigest), record, record.ID)
	if err != nil {
		return Intervention{}, false, err
	}
	record.ID = ensureID("aiint", record.ID, key, digest)
	if record.Invocation.ID == "" {
		record.Invocation.ID = ensureID("aiinv", "", key, digest)
	}
	record.Invocation.IdempotencyKey, record.Invocation.RequestDigest = key, digest
	if record.Invocation.CreatedAt.IsZero() {
		record.Invocation.CreatedAt = time.Now().UTC()
	}
	if record.Context != nil {
		record.Context.InvocationID = firstNonEmpty(record.Context.InvocationID, record.Invocation.ID)
		record.Context.IdempotencyKey = firstNonEmpty(record.Context.IdempotencyKey, key+":context")
		record.Context.RequestDigest = firstNonEmpty(record.Context.RequestDigest, Digest(*record.Context))
		record.Context.ID = ensureID("aictx", record.Context.ID, record.Context.IdempotencyKey, record.Context.RequestDigest)
		if record.Context.CreatedAt.IsZero() {
			record.Context.CreatedAt = record.Invocation.CreatedAt
		}
	}
	if record.Plan != nil {
		record.Plan.InvocationID = firstNonEmpty(record.Plan.InvocationID, record.Invocation.ID)
		record.Plan.IdempotencyKey = firstNonEmpty(record.Plan.IdempotencyKey, key+":plan")
		record.Plan.RequestDigest = firstNonEmpty(record.Plan.RequestDigest, Digest(*record.Plan))
		record.Plan.ID = ensureID("aiplan", record.Plan.ID, record.Plan.IdempotencyKey, record.Plan.RequestDigest)
		if record.Plan.CreatedAt.IsZero() {
			record.Plan.CreatedAt = record.Invocation.CreatedAt
		}
	}
	for i := range record.Actions {
		record.Actions[i].InvocationID = firstNonEmpty(record.Actions[i].InvocationID, record.Invocation.ID)
		record.Actions[i].IdempotencyKey = firstNonEmpty(record.Actions[i].IdempotencyKey, fmt.Sprintf("%s:action:%d", key, i))
		record.Actions[i].RequestDigest = firstNonEmpty(record.Actions[i].RequestDigest, Digest(record.Actions[i]))
		record.Actions[i].ID = ensureID("aiaction", record.Actions[i].ID, record.Actions[i].IdempotencyKey, record.Actions[i].RequestDigest)
		if record.Actions[i].CreatedAt.IsZero() {
			record.Actions[i].CreatedAt = record.Invocation.CreatedAt
		}
	}
	for i := range record.Verifications {
		record.Verifications[i].InvocationID = firstNonEmpty(record.Verifications[i].InvocationID, record.Invocation.ID)
		record.Verifications[i].IdempotencyKey = firstNonEmpty(record.Verifications[i].IdempotencyKey, fmt.Sprintf("%s:verification:%d", key, i))
		record.Verifications[i].RequestDigest = firstNonEmpty(record.Verifications[i].RequestDigest, Digest(record.Verifications[i]))
		record.Verifications[i].ID = ensureID("aiver", record.Verifications[i].ID, record.Verifications[i].IdempotencyKey, record.Verifications[i].RequestDigest)
		if record.Verifications[i].CreatedAt.IsZero() {
			record.Verifications[i].CreatedAt = record.Invocation.CreatedAt
		}
	}
	if record.Rollback != nil {
		record.Rollback.InvocationID = firstNonEmpty(record.Rollback.InvocationID, record.Invocation.ID)
		record.Rollback.IdempotencyKey = firstNonEmpty(record.Rollback.IdempotencyKey, key+":rollback")
		record.Rollback.RequestDigest = firstNonEmpty(record.Rollback.RequestDigest, Digest(*record.Rollback))
		record.Rollback.ID = ensureID("airollback", record.Rollback.ID, record.Rollback.IdempotencyKey, record.Rollback.RequestDigest)
		if record.Rollback.CreatedAt.IsZero() {
			record.Rollback.CreatedAt = record.Invocation.CreatedAt
		}
	}
	if record.Outcome != nil {
		record.Outcome.IdempotencyKey = firstNonEmpty(record.Outcome.IdempotencyKey, key+":outcome")
		record.Outcome.RequestDigest = firstNonEmpty(record.Outcome.RequestDigest, Digest(*record.Outcome))
		record.Outcome.ID = ensureID("aioutcome", record.Outcome.ID, record.Outcome.IdempotencyKey, record.Outcome.RequestDigest)
		record.Outcome.InvocationID = firstNonEmpty(record.Outcome.InvocationID, record.Invocation.ID)
		if record.Outcome.CreatedAt.IsZero() {
			record.Outcome.CreatedAt = record.Invocation.CreatedAt
		}
	}
	if record.CandidateRef != nil {
		record.CandidateRef.IdempotencyKey = firstNonEmpty(record.CandidateRef.IdempotencyKey, key+":candidate")
		record.CandidateRef.RequestDigest = firstNonEmpty(record.CandidateRef.RequestDigest, Digest(*record.CandidateRef))
		record.CandidateRef.ID = ensureID("aicandidate", record.CandidateRef.ID, record.CandidateRef.IdempotencyKey, record.CandidateRef.RequestDigest)
		record.CandidateRef.InvocationID = firstNonEmpty(record.CandidateRef.InvocationID, record.Invocation.ID)
		if record.CandidateRef.CreatedAt.IsZero() {
			record.CandidateRef.CreatedAt = record.Invocation.CreatedAt
		}
	}
	if err := validateIntervention(record); err != nil {
		return Intervention{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.interventions[record.ID]; ok {
		if entry, exists := s.keys[key]; !exists || entry.Digest != digest || entry.Kind != "intervention" {
			return Intervention{}, false, ErrConflict
		}
		return cloneIntervention(existing), true, nil
	}
	backup := s.copyState()
	var replay bool
	if _, replay, err = s.appendInvocationLocked(record.Invocation, key, digest); err != nil {
		s.restoreState(backup)
		return Intervention{}, false, err
	}
	if replay {
		if existing, ok := s.interventions[record.ID]; ok {
			return cloneIntervention(existing), true, nil
		}
	}
	if record.Context != nil {
		if _, _, err = s.appendContextLocked(*record.Context, record.Context.IdempotencyKey, record.Context.RequestDigest); err != nil {
			s.restoreState(backup)
			return Intervention{}, false, err
		}
	}
	if record.Plan != nil {
		if _, _, err = s.appendPlanLocked(*record.Plan, record.Plan.IdempotencyKey, record.Plan.RequestDigest); err != nil {
			s.restoreState(backup)
			return Intervention{}, false, err
		}
	}
	for _, item := range record.Actions {
		if _, _, err = s.appendActionLocked(item, item.IdempotencyKey, item.RequestDigest); err != nil {
			s.restoreState(backup)
			return Intervention{}, false, err
		}
	}
	for _, item := range record.Verifications {
		if _, _, err = s.appendVerificationLocked(item, item.IdempotencyKey, item.RequestDigest); err != nil {
			s.restoreState(backup)
			return Intervention{}, false, err
		}
	}
	if record.Rollback != nil {
		if _, _, err = s.appendRollbackLocked(*record.Rollback, record.Rollback.IdempotencyKey, record.Rollback.RequestDigest); err != nil {
			s.restoreState(backup)
			return Intervention{}, false, err
		}
	}
	if record.Outcome != nil {
		if _, _, err = s.appendOutcomeLocked(*record.Outcome, record.Outcome.IdempotencyKey, record.Outcome.RequestDigest); err != nil {
			s.restoreState(backup)
			return Intervention{}, false, err
		}
	}
	if record.CandidateRef != nil {
		if _, _, err = s.appendCandidateLocked(*record.CandidateRef, record.CandidateRef.IdempotencyKey, record.CandidateRef.RequestDigest); err != nil {
			s.restoreState(backup)
			return Intervention{}, false, err
		}
	}
	s.interventions[record.ID] = cloneIntervention(record)
	s.keys[key] = idempotencyEntry{Digest: digest, Kind: "intervention", ID: record.ID}
	return cloneIntervention(record), false, nil
}

func (s *LocalStore) appendInvocationLocked(record Invocation, key, digest string) (Invocation, bool, error) {
	if entry, ok := s.keys[key]; ok {
		if entry.Digest != digest || entry.Kind != "invocation" {
			return Invocation{}, false, ErrConflict
		}
		item, exists := s.invocations[entry.ID]
		if !exists {
			return Invocation{}, false, ErrCorrupt
		}
		return cloneInvocation(item), true, nil
	}
	if _, ok := s.invocations[record.ID]; ok {
		return Invocation{}, false, ErrConflict
	}
	s.invocations[record.ID] = cloneInvocation(record)
	s.keys[key] = idempotencyEntry{Digest: digest, Kind: "invocation", ID: record.ID}
	return cloneInvocation(record), false, nil
}
func (s *LocalStore) appendContextLocked(record ContextPackage, key, digest string) (ContextPackage, bool, error) {
	if entry, ok := s.keys[key]; ok {
		if entry.Digest != digest || entry.Kind != "context" {
			return ContextPackage{}, false, ErrConflict
		}
		item, exists := s.contexts[entry.ID]
		if !exists {
			return ContextPackage{}, false, ErrCorrupt
		}
		return cloneContext(item), true, nil
	}
	if _, ok := s.contexts[record.ID]; ok {
		return ContextPackage{}, false, ErrConflict
	}
	s.contexts[record.ID] = cloneContext(record)
	s.keys[key] = idempotencyEntry{Digest: digest, Kind: "context", ID: record.ID}
	return cloneContext(record), false, nil
}
func (s *LocalStore) appendPlanLocked(record ActionPlan, key, digest string) (ActionPlan, bool, error) {
	if entry, ok := s.keys[key]; ok {
		if entry.Digest != digest || entry.Kind != "plan" {
			return ActionPlan{}, false, ErrConflict
		}
		item, exists := s.plans[entry.ID]
		if !exists {
			return ActionPlan{}, false, ErrCorrupt
		}
		return clonePlan(item), true, nil
	}
	if _, ok := s.plans[record.ID]; ok {
		return ActionPlan{}, false, ErrConflict
	}
	s.plans[record.ID] = clonePlan(record)
	s.keys[key] = idempotencyEntry{Digest: digest, Kind: "plan", ID: record.ID}
	return clonePlan(record), false, nil
}
func (s *LocalStore) appendActionLocked(record ToolAction, key, digest string) (ToolAction, bool, error) {
	if entry, ok := s.keys[key]; ok {
		if entry.Digest != digest || entry.Kind != "action" {
			return ToolAction{}, false, ErrConflict
		}
		item, exists := s.actions[entry.ID]
		if !exists {
			return ToolAction{}, false, ErrCorrupt
		}
		return cloneAction(item), true, nil
	}
	if _, ok := s.actions[record.ID]; ok {
		return ToolAction{}, false, ErrConflict
	}
	s.actions[record.ID] = cloneAction(record)
	s.keys[key] = idempotencyEntry{Digest: digest, Kind: "action", ID: record.ID}
	return cloneAction(record), false, nil
}
func (s *LocalStore) appendVerificationLocked(record Verification, key, digest string) (Verification, bool, error) {
	if entry, ok := s.keys[key]; ok {
		if entry.Digest != digest || entry.Kind != "verification" {
			return Verification{}, false, ErrConflict
		}
		item, exists := s.verifications[entry.ID]
		if !exists {
			return Verification{}, false, ErrCorrupt
		}
		return cloneVerification(item), true, nil
	}
	if _, ok := s.verifications[record.ID]; ok {
		return Verification{}, false, ErrConflict
	}
	s.verifications[record.ID] = cloneVerification(record)
	s.keys[key] = idempotencyEntry{Digest: digest, Kind: "verification", ID: record.ID}
	return cloneVerification(record), false, nil
}
func (s *LocalStore) appendRollbackLocked(record Rollback, key, digest string) (Rollback, bool, error) {
	if entry, ok := s.keys[key]; ok {
		if entry.Digest != digest || entry.Kind != "rollback" {
			return Rollback{}, false, ErrConflict
		}
		item, exists := s.rollbacks[entry.ID]
		if !exists {
			return Rollback{}, false, ErrCorrupt
		}
		return cloneRollback(item), true, nil
	}
	if _, ok := s.rollbacks[record.ID]; ok {
		return Rollback{}, false, ErrConflict
	}
	s.rollbacks[record.ID] = cloneRollback(record)
	s.keys[key] = idempotencyEntry{Digest: digest, Kind: "rollback", ID: record.ID}
	return cloneRollback(record), false, nil
}
func (s *LocalStore) appendOutcomeLocked(record Outcome, key, digest string) (Outcome, bool, error) {
	if entry, ok := s.keys[key]; ok {
		if entry.Digest != digest || entry.Kind != "outcome" {
			return Outcome{}, false, ErrConflict
		}
		item, exists := s.outcomes[entry.ID]
		if !exists {
			return Outcome{}, false, ErrCorrupt
		}
		return item, true, nil
	}
	if _, ok := s.outcomes[record.ID]; ok {
		return Outcome{}, false, ErrConflict
	}
	s.outcomes[record.ID] = record
	s.keys[key] = idempotencyEntry{Digest: digest, Kind: "outcome", ID: record.ID}
	return record, false, nil
}
func (s *LocalStore) appendCandidateLocked(record CandidateRef, key, digest string) (CandidateRef, bool, error) {
	if entry, ok := s.keys[key]; ok {
		if entry.Digest != digest || entry.Kind != "candidate" {
			return CandidateRef{}, false, ErrConflict
		}
		item, exists := s.candidates[entry.ID]
		if !exists {
			return CandidateRef{}, false, ErrCorrupt
		}
		return item, true, nil
	}
	if _, ok := s.candidates[record.ID]; ok {
		return CandidateRef{}, false, ErrConflict
	}
	s.candidates[record.ID] = record
	s.keys[key] = idempotencyEntry{Digest: digest, Kind: "candidate", ID: record.ID}
	return record, false, nil
}

func (s *LocalStore) GetIntervention(ctx context.Context, id string) (Intervention, error) {
	if err := checkContext(ctx); err != nil {
		return Intervention{}, err
	}
	if s == nil {
		return Intervention{}, ErrInvalid
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if item, ok := s.interventions[strings.TrimSpace(id)]; ok {
		return cloneIntervention(item), nil
	}
	item, ok := s.invocations[strings.TrimSpace(id)]
	if !ok {
		return Intervention{}, ErrNotFound
	}
	return s.buildInterventionLocked(item), nil
}

func (s *LocalStore) buildInterventionLocked(inv Invocation) Intervention {
	result := Intervention{ID: inv.ID, Invocation: cloneInvocation(inv)}
	for _, item := range s.contexts {
		if item.InvocationID == inv.ID {
			value := cloneContext(item)
			result.Context = &value
			break
		}
	}
	for _, item := range s.plans {
		if item.InvocationID == inv.ID {
			value := clonePlan(item)
			result.Plan = &value
			break
		}
	}
	for _, item := range s.actions {
		if item.InvocationID == inv.ID {
			result.Actions = append(result.Actions, cloneAction(item))
		}
	}
	for _, item := range s.verifications {
		if item.InvocationID == inv.ID {
			result.Verifications = append(result.Verifications, cloneVerification(item))
		}
	}
	for _, item := range s.rollbacks {
		if item.InvocationID == inv.ID {
			value := cloneRollback(item)
			result.Rollback = &value
			break
		}
	}
	for _, item := range s.outcomes {
		if item.InvocationID == inv.ID {
			value := cloneOutcome(item)
			result.Outcome = &value
			break
		}
	}
	for _, item := range s.candidates {
		if item.InvocationID == inv.ID {
			value := item
			result.CandidateRef = &value
			break
		}
	}
	sort.Slice(result.Actions, func(i, j int) bool { return result.Actions[i].Sequence < result.Actions[j].Sequence })
	sort.Slice(result.Verifications, func(i, j int) bool {
		return result.Verifications[i].CreatedAt.Before(result.Verifications[j].CreatedAt)
	})
	return result
}

func (s *LocalStore) Query(ctx context.Context, filter QueryFilter) ([]Intervention, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, ErrInvalid
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]Intervention, 0, len(s.invocations))
	for _, inv := range s.invocations {
		item := s.buildInterventionLocked(inv)
		if !matchesInvocation(inv, filter) || !matchesIntervention(item, filter) {
			continue
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Invocation.CreatedAt.Equal(items[j].Invocation.CreatedAt) {
			return items[i].Invocation.ID < items[j].Invocation.ID
		}
		return items[i].Invocation.CreatedAt.Before(items[j].Invocation.CreatedAt)
	})
	if limit := normalizeLimit(filter.Limit); len(items) > limit {
		items = items[:limit]
	}
	for i := range items {
		items[i] = cloneIntervention(items[i])
	}
	return items, nil
}

func (s *LocalStore) Metrics(ctx context.Context, filter QueryFilter) (Metrics, error) {
	items, err := s.Query(ctx, filter)
	if err != nil {
		return Metrics{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var metrics Metrics
	candidates := make(map[string]struct{})
	for _, item := range items {
		metrics.Interventions++
		status := item.Invocation.Outcome
		if item.Outcome != nil {
			status = item.Outcome.Status
			metrics.Tokens += item.Outcome.Tokens
			metrics.DurationMS += item.Outcome.DurationMS
		} else {
			metrics.Tokens += item.Invocation.Tokens
			metrics.DurationMS += item.Invocation.DurationMS
		}
		switch status {
		case OutcomeSucceeded:
			metrics.Succeeded++
		case OutcomeFailed:
			metrics.Failed++
		case OutcomeRolledBack:
			metrics.RolledBack++
		}
		for _, verification := range item.Verifications {
			if !verification.Passed {
				metrics.VerificationFailed++
			}
		}
	}
	// Candidate references are independent append-only facts.  Count them
	// from their own map so multiple references for one occurrence are not
	// hidden by Intervention's convenience pointer (and are never double
	// counted through the invocation loop above).
	for _, ref := range s.candidates {
		invocation, ok := s.invocations[ref.InvocationID]
		if !ok {
			continue
		}
		item := s.buildInterventionLocked(invocation)
		if !matchesInvocation(invocation, filter) || !matchesIntervention(item, filter) {
			continue
		}
		metrics.CandidateRefs++
		candidates[ref.CandidateID] = struct{}{}
	}
	metrics.DistinctCandidates = int64(len(candidates))
	return metrics, nil
}

func matchesInvocation(inv Invocation, filter QueryFilter) bool {
	if filter.ApplicationID != "" && inv.ApplicationID != filter.ApplicationID {
		return false
	}
	if filter.TaskType != "" && inv.TaskType != filter.TaskType {
		return false
	}
	if !filter.From.IsZero() && inv.CreatedAt.Before(filter.From) {
		return false
	}
	if !filter.To.IsZero() && inv.CreatedAt.After(filter.To) {
		return false
	}
	return true
}

func matchesIntervention(item Intervention, filter QueryFilter) bool {
	if filter.CandidateID != "" {
		candidateMatch := item.Invocation.CandidateID == filter.CandidateID
		if item.CandidateRef != nil && item.CandidateRef.CandidateID == filter.CandidateID {
			candidateMatch = true
		}
		if !candidateMatch {
			return false
		}
	}
	if filter.Outcome == "" {
		return true
	}
	status := item.Invocation.Outcome
	if item.Outcome != nil {
		status = item.Outcome.Status
	}
	return status == filter.Outcome
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

type localState struct {
	invocations   map[string]Invocation
	contexts      map[string]ContextPackage
	plans         map[string]ActionPlan
	actions       map[string]ToolAction
	verifications map[string]Verification
	rollbacks     map[string]Rollback
	outcomes      map[string]Outcome
	candidates    map[string]CandidateRef
	interventions map[string]Intervention
	keys          map[string]idempotencyEntry
}

func (s *LocalStore) copyState() localState {
	return localState{copyInvocations(s.invocations), copyContexts(s.contexts), copyPlans(s.plans), copyActions(s.actions), copyVerifications(s.verifications), copyRollbacks(s.rollbacks), copyOutcomes(s.outcomes), copyCandidates(s.candidates), copyInterventions(s.interventions), copyKeys(s.keys)}
}
func (s *LocalStore) restoreState(value localState) {
	s.invocations, s.contexts, s.plans, s.actions, s.verifications, s.rollbacks, s.outcomes, s.candidates, s.interventions, s.keys = value.invocations, value.contexts, value.plans, value.actions, value.verifications, value.rollbacks, value.outcomes, value.candidates, value.interventions, value.keys
}
func copyInvocations(input map[string]Invocation) map[string]Invocation {
	output := make(map[string]Invocation, len(input))
	for k, v := range input {
		output[k] = cloneInvocation(v)
	}
	return output
}
func copyContexts(input map[string]ContextPackage) map[string]ContextPackage {
	output := make(map[string]ContextPackage, len(input))
	for k, v := range input {
		output[k] = cloneContext(v)
	}
	return output
}
func copyPlans(input map[string]ActionPlan) map[string]ActionPlan {
	output := make(map[string]ActionPlan, len(input))
	for k, v := range input {
		output[k] = clonePlan(v)
	}
	return output
}
func copyActions(input map[string]ToolAction) map[string]ToolAction {
	output := make(map[string]ToolAction, len(input))
	for k, v := range input {
		output[k] = cloneAction(v)
	}
	return output
}
func copyVerifications(input map[string]Verification) map[string]Verification {
	output := make(map[string]Verification, len(input))
	for k, v := range input {
		output[k] = cloneVerification(v)
	}
	return output
}
func copyRollbacks(input map[string]Rollback) map[string]Rollback {
	output := make(map[string]Rollback, len(input))
	for k, v := range input {
		output[k] = cloneRollback(v)
	}
	return output
}
func copyOutcomes(input map[string]Outcome) map[string]Outcome {
	output := make(map[string]Outcome, len(input))
	for k, v := range input {
		output[k] = v
	}
	return output
}
func copyCandidates(input map[string]CandidateRef) map[string]CandidateRef {
	output := make(map[string]CandidateRef, len(input))
	for k, v := range input {
		output[k] = v
	}
	return output
}
func copyInterventions(input map[string]Intervention) map[string]Intervention {
	output := make(map[string]Intervention, len(input))
	for k, v := range input {
		output[k] = cloneIntervention(v)
	}
	return output
}
func copyKeys(input map[string]idempotencyEntry) map[string]idempotencyEntry {
	output := make(map[string]idempotencyEntry, len(input))
	for k, v := range input {
		output[k] = v
	}
	return output
}

var _ = errors.Is
