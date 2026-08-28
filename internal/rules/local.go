package rules

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

func (r *LocalRegistry) Aggregate(ctx context.Context, observation Observation) (RuleCandidate, bool, error) {
	if err := checkContext(ctx); err != nil {
		return RuleCandidate{}, false, err
	}
	if r == nil {
		return RuleCandidate{}, false, ErrInvalid
	}
	observation.Fingerprint = strings.TrimSpace(observation.Fingerprint)
	if observation.Fingerprint == "" {
		return RuleCandidate{}, false, fmt.Errorf("%w: observation fingerprint is required", ErrInvalid)
	}
	key, digest, err := ensureRequest(firstNonEmpty(observation.IdempotencyKey, observation.ID), observation.RequestDigest, observation, observation.ID)
	if err != nil {
		return RuleCandidate{}, false, err
	}
	if observation.ID == "" {
		observation.ID = deterministicID("observation", key, digest)
	}
	observation.IdempotencyKey, observation.RequestDigest = key, digest
	observation.At = normalizeTime(observation.At)
	if err := validateSafe(observation); err != nil {
		return RuleCandidate{}, false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if id, ok := r.keys["observation:"+key]; ok {
		candidate, exists := r.candidates[id]
		if !exists {
			return RuleCandidate{}, false, ErrNotFound
		}
		return candidate, true, nil
	}
	var candidate RuleCandidate
	var exists bool
	for _, item := range r.candidates {
		if item.Fingerprint != observation.Fingerprint || item.Status == StatusPromoted {
			continue
		}
		if !exists || item.CreatedAt.After(candidate.CreatedAt) || (item.CreatedAt.Equal(candidate.CreatedAt) && item.ID > candidate.ID) {
			candidate = item
			exists = true
		}
	}
	if !exists || candidate.Status == StatusPromoted {
		candidateIDSeed := observation.Fingerprint
		if exists {
			candidateIDSeed += "\x00" + key
		}
		candidate = RuleCandidate{ID: deterministicID("candidate", candidateIDSeed), Fingerprint: observation.Fingerprint, Name: strings.TrimSpace(observation.Name), Status: StatusDraft, CreatedAt: observation.At, UpdatedAt: observation.At}
		r.candidates[candidate.ID] = candidate
	}
	if observation.Success {
		candidate.SuccessCount++
	}
	if observation.ApplicationID != "" && !r.applicationSeenLocked(candidate.ID, observation.ApplicationID) {
		candidate.ApplicationCount++
	}
	candidate.UpdatedAt = observation.At
	r.candidates[candidate.ID] = candidate
	r.observations[observation.ID] = observation
	r.keys["observation:"+key] = candidate.ID
	return candidate, false, nil
}

func (r *LocalRegistry) applicationSeenLocked(candidateID, applicationID string) bool {
	for _, item := range r.observations {
		candidate := r.candidates[candidateID]
		if item.Fingerprint == candidate.Fingerprint && item.ApplicationID == applicationID {
			return true
		}
	}
	return false
}

func (r *LocalRegistry) GetCandidate(ctx context.Context, id string) (RuleCandidate, error) {
	if err := checkContext(ctx); err != nil {
		return RuleCandidate{}, err
	}
	if r == nil {
		return RuleCandidate{}, ErrInvalid
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	candidate, ok := r.candidates[strings.TrimSpace(id)]
	if !ok {
		return RuleCandidate{}, ErrNotFound
	}
	return candidate, nil
}

func (r *LocalRegistry) Transition(ctx context.Context, request TransitionRequest) (RuleCandidate, error) {
	if err := checkContext(ctx); err != nil {
		return RuleCandidate{}, err
	}
	if r == nil {
		return RuleCandidate{}, ErrInvalid
	}
	request.CandidateID = strings.TrimSpace(request.CandidateID)
	if request.CandidateID == "" {
		return RuleCandidate{}, ErrInvalid
	}
	key, digest, err := ensureRequest(request.IdempotencyKey, request.RequestDigest, request, request.CandidateID+":"+string(request.To))
	if err != nil {
		return RuleCandidate{}, err
	}
	request.At = normalizeTime(request.At)
	r.mu.Lock()
	defer r.mu.Unlock()
	if id, ok := r.keys["transition:"+key]; ok {
		candidate, exists := r.candidates[id]
		if !exists {
			return RuleCandidate{}, ErrCorrupt
		}
		return candidate, nil
	}
	candidate, ok := r.candidates[request.CandidateID]
	if !ok {
		return RuleCandidate{}, ErrNotFound
	}
	next := candidate
	if request.ReviewedBy != "" {
		next.ReviewedBy = strings.TrimSpace(request.ReviewedBy)
	}
	if request.Actor != "" && next.ReviewedBy == "" {
		next.ReviewedBy = strings.TrimSpace(request.Actor)
	}
	if request.ReviewDecision != "" {
		next.ReviewDecision = strings.TrimSpace(request.ReviewDecision)
	}
	if request.ProposedVersion != "" {
		next.ProposedVersion = strings.TrimSpace(request.ProposedVersion)
	}
	if request.RegressionPassed {
		next.RegressionPassed = true
	}
	if request.ShadowPassed {
		next.ShadowPassed = true
	}
	if len(request.TestEvidence) > 0 {
		next.TestEvidence = append([]EvidenceRef(nil), request.TestEvidence...)
	}
	if err := next.Transition(request.To); err != nil {
		return RuleCandidate{}, err
	}
	next.UpdatedAt = request.At
	r.candidates[next.ID] = next
	r.events = append(r.events, RegistryEvent{ID: deterministicID("rule-event", key, digest), CandidateID: next.ID, Fingerprint: next.Fingerprint, Kind: "candidate_" + string(request.To), IdempotencyKey: key, RequestDigest: digest, Actor: strings.TrimSpace(request.Actor), Reason: strings.TrimSpace(request.Reason), CreatedAt: request.At})
	r.keys["transition:"+key] = next.ID
	return next, nil
}

func (r *LocalRegistry) RecordEvaluation(ctx context.Context, evidence EvaluationEvidence) (EvaluationEvidence, bool, error) {
	if err := checkContext(ctx); err != nil {
		return EvaluationEvidence{}, false, err
	}
	if r == nil {
		return EvaluationEvidence{}, false, ErrInvalid
	}
	evidence.CandidateID = strings.TrimSpace(evidence.CandidateID)
	evidence.TestName = strings.TrimSpace(evidence.TestName)
	if evidence.CandidateID == "" || evidence.TestName == "" {
		return EvaluationEvidence{}, false, ErrInvalid
	}
	key, digest, err := ensureRequest(evidence.IdempotencyKey, evidence.RequestDigest, evidence, evidence.ID)
	if err != nil {
		return EvaluationEvidence{}, false, err
	}
	evidence.IdempotencyKey, evidence.RequestDigest = key, digest
	evidence.ID = firstNonEmpty(evidence.ID, deterministicID("evaluation", key, digest))
	evidence.CreatedAt = normalizeTime(evidence.CreatedAt)
	if err := validateSafe(evidence); err != nil {
		return EvaluationEvidence{}, false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if id, ok := r.keys["evaluation:"+key]; ok {
		item, exists := r.evaluations[id]
		if !exists {
			return EvaluationEvidence{}, false, ErrNotFound
		}
		return item, true, nil
	}
	candidate, ok := r.candidates[evidence.CandidateID]
	if !ok {
		return EvaluationEvidence{}, false, ErrNotFound
	}
	if evidence.Passed {
		candidate.RegressionPassed = true
		if len(evidence.Evidence) == 0 {
			evidence.Evidence = []EvidenceRef{{ID: evidence.ID, Kind: "regression"}}
		}
		for _, ref := range evidence.Evidence {
			found := false
			for _, old := range candidate.TestEvidence {
				if old.ID == ref.ID {
					found = true
					break
				}
			}
			if !found {
				candidate.TestEvidence = append(candidate.TestEvidence, ref)
			}
		}
		candidate.UpdatedAt = evidence.CreatedAt
		r.candidates[candidate.ID] = candidate
	}
	r.evaluations[evidence.ID] = evidence
	r.keys["evaluation:"+key] = evidence.ID
	return evidence, false, nil
}

func (r *LocalRegistry) Promote(ctx context.Context, request PromotionRequest) (RuleVersion, bool, error) {
	if err := checkContext(ctx); err != nil {
		return RuleVersion{}, false, err
	}
	if r == nil {
		return RuleVersion{}, false, ErrInvalid
	}
	request.CandidateID = strings.TrimSpace(request.CandidateID)
	request.Version = strings.TrimSpace(request.Version)
	if request.CandidateID == "" || request.Version == "" {
		return RuleVersion{}, false, ErrPromotionGate
	}
	key, digest, err := ensureRequest(request.IdempotencyKey, request.RequestDigest, request, request.CandidateID+":"+request.Version)
	if err != nil {
		return RuleVersion{}, false, err
	}
	request.At = normalizeTime(request.At)
	r.mu.Lock()
	defer r.mu.Unlock()
	if id, ok := r.keys["promote:"+key]; ok {
		version, exists := r.versions[id]
		if !exists {
			return RuleVersion{}, false, ErrNotFound
		}
		return version, true, nil
	}
	candidate, ok := r.candidates[request.CandidateID]
	if !ok {
		return RuleVersion{}, false, ErrNotFound
	}
	if candidate.Status != StatusApproved {
		return RuleVersion{}, false, fmt.Errorf("%w: candidate status is %s", ErrPromotionGate, candidate.Status)
	}
	if request.Version != candidate.ProposedVersion {
		candidate.ProposedVersion = request.Version
	}
	if request.CodeDigest == "" {
		request.CodeDigest = requestDigest(request.Definition)
	}
	candidate.Status = StatusApproved
	if err := candidate.CanPromote(); err != nil {
		return RuleVersion{}, false, err
	}
	version := RuleVersion{ID: deterministicID("rule-version", candidate.ID, request.Version), CandidateID: candidate.ID, Fingerprint: candidate.Fingerprint, Version: request.Version, CodeDigest: request.CodeDigest, Definition: cloneMap(request.Definition), CreatedAt: request.At}
	if err := version.Validate(); err != nil {
		return RuleVersion{}, false, err
	}
	previous := r.currentActiveLocked(candidate.Fingerprint)
	if previous != "" {
		return RuleVersion{}, false, fmt.Errorf("%w: a version is already active", ErrConflict)
	}
	r.versions[version.ID] = version
	candidate.Status = StatusPromoted
	candidate.UpdatedAt = request.At
	r.candidates[candidate.ID] = candidate
	r.events = append(r.events, RegistryEvent{ID: deterministicID("rule-event", key, digest), RuleVersionID: version.ID, CandidateID: candidate.ID, Fingerprint: candidate.Fingerprint, Kind: "promoted", PreviousID: previous, IdempotencyKey: key, RequestDigest: digest, Actor: strings.TrimSpace(request.Actor), Reason: strings.TrimSpace(request.Reason), CreatedAt: request.At})
	r.keys["promote:"+key] = version.ID
	return version, false, nil
}

func (v RuleVersion) Validate() error {
	if strings.TrimSpace(v.ID) == "" || strings.TrimSpace(v.CandidateID) == "" || strings.TrimSpace(v.Fingerprint) == "" || strings.TrimSpace(v.Version) == "" || strings.TrimSpace(v.CodeDigest) == "" || v.CreatedAt.IsZero() {
		return fmt.Errorf("%w: rule version identity is incomplete", ErrInvalid)
	}
	return validateSafe(v)
}

func (r *LocalRegistry) Enable(ctx context.Context, request RegistryRequest) (RuleVersion, error) {
	return r.registryChange(ctx, request, "enabled")
}
func (r *LocalRegistry) Disable(ctx context.Context, request RegistryRequest) (RuleVersion, error) {
	return r.registryChange(ctx, request, "disabled")
}
func (r *LocalRegistry) registryChange(ctx context.Context, request RegistryRequest, kind string) (RuleVersion, error) {
	if err := checkContext(ctx); err != nil {
		return RuleVersion{}, err
	}
	if r == nil {
		return RuleVersion{}, ErrInvalid
	}
	request.RuleVersionID = strings.TrimSpace(request.RuleVersionID)
	if request.RuleVersionID == "" {
		return RuleVersion{}, ErrInvalid
	}
	key, digest, err := ensureRequest(request.IdempotencyKey, request.RequestDigest, request, request.RuleVersionID+":"+kind)
	if err != nil {
		return RuleVersion{}, err
	}
	request.At = normalizeTime(request.At)
	r.mu.Lock()
	defer r.mu.Unlock()
	if id, ok := r.keys[kind+":"+key]; ok {
		version, exists := r.versions[id]
		if !exists {
			return RuleVersion{}, ErrNotFound
		}
		return version, nil
	}
	version, ok := r.versions[request.RuleVersionID]
	if !ok {
		return RuleVersion{}, ErrNotFound
	}
	candidate := r.candidates[version.CandidateID]
	if candidate.Status != StatusPromoted {
		return RuleVersion{}, fmt.Errorf("%w: candidate is not promoted", ErrPromotionGate)
	}
	if kind == "enabled" {
		if active := r.currentActiveLocked(version.Fingerprint); active != "" && active != version.ID {
			return RuleVersion{}, fmt.Errorf("%w: another version is active", ErrConflict)
		}
	}
	previous := r.currentActiveLocked(version.Fingerprint)
	if kind == "disabled" && previous != version.ID {
		return RuleVersion{}, ErrDisabled
	}
	r.events = append(r.events, RegistryEvent{ID: deterministicID("rule-event", key, digest), RuleVersionID: version.ID, CandidateID: version.CandidateID, Fingerprint: version.Fingerprint, Kind: kind, PreviousID: previous, IdempotencyKey: key, RequestDigest: digest, Actor: strings.TrimSpace(request.Actor), Reason: strings.TrimSpace(request.Reason), CreatedAt: request.At})
	r.keys[kind+":"+key] = version.ID
	return version, nil
}

func (r *LocalRegistry) Rollback(ctx context.Context, request RegistryRequest) (RuleVersion, error) {
	if err := checkContext(ctx); err != nil {
		return RuleVersion{}, err
	}
	if r == nil {
		return RuleVersion{}, ErrInvalid
	}
	request.RuleVersionID = strings.TrimSpace(request.RuleVersionID)
	if request.RuleVersionID == "" {
		return RuleVersion{}, ErrInvalid
	}
	key, digest, err := ensureRequest(request.IdempotencyKey, request.RequestDigest, request, request.RuleVersionID+":rollback")
	if err != nil {
		return RuleVersion{}, err
	}
	request.At = normalizeTime(request.At)
	r.mu.Lock()
	defer r.mu.Unlock()
	if id, ok := r.keys["rollback:"+key]; ok {
		version, exists := r.versions[id]
		if !exists {
			return RuleVersion{}, ErrNotFound
		}
		return version, nil
	}
	current, ok := r.versions[request.RuleVersionID]
	if !ok {
		return RuleVersion{}, ErrNotFound
	}
	if r.currentActiveLocked(current.Fingerprint) != current.ID {
		return RuleVersion{}, ErrDisabled
	}
	previous := ""
	for i := len(r.events) - 1; i >= 0; i-- {
		event := r.events[i]
		if event.Fingerprint != current.Fingerprint || event.RuleVersionID == current.ID {
			continue
		}
		if event.Kind == "promoted" || event.Kind == "enabled" || event.Kind == "rollback" {
			previous = event.RuleVersionID
			break
		}
	}
	if previous == "" {
		return RuleVersion{}, ErrNoPrevious
	}
	r.events = append(r.events, RegistryEvent{ID: deterministicID("rule-event", key, digest), RuleVersionID: previous, CandidateID: r.versions[previous].CandidateID, Fingerprint: current.Fingerprint, Kind: "rollback", PreviousID: current.ID, IdempotencyKey: key, RequestDigest: digest, Actor: strings.TrimSpace(request.Actor), Reason: strings.TrimSpace(request.Reason), CreatedAt: request.At})
	r.keys["rollback:"+key] = previous
	return r.versions[previous], nil
}

func (r *LocalRegistry) currentActiveLocked(fingerprint string) string {
	for i := len(r.events) - 1; i >= 0; i-- {
		event := r.events[i]
		if event.Fingerprint != fingerprint {
			continue
		}
		switch event.Kind {
		case "disabled":
			return ""
		case "promoted", "enabled", "rollback":
			return event.RuleVersionID
		}
	}
	return ""
}
func (r *LocalRegistry) Active(ctx context.Context, fingerprint string) (RuleVersion, error) {
	if err := checkContext(ctx); err != nil {
		return RuleVersion{}, err
	}
	if r == nil {
		return RuleVersion{}, ErrInvalid
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	id := r.currentActiveLocked(strings.TrimSpace(fingerprint))
	if id == "" {
		return RuleVersion{}, ErrNotFound
	}
	return r.versions[id], nil
}
func (r *LocalRegistry) Metrics(ctx context.Context) (Metrics, error) {
	if err := checkContext(ctx); err != nil {
		return Metrics{}, err
	}
	if r == nil {
		return Metrics{}, ErrInvalid
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var m Metrics
	m.Candidates = int64(len(r.candidates))
	for _, candidate := range r.candidates {
		switch candidate.Status {
		case StatusDraft:
			m.Draft++
		case StatusTesting:
			m.Testing++
		case StatusReviewed:
			m.Reviewed++
		case StatusShadow:
			m.Shadow++
		case StatusApproved:
			m.Approved++
		case StatusPromoted:
			m.Promoted++
		}
	}
	m.Versions = int64(len(r.versions))
	for _, version := range r.versions {
		if r.currentActiveLocked(version.Fingerprint) == version.ID {
			m.EnabledVersions++
		} else {
			m.DisabledVersions++
		}
	}
	for _, event := range r.events {
		if event.Kind == "rollback" {
			m.Rollbacks++
		}
	}
	m.Observations = int64(len(r.observations))
	for _, item := range r.observations {
		if item.Success {
			m.Successes++
		}
	}
	return m, nil
}

func cloneMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	out := make(map[string]any, len(input))
	for key, value := range input {
		switch typed := value.(type) {
		case map[string]any:
			out[key] = cloneMap(typed)
		case []any:
			items := make([]any, len(typed))
			for i, item := range typed {
				items[i] = item
			}
			out[key] = items
		default:
			out[key] = typed
		}
	}
	return out
}
func sortEvents(events []RegistryEvent) {
	sort.Slice(events, func(i, j int) bool { return events[i].CreatedAt.Before(events[j].CreatedAt) })
}

var _ = sortEvents
