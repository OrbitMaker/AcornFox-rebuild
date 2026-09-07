package assistantactions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/open-card/open-card/internal/assistant"
	"github.com/open-card/open-card/internal/domain"
)

const ProposalTTL = 10 * time.Minute

type Config struct {
	Store    Store
	Resolver TargetResolver
	Executor Executor
	Verifier Verifier
	Clock    func() time.Time
}
type Service struct {
	store    Store
	resolver TargetResolver
	executor Executor
	verifier Verifier
	clock    func() time.Time
	mu       sync.Mutex
	gates    map[domain.ID]*sync.Mutex
}

func NewService(config Config) (*Service, error) {
	if config.Store == nil || config.Resolver == nil || config.Executor == nil {
		return nil, ErrUnavailable
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Service{store: config.Store, resolver: config.Resolver, executor: config.Executor, verifier: config.Verifier, clock: clock, gates: map[domain.ID]*sync.Mutex{}}, nil
}

// PrepareProposal is the only PI/tool-facing mutation. It creates a pending
// card and never calls Executor, regardless of prompt text or tool arguments.
func (s *Service) PrepareProposal(ctx context.Context, actor assistant.Actor, sessionID, runID domain.ID, input PrepareInput, toolCallID string) (Proposal, error) {
	if !validPrepare(actor, sessionID, runID, input, toolCallID) {
		return Proposal{}, ErrInvalid
	}
	key := digest("proposal", actor.AdminID.String(), sessionID.String(), runID.String(), string(input.Action), input.ApplicationID.String(), input.DeploymentID.String())
	requestDigest := digest("request", string(input.Action), input.ApplicationID.String(), input.DeploymentID.String())
	if existing, found, err := s.store.GetPrepared(ctx, actor, key, requestDigest); err != nil {
		return Proposal{}, safeError(err)
	} else if found {
		return existing, nil
	}
	target, err := s.resolver.ResolveExact(ctx, input.ApplicationID, input.DeploymentID)
	if err != nil {
		return Proposal{}, safeError(err)
	}
	if !validTarget(target) || target.ApplicationID != input.ApplicationID || target.DeploymentID != input.DeploymentID {
		return Proposal{}, ErrNotFound
	}
	now := s.now()
	id := domain.ID("asst_action_" + key[:32])
	proposal := Proposal{ID: id, SessionID: sessionID, RunID: runID, Action: input.Action, Target: target, State: StatePending, ExpiresAt: now.Add(ProposalTTL), Verification: Verification{State: VerificationPending}, CreatedAt: now, UpdatedAt: now, owner: actor, proposalKey: key, executionKey: "assistant-action:" + id.String(), requestDigest: requestDigest}
	stored, _, err := s.store.PrepareOrReplay(ctx, actor, proposal)
	if err != nil {
		return Proposal{}, safeError(err)
	}
	return stored, nil
}

func (s *Service) List(ctx context.Context, actor assistant.Actor, sessionID domain.ID) ([]Proposal, error) {
	if actor.AdminID.Empty() || sessionID.Empty() {
		return nil, ErrInvalid
	}
	items, err := s.store.List(ctx, actor, sessionID, s.now())
	if err != nil {
		return nil, safeError(err)
	}
	if s.verifier == nil {
		return items, nil
	}
	for index, item := range items {
		if (item.State != StateAccepted && item.State != StateUnknown) || item.OperationID.Empty() {
			continue
		}
		verification, e := s.verifier.Verify(ctx, item.Action, item.Target, item.OperationID)
		if e != nil || !validVerification(verification) {
			continue
		}
		if verification.State == VerificationVerified || verification.State == VerificationFailed {
			next, e := s.store.FinishVerification(ctx, item.ID, item.OperationID, verification, s.now())
			if e == nil {
				items[index] = next
			}
		} else {
			items[index].Verification = verification
		}
	}
	return items, nil
}

func (s *Service) Decide(ctx context.Context, actor assistant.Actor, sessionID, proposalID domain.ID, approve bool) (Proposal, error) {
	if actor.AdminID.Empty() || sessionID.Empty() || proposalID.Empty() {
		return Proposal{}, ErrInvalid
	}
	gate := s.gate(proposalID)
	gate.Lock()
	defer gate.Unlock()
	now := s.now()
	if !approve {
		proposal, err := s.store.Reject(ctx, actor, sessionID, proposalID, now)
		if err != nil {
			return Proposal{}, safeError(err)
		}
		return proposal, nil
	}
	// Resolve the exact stored app/deployment only. BeginExecution compares the
	// current release snapshot and rejects drift before taking the app slot.
	items, err := s.store.List(ctx, actor, sessionID, now)
	if err != nil {
		return Proposal{}, safeError(err)
	}
	var stored Proposal
	found := false
	for _, item := range items {
		if item.ID == proposalID {
			stored = item
			found = true
			break
		}
	}
	if !found {
		return Proposal{}, ErrNotFound
	}
	if stored.State == StateExpired {
		return stored, ErrExpired
	}
	if stored.State == StateAccepted || stored.State == StateVerified || stored.State == StateFailed || stored.State == StateRejected {
		return stored, nil
	}
	current, err := s.resolver.ResolveExact(ctx, stored.Target.ApplicationID, stored.Target.DeploymentID)
	if err != nil {
		return Proposal{}, safeError(err)
	}
	proposal, execute, err := s.store.BeginExecution(ctx, actor, sessionID, proposalID, current, now)
	if err != nil {
		return Proposal{}, safeError(err)
	}
	if !execute {
		return proposal, nil
	}
	result, executeErr := s.executor.Execute(ctx, ExecutionRequest{ProposalID: proposal.ID, Actor: actor, Action: proposal.Action, Target: proposal.Target, IdempotencyKey: proposal.executionKey})
	state := StateAccepted
	if executeErr != nil {
		state = StateUnknown
		if errors.Is(executeErr, ErrExecutionRejected) {
			state = StateFailed
		}
	}
	if !result.Accepted || result.OperationID.Empty() {
		if executeErr == nil {
			state = StateUnknown
		}
	}
	finishCtx, cancelFinish := context.WithTimeout(context.Background(), 5*time.Second)
	finished, finishErr := s.store.FinishExecution(finishCtx, proposal.ID, result.OperationID, state, s.now())
	cancelFinish()
	if finishErr != nil {
		return Proposal{}, ErrUnavailable
	}
	return finished, nil
}

func (s *Service) gate(id domain.ID) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	gate := s.gates[id]
	if gate == nil {
		gate = &sync.Mutex{}
		s.gates[id] = gate
	}
	return gate
}
func (s *Service) now() time.Time { return s.clock().UTC() }
func validPrepare(actor assistant.Actor, sid, rid domain.ID, input PrepareInput, call string) bool {
	return !actor.AdminID.Empty() && !sid.Empty() && !rid.Empty() && (input.Action == ActionRestart || input.Action == ActionRedeploy) && !input.ApplicationID.Empty() && !input.DeploymentID.Empty() && call != "" && len(call) <= 128
}
func validTarget(t Target) bool {
	return !t.ApplicationID.Empty() && !t.DeploymentID.Empty() && !t.ReleaseID.Empty() && t.ReleaseVersion > 0 && t.ApplicationName != "" && len(t.ApplicationName) <= 128 && utf8.ValidString(t.ApplicationName) && !strings.ContainsRune(t.ApplicationName, 0)
}
func validVerification(v Verification) bool {
	return (v.State == VerificationPending || v.State == VerificationVerified || v.State == VerificationFailed) && len(v.Verdict) <= 256 && utf8.ValidString(v.Verdict)
}
func digest(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		h.Write([]byte{0})
		h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}
func safeError(err error) error {
	switch {
	case errors.Is(err, ErrInvalid):
		return ErrInvalid
	case errors.Is(err, ErrNotFound):
		return ErrNotFound
	case errors.Is(err, ErrConflict):
		return ErrConflict
	case errors.Is(err, ErrExpired):
		return ErrExpired
	case errors.Is(err, ErrTargetChanged):
		return ErrTargetChanged
	default:
		return ErrUnavailable
	}
}
