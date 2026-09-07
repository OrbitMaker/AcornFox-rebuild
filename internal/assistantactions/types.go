// Package assistantactions implements administrator-confirmed restart and
// redeploy proposals. Model/tool calls can prepare cards but cannot approve or
// execute them.
package assistantactions

import (
	"context"
	"errors"
	"time"

	"github.com/open-card/open-card/internal/assistant"
	"github.com/open-card/open-card/internal/domain"
)

type Action string

const (
	ActionRestart  Action = "restart"
	ActionRedeploy Action = "redeploy"
)

type State string

const (
	StatePending   State = "pending"
	StateRejected  State = "rejected"
	StateExpired   State = "expired"
	StateExecuting State = "executing"
	StateAccepted  State = "accepted"
	StateUnknown   State = "unknown"
	StateVerified  State = "verified"
	StateFailed    State = "failed"
)

type VerificationState string

const (
	VerificationPending  VerificationState = "pending"
	VerificationVerified VerificationState = "verified"
	VerificationFailed   VerificationState = "failed"
)

var (
	ErrInvalid           = errors.New("assistant action request is invalid")
	ErrNotFound          = errors.New("assistant action not found")
	ErrConflict          = errors.New("assistant action conflicts with an active action")
	ErrExpired           = errors.New("assistant action expired")
	ErrTargetChanged     = errors.New("assistant action target changed")
	ErrUnavailable       = errors.New("assistant action unavailable")
	ErrExecutionRejected = errors.New("assistant action was rejected before side effects")
)

type Target struct {
	ApplicationID   domain.ID `json:"application_id"`
	DeploymentID    domain.ID `json:"deployment_id"`
	ReleaseID       domain.ID `json:"target_release_id"`
	ReleaseVersion  int64     `json:"target_release_version"`
	ApplicationName string    `json:"application_name"`
}

func (t Target) Equal(other Target) bool {
	return t.ApplicationID == other.ApplicationID && t.DeploymentID == other.DeploymentID && t.ReleaseID == other.ReleaseID && t.ReleaseVersion == other.ReleaseVersion
}

type Proposal struct {
	ID            domain.ID    `json:"proposal_id"`
	SessionID     domain.ID    `json:"session_id"`
	RunID         domain.ID    `json:"run_id"`
	Action        Action       `json:"action"`
	Target        Target       `json:"target"`
	State         State        `json:"state"`
	ExpiresAt     time.Time    `json:"expires_at"`
	OperationID   domain.ID    `json:"operation_id,omitempty"`
	Verification  Verification `json:"verification"`
	CreatedAt     time.Time    `json:"created_at"`
	UpdatedAt     time.Time    `json:"updated_at"`
	owner         assistant.Actor
	proposalKey   string
	executionKey  string
	requestDigest string
}

type PrepareInput struct {
	Action        Action    `json:"action"`
	ApplicationID domain.ID `json:"application_id"`
	DeploymentID  domain.ID `json:"deployment_id"`
}
type DecisionInput struct {
	Approve bool `json:"approve"`
}
type Verification struct {
	State      VerificationState `json:"state"`
	Verdict    string            `json:"verdict,omitempty"`
	ObservedAt *time.Time        `json:"observed_at,omitempty"`
}
type ExecutionRequest struct {
	ProposalID     domain.ID
	Actor          assistant.Actor
	Action         Action
	Target         Target
	IdempotencyKey string
}
type ExecutionResult struct {
	OperationID domain.ID
	Accepted    bool
}

type TargetResolver interface {
	ResolveExact(context.Context, domain.ID, domain.ID) (Target, error)
}
type Executor interface {
	Execute(context.Context, ExecutionRequest) (ExecutionResult, error)
}
type Verifier interface {
	Verify(context.Context, Action, Target, domain.ID) (Verification, error)
}

func activeState(state State) bool {
	return state == StateExecuting || state == StateAccepted || state == StateUnknown
}
func terminalState(state State) bool {
	return state == StateRejected || state == StateExpired || state == StateVerified || state == StateFailed
}
