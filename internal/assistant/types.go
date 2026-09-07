// Package assistant implements the authenticated AcornFox assistant
// conversation boundary. Provider protocols and raw tool events stay behind
// Runner; browser-facing DTOs contain only bounded, projected text and state.
package assistant

import (
	"errors"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

const (
	ScopeHost ScopeKind = "host"
	ScopeApp  ScopeKind = "app"

	RunAccepted  RunStatus = "accepted"
	RunRunning   RunStatus = "running"
	RunCompleted RunStatus = "completed"
	RunFailed    RunStatus = "failed"
	RunAborted   RunStatus = "aborted"
	RunUnknown   RunStatus = "unknown"

	EventRunAccepted      EventType = "run.accepted"
	EventRunStarted       EventType = "run.started"
	EventAssistantDelta   EventType = "assistant.delta"
	EventAssistantMessage EventType = "assistant.message"
	EventRunCompleted     EventType = "run.completed"
	EventRunFailed        EventType = "run.failed"
	EventRunAborted       EventType = "run.aborted"
	EventRunUnknown       EventType = "run.unknown"

	CursorOK           CursorStatus = "ok"
	CursorSlowConsumer CursorStatus = "slow_consumer"
	CursorExpired      CursorStatus = "expired"

	MaxMessageBytes              = 64 << 10
	MaxIdempotencyKeyBytes       = 128
	MaxEventTextBytes            = 64 << 10
	DefaultEventPageSize         = 128
	MaxSessionsPerOwner          = 32
	MaxRunsPerSession            = 256
	MaxQueuedRunsPerSession      = 8
	MaxRunMessageBytesPerSession = 2 << 20
	MaxRunnerStartTimeout        = 5 * time.Second
	MaxRunnerAbortTimeout        = 3 * time.Second
	MaxGlobalConcurrency         = 8
)

var (
	ErrUnauthorized         = errors.New("assistant actor is required")
	ErrNotFound             = errors.New("assistant resource not found")
	ErrInvalidInput         = errors.New("assistant request is invalid")
	ErrIdempotencyConflict  = errors.New("assistant idempotency conflict")
	ErrSessionLimit         = errors.New("assistant session limit reached")
	ErrRunLimit             = errors.New("assistant run limit reached")
	ErrEventLimit           = errors.New("assistant event limit reached")
	ErrCursorExpired        = errors.New("assistant event cursor expired")
	ErrUnavailable          = errors.New("assistant service unavailable")
	ErrRunnerOutcomeUnknown = errors.New("assistant runner outcome is unknown")
)

type Actor struct {
	AdminID domain.ID `json:"admin_id"`
}

type ScopeKind string

type Scope struct {
	Kind  ScopeKind `json:"kind"`
	AppID domain.ID `json:"app_id,omitempty"`
}

func (s Scope) Validate() error {
	switch s.Kind {
	case ScopeHost:
		if !s.AppID.Empty() {
			return ErrInvalidInput
		}
	case ScopeApp:
		if s.AppID.Empty() {
			return ErrInvalidInput
		}
	default:
		return ErrInvalidInput
	}
	return nil
}

type Session struct {
	ID        domain.ID `json:"session_id"`
	Scope     Scope     `json:"scope"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	ownerID   domain.ID
}

type RunStatus string

type Run struct {
	ID             domain.ID `json:"run_id"`
	SessionID      domain.ID `json:"session_id"`
	Status         RunStatus `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	message        string
	requestDigest  string
	idempotencyKey string
	ownerID        domain.ID
}

type EventType string

type Event struct {
	Cursor     uint64    `json:"cursor"`
	RunID      domain.ID `json:"run_id,omitempty"`
	Type       EventType `json:"type"`
	OccurredAt time.Time `json:"occurred_at"`
	Text       string    `json:"text,omitempty"`
}

type CursorStatus string

type EventSnapshot struct {
	Status       CursorStatus `json:"status"`
	OldestCursor uint64       `json:"oldest_cursor"`
	LatestCursor uint64       `json:"latest_cursor"`
	Events       []Event      `json:"events"`
}

type SubmitRunResult struct {
	Run    Run  `json:"run"`
	Replay bool `json:"replay"`
}

type AbortResult struct {
	Aborted int `json:"aborted"`
}

func terminalRunStatus(status RunStatus) bool {
	switch status {
	case RunCompleted, RunFailed, RunAborted, RunUnknown:
		return true
	default:
		return false
	}
}
