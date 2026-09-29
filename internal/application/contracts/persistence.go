package contracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/compatibility"
	"github.com/open-card/open-card/internal/domain"
)

// OutboxEvent is the persistence-shaped event record. Sequence is the
// aggregate-local sequence retained by the original M0 schema; StreamSequence
// is the global replay cursor added by migration 0004.
type OutboxEvent struct {
	ID               string
	AggregateType    string
	AggregateID      string
	AggregateVersion int64
	Sequence         int64
	StreamSequence   int64
	EventType        string
	Payload          json.RawMessage
	CreatedAt        time.Time
	PublishedAt      *time.Time
	PayloadVersion   string
}

var (
	ErrIdempotencyConflict   = errors.New("idempotency key reused with different input")
	ErrIdempotencyInProgress = errors.New("idempotency request is already in progress")
	ErrIdempotencyCorrupt    = errors.New("idempotency record is corrupt")
	ErrOutcomeUnknown        = errors.New("transaction outcome is unknown")
	ErrLeaseLost             = errors.New("task lease is not owned or has expired")
)

// DecodeCreateApplicationResult strictly decodes and validates a persisted
// idempotent create-application response. It performs comprehensive structural,
// referential, and compatibility validation shared across storage backends.
func DecodeCreateApplicationResult(response []byte) (CreateApplicationResult, error) {
	if len(response) == 0 {
		return CreateApplicationResult{}, ErrIdempotencyCorrupt
	}
	dec := json.NewDecoder(bytes.NewReader(response))
	dec.DisallowUnknownFields()
	var result CreateApplicationResult
	if err := dec.Decode(&result); err != nil {
		return CreateApplicationResult{}, fmt.Errorf("%w: invalid stored response: %v", ErrIdempotencyCorrupt, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return CreateApplicationResult{}, fmt.Errorf("%w: trailing json data in response", ErrIdempotencyCorrupt)
	}

	if err := result.Application.Validate(); err != nil {
		return CreateApplicationResult{}, fmt.Errorf("%w: invalid application in response: %v", ErrIdempotencyCorrupt, err)
	}
	if err := domain.RequireID(result.EnvironmentID, "environment id"); err != nil {
		return CreateApplicationResult{}, fmt.Errorf("%w: %v", ErrIdempotencyCorrupt, err)
	}
	if err := domain.RequireID(result.OperationID, "operation id"); err != nil {
		return CreateApplicationResult{}, fmt.Errorf("%w: %v", ErrIdempotencyCorrupt, err)
	}
	if !result.SourceRevisionID.Empty() {
		if err := domain.RequireID(result.SourceRevisionID, "source revision id"); err != nil {
			return CreateApplicationResult{}, fmt.Errorf("%w: %v", ErrIdempotencyCorrupt, err)
		}
	}
	if strings.TrimSpace(result.Event.ID) == "" || result.Event.Sequence == 0 {
		return CreateApplicationResult{}, fmt.Errorf("%w: event identity or sequence invalid", ErrIdempotencyCorrupt)
	}
	if result.Event.ApplicationID != result.Application.ID.String() {
		return CreateApplicationResult{}, fmt.Errorf("%w: event application id does not match result application id", ErrIdempotencyCorrupt)
	}
	if result.Event.OperationID != result.OperationID.String() {
		return CreateApplicationResult{}, fmt.Errorf("%w: event operation id does not match result operation id", ErrIdempotencyCorrupt)
	}
	if strings.TrimSpace(result.Event.Kind) == "" || strings.TrimSpace(result.Event.Status) == "" {
		return CreateApplicationResult{}, fmt.Errorf("%w: event kind or status is empty", ErrIdempotencyCorrupt)
	}
	version, err := compatibility.Parse(result.Event.SchemaVersion)
	if err != nil || version.Major != 1 || version.Minor > 1 {
		return CreateApplicationResult{}, fmt.Errorf("%w: event schema version %q is incompatible", ErrIdempotencyCorrupt, result.Event.SchemaVersion)
	}
	return result, nil
}
