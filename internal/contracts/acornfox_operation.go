package contracts

import (
	"fmt"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

// AcornFoxOperationStatus describes evidence for this operation only. Verified
// means a task-scoped independent fact was persisted; it never means the
// application is healthy, serving, public, or commercially successful.
type AcornFoxOperationStatus string

const (
	AcornFoxOperationAccepted AcornFoxOperationStatus = "accepted"
	AcornFoxOperationRunning  AcornFoxOperationStatus = "running"
	AcornFoxOperationVerified AcornFoxOperationStatus = "verified"
	AcornFoxOperationFailed   AcornFoxOperationStatus = "failed"
	AcornFoxOperationUnknown  AcornFoxOperationStatus = "unknown"
)

type AcornFoxOperationEvidenceKind string

const (
	AcornFoxOperationRuntimeObservation  AcornFoxOperationEvidenceKind = "runtime_observation"
	AcornFoxOperationResponseObservation AcornFoxOperationEvidenceKind = "response_observation"
)

// AcornFoxOperationEvidenceVerdict intentionally has no healthy value. A
// standalone runtime/probe fact is too narrow to establish full application
// health; a 5xx or transport failure can, however, establish an unhealthy
// response observation for the requested check.
type AcornFoxOperationEvidenceVerdict string

const (
	AcornFoxOperationEvidenceObserved  AcornFoxOperationEvidenceVerdict = "observed"
	AcornFoxOperationEvidenceUnhealthy AcornFoxOperationEvidenceVerdict = "unhealthy"
	AcornFoxOperationEvidenceUnknown   AcornFoxOperationEvidenceVerdict = "unknown"
)

type AcornFoxOperationEvidence struct {
	Kind       AcornFoxOperationEvidenceKind    `json:"kind"`
	Verdict    AcornFoxOperationEvidenceVerdict `json:"verdict"`
	ObservedAt time.Time                        `json:"observed_at"`
	HTTPStatus *int                             `json:"http_status,omitempty"`
}

func (e AcornFoxOperationEvidence) Validate() error {
	if e.ObservedAt.IsZero() || e.ObservedAt.Location() != time.UTC {
		return fmt.Errorf("operation evidence observed time is invalid")
	}
	switch e.Kind {
	case AcornFoxOperationRuntimeObservation:
		if e.Verdict != AcornFoxOperationEvidenceObserved || e.HTTPStatus != nil {
			return fmt.Errorf("runtime operation evidence is invalid")
		}
	case AcornFoxOperationResponseObservation:
		if e.Verdict != AcornFoxOperationEvidenceObserved && e.Verdict != AcornFoxOperationEvidenceUnhealthy {
			return fmt.Errorf("response operation evidence verdict is invalid")
		}
		if e.HTTPStatus != nil && (*e.HTTPStatus < 100 || *e.HTTPStatus > 599) {
			return fmt.Errorf("response operation evidence HTTP status is invalid")
		}
	default:
		return fmt.Errorf("operation evidence kind is invalid")
	}
	return nil
}

// AcornFoxOperationResult is a safe read model for the future Pi tool and
// browser. It deliberately excludes task payloads, agent envelopes, raw
// errors, endpoint topology, credentials and evidence references.
type AcornFoxOperationResult struct {
	OperationID   domain.ID                  `json:"operation_id"`
	OperationType string                     `json:"operation_type"`
	Status        AcornFoxOperationStatus    `json:"status"`
	TaskID        domain.ID                  `json:"task_id,omitempty"`
	DeploymentID  domain.ID                  `json:"deployment_id,omitempty"`
	AcceptedAt    time.Time                  `json:"accepted_at"`
	UpdatedAt     time.Time                  `json:"updated_at"`
	Evidence      *AcornFoxOperationEvidence `json:"evidence,omitempty"`
}

func (r AcornFoxOperationResult) Validate() error {
	if err := domain.RequireID(r.OperationID, "operation id"); err != nil {
		return err
	}
	if strings.TrimSpace(r.OperationType) == "" || r.AcceptedAt.IsZero() || r.UpdatedAt.IsZero() || r.AcceptedAt.Location() != time.UTC || r.UpdatedAt.Location() != time.UTC || r.UpdatedAt.Before(r.AcceptedAt) {
		return fmt.Errorf("operation result identity or time is invalid")
	}
	switch r.Status {
	case AcornFoxOperationAccepted, AcornFoxOperationRunning, AcornFoxOperationFailed, AcornFoxOperationUnknown:
		if r.Evidence != nil {
			return fmt.Errorf("non-verified operation result must not contain evidence")
		}
	case AcornFoxOperationVerified:
		if r.Evidence == nil || r.Evidence.Validate() != nil {
			return fmt.Errorf("verified operation result requires valid evidence")
		}
	default:
		return fmt.Errorf("operation result status is invalid")
	}
	return nil
}
