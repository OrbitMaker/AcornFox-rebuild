package contracts

import (
	"context"
	"encoding/json"
)

// AuditContext is bound by trusted command/authentication code. It does not
// authenticate a principal by itself and must not be populated from client actor fields.
type AuditContext struct {
	ActorType string
	ActorID   string
	Reason    string
}

// AuditEvidence preserves legacy exported timestamps verbatim. New writes use
// a fixed UTC format; legacy reads only parse RFC3339Nano without reserializing.
// HashScheme labels legacy provenance, not verified legacy producer algorithms.
type AuditEvidence struct {
	ID           string
	Sequence     int64
	ActorType    string
	ActorID      string
	Action       string
	Reason       string
	InputDigest  string
	Result       string
	EvidenceRefs json.RawMessage
	PreviousHash *string
	RecordHash   string
	HashScheme   string
	CreatedAt    string
}
type AuditFilter struct {
	AfterSequence int64
	Limit         int
}
type AuditRepository interface {
	ListAuditEvidence(context.Context, AuditFilter) ([]AuditEvidence, error)
}
