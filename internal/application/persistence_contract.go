package application

import persistence "github.com/open-card/open-card/internal/application/contracts"

type OutboxEvent = persistence.OutboxEvent

var (
	ErrIdempotencyInProgress = persistence.ErrIdempotencyInProgress
	ErrIdempotencyCorrupt    = persistence.ErrIdempotencyCorrupt
	ErrOutcomeUnknown        = persistence.ErrOutcomeUnknown
	ErrLeaseLost             = persistence.ErrLeaseLost
)

func DecodeCreateApplicationResult(response []byte) (CreateApplicationResult, error) {
	return persistence.DecodeCreateApplicationResult(response)
}
