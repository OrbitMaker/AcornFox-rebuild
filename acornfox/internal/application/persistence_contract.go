package application

import persistence "github.com/acornfox/acornfox/internal/application/contracts"

type OutboxEvent = persistence.OutboxEvent

var (
	ErrIdempotencyInProgress = persistence.ErrIdempotencyInProgress
	ErrIdempotencyCorrupt    = persistence.ErrIdempotencyCorrupt
	ErrOutcomeUnknown        = persistence.ErrOutcomeUnknown
	ErrLeaseLost             = persistence.ErrLeaseLost
)
