package assistantactions

import (
	"context"
	"time"

	"github.com/open-card/open-card/internal/assistant"
	"github.com/open-card/open-card/internal/domain"
)

type Store interface {
	GetPrepared(context.Context, assistant.Actor, string, string) (Proposal, bool, error)
	PrepareOrReplay(context.Context, assistant.Actor, Proposal) (Proposal, bool, error)
	List(context.Context, assistant.Actor, domain.ID, time.Time) ([]Proposal, error)
	Reject(context.Context, assistant.Actor, domain.ID, domain.ID, time.Time) (Proposal, error)
	BeginExecution(context.Context, assistant.Actor, domain.ID, domain.ID, Target, time.Time) (Proposal, bool, error)
	FinishExecution(context.Context, domain.ID, domain.ID, State, time.Time) (Proposal, error)
	FinishVerification(context.Context, domain.ID, domain.ID, Verification, time.Time) (Proposal, error)
}
