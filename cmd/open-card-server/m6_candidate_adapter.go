package main

import (
	"context"
	"time"

	ailedger "github.com/open-card/open-card/internal/ai/ledger"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/rules"
)

type m6CandidateAdapter struct {
	registry rules.Registry
	ledger   ailedger.Repository
}

func (a *m6CandidateAdapter) Evaluate(ctx context.Context, record domain.AIInterventionRecord, diff string) (*domain.RuleCandidate, error) {
	if a == nil || a.registry == nil || record.Outcome != "succeeded" || diff == "" {
		return nil, nil
	}
	refs := make([]rules.EvidenceRef, 0, len(record.Verification))
	for _, ref := range record.Verification {
		refs = append(refs, rules.EvidenceRef{ID: ref.ID.String(), Kind: ref.Kind, Digest: ref.Digest, Locator: ref.Locator})
	}
	candidate, _, err := a.registry.Aggregate(ctx, rules.Observation{ID: record.ID.String() + "-observation", IdempotencyKey: record.ID.String() + ":candidate", RequestDigest: record.ProblemFingerprint, Fingerprint: record.ProblemFingerprint, Name: "reviewed deterministic candidate", InvocationID: record.InvocationID.String(), ApplicationID: record.ApplicationID.String(), Success: true, Evidence: refs, At: time.Now().UTC()})
	if err != nil {
		return nil, err
	}
	if candidate.SuccessCount < rules.MinSuccessCount || candidate.ApplicationCount < rules.MinApplicationCount {
		return nil, nil
	}
	if a.ledger != nil {
		if _, _, err := a.ledger.AppendCandidateRef(ctx, ailedger.AppendCandidateRefRequest{IdempotencyKey: record.ID.String() + ":candidate-ref", RequestDigest: record.ProblemFingerprint, Record: ailedger.CandidateRef{ID: record.ID.String() + "-candidate-ref", InvocationID: record.InvocationID.String(), CandidateID: candidate.ID, Fingerprint: candidate.Fingerprint, Aggregation: "same-fingerprint", Status: string(candidate.Status), CreatedAt: time.Now().UTC()}}); err != nil {
			return nil, err
		}
	}
	result := domain.RuleCandidate{ID: domain.ID(candidate.ID), Fingerprint: candidate.Fingerprint, Status: domain.RuleCandidateProposed, SuccessCount: int(candidate.SuccessCount), ApplicationCount: int(candidate.ApplicationCount)}
	return &result, nil
}
