package dnschange

import (
	"context"
	"errors"
	"sort"
	"time"
)

type Reader interface {
	ListRecords(context.Context, int64, string) ([]Record, error)
}
type Ledger interface {
	ListOwned(context.Context, int64) ([]OwnedRecord, error)
	SavePlan(context.Context, Plan) (Plan, bool, error)
	LastReconcile(context.Context, string) (time.Time, error)
	SetLastReconcile(context.Context, string, time.Time) error
}

type Reconciler struct {
	Store   Ledger
	Reader  Reader
	Desired []DesiredRecord
	// ManagedDomainIDs keeps zones with zero desired records in scope so their
	// owned records can still produce a fail-closed delete dry-run.
	ManagedDomainIDs map[int64]string
	Scope            string
	Clock            func() time.Time
	Interval         time.Duration
}

func (r *Reconciler) ReconcileOnce(ctx context.Context) (ReconcileResult, error) {
	if r == nil || r.Store == nil || r.Reader == nil || r.Scope == "" || (len(r.Desired) == 0 && len(r.ManagedDomainIDs) == 0) {
		return ReconcileResult{}, errors.New("DNS reconciler is not configured")
	}
	now := time.Now().UTC()
	if r.Clock != nil {
		now = r.Clock().UTC()
	}
	interval := r.Interval
	if interval == 0 {
		interval = time.Minute
	}
	if interval != time.Minute {
		return ReconcileResult{}, errors.New("DNS reconciler interval must be exactly 60 seconds")
	}
	last, err := r.Store.LastReconcile(ctx, r.Scope)
	if err != nil {
		return ReconcileResult{}, err
	}
	if !last.IsZero() && now.Sub(last) < interval {
		return ReconcileResult{Due: false}, nil
	}
	byDomain := map[int64][]DesiredRecord{}
	for _, target := range r.Desired {
		if err := target.Validate(); err != nil {
			return ReconcileResult{}, err
		}
		byDomain[target.DomainID] = append(byDomain[target.DomainID], target)
	}
	for id, domain := range r.ManagedDomainIDs {
		if id <= 0 || !validDNSName(domain) {
			return ReconcileResult{}, errors.New("DNS managed domain is invalid")
		}
		if targets, exists := byDomain[id]; exists {
			if targets[0].Domain != domain {
				return ReconcileResult{}, errors.New("DNS managed domain name conflicts with desired records")
			}
			continue
		}
		byDomain[id] = []DesiredRecord{{Record: Record{Provider: ProviderDNSPod, DomainID: id, Domain: domain}}}
	}
	domains := make([]int64, 0, len(byDomain))
	for id := range byDomain {
		domains = append(domains, id)
	}
	sort.Slice(domains, func(i, j int) bool { return domains[i] < domains[j] })
	allObserved, allOwned := []Record{}, []OwnedRecord{}
	for _, id := range domains {
		targets := byDomain[id]
		domain := targets[0].Domain
		observed, err := r.Reader.ListRecords(ctx, id, domain)
		if err != nil {
			return ReconcileResult{}, err
		}
		owned, err := r.Store.ListOwned(ctx, id)
		if err != nil {
			return ReconcileResult{}, err
		}
		allObserved = append(allObserved, observed...)
		allOwned = append(allOwned, owned...)
	}
	key := r.Scope + ":" + now.Truncate(interval).Format("200601021504")
	plan, err := BuildDryRun(key, r.Desired, allObserved, allOwned, now)
	if err != nil {
		return ReconcileResult{}, err
	}
	stored, _, err := r.Store.SavePlan(ctx, plan)
	if err != nil {
		return ReconcileResult{}, err
	}
	if err := r.Store.SetLastReconcile(ctx, r.Scope, now); err != nil {
		return ReconcileResult{}, err
	}
	return ReconcileResult{Due: true, Plan: stored}, nil
}
