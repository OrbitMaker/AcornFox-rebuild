package dnschange

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
)

type Reader interface {
	ListRecords(context.Context, string, string, string) ([]Record, error)
}
type Ledger interface {
	ListOwned(context.Context, string, string, string) ([]OwnedRecord, error)
	SavePlan(context.Context, Plan) (Plan, bool, error)
	LastReconcile(context.Context, string) (time.Time, error)
	SetLastReconcile(context.Context, string, time.Time) error
}

// ManagedZone keeps a provider zone in reconciliation scope when it has no
// desired records, so an owned record can still produce a fail-closed delete
// dry-run. IDs are provider-opaque strings.
type ManagedZone struct {
	InstallationID string
	Provider       string
	ZoneID         string
	Domain         string
}

func (z ManagedZone) Validate() error {
	return (Record{InstallationID: z.InstallationID, Provider: z.Provider, ZoneID: z.ZoneID, Domain: z.Domain, Name: "@", Type: "A", Value: "8.8.8.8", TTL: 60}).Validate(false)
}

type Reconciler struct {
	Store        Ledger
	Reader       Reader
	Desired      []DesiredRecord
	ManagedZones []ManagedZone
	Scope        string
	Clock        func() time.Time
	Interval     time.Duration
}

func (r *Reconciler) ReconcileOnce(ctx context.Context) (ReconcileResult, error) {
	if r == nil || r.Store == nil || r.Reader == nil || r.Scope == "" || (len(r.Desired) == 0 && len(r.ManagedZones) == 0) {
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
	byZone := map[string][]DesiredRecord{}
	zones := map[string]ManagedZone{}
	for _, target := range r.Desired {
		if err := target.Validate(); err != nil {
			return ReconcileResult{}, err
		}
		key := zoneKey(target.Record)
		byZone[key] = append(byZone[key], target)
		zones[key] = ManagedZone{InstallationID: target.InstallationID, Provider: target.Provider, ZoneID: target.ZoneID, Domain: target.Domain}
	}
	for _, zone := range r.ManagedZones {
		if zone.Validate() != nil {
			return ReconcileResult{}, errors.New("DNS managed zone is invalid")
		}
		key := zoneKey(Record{InstallationID: zone.InstallationID, Provider: zone.Provider, ZoneID: zone.ZoneID})
		if targets, exists := byZone[key]; exists {
			if !strings.EqualFold(targets[0].Domain, zone.Domain) {
				return ReconcileResult{}, errors.New("DNS managed domain name conflicts with desired records")
			}
			continue
		}
		zones[key] = zone
	}
	zoneKeys := make([]string, 0, len(zones))
	for key := range zones {
		zoneKeys = append(zoneKeys, key)
	}
	sort.Strings(zoneKeys)
	allObserved, allOwned := []Record{}, []OwnedRecord{}
	for _, key := range zoneKeys {
		zone := zones[key]
		observed, err := r.Reader.ListRecords(ctx, zone.InstallationID, zone.ZoneID, zone.Domain)
		if err != nil {
			return ReconcileResult{}, err
		}
		owned, err := r.Store.ListOwned(ctx, zone.InstallationID, zone.Provider, zone.ZoneID)
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

func zoneKey(record Record) string {
	return opaqueTuple(record.InstallationID, record.Provider, record.ZoneID)
}
