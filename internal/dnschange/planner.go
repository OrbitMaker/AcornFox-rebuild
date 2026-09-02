package dnschange

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// BuildDryRun plans only exact, owned mutations. Any ambiguous matching record
// or manual drift aborts the entire plan instead of guessing an overwrite.
func BuildDryRun(idempotencyKey string, desired []DesiredRecord, observed []Record, owned []OwnedRecord, now time.Time) (Plan, error) {
	if idempotencyKey == "" {
		return Plan{}, errors.New("DNS change idempotency key is required")
	}
	domainNames := map[string]string{}
	registerDomain := func(record Record) error {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(record.Domain), "."))
		zoneKey := strings.Join([]string{record.InstallationID, record.Provider, record.ZoneID}, ":")
		if previous, exists := domainNames[zoneKey]; exists && previous != name {
			return fmt.Errorf("DNS zone id %s maps to multiple names", record.ZoneID)
		}
		domainNames[zoneKey] = name
		return nil
	}
	desiredIdentity := map[string]string{}
	for _, record := range desired {
		if err := record.Validate(); err != nil {
			return Plan{}, err
		}
		if err := registerDomain(record.Record); err != nil {
			return Plan{}, err
		}
		identity := recordKey(record.Record)
		if owner, exists := desiredIdentity[identity]; exists {
			return Plan{}, fmt.Errorf("DNS desired identity %s is duplicated by %s and %s", identity, owner, record.OwnerKey)
		}
		desiredIdentity[identity] = record.OwnerKey
	}
	observedIDs := map[string]struct{}{}
	for _, record := range observed {
		if err := record.Validate(true); err != nil {
			return Plan{}, err
		}
		identity := providerRecordKey(record)
		if _, exists := observedIDs[identity]; exists {
			return Plan{}, fmt.Errorf("DNS observed record identity %s is duplicated", identity)
		}
		observedIDs[identity] = struct{}{}
		if err := registerDomain(record); err != nil {
			return Plan{}, err
		}
	}
	for _, record := range owned {
		if err := record.Validate(); err != nil {
			return Plan{}, err
		}
		if err := registerDomain(record.Record); err != nil {
			return Plan{}, err
		}
	}
	digest, err := CanonicalInputDigest(desired, observed, owned)
	if err != nil {
		return Plan{}, err
	}
	observedByID, observedByKey, ownedByKey, desiredByKey := map[string]Record{}, map[string][]Record{}, map[string]OwnedRecord{}, map[string]DesiredRecord{}
	for _, record := range observed {
		observedByID[providerRecordKey(record)] = record
		observedByKey[recordKey(record)] = append(observedByKey[recordKey(record)], record)
	}
	for _, record := range owned {
		if _, exists := ownedByKey[record.OwnerKey]; exists {
			return Plan{}, errors.New("DNS ownership key is duplicated")
		}
		ownedByKey[record.OwnerKey] = record
	}
	for _, record := range desired {
		if _, exists := desiredByKey[record.OwnerKey]; exists {
			return Plan{}, errors.New("DNS desired ownership key is duplicated")
		}
		desiredByKey[record.OwnerKey] = record
	}
	changes := make([]Change, 0, len(desired)+len(owned))
	for _, target := range desired {
		ownedRecord, exists := ownedByKey[target.OwnerKey]
		if !exists {
			matches := observedByKey[recordKey(target.Record)]
			if len(matches) != 0 {
				return Plan{}, fmt.Errorf("DNS record %s is not owned by this task", recordKey(target.Record))
			}
			changes = append(changes, Change{Kind: ChangeCreate, OwnerKey: target.OwnerKey, After: pointerDesired(target), Rollback: &Rollback{Kind: ChangeDelete, Deferred: true}})
			continue
		}
		if target.InstallationID != ownedRecord.Record.InstallationID || target.Provider != ownedRecord.Record.Provider || target.ZoneID != ownedRecord.Record.ZoneID || !strings.EqualFold(target.Name, ownedRecord.Record.Name) || target.Type != ownedRecord.Record.Type {
			return Plan{}, fmt.Errorf("DNS ownership identity changed for %s", target.OwnerKey)
		}
		current, found := observedByID[providerRecordKey(ownedRecord.Record)]
		if !found || !recordEqual(current, ownedRecord.Record) {
			return Plan{}, fmt.Errorf("DNS ownership drift for %s", target.OwnerKey)
		}
		if recordEqual(current, target.Record) {
			changes = append(changes, Change{Kind: ChangeNoop, OwnerKey: target.OwnerKey, Before: pointerRecord(current), After: pointerDesired(target)})
		} else {
			changes = append(changes, Change{Kind: ChangeUpdate, OwnerKey: target.OwnerKey, Before: pointerRecord(current), After: pointerDesired(target), Rollback: &Rollback{Kind: ChangeUpdate, RecordID: current.RecordID, Record: pointerRecord(current)}})
		}
	}
	for ownerKey, ownedRecord := range ownedByKey {
		if _, exists := desiredByKey[ownerKey]; exists {
			continue
		}
		current, found := observedByID[providerRecordKey(ownedRecord.Record)]
		if !found || !recordEqual(current, ownedRecord.Record) {
			return Plan{}, fmt.Errorf("DNS ownership drift for %s", ownerKey)
		}
		changes = append(changes, Change{Kind: ChangeDelete, OwnerKey: ownerKey, Before: pointerRecord(current), Rollback: &Rollback{Kind: ChangeCreate, Record: pointerRecord(current)}})
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].OwnerKey < changes[j].OwnerKey })
	identity := sha256.Sum256([]byte(idempotencyKey + "\x00" + digest))
	return Plan{ID: "dnsplan-" + hex.EncodeToString(identity[:12]), IdempotencyKey: idempotencyKey, InputDigest: digest, Changes: changes, CreatedAt: now.UTC()}, nil
}

func pointerRecord(value Record) *Record                { return &value }
func pointerDesired(value DesiredRecord) *DesiredRecord { return &value }
