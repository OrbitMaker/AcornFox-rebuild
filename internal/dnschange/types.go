// Package dnschange owns the local, fail-closed DNS change ledger. It plans
// changes from observed records but never sends a provider write request.
package dnschange

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

const ProviderDNSPod = "dnspod"

var ownerKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9:_-]{2,127}$`)
var dnsLabel = regexp.MustCompile(`^[a-z0-9*](?:[a-z0-9*-]{0,61}[a-z0-9*])?$`)
var forbiddenAAddressRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("ff00::/8"),
}

type Record struct {
	Provider  string    `json:"provider"`
	DomainID  int64     `json:"domain_id"`
	Domain    string    `json:"domain"`
	RecordID  int64     `json:"record_id"`
	Host      string    `json:"host"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	TTL       int       `json:"ttl"`
	RequestID string    `json:"request_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (r Record) Validate(requireRecordID bool) error {
	if r.Provider != ProviderDNSPod || r.DomainID <= 0 || !validDNSName(r.Domain) || !validHost(r.Host) || (r.Type != "A" && r.Type != "CNAME") || r.TTL < 1 || r.TTL > 604800 {
		return errors.New("DNS record is invalid")
	}
	if requireRecordID && r.RecordID <= 0 {
		return errors.New("DNS record id is required")
	}
	if r.Type == "A" {
		address, err := netip.ParseAddr(strings.TrimSpace(r.Value))
		if err != nil || !address.Is4() || !address.IsGlobalUnicast() || forbiddenAAddress(address) {
			return errors.New("DNS A value must be a public address")
		}
		if r.Host != "console" && r.Host != "ingress" && r.Host != "*.apps" {
			return errors.New("DNS A host is outside the G4 platform boundary")
		}
	} else if strings.Contains(r.Host, "*") || !validDNSName(strings.TrimSuffix(r.Value, ".")) {
		return errors.New("DNS CNAME value is invalid")
	}
	return nil
}

func forbiddenAAddress(address netip.Addr) bool {
	for _, prefix := range forbiddenAAddressRanges {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

type DesiredRecord struct {
	OwnerKey string `json:"owner_key"`
	Record
}

func (r DesiredRecord) Validate() error {
	if !ownerKeyPattern.MatchString(r.OwnerKey) || r.RecordID != 0 {
		return errors.New("DNS desired ownership is invalid")
	}
	return r.Record.Validate(false)
}

type OwnedRecord struct {
	OwnerKey   string    `json:"owner_key"`
	Record     Record    `json:"record"`
	UpdatedAt  time.Time `json:"updated_at"`
	LastPlanID string    `json:"last_plan_id,omitempty"`
}

func (r OwnedRecord) Validate() error {
	if !ownerKeyPattern.MatchString(r.OwnerKey) || r.Record.Validate(true) != nil || strings.TrimSpace(r.Record.RequestID) == "" || r.Record.CreatedAt.IsZero() || r.UpdatedAt.IsZero() {
		return errors.New("DNS ownership record is incomplete")
	}
	return nil
}

type ChangeKind string

const (
	ChangeNoop   ChangeKind = "noop"
	ChangeCreate ChangeKind = "create"
	ChangeUpdate ChangeKind = "update"
	ChangeDelete ChangeKind = "delete"
)

type Change struct {
	Kind     ChangeKind     `json:"kind"`
	OwnerKey string         `json:"owner_key"`
	Before   *Record        `json:"before,omitempty"`
	After    *DesiredRecord `json:"after,omitempty"`
	Rollback *Rollback      `json:"rollback,omitempty"`
}

// Rollback is declarative only. Create rollback remains pending until a future
// explicit writer records the returned RecordId in the ownership ledger.
type Rollback struct {
	Kind     ChangeKind `json:"kind"`
	RecordID int64      `json:"record_id,omitempty"`
	Record   *Record    `json:"record,omitempty"`
	Deferred bool       `json:"deferred,omitempty"`
}

type Plan struct {
	ID             string    `json:"id"`
	IdempotencyKey string    `json:"idempotency_key"`
	InputDigest    string    `json:"input_digest"`
	Changes        []Change  `json:"changes"`
	CreatedAt      time.Time `json:"created_at"`
}

type ReconcileResult struct {
	Due  bool `json:"due"`
	Plan Plan `json:"plan"`
}

func PlatformARecords(domainID int64, domain, publicIP string, ttl int) ([]DesiredRecord, error) {
	result := make([]DesiredRecord, 0, 3)
	for _, item := range []struct{ owner, host string }{
		{"platform:console", "console"}, {"platform:ingress", "ingress"}, {"platform:apps-wildcard", "*.apps"},
	} {
		record := DesiredRecord{OwnerKey: item.owner, Record: Record{Provider: ProviderDNSPod, DomainID: domainID, Domain: strings.ToLower(strings.TrimSpace(domain)), Host: item.host, Type: "A", Value: strings.TrimSpace(publicIP), TTL: ttl}}
		if err := record.Validate(); err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, nil
}

func CustomerCNAME(ownerKey string, domainID int64, domain, host, target string, ttl int) (DesiredRecord, error) {
	record := DesiredRecord{OwnerKey: ownerKey, Record: Record{Provider: ProviderDNSPod, DomainID: domainID, Domain: strings.ToLower(strings.TrimSpace(domain)), Host: strings.ToLower(strings.TrimSpace(host)), Type: "CNAME", Value: strings.ToLower(strings.TrimSpace(target)), TTL: ttl}}
	return record, record.Validate()
}

func CanonicalInputDigest(desired []DesiredRecord, observed []Record, owned []OwnedRecord) (string, error) {
	desired = append([]DesiredRecord(nil), desired...)
	observed = append([]Record(nil), observed...)
	owned = append([]OwnedRecord(nil), owned...)
	sort.Slice(desired, func(i, j int) bool { return desired[i].OwnerKey < desired[j].OwnerKey })
	sort.Slice(observed, func(i, j int) bool {
		return observed[i].DomainID == observed[j].DomainID && observed[i].RecordID < observed[j].RecordID
	})
	sort.Slice(owned, func(i, j int) bool { return owned[i].OwnerKey < owned[j].OwnerKey })
	payload, err := json.Marshal(struct {
		Desired  []DesiredRecord `json:"desired"`
		Observed []Record        `json:"observed"`
		Owned    []OwnedRecord   `json:"owned"`
	}{desired, observed, owned})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func recordEqual(left, right Record) bool {
	return left.Provider == right.Provider && left.DomainID == right.DomainID && strings.EqualFold(left.Domain, right.Domain) && strings.EqualFold(left.Host, right.Host) && left.Type == right.Type && strings.EqualFold(strings.TrimSuffix(left.Value, "."), strings.TrimSuffix(right.Value, ".")) && left.TTL == right.TTL
}

func recordKey(record Record) string {
	return fmt.Sprintf("%d:%s:%s", record.DomainID, strings.ToLower(record.Host), record.Type)
}

func validDNSName(value string) bool {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !dnsLabel.MatchString(label) || strings.Contains(label, "*") {
			return false
		}
	}
	return true
}

func validHost(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "@" {
		return true
	}
	for _, label := range strings.Split(value, ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}
