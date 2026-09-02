// Package dnschange owns the local, fail-closed DNS change ledger. It plans
// changes from observed records but never sends a provider write request.
package dnschange

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	// ProviderDNSPod is retained for historical Gate 4 ownership facts.
	ProviderDNSPod = "dnspod"
	// ProviderAlibabaCloudDNS is the first AcornFox provider adapter. It is
	// deliberately a provider identity, not an account or endpoint name.
	ProviderAlibabaCloudDNS = "alibaba-cloud-dns"
)

var ownerKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9:_-]{2,127}$`)
var providerPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,127}$`)
var dnsLabel = regexp.MustCompile(`^[a-z0-9*](?:[a-z0-9*-]{0,61}[a-z0-9*])?$`)
var dnsRecordLabel = regexp.MustCompile(`^[a-z0-9_*](?:[a-z0-9_*-]{0,61}[a-z0-9_*])?$`)
var forbiddenAAddressRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("ff00::/8"),
}

type Record struct {
	InstallationID string    `json:"installation_id"`
	Provider       string    `json:"provider"`
	ZoneID         string    `json:"domain_id"`
	Domain         string    `json:"domain"`
	RecordID       string    `json:"record_id"`
	Name           string    `json:"name"`
	Type           string    `json:"type"`
	Value          string    `json:"value"`
	TTL            int       `json:"ttl"`
	RequestID      string    `json:"request_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// UnmarshalJSON accepts historical DNSPod plan payloads where domain_id and
// record_id were JSON numbers and host was the record name. New payloads are
// provider-neutral strings. This keeps durable dry-run plans readable across
// the 0030 ledger migration without maintaining a second identity type.
func (r *Record) UnmarshalJSON(payload []byte) error {
	var value struct {
		InstallationID string          `json:"installation_id"`
		Provider       string          `json:"provider"`
		ZoneID         json.RawMessage `json:"domain_id"`
		Domain         string          `json:"domain"`
		RecordID       json.RawMessage `json:"record_id"`
		Name           string          `json:"name"`
		Host           string          `json:"host"`
		Type           string          `json:"type"`
		Value          string          `json:"value"`
		TTL            int             `json:"ttl"`
		RequestID      string          `json:"request_id"`
		CreatedAt      time.Time       `json:"created_at"`
	}
	if err := json.Unmarshal(payload, &value); err != nil {
		return err
	}
	zoneID, err := opaqueJSONID(value.ZoneID)
	if err != nil {
		return err
	}
	recordID, err := opaqueJSONID(value.RecordID)
	if err != nil {
		return err
	}
	installationID := strings.TrimSpace(value.InstallationID)
	if installationID == "" && value.Provider == ProviderDNSPod {
		installationID = legacyDNSPodInstallationID
	}
	name := value.Name
	if name == "" {
		name = value.Host
	}
	*r = Record{InstallationID: installationID, Provider: value.Provider, ZoneID: zoneID, Domain: value.Domain, RecordID: recordID, Name: name, Type: value.Type, Value: value.Value, TTL: value.TTL, RequestID: value.RequestID, CreatedAt: value.CreatedAt}
	return nil
}

func opaqueJSONID(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var stringValue string
	if err := json.Unmarshal(raw, &stringValue); err == nil {
		return stringValue, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	number, ok := value.(json.Number)
	if !ok {
		return "", errors.New("DNS identifier must be a string or number")
	}
	return number.String(), nil
}

func (r Record) Validate(requireRecordID bool) error {
	if !validInstallationID(r.InstallationID) || !validProvider(r.Provider) || !validOpaqueID(r.ZoneID) || !validDNSName(r.Domain) || !validHost(r.Name) || !validRecordType(r.Type) || r.TTL < 1 || r.TTL > 604800 {
		return errors.New("DNS record is invalid")
	}
	if requireRecordID && !validOpaqueID(r.RecordID) {
		return errors.New("DNS record id is required")
	}
	if r.Type == "A" {
		address, err := netip.ParseAddr(strings.TrimSpace(r.Value))
		if err != nil || !address.Is4() || !address.IsGlobalUnicast() || forbiddenAAddress(address) {
			return errors.New("DNS A value must be a public address")
		}
	} else if r.Type == "CNAME" && (strings.Contains(r.Name, "*") || !validDNSName(strings.TrimSuffix(r.Value, "."))) {
		return errors.New("DNS CNAME value is invalid")
	} else if r.Type == "TXT" && !validTXTValue(r.Value) {
		return errors.New("DNS TXT value is invalid")
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

// UnmarshalJSON keeps the ownership key when Record's compatibility decoder
// handles historical provider identifiers. Without this explicit method, the
// embedded Record decoder consumes the object and silently drops owner_key on
// a durable plan replay.
func (r *DesiredRecord) UnmarshalJSON(payload []byte) error {
	var value struct {
		OwnerKey string `json:"owner_key"`
	}
	if err := json.Unmarshal(payload, &value); err != nil {
		return err
	}
	var record Record
	if err := json.Unmarshal(payload, &record); err != nil {
		return err
	}
	*r = DesiredRecord{OwnerKey: value.OwnerKey, Record: record}
	return nil
}

func (r DesiredRecord) Validate() error {
	if !ownerKeyPattern.MatchString(r.OwnerKey) || strings.TrimSpace(r.RecordID) != "" {
		return errors.New("DNS desired ownership is invalid")
	}
	if err := r.Record.Validate(false); err != nil {
		return err
	}
	if r.Provider == ProviderAlibabaCloudDNS {
		if (r.Type == "A" && r.Name == "*.apps") || (r.Type == "TXT" && r.Name == "_acme-challenge.apps") {
			return nil
		}
		return errors.New("Alibaba DNS desired record is outside the AcornFox wildcard boundary")
	}
	if r.Provider != ProviderDNSPod {
		return errors.New("DNS provider has no desired-record policy")
	}
	if r.Type == "A" && r.Name != "console" && r.Name != "ingress" && r.Name != "*.apps" {
		return errors.New("DNS A host is outside the G4 platform boundary")
	}
	if r.Type == "TXT" {
		return errors.New("DNSPod TXT desired record is unsupported")
	}
	return nil
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
	RecordID string     `json:"record_id,omitempty"`
	Record   *Record    `json:"record,omitempty"`
	Deferred bool       `json:"deferred,omitempty"`
}

// UnmarshalJSON keeps historical rollback entries readable after RecordID
// changed from a DNSPod integer to an opaque provider string.
func (r *Rollback) UnmarshalJSON(payload []byte) error {
	var value struct {
		Kind     ChangeKind      `json:"kind"`
		RecordID json.RawMessage `json:"record_id"`
		Record   *Record         `json:"record"`
		Deferred bool            `json:"deferred"`
	}
	if err := json.Unmarshal(payload, &value); err != nil {
		return err
	}
	recordID, err := opaqueJSONID(value.RecordID)
	if err != nil {
		return err
	}
	*r = Rollback{Kind: value.Kind, RecordID: recordID, Record: value.Record, Deferred: value.Deferred}
	return nil
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

func PlatformARecords(zoneID, domain, publicIP string, ttl int) ([]DesiredRecord, error) {
	result := make([]DesiredRecord, 0, 3)
	for _, item := range []struct{ owner, host string }{
		{"platform:console", "console"}, {"platform:ingress", "ingress"}, {"platform:apps-wildcard", "*.apps"},
	} {
		record := DesiredRecord{OwnerKey: item.owner, Record: Record{InstallationID: legacyDNSPodInstallationID, Provider: ProviderDNSPod, ZoneID: strings.TrimSpace(zoneID), Domain: strings.ToLower(strings.TrimSpace(domain)), Name: item.host, Type: "A", Value: strings.TrimSpace(publicIP), TTL: ttl}}
		if err := record.Validate(); err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, nil
}

func CustomerCNAME(ownerKey, zoneID, domain, name, target string, ttl int) (DesiredRecord, error) {
	record := DesiredRecord{OwnerKey: ownerKey, Record: Record{InstallationID: legacyDNSPodInstallationID, Provider: ProviderDNSPod, ZoneID: strings.TrimSpace(zoneID), Domain: strings.ToLower(strings.TrimSpace(domain)), Name: strings.ToLower(strings.TrimSpace(name)), Type: "CNAME", Value: strings.ToLower(strings.TrimSpace(target)), TTL: ttl}}
	return record, record.Validate()
}

// AlibabaWildcardRecords is the complete desired DNS surface for the first
// AcornFox public beta. Callers cannot use it to create per-app or root records.
func AlibabaWildcardRecords(installationID, zoneID, domain, publicIP, dns01Value string, ttl int) ([]DesiredRecord, error) {
	values := []struct {
		owner, name, recordType, value string
	}{
		{"acornfox:wildcard-a", "*.apps", "A", strings.TrimSpace(publicIP)},
		{"acornfox:wildcard-dns01", "_acme-challenge.apps", "TXT", strings.TrimSpace(dns01Value)},
	}
	result := make([]DesiredRecord, 0, len(values))
	for _, value := range values {
		record := DesiredRecord{OwnerKey: value.owner, Record: Record{InstallationID: strings.TrimSpace(installationID), Provider: ProviderAlibabaCloudDNS, ZoneID: strings.TrimSpace(zoneID), Domain: strings.ToLower(strings.TrimSpace(domain)), Name: value.name, Type: value.recordType, Value: value.value, TTL: ttl}}
		if err := record.Validate(); err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, nil
}

func CanonicalInputDigest(desired []DesiredRecord, observed []Record, owned []OwnedRecord) (string, error) {
	desired = append([]DesiredRecord(nil), desired...)
	observed = append([]Record(nil), observed...)
	owned = append([]OwnedRecord(nil), owned...)
	sort.Slice(desired, func(i, j int) bool { return desired[i].OwnerKey < desired[j].OwnerKey })
	sort.Slice(observed, func(i, j int) bool {
		return recordTuple(observed[i]) < recordTuple(observed[j])
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
	return left.InstallationID == right.InstallationID && left.Provider == right.Provider && left.ZoneID == right.ZoneID && strings.EqualFold(left.Domain, right.Domain) && strings.EqualFold(left.Name, right.Name) && left.Type == right.Type && canonicalValue(left) == canonicalValue(right) && left.TTL == right.TTL
}

func recordKey(record Record) string {
	return opaqueTuple(record.InstallationID, record.Provider, record.ZoneID, strings.ToLower(record.Name), record.Type)
}

func recordTuple(record Record) string {
	return opaqueTuple(record.InstallationID, record.Provider, record.ZoneID, record.RecordID, strings.ToLower(record.Name), record.Type)
}

func providerRecordKey(record Record) string {
	return opaqueTuple(record.InstallationID, record.Provider, record.ZoneID, record.RecordID)
}

func opaqueTuple(parts ...string) string {
	payload, err := json.Marshal(parts)
	if err != nil {
		panic("DNS opaque tuple serialization failed")
	}
	return string(payload)
}

func canonicalValue(record Record) string {
	if record.Type == "TXT" {
		return strings.TrimSpace(record.Value)
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(record.Value), "."))
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
		if !dnsRecordLabel.MatchString(label) {
			return false
		}
	}
	return true
}

const legacyDNSPodInstallationID = "legacy-dnspod"

func validInstallationID(value string) bool { return validOpaqueID(value) }

func validOpaqueID(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 512 && !strings.ContainsAny(value, "\x00\r\n")
}

func validProvider(value string) bool {
	return providerPattern.MatchString(value)
}

func validRecordType(value string) bool {
	return value == "A" || value == "CNAME" || value == "TXT"
}

func validTXTValue(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 4096 && !strings.ContainsRune(value, '\x00')
}
