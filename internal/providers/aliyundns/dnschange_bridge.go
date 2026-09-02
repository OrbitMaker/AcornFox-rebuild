package aliyundns

import (
	"context"
	"errors"
	"strings"

	"github.com/open-card/open-card/internal/dnschange"
)

// DNSChangeBridge maps Alibaba's opaque provider representation to the
// provider-neutral DNS-change executor. It deliberately carries no
// credentials: those stay inside the injected DNS implementation.
type DNSChangeBridge struct {
	DNS            DNS
	InstallationID string
	ZoneID         string
	Domain         string
}

var _ dnschange.ExecutorProvider = DNSChangeBridge{}

func (b DNSChangeBridge) ListRecords(ctx context.Context, zone dnschange.ManagedZone) ([]dnschange.Record, error) {
	if err := b.matches(zone); err != nil {
		return nil, err
	}
	items, err := b.DNS.ListRecords(ctx, b.Domain)
	if err != nil {
		return nil, err
	}
	result := make([]dnschange.Record, 0, len(items))
	for _, item := range items {
		if !strings.EqualFold(item.DomainName, b.Domain) {
			return nil, errors.New("Alibaba DNS returned an unexpected zone")
		}
		result = append(result, dnschange.Record{
			InstallationID: b.InstallationID,
			Provider:       dnschange.ProviderAlibabaCloudDNS,
			ZoneID:         b.ZoneID,
			Domain:         b.Domain,
			RecordID:       item.ID,
			Name:           item.RR,
			Type:           item.Type,
			Value:          item.Value,
			TTL:            item.TTL,
		})
	}
	return result, nil
}

func (b DNSChangeBridge) CreateRecord(ctx context.Context, desired dnschange.DesiredRecord) (dnschange.WriteReceipt, error) {
	if err := b.matchesDesired(desired); err != nil {
		return dnschange.WriteReceipt{}, err
	}
	receipt, err := b.DNS.CreateRecord(ctx, CreateRecord{DomainName: b.Domain, RR: desired.Name, Type: desired.Type, Value: desired.Value, TTL: desired.TTL})
	return dnschange.WriteReceipt{RecordID: receipt.RecordID, RequestID: receipt.RequestID}, err
}

func (b DNSChangeBridge) UpdateRecord(ctx context.Context, record dnschange.Record) (dnschange.WriteReceipt, error) {
	if err := b.matchesRecord(record); err != nil {
		return dnschange.WriteReceipt{}, err
	}
	receipt, err := b.DNS.UpdateRecord(ctx, UpdateRecord{ID: record.RecordID, RR: record.Name, Type: record.Type, Value: record.Value, TTL: record.TTL})
	return dnschange.WriteReceipt{RecordID: receipt.RecordID, RequestID: receipt.RequestID}, err
}

func (b DNSChangeBridge) DeleteRecord(ctx context.Context, record dnschange.Record) (dnschange.WriteReceipt, error) {
	if err := b.matchesRecord(record); err != nil {
		return dnschange.WriteReceipt{}, err
	}
	receipt, err := b.DNS.DeleteRecord(ctx, record.RecordID)
	return dnschange.WriteReceipt{RecordID: receipt.RecordID, RequestID: receipt.RequestID}, err
}

func (b DNSChangeBridge) matches(zone dnschange.ManagedZone) error {
	if b.DNS == nil || zone.Validate() != nil || zone.InstallationID != strings.TrimSpace(b.InstallationID) || zone.Provider != dnschange.ProviderAlibabaCloudDNS || zone.ZoneID != strings.TrimSpace(b.ZoneID) || !strings.EqualFold(strings.TrimSuffix(zone.Domain, "."), strings.TrimSuffix(strings.TrimSpace(b.Domain), ".")) {
		return errors.New("Alibaba DNS bridge scope is invalid")
	}
	return nil
}

func (b DNSChangeBridge) matchesDesired(record dnschange.DesiredRecord) error {
	if record.Validate() != nil {
		return errors.New("Alibaba DNS bridge desired record is invalid")
	}
	return b.matches(dnschange.ManagedZone{InstallationID: record.InstallationID, Provider: record.Provider, ZoneID: record.ZoneID, Domain: record.Domain})
}

func (b DNSChangeBridge) matchesRecord(record dnschange.Record) error {
	if record.Validate(true) != nil {
		return errors.New("Alibaba DNS bridge record is invalid")
	}
	return b.matches(dnschange.ManagedZone{InstallationID: record.InstallationID, Provider: record.Provider, ZoneID: record.ZoneID, Domain: record.Domain})
}
