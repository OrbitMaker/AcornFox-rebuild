// Package dnspod implements only the unsigned, read-shaped DNSPod fixture
// contract used by G4 dry-runs. It has no credential, signing, CLI, or write
// operation surface; confirmed operator writes are intentionally deferred.
package dnspod

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/dnschange"
)

const APIVersion = "2021-03-23"
const ActionDescribeRecordList = "DescribeRecordList"

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Adapter struct {
	Endpoint string
	Client   HTTPDoer
	Clock    func() time.Time
}

func (a Adapter) ListRecords(ctx context.Context, installationID, zoneID, domain string) ([]dnschange.Record, error) {
	domainID, err := strconv.ParseInt(strings.TrimSpace(zoneID), 10, 64)
	if a.Client == nil || err != nil || domainID <= 0 || strings.TrimSpace(installationID) == "" || strings.TrimSpace(domain) == "" {
		return nil, errors.New("DNSPod read adapter is not configured")
	}
	payload, err := json.Marshal(map[string]any{"Domain": strings.ToLower(strings.TrimSpace(domain)), "DomainId": domainID, "Offset": 0, "Limit": 3000})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(a.Endpoint), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TC-Action", ActionDescribeRecordList)
	req.Header.Set("X-TC-Version", APIVersion)
	response, err := a.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DNSPod read fixture returned HTTP %d", response.StatusCode)
	}
	var decoded struct {
		Response struct {
			RequestID string `json:"RequestId"`
			Error     *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
			RecordCountInfo *struct {
				TotalCount int `json:"TotalCount"`
			} `json:"RecordCountInfo"`
			RecordList []struct {
				RecordID  int64  `json:"RecordId"`
				DomainID  int64  `json:"DomainId"`
				Name      string `json:"Name"`
				Type      string `json:"Type"`
				Value     string `json:"Value"`
				TTL       int    `json:"TTL"`
				UpdatedOn string `json:"UpdatedOn"`
			} `json:"RecordList"`
		} `json:"Response"`
	}
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		return nil, err
	}
	if decoded.Response.Error != nil || strings.TrimSpace(decoded.Response.RequestID) == "" || decoded.Response.RecordCountInfo == nil {
		return nil, errors.New("DNSPod read fixture response is incomplete or failed")
	}
	if decoded.Response.RecordCountInfo.TotalCount != len(decoded.Response.RecordList) {
		return nil, errors.New("DNSPod record list pagination is incomplete")
	}
	now := time.Now().UTC()
	if a.Clock != nil {
		now = a.Clock().UTC()
	}
	items := make([]dnschange.Record, 0, len(decoded.Response.RecordList))
	for _, item := range decoded.Response.RecordList {
		itemDomainID := item.DomainID
		if itemDomainID == 0 {
			itemDomainID = domainID
		}
		if itemDomainID != domainID {
			return nil, errors.New("DNSPod fixture record domain id mismatched")
		}
		record := dnschange.Record{InstallationID: installationID, Provider: dnschange.ProviderDNSPod, ZoneID: zoneID, Domain: strings.ToLower(strings.TrimSpace(domain)), RecordID: strconv.FormatInt(item.RecordID, 10), Name: strings.ToLower(strings.TrimSpace(item.Name)), Type: strings.ToUpper(strings.TrimSpace(item.Type)), Value: strings.TrimSpace(item.Value), TTL: item.TTL, RequestID: decoded.Response.RequestID, CreatedAt: now}
		if err := record.Validate(true); err != nil {
			return nil, errors.New("DNSPod fixture record is invalid")
		}
		items = append(items, record)
	}
	return items, nil
}
