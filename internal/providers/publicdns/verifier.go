// Package publicdns verifies public DNS facts through explicitly configured
// recursive resolvers. It has no DNS mutation, provider SDK, credential, or
// system-resolver discovery surface.
package publicdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
)

const (
	providerName          = "public-dns-verifier"
	minimumResolvers      = 2
	maximumCNAMEHops      = 8
	maximumQueryTimeout   = 2 * time.Second
	defaultOverallTimeout = 8 * time.Second
)

var (
	dnsLabel           = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	forbiddenAddresses = mustPrefixes(
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "2001:db8::/32", "2001:2::/48", "ff00::/8",
	)
)

// Config either accepts injected resolvers (for deterministic tests) or two
// or more explicit recursive resolver endpoint IP:port values. No empty
// configuration falls back to a system-default resolver.
type Config struct {
	Resolvers         []contracts.PublicDNSResolver
	ResolverEndpoints []string
	QueryTimeout      time.Duration
	OverallTimeout    time.Duration
}

type Verifier struct {
	resolvers      []contracts.PublicDNSResolver
	queryTimeout   time.Duration
	overallTimeout time.Duration
}

func New(config Config) (*Verifier, error) {
	resolvers := append([]contracts.PublicDNSResolver(nil), config.Resolvers...)
	if len(resolvers) == 0 {
		seenEndpoints := map[string]struct{}{}
		for _, endpoint := range config.ResolverEndpoints {
			if _, exists := seenEndpoints[endpoint]; exists {
				return nil, errors.New("recursive resolver endpoints must be distinct")
			}
			seenEndpoints[endpoint] = struct{}{}
			resolver, err := newRecursiveResolver(endpoint)
			if err != nil {
				return nil, err
			}
			resolvers = append(resolvers, resolver)
		}
	}
	if len(resolvers) < minimumResolvers {
		return nil, fmt.Errorf("at least %d explicit recursive resolvers are required", minimumResolvers)
	}
	queryTimeout := config.QueryTimeout
	if queryTimeout == 0 {
		queryTimeout = maximumQueryTimeout
	}
	if queryTimeout <= 0 || queryTimeout > maximumQueryTimeout {
		return nil, fmt.Errorf("DNS query timeout must be between 1ns and %s", maximumQueryTimeout)
	}
	overallTimeout := config.OverallTimeout
	if overallTimeout == 0 {
		overallTimeout = defaultOverallTimeout
	}
	if overallTimeout <= 0 || overallTimeout > defaultOverallTimeout {
		return nil, fmt.Errorf("DNS overall timeout must be between 1ns and %s", defaultOverallTimeout)
	}
	return &Verifier{resolvers: resolvers, queryTimeout: queryTimeout, overallTimeout: overallTimeout}, nil
}

func (v *Verifier) VerifyPlatformAddress(ctx context.Context, hostname, expectedIP string) (contracts.PublicDNSVerification, error) {
	hostname, err := normalizeHostname(hostname)
	if err != nil {
		return contracts.PublicDNSVerification{}, err
	}
	expected, err := publicExpectedAddress(expectedIP)
	if err != nil {
		return contracts.PublicDNSVerification{}, err
	}
	return v.verify(ctx, hostname, expected.String(), func(ctx context.Context, resolver contracts.PublicDNSResolver, label string) contracts.PublicDNSObservation {
		return v.platformObservation(ctx, resolver, label, hostname, expected)
	}), nil
}

func (v *Verifier) VerifyCustomerIngress(ctx context.Context, hostname, zone string) (contracts.PublicDNSVerification, error) {
	hostname, err := normalizeHostname(hostname)
	if err != nil {
		return contracts.PublicDNSVerification{}, err
	}
	zone, err = normalizeHostname(zone)
	if err != nil {
		return contracts.PublicDNSVerification{}, err
	}
	expected := "ingress." + zone
	return v.verify(ctx, hostname, expected, func(ctx context.Context, resolver contracts.PublicDNSResolver, label string) contracts.PublicDNSObservation {
		return v.cnameObservation(ctx, resolver, label, hostname, expected)
	}), nil
}

func (v *Verifier) verify(ctx context.Context, hostname, expected string, inspect func(context.Context, contracts.PublicDNSResolver, string) contracts.PublicDNSObservation) contracts.PublicDNSVerification {
	bounded, cancel := context.WithTimeout(ctx, v.overallTimeout)
	defer cancel()
	results := make(chan contracts.PublicDNSObservation, len(v.resolvers))
	for index, resolver := range v.resolvers {
		go func(resolver contracts.PublicDNSResolver, label string) { results <- inspect(bounded, resolver, label) }(resolver, fmt.Sprintf("resolver-%d", index+1))
	}
	observations := make([]contracts.PublicDNSObservation, 0, len(v.resolvers))
	received := map[string]struct{}{}
	for len(observations) < len(v.resolvers) {
		select {
		case observation := <-results:
			observations = append(observations, observation)
			received[observation.Resolver] = struct{}{}
		case <-bounded.Done():
			for index := range v.resolvers {
				label := fmt.Sprintf("resolver-%d", index+1)
				if _, exists := received[label]; !exists {
					observations = append(observations, contracts.PublicDNSObservation{Resolver: label, Status: contracts.PublicDNSTimeout})
				}
			}
		}
	}
	sort.Slice(observations, func(left, right int) bool { return observations[left].Resolver < observations[right].Resolver })
	return contracts.PublicDNSVerification{Status: aggregateStatus(observations), Hostname: hostname, Expected: expected, Observations: observations}
}

func (v *Verifier) platformObservation(ctx context.Context, resolver contracts.PublicDNSResolver, label, hostname string, expected netip.Addr) contracts.PublicDNSObservation {
	observation := contracts.PublicDNSObservation{Resolver: label}
	var records []contracts.PublicDNSRecord
	statuses := []contracts.PublicDNSStatus{}
	for _, recordType := range []string{"A", "AAAA"} {
		answer, status := v.lookup(ctx, resolver, hostname, recordType)
		statuses = append(statuses, status)
		for _, record := range answer {
			if record.Type != recordType {
				continue
			}
			ip, err := netip.ParseAddr(strings.TrimSpace(record.Value))
			if err == nil {
				records = append(records, contracts.PublicDNSRecord{Name: hostname, Type: recordType, Value: ip.String()})
			}
		}
	}
	observation.Records = sortedRecords(records)
	for _, record := range records {
		if record.Value == expected.String() {
			observation.Status = contracts.PublicDNSVerified
			return observation
		}
	}
	if len(records) > 0 {
		observation.Status = contracts.PublicDNSMismatch
		return observation
	}
	observation.Status = combineQueryStatuses(statuses)
	return observation
}

func (v *Verifier) cnameObservation(ctx context.Context, resolver contracts.PublicDNSResolver, label, hostname, expected string) contracts.PublicDNSObservation {
	observation := contracts.PublicDNSObservation{Resolver: label}
	current := hostname
	seen := map[string]struct{}{current: {}}
	for hop := 0; hop < maximumCNAMEHops; hop++ {
		records, status := v.lookup(ctx, resolver, current, "CNAME")
		if status == contracts.PublicDNSTimeout || status == contracts.PublicDNSResolverError {
			observation.Status = status
			return observation
		}
		values := make([]string, 0, len(records))
		for _, record := range records {
			if record.Type != "CNAME" {
				continue
			}
			value, err := normalizeCNAMETarget(record.Value)
			if err != nil {
				observation.Status = contracts.PublicDNSMismatch
				return observation
			}
			values = append(values, value)
		}
		values = uniqueStrings(values)
		if len(values) == 0 {
			if current == expected && hop > 0 {
				observation.Status = contracts.PublicDNSVerified
			} else {
				observation.Status = status
			}
			return observation
		}
		if len(values) != 1 {
			observation.Status = contracts.PublicDNSConflict
			return observation
		}
		next := values[0]
		observation.Records = append(observation.Records, contracts.PublicDNSRecord{Name: current, Type: "CNAME", Value: next})
		if next == expected {
			terminal, terminalStatus := v.lookup(ctx, resolver, expected, "CNAME")
			if terminalStatus == contracts.PublicDNSTimeout || terminalStatus == contracts.PublicDNSResolverError {
				observation.Status = terminalStatus
				observation.Records = sortedRecords(observation.Records)
				return observation
			}
			terminalValues := make([]string, 0, len(terminal))
			for _, record := range terminal {
				if record.Type != "CNAME" {
					continue
				}
				value, err := normalizeCNAMETarget(record.Value)
				if err != nil {
					observation.Status = contracts.PublicDNSMismatch
					observation.Records = sortedRecords(observation.Records)
					return observation
				}
				terminalValues = append(terminalValues, value)
			}
			terminalValues = uniqueStrings(terminalValues)
			if len(terminalValues) == 0 {
				observation.Status = contracts.PublicDNSVerified
				observation.Records = sortedRecords(observation.Records)
				return observation
			}
			for _, value := range terminalValues {
				observation.Records = append(observation.Records, contracts.PublicDNSRecord{Name: expected, Type: "CNAME", Value: value})
			}
			if len(terminalValues) > 1 || terminalValues[0] == expected {
				observation.Status = contracts.PublicDNSConflict
			} else {
				observation.Status = contracts.PublicDNSMismatch
			}
			observation.Records = sortedRecords(observation.Records)
			return observation
		}
		if _, duplicate := seen[next]; duplicate {
			observation.Status = contracts.PublicDNSConflict
			observation.Records = sortedRecords(observation.Records)
			return observation
		}
		seen[next], current = struct{}{}, next
	}
	observation.Status = contracts.PublicDNSUnknown
	observation.Records = sortedRecords(observation.Records)
	return observation
}

func (v *Verifier) lookup(ctx context.Context, resolver contracts.PublicDNSResolver, hostname, recordType string) ([]contracts.PublicDNSRecord, contracts.PublicDNSStatus) {
	query, cancel := context.WithTimeout(ctx, v.queryTimeout)
	defer cancel()
	records, err := resolver.Lookup(query, hostname, recordType)
	if err != nil {
		if errors.Is(query.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
			return nil, contracts.PublicDNSTimeout
		}
		return nil, contracts.PublicDNSResolverError
	}
	if len(records) == 0 {
		return nil, contracts.PublicDNSNotFound
	}
	return records, contracts.PublicDNSPending
}

func combineQueryStatuses(statuses []contracts.PublicDNSStatus) contracts.PublicDNSStatus {
	for _, status := range statuses {
		if status == contracts.PublicDNSResolverError {
			return contracts.PublicDNSResolverError
		}
	}
	for _, status := range statuses {
		if status == contracts.PublicDNSTimeout {
			return contracts.PublicDNSTimeout
		}
	}
	return contracts.PublicDNSNotFound
}

func aggregateStatus(observations []contracts.PublicDNSObservation) contracts.PublicDNSStatus {
	counts := map[contracts.PublicDNSStatus]int{}
	for _, observation := range observations {
		counts[observation.Status]++
	}
	if counts[contracts.PublicDNSVerified] >= minimumResolvers {
		return contracts.PublicDNSVerified
	}
	if counts[contracts.PublicDNSVerified] > 0 && (counts[contracts.PublicDNSMismatch] > 0 || counts[contracts.PublicDNSConflict] > 0) {
		return contracts.PublicDNSConflict
	}
	if counts[contracts.PublicDNSConflict] > 0 {
		return contracts.PublicDNSConflict
	}
	if counts[contracts.PublicDNSMismatch] >= minimumResolvers {
		return contracts.PublicDNSMismatch
	}
	if counts[contracts.PublicDNSTimeout] == len(observations) {
		return contracts.PublicDNSTimeout
	}
	if counts[contracts.PublicDNSResolverError] == len(observations) {
		return contracts.PublicDNSResolverError
	}
	if counts[contracts.PublicDNSNotFound] == len(observations) {
		return contracts.PublicDNSNotFound
	}
	if counts[contracts.PublicDNSNotFound]+counts[contracts.PublicDNSPending] >= minimumResolvers {
		return contracts.PublicDNSPending
	}
	return contracts.PublicDNSUnknown
}

func normalizeHostname(value string) (string, error) {
	if value != strings.TrimSpace(value) {
		return "", errors.New("DNS hostname must not contain surrounding whitespace")
	}
	if strings.HasSuffix(value, ".") {
		value = strings.TrimSuffix(value, ".")
	}
	if value == "" || len(value) > 253 || strings.HasSuffix(value, ".") {
		return "", errors.New("DNS hostname is invalid")
	}
	for _, character := range value {
		if character > 0x7f {
			return "", errors.New("DNS hostname must be ASCII LDH")
		}
	}
	value = strings.ToLower(value)
	if net.ParseIP(value) != nil || value == "localhost" {
		return "", errors.New("DNS hostname must not be an IP address or localhost")
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return "", errors.New("DNS hostname must contain a suffix")
	}
	for _, part := range parts {
		if !dnsLabel.MatchString(part) {
			return "", errors.New("DNS hostname label is invalid")
		}
	}
	return value, nil
}

func normalizeCNAMETarget(value string) (string, error) {
	return normalizeHostname(value)
}

func publicExpectedAddress(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || !address.IsGlobalUnicast() {
		return netip.Addr{}, errors.New("expected platform address must be a global unicast IP")
	}
	for _, prefix := range forbiddenAddresses {
		if prefix.Contains(address) {
			return netip.Addr{}, errors.New("expected platform address is private, reserved, documentation, or benchmark space")
		}
	}
	return address, nil
}

func sortedRecords(records []contracts.PublicDNSRecord) []contracts.PublicDNSRecord {
	if len(records) == 0 {
		return nil
	}
	sort.Slice(records, func(left, right int) bool {
		if records[left].Type != records[right].Type {
			return records[left].Type < records[right].Type
		}
		if records[left].Name != records[right].Name {
			return records[left].Name < records[right].Name
		}
		return records[left].Value < records[right].Value
	})
	return records
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; !exists {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func mustPrefixes(values ...string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			panic(err)
		}
		result = append(result, prefix)
	}
	return result
}

type recursiveResolver struct{ resolver *net.Resolver }

func newRecursiveResolver(endpoint string) (*recursiveResolver, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(endpoint))
	if err != nil || host == "" || port == "" || net.ParseIP(host) == nil {
		return nil, errors.New("recursive resolver endpoint must be an explicit IP:port")
	}
	return &recursiveResolver{resolver: &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, endpoint)
	}}}, nil
}

func (r *recursiveResolver) Lookup(ctx context.Context, hostname, recordType string) ([]contracts.PublicDNSRecord, error) {
	switch recordType {
	case "A", "AAAA":
		addresses, err := r.resolver.LookupNetIP(ctx, "ip", hostname)
		if err != nil {
			return nil, err
		}
		result := make([]contracts.PublicDNSRecord, 0, len(addresses))
		for _, address := range addresses {
			if (recordType == "A" && address.Is4()) || (recordType == "AAAA" && address.Is6()) {
				result = append(result, contracts.PublicDNSRecord{Name: hostname, Type: recordType, Value: address.String()})
			}
		}
		return result, nil
	case "CNAME":
		canonical, err := r.resolver.LookupCNAME(ctx, hostname)
		if err != nil {
			return nil, err
		}
		canonical, err = normalizeHostname(canonical)
		if err != nil {
			return nil, err
		}
		if canonical == hostname {
			return nil, nil
		}
		return []contracts.PublicDNSRecord{{Name: hostname, Type: "CNAME", Value: canonical}}, nil
	default:
		return nil, errors.New("unsupported DNS record type")
	}
}
