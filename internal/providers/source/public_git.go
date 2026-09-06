package source

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/foundation"
)

const (
	minimumGitResolvers = 2
	gitResolverTimeout  = 2 * time.Second
	defaultGitTimeout   = 2 * time.Minute
)

var (
	gitDNSLabel          = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	gitForbiddenPrefixes = mustGitPrefixes(
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"2001::/23", "2001:db8::/32", "2002::/16", "2620:4f:8000::/48", "3fff::/20", "5f00::/16",
	)
	publicIPv6Space = netip.MustParsePrefix("2000::/3")
)

// GitResolver is intentionally narrower than net.Resolver: implementations
// receive one hostname and must return only the addresses observed from their
// configured recursive endpoint. There is no system resolver fallback.
type GitResolver interface {
	LookupNetIP(context.Context, string) ([]netip.Addr, error)
}

type gitAuthority struct {
	host      string
	port      uint16
	addresses []netip.Addr
}

type recursiveGitResolver struct{ endpoint string }

func configuredGitResolvers(injected []GitResolver, endpoints []string) ([]GitResolver, error) {
	resolvers := append([]GitResolver(nil), injected...)
	if len(resolvers) == 0 && len(endpoints) > 0 {
		seen := map[string]struct{}{}
		for _, endpoint := range endpoints {
			parsed, err := netip.ParseAddrPort(strings.TrimSpace(endpoint))
			if err != nil || !isPublicGitAddress(parsed.Addr()) {
				return nil, errors.New("recursive Git resolver endpoint must be a public IP:port")
			}
			canonical := parsed.String()
			if _, exists := seen[canonical]; exists {
				return nil, errors.New("recursive Git resolver endpoints must be distinct")
			}
			seen[canonical] = struct{}{}
			resolvers = append(resolvers, recursiveGitResolver{endpoint: canonical})
		}
	}
	if len(resolvers) != 0 && len(resolvers) < minimumGitResolvers {
		return nil, fmt.Errorf("at least %d explicit recursive Git resolvers are required", minimumGitResolvers)
	}
	return resolvers, nil
}

func (r recursiveGitResolver) LookupNetIP(ctx context.Context, host string) ([]netip.Addr, error) {
	resolver := &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, r.endpoint)
		},
	}
	return resolver.LookupNetIP(ctx, "ip", host)
}

func (p *Provider) normalizeGitSource(locator, ref string) (foundation.GitSource, error) {
	git, err := foundation.NormalizeGitSource(locator, ref)
	if err == nil || !p.testGitFixture {
		return git, err
	}
	// Package-local test support permits the local HTTPS fixture's ephemeral
	// port only. No production Config can enable it.
	u, parseErr := url.Parse(strings.TrimSpace(locator))
	if parseErr != nil || strings.ToLower(u.Scheme) != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Hostname() == "" || u.Port() == "" {
		return foundation.GitSource{}, err
	}
	canonical, canonicalErr := foundation.NormalizeGitSource("https://"+u.Hostname()+u.EscapedPath(), ref)
	if canonicalErr != nil {
		return foundation.GitSource{}, canonicalErr
	}
	canonical.Locator = "https://" + strings.ToLower(u.Hostname()) + ":" + u.Port() + strings.TrimPrefix(canonical.Locator, "https://"+strings.ToLower(u.Hostname()))
	return canonical, nil
}

func (p *Provider) resolveGitAuthority(ctx context.Context, git foundation.GitSource) (gitAuthority, error) {
	if strings.HasPrefix(git.Ref, "-") {
		return gitAuthority{}, errGitRejected
	}
	u, err := url.Parse(git.Locator)
	if err != nil || strings.ToLower(u.Scheme) != "https" || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" {
		return gitAuthority{}, errGitRejected
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	port := uint16(443)
	if rawPort := u.Port(); rawPort != "" {
		parsed, parseErr := netip.ParseAddrPort("[::1]:" + rawPort)
		if parseErr != nil || parsed.Port() == 0 {
			return gitAuthority{}, errGitRejected
		}
		port = parsed.Port()
	}
	if !p.testGitFixture && port != 443 {
		return gitAuthority{}, errGitRejected
	}
	if err := validatePublicGitHostname(host, p.testGitFixture); err != nil {
		return gitAuthority{}, errGitRejected
	}
	if len(p.gitResolvers) < minimumGitResolvers {
		return gitAuthority{}, errGitPolicyUnavailable
	}
	answerSets := make([][]netip.Addr, 0, len(p.gitResolvers))
	for _, resolver := range p.gitResolvers {
		query, cancel := context.WithTimeout(ctx, gitResolverTimeout)
		addresses, lookupErr := resolver.LookupNetIP(query, host)
		cancel()
		if lookupErr != nil {
			return gitAuthority{}, errGitResolverUnavailable
		}
		normalized := normalizePublicGitAnswers(addresses, p.testGitFixture)
		if len(normalized) == 0 {
			return gitAuthority{}, errGitRejected
		}
		answerSets = append(answerSets, normalized)
	}
	for index := 1; index < len(answerSets); index++ {
		if !sameGitAddressSet(answerSets[0], answerSets[index]) {
			return gitAuthority{}, errGitResolverConflict
		}
	}
	return gitAuthority{host: host, port: port, addresses: answerSets[0]}, nil
}

func validatePublicGitHostname(host string, fixture bool) error {
	if host == "" || len(host) > 253 || strings.Contains(host, ":") {
		return errors.New("Git hostname is invalid")
	}
	if net.ParseIP(host) != nil || looksLikeNumericIPv4Literal(host) {
		return errors.New("Git hostname must not be an IP literal")
	}
	if !fixture && (host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".test") || strings.HasSuffix(host, ".invalid") || strings.HasSuffix(host, ".example")) {
		return errors.New("Git hostname is reserved")
	}
	for _, label := range strings.Split(host, ".") {
		if !gitDNSLabel.MatchString(label) {
			return errors.New("Git hostname must be ASCII LDH")
		}
	}
	return nil
}

// looksLikeNumericIPv4Literal rejects every dotted or single-label form that
// libc/curl historically accepts as an IPv4 address. net.ParseIP deliberately
// accepts only canonical decimal dotted quads, while Git's HTTP stack may turn
// values such as 2130706433, 0177.0.0.1, or 0x7f.1 into loopback before an
// HTTP resolver pin is consulted.
func looksLikeNumericIPv4Literal(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if !looksLikeCInteger(part) {
			return false
		}
	}
	return true
}

func looksLikeCInteger(value string) bool {
	if value == "" {
		return false
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "0x") {
		if len(lower) == 2 {
			return false
		}
		for _, character := range lower[2:] {
			if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
				return false
			}
		}
		return true
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func normalizePublicGitAnswers(values []netip.Addr, fixture bool) []netip.Addr {
	unique := map[netip.Addr]struct{}{}
	for _, value := range values {
		value = value.Unmap()
		if (fixture && value.IsLoopback()) || (!fixture && isPublicGitAddress(value)) {
			unique[value] = struct{}{}
		}
	}
	result := make([]netip.Addr, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Less(result[right]) })
	return result
}

func sameGitAddressSet(left, right []netip.Addr) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func isPublicGitAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() {
		return false
	}
	// IPv6 uses a default-deny policy outside global-unicast 2000::/3. This
	// excludes NAT64, discard, ULA, link-local, and future special-purpose
	// ranges; the explicit prefix list above covers special allocations inside
	// 2000::/3 such as documentation and benchmark space.
	if address.Is6() && !publicIPv6Space.Contains(address) {
		return false
	}
	for _, prefix := range gitForbiddenPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func mustGitPrefixes(values ...string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}

var (
	errGitRejected            = errors.New("public Git source was rejected")
	errGitPolicyUnavailable   = errors.New("public Git resolver policy is unavailable")
	errGitResolverUnavailable = errors.New("public Git resolver was unavailable")
	errGitResolverConflict    = errors.New("public Git resolver answers conflicted")
)
