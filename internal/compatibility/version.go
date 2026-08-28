// Package compatibility defines explicit N-1/N protocol negotiation. It is
// shared by REST, SSE and Agent transports; it does not silently coerce major
// versions or security capabilities.
package compatibility

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

var (
	ErrInvalidVersion    = errors.New("invalid compatibility version")
	ErrIncompatibleMajor = errors.New("incompatible protocol major version")
	ErrNoCommonVersion   = errors.New("no common protocol version")
)

type Version struct {
	Major int
	Minor int
}

func (v Version) String() string { return fmt.Sprintf("%d.%d", v.Major, v.Minor) }

func (v Version) Compare(other Version) int {
	if v.Major < other.Major || v.Major == other.Major && v.Minor < other.Minor {
		return -1
	}
	if v == other {
		return 0
	}
	return 1
}

func Parse(raw string) (Version, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "v1" || raw == "1" {
		return Version{Major: 1, Minor: 0}, nil
	}
	raw = strings.TrimPrefix(raw, "v")
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return Version{}, ErrInvalidVersion
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil || major < 0 {
		return Version{}, ErrInvalidVersion
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil || minor < 0 {
		return Version{}, ErrInvalidVersion
	}
	return Version{Major: major, Minor: minor}, nil
}

type Negotiation struct {
	Version              Version
	DisabledCapabilities []string
}

func Negotiate(clientMin, clientMax Version, serverSupported []Version, capabilitiesByVersion map[Version][]string) (Negotiation, error) {
	if clientMin.Major != clientMax.Major {
		return Negotiation{}, ErrIncompatibleMajor
	}
	if clientMin.Compare(clientMax) > 0 {
		return Negotiation{}, ErrInvalidVersion
	}
	candidates := append([]Version(nil), serverSupported...)
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Compare(candidates[j]) > 0 })
	var selected Version
	found := false
	for _, candidate := range candidates {
		if candidate.Major != clientMin.Major {
			continue
		}
		if candidate.Compare(clientMin) >= 0 && candidate.Compare(clientMax) <= 0 {
			selected = candidate
			found = true
			break
		}
	}
	if !found {
		for _, candidate := range candidates {
			if candidate.Major != clientMin.Major {
				return Negotiation{}, ErrIncompatibleMajor
			}
		}
		return Negotiation{}, ErrNoCommonVersion
	}
	disabled := capabilityDifference(capabilitiesByVersion[clientMax], capabilitiesByVersion[selected])
	return Negotiation{Version: selected, DisabledCapabilities: disabled}, nil
}

func capabilityDifference(requested, negotiated []string) []string {
	available := make(map[string]struct{}, len(negotiated))
	for _, item := range negotiated {
		available[item] = struct{}{}
	}
	result := make([]string, 0)
	for _, item := range requested {
		if _, ok := available[item]; !ok {
			result = append(result, item)
		}
	}
	sort.Strings(result)
	return result
}
