package versionpolicy

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Supported canonical OS and architecture values (strict, no extra aliases)
var validOS = map[string]struct{}{
	"windows": {},
	"darwin":  {},
	"linux":   {},
}

var validArch = map[string]struct{}{
	"amd64": {},
	"arm64": {},
}

// CanonicalizePlatform validates that input os and arch are standard canonical values ("windows", "darwin", "linux") and ("amd64", "arm64").
func CanonicalizePlatform(osName, archName string) (string, string, error) {
	if _, ok := validOS[osName]; !ok {
		return "", "", fmt.Errorf("unsupported os %q", osName)
	}
	if _, ok := validArch[archName]; !ok {
		return "", "", fmt.Errorf("unsupported arch %q", archName)
	}
	return osName, archName, nil
}

// Semantic version specification:
// Supports optional leading 'v', X.Y.Z, and optional -beta.N or -rc.N (N is a non-negative integer without leading zeros).
// Leading zeros, whitespaces, and overflows in X, Y, Z or N are strictly rejected.
var semverRegexp = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-(beta|rc)\.([0-9]+))?$`)

type Semver struct {
	Major          uint64
	Minor          uint64
	Patch          uint64
	PrereleaseType string // "beta" or "rc", or ""
	PrereleaseNum  uint64
	HasPrerelease  bool
	Raw            string
}

func parseNumericSegment(s string) (uint64, error) {
	if len(s) == 0 {
		return 0, errors.New("empty segment")
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("leading zeros not permitted in segment %q", s)
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func ParseSemver(s string) (Semver, error) {
	if strings.TrimSpace(s) != s || s == "" {
		return Semver{}, fmt.Errorf("invalid version string %q", s)
	}
	m := semverRegexp.FindStringSubmatch(s)
	if m == nil {
		return Semver{}, fmt.Errorf("invalid semver %q", s)
	}
	major, err := parseNumericSegment(m[1])
	if err != nil {
		return Semver{}, fmt.Errorf("major version invalid: %v", err)
	}
	minor, err := parseNumericSegment(m[2])
	if err != nil {
		return Semver{}, fmt.Errorf("minor version invalid: %v", err)
	}
	patch, err := parseNumericSegment(m[3])
	if err != nil {
		return Semver{}, fmt.Errorf("patch version invalid: %v", err)
	}

	res := Semver{
		Major: major,
		Minor: minor,
		Patch: patch,
		Raw:   s,
	}

	if m[4] != "" {
		res.HasPrerelease = true
		res.PrereleaseType = m[4]
		pNum, err := parseNumericSegment(m[5])
		if err != nil {
			return Semver{}, fmt.Errorf("prerelease number invalid: %v", err)
		}
		res.PrereleaseNum = pNum
	}

	return res, nil
}

func (v Semver) IsPrerelease() bool {
	return v.HasPrerelease
}

// Compare returns -1 if v < other, 0 if v == other, 1 if v > other.
// Semver rules: 1.10.0 > 1.9.0; release > prerelease; rc > beta; higher prerelease number wins.
func (v Semver) Compare(other Semver) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}
	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}
	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}
	// Same X.Y.Z
	if !v.HasPrerelease && other.HasPrerelease {
		return 1
	}
	if v.HasPrerelease && !other.HasPrerelease {
		return -1
	}
	if !v.HasPrerelease && !other.HasPrerelease {
		return 0
	}
	// Both have prereleases: compare type ("beta" < "rc")
	if v.PrereleaseType != other.PrereleaseType {
		if v.PrereleaseType == "beta" && other.PrereleaseType == "rc" {
			return -1
		}
		return 1
	}
	// Same prerelease type: compare number
	if v.PrereleaseNum < other.PrereleaseNum {
		return -1
	}
	if v.PrereleaseNum > other.PrereleaseNum {
		return 1
	}
	return 0
}
