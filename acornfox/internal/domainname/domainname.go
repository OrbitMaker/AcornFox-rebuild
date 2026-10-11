// Package domainname validates custom domain names. It has no platform
// dependencies, so the CLI (including the Windows build) and the server share
// one definition.
package domainname

import (
	"regexp"
	"strings"
)

// pattern accepts a lowercase DNS hostname with at least one dot and no
// trailing dot. Each label is 1..63 chars of [a-z0-9-] not starting or ending
// with '-'; total length is bounded to <= 253 by Valid.
var pattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// Valid reports whether name is an acceptable custom domain: lowercase, a
// valid hostname with at least one dot, not a trailing dot, not an IP literal,
// and at most 253 characters.
func Valid(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	if name != strings.ToLower(name) {
		return false
	}
	if !pattern.MatchString(name) {
		return false
	}
	// Reject dotted-decimal IPv4 literals (all-numeric labels).
	for _, l := range strings.Split(name, ".") {
		if strings.TrimFunc(l, func(r rune) bool { return r >= '0' && r <= '9' }) != "" {
			return true
		}
	}
	return false
}
