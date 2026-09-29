package acornfoxrelease

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// Helpers retained from the archived release package for product build input parsing.
const (
	Product          = "acornfox"
	maxManifestBytes = 1 << 20
)

var digestText = regexp.MustCompile(`^[a-f0-9]{64}$`)

func sha256Text(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func validRelativeFile(p string) bool {
	if p == "" || strings.Contains(p, "\\") || strings.HasPrefix(p, "/") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." || part == ".git" || hasASCIIControl(part) {
			return false
		}
	}
	return true
}

func hasASCIIControl(v string) bool {
	for _, b := range []byte(v) {
		if b < 0x20 || b == 0x7f {
			return true
		}
	}
	return false
}
