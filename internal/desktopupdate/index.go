package desktopupdate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/open-card/open-card/internal/versionpolicy"
	"io"
	"net/url"
	"strings"
	"time"
)

const (
	MaxIndexEnvelopeBytes = 1 << 20 // 1MB envelope limit
	MaxArtifactSizeBytes  = 1 << 30 // 1GB default upper bound
	CurrentSchemaVersion  = 1
)

var (
	ErrInvalidEnvelope     = errors.New("desktopupdate: invalid index envelope")
	ErrSignatureMismatch   = errors.New("desktopupdate: signature verification failed")
	ErrInvalidPayload      = errors.New("desktopupdate: invalid index payload")
	ErrExpired             = errors.New("desktopupdate: index has expired")
	ErrChannelMismatch     = errors.New("desktopupdate: channel mismatch")
	ErrSequenceRollback    = errors.New("desktopupdate: sequence rollback or duplicate")
	ErrVersionRollback     = errors.New("desktopupdate: version rollback")
	ErrNoUpdate            = errors.New("desktopupdate: no update available")
	ErrUnsupportedPlatform = errors.New("desktopupdate: unsupported platform or architecture")
	ErrInvalidArtifact     = errors.New("desktopupdate: invalid artifact")
	ErrURLNotAllowed       = errors.New("desktopupdate: artifact url not allowed")
	ErrInvalidOptions      = errors.New("desktopupdate: invalid check options")
)

type Semver = versionpolicy.Semver

func ParseSemver(s string) (Semver, error) {
	v, err := versionpolicy.ParseSemver(s)
	if err != nil {
		return v, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	return v, nil
}
func CanonicalizePlatform(osName, archName string) (string, string, error) {
	os, arch, err := versionpolicy.CanonicalizePlatform(osName, archName)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrUnsupportedPlatform, err)
	}
	return os, arch, nil
}

// IndexEnvelope represents the outer signed JSON envelope.
type IndexEnvelope struct {
	SchemaVersion int    `json:"schema_version"`
	Payload       string `json:"payload"`   // base64 standard encoded
	Signature     string `json:"signature"` // base64 standard encoded ed25519 signature
}

type Artifact struct {
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	URL            string `json:"url"`
	SHA256         string `json:"sha256"`
	Size           int64  `json:"size"`
	BackendBinding string `json:"backend_binding,omitempty"` // optional digest
}

type IndexPayload struct {
	Channel   string     `json:"channel"`  // "stable" or "beta"
	Sequence  uint64     `json:"sequence"` // positive sequence integer
	ExpiresAt string     `json:"expires_at"`
	Version   string     `json:"version"` // e.g. "1.2.3" or "v1.2.3-beta.1"
	Artifacts []Artifact `json:"artifacts"`
}

// CheckUpdateOptions provides parameters to evaluate an index candidate.
type CheckUpdateOptions struct {
	PublicKey       ed25519.PublicKey
	TargetOS        string
	TargetArch      string
	AllowedChannel  string // Must be exact "stable" or "beta"
	CurrentSequence uint64 // Must be >= 0
	CurrentVersion  string // Valid semver or empty for first install
	CurrentTime     time.Time
	AllowedHosts    []string // Must be non-empty list of exact hostnames
	MaxArtifactSize int64
}

// CandidateResult represents the verified target artifact and version metadata.
type CandidateResult struct {
	Channel  string
	Sequence uint64
	Version  string
	Artifact *Artifact // nil when there is no new update to install
}

// Strict JSON decoder that disallows unknown fields, duplicate/case-insensitive duplicate keys, and trailing data.
func strictDecodeEnvelopeJSON(data []byte, v *IndexEnvelope) error {
	allowedFields := map[string]struct{}{
		"schema_version": {},
		"payload":        {},
		"signature":      {},
	}
	if err := checkJSONStrictKeys(data, allowedFields); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing data after envelope JSON")
	}
	return nil
}

func strictDecodePayloadJSON(data []byte, v *IndexPayload) error {
	allowedPayloadFields := map[string]struct{}{
		"channel":    {},
		"sequence":   {},
		"expires_at": {},
		"version":    {},
		"artifacts":  {},
	}
	if err := checkJSONStrictKeys(data, allowedPayloadFields); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing data after payload JSON")
	}
	return nil
}

func checkJSONStrictKeys(data []byte, topLevelAllowed map[string]struct{}) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return errors.New("JSON root must be an object")
	}
	return checkObjectKeysRecursive(dec, topLevelAllowed)
}

func checkObjectKeysRecursive(dec *json.Decoder, allowedExact map[string]struct{}) error {
	seenLower := make(map[string]string)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return errors.New("invalid object key")
		}
		if allowedExact != nil {
			if _, ok := allowedExact[key]; !ok {
				return fmt.Errorf("field %q not allowed or casing mismatch", key)
			}
		}
		lowerKey := strings.ToLower(key)
		if prev, exists := seenLower[lowerKey]; exists {
			return fmt.Errorf("duplicate or case-conflicting key %q (conflicts with %q)", key, prev)
		}
		seenLower[lowerKey] = key

		// Check value
		vTok, err := dec.Token()
		if err != nil {
			return err
		}
		if delim, ok := vTok.(json.Delim); ok {
			if delim == '{' {
				// Child object (e.g. artifact elements)
				artifactAllowed := map[string]struct{}{
					"os":              {},
					"arch":            {},
					"url":             {},
					"sha256":          {},
					"size":            {},
					"backend_binding": {},
				}
				if err := checkObjectKeysRecursive(dec, artifactAllowed); err != nil {
					return err
				}
			} else if delim == '[' {
				if err := checkArrayKeysRecursive(dec); err != nil {
					return err
				}
			}
		}
	}
	// Consume '}'
	_, err := dec.Token()
	return err
}

func checkArrayKeysRecursive(dec *json.Decoder) error {
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if delim, ok := tok.(json.Delim); ok {
			if delim == '{' {
				artifactAllowed := map[string]struct{}{
					"os":              {},
					"arch":            {},
					"url":             {},
					"sha256":          {},
					"size":            {},
					"backend_binding": {},
				}
				if err := checkObjectKeysRecursive(dec, artifactAllowed); err != nil {
					return err
				}
			} else if delim == '[' {
				if err := checkArrayKeysRecursive(dec); err != nil {
					return err
				}
			}
		}
	}
	// Consume ']'
	_, err := dec.Token()
	return err
}

// VerifyAndSelectUpdate verifies the raw signed envelope and selects the artifact for the given options.
// Note on same-version behavior:
// When the index version matches the current version, no installable candidate is returned:
// CandidateResult is returned with the verified Channel, Sequence, and Version, but Artifact is nil,
// accompanied by ErrNoUpdate. The caller should persist the new Sequence if it advanced, but must NOT install.
func VerifyAndSelectUpdate(envelopeBytes []byte, opts CheckUpdateOptions) (*CandidateResult, error) {
	if len(envelopeBytes) == 0 || len(envelopeBytes) > MaxIndexEnvelopeBytes {
		return nil, fmt.Errorf("%w: invalid envelope size", ErrInvalidEnvelope)
	}
	if len(opts.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid public key length", ErrInvalidOptions)
	}

	// 1. Validate options
	if opts.AllowedChannel != "stable" && opts.AllowedChannel != "beta" {
		return nil, fmt.Errorf("%w: AllowedChannel must be exact 'stable' or 'beta', got %q", ErrInvalidOptions, opts.AllowedChannel)
	}
	if len(opts.AllowedHosts) == 0 {
		return nil, fmt.Errorf("%w: AllowedHosts must be non-empty", ErrInvalidOptions)
	}
	seenHosts := make(map[string]struct{}, len(opts.AllowedHosts))
	for _, h := range opts.AllowedHosts {
		if err := validateAllowedHostName(h); err != nil {
			return nil, fmt.Errorf("%w: invalid allowed host %q: %v", ErrInvalidOptions, h, err)
		}
		if _, exists := seenHosts[h]; exists {
			return nil, fmt.Errorf("%w: duplicate allowed host %q", ErrInvalidOptions, h)
		}
		seenHosts[h] = struct{}{}
	}

	if opts.MaxArtifactSize < 0 {
		return nil, fmt.Errorf("%w: MaxArtifactSize cannot be negative", ErrInvalidOptions)
	}

	// CurrentVersion validation:
	// Must be exact empty string (in which case CurrentSequence must be 0 for first install),
	// or a valid semver. Spaces or empty string with non-zero sequence are rejected.
	var curVer Semver
	hasCurrentVersion := opts.CurrentVersion != ""
	if !hasCurrentVersion {
		if opts.CurrentVersion != "" {
			return nil, fmt.Errorf("%w: CurrentVersion contains whitespace", ErrInvalidOptions)
		}
		if opts.CurrentSequence != 0 {
			return nil, fmt.Errorf("%w: CurrentSequence must be 0 when CurrentVersion is empty", ErrInvalidOptions)
		}
	} else {
		var err error
		curVer, err = ParseSemver(opts.CurrentVersion)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid CurrentVersion: %v", ErrInvalidOptions, err)
		}
	}

	targetOS, targetArch, err := CanonicalizePlatform(opts.TargetOS, opts.TargetArch)
	if err != nil {
		return nil, err
	}

	// 2. Decode envelope strictly
	var env IndexEnvelope
	if err := strictDecodeEnvelopeJSON(envelopeBytes, &env); err != nil {
		return nil, fmt.Errorf("%w: envelope decode failed: %v", ErrInvalidEnvelope, err)
	}
	if env.SchemaVersion != CurrentSchemaVersion {
		return nil, fmt.Errorf("%w: unsupported schema_version %d", ErrInvalidEnvelope, env.SchemaVersion)
	}

	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: invalid signature encoding or length", ErrInvalidEnvelope)
	}

	rawPayload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid payload base64 encoding", ErrInvalidEnvelope)
	}

	if !ed25519.Verify(opts.PublicKey, rawPayload, sig) {
		return nil, ErrSignatureMismatch
	}

	// 3. Decode payload strictly
	var p IndexPayload
	if err := strictDecodePayloadJSON(rawPayload, &p); err != nil {
		return nil, fmt.Errorf("%w: payload decode failed: %v", ErrInvalidPayload, err)
	}

	// Channel must match exact allowed channel
	if p.Channel != "stable" && p.Channel != "beta" {
		return nil, fmt.Errorf("%w: invalid payload channel %q", ErrInvalidPayload, p.Channel)
	}
	if p.Channel != opts.AllowedChannel {
		return nil, fmt.Errorf("%w: expected channel %q, got %q", ErrChannelMismatch, opts.AllowedChannel, p.Channel)
	}

	// Sequence must be positive
	if p.Sequence == 0 {
		return nil, fmt.Errorf("%w: sequence must be positive", ErrInvalidPayload)
	}

	// Expiration check
	expTime, err := time.Parse(time.RFC3339, p.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid expires_at RFC3339 timestamp", ErrInvalidPayload)
	}
	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !now.Before(expTime) {
		return nil, ErrExpired
	}

	// Parse index version
	indexVer, err := ParseSemver(p.Version)
	if err != nil {
		return nil, err
	}
	if p.Channel == "stable" && indexVer.IsPrerelease() {
		return nil, fmt.Errorf("%w: stable channel cannot have prerelease version %q", ErrInvalidPayload, p.Version)
	}

	// 4. Validate artifacts, URLs, digests, sizes before checking no_update / rollback
	// This ensures corrupt index payloads are rejected with errors instead of masked as no update.
	if len(p.Artifacts) == 0 {
		return nil, fmt.Errorf("%w: empty artifacts list", ErrInvalidPayload)
	}
	maxSize := opts.MaxArtifactSize
	if maxSize == 0 {
		maxSize = MaxArtifactSizeBytes
	}

	seenPlatform := make(map[string]struct{})
	var matchedArtifact *Artifact

	for i := range p.Artifacts {
		art := &p.Artifacts[i]
		canonOS, canonArch, pErr := CanonicalizePlatform(art.OS, art.Arch)
		if pErr != nil {
			return nil, fmt.Errorf("%w: unknown or invalid os=%q arch=%q", ErrInvalidArtifact, art.OS, art.Arch)
		}
		platformKey := canonOS + "/" + canonArch
		if _, seen := seenPlatform[platformKey]; seen {
			return nil, fmt.Errorf("%w: duplicate platform %q", ErrInvalidArtifact, platformKey)
		}
		seenPlatform[platformKey] = struct{}{}

		// URL validation
		if err := validateArtifactURL(art.URL, opts.AllowedHosts); err != nil {
			return nil, err
		}

		// SHA256 validation (strictly 64 lower-case hex)
		if err := validateSHA256(art.SHA256); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidArtifact, err)
		}

		if art.BackendBinding != "" {
			if err := validateSHA256(art.BackendBinding); err != nil {
				return nil, fmt.Errorf("%w: invalid backend_binding: %v", ErrInvalidArtifact, err)
			}
		}

		if art.Size <= 0 || art.Size > maxSize {
			return nil, fmt.Errorf("%w: size %d out of bounds (1..%d)", ErrInvalidArtifact, art.Size, maxSize)
		}

		if canonOS == targetOS && canonArch == targetArch {
			matchedArtifact = art
		}
	}

	if matchedArtifact == nil {
		return nil, fmt.Errorf("%w: no artifact matching %s/%s", ErrUnsupportedPlatform, targetOS, targetArch)
	}

	// 5. Sequence & Version rules against current state
	// Rule: Regardless of whether version is same or higher, sequence rollback is strictly forbidden.
	if p.Sequence < opts.CurrentSequence {
		return nil, fmt.Errorf("%w: index sequence %d < current %d", ErrSequenceRollback, p.Sequence, opts.CurrentSequence)
	}

	if hasCurrentVersion {
		cmp := indexVer.Compare(curVer)
		if cmp < 0 {
			// Version rollback
			return nil, fmt.Errorf("%w: index version %s < current version %s", ErrVersionRollback, indexVer.Raw, curVer.Raw)
		}

		if cmp == 0 {
			// Same version: never offer installable artifact.
			// Return ErrNoUpdate along with verified metadata (Artifact is nil).
			// Caller updates sequence metadata but does not install.
			return &CandidateResult{
				Channel:  p.Channel,
				Sequence: p.Sequence,
				Version:  indexVer.Raw,
				Artifact: nil,
			}, ErrNoUpdate
		}

		// Higher version (cmp > 0):
		// Sequence MUST be strictly greater than opts.CurrentSequence.
		// Same sequence with higher version is a sequence conflict.
		if p.Sequence <= opts.CurrentSequence {
			return nil, fmt.Errorf("%w: index sequence %d must be strictly greater than current %d for new version %s", ErrSequenceRollback, p.Sequence, opts.CurrentSequence, indexVer.Raw)
		}
	}

	return &CandidateResult{
		Channel:  p.Channel,
		Sequence: p.Sequence,
		Version:  indexVer.Raw,
		Artifact: matchedArtifact,
	}, nil
}

// validateAllowedHostName validates that the host in allowedHosts is a canonical DNS hostname:
// strictly lower-case, no leading/trailing whitespace, no URL scheme/path, no port, no trailing dot.
func validateAllowedHostName(h string) error {
	if h == "" {
		return errors.New("empty host")
	}
	if strings.TrimSpace(h) != h {
		return errors.New("host contains leading or trailing whitespace")
	}
	if strings.ToLower(h) != h {
		return errors.New("host must be lower-case")
	}
	if strings.HasSuffix(h, ".") {
		return errors.New("trailing dot not permitted in host")
	}
	if strings.Contains(h, "/") || strings.Contains(h, ":") || strings.Contains(h, "@") {
		return errors.New("host must not contain url scheme, path, userinfo or port")
	}
	// Validate standard hostname segments
	for _, part := range strings.Split(h, ".") {
		if len(part) == 0 || len(part) > 63 {
			return errors.New("invalid label length")
		}
		if part[0] == '-' || part[len(part)-1] == '-' {
			return errors.New("label cannot begin or end with a hyphen")
		}
		for i := 0; i < len(part); i++ {
			c := part[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return fmt.Errorf("invalid character %q in host", c)
			}
		}
	}
	return nil
}

func validateArtifactURL(rawURL string, allowedHosts []string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: malformed url", ErrInvalidArtifact)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: url scheme must be https", ErrURLNotAllowed)
	}
	if u.User != nil {
		return fmt.Errorf("%w: userinfo not permitted in url", ErrURLNotAllowed)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%w: fragment not permitted in url", ErrURLNotAllowed)
	}
	if u.RawQuery != "" {
		return fmt.Errorf("%w: query string not permitted in url", ErrURLNotAllowed)
	}

	hostname := strings.ToLower(u.Hostname())
	if hostname == "" {
		return fmt.Errorf("%w: missing hostname in url", ErrURLNotAllowed)
	}

	port := u.Port()
	if port != "" && port != "443" {
		return fmt.Errorf("%w: non-standard port %q not permitted", ErrURLNotAllowed, port)
	}

	matched := false
	for _, host := range allowedHosts {
		if hostname == host {
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Errorf("%w: host not in allowed hosts", ErrURLNotAllowed)
	}
	return nil
}

func validateSHA256(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("sha256 must be exactly 64 hex characters, got length %d", len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("sha256 must be lower-case hex character, invalid byte %q", c)
		}
	}
	return nil
}
