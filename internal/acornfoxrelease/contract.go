// Package acornfoxrelease contains repository-only release packaging policy.
package acornfoxrelease

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
)

const (
	DecisionV1Schema = 1
	Product          = "acornfox"
	Architecture     = "amd64"
	Migration        = "0033"
	Layout           = 1
	maxDecisionBytes = 16 << 10
)

var (
	ErrDecision = errors.New("acornfox release decision is invalid")
	digestText  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	commitText  = regexp.MustCompile(`^[a-f0-9]{40}$`)
	versionText = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?(\+[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?$`)
	githubPart  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)
)

// DecisionV1 is the canonical, local-only release decision input.
type DecisionV1 struct {
	SchemaVersion      int    `json:"schema_version"`
	Product            string `json:"product"`
	Architecture       string `json:"architecture"`
	Migration          string `json:"migration"`
	Layout             int    `json:"layout"`
	Version            string `json:"version"`
	ReleaseID          string `json:"release_id"`
	SourceRepository   string `json:"source_repository"`
	SourceCommit       string `json:"source_commit"`
	SourcePolicySHA256 string `json:"source_policy_sha256"`
	ToolchainSHA256    string `json:"toolchain_sha256"`
	RuntimeInputSHA256 string `json:"runtime_input_sha256"`
	LicenseInputSHA256 string `json:"license_input_sha256"`
}

// Witness is produced only by ParseDecisionV1. Its decision is not exported
// and all accessors return immutable scalar copies.
type Witness struct {
	decision DecisionV1
	valid    bool
}

func (w Witness) Valid() bool { return w.valid && w.decision.Validate() == nil }
func (w Witness) Version() (string, error) {
	if !w.Valid() {
		return "", ErrDecision
	}
	return w.decision.Version, nil
}
func (w Witness) ReleaseID() (string, error) {
	if !w.Valid() {
		return "", ErrDecision
	}
	return w.decision.ReleaseID, nil
}
func (w Witness) SourceRepository() (string, error) {
	if !w.Valid() {
		return "", ErrDecision
	}
	return w.decision.SourceRepository, nil
}
func (w Witness) SourceCommit() (string, error) {
	if !w.Valid() {
		return "", ErrDecision
	}
	return w.decision.SourceCommit, nil
}
func (w Witness) SHA256() (string, error) {
	if !w.Valid() {
		return "", ErrDecision
	}
	raw, err := CanonicalDecisionV1(w.decision)
	if err != nil {
		return "", ErrDecision
	}
	return sha256Text(raw), nil
}

func (d DecisionV1) Validate() error {
	if d.SchemaVersion != DecisionV1Schema || d.Product != Product || d.Architecture != Architecture || d.Migration != Migration || d.Layout != Layout || !versionText.MatchString(d.Version) || d.ReleaseID != "release-"+d.Version || !validGitHubRepository(d.SourceRepository) || !commitText.MatchString(d.SourceCommit) {
		return ErrDecision
	}
	for _, value := range []string{d.SourcePolicySHA256, d.ToolchainSHA256, d.RuntimeInputSHA256, d.LicenseInputSHA256} {
		if !digestText.MatchString(value) {
			return ErrDecision
		}
	}
	return nil
}

func validGitHubRepository(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.Hostname() != "github.com" || u.Port() != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || strings.HasSuffix(u.Path, "/") || strings.HasSuffix(u.Path, ".git") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(u.EscapedPath(), "/"), "/")
	return len(parts) == 2 && githubPart.MatchString(parts[0]) && githubPart.MatchString(parts[1])
}

func CanonicalDecisionV1(decision DecisionV1) ([]byte, error) {
	if err := decision.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(decision)
}

func ParseDecisionV1(raw []byte, independentSHA256 string) (Witness, error) {
	if len(raw) == 0 || len(raw) > maxDecisionBytes || !digestText.MatchString(independentSHA256) {
		return Witness{}, ErrDecision
	}
	var decision DecisionV1
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decision); err != nil {
		return Witness{}, ErrDecision
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Witness{}, ErrDecision
	}
	canonical, err := CanonicalDecisionV1(decision)
	if err != nil || !bytes.Equal(raw, canonical) || sha256Text(raw) != independentSHA256 {
		return Witness{}, ErrDecision
	}
	return Witness{decision: decision, valid: true}, nil
}

func sha256Text(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
