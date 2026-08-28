package foundation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// ProblemInput contains only non-secret, stable problem facts. Error messages
// should already be redacted before they enter this structure; the resulting
// keys are hashes and never expose the input contents.
type ProblemInput struct {
	TaskType          string
	ApplicationID     string
	SourceRevisionID  string
	DefinitionVersion string
	ReleaseID         string
	DeploymentID      string
	ErrorCode         string
	ErrorMessage      string
	EvidenceDigests   []string
}

// ProblemFingerprint identifies the underlying issue independent of provider
// or model. Object versions are deliberately excluded; VersionKey/CacheKey
// keep the same issue separate when its source or policy changes.
func ProblemFingerprint(input ProblemInput) string {
	canonical := struct {
		TaskType        string   `json:"task_type"`
		ApplicationID   string   `json:"application_id"`
		ErrorCode       string   `json:"error_code"`
		ErrorMessage    string   `json:"error_message"`
		EvidenceDigests []string `json:"evidence_digests,omitempty"`
	}{
		TaskType:        normalizeKeyText(input.TaskType),
		ApplicationID:   normalizeKeyText(input.ApplicationID),
		ErrorCode:       normalizeKeyText(input.ErrorCode),
		ErrorMessage:    normalizeMessage(input.ErrorMessage),
		EvidenceDigests: sortedNormalized(input.EvidenceDigests),
	}
	return digestCanonical("problem", canonical)
}

// VersionKey captures all version dimensions that can invalidate a cached
// result. Callers should pass source/definition/release/policy/template
// versions in a stable order, e.g. VersionKey(source, definition, policy).
func VersionKey(versions ...string) string {
	normalized := make([]string, len(versions))
	for i, value := range versions {
		normalized[i] = normalizeKeyText(value)
	}
	return digestCanonical("version", normalized)
}

// CacheKey is stable for the same problem and version dimensions, and changes
// whenever either changes. Use AIInvocationKey when provider/model isolation
// is also required because model outputs are not interchangeable facts.
func CacheKey(problemFingerprint, objectVersion, policyVersion string) string {
	return digestCanonical("cache", struct {
		Problem string `json:"problem"`
		Version string `json:"version"`
		Policy  string `json:"policy"`
	}{
		Problem: normalizeKeyText(problemFingerprint),
		Version: normalizeKeyText(objectVersion),
		Policy:  normalizeKeyText(policyVersion),
	})
}

func AIInvocationKey(problemFingerprint, objectVersion, policyVersion, provider, model string) string {
	return digestCanonical("invocation", struct {
		Problem  string `json:"problem"`
		Version  string `json:"version"`
		Policy   string `json:"policy"`
		Provider string `json:"provider"`
		Model    string `json:"model"`
	}{
		Problem:  normalizeKeyText(problemFingerprint),
		Version:  normalizeKeyText(objectVersion),
		Policy:   normalizeKeyText(policyVersion),
		Provider: normalizeKeyText(provider),
		Model:    normalizeKeyText(model),
	})
}

// BuildAIKeys computes the three values persisted with an AI invocation. It
// is a convenience for evidence code and makes the separation between issue,
// version and cache identity explicit.
type AIKeys struct {
	ProblemFingerprint string
	VersionKey         string
	CacheKey           string
}

func BuildAIKeys(problem ProblemInput, versions ...string) AIKeys {
	fingerprint := ProblemFingerprint(problem)
	version := VersionKey(versions...)
	return AIKeys{ProblemFingerprint: fingerprint, VersionKey: version, CacheKey: CacheKey(fingerprint, version, "")}
}

func digestCanonical(domain string, value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		// All current inputs are JSON scalar/struct values. Returning a digest of
		// the domain plus an explicit failure marker is deterministic and avoids
		// exposing a serialization error as a product fact.
		encoded = []byte("json-error")
	}
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(encoded)
	return hex.EncodeToString(h.Sum(nil))
}

func sortedNormalized(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = normalizeKeyText(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func normalizeKeyText(value string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
}

func normalizeMessage(value string) string {
	// Error messages often vary only by line wrapping. Keep case and
	// punctuation because those can identify materially different failures.
	return normalizeKeyText(value)
}
