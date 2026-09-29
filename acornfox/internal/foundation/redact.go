package foundation

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const RedactedValue = "[REDACTED]"

// Redactor applies both field-aware and known-secret redaction. It is safe
// to use at a persistence boundary: callers get a new value and the input is
// never modified in place.
type Redactor struct {
	Secrets     []string
	Replacement string
}

func NewRedactor(secrets ...string) Redactor {
	clean := make([]string, 0, len(secrets))
	seen := make(map[string]struct{}, len(secrets))
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if secret == "" || len(secret) < 3 {
			continue
		}
		if _, ok := seen[secret]; ok {
			continue
		}
		seen[secret] = struct{}{}
		clean = append(clean, secret)
	}
	// Longer values first avoids replacing a short shared prefix before the
	// complete secret has a chance to match.
	sort.SliceStable(clean, func(i, j int) bool { return len(clean[i]) > len(clean[j]) })
	return Redactor{Secrets: clean, Replacement: RedactedValue}
}

// RedactString masks known values and common secret-bearing fields while
// retaining surrounding non-sensitive text. It handles URL/base64/hex
// representations of known values because logs often encode headers before
// persistence.
func (r Redactor) RedactString(input string) string {
	if input == "" {
		return input
	}
	replacement := r.Replacement
	if replacement == "" {
		replacement = RedactedValue
	}
	output := input
	// Remove values behind sensitive field/header names first, then redact
	// generic secret assignments and known encoded variants.
	output = redactCookieHeaders(output, replacement)
	output = redactAuthorizationHeaders(output, replacement)
	output = redactSecretAssignments(output, replacement)
	for _, secret := range r.Secrets {
		for _, variant := range secretVariants(secret) {
			if variant == "" {
				continue
			}
			output = strings.ReplaceAll(output, variant, replacement)
			output = strings.ReplaceAll(output, strings.ToLower(variant), replacement)
		}
	}
	return output
}

// RedactText is the simple functional form used by logging boundaries.
func RedactText(input string, knownSecrets ...string) string {
	return NewRedactor(knownSecrets...).RedactString(input)
}

// Redact is kept as a compact compatibility spelling for tests and providers
// that already have a []string secret inventory.
func Redact(input string, knownSecrets []string) string {
	return NewRedactor(knownSecrets...).RedactString(input)
}

func (r Redactor) RedactBytes(input []byte) []byte {
	output := r.RedactString(string(input))
	return []byte(output)
}

func RedactBytes(input []byte, knownSecrets []string) []byte {
	return NewRedactor(knownSecrets...).RedactBytes(input)
}

// RedactMap deep-copies and redacts structured values before they are
// serialized. Sensitive keys are replaced wholesale, while nested maps and
// arrays retain their shape and non-sensitive fields.
func (r Redactor) RedactMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	output := make(map[string]any, len(input))
	for key, value := range input {
		if isSensitiveKey(key) {
			output[key] = r.replacement()
			continue
		}
		output[key] = r.redactValue(value)
	}
	return output
}

func RedactJSON(input []byte, knownSecrets []string) ([]byte, error) {
	var value any
	if err := json.Unmarshal(input, &value); err != nil {
		return nil, err
	}
	redacted := NewRedactor(knownSecrets...).redactValue(value)
	return json.Marshal(redacted)
}

func (r Redactor) redactValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return r.RedactMap(typed)
	case []any:
		items := make([]any, len(typed))
		for i, item := range typed {
			items[i] = r.redactValue(item)
		}
		return items
	case string:
		return r.RedactString(typed)
	default:
		return typed
	}
}

func (r Redactor) replacement() string {
	if r.Replacement == "" {
		return RedactedValue
	}
	return r.Replacement
}

func secretVariants(secret string) []string {
	variants := []string{secret}
	variants = append(variants,
		url.QueryEscape(secret),
		url.PathEscape(secret),
		base64.StdEncoding.EncodeToString([]byte(secret)),
		base64.RawStdEncoding.EncodeToString([]byte(secret)),
		base64.URLEncoding.EncodeToString([]byte(secret)),
		base64.RawURLEncoding.EncodeToString([]byte(secret)),
		hex.EncodeToString([]byte(secret)),
	)
	query := url.QueryEscape(secret)
	for _, equal := range []string{"=", "%3D", "%3d"} {
		for _, plus := range []string{"+", "%2B", "%2b"} {
			for _, slash := range []string{"/", "%2F", "%2f"} {
				variants = append(variants, strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(query, "%3D", equal), "%2B", plus), "%2F", slash))
			}
		}
	}
	seen := make(map[string]struct{}, len(variants))
	unique := variants[:0]
	for _, value := range variants {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}

var (
	// Assignment values stop at common delimiters so JSON, query-string and
	// shell-style logs can all be handled without parsing or rewriting the
	// entire record.
	secretAssignmentRE = regexp.MustCompile(`(?i)(["']?(?:password|passwd|passphrase|token|access[_-]?token|refresh[_-]?token|api[_-]?key|secret|client[_-]?secret|private[_-]?key|signing[_-]?key|credential|authorization)["']?\s*[:=]\s*(?:(?:bearer|basic)\s+)?["']?)([^"'\s,;&}]+)`)
	cookieHeaderRE     = regexp.MustCompile(`(?i)(\bcookie\s*[:=]\s*)([^\r\n]+)`)
	authorizationRE    = regexp.MustCompile(`(?i)(\bauthorization\s*[:=]\s*)((?:bearer|basic)\s+)([^\r\n,}]+)`)
)

func redactSecretAssignments(input, replacement string) string {
	return secretAssignmentRE.ReplaceAllStringFunc(input, func(match string) string {
		locations := secretAssignmentRE.FindStringSubmatchIndex(match)
		if len(locations) < 4 {
			return replacement
		}
		prefixEnd := locations[3]
		prefix := match[:prefixEnd]
		value := strings.TrimSpace(match[prefixEnd:])
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			return prefix + value[:1] + replacement + value[len(value)-1:]
		}
		return prefix + replacement
	})
}

func redactCookieHeaders(input, replacement string) string {
	return cookieHeaderRE.ReplaceAllStringFunc(input, func(match string) string {
		locations := cookieHeaderRE.FindStringSubmatchIndex(match)
		if len(locations) < 4 {
			return replacement
		}
		return match[:locations[3]] + replacement
	})
}

func redactAuthorizationHeaders(input, replacement string) string {
	return authorizationRE.ReplaceAllStringFunc(input, func(match string) string {
		locations := authorizationRE.FindStringSubmatchIndex(match)
		if len(locations) < 6 {
			return replacement
		}
		return match[:locations[5]] + replacement
	})
}

func isSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	normalized = strings.NewReplacer("-", "", "_", "", " ", "").Replace(normalized)
	for _, marker := range []string{
		"password", "passwd", "passphrase", "token", "accesstoken", "refreshtoken", "apikey", "secret", "clientsecret", "privatekey", "signingkey", "authorization", "cookie", "credential",
	} {
		if normalized == marker || strings.HasSuffix(normalized, marker) {
			return true
		}
	}
	return false
}
