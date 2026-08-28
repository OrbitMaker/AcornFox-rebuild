package ledger

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const RedactedValue = "[REDACTED]"

var (
	secretAssignment = regexp.MustCompile(`(?i)(^|[\s,;{])(?:password|passwd|passphrase|token|access[_-]?token|refresh[_-]?token|api[_-]?key|secret|client[_-]?secret|private[_-]?key|authorization|cookie|credential)(?:\s*[:=])\s*([^\s,;}]+)`)
	bearerValue      = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}`)
	pemValue         = regexp.MustCompile(`(?is)-----BEGIN[^-]*(?:PRIVATE KEY|CERTIFICATE)-----`)
)

// ValidateNoPlaintext traverses a structured value before it is serialized.
// Sensitive field values must be an explicit redaction marker or a reference
// / digest.  This is intentionally a rejection boundary, not a best-effort
// redactor: silently changing an evidence record would make replay ambiguous.
func ValidateNoPlaintext(value any) error {
	if err := walkSafe(value, "$"); err != nil {
		return fmt.Errorf("%w: %v", ErrSensitivePlaintext, err)
	}
	return nil
}

func walkSafe(value any, path string) error {
	switch typed := value.(type) {
	case nil, bool, float32, float64, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return nil
	case string:
		if isSafeReference(typed) {
			return nil
		}
		if containsPlaintextAssignment(typed) || bearerValue.MatchString(typed) || pemValue.MatchString(typed) {
			return fmt.Errorf("plaintext secret pattern at %s", path)
		}
		return nil
	case []string:
		for i, item := range typed {
			if err := walkSafe(item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	case []Reference:
		for i, item := range typed {
			if err := walkSafe(item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	case []any:
		for i, item := range typed {
			if err := walkSafe(item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	case map[string]string:
		for key, item := range typed {
			if err := checkField(key, item, fmt.Sprintf("%s.%s", path, key)); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		for key, item := range typed {
			fieldPath := fmt.Sprintf("%s.%s", path, key)
			if isSensitiveField(key) {
				if text, ok := item.(string); !ok || !isSafeReference(text) {
					return fmt.Errorf("unredacted sensitive field %s", fieldPath)
				}
				continue
			}
			if err := walkSafe(item, fieldPath); err != nil {
				return err
			}
		}
		return nil
	default:
		// Fail-safe: project structs through their persisted JSON shape so JSON
		// field names receive the exact map policy above. If either projection
		// step fails, reject the record; no unsupported value bypasses scanning.
		// Tested by TestLedgerValidationRejectsOpaqueAndNestedSensitiveValues.
		data, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("cannot inspect %s: %w", path, err)
		}
		var decoded any
		if err := json.Unmarshal(data, &decoded); err != nil {
			return fmt.Errorf("cannot inspect %s: %w", path, err)
		}
		return walkSafe(decoded, path)
	}
}

func checkField(key, value, path string) error {
	if isSensitiveField(key) && !isSafeReference(value) {
		return fmt.Errorf("unredacted sensitive field %s", path)
	}
	if containsPlaintextAssignment(value) || bearerValue.MatchString(value) || pemValue.MatchString(value) {
		return fmt.Errorf("plaintext secret pattern at %s", path)
	}
	return nil
}

func normalizedField(value string) string {
	return strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "", ".", "").Replace(strings.TrimSpace(value)))
}

func isSensitiveField(key string) bool {
	key = normalizedField(key)
	// A reference/digest/id suffix is metadata, not the secret itself.
	for _, suffix := range []string{"ref", "digest", "hash", "id", "name", "exists"} {
		if strings.HasSuffix(key, suffix) && key != suffix {
			return false
		}
	}
	switch key {
	case "password", "passwd", "passphrase", "token", "accesstoken", "refreshtoken", "apikey", "secret", "clientsecret", "privatekey", "signingkey", "authorization", "cookie", "credential":
		return true
	default:
		return false
	}
}

func isSafeReference(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || value == RedactedValue {
		return true
	}
	lower := strings.ToLower(value)
	for _, prefix := range []string{"secret://", "ref:", "reference:", "sha256:", "digest:"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func containsPlaintextAssignment(value string) bool {
	if isSafeReference(value) {
		return false
	}
	match := secretAssignment.FindStringSubmatch(value)
	if len(match) == 0 {
		return false
	}
	return !isSafeReference(strings.Trim(match[2], `"'`))
}
