package hostlifecycle

import (
	"regexp"
)

const (
	FrameTypeHello    = "hello"
	FrameTypeAdmit    = "admit"
	FrameTypeReselect = "reselect"
	FrameTypeResult   = "result"

	OpStart         = "start"
	OpStatus        = "status"
	OpCheck         = "check"
	OpAdvance       = "advance"
	OpResumeBackend = "resume-backend"
	OpDismiss       = "dismiss"

	RoleNormal   = "normal"
	RoleRecovery = "recovery"
)

var semverRegex = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-(beta|rc)\.([0-9]+))?$`)

var validStates = map[string]struct{}{
	"idle":              {},
	"cleanup-required":  {},
	"selected":          {},
	"staged":            {},
	"host_prepared":     {},
	"backend_applying":  {},
	"backend_confirmed": {},
	"host_switch":       {},
	"host_trial":        {},
	"host_rollback":     {},
	"discarding":        {},
	"ready":             {},
	"updated":           {},
	"pending":           {},
	"not-configured":    {},
	"uninitialized":     {},
}

var validReasonCodes = map[string]struct{}{
	"ok":                   {},
	"pending":              {},
	"no_update":            {},
	"active_slot_repaired": {},
	"ineligible":           {},
	"suppressed":           {},
	"failed":               {},
	"conflict":             {},
	"uninitialized":        {},
	"not-configured":       {},
}

// HelloFrame is sent by child to parent before opening core roots.
type HelloFrame struct {
	Type          string `json:"type"`
	SchemaVersion int    `json:"schema_version"`
}

// AdmitFrame is sent by parent to child once controller selection has completed
// and the slot selector lock has been unlocked.
type AdmitFrame struct {
	Type          string `json:"type"`
	SchemaVersion int    `json:"schema_version"`
	Operation     string `json:"operation"`
	Role          string `json:"role"`
	SlotID        string `json:"slot_id"`
	InstanceID    string `json:"instance_id"`
	Nonce         string `json:"nonce"`
}

// ReselectFrame is returned by a recovery C0 child when repairing a torn slot
// ledger establishes that the durable active pointer is now a managed slot.
type ReselectFrame struct {
	Type          string `json:"type"`
	SchemaVersion int    `json:"schema_version"`
	Nonce         string `json:"nonce"`
	ReasonCode    string `json:"reason_code"`
	ActiveSlotID  string `json:"active_slot_id"`
}

// ResultFrame carries the bounded, desensitized final outcome from the child.
// It contains no paths, policies, keys, bindings, payloads, or raw backend errors.
type ResultFrame struct {
	Type          string `json:"type"`
	SchemaVersion int    `json:"schema_version"`
	Nonce         string `json:"nonce"`
	Operation     string `json:"operation"`
	State         string `json:"state"`
	ReasonCode    string `json:"reason_code"`
	Version       string `json:"version"`
	SlotID        string `json:"slot_id"`
}

// IsValidOperation checks if op is one of the fixed production operations.
func IsValidOperation(op string) bool {
	switch op {
	case OpStart, OpStatus, OpCheck, OpAdvance, OpResumeBackend, OpDismiss:
		return true
	default:
		return false
	}
}

// IsValidRole checks if role is normal or recovery.
func IsValidRole(role string) bool {
	switch role {
	case RoleNormal, RoleRecovery:
		return true
	default:
		return false
	}
}

// IsValidState checks if state belongs to the closed set of valid states.
func IsValidState(state string) bool {
	_, ok := validStates[state]
	return ok
}

// IsValidReasonCode checks if code belongs to the closed set of valid reason codes.
func IsValidReasonCode(code string) bool {
	_, ok := validReasonCodes[code]
	return ok
}

// IsValidSemver checks if v matches valid semantic version syntax.
func IsValidSemver(v string) bool {
	return semverRegex.MatchString(v)
}

// IsValidHexSHA256 verifies a 64-character lowercase hexadecimal string.
func IsValidHexSHA256(s string) bool {
	if len(s) != SHA256HexLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// IsValidHexNonce verifies a 64-character lowercase hex string representing 32 random bytes.
func IsValidHexNonce(s string) bool {
	return IsValidHexSHA256(s)
}
