package domain

import (
	"errors"
	"fmt"
)

// ErrorCode is the stable, machine-readable error vocabulary shared by the
// control plane and its providers.  Providers must not expose raw backend
// errors as product facts.
type ErrorCode string

const (
	ErrInvalidArgument       ErrorCode = "invalid_argument"
	ErrValidation            ErrorCode = "validation_failed"
	ErrInvalidTransition     ErrorCode = "invalid_transition"
	ErrImmutable             ErrorCode = "immutable"
	ErrConflict              ErrorCode = "conflict"
	ErrNotFound              ErrorCode = "not_found"
	ErrUnauthorized          ErrorCode = "unauthorized"
	ErrForbidden             ErrorCode = "forbidden"
	ErrUnsupportedCapability ErrorCode = "unsupported_capability"
	ErrUnavailable           ErrorCode = "unavailable"
	ErrTimeout               ErrorCode = "timeout"
	ErrCancelled             ErrorCode = "cancelled"
	ErrCapacity              ErrorCode = "capacity_exceeded"
	ErrUnknownState          ErrorCode = "unknown_state"
)

// RetryClass lets a controller make a retry decision without parsing a
// provider-specific error string.
type RetryClass string

const (
	RetryNever          RetryClass = "never"
	RetryImmediate      RetryClass = "immediate"
	RetryBackoff        RetryClass = "backoff"
	RetryAfterReconnect RetryClass = "after_reconnect"
	RetryUserAction     RetryClass = "user_action"
)

var (
	// ErrObjectNotFound is the neutral shared sentinel for absent resources across
	// auth, application, and persistence boundaries.
	ErrObjectNotFound = errors.New("application object not found")

	// ErrCredentialVersionConflict is the neutral shared sentinel for concurrent
	// credential version mismatch during rotation.
	ErrCredentialVersionConflict = errors.New("administrator credential version conflict")

	// ErrRateLimited is the neutral shared sentinel for rate limited authentication attempts.
	ErrRateLimited = errors.New("authentication rate limited")
)

// DomainError is safe to serialize after its message has been redacted by the
// caller. Cause is intentionally not serialized by the default JSON shape.
type DomainError struct {
	Code       ErrorCode  `json:"code"`
	Message    string     `json:"message"`
	Retry      RetryClass `json:"retry"`
	Retryable  bool       `json:"retryable"`
	Operation  string     `json:"operation,omitempty"`
	Capability string     `json:"capability,omitempty"`
	Cause      error      `json:"-"`
}

func (e *DomainError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Operation != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Operation, e.Message, e.Code)
	}
	return fmt.Sprintf("%s (%s)", e.Message, e.Code)
}

func (e *DomainError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func NewError(code ErrorCode, message string) *DomainError {
	return &DomainError{Code: code, Message: message, Retry: RetryNever}
}

func WrapError(code ErrorCode, message string, cause error) *DomainError {
	err := NewError(code, message)
	err.Cause = cause
	return err
}

func TransitionError(object, from, to string) *DomainError {
	return &DomainError{
		Code:      ErrInvalidTransition,
		Message:   fmt.Sprintf("%s cannot transition from %q to %q", object, from, to),
		Retry:     RetryNever,
		Operation: object,
	}
}

func ImmutableError(object string) *DomainError {
	return &DomainError{Code: ErrImmutable, Message: object + " is immutable", Retry: RetryNever, Operation: object}
}

func ValidationError(message string) *DomainError {
	return &DomainError{Code: ErrValidation, Message: message, Retry: RetryNever}
}

func UnsupportedCapabilityError(capability string) *DomainError {
	return &DomainError{Code: ErrUnsupportedCapability, Message: "provider capability is not enabled", Retry: RetryUserAction, Capability: capability}
}

func IsCode(err error, code ErrorCode) bool {
	var de *DomainError
	return errors.As(err, &de) && de.Code == code
}
