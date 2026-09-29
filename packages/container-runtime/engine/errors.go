package engine

import (
	"context"
	"errors"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
)

var (
	// ErrInvalidConfig indicates an invalid engine configuration (e.g. empty or non-absolute socket path).
	ErrInvalidConfig = errors.New("invalid engine configuration")

	// ErrInvalidIdentifier indicates an unsafe, malformed, or ambiguous identifier.
	ErrInvalidIdentifier = errors.New("invalid or unsafe object identifier")

	// ErrIdentityMismatch indicates the returned Docker object identity did not match the requested object.
	// Fixed constant message; never echoes raw inputs or responses.
	ErrIdentityMismatch = errors.New("returned object identity does not match requested identifier")

	// ErrNotFound indicates the requested object was not found in the engine.
	ErrNotFound = errors.New("docker object not found")

	// ErrInvalidParameter indicates invalid or unparseable parameters sent to the engine.
	ErrInvalidParameter = errors.New("invalid parameter sent to engine")

	// ErrConflict indicates an engine conflict state.
	ErrConflict = errors.New("conflict with current engine state")

	// ErrUnavailable indicates the Docker daemon is unreachable, stopped, or connection failed.
	ErrUnavailable = errors.New("docker daemon is unavailable")

	// ErrEngineError indicates an internal engine failure.
	ErrEngineError = errors.New("docker engine operation failed")
)

// mapSDKError maps an SDK or system error to a fixed safe sentinel error derived from SDK errdefs,
// while strictly preserving context.Canceled, context.DeadlineExceeded, and errors.Is identities.
// It returns fixed sentinels only, never passing through arbitrary wrapped error strings or echoing secrets.
func mapSDKError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if errors.Is(err, ErrNotFound) || cerrdefs.IsNotFound(err) {
		return ErrNotFound
	}
	if errors.Is(err, ErrInvalidParameter) || cerrdefs.IsInvalidArgument(err) {
		return ErrInvalidParameter
	}
	if errors.Is(err, ErrConflict) || cerrdefs.IsConflict(err) {
		return ErrConflict
	}
	if errors.Is(err, ErrUnavailable) || cerrdefs.IsUnavailable(err) || client.IsErrConnectionFailed(err) {
		return ErrUnavailable
	}
	if errors.Is(err, ErrInvalidConfig) {
		return ErrInvalidConfig
	}
	if errors.Is(err, ErrInvalidIdentifier) {
		return ErrInvalidIdentifier
	}
	if errors.Is(err, ErrIdentityMismatch) {
		return ErrIdentityMismatch
	}

	return ErrEngineError
}
